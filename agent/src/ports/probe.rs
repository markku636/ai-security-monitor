//! 主動 port 探測（TCP connect）。防禦用途：預設只允許掃自己（loopback）與私有網段；
//! 公網目標必須加 `--allow-public` 並自行確認有授權。可選用已安裝的 nmap（`-sT`，不需 root）。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Semaphore;

use crate::error::{AppError, AppResult};
use crate::util::cmd::CmdSpec;
use crate::util::net::{classify, IpClass};

/// 常見服務與高風險 port（約 70 個）。
pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 514, 587, 631, 636, 873, 993, 995,
    1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3306, 3389, 4444, 4899, 5000, 5432, 5555, 5601, 5672, 5900,
    5984, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8086, 8088, 8443, 8888, 9000, 9090, 9092, 9200, 9300,
    9418, 10000, 11211, 15672, 27017, 31337, 50000,
];

pub const MAX_PORTS: usize = 4096;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProbeResult {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
}

/// `1-1024,3389,8000-8100` → 排序去重的 port 清單（上限 4096）。
pub fn parse_ports(spec: &str) -> AppResult<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let bad = || AppError::InvalidArg(tf!("port 範圍格式錯誤：{part}", part = part));
        if let Some((a, b)) = part.split_once('-') {
            let (a, b): (u16, u16) = (
                a.trim().parse().map_err(|_| bad())?,
                b.trim().parse().map_err(|_| bad())?,
            );
            if a == 0 || a > b {
                return Err(bad());
            }
            out.extend(a..=b);
        } else {
            let p: u16 = part.parse().map_err(|_| bad())?;
            if p == 0 {
                return Err(bad());
            }
            out.push(p);
        }
        if out.len() > MAX_PORTS {
            return Err(AppError::InvalidArg(tf!("一次最多探測 {n} 個 port", n = MAX_PORTS)));
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// 防禦用途護欄：私網 / loopback / link-local 直接允許；公網需明確 `allow_public`。
pub fn authorize_target(ip: IpAddr, allow_public: bool) -> AppResult<()> {
    match classify(ip) {
        IpClass::Loopback | IpClass::Private | IpClass::LinkLocal => Ok(()),
        IpClass::Public if allow_public => Ok(()),
        IpClass::Public => Err(AppError::InvalidArg(tf!(
            "{ip} 是公網位址；只掃描你擁有或已獲授權的主機，確認後加 --allow-public",
            ip = ip
        ))),
        _ => Err(AppError::InvalidArg(tf!("{ip} 不是可探測的單播位址", ip = ip))),
    }
}

pub async fn resolve(host: &str) -> AppResult<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| AppError::InvalidArg(tf!("無法解析主機 {host}：{e}", host = host, e = e)))?;
    addrs
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| AppError::InvalidArg(tf!("無法解析主機 {host}", host = host)))
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8088 | 8888 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 | 8443 => "https",
        445 => "smb",
        1433 => "mssql",
        1521 => "oracle",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        5985 | 5986 => "winrm",
        6379 => "redis",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "",
    }
}

/// TCP connect 掃描（有限併發與逾時）。只回開啟的 port。
pub async fn tcp_scan(ip: IpAddr, ports: &[u16], timeout: Duration, concurrency: usize) -> Vec<ProbeResult> {
    let sem = Arc::new(Semaphore::new(concurrency.clamp(1, 512)));
    let mut set = tokio::task::JoinSet::new();
    for &port in ports {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let addr = SocketAddr::new(ip, port);
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        });
    }
    let mut open = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(p)) = r {
            open.push(p);
        }
    }
    open.sort_unstable();
    open.into_iter()
        .map(|port| ProbeResult {
            port,
            proto: "tcp".into(),
            state: "open".into(),
            service: service_name(port).into(),
        })
        .collect()
}

pub fn nmap_spec(ip: IpAddr, ports: &[u16]) -> CmdSpec {
    let list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let ip_s = ip.to_string();
    let mut args = vec!["-sT", "-Pn", "-n", "-oX", "-", "-p", &list];
    if ip.is_ipv6() {
        args.insert(0, "-6");
    }
    args.push(&ip_s);
    CmdSpec::new("nmap", &args)
        .timeout(600_000)
        .describe(t!("nmap TCP connect 掃描"))
}

fn attr(chunk: &str, name: &str) -> Option<String> {
    let pat = format!("{name}=\"");
    let start = chunk.find(&pat)? + pat.len();
    let end = chunk[start..].find('"')? + start;
    Some(chunk[start..end].to_string())
}

/// 解析 nmap `-oX` 輸出中的 `<port>` 元素（只取 open）。
pub fn parse_nmap_xml(xml: &str) -> Vec<ProbeResult> {
    let mut out = Vec::new();
    for chunk in xml.split("<port ").skip(1) {
        let body = chunk.split("</port>").next().unwrap_or(chunk);
        let (Some(proto), Some(port)) = (
            attr(body, "protocol"),
            attr(body, "portid").and_then(|p| p.parse::<u16>().ok()),
        ) else {
            continue;
        };
        let state = body
            .find("<state ")
            .and_then(|i| attr(&body[i..], "state"))
            .unwrap_or_default();
        if state != "open" {
            continue;
        }
        let service = body
            .find("<service ")
            .and_then(|i| attr(&body[i..], "name"))
            .unwrap_or_default();
        out.push(ProbeResult {
            port,
            proto,
            state,
            service,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_lists() {
        assert_eq!(parse_ports("22,80-82, 22").unwrap(), vec![22, 80, 81, 82]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("1-65535").is_err());
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn authorization_guard() {
        assert!(authorize_target("127.0.0.1".parse().unwrap(), false).is_ok());
        assert!(authorize_target("192.168.1.5".parse().unwrap(), false).is_ok());
        assert!(authorize_target("8.8.8.8".parse().unwrap(), false).is_err());
        assert!(authorize_target("8.8.8.8".parse().unwrap(), true).is_ok());
        assert!(authorize_target("224.0.0.1".parse().unwrap(), true).is_err());
    }

    #[test]
    fn nmap_xml() {
        let xml = r#"<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" method="table"/></port>
<port protocol="tcp" portid="23"><state state="closed" reason="conn-refused"/><service name="telnet"/></port>
<port protocol="tcp" portid="6379"><state state="open" reason="syn-ack"/><service name="redis"/></port>
</ports></host></nmaprun>"#;
        let r = parse_nmap_xml(xml);
        assert_eq!(r.len(), 2);
        assert_eq!(
            r[1],
            ProbeResult {
                port: 6379,
                proto: "tcp".into(),
                state: "open".into(),
                service: "redis".into()
            }
        );
        let spec = nmap_spec("10.0.0.1".parse().unwrap(), &[22, 80]);
        assert_eq!(spec.display(), "nmap -sT -Pn -n -oX - -p 22,80 10.0.0.1");
    }

    #[tokio::test]
    async fn scans_a_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let closed = {
            let l2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l2.local_addr().unwrap().port()
        };
        let r = tcp_scan(
            "127.0.0.1".parse().unwrap(),
            &[port, closed],
            Duration::from_millis(500),
            8,
        )
        .await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].port, port);
    }
}
