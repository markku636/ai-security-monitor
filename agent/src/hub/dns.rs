//! 迷你 DNS 用戶端（只查 SRV／TXT，UDP）：找公司 DNS 上的 `_aisecmon._tcp.<網域>`。
//!
//! 不用系統解析器的 API（各平台都不一樣、也查不到 SRV）：自己讀 DNS 伺服器與搜尋網域，
//! - Linux／macOS：`/etc/resolv.conf` 的 `nameserver`、`search`／`domain`；macOS 另外看 `scutil --dns`
//! - Windows：PowerShell `Get-DnsClientServerAddress`、`Get-DnsClientGlobalSetting`、`Get-DnsClient`、網域成員資格
//!
//! 封包編解碼是純函式，測試用固定封包驗證（含名稱壓縮）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::error::{AppError, AppResult};

pub const TYPE_A: u16 = 1;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Srv {
        name: String,
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt {
        name: String,
        items: Vec<String>,
    },
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Other(u16),
}

/// 一個 DNS 查詢封包（遞迴、單一問題、class IN）。
pub fn encode_query(id: u16, name: &str, qtype: u16) -> AppResult<Vec<u8>> {
    let mut b = Vec::with_capacity(32 + name.len());
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00]); // RD
    b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AppError::InvalidArg(tf!("DNS 名稱格式錯誤：{name}", name = name)));
        }
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&[0, 1]);
    Ok(b)
}

fn bad() -> AppError {
    AppError::Parse("malformed DNS response".into())
}

fn u16_at(b: &[u8], i: usize) -> AppResult<u16> {
    b.get(i..i + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(bad)
}

/// 讀名稱（支援壓縮指標）；回傳（名稱, 下一個位置）。
fn read_name(b: &[u8], mut i: usize) -> AppResult<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(i).ok_or_else(bad)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (u16_at(b, i)? & 0x3FFF) as usize;
            if end.is_none() {
                end = Some(i + 2);
            }
            jumps += 1;
            if jumps > 32 || ptr >= b.len() {
                return Err(bad());
            }
            i = ptr;
            continue;
        }
        if len > 63 {
            return Err(bad());
        }
        let s = b.get(i + 1..i + 1 + len).ok_or_else(bad)?;
        labels.push(String::from_utf8_lossy(s).to_string());
        i += 1 + len;
        if labels.len() > 127 {
            return Err(bad());
        }
    }
    Ok((labels.join("."), end.unwrap_or(i)))
}

/// 解析回應：檢查 id、QR、RCODE；回傳 answer＋additional 的紀錄。NXDOMAIN 回空陣列。
pub fn parse_response(b: &[u8], expect_id: u16) -> AppResult<Vec<Record>> {
    if b.len() < 12 || u16_at(b, 0)? != expect_id || b[2] & 0x80 == 0 {
        return Err(bad());
    }
    let rcode = b[3] & 0x0F;
    if rcode == 3 {
        return Ok(vec![]);
    }
    if rcode != 0 {
        return Err(AppError::Hub(format!("DNS rcode {rcode}")));
    }
    let qd = u16_at(b, 4)? as usize;
    let an = u16_at(b, 6)? as usize;
    let ns = u16_at(b, 8)? as usize;
    let ar = u16_at(b, 10)? as usize;
    let mut i = 12;
    for _ in 0..qd {
        let (_, next) = read_name(b, i)?;
        i = next + 4;
    }
    let mut out = Vec::new();
    for n in 0..(an + ns + ar) {
        let (name, next) = read_name(b, i)?;
        let rtype = u16_at(b, next)?;
        let rdlen = u16_at(b, next + 8)? as usize;
        let start = next + 10;
        let rdata = b.get(start..start + rdlen).ok_or_else(bad)?;
        i = start + rdlen;
        if n >= an && n < an + ns {
            continue; // authority 區段不需要
        }
        out.push(match rtype {
            TYPE_SRV if rdlen >= 7 => Record::Srv {
                name,
                priority: u16_at(rdata, 0)?,
                weight: u16_at(rdata, 2)?,
                port: u16_at(rdata, 4)?,
                target: read_name(b, start + 6)?.0,
            },
            TYPE_TXT => {
                let mut items = Vec::new();
                let mut j = 0;
                while j < rdata.len() {
                    let l = rdata[j] as usize;
                    let s = rdata.get(j + 1..j + 1 + l).ok_or_else(bad)?;
                    items.push(String::from_utf8_lossy(s).to_string());
                    j += 1 + l;
                }
                Record::Txt { name, items }
            }
            TYPE_A if rdlen == 4 => Record::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            TYPE_AAAA if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                Record::Aaaa(Ipv6Addr::from(a))
            }
            t => Record::Other(t),
        });
    }
    Ok(out)
}

/// 對一台 DNS 伺服器查一次（UDP 53）。
pub async fn query(server: IpAddr, name: &str, qtype: u16, timeout: Duration) -> AppResult<Vec<Record>> {
    query_at(SocketAddr::new(server, 53), name, qtype, timeout).await
}

pub async fn query_at(server: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> AppResult<Vec<Record>> {
    let id = u16::from_be_bytes(super::identity::random_bytes::<2>()?);
    let pkt = encode_query(id, name, qtype)?;
    let bind: SocketAddr = if server.ip().is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(&pkt).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| AppError::Timeout(timeout.as_millis() as u64))??;
        // id 不符的封包（遲到的舊回應）略過，繼續等
        match parse_response(&buf[..n], id) {
            Ok(r) => return Ok(r),
            Err(AppError::Parse(_)) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// 依序問每台 DNS 伺服器，第一個有回答（含 NXDOMAIN）的為準。
pub async fn resolve(cfg: &DnsConfig, name: &str, qtype: u16, timeout: Duration) -> AppResult<Vec<Record>> {
    let mut last = None;
    for s in &cfg.servers {
        match query(*s, name, qtype, timeout).await {
            Ok(r) => return Ok(r),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| AppError::Hub(t!("找不到這台電腦使用的 DNS 伺服器").into())))
}

/// 這台電腦的 DNS 設定。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DnsConfig {
    pub servers: Vec<IpAddr>,
    pub search: Vec<String>,
}

impl DnsConfig {
    fn push_server(&mut self, s: &str) {
        // fe80::1%eth0 這種帶 scope 的位址 UDP connect 不一定成功，去掉 scope 後若是 link-local 就略過
        let s = s.split('%').next().unwrap_or("").trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            let link_local_v6 = matches!(ip, IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80);
            if !ip.is_unspecified() && !link_local_v6 && !self.servers.contains(&ip) {
                self.servers.push(ip);
            }
        }
    }

    fn push_search(&mut self, d: &str) {
        let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
        // 「local」是 mDNS 用的，不會有 SRV；單一標籤（例如 lan、home）一樣可以查
        if d.is_empty()
            || d == "local"
            || d.ends_with(".local")
            || !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return;
        }
        if !self.search.contains(&d) {
            self.search.push(d);
        }
    }

    /// 合併另一份（不重複）。
    pub fn merge(&mut self, other: DnsConfig) {
        for s in other.servers {
            if !self.servers.contains(&s) {
                self.servers.push(s);
            }
        }
        for d in other.search {
            self.push_search(&d);
        }
    }
}

/// `/etc/resolv.conf`。
pub fn parse_resolv_conf(text: &str) -> DnsConfig {
    let mut c = DnsConfig::default();
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        let mut it = line.split_whitespace();
        match it.next() {
            Some("nameserver") => {
                if let Some(s) = it.next() {
                    c.push_server(s);
                }
            }
            // 後出現的 search／domain 會蓋掉前面的（resolv.conf 的規則）
            Some("search") | Some("domain") => {
                c.search.clear();
                for d in it {
                    c.push_search(d);
                }
            }
            _ => {}
        }
    }
    c
}

/// macOS `scutil --dns`：`search domain[0] : corp.example`、`nameserver[0] : 10.0.0.1`。
pub fn parse_scutil(text: &str) -> DnsConfig {
    let mut c = DnsConfig::default();
    for line in text.lines() {
        let t = line.trim();
        let Some((k, v)) = t.split_once(" : ") else {
            continue;
        };
        if k.starts_with("search domain[") || k.starts_with("domain") && !k.contains("domain[") {
            c.push_search(v);
        } else if k.starts_with("nameserver[") {
            c.push_server(v);
        }
    }
    c
}

/// Windows 的 PowerShell 輸出：每行 `N <dns 伺服器>` 或 `S <搜尋網域>`。
pub fn parse_windows(text: &str) -> DnsConfig {
    let mut c = DnsConfig::default();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("N ") {
            c.push_server(v);
        } else if let Some(v) = line.strip_prefix("S ") {
            c.push_search(v);
        }
    }
    c
}

pub const WINDOWS_DNS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
(Get-DnsClientGlobalSetting).SuffixSearchList | ForEach-Object { "S $_" }
$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain) { "S $($cs.Domain)" }
Get-DnsClient | Where-Object { $_.ConnectionSpecificSuffix } | ForEach-Object { "S $($_.ConnectionSpecificSuffix)" }
$up = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty ifIndex
Get-DnsClientServerAddress | Where-Object { $up -contains $_.InterfaceIndex } | ForEach-Object { $_.ServerAddresses } | ForEach-Object { "N $_" }
"#;

/// 讀這台電腦的 DNS 伺服器與搜尋網域；讀不到回空的（呼叫端略過 SRV 查詢）。
pub async fn system_config() -> DnsConfig {
    let mut c = DnsConfig::default();
    if cfg!(windows) {
        let spec = crate::util::cmd::powershell(WINDOWS_DNS_SCRIPT).timeout(15_000);
        if let Ok(out) = crate::util::cmd::CmdRunner::run(&crate::util::cmd::RealRunner, &spec).await {
            c.merge(parse_windows(&out.stdout));
        }
    } else {
        if cfg!(target_os = "macos") {
            let spec = crate::util::cmd::CmdSpec::new("scutil", &["--dns"]).timeout(5_000);
            if let Ok(out) = crate::util::cmd::CmdRunner::run(&crate::util::cmd::RealRunner, &spec).await {
                c.merge(parse_scutil(&out.stdout));
            }
        }
        if let Ok(text) = tokio::fs::read_to_string("/etc/resolv.conf").await {
            c.merge(parse_resolv_conf(&text));
        }
    }
    c
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// 組一個回應封包：answer 用壓縮指標指回問題名稱。
    pub(crate) fn srv_response(id: u16, qname: &str, srvs: &[(u16, u16, u16, &str)], txt: &[&str]) -> Vec<u8> {
        let mut b = encode_query(id, qname, TYPE_SRV).unwrap();
        b[2] = 0x81;
        b[3] = 0x80;
        let an = (srvs.len() + usize::from(!txt.is_empty())) as u16;
        b[6..8].copy_from_slice(&an.to_be_bytes());
        for (prio, weight, port, target) in srvs {
            b.extend_from_slice(&[0xC0, 12]);
            b.extend_from_slice(&TYPE_SRV.to_be_bytes());
            b.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]);
            let mut rd = Vec::new();
            rd.extend_from_slice(&prio.to_be_bytes());
            rd.extend_from_slice(&weight.to_be_bytes());
            rd.extend_from_slice(&port.to_be_bytes());
            for l in target.trim_end_matches('.').split('.') {
                rd.push(l.len() as u8);
                rd.extend_from_slice(l.as_bytes());
            }
            rd.push(0);
            b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            b.extend_from_slice(&rd);
        }
        if !txt.is_empty() {
            b.extend_from_slice(&[0xC0, 12]);
            b.extend_from_slice(&TYPE_TXT.to_be_bytes());
            b.extend_from_slice(&[0, 1, 0, 0, 0x0E, 0x10]);
            let mut rd = Vec::new();
            for t in txt {
                rd.push(t.len() as u8);
                rd.extend_from_slice(t.as_bytes());
            }
            b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            b.extend_from_slice(&rd);
        }
        b
    }

    #[test]
    fn query_encoding() {
        let q = encode_query(0x1234, "_aisecmon._tcp.corp.example", TYPE_SRV).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(q[12] as usize, "_aisecmon".len());
        assert_eq!(&q[q.len() - 4..], &[0, 33, 0, 1]);
        assert!(encode_query(1, "a..b", TYPE_SRV).is_err());
    }

    #[test]
    fn parses_srv_and_txt_with_compression() {
        let name = "_aisecmon._tcp.corp.example";
        let b = srv_response(
            7,
            name,
            &[(10, 5, 443, "hub.corp.example"), (0, 0, 8088, "hub2.corp.example")],
            &["url=https://hub.corp.example", "fp=72AS-YEXT"],
        );
        let r = parse_response(&b, 7).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(
            r[0],
            Record::Srv {
                name: name.into(),
                priority: 10,
                weight: 5,
                port: 443,
                target: "hub.corp.example".into()
            }
        );
        assert_eq!(
            r[2],
            Record::Txt {
                name: name.into(),
                items: vec!["url=https://hub.corp.example".into(), "fp=72AS-YEXT".into()]
            }
        );
        // id 不符、截斷的封包
        assert!(parse_response(&b, 8).is_err());
        assert!(parse_response(&b[..b.len() - 3], 7).is_err());
        // NXDOMAIN
        let mut nx = encode_query(9, name, TYPE_SRV).unwrap();
        nx[2] = 0x81;
        nx[3] = 0x83;
        assert_eq!(parse_response(&nx, 9).unwrap(), vec![]);
        // 指標迴圈不會卡住
        let mut evil = encode_query(5, "a", TYPE_SRV).unwrap();
        evil[2] = 0x81;
        evil[3] = 0x80;
        evil[7] = 1;
        evil.extend_from_slice(&[0xC0, (evil.len()) as u8]);
        assert!(parse_response(&evil, 5).is_err());
    }

    #[test]
    fn resolv_conf_and_scutil_and_windows() {
        let c = parse_resolv_conf("# x\nnameserver 10.0.0.53\nnameserver fe80::1%eth0\nnameserver 1.1.1.1\nsearch corp.example lab.corp.example local\noptions ndots:1\n");
        assert_eq!(
            c.servers,
            vec!["10.0.0.53".parse::<IpAddr>().unwrap(), "1.1.1.1".parse().unwrap()]
        );
        assert_eq!(c.search, vec!["corp.example", "lab.corp.example"]);
        let c = parse_resolv_conf("domain old.example\nsearch new.example\n");
        assert_eq!(c.search, vec!["new.example"]);

        let s = "DNS configuration\n\nresolver #1\n  search domain[0] : corp.example\n  search domain[1] : eng.corp.example\n  nameserver[0] : 192.168.1.1\n  if_index : 6 (en0)\n\nresolver #2\n  domain   : local\n  nameserver[0] : 224.0.0.251\n";
        let c = parse_scutil(s);
        assert_eq!(c.search, vec!["corp.example", "eng.corp.example"]);
        assert!(c.servers.contains(&"192.168.1.1".parse().unwrap()));

        let c = parse_windows(
            "S corp.example\r\nS CORP.example.\r\nS \r\nN 10.1.1.1\r\nN fec0:0:0:ffff::1\r\nN 10.1.1.1\r\nN junk\r\n",
        );
        assert_eq!(c.search, vec!["corp.example"]);
        assert_eq!(c.servers.len(), 2);
    }

    #[tokio::test]
    async fn queries_a_local_udp_server_and_skips_stale_ids() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = sock.recv_from(&mut buf).await.unwrap();
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            // 先回一個 id 不對的封包（遲到的舊回應），再回正確的
            let _ = sock.send_to(&srv_response(id ^ 1, "x.example", &[], &[]), from).await;
            let _ = sock
                .send_to(
                    &srv_response(id, "x.example", &[(0, 0, 3000, "hub.example")], &[]),
                    from,
                )
                .await;
        });
        let r = query_at(addr, "x.example", TYPE_SRV, Duration::from_secs(3))
            .await
            .unwrap();
        assert!(matches!(&r[0], Record::Srv { port: 3000, .. }), "{r:?}");
        // 沒人回答 → 逾時
        let quiet = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let e = query_at(
            quiet.local_addr().unwrap(),
            "x.example",
            TYPE_SRV,
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, AppError::Timeout(_)));
    }
}
