//! `ai-security-monitor hub advertise --url <Hub 網址>`：在這台電腦上用 mDNS 幫 Hub 廣播
//! `_aisecmon._tcp.local`，讓區網的電腦自動找到它。
//!
//! Hub 跑在 Docker Desktop（Windows／macOS）或預設 bridge 網路時，容器裡的 mDNS 廣播出不了區網；
//! 這時在區網上任一台（通常就是跑 Docker 的那台）執行這個指令即可。TXT 帶 `url=`，agent 直接用那個網址，
//! 不必和 Hub 在同一台。

use std::collections::HashMap;

use super::discover::MDNS_SERVICE;
use super::identity::HubIdentity;
use crate::error::{AppError, AppResult};

/// 從網址取 port（沒寫就依 scheme）。
pub fn port_of(url: &str) -> u16 {
    let lower = url.to_ascii_lowercase();
    let https = lower.starts_with("https://");
    let rest = lower.split("://").nth(1).unwrap_or("");
    let hostport = rest.split('/').next().unwrap_or("");
    let port = if let Some(end) = hostport.find(']') {
        hostport[end + 1..].strip_prefix(':')
    } else {
        hostport.rsplit_once(':').map(|(_, p)| p)
    };
    port.and_then(|p| p.parse().ok())
        .unwrap_or(if https { 443 } else { 80 })
}

/// mDNS 主機名稱（一個標籤，英數與 -）。
pub fn mdns_host(hostname: &str) -> String {
    let mut h: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    h = h.trim_matches('-').to_string();
    if h.is_empty() {
        h = "hub".into();
    }
    h.truncate(40);
    format!("{h}-asm.local.")
}

pub fn txt_properties(url: &str, id: &HubIdentity) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("url".into(), url.trim_end_matches('/').to_string());
    m.insert("fp".into(), id.fingerprint.clone());
    m.insert("v".into(), id.version.clone());
    m.insert("path".into(), "/".into());
    m.insert(
        "proto".into(),
        if url.to_ascii_lowercase().starts_with("https://") {
            "https"
        } else {
            "http"
        }
        .into(),
    );
    m
}

/// 開始廣播；回傳的 daemon 存活期間持續回應查詢（drop／shutdown 後停止）。
pub fn start(url: &str, id: &HubIdentity, instance: &str) -> AppResult<(mdns_sd::ServiceDaemon, String)> {
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
    // 先給目前的 IPv4 位址（沒給的話要等 daemon 下一次檢查介面才會開始宣告）；之後介面變了由 addr_auto 更新
    let addrs: Vec<std::net::IpAddr> = crate::cli::fw_cmd::local_ips()
        .into_iter()
        .filter(|ip| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    let info = mdns_sd::ServiceInfo::new(
        MDNS_SERVICE,
        instance,
        &mdns_host(&host),
        addrs.as_slice(),
        port_of(url),
        txt_properties(url, id),
    )
    .map_err(|e| AppError::Hub(format!("mDNS: {e}")))?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info).map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
    Ok((daemon, fullname))
}

/// 停止廣播（送出 goodbye）。
pub fn stop(daemon: &mdns_sd::ServiceDaemon, fullname: &str) {
    if let Ok(rx) = daemon.unregister(fullname) {
        let _ = rx.recv_timeout(std::time::Duration::from_secs(2));
    }
    let _ = daemon.shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_hosts_and_txt() {
        assert_eq!(port_of("https://hub.corp.example"), 443);
        assert_eq!(port_of("http://hub.corp.example/"), 80);
        assert_eq!(port_of("http://192.168.1.5:8088"), 8088);
        assert_eq!(port_of("http://[fd00::5]:3000/x"), 3000);
        assert_eq!(port_of("https://[fd00::5]/x"), 443);
        assert_eq!(mdns_host("SRV-01.corp"), "srv-01-corp-asm.local.");
        assert_eq!(mdns_host("！！"), "hub-asm.local.");
        let id = HubIdentity {
            fingerprint: "AAAA-BBBB".into(),
            version: "0.3.0".into(),
            ..HubIdentity::default()
        };
        let t = txt_properties("https://hub.corp.example/", &id);
        assert_eq!(t["url"], "https://hub.corp.example");
        assert_eq!(t["fp"], "AAAA-BBBB");
        assert_eq!(t["proto"], "https");
        // agent 端用同一份 TXT 產生候選：網址要一字不差
        let hit = super::super::discover::MdnsHit {
            fullname: "Security Hub._aisecmon._tcp.local.".into(),
            port: 443,
            addrs: vec![],
            txt: t.into_iter().collect(),
        };
        assert_eq!(
            super::super::discover::mdns_candidate(&hit).unwrap().url,
            "https://hub.corp.example"
        );
    }
}

/// 真的走網路的往返測試（需要多播；CI 不跑）：`cargo test --lib advertise_and_browse -- --ignored`
#[cfg(test)]
mod live {
    #[test]
    #[ignore]
    fn advertise_and_browse_on_this_machine() {
        let id = super::HubIdentity {
            fingerprint: "AAAA-BBBB".into(),
            version: "0".into(),
            ..Default::default()
        };
        let (d, full) = super::start("http://localhost:3999", &id, "LiveTest").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let hits = rt
            .block_on(super::super::discover::browse_mdns(std::time::Duration::from_secs(5)))
            .unwrap();
        super::stop(&d, &full);
        let h = hits
            .iter()
            .find(|h| h.fullname.starts_with("LiveTest."))
            .expect("advertised");
        assert_eq!(h.txt["url"], "http://localhost:3999");
        assert_eq!(h.port, 3999);
    }
}
