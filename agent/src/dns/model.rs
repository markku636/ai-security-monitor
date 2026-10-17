//! DNS 查詢的資料形狀：蒐集端送出的單筆事件 [`DnsEvent`]，與每分鐘聚合後落地／上傳的 [`DnsRecord`]。

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 資料從哪裡來。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Windows DNS Client 的 ETW 即時事件（有 PID）。
    Etw,
    /// Windows `Microsoft-Windows-DNS-Client/Operational` 事件紀錄（有 PID）。
    EventLog,
    /// 系統 DNS 快取快照（沒有 PID）。
    Cache,
    /// Linux systemd-resolved 的查詢監看。
    Resolved,
    /// 直接監聽 53 port 的封包（Linux AF_PACKET、macOS BPF）。
    Packet,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Etw => "etw",
            Source::EventLog => "eventlog",
            Source::Cache => "cache",
            Source::Resolved => "resolved",
            Source::Packet => "packet",
        }
    }
}

/// 一次查詢的結果。
#[derive(Debug, Clone, PartialEq)]
pub struct DnsEvent {
    pub ts: DateTime<Utc>,
    /// 小寫、去掉結尾的點。
    pub name: String,
    pub qtype: u16,
    /// `NOERROR`／`NXDOMAIN`／`NODATA`／`SERVFAIL`／`REFUSED`／`TIMEOUT`／`ERR<碼>`。
    pub rcode: String,
    pub answers: Vec<IpAddr>,
    pub cnames: Vec<String>,
    /// 答案的 TTL（快取快照與封包才有）。
    pub ttl: Option<u32>,
    pub pid: Option<u32>,
    pub source: Source,
}

/// 每分鐘、每個（名稱, 類型, 程式, 結果）聚合成一列：本機落地（`dns/YYYY-MM-DD.jsonl`）與上傳 Hub 都用這個形狀。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// 這一分鐘的開始（UTC）。
    pub ts: DateTime<Utc>,
    pub name: String,
    pub qtype: u16,
    pub rcode: String,
    /// 程式名稱（例 `chrome.exe`）；快取快照與分不出程式的封包是 None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cnames: Vec<String>,
    pub source: Source,
}

/// 每列最多記幾個答案／CNAME（CDN 會回一長串）。
pub const MAX_ANSWERS: usize = 8;
pub const MAX_CNAMES: usize = 4;

/// DNS 類型代碼 → 名稱（常見的；其餘 `TYPE<n>`）。
pub fn qtype_name(t: u16) -> String {
    crate::traffic::proto::qtype_name(t)
}

/// Windows DNS 狀態碼（`QueryStatus`，Win32／DNS_ERROR）→ 結果字串。
pub fn rcode_from_win_status(status: u32) -> String {
    match status {
        0 => "NOERROR".into(),
        9001 => "FORMERR".into(),
        9002 => "SERVFAIL".into(),
        9003 => "NXDOMAIN".into(),
        9004 => "NOTIMP".into(),
        9005 => "REFUSED".into(),
        9501 => "NODATA".into(),
        1460 | 10060 => "TIMEOUT".into(),
        other => format!("ERR{other}"),
    }
}

/// DNS 封包的 RCODE → 結果字串（NOERROR 但沒有答案的由呼叫端改成 NODATA）。
pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

/// 正規化查詢名稱：小寫、去掉結尾點與空白；空的或含控制字元回 None。
pub fn normalize_name(raw: &str) -> Option<String> {
    let n = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.is_empty() || n.len() > 253 || n.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    Some(n)
}

/// 解析 Windows DNS Client 的 `QueryResults`：`type:  5 cname.example;::ffff:93.184.216.34;2606:2800::1;`。
/// 回傳（IP 答案, CNAME）。IPv4 對應的 IPv6（`::ffff:a.b.c.d`）轉回 IPv4。
pub fn parse_win_query_results(s: &str) -> (Vec<IpAddr>, Vec<String>) {
    let mut ips = Vec::new();
    let mut cnames = Vec::new();
    for part in s.split(';') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some(rest) = p.strip_prefix("type:") {
            // `type:  5 target`：CNAME（5）等非位址記錄，取最後一欄
            let mut it = rest.split_whitespace();
            let ty = it.next().and_then(|t| t.parse::<u16>().ok());
            if let (Some(5), Some(target)) = (ty, it.last()) {
                if let Some(n) = normalize_name(target) {
                    if cnames.len() < MAX_CNAMES && !cnames.contains(&n) {
                        cnames.push(n);
                    }
                }
            }
            continue;
        }
        if let Ok(ip) = p.parse::<IpAddr>() {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
                v4 => v4,
            };
            if ips.len() < MAX_ANSWERS && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    (ips, cnames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win_query_results() {
        let (ips, cn) =
            parse_win_query_results("type:  5 www.example.com.edgekey.net;::ffff:93.184.216.34;2606:2800:220:1::248;");
        assert_eq!(
            ips,
            vec![
                "93.184.216.34".parse::<IpAddr>().unwrap(),
                "2606:2800:220:1::248".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(cn, vec!["www.example.com.edgekey.net"]);
        assert_eq!(parse_win_query_results(""), (vec![], vec![]));
        assert_eq!(parse_win_query_results("garbage;;"), (vec![], vec![]));
    }

    #[test]
    fn status_and_names() {
        assert_eq!(rcode_from_win_status(0), "NOERROR");
        assert_eq!(rcode_from_win_status(9003), "NXDOMAIN");
        assert_eq!(rcode_from_win_status(9501), "NODATA");
        assert_eq!(rcode_from_win_status(123), "ERR123");
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(normalize_name(" WWW.Example.COM. ").as_deref(), Some("www.example.com"));
        assert!(normalize_name("").is_none());
        assert!(normalize_name("bad name").is_none());
        assert_eq!(qtype_name(28), "AAAA");
    }
}
