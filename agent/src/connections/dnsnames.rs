//! 連線對應的網域名稱：讀 Windows DNS 用戶端快取（`Get-DnsClientCache`），記下「哪個 IP 是從哪個網域解析來的」，
//! 快照上傳時只附上**目前有連線**的公網 IP 對應的名稱（不是整份快取）。
//!
//! - 快取裡的紀錄 TTL 很短（CDN 常常 20–60 秒），所以每次看到就存進 `<設定目錄>/dns-names.json`（保留 24 小時、最多 5000 筆），
//!   之後連線還在、快取已過期也對得到。
//! - 不是每次快照都跑 PowerShell：只有出現還沒對到名稱的公網 IP、而且距離上次讀快取超過 2 分鐘才讀。
//! - macOS／Linux 沒有可以直接讀的系統 DNS 快取，先不做（回空的）。
//! - `scan.dns_names = false` 可以整個關掉（不讀快取、不上傳名稱）。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::store;

pub const FILE: &str = "dns-names.json";
/// 存檔裡的名稱保留多久（秒）。
pub const RETENTION_SECS: u64 = 24 * 3600;
/// 存檔最多幾組（IP, 名稱）。
pub const MAX_PAIRS: usize = 5000;
/// 兩次讀快取至少隔多久（秒）。
pub const PROBE_GAP_SECS: u64 = 120;
/// 每個 IP 最多上傳幾個名稱。
pub const MAX_NAMES_PER_IP: usize = 10;

/// 只取 A／AAAA（Type 1／28）、有資料的紀錄；每行「IP<Tab>查詢的名稱<Tab>紀錄名稱」。
pub const WINDOWS_CACHE_SCRIPT: &str = r#"
Get-DnsClientCache | Where-Object { ($_.Type -eq 1 -or $_.Type -eq 28) -and $_.Data } | ForEach-Object { "$($_.Data)`t$($_.Entry)`t$($_.Name)" }
"#;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsNames {
    /// IP → (名稱 → 最後看到的 Unix 秒)。
    pub entries: BTreeMap<String, BTreeMap<String, u64>>,
    /// 上次讀 DNS 快取的時間。
    pub last_probe: u64,
}

/// 正規化網域名稱：小寫、去掉結尾的點；不像網域（沒有點、太長、怪字元、反解用的 arpa）回 None。
pub fn normalize_name(raw: &str) -> Option<String> {
    let n = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.len() < 3 || n.len() > 253 || !n.contains('.') || n.ends_with(".arpa") {
        return None;
    }
    let ok = n.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    ok.then_some(n)
}

/// 解析 PowerShell 的輸出 → (IP, 名稱)；同一行的查詢名稱與紀錄名稱（CNAME 之後的）都算。
pub fn parse_cache(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.trim().split('\t');
        let Some(ip) = parts.next().and_then(|s| s.trim().parse::<IpAddr>().ok()) else {
            continue;
        };
        let ip = ip.to_string();
        for name in parts.filter_map(normalize_name) {
            if !out.iter().any(|(i, n)| i == &ip && n == &name) {
                out.push((ip.clone(), name));
            }
        }
    }
    out
}

impl DnsNames {
    pub fn load(dir: &Path) -> Self {
        store::read_json_opt(dir, FILE).ok().flatten().unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> crate::error::AppResult<()> {
        store::write_json_compact_in(dir, FILE, self)
    }

    pub fn merge(&mut self, pairs: &[(String, String)], now: u64) {
        for (ip, name) in pairs {
            self.entries.entry(ip.clone()).or_default().insert(name.clone(), now);
        }
    }

    /// 丟掉超過保留期限的；超過上限時從最舊的開始丟。
    pub fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(RETENTION_SECS);
        for names in self.entries.values_mut() {
            names.retain(|_, seen| *seen >= cutoff);
        }
        self.entries.retain(|_, names| !names.is_empty());
        let total: usize = self.entries.values().map(BTreeMap::len).sum();
        if total > MAX_PAIRS {
            let mut all: Vec<(u64, String, String)> = self
                .entries
                .iter()
                .flat_map(|(ip, names)| names.iter().map(move |(n, s)| (*s, ip.clone(), n.clone())))
                .collect();
            all.sort();
            for (_, ip, n) in all.into_iter().take(total - MAX_PAIRS) {
                if let Some(names) = self.entries.get_mut(&ip) {
                    names.remove(&n);
                }
            }
            self.entries.retain(|_, names| !names.is_empty());
        }
    }

    /// 有沒有必要再讀一次快取：有還沒對到名稱的 IP，而且離上次讀超過 PROBE_GAP_SECS。
    pub fn needs_probe(&self, ips: &[String], now: u64) -> bool {
        now.saturating_sub(self.last_probe) >= PROBE_GAP_SECS && ips.iter().any(|ip| !self.entries.contains_key(ip))
    }

    /// 這些 IP 對應的名稱（最近看到的在前，每個最多 MAX_NAMES_PER_IP 個）。
    pub fn names_for(&self, ips: &[String]) -> BTreeMap<String, Vec<String>> {
        let mut out = BTreeMap::new();
        for ip in ips {
            let Some(names) = self.entries.get(ip) else { continue };
            let mut v: Vec<(&String, &u64)> = names.iter().collect();
            v.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            out.insert(
                ip.clone(),
                v.into_iter().take(MAX_NAMES_PER_IP).map(|(n, _)| n.clone()).collect(),
            );
        }
        out
    }
}

/// 快照用：目前連線的公網遠端 IP（去重）。
pub fn public_remote_ips(conns: &[crate::model::connection::Connection]) -> Vec<String> {
    let mut v: Vec<String> = conns
        .iter()
        .filter_map(|c| c.remote_ip)
        .filter(|ip| crate::util::net::classify(*ip).is_public())
        .map(|ip| ip.to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 讀（必要時更新）存檔，回傳這些 IP 的名稱。非 Windows 回空的；讀快取失敗就用存檔裡已有的。
pub async fn collect(dir: &Path, ips: &[String]) -> BTreeMap<String, Vec<String>> {
    if !cfg!(windows) || ips.is_empty() {
        return BTreeMap::new();
    }
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let mut db = DnsNames::load(dir);
    if db.needs_probe(ips, now) {
        db.last_probe = now;
        let spec = crate::util::cmd::powershell(WINDOWS_CACHE_SCRIPT).timeout(15_000);
        if let Ok(out) = crate::util::cmd::CmdRunner::run(&crate::util::cmd::RealRunner, &spec).await {
            db.merge(&parse_cache(&out.stdout), now);
        }
    }
    // 連線還在的 IP：名稱的「最後看到」往後延（連線一直開著時不會因為 24 小時保留期限被丟掉）
    for ip in ips {
        if let Some(names) = db.entries.get_mut(ip) {
            for seen in names.values_mut() {
                *seen = now;
            }
        }
    }
    db.prune(now);
    let _ = db.save(dir);
    db.names_for(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects_names() {
        assert_eq!(normalize_name("WWW.Example.COM."), Some("www.example.com".into()));
        assert_eq!(normalize_name("_dmarc.example.com"), Some("_dmarc.example.com".into()));
        assert_eq!(normalize_name("localhost"), None);
        assert_eq!(normalize_name("10.2.0.192.in-addr.arpa"), None);
        assert_eq!(normalize_name("bad name.example.com"), None);
        assert_eq!(normalize_name(&format!("{}.com", "a".repeat(64))), None);
    }

    #[test]
    fn parses_cache_lines_with_cname_targets() {
        let text = "203.0.113.5\twww.example.com\te1234.dscb.akamaiedge.net\r\n\
                    203.0.113.5\twww.example.com\te1234.dscb.akamaiedge.net\r\n\
                    2001:db8::1\tv6.example.org\tv6.example.org\n\
                    garbage line\n\
                    198.51.100.7\tlocalhost\t\n";
        assert_eq!(
            parse_cache(text),
            vec![
                ("203.0.113.5".to_string(), "www.example.com".to_string()),
                ("203.0.113.5".to_string(), "e1234.dscb.akamaiedge.net".to_string()),
                ("2001:db8::1".to_string(), "v6.example.org".to_string()),
            ]
        );
    }

    #[test]
    fn probes_only_for_unknown_ips_and_after_the_gap() {
        let mut db = DnsNames::default();
        let ips = vec!["203.0.113.5".to_string()];
        assert!(db.needs_probe(&ips, 1_000));
        db.last_probe = 1_000;
        assert!(!db.needs_probe(&ips, 1_000 + PROBE_GAP_SECS - 1));
        assert!(db.needs_probe(&ips, 1_000 + PROBE_GAP_SECS));
        db.merge(&[("203.0.113.5".into(), "www.example.com".into())], 1_000);
        assert!(!db.needs_probe(&ips, 1_000 + PROBE_GAP_SECS));
    }

    #[test]
    fn prunes_old_and_caps_total_keeping_newest() {
        let mut db = DnsNames::default();
        db.merge(&[("192.0.2.1".into(), "old.example.com".into())], 10);
        db.merge(&[("192.0.2.1".into(), "new.example.com".into())], RETENTION_SECS + 20);
        db.prune(RETENTION_SECS + 20);
        assert_eq!(
            db.names_for(&["192.0.2.1".into()])["192.0.2.1"],
            vec!["new.example.com".to_string()]
        );

        let mut db = DnsNames::default();
        for i in 0..(MAX_PAIRS + 3) {
            db.merge(&[(format!("ip{}", i % 7), format!("n{i}.example.com"))], i as u64 + 100);
        }
        db.prune(MAX_PAIRS as u64 + 200);
        let total: usize = db.entries.values().map(BTreeMap::len).sum();
        assert_eq!(total, MAX_PAIRS);
        assert!(!db.entries.values().any(|n| n.contains_key("n0.example.com")));
    }

    #[test]
    fn names_for_lists_newest_first_and_caps() {
        let mut db = DnsNames::default();
        for i in 0..15u64 {
            db.merge(&[("192.0.2.9".into(), format!("h{i:02}.example.com"))], 100 + i);
        }
        let got = &db.names_for(&["192.0.2.9".into(), "192.0.2.10".into()]);
        assert_eq!(got.len(), 1);
        assert_eq!(got["192.0.2.9"].len(), MAX_NAMES_PER_IP);
        assert_eq!(got["192.0.2.9"][0], "h14.example.com");
    }
}
