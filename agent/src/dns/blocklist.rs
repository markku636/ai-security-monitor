//! DNS 黑名單：自己加的網域（條目含子網域）。兩個來源：
//! - 這台電腦的（`<設定目錄>/dns/blocklist.json`；`dns block`／`dns unblock`、桌面版 DNS 頁）；
//! - Hub 的（「防護 DNS」設定的自訂封鎖，背景服務每 10 分鐘拉一次，存在 `dns/hub-protect.json`）。
//!
//! 查到就告警（`dns.blocklisted`，就算這台沒用防護 DNS 也抓得到）；這台跑的防護 DNS 也直接擋（改了 1 分鐘內生效）。
//!
//! 白名單：這台的白名單是通用白名單（`allowlist`）裡的網域條目（`dns allow` 會加 `x` 與 `*.x` 兩筆，等於含子網域），
//! 加上 Hub 的白名單。白名單上的網域不告警、這台的防護 DNS 不擋；同一個網域，後加的那一邊勝出。

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::intel::domainset;
use crate::store;

pub const FILE: &str = "dns/blocklist.json";
/// 這台的黑名單最多幾筆（再多請用情資清單）。
pub const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub domain: String,
    pub added_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocklist {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// 使用者貼進來的東西轉成網域：去掉 `*.`、網址的 scheme／路徑／port、結尾的點；不合法回 None。
pub fn normalize(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_ascii_lowercase();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest.to_string();
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    let s = s.split(':').next().unwrap_or("");
    let s = s.trim_start_matches("*.").trim_start_matches('.');
    domainset::normalize(s)
}

impl Blocklist {
    pub fn load(config_dir: &Path) -> Blocklist {
        std::fs::read_to_string(config_dir.join(FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        store::ensure_dir(&config_dir.join("dns"))?;
        store::write_json_in(config_dir, FILE, self)
    }

    pub fn domains(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.domain.clone()).collect()
    }

    /// 加入；回傳（新加入的, 不合法的）。已經在清單上的不重複加。
    pub fn add(&mut self, raw: &[String], note: &str) -> (Vec<String>, Vec<String>) {
        let (mut added, mut bad) = (Vec::new(), Vec::new());
        for r in raw {
            let Some(d) = normalize(r) else {
                bad.push(r.clone());
                continue;
            };
            if self.entries.iter().any(|e| e.domain == d) || self.entries.len() >= MAX_ENTRIES {
                continue;
            }
            self.entries.push(Entry {
                domain: d.clone(),
                added_at: Utc::now(),
                note: note.chars().take(200).collect(),
            });
            added.push(d);
        }
        (added, bad)
    }

    /// 移除；回傳移除了哪些。
    pub fn remove(&mut self, raw: &[String]) -> Vec<String> {
        let want: Vec<String> = raw.iter().filter_map(|r| normalize(r)).collect();
        let before: Vec<String> = self.domains();
        self.entries.retain(|e| !want.contains(&e.domain));
        before.into_iter().filter(|d| want.contains(d)).collect()
    }
}

/// 黑名單條目是哪裡來的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// 這台電腦的黑名單。
    Local,
    /// Hub「防護 DNS」的自訂封鎖。
    Hub,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Local => t!("這台電腦的黑名單"),
            Source::Hub => t!("Hub 的黑名單"),
        }
    }
}

/// 兩個來源合起來比對：名稱本身或任一上層在清單上就算命中；白名單（名稱本身或任一上層）優先。
#[derive(Debug, Default)]
pub struct Matcher {
    entries: HashMap<String, Source>,
    allow: std::collections::HashSet<String>,
}

/// 這台白名單裡的網域（allowlist 的 domain 條目，`*.x` 與 `x` 都算成 `x`）。
pub fn local_allow(config_dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = crate::model::allowlist::Allowlist::load(config_dir)
        .map(|a| {
            a.entries
                .into_iter()
                .filter(|e| e.kind == crate::model::allowlist::AllowKind::Domain)
                .filter_map(|e| normalize(&e.value))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// 加進這台的白名單（含子網域：`x` 與 `*.x`），並從這台的黑名單拿掉。回傳（加入的, 不合法的）。
pub fn allow(config_dir: &Path, raw: &[String], note: &str) -> AppResult<(Vec<String>, Vec<String>)> {
    use crate::model::allowlist::{AllowKind, Allowlist};
    let mut al = Allowlist::load(config_dir)?;
    let mut bl = Blocklist::load(config_dir);
    let (mut added, mut bad) = (Vec::new(), Vec::new());
    let note = (!note.trim().is_empty()).then(|| note.trim().chars().take(200).collect::<String>());
    for r in raw {
        let Some(d) = normalize(r) else {
            bad.push(r.clone());
            continue;
        };
        al.add(Some(AllowKind::Domain), &d, note.clone())?;
        al.add(Some(AllowKind::Domain), &format!("*.{d}"), note.clone())?;
        added.push(d);
    }
    if !added.is_empty() {
        al.save(config_dir)?;
        if !bl.remove(&added).is_empty() {
            bl.save(config_dir)?;
        }
    }
    Ok((added, bad))
}

/// 從這台的白名單移除（`x` 與 `*.x`）。回傳移除了哪些網域。
pub fn unallow(config_dir: &Path, raw: &[String]) -> AppResult<Vec<String>> {
    let mut al = crate::model::allowlist::Allowlist::load(config_dir)?;
    let mut removed = Vec::new();
    for d in raw.iter().filter_map(|r| normalize(r)) {
        let a = al.remove(&d);
        let b = al.remove(&format!("*.{d}"));
        if a || b {
            removed.push(d);
        }
    }
    if !removed.is_empty() {
        al.save(config_dir)?;
    }
    Ok(removed)
}

impl Matcher {
    /// `local`／`hub`＝黑名單；`allow`＝白名單（這台的＋Hub 的）。
    pub fn new(local: &[String], hub: &[String], allow: &[String]) -> Matcher {
        let mut entries = HashMap::new();
        for d in hub.iter().filter_map(|d| normalize(d)) {
            entries.insert(d, Source::Hub);
        }
        // 兩邊都有時算這台的（使用者在這台自己加的）
        for d in local.iter().filter_map(|d| normalize(d)) {
            entries.insert(d, Source::Local);
        }
        let allow = allow.iter().filter_map(|d| normalize(d)).collect();
        Matcher { entries, allow }
    }

    pub fn load(config_dir: &Path) -> Matcher {
        let local = Blocklist::load(config_dir).domains();
        let hub = super::usehub::HubProtect::load(config_dir);
        let mut allow = local_allow(config_dir);
        allow.extend(hub.as_ref().map(|h| h.allow.clone()).unwrap_or_default());
        Matcher::new(&local, &hub.map(|h| h.block).unwrap_or_default(), &allow)
    }

    /// 名稱本身或任一上層在白名單上。
    pub fn allowed(&self, name: &str) -> bool {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        let mut cur = n.as_str();
        loop {
            if self.allow.contains(cur) {
                return true;
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return false,
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 命中的條目與來源（白名單上的不算）。
    pub fn find<'a>(&'a self, name: &str) -> Option<(&'a str, Source)> {
        if self.allowed(name) {
            return None;
        }
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        let mut cur = n.as_str();
        loop {
            if let Some((k, v)) = self.entries.get_key_value(cur) {
                return Some((k.as_str(), *v));
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_pasted_values() {
        assert_eq!(normalize("Bad.Example.").as_deref(), Some("bad.example"));
        assert_eq!(normalize("*.bad.example").as_deref(), Some("bad.example"));
        assert_eq!(
            normalize("https://user@bad.example:8443/login?x=1").as_deref(),
            Some("bad.example")
        );
        assert_eq!(normalize("not a domain"), None);
        assert_eq!(normalize("localhost"), None);
    }

    #[test]
    fn add_remove_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Blocklist::load(dir.path());
        let (added, bad) = b.add(&["bad.example".into(), "BAD.example".into(), "??".into()], "phishing");
        assert_eq!((added, bad), (vec!["bad.example".to_string()], vec!["??".to_string()]));
        b.save(dir.path()).unwrap();
        let mut b = Blocklist::load(dir.path());
        assert_eq!(b.entries[0].note, "phishing");
        assert_eq!(
            b.remove(&["https://bad.example/x".into()]),
            vec!["bad.example".to_string()]
        );
        assert!(b.entries.is_empty());
    }

    #[test]
    fn allow_list_wins_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Blocklist::default();
        b.add(&["shared.example".into()], "");
        b.save(dir.path()).unwrap();
        let (added, bad) = allow(dir.path(), &["https://shared.example/x".into(), "??".into()], "誤判").unwrap();
        assert_eq!(
            (added, bad),
            (vec!["shared.example".to_string()], vec!["??".to_string()])
        );
        // 加白名單會從這台黑名單拿掉
        assert!(Blocklist::load(dir.path()).entries.is_empty());
        assert_eq!(local_allow(dir.path()), vec!["shared.example".to_string()]);
        let m = Matcher::load(dir.path());
        assert!(m.allowed("a.shared.example"));
        assert_eq!(
            unallow(dir.path(), &["shared.example".into()]).unwrap(),
            vec!["shared.example".to_string()]
        );
        assert!(local_allow(dir.path()).is_empty());
    }

    #[test]
    fn matcher_covers_subdomains_and_sources() {
        let m = Matcher::new(
            &["local.example".into()],
            &["hub.example".into(), "local.example".into()],
            &["ok.hub.example".into()],
        );
        assert_eq!(m.find("x.ok.hub.example"), None, "allow list wins");
        assert_eq!(m.find("a.b.local.example"), Some(("local.example", Source::Local)));
        assert_eq!(m.find("HUB.example."), Some(("hub.example", Source::Hub)));
        assert_eq!(m.find("example"), None);
        assert_eq!(m.find("nothub.example"), None);
    }
}
