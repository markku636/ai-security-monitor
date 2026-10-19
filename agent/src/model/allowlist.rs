//! 白名單（`<config>/allowlist.json`）：單一 finding / ip / cidr / 行程路徑 glob / domain 萬用字元 / `rule:port`。
//! 命中的 finding 標 `suppressed_by`，連線判定直接 Safe。

use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::model::finding::{Evidence, Finding};
use crate::store;

pub const ALLOWLIST_FILE: &str = "allowlist.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum AllowKind {
    Finding,
    Ip,
    Cidr,
    ProcessPath,
    Domain,
    Rule,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowEntry {
    pub id: String,
    pub kind: AllowKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub added_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Allowlist {
    pub schema_version: u32,
    pub entries: Vec<AllowEntry>,
}

impl Allowlist {
    pub fn load(dir: &Path) -> AppResult<Allowlist> {
        store::read_json_in(dir, ALLOWLIST_FILE)
    }

    pub fn save(&self, dir: &Path) -> AppResult<()> {
        store::write_json_in(dir, ALLOWLIST_FILE, self)
    }

    /// 推斷種類：`f_` 穩定 finding id → finding；可解析成 IP → ip；含 `/` 且可解析 → cidr；含 `:` 且前段像規則名 → rule；
    /// 含路徑分隔或 `*` 且非 domain → process_path；否則 domain。
    pub fn infer_kind(value: &str) -> AllowKind {
        if is_finding_id(value) {
            return AllowKind::Finding;
        }
        if value.parse::<IpAddr>().is_ok() {
            return AllowKind::Ip;
        }
        if value.parse::<IpNet>().is_ok() {
            return AllowKind::Cidr;
        }
        if let Some((rule, _)) = value.split_once(':') {
            if rule.contains('.') && rule.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_') {
                return AllowKind::Rule;
            }
        }
        if value.contains('/') || value.contains('\\') || value.ends_with(".exe") {
            return AllowKind::ProcessPath;
        }
        AllowKind::Domain
    }

    pub fn add(&mut self, kind: Option<AllowKind>, value: &str, note: Option<String>) -> AppResult<&AllowEntry> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AppError::InvalidArg(t!("白名單值不可為空").into()));
        }
        let kind = kind.unwrap_or_else(|| Self::infer_kind(value));
        match kind {
            AllowKind::Finding => {
                if !is_finding_id(value) {
                    return Err(AppError::InvalidArg(tf!(
                        "不是合法的掃描項目 ID：{value}",
                        value = value
                    )));
                }
            }
            AllowKind::Ip => {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| AppError::InvalidArg(tf!("不是合法的 IP：{value}", value = value)))?;
            }
            AllowKind::Cidr => {
                value
                    .parse::<IpNet>()
                    .map_err(|_| AppError::InvalidArg(tf!("不是合法的 CIDR：{value}", value = value)))?;
            }
            AllowKind::ProcessPath => {
                globset::Glob::new(value).map_err(|e| AppError::InvalidArg(tf!("路徑樣式無效：{e}", e = e)))?;
            }
            AllowKind::Domain | AllowKind::Rule => {}
        }
        if let Some(existing) = self.entries.iter().position(|e| e.kind == kind && e.value == value) {
            return Ok(&self.entries[existing]);
        }
        let id = format!("al_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        self.entries.push(AllowEntry {
            id,
            kind,
            value: value.to_string(),
            note,
            added_at: crate::util::time::now_iso(),
        });
        if self.schema_version == 0 {
            self.schema_version = 1;
        }
        Ok(self.entries.last().expect("just pushed"))
    }

    /// 以 id 或 value 移除；回傳是否有移除。
    pub fn remove(&mut self, id_or_value: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id_or_value && e.value != id_or_value);
        before != self.entries.len()
    }

    pub fn match_ip(&self, ip: IpAddr) -> Option<&AllowEntry> {
        self.entries.iter().find(|e| match e.kind {
            AllowKind::Ip => e.value.parse::<IpAddr>().map(|v| v == ip).unwrap_or(false),
            AllowKind::Cidr => e.value.parse::<IpNet>().map(|n| n.contains(&ip)).unwrap_or(false),
            _ => false,
        })
    }

    /// 網段內含任何白名單 IP / CIDR（或被其包含）。
    pub fn overlaps_net(&self, net: &IpNet) -> Option<&AllowEntry> {
        self.entries.iter().find(|e| match e.kind {
            AllowKind::Ip => e.value.parse::<IpAddr>().map(|ip| net.contains(&ip)).unwrap_or(false),
            AllowKind::Cidr => e
                .value
                .parse::<IpNet>()
                .map(|n| n.contains(&net.network()) || net.contains(&n.network()))
                .unwrap_or(false),
            _ => false,
        })
    }

    pub fn match_process_path(&self, path: &str) -> Option<&AllowEntry> {
        let norm = path.replace('\\', "/");
        self.entries
            .iter()
            .filter(|e| e.kind == AllowKind::ProcessPath)
            .find(|e| {
                let pat = e.value.replace('\\', "/");
                globset::GlobBuilder::new(&pat)
                    .case_insensitive(cfg!(windows))
                    .literal_separator(false)
                    .build()
                    .map(|g| g.compile_matcher().is_match(&norm))
                    .unwrap_or(false)
            })
    }

    /// `*.example.com` 匹配子網域（不含裸網域）；`example.com` 精確匹配。
    pub fn match_domain(&self, domain: &str) -> Option<&AllowEntry> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        self.entries.iter().filter(|e| e.kind == AllowKind::Domain).find(|e| {
            let v = e.value.to_ascii_lowercase();
            if let Some(suffix) = v.strip_prefix("*.") {
                d.ends_with(&format!(".{suffix}"))
            } else {
                d == v
            }
        })
    }

    /// `rule` 條目格式 `<rule>:<port>` 或 `<rule>`（全部 port）。
    pub fn match_rule(&self, rule: &str, port: Option<u16>) -> Option<&AllowEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == AllowKind::Rule)
            .find(|e| match e.value.split_once(':') {
                Some((r, p)) => r == rule && port.map(|x| p == x.to_string()).unwrap_or(false),
                None => e.value == rule,
            })
    }

    /// 找出會排除這一筆掃描結果的條目。精準的 finding id 優先，其次沿用既有的規則、IP、行程與網域白名單。
    pub fn match_finding(&self, finding: &Finding) -> Option<&AllowEntry> {
        if self.entries.is_empty() {
            return None;
        }
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.kind == AllowKind::Finding && entry.value == finding.id)
        {
            return Some(entry);
        }
        let port = match &finding.evidence {
            Evidence::Connection(connection) => connection.remote_port.or(Some(connection.local_port)),
            Evidence::Port { port, .. } => Some(*port),
            _ => None,
        };
        if let Some(entry) = self.match_rule(&finding.rule, port) {
            return Some(entry);
        }
        match &finding.evidence {
            Evidence::Connection(connection) => {
                if let Some(ip) = connection.remote_ip {
                    if let Some(entry) = self.match_ip(ip) {
                        return Some(entry);
                    }
                }
                if let Some(exe) = connection.process.as_ref().and_then(|process| process.exe.as_deref()) {
                    if let Some(entry) = self.match_process_path(exe) {
                        return Some(entry);
                    }
                }
            }
            Evidence::Process { exe: Some(exe), .. } => {
                if let Some(entry) = self.match_process_path(exe) {
                    return Some(entry);
                }
            }
            Evidence::Flow { remote, domain, .. } => {
                if let Some(ip) = remote.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()) {
                    if let Some(entry) = self.match_ip(ip) {
                        return Some(entry);
                    }
                }
                if let Some(domain) = domain {
                    if let Some(entry) = self.match_domain(domain) {
                        return Some(entry);
                    }
                }
            }
            _ => {}
        }
        None
    }
}

fn is_finding_id(value: &str) -> bool {
    value
        .strip_prefix("f_")
        .is_some_and(|suffix| suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_and_match() {
        let mut a = Allowlist::default();
        a.add(None, "10.0.0.0/8", None).unwrap();
        a.add(None, "8.8.8.8", None).unwrap();
        a.add(None, "C:\\Program Files\\Docker\\**", Some("docker".into()))
            .unwrap();
        a.add(None, "*.example.com", None).unwrap();
        a.add(None, "connections.risky_port:3389", None).unwrap();
        assert_eq!(a.entries.len(), 5);
        assert_eq!(a.entries[0].kind, AllowKind::Cidr);
        assert_eq!(a.entries[1].kind, AllowKind::Ip);
        assert_eq!(a.entries[2].kind, AllowKind::ProcessPath);
        assert_eq!(a.entries[3].kind, AllowKind::Domain);
        assert_eq!(a.entries[4].kind, AllowKind::Rule);

        assert!(a.match_ip("10.1.2.3".parse().unwrap()).is_some());
        assert!(a.match_ip("8.8.8.8".parse().unwrap()).is_some());
        assert!(a.match_ip("8.8.4.4".parse().unwrap()).is_none());
        assert!(a
            .match_process_path("C:\\Program Files\\Docker\\resources\\com.docker.backend.exe")
            .is_some());
        assert!(a.match_process_path("C:\\Windows\\System32\\svchost.exe").is_none());
        assert!(a.match_domain("cdn.example.com").is_some());
        assert!(a.match_domain("example.com").is_none());
        assert!(a.match_rule("connections.risky_port", Some(3389)).is_some());
        assert!(a.match_rule("connections.risky_port", Some(4444)).is_none());
    }

    #[test]
    fn add_dedups_and_remove_by_id_or_value() {
        let mut a = Allowlist::default();
        let id = a.add(None, "1.2.3.4", None).unwrap().id.clone();
        a.add(None, "1.2.3.4", None).unwrap();
        assert_eq!(a.entries.len(), 1);
        assert!(a.remove(&id));
        assert!(a.entries.is_empty());
        a.add(None, "1.2.3.4", None).unwrap();
        assert!(a.remove("1.2.3.4"));
        assert!(!a.remove("nothing"));
    }

    #[test]
    fn rejects_bad_values() {
        let mut a = Allowlist::default();
        assert!(a.add(Some(AllowKind::Ip), "999.1.1.1", None).is_err());
        assert!(a.add(Some(AllowKind::Cidr), "10.0.0.0/99", None).is_err());
        assert!(a.add(Some(AllowKind::Finding), "f_not-a-valid-id", None).is_err());
        assert!(a.add(None, "", None).is_err());
    }

    #[test]
    fn exact_finding_entry_only_matches_that_finding() {
        use crate::model::finding::{ScannerId, Severity};

        let first = Finding::new(
            ScannerId::Files,
            "fim.autorun.service.added",
            "service|first",
            Severity::High,
            "first",
            "detail",
            Evidence::Text { detail: "first".into() },
            "recommendation",
        );
        let second = Finding::new(
            ScannerId::Files,
            "fim.autorun.service.added",
            "service|second",
            Severity::High,
            "second",
            "detail",
            Evidence::Text {
                detail: "second".into(),
            },
            "recommendation",
        );
        let mut allowlist = Allowlist::default();
        allowlist
            .add(Some(AllowKind::Finding), &first.id, Some("已由 IT 確認".into()))
            .unwrap();

        assert!(allowlist.match_finding(&first).is_some());
        assert!(allowlist.match_finding(&second).is_none());
    }
}
