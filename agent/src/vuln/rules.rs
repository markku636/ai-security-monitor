//! 規則：常見軟體的已知漏洞版本（feeds/vuln/curated-apps.json）、作業系統支援期限（feeds/vuln/os-eol.json）、更新是否過舊。

use chrono::{NaiveDate, Utc};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

use super::inventory::{Inventory, OsInfo, Package};
use super::version::older_than;

pub use crate::i18n::Localized;

#[derive(Debug, Clone, Deserialize)]
pub struct AppRule {
    pub id: String,
    pub app: String,
    #[serde(rename = "match")]
    pub patterns: Vec<String>,
    pub platforms: Vec<String>,
    pub fixed: String,
    #[serde(default)]
    pub cves: Vec<String>,
    pub severity: String,
    #[serde(default)]
    pub eol: bool,
    pub summary: Localized,
    pub fix: Localized,
    #[serde(default)]
    pub r#ref: Option<String>,
}

#[derive(Deserialize, Default)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<AppRule>,
}

pub fn app_rules() -> Vec<AppRule> {
    let text = crate::embedded::feeds_file("vuln/curated-apps.json").unwrap_or("{}");
    serde_json::from_str::<RulesFile>(text).unwrap_or_default().rules
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppHit {
    pub rule_id: String,
    pub app: String,
    pub installed_name: String,
    pub installed: String,
    pub fixed: String,
    pub cves: Vec<String>,
    pub kev: Vec<String>,
    pub severity: String,
    pub eol: bool,
    pub summary: String,
    pub fix: String,
    pub reference: String,
}

fn platform_of(p: &Package) -> &'static str {
    match p.ecosystem.as_str() {
        "windows" => "windows",
        "macos-app" | "brew" | "brew-cask" => "macos",
        _ => "linux",
    }
}

/// 比對清單與規則；`is_kev` 判斷 CVE 是否在 CISA KEV。
pub fn match_apps(packages: &[Package], rules: &[AppRule], is_kev: &dyn Fn(&str) -> bool) -> Vec<AppHit> {
    let mut out: Vec<AppHit> = Vec::new();
    for r in rules {
        let res: Vec<regex::Regex> = r
            .patterns
            .iter()
            .filter_map(|p| {
                RegexBuilder::new(&if p.starts_with('^') {
                    p.clone()
                } else {
                    regex::escape(p)
                })
                .case_insensitive(true)
                .build()
                .ok()
            })
            .collect();
        for p in packages {
            if !r.platforms.iter().any(|x| x == platform_of(p)) || !res.iter().any(|re| re.is_match(&p.name)) {
                continue;
            }
            if !older_than(&p.version, &r.fixed) {
                continue;
            }
            if out.iter().any(|h| h.rule_id == r.id && h.installed == p.version) {
                continue;
            }
            let kev: Vec<String> = r.cves.iter().filter(|c| is_kev(c)).cloned().collect();
            out.push(AppHit {
                rule_id: r.id.clone(),
                app: r.app.clone(),
                installed_name: p.name.clone(),
                installed: p.version.clone(),
                fixed: r.fixed.clone(),
                cves: r.cves.clone(),
                severity: if kev.is_empty() {
                    r.severity.clone()
                } else {
                    "critical".into()
                },
                kev,
                eol: r.eol,
                summary: r.summary.get(),
                fix: r.fix.get(),
                reference: r
                    .r#ref
                    .clone()
                    .or_else(|| r.cves.first().map(|c| format!("https://nvd.nist.gov/vuln/detail/{c}")))
                    .unwrap_or_default(),
            });
        }
    }
    out
}

// ---------------- 作業系統支援期限 ----------------

#[derive(Deserialize, Default)]
struct EolFile {
    #[serde(default)]
    windows: Vec<WinEol>,
    #[serde(default)]
    windows_server: Vec<ServerEol>,
    #[serde(default)]
    linux: Vec<LinuxEol>,
    #[serde(default)]
    macos: Vec<MacEol>,
}

#[derive(Deserialize)]
struct WinEol {
    name: String,
    min_build: u32,
    max_build: u32,
    eol: String,
    enterprise_eol: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct ServerEol {
    name: String,
    #[serde(rename = "match")]
    m: String,
    eol: String,
}

#[derive(Deserialize)]
struct LinuxEol {
    id: String,
    version: String,
    eol: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct MacEol {
    major: u32,
    eol: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsSupport {
    pub product: String,
    pub eol: Option<String>,
    /// supported | ending_soon（90 天內）| eol | unknown
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn status_for(eol: &str, today: NaiveDate) -> (String, Option<i64>) {
    match NaiveDate::parse_from_str(eol, "%Y-%m-%d") {
        Ok(d) => {
            let left = (d - today).num_days();
            let s = if left < 0 {
                "eol"
            } else if left <= 90 {
                "ending_soon"
            } else {
                "supported"
            };
            (s.into(), Some(left))
        }
        Err(_) => ("unknown".into(), None),
    }
}

pub fn os_support(os: &OsInfo, today: NaiveDate) -> OsSupport {
    let text = crate::embedded::feeds_file("vuln/os-eol.json").unwrap_or("{}");
    let f: EolFile = serde_json::from_str(text).unwrap_or_default();
    let unknown = |product: String| OsSupport {
        product,
        eol: None,
        status: "unknown".into(),
        days_left: None,
        note: None,
    };
    let make = |product: String, eol: String, note: Option<String>| {
        let (status, days_left) = status_for(&eol, today);
        OsSupport {
            product,
            eol: Some(eol),
            status,
            days_left,
            note,
        }
    };
    match os.family.as_str() {
        "windows" if os.server => match f.windows_server.iter().find(|s| os.name.contains(&s.m)) {
            Some(s) => make(s.name.clone(), s.eol.clone(), None),
            None => unknown(os.name.clone()),
        },
        "windows" => {
            let Some(build) = os.build else {
                return unknown(os.name.clone());
            };
            match f.windows.iter().find(|w| (w.min_build..=w.max_build).contains(&build)) {
                Some(w) => {
                    let ent = os
                        .edition
                        .as_deref()
                        .map(|e| e.contains("Enterprise") || e.contains("Education"))
                        .unwrap_or(false);
                    make(
                        w.name.clone(),
                        if ent { w.enterprise_eol.clone() } else { w.eol.clone() },
                        w.note.clone(),
                    )
                }
                None => unknown(format!("{} (build {build})", os.name)),
            }
        }
        "macos" => {
            let major: u32 = os.version.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
            match f.macos.iter().find(|m| m.major == major) {
                Some(m) => make(format!("macOS {}", os.version), m.eol.clone(), m.note.clone()),
                None => unknown(format!("macOS {}", os.version)),
            }
        }
        _ => {
            let id = os.distro.clone().unwrap_or_default();
            let ver = os.distro_version.clone().unwrap_or_default();
            // RHEL 系列只看主版本
            let key = if matches!(id.as_str(), "rhel" | "rocky" | "almalinux" | "centos" | "debian") {
                ver.split('.').next().unwrap_or("").to_string()
            } else if id == "alpine" {
                ver.split('.').take(2).collect::<Vec<_>>().join(".")
            } else {
                ver.clone()
            };
            match f.linux.iter().find(|l| l.id == id && l.version == key) {
                Some(l) => make(os.name.clone(), l.eol.clone(), l.note.clone()),
                None => unknown(os.name.clone()),
            }
        }
    }
}

/// 距離上次安裝 Windows 更新幾天。
pub fn patch_age_days(inv: &Inventory, today: NaiveDate) -> Option<i64> {
    let (d, _) = inv.last_patch.as_ref()?;
    NaiveDate::parse_from_str(d, "%Y-%m-%d")
        .ok()
        .map(|p| (today - p).num_days())
}

pub fn today() -> NaiveDate {
    Utc::now().date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: &str, name: &str, ver: &str) -> Package {
        Package {
            ecosystem: eco.into(),
            name: name.into(),
            version: ver.into(),
            vendor: None,
            source: None,
            source_version: None,
        }
    }

    #[test]
    fn curated_rules_match_old_versions_and_kev() {
        let rules = app_rules();
        assert!(rules.len() >= 9);
        let pk = vec![
            pkg("windows", "7-Zip 24.08 (x64)", "24.08"),
            pkg("windows", "WinRAR 7.13 (64-bit)", "7.13.0"),
            pkg("windows", "Git", "2.44.0"),
            pkg("windows", "Node.js", "20.11.0"),
            pkg("windows", "Python 3.12.4 (64-bit)", "3.12.4150.0"),
            pkg("windows", "Python Launcher", "3.9.0"),
            pkg("dpkg", "git", "1:2.43.0-1ubuntu7"),
            pkg("macos-app", "Google Chrome", "141.0.7390.55"),
        ];
        let hits = match_apps(&pk, &rules, &|c| c == "CVE-2025-0411");
        let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "7zip-cve-2025-0411",
                "git-cve-2024-32002",
                "git-cve-2024-32002",
                "nodejs-eol"
            ]
        );
        assert_eq!(hits[0].severity, "critical");
        assert_eq!(hits[0].kev, vec!["CVE-2025-0411".to_string()]);
        assert_eq!(hits[1].reference, "https://nvd.nist.gov/vuln/detail/CVE-2024-32002");
        assert!(hits[3].eol);
    }

    #[test]
    fn os_end_of_life() {
        let d = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        let win = |build: u32, edition: &str| OsInfo {
            family: "windows".into(),
            name: "Microsoft Windows".into(),
            build: Some(build),
            edition: Some(edition.into()),
            ..Default::default()
        };
        assert_eq!(os_support(&win(19045, "Professional"), d).status, "eol");
        assert_eq!(os_support(&win(26100, "Professional"), d).status, "eol");
        assert_eq!(os_support(&win(26100, "Enterprise"), d).status, "supported");
        assert_eq!(os_support(&win(26200, "Professional"), d).status, "supported");
        assert_eq!(os_support(&win(22631, "Enterprise"), d).status, "ending_soon");
        let server = OsInfo {
            family: "windows".into(),
            name: "Microsoft Windows Server 2016 Standard".into(),
            server: true,
            ..Default::default()
        };
        assert_eq!(os_support(&server, d).product, "Windows Server 2016");
        let linux = |id: &str, ver: &str| OsInfo {
            family: "linux".into(),
            name: format!("{id} {ver}"),
            distro: Some(id.into()),
            distro_version: Some(ver.into()),
            ..Default::default()
        };
        assert_eq!(os_support(&linux("ubuntu", "20.04"), d).status, "eol");
        assert_eq!(os_support(&linux("ubuntu", "24.04"), d).status, "supported");
        assert_eq!(os_support(&linux("rocky", "9.4"), d).status, "supported");
        assert_eq!(os_support(&linux("alpine", "3.21.2"), d).status, "ending_soon");
        assert_eq!(os_support(&linux("arch", ""), d).status, "unknown");
        let mac = OsInfo {
            family: "macos".into(),
            version: "13.6.1".into(),
            ..Default::default()
        };
        assert_eq!(os_support(&mac, d).status, "eol");
    }
}
