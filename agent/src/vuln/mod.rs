//! 漏洞與弱點：軟體清單、作業系統是否仍在支援、Windows 更新是否過舊／Linux 待更新、常見軟體的已知漏洞版本、
//! Linux 套件查 OSV（線上，24 小時快取）；CVE 若在 CISA KEV（已被用於攻擊）就升為嚴重。

pub mod inventory;
pub mod osv;
pub mod rules;
pub mod version;

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::AppResult;
use crate::model::finding::{Evidence, Finding, ScannerId, Severity};
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};
use inventory::{Inventory, OsInfo};
use rules::{AppHit, OsSupport};

/// Windows 超過這麼多天沒裝更新就提醒。
pub const PATCH_STALE_DAYS: i64 = 45;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VulnSummary {
    pub os: OsInfo,
    pub support: Option<OsSupport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_patch: Option<LastPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_updates: Option<Pending>,
    pub packages: u32,
    pub by_ecosystem: BTreeMap<String, u32>,
    pub app_hits: Vec<AppHit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub osv: Option<osv::OsvResult>,
    pub kev_count: u32,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LastPatch {
    pub date: String,
    pub id: String,
    pub days: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    pub total: u32,
    pub security: u32,
}

/// CISA KEV（已被用於攻擊的漏洞）清單；由 `asa intel update` 下載的 cisa-kev 來源讀出。
#[derive(Debug, Clone, Default)]
pub struct KevSet(HashSet<String>);

impl KevSet {
    pub fn load(config_dir: &Path) -> KevSet {
        let p = crate::intel::fetch::feed_dir(config_dir, "cisa-kev").join(crate::intel::fetch::DATA_FILE);
        std::fs::read(p).map(|b| Self::parse(&b)).unwrap_or_default()
    }

    pub fn parse(bytes: &[u8]) -> KevSet {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap_or_default();
        KevSet(
            v["vulnerabilities"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x["cveID"].as_str())
                        .map(|c| c.to_ascii_uppercase())
                        .collect()
                })
                .unwrap_or_default(),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, cve: &str) -> bool {
        self.0.contains(&cve.to_ascii_uppercase())
    }
}

pub async fn analyze(inv: Inventory, config_dir: &Path, online: bool, kev: &KevSet) -> VulnSummary {
    let today = rules::today();
    let is_kev = |c: &str| kev.contains(c);
    let mut s = VulnSummary {
        support: Some(rules::os_support(&inv.os, today)),
        packages: inv.packages.len() as u32,
        by_ecosystem: inv.by_ecosystem(),
        app_hits: rules::match_apps(&inv.packages, &rules::app_rules(), &is_kev),
        notes: inv.notes.clone(),
        ..Default::default()
    };
    if kev.is_empty() {
        s.notes
            .push(t!("尚未下載 CISA KEV（執行 asa intel update），無法標示「已被用於攻擊」的漏洞").to_string());
    }
    if let (Some((d, id)), Some(days)) = (&inv.last_patch, rules::patch_age_days(&inv, today)) {
        s.last_patch = Some(LastPatch {
            date: d.clone(),
            id: id.clone(),
            days,
        });
    }
    s.pending_updates = inv.pending_updates.map(|(total, security)| Pending { total, security });
    if online && osv::ecosystem(&inv.os).is_some() {
        match osv::scan(config_dir, &inv, osv::API, &is_kev).await {
            Ok(r) => s.osv = r,
            Err(e) => s.notes.push(e.message()),
        }
    }
    s.kev_count = s.app_hits.iter().map(|h| h.kev.len() as u32).sum::<u32>()
        + s.osv
            .as_ref()
            .map(|o| o.packages.iter().map(|p| p.kev.len() as u32).sum())
            .unwrap_or(0);
    s.os = inv.os;
    s
}

fn sev(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn findings_from(s: &VulnSummary) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(sup) = &s.support {
        let (rule, severity, title) = match sup.status.as_str() {
            "eol" => (
                "vuln.os_eol",
                Severity::High,
                tf!(
                    "作業系統已停止支援：{product}（{eol}）",
                    product = sup.product,
                    eol = sup.eol.clone().unwrap_or_default()
                ),
            ),
            "ending_soon" => (
                "vuln.os_eol_soon",
                Severity::Medium,
                tf!(
                    "作業系統即將停止支援：{product}（{eol}，剩 {days} 天）",
                    product = sup.product,
                    eol = sup.eol.clone().unwrap_or_default(),
                    days = sup.days_left.unwrap_or(0)
                ),
            ),
            _ => ("", Severity::Info, String::new()),
        };
        if !rule.is_empty() {
            out.push(
                Finding::new(
                    ScannerId::Vuln,
                    rule,
                    &sup.product,
                    severity,
                    title,
                    sup.note
                        .clone()
                        .unwrap_or_else(|| t!("停止支援後就不再有安全性更新，新發現的漏洞都不會被修補。").to_string()),
                    Evidence::Text {
                        detail: format!("{} {}", s.os.name, s.os.version),
                    },
                    t!("升級到仍在支援的版本（Windows 用「設定 → Windows Update」，Linux 升級發行版）"),
                )
                .with_tag("eol"),
            );
        }
    }
    if let Some(p) = &s.last_patch {
        if p.days > PATCH_STALE_DAYS {
            out.push(Finding::new(
                ScannerId::Vuln,
                "vuln.updates_stale",
                "windows-update",
                if p.days > 90 { Severity::High } else { Severity::Medium },
                tf!("已經 {days} 天沒有安裝 Windows 更新", days = p.days),
                tf!("最近一次：{id}（{date}）", id = p.id, date = p.date),
                Evidence::Text {
                    detail: format!("{} {}", p.id, p.date),
                },
                t!("到「設定 → Windows Update」檢查並安裝更新"),
            ));
        }
    }
    if let Some(p) = &s.pending_updates {
        if p.security > 0 {
            out.push(Finding::new(
                ScannerId::Vuln,
                "vuln.pending_security_updates",
                "pending-security",
                Severity::Medium,
                tf!(
                    "有 {n} 個安全性更新還沒安裝（共 {total} 個待更新）",
                    n = p.security,
                    total = p.total
                ),
                String::new(),
                Evidence::Text {
                    detail: format!("{}/{}", p.security, p.total),
                },
                t!("執行 sudo apt update && sudo apt upgrade（或發行版對應的更新指令）"),
            ));
        }
    }
    for h in &s.app_hits {
        // 顯示名稱多半已含版本（「Python 3.10.10 (64-bit)」），比登錄檔版本（3.10.10150.0）好懂
        let shown = if h.installed_name.chars().any(|c| c.is_ascii_digit()) {
            h.installed_name.clone()
        } else {
            format!("{} {}", h.app, h.installed)
        };
        let title = if h.eol {
            tf!("{app} 已停止支援", app = shown)
        } else {
            tf!("{app} 有已知漏洞（{cves}）", app = shown, cves = h.cves.join(", "))
        };
        let mut f = Finding::new(
            ScannerId::Vuln,
            &format!("vuln.app.{}", h.rule_id),
            &format!("{}|{}", h.installed_name, h.installed),
            sev(&h.severity),
            title,
            h.summary.clone(),
            Evidence::Package {
                ecosystem: "app".into(),
                name: h.installed_name.clone(),
                version: h.installed.clone(),
                purl: None,
                fixed_version: Some(h.fixed.clone()),
            },
            h.fix.clone(),
        )
        .with_ref(&h.reference);
        if !h.kev.is_empty() {
            f = f.with_tag("kev");
        }
        out.push(f);
    }
    if let Some(o) = &s.osv {
        for p in o.packages.iter().filter(|p| p.severity != "low").take(30) {
            let mut f = Finding::new(
                ScannerId::Vuln,
                "vuln.osv_package",
                &format!("{}|{}", p.name, p.version),
                sev(&p.severity),
                tf!(
                    "{name} {ver} 有 {n} 個已公告漏洞",
                    name = p.name,
                    ver = p.version,
                    n = p.ids.len()
                ),
                if p.summary.is_empty() {
                    p.cves.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
                } else {
                    p.summary.clone()
                },
                Evidence::Package {
                    ecosystem: o.ecosystem.clone(),
                    name: p.name.clone(),
                    version: p.version.clone(),
                    purl: None,
                    fixed_version: None,
                },
                t!("更新這個套件（apt／dnf／apk upgrade）"),
            )
            .with_ref(&format!(
                "https://osv.dev/list?ecosystem={}&q={}",
                o.ecosystem.replace(' ', "+"),
                p.name
            ));
            if !p.kev.is_empty() {
                f = f.with_tag("kev");
            }
            out.push(f);
        }
    }
    out
}

pub struct VulnScanner;

#[async_trait]
impl Scanner for VulnScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Vuln
    }

    fn elevation(&self) -> Elevation {
        Elevation::NotNeeded
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let inv = inventory::collect(ctx.runner.as_ref()).await?;
        {
            let mut shared = ctx.shared.lock().await;
            shared.inventory = Some(json!({ "packages": inv.packages.len(), "by_ecosystem": inv.by_ecosystem() }));
        }
        let kev = KevSet::load(&ctx.config_dir);
        let summary = analyze(inv, &ctx.config_dir, ctx.online, &kev).await;
        let warnings = summary.notes.iter().filter(|n| n.contains("OSV")).cloned().collect();
        Ok(ScanOutput {
            findings: findings_from(&summary),
            warnings,
            summary: serde_json::to_value(&summary).ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_cover_eol_patch_and_apps() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let d = tempfile::tempdir().unwrap();
        let inv = inventory::parse_windows(
            r#"{"apps":[{"n":"7-Zip 24.08 (x64)","v":"24.08","p":"Igor Pavlov"},{"n":"Node.js","v":"18.20.4","p":"Node.js Foundation"}],"hotfix_date":"2026-01-02","hotfix_id":"KB5050000","caption":"Microsoft Windows 10 Pro","build":"19045","edition":"Professional"}"#,
        );
        let kev = KevSet::parse(br#"{"vulnerabilities":[{"cveID":"CVE-2025-0411"}]}"#);
        assert_eq!(kev.len(), 1);
        let s = rt.block_on(analyze(inv, d.path(), false, &kev));
        assert_eq!(s.kev_count, 1);
        assert_eq!(s.support.as_ref().unwrap().status, "eol");
        assert!(s.last_patch.as_ref().unwrap().days > 200);
        let f = findings_from(&s);
        let rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(
            rules,
            vec![
                "vuln.os_eol",
                "vuln.updates_stale",
                "vuln.app.7zip-cve-2025-0411",
                "vuln.app.nodejs-eol"
            ]
        );
        assert_eq!(f[1].severity, Severity::High);
        assert_eq!(f[2].severity, Severity::Critical);
        assert!(f[2].tags.contains(&"kev".to_string()));
        assert_eq!(f[2].refs[0], "https://nvd.nist.gov/vuln/detail/CVE-2025-0411");
        assert_eq!(s.packages, 2);
        assert_eq!(s.by_ecosystem.get("windows"), Some(&2));
    }
}
