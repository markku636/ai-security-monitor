//! `ai-security-monitor vuln`：作業系統支援期限、Windows 更新多久沒裝、已安裝軟體的已知漏洞（Linux 套件查 OSV）。

use super::args::VulnArgs;
use super::render::{print_json, table};
use super::Env;
use crate::config;
use crate::error::AppResult;
use crate::util::cmd::RealRunner;
use crate::util::text::clip;
use crate::vuln::inventory::Inventory;
use crate::vuln::{self, KevSet, VulnSummary};

pub async fn run(env: &Env, a: VulnArgs) -> AppResult<()> {
    if !env.global.quiet && !env.global.json {
        eprintln!("{}", t!("讀取已安裝的軟體清單…"));
    }
    let inv = vuln::inventory::collect(&RealRunner).await?;
    if a.inventory_only {
        if env.global.json {
            print_json(&inv);
        } else {
            print_inventory(&inv, a.filter.as_deref());
        }
        return Ok(());
    }
    let cfg = config::load_or_init(&env.config_dir)?;
    let online = cfg.scan.online && !a.no_online;
    let kev = KevSet::load(&env.config_dir);
    let s = vuln::analyze(inv, &env.config_dir, online, &kev).await;
    if env.global.json {
        print_json(&s);
    } else {
        print_summary(&s);
    }
    Ok(())
}

fn status_label(s: &str) -> String {
    match s {
        "supported" => t!("支援中").into(),
        "ending_soon" => t!("即將停止支援").into(),
        "eol" => t!("已停止支援").into(),
        _ => t!("未知").into(),
    }
}

fn sev_label(s: &str) -> String {
    match s {
        "critical" => t!("嚴重").into(),
        "high" => t!("高").into(),
        "medium" => t!("中").into(),
        "low" => t!("低").into(),
        _ => t!("資訊").into(),
    }
}

fn print_inventory(inv: &Inventory, filter: Option<&str>) {
    println!(
        "{}",
        tf!(
            "{os} · 共 {n} 個軟體／套件",
            os = format!("{} {}", inv.os.name, inv.os.version).trim().to_string(),
            n = inv.packages.len()
        )
    );
    let needle = filter.map(|f| f.to_lowercase());
    let rows: Vec<Vec<String>> = inv
        .packages
        .iter()
        .filter(|p| needle.as_ref().is_none_or(|n| p.name.to_lowercase().contains(n)))
        .map(|p| {
            vec![
                clip(&p.name, 50),
                clip(&p.version, 30),
                p.ecosystem.clone(),
                clip(p.vendor.as_deref().unwrap_or(""), 30),
            ]
        })
        .collect();
    println!("{}", table(&[t!("名稱"), t!("版本"), t!("來源"), t!("發行者")], rows));
}

pub fn print_summary(s: &VulnSummary) {
    let os = format!("{} {}", s.os.name, s.os.version).trim().to_string();
    match &s.support {
        Some(sup) => {
            let left = match sup.days_left {
                Some(d) if d >= 0 => tf!("，剩 {d} 天", d = d),
                _ => String::new(),
            };
            println!(
                "{}",
                tf!(
                    "作業系統：{os} → {product}：{status}（{eol}{left}）",
                    os = os,
                    product = sup.product,
                    status = status_label(&sup.status),
                    eol = sup.eol.clone().unwrap_or_else(|| "?".into()),
                    left = left
                )
            );
        }
        None => println!("{}", tf!("作業系統：{os}", os = os)),
    }
    if let Some(p) = &s.last_patch {
        println!(
            "{}",
            tf!(
                "最近一次 Windows 更新：{id}（{date}，{days} 天前）",
                id = p.id,
                date = p.date,
                days = p.days
            )
        );
    }
    if let Some(p) = &s.pending_updates {
        println!(
            "{}",
            tf!(
                "待安裝更新：{total} 個（其中安全性 {sec} 個）",
                total = p.total,
                sec = p.security
            )
        );
    }
    let eco = s
        .by_ecosystem
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect::<Vec<_>>()
        .join(" · ");
    println!("{}", tf!("已安裝：{n} 個（{eco}）", n = s.packages, eco = eco));

    if s.app_hits.is_empty() {
        println!("\n{}", t!("內建規則沒有比對到已知漏洞版本的軟體。"));
    } else {
        println!("\n{}", t!("有已知漏洞或已停止支援的軟體"));
        let rows = s
            .app_hits
            .iter()
            .map(|h| {
                vec![
                    sev_label(&h.severity),
                    clip(&h.installed_name, 36),
                    h.installed.clone(),
                    h.fixed.clone(),
                    if h.eol {
                        t!("停止支援").to_string()
                    } else {
                        let mut c = h.cves.join(", ");
                        if !h.kev.is_empty() {
                            c.push_str(" · KEV");
                        }
                        c
                    },
                ]
            })
            .collect();
        println!(
            "{}",
            table(&[t!("嚴重度"), t!("軟體"), t!("已安裝"), t!("修正版"), "CVE"], rows)
        );
    }
    if let Some(o) = &s.osv {
        println!(
            "\n{}",
            tf!(
                "OSV（{eco}）：查了 {q} 個套件，{n} 個有已公告漏洞",
                eco = o.ecosystem,
                q = o.queried,
                n = o.packages.len()
            )
        );
        if !o.packages.is_empty() {
            let rows = o
                .packages
                .iter()
                .take(25)
                .map(|p| {
                    vec![
                        sev_label(&p.severity),
                        clip(&p.name, 30),
                        clip(&p.version, 24),
                        p.ids.len().to_string(),
                        clip(&p.cves.join(", "), 40),
                    ]
                })
                .collect();
            println!(
                "{}",
                table(&[t!("嚴重度"), t!("套件"), t!("版本"), t!("漏洞數"), "CVE"], rows)
            );
        }
    }
    if s.kev_count > 0 {
        println!(
            "\n{}",
            tf!(
                "⚠ 其中 {n} 個 CVE 在 CISA KEV（已被用於攻擊），請優先更新。",
                n = s.kev_count
            )
        );
    }
    for n in &s.notes {
        println!("· {n}");
    }
}
