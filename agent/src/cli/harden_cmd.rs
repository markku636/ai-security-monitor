//! `asa harden`：系統硬化檢查（策略在 feeds/policies/<os>.yml，可用 <設定目錄>/policies/*.yml 增修）。

use super::args::HardenArgs;
use super::render::{print_json, table};
use super::Env;
use crate::error::AppResult;
use crate::hardening::{self, HardeningReport};
use crate::model::finding::{CheckResult, Severity};
use crate::util::cmd::RealRunner;
use crate::util::text::clip;

pub async fn run(env: &Env, a: HardenArgs) -> AppResult<()> {
    let (penv, distros) = hardening::current_env();
    let mut r = hardening::run_checks(&env.config_dir, &RealRunner, &penv, &distros).await;
    if let Some(cat) = &a.category {
        r.results.retain(|o| o.category.eq_ignore_ascii_case(cat));
    }
    if env.global.json {
        print_json(&r);
    } else {
        print_report(&r, a.all);
    }
    Ok(())
}

fn result_label(r: &CheckResult) -> String {
    match r {
        CheckResult::Pass => t!("通過").into(),
        CheckResult::Fail => t!("未通過").into(),
        CheckResult::NotApplicable => t!("不適用").into(),
        CheckResult::Error => t!("錯誤").into(),
    }
}

fn sev_label(s: Severity) -> String {
    match s {
        Severity::Critical => t!("嚴重").into(),
        Severity::High => t!("高").into(),
        Severity::Medium => t!("中").into(),
        Severity::Low => t!("低").into(),
        Severity::Info => t!("資訊").into(),
    }
}

pub fn print_report(r: &HardeningReport, all: bool) {
    println!(
        "{}",
        tf!(
            "硬化分數 {score}/100 · 通過 {pass} · 未通過 {fail} · 不適用 {na} · 錯誤 {error}",
            score = r.score,
            pass = r.pass,
            fail = r.fail,
            na = r.na,
            error = r.error
        )
    );
    let mut rows: Vec<_> = r
        .results
        .iter()
        .filter(|o| all || o.result == CheckResult::Fail)
        .collect();
    // 未通過的依嚴重度排前面
    rows.sort_by_key(|o| (o.result != CheckResult::Fail, std::cmp::Reverse(o.severity)));
    if rows.is_empty() {
        println!("\n{}", t!("全部通過。"));
    } else if all {
        let rows = rows
            .iter()
            .map(|o| {
                vec![
                    result_label(&o.result),
                    sev_label(o.severity),
                    clip(&o.title, 44),
                    clip(
                        if o.observed.is_empty() {
                            o.note.as_deref().unwrap_or("")
                        } else {
                            &o.observed
                        },
                        30,
                    ),
                ]
            })
            .collect();
        println!("\n{}", table(&[t!("結果"), t!("嚴重度"), t!("檢查"), t!("目前")], rows));
    } else {
        let rows = rows
            .iter()
            .map(|o| {
                vec![
                    sev_label(o.severity),
                    clip(&o.title, 40),
                    clip(&o.observed, 24),
                    clip(&o.remediation, 60),
                ]
            })
            .collect();
        println!(
            "\n{}",
            table(&[t!("嚴重度"), t!("檢查"), t!("目前"), t!("怎麼修")], rows)
        );
    }
    if !r.needs_admin.is_empty() {
        println!(
            "\n{}",
            tf!(
                "{n} 項需要系統管理員／root 權限才能檢查：{ids}",
                n = r.needs_admin.len(),
                ids = r.needs_admin.join(", ")
            )
        );
    }
    for w in &r.warnings {
        println!("· {w}");
    }
}
