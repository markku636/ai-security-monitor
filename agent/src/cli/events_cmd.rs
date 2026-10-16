//! `asa events`：事件與當機分析；`crashes` 只看當機；`explain` 解釋藍屏代碼或事件 ID；`analyze` 分析檔案。

use std::path::Path;

use chrono::Local;

use super::args::{EventsArgs, EventsCmd};
use super::render::{print_json, table};
use super::Env;
use crate::error::{AppError, AppResult};
use crate::events::{self, catalog, model::EventsSummary};
use crate::util::cmd::RealRunner;
use crate::util::text::clip;
use crate::util::time::parse_duration;

fn days_of(s: &str) -> AppResult<u32> {
    let d = parse_duration(s)?;
    Ok(d.as_secs().div_ceil(86_400).clamp(1, 90) as u32)
}

pub fn kind_label(k: &str) -> String {
    match k {
        "bugcheck" => t!("藍屏").into(),
        "unexpected_shutdown" => t!("非預期關機").into(),
        "app_crash" => t!("程式當掉").into(),
        "app_hang" => t!("程式沒回應").into(),
        "service_fail" => t!("服務失敗").into(),
        "disk_error" => t!("磁碟錯誤").into(),
        "whea_hardware" => t!("硬體錯誤").into(),
        "update_failure" => t!("更新失敗").into(),
        "gpu_reset" => t!("顯示卡重設").into(),
        "low_memory" => t!("記憶體不足").into(),
        "kernel_panic" => "kernel panic".into(),
        "oom" => "OOM".into(),
        "oops" => "kernel oops".into(),
        "segfault" => "segfault".into(),
        other => other.into(),
    }
}

fn rule_label(r: &str) -> String {
    match r {
        "failed_logon_burst" => t!("暴力破解").into(),
        "remote_logon" => t!("公網遠端登入").into(),
        "admin_member_added" => t!("加入管理員群組").into(),
        "group_member_added" => t!("加入群組").into(),
        "user_created" => t!("新帳號").into(),
        "user_enabled" => t!("啟用帳號").into(),
        "service_installed" => t!("新服務").into(),
        "task_created" => t!("新排程").into(),
        "audit_log_cleared" => t!("稽核紀錄被清除").into(),
        "log_cleared" => t!("事件記錄被清除").into(),
        "defender_detection" => t!("Defender 偵測").into(),
        "defender_disabled" => t!("Defender 被關閉").into(),
        other => other.into(),
    }
}

fn local(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string()
}

pub async fn run(env: &Env, a: EventsArgs) -> AppResult<()> {
    match a.cmd {
        Some(EventsCmd::Explain { code }) => explain(env, &code),
        Some(EventsCmd::Analyze { file }) => {
            let intel = crate::hub::watch::load_intel(&env.config_dir).await;
            let s = events::analyze_file(&RealRunner, Path::new(&file), intel.as_deref()).await?;
            output(env, &s, false);
            Ok(())
        }
        Some(EventsCmd::Crashes { since }) => {
            let days = days_of(&since)?;
            let s = gather(env, days).await?;
            output(env, &s, true);
            Ok(())
        }
        None => {
            let days = days_of(&a.since)?;
            let s = gather(env, days).await?;
            output(env, &s, false);
            Ok(())
        }
    }
}

async fn gather(env: &Env, days: u32) -> AppResult<EventsSummary> {
    if !env.global.quiet && !env.global.json {
        eprintln!("{}", tf!("讀取近 {days} 天的事件…", days = days));
    }
    let collected = events::collect(&RealRunner, days).await?;
    let has_public_source = events::rules::security_hits(&collected.events, None)
        .iter()
        .any(|h| h.rule == "failed_logon_burst");
    let intel = if has_public_source {
        crate::hub::watch::load_intel(&env.config_dir).await
    } else {
        None
    };
    Ok(events::summarize(collected, days, intel.as_deref()))
}

fn output(env: &Env, s: &EventsSummary, crashes_only: bool) {
    if env.global.json {
        if crashes_only {
            print_json(
                &serde_json::json!({ "days": s.days, "crash_counts": s.crash_counts, "crashes": s.crashes, "needs_admin": s.needs_admin }),
            );
        } else {
            print_json(s);
        }
        return;
    }
    println!(
        "{}",
        tf!(
            "近 {days} 天：讀了 {n} 筆事件（嚴重 {crit}、錯誤 {err}、警告 {warn}）",
            days = s.days,
            n = s.events_read,
            crit = s.counts_by_level.get("critical").copied().unwrap_or(0),
            err = s.counts_by_level.get("error").copied().unwrap_or(0),
            warn = s.counts_by_level.get("warning").copied().unwrap_or(0)
        )
    );
    for n in &s.needs_admin {
        println!("{}", tf!("⚠ 需要系統管理員權限才能讀取：{what}", what = n));
    }
    if s.crashes.is_empty() {
        println!("\n{}", t!("沒有當機或非預期關機紀錄。"));
    } else {
        println!("\n{}", t!("當機與錯誤"));
        let rows = s
            .crashes
            .iter()
            .take(30)
            .map(|c| {
                vec![
                    local(&c.time),
                    kind_label(&c.kind),
                    clip(
                        &[c.code.clone(), c.name.clone()]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()
                            .join(" "),
                        48,
                    ),
                    clip(&c.module.clone().or(c.process.clone()).unwrap_or_default(), 28),
                ]
            })
            .collect();
        println!(
            "{}",
            table(&[t!("時間"), t!("類型"), t!("代碼／名稱"), t!("模組／程式")], rows)
        );
        // 每種藍屏代碼的原因與處置只列一次
        let mut shown = std::collections::BTreeSet::new();
        for c in s.crashes.iter().filter(|c| c.kind == "bugcheck") {
            let Some(name) = &c.name else { continue };
            if !shown.insert(name.clone()) {
                continue;
            }
            println!("\n{} {}", name, c.code.clone().unwrap_or_default());
            for cause in &c.likely_causes {
                println!("  · {cause}");
            }
            if let Some(f) = &c.remediation {
                println!("  → {f}");
            }
        }
    }
    if crashes_only {
        return;
    }
    if !s.security.is_empty() {
        println!("\n{}", t!("資安事件"));
        let rows = s
            .security
            .iter()
            .map(|h| {
                let intel = h
                    .intel
                    .iter()
                    .map(|i| format!("{} {}%", i.vendor, i.confidence))
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![
                    h.severity.as_str().to_string(),
                    rule_label(&h.rule),
                    h.count.to_string(),
                    [h.source_ip.clone(), h.user.clone()]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" · "),
                    clip(
                        &if intel.is_empty() {
                            h.detail.clone()
                        } else {
                            format!("{} · {intel}", h.detail)
                        },
                        60,
                    ),
                    local(&h.last),
                ]
            })
            .collect();
        println!(
            "{}",
            table(
                &[
                    t!("嚴重度"),
                    t!("類型"),
                    t!("次數"),
                    t!("來源／帳號"),
                    t!("說明"),
                    t!("最後")
                ],
                rows
            )
        );
    }
    if !s.top_error_sources.is_empty() {
        println!("\n{}", t!("最常出現的錯誤"));
        let rows = s
            .top_error_sources
            .iter()
            .map(|t| {
                vec![
                    t.count.to_string(),
                    clip(&t.provider, 40),
                    t.event_id.to_string(),
                    clip(&t.sample.clone().unwrap_or_default(), 60),
                ]
            })
            .collect();
        println!("{}", table(&[t!("次數"), t!("來源"), "ID", t!("訊息")], rows));
    }
    for n in &s.notes {
        println!("· {n}");
    }
}

fn explain(env: &Env, code: &str) -> AppResult<()> {
    let c = code.trim();
    let hex_like = c.to_ascii_lowercase().starts_with("0x");
    let as_num: Option<u32> = c.parse().ok();
    let events_found = if hex_like {
        Vec::new()
    } else {
        as_num.map(|n| catalog::lookup_event(n, None)).unwrap_or_default()
    };
    let bug = if events_found.is_empty() {
        catalog::parse_code(c).and_then(catalog::lookup_bugcheck)
    } else {
        None
    };
    if env.global.json {
        print_json(&serde_json::json!({
            "query": c,
            "events": events_found.iter().map(|e| serde_json::json!({ "id": e.id, "provider": e.provider, "category": e.category, "text": catalog::event_text(e) })).collect::<Vec<_>>(),
            "bugcheck": bug.as_ref().map(|b| { let (causes, fix) = catalog::bugcheck_text(b); serde_json::json!({ "code": b.code, "name": b.name, "causes": causes, "fix": fix }) }),
        }));
        return Ok(());
    }
    if !events_found.is_empty() {
        for e in &events_found {
            println!("{} #{} ({})", e.provider, e.id, e.category);
            println!("  {}", catalog::event_text(e));
        }
        return Ok(());
    }
    match bug {
        Some(b) => {
            let (causes, fix) = catalog::bugcheck_text(&b);
            println!("{} {}", b.name, b.code);
            for cause in causes {
                println!("  · {cause}");
            }
            println!("  → {fix}");
            Ok(())
        }
        None => Err(AppError::InvalidArg(tf!(
            "查無 {code}：可用藍屏代碼（例 0x7E、0x124）或事件 ID（例 41、4625）",
            code = c
        ))),
    }
}
