//! `ai-security-monitor dns`：最近查了哪些網域（背景服務每分鐘記一次）、`--suspicious` 只看可疑、
//! `--follow` 即時看新查詢；`dns status` 看背景蒐集的狀態。
//!
//! 背景服務以系統服務執行時紀錄在系統層設定目錄：哪邊的狀態比較新就讀哪邊（明確給 `--config-dir` 時只看那裡）。

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;

use super::args::{DnsArgs, DnsCmd};
use super::render::{print_json, table};
use super::Env;
use crate::config;
use crate::dns::model::{qtype_name, DnsEvent, DnsRecord};
use crate::dns::store::{self, DnsStatus};
use crate::dns::{collect, heuristics};
use crate::error::AppResult;
use crate::intel::registry::Registry;
use crate::intel::IntelDb;

pub async fn run(env: &Env, a: DnsArgs) -> AppResult<()> {
    match a.cmd {
        Some(DnsCmd::Status) => status(env).await,
        None if a.follow => follow(env, &a).await,
        None => list(env, &a).await,
    }
}

/// 紀錄所在的設定目錄（見 [`store::pick_dir`]）；第二個值是給使用者的提示。
pub(crate) fn data_dir(env: &Env) -> (PathBuf, Option<String>) {
    let explicit = env.global.config_dir.is_some() || crate::util::env::var(config::ENV_CONFIG_DIR).is_some();
    let (dir, unreadable) = store::pick_dir(&env.config_dir, explicit);
    (
        dir,
        unreadable.then(|| t!("背景服務的 DNS 紀錄要以系統管理員身分執行才讀得到").to_string()),
    )
}

/// 一列的可疑理由（情資命中、像亂數產生、少見頂級網域）；沒有就是空的。
fn reasons(db: Option<&IntelDb>, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(db) = db {
        let hits = db.match_domain(name);
        let score = crate::intel::domain_score(&hits, heuristics::is_popular(name));
        if score >= 60 {
            if let Some(h) = hits.first() {
                out.push(tf!(
                    "情資：{feed}（分數 {score}）",
                    feed = h.name.clone(),
                    score = score
                ));
            }
        }
        if let Some((id, _)) = db.doh_endpoint(name) {
            out.push(tf!("加密 DNS 端點（{id}）", id = id));
        }
    }
    if heuristics::looks_generated(name) {
        out.push(t!("像亂數產生（DGA）").into());
    }
    if let Some(s) = heuristics::suspicious_domain(name) {
        out.push(s);
    }
    out
}

async fn load_intel(dir: &Path) -> Option<IntelDb> {
    let reg = Registry::load(dir).ok()?;
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || IntelDb::load(&dir, &reg))
        .await
        .ok()
}

async fn list(env: &Env, a: &DnsArgs) -> AppResult<()> {
    let window = crate::util::time::parse_duration(&a.since)?;
    let since = Utc::now() - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::minutes(15));
    let (dir, note) = data_dir(env);
    let mut recs: Vec<DnsRecord> = store::read_since(&dir, since, 200_000);
    if let Some(p) = &a.process {
        let p = p.to_ascii_lowercase();
        recs.retain(|r| {
            r.process
                .as_deref()
                .is_some_and(|x| x.to_ascii_lowercase().contains(&p))
        });
    }
    // 情資只在要看可疑時才載入（大型網域清單要 0.5–1 秒）
    let db = if a.suspicious {
        load_intel(&env.config_dir).await
    } else {
        None
    };
    let mut rows: Vec<(DnsRecord, Vec<String>)> = recs
        .into_iter()
        .map(|r| {
            let why = if a.suspicious {
                reasons(db.as_ref(), &r.name)
            } else {
                Vec::new()
            };
            (r, why)
        })
        .filter(|(_, why)| !a.suspicious || !why.is_empty())
        .collect();
    let total = rows.len();
    if rows.len() > a.limit {
        rows.drain(..rows.len() - a.limit);
    }
    if env.global.json {
        print_json(&json!({
            "dir": dir,
            "since": since,
            "total": total,
            "records": rows.iter().map(|(r, why)| {
                let mut v = serde_json::to_value(r).unwrap_or_default();
                if !why.is_empty() { v["reasons"] = json!(why); }
                v
            }).collect::<Vec<_>>(),
            "note": note,
        }));
        return Ok(());
    }
    if let Some(n) = &note {
        println!("{n}");
    }
    if rows.is_empty() {
        let st = store::read_status(&dir);
        println!("{}", empty_hint(st.as_ref(), a.suspicious));
        return Ok(());
    }
    let body = rows
        .iter()
        .map(|(r, why)| {
            let mut row = vec![
                r.ts.with_timezone(&chrono::Local).format("%H:%M").to_string(),
                r.name.clone(),
                qtype_name(r.qtype),
                r.rcode.clone(),
                r.process.clone().unwrap_or_else(|| "—".into()),
                r.count.to_string(),
                answers_short(r),
            ];
            if a.suspicious {
                row.push(why.join("；"));
            }
            row
        })
        .collect();
    let mut head = vec![
        t!("時間"),
        t!("網域"),
        t!("類型"),
        t!("結果"),
        t!("程式"),
        t!("次數"),
        t!("解析到"),
    ];
    if a.suspicious {
        head.push(t!("可疑原因"));
    }
    println!("{}", table(&head, body));
    if total > rows.len() {
        println!(
            "{}",
            tf!(
                "共 {total} 筆，只列最新 {n} 筆（--limit 調整）",
                total = total,
                n = rows.len()
            )
        );
    }
    Ok(())
}

fn answers_short(r: &DnsRecord) -> String {
    let mut v: Vec<String> = r.answers.iter().take(2).map(|i| i.to_string()).collect();
    if r.answers.len() > 2 {
        v.push(format!("+{}", r.answers.len() - 2));
    }
    if v.is_empty() {
        r.cnames.first().cloned().unwrap_or_default()
    } else {
        v.join(", ")
    }
}

fn empty_hint(st: Option<&DnsStatus>, suspicious: bool) -> String {
    if suspicious {
        return t!("這段時間沒有可疑的 DNS 查詢").into();
    }
    match st {
        None => {
            t!("還沒有 DNS 紀錄：背景服務（ai-security-monitor service install）啟動後會開始記錄；或用 --follow 即時看")
                .into()
        }
        Some(s) if !s.running => t!("背景 DNS 蒐集目前沒有在跑（ai-security-monitor dns status 看原因）").into(),
        Some(_) => t!("這段時間沒有 DNS 紀錄（每分鐘寫入一次，剛啟動請稍候）").into(),
    }
}

async fn status(env: &Env) -> AppResult<()> {
    let cfg = config::load_or_init(&env.config_dir)?;
    let (dir, note) = data_dir(env);
    let st = store::read_status(&dir);
    let today = store::read_since(&dir, Utc::now() - chrono::Duration::hours(24), usize::MAX);
    let queries: u64 = today.iter().map(|r| u64::from(r.count)).sum();
    if env.global.json {
        print_json(&json!({
            "enabled": cfg.dns.enabled,
            "upload": cfg.dns.upload.as_str(),
            "dir": store::dir(&dir),
            "keep_days": store::KEEP_DAYS,
            "status": st,
            "last_24h": { "records": today.len(), "queries": queries },
            "note": note,
        }));
        return Ok(());
    }
    let yes_no = |b: bool| if b { t!("是") } else { t!("否") };
    println!(
        "{}",
        tf!(
            "DNS 監看：{on} · 上傳 Hub：{upload} · 紀錄保留 {days} 天",
            on = if cfg.dns.enabled { t!("開") } else { t!("關") },
            upload = cfg.dns.upload.as_str(),
            days = store::KEEP_DAYS
        )
    );
    println!(
        "{}",
        tf!("儲存位置：{dir}", dir = store::dir(&dir).display().to_string())
    );
    match &st {
        Some(s) => {
            println!(
                "{}",
                tf!(
                    "背景蒐集：{running} · 來源：{source} · 知道是哪個程式：{proc}",
                    running = if s.running { t!("執行中") } else { t!("已停止") },
                    source = s.source.clone().unwrap_or_else(|| "—".into()),
                    proc = yes_no(s.has_process)
                )
            );
            println!(
                "{}",
                tf!(
                    "事件 {events}（重複略過 {dedup}、來不及處理丟掉 {dropped}）· 最後一筆 {last}",
                    events = s.events,
                    dedup = s.deduped,
                    dropped = s.dropped,
                    last = s
                        .last_event_at
                        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
                        .unwrap_or_else(|| "—".into())
                )
            );
            for n in &s.notes {
                println!("· {n}");
            }
        }
        None => println!(
            "{}",
            t!("背景蒐集：還沒啟動過（ai-security-monitor service install 後自動開始）")
        ),
    }
    println!(
        "{}",
        tf!("最近 24 小時：{q} 次查詢、{r} 列紀錄", q = queries, r = today.len())
    );
    if let Some(n) = note {
        println!("{n}");
    }
    Ok(())
}

/// 即時看：自己開一個來源（Windows 系統管理員走 ETW，否則每 5 秒抓快取快照），印出每筆新查詢。
async fn follow(env: &Env, a: &DnsArgs) -> AppResult<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DnsEvent>(crate::dns::runtime::CHANNEL);
    let dropped = Arc::new(AtomicU64::new(0));
    let session: &'static str = "ai-security-monitor-dns-cli";
    let c = {
        let tx = tx.clone();
        let dropped = dropped.clone();
        tokio::task::spawn_blocking(move || collect::start(session, tx, dropped))
            .await
            .map_err(|e| crate::error::AppError::Scan(e.to_string()))?
    };
    for n in &c.notes {
        eprintln!("{n}");
    }
    if c.source.is_none() {
        return Ok(());
    }
    let db = if a.suspicious {
        load_intel(&env.config_dir).await
    } else {
        None
    };
    let mut procs = crate::dns::procname::ProcNames::new();
    let filter = a.process.as_ref().map(|p| p.to_ascii_lowercase());
    #[cfg(windows)]
    let mut tracker = collect::windows::CacheTracker::default();
    let mut poll = tokio::time::interval(Duration::from_secs(5));
    let _guard = c.guard;
    if !env.global.json {
        eprintln!("{}", t!("即時顯示 DNS 查詢，Ctrl+C 結束"));
    }
    let mut print = |ev: DnsEvent| {
        let proc = ev
            .process
            .clone()
            .or_else(|| ev.pid.and_then(|p| procs.get(p)).map(|p| p.name));
        if let Some(f) = &filter {
            if !proc.as_deref().is_some_and(|p| p.to_ascii_lowercase().contains(f)) {
                return;
            }
        }
        let why = if a.suspicious {
            reasons(db.as_ref(), &ev.name)
        } else {
            Vec::new()
        };
        if a.suspicious && why.is_empty() {
            return;
        }
        if env.global.json {
            println!(
                "{}",
                json!({
                    "ts": ev.ts, "name": ev.name, "qtype": qtype_name(ev.qtype), "rcode": ev.rcode,
                    "process": proc, "pid": ev.pid, "answers": ev.answers, "cnames": ev.cnames,
                    "source": ev.source, "reasons": why,
                })
            );
        } else {
            let ans: Vec<String> = ev.answers.iter().take(3).map(|i| i.to_string()).collect();
            println!(
                "{}  {:<8} {:<6} {:<9} {}  {}{}",
                ev.ts.with_timezone(&chrono::Local).format("%H:%M:%S"),
                proc.unwrap_or_else(|| "—".into()),
                qtype_name(ev.qtype),
                ev.rcode,
                ev.name,
                ans.join(", "),
                if why.is_empty() {
                    String::new()
                } else {
                    format!("  ⚠ {}", why.join("；"))
                }
            );
        }
    };
    loop {
        tokio::select! {
            Some(ev) = rx.recv() => print(ev),
            _ = poll.tick(), if c.poll_cache => {
                #[cfg(windows)]
                if let Ok(text) = collect::windows::cache_snapshot().await {
                    for ev in tracker.diff(&text, Utc::now()) {
                        print(ev);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}
