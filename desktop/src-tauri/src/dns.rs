//! 桌面版「DNS」頁：這台電腦最近查了哪些網域（背景服務的紀錄）、可疑的、查最多的網域與程式、
//! DNS 監看狀態，以及有沒有用公司的防護 DNS（`dns use-hub`）。

use std::collections::HashMap;

use asa_lib::dns::{heuristics, store, usehub};
use chrono::Utc;
use serde_json::{json, Value};
use tauri::State;

use crate::{AppState, CmdResult};

/// 一筆紀錄的可疑理由（情資分數 ≥ 60、像亂數產生、少見頂級網域）。
fn reasons(db: Option<&asa_lib::intel::IntelDb>, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(db) = db {
        let hits = db.match_domain(name);
        let score = asa_lib::intel::domain_score(&hits, heuristics::is_popular(name));
        if score >= 60 {
            if let Some(h) = hits.first() {
                out.push(format!("情資：{}（分數 {score}）", h.name));
            }
        }
        if let Some((_, feed)) = db.doh_endpoint(name) {
            out.push(format!("加密 DNS 端點（{feed}）"));
        }
    }
    if let Some(r) = heuristics::suspicious_domain(name) {
        out.push(r);
    }
    out
}

#[tauri::command]
pub async fn dns_recent(
    state: State<'_, AppState>,
    minutes: Option<i64>,
    suspicious: Option<bool>,
    q: Option<String>,
) -> CmdResult<Value> {
    let dir = state.config_dir.clone();
    let (data, unreadable) = store::pick_dir(&dir, false);
    let since = Utc::now() - chrono::Duration::minutes(minutes.unwrap_or(60).clamp(5, 7 * 24 * 60));
    let d2 = data.clone();
    let recs = tokio::task::spawn_blocking(move || store::read_since(&d2, since, 50_000))
        .await
        .map_err(|e| e.to_string())?;
    let intel = state.intel().await;
    let needle = q.unwrap_or_default().trim().to_ascii_lowercase();
    let only_bad = suspicious.unwrap_or(false);

    let mut total = 0u64;
    let mut nx = 0u64;
    let mut domains: HashMap<String, (u64, String)> = HashMap::new();
    let mut procs: HashMap<String, u64> = HashMap::new();
    let mut rows = Vec::new();
    let mut bad = 0usize;
    for r in recs.iter().rev() {
        let n = u64::from(r.count);
        total += n;
        if r.rcode == "NXDOMAIN" {
            nx += n;
        }
        let reg = r.registrable.clone().unwrap_or_else(|| r.name.clone());
        let e = domains.entry(reg).or_insert((0, String::new()));
        e.0 += n;
        if e.1.is_empty() {
            e.1 = r.process.clone().unwrap_or_default();
        }
        if let Some(p) = &r.process {
            *procs.entry(p.clone()).or_default() += n;
        }
        let why = reasons(intel.as_deref(), &r.name);
        if !why.is_empty() {
            bad += 1;
        }
        if only_bad && why.is_empty() {
            continue;
        }
        if !needle.is_empty()
            && !r.name.contains(&needle)
            && !r
                .process
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&needle)
        {
            continue;
        }
        if rows.len() < 500 {
            rows.push(json!({
                "ts": r.ts,
                "name": r.name,
                "qtype": asa_lib::dns::model::qtype_name(r.qtype),
                "rcode": r.rcode,
                "process": r.process,
                "count": r.count,
                "answers": r.answers,
                "reasons": why,
            }));
        }
    }
    let mut top: Vec<_> = domains.into_iter().collect();
    top.sort_by_key(|t| std::cmp::Reverse(t.1 .0));
    let mut top_procs: Vec<_> = procs.into_iter().collect();
    top_procs.sort_by_key(|t| std::cmp::Reverse(t.1));
    let cfg = asa_lib::config::load_or_init(&dir).ok();
    Ok(json!({
        "records": rows,
        "total": total,
        "nxdomain": nx,
        "suspicious": bad,
        "domains": top.len(),
        "top_domains": top.iter().take(10).map(|(d, (n, p))| json!({ "domain": d, "count": n, "process": p })).collect::<Vec<_>>(),
        "top_processes": top_procs.iter().take(10).map(|(p, n)| json!({ "process": p, "count": n })).collect::<Vec<_>>(),
        "status": store::read_status(&data),
        "unreadable": unreadable,
        "enabled": cfg.as_ref().map(|c| c.dns.enabled).unwrap_or(true),
        "upload": cfg.as_ref().map(|c| c.dns.upload),
        "use_hub": usehub::UseHubState::load(&dir),
        "hub_protect": usehub::HubProtect::load(&dir),
        "dns_server": cfg.as_ref().map(|c| c.dns.server.enabled).unwrap_or(false),
    }))
}
