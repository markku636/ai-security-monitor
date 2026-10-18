//! 桌面版「DNS」頁：這台電腦最近查了哪些網域（背景服務的紀錄）、可疑的、查最多的網域與程式、網域查詢，
//! 以及設定頁的 DNS 區塊（監看開關、上傳、防護 DNS、黑白名單、`dns use-hub`）。

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use asa_lib::dns::{blocklist, heuristics, store, usehub};
use chrono::Utc;
use serde_json::{json, Value};
use tauri::State;

use crate::{AppState, CmdResult};

/// 一筆紀錄的可疑理由（情資分數 ≥ 60、像亂數產生、少見頂級網域）。
fn reasons(db: Option<&asa_lib::intel::IntelDb>, bl: &blocklist::Matcher, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((entry, src)) = bl.find(name) {
        out.push(format!("黑名單：{entry}（{}）", src.label()));
    }
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
    let bl = blocklist::Matcher::load(&dir);

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
        let why = reasons(intel.as_deref(), &bl, &r.name);
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
    let mut out = json!({
        "records": rows,
        "total": total,
        "nxdomain": nx,
        "suspicious": bad,
        "domains": top.len(),
        "top_domains": top.iter().take(10).map(|(d, (n, p))| json!({ "domain": d, "count": n, "process": p })).collect::<Vec<_>>(),
        "top_processes": top_procs.iter().take(10).map(|(p, n)| json!({ "process": p, "count": n })).collect::<Vec<_>>(),
        "status": store::read_status(&data),
        "unreadable": unreadable,
    });
    if let (Value::Object(m), Value::Object(s)) = (&mut out, settings_json(&dir)) {
        m.extend(s);
    }
    Ok(out)
}

/// DNS 設定與黑白名單（設定頁的 DNS 區塊、DNS 頁共用）。
fn settings_json(dir: &Path) -> Value {
    let cfg = asa_lib::config::load_or_init(dir).ok();
    let hub = usehub::HubProtect::load(dir);
    json!({
        "enabled": cfg.as_ref().map(|c| c.dns.enabled).unwrap_or(true),
        "upload": cfg.as_ref().map(|c| c.dns.upload),
        "use_hub": usehub::UseHubState::load(dir),
        "hub_protect": hub,
        "dns_server": cfg.as_ref().map(|c| c.dns.server.enabled).unwrap_or(false),
        "dns_server_listen": cfg.as_ref().map(|c| c.dns.server.listen.join(", ")).unwrap_or_default(),
        "verify_answers": cfg.as_ref().map(|c| c.dns.verify_answers).unwrap_or(false),
        "blocklist": {
            "local": blocklist::Blocklist::load(dir).entries,
            "hub": hub.as_ref().map(|h| h.block.clone()).unwrap_or_default(),
        },
        "allowlist": {
            "local": blocklist::local_allow(dir),
            "hub": hub.as_ref().map(|h| h.allow.clone()).unwrap_or_default(),
        },
    })
}

#[tauri::command]
pub async fn dns_settings(state: State<'_, AppState>) -> CmdResult<Value> {
    Ok(settings_json(&state.config_dir))
}

/// 查一個網域：用這台的 DNS 現在解析到哪裡、黑白名單、威脅情資、像不像亂數網域，
/// 以及這台最近 7 天哪些程式查過它（含子網域）。
#[tauri::command]
pub async fn lookup_domain(state: State<'_, AppState>, domain: String) -> CmdResult<Value> {
    let name = blocklist::normalize(&domain).ok_or_else(|| format!("不是有效的網域：{}", domain.trim()))?;
    let dir = state.config_dir.clone();

    // 系統解析（這台用了防護 DNS 時，被擋的網域會查不到）
    let resolved = match tokio::time::timeout(Duration::from_secs(4), tokio::net::lookup_host((name.as_str(), 0))).await
    {
        Ok(Ok(addrs)) => {
            let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            json!({ "ok": true, "addrs": ips })
        }
        Ok(Err(e)) => json!({ "ok": false, "error": e.to_string() }),
        Err(_) => json!({ "ok": false, "error": "4 秒內沒有回應" }),
    };

    let bl = blocklist::Matcher::load(&dir);
    let local_allow = blocklist::local_allow(&dir);
    let allowed_local = parents(&name)
        .find(|p| local_allow.iter().any(|a| a == p))
        .map(str::to_string);
    let block = bl.find(&name).map(|(entry, src)| {
        json!({ "entry": entry, "source": src.label(), "local": matches!(src, blocklist::Source::Local) })
    });

    let intel = state.intel().await;
    let (hits, score, doh) = match intel.as_deref() {
        Some(db) => {
            let hits = db.match_domain(&name);
            let score = asa_lib::intel::domain_score(&hits, heuristics::is_popular(&name));
            (hits, score, db.doh_endpoint(&name).map(|(_, feed)| feed))
        }
        None => (Vec::new(), 0, None),
    };

    // 這台最近 7 天的查詢紀錄（名稱本身或子網域）
    let (data, _) = store::pick_dir(&dir, false);
    let since = Utc::now() - chrono::Duration::days(7);
    let recs = tokio::task::spawn_blocking(move || store::read_since(&data, since, 200_000))
        .await
        .map_err(|e| e.to_string())?;
    let suffix = format!(".{name}");
    let mut total = 0u64;
    let mut last = None;
    let mut by_proc: HashMap<String, u64> = HashMap::new();
    let mut by_rcode: HashMap<String, u64> = HashMap::new();
    let mut names: HashMap<String, u64> = HashMap::new();
    let mut answers = std::collections::BTreeSet::new();
    for r in recs.iter().filter(|r| r.name == name || r.name.ends_with(&suffix)) {
        let n = u64::from(r.count);
        total += n;
        last = last.max(Some(r.ts));
        *by_proc.entry(r.process.clone().unwrap_or_default()).or_default() += n;
        *by_rcode.entry(r.rcode.clone()).or_default() += n;
        *names.entry(r.name.clone()).or_default() += n;
        for a in r.answers.iter().take(8) {
            if answers.len() < 12 {
                answers.insert(a.to_string());
            }
        }
    }
    let ranked = |m: HashMap<String, u64>, k: &str| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1));
        v.into_iter()
            .take(10)
            .map(|(x, n)| json!({ k: x, "count": n }))
            .collect::<Vec<_>>()
    };

    Ok(json!({
        "domain": name,
        "registrable": heuristics::registrable_domain(&name),
        "popular": heuristics::is_popular(&name),
        "resolved": resolved,
        "use_hub": usehub::UseHubState::load(&dir).is_some(),
        "block": block,
        "allowed": bl.allowed(&name),
        "allowed_local": allowed_local,
        "intel": { "hits": hits, "score": score, "loaded": intel.is_some() },
        "doh": doh,
        "heuristic": heuristics::suspicious_domain(&name),
        "recent": {
            "total": total,
            "last": last,
            "processes": ranked(by_proc, "process"),
            "rcodes": ranked(by_rcode, "rcode"),
            "names": ranked(names, "name"),
            "answers": answers,
        },
    }))
}

/// 名稱本身與各層上層（a.b.example.com → b.example.com → example.com）。
fn parents(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |cur| match cur.split_once('.') {
        Some((_, rest)) if rest.contains('.') => Some(rest),
        _ => None,
    })
}

/// DNS 設定頁可以改的鍵（其他鍵不收）。
const SETTABLE: [&str; 5] = [
    "dns.enabled",
    "dns.upload",
    "dns.verify_answers",
    "dns.server.enabled",
    "dns.server.listen",
];

#[tauri::command]
pub async fn dns_set(state: State<'_, AppState>, key: String, value: String) -> CmdResult<Value> {
    if !SETTABLE.contains(&key.as_str()) {
        return Err(format!("不能從這裡改：{key}"));
    }
    let dir = &state.config_dir;
    let mut cfg = asa_lib::config::load_or_init(dir).map_err(crate::err)?;
    asa_lib::config::set_value(&mut cfg, &key, &value).map_err(crate::err)?;
    asa_lib::config::save(dir, &cfg).map_err(crate::err)?;
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub async fn dns_block(state: State<'_, AppState>, domains: Vec<String>, note: Option<String>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut b = blocklist::Blocklist::load(dir);
    let (added, invalid) = b.add(&domains, note.as_deref().unwrap_or(""));
    if !added.is_empty() {
        b.save(dir).map_err(crate::err)?;
        blocklist::unallow(dir, &added).map_err(crate::err)?;
    }
    Ok(json!({ "added": added, "invalid": invalid }))
}

#[tauri::command]
pub async fn dns_unblock(state: State<'_, AppState>, domains: Vec<String>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut b = blocklist::Blocklist::load(dir);
    let removed = b.remove(&domains);
    if !removed.is_empty() {
        b.save(dir).map_err(crate::err)?;
    }
    Ok(json!({ "removed": removed }))
}

#[tauri::command]
pub async fn dns_allow(state: State<'_, AppState>, domains: Vec<String>, note: Option<String>) -> CmdResult<Value> {
    let (added, invalid) =
        blocklist::allow(&state.config_dir, &domains, note.as_deref().unwrap_or("")).map_err(crate::err)?;
    Ok(json!({ "added": added, "invalid": invalid }))
}

#[tauri::command]
pub async fn dns_unallow(state: State<'_, AppState>, domains: Vec<String>) -> CmdResult<Value> {
    let removed = blocklist::unallow(&state.config_dir, &domains).map_err(crate::err)?;
    Ok(json!({ "removed": removed }))
}

/// 以系統管理員執行命令列版的 `dns use-hub`／`dns restore`（會跳出 UAC／密碼視窗）。
async fn run_dns_elevated(dir: &std::path::Path, args: &[&str]) -> CmdResult<Value> {
    let st = asa_lib::cli::service_cmd::user_service_status(dir)
        .await
        .map_err(crate::err)?;
    let exe = st["exe"].as_str().map(std::path::PathBuf::from).ok_or_else(|| {
        "找不到命令列版 ai-security-monitor（請先在「設定」開啟背景自動回報，或安裝命令列版）".to_string()
    })?;
    let mut argv: Vec<String> = vec![
        exe.display().to_string(),
        "--config-dir".into(),
        dir.display().to_string(),
    ];
    argv.extend(args.iter().map(|s| s.to_string()));
    let r = asa_lib::elevate::run_elevated(&exe, &argv, dir)
        .await
        .map_err(crate::err)?;
    if !r.ok {
        let msg = r
            .error
            .as_ref()
            .and_then(|e| e["message"].as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| r.lines.join("\n"));
        return Err(msg);
    }
    Ok(json!({ "lines": r.lines }))
}

#[tauri::command]
pub async fn dns_use_hub(state: State<'_, AppState>, server: Option<String>) -> CmdResult<Value> {
    let server = server.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut args = vec!["dns", "use-hub", "--yes"];
    if let Some(s) = &server {
        args.push("--server");
        args.push(s);
    }
    run_dns_elevated(&state.config_dir, &args).await
}

#[tauri::command]
pub async fn dns_restore(state: State<'_, AppState>) -> CmdResult<Value> {
    run_dns_elevated(&state.config_dir, &["dns", "restore", "--yes"]).await
}
