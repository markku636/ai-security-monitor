//! AI Security Monitor 桌面版：系統匣常駐，視窗顯示本機的連線判定、掃描結果、情資狀態，
//! 並可用本機的 Claude Code／Codex CLI 做 AI 分析。資料與設定跟 `ai-security-monitor`（含背景的 `ai-security-monitor watch`）共用同一個設定目錄。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use asa_lib::ai::{self, prompts, Provider, RunSpec};
use asa_lib::cli::args::GlobalArgs;
use asa_lib::cli::Env;
use asa_lib::config;
use asa_lib::connections::{beacon, history, Classifier};
use asa_lib::error::AppError;
use asa_lib::hub::{discover, enroll as keyless, identity, watch};
use asa_lib::intel::fetch::{self, FeedMeta, UpdateOpts};
use asa_lib::intel::geo::GeoDb;
use asa_lib::intel::registry::Registry;
use asa_lib::intel::IntelDb;
use asa_lib::mcp::tools::READ_ONLY;
use asa_lib::model::allowlist::Allowlist;
use asa_lib::model::baseline::Baseline;
use serde_json::{json, Value};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tokio::sync::Mutex;

mod ai_auth;
mod dns;
mod lan;
mod live;
mod updates;
mod usage;

type CmdResult<T> = Result<T, String>;

fn err(e: AppError) -> String {
    e.message()
}

struct AppState {
    config_dir: PathBuf,
    intel: Mutex<Option<(Instant, Arc<IntelDb>)>>,
    ai_running: AtomicBool,
    /// 沒有背景服務時，桌面版自己取樣（最近 1 小時在記憶體、24 小時歷史寫進設定目錄；不寫進背景服務的待送佇列）。見 [`usage`]。
    metrics: asa_lib::metrics::Shared,
    metrics_recent: Mutex<Vec<asa_lib::metrics::MetricsSample>>,
}

impl AppState {
    fn env(&self) -> Env {
        Env {
            global: GlobalArgs {
                quiet: true,
                ..Default::default()
            },
            config_dir: self.config_dir.clone(),
        }
    }

    /// 情資資料庫（10 分鐘內重用；更新情資後清掉）。
    async fn intel(&self) -> Option<Arc<IntelDb>> {
        let mut g = self.intel.lock().await;
        if let Some((at, db)) = g.as_ref() {
            if at.elapsed() < Duration::from_secs(600) {
                return Some(db.clone());
            }
        }
        let db = watch::load_intel(&self.config_dir).await?;
        *g = Some((Instant::now(), db.clone()));
        Some(db)
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

/// 總覽：版本、Hub、最新報告分數與問題數、情資新舊、背景服務在不在跑。
#[tauri::command]
async fn overview(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    let reg = Registry::load(dir).map_err(err)?;
    let hub_url = cfg.hub.as_ref().map(|h| h.url.clone());
    let intel = fetch::intel_status(dir, &reg, hub_url.as_deref());
    let report = watch::load_latest(dir).map(|r| {
        let c = r.count_by_severity();
        json!({
            "finished_at": r.finished_at,
            "score": r.score,
            "counts": { "critical": c[0], "high": c[1], "medium": c[2], "low": c[3], "info": c[4] },
            "findings": r.findings.len(),
            "partial": r.partial,
            "hostname": r.agent.hostname,
        })
    });
    let watchers = asa_lib::service::running_watchers(Some(dir));
    Ok(json!({
        "version": asa_lib::VERSION,
        "agent_id": cfg.agent_id,
        "hostname": hostname(),
        "config_dir": dir.display().to_string(),
        "hub_url": hub_url,
        "hub_fingerprint": cfg.hub.as_ref().and_then(|h| h.fingerprint.clone()),
        "report": report,
        "intel": {
            "checked_at": intel.checked_at,
            "ok": intel.ok,
            "total": intel.total,
            "source": intel.source,
        },
        "watcher_running": !watchers.is_empty(),
        "elevated": asa_lib::elevate::is_elevated(),
        "metrics": { "performance": cfg.metrics.performance, "interval": cfg.metrics.interval },
    }))
}

/// 目前的連線（唯讀：不寫入連線歷史，避免干擾背景服務的週期性連線判斷）。
#[tauri::command]
async fn connections(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = state.config_dir.clone();
    let intel = state.intel().await;
    tokio::task::spawn_blocking(move || -> Result<Value, AppError> {
        let allowlist = Allowlist::load(&dir)?;
        let baseline = Baseline::load(&dir)?;
        let mut snap = asa_lib::connections::take(&dir)?;
        let now = chrono::Utc::now().timestamp() as u64;
        let hist = history::load(&dir, now.saturating_sub(history::RETENTION_SECS))?;
        let beacons = beacon::detect(&hist, now);
        Classifier::load().annotate(&mut snap, &allowlist, baseline.as_ref(), &beacons);
        if let Some(db) = intel {
            asa_lib::intel::enrich_connections(&db, &mut snap.connections);
        }
        Ok(json!({ "connections": snap.connections, "listeners": snap.listeners, "intel_loaded": true }))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(err)
}

/// 查一個 IP：本機情資命中＋國家／ASN。
#[tauri::command]
async fn lookup_ip(state: State<'_, AppState>, ip: String) -> CmdResult<Value> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| format!("不是有效的 IP：{ip}"))?;
    let hits = match state.intel().await {
        Some(db) => serde_json::to_value(db.match_ip(addr, None)).unwrap_or(Value::Null),
        None => Value::Array(vec![]),
    };
    let dir = state.config_dir.clone();
    let geo = tokio::task::spawn_blocking(move || GeoDb::load(&dir).lookup(addr))
        .await
        .ok()
        .flatten();
    Ok(json!({
        "ip": addr.to_string(),
        "hits": hits,
        "geo": geo.map(|g| json!({ "country": g.country, "asn": g.asn, "org": g.org })),
        "class": format!("{:?}", asa_lib::util::net::classify(addr)),
    }))
}

/// 最近一次的完整報告（背景服務或「立即掃描」產生的）。
#[tauri::command]
async fn latest_report(state: State<'_, AppState>) -> CmdResult<Value> {
    Ok(watch::load_latest(&state.config_dir)
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .unwrap_or(Value::Null))
}

/// 立即掃描（全部引擎），存成最新報告。
#[tauri::command]
async fn scan_now(state: State<'_, AppState>) -> CmdResult<Value> {
    let env = state.env();
    let (report, _) = asa_lib::cli::scan_cmd::run_scan(&env, &[], false).await.map_err(err)?;
    let _ = watch::save_latest(&state.config_dir, &report);
    serde_json::to_value(report).map_err(|e| e.to_string())
}

/// 各情資來源在本機的狀態。
#[tauri::command]
async fn intel_feeds(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let reg = Registry::load(dir).map_err(err)?;
    let items: Vec<Value> = reg
        .feeds
        .iter()
        .filter(|f| fetch::downloadable(f))
        .map(|f| {
            let m = FeedMeta::load(dir, &f.id);
            json!({
                "id": f.id,
                "name": f.name,
                "vendor": f.vendor,
                "kind": f.kind.as_str(),
                "enabled": reg.is_enabled(f),
                "license": f.license.name,
                "commercial_ok": f.license.commercial_ok,
                "license_blocked": reg.license_blocked(f),
                "source_url": f.source_url(),
                "entries": m.as_ref().map(|m| m.entries).unwrap_or(0),
                "fetched_at": m.as_ref().and_then(|m| m.fetched_at),
                "checked_at": m.as_ref().and_then(|m| m.checked_at),
                "status": m.as_ref().map(|m| m.status.clone()).unwrap_or_else(|| "never".into()),
                "error": m.as_ref().and_then(|m| m.error.clone()),
                "from_hub": m.as_ref().is_some_and(|m| m.url.contains("/api/v1/feeds/")),
            })
        })
        .collect();
    Ok(json!({ "feeds": items }))
}

/// 情資的使用情境（還沒選＝null）與只限非商業用途的來源清單（第一次打開與設定頁用）。
#[tauri::command]
async fn intel_usage(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load(dir).map_err(err)?;
    let reg = Registry::load(dir).map_err(err)?;
    let sources: Vec<Value> = reg
        .feeds
        .iter()
        .filter(|f| !f.license.commercial_ok)
        .map(|f| {
            json!({
                "id": f.id,
                "name": f.name,
                "vendor": f.vendor,
                "license": f.license.name,
                "lookup": !fetch::downloadable(f),
            })
        })
        .collect();
    Ok(json!({
        "usage": cfg.intel.usage.map(|u| u.as_str()),
        "noncommercial": cfg.intel.noncommercial(),
        "sources": sources,
    }))
}

/// 設定使用情境（commercial／noncommercial）。換了就丟掉快取的情資，下次比對照新的來源。
#[tauri::command]
async fn set_intel_usage(state: State<'_, AppState>, usage: String) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut cfg = config::load_or_init(dir).map_err(err)?;
    config::set_value(&mut cfg, "intel.usage", &usage).map_err(err)?;
    config::save(dir, &cfg).map_err(err)?;
    *state.intel.lock().await = None;
    Ok(json!({ "usage": cfg.intel.usage.map(|u| u.as_str()) }))
}

/// 更新情資：已註冊 Hub 就先從 Hub 鏡像拿。
#[tauri::command]
async fn intel_update(state: State<'_, AppState>, force: bool) -> CmdResult<Value> {
    let dir = state.config_dir.clone();
    let reg = Registry::load(&dir).map_err(err)?;
    let cfg = config::load_or_init(&dir).map_err(err)?;
    let mirror = match watch::client_from_config(&dir, &cfg) {
        Ok(Some(c)) => c.feed_mirror().await.ok(),
        _ => None,
    };
    let opts = UpdateOpts {
        only: vec![],
        force,
        mirror,
    };
    let outs = fetch::update(&dir, &reg, &opts, &|_| {}).await.map_err(err)?;
    *state.intel.lock().await = None;
    serde_json::to_value(outs).map_err(|e| e.to_string())
}

/// 本機找得到哪些 AI CLI、是否已登入。
#[tauri::command]
async fn ai_providers() -> CmdResult<Value> {
    let list: Vec<Value> = [Provider::Claude, Provider::Codex]
        .into_iter()
        .map(|p| {
            let bin = ai::resolve_bin(p);
            json!({
                "id": format!("{p:?}").to_lowercase(),
                "label": p.label(),
                "found": bin.is_some(),
                "path": bin.map(|b| b.path.display().to_string()),
                "logged_in": ai::logged_in(p),
            })
        })
        .collect();
    Ok(json!({ "providers": list }))
}

fn parse_provider(s: &str) -> Option<Provider> {
    match s {
        "claude" => Some(Provider::Claude),
        "codex" => Some(Provider::Codex),
        _ => None,
    }
}

/// AI 分析（本機 Claude Code／Codex CLI＋ai-security-monitor 的唯讀 MCP 工具）。事件即時送到視窗的 `ai-event`。
#[tauri::command]
async fn ai_ask(
    app: AppHandle,
    state: State<'_, AppState>,
    provider: String,
    scope: String,
    prompt: String,
) -> CmdResult<Value> {
    if state.ai_running.swap(true, Ordering::SeqCst) {
        return Err("已經有一個 AI 分析在跑".into());
    }
    let result = async {
        let (p, bin) = ai::pick_provider(parse_provider(&provider)).map_err(err)?;
        let question = prompt.trim();
        let full = match scope.as_str() {
            "connections" => format!(
                "分析這台電腦目前判定為可疑或危險的連線：用 list_connections 取得連線，依目的地／行程分組，說明每一組為什麼被判可疑（情資命中還是行為判斷）、對方大概是什麼服務（用 lookup_ip 查國家／ASN／情資）、哪些可能是誤報、哪些真的需要處理，最後給出建議。{}",
                if question.is_empty() { String::new() } else { format!("\n\n使用者補充：{question}") }
            ),
            "report" => {
                let report = watch::load_latest(&state.config_dir)
                    .ok_or_else(|| "還沒有掃描報告，先按「立即掃描」".to_string())?;
                let data = serde_json::to_string(&report).map_err(|e| e.to_string())?;
                format!("{}\n\n```json\n{}\n```\n{}", prompts::render(prompts::ANALYZE_REPORT), data, question)
            }
            _ => {
                if question.is_empty() {
                    return Err("請輸入問題".into());
                }
                question.to_string()
            }
        };
        let spec = RunSpec {
            provider: p,
            prompt: full,
            system: prompts::render(prompts::ASK_SYSTEM),
            tools: READ_ONLY.iter().map(|s| s.to_string()).collect(),
            model: None,
            max_turns: 12,
            timeout: Duration::from_secs(600),
        };
        let _ = app.emit("ai-event", json!({ "type": "start", "provider": p.label() }));
        let outcome = ai::run(&spec, &bin, &state.config_dir, |e| {
            let _ = app.emit("ai-event", e);
        })
        .await
        .map_err(err)?;
        serde_json::to_value(outcome).map_err(|e| e.to_string())
    }
    .await;
    state.ai_running.store(false, Ordering::SeqCst);
    result
}

// ---------------- 加入公司的 Security Hub（免金鑰）----------------

fn pending_json(p: &keyless::PendingEnroll) -> Value {
    json!({
        "hub_url": p.hub_url,
        "hub_name": p.hub_name,
        "hub_fingerprint": p.hub_fingerprint,
        "request_code": p.request_code,
        "created_at": p.created_at,
        "expires_at": p.expires_at,
        "status": p.status,
    })
}

/// 目前的 Hub 狀態：已加入（含釘選的指紋）、等候核准中、或都沒有。
#[tauri::command]
async fn hub_status(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    Ok(json!({
        "hub_url": cfg.hub.as_ref().map(|h| h.url.clone()),
        "hub_fingerprint": cfg.hub.as_ref().and_then(|h| h.fingerprint.clone()),
        "pending": keyless::load_pending(dir).as_ref().map(pending_json),
    }))
}

/// 尋找 Hub：環境變數 AI_SECURITY_MONITOR_HUB_URL、公司 DNS（SRV）、區網廣播（mDNS）；每個都驗過身分簽章。
#[tauri::command]
async fn discover_hubs(state: State<'_, AppState>, url: Option<String>) -> CmdResult<Value> {
    let cfg = config::load_or_init(&state.config_dir).map_err(err)?;
    let opts = discover::Opts {
        explicit: url.filter(|u| !u.trim().is_empty()),
        config_url: cfg.hub.as_ref().map(|h| h.url.clone()),
        all: true,
        ..discover::Opts::default()
    };
    let found = discover::find(&opts).await.map_err(err)?;
    Ok(json!({ "hubs": found, "pinned_fingerprint": cfg.hub.and_then(|h| h.fingerprint) }))
}

/// 對指定的 Hub 送出加入申請（再驗一次身分：指紋要和使用者在畫面上看到的一樣；
/// 和這台電腦目前加入的 Hub 指紋不同時，要使用者明確確認 `confirmed`）。
#[tauri::command]
async fn request_join(
    state: State<'_, AppState>,
    url: String,
    fingerprint: String,
    confirmed: Option<bool>,
) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let check = discover::check_hub(&url, false, pinned_fingerprint(dir).as_deref())
        .await
        .map_err(err)?;
    let id = check
        .identity
        .clone()
        .ok_or_else(|| "這個 Hub 版本太舊，不支援免金鑰加入".to_string())?;
    if !identity::same_fingerprint(&id.fingerprint, &fingerprint) {
        return Err(format!(
            "Hub 的指紋變了（畫面上是 {fingerprint}，現在是 {}），已停止",
            id.fingerprint
        ));
    }
    require_same_hub(&check, confirmed.unwrap_or(false))?;
    let (p, _) = asa_lib::cli::hub_cmd::start_enroll_request(dir, &check.url, &id, false)
        .await
        .map_err(err)?;
    Ok(pending_json(&p))
}

// ---------------- 設定頁：Hub 網址、開機自動啟動 ----------------

fn pinned_fingerprint(dir: &std::path::Path) -> Option<String> {
    config::load_or_init(dir)
        .ok()
        .and_then(|c| c.hub)
        .and_then(|h| h.fingerprint)
}

/// 要換到別的 Hub（指紋和這台記得的不同）時，前端要先讓使用者明確確認。
const NEEDS_CONFIRM: &str = "needs_confirm:";

fn require_same_hub(check: &discover::HubCheck, confirmed: bool) -> CmdResult<()> {
    if check.fingerprint_changed && !confirmed {
        return Err(format!(
            "{NEEDS_CONFIRM}這個 Hub 的指紋（{}）和這台電腦目前加入的 Hub（{}）不同。換過去之後，這台電腦會改回報到新的 Hub。",
            check
                .identity
                .as_ref()
                .map(|i| i.fingerprint.as_str())
                .unwrap_or("—"),
            check.pinned_fingerprint.as_deref().unwrap_or("—")
        ));
    }
    Ok(())
}

/// 測試連線：網址規則、/api/health、Hub 身分（驗章），並和這台釘選的指紋比對。
#[tauri::command]
async fn hub_check(state: State<'_, AppState>, url: String) -> CmdResult<Value> {
    let pinned = pinned_fingerprint(&state.config_dir);
    let c = discover::check_hub(&url, false, pinned.as_deref()).await.map_err(err)?;
    serde_json::to_value(c).map_err(|e| e.to_string())
}

/// 用管理員給的註冊金鑰加入（原本的 enroll --key 流程）。
#[tauri::command]
async fn enroll_with_key(state: State<'_, AppState>, url: String, key: String, confirmed: bool) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let check = discover::check_hub(&url, false, pinned_fingerprint(dir).as_deref())
        .await
        .map_err(err)?;
    require_same_hub(&check, confirmed)?;
    let mut env = state.env();
    env.global.json = true;
    asa_lib::cli::hub_cmd::enroll(&env, &check.url, key.trim(), false, false)
        .await
        .map_err(err)?;
    hub_status(state).await
}

/// 離開目前的 Hub（只刪這台的設定與金鑰；Hub 上的主機紀錄要管理員自己刪）。
#[tauri::command]
async fn leave_hub(state: State<'_, AppState>) -> CmdResult<()> {
    asa_lib::cli::hub_cmd::unenroll(&state.env()).await.map_err(err)
}

/// 背景自動回報（使用者層服務）的狀態。
#[tauri::command]
async fn background_service_status(state: State<'_, AppState>) -> CmdResult<Value> {
    asa_lib::cli::service_cmd::user_service_status(&state.config_dir)
        .await
        .map_err(err)
}

/// 開／關背景自動回報（等同 service install|uninstall --yes，只裝使用者層、不跳 UAC）。
#[tauri::command]
async fn set_background_service(state: State<'_, AppState>, enabled: bool) -> CmdResult<Value> {
    let lines = asa_lib::cli::service_cmd::set_user_service(&state.config_dir, enabled)
        .await
        .map_err(err)?;
    let status = background_service_status(state).await?;
    Ok(json!({ "lines": lines, "status": status }))
}

/// Windows：背景服務改成「登入時以系統管理員權限啟動」（排程工作），才量得到各程式的網路流量。
/// 會跳一次 UAC；實際動作由命令列版以系統管理員身分執行（`service install|uninstall --admin-at-logon --yes`）。
#[tauri::command]
async fn set_admin_logon(state: State<'_, AppState>, enabled: bool) -> CmdResult<Value> {
    let dir = state.config_dir.clone();
    let st = asa_lib::cli::service_cmd::user_service_status(&dir)
        .await
        .map_err(err)?;
    let exe = st["exe"]
        .as_str()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "找不到命令列版 ai-security-monitor".to_string())?;
    let user = asa_lib::service::elevated::current_user().ok_or_else(|| "讀不到目前登入的帳號".to_string())?;
    let argv: Vec<String> = [
        exe.display().to_string(),
        "--config-dir".into(),
        dir.display().to_string(),
        "service".into(),
        if enabled { "install" } else { "uninstall" }.into(),
        "--admin-at-logon".into(),
        "--yes".into(),
        "--task-user".into(),
        user,
    ]
    .into();
    let r = asa_lib::elevate::run_elevated(&exe, &argv, &dir).await.map_err(err)?;
    if !r.ok {
        return Err(r.lines.join("\n"));
    }
    let status = background_service_status(state).await?;
    Ok(json!({ "lines": r.lines, "status": status }))
}

/// 登入時開啟桌面版（常駐系統匣、不跳視窗）。
#[tauri::command]
fn desktop_autostart_status(app: AppHandle) -> CmdResult<bool> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

#[tauri::command]
fn set_desktop_autostart(app: AppHandle, enabled: bool) -> CmdResult<bool> {
    use tauri_plugin_autostart::ManagerExt;
    let a = app.autolaunch();
    if enabled {
        a.enable().map_err(|e| e.to_string())?;
    } else {
        a.disable().map_err(|e| e.to_string())?;
    }
    a.is_enabled().map_err(|e| e.to_string())
}

/// 問一次核准狀態；核准了就完成註冊（存金鑰、釘選 Hub 指紋）。
#[tauri::command]
async fn join_poll(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut cfg = config::load_or_init(dir).map_err(err)?;
    let agent = asa_lib::cli::hub_cmd::agent_info(&cfg);
    match keyless::step(dir, &mut cfg, &agent, false).await.map_err(err)? {
        None => Ok(json!({ "status": "none" })),
        Some(keyless::Step::Waiting(st)) => Ok(json!({
            "status": "pending",
            "poll_interval_s": keyless::poll_delay(None, Some(&st)).as_secs(),
            "pending": keyless::load_pending(dir).as_ref().map(pending_json),
        })),
        Some(keyless::Step::Done(r)) => Ok(json!({
            "status": "approved",
            "hub_url": cfg.hub.as_ref().map(|h| h.url.clone()),
            "hub_name": r.hub.name,
        })),
        Some(keyless::Step::Rejected(reason)) => Ok(json!({ "status": "rejected", "reason": reason })),
        Some(keyless::Step::Expired) => Ok(json!({ "status": "expired" })),
    }
}

/// 取消等候中的申請（Hub 上的申請會自己過期）。
#[tauri::command]
async fn cancel_join(state: State<'_, AppState>) -> CmdResult<()> {
    keyless::clear_pending(&state.config_dir).map_err(err)
}

/// 用預設瀏覽器開網址（只接受 http/https）。
#[tauri::command]
fn open_url(url: String) -> CmdResult<()> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("只能開 http／https 網址".into());
    }
    #[cfg(windows)]
    let r = std::process::Command::new("explorer").arg(&url).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(&url).spawn();
    r.map(|_| ()).map_err(|e| e.to_string())
}

fn show_main(app: &AppHandle) {
    app.state::<updates::Updates>()
        .window_shown
        .store(true, Ordering::SeqCst);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// 登入時自動啟動桌面版用的參數：常駐系統匣、不跳視窗。
pub const TRAY_ARG: &str = "--tray";

pub fn run(start_in_tray: bool) {
    let config_dir = config::config_dir(None).expect("config dir");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![TRAY_ARG]),
        ))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(updates::Updates::default())
        .manage(live::Live::default())
        .manage(AppState {
            config_dir,
            intel: Mutex::new(None),
            ai_running: AtomicBool::new(false),
            metrics: asa_lib::metrics::shared(),
            metrics_recent: Mutex::new(Vec::new()),
        })
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "開啟主視窗", true, None::<&str>)?;
            let hub = MenuItem::with_id(app, "hub", "開啟 Security Hub", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "結束", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &hub, &quit])?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().cloned().expect("icon"))
                .tooltip("AI Security Monitor")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| match e.id.as_ref() {
                    "show" => show_main(app),
                    "hub" => {
                        let dir = app.state::<AppState>().config_dir.clone();
                        if let Some(h) = config::load_or_init(&dir).ok().and_then(|c| c.hub) {
                            let _ = open_url(h.url);
                        } else {
                            show_main(app);
                        }
                    }
                    // auto 模式下載好的更新在這時安裝
                    "quit" => updates::quit(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = e
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            if !start_in_tray {
                show_main(app.handle());
            }
            updates::spawn_background(app.handle().clone(), start_in_tray);
            // 背景服務沒在跑時，桌面版開著就自己累積流量／效能歷史
            usage::spawn_sampler(app.handle().clone());
            // 有開「背景自動回報」卻沒在跑（例如更新安裝時被結束）：把它啟動起來
            let dir = app.state::<AppState>().config_dir.clone();
            tauri::async_runtime::spawn(async move {
                let _ = asa_lib::cli::service_cmd::ensure_user_service_running(&dir).await;
            });
            Ok(())
        })
        .on_window_event(|w, e| {
            // 關視窗只是收到系統匣，「結束」才真的離開
            if let WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            overview,
            connections,
            lookup_ip,
            latest_report,
            scan_now,
            intel_feeds,
            intel_update,
            intel_usage,
            set_intel_usage,
            ai_providers,
            ai_ask,
            ai_auth::ai_auth_status,
            ai_auth::ai_login,
            ai_auth::ai_logout,
            hub_status,
            discover_hubs,
            request_join,
            join_poll,
            cancel_join,
            hub_check,
            enroll_with_key,
            leave_hub,
            background_service_status,
            set_background_service,
            set_admin_logon,
            desktop_autostart_status,
            set_desktop_autostart,
            usage::metrics_now,
            dns::dns_recent,
            dns::dns_set,
            dns::dns_settings,
            dns::lookup_domain,
            dns::dns_block,
            dns::dns_unblock,
            dns::dns_allow,
            dns::dns_unallow,
            dns::dns_use_hub,
            dns::dns_restore,
            usage::metrics_history,
            live::traffic_live,
            usage::set_performance,
            open_url,
            updates::update_status,
            updates::set_update_mode,
            updates::check_updates,
            updates::install_update,
            updates::update_cli_agent,
            lan::local_hub_status,
            lan::set_hub_advertise,
            lan::upload_status,
            lan::upload_now
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
