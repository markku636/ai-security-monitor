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
use asa_lib::hub::watch;
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

type CmdResult<T> = Result<T, String>;

fn err(e: AppError) -> String {
    e.message()
}

struct AppState {
    config_dir: PathBuf,
    intel: Mutex<Option<(Instant, Arc<IntelDb>)>>,
    ai_running: AtomicBool,
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
        "report": report,
        "intel": {
            "checked_at": intel.checked_at,
            "ok": intel.ok,
            "total": intel.total,
            "source": intel.source,
        },
        "watcher_running": !watchers.is_empty(),
        "elevated": asa_lib::elevate::is_elevated(),
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
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn run() {
    let config_dir = config::config_dir(None).expect("config dir");
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .manage(AppState {
            config_dir,
            intel: Mutex::new(None),
            ai_running: AtomicBool::new(false),
        })
        .setup(|app| {
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
                    "quit" => app.exit(0),
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
            show_main(app.handle());
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
            ai_providers,
            ai_ask,
            open_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
