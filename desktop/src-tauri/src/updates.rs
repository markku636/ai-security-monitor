//! 桌面版的更新：tauri-plugin-updater 讀 GitHub Release 的 `latest.json`，下載 minisign 簽章過的安裝檔
//! （Windows NSIS、macOS `.app.tar.gz`、Linux AppImage）驗章後安裝。
//!
//! 一台電腦一個設定：`update.mode`（`off`／`notify`／`auto`，和命令列版共用 config.json）。
//! - 桌面版本身＋它內建的背景自動回報（背景服務登記的就是桌面版執行檔）：由這裡負責；內建的 agent 不會自我更新
//!   （`asa_lib::update::auto` 認得出桌面版，只檢查、記錄、回報 Hub）。
//! - 另外裝的命令列版背景服務：由它自己的 `update.mode`／`self-update` 負責；這裡的「立即更新」可以幫它跑一次。
//!
//! 時機：啟動後約 30 秒檢查一次，之後每 24 小時（加隨機）。notify 只通知；auto 先下載好，結束或下次開啟時安裝
//! （登入時以 `--tray` 啟動、視窗還沒開過的話就直接安裝）。Windows 的安裝程式會結束背景回報，裝完由安裝程式的
//! 收尾步驟（`windows/hooks.nsh`）與桌面版啟動時的檢查把它重新啟動。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asa_lib::config::{self, UpdateMode};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::Mutex;

use crate::{err, AppState, CmdResult};

pub const RELEASES: &str = "https://github.com/markku636/ai-security-monitor/releases";

/// 最近一次檢查的結果（給設定頁與橫幅）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct CheckInfo {
    pub checked_at: Option<DateTime<Utc>>,
    pub latest: Option<String>,
    pub available: bool,
    pub notes: Option<String>,
    pub notes_url: Option<String>,
    pub error: Option<String>,
    /// auto 模式已下載好、等結束或重新開啟時安裝。
    pub ready: bool,
}

#[derive(Default)]
pub struct Updates {
    last: Mutex<CheckInfo>,
    ready: Mutex<Option<(Update, Vec<u8>)>>,
    busy: AtomicBool,
    /// 視窗開過了（登入時 `--tray` 啟動、還沒開過視窗時，auto 模式直接安裝）。
    pub window_shown: AtomicBool,
}

fn notes_url(v: &str) -> String {
    format!("{RELEASES}/tag/v{}", v.trim_start_matches('v'))
}

fn mode_of(dir: &std::path::Path) -> UpdateMode {
    config::load(dir).map(|c| c.update.mode).unwrap_or_default()
}

/// 這份安裝能不能由桌面版自己更新；不行就回原因。
pub fn install_blocker() -> Option<&'static str> {
    if cfg!(debug_assertions) {
        return Some("開發版（從原始碼建置）不會自動更新");
    }
    None
}

/// 這份安裝能不能「不問就」自動安裝：.deb／.rpm 要輸入系統管理員密碼，只在按「立即更新」時安裝。
pub fn auto_install_ok() -> bool {
    use tauri::utils::{config::BundleType, platform::bundle_type};
    !matches!(bundle_type(), Some(BundleType::Deb) | Some(BundleType::Rpm))
}

/// 查一次（不下載）。結果記在 `last`，也寫進 agent 的 update-state.json（內建背景服務的心跳會帶給 Hub）。
async fn check(app: &AppHandle) -> Result<Option<Update>, String> {
    let st = app.state::<Updates>();
    let res = match app.updater() {
        Ok(u) => u.check().await.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    let mut last = st.last.lock().await;
    last.checked_at = Some(Utc::now());
    match &res {
        Ok(Some(u)) => {
            last.latest = Some(u.version.clone());
            last.available = true;
            last.notes = u.body.clone().filter(|b| !b.trim().is_empty());
            last.notes_url = Some(notes_url(&u.version));
            last.error = None;
        }
        Ok(None) => {
            last.latest = Some(asa_lib::VERSION.to_string());
            last.available = false;
            last.notes = None;
            last.notes_url = None;
            last.error = None;
            last.ready = false;
        }
        Err(e) => last.error = Some(e.clone()),
    }
    if let (Ok(_), Some(v)) = (&res, last.latest.clone()) {
        let dir = &app.state::<AppState>().config_dir;
        let mut s = asa_lib::update::auto::UpdateState::load(dir);
        s.record_check(Utc::now(), &v, last.notes_url.as_deref().unwrap_or(""));
        s.save(dir);
    }
    res
}

async fn download(app: &AppHandle, u: &Update) -> Result<Vec<u8>, String> {
    let app2 = app.clone();
    let mut got = 0usize;
    u.download(
        move |n, total| {
            got += n;
            let _ = app2.emit("update-progress", json!({ "downloaded": got, "total": total }));
        },
        || {},
    )
    .await
    .map_err(|e| e.to_string())
}

/// 換好新版之後（macOS／Linux；Windows 的安裝程式會自己處理）：背景自動回報換成新版。
async fn restart_background(app: &AppHandle) {
    let dir = app.state::<AppState>().config_dir.clone();
    let _ = asa_lib::cli::service_cmd::restart_user_service(&dir).await;
}

/// 安裝；Windows 會啟動安裝程式並結束這個程式（`relaunch`：裝完要不要重新開啟桌面版）。
async fn install(app: &AppHandle, u: Update, bytes: Vec<u8>, relaunch: bool) -> Result<(), String> {
    let _ = app.emit("update-installing", json!({ "version": u.version }));
    let u = u.restart_after_install(relaunch);
    u.install(bytes).map_err(|e| e.to_string())?;
    // 到這裡的是 macOS／Linux（Windows 在 install 裡就結束了）
    restart_background(app).await;
    if relaunch {
        app.restart();
    }
    Ok(())
}

/// 依設定檢查一次：notify 送通知；auto 下載好（登入時在系統匣啟動、視窗還沒開過就直接安裝）。
async fn tick(app: &AppHandle, start_in_tray: bool) {
    let st = app.state::<Updates>();
    let mode = mode_of(&app.state::<AppState>().config_dir);
    if mode == UpdateMode::Off || st.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let result = async {
        let Some(u) = check(app).await? else { return Ok(()) };
        let _ = app.emit(
            "update-available",
            json!({ "version": u.version, "notes_url": notes_url(&u.version), "mode": mode.as_str() }),
        );
        if mode != UpdateMode::Auto || install_blocker().is_some() || !auto_install_ok() {
            return Ok(());
        }
        if st
            .ready
            .lock()
            .await
            .as_ref()
            .is_some_and(|(r, _)| r.version == u.version)
        {
            return Ok(());
        }
        let bytes = download(app, &u).await?;
        let version = u.version.clone();
        if start_in_tray && !st.window_shown.load(Ordering::SeqCst) {
            // 剛登入、使用者還沒打開視窗：現在就裝（裝完以系統匣模式重新開啟）
            return install(app, u, bytes, true).await;
        }
        *st.ready.lock().await = Some((u, bytes));
        st.last.lock().await.ready = true;
        let _ = app.emit("update-ready", json!({ "version": version }));
        Ok::<(), String>(())
    }
    .await;
    if let Err(e) = result {
        st.last.lock().await.error = Some(e);
    }
    st.busy.store(false, Ordering::SeqCst);
}

/// 背景：啟動後約 30 秒檢查一次，之後每 24 小時（加 0～3 小時隨機）；關閉時每小時看一次設定。
pub fn spawn_background(app: AppHandle, start_in_tray: bool) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            let mode = mode_of(&app.state::<AppState>().config_dir);
            let wait = if mode == UpdateMode::Off {
                Duration::from_secs(3600)
            } else {
                tick(&app, start_in_tray).await;
                asa_lib::update::auto::CHECK_EVERY + asa_lib::update::auto::jitter(asa_lib::update::auto::JITTER_MAX)
            };
            tokio::time::sleep(wait).await;
        }
    });
}

/// 從系統匣「結束」：auto 模式有下載好的更新就先裝（不重新開啟），再結束。
pub fn quit(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let ready = app.state::<Updates>().ready.lock().await.take();
        if let Some((u, bytes)) = ready {
            let _ = install(&app, u, bytes, false).await;
        }
        app.exit(0);
    });
}

/// 用這個執行檔以外的程式在跑的背景回報（另外裝的命令列版）。
fn other_watchers(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let me = std::env::current_exe().ok();
    let mut v: Vec<std::path::PathBuf> = asa_lib::service::running_watchers(Some(dir))
        .into_iter()
        .filter_map(|w| w.exe)
        .filter(|e| me.as_ref().is_none_or(|m| !same_path(m, e)))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    let n = |p: &std::path::Path| p.display().to_string().trim_start_matches(r"\\?\").to_ascii_lowercase();
    n(a) == n(b)
}

async fn run_cli(exe: &std::path::Path, args: &[&str], timeout: Duration) -> Result<Value, String> {
    let mut c = tokio::process::Command::new(exe);
    c.args(args).kill_on_drop(true);
    #[cfg(windows)]
    {
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = tokio::time::timeout(timeout, c.output())
        .await
        .map_err(|_| "逾時".to_string())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text
        .find('{')
        .ok_or_else(|| String::from_utf8_lossy(&out.stderr).trim().to_string())?;
    serde_json::from_str(&text[start..]).map_err(|e| e.to_string())
}

/// 設定頁要的全部：模式、桌面版的版本與最近一次檢查、背景服務用的是誰。
#[tauri::command]
pub async fn update_status(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    let last = app.state::<Updates>().last.lock().await.clone();
    let agent_state = asa_lib::update::auto::UpdateState::load(dir);
    let mut cli = Vec::new();
    for exe in other_watchers(dir) {
        let v = run_cli(&exe, &["--json", "version"], Duration::from_secs(10))
            .await
            .ok();
        let version = v.as_ref().and_then(|v| v["version"].as_str()).map(str::to_string);
        let latest = last.latest.clone().or(agent_state.latest.clone());
        let newer = match (&version, &latest) {
            (Some(cur), Some(l)) => asa_lib::update::is_newer(l, cur),
            _ => false,
        };
        cli.push(json!({ "exe": exe, "version": version, "latest": latest, "newer": newer }));
    }
    let watchers = asa_lib::service::running_watchers(Some(dir));
    Ok(json!({
        "mode": cfg.update.mode,
        "current": asa_lib::VERSION,
        "desktop": last,
        "blocker": install_blocker(),
        "auto_install_ok": auto_install_ok(),
        "releases_url": RELEASES,
        "background": {
            "running": watchers.len(),
            "uses_desktop": watchers.len() > cli.len(),
            "cli": cli,
        },
        "agent_state": agent_state,
    }))
}

#[tauri::command]
pub async fn set_update_mode(app: AppHandle, state: State<'_, AppState>, mode: String) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut cfg = config::load_or_init(dir).map_err(err)?;
    config::set_value(&mut cfg, "update.mode", &mode).map_err(err)?;
    config::save(dir, &cfg).map_err(err)?;
    if cfg.update.mode == UpdateMode::Off {
        *app.state::<Updates>().ready.lock().await = None;
        app.state::<Updates>().last.lock().await.ready = false;
    }
    update_status(app, state).await
}

/// 「檢查更新」：現在就查（不管設定是不是關閉）。
#[tauri::command]
pub async fn check_updates(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Value> {
    let _ = check(&app).await;
    update_status(app, state).await
}

/// 「立即更新」：下載（或用已下載好的）並安裝，裝完重新開啟桌面版；背景自動回報一起換成新版。
#[tauri::command]
pub async fn install_update(app: AppHandle) -> CmdResult<Value> {
    if let Some(why) = install_blocker() {
        return Err(why.into());
    }
    let st = app.state::<Updates>();
    if st.busy.swap(true, Ordering::SeqCst) {
        return Err("正在檢查或下載更新，請稍候".into());
    }
    let result = async {
        let ready = st.ready.lock().await.take();
        let (u, bytes) = match ready {
            Some(x) => x,
            None => {
                let u = check(&app)
                    .await?
                    .ok_or_else(|| format!("已是最新版（{}）", asa_lib::VERSION))?;
                let bytes = download(&app, &u).await?;
                (u, bytes)
            }
        };
        install(&app, u, bytes, true).await
    }
    .await;
    st.busy.store(false, Ordering::SeqCst);
    result.map(|_| json!({ "ok": true }))
}

/// 另外裝的命令列版背景服務：跑一次它的 `self-update --yes`（下載、驗證、替換，並重新啟動用它的背景服務）。
#[tauri::command]
pub async fn update_cli_agent(state: State<'_, AppState>, exe: String) -> CmdResult<Value> {
    let exe = std::path::PathBuf::from(exe);
    // 只接受目前真的在跑背景回報的那幾個執行檔
    if !other_watchers(&state.config_dir).iter().any(|e| same_path(e, &exe)) {
        return Err("找不到這個背景服務".into());
    }
    let dir = state.config_dir.display().to_string();
    run_cli(
        &exe,
        &["--json", "--config-dir", &dir, "self-update", "--yes"],
        Duration::from_secs(600),
    )
    .await
}
