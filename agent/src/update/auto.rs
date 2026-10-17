//! 背景自動更新（`watch` 用）與「誰負責更新」的判斷。
//!
//! - `update.mode`：`off` 不檢查；`notify`（預設）每天最多查一次 GitHub Release（或 `AI_SECURITY_MONITOR_UPDATE_URL`
//!   指定的鏡像），有新版就記在 `<設定目錄>/update-state.json`，並放進心跳讓 Hub 顯示「有新版」；
//!   `auto` 在背景服務裡下載、比對 SHA256SUMS、原地替換執行檔，再重新啟動常駐行程。
//! - 檢查時間：服務啟動後 2～20 分鐘（隨機）第一次查，之後每 24 小時＋0～3 小時隨機；上次排定的時間還沒到就照舊等。
//! - 誰負責安裝（owner）：桌面版執行檔帶的 agent（桌面版「背景自動回報」登記的就是桌面版本身）一律交給
//!   桌面版的更新器（簽章的安裝檔），這裡只檢查、記錄——否則命令列版的執行檔會蓋掉桌面版。
//! - 不自動安裝：開發版（debug 建置、`cargo run`、`target/` 底下）與套件管理員裝的（`/usr/bin`、Homebrew、Scoop、winget…）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::UpdateMode;
use crate::hub::contract::UpdateInfo;
use crate::store;

pub const STATE_FILE: &str = "update-state.json";
/// 兩次檢查的最短間隔；另加 0～`JITTER_MAX` 隨機，免得整個公司同一刻去 GitHub。
pub const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
pub const JITTER_MAX: Duration = Duration::from_secs(3 * 3600);
/// 服務啟動後第一次檢查前的等待（隨機落在這個區間）：開機時不搶網路。
pub const FIRST_MIN: Duration = Duration::from_secs(2 * 60);
pub const FIRST_MAX: Duration = Duration::from_secs(20 * 60);
/// 交給服務管理器重新啟動時的結束碼（systemd `Restart=on-failure`、launchd `KeepAlive`、Windows 服務的失敗動作）。
pub const RESTART_EXIT_CODE: i32 = 75;

static EMBEDDED_IN_DESKTOP: AtomicBool = AtomicBool::new(false);

/// 桌面版的 `main` 在把命令列交給 asa_lib 之前呼叫：這個行程的執行檔是桌面版，更新歸桌面版的更新器。
pub fn set_embedded_in_desktop() {
    EMBEDDED_IN_DESKTOP.store(true, Ordering::SeqCst);
}

pub fn embedded_in_desktop() -> bool {
    EMBEDDED_IN_DESKTOP.load(Ordering::SeqCst)
}

/// 負責更新這個執行檔的元件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    /// 命令列版自己（`self-update`、`update.mode = auto`）。
    Agent,
    /// 桌面版的更新器。
    Desktop,
}

impl Owner {
    pub fn as_str(self) -> &'static str {
        match self {
            Owner::Agent => "agent",
            Owner::Desktop => "desktop",
        }
    }
}

/// 這個執行檔是怎麼裝的（決定能不能自我更新）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallKind {
    /// 下載的執行檔／安裝腳本裝的：可以自我更新。
    Standalone,
    /// 桌面版執行檔：由桌面版的更新器更新。
    Desktop,
    /// 開發版（debug 建置、`cargo run`、`target/` 底下）。
    DevBuild,
    /// 套件管理員裝的：請用套件管理員更新。
    PackageManager { manager: String },
}

impl InstallKind {
    pub fn owner(&self) -> Owner {
        match self {
            InstallKind::Desktop => Owner::Desktop,
            _ => Owner::Agent,
        }
    }

    pub fn can_self_update(&self) -> bool {
        matches!(self, InstallKind::Standalone)
    }

    /// 不在這裡自動安裝的原因（給 log、心跳、`status`）。
    pub fn reason(&self) -> Option<String> {
        match self {
            InstallKind::Standalone => None,
            InstallKind::Desktop => Some(t!("桌面版內建的背景服務：由桌面版的更新器更新").to_string()),
            InstallKind::DevBuild => Some(t!("開發版（從原始碼建置）：不自動更新").to_string()),
            InstallKind::PackageManager { manager } => {
                Some(tf!("由 {manager} 安裝：請用 {manager} 更新", manager = manager))
            }
        }
    }
}

/// 依執行檔路徑判斷安裝方式（純函數，測試用）。
pub fn classify(exe: &str, debug_build: bool, under_cargo: bool, embedded: bool) -> InstallKind {
    if embedded {
        return InstallKind::Desktop;
    }
    let p = exe.replace('\\', "/").to_ascii_lowercase();
    if debug_build || under_cargo || (p.contains("/target/") && (p.contains("/debug/") || p.contains("/release/"))) {
        return InstallKind::DevBuild;
    }
    const MANAGERS: &[(&str, &str)] = &[
        ("/nix/store/", "Nix"),
        ("/snap/", "Snap"),
        ("/opt/homebrew/", "Homebrew"),
        ("/usr/local/cellar/", "Homebrew"),
        ("/home/linuxbrew/", "Homebrew"),
        ("/scoop/apps/", "Scoop"),
        ("/winget/packages/", "winget"),
        ("/chocolatey/lib/", "Chocolatey"),
        ("/usr/bin/", "apt／dnf"),
        ("/usr/sbin/", "apt／dnf"),
        ("/usr/lib/", "apt／dnf"),
        ("/usr/libexec/", "apt／dnf"),
        ("/bin/", "apt／dnf"),
        ("/sbin/", "apt／dnf"),
    ];
    for (prefix, manager) in MANAGERS {
        let hit = if prefix.starts_with("/usr/")
            || *prefix == "/bin/"
            || *prefix == "/sbin/"
            || *prefix == "/snap/"
            || *prefix == "/nix/store/"
        {
            p.starts_with(prefix)
        } else {
            p.contains(prefix)
        };
        if hit {
            return InstallKind::PackageManager {
                manager: manager.to_string(),
            };
        }
    }
    InstallKind::Standalone
}

/// 目前執行檔（去掉 Windows 的 `\\?\` 前綴）。
pub fn current_exe() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?;
    let s = p.display().to_string();
    Some(PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s)))
}

/// 這個行程的安裝方式。
pub fn install_kind() -> InstallKind {
    let exe = current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    classify(
        &exe,
        cfg!(debug_assertions),
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        embedded_in_desktop(),
    )
}

/// 最近一次自動／手動更新。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Installed {
    pub from: String,
    pub to: String,
    pub at: DateTime<Utc>,
    /// `auto`／`manual`。
    pub how: String,
}

/// `<設定目錄>/update-state.json`。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpdateState {
    pub checked_at: Option<DateTime<Utc>>,
    pub next_check_at: Option<DateTime<Utc>>,
    /// GitHub（或鏡像）上的最新版。
    pub latest: Option<String>,
    pub release_url: Option<String>,
    pub error: Option<String>,
    pub installed: Option<Installed>,
    /// 有新版但沒有自動安裝的原因。
    pub note: Option<String>,
}

impl UpdateState {
    pub fn load(config_dir: &Path) -> Self {
        store::read_json_opt(config_dir, STATE_FILE)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) {
        let _ = store::write_json_in(config_dir, STATE_FILE, self);
    }

    /// 比 `current` 新的最新版。
    pub fn available(&self, current: &str) -> Option<&str> {
        self.latest.as_deref().filter(|l| super::is_newer(l, current))
    }

    /// 記下一次檢查結果（手動 `self-update --check`、`version --check`、桌面版也用）。
    pub fn record_check(&mut self, now: DateTime<Utc>, latest: &str, url: &str) {
        self.checked_at = Some(now);
        self.latest = Some(latest.to_string());
        self.release_url = Some(url.to_string()).filter(|u| !u.is_empty());
        self.error = None;
    }
}

/// 0..max 的隨機時間。
pub fn jitter(max: Duration) -> Duration {
    let secs = max.as_secs().max(1);
    Duration::from_secs((uuid::Uuid::new_v4().as_u128() % u128::from(secs)) as u64)
}

fn add(t: DateTime<Utc>, d: Duration) -> DateTime<Utc> {
    t + chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::zero())
}

/// 檢查完之後的下一次：24 小時＋隨機。
pub fn next_after(now: DateTime<Utc>, jitter: Duration) -> DateTime<Utc> {
    add(now, CHECK_EVERY + jitter.min(JITTER_MAX))
}

/// 服務啟動時決定第一次檢查的時間：上次排定的時間還沒到（而且不離譜）就照舊；否則 2～20 分鐘後。
pub fn first_check_at(state: &UpdateState, now: DateTime<Utc>, jitter: Duration) -> DateTime<Utc> {
    let latest_allowed = add(now, CHECK_EVERY + JITTER_MAX);
    match state.next_check_at {
        Some(t) if t > now && t <= latest_allowed => t,
        _ => add(now, FIRST_MIN + jitter.min(FIRST_MAX - FIRST_MIN)),
    }
}

/// 一次檢查的結果。
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 已是最新版。
    UpToDate { latest: String },
    /// 有新版但這裡不安裝（`notify`、桌面版負責、開發版／套件管理員、沒有這個平台的檔、或不是背景服務）。
    Available {
        latest: String,
        url: String,
        note: Option<String>,
    },
    /// 已下載、驗證並替換執行檔；呼叫端要重新啟動常駐行程。
    Installed { from: String, to: String },
    /// 查詢或安裝失敗（下次照排程再試）。
    Failed(String),
}

/// 檢查一次（`base`：Release API，平常是 `update::base_url()`）；`mode` 是 `auto`、可以自我更新、
/// 而且 `allow_install`（背景服務）時就安裝。結果寫進 `update-state.json`。
pub async fn check_and_apply(
    config_dir: &Path,
    base: &str,
    mode: UpdateMode,
    kind: &InstallKind,
    exe: &Path,
    allow_install: bool,
) -> Outcome {
    let mut state = UpdateState::load(config_dir);
    let now = Utc::now();
    state.next_check_at = Some(next_after(now, jitter(JITTER_MAX)));
    let rel = match super::fetch_release(base, None).await {
        Ok(r) => r,
        Err(e) => {
            state.checked_at = Some(now);
            state.error = Some(e.message());
            state.save(config_dir);
            return Outcome::Failed(e.message());
        }
    };
    let c = super::check_release(&rel, crate::VERSION);
    state.record_check(now, &c.latest, &c.release_url);
    if !c.newer {
        state.note = None;
        state.save(config_dir);
        return Outcome::UpToDate { latest: c.latest };
    }
    let note = if mode != UpdateMode::Auto {
        None
    } else if let Some(why) = kind.reason() {
        Some(why)
    } else if !allow_install {
        Some(
            t!("只有背景服務（watch --service）會自動安裝；手動更新：ai-security-monitor self-update --yes")
                .to_string(),
        )
    } else if c.asset.is_none() {
        Some(tf!(
            "Release {tag} 沒有這個平台（{os}/{arch}）的執行檔",
            tag = rel.tag,
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH
        ))
    } else {
        None
    };
    let install = mode == UpdateMode::Auto && note.is_none();
    state.note = note.clone();
    if !install {
        state.save(config_dir);
        return Outcome::Available {
            latest: c.latest,
            url: c.release_url,
            note,
        };
    }
    let asset = c.asset.clone().expect("checked above");
    let result = async {
        let (bytes, _sha) = super::download_verified(&rel, &asset).await?;
        super::replace_exe(exe, &bytes)
    }
    .await;
    match result {
        Ok(_) => {
            state.installed = Some(Installed {
                from: crate::VERSION.to_string(),
                to: rel.version.clone(),
                at: Utc::now(),
                how: "auto".into(),
            });
            state.save(config_dir);
            Outcome::Installed {
                from: crate::VERSION.to_string(),
                to: rel.version,
            }
        }
        Err(e) => {
            state.error = Some(e.message());
            state.save(config_dir);
            Outcome::Failed(e.message())
        }
    }
}

/// 心跳裡的更新狀態（Hub 依此在主機清單顯示「有新版」）。
pub fn heartbeat_info(state: &UpdateState, mode: UpdateMode, kind: &InstallKind, current: &str) -> UpdateInfo {
    let latest = state.latest.clone();
    UpdateInfo {
        mode: mode.as_str().to_string(),
        owner: kind.owner().as_str().to_string(),
        available: latest.as_deref().is_some_and(|l| super::is_newer(l, current)),
        latest,
        checked_at: state.checked_at,
        note: state.note.clone().or_else(|| state.error.clone()),
    }
}

/// 誰在管這個常駐行程（決定換好新版之後怎麼重新啟動）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Supervisor {
    /// Windows 服務（`service run`）：非零結束 → 服務的失敗動作 1 分鐘後重新啟動。
    WindowsService,
    /// systemd（`Restart=on-failure`）。
    Systemd,
    /// launchd（`KeepAlive` 的 `SuccessfulExit=false`）。
    Launchd,
    /// 登入時啟動（Windows Run、XDG autostart）或手動執行：自己啟動新的一份再結束。
    Plain,
}

/// 判斷常駐行程由誰管理。`scm`：由 Windows 服務入口啟動。
pub fn supervisor(scm: bool) -> Supervisor {
    if scm {
        return Supervisor::WindowsService;
    }
    if cfg!(target_os = "linux") && std::env::var_os("INVOCATION_ID").is_some() {
        return Supervisor::Systemd;
    }
    if cfg!(target_os = "macos") {
        let label = std::env::var("XPC_SERVICE_NAME").unwrap_or_default();
        if label == crate::service::units::NAMES.label || label == crate::service::units::LEGACY_NAMES.label {
            return Supervisor::Launchd;
        }
    }
    Supervisor::Plain
}

/// 換好新版後重新啟動常駐行程（不會回來）。服務管理器管的就以 `RESTART_EXIT_CODE` 結束讓它重新啟動；
/// 登入時啟動的先放掉單一實例鎖、用同樣的參數啟動新版，再結束自己。
pub fn restart(sup: Supervisor, exe: &Path, lock: Option<crate::service::instance::InstanceLock>) -> ! {
    drop(lock);
    if sup == Supervisor::Plain {
        let args: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        match crate::service::spawn_detached(&exe.display().to_string(), &args) {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                crate::service::instance::write_log(&tf!("無法啟動新版：{e}", e = e));
                std::process::exit(RESTART_EXIT_CODE)
            }
        }
    }
    std::process::exit(RESTART_EXIT_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn classifies_install_kinds() {
        let s = |p: &str| classify(p, false, false, false);
        assert_eq!(
            s(r"C:\Users\a\AppData\Local\ai-security-monitor\bin\ai-security-monitor.exe"),
            InstallKind::Standalone
        );
        assert_eq!(s("/usr/local/bin/ai-security-monitor"), InstallKind::Standalone);
        assert_eq!(s("/home/a/.local/bin/ai-security-monitor"), InstallKind::Standalone);
        assert_eq!(
            s("/home/a/src/ai-security-monitor/agent/target/release/ai-security-monitor"),
            InstallKind::DevBuild
        );
        assert_eq!(
            s(r"D:\src\agent\target\debug\ai-security-monitor.exe"),
            InstallKind::DevBuild
        );
        assert_eq!(
            classify("/opt/x/ai-security-monitor", true, false, false),
            InstallKind::DevBuild
        );
        assert_eq!(
            classify("/opt/x/ai-security-monitor", false, true, false),
            InstallKind::DevBuild
        );
        assert_eq!(
            classify("/usr/bin/ai-security-monitor-desktop", false, false, true),
            InstallKind::Desktop
        );
        for (p, m) in [
            ("/usr/bin/ai-security-monitor", "apt／dnf"),
            ("/opt/homebrew/bin/ai-security-monitor", "Homebrew"),
            (
                "/usr/local/Cellar/ai-security-monitor/0.3.0/bin/ai-security-monitor",
                "Homebrew",
            ),
            (
                r"C:\Users\a\scoop\apps\ai-security-monitor\current\ai-security-monitor.exe",
                "Scoop",
            ),
            (
                r"C:\Users\a\AppData\Local\Microsoft\WinGet\Packages\x\ai-security-monitor.exe",
                "winget",
            ),
            ("/nix/store/abc-ai-security-monitor/bin/ai-security-monitor", "Nix"),
        ] {
            assert_eq!(s(p), InstallKind::PackageManager { manager: m.into() }, "{p}");
        }
        assert!(InstallKind::Standalone.can_self_update());
        assert!(!InstallKind::Desktop.can_self_update());
        assert_eq!(InstallKind::Desktop.owner(), Owner::Desktop);
        assert_eq!(InstallKind::DevBuild.owner(), Owner::Agent);
        assert!(InstallKind::Standalone.reason().is_none());
        assert!(InstallKind::PackageManager {
            manager: "Homebrew".into()
        }
        .reason()
        .unwrap()
        .contains("Homebrew"));
    }

    #[test]
    fn checks_at_most_once_a_day_with_jitter() {
        let now = t("2026-10-17T08:00:00Z");
        // 檢查完：24 小時＋隨機（不超過 3 小時）
        let n = next_after(now, Duration::from_secs(3600));
        assert_eq!(n, t("2026-10-18T09:00:00Z"));
        assert_eq!(
            next_after(now, Duration::from_secs(99 * 3600)),
            t("2026-10-18T11:00:00Z")
        );
        for _ in 0..50 {
            let j = jitter(JITTER_MAX);
            assert!(j < JITTER_MAX);
        }
        // 沒排過：2～20 分鐘後
        let s = UpdateState::default();
        assert_eq!(first_check_at(&s, now, Duration::ZERO), t("2026-10-17T08:02:00Z"));
        assert_eq!(
            first_check_at(&s, now, Duration::from_secs(3600)),
            t("2026-10-17T08:20:00Z")
        );
        // 排定的時間還沒到：照舊等（重開服務不會多查一次）
        let s = UpdateState {
            next_check_at: Some(t("2026-10-18T01:00:00Z")),
            ..Default::default()
        };
        assert_eq!(first_check_at(&s, now, Duration::ZERO), t("2026-10-18T01:00:00Z"));
        // 已經過了、或遠得離譜（時鐘被調過）：重新排 2～20 分鐘後
        for bad in ["2026-10-17T07:00:00Z", "2026-11-30T00:00:00Z"] {
            let s = UpdateState {
                next_check_at: Some(t(bad)),
                ..Default::default()
            };
            assert_eq!(
                first_check_at(&s, now, Duration::ZERO),
                t("2026-10-17T08:02:00Z"),
                "{bad}"
            );
        }
    }

    #[test]
    fn state_roundtrip_and_heartbeat() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(UpdateState::load(d.path()), UpdateState::default());
        let mut s = UpdateState::default();
        s.record_check(t("2026-10-17T08:00:00Z"), "9.9.0", "https://example/r");
        s.note = Some("x".into());
        s.save(d.path());
        let s2 = UpdateState::load(d.path());
        assert_eq!(s2, s);
        assert_eq!(s2.available("0.3.0"), Some("9.9.0"));
        assert_eq!(s2.available("9.9.0"), None);
        let hb = heartbeat_info(&s2, UpdateMode::Notify, &InstallKind::Standalone, "0.3.0");
        assert!(hb.available);
        assert_eq!(hb.latest.as_deref(), Some("9.9.0"));
        assert_eq!(hb.mode, "notify");
        assert_eq!(hb.owner, "agent");
        let hb = heartbeat_info(&s2, UpdateMode::Auto, &InstallKind::Desktop, "9.9.0");
        assert!(!hb.available);
        assert_eq!(hb.owner, "desktop");
        assert_eq!(hb.mode, "auto");
    }

    /// 測試伺服器：回一個比目前新的 Release（下載網址指回同一台），需要時再回 SHA256SUMS 與執行檔。
    async fn serve_release(version: &str, with_binary: Option<&str>) -> String {
        let name = super::super::asset_name(version, std::env::consts::OS, std::env::consts::ARCH)
            .unwrap_or_else(|| format!("ai-security-monitor-{version}-x"));
        let mut responses = vec![(
            200,
            format!(
                r#"{{"tag_name":"v{version}","html_url":"https://example/v{version}","assets":[{{"name":"{name}","browser_download_url":"{{BASE}}/dl/{name}","size":3}},{{"name":"SHA256SUMS","browser_download_url":"{{BASE}}/dl/SHA256SUMS","size":100}}]}}"#
            ),
        )];
        if let Some(body) = with_binary {
            responses.push((
                200,
                format!(
                    "{}  {name}
",
                    super::super::sha256_hex(body.as_bytes())
                ),
            ));
            responses.push((200, body.to_string()));
        }
        crate::hub::test_server::serve(responses).await.0
    }

    #[test]
    fn notify_records_without_installing_and_auto_respects_install_kind() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = tempfile::tempdir().unwrap();
            let exe = d.path().join("ai-security-monitor-test-exe");
            std::fs::write(&exe, b"old").unwrap();
            let url = serve_release("99.0.0", None).await;
            let out = check_and_apply(d.path(), &url, UpdateMode::Notify, &InstallKind::Standalone, &exe, true).await;
            assert!(
                matches!(&out, Outcome::Available { latest, note: None, .. } if latest == "99.0.0"),
                "{out:?}"
            );
            assert_eq!(std::fs::read(&exe).unwrap(), b"old");
            let st = UpdateState::load(d.path());
            assert_eq!(st.latest.as_deref(), Some("99.0.0"));
            assert!(st.next_check_at.unwrap() > Utc::now() + chrono::Duration::hours(23));

            // auto，但這是桌面版內建的：不裝，記下原因
            let url = serve_release("99.0.0", None).await;
            let out = check_and_apply(d.path(), &url, UpdateMode::Auto, &InstallKind::Desktop, &exe, true).await;
            assert!(matches!(&out, Outcome::Available { note: Some(_), .. }), "{out:?}");
            assert_eq!(std::fs::read(&exe).unwrap(), b"old");

            // auto 但不是背景服務：不裝
            let url = serve_release("99.0.0", None).await;
            let out = check_and_apply(d.path(), &url, UpdateMode::Auto, &InstallKind::Standalone, &exe, false).await;
            assert!(matches!(&out, Outcome::Available { note: Some(_), .. }), "{out:?}");

            // auto＋可以自我更新＋背景服務：下載、驗證、替換
            if super::super::target_suffix(std::env::consts::OS, std::env::consts::ARCH).is_some() {
                let url = serve_release("99.0.0", Some("new")).await;
                let out = check_and_apply(d.path(), &url, UpdateMode::Auto, &InstallKind::Standalone, &exe, true).await;
                assert_eq!(
                    out,
                    Outcome::Installed {
                        from: crate::VERSION.into(),
                        to: "99.0.0".into()
                    }
                );
                assert_eq!(std::fs::read(&exe).unwrap(), b"new");
                assert_eq!(UpdateState::load(d.path()).installed.unwrap().how, "auto");
            }
            // 查不到（伺服器關了）：記下錯誤，照樣排到明天
            let out = check_and_apply(
                d.path(),
                "http://127.0.0.1:9",
                UpdateMode::Notify,
                &InstallKind::Standalone,
                &exe,
                true,
            )
            .await;
            assert!(matches!(out, Outcome::Failed(_)), "{out:?}");
            let st = UpdateState::load(d.path());
            assert!(st.error.is_some());
            assert!(st.next_check_at.unwrap() > Utc::now() + chrono::Duration::hours(23));
        });
    }
}
