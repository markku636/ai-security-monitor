//! 開機自動啟動：
//! - `--system`（伺服器，需系統管理員／root）：Windows 服務（SCM）、systemd、launchd LaunchDaemon；
//! - `--user`（個人電腦，免管理員）：HKCU\…\Run、systemd --user（沒有就 XDG autostart）、launchd LaunchAgent。
//!
//! 安裝／移除都先產生「計畫」（純函數，可預覽與測試），`--yes` 後才執行。

pub mod instance;
pub mod units;
#[cfg(windows)]
pub mod winsvc;

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::util::cmd::{CmdRunner, CmdSpec};
use units::{DISPLAY_NAME, LABEL, SERVICE_NAME};

pub const WIN_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    WindowsService,
    WindowsRun,
    Systemd,
    SystemdUser,
    XdgAutostart,
    LaunchDaemon,
    LaunchAgent,
}

impl Manager {
    pub fn label(self) -> &'static str {
        match self {
            Manager::WindowsService => "Windows service (SCM)",
            Manager::WindowsRun => "HKCU Run",
            Manager::Systemd => "systemd",
            Manager::SystemdUser => "systemd --user",
            Manager::XdgAutostart => "XDG autostart",
            Manager::LaunchDaemon => "launchd LaunchDaemon",
            Manager::LaunchAgent => "launchd LaunchAgent",
        }
    }
}

/// 安裝目標（由目前環境組出；測試直接建構）。
#[derive(Debug, Clone)]
pub struct Target {
    pub os: Os,
    pub scope: Scope,
    pub exe: PathBuf,
    /// 服務讀的設定目錄（system：系統目錄；user：目前使用者的）。
    pub config_dir: PathBuf,
    /// 目前（安裝者）的設定目錄；system 安裝時從這裡搬註冊資料。
    pub source_config_dir: PathBuf,
    pub home: PathBuf,
    pub uid: u32,
    /// Linux 使用者層：`systemctl --user` 可用。
    pub systemd_user: bool,
    pub interval: Option<String>,
    /// 服務已經裝過（Windows 改用 sc config）。
    pub existing: bool,
    /// 使用者層要強制檔案密鑰庫（安裝時有設 ASA_SECRETS_BACKEND=file）。
    pub secrets_file: bool,
    /// 設定目錄就是預設位置：使用者層的命令列可以省略 --config-dir（Windows Run 有 260 字元上限）。
    pub default_config_dir: bool,
}

impl Target {
    pub fn manager(&self) -> Manager {
        match (self.os, self.scope) {
            (Os::Windows, Scope::System) => Manager::WindowsService,
            (Os::Windows, Scope::User) => Manager::WindowsRun,
            (Os::Linux, Scope::System) => Manager::Systemd,
            (Os::Linux, Scope::User) if self.systemd_user => Manager::SystemdUser,
            (Os::Linux, Scope::User) => Manager::XdgAutostart,
            (Os::Macos, Scope::System) => Manager::LaunchDaemon,
            (Os::Macos, Scope::User) => Manager::LaunchAgent,
        }
    }

    /// 服務的設定檔位置（unit／plist／desktop）。Windows 沒有檔案。
    pub fn unit_path(&self) -> Option<PathBuf> {
        Some(match self.manager() {
            Manager::Systemd => PathBuf::from("/etc/systemd/system/asa.service"),
            Manager::SystemdUser => self.home.join(".config/systemd/user/asa.service"),
            Manager::XdgAutostart => self.home.join(".config/autostart/asa.desktop"),
            Manager::LaunchDaemon => PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist")),
            Manager::LaunchAgent => self.home.join(format!("Library/LaunchAgents/{LABEL}.plist")),
            Manager::WindowsService | Manager::WindowsRun => return None,
        })
    }

    /// 常駐行程的參數（不含程式本身）。
    pub fn run_args(&self) -> Vec<String> {
        let mut a = Vec::new();
        if self.scope == Scope::System || !self.default_config_dir {
            a.extend(["--config-dir".to_string(), self.config_dir.display().to_string()]);
        }
        if self.scope == Scope::System || self.secrets_file {
            a.extend(["--secrets-backend".to_string(), "file".to_string()]);
        }
        if self.manager() == Manager::WindowsService {
            // SCM 要的是服務協定入口
            a.extend(["service".to_string(), "run".to_string()]);
        } else {
            a.extend(["watch".to_string(), "--service".to_string()]);
        }
        if let Some(i) = &self.interval {
            a.extend(["--interval".to_string(), i.clone()]);
        }
        a
    }
}

/// 系統層的設定目錄。
pub fn system_config_dir(os: Os) -> PathBuf {
    match os {
        Os::Windows => PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("ai-security-agent"),
        Os::Macos => PathBuf::from("/Library/Application Support/ai-security-agent"),
        Os::Linux => PathBuf::from("/var/lib/asa"),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    WriteFile {
        path: PathBuf,
        contents: String,
        mode: Option<u32>,
    },
    RemoveFile {
        path: PathBuf,
    },
    Run {
        program: String,
        args: Vec<String>,
        ignore_failure: bool,
    },
    /// 不經服務管理器直接在背景啟動（Windows Run、XDG 沒有「立即啟動」）。
    Spawn {
        program: String,
        args: Vec<String>,
    },
    /// 結束這個設定目錄的常駐 watch。
    StopWatchers {
        config_dir: PathBuf,
    },
    /// 把目前使用者的註冊資料（config.json＋hub 金鑰）搬到系統設定目錄（檔案密鑰庫）。
    CopyEnrollment {
        from: PathBuf,
        to: PathBuf,
    },
}

impl Step {
    pub fn describe(&self) -> String {
        match self {
            Step::WriteFile { path, .. } => tf!("寫入 {path}", path = path.display()),
            Step::RemoveFile { path } => tf!("刪除 {path}", path = path.display()),
            Step::Run { program, args, .. } | Step::Spawn { program, args } => std::iter::once(program.clone())
                .chain(args.iter().map(|a| crate::elevate::quote_win_arg(a)))
                .collect::<Vec<_>>()
                .join(" "),
            Step::StopWatchers { config_dir } => {
                tf!("結束使用 {dir} 的常駐 asa watch", dir = config_dir.display())
            }
            Step::CopyEnrollment { from, to } => {
                tf!("複製註冊資料 {from} → {to}", from = from.display(), to = to.display())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub scope: Scope,
    pub manager: Manager,
    pub steps: Vec<Step>,
    pub notes: Vec<String>,
}

fn run(program: &str, args: &[&str]) -> Step {
    Step::Run {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        ignore_failure: false,
    }
}

fn run_ok(program: &str, args: &[&str]) -> Step {
    Step::Run {
        program: program.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        ignore_failure: true,
    }
}

pub fn plan_install(t: &Target) -> Plan {
    let exe = t.exe.display().to_string();
    let args = t.run_args();
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    if t.scope == Scope::System && t.source_config_dir != t.config_dir {
        steps.push(Step::CopyEnrollment {
            from: t.source_config_dir.clone(),
            to: t.config_dir.clone(),
        });
    }
    let log_dir = instance::log_dir(&t.config_dir);
    match t.manager() {
        Manager::WindowsService => {
            let bin = units::windows_cmdline(&t.exe, &args);
            if t.existing {
                steps.push(run_ok("sc.exe", &["stop", SERVICE_NAME]));
                steps.push(run(
                    "sc.exe",
                    &["config", SERVICE_NAME, "binPath=", &bin, "start=", "auto"],
                ));
            } else {
                steps.push(run(
                    "sc.exe",
                    &[
                        "create",
                        SERVICE_NAME,
                        "binPath=",
                        &bin,
                        "start=",
                        "auto",
                        "DisplayName=",
                        DISPLAY_NAME,
                    ],
                ));
            }
            steps.push(run_ok(
                "sc.exe",
                &[
                    "description",
                    SERVICE_NAME,
                    "ai-security-agent: connection, threat-intel and system security monitoring",
                ],
            ));
            steps.push(run_ok(
                "sc.exe",
                &[
                    "failure",
                    SERVICE_NAME,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/60000/restart/60000/restart/300000",
                ],
            ));
            steps.push(run("sc.exe", &["start", SERVICE_NAME]));
        }
        Manager::WindowsRun => {
            let cmd = units::windows_cmdline(&t.exe, &args);
            if cmd.chars().count() > 260 {
                notes.push(tf!(
                    "命令列 {n} 字元，超過 Windows「執行」機碼的 260 字元上限，登入時可能不會啟動；請把 asa 放到較短的路徑",
                    n = cmd.chars().count()
                ));
            }
            steps.push(run(
                "reg.exe",
                &["add", WIN_RUN_KEY, "/v", SERVICE_NAME, "/t", "REG_SZ", "/d", &cmd, "/f"],
            ));
            steps.push(Step::StopWatchers {
                config_dir: t.config_dir.clone(),
            });
            steps.push(Step::Spawn { program: exe, args });
        }
        Manager::Systemd => {
            let unit = t.unit_path().unwrap();
            steps.push(Step::WriteFile {
                path: unit,
                contents: units::systemd_unit(&t.exe, &args, true, &t.config_dir),
                mode: Some(0o644),
            });
            steps.push(run("systemctl", &["daemon-reload"]));
            steps.push(run("systemctl", &["enable", "asa.service"]));
            steps.push(run("systemctl", &["restart", "asa.service"]));
        }
        Manager::SystemdUser => {
            let unit = t.unit_path().unwrap();
            steps.push(Step::WriteFile {
                path: unit,
                contents: units::systemd_unit(&t.exe, &args, false, &t.config_dir),
                mode: Some(0o644),
            });
            steps.push(run("systemctl", &["--user", "daemon-reload"]));
            steps.push(run("systemctl", &["--user", "enable", "asa.service"]));
            steps.push(run("systemctl", &["--user", "restart", "asa.service"]));
            notes.push(
                t!("沒有登入時也要執行（例如伺服器開機後）：sudo loginctl enable-linger $USER，或改用 --system")
                    .to_string(),
            );
        }
        Manager::XdgAutostart => {
            steps.push(Step::WriteFile {
                path: t.unit_path().unwrap(),
                contents: units::xdg_desktop(&t.exe, &args),
                mode: Some(0o644),
            });
            steps.push(Step::StopWatchers {
                config_dir: t.config_dir.clone(),
            });
            steps.push(Step::Spawn { program: exe, args });
            notes.push(t!("XDG autostart 只在登入桌面時啟動；伺服器請用 --system").to_string());
        }
        Manager::LaunchDaemon | Manager::LaunchAgent => {
            let system = t.manager() == Manager::LaunchDaemon;
            let plist = t.unit_path().unwrap();
            let domain = if system {
                "system".to_string()
            } else {
                format!("gui/{}", t.uid)
            };
            steps.push(Step::WriteFile {
                path: plist.clone(),
                contents: units::launchd_plist(&t.exe, &args, &log_dir, system),
                mode: Some(0o644),
            });
            steps.push(run_ok("launchctl", &["bootout", &format!("{domain}/{LABEL}")]));
            steps.push(run("launchctl", &["bootstrap", &domain, &plist.display().to_string()]));
        }
    }
    Plan {
        scope: t.scope,
        manager: t.manager(),
        steps,
        notes,
    }
}

pub fn plan_uninstall(t: &Target) -> Plan {
    let mut steps = Vec::new();
    match t.manager() {
        Manager::WindowsService => {
            steps.push(run_ok("sc.exe", &["stop", SERVICE_NAME]));
            steps.push(run("sc.exe", &["delete", SERVICE_NAME]));
        }
        Manager::WindowsRun => {
            steps.push(run_ok("reg.exe", &["delete", WIN_RUN_KEY, "/v", SERVICE_NAME, "/f"]));
            steps.push(Step::StopWatchers {
                config_dir: t.config_dir.clone(),
            });
        }
        Manager::Systemd => {
            steps.push(run_ok("systemctl", &["disable", "--now", "asa.service"]));
            steps.push(Step::RemoveFile {
                path: t.unit_path().unwrap(),
            });
            steps.push(run_ok("systemctl", &["daemon-reload"]));
        }
        Manager::SystemdUser => {
            steps.push(run_ok("systemctl", &["--user", "disable", "--now", "asa.service"]));
            steps.push(Step::RemoveFile {
                path: t.unit_path().unwrap(),
            });
            steps.push(run_ok("systemctl", &["--user", "daemon-reload"]));
        }
        Manager::XdgAutostart => {
            steps.push(Step::RemoveFile {
                path: t.unit_path().unwrap(),
            });
            steps.push(Step::StopWatchers {
                config_dir: t.config_dir.clone(),
            });
        }
        Manager::LaunchDaemon | Manager::LaunchAgent => {
            let domain = if t.manager() == Manager::LaunchDaemon {
                "system".to_string()
            } else {
                format!("gui/{}", t.uid)
            };
            steps.push(run_ok("launchctl", &["bootout", &format!("{domain}/{LABEL}")]));
            steps.push(Step::RemoveFile {
                path: t.unit_path().unwrap(),
            });
        }
    }
    Plan {
        scope: t.scope,
        manager: t.manager(),
        steps,
        notes: Vec::new(),
    }
}

/// 常駐中的 asa watch（任何安裝方式；以命令列判斷）。
#[derive(Debug, Clone, Serialize)]
pub struct Watcher {
    pub pid: u32,
    pub cmd: String,
}

pub fn running_watchers(config_dir: Option<&Path>) -> Vec<Watcher> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing()
            .with_cmd(sysinfo::UpdateKind::Always)
            .with_exe(sysinfo::UpdateKind::OnlyIfNotSet),
    );
    let me = std::process::id();
    let dir = config_dir.map(|d| d.display().to_string());
    // 預設設定目錄的常駐行程命令列不帶 --config-dir
    let is_default = config_dir.is_some_and(|d| {
        dirs::config_dir()
            .map(|c| c.join(crate::config::APP_DIR_NAME))
            .is_some_and(|c| c == d)
    });
    sys.processes()
        .iter()
        .filter_map(|(pid, p)| {
            let args: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
            let name = p.name().to_string_lossy().to_ascii_lowercase();
            let is_asa = name == "asa" || name == "asa.exe";
            let daemon = (args.iter().any(|a| a == "watch") && args.iter().any(|a| a == "--service"))
                || (args.iter().any(|a| a == "service") && args.iter().any(|a| a == "run"));
            let same_dir = dir.as_ref().is_none_or(|d| {
                args.iter().any(|a| a == d) || (is_default && !args.iter().any(|a| a == "--config-dir"))
            });
            (is_asa && daemon && same_dir && pid.as_u32() != me).then(|| Watcher {
                pid: pid.as_u32(),
                cmd: args.join(" "),
            })
        })
        .collect()
}

fn stop_watchers(config_dir: &Path) -> usize {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut n = 0;
    for w in running_watchers(Some(config_dir)) {
        if let Some(p) = sys.process(sysinfo::Pid::from_u32(w.pid)) {
            if p.kill() {
                n += 1;
            }
        }
    }
    n
}

fn spawn_detached(program: &str, args: &[String]) -> std::io::Result<u32> {
    let mut c = std::process::Command::new(program);
    c.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        c.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    c.spawn().map(|ch| ch.id())
}

/// 搬註冊資料：config.json＋hub 金鑰（寫入檔案密鑰庫，服務帳號讀得到）。
pub fn copy_enrollment(from: &Path, to: &Path) -> AppResult<bool> {
    copy_enrollment_from(from, to, &crate::secrets::SecretStore::open(from))
}

pub fn copy_enrollment_from(from: &Path, to: &Path, src: &crate::secrets::SecretStore) -> AppResult<bool> {
    let src_cfg = from.join(crate::config::CONFIG_FILE);
    if !src_cfg.exists() {
        return Ok(false);
    }
    crate::store::ensure_dir(to)?;
    let cfg = crate::config::load_or_init(from)?;
    crate::config::save(to, &cfg)?;
    let dst = crate::secrets::SecretStore::with_backend(to, crate::secrets::Backend::File);
    for k in [
        crate::secrets::KEY_HUB_CLIENT,
        crate::secrets::KEY_HUB_ACTION,
        crate::secrets::KEY_HUB_AGENT_TOKEN,
    ] {
        if let Some(v) = src.get(k)? {
            dst.set(k, &v)?;
        }
    }
    for f in ["allowlist.json", "baseline.json"] {
        let p = from.join(f);
        if p.exists() {
            let _ = std::fs::copy(&p, to.join(f));
        }
    }
    Ok(true)
}

/// 執行計畫；回傳每一步的結果行。
pub async fn apply(plan: &Plan, runner: &dyn CmdRunner) -> AppResult<Vec<String>> {
    let mut out = Vec::new();
    for s in &plan.steps {
        match s {
            Step::WriteFile { path, contents, mode } => {
                if let Some(dir) = path.parent() {
                    crate::store::ensure_dir(dir)?;
                }
                crate::store::write_bytes_atomic(path, contents.as_bytes())?;
                #[cfg(unix)]
                if let Some(m) = mode {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(*m));
                }
                #[cfg(not(unix))]
                let _ = mode;
                out.push(format!("✓ {}", s.describe()));
            }
            Step::RemoveFile { path } => match std::fs::remove_file(path) {
                Ok(()) => out.push(format!("✓ {}", s.describe())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(AppError::Storage(format!("{}: {e}", path.display()))),
            },
            Step::Run {
                program,
                args,
                ignore_failure,
            } => {
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let res = runner.run(&CmdSpec::new(program, &a).timeout(60_000)).await;
                match res {
                    Ok(o) if o.ok() => out.push(format!("✓ {}", s.describe())),
                    _ if *ignore_failure => {}
                    Ok(o) => {
                        return Err(AppError::Service(format!(
                            "{}: {}",
                            s.describe(),
                            crate::util::text::clip(format!("{} {}", o.stdout, o.stderr).trim(), 400)
                        )))
                    }
                    Err(e) => return Err(e),
                }
            }
            Step::Spawn { program, args } => {
                let pid = spawn_detached(program, args).map_err(|e| AppError::Service(format!("{program}: {e}")))?;
                out.push(tf!("✓ 已在背景啟動（PID {pid}）", pid = pid));
            }
            Step::StopWatchers { config_dir } => {
                let n = stop_watchers(config_dir);
                if n > 0 {
                    out.push(tf!("✓ 已結束 {n} 個常駐 asa watch", n = n));
                }
            }
            Step::CopyEnrollment { from, to } => {
                if copy_enrollment(from, to)? {
                    out.push(format!("✓ {}", s.describe()));
                } else {
                    out.push(t!("· 目前使用者還沒註冊 hub：服務先只在本機掃描（之後以系統管理員執行 asa --config-dir <系統目錄> enroll …）").to_string());
                }
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeStatus {
    pub scope: Scope,
    pub manager: Manager,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<PathBuf>,
}

/// `sc.exe query asa` 的 STATE。
pub fn parse_sc_state(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim_start().starts_with("STATE"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.to_ascii_lowercase())
}

pub async fn scope_status(t: &Target, runner: &dyn CmdRunner) -> ScopeStatus {
    let mut st = ScopeStatus {
        scope: t.scope,
        manager: t.manager(),
        installed: false,
        state: None,
        unit: t.unit_path(),
    };
    let q = |p: &str, a: &[&str]| CmdSpec::new(p, a).timeout(15_000);
    match t.manager() {
        Manager::WindowsService => {
            if let Ok(o) = runner.run(&q("sc.exe", &["query", SERVICE_NAME])).await {
                if o.ok() {
                    st.installed = true;
                    st.state = parse_sc_state(&o.stdout);
                }
            }
        }
        Manager::WindowsRun => {
            if let Ok(o) = runner
                .run(&q("reg.exe", &["query", WIN_RUN_KEY, "/v", SERVICE_NAME]))
                .await
            {
                st.installed = o.ok();
            }
        }
        Manager::Systemd | Manager::SystemdUser => {
            st.installed = st.unit.as_ref().is_some_and(|p| p.exists());
            let mut a = vec!["is-active", "asa.service"];
            if t.manager() == Manager::SystemdUser {
                a.insert(0, "--user");
            }
            if st.installed {
                if let Ok(o) = runner.run(&q("systemctl", &a)).await {
                    st.state = Some(o.stdout.trim().to_string()).filter(|s| !s.is_empty());
                }
            }
        }
        Manager::XdgAutostart => {
            st.installed = st.unit.as_ref().is_some_and(|p| p.exists());
        }
        Manager::LaunchDaemon | Manager::LaunchAgent => {
            st.installed = st.unit.as_ref().is_some_and(|p| p.exists());
            let domain = if t.manager() == Manager::LaunchDaemon {
                "system".to_string()
            } else {
                format!("gui/{}", t.uid)
            };
            if st.installed {
                if let Ok(o) = runner
                    .run(&q("launchctl", &["print", &format!("{domain}/{LABEL}")]))
                    .await
                {
                    st.state = o
                        .stdout
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("state = ").map(str::to_string));
                }
            }
        }
    }
    st
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// 依目前環境組出安裝目標。
pub async fn current_target(
    scope: Scope,
    user_config_dir: &Path,
    interval: Option<String>,
    runner: &dyn CmdRunner,
) -> AppResult<Target> {
    let os = Os::current();
    let exe = std::env::current_exe().map_err(|e| AppError::External(e.to_string()))?;
    let exe = dunce_like(&exe);
    let home = dirs::home_dir().unwrap_or_default();
    let systemd_user = os == Os::Linux
        && scope == Scope::User
        && runner
            .run(&CmdSpec::new("systemctl", &["--user", "show-environment"]).timeout(10_000))
            .await
            .map(|o| o.ok())
            .unwrap_or(false);
    let config_dir = match scope {
        Scope::System => system_config_dir(os),
        Scope::User => user_config_dir.to_path_buf(),
    };
    let mut t = Target {
        os,
        scope,
        exe,
        config_dir,
        source_config_dir: user_config_dir.to_path_buf(),
        home,
        uid: current_uid(),
        systemd_user,
        interval,
        existing: false,
        secrets_file: std::env::var(crate::secrets::ENV_BACKEND)
            .map(|v| v.eq_ignore_ascii_case("file"))
            .unwrap_or(false),
        default_config_dir: dirs::config_dir()
            .map(|d| d.join(crate::config::APP_DIR_NAME))
            .is_some_and(|d| d == user_config_dir),
    };
    t.existing = scope_status(&t, runner).await.installed;
    Ok(t)
}

/// Windows 的 current_exe 可能帶 `\\?\` 前綴；服務命令列不需要。
fn dunce_like(p: &Path) -> PathBuf {
    let s = p.display().to_string();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::{CmdOutput, FakeRunner};

    fn target(os: Os, scope: Scope) -> Target {
        let (exe, cfg, home) = match os {
            Os::Windows => (
                r"C:\Tools\asa.exe",
                r"C:\Users\me\AppData\Roaming\ai-security-agent",
                r"C:\Users\me",
            ),
            _ => ("/usr/local/bin/asa", "/home/me/.config/ai-security-agent", "/home/me"),
        };
        let config_dir = match scope {
            Scope::System => system_config_dir(os),
            Scope::User => PathBuf::from(cfg),
        };
        Target {
            os,
            scope,
            exe: PathBuf::from(exe),
            config_dir,
            source_config_dir: PathBuf::from(cfg),
            home: PathBuf::from(home),
            uid: 501,
            systemd_user: true,
            interval: Some("15m".into()),
            existing: false,
            secrets_file: false,
            default_config_dir: false,
        }
    }

    fn describe(p: &Plan) -> Vec<String> {
        p.steps.iter().map(|s| s.describe()).collect()
    }

    #[test]
    fn windows_plans() {
        let sys = plan_install(&target(Os::Windows, Scope::System));
        assert_eq!(sys.manager, Manager::WindowsService);
        assert!(matches!(&sys.steps[0], Step::CopyEnrollment { .. }));
        let Step::Run { program, args, .. } = &sys.steps[1] else {
            panic!()
        };
        assert_eq!(program, "sc.exe");
        assert_eq!(&args[..3], &["create", "asa", "binPath="]);
        assert!(args[3].starts_with(r#""C:\Tools\asa.exe" --config-dir "#));
        assert!(args[3].ends_with("--secrets-backend file service run --interval 15m"));
        assert!(describe(&sys).last().unwrap().ends_with("sc.exe start asa"));
        let mut existing = target(Os::Windows, Scope::System);
        existing.existing = true;
        assert!(describe(&plan_install(&existing))[2].contains("sc.exe config asa binPath="));

        let user = plan_install(&target(Os::Windows, Scope::User));
        assert_eq!(user.manager, Manager::WindowsRun);
        let d = describe(&user);
        assert!(d[0].starts_with(r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v asa /t REG_SZ /d"));
        assert!(d[0].contains("watch --service --interval 15m"));
        assert!(!d[0].contains("--secrets-backend"));
        assert!(matches!(user.steps.last(), Some(Step::Spawn { .. })));
        let mut short = target(Os::Windows, Scope::User);
        short.default_config_dir = true;
        assert!(!describe(&plan_install(&short))[0].contains("--config-dir"));
        let un = plan_uninstall(&target(Os::Windows, Scope::User));
        assert!(describe(&un)[0].starts_with("reg.exe delete"));
        assert!(matches!(un.steps[1], Step::StopWatchers { .. }));
    }

    #[test]
    fn linux_and_macos_plans() {
        let sys = plan_install(&target(Os::Linux, Scope::System));
        let Step::WriteFile { path, contents, mode } = &sys.steps[1] else {
            panic!()
        };
        assert_eq!(path, &PathBuf::from("/etc/systemd/system/asa.service"));
        assert_eq!(*mode, Some(0o644));
        assert!(contents.contains("ExecStart=/usr/local/bin/asa --config-dir /var/lib/asa --secrets-backend file watch --service --interval 15m"));
        assert_eq!(
            describe(&sys)[2..],
            [
                "systemctl daemon-reload",
                "systemctl enable asa.service",
                "systemctl restart asa.service"
            ]
        );

        let user = plan_install(&target(Os::Linux, Scope::User));
        assert_eq!(user.manager, Manager::SystemdUser);
        assert!(
            matches!(&user.steps[0], Step::WriteFile { path, .. } if path.ends_with(".config/systemd/user/asa.service"))
        );
        assert_eq!(user.notes.len(), 1);
        let mut xdg = target(Os::Linux, Scope::User);
        xdg.systemd_user = false;
        let p = plan_install(&xdg);
        assert_eq!(p.manager, Manager::XdgAutostart);
        assert!(matches!(p.steps.last(), Some(Step::Spawn { .. })));

        let mac = plan_install(&target(Os::Macos, Scope::User));
        assert_eq!(mac.manager, Manager::LaunchAgent);
        let d = describe(&mac);
        assert_eq!(d[1], "launchctl bootout gui/501/dev.asa.agent");
        // 在 Windows 上跑測試時 join 會用反斜線，只比對頭尾
        assert!(
            d[2].starts_with("launchctl bootstrap gui/501 /home/me") && d[2].ends_with("dev.asa.agent.plist"),
            "{}",
            d[2]
        );
        let msys = plan_install(&target(Os::Macos, Scope::System));
        assert!(describe(&msys)
            .iter()
            .any(|s| s == "launchctl bootstrap system /Library/LaunchDaemons/dev.asa.agent.plist"));
        let un = plan_uninstall(&target(Os::Linux, Scope::System));
        assert_eq!(describe(&un)[0], "systemctl disable --now asa.service");
    }

    #[test]
    fn status_parsing() {
        let sc = "SERVICE_NAME: asa\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n";
        assert_eq!(parse_sc_state(sc).as_deref(), Some("running"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let runner = FakeRunner::new()
            .on("sc.exe query asa", CmdOutput::success(sc))
            .on("reg.exe query", CmdOutput::failure(1, "not found"));
        let s = rt.block_on(scope_status(&target(Os::Windows, Scope::System), &runner));
        assert!(s.installed);
        assert_eq!(s.state.as_deref(), Some("running"));
        let u = rt.block_on(scope_status(&target(Os::Windows, Scope::User), &runner));
        assert!(!u.installed);
    }

    #[test]
    fn apply_writes_files_and_runs_commands() {
        let d = tempfile::tempdir().unwrap();
        let unit = d.path().join("sub/asa.service");
        let plan = Plan {
            scope: Scope::User,
            manager: Manager::SystemdUser,
            steps: vec![
                Step::WriteFile {
                    path: unit.clone(),
                    contents: "x".into(),
                    mode: Some(0o644),
                },
                run_ok("systemctl", &["--user", "daemon-reload"]),
                run("systemctl", &["--user", "enable", "asa.service"]),
                Step::RemoveFile {
                    path: d.path().join("missing"),
                },
            ],
            notes: vec![],
        };
        let runner = FakeRunner::new()
            .on("systemctl --user enable", CmdOutput::success(""))
            .on("daemon-reload", CmdOutput::failure(1, "no bus"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(apply(&plan, &runner)).unwrap();
        assert_eq!(std::fs::read_to_string(&unit).unwrap(), "x");
        assert_eq!(out.len(), 2, "{out:?}");
        let bad = Plan {
            steps: vec![run("systemctl", &["start", "x"])],
            ..plan
        };
        assert!(rt.block_on(apply(&bad, &FakeRunner::new())).is_err());
    }

    #[test]
    fn enrollment_copy_uses_file_secrets() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let store = crate::secrets::SecretStore::with_backend(src.path(), crate::secrets::Backend::File);
        assert!(!copy_enrollment_from(src.path(), dst.path(), &store).unwrap());
        let cfg = crate::config::load_or_init(src.path()).unwrap();
        store.set(crate::secrets::KEY_HUB_CLIENT, "k1").unwrap();
        assert!(copy_enrollment_from(src.path(), dst.path(), &store).unwrap());
        let copied = crate::config::load_or_init(dst.path()).unwrap();
        assert_eq!(copied.agent_id, cfg.agent_id);
        let v = crate::secrets::SecretStore::with_backend(dst.path(), crate::secrets::Backend::File)
            .get(crate::secrets::KEY_HUB_CLIENT)
            .unwrap();
        assert_eq!(v.as_deref(), Some("k1"));
    }
}
