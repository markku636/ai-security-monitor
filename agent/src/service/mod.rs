//! 開機自動啟動：
//! - `--system`（伺服器，需系統管理員／root）：Windows 服務（SCM）、systemd、launchd LaunchDaemon；
//! - `--user`（個人電腦，免管理員）：HKCU\…\Run、systemd --user（沒有就 XDG autostart）、launchd LaunchAgent。
//!
//! 安裝／移除都先產生「計畫」（純函數，可預覽與測試），`--yes` 後才執行。
//!
//! 改名相容：0.1.x 以 `asa` 為名安裝的服務（Windows 服務／Run 值 `asa`、`asa.service`、`asa.desktop`、
//! `dev.asa.agent`）在 status 會被認出來；install 先移除它再裝新的，uninstall／restart 也會處理它。
//! 系統層設定目錄（`%ProgramData%\ai-security-agent`、`/var/lib/asa`…）在 install 時搬到新位置。

pub mod elevated;
pub mod instance;
pub mod units;
#[cfg(windows)]
pub mod winsvc;

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::util::cmd::{CmdRunner, CmdSpec};
use units::{Names, DISPLAY_NAME, LEGACY_NAMES, NAMES};

/// 常駐行程的執行檔名（不分大小寫）：新名、從 0.1.x 原地更新上來仍叫 `asa` 的，
/// 以及桌面版執行檔（桌面版「背景自動回報」登記的是桌面版本身 `… watch --service`）。
pub const PROCESS_NAMES: &[&str] = &[
    "ai-security-monitor",
    "ai-security-monitor.exe",
    "asa",
    "asa.exe",
    "ai-security-monitor-desktop",
    "ai-security-monitor-desktop.exe",
];
const LEGACY_PROCESS_NAMES: &[&str] = &["asa", "asa.exe"];

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
    /// 這個範圍裝著改名前的 `asa` 服務（install 會先移除）。
    pub legacy: bool,
    /// system 安裝：改名前的系統設定目錄還在、新目錄還沒有 → 安裝時搬過去。
    pub legacy_config_dir: Option<PathBuf>,
    /// user 安裝：這次沿用了改名前的使用者設定目錄（舊版常駐 watch 還在用）→ 停掉舊版後搬到 `config_dir`。
    pub migrate_user_dir: Option<PathBuf>,
    /// 使用者層要強制檔案密鑰庫（安裝時有設 AI_SECURITY_MONITOR_SECRETS_BACKEND=file）。
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
        self.unit_path_for(&NAMES)
    }

    /// 指定名稱（新版或改名前）的設定檔位置。
    pub fn unit_path_for(&self, n: &Names) -> Option<PathBuf> {
        Some(match self.manager() {
            Manager::Systemd => PathBuf::from(format!("/etc/systemd/system/{}", n.systemd_unit)),
            Manager::SystemdUser => self.home.join(format!(".config/systemd/user/{}", n.systemd_unit)),
            Manager::XdgAutostart => self.home.join(format!(".config/autostart/{}", n.desktop_file)),
            Manager::LaunchDaemon => PathBuf::from(format!("/Library/LaunchDaemons/{}.plist", n.label)),
            Manager::LaunchAgent => self.home.join(format!("Library/LaunchAgents/{}.plist", n.label)),
            Manager::WindowsService | Manager::WindowsRun => return None,
        })
    }

    fn launchd_domain(&self) -> String {
        if self.manager() == Manager::LaunchDaemon {
            "system".to_string()
        } else {
            format!("gui/{}", self.uid)
        }
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

fn program_data() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
}

/// 系統層的設定目錄。
pub fn system_config_dir(os: Os) -> PathBuf {
    match os {
        Os::Windows => program_data().join(crate::config::APP_DIR_NAME),
        // 字串組合而非 join：在 Windows 上跑測試時路徑分隔符號也要是 /
        Os::Macos => PathBuf::from(format!("/Library/Application Support/{}", crate::config::APP_DIR_NAME)),
        Os::Linux => PathBuf::from(format!("/var/lib/{}", crate::config::APP_DIR_NAME)),
    }
}

/// 改名前（0.1.x）的系統層設定目錄。
pub fn legacy_system_config_dir(os: Os) -> PathBuf {
    match os {
        Os::Windows => program_data().join(crate::config::LEGACY_APP_DIR_NAME),
        Os::Macos => PathBuf::from(format!(
            "/Library/Application Support/{}",
            crate::config::LEGACY_APP_DIR_NAME
        )),
        Os::Linux => PathBuf::from("/var/lib/asa"),
    }
}

/// 實際在用的系統設定目錄：新目錄還不存在、舊目錄存在（舊版系統服務還在用）時回舊目錄。
pub fn effective_system_config_dir(os: Os) -> PathBuf {
    let new = system_config_dir(os);
    let legacy = legacy_system_config_dir(os);
    if !new.exists() && legacy.is_dir() {
        legacy
    } else {
        new
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
    /// 結束改名前的 `asa` 常駐 watch（任何設定目錄；使用者層舊安裝用）。
    StopLegacyWatchers,
    /// 改名前的設定目錄搬到新位置（新目錄已存在就略過）。
    MigrateDir {
        from: PathBuf,
        to: PathBuf,
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
                tf!(
                    "結束使用 {dir} 的常駐 ai-security-monitor watch",
                    dir = config_dir.display()
                )
            }
            Step::StopLegacyWatchers => t!("結束舊版（asa）的常駐 watch").to_string(),
            Step::MigrateDir { from, to } => {
                tf!(
                    "搬移舊版設定目錄 {from} → {to}",
                    from = from.display(),
                    to = to.display()
                )
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

/// 移除改名前（`asa`）的安裝：服務停掉並刪除、設定檔刪掉、常駐行程結束。
fn legacy_removal_steps(t: &Target) -> Vec<Step> {
    let n = &LEGACY_NAMES;
    let mut steps = Vec::new();
    match t.manager() {
        Manager::WindowsService => {
            steps.push(run_ok("sc.exe", &["stop", n.service]));
            steps.push(win_wait_stopped(n.service));
            steps.push(run("sc.exe", &["delete", n.service]));
        }
        Manager::WindowsRun => {
            steps.push(run_ok("reg.exe", &["delete", WIN_RUN_KEY, "/v", n.service, "/f"]));
            steps.push(Step::StopLegacyWatchers);
        }
        Manager::Systemd => {
            steps.push(run_ok("systemctl", &["disable", "--now", n.systemd_unit]));
            steps.push(Step::RemoveFile {
                path: t.unit_path_for(n).unwrap(),
            });
        }
        Manager::SystemdUser => {
            steps.push(run_ok("systemctl", &["--user", "disable", "--now", n.systemd_unit]));
            steps.push(Step::RemoveFile {
                path: t.unit_path_for(n).unwrap(),
            });
        }
        Manager::XdgAutostart => {
            steps.push(Step::RemoveFile {
                path: t.unit_path_for(n).unwrap(),
            });
            steps.push(Step::StopLegacyWatchers);
        }
        Manager::LaunchDaemon | Manager::LaunchAgent => {
            steps.push(run_ok(
                "launchctl",
                &["bootout", &format!("{}/{}", t.launchd_domain(), n.label)],
            ));
            steps.push(Step::RemoveFile {
                path: t.unit_path_for(n).unwrap(),
            });
        }
    }
    steps
}

pub fn plan_install(t: &Target) -> Plan {
    let exe = t.exe.display().to_string();
    let args = t.run_args();
    let n = &NAMES;
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    if t.legacy {
        // 先拆掉改名前的 asa 服務，免得新舊兩個常駐行程同時跑
        steps.extend(legacy_removal_steps(t));
        notes.push(t!("已移除舊版（asa）的開機自動啟動；之後只用 ai-security-monitor").to_string());
    }
    if t.scope == Scope::User {
        if let Some(from) = &t.migrate_user_dir {
            // 舊版常駐 watch 還開著舊目錄：先結束它，再把舊目錄搬到新位置（服務改用新目錄）
            if !steps.iter().any(|s| matches!(s, Step::StopLegacyWatchers)) {
                steps.push(Step::StopLegacyWatchers);
            }
            steps.push(Step::MigrateDir {
                from: from.clone(),
                to: t.config_dir.clone(),
            });
        }
    }
    if t.scope == Scope::System {
        if let Some(from) = &t.legacy_config_dir {
            steps.push(Step::MigrateDir {
                from: from.clone(),
                to: t.config_dir.clone(),
            });
        }
    }
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
                steps.push(run_ok("sc.exe", &["stop", n.service]));
                steps.push(win_wait_stopped(n.service));
                steps.push(run(
                    "sc.exe",
                    &["config", n.service, "binPath=", &bin, "start=", "auto"],
                ));
            } else {
                steps.push(run(
                    "sc.exe",
                    &[
                        "create",
                        n.service,
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
                    n.service,
                    "AI Security Monitor: connection, threat-intel and system security monitoring",
                ],
            ));
            steps.push(run_ok(
                "sc.exe",
                &[
                    "failure",
                    n.service,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/60000/restart/60000/restart/300000",
                ],
            ));
            steps.push(run("sc.exe", &["start", n.service]));
        }
        Manager::WindowsRun => {
            let cmd = units::windows_cmdline(&t.exe, &args);
            if cmd.chars().count() > 260 {
                notes.push(tf!(
                    "命令列 {n} 字元，超過 Windows「執行」機碼的 260 字元上限，登入時可能不會啟動；請把 ai-security-monitor 放到較短的路徑",
                    n = cmd.chars().count()
                ));
            }
            steps.push(run(
                "reg.exe",
                &["add", WIN_RUN_KEY, "/v", n.service, "/t", "REG_SZ", "/d", &cmd, "/f"],
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
            steps.push(run("systemctl", &["enable", n.systemd_unit]));
            steps.push(run("systemctl", &["restart", n.systemd_unit]));
        }
        Manager::SystemdUser => {
            let unit = t.unit_path().unwrap();
            steps.push(Step::WriteFile {
                path: unit,
                contents: units::systemd_unit(&t.exe, &args, false, &t.config_dir),
                mode: Some(0o644),
            });
            steps.push(run("systemctl", &["--user", "daemon-reload"]));
            steps.push(run("systemctl", &["--user", "enable", n.systemd_unit]));
            steps.push(run("systemctl", &["--user", "restart", n.systemd_unit]));
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
            let domain = t.launchd_domain();
            steps.push(Step::WriteFile {
                path: plist.clone(),
                contents: units::launchd_plist(&t.exe, &args, &log_dir, system),
                mode: Some(0o644),
            });
            steps.push(run_ok("launchctl", &["bootout", &format!("{domain}/{}", n.label)]));
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

/// 等 Windows 服務真的停下來（sc stop 是非同步的；還在跑時 sc delete 只會標記待刪）。
fn win_wait_stopped(service: &str) -> Step {
    Step::Run {
        program: "powershell.exe".into(),
        args: vec![
            "-NoProfile".into(),
            "-Command".into(),
            format!(
                "$s = Get-Service '{service}' -ErrorAction SilentlyContinue; if ($s) {{ $s.WaitForStatus('Stopped', '00:00:45') }}"
            ),
        ],
        ignore_failure: true,
    }
}

pub fn plan_uninstall(t: &Target) -> Plan {
    let n = &NAMES;
    let mut steps = Vec::new();
    // 只有舊版 asa 時不去碰（不存在的）新服務，否則 sc delete 會失敗
    let current = t.existing || !t.legacy;
    if current {
        match t.manager() {
            Manager::WindowsService => {
                steps.push(run_ok("sc.exe", &["stop", n.service]));
                steps.push(win_wait_stopped(n.service));
                steps.push(run("sc.exe", &["delete", n.service]));
            }
            Manager::WindowsRun => {
                steps.push(run_ok("reg.exe", &["delete", WIN_RUN_KEY, "/v", n.service, "/f"]));
                steps.push(Step::StopWatchers {
                    config_dir: t.config_dir.clone(),
                });
            }
            Manager::Systemd => {
                steps.push(run_ok("systemctl", &["disable", "--now", n.systemd_unit]));
                steps.push(Step::RemoveFile {
                    path: t.unit_path().unwrap(),
                });
            }
            Manager::SystemdUser => {
                steps.push(run_ok("systemctl", &["--user", "disable", "--now", n.systemd_unit]));
                steps.push(Step::RemoveFile {
                    path: t.unit_path().unwrap(),
                });
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
                steps.push(run_ok(
                    "launchctl",
                    &["bootout", &format!("{}/{}", t.launchd_domain(), n.label)],
                ));
                steps.push(Step::RemoveFile {
                    path: t.unit_path().unwrap(),
                });
            }
        }
    }
    if t.legacy {
        steps.extend(legacy_removal_steps(t));
    }
    match t.manager() {
        Manager::Systemd => steps.push(run_ok("systemctl", &["daemon-reload"])),
        Manager::SystemdUser => steps.push(run_ok("systemctl", &["--user", "daemon-reload"])),
        _ => {}
    }
    Plan {
        scope: t.scope,
        manager: t.manager(),
        steps,
        notes: Vec::new(),
    }
}

/// 重新啟動（更新 ai-security-monitor 之後讓常駐行程換成新版）。
/// 只裝著改名前的 asa 服務時重新啟動那一個（建議之後改用 `service install` 換成新名）。
pub fn plan_restart(t: &Target) -> Plan {
    let args = t.run_args();
    let legacy_only = !t.existing && t.legacy;
    let n = if legacy_only { &LEGACY_NAMES } else { &NAMES };
    let steps = match t.manager() {
        Manager::WindowsService => vec![
            run_ok("sc.exe", &["stop", n.service]),
            win_wait_stopped(n.service),
            run("sc.exe", &["start", n.service]),
        ],
        Manager::Systemd => vec![run("systemctl", &["restart", n.systemd_unit])],
        Manager::SystemdUser => vec![run("systemctl", &["--user", "restart", n.systemd_unit])],
        Manager::LaunchDaemon | Manager::LaunchAgent => vec![run(
            "launchctl",
            &["kickstart", "-k", &format!("{}/{}", t.launchd_domain(), n.label)],
        )],
        Manager::WindowsRun | Manager::XdgAutostart => {
            let mut v = vec![Step::StopWatchers {
                config_dir: t.config_dir.clone(),
            }];
            if legacy_only {
                v.push(Step::StopLegacyWatchers);
            }
            v.push(Step::Spawn {
                program: t.exe.display().to_string(),
                args,
            });
            v
        }
    };
    let mut notes = Vec::new();
    if legacy_only {
        notes.push(t!("這是舊版（asa）的開機自動啟動；執行 ai-security-monitor service install 換成新名").to_string());
    }
    Plan {
        scope: t.scope,
        manager: t.manager(),
        steps,
        notes,
    }
}

/// 常駐中的 ai-security-monitor watch（任何安裝方式；以命令列判斷）。
#[derive(Debug, Clone, Serialize)]
pub struct Watcher {
    pub pid: u32,
    pub cmd: String,
    /// 執行檔路徑（讀得到才有）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<PathBuf>,
}

pub fn running_watchers(config_dir: Option<&Path>) -> Vec<Watcher> {
    watchers_named(config_dir, PROCESS_NAMES)
}

/// 執行檔名是不是常駐行程（新名或舊名 asa，不分大小寫）。
pub fn is_process_name(name: &str, names: &[&str]) -> bool {
    let name = name.to_ascii_lowercase();
    // Linux comm 截成 15 字元（"ai-security-mon"）
    names
        .iter()
        .any(|n| *n == name || (name.len() == 15 && n.len() > 15 && n.starts_with(&name)))
}

fn watchers_named(config_dir: Option<&Path>, names: &[&str]) -> Vec<Watcher> {
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
            // Linux 的行程名（/proc/<pid>/comm）只有 15 字元，ai-security-monitor 會被截斷：
            // 也看執行檔路徑與 argv[0] 的檔名
            let exe_name = p
                .exe()
                .and_then(|e| e.file_name())
                .map(|f| f.to_string_lossy().to_string());
            let argv0 = args
                .first()
                .and_then(|a| Path::new(a).file_name().map(|f| f.to_string_lossy().to_string()));
            let is_ours = std::iter::once(p.name().to_string_lossy().to_string())
                .chain(exe_name)
                .chain(argv0)
                .any(|n| is_process_name(&n, names));
            let daemon = (args.iter().any(|a| a == "watch") && args.iter().any(|a| a == "--service"))
                || (args.iter().any(|a| a == "service") && args.iter().any(|a| a == "run"));
            let same_dir = dir.as_ref().is_none_or(|d| {
                args.iter().any(|a| a == d) || (is_default && !args.iter().any(|a| a == "--config-dir"))
            });
            (is_ours && daemon && same_dir && pid.as_u32() != me).then(|| Watcher {
                pid: pid.as_u32(),
                cmd: args.join(" "),
                exe: p.exe().map(dunce_like),
            })
        })
        .collect()
}

fn stop_watchers(config_dir: &Path) -> usize {
    kill_watchers(running_watchers(Some(config_dir)))
}

/// 有改名前（asa）的常駐 watch 在跑。
pub fn legacy_watcher_running() -> bool {
    !watchers_named(None, LEGACY_PROCESS_NAMES).is_empty()
}

fn stop_legacy_watchers() -> usize {
    kill_watchers(watchers_named(None, LEGACY_PROCESS_NAMES))
}

fn kill_watchers(list: Vec<Watcher>) -> usize {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut n = 0;
    for w in list {
        if let Some(p) = sys.process(sysinfo::Pid::from_u32(w.pid)) {
            if p.kill() {
                n += 1;
            }
        }
    }
    n
}

/// 在背景啟動（不跟著目前的主控台／行程群組）；回傳 PID。
pub fn spawn_detached(program: &str, args: &[String]) -> std::io::Result<u32> {
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
                    out.push(tf!("✓ 已結束 {n} 個常駐 ai-security-monitor watch", n = n));
                }
            }
            Step::StopLegacyWatchers => {
                let n = stop_legacy_watchers();
                if n > 0 {
                    out.push(tf!("✓ 已結束 {n} 個舊版（asa）常駐 watch", n = n));
                }
            }
            Step::MigrateDir { from, to } => {
                match crate::config::migrate_after_stop(to, from, std::time::Duration::from_secs(15))? {
                    crate::config::Migration::NotNeeded => {}
                    _ => out.push(format!("✓ {}", s.describe())),
                }
            }
            Step::CopyEnrollment { from, to } => {
                if copy_enrollment(from, to)? {
                    out.push(format!("✓ {}", s.describe()));
                } else {
                    out.push(t!("· 目前使用者還沒註冊 hub：服務先只在本機掃描（之後以系統管理員執行 ai-security-monitor --config-dir <系統目錄> enroll …）").to_string());
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
    /// 新名（ai-security-monitor）的安裝。
    pub installed: bool,
    /// 改名前（asa）的安裝還在（`service install` 會換掉它）。
    pub legacy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<PathBuf>,
}

/// `sc.exe query <服務名>` 的 STATE。
pub fn parse_sc_state(text: &str) -> Option<String> {
    text.lines()
        .find(|l| l.trim_start().starts_with("STATE"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| s.to_ascii_lowercase())
}

/// 某組名稱的安裝狀態：(已安裝, 狀態)。
async fn probe(t: &Target, n: &Names, runner: &dyn CmdRunner) -> (bool, Option<String>) {
    let q = |p: &str, a: &[&str]| CmdSpec::new(p, a).timeout(15_000);
    let unit = t.unit_path_for(n);
    let unit_exists = unit.as_ref().is_some_and(|p| p.exists());
    match t.manager() {
        Manager::WindowsService => match runner.run(&q("sc.exe", &["query", n.service])).await {
            Ok(o) if o.ok() => (true, parse_sc_state(&o.stdout)),
            _ => (false, None),
        },
        Manager::WindowsRun => {
            let installed = runner
                .run(&q("reg.exe", &["query", WIN_RUN_KEY, "/v", n.service]))
                .await
                .map(|o| o.ok())
                .unwrap_or(false);
            (installed, None)
        }
        Manager::Systemd | Manager::SystemdUser => {
            if !unit_exists {
                return (false, None);
            }
            let mut a = vec!["is-active", n.systemd_unit];
            if t.manager() == Manager::SystemdUser {
                a.insert(0, "--user");
            }
            let state = match runner.run(&q("systemctl", &a)).await {
                Ok(o) => Some(o.stdout.trim().to_string()).filter(|s| !s.is_empty()),
                Err(_) => None,
            };
            (true, state)
        }
        Manager::XdgAutostart => (unit_exists, None),
        Manager::LaunchDaemon | Manager::LaunchAgent => {
            if !unit_exists {
                return (false, None);
            }
            let target = format!("{}/{}", t.launchd_domain(), n.label);
            let state = match runner.run(&q("launchctl", &["print", &target])).await {
                Ok(o) => o
                    .stdout
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("state = ").map(str::to_string)),
                Err(_) => None,
            };
            (true, state)
        }
    }
}

pub async fn scope_status(t: &Target, runner: &dyn CmdRunner) -> ScopeStatus {
    let (installed, state) = probe(t, &NAMES, runner).await;
    let (legacy, legacy_state) = probe(t, &LEGACY_NAMES, runner).await;
    // 只有舊版時顯示舊版的狀態與設定檔
    let (state, unit) = if !installed && legacy {
        (legacy_state, t.unit_path_for(&LEGACY_NAMES))
    } else {
        (state, t.unit_path())
    };
    ScopeStatus {
        scope: t.scope,
        manager: t.manager(),
        installed,
        legacy,
        state,
        unit,
    }
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
    let exe = stable_exe(&exe, std::env::var_os("APPIMAGE").map(PathBuf::from));
    let home = dirs::home_dir().unwrap_or_default();
    let systemd_user = os == Os::Linux
        && scope == Scope::User
        && runner
            .run(&CmdSpec::new("systemctl", &["--user", "show-environment"]).timeout(10_000))
            .await
            .map(|o| o.ok())
            .unwrap_or(false);
    // 使用者層：這次沿用了舊目錄（舊版常駐 watch 還在用）→ 服務改用新目錄，安裝時搬過去
    let deferred = crate::config::deferred_migration().filter(|d| d.legacy == user_config_dir);
    let user_dir = deferred
        .as_ref()
        .map(|d| d.new.clone())
        .unwrap_or_else(|| user_config_dir.to_path_buf());
    let config_dir = match scope {
        Scope::System => system_config_dir(os),
        Scope::User => user_dir.clone(),
    };
    let legacy_config_dir = match scope {
        Scope::System => Some(legacy_system_config_dir(os)).filter(|l| l.is_dir() && !config_dir.exists()),
        Scope::User => None,
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
        legacy: false,
        legacy_config_dir,
        migrate_user_dir: deferred.filter(|_| scope == Scope::User).map(|d| d.legacy),
        secrets_file: crate::secrets::backend_env()
            .map(|v| v.eq_ignore_ascii_case("file"))
            .unwrap_or(false),
        default_config_dir: dirs::config_dir()
            .map(|d| d.join(crate::config::APP_DIR_NAME))
            .is_some_and(|d| d == user_dir),
    };
    let st = scope_status(&t, runner).await;
    t.existing = st.installed;
    t.legacy = st.legacy;
    Ok(t)
}

/// Windows 的 current_exe 可能帶 `\\?\` 前綴；服務命令列不需要。
fn dunce_like(p: &Path) -> PathBuf {
    let s = p.display().to_string();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

/// 開機啟動要用的執行檔路徑：Linux AppImage 執行時 current_exe 是每次都不同的暫時掛載點（/tmp/.mount_…），
/// 改用 `APPIMAGE`（AppImage 檔本身的位置）；其他情況就是安裝位置本身（桌面版的安裝路徑在更新後不變）。
pub fn stable_exe(current: &Path, appimage: Option<PathBuf>) -> PathBuf {
    match appimage.filter(|p| p.is_absolute() && p.is_file()) {
        Some(p) => p,
        None => dunce_like(current),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::{CmdOutput, FakeRunner};

    #[test]
    fn stable_exe_prefers_the_appimage_file() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("AI-Security-Monitor.AppImage");
        std::fs::write(&img, b"x").unwrap();
        let mounted = Path::new("/tmp/.mount_AIabc/usr/bin/ai-security-monitor-desktop");
        assert_eq!(stable_exe(mounted, Some(img.clone())), img);
        // APPIMAGE 指到不存在的檔案、或是相對路徑：照用目前的執行檔
        assert_eq!(
            stable_exe(mounted, Some(dir.path().join("gone"))),
            mounted.to_path_buf()
        );
        assert_eq!(
            stable_exe(mounted, Some(PathBuf::from("rel.AppImage"))),
            mounted.to_path_buf()
        );
        assert_eq!(
            stable_exe(Path::new(r"\\?\C:\Apps\x.exe"), None),
            PathBuf::from(r"C:\Apps\x.exe")
        );
    }

    pub(super) fn target(os: Os, scope: Scope) -> Target {
        let (exe, cfg, home) = match os {
            Os::Windows => (
                r"C:\Tools\ai-security-monitor.exe",
                r"C:\Users\me\AppData\Roaming\ai-security-monitor",
                r"C:\Users\me",
            ),
            _ => (
                "/usr/local/bin/ai-security-monitor",
                "/home/me/.config/ai-security-monitor",
                "/home/me",
            ),
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
            legacy: false,
            legacy_config_dir: None,
            migrate_user_dir: None,
            secrets_file: false,
            default_config_dir: false,
        }
    }

    fn legacy(os: Os, scope: Scope) -> Target {
        Target {
            legacy: true,
            ..target(os, scope)
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
        assert_eq!(&args[..3], &["create", "ai-security-monitor", "binPath="]);
        assert!(args[3].starts_with(r#""C:\Tools\ai-security-monitor.exe" --config-dir "#));
        assert!(args[3].ends_with("--secrets-backend file service run --interval 15m"));
        assert_eq!(&args[6..], &["DisplayName=", "AI Security Monitor"]);
        assert!(describe(&sys)
            .last()
            .unwrap()
            .ends_with("sc.exe start ai-security-monitor"));
        let mut existing = target(Os::Windows, Scope::System);
        existing.existing = true;
        assert!(describe(&plan_install(&existing))[3].contains("sc.exe config ai-security-monitor binPath="));

        let user = plan_install(&target(Os::Windows, Scope::User));
        assert_eq!(user.manager, Manager::WindowsRun);
        let d = describe(&user);
        assert!(d[0].starts_with(
            r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v ai-security-monitor /t REG_SZ /d"
        ));
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
        assert_eq!(path, &PathBuf::from("/etc/systemd/system/ai-security-monitor.service"));
        assert_eq!(*mode, Some(0o644));
        assert!(contents.contains("ExecStart=/usr/local/bin/ai-security-monitor --config-dir /var/lib/ai-security-monitor --secrets-backend file watch --service --interval 15m"));
        assert_eq!(
            describe(&sys)[2..],
            [
                "systemctl daemon-reload",
                "systemctl enable ai-security-monitor.service",
                "systemctl restart ai-security-monitor.service"
            ]
        );

        let user = plan_install(&target(Os::Linux, Scope::User));
        assert_eq!(user.manager, Manager::SystemdUser);
        assert!(
            matches!(&user.steps[0], Step::WriteFile { path, .. } if path.ends_with(".config/systemd/user/ai-security-monitor.service"))
        );
        assert_eq!(user.notes.len(), 1);
        let mut xdg = target(Os::Linux, Scope::User);
        xdg.systemd_user = false;
        let p = plan_install(&xdg);
        assert_eq!(p.manager, Manager::XdgAutostart);
        assert!(
            matches!(&p.steps[0], Step::WriteFile { path, .. } if path.ends_with(".config/autostart/ai-security-monitor.desktop"))
        );
        assert!(matches!(p.steps.last(), Some(Step::Spawn { .. })));

        let mac = plan_install(&target(Os::Macos, Scope::User));
        assert_eq!(mac.manager, Manager::LaunchAgent);
        let d = describe(&mac);
        assert_eq!(d[1], "launchctl bootout gui/501/dev.ai-security-monitor.agent");
        // 在 Windows 上跑測試時 join 會用反斜線，只比對頭尾
        assert!(
            d[2].starts_with("launchctl bootstrap gui/501 /home/me")
                && d[2].ends_with("dev.ai-security-monitor.agent.plist"),
            "{}",
            d[2]
        );
        let msys = plan_install(&target(Os::Macos, Scope::System));
        assert!(describe(&msys)
            .iter()
            .any(|s| s == "launchctl bootstrap system /Library/LaunchDaemons/dev.ai-security-monitor.agent.plist"));
        assert_eq!(
            describe(&plan_restart(&target(Os::Linux, Scope::System))),
            ["systemctl restart ai-security-monitor.service"]
        );
        assert_eq!(
            describe(&plan_restart(&target(Os::Macos, Scope::User))),
            ["launchctl kickstart -k gui/501/dev.ai-security-monitor.agent"]
        );
        assert!(matches!(
            plan_restart(&target(Os::Windows, Scope::User)).steps[1],
            Step::Spawn { .. }
        ));
        let un = plan_uninstall(&target(Os::Linux, Scope::System));
        assert_eq!(describe(&un)[0], "systemctl disable --now ai-security-monitor.service");
        assert_eq!(describe(&un).last().unwrap(), "systemctl daemon-reload");
    }

    #[test]
    fn system_dirs_and_process_names() {
        assert_eq!(
            system_config_dir(Os::Linux),
            PathBuf::from("/var/lib/ai-security-monitor")
        );
        assert_eq!(legacy_system_config_dir(Os::Linux), PathBuf::from("/var/lib/asa"));
        assert_eq!(
            system_config_dir(Os::Macos),
            PathBuf::from("/Library/Application Support/ai-security-monitor")
        );
        assert_eq!(
            legacy_system_config_dir(Os::Macos),
            PathBuf::from("/Library/Application Support/ai-security-agent")
        );
        assert!(system_config_dir(Os::Windows).ends_with("ai-security-monitor"));
        assert!(legacy_system_config_dir(Os::Windows).ends_with("ai-security-agent"));
        for n in ["ai-security-monitor", "AI-SECURITY-MONITOR.EXE", "asa", "Asa.exe"] {
            assert!(is_process_name(n, PROCESS_NAMES), "{n}");
        }
        assert!(!is_process_name("asa-desktop.exe", PROCESS_NAMES));
        // 桌面版執行檔帶 watch --service 跑的也是常駐行程（只看名字；命令列另外要有 watch --service）
        assert!(is_process_name("ai-security-monitor-desktop.exe", PROCESS_NAMES));
        assert!(!is_process_name(
            "ai-security-monitor-desktop.exe",
            LEGACY_PROCESS_NAMES
        ));
        // Linux /proc/<pid>/comm 只有 15 字元
        assert!(is_process_name("ai-security-mon", PROCESS_NAMES));
        assert!(!is_process_name("ai-security-mo", PROCESS_NAMES));
        assert!(!is_process_name("ai-security-monitor.exe", LEGACY_PROCESS_NAMES));
    }

    #[test]
    fn user_install_migrates_the_deferred_legacy_user_dir() {
        // 這次沿用了舊目錄（舊版常駐 watch 還在用）：先停舊版、再搬到新目錄，服務用新目錄
        let mut t = legacy(Os::Windows, Scope::User);
        t.migrate_user_dir = Some(PathBuf::from(r"C:\Users\me\AppData\Roaming\ai-security-agent"));
        t.default_config_dir = true;
        let p = plan_install(&t);
        let stop = p
            .steps
            .iter()
            .position(|s| matches!(s, Step::StopLegacyWatchers))
            .unwrap();
        let mig = p
            .steps
            .iter()
            .position(|s| matches!(s, Step::MigrateDir { from, to } if Some(from) == t.migrate_user_dir.as_ref() && to == &t.config_dir))
            .unwrap();
        assert!(stop < mig);
        assert_eq!(
            p.steps.iter().filter(|s| matches!(s, Step::StopLegacyWatchers)).count(),
            1,
            "no duplicate stop step"
        );
        // 新的 Run 值在搬完之後才寫，命令列不帶 --config-dir（預設的新目錄）
        let run = p
            .steps
            .iter()
            .position(|s| matches!(s, Step::Run { args, .. } if args.first().is_some_and(|a| a == "add")))
            .unwrap();
        assert!(mig < run);
        assert!(!t.run_args().iter().any(|a| a == "--config-dir"));
        // 沒有舊的開機自動啟動（例如手動跑的 asa watch --service）也先結束舊行程
        let mut l = target(Os::Linux, Scope::User);
        l.migrate_user_dir = Some(PathBuf::from("/home/me/.config/ai-security-agent"));
        let p = plan_install(&l);
        assert!(matches!(p.steps[0], Step::StopLegacyWatchers));
        assert!(matches!(&p.steps[1], Step::MigrateDir { to, .. } if to == &l.config_dir));
        // 系統服務不搬使用者目錄
        let mut s = target(Os::Linux, Scope::System);
        s.migrate_user_dir = Some(PathBuf::from("/home/me/.config/ai-security-agent"));
        assert!(!plan_install(&s)
            .steps
            .iter()
            .any(|x| matches!(x, Step::MigrateDir { .. })));
    }

    #[test]
    fn install_replaces_legacy_asa_installs() {
        // Windows 服務：先停掉並刪除 asa 服務，再建立新服務
        let d = describe(&plan_install(&legacy(Os::Windows, Scope::System)));
        assert_eq!(d[0], "sc.exe stop asa");
        assert!(d[1].contains("Get-Service 'asa'"));
        assert_eq!(d[2], "sc.exe delete asa");
        assert!(d.iter().any(|s| s.starts_with("sc.exe create ai-security-monitor ")));
        // HKCU Run：刪掉舊的 asa 值、結束舊行程，再寫新值
        let p = plan_install(&legacy(Os::Windows, Scope::User));
        let d = describe(&p);
        assert_eq!(
            d[0],
            r"reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v asa /f"
        );
        assert!(matches!(p.steps[1], Step::StopLegacyWatchers));
        assert!(d[2].contains("/v ai-security-monitor "));
        assert!(!p.notes.is_empty());
        // systemd：停用並刪掉 asa.service
        let p = plan_install(&legacy(Os::Linux, Scope::System));
        let d = describe(&p);
        assert_eq!(d[0], "systemctl disable --now asa.service");
        assert!(
            matches!(&p.steps[1], Step::RemoveFile { path } if path == &PathBuf::from("/etc/systemd/system/asa.service"))
        );
        assert!(d.contains(&"systemctl enable ai-security-monitor.service".to_string()));
        let p = plan_install(&legacy(Os::Linux, Scope::User));
        assert_eq!(describe(&p)[0], "systemctl --user disable --now asa.service");
        let mut xdg = legacy(Os::Linux, Scope::User);
        xdg.systemd_user = false;
        let p = plan_install(&xdg);
        assert!(matches!(&p.steps[0], Step::RemoveFile { path } if path.ends_with(".config/autostart/asa.desktop")));
        assert!(matches!(p.steps[1], Step::StopLegacyWatchers));
        // launchd
        let d = describe(&plan_install(&legacy(Os::Macos, Scope::System)));
        assert_eq!(d[0], "launchctl bootout system/dev.asa.agent");
        assert!(d[1].ends_with("dev.asa.agent.plist"));
        let d = describe(&plan_install(&legacy(Os::Macos, Scope::User)));
        assert_eq!(d[0], "launchctl bootout gui/501/dev.asa.agent");
        // 沒有舊安裝：計畫裡沒有任何 asa 項目
        for (os, sc) in [
            (Os::Windows, Scope::System),
            (Os::Windows, Scope::User),
            (Os::Linux, Scope::System),
            (Os::Macos, Scope::User),
        ] {
            let p = plan_install(&target(os, sc));
            assert!(!p.steps.iter().any(|s| matches!(s, Step::StopLegacyWatchers)));
            assert!(
                !describe(&p)
                    .iter()
                    .any(|s| s.contains(" asa") || s.contains("dev.asa.")),
                "{:?}",
                describe(&p)
            );
        }
    }

    #[test]
    fn system_install_migrates_the_legacy_system_dir() {
        let mut t = target(Os::Linux, Scope::System);
        t.legacy_config_dir = Some(legacy_system_config_dir(Os::Linux));
        let p = plan_install(&t);
        assert!(matches!(&p.steps[0], Step::MigrateDir { from, to }
            if from == &PathBuf::from("/var/lib/asa") && to == &PathBuf::from("/var/lib/ai-security-monitor")));
        assert!(matches!(&p.steps[1], Step::CopyEnrollment { .. }));
        // 使用者層不搬系統目錄
        let mut u = target(Os::Linux, Scope::User);
        u.legacy_config_dir = Some(PathBuf::from("/var/lib/asa"));
        assert!(!plan_install(&u)
            .steps
            .iter()
            .any(|s| matches!(s, Step::MigrateDir { .. })));
        // 實際執行：搬到新目錄、保留 agent_id
        let base = tempfile::tempdir().unwrap();
        let from = base.path().join("asa");
        let to = base.path().join("ai-security-monitor");
        let cfg = crate::config::load_or_init(&from).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let plan = Plan {
            scope: Scope::System,
            manager: Manager::Systemd,
            steps: vec![Step::MigrateDir {
                from: from.clone(),
                to: to.clone(),
            }],
            notes: vec![],
        };
        let out = rt.block_on(apply(&plan, &FakeRunner::new())).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(crate::config::load(&to).unwrap().agent_id, cfg.agent_id);
        // 第二次：新目錄已存在，什麼都不做
        assert!(rt.block_on(apply(&plan, &FakeRunner::new())).unwrap().is_empty());
    }

    #[test]
    fn uninstall_and_restart_handle_legacy_only_installs() {
        // 只有舊版：不碰新服務（sc delete 會失敗），只移除 asa
        let d = describe(&plan_uninstall(&legacy(Os::Windows, Scope::System)));
        assert_eq!(d.len(), 3);
        assert_eq!((d[0].as_str(), d[2].as_str()), ("sc.exe stop asa", "sc.exe delete asa"));
        // 新舊都有：兩個都移除
        let mut both = legacy(Os::Windows, Scope::User);
        both.existing = true;
        let d = describe(&plan_uninstall(&both));
        assert!(d[0].contains("/v ai-security-monitor /f"));
        assert!(d.iter().any(|s| s.contains("/v asa /f")));
        let d = describe(&plan_uninstall(&legacy(Os::Linux, Scope::System)));
        assert_eq!(d[0], "systemctl disable --now asa.service");
        assert_eq!(d.last().unwrap(), "systemctl daemon-reload");
        // restart：只有舊版就重啟舊版並提示改裝新名
        let r = plan_restart(&legacy(Os::Linux, Scope::System));
        assert_eq!(describe(&r), ["systemctl restart asa.service"]);
        assert_eq!(r.notes.len(), 1);
        assert_eq!(
            describe(&plan_restart(&legacy(Os::Windows, Scope::System)))[0],
            "sc.exe stop asa"
        );
        let r = plan_restart(&legacy(Os::Windows, Scope::User));
        assert!(r.steps.iter().any(|s| matches!(s, Step::StopLegacyWatchers)));
        assert!(matches!(r.steps.last(), Some(Step::Spawn { .. })));
        let mut both = legacy(Os::Macos, Scope::User);
        both.existing = true;
        assert_eq!(
            describe(&plan_restart(&both)),
            ["launchctl kickstart -k gui/501/dev.ai-security-monitor.agent"]
        );
    }

    #[test]
    fn status_parsing() {
        let sc = "SERVICE_NAME: ai-security-monitor\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n";
        assert_eq!(parse_sc_state(sc).as_deref(), Some("running"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let runner = FakeRunner::new()
            .on("sc.exe query ai-security-monitor", CmdOutput::success(sc))
            .on("reg.exe query", CmdOutput::failure(1, "not found"));
        let s = rt.block_on(scope_status(&target(Os::Windows, Scope::System), &runner));
        assert!(s.installed && !s.legacy);
        assert_eq!(s.state.as_deref(), Some("running"));
        let u = rt.block_on(scope_status(&target(Os::Windows, Scope::User), &runner));
        assert!(!u.installed && !u.legacy);

        // 只裝著舊版 asa：installed=false、legacy=true、狀態取舊服務的
        let old = "SERVICE_NAME: asa\n        STATE              : 1  STOPPED\n";
        let runner = FakeRunner::new()
            .on("sc.exe query asa", CmdOutput::success(old))
            .on(
                "reg.exe query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v asa",
                CmdOutput::success("asa REG_SZ x"),
            )
            .on("reg.exe query", CmdOutput::failure(1, "not found"))
            .on("sc.exe query", CmdOutput::failure(1060, "does not exist"));
        let s = rt.block_on(scope_status(&target(Os::Windows, Scope::System), &runner));
        assert!(!s.installed && s.legacy);
        assert_eq!(s.state.as_deref(), Some("stopped"));
        let u = rt.block_on(scope_status(&target(Os::Windows, Scope::User), &runner));
        assert!(!u.installed && u.legacy);

        // systemd：以 unit 檔是否存在判斷
        let home = tempfile::tempdir().unwrap();
        let mut t = target(Os::Linux, Scope::User);
        t.home = home.path().to_path_buf();
        let legacy_unit = t.unit_path_for(&LEGACY_NAMES).unwrap();
        std::fs::create_dir_all(legacy_unit.parent().unwrap()).unwrap();
        std::fs::write(&legacy_unit, "[Unit]\n").unwrap();
        let runner = FakeRunner::new().on("is-active asa.service", CmdOutput::success("active\n"));
        let s = rt.block_on(scope_status(&t, &runner));
        assert!(!s.installed && s.legacy);
        assert_eq!(s.state.as_deref(), Some("active"));
        assert_eq!(s.unit.as_deref(), Some(legacy_unit.as_path()));
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
