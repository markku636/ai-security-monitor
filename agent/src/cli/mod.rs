//! CLI 入口：解析語言 → 本地化 clap help → 分派 → 錯誤輸出與 exit code。
//!
//! exit code：0 成功；1 錯誤；2 `NeedsConfirm`（預演，未執行）。

pub mod args;
pub mod dispatch;
pub mod guard;
pub mod render;

pub mod ai_cmd;
pub mod allowlist_cmd;
pub mod baseline_cmd;
pub mod config_cmd;
pub mod connections_cmd;
pub mod doctor_cmd;
pub mod events_cmd;
pub mod fw_cmd;
pub mod harden_cmd;
pub mod hub_cmd;
pub mod intel_cmd;
pub mod mcp_cmd;
pub mod metrics_cmd;
pub mod ports_cmd;
pub mod scan_cmd;
pub mod service_cmd;
pub mod traffic_cmd;
pub mod update_cmd;
pub mod version_cmd;
pub mod vuln_cmd;

use clap::{CommandFactory, FromArgMatches};

use crate::error::AppError;
use crate::i18n::{self, Lang};

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERR: i32 = 1;
pub const EXIT_NEEDS_CONFIRM: i32 = 2;

/// 共用的執行環境（設定目錄等）。
pub struct Env {
    pub global: args::GlobalArgs,
    pub config_dir: std::path::PathBuf,
}

pub async fn run() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    // clap 的 env = "AI_SECURITY_MONITOR_…" 只認新名：只設了舊名 ASA_* 時先複製過去
    crate::util::env::seed_from_legacy(args::CLAP_ENV);
    let lang = resolve_lang(&argv);
    i18n::set_lang(lang);
    if launch_mode(argv.len() <= 1, console_owned_by_this_process()) == LaunchMode::DoubleClicked {
        // 在檔案總管雙擊命令列版：只印 help 主控台會一閃而過，改成說明＋等 Enter
        print_double_click_help();
        wait_for_enter();
        return EXIT_OK;
    }

    let cmd = localize_command(args::Cli::command());
    let matches = match cmd.try_get_matches_from(&argv) {
        Ok(m) => m,
        Err(e) => {
            // clap 自己處理 --help / --version（exit 0）與參數錯誤（exit 2）。
            let _ = e.print();
            return if e.use_stderr() { EXIT_NEEDS_CONFIRM } else { EXIT_OK };
        }
    };
    let cli = match args::Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return EXIT_ERR;
        }
    };
    let json = cli.global.json;
    if let Some(b) = &cli.global.secrets_backend {
        // 服務的命令列帶 --secrets-backend file（LocalSystem／root 沒有使用者的 keychain）
        std::env::set_var(crate::secrets::ENV_BACKEND, b);
    }
    match dispatch::dispatch(cli).await {
        Ok(()) => EXIT_OK,
        Err(e) => {
            report_error(&e, json);
            if matches!(e, AppError::NeedsConfirm(_)) {
                EXIT_NEEDS_CONFIRM
            } else {
                EXIT_ERR
            }
        }
    }
}

/// 啟動方式：在檔案總管雙擊（沒有參數、主控台是這個行程自己開的）或一般命令列。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchMode {
    Normal,
    DoubleClicked,
}

/// 沒帶任何參數、而且主控台只有這個行程（不是從終端機執行）→ 當成雙擊開啟。
pub fn launch_mode(no_args: bool, console_owned: bool) -> LaunchMode {
    if no_args && console_owned {
        LaunchMode::DoubleClicked
    } else {
        LaunchMode::Normal
    }
}

/// Windows：主控台的行程清單只有自己（檔案總管雙擊時系統替這個行程新開了主控台）。其他平台一律 false。
fn console_owned_by_this_process() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::GetConsoleProcessList;
        let mut pids = [0u32; 4];
        GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub const RELEASES_URL: &str = "https://github.com/markku636/ai-security-monitor/releases/latest";

#[cfg(test)]
const DOUBLE_CLICK_STRINGS: &[&str] = &[
    "AI Security Monitor {v}（命令列版）",
    "這個檔案是命令列工具，要在終端機（PowerShell 或命令提示字元）裡執行；直接雙擊只會看到這段說明。",
    "想要視窗介面：請下載桌面版安裝檔",
    "一行安裝命令列版（在 PowerShell 貼上執行，會加入 PATH）：",
    "常用命令：",
    "檢查環境與權限",
    "完整掃描一次",
    "目前的連線，比對威脅情資",
    "所有命令",
    "按 Enter 關閉…",
];

/// 雙擊命令列版時的說明：這是什麼、視窗版在哪、怎麼安裝、常用命令。
pub fn double_click_help() -> String {
    let v = crate::VERSION;
    [
        tf!("AI Security Monitor {v}（命令列版）", v = v),
        String::new(),
        t!("這個檔案是命令列工具，要在終端機（PowerShell 或命令提示字元）裡執行；直接雙擊只會看到這段說明。")
            .to_string(),
        String::new(),
        t!("想要視窗介面：請下載桌面版安裝檔").to_string(),
        format!("  AI-Security-Monitor-{v}-windows-x64-setup.exe"),
        format!("  {RELEASES_URL}"),
        String::new(),
        t!("一行安裝命令列版（在 PowerShell 貼上執行，會加入 PATH）：").to_string(),
        "  irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex".to_string(),
        String::new(),
        t!("常用命令：").to_string(),
        format!("  ai-security-monitor doctor               {}", t!("檢查環境與權限")),
        format!("  ai-security-monitor scan                 {}", t!("完整掃描一次")),
        format!(
            "  ai-security-monitor connections --intel  {}",
            t!("目前的連線，比對威脅情資")
        ),
        format!("  ai-security-monitor --help               {}", t!("所有命令")),
        String::new(),
    ]
    .join("\n")
}

fn print_double_click_help() {
    println!("{}", double_click_help());
}

fn wait_for_enter() {
    use std::io::Write;
    print!("{}", t!("按 Enter 關閉…"));
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

fn report_error(e: &AppError, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string(&serde_json::json!({ "error": e })) {
            eprintln!("{s}");
            return;
        }
    }
    eprintln!("{}", e.message());
}

/// 語言：`--lang` ＞ `AI_SECURITY_MONITOR_LANG`（舊名 `ASA_LANG`）＞ config.json 的 `lang` ＞ zh-TW。
fn resolve_lang(argv: &[String]) -> Lang {
    let mut i = 0;
    let mut config_dir: Option<std::path::PathBuf> = None;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(v) = a.strip_prefix("--lang=") {
            if let Some(l) = Lang::from_code(v) {
                return l;
            }
        } else if a == "--lang" {
            if let Some(l) = argv.get(i + 1).and_then(|v| Lang::from_code(v)) {
                return l;
            }
        } else if let Some(v) = a.strip_prefix("--config-dir=") {
            config_dir = Some(v.into());
        } else if a == "--config-dir" {
            config_dir = argv.get(i + 1).map(|v| v.into());
        }
        i += 1;
    }
    if let Some(v) = crate::util::env::var("LANG") {
        if let Some(l) = Lang::from_code(&v) {
            return l;
        }
    }
    if let Ok(dir) = crate::config::config_dir(config_dir.as_deref()) {
        if let Ok(cfg) = crate::config::load(&dir) {
            if let Some(l) = cfg.lang.as_deref().and_then(Lang::from_code) {
                return l;
            }
        }
    }
    Lang::ZhTw
}

fn tr_help(zh: &str) -> Option<&'static str> {
    i18n::lookup_opt(zh)
}

/// 遞迴把 clap 的 about / 參數說明換成當前語言。
pub fn localize_command(mut cmd: clap::Command) -> clap::Command {
    if let Some(about) = cmd.get_about().map(|s| s.to_string()) {
        if let Some(en) = tr_help(&about) {
            cmd = cmd.about(en.to_string());
        }
    }
    let arg_ids: Vec<String> = cmd.get_arguments().map(|a| a.get_id().as_str().to_string()).collect();
    for id in arg_ids {
        cmd = cmd.mut_arg(id, |a| match a.get_help().map(|s| s.to_string()) {
            Some(h) => match tr_help(&h) {
                Some(en) => a.help(en.to_string()),
                None => a,
            },
            None => a,
        });
    }
    let sub_names: Vec<String> = cmd.get_subcommands().map(|s| s.get_name().to_string()).collect();
    for name in sub_names {
        cmd = cmd.mut_subcommand(name, localize_command);
    }
    cmd
}

#[cfg(test)]
mod help_tests {
    use super::*;

    #[test]
    fn double_click_pauses_only_without_args_on_own_console() {
        assert_eq!(launch_mode(true, true), LaunchMode::DoubleClicked);
        // 有參數（例如從捷徑帶參數）或從終端機執行（主控台是共用的）：照舊
        assert_eq!(launch_mode(false, true), LaunchMode::Normal);
        assert_eq!(launch_mode(true, false), LaunchMode::Normal);
        assert_eq!(launch_mode(false, false), LaunchMode::Normal);
    }

    #[test]
    fn double_click_help_points_to_the_gui_and_the_installer() {
        let h = double_click_help();
        assert!(
            h.contains(&format!("AI-Security-Monitor-{}-windows-x64-setup.exe", crate::VERSION)),
            "{h}"
        );
        assert!(h.contains(RELEASES_URL) && h.contains("install.ps1 | iex"), "{h}");
        assert!(h.contains("connections --intel") && h.contains("doctor"), "{h}");
        // 不切全域語言（別的測試同時在跑）：直接查英文對照表
        for zh in DOUBLE_CLICK_STRINGS {
            assert!(crate::locales::en::lookup(zh).is_some(), "no English for {zh}");
        }
    }

    fn collect(cmd: &clap::Command, out: &mut Vec<String>) {
        if let Some(a) = cmd.get_about() {
            out.push(a.to_string());
        }
        for a in cmd.get_arguments() {
            if a.is_hide_set() {
                continue;
            }
            if let Some(h) = a.get_help() {
                out.push(h.to_string());
            }
            // ValueEnum 變體的 doc comment 會變成可選值說明，localize_command 換不到：一律不准是中文
            for pv in a.get_possible_values() {
                if let Some(h) = pv.get_help() {
                    out.push(format!("possible value of --{}: {h}", a.get_id()));
                }
            }
        }
        for s in cmd.get_subcommands() {
            collect(s, out);
        }
    }

    /// 每一段繁中 help 都必須有英文譯文，否則 `--lang en` 會漏出中文。
    #[test]
    fn every_help_string_has_english() {
        let mut all = Vec::new();
        collect(&args::Cli::command(), &mut all);
        let missing: Vec<&String> = all
            .iter()
            .filter(|s| !s.is_ascii())
            .filter(|s| crate::locales::en::lookup(s).is_none())
            .collect();
        assert!(missing.is_empty(), "missing en translations: {missing:#?}");
    }

    #[test]
    fn resolve_lang_prefers_flag() {
        assert_eq!(
            resolve_lang(&["ai-security-monitor".into(), "--lang".into(), "en".into()]),
            Lang::En
        );
        assert_eq!(
            resolve_lang(&["ai-security-monitor".into(), "--lang=zh-TW".into()]),
            Lang::ZhTw
        );
    }
}
