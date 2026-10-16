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
    let lang = resolve_lang(&argv);
    i18n::set_lang(lang);

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

fn report_error(e: &AppError, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string(&serde_json::json!({ "error": e })) {
            eprintln!("{s}");
            return;
        }
    }
    eprintln!("{}", e.message());
}

/// 語言：`--lang` ＞ `ASA_LANG` ＞ config.json 的 `lang` ＞ zh-TW。
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
    if let Ok(v) = std::env::var("ASA_LANG") {
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
        assert_eq!(resolve_lang(&["asa".into(), "--lang".into(), "en".into()]), Lang::En);
        assert_eq!(resolve_lang(&["asa".into(), "--lang=zh-TW".into()]), Lang::ZhTw);
    }
}
