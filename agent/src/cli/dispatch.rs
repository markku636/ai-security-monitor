//! 子命令分派。每個 handler 吃 `&Env` 與自己的參數，回 `AppResult<()>`。

use super::args::{Cli, Command};
use super::Env;
use crate::config;
use crate::error::AppResult;

pub async fn dispatch(cli: Cli) -> AppResult<()> {
    let config_dir = config::config_dir(cli.global.config_dir.as_deref())?;
    // 舊版常駐 watch 還在用舊目錄：這次沿用舊目錄，提示一行（service 命令自己處理遷移、常駐行程不印）
    let daemon = matches!(&cli.cmd, Command::Watch(a) if a.service) || matches!(&cli.cmd, Command::Service { .. });
    if let Some(d) = config::deferred_migration().filter(|d| d.busy && d.legacy == config_dir) {
        if !daemon && !cli.global.quiet {
            eprintln!(
                "{}",
                tf!(
                    "· 舊版 asa 的常駐 watch 還在使用 {legacy}，這次先沿用它；執行 ai-security-monitor service install --yes 換掉舊服務時會搬到 {new}",
                    legacy = d.legacy.display(),
                    new = d.new.display()
                )
            );
        }
    }
    let env = Env {
        global: cli.global.clone(),
        config_dir,
    };
    match cli.cmd {
        Command::Version { check } => super::version_cmd::run(&env, check).await,
        Command::Doctor => super::doctor_cmd::run(&env).await,
        Command::SelfUpdate { check, to, no_restart } => super::update_cmd::run(&env, check, to, !no_restart).await,
        Command::Scan(a) => super::scan_cmd::run(&env, a).await,
        Command::Connections(a) => super::connections_cmd::run(&env, a).await,
        Command::Intel { cmd } => super::intel_cmd::run(&env, cmd).await,
        Command::Fw { cmd } => super::fw_cmd::run(&env, cmd).await,
        Command::Enroll(a) => super::hub_cmd::enroll_cmd(&env, a).await,
        Command::Discover(a) => super::hub_cmd::discover(&env, a).await,
        Command::Hub { cmd } => super::hub_cmd::hub(&env, cmd).await,
        Command::Unenroll => super::hub_cmd::unenroll(&env).await,
        Command::Status => super::hub_cmd::status(&env).await,
        Command::Watch(a) => super::hub_cmd::watch(&env, a).await,
        Command::Upload => super::upload_cmd::run(&env).await,
        Command::Service { cmd } => super::service_cmd::run(&env, cmd).await,
        Command::Ports(a) => super::ports_cmd::run(&env, a).await,
        Command::Traffic(a) => super::traffic_cmd::run(&env, a).await,
        Command::Metrics(a) => super::metrics_cmd::run(&env, a).await,
        Command::Events(a) => super::events_cmd::run(&env, a).await,
        Command::Vuln(a) => super::vuln_cmd::run(&env, a).await,
        Command::Harden(a) => super::harden_cmd::run(&env, a).await,
        Command::Mcp(a) => super::mcp_cmd::run(&env, a).await,
        Command::Ai { cmd } => super::ai_cmd::run(&env, cmd).await,
        Command::Config { cmd } => super::config_cmd::run(&env, cmd),
        Command::Allowlist { cmd } => super::allowlist_cmd::run(&env, cmd),
        Command::Baseline { cmd } => super::baseline_cmd::run(&env, cmd).await,
    }
}
