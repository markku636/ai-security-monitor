//! 子命令分派。每個 handler 吃 `&Env` 與自己的參數，回 `AppResult<()>`。

use super::args::{Cli, Command};
use super::Env;
use crate::config;
use crate::error::AppResult;

pub async fn dispatch(cli: Cli) -> AppResult<()> {
    let config_dir = config::config_dir(cli.global.config_dir.as_deref())?;
    let env = Env {
        global: cli.global.clone(),
        config_dir,
    };
    match cli.cmd {
        Command::Version { check } => super::version_cmd::run(&env, check).await,
        Command::Doctor => super::doctor_cmd::run(&env).await,
        Command::Scan(a) => super::scan_cmd::run(&env, a).await,
        Command::Connections(a) => super::connections_cmd::run(&env, a).await,
        Command::Intel { cmd } => super::intel_cmd::run(&env, cmd).await,
        Command::Fw { cmd } => super::fw_cmd::run(&env, cmd).await,
        Command::Enroll {
            url,
            key,
            accept_remote_actions,
            insecure_http,
        } => super::hub_cmd::enroll(&env, &url, &key, accept_remote_actions, insecure_http).await,
        Command::Unenroll => super::hub_cmd::unenroll(&env).await,
        Command::Status => super::hub_cmd::status(&env).await,
        Command::Watch(a) => super::hub_cmd::watch(&env, a).await,
        Command::Ports(a) => super::ports_cmd::run(&env, a).await,
        Command::Config { cmd } => super::config_cmd::run(&env, cmd),
        Command::Allowlist { cmd } => super::allowlist_cmd::run(&env, cmd),
        Command::Baseline { cmd } => super::baseline_cmd::run(&env, cmd).await,
    }
}
