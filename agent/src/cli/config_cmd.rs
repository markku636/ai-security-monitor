use super::args::ConfigCmd;
use super::render::print_json;
use super::Env;
use crate::config;
use crate::error::AppResult;

pub fn run(env: &Env, cmd: ConfigCmd) -> AppResult<()> {
    match cmd {
        ConfigCmd::Show => {
            let cfg = config::load_or_init(&env.config_dir)?;
            if env.global.json {
                print_json(&cfg);
            } else {
                println!("{}", tf!("設定目錄：{dir}", dir = env.config_dir.display()));
                println!("{}", serde_json::to_string_pretty(&cfg)?);
            }
            Ok(())
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg = config::load_or_init(&env.config_dir)?;
            config::set_value(&mut cfg, &key, &value)?;
            config::save(&env.config_dir, &cfg)?;
            if env.global.json {
                print_json(&serde_json::json!({ "ok": true, "key": key, "value": value }));
            } else {
                println!("{}", tf!("已設定 {key} = {value}", key = key, value = value));
            }
            Ok(())
        }
        ConfigCmd::Path => {
            if env.global.json {
                print_json(&serde_json::json!({ "config_dir": env.config_dir }));
            } else {
                println!("{}", env.config_dir.display());
            }
            Ok(())
        }
    }
}
