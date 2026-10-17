use super::render::print_json;
use super::Env;
use crate::error::AppResult;

pub async fn run(env: &Env, check: bool) -> AppResult<()> {
    if env.global.json {
        print_json(&serde_json::json!({
            "version": crate::VERSION,
            "git_sha": crate::GIT_SHA,
            "build_unix": crate::BUILD_UNIX.parse::<u64>().unwrap_or(0),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        }));
    } else {
        println!(
            "ai-security-monitor {} ({}) {}/{}",
            crate::VERSION,
            crate::GIT_SHA,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }
    if check {
        return super::update_cmd::run(env, true, None).await;
    }
    Ok(())
}
