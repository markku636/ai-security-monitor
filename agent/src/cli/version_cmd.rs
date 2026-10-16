use super::render::print_json;
use super::Env;
use crate::error::{AppError, AppResult};

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
            "asa {} ({}) {}/{}",
            crate::VERSION,
            crate::GIT_SHA,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }
    if check {
        // 第 17 輪（self-update）接上 GitHub Release 查詢。
        return Err(AppError::Unsupported(
            t!("版本檢查將隨 self-update 功能一起提供").into(),
        ));
    }
    Ok(())
}
