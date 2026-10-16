//! `asa self-update [--check] [--to VER]`、`asa version --check`。

use super::guard::ensure_confirmed;
use super::render::print_json;
use super::Env;
use crate::error::{AppError, AppResult};
use crate::update::{self, UpdateOutcome};

fn current_exe() -> AppResult<std::path::PathBuf> {
    let p = std::env::current_exe().map_err(|e| AppError::Update(e.to_string()))?;
    let s = p.display().to_string();
    Ok(std::path::PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s)))
}

pub async fn run(env: &Env, check: bool, to: Option<String>) -> AppResult<()> {
    let exe = current_exe()?;
    update::cleanup_old(&exe);
    let rel = update::fetch_release(&update::base_url(), to.as_deref()).await?;
    let c = update::check_release(&rel, crate::VERSION);
    if check {
        if env.global.json {
            print_json(&c);
        } else if c.newer {
            println!(
                "{}",
                tf!(
                    "有新版：{latest}（目前 {current}）→ asa self-update --yes；說明：{url}",
                    latest = c.latest,
                    current = c.current,
                    url = c.release_url
                )
            );
        } else {
            println!("{}", tf!("已是最新版（{current}）", current = c.current));
        }
        return Ok(());
    }
    if !c.newer && to.is_none() {
        println!("{}", tf!("已是最新版（{current}）", current = c.current));
        return Ok(());
    }
    let asset = c.asset.clone().ok_or_else(|| {
        AppError::Update(tf!(
            "Release {tag} 沒有這個平台（{os}/{arch}）的執行檔",
            tag = rel.tag,
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH
        ))
    })?;
    if !env.global.yes {
        println!(
            "{}",
            tf!(
                "將下載 {name}（{size}）並比對 SHA256SUMS，取代 {exe}",
                name = asset.name,
                size = crate::util::text::fmt_bytes(asset.size),
                exe = exe.display()
            )
        );
        return ensure_confirmed(false, false, false, &tf!("更新到 {v}", v = rel.version));
    }
    let (bytes, sha256) = update::download_verified(&rel, &asset).await?;
    let old_file = update::replace_exe(&exe, &bytes)?;
    let out = UpdateOutcome {
        from: crate::VERSION.to_string(),
        to: rel.version.clone(),
        exe: exe.clone(),
        sha256,
        old_file,
    };
    if env.global.json {
        print_json(&out);
    } else {
        println!(
            "{}",
            tf!(
                "已更新 {from} → {to}（SHA256 {sha}）",
                from = out.from,
                to = out.to,
                sha = &out.sha256[..16]
            )
        );
    }
    if !crate::service::running_watchers(None).is_empty() {
        eprintln!(
            "{}",
            t!("常駐中的 asa watch 還是舊版：執行 asa service restart --yes（系統服務加 --system）換成新版")
        );
    }
    Ok(())
}
