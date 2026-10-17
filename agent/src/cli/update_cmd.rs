//! `ai-security-monitor self-update [--check] [--to VER] [--no-restart]`、`ai-security-monitor version --check`。
//!
//! 手動更新和背景自動更新（`update.mode = auto`）走同一條路：查 Release → 下載 → 比對 SHA256SUMS → 原地替換，
//! 然後重新啟動正在用這個執行檔的背景服務。桌面版內建的 agent 不在這裡更新（交給桌面版的更新器）。

use std::path::Path;

use super::guard::ensure_confirmed;
use super::render::print_json;
use super::Env;
use crate::error::{AppError, AppResult};
use crate::service::{self, Scope};
use crate::update::auto::{InstallKind, Installed, UpdateState};
use crate::update::{self, UpdateOutcome};
use crate::util::cmd::RealRunner;

fn current_exe() -> AppResult<std::path::PathBuf> {
    crate::update::auto::current_exe().ok_or_else(|| AppError::Update("current_exe".into()))
}

/// 這個執行檔能不能在這裡自我更新；`force` 可以略過開發版／套件管理員的保護（桌面版不行）。
pub fn ensure_can_self_update(kind: &InstallKind, force: bool) -> AppResult<()> {
    match kind {
        InstallKind::Standalone => Ok(()),
        InstallKind::Desktop => Err(AppError::Update(
            t!("這是桌面版內建的 ai-security-monitor：請在桌面版「設定 → 檢查更新」更新（背景自動回報會跟著一起更新）")
                .into(),
        )),
        _ if force => Ok(()),
        other => Err(AppError::Update(tf!(
            "{why}（確定要直接替換執行檔請加 --force）",
            why = other.reason().unwrap_or_default()
        ))),
    }
}

pub async fn run(env: &Env, check: bool, to: Option<String>, restart: bool) -> AppResult<()> {
    let exe = current_exe()?;
    let kind = crate::update::auto::install_kind();
    if kind.can_self_update() {
        update::cleanup_old(&exe);
    }
    let rel = update::fetch_release(&update::base_url(), to.as_deref()).await?;
    let c = update::check_release(&rel, crate::VERSION);
    if to.is_none() {
        let mut st = UpdateState::load(&env.config_dir);
        st.record_check(chrono::Utc::now(), &c.latest, &c.release_url);
        st.save(&env.config_dir);
    }
    if check {
        if env.global.json {
            print_json(&serde_json::json!({
                "current": c.current,
                "latest": c.latest,
                "newer": c.newer,
                "asset": c.asset,
                "release_url": c.release_url,
                "install": kind,
                "can_self_update": kind.can_self_update(),
            }));
        } else if c.newer {
            println!(
                "{}",
                match kind.reason() {
                    None => tf!(
                        "有新版：{latest}（目前 {current}）→ ai-security-monitor self-update --yes；說明：{url}",
                        latest = c.latest,
                        current = c.current,
                        url = c.release_url
                    ),
                    Some(why) => tf!(
                        "有新版：{latest}（目前 {current}）；{why}；說明：{url}",
                        latest = c.latest,
                        current = c.current,
                        why = why,
                        url = c.release_url
                    ),
                }
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
    ensure_can_self_update(&kind, env.global.force)?;
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
    let mut st = UpdateState::load(&env.config_dir);
    st.installed = Some(Installed {
        from: crate::VERSION.to_string(),
        to: rel.version.clone(),
        at: chrono::Utc::now(),
        how: "manual".into(),
    });
    st.note = None;
    st.error = None;
    st.save(&env.config_dir);
    let out = UpdateOutcome {
        from: crate::VERSION.to_string(),
        to: rel.version.clone(),
        exe: exe.clone(),
        sha256,
        old_file,
    };
    let restarted = if restart {
        restart_services_using(env, &exe).await
    } else {
        Restarted::default()
    };
    if env.global.json {
        let mut v = serde_json::to_value(&out)?;
        v["restarted"] = serde_json::json!(restarted.lines);
        v["restart_hint"] = serde_json::json!(restarted.hint);
        print_json(&v);
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
        for l in &restarted.lines {
            println!("{l}");
        }
        if let Some(h) = &restarted.hint {
            eprintln!("{h}");
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct Restarted {
    lines: Vec<String>,
    hint: Option<String>,
}

/// 用這個執行檔在跑的常駐 watch：換成新版（使用者層直接重新啟動；系統服務要系統管理員）。
async fn restart_services_using(env: &Env, exe: &Path) -> Restarted {
    let me = exe.display().to_string().to_ascii_lowercase();
    let mine: Vec<String> = service::running_watchers(None)
        .into_iter()
        .map(|w| w.cmd.to_ascii_lowercase())
        .filter(|c| c.contains(&me))
        .collect();
    let mut out = Restarted::default();
    if mine.is_empty() {
        return out;
    }
    let sysdir = service::system_config_dir(service::Os::current())
        .display()
        .to_string()
        .to_ascii_lowercase();
    let is_system = |c: &String| c.contains(" service run") || c.contains(&sysdir);
    for scope in [Scope::User, Scope::System] {
        let hit = mine.iter().any(|c| (scope == Scope::System) == is_system(c));
        if !hit {
            continue;
        }
        let Ok(t) = service::current_target(scope, &env.config_dir, None, &RealRunner).await else {
            continue;
        };
        if !t.existing && !t.legacy {
            continue;
        }
        if scope == Scope::System && !crate::elevate::is_elevated() {
            out.hint = Some(
                t!("系統服務還是舊版：以系統管理員執行 ai-security-monitor service restart --system --yes 換成新版")
                    .into(),
            );
            continue;
        }
        match service::apply(&service::plan_restart(&t), &RealRunner).await {
            Ok(lines) => {
                out.lines.push(t!("已重新啟動背景服務（換成新版）").to_string());
                out.lines.extend(lines);
            }
            Err(e) => {
                out.hint = Some(tf!(
                    "背景服務重新啟動失敗：{e}；請執行 ai-security-monitor service restart --yes",
                    e = e.message()
                ))
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_update_guard() {
        assert!(ensure_can_self_update(&InstallKind::Standalone, false).is_ok());
        // 桌面版內建的：--force 也不行（會把桌面版換成命令列版）
        let e = ensure_can_self_update(&InstallKind::Desktop, true).unwrap_err();
        assert!(e.message().contains("桌面版"), "{}", e.message());
        let pm = InstallKind::PackageManager {
            manager: "Homebrew".into(),
        };
        let e = ensure_can_self_update(&pm, false).unwrap_err();
        assert!(e.message().contains("Homebrew") && e.message().contains("--force"));
        assert!(ensure_can_self_update(&pm, true).is_ok());
        assert!(ensure_can_self_update(&InstallKind::DevBuild, false).is_err());
    }
}
