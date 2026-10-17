//! `ai-security-monitor fim`：檔案完整性＋開機自啟的狀態、接受變更、重建基準。

use serde_json::json;

use super::args::{FimArgs, FimCmd};
use super::render::{print_json, table};
use super::Env;
use crate::error::AppResult;
use crate::fim;

pub async fn run(env: &Env, a: FimArgs) -> AppResult<()> {
    let dir = &env.config_dir;
    match a.cmd.unwrap_or(FimCmd::Status) {
        FimCmd::Status => {
            let base = fim::load_baseline(dir);
            let ch = fim::load_changes(dir);
            if env.global.json {
                print_json(&json!({
                    "baseline_created_at": base.created_at,
                    "baseline_updated_at": base.updated_at,
                    "watched_files": base.files.len(),
                    "autoruns": base.autoruns.len(),
                    "changes": ch.items,
                }));
                return Ok(());
            }
            match base.created_at {
                None => println!(
                    "{}",
                    t!("還沒有基準：下次掃描（`scan` 或背景服務）會先記下目前的狀態，之後才會告警。")
                ),
                Some(at) => println!(
                    "{}",
                    tf!(
                        "基準建立於 {at}；監看 {files} 個檔案、{autoruns} 個開機自啟項目。",
                        at = at.format("%Y-%m-%d %H:%M UTC"),
                        files = base.files.len(),
                        autoruns = base.autoruns.len()
                    )
                ),
            }
            if ch.items.is_empty() {
                println!("{}", t!("沒有待確認的變更。"));
                return Ok(());
            }
            let rows = ch
                .items
                .iter()
                .map(|c| {
                    vec![
                        c.first_seen.format("%m-%d %H:%M").to_string(),
                        c.severity.as_str().to_string(),
                        c.rule.clone(),
                        c.key.clone(),
                    ]
                })
                .collect();
            println!(
                "{}",
                table(&[t!("時間"), t!("嚴重度"), t!("規則"), t!("路徑或項目")], rows)
            );
            println!(
                "{}",
                t!("確認是你自己或軟體更新做的：`ai-security-monitor fim accept <路徑>`（或 `--all`）。")
            );
            Ok(())
        }
        FimCmd::Accept { path, all } => {
            if path.is_none() && !all {
                return Err(crate::error::AppError::InvalidArg(
                    t!("請指定路徑，或用 --all 接受全部").into(),
                ));
            }
            let n = fim::accept(dir, if all { None } else { path.as_deref() })?;
            if env.global.json {
                print_json(&json!({ "accepted": n }));
                return Ok(());
            }
            println!(
                "{}",
                tf!("已接受 {n} 個變更；下次上傳後 Hub 上的問題會跟著消失。", n = n)
            );
            Ok(())
        }
        FimCmd::Baseline => {
            fim::reset(dir)?;
            if env.global.json {
                print_json(&json!({ "reset": true }));
                return Ok(());
            }
            println!(
                "{}",
                t!("已清掉基準與變更清單；下次掃描會重新記下目前的狀態（不會告警）。")
            );
            Ok(())
        }
    }
}
