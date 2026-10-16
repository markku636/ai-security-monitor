//! 執行防火牆動作：依計畫寫檔、跑指令、更新期望狀態、寫稽核紀錄（`<config>/actions.jsonl`）。
//! CLI、MCP（preview → review token → execute）與 hub 遠端動作都走這裡。

pub mod review;

use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::error::{AppError, AppResult};
use crate::firewall::desired::DesiredState;
use crate::firewall::plan::{self, FileWrite, FwAction, Plan, PlanCtx, WriteMode};
use crate::store;
use crate::util::cmd::CmdRunner;

pub const AUDIT_FILE: &str = "actions.jsonl";

/// 為動作建立計畫（純計算，不改任何東西）。
pub fn prepare(config_dir: &Path, action: &FwAction, backend: &str, ssh_listening: bool) -> AppResult<Plan> {
    let ctx = PlanCtx {
        tmp_dir: config_dir.join("tmp"),
        desired: DesiredState::load(config_dir)?,
        feed_nets: DesiredState::load_feed_nets(config_dir),
        ssh_listening,
    };
    plan::plan(backend, action, &ctx)
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub step: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub output: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub backend: String,
    pub action: String,
    pub ok: bool,
    pub steps: Vec<StepResult>,
    pub notes: Vec<String>,
}

fn write_file(w: &FileWrite) -> AppResult<()> {
    if let Some(parent) = w.path.parent() {
        store::ensure_dir(parent)?;
    }
    let existing = std::fs::read_to_string(&w.path).unwrap_or_default();
    let body = match w.mode {
        WriteMode::Replace => w.content.clone(),
        WriteMode::AppendLines => {
            let mut out = existing.clone();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            // 整塊（含多行標記）已存在就不再附加；否則逐行補上缺的。
            if !w.content.is_empty() && existing.contains(w.content.trim_end()) {
                out
            } else {
                for line in w.content.lines() {
                    if !existing.lines().any(|l| l == line) {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
                out
            }
        }
        WriteMode::RemoveLines => {
            let drop: Vec<&str> = w.content.lines().collect();
            existing
                .lines()
                .filter(|l| !drop.contains(l))
                .map(|l| format!("{l}\n"))
                .collect()
        }
    };
    let mut bytes = Vec::new();
    if w.bom {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    bytes.extend_from_slice(body.as_bytes());
    store::write_bytes_atomic(&w.path, &bytes)
}

/// 套用計畫；任何非容錯步驟失敗就停止。
pub async fn apply(plan: &Plan, runner: &dyn CmdRunner) -> (bool, Vec<StepResult>) {
    let mut steps = Vec::new();
    for w in &plan.writes {
        let r = write_file(w);
        let ok = r.is_ok();
        if !w.temporary {
            steps.push(StepResult {
                step: format!("write {}", w.path.display()),
                ok,
                output: r.err().map(|e| e.message()).unwrap_or_default(),
            });
        }
        if !ok {
            cleanup(plan);
            return (false, steps);
        }
    }
    let mut all_ok = true;
    for c in &plan.commands {
        let res = runner.run(c).await;
        let (ok, output) = match res {
            Ok(o) => (
                o.ok(),
                crate::util::text::clip(format!("{}{}", o.stdout.trim(), o.stderr.trim()).trim(), 600),
            ),
            Err(e) => (false, e.message()),
        };
        steps.push(StepResult {
            step: crate::util::text::clip(&c.display(), 200),
            ok,
            output,
        });
        if !ok && !c.allow_fail {
            all_ok = false;
            break;
        }
    }
    cleanup(plan);
    (all_ok, steps)
}

fn cleanup(plan: &Plan) {
    for w in plan.writes.iter().filter(|w| w.temporary) {
        let _ = std::fs::remove_file(&w.path);
    }
}

/// 稽核紀錄：每次動作一行 JSON。
pub fn audit(config_dir: &Path, origin: &str, action: &FwAction, report: &ApplyReport) -> AppResult<()> {
    store::ensure_dir(config_dir)?;
    let line = serde_json::json!({
        "ts": crate::util::time::now_iso(),
        "origin": origin,
        "elevated": crate::elevate::is_elevated(),
        "action": action,
        "backend": report.backend,
        "ok": report.ok,
        "steps": report.steps,
    });
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config_dir.join(AUDIT_FILE))?;
    writeln!(f, "{line}")?;
    Ok(())
}

/// 完整流程：計畫 → 套用 → 更新期望狀態 → 稽核。呼叫端負責確認與提權。
pub async fn execute(
    config_dir: &Path,
    action: &FwAction,
    backend: &str,
    origin: &str,
    runner: &dyn CmdRunner,
    ssh_listening: bool,
) -> AppResult<ApplyReport> {
    let plan = prepare(config_dir, action, backend, ssh_listening)?;
    let (ok, steps) = if plan.is_empty() {
        (true, Vec::new())
    } else {
        apply(&plan, runner).await
    };
    let report = ApplyReport {
        backend: backend.to_string(),
        action: action.describe(),
        ok,
        steps,
        notes: plan.notes.clone(),
    };
    if ok {
        let mut d = DesiredState::load(config_dir)?;
        d.apply(config_dir, action, backend)?;
    }
    audit(config_dir, origin, action, &report)?;
    if !ok {
        let last = report
            .steps
            .iter()
            .rev()
            .find(|s| !s.ok)
            .map(|s| format!("{}: {}", s.step, s.output))
            .unwrap_or_default();
        return Err(AppError::Firewall(tf!("套用失敗：{detail}", detail = last)));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::plan::Dir;
    use crate::util::cmd::{CmdOutput, FakeRunner};

    #[test]
    fn file_write_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x/pf.conf");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "anchor \"com.apple/*\"\n").unwrap();
        let block = crate::firewall::plan::PF_CONF_BLOCK.to_string();
        let w = FileWrite {
            path: p.clone(),
            content: block.clone(),
            mode: WriteMode::AppendLines,
            bom: false,
            temporary: false,
        };
        write_file(&w).unwrap();
        write_file(&w).unwrap();
        let s = std::fs::read_to_string(&p).unwrap();
        assert_eq!(s.matches("# asa-begin").count(), 1);
        assert!(s.starts_with("anchor \"com.apple/*\"\n"));
        let rm = FileWrite {
            path: p.clone(),
            content: "anchor \"com.apple/*\"\n".into(),
            mode: WriteMode::RemoveLines,
            bom: false,
            temporary: false,
        };
        write_file(&rm).unwrap();
        assert!(!std::fs::read_to_string(&p).unwrap().contains("com.apple"));
        let bom = FileWrite {
            path: dir.path().join("a.ps1"),
            content: "x".into(),
            mode: WriteMode::Replace,
            bom: true,
            temporary: true,
        };
        write_file(&bom).unwrap();
        assert_eq!(
            &std::fs::read(dir.path().join("a.ps1")).unwrap()[..3],
            &[0xEF, 0xBB, 0xBF]
        );
    }

    #[tokio::test]
    async fn execute_updates_desired_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().on("nft", CmdOutput::success(""));
        let n = "198.51.100.7/32".parse().unwrap();
        let action = FwAction::Block {
            nets: vec![n],
            direction: Dir::Both,
            reason: "test".into(),
        };
        let r = execute(dir.path(), &action, "nft", "cli", &runner, false)
            .await
            .unwrap();
        assert!(r.ok);
        assert!(DesiredState::load(dir.path()).unwrap().is_blocked(&n));
        let log = std::fs::read_to_string(dir.path().join(AUDIT_FILE)).unwrap();
        assert!(log.contains("\"origin\":\"cli\"") && log.contains("198.51.100.7/32"));
    }

    #[tokio::test]
    async fn failed_command_does_not_change_desired() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().on("nft", CmdOutput::failure(1, "Error: Operation not permitted"));
        let n = "198.51.100.8/32".parse().unwrap();
        let action = FwAction::Block {
            nets: vec![n],
            direction: Dir::Both,
            reason: String::new(),
        };
        let r = execute(dir.path(), &action, "nft", "cli", &runner, false).await;
        assert!(matches!(r, Err(AppError::Firewall(_))));
        assert!(!DesiredState::load(dir.path()).unwrap().is_blocked(&n));
        assert!(std::fs::read_to_string(dir.path().join(AUDIT_FILE))
            .unwrap()
            .contains("\"ok\":false"));
    }
}
