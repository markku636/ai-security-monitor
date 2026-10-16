//! `asa service install|uninstall|status|logs`：開機自動啟動（系統服務或使用者登入時）。

use super::args::ServiceCmd;
use super::guard::ensure_confirmed;
use super::render::{print_json, table};
use super::Env;
use crate::elevate::{self, ElevatedResult};
use crate::error::{AppError, AppResult};
use crate::service::{self, instance, Os, Plan, Scope};
use crate::util::cmd::RealRunner;

pub async fn run(env: &Env, cmd: ServiceCmd) -> AppResult<()> {
    match cmd {
        ServiceCmd::Install { system, interval, .. } => {
            if let Some(i) = &interval {
                crate::util::time::parse_duration(i)?;
            }
            change(env, scope(system), interval, true).await
        }
        ServiceCmd::Uninstall { system, .. } => change(env, scope(system), None, false).await,
        ServiceCmd::Status => status(env).await,
        ServiceCmd::Restart { system } => restart(env, scope(system)).await,
        ServiceCmd::Logs { system, tail } => logs(env, system, tail),
        ServiceCmd::Run { interval } => run_service(env, interval).await,
    }
}

fn scope(system: bool) -> Scope {
    if system {
        Scope::System
    } else {
        Scope::User
    }
}

fn print_plan(plan: &Plan, install: bool) {
    println!(
        "{}",
        if install {
            tf!("安裝開機自動啟動（{how}）：", how = plan.manager.label())
        } else {
            tf!("移除開機自動啟動（{how}）：", how = plan.manager.label())
        }
    );
    for s in &plan.steps {
        println!("  · {}", s.describe());
    }
}

async fn change(env: &Env, scope: Scope, interval: Option<String>, install: bool) -> AppResult<()> {
    let target = service::current_target(scope, &env.config_dir, interval, &RealRunner).await?;
    let plan = if install {
        service::plan_install(&target)
    } else {
        service::plan_uninstall(&target)
    };
    let action = if install {
        t!("安裝開機自動啟動")
    } else {
        t!("移除開機自動啟動")
    };
    if !env.global.yes {
        if env.global.json {
            print_json(&plan);
        } else {
            print_plan(&plan, install);
        }
        return ensure_confirmed(false, false, false, action);
    }
    if scope == Scope::System && !elevate::is_elevated() {
        // 系統服務需要系統管理員：以提權的子行程重跑同一個命令
        let r = elevate::rerun_elevated(&env.config_dir).await?;
        if env.global.json {
            print_json(&r.json);
        } else {
            for l in &r.lines {
                println!("{l}");
            }
        }
        return if r.ok {
            Ok(())
        } else {
            Err(AppError::Service(
                r.error
                    .as_ref()
                    .and_then(|e| e["message"].as_str())
                    .unwrap_or("failed")
                    .to_string(),
            ))
        };
    }
    let res = service::apply(&plan, &RealRunner).await;
    let out = match &res {
        Ok(lines) => {
            let mut lines = lines.clone();
            lines.extend(plan.notes.iter().map(|n| format!("· {n}")));
            if install {
                lines.push(tf!(
                    "完成。log：{dir}（asa service logs{sys}）",
                    dir = instance::log_dir(&target.config_dir).display(),
                    sys = if scope == Scope::System { " --system" } else { "" }
                ));
            }
            ElevatedResult {
                ok: true,
                json: serde_json::json!({ "plan": plan, "results": lines }),
                lines,
                error: None,
            }
        }
        Err(e) => ElevatedResult {
            ok: false,
            lines: vec![e.message()],
            json: serde_json::json!({ "error": e }),
            error: serde_json::to_value(e).ok(),
        },
    };
    if let Some(rf) = &env.global.result_file {
        out.write(rf)?;
        return res.map(|_| ());
    }
    if env.global.json {
        print_json(&out.json);
    } else {
        for l in &out.lines {
            println!("{l}");
        }
    }
    res.map(|_| ())
}

async fn restart(env: &Env, scope: Scope) -> AppResult<()> {
    let target = service::current_target(scope, &env.config_dir, None, &RealRunner).await?;
    if !target.existing {
        return Err(AppError::Service(
            t!("還沒安裝開機自動啟動（asa service install）").to_string(),
        ));
    }
    let plan = service::plan_restart(&target);
    if !env.global.yes {
        for s in &plan.steps {
            println!("  · {}", s.describe());
        }
        return ensure_confirmed(false, false, false, t!("重新啟動常駐行程"));
    }
    if scope == Scope::System && !elevate::is_elevated() {
        let r = elevate::rerun_elevated(&env.config_dir).await?;
        for l in &r.lines {
            println!("{l}");
        }
        return if r.ok {
            Ok(())
        } else {
            Err(AppError::Service(t!("重新啟動失敗").to_string()))
        };
    }
    let res = service::apply(&plan, &RealRunner).await;
    if let Some(rf) = &env.global.result_file {
        ElevatedResult {
            ok: res.is_ok(),
            lines: res.as_ref().map(|l| l.clone()).unwrap_or_else(|e| vec![e.message()]),
            json: serde_json::Value::Null,
            error: res.as_ref().err().and_then(|e| serde_json::to_value(e).ok()),
        }
        .write(rf)?;
        return res.map(|_| ());
    }
    for l in res? {
        println!("{l}");
    }
    Ok(())
}

async fn status(env: &Env) -> AppResult<()> {
    let mut rows = Vec::new();
    for sc in [Scope::System, Scope::User] {
        let t = service::current_target(sc, &env.config_dir, None, &RealRunner).await?;
        rows.push(service::scope_status(&t, &RealRunner).await);
    }
    let watchers = service::running_watchers(None);
    if env.global.json {
        print_json(&serde_json::json!({ "scopes": rows, "running": watchers }));
        return Ok(());
    }
    let table_rows = rows
        .iter()
        .map(|s| {
            vec![
                match s.scope {
                    Scope::System => t!("系統").to_string(),
                    Scope::User => t!("使用者").to_string(),
                },
                s.manager.label().to_string(),
                if s.installed { t!("是") } else { t!("否") }.to_string(),
                s.state.clone().unwrap_or_else(|| "—".into()),
                s.unit.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[t!("範圍"), t!("方式"), t!("已安裝"), t!("狀態"), t!("設定檔")],
            table_rows
        )
    );
    if watchers.is_empty() {
        println!("{}", t!("目前沒有常駐中的 asa watch。"));
    } else {
        for w in &watchers {
            println!("{}", tf!("執行中：PID {pid} {cmd}", pid = w.pid, cmd = w.cmd));
        }
    }
    Ok(())
}

fn logs(env: &Env, system: bool, tail: usize) -> AppResult<()> {
    let dir = if system {
        service::system_config_dir(Os::current())
    } else {
        env.config_dir.clone()
    };
    match instance::tail_latest(&dir, tail.clamp(1, 10_000)) {
        Some((path, lines)) => {
            if env.global.json {
                print_json(&serde_json::json!({ "file": path, "lines": lines }));
            } else {
                eprintln!("{}", tf!("（{path}）", path = path.display()));
                for l in lines {
                    println!("{l}");
                }
            }
            Ok(())
        }
        None => Err(AppError::Service(tf!(
            "{dir} 還沒有 log（服務模式的 asa watch 才會寫 log 檔）",
            dir = instance::log_dir(&dir).display()
        ))),
    }
}

async fn run_service(env: &Env, interval: Option<String>) -> AppResult<()> {
    #[cfg(windows)]
    {
        crate::service::winsvc::run(env.global.clone(), env.config_dir.clone(), interval).await
    }
    #[cfg(not(windows))]
    {
        let _ = (env, interval);
        Err(AppError::Unsupported(
            t!("service run 只用於 Windows 服務；其他平台由 systemd／launchd 執行 asa watch --service").to_string(),
        ))
    }
}
