//! `ai-security-monitor service install|uninstall|status|logs`：開機自動啟動（系統服務或使用者登入時）。

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
        ServiceCmd::Install {
            system,
            interval,
            admin_at_logon,
            task_user,
            ..
        } => {
            if let Some(i) = &interval {
                crate::util::time::parse_duration(i)?;
            }
            if admin_at_logon {
                return admin_logon(env, interval, true, task_user).await;
            }
            change(env, scope(system), interval, true).await
        }
        ServiceCmd::Uninstall {
            system,
            admin_at_logon,
            task_user,
            ..
        } => {
            if admin_at_logon {
                return admin_logon(env, None, false, task_user).await;
            }
            change(env, scope(system), None, false).await
        }
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

fn print_plan(plan: &Plan, install: bool, admin_task: bool) {
    let how = if admin_task {
        t!("排程工作，登入時以系統管理員權限啟動").to_string()
    } else {
        plan.manager.label().to_string()
    };
    println!(
        "{}",
        if install {
            tf!("安裝開機自動啟動（{how}）：", how = how)
        } else {
            tf!("移除開機自動啟動（{how}）：", how = how)
        }
    );
    for s in &plan.steps {
        println!("  · {}", s.describe());
    }
}

/// Windows：「登入時以系統管理員權限啟動」開／關（排程工作，見 [`service::elevated`]）。
async fn admin_logon(env: &Env, interval: Option<String>, enable: bool, task_user: Option<String>) -> AppResult<()> {
    if !cfg!(windows) {
        return Err(AppError::Unsupported(t!("--admin-at-logon 只支援 Windows").into()));
    }
    let user = task_user
        .or_else(service::elevated::current_user)
        .ok_or_else(|| AppError::Service(t!("讀不到目前登入的帳號").into()))?;
    let target = service::current_target(Scope::User, &env.config_dir, interval, &RealRunner).await?;
    let plan = if enable {
        service::elevated::plan_enable(&target, &user)
    } else {
        service::elevated::plan_disable(&target)
    };
    // 提權前先記下目前帳號（UAC 換成別的管理員帳號時，排程工作仍要用原本的帳號）
    let extra = vec!["--task-user".to_string(), user];
    apply_plan(env, plan, enable, Scope::User, &target, &extra).await
}

async fn change(env: &Env, scope: Scope, interval: Option<String>, install: bool) -> AppResult<()> {
    let target = service::current_target(scope, &env.config_dir, interval, &RealRunner).await?;
    let plan = if install {
        service::plan_install(&target)
    } else {
        service::plan_uninstall(&target)
    };
    apply_plan(env, plan, install, scope, &target, &[]).await
}

/// 照計畫執行（需要時提權重跑同一個命令，`extra` 加在子行程的參數後面）。
async fn apply_plan(
    env: &Env,
    plan: Plan,
    install: bool,
    scope: Scope,
    target: &service::Target,
    extra: &[String],
) -> AppResult<()> {
    let elevated_plan = scope == Scope::System || !extra.is_empty();
    if !env.global.yes {
        if env.global.json {
            print_json(&plan);
        } else {
            print_plan(&plan, install, !extra.is_empty());
        }
        let action = if install {
            t!("安裝開機自動啟動")
        } else {
            t!("移除開機自動啟動")
        };
        return ensure_confirmed(false, false, false, action);
    }
    if elevated_plan && !elevate::is_elevated() {
        // 需要系統管理員：以提權的子行程重跑同一個命令
        let r = elevate::rerun_elevated_with(&env.config_dir, extra).await?;
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
    // Windows 系統服務：設定目錄先收緊成只有 SYSTEM／Administrators 能寫，再讓服務開始讀它
    if install && scope == Scope::System && target.os == Os::Windows {
        crate::store::harden_system_dir(&target.config_dir)?;
    }
    let res = service::apply(&plan, &RealRunner).await;
    let out = match &res {
        Ok(lines) => {
            let mut lines = lines.clone();
            lines.extend(plan.notes.iter().map(|n| format!("· {n}")));
            if install {
                lines.push(tf!(
                    "完成。log：{dir}（ai-security-monitor service logs{sys}）",
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

/// 桌面版用：使用者層的開機自動回報（等同 `service install|uninstall --yes`，不提權）。
/// 和命令列走同一份計畫：會換掉舊版 asa 的登入啟動項目、停掉舊版常駐行程並搬設定目錄。回傳執行結果（每步一行）。
pub async fn set_user_service(config_dir: &std::path::Path, install: bool) -> AppResult<Vec<String>> {
    let target = service::current_target(Scope::User, config_dir, None, &RealRunner).await?;
    let plan = if install {
        service::plan_install(&target)
    } else {
        service::plan_uninstall(&target)
    };
    let mut lines = service::apply(&plan, &RealRunner).await?;
    lines.extend(plan.notes.iter().map(|n| format!("· {n}")));
    Ok(lines)
}

/// 桌面版用：使用者層服務的狀態（已安裝／舊版 asa／狀態）、會用哪個執行檔，以及目前常駐中的 watch 數。
pub async fn user_service_status(config_dir: &std::path::Path) -> AppResult<serde_json::Value> {
    let target = service::current_target(Scope::User, config_dir, None, &RealRunner).await?;
    let st = service::scope_status(&target, &RealRunner).await;
    Ok(serde_json::json!({
        "status": st,
        "exe": target.exe,
        "config_dir": target.config_dir,
        "running": service::running_watchers(None).len(),
        "legacy_running": service::legacy_watcher_running(),
        "admin_at_logon": service::elevated::installed(&RealRunner).await,
    }))
}

/// 排程工作版（登入時以系統管理員權限啟動）的重新啟動：不用提權。
async fn restart_admin_task() -> AppResult<Vec<String>> {
    let plan = Plan {
        scope: Scope::User,
        manager: service::Manager::WindowsRun,
        steps: service::elevated::plan_restart(),
        notes: Vec::new(),
    };
    service::apply(&plan, &RealRunner).await
}

/// 桌面版用：使用者層的背景服務有登記、卻沒有在跑（例如更新安裝時被結束）→ 把它啟動起來。回傳有沒有啟動。
pub async fn ensure_user_service_running(config_dir: &std::path::Path) -> AppResult<Option<Vec<String>>> {
    if !service::running_watchers(Some(config_dir)).is_empty() {
        return Ok(None);
    }
    if service::elevated::installed(&RealRunner).await {
        return restart_admin_task().await.map(Some);
    }
    let target = service::current_target(Scope::User, config_dir, None, &RealRunner).await?;
    if !target.existing {
        return Ok(None);
    }
    service::apply(&service::plan_restart(&target), &RealRunner)
        .await
        .map(Some)
}

/// 桌面版用：更新之後讓使用者層的背景服務換成新版（有登記才做）。
pub async fn restart_user_service(config_dir: &std::path::Path) -> AppResult<Option<Vec<String>>> {
    if service::elevated::installed(&RealRunner).await {
        return restart_admin_task().await.map(Some);
    }
    let target = service::current_target(Scope::User, config_dir, None, &RealRunner).await?;
    if !target.existing {
        return Ok(None);
    }
    service::apply(&service::plan_restart(&target), &RealRunner)
        .await
        .map(Some)
}

async fn restart(env: &Env, scope: Scope) -> AppResult<()> {
    let target = service::current_target(scope, &env.config_dir, None, &RealRunner).await?;
    if !target.existing && !target.legacy {
        return Err(AppError::Service(
            t!("還沒安裝開機自動啟動（ai-security-monitor service install）").to_string(),
        ));
    }
    let plan = service::plan_restart(&target);
    if !env.global.yes {
        for s in &plan.steps {
            println!("  · {}", s.describe());
        }
        for n in &plan.notes {
            println!("· {n}");
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
    let admin_task = service::elevated::installed(&RealRunner).await;
    if env.global.json {
        print_json(&serde_json::json!({ "scopes": rows, "running": watchers, "admin_at_logon": admin_task }));
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
                if s.installed {
                    t!("是").to_string()
                } else if s.legacy {
                    t!("舊版 asa（service install 會換成新名）").to_string()
                } else {
                    t!("否").to_string()
                },
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
    if admin_task {
        println!(
            "{}",
            tf!(
                "登入時以系統管理員權限啟動：已開啟（排程工作「{task}」）",
                task = service::elevated::TASK
            )
        );
    }
    if watchers.is_empty() {
        println!("{}", t!("目前沒有常駐中的 ai-security-monitor watch。"));
    } else {
        for w in &watchers {
            println!("{}", tf!("執行中：PID {pid} {cmd}", pid = w.pid, cmd = w.cmd));
        }
    }
    Ok(())
}

fn logs(env: &Env, system: bool, tail: usize) -> AppResult<()> {
    let dir = if system {
        // 舊版系統服務還沒換掉時讀舊目錄的 log
        service::effective_system_config_dir(Os::current())
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
            "{dir} 還沒有 log（服務模式的 ai-security-monitor watch 才會寫 log 檔）",
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
            t!("service run 只用於 Windows 服務；其他平台由 systemd／launchd 執行 ai-security-monitor watch --service")
                .to_string(),
        ))
    }
}
