//! Windows「登入時以系統管理員權限啟動」：用排程工作（登入觸發、最高權限）跑使用者層的背景服務，
//! 讓 `watch` 讀得到各程式的網路流量（TCP 延伸統計要系統管理員）。跟一般使用者層一樣用使用者自己的設定目錄，
//! 桌面版、命令列與 Hub 看到的是同一份資料；只是取代 HKCU Run 那一項。
//!
//! - 開啟（要提權一次）：移除 HKCU Run → 結束目前的背景服務 → 建立排程工作 → 立刻啟動。之後每次登入自動以管理員權限啟動，不再跳 UAC。
//! - 關閉（要提權一次）：結束並刪除排程工作 → 換回 HKCU Run（等同 `service install`）。
//! - 帳號要是系統管理員群組成員才有效果（標準使用者的「最高權限」還是標準權限）。

use super::{plan_install, run, run_ok, Manager, Plan, Scope, Step, Target, NAMES, WIN_RUN_KEY};
use crate::util::cmd::{CmdRunner, CmdSpec};

/// 排程工作名稱。
pub const TASK: &str = "AI Security Monitor (elevated)";
/// schtasks /TR 的長度上限。
pub const TR_MAX: usize = 261;

/// 執行排程工作的帳號：`網域\帳號`（沒有網域就只有帳號）。
pub fn current_user() -> Option<String> {
    let user = std::env::var("USERNAME").ok().filter(|u| !u.is_empty())?;
    Some(match std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty()) {
        Some(d) => format!("{d}\\{user}"),
        None => user,
    })
}

/// 開啟：`t` 是使用者層的目標（設定目錄、執行檔都沿用）。
pub fn plan_enable(t: &Target, user: &str) -> Plan {
    let cmd = super::units::windows_cmdline(&t.exe, &t.run_args());
    let mut notes = vec![t!("帳號要是系統管理員群組的成員，背景服務才會有管理員權限。").to_string()];
    if cmd.chars().count() > TR_MAX {
        notes.push(tf!(
            "指令超過 {n} 個字元，排程工作可能建立失敗；請把程式裝到路徑較短的位置。",
            n = TR_MAX
        ));
    }
    let steps = vec![
        run_ok("reg.exe", &["delete", WIN_RUN_KEY, "/v", NAMES.service, "/f"]),
        Step::StopWatchers {
            config_dir: t.config_dir.clone(),
        },
        run(
            "schtasks.exe",
            &[
                "/Create", "/F", "/TN", TASK, "/SC", "ONLOGON", "/RL", "HIGHEST", "/IT", "/RU", user, "/TR", &cmd,
            ],
        ),
        run("schtasks.exe", &["/Run", "/TN", TASK]),
    ];
    Plan {
        scope: Scope::User,
        manager: Manager::WindowsRun,
        steps,
        notes,
    }
}

/// 關閉：刪掉排程工作，換回一般的使用者層（HKCU Run，立刻啟動）。
pub fn plan_disable(t: &Target) -> Plan {
    let mut steps = vec![
        run_ok("schtasks.exe", &["/End", "/TN", TASK]),
        run_ok("schtasks.exe", &["/Delete", "/TN", TASK, "/F"]),
        Step::StopWatchers {
            config_dir: t.config_dir.clone(),
        },
    ];
    let back = plan_install(t);
    steps.extend(back.steps);
    Plan {
        scope: Scope::User,
        manager: Manager::WindowsRun,
        steps,
        notes: back.notes,
    }
}

/// 重新啟動（例如更新之後）：不需要提權，排程工作允許建立它的使用者結束與執行。
pub fn plan_restart() -> Vec<Step> {
    vec![
        run_ok("schtasks.exe", &["/End", "/TN", TASK]),
        run("schtasks.exe", &["/Run", "/TN", TASK]),
    ]
}

/// 排程工作在不在。
pub async fn installed(runner: &dyn CmdRunner) -> bool {
    if !cfg!(windows) {
        return false;
    }
    runner
        .run(&CmdSpec::new("schtasks.exe", &["/Query", "/TN", TASK]).timeout(10_000))
        .await
        .map(|o| o.ok())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{tests::target, Os};

    fn user_target() -> Target {
        target(Os::Windows, Scope::User)
    }

    #[test]
    fn enable_replaces_the_run_key_with_an_elevated_logon_task() {
        let t = user_target();
        let p = plan_enable(&t, r"PC\mark");
        let d: Vec<String> = p.steps.iter().map(|s| s.describe()).collect();
        assert!(d[0].contains("reg.exe delete"), "{d:?}");
        assert!(d
            .iter()
            .any(|s| s.contains("/RL HIGHEST") && s.contains("/SC ONLOGON") && s.contains(r"PC\mark")));
        assert!(d.iter().any(|s| s.contains("watch") && s.contains("--service")));
        assert!(d.last().unwrap().contains("/Run"));
    }

    #[test]
    fn disable_deletes_the_task_and_restores_the_run_key() {
        let d: Vec<String> = plan_disable(&user_target())
            .steps
            .iter()
            .map(|s| s.describe())
            .collect();
        assert!(d.iter().any(|s| s.contains("/Delete")));
        assert!(d.iter().any(|s| s.contains("reg.exe add")), "{d:?}");
    }
}
