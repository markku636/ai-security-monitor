//! `ai-security-monitor web-scan-runner`：網站弱點掃描 runner（前景；Ctrl+C 或服務停止就結束）。
//! `--healthcheck` 列出偵測到的掃描工具與版本（至少一個才回 0）；`--once` 認領一次、做完就結束。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use super::args::WebScanRunnerArgs;
use super::render::print_json;
use super::Env;
use crate::error::{AppError, AppResult};
use crate::util::cmd::{CmdRunner, RealRunner};
use crate::webscan::caps::{self, Tools};
use crate::webscan::{exec, runner, verify, Capability, Scanner};

/// 「httpx 1.12.0、nuclei 3.11.1（模板 10.5.0）」。
fn caps_line(caps: &[Capability]) -> String {
    caps.iter()
        .map(|c| match &c.templates {
            Some(t) => tf!(
                "{scanner} {version}（模板 {templates}）",
                scanner = c.scanner,
                version = c.version,
                templates = t
            ),
            None => format!("{} {}", c.scanner, c.version),
        })
        .collect::<Vec<_>>()
        .join(t!("、"))
}

async fn healthcheck(env: &Env, tools: &Tools, runner: &dyn CmdRunner) -> AppResult<()> {
    let found = caps::detect(runner, tools).await;
    let missing: Vec<Scanner> = Scanner::ALL
        .into_iter()
        .filter(|s| !found.iter().any(|c| c.scanner == *s))
        .collect();
    if env.global.json {
        print_json(&serde_json::json!({ "tools": found, "missing": missing }));
    } else {
        for c in &found {
            println!("{}", caps_line(std::slice::from_ref(c)));
        }
        for s in &missing {
            println!("{}", tf!("{scanner}：找不到", scanner = s));
        }
    }
    if found.is_empty() {
        return Err(AppError::External(
            t!("找不到任何掃描工具（httpx、tlsx、nuclei、testssl.sh）").to_string(),
        ));
    }
    Ok(())
}

pub async fn run(env: &Env, a: WebScanRunnerArgs) -> AppResult<()> {
    let tools = Tools {
        dir: a.tools_dir.clone(),
        templates: a.nuclei_templates.clone(),
    };
    let runner: Arc<dyn CmdRunner> = Arc::new(RealRunner);
    if a.healthcheck {
        return healthcheck(env, &tools, runner.as_ref()).await;
    }
    let url = a
        .hub
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| AppError::InvalidArg(t!("要指定 Hub 網址（--hub）").to_string()))?;
    let token = a
        .hub_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::InvalidArg(t!("連 Hub 需要網站掃描權杖（--hub-token）").to_string()))?;
    let url = crate::hub::validate_url(url, a.insecure_http)?;
    let client = crate::hub::HubClient::new(&url, token, "")?;
    let work_dir = a
        .work_dir
        .clone()
        .unwrap_or_else(|| env.config_dir.join(crate::webscan::WORK_DIR));
    crate::store::ensure_dir(&work_dir)?;
    let found = caps::detect(runner.as_ref(), &tools).await;
    if !env.global.json {
        println!(
            "{}",
            tf!(
                "網站弱點掃描 runner 啟動：Hub {url}；同時最多 {n} 個工作；暫存目錄 {dir}（Ctrl+C 結束）",
                url = client.base(),
                n = a.max_jobs,
                dir = work_dir.display()
            )
        );
        if found.is_empty() {
            println!(
                "{}",
                t!("找不到任何掃描工具：只能做擁有權驗證（httpx、tlsx、nuclei、testssl.sh 要在 PATH 或 --tools-dir）")
            );
        } else {
            println!("{}", tf!("掃描工具：{tools}", tools = caps_line(&found)));
        }
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    tokio::spawn(async move {
        let svc = crate::service::instance::stopped();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = svc => {}
        }
        let _ = stop_tx.send(true);
    });
    let ctx = Arc::new(exec::Ctx {
        client: Arc::new(client),
        runner,
        tools,
        caps: found,
        work_dir,
        heartbeat_min: Duration::from_secs(10),
        verify_timeout: verify::TIMEOUT,
        quiet: env.global.quiet,
    });
    let cfg = runner::Config {
        max_jobs: usize::from(a.max_jobs),
        once: a.once,
        timing: runner::Timing::default(),
    };
    let result = runner::run(ctx, cfg, stop_rx).await;
    if matches!(result, Err(AppError::HubAuth)) {
        eprintln!(
            "{}",
            t!("Hub 拒絕了網站掃描權杖（--hub-token）；請確認權杖有勾「網站掃描」，或跟 Hub 的 AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN 一致")
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_flags_and_limits_max_jobs() {
        let cli = crate::cli::args::Cli::try_parse_from([
            "ai-security-monitor",
            "web-scan-runner",
            "--hub",
            "https://hub.example",
            "--hub-token",
            "t0k",
            "--max-jobs",
            "4",
            "--tools-dir",
            "/opt/tools",
            "--work-dir",
            "/work",
            "--once",
        ])
        .unwrap();
        let crate::cli::args::Command::WebScanRunner(a) = cli.cmd else {
            panic!("wrong subcommand");
        };
        assert_eq!(a.max_jobs, 4);
        assert!(a.once && !a.healthcheck && !a.insecure_http);
        assert_eq!(a.tools_dir.as_deref(), Some(std::path::Path::new("/opt/tools")));
        assert_eq!(a.nuclei_templates, std::path::PathBuf::from("/opt/nuclei-templates"));
        for bad in ["0", "5"] {
            assert!(crate::cli::args::Cli::try_parse_from([
                "ai-security-monitor",
                "web-scan-runner",
                "--max-jobs",
                bad
            ])
            .is_err());
        }
    }

    #[test]
    fn caps_line_lists_versions() {
        let caps = vec![
            Capability {
                scanner: Scanner::Httpx,
                version: "1.12.0".into(),
                templates: None,
            },
            Capability {
                scanner: Scanner::Nuclei,
                version: "3.11.1".into(),
                templates: Some("10.5.0".into()),
            },
        ];
        let line = caps_line(&caps);
        assert!(line.starts_with("httpx 1.12.0"), "{line}");
        assert!(line.contains("nuclei 3.11.1") && line.contains("10.5.0"), "{line}");
    }

    fn env_in(dir: &std::path::Path) -> Env {
        Env {
            global: crate::cli::args::GlobalArgs {
                quiet: true,
                ..Default::default()
            },
            config_dir: dir.to_path_buf(),
        }
    }

    /// 映像的 HEALTHCHECK 只帶 `web-scan-runner --healthcheck`：不需要 --hub／--hub-token／--insecure-http、
    /// 不連 Hub、不寫設定目錄；一個工具都沒有就回錯（非 0）。
    #[tokio::test]
    async fn healthcheck_is_local_only() {
        let empty = tempfile::tempdir().unwrap();
        let none = empty.path().join("no-templates");
        let cli = crate::cli::args::Cli::try_parse_from([
            "ai-security-monitor",
            "web-scan-runner",
            "--healthcheck",
            "--tools-dir",
            empty.path().to_str().unwrap(),
            "--nuclei-templates",
            none.to_str().unwrap(),
        ])
        .unwrap();
        let crate::cli::args::Command::WebScanRunner(a) = cli.cmd else {
            panic!("wrong subcommand");
        };
        let cfg = tempfile::tempdir().unwrap();
        let e = run(&env_in(cfg.path()), a).await.unwrap_err();
        assert!(matches!(e, AppError::External(_)), "{e:?}");
        assert_eq!(std::fs::read_dir(cfg.path()).unwrap().count(), 0, "nothing written");
    }

    #[tokio::test]
    async fn healthcheck_passes_with_one_tool() {
        use crate::util::cmd::{CmdOutput, FakeRunner};
        let tools = Tools {
            dir: None,
            templates: std::path::PathBuf::from("/nonexistent-templates"),
        };
        let cfg = tempfile::tempdir().unwrap();
        let one = FakeRunner::new().on(
            "httpx -version",
            CmdOutput {
                code: Some(0),
                stdout: String::new(),
                stderr: "[INF] Current Version: v1.12.0".into(),
            },
        );
        healthcheck(&env_in(cfg.path()), &tools, &one).await.unwrap();
        assert!(healthcheck(&env_in(cfg.path()), &tools, &FakeRunner::new())
            .await
            .is_err());
    }
}
