//! `ai-security-monitor ai ask|analyze|status`：交給 Claude Code／Codex CLI，掛上 ai-security-monitor 的唯讀 MCP 工具。

use std::io::Write;
use std::time::Duration;

use super::args::{AiCmd, AiOpts};
use super::render::{print_json, table};
use super::Env;
use crate::ai::{self, prompts, AiEvent, Provider, RunSpec};
use crate::error::{AppError, AppResult};
use crate::mcp::tools::READ_ONLY;
use crate::util::cmd::{CmdRunner, CmdSpec, RealRunner};
use crate::util::time::parse_duration;

fn tools() -> Vec<String> {
    READ_ONLY.iter().map(|s| s.to_string()).collect()
}

async fn version(bin: &ai::Bin) -> Option<String> {
    let spec = if bin.via_cmd {
        CmdSpec::new("cmd", &["/C", &bin.path.display().to_string(), "--version"])
    } else {
        CmdSpec::new(&bin.path.display().to_string(), &["--version"])
    }
    .timeout(15_000);
    let out = RealRunner.run(&spec).await.ok()?;
    out.stdout
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

pub async fn run(env: &Env, cmd: AiCmd) -> AppResult<()> {
    match cmd {
        AiCmd::Status => status(env).await,
        AiCmd::Ask { question, opts } => {
            let system = prompts::render(prompts::ASK_SYSTEM);
            ask(env, &opts, question, system).await
        }
        AiCmd::Analyze {
            report,
            traffic,
            events,
            duration,
            since,
            opts,
        } => {
            let (tpl, data) = if traffic {
                let d = parse_duration(&duration)?.min(Duration::from_secs(300));
                let intel = crate::hub::watch::load_intel(&env.config_dir).await;
                if !env.global.quiet {
                    eprintln!("{}", tf!("觀察流量 {d}…", d = duration));
                }
                let s = crate::traffic::lite::sample(&env.config_dir, d, Duration::from_secs(2), intel).await?;
                (prompts::ANALYZE_TRAFFIC, serde_json::to_value(s)?)
            } else if events {
                let days = (parse_duration(&since)?.as_secs().div_ceil(86_400)).clamp(1, 90) as u32;
                let collected = crate::events::collect(&RealRunner, days).await?;
                let s = crate::events::summarize(collected, days, None);
                (prompts::ANALYZE_EVENTS, serde_json::to_value(s)?)
            } else {
                let r = match report {
                    Some(p) => serde_json::from_slice::<serde_json::Value>(&std::fs::read(&p)?)?,
                    None => match crate::hub::watch::load_latest(&env.config_dir) {
                        Some(r) => serde_json::to_value(r)?,
                        None => {
                            if !env.global.quiet {
                                eprintln!("{}", t!("還沒有報告，先掃描一次…"));
                            }
                            let (r, _) = super::scan_cmd::run_scan(env, &[], false).await?;
                            let _ = crate::hub::watch::save_latest(&env.config_dir, &r);
                            serde_json::to_value(r)?
                        }
                    },
                };
                (prompts::ANALYZE_REPORT, r)
            };
            let json = serde_json::to_string(&data)?;
            if !env.global.quiet {
                eprintln!(
                    "{}",
                    tf!(
                        "送給 AI 的資料：{n} bytes（可在 ai-security-monitor 設定目錄以外的地方檢查內容）",
                        n = json.len()
                    )
                );
            }
            let prompt = format!("{}\n\n```json\n{}\n```\n", prompts::render(tpl), json);
            let system = prompts::render(prompts::ASK_SYSTEM);
            ask(env, &opts, prompt, system).await
        }
    }
}

async fn ask(env: &Env, opts: &AiOpts, prompt: String, system: String) -> AppResult<()> {
    let (provider, bin) = ai::pick_provider(opts.provider)?;
    let spec = RunSpec {
        provider,
        prompt,
        system,
        tools: tools(),
        model: opts.model.clone(),
        max_turns: opts.max_turns,
        timeout: parse_duration(&opts.timeout)?,
    };
    if !env.global.quiet && !env.global.json {
        eprintln!(
            "{}",
            tf!(
                "使用 {cli}（{path}）…",
                cli = provider.label(),
                path = bin.path.display()
            )
        );
    }
    let json = env.global.json;
    let mut at_line_start = true;
    let outcome = ai::run(&spec, &bin, &env.config_dir, |e| {
        if json {
            println!("{}", serde_json::to_string(e).unwrap_or_default());
            return;
        }
        match e {
            AiEvent::Text { text } => {
                print!("{text}");
                let _ = std::io::stdout().flush();
                at_line_start = text.ends_with('\n');
            }
            AiEvent::Tool { name, input } => {
                if !at_line_start {
                    println!();
                    at_line_start = true;
                }
                eprintln!("  ⚙ {name} {}", input.clone().unwrap_or_default());
            }
            AiEvent::ToolResult { ok: false, preview } => eprintln!("  ✗ {preview}"),
            AiEvent::Error { message } => eprintln!("  ! {message}"),
            _ => {}
        }
    })
    .await?;
    if !json {
        if !outcome.text.ends_with('\n') {
            println!();
        }
        if outcome.is_error {
            return Err(AppError::Ai(t!("AI 回報錯誤（見上方輸出）").into()));
        }
    }
    Ok(())
}

async fn status(env: &Env) -> AppResult<()> {
    let mut rows = Vec::new();
    let mut items = Vec::new();
    for p in [Provider::Claude, Provider::Codex] {
        let bin = ai::resolve_bin(p);
        let ver = match &bin {
            Some(b) => version(b).await,
            None => None,
        };
        let logged = ai::logged_in(p);
        items.push(serde_json::json!({ "provider": p, "path": bin.as_ref().map(|b| &b.path), "version": ver, "credentials_found": logged }));
        rows.push(vec![
            p.label().to_string(),
            bin.as_ref()
                .map(|b| b.path.display().to_string())
                .unwrap_or_else(|| t!("未安裝").into()),
            ver.unwrap_or_else(|| "-".into()),
            if bin.is_none() {
                "-".into()
            } else if logged {
                "✓".into()
            } else {
                t!("可能未登入").into()
            },
        ]);
    }
    if env.global.json {
        print_json(&items);
        return Ok(());
    }
    println!("{}", table(&[t!("AI"), t!("路徑"), t!("版本"), t!("登入")], rows));
    println!(
        "{}",
        t!("安裝：npm i -g @anthropic-ai/claude-code（登入：claude）或 npm i -g @openai/codex（登入：codex login）")
    );
    Ok(())
}
