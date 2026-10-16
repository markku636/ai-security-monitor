//! `asa ai`：交給 Claude Code（`claude -p`）或 Codex（`codex exec`）分析，並把 `asa mcp` 掛成它們的工具，
//! 讓 AI 自己查連線、情資、防火牆、流量、事件。只給唯讀工具；不會讓 AI 改系統。
//! 參數與事件對應照 db-kit agent.rs；子行程用 Job Object／process group 管，逾時整棵收掉。

pub mod events;
pub mod proc;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::error::{AppError, AppResult};
pub use events::AiEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Claude,
    Codex,
}

impl Provider {
    pub fn exe(self) -> &'static str {
        match self {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
        }
    }

    pub fn env_override(self) -> &'static str {
        match self {
            Provider::Claude => "ASA_CLAUDE_BIN",
            Provider::Codex => "ASA_CODEX_BIN",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Claude => "Claude Code",
            Provider::Codex => "Codex CLI",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Bin {
    pub path: PathBuf,
    /// Windows 的 .cmd／.bat 要透過 `cmd /C`
    pub via_cmd: bool,
}

fn classify(path: PathBuf) -> Bin {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    Bin {
        via_cmd: cfg!(windows) && (ext == "cmd" || ext == "bat"),
        path,
    }
}

/// 找 CLI：環境變數覆寫 → PATH → 常見安裝位置。
pub fn resolve_bin(p: Provider) -> Option<Bin> {
    if let Some(v) = std::env::var_os(p.env_override())
        .map(PathBuf::from)
        .filter(|v| v.is_file())
    {
        return Some(classify(v));
    }
    if let Some(found) = crate::cli::doctor_cmd::find_in_path(p.exe()) {
        return Some(classify(found));
    }
    let home = dirs::home_dir()?;
    let mut candidates = vec![
        home.join(".local").join("bin").join(p.exe()),
        home.join(".claude").join("local").join(p.exe()),
    ];
    if cfg!(windows) {
        if let Some(app) = std::env::var_os("APPDATA").map(PathBuf::from) {
            candidates.push(app.join("npm").join(format!("{}.cmd", p.exe())));
        }
        candidates.push(home.join(".local").join("bin").join(format!("{}.exe", p.exe())));
    }
    candidates.into_iter().find(|c| c.is_file()).map(classify)
}

/// 粗略判斷是否登入過（找不到憑證檔不代表一定沒登入，只當提示）。
pub fn logged_in(p: Provider) -> bool {
    let env_set = |k: &str| std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false);
    let home = dirs::home_dir().unwrap_or_default();
    match p {
        Provider::Claude => {
            env_set("ANTHROPIC_API_KEY")
                || env_set("CLAUDE_CODE_OAUTH_TOKEN")
                || home.join(".claude").join(".credentials.json").is_file()
                || cfg!(target_os = "macos")
        }
        Provider::Codex => {
            env_set("OPENAI_API_KEY") || env_set("CODEX_API_KEY") || home.join(".codex").join("auth.json").is_file()
        }
    }
}

/// 沒指定就用找得到的那個（Claude 優先）。
pub fn pick_provider(wanted: Option<Provider>) -> AppResult<(Provider, Bin)> {
    let order = match wanted {
        Some(p) => vec![p],
        None => vec![Provider::Claude, Provider::Codex],
    };
    for p in order {
        if let Some(b) = resolve_bin(p) {
            return Ok((p, b));
        }
    }
    Err(AppError::Ai(match wanted {
        Some(p) => tf!("找不到 {cli}；請先安裝並登入（asa ai status 看詳情）", cli = p.label()),
        None => t!("找不到 Claude Code 或 Codex CLI；請先安裝其中一個並登入（asa ai status 看詳情）").to_string(),
    }))
}

pub struct RunSpec {
    pub provider: Provider,
    pub prompt: String,
    pub system: String,
    /// 掛給 AI 的 asa MCP 工具（唯讀）
    pub tools: Vec<String>,
    pub model: Option<String>,
    pub max_turns: u32,
    pub timeout: Duration,
}

pub const MCP_NAME: &str = "asa";

/// `asa --config-dir <dir> --lang <lang> mcp --tools …`
pub fn mcp_args(config_dir: &Path, tools: &[String]) -> Vec<String> {
    vec![
        "--config-dir".into(),
        config_dir.display().to_string(),
        "--lang".into(),
        crate::i18n::current().as_code().into(),
        "mcp".into(),
        "--tools".into(),
        if tools.is_empty() {
            "none".into()
        } else {
            tools.join(",")
        },
    ]
}

/// `system_flag`=false 時不用 --append-system-prompt（經 `cmd /C` 啟動 .cmd 時，參數裡的換行會截斷命令列）。
pub fn claude_args(spec: &RunSpec, mcp_config: &Path, system_flag: bool) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-p".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--include-partial-messages".into(),
        "--permission-mode".into(),
        "dontAsk".into(),
    ];
    if !spec.tools.is_empty() {
        a.push("--allowedTools".into());
        a.push(
            spec.tools
                .iter()
                .map(|t| format!("mcp__{MCP_NAME}__{t}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    a.push("--mcp-config".into());
    a.push(mcp_config.display().to_string());
    a.push("--strict-mcp-config".into());
    a.push("--max-turns".into());
    a.push(spec.max_turns.max(1).to_string());
    if let Some(m) = &spec.model {
        a.push("--model".into());
        a.push(m.clone());
    }
    if system_flag && !spec.system.trim().is_empty() {
        a.push("--append-system-prompt".into());
        a.push(spec.system.clone());
    }
    a
}

pub fn codex_args(spec: &RunSpec, workspace: &Path, exe: &str, mcp: &[String]) -> Vec<String> {
    use crate::mcp::setup::toml_string;
    let mut a: Vec<String> = vec![
        "exec".into(),
        "--json".into(),
        "--skip-git-repo-check".into(),
        "--sandbox".into(),
        "read-only".into(),
        "--cd".into(),
        workspace.display().to_string(),
        "-c".into(),
        format!("mcp_servers.{MCP_NAME}.command={}", toml_string(exe)),
        "-c".into(),
        format!(
            "mcp_servers.{MCP_NAME}.args=[{}]",
            mcp.iter().map(|s| toml_string(s)).collect::<Vec<_>>().join(", ")
        ),
    ];
    if let Some(m) = &spec.model {
        a.push("--model".into());
        a.push(m.clone());
    }
    a.push("-".into());
    a
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RunOutcome {
    pub text: String,
    pub is_error: bool,
    pub tools_called: u32,
}

/// 執行一輪：寫 MCP 設定、起子行程、餵 prompt、逐行解析事件。
pub async fn run(
    spec: &RunSpec,
    bin: &Bin,
    config_dir: &Path,
    mut on_event: impl FnMut(&AiEvent),
) -> AppResult<RunOutcome> {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "asa".into());
    let margs = mcp_args(config_dir, &spec.tools);
    let tmp = config_dir.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    let mcp_file = tmp.join(format!("mcp-{}.json", uuid::Uuid::new_v4().simple()));
    let workspace = config_dir.join("ai-workspace");
    let (args, prompt) = match spec.provider {
        Provider::Claude => {
            let cfg = serde_json::json!({ "mcpServers": { MCP_NAME: { "command": exe, "args": margs } } });
            crate::store::write_bytes_atomic(&mcp_file, serde_json::to_string(&cfg)?.as_bytes())?;
            let prompt = if bin.via_cmd && !spec.system.trim().is_empty() {
                format!("{}\n\n---\n\n{}", spec.system.trim(), spec.prompt)
            } else {
                spec.prompt.clone()
            };
            (claude_args(spec, &mcp_file, !bin.via_cmd), prompt)
        }
        Provider::Codex => {
            std::fs::create_dir_all(&workspace)?;
            // Codex 沒有 --append-system-prompt：系統指示放在提示最前面
            let prompt = if spec.system.trim().is_empty() {
                spec.prompt.clone()
            } else {
                format!("{}\n\n---\n\n{}", spec.system.trim(), spec.prompt)
            };
            (codex_args(spec, &workspace, &exe, &margs), prompt)
        }
    };
    let mut cmd = if bin.via_cmd {
        let mut c = tokio::process::Command::new("cmd");
        c.arg("/C").arg(&bin.path);
        c
    } else {
        tokio::process::Command::new(&bin.path)
    };
    cmd.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    proc::prepare(&mut cmd);
    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::Ai(tf!("無法啟動 {cli}：{e}", cli = spec.provider.label(), e = e)))?;
    let job = proc::Job::new();
    if let Some(j) = &job {
        j.assign(&child);
    }
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let stdout = child.stdout.take().ok_or_else(|| AppError::Ai("no stdout".into()))?;
    let mut stderr = child.stderr.take().ok_or_else(|| AppError::Ai("no stderr".into()))?;
    let err_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).to_string()
    });

    let mut out = RunOutcome::default();
    let mut done = false;
    let mut streamed = false;
    let mut cx = events::CodexState::default();
    let mut lines = BufReader::new(stdout).lines();
    let read = async {
        while let Some(line) = lines.next_line().await? {
            let evs = match spec.provider {
                Provider::Claude => events::claude_events(&line, &mut streamed),
                Provider::Codex => events::codex_events(&line, &mut cx, started.elapsed().as_millis() as u64),
            };
            for e in evs {
                match &e {
                    AiEvent::Text { text } => out.text.push_str(text),
                    AiEvent::Tool { .. } => out.tools_called += 1,
                    AiEvent::Done { text, is_error, .. } => {
                        done = true;
                        out.is_error = *is_error;
                        if out.text.trim().is_empty() {
                            out.text = text.clone().unwrap_or_default();
                        }
                    }
                    _ => {}
                }
                on_event(&e);
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let timed_out = tokio::time::timeout(spec.timeout, read).await.is_err();
    if timed_out {
        if let Some(j) = &job {
            j.kill();
        }
        let _ = child.start_kill();
    }
    let status = child.wait().await.ok();
    let stderr_text = err_task.await.unwrap_or_default();
    let _ = std::fs::remove_file(&mcp_file);
    drop(job);
    if timed_out {
        return Err(AppError::Timeout(spec.timeout.as_secs()));
    }
    if !done && !status.map(|s| s.success()).unwrap_or(false) {
        let tail: String = stderr_text
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(AppError::Ai(tf!(
            "{cli} 執行失敗：{detail}",
            cli = spec.provider.label(),
            detail = crate::util::text::clip(&tail, 600)
        )));
    }
    Ok(out)
}

/// 系統提示與分析範本（內嵌）。
pub mod prompts {
    pub const ASK_SYSTEM: &str = include_str!("../../prompts/ask_system.md");
    pub const ANALYZE_REPORT: &str = include_str!("../../prompts/analyze_report.md");
    pub const ANALYZE_TRAFFIC: &str = include_str!("../../prompts/analyze_traffic.md");
    pub const ANALYZE_EVENTS: &str = include_str!("../../prompts/analyze_events.md");

    /// 範本裡的 `{{LANG}}` 換成回答語言。
    pub fn render(tpl: &str) -> String {
        let lang = match crate::i18n::current() {
            crate::i18n::Lang::En => "English",
            crate::i18n::Lang::ZhTw => "Traditional Chinese (繁體中文, Taiwan usage)",
        };
        tpl.replace("{{LANG}}", lang)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(p: Provider) -> RunSpec {
        RunSpec {
            provider: p,
            prompt: "hi".into(),
            system: "be careful".into(),
            tools: vec!["lookup_ip".into(), "list_connections".into()],
            model: Some("m1".into()),
            max_turns: 6,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn claude_args_lock_down_tools() {
        let a = claude_args(&spec(Provider::Claude), Path::new("/tmp/mcp.json"), true);
        let s = a.join(" ");
        assert!(s.contains("--permission-mode dontAsk"));
        assert!(s.contains("--allowedTools mcp__asa__lookup_ip,mcp__asa__list_connections"));
        assert!(s.contains("--strict-mcp-config") && s.contains("--max-turns 6") && s.contains("--model m1"));
        assert_eq!(a.last().unwrap(), "be careful");
        assert!(!claude_args(&spec(Provider::Claude), Path::new("x"), false)
            .iter()
            .any(|x| x == "--append-system-prompt"));
    }

    #[test]
    fn codex_args_inline_mcp_and_read_only_sandbox() {
        let m = mcp_args(Path::new("C:\\cfg"), &["lookup_ip".into()]);
        assert_eq!(&m[4..], &["mcp".to_string(), "--tools".into(), "lookup_ip".into()]);
        let a = codex_args(&spec(Provider::Codex), Path::new("C:\\ws"), "C:\\asa.exe", &m);
        let s = a.join(" ");
        assert!(s.contains("--sandbox read-only"));
        assert!(s.contains("mcp_servers.asa.command='C:\\asa.exe'"));
        assert!(s.contains("mcp_servers.asa.args=['--config-dir', 'C:\\cfg'"));
        assert_eq!(a.last().unwrap(), "-");
        assert_eq!(mcp_args(Path::new("x"), &[]).last().unwrap(), "none");
    }

    #[test]
    fn prompts_render_language() {
        assert!(!prompts::render(prompts::ASK_SYSTEM).contains("{{LANG}}"));
        assert!(prompts::ANALYZE_EVENTS.len() > 100);
    }
}
