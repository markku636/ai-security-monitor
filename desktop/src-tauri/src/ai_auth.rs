//! AI 帳號（桌面版）：這台電腦上的 Claude Code／Codex CLI 有沒有登入；登入＝開新的終端機視窗跑官方登入指令
//! （本機有瀏覽器，授權完成會自動回到 CLI）；登出＝跑 `claude auth logout`／`codex logout`。
//! 注意：這就是使用者平常用的 CLI，登出會連他自己的 Claude Code／Codex 一起登出（前端會先警告）。

use std::process::Command;

use asa_lib::ai::{self, Provider};
use serde_json::{json, Value};

type CmdResult<T> = Result<T, String>;

fn provider(s: &str) -> CmdResult<Provider> {
    match s {
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        _ => Err(format!("不認得的 AI：{s}")),
    }
}

/// 不跳主控台視窗地執行 CLI（.cmd 透過 cmd /C）。
fn cli(bin: &ai::Bin, args: &[&str]) -> Command {
    let mut c = if bin.via_cmd {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(&bin.path);
        c
    } else {
        Command::new(&bin.path)
    };
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

fn env_override(p: Provider) -> Vec<&'static str> {
    let keys: &[&'static str] = match p {
        Provider::Claude => &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"],
        Provider::Codex => &["OPENAI_API_KEY", "CODEX_API_KEY"],
    };
    keys.iter()
        .copied()
        .filter(|k| std::env::var(k).map(|v| !v.trim().is_empty()).unwrap_or(false))
        .collect()
}

fn status_of(p: Provider) -> Value {
    let id = format!("{p:?}").to_lowercase();
    let base = json!({ "id": id, "label": p.label(), "installed": false, "logged_in": false, "env_override": env_override(p) });
    let Some(bin) = ai::resolve_bin(p) else {
        return base;
    };
    match p {
        Provider::Claude => {
            let out = cli(&bin, &["auth", "status", "--json"]).output();
            let parsed = out.ok().and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).to_string();
                s.find('{').and_then(|i| serde_json::from_str::<Value>(&s[i..]).ok())
            });
            let j = parsed.unwrap_or(Value::Null);
            json!({
                "id": id,
                "label": p.label(),
                "installed": true,
                "logged_in": j["loggedIn"].as_bool().unwrap_or(false),
                "method": j["authMethod"],
                "email": j["email"],
                "plan": j["subscriptionType"],
                "env_override": env_override(p),
            })
        }
        Provider::Codex => {
            let out = cli(&bin, &["login", "status"]).output();
            let (ok, text) = match out {
                Ok(o) => (
                    o.status.success(),
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                ),
                Err(_) => (false, String::new()),
            };
            let lower = text.to_ascii_lowercase();
            let logged = ok && lower.contains("logged in") && !lower.contains("not logged in");
            json!({
                "id": id,
                "label": p.label(),
                "installed": true,
                "logged_in": logged,
                "method": if !logged { Value::Null } else if lower.contains("api key") { json!("api_key") } else { json!("chatgpt") },
                "env_override": env_override(p),
            })
        }
    }
}

#[tauri::command]
pub async fn ai_auth_status() -> CmdResult<Value> {
    let list = tokio::task::spawn_blocking(|| [Provider::Claude, Provider::Codex].map(status_of).to_vec())
        .await
        .map_err(|e| e.to_string())?;
    Ok(json!({ "providers": list }))
}

/// 開一個新的終端機視窗跑官方登入指令（使用者在那個視窗完成；前端每幾秒重新查狀態）。
#[tauri::command]
pub fn ai_login(provider_id: String) -> CmdResult<()> {
    let p = provider(&provider_id)?;
    if ai::resolve_bin(p).is_none() {
        return Err(format!("這台電腦沒有安裝 {}", p.label()));
    }
    let args: &[&str] = match p {
        Provider::Claude => &["claude", "auth", "login"],
        Provider::Codex => &["codex", "login"],
    };
    #[cfg(windows)]
    let r = Command::new("cmd")
        .args(["/C", "start", "", "cmd", "/K"])
        .args(args)
        .spawn();
    #[cfg(target_os = "macos")]
    let r = Command::new("osascript")
        .args([
            "-e",
            &format!("tell application \"Terminal\" to do script \"{}\"", args.join(" ")),
            "-e",
            "tell application \"Terminal\" to activate",
        ])
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = Command::new("x-terminal-emulator")
        .arg("-e")
        .args(args)
        .spawn()
        .or_else(|_| Command::new("gnome-terminal").arg("--").args(args).spawn());
    r.map(|_| ())
        .map_err(|e| format!("開不了終端機：{e}（請自己開終端機執行 {}）", args.join(" ")))
}

#[tauri::command]
pub async fn ai_logout(provider_id: String) -> CmdResult<Value> {
    let p = provider(&provider_id)?;
    let bin = ai::resolve_bin(p).ok_or_else(|| format!("這台電腦沒有安裝 {}", p.label()))?;
    let args: &[&str] = match p {
        Provider::Claude => &["auth", "logout"],
        Provider::Codex => &["logout"],
    };
    let out = tokio::task::spawn_blocking(move || cli(&bin, args).output())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if msg.is_empty() { "登出失敗".into() } else { msg });
    }
    tokio::task::spawn_blocking(move || status_of(p))
        .await
        .map_err(|e| e.to_string())
}
