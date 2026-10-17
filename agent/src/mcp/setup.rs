//! 把 `ai-security-monitor mcp` 寫進各 AI 用戶端的設定（照 db-kit mcp_setup）：保留其他設定、先備份 `.bak`、原子寫入。
//! Claude Code（~/.claude.json 或專案 .mcp.json）、Codex（~/.codex/config.toml 區塊取代，不用 toml crate）、
//! Cursor、VS Code（專案 .vscode/mcp.json，key 是 `servers`）、Claude Desktop、Windsurf。
//!
//! 改名相容：伺服器名從 `asa` 改成 `ai-security-monitor`；寫入或移除時都會一併刪掉舊的 `asa` 項目，
//! 免得 AI 用戶端同時掛兩份。

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{LEGACY_SERVER_NAME, SERVER_NAME};
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Client {
    ClaudeCode,
    Codex,
    Cursor,
    Vscode,
    ClaudeDesktop,
    Windsurf,
}

impl Client {
    pub fn label(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::Codex => "Codex CLI",
            Client::Cursor => "Cursor",
            Client::Vscode => "VS Code",
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Windsurf => "Windsurf",
        }
    }
}

/// 設定檔位置；`project` 給了就用專案層級（支援的用戶端）。
pub fn config_path(client: Client, home: &Path, project: Option<&Path>) -> AppResult<PathBuf> {
    Ok(match (client, project) {
        (Client::ClaudeCode, Some(p)) => p.join(".mcp.json"),
        (Client::ClaudeCode, None) => home.join(".claude.json"),
        (Client::Codex, _) => home.join(".codex").join("config.toml"),
        (Client::Cursor, Some(p)) => p.join(".cursor").join("mcp.json"),
        (Client::Cursor, None) => home.join(".cursor").join("mcp.json"),
        (Client::Vscode, Some(p)) => p.join(".vscode").join("mcp.json"),
        (Client::Vscode, None) => {
            return Err(AppError::InvalidArg(
                t!("VS Code 請用 --project <資料夾>（寫進 .vscode/mcp.json）").into(),
            ))
        }
        (Client::ClaudeDesktop, _) => if cfg!(windows) {
            std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData").join("Roaming"))
                .join("Claude")
        } else if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Claude")
        } else {
            home.join(".config/Claude")
        }
        .join("claude_desktop_config.json"),
        (Client::Windsurf, _) => home.join(".codeium").join("windsurf").join("mcp_config.json"),
    })
}

fn servers_key(client: Client) -> &'static str {
    if client == Client::Vscode {
        "servers"
    } else {
        "mcpServers"
    }
}

pub fn server_entry(client: Client, exe: &str, args: &[String]) -> Value {
    let mut v = json!({ "command": exe, "args": args });
    if client == Client::Vscode {
        v["type"] = json!("stdio");
    }
    v
}

/// TOML 字串字面值（能用單引號就用，Windows 路徑最友善）。
pub fn toml_string(s: &str) -> String {
    if !s.contains('\'') && !s.contains('\n') && !s.contains('\r') {
        format!("'{s}'")
    } else {
        let esc = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");
        format!("\"{esc}\"")
    }
}

pub fn codex_block(exe: &str, args: &[String]) -> String {
    let a = args.iter().map(|s| toml_string(s)).collect::<Vec<_>>().join(", ");
    format!(
        "[mcp_servers.{SERVER_NAME}]\ncommand = {}\nargs = [{a}]\n",
        toml_string(exe)
    )
}

/// 在 TOML 文字裡取代（或附加）`[mcp_servers.ai-security-monitor]` 區塊；`block` 為 None 時刪除。
/// 舊的 `[mcp_servers.asa]` 區塊一律刪除。
pub fn replace_toml_block(text: &str, block: Option<&str>) -> String {
    let without_legacy = replace_named_toml_block(text, LEGACY_SERVER_NAME, None);
    replace_named_toml_block(&without_legacy, SERVER_NAME, block)
}

fn replace_named_toml_block(text: &str, name: &str, block: Option<&str>) -> String {
    let header = format!("[mcp_servers.{name}]");
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| l.trim() == header);
    let mut out: Vec<String> = Vec::new();
    match start {
        Some(s) => {
            let end = lines[s + 1..]
                .iter()
                .position(|l| l.trim_start().starts_with('['))
                .map(|i| s + 1 + i)
                .unwrap_or(lines.len());
            out.extend(lines[..s].iter().map(|l| l.to_string()));
            if let Some(b) = block {
                out.extend(b.trim_end().lines().map(String::from));
                if end < lines.len() {
                    out.push(String::new());
                }
            }
            out.extend(lines[end..].iter().map(|l| l.to_string()));
        }
        None => {
            out.extend(lines.iter().map(|l| l.to_string()));
            if let Some(b) = block {
                if out.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                    out.push(String::new());
                }
                out.extend(b.trim_end().lines().map(String::from));
            }
        }
    }
    let mut s = out.join("\n");
    while s.ends_with("\n\n") {
        s.pop();
    }
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// 在 JSON 設定裡設定（或刪除）`<servers_key>.ai-security-monitor`，其他內容原樣保留；舊的 `asa` 項目一律刪除。
pub fn merge_json(text: &str, key: &str, entry: Option<Value>) -> AppResult<String> {
    let mut root: Value = if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(text).map_err(|e| AppError::Config(tf!("設定檔不是合法的 JSON：{e}", e = e)))?
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| AppError::Config(t!("設定檔最外層必須是 JSON 物件").into()))?;
    let servers = obj.entry(key).or_insert_with(|| Value::Object(Map::new()));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| AppError::Config(tf!("{key} 必須是 JSON 物件", key = key)))?;
    servers.remove(LEGACY_SERVER_NAME);
    match entry {
        Some(e) => {
            servers.insert(SERVER_NAME.into(), e);
        }
        None => {
            servers.remove(SERVER_NAME);
        }
    }
    Ok(serde_json::to_string_pretty(&root)? + "\n")
}

/// 寫入（或移除）設定；回傳檔案路徑。寫之前把原檔備份成 `.bak`。
pub fn apply(
    client: Client,
    home: &Path,
    project: Option<&Path>,
    exe: &str,
    args: &[String],
    remove: bool,
) -> AppResult<PathBuf> {
    let path = config_path(client, home, project)?;
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let new = if client == Client::Codex {
        replace_toml_block(&old, (!remove).then(|| codex_block(exe, args)).as_deref())
    } else {
        merge_json(
            &old,
            servers_key(client),
            (!remove).then(|| server_entry(client, exe, args)),
        )?
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if !old.is_empty() {
        std::fs::write(
            path.with_extension(format!(
                "{}.bak",
                path.extension().and_then(|e| e.to_str()).unwrap_or("cfg")
            )),
            &old,
        )?;
    }
    crate::store::write_bytes_atomic(&path, new.as_bytes())?;
    Ok(path)
}

/// 給使用者複製的設定片段＋等效 CLI 指令。
pub fn snippet(client: Client, exe: &str, args: &[String]) -> String {
    let quoted: Vec<String> = std::iter::once(exe.to_string())
        .chain(args.iter().cloned())
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a })
        .collect();
    match client {
        Client::Codex => format!(
            "# ~/.codex/config.toml\n{}\n# {}\ncodex mcp add {SERVER_NAME} -- {}\n",
            codex_block(exe, args),
            t!("或"),
            quoted.join(" ")
        ),
        Client::ClaudeCode => format!(
            "{}\n\n# {}\nclaude mcp add {SERVER_NAME} -- {}\n",
            serde_json::to_string_pretty(&json!({ "mcpServers": { SERVER_NAME: server_entry(client, exe, args) } }))
                .unwrap_or_default(),
            t!("或"),
            quoted.join(" ")
        ),
        other => {
            serde_json::to_string_pretty(
                &json!({ servers_key(other): { SERVER_NAME: server_entry(other, exe, args) } }),
            )
            .unwrap_or_default()
                + "\n"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_merge_keeps_other_settings_and_removes_cleanly() {
        let old = r#"{"theme":"dark","mcpServers":{"other":{"command":"x"}}}"#;
        let new = merge_json(
            old,
            "mcpServers",
            Some(server_entry(
                Client::ClaudeCode,
                "C:\\ai-security-monitor.exe",
                &["mcp".into()],
            )),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&new).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["ai-security-monitor"]["args"][0], "mcp");
        let removed: Value = serde_json::from_str(&merge_json(&new, "mcpServers", None).unwrap()).unwrap();
        assert!(removed["mcpServers"].get("ai-security-monitor").is_none());
        assert!(merge_json("[1]", "mcpServers", None).is_err());
        assert!(merge_json("{not json", "mcpServers", None).is_err());
        let vs: Value = serde_json::from_str(
            &merge_json(
                "",
                "servers",
                Some(server_entry(Client::Vscode, "ai-security-monitor", &[])),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(vs["servers"]["ai-security-monitor"]["type"], "stdio");
    }

    #[test]
    fn install_and_uninstall_drop_the_legacy_asa_entry() {
        let old = r#"{"mcpServers":{"asa":{"command":"C:\\asa.exe","args":["mcp"]},"other":{"command":"x"}}}"#;
        let new: Value = serde_json::from_str(
            &merge_json(
                old,
                "mcpServers",
                Some(server_entry(
                    Client::ClaudeCode,
                    "C:\\ai-security-monitor.exe",
                    &["mcp".into()],
                )),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(new["mcpServers"].get("asa").is_none());
        assert_eq!(new["mcpServers"]["ai-security-monitor"]["args"][0], "mcp");
        assert_eq!(new["mcpServers"]["other"]["command"], "x");
        let un: Value = serde_json::from_str(&merge_json(old, "mcpServers", None).unwrap()).unwrap();
        assert!(un["mcpServers"].get("asa").is_none() && un["mcpServers"].get("other").is_some());

        let toml = "model = 'o4'\n\n[mcp_servers.asa]\ncommand = 'asa'\nargs = ['mcp']\n\n[profiles.x]\nmodel = 'y'\n";
        let added = replace_toml_block(toml, Some(&codex_block("ai-security-monitor", &["mcp".into()])));
        assert!(!added.contains("[mcp_servers.asa]"), "{added}");
        assert!(added.contains("[mcp_servers.ai-security-monitor]") && added.contains("[profiles.x]"));
        let gone = replace_toml_block(toml, None);
        assert!(!gone.contains("mcp_servers") && gone.contains("[profiles.x]") && gone.contains("model = 'o4'"));
    }

    #[test]
    fn toml_block_replace_append_and_remove() {
        let block = codex_block(
            "C:\\Program Files\\ai-security-monitor\\ai-security-monitor.exe",
            &["mcp".into(), "--allow-actions".into()],
        );
        assert!(block.contains("command = 'C:\\Program Files\\ai-security-monitor\\ai-security-monitor.exe'"));
        let base = "model = \"o4\"\n\n[mcp_servers.other]\ncommand = 'x'\n";
        let added = replace_toml_block(base, Some(&block));
        assert!(added.contains("[mcp_servers.other]") && added.contains("[mcp_servers.ai-security-monitor]"));
        let again = replace_toml_block(&added, Some(&codex_block("ai-security-monitor", &["mcp".into()])));
        assert_eq!(again.matches("[mcp_servers.ai-security-monitor]").count(), 1);
        assert!(again.contains("command = 'ai-security-monitor'"));
        // 區塊在中間：取代後後面的表格還在
        let middle = format!("{}\n[profiles.x]\nmodel = 'y'\n", block);
        let replaced = replace_toml_block(&middle, Some(&codex_block("new", &[])));
        assert!(replaced.contains("[profiles.x]") && replaced.contains("command = 'new'"));
        let gone = replace_toml_block(&replaced, None);
        assert!(!gone.contains("mcp_servers.ai-security-monitor") && gone.contains("[profiles.x]"));
        assert_eq!(toml_string("it's"), "\"it's\"");
    }

    #[test]
    fn apply_writes_backup_and_paths() {
        let home = tempfile::tempdir().unwrap();
        let p = apply(
            Client::Codex,
            home.path(),
            None,
            "ai-security-monitor",
            &["mcp".into()],
            false,
        )
        .unwrap();
        assert!(p.ends_with(".codex/config.toml") || p.ends_with(".codex\\config.toml"));
        std::fs::write(&p, "model = 'x'\n").unwrap();
        apply(
            Client::Codex,
            home.path(),
            None,
            "ai-security-monitor",
            &["mcp".into()],
            false,
        )
        .unwrap();
        assert!(std::fs::read_to_string(&p)
            .unwrap()
            .contains("[mcp_servers.ai-security-monitor]"));
        assert!(p.with_extension("toml.bak").exists());
        let proj = tempfile::tempdir().unwrap();
        let mp = apply(
            Client::ClaudeCode,
            home.path(),
            Some(proj.path()),
            "ai-security-monitor",
            &["mcp".into()],
            false,
        )
        .unwrap();
        assert_eq!(mp, proj.path().join(".mcp.json"));
        assert!(config_path(Client::Vscode, home.path(), None).is_err());
        assert!(snippet(Client::ClaudeCode, "ai-security-monitor", &["mcp".into()])
            .contains("claude mcp add ai-security-monitor -- ai-security-monitor mcp"));
    }
}
