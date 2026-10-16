//! `asa mcp`：把這台機器的資安狀態以 MCP 工具提供給 Claude Code／Codex／Cursor／VS Code 等 AI 用戶端。
//! 協定照 db-kit 手刻（JSON-RPC 2.0；initialize／ping／tools/list／tools/call），stdio 與 Streamable HTTP 兩種傳輸。
//!
//! 行為：
//! - stdio 模式 stdout **只**走協定，診斷一律 stderr。
//! - 工具失敗回 `isError: true` 的結果（讓模型看到錯誤文字自己修正），不是 JSON-RPC 錯誤。
//! - 預設唯讀。防禦動作要伺服器啟動時 `--allow-actions`（破壞性再加 `--allow-destructive`）；
//!   一律 preview_action → 使用者同意 → execute_action（審查代碼單次有效、15 分鐘），模型改不了這些旗標。

pub mod http;
pub mod setup;
pub mod tools;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::actions::review::PendingStore;
use crate::error::AppResult;
use tools::ToolCtx;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
pub const SERVER_NAME: &str = "asa";

pub struct ServeOpts {
    pub tools: Vec<String>,
    pub allow_actions: bool,
    pub allow_destructive: bool,
}

pub struct McpServer {
    ctx: ToolCtx,
    allow: Option<Vec<String>>,
    allow_actions: bool,
}

impl McpServer {
    pub fn new(config_dir: std::path::PathBuf, o: &ServeOpts) -> Self {
        let tools: Vec<String> = o
            .tools
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            ctx: ToolCtx {
                config_dir,
                allow_destructive: o.allow_destructive,
                pending: PendingStore::new(),
                intel: tokio::sync::OnceCell::new(),
            },
            allow: (!tools.is_empty()).then_some(tools),
            allow_actions: o.allow_actions,
        }
    }

    fn allows(&self, name: &str) -> bool {
        self.allow.as_ref().is_none_or(|a| a.iter().any(|n| n == name))
    }

    pub fn tool_defs(&self) -> Vec<tools::ToolDef> {
        let mut defs = tools::read_only_defs();
        if self.allow_actions {
            defs.extend(tools::action_defs());
        }
        defs.into_iter().filter(|d| self.allows(d.name)).collect()
    }

    fn instructions(&self) -> String {
        let mut p = vec![t!(
            "這些工具唯讀地檢查使用者這台電腦的資安狀態（連線、威脅情資、防火牆、port、流量、事件與當機）。\
引用情資命中時一律附上來源廠商與 source_url；不確定就說不確定，不要臆測。"
        )];
        if self.allow_actions {
            p.push(t!(
                "要封鎖 IP 或關閉 port 時，先呼叫 preview_action，把計畫完整給使用者看並取得明確同意後，才以 review_token 呼叫 execute_action。"
            ));
        }
        p.join("\n")
    }

    async fn call_tool(&self, name: &str, args: &Value) -> Result<String, String> {
        let known = tools::READ_ONLY.contains(&name) || tools::ACTION_TOOLS.contains(&name);
        if !known {
            return Err(tf!("未知的工具：{name}", name = name));
        }
        if tools::ACTION_TOOLS.contains(&name) && !self.allow_actions {
            return Err(t!("這個 MCP 伺服器沒有開放防禦動作（啟動時要加 --allow-actions）").to_string());
        }
        if !self.allows(name) {
            return Err(tf!("這個 MCP 伺服器沒有開放 {name}（--tools 限制）", name = name));
        }
        tools::call(&self.ctx, name, args).await
    }

    pub async fn handle_line(&self, line: &str) -> Option<Value> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => self.handle_value(v).await,
            Err(_) => Some(rpc_err(&Value::Null, -32700, "Parse error")),
        }
    }

    pub async fn handle_value(&self, v: Value) -> Option<Value> {
        match v {
            Value::Array(batch) => {
                let mut out = Vec::new();
                for req in &batch {
                    if let Some(r) = self.handle_request(req).await {
                        out.push(r);
                    }
                }
                (!out.is_empty()).then_some(Value::Array(out))
            }
            other => self.handle_request(&other).await,
        }
    }

    pub async fn handle_request(&self, req: &Value) -> Option<Value> {
        let method = req.get("method").and_then(Value::as_str)?;
        let id = req.get("id").cloned().filter(|i| !i.is_null())?;
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => {
                let asked = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSION);
                let ver = if SUPPORTED_VERSIONS.contains(&asked) {
                    asked
                } else {
                    PROTOCOL_VERSION
                };
                Ok(json!({
                    "protocolVersion": ver,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": SERVER_NAME, "version": crate::VERSION },
                    "instructions": self.instructions(),
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({
                "tools": self.tool_defs().into_iter().map(|d| json!({
                    "name": d.name,
                    "description": d.description,
                    "inputSchema": d.input_schema,
                    "annotations": { "readOnlyHint": !tools::ACTION_TOOLS.contains(&d.name) },
                })).collect::<Vec<_>>(),
            })),
            "tools/call" => {
                let Some(name) = params.get("name").and_then(Value::as_str) else {
                    return Some(rpc_err(&id, -32602, "Missing params.name"));
                };
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                Ok(match self.call_tool(name, &args).await {
                    Ok(text) => tool_result(&text, false),
                    Err(e) => tool_result(&e, true),
                })
            }
            "resources/list" => Ok(json!({ "resources": [] })),
            "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            other => Err((-32601, format!("Method not found: {other}"))),
        };
        Some(match result {
            Ok(r) => rpc_ok(&id, r),
            Err((code, msg)) => rpc_err(&id, code, &msg),
        })
    }
}

fn tool_result(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

pub fn rpc_ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

pub fn rpc_err(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// stdio 主迴圈：一行一則 JSON-RPC；stdin 結束就離開。
pub async fn serve_stdio(server: McpServer) -> AppResult<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if let Some(resp) = server.handle_line(&line).await {
            let mut bytes = serde_json::to_vec(&resp)?;
            bytes.push(b'\n');
            out.write_all(&bytes).await?;
            out.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(actions: bool, tools: &[&str]) -> McpServer {
        McpServer::new(
            tempfile::tempdir().unwrap().keep(),
            &ServeOpts {
                tools: tools.iter().map(|s| s.to_string()).collect(),
                allow_actions: actions,
                allow_destructive: false,
            },
        )
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn initialize_list_and_notifications() {
        let s = server(false, &[]);
        let rt = rt();
        let init = rt
            .block_on(s.handle_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            ))
            .unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["result"]["serverInfo"]["name"], "asa");
        assert!(rt
            .block_on(s.handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#))
            .is_none());
        let list = rt
            .block_on(s.handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#))
            .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), tools::READ_ONLY.len());
        assert!(!names.contains(&"execute_action"));
        let bad = rt.block_on(s.handle_line("{nope")).unwrap();
        assert_eq!(bad["error"]["code"], -32700);
        let missing = rt
            .block_on(s.handle_line(r#"{"jsonrpc":"2.0","id":3,"method":"nope"}"#))
            .unwrap();
        assert_eq!(missing["error"]["code"], -32601);
    }

    #[test]
    fn actions_and_allowlist_are_server_side() {
        let rt = rt();
        let ro = server(false, &[]);
        let r = rt
            .block_on(ro.handle_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_action","arguments":{"review_token":"x"}}}"#,
            ))
            .unwrap();
        assert_eq!(r["result"]["isError"], true);
        let limited = server(true, &["explain_code"]);
        let names: Vec<String> = limited.tool_defs().iter().map(|d| d.name.to_string()).collect();
        assert_eq!(names, vec!["explain_code".to_string()]);
        let r = rt
            .block_on(limited.handle_line(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"doctor","arguments":{}}}"#,
            ))
            .unwrap();
        assert_eq!(r["result"]["isError"], true);
        let ok = rt
            .block_on(limited.handle_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"explain_code","arguments":{"code":"0x124"}}}"#,
            ))
            .unwrap();
        assert_eq!(ok["result"]["isError"], false);
        assert!(ok["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("WHEA_UNCORRECTABLE_ERROR"));
        let all = server(true, &[]);
        assert_eq!(
            all.tool_defs().len(),
            tools::READ_ONLY.len() + tools::ACTION_TOOLS.len()
        );
    }

    #[test]
    fn preview_then_execute_needs_a_valid_token() {
        let rt = rt();
        let s = server(true, &[]);
        let prev = rt
            .block_on(s.handle_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"preview_action","arguments":{"kind":"block_ip","ip":"198.51.100.77","reason":"test"}}}"#,
            ))
            .unwrap();
        assert_eq!(prev["result"]["isError"], false, "{prev}");
        let text = prev["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["review_token"].as_str().unwrap().len(), 12);
        // 破壞性動作沒開 --allow-destructive
        let close = rt
            .block_on(s.handle_line(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"preview_action","arguments":{"kind":"close_port","proto":"tcp","port":6379}}}"#,
            ))
            .unwrap();
        assert_eq!(close["result"]["isError"], true);
        let bad = rt
            .block_on(s.handle_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_action","arguments":{"review_token":"nope"}}}"#,
            ))
            .unwrap();
        assert_eq!(bad["result"]["isError"], true);
        let loopback = rt
            .block_on(s.handle_line(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"preview_action","arguments":{"kind":"block_ip","ip":"127.0.0.1"}}}"#,
            ))
            .unwrap();
        assert_eq!(loopback["result"]["isError"], true);
    }
}
