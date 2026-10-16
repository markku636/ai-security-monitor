//! 把 `claude -p --output-format stream-json` 與 `codex exec --json` 的 JSONL 轉成共同事件（照 db-kit agent.rs 的對應）。

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AiEvent {
    Init {
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
    /// 回答文字（Claude 是逐字增量；Codex 是整段）
    Text {
        text: String,
    },
    Tool {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        input: Option<String>,
    },
    ToolResult {
        ok: bool,
        preview: String,
    },
    Done {
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        is_error: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
    Error {
        message: String,
    },
}

fn preview(s: &str) -> String {
    crate::util::text::clip(&s.split_whitespace().collect::<Vec<_>>().join(" "), 200)
}

/// `mcp__asa__lookup_ip` → `lookup_ip`
pub fn strip_mcp_prefix(name: &str) -> String {
    name.strip_prefix("mcp__")
        .and_then(|r| r.split_once("__").map(|(_, t)| t))
        .unwrap_or(name)
        .to_string()
}

fn input_display(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) if m.is_empty() => None,
        Value::Null => None,
        other => Some(crate::util::text::clip(&other.to_string(), 160)),
    }
}

fn blocks(v: &Value) -> Vec<&Value> {
    v.get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn tool_result_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Claude 的一行；`streamed` 記錄是否已收過增量文字（避免最後的完整訊息重複輸出）。
pub fn claude_events(line: &str, streamed: &mut bool) -> Vec<AiEvent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return out;
    };
    match v.get("type").and_then(Value::as_str) {
        Some("system") if v.get("subtype").and_then(Value::as_str) == Some("init") => {
            out.push(AiEvent::Init {
                model: v.get("model").and_then(Value::as_str).map(String::from),
            });
        }
        Some("stream_event") => {
            let e = &v["event"];
            if e["type"] == "content_block_delta" && e["delta"]["type"] == "text_delta" {
                if let Some(t) = e["delta"]["text"].as_str() {
                    *streamed = true;
                    out.push(AiEvent::Text { text: t.to_string() });
                }
            }
        }
        Some("assistant") => {
            for b in blocks(&v) {
                match b.get("type").and_then(Value::as_str) {
                    Some("tool_use") => out.push(AiEvent::Tool {
                        name: strip_mcp_prefix(b["name"].as_str().unwrap_or("tool")),
                        input: b.get("input").and_then(input_display),
                    }),
                    // 沒有增量串流時（舊版 CLI）才用完整文字
                    Some("text") if !*streamed => {
                        if let Some(t) = b["text"].as_str() {
                            out.push(AiEvent::Text { text: t.to_string() });
                        }
                    }
                    _ => {}
                }
            }
        }
        Some("user") => {
            for b in blocks(&v) {
                if b.get("type").and_then(Value::as_str) == Some("tool_result") {
                    out.push(AiEvent::ToolResult {
                        ok: !b.get("is_error").and_then(Value::as_bool).unwrap_or(false),
                        preview: preview(&tool_result_text(b.get("content"))),
                    });
                }
            }
        }
        Some("result") => out.push(AiEvent::Done {
            text: v.get("result").and_then(Value::as_str).map(String::from),
            is_error: v.get("is_error").and_then(Value::as_bool).unwrap_or(false),
            duration_ms: v.get("duration_ms").and_then(Value::as_u64),
            cost_usd: v.get("total_cost_usd").and_then(Value::as_f64),
        }),
        _ => {}
    }
    out
}

#[derive(Debug, Default)]
pub struct CodexState {
    pub last_text: Option<String>,
}

/// Codex 的一行（thread.started／item.*／turn.completed／turn.failed／error）。
pub fn codex_events(line: &str, st: &mut CodexState, elapsed_ms: u64) -> Vec<AiEvent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return out;
    };
    let item = &v["item"];
    let tool_name = || {
        item.get("tool")
            .or_else(|| item.get("name"))
            .and_then(Value::as_str)
            .map(strip_mcp_prefix)
            .unwrap_or_else(|| "mcp".into())
    };
    match v.get("type").and_then(Value::as_str) {
        Some("thread.started") => out.push(AiEvent::Init { model: None }),
        Some("item.started") if item["type"] == "mcp_tool_call" => out.push(AiEvent::Tool {
            name: tool_name(),
            input: item.get("arguments").and_then(input_display),
        }),
        Some("item.completed") => match item["type"].as_str() {
            Some("agent_message") => {
                if let Some(t) = item["text"].as_str().filter(|t| !t.is_empty()) {
                    st.last_text = Some(t.to_string());
                    out.push(AiEvent::Text { text: t.to_string() });
                }
            }
            Some("mcp_tool_call") => {
                let err = item
                    .get("error")
                    .filter(|e| !e.is_null())
                    .map(|e| e.as_str().map(String::from).unwrap_or_else(|| e.to_string()));
                let text = match (&err, item.get("result")) {
                    (Some(e), _) => e.clone(),
                    (None, Some(r)) => tool_result_text(r.get("content").or(Some(r))),
                    _ => String::new(),
                };
                out.push(AiEvent::ToolResult {
                    ok: err.is_none() && item["status"] != "failed",
                    preview: preview(&text),
                });
            }
            _ => {}
        },
        Some(k @ ("turn.completed" | "turn.failed")) => {
            let failed = k == "turn.failed";
            out.push(AiEvent::Done {
                text: if failed {
                    v["error"]["message"]
                        .as_str()
                        .or(v["message"].as_str())
                        .map(String::from)
                } else {
                    st.last_text.clone()
                },
                is_error: failed,
                duration_ms: Some(elapsed_ms),
                cost_usd: None,
            });
        }
        Some("error") => out.push(AiEvent::Error {
            message: v["message"].as_str().unwrap_or("").to_string(),
        }),
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_stream_json() {
        let mut streamed = false;
        assert_eq!(
            claude_events(
                r#"{"type":"system","subtype":"init","model":"claude-opus-5-5","session_id":"s"}"#,
                &mut streamed
            ),
            vec![AiEvent::Init {
                model: Some("claude-opus-5-5".into())
            }]
        );
        let d = claude_events(
            r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"你好"}}}"#,
            &mut streamed,
        );
        assert_eq!(d, vec![AiEvent::Text { text: "你好".into() }]);
        let a = claude_events(
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"你好"},{"type":"tool_use","id":"t1","name":"mcp__asa__lookup_ip","input":{"indicator":"1.2.3.4"}}]}}"#,
            &mut streamed,
        );
        assert_eq!(
            a,
            vec![AiEvent::Tool {
                name: "lookup_ip".into(),
                input: Some(r#"{"indicator":"1.2.3.4"}"#.into())
            }]
        );
        let r = claude_events(
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"{\n \"verdict\": \"safe\"\n}"}],"is_error":false}]}}"#,
            &mut streamed,
        );
        assert_eq!(
            r,
            vec![AiEvent::ToolResult {
                ok: true,
                preview: "{ \"verdict\": \"safe\" }".into()
            }]
        );
        let done = claude_events(
            r#"{"type":"result","subtype":"success","is_error":false,"result":"OK","duration_ms":1200,"total_cost_usd":0.01}"#,
            &mut streamed,
        );
        assert!(matches!(
            &done[0],
            AiEvent::Done {
                is_error: false,
                duration_ms: Some(1200),
                ..
            }
        ));
        assert!(claude_events("not json", &mut streamed).is_empty());
    }

    #[test]
    fn claude_without_partial_messages_uses_full_text() {
        let mut streamed = false;
        let a = claude_events(
            r#"{"type":"assistant","message":{"content":[{"type":"text","text":"整段"}]}}"#,
            &mut streamed,
        );
        assert_eq!(a, vec![AiEvent::Text { text: "整段".into() }]);
    }

    #[test]
    fn codex_jsonl() {
        let mut st = CodexState::default();
        assert_eq!(
            codex_events(r#"{"type":"thread.started","thread_id":"x"}"#, &mut st, 0),
            vec![AiEvent::Init { model: None }]
        );
        let t = codex_events(
            r#"{"type":"item.started","item":{"id":"1","type":"mcp_tool_call","server":"asa","tool":"list_connections","arguments":{"verdict":["dangerous"]},"status":"in_progress"}}"#,
            &mut st,
            0,
        );
        assert!(matches!(&t[0], AiEvent::Tool { name, .. } if name == "list_connections"));
        let r = codex_events(
            r#"{"type":"item.completed","item":{"id":"1","type":"mcp_tool_call","tool":"list_connections","result":{"content":[{"type":"text","text":"{}"}]},"status":"completed"}}"#,
            &mut st,
            0,
        );
        assert_eq!(
            r,
            vec![AiEvent::ToolResult {
                ok: true,
                preview: "{}".into()
            }]
        );
        let m = codex_events(
            r#"{"type":"item.completed","item":{"id":"2","type":"agent_message","text":"沒有危險連線。"}}"#,
            &mut st,
            0,
        );
        assert_eq!(
            m,
            vec![AiEvent::Text {
                text: "沒有危險連線。".into()
            }]
        );
        let d = codex_events(r#"{"type":"turn.completed","usage":{}}"#, &mut st, 900);
        assert_eq!(
            d,
            vec![AiEvent::Done {
                text: Some("沒有危險連線。".into()),
                is_error: false,
                duration_ms: Some(900),
                cost_usd: None
            }]
        );
        let f = codex_events(r#"{"type":"turn.failed","error":{"message":"quota"}}"#, &mut st, 1);
        assert!(matches!(&f[0], AiEvent::Done { is_error: true, text: Some(t), .. } if t == "quota"));
    }
}
