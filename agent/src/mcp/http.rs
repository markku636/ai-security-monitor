//! `ai-security-monitor mcp --http ADDR`：MCP Streamable HTTP 傳輸（手寫 HTTP/1.1，一個請求一條連線）。
//! - 只收 POST `/mcp`；`initialize` 回 `Mcp-Session-Id`；純通知回 202；`Accept` 只要 SSE 時包成單一事件。
//! - 沒有設 token：只能綁 loopback，且 Host／Origin 都必須是本機（擋 DNS rebinding）。
//! - 有 token：`Authorization: Bearer <token>`（常數時間比對）；瀏覽器跨站送不出這個標頭（會先 preflight，我們不回 CORS）。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::McpServer;
use crate::error::{AppError, AppResult};

pub const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_HEAD: usize = 16 * 1024;
const MAX_SESSIONS: usize = 1024;

pub struct HttpState {
    pub server: McpServer,
    pub token: Option<String>,
    sessions: Mutex<VecDeque<String>>,
}

impl HttpState {
    pub fn new(server: McpServer, token: Option<String>) -> Self {
        Self {
            server,
            token: token.filter(|t| !t.is_empty()),
            sessions: Mutex::new(VecDeque::new()),
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_loopback_host(h: &str) -> bool {
    let host = h.trim().trim_start_matches("http://").trim_start_matches("https://");
    let host = host.split('/').next().unwrap_or(host);
    let name = if host.starts_with('[') {
        host.split(']').next().unwrap_or(host).trim_start_matches('[')
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1")
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

fn resp(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    }
}

/// 純邏輯：一個已讀好的請求 → 回應（方便單元測試）。
pub async fn handle(state: &HttpState, req: Request) -> Response {
    if req.path.split('?').next() != Some("/mcp") {
        return resp(404, r#"{"error":"not_found"}"#);
    }
    match &state.token {
        Some(t) => {
            let given = req
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("")
                .trim();
            if !ct_eq(given.as_bytes(), t.as_bytes()) {
                return resp(401, r#"{"error":"unauthorized"}"#);
            }
        }
        None => {
            if !req.header("host").map(is_loopback_host).unwrap_or(false) {
                return resp(403, r#"{"error":"host_not_allowed"}"#);
            }
            if let Some(o) = req.header("origin") {
                if !is_loopback_host(o) {
                    return resp(403, r#"{"error":"origin_not_allowed"}"#);
                }
            }
        }
    }
    match req.method.as_str() {
        "POST" => {}
        "DELETE" => {
            if let Some(sid) = req.header("mcp-session-id") {
                state
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|s| s != sid);
            }
            return resp(200, "{}");
        }
        _ => {
            let mut r = resp(405, r#"{"error":"method_not_allowed"}"#);
            r.headers.push(("allow".into(), "POST, DELETE".into()));
            return r;
        }
    }
    let v: Value = match serde_json::from_slice(&req.body) {
        Ok(v) => v,
        Err(_) => return resp(400, &super::rpc_err(&Value::Null, -32700, "Parse error").to_string()),
    };
    let is_init = v.get("method").and_then(Value::as_str) == Some("initialize");
    if !is_init {
        if let Some(sid) = req.header("mcp-session-id") {
            if !state
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|s| s == sid)
            {
                return resp(404, r#"{"error":"unknown_session"}"#);
            }
        }
    }
    let Some(out) = state.server.handle_value(v).await else {
        return Response {
            status: 202,
            headers: Vec::new(),
            body: Vec::new(),
        };
    };
    let json = out.to_string();
    let accept = req.header("accept").unwrap_or("").to_ascii_lowercase();
    let sse_only = accept.contains("text/event-stream") && !accept.contains("application/json");
    let mut r = if sse_only {
        Response {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("cache-control".into(), "no-store".into()),
            ],
            body: format!("event: message\ndata: {json}\n\n").into_bytes(),
        }
    } else {
        resp(200, &json)
    };
    if is_init {
        let sid = uuid::Uuid::new_v4().simple().to_string();
        let mut s = state.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if s.len() >= MAX_SESSIONS {
            s.pop_front();
        }
        s.push_back(sid.clone());
        r.headers.push(("mcp-session-id".into(), sid));
    }
    r
}

async fn read_request(sock: &mut TcpStream) -> Result<Request, u16> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let n = sock.read(&mut tmp).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(400);
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = sock.read(&mut tmp).await.map_err(|_| 400u16)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > MAX_BODY {
            return Err(413);
        }
    }
    body.truncate(len);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

async fn write_response(sock: &mut TcpStream, r: Response) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        r.status,
        reason(r.status),
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(&r.body).await;
    let _ = sock.shutdown().await;
}

pub async fn serve(state: Arc<HttpState>, addr: SocketAddr) -> AppResult<()> {
    if state.token.is_none() && !addr.ip().is_loopback() {
        return Err(AppError::InvalidArg(
            t!("沒有設定 token 時 MCP HTTP 只能綁 127.0.0.1／::1（用 --token 或 AI_SECURITY_MONITOR_MCP_TOKEN）")
                .into(),
        ));
    }
    let listener = TcpListener::bind(addr).await?;
    eprintln!(
        "{}",
        tf!("MCP HTTP 已啟動：http://{addr}/mcp", addr = listener.local_addr()?)
    );
    loop {
        let (mut sock, _) = listener.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            let r = match read_request(&mut sock).await {
                Ok(req) => handle(&st, req).await,
                Err(code) => resp(code, r#"{"error":"bad_request"}"#),
            };
            write_response(&mut sock, r).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::ServeOpts;

    fn state(token: Option<&str>) -> HttpState {
        let s = McpServer::new(
            tempfile::tempdir().unwrap().keep(),
            &ServeOpts {
                tools: vec![],
                allow_actions: false,
                allow_destructive: false,
            },
        );
        HttpState::new(s, token.map(String::from))
    }

    fn req(method: &str, headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: method.into(),
            path: "/mcp".into(),
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;

    #[test]
    fn loopback_without_token_and_sessions() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let st = state(None);
        let r = rt.block_on(handle(&st, req("POST", &[("Host", "127.0.0.1:7870")], INIT)));
        assert_eq!(r.status, 200);
        let sid = r.headers.iter().find(|(k, _)| k == "mcp-session-id").unwrap().1.clone();
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert_eq!(
            rt.block_on(handle(
                &st,
                req("POST", &[("Host", "localhost:7870"), ("Mcp-Session-Id", &sid)], list)
            ))
            .status,
            200
        );
        assert_eq!(
            rt.block_on(handle(
                &st,
                req("POST", &[("Host", "localhost"), ("Mcp-Session-Id", "nope")], list)
            ))
            .status,
            404
        );
        // DNS rebinding：Host 是別的網域
        assert_eq!(
            rt.block_on(handle(&st, req("POST", &[("Host", "evil.example:7870")], INIT)))
                .status,
            403
        );
        assert_eq!(
            rt.block_on(handle(
                &st,
                req(
                    "POST",
                    &[("Host", "127.0.0.1"), ("Origin", "https://evil.example")],
                    INIT
                )
            ))
            .status,
            403
        );
        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(
            rt.block_on(handle(&st, req("POST", &[("Host", "127.0.0.1")], note)))
                .status,
            202
        );
        assert_eq!(
            rt.block_on(handle(&st, req("GET", &[("Host", "127.0.0.1")], "")))
                .status,
            405
        );
        let sse = rt.block_on(handle(
            &st,
            req("POST", &[("Host", "127.0.0.1"), ("Accept", "text/event-stream")], INIT),
        ));
        assert!(String::from_utf8(sse.body)
            .unwrap()
            .starts_with("event: message\ndata: {"));
    }

    #[test]
    fn bearer_token_required_when_set() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let st = state(Some("s3cret-token"));
        assert_eq!(
            rt.block_on(handle(&st, req("POST", &[("Host", "10.0.0.5")], INIT)))
                .status,
            401
        );
        assert_eq!(
            rt.block_on(handle(&st, req("POST", &[("Authorization", "Bearer wrong")], INIT)))
                .status,
            401
        );
        let ok = rt.block_on(handle(
            &st,
            req(
                "POST",
                &[("Authorization", "Bearer s3cret-token"), ("Host", "10.0.0.5")],
                INIT,
            ),
        ));
        assert_eq!(ok.status, 200);
        assert!(
            is_loopback_host("[::1]:80")
                && is_loopback_host("http://localhost:3000")
                && !is_loopback_host("127.0.0.1.evil.com")
        );
    }
}
