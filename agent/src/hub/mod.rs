//! Hub 客戶端：註冊、上傳報告（gzip）、連線快照、心跳；失敗的上傳存進 outbox 下次重送。

pub mod contract;
pub mod outbox;
pub mod watch;

use std::io::Write;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::model::report::{AgentInfo, Report};
use contract::{HeartbeatPayload, RegisterPayload, RegisterResponse, SnapshotPayload};

/// 超過這個大小就 gzip。
const GZIP_OVER: usize = 16 * 1024;
pub const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;

/// 驗證 hub 網址：https；http 只允許 loopback / 私網（除非明確 `allow_insecure`）。
pub fn validate_url(url: &str, allow_insecure: bool) -> AppResult<String> {
    let u = url.trim().trim_end_matches('/').to_string();
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Ok(u);
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let local = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| !crate::util::net::classify(ip).is_public())
                .unwrap_or(false);
        if local || allow_insecure {
            return Ok(u);
        }
        return Err(AppError::InvalidArg(tf!(
            "Hub 網址必須是 https（http 只允許本機或私網；確定要用請加 --insecure-http）：{url}",
            url = url
        )));
    }
    Err(AppError::InvalidArg(tf!("Hub 網址格式錯誤：{url}", url = url)))
}

pub struct HubClient {
    base: String,
    key: String,
    agent_id: String,
    http: reqwest::Client,
}

#[derive(Debug)]
pub struct HubResponse {
    pub status: u16,
    pub body: Value,
}

fn gzip(bytes: &[u8]) -> AppResult<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes)?;
    Ok(enc.finish()?)
}

impl HubClient {
    pub fn new(base: &str, key: &str, agent_id: &str) -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .user_agent(format!("asa/{}", crate::VERSION))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| AppError::Hub(e.to_string()))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            key: key.to_string(),
            agent_id: agent_id.to_string(),
            http,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    async fn post<T: Serialize>(&self, path: &str, body: &T) -> AppResult<HubResponse> {
        let raw = serde_json::to_vec(body)?;
        let (payload, gz) = if raw.len() > GZIP_OVER {
            (gzip(&raw)?, true)
        } else {
            (raw, false)
        };
        if payload.len() > MAX_REPORT_BYTES {
            return Err(AppError::Hub(tf!(
                "上傳內容超過 hub 上限（{n} bytes）",
                n = payload.len()
            )));
        }
        let mut req = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.key)
            .header("content-type", "application/json")
            .header("x-asa-agent-id", &self.agent_id)
            .header("x-asa-agent-version", crate::VERSION);
        if gz {
            req = req.header("content-encoding", "gzip");
        }
        let resp = req
            .body(payload)
            .send()
            .await
            .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        match status {
            200..=299 => Ok(HubResponse { status, body }),
            401 | 403 => Err(AppError::HubAuth),
            429 => Err(AppError::Hub(tf!(
                "hub 要求稍後再傳（{s} 秒後）",
                s = retry_after.unwrap_or_else(|| "?".into())
            ))),
            // 格式／大小被拒：重送也不會過，呼叫端應丟棄（outbox 不保留）。
            400 | 413 | 422 => Err(AppError::HubRejected(tf!(
                "HTTP {status}：{detail}",
                status = status,
                detail = body
                    .get("rule")
                    .or(body.get("error"))
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            ))),
            _ => Err(AppError::Hub(tf!(
                "hub 回應 HTTP {status}：{detail}",
                status = status,
                detail = body
                    .get("rule")
                    .or(body.get("error"))
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            ))),
        }
    }

    pub async fn health(&self) -> AppResult<Value> {
        let resp = self
            .http
            .get(format!("{}/api/health", self.base))
            .send()
            .await
            .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status != 200 {
            return Err(AppError::Hub(tf!("hub 健康檢查失敗（HTTP {status}）", status = status)));
        }
        Ok(body)
    }

    pub async fn register(
        &self,
        agent: &AgentInfo,
        accept_remote_actions: bool,
        service_mode: bool,
    ) -> AppResult<RegisterResponse> {
        let r = self
            .post(
                "/api/v1/agents/register",
                &RegisterPayload {
                    agent: agent.clone(),
                    accept_remote_actions,
                    service_mode,
                },
            )
            .await?;
        serde_json::from_value(r.body).map_err(|e| AppError::Hub(e.to_string()))
    }

    pub async fn upload_report(&self, report: &Report) -> AppResult<Value> {
        Ok(self.post("/api/v1/ingest/report", report).await?.body)
    }

    pub async fn upload_snapshot(&self, snap: &SnapshotPayload) -> AppResult<Value> {
        Ok(self.post("/api/v1/ingest/snapshot", snap).await?.body)
    }

    pub async fn heartbeat(&self, hb: &HeartbeatPayload) -> AppResult<Value> {
        Ok(self.post("/api/v1/agents/me/heartbeat", hb).await?.body)
    }
}

#[cfg(test)]
pub(crate) mod test_server {
    //! 迷你 HTTP 伺服器：依序回應預設內容，並把收到的請求（含 body）交回測試。
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug, Clone)]
    pub struct Captured {
        pub head: String,
        pub body: Vec<u8>,
    }

    pub async fn serve(responses: Vec<(u16, String)>) -> (String, Arc<Mutex<Vec<Captured>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let cap = captured.clone();
        tokio::spawn(async move {
            for (status, body) in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 8192];
                let head_end;
                loop {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        head_end = p + 4;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                cap.lock().unwrap().push(Captured {
                    head,
                    body: buf[head_end..].to_vec(),
                });
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nretry-after: 7\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (url, captured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn url_rules() {
        assert_eq!(
            validate_url("https://hub.example.com/", false).unwrap(),
            "https://hub.example.com"
        );
        assert!(validate_url("http://127.0.0.1:3000", false).is_ok());
        assert!(validate_url("http://192.168.1.5:8088", false).is_ok());
        assert!(validate_url("http://localhost:3000", false).is_ok());
        assert!(validate_url("http://hub.example.com", false).is_err());
        assert!(validate_url("http://hub.example.com", true).is_ok());
        assert!(validate_url("ftp://x", true).is_err());
    }

    #[tokio::test]
    async fn uploads_gzip_with_headers_and_maps_errors() {
        let (url, cap) = test_server::serve(vec![
            (200, r#"{"agent_id":"a1","created":true,"hub":{"name":"Security Hub","version":"0.1.0","min_report_interval_s":60,"snapshot_interval_s":60,"max_report_bytes":4194304,"server_time":"x"}}"#.into()),
            (200, r#"{"ok":true,"duplicate":false}"#.into()),
            (401, r#"{"error":"unauthorized"}"#.into()),
            (429, r#"{"error":"too_frequent"}"#.into()),
            (400, r#"{"error":"bad_request","rule":"max_depth"}"#.into()),
        ])
        .await;
        let c = HubClient::new(&url, "k1", "a1").unwrap();
        let reg = c
            .register(&crate::model::contract::sample_agent(), false, true)
            .await
            .unwrap();
        assert_eq!(reg.hub.max_report_bytes, 4_194_304);
        let rep = crate::model::contract::sample_report();
        c.upload_report(&rep).await.unwrap();
        assert!(matches!(c.upload_report(&rep).await, Err(AppError::HubAuth)));
        let e = c.upload_report(&rep).await.unwrap_err();
        assert!(e.message().contains('7'), "{}", e.message());
        // 400 是永久拒收：outbox 會丟掉，不該當成可重試的 Hub 錯誤。
        let e = c.upload_report(&rep).await.unwrap_err();
        assert!(
            matches!(&e, AppError::HubRejected(m) if m.contains("max_depth")),
            "{e:?}"
        );

        let reqs = cap.lock().unwrap().clone();
        assert!(reqs[0].head.starts_with("POST /api/v1/agents/register"));
        assert!(reqs[0].head.to_ascii_lowercase().contains("authorization: bearer k1"));
        assert!(reqs[0].head.to_ascii_lowercase().contains("x-asa-agent-id: a1"));
        let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["service_mode"], true);
        // 報告 < 16 KB 不壓縮；用大一點的報告驗 gzip。
        let mut big = rep.clone();
        for i in 0..80 {
            let mut f = big.findings[0].clone();
            f.id = format!("f_{i:016}");
            big.findings.push(f);
        }
        let (url2, cap2) = test_server::serve(vec![(200, "{}".into())]).await;
        HubClient::new(&url2, "k1", "a1")
            .unwrap()
            .upload_report(&big)
            .await
            .unwrap();
        let r = cap2.lock().unwrap()[0].clone();
        assert!(r.head.to_ascii_lowercase().contains("content-encoding: gzip"));
        let mut out = String::new();
        flate2::read::GzDecoder::new(&r.body[..])
            .read_to_string(&mut out)
            .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["findings"].as_array().unwrap().len(), 82);
    }
}
