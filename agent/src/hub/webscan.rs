//! 網站弱點掃描 runner 跟 Hub 的四個端點（`contract/webscan-*.v1.json`）：認領工作、心跳、上傳原始輸出、回報結果。
//! 身分是 webscan 權杖（`HubClient::new(url, token, "")`，agent id 空字串），跟防護 DNS 的權杖一樣。

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::HubClient;
use crate::error::{AppError, AppResult};

/// 一個 artifact（壓縮後）的上限。
pub const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// 上傳 artifact 的逾時（比一般請求長：最多 8 MiB）。
const ARTIFACT_TIMEOUT: Duration = Duration::from_secs(300);

/// artifact 的描述（放在 query string）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactMeta<'a> {
    pub scanner: &'a str,
    /// `jsonl`／`json`／`txt`。
    pub format: &'a str,
    /// 工具的結束碼；被殺掉（逾時）沒有結束碼時送 -1。
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub truncated: bool,
}

/// 工作 id 會放進網址路徑：只收英數、底線、連字號（不能有 `/`、`.`、`%`）。
pub fn valid_job_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn job_path(id: &str, tail: &str) -> AppResult<String> {
    if !valid_job_id(id) {
        return Err(AppError::InvalidArg(t!("工作 id 格式不對").to_string()));
    }
    Ok(format!("/api/v1/webscan/jobs/{id}/{tail}"))
}

/// 工作已經不屬於這台（被取消、租約過期改給別台、被刪掉）。
fn gone(status: u16) -> bool {
    matches!(status, 404 | 409 | 410)
}

impl HubClient {
    /// 認領工作；舊版 Hub 沒有網站掃描端點（404）回 `Ok(None)`。
    pub async fn webscan_claim<T: Serialize>(&self, claim: &T) -> AppResult<Option<Value>> {
        self.post_or_unsupported("/api/v1/webscan/jobs/claim", claim).await
    }

    /// 心跳；`Ok(None)`＝工作已經不屬於這台（404／409／410），要馬上停。
    pub async fn webscan_heartbeat<T: Serialize>(&self, job_id: &str, body: &T) -> AppResult<Option<Value>> {
        let sent = self.send_post(&job_path(job_id, "heartbeat")?, body).await?;
        if let Ok(r) = &sent {
            if gone(r.status().as_u16()) {
                return Ok(None);
            }
        }
        Ok(Some(Self::finish(sent).await?.body))
    }

    /// 上傳一個步驟的原始輸出（`body` 是工具輸出的 bytes，`gzipped` 表示已經 gzip 過）。
    /// 不走 JSON 的 `send_post`（4 MB 上限）；`Ok(false)`＝工作已經不屬於這台。
    pub async fn webscan_artifact(
        &self,
        job_id: &str,
        meta: &ArtifactMeta<'_>,
        body: Vec<u8>,
        gzipped: bool,
    ) -> AppResult<bool> {
        let path = job_path(job_id, "artifacts")?;
        if body.len() > MAX_ARTIFACT_BYTES {
            return Err(AppError::HubRejected(tf!(
                "上傳內容超過 hub 上限（{n} bytes）",
                n = body.len()
            )));
        }
        let exit_code = meta.exit_code.unwrap_or(-1).to_string();
        let duration_ms = meta.duration_ms.to_string();
        let query = [
            ("scanner", meta.scanner),
            ("format", meta.format),
            ("exit_code", exit_code.as_str()),
            ("duration_ms", duration_ms.as_str()),
            ("truncated", if meta.truncated { "1" } else { "0" }),
        ];
        let mut req = self
            .authed(self.http.post(format!("{}{path}", self.base)))
            .query(&query)
            .header("content-type", "application/octet-stream")
            .timeout(ARTIFACT_TIMEOUT);
        if gzipped {
            req = req.header("content-encoding", "gzip");
        }
        let sent = req.body(body).send().await;
        if let Ok(r) = &sent {
            if gone(r.status().as_u16()) {
                return Ok(false);
            }
        }
        Self::finish(sent).await?;
        Ok(true)
    }

    /// 回報工作結果；`Ok(false)`＝工作已經不屬於這台。
    pub async fn webscan_result<T: Serialize>(&self, job_id: &str, body: &T) -> AppResult<bool> {
        let sent = self.send_post(&job_path(job_id, "results")?, body).await?;
        if let Ok(r) = &sent {
            if gone(r.status().as_u16()) {
                return Ok(false);
            }
        }
        Self::finish(sent).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::test_server;

    #[test]
    fn job_ids_are_path_safe() {
        assert!(valid_job_id("wsj_0123456789abcdef"));
        assert!(valid_job_id("A-b_9"));
        for bad in ["", "../x", "a/b", "a.b", "a%2f", "a b", "a?b", &"x".repeat(129)] {
            assert!(!valid_job_id(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn endpoints_paths_headers_and_status_mapping() {
        let (url, cap) = test_server::serve(vec![
            (200, r#"{"jobs":[],"poll_after_ms":15000}"#.into()),
            (404, r#"{"error":"not_found"}"#.into()),
            (200, r#"{"ok":true,"cancel":false}"#.into()),
            (409, r#"{"error":"lease_lost"}"#.into()),
            (200, r#"{"ok":true}"#.into()),
            (410, "{}".into()),
            (200, r#"{"ok":true}"#.into()),
            (401, r#"{"error":"unauthorized"}"#.into()),
            (429, r#"{"error":"slow_down"}"#.into()),
        ])
        .await;
        let c = HubClient::new(&url, "tok-webscan", "").unwrap();
        let body = serde_json::json!({ "max_jobs": 1 });
        assert!(c.webscan_claim(&body).await.unwrap().is_some());
        assert!(c.webscan_claim(&body).await.unwrap().is_none(), "404 = hub too old");
        assert_eq!(
            c.webscan_heartbeat("wsj_1", &body).await.unwrap().unwrap()["cancel"],
            false
        );
        assert!(
            c.webscan_heartbeat("wsj_1", &body).await.unwrap().is_none(),
            "409 = not ours"
        );
        let meta = ArtifactMeta {
            scanner: "httpx",
            format: "jsonl",
            exit_code: None,
            duration_ms: 1530,
            truncated: true,
        };
        assert!(c
            .webscan_artifact("wsj_1", &meta, b"{\"a\":1}\n".to_vec(), false)
            .await
            .unwrap());
        assert!(
            !c.webscan_artifact("wsj_1", &meta, b"x".to_vec(), true).await.unwrap(),
            "410 = gone"
        );
        assert!(c.webscan_result("wsj_1", &body).await.unwrap());
        assert!(matches!(c.webscan_result("wsj_1", &body).await, Err(AppError::HubAuth)));
        assert!(matches!(
            c.webscan_result("wsj_1", &body).await,
            Err(AppError::HubThrottled { retry_after_s: Some(7) })
        ));
        // 不合法的 id 不送出去
        assert!(matches!(
            c.webscan_result("../admin", &body).await,
            Err(AppError::InvalidArg(_))
        ));
        let too_big = vec![0u8; MAX_ARTIFACT_BYTES + 1];
        assert!(matches!(
            c.webscan_artifact("wsj_1", &meta, too_big, true).await,
            Err(AppError::HubRejected(_))
        ));

        let reqs = cap.lock().unwrap().clone();
        assert_eq!(reqs.len(), 9);
        assert!(reqs[0].head.starts_with("POST /api/v1/webscan/jobs/claim "));
        assert!(reqs[0]
            .head
            .to_ascii_lowercase()
            .contains("authorization: bearer tok-webscan"));
        assert!(reqs[2].head.starts_with("POST /api/v1/webscan/jobs/wsj_1/heartbeat "));
        let art = &reqs[4];
        assert!(
            art.head.starts_with(
                "POST /api/v1/webscan/jobs/wsj_1/artifacts?scanner=httpx&format=jsonl&exit_code=-1&duration_ms=1530&truncated=1 "
            ),
            "{}",
            art.head
        );
        let head = art.head.to_ascii_lowercase();
        assert!(head.contains("content-type: application/octet-stream"));
        assert!(!head.contains("content-encoding"));
        assert_eq!(art.body, b"{\"a\":1}\n");
        assert!(reqs[5].head.to_ascii_lowercase().contains("content-encoding: gzip"));
        assert!(reqs[6].head.starts_with("POST /api/v1/webscan/jobs/wsj_1/results "));
    }
}
