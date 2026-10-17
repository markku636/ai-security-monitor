//! 免金鑰加入：送出加入申請 → 等管理員在 Hub 核准（或來源網段自動核准）→ 拿到這台專用的註冊金鑰 → 照一般流程 register。
//!
//! - 申請密語（32 bytes 亂數）只存在這台的密鑰庫（`hub.enroll_request_secret`），Hub 只存 sha256；輪詢時以 Bearer 帶上。
//! - 待核准的申請存在 `<設定目錄>/hub-enroll-request.json`：再執行一次 `enroll --auto`、或常駐的 `watch` 都會接著等。
//! - 核准結果由 Hub 的 Ed25519 身分簽章；agent 用加入時釘選的公鑰驗證（TOFU），簽章不對就不收。

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::contract::RegisterResponse;
use super::identity::{self, HubIdentity};
use super::HubClient;
use crate::config::{self, AgentConfig, HubConfig};
use crate::error::{AppError, AppResult};
use crate::model::report::AgentInfo;
use crate::secrets::{SecretStore, KEY_HUB_CLIENT, KEY_HUB_ENROLL_SECRET};
use crate::store;

pub const PENDING_FILE: &str = "hub-enroll-request.json";
pub const REQUEST_PATH: &str = "/api/v1/agents/enroll-request";

/// 送給 Hub 的加入申請（`contract/enroll-request.v1.json`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequestPayload {
    pub agent: AgentInfo,
    pub accept_remote_actions: bool,
    pub request_secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Credentials {
    pub agent_id: String,
    pub client_key: String,
    pub hub_fingerprint: String,
    pub signature: String,
}

/// 申請狀態（`contract/enroll-status.v1.json`；建立申請的回應也是這個形狀再加 `hub`）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct EnrollStatus {
    pub request_id: String,
    pub status: String,
    pub request_code: String,
    pub poll_interval_s: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub auto_approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
}

/// 等候中的申請（存檔；密語另存密鑰庫）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingEnroll {
    pub hub_url: String,
    pub hub_name: String,
    pub hub_fingerprint: String,
    pub hub_public_key: String,
    pub request_id: String,
    pub request_code: String,
    pub accept_remote_actions: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub poll_interval_s: u64,
}

pub fn load_pending(dir: &Path) -> Option<PendingEnroll> {
    store::read_json_opt(dir, PENDING_FILE).ok().flatten()
}

pub fn save_pending(dir: &Path, p: &PendingEnroll) -> AppResult<()> {
    store::write_json_in(dir, PENDING_FILE, p)
}

pub fn clear_pending(dir: &Path) -> AppResult<()> {
    let _ = std::fs::remove_file(dir.join(PENDING_FILE));
    SecretStore::open(dir).delete(KEY_HUB_ENROLL_SECRET)
}

pub fn new_secret() -> AppResult<String> {
    Ok(identity::b64url(&identity::random_bytes::<32>()?))
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// 核准結果的簽章：用釘選的 Hub 公鑰驗；指紋、agent id 也要對。
pub fn verify_credentials(p: &PendingEnroll, agent_id: &str, c: &Credentials) -> AppResult<()> {
    if !identity::same_fingerprint(&c.hub_fingerprint, &p.hub_fingerprint) {
        return Err(AppError::HubIdentity(identity::mismatch_message(
            &p.hub_fingerprint,
            &c.hub_fingerprint,
        )));
    }
    if c.agent_id != agent_id {
        return Err(AppError::HubIdentity(
            t!("Hub 核准的不是這台電腦（agent id 不符）").into(),
        ));
    }
    if !c.client_key.starts_with("asa_") || c.client_key.len() > 256 {
        return Err(AppError::HubIdentity(t!("Hub 回傳的金鑰格式不對").into()));
    }
    let msg = format!(
        "asa-enroll-approved|v1|{}|{}|{}",
        p.request_id,
        c.agent_id,
        sha256_hex(&c.client_key)
    );
    if !identity::verify_signature(&p.hub_public_key, &msg, &c.signature) {
        return Err(AppError::HubIdentity(
            t!("核准結果的簽章驗證失敗：不是加入時那個 Hub 發的").into(),
        ));
    }
    Ok(())
}

fn status_error(status: u16, body: &serde_json::Value) -> AppError {
    let code = body["error"].as_str().unwrap_or("").to_string();
    match (status, code.as_str()) {
        (403, "enroll_requests_disabled") => {
            AppError::Hub(t!("這個 Hub 沒有開放免金鑰加入：請向管理員要註冊金鑰（enroll --key）").into())
        }
        (409, "hub_fingerprint_mismatch") => AppError::HubIdentity(identity::mismatch_message(
            "?",
            body["fingerprint"].as_str().unwrap_or("?"),
        )),
        (429, _) => AppError::Hub(t!("加入申請太頻繁，請稍後再試").into()),
        (503, "too_many_pending") => AppError::Hub(t!("Hub 待核准的申請太多，請管理員先處理").into()),
        _ => AppError::Hub(tf!("Hub 回應 HTTP {status}：{code}", status = status, code = code)),
    }
}

/// 送出加入申請（Hub 身分已驗證過）。
pub async fn submit(
    http: &reqwest::Client,
    url: &str,
    hub: &HubIdentity,
    agent: &AgentInfo,
    accept_remote_actions: bool,
    secret: &str,
) -> AppResult<(PendingEnroll, EnrollStatus)> {
    let body = EnrollRequestPayload {
        agent: agent.clone(),
        accept_remote_actions,
        request_secret: secret.to_string(),
        hub_fingerprint: Some(hub.fingerprint.clone()),
    };
    let resp = http
        .post(format!("{}{REQUEST_PATH}", url.trim_end_matches('/')))
        .header("x-asa-agent-id", &agent.id)
        .header("x-asa-agent-version", crate::VERSION)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
    let status = resp.status().as_u16();
    let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !(200..300).contains(&status) {
        return Err(status_error(status, &v));
    }
    let st: EnrollStatus = serde_json::from_value(v).map_err(|e| AppError::Hub(e.to_string()))?;
    if st.request_id.is_empty() {
        return Err(AppError::Hub(t!("Hub 沒有回傳申請編號").into()));
    }
    let code = identity::request_code(secret);
    let pending = PendingEnroll {
        hub_url: url.trim_end_matches('/').to_string(),
        hub_name: hub.name.clone(),
        hub_fingerprint: hub.fingerprint.clone(),
        hub_public_key: hub.public_key.clone(),
        request_id: st.request_id.clone(),
        request_code: code,
        accept_remote_actions,
        created_at: Utc::now(),
        expires_at: st.expires_at,
        status: st.status.clone(),
        poll_interval_s: st.poll_interval_s,
    };
    Ok((pending, st))
}

/// 問一次申請狀態。
pub async fn poll(http: &reqwest::Client, p: &PendingEnroll, secret: &str) -> AppResult<EnrollStatus> {
    let resp = http
        .get(format!("{}{REQUEST_PATH}/{}", p.hub_url, p.request_id))
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
    let status = resp.status().as_u16();
    let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    match status {
        200 => serde_json::from_value(v).map_err(|e| AppError::Hub(e.to_string())),
        // 申請不見了（Hub 清掉、或密語不對）：當成過期，要重新申請
        404 => Ok(EnrollStatus {
            request_id: p.request_id.clone(),
            status: "expired".into(),
            request_code: p.request_code.clone(),
            ..EnrollStatus::default()
        }),
        _ => Err(status_error(status, &v)),
    }
}

/// 拿到核准的金鑰後：一般 register（帶身分 token 釘選）→ 存金鑰、設定（含釘選的 Hub 指紋）→ 清掉待核准狀態。
pub async fn finalize(
    config_dir: &Path,
    cfg: &mut AgentConfig,
    p: &PendingEnroll,
    creds: &Credentials,
    agent: &AgentInfo,
    service_mode: bool,
) -> AppResult<RegisterResponse> {
    verify_credentials(p, &cfg.agent_id, creds)?;
    let token = super::watch::agent_token(config_dir)?;
    let client = HubClient::new(&p.hub_url, &creds.client_key, &cfg.agent_id)?.with_agent_token(Some(token));
    let reg = client.register(agent, p.accept_remote_actions, service_mode).await?;
    SecretStore::open(config_dir).set(KEY_HUB_CLIENT, &creds.client_key)?;
    super::watch::save_action_key(config_dir, p.accept_remote_actions, reg.action_key.as_deref())?;
    cfg.hub = Some(HubConfig {
        url: p.hub_url.clone(),
        enrolled_at: crate::util::time::now_iso(),
        min_report_interval_s: Some(reg.hub.min_report_interval_s),
        max_report_bytes: Some(reg.hub.max_report_bytes),
        snapshot_interval_s: Some(reg.hub.snapshot_interval_s),
        feed_mirror: false,
        fingerprint: Some(p.hub_fingerprint.clone()),
        public_key: Some(p.hub_public_key.clone()),
    });
    cfg.remote_actions.accept = p.accept_remote_actions;
    config::save(config_dir, cfg)?;
    clear_pending(config_dir)?;
    Ok(reg)
}

/// 一次輪詢的結果。
#[derive(Debug)]
pub enum Step {
    Waiting(EnrollStatus),
    Done(Box<RegisterResponse>),
    Rejected(Option<String>),
    Expired,
}

/// 輪詢一次；核准了就完成註冊。被拒絕／過期會清掉待核准狀態。
pub async fn step(
    config_dir: &Path,
    cfg: &mut AgentConfig,
    agent: &AgentInfo,
    service_mode: bool,
) -> AppResult<Option<Step>> {
    let Some(mut p) = load_pending(config_dir) else {
        return Ok(None);
    };
    let Some(secret) = SecretStore::open(config_dir).get(KEY_HUB_ENROLL_SECRET)? else {
        // 密語不見了（換了密鑰庫）：這個申請沒辦法再問，重新申請
        clear_pending(config_dir)?;
        return Ok(Some(Step::Expired));
    };
    let http = identity::http_client(Duration::from_secs(20))?;
    let st = poll(&http, &p, &secret).await?;
    match st.status.as_str() {
        "approved" => match &st.credentials {
            Some(c) => {
                let reg = finalize(config_dir, cfg, &p, c, agent, service_mode).await?;
                Ok(Some(Step::Done(Box::new(reg))))
            }
            // 核准過但已不給金鑰（被別的行程領走後超過時限、金鑰被撤銷、核准已過期）：這個申請用不了了，重新申請
            None => {
                clear_pending(config_dir)?;
                Ok(Some(Step::Expired))
            }
        },
        "rejected" => {
            clear_pending(config_dir)?;
            Ok(Some(Step::Rejected(st.reason.clone())))
        }
        "expired" => {
            clear_pending(config_dir)?;
            Ok(Some(Step::Expired))
        }
        _ => {
            if p.status != st.status || p.poll_interval_s != st.poll_interval_s {
                p.status = st.status.clone();
                p.poll_interval_s = st.poll_interval_s;
                let _ = save_pending(config_dir, &p);
            }
            Ok(Some(Step::Waiting(st)))
        }
    }
}

/// 下次輪詢前等多久（Hub 建議值，5 秒～5 分鐘）。
pub fn poll_delay(p: Option<&PendingEnroll>, st: Option<&EnrollStatus>) -> Duration {
    let s = st
        .map(|s| s.poll_interval_s)
        .filter(|&s| s > 0)
        .or(p.map(|p| p.poll_interval_s).filter(|&s| s > 0))
        .unwrap_or(15);
    Duration::from_secs(s.clamp(5, 300))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(name: &str) -> serde_json::Value {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../contract")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn pending_for_contract() -> PendingEnroll {
        let id = contract("hub-identity.v1.json");
        let st = contract("enroll-status.v1.json");
        PendingEnroll {
            hub_url: "http://127.0.0.1:1".into(),
            hub_name: "Security Hub".into(),
            hub_fingerprint: id["fingerprint"].as_str().unwrap().into(),
            hub_public_key: id["public_key"].as_str().unwrap().into(),
            request_id: st["request_id"].as_str().unwrap().into(),
            request_code: st["request_code"].as_str().unwrap().into(),
            accept_remote_actions: false,
            created_at: Utc::now(),
            expires_at: None,
            status: "pending".into(),
            poll_interval_s: 15,
        }
    }

    #[test]
    fn contract_request_round_trips() {
        let v = contract("enroll-request.v1.json");
        let p: EnrollRequestPayload = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&p).unwrap(), v);
        assert_eq!(identity::request_code(&p.request_secret), "ENDY-Z24W");
    }

    #[test]
    fn approval_signature_is_verified_against_the_pinned_key() {
        let st: EnrollStatus = serde_json::from_value(contract("enroll-status.v1.json")).unwrap();
        let c = st.credentials.clone().unwrap();
        let p = pending_for_contract();
        verify_credentials(&p, &c.agent_id, &c).unwrap();
        // 別台電腦、被換掉的金鑰、別的申請、別的 Hub 公鑰都不收
        assert!(verify_credentials(&p, "other-agent", &c).is_err());
        let mut forged = c.clone();
        forged.client_key = format!("{}6", &c.client_key[..c.client_key.len() - 1]);
        assert!(verify_credentials(&p, &c.agent_id, &forged).is_err());
        let mut other = p.clone();
        other.request_id = "rq_ffffffffffffffffffffffff".into();
        assert!(verify_credentials(&other, &c.agent_id, &c).is_err());
        let mut other = p.clone();
        other.hub_fingerprint = "AAAA-BBBB-CCCC-DDDD-EEEE".into();
        let e = verify_credentials(&other, &c.agent_id, &c).unwrap_err();
        assert!(e.message().contains("AAAA-BBBB-CCCC-DDDD-EEEE"), "{}", e.message());
    }

    #[test]
    fn poll_delay_bounds() {
        assert_eq!(poll_delay(None, None), Duration::from_secs(15));
        let st = EnrollStatus {
            poll_interval_s: 1,
            ..EnrollStatus::default()
        };
        assert_eq!(poll_delay(None, Some(&st)), Duration::from_secs(5));
        let st = EnrollStatus {
            poll_interval_s: 9999,
            ..EnrollStatus::default()
        };
        assert_eq!(poll_delay(None, Some(&st)), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn submit_poll_and_resume_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::with_backend(dir.path(), crate::secrets::Backend::File);
        let id: HubIdentity = serde_json::from_value(contract("hub-identity.v1.json")).unwrap();
        let created = r#"{"request_id":"rq_00112233445566778899aabb","status":"pending","auto_approved":false,"request_code":"ENDY-Z24W","poll_interval_s":15,"expires_at":"2026-10-24T08:00:00.000Z","hub":{"name":"Security Hub","version":"0.2.1","fingerprint":"72AS-YEXT-VNGO-NLC5-W2NM"}}"#;
        let (url, cap) = crate::hub::test_server::serve(vec![
            (201, created.into()),
            (200, r#"{"request_id":"rq_00112233445566778899aabb","status":"pending","request_code":"ENDY-Z24W","poll_interval_s":20}"#.into()),
            (200, r#"{"request_id":"rq_00112233445566778899aabb","status":"rejected","request_code":"ENDY-Z24W","reason":"not ours"}"#.into()),
        ])
        .await;
        let http = identity::http_client(Duration::from_secs(5)).unwrap();
        let agent = crate::model::contract::sample_agent();
        let secret = contract("enroll-request.v1.json")["request_secret"]
            .as_str()
            .unwrap()
            .to_string();
        let (p, st) = submit(&http, &url, &id, &agent, false, &secret).await.unwrap();
        assert_eq!(st.status, "pending");
        assert_eq!(p.request_code, "ENDY-Z24W");
        save_pending(dir.path(), &p).unwrap();
        store.set(KEY_HUB_ENROLL_SECRET, &secret).unwrap();
        // 重新執行（新行程）從檔案接著等
        let again = load_pending(dir.path()).unwrap();
        assert_eq!(again, p);
        let st = poll(&http, &again, &secret).await.unwrap();
        assert_eq!(poll_delay(Some(&again), Some(&st)), Duration::from_secs(20));
        let st = poll(&http, &again, &secret).await.unwrap();
        assert_eq!(st.status, "rejected");
        assert_eq!(st.reason.as_deref(), Some("not ours"));

        let reqs = cap.lock().unwrap().clone();
        assert!(reqs[0].head.starts_with("POST /api/v1/agents/enroll-request "));
        assert!(!reqs[0].head.to_ascii_lowercase().contains("authorization:"));
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["hub_fingerprint"], "72AS-YEXT-VNGO-NLC5-W2NM");
        assert_eq!(body["request_secret"], secret.as_str());
        assert!(reqs[1]
            .head
            .starts_with("GET /api/v1/agents/enroll-request/rq_00112233445566778899aabb "));
        assert!(reqs[1]
            .head
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {}", secret.to_ascii_lowercase())));
        clear_pending(dir.path()).unwrap();
        assert!(load_pending(dir.path()).is_none());
    }

    #[tokio::test]
    async fn approved_request_registers_and_pins_the_hub() {
        let dir = tempfile::tempdir().unwrap();
        let status = contract("enroll-status.v1.json");
        let agent_id = status["credentials"]["agent_id"].as_str().unwrap().to_string();
        let client_key = status["credentials"]["client_key"].as_str().unwrap().to_string();
        let reg = r#"{"agent_id":"AGENT","created":true,"pinned":true,"hub":{"name":"Security Hub","version":"0.2.1","min_report_interval_s":60,"snapshot_interval_s":60,"max_report_bytes":4194304,"server_time":"x"}}"#.replace("AGENT", &agent_id);
        let (url, cap) = crate::hub::test_server::serve(vec![(200, status.to_string()), (200, reg)]).await;
        let mut p = pending_for_contract();
        p.hub_url = url.clone();
        save_pending(dir.path(), &p).unwrap();
        SecretStore::open(dir.path())
            .set(KEY_HUB_ENROLL_SECRET, "s3cret-s3cret-s3cret")
            .unwrap();
        let mut cfg = config::load_or_init(dir.path()).unwrap();
        cfg.agent_id = agent_id.clone();
        let agent = crate::model::contract::sample_agent();
        let step = step(dir.path(), &mut cfg, &agent, true).await.unwrap().unwrap();
        assert!(matches!(step, Step::Done(_)), "{step:?}");
        let h = cfg.hub.clone().unwrap();
        assert_eq!(h.url, url);
        assert_eq!(h.fingerprint.as_deref(), Some("72AS-YEXT-VNGO-NLC5-W2NM"));
        assert_eq!(h.public_key.as_deref(), Some(p.hub_public_key.as_str()));
        // 設定有存檔、金鑰存進密鑰庫、待核准狀態清掉
        assert_eq!(config::load_or_init(dir.path()).unwrap().hub, Some(h));
        assert_eq!(
            SecretStore::open(dir.path()).get(KEY_HUB_CLIENT).unwrap().as_deref(),
            Some(client_key.as_str())
        );
        assert!(load_pending(dir.path()).is_none());
        assert!(SecretStore::open(dir.path())
            .get(KEY_HUB_ENROLL_SECRET)
            .unwrap()
            .is_none());
        let reqs = cap.lock().unwrap().clone();
        let reg_head = reqs[1].head.to_ascii_lowercase();
        assert!(reg_head.starts_with("post /api/v1/agents/register"));
        assert!(reg_head.contains(&format!("authorization: bearer {}", client_key.to_ascii_lowercase())));
        assert!(reg_head.contains("x-asa-agent-token:"));
    }

    #[tokio::test]
    async fn forged_approval_is_refused_and_state_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut status = contract("enroll-status.v1.json");
        status["credentials"]["client_key"] = serde_json::json!(format!("asa_ek_0a1b2c3d_{}", "6".repeat(40)));
        let (url, _) = crate::hub::test_server::serve(vec![(200, status.to_string())]).await;
        let mut p = pending_for_contract();
        p.hub_url = url;
        save_pending(dir.path(), &p).unwrap();
        SecretStore::open(dir.path())
            .set(KEY_HUB_ENROLL_SECRET, "s3cret-s3cret-s3cret")
            .unwrap();
        let mut cfg = config::load_or_init(dir.path()).unwrap();
        cfg.agent_id = status["credentials"]["agent_id"].as_str().unwrap().to_string();
        let e = step(dir.path(), &mut cfg, &crate::model::contract::sample_agent(), false)
            .await
            .unwrap_err();
        assert!(matches!(e, AppError::HubIdentity(_)), "{e:?}");
        assert!(cfg.hub.is_none());
        assert!(SecretStore::open(dir.path()).get(KEY_HUB_CLIENT).unwrap().is_none());
    }

    #[tokio::test]
    async fn submit_maps_hub_errors() {
        let id: HubIdentity = serde_json::from_value(contract("hub-identity.v1.json")).unwrap();
        let (url, _) = crate::hub::test_server::serve(vec![
            (403, r#"{"error":"enroll_requests_disabled"}"#.into()),
            (
                409,
                r#"{"error":"hub_fingerprint_mismatch","fingerprint":"ZZZZ-ZZZZ"}"#.into(),
            ),
        ])
        .await;
        let http = identity::http_client(Duration::from_secs(5)).unwrap();
        let agent = crate::model::contract::sample_agent();
        let e = submit(&http, &url, &id, &agent, false, "x".repeat(43).as_str())
            .await
            .unwrap_err();
        assert!(e.message().contains("--key"), "{}", e.message());
        let e = submit(&http, &url, &id, &agent, false, "x".repeat(43).as_str())
            .await
            .unwrap_err();
        assert!(e.message().contains("ZZZZ-ZZZZ"), "{}", e.message());
    }
}
