//! `ai-security-monitor watch` 用的零件：連線快照（含情資判定）、最新報告存檔、hub 連線建立。

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;

use super::contract::SnapshotPayload;
use super::HubClient;
use crate::config::AgentConfig;
use crate::connections::{beacon, history, Classifier};
use crate::error::{AppError, AppResult};
use crate::intel::registry::Registry;
use crate::intel::IntelDb;
use crate::model::allowlist::Allowlist;
use crate::model::baseline::Baseline;
use crate::model::report::Report;
use crate::secrets::{SecretStore, KEY_HUB_ACTION, KEY_HUB_AGENT_TOKEN, KEY_HUB_CLIENT};
use crate::store;

pub const LATEST_REPORT: &str = "reports/latest.json";
/// 最近一次上傳到 Hub 的時間與錯誤（桌面版「上次上傳」、`status`）。
pub const UPLOAD_STATE: &str = "upload-state.json";

/// 已註冊就建立 hub 客戶端；沒註冊回 None；有註冊但缺金鑰是錯誤。
pub fn client_from_config(config_dir: &Path, cfg: &AgentConfig) -> AppResult<Option<HubClient>> {
    let Some(h) = &cfg.hub else {
        return Ok(None);
    };
    let key = SecretStore::open(config_dir).get(KEY_HUB_CLIENT)?.ok_or_else(|| {
        AppError::Hub(t!("已註冊 hub 但找不到 client 金鑰；重新執行 ai-security-monitor enroll").into())
    })?;
    let token = agent_token(config_dir)?;
    Ok(Some(
        HubClient::new(&h.url, &key, &cfg.agent_id)?.with_agent_token(Some(token)),
    ))
}

/// 這台 agent 的身分 token（hub 第一次看到就釘選）；沒有就產生。取消註冊也保留，重新註冊才不會被當成冒名。
pub fn agent_token(config_dir: &Path) -> AppResult<String> {
    let store = SecretStore::open(config_dir);
    if let Some(t) = store.get(KEY_HUB_AGENT_TOKEN)? {
        return Ok(t);
    }
    let t = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    store.set(KEY_HUB_AGENT_TOKEN, &t)?;
    Ok(t)
}

/// 依註冊回應保存或清掉驗章金鑰；回傳目前是否持有金鑰。
pub fn save_action_key(config_dir: &Path, accept: bool, key: Option<&str>) -> AppResult<bool> {
    let store = SecretStore::open(config_dir);
    match key.filter(|_| accept) {
        Some(k) => {
            store.set(KEY_HUB_ACTION, k)?;
            Ok(true)
        }
        None => {
            store.delete(KEY_HUB_ACTION)?;
            Ok(false)
        }
    }
}

/// 拍一次連線快照：socket＋行程、方向、異常旗標、beacon、情資判定、地理；`dns_names` 時附上連線 IP 對應的網域（Windows）。
pub async fn snapshot(
    config_dir: &Path,
    agent_id: &str,
    intel: Option<Arc<IntelDb>>,
    dns_names: bool,
) -> AppResult<SnapshotPayload> {
    let dir = config_dir.to_path_buf();
    let allowlist = Allowlist::load(&dir)?;
    let baseline = Baseline::load(&dir)?;
    let agent_id = agent_id.to_string();
    let mut payload = tokio::task::spawn_blocking(move || -> AppResult<SnapshotPayload> {
        let mut snap = crate::connections::take(&dir)?;
        crate::dns::annotate_domains(&mut snap.connections);
        let now = Utc::now().timestamp() as u64;
        history::append(&dir, now, &history::pairs_of(&snap.connections))?;
        let hist = history::load(&dir, now.saturating_sub(history::RETENTION_SECS))?;
        let beacons = beacon::detect(&hist, now);
        Classifier::load().annotate(&mut snap, &allowlist, baseline.as_ref(), &beacons);
        if let Some(db) = intel {
            crate::intel::enrich_connections(&db, &mut snap.connections);
        }
        Ok(SnapshotPayload {
            agent_id,
            ts: Utc::now(),
            connections: snap.connections,
            listeners: snap.listeners,
            dns_names: Default::default(),
        })
    })
    .await
    .map_err(|e| AppError::Scan(e.to_string()))??;
    if dns_names {
        payload.dns_names = crate::connections::dnsnames::collect(config_dir, &payload.connections).await;
    }
    Ok(payload)
}

/// 載入情資（沒下載過回 None）。
pub async fn load_intel(config_dir: &Path) -> Option<Arc<IntelDb>> {
    let reg = Registry::load(config_dir).ok()?;
    let dir = config_dir.to_path_buf();
    let db = tokio::task::spawn_blocking(move || IntelDb::load(&dir, &reg))
        .await
        .ok()?;
    if db.feeds.is_empty() {
        None
    } else {
        Some(Arc::new(db))
    }
}

pub fn save_latest(config_dir: &Path, report: &Report) -> AppResult<()> {
    store::ensure_dir(&config_dir.join("reports"))?;
    store::write_json_compact_in(config_dir, LATEST_REPORT, report)
}

pub fn load_latest(config_dir: &Path) -> Option<Report> {
    store::read_json_opt(config_dir, LATEST_REPORT).ok().flatten()
}

/// `<設定目錄>/upload-state.json`：背景服務與「立即上傳」都會更新。
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct UploadState {
    pub hub: Option<String>,
    pub last_report_at: Option<chrono::DateTime<Utc>>,
    pub last_report_id: Option<String>,
    pub last_snapshot_at: Option<chrono::DateTime<Utc>>,
    pub last_heartbeat_at: Option<chrono::DateTime<Utc>>,
    /// 最近一次失敗（之後有成功的上傳就清掉）。
    pub last_error: Option<String>,
    pub last_error_at: Option<chrono::DateTime<Utc>>,
}

impl UploadState {
    /// 最近一次成功上傳（報告或快照）。
    pub fn last_upload_at(&self) -> Option<chrono::DateTime<Utc>> {
        self.last_report_at.max(self.last_snapshot_at)
    }
}

/// 上傳結果。
#[derive(Debug, Clone, Copy)]
pub enum Uploaded<'a> {
    Report(&'a str),
    Snapshot,
    Heartbeat,
    Failed(&'a str),
}

pub fn upload_state(config_dir: &Path) -> UploadState {
    store::read_json_opt(config_dir, UPLOAD_STATE)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// 記一筆上傳結果（寫檔失敗就算了，不影響上傳本身）。
pub fn record_upload(config_dir: &Path, hub: &str, ev: Uploaded<'_>) {
    let mut s = upload_state(config_dir);
    let now = Utc::now();
    s.hub = Some(hub.to_string());
    match ev {
        Uploaded::Report(id) => {
            s.last_report_at = Some(now);
            s.last_report_id = Some(id.to_string());
            s.last_error = None;
            s.last_error_at = None;
        }
        Uploaded::Snapshot => {
            s.last_snapshot_at = Some(now);
            s.last_error = None;
            s.last_error_at = None;
        }
        Uploaded::Heartbeat => s.last_heartbeat_at = Some(now),
        Uploaded::Failed(e) => {
            s.last_error = Some(e.to_string());
            s.last_error_at = Some(now);
        }
    }
    let _ = store::write_json_in(config_dir, UPLOAD_STATE, &s);
}

#[cfg(test)]
mod upload_state_tests {
    use super::*;

    #[test]
    fn records_successes_and_failures() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(upload_state(d.path()), UploadState::default());
        record_upload(d.path(), "http://hub", Uploaded::Failed("down"));
        let s = upload_state(d.path());
        assert_eq!(s.last_error.as_deref(), Some("down"));
        assert!(s.last_upload_at().is_none());
        record_upload(d.path(), "http://hub", Uploaded::Snapshot);
        record_upload(d.path(), "http://hub", Uploaded::Report("r1"));
        record_upload(d.path(), "http://hub", Uploaded::Heartbeat);
        let s = upload_state(d.path());
        assert!(s.last_error.is_none());
        assert_eq!(s.last_report_id.as_deref(), Some("r1"));
        assert_eq!(s.hub.as_deref(), Some("http://hub"));
        assert!(s.last_upload_at().is_some() && s.last_heartbeat_at.is_some());
    }
}
