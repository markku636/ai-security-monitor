//! `asa watch` 用的零件：連線快照（含情資判定）、最新報告存檔、hub 連線建立。

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
use crate::secrets::{SecretStore, KEY_HUB_CLIENT};
use crate::store;

pub const LATEST_REPORT: &str = "reports/latest.json";

/// 已註冊就建立 hub 客戶端；沒註冊回 None；有註冊但缺金鑰是錯誤。
pub fn client_from_config(config_dir: &Path, cfg: &AgentConfig) -> AppResult<Option<HubClient>> {
    let Some(h) = &cfg.hub else {
        return Ok(None);
    };
    let key = SecretStore::open(config_dir)
        .get(KEY_HUB_CLIENT)?
        .ok_or_else(|| AppError::Hub(t!("已註冊 hub 但找不到 client 金鑰；重新執行 asa enroll").into()))?;
    Ok(Some(HubClient::new(&h.url, &key, &cfg.agent_id)?))
}

/// 拍一次連線快照：socket＋行程、方向、異常旗標、beacon、情資判定、地理。
pub async fn snapshot(config_dir: &Path, agent_id: &str, intel: Option<Arc<IntelDb>>) -> AppResult<SnapshotPayload> {
    let dir = config_dir.to_path_buf();
    let allowlist = Allowlist::load(&dir)?;
    let baseline = Baseline::load(&dir)?;
    let agent_id = agent_id.to_string();
    tokio::task::spawn_blocking(move || -> AppResult<SnapshotPayload> {
        let mut snap = crate::connections::take(&dir)?;
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
        })
    })
    .await
    .map_err(|e| AppError::Scan(e.to_string()))?
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
