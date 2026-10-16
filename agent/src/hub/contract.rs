//! 上傳到 hub 的 payload（報告本身是 `model::report::Report`）。欄位名與 `contract/*.v1.json` 一致。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::connection::{Connection, Listener};
use crate::model::report::AgentInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub agent: AgentInfo,
    pub accept_remote_actions: bool,
    pub service_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPayload {
    pub agent_id: String,
    pub ts: DateTime<Utc>,
    pub connections: Vec<Connection>,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub agent_id: String,
    pub ts: DateTime<Utc>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_at: Option<DateTime<Utc>>,
    pub elevated: bool,
}

/// hub 註冊回應裡的設定。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HubInfo {
    pub name: String,
    pub version: String,
    pub min_report_interval_s: u64,
    pub snapshot_interval_s: u64,
    pub max_report_bytes: u64,
    pub server_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    #[serde(default)]
    pub created: bool,
    #[serde(default)]
    pub hub: HubInfo,
    /// hub 是否已釘選這台 agent 的身分 token。
    #[serde(default)]
    pub pinned: bool,
    /// 驗證遠端動作 token 用的金鑰（只在接受遠端動作且已釘選時給）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_key: Option<String>,
}
