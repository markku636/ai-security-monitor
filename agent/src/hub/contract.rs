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
    /// 目前連線的公網 IP → 這台電腦解析過的網域名稱（Windows DNS 快取；`scan.dns_names = false` 時不送）。
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub dns_names: std::collections::BTreeMap<String, Vec<String>>,
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
    /// 情資清單最舊的一次檢查時間（hub 用來判斷要不要叫這台更新）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_checked_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_feeds: Option<IntelFeedsInfo>,
    /// 自動更新狀態（Hub 在主機清單顯示「有新版」）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateInfo>,
    /// 這台電腦的背景服務正在幫哪個 Hub 做區網廣播（`hub.advertise_url`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertising: Option<AdvertiseInfo>,
}

/// 心跳裡的更新狀態。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateInfo {
    /// `off`／`notify`／`auto`。
    pub mode: String,
    /// 誰負責安裝：`agent`（命令列版自己）／`desktop`（桌面版的更新器）。
    pub owner: String,
    /// 最新版（檢查過才有）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// `latest` 比這台的版本新。
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
    /// 沒有自動安裝的原因或最近的錯誤。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// 心跳裡的區網廣播狀態。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AdvertiseInfo {
    /// 廣播的 Hub 網址。
    pub url: String,
    /// `advertising`（廣播中）／`hub_unreachable`（連不到 Hub，已停止）／`starting`／`error`。
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 這一輪開始廣播的時間。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntelFeedsInfo {
    pub ok: usize,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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
