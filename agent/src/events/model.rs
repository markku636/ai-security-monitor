//! 事件與當機的共同模型：三個平台的記錄都先轉成 `NormEvent`，再由規則產生 `CrashRecord`／`SecurityHit`，
//! 彙整成 `EventsSummary`（≤ 約 40 KB，給人看、給 hub、給 AI）。欄位名對齊 Sigma 的 windows logsource 習慣。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::finding::Severity;
use crate::traffic::summary::IntelRef;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormEvent {
    /// `windows` | `journal` | `macos`
    pub source: String,
    /// Windows 記錄檔名（System／Application／Security…）或 journal 的 unit
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    /// 1 嚴重、2 錯誤、3 警告、4 資訊（Windows 編號；journal priority 對應過來）
    pub level: u8,
    pub time: DateTime<Utc>,
    #[serde(default)]
    pub computer: String,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl NormEvent {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.data
            .get(k)
            .map(String::as_str)
            .filter(|v| !v.is_empty() && *v != "-")
    }

    pub fn level_name(&self) -> &'static str {
        match self.level {
            0 | 1 => "critical",
            2 => "error",
            3 => "warning",
            _ => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrashRecord {
    /// bugcheck | unexpected_shutdown | app_crash | app_hang | service_fail | disk_error | whea_hardware |
    /// update_failure | gpu_reset | low_memory | kernel_panic | oom | oops | segfault
    pub kind: String,
    pub time: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub likely_causes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// 來源：`System/Microsoft-Windows-Kernel-Power#41`、`minidump:C:\Windows\Minidump\…`、`journal:kernel`…
    pub source: String,
}

impl CrashRecord {
    pub fn new(kind: &str, time: DateTime<Utc>, source: String) -> Self {
        Self {
            kind: kind.into(),
            time,
            code: None,
            name: None,
            module: None,
            process: None,
            params: Vec::new(),
            likely_causes: Vec::new(),
            remediation: None,
            source,
        }
    }
}

/// 資安事件規則的彙總結果（同一規則＋同一來源合併成一筆）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityHit {
    /// failed_logon_burst | remote_logon | user_created | user_enabled | group_member_added | admin_member_added |
    /// service_installed | task_created | audit_log_cleared | log_cleared | defender_detection | defender_disabled
    pub rule: String,
    pub severity: Severity,
    pub count: u32,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intel: Vec<IntelRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<NormEvent>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TopSource {
    pub provider: String,
    pub event_id: u32,
    pub level: String,
    pub count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventsSummary {
    pub platform: String,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub days: u32,
    pub events_read: u64,
    pub counts_by_level: BTreeMap<String, u64>,
    pub crash_counts: BTreeMap<String, u32>,
    pub crashes: Vec<CrashRecord>,
    pub security: Vec<SecurityHit>,
    pub top_error_sources: Vec<TopSource>,
    /// 因權限不足沒讀到的來源（Security 記錄、Minidump 資料夾、journal…）
    pub needs_admin: Vec<String>,
    pub notes: Vec<String>,
}

pub const MAX_CRASHES: usize = 50;
pub const MAX_TOP: usize = 15;
