//! Report：一次掃描的完整輸出（hub ingest 的主體）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::finding::{Finding, ScannerId};

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OsInfo {
    /// `windows` / `macos` / `linux`。
    pub family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Windows：`workstation` | `server` | `domain_controller`（ProductType）。舊版 agent 不送。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_type: Option<String>,
    /// Windows：`Client` | `Server` | `Server Core`（InstallationType）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_type: Option<String>,
    /// Windows EditionID（例：`Professional`、`ServerDatacenter`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub version: String,
    pub hostname: String,
    pub os: OsInfo,
    pub arch: String,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_s: Option<u64>,
    pub elevated: bool,
    #[serde(default)]
    pub scanners_available: Vec<ScannerId>,
}

impl AgentInfo {
    /// 以目前行程環境建立（OS 版本細節由 connections 引擎的 sysinfo 補上）。
    pub fn current(agent_id: &str) -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into());
        Self {
            id: agent_id.to_string(),
            version: crate::VERSION.to_string(),
            hostname,
            os: OsInfo {
                family: std::env::consts::OS.to_string(),
                ..Default::default()
            },
            arch: std::env::consts::ARCH.to_string(),
            ips: Vec::new(),
            uptime_s: None,
            elevated: crate::elevate::is_elevated(),
            scanners_available: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Scores {
    pub overall: u8,
    pub connections: u8,
    pub exposure: u8,
    pub vulns: u8,
    pub hardening: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct InventorySummary {
    pub packages: u32,
    pub by_ecosystem: serde_json::Map<String, serde_json::Value>,
    pub listeners: u32,
    pub connections: u32,
    pub processes_with_network: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HardeningSummary {
    pub pass: u32,
    pub fail: u32,
    pub na: u32,
    pub error: u32,
    /// 嚴重度加權分數（0–100）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub needs_admin: Vec<String>,
    /// 每條檢查的結果（hardening::Outcome）。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Summaries {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardening: Option<HardeningSummary>,
    /// VulnSummary（作業系統支援、更新、已知漏洞軟體、OSV）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vuln: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct BaselineDiffSummary {
    pub new_listeners: u32,
    pub new_network_processes: u32,
    pub new_destinations: u32,
    pub new_findings: u32,
    pub resolved_findings: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub report_id: String,
    pub agent: AgentInfo,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub scanners_run: Vec<ScannerId>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub inventory: InventorySummary,
    #[serde(default)]
    pub summaries: Summaries,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineDiffSummary>,
    pub score: Scores,
    /// 權限不足時部分資料缺失（hub 不應把較少的 finding 當成改善）。
    #[serde(default)]
    pub partial: bool,
}

impl Report {
    pub fn count_by_severity(&self) -> [u32; 5] {
        let mut c = [0u32; 5];
        for f in &self.findings {
            if f.suppressed_by.is_some() {
                continue;
            }
            c[f.severity as usize] += 1;
        }
        c
    }
}
