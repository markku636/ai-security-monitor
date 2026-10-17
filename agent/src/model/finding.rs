//! Finding：所有掃描器的統一輸出。`id` 以 evidence key 雜湊，跨次掃描穩定（hub 靠它做 upsert / diff）。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::util::hash::stable_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// 分數罰分（見 `scan::score`）。
    pub fn penalty(self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 7,
            Severity::High => 15,
            Severity::Critical => 25,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum ScannerId {
    Connections,
    Intel,
    Ports,
    Firewall,
    Vuln,
    Hardening,
    Files,
    Traffic,
    Events,
    Dns,
}

impl ScannerId {
    pub const ALL: [ScannerId; 10] = [
        ScannerId::Connections,
        ScannerId::Intel,
        ScannerId::Ports,
        ScannerId::Firewall,
        ScannerId::Vuln,
        ScannerId::Hardening,
        ScannerId::Files,
        ScannerId::Traffic,
        ScannerId::Events,
        ScannerId::Dns,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScannerId::Connections => "connections",
            ScannerId::Intel => "intel",
            ScannerId::Ports => "ports",
            ScannerId::Firewall => "firewall",
            ScannerId::Vuln => "vuln",
            ScannerId::Hardening => "hardening",
            ScannerId::Files => "files",
            ScannerId::Traffic => "traffic",
            ScannerId::Events => "events",
            ScannerId::Dns => "dns",
        }
    }

    pub fn parse(s: &str) -> Option<ScannerId> {
        Self::ALL
            .into_iter()
            .find(|id| id.as_str() == s.trim().to_ascii_lowercase())
    }
}

/// 情資命中——每一筆都帶來源與授權，UI / AI 必須原樣引用。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntelHit {
    pub feed_id: String,
    pub name: String,
    pub vendor: String,
    /// 0–100。
    pub confidence: u8,
    pub license: String,
    pub license_url: String,
    pub attribution_required: bool,
    pub fetched_at: DateTime<Utc>,
    pub source_url: String,
    /// 命中的 ip / cidr / domain 原值。
    pub matched: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    BlockIp,
    UnblockIp,
    ClosePort,
    DisableService,
    UpdatePackage,
    KillProcess,
    QuarantineFile,
    EnableFirewall,
    CapturePcap,
    BaselineAccept,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::BlockIp => "block_ip",
            ActionKind::UnblockIp => "unblock_ip",
            ActionKind::ClosePort => "close_port",
            ActionKind::DisableService => "disable_service",
            ActionKind::UpdatePackage => "update_package",
            ActionKind::KillProcess => "kill_process",
            ActionKind::QuarantineFile => "quarantine_file",
            ActionKind::EnableFirewall => "enable_firewall",
            ActionKind::CapturePcap => "capture_pcap",
            ActionKind::BaselineAccept => "baseline_accept",
        }
    }

    pub fn parse(s: &str) -> Option<ActionKind> {
        [
            ActionKind::BlockIp,
            ActionKind::UnblockIp,
            ActionKind::ClosePort,
            ActionKind::DisableService,
            ActionKind::UpdatePackage,
            ActionKind::KillProcess,
            ActionKind::QuarantineFile,
            ActionKind::EnableFirewall,
            ActionKind::CapturePcap,
            ActionKind::BaselineAccept,
        ]
        .into_iter()
        .find(|k| k.as_str() == s.trim().to_ascii_lowercase())
    }

    /// 高破壞（不可逆或影響運作）：CLI 需 `--force`，MCP 需 `--allow-destructive`。
    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            ActionKind::KillProcess
                | ActionKind::QuarantineFile
                | ActionKind::DisableService
                | ActionKind::UpdatePackage
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedAction {
    pub kind: ActionKind,
    pub params: serde_json::Value,
    pub requires_elevation: bool,
    pub destructive: bool,
    pub reversible: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    NotApplicable,
    Error,
}

/// 典型證據（tagged union）。各掃描器只用自己的變體。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    Connection(super::connection::Connection),
    Process {
        pid: u32,
        name: String,
        exe: Option<String>,
        cmdline: Option<String>,
        parent_pid: Option<u32>,
        user: Option<String>,
        sha256: Option<String>,
    },
    Port {
        proto: String,
        port: u16,
        bind: String,
        pid: Option<u32>,
        process: Option<String>,
        reachability: String,
    },
    Package {
        ecosystem: String,
        name: String,
        version: String,
        purl: Option<String>,
        fixed_version: Option<String>,
    },
    Cve {
        id: String,
        cvss: Option<f32>,
        epss: Option<f32>,
        kev: bool,
        kev_due: Option<String>,
        summary: Option<String>,
        packages: Vec<String>,
    },
    Policy {
        policy_id: String,
        check: String,
        observed: String,
        expected: String,
        result: CheckResult,
    },
    File {
        path: String,
        sha256: Option<String>,
        size: u64,
        rule: Option<String>,
        matched_strings: Vec<String>,
    },
    Flow {
        proto: String,
        local: String,
        remote: String,
        bytes_in: u64,
        bytes_out: u64,
        packets: u64,
        first_seen: String,
        last_seen: String,
        sni: Option<String>,
        domain: Option<String>,
        process: Option<String>,
        period_s: Option<f32>,
    },
    Event {
        event_id: u32,
        channel: String,
        provider: String,
        time: String,
        computer: String,
        data: serde_json::Value,
    },
    Crash {
        kind: String,
        time: String,
        code: Option<String>,
        name: Option<String>,
        module: Option<String>,
        params: Vec<String>,
    },
    /// DNS 查詢（每分鐘聚合的紀錄經規則判斷）。
    Dns {
        name: String,
        registrable: Option<String>,
        process: Option<String>,
        /// 窗內查詢次數。
        queries: u32,
        /// 窗內不同名稱數（通道、DGA 才有）。
        unique_names: Option<u32>,
        window_s: u32,
        first_seen: String,
        samples: Vec<String>,
        /// 情資來源（廠商、清單、信心、網址）。
        sources: Vec<String>,
    },
    Text {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// `f_` + 16 hex；由 `Finding::new` 以 (scanner, rule, evidence_key) 算出。
    pub id: String,
    pub scanner: ScannerId,
    /// 穩定規則名，例 `connections.risky_port`、`intel.ip_match`。hub 用它做自己的 i18n。
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Evidence,
    #[serde(default)]
    pub intel_hits: Vec<IntelHit>,
    pub recommendation: String,
    #[serde(default)]
    pub actions: Vec<ProposedAction>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_by: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub refs: Vec<String>,
}

impl Finding {
    /// 建立 finding；`evidence_key` 必須排除 pid、本地 port 等易變欄位。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scanner: ScannerId,
        rule: &str,
        evidence_key: &str,
        severity: Severity,
        title: impl Into<String>,
        detail: impl Into<String>,
        evidence: Evidence,
        recommendation: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Self::make_id(scanner, rule, evidence_key),
            scanner,
            rule: rule.to_string(),
            severity,
            title: title.into(),
            detail: detail.into(),
            evidence,
            intel_hits: Vec::new(),
            recommendation: recommendation.into(),
            actions: Vec::new(),
            first_seen: now,
            last_seen: now,
            suppressed_by: None,
            tags: Vec::new(),
            refs: Vec::new(),
        }
    }

    pub fn make_id(scanner: ScannerId, rule: &str, evidence_key: &str) -> String {
        stable_id("f", &[scanner.as_str(), rule, evidence_key])
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.iter().any(|t| t == tag) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn with_action(mut self, a: ProposedAction) -> Self {
        self.actions.push(a);
        self
    }

    pub fn with_ref(mut self, url: &str) -> Self {
        self.refs.push(url.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_ignores_volatile_fields() {
        let a = Finding::make_id(ScannerId::Connections, "risky_port", "1.2.3.4:4444|tcp|C:/x.exe");
        let b = Finding::make_id(ScannerId::Connections, "risky_port", "1.2.3.4:4444|tcp|C:/x.exe");
        assert_eq!(a, b);
        assert_ne!(
            a,
            Finding::make_id(ScannerId::Ports, "risky_port", "1.2.3.4:4444|tcp|C:/x.exe")
        );
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::High && Severity::High > Severity::Info);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(ScannerId::parse("traffic"), Some(ScannerId::Traffic));
        assert_eq!(ActionKind::parse("block_ip"), Some(ActionKind::BlockIp));
        assert!(ActionKind::KillProcess.is_destructive());
        assert!(!ActionKind::BlockIp.is_destructive());
    }

    #[test]
    fn evidence_serializes_tagged() {
        let e = Evidence::Text { detail: "x".into() };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "text");
    }
}
