//! agent ↔ hub 的 JSON 契約範例：`contract/*.v1.json`（repo 根目錄）。
//! Rust 測試確認序列化結果與檔案一致；hub 的測試用 zod 驗證同一份檔案 → 任一邊改格式 CI 都會擋。
//! 有意改格式時：`ASA_UPDATE_CONTRACT=1 cargo test contract` 重新產生，並同步更新 hub 的 schema。

use chrono::{TimeZone, Utc};
use serde_json::json;

use super::connection::{Connection, Direction, GeoInfo, Listener, ProcessRef, Reachability};
use super::finding::{ActionKind, Evidence, Finding, IntelHit, ProposedAction, ScannerId, Severity};
use super::report::{AgentInfo, InventorySummary, OsInfo, Report, Scores, Summaries};
use super::verdict::{AnomalyKind, Reason, Verdict, VerdictLevel};

fn t(h: u32, m: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 16, h, m, 0).unwrap()
}

pub fn sample_agent() -> AgentInfo {
    AgentInfo {
        id: "0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee".into(),
        version: "0.1.0".into(),
        hostname: "demo-host".into(),
        os: OsInfo {
            family: "windows".into(),
            name: Some("Windows".into()),
            version: Some("11 (26200)".into()),
            build: Some("Windows 11 Pro".into()),
            kernel: Some("26200".into()),
        },
        arch: "x86_64".into(),
        ips: vec!["192.0.2.10".into()],
        uptime_s: Some(3600),
        elevated: false,
        scanners_available: vec![
            ScannerId::Connections,
            ScannerId::Intel,
            ScannerId::Firewall,
            ScannerId::Ports,
        ],
    }
}

fn sample_hit() -> IntelHit {
    IntelHit {
        feed_id: "abusech-feodo".into(),
        name: "Feodo Tracker (recommended)".into(),
        vendor: "abuse.ch".into(),
        confidence: 90,
        license: "CC0 1.0".into(),
        license_url: "https://creativecommons.org/publicdomain/zero/1.0/".into(),
        attribution_required: false,
        fetched_at: t(9, 0),
        source_url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt".into(),
        matched: "203.0.113.66".into(),
        extra: json!({ "commercial_ok": true, "feed_direction": "outbound" }),
    }
}

pub fn sample_connection() -> Connection {
    let hit = sample_hit();
    Connection {
        proto: "tcp".into(),
        local_ip: "192.0.2.10".parse().unwrap(),
        local_port: 51234,
        remote_ip: Some("203.0.113.66".parse().unwrap()),
        remote_port: Some(443),
        state: "ESTABLISHED".into(),
        direction: Direction::Outbound,
        process: Some(ProcessRef {
            pid: 4242,
            name: "updater.exe".into(),
            exe: Some("C:\\Users\\demo\\AppData\\Local\\Temp\\updater.exe".into()),
            cmdline: None,
            parent_pid: Some(1000),
            user: Some("demo".into()),
            sha256: Some("0".repeat(64)),
        }),
        geo: Some(GeoInfo {
            country: Some("NL".into()),
            asn: Some(64500),
            org: Some("Example Hosting".into()),
        }),
        verdict: Verdict {
            level: VerdictLevel::Dangerous,
            reasons: vec![
                Reason::Anomaly {
                    kind: AnomalyKind::TempDirProcess,
                    detail: "C:\\Users\\demo\\AppData\\Local\\Temp\\updater.exe".into(),
                },
                Reason::IntelHit(Box::new(hit)),
            ],
        },
        bytes_in: None,
        bytes_out: None,
    }
}

pub fn sample_listener() -> Listener {
    Listener {
        proto: "tcp".into(),
        bind_ip: "0.0.0.0".parse().unwrap(),
        port: 6379,
        process: Some(ProcessRef {
            pid: 900,
            name: "redis-server".into(),
            ..Default::default()
        }),
        exposed: true,
        reachability: Some(Reachability::Open { rule: None }),
    }
}

pub fn sample_report() -> Report {
    let c = sample_connection();
    let mut intel = Finding::new(
        ScannerId::Intel,
        "intel.outbound_match",
        &c.evidence_key(),
        Severity::Critical,
        "連到威脅情資列名的 IP：203.0.113.66",
        "updater.exe (pid 4242) ↔ 203.0.113.66:443（判定：危險）。來源：abuse.ch Feodo Tracker (recommended)（CC0 1.0，90%）",
        Evidence::Connection(c.clone()),
        "封鎖此 IP 並檢查相關行程；確認是誤判可加入白名單",
    )
    .with_tag("intel")
    .with_action(ProposedAction {
        kind: ActionKind::BlockIp,
        params: json!({ "ip": "203.0.113.66", "direction": "both", "reason": "abusech-feodo" }),
        requires_elevation: true,
        destructive: false,
        reversible: true,
        description: "以防火牆封鎖 203.0.113.66（雙向）".into(),
    })
    .with_ref("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt");
    intel.intel_hits = vec![sample_hit()];
    intel.first_seen = t(9, 30);
    intel.last_seen = t(9, 30);

    let mut port = Finding::new(
        ScannerId::Ports,
        "ports.exposed_open",
        "tcp:6379",
        Severity::Critical,
        "Redis（tcp 6379）可從網路連入",
        "redis-server (pid 900) 綁在 0.0.0.0/::，防火牆沒有阻擋",
        Evidence::Port {
            proto: "tcp".into(),
            port: 6379,
            bind: "0.0.0.0/::".into(),
            pid: Some(900),
            process: Some("redis-server".into()),
            reachability: "open".into(),
        },
        "不需對外就改綁 127.0.0.1",
    )
    .with_tag("exposed");
    port.first_seen = t(9, 30);
    port.last_seen = t(9, 30);

    Report {
        schema_version: 1,
        report_id: "7d3f1b2a-0c4e-4f5a-8b6c-9d0e1f2a3b4c".into(),
        agent: sample_agent(),
        started_at: t(9, 29),
        finished_at: t(9, 30),
        scanners_run: vec![
            ScannerId::Connections,
            ScannerId::Intel,
            ScannerId::Firewall,
            ScannerId::Ports,
        ],
        warnings: vec!["部分 socket 無法對應到行程（需要系統管理員權限）".into()],
        findings: vec![intel, port],
        inventory: InventorySummary {
            packages: 0,
            by_ecosystem: Default::default(),
            listeners: 12,
            connections: 85,
            processes_with_network: 9,
        },
        summaries: Summaries::default(),
        baseline: None,
        score: Scores {
            overall: 52,
            connections: 75,
            exposure: 75,
            vulns: 100,
            hardening: 100,
        },
        partial: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn contract_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("contract")
    }

    fn check(name: &str, value: serde_json::Value) {
        let path = contract_dir().join(name);
        if std::env::var("ASA_UPDATE_CONTRACT").as_deref() == Ok("1") {
            std::fs::create_dir_all(contract_dir()).unwrap();
            std::fs::write(&path, serde_json::to_string_pretty(&value).unwrap() + "\n").unwrap();
            return;
        }
        let on_disk: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing {}; run ASA_UPDATE_CONTRACT=1 cargo test contract",
                path.display()
            )
        }))
        .unwrap();
        assert_eq!(
            on_disk, value,
            "{name} drifted from the Rust models; regenerate with ASA_UPDATE_CONTRACT=1 cargo test contract and update hub/lib/ingest/schema.ts"
        );
    }

    #[test]
    fn contract_report_v1() {
        check("report.v1.json", serde_json::to_value(sample_report()).unwrap());
    }

    #[test]
    fn contract_snapshot_v1() {
        check(
            "snapshot.v1.json",
            json!({
                "agent_id": sample_agent().id,
                "ts": t(9, 31),
                "connections": [sample_connection()],
                "listeners": [sample_listener()],
            }),
        );
    }

    #[test]
    fn contract_register_v1() {
        check(
            "register.v1.json",
            json!({
                "agent": sample_agent(),
                "accept_remote_actions": false,
                "service_mode": false,
            }),
        );
    }
}
