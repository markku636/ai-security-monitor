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
            product_type: Some("workstation".into()),
            installation_type: Some("Client".into()),
            edition: Some("Professional".into()),
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
        domain: None,
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
        let payload = crate::hub::contract::SnapshotPayload {
            agent_id: sample_agent().id,
            ts: t(9, 31),
            connections: vec![sample_connection()],
            listeners: vec![sample_listener()],
            dns_names: [("203.0.113.66".to_string(), vec!["updates.example.net".to_string()])].into(),
        };
        check("snapshot.v1.json", serde_json::to_value(payload).unwrap());
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

    /// 網路流量與效能樣本（`POST /api/v1/ingest/metrics`）。
    #[test]
    fn contract_metrics_v1() {
        check(
            "metrics.v1.json",
            serde_json::to_value(crate::metrics::sample_batch()).unwrap(),
        );
    }

    /// DNS 查詢紀錄（`POST /api/v1/ingest/dns`）。
    #[test]
    fn contract_dns_v1() {
        check(
            "dns.v1.json",
            serde_json::to_value(crate::dns::queue::sample_batch()).unwrap(),
        );
    }

    /// 防護 DNS 的查詢紀錄與心跳（`POST /api/v1/dns/queries`、`/api/v1/dns/heartbeat`）。
    #[cfg(feature = "dns-server")]
    #[test]
    fn contract_dns_server_v1() {
        check(
            "dns-resolver.v1.json",
            serde_json::to_value(crate::dnsd::hub::sample_batch()).unwrap(),
        );
        check(
            "dns-heartbeat.v1.json",
            serde_json::to_value(crate::dnsd::hub::sample_heartbeat()).unwrap(),
        );
    }

    /// 免金鑰加入申請。`hub-identity.v1.json`／`enroll-status.v1.json` 帶真的簽章（測試專用金鑰），
    /// 由 hub 那邊產生，這裡只驗（`hub::identity`、`hub::enroll` 的測試）。
    #[test]
    fn contract_enroll_request_v1() {
        let p = crate::hub::enroll::EnrollRequestPayload {
            agent: sample_agent(),
            accept_remote_actions: false,
            request_secret: "Zm9vYmFyLXRlc3Qtb25seS1yZXF1ZXN0LXNlY3JldDE".into(),
            hub_fingerprint: Some("72AS-YEXT-VNGO-NLC5-W2NM".into()),
        };
        check("enroll-request.v1.json", serde_json::to_value(p).unwrap());
    }

    /// 網站掃描 runner 送給 Hub 的認領、心跳、結果（`POST /api/v1/webscan/jobs/…`）。
    #[cfg(feature = "web-scan-runner")]
    #[test]
    fn contract_webscan_v1() {
        check(
            "webscan-claim.v1.json",
            serde_json::to_value(crate::webscan::sample_claim()).unwrap(),
        );
        check(
            "webscan-heartbeat.v1.json",
            serde_json::to_value(crate::webscan::sample_heartbeat()).unwrap(),
        );
        check(
            "webscan-result.v1.json",
            serde_json::to_value(crate::webscan::sample_result()).unwrap(),
        );
    }

    /// 工作內容（`webscan-job.v1.json`）由 Hub 產生，這裡只驗 runner 讀得懂、結構檢查會過。
    /// 範例的釘選位址是文件用網段（203.0.113.10），runner 的範圍檢查本來就會擋（`blocked_target:reserved`）；
    /// 換成公網位址後兩個工作都要通過完整檢查。
    #[cfg(feature = "web-scan-runner")]
    #[test]
    fn contract_webscan_job_v1_parses() {
        use crate::webscan::job;
        let text = std::fs::read_to_string(contract_dir().join("webscan-job.v1.json")).unwrap();
        let resp: crate::webscan::ClaimResponse = serde_json::from_str(&text).unwrap();
        assert_eq!(resp.jobs.len(), 2);
        assert_eq!(resp.poll_after_ms, Some(15_000));
        assert!(resp.server_time.is_some());
        let kinds: Vec<job::JobKind> = resp
            .jobs
            .iter()
            .map(|j| job::decode(j.clone()).expect("structure").raw.kind)
            .collect();
        assert_eq!(kinds, vec![job::JobKind::Scan, job::JobKind::Verify]);
        for j in &resp.jobs {
            assert!(job::job_id(j).is_some());
            assert_eq!(
                job::parse(j.clone(), &[]).unwrap_err(),
                job::Rejection::Blocked(crate::webscan::scope::Blocked::Reserved)
            );
            let mut public = j.clone();
            public["target"]["pinned_ips"] = json!(["8.8.8.8"]);
            let parsed = job::parse(public, &[]).expect("passes with a public pinned ip");
            assert_eq!(parsed.target.url(), "https://shop.example.com/");
        }
    }
}
