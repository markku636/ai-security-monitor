//! 連線分類：風險 port、shell 帶網路、暫存目錄行程、曝露 listener、beacon、known-good、白名單 →
//! 每條連線的 `Verdict`，以及要上報的 Finding。

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::beacon::BeaconCandidate;
use super::snapshot::SnapshotResult;
use crate::model::allowlist::Allowlist;
use crate::model::baseline::Baseline;
use crate::model::connection::{Connection, Direction, Listener};
use crate::model::finding::{ActionKind, Evidence, Finding, ProposedAction, ScannerId, Severity};
use crate::model::verdict::{AnomalyKind, Reason, Verdict};
use crate::util::net::{classify, IpClass};

// ---------------------------------------------------------------- risky ports

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RiskyPort {
    pub port: u16,
    pub proto: String,
    pub name: String,
    pub severity: Severity,
    /// `listening` | `outbound` | `any`
    pub direction: String,
    pub rationale: String,
}

#[derive(Debug, Default, Deserialize)]
struct RiskyFile {
    #[serde(default)]
    ports: Vec<RiskyPort>,
}

#[derive(Debug, Default, Clone)]
pub struct RiskyTable {
    by_key: HashMap<(String, u16), RiskyPort>,
}

impl RiskyTable {
    pub fn load() -> Self {
        let text = crate::embedded::feeds_file("vuln/risky-ports.json").unwrap_or("{}");
        let file: RiskyFile = serde_json::from_str(text).unwrap_or_default();
        let mut by_key = HashMap::new();
        for p in file.ports {
            by_key.insert((p.proto.clone(), p.port), p);
        }
        Self { by_key }
    }

    pub fn listening(&self, proto: &str, port: u16) -> Option<&RiskyPort> {
        self.by_key
            .get(&(proto.to_string(), port))
            .filter(|p| p.direction == "listening" || p.direction == "any")
    }

    pub fn outbound(&self, proto: &str, port: u16) -> Option<&RiskyPort> {
        self.by_key
            .get(&(proto.to_string(), port))
            .filter(|p| p.direction == "outbound" || p.direction == "any")
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

// ---------------------------------------------------------------- known-good

#[derive(Debug, Clone, Deserialize)]
pub struct KnownGoodList {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub kind: String,
    pub source_url: String,
    #[serde(default)]
    pub entries: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct KnownGoodFile {
    #[serde(default)]
    lists: Vec<KnownGoodList>,
}

#[derive(Debug, Default, Clone)]
pub struct KnownGood {
    cidrs: Vec<(IpNet, String)>,
    domains: Vec<(String, String)>,
}

impl KnownGood {
    pub fn load() -> Self {
        let text = crate::embedded::feeds_file("known-good.json").unwrap_or("{}");
        let file: KnownGoodFile = serde_json::from_str(text).unwrap_or_default();
        let mut kg = KnownGood::default();
        for l in file.lists {
            for e in &l.entries {
                if l.kind == "cidr" {
                    if let Ok(n) = e.parse::<IpNet>() {
                        kg.cidrs.push((n, l.name.clone()));
                    }
                } else {
                    kg.domains.push((e.to_ascii_lowercase(), l.name.clone()));
                }
            }
        }
        kg
    }

    pub fn match_ip(&self, ip: IpAddr) -> Option<&str> {
        self.cidrs
            .iter()
            .find(|(n, _)| n.contains(&ip))
            .map(|(_, name)| name.as_str())
    }

    /// 網段與任何已知良性網段重疊（互相包含）。
    pub fn overlaps_net(&self, net: &IpNet) -> Option<&str> {
        self.cidrs
            .iter()
            .find(|(n, _)| n.contains(&net.network()) || net.contains(&n.network()))
            .map(|(_, name)| name.as_str())
    }

    pub fn match_domain(&self, domain: &str) -> Option<&str> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        self.domains
            .iter()
            .find(|(pat, _)| match pat.strip_prefix("*.") {
                Some(suffix) => d.ends_with(&format!(".{suffix}")),
                None => d == *pat,
            })
            .map(|(_, name)| name.as_str())
    }
}

// ---------------------------------------------------------------- heuristics

/// 常被濫用來開反向 shell / 下載執行的程式（小寫、不含副檔名）。
pub const SHELL_HOSTS: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd",
    "bash",
    "sh",
    "zsh",
    "dash",
    "fish",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "certutil",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "bitsadmin",
    "msbuild",
    "installutil",
    "cmstp",
    "wmic",
    "telnet",
];

const TEMP_DIR_MARKERS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/temp/",
    "/appdata/local/temp/",
    "/windows/temp/",
    "/downloads/",
];

fn base_name_lower(exe_or_name: &str) -> String {
    let p = exe_or_name.replace('\\', "/");
    let base = p.rsplit('/').next().unwrap_or(&p).to_ascii_lowercase();
    base.strip_suffix(".exe").map(|s| s.to_string()).unwrap_or(base)
}

pub fn is_shell_host(name: &str) -> bool {
    let b = base_name_lower(name);
    // python3.12 → python3
    let b = b.split(['.', '-']).next().unwrap_or(&b).to_string();
    SHELL_HOSTS.contains(&b.as_str())
}

pub fn is_temp_dir(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    TEMP_DIR_MARKERS.iter().any(|m| p.contains(m))
}

// ---------------------------------------------------------------- classifier

pub struct Classifier {
    pub risky: RiskyTable,
    pub known_good: KnownGood,
}

impl Classifier {
    pub fn load() -> Self {
        Self {
            risky: RiskyTable::load(),
            known_good: KnownGood::load(),
        }
    }

    /// 替每條連線算判定，並產生 finding。
    pub fn annotate(
        &self,
        snap: &mut SnapshotResult,
        allowlist: &Allowlist,
        baseline: Option<&Baseline>,
        beacons: &[BeaconCandidate],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for c in snap.connections.iter_mut() {
            let mut reasons: Vec<Reason> = Vec::new();
            let exe = c.process.as_ref().and_then(|p| p.exe.clone());
            let pname = c.process.as_ref().map(|p| p.name.clone()).unwrap_or_default();

            if let Some(exe) = &exe {
                if let Some(e) = allowlist.match_process_path(exe) {
                    reasons.push(Reason::Allowlisted { entry_id: e.id.clone() });
                }
            }

            match c.direction {
                Direction::Listening | Direction::Local => {}
                Direction::Outbound | Direction::Inbound => {
                    if let (Some(ip), Some(port)) = (c.remote_ip, c.remote_port) {
                        if let Some(e) = allowlist.match_ip(ip) {
                            reasons.push(Reason::Allowlisted { entry_id: e.id.clone() });
                        }
                        match classify(ip) {
                            IpClass::Loopback => reasons.push(Reason::Loopback),
                            IpClass::Private | IpClass::LinkLocal => reasons.push(Reason::PrivateNetwork),
                            IpClass::Public => {
                                if let Some(list) = self.known_good.match_ip(ip) {
                                    reasons.push(Reason::KnownGood {
                                        list: list.to_string(),
                                        detail: ip.to_string(),
                                    });
                                }
                            }
                            _ => {}
                        }
                        let public = classify(ip).is_public();
                        if c.direction == Direction::Outbound {
                            if let Some(r) = self.risky.outbound(&c.proto, port) {
                                reasons.push(Reason::Anomaly {
                                    kind: AnomalyKind::RiskyPort,
                                    detail: format!("{} ({})", r.name, port),
                                });
                                if public || classify(ip) == IpClass::Private {
                                    findings.push(risky_outbound_finding(c, r));
                                }
                            }
                            if public && is_shell_host(exe.as_deref().unwrap_or(&pname)) {
                                reasons.push(Reason::Anomaly {
                                    kind: AnomalyKind::ShellWithNetwork,
                                    detail: pname.clone(),
                                });
                                findings.push(shell_finding(c));
                            }
                        }
                        if let Some(exe) = &exe {
                            if is_temp_dir(exe) && (public || c.direction == Direction::Inbound) {
                                reasons.push(Reason::Anomaly {
                                    kind: AnomalyKind::TempDirProcess,
                                    detail: exe.clone(),
                                });
                                findings.push(temp_dir_finding(c));
                            }
                        }
                        if c.direction == Direction::Outbound && public {
                            let pair = format!("{}|{}:{}", exe.clone().unwrap_or_else(|| pname.clone()), ip, port);
                            if let Some(b) = beacons.iter().find(|b| b.pair == pair) {
                                reasons.push(Reason::Anomaly {
                                    kind: AnomalyKind::Beaconing,
                                    detail: format!(
                                        "period {:.0}s, jitter {:.2}, n={}",
                                        b.period_s, b.jitter, b.observations
                                    ),
                                });
                                findings.push(beacon_finding(c, b));
                            }
                            if let Some(base) = baseline {
                                let dest = format!("{ip}:{port}");
                                if !base.destinations.contains(&dest) {
                                    reasons.push(Reason::Anomaly {
                                        kind: AnomalyKind::NewDestination,
                                        detail: dest,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            c.verdict = Verdict::compute(reasons);
        }

        // listener：曝露在非 loopback 介面的高風險服務。
        for l in &snap.listeners {
            if !l.exposed {
                continue;
            }
            let in_baseline = baseline
                .map(|b| b.listeners.iter().any(|bl| bl.proto == l.proto && bl.port == l.port))
                .unwrap_or(true);
            if let Some(r) = self.risky.listening(&l.proto, l.port) {
                if allowlist
                    .match_rule("connections.exposed_listener", Some(l.port))
                    .is_none()
                {
                    let mut f = exposed_listener_finding(l, r);
                    if !in_baseline {
                        f = f.with_tag("new");
                    }
                    findings.push(f);
                }
            } else if !in_baseline && baseline.is_some() {
                findings.push(new_listener_finding(l));
            }
        }

        // 把 listener 的 verdict 也標一下（曝露的風險 port → suspicious 旗標）。
        for c in snap.connections.iter_mut() {
            if c.direction == Direction::Listening {
                let exposed = c.local_ip.is_unspecified() || classify(c.local_ip) != IpClass::Loopback;
                let mut reasons = Vec::new();
                if !exposed {
                    reasons.push(Reason::Loopback);
                } else if let Some(r) = self.risky.listening(&c.proto, c.local_port) {
                    reasons.push(Reason::Anomaly {
                        kind: AnomalyKind::ExposedListener,
                        detail: format!("{} ({})", r.name, c.local_port),
                    });
                }
                c.verdict = Verdict::compute(reasons);
            }
        }

        findings
    }
}

// ---------------------------------------------------------------- finding builders

fn conn_evidence(c: &Connection) -> Evidence {
    Evidence::Connection(c.clone())
}

fn process_label(c: &Connection) -> String {
    c.process
        .as_ref()
        .map(|p| format!("{} (pid {})", p.name, p.pid))
        .unwrap_or_else(|| t!("未知行程").to_string())
}

fn risky_outbound_finding(c: &Connection, r: &RiskyPort) -> Finding {
    let sev = if r.severity >= Severity::High {
        Severity::High
    } else {
        Severity::Medium
    };
    Finding::new(
        ScannerId::Connections,
        "connections.risky_port_outbound",
        &c.evidence_key(),
        sev,
        tf!(
            "對外連到高風險 port {port}（{name}）",
            port = c.remote_port.unwrap_or(0),
            name = r.name
        ),
        tf!(
            "{process} 連到 {remote}：{rationale}",
            process = process_label(c),
            remote = c.remote_display(),
            rationale = r.rationale
        ),
        conn_evidence(c),
        t!("確認該行程是否應有此連線；若非預期，封鎖目的地並檢查該行程"),
    )
    .with_action(block_ip_action(c))
}

fn shell_finding(c: &Connection) -> Finding {
    Finding::new(
        ScannerId::Connections,
        "connections.shell_with_network",
        &c.evidence_key(),
        Severity::High,
        tf!("Shell / 腳本程式有對外連線：{process}", process = process_label(c)),
        tf!(
            "{process} 連到公網 {remote}；這類程式對外連線常見於反向 shell 或惡意下載",
            process = process_label(c),
            remote = c.remote_display()
        ),
        conn_evidence(c),
        t!("檢查該行程的命令列與父行程；非預期則終止並封鎖目的地"),
    )
    .with_action(block_ip_action(c))
}

fn temp_dir_finding(c: &Connection) -> Finding {
    Finding::new(
        ScannerId::Connections,
        "connections.temp_dir_process",
        &c.evidence_key(),
        Severity::Medium,
        tf!("暫存／下載目錄的程式有網路連線：{process}", process = process_label(c)),
        tf!(
            "執行檔位於暫存或下載目錄，並連到 {remote}；惡意程式常從這類位置執行",
            remote = c.remote_display()
        ),
        conn_evidence(c),
        t!("確認該執行檔來源與雜湊；非預期則隔離檔案並封鎖目的地"),
    )
    .with_action(block_ip_action(c))
}

fn beacon_finding(c: &Connection, b: &BeaconCandidate) -> Finding {
    Finding::new(
        ScannerId::Connections,
        "connections.beaconing",
        &c.evidence_key(),
        Severity::Medium,
        tf!("規律回連（疑似 beacon）：{remote}", remote = c.remote_display()),
        tf!(
            "{process} 每約 {period} 秒重新連到 {remote}（{n} 次，抖動 {jitter}）；C2 常以固定週期回報",
            process = process_label(c),
            period = format!("{:.0}", b.period_s),
            remote = c.remote_display(),
            n = b.observations,
            jitter = format!("{:.2}", b.jitter)
        ),
        conn_evidence(c),
        t!("用 AI 解讀此目的地與行程；非已知服務則封鎖並進一步鑑識"),
    )
    .with_tag("beacon")
    .with_action(block_ip_action(c))
}

fn exposed_listener_finding(l: &Listener, r: &RiskyPort) -> Finding {
    let bind = if l.bind_ip.is_unspecified() {
        "0.0.0.0/::".to_string()
    } else {
        l.bind_ip.to_string()
    };
    let key = format!(
        "{}:{}:{}",
        l.proto,
        l.port,
        if l.bind_ip.is_unspecified() { "any" } else { "iface" }
    );
    Finding::new(
        ScannerId::Connections,
        "connections.exposed_listener",
        &key,
        r.severity,
        tf!(
            "{name}（{proto} {port}）對外監聽",
            name = r.name,
            proto = l.proto,
            port = l.port
        ),
        tf!(
            "{process} 綁在 {bind}：{rationale}",
            process = l
                .process
                .as_ref()
                .map(|p| format!("{} (pid {})", p.name, p.pid))
                .unwrap_or_else(|| t!("未知行程").to_string()),
            bind = bind,
            rationale = r.rationale
        ),
        Evidence::Port {
            proto: l.proto.clone(),
            port: l.port,
            bind,
            pid: l.process.as_ref().map(|p| p.pid),
            process: l.process.as_ref().map(|p| p.name.clone()),
            reachability: "unknown".into(),
        },
        t!("若不需對外提供，改綁 127.0.0.1 或用防火牆只允許特定來源"),
    )
    .with_tag("exposed")
    .with_action(ProposedAction {
        kind: ActionKind::ClosePort,
        params: serde_json::json!({ "proto": l.proto, "port": l.port, "direction": "inbound" }),
        requires_elevation: true,
        destructive: false,
        reversible: true,
        description: tf!("以防火牆封鎖對內 {proto} {port}", proto = l.proto, port = l.port),
    })
}

fn new_listener_finding(l: &Listener) -> Finding {
    let key = format!("{}:{}:new", l.proto, l.port);
    Finding::new(
        ScannerId::Connections,
        "connections.new_listener",
        &key,
        Severity::Low,
        tf!("基準線外的新 listener：{proto} {port}", proto = l.proto, port = l.port),
        tf!(
            "{process} 開始監聽 {proto} {port}，基準線中沒有這個 port",
            process = l
                .process
                .as_ref()
                .map(|p| format!("{} (pid {})", p.name, p.pid))
                .unwrap_or_else(|| t!("未知行程").to_string()),
            proto = l.proto,
            port = l.port
        ),
        Evidence::Port {
            proto: l.proto.clone(),
            port: l.port,
            bind: l.bind_ip.to_string(),
            pid: l.process.as_ref().map(|p| p.pid),
            process: l.process.as_ref().map(|p| p.name.clone()),
            reachability: "unknown".into(),
        },
        t!("確認是否為預期服務；是則執行 asa baseline save --yes 納入基準線"),
    )
    .with_tag("new")
}

fn block_ip_action(c: &Connection) -> ProposedAction {
    let ip = c.remote_ip.map(|i| i.to_string()).unwrap_or_default();
    ProposedAction {
        kind: ActionKind::BlockIp,
        params: serde_json::json!({ "ip": ip, "direction": "both", "reason": c.evidence_key() }),
        requires_elevation: true,
        destructive: false,
        reversible: true,
        description: tf!("以防火牆封鎖 {ip}（雙向）", ip = ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::connection::ProcessRef;

    fn conn(remote: &str, port: u16, exe: &str, dir: Direction) -> Connection {
        Connection {
            proto: "tcp".into(),
            local_ip: "192.168.1.10".parse().unwrap(),
            local_port: 51000,
            remote_ip: Some(remote.parse().unwrap()),
            remote_port: Some(port),
            state: "ESTABLISHED".into(),
            direction: dir,
            process: Some(ProcessRef {
                pid: 42,
                name: base_name_lower(exe),
                exe: Some(exe.into()),
                ..Default::default()
            }),
            geo: None,
            verdict: Verdict::default(),
            bytes_in: None,
            bytes_out: None,
        }
    }

    #[test]
    fn risky_table_and_heuristics() {
        let t = RiskyTable::load();
        assert!(!t.is_empty());
        assert!(t.listening("tcp", 3389).is_some());
        assert!(t.outbound("tcp", 3389).is_none());
        assert!(t.outbound("tcp", 4444).is_some());
        assert!(is_shell_host(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ));
        assert!(is_shell_host("/usr/bin/python3.12"));
        assert!(!is_shell_host("chrome.exe"));
        assert!(is_temp_dir("C:\\Users\\x\\AppData\\Local\\Temp\\a.exe"));
        assert!(is_temp_dir("/tmp/x"));
        assert!(!is_temp_dir("/usr/bin/curl"));
    }

    #[test]
    fn known_good_dns_is_safe_and_shell_to_public_is_suspicious() {
        let cl = Classifier::load();
        let mut snap = SnapshotResult {
            connections: vec![
                conn("8.8.8.8", 53, "/usr/bin/systemd-resolved", Direction::Outbound),
                conn(
                    "185.199.108.9",
                    443,
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    Direction::Outbound,
                ),
                conn("185.199.108.10", 4444, "/tmp/payload", Direction::Outbound),
                conn("10.0.0.5", 445, "/usr/sbin/smbd", Direction::Inbound),
            ],
            ..Default::default()
        };
        let findings = cl.annotate(&mut snap, &Allowlist::default(), None, &[]);
        assert_eq!(
            snap.connections[0].verdict.level,
            crate::model::verdict::VerdictLevel::Safe
        );
        assert_eq!(
            snap.connections[1].verdict.level,
            crate::model::verdict::VerdictLevel::Suspicious
        );
        assert_eq!(
            snap.connections[2].verdict.level,
            crate::model::verdict::VerdictLevel::Suspicious
        );
        assert_eq!(
            snap.connections[3].verdict.level,
            crate::model::verdict::VerdictLevel::Safe
        );
        let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(rules.contains(&"connections.shell_with_network"));
        assert!(rules.contains(&"connections.risky_port_outbound"));
        assert!(rules.contains(&"connections.temp_dir_process"));
        assert!(findings.iter().all(|f| !f.actions.is_empty()));
    }

    #[test]
    fn allowlisted_ip_wins() {
        let cl = Classifier::load();
        let mut al = Allowlist::default();
        al.add(None, "185.199.108.9", None).unwrap();
        let mut snap = SnapshotResult {
            connections: vec![conn("185.199.108.9", 4444, "/tmp/payload", Direction::Outbound)],
            ..Default::default()
        };
        cl.annotate(&mut snap, &al, None, &[]);
        assert_eq!(
            snap.connections[0].verdict.level,
            crate::model::verdict::VerdictLevel::Safe
        );
    }

    #[test]
    fn exposed_risky_listener_yields_finding() {
        let cl = Classifier::load();
        let mut snap = SnapshotResult {
            listeners: vec![Listener {
                proto: "tcp".into(),
                bind_ip: "0.0.0.0".parse().unwrap(),
                port: 6379,
                process: None,
                exposed: true,
                reachability: None,
            }],
            ..Default::default()
        };
        let f = cl.annotate(&mut snap, &Allowlist::default(), None, &[]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "connections.exposed_listener");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(matches!(f[0].actions[0].kind, ActionKind::ClosePort));
    }
}
