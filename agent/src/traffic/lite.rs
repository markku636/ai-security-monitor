//! flow-lite：不抓封包，只在一段時間內反覆讀 socket 表＋介面計數器。
//! 不需要 Npcap／libpcap 或系統管理員權限；看得到「誰連誰、哪個行程、新出現的連線、介面總流量」，
//! 看不到逐連線位元組、DNS、SNI（那些要 pcap 模式：`ai-security-monitor traffic analyze <file.pcap>`）。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;

use super::summary::{
    plaintext_protocol, IntelRef, ProcessTraffic, Talker, TrafficAlert, TrafficSummary, Window, TOP_N,
};
use crate::connections::{beacon, history, RiskyTable};
use crate::error::{AppError, AppResult};
use crate::intel::IntelDb;
use crate::model::connection::{Connection, Direction};
use crate::util::net::classify;

#[derive(Debug, Clone)]
struct Seen {
    remote: IpAddr,
    port: u16,
    proto: String,
    direction: Direction,
    process: Option<String>,
    first: u32,
    samples: u32,
}

/// 遠端端點（連出看遠端 port；連入看本機 port）。
fn key_of(c: &Connection) -> Option<(IpAddr, u16, String, String)> {
    let ip = c.remote_ip?;
    if !matches!(c.direction, Direction::Outbound | Direction::Inbound) {
        return None;
    }
    let port = if c.direction == Direction::Inbound {
        c.local_port
    } else {
        c.remote_port?
    };
    let proc_name = c.process.as_ref().map(|p| p.name.clone()).unwrap_or_default();
    Some((ip, port, c.proto.clone(), proc_name))
}

fn iface_totals() -> BTreeMap<String, (u64, u64)> {
    let nets = sysinfo::Networks::new_with_refreshed_list();
    nets.iter()
        .map(|(name, d)| (name.clone(), (d.total_received(), d.total_transmitted())))
        .collect()
}

fn is_loopback_iface(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n.starts_with("lo0") || n.contains("loopback")
}

pub async fn sample(
    config_dir: &Path,
    duration: Duration,
    every: Duration,
    intel: Option<Arc<IntelDb>>,
) -> AppResult<TrafficSummary> {
    let started = Utc::now();
    let t0 = Instant::now();
    let before = iface_totals();
    let mut seen: HashMap<(IpAddr, u16, String, String), Seen> = HashMap::new();
    let mut round = 0u32;
    loop {
        let dir = config_dir.to_path_buf();
        // 每輪重新列 socket（不算 exe 雜湊，比較快）
        let snap = tokio::task::spawn_blocking(move || crate::connections::snapshot::take_with(&dir, false))
            .await
            .map_err(|e| AppError::Scan(e.to_string()))??;
        for c in &snap.connections {
            if let Some(k) = key_of(c) {
                let e = seen.entry(k.clone()).or_insert(Seen {
                    remote: k.0,
                    port: k.1,
                    proto: k.2.clone(),
                    direction: c.direction,
                    process: (!k.3.is_empty()).then(|| k.3.clone()),
                    first: round,
                    samples: 0,
                });
                e.samples += 1;
            }
        }
        round += 1;
        if t0.elapsed() + every > duration {
            break;
        }
        tokio::time::sleep(every).await;
    }
    let after = iface_totals();
    let elapsed = t0.elapsed().as_secs_f64();

    let mut s = TrafficSummary {
        mode: "flow-lite".into(),
        source: "live".into(),
        window: Window {
            start: Some(started.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            end: Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            duration_s: (elapsed * 10.0).round() / 10.0,
        },
        ..Default::default()
    };
    for (name, (rx1, tx1)) in &after {
        if is_loopback_iface(name) {
            continue;
        }
        let (rx0, tx0) = before.get(name).copied().unwrap_or((*rx1, *tx1));
        let (rx, tx) = (rx1.saturating_sub(rx0), tx1.saturating_sub(tx0));
        if rx + tx == 0 {
            continue;
        }
        s.totals.bytes_in += rx;
        s.totals.bytes_out += tx;
        s.interfaces.push(super::summary::IfaceTotals {
            name: name.clone(),
            rx_bytes: rx,
            tx_bytes: tx,
        });
    }
    s.interfaces.sort_by_key(|i| std::cmp::Reverse(i.rx_bytes + i.tx_bytes));
    s.totals.bytes = s.totals.bytes_in + s.totals.bytes_out;
    s.totals.flows = seen.len() as u64;

    let risky = RiskyTable::load();
    // 依遠端彙總
    struct Agg {
        ports: BTreeSet<u16>,
        flows: u64,
        procs: BTreeMap<String, u32>,
        new_flows: u64,
    }
    let mut by_remote: BTreeMap<IpAddr, Agg> = BTreeMap::new();
    let mut by_proc: BTreeMap<String, (u64, BTreeSet<IpAddr>)> = BTreeMap::new();
    for v in seen.values() {
        let a = by_remote.entry(v.remote).or_insert(Agg {
            ports: BTreeSet::new(),
            flows: 0,
            procs: BTreeMap::new(),
            new_flows: 0,
        });
        a.ports.insert(v.port);
        a.flows += 1;
        if v.first > 0 {
            a.new_flows += 1;
        }
        if let Some(p) = &v.process {
            *a.procs.entry(p.clone()).or_default() += 1;
            let e = by_proc.entry(p.clone()).or_default();
            e.0 += 1;
            e.1.insert(v.remote);
        }
        if v.direction == Direction::Outbound && classify(v.remote).is_public() {
            let proto_num = if v.proto == "udp" { 17 } else { 6 };
            if let Some(p) = plaintext_protocol(proto_num, v.port) {
                push(
                    &mut s.alerts,
                    "plaintext_protocol",
                    if matches!(p, "Telnet" | "FTP" | "r-services") {
                        "high"
                    } else {
                        "low"
                    },
                    v,
                    format!("{p} · {}", v.process.clone().unwrap_or_default()),
                );
            }
            if let Some(rp) = risky.outbound(&v.proto, v.port) {
                push(
                    &mut s.alerts,
                    "unusual_port",
                    "medium",
                    v,
                    format!("{}/{} {} — {}", v.proto, v.port, rp.name, rp.rationale),
                );
            }
        }
    }
    let mut talkers: Vec<Talker> = by_remote
        .into_iter()
        .map(|(ip, a)| {
            let hits = match &intel {
                Some(db) if classify(ip).is_public() => db.match_ip(ip, a.ports.iter().next().copied()),
                _ => Vec::new(),
            };
            if !hits.is_empty() {
                s.alerts.push(TrafficAlert {
                    kind: "intel_match".into(),
                    severity: if hits.iter().any(|h| h.confidence >= 80) {
                        "high"
                    } else {
                        "medium"
                    }
                    .into(),
                    remote: ip.to_string(),
                    port: a.ports.iter().next().copied(),
                    detail: a.procs.keys().next().cloned().unwrap_or_default(),
                    intel: hits.iter().map(IntelRef::from).collect(),
                });
            }
            Talker {
                remote: ip.to_string(),
                domain: None,
                ports: a.ports.into_iter().take(8).collect(),
                bytes_out: 0,
                bytes_in: 0,
                flows: a.flows,
                process: a.procs.into_iter().max_by_key(|(_, n)| *n).map(|(p, _)| p),
                intel: hits.iter().map(IntelRef::from).collect(),
            }
        })
        .collect();
    talkers.sort_by(|a, b| {
        b.intel
            .len()
            .cmp(&a.intel.len())
            .then(b.flows.cmp(&a.flows))
            .then(a.remote.cmp(&b.remote))
    });
    talkers.truncate(TOP_N);
    s.top_talkers = talkers;
    let mut procs: Vec<ProcessTraffic> = by_proc
        .into_iter()
        .map(|(process, (connections, remotes))| ProcessTraffic {
            process,
            connections,
            remotes: remotes.len() as u64,
        })
        .collect();
    procs.sort_by(|a, b| b.connections.cmp(&a.connections).then(a.process.cmp(&b.process)));
    procs.truncate(TOP_N);
    s.per_process = procs;

    // 週期性連線：用 ai-security-monitor 累積的 24 小時連線歷史
    let now = Utc::now().timestamp() as u64;
    if let Ok(hist) = history::load(config_dir, now.saturating_sub(history::RETENTION_SECS)) {
        for b in beacon::detect(&hist, now) {
            let (exe, ep) = b.pair.split_once('|').unwrap_or(("", b.pair.as_str()));
            let (remote, port) = ep
                .rsplit_once(':')
                .map(|(r, p)| (r.to_string(), p.parse().ok()))
                .unwrap_or((ep.to_string(), None));
            s.alerts.push(TrafficAlert {
                kind: "beaconing".into(),
                severity: "medium".into(),
                remote,
                port,
                detail: format!(
                    "period ≈ {:.0}s, jitter {:.2}, {} times · {}",
                    b.period_s, b.jitter, b.observations, exe
                ),
                intel: vec![],
            });
        }
    }
    s.alerts.sort_by(|a, b| {
        sev(&b.severity)
            .cmp(&sev(&a.severity))
            .then(a.kind.cmp(&b.kind))
            .then(a.remote.cmp(&b.remote))
    });
    s.alerts.truncate(100);
    s.notes.push(
        "flow-lite: socket table sampling only; per-connection bytes, DNS and TLS SNI need packet capture (ai-security-monitor traffic analyze <file.pcap>)".into(),
    );
    if intel.is_none() {
        s.notes
            .push("threat intel not loaded (run `ai-security-monitor intel update`)".into());
    }
    Ok(s)
}

fn sev(s: &str) -> u8 {
    match s {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

fn push(v: &mut Vec<TrafficAlert>, kind: &str, severity: &str, s: &Seen, detail: String) {
    let remote = s.remote.to_string();
    if v.iter()
        .any(|a| a.kind == kind && a.remote == remote && a.port == Some(s.port))
    {
        return;
    }
    v.push(TrafficAlert {
        kind: kind.into(),
        severity: severity.into(),
        remote,
        port: Some(s.port),
        detail,
        intel: vec![],
    });
}
