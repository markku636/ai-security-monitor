//! 流量摘要（給人看、給 hub、也給 LLM；整份控制在約 40 KB 內）與偵測：
//! 明文協定、異常 port、大量上傳、週期性連線（beacon）、可疑 DNS、情資命中。

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::flow::{Flow, FlowTable};
use super::proto::qtype_name;
use crate::connections::classify::RiskyTable;
use crate::intel::IntelDb;
use crate::model::finding::IntelHit;
use crate::util::net::classify;

pub const TOP_N: usize = 15;
pub const DNS_N: usize = 50;
pub const NAMES_N: usize = 30;
/// 大量上傳：送出超過 50 MB，或超過 1 MB 且送出是收到的 10 倍以上。
pub const UPLOAD_ABS: u64 = 50 * 1024 * 1024;
pub const UPLOAD_MIN: u64 = 1024 * 1024;
pub const UPLOAD_RATIO: f64 = 10.0;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TrafficSummary {
    /// `pcap`（逐封包）或 `flow-lite`（只看 socket 表，沒有位元組、DNS、SNI）
    pub mode: String,
    /// 檔名或 `live`
    pub source: String,
    pub window: Window,
    pub totals: Totals,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<IfaceTotals>,
    pub top_talkers: Vec<Talker>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_process: Vec<ProcessTraffic>,
    pub dns_queries: Vec<DnsQuery>,
    pub tls_sni: Vec<NameCount>,
    pub http_hosts: Vec<NameCount>,
    pub alerts: Vec<TrafficAlert>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Window {
    pub start: Option<String>,
    pub end: Option<String>,
    pub duration_s: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Totals {
    pub packets: u64,
    pub bytes: u64,
    pub flows: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IfaceTotals {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Talker {
    pub remote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub ports: Vec<u16>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub flows: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intel: Vec<IntelRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProcessTraffic {
    pub process: String,
    pub connections: u64,
    pub remotes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: String,
    pub count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub nxdomain: u32,
    /// 可疑原因（高熵、少見頂級網域、情資命中）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NameCount {
    pub name: String,
    pub flows: u64,
    pub remotes: Vec<String>,
}

/// 情資命中（精簡；完整來源資訊在 finding 裡）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IntelRef {
    pub feed_id: String,
    pub vendor: String,
    pub confidence: u8,
    pub source_url: String,
}

impl From<&IntelHit> for IntelRef {
    fn from(h: &IntelHit) -> Self {
        Self {
            feed_id: h.feed_id.clone(),
            vendor: h.vendor.clone(),
            confidence: h.confidence,
            source_url: h.source_url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrafficAlert {
    /// `intel_match` | `plaintext_protocol` | `unusual_port` | `large_upload` | `beaconing` | `suspicious_dns`
    pub kind: String,
    /// `high` | `medium` | `low`
    pub severity: String,
    pub remote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intel: Vec<IntelRef>,
}

/// 明文協定（server port → 名稱）。
pub fn plaintext_protocol(proto: u8, port: u16) -> Option<&'static str> {
    match (proto, port) {
        (6, 21) => Some("FTP"),
        (6, 23) => Some("Telnet"),
        (6, 25) => Some("SMTP"),
        (6, 80) => Some("HTTP"),
        (6, 110) => Some("POP3"),
        (6, 143) => Some("IMAP"),
        (6, 389) => Some("LDAP"),
        (6, 512..=514) => Some("r-services"),
        (17, 69) => Some("TFTP"),
        (17, 161) => Some("SNMP"),
        _ => None,
    }
}

/// 網域名稱是否可疑：最長標籤很長且高熵（DGA／DNS 通道），或少見頂級網域。
pub fn suspicious_domain(name: &str) -> Option<String> {
    const RARE_TLDS: [&str; 12] = [
        "zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "ga", "click", "country", "kim",
    ];
    let labels: Vec<&str> = name.split('.').collect();
    if let Some(tld) = labels.last() {
        if RARE_TLDS.contains(tld) {
            return Some(format!("rare-tld .{tld}"));
        }
    }
    let longest = labels
        .iter()
        .take(labels.len().saturating_sub(2).max(1))
        .max_by_key(|l| l.len())?;
    if longest.len() >= 20 && shannon(longest) >= 3.6 {
        return Some(format!("high-entropy label ({:.1} bits)", shannon(longest)));
    }
    None
}

fn shannon(s: &str) -> f64 {
    let mut counts: HashMap<u8, f64> = HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_default() += 1.0;
    }
    let n = s.len() as f64;
    counts.values().map(|c| -(c / n) * (c / n).log2()).sum()
}

/// 週期性：同一組 client → server:port 的新連線開始時間間隔很規律。回傳 (週期秒, 變異係數)。
pub fn periodicity(mut starts: Vec<f64>) -> Option<(f64, f64)> {
    if starts.len() < 4 {
        return None;
    }
    starts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let gaps: Vec<f64> = starts.windows(2).map(|w| w[1] - w[0]).filter(|g| *g > 0.5).collect();
    if gaps.len() < 3 {
        return None;
    }
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
    let cv = var.sqrt() / mean;
    (mean >= 5.0 && cv <= 0.2).then_some((mean, cv))
}

fn iso(ts: f64) -> Option<String> {
    chrono::DateTime::from_timestamp(ts.trunc() as i64, ((ts.fract()) * 1e9) as u32)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn severity_of(hits: &[IntelHit]) -> &'static str {
    if hits.iter().any(|h| h.confidence >= 80) {
        "high"
    } else {
        "medium"
    }
}

/// 逐封包模式的摘要。`intel` 有載入就比對遠端 IP 與網域。
pub fn from_flows(table: &FlowTable, source: &str, intel: Option<&IntelDb>) -> TrafficSummary {
    let risky = RiskyTable::load();
    let mut s = TrafficSummary {
        mode: "pcap".into(),
        source: source.into(),
        ..Default::default()
    };
    let (first, last) = (table.first_ts.unwrap_or(0.0), table.last_ts.unwrap_or(0.0));
    s.window = Window {
        start: table.first_ts.and_then(iso),
        end: table.last_ts.and_then(iso),
        duration_s: ((last - first) * 10.0).round() / 10.0,
    };
    s.totals.packets = table.packets;
    s.totals.bytes = table.bytes;
    s.totals.flows = table.flow_count() as u64;

    let flows: Vec<&Flow> = table.flows().collect();
    let mut intel_cache: HashMap<IpAddr, Vec<IntelHit>> = HashMap::new();
    let mut ip_hits = |ip: IpAddr, port: Option<u16>| -> Vec<IntelHit> {
        match intel {
            Some(db) if classify(ip).is_public() => {
                intel_cache.entry(ip).or_insert_with(|| db.match_ip(ip, port)).clone()
            }
            _ => Vec::new(),
        }
    };

    // 依遠端（server）彙總 → top talkers
    struct Agg {
        domain: Option<String>,
        ports: Vec<u16>,
        out: u64,
        inn: u64,
        flows: u64,
    }
    let mut by_remote: BTreeMap<IpAddr, Agg> = BTreeMap::new();
    let mut sni: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    let mut hosts: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    let mut groups: HashMap<(IpAddr, IpAddr, u16, u8), Vec<f64>> = HashMap::new();
    for f in &flows {
        s.totals.bytes_out += f.bytes_c2s;
        s.totals.bytes_in += f.bytes_s2c;
        let remote = f.server.0;
        let domain = f
            .sni
            .clone()
            .or_else(|| f.http_host.clone())
            .or_else(|| table.names.get(&remote).cloned());
        let a = by_remote.entry(remote).or_insert(Agg {
            domain: None,
            ports: Vec::new(),
            out: 0,
            inn: 0,
            flows: 0,
        });
        a.out += f.bytes_c2s;
        a.inn += f.bytes_s2c;
        a.flows += 1;
        if a.domain.is_none() {
            a.domain = domain;
        }
        if !a.ports.contains(&f.server.1) && a.ports.len() < 8 {
            a.ports.push(f.server.1);
        }
        for (map, name) in [(&mut sni, &f.sni), (&mut hosts, &f.http_host)] {
            if let Some(n) = name {
                let e = map.entry(n.clone()).or_default();
                e.0 += 1;
                let r = remote.to_string();
                if !e.1.contains(&r) && e.1.len() < 5 {
                    e.1.push(r);
                }
            }
        }
        groups
            .entry((f.client.0, remote, f.server.1, f.proto))
            .or_default()
            .push(f.first);

        // 明文協定
        if let Some(p) = plaintext_protocol(f.proto, f.server.1).or(f.http_plain.then_some("HTTP")) {
            push_alert(
                &mut s.alerts,
                TrafficAlert {
                    kind: "plaintext_protocol".into(),
                    severity: if matches!(p, "Telnet" | "FTP" | "r-services") {
                        "high"
                    } else {
                        "low"
                    }
                    .into(),
                    remote: remote.to_string(),
                    port: Some(f.server.1),
                    detail: f
                        .http_host
                        .as_ref()
                        .map(|h| format!("{p} · {h}"))
                        .unwrap_or_else(|| p.to_string()),
                    intel: vec![],
                },
            );
        }
        // 異常 port（連出到高風險 port）
        let proto = f.proto_name();
        if let Some(rp) = risky.outbound(proto, f.server.1) {
            push_alert(
                &mut s.alerts,
                TrafficAlert {
                    kind: "unusual_port".into(),
                    severity: "medium".into(),
                    remote: remote.to_string(),
                    port: Some(f.server.1),
                    detail: format!("{proto}/{} {} — {}", f.server.1, rp.name, rp.rationale),
                    intel: vec![],
                },
            );
        }
    }

    // 大量上傳
    for (ip, a) in &by_remote {
        if a.out >= UPLOAD_ABS || (a.out >= UPLOAD_MIN && a.out as f64 >= UPLOAD_RATIO * a.inn.max(1) as f64) {
            s.alerts.push(TrafficAlert {
                kind: "large_upload".into(),
                severity: "medium".into(),
                remote: ip.to_string(),
                port: a.ports.first().copied(),
                detail: format!(
                    "out {} / in {}{}",
                    crate::util::text::fmt_bytes(a.out),
                    crate::util::text::fmt_bytes(a.inn),
                    a.domain.as_ref().map(|d| format!(" · {d}")).unwrap_or_default()
                ),
                intel: vec![],
            });
        }
    }
    // 週期性連線
    for ((_, remote, port, _), starts) in groups {
        let n = starts.len();
        if let Some((period, cv)) = periodicity(starts) {
            s.alerts.push(TrafficAlert {
                kind: "beaconing".into(),
                severity: "medium".into(),
                remote: remote.to_string(),
                port: Some(port),
                detail: format!("period ≈ {period:.0}s, jitter {cv:.2}, {n} connections"),
                intel: vec![],
            });
        }
    }

    // top talkers（依總位元組）
    let mut talkers: Vec<Talker> = by_remote
        .into_iter()
        .map(|(ip, a)| {
            let hits = ip_hits(ip, a.ports.first().copied());
            Talker {
                remote: ip.to_string(),
                domain: a.domain,
                ports: a.ports,
                bytes_out: a.out,
                bytes_in: a.inn,
                flows: a.flows,
                process: None,
                intel: hits.iter().map(IntelRef::from).collect(),
            }
        })
        .collect();
    // 情資命中：每個命中的遠端都出一則（不受 top N 限制）
    for t in &talkers {
        if !t.intel.is_empty() {
            let ip: IpAddr = t.remote.parse().expect("talker remote is an IP");
            let hits = ip_hits(ip, t.ports.first().copied());
            s.alerts.push(TrafficAlert {
                kind: "intel_match".into(),
                severity: severity_of(&hits).into(),
                remote: t.remote.clone(),
                port: t.ports.first().copied(),
                detail: t.domain.clone().unwrap_or_default(),
                intel: t.intel.clone(),
            });
        }
    }
    talkers.sort_by(|a, b| {
        (b.bytes_out + b.bytes_in)
            .cmp(&(a.bytes_out + a.bytes_in))
            .then(a.remote.cmp(&b.remote))
    });
    talkers.truncate(TOP_N);
    s.top_talkers = talkers;

    // DNS
    let mut dns: Vec<DnsQuery> = table
        .dns
        .iter()
        .map(|((name, qtype), agg)| {
            let hits = intel.map(|db| db.match_domain(name)).unwrap_or_default();
            let suspicious = if let Some(h) = hits.first() {
                Some(format!("intel: {} ({}%)", h.vendor, h.confidence))
            } else {
                suspicious_domain(name)
            };
            if !hits.is_empty() {
                s.alerts.push(TrafficAlert {
                    kind: "intel_match".into(),
                    severity: severity_of(&hits).into(),
                    remote: name.clone(),
                    port: None,
                    detail: "DNS".into(),
                    intel: hits.iter().map(IntelRef::from).collect(),
                });
            } else if let Some(why) = &suspicious {
                s.alerts.push(TrafficAlert {
                    kind: "suspicious_dns".into(),
                    severity: "low".into(),
                    remote: name.clone(),
                    port: None,
                    detail: why.clone(),
                    intel: vec![],
                });
            }
            DnsQuery {
                name: name.clone(),
                qtype: qtype_name(*qtype),
                count: agg.count.max(u32::from(agg.nxdomain > 0 || !agg.answers.is_empty())),
                answers: agg.answers.iter().cloned().collect(),
                nxdomain: agg.nxdomain,
                suspicious,
            }
        })
        .collect();
    dns.sort_by(|a, b| {
        b.suspicious
            .is_some()
            .cmp(&a.suspicious.is_some())
            .then(b.count.cmp(&a.count))
            .then(a.name.cmp(&b.name))
    });
    dns.truncate(DNS_N);
    s.dns_queries = dns;
    s.tls_sni = top_names(sni);
    s.http_hosts = top_names(hosts);

    s.alerts.sort_by(|a, b| {
        sev_rank(&b.severity)
            .cmp(&sev_rank(&a.severity))
            .then(a.kind.cmp(&b.kind))
            .then(a.remote.cmp(&b.remote))
    });
    s.alerts.truncate(100);
    if table.dropped_flows > 0 {
        s.notes
            .push(format!("flow table full: {} flows not tracked", table.dropped_flows));
    }
    if intel.is_none() {
        s.notes
            .push("threat intel not loaded (run `ai-security-monitor intel update`)".into());
    }
    s
}

fn top_names(m: BTreeMap<String, (u64, Vec<String>)>) -> Vec<NameCount> {
    let mut v: Vec<NameCount> = m
        .into_iter()
        .map(|(name, (flows, remotes))| NameCount { name, flows, remotes })
        .collect();
    v.sort_by(|a, b| b.flows.cmp(&a.flows).then(a.name.cmp(&b.name)));
    v.truncate(NAMES_N);
    v
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}

/// 同一種警示、同一個遠端與 port 只留一則。
fn push_alert(v: &mut Vec<TrafficAlert>, a: TrafficAlert) {
    if !v
        .iter()
        .any(|x| x.kind == a.kind && x.remote == a.remote && x.port == a.port)
    {
        v.push(a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodicity_detects_regular_starts() {
        assert!(periodicity(vec![0.0, 60.0, 120.0, 181.0, 240.0]).is_some());
        assert!(periodicity(vec![0.0, 5.0, 90.0, 100.0, 400.0]).is_none());
        assert!(periodicity(vec![0.0, 60.0, 120.0]).is_none());
        assert!(
            periodicity(vec![0.0, 1.0, 2.0, 3.0, 4.0]).is_none(),
            "faster than 5 s is not a beacon"
        );
    }

    #[test]
    fn suspicious_domains() {
        assert!(suspicious_domain("x9q2kz7f1v8m3n4b6c0d2e5r.example.com").is_some());
        assert!(suspicious_domain("login.microsoftonline.com").is_none());
        assert!(suspicious_domain("free-gift.zip").is_some());
        assert!(suspicious_domain("www.googleapis.com").is_none());
    }
}
