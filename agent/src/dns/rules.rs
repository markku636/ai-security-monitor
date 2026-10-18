//! DNS 偵測規則。輸入是每分鐘聚合的紀錄（[`DnsRecord`]），以 5 分鐘為一窗，鍵用（程式, 可註冊網域）。
//! 門檻參考 Zeek DNS tunnel 腳本、Sigma、Splunk ESCU 與 Elastic 的規則（見 docs/dns.md），全部集中在這裡。
//!
//! | 規則 | 條件 |
//! |---|---|
//! | `dns.intel_domain` | 網域分數 ≥ 60（≥ 80 高、≥ 90 嚴重） |
//! | `dns.tunnel` | 同一程式對同一網域 5 分鐘 ≥ 100 次、相異子網域比例 ≥ 0.8、平均標籤長 ≥ 25 或熵 ≥ 3.5（高）；或 ≥ 20 次且 TXT／NULL ≥ 30%（中） |
//! | `dns.dga` | 同一程式 5 分鐘內 ≥ 10 個不存在（NXDOMAIN）、看起來像亂數產生的網域 |
//! | `dns.nxdomain_burst` | 同一程式 5 分鐘內 ≥ 50 次 NXDOMAIN、涉及 ≥ 20 個不同網域 |
//! | `dns.doh_bypass` | 瀏覽器與系統以外的程式查加密 DNS（DoH）端點 |
//! | `dns.tunnel_service` | 查詢 Cloudflare Tunnel、Dev Tunnels、ngrok 等反向通道服務 |
//! | `dns.blocklisted` | 查詢了黑名單上的網域（這台的或 Hub 的；條目含子網域） |

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, DurationRound, TimeDelta, Utc};

use super::heuristics::{self, is_chromium_probe, looks_generated, registrable_domain, shannon};
use super::model::{qtype_name, DnsRecord};
use crate::intel::{domain_score, IntelDb};
use crate::model::finding::{Evidence, Finding, ScannerId, Severity};

pub const WINDOW_S: i64 = 300;
pub const INTEL_SCORE_ALERT: u8 = 60;
pub const TUNNEL_QUERIES: u32 = 100;
pub const TUNNEL_UNIQUE_RATIO: f64 = 0.8;
pub const TUNNEL_AVG_LABEL: f64 = 25.0;
pub const TUNNEL_ENTROPY: f64 = 3.5;
pub const TUNNEL_TXT_QUERIES: u32 = 20;
pub const TUNNEL_TXT_RATIO: f64 = 0.3;
pub const DGA_NAMES: usize = 10;
pub const NX_BURST: u32 = 50;
pub const NX_DISTINCT: usize = 20;
/// 每條規則的證據最多附幾個範例網域。
const SAMPLES: usize = 8;

/// 加密 DNS 本來就是瀏覽器與系統的功能：這些程式查 DoH 端點不算繞過。
const DOH_EXPECTED: [&str; 16] = [
    "chrome",
    "msedge",
    "firefox",
    "brave",
    "opera",
    "vivaldi",
    "safari",
    "arc",
    "chromium",
    "iexplore",
    "svchost",
    "system",
    "mdnsresponder",
    "systemd-resolve",
    "dnscache",
    "librewolf",
];

/// 反向通道服務（把內網服務開到網際網路上；攻擊者也拿來當 C2）。
const TUNNEL_SERVICES: [&str; 7] = [
    "argotunnel.com",
    "cftunnel.com",
    "trycloudflare.com",
    "devtunnels.ms",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
];

/// 這個網域是否可信（白名單、known-good）；可信的不做推測型與情資告警。
pub type Trusted<'a> = &'a dyn Fn(&str) -> bool;

fn proc_key(r: &DnsRecord) -> String {
    r.process.clone().unwrap_or_default()
}

fn proc_label(p: &str) -> String {
    if p.is_empty() {
        t!("未知程式").to_string()
    } else {
        p.to_string()
    }
}

fn window_of(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.duration_trunc(TimeDelta::seconds(WINDOW_S)).unwrap_or(ts)
}

fn is_arpa(name: &str) -> bool {
    name.ends_with(".arpa")
}

/// 子網域部分（去掉可註冊網域）。
fn subdomain_part<'a>(name: &'a str, reg: &str) -> &'a str {
    name.strip_suffix(reg).map(|s| s.trim_end_matches('.')).unwrap_or("")
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    name: &str,
    registrable: Option<&str>,
    process: &str,
    queries: u32,
    unique: Option<u32>,
    first: DateTime<Utc>,
    samples: Vec<String>,
    sources: Vec<String>,
) -> Evidence {
    Evidence::Dns {
        name: name.to_string(),
        registrable: registrable.map(str::to_string),
        process: (!process.is_empty()).then(|| process.to_string()),
        queries,
        unique_names: unique,
        window_s: WINDOW_S as u32,
        first_seen: first.to_rfc3339(),
        samples,
        sources,
    }
}

/// 跑全部規則。`intel` 沒有時略過情資與 DoH 規則；`trusted` 回 true 的網域不告警。
pub fn detect(records: &[DnsRecord], intel: Option<&IntelDb>, trusted: Trusted<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(db) = intel {
        out.extend(intel_hits(records, db, trusted));
        out.extend(doh_bypass(records, db));
    }
    out.extend(tunnel_service(records));
    out.extend(window_rules(records, trusted));
    out
}

/// 查詢了黑名單上的網域（使用者自己加的，不看白名單與熱門網域）。同一（條目, 程式）報一次。
pub fn blocklisted(records: &[DnsRecord], m: &super::blocklist::Matcher) -> Vec<Finding> {
    if m.is_empty() {
        return Vec::new();
    }
    type Hits = (u32, DateTime<Utc>, BTreeSet<String>, super::blocklist::Source);
    let mut by: BTreeMap<(String, String), Hits> = BTreeMap::new();
    for r in records {
        let Some((entry, src)) = m.find(&r.name) else {
            continue;
        };
        let e = by
            .entry((entry.to_string(), proc_key(r)))
            .or_insert((0, r.ts, BTreeSet::new(), src));
        e.0 = e.0.saturating_add(r.count);
        e.1 = e.1.min(r.ts);
        if e.2.len() < SAMPLES {
            e.2.insert(r.name.clone());
        }
    }
    by.into_iter()
        .map(|((entry, proc), (count, first, names, src))| {
            let name = names.iter().next().cloned().unwrap_or_else(|| entry.clone());
            Finding::new(
                ScannerId::Dns,
                "dns.blocklisted",
                &format!("blocklist|{entry}|{proc}"),
                Severity::High,
                tf!("查詢了黑名單上的網域：{name}", name = name.clone()),
                tf!(
                    "{process} 查詢 {name} {count} 次；{entry}（含子網域）在{source}上。",
                    process = proc_label(&proc),
                    name = name.clone(),
                    count = count,
                    entry = entry.clone(),
                    source = src.label()
                ),
                evidence(
                    &name,
                    registrable_domain(&name),
                    &proc,
                    count,
                    Some(names.len() as u32),
                    first,
                    names.into_iter().collect(),
                    vec![src.label().to_string()],
                ),
                t!("確認是哪個程式在連這個網域；用防護 DNS 的電腦會直接被擋。確認沒問題就從黑名單移除（ai-security-monitor dns unblock）"),
            )
            .with_tag("dns")
        })
        .collect()
}

fn intel_hits(records: &[DnsRecord], db: &IntelDb, trusted: Trusted<'_>) -> Vec<Finding> {
    // 同一（網域, 程式）只報一次
    let mut seen: BTreeMap<(String, String), (u32, DateTime<Utc>)> = BTreeMap::new();
    for r in records {
        let e = seen.entry((r.name.clone(), proc_key(r))).or_insert((0, r.ts));
        e.0 = e.0.saturating_add(r.count);
        e.1 = e.1.min(r.ts);
    }
    let mut verdicts: HashMap<String, Option<(u8, Vec<crate::model::finding::IntelHit>)>> = HashMap::new();
    let mut out = Vec::new();
    for ((name, proc), (count, first)) in seen {
        let v = verdicts.entry(name.clone()).or_insert_with(|| {
            if trusted(&name) {
                return None;
            }
            let hits = db.match_domain(&name);
            let score = domain_score(&hits, heuristics::is_popular(&name));
            (score >= INTEL_SCORE_ALERT).then_some((score, hits))
        });
        let Some((score, hits)) = v else {
            continue;
        };
        let sev = match *score {
            90.. => Severity::Critical,
            80..=89 => Severity::High,
            _ => Severity::Medium,
        };
        let sources: Vec<String> = hits
            .iter()
            .map(|h| format!("{} {}（{}%，{}）", h.vendor, h.name, h.confidence, h.source_url))
            .collect();
        let reg = registrable_domain(&name).map(str::to_string);
        let mut f = Finding::new(
            ScannerId::Dns,
            "dns.intel_domain",
            &format!("intel|{name}|{proc}"),
            sev,
            tf!("查詢了威脅情資列名的網域：{name}", name = name.clone()),
            tf!(
                "{process} 查詢 {name} {count} 次（網域分數 {score}）。來源：{sources}",
                process = proc_label(&proc),
                name = name.clone(),
                count = count,
                score = *score,
                sources = sources.join("；")
            ),
            evidence(
                &name,
                reg.as_deref(),
                &proc,
                count,
                None,
                first,
                vec![name.clone()],
                sources.clone(),
            ),
            t!("確認是哪個程式在連這個網域、是否為惡意程式；可在防護 DNS 封鎖此網域。確認是誤判就加入白名單"),
        )
        .with_tag("dns")
        .with_tag("intel");
        for h in hits.iter().take(3) {
            f = f.with_ref(&h.source_url);
        }
        out.push(f);
    }
    out
}

fn doh_bypass(records: &[DnsRecord], db: &IntelDb) -> Vec<Finding> {
    let mut by: BTreeMap<(String, String), (u32, DateTime<Utc>, String)> = BTreeMap::new();
    for r in records {
        let p = proc_key(r);
        let lp = p.to_ascii_lowercase();
        if p.is_empty()
            || DOH_EXPECTED
                .iter()
                .any(|x| lp.trim_end_matches(".exe") == *x || lp.starts_with(x))
        {
            continue;
        }
        let Some((feed, _)) = db.doh_endpoint(&r.name) else {
            continue;
        };
        let e = by.entry((p, r.name.clone())).or_insert((0, r.ts, feed));
        e.0 = e.0.saturating_add(r.count);
        e.1 = e.1.min(r.ts);
    }
    by.into_iter()
        .map(|((p, name), (count, first, feed))| {
            Finding::new(
                ScannerId::Dns,
                "dns.doh_bypass",
                &format!("doh|{name}|{p}"),
                Severity::Medium,
                tf!("{process} 改走加密 DNS（{name}）", process = p.clone(), name = name.clone()),
                tf!(
                    "{process} 查詢加密 DNS（DoH）端點 {name} {count} 次：之後的網域查詢會繞過公司 DNS 與 DNS 監看。不是瀏覽器或系統內建的 DoH，惡意程式常用這招藏 C2。",
                    process = p.clone(),
                    name = name.clone(),
                    count = count
                ),
                evidence(&name, registrable_domain(&name), &p, count, None, first, vec![name.clone()], vec![feed]),
                t!("確認這個程式為什麼要自己走加密 DNS；不需要的話用 fw dns-lock --block-doh 擋掉加密 DNS"),
            )
            .with_tag("dns")
        })
        .collect()
}

/// 同一（程式, 通道服務）的累計。
struct SvcHits {
    count: u32,
    first: DateTime<Utc>,
    names: BTreeSet<String>,
}

fn tunnel_service(records: &[DnsRecord]) -> Vec<Finding> {
    let mut by: BTreeMap<(String, String), SvcHits> = BTreeMap::new();
    for r in records {
        let Some(svc) = TUNNEL_SERVICES
            .iter()
            .find(|s| r.name == **s || r.name.ends_with(&format!(".{s}")))
        else {
            continue;
        };
        let e = by.entry((proc_key(r), svc.to_string())).or_insert(SvcHits {
            count: 0,
            first: r.ts,
            names: BTreeSet::new(),
        });
        e.count = e.count.saturating_add(r.count);
        e.first = e.first.min(r.ts);
        if e.names.len() < SAMPLES {
            e.names.insert(r.name.clone());
        }
    }
    by.into_iter()
        .map(|((p, svc), SvcHits { count, first, names })| {
            Finding::new(
                ScannerId::Dns,
                "dns.tunnel_service",
                &format!("tunnelsvc|{svc}|{p}"),
                Severity::Low,
                tf!("{process} 連到反向通道服務（{svc}）", process = proc_label(&p), svc = svc.clone()),
                tf!(
                    "{process} 查詢 {svc} {count} 次。這類服務能把這台電腦的服務開到網際網路上，攻擊者也拿來當遠端控制通道；不是你開的就要查。",
                    process = proc_label(&p),
                    svc = svc.clone(),
                    count = count
                ),
                evidence(&svc, Some(&svc), &p, count, None, first, names.into_iter().collect(), Vec::new()),
                t!("確認是誰開的通道（cloudflared、devtunnel、ngrok）；不是自己開的就結束那個程式並檢查開機啟動項目"),
            )
            .with_tag("dns")
        })
        .collect()
}

#[derive(Default)]
struct Agg {
    queries: u32,
    names: HashSet<String>,
    label_len_sum: f64,
    label_n: u32,
    max_entropy: f64,
    txt: u32,
    first: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct ProcWin {
    nx: u32,
    nx_regs: HashSet<String>,
    dga: HashSet<String>,
    first: Option<DateTime<Utc>>,
}

fn window_rules(records: &[DnsRecord], trusted: Trusted<'_>) -> Vec<Finding> {
    let mut tunnels: BTreeMap<(DateTime<Utc>, String, String), Agg> = BTreeMap::new();
    let mut procs: BTreeMap<(DateTime<Utc>, String), ProcWin> = BTreeMap::new();
    let mut trust_cache: HashMap<String, bool> = HashMap::new();
    for r in records {
        if is_arpa(&r.name) {
            continue;
        }
        let w = window_of(r.ts);
        let p = proc_key(r);
        let reg = registrable_domain(&r.name).unwrap_or(&r.name).to_string();
        let trusted_reg = *trust_cache
            .entry(reg.clone())
            .or_insert_with(|| trusted(&reg) || heuristics::is_popular(&reg));
        if !trusted_reg {
            let a = tunnels.entry((w, p.clone(), reg.clone())).or_default();
            a.queries = a.queries.saturating_add(r.count);
            a.first = Some(a.first.map_or(r.ts, |f| f.min(r.ts)));
            if a.names.insert(r.name.clone()) {
                let sub = subdomain_part(&r.name, &reg);
                if !sub.is_empty() {
                    a.label_len_sum += sub.len() as f64;
                    a.label_n += 1;
                    a.max_entropy = a.max_entropy.max(shannon(sub));
                }
            }
            if matches!(r.qtype, 10 | 16) {
                a.txt = a.txt.saturating_add(r.count);
            }
        }
        if r.rcode == "NXDOMAIN" {
            let pw = procs.entry((w, p.clone())).or_default();
            pw.nx = pw.nx.saturating_add(r.count);
            pw.nx_regs.insert(reg.clone());
            pw.first = Some(pw.first.map_or(r.ts, |f| f.min(r.ts)));
            if !trusted_reg && looks_generated(&r.name) && !is_chromium_probe(&r.name) {
                pw.dga.insert(r.name.clone());
            }
        }
    }
    let mut out = Vec::new();
    let mut reported: HashSet<String> = HashSet::new();
    for ((w, p, reg), a) in tunnels {
        let unique = a.names.len() as u32;
        let ratio = f64::from(unique) / f64::from(a.queries.max(1));
        let avg = if a.label_n > 0 {
            a.label_len_sum / f64::from(a.label_n)
        } else {
            0.0
        };
        let high = a.queries >= TUNNEL_QUERIES
            && ratio >= TUNNEL_UNIQUE_RATIO
            && (avg >= TUNNEL_AVG_LABEL || a.max_entropy >= TUNNEL_ENTROPY);
        let txt = a.queries >= TUNNEL_TXT_QUERIES && f64::from(a.txt) / f64::from(a.queries) >= TUNNEL_TXT_RATIO;
        if !(high || txt) {
            continue;
        }
        let key = format!("tunnel|{reg}|{p}");
        if !reported.insert(key.clone()) {
            continue;
        }
        let mut samples: Vec<String> = a.names.iter().take(SAMPLES).cloned().collect();
        samples.sort();
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.tunnel",
                &key,
                if high { Severity::High } else { Severity::Medium },
                tf!("疑似 DNS 通道（用 DNS 偷傳資料）：{reg}", reg = reg.clone()),
                tf!(
                    "{process} 在 5 分鐘內對 {reg} 查了 {q} 次、{u} 個不同的子網域（平均長度 {avg}、最高熵 {ent}、TXT／NULL {txt} 次）。大量又長又亂的子網域是把資料編碼進 DNS 查詢送出去的典型手法。",
                    process = proc_label(&p),
                    reg = reg.clone(),
                    q = a.queries,
                    u = unique,
                    avg = format!("{avg:.0}"),
                    ent = format!("{:.1}", a.max_entropy),
                    txt = a.txt
                ),
                evidence(&reg, Some(&reg), &p, a.queries, Some(unique), a.first.unwrap_or(w), samples, Vec::new()),
                t!("查這個程式是什麼、為什麼一直查這個網域；確認可疑就在防護 DNS 封鎖這個網域並隔離這台電腦"),
            )
            .with_tag("dns"),
        );
    }
    for ((w, p), pw) in procs {
        if pw.dga.len() >= DGA_NAMES {
            let key = format!("dga|{p}");
            if reported.insert(key.clone()) {
                let mut samples: Vec<String> = pw.dga.iter().take(SAMPLES).cloned().collect();
                samples.sort();
                out.push(
                    Finding::new(
                        ScannerId::Dns,
                        "dns.dga",
                        &key,
                        Severity::High,
                        tf!("{process} 查了大量亂數產生的網域（疑似 DGA 惡意程式）", process = proc_label(&p)),
                        tf!(
                            "{process} 在 5 分鐘內查了 {n} 個不存在、看起來像亂數產生的網域（例：{sample}）。殭屍網路用演算法每天產生大量網域找控制伺服器。",
                            process = proc_label(&p),
                            n = pw.dga.len(),
                            sample = samples.first().cloned().unwrap_or_default()
                        ),
                        evidence(
                            samples.first().map(String::as_str).unwrap_or(""),
                            None,
                            &p,
                            pw.nx,
                            Some(pw.dga.len() as u32),
                            pw.first.unwrap_or(w),
                            samples.clone(),
                            Vec::new(),
                        ),
                        t!("用防毒完整掃描這台電腦，檢查這個程式的來源與開機啟動項目"),
                    )
                    .with_tag("dns"),
                );
            }
        }
        if pw.nx >= NX_BURST && pw.nx_regs.len() >= NX_DISTINCT {
            let key = format!("nxburst|{p}");
            if reported.insert(key.clone()) {
                let mut samples: Vec<String> = pw.nx_regs.iter().take(SAMPLES).cloned().collect();
                samples.sort();
                let first_name = samples.first().cloned().unwrap_or_default();
                out.push(
                    Finding::new(
                        ScannerId::Dns,
                        "dns.nxdomain_burst",
                        &key,
                        Severity::Medium,
                        tf!("{process} 大量查詢不存在的網域", process = proc_label(&p)),
                        tf!(
                            "{process} 在 5 分鐘內有 {n} 次查無此網域（NXDOMAIN），涉及 {d} 個不同網域。可能是 DGA 惡意程式、設定錯誤或掃描行為。",
                            process = proc_label(&p),
                            n = pw.nx,
                            d = pw.nx_regs.len()
                        ),
                        evidence(
                            &first_name,
                            None,
                            &p,
                            pw.nx,
                            Some(pw.nx_regs.len() as u32),
                            pw.first.unwrap_or(w),
                            samples,
                            Vec::new(),
                        ),
                        t!("確認這個程式在做什麼；不認得的程式先用防毒掃描"),
                    )
                    .with_tag("dns"),
                );
            }
        }
    }
    out
}

/// 給摘要用：這段時間的查詢量、不同網域數、NXDOMAIN 數、前幾名網域。
pub fn summary(records: &[DnsRecord]) -> serde_json::Value {
    let mut by_reg: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;
    let mut nx = 0u64;
    let mut names = HashSet::new();
    let mut procs: HashMap<String, u64> = HashMap::new();
    for r in records {
        total += u64::from(r.count);
        if r.rcode == "NXDOMAIN" {
            nx += u64::from(r.count);
        }
        names.insert(r.name.as_str());
        *by_reg
            .entry(registrable_domain(&r.name).unwrap_or(&r.name).to_string())
            .or_default() += u64::from(r.count);
        *procs.entry(proc_label(&proc_key(r))).or_default() += u64::from(r.count);
    }
    let top = |m: HashMap<String, u64>| {
        let mut v: Vec<(String, u64)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(10);
        v.into_iter()
            .map(|(k, n)| serde_json::json!({ "name": k, "count": n }))
            .collect::<Vec<_>>()
    };
    let types: BTreeMap<String, u64> = records.iter().fold(BTreeMap::new(), |mut m, r| {
        *m.entry(qtype_name(r.qtype)).or_default() += u64::from(r.count);
        m
    });
    serde_json::json!({
        "queries": total,
        "unique_names": names.len(),
        "nxdomain": nx,
        "top_domains": top(by_reg),
        "top_processes": top(procs),
        "types": types,
    })
}

#[cfg(test)]
mod tests {
    use super::super::model::Source;
    use super::*;

    #[test]
    fn blocklisted_domains_alert_per_entry_and_process() {
        let m = super::super::blocklist::Matcher::new(&["bad.example".into()], &["hub-bad.example".into()]);
        let recs = vec![
            rec(1, "a.bad.example", Some("chrome.exe"), 1, "NOERROR", 2),
            rec(2, "b.bad.example", Some("chrome.exe"), 1, "NOERROR", 2),
            rec(2, "hub-bad.example", Some("curl.exe"), 1, "NOERROR", 1),
            rec(3, "fine.example", Some("chrome.exe"), 1, "NOERROR", 5),
        ];
        let f = blocklisted(&recs, &m);
        assert_eq!(f.len(), 2);
        assert!(f
            .iter()
            .all(|x| x.rule == "dns.blocklisted" && x.severity == Severity::High));
        assert!(f
            .iter()
            .any(|x| x.detail.contains("chrome.exe") && x.detail.contains(" 4 ")));
        assert!(blocklisted(&recs, &super::super::blocklist::Matcher::default()).is_empty());
    }

    fn rec(min: i64, name: &str, proc: Option<&str>, qtype: u16, rcode: &str, count: u32) -> DnsRecord {
        DnsRecord {
            ts: DateTime::from_timestamp(1_760_000_000 - 1_760_000_000 % 300 + min * 60, 0).unwrap(),
            name: name.into(),
            registrable: None,
            qtype,
            rcode: rcode.into(),
            process: proc.map(str::to_string),
            exe: None,
            pid: None,
            count,
            answers: vec![],
            cnames: vec![],
            client: None,
            source: Source::Etw,
        }
    }

    fn never(_: &str) -> bool {
        false
    }

    #[test]
    fn tunnel_high_and_txt() {
        let mut recs = Vec::new();
        for i in 0..120 {
            recs.push(rec(
                i % 5,
                &format!("{:x}{:x}a9f3k2m8q1z7x4c6v0b5n.exfil-c2.example", i * 7919, i * 104729),
                Some("evil.exe"),
                1,
                "NOERROR",
                1,
            ));
        }
        for i in 0..25 {
            recs.push(rec(1, &format!("t{i}.txtc2.example"), Some("x.exe"), 16, "NOERROR", 1));
        }
        let f = detect(&recs, None, &never);
        let tunnels: Vec<&Finding> = f.iter().filter(|x| x.rule == "dns.tunnel").collect();
        assert_eq!(tunnels.len(), 2);
        assert!(tunnels
            .iter()
            .any(|x| x.severity == Severity::High && x.title.contains("exfil-c2.example")));
        assert!(tunnels
            .iter()
            .any(|x| x.severity == Severity::Medium && x.title.contains("txtc2.example")));
        // 可信的網域不判
        let trusted = |d: &str| d == "exfil-c2.example" || d == "txtc2.example";
        assert!(detect(&recs, None, &trusted).iter().all(|x| x.rule != "dns.tunnel"));
        // 熱門網域（google.com）的大量不同子網域也不判
        let cdn: Vec<DnsRecord> = (0..150)
            .map(|i| {
                rec(
                    0,
                    &format!("r{i}x9q2kz7f1v8m3n4b6c0d2e5.google.com"),
                    Some("chrome.exe"),
                    1,
                    "NOERROR",
                    1,
                )
            })
            .collect();
        assert!(detect(&cdn, None, &never).is_empty());
    }

    #[test]
    fn dga_and_nx_burst() {
        let dga = [
            "kqfcpqbyqllgbr",
            "xkmqjzdlwpvbt",
            "zxcvqwrtplkj",
            "fjwqxzkvbnm",
            "rhqjxvzwkpld",
            "vqzxjkwpfm",
            "lkjhgfdsaqwrtz",
            "ydchmosgjqtw",
            "ewfqhjvnbrkls",
            "pqzmwxnvfgthr",
            "bfnhgqzrtjpl",
        ];
        let mut recs: Vec<DnsRecord> = dga
            .iter()
            .map(|d| rec(2, &format!("{d}.net"), Some("bot.exe"), 1, "NXDOMAIN", 1))
            .collect();
        for i in 0..45 {
            recs.push(rec(
                3,
                &format!("host{i}.corp{}.example", i % 25),
                Some("bot.exe"),
                1,
                "NXDOMAIN",
                1,
            ));
        }
        let f = detect(&recs, None, &never);
        assert!(f.iter().any(|x| x.rule == "dns.dga" && x.severity == Severity::High));
        let nx = f.iter().find(|x| x.rule == "dns.nxdomain_burst").expect("nx burst");
        assert!(nx.detail.contains("56"));
        // Chromium 的單段探測名稱不算 DGA；正常程式少量 NXDOMAIN 不告警
        let chromium: Vec<DnsRecord> = (0..12)
            .map(|i| {
                rec(
                    0,
                    &format!("qwkdhsue{}", (b'a' + i as u8) as char),
                    Some("chrome.exe"),
                    1,
                    "NXDOMAIN",
                    1,
                )
            })
            .collect();
        assert!(detect(&chromium, None, &never).is_empty());
    }

    #[test]
    fn tunnel_services_and_summary() {
        let recs = vec![
            rec(0, "region1.v2.argotunnel.com", Some("cloudflared.exe"), 1, "NOERROR", 3),
            rec(0, "www.example.com", Some("chrome.exe"), 1, "NOERROR", 5),
            rec(1, "1.0.0.127.in-addr.arpa", None, 12, "NOERROR", 1),
        ];
        let f = detect(&recs, None, &never);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "dns.tunnel_service");
        let s = summary(&recs);
        assert_eq!(s["queries"], 9);
        assert_eq!(s["top_domains"][0]["name"], "example.com");
    }
}
