//! DNS 竄改偵測（`dns` 掃描器的一部分）：
//!
//! | 規則 | 條件 |
//! |---|---|
//! | `dns.resolver_changed` | 這個網路的 DNS 伺服器跟記下的基準不同（筆電換網路分開記；`dns accept` 確認後更新基準） |
//! | `dns.resolver_intel` | 正在用的 DNS 伺服器在威脅情資黑名單上 |
//! | `dns.hosts_tampered` | hosts 檔把熱門網站導到別的位址、擋掉或導走防毒與系統更新網域、或有 `wpad` 條目（T1565.001） |
//! | `dns.wpad` | 查詢 `wpad.*` 有回答（區網有人提供自動代理設定，可能被拿來攔截流量；T1557.001） |
//! | `dns.nxdomain_hijack` | 查 3 個不存在的亂數網域，有 2 個以上回同一個位址（DNS 把「查無此網域」改成導向，仿 Chromium 的測法） |
//! | `dns.answer_mismatch` | （`dns.verify_answers` 開啟時）幾個常見網域的答案跟加密 DNS（Cloudflare）查到的完全不同網段 |
//! | `dns.rogue_profile` | macOS 裝了不明的加密 DNS 描述檔 |
//!
//! hosts 檔「有沒有被改」由檔案完整性監看（`fim`）負責；這裡只看條目內容危不危險。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::heuristics;
use super::model::DnsRecord;
use crate::connections::KnownGood;
use crate::error::AppResult;
use crate::intel::IntelDb;
use crate::model::finding::{Evidence, Finding, ScannerId, Severity};
use crate::store;
use crate::util::net::{classify, IpClass};

pub const STATE_FILE: &str = "dns/tamper.json";
/// NXDOMAIN 劫持多久測一次（每個網路）。
const NX_EVERY: chrono::TimeDelta = chrono::TimeDelta::hours(6);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// 被擋掉或導走就很可疑的網域：防毒與系統更新（可註冊網域，含子網域）。
const PROTECTED_REGISTRABLE: [&str; 17] = [
    "windowsupdate.com",
    "kaspersky.com",
    "eset.com",
    "avast.com",
    "avg.com",
    "bitdefender.com",
    "sophos.com",
    "trendmicro.com",
    "malwarebytes.com",
    "mcafee.com",
    "norton.com",
    "symantec.com",
    "f-secure.com",
    "virustotal.com",
    "clamav.net",
    "crowdstrike.com",
    "sentinelone.net",
];
/// 微軟的更新與 Defender 主機（只比完整名稱，不擋整個 microsoft.com：有人刻意封鎖遙測）。
const PROTECTED_HOSTS: [&str; 7] = [
    "update.microsoft.com",
    "download.microsoft.com",
    "definitionupdates.microsoft.com",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "smartscreen.microsoft.com",
    "go.microsoft.com",
];
/// 答案比對用的常見網域。
const SENTINELS: [&str; 3] = ["www.microsoft.com", "www.google.com", "github.com"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetState {
    /// 確認過的 DNS 伺服器（排序）。
    pub servers: Vec<IpAddr>,
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nx_checked_at: Option<DateTime<Utc>>,
    /// 上次 NXDOMAIN 測試被導去的位址（沒被劫持是 None）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nx_hijack: Option<IpAddr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TamperState {
    #[serde(default)]
    pub networks: BTreeMap<String, NetState>,
}

impl TamperState {
    pub fn load(config_dir: &Path) -> TamperState {
        store::read_json_in(config_dir, STATE_FILE).unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        store::ensure_dir(&super::store::dir(config_dir))?;
        store::write_json_in(config_dir, STATE_FILE, self)
    }
}

/// 這台目前所在的網路（預設路由那張網卡的位址：IPv4 取 /24、IPv6 取 /64）。UDP connect 不會送出封包。
pub fn network_key() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:53").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    Some(match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    })
}

/// 目前的 DNS 伺服器（去重、排序）。
pub async fn current_servers() -> Vec<IpAddr> {
    let mut v = crate::hub::dns::system_config().await.servers;
    v.sort();
    v.dedup();
    v
}

/// DNS 伺服器的類別：情資命中／區網／已知公共 DNS／未知公網。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ResolverClass {
    Lan,
    KnownPublic,
    UnknownPublic,
    Intel,
}

fn classify_resolver(ip: IpAddr, intel: Option<&IntelDb>, kg: &KnownGood) -> ResolverClass {
    if intel.is_some_and(|db| db.match_ip(ip, Some(53)).iter().any(|h| h.confidence >= 60)) {
        return ResolverClass::Intel;
    }
    match classify(ip) {
        IpClass::Public if kg.match_ip(ip).is_some() => ResolverClass::KnownPublic,
        IpClass::Public => ResolverClass::UnknownPublic,
        _ => ResolverClass::Lan,
    }
}

fn join_ips(v: &[IpAddr]) -> String {
    if v.is_empty() {
        return "—".into();
    }
    v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

fn text(detail: String) -> Evidence {
    Evidence::Text { detail }
}

/// DNS 伺服器：跟這個網路的基準比，以及正在用的有沒有在黑名單上。
fn resolver_findings(
    st: &mut TamperState,
    key: &str,
    servers: &[IpAddr],
    intel: Option<&IntelDb>,
    kg: &KnownGood,
    now: DateTime<Utc>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if servers.is_empty() {
        return out;
    }
    let net = st.networks.entry(key.to_string()).or_insert_with(|| NetState {
        servers: servers.to_vec(),
        first_seen: Some(now),
        ..Default::default()
    });
    let base: BTreeSet<IpAddr> = net.servers.iter().copied().collect();
    let added: Vec<IpAddr> = servers.iter().copied().filter(|s| !base.contains(s)).collect();
    if !added.is_empty() {
        let worst = added
            .iter()
            .map(|ip| classify_resolver(*ip, intel, kg))
            .max()
            .unwrap_or(ResolverClass::Lan);
        let sev = match worst {
            ResolverClass::Intel => Severity::High,
            ResolverClass::UnknownPublic => Severity::Medium,
            _ => Severity::Low,
        };
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.resolver_changed",
                &format!("resolver|{key}|{}", join_ips(servers)),
                sev,
                tf!("這個網路的 DNS 伺服器被改了：{new}", new = join_ips(&added)),
                tf!(
                    "網路 {net} 原本用 {old}，現在是 {cur}。惡意程式或被入侵的路由器會改 DNS，把你導到假網站；換了網路設定、VPN 或公司改 DNS 也會出現。",
                    net = key.to_string(),
                    old = join_ips(&net.servers),
                    cur = join_ips(servers)
                ),
                text(format!("network={key} baseline={} current={}", join_ips(&net.servers), join_ips(servers))),
                t!("確認是自己或公司改的就在這台執行 ai-security-monitor dns accept；不是的話檢查網卡與路由器的 DNS 設定、用防毒掃描"),
            )
            .with_tag("dns"),
        );
    }
    for ip in servers {
        if classify_resolver(*ip, intel, kg) == ResolverClass::Intel {
            let hits = intel.map(|db| db.match_ip(*ip, Some(53))).unwrap_or_default();
            let mut f = Finding::new(
                ScannerId::Dns,
                "dns.resolver_intel",
                &format!("resolverintel|{ip}"),
                Severity::High,
                tf!("正在用的 DNS 伺服器在威脅情資黑名單上：{ip}", ip = ip.to_string()),
                tf!(
                    "這台電腦的 DNS 伺服器 {ip} 被威脅情資列名：所有網域查詢都經過它，可能被導到假網站。來源：{src}",
                    ip = ip.to_string(),
                    src = hits
                        .iter()
                        .map(|h| format!("{} {}（{}%）", h.vendor, h.name, h.confidence))
                        .collect::<Vec<_>>()
                        .join("；")
                ),
                text(format!("resolver={ip}")),
                t!("立刻把 DNS 改回公司或可信任的 DNS，並檢查是誰改的（惡意程式、路由器）"),
            )
            .with_tag("dns")
            .with_tag("intel");
            for h in hits.iter().take(3) {
                f = f.with_ref(&h.source_url);
            }
            out.push(f);
        }
    }
    out
}

pub fn hosts_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// hosts 檔的條目（IP, 名稱）；略過註解與 localhost 類名稱。
pub fn parse_hosts(text: &str) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        let mut it = l.split_whitespace();
        let Some(ip) = it.next().and_then(|t| t.parse::<IpAddr>().ok()) else {
            continue;
        };
        for n in it {
            let n = n.trim_end_matches('.').to_ascii_lowercase();
            if n.is_empty()
                || n == "localhost"
                || n == "broadcasthost"
                || n.starts_with("ip6-")
                || n.ends_with(".localdomain")
                || n.ends_with(".local")
            {
                continue;
            }
            out.push((ip, n));
        }
    }
    out
}

fn is_protected(name: &str) -> bool {
    PROTECTED_HOSTS.contains(&name)
        || heuristics::registrable_domain(name).is_some_and(|r| PROTECTED_REGISTRABLE.contains(&r))
}

fn sink(ip: IpAddr) -> bool {
    matches!(classify(ip), IpClass::Loopback | IpClass::Unspecified)
}

/// hosts 檔裡危險的條目。
pub fn hosts_findings(path: &Path, text: &str) -> Vec<Finding> {
    let entries = parse_hosts(text);
    let sha = hex::encode(Sha256::digest(text.as_bytes()));
    let mut wpad = Vec::new();
    let mut protected = Vec::new();
    let mut redirect_pub = Vec::new();
    let mut redirect_lan = Vec::new();
    for (ip, name) in &entries {
        let line = format!("{ip} {name}");
        if name == "wpad" || name.starts_with("wpad.") {
            wpad.push(line);
        } else if is_protected(name) {
            protected.push(line);
        } else if heuristics::is_popular(name) && !sink(*ip) {
            if classify(*ip) == IpClass::Public {
                redirect_pub.push(line);
            } else {
                redirect_lan.push(line);
            }
        }
    }
    let file_ev = |rule: &str, lines: &[String]| Evidence::File {
        path: path.display().to_string(),
        sha256: Some(sha.clone()),
        size: text.len() as u64,
        rule: Some(rule.to_string()),
        matched_strings: lines.iter().take(20).cloned().collect(),
    };
    let remove = t!("用系統管理員身分編輯 hosts 檔刪掉這幾行；不是自己加的，用防毒完整掃描");
    let mut out = Vec::new();
    if !protected.is_empty() {
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.hosts_tampered",
                "hosts|protected",
                Severity::High,
                t!("hosts 檔擋掉或導走了防毒與系統更新網站"),
                tf!(
                    "hosts 檔裡有 {n} 行把防毒或系統更新的網域指到別處（例：{ex}）。惡意程式常這樣讓防毒拿不到更新。",
                    n = protected.len(),
                    ex = protected[0].clone()
                ),
                file_ev("protected", &protected),
                remove,
            )
            .with_tag("dns"),
        );
    }
    if !redirect_pub.is_empty() || !redirect_lan.is_empty() {
        let all: Vec<String> = redirect_pub.iter().chain(redirect_lan.iter()).cloned().collect();
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.hosts_tampered",
                "hosts|redirect",
                if redirect_pub.is_empty() { Severity::Medium } else { Severity::High },
                t!("hosts 檔把熱門網站導到別的位址"),
                tf!(
                    "hosts 檔裡有 {n} 行把熱門網站指到固定位址（例：{ex}）：打開這些網站會連到那個位址，常見於釣魚或攔截帳密。",
                    n = all.len(),
                    ex = all[0].clone()
                ),
                file_ev("redirect", &all),
                remove,
            )
            .with_tag("dns"),
        );
    }
    if !wpad.is_empty() {
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.hosts_tampered",
                "hosts|wpad",
                Severity::High,
                t!("hosts 檔裡有 wpad 條目"),
                tf!(
                    "hosts 檔把 wpad 指到 {ex}：瀏覽器會從那裡下載自動代理設定，所有網頁流量都可能被攔截。",
                    ex = wpad[0].clone()
                ),
                file_ev("wpad", &wpad),
                remove,
            )
            .with_tag("dns"),
        );
    }
    out
}

/// DNS 紀錄裡 `wpad.*` 有回答。
pub fn wpad_findings(records: &[DnsRecord]) -> Vec<Finding> {
    let hits: Vec<&DnsRecord> = records
        .iter()
        .filter(|r| (r.name == "wpad" || r.name.starts_with("wpad.")) && r.rcode == "NOERROR" && !r.answers.is_empty())
        .collect();
    let Some(first) = hits.first() else {
        return Vec::new();
    };
    let answers: Vec<IpAddr> = hits
        .iter()
        .flat_map(|r| r.answers.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    vec![Finding::new(
        ScannerId::Dns,
        "dns.wpad",
        &format!("wpad|{}", first.name),
        Severity::Medium,
        tf!("區網有人回應 WPAD 自動代理查詢：{name}", name = first.name.clone()),
        tf!(
            "這台查 {name} 拿到了位址 {ips}：瀏覽器會從那裡下載代理設定。公司有設自動代理就是正常的；不是的話可能有人在區網攔截流量（Responder 一類工具）。",
            name = first.name.clone(),
            ips = join_ips(&answers)
        ),
        Evidence::Dns {
            name: first.name.clone(),
            registrable: first.registrable.clone(),
            process: first.process.clone(),
            queries: hits.iter().map(|r| r.count).sum(),
            unique_names: None,
            window_s: super::rules::WINDOW_S as u32,
            first_seen: first.ts.to_rfc3339(),
            samples: hits.iter().map(|r| r.name.clone()).collect::<BTreeSet<_>>().into_iter().collect(),
            sources: Vec::new(),
        },
        t!("確認公司有沒有設 WPAD；沒有的話關閉「自動偵測設定」（硬化檢查 win.wpad.disabled）並找出回應的那台電腦"),
    )
    .with_tag("dns")]
}

fn random_label() -> String {
    uuid::Uuid::new_v4()
        .into_bytes()
        .iter()
        .take(12)
        .map(|b| (b'a' + b % 26) as char)
        .collect()
}

async fn resolve_v4(name: &str) -> Vec<IpAddr> {
    match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host((name, 80))).await {
        Ok(Ok(it)) => it.map(|s| s.ip()).filter(|ip| ip.is_ipv4()).collect(),
        _ => Vec::new(),
    }
}

/// 查 3 個不存在的亂數網域；有 2 個以上回同一個位址＝NXDOMAIN 被改成導向，回那個位址。
pub async fn probe_nxdomain() -> Option<IpAddr> {
    let mut counts: BTreeMap<IpAddr, usize> = BTreeMap::new();
    for _ in 0..3 {
        let name = format!("asm-{}.com", random_label());
        let ips: HashSet<IpAddr> = resolve_v4(&name).await.into_iter().collect();
        for ip in ips {
            *counts.entry(ip).or_default() += 1;
        }
    }
    counts.into_iter().find(|(_, n)| *n >= 2).map(|(ip, _)| ip)
}

fn nx_finding(key: &str, ip: IpAddr) -> Finding {
    Finding::new(
        ScannerId::Dns,
        "dns.nxdomain_hijack",
        &format!("nxhijack|{key}"),
        Severity::Medium,
        tf!("DNS 把不存在的網域導到 {ip}", ip = ip.to_string()),
        tf!(
            "這個網路的 DNS 對不存在的網域回了位址 {ip}，而不是「查無此網域」。有些電信業者這樣塞廣告；被入侵的路由器或惡意 DNS 也會這樣把打錯字的網址導到假網站。",
            ip = ip.to_string()
        ),
        text(format!("network={key} nxdomain_redirect={ip}")),
        t!("改用可信任的 DNS（公司 DNS 或 1.1.1.1、9.9.9.9），檢查路由器的 DNS 設定"),
    )
    .with_tag("dns")
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

#[derive(Deserialize)]
struct DohResp {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

async fn doh_v4(client: &reqwest::Client, name: &str) -> Vec<IpAddr> {
    let url = format!("https://cloudflare-dns.com/dns-query?name={name}&type=A");
    let Ok(resp) = client.get(&url).header("accept", "application/dns-json").send().await else {
        return Vec::new();
    };
    let Ok(r) = resp.json::<DohResp>().await else {
        return Vec::new();
    };
    r.answer
        .into_iter()
        .filter(|a| a.rtype == 1)
        .filter_map(|a| a.data.parse().ok())
        .collect()
}

/// 兩組答案是不是同一個業者：有共同的 ASN（有 ASN 資料時）或共同的 /16。
fn same_operator(a: &[IpAddr], b: &[IpAddr], intel: Option<&IntelDb>) -> bool {
    let asn = |ip: &IpAddr| intel.and_then(|db| db.geo.lookup(*ip)).and_then(|g| g.asn);
    let asns_a: HashSet<u32> = a.iter().filter_map(asn).collect();
    if asns_a.iter().any(|x| b.iter().filter_map(asn).any(|y| y == *x)) {
        return true;
    }
    let net16 = |ip: &IpAddr| match ip {
        IpAddr::V4(v) => Some([v.octets()[0], v.octets()[1]]),
        _ => None,
    };
    let na: HashSet<[u8; 2]> = a.iter().filter_map(net16).collect();
    b.iter().filter_map(net16).any(|n| na.contains(&n))
}

/// （選用）常見網域的答案跟加密 DNS 比：≥ 2 個完全不同業者就告警。會把這 3 個網域送給 Cloudflare。
pub async fn verify_answers(intel: Option<&IntelDb>) -> Vec<Finding> {
    let Ok(client) = crate::intel::fetch::http_client() else {
        return Vec::new();
    };
    let mut bad = Vec::new();
    for name in SENTINELS {
        let (sys, doh) = (resolve_v4(name).await, doh_v4(&client, name).await);
        if sys.is_empty() || doh.is_empty() {
            continue;
        }
        if !same_operator(&sys, &doh, intel) {
            bad.push(format!("{name}: {} ≠ {}", join_ips(&sys), join_ips(&doh)));
        }
    }
    if bad.len() < 2 {
        return Vec::new();
    }
    vec![Finding::new(
        ScannerId::Dns,
        "dns.answer_mismatch",
        "answers|sentinels",
        Severity::Medium,
        t!("DNS 回的答案跟加密 DNS 查到的不一樣"),
        tf!(
            "幾個常見網站，這台的 DNS 回的位址跟加密 DNS（Cloudflare）查到的屬於完全不同的業者：{list}。可能是 DNS 被竄改或被攔截。",
            list = bad.join("；")
        ),
        text(bad.join("\n")),
        t!("改用可信任的 DNS 並檢查路由器與網卡的 DNS 設定；在公司網路請先確認是不是公司的 DNS 過濾或代理"),
    )
    .with_tag("dns")]
}

/// macOS：裝了加密 DNS 描述檔（`com.apple.dnsSettings.managed`）。需要 root；讀不到就略過。
pub async fn macos_profile_findings() -> Vec<Finding> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let spec = crate::util::cmd::CmdSpec::new("/usr/bin/profiles", &["show", "-type", "configuration"]).timeout(15_000);
    let Ok(out) = crate::util::cmd::CmdRunner::run(&crate::util::cmd::RealRunner, &spec).await else {
        return Vec::new();
    };
    if !out.stdout.contains("com.apple.dnsSettings.managed") {
        return Vec::new();
    }
    let lines: Vec<String> = out
        .stdout
        .lines()
        .map(str::trim)
        .filter(|l| {
            l.contains("ServerURL")
                || l.contains("ServerName")
                || l.contains("DNSProtocol")
                || l.contains("attribute: name")
        })
        .take(12)
        .map(str::to_string)
        .collect();
    vec![Finding::new(
        ScannerId::Dns,
        "dns.rogue_profile",
        "macprofile|dns",
        Severity::Medium,
        t!("這台 Mac 裝了加密 DNS 設定描述檔"),
        tf!(
            "系統設定裡有一個描述檔把 DNS 改走指定的加密 DNS 伺服器（{detail}）。公司 MDM 派的就是正常的；不認得的描述檔可能把所有網域查詢導給別人。",
            detail = if lines.is_empty() { "—".to_string() } else { lines.join("；") }
        ),
        text(lines.join("\n")),
        t!("到「系統設定 → 一般 → 裝置管理」確認描述檔來源；不認得就移除"),
    )
    .with_tag("dns")]
}

pub struct Inputs<'a> {
    pub records: &'a [DnsRecord],
    pub intel: Option<&'a IntelDb>,
    pub kg: &'a KnownGood,
    pub verify_answers: bool,
}

/// 跑全部竄改偵測，更新 `dns/tamper.json`。
pub async fn check(config_dir: &Path, i: Inputs<'_>) -> Vec<Finding> {
    let now = Utc::now();
    let mut st = TamperState::load(config_dir);
    let mut out = Vec::new();
    let servers = current_servers().await;
    if let Some(key) = network_key() {
        out.extend(resolver_findings(&mut st, &key, &servers, i.intel, i.kg, now));
        if let Some(net) = st.networks.get_mut(&key) {
            if net.nx_checked_at.is_none_or(|t| now - t > NX_EVERY) {
                net.nx_hijack = probe_nxdomain().await;
                net.nx_checked_at = Some(now);
            }
            if let Some(ip) = net.nx_hijack {
                out.push(nx_finding(&key, ip));
            }
        }
    }
    let hp = hosts_path();
    if let Ok(text) = tokio::fs::read_to_string(&hp).await {
        out.extend(hosts_findings(&hp, &text));
    }
    out.extend(wpad_findings(i.records));
    if i.verify_answers {
        out.extend(verify_answers(i.intel).await);
    }
    out.extend(macos_profile_findings().await);
    out.extend(protect_findings(config_dir, &servers, now));
    let _ = st.save(config_dir);
    out
}

/// 公司有防護 DNS 但這台沒在用（`dns.not_protected`）、防護 DNS 連不上而自動改回原本的 DNS（`dns.protect_restored`）。
pub fn protect_findings(config_dir: &Path, servers: &[IpAddr], now: chrono::DateTime<Utc>) -> Vec<Finding> {
    use crate::dns::usehub::{HubProtect, Restored, RESTORED_FILE};
    let mut out = Vec::new();
    let restored: Option<Restored> = std::fs::read_to_string(config_dir.join(RESTORED_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    if let Some(r) = restored.filter(|r| now - r.at < chrono::Duration::hours(24)) {
        let list = r.servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
        out.push(
            Finding::new(
                ScannerId::Dns,
                "dns.protect_restored",
                &format!("protect_restored|{}", r.at.timestamp()),
                Severity::Medium,
                t!("防護 DNS 連不上，已改回原本的 DNS"),
                tf!(
                    "這台設定成用公司的防護 DNS（{servers}），但連續查不到，背景服務為了不斷網已自動改回原本的 DNS；這段期間不受防護 DNS 保護。",
                    servers = list.clone()
                ),
                text(format!("servers={list} restored_at={}", r.at.to_rfc3339())),
                t!("確認防護 DNS 在跑、這台連得到，再執行 ai-security-monitor dns use-hub"),
            )
            .with_tag("dns"),
        );
    }
    let Some(hp) = HubProtect::load(config_dir) else {
        return out;
    };
    if !hp.enabled || hp.resolver_ips.is_empty() || servers.is_empty() {
        return out;
    }
    // 這台自己就是防護 DNS 時，系統 DNS 指向 loopback 也算有保護
    let local = crate::config::load(config_dir)
        .map(|c| c.dns.server.enabled)
        .unwrap_or(false);
    if servers
        .iter()
        .any(|s| hp.resolver_ips.contains(s) || (local && s.is_loopback()))
    {
        return out;
    }
    let cur = servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
    let want = hp
        .resolver_ips
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    out.push(
        Finding::new(
            ScannerId::Dns,
            "dns.not_protected",
            "not_protected",
            Severity::Low,
            t!("這台沒有用公司的防護 DNS"),
            tf!(
                "公司的防護 DNS（{want}）會擋掉威脅情資列名的網域，但這台目前用的是 {cur}，查詢不會經過它。",
                want = want.clone(),
                cur = cur.clone()
            ),
            text(format!("current={cur} expected={want}")),
            t!("在這台執行 ai-security-monitor dns use-hub（或請網管把路由器 DHCP 的 DNS 改成防護 DNS）"),
        )
        .with_tag("dns"),
    );
    out
}

/// `dns accept`：把這個網路目前的 DNS 伺服器記為正確的基準。
pub async fn accept(config_dir: &Path) -> AppResult<Option<(String, Vec<IpAddr>)>> {
    let Some(key) = network_key() else {
        return Ok(None);
    };
    let servers = current_servers().await;
    let mut st = TamperState::load(config_dir);
    let now = Utc::now();
    let net = st.networks.entry(key.clone()).or_default();
    net.servers = servers.clone();
    net.first_seen.get_or_insert(now);
    net.accepted_at = Some(now);
    st.save(config_dir)?;
    Ok(Some((key, servers)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protect_findings_follow_hub_settings() {
        use crate::dns::usehub::{HubProtect, Restored, RESTORED_FILE};
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let lan: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        // 沒有 Hub 資訊：不提醒
        assert!(protect_findings(dir.path(), &lan, now).is_empty());
        HubProtect {
            enabled: true,
            resolver_ips: vec!["192.168.1.5".parse().unwrap()],
            block: Vec::new(),
            fetched_at: Some(now),
        }
        .save(dir.path())
        .unwrap();
        let f = protect_findings(dir.path(), &lan, now);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "dns.not_protected");
        // 有用防護 DNS：不提醒
        assert!(protect_findings(dir.path(), &["192.168.1.5".parse().unwrap()], now).is_empty());
        // Hub 關掉：不提醒
        HubProtect {
            enabled: false,
            ..HubProtect::load(dir.path()).unwrap()
        }
        .save(dir.path())
        .unwrap();
        assert!(protect_findings(dir.path(), &lan, now).is_empty());
        // 24 小時內自動還原過：中
        crate::store::write_json_in(
            dir.path(),
            RESTORED_FILE,
            &Restored {
                at: now - chrono::Duration::hours(1),
                servers: vec!["192.168.1.5".parse().unwrap()],
            },
        )
        .unwrap();
        let f = protect_findings(dir.path(), &lan, now);
        assert_eq!(
            (f.len(), f[0].rule.as_str(), f[0].severity),
            (1, "dns.protect_restored", Severity::Medium)
        );
        assert!(protect_findings(dir.path(), &lan, now + chrono::Duration::hours(30)).is_empty());
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolver_baseline_change_and_intel() {
        let kg = KnownGood::load();
        let mut st = TamperState::default();
        let now = Utc::now();
        // 第一次看到這個網路：只記基準
        assert!(resolver_findings(&mut st, "192.168.1.0/24", &[ip("192.168.1.1")], None, &kg, now).is_empty());
        // 改成已知公共 DNS：低
        let f = resolver_findings(&mut st, "192.168.1.0/24", &[ip("8.8.8.8")], None, &kg, now);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Low);
        // 改成不認得的公網 DNS：中
        let f = resolver_findings(&mut st, "192.168.1.0/24", &[ip("45.33.32.156")], None, &kg, now);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].title.contains("45.33.32.156"));
        // 另一個網路有自己的基準
        assert!(resolver_findings(&mut st, "10.0.0.0/24", &[ip("10.0.0.1")], None, &kg, now).is_empty());
        // 回到基準：沒事
        assert!(resolver_findings(&mut st, "192.168.1.0/24", &[ip("192.168.1.1")], None, &kg, now).is_empty());
    }

    #[test]
    fn hosts_rules() {
        let text = "# comment\n127.0.0.1 localhost\n::1 localhost ip6-localhost\n0.0.0.0 ads.doubleclick.net\n127.0.0.1 update.microsoft.com\n0.0.0.0 www.kaspersky.com\n45.33.32.156 www.google.com\n10.0.0.8 github.com\n10.1.1.1 wpad wpad.corp.example\n192.168.1.20 nas.home\n";
        let p = Path::new("/etc/hosts");
        let f = hosts_findings(p, text);
        let by = |key: &str| {
            f.iter().find(|x| {
                x.id == Finding::new(
                    ScannerId::Dns,
                    "dns.hosts_tampered",
                    key,
                    Severity::Low,
                    String::new(),
                    String::new(),
                    Evidence::Text { detail: String::new() },
                    String::new(),
                )
                .id
            })
        };
        let prot = by("hosts|protected").expect("protected");
        assert_eq!(prot.severity, Severity::High);
        if let Evidence::File { matched_strings, .. } = &prot.evidence {
            assert_eq!(matched_strings.len(), 2);
        } else {
            panic!("file evidence");
        }
        let red = by("hosts|redirect").expect("redirect");
        assert_eq!(red.severity, Severity::High);
        assert!(by("hosts|wpad").is_some());
        // 只有擋廣告（0.0.0.0）與區網自己的名稱：沒事
        assert!(hosts_findings(p, "0.0.0.0 ads.example.com\n192.168.1.20 nas.home\n").is_empty());
        assert_eq!(parse_hosts("1.2.3.4 a.example b.example # x\n").len(), 2);
    }

    #[test]
    fn wpad_from_records() {
        use super::super::model::Source;
        let r = DnsRecord {
            ts: Utc::now(),
            name: "wpad.corp.example".into(),
            registrable: Some("corp.example".into()),
            qtype: 1,
            rcode: "NOERROR".into(),
            process: Some("svchost.exe".into()),
            exe: None,
            pid: None,
            count: 2,
            answers: vec![ip("10.0.0.66")],
            cnames: vec![],
            client: None,
            source: Source::Etw,
        };
        let f = wpad_findings(std::slice::from_ref(&r));
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("10.0.0.66"));
        let mut nx = r.clone();
        nx.rcode = "NXDOMAIN".into();
        nx.answers.clear();
        assert!(wpad_findings(&[nx]).is_empty());
    }

    #[test]
    fn operators_and_labels() {
        assert!(same_operator(&[ip("140.82.112.3")], &[ip("140.82.113.4")], None));
        assert!(!same_operator(&[ip("140.82.112.3")], &[ip("203.0.113.9")], None));
        let l = random_label();
        assert_eq!(l.len(), 12);
        assert!(l.chars().all(|c| c.is_ascii_alphabetic()));
    }
}
