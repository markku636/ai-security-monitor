//! 尋找公司的 Security Hub：依序
//! 1. 明確給的網址（`--hub`／參數）、環境變數 `AI_SECURITY_MONITOR_HUB_URL`、設定檔裡已註冊的 Hub
//! 2. 公司 DNS 的 SRV 紀錄 `_aisecmon._tcp.<搜尋網域>`（同名 TXT 可帶 `url=`、`fp=`、`path=`、`proto=`）
//! 3. 區網 mDNS／DNS-SD 廣播 `_aisecmon._tcp.local`（TXT 同上）
//!
//! 每個候選都打 `/api/v1/hub/identity` 驗章，拿到名稱與指紋給使用者確認；前一層找到可用的 Hub 就不再往下找
//! （`discover` 指令列出全部）。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::dns::{self, Record};
use super::identity::{self, HubIdentity};
use super::validate_url;
use crate::error::{AppError, AppResult};

/// DNS-SD 服務類型（不含網域）。服務名稱 `aisecmon` 9 字，符合 RFC 6335／6763 的 15 字上限。
pub const SERVICE: &str = "_aisecmon._tcp";
pub const MDNS_SERVICE: &str = "_aisecmon._tcp.local.";
/// 0.3.0 發佈前用過的長名稱（20 字，不合規）；DNS SRV 找不到新名稱時才查它，給已經照舊說明建好紀錄的人。
pub const LEGACY_SERVICE: &str = "_ai-security-monitor._tcp";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// 命令列 `--hub`／網址參數、安裝程式預填。
    Explicit,
    /// 環境變數 `AI_SECURITY_MONITOR_HUB_URL`。
    Env,
    /// 設定檔裡已註冊的 Hub。
    Config,
    /// 公司 DNS 的 SRV 紀錄。
    DnsSrv,
    /// 區網 mDNS 廣播。
    Mdns,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Explicit => t!("指定的網址"),
            Source::Env => t!("環境變數"),
            Source::Config => t!("設定檔"),
            Source::DnsSrv => t!("公司 DNS（SRV）"),
            Source::Mdns => t!("區網廣播（mDNS）"),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Candidate {
    pub url: String,
    pub source: Source,
    /// 來源細節：DNS 網域或 mDNS 服務名稱。
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// DNS／mDNS TXT 裡宣告的指紋（要和 Hub 實際的一致）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txt_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Found {
    #[serde(flatten)]
    pub candidate: Candidate,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<HubIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Found {
    pub fn fingerprint(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.fingerprint.as_str())
    }
}

/// TXT 的 `key=value`（key 不分大小寫）。
pub fn txt_map<'a>(items: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, String> {
    items
        .into_iter()
        .filter_map(|s| {
            let (k, v) = s.split_once('=')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

fn path_of(txt: &BTreeMap<String, String>) -> String {
    let p = txt.get("path").map(|s| s.trim().trim_end_matches('/')).unwrap_or("");
    if p.is_empty()
        || !p.starts_with('/')
        || p.contains("..")
        || !p.chars().all(|c| c.is_ascii_alphanumeric() || "/-._~".contains(c))
    {
        String::new()
    } else {
        p.to_string()
    }
}

fn scheme_of(txt: &BTreeMap<String, String>, port: u16) -> &'static str {
    match txt
        .get("proto")
        .or(txt.get("scheme"))
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("https") => "https",
        Some("http") => "http",
        _ if port == 443 || port == 8443 => "https",
        _ => "http",
    }
}

fn host_for_url(host: &str) -> String {
    let h = host.trim_end_matches('.');
    if h.contains(':') && !h.starts_with('[') {
        format!("[{h}]")
    } else {
        h.to_string()
    }
}

fn fmt_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let default = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    if default {
        format!("{scheme}://{}{path}", host_for_url(host))
    } else {
        format!("{scheme}://{}:{port}{path}", host_for_url(host))
    }
}

/// 只接受單純的 http(s) 網址（TXT 是別人可以寫的資料）。
fn clean_txt_url(u: &str) -> Option<String> {
    let s = u.trim().trim_end_matches('/');
    let lower = s.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    let ok = !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~:/[]".contains(c));
    ok.then(|| s.to_string())
}

/// SRV＋TXT 紀錄 → 候選（依 priority 小到大、weight 大到小）。TXT 有 `url=` 時以它為準。
pub fn srv_candidates(domain: &str, records: &[Record]) -> Vec<Candidate> {
    let txt_items: Vec<&str> = records
        .iter()
        .filter_map(|r| match r {
            Record::Txt { items, .. } => Some(items.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();
    let txt = txt_map(txt_items);
    let fp = txt.get("fp").cloned().filter(|s| !s.is_empty());
    let mk = |url: String| Candidate {
        url,
        source: Source::DnsSrv,
        detail: domain.to_string(),
        txt_fingerprint: fp.clone(),
    };
    if let Some(u) = txt.get("url").and_then(|u| clean_txt_url(u)) {
        return vec![mk(u)];
    }
    let mut srvs: Vec<(u16, u16, u16, &str)> = records
        .iter()
        .filter_map(|r| match r {
            // 目標是 "." 表示「沒有這個服務」（RFC 2782）
            Record::Srv {
                priority,
                weight,
                port,
                target,
                ..
            } if !target.is_empty() && target != "." && *port > 0 => Some((*priority, *weight, *port, target.as_str())),
            _ => None,
        })
        .collect();
    srvs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let path = path_of(&txt);
    srvs.into_iter()
        .map(|(_, _, port, target)| mk(fmt_url(scheme_of(&txt, port), target, port, &path)))
        .collect()
}

/// mDNS 解析到的服務。
#[derive(Debug, Clone, PartialEq)]
pub struct MdnsHit {
    pub fullname: String,
    pub port: u16,
    pub addrs: Vec<IpAddr>,
    pub txt: BTreeMap<String, String>,
}

/// 優先順序：私網 IPv4 → 其他 IPv4 → IPv6（link-local 不用）。
fn best_addr(addrs: &[IpAddr]) -> Option<IpAddr> {
    let rank = |ip: &IpAddr| match ip {
        IpAddr::V4(v) if v.is_loopback() => 3,
        IpAddr::V4(v) if v.is_private() => 0,
        IpAddr::V4(v) if v.is_link_local() => 2,
        IpAddr::V4(_) => 1,
        IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80 => 9,
        IpAddr::V6(_) => 4,
    };
    addrs
        .iter()
        .filter(|ip| rank(ip) < 9)
        .min_by_key(|ip| rank(ip))
        .copied()
}

pub fn mdns_candidate(hit: &MdnsHit) -> Option<Candidate> {
    let detail = hit
        .fullname
        .trim_end_matches('.')
        .trim_end_matches(MDNS_SERVICE.trim_end_matches('.'))
        .trim_end_matches('.')
        .replace("\\032", " ");
    let fp = hit.txt.get("fp").cloned().filter(|s| !s.is_empty());
    let url = match hit.txt.get("url").and_then(|u| clean_txt_url(u)) {
        Some(u) => u,
        None => {
            let ip = best_addr(&hit.addrs)?;
            fmt_url(
                scheme_of(&hit.txt, hit.port),
                &ip.to_string(),
                hit.port,
                &path_of(&hit.txt),
            )
        }
    };
    Some(Candidate {
        url,
        source: Source::Mdns,
        detail,
        txt_fingerprint: fp,
    })
}

/// 在區網上找 `_aisecmon._tcp.local`（等 `timeout`）。只送出查詢與接收回應，不對外宣告任何東西。
pub async fn browse_mdns(timeout: Duration) -> AppResult<Vec<MdnsHit>> {
    tokio::task::spawn_blocking(move || -> AppResult<Vec<MdnsHit>> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
        let rx = daemon
            .browse(MDNS_SERVICE)
            .map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
        let deadline = std::time::Instant::now() + timeout;
        let mut hits: Vec<MdnsHit> = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                    let hit = MdnsHit {
                        fullname: info.fullname.clone(),
                        port: info.port,
                        addrs: info.addresses.iter().map(|a| a.to_ip_addr()).collect(),
                        txt: info
                            .txt_properties
                            .iter()
                            .map(|p| (p.key().to_ascii_lowercase(), p.val_str().to_string()))
                            .collect(),
                    };
                    hits.retain(|h| h.fullname != hit.fullname);
                    hits.push(hit);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = daemon.stop_browse(MDNS_SERVICE);
        let _ = daemon.shutdown();
        Ok(hits)
    })
    .await
    .map_err(|e| AppError::Hub(e.to_string()))?
}

/// 查一個 SRV 名稱（含同名 TXT）。DNS 沒回應時回 `None`。
async fn srv_lookup(cfg: &dns::DnsConfig, domain: &str, service: &str, timeout: Duration) -> Option<Vec<Candidate>> {
    let name = format!("{service}.{domain}");
    let mut recs = dns::resolve(cfg, &name, dns::TYPE_SRV, timeout).await.ok()?;
    if recs.iter().any(|r| matches!(r, Record::Srv { .. })) || recs.is_empty() {
        // TXT 另外查（多數 DNS 伺服器不會把 TXT 放進 SRV 回應的 additional）
        if let Ok(t) = dns::resolve(cfg, &name, dns::TYPE_TXT, timeout).await {
            recs.extend(t.into_iter().filter(|r| matches!(r, Record::Txt { .. })));
        }
    }
    Some(srv_candidates(domain, &recs))
}

/// 從 DNS SRV 找。
pub async fn find_srv(cfg: &dns::DnsConfig, timeout: Duration) -> Vec<Candidate> {
    let mut out = Vec::new();
    for domain in &cfg.search {
        // 先查新名稱；DNS 有回答但沒有紀錄才查舊的長名稱（沒回應就不再多等一次）
        for service in [SERVICE, LEGACY_SERVICE] {
            match srv_lookup(cfg, domain, service, timeout).await {
                Some(found) if found.is_empty() => continue,
                Some(found) => out.extend(found),
                None => {}
            }
            break;
        }
    }
    out
}

/// http 的主機名稱：解析得到的位址全是本機或私網才接受（公司內網的 hub.corp.example）。
async fn private_hostname(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://") else {
        return false;
    };
    let hostport = rest.split('/').next().unwrap_or("");
    let target = if hostport.contains(':') && !hostport.starts_with('[') {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };
    match tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(target)).await {
        Ok(Ok(addrs)) => {
            let v: Vec<_> = addrs.collect();
            !v.is_empty() && v.iter().all(|a| !crate::util::net::classify(a.ip()).is_public())
        }
        _ => false,
    }
}

/// 候選網址能不能用：https，或 http 但是本機／私網（主機名稱要解析成私網位址）。
pub async fn acceptable_url(url: &str, insecure_http: bool) -> AppResult<String> {
    match validate_url(url, insecure_http) {
        Ok(u) => Ok(u),
        Err(e) => {
            if private_hostname(url).await {
                Ok(url.trim().trim_end_matches('/').to_string())
            } else {
                Err(e)
            }
        }
    }
}

/// 「測試連線」的結果（桌面版設定頁）。
#[derive(Debug, Clone, Serialize)]
pub struct HubCheck {
    pub url: String,
    /// `/api/health` 回應（版本、資料庫狀態）。
    pub health: serde_json::Value,
    /// Hub 身分（舊版 Hub 沒有）。
    pub identity: Option<HubIdentity>,
    /// 這台電腦釘選的指紋。
    pub pinned_fingerprint: Option<String>,
    /// 和釘選的不同（要換 Hub，需要明確確認）。
    pub fingerprint_changed: bool,
}

/// 測試一個 Hub 網址：網址規則（https；http 只限本機／私網）、健康檢查、身分驗章，並和釘選的指紋比對。
pub async fn check_hub(url: &str, insecure_http: bool, pinned: Option<&str>) -> AppResult<HubCheck> {
    let url = acceptable_url(url, insecure_http).await?;
    let http = identity::http_client(Duration::from_secs(10))?;
    let resp = http
        .get(format!("{url}/api/health"))
        .send()
        .await
        .map_err(|e| AppError::Hub(tf!("連不上 hub：{e}", e = e)))?;
    let status = resp.status().as_u16();
    let health: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if status != 200 && health.get("version").is_none() {
        return Err(AppError::Hub(tf!("hub 健康檢查失敗（HTTP {status}）", status = status)));
    }
    let identity = identity::fetch(&http, &url).await?;
    let pinned = pinned.filter(|p| !p.trim().is_empty()).map(str::to_string);
    let fingerprint_changed = match (&pinned, &identity) {
        (Some(p), Some(id)) => !identity::same_fingerprint(p, &id.fingerprint),
        (Some(_), None) => true,
        _ => false,
    };
    Ok(HubCheck {
        url,
        health,
        identity,
        pinned_fingerprint: pinned,
        fingerprint_changed,
    })
}

/// 驗證一個候選：網址規則、身分驗章、TXT 指紋（有寫就要一致）。
pub async fn probe(http: &reqwest::Client, c: Candidate, insecure_http: bool) -> Found {
    let url = match acceptable_url(&c.url, insecure_http).await {
        Ok(u) => u,
        Err(e) => {
            return Found {
                candidate: c,
                identity: None,
                error: Some(e.message()),
            };
        }
    };
    let c = Candidate { url: url.clone(), ..c };
    match identity::fetch(http, &url).await {
        Ok(Some(id)) => {
            if let Some(fp) = c.txt_fingerprint.as_deref() {
                if !identity::same_fingerprint(fp, &id.fingerprint) {
                    let msg = tf!(
                        "DNS／mDNS 宣告的指紋 {txt} 和 Hub 實際的 {fp} 不符，略過",
                        txt = fp,
                        fp = id.fingerprint
                    );
                    return Found {
                        candidate: c,
                        identity: Some(id),
                        error: Some(msg),
                    };
                }
            }
            Found {
                candidate: c,
                identity: Some(id),
                error: None,
            }
        }
        Ok(None) => Found {
            candidate: c,
            identity: None,
            error: Some(t!("這個 Hub 版本太舊，不支援免金鑰加入（請用 --key）").into()),
        },
        Err(e) => Found {
            candidate: c,
            identity: None,
            error: Some(e.message()),
        },
    }
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub explicit: Option<String>,
    pub env_url: Option<String>,
    pub config_url: Option<String>,
    pub dns: bool,
    pub mdns: bool,
    pub timeout: Duration,
    pub insecure_http: bool,
    /// 列出所有來源（`discover`）；否則前一層找到可用的就停。
    pub all: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            explicit: None,
            env_url: crate::util::env::var("HUB_URL"),
            config_url: None,
            dns: true,
            mdns: true,
            timeout: Duration::from_secs(3),
            insecure_http: false,
            all: false,
        }
    }
}

/// 明確來源（命令列 → 環境變數 → 設定檔）。
pub fn direct_candidates(o: &Opts) -> Vec<Candidate> {
    let mut v = Vec::new();
    for (u, s) in [
        (&o.explicit, Source::Explicit),
        (&o.env_url, Source::Env),
        (&o.config_url, Source::Config),
    ] {
        if let Some(u) = u.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            v.push(Candidate {
                url: u.trim_end_matches('/').to_string(),
                source: s,
                detail: String::new(),
                txt_fingerprint: None,
            });
        }
    }
    v
}

fn dedupe(v: Vec<Candidate>) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for c in v {
        if !out.iter().any(|o| o.url.eq_ignore_ascii_case(&c.url)) {
            out.push(c);
        }
    }
    out
}

async fn probe_all(http: &reqwest::Client, cands: Vec<Candidate>, insecure_http: bool) -> Vec<Found> {
    let mut set = tokio::task::JoinSet::new();
    for (i, c) in dedupe(cands).into_iter().enumerate() {
        let http = http.clone();
        set.spawn(async move { (i, probe(&http, c, insecure_http).await) });
    }
    let mut v: Vec<(usize, Found)> = set.join_all().await;
    v.sort_by_key(|(i, f)| (f.candidate.source, *i));
    v.into_iter().map(|(_, f)| f).collect()
}

/// 依序找 Hub。`all` 時每一層都找。
pub async fn find(o: &Opts) -> AppResult<Vec<Found>> {
    let http = identity::http_client(Duration::from_secs(6))?;
    let mut found = probe_all(&http, direct_candidates(o), o.insecure_http).await;
    let usable = |f: &[Found]| f.iter().any(|x| x.identity.is_some() && x.error.is_none());
    if !o.all && !found.is_empty() {
        // 明確指定的網址就用它（找不到也不改去找別的 Hub）
        return Ok(found);
    }
    if o.dns {
        let cfg = dns::system_config().await;
        let srv = find_srv(&cfg, Duration::from_millis(1500)).await;
        found.extend(probe_all(&http, srv, o.insecure_http).await);
        if !o.all && usable(&found) {
            return Ok(found);
        }
    }
    if o.mdns {
        match browse_mdns(o.timeout).await {
            Ok(hits) => {
                let cands: Vec<Candidate> = hits.iter().filter_map(mdns_candidate).collect();
                let known: Vec<String> = found.iter().map(|f| f.candidate.url.to_ascii_lowercase()).collect();
                let cands = cands
                    .into_iter()
                    .filter(|c| !known.contains(&c.url.to_ascii_lowercase()))
                    .collect();
                found.extend(probe_all(&http, cands, o.insecure_http).await);
            }
            Err(e) => {
                if found.is_empty() {
                    return Err(e);
                }
            }
        }
    }
    Ok(found)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// 沒找到可用的 Hub。
    None,
    /// 只有一個（同一個指紋的多個網址算一個）：索引。
    One(usize),
    /// 好幾個不同的 Hub：要使用者用 --hub 選。
    Many(Vec<usize>),
    /// 有找到 Hub，但都不是這台電腦釘選的那一個。
    PinnedMismatch(Vec<usize>),
}

/// 挑 Hub：有釘選就只認釘選的指紋；否則不同指紋只有一個才自動選（取優先序最高的網址）。
pub fn choose(found: &[Found], pinned: Option<&str>) -> Choice {
    let ok: Vec<usize> = (0..found.len())
        .filter(|&i| found[i].identity.is_some() && found[i].error.is_none())
        .collect();
    if ok.is_empty() {
        return Choice::None;
    }
    if let Some(p) = pinned.filter(|p| !p.trim().is_empty()) {
        return match ok
            .iter()
            .find(|&&i| identity::same_fingerprint(p, found[i].fingerprint().unwrap_or("")))
        {
            Some(&i) => Choice::One(i),
            None => Choice::PinnedMismatch(ok),
        };
    }
    let mut fps: Vec<&str> = Vec::new();
    for &i in &ok {
        let fp = found[i].fingerprint().unwrap_or("");
        if !fps.iter().any(|f| identity::same_fingerprint(f, fp)) {
            fps.push(fp);
        }
    }
    if fps.len() == 1 {
        Choice::One(ok[0])
    } else {
        Choice::Many(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(prio: u16, weight: u16, port: u16, target: &str) -> Record {
        Record::Srv {
            name: "x".into(),
            priority: prio,
            weight,
            port,
            target: target.into(),
        }
    }

    #[test]
    fn service_names_follow_rfc6335() {
        // 服務名稱 1–15 字、英數與連字號、不以連字號開頭結尾（RFC 6335 §5.1）；mDNS 名稱同一個
        let name = SERVICE.strip_prefix('_').unwrap().strip_suffix("._tcp").unwrap();
        assert!((1..=15).contains(&name.len()), "{name}");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert!(!name.starts_with('-') && !name.ends_with('-'));
        assert_eq!(MDNS_SERVICE, format!("{SERVICE}.local."));
        assert_ne!(LEGACY_SERVICE, SERVICE);
    }

    #[test]
    fn srv_records_become_ordered_urls_and_txt_url_wins() {
        let r = vec![
            srv(10, 0, 8088, "hub2.corp.example."),
            srv(0, 0, 443, "hub.corp.example."),
        ];
        let c = srv_candidates("corp.example", &r);
        assert_eq!(
            c.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(),
            vec!["https://hub.corp.example", "http://hub2.corp.example:8088"]
        );
        assert_eq!(c[0].source, Source::DnsSrv);
        assert_eq!(c[0].detail, "corp.example");

        let mut r2 = r.clone();
        r2.push(Record::Txt {
            name: "x".into(),
            items: vec![
                "url=https://sec.corp.example/hub/".into(),
                "fp=72AS-YEXT-VNGO-NLC5-W2NM".into(),
            ],
        });
        let c = srv_candidates("corp.example", &r2);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].url, "https://sec.corp.example/hub");
        assert_eq!(c[0].txt_fingerprint.as_deref(), Some("72AS-YEXT-VNGO-NLC5-W2NM"));

        // proto／path、"." 目標、惡意 url
        let r3 = vec![
            srv(0, 0, 9000, "."),
            srv(0, 0, 9443, "hub.corp.example"),
            Record::Txt {
                name: "x".into(),
                items: vec![
                    "proto=https".into(),
                    "path=/sec".into(),
                    "url=javascript:alert(1)".into(),
                ],
            },
        ];
        let c = srv_candidates("corp.example", &r3);
        assert_eq!(
            c.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(),
            vec!["https://hub.corp.example:9443/sec"]
        );
        assert!(srv_candidates(
            "corp.example",
            &[Record::Txt {
                name: "x".into(),
                items: vec!["path=/../x".into()]
            }]
        )
        .is_empty());
    }

    #[test]
    fn mdns_hits_prefer_txt_url_then_private_ipv4() {
        let mut txt = BTreeMap::new();
        txt.insert("fp".to_string(), "72AS-YEXT-VNGO-NLC5-W2NM".to_string());
        let hit = MdnsHit {
            fullname: "Security\\032Hub\\032(srv1)._aisecmon._tcp.local.".into(),
            port: 3000,
            addrs: vec![
                "fe80::1".parse().unwrap(),
                "203.0.113.5".parse().unwrap(),
                "192.168.1.20".parse().unwrap(),
            ],
            txt: txt.clone(),
        };
        let c = mdns_candidate(&hit).unwrap();
        assert_eq!(c.url, "http://192.168.1.20:3000");
        assert_eq!(c.source, Source::Mdns);
        assert_eq!(c.detail, "Security Hub (srv1)");
        assert_eq!(c.txt_fingerprint.as_deref(), Some("72AS-YEXT-VNGO-NLC5-W2NM"));

        txt.insert("url".to_string(), "https://hub.corp.example".to_string());
        let c = mdns_candidate(&MdnsHit { txt, ..hit.clone() }).unwrap();
        assert_eq!(c.url, "https://hub.corp.example");

        let v6 = MdnsHit {
            addrs: vec!["2001:db8::5".parse().unwrap()],
            txt: BTreeMap::new(),
            ..hit.clone()
        };
        assert_eq!(mdns_candidate(&v6).unwrap().url, "http://[2001:db8::5]:3000");
        assert!(mdns_candidate(&MdnsHit {
            addrs: vec!["fe80::9".parse().unwrap()],
            txt: BTreeMap::new(),
            ..hit
        })
        .is_none());
    }

    #[test]
    fn direct_sources_keep_order_and_dedupe() {
        let o = Opts {
            explicit: Some("https://a.example/".into()),
            env_url: Some("https://b.example".into()),
            config_url: Some("https://A.example".into()),
            ..Opts::default()
        };
        let c = dedupe(direct_candidates(&o));
        assert_eq!(
            c.iter().map(|c| (c.url.as_str(), c.source)).collect::<Vec<_>>(),
            vec![
                ("https://a.example", Source::Explicit),
                ("https://b.example", Source::Env)
            ]
        );
        let none = Opts {
            explicit: None,
            env_url: None,
            config_url: None,
            ..Opts::default()
        };
        assert!(direct_candidates(&none).is_empty());
    }

    fn found(url: &str, source: Source, fp: Option<&str>, err: Option<&str>) -> Found {
        Found {
            candidate: Candidate {
                url: url.into(),
                source,
                detail: String::new(),
                txt_fingerprint: None,
            },
            identity: fp.map(|f| HubIdentity {
                fingerprint: f.into(),
                ..HubIdentity::default()
            }),
            error: err.map(|e| e.into()),
        }
    }

    #[test]
    fn choosing_a_hub() {
        assert_eq!(choose(&[], None), Choice::None);
        let one = vec![
            found("https://x", Source::DnsSrv, Some("AAAA-BBBB"), None),
            found("http://10.0.0.5:3000", Source::Mdns, Some("aaaa-bbbb"), None),
        ];
        assert_eq!(choose(&one, None), Choice::One(0));
        let two = vec![
            found("https://x", Source::DnsSrv, Some("AAAA-BBBB"), None),
            found("http://10.0.0.6:3000", Source::Mdns, Some("CCCC-DDDD"), None),
            found("http://10.0.0.7:3000", Source::Mdns, None, Some("unreachable")),
        ];
        assert_eq!(choose(&two, None), Choice::Many(vec![0, 1]));
        // 有釘選：只認那個指紋
        assert_eq!(choose(&two, Some("CCCC-DDDD")), Choice::One(1));
        assert_eq!(choose(&two, Some("EEEE-FFFF")), Choice::PinnedMismatch(vec![0, 1]));
        // TXT 指紋不符（有 identity 但有 error）不算可用
        let bad = vec![found(
            "https://x",
            Source::DnsSrv,
            Some("AAAA-BBBB"),
            Some("txt mismatch"),
        )];
        assert_eq!(choose(&bad, None), Choice::None);
    }

    #[tokio::test]
    async fn check_hub_reports_health_and_pin_changes() {
        // 公網 http 直接拒絕（不連線）
        let e = check_hub("http://8.8.8.8:3000", false, None).await.unwrap_err();
        assert!(matches!(e, AppError::InvalidArg(_)), "{e:?}");
        // 舊版 Hub：健康檢查 OK、沒有身分端點；有釘選指紋就算「換了」
        let (url, cap) = crate::hub::test_server::serve(vec![
            (200, r#"{"ok":true,"version":"0.2.1","db":"ok"}"#.into()),
            (404, "{}".into()),
            (200, r#"{"ok":true,"version":"0.2.1","db":"ok"}"#.into()),
            (404, "{}".into()),
        ])
        .await;
        let c = check_hub(&url, false, None).await.unwrap();
        assert_eq!(c.health["version"], "0.2.1");
        assert!(c.identity.is_none() && !c.fingerprint_changed);
        let c = check_hub(&format!("{url}/"), false, Some("AAAA-BBBB")).await.unwrap();
        assert!(c.fingerprint_changed);
        assert!(cap.lock().unwrap()[0].head.starts_with("GET /api/health "));
    }

    #[tokio::test]
    async fn probe_rejects_public_http_and_txt_mismatch() {
        let http = identity::http_client(Duration::from_secs(3)).unwrap();
        let c = Candidate {
            url: "http://203.0.113.9:3000".into(),
            source: Source::Mdns,
            detail: String::new(),
            txt_fingerprint: None,
        };
        let f = probe(&http, c, false).await;
        assert!(f.identity.is_none() && f.error.is_some());
        // 舊版 Hub（404）
        let (url, _) = crate::hub::test_server::serve(vec![(404, "{}".into())]).await;
        let f = probe(
            &http,
            Candidate {
                url,
                source: Source::Explicit,
                detail: String::new(),
                txt_fingerprint: None,
            },
            false,
        )
        .await;
        assert!(f.error.unwrap().contains("--key"));
    }
}
