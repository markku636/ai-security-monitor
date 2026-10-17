//! 防護 DNS 連上 Hub：每分鐘拉設定（ETag，沒變 304）、每 30 秒送心跳、每 30 秒分批送查詢紀錄（離線時暫存、恢復後補送）。
//! Hub 是設定的唯一來源：封鎖開關（關掉或暫停＝只轉送）、上游、清單、自訂封鎖／允許、內部網域、要不要記錄。
//! 身分：dns 權杖（`--hub-token`）或這台電腦加入 Hub 的 client 金鑰（`--hub-agent`，背景服務帶起時用）。

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

use super::server::Shared;
use super::upstream::Pool;
use super::{qlog, Config, Status};
use crate::dns::model::DnsRecord;
use crate::dns::queue::{self, Flush};
use crate::hub::{DnsConfigFetch, HubClient};

const CONFIG_EVERY: Duration = Duration::from_secs(60);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(30);
const UPLOAD_EVERY: Duration = Duration::from_secs(30);
/// 上次從 Hub 拿到的設定（重啟時 Hub 連不上也照上次的設定跑）。
pub const CACHED_CONFIG: &str = "dns-server/hub-config.json";

/// Hub 下發的設定（`GET /api/v1/dns/config`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemoteConfig {
    pub blocking: bool,
    pub upstreams: Vec<String>,
    pub feeds: Vec<String>,
    pub min_confidence: u8,
    pub block: Vec<String>,
    pub allow: Vec<String>,
    pub internal_suffixes: Vec<String>,
    pub block_private_relay: bool,
    pub log: bool,
    pub etag: String,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        RemoteConfig {
            blocking: false,
            upstreams: Vec::new(),
            feeds: Vec::new(),
            min_confidence: super::lists::DEFAULT_MIN_CONFIDENCE,
            block: Vec::new(),
            allow: Vec::new(),
            internal_suffixes: Vec::new(),
            block_private_relay: false,
            log: true,
            etag: String::new(),
        }
    }
}

/// 心跳（`POST /api/v1/dns/heartbeat`，`contract/dns-heartbeat.v1.json`）。
#[derive(Debug, Clone, Serialize)]
pub struct Heartbeat {
    pub version: String,
    pub hostname: String,
    pub status: Status,
}

/// 查詢紀錄一批（`POST /api/v1/dns/queries`，`contract/dns-resolver.v1.json`）；每列都帶 client。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolverBatch {
    pub records: Vec<DnsRecord>,
}

/// 連 Hub 的狀態（寫進 status.json，`dns-server --status` 看得到）。
#[derive(Debug, Clone, Default, Serialize)]
pub struct LinkStatus {
    pub url: String,
    /// `token`（dns 權杖）或 `agent`（這台電腦的 client 金鑰）。
    pub auth: String,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ok: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_etag: Option<String>,
    /// Hub 太舊、沒有防護 DNS 端點。
    pub unsupported: bool,
    pub queued_records: usize,
}

pub struct Link {
    pub client: Arc<HubClient>,
    pub status: Arc<Mutex<LinkStatus>>,
}

impl Link {
    pub fn new(client: HubClient, auth: &str) -> Link {
        let status = LinkStatus {
            url: client.base().to_string(),
            auth: auth.to_string(),
            ..Default::default()
        };
        Link {
            client: Arc::new(client),
            status: Arc::new(Mutex::new(status)),
        }
    }
}

fn set_ok(st: &Mutex<LinkStatus>) {
    if let Ok(mut s) = st.lock() {
        s.connected = true;
        s.unsupported = false;
        s.last_ok = Some(Utc::now());
        s.last_error = None;
    }
}

fn set_err(st: &Mutex<LinkStatus>, e: String) {
    if let Ok(mut s) = st.lock() {
        s.connected = false;
        s.last_error = Some(e);
    }
}

fn set_unsupported(st: &Mutex<LinkStatus>) {
    if let Ok(mut s) = st.lock() {
        s.connected = false;
        s.unsupported = true;
    }
}

/// 上次的 Hub 設定；沒有（第一次連）回 None。
pub fn load_cached(config_dir: &std::path::Path) -> Option<RemoteConfig> {
    let text = std::fs::read_to_string(config_dir.join(CACHED_CONFIG)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 套用 Hub 的設定；清單相關的欄位變了回 true（要重建封鎖清單）。
pub async fn apply(rc: &RemoteConfig, sh: &Shared, live: &RwLock<Config>) -> bool {
    use std::sync::atomic::Ordering;
    sh.blocking.store(rc.blocking, Ordering::Relaxed);
    sh.log_on.store(rc.log, Ordering::Relaxed);
    sh.internal_suffixes.store(Arc::new(rc.internal_suffixes.clone()));
    let cur_up = live.read().map(|c| c.upstreams.clone()).unwrap_or_default();
    if cur_up != rc.upstreams {
        let ups = rc.upstreams.clone();
        // DoH 上游建立時可能要解析 bootstrap 名稱，不要卡住 runtime
        if let Ok(Ok(p)) = tokio::task::spawn_blocking(move || Pool::new(&ups)).await {
            sh.pool.store(Arc::new(p));
            if let Ok(mut c) = live.write() {
                c.upstreams = rc.upstreams.clone();
            }
        }
    }
    let Ok(mut c) = live.write() else {
        return false;
    };
    let changed = c.feeds != rc.feeds
        || c.min_confidence != rc.min_confidence
        || c.custom_block != rc.block
        || c.custom_allow != rc.allow
        || c.block_private_relay != rc.block_private_relay;
    c.feeds = rc.feeds.clone();
    c.min_confidence = rc.min_confidence;
    c.custom_block = rc.block.clone();
    c.custom_allow = rc.allow.clone();
    c.block_private_relay = rc.block_private_relay;
    c.blocking = rc.blocking;
    c.internal_suffixes = rc.internal_suffixes.clone();
    c.log = rc.log;
    changed
}

async fn fetch_config(
    link: &Link,
    etag: &mut Option<String>,
    sh: &Shared,
    live: &RwLock<Config>,
    reload: &Notify,
    config_dir: &std::path::Path,
) {
    match link.client.dns_config(etag.as_deref()).await {
        Ok(DnsConfigFetch::NotModified) => set_ok(&link.status),
        Ok(DnsConfigFetch::Unsupported) => set_unsupported(&link.status),
        Ok(DnsConfigFetch::Config(v)) => match serde_json::from_value::<RemoteConfig>(v) {
            Ok(rc) => {
                if apply(&rc, sh, live).await {
                    reload.notify_one();
                }
                let _ = crate::store::write_json_in(config_dir, CACHED_CONFIG, &rc);
                *etag = Some(rc.etag.clone()).filter(|e| !e.is_empty());
                set_ok(&link.status);
                if let Ok(mut s) = link.status.lock() {
                    s.config_etag = etag.clone();
                }
            }
            Err(e) => set_err(&link.status, e.to_string()),
        },
        Err(e) => set_err(&link.status, e.message()),
    }
}

/// 跟 Hub 同步，直到被 abort。`status` 產生目前的狀態（心跳用）。
pub async fn run(
    link: Link,
    sh: Arc<Shared>,
    live: Arc<RwLock<Config>>,
    reload: Arc<Notify>,
    config_dir: PathBuf,
    status: impl Fn() -> Status + Send + 'static,
) {
    let base = qlog::base_dir(&config_dir);
    let hostname = sysinfo::System::host_name().unwrap_or_default();
    let mut etag: Option<String> = None;
    let mut cfg_tick = tokio::time::interval(CONFIG_EVERY);
    let mut hb_tick = tokio::time::interval(HEARTBEAT_EVERY);
    let mut up_tick = tokio::time::interval(UPLOAD_EVERY);
    // 先拉一次設定，心跳才不會報出還沒套用的狀態
    cfg_tick.tick().await;
    fetch_config(&link, &mut etag, &sh, &live, &reload, &config_dir).await;
    loop {
        tokio::select! {
            _ = cfg_tick.tick() => fetch_config(&link, &mut etag, &sh, &live, &reload, &config_dir).await,
            _ = hb_tick.tick() => {
                let hb = Heartbeat { version: crate::VERSION.to_string(), hostname: hostname.clone(), status: status() };
                match link.client.dns_heartbeat(&hb).await {
                    Ok(Some(v)) => {
                        set_ok(&link.status);
                        let remote = v.get("config_etag").and_then(Value::as_str).map(str::to_string);
                        if remote.is_some() && remote != etag {
                            fetch_config(&link, &mut etag, &sh, &live, &reload, &config_dir).await;
                        }
                    }
                    Ok(None) => set_unsupported(&link.status),
                    Err(e) => set_err(&link.status, e.message()),
                }
            }
            _ = up_tick.tick() => {
                let client = link.client.clone();
                let r = queue::flush_with(&base, |records| {
                    let client = client.clone();
                    async move { client.upload_resolver(&ResolverBatch { records }).await }
                })
                .await;
                match r {
                    Flush::Sent { left, .. } => {
                        if let Ok(mut s) = link.status.lock() {
                            s.queued_records = left;
                        }
                    }
                    Flush::Unsupported => set_unsupported(&link.status),
                    Flush::Failed(e) => set_err(&link.status, e),
                }
            }
        }
    }
}

/// 契約範例（`contract/dns-heartbeat.v1.json`）。
#[doc(hidden)]
pub fn sample_heartbeat() -> Heartbeat {
    use chrono::TimeZone;
    let at = |m: u32| Utc.with_ymd_and_hms(2026, 10, 17, 9, m, 0).unwrap();
    Heartbeat {
        version: "0.6.0".into(),
        hostname: "dns-01".into(),
        status: Status {
            running: true,
            started_at: at(0),
            updated_at: at(30),
            listen: vec!["0.0.0.0:53".into(), "[::]:53".into()],
            blocking: true,
            lists_loaded: vec!["certpl-domains".into(), "hagezi-tif-mini".into()],
            lists_missing: Vec::new(),
            blocklist_entries: 354_812,
            lists_memory_bytes: 3_412_224,
            cache_entries: 18_204,
            upstreams: vec![super::UpstreamStatus {
                upstream: "https://dns.quad9.net/dns-query".into(),
                ewma_ms: 18.4,
                failures: 0,
            }],
            stats: super::stats::Snapshot {
                queries: 125_000,
                blocked: 312,
                cache_hits: 98_000,
                cache_misses: 26_500,
                hit_p50_us: Some(100),
                hit_p99_us: Some(500),
                miss_p50_us: Some(20_000),
                miss_p99_us: Some(100_000),
                ..Default::default()
            },
            hub: Some(LinkStatus {
                url: "https://hub.example.test".into(),
                auth: "token".into(),
                connected: true,
                last_ok: Some(at(30)),
                config_etag: Some("\"5f2c0e0d\"".into()),
                ..Default::default()
            }),
        },
    }
}

/// 契約範例（`contract/dns-resolver.v1.json`）。
#[doc(hidden)]
pub fn sample_batch() -> ResolverBatch {
    use chrono::TimeZone;
    let at = |m: u32| Utc.with_ymd_and_hms(2026, 10, 17, 9, m, 0).unwrap();
    let rec = |m: u32, client: &str, name: &str, rcode: &str, blocked: Option<&str>, answers: &[&str]| DnsRecord {
        ts: at(m),
        name: name.into(),
        registrable: crate::dns::heuristics::registrable_domain(name).map(str::to_string),
        qtype: 1,
        rcode: rcode.into(),
        process: blocked.map(str::to_string),
        exe: None,
        pid: None,
        count: 3,
        answers: answers.iter().map(|a| a.parse().unwrap()).collect(),
        cnames: Vec::new(),
        client: Some(client.into()),
        source: crate::dns::model::Source::Resolver,
    };
    ResolverBatch {
        records: vec![
            rec(
                30,
                "192.0.2.10",
                "updates.example.net",
                "NOERROR",
                None,
                &["203.0.113.20"],
            ),
            rec(
                30,
                "192.0.2.77",
                "login.example-phish.test",
                "BLOCKED",
                Some("CERT Polska"),
                &[],
            ),
            rec(31, "2001:db8::77", "nonexistent.example.org", "NXDOMAIN", None, &[]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsd::cache::Cache;
    use crate::dnsd::lists::Lists;

    fn shared() -> Shared {
        Shared::new(
            Lists::default(),
            Cache::new(10),
            Pool::new(&["127.0.0.1:5399".to_string()]).unwrap(),
            crate::dnsd::default_acl(),
            0,
            true,
            Vec::new(),
            None,
        )
    }

    #[tokio::test]
    async fn applies_remote_config() {
        use std::sync::atomic::Ordering;
        let sh = shared();
        let live = RwLock::new(Config {
            upstreams: vec!["127.0.0.1:5399".into()],
            ..Config::default()
        });
        let rc: RemoteConfig = serde_json::from_value(serde_json::json!({
            "blocking": false,
            "upstreams": ["127.0.0.1:5399"],
            "feeds": [],
            "min_confidence": 75,
            "block": ["bad.example"],
            "allow": [],
            "internal_suffixes": ["corp.example"],
            "block_private_relay": false,
            "log": false,
            "etag": "\"abc\"",
            "paused_until": null
        }))
        .unwrap();
        assert!(apply(&rc, &sh, &live).await, "custom block changed → lists reload");
        assert!(!sh.blocking.load(Ordering::Relaxed));
        assert!(!sh.log_on.load(Ordering::Relaxed));
        assert_eq!(sh.internal_suffixes.load().as_slice(), ["corp.example".to_string()]);
        assert_eq!(live.read().unwrap().custom_block, vec!["bad.example".to_string()]);
        // 同一份設定再套一次：清單不用重建
        assert!(!apply(&rc, &sh, &live).await);
        // 換上游：整組換掉
        let rc2 = RemoteConfig {
            upstreams: vec!["127.0.0.1:5400".into()],
            ..rc
        };
        assert!(!apply(&rc2, &sh, &live).await);
        assert_eq!(sh.pool.load().ups[0].label, "127.0.0.1:5400");
    }

    #[test]
    fn sample_batch_has_clients() {
        let b = sample_batch();
        assert!(b
            .records
            .iter()
            .all(|r| r.client.is_some() && r.source == crate::dns::model::Source::Resolver));
    }
}
