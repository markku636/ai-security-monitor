//! 下載情資：ETag / Last-Modified 條件請求、大小上限、內容驗證（HTML 錯誤頁或空清單不覆蓋舊資料）。
//! 檔案：`<config>/feeds/<id>/data`（或 `data.mmdb`）＋ `meta.json`。
//! 已註冊 hub 時先從 hub 的鏡像拿（`/api/v1/feeds/<id>`，原檔原樣），hub 沒有或連不上才直接找廠商。

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, Utc};
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};

use super::parse;
use super::registry::{FeedEntry, FeedFormat, Registry};
use crate::error::{AppError, AppResult};
use crate::store;

pub const DATA_FILE: &str = "data";
pub const MMDB_FILE: &str = "data.mmdb";
pub const META_FILE: &str = "meta.json";
pub const MAX_BYTES: u64 = 96 * 1024 * 1024;
const CONCURRENCY: usize = 4;

pub fn feed_dir(config_dir: &Path, id: &str) -> PathBuf {
    config_dir.join("feeds").join(id)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct FeedMeta {
    pub feed_id: String,
    /// 最後一次成功取得新內容的時間。
    pub fetched_at: Option<DateTime<Utc>>,
    /// 最後一次檢查（含 304 / 失敗）的時間。
    pub checked_at: Option<DateTime<Utc>>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub entries: u64,
    pub sha256: String,
    pub bytes: u64,
    pub url: String,
    /// 授權要求保留的檔頭 / metadata（Spamhaus、ET、DShield）。
    pub header_lines: Vec<String>,
    /// `ok` / `error`
    pub status: String,
    pub error: Option<String>,
}

impl FeedMeta {
    pub fn load(config_dir: &Path, id: &str) -> Option<FeedMeta> {
        store::read_json_opt(&feed_dir(config_dir, id), META_FILE)
            .ok()
            .flatten()
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        let dir = feed_dir(config_dir, &self.feed_id);
        store::ensure_dir(&dir)?;
        store::write_json_in(&dir, META_FILE, self)
    }

    pub fn has_data(&self) -> bool {
        self.fetched_at.is_some()
    }

    pub fn is_fresh(&self, entry: &FeedEntry, now: DateTime<Utc>) -> bool {
        let Some(last) = self.checked_at.or(self.fetched_at) else {
            return false;
        };
        let ttl = chrono::Duration::from_std(entry.refresh()).unwrap_or_else(|_| chrono::Duration::hours(1));
        now - last < ttl
    }
}

/// `{YYYY}-{MM}` 範本：先試本月，再試上個月（DB-IP 月初才發布）。
pub fn expand_urls(tpl: &str, now: DateTime<Utc>) -> Vec<String> {
    if !tpl.contains("{YYYY}") {
        return vec![tpl.to_string()];
    }
    let cur = (now.year(), now.month());
    let prev = if cur.1 == 1 {
        (cur.0 - 1, 12)
    } else {
        (cur.0, cur.1 - 1)
    };
    [cur, prev]
        .iter()
        .map(|(y, m)| {
            tpl.replace("{YYYY}", &format!("{y:04}"))
                .replace("{MM}", &format!("{m:02}"))
        })
        .collect()
}

pub fn http_client() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!(
            "ai-security-monitor/{} (+https://github.com/markku636/ai-security-monitor)",
            crate::VERSION
        ))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| AppError::Intel(e.to_string()))
}

/// 可下載成本地檔的來源（排除即時查詢 API）。
pub fn downloadable(e: &FeedEntry) -> bool {
    !matches!(e.format, FeedFormat::LookupApi | FeedFormat::Unknown) && !e.urls.is_empty()
}

#[derive(Debug, Clone, Default)]
pub struct UpdateOpts {
    /// 只更新這些 id（空＝所有已啟用的）。
    pub only: Vec<String>,
    /// 忽略更新間隔。
    pub force: bool,
    /// hub 鏡像（已註冊且 hub 有提供時）。
    pub mirror: Option<Mirror>,
}

/// hub 的情資鏡像：網址、client 金鑰與鏡像裡有的清單。
#[derive(Debug, Clone, Default)]
pub struct Mirror {
    pub base: String,
    pub key: String,
    pub agent_id: String,
    pub ids: HashSet<String>,
}

impl Mirror {
    pub fn url_for(&self, id: &str) -> String {
        format!("{}/api/v1/feeds/{id}", self.base)
    }

    pub fn owns(&self, url: &str) -> bool {
        !self.base.is_empty() && url.starts_with(&format!("{}/api/v1/feeds/", self.base))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateOutcome {
    pub feed_id: String,
    /// `updated` / `not_modified` / `fresh` / `error`
    pub status: String,
    pub entries: u64,
    pub bytes: u64,
    pub ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// `hub`（鏡像）或 `vendor`（直接找廠商）；沒下載的是 None。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

pub async fn update(
    config_dir: &Path,
    reg: &Registry,
    opts: &UpdateOpts,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> AppResult<Vec<UpdateOutcome>> {
    for id in &opts.only {
        if reg.get(id).is_none() {
            return Err(AppError::InvalidArg(tf!("沒有這個情資來源：{id}", id = id)));
        }
    }
    let now = Utc::now();
    let targets: Vec<FeedEntry> = reg
        .feeds
        .iter()
        .filter(|f| downloadable(f))
        .filter(|f| {
            if opts.only.is_empty() {
                reg.is_enabled(f)
            } else {
                opts.only.contains(&f.id)
            }
        })
        .cloned()
        .collect();
    let client = http_client()?;
    let mut outcomes = Vec::new();
    let mut set = tokio::task::JoinSet::new();
    let mut queue = targets.into_iter();
    loop {
        while set.len() < CONCURRENCY {
            let Some(f) = queue.next() else {
                break;
            };
            let meta = FeedMeta::load(config_dir, &f.id);
            if !opts.force {
                if let Some(m) = &meta {
                    if m.has_data() && m.is_fresh(&f, now) {
                        outcomes.push(UpdateOutcome {
                            feed_id: f.id.clone(),
                            status: "fresh".into(),
                            entries: m.entries,
                            bytes: m.bytes,
                            ms: 0,
                            detail: None,
                            source: None,
                        });
                        continue;
                    }
                }
            }
            progress(&tf!("下載情資：{id}", id = f.id));
            let client = client.clone();
            let dir = config_dir.to_path_buf();
            let mirror = opts.mirror.clone().filter(|m| m.ids.contains(&f.id));
            set.spawn(async move { fetch_one(&client, &dir, &f, meta, mirror.as_ref()).await });
        }
        match set.join_next().await {
            Some(Ok(o)) => outcomes.push(o),
            Some(Err(e)) => outcomes.push(UpdateOutcome {
                feed_id: "?".into(),
                status: "error".into(),
                entries: 0,
                bytes: 0,
                ms: 0,
                detail: Some(e.to_string()),
                source: None,
            }),
            None => break,
        }
    }
    outcomes.sort_by(|a, b| a.feed_id.cmp(&b.feed_id));
    Ok(outcomes)
}

enum Download {
    NotModified {
        url: String,
    },
    Body {
        bytes: Vec<u8>,
        url: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

async fn fetch_one(
    client: &reqwest::Client,
    dir: &Path,
    f: &FeedEntry,
    prev: Option<FeedMeta>,
    mirror: Option<&Mirror>,
) -> UpdateOutcome {
    let started = Instant::now();
    let mut meta = prev.clone().unwrap_or_else(|| FeedMeta {
        feed_id: f.id.clone(),
        ..Default::default()
    });
    meta.feed_id = f.id.clone();
    let result = download(client, f, prev.as_ref(), mirror).await;
    let now = Utc::now();
    meta.checked_at = Some(now);
    let via = match &result {
        Ok(Download::Body { url, .. }) => Some(url.clone()),
        Ok(Download::NotModified { url }) => Some(url.clone()),
        Err(_) => None,
    };
    let source = via.map(|u| {
        if mirror.is_some_and(|m| m.owns(&u)) {
            "hub"
        } else {
            "vendor"
        }
        .to_string()
    });
    let stored = result.and_then(|d| store_download(dir, f, &mut meta, d, now));
    let ms = started.elapsed().as_millis() as u64;
    match stored {
        Ok(status) => {
            meta.status = "ok".into();
            meta.error = None;
            let _ = meta.save(dir);
            UpdateOutcome {
                feed_id: f.id.clone(),
                status,
                entries: meta.entries,
                bytes: meta.bytes,
                ms,
                detail: None,
                source,
            }
        }
        Err(e) => {
            meta.status = "error".into();
            meta.error = Some(e.message());
            let _ = meta.save(dir);
            UpdateOutcome {
                feed_id: f.id.clone(),
                status: "error".into(),
                entries: meta.entries,
                bytes: meta.bytes,
                ms,
                detail: Some(e.message()),
                source: None,
            }
        }
    }
}

fn header_str(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

async fn download(
    client: &reqwest::Client,
    f: &FeedEntry,
    prev: Option<&FeedMeta>,
    mirror: Option<&Mirror>,
) -> AppResult<Download> {
    let mut urls: Vec<String> = mirror.map(|m| m.url_for(&f.id)).into_iter().collect();
    urls.extend(f.urls.iter().take(1).flat_map(|u| expand_urls(u, Utc::now())));
    let mut last_err: Option<AppError> = None;
    for url in urls {
        let mut req = client.get(&url);
        if let Some(m) = mirror.filter(|m| m.owns(&url)) {
            req = req
                .bearer_auth(&m.key)
                .header("x-asa-agent-id", &m.agent_id)
                .header("x-asa-agent-version", crate::VERSION);
        }
        if let Some(p) = prev.filter(|p| p.url == url && p.has_data()) {
            if let Some(e) = &p.etag {
                req = req.header(IF_NONE_MATCH, e);
            }
            if let Some(lm) = &p.last_modified {
                req = req.header(IF_MODIFIED_SINCE, lm);
            }
        }
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(AppError::Intel(tf!("下載失敗：{url}：{e}", url = url, e = e)));
                continue;
            }
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Download::NotModified { url });
        }
        if !status.is_success() {
            last_err = Some(AppError::Intel(tf!(
                "HTTP {status}：{url}",
                status = status.as_u16(),
                url = url
            )));
            continue;
        }
        if resp.content_length().unwrap_or(0) > MAX_BYTES {
            return Err(AppError::Intel(tf!("檔案超過大小上限：{url}", url = url)));
        }
        let etag = header_str(&resp, ETAG);
        let last_modified = header_str(&resp, LAST_MODIFIED);
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| AppError::Intel(tf!("下載失敗：{url}：{e}", url = url, e = e)))?
        {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > MAX_BYTES {
                return Err(AppError::Intel(tf!("檔案超過大小上限：{url}", url = url)));
            }
        }
        return Ok(Download::Body {
            bytes: buf,
            url,
            etag,
            last_modified,
        });
    }
    Err(last_err.unwrap_or_else(|| AppError::Intel(t!("沒有可用的下載網址").into())))
}

/// gzip 就解壓（含大小上限）；伺服器已透明解壓時原樣回傳。
fn maybe_gunzip(bytes: &[u8]) -> AppResult<Vec<u8>> {
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Ok(bytes.to_vec());
    }
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| AppError::Intel(tf!("解壓縮失敗：{e}", e = e)))?;
    if out.len() as u64 > MAX_BYTES {
        return Err(AppError::Intel(t!("解壓後超過大小上限").into()));
    }
    Ok(out)
}

fn store_download(
    dir: &Path,
    f: &FeedEntry,
    meta: &mut FeedMeta,
    d: Download,
    now: DateTime<Utc>,
) -> AppResult<String> {
    let (bytes, url, etag, last_modified) = match d {
        Download::Body {
            bytes,
            url,
            etag,
            last_modified,
        } => (bytes, url, etag, last_modified),
        Download::NotModified { .. } => return Ok("not_modified".into()),
    };
    let fdir = feed_dir(dir, &f.id);
    store::ensure_dir(&fdir)?;
    let stored: Vec<u8> = if f.format == FeedFormat::MmdbGz {
        let raw = maybe_gunzip(&bytes)?;
        maxminddb::Reader::from_source(raw.as_slice())
            .map_err(|e| AppError::Intel(tf!("GeoIP 資料庫格式錯誤：{e}", e = e)))?;
        store::write_bytes_in(&fdir, MMDB_FILE, &raw)?;
        meta.entries = 0;
        meta.header_lines = Vec::new();
        raw
    } else {
        let parsed = parse::parse(f.format, &bytes)?;
        if parsed.records.is_empty() {
            return Err(AppError::Intel(t!("下載內容沒有任何條目（保留舊資料）").into()));
        }
        store::write_bytes_in(&fdir, DATA_FILE, &bytes)?;
        meta.entries = parsed.records.len() as u64;
        meta.header_lines = parsed.header_lines;
        bytes
    };
    meta.bytes = stored.len() as u64;
    meta.sha256 = crate::util::hash::sha256_hex(&stored);
    meta.url = url;
    meta.etag = etag;
    meta.last_modified = last_modified;
    meta.fetched_at = Some(now);
    Ok("updated".into())
}

/// 給 hub 心跳的情資狀態：最舊的一次檢查時間（全部都檢查過才算更新完）、有資料的清單數、多數從哪裡來。
#[derive(Debug, Clone, PartialEq)]
pub struct IntelStatus {
    pub checked_at: Option<DateTime<Utc>>,
    pub ok: usize,
    pub total: usize,
    pub source: Option<&'static str>,
}

pub fn intel_status(config_dir: &Path, reg: &Registry, hub_base: Option<&str>) -> IntelStatus {
    let mirror_prefix = hub_base.map(|b| format!("{}/api/v1/feeds/", b.trim_end_matches('/')));
    let (mut ok, mut total, mut from_hub) = (0, 0, 0);
    let mut oldest: Option<DateTime<Utc>> = None;
    for f in reg.enabled().filter(|f| downloadable(f)) {
        total += 1;
        let Some(m) = FeedMeta::load(config_dir, &f.id) else {
            continue;
        };
        if m.has_data() {
            ok += 1;
            if mirror_prefix.as_ref().is_some_and(|p| m.url.starts_with(p)) {
                from_hub += 1;
            }
        }
        if let Some(c) = m.checked_at {
            oldest = Some(oldest.map_or(c, |o| o.min(c)));
        }
    }
    IntelStatus {
        checked_at: oldest,
        ok,
        total,
        source: (ok > 0).then_some(if from_hub * 2 >= ok { "hub" } else { "vendor" }),
    }
}

/// (最新, 過期, 未下載) 的已啟用清單類來源數。
pub fn freshness(config_dir: &Path, reg: &Registry) -> (usize, usize, usize) {
    let now = Utc::now();
    let (mut fresh, mut stale, mut missing) = (0, 0, 0);
    for f in reg.enabled().filter(|f| downloadable(f)) {
        match FeedMeta::load(config_dir, &f.id) {
            Some(m) if m.has_data() => {
                // 容忍兩倍更新間隔，才算過期。
                let ttl = chrono::Duration::from_std(f.refresh() * 2).unwrap_or_else(|_| chrono::Duration::hours(2));
                if m.fetched_at.map(|t| now - t < ttl).unwrap_or(false) || m.is_fresh(f, now) {
                    fresh += 1;
                } else {
                    stale += 1;
                }
            }
            _ => missing += 1,
        }
    }
    (fresh, stale, missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn url_template_expands_to_current_and_previous_month() {
        let now = Utc.with_ymd_and_hms(2026, 1, 3, 0, 0, 0).unwrap();
        let v = expand_urls("https://x/dbip-country-lite-{YYYY}-{MM}.mmdb.gz", now);
        assert_eq!(
            v,
            vec![
                "https://x/dbip-country-lite-2026-01.mmdb.gz",
                "https://x/dbip-country-lite-2025-12.mmdb.gz"
            ]
        );
        assert_eq!(expand_urls("https://x/a.txt", now), vec!["https://x/a.txt"]);
    }

    #[test]
    fn store_rejects_empty_and_keeps_old_data() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        let f = reg.get("abusech-feodo").unwrap().clone();
        let mut meta = FeedMeta {
            feed_id: f.id.clone(),
            ..Default::default()
        };
        let ok = store_download(
            dir.path(),
            &f,
            &mut meta,
            Download::Body {
                bytes: b"# header\n1.2.3.4\n".to_vec(),
                url: "https://x".into(),
                etag: Some("\"e1\"".into()),
                last_modified: None,
            },
            Utc::now(),
        )
        .unwrap();
        assert_eq!(ok, "updated");
        assert_eq!(meta.entries, 1);
        let bad = store_download(
            dir.path(),
            &f,
            &mut meta,
            Download::Body {
                bytes: b"# nothing\n".to_vec(),
                url: "https://x".into(),
                etag: None,
                last_modified: None,
            },
            Utc::now(),
        );
        assert!(bad.is_err());
        let data = std::fs::read(feed_dir(dir.path(), &f.id).join(DATA_FILE)).unwrap();
        assert_eq!(data, b"# header\n1.2.3.4\n");
        assert_eq!(meta.etag.as_deref(), Some("\"e1\""));
    }

    #[test]
    fn freshness_counts() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        let (fresh, stale, missing) = freshness(dir.path(), &reg);
        assert_eq!((fresh, stale), (0, 0));
        assert!(missing > 10);
    }

    #[tokio::test]
    async fn downloads_from_hub_mirror_first_and_reports_source() {
        let dir = tempfile::tempdir().unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        let (base, cap) = crate::hub::test_server::serve(vec![(200, "# mirrored\n198.51.100.7\n".into())]).await;
        let mirror = Mirror {
            base: base.clone(),
            key: "client-a".into(),
            agent_id: "a1".into(),
            ids: ["abusech-feodo".to_string()].into_iter().collect(),
        };
        let opts = UpdateOpts {
            only: vec!["abusech-feodo".into()],
            force: true,
            mirror: Some(mirror),
        };
        let outs = update(dir.path(), &reg, &opts, &|_| {}).await.unwrap();
        assert_eq!(outs[0].status, "updated");
        assert_eq!(outs[0].source.as_deref(), Some("hub"));
        let head = cap.lock().unwrap()[0].head.to_ascii_lowercase();
        assert!(head.starts_with("get /api/v1/feeds/abusech-feodo "));
        assert!(head.contains("authorization: bearer client-a"));
        assert!(head.contains("x-asa-agent-id: a1"));
        let meta = FeedMeta::load(dir.path(), "abusech-feodo").unwrap();
        assert_eq!(meta.entries, 1);
        let s = intel_status(dir.path(), &reg, Some(&base));
        assert_eq!(s.ok, 1);
        assert!(s.total > 10);
        assert_eq!(s.source, Some("hub"));
        assert!(s.checked_at.is_some());
        assert_eq!(intel_status(dir.path(), &reg, None).source, Some("vendor"));
    }

    #[test]
    fn gunzip_passthrough() {
        assert_eq!(maybe_gunzip(b"plain").unwrap(), b"plain");
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, b"hello").unwrap();
        let gz = enc.finish().unwrap();
        assert_eq!(maybe_gunzip(&gz).unwrap(), b"hello");
    }
}
