//! 背景 DNS 蒐集（由 `watch` 帶起）：來源事件 → 有界 channel（滿了就丟並計數，絕不擋住 DNS）→ 聚合 →
//! 每 15 秒把結束的分鐘寫進 `dns/YYYY-MM-DD.jsonl`、更新 `dns/status.json`；每小時清掉過期的日期檔。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use super::agg::{Aggregator, SharedIpMap};
use super::collect;
use super::store::{self, DnsStatus};

/// 事件 channel 容量（尖峰時的緩衝；滿了就丟）。
pub const CHANNEL: usize = 8192;
const FLUSH_EVERY: Duration = Duration::from_secs(15);
const CACHE_EVERY: Duration = Duration::from_secs(30);
const CLEANUP_EVERY: Duration = Duration::from_secs(3600);

/// 背景服務的 ETW session 名稱（非 Windows 不使用）。
pub const SERVICE_SESSION: &str = "ai-security-monitor-dns";

static IP_MAP: OnceLock<SharedIpMap> = OnceLock::new();

/// 背景蒐集在跑時，給連線快照查「這個 IP 是哪個網域」。
pub fn ip_map() -> Option<&'static SharedIpMap> {
    IP_MAP.get()
}

pub struct DnsRuntime {
    stop: Arc<Notify>,
    task: JoinHandle<()>,
}

impl DnsRuntime {
    /// 啟動。`session` 是 ETW session 名稱。
    pub fn spawn(config_dir: PathBuf, session: &'static str) -> DnsRuntime {
        let stop = Arc::new(Notify::new());
        let task = tokio::spawn(run(config_dir, session, stop.clone()));
        DnsRuntime { stop, task }
    }

    /// 停止並把還在累積的分鐘寫進檔案。
    pub async fn shutdown(self) {
        self.stop.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(10), self.task).await;
    }
}

async fn run(config_dir: PathBuf, session: &'static str, stop: Arc<Notify>) {
    let (tx, mut rx) = mpsc::channel(CHANNEL);
    let dropped = Arc::new(AtomicU64::new(0));
    let mut agg = Aggregator::new();
    agg.ip_map = IP_MAP.get_or_init(SharedIpMap::default).clone();
    let c = {
        let tx = tx.clone();
        let dropped = dropped.clone();
        tokio::task::spawn_blocking(move || collect::start(session, tx, dropped))
            .await
            .unwrap_or_else(|e| collect::Collector::none(e.to_string()))
    };
    let mut status = DnsStatus {
        source: c.source.map(|s| s.as_str().to_string()),
        running: c.source.is_some(),
        started_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        has_process: c.has_process,
        notes: c.notes.clone(),
        ..Default::default()
    };
    let _ = store::write_status(&config_dir, &status);
    let _guard = c.guard;
    #[cfg(windows)]
    let mut tracker = collect::windows::CacheTracker::default();
    let mut flush = tokio::time::interval(FLUSH_EVERY);
    let mut cache = tokio::time::interval(CACHE_EVERY);
    let mut cleanup = tokio::time::interval(CLEANUP_EVERY);
    loop {
        tokio::select! {
            Some(ev) = rx.recv() => {
                status.last_event_at = Some(ev.ts);
                agg.push(ev);
            }
            _ = flush.tick() => {
                let recs = agg.take_finished(Utc::now());
                let dir = config_dir.clone();
                let _ = tokio::task::spawn_blocking(move || store::append(&dir, &recs)).await;
                status.events = agg.stats.events;
                status.deduped = agg.stats.deduped;
                status.dropped = dropped.load(Ordering::Relaxed);
                status.updated_at = Some(Utc::now());
                let _ = store::write_status(&config_dir, &status);
            }
            _ = cache.tick(), if c.poll_cache => {
                #[cfg(windows)]
                if let Ok(text) = collect::windows::cache_snapshot().await {
                    for ev in tracker.diff(&text, Utc::now()) {
                        status.last_event_at = Some(ev.ts);
                        agg.push(ev);
                    }
                }
            }
            _ = cleanup.tick() => {
                store::cleanup(&config_dir, Utc::now());
            }
            _ = stop.notified() => break,
        }
    }
    drop(_guard);
    while let Ok(ev) = rx.try_recv() {
        agg.push(ev);
    }
    let _ = store::append(&config_dir, &agg.take_all());
    status.running = false;
    status.events = agg.stats.events;
    status.deduped = agg.stats.deduped;
    status.dropped = dropped.load(Ordering::Relaxed);
    status.updated_at = Some(Utc::now());
    let _ = store::write_status(&config_dir, &status);
}
