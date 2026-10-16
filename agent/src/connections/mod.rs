//! connections 引擎：列出所有 socket、接上行程、判方向（對外／對內／監聯／本機）、
//! 標異常旗標、算判定（安全／未知／可疑／危險）。情資命中由 intel 引擎在其後補上並重算判定。

pub mod beacon;
pub mod classify;
pub mod hashcache;
pub mod history;
pub mod snapshot;

use async_trait::async_trait;

use crate::error::AppResult;
use crate::model::finding::ScannerId;
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};

pub use classify::{Classifier, KnownGood, RiskyTable};
pub use snapshot::{take, SnapshotResult};

pub struct ConnectionsScanner;

#[async_trait]
impl Scanner for ConnectionsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Connections
    }

    fn elevation(&self) -> Elevation {
        // 沒提權也能跑，但他人行程的 socket 可能對不到 PID。
        Elevation::Preferred
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let dir = ctx.config_dir.clone();
        let allowlist = ctx.allowlist.clone();
        let baseline = ctx.baseline.clone();
        // netstat2 / sysinfo 都是同步呼叫，丟到 blocking thread。
        let (snap, findings) = tokio::task::spawn_blocking(move || -> AppResult<_> {
            let mut snap = snapshot::take(&dir)?;
            let classifier = Classifier::load();
            let now = crate::util::time::now().timestamp() as u64;
            history::append(&dir, now, &history::pairs_of(&snap.connections))?;
            let hist = history::load(&dir, now.saturating_sub(history::RETENTION_SECS))?;
            let beacons = beacon::detect(&hist, now);
            let findings = classifier.annotate(&mut snap, &allowlist, baseline.as_ref(), &beacons);
            Ok((snap, findings))
        })
        .await
        .map_err(|e| crate::error::AppError::Scan(e.to_string()))??;

        let mut warnings = snap.warnings.clone();
        if snap.partial {
            warnings.push(t!("部分 socket 無法對應到行程（需要系統管理員權限）").into());
        }
        let mut shared = ctx.shared.lock().await;
        shared.connections = snap.connections;
        shared.listeners = snap.listeners;
        Ok(ScanOutput {
            findings,
            warnings,
            summary: None,
        })
    }
}
