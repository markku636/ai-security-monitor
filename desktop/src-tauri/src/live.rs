//! 即時流量（桌面版「即時流量」頁）：用自己的取樣器每秒取一次網卡計數器相減，
//! 跟背景服務、總覽卡片每分鐘的取樣分開（互不干擾）；各程式用量在 Windows 要系統管理員、macOS 用 nettop、Linux 沒有。

use std::time::Instant;

use asa_lib::metrics::{self, Options};
use serde_json::{json, Value};
use tauri::State;
use tokio::sync::Mutex;

pub struct Live {
    collector: metrics::Shared,
    last: Mutex<Option<Instant>>,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            collector: metrics::shared(),
            last: Mutex::new(None),
        }
    }
}

/// 隔太久（離開頁面再回來）就重建基準，不把幾分鐘的量平均成一個點。
const MAX_GAP_S: f64 = 5.0;

#[tauri::command]
pub async fn traffic_live(live: State<'_, Live>) -> Result<Value, String> {
    let opts = Options {
        performance: false,
        process_network: true,
    };
    let sample = metrics::tick(&live.collector, opts).await;
    let now = Instant::now();
    let mut last = live.last.lock().await;
    let elapsed = last.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
    *last = Some(now);
    let Some(s) = sample else {
        return Ok(json!({ "ready": false }));
    };
    if !(0.2..=MAX_GAP_S).contains(&elapsed) {
        return Ok(json!({ "ready": false }));
    }
    let rate = |b: u64| (b as f64 / elapsed).round();
    let interfaces: Vec<Value> = s
        .net
        .interfaces
        .iter()
        .map(|i| json!({ "name": i.name, "virtual": i.is_virtual, "rx_rate": rate(i.rx_bytes), "tx_rate": rate(i.tx_bytes) }))
        .collect();
    let processes = s.net.processes.as_ref().map(|ps| {
        ps.iter()
            .map(|p| json!({ "name": p.name, "rx_rate": rate(p.rx_bytes), "tx_rate": rate(p.tx_bytes) }))
            .collect::<Vec<_>>()
    });
    Ok(json!({
        "ready": true,
        "elapsed_s": elapsed,
        "rx_rate": rate(s.net.rx_bytes),
        "tx_rate": rate(s.net.tx_bytes),
        "rx_bytes": s.net.rx_bytes,
        "tx_bytes": s.net.tx_bytes,
        "interfaces": interfaces,
        "processes": processes,
        "process_source": s.net.process_source,
        "elevated": asa_lib::elevate::is_elevated(),
        "os": std::env::consts::OS,
    }))
}
