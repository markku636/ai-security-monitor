//! 網路流量與效能：總覽的小圖（`metrics_now`）、「效能與流量」頁（`metrics_history`）、效能蒐集開關。
//!
//! 背景服務（`watch`）在跑時用它每分鐘寫的樣本與 24 小時歷史；沒在跑時，桌面版開著（含縮到系統匣）
//! 就自己每分鐘取樣一次，一樣記進本機 24 小時歷史（`metrics/history.jsonl`），最近 1 小時的樣本留在記憶體。

use std::time::Duration;

use asa_lib::config::{self, AgentConfig};
use asa_lib::metrics::{self, history, MetricsSample};
use chrono::Utc;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};

use crate::{err, AppState, CmdResult};

/// 記憶體裡最多留幾個樣本（總覽開著時每 10 秒一個；「最近 1 小時」只看時間）。
const MEMORY_CAP: usize = 800;
/// 總覽小圖畫幾個點。
const SPARK_POINTS: usize = 60;

fn memory_window() -> chrono::Duration {
    chrono::Duration::minutes(62)
}

/// 背景服務最近寫的樣本，以及它是不是還在持續寫（夠新、而且有沒有效能資料和現在的設定一致）。
fn background(cfg: &AgentConfig, dir: &std::path::Path) -> (bool, Vec<MetricsSample>) {
    let opts = metrics::Options::from_config(&cfg.metrics);
    let every = metrics::interval_of(&cfg.metrics);
    let recent = metrics::queue::recent(dir);
    let fresh = recent.last().is_some_and(|s| {
        (Utc::now() - s.ts).to_std().unwrap_or_default() <= every * 2 + Duration::from_secs(30)
            && s.perf.is_some() == opts.performance
    });
    (fresh, recent)
}

/// 桌面版自己取一個樣本：記進本機 24 小時歷史與記憶體裡的最近 1 小時。取樣器忙（上一輪還沒好）就回 `None`。
async fn desktop_sample(state: &AppState, opts: metrics::Options) -> Option<MetricsSample> {
    let s = metrics::tick(&state.metrics, opts).await?;
    let dir = state.config_dir.clone();
    let rec = s.clone();
    let _ = tokio::task::spawn_blocking(move || history::record(&dir, &rec)).await;
    let mut h = state.metrics_recent.lock().await;
    h.push(s.clone());
    let cutoff = Utc::now() - memory_window();
    h.retain(|x| x.ts >= cutoff);
    let n = h.len();
    if n > MEMORY_CAP {
        h.drain(..n - MEMORY_CAP);
    }
    Some(s)
}

/// 背景服務沒在跑時，桌面版開著就每個取樣間隔（預設 1 分鐘）取一次樣，讓「效能與流量」頁一直有資料。
pub fn spawn_sampler(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // 先讓畫面第一次的 metrics_now 取樣，避免同時搶取樣器
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            let state = app.state::<AppState>();
            let every = match config::load_or_init(&state.config_dir) {
                Ok(cfg) => {
                    let (fresh, _) = background(&cfg, &state.config_dir);
                    let last = state.metrics_recent.lock().await.last().map(|s| s.ts);
                    // 總覽開著時每 10 秒也會取樣：剛取過就不必再取
                    let due = last.is_none_or(|t| Utc::now() - t >= chrono::Duration::seconds(50));
                    if !fresh && due {
                        desktop_sample(&state, metrics::Options::from_config(&cfg.metrics)).await;
                    }
                    metrics::interval_of(&cfg.metrics)
                }
                Err(_) => Duration::from_secs(60),
            };
            tokio::time::sleep(every).await;
        }
    });
}

/// 小圖用的精簡樣本：時間、上傳／下載速率；開啟效能蒐集時加 CPU、記憶體、最滿的磁碟（%）。
fn point(s: &MetricsSample) -> Value {
    let (rx, tx) = s.rates();
    let p = s.perf.as_ref();
    let mem = p.and_then(|p| (p.mem_total > 0).then(|| p.mem_used as f64 * 100.0 / p.mem_total as f64));
    let disk = p.and_then(|p| {
        p.disks
            .iter()
            .filter(|d| d.total > 0)
            .map(|d| d.used as f64 * 100.0 / d.total as f64)
            .reduce(f64::max)
    });
    json!({ "ts": s.ts, "rx": rx, "tx": tx, "cpu": p.map(|p| p.cpu_pct), "mem": mem, "disk": disk })
}

/// 總覽的流量／效能卡片：背景服務在跑而且最近有樣本就用它的（最近 1 小時）；否則桌面版自己量
/// （開著視窗時每次呼叫取一個樣本）。效能只在使用者開啟時才量。
#[tauri::command]
pub async fn metrics_now(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    let (fresh, recent) = background(&cfg, dir);
    let (current, points, source) = if fresh {
        (recent.last().cloned(), recent, "background")
    } else {
        let s = desktop_sample(&state, metrics::Options::from_config(&cfg.metrics)).await;
        let h = state.metrics_recent.lock().await;
        let tail = h[h.len().saturating_sub(SPARK_POINTS)..].to_vec();
        (s.or_else(|| h.last().cloned()), tail, "desktop")
    };
    Ok(json!({
        "performance_enabled": cfg.metrics.performance,
        "interval": cfg.metrics.interval,
        "source": source,
        "current": current,
        "points": points.iter().map(point).collect::<Vec<_>>(),
    }))
}

/// 「效能與流量」頁：`range`＝`1h`（每分鐘一點，60 點）或 `24h`（每 5 分鐘一點，288 點）。
/// 沒有資料的時段是空的點（圖上斷開）。`current` 是最新的一個完整樣本（最吃資源的程式、各磁碟區、電池）。
#[tauri::command]
pub async fn metrics_history(state: State<'_, AppState>, range: String) -> CmdResult<Value> {
    let dir = state.config_dir.clone();
    let cfg = config::load_or_init(&dir).map_err(err)?;
    let (fresh, recent) = background(&cfg, &dir);
    let fine = if fresh {
        recent
    } else {
        state.metrics_recent.lock().await.clone()
    };
    let now = Utc::now();
    let day = range == "24h";
    let (step, n) = if day { (history::STEP_SECS, 288) } else { (60, 60) };
    let buckets = if day {
        let since = now - chrono::Duration::hours(history::KEEP_HOURS + 1);
        tokio::task::spawn_blocking(move || history::load(&dir, since))
            .await
            .map_err(|e| e.to_string())?
    } else {
        history::aggregate(&fine, 60)
    };
    // 最後一格通常還沒有樣本（樣本歸在它涵蓋時段的中間）：從最新有資料的那格往前算，線才會畫到右邊
    let end = buckets
        .last()
        .map(|b| b.start)
        .filter(|s| now - *s <= chrono::Duration::seconds(step * 2))
        .unwrap_or(now);
    let has_processes = fine.iter().any(|s| s.net.processes.is_some()) || buckets.iter().any(|b| b.processes.is_some());
    Ok(json!({
        "range": if day { "24h" } else { "1h" },
        "step_s": step,
        "source": if fresh { "background" } else { "desktop" },
        "interval": cfg.metrics.interval,
        "performance_enabled": cfg.metrics.performance,
        "process_network": cfg.metrics.process_network,
        "has_processes": has_processes,
        "platform": std::env::consts::OS,
        "elevated": asa_lib::elevate::is_elevated(),
        "points": history::points(&buckets, end, step, n),
        "current": fine.last(),
    }))
}

/// 開／關效能蒐集（metrics.performance）。背景服務每輪重讀設定，不用重新啟動。
#[tauri::command]
pub async fn set_performance(state: State<'_, AppState>, enabled: bool) -> CmdResult<bool> {
    let dir = &state.config_dir;
    let mut cfg = config::load_or_init(dir).map_err(err)?;
    config::set_value(&mut cfg, "metrics.performance", if enabled { "true" } else { "false" }).map_err(err)?;
    config::save(dir, &cfg).map_err(err)?;
    // 換設定後重新累積（避免小圖混著有／沒有效能的樣本）
    state.metrics_recent.lock().await.clear();
    Ok(cfg.metrics.performance)
}
