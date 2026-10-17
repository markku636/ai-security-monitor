//! 網路流量統計（一律開啟，很便宜）與效能指標（使用者明確開啟才蒐集）。
//!
//! - 網路：每個介面的收發位元組（累計計數器相減），實體介面加總成這台電腦的上傳／下載量；
//!   Windows（系統管理員）與 macOS 另外估各程式的收發量（見 [`procnet`]）。
//! - 效能（`metrics.performance = true`）：CPU、記憶體、置換空間、各磁碟用量與讀寫、開機時間、負載、
//!   最吃 CPU／記憶體的前 5 個程式、電池。只送到這台電腦加入的 Security Hub；Hub 無法從遠端開啟。
//!
//! `watch` 每 `metrics.interval`（預設 1 分鐘，最短 30 秒）取一個樣本：存進最近 1 小時（桌面版小圖用），
//! 有加入 Hub 時放進待送佇列並分批送到 `POST /api/v1/ingest/metrics`（離線時累積、恢復後補送）。
//! 取樣在背景執行緒做、有逾時，永遠不會卡住 `watch` 的其他工作。

pub mod battery;
pub mod net;
pub mod perf;
pub mod procnet;
pub mod queue;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{DiskRefreshKind, Disks, Networks, System};

pub use battery::Battery;
pub use net::IfaceSample;
pub use perf::{DiskVol, PerfSample, ProcPerf};
pub use procnet::ProcNet;

/// 最短取樣間隔。
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
/// 一次上傳最多幾個樣本。
pub const BATCH: usize = 120;
/// 一輪最多補送幾批（每批之間不等待；剩下的下一輪再送）。
pub const BATCHES_PER_TICK: usize = 3;
/// 整個取樣的逾時（超過就放棄這一輪）。
pub const SAMPLE_TIMEOUT: Duration = Duration::from_secs(25);

/// 這段時間的網路用量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetSample {
    /// 實體介面加總（不含迴路與虛擬介面）。
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub interfaces: Vec<IfaceSample>,
    /// 各程式的收發量；`None`＝這台讀不到（Linux、沒有系統管理員權限的 Windows）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcNet>>,
    /// 各程式用量的來源：`estats`（Windows）或 `nettop`（macOS）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_source: Option<String>,
}

/// 一個樣本：`ts` 往前 `interval_s` 秒內的量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsSample {
    pub ts: DateTime<Utc>,
    pub interval_s: u32,
    pub net: NetSample,
    /// 只有開啟效能蒐集時才有。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perf: Option<PerfSample>,
}

impl MetricsSample {
    /// 下載／上傳速率（bytes/s）。
    pub fn rates(&self) -> (f64, f64) {
        let s = self.interval_s.max(1) as f64;
        (self.net.rx_bytes as f64 / s, self.net.tx_bytes as f64 / s)
    }
}

/// 上傳到 Hub 的一批樣本（`contract/metrics.v1.json`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsBatch {
    pub agent_id: String,
    /// 這台電腦是否開啟了效能蒐集（Hub 據此顯示「未開啟」）。
    pub performance: bool,
    pub samples: Vec<MetricsSample>,
}

/// 這一輪要蒐集什麼。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub performance: bool,
    pub process_network: bool,
}

impl Options {
    pub fn from_config(c: &crate::config::MetricsConfig) -> Self {
        Self {
            performance: c.performance,
            process_network: c.process_network,
        }
    }
}

/// 設定裡的間隔（最短 30 秒；寫錯就用 1 分鐘）。
pub fn interval_of(c: &crate::config::MetricsConfig) -> Duration {
    crate::util::time::parse_duration(&c.interval)
        .unwrap_or(Duration::from_secs(60))
        .max(MIN_INTERVAL)
}

/// 取樣器：保留上一次的讀數，算出這段時間的差值。跨 `watch` 的每一輪重複使用（CPU 百分比要兩次刷新）。
pub struct Collector {
    sys: System,
    nets: Networks,
    disks: Disks,
    prev_at: DateTime<Utc>,
    prev_net: BTreeMap<String, net::IfaceCounters>,
    prev_disk_io: Option<(u64, u64)>,
    prev_estats: Option<HashMap<procnet::ConnKey, (u64, u64)>>,
    prev_nettop: Option<HashMap<(String, u32), (u64, u64)>>,
    /// 上一次有沒有刷新過 CPU／行程（效能剛開啟的第一輪，CPU 百分比還不準）。
    perf_primed: bool,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    /// 建立並記下第一組基準讀數（網路計數器、磁碟讀寫）。
    pub fn new() -> Self {
        let nets = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list_specifics(DiskRefreshKind::nothing().with_storage().with_io_usage());
        let prev_net = net::read_counters(&nets);
        let prev_disk_io = perf::disk_io_totals(&disks);
        Self {
            sys: System::new(),
            nets,
            disks,
            prev_at: Utc::now(),
            prev_net,
            prev_disk_io,
            prev_estats: None,
            prev_nettop: None,
            perf_primed: false,
        }
    }

    /// 先刷新一次 CPU／行程，讓下一次取樣的百分比有基準（CLI、桌面版用；`watch` 每輪都會刷新）。
    pub fn prime(&mut self, opts: Options) {
        if opts.performance {
            perf::refresh(&mut self.sys);
            self.perf_primed = true;
        }
        if opts.process_network && cfg!(windows) {
            self.prev_estats = procnet::estats_snapshot(crate::elevate::is_elevated());
        }
    }

    /// 取一個樣本（同步、會讀系統資料；請在背景執行緒呼叫）。`nettop`／`battery` 是先在 async 端取好的。
    pub fn sample(
        &mut self,
        opts: Options,
        nettop: Option<HashMap<(String, u32), (u64, u64)>>,
        battery: Option<Battery>,
    ) -> MetricsSample {
        let now = Utc::now();
        let elapsed = ((now - self.prev_at).num_milliseconds().max(1) as f64) / 1000.0;
        // 網路：refresh(true) 會移除消失的介面、加入新介面
        self.nets.refresh(true);
        let cur = net::read_counters(&self.nets);
        let (interfaces, rx, tx) = net::deltas(&self.prev_net, &cur, elapsed, &net::is_virtual);
        self.prev_net = cur;

        let (processes, process_source) = if opts.process_network {
            self.process_bytes(nettop, elapsed)
        } else {
            (None, None)
        };

        let perf = if opts.performance {
            Some(self.perf(elapsed, battery))
        } else {
            self.perf_primed = false;
            None
        };
        self.prev_at = now;
        MetricsSample {
            ts: now,
            interval_s: elapsed.round().clamp(1.0, u32::MAX as f64) as u32,
            net: NetSample {
                rx_bytes: rx,
                tx_bytes: tx,
                interfaces,
                processes,
                process_source,
            },
            perf,
        }
    }

    fn process_bytes(
        &mut self,
        nettop: Option<HashMap<(String, u32), (u64, u64)>>,
        elapsed: f64,
    ) -> (Option<Vec<ProcNet>>, Option<String>) {
        if let Some(cur) = nettop {
            let out = self.prev_nettop.as_ref().map(|prev| {
                procnet::top_by_name(
                    procnet::cumulative_deltas(prev, &cur)
                        .into_iter()
                        .map(|((name, _pid), rx, tx)| (name, rx, tx)),
                )
            });
            self.prev_nettop = Some(cur);
            return (out, Some("nettop".into()));
        }
        if !cfg!(windows) {
            return (None, None);
        }
        let Some(cur) = procnet::estats_snapshot(crate::elevate::is_elevated()) else {
            self.prev_estats = None;
            return (None, None);
        };
        // pid → 程式名稱（只列名稱，便宜）
        self.sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing().without_tasks(),
        );
        let name_of = |pid: u32| {
            self.sys
                .process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    if pid == 4 {
                        "System".into()
                    } else {
                        format!("pid {pid}")
                    }
                })
        };
        let empty = HashMap::new();
        let prev = self.prev_estats.as_ref().unwrap_or(&empty);
        // 一條連線在這段時間超過 100 Gbps 不可能是真的：丟掉
        let cap = (elapsed.max(1.0) * 100e9 / 8.0) as u64;
        let list = procnet::top_by_name(
            procnet::cumulative_deltas(prev, &cur)
                .into_iter()
                .filter(|(_, rx, tx)| *rx <= cap && *tx <= cap)
                .map(|(k, rx, tx)| (name_of(k.pid), rx, tx)),
        );
        self.prev_estats = Some(cur);
        (Some(list), Some("estats".into()))
    }

    fn perf(&mut self, _elapsed: f64, battery: Option<Battery>) -> PerfSample {
        if !self.perf_primed {
            // 剛開啟：先刷新一次再等一下，這一輪的 CPU 百分比才有意義
            perf::refresh(&mut self.sys);
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(300)));
        }
        perf::refresh(&mut self.sys);
        self.perf_primed = true;
        self.disks
            .refresh_specifics(true, DiskRefreshKind::nothing().with_storage().with_io_usage());
        let io = perf::disk_io_totals(&self.disks);
        let (disk_read_bytes, disk_write_bytes) = match (self.prev_disk_io, io) {
            (Some((pr, pw)), Some((r, w))) => (
                Some(if r >= pr { r - pr } else { r }),
                Some(if w >= pw { w - pw } else { w }),
            ),
            _ => (None, None),
        };
        self.prev_disk_io = io;
        let cores = self.sys.cpus().len();
        let (top_cpu, top_mem) = perf::top_processes(&self.sys, cores);
        let total = self.sys.total_memory();
        PerfSample {
            cpu_pct: perf::round1(f64::from(self.sys.global_cpu_usage()).clamp(0.0, 100.0)),
            cpu_cores: cores as u32,
            mem_used: perf::mem_used(total, self.sys.available_memory(), self.sys.used_memory()),
            mem_total: total,
            swap_used: self.sys.used_swap(),
            swap_total: self.sys.total_swap(),
            disks: perf::volumes(&self.disks),
            disk_read_bytes,
            disk_write_bytes,
            load: perf::load_average(),
            uptime_s: System::uptime(),
            boot_time: perf::boot_time(),
            top_cpu,
            top_mem,
            battery,
        }
    }
}

/// 共用的取樣器（`watch` 的每一輪、桌面版）。
pub type Shared = Arc<Mutex<Collector>>;

pub fn shared() -> Shared {
    Arc::new(Mutex::new(Collector::new()))
}

/// 非同步取一個樣本：先在 async 端跑外部指令（nettop、pmset），再到背景執行緒讀系統資料；整體有逾時。
/// 上一輪還卡著（取樣器被鎖住）就跳過這一輪，回 `None`。
pub async fn tick(collector: &Shared, opts: Options) -> Option<MetricsSample> {
    let nettop = if opts.process_network && cfg!(target_os = "macos") {
        procnet::nettop_snapshot().await
    } else {
        None
    };
    let battery = if opts.performance { battery::read().await } else { None };
    let c = collector.clone();
    let task = tokio::task::spawn_blocking(move || {
        let mut g = match c.try_lock() {
            Ok(g) => g,
            // 上一輪取樣中途出錯：換一個新的取樣器（這一輪當作重新建立基準）
            Err(std::sync::TryLockError::Poisoned(p)) => {
                let mut g = p.into_inner();
                *g = Collector::new();
                c.clear_poison();
                g
            }
            Err(std::sync::TryLockError::WouldBlock) => return None,
        };
        Some(g.sample(opts, nettop, battery))
    });
    match tokio::time::timeout(SAMPLE_TIMEOUT, task).await {
        Ok(Ok(s)) => s,
        _ => None,
    }
}

/// 只量一次（`ai-security-monitor metrics`、MCP、桌面版沒有背景服務時）：建立取樣器、等 `window`、取樣。
/// 不碰 `watch` 的佇列與最近樣本。
pub async fn measure(window: Duration, opts: Options) -> Option<MetricsSample> {
    let nettop = if opts.process_network && cfg!(target_os = "macos") {
        procnet::nettop_snapshot().await
    } else {
        None
    };
    let c = tokio::task::spawn_blocking(move || {
        let mut c = Collector::new();
        c.prime(opts);
        c.prev_nettop = nettop;
        c
    })
    .await
    .ok()?;
    let shared: Shared = Arc::new(Mutex::new(c));
    tokio::time::sleep(window.max(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL)).await;
    tick(&shared, opts).await
}

/// 每個介面目前的累計計數器（CLI `--json` 給人檢查「計數器真的讀得到」）。
pub fn interface_totals() -> Vec<serde_json::Value> {
    let nets = Networks::new_with_refreshed_list();
    net::read_counters(&nets)
        .into_iter()
        .map(|(name, c)| {
            serde_json::json!({
                "name": name,
                "virtual": net::is_virtual(&name),
                "rx_total": c.rx,
                "tx_total": c.tx,
            })
        })
        .collect()
}

/// 上傳結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flush {
    /// 送出了幾個樣本、佇列還剩幾個。
    Sent { sent: usize, left: usize },
    /// Hub 太舊，沒有 `/api/v1/ingest/metrics`：先留著，稍後再試。
    Unsupported,
    /// 暫時失敗（連不上、429…），訊息給 log。
    Failed(String),
}

/// 把待送佇列分批送到 Hub（最多 [`BATCHES_PER_TICK`] 批）。被拒收（400／413／422）的那批直接丟掉。
pub async fn flush(config_dir: &Path, client: &crate::hub::HubClient, agent_id: &str, performance: bool) -> Flush {
    let mut sent = 0usize;
    for _ in 0..BATCHES_PER_TICK {
        let (samples, total) = queue::peek(config_dir, BATCH);
        if total == 0 {
            return Flush::Sent { sent, left: 0 };
        }
        let n = samples.len();
        let lines = BATCH.min(total);
        if n == 0 {
            // 全是壞掉的行
            let _ = queue::drop_first(config_dir, lines);
            continue;
        }
        let batch = MetricsBatch {
            agent_id: agent_id.to_string(),
            performance,
            samples,
        };
        match client.upload_metrics(&batch).await {
            Ok(Some(_)) => {
                let _ = queue::drop_first(config_dir, lines);
                sent += n;
            }
            Ok(None) => return Flush::Unsupported,
            Err(crate::error::AppError::HubRejected(m)) => {
                let _ = queue::drop_first(config_dir, lines);
                return Flush::Failed(m);
            }
            Err(e) => return Flush::Failed(e.message()),
        }
    }
    Flush::Sent {
        sent,
        left: queue::len(config_dir),
    }
}

/// 測試用的固定樣本（`i` 讓每個樣本不同）。
#[doc(hidden)]
pub fn sample_for_tests(i: u64) -> MetricsSample {
    use chrono::TimeZone;
    MetricsSample {
        ts: Utc.with_ymd_and_hms(2026, 10, 17, 9, 0, 0).unwrap() + chrono::Duration::minutes(i as i64),
        interval_s: 60,
        net: NetSample {
            rx_bytes: i * 1000,
            tx_bytes: i * 100,
            interfaces: vec![IfaceSample {
                name: "eth0".into(),
                is_virtual: false,
                rx_bytes: i * 1000,
                tx_bytes: i * 100,
            }],
            processes: None,
            process_source: None,
        },
        perf: None,
    }
}

/// 契約範例（`contract/metrics.v1.json`）：兩個樣本，第二個有效能資料。
#[doc(hidden)]
pub fn sample_batch() -> MetricsBatch {
    use chrono::TimeZone;
    let at = |m: u32| Utc.with_ymd_and_hms(2026, 10, 17, 9, m, 0).unwrap();
    let mut a = sample_for_tests(0);
    a.ts = at(30);
    a.net = NetSample {
        rx_bytes: 18_874_368,
        tx_bytes: 2_097_152,
        interfaces: vec![
            IfaceSample {
                name: "Ethernet".into(),
                is_virtual: false,
                rx_bytes: 18_874_368,
                tx_bytes: 2_097_152,
            },
            IfaceSample {
                name: "vEthernet (WSL)".into(),
                is_virtual: true,
                rx_bytes: 4_096,
                tx_bytes: 1_024,
            },
        ],
        processes: Some(vec![
            ProcNet {
                name: "chrome.exe".into(),
                rx_bytes: 15_728_640,
                tx_bytes: 1_048_576,
            },
            ProcNet {
                name: "OneDrive.exe".into(),
                rx_bytes: 1_048_576,
                tx_bytes: 786_432,
            },
        ]),
        process_source: Some("estats".into()),
    };
    let mut b = a.clone();
    b.ts = at(31);
    b.net.processes = None;
    b.net.process_source = None;
    b.perf = Some(PerfSample {
        cpu_pct: 23.5,
        cpu_cores: 8,
        mem_used: 9_663_676_416,
        mem_total: 17_179_869_184,
        swap_used: 536_870_912,
        swap_total: 4_294_967_296,
        disks: vec![DiskVol {
            mount: "C:\\".into(),
            fs: "NTFS".into(),
            used: 412_316_860_416,
            total: 511_101_108_224,
            removable: false,
        }],
        disk_read_bytes: Some(52_428_800),
        disk_write_bytes: Some(10_485_760),
        load: None,
        uptime_s: 259_200,
        boot_time: Utc.with_ymd_and_hms(2026, 10, 14, 9, 31, 0).unwrap(),
        top_cpu: vec![ProcPerf {
            name: "chrome.exe".into(),
            pid: None,
            count: 23,
            cpu_pct: 11.2,
            rss: 2_147_483_648,
        }],
        top_mem: vec![ProcPerf {
            name: "Code.exe".into(),
            pid: Some(4120),
            count: 1,
            cpu_pct: 2.1,
            rss: 1_073_741_824,
        }],
        battery: Some(Battery {
            percent: 81,
            charging: false,
            plugged: Some(false),
        }),
    });
    MetricsBatch {
        agent_id: crate::model::contract::sample_agent().id,
        performance: true,
        samples: vec![a, b],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_shape_is_small_and_optional_fields_are_omitted() {
        let b = sample_batch();
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["performance"], true);
        assert!(v["samples"][0].get("perf").is_none(), "no perf → field omitted");
        assert_eq!(v["samples"][0]["net"]["interfaces"][1]["virtual"], true);
        assert!(v["samples"][1]["net"].get("processes").is_none());
        assert!(
            v["samples"][1]["perf"].get("load").is_none(),
            "Windows: no load average"
        );
        // 一個完整樣本（含效能）壓在 2 KB 以內
        let one = serde_json::to_vec(&b.samples[1]).unwrap();
        assert!(one.len() < 2048, "{} bytes", one.len());
        let back: MetricsBatch = serde_json::from_value(v).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn interval_has_a_floor() {
        let mut c = crate::config::MetricsConfig::default();
        assert_eq!(interval_of(&c), Duration::from_secs(60));
        c.interval = "5s".into();
        assert_eq!(interval_of(&c), MIN_INTERVAL);
        c.interval = "garbage".into();
        assert_eq!(interval_of(&c), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn performance_is_only_collected_when_enabled() {
        let off = measure(
            Duration::from_millis(250),
            Options {
                performance: false,
                process_network: false,
            },
        )
        .await
        .expect("sample");
        assert!(off.perf.is_none());
        assert!(off.interval_s >= 1);
        let on = measure(
            Duration::from_millis(250),
            Options {
                performance: true,
                process_network: true,
            },
        )
        .await
        .expect("sample");
        let p = on.perf.expect("perf when enabled");
        assert!(p.cpu_cores >= 1 && p.mem_total > 0 && p.mem_used <= p.mem_total);
        assert!((0.0..=100.0).contains(&p.cpu_pct));
        assert!(p.uptime_s > 0);
        if cfg!(windows) {
            assert!(p.load.is_none());
        } else {
            assert!(p.load.is_some());
        }
        if cfg!(target_os = "linux") {
            assert!(on.net.processes.is_none(), "linux: per-process bytes need eBPF");
        }
    }

    #[test]
    fn counters_are_readable() {
        // 每個 CI 平台都至少有一個非迴路介面
        let all = interface_totals();
        assert!(!all.is_empty(), "no network interface counters");
        assert!(all
            .iter()
            .all(|i| i["name"].as_str().is_some_and(|n| !net::is_loopback(n))));
    }
}
