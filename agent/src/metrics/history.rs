//! 本機的流量／效能歷史（桌面版「效能與流量」頁用）：每 5 分鐘一格的彙總，保留 24 小時，
//! 不管有沒有加入 Hub 都記（背景 `watch` 每輪寫；背景沒在跑時桌面版開著也會寫）。
//!
//! - `metrics/history.jsonl`：已經結束的格子，一行一格。最多約 24 小時多一點（288＋[`COMPACT_SLACK`] 行，約 300 KB）。
//! - `metrics/history-open.json`：還在累積的這一格（每個樣本改寫一次，只有 1–2 KB）。
//!
//! 每分鐘的負擔＝改寫一個小檔；每 5 分鐘在 `history.jsonl` 後面加一行。讀的時候壞掉的行直接略過；
//! 有壞行、或過期的行超過 [`COMPACT_SLACK`] 行時才整檔重寫——損壞的檔案就這樣自動重建，不用使用者處理。
//! 同一格出現兩次（時鐘倒退、兩個程式同時寫）讀的時候合併。

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::queue::DIR;
use super::{Battery, DiskVol, MetricsSample, ProcNet};
use crate::error::AppResult;
use crate::store;

pub const HISTORY_FILE: &str = "history.jsonl";
pub const OPEN_FILE: &str = "history-open.json";
/// 一格幾秒（5 分鐘）。
pub const STEP_SECS: i64 = 300;
/// 保留多久。
pub const KEEP_HOURS: i64 = 24;
/// 每一格最多記幾個程式（其餘併成「其他」）。
pub const MAX_PROCS: usize = 12;
/// 過期的行累積到這麼多（1 小時份）才整檔重寫。
pub const COMPACT_SLACK: usize = 12;

/// 各程式在一格裡的收發量：前 [`MAX_PROCS`] 名＋其餘加總。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcTotals {
    pub top: Vec<ProcNet>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub other_rx: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub other_tx: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// 一格裡的效能彙總（只有開啟效能蒐集的樣本才算進來）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfAgg {
    /// 有效能資料的秒數（平均的權重）。
    pub secs: u32,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub cpu_cores: u32,
    /// 記憶體已用量（依秒數加權平均）與最高值。
    pub mem_avg: u64,
    pub mem_max: u64,
    pub mem_total: u64,
    /// 各磁碟區（這一格最後一個樣本的）。
    pub disks: Vec<DiskVol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_read_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_write_bytes: Option<u64>,
    /// 電池（這一格最後一個樣本的）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<Battery>,
}

/// 一格（`start` 起 `step_s` 秒）的彙總。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bucket {
    pub start: DateTime<Utc>,
    pub step_s: u32,
    /// 有資料的秒數（各樣本 `interval_s` 的和；可能比 `step_s` 少，例如只開了一下子）。
    pub secs: u32,
    pub samples: u32,
    /// 最後一個樣本的時間（略過重複的樣本用）。
    pub last: DateTime<Utc>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// `None`＝這一格都讀不到各程式的量（Linux、沒有系統管理員權限的 Windows）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<ProcTotals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perf: Option<PerfAgg>,
}

/// 樣本歸到哪一格：樣本涵蓋 `ts` 往前 `interval_s` 秒，用中間點對齊到 `step` 秒。
pub fn slot_of(s: &MetricsSample, step: i64) -> DateTime<Utc> {
    align(s.ts - Duration::seconds(i64::from(s.interval_s) / 2), step)
}

/// 往前對齊到 `step` 秒的整數倍（UTC）。
pub fn align(t: DateTime<Utc>, step: i64) -> DateTime<Utc> {
    let step = step.max(1);
    let secs = t.timestamp();
    DateTime::from_timestamp(secs - secs.rem_euclid(step), 0).unwrap_or(t)
}

fn weighted(a: f64, wa: u32, b: f64, wb: u32) -> f64 {
    let w = f64::from(wa) + f64::from(wb);
    if w <= 0.0 {
        return b;
    }
    (a * f64::from(wa) + b * f64::from(wb)) / w
}

fn add_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
    }
}

impl ProcTotals {
    fn from_list(list: &[ProcNet]) -> Self {
        let mut t = Self::default();
        t.merge_list(list, 0, 0);
        t
    }

    /// 依名稱合併、依總量排序、只留前 [`MAX_PROCS`] 名，其餘加進「其他」。
    fn merge_list(&mut self, list: &[ProcNet], other_rx: u64, other_tx: u64) {
        let mut m: HashMap<String, (u64, u64)> = HashMap::new();
        for p in self.top.iter().chain(list) {
            let e = m.entry(p.name.clone()).or_default();
            e.0 = e.0.saturating_add(p.rx_bytes);
            e.1 = e.1.saturating_add(p.tx_bytes);
        }
        let mut v: Vec<ProcNet> = m
            .into_iter()
            .map(|(name, (rx_bytes, tx_bytes))| ProcNet {
                name,
                rx_bytes,
                tx_bytes,
            })
            .collect();
        v.sort_by(|a, b| {
            (b.rx_bytes.saturating_add(b.tx_bytes))
                .cmp(&a.rx_bytes.saturating_add(a.tx_bytes))
                .then_with(|| a.name.cmp(&b.name))
        });
        self.other_rx = self.other_rx.saturating_add(other_rx);
        self.other_tx = self.other_tx.saturating_add(other_tx);
        for p in v.drain(MAX_PROCS.min(v.len())..) {
            self.other_rx = self.other_rx.saturating_add(p.rx_bytes);
            self.other_tx = self.other_tx.saturating_add(p.tx_bytes);
        }
        self.top = v;
    }
}

impl PerfAgg {
    fn from_sample(s: &MetricsSample) -> Option<Self> {
        let p = s.perf.as_ref()?;
        Some(Self {
            secs: s.interval_s.max(1),
            cpu_avg: p.cpu_pct,
            cpu_max: p.cpu_pct,
            cpu_cores: p.cpu_cores,
            mem_avg: p.mem_used,
            mem_max: p.mem_used,
            mem_total: p.mem_total,
            disks: p.disks.clone(),
            disk_read_bytes: p.disk_read_bytes,
            disk_write_bytes: p.disk_write_bytes,
            battery: p.battery.clone(),
        })
    }

    /// 合併；`newer` 為 true 時「最後一個樣本的值」（磁碟區、電池、核心數、總量）用 `o` 的。
    fn merge(&mut self, o: &PerfAgg, newer: bool) {
        self.cpu_avg = super::perf::round1(weighted(self.cpu_avg, self.secs, o.cpu_avg, o.secs));
        self.cpu_max = self.cpu_max.max(o.cpu_max);
        self.mem_avg = weighted(self.mem_avg as f64, self.secs, o.mem_avg as f64, o.secs).round() as u64;
        self.mem_max = self.mem_max.max(o.mem_max);
        self.disk_read_bytes = add_opt(self.disk_read_bytes, o.disk_read_bytes);
        self.disk_write_bytes = add_opt(self.disk_write_bytes, o.disk_write_bytes);
        self.secs = self.secs.saturating_add(o.secs);
        if newer {
            self.cpu_cores = o.cpu_cores;
            self.mem_total = o.mem_total;
            self.disks = o.disks.clone();
            if o.battery.is_some() {
                self.battery = o.battery.clone();
            }
        }
    }
}

impl Bucket {
    /// 只有一個樣本的格子。
    pub fn from_sample(start: DateTime<Utc>, step_s: u32, s: &MetricsSample) -> Self {
        Self {
            start,
            step_s,
            secs: s.interval_s.max(1),
            samples: 1,
            last: s.ts,
            rx_bytes: s.net.rx_bytes,
            tx_bytes: s.net.tx_bytes,
            processes: s.net.processes.as_deref().map(ProcTotals::from_list),
            perf: PerfAgg::from_sample(s),
        }
    }

    /// 把另一格（同一個 `start`）加進來。
    pub fn merge(&mut self, o: &Bucket) {
        let newer = o.last >= self.last;
        self.secs = self.secs.saturating_add(o.secs);
        self.samples = self.samples.saturating_add(o.samples);
        self.last = self.last.max(o.last);
        self.rx_bytes = self.rx_bytes.saturating_add(o.rx_bytes);
        self.tx_bytes = self.tx_bytes.saturating_add(o.tx_bytes);
        match (&mut self.processes, &o.processes) {
            (Some(a), Some(b)) => a.merge_list(&b.top, b.other_rx, b.other_tx),
            (None, Some(b)) => self.processes = Some(b.clone()),
            _ => {}
        }
        match (&mut self.perf, &o.perf) {
            (Some(a), Some(b)) => a.merge(b, newer),
            (None, Some(b)) => self.perf = Some(b.clone()),
            _ => {}
        }
    }

    /// 加一個樣本。
    pub fn add(&mut self, s: &MetricsSample) {
        let one = Bucket::from_sample(self.start, self.step_s, s);
        self.merge(&one);
    }
}

/// 把樣本依 `step` 秒分格彙總（舊→新）。桌面版「最近 1 小時」用每分鐘一格。
pub fn aggregate(samples: &[MetricsSample], step: i64) -> Vec<Bucket> {
    let mut m: BTreeMap<DateTime<Utc>, Bucket> = BTreeMap::new();
    for s in samples {
        let start = slot_of(s, step);
        match m.get_mut(&start) {
            Some(b) => b.add(s),
            None => {
                m.insert(start, Bucket::from_sample(start, step as u32, s));
            }
        }
    }
    m.into_values().collect()
}

fn dir(config_dir: &Path) -> PathBuf {
    config_dir.join(DIR)
}

fn read_open(config_dir: &Path) -> Option<Bucket> {
    // 壞掉的檔案（例如寫到一半斷電）就當作沒有：從這個樣本重新開始這一格
    store::read_json_opt::<Bucket>(&dir(config_dir), OPEN_FILE)
        .ok()
        .flatten()
}

/// 記一個樣本：加進這一格；換格時把上一格接到 `history.jsonl` 後面。
pub fn record(config_dir: &Path, s: &MetricsSample) -> AppResult<()> {
    let start = slot_of(s, STEP_SECS);
    let cur = match read_open(config_dir) {
        Some(mut b) if b.start == start => {
            if s.ts <= b.last {
                return Ok(()); // 同一個樣本記第二次
            }
            b.add(s);
            b
        }
        Some(prev) => {
            append_closed(config_dir, &prev, s.ts)?;
            Bucket::from_sample(start, STEP_SECS as u32, s)
        }
        None => Bucket::from_sample(start, STEP_SECS as u32, s),
    };
    store::write_json_compact_in(&dir(config_dir), OPEN_FILE, &cur)
}

/// 把結束的一格接到 `history.jsonl` 後面（上次寫到一半、沒有換行的話先補換行），必要時整理檔案。
fn append_closed(config_dir: &Path, b: &Bucket, now: DateTime<Utc>) -> AppResult<()> {
    store::ensure_dir(&dir(config_dir))?;
    let path = dir(config_dir).join(HISTORY_FILE);
    let mut line = serde_json::to_vec(b)?;
    line.push(b'\n');
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let len = f.metadata()?.len();
        if len > 0 {
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                f.write_all(b"\n")?;
            }
        }
        f.write_all(&line)?;
    }
    compact(config_dir, now)
}

/// 有壞行、或過期的行累積到 [`COMPACT_SLACK`] 行時，只留 24 小時內的好行重寫。
fn compact(config_dir: &Path, now: DateTime<Utc>) -> AppResult<()> {
    let path = dir(config_dir).join(HISTORY_FILE);
    let Ok(body) = std::fs::read(&path) else {
        return Ok(());
    };
    let cutoff = now - Duration::hours(KEEP_HOURS) - Duration::seconds(STEP_SECS);
    let (mut bad, mut stale) = (0usize, 0usize);
    let mut keep: Vec<&[u8]> = Vec::new();
    for line in body.split(|&c| c == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<Bucket>(line) {
            Ok(b) if b.start >= cutoff => keep.push(line),
            Ok(_) => stale += 1,
            Err(_) => bad += 1,
        }
    }
    if bad == 0 && stale < COMPACT_SLACK {
        return Ok(());
    }
    let mut out = Vec::with_capacity(body.len());
    for l in keep {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    store::write_bytes_atomic(&path, &out)
}

/// `since` 之後的格子（含還在累積的這一格），舊→新；同一格出現兩次就合併。
pub fn load(config_dir: &Path, since: DateTime<Utc>) -> Vec<Bucket> {
    let mut m: BTreeMap<DateTime<Utc>, Bucket> = BTreeMap::new();
    let body = std::fs::read(dir(config_dir).join(HISTORY_FILE)).unwrap_or_default();
    let lines = body
        .split(|&c| c == b'\n')
        .filter_map(|l| serde_json::from_slice::<Bucket>(l).ok());
    for b in lines.chain(read_open(config_dir)) {
        if b.start < since {
            continue;
        }
        match m.get_mut(&b.start) {
            Some(a) => a.merge(&b),
            None => {
                m.insert(b.start, b);
            }
        }
    }
    m.into_values().collect()
}

/// 一個程式在一個時間點的速率（bytes/s）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcRate {
    pub name: String,
    pub rx: f64,
    pub tx: f64,
}

/// 圖上的一個點（一格）：速率都是 bytes/s（這一格的量 ÷ 有資料的秒數）；沒有資料的格子只有 `ts`。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Point {
    pub ts: DateTime<Utc>,
    pub secs: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<f64>,
    /// 各程式（前幾名）；`procs_other` 是其餘程式的合計。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procs: Option<Vec<ProcRate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub procs_other: Option<ProcRate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_read: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_write: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery: Option<u8>,
}

impl Point {
    fn empty(ts: DateTime<Utc>) -> Self {
        Self {
            ts,
            secs: 0,
            rx: None,
            tx: None,
            procs: None,
            procs_other: None,
            cpu: None,
            cpu_max: None,
            mem_used: None,
            mem_total: None,
            disk_read: None,
            disk_write: None,
            battery: None,
        }
    }

    fn from_bucket(b: &Bucket) -> Self {
        let secs = f64::from(b.secs.max(1));
        let rate = |v: u64| v as f64 / secs;
        let p = b.perf.as_ref();
        let psecs = p.map(|p| f64::from(p.secs.max(1))).unwrap_or(1.0);
        Self {
            ts: b.start,
            secs: b.secs,
            rx: Some(rate(b.rx_bytes)),
            tx: Some(rate(b.tx_bytes)),
            procs: b.processes.as_ref().map(|t| {
                t.top
                    .iter()
                    .map(|x| ProcRate {
                        name: x.name.clone(),
                        rx: rate(x.rx_bytes),
                        tx: rate(x.tx_bytes),
                    })
                    .collect()
            }),
            procs_other: b
                .processes
                .as_ref()
                .filter(|t| t.other_rx > 0 || t.other_tx > 0)
                .map(|t| ProcRate {
                    name: String::new(),
                    rx: rate(t.other_rx),
                    tx: rate(t.other_tx),
                }),
            cpu: p.map(|p| p.cpu_avg),
            cpu_max: p.map(|p| p.cpu_max),
            mem_used: p.map(|p| p.mem_avg),
            mem_total: p.map(|p| p.mem_total),
            disk_read: p.and_then(|p| p.disk_read_bytes).map(|v| v as f64 / psecs),
            disk_write: p.and_then(|p| p.disk_write_bytes).map(|v| v as f64 / psecs),
            battery: p.and_then(|p| p.battery.as_ref()).map(|b| b.percent),
        }
    }
}

/// 固定的時間軸：到 `end` 為止的最近 `n` 格（每格 `step` 秒），沒有資料的格子留空（圖上斷開）。
pub fn points(buckets: &[Bucket], end: DateTime<Utc>, step: i64, n: usize) -> Vec<Point> {
    let by_start: HashMap<DateTime<Utc>, &Bucket> = buckets.iter().map(|b| (b.start, b)).collect();
    let last = align(end, step);
    (0..n)
        .rev()
        .map(|k| {
            let ts = last - Duration::seconds(step * k as i64);
            by_start
                .get(&ts)
                .map(|b| Point::from_bucket(b))
                .unwrap_or_else(|| Point::empty(ts))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::sample_for_tests;
    use chrono::TimeZone;

    fn at(h: u32, m: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 17, h, m, s).unwrap()
    }

    fn sample(ts: DateTime<Utc>, rx: u64, cpu: Option<f64>, procs: Option<Vec<(&str, u64, u64)>>) -> MetricsSample {
        let mut s = sample_for_tests(1);
        s.ts = ts;
        s.interval_s = 60;
        s.net.rx_bytes = rx;
        s.net.tx_bytes = rx / 10;
        s.net.processes = procs.map(|v| {
            v.into_iter()
                .map(|(n, r, t)| ProcNet {
                    name: n.into(),
                    rx_bytes: r,
                    tx_bytes: t,
                })
                .collect()
        });
        s.perf = cpu.map(|c| {
            let mut p = crate::metrics::sample_batch().samples[1].perf.clone().unwrap();
            p.cpu_pct = c;
            p.mem_used = (c * 100.0) as u64;
            p
        });
        s
    }

    #[test]
    fn slots_use_the_middle_of_the_sample() {
        let s = sample(at(9, 5, 20), 1, None, None);
        // 09:04:20–09:05:20 的中間點是 09:04:50 → 09:00 那一格
        assert_eq!(slot_of(&s, STEP_SECS), at(9, 0, 0));
        assert_eq!(slot_of(&s, 60), at(9, 4, 0));
        assert_eq!(align(at(9, 59, 59), 300), at(9, 55, 0));
    }

    #[test]
    fn bucket_sums_bytes_and_weights_averages() {
        let start = at(9, 0, 0);
        let mut b = Bucket::from_sample(start, 300, &sample(at(9, 1, 0), 1000, Some(10.0), None));
        let mut short = sample(at(9, 1, 20), 500, Some(70.0), None);
        short.interval_s = 20;
        b.add(&short);
        assert_eq!((b.samples, b.secs, b.rx_bytes, b.tx_bytes), (2, 80, 1500, 150));
        let p = b.perf.as_ref().unwrap();
        // (10×60 + 70×20) / 80 = 25
        assert!((p.cpu_avg - 25.0).abs() < 1e-9, "{}", p.cpu_avg);
        assert_eq!(p.cpu_max, 70.0);
        assert_eq!(p.mem_max, 7000);
        assert_eq!(p.disk_read_bytes, Some(2 * 52_428_800));
        // 一個有效能、一個沒有：效能只算有資料的秒數
        let mut c = Bucket::from_sample(start, 300, &sample(at(9, 2, 0), 1, None, None));
        c.merge(&b);
        assert_eq!(c.perf.as_ref().unwrap().secs, 80);
        assert_eq!(c.secs, 140);
    }

    #[test]
    fn processes_are_merged_by_name_and_folded_into_other() {
        let many: Vec<(String, u64, u64)> = (0..20).map(|i| (format!("p{i:02}.exe"), 1000 - i * 10, 1)).collect();
        let list: Vec<(&str, u64, u64)> = many.iter().map(|(n, r, t)| (n.as_str(), *r, *t)).collect();
        let mut b = Bucket::from_sample(at(9, 0, 0), 300, &sample(at(9, 1, 0), 1, None, Some(list)));
        let t = b.processes.as_ref().unwrap();
        assert_eq!(t.top.len(), MAX_PROCS);
        assert_eq!(t.top[0].name, "p00.exe");
        // 第 13～20 名：1000-120 … 1000-190
        assert_eq!(t.other_rx, (12..20).map(|i| 1000 - i * 10).sum::<u64>());
        assert_eq!(t.other_tx, 8);
        // 同名合併；讀不到各程式的樣本不會清掉已有的資料
        b.add(&sample(at(9, 2, 0), 1, None, Some(vec![("p05.exe", 5000, 0)])));
        b.add(&sample(at(9, 3, 0), 1, None, None));
        let t = b.processes.as_ref().unwrap();
        assert_eq!(t.top[0].name, "p05.exe");
        assert_eq!(t.top[0].rx_bytes, 5000 + 950);
        // 從頭到尾讀不到 → None
        let none = Bucket::from_sample(at(9, 0, 0), 300, &sample(at(9, 1, 0), 1, None, None));
        assert!(none.processes.is_none());
    }

    #[test]
    fn record_rolls_over_and_load_returns_everything_in_order() {
        let d = tempfile::tempdir().unwrap();
        for m in [1, 2, 3, 6, 7, 11] {
            record(d.path(), &sample(at(9, m, 30), 100, Some(5.0), None)).unwrap();
        }
        // 同一個樣本記第二次不重複計算
        record(d.path(), &sample(at(9, 11, 30), 100, Some(5.0), None)).unwrap();
        let body = std::fs::read_to_string(d.path().join(DIR).join(HISTORY_FILE)).unwrap();
        assert_eq!(body.lines().count(), 2, "09:00 and 09:05 are closed");
        let all = load(d.path(), at(0, 0, 0));
        let starts: Vec<_> = all.iter().map(|b| b.start).collect();
        assert_eq!(starts, vec![at(9, 0, 0), at(9, 5, 0), at(9, 10, 0)]);
        assert_eq!(all.iter().map(|b| b.samples).collect::<Vec<_>>(), vec![3, 2, 1]);
        assert_eq!(all[0].rx_bytes, 300);
        assert_eq!(load(d.path(), at(9, 5, 0)).len(), 2);
    }

    #[test]
    fn broken_files_are_rebuilt() {
        let d = tempfile::tempdir().unwrap();
        let mdir = d.path().join(DIR);
        std::fs::create_dir_all(&mdir).unwrap();
        // 壞掉的「這一格」：直接從新樣本重新開始
        std::fs::write(mdir.join(OPEN_FILE), b"\x00\x01 not json").unwrap();
        // 歷史檔有壞行、最後一行寫到一半沒有換行
        let good = serde_json::to_string(&Bucket::from_sample(
            at(8, 0, 0),
            300,
            &sample(at(8, 1, 0), 7, None, None),
        ))
        .unwrap();
        std::fs::write(
            mdir.join(HISTORY_FILE),
            format!("garbage\n{good}\n{{\"start\":\"2026-10"),
        )
        .unwrap();
        record(d.path(), &sample(at(9, 1, 0), 1, None, None)).unwrap();
        record(d.path(), &sample(at(9, 6, 0), 2, None, None)).unwrap();
        let body = std::fs::read_to_string(mdir.join(HISTORY_FILE)).unwrap();
        assert_eq!(body.lines().count(), 2, "bad lines dropped on compaction: {body}");
        assert!(body.lines().all(|l| serde_json::from_str::<Bucket>(l).is_ok()));
        let all = load(d.path(), at(0, 0, 0));
        assert_eq!(
            all.iter().map(|b| (b.start, b.rx_bytes)).collect::<Vec<_>>(),
            vec![(at(8, 0, 0), 7), (at(9, 0, 0), 1), (at(9, 5, 0), 2)]
        );
    }

    #[test]
    fn old_rows_are_dropped_after_a_day_and_the_file_stays_small() {
        let d = tempfile::tempdir().unwrap();
        // 26 小時、每 5 分鐘兩個樣本（每格都有），每個都有 12 個以上、名字很長的程式和效能資料
        let procs: Vec<(String, u64, u64)> = (0..14)
            .map(|i| (format!("a-rather-long-program-name-{i:02}.exe"), 1_000_000 + i, 2_000))
            .collect();
        let list: Vec<(&str, u64, u64)> = procs.iter().map(|(n, r, t)| (n.as_str(), *r, *t)).collect();
        let t0 = at(0, 1, 30);
        let rounds = 26 * 12;
        for k in 0..rounds {
            for half in [0, 2] {
                let ts = t0 + Duration::minutes(k * 5 + half);
                record(d.path(), &sample(ts, 5_000_000, Some(12.5), Some(list.clone()))).unwrap();
            }
        }
        let path = d.path().join(DIR).join(HISTORY_FILE);
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        let per_day = (KEEP_HOURS * 3600 / STEP_SECS) as usize;
        assert!(lines <= per_day + COMPACT_SLACK + 2, "{lines} lines");
        // 一格約 1.5 KB：一天的檔案在 600 KB 以內
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size < 600 * 1024, "{size} bytes");
        let open = std::fs::metadata(d.path().join(DIR).join(OPEN_FILE)).unwrap().len();
        assert!(open < 2 * 1024, "open bucket {open} bytes");
        let end = t0 + Duration::minutes(rounds * 5);
        let day = load(d.path(), end - Duration::hours(24));
        assert!(day.len() >= per_day - 1 && day.len() <= per_day + 1, "{}", day.len());
    }

    #[test]
    fn points_fill_gaps_and_turn_bytes_into_rates() {
        let mut a = Bucket::from_sample(
            at(9, 0, 0),
            300,
            &sample(at(9, 1, 0), 6_000, Some(40.0), Some(vec![("a.exe", 600, 60)])),
        );
        a.processes.as_mut().unwrap().other_rx = 120;
        let b = Bucket::from_sample(at(9, 10, 0), 300, &sample(at(9, 11, 0), 60, None, None));
        let pts = points(&[a, b], at(9, 12, 0), 300, 4);
        assert_eq!(
            pts.iter().map(|p| p.ts).collect::<Vec<_>>(),
            vec![at(8, 55, 0), at(9, 0, 0), at(9, 5, 0), at(9, 10, 0)]
        );
        assert!(pts[0].rx.is_none() && pts[2].rx.is_none(), "gaps stay empty");
        // 60 秒 6000 bytes → 100 B/s
        assert_eq!(pts[1].rx, Some(100.0));
        assert_eq!(pts[1].cpu, Some(40.0));
        assert_eq!(pts[1].disk_read, Some(52_428_800.0 / 60.0));
        let procs = pts[1].procs.as_ref().unwrap();
        assert_eq!((procs[0].name.as_str(), procs[0].rx, procs[0].tx), ("a.exe", 10.0, 1.0));
        assert_eq!(pts[1].procs_other.as_ref().unwrap().rx, 2.0);
        assert!(pts[3].cpu.is_none() && pts[3].procs.is_none());
        let v = serde_json::to_value(&pts[0]).unwrap();
        assert_eq!(v.as_object().unwrap().len(), 2, "empty point is just ts + secs: {v}");
    }

    #[test]
    fn aggregate_makes_one_bucket_per_minute() {
        let s: Vec<MetricsSample> = [(9, 0, 10), (9, 0, 40), (9, 0, 55), (9, 2, 5)]
            .iter()
            .map(|&(h, m, sec)| {
                let mut x = sample(at(h, m, sec), 10, None, None);
                x.interval_s = 10;
                x
            })
            .collect();
        let b = aggregate(&s, 60);
        assert_eq!(
            b.iter().map(|b| (b.start, b.samples)).collect::<Vec<_>>(),
            vec![(at(9, 0, 0), 3), (at(9, 2, 0), 1)]
        );
        assert_eq!(b[0].secs, 30);
    }
}
