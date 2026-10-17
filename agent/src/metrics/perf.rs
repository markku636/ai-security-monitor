//! 效能（使用者明確開啟才蒐集）：CPU、記憶體、置換空間、各磁碟用量與讀寫量、開機時間、負載、最吃 CPU／記憶體的程式、電池。

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, ProcessesToUpdate, System};

use super::battery::Battery;

/// 一個磁碟區的用量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskVol {
    /// 掛載點（`C:\`、`/`、`/home`）。
    pub mount: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fs: String,
    pub used: u64,
    pub total: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removable: bool,
}

/// 一個程式（同名合併）的 CPU 與記憶體。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcPerf {
    pub name: String,
    /// 只有一個行程時才有。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// 同名的行程數。
    #[serde(default = "one")]
    pub count: u32,
    /// 佔整台電腦 CPU 的百分比（0–100，已除以核心數）。
    pub cpu_pct: f64,
    /// 實體記憶體（RSS），bytes。
    pub rss: u64,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerfSample {
    /// 整體 CPU 使用率（0–100，這段時間的平均）。
    pub cpu_pct: f64,
    /// 邏輯核心數。
    pub cpu_cores: u32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disks: Vec<DiskVol>,
    /// 這段時間所有磁碟讀取／寫入的 bytes（讀不到就沒有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_read_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_write_bytes: Option<u64>,
    /// 1／5／15 分鐘負載（只有 Linux／macOS）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<[f64; 3]>,
    pub uptime_s: u64,
    pub boot_time: DateTime<Utc>,
    pub top_cpu: Vec<ProcPerf>,
    pub top_mem: Vec<ProcPerf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery: Option<Battery>,
}

/// 每種排行列幾個程式。
pub const TOP_N: usize = 5;
/// 最多列幾個磁碟區。
pub const MAX_DISKS: usize = 12;

/// 不列的檔案系統（唯讀映像、容器層、虛擬檔案系統）。
const SKIP_FS: &[&str] = &[
    "squashfs",
    "overlay",
    "overlayfs",
    "iso9660",
    "udf",
    "devfs",
    "autofs",
    "tmpfs",
    "devtmpfs",
    "ramfs",
    "nullfs",
    "efivarfs",
];

/// 這個掛載點要不要列（macOS 的 /System/Volumes/* 跟 / 共用同一個 APFS 容器，只看 /）。
pub fn keep_volume(mount: &str, fs: &str, total: u64) -> bool {
    if total < 256 * 1024 * 1024 {
        return false;
    }
    let fs = fs.to_ascii_lowercase();
    if SKIP_FS.iter().any(|s| fs == *s) {
        return false;
    }
    let m = mount.replace('\\', "/");
    !(m.starts_with("/System/Volumes/")
        || m.starts_with("/private/var/vm")
        || m.starts_with("/snap/")
        || m.starts_with("/boot/efi")
        || m.starts_with("/var/lib/docker/")
        || m.starts_with("/run/"))
}

/// 磁碟區清單（同一個裝置只留最短的掛載點）。
pub fn volumes(disks: &Disks) -> Vec<DiskVol> {
    let mut by_dev: HashMap<String, DiskVol> = HashMap::new();
    for d in disks.list() {
        let mount = d.mount_point().to_string_lossy().to_string();
        let fs = d.file_system().to_string_lossy().to_string();
        let total = d.total_space();
        if !keep_volume(&mount, &fs, total) {
            continue;
        }
        let v = DiskVol {
            mount: crate::util::text::clip(&mount, 120),
            fs: crate::util::text::clip(&fs, 32),
            used: total.saturating_sub(d.available_space()),
            total,
            removable: d.is_removable(),
        };
        let key = d.name().to_string_lossy().to_string();
        let key = if key.is_empty() { mount.clone() } else { key };
        match by_dev.get(&key) {
            Some(old) if old.mount.len() <= v.mount.len() => {}
            _ => {
                by_dev.insert(key, v);
            }
        }
    }
    let mut out: Vec<DiskVol> = by_dev.into_values().collect();
    out.sort_by(|a, b| a.mount.cmp(&b.mount));
    out.truncate(MAX_DISKS);
    out
}

/// 所有磁碟的累計讀寫 bytes（同一個裝置只算一次）；全部是 0 表示這個平台讀不到。
pub fn disk_io_totals(disks: &Disks) -> Option<(u64, u64)> {
    let mut seen = std::collections::HashSet::new();
    let (mut r, mut w) = (0u64, 0u64);
    for d in disks.list() {
        let name = d.name().to_string_lossy().to_string();
        if !seen.insert(name) {
            continue;
        }
        let u = d.usage();
        r = r.saturating_add(u.total_read_bytes);
        w = w.saturating_add(u.total_written_bytes);
    }
    (r > 0 || w > 0).then_some((r, w))
}

/// 依名稱合併行程，排出最吃 CPU 與最吃記憶體的前 N 名。`cores` 用來把 CPU 換成整台電腦的百分比。
pub fn top_processes(sys: &System, cores: usize) -> (Vec<ProcPerf>, Vec<ProcPerf>) {
    let cores = cores.max(1) as f64;
    let mut m: HashMap<String, ProcPerf> = HashMap::new();
    for (pid, p) in sys.processes() {
        if p.thread_kind().is_some() {
            continue;
        }
        let name = p.name().to_string_lossy().to_string();
        if name.is_empty() {
            continue;
        }
        let cpu = f64::from(p.cpu_usage()) / cores;
        let e = m.entry(name.clone()).or_insert(ProcPerf {
            name: crate::util::text::clip(&name, 80),
            pid: Some(pid.as_u32()),
            count: 0,
            cpu_pct: 0.0,
            rss: 0,
        });
        e.count += 1;
        if e.count > 1 {
            e.pid = None;
        }
        e.cpu_pct += cpu;
        e.rss = e.rss.saturating_add(p.memory());
    }
    let all: Vec<ProcPerf> = m
        .into_values()
        .map(|mut p| {
            p.cpu_pct = round1(p.cpu_pct.min(100.0));
            p
        })
        .collect();
    let mut by_cpu: Vec<ProcPerf> = all.iter().filter(|p| p.cpu_pct > 0.0).cloned().collect();
    by_cpu.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct).then_with(|| a.name.cmp(&b.name)));
    by_cpu.truncate(TOP_N);
    let mut by_mem = all;
    by_mem.sort_by(|a, b| b.rss.cmp(&a.rss).then_with(|| a.name.cmp(&b.name)));
    by_mem.truncate(TOP_N);
    (by_cpu, by_mem)
}

pub fn round1(v: f64) -> f64 {
    if v.is_finite() {
        (v * 10.0).round() / 10.0
    } else {
        0.0
    }
}

/// 記憶體「已用」：total − available（各平台一致，不把可回收的快取算成已用）。
pub fn mem_used(total: u64, available: u64, used_fallback: u64) -> u64 {
    if available > 0 && available <= total {
        total - available
    } else {
        used_fallback.min(total)
    }
}

pub fn boot_time() -> DateTime<Utc> {
    Utc.timestamp_opt(System::boot_time() as i64, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

pub fn load_average() -> Option<[f64; 3]> {
    if cfg!(windows) {
        return None;
    }
    let l = System::load_average();
    Some([round2(l.one), round2(l.five), round2(l.fifteen)])
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// 刷新 CPU、記憶體、行程（呼叫端負責兩次刷新之間的間隔 ≥ 200 ms，CPU 百分比才準）。
pub fn refresh(sys: &mut System) {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .without_tasks(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_filter() {
        const G: u64 = 1 << 30;
        assert!(keep_volume("C:\\", "NTFS", 256 * G));
        assert!(keep_volume("/", "apfs", 500 * G));
        assert!(keep_volume("/home", "ext4", 100 * G));
        assert!(!keep_volume("/System/Volumes/Data", "apfs", 500 * G));
        assert!(!keep_volume("/snap/core22/1380", "squashfs", G));
        assert!(!keep_volume("/boot/efi", "vfat", G));
        assert!(!keep_volume("/mnt/tiny", "ext4", 1024));
        assert!(!keep_volume("/var/lib/docker/overlay2/x/merged", "overlay", 100 * G));
    }

    #[test]
    fn memory_and_rounding() {
        assert_eq!(mem_used(16, 6, 99), 10);
        assert_eq!(mem_used(16, 0, 7), 7, "no available figure: fall back to used");
        assert_eq!(mem_used(16, 0, 99), 16);
        assert_eq!(round1(12.345), 12.3);
        assert_eq!(round1(f64::NAN), 0.0);
    }

    #[test]
    fn live_perf_values_are_sane() {
        let mut sys = System::new();
        refresh(&mut sys);
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        refresh(&mut sys);
        let cores = sys.cpus().len();
        assert!(cores >= 1);
        assert!(sys.global_cpu_usage() >= 0.0 && sys.global_cpu_usage() <= 100.0 + f32::EPSILON);
        assert!(sys.total_memory() > 0);
        let (by_cpu, by_mem) = top_processes(&sys, cores);
        assert!(by_cpu.len() <= TOP_N && by_mem.len() <= TOP_N);
        assert!(!by_mem.is_empty(), "at least this test process uses memory");
        assert!(by_mem.iter().all(|p| p.count >= 1 && p.cpu_pct <= 100.0));
        let disks = Disks::new_with_refreshed_list();
        let v = volumes(&disks);
        assert!(v.iter().all(|d| d.used <= d.total));
        assert!(boot_time() <= Utc::now());
    }
}
