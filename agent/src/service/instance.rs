//! 常駐行程的共用設施：單一實例鎖、每日 log 檔（保留 14 天）、停止訊號（Ctrl-C／SIGTERM／Windows 服務控制）。

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use chrono::{NaiveDate, Utc};
use tokio::sync::Notify;

pub const LOG_KEEP_DAYS: i64 = 14;
pub const LOCK_FILE: &str = "watch.lock";
/// log 檔名前綴：`ai-security-monitor-YYYY-MM-DD.log`。
pub const LOG_PREFIX: &str = "ai-security-monitor-";
/// 改名前的 log 檔名前綴（保留期內的舊檔照樣清理、照樣讀）。
pub const LEGACY_LOG_PREFIX: &str = "asa-";

static STOP: Notify = Notify::const_new();
static STOPPING: AtomicBool = AtomicBool::new(false);
static LOG: OnceLock<Mutex<LogFile>> = OnceLock::new();

/// 要求常駐迴圈結束（服務控制處理器、測試用）。
pub fn request_stop() {
    STOPPING.store(true, Ordering::SeqCst);
    STOP.notify_one();
}

pub fn stop_requested() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

/// 等到 Ctrl-C、SIGTERM 或 `request_stop()`。
pub async fn stopped() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let sigterm = async {
            match term.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm => {}
            _ = STOP.notified() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = STOP.notified() => {}
        }
    }
    STOPPING.store(true, Ordering::SeqCst);
}

/// 單一實例鎖：同一個設定目錄只能有一個常駐 watch。拿不到就回 None。
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn acquire(config_dir: &Path) -> std::io::Result<Option<InstanceLock>> {
        crate::store::ensure_dir(config_dir).map_err(|e| std::io::Error::other(e.message()))?;
        let path = config_dir.join(LOCK_FILE);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.share_mode(0);
        }
        let mut file = match opts.open(&path) {
            Ok(f) => f,
            // Windows：別人開著（share_mode 0）→ sharing violation
            Err(e) if e.raw_os_error() == Some(32) => return Ok(None),
            Err(e) => return Err(e),
        };
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Ok(None);
            }
        }
        let _ = file.set_len(0);
        let _ = writeln!(file, "{}", std::process::id());
        Ok(Some(InstanceLock { _file: file, path }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 這個設定目錄的鎖正被別的常駐行程占用（只探測：不建立鎖檔、不改內容，拿到也馬上放掉）。
    pub fn is_held(config_dir: &Path) -> bool {
        let path = config_dir.join(LOCK_FILE);
        if !path.is_file() {
            return false;
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.share_mode(0);
        }
        match opts.open(&path) {
            Ok(_file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    // 拿得到就是沒人占用；關檔時自動放開
                    if unsafe { libc::flock(_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                        return true;
                    }
                }
                false
            }
            // Windows：別人獨占開著 → sharing violation
            Err(e) => e.raw_os_error() == Some(32),
        }
    }
}

struct LogFile {
    dir: PathBuf,
    day: Option<NaiveDate>,
    file: Option<File>,
}

impl LogFile {
    fn write_line(&mut self, line: &str) {
        let today = Utc::now().date_naive();
        if self.day != Some(today) || self.file.is_none() {
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path(&self.dir, today))
                .ok();
            self.day = Some(today);
            prune_logs(&self.dir, today);
        }
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub fn log_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("logs")
}

pub fn log_path(dir: &Path, day: NaiveDate) -> PathBuf {
    dir.join(format!("{LOG_PREFIX}{}.log", day.format("%Y-%m-%d")))
}

/// `ai-security-monitor-YYYY-MM-DD.log`（或舊的 `asa-YYYY-MM-DD.log`）的日期。
fn log_day(name: &str) -> Option<NaiveDate> {
    name.strip_prefix(LOG_PREFIX)
        .or_else(|| name.strip_prefix(LEGACY_LOG_PREFIX))
        .and_then(|s| s.strip_suffix(".log"))
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
}

/// 刪掉超過保留天數的 log 檔（新舊檔名都算）。
pub fn prune_logs(dir: &Path, today: NaiveDate) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(d) = log_day(&name) else {
            continue;
        };
        if (today - d).num_days() > LOG_KEEP_DAYS {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// 開始寫 log 檔（服務模式）；之後 `write_log` 會寫進去。
pub fn init_log(config_dir: &Path) -> bool {
    let dir = log_dir(config_dir);
    if crate::store::ensure_dir(&dir).is_err() {
        return false;
    }
    LOG.set(Mutex::new(LogFile {
        dir,
        day: None,
        file: None,
    }))
    .is_ok()
}

pub fn log_enabled() -> bool {
    LOG.get().is_some()
}

pub fn write_log(line: &str) {
    if let Some(m) = LOG.get() {
        if let Ok(mut l) = m.lock() {
            l.write_line(line);
        }
    }
}

/// 最新 log 檔的最後 n 行。
pub fn tail_latest(config_dir: &Path, n: usize) -> Option<(PathBuf, Vec<String>)> {
    let dir = log_dir(config_dir);
    // 依日期挑最新的（新舊檔名混在一起時不能用檔名排序）；同一天新檔名優先
    let last = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            log_day(&name).map(|d| ((d, name.starts_with(LOG_PREFIX)), e.path()))
        })
        .max_by(|a, b| a.0.cmp(&b.0))?
        .1;
    let text = std::fs::read_to_string(&last).ok()?;
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let start = lines.len().saturating_sub(n);
    Some((last, lines[start..].to_vec()))
}

/// Windows：從「執行」機碼開機啟動時會自帶一個主控台視窗；這個行程獨占它時就把它關掉。
pub fn detach_console_if_owned() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
        let mut pids = [0u32; 4];
        if GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 {
            FreeConsole();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_instance_lock() {
        let d = tempfile::tempdir().unwrap();
        let a = InstanceLock::acquire(d.path()).unwrap();
        assert!(a.is_some());
        assert!(a.as_ref().unwrap().path().ends_with(LOCK_FILE));
        // 同一行程另開一次：Windows 會 sharing violation；Unix flock 對同行程不同 fd 也互斥
        assert!(InstanceLock::acquire(d.path()).unwrap().is_none());
        drop(a);
        assert!(InstanceLock::acquire(d.path()).unwrap().is_some());
    }

    #[test]
    fn is_held_only_probes() {
        let d = tempfile::tempdir().unwrap();
        // 沒有鎖檔：沒人占用，也不建立
        assert!(!InstanceLock::is_held(d.path()));
        assert!(!d.path().join(LOCK_FILE).exists());
        let a = InstanceLock::acquire(d.path()).unwrap().unwrap();
        assert!(InstanceLock::is_held(d.path()));
        drop(a);
        assert!(!InstanceLock::is_held(d.path()));
        // 探測不改鎖檔內容，探測後照樣拿得到
        assert_eq!(
            std::fs::read_to_string(d.path().join(LOCK_FILE)).unwrap().trim(),
            std::process::id().to_string()
        );
        assert!(InstanceLock::acquire(d.path()).unwrap().is_some());
    }

    #[test]
    fn prune_and_tail() {
        let d = tempfile::tempdir().unwrap();
        let dir = log_dir(d.path());
        std::fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        std::fs::write(log_path(&dir, NaiveDate::from_ymd_opt(2026, 9, 1).unwrap()), "old\n").unwrap();
        std::fs::write(log_path(&dir, NaiveDate::from_ymd_opt(2026, 10, 10).unwrap()), "a\n").unwrap();
        std::fs::write(log_path(&dir, today), "1\n2\n3\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        prune_logs(&dir, today);
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "ai-security-monitor-2026-10-10.log",
                "ai-security-monitor-2026-10-17.log",
                "notes.txt"
            ]
        );
        let (p, lines) = tail_latest(d.path(), 2).unwrap();
        assert!(p.ends_with("ai-security-monitor-2026-10-17.log"));
        assert_eq!(lines, vec!["2", "3"]);
    }

    #[test]
    fn legacy_log_names_are_pruned_and_read() {
        let d = tempfile::tempdir().unwrap();
        let dir = log_dir(d.path());
        std::fs::create_dir_all(&dir).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 10, 17).unwrap();
        std::fs::write(dir.join("asa-2026-09-01.log"), "old\n").unwrap();
        std::fs::write(dir.join("asa-2026-10-16.log"), "legacy\n").unwrap();
        prune_logs(&dir, today);
        assert!(!dir.join("asa-2026-09-01.log").exists());
        // 只有舊檔：讀舊檔
        let (p, lines) = tail_latest(d.path(), 5).unwrap();
        assert!(p.ends_with("asa-2026-10-16.log"));
        assert_eq!(lines, vec!["legacy"]);
        // 新檔日期較新：讀新檔（檔名排序會挑錯）
        std::fs::write(log_path(&dir, today), "new\n").unwrap();
        let (p, _) = tail_latest(d.path(), 5).unwrap();
        assert!(p.ends_with("ai-security-monitor-2026-10-17.log"));
    }
}
