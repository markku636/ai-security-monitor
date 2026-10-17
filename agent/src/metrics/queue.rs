//! 本機保存：
//! - `metrics/queue.jsonl`：還沒送到 Hub 的樣本（一行一個；Hub 暫時連不上時累積，最多 [`MAX_QUEUE`] 個，丟最舊的）；
//! - `metrics/recent.json`：最近 [`RECENT`] 個樣本（桌面版的小圖、`get_metrics` 工具用），不管有沒有加入 Hub。
//!
//! 24 小時的彙總歷史在 [`super::history`]。

use std::io::Write;
use std::path::{Path, PathBuf};

use super::MetricsSample;
use crate::error::AppResult;
use crate::store;

pub const DIR: &str = "metrics";
pub const QUEUE_FILE: &str = "queue.jsonl";
pub const RECENT_FILE: &str = "recent.json";
/// 待送上限：每分鐘一個約一天。
pub const MAX_QUEUE: usize = 1440;
/// 保留在本機的最近樣本數（每分鐘一個＝1 小時）。
pub const RECENT: usize = 60;

fn dir(config_dir: &Path) -> PathBuf {
    config_dir.join(DIR)
}

fn queue_path(config_dir: &Path) -> PathBuf {
    dir(config_dir).join(QUEUE_FILE)
}

fn read_lines(config_dir: &Path) -> Vec<String> {
    std::fs::read_to_string(queue_path(config_dir))
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

fn rewrite(config_dir: &Path, lines: &[String]) -> AppResult<()> {
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    store::ensure_dir(&dir(config_dir))?;
    store::write_bytes_atomic(&queue_path(config_dir), body.as_bytes())
}

/// 加到待送佇列尾端；超過上限就丟最舊的。
pub fn push(config_dir: &Path, s: &MetricsSample) -> AppResult<()> {
    store::ensure_dir(&dir(config_dir))?;
    let line = serde_json::to_string(s)?;
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(queue_path(config_dir))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    // 一行至少百來個 bytes：檔案還小就不用數
    let size = std::fs::metadata(queue_path(config_dir)).map(|m| m.len()).unwrap_or(0);
    if size < (MAX_QUEUE as u64) * 100 {
        return Ok(());
    }
    let lines = read_lines(config_dir);
    if lines.len() > MAX_QUEUE {
        rewrite(config_dir, &lines[lines.len() - MAX_QUEUE..])?;
    }
    Ok(())
}

/// 最舊的 `n` 個樣本（壞掉的行直接略過）與佇列裡的總數。
pub fn peek(config_dir: &Path, n: usize) -> (Vec<MetricsSample>, usize) {
    let lines = read_lines(config_dir);
    let total = lines.len();
    let items = lines
        .iter()
        .take(n)
        .filter_map(|l| serde_json::from_str::<MetricsSample>(l).ok())
        .collect();
    (items, total)
}

/// 送出成功（或被 Hub 拒收）後移掉最舊的 `n` 行。
pub fn drop_first(config_dir: &Path, n: usize) -> AppResult<()> {
    let lines = read_lines(config_dir);
    rewrite(config_dir, &lines[n.min(lines.len())..])
}

pub fn len(config_dir: &Path) -> usize {
    read_lines(config_dir).len()
}

/// 最近的樣本（舊→新）。
pub fn recent(config_dir: &Path) -> Vec<MetricsSample> {
    store::read_json_opt::<Vec<MetricsSample>>(&dir(config_dir), RECENT_FILE)
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// 加進最近樣本（只留 [`RECENT`] 個）。
pub fn remember(config_dir: &Path, s: &MetricsSample) -> AppResult<()> {
    let mut v = recent(config_dir);
    v.push(s.clone());
    if v.len() > RECENT {
        v.drain(..v.len() - RECENT);
    }
    store::write_json_compact_in(&dir(config_dir), RECENT_FILE, &v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::sample_for_tests;

    #[test]
    fn queue_push_peek_drop_and_cap() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..5 {
            push(d.path(), &sample_for_tests(i)).unwrap();
        }
        let (items, total) = peek(d.path(), 3);
        assert_eq!((items.len(), total), (3, 5));
        assert_eq!(items[0].net.rx_bytes, 0);
        drop_first(d.path(), 3).unwrap();
        let (items, total) = peek(d.path(), 10);
        assert_eq!(total, 2);
        assert_eq!(items[0].net.rx_bytes, 3_000);
        // 壞掉的行不擋住後面的
        std::fs::OpenOptions::new()
            .append(true)
            .open(d.path().join(DIR).join(QUEUE_FILE))
            .unwrap()
            .write_all(b"{not json\n")
            .unwrap();
        push(d.path(), &sample_for_tests(9)).unwrap();
        let (items, total) = peek(d.path(), 10);
        assert_eq!((items.len(), total), (3, 4));
        drop_first(d.path(), 99).unwrap();
        assert_eq!(len(d.path()), 0);
    }

    #[test]
    fn queue_is_capped() {
        let d = tempfile::tempdir().unwrap();
        // 直接寫超過上限的行，再 push 一次觸發修剪
        let line = serde_json::to_string(&sample_for_tests(1)).unwrap();
        let body = format!("{line}\n").repeat(MAX_QUEUE + 5);
        std::fs::create_dir_all(d.path().join(DIR)).unwrap();
        std::fs::write(d.path().join(DIR).join(QUEUE_FILE), body).unwrap();
        push(d.path(), &sample_for_tests(2)).unwrap();
        assert_eq!(len(d.path()), MAX_QUEUE);
        let lines = read_lines(d.path());
        assert!(lines.last().unwrap().contains("2000"), "newest kept");
    }

    #[test]
    fn recent_ring() {
        let d = tempfile::tempdir().unwrap();
        assert!(recent(d.path()).is_empty());
        for i in 0..(RECENT as u64 + 7) {
            remember(d.path(), &sample_for_tests(i)).unwrap();
        }
        let r = recent(d.path());
        assert_eq!(r.len(), RECENT);
        assert_eq!(r.last().unwrap().net.rx_bytes, (RECENT as u64 + 6) * 1000);
    }
}
