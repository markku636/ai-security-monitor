//! 上傳失敗（hub 停機、網路斷）的報告暫存在 `<config>/outbox/`，下次連得上時依序重送；最多留 50 份。

use std::path::{Path, PathBuf};

use crate::error::AppResult;
use crate::model::report::Report;
use crate::store;

pub const OUTBOX_DIR: &str = "outbox";
pub const MAX_ITEMS: usize = 50;

fn dir(config_dir: &Path) -> PathBuf {
    config_dir.join(OUTBOX_DIR)
}

/// 依檔名（時間戳開頭）排序的待送清單。
pub fn list(config_dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir(config_dir))
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

pub fn push(config_dir: &Path, report: &Report) -> AppResult<PathBuf> {
    let d = dir(config_dir);
    store::ensure_dir(&d)?;
    let name = format!(
        "{}-{}.json",
        report.finished_at.format("%Y%m%dT%H%M%S"),
        &report.report_id
    );
    store::write_json_compact_in(&d, &name, report)?;
    // 超過上限丟最舊的。
    let items = list(config_dir);
    if items.len() > MAX_ITEMS {
        for p in &items[..items.len() - MAX_ITEMS] {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(d.join(name))
}

pub fn load(path: &Path) -> Option<Report> {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_list_and_cap() {
        let d = tempfile::tempdir().unwrap();
        let mut r = crate::model::contract::sample_report();
        for i in 0..(MAX_ITEMS + 3) {
            r.report_id = format!("00000000-0000-4000-8000-{i:012}");
            r.finished_at += chrono::Duration::seconds(1);
            push(d.path(), &r).unwrap();
        }
        let items = list(d.path());
        assert_eq!(items.len(), MAX_ITEMS);
        assert!(load(&items[0]).unwrap().report_id.ends_with("000000000003"));
        remove(&items[0]);
        assert_eq!(list(d.path()).len(), MAX_ITEMS - 1);
    }
}
