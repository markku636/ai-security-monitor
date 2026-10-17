//! 本機保存（`<設定目錄>/dns/`）：
//! - `YYYY-MM-DD.jsonl`：每分鐘聚合的查詢（依 UTC 日期分檔，一行一列 [`DnsRecord`]），保留 [`KEEP_DAYS`] 天；
//! - `status.json`：背景蒐集的狀態（資料來源、事件數、最後一筆時間、錯誤），`dns status` 與桌面版讀。
//!
//! DNS 紀錄等於上網紀錄：系統服務寫在系統層設定目錄，只有系統管理員讀得到。

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use super::model::DnsRecord;
use crate::error::AppResult;
use crate::store;

pub const DIR: &str = "dns";
pub const STATUS_FILE: &str = "status.json";
pub const KEEP_DAYS: i64 = 7;

pub fn dir(config_dir: &Path) -> PathBuf {
    config_dir.join(DIR)
}

fn day_path(config_dir: &Path, day: NaiveDate) -> PathBuf {
    dir(config_dir).join(format!("{}.jsonl", day.format("%Y-%m-%d")))
}

/// 加到各自日期的檔案尾端。
pub fn append(config_dir: &Path, recs: &[DnsRecord]) -> AppResult<()> {
    if recs.is_empty() {
        return Ok(());
    }
    store::ensure_dir(&dir(config_dir))?;
    let mut i = 0;
    while i < recs.len() {
        let day = recs[i].ts.date_naive();
        let mut body = String::new();
        while i < recs.len() && recs[i].ts.date_naive() == day {
            body.push_str(&serde_json::to_string(&recs[i])?);
            body.push('\n');
            i += 1;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(day_path(config_dir, day))?;
        f.write_all(body.as_bytes())?;
    }
    Ok(())
}

/// 讀 `since` 之後的紀錄（舊到新）；最多 `limit` 列（超過時留最新的）。壞掉的行略過。
pub fn read_since(config_dir: &Path, since: DateTime<Utc>, limit: usize) -> Vec<DnsRecord> {
    let today = Utc::now().date_naive();
    let mut day = since.date_naive();
    let mut out = Vec::new();
    while day <= today {
        if let Ok(text) = std::fs::read_to_string(day_path(config_dir, day)) {
            out.extend(
                text.lines()
                    .filter_map(|l| serde_json::from_str::<DnsRecord>(l).ok())
                    .filter(|r| r.ts >= since),
            );
        }
        match day.succ_opt() {
            Some(d) => day = d,
            None => break,
        }
    }
    out.sort_by_key(|a| a.ts);
    if out.len() > limit {
        out.drain(..out.len() - limit);
    }
    out
}

/// 刪掉超過保留天數的日期檔。
pub fn cleanup(config_dir: &Path, now: DateTime<Utc>) -> usize {
    let cutoff = now.date_naive() - chrono::Days::new(KEEP_DAYS as u64);
    let Ok(rd) = std::fs::read_dir(dir(config_dir)) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(stem) = name.strip_suffix(".jsonl") else {
            continue;
        };
        if let Ok(d) = NaiveDate::parse_from_str(stem, "%Y-%m-%d") {
            if d < cutoff && std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// 紀錄實際所在的設定目錄：背景服務以系統服務執行時寫在系統層目錄。
/// `explicit`（明確指定了設定目錄）時只看 `config_dir`；否則兩邊誰的 `status.json` 比較新就用誰。
/// 第二個值：系統層紀錄存在但讀不到（不是系統管理員）。
pub fn pick_dir(config_dir: &Path, explicit: bool) -> (PathBuf, bool) {
    if explicit {
        return (config_dir.to_path_buf(), false);
    }
    let sys = crate::service::effective_system_config_dir(crate::service::Os::current());
    if sys == config_dir {
        return (sys, false);
    }
    let mine = read_status(config_dir).and_then(|s| s.updated_at);
    let theirs = read_status(&sys).and_then(|s| s.updated_at);
    let unreadable = dir(&sys).exists() && std::fs::read_dir(dir(&sys)).is_err();
    match (mine, theirs) {
        (_, Some(t)) if mine.is_none_or(|m| t > m) => (sys, unreadable),
        _ => (config_dir.to_path_buf(), unreadable),
    }
}

/// 背景蒐集的狀態。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsStatus {
    /// 正在用的資料來源（`etw`、`cache`…）；沒有可用來源時 None。
    pub source: Option<String>,
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub events: u64,
    pub deduped: u64,
    /// 來不及處理而丟掉的事件（不會擋住 DNS，只是少記）。
    pub dropped: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<DateTime<Utc>>,
    /// 有 PID（知道是哪個程式查的）。
    pub has_process: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

pub fn write_status(config_dir: &Path, s: &DnsStatus) -> AppResult<()> {
    store::ensure_dir(&dir(config_dir))?;
    store::write_json_in(config_dir, &format!("{DIR}/{STATUS_FILE}"), s)
}

pub fn read_status(config_dir: &Path) -> Option<DnsStatus> {
    let text = std::fs::read_to_string(dir(config_dir).join(STATUS_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::super::model::Source;
    use super::*;

    fn rec(ts: DateTime<Utc>, name: &str) -> DnsRecord {
        DnsRecord {
            ts,
            name: name.into(),
            registrable: None,
            qtype: 1,
            rcode: "NOERROR".into(),
            process: Some("app.exe".into()),
            exe: None,
            pid: Some(1),
            count: 1,
            answers: vec![],
            cnames: vec![],
            client: None,
            source: Source::Etw,
        }
    }

    #[test]
    fn append_read_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let y = now - chrono::Duration::days(1);
        let old = now - chrono::Duration::days(KEEP_DAYS + 2);
        append(
            dir.path(),
            &[rec(old, "old.example"), rec(y, "y.example"), rec(now, "n.example")],
        )
        .unwrap();
        // 壞掉的行不影響其他行
        let today = day_path(dir.path(), now.date_naive());
        let mut f = std::fs::OpenOptions::new().append(true).open(&today).unwrap();
        f.write_all(b"{not json\n").unwrap();
        let got = read_since(dir.path(), now - chrono::Duration::days(2), 100);
        assert_eq!(
            got.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["y.example", "n.example"]
        );
        assert_eq!(
            read_since(dir.path(), now - chrono::Duration::days(2), 1)[0].name,
            "n.example"
        );
        assert_eq!(cleanup(dir.path(), now), 1);
        assert!(read_since(dir.path(), old - chrono::Duration::hours(1), 100)
            .iter()
            .all(|r| r.name != "old.example"));

        let s = DnsStatus {
            source: Some("etw".into()),
            running: true,
            events: 3,
            ..Default::default()
        };
        write_status(dir.path(), &s).unwrap();
        assert_eq!(read_status(dir.path()), Some(s));
    }
}
