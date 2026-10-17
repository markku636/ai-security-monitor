//! 上傳 Hub 的待送佇列（`<設定目錄>/dns/queue.jsonl`，一行一列 [`DnsRecord`]）。
//! 背景蒐集每次落地時，`dns.upload = all` 且有加入 Hub 才排進來；watch 每分鐘分批送出。
//! Hub 暫時連不上時累積（最多 [`MAX_QUEUE`] 列，丟最舊的）；Hub 太舊（404）就留著、升級後補送。

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};

use super::model::{DnsRecord, Source};
use crate::error::{AppError, AppResult};
use crate::store;

pub const QUEUE_FILE: &str = "queue.jsonl";
/// 待送上限（約一天份的一般用量）。
pub const MAX_QUEUE: usize = 50_000;
/// 一批幾列。
pub const BATCH: usize = 500;
/// 每次最多送幾批。
pub const BATCHES_PER_TICK: usize = 4;

/// 上傳到 Hub 的一批（`POST /api/v1/ingest/dns`，`contract/dns.v1.json`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsBatch {
    pub agent_id: String,
    pub records: Vec<DnsRecord>,
}

fn path(config_dir: &Path) -> PathBuf {
    super::store::dir(config_dir).join(QUEUE_FILE)
}

fn read_lines(config_dir: &Path) -> Vec<String> {
    std::fs::read_to_string(path(config_dir))
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

fn rewrite(config_dir: &Path, lines: &[String]) -> AppResult<()> {
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    store::ensure_dir(&super::store::dir(config_dir))?;
    store::write_bytes_atomic(&path(config_dir), body.as_bytes())
}

/// 排進佇列；超過上限丟最舊的。
pub fn push(config_dir: &Path, recs: &[DnsRecord]) -> AppResult<()> {
    if recs.is_empty() {
        return Ok(());
    }
    store::ensure_dir(&super::store::dir(config_dir))?;
    let mut body = String::new();
    for r in recs {
        body.push_str(&serde_json::to_string(r)?);
        body.push('\n');
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path(config_dir))?
        .write_all(body.as_bytes())?;
    // 一列至少百來個 bytes：檔案還小就不用數
    let size = std::fs::metadata(path(config_dir)).map(|m| m.len()).unwrap_or(0);
    if size > (MAX_QUEUE as u64) * 100 {
        let lines = read_lines(config_dir);
        if lines.len() > MAX_QUEUE {
            rewrite(config_dir, &lines[lines.len() - MAX_QUEUE..])?;
        }
    }
    Ok(())
}

/// 最舊的 `n` 列（壞行略過）與總列數。
pub fn peek(config_dir: &Path, n: usize) -> (Vec<DnsRecord>, usize) {
    let lines = read_lines(config_dir);
    let total = lines.len();
    let items = lines
        .iter()
        .take(n)
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    (items, total)
}

pub fn drop_first(config_dir: &Path, n: usize) -> AppResult<()> {
    let lines = read_lines(config_dir);
    rewrite(config_dir, &lines[n.min(lines.len())..])
}

pub fn len(config_dir: &Path) -> usize {
    read_lines(config_dir).len()
}

/// 背景蒐集要不要把紀錄排進佇列：有加入 Hub、且 `dns.upload = all`。
pub fn wants_upload(config_dir: &Path) -> bool {
    crate::config::load(config_dir)
        .map(|c| c.hub.is_some() && c.dns.upload == crate::config::DnsUpload::All)
        .unwrap_or(false)
}

pub enum Flush {
    Sent {
        sent: usize,
        left: usize,
    },
    /// Hub 沒有這個端點（舊版）。
    Unsupported,
    Failed(String),
}

/// 分批送出（最多 [`BATCHES_PER_TICK`] 批）。被拒收（400／413／422）的那批丟掉。
pub async fn flush(config_dir: &Path, client: &crate::hub::HubClient, agent_id: &str) -> Flush {
    flush_with(config_dir, |records| async move {
        client
            .upload_dns(&DnsBatch {
                agent_id: agent_id.to_string(),
                records,
            })
            .await
    })
    .await
}

/// 同 [`flush`]，送出的方式由呼叫端決定（防護 DNS 的紀錄送另一個端點）；`Ok(None)`＝Hub 沒有這個端點。
pub async fn flush_with<F, Fut>(config_dir: &Path, mut send: F) -> Flush
where
    F: FnMut(Vec<DnsRecord>) -> Fut,
    Fut: std::future::Future<Output = AppResult<Option<serde_json::Value>>>,
{
    let mut sent = 0usize;
    for _ in 0..BATCHES_PER_TICK {
        let (records, total) = peek(config_dir, BATCH);
        if total == 0 {
            return Flush::Sent { sent, left: 0 };
        }
        let lines = BATCH.min(total);
        if records.is_empty() {
            let _ = drop_first(config_dir, lines);
            continue;
        }
        let n = records.len();
        match send(records).await {
            Ok(Some(_)) => {
                let _ = drop_first(config_dir, lines);
                sent += n;
            }
            Ok(None) => return Flush::Unsupported,
            Err(AppError::HubRejected(m)) => {
                let _ = drop_first(config_dir, lines);
                return Flush::Failed(m);
            }
            Err(e) => return Flush::Failed(e.message()),
        }
    }
    Flush::Sent {
        sent,
        left: len(config_dir),
    }
}

/// 契約範例（`contract/dns.v1.json`）。
#[doc(hidden)]
pub fn sample_batch() -> DnsBatch {
    let at = |m: u32| Utc.with_ymd_and_hms(2026, 10, 17, 9, m, 0).unwrap();
    DnsBatch {
        agent_id: "0f8e5a52-1c3b-4b8e-9d7a-2b1f00c0ffee".into(),
        records: vec![
            DnsRecord {
                ts: at(30),
                name: "updates.example.net".into(),
                registrable: Some("example.net".into()),
                qtype: 1,
                rcode: "NOERROR".into(),
                process: Some("updater.exe".into()),
                exe: Some(r"C:\Program Files\Updater\updater.exe".into()),
                pid: Some(4120),
                count: 3,
                answers: vec!["203.0.113.66".parse().unwrap()],
                cnames: vec!["edge.example.net".into()],
                client: None,
                source: Source::Etw,
            },
            DnsRecord {
                ts: at(31),
                name: "kqfcpqbyqllgbr.example".into(),
                registrable: Some("kqfcpqbyqllgbr.example".into()),
                qtype: 1,
                rcode: "NXDOMAIN".into(),
                process: None,
                exe: None,
                pid: None,
                count: 1,
                answers: vec![],
                cnames: vec![],
                client: None,
                source: Source::Packet,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_peek_drop_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let b = sample_batch();
        push(dir.path(), &b.records).unwrap();
        push(dir.path(), &b.records[..1]).unwrap();
        let (items, total) = peek(dir.path(), 2);
        assert_eq!((items.len(), total), (2, 3));
        assert_eq!(items[0], b.records[0]);
        drop_first(dir.path(), 2).unwrap();
        assert_eq!(len(dir.path()), 1);
        assert!(!wants_upload(dir.path()));
    }
}
