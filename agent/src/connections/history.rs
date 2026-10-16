//! 連線歷史（`<config>/state/connections.jsonl`）：每次快照記下「行程|遠端」配對，保留 24 小時，供 beacon 偵測。

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::model::connection::{Connection, Direction};
use crate::store;

pub const HISTORY_FILE: &str = "state/connections.jsonl";
pub const RETENTION_SECS: u64 = 24 * 3600;
const MAX_LINES: usize = 20_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub ts: u64,
    pub pairs: Vec<String>,
}

/// 對外、公網的 (exe|ip:port) 配對。
pub fn pairs_of(conns: &[Connection]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for c in conns {
        if c.direction != Direction::Outbound {
            continue;
        }
        let (Some(ip), Some(port)) = (c.remote_ip, c.remote_port) else {
            continue;
        };
        if !crate::util::net::classify(ip).is_public() {
            continue;
        }
        let exe = c
            .process
            .as_ref()
            .map(|p| p.exe.clone().unwrap_or_else(|| p.name.clone()))
            .unwrap_or_default();
        set.insert(format!("{exe}|{ip}:{port}"));
    }
    set.into_iter().collect()
}

pub fn append(dir: &Path, ts: u64, pairs: &[String]) -> AppResult<()> {
    let path = dir.join(HISTORY_FILE);
    store::ensure_dir(path.parent().unwrap_or(dir))?;
    let mut entries = load(dir, ts.saturating_sub(RETENTION_SECS))?;
    entries.push(Entry {
        ts,
        pairs: pairs.to_vec(),
    });
    if entries.len() > MAX_LINES {
        let drop = entries.len() - MAX_LINES;
        entries.drain(..drop);
    }
    let mut buf = Vec::new();
    for e in &entries {
        serde_json::to_writer(&mut buf, e)?;
        buf.push(b'\n');
    }
    let mut f = std::fs::File::create(&path)?;
    f.write_all(&buf)?;
    Ok(())
}

/// 讀取 `since` 之後的紀錄（檔案不存在回空）。
pub fn load(dir: &Path, since: u64) -> AppResult<Vec<Entry>> {
    let path = dir.join(HISTORY_FILE);
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(e) = serde_json::from_str::<Entry>(&line) {
            if e.ts >= since {
                out.push(e);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_prunes_old_entries() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), 1_000, &["a|1.1.1.1:443".into()]).unwrap();
        append(dir.path(), 1_000 + RETENTION_SECS + 10, &["b|2.2.2.2:80".into()]).unwrap();
        let all = load(dir.path(), 0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].pairs, vec!["b|2.2.2.2:80".to_string()]);
    }
}
