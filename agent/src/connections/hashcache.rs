//! exe 的 sha256 快取：以 (路徑, mtime, size) 為 key，避免每次快照重算所有行程的雜湊。

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::store;

pub const CACHE_FILE: &str = "state/exe-hash-cache.json";
const MAX_ENTRIES: usize = 4000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    mtime: u64,
    size: u64,
    sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HashCache {
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
    #[serde(skip)]
    dirty: bool,
}

impl HashCache {
    pub fn load(dir: &Path) -> Self {
        store::read_json_in(dir, CACHE_FILE).unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> crate::error::AppResult<()> {
        if !self.dirty {
            return Ok(());
        }
        let state_dir = dir.join("state");
        store::ensure_dir(&state_dir)?;
        store::write_json_compact_in(dir, CACHE_FILE, self)
    }

    /// 取檔案 sha256；讀不到（受保護 / 不存在）回 `None`。
    pub fn sha256(&mut self, path: &Path) -> Option<String> {
        const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = meta.len();
        if size > MAX_HASH_BYTES {
            return None;
        }
        let key = path.to_string_lossy().to_string();
        if let Some(e) = self.entries.get(&key) {
            if e.mtime == mtime && e.size == size {
                return Some(e.sha256.clone());
            }
        }
        let sha = crate::util::hash::sha256_file(path).ok()?;
        if self.entries.len() >= MAX_ENTRIES {
            // 粗略淘汰：清掉前半。
            let keys: Vec<String> = self.entries.keys().take(MAX_ENTRIES / 2).cloned().collect();
            for k in keys {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            key,
            Entry {
                mtime,
                size,
                sha256: sha.clone(),
            },
        );
        self.dirty = true;
        Some(sha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_by_mtime_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, b"hello").unwrap();
        let mut c = HashCache::load(dir.path());
        let h1 = c.sha256(&f).unwrap();
        assert_eq!(h1, crate::util::hash::sha256_hex(b"hello"));
        assert!(c.dirty);
        c.save(dir.path()).unwrap();
        let mut c2 = HashCache::load(dir.path());
        assert_eq!(c2.sha256(&f).unwrap(), h1);
        assert!(!c2.dirty);
        assert!(c2.sha256(&dir.path().join("missing")).is_none());
    }
}
