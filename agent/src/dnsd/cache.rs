//! 回應快取：存上游回應的原始封包＋分析結果（TTL 位置），命中時只改 ID 與 TTL（[`super::wire::rewrite_cached`]）。
//! moka（並行 TinyLFU）；項目在 TTL 過後再留 [`STALE_FOR`]，上游全掛時拿來頂著（serve-stale，RFC 8767）。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache as Moka;
use moka::Expiry;

use super::wire::RespInfo;

/// TTL 過後還保留多久給 serve-stale。
pub const STALE_FOR: Duration = Duration::from_secs(86_400);
/// 正答案 TTL 上下限、負快取（NXDOMAIN／NODATA）上限。
pub const MIN_TTL: u32 = 5;
pub const MAX_TTL: u32 = 86_400;
pub const MAX_NEG_TTL: u32 = 3_600;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub do_bit: bool,
}

#[derive(Debug)]
pub struct Entry {
    pub bytes: Vec<u8>,
    pub info: RespInfo,
    pub stored: Instant,
    /// 這筆可以當「新鮮」用多久（秒）。
    pub ttl: u32,
    pub hits: AtomicU32,
}

impl Entry {
    pub fn new(bytes: Vec<u8>, info: RespInfo) -> Entry {
        let negative = info.ancount == 0;
        let ttl = if negative {
            info.cache_ttl.clamp(MIN_TTL, MAX_NEG_TTL)
        } else {
            info.cache_ttl.clamp(MIN_TTL, MAX_TTL)
        };
        Entry {
            bytes,
            info,
            stored: Instant::now(),
            ttl,
            hits: AtomicU32::new(0),
        }
    }

    pub fn age(&self) -> u32 {
        self.stored.elapsed().as_secs().min(u64::from(u32::MAX)) as u32
    }

    pub fn fresh(&self) -> bool {
        self.age() < self.ttl
    }

    /// 剩下不到一成壽命、而且常被問：該在背景先刷新了。
    pub fn wants_prefetch(&self) -> bool {
        let hits = self.hits.fetch_add(1, Ordering::Relaxed) + 1;
        let left = self.ttl.saturating_sub(self.age());
        hits >= 3 && self.ttl >= 30 && left * 10 < self.ttl
    }
}

struct ExpireAfterTtl;

impl Expiry<Key, Arc<Entry>> for ExpireAfterTtl {
    fn expire_after_create(&self, _k: &Key, v: &Arc<Entry>, _now: Instant) -> Option<Duration> {
        Some(Duration::from_secs(u64::from(v.ttl)) + STALE_FOR)
    }
}

/// 只有成功與查無此網域的回應會進快取（SERVFAIL、截斷的不存）。
pub fn cacheable(info: &RespInfo) -> bool {
    !info.tc && matches!(info.rcode, super::wire::RCODE_NOERROR | super::wire::RCODE_NXDOMAIN)
}

pub struct Cache {
    inner: Moka<Key, Arc<Entry>>,
}

impl Cache {
    pub fn new(max_entries: u64) -> Cache {
        Cache {
            inner: Moka::builder()
                .max_capacity(max_entries.max(1_000))
                .expire_after(ExpireAfterTtl)
                .build(),
        }
    }

    pub fn get(&self, k: &Key) -> Option<Arc<Entry>> {
        self.inner.get(k)
    }

    pub fn insert(&self, k: Key, e: Arc<Entry>) {
        self.inner.insert(k, e);
    }

    pub fn len(&self) -> u64 {
        self.inner.entry_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsd::wire::{
        analyze_response, parse_query,
        tests::{query_edns, response_a},
    };

    #[test]
    fn entries_clamp_ttl_and_cache_roundtrip() {
        let q = parse_query(&query_edns(1, "example.com", 1)).unwrap();
        let info = analyze_response(&response_a(0, "example.com", [1, 2, 3, 4], 2), &q).unwrap();
        let e = Entry::new(vec![1, 2, 3], info.clone());
        assert_eq!(e.ttl, MIN_TTL);
        assert!(e.fresh());
        assert!(cacheable(&info));
        let c = Cache::new(10);
        let k = Key {
            name: "example.com".into(),
            qtype: 1,
            qclass: 1,
            do_bit: true,
        };
        c.insert(k.clone(), Arc::new(e));
        assert!(c.get(&k).is_some());
        let other = Key { do_bit: false, ..k };
        assert!(c.get(&other).is_none());
    }
}
