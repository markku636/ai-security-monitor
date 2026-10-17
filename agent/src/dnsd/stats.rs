//! 計數與延遲分布（全部 atomic，熱路徑不上鎖）。延遲用固定的對數區間，算 p50／p99 夠用。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

/// 延遲區間上界（微秒）：50µs … 5s。
const BUCKETS_US: [u64; 16] = [
    50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000, 2_000_000,
    5_000_000,
];

#[derive(Default)]
pub struct Histogram {
    counts: [AtomicU64; 17],
}

impl Histogram {
    pub fn record(&self, d: Duration) {
        let us = d.as_micros().min(u128::from(u64::MAX)) as u64;
        let i = BUCKETS_US.iter().position(|b| us <= *b).unwrap_or(BUCKETS_US.len());
        self.counts[i].fetch_add(1, Ordering::Relaxed);
    }

    /// 分位數（0–1）的上界，單位微秒；沒有資料回 None。
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        let counts: Vec<u64> = self.counts.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return None;
        }
        let target = ((total as f64) * q).ceil().max(1.0) as u64;
        let mut acc = 0;
        for (i, c) in counts.iter().enumerate() {
            acc += c;
            if acc >= target {
                return Some(BUCKETS_US.get(i).copied().unwrap_or(10_000_000));
            }
        }
        None
    }
}

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub stale: AtomicU64,
    pub coalesced: AtomicU64,
    pub prefetch: AtomicU64,
    pub refused: AtomicU64,
    pub ratelimited: AtomicU64,
    pub servfail: AtomicU64,
    pub formerr: AtomicU64,
    pub rebinding: AtomicU64,
    pub tcp: AtomicU64,
    pub dropped_logs: AtomicU64,
    pub hit_latency: Histogram,
    pub miss_latency: Histogram,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub queries: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub stale: u64,
    pub coalesced: u64,
    pub prefetch: u64,
    pub refused: u64,
    pub ratelimited: u64,
    pub servfail: u64,
    pub formerr: u64,
    pub rebinding: u64,
    pub tcp: u64,
    pub dropped_logs: u64,
    pub hit_p50_us: Option<u64>,
    pub hit_p99_us: Option<u64>,
    pub miss_p50_us: Option<u64>,
    pub miss_p99_us: Option<u64>,
}

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Snapshot {
            queries: g(&self.queries),
            blocked: g(&self.blocked),
            cache_hits: g(&self.cache_hits),
            cache_misses: g(&self.cache_misses),
            stale: g(&self.stale),
            coalesced: g(&self.coalesced),
            prefetch: g(&self.prefetch),
            refused: g(&self.refused),
            ratelimited: g(&self.ratelimited),
            servfail: g(&self.servfail),
            formerr: g(&self.formerr),
            rebinding: g(&self.rebinding),
            tcp: g(&self.tcp),
            dropped_logs: g(&self.dropped_logs),
            hit_p50_us: self.hit_latency.quantile_us(0.5),
            hit_p99_us: self.hit_latency.quantile_us(0.99),
            miss_p50_us: self.miss_latency.quantile_us(0.5),
            miss_p99_us: self.miss_latency.quantile_us(0.99),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_quantiles() {
        let h = Histogram::default();
        assert_eq!(h.quantile_us(0.5), None);
        for _ in 0..98 {
            h.record(Duration::from_micros(80));
        }
        h.record(Duration::from_millis(30));
        h.record(Duration::from_secs(10));
        assert_eq!(h.quantile_us(0.5), Some(100));
        assert_eq!(h.quantile_us(0.99), Some(50_000));
        assert_eq!(h.quantile_us(1.0), Some(10_000_000));
    }
}
