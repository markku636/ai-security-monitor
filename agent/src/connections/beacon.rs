//! beacon 偵測：同一個 (行程|遠端) 配對在歷史快照中反覆「出現→消失→再出現」，且間隔規律。
//! 持續存在的長連線不是 beacon；只看（重新）出現事件之間的間隔。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::history::Entry;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BeaconCandidate {
    /// `exe|ip:port`
    pub pair: String,
    pub period_s: f32,
    /// 變異係數（std / mean），越小越規律。
    pub jitter: f32,
    pub observations: u32,
}

pub const MIN_APPEARANCES: usize = 5;
pub const MIN_PERIOD_S: f32 = 10.0;
pub const MAX_JITTER: f32 = 0.3;
/// 週期至少要是快照間隔的幾倍才算量得到：間隔只有一兩個快照時，
/// 「規律」其實是取樣造成的（間隔永遠是快照間隔的整數倍），瀏覽器反覆開關 keep-alive 就會被誤判。
pub const MIN_PERIOD_SAMPLES: f32 = 3.0;

/// 快照間隔（相鄰快照時間差的中位數）。
fn sample_spacing(sorted: &[&Entry]) -> f32 {
    let mut d: Vec<u64> = sorted
        .windows(2)
        .map(|w| w[1].ts.saturating_sub(w[0].ts))
        .filter(|g| *g > 0)
        .collect();
    if d.is_empty() {
        return 0.0;
    }
    d.sort_unstable();
    d[d.len() / 2] as f32
}

pub fn detect(history: &[Entry], _now: u64) -> Vec<BeaconCandidate> {
    if history.len() < MIN_APPEARANCES + 1 {
        return Vec::new();
    }
    let mut sorted: Vec<&Entry> = history.iter().collect();
    sorted.sort_by_key(|e| e.ts);
    let min_period = MIN_PERIOD_S.max(sample_spacing(&sorted) * MIN_PERIOD_SAMPLES);

    // 每個配對的「出現事件」時間：前一個快照沒有、這個快照有。
    let mut appearances: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    let mut prev: Option<&Entry> = None;
    for e in &sorted {
        for p in &e.pairs {
            let was_present = prev.map(|pe| pe.pairs.iter().any(|x| x == p)).unwrap_or(false);
            if !was_present {
                appearances.entry(p.as_str()).or_default().push(e.ts);
            }
        }
        prev = Some(e);
    }

    let mut out = Vec::new();
    for (pair, times) in appearances {
        if times.len() < MIN_APPEARANCES {
            continue;
        }
        let gaps: Vec<f32> = times.windows(2).map(|w| (w[1] - w[0]) as f32).collect();
        let mean = gaps.iter().sum::<f32>() / gaps.len() as f32;
        if mean < min_period {
            continue;
        }
        let var = gaps.iter().map(|g| (g - mean) * (g - mean)).sum::<f32>() / gaps.len() as f32;
        let jitter = var.sqrt() / mean;
        if jitter <= MAX_JITTER {
            out.push(BeaconCandidate {
                pair: pair.to_string(),
                period_s: mean,
                jitter,
                observations: times.len() as u32,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, pairs: &[&str]) -> Entry {
        Entry {
            ts,
            pairs: pairs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn regular_reappearance_is_a_beacon() {
        // 快照每 30 秒一次；每 120 秒出現一次、下一個快照消失（週期是快照間隔的 4 倍）。
        let mut h = Vec::new();
        for i in 0..24u64 {
            let pairs: &[&str] = if i % 4 == 0 { &["mal.exe|5.5.5.5:443"] } else { &[] };
            h.push(entry(i * 30, pairs));
        }
        let b = detect(&h, 800);
        assert_eq!(b.len(), 1);
        assert!((b[0].period_s - 120.0).abs() < 1.0);
        assert_eq!(b[0].observations, 6);
    }

    #[test]
    fn period_of_one_or_two_snapshots_is_a_sampling_artifact() {
        // 每兩個快照出現一次（週期＝快照間隔的 2 倍）：分不出是 beacon 還是 keep-alive 反覆開關。
        let mut h = Vec::new();
        for i in 0..6u64 {
            h.push(entry(i * 120, &["chrome.exe|104.18.8.226:443"]));
            h.push(entry(i * 120 + 60, &[]));
        }
        assert!(detect(&h, 800).is_empty());
    }

    #[test]
    fn persistent_connection_is_not_a_beacon() {
        let h: Vec<Entry> = (0..12u64).map(|i| entry(i * 30, &["chrome|1.1.1.1:443"])).collect();
        assert!(detect(&h, 400).is_empty());
    }

    #[test]
    fn irregular_gaps_are_ignored() {
        let times = [0u64, 10, 200, 230, 900, 905];
        let mut h = Vec::new();
        for t in times {
            h.push(entry(t, &["x|9.9.9.9:80"]));
            h.push(entry(t + 2, &[]));
        }
        assert!(detect(&h, 1000).is_empty());
    }
}
