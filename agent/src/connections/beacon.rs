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

pub fn detect(history: &[Entry], _now: u64) -> Vec<BeaconCandidate> {
    if history.len() < MIN_APPEARANCES + 1 {
        return Vec::new();
    }
    let mut sorted: Vec<&Entry> = history.iter().collect();
    sorted.sort_by_key(|e| e.ts);

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
        if mean < MIN_PERIOD_S {
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
        // 每 60 秒出現一次、下一個快照消失。
        let mut h = Vec::new();
        for i in 0..6u64 {
            h.push(entry(i * 60, &["mal.exe|5.5.5.5:443"]));
            h.push(entry(i * 60 + 30, &[]));
        }
        let b = detect(&h, 400);
        assert_eq!(b.len(), 1);
        assert!((b[0].period_s - 60.0).abs() < 1.0);
        assert_eq!(b[0].observations, 6);
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
