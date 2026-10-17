//! 事件聚合：同一程式 1 秒內重複的同一題只算一次；每分鐘、每個（名稱, 類型, 結果, 程式）合成一列 [`DnsRecord`]；
//! 順便維護「IP → 網域」對照（連線表補網域名稱用）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, DurationRound, TimeDelta, Utc};

use super::model::{DnsEvent, DnsRecord, MAX_ANSWERS, MAX_CNAMES};
use super::procname::ProcNames;

/// 同一（程式, 名稱, 類型）在這段時間內重複出現只算一次。
const DEDUP_WINDOW: TimeDelta = TimeDelta::seconds(1);
/// IP → 網域對照最多幾筆。
pub const IP_MAP_MAX: usize = 20_000;
/// 對照保留多久：至少 10 分鐘（連線常比 DNS TTL 活得久）、最多 1 小時。
const IP_MAP_MIN: Duration = Duration::from_secs(600);
const IP_MAP_MAX_TTL: Duration = Duration::from_secs(3600);

/// IP → 最近一次解析到它的網域。
#[derive(Debug, Default)]
pub struct IpDomainMap {
    map: HashMap<IpAddr, (String, Instant)>,
}

impl IpDomainMap {
    pub fn insert(&mut self, ip: IpAddr, name: &str, ttl: Option<u32>) {
        let keep = ttl
            .map(|t| Duration::from_secs(u64::from(t)))
            .unwrap_or(IP_MAP_MAX_TTL)
            .clamp(IP_MAP_MIN, IP_MAP_MAX_TTL);
        let now = Instant::now();
        if self.map.len() >= IP_MAP_MAX && !self.map.contains_key(&ip) {
            self.map.retain(|_, (_, exp)| *exp > now);
            if self.map.len() >= IP_MAP_MAX {
                self.map.clear();
            }
        }
        self.map.insert(ip, (name.to_string(), now + keep));
    }

    pub fn get(&self, ip: &IpAddr) -> Option<&str> {
        self.map
            .get(ip)
            .filter(|(_, exp)| *exp > Instant::now())
            .map(|(n, _)| n.as_str())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// 背景蒐集與連線快照共用的對照。
pub type SharedIpMap = Arc<RwLock<IpDomainMap>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    minute: DateTime<Utc>,
    name: String,
    qtype: u16,
    rcode: String,
    process: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct AggStats {
    pub events: u64,
    pub deduped: u64,
}

pub struct Aggregator {
    procs: ProcNames,
    recent: HashMap<(Option<u32>, String, u16), DateTime<Utc>>,
    buckets: HashMap<Key, DnsRecord>,
    pub ip_map: SharedIpMap,
    pub stats: AggStats,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

fn minute_of(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.duration_trunc(TimeDelta::minutes(1)).unwrap_or(ts)
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            procs: ProcNames::new(),
            recent: HashMap::new(),
            buckets: HashMap::new(),
            ip_map: SharedIpMap::default(),
            stats: AggStats::default(),
        }
    }

    pub fn push(&mut self, ev: DnsEvent) {
        self.stats.events += 1;
        if !ev.answers.is_empty() {
            if let Ok(mut m) = self.ip_map.write() {
                for ip in &ev.answers {
                    m.insert(*ip, &ev.name, ev.ttl);
                }
            }
        }
        let dk = (ev.pid, ev.name.clone(), ev.qtype);
        if let Some(prev) = self.recent.get(&dk) {
            if ev.ts - *prev < DEDUP_WINDOW && ev.ts >= *prev {
                self.stats.deduped += 1;
                return;
            }
        }
        self.recent.insert(dk, ev.ts);
        if self.recent.len() > 8192 {
            let cutoff = ev.ts - DEDUP_WINDOW;
            self.recent.retain(|_, t| *t >= cutoff);
        }
        let proc = ev.pid.and_then(|p| self.procs.get(p));
        let key = Key {
            minute: minute_of(ev.ts),
            name: ev.name.clone(),
            qtype: ev.qtype,
            rcode: ev.rcode.clone(),
            process: proc.as_ref().map(|p| p.name.clone()),
        };
        let rec = self.buckets.entry(key.clone()).or_insert_with(|| DnsRecord {
            ts: key.minute,
            name: key.name.clone(),
            qtype: key.qtype,
            rcode: key.rcode.clone(),
            process: key.process.clone(),
            exe: proc.as_ref().and_then(|p| p.exe.clone()),
            pid: ev.pid,
            count: 0,
            answers: Vec::new(),
            cnames: Vec::new(),
            source: ev.source,
        });
        rec.count = rec.count.saturating_add(1);
        rec.pid = ev.pid.or(rec.pid);
        for ip in ev.answers {
            if rec.answers.len() < MAX_ANSWERS && !rec.answers.contains(&ip) {
                rec.answers.push(ip);
            }
        }
        for c in ev.cnames {
            if rec.cnames.len() < MAX_CNAMES && !rec.cnames.contains(&c) {
                rec.cnames.push(c);
            }
        }
    }

    /// 取出已經結束的分鐘（早於 `now` 所在那一分鐘），依時間排序。
    pub fn take_finished(&mut self, now: DateTime<Utc>) -> Vec<DnsRecord> {
        let cur = minute_of(now);
        let done: Vec<Key> = self.buckets.keys().filter(|k| k.minute < cur).cloned().collect();
        let mut out: Vec<DnsRecord> = done.iter().filter_map(|k| self.buckets.remove(k)).collect();
        out.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.name.cmp(&b.name)));
        out
    }

    /// 全部取出（結束時）。
    pub fn take_all(&mut self) -> Vec<DnsRecord> {
        let mut out: Vec<DnsRecord> = self.buckets.drain().map(|(_, v)| v).collect();
        out.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.name.cmp(&b.name)));
        out
    }

    pub fn pending(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::Source;
    use super::*;

    fn ev(sec: i64, name: &str, pid: Option<u32>, ip: &str) -> DnsEvent {
        DnsEvent {
            ts: DateTime::from_timestamp(1_760_000_000 + sec, 0).unwrap(),
            name: name.into(),
            qtype: 1,
            rcode: "NOERROR".into(),
            answers: vec![ip.parse().unwrap()],
            cnames: vec![],
            ttl: Some(60),
            pid,
            source: Source::Etw,
        }
    }

    #[test]
    fn dedups_and_buckets_per_minute() {
        let mut a = Aggregator::new();
        let me = Some(std::process::id());
        // 1_760_000_000 是 xx:13:20 → 同一分鐘內
        a.push(ev(0, "a.example", me, "192.0.2.1"));
        a.push(ev(0, "a.example", me, "192.0.2.1")); // 同秒重複：去掉
        a.push(ev(5, "a.example", me, "192.0.2.2"));
        a.push(ev(6, "b.example", None, "192.0.2.3"));
        a.push(ev(50, "a.example", me, "192.0.2.1")); // 下一分鐘
        assert_eq!(a.stats.deduped, 1);
        let now = DateTime::from_timestamp(1_760_000_000 + 45, 0).unwrap();
        let done = a.take_finished(now);
        assert_eq!(done.len(), 2);
        let ra = done.iter().find(|r| r.name == "a.example").unwrap();
        assert_eq!(ra.count, 2);
        assert_eq!(ra.answers.len(), 2);
        assert!(ra.process.is_some());
        let rb = done.iter().find(|r| r.name == "b.example").unwrap();
        assert!(rb.process.is_none());
        assert_eq!(a.pending(), 1);
        assert_eq!(a.take_all().len(), 1);
        let m = a.ip_map.read().unwrap();
        assert_eq!(m.get(&"192.0.2.3".parse().unwrap()), Some("b.example"));
        assert!(m.get(&"198.51.100.1".parse().unwrap()).is_none());
    }

    #[test]
    fn ip_map_is_bounded() {
        let mut m = IpDomainMap::default();
        for i in 0..(IP_MAP_MAX as u32 + 10) {
            m.insert(IpAddr::V4(i.into()), "x.example", None);
        }
        assert!(m.len() <= IP_MAP_MAX);
    }
}
