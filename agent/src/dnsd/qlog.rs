//! 防護 DNS 的查詢紀錄：每分鐘依（用戶端, 網域, 類型, 結果）聚合成 [`DnsRecord`]（source＝resolver、帶 client），
//! 寫進自己的目錄 `<設定目錄>/dns-server/dns/`，不跟這台電腦自己的 DNS 監看紀錄混在一起。

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use tokio::sync::{mpsc, Notify};

use crate::dns::heuristics;
use crate::dns::model::{rcode_name, DnsRecord, Source, MAX_ANSWERS};
use crate::dns::store;

pub const CHANNEL: usize = 16_384;
const FLUSH_EVERY: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub ts: DateTime<Utc>,
    pub client: IpAddr,
    pub name: String,
    pub qtype: u16,
    pub rcode: u8,
    pub answers: Vec<IpAddr>,
    /// 被哪個清單封鎖（沒封鎖是 None）。
    pub blocked: Option<String>,
}

/// 紀錄目錄（`<設定目錄>/dns-server`，裡面一樣是 `dns/YYYY-MM-DD.jsonl`）。
pub fn base_dir(config_dir: &std::path::Path) -> PathBuf {
    config_dir.join("dns-server")
}

#[derive(Default)]
pub struct Agg {
    buckets: HashMap<(DateTime<Utc>, IpAddr, String, u16, String), DnsRecord>,
}

impl Agg {
    pub fn push(&mut self, ev: LogEvent) {
        let minute = ev.ts.duration_trunc(TimeDelta::minutes(1)).unwrap_or(ev.ts);
        let rcode = if ev.blocked.is_some() {
            "BLOCKED".to_string()
        } else if ev.rcode == 0 && ev.answers.is_empty() {
            "NOERROR".to_string()
        } else {
            rcode_name(ev.rcode)
        };
        let key = (minute, ev.client, ev.name.clone(), ev.qtype, rcode.clone());
        let r = self.buckets.entry(key).or_insert_with(|| DnsRecord {
            ts: minute,
            registrable: heuristics::registrable_domain(&ev.name).map(str::to_string),
            name: ev.name.clone(),
            qtype: ev.qtype,
            rcode,
            process: ev.blocked.clone(),
            exe: None,
            pid: None,
            count: 0,
            answers: Vec::new(),
            cnames: Vec::new(),
            client: Some(ev.client.to_string()),
            source: Source::Resolver,
        });
        r.count = r.count.saturating_add(1);
        for ip in ev.answers {
            if r.answers.len() < MAX_ANSWERS && !r.answers.contains(&ip) {
                r.answers.push(ip);
            }
        }
    }

    pub fn take_finished(&mut self, now: DateTime<Utc>) -> Vec<DnsRecord> {
        let cur = now.duration_trunc(TimeDelta::minutes(1)).unwrap_or(now);
        let keys: Vec<_> = self.buckets.keys().filter(|k| k.0 < cur).cloned().collect();
        let mut out: Vec<DnsRecord> = keys.iter().filter_map(|k| self.buckets.remove(k)).collect();
        out.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.name.cmp(&b.name)));
        out
    }

    pub fn take_all(&mut self) -> Vec<DnsRecord> {
        let mut out: Vec<DnsRecord> = self.buckets.drain().map(|(_, v)| v).collect();
        out.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.name.cmp(&b.name)));
        out
    }
}

/// 接紀錄、每 15 秒把結束的分鐘寫檔、每小時清過期的日期檔。
pub async fn run(dir: PathBuf, mut rx: mpsc::Receiver<LogEvent>, stop: std::sync::Arc<Notify>) {
    let mut agg = Agg::default();
    let mut flush = tokio::time::interval(FLUSH_EVERY);
    let mut cleanup = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tokio::select! {
            Some(ev) = rx.recv() => agg.push(ev),
            _ = flush.tick() => {
                let recs = agg.take_finished(Utc::now());
                let d = dir.clone();
                let _ = tokio::task::spawn_blocking(move || store::append(&d, &recs)).await;
            }
            _ = cleanup.tick() => { store::cleanup(&dir, Utc::now()); }
            _ = stop.notified() => break,
        }
    }
    while let Ok(ev) = rx.try_recv() {
        agg.push(ev);
    }
    let _ = store::append(&dir, &agg.take_all());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_per_client_minute() {
        let mut a = Agg::default();
        let t = DateTime::from_timestamp(1_760_000_000, 0).unwrap();
        let ev = |client: &str, blocked: Option<&str>| LogEvent {
            ts: t,
            client: client.parse().unwrap(),
            name: "a.example.com".into(),
            qtype: 1,
            rcode: 0,
            answers: vec!["203.0.113.1".parse().unwrap()],
            blocked: blocked.map(str::to_string),
        };
        a.push(ev("192.168.1.2", None));
        a.push(ev("192.168.1.2", None));
        a.push(ev("192.168.1.3", None));
        a.push(ev("192.168.1.3", Some("CERT Polska")));
        let out = a.take_finished(t + TimeDelta::minutes(2));
        assert_eq!(out.len(), 3);
        let two = out.iter().find(|r| r.client.as_deref() == Some("192.168.1.2")).unwrap();
        assert_eq!(
            (two.count, two.source, two.registrable.as_deref()),
            (2, Source::Resolver, Some("example.com"))
        );
        let b = out.iter().find(|r| r.rcode == "BLOCKED").unwrap();
        assert_eq!(b.process.as_deref(), Some("CERT Polska"));
    }
}
