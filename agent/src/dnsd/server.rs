//! 處理流程。熱路徑（拒絕、封鎖、快取命中）在接收迴圈裡同步完成、不開新 task；只有要問上游的才 spawn。
//!
//! ```text
//! recv → ACL → 每用戶端限速（UDP）→ 解析 → ANY／本機測試名稱 → 封鎖比對 → 快取（新鮮）→ 回應
//!                                                                   └ 沒有／過期 → in-flight 合併 → 上游 → 寫快取 → 回應
//!                                                                                                └ 上游失敗 → serve-stale／SERVFAIL
//! ```
//! 回應前檢查 DNS rebinding（公網名稱回私有位址就擋）。紀錄丟進有界 channel，滿了只計數，絕不擋住解析。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};

use super::cache::{cacheable, Cache, Entry, Key};
use super::lists::{Decision, Lists};
use super::qlog::LogEvent;
use super::stats::Stats;
use super::upstream::Pool;
use super::wire::{self, Query, WireError};
use crate::util::net::{classify, IpClass};

/// 本機測試名稱：健康檢查（回 NOERROR，不問上游）與一定被封鎖的測試網域。
pub const HEALTH_NAME: &str = "healthcheck.asm-dns.invalid";
pub const BLOCK_TEST_NAME: &str = "blocked-test.asm-dns.invalid";
const TCP_IDLE: Duration = Duration::from_secs(10);
/// serve-stale 回應的 TTL（RFC 8767 建議 30 秒）。
const STALE_TTL: u32 = 30;

pub struct Shared {
    pub lists: ArcSwap<Lists>,
    pub cache: Cache,
    pub pool: Pool,
    pub stats: Stats,
    pub acl: Vec<IpNet>,
    pub rrl_qps: u32,
    pub blocking: AtomicBool,
    pub internal_suffixes: Vec<String>,
    pub log: Option<mpsc::Sender<LogEvent>>,
    inflight: Mutex<HashMap<Key, Vec<Waiter>>>,
}

/// 等同一題上游結果的請求。
type Waiter = oneshot::Sender<Option<Arc<Entry>>>;

impl Shared {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lists: Lists,
        cache: Cache,
        pool: Pool,
        acl: Vec<IpNet>,
        rrl_qps: u32,
        blocking: bool,
        internal_suffixes: Vec<String>,
        log: Option<mpsc::Sender<LogEvent>>,
    ) -> Shared {
        Shared {
            lists: ArcSwap::from_pointee(lists),
            cache,
            pool,
            stats: Stats::default(),
            acl,
            rrl_qps,
            blocking: AtomicBool::new(blocking),
            internal_suffixes,
            log,
            inflight: Mutex::new(HashMap::new()),
        }
    }
}

/// 每個用戶端的 token bucket（每個接收 task 一份，不必上鎖）。
pub struct Rrl {
    qps: f64,
    burst: f64,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl Rrl {
    pub fn new(qps: u32) -> Rrl {
        Rrl {
            qps: f64::from(qps),
            burst: f64::from(qps) * 2.0,
            buckets: HashMap::new(),
        }
    }

    pub fn allow(&mut self, ip: IpAddr) -> bool {
        if self.qps <= 0.0 {
            return true;
        }
        let now = Instant::now();
        if self.buckets.len() > 50_000 {
            self.buckets
                .retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let (tokens, last) = self.buckets.entry(ip).or_insert((self.burst, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.qps).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub enum Step {
    Reply(Vec<u8>),
    /// 回應並在背景先刷新快取。
    ReplyPrefetch(Vec<u8>, Query),
    Upstream(Query, Option<Arc<Entry>>),
    Drop,
}

fn allowed(acl: &[IpNet], ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    acl.iter().any(|n| n.contains(&ip))
}

fn key_of(q: &Query) -> Key {
    Key {
        name: q.name.clone(),
        qtype: q.qtype,
        qclass: q.qclass,
        do_bit: q.do_bit(),
    }
}

/// 公網名稱卻回了私有位址（DNS rebinding）。內部網域、單段名稱不算。
pub fn is_rebinding(sh: &Shared, name: &str, answers: &[IpAddr]) -> bool {
    if answers.is_empty() || !name.contains('.') || name == "localhost" || name.ends_with(".localhost") {
        return false;
    }
    let internal = [
        ".lan",
        ".local",
        ".home.arpa",
        ".internal",
        ".localdomain",
        ".corp",
        ".intranet",
    ];
    if internal.iter().any(|s| name.ends_with(s))
        || sh
            .internal_suffixes
            .iter()
            .any(|s| name == s.trim_start_matches('.') || name.ends_with(&format!(".{}", s.trim_start_matches('.'))))
    {
        return false;
    }
    answers.iter().any(|ip| {
        matches!(
            classify(*ip),
            IpClass::Private | IpClass::Loopback | IpClass::LinkLocal | IpClass::Unspecified
        )
    })
}

fn log(sh: &Shared, client: IpAddr, q: &Query, rcode: u8, answers: &[IpAddr], blocked: Option<String>) {
    let Some(tx) = &sh.log else {
        return;
    };
    let ev = LogEvent {
        ts: chrono::Utc::now(),
        client,
        name: q.name.clone(),
        qtype: q.qtype,
        rcode,
        answers: answers.iter().take(8).copied().collect(),
        blocked,
    };
    if tx.try_send(ev).is_err() {
        Stats::inc(&sh.stats.dropped_logs);
    }
}

/// 熱路徑：不 await。`rrl` 只給 UDP；`max_len` 是回應大小上限。
pub fn handle_fast(sh: &Shared, raw: &[u8], src: IpAddr, rrl: Option<&mut Rrl>, max_len: Option<usize>) -> Step {
    let t0 = Instant::now();
    Stats::inc(&sh.stats.queries);
    if let Some(r) = rrl {
        if !r.allow(src) {
            Stats::inc(&sh.stats.ratelimited);
            return Step::Drop;
        }
    }
    let q = match wire::parse_query(raw) {
        Ok(q) => q,
        Err(WireError::Short) | Err(WireError::NotQuery) => return Step::Drop,
        Err(WireError::BadOpcode) => {
            return wire::build_header_error(raw, wire::RCODE_NOTIMP)
                .map(Step::Reply)
                .unwrap_or(Step::Drop)
        }
        Err(_) => {
            Stats::inc(&sh.stats.formerr);
            return wire::build_header_error(raw, wire::RCODE_FORMERR)
                .map(Step::Reply)
                .unwrap_or(Step::Drop);
        }
    };
    let max_len = max_len.unwrap_or_else(|| q.max_udp());
    if !allowed(&sh.acl, src) {
        Stats::inc(&sh.stats.refused);
        return Step::Reply(wire::build_empty(raw, &q, wire::RCODE_REFUSED, None, false));
    }
    if q.qclass != 1 {
        Stats::inc(&sh.stats.refused);
        return Step::Reply(wire::build_empty(raw, &q, wire::RCODE_REFUSED, None, false));
    }
    if q.qtype == wire::TYPE_ANY {
        return Step::Reply(wire::build_any(raw, &q));
    }
    if q.name == HEALTH_NAME {
        return Step::Reply(wire::build_empty(raw, &q, wire::RCODE_NOERROR, None, false));
    }
    let blocking = sh.blocking.load(Ordering::Relaxed);
    let decision = if q.name == BLOCK_TEST_NAME {
        Decision::Block(t!("測試網域").to_string())
    } else if blocking {
        sh.lists.load().decide(&q.name)
    } else {
        Decision::Pass
    };
    if let Decision::Block(src_list) = decision {
        Stats::inc(&sh.stats.blocked);
        let text = format!("blocked by ai-security-monitor: {src_list}");
        log(sh, src, &q, wire::RCODE_NXDOMAIN, &[], Some(src_list));
        return Step::Reply(wire::build_empty(
            raw,
            &q,
            wire::RCODE_NXDOMAIN,
            Some((wire::EDE_BLOCKED, &text)),
            false,
        ));
    }
    let key = key_of(&q);
    if let Some(e) = sh.cache.get(&key) {
        if e.fresh() {
            Stats::inc(&sh.stats.cache_hits);
            if blocking && is_rebinding(sh, &q.name, &e.info.answers) {
                Stats::inc(&sh.stats.rebinding);
                log(sh, src, &q, wire::RCODE_NXDOMAIN, &[], Some("dns rebinding".into()));
                return Step::Reply(wire::build_empty(
                    raw,
                    &q,
                    wire::RCODE_NXDOMAIN,
                    Some((wire::EDE_BLOCKED, "dns rebinding")),
                    false,
                ));
            }
            let out = wire::rewrite_cached(&e.bytes, &e.info, raw, &q, e.age(), 1, max_len);
            log(sh, src, &q, e.info.rcode, &e.info.answers, None);
            sh.stats.hit_latency.record(t0.elapsed());
            if e.wants_prefetch() {
                return Step::ReplyPrefetch(out, q);
            }
            return Step::Reply(out);
        }
        Stats::inc(&sh.stats.cache_misses);
        return Step::Upstream(q, Some(e));
    }
    Stats::inc(&sh.stats.cache_misses);
    Step::Upstream(q, None)
}

/// 問上游（同一題同時多人問只送一次）；成功寫快取。回 None＝上游失敗。
pub async fn fetch(sh: &Arc<Shared>, raw: &[u8], q: &Query) -> Option<Arc<Entry>> {
    let key = key_of(q);
    let rx = {
        let mut m = sh.inflight.lock().ok()?;
        match m.get_mut(&key) {
            Some(waiters) => {
                let (tx, rx) = oneshot::channel();
                waiters.push(tx);
                Some(rx)
            }
            None => {
                m.insert(key.clone(), Vec::new());
                None
            }
        }
    };
    if let Some(rx) = rx {
        Stats::inc(&sh.stats.coalesced);
        return rx.await.ok().flatten();
    }
    let result = match sh.pool.query(raw, q).await {
        Ok(bytes) => wire::analyze_response(&bytes, q).map(|info| Arc::new(Entry::new(bytes, info))),
        Err(_) => None,
    };
    if let Some(e) = &result {
        if cacheable(&e.info) {
            sh.cache.insert(key.clone(), e.clone());
        }
    }
    let waiters = sh
        .inflight
        .lock()
        .ok()
        .and_then(|mut m| m.remove(&key))
        .unwrap_or_default();
    for w in waiters {
        let _ = w.send(result.clone());
    }
    result
}

/// 慢路徑：問上游後組回應；上游失敗時用過期的快取頂著（serve-stale）或回 SERVFAIL。
pub async fn handle_slow(
    sh: &Arc<Shared>,
    raw: &[u8],
    q: &Query,
    stale: Option<Arc<Entry>>,
    src: IpAddr,
    max_len: usize,
) -> Vec<u8> {
    let t0 = Instant::now();
    let out = match fetch(sh, raw, q).await {
        Some(e) => {
            if sh.blocking.load(Ordering::Relaxed) && is_rebinding(sh, &q.name, &e.info.answers) {
                Stats::inc(&sh.stats.rebinding);
                log(sh, src, q, wire::RCODE_NXDOMAIN, &[], Some("dns rebinding".into()));
                return wire::build_empty(
                    raw,
                    q,
                    wire::RCODE_NXDOMAIN,
                    Some((wire::EDE_BLOCKED, "dns rebinding")),
                    false,
                );
            }
            log(sh, src, q, e.info.rcode, &e.info.answers, None);
            wire::rewrite_cached(&e.bytes, &e.info, raw, q, 0, 1, max_len)
        }
        None => match stale {
            Some(e) => {
                Stats::inc(&sh.stats.stale);
                log(sh, src, q, e.info.rcode, &e.info.answers, None);
                wire::rewrite_cached(&e.bytes, &e.info, raw, q, e.age(), STALE_TTL, max_len)
            }
            None => {
                Stats::inc(&sh.stats.servfail);
                log(sh, src, q, wire::RCODE_SERVFAIL, &[], None);
                wire::build_empty(raw, q, wire::RCODE_SERVFAIL, None, false)
            }
        },
    };
    sh.stats.miss_latency.record(t0.elapsed());
    out
}

/// UDP 接收迴圈。
pub async fn udp_loop(sh: Arc<Shared>, sock: Arc<UdpSocket>, stop: Arc<Notify>) {
    let mut buf = vec![0u8; 4096];
    let mut rrl = Rrl::new(sh.rrl_qps);
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r {
                Ok(v) => v,
                // Windows 的 ICMP 不可達等暫時錯誤：繼續收
                Err(_) => continue,
            },
            _ = stop.notified() => return,
        };
        let raw = &buf[..n];
        match handle_fast(&sh, raw, from.ip(), Some(&mut rrl), None) {
            Step::Reply(v) => {
                let _ = sock.send_to(&v, from).await;
            }
            Step::ReplyPrefetch(v, q) => {
                let _ = sock.send_to(&v, from).await;
                Stats::inc(&sh.stats.prefetch);
                let (sh2, raw2) = (sh.clone(), raw.to_vec());
                tokio::spawn(async move {
                    let _ = fetch(&sh2, &raw2, &q).await;
                });
            }
            Step::Upstream(q, stale) => {
                let (sh2, sock2, raw2) = (sh.clone(), sock.clone(), raw.to_vec());
                tokio::spawn(async move {
                    let max = q.max_udp();
                    let v = handle_slow(&sh2, &raw2, &q, stale, from.ip(), max).await;
                    let _ = sock2.send_to(&v, from).await;
                });
            }
            Step::Drop => {}
        }
    }
}

async fn tcp_conn(sh: Arc<Shared>, mut s: TcpStream, src: IpAddr) {
    Stats::inc(&sh.stats.tcp);
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let mut raw = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if tokio::time::timeout(TCP_IDLE, s.read_exact(&mut raw))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_none()
        {
            return;
        }
        let out = match handle_fast(&sh, &raw, src, None, Some(65_535)) {
            Step::Reply(v) | Step::ReplyPrefetch(v, _) => v,
            Step::Upstream(q, stale) => handle_slow(&sh, &raw, &q, stale, src, 65_535).await,
            Step::Drop => return,
        };
        if s.write_all(&(out.len() as u16).to_be_bytes()).await.is_err() || s.write_all(&out).await.is_err() {
            return;
        }
    }
}

pub async fn tcp_loop(sh: Arc<Shared>, l: TcpListener, stop: Arc<Notify>) {
    loop {
        let (s, from) = tokio::select! {
            r = l.accept() => match r {
                Ok(v) => v,
                Err(_) => continue,
            },
            _ = stop.notified() => return,
        };
        tokio::spawn(tcp_conn(sh.clone(), s, from.ip()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsd::wire::tests::{query_edns, response_a};
    use crate::traffic::proto::parse_dns;

    fn shared(pool: Pool) -> Arc<Shared> {
        Arc::new(Shared::new(
            Lists::default(),
            Cache::new(1000),
            pool,
            super::super::default_acl(),
            0,
            true,
            vec!["corp.example".into()],
            None,
        ))
    }

    #[test]
    fn rrl_and_acl() {
        let mut r = Rrl::new(2);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        assert!(r.allow(ip) && r.allow(ip) && r.allow(ip) && r.allow(ip));
        assert!(!r.allow(ip));
        let acl = super::super::default_acl();
        assert!(allowed(&acl, "192.168.1.5".parse().unwrap()));
        assert!(allowed(&acl, "::ffff:10.0.0.1".parse().unwrap()));
        assert!(!allowed(&acl, "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn fast_path_refuses_blocks_and_answers_local_names() {
        let sh = shared(Pool::new(&["192.0.2.1".into()]).unwrap());
        let lan: IpAddr = "192.168.1.10".parse().unwrap();
        let raw = query_edns(5, BLOCK_TEST_NAME, 1);
        let Step::Reply(v) = handle_fast(&sh, &raw, lan, None, None) else {
            panic!("reply")
        };
        assert_eq!(parse_dns(&v).unwrap().rcode, wire::RCODE_NXDOMAIN);
        let Step::Reply(v) = handle_fast(&sh, &query_edns(6, HEALTH_NAME, 1), lan, None, None) else {
            panic!()
        };
        assert_eq!(parse_dns(&v).unwrap().rcode, wire::RCODE_NOERROR);
        let Step::Reply(v) = handle_fast(
            &sh,
            &query_edns(7, "example.com", 1),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        ) else {
            panic!()
        };
        assert_eq!(parse_dns(&v).unwrap().rcode, wire::RCODE_REFUSED);
        assert!(matches!(
            handle_fast(&sh, &query_edns(8, "example.com", 1), lan, None, None),
            Step::Upstream(_, None)
        ));
        assert_eq!(sh.stats.snapshot().blocked, 1);
    }

    #[test]
    fn rebinding_rules() {
        let sh = shared(Pool::new(&["192.0.2.1".into()]).unwrap());
        let private: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let public: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        assert!(is_rebinding(&sh, "evil.example", &private));
        assert!(!is_rebinding(&sh, "evil.example", &public));
        assert!(!is_rebinding(&sh, "nas.lan", &private));
        assert!(!is_rebinding(&sh, "git.corp.example", &private));
        assert!(!is_rebinding(&sh, "printer", &private));
    }

    /// 本機假上游＋實際的 UDP 迴圈：未命中→上游、第二次命中快取、上游掛掉後 serve-stale 的路徑由 fetch 測。
    #[tokio::test]
    async fn end_to_end_udp_with_cache() {
        let up = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let h2 = hits.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = up.recv_from(&mut buf).await else {
                    return;
                };
                h2.fetch_add(1, Ordering::Relaxed);
                let q = wire::parse_query(&buf[..n]).unwrap();
                let mut r = response_a(q.id, &q.name, [93, 184, 216, 34], 300);
                r[0..2].copy_from_slice(&q.id.to_be_bytes());
                let _ = up.send_to(&r, from).await;
            }
        });
        let sh = shared(Pool::new(&[up_addr.to_string()]).unwrap());
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stop = Arc::new(Notify::new());
        tokio::spawn(udp_loop(sh.clone(), sock, stop.clone()));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 2048];
        for id in [11u16, 12] {
            client.send_to(&query_edns(id, "example.com", 1), addr).await.unwrap();
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let m = parse_dns(&buf[..n]).unwrap();
            assert_eq!(m.id, id);
            assert_eq!(m.answers.len(), 1);
        }
        assert_eq!(hits.load(Ordering::Relaxed), 1, "second answer from cache");
        let s = sh.stats.snapshot();
        assert_eq!((s.cache_hits, s.cache_misses), (1, 1));
        stop.notify_waiters();
    }
}
