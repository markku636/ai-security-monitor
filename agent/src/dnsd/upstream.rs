//! 上游：DoH（HTTP/2 連線複用，RFC 8484 POST）或明文 UDP（截斷時改 TCP）。
//! 依延遲 EWMA 挑最快的健康上游；送出後 [`HEDGE_AFTER`] 還沒回就同時問第二快的，誰先回用誰（hedged request）。
//! DoH 主機名用內建的 bootstrap 位址連線，不經過系統 DNS（這台的 DNS 可能就指向自己）。

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::wire::{analyze_response, build_upstream_query, Query};
use crate::error::{AppError, AppResult};

pub const TIMEOUT: Duration = Duration::from_millis(2_500);
pub const HEDGE_AFTER: Duration = Duration::from_millis(250);

/// 常見 DoH 主機的 bootstrap 位址。
const BOOTSTRAP: [(&str, [&str; 2]); 4] = [
    ("dns.quad9.net", ["9.9.9.9", "149.112.112.112"]),
    ("cloudflare-dns.com", ["1.1.1.1", "1.0.0.1"]),
    ("dns.google", ["8.8.8.8", "8.8.4.4"]),
    ("dns.adguard-dns.com", ["94.140.14.14", "94.140.15.15"]),
];

pub const DEFAULT_UPSTREAMS: [&str; 2] = [
    "https://dns.quad9.net/dns-query",
    "https://cloudflare-dns.com/dns-query",
];

enum Kind {
    Doh { url: String, client: reqwest::Client },
    Udp { addr: SocketAddr },
}

pub struct Upstream {
    pub label: String,
    kind: Kind,
    /// 延遲 EWMA（微秒）。
    ewma_us: AtomicU64,
    fails: AtomicU32,
}

impl Upstream {
    /// `https://…` → DoH；IP 或 IP:port → 明文 UDP。
    pub fn parse(spec: &str) -> AppResult<Upstream> {
        let spec = spec.trim();
        if let Some(rest) = spec.strip_prefix("https://") {
            let host = rest.split(['/', ':']).next().unwrap_or("");
            let mut b = reqwest::Client::builder()
                .use_rustls_tls()
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(4)
                .connect_timeout(Duration::from_secs(3))
                .timeout(TIMEOUT)
                .user_agent(format!("ai-security-monitor-dns/{}", crate::VERSION));
            if host.parse::<IpAddr>().is_err() {
                if let Some((_, ips)) = BOOTSTRAP.iter().find(|(h, _)| *h == host) {
                    for ip in ips {
                        if let Ok(ip) = ip.parse::<IpAddr>() {
                            b = b.resolve(host, SocketAddr::new(ip, 443));
                        }
                    }
                }
            }
            let client = b.build().map_err(|e| AppError::InvalidArg(e.to_string()))?;
            return Ok(Upstream {
                label: spec.to_string(),
                kind: Kind::Doh {
                    url: spec.to_string(),
                    client,
                },
                ewma_us: AtomicU64::new(50_000),
                fails: AtomicU32::new(0),
            });
        }
        let addr: SocketAddr = spec
            .parse()
            .or_else(|_| spec.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            .map_err(|_| AppError::InvalidArg(tf!("不是合法的上游 DNS：{value}", value = spec)))?;
        Ok(Upstream {
            label: addr.to_string(),
            kind: Kind::Udp { addr },
            ewma_us: AtomicU64::new(50_000),
            fails: AtomicU32::new(0),
        })
    }

    /// 挑選用的分數（越小越好）：延遲＋連續失敗的懲罰。
    fn score(&self) -> u64 {
        self.ewma_us.load(Ordering::Relaxed) + u64::from(self.fails.load(Ordering::Relaxed).min(20)) * 500_000
    }

    fn observe(&self, ok: bool, took: Duration) {
        if ok {
            let us = took.as_micros().min(10_000_000) as u64;
            let old = self.ewma_us.load(Ordering::Relaxed);
            self.ewma_us.store((old * 7 + us) / 8, Ordering::Relaxed);
            self.fails.store(0, Ordering::Relaxed);
        } else {
            self.fails.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn ewma_ms(&self) -> f64 {
        self.ewma_us.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn failures(&self) -> u32 {
        self.fails.load(Ordering::Relaxed)
    }

    async fn exchange(&self, raw: &[u8], q: &Query) -> AppResult<Vec<u8>> {
        let t0 = Instant::now();
        let r = match &self.kind {
            Kind::Doh { url, client } => doh(client, url, raw, q).await,
            Kind::Udp { addr } => udp(*addr, raw, q).await,
        };
        self.observe(r.is_ok(), t0.elapsed());
        r
    }
}

async fn doh(client: &reqwest::Client, url: &str, raw: &[u8], q: &Query) -> AppResult<Vec<u8>> {
    let body = build_upstream_query(raw, q, 0);
    let resp = client
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(body)
        .send()
        .await
        .map_err(|e| AppError::Unsupported(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AppError::Unsupported(format!("HTTP {}", resp.status().as_u16())));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::Unsupported(e.to_string()))?
        .to_vec();
    analyze_response(&bytes, q).ok_or_else(|| AppError::Parse("bad DoH answer".into()))?;
    Ok(bytes)
}

fn random_id() -> u16 {
    let b = uuid::Uuid::new_v4().into_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

async fn udp(addr: SocketAddr, raw: &[u8], q: &Query) -> AppResult<Vec<u8>> {
    let id = random_id();
    let msg = build_upstream_query(raw, q, id);
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("valid")
    } else {
        "0.0.0.0:0".parse().expect("valid")
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(&msg).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .map_err(|_| AppError::Timeout(TIMEOUT.as_millis() as u64))??;
        let b = &buf[..n];
        // 只收 ID 與問題都對得上的回應（防偽造）
        if n >= 2 && u16::from_be_bytes([b[0], b[1]]) == id {
            if let Some(info) = analyze_response(b, q) {
                if info.tc {
                    return tcp(addr, raw, q).await;
                }
                return Ok(b.to_vec());
            }
        }
    }
}

async fn tcp(addr: SocketAddr, raw: &[u8], q: &Query) -> AppResult<Vec<u8>> {
    let id = random_id();
    let msg = build_upstream_query(raw, q, id);
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await?;
        s.write_all(&(msg.len() as u16).to_be_bytes()).await?;
        s.write_all(&msg).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let mut b = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut b).await?;
        Ok::<_, std::io::Error>(b)
    };
    let b = tokio::time::timeout(TIMEOUT, fut)
        .await
        .map_err(|_| AppError::Timeout(TIMEOUT.as_millis() as u64))??;
    if b.len() >= 2 && u16::from_be_bytes([b[0], b[1]]) == id && analyze_response(&b, q).is_some() {
        Ok(b)
    } else {
        Err(AppError::Parse("bad TCP answer".into()))
    }
}

pub struct Pool {
    pub ups: Vec<Arc<Upstream>>,
}

impl Pool {
    pub fn new(specs: &[String]) -> AppResult<Pool> {
        let list: Vec<String> = if specs.is_empty() {
            DEFAULT_UPSTREAMS.iter().map(|s| s.to_string()).collect()
        } else {
            specs.to_vec()
        };
        let ups = list
            .iter()
            .map(|s| Upstream::parse(s).map(Arc::new))
            .collect::<AppResult<Vec<_>>>()?;
        Ok(Pool { ups })
    }

    /// 依分數排出最好的兩個。
    fn best_two(&self) -> (Arc<Upstream>, Option<Arc<Upstream>>) {
        let mut v: Vec<&Arc<Upstream>> = self.ups.iter().collect();
        v.sort_by_key(|u| u.score());
        (v[0].clone(), v.get(1).map(|u| (*u).clone()))
    }

    /// 問上游：最快的那家；超過 [`HEDGE_AFTER`] 還沒回（或失敗）就同時問第二家，誰先成功用誰。
    pub async fn query(&self, raw: &[u8], q: &Query) -> AppResult<Vec<u8>> {
        let (a, b) = self.best_two();
        let Some(b) = b else {
            return a.exchange(raw, q).await;
        };
        let fa = a.exchange(raw, q);
        tokio::pin!(fa);
        tokio::select! {
            r = &mut fa => match r {
                Ok(v) => return Ok(v),
                Err(_) => return b.exchange(raw, q).await,
            },
            _ = tokio::time::sleep(HEDGE_AFTER) => {}
        }
        let fb = b.exchange(raw, q);
        tokio::pin!(fb);
        let mut a_done = false;
        let mut b_done = false;
        loop {
            tokio::select! {
                r = &mut fa, if !a_done => match r {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        a_done = true;
                        if b_done {
                            return Err(e);
                        }
                    }
                },
                r = &mut fb, if !b_done => match r {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        b_done = true;
                        if a_done {
                            return Err(e);
                        }
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert!(matches!(Upstream::parse("9.9.9.9").unwrap().kind, Kind::Udp { addr } if addr.port() == 53));
        assert!(
            matches!(Upstream::parse("[2620:fe::fe]:5353").unwrap().kind, Kind::Udp { addr } if addr.port() == 5353)
        );
        assert!(matches!(
            Upstream::parse("https://dns.quad9.net/dns-query").unwrap().kind,
            Kind::Doh { .. }
        ));
        assert!(Upstream::parse("not a server").is_err());
        assert_eq!(Pool::new(&[]).unwrap().ups.len(), 2);
    }

    #[test]
    fn scoring_prefers_fast_healthy() {
        let p = Pool::new(&["192.0.2.1".into(), "192.0.2.2".into()]).unwrap();
        p.ups[0].observe(false, Duration::ZERO);
        p.ups[1].observe(true, Duration::from_millis(5));
        let (a, b) = p.best_two();
        assert_eq!(a.label, "192.0.2.2:53");
        assert_eq!(b.unwrap().label, "192.0.2.1:53");
    }

    /// 本機假上游：收到查詢就回一筆 A。
    async fn fake_upstream(delay: Duration) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let q = crate::dnsd::wire::parse_query(&buf[..n]).unwrap();
                tokio::time::sleep(delay).await;
                let mut r = crate::dnsd::wire::tests::response_a(q.id, &q.name, [203, 0, 113, 7], 120);
                r[0..2].copy_from_slice(&q.id.to_be_bytes());
                let _ = sock.send_to(&r, from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_exchange_and_hedging() {
        let slow = fake_upstream(Duration::from_millis(900)).await;
        let fast = fake_upstream(Duration::ZERO).await;
        let p = Pool::new(&[slow.to_string(), fast.to_string()]).unwrap();
        // 讓慢的那家看起來比較快，確認 hedge 會接手
        p.ups[0].ewma_us.store(1, Ordering::Relaxed);
        let raw = crate::traffic::proto::build::dns_query(9, "example.com", 1);
        let q = crate::dnsd::wire::parse_query(&raw).unwrap();
        let t0 = Instant::now();
        let r = p.query(&raw, &q).await.unwrap();
        assert!(t0.elapsed() < Duration::from_millis(800), "{:?}", t0.elapsed());
        let info = analyze_response(&r, &q).unwrap();
        assert_eq!(info.answers, vec!["203.0.113.7".parse::<IpAddr>().unwrap()]);
    }
}
