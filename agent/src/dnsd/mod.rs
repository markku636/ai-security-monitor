//! 防護 DNS 伺服器（`ai-security-monitor dns-server`，選用、預設不開）。
//!
//! UDP／TCP 53 → ACL（只服務區網）→ 每用戶端限速 → 封鎖比對（情資網域、自訂、Firefox canary）→
//! 快取（TinyLFU、只改 ID 與 TTL、serve-stale）→ in-flight 合併 → 上游 DoH（HTTP/2 複用）／UDP，兩家 hedged。
//! 封包處理自己寫（零拷貝，見 [`wire`]）；清單與設定用 arc-swap 無鎖替換；紀錄走有界 channel。
//! 啟動時先用轉送模式服務，封鎖清單在背景建好再換上（重啟只斷不到 1 秒）。

pub mod cache;
pub mod lists;
pub mod qlog;
pub mod server;
pub mod stats;
pub mod sys;
pub mod upstream;
pub mod wire;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use serde::Serialize;
use tokio::sync::{mpsc, Notify};

use crate::error::{AppError, AppResult};
use crate::store;
use cache::Cache;
use lists::{ListOpts, Lists};
use server::Shared;
use upstream::Pool;

pub const STATUS_FILE: &str = "dns-server/status.json";
const STATUS_EVERY: Duration = Duration::from_secs(30);
const RELOAD_EVERY: Duration = Duration::from_secs(600);

/// 預設只服務這些網段（避免變成網際網路上的開放解析器）。
pub fn default_acl() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<String>,
    pub feeds: Vec<String>,
    pub min_confidence: u8,
    pub custom_block: Vec<String>,
    pub custom_allow: Vec<String>,
    pub acl: Vec<IpNet>,
    /// 每個用戶端每秒最多幾題（0＝不限）。
    pub rrl_qps: u32,
    pub cache_entries: u64,
    pub blocking: bool,
    pub block_canary: bool,
    pub block_private_relay: bool,
    pub internal_suffixes: Vec<String>,
    pub log: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53),
            ],
            upstreams: Vec::new(),
            feeds: Vec::new(),
            min_confidence: lists::DEFAULT_MIN_CONFIDENCE,
            custom_block: Vec::new(),
            custom_allow: Vec::new(),
            acl: default_acl(),
            rrl_qps: 200,
            cache_entries: 200_000,
            blocking: true,
            block_canary: true,
            block_private_relay: false,
            internal_suffixes: Vec::new(),
            log: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    pub upstream: String,
    pub ewma_ms: f64,
    pub failures: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub running: bool,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub listen: Vec<String>,
    pub blocking: bool,
    pub lists_loaded: Vec<String>,
    pub lists_missing: Vec<String>,
    pub blocklist_entries: usize,
    pub lists_memory_bytes: usize,
    pub cache_entries: u64,
    pub upstreams: Vec<UpstreamStatus>,
    pub stats: stats::Snapshot,
}

fn opts(cfg: &Config) -> ListOpts<'_> {
    ListOpts {
        feeds: &cfg.feeds,
        min_confidence: cfg.min_confidence,
        custom_block: &cfg.custom_block,
        custom_allow: &cfg.custom_allow,
        block_canary: cfg.block_canary,
        block_private_relay: cfg.block_private_relay,
    }
}

/// 綁定監聽位址；`0.0.0.0:53` 被佔（Linux 的 systemd-resolved stub、Windows 的 ICS）時改成逐一綁各網卡位址。
async fn bind_all(
    listen: &[SocketAddr],
) -> AppResult<(Vec<(SocketAddr, std::net::UdpSocket)>, Vec<std::net::TcpListener>)> {
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    let mut errors = Vec::new();
    let per = sys::udp_sockets_per_addr();
    let mut targets: Vec<SocketAddr> = Vec::new();
    for a in listen {
        match sys::udp_socket(*a, per > 1) {
            Ok(s) => {
                udp.push((*a, s));
                for _ in 1..per {
                    if let Ok(s) = sys::udp_socket(*a, true) {
                        udp.push((*a, s));
                    }
                }
                targets.push(*a);
            }
            Err(e) if a.ip().is_unspecified() && e.kind() == std::io::ErrorKind::AddrInUse => {
                for ip in sys::interface_addrs()
                    .into_iter()
                    .filter(|ip| ip.is_ipv4() == a.is_ipv4())
                {
                    let sa = SocketAddr::new(ip, a.port());
                    match sys::udp_socket(sa, false) {
                        Ok(s) => {
                            udp.push((sa, s));
                            targets.push(sa);
                        }
                        Err(e) => errors.push(format!("{sa}: {e}")),
                    }
                }
            }
            Err(e) => errors.push(format!("{a}: {e}")),
        }
    }
    for a in &targets {
        match sys::tcp_listener(*a) {
            Ok(l) => tcp.push(l),
            Err(e) => errors.push(format!("tcp {a}: {e}")),
        }
    }
    if udp.is_empty() {
        return Err(AppError::Unsupported(tf!(
            "無法監聽 DNS port：{detail}",
            detail = errors.join("；")
        )));
    }
    Ok((udp, tcp))
}

fn write_status(
    config_dir: &Path,
    sh: &Shared,
    started: chrono::DateTime<chrono::Utc>,
    listen: &[String],
    running: bool,
) {
    let l = sh.lists.load();
    let st = Status {
        running,
        started_at: started,
        updated_at: chrono::Utc::now(),
        listen: listen.to_vec(),
        blocking: sh.blocking.load(std::sync::atomic::Ordering::Relaxed),
        lists_loaded: l.loaded.clone(),
        lists_missing: l.missing.clone(),
        blocklist_entries: l.entries,
        lists_memory_bytes: l.memory_bytes(),
        cache_entries: sh.cache.len(),
        upstreams: sh
            .pool
            .ups
            .iter()
            .map(|u| UpstreamStatus {
                upstream: u.label.clone(),
                ewma_ms: (u.ewma_ms() * 10.0).round() / 10.0,
                failures: u.failures(),
            })
            .collect(),
        stats: sh.stats.snapshot(),
    };
    let _ = store::ensure_dir(&config_dir.join("dns-server"));
    let _ = store::write_json_in(config_dir, STATUS_FILE, &st);
}

pub fn read_status(config_dir: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(config_dir.join(STATUS_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

/// 跑伺服器直到 `stop`。啟動時清單是空的（純轉送），背景建好封鎖清單後換上。
pub async fn run(cfg: Config, config_dir: PathBuf, stop: Arc<Notify>) -> AppResult<()> {
    let (udp, tcp) = bind_all(&cfg.listen).await?;
    let listen: Vec<String> = {
        let mut v: Vec<String> = udp.iter().map(|(a, _)| a.to_string()).collect();
        v.sort();
        v.dedup();
        v
    };
    let (log_tx, log_rx) = if cfg.log {
        let (tx, rx) = mpsc::channel(qlog::CHANNEL);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let sh = Arc::new(Shared::new(
        Lists::default(),
        Cache::new(cfg.cache_entries),
        Pool::new(&cfg.upstreams)?,
        cfg.acl.clone(),
        cfg.rrl_qps,
        cfg.blocking,
        cfg.internal_suffixes.clone(),
        log_tx,
    ));
    let started = chrono::Utc::now();
    let mut tasks = Vec::new();
    for (_, s) in udp {
        let sock = Arc::new(tokio::net::UdpSocket::from_std(s)?);
        for _ in 0..sys::tasks_per_socket() {
            tasks.push(tokio::spawn(server::udp_loop(sh.clone(), sock.clone(), stop.clone())));
        }
    }
    for l in tcp {
        let l = tokio::net::TcpListener::from_std(l)?;
        tasks.push(tokio::spawn(server::tcp_loop(sh.clone(), l, stop.clone())));
    }
    if let Some(rx) = log_rx {
        tasks.push(tokio::spawn(qlog::run(qlog::base_dir(&config_dir), rx, stop.clone())));
    }
    // 背景建封鎖清單（建好之前是純轉送）
    {
        let (sh, cfg, dir) = (sh.clone(), cfg.clone(), config_dir.clone());
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(RELOAD_EVERY);
            loop {
                tick.tick().await;
                let (c, d) = (cfg.clone(), dir.clone());
                if let Ok(l) = tokio::task::spawn_blocking(move || Lists::load(&d, &opts(&c))).await {
                    sh.lists.store(Arc::new(l));
                }
            }
        }));
    }
    write_status(&config_dir, &sh, started, &listen, true);
    let mut status = tokio::time::interval(STATUS_EVERY);
    loop {
        tokio::select! {
            _ = status.tick() => write_status(&config_dir, &sh, started, &listen, true),
            _ = stop.notified() => break,
        }
    }
    stop.notify_waiters();
    // 給紀錄一點時間把還在累積的分鐘寫進檔案
    tokio::time::sleep(Duration::from_millis(300)).await;
    for t in &tasks {
        t.abort();
    }
    write_status(&config_dir, &sh, started, &listen, false);
    Ok(())
}

/// `dns-server --healthcheck`：對本機的伺服器查健康檢查名稱（應 NOERROR）與測試封鎖網域（應 NXDOMAIN）。
pub async fn healthcheck(addr: SocketAddr) -> AppResult<()> {
    let target = if addr.ip().is_unspecified() {
        SocketAddr::new(
            if addr.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            },
            addr.port(),
        )
    } else {
        addr
    };
    let sock = tokio::net::UdpSocket::bind(if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    for (name, want) in [
        (server::HEALTH_NAME, wire::RCODE_NOERROR),
        (server::BLOCK_TEST_NAME, wire::RCODE_NXDOMAIN),
    ] {
        let mut q = vec![0x4a, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        sock.send_to(&q, target).await?;
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
            .await
            .map_err(|_| AppError::Timeout(3000))??;
        let rcode = buf.get(3).map(|b| b & 0xF).unwrap_or(0xF);
        if n < 12 || rcode != want {
            return Err(AppError::Unsupported(tf!(
                "健康檢查失敗：{name} 回 {rcode}",
                name = name,
                rcode = rcode
            )));
        }
    }
    Ok(())
}
