//! 防護 DNS 壓測：同一個行程裡起 dns-server（上游是自己的假 DNS，量到的是伺服器本身）＋多個用戶端 socket。
//!
//! ```text
//! cargo run --release --example dnsbench -- [--seconds 10] [--clients 64] [--entries 2000000] [--json]
//! ```
//!
//! 量：快取命中＋封鎖混合查詢的 QPS 與延遲分位數、未命中（送上游）延遲、封鎖清單比對時間（200 萬筆）、
//! 清單重建時間、行程常駐記憶體。`--json` 輸出給 CI 寫進 job summary。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use asa_lib::dnsd::{self, Config};
use asa_lib::intel::domainset::{self, DomainSet};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

const CACHED: usize = 5_000;
const BLOCKED: usize = 1_000;

fn arg<T: std::str::FromStr>(name: &str, default: T) -> T {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut q = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// 假上游：每題回一筆 A 192.0.2.1（TTL 300）。
async fn fake_upstream() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if n < 12 {
                continue;
            }
            // 問題區段結尾
            let mut i = 12;
            while i < n && buf[i] != 0 {
                i += 1 + buf[i] as usize;
            }
            let qend = (i + 5).min(n);
            let mut r = Vec::with_capacity(qend + 16);
            r.extend_from_slice(&buf[0..2]);
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(&buf[12..qend]);
            r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 192, 0, 2, 1]);
            let _ = sock.send_to(&r, from).await;
        }
    });
    addr
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn percentile(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[i] as f64
}

/// 一個用戶端：一次一題（等到回答再送下一題），記每題延遲（微秒）。
async fn client(
    server: SocketAddr,
    packets: Arc<Vec<Vec<u8>>>,
    start: usize,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
) -> Vec<u32> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(server).await.unwrap();
    let mut lat = Vec::with_capacity(200_000);
    let mut buf = [0u8; 1500];
    let mut i = start;
    while !stop.load(Ordering::Relaxed) {
        let p = &packets[i % packets.len()];
        i = i.wrapping_add(7);
        let t = Instant::now();
        if sock.send(p).await.is_err() {
            continue;
        }
        match tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
            Ok(Ok(_)) => {
                lat.push(t.elapsed().as_micros().min(u32::MAX as u128) as u32);
                done.fetch_add(1, Ordering::Relaxed);
            }
            _ => continue,
        }
    }
    lat
}

fn rss_mb() -> f64 {
    let pid = sysinfo::get_current_pid().unwrap();
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    sys.process(pid).map(|p| p.memory() as f64 / 1_048_576.0).unwrap_or(0.0)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let seconds: u64 = arg("--seconds", 10);
    let clients: usize = arg("--clients", 64);
    let entries: usize = arg("--entries", 2_000_000);
    let json = std::env::args().any(|a| a == "--json");

    // 1) 封鎖清單：建 N 筆、比對時間（命中與沒命中各半，含逐層往上查）
    let t = Instant::now();
    let set = DomainSet::build(
        (0..entries)
            .map(|i| (domainset::hash(&format!("bad{i}.example-threat.test")), 0))
            .collect(),
    );
    let rebuild_ms = t.elapsed().as_secs_f64() * 1000.0;
    let names: Vec<String> = (0..200_000)
        .map(|i| {
            if i % 2 == 0 {
                format!("www.bad{}.example-threat.test", i * 7 % entries.max(1))
            } else {
                format!("cdn{i}.static.example.org")
            }
        })
        .collect();
    let t = Instant::now();
    let mut hits = 0usize;
    for n in &names {
        hits += set.lookup(n, true).is_some() as usize;
    }
    let lookup_ns = t.elapsed().as_nanos() as f64 / names.len() as f64;
    let list_mb = set.heap_bytes() as f64 / 1_048_576.0;
    assert!(hits >= names.len() / 2, "lookup sanity");
    drop(set);

    // 2) 起伺服器（上游＝假 DNS；不限速、不記錄）
    let up = fake_upstream().await;
    let port = free_port();
    let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        listen: vec![listen],
        upstreams: vec![up.to_string()],
        custom_block: (0..BLOCKED).map(|i| format!("blocked{i}.example.net")).collect(),
        rrl_qps: 0,
        log: false,
        update_feeds: false,
        ..Config::default()
    };
    let stop = Arc::new(Notify::new());
    let (s2, d2) = (stop.clone(), dir.path().to_path_buf());
    let server = tokio::spawn(async move { dnsd::run(cfg, d2, s2, None).await });
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 暖快取＋量未命中延遲（每個名稱第一次都要問上游）
    let cached: Vec<Vec<u8>> = (0..CACHED)
        .map(|i| query(i as u16, &format!("host{i}.bench.example.com")))
        .collect();
    let warm = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    warm.connect(listen).await.unwrap();
    let mut miss_lat = Vec::with_capacity(CACHED);
    let mut buf = [0u8; 1500];
    for p in &cached {
        let t = Instant::now();
        warm.send(p).await.unwrap();
        if tokio::time::timeout(Duration::from_secs(2), warm.recv(&mut buf))
            .await
            .is_ok()
        {
            miss_lat.push(t.elapsed().as_micros() as u32);
        }
    }
    miss_lat.sort_unstable();

    // 3) 混合負載：90% 快取命中、10% 封鎖
    let mut packets = Vec::with_capacity(CACHED + BLOCKED);
    for (i, p) in cached.iter().enumerate() {
        packets.push(p.clone());
        if i % 9 == 0 {
            let b = i / 9 % BLOCKED;
            packets.push(query(b as u16, &format!("blocked{b}.example.net")));
        }
    }
    let packets = Arc::new(packets);
    let halt = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let t = Instant::now();
    let tasks: Vec<_> = (0..clients)
        .map(|c| tokio::spawn(client(listen, packets.clone(), c * 131, halt.clone(), done.clone())))
        .collect();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    halt.store(true, Ordering::Relaxed);
    let mut lat = Vec::new();
    for t in tasks {
        lat.extend(t.await.unwrap());
    }
    let elapsed = t.elapsed().as_secs_f64();
    lat.sort_unstable();
    let qps = lat.len() as f64 / elapsed;
    let rss = rss_mb();
    stop.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(3), server).await;

    let out = serde_json::json!({
        "clients": clients,
        "seconds": seconds,
        "cpus": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "queries": lat.len(),
        "qps": qps.round(),
        "hit_p50_us": percentile(&lat, 0.50),
        "hit_p99_us": percentile(&lat, 0.99),
        "hit_p999_us": percentile(&lat, 0.999),
        "miss_p50_us": percentile(&miss_lat, 0.50),
        "miss_p99_us": percentile(&miss_lat, 0.99),
        "blocklist_entries": entries,
        "blocklist_mb": (list_mb * 10.0).round() / 10.0,
        "block_lookup_ns": lookup_ns.round(),
        "rebuild_ms": rebuild_ms.round(),
        "rss_mb": rss.round(),
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("dnsbench ({} clients, {} s, {} CPUs)", clients, seconds, out["cpus"]);
        println!(
            "  cache hit + block mix: {:.0} QPS, p50 {} µs, p99 {} µs, p99.9 {} µs",
            qps, out["hit_p50_us"], out["hit_p99_us"], out["hit_p999_us"]
        );
        println!(
            "  cache miss (fake upstream): p50 {} µs, p99 {} µs",
            out["miss_p50_us"], out["miss_p99_us"]
        );
        println!(
            "  blocklist: {} entries, {} MB, lookup {} ns, rebuild {} ms",
            entries, out["blocklist_mb"], out["block_lookup_ns"], out["rebuild_ms"]
        );
        println!("  process RSS: {} MB", out["rss_mb"]);
    }
}
