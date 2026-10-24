//! 主迴圈：認領 → 沒工作就睡 `poll_after_ms`（加一點抖動）→ 每個工作跑完送結果（[`exec::execute`]）。
//! - 401／403：權杖錯，結束並回錯。
//! - 404：Hub 太舊（沒有網站掃描端點），印一次，5 分鐘後再試。
//! - 429：照 Retry-After 等。
//! - 連不上：指數退避重試。
//! - 停止（Ctrl+C／服務停止）：通知所有工作（殺掉工具、回報 `runner_stopped`），最多等 30 秒。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::exec::{self, Ctx, Finished, Outcome};
use super::{log, Claim, ClaimResponse};
use crate::error::{AppError, AppResult};
use crate::util::net::{classify, IpClass};

/// 等待時間的設定（測試會縮短）。
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Hub 太舊時多久再試。
    pub unsupported_wait: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    /// 429 最少／最多等多久。
    pub throttle_min: Duration,
    pub throttle_max: Duration,
    /// Hub 沒給 `poll_after_ms` 時的認領間隔，以及夾的範圍。
    pub poll_default: Duration,
    pub poll_min: Duration,
    pub poll_max: Duration,
    /// 停止時等工作收尾最多多久。
    pub drain: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            unsupported_wait: Duration::from_secs(300),
            backoff_min: Duration::from_secs(5),
            backoff_max: Duration::from_secs(300),
            throttle_min: Duration::from_secs(1),
            throttle_max: Duration::from_secs(3600),
            poll_default: Duration::from_secs(15),
            poll_min: Duration::from_secs(1),
            poll_max: Duration::from_secs(300),
            drain: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// 同時最多跑幾個工作（1–4）。
    pub max_jobs: usize,
    /// 認領一次、跑完就結束。
    pub once: bool,
    pub timing: Timing,
}

/// `--once` 認領失敗最多重試幾次。
const ONCE_ATTEMPTS: u32 = 5;

/// 一次認領該怎麼處理。
#[derive(Debug)]
pub enum ClaimStep {
    Jobs(ClaimResponse),
    /// Hub 太舊（404）。
    Unsupported,
    /// 照 Hub 的要求等這麼久再認領（429）。
    Throttled(Duration),
    /// 連不上或暫時的錯誤：退避重試。
    Retry(String),
    /// 權杖被拒（401／403）：結束。
    Fatal(AppError),
}

pub fn classify_claim(r: AppResult<Option<Value>>, t: &Timing) -> ClaimStep {
    match r {
        Ok(Some(v)) => match serde_json::from_value::<ClaimResponse>(v) {
            Ok(c) => ClaimStep::Jobs(c),
            Err(e) => ClaimStep::Retry(e.to_string()),
        },
        Ok(None) => ClaimStep::Unsupported,
        Err(AppError::HubAuth) => ClaimStep::Fatal(AppError::HubAuth),
        Err(AppError::HubThrottled { retry_after_s }) => {
            ClaimStep::Throttled(Duration::from_secs(retry_after_s.unwrap_or(30)).clamp(t.throttle_min, t.throttle_max))
        }
        Err(e) => ClaimStep::Retry(e.message()),
    }
}

/// 隨機多等 0～`max`（大家同時重啟時不要一起打 Hub）。
fn jitter(d: Duration, max: Duration) -> Duration {
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(0);
    if max_ms == 0 {
        return d;
    }
    let r = (uuid::Uuid::new_v4().as_u128() & u128::from(u64::MAX)) as u64;
    d + Duration::from_millis(r % (max_ms + 1))
}

/// 下次認領前等多久：Hub 給的 `poll_after_ms`（夾到範圍內）＋最多一成的抖動（最多 3 秒）。
pub fn poll_wait(poll_after_ms: Option<u64>, t: &Timing) -> Duration {
    let base = poll_after_ms
        .map(Duration::from_millis)
        .unwrap_or(t.poll_default)
        .clamp(t.poll_min, t.poll_max);
    jitter(base, (base / 10).min(Duration::from_secs(3)))
}

/// 不准當目標的本機位址：這台所有網卡的位址＋預設閘道（Docker 網路的閘道就是主機本身，
/// 主機上綁 0.0.0.0 的服務從容器打得到）。範圍檢查把這些當成 `self` 擋掉，認領時也告訴 Hub。
pub fn self_ips() -> Vec<IpAddr> {
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut v: Vec<IpAddr> = nets
        .values()
        .flat_map(|d| d.ip_networks().iter().map(|n| n.addr))
        .chain(default_gateways())
        .map(|ip| ip.to_canonical())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Linux 路由表裡的 RTF_GATEWAY 旗標。
const RTF_GATEWAY: u32 = 0x0002;

/// 預設閘道：Linux 讀 `/proc/net/route` 與 `/proc/net/ipv6_route`；其他平台取不到就略過。
pub fn default_gateways() -> Vec<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        let mut v = std::fs::read_to_string("/proc/net/route")
            .map(|t| parse_route_v4(&t))
            .unwrap_or_default();
        v.extend(
            std::fs::read_to_string("/proc/net/ipv6_route")
                .map(|t| parse_route_v6(&t))
                .unwrap_or_default(),
        );
        v
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// `/proc/net/route`：Destination 與 Mask 都是 0（預設路由）、有 RTF_GATEWAY 的列的 Gateway。
/// 位址是核心把網路位元組序的 32 位元值照「本機位元組序」印成 8 個十六進位字（x86 上 172.20.0.1 印成 `010014AC`）。
pub fn parse_route_v4(text: &str) -> Vec<IpAddr> {
    let mut v = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        let (Some(dest), Some(gw), Some(flags), Some(mask)) = (hex(f[1]), hex(f[2]), hex(f[3]), hex(f[7])) else {
            continue;
        };
        if dest == 0 && mask == 0 && gw != 0 && flags & RTF_GATEWAY != 0 {
            v.push(IpAddr::from(gw.to_ne_bytes()));
        }
    }
    v
}

/// `/proc/net/ipv6_route`：目的 `::/0`（預設路由）、有 RTF_GATEWAY 的列的下一跳（位址以網路位元組序印成 32 個十六進位字）。
pub fn parse_route_v6(text: &str) -> Vec<IpAddr> {
    fn addr(s: &str) -> Option<[u8; 16]> {
        if s.len() != 32 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }
    let mut v = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[1] != "00" {
            continue;
        }
        let (Some(dest), Some(gw), Ok(flags)) = (addr(f[0]), addr(f[4]), u32::from_str_radix(f[8], 16)) else {
            continue;
        };
        if dest == [0; 16] && gw != [0; 16] && flags & RTF_GATEWAY != 0 {
            v.push(IpAddr::from(gw));
        }
    }
    v
}

/// 認領時告訴 Hub 的本機位址（含預設閘道；不含 loopback、link-local，那些 Hub 本來就擋）。
fn claim_ips(all: &[IpAddr]) -> Vec<IpAddr> {
    all.iter()
        .copied()
        .filter(|ip| {
            !matches!(
                classify(*ip),
                IpClass::Loopback | IpClass::LinkLocal | IpClass::Unspecified
            )
        })
        .collect()
}

/// 等 `stop` 變化；送出端已經不在時永遠等。
async fn changed(stop: &mut watch::Receiver<bool>) {
    if stop.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// 一個工作結束：Hub 拒絕權杖就要整個結束。
fn on_finished(r: Result<Finished, tokio::task::JoinError>) -> AppResult<()> {
    match r {
        Ok(Finished {
            outcome: Outcome::AuthRejected,
            ..
        }) => Err(AppError::HubAuth),
        Ok(_) => Ok(()),
        Err(e) => {
            // 一個工作 panic 不拖垮整個 runner
            log(false, &tf!("掃描工作異常結束：{e}", e = e));
            Ok(())
        }
    }
}

/// 跑到停止（`stop` 變成 true）或 `--once` 做完；權杖被拒、`--once` 認領失敗時回錯。
pub async fn run(ctx: Arc<Ctx>, cfg: Config, mut stop: watch::Receiver<bool>) -> AppResult<()> {
    let t = cfg.timing;
    let max_jobs = cfg.max_jobs.clamp(1, 4);
    exec::cleanup_stale(&ctx.work_dir, exec::STALE_AFTER);
    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string());
    // 給工作的停止訊號：外面要求停止，或這裡要結束（權杖被拒）時都會送
    let (jobs_stop, jobs_stop_rx) = watch::channel(false);
    let mut running: JoinSet<Finished> = JoinSet::new();
    let mut backoff = t.backoff_min;
    let mut told_unsupported = false;
    let mut claimed = false;
    let mut failures: u32 = 0;

    let result: AppResult<()> = 'main: loop {
        while let Some(done) = running.try_join_next() {
            if let Err(e) = on_finished(done) {
                break 'main Err(e);
            }
        }
        if *stop.borrow() {
            break Ok(());
        }
        let free = max_jobs.saturating_sub(running.len());
        if (cfg.once && claimed) || free == 0 {
            if running.is_empty() {
                break Ok(());
            }
            tokio::select! {
                done = running.join_next() => {
                    if let Some(done) = done {
                        if let Err(e) = on_finished(done) {
                            break 'main Err(e);
                        }
                    }
                }
                _ = changed(&mut stop) => {}
            }
            continue;
        }

        let ips = self_ips();
        let claim = Claim {
            version: crate::VERSION.to_string(),
            hostname: hostname.clone(),
            capabilities: ctx.caps.clone(),
            max_jobs: u8::try_from(free).unwrap_or(1),
            self_ips: claim_ips(&ips),
        };
        // 認領中途要求停止：不等 Hub 回應（拿到的工作會在租約到期後回到佇列）
        let sent = tokio::select! {
            r = ctx.client.webscan_claim(&claim) => r,
            _ = changed(&mut stop) => continue,
        };
        let wait = match classify_claim(sent, &t) {
            ClaimStep::Jobs(resp) => {
                claimed = true;
                failures = 0;
                backoff = t.backoff_min;
                told_unsupported = false;
                let clock = resp
                    .server_time
                    .map(|st| st - Utc::now())
                    .unwrap_or_else(chrono::Duration::zero);
                let n = resp.jobs.len();
                for raw in resp.jobs.into_iter().take(free) {
                    running.spawn(exec::execute(
                        ctx.clone(),
                        raw,
                        ips.clone(),
                        clock,
                        jobs_stop_rx.clone(),
                    ));
                }
                if cfg.once {
                    if n == 0 {
                        log(ctx.quiet, t!("沒有待做的掃描工作"));
                    }
                    continue;
                }
                if n >= free {
                    Duration::ZERO
                } else {
                    poll_wait(resp.poll_after_ms, &t)
                }
            }
            ClaimStep::Unsupported => {
                if cfg.once {
                    break Err(AppError::Unsupported(t!("Hub 太舊，沒有網站掃描的端點").to_string()));
                }
                if !told_unsupported {
                    log(false, t!("Hub 太舊，沒有網站掃描的端點；5 分鐘後再試"));
                    told_unsupported = true;
                }
                t.unsupported_wait
            }
            ClaimStep::Throttled(d) => d,
            ClaimStep::Retry(msg) => {
                failures += 1;
                log(false, &tf!("認領工作失敗，稍後重試：{e}", e = msg));
                if cfg.once && failures >= ONCE_ATTEMPTS {
                    break Err(AppError::Hub(msg));
                }
                let d = jitter(backoff, backoff / 5);
                backoff = (backoff * 2).min(t.backoff_max);
                d
            }
            ClaimStep::Fatal(e) => break Err(e),
        };
        if wait.is_zero() {
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = changed(&mut stop) => {}
            done = running.join_next(), if !running.is_empty() => {
                if let Some(done) = done {
                    if let Err(e) = on_finished(done) {
                        break 'main Err(e);
                    }
                }
            }
        }
    };

    // 收尾：叫還在跑的工作停下來（它們會殺掉工具、回報 runner_stopped），最多等 drain
    jobs_stop.send_replace(true);
    if !running.is_empty() {
        let drain = async {
            while let Some(done) = running.join_next().await {
                let _ = on_finished(done);
            }
        };
        if tokio::time::timeout(t.drain, drain).await.is_err() {
            running.abort_all();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::test_server;
    use crate::util::cmd::FakeRunner;
    use crate::webscan::exec::tests::ctx;
    use crate::webscan::job::tests::scan_job;
    use serde_json::json;

    fn fast() -> Timing {
        Timing {
            unsupported_wait: Duration::from_millis(30),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(40),
            throttle_min: Duration::from_millis(1),
            throttle_max: Duration::from_millis(30),
            poll_default: Duration::from_millis(20),
            poll_min: Duration::from_millis(1),
            poll_max: Duration::from_millis(50),
            drain: Duration::from_secs(10),
        }
    }

    fn once() -> Config {
        Config {
            max_jobs: 1,
            once: true,
            timing: fast(),
        }
    }

    #[test]
    fn claim_results_are_classified() {
        let t = Timing::default();
        assert!(matches!(
            classify_claim(Ok(Some(json!({"jobs": [], "poll_after_ms": 15000}))), &t),
            ClaimStep::Jobs(c) if c.jobs.is_empty() && c.poll_after_ms == Some(15000)
        ));
        assert!(matches!(classify_claim(Ok(None), &t), ClaimStep::Unsupported));
        assert!(matches!(
            classify_claim(Err(AppError::HubAuth), &t),
            ClaimStep::Fatal(AppError::HubAuth)
        ));
        assert!(matches!(
            classify_claim(Err(AppError::HubThrottled { retry_after_s: Some(7) }), &t),
            ClaimStep::Throttled(d) if d == Duration::from_secs(7)
        ));
        assert!(matches!(
            classify_claim(Err(AppError::HubThrottled { retry_after_s: Some(999_999) }), &t),
            ClaimStep::Throttled(d) if d == Duration::from_secs(3600)
        ));
        assert!(matches!(
            classify_claim(Err(AppError::HubThrottled { retry_after_s: None }), &t),
            ClaimStep::Throttled(d) if d == Duration::from_secs(30)
        ));
        assert!(matches!(
            classify_claim(Err(AppError::Hub("down".into())), &t),
            ClaimStep::Retry(_)
        ));
        assert!(matches!(
            classify_claim(Ok(Some(json!({"jobs": 5}))), &t),
            ClaimStep::Retry(_)
        ));
    }

    #[test]
    fn poll_wait_is_clamped_with_small_jitter() {
        let t = Timing::default();
        for _ in 0..20 {
            let w = poll_wait(Some(15_000), &t);
            assert!(
                w >= Duration::from_secs(15) && w <= Duration::from_millis(16_500),
                "{w:?}"
            );
        }
        assert!(poll_wait(Some(0), &t) >= Duration::from_secs(1));
        assert!(poll_wait(Some(86_400_000), &t) <= Duration::from_secs(303));
        assert!(poll_wait(None, &t) >= Duration::from_secs(15));
    }

    #[test]
    fn claim_ips_skip_loopback_and_link_local() {
        let all: Vec<IpAddr> = ["127.0.0.1", "::1", "fe80::1", "172.20.0.5", "2001:db8::5"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(
            claim_ips(&all),
            vec!["172.20.0.5".parse::<IpAddr>().unwrap(), "2001:db8::5".parse().unwrap()]
        );
    }

    #[test]
    fn default_gateways_are_parsed_from_proc_net_route() {
        // 核心照本機位元組序印位址：用同樣的方式組測試資料，大小端都對
        let hex = |a: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(a));
        let v4 = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             eth0\t00000000\t{}\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
             eth0\t{}\t00000000\t0001\t0\t0\t0\t{}\t0\t0\t0\n\
             eth1\t{}\t{}\t0003\t0\t0\t0\t{}\t0\t0\t0\n",
            hex([172, 20, 0, 1]),
            hex([172, 20, 0, 0]),
            hex([255, 255, 0, 0]),
            hex([10, 9, 0, 0]),
            hex([172, 20, 0, 254]),
            hex([255, 255, 0, 0]),
        );
        assert_eq!(
            parse_route_v4(&v4),
            vec![IpAddr::from([172, 20, 0, 1])],
            "only the default route's gateway"
        );
        assert!(parse_route_v4("garbage\nnot a route line at all\n").is_empty());
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
                  fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert_eq!(parse_route_v6(v6), vec!["fe80::1".parse::<IpAddr>().unwrap()]);
        assert!(parse_route_v6("00 zz\n").is_empty());
    }

    #[test]
    fn gateways_are_reported_and_blocked_like_own_addresses() {
        let gw: IpAddr = "172.20.0.1".parse().unwrap();
        let local: Vec<IpAddr> = vec!["172.20.0.5".parse().unwrap(), gw, "fe80::1".parse().unwrap()];
        assert_eq!(claim_ips(&local), vec!["172.20.0.5".parse::<IpAddr>().unwrap(), gw]);
        // 閘道就算在內網白名單裡也不准掃
        let mut j = crate::webscan::job::tests::scan_job("172.20.0.1");
        j["scope"]["allowed_private_cidrs"] = json!(["172.16.0.0/12"]);
        assert_eq!(
            crate::webscan::job::parse(j, &local).unwrap_err().code(),
            "blocked_target:self"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn self_ips_include_the_default_gateway() {
        let mine = self_ips();
        for gw in default_gateways() {
            assert!(mine.contains(&gw.to_canonical()), "{gw} missing from {mine:?}");
        }
    }

    #[tokio::test]
    async fn once_claims_runs_and_reports() {
        let work = tempfile::tempdir().unwrap();
        let claim = json!({ "jobs": [scan_job("8.8.8.8")], "poll_after_ms": 15000, "server_time": Utc::now() });
        let ok = r#"{"ok":true}"#.to_string();
        let (url, cap) = test_server::serve(vec![
            (200, claim.to_string()),
            (200, r#"{"ok":true,"cancel":false}"#.into()),
            (200, ok.clone()),
            (200, ok.clone()),
            (200, ok.clone()),
            (200, ok.clone()),
            (200, ok),
        ])
        .await;
        let fake = Arc::new(
            FakeRunner::new()
                .on("httpx -u", crate::util::cmd::CmdOutput::success("{}\n"))
                .on("tlsx -u", crate::util::cmd::CmdOutput::success("{}\n"))
                .on("nuclei -u", crate::util::cmd::CmdOutput::success(""))
                .on("testssl.sh", crate::util::cmd::CmdOutput::success("")),
        );
        let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        let (_tx, stop) = watch::channel(false);
        run(c, once(), stop).await.unwrap();
        let reqs = cap.lock().unwrap().clone();
        assert_eq!(reqs.len(), 7);
        assert!(reqs[0].head.starts_with("POST /api/v1/webscan/jobs/claim "));
        assert!(reqs[0]
            .head
            .to_ascii_lowercase()
            .contains("authorization: bearer tok-webscan"));
        let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["version"], crate::VERSION);
        assert_eq!(body["max_jobs"], 1);
        assert_eq!(body["capabilities"].as_array().unwrap().len(), 4);
        assert_eq!(body["capabilities"][0], json!({"scanner": "httpx", "version": "1.0.0"}));
        assert!(body["self_ips"].is_array() && body["hostname"].is_string());
        assert!(reqs[6]
            .head
            .starts_with("POST /api/v1/webscan/jobs/wsj_0123456789abcdef/results "));
        assert_eq!(fake.calls().len(), 4);
    }

    #[tokio::test]
    async fn once_with_no_jobs_exits_cleanly() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![(200, r#"{"jobs":[],"poll_after_ms":15000}"#.into())]).await;
        let c = ctx(
            &url,
            Arc::new(FakeRunner::new()),
            work.path(),
            Duration::from_secs(3600),
        );
        let (_tx, stop) = watch::channel(false);
        run(c, once(), stop).await.unwrap();
        assert_eq!(cap.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn auth_failure_ends_the_runner() {
        let work = tempfile::tempdir().unwrap();
        let (url, _cap) = test_server::serve(vec![(401, r#"{"error":"unauthorized"}"#.into())]).await;
        let c = ctx(
            &url,
            Arc::new(FakeRunner::new()),
            work.path(),
            Duration::from_secs(3600),
        );
        let (_tx, stop) = watch::channel(false);
        let cfg = Config { once: false, ..once() };
        assert!(matches!(run(c, cfg, stop).await, Err(AppError::HubAuth)));
    }

    #[tokio::test]
    async fn old_hub_and_throttling_wait_then_retry() {
        let work = tempfile::tempdir().unwrap();
        // 404（Hub 太舊）→ 等一下再試；429 → 照 Retry-After（測試夾到 30 ms）；最後拿到空的工作清單
        let (url, cap) = test_server::serve(vec![
            (404, r#"{"error":"not_found"}"#.into()),
            (429, r#"{"error":"slow_down"}"#.into()),
            (200, r#"{"jobs":[],"poll_after_ms":15000}"#.into()),
        ])
        .await;
        let c = ctx(
            &url,
            Arc::new(FakeRunner::new()),
            work.path(),
            Duration::from_secs(3600),
        );
        let (tx, stop) = watch::channel(false);
        let cfg = Config { once: false, ..once() };
        let runner = tokio::spawn(run(c, cfg, stop));
        // 三次認領都送出後要求停止
        for _ in 0..200 {
            if cap.lock().unwrap().len() >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), runner)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let reqs = cap.lock().unwrap().clone();
        assert!(reqs.len() >= 3);
        assert!(reqs
            .iter()
            .all(|r| r.head.starts_with("POST /api/v1/webscan/jobs/claim ")));
    }

    #[tokio::test]
    async fn once_against_an_old_hub_is_an_error() {
        let work = tempfile::tempdir().unwrap();
        let (url, _cap) = test_server::serve(vec![(404, "{}".into())]).await;
        let c = ctx(
            &url,
            Arc::new(FakeRunner::new()),
            work.path(),
            Duration::from_secs(3600),
        );
        let (_tx, stop) = watch::channel(false);
        assert!(matches!(run(c, once(), stop).await, Err(AppError::Unsupported(_))));
    }

    #[tokio::test]
    async fn once_gives_up_when_the_hub_stays_unreachable() {
        let work = tempfile::tempdir().unwrap();
        // 沒有人在聽的 port
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let c = ctx(
            &format!("http://127.0.0.1:{port}"),
            Arc::new(FakeRunner::new()),
            work.path(),
            Duration::from_secs(3600),
        );
        let (_tx, stop) = watch::channel(false);
        let r = tokio::time::timeout(Duration::from_secs(60), run(c, once(), stop))
            .await
            .unwrap();
        assert!(matches!(r, Err(AppError::Hub(_))), "{r:?}");
    }
}
