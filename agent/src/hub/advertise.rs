//! `ai-security-monitor hub advertise --url <Hub 網址>`：在這台電腦上用 mDNS 幫 Hub 廣播
//! `_aisecmon._tcp.local`，讓區網的電腦自動找到它。
//!
//! Hub 跑在 Docker Desktop（Windows／macOS）或預設 bridge 網路時，容器裡的 mDNS 廣播出不了區網；
//! 這時在區網上任一台（通常就是跑 Docker 的那台）執行這個指令即可。TXT 帶 `url=`，agent 直接用那個網址，
//! 不必和 Hub 在同一台。
//!
//! 背景服務（`watch`）也能常駐廣播：設定 `hub.advertise_url` 後由 [`Advertiser`] 每分鐘確認 Hub 的身分端點，
//! 連得到才廣播（TXT 帶 Hub 的指紋 `fp=`），連續 3 次連不到就停止廣播，Hub 回來再自動恢復。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;

use super::contract::AdvertiseInfo;
use super::discover::MDNS_SERVICE;
use super::identity::{self, HubIdentity};
use crate::error::{AppError, AppResult};

/// 背景服務的廣播狀態檔（桌面版的設定頁讀）。
pub const STATE_FILE: &str = "advertise-state.json";

/// 背景服務目前的廣播狀態與寫入時間（沒在廣播就是 `None`）。寫入時間太舊＝背景服務沒在跑。
pub fn load_state(config_dir: &std::path::Path) -> Option<(AdvertiseInfo, chrono::DateTime<Utc>)> {
    #[derive(serde::Deserialize)]
    struct F {
        info: AdvertiseInfo,
        at: chrono::DateTime<Utc>,
    }
    let f: F = crate::store::read_json_opt(config_dir, STATE_FILE).ok().flatten()?;
    Some((f.info, f.at))
}

fn save_state(config_dir: Option<&std::path::Path>, info: Option<&AdvertiseInfo>) {
    let Some(dir) = config_dir else { return };
    match info {
        Some(i) => {
            let _ = crate::store::write_json_in(dir, STATE_FILE, &serde_json::json!({ "info": i, "at": Utc::now() }));
        }
        None => {
            let _ = std::fs::remove_file(dir.join(STATE_FILE));
        }
    }
}

/// 背景廣播多久確認一次 Hub。
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// 連續幾次連不到 Hub 就停止廣播。
pub const GONE_AFTER: u32 = 3;

/// 從網址取 port（沒寫就依 scheme）。
pub fn port_of(url: &str) -> u16 {
    let lower = url.to_ascii_lowercase();
    let https = lower.starts_with("https://");
    let rest = lower.split("://").nth(1).unwrap_or("");
    let hostport = rest.split('/').next().unwrap_or("");
    let port = if let Some(end) = hostport.find(']') {
        hostport[end + 1..].strip_prefix(':')
    } else {
        hostport.rsplit_once(':').map(|(_, p)| p)
    };
    port.and_then(|p| p.parse().ok())
        .unwrap_or(if https { 443 } else { 80 })
}

/// mDNS 主機名稱（一個標籤，英數與 -）。
pub fn mdns_host(hostname: &str) -> String {
    let mut h: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    h = h.trim_matches('-').to_string();
    if h.is_empty() {
        h = "hub".into();
    }
    h.truncate(40);
    format!("{h}-asm.local.")
}

pub fn txt_properties(url: &str, id: &HubIdentity) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("url".into(), url.trim_end_matches('/').to_string());
    m.insert("fp".into(), id.fingerprint.clone());
    m.insert("v".into(), id.version.clone());
    m.insert("path".into(), "/".into());
    m.insert(
        "proto".into(),
        if url.to_ascii_lowercase().starts_with("https://") {
            "https"
        } else {
            "http"
        }
        .into(),
    );
    m
}

/// 開始廣播；回傳的 daemon 存活期間持續回應查詢（drop／shutdown 後停止）。
pub fn start(url: &str, id: &HubIdentity, instance: &str) -> AppResult<(mdns_sd::ServiceDaemon, String)> {
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
    // 先給目前的 IPv4 位址（沒給的話要等 daemon 下一次檢查介面才會開始宣告）；之後介面變了由 addr_auto 更新
    let addrs: Vec<std::net::IpAddr> = crate::cli::fw_cmd::local_ips()
        .into_iter()
        .filter(|ip| ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    let info = mdns_sd::ServiceInfo::new(
        MDNS_SERVICE,
        instance,
        &mdns_host(&host),
        addrs.as_slice(),
        port_of(url),
        txt_properties(url, id),
    )
    .map_err(|e| AppError::Hub(format!("mDNS: {e}")))?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info).map_err(|e| AppError::Hub(format!("mDNS: {e}")))?;
    Ok((daemon, fullname))
}

/// 停止廣播（送出 goodbye）。
pub fn stop(daemon: &mdns_sd::ServiceDaemon, fullname: &str) {
    if let Ok(rx) = daemon.unregister(fullname) {
        let _ = rx.recv_timeout(std::time::Duration::from_secs(2));
    }
    let _ = daemon.shutdown();
}

/// 廣播的名稱：Hub 的名稱＋這台電腦的名稱。
pub fn instance_name(id: &HubIdentity) -> String {
    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    format!("{} ({host})", id.name)
}

/// 背景服務裡的常駐廣播（`hub.advertise_url`）。
pub struct Advertiser {
    url: String,
    status: Arc<Mutex<AdvertiseInfo>>,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// 一次確認之後怎麼做（純函數，測試用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 開始（或繼續）廣播；`restart`：Hub 的指紋變了，要重新登記。
    Advertise { restart: bool },
    /// 停止廣播（Hub 不見了）。
    Stop,
    /// 維持現狀（偶爾一次連不到）。
    Keep,
}

pub fn decide(running_fp: Option<&str>, seen_fp: Option<&str>, fails: u32) -> Decision {
    match seen_fp {
        Some(fp) => Decision::Advertise {
            restart: running_fp.is_some_and(|r| !identity::same_fingerprint(r, fp)),
        },
        None if fails >= GONE_AFTER => Decision::Stop,
        None => Decision::Keep,
    }
}

/// 背景 log 的寫法（服務模式寫 log 檔）。
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

impl Advertiser {
    /// 開始常駐廣播；`state_dir` 有給就把狀態寫到 `<state_dir>/advertise-state.json`（桌面版讀）。
    pub fn spawn(url: String, log: LogFn, state_dir: Option<std::path::PathBuf>) -> Advertiser {
        let status = Arc::new(Mutex::new(AdvertiseInfo {
            url: url.clone(),
            state: "starting".into(),
            ..Default::default()
        }));
        let (stop, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(supervise(url.clone(), status.clone(), rx, log, state_dir));
        Advertiser {
            url,
            status,
            stop,
            task,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// 目前狀態（放進心跳）。
    pub fn info(&self) -> AdvertiseInfo {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// 停止廣播（送出 goodbye）並等背景工作結束。
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn set_status(status: &Mutex<AdvertiseInfo>, f: impl FnOnce(&mut AdvertiseInfo)) {
    if let Ok(mut s) = status.lock() {
        f(&mut s);
    }
}

/// (daemon, 服務全名, 指紋)
type Running = (mdns_sd::ServiceDaemon, String, String);

async fn stop_blocking(running: Option<Running>) {
    if let Some((d, full, _)) = running {
        let _ = tokio::task::spawn_blocking(move || stop(&d, &full)).await;
    }
}

async fn supervise(
    url: String,
    status: Arc<Mutex<AdvertiseInfo>>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    log: LogFn,
    state_dir: Option<std::path::PathBuf>,
) {
    let mut running: Option<Running> = None;
    let mut fails = 0u32;
    let http = identity::http_client(Duration::from_secs(10)).ok();
    loop {
        let seen: Result<HubIdentity, String> = match &http {
            Some(h) => match identity::fetch(h, &url).await {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(t!("這個 Hub 版本太舊，沒有身分端點，不能廣播").to_string()),
                Err(e) => Err(e.message()),
            },
            None => Err("http client".to_string()),
        };
        fails = if seen.is_ok() { 0 } else { fails + 1 };
        let running_fp = running.as_ref().map(|r| r.2.clone());
        let seen_fp = seen.as_ref().ok().map(|i| i.fingerprint.clone());
        match (decide(running_fp.as_deref(), seen_fp.as_deref(), fails), seen) {
            (Decision::Advertise { restart }, Ok(id)) => {
                if restart {
                    log(&tf!("Hub 的指紋變了（{fp}），重新廣播", fp = id.fingerprint));
                    stop_blocking(running.take()).await;
                }
                if running.is_none() {
                    match start(&url, &id, &instance_name(&id)) {
                        Ok((d, full)) => {
                            log(&tf!(
                                "開始在區網廣播 Hub：{url}（指紋 {fp}）",
                                url = url,
                                fp = id.fingerprint
                            ));
                            running = Some((d, full, id.fingerprint.clone()));
                            set_status(&status, |s| {
                                s.state = "advertising".into();
                                s.fingerprint = Some(id.fingerprint.clone());
                                s.error = None;
                                s.since = Some(Utc::now());
                            });
                        }
                        Err(e) => set_status(&status, |s| {
                            s.state = "error".into();
                            s.error = Some(e.message());
                        }),
                    }
                } else {
                    set_status(&status, |s| s.error = None);
                }
            }
            (Decision::Stop, seen) => {
                let err = seen.err();
                if running.is_some() {
                    log(&tf!(
                        "連不到 Hub（{url}），停止區網廣播：{e}",
                        url = url,
                        e = err.clone().unwrap_or_default()
                    ));
                    stop_blocking(running.take()).await;
                }
                set_status(&status, |s| {
                    s.state = "hub_unreachable".into();
                    s.error = err;
                    s.since = None;
                });
            }
            (_, seen) => {
                if running.is_none() {
                    set_status(&status, |s| {
                        s.state = "hub_unreachable".into();
                        s.error = seen.err();
                    });
                }
            }
        }
        if let Ok(s) = status.lock() {
            save_state(state_dir.as_deref(), Some(&s));
        }
        tokio::select! {
            _ = tokio::time::sleep(CHECK_EVERY) => {}
            _ = stop_rx.changed() => break,
        }
    }
    stop_blocking(running.take()).await;
    save_state(state_dir.as_deref(), None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertise_decisions() {
        // 連得到 Hub：廣播；指紋變了要重新登記
        assert_eq!(
            decide(None, Some("AAAA-BBBB"), 0),
            Decision::Advertise { restart: false }
        );
        assert_eq!(
            decide(Some("AAAA-BBBB"), Some("aaaabbbb"), 0),
            Decision::Advertise { restart: false }
        );
        assert_eq!(
            decide(Some("AAAA-BBBB"), Some("CCCC-DDDD"), 0),
            Decision::Advertise { restart: true }
        );
        // 偶爾一次連不到：維持；連續 3 次：停止
        assert_eq!(decide(Some("AAAA-BBBB"), None, 1), Decision::Keep);
        assert_eq!(decide(Some("AAAA-BBBB"), None, 2), Decision::Keep);
        assert_eq!(decide(Some("AAAA-BBBB"), None, 3), Decision::Stop);
        assert_eq!(decide(None, None, 5), Decision::Stop);
    }

    #[test]
    fn advertiser_reports_unreachable_hub_without_advertising() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let lines = Arc::new(Mutex::new(Vec::<String>::new()));
            let l2 = lines.clone();
            let dir = tempfile::tempdir().unwrap();
            let a = Advertiser::spawn(
                "http://127.0.0.1:9".into(),
                Arc::new(move |m: &str| l2.lock().unwrap().push(m.to_string())),
                Some(dir.path().to_path_buf()),
            );
            for _ in 0..200 {
                if a.info().state != "starting" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let info = a.info();
            assert_eq!(info.state, "hub_unreachable");
            assert_eq!(info.url, "http://127.0.0.1:9");
            assert_eq!(a.url(), "http://127.0.0.1:9");
            assert!(info.error.is_some());
            assert!(info.fingerprint.is_none());
            // 狀態寫進檔案給桌面版看；停止後刪掉
            for _ in 0..40 {
                if load_state(dir.path()).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(load_state(dir.path()).unwrap().0.state, "hub_unreachable");
            a.shutdown().await;
            assert!(load_state(dir.path()).is_none());
            // 沒有開始廣播過，就沒有「開始／停止廣播」的 log
            assert!(lines.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn ports_hosts_and_txt() {
        assert_eq!(port_of("https://hub.corp.example"), 443);
        assert_eq!(port_of("http://hub.corp.example/"), 80);
        assert_eq!(port_of("http://192.168.1.5:8088"), 8088);
        assert_eq!(port_of("http://[fd00::5]:3000/x"), 3000);
        assert_eq!(port_of("https://[fd00::5]/x"), 443);
        assert_eq!(mdns_host("SRV-01.corp"), "srv-01-corp-asm.local.");
        assert_eq!(mdns_host("！！"), "hub-asm.local.");
        let id = HubIdentity {
            fingerprint: "AAAA-BBBB".into(),
            version: "0.3.0".into(),
            ..HubIdentity::default()
        };
        let t = txt_properties("https://hub.corp.example/", &id);
        assert_eq!(t["url"], "https://hub.corp.example");
        assert_eq!(t["fp"], "AAAA-BBBB");
        assert_eq!(t["proto"], "https");
        // agent 端用同一份 TXT 產生候選：網址要一字不差
        let hit = super::super::discover::MdnsHit {
            fullname: "Security Hub._aisecmon._tcp.local.".into(),
            port: 443,
            addrs: vec![],
            txt: t.into_iter().collect(),
        };
        assert_eq!(
            super::super::discover::mdns_candidate(&hit).unwrap().url,
            "https://hub.corp.example"
        );
    }
}

/// 真的走網路的往返測試（需要多播；CI 不跑）：`cargo test --lib advertise_and_browse -- --ignored`
#[cfg(test)]
mod live {
    #[test]
    #[ignore]
    fn advertise_and_browse_on_this_machine() {
        let id = super::HubIdentity {
            fingerprint: "AAAA-BBBB".into(),
            version: "0".into(),
            ..Default::default()
        };
        let (d, full) = super::start("http://localhost:3999", &id, "LiveTest").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let hits = rt
            .block_on(super::super::discover::browse_mdns(std::time::Duration::from_secs(5)))
            .unwrap();
        super::stop(&d, &full);
        let h = hits
            .iter()
            .find(|h| h.fullname.starts_with("LiveTest."))
            .expect("advertised");
        assert_eq!(h.txt["url"], "http://localhost:3999");
        assert_eq!(h.port, 3999);
    }
}
