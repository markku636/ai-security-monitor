//! 背景服務帶起防護 DNS（`dns.server.enabled`）：獨立子行程，watch 掃描或自我更新時 DNS 照常服務；
//! 子行程結束就重啟（連續失敗時退避，最多 5 分鐘）；監聽位址或 Hub 設定變了就重啟套用。
//! Windows 用 Job Object（watch 意外結束時子行程一起收掉）、Unix 用 process group。
//! 輸出寫進 `<設定目錄>/dns-server/server.log`（每次啟動重寫），綁不到 port 這類錯誤看得到。

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::ai::proc::{prepare, Job};
use crate::config::AgentConfig;

const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// 跑超過這麼久才結束不算連續失敗（退避從頭算）。
const HEALTHY_RUN: Duration = Duration::from_secs(600);
pub const LOG_FILE: &str = "dns-server/server.log";

/// 這份設定要跑的 dns-server 參數；沒開回 None。
pub fn args_for(cfg: &AgentConfig) -> Option<Vec<String>> {
    if !cfg.dns.server.enabled {
        return None;
    }
    // 情資清單由 watch 每 30 分鐘更新，子行程每 10 分鐘重新載入
    let mut a = vec!["dns-server".to_string(), "--no-feed-update".to_string()];
    if !cfg.dns.server.listen.is_empty() {
        a.push("--listen".into());
        a.push(cfg.dns.server.listen.join(","));
    }
    if cfg.hub.is_some() {
        a.push("--hub-agent".into());
    }
    Some(a)
}

fn backoff(fails: u32) -> Duration {
    Duration::from_secs(5u64.saturating_mul(1u64 << fails.min(6))).min(MAX_BACKOFF)
}

#[derive(Default)]
pub struct Supervisor {
    child: Option<(tokio::process::Child, Job)>,
    args: Vec<String>,
    fails: u32,
    next_try: Option<Instant>,
    started: Option<Instant>,
}

impl Supervisor {
    pub fn running(&self) -> bool {
        self.child.is_some()
    }

    /// 每輪呼叫：`want` 是要跑的參數（None＝停掉）。回傳要寫進 log 的事件。
    pub async fn reconcile(&mut self, exe: &Path, config_dir: &Path, want: Option<Vec<String>>) -> Vec<String> {
        let mut events = Vec::new();
        if let Some((c, _)) = &mut self.child {
            if let Ok(Some(status)) = c.try_wait() {
                self.child = None;
                let ran = self.started.map(|s| s.elapsed()).unwrap_or_default();
                self.fails = if ran > HEALTHY_RUN { 1 } else { self.fails + 1 };
                let wait = backoff(self.fails);
                self.next_try = Some(Instant::now() + wait);
                events.push(tf!(
                    "防護 DNS 結束了（{status}），{s} 秒後重新啟動；原因見 {log}",
                    status = status,
                    s = wait.as_secs(),
                    log = config_dir.join(LOG_FILE).display()
                ));
            }
        }
        let Some(args) = want else {
            if self.child.is_some() {
                self.stop().await;
                events.push(t!("防護 DNS 已停止").to_string());
            }
            self.fails = 0;
            self.next_try = None;
            return events;
        };
        if self.child.is_some() && args != self.args {
            self.stop().await;
            self.next_try = None;
            events.push(t!("防護 DNS 的設定變了，重新啟動").to_string());
        }
        if self.child.is_none() && self.next_try.is_none_or(|t| Instant::now() >= t) {
            match spawn(exe, config_dir, &args) {
                Ok(c) => {
                    events.push(tf!("防護 DNS 已啟動：{args}", args = args.join(" ")));
                    self.child = Some(c);
                    self.args = args;
                    self.started = Some(Instant::now());
                }
                Err(e) => {
                    self.fails += 1;
                    self.next_try = Some(Instant::now() + backoff(self.fails));
                    events.push(tf!("防護 DNS 啟動失敗：{e}", e = e));
                }
            }
        }
        events
    }

    /// 停掉子行程：Unix 先送 SIGTERM（讓它把紀錄寫完），3 秒內沒結束再整組砍掉。
    pub async fn stop(&mut self) {
        let Some((mut c, job)) = self.child.take() else {
            return;
        };
        #[cfg(unix)]
        if let Some(pid) = c.id() {
            // SAFETY: 送訊號給自己帶起的子行程。
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            if tokio::time::timeout(Duration::from_secs(3), c.wait()).await.is_ok() {
                return;
            }
        }
        job.kill();
        let _ = tokio::time::timeout(Duration::from_secs(3), c.wait()).await;
    }
}

fn spawn(exe: &Path, config_dir: &Path, args: &[String]) -> std::io::Result<(tokio::process::Child, Job)> {
    let log_path = config_dir.join(LOG_FILE);
    if let Some(dir) = log_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let out = std::fs::File::create(&log_path)?;
    let err = out.try_clone()?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("--config-dir")
        .arg(config_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    prepare(&mut cmd);
    let child = cmd.spawn()?;
    let job = Job::new().ok_or_else(|| std::io::Error::other("job object"))?;
    job.assign(&child);
    Ok((child, job))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_follow_config() {
        let mut c = AgentConfig::default();
        assert_eq!(args_for(&c), None);
        c.dns.server.enabled = true;
        assert_eq!(args_for(&c).unwrap(), vec!["dns-server", "--no-feed-update"]);
        c.dns.server.listen = vec!["192.168.1.5:53".into(), "[fd00::5]:53".into()];
        c.hub = Some(crate::config::HubConfig {
            url: "https://hub.example".into(),
            ..Default::default()
        });
        assert_eq!(
            args_for(&c).unwrap(),
            vec![
                "dns-server",
                "--no-feed-update",
                "--listen",
                "192.168.1.5:53,[fd00::5]:53",
                "--hub-agent"
            ]
        );
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(10));
        assert_eq!(backoff(3), Duration::from_secs(40));
        assert_eq!(backoff(20), MAX_BACKOFF);
    }

    #[tokio::test]
    async fn restarts_and_stops_a_child() {
        // 拿測試執行檔當「子行程」：參數錯誤會馬上結束，驗證結束偵測與退避
        let exe = std::env::current_exe().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut s = Supervisor::default();
        let ev = s
            .reconcile(&exe, dir.path(), Some(vec!["--definitely-not-a-test-flag".into()]))
            .await;
        assert!(s.running(), "{ev:?}");
        // 等它結束
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some((c, _)) = &mut s.child {
                if c.try_wait().ok().flatten().is_some() {
                    break;
                }
            }
        }
        let ev = s
            .reconcile(&exe, dir.path(), Some(vec!["--definitely-not-a-test-flag".into()]))
            .await;
        assert!(!s.running(), "backing off: {ev:?}");
        assert!(s.next_try.is_some());
        let ev = s.reconcile(&exe, dir.path(), None).await;
        assert!(ev.is_empty() && !s.running());
        assert!(dir.path().join(LOG_FILE).exists());
    }
}
