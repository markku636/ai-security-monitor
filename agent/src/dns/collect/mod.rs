//! 依平台挑 DNS 資料來源：
//! - Windows：ETW 即時事件（系統管理員／SYSTEM，有 PID）→ 做不到時改用 DNS 快取快照（每 30 秒，沒有 PID）。
//! - Linux／macOS：之後加入（systemd-resolved 監看、監聽 53 port）。

#[cfg(windows)]
pub mod windows;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use super::model::{DnsEvent, Source};

/// 啟動結果：用哪個來源、有沒有 PID、要不要由呼叫端定期抓快取快照；`guard` 活著來源就持續送事件。
pub struct Collector {
    pub source: Option<Source>,
    pub has_process: bool,
    pub poll_cache: bool,
    pub notes: Vec<String>,
    pub guard: Option<Box<dyn Send>>,
}

impl Collector {
    pub fn none(note: String) -> Collector {
        Collector {
            source: None,
            has_process: false,
            poll_cache: false,
            notes: vec![note],
            guard: None,
        }
    }
}

/// 啟動這個平台最好的即時來源。`session` 是 ETW session 名稱（背景服務與命令列各用各的）。
pub fn start(session: &str, tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>) -> Collector {
    #[cfg(windows)]
    {
        match windows::EtwSession::start(session, tx, dropped) {
            Ok(s) => Collector {
                source: Some(Source::Etw),
                has_process: true,
                poll_cache: false,
                notes: Vec::new(),
                guard: Some(Box::new(s)),
            },
            Err(e) => Collector {
                source: Some(Source::Cache),
                has_process: false,
                poll_cache: true,
                notes: vec![tf!("改用 DNS 快取快照（看不到是哪個程式查的）：{e}", e = e.message())],
                guard: None,
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (session, tx, dropped);
        Collector::none(t!("這個平台的即時 DNS 蒐集還沒支援").into())
    }
}
