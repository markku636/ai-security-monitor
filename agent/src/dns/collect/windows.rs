//! Windows：Microsoft-Windows-DNS-Client 的 ETW 即時事件（自己開一個私有 session，不改系統的事件紀錄設定），
//! 需要系統管理員／SYSTEM；做不到時改用 DNS 快取快照（`Get-DnsClientCache`，沒有 PID）。
//!
//! 只收事件 3008（查詢完成：QueryName、QueryType、QueryOptions、QueryStatus、QueryResults），PID 取事件標頭。
//! 參考 Velociraptor `Windows.ETW.DNS` 與 Palantir WEF 的過濾：略過 Dnscache 服務自己（避免一題記兩次）
//! 與查本機名稱的查詢（QueryOptions = 0x800000000000）。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::mpsc::Sender;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhGetProperty,
    TdhGetPropertySize, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_EVENT_ID, EVENT_FILTER_TYPE_EVENT_ID,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR,
    WNODE_FLAG_TRACED_GUID,
};

use super::super::model::{normalize_name, parse_win_query_results, rcode_from_win_status, DnsEvent, Source};
use crate::error::{AppError, AppResult};

/// 背景服務用的 session 名稱；命令列 `dns --follow` 另取名字，不會搶走服務的 session。
pub const SERVICE_SESSION: &str = "ai-security-monitor-dns";
const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
const EVENT_QUERY_COMPLETED: u16 = 3008;
/// 查本機自己名稱的查詢。
const LOCAL_NAME_OPTION: u64 = 0x8000_0000_0000;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_ALREADY_EXISTS: u32 = 183;
const TRACE_LEVEL_VERBOSE: u8 = 5;
const INVALID_PROCESSTRACE: u64 = u64::MAX;
/// FILETIME（1601 起的 100ns）與 Unix 紀元的差。
const FILETIME_UNIX_DIFF: i64 = 116_444_736_000_000_000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// EVENT_TRACE_PROPERTIES 後面接 session 名稱；用 u64 陣列保證對齊。
struct Props {
    buf: Vec<u64>,
}

impl Props {
    fn new(name_len_u16: usize) -> Props {
        let base = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let total = base + name_len_u16 * 2;
        let mut buf = vec![0u64; total.div_ceil(8)];
        // SAFETY: buf 至少 total bytes、8 bytes 對齊，EVENT_TRACE_PROPERTIES 全是 POD。
        let p = unsafe { &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        p.Wnode.BufferSize = total as u32;
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // 2＝系統時間（FILETIME），事件時間戳直接換算 UTC
        p.Wnode.ClientContext = 2;
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p.FlushTimer = 1;
        p.BufferSize = 64;
        p.MinimumBuffers = 4;
        p.MaximumBuffers = 32;
        p.LoggerNameOffset = base as u32;
        Props { buf }
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

fn stop_by_name(name: &[u16]) {
    let mut p = Props::new(name.len());
    // SAFETY: name 以 0 結尾；props 緩衝區大小正確。
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            p.ptr(),
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// callback 用的狀態（指標放在 EVENT_TRACE_LOGFILEW.Context，事件的 UserContext 拿得到）。
struct Ctx {
    tx: Sender<DnsEvent>,
    dropped: Arc<AtomicU64>,
    skip_pid: Option<u32>,
    p_name: Vec<u16>,
    p_type: Vec<u16>,
    p_options: Vec<u16>,
    p_status: Vec<u16>,
    p_results: Vec<u16>,
}

/// 一個執行中的 ETW session；drop 時停止並等消費執行緒結束。
pub struct EtwSession {
    name: Vec<u16>,
    handle: CONTROLTRACE_HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EtwSession {
    /// 開 session、啟用 DNS Client 提供者（只收 3008）、在專用執行緒處理事件。
    /// 沒有系統管理員權限時回錯誤（呼叫端改用快取快照）。
    pub fn start(session: &str, tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>) -> AppResult<EtwSession> {
        let name = wide(session);
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut props = Props::new(name.len());
        // SAFETY: 參數皆為有效指標，props 緩衝區含名稱空間。
        let mut rc = unsafe { StartTraceW(&mut handle, name.as_ptr(), props.ptr()) };
        if rc == ERROR_ALREADY_EXISTS {
            // 上次異常結束留下的同名 session
            stop_by_name(&name);
            props = Props::new(name.len());
            // SAFETY: 同上。
            rc = unsafe { StartTraceW(&mut handle, name.as_ptr(), props.ptr()) };
        }
        if rc == ERROR_ACCESS_DENIED {
            return Err(AppError::Unsupported(t!("即時 DNS 事件需要系統管理員權限").into()));
        }
        if rc != 0 {
            return Err(AppError::Unsupported(tf!("無法開啟 ETW session（錯誤 {rc}）", rc = rc)));
        }
        let session_guard = EtwSession {
            name: name.clone(),
            handle,
            thread: None,
        };

        let mut filter = EVENT_FILTER_EVENT_ID {
            FilterIn: true,
            Reserved: 0,
            Count: 1,
            Events: [EVENT_QUERY_COMPLETED],
        };
        let mut desc = EVENT_FILTER_DESCRIPTOR {
            Ptr: &mut filter as *mut _ as u64,
            Size: std::mem::size_of::<EVENT_FILTER_EVENT_ID>() as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        };
        let params = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableFilterDesc: &mut desc,
            FilterDescCount: 1,
            ..Default::default()
        };
        // SAFETY: handle 來自成功的 StartTraceW；params／filter 在呼叫期間有效。
        let mut rc = unsafe {
            EnableTraceEx2(
                handle,
                &DNS_CLIENT,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                u64::MAX,
                0,
                0,
                &params,
            )
        };
        if rc != 0 {
            // 舊版系統不支援事件 ID 篩選：改成全收，在 callback 裡篩
            // SAFETY: 同上，不帶篩選參數。
            rc = unsafe {
                EnableTraceEx2(
                    handle,
                    &DNS_CLIENT,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_VERBOSE,
                    u64::MAX,
                    0,
                    0,
                    std::ptr::null(),
                )
            };
        }
        if rc != 0 {
            return Err(AppError::Unsupported(tf!(
                "無法啟用 DNS Client 事件提供者（錯誤 {rc}）",
                rc = rc
            )));
        }

        let ctx = Box::new(Ctx {
            tx,
            dropped,
            skip_pid: dnscache_pid(),
            p_name: wide("QueryName"),
            p_type: wide("QueryType"),
            p_options: wide("QueryOptions"),
            p_status: wide("QueryStatus"),
            p_results: wide("QueryResults"),
        });
        let ctx_addr = Box::into_raw(ctx) as usize;
        let thread_name = name.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
        let thread = std::thread::Builder::new()
            .name("dns-etw".into())
            .spawn(move || {
                let mut lf = EVENT_TRACE_LOGFILEW {
                    LoggerName: thread_name.as_ptr() as *mut u16,
                    Context: ctx_addr as *mut c_void,
                    ..Default::default()
                };
                lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
                lf.Anonymous2.EventRecordCallback = Some(on_event);
                // SAFETY: lf 欄位有效；LoggerName 在整個執行緒期間存活。
                let th: PROCESSTRACE_HANDLE = unsafe { OpenTraceW(&mut lf) };
                let ok = th.Value != INVALID_PROCESSTRACE;
                let _ = ready_tx.send(ok);
                if ok {
                    // SAFETY: th 是有效的 trace handle；ProcessTrace 阻塞到 session 停止。
                    unsafe {
                        ProcessTrace(&th, 1, std::ptr::null(), std::ptr::null());
                        CloseTrace(th);
                    }
                }
                // SAFETY: ProcessTrace 已返回，不會再有 callback 使用 ctx。
                drop(unsafe { Box::from_raw(ctx_addr as *mut Ctx) });
            })
            .map_err(|e| AppError::Unsupported(e.to_string()))?;
        let mut s = session_guard;
        s.thread = Some(thread);
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(true) => Ok(s),
            _ => Err(AppError::Unsupported(t!("無法讀取 ETW 即時事件").into())),
        }
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        let mut p = Props::new(self.name.len());
        // SAFETY: handle 來自成功的 StartTraceW。
        unsafe {
            ControlTraceW(self.handle, std::ptr::null(), p.ptr(), EVENT_TRACE_CONTROL_STOP);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Dnscache 服務所在的 svchost PID（它代替程式查詢時也會記一筆，略過以免重複）。
fn dnscache_pid() -> Option<u32> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let s = m.open_service("Dnscache", ServiceAccess::QUERY_STATUS).ok()?;
    s.query_status().ok()?.process_id
}

/// 讀一個屬性的原始位元組（TDH 依事件的 manifest 解析，跨 Windows 版本穩定）。
///
/// # Safety
/// `rec` 必須是 ETW callback 給的有效事件；`name` 以 0 結尾。
unsafe fn prop(rec: &EVENT_RECORD, name: &[u16]) -> Option<Vec<u8>> {
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0u32;
    if TdhGetPropertySize(rec, 0, std::ptr::null(), 1, &desc, &mut size) != 0 || size == 0 || size > 65_536 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if TdhGetProperty(rec, 0, std::ptr::null(), 1, &desc, size, buf.as_mut_ptr()) != 0 {
        return None;
    }
    Some(buf)
}

fn utf16z(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn le_u64(b: &[u8]) -> Option<u64> {
    match b.len() {
        8.. => Some(u64::from_le_bytes(b[..8].try_into().ok()?)),
        4..=7 => Some(u64::from(u32::from_le_bytes(b[..4].try_into().ok()?))),
        _ => None,
    }
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn filetime_to_utc(ft: i64) -> DateTime<Utc> {
    let since_unix = ft - FILETIME_UNIX_DIFF;
    DateTime::from_timestamp(
        since_unix.div_euclid(10_000_000),
        (since_unix.rem_euclid(10_000_000) * 100) as u32,
    )
    .unwrap_or_else(Utc::now)
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    // callback 裡絕不能 panic 穿過 FFI 邊界
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: ETW 給的事件指標在 callback 期間有效。
        let Some(r) = (unsafe { rec.as_ref() }) else {
            return;
        };
        handle(r);
    });
}

fn handle(r: &EVENT_RECORD) {
    let h = &r.EventHeader;
    if h.EventDescriptor.Id != EVENT_QUERY_COMPLETED || !same_guid(&h.ProviderId, &DNS_CLIENT) {
        return;
    }
    // SAFETY: UserContext 是 start() 放進去的 Ctx，生命週期涵蓋整個 ProcessTrace。
    let Some(ctx) = (unsafe { (r.UserContext as *const Ctx).as_ref() }) else {
        return;
    };
    if ctx.skip_pid == Some(h.ProcessId) {
        return;
    }
    // SAFETY: r 是有效事件，屬性名稱以 0 結尾。
    let get = |n: &[u16]| unsafe { prop(r, n) };
    if get(&ctx.p_options).as_deref().and_then(le_u64) == Some(LOCAL_NAME_OPTION) {
        return;
    }
    let Some(name) = get(&ctx.p_name).map(|b| utf16z(&b)).and_then(|n| normalize_name(&n)) else {
        return;
    };
    let qtype = get(&ctx.p_type).as_deref().and_then(le_u64).unwrap_or(0) as u16;
    let status = get(&ctx.p_status).as_deref().and_then(le_u64).unwrap_or(0) as u32;
    // 87（ERROR_INVALID_PARAMETER）是 DNS Client 內部略過的題目（例如沒有 IPv6 時的 AAAA），不是解析結果
    if status == ERROR_INVALID_PARAMETER {
        return;
    }
    let results = get(&ctx.p_results).map(|b| utf16z(&b)).unwrap_or_default();
    let (answers, cnames) = parse_win_query_results(&results);
    let rcode = if status == 0 && answers.is_empty() && cnames.is_empty() {
        "NODATA".to_string()
    } else {
        rcode_from_win_status(status)
    };
    let ev = DnsEvent {
        ts: filetime_to_utc(h.TimeStamp),
        name,
        qtype,
        rcode,
        answers,
        cnames,
        ttl: None,
        pid: Some(h.ProcessId),
        source: Source::Etw,
    };
    if ctx.tx.try_send(ev).is_err() {
        ctx.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// DNS 快取快照的 PowerShell：一行一筆 `名稱<TAB>類型<TAB>狀態<TAB>TTL<TAB>資料`。
pub const CACHE_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-DnsClientCache | ForEach-Object { "$($_.Entry)`t$($_.Type)`t$($_.Status)`t$($_.TimeToLive)`t$($_.Data)" }
"#;

/// 解析快取快照的一行。
pub fn parse_cache_line(line: &str) -> Option<(String, u16, u32, u32, String)> {
    let mut it = line.trim_end_matches(['\r', '\n']).split('\t');
    let name = normalize_name(it.next()?)?;
    let ty: u16 = it.next()?.trim().parse().ok()?;
    let status: u32 = it.next()?.trim().parse().ok()?;
    let ttl: u32 = it.next()?.trim().parse().unwrap_or(0);
    let data = it.next().unwrap_or("").trim().to_string();
    Some((name, ty, status, ttl, data))
}

/// 快取快照只看得到「現在在快取裡」的名稱：記住看過的，下次只送新出現的。
#[derive(Default)]
pub struct CacheTracker {
    seen: HashMap<(String, u16, String), Instant>,
}

impl CacheTracker {
    /// 把一次快照轉成新事件（同一筆在它的 TTL 內不重送）。
    pub fn diff(&mut self, text: &str, now: DateTime<Utc>) -> Vec<DnsEvent> {
        let t0 = Instant::now();
        self.seen.retain(|_, exp| *exp > t0);
        let mut by_name: HashMap<(String, u16), DnsEvent> = HashMap::new();
        for line in text.lines() {
            let Some((name, ty, status, ttl, data)) = parse_cache_line(line) else {
                continue;
            };
            let key = (name.clone(), ty, data.clone());
            if self.seen.contains_key(&key) {
                continue;
            }
            self.seen
                .insert(key, t0 + Duration::from_secs(u64::from(ttl.clamp(30, 3600))));
            // CNAME（5）記錄的資料是目標名稱；A／AAAA 是位址
            let (qtype, answer, cname) = match ty {
                5 => (1, None, normalize_name(&data)),
                _ => (ty, data.parse().ok(), None),
            };
            let ev = by_name.entry((name.clone(), qtype)).or_insert_with(|| DnsEvent {
                ts: now,
                name,
                qtype,
                rcode: if status == 0 {
                    "NOERROR".into()
                } else {
                    rcode_from_win_status(status)
                },
                answers: Vec::new(),
                cnames: Vec::new(),
                ttl: Some(ttl),
                pid: None,
                source: Source::Cache,
            });
            if let Some(ip) = answer {
                if !ev.answers.contains(&ip) {
                    ev.answers.push(ip);
                }
            }
            if let Some(c) = cname {
                if !ev.cnames.contains(&c) {
                    ev.cnames.push(c);
                }
            }
        }
        let mut out: Vec<DnsEvent> = by_name.into_values().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// 抓一次 DNS 快取快照（不需要系統管理員）。
pub async fn cache_snapshot() -> AppResult<String> {
    let spec = crate::util::cmd::powershell(CACHE_SCRIPT).timeout(20_000);
    let out = crate::util::cmd::CmdRunner::run(&crate::util::cmd::RealRunner, &spec).await?;
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_lines_and_tracker() {
        let snap = "www.example.com\t5\t0\t120\tedge.example.net\r\nwww.example.com\t1\t0\t120\t93.184.216.34\r\nnx.example\t1\t9003\t60\t\r\nbad line\r\n";
        let mut t = CacheTracker::default();
        let now = Utc::now();
        let evs = t.diff(snap, now);
        assert_eq!(evs.len(), 2);
        let w = evs.iter().find(|e| e.name == "www.example.com").unwrap();
        assert_eq!(w.qtype, 1);
        assert_eq!(w.answers, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
        assert_eq!(w.cnames, vec!["edge.example.net"]);
        assert_eq!(w.ttl, Some(120));
        let nx = evs.iter().find(|e| e.name == "nx.example").unwrap();
        assert_eq!(nx.rcode, "NXDOMAIN");
        // 同一份快照再看一次：沒有新事件
        assert!(t.diff(snap, now).is_empty());
    }

    #[test]
    fn filetime_and_utf16() {
        let t = filetime_to_utc(FILETIME_UNIX_DIFF + 15 * 10_000_000);
        assert_eq!(t.timestamp(), 15);
        let b: Vec<u8> = "ab"
            .encode_utf16()
            .chain([0, 99])
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(utf16z(&b), "ab");
        assert_eq!(le_u64(&7u32.to_le_bytes()), Some(7));
        assert_eq!(le_u64(&[1, 2]), None);
    }

    /// 需要系統管理員：開 session、查一個網域、等事件。CI 的 Windows runner 跑（`--ignored`）。
    #[tokio::test]
    #[ignore]
    async fn etw_live_query_is_captured() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let dropped = Arc::new(AtomicU64::new(0));
        let _s = EtwSession::start("ai-security-monitor-dns-test", tx, dropped).expect("needs admin");
        let target = format!("asm-etw-{}.example.com", std::process::id());
        let t2 = target.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(800));
            let _ = std::net::ToSocketAddrs::to_socket_addrs(&(t2.as_str(), 80));
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let ev = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("no ETW DNS event within 20s")
                .expect("channel closed");
            if ev.name == target {
                eprintln!("{ev:?}");
                assert_eq!(ev.pid, Some(std::process::id()));
                assert_eq!(ev.source, Source::Etw);
                // 不存在的子網域：有的 DNS 回 NXDOMAIN、有的回 NOERROR 沒答案（NODATA），都算
                assert_ne!(ev.rcode, "ERR87");
                break;
            }
        }
    }
}
