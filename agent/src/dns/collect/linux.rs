//! Linux：AF_PACKET 監聽 UDP 53 的回應（需要 root／CAP_NET_RAW）。
//!
//! - 核心過濾器只放行「UDP 來源 port 53」，其餘流量不會複製到使用者空間。
//! - 回應的目的 port 就是查詢程式的 socket：用 `/proc` 的 socket 表對到 PID（盡力而為，程式關得太快就對不到）。
//! - 有 systemd-resolved 時，程式問的是 127.0.0.53 的 stub：stub 回給程式的那筆走 loopback、對得到程式。
//!   resolved 向上游查的那筆先扣住 [`HOLD`]：等到 stub 那筆就丟掉（同一題不記兩次）；等不到（程式用 nss-resolve
//!   走 varlink、不經 stub，例如 Fedora）就照樣記，只是看不出是哪個程式。
//! - loopback 上每個封包會出現兩次（送出／收到），只留收到的那份。
//! - 走 DoH／DoT 的查詢（瀏覽器自帶的加密 DNS）看不到，交給 DoH 繞過偵測。

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use tokio::sync::mpsc::Sender;

use super::packet::{dns_response_filter, event_from_response, parse_ip_udp, BpfInsn};
use crate::dns::model::DnsEvent;
use crate::error::{AppError, AppResult};

/// resolved 代查的回應最多扣住多久（等 stub 回給程式的那筆）。
const HOLD: Duration = Duration::from_millis(300);

/// 本機 UDP port → PID（最多每 500 ms 重讀一次 socket 表）。
struct PortOwners {
    map: HashMap<u16, u32>,
    at: Option<Instant>,
    resolved: Option<u32>,
    resolved_at: Instant,
}

impl PortOwners {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            at: None,
            resolved: resolved_pid(),
            resolved_at: Instant::now(),
        }
    }

    fn refresh(&mut self) {
        self.map.clear();
        if let Ok(socks) =
            netstat2::get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::UDP)
        {
            for s in socks {
                if let (ProtocolSocketInfo::Udp(u), Some(pid)) = (&s.protocol_socket_info, s.associated_pids.first()) {
                    self.map.insert(u.local_port, *pid);
                }
            }
        }
        self.at = Some(Instant::now());
        if self.resolved_at.elapsed() > Duration::from_secs(300) {
            self.resolved = resolved_pid();
            self.resolved_at = Instant::now();
        }
    }

    fn owner(&mut self, port: u16) -> Option<u32> {
        if let Some(p) = self.map.get(&port) {
            return Some(*p);
        }
        if self.at.is_none_or(|t| t.elapsed() > Duration::from_millis(500)) {
            self.refresh();
        }
        self.map.get(&port).copied()
    }
}

fn resolved_pid() -> Option<u32> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    sys.processes()
        .values()
        .find(|p| p.name().to_string_lossy() == "systemd-resolve")
        .map(|p| p.pid().as_u32())
}

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// 執行中的擷取；drop 時停止（讀取逾時 1 秒，最多等 1 秒）。
pub struct PacketCapture {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PacketCapture {
    pub fn start(tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>) -> AppResult<PacketCapture> {
        let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        // SAFETY: 單純的系統呼叫，回傳值檢查後才包成 OwnedFd。
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, proto) };
        if raw < 0 {
            let e = last_os_error();
            return Err(AppError::Unsupported(if e.raw_os_error() == Some(libc::EPERM) {
                t!("監聽 DNS 封包需要 root 權限").into()
            } else {
                tf!("無法開啟封包擷取：{e}", e = e)
            }));
        }
        // SAFETY: raw 是剛建立、尚無其他擁有者的有效 fd。
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let prog: Vec<BpfInsn> = dns_response_filter(0);
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_ptr() as *mut libc::sock_filter,
        };
        // 200 ms 讀取逾時：扣住的事件按時放出、停止時很快結束
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        let rcvbuf: libc::c_int = 1 << 20;
        // SAFETY: 參數指標在呼叫期間有效，大小正確；BpfInsn 與 sock_filter 版面相同。
        unsafe {
            if libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &fprog as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            ) != 0
            {
                return Err(AppError::Unsupported(tf!(
                    "無法設定封包過濾器：{e}",
                    e = last_os_error()
                )));
            }
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = std::thread::Builder::new()
            .name("dns-packet".into())
            .spawn(move || capture_loop(fd, tx, dropped, stop2))
            .map_err(|e| AppError::Unsupported(e.to_string()))?;
        Ok(PacketCapture {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for PacketCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn capture_loop(fd: OwnedFd, tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 65_536];
    let mut owners = PortOwners::new();
    let mut held: VecDeque<(Instant, DnsEvent)> = VecDeque::new();
    let send = |ev: DnsEvent| {
        if tx.try_send(ev).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    };
    while !stop.load(Ordering::Relaxed) {
        while held.front().is_some_and(|(t, _)| t.elapsed() >= HOLD) {
            if let Some((_, ev)) = held.pop_front() {
                send(ev);
            }
        }
        // SAFETY: sockaddr_ll 是 POD；長度正確。
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: buf 與 sll 在呼叫期間有效。
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sll as *mut _ as *mut libc::sockaddr,
                &mut len,
            )
        };
        if n < 0 {
            match last_os_error().raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => break,
            }
        }
        if sll.sll_pkttype == libc::PACKET_OUTGOING {
            continue;
        }
        let Some(udp) = parse_ip_udp(&buf[..n as usize]) else {
            continue;
        };
        let pid = owners.owner(udp.dport);
        let Some(mut ev) = event_from_response(udp.payload, Utc::now(), pid) else {
            continue;
        };
        if pid.is_some() && pid == owners.resolved {
            // resolved 代查：先扣住，等 stub 回給程式的那筆
            ev.pid = None;
            held.push_back((Instant::now(), ev));
            continue;
        }
        held.retain(|(_, h)| !(h.name == ev.name && h.qtype == ev.qtype));
        send(ev);
    }
    for (_, ev) in held {
        send(ev);
    }
}
