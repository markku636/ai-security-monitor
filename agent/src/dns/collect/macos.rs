//! macOS：BPF（`/dev/bpf*`）監聽各網卡上 UDP 53 的回應（需要 root）。
//!
//! - 每個啟用中、非 loopback 的網卡（含 VPN 的 `utun*`）開一個 BPF，核心過濾器只放行「UDP 來源 port 53」。
//! - 程式的查詢都由 mDNSResponder 代送，封包看不出是哪個 App；改用「解析出的 IP → 之後哪個程式連過去」
//!   在連線表上反推（[`crate::dns::annotate_domains`]）。
//! - 每分鐘重新列一次網卡（換 Wi-Fi、開 VPN 時跟上）。
//! - NetworkExtension 的 DNS proxy 要 Apple 授權與系統延伸套件，這裡不用。

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::mpsc::Sender;

use super::packet::{dns_response_filter, event_from_response, parse_ip_udp, BpfInsn};
use crate::dns::model::DnsEvent;
use crate::error::{AppError, AppResult};

// BPF ioctl（macOS 64 位元 ABI；自己定義，不依賴 libc 版本）
const BIOCGBLEN: libc::c_ulong = 0x4004_4266;
const BIOCSBLEN: libc::c_ulong = 0xc004_4266;
const BIOCGDLT: libc::c_ulong = 0x4004_426a;
const BIOCSETIF: libc::c_ulong = 0x8020_426c;
const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270;
const BIOCSETF: libc::c_ulong = 0x8010_4267;
const BIOCSRTIMEOUT: libc::c_ulong = 0x8010_426d;
const DLT_NULL: u32 = 0;
const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 12;
const DLT_LOOP: u32 = 108;
const BUF_LEN: u32 = 512 * 1024;
const RESCAN_EVERY: Duration = Duration::from_secs(60);

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const BpfInsn,
}

struct Tap {
    fd: OwnedFd,
    /// 鏈路層標頭長度。
    base: usize,
    buf_len: usize,
}

/// 啟用中、非 loopback、有 IPv4 位址（或是 VPN 介面）的網卡名稱。
fn interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 配置串列，最後 freeifaddrs 釋放；只讀取欄位。
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            let flags = ifa.ifa_flags as libc::c_int;
            if flags & libc::IFF_UP == 0 || flags & libc::IFF_LOOPBACK != 0 || ifa.ifa_name.is_null() {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
            let fam = if ifa.ifa_addr.is_null() {
                -1
            } else {
                i32::from((*ifa.ifa_addr).sa_family)
            };
            let vpn = name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("ppp");
            if (fam == libc::AF_INET || vpn) && !out.contains(&name) {
                out.push(name);
            }
        }
        libc::freeifaddrs(ifap);
    }
    out
}

fn open_bpf() -> Option<OwnedFd> {
    for i in 0..256 {
        let path = std::ffi::CString::new(format!("/dev/bpf{i}")).ok()?;
        // SAFETY: path 以 0 結尾。
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            // SAFETY: 剛開啟的有效 fd。
            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EBUSY) => continue,
            _ => return None,
        }
    }
    None
}

fn open_tap(ifname: &str) -> AppResult<Tap> {
    let fd = open_bpf().ok_or_else(|| {
        let e = std::io::Error::last_os_error();
        AppError::Unsupported(if matches!(e.raw_os_error(), Some(libc::EACCES) | Some(libc::EPERM)) {
            t!("監聽 DNS 封包需要 root 權限").into()
        } else {
            tf!("無法開啟封包擷取：{e}", e = e)
        })
    })?;
    let raw = fd.as_raw_fd();
    let mut blen: u32 = BUF_LEN;
    let mut ifr = [0u8; 32];
    let name = ifname.as_bytes();
    ifr[..name.len().min(15)].copy_from_slice(&name[..name.len().min(15)]);
    let one: u32 = 1;
    let mut dlt: u32 = 0;
    let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: 各 ioctl 的參數型別與大小符合 macOS 64 位元 ABI。
    unsafe {
        libc::ioctl(raw, BIOCSBLEN, &mut blen);
        if libc::ioctl(raw, BIOCSETIF, ifr.as_ptr()) != 0 {
            return Err(AppError::Unsupported(tf!(
                "無法監聽網卡 {name}：{e}",
                name = ifname,
                e = std::io::Error::last_os_error()
            )));
        }
        libc::ioctl(raw, BIOCIMMEDIATE, &one);
        libc::ioctl(raw, BIOCGDLT, &mut dlt);
    }
    let base: u32 = match dlt {
        DLT_EN10MB => 14,
        DLT_NULL | DLT_LOOP => 4,
        DLT_RAW => 0,
        other => {
            return Err(AppError::Unsupported(tf!(
                "網卡 {name} 的鏈路類型 {dlt} 不支援",
                name = ifname,
                dlt = other
            )))
        }
    };
    let prog = dns_response_filter(base);
    let bp = BpfProgram {
        bf_len: prog.len() as u32,
        bf_insns: prog.as_ptr(),
    };
    let mut actual: u32 = 0;
    // SAFETY: bp 指向的指令在呼叫期間有效（核心會複製一份）。
    unsafe {
        if libc::ioctl(raw, BIOCSETF, &bp) != 0 {
            return Err(AppError::Unsupported(tf!(
                "無法設定封包過濾器：{e}",
                e = std::io::Error::last_os_error()
            )));
        }
        libc::ioctl(raw, BIOCSRTIMEOUT, &tv);
        libc::ioctl(raw, BIOCGBLEN, &mut actual);
    }
    Ok(Tap {
        fd,
        base: base as usize,
        buf_len: if actual > 0 { actual as usize } else { BUF_LEN as usize },
    })
}

pub struct BpfCapture {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl BpfCapture {
    pub fn start(tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>) -> AppResult<BpfCapture> {
        let mut taps = HashMap::new();
        let mut last_err = None;
        for name in interfaces() {
            match open_tap(&name) {
                Ok(t) => {
                    taps.insert(name, t);
                }
                Err(e) => last_err = Some(e),
            }
        }
        if taps.is_empty() {
            return Err(last_err.unwrap_or_else(|| AppError::Unsupported(t!("找不到可以監聽的網卡").into())));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = std::thread::Builder::new()
            .name("dns-bpf".into())
            .spawn(move || capture_loop(taps, tx, dropped, stop2))
            .map_err(|e| AppError::Unsupported(e.to_string()))?;
        Ok(BpfCapture {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for BpfCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// 一次 read 拿到的多筆紀錄：`bpf_hdr`（時間 8、caplen 4、datalen 4、hdrlen 2）＋封包，以 4 bytes 對齊。
fn records(buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 18 <= buf.len() {
        let caplen = u32::from_ne_bytes([buf[off + 8], buf[off + 9], buf[off + 10], buf[off + 11]]) as usize;
        let hdrlen = usize::from(u16::from_ne_bytes([buf[off + 16], buf[off + 17]]));
        let start = off + hdrlen;
        let end = start + caplen;
        if hdrlen < 18 || end > buf.len() {
            break;
        }
        out.push(&buf[start..end]);
        off += (hdrlen + caplen + 3) & !3;
    }
    out
}

fn capture_loop(mut taps: HashMap<String, Tap>, tx: Sender<DnsEvent>, dropped: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut rescan = Instant::now();
    let mut buf = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        if rescan.elapsed() > RESCAN_EVERY {
            rescan = Instant::now();
            let now = interfaces();
            taps.retain(|name, _| now.contains(name));
            for name in now {
                if let std::collections::hash_map::Entry::Vacant(e) = taps.entry(name) {
                    if let Ok(t) = open_tap(e.key()) {
                        e.insert(t);
                    }
                }
            }
        }
        let names: Vec<String> = taps.keys().cloned().collect();
        let mut fds: Vec<libc::pollfd> = names
            .iter()
            .map(|n| libc::pollfd {
                fd: taps[n].fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if fds.is_empty() {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        // SAFETY: fds 在呼叫期間有效。
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) };
        if r <= 0 {
            continue;
        }
        let mut dead = Vec::new();
        for (i, p) in fds.iter().enumerate() {
            if p.revents == 0 {
                continue;
            }
            let tap = &taps[&names[i]];
            if p.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0 {
                dead.push(names[i].clone());
                continue;
            }
            buf.resize(tap.buf_len, 0);
            // SAFETY: buf 長度等於 BPF 緩衝區大小（BPF 要求 read 的長度與它一致）。
            let n = unsafe { libc::read(tap.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                continue;
            }
            for pkt in records(&buf[..n as usize]) {
                let Some(ip) = pkt.get(tap.base..) else {
                    continue;
                };
                let Some(udp) = parse_ip_udp(ip) else {
                    continue;
                };
                if let Some(ev) = event_from_response(udp.payload, Utc::now(), None) {
                    if tx.try_send(ev).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        for d in dead {
            taps.remove(&d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_bpf_records() {
        let mut buf = Vec::new();
        for pkt in [&b"abcde"[..], &b"xyz"[..]] {
            let mut h = vec![0u8; 18];
            h[8..12].copy_from_slice(&(pkt.len() as u32).to_ne_bytes());
            h[12..16].copy_from_slice(&(pkt.len() as u32).to_ne_bytes());
            h[16..18].copy_from_slice(&18u16.to_ne_bytes());
            buf.extend_from_slice(&h);
            buf.extend_from_slice(pkt);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        assert_eq!(records(&buf), vec![&b"abcde"[..], &b"xyz"[..]]);
        assert!(records(&buf[..10]).is_empty());
    }
}
