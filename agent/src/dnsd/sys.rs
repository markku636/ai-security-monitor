//! 平台相關的 socket 設定：
//! - Linux：每個 worker 一個 SO_REUSEPORT UDP socket，核心把封包分散到各核心。
//! - macOS：BSD 的 SO_REUSEPORT 不會分流，用一個 socket 給多個 task 共用。
//! - Windows：多個 task 共用一個 socket（IOCP）；**關掉 SIO_UDP_CONNRESET**，否則回應送到已關閉的用戶端 port
//!   收到 ICMP 不可達後，下一次 recv 會報錯中斷。綁 53 在 Windows 不需要系統管理員，所以用 **SO_EXCLUSIVEADDRUSE**
//!   獨佔 port，別的程式不能用 SO_REUSEADDR 綁同一個位址搶走查詢。
//! - UDP 一律不設 SO_REUSEADDR（Linux 上會讓另一個 socket 綁同一個位址分走封包）；Linux 多核心分流用 SO_REUSEPORT（核心會檢查同一個使用者）。

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};

/// 建一個 UDP socket（非阻塞、大接收緩衝區）；`reuse_port` 只在 Linux 有作用。
pub fn udp_socket(addr: SocketAddr, reuse_port: bool) -> std::io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    exclusive(&s);
    #[cfg(target_os = "linux")]
    if reuse_port {
        s.set_reuse_port(true)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = reuse_port;
    let _ = s.set_recv_buffer_size(4 << 20);
    let _ = s.set_send_buffer_size(4 << 20);
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    let std: std::net::UdpSocket = s.into();
    disable_connreset(&std);
    Ok(std)
}

pub fn tcp_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    // Unix：重啟時不必等 TIME_WAIT；Windows：獨佔
    #[cfg(unix)]
    s.set_reuse_address(true)?;
    exclusive(&s);
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    Ok(s.into())
}

/// 每個監聽位址開幾個 UDP socket（Linux 依核心數，其他平台 1 個）。
pub fn udp_sockets_per_addr() -> usize {
    if cfg!(target_os = "linux") {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8)
    } else {
        1
    }
}

/// 共用同一個 socket 的接收 task 數（Windows／macOS 用多個 task 一起收）。
pub fn tasks_per_socket() -> usize {
    if cfg!(target_os = "linux") {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(2, 8)
    }
}

#[cfg(windows)]
fn disable_connreset(s: &std::net::UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SOCKET};
    let flag: u32 = 0;
    let mut ret: u32 = 0;
    // SAFETY: 有效的 socket handle；輸入緩衝區是 4 bytes 的 BOOL。
    unsafe {
        WSAIoctl(
            s.as_raw_socket() as SOCKET,
            SIO_UDP_CONNRESET,
            &flag as *const u32 as *const core::ffi::c_void,
            4,
            std::ptr::null_mut(),
            0,
            &mut ret,
            std::ptr::null_mut(),
            None,
        );
    }
}

#[cfg(not(windows))]
fn disable_connreset(_s: &std::net::UdpSocket) {}

#[cfg(windows)]
fn exclusive(s: &Socket) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};
    let on: i32 = 1;
    // SAFETY: 有效的 socket handle（還沒 bind）；選項值是 4 bytes 的 BOOL。
    unsafe {
        setsockopt(
            s.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            &on as *const i32 as *const u8,
            4,
        );
    }
}

#[cfg(not(windows))]
fn exclusive(_s: &Socket) {}

/// 這台各網卡的位址（綁 0.0.0.0:53 失敗時，例如 Linux 的 systemd-resolved 佔了 127.0.0.53，改成逐一綁）。
pub fn interface_addrs() -> Vec<std::net::IpAddr> {
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut v: Vec<std::net::IpAddr> = nets
        .values()
        .flat_map(|d| d.ip_networks().iter().map(|n| n.addr))
        .filter(|ip| match ip {
            std::net::IpAddr::V4(_) => true,
            std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 別的 socket 用 SO_REUSEADDR 也綁不到同一個位址（Windows 靠 SO_EXCLUSIVEADDRUSE，其他平台本來就不行）。
    #[test]
    fn port_cannot_be_shared() {
        let a = udp_socket("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let addr = a.local_addr().unwrap();
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        s.set_reuse_address(true).unwrap();
        assert!(s.bind(&addr.into()).is_err(), "{addr} was shared");
    }
}
