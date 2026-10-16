//! 一次 socket 快照：netstat2（socket＋PID）× sysinfo（行程）→ `Connection` / `Listener`。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use super::hashcache::HashCache;
use crate::error::{AppError, AppResult};
use crate::model::connection::{Connection, Direction, Listener, ProcessRef};
use crate::model::verdict::Verdict;
use crate::util::net::{classify, IpClass};

#[derive(Debug, Default, Clone)]
pub struct SnapshotResult {
    pub connections: Vec<Connection>,
    pub listeners: Vec<Listener>,
    pub warnings: Vec<String>,
    /// 有 socket 對不到 PID（通常是他人行程且未提權）。
    pub partial: bool,
}

/// UDP 的暫時 port 下限（Linux 32768、Windows 49152；取較小者避免漏掉 listener）。
const UDP_EPHEMERAL_FLOOR: u16 = 32768;

fn tcp_state_str(s: &TcpState) -> &'static str {
    match s {
        TcpState::Closed => "CLOSED",
        TcpState::Listen => "LISTEN",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynReceived => "SYN_RECV",
        TcpState::Established => "ESTABLISHED",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::Closing => "CLOSING",
        TcpState::LastAck => "LAST_ACK",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::DeleteTcb => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn is_any(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

/// 行程表（一次刷新、多次查）。
pub struct ProcessTable {
    sys: System,
    users: Users,
    cache: HashCache,
    refs: HashMap<u32, ProcessRef>,
    hash_exes: bool,
}

impl ProcessTable {
    pub fn load(config_dir: &Path, hash_exes: bool) -> Self {
        let mut sys = System::new();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::Always)
                .with_cmd(UpdateKind::Always)
                .with_user(UpdateKind::Always),
        );
        let users = Users::new_with_refreshed_list();
        let cache = HashCache::load(config_dir);
        Self {
            sys,
            users,
            cache,
            refs: HashMap::new(),
            hash_exes,
        }
    }

    pub fn get(&mut self, pid: u32) -> Option<ProcessRef> {
        if let Some(r) = self.refs.get(&pid) {
            return Some(r.clone());
        }
        let p = self.sys.process(sysinfo::Pid::from_u32(pid))?;
        let exe = p.exe().map(|e| e.to_string_lossy().to_string());
        let sha256 = if self.hash_exes {
            exe.as_deref().and_then(|e| self.cache.sha256(Path::new(e)))
        } else {
            None
        };
        let cmdline = {
            let joined = p
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            if joined.is_empty() {
                None
            } else {
                Some(crate::util::text::clip(&joined, 240))
            }
        };
        let user = p
            .user_id()
            .and_then(|uid| self.users.get_user_by_id(uid))
            .map(|u| u.name().to_string());
        let r = ProcessRef {
            pid,
            name: p.name().to_string_lossy().to_string(),
            exe,
            cmdline,
            parent_pid: p.parent().map(|pp| pp.as_u32()),
            user,
            sha256,
        };
        self.refs.insert(pid, r.clone());
        Some(r)
    }

    pub fn finish(self, config_dir: &Path) {
        let _ = self.cache.save(config_dir);
    }
}

/// 取快照。`config_dir` 給 exe 雜湊快取用。
pub fn take(config_dir: &Path) -> AppResult<SnapshotResult> {
    take_with(config_dir, true)
}

/// `hash_exes = false` 跳過 exe 雜湊（測試 / 快速預覽用）。
pub fn take_with(config_dir: &Path, hash_exes: bool) -> AppResult<SnapshotResult> {
    let sockets = netstat2::get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .map_err(|e| AppError::Scan(tf!("列舉 socket 失敗：{e}", e = e)))?;

    let mut procs = ProcessTable::load(config_dir, hash_exes);
    let mut out = SnapshotResult::default();

    // 第一遍：listener 集合（判斷 inbound 用）。
    let mut listen_ports: HashSet<(String, u16)> = HashSet::new();
    for s in &sockets {
        match &s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) if t.state == TcpState::Listen => {
                listen_ports.insert(("tcp".into(), t.local_port));
            }
            ProtocolSocketInfo::Udp(u) if u.local_port < UDP_EPHEMERAL_FLOOR => {
                listen_ports.insert(("udp".into(), u.local_port));
            }
            _ => {}
        }
    }

    let mut seen_listeners: HashSet<(String, IpAddr, u16)> = HashSet::new();
    for s in &sockets {
        // pid 0 是核心保留 / TIME_WAIT 殘留，沒有可對應的行程。
        let pid = s.associated_pids.first().copied().filter(|p| *p != 0);
        if pid.is_none() && !s.associated_pids.contains(&0) {
            out.partial = true;
        }
        let process = pid.and_then(|p| procs.get(p));
        match &s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) => {
                let (direction, remote_ip, remote_port) = if t.state == TcpState::Listen {
                    (Direction::Listening, None, None)
                } else {
                    let local_cls = classify(t.local_addr);
                    let remote_cls = classify(t.remote_addr);
                    let dir = if remote_cls == IpClass::Loopback && local_cls == IpClass::Loopback {
                        Direction::Local
                    } else if listen_ports.contains(&("tcp".to_string(), t.local_port))
                        && !listen_ports.contains(&("tcp".to_string(), t.remote_port))
                    {
                        Direction::Inbound
                    } else {
                        Direction::Outbound
                    };
                    (dir, Some(t.remote_addr), Some(t.remote_port))
                };
                if t.state == TcpState::Listen {
                    let key = ("tcp".to_string(), t.local_addr, t.local_port);
                    if seen_listeners.insert(key) {
                        out.listeners.push(Listener {
                            proto: "tcp".into(),
                            bind_ip: t.local_addr,
                            port: t.local_port,
                            process: process.clone(),
                            exposed: is_any(t.local_addr) || classify(t.local_addr) != IpClass::Loopback,
                        });
                    }
                }
                out.connections.push(Connection {
                    proto: "tcp".into(),
                    local_ip: t.local_addr,
                    local_port: t.local_port,
                    remote_ip,
                    remote_port,
                    state: tcp_state_str(&t.state).into(),
                    direction,
                    process,
                    geo: None,
                    verdict: Verdict::default(),
                    bytes_in: None,
                    bytes_out: None,
                });
            }
            ProtocolSocketInfo::Udp(u) => {
                // 暫時 port 的 UDP socket（DNS client 等）沒有可判讀的對端，略過以免噪音。
                if u.local_port >= UDP_EPHEMERAL_FLOOR {
                    continue;
                }
                let key = ("udp".to_string(), u.local_addr, u.local_port);
                if seen_listeners.insert(key) {
                    out.listeners.push(Listener {
                        proto: "udp".into(),
                        bind_ip: u.local_addr,
                        port: u.local_port,
                        process: process.clone(),
                        exposed: is_any(u.local_addr) || classify(u.local_addr) != IpClass::Loopback,
                    });
                }
                out.connections.push(Connection {
                    proto: "udp".into(),
                    local_ip: u.local_addr,
                    local_port: u.local_port,
                    remote_ip: None,
                    remote_port: None,
                    state: "BOUND".into(),
                    direction: Direction::Listening,
                    process,
                    geo: None,
                    verdict: Verdict::default(),
                    bytes_in: None,
                    bytes_out: None,
                });
            }
        }
    }

    procs.finish(config_dir);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_runs_and_has_consistent_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let snap = take_with(dir.path(), false).expect("snapshot");
        for l in &snap.listeners {
            assert!(snap
                .connections
                .iter()
                .any(|c| c.direction == Direction::Listening && c.local_port == l.port && c.proto == l.proto));
        }
        for c in &snap.connections {
            if c.direction == Direction::Listening {
                assert!(c.remote_ip.is_none());
            } else {
                assert!(c.remote_ip.is_some());
            }
        }
    }
}
