//! 各程式的網路用量（盡力而為）：
//! - Windows：TCP 連線的延伸統計（`GetPerTcpConnectionEStats`）。要先對每條連線開啟統計
//!   （`SetPerTcpConnectionEStats`，需要系統管理員）；沒有權限時只讀得到別人已開啟的連線，通常是沒有。
//!   只算 TCP 的資料位元組（不含標頭與 UDP），連線在兩次取樣之間就關掉的最後那段量會漏掉。
//! - macOS：`nettop -P -L 1 -x`（每個程式累計收發量），兩次取樣相減。
//! - Linux：不裝 eBPF 拿不到，回 `None`（Hub 改顯示各程式的連線數）。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 一個程式（同名合併）這段時間的收發量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcNet {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// 最多列幾個程式。
pub const MAX_PROCS: usize = 10;

/// 依「程式名稱」合併、依總量排序、只留前 N 個（沒有流量的不列）。
pub fn top_by_name(items: impl IntoIterator<Item = (String, u64, u64)>) -> Vec<ProcNet> {
    let mut m: HashMap<String, (u64, u64)> = HashMap::new();
    for (name, rx, tx) in items {
        let e = m.entry(name).or_default();
        e.0 = e.0.saturating_add(rx);
        e.1 = e.1.saturating_add(tx);
    }
    let mut v: Vec<ProcNet> = m
        .into_iter()
        .filter(|(_, (rx, tx))| rx.saturating_add(*tx) > 0)
        .map(|(name, (rx, tx))| ProcNet {
            name: crate::util::text::clip(&name, 80),
            rx_bytes: rx,
            tx_bytes: tx,
        })
        .collect();
    v.sort_by(|a, b| {
        b.rx_bytes
            .saturating_add(b.tx_bytes)
            .cmp(&a.rx_bytes.saturating_add(a.tx_bytes))
            .then_with(|| a.name.cmp(&b.name))
    });
    v.truncate(MAX_PROCS);
    v
}

/// 延伸統計沒開啟時計數器是 -1（全 1）；大於 2^62 的值一律當成「沒有資料」。
pub fn valid_counter(v: u64) -> bool {
    v < (1u64 << 62)
}

/// 累計值 → 這段時間的差值（第一次看到的鍵當作從 0 開始；變小當作重新計數）。
pub fn cumulative_deltas<K: std::hash::Hash + Eq + Clone>(
    prev: &HashMap<K, (u64, u64)>,
    cur: &HashMap<K, (u64, u64)>,
) -> Vec<(K, u64, u64)> {
    cur.iter()
        .map(|(k, &(rx, tx))| {
            let (prx, ptx) = prev.get(k).copied().unwrap_or((0, 0));
            let d = |p: u64, c: u64| if c >= p { c - p } else { c };
            (k.clone(), d(prx, rx), d(ptx, tx))
        })
        .collect()
}

/// `nettop -P -L 1 -x -J bytes_in,bytes_out` 的 CSV → (程式名稱, pid) → (收, 送) 累計值。
pub fn parse_nettop(out: &str) -> HashMap<(String, u32), (u64, u64)> {
    let mut m = HashMap::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 4 || f[1].is_empty() {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (f[2].trim().parse::<u64>(), f[3].trim().parse::<u64>()) else {
            continue;
        };
        // 「程式名稱.pid」；名稱本身可能有點
        let (name, pid) = match f[1].rsplit_once('.') {
            Some((n, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (n.to_string(), p.parse::<u32>().unwrap_or(0))
            }
            _ => (f[1].to_string(), 0),
        };
        let e: &mut (u64, u64) = m.entry((name, pid)).or_insert((0, 0));
        e.0 = e.0.saturating_add(rx);
        e.1 = e.1.saturating_add(tx);
    }
    m
}

/// macOS：跑一次 nettop（8 秒逾時）。
#[cfg(target_os = "macos")]
pub async fn nettop_snapshot() -> Option<HashMap<(String, u32), (u64, u64)>> {
    use crate::util::cmd::{CmdRunner, CmdSpec, RealRunner};
    let spec = CmdSpec::new("nettop", &["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"]).timeout(8_000);
    let out = RealRunner.run(&spec).await.ok()?;
    if !out.ok() {
        return None;
    }
    let m = parse_nettop(&out.stdout);
    (!m.is_empty()).then_some(m)
}

#[cfg(not(target_os = "macos"))]
pub async fn nettop_snapshot() -> Option<HashMap<(String, u32), (u64, u64)>> {
    None
}

/// 一條 TCP 連線（Windows 延伸統計的鍵）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub local: String,
    pub remote: String,
}

/// Windows：所有已建立的 TCP 連線的累計資料位元組（先開啟每條連線的統計，需要系統管理員）。
/// 回傳 `None` 表示一條都讀不到（沒權限、或系統不支援）。
#[cfg(windows)]
pub fn estats_snapshot(elevated: bool) -> Option<HashMap<ConnKey, (u64, u64)>> {
    win::snapshot(elevated)
}

#[cfg(not(windows))]
pub fn estats_snapshot(_elevated: bool) -> Option<HashMap<ConnKey, (u64, u64)>> {
    None
}

#[cfg(windows)]
mod win {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, GetTcp6Table2, GetTcpTable2, SetPerTcp6ConnectionEStats,
        SetPerTcpConnectionEStats, TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TcpConnectionEstatsData, MIB_TCP6ROW,
        MIB_TCP6ROW2, MIB_TCP6TABLE2, MIB_TCPROW2, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPTABLE2, MIB_TCP_STATE_ESTAB,
    };

    use super::ConnKey;

    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    /// 一次最多處理幾條連線（避免連線數爆量的伺服器拖太久）。
    const MAX_ROWS: usize = 4000;

    /// 呼叫「先問大小再取資料」的 API，緩衝區以 u64 對齊。
    fn table(call: impl Fn(*mut u8, *mut u32) -> u32) -> Option<Vec<u64>> {
        let mut size: u32 = 0;
        let r = call(std::ptr::null_mut(), &mut size);
        if r != ERROR_INSUFFICIENT_BUFFER && r != NO_ERROR {
            return None;
        }
        for _ in 0..3 {
            let mut buf = vec![0u64; (size as usize / 8) + 2];
            let mut sz = (buf.len() * 8) as u32;
            match call(buf.as_mut_ptr() as *mut u8, &mut sz) {
                NO_ERROR => return Some(buf),
                ERROR_INSUFFICIENT_BUFFER => size = sz,
                _ => return None,
            }
        }
        None
    }

    fn port(p: u32) -> u16 {
        u16::from_be(p as u16)
    }

    /// 開啟這條連線的統計後讀累計值。開啟失敗（沒權限）就不讀：沒開啟統計的連線，回來的數字是沒意義的殘值。
    fn rod_v4(row: &MIB_TCPROW_LH) -> Option<(u64, u64)> {
        let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
        let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
        // SAFETY: 指標都指向本函式內有效的結構，大小正確。
        unsafe {
            let set = SetPerTcpConnectionEStats(
                row,
                TcpConnectionEstatsData,
                &rw as *const _ as *const u8,
                0,
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32,
                0,
            );
            if set != NO_ERROR {
                return None;
            }
            let r = GetPerTcpConnectionEStats(
                row,
                TcpConnectionEstatsData,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                &mut rod as *mut _ as *mut u8,
                0,
                std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>() as u32,
            );
            (r == NO_ERROR && super::valid_counter(rod.DataBytesIn) && super::valid_counter(rod.DataBytesOut))
                .then_some((rod.DataBytesIn, rod.DataBytesOut))
        }
    }

    fn rod_v6(row: &MIB_TCP6ROW) -> Option<(u64, u64)> {
        let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: true };
        let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
        // SAFETY: 同上。
        unsafe {
            let set = SetPerTcp6ConnectionEStats(
                row,
                TcpConnectionEstatsData,
                &rw as *const _ as *const u8,
                0,
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32,
                0,
            );
            if set != NO_ERROR {
                return None;
            }
            let r = GetPerTcp6ConnectionEStats(
                row,
                TcpConnectionEstatsData,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                &mut rod as *mut _ as *mut u8,
                0,
                std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>() as u32,
            );
            (r == NO_ERROR && super::valid_counter(rod.DataBytesIn) && super::valid_counter(rod.DataBytesOut))
                .then_some((rod.DataBytesIn, rod.DataBytesOut))
        }
    }

    pub fn snapshot(elevated: bool) -> Option<HashMap<ConnKey, (u64, u64)>> {
        // 開啟統計需要系統管理員；沒有權限就不讀（讀到的是殘值）
        if !elevated {
            return None;
        }
        let mut out = HashMap::new();
        let mut seen = 0usize;
        // IPv4
        // SAFETY: GetTcpTable2 依我們給的大小寫入緩衝區；讀取時以 dwNumEntries 為界。
        if let Some(buf) = table(|p, sz| unsafe { GetTcpTable2(p as *mut MIB_TCPTABLE2, sz, 0) }) {
            let t = buf.as_ptr() as *const MIB_TCPTABLE2;
            let n = unsafe { (*t).dwNumEntries } as usize;
            let rows = unsafe { std::slice::from_raw_parts((*t).table.as_ptr(), n) };
            for r in rows.iter().filter(|r| r.dwState == MIB_TCP_STATE_ESTAB as u32) {
                if seen >= MAX_ROWS {
                    break;
                }
                seen += 1;
                let lh = lh_of(r);
                if let Some(v) = rod_v4(&lh) {
                    out.insert(
                        ConnKey {
                            pid: r.dwOwningPid,
                            local: format!(
                                "{}:{}",
                                Ipv4Addr::from(u32::from_be(r.dwLocalAddr)),
                                port(r.dwLocalPort)
                            ),
                            remote: format!(
                                "{}:{}",
                                Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)),
                                port(r.dwRemotePort)
                            ),
                        },
                        v,
                    );
                }
            }
        }
        // IPv6
        // SAFETY: 同上。
        if let Some(buf) = table(|p, sz| unsafe { GetTcp6Table2(p as *mut MIB_TCP6TABLE2, sz, 0) }) {
            let t = buf.as_ptr() as *const MIB_TCP6TABLE2;
            let n = unsafe { (*t).dwNumEntries } as usize;
            let rows: &[MIB_TCP6ROW2] = unsafe { std::slice::from_raw_parts((*t).table.as_ptr(), n) };
            for r in rows.iter().filter(|r| r.State == MIB_TCP_STATE_ESTAB) {
                if seen >= MAX_ROWS {
                    break;
                }
                seen += 1;
                let row = MIB_TCP6ROW {
                    State: r.State,
                    LocalAddr: r.LocalAddr,
                    dwLocalScopeId: r.dwLocalScopeId,
                    dwLocalPort: r.dwLocalPort,
                    RemoteAddr: r.RemoteAddr,
                    dwRemoteScopeId: r.dwRemoteScopeId,
                    dwRemotePort: r.dwRemotePort,
                };
                if let Some(v) = rod_v6(&row) {
                    // SAFETY: IN6_ADDR 是 16 bytes 的 union，以 Byte 陣列讀取。
                    let (l, rm) = unsafe { (r.LocalAddr.u.Byte, r.RemoteAddr.u.Byte) };
                    out.insert(
                        ConnKey {
                            pid: r.dwOwningPid,
                            local: format!("[{}]:{}", Ipv6Addr::from(l), port(r.dwLocalPort)),
                            remote: format!("[{}]:{}", Ipv6Addr::from(rm), port(r.dwRemotePort)),
                        },
                        v,
                    );
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    fn lh_of(r: &MIB_TCPROW2) -> MIB_TCPROW_LH {
        MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { dwState: r.dwState },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nettop_csv() {
        let out = "time,,bytes_in,bytes_out,\n10:01:02.1,launchd.1,0,0,\n10:01:02.1,Google Chrome He.912,1048576,2048,\n10:01:02.1,Google Chrome He.913,10,20,\n10:01:02.1,com.apple.WebKit.Networking.77,5,6,\nbad line\n";
        let m = parse_nettop(out);
        assert_eq!(m.get(&("Google Chrome He".to_string(), 912)), Some(&(1_048_576, 2_048)));
        assert_eq!(m.get(&("com.apple.WebKit.Networking".to_string(), 77)), Some(&(5, 6)));
        assert_eq!(m.len(), 4);
    }

    #[test]
    fn deltas_and_top() {
        let prev: HashMap<&str, (u64, u64)> = [("a", (100, 10)), ("b", (500, 0))].into();
        let cur: HashMap<&str, (u64, u64)> = [("a", (160, 30)), ("b", (20, 5)), ("c", (7, 0))].into();
        let mut d = cumulative_deltas(&prev, &cur);
        d.sort();
        assert_eq!(d, vec![("a", 60, 20), ("b", 20, 5), ("c", 7, 0)]);
        let top = top_by_name(vec![
            ("chrome".to_string(), 10, 10),
            ("chrome".to_string(), 5, 0),
            ("idle".to_string(), 0, 0),
            ("curl".to_string(), 100, 1),
        ]);
        assert_eq!(top.len(), 2, "zero-traffic processes are dropped");
        assert_eq!(top[0].name, "curl");
        assert_eq!((top[1].rx_bytes, top[1].tx_bytes), (15, 10));
        let many = top_by_name((0..30).map(|i| (format!("p{i}"), i + 1, 0)));
        assert_eq!(many.len(), MAX_PROCS);
        // 不會溢位
        let big = top_by_name(vec![("x".to_string(), u64::MAX, u64::MAX), ("x".to_string(), 5, 5)]);
        assert_eq!(big[0].rx_bytes, u64::MAX);
        assert!(!valid_counter(u64::MAX) && valid_counter(1 << 40));
    }

    #[test]
    fn estats_never_panics() {
        // Windows 上真的呼叫 API（CI 的 runner 是系統管理員）；沒權限或其他平台回 None
        let r = estats_snapshot(crate::elevate::is_elevated());
        if !cfg!(windows) || !crate::elevate::is_elevated() {
            assert!(r.is_none());
        }
        for (_, (rx, tx)) in r.unwrap_or_default() {
            assert!(valid_counter(rx) && valid_counter(tx));
        }
    }
}
