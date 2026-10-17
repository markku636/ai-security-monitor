//! 網路介面：讀累計位元組計數器、判斷虛擬介面、算出這段時間的差值（含計數器歸零／32 位元溢位）。
//!
//! 總量只算實體介面（不含迴路與虛擬介面）：VPN、Docker、WSL、Hyper-V 的流量其實也會經過實體網卡，
//! 加進去會重複計算。虛擬介面仍然列在 `interfaces` 裡，標 `virtual: true`。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 一個介面在某一刻的累計計數器。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IfaceCounters {
    pub rx: u64,
    pub tx: u64,
}

/// 這段時間內一個介面的收發量。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfaceSample {
    pub name: String,
    /// 虛擬介面（VPN、Docker、WSL、Hyper-V、VirtualBox…）：不算進總量。
    #[serde(rename = "virtual", default)]
    pub is_virtual: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// 每秒 100 Gbps 以上就不可能是真的（換成歸零處理）。
const MAX_BYTES_PER_SEC: f64 = 100e9 / 8.0;

/// 累計計數器的差值。
/// - 正常：`cur - prev`；
/// - `cur < prev`、`prev` 已接近 32 位元上限（> 3 GiB）而 `cur` 很小（< 1 GiB）：當成 32 位元計數器溢位
///   （舊驅動、部分虛擬網卡），差值是繞一圈的量；
/// - 其他 `cur < prev`：計數器歸零（重開機、網卡重設、休眠喚醒），只算歸零後的 `cur`；
/// - 差值換算超過 100 Gbps：夾到上限（避免把錯亂的計數器當成流量尖峰）。
pub fn counter_delta(prev: u64, cur: u64, elapsed_s: f64) -> u64 {
    const GIB: u64 = 1 << 30;
    let max = (elapsed_s.max(1.0) * MAX_BYTES_PER_SEC) as u64;
    let d = if cur >= prev {
        cur - prev
    } else if prev <= u32::MAX as u64 && prev > 3 * GIB && cur < GIB {
        (u32::MAX as u64 - prev) + cur + 1
    } else {
        cur
    };
    if d > max {
        cur.min(max)
    } else {
        d
    }
}

/// 迴路介面（完全不列）。
pub fn is_loopback(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "lo" || n.starts_with("lo0") || n.contains("loopback")
}

/// 依名稱判斷是不是虛擬介面（三個平台共用；Linux 另看 /sys/class/net 是否在 devices/virtual 底下）。
pub fn is_virtual_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "docker",
        "veth",
        "br-",
        "virbr",
        "vmnet",
        "vboxnet",
        "tun",
        "tap",
        "utun",
        "wg",
        "tailscale",
        "zt",
        "ipsec",
        "ppp",
        "gif",
        "stf",
        "awdl",
        "llw",
        "bridge",
        "anpi",
        "ap1",
        "feth",
        "vnic",
        "vmenet",
        "cni",
        "flannel",
        "cali",
        "kube",
        "lxc",
        "lxd",
        "podman",
        "nordlynx",
        "proton",
        "ham",
        "isatap",
        "teredo",
    ];
    const CONTAINS: &[&str] = &[
        "vethernet",
        "hyper-v",
        "virtualbox",
        "vmware",
        "virtual",
        "wsl",
        "tap-windows",
        "wintun",
        "wireguard",
        "tailscale",
        "zerotier",
        "openvpn",
        "npcap",
        "pseudo",
        "teredo",
        "isatap",
        "6to4",
        "vpn",
        "docker",
    ];
    PREFIXES.iter().any(|p| n.starts_with(p)) || CONTAINS.iter().any(|c| n.contains(c))
}

/// Linux：`/sys/class/net/<名稱>` 指向 `…/devices/virtual/net/…` 就是虛擬介面。
#[cfg(target_os = "linux")]
fn sysfs_virtual(name: &str) -> Option<bool> {
    if name.contains('/') || name.contains("..") {
        return None;
    }
    let target = std::fs::read_link(format!("/sys/class/net/{name}")).ok()?;
    Some(target.to_string_lossy().contains("/virtual/"))
}

#[cfg(not(target_os = "linux"))]
fn sysfs_virtual(_name: &str) -> Option<bool> {
    None
}

pub fn is_virtual(name: &str) -> bool {
    sysfs_virtual(name).unwrap_or(false) || is_virtual_name(name)
}

/// Windows 在網卡上疊的篩選層（`Wi-Fi-Native WiFi Filter Driver-0000`、`Ethernet-WFP Native MAC Layer
/// LightWeight Filter-0000`、`…-QoS Packet Scheduler-0000`、`…-Npcap Packet Driver (NPCAP)-0000`）：
/// 計數器跟底下的網卡一模一樣，列進來會重複計算，整個不列。
pub fn is_filter_layer(name: &str, all: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    const PHRASES: &[&str] = &[
        "filter driver",
        "packet scheduler",
        "lightweight filter",
        "native mac layer",
        "wfp ",
        "npcap packet driver",
        "qos packet",
    ];
    if PHRASES.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // 「<另一個介面名稱>-<任何字>-0000」
    let suffix = name
        .rsplit_once('-')
        .map(|(_, n)| n.len() == 4 && n.chars().all(|c| c.is_ascii_digit()));
    suffix == Some(true)
        && all
            .iter()
            .any(|other| *other != name && name.len() > other.len() + 1 && name.starts_with(&format!("{other}-")))
}

/// 讀所有非迴路介面的累計計數器（`nets` 要先 refresh）；Windows 的篩選層不列。
pub fn read_counters(nets: &sysinfo::Networks) -> BTreeMap<String, IfaceCounters> {
    let names: Vec<&str> = nets.keys().map(String::as_str).collect();
    nets.iter()
        .filter(|(name, _)| !is_loopback(name) && !is_filter_layer(name, &names))
        .map(|(name, d)| {
            (
                name.clone(),
                IfaceCounters {
                    rx: d.total_received(),
                    tx: d.total_transmitted(),
                },
            )
        })
        .collect()
}

/// 兩次讀數 → 每個介面的差值（新出現的介面這次不算，下一次才有基準）、實體介面的總量。
pub fn deltas(
    prev: &BTreeMap<String, IfaceCounters>,
    cur: &BTreeMap<String, IfaceCounters>,
    elapsed_s: f64,
    virtual_of: &dyn Fn(&str) -> bool,
) -> (Vec<IfaceSample>, u64, u64) {
    let mut out = Vec::new();
    let (mut rx, mut tx) = (0u64, 0u64);
    let (mut vrx, mut vtx) = (0u64, 0u64);
    let mut physical = 0usize;
    for (name, c) in cur {
        let Some(p) = prev.get(name) else { continue };
        let s = IfaceSample {
            name: crate::util::text::clip(name, 64),
            is_virtual: virtual_of(name),
            rx_bytes: counter_delta(p.rx, c.rx, elapsed_s),
            tx_bytes: counter_delta(p.tx, c.tx, elapsed_s),
        };
        if s.is_virtual {
            vrx = vrx.saturating_add(s.rx_bytes);
            vtx = vtx.saturating_add(s.tx_bytes);
        } else {
            physical += 1;
            rx = rx.saturating_add(s.rx_bytes);
            tx = tx.saturating_add(s.tx_bytes);
        }
        out.push(s);
    }
    // 只有虛擬介面（例如跑在容器裡，eth0 其實是 veth）：只好算虛擬介面的量
    if physical == 0 {
        rx = vrx;
        tx = vtx;
    }
    // 流量大的在前；名稱排序當作次序（穩定輸出）
    out.sort_by(|a, b| {
        (b.rx_bytes + b.tx_bytes)
            .cmp(&(a.rx_bytes + a.tx_bytes))
            .then_with(|| a.name.cmp(&b.name))
    });
    out.truncate(MAX_IFACES);
    (out, rx, tx)
}

/// 每個樣本最多列幾個介面（容器主機可能有上百個 veth）。
pub const MAX_IFACES: usize = 24;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_normal_wrap_and_reset() {
        assert_eq!(counter_delta(100, 250, 60.0), 150);
        // 32 位元溢位：繞一圈
        assert_eq!(counter_delta(u32::MAX as u64 - 9, 20, 60.0), 30);
        // 64 位元計數器變小：歸零（重開機／網卡重設），只算歸零後的量
        assert_eq!(counter_delta(10_000_000_000, 5_000, 60.0), 5_000);
        // 32 位元範圍內、但不是接近上限：重開機歸零，不是溢位
        assert_eq!(counter_delta(1_000_000_000, 500, 60.0), 500);
        // 超過 100 Gbps：不可能，夾到上限
        let huge = counter_delta(0, u64::MAX / 2, 1.0);
        assert!(huge <= (MAX_BYTES_PER_SEC as u64) + 1, "{huge}");
        assert_eq!(counter_delta(5, 5, 60.0), 0);
    }

    #[test]
    fn interface_classification() {
        for v in [
            "docker0",
            "veth12ab",
            "br-3f2a",
            "vEthernet (WSL)",
            "vEthernet (Default Switch)",
            "utun3",
            "tun0",
            "wg0",
            "tailscale0",
            "VirtualBox Host-Only Network",
            "VMware Network Adapter VMnet8",
            "awdl0",
            "llw0",
            "bridge100",
        ] {
            assert!(is_virtual_name(v), "{v} should be virtual");
        }
        for p in [
            "eth0",
            "en0",
            "wlan0",
            "Ethernet",
            "Wi-Fi",
            "enp3s0",
            "wlp2s0",
            "乙太網路",
        ] {
            assert!(!is_virtual_name(p), "{p} should be physical");
        }
        assert!(is_loopback("lo"));
        assert!(is_loopback("lo0"));
        assert!(is_loopback("Loopback Pseudo-Interface 1"));
        assert!(!is_loopback("eth0"));

        let all = [
            "Wi-Fi 2",
            "Wi-Fi 2-Native WiFi Filter Driver-0000",
            "Ethernet",
            "Ethernet-Foo Bar-0001",
            "Hub-2024",
        ];
        assert!(is_filter_layer("Wi-Fi 2-Native WiFi Filter Driver-0000", &all));
        assert!(is_filter_layer("Wi-Fi 2-Virtual WiFi Filter Driver-0000", &all));
        assert!(is_filter_layer(
            "Ethernet-WFP Native MAC Layer LightWeight Filter-0000",
            &all
        ));
        assert!(is_filter_layer("Ethernet-Foo Bar-0001", &all));
        assert!(!is_filter_layer("Wi-Fi 2", &all));
        assert!(!is_filter_layer("Ethernet", &all));
        assert!(!is_filter_layer("Hub-2024", &all), "no base interface named Hub");
    }

    #[test]
    fn totals_skip_virtual_and_new_interfaces() {
        let c = |rx, tx| IfaceCounters { rx, tx };
        let prev: BTreeMap<String, IfaceCounters> =
            [("eth0".to_string(), c(1_000, 500)), ("docker0".to_string(), c(0, 0))].into();
        let cur: BTreeMap<String, IfaceCounters> = [
            ("eth0".to_string(), c(4_000, 1_500)),
            ("docker0".to_string(), c(9_000, 9_000)),
            ("wlan0".to_string(), c(77, 77)),
        ]
        .into();
        let (list, rx, tx) = deltas(&prev, &cur, 60.0, &is_virtual_name);
        assert_eq!((rx, tx), (3_000, 1_000));
        assert_eq!(list.len(), 2, "wlan0 is new: no baseline yet");
        assert_eq!(list[0].name, "docker0");
        assert!(list[0].is_virtual);
        assert_eq!(list[1].rx_bytes, 3_000);
        let json = serde_json::to_value(&list[0]).unwrap();
        assert_eq!(json["virtual"], true);

        // 只有虛擬介面（容器裡）：總量改算虛擬介面
        let only_v: BTreeMap<String, IfaceCounters> = [("veth0".to_string(), c(0, 0))].into();
        let only_v2: BTreeMap<String, IfaceCounters> = [("veth0".to_string(), c(10, 20))].into();
        let (_, rx, tx) = deltas(&only_v, &only_v2, 60.0, &is_virtual_name);
        assert_eq!((rx, tx), (10, 20));
    }
}
