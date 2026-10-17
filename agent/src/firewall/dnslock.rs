//! DNS 鎖定（`fw dns-lock`）：擋掉程式直接連外部 DNS（53／853），只准連允許的 DNS 伺服器；
//! 可選另外擋掉常見加密 DNS（DoH）業者的 443，逼瀏覽器回到系統 DNS。
//!
//! - Windows：封鎖規則優先於允許規則，所以用「允許清單的補集」當封鎖的 RemoteAddress（規則 `ASA: dns-lock …`）。
//! - Linux nftables：`table inet asa` 裡獨立的 `dnslock` chain（其他動作重設 input／output chain 時不會被清掉）。
//! - Linux iptables＋ipset：`asa_dnsallow4/6`、`asa_doh4/6` 與 OUTPUT 規則。
//! - macOS pf：寫進 `com.asa` anchor（`to ! <asa_dnsallow> port { 53 853 }`）。
//!
//! 允許清單一定包含 loopback（本機的 DNS stub，例如 systemd-resolved 的 127.0.0.53）。

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// 常見公共加密 DNS 業者的位址（`--block-doh` 擋這些位址的 443）。
pub const DOH_IPS: [&str; 22] = [
    "1.1.1.1/32",
    "1.0.0.1/32",
    "2606:4700:4700::1111/128",
    "2606:4700:4700::1001/128",
    "8.8.8.8/32",
    "8.8.4.4/32",
    "2001:4860:4860::8888/128",
    "2001:4860:4860::8844/128",
    "9.9.9.9/32",
    "149.112.112.112/32",
    "2620:fe::fe/128",
    "2620:fe::9/128",
    "208.67.222.222/32",
    "208.67.220.220/32",
    "94.140.14.14/32",
    "94.140.15.15/32",
    "45.90.28.0/24",
    "45.90.30.0/24",
    "185.228.168.9/32",
    "185.228.169.9/32",
    "194.242.2.2/32",
    "76.76.2.0/24",
];

/// 期望狀態裡的 DNS 鎖定。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsLockState {
    pub allow: Vec<IpNet>,
    pub block_doh: bool,
    pub added_at: String,
}

pub fn loopbacks() -> Vec<IpNet> {
    vec!["127.0.0.0/8".parse().expect("valid"), "::1/128".parse().expect("valid")]
}

/// 允許清單：指定的位址＋loopback，去重。
pub fn normalize_allow(allow: &[IpNet]) -> Vec<IpNet> {
    let mut v: Vec<IpNet> = allow.iter().map(|n| n.trunc()).chain(loopbacks()).collect();
    v.sort();
    v.dedup();
    IpNet::aggregate(&v)
}

pub fn doh_nets() -> Vec<IpNet> {
    DOH_IPS.iter().filter_map(|s| s.parse().ok()).collect()
}

/// 從 `net` 挖掉 `hole`，回傳剩下的網段。
fn subtract(net: IpNet, hole: &IpNet, out: &mut Vec<IpNet>) {
    if hole.contains(&net) {
        return;
    }
    if !net.contains(hole) {
        out.push(net);
        return;
    }
    if let Ok(halves) = net.subnets(net.prefix_len() + 1) {
        for h in halves {
            subtract(h, hole, out);
        }
    }
}

/// 允許清單在整個位址空間的補集（IPv4、IPv6 分開）。
pub fn complement(allow: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let mut v4 = vec![IpNet::V4(Ipv4Net::new([0, 0, 0, 0].into(), 0).expect("valid"))];
    let mut v6 = vec![IpNet::V6(
        Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0).expect("valid"),
    )];
    for hole in allow {
        let target = if matches!(hole, IpNet::V4(_)) { &mut v4 } else { &mut v6 };
        let mut next = Vec::new();
        for n in target.drain(..) {
            subtract(n, hole, &mut next);
        }
        *target = next;
    }
    (IpNet::aggregate(&v4), IpNet::aggregate(&v6))
}

/// 這台實際在用的上游 DNS（systemd-resolved 的 stub 127.0.0.53 時，改讀 resolved 自己的上游清單）。
pub async fn current_upstreams() -> Vec<IpAddr> {
    let mut v = crate::hub::dns::system_config().await.servers;
    if v.iter().any(|ip| ip.is_loopback()) {
        if let Ok(text) = tokio::fs::read_to_string("/run/systemd/resolve/resolv.conf").await {
            v.extend(crate::hub::dns::parse_resolv_conf(&text).servers);
        }
    }
    v.sort();
    v.dedup();
    v
}

/// 目前在用、但不在允許清單裡的 DNS 伺服器（套用後會斷網的那些）。
pub fn uncovered(current: &[IpAddr], allow: &[IpNet]) -> Vec<IpAddr> {
    current
        .iter()
        .copied()
        .filter(|ip| !allow.iter().any(|n| n.contains(ip)))
        .collect()
}

fn ps_list(nets: &[IpNet]) -> String {
    let items: Vec<String> = nets.iter().map(|n| format!("'{n}'")).collect();
    format!("@({})", items.join(","))
}

/// Windows：兩條（TCP／UDP）封鎖規則，RemoteAddress＝允許清單的補集；可選擋 DoH 的 443。
pub fn win_lock_script(lock: &DnsLockState) -> String {
    let (c4, c6) = complement(&lock.allow);
    let all: Vec<IpNet> = c4.into_iter().chain(c6).collect();
    let mut s = format!(
        "Remove-NetFirewallRule -DisplayName 'ASA: dns-lock*' -ErrorAction SilentlyContinue\n$other = {}\nforeach ($p in @('TCP','UDP')) {{\n  New-NetFirewallRule -DisplayName \"ASA: dns-lock $p\" -Group 'ASA' -Direction Outbound -Action Block -Protocol $p -RemotePort 53,853 -RemoteAddress $other -Description 'asa: dns-lock' | Out-Null\n}}\n",
        ps_list(&all)
    );
    if lock.block_doh {
        s.push_str(&format!(
            "New-NetFirewallRule -DisplayName 'ASA: dns-lock doh' -Group 'ASA' -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 -RemoteAddress {} -Description 'asa: dns-lock doh' | Out-Null\n",
            ps_list(&doh_nets())
        ));
    }
    s.push_str("\"ok dns-lock\"\n");
    s
}

pub const WIN_UNLOCK: &str =
    "Remove-NetFirewallRule -DisplayName 'ASA: dns-lock*' -ErrorAction SilentlyContinue\n\"ok\"\n";

fn split(nets: &[IpNet]) -> (Vec<String>, Vec<String>) {
    let v4 = nets
        .iter()
        .filter(|n| matches!(n, IpNet::V4(_)))
        .map(|n| n.to_string())
        .collect();
    let v6 = nets
        .iter()
        .filter(|n| matches!(n, IpNet::V6(_)))
        .map(|n| n.to_string())
        .collect();
    (v4, v6)
}

/// nftables：獨立的 `dnslock` chain（hook output priority -9）。
pub fn nft_lock_script(lock: &DnsLockState) -> String {
    let (a4, a6) = split(&lock.allow);
    let (d4, d6) = if lock.block_doh {
        split(&doh_nets())
    } else {
        (Vec::new(), Vec::new())
    };
    let mut s = String::from(
        "add table inet asa
add set inet asa dns_allow4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa dns_allow6 { type ipv6_addr; flags interval; auto-merge; }
add set inet asa doh4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa doh6 { type ipv6_addr; flags interval; auto-merge; }
add chain inet asa dnslock { type filter hook output priority -9; policy accept; }
flush chain inet asa dnslock
flush set inet asa dns_allow4
flush set inet asa dns_allow6
flush set inet asa doh4
flush set inet asa doh6
",
    );
    for (set, items) in [("dns_allow4", &a4), ("dns_allow6", &a6), ("doh4", &d4), ("doh6", &d6)] {
        if !items.is_empty() {
            s.push_str(&format!("add element inet asa {set} {{ {} }}\n", items.join(", ")));
        }
    }
    s.push_str("add rule inet asa dnslock meta nfproto ipv4 meta l4proto { tcp, udp } th dport { 53, 853 } ip daddr != @dns_allow4 drop\n");
    s.push_str("add rule inet asa dnslock meta nfproto ipv6 meta l4proto { tcp, udp } th dport { 53, 853 } ip6 daddr != @dns_allow6 drop\n");
    if lock.block_doh {
        s.push_str("add rule inet asa dnslock tcp dport 443 ip daddr @doh4 drop\n");
        s.push_str("add rule inet asa dnslock tcp dport 443 ip6 daddr @doh6 drop\n");
    }
    s
}

pub const NFT_UNLOCK: &str = "delete chain inet asa dnslock\ndelete set inet asa dns_allow4\ndelete set inet asa dns_allow6\ndelete set inet asa doh4\ndelete set inet asa doh6\n";

/// iptables＋ipset：(ipset restore 內容, 要確保存在的規則)。規則形如 `OUTPUT -p udp --dport 53 -m set ! --match-set … dst -j DROP`。
pub fn ipset_lock(lock: &DnsLockState) -> (String, Vec<(&'static str, String)>) {
    let (a4, a6) = split(&lock.allow);
    let (d4, d6) = if lock.block_doh {
        split(&doh_nets())
    } else {
        (Vec::new(), Vec::new())
    };
    let mut restore = String::new();
    for (name, fam, items) in [
        ("asa_dnsallow4", "inet", &a4),
        ("asa_dnsallow6", "inet6", &a6),
        ("asa_doh4", "inet", &d4),
        ("asa_doh6", "inet6", &d6),
    ] {
        restore.push_str(&format!("create {name} hash:net family {fam} -exist\nflush {name}\n"));
        for it in items {
            restore.push_str(&format!("add {name} {it} -exist\n"));
        }
    }
    (restore, ipset_rules(lock.block_doh))
}

pub fn ipset_rules(block_doh: bool) -> Vec<(&'static str, String)> {
    let mut rules = Vec::new();
    for (bin, set) in [("iptables", "asa_dnsallow4"), ("ip6tables", "asa_dnsallow6")] {
        for proto in ["udp", "tcp"] {
            for port in [53, 853] {
                rules.push((
                    bin,
                    format!("OUTPUT -p {proto} --dport {port} -m set ! --match-set {set} dst -j DROP"),
                ));
            }
        }
    }
    if block_doh {
        rules.push((
            "iptables",
            "OUTPUT -p tcp --dport 443 -m set --match-set asa_doh4 dst -j DROP".to_string(),
        ));
        rules.push((
            "ip6tables",
            "OUTPUT -p tcp --dport 443 -m set --match-set asa_doh6 dst -j DROP".to_string(),
        ));
    }
    rules
}

pub const PF_DNSALLOW: &str = "/etc/pf.anchors/asa_dnsallow.txt";
pub const PF_DOH: &str = "/etc/pf.anchors/asa_doh.txt";

/// pf anchor 裡 DNS 鎖定的那幾行。
pub fn pf_lines(lock: &DnsLockState) -> String {
    let mut s = format!(
        "table <asa_dnsallow> persist file \"{PF_DNSALLOW}\"\nblock drop out quick proto {{ tcp udp }} from any to ! <asa_dnsallow> port {{ 53 853 }}\n"
    );
    if lock.block_doh {
        s.push_str(&format!(
            "table <asa_doh> persist file \"{PF_DOH}\"\nblock drop out quick proto tcp from any to <asa_doh> port 443\n"
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(allow: &[&str], doh: bool) -> DnsLockState {
        DnsLockState {
            allow: normalize_allow(&allow.iter().map(|s| s.parse().unwrap()).collect::<Vec<_>>()),
            block_doh: doh,
            added_at: "now".into(),
        }
    }

    #[test]
    fn complement_covers_everything_but_allowed() {
        let l = lock(&["192.168.1.1/32", "10.0.0.53/32", "2001:db8::53/128"], false);
        let (c4, c6) = complement(&l.allow);
        let all: Vec<IpNet> = c4.iter().chain(c6.iter()).copied().collect();
        let inside = |ip: &str| {
            let ip: IpAddr = ip.parse().unwrap();
            all.iter().any(|n| n.contains(&ip))
        };
        for ok in ["192.168.1.1", "10.0.0.53", "127.0.0.53", "::1", "2001:db8::53"] {
            assert!(!inside(ok), "{ok} should be allowed");
        }
        for bad in [
            "8.8.8.8",
            "192.168.1.2",
            "10.0.0.52",
            "2001:4860:4860::8888",
            "255.255.255.255",
            "0.0.0.0",
        ] {
            assert!(inside(bad), "{bad} should be blocked");
        }
        // 每個 /32 洞大約切出 32 段：數量有上限
        assert!(c4.len() < 100, "{}", c4.len());
    }

    #[test]
    fn scripts_per_backend() {
        let l = lock(&["192.168.1.1/32"], true);
        let w = win_lock_script(&l);
        assert!(w.contains("-RemotePort 53,853") && w.contains("ASA: dns-lock doh") && w.contains("'0.0.0.0/2'"));
        assert!(!w.contains("'192.168.1.1/32'"));
        let n = nft_lock_script(&l);
        assert!(n.contains("add element inet asa dns_allow4 { 127.0.0.0/8, 192.168.1.1/32 }"));
        assert!(n.contains("ip daddr != @dns_allow4 drop") && n.contains("tcp dport 443 ip daddr @doh4 drop"));
        let (restore, rules) = ipset_lock(&l);
        assert!(restore.contains("add asa_dnsallow4 192.168.1.1/32 -exist"));
        assert_eq!(rules.len(), 10);
        assert!(pf_lines(&l).contains("to ! <asa_dnsallow> port { 53 853 }"));
        let no_doh = lock(&["192.168.1.1/32"], false);
        assert!(!nft_lock_script(&no_doh).contains("443"));
        assert_eq!(ipset_rules(false).len(), 8);
    }

    #[test]
    fn uncovered_resolvers() {
        let allow = normalize_allow(&["192.168.1.1/32".parse().unwrap()]);
        let cur: Vec<IpAddr> = vec![
            "192.168.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "127.0.0.53".parse().unwrap(),
        ];
        assert_eq!(uncovered(&cur, &allow), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }
}
