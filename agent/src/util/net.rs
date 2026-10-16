use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// IP 位址分類（判定 Safe / 是否要查情資用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpClass {
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Unspecified,
    Reserved,
    Public,
}

impl IpClass {
    /// 是否值得查公開情資（只有 Public 才查）。
    pub fn is_public(self) -> bool {
        self == IpClass::Public
    }
}

pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    let o = ip.octets();
    if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if ip.is_private() || (o[0] == 100 && (64..=127).contains(&o[1])) {
        // 100.64.0.0/10 CGNAT 視為私網
        IpClass::Private
    } else if ip.is_link_local() {
        IpClass::LinkLocal
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if ip.is_broadcast() || ip.is_documentation() || o[0] == 0 || o[0] >= 240 {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let seg = ip.segments();
    if ip.is_unspecified() {
        IpClass::Unspecified
    } else if ip.is_loopback() {
        IpClass::Loopback
    } else if (seg[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 ULA
        IpClass::Private
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        IpClass::LinkLocal
    } else if ip.is_multicast() {
        IpClass::Multicast
    } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        IpClass::Reserved
    } else {
        IpClass::Public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_ranges() {
        assert_eq!(classify("127.0.0.1".parse().unwrap()), IpClass::Loopback);
        assert_eq!(classify("10.1.2.3".parse().unwrap()), IpClass::Private);
        assert_eq!(classify("100.64.5.5".parse().unwrap()), IpClass::Private);
        assert_eq!(classify("169.254.1.1".parse().unwrap()), IpClass::LinkLocal);
        assert_eq!(classify("224.0.0.1".parse().unwrap()), IpClass::Multicast);
        assert_eq!(classify("8.8.8.8".parse().unwrap()), IpClass::Public);
        assert_eq!(classify("::1".parse().unwrap()), IpClass::Loopback);
        assert_eq!(classify("fd12::1".parse().unwrap()), IpClass::Private);
        assert_eq!(classify("fe80::1".parse().unwrap()), IpClass::LinkLocal);
        assert_eq!(classify("2606:4700::1111".parse().unwrap()), IpClass::Public);
        assert_eq!(classify("::ffff:8.8.8.8".parse().unwrap()), IpClass::Public);
    }
}
