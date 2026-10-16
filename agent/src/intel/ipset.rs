//! IpSet：單一來源的可查詢集合。IP / CIDR 存成排序區間（v4 u32、v6 u128）＋「前綴最大終點」陣列，
//! 允許重疊（/16 內含 /24）仍能二分搜尋；另有 ip:port、網域（含上層網域）、ASN、CVE 雜湊表。

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::Value;

use super::parse::{Indicator, Record};

#[derive(Debug, Clone, Default)]
pub struct RecordMeta {
    /// 顯示用的原始值（`1.2.3.0/24`、`1.2.3.4:443`、`evil.com`、`AS123`）。
    pub display: String,
    pub extra: Value,
    pub confidence: Option<u8>,
}

#[derive(Debug, Default)]
pub struct IpSet {
    v4: Vec<(u32, u32, u32)>,
    v4_maxend: Vec<u32>,
    v6: Vec<(u128, u128, u32)>,
    v6_maxend: Vec<u128>,
    ip_ports: HashMap<(IpAddr, u16), u32>,
    port_ips: HashMap<IpAddr, u32>,
    domains: HashMap<String, u32>,
    asns: HashMap<u32, u32>,
    cves: HashMap<String, u32>,
    metas: Vec<RecordMeta>,
}

fn maxend<T: Ord + Copy>(v: &[(T, T, u32)]) -> Vec<T> {
    let mut out = Vec::with_capacity(v.len());
    let mut cur: Option<T> = None;
    for (_, e, _) in v {
        cur = Some(match cur {
            Some(c) if c > *e => c,
            _ => *e,
        });
        out.push(cur.expect("set above"));
    }
    out
}

fn find<T: Ord + Copy>(v: &[(T, T, u32)], maxend: &[T], x: T) -> Option<u32> {
    let mut j = v.partition_point(|e| e.0 <= x);
    while j > 0 {
        j -= 1;
        if maxend[j] < x {
            break;
        }
        let (s, e, m) = v[j];
        if s <= x && x <= e {
            return Some(m);
        }
    }
    None
}

impl IpSet {
    pub fn build(records: Vec<Record>) -> IpSet {
        let mut s = IpSet::default();
        for r in records {
            let idx = s.metas.len() as u32;
            let display = match &r.ind {
                Indicator::Net(n) => {
                    if n.prefix_len() == n.max_prefix_len() {
                        n.addr().to_string()
                    } else {
                        n.to_string()
                    }
                }
                Indicator::IpPort(ip, p) => format!("{ip}:{p}"),
                Indicator::Domain(d) => d.clone(),
                Indicator::Asn(a) => format!("AS{a}"),
                Indicator::Cve(c) => c.clone(),
            };
            match r.ind {
                Indicator::Net(IpNet::V4(n)) => s.v4.push((u32::from(n.network()), u32::from(n.broadcast()), idx)),
                Indicator::Net(IpNet::V6(n)) => s.v6.push((u128::from(n.network()), u128::from(n.broadcast()), idx)),
                Indicator::IpPort(ip, port) => {
                    s.ip_ports.insert((ip, port), idx);
                    s.port_ips.entry(ip).or_insert(idx);
                }
                Indicator::Domain(d) => {
                    s.domains.insert(d.trim_end_matches('.').to_ascii_lowercase(), idx);
                }
                Indicator::Asn(a) => {
                    s.asns.insert(a, idx);
                }
                Indicator::Cve(c) => {
                    s.cves.insert(c.to_ascii_uppercase(), idx);
                }
            }
            s.metas.push(RecordMeta {
                display,
                extra: r.extra,
                confidence: r.confidence,
            });
        }
        s.v4.sort_unstable_by_key(|e| (e.0, e.1));
        s.v6.sort_unstable_by_key(|e| (e.0, e.1));
        s.v4_maxend = maxend(&s.v4);
        s.v6_maxend = maxend(&s.v6);
        s
    }

    pub fn len(&self) -> usize {
        self.metas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.metas.is_empty()
    }

    fn meta(&self, idx: u32) -> &RecordMeta {
        &self.metas[idx as usize]
    }

    /// IP 落在任一 IP / CIDR 條目內。
    pub fn match_ip(&self, ip: IpAddr) -> Option<&RecordMeta> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let idx = match ip {
            IpAddr::V4(v4) => find(&self.v4, &self.v4_maxend, u32::from(v4)),
            IpAddr::V6(v6) => find(&self.v6, &self.v6_maxend, u128::from(v6)),
        }?;
        Some(self.meta(idx))
    }

    /// ip:port 條目。回傳 (meta, 是否 port 也相符)；只有 IP 相符時 port 不同（降信心用）。
    pub fn match_ip_port(&self, ip: IpAddr, port: Option<u16>) -> Option<(&RecordMeta, bool)> {
        if let Some(p) = port {
            if let Some(idx) = self.ip_ports.get(&(ip, p)) {
                return Some((self.meta(*idx), true));
            }
        }
        self.port_ips.get(&ip).map(|idx| (self.meta(*idx), false))
    }

    /// 網域本身或其上層網域在清單中。
    pub fn match_domain(&self, domain: &str) -> Option<&RecordMeta> {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut cur: &str = &d;
        loop {
            if let Some(idx) = self.domains.get(cur) {
                return Some(self.meta(*idx));
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return None,
            }
        }
    }

    pub fn match_asn(&self, asn: u32) -> Option<&RecordMeta> {
        self.asns.get(&asn).map(|i| self.meta(*i))
    }

    pub fn match_cve(&self, cve: &str) -> Option<&RecordMeta> {
        self.cves.get(&cve.to_ascii_uppercase()).map(|i| self.meta(*i))
    }

    /// 所有 IP / CIDR 條目（給防火牆同步用）。
    pub fn networks(&self) -> Vec<IpNet> {
        let mut out = Vec::with_capacity(self.v4.len() + self.v6.len());
        for (s, e, _) in &self.v4 {
            let prefix = 32 - (e - s).wrapping_add(1).trailing_zeros().min(32) as u8;
            if let Ok(n) = IpNet::new(IpAddr::V4((*s).into()), if e == s { 32 } else { prefix }) {
                out.push(n);
            }
        }
        for (s, e, _) in &self.v6 {
            let prefix = if e == s {
                128
            } else {
                128 - (e - s).wrapping_add(1).trailing_zeros().min(128) as u8
            };
            if let Ok(n) = IpNet::new(IpAddr::V6((*s).into()), prefix) {
                out.push(n);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::parse::parse_ip_or_net;

    fn net(s: &str) -> Record {
        Record {
            ind: Indicator::Net(parse_ip_or_net(s).unwrap()),
            extra: Value::Null,
            confidence: None,
        }
    }

    #[test]
    fn overlapping_ranges_and_boundaries() {
        let s = IpSet::build(vec![
            net("10.0.0.0/8"),
            net("10.1.2.0/24"),
            net("192.168.1.5"),
            net("172.16.0.0/30"),
        ]);
        assert_eq!(s.match_ip("10.1.2.3".parse().unwrap()).unwrap().display, "10.1.2.0/24");
        assert_eq!(s.match_ip("10.200.0.1".parse().unwrap()).unwrap().display, "10.0.0.0/8");
        assert!(s.match_ip("192.168.1.5".parse().unwrap()).is_some());
        assert!(s.match_ip("192.168.1.6".parse().unwrap()).is_none());
        assert!(s.match_ip("172.16.0.3".parse().unwrap()).is_some());
        assert!(s.match_ip("172.16.0.4".parse().unwrap()).is_none());
        assert!(s.match_ip("11.0.0.0".parse().unwrap()).is_none());
        assert!(s.match_ip("::ffff:10.9.9.9".parse().unwrap()).is_some());
    }

    #[test]
    fn ipv6_ports_domains_asns() {
        let s = IpSet::build(vec![
            net("2a06:e480::/29"),
            Record {
                ind: Indicator::IpPort("1.2.3.4".parse().unwrap(), 443),
                extra: Value::Null,
                confidence: Some(75),
            },
            Record {
                ind: Indicator::Domain("evil.example".into()),
                extra: Value::Null,
                confidence: None,
            },
            Record {
                ind: Indicator::Asn(64500),
                extra: Value::Null,
                confidence: None,
            },
        ]);
        assert!(s.match_ip("2a06:e481::1".parse().unwrap()).is_some());
        assert!(s.match_ip("2a07::1".parse().unwrap()).is_none());
        let (m, exact) = s.match_ip_port("1.2.3.4".parse().unwrap(), Some(443)).unwrap();
        assert!(exact && m.confidence == Some(75));
        assert!(!s.match_ip_port("1.2.3.4".parse().unwrap(), Some(80)).unwrap().1);
        assert!(s.match_domain("cdn.evil.example").is_some());
        assert!(s.match_domain("evil.example.").is_some());
        assert!(s.match_domain("example").is_none());
        assert!(s.match_asn(64500).is_some());
        assert_eq!(s.len(), 4);
    }

    #[test]
    fn networks_roundtrip() {
        let s = IpSet::build(vec![net("10.1.2.0/24"), net("8.8.8.8"), net("2a06:e480::/29")]);
        let mut n: Vec<String> = s.networks().iter().map(|n| n.to_string()).collect();
        n.sort();
        assert_eq!(n, vec!["10.1.2.0/24", "2a06:e480::/29", "8.8.8.8/32"]);
    }
}
