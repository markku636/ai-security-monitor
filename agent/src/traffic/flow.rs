//! 封包 → 流（5-tuple 彙總）。每條流記 client／server（誰先開口）、雙向位元組、SNI、HTTP Host；
//! 另外彙總 DNS 查詢與「IP → 查詢名稱」對照（讓目的地顯示成網域）。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use super::proto::{self, DnsAnswer};

/// 解碼後的一個封包（只留分析需要的欄位）。
#[derive(Debug, Clone)]
pub struct Pkt<'a> {
    /// 秒（含小數）
    pub ts: f64,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// 6 = TCP、17 = UDP；其他協定只計總量
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    /// 線上長度（原始封包長度，不是擷取長度）
    pub len: u64,
    pub syn: bool,
    pub ack: bool,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Flow {
    pub proto: u8,
    pub client: (IpAddr, u16),
    pub server: (IpAddr, u16),
    pub first: f64,
    pub last: f64,
    pub packets: u64,
    pub bytes_c2s: u64,
    pub bytes_s2c: u64,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    /// 看到明文 HTTP 請求
    pub http_plain: bool,
}

impl Flow {
    pub fn proto_name(&self) -> &'static str {
        match self.proto {
            6 => "tcp",
            17 => "udp",
            _ => "ip",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DnsAgg {
    pub count: u32,
    pub nxdomain: u32,
    pub answers: BTreeSet<String>,
}

type Endpoint = (IpAddr, u16);
type Key = (u8, Endpoint, Endpoint);

/// 常見服務 port：用來猜「誰是 server」（第一個封包不是 SYN 時）。
fn service_like(port: u16) -> bool {
    port < 1024
        || matches!(
            port,
            1433 | 1521
                | 1883
                | 3000
                | 3306
                | 3389
                | 5060
                | 5432
                | 5900
                | 5985
                | 5986
                | 6379
                | 8000
                | 8080
                | 8443
                | 8883
                | 9000
                | 9200
                | 27017
        )
}

pub const MAX_FLOWS: usize = 20_000;

#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<Key, Flow>,
    pub dropped_flows: u64,
    pub packets: u64,
    pub bytes: u64,
    pub other_packets: u64,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
    /// (qname, qtype) → 次數／NXDOMAIN／回應位址
    pub dns: BTreeMap<(String, u16), DnsAgg>,
    /// DNS 回應裡的位址 → 查詢名稱
    pub names: HashMap<IpAddr, String>,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// 非 TCP／UDP 的 IP 封包只計總量。
    pub fn add_other(&mut self, ts: f64, len: u64) {
        self.touch(ts, len);
        self.other_packets += 1;
    }

    fn touch(&mut self, ts: f64, len: u64) {
        self.packets += 1;
        self.bytes += len;
        self.first_ts = Some(self.first_ts.map_or(ts, |f| f.min(ts)));
        self.last_ts = Some(self.last_ts.map_or(ts, |l| l.max(ts)));
    }

    pub fn add(&mut self, p: &Pkt) {
        self.touch(p.ts, p.len);
        if p.proto == 17 && (p.sport == 53 || p.dport == 53) {
            self.observe_dns(p.payload);
        }
        let a = (p.src, p.sport);
        let b = (p.dst, p.dport);
        let key = if a <= b { (p.proto, a, b) } else { (p.proto, b, a) };
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= MAX_FLOWS {
                self.dropped_flows += 1;
                return;
            }
            // 誰是 client：SYN 的發送方；SYN-ACK 的接收方；否則看哪邊像服務 port。
            let src_is_client = if p.proto == 6 && p.syn {
                !p.ack
            } else {
                !service_like(p.sport) || service_like(p.dport)
            };
            let (client, server) = if src_is_client { (a, b) } else { (b, a) };
            self.flows.insert(
                key,
                Flow {
                    proto: p.proto,
                    client,
                    server,
                    first: p.ts,
                    last: p.ts,
                    packets: 0,
                    bytes_c2s: 0,
                    bytes_s2c: 0,
                    sni: None,
                    http_host: None,
                    http_plain: false,
                },
            );
        }
        let f = self.flows.get_mut(&key).expect("inserted above");
        f.packets += 1;
        f.first = f.first.min(p.ts);
        f.last = f.last.max(p.ts);
        let from_client = (p.src, p.sport) == f.client;
        if from_client {
            f.bytes_c2s += p.len;
        } else {
            f.bytes_s2c += p.len;
        }
        if p.proto == 6 && from_client && !p.payload.is_empty() {
            if f.sni.is_none() {
                f.sni = proto::tls_sni(p.payload);
            }
            if !f.http_plain && proto::is_http_request(p.payload) {
                f.http_plain = true;
                f.http_host = proto::http_host(p.payload);
            }
        }
    }

    fn observe_dns(&mut self, payload: &[u8]) {
        let Some(m) = proto::parse_dns(payload) else {
            return;
        };
        if m.qname.is_empty() {
            return;
        }
        let agg = self.dns.entry((m.qname.clone(), m.qtype)).or_default();
        if !m.response {
            agg.count += 1;
            return;
        }
        if m.rcode == 3 {
            agg.nxdomain += 1;
        }
        for a in m.answers {
            if let DnsAnswer::Addr(ip) = a {
                if agg.answers.len() < 16 {
                    agg.answers.insert(ip.to_string());
                }
                self.names.entry(ip).or_insert_with(|| m.qname.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn pkt<'a>(
        ts: f64,
        src: &str,
        sp: u16,
        dst: &str,
        dp: u16,
        proto: u8,
        len: u64,
        syn: bool,
        ack: bool,
        payload: &'a [u8],
    ) -> Pkt<'a> {
        Pkt {
            ts,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            proto,
            sport: sp,
            dport: dp,
            len,
            syn,
            ack,
            payload,
        }
    }

    #[test]
    fn client_server_by_syn_and_ports() {
        let mut t = FlowTable::new();
        // SYN-ACK 先到（擷取開始時連線已在進行）：client 仍判對
        t.add(&pkt(
            1.0,
            "93.184.216.34",
            443,
            "10.0.0.5",
            50000,
            6,
            60,
            true,
            true,
            b"",
        ));
        t.add(&pkt(
            1.1,
            "10.0.0.5",
            50000,
            "93.184.216.34",
            443,
            6,
            1500,
            false,
            true,
            b"x",
        ));
        // 中途開始、第一個封包是 server → client
        t.add(&pkt(2.0, "8.8.8.8", 53, "10.0.0.5", 53001, 17, 90, false, false, b""));
        assert_eq!(t.flow_count(), 2);
        for f in t.flows() {
            assert_eq!(f.client.0.to_string(), "10.0.0.5");
        }
        let https = t.flows().find(|f| f.server.1 == 443).unwrap();
        assert_eq!((https.bytes_c2s, https.bytes_s2c, https.packets), (1500, 60, 2));
        assert_eq!((t.packets, t.bytes), (3, 1650));
    }

    #[test]
    fn caps_flow_count() {
        let mut t = FlowTable::new();
        for i in 0..(MAX_FLOWS as u32 + 5) {
            let port = 1024 + (i % 60000) as u16;
            let dst = format!("198.51.{}.{}", (i / 60000) % 256, 7);
            t.add(&pkt(i as f64, "10.0.0.5", port, &dst, 443, 6, 60, true, false, b""));
        }
        assert_eq!(t.flow_count(), MAX_FLOWS);
        assert_eq!(t.dropped_flows, 5);
    }
}
