//! 監聽 53 port 回應封包的共用部分（Linux AF_PACKET、macOS BPF）：
//! 核心層過濾器（classic BPF，只有「UDP 來源 port 53」的封包才複製到使用者空間，其他流量零成本）、
//! IP／UDP 解析、DNS 回應 → [`DnsEvent`]。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};

use super::super::model::{normalize_name, rcode_name, DnsEvent, Source, MAX_ANSWERS, MAX_CNAMES};
use crate::traffic::proto::{parse_dns, DnsAnswer};

/// classic BPF 指令（與 Linux `sock_filter`、BSD `bpf_insn` 相同版面）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

const LD_B_ABS: u16 = 0x30;
const LD_H_ABS: u16 = 0x28;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const ALU_RSH_K: u16 = 0x74;
const JMP_JEQ_K: u16 = 0x15;
const JMP_JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;
/// 每個封包最多複製多少 bytes（DNS 回應通常 < 1500）。
pub const SNAPLEN: u32 = 4096;

/// 「IPv4／IPv6、UDP、來源 port 53、不是分段」才收的過濾器。`base`＝鏈路層標頭長度
/// （Linux AF_PACKET SOCK_DGRAM＝0、乙太網路＝14、BSD loopback／utun＝4）。
pub fn dns_response_filter(base: u32) -> Vec<BpfInsn> {
    vec![
        ins(LD_B_ABS, 0, 0, base),      // 0: A = 第一個 byte
        ins(ALU_RSH_K, 0, 0, 4),        // 1: A >>= 4（IP 版本）
        ins(JMP_JEQ_K, 0, 7, 4),        // 2: IPv4？否 → 10
        ins(LD_B_ABS, 0, 0, base + 9),  // 3: 協定
        ins(JMP_JEQ_K, 0, 11, 17),      // 4: UDP？否 → 16
        ins(LD_H_ABS, 0, 0, base + 6),  // 5: 旗標＋分段位移
        ins(JMP_JSET_K, 9, 0, 0x1fff),  // 6: 分段 → 16
        ins(LDX_B_MSH, 0, 0, base),     // 7: X = IPv4 標頭長度
        ins(LD_H_IND, 0, 0, base),      // 8: A = UDP 來源 port
        ins(JMP_JEQ_K, 5, 6, 53),       // 9: 53 → 15，否則 16
        ins(JMP_JEQ_K, 0, 5, 6),        // 10: IPv6？否 → 16
        ins(LD_B_ABS, 0, 0, base + 6),  // 11: next header
        ins(JMP_JEQ_K, 0, 3, 17),       // 12: UDP？否 → 16
        ins(LD_H_ABS, 0, 0, base + 40), // 13: UDP 來源 port
        ins(JMP_JEQ_K, 0, 1, 53),       // 14: 53 → 15，否則 16
        ins(RET_K, 0, 0, SNAPLEN),      // 15: 收
        ins(RET_K, 0, 0, 0),            // 16: 丟
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

/// 從 IP 標頭開始解析 UDP（IPv6 不處理延伸標頭）。
pub fn parse_ip_udp(p: &[u8]) -> Option<Udp<'_>> {
    let ver = p.first()? >> 4;
    let (src, dst, l4) = match ver {
        4 => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            if ihl < 20 || p.len() < ihl + 8 || *p.get(9)? != 17 {
                return None;
            }
            let s = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
            let d = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
            (IpAddr::V4(s), IpAddr::V4(d), &p[ihl..])
        }
        6 => {
            if p.len() < 48 || p[6] != 17 {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&p[8..24]);
            d.copy_from_slice(&p[24..40]);
            (IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)), &p[40..])
        }
        _ => return None,
    };
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    let ulen = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    let end = if ulen >= 8 { ulen.min(l4.len()) } else { l4.len() };
    Some(Udp {
        src,
        dst,
        sport,
        dport,
        payload: &l4[8..end],
    })
}

/// DNS 回應 → 事件（問題、結果、位址與 CNAME）。不是回應或解析失敗回 None。
pub fn event_from_response(payload: &[u8], ts: DateTime<Utc>, pid: Option<u32>) -> Option<DnsEvent> {
    let m = parse_dns(payload)?;
    if !m.response {
        return None;
    }
    let name = normalize_name(&m.qname)?;
    let mut answers = Vec::new();
    let mut cnames = Vec::new();
    for a in m.answers {
        match a {
            DnsAnswer::Addr(ip) if answers.len() < MAX_ANSWERS && !answers.contains(&ip) => answers.push(ip),
            DnsAnswer::Name(n) => {
                if let Some(n) = normalize_name(&n) {
                    if cnames.len() < MAX_CNAMES && !cnames.contains(&n) {
                        cnames.push(n);
                    }
                }
            }
            _ => {}
        }
    }
    let rcode = if m.rcode == 0 && answers.is_empty() && cnames.is_empty() {
        "NODATA".to_string()
    } else {
        rcode_name(m.rcode)
    };
    Some(DnsEvent {
        ts,
        name,
        qtype: m.qtype,
        rcode,
        answers,
        cnames,
        ttl: None,
        pid,
        source: Source::Packet,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::traffic::proto::build;

    /// 測試用的迷你 cBPF 直譯器（只支援過濾器用到的指令），確認跳躍位移沒算錯。
    pub(crate) fn run_bpf(prog: &[BpfInsn], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let byte = |i: u32| pkt.get(i as usize).copied().map(u32::from);
        let half = |i: u32| Some((byte(i)? << 8) | byte(i + 1)?);
        while pc < prog.len() {
            let i = prog[pc];
            pc += 1;
            match i.code {
                LD_B_ABS => match byte(i.k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LD_H_ABS => match half(i.k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LD_H_IND => match half(x + i.k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                LDX_B_MSH => match byte(i.k) {
                    Some(v) => x = (v & 0xf) * 4,
                    None => return 0,
                },
                ALU_RSH_K => a >>= i.k,
                JMP_JEQ_K => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
                JMP_JSET_K => pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf }),
                RET_K => return i.k,
                c => panic!("unsupported opcode {c:#x}"),
            }
        }
        0
    }

    fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8], frag: u16) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    fn udp6(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[17, 64]);
        p.extend_from_slice(&"2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn filter_accepts_only_udp_from_port_53() {
        let resp = build::dns_response(7, "example.com", [93, 184, 216, 34]);
        for base in [0u32, 4, 14] {
            let prog = dns_response_filter(base);
            let pad = vec![0u8; base as usize];
            let wrap = |p: Vec<u8>| [pad.clone(), p].concat();
            assert_eq!(
                run_bpf(&prog, &wrap(udp4([8, 8, 8, 8], [10, 0, 0, 2], 53, 40000, &resp, 0))),
                SNAPLEN
            );
            assert_eq!(run_bpf(&prog, &wrap(udp6(53, 40000, &resp))), SNAPLEN);
            // 查詢（目的 port 53）、別的 port、後續分段（位移≠0，沒有 UDP 標頭）、TCP 都不收
            assert_eq!(
                run_bpf(&prog, &wrap(udp4([10, 0, 0, 2], [8, 8, 8, 8], 40000, 53, &resp, 0))),
                0
            );
            assert_eq!(
                run_bpf(&prog, &wrap(udp4([8, 8, 8, 8], [10, 0, 0, 2], 443, 40000, &resp, 0))),
                0
            );
            assert_eq!(
                run_bpf(
                    &prog,
                    &wrap(udp4([8, 8, 8, 8], [10, 0, 0, 2], 53, 40000, &resp, 0x0001))
                ),
                0
            );
            let mut tcp = udp4([8, 8, 8, 8], [10, 0, 0, 2], 53, 40000, &resp, 0);
            tcp[9] = 6;
            assert_eq!(run_bpf(&prog, &wrap(tcp)), 0);
            assert_eq!(run_bpf(&prog, &wrap(udp6(443, 40000, &resp))), 0);
        }
    }

    #[test]
    fn parses_response_packets_into_events() {
        let resp = build::dns_response(7, "Example.COM", [93, 184, 216, 34]);
        let pkt = udp4([8, 8, 8, 8], [10, 0, 0, 2], 53, 40000, &resp, 0);
        let u = parse_ip_udp(&pkt).unwrap();
        assert_eq!((u.sport, u.dport), (53, 40000));
        assert_eq!(u.src, "8.8.8.8".parse::<IpAddr>().unwrap());
        let ev = event_from_response(u.payload, Utc::now(), Some(42)).unwrap();
        assert_eq!(ev.name, "example.com");
        assert_eq!(ev.rcode, "NOERROR");
        assert_eq!(ev.answers, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(ev.pid, Some(42));
        assert_eq!(ev.source, Source::Packet);
        // 查詢本身不是事件
        let q = build::dns_query(8, "example.com", 1);
        assert!(event_from_response(&q, Utc::now(), None).is_none());
        let u6 = udp6(53, 40000, &resp);
        assert_eq!(parse_ip_udp(&u6).unwrap().payload, resp.as_slice());
        assert!(parse_ip_udp(&[0x45, 0, 0]).is_none());
    }
}
