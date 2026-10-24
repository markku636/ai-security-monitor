//! 每個工作一個釘選解析器：綁 `127.0.0.1:0`（UDP），範圍內的名稱（不分大小寫、可帶結尾點）回答釘選位址
//! （A 給 IPv4、AAAA 給 IPv6），其他名稱一律 NXDOMAIN，非 QUERY 的 opcode 回 NOTIMP。工作結束（丟掉）就關。
//! httpx、nuclei 用 `-r` 指向它；封包解析／組裝用 [`crate::dnsd::wire`]。

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::dnsd::wire::{self, Query, WireError};
use crate::error::AppResult;

const TTL: u32 = 60;
const CLASS_IN: u16 = 1;

/// 回答表：範圍內的名稱（小寫、沒有結尾點）→ 釘選位址。
#[derive(Debug, Clone, Default)]
pub struct Table {
    names: HashSet<String>,
    ips: Vec<IpAddr>,
}

impl Table {
    pub fn new(names: &[String], ips: &[IpAddr]) -> Table {
        Table {
            names: names
                .iter()
                .map(|n| n.strip_suffix('.').unwrap_or(n).to_ascii_lowercase())
                .filter(|n| !n.is_empty())
                .collect(),
            ips: ips.to_vec(),
        }
    }
}

/// 回一個封包；`None`＝不回（是回應封包、太短）。
pub fn respond(raw: &[u8], table: &Table) -> Option<Vec<u8>> {
    match wire::parse_query(raw) {
        Ok(q) if q.qclass == CLASS_IN && table.names.contains(&q.name) => Some(answer(raw, &q, &table.ips)),
        Ok(q) => Some(wire::build_empty(raw, &q, wire::RCODE_NXDOMAIN, None, false)),
        Err(WireError::BadOpcode) => wire::build_header_error(raw, wire::RCODE_NOTIMP),
        Err(WireError::NotQuery | WireError::Short) => None,
        Err(_) => wire::build_header_error(raw, wire::RCODE_FORMERR),
    }
}

/// 範圍內的名稱：釘選位址（依查詢類型挑 A／AAAA，ANY 都給）；塞不進 UDP 大小就少給幾筆（這裡不提供 TCP，不設 TC）。
fn answer(raw: &[u8], q: &Query, ips: &[IpAddr]) -> Vec<u8> {
    let mut v = wire::build_empty(raw, q, wire::RCODE_NOERROR, None, false);
    // AA：這是權威答案
    v[2] |= 0x04;
    let max = q.max_udp();
    let mut rrs: Vec<u8> = Vec::new();
    let mut n: u16 = 0;
    for ip in ips {
        let (rtype, rdata): (u16, Vec<u8>) = match (q.qtype, ip) {
            (wire::TYPE_A | wire::TYPE_ANY, IpAddr::V4(v4)) => (wire::TYPE_A, v4.octets().to_vec()),
            (wire::TYPE_AAAA | wire::TYPE_ANY, IpAddr::V6(v6)) => (wire::TYPE_AAAA, v6.octets().to_vec()),
            _ => continue,
        };
        // 名稱用壓縮指標指回問題（offset 12）
        let mut rr = vec![0xC0, 0x0C];
        rr.extend_from_slice(&rtype.to_be_bytes());
        rr.extend_from_slice(&CLASS_IN.to_be_bytes());
        rr.extend_from_slice(&TTL.to_be_bytes());
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        if v.len() + rrs.len() + rr.len() > max {
            break;
        }
        rrs.extend_from_slice(&rr);
        n += 1;
    }
    v[6..8].copy_from_slice(&n.to_be_bytes());
    // 答案放在問題之後、OPT 之前
    let at = q.question_end;
    v.splice(at..at, rrs);
    v
}

/// 跑在背景的釘選解析器；丟掉就關。
pub struct PinnedResolver {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl PinnedResolver {
    pub async fn start(names: &[String], ips: &[IpAddr]) -> AppResult<PinnedResolver> {
        let sock = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await?;
        let addr = sock.local_addr()?;
        let table = Table::new(names, ips);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    // Windows 上前一個回應的對象已經關掉會收到 ConnectionReset：略過
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                if let Some(resp) = respond(&buf[..n], &table) {
                    let _ = sock.send_to(&resp, peer).await;
                }
            }
        });
        Ok(PinnedResolver { addr, task })
    }

    /// `127.0.0.1:<port>`。
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for PinnedResolver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::proto::{parse_dns, DnsAnswer};

    /// 組查詢（名稱可帶結尾點；`opcode` 0＝QUERY）。
    fn query(id: u16, name: &str, qtype: u16, opcode: u8) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.push(0x01 | (opcode << 3));
        v.extend_from_slice(&[0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for l in name.strip_suffix('.').unwrap_or(name).split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&CLASS_IN.to_be_bytes());
        v
    }

    fn ips() -> Vec<IpAddr> {
        vec!["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()]
    }

    async fn ask(r: &PinnedResolver, pkt: &[u8]) -> Option<Vec<u8>> {
        let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(pkt, r.addr()).await.unwrap();
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(1500), c.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    fn addrs(resp: &[u8]) -> (u8, Vec<IpAddr>) {
        let m = parse_dns(resp).expect("valid response");
        assert!(m.response);
        let ips = m
            .answers
            .iter()
            .filter_map(|a| match a {
                DnsAnswer::Addr(ip) => Some(*ip),
                DnsAnswer::Name(_) => None,
            })
            .collect();
        (m.rcode, ips)
    }

    #[tokio::test]
    async fn answers_pinned_ips_over_udp_and_nxdomain_for_the_rest() {
        let r = PinnedResolver::start(
            &["Shop.Example.com.".to_string(), "www.example.com".to_string()],
            &ips(),
        )
        .await
        .unwrap();
        assert!(r.addr().ip().is_loopback() && r.addr().port() != 0);
        let v4: IpAddr = "203.0.113.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::10".parse().unwrap();
        // A 給 IPv4、AAAA 給 IPv6；大小寫、結尾點都一樣
        for name in [
            "shop.example.com",
            "SHOP.EXAMPLE.COM",
            "Shop.Example.Com.",
            "www.example.com",
        ] {
            let a = ask(&r, &query(7, name, wire::TYPE_A, 0)).await.expect("answered");
            assert_eq!(addrs(&a), (wire::RCODE_NOERROR, vec![v4]), "{name}");
            assert_eq!(u16::from_be_bytes([a[0], a[1]]), 7);
            assert_eq!(a[2] & 0x04, 0x04, "authoritative");
            let aaaa = ask(&r, &query(8, name, wire::TYPE_AAAA, 0)).await.expect("answered");
            assert_eq!(addrs(&aaaa), (wire::RCODE_NOERROR, vec![v6]), "{name}");
        }
        // 範圍內但沒有那種記錄：NOERROR、沒有答案
        let txt = ask(&r, &query(9, "shop.example.com", 16, 0)).await.unwrap();
        assert_eq!(addrs(&txt), (wire::RCODE_NOERROR, vec![]));
        // 範圍外（包括上層網域與子網域）一律 NXDOMAIN
        for name in [
            "example.com",
            "a.shop.example.com",
            "evil.example.net",
            "metadata.google.internal",
        ] {
            let resp = ask(&r, &query(10, name, wire::TYPE_A, 0)).await.expect("answered");
            assert_eq!(addrs(&resp), (wire::RCODE_NXDOMAIN, vec![]), "{name}");
        }
        // 非 QUERY 的 opcode（STATUS、NOTIFY、UPDATE）：NOTIMP
        for op in [2u8, 4, 5] {
            let resp = ask(&r, &query(11, "shop.example.com", wire::TYPE_A, op))
                .await
                .expect("answered");
            assert_eq!(resp[3] & 0x0F, wire::RCODE_NOTIMP, "opcode {op}");
            assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 11);
        }
        // 回應封包不回
        let mut not_query = query(12, "shop.example.com", wire::TYPE_A, 0);
        not_query[2] |= 0x80;
        assert!(ask(&r, &not_query).await.is_none());
    }

    #[tokio::test]
    async fn stops_answering_after_drop() {
        let r = PinnedResolver::start(&["shop.example.com".to_string()], &ips())
            .await
            .unwrap();
        let addr = r.addr();
        assert!(ask(&r, &query(1, "shop.example.com", wire::TYPE_A, 0)).await.is_some());
        drop(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _ = c.send_to(&query(2, "shop.example.com", wire::TYPE_A, 0), addr).await;
        let mut buf = [0u8; 512];
        let got = tokio::time::timeout(Duration::from_millis(500), c.recv_from(&mut buf)).await;
        assert!(!matches!(got, Ok(Ok(_))), "closed resolver must not answer");
    }

    #[test]
    fn edns_any_and_size_limits() {
        let t = Table::new(&["shop.example.com".to_string()], &ips());
        // ANY：兩種都給；帶 EDNS 的查詢回應也帶 OPT
        let mut q = query(3, "shop.example.com", wire::TYPE_ANY, 0);
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        let r = respond(&q, &t).unwrap();
        let (rcode, got) = addrs(&r);
        assert_eq!(rcode, wire::RCODE_NOERROR);
        assert_eq!(got, ips());
        assert_eq!(u16::from_be_bytes([r[10], r[11]]), 1, "OPT kept");
        // 名稱很長、位址很多、沒有 EDNS：不超過 512 bytes
        let long = format!("{}.{}.{}.example.com", "a".repeat(63), "b".repeat(63), "c".repeat(63));
        let many: Vec<IpAddr> = (0..16).map(|i| format!("2001:db8::{i:x}").parse().unwrap()).collect();
        let t = Table::new(std::slice::from_ref(&long), &many);
        let r = respond(&query(4, &long, wire::TYPE_AAAA, 0), &t).unwrap();
        assert!(r.len() <= 512, "{}", r.len());
        let (_, got) = addrs(&r);
        assert!(!got.is_empty() && got.len() < many.len());
        // 壞封包：太短不回、兩個問題回 FORMERR
        assert!(respond(&[0, 1, 2], &t).is_none());
        let mut two = query(5, "shop.example.com", wire::TYPE_A, 0);
        two[5] = 2;
        assert_eq!(respond(&two, &t).unwrap()[3] & 0x0F, wire::RCODE_FORMERR);
    }
}
