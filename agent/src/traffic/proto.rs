//! 應用層小解析器（全部只讀 bytes、嚴格檢查邊界，壞封包回 None）：DNS、TLS ClientHello SNI、HTTP Host。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    /// 0 = NOERROR、3 = NXDOMAIN …
    pub rcode: u8,
    pub qname: String,
    pub qtype: u16,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsAnswer {
    Addr(IpAddr),
    Name(String),
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// 讀網域名稱（支援壓縮指標）；回傳名稱與「指標前」的下一個位移。
fn read_name(msg: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (u16_at(msg, i)? & 0x3FFF) as usize;
            if end.is_none() {
                end = Some(i + 2);
            }
            jumps += 1;
            if jumps > 16 || ptr >= msg.len() {
                return None;
            }
            i = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(i + 1..i + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 127 {
            return None;
        }
        i += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(i)))
}

/// 解析 DNS 訊息（UDP payload；TCP 的兩位元組長度前綴由呼叫端去掉）。只取第一個問題。
pub fn parse_dns(msg: &[u8]) -> Option<DnsMessage> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16_at(msg, 0)?;
    let flags = u16_at(msg, 2)?;
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)?;
    if qd == 0 || qd > 4 || an > 64 {
        return None;
    }
    let (qname, mut i) = read_name(msg, 12)?;
    let qtype = u16_at(msg, i)?;
    i += 4;
    // 其餘問題略過
    for _ in 1..qd {
        let (_, j) = read_name(msg, i)?;
        i = j + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        let (_, j) = read_name(msg, i)?;
        let rtype = u16_at(msg, j)?;
        let rdlen = u16_at(msg, j + 8)? as usize;
        let start = j + 10;
        let rdata = msg.get(start..start + rdlen)?;
        match (rtype, rdlen) {
            (1, 4) => answers.push(DnsAnswer::Addr(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )))),
            (28, 16) => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                answers.push(DnsAnswer::Addr(IpAddr::V6(Ipv6Addr::from(a))));
            }
            (5, _) => {
                if let Some((n, _)) = read_name(msg, start) {
                    answers.push(DnsAnswer::Name(n));
                }
            }
            _ => {}
        }
        i = start + rdlen;
    }
    Some(DnsMessage {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0x000F) as u8,
        qname,
        qtype,
        answers,
    })
}

/// TLS ClientHello 的 SNI（只看第一個 TCP 區段；ClientHello 被切開時抓不到，屬已知限制）。
pub fn tls_sni(p: &[u8]) -> Option<String> {
    // record: type 22, version 3.x, length
    if p.len() < 9 || p[0] != 22 || p[1] != 3 {
        return None;
    }
    // handshake: type 1 = ClientHello
    if p[5] != 1 {
        return None;
    }
    let mut i = 9; // record header 5 + handshake header 4
    i += 2 + 32; // client_version + random
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let cs = u16_at(p, i)? as usize;
    i += 2 + cs;
    let comp = *p.get(i)? as usize;
    i += 1 + comp;
    let ext_total = u16_at(p, i)? as usize;
    i += 2;
    let end = (i + ext_total).min(p.len());
    while i + 4 <= end {
        let etype = u16_at(p, i)?;
        let elen = u16_at(p, i + 2)? as usize;
        let body = p.get(i + 4..i + 4 + elen)?;
        if etype == 0 {
            // server_name_list: len(2) type(1)=host_name len(2) name
            if body.len() >= 5 && body[2] == 0 {
                let n = u16_at(body, 3)? as usize;
                let name = body.get(5..5 + n)?;
                let s = std::str::from_utf8(name)
                    .ok()?
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !s.is_empty() && s.len() <= 253 && s.bytes().all(|c| c.is_ascii_graphic()) {
                    return Some(s);
                }
            }
            return None;
        }
        i += 4 + elen;
    }
    None
}

const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// 明文 HTTP 請求的 Host（沒有就回 None；回傳時去掉 port）。
pub fn http_host(p: &[u8]) -> Option<String> {
    if !METHODS.iter().any(|m| p.starts_with(m)) {
        return None;
    }
    let head = &p[..p.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                let host = if v.starts_with('[') {
                    v.split(']').next().unwrap_or(v).trim_start_matches('[')
                } else {
                    v.split(':').next().unwrap_or(v)
                };
                let h = host.to_ascii_lowercase();
                return (!h.is_empty() && h.len() <= 253).then_some(h);
            }
        }
    }
    None
}

/// 是否看起來是 HTTP 請求（沒有 Host 也算明文 HTTP）。
pub fn is_http_request(p: &[u8]) -> bool {
    METHODS.iter().any(|m| p.starts_with(m))
}

#[cfg(test)]
pub(crate) mod build {
    //! 測試用：組 DNS 查詢／回應與 TLS ClientHello。
    pub fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes());
        v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for l in name.split('.') {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    /// 回應：一筆 CNAME（指向自己的壓縮名稱）＋一筆 A。
    pub fn dns_response(id: u16, name: &str, addr: [u8; 4]) -> Vec<u8> {
        let mut v = dns_query(id, name, 1);
        v[2] = 0x81;
        v[3] = 0x80;
        v[7] = 2; // ANCOUNT
                  // CNAME → 指標指回問題名稱 (0xC00C)
        v.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x0C]);
        // A
        v.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        v.extend_from_slice(&addr);
        v
    }

    pub fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);
        let mut exts = Vec::new();
        // 先放一個無關的擴充（supported_versions）再放 SNI
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[1, 0]); // compression: null
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![22u8, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_and_response_with_compression() {
        let q = parse_dns(&build::dns_query(7, "Example.COM", 28)).unwrap();
        assert_eq!(
            (q.id, q.response, q.qname.as_str(), q.qtype),
            (7, false, "example.com", 28)
        );
        let r = parse_dns(&build::dns_response(7, "example.com", [93, 184, 216, 34])).unwrap();
        assert!(r.response);
        assert_eq!(r.answers.len(), 2);
        assert_eq!(r.answers[0], DnsAnswer::Name("example.com".into()));
        assert_eq!(r.answers[1], DnsAnswer::Addr("93.184.216.34".parse().unwrap()));
        assert_eq!(qtype_name(28), "AAAA");
    }

    #[test]
    fn dns_rejects_garbage_and_pointer_loops() {
        assert!(parse_dns(&[0u8; 5]).is_none());
        let mut loopy = build::dns_query(1, "a.b", 1);
        loopy.truncate(12);
        loopy.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]); // 指向自己
        assert!(parse_dns(&loopy).is_none());
        let mut truncated = build::dns_response(2, "x.example", [1, 2, 3, 4]);
        truncated.truncate(truncated.len() - 2);
        assert!(parse_dns(&truncated).is_none());
    }

    #[test]
    fn sni_from_client_hello() {
        assert_eq!(
            tls_sni(&build::client_hello("Api.Example.org")).as_deref(),
            Some("api.example.org")
        );
        let mut cut = build::client_hello("x.example");
        cut.truncate(40);
        assert!(tls_sni(&cut).is_none());
        assert!(tls_sni(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn http_host_header() {
        assert_eq!(
            http_host(b"GET /a HTTP/1.1\r\nUser-Agent: x\r\nHOST: Plain.Example:8080\r\n\r\n").as_deref(),
            Some("plain.example")
        );
        assert_eq!(
            http_host(b"POST / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n").as_deref(),
            Some("::1")
        );
        assert!(http_host(b"\x16\x03\x01").is_none());
        assert!(is_http_request(b"GET / HTTP/1.0\r\n\r\n"));
    }
}
