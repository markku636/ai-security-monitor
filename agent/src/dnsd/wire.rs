//! DNS 封包的零拷貝處理（熱路徑不配置 Message 物件）：解析查詢（標頭、單一問題、EDNS）、
//! 分析上游回應（各記錄 TTL 的位置、OPT 的位置、位址答案、負快取 TTL）、組錯誤／封鎖回應、改寫快取回應的 ID 與 TTL。
//! 所有讀取都檢查邊界，壞封包回錯誤，不 panic。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const HEADER: usize = 12;
pub const TYPE_A: u16 = 1;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_HINFO: u16 = 13;
pub const TYPE_ANY: u16 = 255;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;
/// 我們對外宣告的 EDNS UDP 大小（DNS Flag Day 2020）。
pub const EDNS_UDP: u16 = 1232;
/// EDE（RFC 8914）選項代碼與資訊碼。
const OPT_EDE: u16 = 15;
pub const EDE_BLOCKED: u16 = 15;
pub const EDE_STALE: u16 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Short,
    NotQuery,
    BadOpcode,
    BadCount,
    BadName,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edns {
    pub udp_size: u16,
    pub do_bit: bool,
}

/// 解析好的查詢。`name` 是小寫、以點分隔、沒有結尾點（根名稱是空字串）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub rd: bool,
    pub cd: bool,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// 問題區段結束的位置（`raw[12..question_end]` 就是問題）。
    pub question_end: usize,
    pub edns: Option<Edns>,
}

impl Query {
    /// 回應能用的最大 UDP 大小。
    pub fn max_udp(&self) -> usize {
        match self.edns {
            Some(e) => usize::from(e.udp_size.clamp(512, EDNS_UDP)),
            None => 512,
        }
    }

    pub fn do_bit(&self) -> bool {
        self.edns.is_some_and(|e| e.do_bit)
    }
}

/// 讀一個未壓縮的名稱（查詢的問題不該有壓縮指標），回傳（小寫名稱, 結束位置）。
fn read_plain_name(b: &[u8], mut i: usize) -> Result<(String, usize), WireError> {
    let mut name = String::new();
    loop {
        let len = *b.get(i).ok_or(WireError::Short)? as usize;
        if len == 0 {
            return Ok((name, i + 1));
        }
        if len & 0xC0 != 0 || len > 63 {
            return Err(WireError::BadName);
        }
        let label = b.get(i + 1..i + 1 + len).ok_or(WireError::Short)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &c in label {
            // 名稱只收可見 ASCII（排除點與空白，避免拼出歧義的名稱）
            if !(0x21..0x7f).contains(&c) || c == b'.' {
                return Err(WireError::BadName);
            }
            name.push(c.to_ascii_lowercase() as char);
        }
        if name.len() > 253 {
            return Err(WireError::BadName);
        }
        i += 1 + len;
    }
}

/// 跳過一個名稱（允許壓縮指標），回傳結束位置。
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *b.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            b.get(i + 1)?;
            return Some(i + 2);
        }
        if len > 63 {
            return None;
        }
        i += 1 + len;
    }
    None
}

/// 解析查詢：只接受標準查詢、恰好一個問題；額外區段只看 OPT。
pub fn parse_query(b: &[u8]) -> Result<Query, WireError> {
    if b.len() < HEADER {
        return Err(WireError::Short);
    }
    let id = u16_at(b, 0).ok_or(WireError::Short)?;
    let flags = u16_at(b, 2).ok_or(WireError::Short)?;
    if flags & 0x8000 != 0 {
        return Err(WireError::NotQuery);
    }
    if (flags >> 11) & 0xF != 0 {
        return Err(WireError::BadOpcode);
    }
    let (qd, an, ns, ar) = (
        u16_at(b, 4).unwrap_or(0),
        u16_at(b, 6).unwrap_or(0),
        u16_at(b, 8).unwrap_or(0),
        u16_at(b, 10).unwrap_or(0),
    );
    if qd != 1 || an != 0 || ns > 1 || ar > 2 {
        return Err(WireError::BadCount);
    }
    let (name, i) = read_plain_name(b, HEADER)?;
    let qtype = u16_at(b, i).ok_or(WireError::Short)?;
    let qclass = u16_at(b, i + 2).ok_or(WireError::Short)?;
    let question_end = i + 4;
    let mut edns = None;
    let mut j = question_end;
    for _ in 0..(usize::from(ns) + usize::from(ar)) {
        let Some(k) = skip_name(b, j) else {
            break;
        };
        let (Some(rtype), Some(class), Some(ttl), Some(rdlen)) =
            (u16_at(b, k), u16_at(b, k + 2), u32_at(b, k + 4), u16_at(b, k + 8))
        else {
            break;
        };
        if rtype == TYPE_OPT {
            edns = Some(Edns {
                udp_size: class.max(512),
                do_bit: ttl & 0x8000 != 0,
            });
        }
        j = k + 10 + usize::from(rdlen);
    }
    Ok(Query {
        id,
        rd: flags & 0x0100 != 0,
        cd: flags & 0x0010 != 0,
        name,
        qtype,
        qclass,
        question_end,
        edns,
    })
}

fn opt_rr(do_bit: bool, ede: Option<(u16, &str)>) -> Vec<u8> {
    let mut rd = Vec::new();
    if let Some((code, text)) = ede {
        let t = text.as_bytes();
        rd.extend_from_slice(&OPT_EDE.to_be_bytes());
        rd.extend_from_slice(&((2 + t.len()) as u16).to_be_bytes());
        rd.extend_from_slice(&code.to_be_bytes());
        rd.extend_from_slice(t);
    }
    let mut v = vec![0u8];
    v.extend_from_slice(&TYPE_OPT.to_be_bytes());
    v.extend_from_slice(&EDNS_UDP.to_be_bytes());
    v.extend_from_slice(&[0, 0, if do_bit { 0x80 } else { 0 }, 0]);
    v.extend_from_slice(&(rd.len() as u16).to_be_bytes());
    v.extend_from_slice(&rd);
    v
}

/// 只有標頭＋問題（＋OPT）的回應：錯誤、封鎖（NXDOMAIN＋EDE「Blocked」）、截斷。
pub fn build_empty(raw: &[u8], q: &Query, rcode: u8, ede: Option<(u16, &str)>, tc: bool) -> Vec<u8> {
    let question = raw.get(HEADER..q.question_end).unwrap_or(&[]);
    let mut v = Vec::with_capacity(HEADER + question.len() + 32);
    v.extend_from_slice(&q.id.to_be_bytes());
    let mut flags: u16 = 0x8000 | 0x0080 | u16::from(rcode & 0xF);
    if q.rd {
        flags |= 0x0100;
    }
    if tc {
        flags |= 0x0200;
    }
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(&u16::from(q.edns.is_some()).to_be_bytes());
    v.extend_from_slice(question);
    if q.edns.is_some() {
        v.extend_from_slice(&opt_rr(q.do_bit(), ede));
    }
    v
}

/// 標頭＋問題，給還沒解析出問題的壞封包回 FORMERR／NOTIMP 用。
pub fn build_header_error(raw: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let id = u16_at(raw, 0)?;
    let mut v = Vec::with_capacity(HEADER);
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&(0x8000u16 | 0x0080 | u16::from(rcode)).to_be_bytes());
    v.extend_from_slice(&[0; 8]);
    Some(v)
}

/// ANY 查詢回最小答案（RFC 8482）：一筆 HINFO "RFC8482"。
pub fn build_any(raw: &[u8], q: &Query) -> Vec<u8> {
    let mut v = build_empty(raw, q, RCODE_NOERROR, None, false);
    // ANCOUNT = 1；答案插在問題之後、OPT 之前
    v[6..8].copy_from_slice(&1u16.to_be_bytes());
    let mut rr = vec![0xC0, 0x0C];
    rr.extend_from_slice(&TYPE_HINFO.to_be_bytes());
    rr.extend_from_slice(&q.qclass.to_be_bytes());
    rr.extend_from_slice(&3600u32.to_be_bytes());
    let cpu = b"RFC8482";
    rr.extend_from_slice(&((cpu.len() + 2) as u16).to_be_bytes());
    rr.push(cpu.len() as u8);
    rr.extend_from_slice(cpu);
    rr.push(0);
    let at = HEADER + (q.question_end - HEADER);
    v.splice(at..at, rr);
    v
}

/// 給上游的查詢：同一個問題、RD=1、帶我們的 EDNS（DO 照抄）。`id` 由呼叫端決定（DoH 用 0）。
pub fn build_upstream_query(raw: &[u8], q: &Query, id: u16) -> Vec<u8> {
    let question = raw.get(HEADER..q.question_end).unwrap_or(&[]);
    let mut v = Vec::with_capacity(HEADER + question.len() + 11);
    v.extend_from_slice(&id.to_be_bytes());
    let mut flags: u16 = 0x0100;
    if q.cd {
        flags |= 0x0010;
    }
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]);
    v.extend_from_slice(question);
    v.extend_from_slice(&opt_rr(q.do_bit(), None));
    v
}

/// 上游回應的分析結果（給快取用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespInfo {
    pub id: u16,
    pub rcode: u8,
    pub tc: bool,
    /// 各記錄 TTL 欄位的位置（OPT 除外）。
    pub ttl_offsets: Vec<u16>,
    /// 可快取多久（秒）：正答案取最小 TTL；NXDOMAIN／NODATA 取 SOA 的負快取 TTL。
    pub cache_ttl: u32,
    /// OPT 記錄在封包裡的範圍（回應沒有 EDNS 的用戶端時要拿掉）。
    pub opt: Option<(usize, usize)>,
    pub answers: Vec<IpAddr>,
    pub ancount: u16,
}

/// 分析回應；問題要跟 `q` 一樣（防止拿別題的答案污染快取）。
pub fn analyze_response(b: &[u8], q: &Query) -> Option<RespInfo> {
    if b.len() < HEADER {
        return None;
    }
    let flags = u16_at(b, 2)?;
    if flags & 0x8000 == 0 {
        return None;
    }
    let qd = u16_at(b, 4)?;
    let an = u16_at(b, 6)?;
    let ns = u16_at(b, 8)?;
    let ar = u16_at(b, 10)?;
    if qd != 1 {
        return None;
    }
    let (name, i) = read_plain_name(b, HEADER).ok()?;
    if name != q.name || u16_at(b, i)? != q.qtype || u16_at(b, i + 2)? != q.qclass {
        return None;
    }
    let mut j = i + 4;
    let mut ttl_offsets = Vec::new();
    let mut min_ttl = u32::MAX;
    let mut neg_ttl: Option<u32> = None;
    let mut opt = None;
    let mut answers = Vec::new();
    let total = usize::from(an) + usize::from(ns) + usize::from(ar);
    for idx in 0..total {
        let start = j;
        let k = skip_name(b, j)?;
        let rtype = u16_at(b, k)?;
        let ttl = u32_at(b, k + 4)?;
        let rdlen = usize::from(u16_at(b, k + 8)?);
        let rdata = b.get(k + 10..k + 10 + rdlen)?;
        if rtype == TYPE_OPT {
            opt = Some((start, k + 10 + rdlen));
        } else {
            ttl_offsets.push(u16::try_from(k + 4).ok()?);
            let section_answer = idx < usize::from(an);
            if section_answer {
                min_ttl = min_ttl.min(ttl);
                match (rtype, rdlen) {
                    (TYPE_A, 4) => answers.push(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
                    (TYPE_AAAA, 16) => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(rdata);
                        answers.push(IpAddr::V6(Ipv6Addr::from(a)));
                    }
                    _ => {}
                }
            } else if rtype == TYPE_SOA && idx < usize::from(an) + usize::from(ns) && rdlen >= 20 {
                let minimum = u32_at(rdata, rdlen - 4)?;
                neg_ttl = Some(ttl.min(minimum));
            }
        }
        j = k + 10 + rdlen;
    }
    let rcode = (flags & 0xF) as u8;
    let cache_ttl = if an > 0 && min_ttl != u32::MAX {
        min_ttl
    } else {
        neg_ttl.unwrap_or(60)
    };
    Some(RespInfo {
        id: u16_at(b, 0)?,
        rcode,
        tc: flags & 0x0200 != 0,
        ttl_offsets,
        cache_ttl,
        opt,
        answers,
        ancount: an,
    })
}

/// 把快取的回應改成給這個用戶端：換 ID、TTL 減去經過秒數（最少 `floor`）、
/// 用戶端沒帶 EDNS 就拿掉 OPT，超過 `max_len`（UDP 是用戶端宣告的大小，TCP 是 65535）就改成截斷回應。
pub fn rewrite_cached(
    cached: &[u8],
    info: &RespInfo,
    raw: &[u8],
    q: &Query,
    age_s: u32,
    floor: u32,
    max_len: usize,
) -> Vec<u8> {
    let mut v = cached.to_vec();
    v[0..2].copy_from_slice(&q.id.to_be_bytes());
    // RD 照用戶端
    if q.rd {
        v[2] |= 0x01;
    } else {
        v[2] &= !0x01;
    }
    for &off in &info.ttl_offsets {
        let o = usize::from(off);
        if let Some(t) = u32_at(&v, o) {
            let nt = t.saturating_sub(age_s).max(floor);
            v[o..o + 4].copy_from_slice(&nt.to_be_bytes());
        }
    }
    if q.edns.is_none() {
        if let Some((s, e)) = info.opt {
            if e <= v.len() {
                v.drain(s..e);
                let ar = u16_at(&v, 10).unwrap_or(1).saturating_sub(1);
                v[10..12].copy_from_slice(&ar.to_be_bytes());
            }
        }
    }
    if v.len() > max_len {
        return build_empty(raw, q, info.rcode, None, true);
    }
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::traffic::proto::{build, parse_dns, DnsAnswer};

    /// 帶 EDNS（DO=1）的查詢。
    pub(crate) fn query_edns(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut v = build::dns_query(id, name, qtype);
        v[11] = 1;
        v.extend_from_slice(&opt_rr(true, None));
        v
    }

    /// 回應：一筆 A 記錄（指定 TTL）＋ OPT。
    pub(crate) fn response_a(id: u16, name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut v = build::dns_query(id, name, 1);
        v[2] = 0x81;
        v[3] = 0x80;
        v[7] = 1;
        v[11] = 1;
        v.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        v.extend_from_slice(&ttl.to_be_bytes());
        v.extend_from_slice(&[0, 4]);
        v.extend_from_slice(&ip);
        v.extend_from_slice(&opt_rr(false, None));
        v
    }

    #[test]
    fn parses_queries_and_edns() {
        let q = parse_query(&query_edns(7, "WWW.Example.COM", 28)).unwrap();
        assert_eq!(
            (q.id, q.name.as_str(), q.qtype, q.qclass),
            (7, "www.example.com", 28, 1)
        );
        assert!(q.rd && q.do_bit());
        assert_eq!(q.max_udp(), 1232);
        let plain = parse_query(&build::dns_query(9, "a.b", 1)).unwrap();
        assert!(plain.edns.is_none());
        assert_eq!(plain.max_udp(), 512);
        // 回應、壞 opcode、兩個問題、壓縮指標、太短都拒絕
        let mut resp = build::dns_query(1, "x.test", 1);
        resp[2] |= 0x80;
        assert_eq!(parse_query(&resp), Err(WireError::NotQuery));
        let mut op = build::dns_query(1, "x.test", 1);
        op[2] |= 0x28;
        assert_eq!(parse_query(&op), Err(WireError::BadOpcode));
        let mut two = build::dns_query(1, "x.test", 1);
        two[5] = 2;
        assert_eq!(parse_query(&two), Err(WireError::BadCount));
        let mut ptr = build::dns_query(1, "x.test", 1);
        ptr[12] = 0xC0;
        assert!(parse_query(&ptr).is_err());
        assert_eq!(parse_query(&[0; 5]), Err(WireError::Short));
    }

    #[test]
    fn blocked_and_error_responses_are_valid() {
        let raw = query_edns(42, "evil.example", 1);
        let q = parse_query(&raw).unwrap();
        let r = build_empty(
            &raw,
            &q,
            RCODE_NXDOMAIN,
            Some((EDE_BLOCKED, "blocked by ai-security-monitor")),
            false,
        );
        let m = parse_dns(&r).unwrap();
        assert!(m.response && m.rcode == RCODE_NXDOMAIN && m.id == 42);
        assert_eq!(m.qname, "evil.example");
        assert!(r.windows(30).any(|w| w == b"blocked by ai-security-monitor"));
        let info = analyze_response(&r, &q).unwrap();
        assert!(info.opt.is_some());
        let tc = build_empty(&raw, &q, 0, None, true);
        assert_eq!(tc[2] & 0x02, 0x02);
        let any_raw = query_edns(5, "x.test", TYPE_ANY);
        let aq = parse_query(&any_raw).unwrap();
        let any = build_any(&any_raw, &aq);
        let ai = analyze_response(&any, &aq).unwrap();
        assert_eq!(ai.ancount, 1);
        assert!(build_header_error(&[0, 9, 0, 0], RCODE_FORMERR).is_some());
    }

    #[test]
    fn analyze_and_rewrite_cached() {
        let raw = query_edns(1, "example.com", 1);
        let q = parse_query(&raw).unwrap();
        let up = response_a(0, "example.com", [93, 184, 216, 34], 300);
        let info = analyze_response(&up, &q).unwrap();
        assert_eq!(info.cache_ttl, 300);
        assert_eq!(info.answers, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(info.ttl_offsets.len(), 1);
        // 給另一個沒帶 EDNS 的用戶端、過了 100 秒
        let raw2 = build::dns_query(777, "example.com", 1);
        let q2 = parse_query(&raw2).unwrap();
        let out = rewrite_cached(&up, &info, &raw2, &q2, 100, 1, q2.max_udp());
        let m = parse_dns(&out).unwrap();
        assert_eq!(m.id, 777);
        assert_eq!(m.answers, vec![DnsAnswer::Addr("93.184.216.34".parse().unwrap())]);
        let o2 = analyze_response(&out, &q2).unwrap();
        assert!(o2.opt.is_none(), "OPT removed for non-EDNS client");
        assert_eq!(o2.cache_ttl, 200);
        // 過期的 TTL 不會變成 0 以下（serve-stale 用 floor）
        let stale = rewrite_cached(&up, &info, &raw2, &q2, 10_000, 30, q2.max_udp());
        assert_eq!(analyze_response(&stale, &q2).unwrap().cache_ttl, 30);
        // 問題不符的回應拒收
        let other = parse_query(&query_edns(1, "other.com", 1)).unwrap();
        assert!(analyze_response(&up, &other).is_none());
    }

    #[test]
    fn upstream_query_carries_question_and_edns() {
        let raw = build::dns_query(3, "a.example", 28);
        let q = parse_query(&raw).unwrap();
        let up = build_upstream_query(&raw, &q, 0);
        let uq = parse_query(&up).unwrap();
        assert_eq!((uq.id, uq.name.as_str(), uq.qtype), (0, "a.example", 28));
        assert!(uq.edns.is_some() && uq.rd);
    }

    #[test]
    fn garbage_never_panics() {
        // 簡易模糊測試：亂數 bytes 與截斷的合法封包
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let good = response_a(1, "example.com", [1, 2, 3, 4], 60);
        let q = parse_query(&query_edns(1, "example.com", 1)).unwrap();
        for n in 0..20_000 {
            let len = (next() % 600) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if n % 3 == 0 && !good.is_empty() {
                b = good[..(next() as usize % good.len())].to_vec();
            }
            let _ = parse_query(&b);
            if let Some(info) = analyze_response(&b, &q) {
                let _ = rewrite_cached(&b, &info, &b, &q, 5, 1, 512);
            }
        }
    }
}
