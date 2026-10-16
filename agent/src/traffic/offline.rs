//! 離線分析 .pcap／.pcapng（純 Rust：pcap-parser＋etherparse，不需要 libpcap／Npcap）。

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{Block, Linktype, PcapBlockOwned, PcapError};

use super::flow::{FlowTable, Pkt};
use crate::error::{AppError, AppResult};

/// 讀檔上限：預設最多處理 200 萬個封包（大檔請先用 Wireshark／tshark 篩過）。
pub const DEFAULT_MAX_PACKETS: u64 = 2_000_000;

#[derive(Debug, Default)]
pub struct ReadStats {
    pub records: u64,
    pub unsupported_link: u64,
    pub undecodable: u64,
    pub truncated: bool,
}

/// 依 link type 切出 IP 封包。
fn slice(link: Linktype, data: &[u8]) -> Option<SlicedPacket<'_>> {
    match link {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => SlicedPacket::from_ip(data).ok(),
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),
        Linktype::NULL | Linktype::LOOP => SlicedPacket::from_ip(data.get(4..)?).ok(),
        Linktype::LINUX_SLL2 => SlicedPacket::from_ip(data.get(20..)?).ok(),
        _ => None,
    }
}

fn link_supported(link: Linktype) -> bool {
    matches!(
        link,
        Linktype::ETHERNET
            | Linktype::RAW
            | Linktype::IPV4
            | Linktype::IPV6
            | Linktype::LINUX_SLL
            | Linktype::NULL
            | Linktype::LOOP
            | Linktype::LINUX_SLL2
    )
}

/// 把一個擷取到的封包加進流表。
pub fn ingest(table: &mut FlowTable, stats: &mut ReadStats, link: Linktype, ts: f64, wire_len: u64, data: &[u8]) {
    stats.records += 1;
    if !link_supported(link) {
        stats.unsupported_link += 1;
        return;
    }
    let Some(sp) = slice(link, data) else {
        stats.undecodable += 1;
        return;
    };
    let (src, dst) = match &sp.net {
        Some(NetSlice::Ipv4(v4)) => (v4.header().source_addr().into(), v4.header().destination_addr().into()),
        Some(NetSlice::Ipv6(v6)) => (v6.header().source_addr().into(), v6.header().destination_addr().into()),
        _ => {
            stats.undecodable += 1;
            return;
        }
    };
    let pkt = match &sp.transport {
        Some(TransportSlice::Tcp(t)) => Pkt {
            ts,
            src,
            dst,
            proto: 6,
            sport: t.source_port(),
            dport: t.destination_port(),
            len: wire_len,
            syn: t.syn(),
            ack: t.ack(),
            payload: t.payload(),
        },
        Some(TransportSlice::Udp(u)) => Pkt {
            ts,
            src,
            dst,
            proto: 17,
            sport: u.source_port(),
            dport: u.destination_port(),
            len: wire_len,
            syn: false,
            ack: false,
            payload: u.payload(),
        },
        _ => {
            table.add_other(ts, wire_len);
            return;
        }
    };
    table.add(&pkt);
}

/// pcapng 的時間解析度（if_tsresol）：最高位元 0 → 10^n、1 → 2^n；預設微秒。
fn ts_units(tsresol: u8) -> f64 {
    if tsresol & 0x80 != 0 {
        2f64.powi((tsresol & 0x7f) as i32)
    } else {
        10f64.powi(tsresol as i32)
    }
}

pub fn analyze_file(path: &Path, max_packets: u64) -> AppResult<(FlowTable, ReadStats)> {
    let file = File::open(path)
        .map_err(|e| AppError::InvalidArg(tf!("無法開啟 {path}：{e}", path = path.display(), e = e)))?;
    let mut reader = pcap_parser::create_reader(1 << 20, BufReader::new(file))
        .map_err(|e| AppError::Parse(tf!("不是 pcap／pcapng 檔：{e:?}", e = e)))?;
    let mut table = FlowTable::new();
    let mut stats = ReadStats::default();
    let mut legacy_link = Linktype::ETHERNET;
    let mut legacy_nanos = false;
    // pcapng：每個介面的 (link type, 時間單位)
    let mut ifaces: Vec<(Linktype, f64)> = Vec::new();
    loop {
        if stats.records >= max_packets {
            stats.truncated = true;
            break;
        }
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(h) => {
                        legacy_link = h.network;
                        legacy_nanos = h.is_nanosecond_precision();
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frac = if legacy_nanos {
                            b.ts_usec as f64 / 1e9
                        } else {
                            b.ts_usec as f64 / 1e6
                        };
                        ingest(
                            &mut table,
                            &mut stats,
                            legacy_link,
                            b.ts_sec as f64 + frac,
                            b.origlen as u64,
                            b.data,
                        );
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => ifaces.clear(),
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        ifaces.push((idb.linktype, ts_units(idb.if_tsresol)));
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let (link, units) = ifaces
                            .get(epb.if_id as usize)
                            .copied()
                            .unwrap_or((Linktype::ETHERNET, 1e6));
                        let raw = ((epb.ts_high as u64) << 32) | epb.ts_low as u64;
                        ingest(
                            &mut table,
                            &mut stats,
                            link,
                            raw as f64 / units,
                            epb.origlen as u64,
                            epb.data,
                        );
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        let link = ifaces.first().map(|i| i.0).unwrap_or(Linktype::ETHERNET);
                        ingest(&mut table, &mut stats, link, 0.0, spb.origlen as u64, spb.data);
                    }
                    PcapBlockOwned::NG(_) => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader
                    .refill()
                    .map_err(|e| AppError::Parse(tf!("讀取 pcap 失敗：{e:?}", e = e)))?;
            }
            Err(e) => {
                // 檔尾截斷等：保留已解析的部分
                stats.truncated = true;
                if stats.records == 0 {
                    return Err(AppError::Parse(tf!("讀取 pcap 失敗：{e:?}", e = e)));
                }
                break;
            }
        }
    }
    Ok((table, stats))
}

#[cfg(test)]
pub(crate) mod testcap {
    //! 用 etherparse 組封包、手寫 pcap 檔頭，產生可重現的測試擷取檔。
    use etherparse::PacketBuilder;

    pub struct Cap {
        pub records: Vec<(f64, Vec<u8>)>,
    }

    const LOCAL: [u8; 4] = [192, 168, 1, 10];
    const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

    impl Cap {
        pub fn new() -> Self {
            Self { records: Vec::new() }
        }

        pub fn tcp(&mut self, ts: f64, src: ([u8; 4], u16), dst: ([u8; 4], u16), syn: bool, ack: bool, payload: &[u8]) {
            let mut b = PacketBuilder::ethernet2(MAC_A, MAC_B)
                .ipv4(src.0, dst.0, 64)
                .tcp(src.1, dst.1, 1, 64240);
            if syn {
                b = b.syn();
            }
            if ack {
                b = b.ack(1);
            }
            let mut v = Vec::with_capacity(b.size(payload.len()));
            b.write(&mut v, payload).unwrap();
            self.records.push((ts, v));
        }

        pub fn udp(&mut self, ts: f64, src: ([u8; 4], u16), dst: ([u8; 4], u16), payload: &[u8]) {
            let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
                .ipv4(src.0, dst.0, 64)
                .udp(src.1, dst.1);
            let mut v = Vec::with_capacity(b.size(payload.len()));
            b.write(&mut v, payload).unwrap();
            self.records.push((ts, v));
        }

        /// pcapng：SHB → IDB（Ethernet、奈秒解析度）→ 每個封包一個 EPB。
        pub fn to_pcapng(&self) -> Vec<u8> {
            fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
                let pad = (4 - body.len() % 4) % 4;
                let len = (12 + body.len() + pad) as u32;
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(body);
                out.extend(std::iter::repeat_n(0u8, pad));
                out.extend_from_slice(&len.to_le_bytes());
            }
            let mut out = Vec::new();
            let mut shb = Vec::new();
            shb.extend_from_slice(&0x1A2B3C4Du32.to_le_bytes());
            shb.extend_from_slice(&1u16.to_le_bytes());
            shb.extend_from_slice(&0u16.to_le_bytes());
            shb.extend_from_slice(&(-1i64).to_le_bytes());
            block(&mut out, 0x0A0D0D0A, &shb);
            let mut idb = Vec::new();
            idb.extend_from_slice(&1u16.to_le_bytes()); // ETHERNET
            idb.extend_from_slice(&0u16.to_le_bytes());
            idb.extend_from_slice(&65535u32.to_le_bytes());
            // option if_tsresol = 9（奈秒）
            idb.extend_from_slice(&9u16.to_le_bytes());
            idb.extend_from_slice(&1u16.to_le_bytes());
            idb.extend_from_slice(&[9, 0, 0, 0]);
            idb.extend_from_slice(&[0, 0, 0, 0]); // opt_endofopt
            block(&mut out, 1, &idb);
            for (ts, data) in &self.records {
                let t = (ts * 1e9).round() as u64;
                let mut epb = Vec::new();
                epb.extend_from_slice(&0u32.to_le_bytes());
                epb.extend_from_slice(&((t >> 32) as u32).to_le_bytes());
                epb.extend_from_slice(&(t as u32).to_le_bytes());
                epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
                epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
                epb.extend_from_slice(data);
                epb.extend(std::iter::repeat_n(0u8, (4 - data.len() % 4) % 4));
                block(&mut out, 6, &epb);
            }
            out
        }

        pub fn to_pcap(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
            out.extend_from_slice(&2u16.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&0i32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&65535u32.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes()); // ETHERNET
            for (ts, data) in &self.records {
                out.extend_from_slice(&(ts.trunc() as u32).to_le_bytes());
                out.extend_from_slice(&((ts.fract() * 1e6).round() as u32).to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(data);
            }
            out
        }
    }

    /// 一個涵蓋所有偵測的擷取：DNS、TLS SNI、明文 HTTP、Telnet、大量上傳、週期性連到 4444。
    pub fn scenario() -> Cap {
        use crate::traffic::proto::build;
        let mut c = Cap::new();
        let t0 = 1_760_000_000.0;
        let dns = [8, 8, 8, 8];
        c.udp(t0, (LOCAL, 53001), (dns, 53), &build::dns_query(1, "example.com", 1));
        c.udp(
            t0 + 0.02,
            (dns, 53),
            (LOCAL, 53001),
            &build::dns_response(1, "example.com", [93, 184, 216, 34]),
        );
        c.udp(
            t0 + 0.1,
            (LOCAL, 53002),
            (dns, 53),
            &build::dns_query(2, "q7x9z2k4m8v1b3n5c6d0f2g7.example.net", 1),
        );
        let web = [93, 184, 216, 34];
        c.tcp(t0 + 1.0, (LOCAL, 50000), (web, 443), true, false, b"");
        c.tcp(t0 + 1.05, (web, 443), (LOCAL, 50000), true, true, b"");
        c.tcp(
            t0 + 1.1,
            (LOCAL, 50000),
            (web, 443),
            false,
            true,
            &build::client_hello("example.com"),
        );
        let plain = [198, 51, 100, 20];
        c.tcp(t0 + 2.0, (LOCAL, 50001), (plain, 80), true, false, b"");
        c.tcp(
            t0 + 2.1,
            (LOCAL, 50001),
            (plain, 80),
            false,
            true,
            b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n",
        );
        c.tcp(t0 + 3.0, (LOCAL, 50002), ([203, 0, 113, 5], 23), true, false, b"");
        let sink = [203, 0, 113, 9];
        let chunk = vec![0x41u8; 1400];
        for i in 0..800 {
            c.tcp(
                t0 + 4.0 + i as f64 * 0.001,
                (LOCAL, 50003),
                (sink, 8443),
                false,
                true,
                &chunk,
            );
        }
        c.tcp(t0 + 5.0, (sink, 8443), (LOCAL, 50003), false, true, b"ok");
        let c2 = [203, 0, 113, 77];
        for i in 0..6 {
            c.tcp(
                t0 + 10.0 + i as f64 * 60.0,
                (LOCAL, 51000 + i),
                (c2, 4444),
                true,
                false,
                b"",
            );
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::summary;

    #[test]
    fn analyzes_a_synthetic_capture() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scenario.pcap");
        std::fs::write(&p, testcap::scenario().to_pcap()).unwrap();
        // 手動檢查 CLI 用：ASA_DUMP_PCAP=<路徑> cargo test analyzes_a_synthetic_capture
        if let Ok(out) = std::env::var("ASA_DUMP_PCAP") {
            std::fs::copy(&p, out).unwrap();
        }
        let (table, stats) = analyze_file(&p, DEFAULT_MAX_PACKETS).unwrap();
        assert_eq!(stats.records, 816);
        assert_eq!(stats.undecodable, 0);
        let s = summary::from_flows(&table, "scenario.pcap", None);
        assert_eq!(s.mode, "pcap");
        assert_eq!(s.totals.packets, 816);
        assert!(s.window.duration_s > 300.0);
        // DNS：名稱、答案、高熵可疑
        let ex = s.dns_queries.iter().find(|d| d.name == "example.com").unwrap();
        assert_eq!(ex.answers, vec!["93.184.216.34".to_string()]);
        assert!(s
            .dns_queries
            .iter()
            .any(|d| d.name.starts_with("q7x9") && d.suspicious.is_some()));
        // SNI 與 HTTP Host
        assert_eq!(s.tls_sni[0].name, "example.com");
        assert_eq!(s.http_hosts[0].name, "plain.example");
        // top talker：上傳最多的那台，並帶 DNS／SNI 名稱
        assert_eq!(s.top_talkers[0].remote, "203.0.113.9");
        let web = s.top_talkers.iter().find(|t| t.remote == "93.184.216.34").unwrap();
        assert_eq!(web.domain.as_deref(), Some("example.com"));
        let kinds: Vec<(&str, &str)> = s.alerts.iter().map(|a| (a.kind.as_str(), a.remote.as_str())).collect();
        assert!(kinds.contains(&("plaintext_protocol", "198.51.100.20")), "{kinds:?}");
        assert!(kinds.contains(&("plaintext_protocol", "203.0.113.5")), "{kinds:?}");
        assert!(kinds.contains(&("large_upload", "203.0.113.9")), "{kinds:?}");
        assert!(kinds.contains(&("beaconing", "203.0.113.77")), "{kinds:?}");
        assert!(kinds.contains(&("unusual_port", "203.0.113.77")), "{kinds:?}");
        assert!(
            kinds.contains(&("suspicious_dns", "q7x9z2k4m8v1b3n5c6d0f2g7.example.net")),
            "{kinds:?}"
        );
        // Telnet 是高風險、排最前面
        assert_eq!(s.alerts[0].severity, "high");
        // 摘要要夠小（給 LLM）
        assert!(serde_json::to_vec(&s).unwrap().len() < 40 * 1024);
    }

    #[test]
    fn reads_pcapng_with_nanosecond_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("scenario.pcapng");
        std::fs::write(&p, testcap::scenario().to_pcapng()).unwrap();
        let (table, stats) = analyze_file(&p, DEFAULT_MAX_PACKETS).unwrap();
        assert_eq!((stats.records, stats.undecodable, stats.unsupported_link), (816, 0, 0));
        let s = summary::from_flows(&table, "scenario.pcapng", None);
        assert!((s.window.duration_s - 310.0).abs() < 1.0, "{}", s.window.duration_s);
        assert_eq!(s.window.start.as_deref(), Some("2025-10-09T08:53:20Z"));
        assert!(s.alerts.iter().any(|a| a.kind == "beaconing"));
    }

    #[test]
    fn rejects_non_pcap_and_truncates_large_files() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("x.pcap");
        std::fs::write(&bad, b"hello world, not a capture").unwrap();
        assert!(analyze_file(&bad, 10).is_err());
        let p = dir.path().join("s.pcap");
        std::fs::write(&p, testcap::scenario().to_pcap()).unwrap();
        let (_, stats) = analyze_file(&p, 100).unwrap();
        assert!(stats.truncated);
        assert_eq!(stats.records, 100);
    }
}
