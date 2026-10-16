//! 情資格式解析：純文字 IP / CIDR、Spamhaus NDJSON、URLhaus URL 清單、ThreatFox JSON、DShield tab、IPsum、CISA KEV。
//! 解析結果保留每筆的附加資訊（SBL id、惡意程式家族、分數…）與檔頭（授權要求保留）。

use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::{json, Value};

use super::registry::FeedFormat;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, PartialEq)]
pub enum Indicator {
    Net(IpNet),
    IpPort(IpAddr, u16),
    Domain(String),
    Asn(u32),
    Cve(String),
}

#[derive(Debug, Clone)]
pub struct Record {
    pub ind: Indicator,
    pub extra: Value,
    /// 每筆自帶的信心值（IPsum score、ThreatFox confidence_level），覆蓋來源預設。
    pub confidence: Option<u8>,
}

#[derive(Debug, Default)]
pub struct Parsed {
    pub records: Vec<Record>,
    pub header_lines: Vec<String>,
}

const MAX_HEADER_LINES: usize = 12;
/// URLhaus 網域級命中的信心（低於危險門檻 80）。
pub const URLHAUS_DOMAIN_CONFIDENCE: u8 = 40;

fn rec(ind: Indicator) -> Record {
    Record {
        ind,
        extra: Value::Null,
        confidence: None,
    }
}

pub fn parse_ip_or_net(tok: &str) -> Option<IpNet> {
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(n) = t.parse::<IpNet>() {
        return Some(n.trunc());
    }
    t.parse::<IpAddr>().ok().map(IpNet::from)
}

fn is_comment(l: &str) -> bool {
    l.starts_with('#') || l.starts_with(';') || l.starts_with("//")
}

fn push_header(p: &mut Parsed, l: &str) {
    if p.records.is_empty() && p.header_lines.len() < MAX_HEADER_LINES {
        p.header_lines.push(l.to_string());
    }
}

/// 每行一個 IP 或 CIDR；行內 `#`、`;`、`,`、空白之後的內容忽略。
fn parse_lines(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if is_comment(l) {
            push_header(&mut p, l);
            continue;
        }
        let tok = l
            .split(|c: char| c.is_whitespace() || c == ';' || c == ',' || c == '#')
            .next()
            .unwrap_or("");
        if let Some(n) = parse_ip_or_net(tok) {
            p.records.push(rec(Indicator::Net(n)));
        }
    }
    p
}

/// IPsum：`ip<TAB>score`；有效信心 = min(95, 40 + 10 × score)。
fn parse_ipsum(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if is_comment(l) {
            push_header(&mut p, l);
            continue;
        }
        let mut parts = l.split_whitespace();
        let Some(n) = parts.next().and_then(parse_ip_or_net) else {
            continue;
        };
        let score: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(1);
        p.records.push(Record {
            ind: Indicator::Net(n),
            extra: json!({ "score": score }),
            confidence: Some((40 + 10 * score).min(95) as u8),
        });
    }
    p
}

/// DShield block.txt：`start<TAB>end<TAB>netmask<TAB>attacks<TAB>name<TAB>country<TAB>email`。
fn parse_dshield(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if is_comment(l) {
            push_header(&mut p, l);
            continue;
        }
        let cols: Vec<&str> = l.split('\t').map(str::trim).collect();
        let cols = if cols.len() >= 3 {
            cols
        } else {
            l.split_whitespace().collect()
        };
        if cols.len() < 3 {
            continue;
        }
        let (Ok(start), Ok(mask)) = (cols[0].parse::<IpAddr>(), cols[2].parse::<u8>()) else {
            continue;
        };
        let Ok(net) = IpNet::new(start, mask) else {
            continue;
        };
        p.records.push(Record {
            ind: Indicator::Net(net.trunc()),
            extra: json!({
                "attacks": cols.get(3).and_then(|s| s.parse::<u64>().ok()),
                "name": cols.get(4),
                "country": cols.get(5),
            }),
            confidence: None,
        });
    }
    p
}

/// Spamhaus DROP / ASN-DROP：NDJSON，最後一行是 `{"type":"metadata",…}`（授權要求保留）。
fn parse_spamhaus(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(l) else {
            continue;
        };
        if v["type"] == "metadata" {
            p.header_lines.push(l.to_string());
            continue;
        }
        if let Some(c) = v["cidr"].as_str() {
            if let Some(n) = parse_ip_or_net(c) {
                p.records.push(Record {
                    ind: Indicator::Net(n),
                    extra: json!({ "sblid": v["sblid"], "rir": v["rir"] }),
                    confidence: None,
                });
            }
        } else if !v["asn"].is_null() {
            let asn = match &v["asn"] {
                Value::Number(n) => n.as_u64().map(|x| x as u32),
                Value::String(s) => s.trim_start_matches("AS").trim_start_matches("as").parse().ok(),
                _ => None,
            };
            if let Some(a) = asn {
                p.records.push(Record {
                    ind: Indicator::Asn(a),
                    extra: json!({ "asname": v["asname"], "cc": v["cc"], "domain": v["domain"] }),
                    confidence: None,
                });
            }
        }
    }
    p
}

/// 由 URL 取出 host（處理 userinfo、port、IPv6 中括號）。
pub fn host_of_url(u: &str) -> Option<String> {
    let rest = u.split_once("://").map(|x| x.1).unwrap_or(u);
    let hostport = rest.split(['/', '?', '#']).next()?;
    let hostport = hostport.rsplit('@').next()?;
    if let Some(stripped) = hostport.strip_prefix('[') {
        return stripped.split(']').next().map(|s| s.to_ascii_lowercase());
    }
    let host = hostport.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// URLhaus text_online：每行一個 URL → host（IP 或網域）。
fn parse_urlhaus(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut seen = std::collections::HashSet::new();
    for raw in text.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        if is_comment(l) {
            push_header(&mut p, l);
            continue;
        }
        let Some(host) = host_of_url(l) else {
            continue;
        };
        if !seen.insert(host.clone()) {
            continue;
        }
        let extra = json!({ "url": l });
        if let Ok(ip) = host.parse::<IpAddr>() {
            p.records.push(Record {
                ind: Indicator::Net(IpNet::from(ip)),
                extra,
                confidence: None,
            });
        } else if host.contains('.') {
            p.records.push(Record {
                ind: Indicator::Domain(host),
                extra: json!({ "url": l, "url_level": true }),
                // URLhaus 列的是單一 URL；共用主機（CDN、雲端硬碟）整台判死會誤殺 → 降為可疑等級。
                confidence: Some(URLHAUS_DOMAIN_CONFIDENCE),
            });
        }
    }
    p
}

/// ThreatFox `export/json/ip-port/recent`：`{ "<id>": [ { ioc_value: "ip:port", … } ] }`。
fn parse_threatfox(bytes: &[u8]) -> AppResult<Parsed> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| AppError::Parse(e.to_string()))?;
    let mut p = Parsed::default();
    let Some(obj) = v.as_object() else {
        return Ok(p);
    };
    for (_, arr) in obj {
        let Some(items) = arr.as_array() else {
            continue;
        };
        for it in items {
            let Some(val) = it["ioc_value"].as_str() else {
                continue;
            };
            let Some((ip, port)) = val.rsplit_once(':') else {
                continue;
            };
            let (Ok(ip), Ok(port)) = (ip.trim_matches(['[', ']']).parse::<IpAddr>(), port.parse::<u16>()) else {
                continue;
            };
            p.records.push(Record {
                ind: Indicator::IpPort(ip, port),
                extra: json!({
                    "malware": it["malware_printable"],
                    "threat_type": it["threat_type"],
                    "first_seen": it["first_seen_utc"],
                }),
                confidence: it["confidence_level"].as_u64().map(|c| c.min(100) as u8),
            });
        }
    }
    Ok(p)
}

/// CISA KEV：`vulnerabilities[].cveID`。
fn parse_kev(bytes: &[u8]) -> AppResult<Parsed> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| AppError::Parse(e.to_string()))?;
    let mut p = Parsed::default();
    if let Some(ver) = v["catalogVersion"].as_str() {
        p.header_lines.push(format!(
            "catalogVersion {ver} released {}",
            v["dateReleased"].as_str().unwrap_or("")
        ));
    }
    for it in v["vulnerabilities"].as_array().into_iter().flatten() {
        if let Some(id) = it["cveID"].as_str() {
            p.records.push(Record {
                ind: Indicator::Cve(id.to_ascii_uppercase()),
                extra: json!({
                    "vendor": it["vendorProject"],
                    "product": it["product"],
                    "name": it["vulnerabilityName"],
                    "date_added": it["dateAdded"],
                    "due_date": it["dueDate"],
                    "ransomware": it["knownRansomwareCampaignUse"],
                }),
                confidence: None,
            });
        }
    }
    Ok(p)
}

/// 下載到的是 HTML 錯誤頁 / 登入頁，而不是清單。
pub fn looks_like_html(bytes: &[u8]) -> bool {
    let head: String = String::from_utf8_lossy(&bytes[..bytes.len().min(512)])
        .trim_start()
        .to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html") || head.starts_with("<head")
}

pub fn parse(format: FeedFormat, bytes: &[u8]) -> AppResult<Parsed> {
    if looks_like_html(bytes) {
        return Err(AppError::Parse(t!("下載內容是 HTML 網頁而不是清單").into()));
    }
    let text = || String::from_utf8_lossy(bytes);
    Ok(match format {
        FeedFormat::PlainIpPerLine | FeedFormat::CidrPerLine => parse_lines(&text()),
        FeedFormat::IpsumTab => parse_ipsum(&text()),
        FeedFormat::DshieldTab => parse_dshield(&text()),
        FeedFormat::SpamhausJson => parse_spamhaus(&text()),
        FeedFormat::UrlhausText => parse_urlhaus(&text()),
        FeedFormat::ThreatfoxJson => parse_threatfox(bytes)?,
        FeedFormat::CisaKevJson => parse_kev(bytes)?,
        FeedFormat::MmdbGz | FeedFormat::LookupApi | FeedFormat::Unknown => {
            return Err(AppError::Unsupported(tf!(
                "此格式不能當清單解析：{format}",
                format = format!("{format:?}")
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/feeds")
                .join(name),
        )
        .unwrap()
    }

    fn nets(p: &Parsed) -> Vec<String> {
        p.records
            .iter()
            .filter_map(|r| match &r.ind {
                Indicator::Net(n) => Some(n.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn plain_lists_keep_header_and_skip_comments() {
        let p = parse(FeedFormat::PlainIpPerLine, &fixture("feodo_recommended.txt")).unwrap();
        assert_eq!(
            nets(&p),
            vec!["185.199.108.9/32", "203.0.113.200/32", "45.33.32.156/32"]
        );
        assert!(p.header_lines[1].contains("abuse.ch"));
        let p = parse(FeedFormat::CidrPerLine, &fixture("firehol_level1.netset")).unwrap();
        assert!(nets(&p).contains(&"203.0.113.64/26".to_string()));
        assert!(nets(&p).contains(&"224.0.0.0/3".to_string()));
        let p = parse(FeedFormat::CidrPerLine, &fixture("et_block.txt")).unwrap();
        assert_eq!(p.records.len(), 3);
    }

    #[test]
    fn spamhaus_ndjson_with_metadata() {
        let p = parse(FeedFormat::SpamhausJson, &fixture("drop_v4.json")).unwrap();
        assert_eq!(p.records.len(), 3);
        assert_eq!(p.records[0].extra["sblid"], "SBL256894");
        assert!(p.header_lines[0].contains("Spamhaus"));
        let p = parse(FeedFormat::SpamhausJson, &fixture("drop_v6.json")).unwrap();
        assert_eq!(nets(&p)[0], "2a06:e480::/29");
        let p = parse(FeedFormat::SpamhausJson, &fixture("asndrop.json")).unwrap();
        assert_eq!(p.records[1].ind, Indicator::Asn(67890));
    }

    #[test]
    fn urlhaus_hosts() {
        let p = parse(FeedFormat::UrlhausText, &fixture("urlhaus_hosts.txt")).unwrap();
        let inds: Vec<&Indicator> = p.records.iter().map(|r| &r.ind).collect();
        assert!(inds.contains(&&Indicator::Net("185.199.108.11/32".parse().unwrap())));
        assert!(inds.contains(&&Indicator::Domain("evil.example.test".into())));
        let dom = p
            .records
            .iter()
            .find(|r| matches!(r.ind, Indicator::Domain(_)))
            .unwrap();
        assert_eq!(dom.confidence, Some(URLHAUS_DOMAIN_CONFIDENCE));
        assert!(inds.contains(&&Indicator::Net("198.51.100.7/32".parse().unwrap())));
        assert!(inds.contains(&&Indicator::Net("2001:db8::1/128".parse().unwrap())));
        assert_eq!(
            host_of_url("http://user:pw@Host.Example:8080/x"),
            Some("host.example".into())
        );
    }

    #[test]
    fn threatfox_ip_ports_with_confidence() {
        let p = parse(FeedFormat::ThreatfoxJson, &fixture("threatfox_ipport.json")).unwrap();
        assert_eq!(p.records.len(), 2);
        let r = p
            .records
            .iter()
            .find(|r| r.ind == Indicator::IpPort("185.199.108.12".parse().unwrap(), 443))
            .unwrap();
        assert_eq!(r.confidence, Some(75));
        assert_eq!(r.extra["malware"], "Cobalt Strike");
    }

    #[test]
    fn dshield_and_ipsum() {
        let p = parse(FeedFormat::DshieldTab, &fixture("dshield_block.txt")).unwrap();
        assert_eq!(nets(&p), vec!["185.199.108.0/24", "45.33.0.0/16"]);
        assert!(p.header_lines.iter().any(|l| l.contains("by-nc-sa")));
        let p = parse(FeedFormat::IpsumTab, &fixture("ipsum.txt")).unwrap();
        assert_eq!(p.records[0].confidence, Some(95));
        assert_eq!(p.records[1].confidence, Some(60));
        assert_eq!(p.records[2].extra["score"], 4);
    }

    #[test]
    fn kev_and_html_rejection() {
        let p = parse(FeedFormat::CisaKevJson, &fixture("kev_small.json")).unwrap();
        assert_eq!(p.records.len(), 2);
        assert_eq!(p.records[1].ind, Indicator::Cve("CVE-2021-44228".into()));
        assert!(parse(FeedFormat::PlainIpPerLine, b"<!DOCTYPE html><html>blocked</html>").is_err());
        assert!(parse(FeedFormat::MmdbGz, b"x").is_err());
    }
}
