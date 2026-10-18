//! 防護 DNS 的封鎖／允許清單：從已下載的情資（`<設定目錄>/feeds/<id>/data`，Hub 鏡像或廠商）挑網域清單，
//! 每個來源分開解析（不合併成檔案，守住 GPL／CC 授權隔離），在記憶體裡合成一個 [`DomainSet`]（只存雜湊，200 萬筆約 24 MB）。
//! 比對：允許清單（白名單、known-good、熱門網域本身）優先；再看封鎖清單（條目涵蓋子網域）。

use std::collections::HashSet;
use std::path::Path;

use crate::connections::KnownGood;
use crate::dns::heuristics;
use crate::intel::domainset::{self, DomainSet, NO_META};
use crate::intel::fetch::{feed_dir, FeedMeta, DATA_FILE};
use crate::intel::parse;
use crate::intel::registry::{FeedEntry, FeedKind, Registry};

/// 預設只拿信心 ≥ 這個值的網域清單來封鎖（CERT.PL 85、HaGeZi TIF mini 75）。
pub const DEFAULT_MIN_CONFIDENCE: u8 = 75;
/// 一定不封鎖的名稱（完全相同才算；子網域照常比對，避免整個託管平台被放行）。
const NEVER_BLOCK: [&str; 12] = [
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "www.google.com",
    "google.com",
    "www.microsoft.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "www.apple.com",
    "apple.com",
    "drive.google.com",
    "docs.google.com",
];
/// 關掉瀏覽器自帶加密 DNS 的「暗號」網域（回 NXDOMAIN 讓 Firefox 停用 DoH；iCloud Private Relay 可選）。
pub const CANARY: [&str; 1] = ["use-application-dns.net"];
pub const PRIVATE_RELAY: [&str; 2] = ["mask.icloud.com", "mask-h2.icloud.com"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 照常解析。
    Pass,
    /// 封鎖；附上清單名稱（記錄與 EDE 用）。
    Block(String),
}

#[derive(Default)]
pub struct Lists {
    block: DomainSet,
    /// meta 索引 → 清單名稱。
    sources: Vec<String>,
    allow: DomainSet,
    exact_allow: HashSet<u64>,
    bypass: HashSet<u64>,
    pub entries: usize,
    pub loaded: Vec<String>,
    pub missing: Vec<String>,
}

pub struct ListOpts<'a> {
    /// 指定清單 id（空＝依信心門檻自動挑已啟用的網域清單）。
    pub feeds: &'a [String],
    pub min_confidence: u8,
    /// 管理員自訂封鎖（網域，含子網域）。
    pub custom_block: &'a [String],
    /// 管理員白名單（網域，含子網域）。
    pub custom_allow: &'a [String],
    pub block_canary: bool,
    pub block_private_relay: bool,
}

/// 要拿來封鎖的網域情資：指定的，或自動挑已啟用、信心夠高、可商用的（非商用授權的來源照防火牆的規矩只告警不封鎖）。
fn picked<'r>(reg: &'r Registry, o: &ListOpts<'_>) -> Vec<&'r FeedEntry> {
    reg.feeds
        .iter()
        .filter(|f| f.kind == FeedKind::Domain)
        .filter(|f| {
            if o.feeds.is_empty() {
                reg.is_enabled(f) && f.confidence >= o.min_confidence && f.license.commercial_ok
            } else {
                o.feeds.contains(&f.id)
            }
        })
        .collect()
}

/// 要下載的清單 id（防護 DNS 自己更新情資時用）。
pub fn wanted_feeds(config_dir: &Path, o: &ListOpts<'_>) -> Vec<String> {
    let reg = Registry::load(config_dir).unwrap_or_default();
    picked(&reg, o).into_iter().map(|f| f.id.clone()).collect()
}

impl Lists {
    pub fn load(config_dir: &Path, o: &ListOpts<'_>) -> Lists {
        let mut l = Lists::default();
        let reg = Registry::load(config_dir).unwrap_or_default();
        let picked = picked(&reg, o);
        let mut entries: Vec<(u64, u32)> = Vec::new();
        for f in picked {
            let has = FeedMeta::load(config_dir, &f.id).is_some_and(|m| m.has_data());
            let bytes = has
                .then(|| std::fs::read(feed_dir(config_dir, &f.id).join(DATA_FILE)).ok())
                .flatten();
            let Some(bytes) = bytes else {
                l.missing.push(f.id.clone());
                continue;
            };
            let Ok(p) = parse::parse(f.format, &bytes) else {
                l.missing.push(f.id.clone());
                continue;
            };
            let idx = l.sources.len() as u32;
            l.sources.push(f.name.clone());
            entries.extend(p.domain_hashes.into_iter().map(|h| (h, idx)));
            // 每筆自己帶的信心（例如 URLhaus 的網域級條目只有 40）也要過門檻
            for r in p.records {
                if let parse::Indicator::Domain(d) = r.ind {
                    if r.confidence.unwrap_or(f.confidence) >= o.min_confidence {
                        entries.push((domainset::hash(&d), idx));
                    }
                }
            }
            l.loaded.push(f.id.clone());
        }
        let local = crate::dns::blocklist::Blocklist::load(config_dir).domains();
        if !local.is_empty() {
            let idx = l.sources.len() as u32;
            l.sources.push(t!("這台電腦的黑名單").to_string());
            entries.extend(local.iter().map(|d| (domainset::hash(d), idx)));
            l.loaded.push("local-blocklist".into());
        }
        if !o.custom_block.is_empty() {
            let idx = l.sources.len() as u32;
            l.sources.push(t!("自訂封鎖").to_string());
            entries.extend(
                o.custom_block
                    .iter()
                    .filter_map(|d| domainset::normalize(d))
                    .map(|d| (domainset::hash(&d), idx)),
            );
        }
        l.entries = entries.len();
        l.block = DomainSet::build(entries);
        let kg = KnownGood::load();
        let local_allow = crate::dns::blocklist::local_allow(config_dir);
        let allow: Vec<(u64, u32)> = o
            .custom_allow
            .iter()
            .chain(local_allow.iter())
            .filter_map(|d| domainset::normalize(d))
            .chain(kg.domain_patterns().map(|d| d.trim_start_matches("*.").to_string()))
            .map(|d| (domainset::hash(&d), NO_META))
            .collect();
        l.allow = DomainSet::build(allow);
        l.exact_allow = NEVER_BLOCK.iter().map(|d| domainset::hash(d)).collect();
        if o.block_canary {
            l.bypass.extend(CANARY.iter().map(|d| domainset::hash(d)));
        }
        if o.block_private_relay {
            l.bypass.extend(PRIVATE_RELAY.iter().map(|d| domainset::hash(d)));
        }
        l
    }

    /// 這個名稱要不要封鎖。
    pub fn decide(&self, name: &str) -> Decision {
        let h = domainset::hash(name);
        if self.bypass.contains(&h) {
            return Decision::Block(t!("加密 DNS 繞過").to_string());
        }
        if self.block.is_empty() {
            return Decision::Pass;
        }
        let Some(hit) = self.block.lookup(name, true) else {
            return Decision::Pass;
        };
        // 允許清單：白名單與 known-good（含子網域）、固定不封鎖的名稱、熱門網域本身（完全相同才算）
        if self.allow.lookup(name, true).is_some()
            || self.exact_allow.contains(&h)
            || (heuristics::is_popular(name) && heuristics::registrable_domain(name) == Some(name))
        {
            return Decision::Pass;
        }
        let src = self
            .sources
            .get(hit.meta as usize)
            .cloned()
            .unwrap_or_else(|| t!("封鎖清單").to_string());
        Decision::Block(src)
    }

    pub fn memory_bytes(&self) -> usize {
        self.block.heap_bytes() + self.allow.heap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/feeds");
        for (id, file) in [
            ("certpl-domains", "certpl_domains.txt"),
            ("hagezi-tif-mini", "hagezi_tif_mini.txt"),
            ("phishing-database-active", "phishing_db.txt"),
        ] {
            let fdir = feed_dir(dir.path(), id);
            std::fs::create_dir_all(&fdir).unwrap();
            std::fs::copy(fx.join(file), fdir.join(DATA_FILE)).unwrap();
            FeedMeta {
                feed_id: id.into(),
                fetched_at: Some(chrono::Utc::now()),
                status: "ok".into(),
                entries: 1,
                ..Default::default()
            }
            .save(dir.path())
            .unwrap();
        }
        dir
    }

    #[test]
    fn blocks_high_confidence_feeds_with_allowlist() {
        let dir = fixture_dir();
        let o = ListOpts {
            feeds: &[],
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            custom_block: &["bad.example".into()],
            custom_allow: &["c2.example.test".into()],
            block_canary: true,
            block_private_relay: false,
        };
        let l = Lists::load(dir.path(), &o);
        // Phishing.Database（60）不進封鎖
        assert_eq!(l.loaded, vec!["certpl-domains", "hagezi-tif-mini"]);
        assert!(matches!(l.decide("www.phish-bank.example.test"), Decision::Block(s) if s.contains("CERT")));
        assert!(matches!(l.decide("x.malware.example.test"), Decision::Block(_)));
        assert_eq!(l.decide("exact-only.example.test"), Decision::Pass);
        // 白名單蓋過封鎖清單
        assert_eq!(l.decide("a.c2.example.test"), Decision::Pass);
        assert!(matches!(l.decide("www.bad.example"), Decision::Block(s) if s == "自訂封鎖" || s == "Custom block"));
        assert!(matches!(l.decide("use-application-dns.net"), Decision::Block(_)));
        assert_eq!(l.decide("mask.icloud.com"), Decision::Pass);
        assert_eq!(l.decide("example.com"), Decision::Pass);
    }

    #[test]
    fn explicit_feed_selection() {
        let dir = fixture_dir();
        let o = ListOpts {
            feeds: &["phishing-database-active".into()],
            min_confidence: 0,
            custom_block: &[],
            custom_allow: &[],
            block_canary: false,
            block_private_relay: false,
        };
        let l = Lists::load(dir.path(), &o);
        assert_eq!(l.loaded, vec!["phishing-database-active"]);
        assert!(matches!(l.decide("exact-only.example.test"), Decision::Block(_)));
        assert_eq!(l.decide("use-application-dns.net"), Decision::Pass);
    }
}
