//! intel 引擎：載入已下載的威脅情資 → 比對連線的遠端 IP（含 ip:port、ASN）→ 附上來源與授權，
//! 重算判定（安全／未知／可疑／危險），產生 finding。可選線上名譽查詢補強「未知」的公網 IP。

pub mod domainset;
pub mod fetch;
pub mod geo;
pub mod ipset;
pub mod lookup;
pub mod parse;
pub mod registry;

use std::net::IpAddr;
use std::path::Path;

use async_trait::async_trait;
use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::model::connection::{Connection, Direction};
use crate::model::finding::{ActionKind, Evidence, Finding, IntelHit, ProposedAction, ScannerId, Severity};
use crate::model::verdict::{AnomalyKind, Reason, Verdict, VerdictLevel};
use crate::scan::{ScanCtx, ScanOutput, Scanner};
use crate::util::net::classify;

use fetch::{feed_dir, FeedMeta, DATA_FILE};
use geo::GeoDb;
use ipset::{IpSet, RecordMeta};
use lookup::Reputation;
use registry::{FeedEntry, FeedKind, Registry};

pub const TOR_FEED: &str = "tor-exits";
/// 每次掃描最多做幾個 IP 的線上名譽查詢（保護免費額度）。
pub const MAX_ONLINE_LOOKUPS_PER_SCAN: usize = 10;

pub struct LoadedFeed {
    pub entry: FeedEntry,
    pub meta: FeedMeta,
    pub set: IpSet,
}

#[derive(Default)]
pub struct IntelDb {
    pub feeds: Vec<LoadedFeed>,
    /// 加密 DNS 端點清單（`kind: doh`）：不算威脅，只給繞過偵測用。
    pub doh: Vec<LoadedFeed>,
    pub geo: GeoDb,
    /// 已啟用但尚未下載的來源 id。
    pub missing: Vec<String>,
    pub warnings: Vec<String>,
}

impl IntelDb {
    /// 載入所有已啟用、已下載的清單類來源（解析失敗的記為警告，不中斷）。
    pub fn load(config_dir: &Path, reg: &Registry) -> IntelDb {
        let mut db = IntelDb {
            geo: GeoDb::load(config_dir),
            ..Default::default()
        };
        for f in reg
            .enabled()
            .filter(|f| (f.is_blocklist() || f.kind == FeedKind::Doh) && fetch::downloadable(f))
        {
            let Some(meta) = FeedMeta::load(config_dir, &f.id).filter(|m| m.has_data()) else {
                db.missing.push(f.id.clone());
                continue;
            };
            let bytes = match std::fs::read(feed_dir(config_dir, &f.id).join(DATA_FILE)) {
                Ok(b) => b,
                Err(_) => {
                    db.missing.push(f.id.clone());
                    continue;
                }
            };
            match parse::parse(f.format, &bytes) {
                Ok(p) => {
                    let lf = LoadedFeed {
                        entry: f.clone(),
                        meta,
                        set: IpSet::build_with_domains(p.records, p.domain_hashes),
                    };
                    if f.kind == FeedKind::Doh {
                        db.doh.push(lf);
                    } else {
                        db.feeds.push(lf);
                    }
                }
                Err(e) => db
                    .warnings
                    .push(tf!("解析情資 {id} 失敗：{e}", id = f.id, e = e.message())),
            }
        }
        db
    }

    pub fn entries(&self) -> usize {
        self.feeds.iter().map(|f| f.set.len()).sum()
    }

    fn hit(lf: &LoadedFeed, rm: &RecordMeta, adjust: i16) -> IntelHit {
        let base = rm.confidence.unwrap_or(lf.entry.confidence) as i16;
        let confidence = (base + adjust).clamp(1, 100) as u8;
        let mut extra = match &rm.extra {
            serde_json::Value::Object(m) => serde_json::Value::Object(m.clone()),
            _ => json!({}),
        };
        extra["commercial_ok"] = json!(lf.entry.license.commercial_ok);
        extra["feed_direction"] = json!(lf.entry.direction);
        if !lf.entry.tags.is_empty() {
            extra["tags"] = json!(lf.entry.tags);
        }
        IntelHit {
            feed_id: lf.entry.id.clone(),
            name: lf.entry.name.clone(),
            vendor: lf.entry.vendor.clone(),
            confidence,
            license: lf.entry.license.name.clone(),
            license_url: lf.entry.license.url.clone(),
            attribution_required: lf.entry.license.attribution_required,
            fetched_at: lf.meta.fetched_at.unwrap_or_else(chrono::Utc::now),
            source_url: lf.entry.source_url(),
            matched: rm.display.clone(),
            extra,
        }
    }

    /// 比對 IP（每個來源最多一筆命中）。`port` 用於 ip:port 類來源；ASN 類來源以 DB-IP ASN 對應。
    pub fn match_ip(&self, ip: IpAddr, port: Option<u16>) -> Vec<IntelHit> {
        let asn = self.geo.lookup(ip).and_then(|g| g.asn);
        let mut hits = Vec::new();
        for lf in &self.feeds {
            if let Some(rm) = lf.set.match_ip(ip) {
                hits.push(Self::hit(lf, rm, 0));
            } else if let Some((rm, exact)) = lf.set.match_ip_port(ip, port) {
                // 只有 IP 相符、port 不同：信心降 25。
                hits.push(Self::hit(lf, rm, if exact { 0 } else { -25 }));
            } else if let Some(rm) = asn.and_then(|a| lf.set.match_asn(a)) {
                hits.push(Self::hit(lf, rm, -10));
            }
        }
        hits.sort_by_key(|h| std::cmp::Reverse(h.confidence));
        hits
    }

    pub fn match_domain(&self, domain: &str) -> Vec<IntelHit> {
        let mut hits: Vec<IntelHit> = self
            .feeds
            .iter()
            .filter(|lf| lf.entry.kind == FeedKind::Domain)
            .filter_map(|lf| {
                lf.set
                    .match_domain(domain, lf.entry.match_subdomains)
                    .map(|rm| Self::hit(lf, &rm, 0))
            })
            .collect();
        hits.sort_by_key(|h| std::cmp::Reverse(h.confidence));
        hits
    }

    /// 網域是不是已知的加密 DNS（DoH／DoT）端點；回傳比中的清單 id 與那層網域。
    pub fn doh_endpoint(&self, domain: &str) -> Option<(String, String)> {
        self.doh.iter().find_map(|lf| {
            lf.set
                .match_domain(domain, lf.entry.match_subdomains)
                .map(|rm| (lf.entry.id.clone(), rm.display))
        })
    }
}

/// 網域綜合分數（0–100）：最高來源信心，每多一個不同來源 +10（上限 100）；
/// 熱門網域只對最高信心 < 70 的命中扣 30（不能蓋掉高信心情資）。
/// ≥ 80 危險、60–79 可疑、40–59 只當補充資訊。
pub fn domain_score(hits: &[IntelHit], popular: bool) -> u8 {
    let Some(max) = hits.iter().map(|h| h.confidence).max() else {
        return 0;
    };
    let mut feeds: Vec<&str> = hits.iter().map(|h| h.feed_id.as_str()).collect();
    feeds.sort_unstable();
    feeds.dedup();
    let mut score = u32::from(max) + 10 * (feeds.len() as u32).saturating_sub(1);
    if popular && max < 70 {
        score = score.saturating_sub(30);
    }
    score.min(100) as u8
}

fn severity_for(max_conf: u8) -> Severity {
    match max_conf {
        90..=u8::MAX => Severity::Critical,
        80..=89 => Severity::High,
        50..=79 => Severity::Medium,
        _ => Severity::Low,
    }
}

fn process_label(c: &Connection) -> String {
    c.process
        .as_ref()
        .map(|p| format!("{} (pid {})", p.name, p.pid))
        .unwrap_or_else(|| t!("未知行程").to_string())
}

/// 情資 / 名譽命中 → finding（附來源、授權、封鎖動作）。
pub fn intel_finding(c: &Connection, hits: &[IntelHit], reps: &[Reputation]) -> Finding {
    let inbound = c.direction == Direction::Inbound;
    let ip = c.remote_ip.map(|i| i.to_string()).unwrap_or_default();
    let max_conf = hits
        .iter()
        .map(|h| h.confidence)
        .chain(reps.iter().map(|r| r.score))
        .max()
        .unwrap_or(0);
    let mut sources: Vec<String> = hits
        .iter()
        .map(|h| format!("{} {}（{}，{}%）", h.vendor, h.name, h.license, h.confidence))
        .collect();
    sources.extend(reps.iter().map(|r| format!("{} score {}", r.provider, r.score)));
    let (rule, title) = if hits.is_empty() {
        ("intel.reputation", tf!("線上名譽服務標記為可疑的 IP：{ip}", ip = ip))
    } else if inbound {
        ("intel.inbound_match", tf!("來自威脅情資列名 IP 的連入：{ip}", ip = ip))
    } else {
        ("intel.outbound_match", tf!("連到威脅情資列名的 IP：{ip}", ip = ip))
    };
    let mut f = Finding::new(
        ScannerId::Intel,
        rule,
        &c.evidence_key(),
        severity_for(max_conf),
        title,
        tf!(
            "{process} ↔ {remote}（判定：{verdict}）。來源：{sources}",
            process = process_label(c),
            remote = c.remote_display(),
            verdict = c.verdict.level.label(),
            sources = sources.join("；")
        ),
        Evidence::Connection(c.clone()),
        t!("封鎖此 IP 並檢查相關行程；確認是誤判可加入白名單"),
    )
    .with_tag("intel")
    .with_action(ProposedAction {
        kind: ActionKind::BlockIp,
        params: json!({
            "ip": ip,
            "direction": if inbound { "inbound" } else { "both" },
            "reason": hits.first().map(|h| h.feed_id.clone()).unwrap_or_else(|| "reputation".into()),
        }),
        requires_elevation: true,
        destructive: false,
        reversible: true,
        description: tf!("以防火牆封鎖 {ip}（雙向）", ip = ip),
    });
    f.intel_hits = hits.to_vec();
    for h in hits {
        if !f.refs.contains(&h.source_url) {
            f.refs.push(h.source_url.clone());
        }
    }
    f
}

fn needs_intel(c: &Connection) -> Option<IpAddr> {
    if matches!(c.direction, Direction::Listening | Direction::Local) {
        return None;
    }
    c.remote_ip.filter(|ip| classify(*ip).is_public())
}

/// 對連線做情資比對與地理標註；命中者重算判定並回傳 finding。
pub fn enrich_connections(db: &IntelDb, conns: &mut [Connection]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for c in conns.iter_mut() {
        let Some(ip) = needs_intel(c) else {
            continue;
        };
        if let Some(g) = db.geo.lookup(ip) {
            c.geo = Some(g);
        }
        let hits = db.match_ip(ip, c.remote_port);
        if hits.is_empty() {
            continue;
        }
        let mut reasons = c.verdict.reasons.clone();
        for h in &hits {
            if h.feed_id == TOR_FEED {
                reasons.push(Reason::Anomaly {
                    kind: AnomalyKind::TorExit,
                    detail: ip.to_string(),
                });
            }
            reasons.push(Reason::IntelHit(Box::new(h.clone())));
        }
        c.verdict = Verdict::compute(reasons);
        // 白名單判 Safe 的不出 finding（使用者已明示）。
        if c.verdict.level != VerdictLevel::Safe {
            findings.push(intel_finding(c, &hits, &[]));
        }
    }
    findings
}

/// 把線上名譽結果套到某 IP 的所有連線；變成可疑 / 危險者回傳 finding。
pub fn apply_reputation(conns: &mut [Connection], ip: IpAddr, reps: &[Reputation]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if reps.is_empty() {
        return findings;
    }
    for c in conns.iter_mut().filter(|c| c.remote_ip == Some(ip)) {
        let before = c.verdict.level;
        let mut reasons = c.verdict.reasons.clone();
        for r in reps {
            reasons.push(Reason::Reputation {
                provider: r.provider.clone(),
                score: r.score,
                detail: r.detail.clone(),
            });
        }
        c.verdict = Verdict::compute(reasons);
        if c.verdict.is_bad() && !before_is_bad(before) {
            findings.push(intel_finding(c, &[], reps));
        }
    }
    findings
}

fn before_is_bad(l: VerdictLevel) -> bool {
    matches!(l, VerdictLevel::Suspicious | VerdictLevel::Dangerous)
}

pub struct IntelScanner;

#[async_trait]
impl Scanner for IntelScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Intel
    }

    fn depends_on(&self) -> &'static [ScannerId] {
        &[ScannerId::Connections]
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let reg = Registry::load(&ctx.config_dir)?;
        let mut warnings = reg.warnings.clone();
        if ctx.online && ctx.config.intel.refresh_on_scan {
            let progress = |m: &str| ctx.report_progress(m);
            match fetch::update(&ctx.config_dir, &reg, &fetch::UpdateOpts::default(), &progress).await {
                Ok(outs) => {
                    for o in outs.iter().filter(|o| o.status == "error") {
                        warnings.push(tf!(
                            "情資 {id} 更新失敗：{e}",
                            id = o.feed_id,
                            e = o.detail.clone().unwrap_or_default()
                        ));
                    }
                }
                Err(e) => warnings.push(e.message()),
            }
        }
        let dir = ctx.config_dir.clone();
        let reg2 = reg.clone();
        let db = tokio::task::spawn_blocking(move || IntelDb::load(&dir, &reg2))
            .await
            .map_err(|e| AppError::Intel(e.to_string()))?;
        warnings.extend(db.warnings.iter().cloned());
        if db.feeds.is_empty() {
            warnings.push(t!("尚未下載任何威脅情資；執行 ai-security-monitor intel update").into());
        } else if !db.missing.is_empty() {
            warnings.push(tf!(
                "有 {n} 個已啟用的情資來源尚未下載：{ids}",
                n = db.missing.len(),
                ids = db.missing.join(", ")
            ));
        }

        let mut findings;
        let unknown_ips: Vec<IpAddr>;
        {
            let mut shared = ctx.shared.lock().await;
            findings = enrich_connections(&db, &mut shared.connections);
            let mut ips: Vec<IpAddr> = shared
                .connections
                .iter()
                .filter(|c| c.verdict.level == VerdictLevel::Unknown && c.direction == Direction::Outbound)
                .filter_map(needs_intel)
                .collect();
            ips.sort();
            ips.dedup();
            unknown_ips = ips;
        }

        if ctx.online
            && ctx.config.intel.online_lookups
            && !lookup::configured_providers(&ctx.config_dir, &reg).is_empty()
        {
            for ip in unknown_ips.into_iter().take(MAX_ONLINE_LOOKUPS_PER_SCAN) {
                let (reps, w) = lookup::lookup_ip(&ctx.config_dir, &reg, ip).await;
                warnings.extend(w);
                let mut shared = ctx.shared.lock().await;
                findings.extend(apply_reputation(&mut shared.connections, ip, &reps));
            }
        }

        Ok(ScanOutput {
            findings,
            warnings,
            summary: Some(json!({
                "feeds_loaded": db.feeds.len(),
                "entries": db.entries(),
                "missing": db.missing,
                "geo": db.geo.is_loaded(),
            })),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::connection::ProcessRef;

    /// 以 fixtures 建一個假的設定目錄（像是 `ai-security-monitor intel update` 跑過）。
    pub fn fixture_config_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/feeds");
        let pairs = [
            ("abusech-feodo", "feodo_recommended.txt"),
            ("abusech-threatfox-ipport", "threatfox_ipport.json"),
            ("tor-exits", "tor_exits.txt"),
            ("spamhaus-drop-v4", "drop_v4.json"),
            ("dshield-block", "dshield_block.txt"),
            ("abusech-urlhaus-hosts", "urlhaus_hosts.txt"),
            ("certpl-domains", "certpl_domains.txt"),
            ("hagezi-tif-mini", "hagezi_tif_mini.txt"),
            ("phishing-database-active", "phishing_db.txt"),
            ("hagezi-doh", "hagezi_doh.txt"),
        ];
        for (id, file) in pairs {
            let fdir = feed_dir(dir.path(), id);
            std::fs::create_dir_all(&fdir).unwrap();
            std::fs::copy(fx.join(file), fdir.join(DATA_FILE)).unwrap();
            FeedMeta {
                feed_id: id.into(),
                fetched_at: Some(chrono::Utc::now()),
                checked_at: Some(chrono::Utc::now()),
                status: "ok".into(),
                entries: 1,
                ..Default::default()
            }
            .save(dir.path())
            .unwrap();
        }
        dir
    }

    fn conn(remote: &str, port: u16, dir: Direction) -> Connection {
        Connection {
            proto: "tcp".into(),
            local_ip: "192.168.1.10".parse().unwrap(),
            local_port: if dir == Direction::Inbound { 22 } else { 51000 },
            remote_ip: Some(remote.parse().unwrap()),
            remote_port: Some(port),
            state: "ESTABLISHED".into(),
            direction: dir,
            process: Some(ProcessRef {
                pid: 7,
                name: "app.exe".into(),
                exe: Some("C:/app.exe".into()),
                ..Default::default()
            }),
            geo: None,
            verdict: Verdict::default(),
            bytes_in: None,
            bytes_out: None,
            domain: None,
        }
    }

    #[test]
    fn loads_fixture_feeds_and_matches_with_sources() {
        let dir = fixture_config_dir();
        let reg = Registry::load(dir.path()).unwrap();
        let db = IntelDb::load(dir.path(), &reg);
        assert_eq!(db.feeds.len(), 9);
        assert_eq!(db.doh.len(), 1);
        assert!(db.missing.contains(&"cins-army".to_string()));

        // 185.199.108.9 同時在 Feodo（/32）與 DShield（/24）。
        let hits = db.match_ip("185.199.108.9".parse().unwrap(), Some(443));
        let ids: Vec<&str> = hits.iter().map(|h| h.feed_id.as_str()).collect();
        assert!(ids.contains(&"abusech-feodo") && ids.contains(&"dshield-block"));
        assert_eq!(hits[0].feed_id, "abusech-feodo");
        assert_eq!(hits[0].license, "CC0 1.0");
        assert!(hits[0].source_url.starts_with("https://feodotracker.abuse.ch/"));
        let ds = hits.iter().find(|h| h.feed_id == "dshield-block").unwrap();
        assert_eq!(ds.extra["commercial_ok"], false);

        // ThreatFox ip:port：port 相符 75，不符降 25。
        let tf = db.match_ip("185.199.108.12".parse().unwrap(), Some(443));
        assert_eq!(
            tf.iter()
                .find(|h| h.feed_id == "abusech-threatfox-ipport")
                .unwrap()
                .confidence,
            75
        );
        let tf = db.match_ip("185.199.108.12".parse().unwrap(), Some(80));
        assert_eq!(
            tf.iter()
                .find(|h| h.feed_id == "abusech-threatfox-ipport")
                .unwrap()
                .confidence,
            50
        );

        // Spamhaus CIDR、URLhaus 網域。
        assert!(db
            .match_ip("1.10.20.30".parse().unwrap(), None)
            .iter()
            .any(|h| h.feed_id == "spamhaus-drop-v4"));
        assert_eq!(
            db.match_domain("x.evil.example.test")[0].feed_id,
            "abusech-urlhaus-hosts"
        );
        assert!(db.match_ip("8.8.8.8".parse().unwrap(), Some(53)).is_empty());
    }

    #[test]
    fn domain_feeds_subdomain_semantics_doh_and_score() {
        let dir = fixture_config_dir();
        let reg = Registry::load(dir.path()).unwrap();
        let db = IntelDb::load(dir.path(), &reg);

        // CERT.PL＋Phishing.Database 都列了 phish-bank：兩個來源。
        let hits = db.match_domain("phish-bank.example.test");
        let ids: Vec<&str> = hits.iter().map(|h| h.feed_id.as_str()).collect();
        assert_eq!(ids, vec!["certpl-domains", "phishing-database-active"]);
        assert_eq!(hits[0].matched, "phish-bank.example.test");
        assert_eq!(domain_score(&hits, false), 95);

        // CERT.PL 涵蓋子網域；Phishing.Database 只比完全相同。
        let ids: Vec<String> = db
            .match_domain("www.phish-bank.example.test")
            .into_iter()
            .map(|h| h.feed_id)
            .collect();
        assert_eq!(ids, vec!["certpl-domains"]);
        assert!(db.match_domain("x.exact-only.example.test").is_empty());
        assert_eq!(db.match_domain("exact-only.example.test")[0].confidence, 60);

        // 萬用字元清單（*.evil… 與 c2…）
        let h = db.match_domain("a.b.c2.example.test");
        assert_eq!(h[0].feed_id, "hagezi-tif-mini");
        assert_eq!(h[0].matched, "c2.example.test");
        assert_eq!(
            db.match_domain("x.malware.example.test")[0].matched,
            "malware.example.test"
        );

        // DoH 端點不算威脅
        assert!(db.match_domain("dns.google").is_empty());
        assert_eq!(db.doh_endpoint("dns.google").unwrap().0, "hagezi-doh");
        assert!(db.doh_endpoint("example.test").is_none());
    }

    #[test]
    fn domain_score_rules() {
        let mk = |feed: &str, c: u8| IntelHit {
            feed_id: feed.into(),
            name: feed.into(),
            vendor: "v".into(),
            confidence: c,
            license: "l".into(),
            license_url: "u".into(),
            attribution_required: false,
            fetched_at: chrono::Utc::now(),
            source_url: "https://x".into(),
            matched: "m".into(),
            extra: json!({}),
        };
        assert_eq!(domain_score(&[], false), 0);
        assert_eq!(domain_score(&[mk("a", 60)], false), 60);
        assert_eq!(domain_score(&[mk("a", 60), mk("b", 40)], false), 70);
        assert_eq!(domain_score(&[mk("a", 60), mk("a", 50)], false), 60);
        // 熱門網域只壓低信心 < 70 的命中
        assert_eq!(domain_score(&[mk("a", 60)], true), 30);
        assert_eq!(domain_score(&[mk("a", 85)], true), 85);
        assert_eq!(domain_score(&[mk("a", 95), mk("b", 90), mk("c", 80)], false), 100);
    }

    #[test]
    fn enrich_sets_verdicts_and_findings() {
        let dir = fixture_config_dir();
        let reg = Registry::load(dir.path()).unwrap();
        let db = IntelDb::load(dir.path(), &reg);
        let mut conns = vec![
            conn("185.199.108.9", 443, Direction::Outbound),
            conn("151.80.1.17", 9001, Direction::Outbound),
            conn("45.33.32.156", 51515, Direction::Inbound),
            conn("8.8.8.8", 53, Direction::Outbound),
        ];
        let f = enrich_connections(&db, &mut conns);
        assert_eq!(conns[0].verdict.level, VerdictLevel::Dangerous);
        assert_eq!(conns[1].verdict.level, VerdictLevel::Suspicious); // Tor 只是低信心
        assert_eq!(conns[2].verdict.level, VerdictLevel::Dangerous);
        assert_eq!(conns[3].verdict.level, VerdictLevel::Unknown);
        assert_eq!(f.len(), 3);
        let out = f.iter().find(|x| x.rule == "intel.outbound_match").unwrap();
        assert_eq!(out.severity, Severity::Critical);
        assert!(!out.intel_hits.is_empty() && !out.refs.is_empty());
        assert!(f.iter().any(|x| x.rule == "intel.inbound_match"));
        let tor = f.iter().find(|x| x.evidence_key_contains("151.80.1.17")).unwrap();
        assert_eq!(tor.severity, Severity::Low);
    }

    #[test]
    fn reputation_upgrades_unknown() {
        let mut conns = vec![conn("93.184.216.34", 443, Direction::Outbound)];
        let reps = vec![Reputation {
            provider: "abuseipdb".into(),
            score: 90,
            detail: String::new(),
        }];
        let f = apply_reputation(&mut conns, "93.184.216.34".parse().unwrap(), &reps);
        assert_eq!(conns[0].verdict.level, VerdictLevel::Dangerous);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "intel.reputation");
    }

    impl Finding {
        fn evidence_key_contains(&self, s: &str) -> bool {
            matches!(&self.evidence, Evidence::Connection(c) if c.remote_display().contains(s))
        }
    }
}
