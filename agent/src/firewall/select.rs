//! 從已下載的情資挑出「可以安全封鎖」的網段：只取公網、夠窄、非本機 / 已知良性 / 白名單、
//! 授權允許（非商用來源預設排除）、信心達門檻、排除 Tor（資訊性），最後合併重疊網段並設上限。

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;

use crate::connections::KnownGood;
use crate::intel::registry::FeedKind;
use crate::intel::{IntelDb, TOR_FEED};
use crate::model::allowlist::Allowlist;
use crate::util::net::classify;

/// v4 至少 /10、v6 至少 /19，避免一條規則封掉半個網際網路。
pub const MIN_PREFIX_V4: u8 = 10;
pub const MIN_PREFIX_V6: u8 = 19;

pub struct SelectOpts<'a> {
    pub feeds: &'a [String],
    pub min_confidence: u8,
    pub allow_noncommercial: bool,
    pub max_entries: usize,
    pub local_ips: &'a [IpAddr],
    pub allowlist: &'a Allowlist,
    pub known_good: &'a KnownGood,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SelectStats {
    pub per_feed: BTreeMap<String, usize>,
    pub skipped_reserved: usize,
    pub skipped_too_wide: usize,
    pub skipped_local_or_allowlisted: usize,
    pub skipped_low_confidence: usize,
    pub skipped_feeds_noncommercial: Vec<String>,
    pub skipped_feeds_informational: Vec<String>,
    pub before_merge: usize,
    pub after_merge: usize,
    pub truncated: bool,
}

/// 網段兩端都是公網位址。
fn is_public_net(n: &IpNet) -> bool {
    classify(n.network()).is_public() && classify(n.broadcast()).is_public()
}

fn too_wide(n: &IpNet) -> bool {
    match n {
        IpNet::V4(x) => x.prefix_len() < MIN_PREFIX_V4,
        IpNet::V6(x) => x.prefix_len() < MIN_PREFIX_V6,
    }
}

pub fn select(db: &IntelDb, o: &SelectOpts) -> (Vec<IpNet>, SelectStats) {
    let mut st = SelectStats::default();
    let mut picked: Vec<(u8, IpNet)> = Vec::new();
    for lf in &db.feeds {
        let e = &lf.entry;
        if !o.feeds.is_empty() && !o.feeds.contains(&e.id) {
            continue;
        }
        if !matches!(e.kind, FeedKind::Ip | FeedKind::Cidr) {
            continue;
        }
        if e.id == TOR_FEED {
            st.skipped_feeds_informational.push(e.id.clone());
            continue;
        }
        if !e.license.commercial_ok && !o.allow_noncommercial {
            st.skipped_feeds_noncommercial.push(e.id.clone());
            continue;
        }
        let mut n_feed = 0usize;
        for (net, conf) in lf.set.networks_with_conf() {
            let conf = conf.unwrap_or(e.confidence);
            if conf < o.min_confidence {
                st.skipped_low_confidence += 1;
                continue;
            }
            if !is_public_net(&net) {
                st.skipped_reserved += 1;
                continue;
            }
            if too_wide(&net) {
                st.skipped_too_wide += 1;
                continue;
            }
            if o.local_ips.iter().any(|ip| net.contains(ip))
                || o.allowlist.overlaps_net(&net).is_some()
                || o.known_good.overlaps_net(&net).is_some()
            {
                st.skipped_local_or_allowlisted += 1;
                continue;
            }
            picked.push((conf, net));
            n_feed += 1;
        }
        st.per_feed.insert(e.id.clone(), n_feed);
    }
    st.before_merge = picked.len();
    // 超過上限時先保留高信心來源（Spamhaus 95、Feodo 90…），再合併。
    picked.sort_by_key(|(c, _)| std::cmp::Reverse(*c));
    let mut seen = std::collections::HashSet::new();
    picked.retain(|(_, n)| seen.insert(*n));
    if picked.len() > o.max_entries {
        picked.truncate(o.max_entries);
        st.truncated = true;
    }
    let picked: Vec<IpNet> = picked.into_iter().map(|(_, n)| n).collect();
    let mut merged = IpNet::aggregate(&picked);
    // 合併後若某網段把本機或已知良性位址含進去（例如兩個相鄰 /25 合成 /24），整段放棄。
    merged.retain(|n| {
        !o.local_ips.iter().any(|ip| n.contains(ip))
            && !too_wide(n)
            && o.known_good.overlaps_net(n).is_none()
            && o.allowlist.overlaps_net(n).is_none()
    });
    if merged.len() > o.max_entries {
        merged.truncate(o.max_entries);
        st.truncated = true;
    }
    st.after_merge = merged.len();
    (merged, st)
}

/// 各後端可承受的條目數。
pub fn max_entries_for(backend: &str) -> usize {
    match backend {
        "windows" => 10_000,
        "nft" | "pf" => 200_000,
        "ipset" => 250_000,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::fetch::{feed_dir, FeedMeta, DATA_FILE};
    use crate::intel::registry::Registry;

    fn db_with(id: &str, body: &str) -> (tempfile::TempDir, IntelDb) {
        let dir = tempfile::tempdir().unwrap();
        let fdir = feed_dir(dir.path(), id);
        std::fs::create_dir_all(&fdir).unwrap();
        std::fs::write(fdir.join(DATA_FILE), body).unwrap();
        FeedMeta {
            feed_id: id.into(),
            fetched_at: Some(chrono::Utc::now()),
            status: "ok".into(),
            ..Default::default()
        }
        .save(dir.path())
        .unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        let db = IntelDb::load(dir.path(), &reg);
        (dir, db)
    }

    fn opts<'a>(local: &'a [IpAddr], al: &'a Allowlist, kg: &'a KnownGood) -> SelectOpts<'a> {
        SelectOpts {
            feeds: &[],
            min_confidence: 80,
            allow_noncommercial: false,
            max_entries: 1000,
            local_ips: local,
            allowlist: al,
            known_good: kg,
        }
    }

    #[test]
    fn firehol_bogons_and_wide_ranges_are_never_blocked() {
        let (_d, db) = db_with(
            "firehol-level1",
            "0.0.0.0/8\n10.0.0.0/8\n127.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n224.0.0.0/3\n5.0.0.0/8\n45.0.0.0/16\n45.1.0.0/16\n8.8.8.0/24\n93.184.216.34\n",
        );
        let al = Allowlist::default();
        let kg = KnownGood::load();
        let local: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        let (nets, st) = select(&db, &opts(&local, &al, &kg));
        let s: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
        assert_eq!(s, vec!["45.0.0.0/15"]);
        assert_eq!(st.skipped_reserved, 6);
        assert_eq!(st.skipped_too_wide, 1);
        assert_eq!(st.skipped_local_or_allowlisted, 2); // 8.8.8.0/24（known-good）＋本機 IP
        assert_eq!(st.before_merge, 2);
    }

    #[test]
    fn noncommercial_tor_and_low_confidence_are_excluded() {
        let (_d, db) = db_with("dshield-block", "45.33.0.0\t45.33.255.255\t16\t9\tx\tUS\te\n");
        let al = Allowlist::default();
        let kg = KnownGood::load();
        let (nets, st) = select(&db, &opts(&[], &al, &kg));
        assert!(nets.is_empty());
        assert_eq!(st.skipped_feeds_noncommercial, vec!["dshield-block".to_string()]);

        let (_d2, db2) = db_with("tor-exits", "45.33.32.156\n");
        let (n2, st2) = select(&db2, &opts(&[], &al, &kg));
        assert!(n2.is_empty() && st2.skipped_feeds_informational.len() == 1);

        let (_d3, db3) = db_with("cins-army", "45.33.32.156\n");
        let (n3, st3) = select(&db3, &opts(&[], &al, &kg));
        assert!(n3.is_empty() && st3.skipped_low_confidence == 1); // CINS 信心 70 < 80
    }
}
