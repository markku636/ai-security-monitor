//! DNS 防禦：即時蒐集這台電腦查了哪些網域（哪個程式查的）、每分鐘聚合後落地，
//! 連線表補上網域名稱；網域推測型判斷（DGA、熱門網域、可註冊網域）在 [`heuristics`]。

pub mod agg;
pub mod blocklist;
pub mod collect;
pub mod heuristics;
pub mod model;
pub mod procname;
pub mod queue;
pub mod rules;
pub mod runtime;
pub mod scanner;
pub mod store;
pub mod tamper;
pub mod usehub;

use std::path::Path;

use chrono::Utc;

use crate::model::connection::Connection;
use agg::IpDomainMap;

/// 用背景蒐集的「IP → 網域」對照替連線補上網域名稱（沒有在跑時什麼都不做）。
pub fn annotate_domains(conns: &mut [Connection]) {
    let Some(map) = runtime::ip_map() else {
        return;
    };
    let Ok(m) = map.read() else {
        return;
    };
    fill(conns, &m);
}

/// 沒有背景蒐集的行程（命令列 `connections`）：從最近一小時的紀錄建對照再補。
pub fn annotate_domains_from_store(config_dir: &Path, conns: &mut [Connection]) {
    let since = Utc::now() - chrono::Duration::hours(1);
    let recs = store::read_since(config_dir, since, 50_000);
    if recs.is_empty() {
        return;
    }
    let mut m = IpDomainMap::default();
    for r in &recs {
        for ip in &r.answers {
            m.insert(*ip, &r.name, None);
        }
    }
    fill(conns, &m);
}

fn fill(conns: &mut [Connection], m: &IpDomainMap) {
    for c in conns.iter_mut() {
        if c.domain.is_some() {
            continue;
        }
        if let Some(ip) = c.remote_ip {
            if let Some(d) = m.get(&ip) {
                c.domain = Some(d.to_string());
            }
        }
    }
}
