//! `ai-security-monitor intel`：更新、狀態、來源清單、查詢 IP／網域、啟停來源、設定線上名譽 API key。

use std::io::BufRead;
use std::net::IpAddr;

use chrono::Utc;
use serde_json::json;

use super::args::{IntelCmd, IntelKeyCmd};
use super::render::{print_json, table};
use super::Env;
use crate::connections::KnownGood;
use crate::dns::heuristics;
use crate::error::{AppError, AppResult};
use crate::intel::fetch::{self, FeedMeta, UpdateOpts};
use crate::intel::registry::Registry;
use crate::intel::{geo, lookup, IntelDb, TOR_FEED};
use crate::model::allowlist::Allowlist;
use crate::model::verdict::{AnomalyKind, Reason, Verdict};
use crate::secrets::SecretStore;
use crate::util::net::{classify, IpClass};
use crate::util::text::{clip, fmt_bytes};

fn age(t: Option<chrono::DateTime<Utc>>) -> String {
    match t {
        Some(t) => {
            let secs = (Utc::now() - t).num_seconds().max(0) as u64;
            crate::util::time::fmt_duration(std::time::Duration::from_secs(secs))
        }
        None => "-".into(),
    }
}

pub async fn run(env: &Env, cmd: IntelCmd) -> AppResult<()> {
    match cmd {
        IntelCmd::Update { feeds, force, no_hub } => update(env, feeds, force, no_hub).await,
        IntelCmd::Status => status(env),
        IntelCmd::Sources => sources(env),
        IntelCmd::Lookup { indicator, online } => lookup_cmd(env, &indicator, online).await,
        IntelCmd::Enable { id } => toggle(env, &id, true),
        IntelCmd::Disable { id } => toggle(env, &id, false),
        IntelCmd::Key { cmd } => key(env, cmd),
    }
}

/// 已註冊 hub 就拿它的鏡像清單；沒註冊、舊版 hub 或連不上就回 None（直接找廠商）。
async fn hub_mirror(env: &Env) -> Option<fetch::Mirror> {
    let cfg = crate::config::load_or_init(&env.config_dir).ok()?;
    let client = crate::hub::watch::client_from_config(&env.config_dir, &cfg).ok()??;
    match client.feed_mirror().await {
        Ok(m) => {
            if !env.global.quiet && !env.global.json {
                eprintln!(
                    "  · {}",
                    tf!("從 Hub 鏡像下載（{n} 個清單）：{url}", n = m.ids.len(), url = m.base)
                );
            }
            Some(m)
        }
        Err(e) => {
            if !env.global.quiet && !env.global.json {
                eprintln!("  ! {}", tf!("Hub 鏡像不可用，直接找廠商：{e}", e = e.message()));
            }
            None
        }
    }
}

async fn update(env: &Env, feeds: Vec<String>, force: bool, no_hub: bool) -> AppResult<()> {
    let reg = Registry::load(&env.config_dir)?;
    for w in &reg.warnings {
        eprintln!("  ! {w}");
    }
    let quiet = env.global.quiet || env.global.json;
    let progress = move |m: &str| {
        if !quiet {
            eprintln!("  · {m}");
        }
    };
    let mirror = if no_hub { None } else { hub_mirror(env).await };
    let outs = fetch::update(
        &env.config_dir,
        &reg,
        &UpdateOpts {
            only: feeds,
            force,
            mirror,
        },
        &progress,
    )
    .await?;
    if env.global.json {
        print_json(&outs);
        return Ok(());
    }
    let rows = outs
        .iter()
        .map(|o| {
            vec![
                o.feed_id.clone(),
                match o.status.as_str() {
                    "updated" => t!("已更新").to_string(),
                    "not_modified" => t!("未變更").to_string(),
                    "fresh" => t!("仍新鮮").to_string(),
                    _ => t!("失敗").to_string(),
                },
                o.entries.to_string(),
                fmt_bytes(o.bytes),
                format!("{} ms", o.ms),
                match o.source.as_deref() {
                    Some("hub") => "Hub".to_string(),
                    Some(_) => t!("廠商").to_string(),
                    None => "-".to_string(),
                },
                clip(&o.detail.clone().unwrap_or_default(), 60),
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[
                t!("來源"),
                t!("結果"),
                t!("筆數"),
                t!("大小"),
                t!("耗時"),
                t!("下載自"),
                t!("細節")
            ],
            rows
        )
    );
    let failed = outs.iter().filter(|o| o.status == "error").count();
    if failed > 0 {
        println!("{}", tf!("{n} 個來源更新失敗；舊資料仍保留可用", n = failed));
    }
    Ok(())
}

fn status(env: &Env) -> AppResult<()> {
    let reg = Registry::load(&env.config_dir)?;
    let mut items = Vec::new();
    for f in reg.feeds.iter().filter(|f| fetch::downloadable(f)) {
        let m = FeedMeta::load(&env.config_dir, &f.id);
        items.push(json!({
            "id": f.id,
            "name": f.name,
            "vendor": f.vendor,
            "kind": f.kind.as_str(),
            "enabled": reg.is_enabled(f),
            "license_blocked": reg.license_blocked(f),
            "entries": m.as_ref().map(|m| m.entries).unwrap_or(0),
            "bytes": m.as_ref().map(|m| m.bytes).unwrap_or(0),
            "fetched_at": m.as_ref().and_then(|m| m.fetched_at),
            "checked_at": m.as_ref().and_then(|m| m.checked_at),
            "status": m.as_ref().map(|m| m.status.clone()).unwrap_or_else(|| "never".into()),
            "error": m.as_ref().and_then(|m| m.error.clone()),
            "license": f.license.name,
            "commercial_ok": f.license.commercial_ok,
            "refresh_interval": f.refresh_interval,
        }));
    }
    if env.global.json {
        print_json(&items);
        return Ok(());
    }
    let rows = reg
        .feeds
        .iter()
        .filter(|f| fetch::downloadable(f))
        .map(|f| {
            let m = FeedMeta::load(&env.config_dir, &f.id);
            vec![
                if reg.is_enabled(f) {
                    "✓".into()
                } else if reg.license_blocked(f) {
                    t!("非商用").to_string()
                } else {
                    "–".into()
                },
                f.id.clone(),
                f.vendor.clone(),
                m.as_ref().map(|m| m.entries.to_string()).unwrap_or_else(|| "-".into()),
                age(m.as_ref().and_then(|m| m.fetched_at)),
                match m.as_ref().map(|m| m.status.as_str()) {
                    Some("ok") => "ok".into(),
                    Some("error") => format!(
                        "error: {}",
                        clip(m.as_ref().and_then(|m| m.error.as_deref()).unwrap_or(""), 40)
                    ),
                    _ => t!("未下載").to_string(),
                },
                if f.license.commercial_ok {
                    clip(&f.license.name, 28)
                } else {
                    format!("{} [NC]", clip(&f.license.name, 22))
                },
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[
                "",
                t!("來源"),
                t!("廠商"),
                t!("筆數"),
                t!("距今"),
                t!("狀態"),
                t!("授權")
            ],
            rows
        )
    );
    let (fresh, stale, missing) = fetch::freshness(&env.config_dir, &reg);
    println!(
        "{}",
        tf!(
            "已啟用：{fresh} 個最新、{stale} 個過期、{missing} 個未下載",
            fresh = fresh,
            stale = stale,
            missing = missing
        )
    );
    Ok(())
}

fn sources(env: &Env) -> AppResult<()> {
    let reg = Registry::load(&env.config_dir)?;
    if env.global.json {
        let v: Vec<serde_json::Value> = reg
            .feeds
            .iter()
            .map(|f| {
                let mut x = serde_json::to_value(f).unwrap_or_default();
                x["enabled"] = json!(reg.is_enabled(f));
                x
            })
            .collect();
        print_json(&v);
        return Ok(());
    }
    let rows = reg
        .feeds
        .iter()
        .map(|f| {
            vec![
                if reg.is_enabled(f) { "✓".into() } else { "–".into() },
                f.id.clone(),
                format!("{} · {}", f.vendor, f.name),
                f.kind.as_str().to_string(),
                format!(
                    "{}{}",
                    f.license.name,
                    if f.license.commercial_ok { "" } else { " [NC]" }
                ),
                f.source_url(),
            ]
        })
        .collect();
    println!(
        "{}",
        table(&["", "id", t!("來源"), t!("類型"), t!("授權"), t!("網址")], rows)
    );
    println!("{}", t!("[NC]＝非商用授權：預設只告警、不用於防火牆封鎖。"));
    Ok(())
}

/// 查一個 IP／網域的計算結果（CLI 與 MCP 共用）。
pub struct LookupOut {
    pub ind: String,
    pub class: String,
    pub verdict: Verdict,
    pub geo: Option<crate::model::connection::GeoInfo>,
    pub hits: Vec<crate::model::finding::IntelHit>,
    pub reps: Vec<lookup::Reputation>,
    pub warnings: Vec<String>,
    pub feeds_loaded: usize,
    /// 網域才有：可註冊網域、熱門、像不像 DGA、網域綜合分數。
    pub domain: Option<DomainInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainInfo {
    pub registrable: Option<String>,
    pub popular: bool,
    pub looks_generated: bool,
    pub score: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh_endpoint: Option<String>,
}

impl LookupOut {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "indicator": self.ind,
            "class": self.class,
            "verdict": self.verdict,
            "geo": self.geo,
            "hits": self.hits,
            "reputation": self.reps,
            "feeds_loaded": self.feeds_loaded,
            "domain": self.domain,
            "warnings": self.warnings,
            "attribution": if self.geo.is_some() { Some(geo::ATTRIBUTION) } else { None },
        })
    }
}

pub async fn compute_lookup(config_dir: &std::path::Path, indicator: &str, online: bool) -> AppResult<LookupOut> {
    let env_dir = config_dir.to_path_buf();
    let reg = Registry::load(&env_dir)?;
    let dir = env_dir.clone();
    let reg2 = reg.clone();
    let db = tokio::task::spawn_blocking(move || IntelDb::load(&dir, &reg2))
        .await
        .map_err(|e| AppError::Intel(e.to_string()))?;
    let kg = KnownGood::load();
    let allow = Allowlist::load(&env_dir)?;
    let ind = indicator.trim();

    let mut reasons: Vec<Reason> = Vec::new();
    let mut reps = Vec::new();
    let mut warnings = Vec::new();
    let (hits, class, geo_info) = if let Ok(ip) = ind.parse::<IpAddr>() {
        let class = classify(ip);
        match class {
            IpClass::Loopback => reasons.push(Reason::Loopback),
            IpClass::Private | IpClass::LinkLocal => reasons.push(Reason::PrivateNetwork),
            _ => {}
        }
        if let Some(e) = allow.match_ip(ip) {
            reasons.push(Reason::Allowlisted { entry_id: e.id.clone() });
        }
        if let Some(list) = kg.match_ip(ip) {
            reasons.push(Reason::KnownGood {
                list: list.into(),
                detail: ip.to_string(),
            });
        }
        let hits = db.match_ip(ip, None);
        if online && class.is_public() {
            let (r, w) = lookup::lookup_ip(&env_dir, &reg, ip).await;
            reps = r;
            warnings = w;
        }
        (hits, format!("{class:?}").to_lowercase(), db.geo.lookup(ip))
    } else {
        if let Some(e) = allow.match_domain(ind) {
            reasons.push(Reason::Allowlisted { entry_id: e.id.clone() });
        }
        if let Some(list) = kg.match_domain(ind) {
            reasons.push(Reason::KnownGood {
                list: list.into(),
                detail: ind.to_string(),
            });
        }
        (db.match_domain(ind), "domain".to_string(), None)
    };
    let domain = if class == "domain" {
        let name = ind.trim_end_matches('.').to_ascii_lowercase();
        let popular = heuristics::is_popular(&name);
        Some(DomainInfo {
            registrable: heuristics::registrable_domain(&name).map(str::to_string),
            popular,
            looks_generated: heuristics::looks_generated(&name),
            score: crate::intel::domain_score(&hits, popular),
            doh_endpoint: db.doh_endpoint(&name).map(|(id, _)| id),
        })
    } else {
        None
    };
    for h in &hits {
        if h.feed_id == TOR_FEED {
            reasons.push(Reason::Anomaly {
                kind: AnomalyKind::TorExit,
                detail: ind.to_string(),
            });
        }
        reasons.push(Reason::IntelHit(Box::new(h.clone())));
    }
    for r in &reps {
        reasons.push(Reason::Reputation {
            provider: r.provider.clone(),
            score: r.score,
            detail: r.detail.clone(),
        });
    }
    let verdict = Verdict::compute(reasons);
    Ok(LookupOut {
        ind: ind.to_string(),
        class,
        verdict,
        geo: geo_info,
        hits,
        reps,
        warnings,
        feeds_loaded: db.feeds.len(),
        domain,
    })
}

async fn lookup_cmd(env: &Env, indicator: &str, online: bool) -> AppResult<()> {
    let out = compute_lookup(&env.config_dir, indicator, online).await?;
    let LookupOut {
        ind,
        class,
        verdict,
        geo: geo_info,
        hits,
        reps,
        warnings,
        feeds_loaded,
        domain,
    } = &out;
    let ind = ind.as_str();

    if env.global.json {
        print_json(&out.to_json());
        return Ok(());
    }

    println!(
        "{}",
        tf!(
            "{ind}（{class}）判定：{verdict}",
            ind = ind,
            class = class,
            verdict = verdict.level.label()
        )
    );
    if let Some(g) = &geo_info {
        println!(
            "{}",
            tf!(
                "地理：{country} · AS{asn} {org}",
                country = g.country.clone().unwrap_or_else(|| "-".into()),
                asn = g.asn.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                org = g.org.clone().unwrap_or_default()
            )
        );
    }
    if let Some(d) = domain {
        let yes_no = |b: bool| if b { t!("是") } else { t!("否") };
        println!(
            "{}",
            tf!(
                "可註冊網域：{reg} · 熱門網域：{popular} · 像亂數產生（DGA）：{dga} · 網域分數：{score}",
                reg = d.registrable.clone().unwrap_or_else(|| "-".into()),
                popular = yes_no(d.popular),
                dga = yes_no(d.looks_generated),
                score = d.score
            )
        );
        if let Some(id) = &d.doh_endpoint {
            println!("{}", tf!("這是加密 DNS（DoH）端點（{id}），本身不是惡意", id = id));
        }
    }
    if hits.is_empty() {
        println!("{}", tf!("沒有命中任何已載入的情資（{n} 個來源）", n = feeds_loaded));
    } else {
        let rows = hits
            .iter()
            .map(|h| {
                vec![
                    format!("{} · {}", h.vendor, h.name),
                    h.matched.clone(),
                    format!("{}%", h.confidence),
                    h.license.clone(),
                    age(Some(h.fetched_at)),
                    h.source_url.clone(),
                ]
            })
            .collect();
        println!(
            "{}",
            table(
                &[
                    t!("來源"),
                    t!("命中"),
                    t!("信心"),
                    t!("授權"),
                    t!("資料距今"),
                    t!("網址")
                ],
                rows
            )
        );
    }
    for r in reps {
        println!(
            "{}",
            tf!(
                "線上名譽：{provider} = {score}（{detail}）",
                provider = r.provider,
                score = r.score,
                detail = r.detail
            )
        );
    }
    for r in &verdict.reasons {
        match r {
            Reason::KnownGood { list, .. } => println!("{}", tf!("已知良性清單：{list}", list = list)),
            Reason::Allowlisted { entry_id } => println!("{}", tf!("白名單條目：{id}", id = entry_id)),
            _ => {}
        }
    }
    for w in warnings {
        println!("  ! {w}");
    }
    if online
        && reps.is_empty()
        && Registry::load(&env.config_dir)
            .map(|reg| lookup::configured_providers(&env.config_dir, &reg).is_empty())
            .unwrap_or(true)
    {
        println!(
            "{}",
            t!("沒有設定任何線上名譽服務的 API key（ai-security-monitor intel key set abuseipdb -）")
        );
    }
    if *feeds_loaded == 0 {
        println!("{}", t!("尚未下載任何威脅情資；執行 ai-security-monitor intel update"));
    }
    if geo_info.is_some() {
        println!("{}", geo::ATTRIBUTION);
    }
    Ok(())
}

fn toggle(env: &Env, id: &str, on: bool) -> AppResult<()> {
    Registry::set_enabled(&env.config_dir, id, on)?;
    let reg = Registry::load(&env.config_dir)?;
    if on && reg.get(id).is_some_and(|f| !reg.license_ok(f)) {
        // 記住使用者的選擇，但要等使用情境改成非商用才會用
        return Err(AppError::InvalidArg(tf!(
            "{id} 只限非商業用途；個人／非商業使用請先執行 ai-security-monitor config set intel.usage noncommercial",
            id = id
        )));
    }
    if env.global.json {
        print_json(&json!({ "id": id, "enabled": on }));
    } else if on {
        println!(
            "{}",
            tf!("已啟用 {id}；執行 ai-security-monitor intel update 下載", id = id)
        );
    } else {
        println!("{}", tf!("已停用 {id}", id = id));
    }
    Ok(())
}

fn key(env: &Env, cmd: IntelKeyCmd) -> AppResult<()> {
    let store = SecretStore::open(&env.config_dir);
    match cmd {
        IntelKeyCmd::Set { id, value } => {
            if !lookup::PROVIDERS.iter().any(|p| p.id == id) {
                return Err(AppError::InvalidArg(tf!(
                    "不支援的名譽服務：{id}；可用：{ids}",
                    id = id,
                    ids = lookup::PROVIDERS.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
                )));
            }
            let v = if value == "-" {
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line)?;
                line.trim().to_string()
            } else {
                value
            };
            if v.is_empty() {
                return Err(AppError::InvalidArg(t!("API key 不可為空").into()));
            }
            store.set(&format!("intel.{id}"), &v)?;
            println!(
                "{}",
                tf!(
                    "已儲存 {id} 的 API key（{backend}）",
                    id = id,
                    backend = store.backend().name()
                )
            );
            println!(
                "{}",
                t!("要讓掃描自動查詢，執行 ai-security-monitor config set intel.online_lookups true")
            );
        }
        IntelKeyCmd::Delete { id } => {
            store.delete(&format!("intel.{id}"))?;
            println!("{}", tf!("已刪除 {id} 的 API key", id = id));
        }
    }
    Ok(())
}
