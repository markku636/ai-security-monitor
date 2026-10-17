//! `ai-security-monitor dns-server`：在這台跑防護 DNS（前景；Ctrl+C 或服務停止就結束）。
//! `--healthcheck` 檢查本機伺服器、`--status` 印出狀態檔。

use std::net::SocketAddr;
use std::sync::Arc;

use ipnet::IpNet;
use tokio::sync::Notify;

use super::args::DnsServerArgs;
use super::render::print_json;
use super::Env;
use crate::dnsd::{self, Config};
use crate::error::{AppError, AppResult};

fn parse_addrs(v: &[String]) -> AppResult<Vec<SocketAddr>> {
    v.iter()
        .map(|s| {
            let s = s.trim();
            s.parse::<SocketAddr>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                .map_err(|_| AppError::InvalidArg(tf!("不是合法的監聽位址：{value}", value = s)))
        })
        .collect()
}

fn parse_nets(v: &[String]) -> AppResult<Vec<IpNet>> {
    v.iter()
        .map(|s| {
            let s = s.trim();
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| AppError::InvalidArg(tf!("不是合法的 IP 或 CIDR：{value}", value = s)))
        })
        .collect()
}

pub async fn run(env: &Env, a: DnsServerArgs) -> AppResult<()> {
    let mut cfg = Config::default();
    if !a.listen.is_empty() {
        cfg.listen = parse_addrs(&a.listen)?;
    }
    if a.status {
        match dnsd::read_status(&env.config_dir) {
            Some(v) => print_json(&v),
            None => println!("{}", t!("這台還沒跑過防護 DNS")),
        }
        return Ok(());
    }
    if a.healthcheck {
        let addr = cfg
            .listen
            .first()
            .copied()
            .unwrap_or_else(|| "127.0.0.1:53".parse().expect("valid"));
        dnsd::healthcheck(addr).await?;
        println!("{}", t!("防護 DNS 正常"));
        return Ok(());
    }
    let link = hub_link(env, &a)?;
    cfg.upstreams = a.upstream;
    cfg.feeds = a.feeds;
    cfg.min_confidence = a.min_confidence;
    cfg.custom_block = a.block;
    cfg.custom_allow = a.allow;
    if !a.acl.is_empty() {
        cfg.acl = parse_nets(&a.acl)?;
    }
    cfg.rrl_qps = a.rate_limit;
    cfg.cache_entries = a.cache;
    cfg.blocking = !a.no_block;
    cfg.block_private_relay = a.block_private_relay;
    cfg.log = !a.no_log;
    cfg.internal_suffixes = a.internal_suffix;
    cfg.update_feeds = !a.no_feed_update;
    // 先確認上游設定合法，再開始監聽
    dnsd::upstream::Pool::new(&cfg.upstreams)?;
    if !env.global.json {
        println!(
            "{}",
            tf!(
                "防護 DNS 啟動：監聽 {listen}；上游 {up}；{block}（Ctrl+C 結束）",
                listen = cfg.listen.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "),
                up = if cfg.upstreams.is_empty() {
                    dnsd::upstream::DEFAULT_UPSTREAMS.join(", ")
                } else {
                    cfg.upstreams.join(", ")
                },
                block = if cfg.blocking {
                    t!("封鎖情資列名的網域")
                } else {
                    t!("不封鎖（只轉送）")
                }
            )
        );
    }
    if let (Some(l), false) = (&link, env.global.json) {
        println!(
            "{}",
            tf!(
                "連上 Hub：{url}（封鎖開關、上游與清單以 Hub 的設定為準）",
                url = l.client.base()
            )
        );
    }
    let stop = Arc::new(Notify::new());
    let s2 = stop.clone();
    tokio::spawn(async move {
        let svc = crate::service::instance::stopped();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = svc => {}
        }
        s2.notify_waiters();
    });
    dnsd::run(cfg, env.config_dir.clone(), stop, link).await
}

/// `--hub-agent`：這台電腦加入 Hub 的身分；`--hub URL --hub-token`：防護 DNS 權杖。都沒有＝不連 Hub。
fn hub_link(env: &Env, a: &DnsServerArgs) -> AppResult<Option<dnsd::hub::Link>> {
    if a.hub_agent {
        let c = crate::config::load(&env.config_dir)?;
        return match crate::hub::watch::client_from_config(&env.config_dir, &c)? {
            Some(client) => Ok(Some(dnsd::hub::Link::new(client, "agent"))),
            None => Err(AppError::InvalidArg(
                t!("這台電腦還沒加入 Hub（--hub-agent 要先 enroll）").into(),
            )),
        };
    }
    let Some(url) = a.hub.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    let token = a
        .hub_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::InvalidArg(t!("連 Hub 需要防護 DNS 權杖（--hub-token）").into()))?;
    let url = crate::hub::validate_url(url, a.insecure_http)?;
    Ok(Some(dnsd::hub::Link::new(
        crate::hub::HubClient::new(&url, token, "")?,
        "token",
    )))
}
