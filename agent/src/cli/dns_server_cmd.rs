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
    dnsd::run(cfg, env.config_dir.clone(), stop).await
}
