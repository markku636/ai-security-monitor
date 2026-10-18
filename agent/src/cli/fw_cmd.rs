//! `ai-security-monitor fw`：防火牆狀態、稽核、規則清單，以及寫入動作（封鎖 / 解封 / 關 port / 啟用 / 同步情資 / 重套）。
//! 寫入一律：`--dry-run` 預覽 → `--yes` 確認 → 未提權就以管理員身分重跑自己（子行程寫結果檔回報）。

use std::net::IpAddr;

use ipnet::IpNet;

use super::args::{FwCmd, ScanArgs};
use super::guard::ensure_confirmed;
use super::render::{print_json, table};
use super::Env;
use crate::actions;
use crate::connections::KnownGood;
use crate::elevate::{self, ElevatedResult};
use crate::error::{AppError, AppResult};
use crate::firewall::desired::DesiredState;
use crate::firewall::plan::{self, FwAction};
use crate::firewall::select::{self, SelectOpts};
use crate::firewall::{read_current, FwSnapshot};
use crate::intel::registry::Registry;
use crate::intel::IntelDb;
use crate::model::allowlist::Allowlist;
use crate::model::finding::ScannerId;
use crate::util::cmd::RealRunner;
use crate::util::net::{classify, IpClass};
use crate::util::text::clip;

fn on_off(v: Option<bool>) -> String {
    match v {
        Some(true) => t!("啟用").into(),
        Some(false) => t!("關閉").into(),
        None => t!("未知").into(),
    }
}

pub fn print_status(fw: &FwSnapshot) {
    println!(
        "{}",
        tf!(
            "後端：{backend} · 狀態：{state} · 預設連入：{din} · 允許連入規則：{n} · ai-security-monitor 規則：{ours}",
            backend = fw.backend,
            state = on_off(fw.enabled),
            din = fw.default_inbound.clone().unwrap_or_else(|| "-".into()),
            n = fw.inbound_allow.len(),
            ours = fw.ours_rules
        )
    );
    if !fw.profiles.is_empty() {
        let rows = fw
            .profiles
            .iter()
            .map(|p| {
                vec![
                    if p.active { "●".into() } else { "".into() },
                    p.name.clone(),
                    on_off(Some(p.enabled)),
                    p.default_inbound.clone(),
                    p.default_outbound.clone(),
                ]
            })
            .collect();
        println!(
            "{}",
            table(
                &[
                    t!("作用中"),
                    t!("防火牆設定檔"),
                    t!("狀態"),
                    t!("預設連入"),
                    t!("預設連出")
                ],
                rows
            )
        );
    }
    for n in &fw.notes {
        println!("  · {n}");
    }
    if fw.needs_elevation {
        println!(
            "{}",
            t!("部分規則需要系統管理員權限才能讀取（sudo ai-security-monitor fw status）")
        );
    }
}

/// 本機介面位址（封鎖時避免把自己封掉）。
pub fn local_ips() -> Vec<IpAddr> {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let mut v: Vec<IpAddr> = Vec::new();
    for (_n, data) in &networks {
        for ipn in data.ip_networks() {
            if !v.contains(&ipn.addr) {
                v.push(ipn.addr);
            }
        }
    }
    v
}

/// 解析 IP / CIDR 目標並套用安全檢查。
pub fn parse_targets(targets: &[String], force: bool) -> AppResult<Vec<IpNet>> {
    if targets.is_empty() {
        return Err(AppError::InvalidArg(t!("至少要指定一個 IP 或 CIDR").into()));
    }
    let local = local_ips();
    let mut out = Vec::new();
    for t in targets {
        let net: IpNet = match t.trim().parse::<IpNet>() {
            Ok(n) => n.trunc(),
            Err(_) => t
                .trim()
                .parse::<IpAddr>()
                .map(IpNet::from)
                .map_err(|_| AppError::InvalidArg(tf!("不是合法的 IP 或 CIDR：{value}", value = t)))?,
        };
        match classify(net.network()) {
            IpClass::Loopback | IpClass::Unspecified | IpClass::Multicast => {
                return Err(AppError::InvalidArg(tf!(
                    "拒絕封鎖 {net}：loopback / 未指定 / 多播位址",
                    net = net
                )))
            }
            _ => {}
        }
        let wide = match net {
            IpNet::V4(n) => n.prefix_len() < 8,
            IpNet::V6(n) => n.prefix_len() < 16,
        };
        if wide {
            return Err(AppError::InvalidArg(tf!("拒絕封鎖 {net}：範圍太大", net = net)));
        }
        if !force && local.iter().any(|ip| net.contains(ip)) {
            return Err(AppError::InvalidArg(tf!(
                "{net} 包含本機介面位址，封鎖會切斷自己的連線；確定要做請加 --force",
                net = net
            )));
        }
        if !out.contains(&net) {
            out.push(net);
        }
    }
    Ok(out)
}

/// `tcp/6379`、`6379/udp`、`6379`（預設 tcp）。
pub fn parse_port_spec(s: &str) -> AppResult<(String, u16)> {
    let bad = || AppError::InvalidArg(tf!("port 格式錯誤：{spec}（例：tcp/6379）", spec = s));
    let (a, b) = s.split_once('/').unwrap_or(("tcp", s));
    let (proto, port) = if a.parse::<u16>().is_ok() { (b, a) } else { (a, b) };
    let proto = proto.trim().to_ascii_lowercase();
    if proto != "tcp" && proto != "udp" {
        return Err(bad());
    }
    let port: u16 = port.trim().parse().map_err(|_| bad())?;
    if port == 0 {
        return Err(bad());
    }
    Ok((proto, port))
}

fn ssh_listening(env: &Env) -> bool {
    crate::connections::snapshot::take_with(&env.config_dir, false)
        .map(|s| {
            s.listeners
                .iter()
                .any(|l| l.proto == "tcp" && l.port == 22 && l.exposed)
        })
        .unwrap_or(false)
}

fn report_lines(r: &actions::ApplyReport) -> Vec<String> {
    let mut lines = vec![tf!(
        "已套用：{action}（後端 {backend}）",
        action = r.action,
        backend = r.backend
    )];
    for s in &r.steps {
        lines.push(format!(
            "  {} {}{}",
            if s.ok { "✓" } else { "✗" },
            s.step,
            if s.output.is_empty() || s.ok {
                String::new()
            } else {
                format!(" — {}", s.output)
            }
        ));
    }
    for n in &r.notes {
        lines.push(format!("  · {n}"));
    }
    lines
}

/// 寫入動作的共同流程。
async fn write_action(env: &Env, action: FwAction, dry_run: bool, preface: Vec<String>) -> AppResult<()> {
    let backend = plan::write_backend();
    let ssh = matches!(action, FwAction::Enable { .. }) && ssh_listening(env);
    let p = actions::prepare(&env.config_dir, &action, backend, ssh)?;
    let desc = action.describe();
    if dry_run {
        if env.global.json {
            print_json(&serde_json::json!({ "dry_run": true, "action": action, "plan": p, "backend": backend }));
        } else {
            for l in &preface {
                println!("{l}");
            }
            println!(
                "{}",
                tf!(
                    "預演（未執行）：{action}；後端 {backend}",
                    action = desc,
                    backend = backend
                )
            );
            for s in p.display() {
                println!("  $ {s}");
            }
            for n in &p.notes {
                println!("  · {n}");
            }
        }
        return Ok(());
    }
    ensure_confirmed(env.global.yes, env.global.force, false, &desc)?;

    if !elevate::is_elevated() {
        if env.global.elevated {
            return Err(AppError::Elevation(t!("已嘗試提權但仍不是系統管理員").into()));
        }
        for l in &preface {
            if !env.global.json {
                println!("{l}");
            }
        }
        let r = elevate::rerun_elevated(&env.config_dir).await?;
        if env.global.json {
            print_json(&r.json);
        } else {
            for l in &r.lines {
                println!("{l}");
            }
        }
        if !r.ok {
            let msg = r
                .error
                .as_ref()
                .and_then(|e| e["message"].as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| t!("提權後的動作失敗").to_string());
            return Err(AppError::Firewall(msg));
        }
        return Ok(());
    }

    let res = actions::execute(&env.config_dir, &action, backend, "cli", &RealRunner, ssh).await;
    let out = match &res {
        Ok(r) => ElevatedResult {
            ok: true,
            lines: preface.iter().cloned().chain(report_lines(r)).collect(),
            json: serde_json::to_value(r).unwrap_or_default(),
            error: None,
        },
        Err(e) => ElevatedResult {
            ok: false,
            lines: preface.clone(),
            json: serde_json::json!({ "error": e }),
            error: serde_json::to_value(e).ok(),
        },
    };
    if let Some(rf) = &env.global.result_file {
        // 被提權重跑的子行程：結果寫檔交給父行程顯示。
        out.write(rf)?;
        return Ok(());
    }
    if env.global.json {
        print_json(&out.json);
    } else {
        for l in &out.lines {
            println!("{l}");
        }
    }
    res.map(|_| ())
}

pub async fn run(env: &Env, cmd: FwCmd) -> AppResult<()> {
    match cmd {
        FwCmd::Status => {
            let fw = read_current(&RealRunner, elevate::is_elevated()).await?;
            if env.global.json {
                print_json(&fw);
            } else {
                print_status(&fw);
            }
            Ok(())
        }
        FwCmd::Audit => {
            super::scan_cmd::run(
                env,
                ScanArgs {
                    scanners: vec![ScannerId::Firewall, ScannerId::Ports],
                    no_online: true,
                    ..Default::default()
                },
            )
            .await
        }
        FwCmd::List { all, ours } => {
            if ours {
                let d = DesiredState::load(&env.config_dir)?;
                if env.global.json {
                    print_json(&d);
                    return Ok(());
                }
                let rows = d
                    .blocked
                    .iter()
                    .map(|b| {
                        vec![
                            b.net.to_string(),
                            format!("{:?}", b.direction).to_lowercase(),
                            clip(&b.reason, 40),
                            b.added_at.clone(),
                        ]
                    })
                    .collect();
                println!("{}", table(&[t!("位址"), t!("方向"), t!("原因"), t!("加入時間")], rows));
                for c in &d.closed_ports {
                    println!("{}", tf!("已關閉：{proto} {port}", proto = c.proto, port = c.port));
                }
                println!(
                    "{}",
                    tf!(
                        "情資黑名單：{n} 個網段（來源：{feeds}；同步於 {at}）",
                        n = d.feed_nets,
                        feeds = d.feed_ids.join(", "),
                        at = d.feed_synced_at.clone().unwrap_or_else(|| "-".into())
                    )
                );
                return Ok(());
            }
            let fw = read_current(&RealRunner, elevate::is_elevated()).await?;
            let rules: Vec<_> = fw.inbound_allow.iter().filter(|r| all || r.owner.is_none()).collect();
            if env.global.json {
                print_json(&rules);
                return Ok(());
            }
            let rows = rules
                .iter()
                .map(|r| {
                    vec![
                        clip(&r.display, 44),
                        r.protocol.clone(),
                        clip(&r.ports.iter().map(|p| p.display()).collect::<Vec<_>>().join(","), 20),
                        clip(r.program.as_deref().unwrap_or("any"), 40),
                        r.profiles.join(","),
                        clip(&r.remote_address, 18),
                    ]
                })
                .collect();
            println!(
                "{}",
                table(
                    &[
                        t!("規則"),
                        t!("協定"),
                        "port",
                        t!("程式"),
                        t!("防火牆設定檔"),
                        t!("來源位址")
                    ],
                    rows
                )
            );
            println!(
                "{}",
                tf!(
                    "共 {n} 條允許連入規則（{total} 條含 UWP 應用程式規則；--all 全部列出）",
                    n = rules.len(),
                    total = fw.inbound_allow.len()
                )
            );
            Ok(())
        }
        FwCmd::Block {
            targets,
            direction,
            reason,
            dry_run,
        } => {
            let nets = parse_targets(&targets, env.global.force)?;
            write_action(
                env,
                FwAction::Block {
                    nets,
                    direction,
                    reason: plan::sanitize(&reason),
                },
                dry_run,
                Vec::new(),
            )
            .await
        }
        FwCmd::Unblock {
            targets,
            all_asa,
            dry_run,
        } => {
            let action = if all_asa {
                FwAction::UnblockAll
            } else {
                FwAction::Unblock {
                    nets: parse_targets(&targets, true)?,
                }
            };
            write_action(env, action, dry_run, Vec::new()).await
        }
        FwCmd::ClosePort { spec, dry_run } => {
            let (proto, port) = parse_port_spec(&spec)?;
            write_action(env, FwAction::ClosePort { proto, port }, dry_run, Vec::new()).await
        }
        FwCmd::OpenPort { spec, dry_run } => {
            let (proto, port) = parse_port_spec(&spec)?;
            write_action(env, FwAction::OpenPort { proto, port }, dry_run, Vec::new()).await
        }
        FwCmd::Enable { profile, dry_run } => {
            write_action(env, FwAction::Enable { profile }, dry_run, Vec::new()).await
        }
        FwCmd::Ensure { dry_run } => write_action(env, FwAction::Ensure, dry_run, Vec::new()).await,
        FwCmd::DnsLock {
            allow,
            block_doh,
            dry_run,
        } => {
            let current = crate::firewall::dnslock::current_upstreams().await;
            let nets: Vec<IpNet> = if allow.is_empty() {
                current.iter().map(|ip| IpNet::from(*ip)).collect()
            } else {
                allow
                    .iter()
                    .map(|t| {
                        let t = t.trim();
                        t.parse::<IpNet>()
                            .map(|n| n.trunc())
                            .or_else(|_| t.parse::<IpAddr>().map(IpNet::from))
                            .map_err(|_| AppError::InvalidArg(tf!("不是合法的 IP 或 CIDR：{value}", value = t)))
                    })
                    .collect::<AppResult<Vec<IpNet>>>()?
            };
            if nets.is_empty() {
                return Err(AppError::InvalidArg(
                    t!("找不到目前在用的 DNS 伺服器；請用 --allow 指定").into(),
                ));
            }
            let normalized = crate::firewall::dnslock::normalize_allow(&nets);
            let missing = crate::firewall::dnslock::uncovered(&current, &normalized);
            if !missing.is_empty() && !env.global.force {
                return Err(AppError::InvalidArg(tf!(
                    "目前在用的 DNS {list} 不在允許清單裡，鎖定後這台會查不到網域；確定要這樣就加 --force",
                    list = missing.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                )));
            }
            let preface = vec![tf!(
                "目前在用的 DNS：{list}",
                list = if current.is_empty() {
                    "—".to_string()
                } else {
                    current.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                }
            )];
            write_action(env, FwAction::DnsLock { allow: nets, block_doh }, dry_run, preface).await
        }
        FwCmd::DnsUnlock { dry_run } => write_action(env, FwAction::DnsUnlock, dry_run, Vec::new()).await,
        FwCmd::SyncBlocklist {
            feeds,
            min_confidence,
            max,
            dry_run,
        } => {
            let backend = plan::write_backend();
            let reg = Registry::load(&env.config_dir)?;
            let cfg = crate::config::load_or_init(&env.config_dir)?;
            let dir = env.config_dir.clone();
            let reg2 = reg.clone();
            let db = tokio::task::spawn_blocking(move || IntelDb::load(&dir, &reg2))
                .await
                .map_err(|e| AppError::Intel(e.to_string()))?;
            if db.feeds.is_empty() {
                return Err(AppError::Intel(
                    t!("尚未下載任何威脅情資；執行 ai-security-monitor intel update").into(),
                ));
            }
            let allowlist = Allowlist::load(&env.config_dir)?;
            let kg = KnownGood::load();
            let local = local_ips();
            let (nets, st) = select::select(
                &db,
                &SelectOpts {
                    feeds: &feeds,
                    min_confidence,
                    allow_noncommercial: cfg.intel.noncommercial(),
                    max_entries: max.unwrap_or_else(|| select::max_entries_for(backend)),
                    local_ips: &local,
                    allowlist: &allowlist,
                    known_good: &kg,
                },
            );
            let mut preface = vec![tf!(
                "選出 {n} 個網段（合併前 {before}）；略過：保留／私網 {reserved}、過寬 {wide}、本機／白名單／已知良性 {local}、信心不足 {low}",
                n = st.after_merge,
                before = st.before_merge,
                reserved = st.skipped_reserved,
                wide = st.skipped_too_wide,
                local = st.skipped_local_or_allowlisted,
                low = st.skipped_low_confidence
            )];
            for (id, n) in &st.per_feed {
                preface.push(format!("  · {id}: {n}"));
            }
            if !st.skipped_feeds_noncommercial.is_empty() {
                preface.push(tf!(
                    "  · 非商用授權來源不用於封鎖：{ids}（非商業用途可執行 config set intel.usage noncommercial）",
                    ids = st.skipped_feeds_noncommercial.join(", ")
                ));
            }
            if st.truncated {
                preface.push(tf!("  · 超過後端上限，只同步前 {n} 個", n = st.after_merge));
            }
            let feed_ids: Vec<String> = st
                .per_feed
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(k, _)| k.clone())
                .collect();
            write_action(env, FwAction::SyncFeeds { nets, feed_ids }, dry_run, preface).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs() {
        assert_eq!(parse_port_spec("tcp/6379").unwrap(), ("tcp".into(), 6379));
        assert_eq!(parse_port_spec("6379/udp").unwrap(), ("udp".into(), 6379));
        assert_eq!(parse_port_spec("445").unwrap(), ("tcp".into(), 445));
        assert!(parse_port_spec("icmp/1").is_err());
        assert!(parse_port_spec("tcp/0").is_err());
    }

    #[test]
    fn target_guards() {
        assert_eq!(
            parse_targets(&["198.51.100.7".into()], false).unwrap()[0].to_string(),
            "198.51.100.7/32"
        );
        assert_eq!(
            parse_targets(&["198.51.100.9/24".into()], false).unwrap()[0].to_string(),
            "198.51.100.0/24"
        );
        assert!(parse_targets(&["127.0.0.1".into()], true).is_err());
        assert!(parse_targets(&["0.0.0.0/0".into()], true).is_err());
        assert!(parse_targets(&["10.0.0.0/4".into()], true).is_err());
        assert!(parse_targets(&["nope".into()], true).is_err());
        assert!(parse_targets(&[], true).is_err());
    }
}
