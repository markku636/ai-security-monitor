//! `asa ports`：列出本機 listener 與可達性；`--probe HOST` 做受限的 TCP 探測。

use std::time::Duration;

use super::args::PortsArgs;
use super::render::{print_json, table};
use super::Env;
use crate::connections::RiskyTable;
use crate::error::{AppError, AppResult};
use crate::firewall::read_current;
use crate::ports::{assess, probe};
use crate::util::cmd::{CmdRunner, RealRunner};

pub async fn run(env: &Env, a: PortsArgs) -> AppResult<()> {
    if let Some(host) = &a.probe {
        return run_probe(env, host, &a).await;
    }
    let dir = env.config_dir.clone();
    let snap = tokio::task::spawn_blocking(move || crate::connections::snapshot::take_with(&dir, false))
        .await
        .map_err(|e| AppError::Scan(e.to_string()))??;
    let fw = read_current(&RealRunner, crate::elevate::is_elevated()).await.ok();
    let risky = RiskyTable::load();
    let mut listeners = snap.listeners;
    let (_findings, sum) = assess(&mut listeners, fw.as_ref(), &risky);
    listeners.sort_by_key(|l| (l.port, l.proto.clone()));
    if env.global.json {
        print_json(
            &serde_json::json!({ "summary": sum, "listeners": listeners, "firewall": fw.as_ref().map(|f| &f.backend) }),
        );
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    let rows = listeners
        .iter()
        .filter(|l| a.all || l.exposed)
        // 同一 port 同時綁 0.0.0.0 與 :: 時只列一行。
        .filter(|l| {
            seen.insert((
                l.proto.clone(),
                l.port,
                l.bind_ip.is_unspecified(),
                l.process.as_ref().map(|p| p.pid),
            ))
        })
        .map(|l| {
            vec![
                l.proto.clone(),
                l.port.to_string(),
                if l.bind_ip.is_unspecified() {
                    "0.0.0.0/::".into()
                } else {
                    l.bind_ip.to_string()
                },
                l.process
                    .as_ref()
                    .map(|p| format!("{} ({})", p.name, p.pid))
                    .unwrap_or_else(|| "-".into()),
                l.reachability.as_ref().map(|r| r.label()).unwrap_or_default(),
                risky
                    .listening(&l.proto, l.port)
                    .map(|r| format!("{} [{}]", r.name, r.severity.as_str()))
                    .unwrap_or_default(),
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[t!("協定"), "port", t!("綁定"), t!("行程"), t!("可達性"), t!("風險")],
            rows
        )
    );
    println!(
        "{}",
        tf!(
            "對外監聽 {exposed} 個（可連入 {open}、已阻擋 {filtered}、未知 {unknown}）；共 {n} 個 listener（--all 含僅本機）",
            exposed = sum.exposed,
            open = sum.open,
            filtered = sum.filtered,
            unknown = sum.unknown,
            n = sum.listeners
        )
    );
    Ok(())
}

async fn run_probe(env: &Env, host: &str, a: &PortsArgs) -> AppResult<()> {
    let ip = probe::resolve(host).await?;
    probe::authorize_target(ip, a.allow_public)?;
    let ports = match &a.ports {
        Some(spec) => probe::parse_ports(spec)?,
        None => probe::TOP_PORTS.to_vec(),
    };
    let timeout =
        crate::util::time::parse_duration(&a.timeout)?.clamp(Duration::from_millis(100), Duration::from_secs(10));
    if !env.global.quiet && !env.global.json {
        eprintln!("{}", tf!("探測 {ip} 的 {n} 個 TCP port…", ip = ip, n = ports.len()));
    }
    let results = if a.nmap {
        let out = RealRunner.run(&probe::nmap_spec(ip, &ports)).await?;
        if !out.ok() {
            return Err(AppError::External(tf!(
                "nmap 失敗：{e}",
                e = out.stderr.lines().next().unwrap_or("")
            )));
        }
        probe::parse_nmap_xml(&out.stdout)
    } else {
        probe::tcp_scan(ip, &ports, timeout, 128).await
    };
    if env.global.json {
        print_json(&serde_json::json!({ "target": ip, "ports_scanned": ports.len(), "open": results }));
        return Ok(());
    }
    let risky = RiskyTable::load();
    let rows = results
        .iter()
        .map(|r| {
            vec![
                r.port.to_string(),
                r.proto.clone(),
                r.service.clone(),
                risky
                    .listening(&r.proto, r.port)
                    .map(|x| format!("{} [{}]", x.name, x.severity.as_str()))
                    .unwrap_or_default(),
            ]
        })
        .collect();
    println!("{}", table(&["port", t!("協定"), t!("服務"), t!("風險")], rows));
    println!(
        "{}",
        tf!(
            "{ip}：{open} 個開啟／已探測 {n} 個",
            ip = ip,
            open = results.len(),
            n = ports.len()
        )
    );
    Ok(())
}
