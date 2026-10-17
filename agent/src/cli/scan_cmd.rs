//! `ai-security-monitor scan`：組 Pipeline（各引擎在後續輪次掛入）、執行、輸出。

use std::sync::Arc;

use super::args::ScanArgs;
use super::render::{print_json, print_report};
use super::Env;
use crate::config;
use crate::error::{AppError, AppResult};
use crate::model::allowlist::Allowlist;
use crate::model::baseline::{Baseline, Snapshot};
use crate::model::finding::ScannerId;
use crate::model::report::{AgentInfo, Report};
use crate::scan::{Pipeline, ScanCtx};

/// 建立含所有本版本可用引擎的 Pipeline（各輪次在此掛入）。
pub fn build_pipeline() -> Pipeline {
    Pipeline::new()
        .register(Box::new(crate::connections::ConnectionsScanner))
        .register(Box::new(crate::intel::IntelScanner))
        .register(Box::new(crate::firewall::FirewallScanner))
        .register(Box::new(crate::ports::PortsScanner))
        .register(Box::new(crate::events::EventsScanner))
        .register(Box::new(crate::vuln::VulnScanner))
        .register(Box::new(crate::hardening::HardeningScanner))
        .register(Box::new(crate::fim::FimScanner))
}

/// 解析要跑的掃描器：參數 ＞ config.scan.scanners ＞ 全部可用。
fn select(pipeline: &Pipeline, args: &[ScannerId], cfg: &config::AgentConfig) -> AppResult<Vec<ScannerId>> {
    if !args.is_empty() {
        return Ok(args.to_vec());
    }
    if !cfg.scan.scanners.is_empty() {
        let mut v = Vec::new();
        for s in &cfg.scan.scanners {
            v.push(ScannerId::parse(s).ok_or_else(|| AppError::Config(tf!("設定裡有未知的掃描器：{id}", id = s)))?);
        }
        return Ok(v);
    }
    Ok(pipeline.available())
}

pub async fn run_scan(env: &Env, scanners: &[ScannerId], no_online: bool) -> AppResult<(Report, Snapshot)> {
    let (report, snapshot, _) = run_scan_full(env, scanners, no_online).await?;
    Ok((report, snapshot))
}

/// 同 run_scan，另外交回掃描後的 listener（含 ports 引擎算出的可達性），給 MCP 用。
pub async fn run_scan_full(
    env: &Env,
    scanners: &[ScannerId],
    no_online: bool,
) -> AppResult<(Report, Snapshot, Vec<crate::model::connection::Listener>)> {
    let mut cfg = config::load_or_init(&env.config_dir)?;
    if no_online {
        cfg.scan.online = false;
    }
    let pipeline = build_pipeline();
    let selected = select(&pipeline, scanners, &cfg)?;
    let allowlist = Allowlist::load(&env.config_dir)?;
    let baseline = Baseline::load(&env.config_dir)?;
    let quiet = env.global.quiet || env.global.json;
    let ctx =
        ScanCtx::new(Arc::new(cfg.clone()), env.config_dir.clone(), allowlist, baseline).with_progress(move |m| {
            if !quiet {
                eprintln!("  · {m}");
            }
        });
    let mut agent = AgentInfo::current(&cfg.agent_id);
    crate::sysmeta::enrich(&mut agent);
    agent.scanners_available = pipeline.available();
    let report = pipeline.run(&selected, &ctx, agent).await?;
    let shared = ctx.shared.lock().await;
    let snapshot = Snapshot::from_parts(&shared.listeners, &shared.connections, &report.findings);
    Ok((report, snapshot, shared.listeners.clone()))
}

/// 給 baseline 子命令用：跑全部可用掃描器（不線上查詢，求快）。
pub async fn scan_for_baseline(env: &Env) -> AppResult<(Report, Snapshot)> {
    run_scan(env, &[], true).await
}

pub async fn run(env: &Env, args: ScanArgs) -> AppResult<()> {
    let (report, snapshot) = run_scan(env, &args.scanners, args.no_online).await?;
    if let Some(out) = &args.out {
        let bytes = serde_json::to_vec_pretty(&report)?;
        crate::store::write_bytes_atomic(out, &bytes)?;
        if !env.global.quiet {
            eprintln!("{}", tf!("報告已寫入 {path}", path = out.display()));
        }
    }
    if args.baseline {
        let mut base =
            Baseline::load(&env.config_dir)?.unwrap_or_else(|| Baseline::from_snapshot(&Snapshot::default()));
        base.merge(&snapshot);
        base.save(&env.config_dir)?;
        if !env.global.quiet {
            eprintln!("{}", t!("基準線已更新"));
        }
    }
    if env.global.json || args.json_out {
        print_json(&report);
    } else {
        print_report(&report);
    }
    Ok(())
}
