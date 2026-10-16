//! `asa enroll` / `unenroll` / `status` / `watch`：註冊到 Security Hub 與常駐回報。

use std::io::BufRead;
use std::time::Duration;

use chrono::Utc;

use super::args::{ScanArgs, WatchArgs};
use super::render::{print_json, table};
use super::Env;
use crate::config::{self, HubConfig};
use crate::error::{AppError, AppResult};
use crate::hub::contract::HeartbeatPayload;
use crate::hub::{actions as remote, outbox, validate_url, watch, HubClient};
use crate::model::report::AgentInfo;
use crate::secrets::{SecretStore, KEY_HUB_ACTION, KEY_HUB_CLIENT};

fn log(env: &Env, msg: &str) {
    let line = format!("[{}] {msg}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    // 服務模式：寫每日 log 檔（<設定目錄>/logs），不寫主控台
    if crate::service::instance::log_enabled() {
        crate::service::instance::write_log(&line);
    } else if !env.global.quiet {
        eprintln!("{line}");
    }
}

fn agent_info(cfg: &config::AgentConfig) -> AgentInfo {
    let mut a = AgentInfo::current(&cfg.agent_id);
    crate::sysmeta::enrich(&mut a);
    a.scanners_available = super::scan_cmd::build_pipeline().available();
    a
}

pub async fn enroll(
    env: &Env,
    url: &str,
    key: &str,
    accept_remote_actions: bool,
    insecure_http: bool,
) -> AppResult<()> {
    let url = validate_url(url, insecure_http)?;
    let key = if key == "-" {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim().to_string()
    } else {
        key.trim().to_string()
    };
    if key.is_empty() {
        return Err(AppError::InvalidArg(t!("client 金鑰不可為空").into()));
    }
    let mut cfg = config::load_or_init(&env.config_dir)?;
    let token = watch::agent_token(&env.config_dir)?;
    let client = HubClient::new(&url, &key, &cfg.agent_id)?.with_agent_token(Some(token));
    let health = client.health().await?;
    let agent = agent_info(&cfg);
    let reg = client
        .register(&agent, accept_remote_actions, false)
        .await
        .map_err(|e| match e {
            AppError::HubAuth => AppError::HubAuth,
            other => other,
        })?;
    SecretStore::open(&env.config_dir).set(KEY_HUB_CLIENT, &key)?;
    let has_action_key = watch::save_action_key(&env.config_dir, accept_remote_actions, reg.action_key.as_deref())?;
    cfg.hub = Some(HubConfig {
        url: url.clone(),
        enrolled_at: crate::util::time::now_iso(),
        min_report_interval_s: Some(reg.hub.min_report_interval_s),
        max_report_bytes: Some(reg.hub.max_report_bytes),
        snapshot_interval_s: Some(reg.hub.snapshot_interval_s),
        feed_mirror: false,
    });
    cfg.remote_actions.accept = accept_remote_actions;
    config::save(&env.config_dir, &cfg)?;
    if env.global.json {
        print_json(
            &serde_json::json!({ "ok": true, "hub": url, "agent_id": reg.agent_id, "created": reg.created, "pinned": reg.pinned, "remote_actions": has_action_key, "hub_info": reg.hub, "health": health }),
        );
    } else {
        println!(
            "{}",
            tf!(
                "已註冊到 {url}（{hub} {version}）；agent id {id}",
                url = url,
                hub = reg.hub.name,
                version = reg.hub.version,
                id = reg.agent_id
            )
        );
        if accept_remote_actions && !has_action_key {
            println!(
                "{}",
                t!("注意：hub 沒有提供遠端動作金鑰（hub 版本太舊，或這台 agent 的身分未能釘選），遠端動作不會執行")
            );
        } else if has_action_key {
            println!(
                "{}",
                t!("已啟用遠端動作：hub 核准的封鎖會在這台機器執行（需以系統管理員／服務模式執行 asa watch）")
            );
        }
        println!(
            "{}",
            t!("下一步：執行 asa watch 開始定期回報（或 asa watch --once 先試一輪）")
        );
    }
    Ok(())
}

pub async fn unenroll(env: &Env) -> AppResult<()> {
    let mut cfg = config::load_or_init(&env.config_dir)?;
    let was = cfg.hub.take();
    config::save(&env.config_dir, &cfg)?;
    let store = SecretStore::open(&env.config_dir);
    store.delete(KEY_HUB_CLIENT)?;
    store.delete(KEY_HUB_ACTION)?;
    match was {
        Some(h) => println!("{}", tf!("已取消註冊：{url}", url = h.url)),
        None => println!("{}", t!("原本就沒有註冊任何 hub")),
    }
    Ok(())
}

pub async fn status(env: &Env) -> AppResult<()> {
    let cfg = config::load_or_init(&env.config_dir)?;
    let latest = watch::load_latest(&env.config_dir);
    let pending = outbox::list(&env.config_dir).len();
    let key_ok = SecretStore::open(&env.config_dir)
        .get(KEY_HUB_CLIENT)
        .ok()
        .flatten()
        .is_some();
    let health = match watch::client_from_config(&env.config_dir, &cfg) {
        Ok(Some(c)) => Some(c.health().await.map_err(|e| e.message())),
        _ => None,
    };
    if env.global.json {
        print_json(&serde_json::json!({
            "agent_id": cfg.agent_id,
            "version": crate::VERSION,
            "config_dir": env.config_dir,
            "hub": cfg.hub,
            "client_key": key_ok,
            "outbox": pending,
            "last_report": latest.as_ref().map(|r| serde_json::json!({ "finished_at": r.finished_at, "score": r.score, "findings": r.findings.len() })),
            "hub_health": health.as_ref().map(|h| match h { Ok(v) => v.clone(), Err(e) => serde_json::json!({ "error": e }) }),
        }));
        return Ok(());
    }
    let mut rows = vec![
        vec!["agent id".to_string(), cfg.agent_id.clone()],
        vec![t!("版本").to_string(), crate::VERSION.to_string()],
        vec![t!("設定目錄").to_string(), env.config_dir.display().to_string()],
        vec![
            "hub".to_string(),
            cfg.hub
                .as_ref()
                .map(|h| h.url.clone())
                .unwrap_or_else(|| t!("未註冊").to_string()),
        ],
    ];
    if cfg.hub.is_some() {
        rows.push(vec![
            t!("client 金鑰").to_string(),
            if key_ok { "✓".into() } else { "✗".into() },
        ]);
        rows.push(vec![
            t!("hub 狀態").to_string(),
            match &health {
                Some(Ok(v)) => format!(
                    "ok · {} · db {}",
                    v["version"].as_str().unwrap_or("?"),
                    v["db"].as_str().unwrap_or("?")
                ),
                Some(Err(e)) => e.clone(),
                None => "-".into(),
            },
        ]);
        rows.push(vec![t!("待重送").to_string(), pending.to_string()]);
    }
    rows.push(vec![
        t!("最後一次掃描").to_string(),
        latest
            .as_ref()
            .map(|r| {
                tf!(
                    "{at} · {n} 筆發現 · 總分 {score}",
                    at = r.finished_at.format("%Y-%m-%d %H:%M"),
                    n = r.findings.len(),
                    score = r.score.overall
                )
            })
            .unwrap_or_else(|| "-".into()),
    ]);
    println!("{}", table(&[t!("項目"), t!("值")], rows));
    Ok(())
}

/// 領取並執行 hub 核准的遠端動作；每個動作都回報結果（包含拒絕執行的原因）。
async fn run_remote_actions(env: &Env, client: &HubClient, cfg: &config::AgentConfig) {
    if !cfg.remote_actions.accept {
        return;
    }
    let Ok(Some(key)) = SecretStore::open(&env.config_dir).get(KEY_HUB_ACTION) else {
        return;
    };
    let items = match client.poll_actions().await {
        Ok(v) => v,
        Err(e) => {
            log(env, &tf!("領取遠端動作失敗：{e}", e = e.message()));
            return;
        }
    };
    let allowlist = crate::model::allowlist::Allowlist::load(&env.config_dir).unwrap_or_default();
    let mut done = remote::DoneLog::load(&env.config_dir);
    for a in items {
        let (ok, output) = match done.items.get(&a.action_id) {
            Some(prev) => (prev.ok, prev.output.clone()),
            None => {
                let r = execute_remote(env, &a, &key, cfg, &allowlist).await;
                done.record(&a.action_id, r.0, &r.1);
                let _ = done.save(&env.config_dir);
                r
            }
        };
        log(
            env,
            &tf!(
                "遠端動作 {id}（{kind}）：{result}",
                id = a.action_id,
                kind = a.kind,
                result = output
            ),
        );
        if let Err(e) = client.post_action_result(&a.action_id, ok, &output).await {
            log(env, &tf!("回報遠端動作結果失敗：{e}", e = e.message()));
        }
    }
}

async fn execute_remote(
    env: &Env,
    a: &remote::RemoteAction,
    key: &str,
    cfg: &config::AgentConfig,
    allowlist: &crate::model::allowlist::Allowlist,
) -> (bool, String) {
    let fw = match remote::check(a, key, &cfg.agent_id, &cfg.remote_actions, allowlist, Utc::now()) {
        Ok(fw) => fw,
        Err(why) => return (false, tf!("拒絕執行：{why}", why = why)),
    };
    // 背景執行不跳 UAC／sudo：沒有權限就回報失敗。
    if !crate::elevate::is_elevated() {
        return (
            false,
            t!("需要系統管理員權限：請以服務模式（asa service install）或系統管理員身分執行 asa watch").to_string(),
        );
    }
    let backend = crate::firewall::plan::write_backend();
    let origin = format!("hub:{}", a.action_id);
    let runner = crate::util::cmd::RealRunner;
    match crate::actions::execute(&env.config_dir, &fw, backend, &origin, &runner, false).await {
        Ok(rep) => (
            true,
            tf!(
                "已套用：{action}（後端 {backend}）",
                action = rep.action,
                backend = rep.backend
            ),
        ),
        Err(e) => (false, e.message()),
    }
}

/// 先把 outbox 裡的舊報告送掉（遇到錯誤就停，等下一輪）。
async fn flush_outbox(env: &Env, client: &HubClient) {
    for p in outbox::list(&env.config_dir) {
        let Some(r) = outbox::load(&p) else {
            outbox::remove(&p);
            continue;
        };
        match client.upload_report(&r).await {
            Ok(_) => {
                outbox::remove(&p);
                log(env, &tf!("已補送暫存報告 {id}", id = r.report_id));
            }
            Err(e @ AppError::HubRejected(_)) => {
                outbox::remove(&p);
                log(env, &e.message());
            }
            Err(e) => {
                log(env, &tf!("補送失敗，稍後再試：{e}", e = e.message()));
                return;
            }
        }
    }
}

pub async fn watch(env: &Env, a: WatchArgs) -> AppResult<()> {
    // 服務模式：不印進度、單一實例、寫 log 檔、Windows 開機自動啟動時把自帶的主控台關掉
    let quiet_env;
    let env = if a.service {
        quiet_env = Env {
            global: super::args::GlobalArgs {
                quiet: true,
                ..env.global.clone()
            },
            config_dir: env.config_dir.clone(),
        };
        &quiet_env
    } else {
        env
    };
    let _lock = if a.service {
        crate::service::instance::init_log(&env.config_dir);
        crate::service::instance::detach_console_if_owned();
        match crate::service::instance::InstanceLock::acquire(&env.config_dir) {
            Ok(Some(l)) => Some(l),
            Ok(None) => {
                log(env, t!("同一個設定目錄已經有常駐的 asa watch，這個不再啟動"));
                return Ok(());
            }
            Err(e) => {
                log(env, &tf!("無法建立單一實例鎖：{e}", e = e));
                None
            }
        }
    } else {
        None
    };
    if a.service {
        log(
            env,
            &tf!(
                "服務模式啟動（asa {v}，設定目錄 {dir}）",
                v = crate::VERSION,
                dir = env.config_dir.display()
            ),
        );
    }
    let cfg = config::load_or_init(&env.config_dir)?;
    let client = if a.no_upload {
        None
    } else {
        watch::client_from_config(&env.config_dir, &cfg)?
    };
    if client.is_none() && !a.no_upload {
        log(
            env,
            t!("尚未註冊 hub：只在本機掃描（asa enroll <HUB_URL> --key … 後才會上傳）"),
        );
    }
    let mut interval = crate::util::time::parse_duration(a.interval.as_deref().unwrap_or(&cfg.scan.interval))?;
    let mut snap_every =
        crate::util::time::parse_duration(a.snapshot_interval.as_deref().unwrap_or(&cfg.scan.snapshot_interval))?;
    let agent = agent_info(&cfg);
    if let Some(c) = &client {
        match c.register(&agent, cfg.remote_actions.accept, a.service).await {
            Ok(r) => {
                match watch::save_action_key(&env.config_dir, cfg.remote_actions.accept, r.action_key.as_deref()) {
                    Ok(true) => log(env, t!("遠端動作：已啟用")),
                    Ok(false) if cfg.remote_actions.accept => log(env, t!("遠端動作：hub 沒有提供驗章金鑰，暫不執行")),
                    Ok(false) => {}
                    Err(e) => log(env, &e.message()),
                }
                interval = interval.max(Duration::from_secs(r.hub.min_report_interval_s));
                snap_every = snap_every.max(Duration::from_secs(r.hub.snapshot_interval_s.max(10)));
                log(
                    env,
                    &tf!(
                        "已連上 {url}（{hub} {version}）",
                        url = c.base(),
                        hub = r.hub.name,
                        version = r.hub.version
                    ),
                );
            }
            Err(e) => log(env, &tf!("註冊失敗，稍後重試：{e}", e = e.message())),
        }
    }
    interval = interval.max(Duration::from_secs(60));
    snap_every = snap_every.max(Duration::from_secs(10));

    let mut intel = watch::load_intel(&env.config_dir).await;
    let mut intel_loaded = std::time::Instant::now();
    let mut next_scan = tokio::time::Instant::now();
    let mut next_snap = tokio::time::Instant::now();
    let mut last_scan_at: Option<chrono::DateTime<Utc>> = None;

    loop {
        let now = tokio::time::Instant::now();
        if now >= next_snap {
            if intel_loaded.elapsed() > Duration::from_secs(3600) {
                intel = watch::load_intel(&env.config_dir).await;
                intel_loaded = std::time::Instant::now();
            }
            match watch::snapshot(&env.config_dir, &cfg.agent_id, intel.clone()).await {
                Ok(s) => {
                    let bad = s.connections.iter().filter(|c| c.verdict.is_bad()).count();
                    if let Some(c) = &client {
                        match c.upload_snapshot(&s).await {
                            Ok(_) => log(
                                env,
                                &tf!(
                                    "快照已上傳：{n} 條連線（可疑／危險 {bad}）",
                                    n = s.connections.len(),
                                    bad = bad
                                ),
                            ),
                            Err(e) => log(env, &tf!("快照上傳失敗：{e}", e = e.message())),
                        }
                        let hb = HeartbeatPayload {
                            agent_id: cfg.agent_id.clone(),
                            ts: Utc::now(),
                            version: crate::VERSION.to_string(),
                            uptime_s: agent.uptime_s,
                            last_scan_at,
                            elevated: crate::elevate::is_elevated(),
                        };
                        match c.heartbeat(&hb).await {
                            Ok(v) if v["pending_actions"].as_u64().unwrap_or(0) > 0 => {
                                run_remote_actions(env, c, &cfg).await;
                            }
                            Ok(_) => {}
                            Err(e) => log(env, &tf!("心跳失敗：{e}", e = e.message())),
                        }
                    } else {
                        log(
                            env,
                            &tf!(
                                "快照：{n} 條連線（可疑／危險 {bad}）",
                                n = s.connections.len(),
                                bad = bad
                            ),
                        );
                    }
                }
                Err(e) => log(env, &tf!("快照失敗：{e}", e = e.message())),
            }
            next_snap = now + snap_every;
        }
        if now >= next_scan {
            if let Some(c) = &client {
                flush_outbox(env, c).await;
            }
            match super::scan_cmd::run_scan(env, &ScanArgs::default().scanners, false).await {
                Ok((report, _)) => {
                    last_scan_at = Some(report.finished_at);
                    let _ = watch::save_latest(&env.config_dir, &report);
                    let summary = tf!(
                        "掃描完成：{n} 筆發現，總分 {score}",
                        n = report.findings.len(),
                        score = report.score.overall
                    );
                    if let Some(c) = &client {
                        match c.upload_report(&report).await {
                            Ok(v) => log(
                                env,
                                &tf!(
                                    "{summary}；已上傳（新 {new}、解決 {resolved}）",
                                    summary = summary,
                                    new = v["findings"]["new"].as_u64().unwrap_or(0),
                                    resolved = v["findings"]["resolved"].as_u64().unwrap_or(0)
                                ),
                            ),
                            Err(e @ AppError::HubRejected(_)) => log(env, &format!("{summary}；{}", e.message())),
                            Err(e) => {
                                let _ = outbox::push(&env.config_dir, &report);
                                log(
                                    env,
                                    &tf!("{summary}；上傳失敗已暫存：{e}", summary = summary, e = e.message()),
                                );
                            }
                        }
                    } else {
                        log(env, &summary);
                    }
                }
                Err(e) => log(env, &tf!("掃描失敗：{e}", e = e.message())),
            }
            next_scan = now + interval;
        }
        if a.once || crate::service::instance::stop_requested() {
            break;
        }
        let wake = next_scan.min(next_snap);
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {}
            _ = crate::service::instance::stopped() => {
                log(env, t!("收到停止訊號，結束"));
                break;
            }
        }
    }
    Ok(())
}
