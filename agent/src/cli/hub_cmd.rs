//! `ai-security-monitor enroll` / `unenroll` / `status` / `watch`：註冊到 Security Hub 與常駐回報。

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use chrono::Utc;

use super::args::{DiscoverArgs, EnrollArgs, HubCmd, ScanArgs, WatchArgs};
use super::render::{print_json, table};
use super::Env;
use crate::config::{self, HubConfig};
use crate::error::{AppError, AppResult};
use crate::hub::contract::{HeartbeatPayload, IntelFeedsInfo};
use crate::hub::discover::{self, Choice, Found};
use crate::hub::enroll::{self as keyless, PendingEnroll, Step};
use crate::hub::identity::{self, HubIdentity, PinCheck};
use crate::hub::{actions as remote, outbox, validate_url, watch, HubClient};
use crate::model::report::AgentInfo;
use crate::secrets::{SecretStore, KEY_HUB_ACTION, KEY_HUB_CLIENT, KEY_HUB_ENROLL_SECRET};

fn log(env: &Env, msg: &str) {
    let line = format!("[{}] {msg}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    // 服務模式：寫每日 log 檔（<設定目錄>/logs），不寫主控台
    if crate::service::instance::log_enabled() {
        crate::service::instance::write_log(&line);
    } else if !env.global.quiet {
        eprintln!("{line}");
    }
}

/// 服務啟動時依期望狀態重新套用 ai-security-monitor 的防火牆規則（pf／nftables 重開機不保留）；只在有權限且真的有東西要套時做。
async fn reapply_firewall(env: &Env) {
    let Ok(d) = crate::firewall::desired::DesiredState::load(&env.config_dir) else {
        return;
    };
    if d.blocked.is_empty() && d.closed_ports.is_empty() && d.feed_nets == 0 {
        return;
    }
    if !crate::elevate::is_elevated() {
        log(
            env,
            t!("有 ai-security-monitor 防火牆規則要重新套用，但沒有系統管理員權限（請用 ai-security-monitor service install --system）"),
        );
        return;
    }
    let backend = crate::firewall::plan::write_backend();
    let action = crate::firewall::plan::FwAction::Ensure;
    match crate::actions::execute(
        &env.config_dir,
        &action,
        backend,
        "service",
        &crate::util::cmd::RealRunner,
        false,
    )
    .await
    {
        Ok(_) => log(
            env,
            &tf!(
                "已重新套用防火牆規則：封鎖 {b} 筆、關閉 {p} 個 port、情資網段 {n} 個",
                b = d.blocked.len(),
                p = d.closed_ports.len(),
                n = d.feed_nets
            ),
        ),
        Err(e) => log(env, &tf!("重新套用防火牆規則失敗：{e}", e = e.message())),
    }
}

pub fn agent_info(cfg: &config::AgentConfig) -> AgentInfo {
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
    // 用金鑰註冊也釘選 Hub 身分（舊版 Hub 沒有身分端點就不釘）；明確給金鑰＝使用者確定要這個 Hub
    let hub_id = client.identity().await.ok().flatten();
    cfg.hub = Some(HubConfig {
        url: url.clone(),
        enrolled_at: crate::util::time::now_iso(),
        min_report_interval_s: Some(reg.hub.min_report_interval_s),
        max_report_bytes: Some(reg.hub.max_report_bytes),
        snapshot_interval_s: Some(reg.hub.snapshot_interval_s),
        feed_mirror: false,
        fingerprint: hub_id.as_ref().map(|i| i.fingerprint.clone()),
        public_key: hub_id.as_ref().map(|i| i.public_key.clone()),
    });
    cfg.remote_actions.accept = accept_remote_actions;
    config::save(&env.config_dir, &cfg)?;
    // 改用金鑰加入：之前的免金鑰申請就不用再等
    if keyless::load_pending(&env.config_dir).is_some() {
        keyless::clear_pending(&env.config_dir)?;
    }
    if env.global.json {
        print_json(
            &serde_json::json!({ "ok": true, "hub": url, "agent_id": reg.agent_id, "created": reg.created, "pinned": reg.pinned, "remote_actions": has_action_key, "hub_info": reg.hub, "health": health, "hub_fingerprint": hub_id.as_ref().map(|i| i.fingerprint.clone()) }),
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
        if let Some(i) = &hub_id {
            println!(
                "{}",
                tf!(
                    "Hub 指紋：{fp}（已記下，之後 Hub 身分不同會拒絕上傳）",
                    fp = i.fingerprint
                )
            );
        }
        if accept_remote_actions && !has_action_key {
            println!(
                "{}",
                t!("注意：hub 沒有提供遠端動作金鑰（hub 版本太舊，或這台 agent 的身分未能釘選），遠端動作不會執行")
            );
        } else if has_action_key {
            println!(
                "{}",
                t!("已啟用遠端動作：hub 核准的封鎖會在這台機器執行（需以系統管理員／服務模式執行 ai-security-monitor watch）")
            );
        }
        println!(
            "{}",
            t!("下一步：執行 ai-security-monitor watch 開始定期回報（或 ai-security-monitor watch --once 先試一輪）")
        );
    }
    Ok(())
}

/// `enroll`：有 `--key` 走原本的金鑰註冊；沒有就免金鑰加入（自動尋找＋加入申請）。
pub async fn enroll_cmd(env: &Env, a: EnrollArgs) -> AppResult<()> {
    match a.key.as_deref() {
        Some(key) => {
            let url = a.url.as_deref().or(a.hub.as_deref()).ok_or_else(|| {
                AppError::InvalidArg(
                    t!("用 --key 註冊時要給 Hub 網址（ai-security-monitor enroll <HUB_URL> --key …）").into(),
                )
            })?;
            enroll(env, url, key, a.accept_remote_actions, a.insecure_http).await
        }
        None => enroll_auto(env, a).await,
    }
}

fn fmt_found_rows(found: &[Found], pinned: Option<&str>) -> Vec<Vec<String>> {
    found
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let state = match (&f.identity, &f.error) {
                (Some(id), None) if pinned.is_some_and(|p| identity::same_fingerprint(p, &id.fingerprint)) => {
                    t!("可加入 · 這台電腦釘選的 Hub").to_string()
                }
                (Some(id), None) if !id.enrollment.keyless => t!("可連線，但不接受免金鑰加入").to_string(),
                (Some(_), None) => t!("可加入").to_string(),
                (_, Some(e)) => e.clone(),
                (None, None) => "-".into(),
            };
            vec![
                (i + 1).to_string(),
                f.candidate.source.label().to_string(),
                f.candidate.url.clone(),
                f.identity
                    .as_ref()
                    .map(|i| i.name.clone())
                    .unwrap_or_else(|| "-".into()),
                f.identity
                    .as_ref()
                    .map(|i| i.fingerprint.clone())
                    .unwrap_or_else(|| "-".into()),
                state,
            ]
        })
        .collect()
}

fn found_table(found: &[Found], pinned: Option<&str>) -> String {
    table(
        &["#", t!("來源"), t!("網址"), t!("名稱"), t!("指紋"), t!("狀態")],
        fmt_found_rows(found, pinned),
    )
}

const NOT_FOUND_HINT: &str = "沒有找到 Security Hub。請管理員在公司 DNS 加 _aisecmon._tcp 的 SRV 紀錄、在區網開啟 Hub 廣播，或直接用 ai-security-monitor enroll --hub <網址>";

/// `discover`：列出找到的 Hub（每一種方式都試）。
pub async fn discover(env: &Env, a: DiscoverArgs) -> AppResult<()> {
    let cfg = config::load_or_init(&env.config_dir)?;
    let opts = discover::Opts {
        config_url: cfg.hub.as_ref().map(|h| h.url.clone()),
        dns: !a.no_dns,
        mdns: !a.no_mdns,
        timeout: crate::util::time::parse_duration(&a.timeout)?,
        insecure_http: a.insecure_http,
        all: true,
        ..discover::Opts::default()
    };
    if !env.global.json && !env.global.quiet {
        eprintln!("{}", t!("正在尋找 Security Hub（公司 DNS、區網廣播）…"));
    }
    let found = discover::find(&opts).await?;
    let pinned = cfg.hub.as_ref().and_then(|h| h.fingerprint.clone());
    if env.global.json {
        print_json(&serde_json::json!({ "hubs": found, "pinned_fingerprint": pinned }));
        return Ok(());
    }
    if found.is_empty() {
        println!("{}", crate::i18n::lookup(NOT_FOUND_HINT));
        return Ok(());
    }
    println!("{}", found_table(&found, pinned.as_deref()));
    Ok(())
}

/// 等候中的申請說明（給使用者核對）。
fn print_waiting(p: &PendingEnroll) {
    println!(
        "{}",
        tf!(
            "等候管理員核准… Hub「{name}」（{url}）\n  Hub 指紋：{fp}\n  這台電腦的核對碼：{code}\n  請管理員在 Hub 的「新增主機 → 待核准的主機」核對後按核准。",
            name = p.hub_name,
            url = p.hub_url,
            fp = p.hub_fingerprint,
            code = p.request_code
        )
    );
}

/// 互動確認（沒有終端機就要 --yes）。
fn confirm(env: &Env, prompt: &str) -> AppResult<bool> {
    if env.global.yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(AppError::InvalidArg(
            t!("要加入這個 Hub 請加 --yes（或用 --hub <網址> 指定）").into(),
        ));
    }
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "是"))
}

/// 送出加入申請並存檔（密語存密鑰庫）。桌面版也用這個。
pub async fn start_enroll_request(
    config_dir: &std::path::Path,
    url: &str,
    hub: &HubIdentity,
    accept_remote_actions: bool,
) -> AppResult<(PendingEnroll, keyless::EnrollStatus)> {
    if !hub.enrollment.keyless {
        return Err(AppError::Hub(
            t!("這個 Hub 沒有開放免金鑰加入：請向管理員要註冊金鑰（enroll --key）").into(),
        ));
    }
    let cfg = config::load_or_init(config_dir)?;
    let secret = keyless::new_secret()?;
    SecretStore::open(config_dir).set(KEY_HUB_ENROLL_SECRET, &secret)?;
    let http = identity::http_client(Duration::from_secs(20))?;
    let agent = agent_info(&cfg);
    let (p, st) = keyless::submit(&http, url, hub, &agent, accept_remote_actions, &secret).await?;
    keyless::save_pending(config_dir, &p)?;
    Ok((p, st))
}

fn finish_message(env: &Env, cfg: &config::AgentConfig, reg: &crate::hub::contract::RegisterResponse) {
    let h = cfg.hub.as_ref();
    if env.global.json {
        print_json(&serde_json::json!({
            "ok": true,
            "status": "enrolled",
            "hub": h.map(|h| h.url.clone()),
            "agent_id": reg.agent_id,
            "hub_fingerprint": h.and_then(|h| h.fingerprint.clone()),
            "hub_info": reg.hub,
        }));
        return;
    }
    println!(
        "{}",
        tf!(
            "管理員已核准：已加入 {url}（{hub} {version}）；agent id {id}",
            url = h.map(|h| h.url.as_str()).unwrap_or("?"),
            hub = reg.hub.name,
            version = reg.hub.version,
            id = reg.agent_id
        )
    );
    println!(
        "{}",
        t!("下一步：執行 ai-security-monitor service install --yes 開機自動回報（或 ai-security-monitor watch --once 先試一輪）")
    );
}

/// 已經加入某個 Hub 時再執行 `enroll --auto`：同一個 Hub 不用再申請；指紋相同的新網址就更新網址；不同的 Hub 要 --repin。
async fn already_enrolled(
    env: &Env,
    cfg: &mut config::AgentConfig,
    h: HubConfig,
    target: Option<String>,
    insecure_http: bool,
) -> AppResult<()> {
    let same_url = target
        .as_deref()
        .is_none_or(|t| t.trim_end_matches('/').eq_ignore_ascii_case(&h.url));
    if same_url {
        if env.global.json {
            print_json(
                &serde_json::json!({ "ok": true, "status": "enrolled", "hub": h.url, "hub_fingerprint": h.fingerprint }),
            );
        } else {
            println!(
                "{}",
                tf!("這台電腦已經加入 {url}（要改加入別的 Hub 請加 --repin）", url = h.url)
            );
        }
        return Ok(());
    }
    let url = discover::acceptable_url(target.as_deref().unwrap_or_default(), insecure_http).await?;
    let http = identity::http_client(Duration::from_secs(10))?;
    let id = identity::fetch(&http, &url)
        .await?
        .ok_or_else(|| AppError::Hub(t!("這個 Hub 版本太舊，不支援免金鑰加入（請用 --key）").into()))?;
    match identity::check_pin(h.fingerprint.as_deref(), &id.fingerprint) {
        PinCheck::Same => {
            // 同一個 Hub 換了網址：更新網址就好
            let mut nh = h;
            nh.url = url.clone();
            cfg.hub = Some(nh);
            config::save(&env.config_dir, cfg)?;
            println!(
                "{}",
                tf!(
                    "同一個 Hub（指紋 {fp}）的新網址：已改成 {url}",
                    fp = id.fingerprint,
                    url = url
                )
            );
            Ok(())
        }
        PinCheck::Mismatch { pinned, seen } => Err(AppError::HubIdentity(identity::mismatch_message(&pinned, &seen))),
        PinCheck::Unpinned => Err(AppError::InvalidArg(tf!(
            "這台電腦已經加入 {url}；要改加入 {new} 請加 --repin",
            url = h.url,
            new = url
        ))),
    }
}

/// 尋找 Hub → 確認指紋 → 送出申請。
async fn discover_and_request(
    env: &Env,
    cfg: &config::AgentConfig,
    a: &EnrollArgs,
    explicit: Option<String>,
) -> AppResult<PendingEnroll> {
    let opts = discover::Opts {
        explicit: explicit.clone(),
        insecure_http: a.insecure_http,
        ..discover::Opts::default()
    };
    if !env.global.json && explicit.is_none() {
        eprintln!("{}", t!("正在尋找 Security Hub（公司 DNS、區網廣播）…"));
    }
    let found = discover::find(&opts).await?;
    let pinned = if a.repin {
        None
    } else {
        cfg.hub.as_ref().and_then(|h| h.fingerprint.clone())
    };
    if !env.global.json && !found.is_empty() {
        println!("{}", found_table(&found, pinned.as_deref()));
    }
    let idx = match discover::choose(&found, pinned.as_deref()) {
        Choice::One(i) => i,
        Choice::None => {
            let detail = found
                .iter()
                .filter_map(|f| f.error.clone())
                .collect::<Vec<_>>()
                .join("；");
            return Err(AppError::Hub(if found.is_empty() {
                crate::i18n::lookup(NOT_FOUND_HINT).into()
            } else {
                tf!("找到的 Hub 都不能用：{detail}", detail = detail)
            }));
        }
        Choice::Many(_) => {
            return Err(AppError::InvalidArg(
                t!("找到好幾個不同的 Hub：請和管理員確認指紋後，用 ai-security-monitor enroll --hub <網址> 指定")
                    .into(),
            ));
        }
        Choice::PinnedMismatch(v) => {
            let seen = found[v[0]].fingerprint().unwrap_or("?").to_string();
            return Err(AppError::HubIdentity(identity::mismatch_message(
                pinned.as_deref().unwrap_or("?"),
                &seen,
            )));
        }
    };
    let f = &found[idx];
    let Some(id) = f.identity.clone() else {
        return Err(AppError::Hub(crate::i18n::lookup(NOT_FOUND_HINT).into()));
    };
    if explicit.is_none()
        && !confirm(
            env,
            &tf!(
                "加入「{name}」（{url}，指紋 {fp}）？",
                name = id.name,
                url = f.candidate.url,
                fp = id.fingerprint
            ),
        )?
    {
        return Err(AppError::Cancelled);
    }
    let (p, _) = start_enroll_request(&env.config_dir, &f.candidate.url, &id, a.accept_remote_actions).await?;
    Ok(p)
}

/// 重試也不會過的錯誤（簽章、指紋）：等候迴圈直接停。
fn fatal_enroll_error(e: &AppError) -> bool {
    matches!(e, AppError::HubIdentity(_))
}

/// 免金鑰加入：接著等之前的申請，或尋找 Hub → 確認指紋 → 送出申請 → 等核准。
async fn enroll_auto(env: &Env, a: EnrollArgs) -> AppResult<()> {
    let dir = &env.config_dir;
    let mut cfg = config::load_or_init(dir)?;
    let wait = crate::util::time::parse_duration(a.wait.as_deref().unwrap_or("15m"))?;
    let explicit = a
        .hub
        .clone()
        .or(a.url.clone())
        .map(|u| u.trim().trim_end_matches('/').to_string());
    let has_key = SecretStore::open(dir).get(KEY_HUB_CLIENT).ok().flatten().is_some();
    if let (Some(h), true, false) = (cfg.hub.clone(), has_key, a.repin) {
        let target = explicit.clone().or_else(|| crate::util::env::var("HUB_URL"));
        return already_enrolled(env, &mut cfg, h, target, a.insecure_http).await;
    }

    // 有等候中的申請：同一個 Hub（或沒指定）就接著等；指定了別的 Hub 就改申請那個
    let mut pending = keyless::load_pending(dir);
    if let (Some(p), Some(e)) = (&pending, &explicit) {
        if !p.hub_url.eq_ignore_ascii_case(e) {
            keyless::clear_pending(dir)?;
            pending = None;
        }
    }
    let pending = match pending {
        Some(p) => {
            if !env.global.json {
                println!("{}", t!("接著等候之前送出的加入申請。"));
            }
            p
        }
        None => discover_and_request(env, &cfg, &a, explicit).await?,
    };
    if !env.global.json {
        print_waiting(&pending);
    }

    // 等候核准（每次都重新讀檔：watch／另一個 enroll 也可能在等）
    let agent = agent_info(&cfg);
    let deadline = tokio::time::Instant::now() + wait;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        let delay = match keyless::step(dir, &mut cfg, &agent, false).await {
            Ok(Some(Step::Done(reg))) => {
                finish_message(env, &cfg, &reg);
                return Ok(());
            }
            Ok(Some(Step::Rejected(reason))) => {
                return Err(AppError::Hub(match reason.filter(|r| !r.trim().is_empty()) {
                    Some(r) => tf!("管理員拒絕了這台電腦的加入申請：{reason}", reason = r),
                    None => t!("管理員拒絕了這台電腦的加入申請").into(),
                }));
            }
            Ok(Some(Step::Expired)) | Ok(None) => {
                return Err(AppError::Hub(
                    t!("加入申請已過期或被刪除：請重新執行 ai-security-monitor enroll --auto").into(),
                ));
            }
            Ok(Some(Step::Waiting(st))) => keyless::poll_delay(Some(&pending), Some(&st)),
            Err(e) if fatal_enroll_error(&e) => return Err(e),
            Err(e) => {
                if !env.global.json {
                    eprintln!("{}", tf!("查詢核准狀態失敗，稍後重試：{e}", e = e.message()));
                }
                Duration::from_secs(30)
            }
        };
        let now = tokio::time::Instant::now();
        if now >= deadline {
            if env.global.json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "status": "pending",
                    "hub": pending.hub_url,
                    "request_id": pending.request_id,
                    "request_code": pending.request_code,
                    "hub_fingerprint": pending.hub_fingerprint,
                }));
            } else {
                println!("{}", t!("還沒核准。之後再執行 ai-security-monitor enroll --auto 會接著等；已安裝常駐服務（watch）的話，它會在背景繼續等，核准後自動開始回報。"));
            }
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(delay.min(deadline - now)) => {}
            _ = &mut ctrl_c => {
                println!("{}", t!("已中斷等候；申請仍然有效，之後再執行 ai-security-monitor enroll --auto 會接著等。"));
                return Ok(());
            }
        }
    }
}

/// `hub advertise`：用 mDNS 在區網上廣播 Hub。
pub async fn hub(env: &Env, cmd: HubCmd) -> AppResult<()> {
    match cmd {
        HubCmd::Advertise {
            url,
            name,
            duration,
            insecure_http,
        } => {
            let url = discover::acceptable_url(&url, insecure_http).await?;
            let http = identity::http_client(Duration::from_secs(10))?;
            let id = identity::fetch(&http, &url)
                .await?
                .ok_or_else(|| AppError::Hub(t!("這個 Hub 版本太舊，沒有身分端點，不能廣播").into()))?;
            let host = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_default();
            let instance = name.unwrap_or_else(|| format!("{} ({host})", id.name));
            let dur = duration.as_deref().map(crate::util::time::parse_duration).transpose()?;
            let (daemon, fullname) = crate::hub::advertise::start(&url, &id, &instance)?;
            if env.global.json {
                print_json(
                    &serde_json::json!({ "ok": true, "advertising": fullname, "url": url, "fingerprint": id.fingerprint }),
                );
            } else {
                println!(
                    "{}",
                    tf!(
                        "正在區網廣播「{name}」→ {url}（指紋 {fp}）。按 Ctrl-C 結束。",
                        name = instance,
                        url = url,
                        fp = id.fingerprint
                    )
                );
            }
            let stop = crate::service::instance::stopped();
            match dur {
                Some(d) => {
                    tokio::select! {
                        _ = tokio::time::sleep(d) => {}
                        _ = stop => {}
                    }
                }
                None => stop.await,
            }
            crate::hub::advertise::stop(&daemon, &fullname);
            if !env.global.json {
                println!("{}", t!("已停止廣播"));
            }
            Ok(())
        }
    }
}

pub async fn unenroll(env: &Env) -> AppResult<()> {
    let mut cfg = config::load_or_init(&env.config_dir)?;
    let was = cfg.hub.take();
    config::save(&env.config_dir, &cfg)?;
    let store = SecretStore::open(&env.config_dir);
    store.delete(KEY_HUB_CLIENT)?;
    store.delete(KEY_HUB_ACTION)?;
    if let Some(p) = keyless::load_pending(&env.config_dir) {
        keyless::clear_pending(&env.config_dir)?;
        println!("{}", tf!("已取消等候中的加入申請（{url}）", url = p.hub_url));
    }
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
    let enroll_req = keyless::load_pending(&env.config_dir);
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
            "enroll_request": enroll_req.as_ref().map(|p| serde_json::json!({ "hub": p.hub_url, "hub_name": p.hub_name, "hub_fingerprint": p.hub_fingerprint, "request_id": p.request_id, "request_code": p.request_code, "status": p.status, "created_at": p.created_at })),
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
        if let Some(fp) = cfg.hub.as_ref().and_then(|h| h.fingerprint.as_deref()) {
            rows.push(vec![t!("Hub 指紋").to_string(), fp.to_string()]);
        }
    }
    if let Some(p) = &enroll_req {
        rows.push(vec![
            t!("加入申請").to_string(),
            tf!(
                "等候管理員核准 · {url} · 核對碼 {code} · Hub 指紋 {fp}",
                url = p.hub_url,
                code = p.request_code,
                fp = p.hub_fingerprint
            ),
        ]);
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
            t!("需要系統管理員權限：請以服務模式（ai-security-monitor service install）或系統管理員身分執行 ai-security-monitor watch").to_string(),
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

/// 檢查 Hub 身分是否是釘選的那一個；沒釘選過（舊設定）就第一次看到時釘選。回傳能不能上傳。
async fn hub_identity_ok(env: &Env, c: &HubClient, cfg: &mut config::AgentConfig) -> bool {
    let pinned = cfg.hub.as_ref().and_then(|h| h.fingerprint.clone());
    match c.identity().await {
        Ok(Some(id)) => match identity::check_pin(pinned.as_deref(), &id.fingerprint) {
            PinCheck::Same => true,
            PinCheck::Unpinned => {
                if let Some(h) = cfg.hub.as_mut() {
                    h.fingerprint = Some(id.fingerprint.clone());
                    h.public_key = Some(id.public_key.clone());
                }
                match config::save(&env.config_dir, cfg) {
                    Ok(()) => log(env, &tf!("已記下 Hub 指紋 {fp}", fp = id.fingerprint)),
                    Err(e) => log(env, &e.message()),
                }
                true
            }
            PinCheck::Mismatch { pinned, seen } => {
                log(env, &identity::mismatch_message(&pinned, &seen));
                log(env, t!("Hub 身分不符：停止上傳，直到重新加入"));
                false
            }
        },
        Ok(None) if pinned.is_some() => {
            log(
                env,
                t!("這個網址的 Hub 不再提供身分驗證（可能被換掉）：停止上傳，直到重新加入"),
            );
            false
        }
        Ok(None) => true,
        Err(e @ AppError::HubIdentity(_)) => {
            log(env, &e.message());
            log(env, t!("Hub 身分不符：停止上傳，直到重新加入"));
            false
        }
        // 暫時連不上：之後的上傳也會失敗、下一輪重試；不因此擋住
        Err(e) => {
            log(env, &tf!("無法確認 Hub 身分：{e}", e = e.message()));
            true
        }
    }
}

/// 先把 outbox 裡的舊報告送掉（遇到錯誤就停，等下一輪）。
/// 自動檢查情資的間隔（各清單仍依自己的更新間隔決定要不要真的下載）。
const INTEL_EVERY: Duration = Duration::from_secs(30 * 60);

/// 更新情資（有註冊就先從 hub 鏡像拿）；回傳有沒有任何清單換新（要重新載入）。
async fn refresh_intel(env: &Env, client: Option<&HubClient>, force: bool) -> bool {
    let reg = match crate::intel::registry::Registry::load(&env.config_dir) {
        Ok(r) => r,
        Err(e) => {
            log(env, &tf!("情資更新失敗：{e}", e = e.message()));
            return false;
        }
    };
    let mirror = match client {
        Some(c) => c.feed_mirror().await.ok(),
        None => None,
    };
    let opts = crate::intel::fetch::UpdateOpts {
        only: vec![],
        force,
        mirror,
    };
    match crate::intel::fetch::update(&env.config_dir, &reg, &opts, &|_| {}).await {
        Ok(outs) => {
            let updated = outs.iter().filter(|o| o.status == "updated").count();
            let failed = outs.iter().filter(|o| o.status == "error").count();
            let checked = outs.iter().filter(|o| o.status != "fresh").count();
            if checked > 0 {
                let from_hub = outs.iter().filter(|o| o.source.as_deref() == Some("hub")).count();
                log(
                    env,
                    &tf!(
                        "情資更新：檢查 {checked} 個、{updated} 個有新資料、{failed} 個失敗（{hub} 個從 Hub）",
                        checked = checked,
                        updated = updated,
                        failed = failed,
                        hub = from_hub
                    ),
                );
            }
            updated > 0
        }
        Err(e) => {
            log(env, &tf!("情資更新失敗：{e}", e = e.message()));
            false
        }
    }
}

fn intel_heartbeat(env: &Env, client: &HubClient) -> (Option<chrono::DateTime<Utc>>, Option<IntelFeedsInfo>) {
    let Ok(reg) = crate::intel::registry::Registry::load(&env.config_dir) else {
        return (None, None);
    };
    let s = crate::intel::fetch::intel_status(&env.config_dir, &reg, Some(client.base()));
    (
        s.checked_at,
        Some(IntelFeedsInfo {
            ok: s.ok,
            total: s.total,
            source: s.source.map(|x| x.to_string()),
        }),
    )
}

/// `watch` 的流量／效能取樣狀態。
struct MetricsState {
    collector: crate::metrics::Shared,
    /// Hub 太舊（沒有 metrics 端點）時，下次再試的時間。
    unsupported_until: Option<tokio::time::Instant>,
    warned_unsupported: bool,
    last_performance: Option<bool>,
}

/// 取一個流量（＋效能）樣本：存進本機最近樣本；有 Hub 就排進待送佇列並分批送出。回傳下一次的間隔。
/// 設定每輪重讀（桌面版切換「蒐集效能」不必重啟背景服務）。
async fn metrics_round(env: &Env, st: &mut MetricsState, agent_id: &str, client: Option<&HubClient>) -> Duration {
    let mc = config::load(&env.config_dir).map(|c| c.metrics).unwrap_or_default();
    let opts = crate::metrics::Options::from_config(&mc);
    if st.last_performance != Some(opts.performance) {
        log(
            env,
            if opts.performance {
                t!("效能蒐集：已開啟（CPU、記憶體、磁碟，只送到這台加入的 Hub）")
            } else {
                t!("效能蒐集：未開啟（只統計網路流量；開啟：ai-security-monitor config set metrics.performance true）")
            },
        );
        st.last_performance = Some(opts.performance);
    }
    match crate::metrics::tick(&st.collector, opts).await {
        Some(s) => {
            let _ = crate::metrics::queue::remember(&env.config_dir, &s);
            if client.is_some() {
                if let Err(e) = crate::metrics::queue::push(&env.config_dir, &s) {
                    log(env, &tf!("流量資料暫存失敗：{e}", e = e.message()));
                }
            }
        }
        None => log(env, t!("流量／效能取樣逾時，這一輪略過")),
    }
    if let Some(c) = client {
        let now = tokio::time::Instant::now();
        if st.unsupported_until.is_none_or(|t| now >= t) {
            match crate::metrics::flush(&env.config_dir, c, agent_id, opts.performance).await {
                crate::metrics::Flush::Sent { sent, left } => {
                    st.unsupported_until = None;
                    if sent > crate::metrics::BATCH || left > 0 {
                        log(
                            env,
                            &tf!("已補送 {n} 筆流量資料（還有 {left} 筆）", n = sent, left = left),
                        );
                    }
                }
                crate::metrics::Flush::Unsupported => {
                    if !st.warned_unsupported {
                        log(
                            env,
                            t!("這個 Hub 版本還不收流量／效能資料：先存在本機（最多一天），Hub 升級後自動補送"),
                        );
                        st.warned_unsupported = true;
                    }
                    st.unsupported_until = Some(now + Duration::from_secs(30 * 60));
                }
                crate::metrics::Flush::Failed(m) => {
                    log(env, &tf!("流量資料上傳失敗，稍後再試：{e}", e = m));
                }
            }
        }
    }
    crate::metrics::interval_of(&mc)
}

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
                log(
                    env,
                    t!("同一個設定目錄已經有常駐的 ai-security-monitor watch，這個不再啟動"),
                );
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
                "服務模式啟動（ai-security-monitor {v}，設定目錄 {dir}）",
                v = crate::VERSION,
                dir = env.config_dir.display()
            ),
        );
        reapply_firewall(env).await;
    }
    let mut cfg = config::load_or_init(&env.config_dir)?;
    let mut client = if a.no_upload {
        None
    } else {
        watch::client_from_config(&env.config_dir, &cfg)?
    };
    // 釘選的 Hub 身分不符就不上傳（TOFU）
    let mut pin_blocked = false;
    if let Some(c) = &client {
        if !hub_identity_ok(env, c, &mut cfg).await {
            client = None;
            pin_blocked = true;
        }
    }
    // 免金鑰加入的申請還在等核准：背景繼續問，核准後就開始上傳
    let mut next_enroll = (!a.no_upload && client.is_none() && !pin_blocked)
        .then(|| keyless::load_pending(&env.config_dir))
        .flatten()
        .map(|p| {
            log(
                env,
                &tf!(
                    "等候 Hub 管理員核准加入申請：{url}（核對碼 {code}，Hub 指紋 {fp}）",
                    url = p.hub_url,
                    code = p.request_code,
                    fp = p.hub_fingerprint
                ),
            );
            tokio::time::Instant::now()
        });
    if client.is_none() && !a.no_upload && !pin_blocked && next_enroll.is_none() {
        log(
            env,
            t!("尚未註冊 hub：只在本機掃描（ai-security-monitor enroll --auto 自動尋找公司的 Hub，或 enroll <HUB_URL> --key …）"),
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
    // --once（測試、排程）不自動更新情資，避免每次都去下載
    let mut next_intel = if a.once {
        tokio::time::Instant::now() + Duration::from_secs(365 * 86_400)
    } else {
        tokio::time::Instant::now()
    };
    let mut force_intel = false;
    let mut last_scan_at: Option<chrono::DateTime<Utc>> = None;
    // 流量／效能：建立取樣器時記下基準讀數，第一個樣本在一個間隔之後（--once 等 2 秒）
    let mut metrics = MetricsState {
        collector: tokio::task::spawn_blocking(crate::metrics::shared)
            .await
            .map_err(|e| AppError::Scan(e.to_string()))?,
        unsupported_until: None,
        warned_unsupported: false,
        last_performance: None,
    };
    let metrics_started = tokio::time::Instant::now();
    let mut next_metrics = metrics_started
        + if a.once {
            Duration::from_secs(2)
        } else {
            crate::metrics::interval_of(&cfg.metrics)
        };
    // 停止訊號（Ctrl-C／SIGTERM／服務停止）：等待與掃描中都會被打斷，服務停止不必等完整掃描跑完
    let stop = crate::service::instance::stopped();
    tokio::pin!(stop);

    loop {
        let now = tokio::time::Instant::now();
        if next_enroll.is_some_and(|t| now >= t) {
            next_enroll = match keyless::step(&env.config_dir, &mut cfg, &agent, a.service).await {
                Ok(Some(Step::Done(r))) => {
                    log(
                        env,
                        &tf!(
                            "管理員已核准：已加入 {url}（{hub} {version}），開始回報",
                            url = cfg.hub.as_ref().map(|h| h.url.as_str()).unwrap_or("?"),
                            hub = r.hub.name,
                            version = r.hub.version
                        ),
                    );
                    client = watch::client_from_config(&env.config_dir, &cfg).unwrap_or(None);
                    interval = interval.max(Duration::from_secs(r.hub.min_report_interval_s));
                    snap_every = snap_every.max(Duration::from_secs(r.hub.snapshot_interval_s.max(10)));
                    if r.action_key.is_some() && cfg.remote_actions.accept {
                        log(env, t!("遠端動作：已啟用"));
                    }
                    // 馬上送第一份快照與報告
                    next_snap = now;
                    next_scan = now;
                    None
                }
                Ok(Some(Step::Rejected(reason))) => {
                    log(
                        env,
                        &tf!(
                            "管理員拒絕了這台電腦的加入申請：{reason}",
                            reason = reason.unwrap_or_else(|| "-".into())
                        ),
                    );
                    None
                }
                Ok(Some(Step::Expired)) | Ok(None) => {
                    log(
                        env,
                        t!("加入申請已過期或被刪除：請重新執行 ai-security-monitor enroll --auto"),
                    );
                    None
                }
                Ok(Some(Step::Waiting(st))) => Some(now + keyless::poll_delay(None, Some(&st))),
                Err(e) if matches!(e, AppError::HubIdentity(_)) => {
                    log(env, &e.message());
                    None
                }
                Err(e) => {
                    log(env, &tf!("查詢核准狀態失敗，稍後重試：{e}", e = e.message()));
                    Some(now + Duration::from_secs(60))
                }
            };
        }
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
                        let (intel_checked_at, intel_feeds) = intel_heartbeat(env, c);
                        let hb = HeartbeatPayload {
                            agent_id: cfg.agent_id.clone(),
                            ts: Utc::now(),
                            version: crate::VERSION.to_string(),
                            uptime_s: agent.uptime_s,
                            last_scan_at,
                            elevated: crate::elevate::is_elevated(),
                            intel_checked_at,
                            intel_feeds,
                        };
                        match c.heartbeat(&hb).await {
                            Ok(v) => {
                                let commands = v["commands"].as_array().cloned().unwrap_or_default();
                                if commands.iter().any(|x| x == "refresh_feeds") && !force_intel {
                                    log(env, t!("Hub 要求立即更新情資"));
                                    force_intel = true;
                                }
                                if v["pending_actions"].as_u64().unwrap_or(0) > 0 {
                                    run_remote_actions(env, c, &cfg).await;
                                }
                            }
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
        if force_intel || tokio::time::Instant::now() >= next_intel {
            let force = std::mem::take(&mut force_intel);
            if refresh_intel(env, client.as_ref(), force).await {
                intel = watch::load_intel(&env.config_dir).await;
                intel_loaded = std::time::Instant::now();
            }
            next_intel = tokio::time::Instant::now() + INTEL_EVERY;
        }
        if now >= next_scan {
            if let Some(c) = &client {
                flush_outbox(env, c).await;
            }
            let all_scanners = ScanArgs::default().scanners;
            let scanned = tokio::select! {
                r = super::scan_cmd::run_scan(env, &all_scanners, false) => Some(r),
                _ = &mut stop => None,
            };
            let Some(scanned) = scanned else {
                log(env, t!("收到停止訊號，結束"));
                break;
            };
            match scanned {
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
        if a.once {
            // 跑一次也送一個流量樣本（離開取樣器建立至少 2 秒）
            tokio::time::sleep_until(next_metrics).await;
        }
        if tokio::time::Instant::now() >= next_metrics {
            let every = metrics_round(env, &mut metrics, &cfg.agent_id, client.as_ref()).await;
            next_metrics = tokio::time::Instant::now() + every;
        }
        if a.once || crate::service::instance::stop_requested() {
            break;
        }
        let mut wake = next_scan.min(next_snap).min(next_intel).min(next_metrics);
        if let Some(t) = next_enroll {
            wake = wake.min(t);
        }
        tokio::select! {
            _ = tokio::time::sleep_until(wake) => {}
            _ = &mut stop => {
                log(env, t!("收到停止訊號，結束"));
                break;
            }
        }
    }
    Ok(())
}
