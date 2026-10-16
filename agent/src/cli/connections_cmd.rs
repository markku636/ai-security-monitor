//! `asa connections`：列出連線（方向／判定／行程／原因），可 `--watch` 持續刷新。

use std::time::Duration;

use super::args::ConnectionsArgs;
use super::render::{print_json, table};
use super::Env;
use crate::connections::{beacon, history, Classifier};
use crate::error::AppResult;
use crate::model::allowlist::Allowlist;
use crate::model::baseline::Baseline;
use crate::model::connection::{Connection, Direction};
use crate::model::verdict::{Reason, VerdictLevel};
use crate::util::text::clip;

fn reason_summary(c: &Connection) -> String {
    let mut parts: Vec<String> = Vec::new();
    for r in &c.verdict.reasons {
        match r {
            Reason::IntelHit(h) => parts.push(format!("{}:{}", h.vendor, h.name)),
            Reason::Anomaly { kind, detail } => parts.push(format!(
                "{kind:?}{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!("({})", clip(detail, 24))
                }
            )),
            Reason::Reputation { provider, score, .. } => parts.push(format!("{provider}={score}")),
            Reason::KnownGood { list, .. } => parts.push(format!("known-good:{list}")),
            Reason::Allowlisted { entry_id } => parts.push(format!("allowlist:{entry_id}")),
            Reason::PrivateNetwork => parts.push("private".into()),
            Reason::Loopback => parts.push("loopback".into()),
        }
    }
    clip(&parts.join("; "), 60)
}

fn passes(c: &Connection, a: &ConnectionsArgs) -> bool {
    if let Some(d) = a.direction {
        if c.direction != d {
            return false;
        }
    }
    if !a.verdict.is_empty() && !a.verdict.contains(&c.verdict.level) {
        return false;
    }
    if !a.all {
        // 預設隱藏本機對本機與 loopback listener，這些幾乎永遠是噪音。
        if c.direction == Direction::Local || c.state == "TIME_WAIT" || c.state == "CLOSE_WAIT" {
            return false;
        }
        if c.direction == Direction::Listening && c.verdict.level == VerdictLevel::Safe {
            return false;
        }
    }
    true
}

fn render(conns: &[Connection], a: &ConnectionsArgs) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut sorted: Vec<&Connection> = conns.iter().filter(|c| passes(c, a)).collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.verdict.level));
    for c in sorted {
        rows.push(vec![
            c.direction.label().to_string(),
            c.verdict.level.label().to_string(),
            c.proto.clone(),
            format!("{}:{}", c.local_ip, c.local_port),
            match c.geo.as_ref().and_then(|g| g.country.clone()) {
                Some(cc) => format!("{} [{cc}]", c.remote_display()),
                None => c.remote_display(),
            },
            c.state.clone(),
            c.process
                .as_ref()
                .map(|p| format!("{} ({})", p.name, p.pid))
                .unwrap_or_else(|| "-".into()),
            reason_summary(c),
        ]);
    }
    let n = rows.len();
    let t = table(
        &[
            t!("方向"),
            t!("判定"),
            t!("協定"),
            t!("本機位址"),
            t!("遠端"),
            t!("狀態"),
            t!("行程"),
            t!("原因"),
        ],
        rows,
    );
    format!(
        "{t}\n{}",
        tf!("共 {n} 筆（{total} 筆原始 socket）", n = n, total = conns.len())
    )
}

async fn one_shot(env: &Env, a: &ConnectionsArgs) -> AppResult<Vec<Connection>> {
    let with_intel = a.intel;
    let dir = env.config_dir.clone();
    let allowlist = Allowlist::load(&dir)?;
    let baseline = Baseline::load(&dir)?;
    tokio::task::spawn_blocking(move || -> AppResult<Vec<Connection>> {
        let mut snap = crate::connections::take(&dir)?;
        let now = crate::util::time::now().timestamp() as u64;
        history::append(&dir, now, &history::pairs_of(&snap.connections))?;
        let hist = history::load(&dir, now.saturating_sub(history::RETENTION_SECS))?;
        let beacons = beacon::detect(&hist, now);
        let cl = Classifier::load();
        cl.annotate(&mut snap, &allowlist, baseline.as_ref(), &beacons);
        if with_intel {
            let reg = crate::intel::registry::Registry::load(&dir)?;
            let db = crate::intel::IntelDb::load(&dir, &reg);
            crate::intel::enrich_connections(&db, &mut snap.connections);
        }
        Ok(snap.connections)
    })
    .await
    .map_err(|e| crate::error::AppError::Scan(e.to_string()))?
}

pub async fn run(env: &Env, a: ConnectionsArgs) -> AppResult<()> {
    if !a.watch {
        let conns = one_shot(env, &a).await?;
        if env.global.json {
            let filtered: Vec<&Connection> = conns.iter().filter(|c| passes(c, &a)).collect();
            print_json(&filtered);
        } else {
            println!("{}", render(&conns, &a));
        }
        return Ok(());
    }
    let interval = crate::util::time::parse_duration(&a.interval)?.max(Duration::from_secs(1));
    loop {
        let conns = one_shot(env, &a).await?;
        if env.global.json {
            let filtered: Vec<&Connection> = conns.iter().filter(|c| passes(c, &a)).collect();
            println!(
                "{}",
                serde_json::to_string(
                    &serde_json::json!({ "ts": crate::util::time::now_iso(), "connections": filtered })
                )?
            );
        } else {
            println!("\n=== {} ===", crate::util::time::now_iso());
            println!("{}", render(&conns, &a));
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => { break; }
        }
    }
    Ok(())
}
