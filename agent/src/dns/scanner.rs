//! `dns` 掃描器：讀最近 [`WINDOW`] 的 DNS 紀錄跑 [`super::rules`]，產生問題與摘要。
//! 情資沿用 intel 掃描器已載入的（掃描共用區），沒有才自己載。

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

use super::{rules, store, tamper};
use crate::connections::KnownGood;
use crate::error::{AppError, AppResult};
use crate::intel::registry::Registry;
use crate::intel::IntelDb;
use crate::model::finding::ScannerId;
use crate::scan::{ScanCtx, ScanOutput, Scanner};

/// 每次掃描看最近多久（比預設掃描間隔 10 分鐘長一點；重疊的部分問題 id 相同，Hub 不會重複）。
pub const WINDOW: chrono::TimeDelta = chrono::TimeDelta::minutes(15);
/// 一次最多讀幾列。
const MAX_RECORDS: usize = 200_000;

pub struct DnsScanner;

#[async_trait]
impl Scanner for DnsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Dns
    }

    fn depends_on(&self) -> &'static [ScannerId] {
        &[ScannerId::Intel]
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        if !ctx.config.dns.enabled {
            return Ok(ScanOutput {
                summary: Some(json!({ "enabled": false })),
                ..Default::default()
            });
        }
        let explicit = crate::util::env::var(crate::config::ENV_CONFIG_DIR).is_some();
        let (dir, _) = store::pick_dir(&ctx.config_dir, explicit);
        let since = Utc::now() - WINDOW;
        let d2 = dir.clone();
        let recs = tokio::task::spawn_blocking(move || store::read_since(&d2, since, MAX_RECORDS))
            .await
            .map_err(|e| AppError::Scan(e.to_string()))?;
        let status = store::read_status(&dir);
        let mut warnings = Vec::new();
        if status.as_ref().is_none_or(|s| !s.running) {
            warnings.push(t!("背景 DNS 蒐集沒有在跑（ai-security-monitor dns status 看原因）").to_string());
        }
        let shared = ctx.shared.lock().await.intel.clone();
        let intel: Option<Arc<IntelDb>> = match shared {
            Some(s) => Some(s.0),
            None if !recs.is_empty() => {
                let reg = Registry::load(&ctx.config_dir)?;
                let d = ctx.config_dir.clone();
                tokio::task::spawn_blocking(move || IntelDb::load(&d, &reg))
                    .await
                    .ok()
                    .map(Arc::new)
            }
            None => None,
        };
        let kg = KnownGood::load();
        let allow = &ctx.allowlist;
        let trusted = |d: &str| allow.match_domain(d).is_some() || kg.match_domain(d).is_some();
        let mut findings = rules::detect(&recs, intel.as_deref(), &trusted);
        findings.extend(rules::blocklisted(
            &recs,
            &super::blocklist::Matcher::load(&ctx.config_dir),
        ));
        findings.extend(
            tamper::check(
                &ctx.config_dir,
                tamper::Inputs {
                    records: &recs,
                    intel: intel.as_deref(),
                    kg: &kg,
                    verify_answers: ctx.config.dns.verify_answers,
                },
            )
            .await,
        );
        let mut summary = rules::summary(&recs);
        summary["window_s"] = json!(WINDOW.num_seconds());
        summary["collector"] = json!(status);
        Ok(ScanOutput {
            findings,
            warnings,
            summary: Some(summary),
        })
    }
}
