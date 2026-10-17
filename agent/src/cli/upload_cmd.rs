//! `ai-security-monitor upload`：立即掃描並上傳到 Hub——跟背景服務的一輪一樣：先補送暫存（outbox）的報告、
//! 上傳連線快照、跑完整掃描並上傳報告、送心跳。上傳失敗的報告照樣暫存，之後由背景服務重送。
//! 桌面版的「立即掃描並上傳到 Hub」也呼叫 [`upload_now`]。

use serde::Serialize;

use super::args::ScanArgs;
use super::hub_cmd::{flush_outbox, heartbeat_payload, hub_identity_ok, OutboxFlush};
use super::render::print_json;
use super::Env;
use crate::config;
use crate::error::{AppError, AppResult};
use crate::hub::{outbox, watch};

#[derive(Debug, Clone, Default, Serialize)]
pub struct SnapshotSent {
    pub connections: usize,
    /// 可疑＋危險。
    pub flagged: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSent {
    pub report_id: String,
    /// 這份報告的發現數（Hub 收到幾筆）。
    pub findings: usize,
    pub score: u8,
    /// Hub 的比對結果：新出現、已解決。
    pub new: u64,
    pub resolved: u64,
    /// 沒送成功、已暫存（之後自動重送）。
    pub queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UploadSummary {
    pub ok: bool,
    pub hub: String,
    pub outbox: OutboxFlush,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotSent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ReportSent>,
    pub heartbeat: bool,
    /// 還在 outbox 等重送的報告數。
    pub pending: usize,
}

/// 進度回報（CLI 印到 stderr；桌面版送到視窗）。
pub type Progress<'a> = &'a (dyn Fn(&str) + Send + Sync);

/// 立即上傳一輪。沒加入 Hub、或 Hub 身分和這台記得的不同時回錯誤。
pub async fn upload_now(env: &Env, progress: Progress<'_>) -> AppResult<UploadSummary> {
    let dir = &env.config_dir;
    let mut cfg = config::load_or_init(dir)?;
    let client = watch::client_from_config(dir, &cfg)?.ok_or_else(|| {
        AppError::Hub(
            t!("這台電腦還沒加入 Hub：先申請加入（桌面版「加入公司 Hub」，或 ai-security-monitor enroll --auto）")
                .into(),
        )
    })?;
    progress(t!("確認 Hub 身分…"));
    if !hub_identity_ok(env, &client, &mut cfg).await {
        return Err(AppError::HubIdentity(
            t!("Hub 的身分和這台電腦記得的不同，已停止上傳（確認過指紋後重新加入：ai-security-monitor enroll --auto --repin）")
                .into(),
        ));
    }
    let mut sum = UploadSummary {
        hub: client.base().to_string(),
        ..Default::default()
    };

    if !outbox::list(dir).is_empty() {
        progress(t!("補送之前沒送出的報告…"));
    }
    sum.outbox = flush_outbox(env, &client).await;

    progress(t!("拍連線快照並上傳…"));
    let intel = watch::load_intel(dir).await;
    match watch::snapshot(dir, &cfg.agent_id, intel).await {
        Ok(s) => {
            let mut sent = SnapshotSent {
                connections: s.connections.len(),
                flagged: s.connections.iter().filter(|c| c.verdict.is_bad()).count(),
                error: None,
            };
            match client.upload_snapshot(&s).await {
                Ok(_) => watch::record_upload(dir, client.base(), watch::Uploaded::Snapshot),
                Err(e) => sent.error = Some(e.message()),
            }
            sum.snapshot = Some(sent);
        }
        Err(e) => {
            sum.snapshot = Some(SnapshotSent {
                error: Some(e.message()),
                ..Default::default()
            })
        }
    }

    progress(t!("完整掃描中（約 10–60 秒）…"));
    let scanners = ScanArgs::default().scanners;
    let (report, _) = super::scan_cmd::run_scan(env, &scanners, false).await?;
    let _ = watch::save_latest(dir, &report);
    progress(t!("上傳掃描報告…"));
    let mut sent = ReportSent {
        report_id: report.report_id.clone(),
        findings: report.findings.len(),
        score: report.score.overall,
        ..Default::default()
    };
    match client.upload_report(&report).await {
        Ok(v) => {
            sent.new = v["findings"]["new"].as_u64().unwrap_or(0);
            sent.resolved = v["findings"]["resolved"].as_u64().unwrap_or(0);
            watch::record_upload(dir, client.base(), watch::Uploaded::Report(&report.report_id));
        }
        Err(e @ AppError::HubRejected(_)) => sent.error = Some(e.message()),
        Err(e) => {
            let _ = outbox::push(dir, &report);
            watch::record_upload(dir, client.base(), watch::Uploaded::Failed(&e.message()));
            sent.queued = true;
            sent.error = Some(e.message());
        }
    }
    sum.ok = sent.error.is_none();
    sum.report = Some(sent);

    let hb = heartbeat_payload(env, &cfg, &client, None, Some(report.finished_at), None);
    if client.heartbeat(&hb).await.is_ok() {
        watch::record_upload(dir, client.base(), watch::Uploaded::Heartbeat);
        sum.heartbeat = true;
    }
    sum.pending = outbox::list(dir).len();
    Ok(sum)
}

/// 給人看的一行結果。
pub fn summary_line(s: &UploadSummary) -> String {
    let Some(r) = &s.report else {
        return t!("沒有上傳任何東西").to_string();
    };
    if let Some(e) = &r.error {
        return if r.queued {
            tf!("上傳失敗，報告已暫存，之後會自動重送：{e}", e = e)
        } else {
            tf!("Hub 拒收這份報告：{e}", e = e)
        };
    }
    let mut line = tf!(
        "已上傳，Hub 收到 {n} 筆（新 {new}、解決 {resolved}，總分 {score}）",
        n = r.findings,
        new = r.new,
        resolved = r.resolved,
        score = r.score
    );
    if let Some(sn) = &s.snapshot {
        line.push_str(&match &sn.error {
            None => tf!("；連線快照 {n} 條", n = sn.connections),
            Some(e) => tf!("；連線快照沒送出（{e}）", e = e),
        });
    }
    if s.outbox.sent > 0 {
        line.push_str(&tf!("；補送暫存報告 {n} 份", n = s.outbox.sent));
    }
    if s.pending > 0 {
        line.push_str(&tf!("；還有 {n} 份等重送", n = s.pending));
    }
    line
}

pub async fn run(env: &Env) -> AppResult<()> {
    let quiet = env.global.quiet || env.global.json;
    let progress = move |m: &str| {
        if !quiet {
            eprintln!("· {m}");
        }
    };
    let s = upload_now(env, &progress).await?;
    if env.global.json {
        print_json(&s);
    } else {
        println!("{}", summary_line(&s));
    }
    if s.ok {
        Ok(())
    } else {
        Err(AppError::Hub(
            s.report.and_then(|r| r.error).unwrap_or_else(|| t!("上傳失敗").into()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_lines() {
        let mut s = UploadSummary {
            ok: true,
            hub: "http://hub".into(),
            report: Some(ReportSent {
                report_id: "r".into(),
                findings: 7,
                score: 81,
                new: 2,
                resolved: 1,
                ..Default::default()
            }),
            snapshot: Some(SnapshotSent {
                connections: 40,
                ..Default::default()
            }),
            ..Default::default()
        };
        s.outbox.sent = 2;
        let l = summary_line(&s);
        assert!(
            l.contains("Hub 收到 7 筆") && l.contains("快照 40") && l.contains("補送暫存報告 2"),
            "{l}"
        );
        s.report.as_mut().unwrap().error = Some("連不上 hub".into());
        s.report.as_mut().unwrap().queued = true;
        assert!(summary_line(&s).contains("已暫存"));
    }

    #[test]
    fn not_enrolled_is_a_clear_error() {
        let d = tempfile::tempdir().unwrap();
        let env = Env {
            global: Default::default(),
            config_dir: d.path().to_path_buf(),
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let e = rt.block_on(upload_now(&env, &|_| {})).unwrap_err();
        assert!(e.message().contains("還沒加入 Hub"), "{}", e.message());
    }
}
