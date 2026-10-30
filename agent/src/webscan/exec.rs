//! 執行一個工作：
//! 1. 解析與檢查（[`job::parse`]）：不合（`bad_job:…`）或範圍不過（`blocked_target:…`）→ 直接回報失敗，不送心跳、不呼叫任何工具。
//! 2. 開始前送一次心跳，之後每 max(10 秒, lease_ms/3) 送一次；`cancel:true` 或 409（工作已不屬於這台）→ 立刻中止（殺掉正在跑的工具）。
//! 3. 掃描：一個工作一個暫存目錄＋釘選解析器，逐步跑工具（每步逾時＝min(離截止的時間, limits.timeout_ms)），
//!    每步上傳原始輸出（超過 16 KB 就 gzip，壓縮後上限 8 MiB）。
//! 4. 回報結果；暫存目錄刪掉、解析器關掉。

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::sync::watch;

use super::caps::Tools;
use super::job::{self, Job, JobKind};
use super::resolver::PinnedResolver;
use super::tools::{self, Artifact, JobFiles, StepEnv};
use super::{clean_detail, log, Capability, Heartbeat, HeartbeatReply, JobResult, Scanner, StepResult};
use crate::error::AppError;
use crate::hub::webscan::{ArtifactMeta, MAX_ARTIFACT_BYTES};
use crate::hub::HubClient;
use crate::util::cmd::CmdRunner;

/// 超過這個大小的 artifact 就 gzip（跟 Hub 客戶端一樣）。
const GZIP_OVER: usize = 16 * 1024;
/// 剩下的時間不到這麼多就不開始下一步。
const MIN_STEP_MS: u64 = 1_000;
/// 心跳一直失敗多久就當作租約已經過期（至少這麼久，否則照 lease_ms）。
const MIN_LEASE: Duration = Duration::from_secs(30);
const RESULT_ATTEMPTS: u32 = 4;
const ARTIFACT_ATTEMPTS: u32 = 3;
/// 每個工作的暫存目錄名稱開頭（啟動時清掉舊的）。
pub const JOB_DIR_PREFIX: &str = "job-";
/// 留下來的暫存目錄多舊才清（最長的工作是 3 小時）。
pub const STALE_AFTER: Duration = Duration::from_secs(6 * 3600);

/// 執行工作需要的東西（主迴圈建一份、所有工作共用）。
pub struct Ctx {
    pub client: Arc<HubClient>,
    pub runner: Arc<dyn CmdRunner>,
    pub tools: Tools,
    /// 啟動時偵測到的工具（沒有的步驟回報 `not_installed`）。
    pub caps: Vec<Capability>,
    /// 每個工作的暫存目錄放在這底下。
    pub work_dir: PathBuf,
    /// 心跳的最短間隔（10 秒；測試縮短）。
    pub heartbeat_min: Duration,
    /// 是否省略一般進度訊息。
    pub quiet: bool,
}

impl Ctx {
    fn installed(&self, s: Scanner) -> bool {
        self.caps.iter().any(|c| c.scanner == s)
    }
}

/// 工作被中止的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// Hub 在心跳回應裡要求取消。
    Cancelled,
    /// 工作已經不屬於這台（409／404／410，或心跳一直送不到、租約過期）。
    LeaseLost,
    /// runner 要結束（Ctrl+C、服務停止）。
    RunnerStopped,
    /// Hub 拒絕權杖。
    HubAuth,
}

impl Abort {
    pub fn code(self) -> &'static str {
        match self {
            Abort::Cancelled => "cancelled",
            Abort::LeaseLost => "lease_lost",
            Abort::RunnerStopped => "runner_stopped",
            Abort::HubAuth => "hub_auth",
        }
    }
}

/// 一個工作的結局。
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 結果已經交給 Hub。
    Reported { ok: bool, error: Option<String> },
    /// 沒有回報（工作已經不屬於這台、Hub 連不上、id 不合法…）。
    NotReported(String),
    /// Hub 拒絕權杖：主迴圈要結束。
    AuthRejected,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    pub id: Option<String>,
    pub outcome: Outcome,
}

enum Run {
    Done(JobResult),
    Aborted(Abort, Vec<StepResult>),
}

fn set_abort(tx: &watch::Sender<Option<Abort>>, a: Abort) {
    // 第一個原因為準
    tx.send_if_modified(|v| {
        if v.is_none() {
            *v = Some(a);
            true
        } else {
            false
        }
    });
}

async fn wait_abort(rx: &mut watch::Receiver<Option<Abort>>) -> Abort {
    loop {
        if let Some(a) = *rx.borrow_and_update() {
            return a;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn elapsed_ms(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// 離截止還有幾毫秒（`clock`＝Hub 時間 − 本機時間，claim 回應的 server_time 算的）。
fn remaining_ms(deadline: DateTime<Utc>, clock: chrono::Duration) -> u64 {
    let now = Utc::now() + clock;
    u64::try_from((deadline - now).num_milliseconds()).unwrap_or(0)
}

fn set_progress(p: &Mutex<Heartbeat>, scanner: Scanner, done: usize, total: usize) {
    if let Ok(mut h) = p.lock() {
        h.step = Some(scanner);
        h.message = Some(format!("{scanner} {done}/{total}"));
        h.progress = Some(if total == 0 { 0.0 } else { done as f64 / total as f64 });
    }
}

enum Beat {
    Ok,
    Abort(Abort),
    Failed,
}

async fn beat(ctx: &Ctx, id: &str, progress: &Mutex<Heartbeat>) -> Beat {
    let hb = progress.lock().map(|p| p.clone()).unwrap_or_default();
    match ctx.client.webscan_heartbeat(id, &hb).await {
        Ok(Some(v)) => {
            let reply: HeartbeatReply = serde_json::from_value(v).unwrap_or_default();
            if reply.cancel {
                Beat::Abort(Abort::Cancelled)
            } else {
                Beat::Ok
            }
        }
        Ok(None) => Beat::Abort(Abort::LeaseLost),
        Err(AppError::HubAuth) => Beat::Abort(Abort::HubAuth),
        Err(_) => Beat::Failed,
    }
}

async fn heartbeat_loop(
    ctx: Arc<Ctx>,
    id: String,
    progress: Arc<Mutex<Heartbeat>>,
    abort: watch::Sender<Option<Abort>>,
    every: Duration,
    lease: Duration,
) {
    let mut last_ok = Instant::now();
    loop {
        tokio::time::sleep(every).await;
        match beat(&ctx, &id, &progress).await {
            Beat::Ok => last_ok = Instant::now(),
            Beat::Abort(a) => {
                set_abort(&abort, a);
                return;
            }
            Beat::Failed => {
                if last_ok.elapsed() > lease {
                    set_abort(&abort, Abort::LeaseLost);
                    return;
                }
            }
        }
    }
}

/// 建這個工作的暫存目錄（只有這個使用者讀得到）。
fn create_job_dir(base: &Path, id: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(base)?;
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let dir = base.join(format!("{JOB_DIR_PREFIX}{id}-{}", &suffix[..8]));
    std::fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// 工作結束（含中止、panic）時刪掉暫存目錄。
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 清掉上次沒收乾淨的暫存目錄（`job-` 開頭、超過 `older_than`）。
pub fn cleanup_stale(base: &Path, older_than: Duration) {
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    for e in rd.flatten() {
        if !e.file_name().to_string_lossy().starts_with(JOB_DIR_PREFIX) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > older_than);
        if old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn gzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes)?;
    enc.finish()
}

/// artifact 的 body：超過 16 KB 就 gzip；壓縮後還超過 8 MiB 就從後面砍（照比例、留一成餘裕；`lines` 時切在換行）。
/// 回（body, 有沒有 gzip, 有沒有截斷）。
pub fn encode_artifact(raw: &[u8], truncated: bool, lines: bool) -> std::io::Result<(Vec<u8>, bool, bool)> {
    if raw.len() <= GZIP_OVER {
        return Ok((raw.to_vec(), false, truncated));
    }
    let mut cut = raw.len();
    let mut truncated = truncated;
    loop {
        let gz = gzip(&raw[..cut])?;
        if gz.len() <= MAX_ARTIFACT_BYTES {
            return Ok((gz, true, truncated));
        }
        let target = (cut as u128 * MAX_ARTIFACT_BYTES as u128 * 9 / 10 / gz.len() as u128) as usize;
        let mut next = target.min(cut.saturating_sub(1));
        if lines {
            next = raw[..next].iter().rposition(|&c| c == b'\n').map_or(0, |p| p + 1);
        }
        cut = next;
        truncated = true;
        if cut == 0 {
            return Ok((gzip(&[])?, true, true));
        }
    }
}

enum Upload {
    Done,
    Gone,
    Auth,
    Failed(String),
}

async fn upload(
    ctx: &Ctx,
    id: &str,
    scanner: Scanner,
    art: &Artifact,
    exit_code: Option<i32>,
    duration_ms: u64,
) -> Upload {
    let Ok((body, gzipped, truncated)) = encode_artifact(&art.bytes, art.truncated, art.format == "jsonl") else {
        return Upload::Failed("encode".into());
    };
    let meta = ArtifactMeta {
        scanner: scanner.id(),
        format: art.format,
        exit_code,
        duration_ms,
        truncated,
    };
    let mut wait = Duration::from_secs(1);
    for attempt in 0..ARTIFACT_ATTEMPTS {
        match ctx.client.webscan_artifact(id, &meta, body.clone(), gzipped).await {
            Ok(true) => return Upload::Done,
            Ok(false) => return Upload::Gone,
            Err(AppError::HubAuth) => return Upload::Auth,
            Err(AppError::HubRejected(m)) => return Upload::Failed(format!("rejected:{}", clean_detail(&m, 80))),
            Err(AppError::HubThrottled { retry_after_s }) => {
                wait = Duration::from_secs(retry_after_s.unwrap_or(5).clamp(1, 30));
            }
            Err(_) => {}
        }
        if attempt + 1 < ARTIFACT_ATTEMPTS {
            tokio::time::sleep(wait).await;
            wait = (wait * 3).min(Duration::from_secs(30));
        }
    }
    Upload::Failed("hub_unreachable".into())
}

/// 送出結果（暫時的錯誤重試幾次）。
async fn report(ctx: &Ctx, id: &str, res: &JobResult) -> Outcome {
    let mut wait = Duration::from_secs(1);
    for attempt in 0..RESULT_ATTEMPTS {
        match ctx.client.webscan_result(id, res).await {
            Ok(true) => {
                return Outcome::Reported {
                    ok: res.ok,
                    error: res.error.clone(),
                }
            }
            Ok(false) => return Outcome::NotReported("lease_lost".into()),
            Err(AppError::HubAuth) => return Outcome::AuthRejected,
            Err(AppError::HubRejected(m)) => return Outcome::NotReported(format!("rejected: {m}")),
            Err(AppError::HubThrottled { retry_after_s }) => {
                wait = Duration::from_secs(retry_after_s.unwrap_or(5).clamp(1, 30));
            }
            Err(_) => {}
        }
        if attempt + 1 < RESULT_ATTEMPTS {
            tokio::time::sleep(wait).await;
            wait = (wait * 3).min(Duration::from_secs(30));
        }
    }
    Outcome::NotReported("hub_unreachable".into())
}

async fn finish(ctx: &Ctx, id: String, res: JobResult) -> Finished {
    let outcome = report(ctx, &id, &res).await;
    match &outcome {
        Outcome::Reported { ok: true, .. } => log(ctx.quiet, &tf!("工作 {id} 完成並已回報", id = id)),
        Outcome::Reported { error, .. } => log(
            ctx.quiet,
            &tf!(
                "工作 {id} 失敗並已回報：{error}",
                id = id,
                error = error.as_deref().unwrap_or("-")
            ),
        ),
        Outcome::NotReported(why) => log(false, &tf!("工作 {id} 的結果沒有送出：{why}", id = id, why = why)),
        Outcome::AuthRejected => log(false, &tf!("工作 {id}：Hub 拒絕了網站掃描權杖", id = id)),
    }
    Finished { id: Some(id), outcome }
}

/// 執行一個 Hub 給的工作（原始 JSON）直到回報完。`self_ips`＝這台自己的位址；`clock`＝Hub 時間 − 本機時間；
/// `stop` 變成 true 時中止（殺掉工具、回報 `runner_stopped`）。
pub async fn execute(
    ctx: Arc<Ctx>,
    raw: Value,
    self_ips: Vec<IpAddr>,
    clock: chrono::Duration,
    stop: watch::Receiver<bool>,
) -> Finished {
    let Some(id) = job::job_id(&raw) else {
        log(false, t!("Hub 給的工作沒有合法的 id，略過"));
        return Finished {
            id: None,
            outcome: Outcome::NotReported("bad_id".into()),
        };
    };
    let job = match job::parse(raw, &self_ips) {
        Ok(j) => j,
        Err(rej) => {
            let code = rej.code();
            log(false, &tf!("工作 {id} 不執行：{reason}", id = id, reason = code));
            return finish(&ctx, id, JobResult::failed(code)).await;
        }
    };
    log(
        ctx.quiet,
        &tf!(
            "開始工作 {id}：{kind} {url}",
            id = job.id,
            kind = match job.kind {
                JobKind::Scan => "scan",
                JobKind::Verify => "verify",
            },
            url = job.target.url()
        ),
    );
    if *stop.borrow() {
        return finish(&ctx, job.id.clone(), JobResult::failed(Abort::RunnerStopped.code())).await;
    }

    let (abort_tx, abort_rx) = watch::channel(None::<Abort>);
    let first = match (job.kind, job.steps.first()) {
        (JobKind::Scan, Some(s)) => Heartbeat {
            step: Some(s.scanner()),
            message: Some(format!("{} 0/{}", s.scanner(), job.steps.len())),
            progress: Some(0.0),
        },
        _ => Heartbeat {
            step: None,
            message: Some("verify".into()),
            progress: Some(0.0),
        },
    };
    let progress = Arc::new(Mutex::new(first));
    // 開始前先送一次心跳：Hub 可以馬上取消
    if let Beat::Abort(a) = beat(&ctx, &job.id, &progress).await {
        set_abort(&abort_tx, a);
    }
    let every = ctx.heartbeat_min.max(job.lease / 3);
    let hb = tokio::spawn(heartbeat_loop(
        ctx.clone(),
        job.id.clone(),
        progress.clone(),
        abort_tx.clone(),
        every,
        job.lease.max(MIN_LEASE),
    ));
    let stop_fwd = {
        let tx = abort_tx.clone();
        let mut stop = stop.clone();
        tokio::spawn(async move {
            if stop.wait_for(|s| *s).await.is_ok() {
                set_abort(&tx, Abort::RunnerStopped);
            }
        })
    };

    let initial = *abort_rx.borrow();
    let run = match (initial, job.kind) {
        (Some(a), _) => Run::Aborted(a, Vec::new()),
        (None, JobKind::Scan) => run_scan(&ctx, &job, &progress, abort_rx.clone(), clock).await,
        (None, JobKind::Verify) => Run::Done(JobResult::failed("bad_job:verification_removed")),
    };
    hb.abort();
    stop_fwd.abort();

    match run {
        Run::Done(res) => finish(&ctx, job.id, res).await,
        Run::Aborted(a @ (Abort::Cancelled | Abort::RunnerStopped), steps) => {
            let res = JobResult {
                ok: false,
                error: Some(a.code().to_string()),
                steps,
                verify: None,
            };
            finish(&ctx, job.id, res).await
        }
        Run::Aborted(Abort::LeaseLost, _) => {
            log(false, &tf!("工作 {id} 已經不屬於這台，停止", id = job.id));
            Finished {
                id: Some(job.id),
                outcome: Outcome::NotReported("lease_lost".into()),
            }
        }
        Run::Aborted(Abort::HubAuth, _) => {
            log(false, &tf!("工作 {id}：Hub 拒絕了網站掃描權杖", id = job.id));
            Finished {
                id: Some(job.id),
                outcome: Outcome::AuthRejected,
            }
        }
    }
}

async fn run_scan(
    ctx: &Ctx,
    job: &Job,
    progress: &Mutex<Heartbeat>,
    mut abort: watch::Receiver<Option<Abort>>,
    clock: chrono::Duration,
) -> Run {
    let dir = match create_job_dir(&ctx.work_dir, &job.id) {
        Ok(d) => d,
        Err(e) => {
            log(
                false,
                &tf!(
                    "工作 {id}：建不了暫存目錄 {path}：{e}",
                    id = job.id,
                    path = ctx.work_dir.display(),
                    e = e
                ),
            );
            return Run::Done(JobResult::failed("work_dir_unavailable"));
        }
    };
    let _cleanup = RemoveOnDrop(dir.clone());
    let files = JobFiles::in_dir(&dir);
    let resolver = match PinnedResolver::start(&job.target.names, &job.target.pinned).await {
        Ok(r) => r,
        Err(_) => return Run::Done(JobResult::failed("resolver_unavailable")),
    };
    if let Err(e) = files.write(&job.target, resolver.addr(), &ctx.tools.templates) {
        log(
            false,
            &tf!(
                "工作 {id}：建不了暫存目錄 {path}：{e}",
                id = job.id,
                path = dir.display(),
                e = e
            ),
        );
        return Run::Done(JobResult::failed("work_dir_unavailable"));
    }
    let total = job.steps.len();
    let mut results: Vec<StepResult> = Vec::with_capacity(total);
    for (i, step) in job.steps.iter().enumerate() {
        if let Some(a) = *abort.borrow() {
            return Run::Aborted(a, results);
        }
        let scanner = step.scanner();
        set_progress(progress, scanner, i, total);
        if !ctx.installed(scanner) {
            results.push(StepResult::failed(scanner, "not_installed"));
            continue;
        }
        let remaining = remaining_ms(job.deadline, clock);
        if remaining < MIN_STEP_MS {
            results.push(StepResult::failed(scanner, "deadline_exceeded"));
            continue;
        }
        let env = StepEnv {
            program: ctx.tools.program(scanner),
            target: &job.target,
            limits: &job.limits,
            files: &files,
            resolver: resolver.addr(),
            templates: &ctx.tools.templates,
            timeout_ms: remaining.min(job.limits.timeout_ms),
        };
        let spec = tools::spec(step, &env);
        let started = Instant::now();
        let out = tokio::select! {
            out = ctx.runner.run_bounded(&spec) => out,
            a = wait_abort(&mut abort) => {
                // 丟掉執行中的 future＝殺掉整棵子行程
                let mut r = StepResult::failed(scanner, a.code());
                r.duration_ms = elapsed_ms(started);
                results.push(r);
                return Run::Aborted(a, results);
            }
        };
        let duration_ms = elapsed_ms(started);
        if let Err(e) = &out {
            log(
                false,
                &tf!(
                    "工作 {id}：{scanner} 執行失敗：{e}",
                    id = job.id,
                    scanner = scanner,
                    e = e.message()
                ),
            );
        }
        let (mut res, artifact) = tools::collect(step, &files, out, duration_ms, job.limits.max_output_bytes);
        if let Some(art) = artifact {
            match upload(ctx, &job.id, scanner, &art, res.exit_code, duration_ms).await {
                Upload::Done => {}
                Upload::Gone => {
                    results.push(res);
                    return Run::Aborted(Abort::LeaseLost, results);
                }
                Upload::Auth => return Run::Aborted(Abort::HubAuth, results),
                Upload::Failed(why) => {
                    res.ok = false;
                    res.error = Some(format!("artifact_upload_failed:{why}"));
                }
            }
        }
        log(
            ctx.quiet,
            &tf!(
                "工作 {id}：{scanner} {status}（{ms} ms）",
                id = job.id,
                scanner = scanner,
                status = res.error.as_deref().unwrap_or("ok"),
                ms = duration_ms
            ),
        );
        results.push(res);
    }
    Run::Done(JobResult::from_steps(results))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hub::test_server::{self, Captured};
    use crate::util::cmd::{CmdOutput, CmdSpec, FakeRunner};
    use crate::webscan::job::tests::scan_job;
    use crate::webscan::Capability;
    use async_trait::async_trait;
    use serde_json::json;
    use std::io::Read;

    pub(crate) fn all_caps() -> Vec<Capability> {
        Scanner::ALL
            .iter()
            .map(|s| Capability {
                scanner: *s,
                version: "1.0.0".into(),
                templates: None,
            })
            .collect()
    }

    pub(crate) fn ctx(url: &str, runner: Arc<dyn CmdRunner>, work: &Path, heartbeat_min: Duration) -> Arc<Ctx> {
        Arc::new(Ctx {
            client: Arc::new(HubClient::new(url, "tok-webscan", "").unwrap()),
            runner,
            tools: Tools {
                dir: None,
                templates: PathBuf::from("/opt/nuclei-templates"),
            },
            caps: all_caps(),
            work_dir: work.to_path_buf(),
            heartbeat_min,
            quiet: true,
        })
    }

    fn body(c: &Captured) -> Value {
        serde_json::from_slice(&c.body).unwrap()
    }

    fn not_stopped() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    fn fake_tools() -> FakeRunner {
        FakeRunner::new()
            .on(
                "httpx -u",
                CmdOutput::success("{\"url\":\"https://shop.example.com/\",\"status_code\":200}\n"),
            )
            .on(
                "tlsx -u",
                CmdOutput::success("{\"host\":\"8.8.8.8\",\"tls_version\":\"tls13\"}\n"),
            )
            .on(
                "nuclei -u",
                CmdOutput::success("{\"template-id\":\"tech-detect\",\"matched-at\":\"https://shop.example.com/\"}\n"),
            )
            .on(
                "testssl.sh --jsonfile",
                CmdOutput::success("Start 2026-10-24 09:00:00 -->> 8.8.8.8:443 <<--"),
            )
    }

    const HB_OK: &str = r#"{"ok":true,"lease_expires_at":"2099-01-01T00:00:00Z","cancel":false}"#;
    const HB_CANCEL: &str = r#"{"ok":true,"lease_expires_at":"2099-01-01T00:00:00Z","cancel":true}"#;

    #[tokio::test]
    async fn full_scan_job_heartbeat_artifacts_results() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![
            (200, HB_OK.into()),
            (200, r#"{"ok":true}"#.into()),
            (200, r#"{"ok":true}"#.into()),
            (200, r#"{"ok":true}"#.into()),
            (200, r#"{"ok":true}"#.into()),
            (200, r#"{"ok":true}"#.into()),
        ])
        .await;
        let fake = Arc::new(fake_tools());
        let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        let (_tx, stop) = not_stopped();
        let done = execute(c, scan_job("8.8.8.8"), vec![], chrono::Duration::zero(), stop).await;
        assert_eq!(done.id.as_deref(), Some("wsj_0123456789abcdef"));
        assert_eq!(done.outcome, Outcome::Reported { ok: true, error: None });

        let reqs = cap.lock().unwrap().clone();
        assert_eq!(reqs.len(), 6, "{reqs:#?}");
        // 心跳
        assert!(reqs[0]
            .head
            .starts_with("POST /api/v1/webscan/jobs/wsj_0123456789abcdef/heartbeat "));
        assert!(reqs[0]
            .head
            .to_ascii_lowercase()
            .contains("authorization: bearer tok-webscan"));
        assert_eq!(
            body(&reqs[0]),
            json!({"step": "httpx", "message": "httpx 0/4", "progress": 0.0})
        );
        // 每步一個 artifact：原始輸出 bytes
        let expect = [
            (
                "httpx",
                "jsonl",
                "{\"url\":\"https://shop.example.com/\",\"status_code\":200}\n",
            ),
            ("tlsx", "jsonl", "{\"host\":\"8.8.8.8\",\"tls_version\":\"tls13\"}\n"),
            (
                "nuclei",
                "jsonl",
                "{\"template-id\":\"tech-detect\",\"matched-at\":\"https://shop.example.com/\"}\n",
            ),
            ("testssl", "txt", "Start 2026-10-24 09:00:00 -->> 8.8.8.8:443 <<--"),
        ];
        for (i, (scanner, format, out)) in expect.iter().enumerate() {
            let r = &reqs[1 + i];
            let prefix = format!(
                "POST /api/v1/webscan/jobs/wsj_0123456789abcdef/artifacts?scanner={scanner}&format={format}&exit_code=0&duration_ms="
            );
            assert!(r.head.starts_with(&prefix), "{}", r.head);
            assert!(r.head.contains("&truncated=0 "), "{}", r.head);
            assert!(r
                .head
                .to_ascii_lowercase()
                .contains("content-type: application/octet-stream"));
            assert_eq!(r.body, out.as_bytes(), "{scanner}");
        }
        // 結果：testssl 沒有 JSON 檔（FakeRunner 不會寫）→ 那一步失敗，整體仍 ok
        assert!(reqs[5]
            .head
            .starts_with("POST /api/v1/webscan/jobs/wsj_0123456789abcdef/results "));
        let res = body(&reqs[5]);
        assert_eq!(res["ok"], true);
        assert_eq!(res["error"], Value::Null);
        assert_eq!(res["verify"], Value::Null);
        let steps = res["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 4);
        for (s, name) in steps.iter().zip(["httpx", "tlsx", "nuclei"]) {
            assert_eq!(
                (s["scanner"].as_str(), s["ok"].as_bool(), s["exit_code"].as_i64()),
                (Some(name), Some(true), Some(0))
            );
            assert_eq!(s["error"], Value::Null);
        }
        assert_eq!(steps[3]["scanner"], "testssl");
        assert_eq!(steps[3]["ok"], false);
        assert_eq!(steps[3]["error"], "no_output_file");

        // 工具呼叫：釘選的參數與環境、暫存目錄事後刪掉
        let calls = fake.calls();
        assert_eq!(
            calls.iter().map(|c| c.program.as_str()).collect::<Vec<_>>(),
            ["httpx", "tlsx", "nuclei", "testssl.sh"]
        );
        let nuclei = &calls[2];
        for flag in ["-ni", "-duc", "-dr", "-or", "-lna"] {
            assert!(nuclei.args.iter().any(|a| a == flag), "nuclei {flag}");
        }
        let etags = nuclei.args.iter().position(|a| a == "-etags").unwrap();
        assert!(nuclei.args[etags + 1].split(',').any(|t| t == "dos"));
        for c in [&calls[0], &calls[2]] {
            assert!(c.env.iter().any(|(k, _)| k == "HOSTS_PATH"));
            assert!(c.env.iter().any(|(k, _)| k == "RESOLVERS_PATH"));
        }
        let job_dir = calls[0].cwd.clone().unwrap();
        assert!(job_dir.starts_with(work.path()));
        // nuclei 用這個工作自己的 HOME（設定目錄每次新的）
        let home = job_dir.join("home").to_string_lossy().to_string();
        assert!(nuclei.env.contains(&("HOME".to_string(), home)));
        assert!(!job_dir.exists(), "job dir removed after the job");
        assert_eq!(
            calls[3]
                .args
                .iter()
                .position(|a| a == "--ip")
                .map(|i| calls[3].args[i + 1].as_str()),
            Some("8.8.8.8")
        );
    }

    #[tokio::test]
    async fn bad_jobs_and_blocked_targets_never_run_tools() {
        let work = tempfile::tempdir().unwrap();
        let mut bad = scan_job("8.8.8.8");
        bad["steps"] =
            json!([{"scanner": "nuclei", "options": {"exclude_tags": [], "severities": [], "templates": "/etc"}}]);
        let cases = [
            (bad, "bad_job:bad_options:nuclei:"),
            (scan_job("169.254.169.254"), "blocked_target:metadata"),
            (scan_job("10.0.0.8"), "blocked_target:private_not_allowed"),
            (scan_job("127.0.0.1"), "blocked_target:loopback"),
        ];
        for (job, want) in cases {
            let (url, cap) = test_server::serve(vec![(200, r#"{"ok":true}"#.into())]).await;
            let fake = Arc::new(fake_tools());
            let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
            let (_tx, stop) = not_stopped();
            let done = execute(c, job, vec![], chrono::Duration::zero(), stop).await;
            assert!(fake.calls().is_empty(), "{want}: no tool may run");
            let reqs = cap.lock().unwrap().clone();
            assert_eq!(reqs.len(), 1, "{want}: only the result, no heartbeat");
            assert!(reqs[0]
                .head
                .starts_with("POST /api/v1/webscan/jobs/wsj_0123456789abcdef/results "));
            let res = body(&reqs[0]);
            assert_eq!(res["ok"], false);
            assert!(res["error"].as_str().unwrap().starts_with(want), "{res}");
            assert_eq!(res["steps"], json!([]));
            assert!(matches!(done.outcome, Outcome::Reported { ok: false, .. }));
        }
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0, "no job dir created");
    }

    #[tokio::test]
    async fn cancel_in_the_first_heartbeat_runs_nothing() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![(200, HB_CANCEL.into()), (200, r#"{"ok":true}"#.into())]).await;
        let fake = Arc::new(fake_tools());
        let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        let (_tx, stop) = not_stopped();
        let done = execute(c, scan_job("8.8.8.8"), vec![], chrono::Duration::zero(), stop).await;
        assert!(fake.calls().is_empty());
        assert_eq!(
            done.outcome,
            Outcome::Reported {
                ok: false,
                error: Some("cancelled".into())
            }
        );
        let reqs = cap.lock().unwrap().clone();
        assert_eq!(body(&reqs[1])["error"], "cancelled");
    }

    /// 一直跑到被取消的工具；future 被丟掉時記下來。
    struct Hang {
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    struct SetOnDrop(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CmdRunner for Hang {
        async fn run(&self, _spec: &CmdSpec) -> crate::error::AppResult<CmdOutput> {
            let _guard = SetOnDrop(self.dropped.clone());
            tokio::time::sleep(Duration::from_secs(600)).await;
            Ok(CmdOutput::success(""))
        }
    }

    #[tokio::test]
    async fn heartbeat_cancel_kills_the_running_tool() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![
            (200, HB_OK.into()),
            (200, HB_CANCEL.into()),
            (200, r#"{"ok":true}"#.into()),
        ])
        .await;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let runner = Arc::new(Hang {
            dropped: dropped.clone(),
        });
        let c = ctx(&url, runner, work.path(), Duration::from_millis(50));
        let mut j = scan_job("8.8.8.8");
        j["lease_ms"] = json!(60);
        let (_tx, stop) = not_stopped();
        let t0 = Instant::now();
        let done = execute(c, j, vec![], chrono::Duration::zero(), stop).await;
        assert!(t0.elapsed() < Duration::from_secs(20), "{:?}", t0.elapsed());
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "tool future dropped (process tree killed)"
        );
        assert_eq!(
            done.outcome,
            Outcome::Reported {
                ok: false,
                error: Some("cancelled".into())
            }
        );
        let reqs = cap.lock().unwrap().clone();
        assert_eq!(reqs.len(), 3);
        let res = body(&reqs[2]);
        assert_eq!(res["error"], "cancelled");
        assert_eq!(res["steps"][0]["scanner"], "httpx");
        assert_eq!(res["steps"][0]["error"], "cancelled");
        assert_eq!(res["steps"].as_array().unwrap().len(), 1, "later steps never started");
    }

    #[tokio::test]
    async fn lease_lost_stops_without_reporting() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![(409, r#"{"error":"not_yours"}"#.into())]).await;
        let fake = Arc::new(fake_tools());
        let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        let (_tx, stop) = not_stopped();
        let done = execute(c, scan_job("8.8.8.8"), vec![], chrono::Duration::zero(), stop).await;
        assert_eq!(done.outcome, Outcome::NotReported("lease_lost".into()));
        assert!(fake.calls().is_empty());
        assert_eq!(cap.lock().unwrap().len(), 1, "no results after 409");
    }

    #[tokio::test]
    async fn runner_stop_reports_runner_stopped() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![(200, HB_OK.into()), (200, r#"{"ok":true}"#.into())]).await;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c = ctx(
            &url,
            Arc::new(Hang {
                dropped: dropped.clone(),
            }),
            work.path(),
            Duration::from_secs(3600),
        );
        let (tx, stop) = not_stopped();
        let job = tokio::spawn(execute(c, scan_job("8.8.8.8"), vec![], chrono::Duration::zero(), stop));
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send(true).unwrap();
        let done = tokio::time::timeout(Duration::from_secs(20), job)
            .await
            .unwrap()
            .unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            done.outcome,
            Outcome::Reported {
                ok: false,
                error: Some("runner_stopped".into())
            }
        );
        let reqs = cap.lock().unwrap().clone();
        assert_eq!(body(&reqs[1])["error"], "runner_stopped");
    }

    #[tokio::test]
    async fn missing_tools_and_deadline_are_step_errors() {
        let work = tempfile::tempdir().unwrap();
        let (url, cap) = test_server::serve(vec![
            (200, HB_OK.into()),
            (200, r#"{"ok":true}"#.into()),
            (200, r#"{"ok":true}"#.into()),
        ])
        .await;
        let fake = Arc::new(fake_tools());
        let mut c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        Arc::get_mut(&mut c)
            .unwrap()
            .caps
            .retain(|x| x.scanner == Scanner::Httpx);
        let mut j = scan_job("8.8.8.8");
        j["steps"] = json!([{"scanner": "httpx", "options": {}}, {"scanner": "nuclei", "options": {}}]);
        let (_tx, stop) = not_stopped();
        let done = execute(c, j, vec![], chrono::Duration::zero(), stop).await;
        assert!(matches!(done.outcome, Outcome::Reported { ok: true, .. }));
        let reqs = cap.lock().unwrap().clone();
        let res = body(&reqs[2]);
        assert_eq!(res["steps"][1]["error"], "not_installed");
        assert_eq!(fake.calls().len(), 1);

        // 已經過了截止時間：一個步驟都不開始
        let (url, cap) = test_server::serve(vec![(200, HB_OK.into()), (200, r#"{"ok":true}"#.into())]).await;
        let fake = Arc::new(fake_tools());
        let c = ctx(&url, fake.clone(), work.path(), Duration::from_secs(3600));
        let mut j = scan_job("8.8.8.8");
        j["deadline"] = json!("2020-01-01T00:00:00Z");
        let (_tx, stop) = not_stopped();
        let done = execute(c, j, vec![], chrono::Duration::zero(), stop).await;
        assert_eq!(
            done.outcome,
            Outcome::Reported {
                ok: false,
                error: Some("all_steps_failed".into())
            }
        );
        assert!(fake.calls().is_empty());
        let res = body(&cap.lock().unwrap()[1]);
        assert!(res["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["error"] == "deadline_exceeded"));
    }

    #[test]
    fn artifact_encoding_gzips_and_caps() {
        let small = b"{\"a\":1}\n".to_vec();
        assert_eq!(
            encode_artifact(&small, false, true).unwrap(),
            (small.clone(), false, false)
        );
        let lines: Vec<u8> = (0..5000)
            .flat_map(|i| format!("{{\"n\":{i}}}\n").into_bytes())
            .collect();
        let (gz, zipped, truncated) = encode_artifact(&lines, false, true).unwrap();
        assert!(zipped && !truncated && gz.len() < lines.len());
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, lines);
        // 壓不下來的內容：砍到 8 MiB 以內、標 truncated、切在換行
        let mut seed: u64 = 0x2545_F491_4F6C_DD1D;
        let mut noise: Vec<u8> = Vec::with_capacity(10 * 1024 * 1024);
        while noise.len() < 10 * 1024 * 1024 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            noise.extend_from_slice(&seed.to_le_bytes());
            if noise.len() % 4096 == 0 {
                noise.push(b'\n');
            }
        }
        let (gz, zipped, truncated) = encode_artifact(&noise, false, true).unwrap();
        assert!(zipped && truncated);
        assert!(gz.len() <= MAX_ARTIFACT_BYTES, "{}", gz.len());
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        assert!(out.ends_with(b"\n") && noise.starts_with(&out));
    }

    #[test]
    fn stale_job_dirs_are_cleaned() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("job-old-1234")).unwrap();
        std::fs::create_dir(d.path().join("keep-me")).unwrap();
        cleanup_stale(d.path(), Duration::from_secs(3600));
        assert!(d.path().join("job-old-1234").exists(), "fresh dirs stay");
        cleanup_stale(d.path(), Duration::ZERO);
        assert!(!d.path().join("job-old-1234").exists());
        assert!(d.path().join("keep-me").exists(), "only job-* dirs");
    }
}
