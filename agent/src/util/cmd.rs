//! 外部指令執行：逾時、Windows 不開主控台視窗、PowerShell 以 `-EncodedCommand`（UTF-16LE）傳腳本
//! 避開引號與編碼問題。`CmdRunner` 可換成 `FakeRunner` 讓防火牆 / 事件解析在 CI 以 fixture 測試。

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CmdSpec {
    pub program: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    pub timeout_ms: u64,
    pub needs_elevation: bool,
    pub description: String,
    /// PowerShell 腳本原文（`args` 裡是 base64，預覽時顯示這個）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    /// 失敗不中斷後續指令（冪等的刪除 / 檢查類）。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_fail: bool,
    /// 子行程的工作目錄（省略＝沿用目前的）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<std::path::PathBuf>,
    /// 子行程另外設定的環境變數（同名覆蓋）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
    /// 從子行程環境拿掉的變數（例如代理設定）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_remove: Vec<String>,
    /// [`CmdRunner::run_bounded`]：stdout 最多留幾 bytes，其餘讀掉丟棄（結果標 `truncated`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stdout: Option<usize>,
}

impl CmdSpec {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: None,
            timeout_ms: 30_000,
            needs_elevation: false,
            description: String::new(),
            script: None,
            allow_fail: false,
            cwd: None,
            env: Vec::new(),
            env_remove: Vec::new(),
            max_stdout: None,
        }
    }

    pub fn describe(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn elevated(mut self) -> Self {
        self.needs_elevation = true;
        self
    }

    pub fn timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn tolerate_failure(mut self) -> Self {
        self.allow_fail = true;
        self
    }

    pub fn with_stdin(mut self, s: impl Into<String>) -> Self {
        self.stdin = Some(s.into());
        self
    }

    /// 在指定的目錄執行。
    pub fn in_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// 另外設一個環境變數。
    pub fn with_env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.push((key.to_string(), value.into()));
        self
    }

    /// 不讓子行程繼承這個環境變數。
    pub fn without_env(mut self, key: &str) -> Self {
        self.env_remove.push(key.to_string());
        self
    }

    /// stdout 最多留 `n` bytes（[`CmdRunner::run_bounded`]）。
    pub fn cap_stdout(mut self, n: usize) -> Self {
        self.max_stdout = Some(n);
        self
    }

    /// 給人看的命令列（PowerShell 顯示腳本原文）。
    pub fn display(&self) -> String {
        if let Some(s) = &self.script {
            return format!("powershell -NoProfile -Command {{ {} }}", s.trim());
        }
        let mut out = self.program.clone();
        for a in &self.args {
            out.push(' ');
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'') {
                out.push('"');
                out.push_str(&a.replace('"', "\\\""));
                out.push('"');
            } else {
                out.push_str(a);
            }
        }
        out
    }

    /// FakeRunner 比對用的 key：program + 參數（PowerShell 用腳本原文）。
    pub fn match_key(&self) -> String {
        match &self.script {
            Some(s) => format!("powershell {s}"),
            None => format!("{} {}", self.program, self.args.join(" ")),
        }
    }
}

/// PowerShell 腳本前置：UTF-8 輸出、靜音進度列、錯誤即停。
pub const PS_PRELUDE: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n$ProgressPreference = 'SilentlyContinue'\n$ErrorActionPreference = 'Stop'\n";

pub fn powershell(script: &str) -> CmdSpec {
    let full = format!("{PS_PRELUDE}{script}");
    let utf16: Vec<u8> = full.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
    let mut spec = CmdSpec::new(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &b64,
        ],
    );
    spec.script = Some(script.to_string());
    spec.timeout_ms = 60_000;
    spec
}

/// 執行一個 PowerShell 腳本檔（大量位址的腳本會超過命令列長度上限，改寫成帶 BOM 的 .ps1 再 -File）。
pub fn powershell_file(path: &std::path::Path, script: &str) -> CmdSpec {
    let p = path.to_string_lossy().to_string();
    let mut spec = CmdSpec::new(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &p,
        ],
    );
    spec.script = Some(script.to_string());
    spec.timeout_ms = 600_000;
    spec
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CmdOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    pub fn success(stdout: &str) -> Self {
        Self {
            code: Some(0),
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    pub fn failure(code: i32, stderr: &str) -> Self {
        Self {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    /// stderr 看起來是權限不足。
    pub fn permission_denied(&self) -> bool {
        let e = self.stderr.to_ascii_lowercase();
        e.contains("permission denied")
            || e.contains("operation not permitted")
            || e.contains("you need to be root")
            || e.contains("must be root")
            || e.contains("access is denied")
            || e.contains("not authorized")
    }
}

/// [`CmdRunner::run_bounded`] 的結果：逾時也回 `Ok`，帶著已經收到的輸出。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BoundedOutput {
    /// `output.code` 是 `None`＝行程被殺掉（逾時或訊號）。
    pub output: CmdOutput,
    pub timed_out: bool,
    /// stdout 超過 `max_stdout`，後面的被丟掉了。
    pub truncated: bool,
}

/// 把字串截到最多 `max` bytes（落在字元邊界）；有截到回 true。
pub fn truncate_utf8(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

#[async_trait]
pub trait CmdRunner: Send + Sync {
    async fn run(&self, spec: &CmdSpec) -> AppResult<CmdOutput>;

    /// 有上限的執行（長時間的外部掃描工具用）：逾時殺掉整棵子行程（Unix process group、Windows Job Object），
    /// 回 `Ok`（`timed_out`）並帶著已經收到的輸出；stdout 只留 `max_stdout` bytes。
    /// future 被丟掉（取消）時一樣殺掉整棵子行程。預設實作套在 `run` 上（`FakeRunner` 用）。
    async fn run_bounded(&self, spec: &CmdSpec) -> AppResult<BoundedOutput> {
        match self.run(spec).await {
            Ok(mut output) => {
                let truncated = spec
                    .max_stdout
                    .is_some_and(|max| truncate_utf8(&mut output.stdout, max));
                Ok(BoundedOutput {
                    output,
                    timed_out: false,
                    truncated,
                })
            }
            Err(AppError::Timeout(_)) => Ok(BoundedOutput {
                timed_out: true,
                ..Default::default()
            }),
            Err(e) => Err(e),
        }
    }
}

fn spawn_error(spec: &CmdSpec, e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::NotFound {
        AppError::External(tf!("找不到指令：{program}", program = spec.program))
    } else {
        AppError::External(tf!("無法執行 {program}：{e}", program = spec.program, e = e))
    }
}

/// 工作目錄與環境變數。
fn apply_env(cmd: &mut tokio::process::Command, spec: &CmdSpec) {
    if let Some(dir) = &spec.cwd {
        cmd.current_dir(dir);
    }
    for k in &spec.env_remove {
        cmd.env_remove(k);
    }
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
}

fn strip_bom(s: String) -> String {
    s.strip_prefix('\u{feff}').map(|x| x.to_string()).unwrap_or(s)
}

/// stderr 最多留這麼多（只拿來看錯誤原因）。
const STDERR_KEEP: usize = 64 * 1024;
/// 行程樹收掉之後，等 pipe 讀完最多這麼久（脫離行程群組的孫行程還開著 pipe 時不要卡住）。
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// 在背景讀一條 pipe：最多留 `keep` bytes，其餘讀掉丟棄（子行程才不會因為 pipe 滿了卡住）。
struct PipeReader(Option<tokio::task::JoinHandle<Vec<u8>>>);

impl PipeReader {
    fn spawn<R>(pipe: Option<R>, keep: usize) -> PipeReader
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        PipeReader(Some(tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut kept = Vec::new();
            let Some(mut pipe) = pipe else {
                return kept;
            };
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match pipe.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = keep.saturating_sub(kept.len());
                        kept.extend_from_slice(&buf[..n.min(room)]);
                    }
                }
            }
            kept
        })))
    }

    async fn finish(mut self) -> Vec<u8> {
        let Some(mut h) = self.0.take() else {
            return Vec::new();
        };
        match tokio::time::timeout(DRAIN_GRACE, &mut h).await {
            Ok(Ok(v)) => v,
            _ => {
                h.abort();
                Vec::new()
            }
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

pub struct RealRunner;

#[async_trait]
impl CmdRunner for RealRunner {
    async fn run(&self, spec: &CmdSpec) -> AppResult<CmdOutput> {
        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(if spec.stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        apply_env(&mut cmd, spec);
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = cmd.spawn().map_err(|e| spawn_error(spec, e))?;
        if let (Some(input), Some(mut stdin)) = (spec.stdin.clone(), child.stdin.take()) {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        let out = tokio::time::timeout(Duration::from_millis(spec.timeout_ms), child.wait_with_output())
            .await
            .map_err(|_| AppError::Timeout(spec.timeout_ms))??;
        Ok(CmdOutput {
            code: out.status.code(),
            stdout: strip_bom(String::from_utf8_lossy(&out.stdout).to_string()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    async fn run_bounded(&self, spec: &CmdSpec) -> AppResult<BoundedOutput> {
        let mut cmd = tokio::process::Command::new(&spec.program);
        cmd.args(&spec.args)
            .stdin(if spec.stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        apply_env(&mut cmd, spec);
        // Windows 不開主控台視窗、Unix 自己一個 process group；Child 被丟掉時殺掉直接子行程
        crate::ai::proc::prepare(&mut cmd);
        // 整棵子行程樹：Unix kill 整個 process group、Windows 收掉 Job Object（KILL_ON_JOB_CLOSE）；
        // 這個 future 被丟掉（取消）時 Drop 一樣會收掉
        let tree = crate::ai::proc::Job::new();
        let mut child = cmd.spawn().map_err(|e| spawn_error(spec, e))?;
        if let Some(t) = &tree {
            t.assign(&child);
        }
        if let (Some(input), Some(mut stdin)) = (spec.stdin.clone(), child.stdin.take()) {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        let keep = spec.max_stdout.unwrap_or(usize::MAX - 1);
        // 多留 1 byte 才知道有沒有超過
        let out = PipeReader::spawn(child.stdout.take(), keep.saturating_add(1));
        let err = PipeReader::spawn(child.stderr.take(), STDERR_KEEP);
        let waited = tokio::time::timeout(Duration::from_millis(spec.timeout_ms), child.wait()).await;
        // 結束或逾時都把整棵樹收掉：逾時＝殺掉還在跑的；正常結束＝收掉留下來的孫行程（不然 pipe 一直開著）
        if let Some(t) = &tree {
            t.kill();
        }
        let (code, timed_out) = match waited {
            Ok(status) => (status?.code(), false),
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                (None, true)
            }
        };
        let mut stdout = out.finish().await;
        let truncated = stdout.len() > keep;
        stdout.truncate(keep);
        let stderr = err.finish().await;
        Ok(BoundedOutput {
            output: CmdOutput {
                code,
                stdout: strip_bom(String::from_utf8_lossy(&stdout).to_string()),
                stderr: String::from_utf8_lossy(&stderr).to_string(),
            },
            timed_out,
            truncated,
        })
    }
}

/// 測試用：依 `match_key` 的子字串回固定輸出，並記錄呼叫。沒對上的回「找不到指令」。
#[derive(Default)]
pub struct FakeRunner {
    pub responses: Vec<(String, CmdOutput)>,
    pub calls: Mutex<Vec<CmdSpec>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on(mut self, needle: &str, out: CmdOutput) -> Self {
        self.responses.push((needle.to_string(), out));
        self
    }

    pub fn calls(&self) -> Vec<CmdSpec> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl CmdRunner for FakeRunner {
    async fn run(&self, spec: &CmdSpec) -> AppResult<CmdOutput> {
        if let Ok(mut c) = self.calls.lock() {
            c.push(spec.clone());
        }
        let key = spec.match_key();
        self.responses
            .iter()
            .find(|(needle, _)| key.contains(needle.as_str()))
            .map(|(_, o)| o.clone())
            .ok_or_else(|| AppError::External(tf!("找不到指令：{program}", program = spec.program)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_encodes_utf16le_with_prelude() {
        let s = powershell("Get-Date");
        let b64 = s.args.last().unwrap();
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let u16s: Vec<u16> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let text = String::from_utf16(&u16s).unwrap();
        assert!(text.starts_with("[Console]::OutputEncoding"));
        assert!(text.ends_with("Get-Date"));
        assert!(s.display().contains("Get-Date"));
        assert_eq!(s.match_key(), "powershell Get-Date");
    }

    #[test]
    fn display_quotes_spaces() {
        let s = CmdSpec::new("nft", &["add", "element", "inet asa", "block4", "{ 1.2.3.4 }"]);
        assert_eq!(s.display(), "nft add element \"inet asa\" block4 \"{ 1.2.3.4 }\"");
    }

    #[tokio::test]
    async fn fake_runner_matches_and_records() {
        let f = FakeRunner::new().on("ufw status", CmdOutput::success("Status: active"));
        let out = f.run(&CmdSpec::new("ufw", &["status", "verbose"])).await.unwrap();
        assert!(out.ok() && out.stdout.contains("active"));
        assert!(f.run(&CmdSpec::new("nft", &["list"])).await.is_err());
        assert_eq!(f.calls().len(), 2);
    }

    #[tokio::test]
    async fn real_runner_reports_missing_program() {
        let r = RealRunner
            .run(&CmdSpec::new("definitely-not-a-real-binary-asa", &[]))
            .await;
        assert!(matches!(r, Err(AppError::External(_))));
    }

    #[test]
    fn permission_detection() {
        assert!(CmdOutput::failure(1, "ERROR: You need to be root to run this script").permission_denied());
        assert!(CmdOutput::failure(1, "Error: Operation not permitted").permission_denied());
        assert!(!CmdOutput::failure(1, "syntax error").permission_denied());
    }

    /// 各平台都有的 shell（測試用）。
    fn shell(script: &str) -> CmdSpec {
        if cfg!(windows) {
            CmdSpec::new("cmd", &["/C", script])
        } else {
            CmdSpec::new("sh", &["-c", script])
        }
    }

    #[test]
    fn truncates_on_char_boundary() {
        let mut s = "ab中文".to_string();
        assert!(truncate_utf8(&mut s, 4));
        assert_eq!(s, "ab");
        let mut t = "abc".to_string();
        assert!(!truncate_utf8(&mut t, 3));
        assert_eq!(t, "abc");
    }

    #[tokio::test]
    async fn default_bounded_run_caps_fake_output_and_maps_timeouts() {
        let f = FakeRunner::new().on("tool", CmdOutput::success("0123456789"));
        let r = f.run_bounded(&CmdSpec::new("tool", &[]).cap_stdout(4)).await.unwrap();
        assert_eq!(r.output.stdout, "0123");
        assert!(r.truncated && !r.timed_out);
        struct Slow;
        #[async_trait]
        impl CmdRunner for Slow {
            async fn run(&self, spec: &CmdSpec) -> AppResult<CmdOutput> {
                Err(AppError::Timeout(spec.timeout_ms))
            }
        }
        let r = Slow.run_bounded(&CmdSpec::new("x", &[])).await.unwrap();
        assert!(r.timed_out && r.output.code.is_none());
    }

    #[tokio::test]
    async fn bounded_run_caps_stdout_but_drains_the_pipe() {
        // 72 KB 以上（超過 pipe 緩衝）：只留 100 bytes，其餘要讀掉，行程才不會卡住
        let script = if cfg!(windows) {
            "for /L %i in (1,1,6000) do @echo 0123456789"
        } else {
            "yes 0123456789 | head -n 6000"
        };
        let r = RealRunner
            .run_bounded(&shell(script).cap_stdout(100).timeout(60_000))
            .await
            .unwrap();
        assert!(!r.timed_out, "{r:?}");
        assert_eq!(r.output.code, Some(0));
        assert!(r.truncated);
        assert_eq!(r.output.stdout.len(), 100);
        assert!(r.output.stdout.starts_with("0123456789"));
    }

    #[tokio::test]
    async fn bounded_run_times_out_and_keeps_partial_output() {
        let script = if cfg!(windows) {
            "echo started& ping -n 30 127.0.0.1 > nul"
        } else {
            "echo started; sleep 30"
        };
        let t0 = std::time::Instant::now();
        let r = RealRunner.run_bounded(&shell(script).timeout(1_500)).await.unwrap();
        assert!(r.timed_out, "{r:?}");
        assert_eq!(r.output.code, None);
        assert!(r.output.stdout.contains("started"), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(15), "{:?}", t0.elapsed());
    }

    #[tokio::test]
    async fn bounded_run_sets_cwd_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let script = if cfg!(windows) {
            "echo %ASA_CMD_TEST%& cd"
        } else {
            "echo $ASA_CMD_TEST; pwd"
        };
        let r = RealRunner
            .run_bounded(&shell(script).in_dir(dir.path()).with_env("ASA_CMD_TEST", "pinned-123"))
            .await
            .unwrap();
        assert!(r.output.stdout.contains("pinned-123"), "{r:?}");
        let name = dir.path().file_name().unwrap().to_string_lossy().to_string();
        assert!(r.output.stdout.contains(&name), "{r:?}");
    }

    #[cfg(unix)]
    fn gone(pid: i32) -> bool {
        // 已經被收掉，或只剩殭屍（Linux 的 /proc 看得到狀態 Z）都算不見了
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|s| s.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
            .unwrap_or(false);
        let reaped = unsafe { libc::kill(pid, 0) } != 0;
        reaped || zombie
    }

    #[cfg(unix)]
    async fn wait_gone(pid: i32) -> bool {
        for _ in 0..50 {
            if gone(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }

    /// 逾時要殺掉整個 process group：背景跑的孫行程也要不見。
    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_timeout_kills_the_process_group() {
        let r = RealRunner
            .run_bounded(&shell("sleep 30 & echo $!; wait").timeout(800))
            .await
            .unwrap();
        assert!(r.timed_out, "{r:?}");
        let pid: i32 = r.output.stdout.trim().parse().unwrap();
        assert!(wait_gone(pid).await, "grandchild {pid} survived the timeout");
    }

    /// 取消（future 被丟掉）也要殺掉整個 process group。
    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_a_bounded_run_kills_the_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pidfile.display());
        let spec = shell(&script).timeout(60_000);
        let run = RealRunner.run_bounded(&spec);
        let waited = tokio::time::timeout(Duration::from_millis(800), run).await;
        assert!(waited.is_err(), "should still be running");
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        assert!(wait_gone(pid).await, "grandchild {pid} survived the cancellation");
    }
}
