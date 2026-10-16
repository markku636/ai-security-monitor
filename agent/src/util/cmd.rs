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

#[async_trait]
pub trait CmdRunner: Send + Sync {
    async fn run(&self, spec: &CmdSpec) -> AppResult<CmdOutput>;
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
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::External(tf!("找不到指令：{program}", program = spec.program))
            } else {
                AppError::External(tf!("無法執行 {program}：{e}", program = spec.program, e = e))
            }
        })?;
        if let (Some(input), Some(mut stdin)) = (spec.stdin.clone(), child.stdin.take()) {
            stdin.write_all(input.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        let out = tokio::time::timeout(Duration::from_millis(spec.timeout_ms), child.wait_with_output())
            .await
            .map_err(|_| AppError::Timeout(spec.timeout_ms))??;
        let strip_bom = |s: String| s.strip_prefix('\u{feff}').map(|x| x.to_string()).unwrap_or(s);
        Ok(CmdOutput {
            code: out.status.code(),
            stdout: strip_bom(String::from_utf8_lossy(&out.stdout).to_string()),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
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
}
