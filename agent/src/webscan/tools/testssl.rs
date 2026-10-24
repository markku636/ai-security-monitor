//! testssl.sh（<https://github.com/testssl/testssl.sh>，GPL-2.0，以未修改的獨立程式執行）：完整的 TLS 設定與弱點檢查。
//!
//! 旗標對照官方說明 `doc/testssl.1.md`（3.2 分支）與 <https://testssl.sh/doc/testssl.1.html>（2026-10 查核）：
//! `--jsonfile <檔>`（可給絕對路徑）、`--quiet`（不印 banner）、`--color 0`、`--warnings off`（不等按鍵確認）、
//! `--ip <ip>`（不解析主機、直接測這個位址；IPv6 要加中括號）、`--nodns none`（完全不做 DNS 查詢）、
//! `--connect-timeout`／`--openssl-timeout`（秒；需要系統有 timeout 指令）、`--fast`（3.2 起標為 deprecated，仍可用、只印警告）。
//! 撤銷檢查（CRL／OCSP）預設不做（`--phone-out` 才會連第三方）；環境變數 `PHONE_OUT` 也明確設成 false。
//! 結束碼：0＝成功、1～245＝有模稜兩可的結果或小錯（50–200 保留給弱點分數）、≥ 246 是錯誤（連線、DNS、參數…）。
//! 結束碼 < 246 而且 JSON 檔存在才算成功，artifact 是那個 JSON 檔（沒有 JSON 時改傳 stdout，format＝txt）。

use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use super::{argv, Artifact, JobFiles, StepEnv, CONNECT_TIMEOUT_S};
use crate::util::cmd::{BoundedOutput, CmdSpec};
use crate::webscan::{Scanner, StepResult};

/// testssl.sh 的 stdout 只拿來除錯（結果在 JSON 檔），最多留這麼多。
const STDOUT_KEEP: usize = 1024 * 1024;
/// 結束碼從這裡開始是 testssl.sh 自己的錯誤（ERR_CONNECT 246 … ERR_BASH 255）。
pub const FIRST_ERROR_CODE: i32 = 246;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub fast: bool,
}

pub fn spec(env: &StepEnv, opts: &Options) -> CmdSpec {
    let t = env.target;
    let json = env.files.testssl_json.to_string_lossy().to_string();
    let mut args = argv(&["--jsonfile", &json, "--quiet", "--color", "0", "--warnings", "off"]);
    // 只測第一個釘選位址（`--ip` 只收一個；範圍檢查保證至少有一個）
    if let Some(ip) = t.pinned.first() {
        let ip = match ip {
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };
        args.extend(argv(&["--ip", &ip]));
    }
    args.extend(argv(&[
        "--nodns",
        "none",
        "--connect-timeout",
        CONNECT_TIMEOUT_S,
        "--openssl-timeout",
        CONNECT_TIMEOUT_S,
    ]));
    if opts.fast {
        args.push("--fast".to_string());
    }
    args.push(t.host_port());
    let mut spec = env.command(Scanner::Testssl, args).with_env("PHONE_OUT", "false");
    spec.max_stdout = Some(STDOUT_KEEP.min(env.limits.max_output_bytes));
    spec
}

/// 讀檔，最多 `max` bytes；回（內容, 有沒有截斷）。檔案不存在回 None。
fn read_capped(path: &Path, max: usize) -> Option<(Vec<u8>, bool)> {
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut buf).ok()?;
    let truncated = buf.len() > max;
    buf.truncate(max);
    Some((buf, truncated))
}

/// 結束碼 < 246 且 JSON 檔存在＝成功；artifact 是 JSON 檔（沒有就傳 stdout）。
pub fn collect(
    files: &JobFiles,
    b: BoundedOutput,
    duration_ms: u64,
    max_output: usize,
) -> (StepResult, Option<Artifact>) {
    let code = b.output.code;
    let json = read_capped(&files.testssl_json, max_output);
    let error = if b.timed_out {
        Some("timeout".to_string())
    } else {
        match code {
            None => Some("killed".to_string()),
            Some(c) if !(0..FIRST_ERROR_CODE).contains(&c) => Some(format!("exit_code:{c}")),
            Some(_) if json.is_none() => Some("no_output_file".to_string()),
            Some(_) => None,
        }
    };
    let artifact = match json {
        Some((bytes, truncated)) => Artifact {
            format: "json",
            bytes,
            truncated,
        },
        None => Artifact {
            format: "txt",
            bytes: b.output.stdout.into_bytes(),
            truncated: b.truncated,
        },
    };
    (
        StepResult {
            scanner: Scanner::Testssl,
            ok: error.is_none(),
            exit_code: code,
            duration_ms,
            error,
        },
        Some(artifact),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::CmdOutput;
    use crate::webscan::tools::tests::{env, files, job};

    #[test]
    fn argv_pins_the_ip_and_disables_dns() {
        let j = job("8.8.8.8");
        let f = files();
        let s = spec(&env(&j, &f, "testssl.sh"), &Options::default());
        assert_eq!(s.program, "testssl.sh");
        assert_eq!(
            s.args,
            argv(&[
                "--jsonfile",
                &f.testssl_json.to_string_lossy(),
                "--quiet",
                "--color",
                "0",
                "--warnings",
                "off",
                "--ip",
                "8.8.8.8",
                "--nodns",
                "none",
                "--connect-timeout",
                "10",
                "--openssl-timeout",
                "10",
                "shop.example.com:443",
            ])
        );
        assert!(s.env.contains(&("PHONE_OUT".to_string(), "false".to_string())));
        assert!(!s.args.iter().any(|a| a == "--phone-out"));
        assert_eq!(s.max_stdout, Some(STDOUT_KEEP));
        let fast = spec(&env(&j, &f, "testssl.sh"), &Options { fast: true });
        assert_eq!(fast.args[fast.args.len() - 2], "--fast");
        assert_eq!(fast.args.last().unwrap(), "shop.example.com:443");
    }

    #[test]
    fn ipv6_is_bracketed() {
        let mut j = job("8.8.8.8");
        j.target.pinned = vec!["2606:4700::1111".parse().unwrap()];
        j.target.port = 8443;
        let f = files();
        let s = spec(&env(&j, &f, "testssl.sh"), &Options::default());
        let i = s.args.iter().position(|a| a == "--ip").unwrap();
        assert_eq!(s.args[i + 1], "[2606:4700::1111]");
        assert_eq!(s.args.last().unwrap(), "shop.example.com:8443");
    }

    #[test]
    fn success_needs_exit_below_246_and_the_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = JobFiles::in_dir(dir.path());
        let out = |code: Option<i32>| BoundedOutput {
            output: CmdOutput {
                code,
                stdout: "Start 2026-10-24".into(),
                stderr: String::new(),
            },
            ..Default::default()
        };
        // 沒有 JSON：失敗，改傳 stdout
        let (r, a) = collect(&f, out(Some(0)), 10, 1024);
        assert_eq!((r.ok, r.error.as_deref()), (false, Some("no_output_file")));
        assert_eq!(a.unwrap().format, "txt");
        std::fs::write(&f.testssl_json, b"[{\"id\":\"cert_expirationStatus\"}]").unwrap();
        for code in [0, 1, 45, 245] {
            let (r, a) = collect(&f, out(Some(code)), 10, 1024);
            assert!(r.ok, "exit {code}");
            let a = a.unwrap();
            assert_eq!((a.format, a.truncated), ("json", false));
            assert!(a.bytes.starts_with(b"[{"));
        }
        for code in [246, 247, 254, 255] {
            let (r, _) = collect(&f, out(Some(code)), 10, 1024);
            assert_eq!(r.error, Some(format!("exit_code:{code}")));
        }
        let (r, a) = collect(&f, out(Some(0)), 10, 4);
        assert!(r.ok);
        let a = a.unwrap();
        assert_eq!((a.bytes.len(), a.truncated), (4, true));
        let mut to = out(None);
        to.timed_out = true;
        let (r, _) = collect(&f, to, 10, 1024);
        assert_eq!(r.error.as_deref(), Some("timeout"));
    }
}
