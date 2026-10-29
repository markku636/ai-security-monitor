//! httpx（<https://github.com/projectdiscovery/httpx>，MIT）：HTTP 探測（狀態碼、標題、伺服器、技術、IP、TLS 資訊）。
//!
//! 旗標對照官方 README 的 Usage 與 `runner/options.go`（2026-10 查核）：
//! `-u`／`-target` 目標、`-j`／`-json` JSONL、`-silent`、`-nc`／`-no-color`、`-duc`／`-disable-update-check`、
//! `-sc`、`-title`、`-server`／`-web-server`、`-td`／`-tech-detect`（內建 wappalyzer 資料，不連外）、`-ip`、
//! `-tls-grab`、`-irh`／`-include-response-header`（把回應標頭放進 JSON 的 `header`：拿來做被動的安全標頭檢查）、
//! `-timeout`（秒）、`-retries`、`-rl`／`-rate-limit`、`-r`／`-resolvers`（檔案或逗號分隔）、
//! `-nfs`／`-no-fallback-scheme`（只用網址的 scheme，不會退回 http 改連 80 port）、
//! `-allow`（IP／CIDR 白名單，由 fastdialer 的 network policy 在連線時強制，不在名單內的位址一律不連）。
//! 不加 `-fr`：預設不跟轉址。
//!
//! 隱私：`-irh` 會把回應標頭寫進 JSON，其中可能有 `Set-Cookie`（連 session token）、`Authorization` 等祕密。
//! 比照 nuclei 的 `-or`（不留 response 原文），[`collect`] 在上傳成 artifact 前，把每一行的 `header` 物件裡的
//! 敏感標頭（[`REDACT_HEADERS`]）換成 `"[redacted]"`：安全標頭（CSP、HSTS…）照留，祕密不進 Hub。

use serde::Deserialize;
use serde_json::Value;

use super::{argv, Artifact, StepEnv, CONNECT_TIMEOUT_S};
use crate::util::cmd::{BoundedOutput, CmdSpec};
use crate::webscan::{Scanner, StepResult};

/// httpx 沒有可調的選項（`{}`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {}

pub fn spec(env: &StepEnv, _opts: &Options) -> CmdSpec {
    let t = env.target;
    let url = t.url();
    let rate = env.limits.rate_per_sec.to_string();
    let resolver = env.resolver.to_string();
    let allow = t.pinned.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
    let args = argv(&[
        "-u",
        &url,
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-sc",
        "-title",
        "-server",
        "-td",
        "-ip",
        "-tls-grab",
        "-irh",
        "-timeout",
        CONNECT_TIMEOUT_S,
        "-retries",
        "1",
        "-rl",
        &rate,
        "-r",
        &resolver,
        "-nfs",
        "-allow",
        &allow,
    ]);
    env.job_home(env.pinned_dns(env.command(Scanner::Httpx, args)))
}

/// `header` 物件裡要遮掉的標頭（httpx 把標頭名稱正規化成小寫底線）：帶祕密、不該進 artifact。
pub const REDACT_HEADERS: [&str; 5] = [
    "set_cookie",
    "cookie",
    "authorization",
    "proxy_authorization",
    "proxy_authenticate",
];

/// 把一行 JSON 裡 `header` 物件的敏感標頭換成 `"[redacted]"`（其他欄位、其他標頭不動）；回傳有沒有動過。
fn redact_line(line: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(line).ok()?;
    let header = v.get_mut("header")?.as_object_mut()?;
    let mut changed = false;
    for k in REDACT_HEADERS {
        if let Some(slot) = header.get_mut(k) {
            if *slot != Value::String("[redacted]".into()) {
                *slot = Value::String("[redacted]".into());
                changed = true;
            }
        }
    }
    changed.then(|| serde_json::to_string(&v).unwrap_or_else(|_| line.to_string()))
}

/// 逐行遮罩（JSONL）：壞掉或沒有敏感標頭的行原樣保留。
pub fn redact_headers(bytes: Vec<u8>) -> Vec<u8> {
    let Ok(text) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    // 沒有任何敏感標頭名稱就完全不用解析（絕大多數情況）
    if !REDACT_HEADERS.iter().any(|h| text.contains(h)) {
        return text.into_bytes();
    }
    let trailing_newline = text.ends_with('\n');
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        match redact_line(line) {
            Some(fixed) => out.push(fixed),
            None => out.push(line.to_string()),
        }
    }
    let mut joined = out.join("\n");
    if trailing_newline {
        joined.push('\n');
    }
    joined.into_bytes()
}

/// 成功規則比照一般工具（結束碼 0），但上傳前先遮掉 `header` 裡的敏感標頭。
pub fn collect(b: BoundedOutput, duration_ms: u64) -> (StepResult, Option<Artifact>) {
    let code = b.output.code;
    let error = if b.timed_out {
        Some("timeout".to_string())
    } else {
        match code {
            Some(0) => None,
            Some(c) => Some(format!("exit_code:{c}")),
            None => Some("killed".to_string()),
        }
    };
    let mut bytes = b.output.stdout.into_bytes();
    if b.truncated {
        super::cut_to_last_line(&mut bytes);
    }
    bytes = redact_headers(bytes);
    (
        StepResult {
            scanner: Scanner::Httpx,
            ok: error.is_none(),
            exit_code: code,
            duration_ms,
            error,
        },
        Some(Artifact {
            format: "jsonl",
            bytes,
            truncated: b.truncated,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::CmdOutput;
    use crate::webscan::tools::tests::{env, files, job};

    #[test]
    fn argv_is_exactly_the_whitelist() {
        let mut j = job("8.8.8.8");
        j.target.pinned.push("2606:4700::1111".parse().unwrap());
        let f = files();
        let s = spec(&env(&j, &f, "httpx"), &Options::default());
        assert_eq!(s.program, "httpx");
        assert_eq!(
            s.args,
            argv(&[
                "-u",
                "https://shop.example.com/",
                "-json",
                "-silent",
                "-nc",
                "-duc",
                "-sc",
                "-title",
                "-server",
                "-td",
                "-ip",
                "-tls-grab",
                "-irh",
                "-timeout",
                "10",
                "-retries",
                "1",
                "-rl",
                "10",
                "-r",
                "127.0.0.1:53535",
                "-nfs",
                "-allow",
                "8.8.8.8,2606:4700::1111",
            ])
        );
        assert!(!s.args.iter().any(|a| a == "-fr" || a == "-follow-redirects"));
        assert!(s
            .env
            .contains(&("HOSTS_PATH".to_string(), f.hosts.to_string_lossy().to_string())));
        assert!(s
            .env
            .contains(&("RESOLVERS_PATH".to_string(), f.resolv.to_string_lossy().to_string())));
        assert_eq!(s.max_stdout, Some(8_388_608));
    }

    #[test]
    fn collect_redacts_sensitive_headers_but_keeps_the_rest() {
        let line = serde_json::json!({
            "url": "https://shop.example.com/",
            "status_code": 200,
            "header": {
                "set_cookie": "session=supersecrettoken; HttpOnly",
                "strict_transport_security": "max-age=63072000",
                "content_security_policy": "default-src 'self'",
                "server": "nginx"
            }
        })
        .to_string();
        let b = BoundedOutput {
            output: CmdOutput::success(&format!("{line}\n")),
            ..Default::default()
        };
        let (r, a) = collect(b, 42);
        assert!(r.ok && r.exit_code == Some(0) && r.duration_ms == 42);
        let out = String::from_utf8(a.unwrap().bytes).unwrap();
        let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        let h = &v["header"];
        // 祕密被遮掉
        assert_eq!(h["set_cookie"], "[redacted]");
        // 安全標頭與一般欄位照留
        assert_eq!(h["strict_transport_security"], "max-age=63072000");
        assert_eq!(h["content_security_policy"], "default-src 'self'");
        assert_eq!(h["server"], "nginx");
        assert_eq!(v["status_code"], 200);
        assert!(out.ends_with('\n'), "trailing newline preserved");
    }

    #[test]
    fn redact_is_noop_without_sensitive_headers() {
        let text = b"{\"status_code\":200,\"header\":{\"server\":\"nginx\"}}\n".to_vec();
        assert_eq!(redact_headers(text.clone()), text);
        // 壞掉的行原樣保留
        let broken = b"{\"status_code\":200,\"header\":{\"set_cookie\"\n".to_vec();
        assert_eq!(redact_headers(broken.clone()), broken);
    }
}
