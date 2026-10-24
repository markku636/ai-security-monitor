//! httpx（<https://github.com/projectdiscovery/httpx>，MIT）：HTTP 探測（狀態碼、標題、伺服器、技術、IP、TLS 資訊）。
//!
//! 旗標對照官方 README 的 Usage 與 `runner/options.go`（2026-10 查核）：
//! `-u`／`-target` 目標、`-j`／`-json` JSONL、`-silent`、`-nc`／`-no-color`、`-duc`／`-disable-update-check`、
//! `-sc`、`-title`、`-server`／`-web-server`、`-td`／`-tech-detect`（內建 wappalyzer 資料，不連外）、`-ip`、
//! `-tls-grab`、`-timeout`（秒）、`-retries`、`-rl`／`-rate-limit`、`-r`／`-resolvers`（檔案或逗號分隔）、
//! `-nfs`／`-no-fallback-scheme`（只用網址的 scheme，不會退回 http 改連 80 port）、
//! `-allow`（IP／CIDR 白名單，由 fastdialer 的 network policy 在連線時強制，不在名單內的位址一律不連）。
//! 不加 `-fr`：預設不跟轉址。

use serde::Deserialize;

use super::{argv, StepEnv, CONNECT_TIMEOUT_S};
use crate::util::cmd::CmdSpec;
use crate::webscan::Scanner;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
