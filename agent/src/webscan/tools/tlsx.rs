//! tlsx（<https://github.com/projectdiscovery/tlsx>，MIT）：TLS 憑證與設定（過期、自簽、版本、cipher）。
//!
//! 旗標對照官方 README 的 Usage 與 `internal/runner/runner.go`（2026-10 查核）：
//! `-u`／`-host`（`ip:port`；IPv6 要 `[ip]:port`，裸的 IPv6 會被當成沒有 port 而丟掉）、`-sni`（每個 SNI 一個任務）、
//! `-j`／`-json`、`-silent`、`-nc`、`-duc`／`-disable-update-check`、`-ex`／`-expired`、`-ss`／`-self-signed`、
//! `-mm`／`-mismatched`、`-tv`／`-tls-version`、`-cipher`、`-timeout`（秒）。
//! 直接連釘選位址（輸入是 IP 時 tlsx 不做 DNS 解析）；不加 `-revoked`（會連第三方的 OCSP／CRL）。
//! 注意：tlsx 的 `mismatched` 是拿「輸入的主機」（這裡是 IP）比對憑證名稱，不是 SNI；
//! 要判斷憑證名稱跟網站名稱合不合，請用 JSON 的 `subject_cn`／`subject_an` 對 target.host（或看 testssl.sh 的結果）。

use serde::Deserialize;

use super::{argv, ip_port, StepEnv, CONNECT_TIMEOUT_S};
use crate::util::cmd::CmdSpec;
use crate::webscan::Scanner;

/// tlsx 沒有可調的選項（`{}`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {}

pub fn spec(env: &StepEnv, _opts: &Options) -> CmdSpec {
    let t = env.target;
    // 每個釘選位址都掃（逗號分隔）；目標本身是 IP 時只有它
    let inputs = t
        .pinned
        .iter()
        .map(|ip| ip_port(*ip, t.port))
        .collect::<Vec<_>>()
        .join(",");
    let mut args = argv(&["-u", &inputs]);
    if t.host_ip.is_none() {
        args.extend(argv(&["-sni", &t.host]));
    }
    args.extend(argv(&[
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-expired",
        "-self-signed",
        "-mismatched",
        "-tls-version",
        "-cipher",
        "-timeout",
        CONNECT_TIMEOUT_S,
    ]));
    env.job_home(env.command(Scanner::Tlsx, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webscan::tools::tests::{env, files, job};

    #[test]
    fn connects_to_pinned_ips_with_sni() {
        let mut j = job("8.8.8.8");
        j.target.pinned.push("2606:4700::1111".parse().unwrap());
        let f = files();
        let s = spec(&env(&j, &f, "tlsx"), &Options::default());
        assert_eq!(
            s.args,
            argv(&[
                "-u",
                "8.8.8.8:443,[2606:4700::1111]:443",
                "-sni",
                "shop.example.com",
                "-json",
                "-silent",
                "-nc",
                "-duc",
                "-expired",
                "-self-signed",
                "-mismatched",
                "-tls-version",
                "-cipher",
                "-timeout",
                "10",
            ])
        );
        assert!(!s.args.iter().any(|a| a.contains("revoked") || a == "-re"));
        // 不經 DNS：不需要 hosts 檔；HOME 是這個工作自己的
        assert!(!s.env.iter().any(|(k, _)| k == "HOSTS_PATH" || k == "RESOLVERS_PATH"));
        assert!(s
            .env
            .contains(&("HOME".to_string(), f.home.to_string_lossy().to_string())));
    }

    #[test]
    fn ip_targets_skip_sni() {
        let mut j = job("8.8.8.8");
        j.target.host = "8.8.8.8".into();
        j.target.host_ip = Some("8.8.8.8".parse().unwrap());
        j.target.port = 8443;
        let f = files();
        let s = spec(&env(&j, &f, "tlsx"), &Options::default());
        assert_eq!(&s.args[..3], &argv(&["-u", "8.8.8.8:8443", "-json"])[..]);
    }
}
