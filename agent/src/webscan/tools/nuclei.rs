//! nuclei（<https://github.com/projectdiscovery/nuclei>，MIT）：用模板檢查已知弱點與錯誤設定（只跑 http／ssl 模板）。
//!
//! 旗標對照官方 README 的 Usage 與 `cmd/nuclei/main.go`（2026-10 查核）：
//! `-u`／`-target`、`-j`／`-jsonl`、`-silent`、`-nc`、`-duc`／`-disable-update-check`（連帶關掉啟動時的模板安裝與更新：
//! `config.DefaultConfig.CanCheckForUpdates()`）、`-ni`／`-no-interactsh`（關掉 OAST，不送資料給 interactsh 伺服器）、
//! `-dr`／`-disable-redirects`、`-t`／`-templates`、`-pt`／`-type`（只跑 http、ssl；不跑 code／headless／javascript／file…）、
//! `-etags`／`-exclude-tags`、`-s`／`-severity`、`-rl`／`-rate-limit`、`-c`／`-concurrency`、`-timeout`（秒）、`-retries`、
//! `-r`／`-resolvers`（解析器清單「檔案」）、`-or`／`-omit-raw`（JSONL 不帶 request／response 原文：命中外洩的 .env／金鑰檔時，
//! 祕密才不會整包進 artifact 與 Hub）、`-ot`／`-omit-template`（不帶編碼過的模板，縮小輸出）、
//! `-lna`／`-restrict-local-network-access`（不准連本機／私有網段；只在目標全是公網位址時加）。
//! 不加 `-sr`（不准退回系統 DNS）、不加 `-dashboard`（不上傳雲端），也不帶 `-ut`／`-ud`（模板由 `--nuclei-templates` 給、不下載）。

use serde::Deserialize;

use super::{argv, StepEnv, CONNECT_TIMEOUT_S};
use crate::util::cmd::CmdSpec;
use crate::webscan::Scanner;

/// 可以排除的模板標籤。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tag {
    Intrusive,
    Dos,
    Fuzz,
}

impl Tag {
    pub fn as_str(self) -> &'static str {
        match self {
            Tag::Intrusive => "intrusive",
            Tag::Dos => "dos",
            Tag::Fuzz => "fuzz",
        }
    }
}

/// 要跑的模板嚴重度（不收 `unknown`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub exclude_tags: Vec<Tag>,
    #[serde(default)]
    pub severities: Vec<Severity>,
}

impl Options {
    /// 要排除的標籤：Hub 給的（去重）＋**一定有 dos**（runner 強制，Hub 沒給也一樣）。
    pub fn exclude(&self) -> Vec<Tag> {
        let mut v: Vec<Tag> = Vec::new();
        for t in self.exclude_tags.iter().copied().chain([Tag::Dos]) {
            if !v.contains(&t) {
                v.push(t);
            }
        }
        v
    }

    /// 要跑的嚴重度（去重；沒給＝五種都跑）。
    pub fn severity(&self) -> Vec<Severity> {
        let mut v: Vec<Severity> = Vec::new();
        for s in &self.severities {
            if !v.contains(s) {
                v.push(*s);
            }
        }
        if v.is_empty() {
            v = Severity::ALL.to_vec();
        }
        v
    }
}

pub fn spec(env: &StepEnv, opts: &Options) -> CmdSpec {
    let t = env.target;
    let url = t.url();
    let templates = env.templates.to_string_lossy().to_string();
    let tags = opts.exclude().iter().map(|t| t.as_str()).collect::<Vec<_>>().join(",");
    let severities = opts.severity().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",");
    let rate = env.limits.rate_per_sec.to_string();
    let concurrency = env.limits.concurrency.to_string();
    let resolvers = env.files.resolvers.to_string_lossy().to_string();
    let mut args = argv(&[
        "-u",
        &url,
        "-jsonl",
        "-silent",
        "-nc",
        "-duc",
        "-ni",
        "-dr",
        "-t",
        &templates,
        "-pt",
        "http,ssl",
        "-etags",
        &tags,
        "-s",
        &severities,
        "-rl",
        &rate,
        "-c",
        &concurrency,
        "-timeout",
        CONNECT_TIMEOUT_S,
        "-retries",
        "1",
        "-r",
        &resolvers,
        "-or",
        "-ot",
    ]);
    if !t.internal {
        args.push("-lna".to_string());
    }
    // 這個工作自己的 HOME：設定目錄每次都是新的，`.nuclei-ignore` 由 JobFiles::write 從模板目錄複製進去
    env.job_home(env.pinned_dns(env.command(Scanner::Nuclei, args)))
        // 雲端上傳只在 -dashboard 或這個環境變數時才會開；明確關掉
        .with_env("ENABLE_CLOUD_UPLOAD", "false")
        .with_env("DISABLE_CLOUD_UPLOAD_WRN", "true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webscan::tools::tests::{env, files, job};

    fn opts(v: serde_json::Value) -> Options {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn argv_is_exactly_the_whitelist() {
        let j = job("8.8.8.8");
        let f = files();
        let o = opts(serde_json::json!({
            "exclude_tags": ["intrusive", "dos", "fuzz"],
            "severities": ["info", "low", "medium", "high", "critical"]
        }));
        let s = spec(&env(&j, &f, "nuclei"), &o);
        assert_eq!(
            s.args,
            argv(&[
                "-u",
                "https://shop.example.com/",
                "-jsonl",
                "-silent",
                "-nc",
                "-duc",
                "-ni",
                "-dr",
                "-t",
                "/opt/nuclei-templates",
                "-pt",
                "http,ssl",
                "-etags",
                "intrusive,dos,fuzz",
                "-s",
                "info,low,medium,high,critical",
                "-rl",
                "10",
                "-c",
                "5",
                "-timeout",
                "10",
                "-retries",
                "1",
                "-r",
                &f.resolvers.to_string_lossy(),
                "-or",
                "-ot",
                "-lna",
            ])
        );
        assert!(s
            .env
            .contains(&("HOSTS_PATH".to_string(), f.hosts.to_string_lossy().to_string())));
        assert!(s
            .env
            .contains(&("RESOLVERS_PATH".to_string(), f.resolv.to_string_lossy().to_string())));
        assert!(s
            .env
            .contains(&("ENABLE_CLOUD_UPLOAD".to_string(), "false".to_string())));
    }

    #[test]
    fn privacy_flags_are_always_present_and_no_fallbacks() {
        let j = job("8.8.8.8");
        let f = files();
        for o in [
            Options::default(),
            opts(serde_json::json!({"exclude_tags": [], "severities": ["critical"]})),
        ] {
            let s = spec(&env(&j, &f, "nuclei"), &o);
            for flag in ["-ni", "-duc", "-dr", "-or", "-ot", "-silent", "-jsonl"] {
                assert!(s.args.iter().any(|a| a == flag), "missing {flag}");
            }
            for banned in [
                "-sr",
                "-system-resolvers",
                "-ut",
                "-ud",
                "-up",
                "-dashboard",
                "-pd",
                "-code",
                "-headless",
                "-lfa",
                "-dast",
                "-fr",
            ] {
                assert!(!s.args.iter().any(|a| a == banned), "must not pass {banned}");
            }
            let pt = s.args.iter().position(|a| a == "-pt").unwrap();
            assert_eq!(s.args[pt + 1], "http,ssl");
        }
    }

    #[test]
    fn dos_is_always_excluded() {
        let j = job("8.8.8.8");
        let f = files();
        let cases = [
            (serde_json::json!({}), "dos"),
            (serde_json::json!({"exclude_tags": []}), "dos"),
            (serde_json::json!({"exclude_tags": ["intrusive"]}), "intrusive,dos"),
            (serde_json::json!({"exclude_tags": ["fuzz", "fuzz", "dos"]}), "fuzz,dos"),
        ];
        for (v, want) in cases {
            let s = spec(&env(&j, &f, "nuclei"), &opts(v.clone()));
            let i = s.args.iter().position(|a| a == "-etags").unwrap();
            assert_eq!(s.args[i + 1], want, "{v}");
            assert!(s.args[i + 1].split(',').any(|t| t == "dos"));
        }
        // 沒給嚴重度＝五種都跑（不跑 unknown）
        let s = spec(&env(&j, &f, "nuclei"), &Options::default());
        let i = s.args.iter().position(|a| a == "-s").unwrap();
        assert_eq!(s.args[i + 1], "info,low,medium,high,critical");
    }

    #[test]
    fn internal_targets_do_not_restrict_local_network() {
        let mut j = job("8.8.8.8");
        j.target.internal = true;
        let f = files();
        let s = spec(&env(&j, &f, "nuclei"), &Options::default());
        assert!(!s.args.iter().any(|a| a == "-lna"));
    }

    #[test]
    fn unknown_options_are_rejected() {
        for bad in [
            serde_json::json!({"exclude_tags": [], "severities": [], "templates": "/etc"}),
            serde_json::json!({"exclude_tags": ["rce"]}),
            serde_json::json!({"severities": ["unknown"]}),
            serde_json::json!({"exclude_tags": "dos"}),
        ] {
            assert!(serde_json::from_value::<Options>(bad.clone()).is_err(), "{bad}");
        }
    }
}
