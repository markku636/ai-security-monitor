//! 偵測這台有哪些掃描工具：啟動時跑各工具的版本指令、解析版本；找不到的工具不放進 capabilities。
//! nuclei 另外要有模板目錄（runner 不會自動下載模板），並回報模板版本（讀得到才有）。

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

use super::{Capability, Scanner};
use crate::util::cmd::{CmdOutput, CmdRunner, CmdSpec};

/// 版本指令的逾時。
const VERSION_TIMEOUT_MS: u64 = 30_000;
/// Docker 映像建置時寫的模板版本檔（`docker/Dockerfile.webscan`）。
pub const TEMPLATES_VERSION_FILE: &str = ".asm-templates-version";

/// 工具在哪裡。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    /// `--tools-dir`；省略＝從 PATH 找。
    pub dir: Option<PathBuf>,
    /// `--nuclei-templates`。
    pub templates: PathBuf,
}

impl Tools {
    pub fn program(&self, s: Scanner) -> String {
        match &self.dir {
            Some(d) => d.join(s.program()).to_string_lossy().to_string(),
            None => s.program().to_string(),
        }
    }
}

/// 版本指令（`-duc`：連版本查詢也不檢查更新）。
fn version_args(s: Scanner) -> &'static [&'static str] {
    match s {
        Scanner::Httpx | Scanner::Tlsx | Scanner::Nuclei => &["-version", "-duc"],
        Scanner::Testssl => &["--version"],
    }
}

/// 版本字串只留英數與 `.+-`、最多 32 個字元；去掉開頭的 `v`。
fn clean_version(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let v: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        .take(32)
        .collect();
    (!v.is_empty() && v.as_bytes()[0].is_ascii_digit()).then_some(v)
}

/// 從版本指令的輸出（stdout＋stderr）找版本：
/// httpx「Current Version: v1.7.4」、tlsx「Current version: v1.2.2」、nuclei「Nuclei Engine Version: v3.4.10」、
/// testssl.sh banner「testssl.sh version 3.2.2 from https://testssl.sh/」（舊版是「testssl.sh       3.0.8 from …」）。
pub fn parse_version(s: Scanner, out: &CmdOutput) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"v?\d+\.\d+(?:\.\d+)*(?:[-+.~]?[0-9A-Za-z]+)*").expect("valid regex"));
    let text = format!("{}\n{}", out.stdout, out.stderr);
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let from = match s {
            Scanner::Testssl => lower.find("testssl"),
            Scanner::Nuclei => lower.find("engine version").or_else(|| {
                if lower.contains("template") {
                    None
                } else {
                    lower.find("version")
                }
            }),
            Scanner::Httpx | Scanner::Tlsx => lower.find("version"),
        };
        let Some(from) = from else {
            continue;
        };
        if let Some(m) = re.find(&line[from..]) {
            if let Some(v) = clean_version(m.as_str()) {
                return Some(v);
            }
        }
    }
    None
}

/// nuclei 的設定目錄（`nuclei -ut -ud <dir>` 會把模板版本寫在這裡）。
fn nuclei_config_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = dirs::home_dir() {
        v.push(home.join(".config").join("nuclei"));
    }
    if let Some(c) = dirs::config_dir() {
        let d = c.join("nuclei");
        if !v.contains(&d) {
            v.push(d);
        }
    }
    v
}

/// nuclei 模板的版本：先讀映像寫的版本檔，再看 nuclei 自己的設定（目錄要是同一個）；都讀不到就省略。
pub fn templates_version(dir: &Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(dir.join(TEMPLATES_VERSION_FILE)) {
        if let Some(v) = text.lines().next().and_then(clean_version) {
            return Some(v);
        }
    }
    for cfg in nuclei_config_dirs() {
        for name in [".templates-config.json", "templates.json"] {
            let Ok(text) = std::fs::read_to_string(cfg.join(name)) else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            let same_dir = v["nuclei-templates-directory"]
                .as_str()
                .is_none_or(|d| Path::new(d) == dir);
            if let (true, Some(ver)) = (same_dir, v["nuclei-templates-version"].as_str().and_then(clean_version)) {
                return Some(ver);
            }
        }
    }
    None
}

/// 一個工具：版本指令跑得起來（而且有版本或結束碼 0）才算有；nuclei 還要有模板目錄。
async fn probe(runner: &dyn CmdRunner, tools: &Tools, s: Scanner) -> Option<Capability> {
    let spec = CmdSpec::new(&tools.program(s), version_args(s))
        .timeout(VERSION_TIMEOUT_MS)
        .describe(s.id());
    let out = runner.run(&spec).await.ok()?;
    let version = parse_version(s, &out);
    if version.is_none() && !out.ok() {
        return None;
    }
    let templates = if s == Scanner::Nuclei {
        if !tools.templates.is_dir() {
            return None;
        }
        templates_version(&tools.templates)
    } else {
        None
    };
    Some(Capability {
        scanner: s,
        version: version.unwrap_or_else(|| "unknown".to_string()),
        templates,
    })
}

/// 跑各工具的版本指令（同時跑：容器的健康檢查只有幾秒）；找不到的不列，順序固定。
pub async fn detect(runner: &dyn CmdRunner, tools: &Tools) -> Vec<Capability> {
    let (httpx, tlsx, nuclei, testssl) = tokio::join!(
        probe(runner, tools, Scanner::Httpx),
        probe(runner, tools, Scanner::Tlsx),
        probe(runner, tools, Scanner::Nuclei),
        probe(runner, tools, Scanner::Testssl),
    );
    [httpx, tlsx, nuclei, testssl].into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::FakeRunner;

    fn out(stdout: &str, stderr: &str) -> CmdOutput {
        CmdOutput {
            code: Some(0),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[test]
    fn parses_tool_version_output() {
        let httpx = out("", "\n    __    __  __       _  __\n[INF] Current Version: v1.12.0\n");
        assert_eq!(parse_version(Scanner::Httpx, &httpx).as_deref(), Some("1.12.0"));
        let tlsx = out("", "[INF] Current version: v1.4.0 (latest)\n");
        assert_eq!(parse_version(Scanner::Tlsx, &tlsx).as_deref(), Some("1.4.0"));
        let nuclei = out(
            "",
            "[INF] Nuclei Engine Version: v3.11.1\n[INF] Nuclei Config Directory: /tmp/.config/nuclei\n[INF] Nuclei Cache Directory: /tmp/.cache/nuclei\n",
        );
        assert_eq!(parse_version(Scanner::Nuclei, &nuclei).as_deref(), Some("3.11.1"));
        let testssl = out(
            "\n###########################################################\n    testssl.sh version 3.2.4 from https://testssl.sh/\n      (a1b2c3d 2026-07-12 10:00:00)\n\n      This program is free software. Distribution and\n             modification under GPLv2 permitted.\n\n Using \"OpenSSL 3.5.1 1 Jul 2025\" [~92 ciphers]\n",
            "",
        );
        assert_eq!(parse_version(Scanner::Testssl, &testssl).as_deref(), Some("3.2.4"));
        let old = out("     testssl.sh       3.0.8 from https://testssl.sh/\n", "");
        assert_eq!(parse_version(Scanner::Testssl, &old).as_deref(), Some("3.0.8"));
        let rc = out("testssl.sh version 3.2rc3 from https://testssl.sh/dev/\n", "");
        assert_eq!(parse_version(Scanner::Testssl, &rc).as_deref(), Some("3.2rc3"));
        assert_eq!(parse_version(Scanner::Httpx, &out("no version here", "")), None);
    }

    #[test]
    fn reads_the_baked_templates_version() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(templates_version(d.path()), None);
        std::fs::write(d.path().join(TEMPLATES_VERSION_FILE), "v10.5.0\n").unwrap();
        assert_eq!(templates_version(d.path()).as_deref(), Some("10.5.0"));
        std::fs::write(d.path().join(TEMPLATES_VERSION_FILE), "garbage; rm -rf /\n").unwrap();
        assert_eq!(templates_version(d.path()), None, "only version-looking text");
    }

    #[tokio::test]
    async fn detects_installed_tools_only() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(TEMPLATES_VERSION_FILE), "10.5.0\n").unwrap();
        let tools = Tools {
            dir: None,
            templates: d.path().to_path_buf(),
        };
        let fake = FakeRunner::new()
            .on("httpx -version -duc", out("", "[INF] Current Version: v1.12.0"))
            .on("nuclei -version -duc", out("", "[INF] Nuclei Engine Version: v3.11.1"))
            .on(
                "testssl.sh --version",
                out("testssl.sh version 3.2.4 from https://testssl.sh/", ""),
            );
        let caps = detect(&fake, &tools).await;
        assert_eq!(
            caps,
            vec![
                Capability {
                    scanner: Scanner::Httpx,
                    version: "1.12.0".into(),
                    templates: None
                },
                Capability {
                    scanner: Scanner::Nuclei,
                    version: "3.11.1".into(),
                    templates: Some("10.5.0".into())
                },
                Capability {
                    scanner: Scanner::Testssl,
                    version: "3.2.4".into(),
                    templates: None
                },
            ],
            "tlsx is missing"
        );
        // 沒有模板目錄：nuclei 不能跑
        let no_templates = Tools {
            dir: None,
            templates: d.path().join("missing"),
        };
        let caps = detect(&fake, &no_templates).await;
        assert!(caps.iter().all(|c| c.scanner != Scanner::Nuclei));
        // --tools-dir
        let custom = Tools {
            dir: Some(PathBuf::from("/opt/tools")),
            templates: d.path().to_path_buf(),
        };
        assert_eq!(
            Path::new(&custom.program(Scanner::Testssl)),
            Path::new("/opt/tools").join("testssl.sh")
        );
    }
}
