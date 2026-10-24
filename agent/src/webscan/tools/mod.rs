//! 掃描工具的 argv builder：每個工具一個，只吃型別化的選項＋驗證過的目標（[`Target`]）。
//! Hub 給的任何字串都不會直接變成參數：網址由驗證過的欄位重新組出來、位址是解析過的 `IpAddr`、
//! 數字是夾過的限制、路徑是 runner 自己的設定與工作目錄。
//!
//! 釘 IP（httpx、nuclei 用 ProjectDiscovery 的 fastdialer 解析名稱）：
//! - 只給 `-r <釘選解析器>` 不夠：fastdialer 預設（`DefaultOptions.ResolversFile = true`）會把 /etc/resolv.conf 的
//!   解析器排在 `-r` 前面、輪流使用（fastdialer `NewDialer`、retryabledns round robin）。
//! - 所以另外設 `RESOLVERS_PATH`＝空檔（沒有系統解析器）、`HOSTS_PATH`＝範圍內名稱→釘選位址
//!   （fastdialer metafiles；hosts 的資料優先於 DNS），`-r` 指向釘選解析器（其他名稱一律 NXDOMAIN），不加 `-sr`。
//! - httpx 再加 `-allow <釘選位址>`（fastdialer network policy：IP 白名單是排他的）；nuclei 目標全是公網時加 `-lna`。
//! - tlsx、testssl.sh 直接給 IP（不解析名稱）。
//! - 代理相關的環境變數一律拿掉（走代理時由代理自己解析名稱，會繞過釘選）。
//!
//! 每個工作一個暫存目錄（[`JobFiles`]），ProjectDiscovery 的工具用其中的 `home/` 當 HOME（設定與快取不跨工作，
//! 也讀不到映像或主機上的 `~/.config`），模板目錄的 `.nuclei-ignore` 會複製到 `home/.config/nuclei/`。

pub mod httpx;
pub mod nuclei;
pub mod testssl;
pub mod tlsx;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use super::job::{Limits, Step};
use super::scope::Target;
use super::{Scanner, StepResult};
use crate::error::AppResult;
use crate::util::cmd::{BoundedOutput, CmdSpec};

/// 工具自己每個連線的逾時（秒）。
pub const CONNECT_TIMEOUT_S: &str = "10";
/// 不讓工具繼承的環境變數：代理（會繞過釘選）、ProjectDiscovery 雲端的金鑰（不上傳任何東西）。
pub const STRIPPED_ENV: [&str; 9] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "PDCP_API_KEY",
];

/// 每個工作的暫存目錄裡的檔案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFiles {
    pub dir: PathBuf,
    /// `HOSTS_PATH`：範圍內的名稱 → 釘選位址。
    pub hosts: PathBuf,
    /// `RESOLVERS_PATH`：沒有任何 nameserver（不用系統解析器）。
    pub resolv: PathBuf,
    /// nuclei `-r` 的解析器清單檔（只有釘選解析器）。
    pub resolvers: PathBuf,
    /// testssl.sh `--jsonfile`。
    pub testssl_json: PathBuf,
    /// 這個工作專用的 HOME（ProjectDiscovery 的工具把設定、快取寫在 `~/.config`、`~/.cache`）。
    pub home: PathBuf,
}

/// nuclei 預設排除的模板清單（模板目錄裡有、要放進 nuclei 的設定目錄才會生效）。
pub const NUCLEI_IGNORE: &str = ".nuclei-ignore";

impl JobFiles {
    pub fn in_dir(dir: &Path) -> JobFiles {
        JobFiles {
            dir: dir.to_path_buf(),
            hosts: dir.join("hosts"),
            resolv: dir.join("resolv.conf"),
            resolvers: dir.join("resolvers.txt"),
            testssl_json: dir.join("testssl.json"),
            home: dir.join("home"),
        }
    }

    /// nuclei 的設定目錄（`HOME`／`XDG_CONFIG_HOME` 指到這個工作的 home）。
    pub fn nuclei_config(&self) -> PathBuf {
        self.home.join(".config").join("nuclei")
    }

    /// 寫 hosts、resolv.conf、resolvers 檔（內容都是驗證過的名稱與位址），建這個工作的 HOME，
    /// 並把 `<模板目錄>/.nuclei-ignore` 複製到 nuclei 的設定目錄（沒有就略過）。
    pub fn write(&self, target: &Target, resolver: SocketAddr, templates: &Path) -> std::io::Result<()> {
        let mut hosts = String::from("# ai-security-monitor web-scan-runner: pinned addresses for this job\n");
        for name in &target.names {
            for ip in &target.pinned {
                hosts.push_str(&format!("{ip} {name}\n"));
            }
        }
        std::fs::write(&self.hosts, hosts)?;
        std::fs::write(&self.resolv, "# no system resolvers for pinned scan jobs\n")?;
        std::fs::write(&self.resolvers, format!("{resolver}\n"))?;
        let cfg = self.nuclei_config();
        std::fs::create_dir_all(&cfg)?;
        std::fs::create_dir_all(self.home.join(".cache"))?;
        // 讀出來再寫（不用 fs::copy：映像裡的模板是唯讀檔，複製權限後 Windows 上刪不掉暫存目錄）
        match std::fs::read(templates.join(NUCLEI_IGNORE)) {
            Ok(bytes) => std::fs::write(cfg.join(NUCLEI_IGNORE), bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

/// 執行一個步驟需要的東西（都驗證過）。
pub struct StepEnv<'a> {
    pub program: String,
    pub target: &'a Target,
    pub limits: &'a Limits,
    pub files: &'a JobFiles,
    /// 釘選解析器（`127.0.0.1:<port>`）。
    pub resolver: SocketAddr,
    pub templates: &'a Path,
    /// 這一步的逾時：min(離截止的時間, limits.timeout_ms)。
    pub timeout_ms: u64,
}

impl StepEnv<'_> {
    /// 所有工具共用：在工作目錄執行、逾時、stdout 上限、拿掉代理與雲端金鑰。
    fn command(&self, scanner: Scanner, args: Vec<String>) -> CmdSpec {
        let mut spec = CmdSpec::new(&self.program, &[])
            .timeout(self.timeout_ms)
            .in_dir(&self.files.dir)
            .cap_stdout(self.limits.max_output_bytes)
            .describe(scanner.id());
        spec.args = args;
        for k in STRIPPED_ENV {
            spec = spec.without_env(k);
        }
        spec
    }

    /// httpx、nuclei（fastdialer）：名稱只從 hosts 檔與釘選解析器來。
    fn pinned_dns(&self, spec: CmdSpec) -> CmdSpec {
        spec.with_env("HOSTS_PATH", self.files.hosts.to_string_lossy())
            .with_env("RESOLVERS_PATH", self.files.resolv.to_string_lossy())
    }

    /// ProjectDiscovery 的工具（httpx、tlsx、nuclei）：用這個工作自己的 HOME，設定與快取不跨工作、
    /// 不吃到映像或主機上的 `~/.config`（例如雲端金鑰）；nuclei 從這裡讀 `.nuclei-ignore`。
    fn job_home(&self, spec: CmdSpec) -> CmdSpec {
        spec.with_env("HOME", self.files.home.to_string_lossy())
            .with_env("XDG_CONFIG_HOME", self.files.home.join(".config").to_string_lossy())
            .with_env("XDG_CACHE_HOME", self.files.home.join(".cache").to_string_lossy())
    }
}

pub(crate) fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `ip:port`（IPv6 加中括號）。
pub(crate) fn ip_port(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// 這個步驟的命令列。
pub fn spec(step: &Step, env: &StepEnv) -> CmdSpec {
    match step {
        Step::Httpx(o) => httpx::spec(env, o),
        Step::Tlsx(o) => tlsx::spec(env, o),
        Step::Nuclei(o) => nuclei::spec(env, o),
        Step::Testssl(o) => testssl::spec(env, o),
    }
}

/// 一個步驟的原始輸出（上傳成 artifact）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// `jsonl`／`json`／`txt`。
    pub format: &'static str,
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// 截斷過的 JSONL 只留完整的行。
pub fn cut_to_last_line(bytes: &mut Vec<u8>) {
    match bytes.iter().rposition(|&c| c == b'\n') {
        Some(p) => bytes.truncate(p + 1),
        None => bytes.clear(),
    }
}

/// 依各工具的成功規則整理一個步驟的結果與要上傳的 artifact。
pub fn collect(
    step: &Step,
    files: &JobFiles,
    out: AppResult<BoundedOutput>,
    duration_ms: u64,
    max_output: usize,
) -> (StepResult, Option<Artifact>) {
    let scanner = step.scanner();
    let b = match out {
        Ok(b) => b,
        // 起不來（找不到執行檔、權限）：細節只記在本機 log
        Err(_) => {
            let mut r = StepResult::failed(scanner, "spawn_failed");
            r.duration_ms = duration_ms;
            return (r, None);
        }
    };
    match step {
        Step::Testssl(_) => testssl::collect(files, b, duration_ms, max_output),
        _ => {
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
                cut_to_last_line(&mut bytes);
            }
            (
                StepResult {
                    scanner,
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
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::util::cmd::CmdOutput;
    use crate::webscan::job::{self, Job};

    pub(crate) fn job(ip: &str) -> Job {
        job::parse(job::tests::scan_job(ip), &[]).unwrap()
    }

    pub(crate) fn files() -> JobFiles {
        JobFiles::in_dir(Path::new("/work/job-1"))
    }

    pub(crate) fn env<'a>(j: &'a Job, files: &'a JobFiles, program: &str) -> StepEnv<'a> {
        StepEnv {
            program: program.to_string(),
            target: &j.target,
            limits: &j.limits,
            files,
            resolver: "127.0.0.1:53535".parse().unwrap(),
            templates: Path::new("/opt/nuclei-templates"),
            timeout_ms: 600_000,
        }
    }

    #[test]
    fn every_tool_runs_in_the_job_dir_without_proxies() {
        let j = job("8.8.8.8");
        let f = files();
        for step in &j.steps {
            let s = spec(step, &env(&j, &f, "tool"));
            assert_eq!(s.cwd.as_deref(), Some(f.dir.as_path()));
            assert_eq!(s.timeout_ms, 600_000);
            assert!(s.max_stdout.is_some());
            for k in STRIPPED_ENV {
                assert!(
                    s.env_remove.iter().any(|e| e == k),
                    "{k} not stripped for {}",
                    step.scanner()
                );
            }
            // 參數裡不會出現 Hub 原始的 target.url 以外的字串（這裡就是重新組出來的網址）
            assert!(s.args.iter().all(|a| !a.contains(' ')), "{:?}", s.args);
        }
    }

    #[test]
    fn job_files_pin_names_to_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = job("8.8.8.8");
        j.target.pinned.push("2606:4700::1111".parse().unwrap());
        j.target.names.push("www.example.com".into());
        let f = JobFiles::in_dir(dir.path());
        let no_templates = dir.path().join("no-templates");
        f.write(&j.target, "127.0.0.1:5300".parse().unwrap(), &no_templates)
            .unwrap();
        let hosts = std::fs::read_to_string(&f.hosts).unwrap();
        for line in [
            "8.8.8.8 shop.example.com",
            "2606:4700::1111 shop.example.com",
            "8.8.8.8 www.example.com",
            "2606:4700::1111 www.example.com",
        ] {
            assert!(hosts.lines().any(|l| l == line), "{hosts}");
        }
        let resolv = std::fs::read_to_string(&f.resolv).unwrap();
        assert!(!resolv.contains("nameserver"), "no system resolvers");
        assert_eq!(std::fs::read_to_string(&f.resolvers).unwrap(), "127.0.0.1:5300\n");
        // 模板目錄沒有 .nuclei-ignore：HOME 照樣建好，只是沒有那個檔
        assert!(f.nuclei_config().is_dir());
        assert!(!f.nuclei_config().join(NUCLEI_IGNORE).exists());
    }

    /// 每個工作一個 HOME：模板目錄的 .nuclei-ignore 複製到 nuclei 的設定目錄，三個 ProjectDiscovery 工具都用它。
    #[test]
    fn job_home_carries_the_nuclei_ignore_file() {
        let dir = tempfile::tempdir().unwrap();
        let templates = dir.path().join("templates");
        std::fs::create_dir(&templates).unwrap();
        std::fs::write(templates.join(NUCLEI_IGNORE), "tags:\n  - fuzz\n  - dos\n").unwrap();
        let work = dir.path().join("job-1");
        std::fs::create_dir(&work).unwrap();
        let j = job("8.8.8.8");
        let f = JobFiles::in_dir(&work);
        f.write(&j.target, "127.0.0.1:5300".parse().unwrap(), &templates)
            .unwrap();
        assert_eq!(f.nuclei_config(), work.join("home").join(".config").join("nuclei"));
        assert_eq!(
            std::fs::read_to_string(f.nuclei_config().join(NUCLEI_IGNORE)).unwrap(),
            "tags:\n  - fuzz\n  - dos\n"
        );
        let home = f.home.to_string_lossy().to_string();
        let config = f.home.join(".config").to_string_lossy().to_string();
        for step in &j.steps {
            let s = spec(step, &env(&j, &f, "tool"));
            let has = |k: &str, v: &str| s.env.contains(&(k.to_string(), v.to_string()));
            match step.scanner() {
                Scanner::Testssl => assert!(!s.env.iter().any(|(k, _)| k == "HOME")),
                other => {
                    assert!(has("HOME", &home), "{other} HOME");
                    assert!(has("XDG_CONFIG_HOME", &config), "{other} XDG_CONFIG_HOME");
                }
            }
        }
        // 暫存目錄整個刪得掉（複製過來的檔案不是唯讀）
        std::fs::remove_dir_all(&work).unwrap();
    }

    #[test]
    fn jsonl_results_and_truncation() {
        let j = job("8.8.8.8");
        let f = files();
        let ok = BoundedOutput {
            output: CmdOutput::success("{\"a\":1}\n{\"b\":2}\n"),
            ..Default::default()
        };
        let (r, a) = collect(&j.steps[0], &f, Ok(ok), 12, 1024);
        assert!(r.ok && r.error.is_none() && r.exit_code == Some(0) && r.duration_ms == 12);
        let a = a.unwrap();
        assert_eq!((a.format, a.truncated), ("jsonl", false));
        assert_eq!(a.bytes, b"{\"a\":1}\n{\"b\":2}\n");
        // 截斷：只留完整的行
        let cut = BoundedOutput {
            output: CmdOutput::success("{\"a\":1}\n{\"b\":"),
            truncated: true,
            ..Default::default()
        };
        let (r, a) = collect(&j.steps[2], &f, Ok(cut), 5, 1024);
        assert!(r.ok);
        let a = a.unwrap();
        assert!(a.truncated);
        assert_eq!(a.bytes, b"{\"a\":1}\n");
        // 逾時、非 0 結束碼、起不來
        let to = BoundedOutput {
            output: CmdOutput {
                code: None,
                stdout: "{\"partial\":true}\n".into(),
                stderr: String::new(),
            },
            timed_out: true,
            ..Default::default()
        };
        let (r, a) = collect(&j.steps[1], &f, Ok(to), 5, 1024);
        assert_eq!((r.ok, r.error.as_deref(), r.exit_code), (false, Some("timeout"), None));
        assert_eq!(a.unwrap().bytes, b"{\"partial\":true}\n", "partial output kept");
        let bad = BoundedOutput {
            output: CmdOutput::failure(2, "flag provided but not defined"),
            ..Default::default()
        };
        let (r, _) = collect(&j.steps[0], &f, Ok(bad), 5, 1024);
        assert_eq!(r.error.as_deref(), Some("exit_code:2"));
        let (r, a) = collect(
            &j.steps[0],
            &f,
            Err(crate::error::AppError::External("x".into())),
            3,
            1024,
        );
        assert_eq!((r.error.as_deref(), r.duration_ms), (Some("spawn_failed"), 3));
        assert!(a.is_none());
    }
}
