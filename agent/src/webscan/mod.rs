//! 網站弱點掃描 runner（`ai-security-monitor web-scan-runner`，選用；Docker sidecar，比照防護 DNS 的 `dns-server --hub`）。
//!
//! 向 Security Hub 認領「掃描工作」，在這台用開源掃描器（httpx、tlsx、nuclei、testssl.sh）掃使用者自己驗證過擁有權
//! （或管理員列入內網白名單）的網站，把原始輸出與結果交回 Hub。這是防禦用途；範圍由 Hub 與 runner 雙重強制：
//!
//! - **範圍**（[`scope`]）：執行任何步驟前先檢查工作：只准 http／https、網址要跟目標欄位一致、目標要在範圍內；
//!   釘選位址不能是 loopback／link-local／multicast／保留網段／雲端 metadata／這台自己（含預設閘道，也就是 Docker 主機），私有位址要落在管理員的內網白名單。
//!   任何一項不過，整個工作回報 `blocked_target:<原因>`，什麼都不執行。
//! - **釘 IP**：工具只連 Hub 釘選的位址。每個工作一個只回釘選位址的 DNS（[`resolver`]）＋hosts 檔
//!   （httpx、nuclei），tlsx 與 testssl.sh 直接給 IP；runner 自己的 HTTP（擁有權驗證）用 reqwest 的 resolve 覆寫。
//! - **參數只由白名單組**（[`tools`]）：每個工具一個 argv builder，只吃型別化的選項＋驗證過的目標，
//!   Hub 給的字串一律不直接拼進命令列。
//! - **不送資料給第三方**：關掉更新檢查、interactsh、雲端上傳；不自動下載或更新 nuclei 模板。
//! - **資源上限**：每步逾時（殺整棵子行程）、輸出上限、每個工作一個暫存目錄（結束刪掉）。

pub mod caps;
pub mod exec;
pub mod job;
pub mod resolver;
pub mod runner;
pub mod scope;
pub mod tools;
pub mod verify;

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `--work-dir` 省略時，設定目錄下放每個工作暫存目錄的地方。
pub const WORK_DIR: &str = "webscan-work";
/// `--nuclei-templates` 的預設（Docker 映像把模板烘焙在這裡）。
pub const DEFAULT_NUCLEI_TEMPLATES: &str = "/opt/nuclei-templates";

/// 支援的掃描器。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scanner {
    Httpx,
    Tlsx,
    Nuclei,
    Testssl,
}

impl Scanner {
    pub const ALL: [Scanner; 4] = [Scanner::Httpx, Scanner::Tlsx, Scanner::Nuclei, Scanner::Testssl];

    /// 契約裡的 id（`httpx`／`tlsx`／`nuclei`／`testssl`）。
    pub fn id(self) -> &'static str {
        match self {
            Scanner::Httpx => "httpx",
            Scanner::Tlsx => "tlsx",
            Scanner::Nuclei => "nuclei",
            Scanner::Testssl => "testssl",
        }
    }

    pub fn from_id(s: &str) -> Option<Scanner> {
        Scanner::ALL.into_iter().find(|x| x.id() == s)
    }

    /// 執行檔名稱（`--tools-dir` 省略時從 PATH 找）。
    pub fn program(self) -> &'static str {
        match self {
            Scanner::Httpx => "httpx",
            Scanner::Tlsx => "tlsx",
            Scanner::Nuclei => "nuclei",
            Scanner::Testssl => "testssl.sh",
        }
    }
}

impl std::fmt::Display for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// 這台有的掃描器與版本（認領時告訴 Hub）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Capability {
    pub scanner: Scanner,
    pub version: String,
    /// nuclei 模板的版本（讀得到才有）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<String>,
}

/// 認領工作（`POST /api/v1/webscan/jobs/claim`，`contract/webscan-claim.v1.json`）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Claim {
    /// runner（ai-security-monitor）的版本。
    pub version: String,
    pub hostname: String,
    pub capabilities: Vec<Capability>,
    /// 這次最多拿幾個工作（空出來的名額）。
    pub max_jobs: u8,
    /// 這台自己所有網卡的位址＋預設閘道（Hub 不會把這些位址當成目標）。
    pub self_ips: Vec<IpAddr>,
}

/// 認領的回應（`contract/webscan-job.v1.json`）。工作逐一解析：一個壞掉不影響其他的，而且還能用它的 id 回報 `bad_job`。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClaimResponse {
    #[serde(default)]
    pub jobs: Vec<Value>,
    #[serde(default)]
    pub poll_after_ms: Option<u64>,
    #[serde(default)]
    pub server_time: Option<DateTime<Utc>>,
}

/// 心跳（`POST /api/v1/webscan/jobs/{id}/heartbeat`，`contract/webscan-heartbeat.v1.json`）。
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Heartbeat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<Scanner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// 0～1。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
}

/// 心跳的回應：`cancel` 是 true 就馬上停。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeartbeatReply {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub lease_expires_at: Option<String>,
    #[serde(default)]
    pub cancel: bool,
}

/// 一個步驟的結果。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StepResult {
    pub scanner: Scanner,
    pub ok: bool,
    /// 被殺掉（逾時、取消）或根本沒執行時是 null。
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl StepResult {
    /// 沒執行或執行失敗（沒有結束碼）。
    pub fn failed(scanner: Scanner, error: impl Into<String>) -> StepResult {
        StepResult {
            scanner,
            ok: false,
            exit_code: None,
            duration_ms: 0,
            error: Some(error.into()),
        }
    }
}

/// 擁有權驗證的結果。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifyResult {
    pub found: bool,
    /// 沒拿到 HTTP 回應時是 null。
    pub http_status: Option<u16>,
    pub detail: String,
}

/// 工作結果（`POST /api/v1/webscan/jobs/{id}/results`，`contract/webscan-result.v1.json`）。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JobResult {
    pub ok: bool,
    pub error: Option<String>,
    pub steps: Vec<StepResult>,
    pub verify: Option<VerifyResult>,
}

impl JobResult {
    /// 整個工作沒做（`bad_job:…`、`blocked_target:…`、`runner_stopped`…）。
    pub fn failed(error: impl Into<String>) -> JobResult {
        JobResult {
            ok: false,
            error: Some(error.into()),
            steps: Vec::new(),
            verify: None,
        }
    }

    /// 掃描做完：至少一個步驟成功才算 ok，個別失敗看各步驟。
    pub fn from_steps(steps: Vec<StepResult>) -> JobResult {
        let ok = steps.iter().any(|s| s.ok);
        JobResult {
            ok,
            error: (!ok).then(|| "all_steps_failed".to_string()),
            steps,
            verify: None,
        }
    }
}

/// 給人看、也會送回 Hub 的錯誤細節：只留可見 ASCII，最多 `max` 個字元。
pub fn clean_detail(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .take(max)
        .collect()
}

/// 印一行 log：服務模式寫每日 log 檔，否則印到 stderr（`quiet` 時只印錯誤）。
pub(crate) fn log(quiet: bool, msg: &str) {
    let line = format!("[{}] {msg}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    if crate::service::instance::log_enabled() {
        crate::service::instance::write_log(&line);
    } else if !quiet {
        eprintln!("{line}");
    }
}

/// 契約範例（`contract/webscan-claim.v1.json`）。
#[doc(hidden)]
pub fn sample_claim() -> Claim {
    let cap = |scanner, version: &str, templates: Option<&str>| Capability {
        scanner,
        version: version.into(),
        templates: templates.map(str::to_string),
    };
    Claim {
        version: "0.9.0".into(),
        hostname: "webscan-01".into(),
        capabilities: vec![
            cap(Scanner::Httpx, "1.7.4", None),
            cap(Scanner::Tlsx, "1.2.2", None),
            cap(Scanner::Nuclei, "3.4.10", Some("10.3.1")),
            cap(Scanner::Testssl, "3.2.2", None),
        ],
        max_jobs: 1,
        self_ips: vec!["172.20.0.5".parse().expect("valid ip")],
    }
}

/// 契約範例（`contract/webscan-heartbeat.v1.json`）。
#[doc(hidden)]
pub fn sample_heartbeat() -> Heartbeat {
    Heartbeat {
        step: Some(Scanner::Nuclei),
        message: Some("nuclei 2/4".into()),
        progress: Some(0.5),
    }
}

/// 契約範例（`contract/webscan-result.v1.json`）。
#[doc(hidden)]
pub fn sample_result() -> JobResult {
    let step = |scanner, ok, exit_code, duration_ms, error: Option<&str>| StepResult {
        scanner,
        ok,
        exit_code: Some(exit_code),
        duration_ms,
        error: error.map(str::to_string),
    };
    JobResult {
        ok: true,
        error: None,
        steps: vec![
            step(Scanner::Httpx, true, 0, 1530, None),
            step(Scanner::Tlsx, true, 0, 820, None),
            step(Scanner::Nuclei, true, 0, 184_000, None),
            step(Scanner::Testssl, false, 245, 60_000, Some("timeout")),
        ],
        verify: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_ids_round_trip() {
        for s in Scanner::ALL {
            assert_eq!(Scanner::from_id(s.id()), Some(s));
            assert_eq!(serde_json::to_value(s).unwrap(), s.id());
        }
        assert_eq!(Scanner::from_id("zap"), None);
        assert_eq!(Scanner::Testssl.program(), "testssl.sh");
    }

    #[test]
    fn job_result_ok_needs_one_good_step() {
        let r = JobResult::from_steps(vec![StepResult::failed(Scanner::Httpx, "timeout")]);
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("all_steps_failed"));
        let v = serde_json::to_value(JobResult::failed("bad_job:no_steps")).unwrap();
        assert_eq!(v["verify"], Value::Null);
        assert_eq!(v["steps"], serde_json::json!([]));
    }

    #[test]
    fn details_are_printable_ascii() {
        assert_eq!(clean_detail("a\nb\u{7f}中", 10), "a?b??");
        assert_eq!(clean_detail("abcdef", 3), "abc");
    }
}
