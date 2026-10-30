//! 掃描工作（`contract/webscan-job.v1.json` 的 JobSpec）的解析與驗證。
//!
//! 每個掃描器的 `options` 是型別嚴格的（`deny_unknown_fields`）；不認得的掃描器、選項不合、同一個掃描器出現兩次、
//! 層級不准跑的掃描器（`passive` 只准 httpx／tlsx）→ `bad_job:<原因>`，什麼都不執行。
//! 限制一律夾到安全範圍：rate 1–50、concurrency 1–10、逾時 ≤ 3 小時、輸出 ≤ 32 MiB。

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

use super::scope::{self, Target};
use super::tools::{httpx, nuclei, testssl, tlsx};
use super::{clean_detail, Scanner};

pub const MIN_RATE: u64 = 1;
pub const MAX_RATE: u64 = 50;
pub const MIN_CONCURRENCY: u64 = 1;
pub const MAX_CONCURRENCY: u64 = 10;
pub const MIN_TIMEOUT_MS: u64 = 1_000;
pub const MAX_TIMEOUT_MS: u64 = 3 * 3600 * 1000;
pub const MIN_OUTPUT_BYTES: u64 = 4 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;
/// 擁有權驗證的 token：英數、底線、連字號。
const TOKEN_MIN: usize = 8;
const TOKEN_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Scan,
    Verify,
}

/// 掃描層級：`passive` 已登錄就能跑（只做跟一般瀏覽器差不多的請求）；`active_light` 由管理員手動發起。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Passive,
    ActiveLight,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawTarget {
    pub id: String,
    pub url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub pinned_ips: Vec<String>,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawScope {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub allowed_private_cidrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RawLimits {
    pub timeout_ms: u64,
    pub rate_per_sec: u64,
    pub concurrency: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawStep {
    pub scanner: String,
    pub options: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
// Legacy wire types are decoded for compatibility; execution rejects verify jobs.
pub enum VerifyMethod {
    #[serde(rename = "well-known")]
    WellKnown,
    #[serde(rename = "meta")]
    Meta,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Verify {
    pub method: VerifyMethod,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawJob {
    pub id: String,
    pub kind: JobKind,
    pub profile: Profile,
    pub lease_ms: u64,
    pub deadline: DateTime<Utc>,
    pub target: RawTarget,
    pub scope: RawScope,
    pub limits: RawLimits,
    #[serde(default)]
    pub steps: Vec<RawStep>,
    #[serde(default)]
    pub verify: Option<Verify>,
}

/// 型別化的步驟（選項已驗證）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Httpx(httpx::Options),
    Tlsx(tlsx::Options),
    Nuclei(nuclei::Options),
    Testssl(testssl::Options),
}

impl Step {
    pub fn scanner(&self) -> Scanner {
        match self {
            Step::Httpx(_) => Scanner::Httpx,
            Step::Tlsx(_) => Scanner::Tlsx,
            Step::Nuclei(_) => Scanner::Nuclei,
            Step::Testssl(_) => Scanner::Testssl,
        }
    }
}

/// 夾過的限制。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub timeout_ms: u64,
    pub rate_per_sec: u32,
    pub concurrency: u32,
    pub max_output_bytes: usize,
}

impl Limits {
    pub fn clamp(raw: &RawLimits) -> Limits {
        Limits {
            timeout_ms: raw.timeout_ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS),
            rate_per_sec: raw.rate_per_sec.clamp(MIN_RATE, MAX_RATE) as u32,
            concurrency: raw.concurrency.clamp(MIN_CONCURRENCY, MAX_CONCURRENCY) as u32,
            max_output_bytes: raw.max_output_bytes.clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES) as usize,
        }
    }
}

/// 驗證過、可以執行的工作。
#[derive(Debug, Clone)]
pub struct Job {
    pub id: String,
    pub kind: JobKind,
    pub profile: Profile,
    pub lease: Duration,
    pub deadline: DateTime<Utc>,
    pub target: Target,
    pub limits: Limits,
    pub steps: Vec<Step>,
    pub verify: Option<Verify>,
}

/// 結構檢查過、還沒做範圍檢查的工作。
#[derive(Debug, Clone)]
pub struct Decoded {
    pub raw: RawJob,
    pub limits: Limits,
    pub steps: Vec<Step>,
}

/// 不執行的原因（整個工作回報成 `error`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// 工作內容不合（`bad_job:<原因>`）。
    BadJob(String),
    /// 範圍檢查不過（`blocked_target:<原因>`）。
    Blocked(scope::Blocked),
}

impl Rejection {
    pub fn code(&self) -> String {
        match self {
            Rejection::BadJob(r) => format!("bad_job:{r}"),
            Rejection::Blocked(b) => format!("blocked_target:{}", b.code()),
        }
    }
}

fn bad(reason: impl Into<String>) -> Rejection {
    Rejection::BadJob(reason.into())
}

/// 工作 id（會放進網址路徑；格式不對就沒辦法回報，只能略過）。
pub fn job_id(raw: &Value) -> Option<String> {
    raw.get("id")
        .and_then(Value::as_str)
        .filter(|id| crate::hub::webscan::valid_job_id(id))
        .map(str::to_string)
}

fn options<T: DeserializeOwned>(scanner: Scanner, v: Value) -> Result<T, Rejection> {
    // 只收 JSON 物件（serde 也接受用陣列表示 struct，這裡不准）
    if !v.is_object() {
        return Err(bad(format!("bad_options:{scanner}:not_an_object")));
    }
    serde_json::from_value(v).map_err(|e| bad(format!("bad_options:{scanner}:{}", clean_detail(&e.to_string(), 160))))
}

/// 這個層級准不准跑這個掃描器（跟 Hub 的 tierMin 一樣：nuclei、testssl 要 active_light）。
pub fn allowed(profile: Profile, scanner: Scanner) -> bool {
    match scanner {
        Scanner::Httpx | Scanner::Tlsx => true,
        Scanner::Nuclei | Scanner::Testssl => profile == Profile::ActiveLight,
    }
}

fn valid_token(t: &str) -> bool {
    (TOKEN_MIN..=TOKEN_MAX).contains(&t.len()) && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// 結構檢查：JSON 形狀、掃描器與選項、層級、種類（掃描要有步驟、驗證要有 verify）、限制。
pub fn decode(raw: Value) -> Result<Decoded, Rejection> {
    let raw: RawJob =
        serde_json::from_value(raw).map_err(|e| bad(format!("invalid:{}", clean_detail(&e.to_string(), 160))))?;
    let mut steps: Vec<Step> = Vec::with_capacity(raw.steps.len());
    for s in &raw.steps {
        let Some(scanner) = Scanner::from_id(&s.scanner) else {
            return Err(bad(format!("unknown_scanner:{}", clean_detail(&s.scanner, 40))));
        };
        if steps.iter().any(|x| x.scanner() == scanner) {
            return Err(bad(format!("duplicate_step:{scanner}")));
        }
        if !allowed(raw.profile, scanner) {
            return Err(bad(format!("scanner_not_allowed:{scanner}")));
        }
        let opts = s.options.clone();
        steps.push(match scanner {
            Scanner::Httpx => Step::Httpx(options(scanner, opts)?),
            Scanner::Tlsx => Step::Tlsx(options(scanner, opts)?),
            Scanner::Nuclei => Step::Nuclei(options(scanner, opts)?),
            Scanner::Testssl => Step::Testssl(options(scanner, opts)?),
        });
    }
    match raw.kind {
        JobKind::Scan => {
            if steps.is_empty() {
                return Err(bad("no_steps"));
            }
            if raw.verify.is_some() {
                return Err(bad("unexpected_verify"));
            }
        }
        JobKind::Verify => {
            let Some(v) = &raw.verify else {
                return Err(bad("missing_verify"));
            };
            if !steps.is_empty() {
                return Err(bad("unexpected_steps"));
            }
            if !valid_token(&v.token) {
                return Err(bad("bad_verify_token"));
            }
        }
    }
    let limits = Limits::clamp(&raw.limits);
    Ok(Decoded { raw, limits, steps })
}

/// 結構檢查＋範圍檢查（`self_ips`＝這台自己所有網卡的位址）。
pub fn parse(raw: Value, self_ips: &[IpAddr]) -> Result<Job, Rejection> {
    let d = decode(raw)?;
    let target = scope::check(&d.raw.target, &d.raw.scope, self_ips).map_err(Rejection::Blocked)?;
    Ok(Job {
        id: d.raw.id,
        kind: d.raw.kind,
        profile: d.raw.profile,
        lease: Duration::from_millis(d.raw.lease_ms),
        deadline: d.raw.deadline,
        target,
        limits: d.limits,
        steps: d.steps,
        verify: d.raw.verify,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// 契約裡的掃描工作，釘選位址換成 `ip`（契約用的是文件用網段 203.0.113.10，runner 會擋）。
    pub(crate) fn scan_job(ip: &str) -> Value {
        json!({
            "id": "wsj_0123456789abcdef",
            "kind": "scan",
            "profile": "active_light",
            "lease_ms": 120000,
            "deadline": "2099-10-24T09:20:00.000Z",
            "target": {
                "id": "wt_0123456789abcdef",
                "url": "https://shop.example.com/",
                "scheme": "https",
                "host": "shop.example.com",
                "port": 443,
                "path": "/",
                "pinned_ips": [ip],
                "internal": false
            },
            "scope": { "hosts": ["shop.example.com"], "allowed_private_cidrs": [] },
            "limits": { "timeout_ms": 900000, "rate_per_sec": 10, "concurrency": 5, "max_output_bytes": 8388608 },
            "steps": [
                { "scanner": "httpx", "options": {} },
                { "scanner": "tlsx", "options": {} },
                { "scanner": "nuclei", "options": { "exclude_tags": ["intrusive", "dos", "fuzz"], "severities": ["info", "low", "medium", "high", "critical"] } },
                { "scanner": "testssl", "options": { "fast": false } }
            ],
            "verify": null
        })
    }

    pub(crate) fn verify_job(ip: &str) -> Value {
        let mut j = scan_job(ip);
        j["id"] = json!("wsj_fedcba9876543210");
        j["kind"] = json!("verify");
        j["profile"] = json!("passive");
        j["steps"] = json!([]);
        j["verify"] = json!({ "method": "well-known", "token": "asm-verify-6f1c2b9a0d4e8f7a6b5c4d3e2f1a0b9c" });
        j
    }

    fn reason(v: Value) -> String {
        parse(v, &[]).unwrap_err().code()
    }

    #[test]
    fn contract_shaped_jobs_parse() {
        let j = parse(scan_job("8.8.8.8"), &[]).unwrap();
        assert_eq!(j.id, "wsj_0123456789abcdef");
        assert_eq!((j.kind, j.profile), (JobKind::Scan, Profile::ActiveLight));
        assert_eq!(j.lease, Duration::from_secs(120));
        assert_eq!(
            j.steps.iter().map(Step::scanner).collect::<Vec<_>>(),
            Scanner::ALL.to_vec()
        );
        assert_eq!(
            j.limits,
            Limits {
                timeout_ms: 900_000,
                rate_per_sec: 10,
                concurrency: 5,
                max_output_bytes: 8_388_608
            }
        );
        let v = parse(verify_job("8.8.8.8"), &[]).unwrap();
        assert_eq!(v.kind, JobKind::Verify);
        assert_eq!(v.verify.unwrap().method, VerifyMethod::WellKnown);
    }

    #[test]
    fn limits_are_clamped() {
        let mut j = scan_job("8.8.8.8");
        j["limits"] = json!({ "timeout_ms": 99_999_999_999u64, "rate_per_sec": 5000, "concurrency": 0, "max_output_bytes": 1u64 << 40 });
        let l = parse(j, &[]).unwrap().limits;
        assert_eq!(
            l,
            Limits {
                timeout_ms: MAX_TIMEOUT_MS,
                rate_per_sec: 50,
                concurrency: 1,
                max_output_bytes: 32 * 1024 * 1024
            }
        );
        let mut j = scan_job("8.8.8.8");
        j["limits"] = json!({ "timeout_ms": 0, "rate_per_sec": 0, "concurrency": 99, "max_output_bytes": 0 });
        let l = parse(j, &[]).unwrap().limits;
        assert_eq!((l.timeout_ms, l.rate_per_sec, l.concurrency), (MIN_TIMEOUT_MS, 1, 10));
        assert_eq!(l.max_output_bytes, MIN_OUTPUT_BYTES as usize);
    }

    #[test]
    fn strict_options_and_unknown_scanners_are_bad_jobs() {
        let with_step = |step: Value| {
            let mut j = scan_job("8.8.8.8");
            j["steps"] = json!([step]);
            reason(j)
        };
        assert_eq!(
            with_step(json!({"scanner": "zap", "options": {}})),
            "bad_job:unknown_scanner:zap"
        );
        assert!(
            with_step(json!({"scanner": "httpx", "options": {"follow_redirects": true}}))
                .starts_with("bad_job:bad_options:httpx:")
        );
        assert!(with_step(json!({"scanner": "tlsx", "options": {"revoked": true}}))
            .starts_with("bad_job:bad_options:tlsx:"));
        assert!(with_step(
            json!({"scanner": "nuclei", "options": {"exclude_tags": [], "severities": [], "templates": "/etc"}})
        )
        .starts_with("bad_job:bad_options:nuclei:"));
        assert!(
            with_step(json!({"scanner": "nuclei", "options": {"exclude_tags": ["rce"]}}))
                .starts_with("bad_job:bad_options:nuclei:")
        );
        assert!(
            with_step(json!({"scanner": "nuclei", "options": {"severities": ["unknown"]}}))
                .starts_with("bad_job:bad_options:nuclei:")
        );
        assert!(with_step(json!({"scanner": "testssl", "options": {"fast": "yes"}}))
            .starts_with("bad_job:bad_options:testssl:"));
        assert!(
            with_step(json!({"scanner": "testssl", "options": {"fast": true, "extra": "--phone-out"}}))
                .starts_with("bad_job:bad_options:testssl:")
        );
        assert_eq!(
            with_step(json!({"scanner": "httpx", "options": null})),
            "bad_job:bad_options:httpx:not_an_object"
        );
        assert_eq!(
            with_step(json!({"scanner": "nuclei", "options": [["dos"], ["info"]]})),
            "bad_job:bad_options:nuclei:not_an_object"
        );
        // 步驟本身多出欄位、少了 options
        assert!(with_step(json!({"scanner": "httpx", "options": {}, "args": ["-x"]})).starts_with("bad_job:invalid:"));
        assert!(with_step(json!({"scanner": "httpx"})).starts_with("bad_job:invalid:"));
        let mut j = scan_job("8.8.8.8");
        j["steps"] = json!([{"scanner": "httpx", "options": {}}, {"scanner": "httpx", "options": {}}]);
        assert_eq!(reason(j), "bad_job:duplicate_step:httpx");
    }

    #[test]
    fn profile_kind_and_verify_rules() {
        let mut j = scan_job("8.8.8.8");
        j["profile"] = json!("passive");
        assert_eq!(reason(j), "bad_job:scanner_not_allowed:nuclei");
        let mut j = scan_job("8.8.8.8");
        j["profile"] = json!("passive");
        j["steps"] = json!([{"scanner": "httpx", "options": {}}, {"scanner": "tlsx", "options": {}}]);
        assert!(parse(j, &[]).is_ok(), "passive may run httpx and tlsx");
        let mut j = scan_job("8.8.8.8");
        j["profile"] = json!("aggressive");
        assert!(reason(j).starts_with("bad_job:invalid:"));
        let mut j = scan_job("8.8.8.8");
        j["steps"] = json!([]);
        assert_eq!(reason(j), "bad_job:no_steps");
        let mut j = verify_job("8.8.8.8");
        j["verify"] = Value::Null;
        assert_eq!(reason(j), "bad_job:missing_verify");
        let mut j = verify_job("8.8.8.8");
        j["steps"] = json!([{"scanner": "httpx", "options": {}}]);
        assert_eq!(reason(j), "bad_job:unexpected_steps");
        let mut j = scan_job("8.8.8.8");
        j["verify"] = json!({"method": "meta", "token": "abcdefgh12"});
        assert_eq!(reason(j), "bad_job:unexpected_verify");
        for tok in ["short", "has space token", "tok<script>1234", &"x".repeat(129)] {
            let mut j = verify_job("8.8.8.8");
            j["verify"]["token"] = json!(tok);
            assert_eq!(reason(j), "bad_job:bad_verify_token", "{tok}");
        }
        let mut j = verify_job("8.8.8.8");
        j["verify"]["method"] = json!("dns-txt");
        assert!(reason(j).starts_with("bad_job:invalid:"));
    }

    #[test]
    fn scope_failures_are_blocked_targets() {
        assert_eq!(reason(scan_job("127.0.0.1")), "blocked_target:loopback");
        assert_eq!(reason(scan_job("10.0.0.1")), "blocked_target:private_not_allowed");
        assert_eq!(reason(scan_job("203.0.113.10")), "blocked_target:reserved");
        assert_eq!(
            parse(scan_job("8.8.4.4"), &["8.8.4.4".parse().unwrap()]).unwrap_err(),
            Rejection::Blocked(scope::Blocked::SelfAddr)
        );
        let mut j = scan_job("8.8.8.8");
        j["target"]["url"] = json!("https://evil.example.net/");
        assert_eq!(reason(j), "blocked_target:url_mismatch");
    }

    #[test]
    fn ids_must_be_path_safe() {
        assert_eq!(job_id(&scan_job("8.8.8.8")).as_deref(), Some("wsj_0123456789abcdef"));
        assert_eq!(job_id(&json!({"id": "../../admin"})), None);
        assert_eq!(job_id(&json!({"id": 5})), None);
        assert_eq!(job_id(&json!("nope")), None);
    }
}
