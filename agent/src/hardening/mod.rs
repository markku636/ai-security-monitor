//! 系統硬化檢查：依 `feeds/policies/<os>.yml` 逐條取值比對，給通過／未通過／不適用與 0–100 分（嚴重度加權）。
//! 防火牆設定由 fw 引擎負責，這裡不重複。

pub mod policy;
pub mod probe;

use std::path::Path;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppResult;
use crate::model::finding::{CheckResult, Evidence, Finding, ScannerId, Severity};
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};
use crate::util::cmd::CmdRunner;
use crate::util::text::clip;
use policy::{Check, Missing, Op};
use probe::{Observed, ProbeEnv};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub result: CheckResult,
    pub observed: String,
    pub expected: String,
    pub remediation: String,
    pub rationale: String,
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HardeningReport {
    pub os_family: String,
    pub pass: u32,
    pub fail: u32,
    pub na: u32,
    pub error: u32,
    pub score: u8,
    /// 需要系統管理員／root 才能檢查的項目。
    pub needs_admin: Vec<String>,
    pub results: Vec<Outcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn os_family() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// `/etc/os-release` 的 ID 與 ID_LIKE（小寫）。
pub fn distro_ids(os_release: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in os_release.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k == "ID" || k == "ID_LIKE" {
                out.extend(v.trim_matches('"').split_whitespace().map(|s| s.to_ascii_lowercase()));
            }
        }
    }
    out
}

fn norm(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_lowercase(),
        Value::Number(n) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", f as i64),
            Some(f) => f.to_string(),
            None => n.to_string(),
        },
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn loose_eq(a: &Value, b: &Value) -> bool {
    norm(a) == norm(b)
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

fn display(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(display).collect::<Vec<_>>().join(", "),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    clip(s.trim(), 200)
}

fn test(op: Op, v: &Value, e: &Value) -> bool {
    let num = |x: &Value| norm(x).parse::<f64>().ok();
    let contains = || match v {
        Value::Array(a) => a.iter().any(|x| loose_eq(x, e)),
        _ => norm(v).contains(&norm(e)),
    };
    let one_of = || e.as_array().is_some_and(|a| a.iter().any(|x| loose_eq(v, x)));
    match op {
        Op::Eq => loose_eq(v, e),
        Op::Ne => !loose_eq(v, e),
        Op::Gte => matches!((num(v), num(e)), (Some(a), Some(b)) if a >= b),
        Op::Lte => matches!((num(v), num(e)), (Some(a), Some(b)) if a <= b),
        Op::Contains => contains(),
        Op::NotContains => !contains(),
        Op::Matches => e
            .as_str()
            .and_then(|p| regex::RegexBuilder::new(p).case_insensitive(true).build().ok())
            .is_some_and(|re| re.is_match(&display(v))),
        Op::In => one_of(),
        Op::NotIn => !one_of(),
        Op::Empty => is_empty(v),
        Op::NotEmpty => !is_empty(v),
    }
}

pub fn expected_text(c: &Check) -> String {
    match c.expect.op {
        Op::Empty | Op::NotEmpty => c.expect.op.as_str().to_string(),
        op => format!("{} {}", op.as_str(), display(&c.expect.value)),
    }
}

/// 比對一條檢查的觀察值。
pub fn evaluate(c: &Check, o: &Observed) -> (CheckResult, String, Option<String>) {
    match o {
        Observed::Missing => {
            let r = match c.missing {
                Missing::Pass => CheckResult::Pass,
                Missing::Fail => CheckResult::Fail,
                Missing::Na => CheckResult::NotApplicable,
            };
            (r, String::new(), Some(t!("讀不到設定值（使用系統預設）").to_string()))
        }
        Observed::NeedsAdmin => (
            CheckResult::NotApplicable,
            String::new(),
            Some(t!("需要系統管理員／root 權限才能檢查").to_string()),
        ),
        Observed::NotApplicable(why) => (CheckResult::NotApplicable, String::new(), Some(why.clone())),
        Observed::Error(e) => (CheckResult::Error, String::new(), Some(clip(e, 200))),
        Observed::Value(v) => {
            if c.na_values.iter().any(|x| loose_eq(v, x)) {
                return (CheckResult::NotApplicable, display(v), None);
            }
            let r = if test(c.expect.op, v, &c.expect.value) {
                CheckResult::Pass
            } else {
                CheckResult::Fail
            };
            (r, display(v), None)
        }
    }
}

/// 嚴重度加權分數：每個通過算 2、未通過依嚴重度 crit 4／high 3／med 2／其他 1（與 scan::score 一致）。
pub fn weighted_score(pass: u32, fails: impl Iterator<Item = Severity>) -> u8 {
    let fail_weight: u32 = fails
        .map(|s| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            _ => 1,
        })
        .sum();
    let total = pass * 2 + fail_weight;
    if total == 0 {
        return 100;
    }
    ((pass * 2) as f64 / total as f64 * 100.0).round() as u8
}

pub async fn run_checks(
    config_dir: &Path,
    runner: &dyn CmdRunner,
    env: &ProbeEnv,
    distros: &[String],
) -> HardeningReport {
    let (checks, warnings) = policy::load(&env.family, distros, config_dir);
    let observed = probe::observe(&checks, runner, env).await;
    let mut r = HardeningReport {
        os_family: env.family.clone(),
        warnings,
        ..Default::default()
    };
    for c in &checks {
        let o = observed
            .get(&c.id)
            .cloned()
            .unwrap_or(Observed::Error("not probed".into()));
        if o == Observed::NeedsAdmin {
            r.needs_admin.push(c.id.clone());
        }
        let (result, obs, note) = evaluate(c, &o);
        match result {
            CheckResult::Pass => r.pass += 1,
            CheckResult::Fail => r.fail += 1,
            CheckResult::NotApplicable => r.na += 1,
            CheckResult::Error => r.error += 1,
        }
        r.results.push(Outcome {
            id: c.id.clone(),
            category: c.category.clone(),
            severity: c.severity,
            title: c.title.get(),
            result,
            observed: obs,
            expected: expected_text(c),
            remediation: c.remediation.get(),
            rationale: c.rationale.get(),
            references: c.references.clone(),
            note,
        });
    }
    r.score = weighted_score(
        r.pass,
        r.results
            .iter()
            .filter(|o| o.result == CheckResult::Fail)
            .map(|o| o.severity),
    );
    r
}

pub fn findings_from(r: &HardeningReport) -> Vec<Finding> {
    r.results
        .iter()
        .filter(|o| o.result == CheckResult::Fail)
        .map(|o| {
            let mut f = Finding::new(
                ScannerId::Hardening,
                &format!("hardening.{}", o.id),
                &o.id,
                o.severity,
                tf!("未通過：{title}", title = o.title),
                o.rationale.clone(),
                Evidence::Policy {
                    policy_id: o.id.clone(),
                    check: o.title.clone(),
                    observed: o.observed.clone(),
                    expected: o.expected.clone(),
                    result: CheckResult::Fail,
                },
                o.remediation.clone(),
            );
            if !o.category.is_empty() {
                f = f.with_tag(&o.category);
            }
            for u in &o.references {
                f = f.with_ref(u);
            }
            f
        })
        .collect()
}

pub fn current_env() -> (ProbeEnv, Vec<String>) {
    let family = os_family();
    let distros = if family == "linux" {
        distro_ids(&std::fs::read_to_string("/etc/os-release").unwrap_or_default())
    } else {
        Vec::new()
    };
    (ProbeEnv::current(family), distros)
}

pub struct HardeningScanner;

#[async_trait]
impl Scanner for HardeningScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Hardening
    }

    fn elevation(&self) -> Elevation {
        Elevation::Preferred
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let (env, distros) = current_env();
        let r = run_checks(&ctx.config_dir, ctx.runner.as_ref(), &env, &distros).await;
        Ok(ScanOutput {
            findings: findings_from(&r),
            warnings: r.warnings.clone(),
            summary: serde_json::to_value(&r).ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::{CmdOutput, FakeRunner};
    use serde_json::json;

    #[test]
    fn evaluate_ops_and_states() {
        let checks = policy::parse(crate::embedded::feeds_file("policies/windows.yml").unwrap()).unwrap();
        let get = |id: &str| checks.iter().find(|c| c.id == id).unwrap().clone();
        let v = |x: Value| Observed::Value(x);
        assert_eq!(evaluate(&get("win.uac.enabled"), &v(json!(1))).0, CheckResult::Pass);
        assert_eq!(evaluate(&get("win.uac.enabled"), &v(json!("1"))).0, CheckResult::Pass);
        assert_eq!(evaluate(&get("win.uac.enabled"), &v(json!(0))).0, CheckResult::Fail);
        assert_eq!(
            evaluate(&get("win.uac.enabled"), &Observed::Missing).0,
            CheckResult::Pass
        );
        assert_eq!(
            evaluate(&get("win.lsa.protection"), &Observed::Missing).0,
            CheckResult::Fail
        );
        assert_eq!(evaluate(&get("win.lsa.protection"), &v(json!(2))).0, CheckResult::Pass);
        assert_eq!(
            evaluate(&get("win.secureboot"), &Observed::Missing).0,
            CheckResult::NotApplicable
        );
        assert_eq!(
            evaluate(&get("win.defender.realtime"), &v(json!("other_av"))).0,
            CheckResult::NotApplicable
        );
        assert_eq!(
            evaluate(&get("win.defender.signatures"), &v(json!(3))).0,
            CheckResult::Pass
        );
        assert_eq!(
            evaluate(&get("win.defender.signatures"), &v(json!(30))).0,
            CheckResult::Fail
        );
        assert_eq!(
            evaluate(&get("win.account.guest"), &v(json!("Disabled"))).0,
            CheckResult::Pass
        );
        assert_eq!(
            evaluate(&get("win.powershell_v2.removed"), &v(json!("2.0"))).0,
            CheckResult::Fail
        );
        assert_eq!(
            evaluate(&get("win.account.guest"), &Observed::Error("x".into())).0,
            CheckResult::Error
        );
        assert_eq!(expected_text(&get("win.lsa.protection")), "in 1, 2");

        let lin = policy::parse(crate::embedded::feeds_file("policies/linux.yml").unwrap()).unwrap();
        let l = |id: &str| lin.iter().find(|c| c.id == id).unwrap().clone();
        assert_eq!(evaluate(&l("lin.accounts.uid0"), &v(json!([]))).0, CheckResult::Pass);
        let (r, obs, _) = evaluate(&l("lin.accounts.uid0"), &v(json!(["toor"])));
        assert_eq!((r, obs.as_str()), (CheckResult::Fail, "toor"));
        assert_eq!(
            evaluate(&l("lin.ssh.max_auth_tries"), &v(json!("6"))).0,
            CheckResult::Fail
        );
        assert_eq!(
            evaluate(&l("lin.ssh.max_auth_tries"), &v(json!("3"))).0,
            CheckResult::Pass
        );
        assert_eq!(
            evaluate(&l("lin.sudo.nopasswd"), &Observed::NeedsAdmin).0,
            CheckResult::NotApplicable
        );
    }

    #[test]
    fn weighted() {
        assert_eq!(weighted_score(0, std::iter::empty()), 100);
        assert_eq!(weighted_score(6, [Severity::High, Severity::Low].into_iter()), 75);
    }

    #[test]
    fn windows_report_and_findings() {
        let d = tempfile::tempdir().unwrap();
        let runner = FakeRunner::new().on(
            "powershell",
            CmdOutput::success(r#"{"win.uac.enabled":1,"win.uac.admin_prompt":5,"win.defender.realtime":"on","win.defender.signatures":1,"win.defender.tamper":"off","win.smartscreen":"on","win.smb1.client":4,"win.smb1.server":null,"win.rdp.nla":"rdp_off","win.bitlocker.system":"off","win.secureboot":1,"win.lsa.protection":null,"win.wdigest":null,"win.account.guest":"disabled","win.account.builtin_admin":"disabled","win.update.not_disabled":null,"win.autorun.disabled":"on","win.llmnr.disabled":null,"win.powershell_v2.removed":null,"win.remote_registry":"Disabled"}"#),
        );
        let env = ProbeEnv {
            family: "windows".into(),
            root: d.path().to_path_buf(),
            path_var: None,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let r = rt.block_on(run_checks(d.path(), &runner, &env, &[]));
        assert_eq!(runner.calls().len(), 1, "一次 PowerShell");
        assert_eq!((r.pass, r.fail, r.na, r.error), (14, 5, 1, 0));
        let f = findings_from(&r);
        let ids: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "hardening.win.defender.tamper",
                "hardening.win.bitlocker.system",
                "hardening.win.lsa.protection",
                "hardening.win.autorun.disabled",
                "hardening.win.llmnr.disabled"
            ]
        );
        assert!(f[1].tags.contains(&"encryption".to_string()));
        assert!(matches!(&f[1].evidence, Evidence::Policy { observed, .. } if observed == "off"));
        assert_eq!(
            r.score,
            weighted_score(
                14,
                [
                    Severity::Medium,
                    Severity::High,
                    Severity::Medium,
                    Severity::Low,
                    Severity::Low
                ]
                .into_iter()
            )
        );
    }

    #[test]
    fn distro_ids_include_like() {
        assert_eq!(
            distro_ids("NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"),
            vec!["linuxmint", "ubuntu", "debian"]
        );
    }
}
