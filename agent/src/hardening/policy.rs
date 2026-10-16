//! 硬化策略：`feeds/policies/<os>.yml`（內建）＋`<設定目錄>/policies/*.yml`（自訂；同 id 覆蓋內建、`disabled: true` 關掉）。

use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::i18n::Localized;
use crate::model::finding::Severity;

#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub id: String,
    #[serde(default)]
    pub category: String,
    pub severity: Severity,
    pub title: Localized,
    #[serde(default)]
    pub rationale: Localized,
    #[serde(default)]
    pub remediation: Localized,
    #[serde(default)]
    pub references: Vec<String>,
    pub probe: Probe,
    pub expect: Expect,
    /// 讀不到值時的結果。
    #[serde(default)]
    pub missing: Missing,
    /// 讀到這些值代表「不適用」（例：裝了別家防毒時 Defender 檢查不適用）。
    #[serde(default)]
    pub na_values: Vec<Value>,
    /// 只在這些 Linux 發行版檢查（os-release 的 ID 或 ID_LIKE）。
    #[serde(default)]
    pub distros: Vec<String>,
    /// 這個檔案不存在就不適用（例：沒裝 sshd 就不檢查暴力破解防護）。
    #[serde(default)]
    pub only_if_exists: Option<String>,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Missing {
    Pass,
    Fail,
    #[default]
    Na,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Expect {
    pub op: Op,
    #[serde(default)]
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Gte,
    Lte,
    Contains,
    NotContains,
    Matches,
    In,
    NotIn,
    Empty,
    NotEmpty,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "≠",
            Op::Gte => "≥",
            Op::Lte => "≤",
            Op::Contains => "contains",
            Op::NotContains => "not contains",
            Op::Matches => "matches",
            Op::In => "in",
            Op::NotIn => "not in",
            Op::Empty => "empty",
            Op::NotEmpty => "not empty",
        }
    }
}

/// 取值方式：恰好設定一種來源；`regex`／`stderr` 套用在 command／file 的文字上。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Probe {
    pub registry: Option<RegistryProbe>,
    pub powershell: Option<String>,
    pub command: Option<Vec<String>>,
    pub file: Option<String>,
    pub sysctl: Option<String>,
    pub sshd: Option<SshdProbe>,
    pub service: Option<ServiceProbe>,
    pub builtin: Option<String>,
    pub regex: Option<String>,
    #[serde(default)]
    pub stderr: bool,
}

impl Probe {
    pub fn sources(&self) -> usize {
        [
            self.registry.is_some(),
            self.powershell.is_some(),
            self.command.as_ref().is_some_and(|c| !c.is_empty()),
            self.file.is_some(),
            self.sysctl.is_some(),
            self.sshd.is_some(),
            self.service.is_some(),
            self.builtin.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    /// Windows 上合併成一次 PowerShell 的種類。
    pub fn is_powershell(&self) -> bool {
        self.registry.is_some() || self.powershell.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistryProbe {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshdProbe {
    pub key: String,
    #[serde(default)]
    pub default: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceProbe {
    pub names: Vec<String>,
    #[serde(default)]
    pub query: ServiceQuery,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceQuery {
    #[default]
    Active,
    Enabled,
}

pub fn parse(text: &str) -> Result<Vec<Check>, String> {
    let checks: Vec<Check> = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;
    for c in &checks {
        // 會進 finding 的 rule（hardening.<id>）；hub 只收小寫英數與 . _ -
        let id_ok = !c.id.is_empty()
            && c.id.len() <= 100
            && c.id
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'));
        if !id_ok {
            return Err(format!(
                "{}: id must be lowercase letters, digits, '.', '_' or '-'",
                c.id
            ));
        }
        if c.probe.sources() != 1 {
            return Err(format!("{}: probe must set exactly one source", c.id));
        }
        if let Some(r) = &c.probe.regex {
            regex::Regex::new(r).map_err(|e| format!("{}: {e}", c.id))?;
        }
    }
    Ok(checks)
}

/// 這個作業系統要跑的檢查（內建＋自訂，已套用 disabled 與發行版篩選）；第二個值是自訂檔的錯誤。
pub fn load(family: &str, distro_ids: &[String], config_dir: &Path) -> (Vec<Check>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut checks = crate::embedded::feeds_file(&format!("policies/{family}.yml"))
        .map(|t| {
            parse(t).unwrap_or_else(|e| {
                warnings.push(format!("policies/{family}.yml: {e}"));
                Vec::new()
            })
        })
        .unwrap_or_default();
    let dir = config_dir.join("policies");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut files: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
            .collect();
        files.sort();
        for p in files {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            match parse(&text) {
                Ok(custom) => {
                    for c in custom {
                        // 自訂檔可以放多個作業系統的檢查：用 id 前綴分辨
                        if !applies_to_family(&c.id, family) {
                            continue;
                        }
                        checks.retain(|x| x.id != c.id);
                        checks.push(c);
                    }
                }
                Err(e) => warnings.push(format!("{name}: {e}")),
            }
        }
    }
    checks.retain(|c| !c.disabled);
    checks.retain(|c| c.distros.is_empty() || c.distros.iter().any(|d| distro_ids.contains(d)));
    (checks, warnings)
}

fn applies_to_family(id: &str, family: &str) -> bool {
    let prefix = match family {
        "windows" => "win.",
        "macos" => "mac.",
        _ => "lin.",
    };
    id.starts_with(prefix) || !(id.starts_with("win.") || id.starts_with("mac.") || id.starts_with("lin."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_policies_parse() {
        for (fam, min) in [("windows", 18), ("linux", 22), ("macos", 14)] {
            let text = crate::embedded::feeds_file(&format!("policies/{fam}.yml")).unwrap();
            let checks = parse(text).unwrap_or_else(|e| panic!("{fam}: {e}"));
            assert!(checks.len() >= min, "{fam}: {}", checks.len());
            let mut ids: Vec<&str> = checks.iter().map(|c| c.id.as_str()).collect();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), checks.len(), "{fam}: duplicate ids");
            for c in &checks {
                assert!(!c.title.zh.is_empty() && !c.title.en.is_empty(), "{}", c.id);
                assert!(!c.remediation.en.is_empty(), "{}", c.id);
                assert!(!c.references.is_empty(), "{}", c.id);
            }
        }
    }

    #[test]
    fn custom_overrides_disable_and_distro_filter() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("policies")).unwrap();
        std::fs::write(
            d.path().join("policies/local.yml"),
            r#"
- id: lin.audit.auditd
  severity: low
  title: { zh: x, en: x }
  probe: { builtin: lsm }
  expect: { op: eq, value: x }
  disabled: true
- id: lin.custom.motd
  severity: info
  title: { zh: 有 motd, en: has motd }
  probe: { file: /etc/motd }
  expect: { op: not_empty }
- id: win.only
  severity: info
  title: { zh: x, en: x }
  probe: { powershell: "1" }
  expect: { op: eq, value: 1 }
"#,
        )
        .unwrap();
        let (ubuntu, w) = load("linux", &["ubuntu".into(), "debian".into()], d.path());
        assert!(w.is_empty(), "{w:?}");
        let ids: Vec<&str> = ubuntu.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"lin.custom.motd"));
        assert!(!ids.contains(&"lin.audit.auditd"));
        assert!(!ids.contains(&"win.only"));
        assert!(ids.contains(&"lin.updates.unattended"));
        assert!(!ids.contains(&"lin.updates.dnf_automatic"));
        let (rocky, _) = load("linux", &["rocky".into(), "rhel".into()], d.path());
        assert!(rocky.iter().any(|c| c.id == "lin.updates.dnf_automatic"));
        assert!(
            parse("- id: x\n  severity: low\n  title: {zh: a, en: a}\n  probe: {}\n  expect: {op: empty}\n").is_err()
        );
        assert!(parse(
            "- id: Lin.X\n  severity: low\n  title: {zh: a, en: a}\n  probe: {builtin: lsm}\n  expect: {op: empty}\n"
        )
        .is_err());
    }
}
