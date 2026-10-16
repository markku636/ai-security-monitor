//! macOS：應用程式防火牆（socketfilterfw，免 root）＋ pf 狀態（需 root）。
//! 應用程式防火牆以「程式」決定放行，port 層級的可達性無法得知 → 預設連入動作記為 `app`。

use super::{FirewallBackend, FwProfile, FwSnapshot};
use crate::util::cmd::{CmdOutput, CmdSpec};

pub const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

fn on_off(text: &str) -> Option<bool> {
    let t = text.to_ascii_lowercase();
    if t.contains("disabled") || t.contains("is off") || t.contains("state = 0") {
        Some(false)
    } else if t.contains("enabled") || t.contains("is on") || t.contains("state = 1") || t.contains("state = 2") {
        Some(true)
    } else {
        None
    }
}

pub struct MacOs;

impl FirewallBackend for MacOs {
    fn id(&self) -> &'static str {
        "macos-alf"
    }

    fn read_specs(&self) -> Vec<CmdSpec> {
        vec![
            CmdSpec::new(SOCKETFILTERFW, &["--getglobalstate"]).describe(t!("讀取應用程式防火牆狀態")),
            CmdSpec::new(SOCKETFILTERFW, &["--getstealthmode"]).describe(t!("讀取隱形模式")),
            CmdSpec::new(SOCKETFILTERFW, &["--getblockall"]).describe(t!("讀取「阻擋所有連入」")),
            CmdSpec::new("pfctl", &["-s", "info"])
                .elevated()
                .describe(t!("讀取 pf 狀態")),
            CmdSpec::new("pfctl", &["-a", "com.asa", "-t", "asa_block", "-T", "show"])
                .elevated()
                .describe(t!("讀取 asa 封鎖表")),
        ]
    }

    fn parse(&self, outputs: &[Option<CmdOutput>], elevated: bool) -> FwSnapshot {
        let text = |i: usize| -> Option<String> {
            outputs
                .get(i)
                .cloned()
                .flatten()
                .filter(|o| o.ok())
                .map(|o| format!("{}{}", o.stdout, o.stderr))
        };
        let alf = text(0).and_then(|t| on_off(&t));
        let stealth = text(1).and_then(|t| on_off(&t));
        let blockall = text(2).and_then(|t| on_off(&t));
        let pf = text(3).and_then(|t| {
            t.lines()
                .find(|l| l.trim_start().starts_with("Status:"))
                .map(|l| l.to_ascii_lowercase().contains("enabled"))
        });
        let ours = text(4)
            .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        let mut notes = Vec::new();
        if let Some(s) = stealth {
            notes.push(if s { "stealth:on" } else { "stealth:off" }.to_string());
        }
        match pf {
            Some(true) => notes.push("pf:enabled".into()),
            Some(false) => notes.push("pf:disabled".into()),
            None => notes.push("pf:unknown".into()),
        }
        let default_inbound = match (alf, blockall) {
            (Some(true), Some(true)) => Some("block".to_string()),
            (Some(true), _) => Some("app".to_string()),
            (Some(false), _) if pf == Some(true) => Some("app".to_string()),
            (Some(false), _) => Some("allow".to_string()),
            _ => None,
        };
        FwSnapshot {
            backend: "macos-alf".into(),
            available: alf.is_some(),
            enabled: match (alf, pf) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) | (Some(false), None) => Some(false),
                _ => None,
            },
            profiles: vec![FwProfile {
                name: "application-firewall".into(),
                enabled: alf.unwrap_or(false),
                default_inbound: default_inbound.clone().unwrap_or_default(),
                default_outbound: "allow".into(),
                active: true,
            }],
            default_inbound,
            inbound_allow: Vec::new(),
            ours_rules: ours,
            needs_elevation: pf.is_none() && !elevated,
            notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::audit;

    fn ok(s: &str) -> Option<CmdOutput> {
        Some(CmdOutput::success(s))
    }

    #[test]
    fn alf_off_without_root() {
        let outs = vec![
            ok("Firewall is disabled. (State = 0)"),
            ok("Firewall stealth mode is off"),
            ok("Firewall has block all state set to disabled."),
            Some(CmdOutput::failure(1, "pfctl: /dev/pf: Permission denied")),
            None,
        ];
        let s = MacOs.parse(&outs, false);
        assert_eq!(s.enabled, Some(false));
        assert_eq!(s.default_inbound.as_deref(), Some("allow"));
        assert!(s.needs_elevation);
        assert_eq!(audit(&s)[0].rule, "firewall.app_firewall_off");
    }

    #[test]
    fn alf_on_with_pf() {
        let outs = vec![
            ok("Firewall is enabled. (State = 1)"),
            ok("Firewall stealth mode is off"),
            ok("Firewall has block all state set to disabled."),
            ok("Status: Enabled for 0 days 01:02:03           Debug: Urgent\n"),
            ok("   1.2.3.4\n   5.6.7.0/24\n"),
        ];
        let s = MacOs.parse(&outs, true);
        assert_eq!(s.enabled, Some(true));
        assert_eq!(s.default_inbound.as_deref(), Some("app"));
        assert_eq!(s.ours_rules, 2);
        assert!(!s.needs_elevation);
        let f = audit(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "firewall.stealth_off");
    }
}
