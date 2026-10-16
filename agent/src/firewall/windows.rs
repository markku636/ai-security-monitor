//! Windows 防火牆（NetSecurity）：一次 PowerShell 取得設定檔、作用中網路類別、所有「允許連入」規則與其
//! port／程式／位址篩選（用 `-All` 批次取篩選器再以 InstanceID 對應，比逐條管線快一個數量級）。

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{FirewallBackend, FwProfile, FwRule, FwSnapshot, PortSpec};
use crate::util::cmd::{powershell, CmdOutput, CmdSpec};

pub const READ_SCRIPT: &str = r##"
$p = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Enabled = "$($_.Enabled)"; DefaultInboundAction = "$($_.DefaultInboundAction)"; DefaultOutboundAction = "$($_.DefaultOutboundAction)" } })
$active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.NetworkCategory)" })
$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
$pf = @{}; Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $pf[$_.InstanceID] = $_ }
$af = @{}; Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $af[$_.InstanceID] = $_ }
$df = @{}; Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue | ForEach-Object { $df[$_.InstanceID] = $_ }
$out = @($rules | ForEach-Object {
  $x = $pf[$_.Name]; $a = $af[$_.Name]; $d = $df[$_.Name]
  [pscustomobject]@{
    Name = "$($_.Name)"; DisplayName = "$($_.DisplayName)"; Group = "$($_.Group)"; Profile = "$($_.Profile)"; Owner = "$($_.Owner)"
    Protocol = $(if ($x) { "$($x.Protocol)" } else { 'Any' })
    LocalPort = $(if ($x) { (@($x.LocalPort) -join ',') } else { 'Any' })
    Program = $(if ($a) { "$($a.Program)" } else { 'Any' })
    LocalAddress = $(if ($d) { (@($d.LocalAddress) -join ',') } else { 'Any' })
    RemoteAddress = $(if ($d) { (@($d.RemoteAddress) -join ',') } else { 'Any' })
  }
})
$ours = @(Get-NetFirewallRule -Group 'ASA' -ErrorAction SilentlyContinue).Count
[pscustomobject]@{ profiles = $p; active = $active; rules = $out; ours = $ours } | ConvertTo-Json -Depth 4 -Compress
"##;

fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let v = Value::deserialize(d)?;
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Array(a) => a
            .into_iter()
            .map(|x| serde_json::from_value(x).map_err(serde::de::Error::custom))
            .collect(),
        other => Ok(vec![serde_json::from_value(other).map_err(serde::de::Error::custom)?]),
    }
}

fn any() -> String {
    "Any".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WinProfile {
    name: String,
    enabled: String,
    #[serde(default)]
    default_inbound_action: String,
    #[serde(default)]
    default_outbound_action: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WinRule {
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    profile: String,
    #[serde(default)]
    owner: String,
    #[serde(default = "any")]
    protocol: String,
    #[serde(default = "any")]
    local_port: String,
    #[serde(default = "any")]
    program: String,
    #[serde(default = "any")]
    local_address: String,
    #[serde(default = "any")]
    remote_address: String,
}

#[derive(Deserialize)]
struct WinState {
    #[serde(default, deserialize_with = "one_or_many")]
    profiles: Vec<WinProfile>,
    #[serde(default, deserialize_with = "one_or_many")]
    active: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    rules: Vec<WinRule>,
    #[serde(default)]
    ours: usize,
}

fn action(s: &str) -> String {
    // NotConfigured＝系統預設：連入封鎖、連出允許。
    match s.to_ascii_lowercase().as_str() {
        "allow" => "allow".into(),
        "block" => "block".into(),
        _ => String::new(),
    }
}

fn protocol(s: &str) -> String {
    match s.trim().to_ascii_lowercase().as_str() {
        "any" | "" => "any".into(),
        "tcp" | "6" => "tcp".into(),
        "udp" | "17" => "udp".into(),
        other => other.to_string(),
    }
}

fn category(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "domainauthenticated" | "domain" => "domain".into(),
        "private" => "private".into(),
        _ => "public".into(),
    }
}

/// 解析 READ_SCRIPT 的 JSON 輸出。
pub fn parse_state(json: &str) -> Result<FwSnapshot, String> {
    let st: WinState = serde_json::from_str(json.trim_start_matches('\u{feff}').trim()).map_err(|e| e.to_string())?;
    let active: Vec<String> = st.active.iter().map(|a| category(a)).collect();
    let profiles: Vec<FwProfile> = st
        .profiles
        .iter()
        .map(|p| {
            let name = p.name.to_ascii_lowercase();
            let din = action(&p.default_inbound_action);
            let dout = action(&p.default_outbound_action);
            FwProfile {
                active: active.contains(&name),
                enabled: p.enabled.eq_ignore_ascii_case("true"),
                default_inbound: if din.is_empty() { "block".into() } else { din },
                default_outbound: if dout.is_empty() { "allow".into() } else { dout },
                name,
            }
        })
        .collect();
    let mut snap = FwSnapshot {
        backend: "windows".into(),
        available: true,
        profiles,
        ours_rules: st.ours,
        ..Default::default()
    };
    let act = snap.active_profiles();
    let act_profiles: Vec<&FwProfile> = snap.profiles.iter().filter(|p| act.contains(&p.name)).collect();
    snap.enabled = Some(!act_profiles.is_empty() && act_profiles.iter().all(|p| p.enabled));
    snap.default_inbound = Some(
        if act_profiles.iter().any(|p| p.enabled && p.default_inbound == "allow") {
            "allow"
        } else {
            "block"
        }
        .into(),
    );
    snap.inbound_allow = st
        .rules
        .into_iter()
        .map(|r| FwRule {
            display: if r.display_name.is_empty() {
                r.name.clone()
            } else {
                r.display_name
            },
            name: r.name,
            protocol: protocol(&r.protocol),
            ports: PortSpec::list(&r.local_port),
            program: if r.program.eq_ignore_ascii_case("any") || r.program.is_empty() {
                None
            } else {
                Some(r.program)
            },
            profiles: r
                .profile
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .into_iter()
                .map(|s| if s == "any" { "any".to_string() } else { s })
                .collect(),
            owner: if r.owner.trim().is_empty() { None } else { Some(r.owner) },
            local_address: r.local_address,
            remote_address: r.remote_address,
        })
        .collect();
    Ok(snap)
}

pub struct Windows;

impl FirewallBackend for Windows {
    fn id(&self) -> &'static str {
        "windows"
    }

    fn read_specs(&self) -> Vec<CmdSpec> {
        vec![powershell(READ_SCRIPT).describe(t!("讀取 Windows 防火牆設定檔與允許連入規則"))]
    }

    fn parse(&self, outputs: &[Option<CmdOutput>], _elevated: bool) -> FwSnapshot {
        match outputs.first().cloned().flatten() {
            Some(o) if o.ok() => parse_state(&o.stdout).unwrap_or_else(|e| FwSnapshot {
                backend: "windows".into(),
                available: true,
                notes: vec![tf!("解析防火牆狀態失敗：{e}", e = e)],
                ..Default::default()
            }),
            Some(o) => FwSnapshot {
                backend: "windows".into(),
                available: true,
                needs_elevation: o.permission_denied(),
                notes: vec![o.stderr.lines().next().unwrap_or("").to_string()],
                ..Default::default()
            },
            None => FwSnapshot {
                backend: "windows".into(),
                notes: vec![t!("無法執行 PowerShell").to_string()],
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{audit, reachability};
    use crate::model::connection::{Listener, ProcessRef, Reachability};

    fn fixture() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/firewall/win_state.json"),
        )
        .unwrap()
    }

    #[test]
    fn parses_real_shaped_output() {
        let s = parse_state(&fixture()).unwrap();
        assert_eq!(s.profiles.len(), 3);
        let public = s.profiles.iter().find(|p| p.name == "public").unwrap();
        assert!(public.active && !public.enabled);
        assert_eq!(public.default_inbound, "block");
        assert_eq!(s.enabled, Some(false));
        assert_eq!(s.inbound_allow.len(), 8);
        let uwp = s.inbound_allow.iter().find(|r| r.owner.is_some()).unwrap();
        assert!(!uwp.is_broad());
        let broad: Vec<&FwRule> = s.inbound_allow.iter().filter(|r| r.is_broad()).collect();
        assert_eq!(broad.len(), 1);
        assert_eq!(broad[0].name, "TEST-Broad");
        let ranges = s
            .inbound_allow
            .iter()
            .find(|r| r.ports.iter().any(|p| matches!(p, PortSpec::Range(5000, 5020))))
            .unwrap();
        assert_eq!(ranges.protocol, "udp");
    }

    #[test]
    fn audit_flags_active_profile_off() {
        let s = parse_state(&fixture()).unwrap();
        let f = audit(&s);
        let high = f.iter().find(|x| x.rule == "firewall.profile_disabled").unwrap();
        assert!(high.title.contains("public"));
        assert!(f.iter().any(|x| x.rule == "firewall.profile_disabled_inactive"));
        assert!(f.iter().any(|x| x.rule == "firewall.broad_allow_rule"));
    }

    #[test]
    fn reachability_with_enabled_profile() {
        let mut s = parse_state(&fixture()).unwrap();
        for p in s.profiles.iter_mut() {
            p.enabled = true;
        }
        s.enabled = Some(true);
        s.inbound_allow.retain(|r| r.name != "TEST-Broad");
        let smb = Listener {
            proto: "tcp".into(),
            bind_ip: "0.0.0.0".parse().unwrap(),
            port: 445,
            process: Some(ProcessRef {
                pid: 4,
                name: "System".into(),
                ..Default::default()
            }),
            exposed: true,
            reachability: None,
        };
        assert!(matches!(
            reachability(Some(&s), &smb),
            Reachability::Open { rule: Some(_) }
        ));
        let mut redis = smb.clone();
        redis.port = 6379;
        redis.process = Some(ProcessRef {
            pid: 9,
            name: "redis.exe".into(),
            exe: Some("C:/redis/redis.exe".into()),
            ..Default::default()
        });
        assert_eq!(reachability(Some(&s), &redis), Reachability::Filtered);
    }

    #[test]
    fn single_objects_are_accepted() {
        let j = r#"{"profiles":{"Name":"Public","Enabled":"True","DefaultInboundAction":"Allow","DefaultOutboundAction":"NotConfigured"},"active":"Public","rules":null,"ours":2}"#;
        let s = parse_state(j).unwrap();
        assert_eq!(s.enabled, Some(true));
        assert_eq!(s.default_inbound.as_deref(), Some("allow"));
        assert_eq!(s.ours_rules, 2);
        assert_eq!(audit(&s)[0].rule, "firewall.default_inbound_allow");
    }
}
