//! 防火牆：讀取狀態與規則（Windows NetSecurity、macOS 應用程式防火牆＋pf、Linux nftables／ufw／firewalld／iptables），
//! 判斷 listener 是否真的能從網路連入，並稽核常見弱點（作用中網路的設定檔關閉、預設允許連入、全開規則）。
//! 本輪只讀；封鎖 / 同步黑名單在下一輪（需提權＋確認）。

pub mod desired;
pub mod linux;
pub mod macos;
pub mod plan;
pub mod select;
pub mod windows;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::model::connection::{Listener, Reachability};
use crate::model::finding::{ActionKind, Evidence, Finding, ProposedAction, ScannerId, Severity};
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};
use crate::util::cmd::{CmdOutput, CmdRunner, CmdSpec};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSpec {
    Any,
    Single(u16),
    Range(u16, u16),
    Named(String),
}

impl PortSpec {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortSpec::Any => true,
            PortSpec::Single(p) => *p == port,
            PortSpec::Range(a, b) => (*a..=*b).contains(&port),
            PortSpec::Named(_) => false,
        }
    }

    /// `80`、`5000-5020`、`8000:8010`、`Any`、其他字串 → Named。
    pub fn parse(s: &str) -> PortSpec {
        let t = s.trim();
        if t.eq_ignore_ascii_case("any") || t == "*" {
            return PortSpec::Any;
        }
        if let Ok(p) = t.parse::<u16>() {
            return PortSpec::Single(p);
        }
        if let Some((a, b)) = t.split_once(['-', ':']) {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                return PortSpec::Range(a.min(b), a.max(b));
            }
        }
        PortSpec::Named(t.to_string())
    }

    pub fn list(s: &str) -> Vec<PortSpec> {
        s.split(',')
            .filter(|x| !x.trim().is_empty())
            .map(PortSpec::parse)
            .collect()
    }

    pub fn display(&self) -> String {
        match self {
            PortSpec::Any => "any".into(),
            PortSpec::Single(p) => p.to_string(),
            PortSpec::Range(a, b) => format!("{a}-{b}"),
            PortSpec::Named(n) => n.clone(),
        }
    }
}

/// 一條「允許連入」規則（正規化後）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FwRule {
    pub name: String,
    pub display: String,
    /// `tcp` / `udp` / `any` / 其他（icmpv6…）
    pub protocol: String,
    pub ports: Vec<PortSpec>,
    /// 限定程式（None＝任何程式）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// 適用的設定檔（Windows：domain/private/public；其他平台為 any）。
    pub profiles: Vec<String>,
    /// Windows 每使用者 AppContainer（UWP）規則的擁有者 SID。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default = "any_str")]
    pub local_address: String,
    #[serde(default = "any_str")]
    pub remote_address: String,
}

fn any_str() -> String {
    "any".into()
}

impl FwRule {
    pub fn simple(name: &str, protocol: &str, ports: Vec<PortSpec>) -> FwRule {
        FwRule {
            name: name.to_string(),
            display: name.to_string(),
            protocol: protocol.to_string(),
            ports,
            program: None,
            profiles: vec!["any".into()],
            owner: None,
            local_address: "any".into(),
            remote_address: "any".into(),
        }
    }

    fn applies_to(&self, active: &[String]) -> bool {
        self.profiles
            .iter()
            .any(|p| p == "any" || active.iter().any(|a| a == p))
    }

    /// 任何程式、任何協定、任何 port、任何位址 → 全開。
    pub fn is_broad(&self) -> bool {
        self.protocol == "any"
            && self.ports.contains(&PortSpec::Any)
            && self.program.is_none()
            && self.owner.is_none()
            && self.local_address.eq_ignore_ascii_case("any")
            && self.remote_address.eq_ignore_ascii_case("any")
    }

    pub fn matches(&self, l: &Listener, active: &[String]) -> bool {
        // 每使用者 AppContainer（UWP）規則只放行該套件的行程，不適用一般桌面程式。
        if self.owner.is_some() {
            return false;
        }
        if !self.applies_to(active) {
            return false;
        }
        if self.protocol != "any" && self.protocol != l.proto {
            return false;
        }
        if !self.ports.iter().any(|p| p.matches(l.port)) {
            return false;
        }
        match &self.program {
            None => true,
            Some(prog) => {
                let p = normalize_path(prog);
                match l.process.as_ref() {
                    None => true, // 對不到行程（權限不足）：無法排除，保守視為可能放行。
                    Some(proc_ref) => {
                        if p == "system" {
                            return proc_ref.name.eq_ignore_ascii_case("system");
                        }
                        match &proc_ref.exe {
                            Some(exe) => normalize_path(exe) == p,
                            None => true,
                        }
                    }
                }
            }
        }
    }
}

/// 展開 `%SystemRoot%` 等環境變數、統一斜線與大小寫（比對 Windows 路徑用）。
pub fn normalize_path(p: &str) -> String {
    let mut out = String::new();
    let mut rest = p;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.replace('\\', "/").to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FwProfile {
    pub name: String,
    pub enabled: bool,
    /// `block` / `allow`
    pub default_inbound: String,
    pub default_outbound: String,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FwSnapshot {
    /// `windows` / `macos-alf` / `nftables` / `ufw` / `firewalld` / `iptables` / `none`
    pub backend: String,
    /// 管理工具存在。
    pub available: bool,
    /// None＝讀不到（通常是權限不足）。
    pub enabled: Option<bool>,
    pub profiles: Vec<FwProfile>,
    /// 作用中網路的預設連入動作：`block` / `allow` / `app`（macOS 依程式決定）。
    pub default_inbound: Option<String>,
    pub inbound_allow: Vec<FwRule>,
    /// 本工具建立的封鎖規則 / 位址數。
    pub ours_rules: usize,
    pub needs_elevation: bool,
    pub notes: Vec<String>,
}

impl FwSnapshot {
    pub fn active_profiles(&self) -> Vec<String> {
        let act: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| p.active)
            .map(|p| p.name.clone())
            .collect();
        if act.is_empty() {
            self.profiles.iter().map(|p| p.name.clone()).collect()
        } else {
            act
        }
    }
}

/// listener 是否能從網路連入。
pub fn reachability(fw: Option<&FwSnapshot>, l: &Listener) -> Reachability {
    if !l.exposed {
        return Reachability::LocalOnly;
    }
    let Some(fw) = fw else {
        return Reachability::Unknown;
    };
    match fw.enabled {
        None => Reachability::Unknown,
        Some(false) => Reachability::Open { rule: None },
        Some(true) => match fw.default_inbound.as_deref() {
            Some("allow") => Reachability::Open { rule: None },
            Some("app") => Reachability::Unknown,
            _ => {
                let active = fw.active_profiles();
                match fw.inbound_allow.iter().find(|r| r.matches(l, &active)) {
                    Some(r) => Reachability::Open {
                        rule: Some(r.display.clone()),
                    },
                    None => Reachability::Filtered,
                }
            }
        },
    }
}

/// 一個防火牆後端：要跑哪些唯讀指令、如何解析輸出（解析是純函數，用 fixture 測）。
pub trait FirewallBackend: Send + Sync {
    fn id(&self) -> &'static str;
    fn read_specs(&self) -> Vec<CmdSpec>;
    /// `outputs` 與 `read_specs` 同順序；跑不起來的為 None。
    fn parse(&self, outputs: &[Option<CmdOutput>], elevated: bool) -> FwSnapshot;
}

pub async fn read_with(backend: &dyn FirewallBackend, runner: &dyn CmdRunner, elevated: bool) -> FwSnapshot {
    let mut outs = Vec::new();
    for spec in backend.read_specs() {
        outs.push(runner.run(&spec).await.ok());
    }
    backend.parse(&outs, elevated)
}

/// 偵測本機後端並讀取狀態。
pub async fn read_current(runner: &dyn CmdRunner, elevated: bool) -> AppResult<FwSnapshot> {
    if cfg!(windows) {
        Ok(read_with(&windows::Windows, runner, elevated).await)
    } else if cfg!(target_os = "macos") {
        Ok(read_with(&macos::MacOs, runner, elevated).await)
    } else {
        let backend = linux::detect(runner).await;
        Ok(read_with(backend.as_ref(), runner, elevated).await)
    }
}

// ---------------------------------------------------------------- audit

fn fw_finding(rule: &str, key: &str, sev: Severity, title: String, detail: String, rec: &str) -> Finding {
    Finding::new(
        ScannerId::Firewall,
        rule,
        key,
        sev,
        title,
        detail.clone(),
        Evidence::Text { detail },
        rec.to_string(),
    )
}

fn enable_action(profile: Option<&str>) -> ProposedAction {
    ProposedAction {
        kind: ActionKind::EnableFirewall,
        params: serde_json::json!({ "profile": profile }),
        requires_elevation: true,
        destructive: false,
        reversible: true,
        description: match profile {
            Some(p) => tf!("啟用 {profile} 防火牆設定檔", profile = p),
            None => t!("啟用主機防火牆").to_string(),
        },
    }
}

/// 依快照產生稽核 finding。
pub fn audit(fw: &FwSnapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    match fw.backend.as_str() {
        "windows" => {
            for p in &fw.profiles {
                if !p.enabled {
                    if p.active {
                        out.push(
                            fw_finding(
                                "firewall.profile_disabled",
                                &p.name,
                                Severity::High,
                                tf!("作用中網路的 {profile} 防火牆設定檔已關閉", profile = p.name),
                                tf!(
                                    "目前連線的網路類別是 {profile}，但此設定檔沒有啟用 Windows 防火牆；本機所有對外監聽的服務都能直接從這個網路連入",
                                    profile = p.name
                                ),
                                t!("啟用該設定檔（Set-NetFirewallProfile -Profile <名稱> -Enabled True），再只為需要的服務開例外"),
                            )
                            .with_action(enable_action(Some(&p.name))),
                        );
                    } else {
                        out.push(
                            fw_finding(
                                "firewall.profile_disabled_inactive",
                                &p.name,
                                Severity::Low,
                                tf!("{profile} 防火牆設定檔已關閉（目前非作用中）", profile = p.name),
                                tf!("切換到 {profile} 類別的網路時將沒有防火牆保護", profile = p.name),
                                t!("啟用該設定檔，避免換網路時曝露"),
                            )
                            .with_action(enable_action(Some(&p.name))),
                        );
                    }
                } else if p.active && p.default_inbound == "allow" {
                    out.push(fw_finding(
                        "firewall.default_inbound_allow",
                        &p.name,
                        Severity::High,
                        tf!("{profile} 設定檔預設允許所有連入", profile = p.name),
                        t!("預設連入動作是允許：沒有被規則明確阻擋的連入都會通過").to_string(),
                        t!("把預設連入動作改為封鎖（Set-NetFirewallProfile -DefaultInboundAction Block）"),
                    ));
                }
            }
            let active = fw.active_profiles();
            for r in fw
                .inbound_allow
                .iter()
                .filter(|r| r.is_broad() && r.applies_to(&active))
                .take(10)
            {
                out.push(fw_finding(
                    "firewall.broad_allow_rule",
                    &r.name,
                    Severity::Medium,
                    tf!("防火牆規則允許任何連入：{name}", name = r.display),
                    tf!(
                        "規則「{name}」不限程式、協定、port 與位址，套用於作用中網路（{profiles}）",
                        name = r.display,
                        profiles = r.profiles.join(", ")
                    ),
                    t!("確認是否仍需要；需要的話限縮到特定程式、port 或來源位址"),
                ));
            }
        }
        "macos-alf" => {
            if fw.enabled == Some(false) {
                out.push(
                    fw_finding(
                        "firewall.app_firewall_off",
                        "alf",
                        Severity::Medium,
                        t!("macOS 應用程式防火牆已關閉").to_string(),
                        t!("系統設定 → 網路 → 防火牆 為關閉；所有對外監聽的服務都能從網路連入").to_string(),
                        t!("開啟應用程式防火牆（socketfilterfw --setglobalstate on），必要時啟用隱形模式"),
                    )
                    .with_action(enable_action(None)),
                );
            }
            if fw.enabled == Some(true) && fw.notes.iter().any(|n| n == "stealth:off") {
                out.push(fw_finding(
                    "firewall.stealth_off",
                    "alf",
                    Severity::Low,
                    t!("macOS 防火牆未開啟隱形模式").to_string(),
                    t!("未開啟隱形模式時，主機會回應 ping 與連到已關閉 port 的探測，較容易被掃描發現").to_string(),
                    t!("socketfilterfw --setstealthmode on"),
                ));
            }
        }
        _ => {
            if fw.enabled == Some(false) {
                out.push(
                    fw_finding(
                        "firewall.none_active",
                        &fw.backend,
                        Severity::Medium,
                        tf!("沒有啟用中的主機防火牆（{backend}）", backend = fw.backend),
                        t!("沒有偵測到運作中的 nftables / ufw / firewalld / iptables 規則；對外監聽的服務都能直接連入")
                            .to_string(),
                        t!("啟用 ufw 或 firewalld，預設拒絕連入，只開放需要的服務"),
                    )
                    .with_action(enable_action(None)),
                );
            } else if fw.enabled == Some(true) && fw.default_inbound.as_deref() == Some("allow") {
                out.push(fw_finding(
                    "firewall.default_inbound_allow",
                    &fw.backend,
                    Severity::Medium,
                    tf!("{backend} 預設允許所有連入", backend = fw.backend),
                    t!("INPUT 預設政策是接受；沒有被規則明確阻擋的連入都會通過").to_string(),
                    t!("把預設連入政策改為 drop / deny，只放行需要的服務"),
                ));
            }
        }
    }
    out
}

pub struct FirewallScanner;

#[async_trait]
impl Scanner for FirewallScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Firewall
    }

    fn elevation(&self) -> Elevation {
        if cfg!(windows) {
            Elevation::NotNeeded
        } else {
            Elevation::Preferred
        }
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let snap = read_current(ctx.runner.as_ref(), ctx.elevated).await?;
        let mut warnings = Vec::new();
        if snap.needs_elevation {
            warnings.push(tf!(
                "防火牆（{backend}）規則需要系統管理員權限才能讀取；部分結果為「未知」",
                backend = snap.backend
            ));
        }
        let findings = audit(&snap);
        let summary = serde_json::to_value(&snap).ok();
        ctx.shared.lock().await.firewall_state = summary.clone();
        Ok(ScanOutput {
            findings,
            warnings,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::connection::ProcessRef;

    fn listener(proto: &str, port: u16, exe: Option<&str>, name: &str) -> Listener {
        Listener {
            proto: proto.into(),
            bind_ip: "0.0.0.0".parse().unwrap(),
            port,
            process: Some(ProcessRef {
                pid: 10,
                name: name.into(),
                exe: exe.map(|s| s.into()),
                ..Default::default()
            }),
            exposed: true,
            reachability: None,
        }
    }

    #[test]
    fn port_spec_parsing() {
        assert_eq!(PortSpec::parse("Any"), PortSpec::Any);
        assert_eq!(PortSpec::parse("5000-5020"), PortSpec::Range(5000, 5020));
        assert_eq!(PortSpec::parse("8010:8000"), PortSpec::Range(8000, 8010));
        assert_eq!(PortSpec::parse("RPC"), PortSpec::Named("RPC".into()));
        assert_eq!(PortSpec::list("554,8554-8558").len(), 2);
        assert!(PortSpec::Range(8554, 8558).matches(8556));
    }

    #[test]
    fn rule_matching_and_reachability() {
        let mut fw = FwSnapshot {
            backend: "ufw".into(),
            available: true,
            enabled: Some(true),
            default_inbound: Some("block".into()),
            inbound_allow: vec![FwRule::simple("22/tcp", "tcp", vec![PortSpec::Single(22)])],
            ..Default::default()
        };
        let ssh = listener("tcp", 22, Some("/usr/sbin/sshd"), "sshd");
        let redis = listener("tcp", 6379, Some("/usr/bin/redis-server"), "redis-server");
        assert_eq!(
            reachability(Some(&fw), &ssh),
            Reachability::Open {
                rule: Some("22/tcp".into())
            }
        );
        assert_eq!(reachability(Some(&fw), &redis), Reachability::Filtered);
        let mut local = redis.clone();
        local.exposed = false;
        assert_eq!(reachability(Some(&fw), &local), Reachability::LocalOnly);
        fw.enabled = None;
        assert_eq!(reachability(Some(&fw), &redis), Reachability::Unknown);
        fw.enabled = Some(false);
        assert_eq!(reachability(Some(&fw), &redis), Reachability::Open { rule: None });
        assert_eq!(reachability(None, &redis), Reachability::Unknown);
    }

    #[test]
    fn program_specific_rules() {
        let mut r = FwRule::simple("smb", "tcp", vec![PortSpec::Single(445)]);
        r.program = Some("System".into());
        assert!(r.matches(&listener("tcp", 445, None, "System"), &["public".into()]));
        assert!(!r.matches(
            &listener("tcp", 445, Some("C:/x/evil.exe"), "evil.exe"),
            &["public".into()]
        ));
        let mut r2 = FwRule::simple("app", "any", vec![PortSpec::Any]);
        r2.program = Some("C:\\Program Files\\App\\app.exe".into());
        assert!(r2.matches(
            &listener("udp", 9999, Some("c:/program files/app/APP.exe"), "app.exe"),
            &["any".into()]
        ));
        r2.profiles = vec!["domain".into()];
        assert!(!r2.matches(
            &listener("udp", 9999, Some("c:/program files/app/APP.exe"), "app.exe"),
            &["public".into()]
        ));
    }

    #[test]
    fn audit_linux_none_and_default_allow() {
        let fw = FwSnapshot {
            backend: "none".into(),
            enabled: Some(false),
            ..Default::default()
        };
        let f = audit(&fw);
        assert_eq!(f[0].rule, "firewall.none_active");
        assert_eq!(f[0].actions[0].kind, ActionKind::EnableFirewall);
        let fw = FwSnapshot {
            backend: "iptables".into(),
            enabled: Some(true),
            default_inbound: Some("allow".into()),
            ..Default::default()
        };
        assert_eq!(audit(&fw)[0].rule, "firewall.default_inbound_allow");
    }

    #[test]
    fn normalize_expands_env() {
        std::env::set_var("ASA_TEST_ROOT", "C:\\Win");
        assert_eq!(
            normalize_path("%ASA_TEST_ROOT%\\System32\\svchost.exe"),
            "c:/win/system32/svchost.exe"
        );
        assert_eq!(normalize_path("%NOPE_ASA%\\x"), "%nope_asa%/x");
    }
}
