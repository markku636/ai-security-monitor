//! Linux：依序偵測 firewalld（運作中）→ ufw（啟用中）→ nftables → iptables → 都沒有。
//! 讀規則多半需要 root；讀不到時狀態記為未知並提示提權。

use super::{FirewallBackend, FwProfile, FwRule, FwSnapshot, PortSpec};
use crate::util::cmd::{CmdOutput, CmdRunner, CmdSpec};

// ---------------------------------------------------------------- service maps

/// firewalld 服務名 → (協定, port)。
pub fn firewalld_service(name: &str) -> Vec<(&'static str, PortSpec)> {
    use PortSpec::*;
    match name {
        "ssh" => vec![("tcp", Single(22))],
        "http" => vec![("tcp", Single(80))],
        "https" => vec![("tcp", Single(443))],
        "http3" => vec![("udp", Single(443))],
        "dhcpv6-client" => vec![("udp", Single(546))],
        "dhcp" => vec![("udp", Single(67))],
        "cockpit" => vec![("tcp", Single(9090))],
        "mdns" => vec![("udp", Single(5353))],
        "samba" => vec![("tcp", Single(139)), ("tcp", Single(445)), ("udp", Range(137, 138))],
        "samba-client" => vec![("udp", Range(137, 138))],
        "mysql" => vec![("tcp", Single(3306))],
        "postgresql" => vec![("tcp", Single(5432))],
        "redis" => vec![("tcp", Single(6379))],
        "dns" => vec![("tcp", Single(53)), ("udp", Single(53))],
        "ftp" => vec![("tcp", Single(21))],
        "smtp" => vec![("tcp", Single(25))],
        "rdp" => vec![("tcp", Single(3389))],
        "vnc-server" => vec![("tcp", Range(5900, 5903))],
        "nfs" => vec![("tcp", Single(2049))],
        "ntp" => vec![("udp", Single(123))],
        "docker-registry" => vec![("tcp", Single(5000))],
        "kube-apiserver" => vec![("tcp", Single(6443))],
        "prometheus" => vec![("tcp", Single(9090))],
        _ => Vec::new(),
    }
}

/// ufw 應用程式設定檔 → (協定, port)。
pub fn ufw_app(name: &str) -> Vec<(&'static str, PortSpec)> {
    use PortSpec::*;
    match name.to_ascii_lowercase().as_str() {
        "openssh" => vec![("tcp", Single(22))],
        "nginx full" | "apache full" => vec![("tcp", Single(80)), ("tcp", Single(443))],
        "nginx http" | "apache" | "www" => vec![("tcp", Single(80))],
        "nginx https" | "apache secure" | "www secure" => vec![("tcp", Single(443))],
        "samba" => vec![("tcp", Single(139)), ("tcp", Single(445)), ("udp", Range(137, 138))],
        "postfix" => vec![("tcp", Single(25))],
        "cups" => vec![("tcp", Single(631))],
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------- parsers

/// `ufw status verbose` → (啟用, 預設連入, 允許規則)。
pub fn parse_ufw(text: &str) -> (Option<bool>, Option<String>, Vec<FwRule>) {
    let mut enabled = None;
    let mut default_in = None;
    let mut rules = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let l = line.trim();
        if let Some(s) = l.strip_prefix("Status:") {
            enabled = Some(s.trim().eq_ignore_ascii_case("active"));
        } else if let Some(d) = l.strip_prefix("Default:") {
            let first = d.split(',').next().unwrap_or("").to_ascii_lowercase();
            default_in = Some(if first.contains("allow") { "allow" } else { "block" }.to_string());
        } else if l.starts_with("--") {
            in_table = true;
        } else if in_table && !l.is_empty() {
            // `22/tcp  ALLOW IN  Anywhere`；To 欄位可能含空白（Nginx Full），以 ALLOW 切開。
            let upper = l.to_ascii_uppercase();
            let Some(pos) = upper.find(" ALLOW") else {
                continue;
            };
            let to = l[..pos].trim().trim_end_matches("(v6)").trim();
            let from = l[pos..].split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
            let (spec, proto) = match to.split_once('/') {
                Some((p, proto)) => (p, proto.to_ascii_lowercase()),
                None => (to, "any".to_string()),
            };
            let first = spec.chars().next().unwrap_or('x');
            let mut push = |proto: &str, ports: Vec<PortSpec>| {
                let mut r = FwRule::simple(l, proto, ports);
                r.remote_address = if from.is_empty() || from.starts_with("Anywhere") {
                    "any".into()
                } else {
                    from.clone()
                };
                rules.push(r);
            };
            if first.is_ascii_digit() {
                push(&proto, PortSpec::list(spec));
            } else {
                for (p, port) in ufw_app(spec) {
                    push(p, vec![port]);
                }
            }
        }
    }
    (enabled, default_in, rules)
}

/// `firewall-cmd --list-all` → (預設連入, 允許規則)。target `default`/`reject`/`drop` 皆視為封鎖、`ACCEPT` 為允許。
pub fn parse_firewalld(text: &str) -> (Option<String>, Vec<FwRule>) {
    let mut default_in = Some("block".to_string());
    let mut rules = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(t) = l.strip_prefix("target:") {
            if t.trim().eq_ignore_ascii_case("accept") {
                default_in = Some("allow".into());
            }
        } else if let Some(s) = l.strip_prefix("services:") {
            for svc in s.split_whitespace() {
                for (proto, port) in firewalld_service(svc) {
                    rules.push(FwRule::simple(&format!("service:{svc}"), proto, vec![port]));
                }
            }
        } else if let Some(p) = l.strip_prefix("ports:") {
            for item in p.split_whitespace() {
                if let Some((port, proto)) = item.split_once('/') {
                    rules.push(FwRule::simple(
                        &format!("port:{item}"),
                        &proto.to_ascii_lowercase(),
                        vec![PortSpec::parse(port)],
                    ));
                }
            }
        }
    }
    (default_in, rules)
}

fn nft_ports(after_dport: &str) -> Vec<PortSpec> {
    let s = after_dport.trim();
    if let Some(rest) = s.strip_prefix('{') {
        let inner = rest.split('}').next().unwrap_or("");
        return inner.split(',').map(|p| PortSpec::parse(p.trim())).collect();
    }
    s.split_whitespace()
        .next()
        .map(|p| vec![PortSpec::parse(p)])
        .unwrap_or_default()
}

/// `nft list ruleset` → (有 input hook 鏈, 預設政策, 允許規則)。
pub fn parse_nft(text: &str) -> (bool, Option<String>, Vec<FwRule>) {
    let mut has_input = false;
    let mut policy: Option<String> = None;
    let mut rules = Vec::new();
    let mut in_input = false;
    let mut depth_at_chain = 0usize;
    let mut depth = 0usize;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("chain ") && l.ends_with('{') {
            depth_at_chain = depth;
        }
        if l.contains("hook input") {
            in_input = true;
            has_input = true;
            if l.contains("policy drop") || l.contains("policy reject") {
                policy = Some("block".into());
            } else if l.contains("policy accept") && policy.is_none() {
                policy = Some("allow".into());
            }
        }
        if in_input && l.ends_with("accept") && !l.contains("hook input") {
            let skip =
                l.contains("ct state") || l.starts_with("iif") || l.starts_with("iifname") || l.contains("saddr");
            if let Some(pos) = l.find("dport") {
                let proto = if l.starts_with("tcp") || l.contains(" tcp dport") {
                    "tcp"
                } else if l.starts_with("udp") || l.contains(" udp dport") {
                    "udp"
                } else {
                    "any"
                };
                rules.push(FwRule::simple(l, proto, nft_ports(&l[pos + 5..])));
            } else if !skip && l == "accept" {
                rules.push(FwRule::simple(l, "any", vec![PortSpec::Any]));
            }
        }
        depth += l.matches('{').count();
        depth = depth.saturating_sub(l.matches('}').count());
        if in_input && depth <= depth_at_chain {
            in_input = false;
        }
    }
    (has_input, policy, rules)
}

/// `iptables -S INPUT` → (預設政策, 允許規則)。
pub fn parse_iptables(text: &str) -> (Option<String>, Vec<FwRule>) {
    let mut policy = None;
    let mut rules = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(p) = l.strip_prefix("-P INPUT ") {
            policy = Some(if p.trim() == "ACCEPT" { "allow" } else { "block" }.to_string());
            continue;
        }
        if !l.starts_with("-A INPUT") || !l.ends_with("-j ACCEPT") {
            continue;
        }
        let toks: Vec<&str> = l.split_whitespace().collect();
        let get = |flag: &str| {
            toks.iter()
                .position(|t| *t == flag)
                .and_then(|i| toks.get(i + 1))
                .copied()
        };
        if get("-i") == Some("lo") || l.contains("--state") || l.contains("--ctstate") || get("-s").is_some() {
            continue;
        }
        let proto = get("-p").unwrap_or("any").to_ascii_lowercase();
        let ports = if let Some(p) = get("--dport") {
            vec![PortSpec::parse(p)]
        } else if let Some(p) = get("--dports") {
            PortSpec::list(p)
        } else {
            vec![PortSpec::Any]
        };
        rules.push(FwRule::simple(l, &proto, ports));
    }
    (policy, rules)
}

// ---------------------------------------------------------------- backends

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Firewalld,
    Ufw,
    Nft,
    Iptables,
    None,
}

pub struct Linux(pub Kind);

fn out_text(outputs: &[Option<CmdOutput>], i: usize) -> Option<&CmdOutput> {
    outputs.get(i).and_then(|o| o.as_ref())
}

fn base(kind: &str) -> FwSnapshot {
    FwSnapshot {
        backend: kind.into(),
        available: true,
        profiles: Vec::new(),
        ..Default::default()
    }
}

fn finish(mut s: FwSnapshot, enabled: Option<bool>, default_in: Option<String>, rules: Vec<FwRule>) -> FwSnapshot {
    s.enabled = enabled;
    s.default_inbound = default_in.clone();
    s.inbound_allow = rules;
    if let Some(e) = enabled {
        s.profiles.push(FwProfile {
            name: s.backend.clone(),
            enabled: e,
            default_inbound: default_in.unwrap_or_default(),
            default_outbound: "allow".into(),
            active: true,
        });
    }
    s
}

impl FirewallBackend for Linux {
    fn id(&self) -> &'static str {
        match self.0 {
            Kind::Firewalld => "firewalld",
            Kind::Ufw => "ufw",
            Kind::Nft => "nftables",
            Kind::Iptables => "iptables",
            Kind::None => "none",
        }
    }

    fn read_specs(&self) -> Vec<CmdSpec> {
        match self.0 {
            Kind::Firewalld => vec![
                CmdSpec::new("firewall-cmd", &["--state"]).describe(t!("讀取 firewalld 狀態")),
                CmdSpec::new("firewall-cmd", &["--list-all"]).describe(t!("讀取 firewalld 預設 zone")),
            ],
            Kind::Ufw => vec![CmdSpec::new("ufw", &["status", "verbose"])
                .elevated()
                .describe(t!("讀取 ufw 狀態"))],
            Kind::Nft => vec![CmdSpec::new("nft", &["list", "ruleset"])
                .elevated()
                .describe(t!("讀取 nftables 規則"))],
            Kind::Iptables => vec![CmdSpec::new("iptables", &["-S", "INPUT"])
                .elevated()
                .describe(t!("讀取 iptables INPUT 鏈"))],
            Kind::None => Vec::new(),
        }
    }

    fn parse(&self, outputs: &[Option<CmdOutput>], elevated: bool) -> FwSnapshot {
        let id = self.id();
        let denied = |o: Option<&CmdOutput>| {
            o.map(|o| !o.ok() && (o.permission_denied() || !elevated))
                .unwrap_or(false)
        };
        match self.0 {
            Kind::None => FwSnapshot {
                backend: "none".into(),
                available: false,
                enabled: Some(false),
                notes: vec![t!("沒有找到 nft / iptables / ufw / firewall-cmd").to_string()],
                ..Default::default()
            },
            Kind::Firewalld => {
                let state = out_text(outputs, 0)
                    .filter(|o| o.ok())
                    .map(|o| o.stdout.trim() == "running");
                let list = out_text(outputs, 1).filter(|o| o.ok());
                match (state, list) {
                    (Some(true), Some(l)) => {
                        let (din, rules) = parse_firewalld(&l.stdout);
                        finish(base(id), Some(true), din, rules)
                    }
                    (Some(false), _) => finish(base(id), Some(false), None, Vec::new()),
                    _ => {
                        let mut s = base(id);
                        s.needs_elevation = denied(out_text(outputs, 1));
                        s
                    }
                }
            }
            Kind::Ufw => match out_text(outputs, 0) {
                Some(o) if o.ok() => {
                    let (en, din, rules) = parse_ufw(&o.stdout);
                    finish(base(id), en, din, rules)
                }
                o => {
                    let mut s = base(id);
                    s.needs_elevation = denied(o);
                    s
                }
            },
            Kind::Nft => match out_text(outputs, 0) {
                Some(o) if o.ok() => {
                    let (has_input, policy, rules) = parse_nft(&o.stdout);
                    if !has_input {
                        finish(base(id), Some(false), None, Vec::new())
                    } else {
                        finish(base(id), Some(true), policy.or(Some("allow".into())), rules)
                    }
                }
                o => {
                    let mut s = base(id);
                    s.needs_elevation = denied(o);
                    s
                }
            },
            Kind::Iptables => match out_text(outputs, 0) {
                Some(o) if o.ok() => {
                    let (policy, rules) = parse_iptables(&o.stdout);
                    let empty = rules.is_empty() && policy.as_deref() != Some("block");
                    finish(base(id), Some(!empty), policy, rules)
                }
                o => {
                    let mut s = base(id);
                    s.needs_elevation = denied(o);
                    s
                }
            },
        }
    }
}

/// 偵測後端：服務狀態（免 root）＋ PATH 上的工具。
pub async fn detect(runner: &dyn CmdRunner) -> Box<dyn FirewallBackend> {
    let active = |o: Option<CmdOutput>| o.map(|o| o.stdout.trim() == "active").unwrap_or(false);
    let fwd = runner
        .run(&CmdSpec::new("systemctl", &["is-active", "firewalld"]))
        .await
        .ok();
    if active(fwd) {
        return Box::new(Linux(Kind::Firewalld));
    }
    let ufw = runner.run(&CmdSpec::new("systemctl", &["is-active", "ufw"])).await.ok();
    if active(ufw) && crate::cli::doctor_cmd::find_in_path("ufw").is_some() {
        return Box::new(Linux(Kind::Ufw));
    }
    if crate::cli::doctor_cmd::find_in_path("nft").is_some() {
        return Box::new(Linux(Kind::Nft));
    }
    if crate::cli::doctor_cmd::find_in_path("iptables").is_some() {
        return Box::new(Linux(Kind::Iptables));
    }
    Box::new(Linux(Kind::None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{audit, reachability};
    use crate::model::connection::{Listener, Reachability};

    fn fx(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/firewall")
                .join(name),
        )
        .unwrap()
    }

    fn l(proto: &str, port: u16) -> Listener {
        Listener {
            proto: proto.into(),
            bind_ip: "0.0.0.0".parse().unwrap(),
            port,
            process: None,
            exposed: true,
            reachability: None,
        }
    }

    #[test]
    fn ufw() {
        let (en, din, rules) = parse_ufw(&fx("ufw_status.txt"));
        assert_eq!(en, Some(true));
        assert_eq!(din.as_deref(), Some("block"));
        let s = finish(base("ufw"), en, din, rules);
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 22)),
            Reachability::Open { .. }
        ));
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 443)),
            Reachability::Open { .. }
        ));
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 8005)),
            Reachability::Open { .. }
        ));
        assert_eq!(reachability(Some(&s), &l("tcp", 6379)), Reachability::Filtered);
        assert!(audit(&s).is_empty());
    }

    #[test]
    fn firewalld() {
        let (din, rules) = parse_firewalld(&fx("firewalld_list_all.txt"));
        let s = finish(base("firewalld"), Some(true), din, rules);
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 22)),
            Reachability::Open { .. }
        ));
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 9090)),
            Reachability::Open { .. }
        ));
        assert!(matches!(
            reachability(Some(&s), &l("udp", 9005)),
            Reachability::Open { .. }
        ));
        assert_eq!(reachability(Some(&s), &l("tcp", 3306)), Reachability::Filtered);
    }

    #[test]
    fn nft() {
        let (has, policy, rules) = parse_nft(&fx("nft_list.txt"));
        assert!(has);
        assert_eq!(policy.as_deref(), Some("block"));
        assert_eq!(rules.len(), 3);
        let s = finish(base("nftables"), Some(true), policy, rules);
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 80)),
            Reachability::Open { .. }
        ));
        assert!(matches!(
            reachability(Some(&s), &l("udp", 5005)),
            Reachability::Open { .. }
        ));
        assert_eq!(reachability(Some(&s), &l("tcp", 5005)), Reachability::Filtered);
    }

    #[test]
    fn iptables() {
        let (policy, rules) = parse_iptables(&fx("iptables_S.txt"));
        assert_eq!(policy.as_deref(), Some("block"));
        assert_eq!(rules.len(), 3);
        let s = finish(base("iptables"), Some(true), policy, rules);
        assert!(matches!(
            reachability(Some(&s), &l("tcp", 443)),
            Reachability::Open { .. }
        ));
        assert_eq!(reachability(Some(&s), &l("tcp", 3389)), Reachability::Filtered);
        let (p2, r2) = parse_iptables("-P INPUT ACCEPT\n");
        let s2 = finish(
            base("iptables"),
            Some(!r2.is_empty() || p2.as_deref() == Some("block")),
            p2,
            r2,
        );
        assert_eq!(s2.enabled, Some(false));
        assert_eq!(audit(&s2)[0].rule, "firewall.none_active");
    }

    #[test]
    fn permission_denied_is_unknown() {
        let outs = vec![Some(CmdOutput::failure(
            1,
            "ERROR: You need to be root to run this script",
        ))];
        let s = Linux(Kind::Ufw).parse(&outs, false);
        assert_eq!(s.enabled, None);
        assert!(s.needs_elevation);
        assert_eq!(reachability(Some(&s), &l("tcp", 22)), Reachability::Unknown);
    }
}
