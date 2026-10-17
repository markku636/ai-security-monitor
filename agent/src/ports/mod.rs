//! ports 引擎：每個對外 listener 對照防火牆狀態算可達性（僅本機／可連入／已阻擋／未知），
//! 高風險服務真的能從網路連入時報出。另提供受限的 TCP 連線探測（只掃自己網段，見 probe.rs）。

pub mod probe;

use async_trait::async_trait;
use serde::Serialize;

use crate::connections::RiskyTable;
use crate::error::AppResult;
use crate::firewall::{reachability, FwSnapshot};
use crate::model::connection::{Listener, Reachability};
use crate::model::finding::{ActionKind, Evidence, Finding, ProposedAction, ScannerId, Severity};
use crate::scan::{ScanCtx, ScanOutput, Scanner};

#[derive(Debug, Default, Clone, Serialize)]
pub struct PortsSummary {
    pub listeners: usize,
    pub exposed: usize,
    pub open: usize,
    pub filtered: usize,
    pub unknown: usize,
}

fn lower(sev: Severity) -> Severity {
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        _ => Severity::Info,
    }
}

fn process_label(l: &Listener) -> String {
    l.process
        .as_ref()
        .map(|p| format!("{} (pid {})", p.name, p.pid))
        .unwrap_or_else(|| t!("未知行程").to_string())
}

fn bind_label(l: &Listener) -> String {
    if l.bind_ip.is_unspecified() {
        "0.0.0.0/::".into()
    } else {
        l.bind_ip.to_string()
    }
}

/// 為 listener 填入可達性，並對高風險服務產生 finding。
pub fn assess(listeners: &mut [Listener], fw: Option<&FwSnapshot>, risky: &RiskyTable) -> (Vec<Finding>, PortsSummary) {
    let mut findings = Vec::new();
    let mut sum = PortsSummary {
        listeners: listeners.len(),
        ..Default::default()
    };
    let mut seen = std::collections::HashSet::new();
    for l in listeners.iter_mut() {
        let r = reachability(fw, l);
        l.reachability = Some(r.clone());
        if !l.exposed {
            continue;
        }
        sum.exposed += 1;
        match r {
            Reachability::Open { .. } => sum.open += 1,
            Reachability::Filtered => sum.filtered += 1,
            _ => sum.unknown += 1,
        }
        let Some(rp) = risky.listening(&l.proto, l.port) else {
            continue;
        };
        // 同一 port 綁多個位址（0.0.0.0 與 ::）只報一次。
        if !seen.insert((l.proto.clone(), l.port)) {
            continue;
        }
        let key = format!("{}:{}", l.proto, l.port);
        let (rule, sev, title, detail, rec) = match &r {
            Reachability::Open { rule } => (
                "ports.exposed_open",
                rp.severity,
                tf!(
                    "{name}（{proto} {port}）可從網路連入",
                    name = rp.name,
                    proto = l.proto,
                    port = l.port
                ),
                tf!(
                    "{process} 綁在 {bind}，防火牆沒有阻擋（{why}）：{rationale}",
                    process = process_label(l),
                    bind = bind_label(l),
                    why = rule.clone().unwrap_or_else(|| t!("防火牆關閉或預設允許").to_string()),
                    rationale = rp.rationale
                ),
                t!("不需對外就改綁 127.0.0.1；需要的話用防火牆只允許特定來源"),
            ),
            Reachability::Filtered => (
                "ports.exposed_filtered",
                Severity::Low,
                tf!(
                    "{name}（{proto} {port}）綁在所有介面，目前被防火牆阻擋",
                    name = rp.name,
                    proto = l.proto,
                    port = l.port
                ),
                tf!(
                    "{process} 綁在 {bind}；防火牆擋住了連入，但只要規則變動就會曝露：{rationale}",
                    process = process_label(l),
                    bind = bind_label(l),
                    rationale = rp.rationale
                ),
                t!("縱深防禦：改綁 127.0.0.1 或內部介面"),
            ),
            _ => (
                "ports.exposed_unknown",
                lower(rp.severity).max(Severity::Low),
                tf!(
                    "{name}（{proto} {port}）對外監聽，無法確認防火牆是否阻擋",
                    name = rp.name,
                    proto = l.proto,
                    port = l.port
                ),
                tf!(
                    "{process} 綁在 {bind}；讀不到防火牆規則（以系統管理員身分重跑可確認）：{rationale}",
                    process = process_label(l),
                    bind = bind_label(l),
                    rationale = rp.rationale
                ),
                t!("以系統管理員身分執行 ai-security-monitor fw audit 確認是否可連入"),
            ),
        };
        let mut f = Finding::new(
            ScannerId::Ports,
            rule,
            &key,
            sev,
            title,
            detail,
            Evidence::Port {
                proto: l.proto.clone(),
                port: l.port,
                bind: bind_label(l),
                pid: l.process.as_ref().map(|p| p.pid),
                process: l.process.as_ref().map(|p| p.name.clone()),
                reachability: r.as_str().into(),
            },
            rec,
        )
        .with_tag("exposed");
        if !matches!(r, Reachability::Filtered) {
            f = f.with_action(ProposedAction {
                kind: ActionKind::ClosePort,
                params: serde_json::json!({ "proto": l.proto, "port": l.port, "direction": "inbound" }),
                requires_elevation: true,
                destructive: false,
                reversible: true,
                description: tf!("以防火牆封鎖對內 {proto} {port}", proto = l.proto, port = l.port),
            });
        }
        findings.push(f);
    }
    (findings, sum)
}

pub struct PortsScanner;

#[async_trait]
impl Scanner for PortsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Ports
    }

    fn depends_on(&self) -> &'static [ScannerId] {
        &[ScannerId::Connections, ScannerId::Firewall]
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let risky = RiskyTable::load();
        let mut shared = ctx.shared.lock().await;
        let fw: Option<FwSnapshot> = shared
            .firewall_state
            .clone()
            .and_then(|v| serde_json::from_value(v).ok());
        let (findings, sum) = assess(&mut shared.listeners, fw.as_ref(), &risky);
        Ok(ScanOutput {
            findings,
            warnings: Vec::new(),
            summary: serde_json::to_value(&sum).ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FwRule, PortSpec};

    fn l(port: u16, bind: &str) -> Listener {
        Listener {
            proto: "tcp".into(),
            bind_ip: bind.parse().unwrap(),
            port,
            process: None,
            exposed: bind != "127.0.0.1",
            reachability: None,
        }
    }

    #[test]
    fn open_filtered_unknown() {
        let risky = RiskyTable::load();
        let fw = FwSnapshot {
            backend: "ufw".into(),
            available: true,
            enabled: Some(true),
            default_inbound: Some("block".into()),
            inbound_allow: vec![FwRule::simple("6379", "tcp", vec![PortSpec::Single(6379)])],
            ..Default::default()
        };
        let mut ls = vec![
            l(6379, "0.0.0.0"),
            l(6379, "::"),
            l(3306, "0.0.0.0"),
            l(5432, "127.0.0.1"),
            l(51234, "0.0.0.0"),
        ];
        let (f, sum) = assess(&mut ls, Some(&fw), &risky);
        assert_eq!(f.len(), 2);
        let redis = f.iter().find(|x| x.rule == "ports.exposed_open").unwrap();
        assert_eq!(redis.severity, Severity::Critical);
        assert!(!redis.actions.is_empty());
        let mysql = f.iter().find(|x| x.rule == "ports.exposed_filtered").unwrap();
        assert_eq!(mysql.severity, Severity::Low);
        assert!(mysql.actions.is_empty());
        assert_eq!(ls[3].reachability, Some(Reachability::LocalOnly));
        assert_eq!((sum.exposed, sum.open, sum.filtered), (4, 2, 2));

        let mut ls2 = vec![l(6379, "0.0.0.0")];
        let (f2, _) = assess(&mut ls2, None, &risky);
        assert_eq!(f2[0].rule, "ports.exposed_unknown");
        assert_eq!(f2[0].severity, Severity::High);
    }
}
