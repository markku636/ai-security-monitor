//! Scanner trait 與 Pipeline。各引擎實作 `Scanner`，Pipeline 依相依順序執行、套白名單與基準線、算分、組 Report。

pub mod score;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::config::AgentConfig;
use crate::error::{AppError, AppResult};
use crate::model::allowlist::Allowlist;
use crate::model::baseline::{Baseline, Snapshot};
use crate::model::connection::{Connection, Listener};
use crate::model::finding::{Evidence, Finding, ScannerId};
use crate::model::report::{AgentInfo, InventorySummary, Report, Summaries, REPORT_SCHEMA_VERSION};

/// 掃描器對提權的需求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    NotNeeded,
    /// 沒提權也能跑，但結果較少（例：他人行程的 socket）。
    Preferred,
    Required,
}

/// 掃描器之間的交接資料（connections → intel / ports / traffic …）。
#[derive(Default, Debug)]
pub struct Shared {
    pub connections: Vec<Connection>,
    pub listeners: Vec<Listener>,
    pub firewall_state: Option<serde_json::Value>,
    pub inventory: Option<serde_json::Value>,
    pub events: Vec<serde_json::Value>,
}

pub struct ScanCtx {
    pub config: Arc<AgentConfig>,
    pub config_dir: PathBuf,
    pub allowlist: Allowlist,
    pub baseline: Option<Baseline>,
    pub shared: Mutex<Shared>,
    pub started_at: DateTime<Utc>,
    pub elevated: bool,
    pub online: bool,
    pub progress: Box<dyn Fn(&str) + Send + Sync>,
    /// 執行外部指令（測試可換成 FakeRunner）。
    pub runner: Arc<dyn crate::util::cmd::CmdRunner>,
    /// 這次要跑的掃描器（Pipeline 排序後填入），讓引擎知道後面還有誰（例：有 ports 時 connections 不重複報曝露）。
    pub plan: std::sync::Mutex<Vec<ScannerId>>,
}

impl ScanCtx {
    pub fn new(
        config: Arc<AgentConfig>,
        config_dir: PathBuf,
        allowlist: Allowlist,
        baseline: Option<Baseline>,
    ) -> Self {
        let online = config.scan.online;
        Self {
            config,
            config_dir,
            allowlist,
            baseline,
            shared: Mutex::new(Shared::default()),
            started_at: Utc::now(),
            elevated: crate::elevate::is_elevated(),
            online,
            progress: Box::new(|_| {}),
            runner: Arc::new(crate::util::cmd::RealRunner),
            plan: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn with_progress(mut self, f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.progress = Box::new(f);
        self
    }

    /// 這次掃描是否包含某掃描器。
    pub fn plans(&self, id: ScannerId) -> bool {
        self.plan.lock().map(|p| p.contains(&id)).unwrap_or(false)
    }

    pub fn with_runner(mut self, r: Arc<dyn crate::util::cmd::CmdRunner>) -> Self {
        self.runner = r;
        self
    }

    pub fn report_progress(&self, msg: &str) {
        (self.progress)(msg);
    }
}

#[derive(Debug, Default)]
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    /// 引擎層摘要（TrafficSummary / EventsSummary / inventory），由 Pipeline 塞進 `Report.summaries`。
    pub summary: Option<serde_json::Value>,
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn id(&self) -> ScannerId;
    fn depends_on(&self) -> &'static [ScannerId] {
        &[]
    }
    fn elevation(&self) -> Elevation {
        Elevation::NotNeeded
    }
    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput>;
}

pub struct Pipeline {
    scanners: Vec<Box<dyn Scanner>>,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    pub fn new() -> Self {
        Self { scanners: Vec::new() }
    }

    pub fn register(mut self, s: Box<dyn Scanner>) -> Self {
        self.scanners.push(s);
        self
    }

    pub fn available(&self) -> Vec<ScannerId> {
        self.scanners.iter().map(|s| s.id()).collect()
    }

    /// 以相依順序排出要跑的掃描器；被選的掃描器的相依項會自動加入。
    pub fn order(&self, selected: &[ScannerId]) -> AppResult<Vec<ScannerId>> {
        let available: HashSet<ScannerId> = self.available().into_iter().collect();
        let mut wanted: Vec<ScannerId> = Vec::new();
        let mut queue: Vec<ScannerId> = selected.to_vec();
        while let Some(id) = queue.pop() {
            if wanted.contains(&id) {
                continue;
            }
            if !available.contains(&id) {
                return Err(AppError::Scan(tf!("此版本沒有掃描器：{id}", id = id.as_str())));
            }
            wanted.push(id);
            if let Some(s) = self.scanners.iter().find(|s| s.id() == id) {
                queue.extend(s.depends_on().iter().copied());
            }
        }
        // 簡單拓撲排序：反覆挑出相依都已排入者。
        let mut ordered: Vec<ScannerId> = Vec::new();
        let mut remaining = wanted.clone();
        while !remaining.is_empty() {
            let before = ordered.len();
            remaining.retain(|id| {
                let deps = self
                    .scanners
                    .iter()
                    .find(|s| s.id() == *id)
                    .map(|s| s.depends_on())
                    .unwrap_or(&[]);
                if deps.iter().all(|d| ordered.contains(d)) {
                    ordered.push(*id);
                    false
                } else {
                    true
                }
            });
            if ordered.len() == before {
                return Err(AppError::Scan(t!("掃描器相依順序有循環").into()));
            }
        }
        Ok(ordered)
    }

    /// 執行並組出 Report。
    pub async fn run(&self, selected: &[ScannerId], ctx: &ScanCtx, agent: AgentInfo) -> AppResult<Report> {
        let order = self.order(selected)?;
        if let Ok(mut p) = ctx.plan.lock() {
            *p = order.clone();
        }
        let mut findings: Vec<Finding> = Vec::new();
        let mut warnings: Vec<String> = Vec::new();
        let mut summaries = Summaries::default();
        let mut partial = false;

        for id in &order {
            let scanner = self
                .scanners
                .iter()
                .find(|s| s.id() == *id)
                .expect("ordered from available");
            if scanner.elevation() == Elevation::Required && !ctx.elevated {
                warnings.push(tf!("掃描器 {id} 需要系統管理員權限，已略過", id = id.as_str()));
                partial = true;
                continue;
            }
            if scanner.elevation() == Elevation::Preferred && !ctx.elevated {
                partial = true;
            }
            ctx.report_progress(&tf!("執行掃描器：{id}", id = id.as_str()));
            match scanner.run(ctx).await {
                Ok(out) => {
                    findings.extend(out.findings);
                    warnings.extend(out.warnings);
                    if let Some(s) = out.summary {
                        match id {
                            ScannerId::Traffic => summaries.traffic = Some(s),
                            ScannerId::Events => summaries.events = Some(s),
                            ScannerId::Vuln => summaries.vuln = Some(s),
                            ScannerId::Hardening => {
                                summaries.hardening = serde_json::from_value(s).ok();
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    warnings.push(tf!("掃描器 {id} 失敗：{e}", id = id.as_str(), e = e.message()));
                    partial = true;
                }
            }
        }

        // 同一 finding id（例：同 port 同時綁 0.0.0.0 與 ::）只保留一筆，標籤合併。
        {
            let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            let mut deduped: Vec<Finding> = Vec::with_capacity(findings.len());
            for f in findings.drain(..) {
                if let Some(&i) = seen.get(&f.id) {
                    for t in f.tags {
                        if !deduped[i].tags.contains(&t) {
                            deduped[i].tags.push(t);
                        }
                    }
                } else {
                    seen.insert(f.id.clone(), deduped.len());
                    deduped.push(f);
                }
            }
            findings = deduped;
        }

        // 白名單：命中的 finding 標 suppressed_by（保留在報告裡，hub 可選擇隱藏）。
        for f in &mut findings {
            if let Some(entry) = allowlist_hit(&ctx.allowlist, f) {
                f.suppressed_by = Some(entry);
            }
        }

        let shared = ctx.shared.lock().await;
        let snapshot = Snapshot::from_parts(&shared.listeners, &shared.connections, &findings);
        let inv = shared.inventory.as_ref();
        let inventory = InventorySummary {
            packages: inv.and_then(|v| v["packages"].as_u64()).unwrap_or(0) as u32,
            by_ecosystem: inv
                .and_then(|v| v["by_ecosystem"].as_object().cloned())
                .unwrap_or_default(),
            listeners: shared.listeners.len() as u32,
            connections: shared.connections.len() as u32,
            processes_with_network: snapshot.network_processes.len() as u32,
        };
        drop(shared);

        let baseline_summary = ctx.baseline.as_ref().map(|b| {
            let d = b.diff(&snapshot);
            for f in &mut findings {
                if d.new_findings.contains(&f.id) && !f.tags.iter().any(|t| t == "new") {
                    f.tags.push("new".into());
                }
            }
            d.summary()
        });

        let score = score::compute(&findings, summaries.hardening.as_ref(), &order);
        let mut scanners_run = order.clone();
        scanners_run.dedup();

        Ok(Report {
            schema_version: REPORT_SCHEMA_VERSION,
            report_id: uuid::Uuid::new_v4().to_string(),
            agent,
            started_at: ctx.started_at,
            finished_at: Utc::now(),
            scanners_run,
            warnings,
            findings,
            inventory,
            summaries,
            baseline: baseline_summary,
            score,
            partial,
        })
    }
}

/// 檢查 finding 是否命中白名單；回傳條目 id。
fn allowlist_hit(al: &Allowlist, f: &Finding) -> Option<String> {
    if al.entries.is_empty() {
        return None;
    }
    let port = match &f.evidence {
        Evidence::Connection(c) => c.remote_port.or(Some(c.local_port)),
        Evidence::Port { port, .. } => Some(*port),
        _ => None,
    };
    if let Some(e) = al.match_rule(&f.rule, port) {
        return Some(e.id.clone());
    }
    match &f.evidence {
        Evidence::Connection(c) => {
            if let Some(ip) = c.remote_ip {
                if let Some(e) = al.match_ip(ip) {
                    return Some(e.id.clone());
                }
            }
            if let Some(exe) = c.process.as_ref().and_then(|p| p.exe.as_deref()) {
                if let Some(e) = al.match_process_path(exe) {
                    return Some(e.id.clone());
                }
            }
        }
        Evidence::Process { exe: Some(exe), .. } => {
            if let Some(e) = al.match_process_path(exe) {
                return Some(e.id.clone());
            }
        }
        Evidence::Flow { remote, domain, .. } => {
            if let Some(ip) = remote.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()) {
                if let Some(e) = al.match_ip(ip) {
                    return Some(e.id.clone());
                }
            }
            if let Some(d) = domain {
                if let Some(e) = al.match_domain(d) {
                    return Some(e.id.clone());
                }
            }
        }
        _ => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::Severity;

    struct Fake(ScannerId, &'static [ScannerId]);

    #[async_trait]
    impl Scanner for Fake {
        fn id(&self) -> ScannerId {
            self.0
        }
        fn depends_on(&self) -> &'static [ScannerId] {
            self.1
        }
        async fn run(&self, _ctx: &ScanCtx) -> AppResult<ScanOutput> {
            let f = Finding::new(
                self.0,
                "fake",
                self.0.as_str(),
                Severity::Low,
                "t",
                "d",
                Evidence::Text { detail: "x".into() },
                "r",
            );
            Ok(ScanOutput {
                findings: vec![f],
                warnings: vec![],
                summary: None,
            })
        }
    }

    fn ctx() -> ScanCtx {
        let dir = std::env::temp_dir();
        ScanCtx::new(Arc::new(AgentConfig::default()), dir, Allowlist::default(), None)
    }

    #[tokio::test]
    async fn orders_dependencies_and_runs() {
        let p = Pipeline::new()
            .register(Box::new(Fake(ScannerId::Intel, &[ScannerId::Connections])))
            .register(Box::new(Fake(ScannerId::Connections, &[])));
        let order = p.order(&[ScannerId::Intel]).unwrap();
        assert_eq!(order, vec![ScannerId::Connections, ScannerId::Intel]);
        let r = p
            .run(&[ScannerId::Intel], &ctx(), AgentInfo::current("a"))
            .await
            .unwrap();
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.scanners_run, order);
        assert_eq!(r.schema_version, 1);
    }

    #[test]
    fn unknown_scanner_is_an_error() {
        let p = Pipeline::new();
        assert!(matches!(p.order(&[ScannerId::Vuln]), Err(AppError::Scan(_))));
    }

    #[tokio::test]
    async fn allowlist_rule_suppresses() {
        let p = Pipeline::new().register(Box::new(Fake(ScannerId::Connections, &[])));
        let mut c = ctx();
        c.allowlist
            .add(Some(crate::model::allowlist::AllowKind::Rule), "fake", None)
            .unwrap();
        let r = p
            .run(&[ScannerId::Connections], &c, AgentInfo::current("a"))
            .await
            .unwrap();
        assert!(r.findings[0].suppressed_by.is_some());
    }
}
