//! 基準線（`<config>/baseline.json`）：已知 listener、已知有網路的行程、已知目的地、已知 finding。
//! 之後的掃描比對它標出「新」項目（新 listener / 新目的地 / 新 finding）。

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::connection::{Connection, Direction, Listener};
use super::finding::Finding;
use super::report::BaselineDiffSummary;
use crate::error::AppResult;
use crate::store;

pub const BASELINE_FILE: &str = "baseline.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BaselineListener {
    pub proto: String,
    pub port: u16,
    pub bind: String,
    #[serde(default)]
    pub exe: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Baseline {
    pub schema_version: u32,
    pub created_at: String,
    pub updated_at: String,
    pub listeners: Vec<BaselineListener>,
    /// 曾經有網路活動的行程 exe 路徑。
    pub network_processes: Vec<String>,
    /// `ip:port` 或 domain。
    pub destinations: Vec<String>,
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BaselineDiff {
    pub new_listeners: Vec<BaselineListener>,
    pub new_network_processes: Vec<String>,
    pub new_destinations: Vec<String>,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
}

impl BaselineDiff {
    pub fn summary(&self) -> BaselineDiffSummary {
        BaselineDiffSummary {
            new_listeners: self.new_listeners.len() as u32,
            new_network_processes: self.new_network_processes.len() as u32,
            new_destinations: self.new_destinations.len() as u32,
            new_findings: self.new_findings.len() as u32,
            resolved_findings: self.resolved_findings.len() as u32,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.new_listeners.is_empty()
            && self.new_network_processes.is_empty()
            && self.new_destinations.is_empty()
            && self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
    }
}

/// 一次掃描的「目前狀態」切片，供 baseline 建立 / 比對。
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub listeners: Vec<BaselineListener>,
    pub network_processes: Vec<String>,
    pub destinations: Vec<String>,
    pub finding_ids: Vec<String>,
}

impl Snapshot {
    pub fn from_parts(listeners: &[Listener], connections: &[Connection], findings: &[Finding]) -> Self {
        let mut s = Snapshot::default();
        for l in listeners {
            s.listeners.push(BaselineListener {
                proto: l.proto.clone(),
                port: l.port,
                bind: if l.exposed { "any".into() } else { l.bind_ip.to_string() },
                exe: l.process.as_ref().and_then(|p| p.exe.clone()).unwrap_or_default(),
            });
        }
        let mut procs = BTreeSet::new();
        let mut dests = BTreeSet::new();
        for c in connections {
            if let Some(p) = &c.process {
                if let Some(exe) = &p.exe {
                    procs.insert(exe.clone());
                }
            }
            if c.direction == Direction::Outbound {
                if let (Some(ip), Some(port)) = (c.remote_ip, c.remote_port) {
                    if crate::util::net::classify(ip).is_public() {
                        dests.insert(format!("{ip}:{port}"));
                    }
                }
            }
        }
        s.network_processes = procs.into_iter().collect();
        s.destinations = dests.into_iter().collect();
        s.finding_ids = findings
            .iter()
            .filter(|f| f.suppressed_by.is_none())
            .map(|f| f.id.clone())
            .collect();
        s.listeners.sort();
        s.listeners.dedup();
        s
    }
}

impl Baseline {
    pub fn load(dir: &Path) -> AppResult<Option<Baseline>> {
        store::read_json_opt(dir, BASELINE_FILE)
    }

    pub fn save(&self, dir: &Path) -> AppResult<()> {
        store::write_json_in(dir, BASELINE_FILE, self)
    }

    pub fn from_snapshot(s: &Snapshot) -> Baseline {
        let now = crate::util::time::now_iso();
        Baseline {
            schema_version: 1,
            created_at: now.clone(),
            updated_at: now,
            listeners: s.listeners.clone(),
            network_processes: s.network_processes.clone(),
            destinations: s.destinations.clone(),
            finding_ids: s.finding_ids.clone(),
        }
    }

    /// 把目前狀態併進基準線（只增不減；`created_at` 不動）。
    pub fn merge(&mut self, s: &Snapshot) {
        for l in &s.listeners {
            if !self.listeners.contains(l) {
                self.listeners.push(l.clone());
            }
        }
        for p in &s.network_processes {
            if !self.network_processes.contains(p) {
                self.network_processes.push(p.clone());
            }
        }
        for d in &s.destinations {
            if !self.destinations.contains(d) {
                self.destinations.push(d.clone());
            }
        }
        for f in &s.finding_ids {
            if !self.finding_ids.contains(f) {
                self.finding_ids.push(f.clone());
            }
        }
        self.updated_at = crate::util::time::now_iso();
        if self.schema_version == 0 {
            self.schema_version = 1;
        }
    }

    pub fn diff(&self, s: &Snapshot) -> BaselineDiff {
        let known_l: BTreeSet<_> = self.listeners.iter().cloned().collect();
        let known_p: BTreeSet<_> = self.network_processes.iter().cloned().collect();
        let known_d: BTreeSet<_> = self.destinations.iter().cloned().collect();
        let known_f: BTreeSet<_> = self.finding_ids.iter().cloned().collect();
        let cur_f: BTreeSet<_> = s.finding_ids.iter().cloned().collect();
        BaselineDiff {
            new_listeners: s.listeners.iter().filter(|l| !known_l.contains(*l)).cloned().collect(),
            new_network_processes: s
                .network_processes
                .iter()
                .filter(|p| !known_p.contains(*p))
                .cloned()
                .collect(),
            new_destinations: s
                .destinations
                .iter()
                .filter(|d| !known_d.contains(*d))
                .cloned()
                .collect(),
            new_findings: s
                .finding_ids
                .iter()
                .filter(|f| !known_f.contains(*f))
                .cloned()
                .collect(),
            resolved_findings: self
                .finding_ids
                .iter()
                .filter(|f| !cur_f.contains(*f))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_detects_new_and_resolved() {
        let base = Baseline::from_snapshot(&Snapshot {
            listeners: vec![BaselineListener {
                proto: "tcp".into(),
                port: 22,
                bind: "any".into(),
                exe: "sshd".into(),
            }],
            network_processes: vec!["/usr/bin/curl".into()],
            destinations: vec!["1.1.1.1:443".into()],
            finding_ids: vec!["f_a".into(), "f_b".into()],
        });
        let cur = Snapshot {
            listeners: vec![
                BaselineListener {
                    proto: "tcp".into(),
                    port: 22,
                    bind: "any".into(),
                    exe: "sshd".into(),
                },
                BaselineListener {
                    proto: "tcp".into(),
                    port: 4444,
                    bind: "any".into(),
                    exe: "nc".into(),
                },
            ],
            network_processes: vec!["/usr/bin/curl".into(), "/tmp/x".into()],
            destinations: vec!["1.1.1.1:443".into(), "9.9.9.9:80".into()],
            finding_ids: vec!["f_a".into(), "f_c".into()],
        };
        let d = base.diff(&cur);
        assert_eq!(d.new_listeners.len(), 1);
        assert_eq!(d.new_network_processes, vec!["/tmp/x".to_string()]);
        assert_eq!(d.new_destinations, vec!["9.9.9.9:80".to_string()]);
        assert_eq!(d.new_findings, vec!["f_c".to_string()]);
        assert_eq!(d.resolved_findings, vec!["f_b".to_string()]);
        assert_eq!(d.summary().new_listeners, 1);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Baseline::load(dir.path()).unwrap().is_none());
        let b = Baseline::from_snapshot(&Snapshot::default());
        b.save(dir.path()).unwrap();
        let back = Baseline::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.schema_version, 1);
    }
}
