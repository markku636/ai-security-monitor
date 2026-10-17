//! 期望狀態（`<config>/firewall/desired.json` ＋ `feed-nets.txt`）：ai-security-monitor 封鎖了什麼、關了哪些 port、同步了哪些情資網段。
//! pf / nftables 規則重開機不會保留，服務啟動時 `ai-security-monitor fw ensure` 依此重套；也用來安全地解除封鎖。

use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::plan::{Dir, FwAction};
use crate::error::AppResult;
use crate::store;

pub const DESIRED_FILE: &str = "firewall/desired.json";
pub const FEED_NETS_FILE: &str = "firewall/feed-nets.txt";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockedEntry {
    pub net: IpNet,
    pub direction: Dir,
    pub reason: String,
    pub added_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClosedPort {
    pub proto: String,
    pub port: u16,
    pub added_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DesiredState {
    pub schema_version: u32,
    pub blocked: Vec<BlockedEntry>,
    pub closed_ports: Vec<ClosedPort>,
    pub feed_nets: usize,
    pub feed_ids: Vec<String>,
    pub feed_synced_at: Option<String>,
    /// 最後一次套用時使用的後端（換後端時要先清掉舊的）。
    pub backend: Option<String>,
}

pub fn feed_nets_path(dir: &Path) -> PathBuf {
    dir.join(FEED_NETS_FILE)
}

impl DesiredState {
    pub fn load(dir: &Path) -> AppResult<DesiredState> {
        store::read_json_in(dir, DESIRED_FILE)
    }

    pub fn save(&self, dir: &Path) -> AppResult<()> {
        store::ensure_dir(&dir.join("firewall"))?;
        store::write_json_in(dir, DESIRED_FILE, self)
    }

    pub fn load_feed_nets(dir: &Path) -> Vec<IpNet> {
        std::fs::read_to_string(feed_nets_path(dir))
            .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default()
    }

    pub fn save_feed_nets(dir: &Path, nets: &[IpNet]) -> AppResult<()> {
        store::ensure_dir(&dir.join("firewall"))?;
        let body: String = nets.iter().map(|n| format!("{n}\n")).collect();
        store::write_bytes_atomic(&feed_nets_path(dir), body.as_bytes())
    }

    pub fn is_blocked(&self, net: &IpNet) -> bool {
        self.blocked.iter().any(|b| b.net == *net)
    }

    /// 動作成功套用後更新期望狀態。
    pub fn apply(&mut self, dir: &Path, action: &FwAction, backend: &str) -> AppResult<()> {
        let now = crate::util::time::now_iso();
        self.schema_version = 1;
        self.backend = Some(backend.to_string());
        match action {
            FwAction::Block {
                nets,
                direction,
                reason,
            } => {
                for n in nets {
                    self.blocked.retain(|b| b.net != *n);
                    self.blocked.push(BlockedEntry {
                        net: *n,
                        direction: *direction,
                        reason: reason.clone(),
                        added_at: now.clone(),
                    });
                }
            }
            FwAction::Unblock { nets } => self.blocked.retain(|b| !nets.contains(&b.net)),
            FwAction::UnblockAll => {
                self.blocked.clear();
                self.closed_ports.clear();
                self.feed_nets = 0;
                self.feed_ids.clear();
                self.feed_synced_at = None;
                Self::save_feed_nets(dir, &[])?;
            }
            FwAction::ClosePort { proto, port } => {
                if !self.closed_ports.iter().any(|c| c.proto == *proto && c.port == *port) {
                    self.closed_ports.push(ClosedPort {
                        proto: proto.clone(),
                        port: *port,
                        added_at: now,
                    });
                }
            }
            FwAction::OpenPort { proto, port } => self.closed_ports.retain(|c| !(c.proto == *proto && c.port == *port)),
            FwAction::SyncFeeds { nets, feed_ids } => {
                self.feed_nets = nets.len();
                self.feed_ids = feed_ids.clone();
                self.feed_synced_at = Some(now);
                Self::save_feed_nets(dir, nets)?;
            }
            FwAction::Enable { .. } | FwAction::Ensure => {}
        }
        self.save(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_tracks_blocks_ports_and_feeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = DesiredState::load(dir.path()).unwrap();
        let n: IpNet = "198.51.100.7/32".parse().unwrap();
        d.apply(
            dir.path(),
            &FwAction::Block {
                nets: vec![n],
                direction: Dir::Both,
                reason: "test".into(),
            },
            "nft",
        )
        .unwrap();
        d.apply(
            dir.path(),
            &FwAction::ClosePort {
                proto: "tcp".into(),
                port: 6379,
            },
            "nft",
        )
        .unwrap();
        d.apply(
            dir.path(),
            &FwAction::SyncFeeds {
                nets: vec!["203.0.113.0/24".parse().unwrap()],
                feed_ids: vec!["x".into()],
            },
            "nft",
        )
        .unwrap();
        let back = DesiredState::load(dir.path()).unwrap();
        assert!(back.is_blocked(&n));
        assert_eq!(back.closed_ports.len(), 1);
        assert_eq!(back.feed_nets, 1);
        assert_eq!(DesiredState::load_feed_nets(dir.path()).len(), 1);
        let mut back = back;
        back.apply(dir.path(), &FwAction::Unblock { nets: vec![n] }, "nft")
            .unwrap();
        assert!(back.blocked.is_empty());
        back.apply(dir.path(), &FwAction::UnblockAll, "nft").unwrap();
        assert!(back.closed_ports.is_empty() && DesiredState::load_feed_nets(dir.path()).is_empty());
    }
}
