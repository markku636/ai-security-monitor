//! 單一網路連線（socket）列：方向、行程、地理、判定。連線掃描器產出，快照上傳到 hub。

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::verdict::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum Direction {
    /// 本機主動連出。
    Outbound,
    /// 遠端連入到本機 listener。
    Inbound,
    /// 本機監聽中的 port。
    Listening,
    /// 本機對本機（loopback 兩端都是自己）。
    Local,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
            Direction::Listening => "listening",
            Direction::Local => "local",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Direction::Outbound => t!("對外"),
            Direction::Inbound => t!("對內"),
            Direction::Listening => t!("監聽"),
            Direction::Local => t!("本機"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub proto: String,
    pub local_ip: IpAddr,
    pub local_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    pub state: String,
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<GeoInfo>,
    #[serde(default)]
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
}

impl Connection {
    /// 給 finding id 用的穩定 key：排除 pid 與本地 port。
    pub fn evidence_key(&self) -> String {
        let remote = match (self.remote_ip, self.remote_port) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.to_string(),
            _ => format!("listen:{}", self.local_port),
        };
        let exe = self
            .process
            .as_ref()
            .and_then(|p| p.exe.clone().or_else(|| Some(p.name.clone())))
            .unwrap_or_default();
        format!("{}|{}|{}|{}", self.proto, remote, self.direction.as_str(), exe)
    }

    pub fn remote_display(&self) -> String {
        match (self.remote_ip, self.remote_port) {
            (Some(ip), Some(p)) => format!("{ip}:{p}"),
            (Some(ip), None) => ip.to_string(),
            _ => "-".into(),
        }
    }
}

/// 監聯中的 port（listener）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Listener {
    pub proto: String,
    pub bind_ip: IpAddr,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRef>,
    /// 是否綁在所有介面（0.0.0.0 / ::）→ 可能對外曝露。
    pub exposed: bool,
}
