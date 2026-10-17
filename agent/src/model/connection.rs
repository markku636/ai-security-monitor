//! 單一網路連線（socket）列：方向、行程、地理、判定。連線掃描器產出，快照上傳到 hub。

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::verdict::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum Direction {
    // 本機主動連出。（不用 ///：會變成 clap 可選值說明，無法翻譯）
    Outbound,
    // 遠端連入到本機 listener。
    Inbound,
    // 本機監聽中的 port。
    Listening,
    // 本機對本機（loopback 兩端都是自己）。
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
    /// 遠端 IP 最近一次被解析時的網域（背景 DNS 蒐集提供；沒有就是 None）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
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
    /// 防火牆判斷後的可達性（ports 掃描器填）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,
}

/// listener 能否從網路連入。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Reachability {
    /// 只綁 loopback。
    LocalOnly,
    /// 防火牆關閉、預設允許，或有規則放行（`rule`＝放行的規則名）。
    Open {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
    },
    /// 防火牆會擋。
    Filtered,
    /// 讀不到防火牆規則（權限不足）或依程式決定（macOS）。
    Unknown,
}

impl Reachability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reachability::LocalOnly => "local_only",
            Reachability::Open { .. } => "open",
            Reachability::Filtered => "filtered",
            Reachability::Unknown => "unknown",
        }
    }

    pub fn label(&self) -> String {
        match self {
            Reachability::LocalOnly => t!("僅本機").to_string(),
            Reachability::Open { rule: None } => t!("可連入").to_string(),
            Reachability::Open { rule: Some(r) } => tf!("可連入（規則：{rule}）", rule = r),
            Reachability::Filtered => t!("已阻擋").to_string(),
            Reachability::Unknown => t!("未知").to_string(),
        }
    }
}
