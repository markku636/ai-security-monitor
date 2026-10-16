//! Agent 設定（`<config>/config.json`）。密鑰不放這裡（見 `secrets.rs`）。
//!
//! 設定目錄解析：`--config-dir` ＞ `ASA_CONFIG_DIR` ＞ `dirs::config_dir()/ai-security-agent`。
//! 服務模式（`--system`）改用系統層目錄（`%ProgramData%\ai-security-agent` / `/var/lib/asa` /
//! `/Library/Application Support/ai-security-agent`），由 service 安裝時以 `--config-dir` 帶入。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::store;

pub const CONFIG_FILE: &str = "config.json";
pub const APP_DIR_NAME: &str = "ai-security-agent";
pub const ENV_CONFIG_DIR: &str = "ASA_CONFIG_DIR";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AgentConfig {
    pub schema_version: u32,
    /// 第一次執行時產生的 UUID；hub 以此識別 agent。
    pub agent_id: String,
    /// 介面語言（`zh-TW` / `en`）；`None` 表示未設定（CLI 以 zh-TW 為預設）。
    pub lang: Option<String>,
    pub scan: ScanConfig,
    pub intel: IntelConfig,
    pub hub: Option<HubConfig>,
    pub remote_actions: RemoteActionsConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            agent_id: String::new(),
            lang: None,
            scan: ScanConfig::default(),
            intel: IntelConfig::default(),
            hub: None,
            remote_actions: RemoteActionsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ScanConfig {
    /// `asa watch` 完整掃描間隔（humantime，例 `10m`）。
    pub interval: String,
    /// 連線快照間隔。
    pub snapshot_interval: String,
    /// 預設啟用的掃描器；空＝全部可用的。
    pub scanners: Vec<String>,
    /// 允許線上查詢（OSV / EPSS / NVD / keyed 名譽查詢）。
    pub online: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interval: "10m".into(),
            snapshot_interval: "1m".into(),
            scanners: Vec::new(),
            online: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct IntelConfig {
    /// 允許把 `commercial_ok=false` 的來源（如 DShield）用於封鎖；預設只告警。
    pub allow_noncommercial: bool,
    /// 對 unknown 公網 IP 做 keyed 名譽查詢（需設定 API key）。
    pub online_lookups: bool,
    /// 掃描前先刷新過期 feed。
    pub refresh_on_scan: bool,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            allow_noncommercial: false,
            online_lookups: false,
            refresh_on_scan: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct HubConfig {
    pub url: String,
    pub enrolled_at: String,
    /// hub 回報的上傳上限 / 間隔（register 時更新）。
    pub min_report_interval_s: Option<u64>,
    pub max_report_bytes: Option<u64>,
    pub snapshot_interval_s: Option<u64>,
    pub feed_mirror: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RemoteActionsConfig {
    /// 是否接受 hub 核准的遠端動作（預設關）。
    pub accept: bool,
    /// 允許的動作種類（空＝block_ip / unblock_ip）。
    pub allowed_kinds: Vec<String>,
    pub allow_destructive: bool,
}

impl Default for RemoteActionsConfig {
    fn default() -> Self {
        Self {
            accept: false,
            allowed_kinds: vec!["block_ip".into(), "unblock_ip".into()],
            allow_destructive: false,
        }
    }
}

/// 解析設定目錄。
pub fn config_dir(explicit: Option<&Path>) -> AppResult<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(v) = std::env::var(ENV_CONFIG_DIR) {
        if !v.trim().is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let base = dirs::config_dir().ok_or_else(|| AppError::Storage(t!("無法取得使用者設定目錄").into()))?;
    Ok(base.join(APP_DIR_NAME))
}

/// 讀設定；不存在回預設（`agent_id` 可能為空，請用 `load_or_init`）。
pub fn load(dir: &Path) -> AppResult<AgentConfig> {
    store::read_json_in(dir, CONFIG_FILE)
}

/// 讀設定並補齊 `agent_id`；有變動就寫回。
pub fn load_or_init(dir: &Path) -> AppResult<AgentConfig> {
    let mut cfg = load(dir)?;
    let mut dirty = false;
    if cfg.agent_id.trim().is_empty() {
        cfg.agent_id = uuid::Uuid::new_v4().to_string();
        dirty = true;
    }
    if cfg.schema_version == 0 {
        cfg.schema_version = 1;
        dirty = true;
    }
    if dirty {
        save(dir, &cfg)?;
    }
    Ok(cfg)
}

pub fn save(dir: &Path, cfg: &AgentConfig) -> AppResult<()> {
    store::write_json_in(dir, CONFIG_FILE, cfg)
}

/// `asa config set <key> <value>` 支援的鍵（dotted）。
pub const SETTABLE_KEYS: &[&str] = &[
    "lang",
    "scan.interval",
    "scan.snapshot_interval",
    "scan.scanners",
    "scan.online",
    "intel.allow_noncommercial",
    "intel.online_lookups",
    "intel.refresh_on_scan",
    "remote_actions.accept",
    "remote_actions.allowed_kinds",
    "remote_actions.allow_destructive",
];

fn parse_bool(key: &str, v: &str) -> AppResult<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(AppError::InvalidArg(tf!("{key} 需要布林值（true/false）", key = key))),
    }
}

fn parse_duration_str(key: &str, v: &str) -> AppResult<String> {
    humantime::parse_duration(v.trim())
        .map(|_| v.trim().to_string())
        .map_err(|_| AppError::InvalidArg(tf!("{key} 需要時間長度（例 10m、30s）", key = key)))
}

fn parse_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 設定單一鍵值；未知鍵回 `InvalidArg`。
pub fn set_value(cfg: &mut AgentConfig, key: &str, value: &str) -> AppResult<()> {
    match key {
        "lang" => {
            let l = crate::i18n::Lang::from_code(value)
                .ok_or_else(|| AppError::InvalidArg(tf!("不支援的語言：{value}", value = value)))?;
            cfg.lang = Some(l.as_code().to_string());
        }
        "scan.interval" => cfg.scan.interval = parse_duration_str(key, value)?,
        "scan.snapshot_interval" => cfg.scan.snapshot_interval = parse_duration_str(key, value)?,
        "scan.scanners" => cfg.scan.scanners = parse_list(value),
        "scan.online" => cfg.scan.online = parse_bool(key, value)?,
        "intel.allow_noncommercial" => cfg.intel.allow_noncommercial = parse_bool(key, value)?,
        "intel.online_lookups" => cfg.intel.online_lookups = parse_bool(key, value)?,
        "intel.refresh_on_scan" => cfg.intel.refresh_on_scan = parse_bool(key, value)?,
        "remote_actions.accept" => cfg.remote_actions.accept = parse_bool(key, value)?,
        "remote_actions.allowed_kinds" => cfg.remote_actions.allowed_kinds = parse_list(value),
        "remote_actions.allow_destructive" => cfg.remote_actions.allow_destructive = parse_bool(key, value)?,
        _ => {
            return Err(AppError::InvalidArg(tf!(
                "未知的設定鍵：{key}；可用：{keys}",
                key = key,
                keys = SETTABLE_KEYS.join(", ")
            )))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dir_wins_over_env() {
        let d = config_dir(Some(Path::new("/tmp/x"))).unwrap();
        assert_eq!(d, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn load_or_init_assigns_agent_id_once() {
        let dir = tempfile::tempdir().unwrap();
        let a = load_or_init(dir.path()).unwrap();
        assert!(!a.agent_id.is_empty());
        let b = load_or_init(dir.path()).unwrap();
        assert_eq!(a.agent_id, b.agent_id);
    }

    #[test]
    fn set_value_validates() {
        let mut c = AgentConfig::default();
        set_value(&mut c, "scan.interval", "15m").unwrap();
        assert_eq!(c.scan.interval, "15m");
        assert!(set_value(&mut c, "scan.interval", "soon").is_err());
        set_value(&mut c, "remote_actions.accept", "yes").unwrap();
        assert!(c.remote_actions.accept);
        assert!(set_value(&mut c, "nope", "1").is_err());
        set_value(&mut c, "lang", "EN").unwrap();
        assert_eq!(c.lang.as_deref(), Some("en"));
    }
}
