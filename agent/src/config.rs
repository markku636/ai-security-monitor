//! Agent 設定（`<config>/config.json`）。密鑰不放這裡（見 `secrets.rs`）。
//!
//! 設定目錄解析：`--config-dir` ＞ `AI_SECURITY_MONITOR_CONFIG_DIR`（舊名 `ASA_CONFIG_DIR`）＞
//! `dirs::config_dir()/ai-security-monitor`。
//! 服務模式（`--system`）改用系統層目錄（`%ProgramData%\ai-security-monitor` / `/var/lib/ai-security-monitor` /
//! `/Library/Application Support/ai-security-monitor`），由 service 安裝時以 `--config-dir` 帶入。
//!
//! 改名遷移：預設位置的新目錄還不存在、但舊的 `ai-security-agent` 目錄存在時，第一次解析就把它搬過來
//! （改名；改名失敗——例如舊版常駐行程還開著檔案——就整個複製），`agent_id`、密鑰檔、允許清單、基準線、
//! 情資都保留。明確指定的 `--config-dir`／環境變數一律照用，不搬。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::store;

pub const CONFIG_FILE: &str = "config.json";
pub const APP_DIR_NAME: &str = "ai-security-monitor";
/// 改名前（0.1.x）的使用者設定目錄名。
pub const LEGACY_APP_DIR_NAME: &str = "ai-security-agent";
/// 不含前綴的環境變數名（見 `util::env`）：`AI_SECURITY_MONITOR_CONFIG_DIR`，舊名 `ASA_CONFIG_DIR`。
pub const ENV_CONFIG_DIR: &str = "CONFIG_DIR";

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
    /// `ai-security-monitor watch` 完整掃描間隔（humantime，例 `10m`）。
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
    if let Some(v) = crate::util::env::var(ENV_CONFIG_DIR) {
        if !v.trim().is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let base = dirs::config_dir().ok_or_else(|| AppError::Storage(t!("無法取得使用者設定目錄").into()))?;
    Ok(default_dir_in(&base))
}

/// `<base>/ai-security-monitor`；必要時先從 `<base>/ai-security-agent` 遷移。
/// 遷移失敗時回舊目錄（照舊能用，下次再試）。
pub fn default_dir_in(base: &Path) -> PathBuf {
    let new = base.join(APP_DIR_NAME);
    let legacy = base.join(LEGACY_APP_DIR_NAME);
    match migrate_legacy_dir(&new, &legacy) {
        Ok(_) => new,
        Err(_) => legacy,
    }
}

/// 遷移結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// 不需要（新目錄已存在，或沒有舊目錄）。
    NotNeeded,
    /// 舊目錄改名成新目錄。
    Renamed,
    /// 改名失敗，已整個複製（舊目錄保留）。
    Copied,
}

/// 新目錄不存在、舊目錄存在時把舊目錄搬過去：先改名，失敗再複製到暫存目錄後改名。
/// 複製時略過單一實例鎖（舊版常駐行程獨占開啟）；其他檔案讀不到就放棄並回錯誤（舊目錄不動）。
pub fn migrate_legacy_dir(new: &Path, legacy: &Path) -> AppResult<Migration> {
    if new.exists() || !legacy.is_dir() {
        return Ok(Migration::NotNeeded);
    }
    if let Some(parent) = new.parent() {
        store::ensure_dir(parent)?;
    }
    if std::fs::rename(legacy, new).is_ok() {
        return Ok(Migration::Renamed);
    }
    let name = new
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| APP_DIR_NAME.into());
    let tmp = new.with_file_name(format!(".{name}.migrating-{}", uuid::Uuid::new_v4().simple()));
    let copied = copy_tree(legacy, &tmp).and_then(|()| std::fs::rename(&tmp, new));
    match copied {
        Ok(()) => Ok(Migration::Copied),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            if new.exists() {
                // 別的行程同時搬好了
                return Ok(Migration::NotNeeded);
            }
            Err(AppError::Storage(tf!(
                "無法把 {from} 搬到 {to}：{e}",
                from = legacy.display(),
                to = new.display(),
                e = e
            )))
        }
    }
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let ty = e.file_type()?;
        let dst = to.join(e.file_name());
        if ty.is_dir() {
            copy_tree(&e.path(), &dst)?;
        } else if ty.is_file() {
            if e.file_name() == crate::service::instance::LOCK_FILE {
                continue;
            }
            std::fs::copy(e.path(), &dst)?;
        }
    }
    Ok(())
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

/// `ai-security-monitor config set <key> <value>` 支援的鍵（dotted）。
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

    /// 舊版目錄：config.json（含 agent_id）、secrets.json、允許清單、基準線、情資子目錄、被占用的鎖檔。
    fn legacy_tree(base: &Path) -> (PathBuf, String) {
        let legacy = base.join(LEGACY_APP_DIR_NAME);
        let cfg = load_or_init(&legacy).unwrap();
        std::fs::write(legacy.join("secrets.json"), r#"{"hub.client_key":"k1"}"#).unwrap();
        std::fs::write(legacy.join("allowlist.json"), "{}").unwrap();
        std::fs::write(legacy.join("baseline.json"), "{}").unwrap();
        std::fs::create_dir_all(legacy.join("intel")).unwrap();
        std::fs::write(legacy.join("intel").join("feodo.txt"), "1.2.3.4\n").unwrap();
        (legacy, cfg.agent_id)
    }

    #[test]
    fn default_dir_migrates_legacy_once() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        let dir = default_dir_in(base.path());
        assert_eq!(dir, base.path().join(APP_DIR_NAME));
        assert_eq!(load(&dir).unwrap().agent_id, agent_id);
        assert!(dir.join("secrets.json").exists());
        assert!(dir.join("allowlist.json").exists() && dir.join("baseline.json").exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("intel").join("feodo.txt")).unwrap(),
            "1.2.3.4\n"
        );
        assert!(!legacy.exists(), "renamed, not copied");
        // 新目錄已存在：之後再出現舊目錄也不碰
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join(CONFIG_FILE), r#"{"agent_id":"other"}"#).unwrap();
        assert_eq!(default_dir_in(base.path()), dir);
        assert_eq!(load(&dir).unwrap().agent_id, agent_id);
        assert_eq!(migrate_legacy_dir(&dir, &legacy).unwrap(), Migration::NotNeeded);
    }

    #[test]
    fn fresh_install_has_nothing_to_migrate() {
        let base = tempfile::tempdir().unwrap();
        let dir = default_dir_in(base.path());
        assert_eq!(dir, base.path().join(APP_DIR_NAME));
        assert!(!base.path().join(LEGACY_APP_DIR_NAME).exists());
    }

    #[test]
    fn copy_fallback_keeps_legacy_and_skips_lock() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        std::fs::write(legacy.join(crate::service::instance::LOCK_FILE), "123\n").unwrap();
        let new = base.path().join("copied");
        copy_tree(&legacy, &new).unwrap();
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        assert!(new.join("intel").join("feodo.txt").exists());
        assert!(!new.join(crate::service::instance::LOCK_FILE).exists());
        assert!(legacy.join(CONFIG_FILE).exists());
    }

    #[test]
    fn migrates_while_old_watcher_holds_the_lock() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        // 舊版常駐行程還在跑：鎖檔被獨占開啟（Windows 上目錄改名會失敗，改走複製）
        let lock = crate::service::instance::InstanceLock::acquire(&legacy)
            .unwrap()
            .unwrap();
        let new = base.path().join(APP_DIR_NAME);
        let m = migrate_legacy_dir(&new, &legacy).unwrap();
        assert_ne!(m, Migration::NotNeeded);
        if cfg!(windows) {
            assert_eq!(m, Migration::Copied);
        }
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        assert!(new.join("secrets.json").exists());
        if m == Migration::Copied {
            assert!(legacy.join(CONFIG_FILE).exists());
        }
        drop(lock);
        // 沒有殘留的暫存目錄
        let leftovers = std::fs::read_dir(base.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".migrating-"))
            .count();
        assert_eq!(leftovers, 0);
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
