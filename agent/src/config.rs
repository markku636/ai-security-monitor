//! Agent 設定（`<config>/config.json`）。密鑰不放這裡（見 `secrets.rs`）。
//!
//! 設定目錄解析：`--config-dir` ＞ `AI_SECURITY_MONITOR_CONFIG_DIR`（舊名 `ASA_CONFIG_DIR`）＞
//! `dirs::config_dir()/ai-security-monitor`。
//! 服務模式（`--system`）改用系統層目錄（`%ProgramData%\ai-security-monitor` / `/var/lib/ai-security-monitor` /
//! `/Library/Application Support/ai-security-monitor`），由 service 安裝時以 `--config-dir` 帶入。
//!
//! 改名遷移：預設位置的新目錄還不存在、但舊的 `ai-security-agent` 目錄存在時，第一次解析就把它搬過來
//! （改名；改名失敗就整個複製，並在新目錄留 `.migrated-from` 標記），`agent_id`、密鑰檔、允許清單、基準線、
//! 情資都保留。明確指定的 `--config-dir`／環境變數一律照用，不搬。
//!
//! 舊版（0.1.x）的常駐 watch 還在用舊目錄（`watch.lock` 被占用，或有 `asa watch --service` 在跑）時**不搬**：
//! 這次直接讀寫舊目錄，等 `service install` 換掉舊服務時再搬，免得新目錄變成一份之後不再更新的快照。
//! 已經是這種過期快照的新目錄（複製標記之後舊目錄又有更新；或 0.2.0 沒留標記、`agent_id` 相同且舊目錄較新）
//! 在下一次舊目錄沒被占用時重新同步：過期的新目錄改名成 `ai-security-monitor.bak-<時間>` 保留，再重新搬一次。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::store;

pub const CONFIG_FILE: &str = "config.json";
pub const APP_DIR_NAME: &str = "ai-security-monitor";
/// 改名前（0.1.x）的使用者設定目錄名。
pub const LEGACY_APP_DIR_NAME: &str = "ai-security-agent";
/// 複製式遷移留在新目錄的標記（來源、時間、方式）。
pub const MIGRATION_MARKER: &str = ".migrated-from";
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
    pub metrics: MetricsConfig,
    /// 檔案完整性＋開機自啟監控（`fim.*`）。
    pub fim: FimConfig,
    /// DNS 監看（`dns.*`）。
    pub dns: DnsConfig,
    /// 自動更新（`update.mode`）。
    pub update: UpdateConfig,
    /// 這台電腦的背景服務（`watch`）用 mDNS 在區網廣播的 Hub 網址（`config set hub.advertise_url <URL>`）；
    /// 通常設在跑 Hub 的那台。沒設定＝不廣播。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hub_advertise_url: Option<String>,
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
            metrics: MetricsConfig::default(),
            fim: FimConfig::default(),
            dns: DnsConfig::default(),
            update: UpdateConfig::default(),
            hub_advertise_url: None,
        }
    }
}

/// DNS 查詢紀錄要不要上傳 Hub。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsUpload {
    /// 全部上傳（預設）。
    #[default]
    All,
    /// 只上傳告警（可疑查詢）與統計。
    Alerts,
    /// 不上傳。
    Off,
}

impl DnsUpload {
    pub fn parse(v: &str) -> Option<Self> {
        match v.trim().to_ascii_lowercase().as_str() {
            "all" => Some(Self::All),
            "alerts" => Some(Self::Alerts),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Alerts => "alerts",
            Self::Off => "off",
        }
    }
}

/// DNS 監看：背景服務即時記錄這台電腦查了哪些網域（哪個程式查的），本機保留 7 天。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsConfig {
    /// 開啟背景 DNS 蒐集（預設開）。
    pub enabled: bool,
    /// 上傳 Hub 的程度：all／alerts／off（只在加入 Hub 時有作用）。
    pub upload: DnsUpload,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            upload: DnsUpload::All,
        }
    }
}

/// 檔案完整性＋開機自啟監控（掃描器 `files`）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FimConfig {
    pub enabled: bool,
    /// 額外監看的檔案或資料夾（資料夾含子資料夾）。
    pub extra_paths: Vec<String>,
    /// 不監看的路徑：前綴，或含 `*` 的萬用字元。
    pub ignore: Vec<String>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            extra_paths: Vec::new(),
            ignore: Vec::new(),
        }
    }
}

/// 網路流量統計（一律開啟）與效能指標（預設關，這台電腦自己決定；Hub 不能從遠端開）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MetricsConfig {
    /// 蒐集效能：CPU、記憶體、磁碟、最吃資源的程式、電池（只送到這台加入的 Hub）。
    pub performance: bool,
    /// 取樣間隔（最短 30 秒）。
    pub interval: String,
    /// 估算各程式的網路用量（Windows 需要系統管理員；macOS 用 nettop；Linux 沒有）。
    pub process_network: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            performance: false,
            interval: "1m".into(),
            process_network: true,
        }
    }
}

/// 自動更新方式：關閉／有新版時通知（預設）／自動更新。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    /// 不檢查。
    Off,
    /// 每天檢查一次；有新版就記下、回報給 Hub（桌面版顯示提示），不自動安裝。
    #[default]
    Notify,
    /// 背景服務自動下載、比對 SHA256SUMS 後更新並重新啟動。
    Auto,
}

impl UpdateMode {
    pub fn parse(s: &str) -> Option<UpdateMode> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" | "disabled" | "關閉" => UpdateMode::Off,
            "notify" | "check" | "通知" => UpdateMode::Notify,
            "auto" | "on" | "1" | "true" | "yes" | "自動" | "自動更新" => UpdateMode::Auto,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            UpdateMode::Off => "off",
            UpdateMode::Notify => "notify",
            UpdateMode::Auto => "auto",
        }
    }
}

impl<'de> Deserialize<'de> for UpdateMode {
    /// 看不懂的值當成預設（notify），免得一個打錯的字讓整份設定讀不進來。
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        Ok(v.as_str().and_then(UpdateMode::parse).unwrap_or_default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct UpdateConfig {
    /// `off`／`notify`／`auto`。桌面版內建的背景服務由桌面版的更新器負責安裝（見 `update::auto`）。
    pub mode: UpdateMode,
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
    /// 上傳快照時附上連線 IP 對應的網域名稱（讀 Windows DNS 快取；其他平台沒有作用）。
    pub dns_names: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interval: "10m".into(),
            snapshot_interval: "1m".into(),
            scanners: Vec::new(),
            online: true,
            dns_names: true,
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
    /// 釘選的 Hub 身分指紋（第一次加入時記下，TOFU）；之後 Hub 身分不同就拒絕上傳，除非重新加入。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// 釘選的 Hub 公鑰（Ed25519，base64url），用來驗 Hub 的簽章。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
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
/// 舊版常駐行程還在用舊目錄、或遷移失敗時回舊目錄（照舊能用，之後再搬），並記下來給 `deferred_migration()`。
pub fn default_dir_in(base: &Path) -> PathBuf {
    default_dir_with(base, &legacy_in_use)
}

/// `default_dir_in`，但「舊目錄是否被占用」由呼叫端判斷（測試不看主機上的行程）。
pub fn default_dir_with(base: &Path, busy: &dyn Fn(&Path, &Path) -> bool) -> PathBuf {
    let new = base.join(APP_DIR_NAME);
    let legacy = base.join(LEGACY_APP_DIR_NAME);
    let (dir, res) = resolve_default_dir(&new, &legacy, busy);
    let busy = match res {
        Resolution::LegacyBusy => Some(true),
        Resolution::LegacyFallback => Some(false),
        Resolution::New(_) => None,
    };
    if let Some(busy) = busy {
        if let Ok(mut d) = DEFERRED.lock() {
            *d = Some(Deferred { legacy, new, busy });
        }
    }
    dir
}

/// 這次沒有遷移、沿用舊目錄的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    pub legacy: PathBuf,
    pub new: PathBuf,
    /// true：舊版常駐 watch 還在用舊目錄；false：遷移失敗。
    pub busy: bool,
}

static DEFERRED: Mutex<Option<Deferred>> = Mutex::new(None);

/// 這個行程解析預設設定目錄時沿用了舊目錄（`service install` 會在換掉舊服務後搬過去）。
pub fn deferred_migration() -> Option<Deferred> {
    DEFERRED.lock().ok().and_then(|d| d.clone())
}

/// 預設設定目錄的解析結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// 用新目錄（必要時剛遷移／重新同步完）。
    New(Migration),
    /// 舊版常駐 watch 還在用舊目錄：這次沿用舊目錄、不搬。
    LegacyBusy,
    /// 遷移失敗：沿用舊目錄，下次再試。
    LegacyFallback,
}

/// 舊目錄正被舊版常駐 watch 使用：鎖檔被占用，或有舊名（asa）的常駐 watch 在跑而新目錄的鎖沒人拿
/// （0.2.x 自我更新後檔名還是 asa 的常駐行程用的是新目錄，會占用新目錄的鎖）。
pub fn legacy_in_use(legacy: &Path, new: &Path) -> bool {
    use crate::service::instance::InstanceLock;
    InstanceLock::is_held(legacy) || (crate::service::legacy_watcher_running() && !InstanceLock::is_held(new))
}

/// 決定這次用哪個目錄，必要時遷移或重新同步。`busy(legacy, new)` 只在真的要搬時才呼叫。
pub fn resolve_default_dir(new: &Path, legacy: &Path, busy: &dyn Fn(&Path, &Path) -> bool) -> (PathBuf, Resolution) {
    if !legacy.is_dir() {
        return (new.to_path_buf(), Resolution::New(Migration::NotNeeded));
    }
    let resync = new.exists();
    if resync && !is_stale_snapshot(new, legacy) {
        return (new.to_path_buf(), Resolution::New(Migration::NotNeeded));
    }
    if busy(legacy, new) {
        return (legacy.to_path_buf(), Resolution::LegacyBusy);
    }
    let r = if resync {
        resync_from_legacy(new, legacy)
    } else {
        migrate_legacy_dir(new, legacy)
    };
    match r {
        Ok(m) => (new.to_path_buf(), Resolution::New(m)),
        Err(_) => (legacy.to_path_buf(), Resolution::LegacyFallback),
    }
}

/// 遷移結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Migration {
    /// 不需要（新目錄已存在且不是過期快照，或沒有舊目錄）。
    NotNeeded,
    /// 舊目錄改名成新目錄。
    Renamed,
    /// 改名失敗，已整個複製（舊目錄保留，新目錄有 `.migrated-from` 標記）。
    Copied,
    /// 新目錄是過期快照：已備份成 `…bak-<時間>` 並重新從舊目錄搬過來。
    Resynced,
}

/// `.migrated-from` 的內容。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MigrationMarker {
    pub from: String,
    /// RFC 3339。
    pub at: String,
    /// `copy` 或 `rename`。
    pub mode: String,
}

fn write_marker(new: &Path, legacy: &Path, mode: &str) {
    let m = MigrationMarker {
        from: legacy.display().to_string(),
        at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        mode: mode.into(),
    };
    if let Ok(text) = serde_json::to_string_pretty(&m) {
        let _ = std::fs::write(new.join(MIGRATION_MARKER), text);
    }
}

pub fn read_marker(dir: &Path) -> Option<MigrationMarker> {
    serde_json::from_str(&std::fs::read_to_string(dir.join(MIGRATION_MARKER)).ok()?).ok()
}

/// 標記的時間；解析不了就用標記檔的修改時間。
fn marker_time(dir: &Path, m: &MigrationMarker) -> Option<SystemTime> {
    chrono::DateTime::parse_from_rfc3339(&m.at)
        .ok()
        .map(SystemTime::from)
        .or_else(|| {
            std::fs::metadata(dir.join(MIGRATION_MARKER))
                .and_then(|md| md.modified())
                .ok()
        })
}

/// 目錄裡（遞迴）最新的檔案修改時間；不算鎖檔與遷移標記。
pub fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let Ok(ty) = e.file_type() else { continue };
        let t = if ty.is_dir() {
            newest_mtime(&e.path())
        } else if ty.is_file() {
            let name = e.file_name();
            if name == crate::service::instance::LOCK_FILE || name == MIGRATION_MARKER {
                continue;
            }
            e.metadata().and_then(|m| m.modified()).ok()
        } else {
            None
        };
        if let Some(t) = t {
            newest = Some(newest.map_or(t, |n| n.max(t)));
        }
    }
    newest
}

fn agent_id_of(dir: &Path) -> String {
    load(dir).map(|c| c.agent_id.trim().to_string()).unwrap_or_default()
}

/// 新目錄是之前複製過來、之後舊目錄又有更新的過期快照：
/// - 有 `.migrated-from`（mode=copy）：舊目錄最新的檔案比標記時間新。
/// - 沒有標記（0.2.0 複製的）：`agent_id` 相同，且新目錄最新的檔案比舊目錄最新的舊。
///
/// 新目錄的鎖被占用（有常駐行程在用）時一律不算。
pub fn is_stale_snapshot(new: &Path, legacy: &Path) -> bool {
    if crate::service::instance::InstanceLock::is_held(new) {
        return false;
    }
    let Some(legacy_newest) = newest_mtime(legacy) else {
        return false;
    };
    match read_marker(new) {
        Some(m) => m.mode == "copy" && marker_time(new, &m).is_some_and(|t| legacy_newest > t),
        None => {
            let id = agent_id_of(new);
            !id.is_empty() && id == agent_id_of(legacy) && newest_mtime(new).is_none_or(|n| n < legacy_newest)
        }
    }
}

/// 過期快照的備份位置：`<new>.bak-<本機時間>`（同名已存在就加序號）。
fn backup_path(new: &Path) -> PathBuf {
    let name = new
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| APP_DIR_NAME.into());
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let mut p = new.with_file_name(format!("{name}.bak-{stamp}"));
    let mut i = 1;
    while p.exists() {
        p = new.with_file_name(format!("{name}.bak-{stamp}-{i}"));
        i += 1;
    }
    p
}

/// 把過期的新目錄改名成備份，再從舊目錄重新搬一次；搬不成就把備份改回來。
pub fn resync_from_legacy(new: &Path, legacy: &Path) -> AppResult<Migration> {
    let bak = backup_path(new);
    std::fs::rename(new, &bak).map_err(|e| {
        AppError::Storage(tf!(
            "無法把 {from} 搬到 {to}：{e}",
            from = new.display(),
            to = bak.display(),
            e = e
        ))
    })?;
    match migrate_legacy_dir(new, legacy) {
        Ok(_) => Ok(Migration::Resynced),
        Err(e) => {
            if !new.exists() {
                let _ = std::fs::rename(&bak, new);
            }
            Err(e)
        }
    }
}

/// 舊目錄沒被占用時的完整遷移：新目錄不存在就搬，新目錄是過期快照就重新同步。
pub fn migrate_or_resync(new: &Path, legacy: &Path) -> AppResult<Migration> {
    if !legacy.is_dir() {
        return Ok(Migration::NotNeeded);
    }
    if new.exists() {
        if is_stale_snapshot(new, legacy) {
            return resync_from_legacy(new, legacy);
        }
        return Ok(Migration::NotNeeded);
    }
    migrate_legacy_dir(new, legacy)
}

/// `service install` 的遷移步驟：舊服務剛停掉，鎖可能還要一下子才放開（最多等 `wait`）。
pub fn migrate_after_stop(new: &Path, legacy: &Path, wait: std::time::Duration) -> AppResult<Migration> {
    let start = std::time::Instant::now();
    while crate::service::instance::InstanceLock::is_held(legacy) {
        if start.elapsed() >= wait {
            return Err(AppError::Storage(tf!(
                "舊版 asa 還在使用 {dir}，沒有搬移；結束它之後再執行一次 ai-security-monitor service install --yes",
                dir = legacy.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    migrate_or_resync(new, legacy)
}

/// 新目錄不存在、舊目錄存在時把舊目錄搬過去：先改名，失敗再複製到暫存目錄後改名（留 `.migrated-from` 標記）。
/// 複製時略過單一實例鎖；其他檔案讀不到就放棄並回錯誤（舊目錄不動）。舊目錄是否被占用由呼叫端先判斷。
pub fn migrate_legacy_dir(new: &Path, legacy: &Path) -> AppResult<Migration> {
    if new.exists() || !legacy.is_dir() {
        return Ok(Migration::NotNeeded);
    }
    if let Some(parent) = new.parent() {
        store::ensure_dir(parent)?;
    }
    if std::fs::rename(legacy, new).is_ok() {
        write_marker(new, legacy, "rename");
        return Ok(Migration::Renamed);
    }
    let name = new
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| APP_DIR_NAME.into());
    let tmp = new.with_file_name(format!(".{name}.migrating-{}", uuid::Uuid::new_v4().simple()));
    let copied = copy_tree(legacy, &tmp).and_then(|()| std::fs::rename(&tmp, new));
    match copied {
        Ok(()) => {
            write_marker(new, legacy, "copy");
            Ok(Migration::Copied)
        }
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
    "fim.enabled",
    "fim.extra_paths",
    "fim.ignore",
    "scan.dns_names",
    "intel.allow_noncommercial",
    "intel.online_lookups",
    "intel.refresh_on_scan",
    "remote_actions.accept",
    "remote_actions.allowed_kinds",
    "remote_actions.allow_destructive",
    "metrics.performance",
    "metrics.interval",
    "metrics.process_network",
    "dns.enabled",
    "dns.upload",
    "update.mode",
    "hub.advertise_url",
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
        "fim.enabled" => cfg.fim.enabled = parse_bool(key, value)?,
        "fim.extra_paths" => cfg.fim.extra_paths = parse_list(value),
        "fim.ignore" => cfg.fim.ignore = parse_list(value),
        "scan.dns_names" => cfg.scan.dns_names = parse_bool(key, value)?,
        "intel.allow_noncommercial" => cfg.intel.allow_noncommercial = parse_bool(key, value)?,
        "intel.online_lookups" => cfg.intel.online_lookups = parse_bool(key, value)?,
        "intel.refresh_on_scan" => cfg.intel.refresh_on_scan = parse_bool(key, value)?,
        "remote_actions.accept" => cfg.remote_actions.accept = parse_bool(key, value)?,
        "remote_actions.allowed_kinds" => cfg.remote_actions.allowed_kinds = parse_list(value),
        "remote_actions.allow_destructive" => cfg.remote_actions.allow_destructive = parse_bool(key, value)?,
        "metrics.performance" => cfg.metrics.performance = parse_bool(key, value)?,
        "metrics.interval" => {
            let v = parse_duration_str(key, value)?;
            if humantime::parse_duration(&v).map(|d| d.as_secs() < 30).unwrap_or(true) {
                return Err(AppError::InvalidArg(tf!("{key} 最短 30 秒", key = key)));
            }
            cfg.metrics.interval = v;
        }
        "metrics.process_network" => cfg.metrics.process_network = parse_bool(key, value)?,
        "dns.enabled" => cfg.dns.enabled = parse_bool(key, value)?,
        "dns.upload" => {
            cfg.dns.upload = DnsUpload::parse(value)
                .ok_or_else(|| AppError::InvalidArg(tf!("{key} 只能是 all、alerts 或 off", key = key)))?
        }
        "update.mode" => {
            cfg.update.mode = UpdateMode::parse(value)
                .ok_or_else(|| AppError::InvalidArg(tf!("{key} 只能是 off、notify 或 auto", key = key)))?
        }
        "hub.advertise_url" | "hub_advertise_url" => {
            let v = value.trim();
            cfg.hub_advertise_url = if v.is_empty() || ["off", "none", "-"].contains(&v.to_ascii_lowercase().as_str()) {
                None
            } else {
                Some(crate::hub::validate_url(v, false)?)
            };
        }
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
        let dir = default_dir_with(base.path(), &lock_only);
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
        assert_eq!(default_dir_with(base.path(), &lock_only), dir);
        assert_eq!(load(&dir).unwrap().agent_id, agent_id);
        assert_eq!(migrate_legacy_dir(&dir, &legacy).unwrap(), Migration::NotNeeded);
    }

    #[test]
    fn fresh_install_has_nothing_to_migrate() {
        let base = tempfile::tempdir().unwrap();
        let dir = default_dir_with(base.path(), &lock_only);
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

    /// 測試用的「舊目錄被占用」判斷：只看鎖檔（不看主機上的行程）。
    fn lock_only(legacy: &Path, _new: &Path) -> bool {
        crate::service::instance::InstanceLock::is_held(legacy)
    }

    fn set_tree_mtime(dir: &Path, t: SystemTime) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                set_tree_mtime(&e.path(), t);
            } else {
                std::fs::File::options()
                    .write(true)
                    .open(e.path())
                    .unwrap()
                    .set_modified(t)
                    .unwrap();
            }
        }
    }

    fn backups(base: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(base)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{APP_DIR_NAME}.bak-"))
            })
            .map(|e| e.path())
            .collect()
    }

    fn write_marker_at(new: &Path, legacy: &Path, mode: &str, at: chrono::DateTime<chrono::Utc>) {
        let m = MigrationMarker {
            from: legacy.display().to_string(),
            at: at.to_rfc3339(),
            mode: mode.into(),
        };
        std::fs::write(new.join(MIGRATION_MARKER), serde_json::to_string(&m).unwrap()).unwrap();
    }

    /// 0.2.0 在舊版常駐 watch 還在跑時留下的快照：整份複製、之後舊目錄繼續更新。
    fn snapshot_of(legacy: &Path, new: &Path) {
        copy_tree(legacy, new).unwrap();
        std::fs::write(new.join("latest.json"), "{\"from\":\"snapshot\"}").unwrap();
        set_tree_mtime(new, SystemTime::now() - std::time::Duration::from_secs(3600));
        std::fs::write(legacy.join("latest.json"), "{\"from\":\"legacy\"}").unwrap();
    }

    #[test]
    fn locked_legacy_is_used_in_place_not_copied() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        let lock = crate::service::instance::InstanceLock::acquire(&legacy)
            .unwrap()
            .unwrap();
        // 舊版常駐 watch 拿著鎖：不複製，這次直接用舊目錄
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!((dir.as_path(), res), (legacy.as_path(), Resolution::LegacyBusy));
        assert!(!new.exists(), "no snapshot copy while the old watcher runs");
        // 真正的判斷（鎖＋行程）也認得被占用的鎖
        assert!(legacy_in_use(&legacy, &new));
        // default_dir_with 記下沿用舊目錄的原因（service install 依此搬移）
        assert_eq!(default_dir_with(base.path(), &lock_only), legacy);
        let d = deferred_migration().unwrap();
        assert!(d.busy && d.legacy == legacy && d.new == new);
        // 舊服務換掉、鎖放開：正常啟動時才搬（改名），資料都在
        drop(lock);
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!(dir, new);
        assert_eq!(res, Resolution::New(Migration::Renamed));
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        assert!(new.join("secrets.json").exists() && new.join("intel").join("feodo.txt").exists());
        assert!(!legacy.exists());
        assert_eq!(read_marker(&new).unwrap().mode, "rename");
    }

    #[test]
    fn running_legacy_watcher_without_lock_counts_as_busy() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, _) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        let (dir, res) = resolve_default_dir(&new, &legacy, &|_, _| true);
        assert_eq!((dir, res), (legacy.clone(), Resolution::LegacyBusy));
        assert!(!new.exists());
        // 不需要搬的時候根本不問（例如新目錄已存在且不是快照）
        std::fs::create_dir_all(&new).unwrap();
        save(
            &new,
            &AgentConfig {
                agent_id: "independent".into(),
                ..AgentConfig::default()
            },
        )
        .unwrap();
        let (dir, res) = resolve_default_dir(&new, &legacy, &|_, _| panic!("busy probe called"));
        assert_eq!((dir, res), (new, Resolution::New(Migration::NotNeeded)));
    }

    #[test]
    fn copy_migration_writes_a_marker() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        // 舊版行程還開著鎖檔時呼叫底層遷移（Windows 改名會失敗、改走複製）
        let lock = crate::service::instance::InstanceLock::acquire(&legacy)
            .unwrap()
            .unwrap();
        let new = base.path().join(APP_DIR_NAME);
        let m = migrate_legacy_dir(&new, &legacy).unwrap();
        drop(lock);
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        let marker = read_marker(&new).unwrap();
        assert_eq!(marker.from, legacy.display().to_string());
        assert!(chrono::DateTime::parse_from_rfc3339(&marker.at).is_ok());
        match m {
            Migration::Copied => assert_eq!(marker.mode, "copy"),
            Migration::Renamed => assert_eq!(marker.mode, "rename"),
            other => panic!("{other:?}"),
        }
        // 剛複製完、舊目錄沒有更新：不是過期快照
        assert!(!is_stale_snapshot(&new, &legacy));
    }

    #[test]
    fn copy_snapshot_is_resynced_when_legacy_changed_later() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        snapshot_of(&legacy, &new);
        write_marker_at(
            &new,
            &legacy,
            "copy",
            chrono::Utc::now() - chrono::Duration::minutes(30),
        );
        assert!(is_stale_snapshot(&new, &legacy));
        // 舊目錄還被占用：照樣先用舊目錄（它才是最新的），快照不動
        let lock = crate::service::instance::InstanceLock::acquire(&legacy)
            .unwrap()
            .unwrap();
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!((dir, res), (legacy.clone(), Resolution::LegacyBusy));
        assert!(backups(base.path()).is_empty());
        drop(lock);
        // 放開後：快照備份成 .bak-<時間>，重新從舊目錄搬
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!((dir, res), (new.clone(), Resolution::New(Migration::Resynced)));
        assert_eq!(
            std::fs::read_to_string(new.join("latest.json")).unwrap(),
            "{\"from\":\"legacy\"}"
        );
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        let bak = backups(base.path());
        assert_eq!(bak.len(), 1);
        assert_eq!(
            std::fs::read_to_string(bak[0].join("latest.json")).unwrap(),
            "{\"from\":\"snapshot\"}"
        );
        // 之後就穩定了
        assert_eq!(migrate_or_resync(&new, &legacy).unwrap(), Migration::NotNeeded);
    }

    #[test]
    fn copy_snapshot_without_later_legacy_changes_is_kept() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, _) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        snapshot_of(&legacy, &new);
        write_marker_at(
            &new,
            &legacy,
            "copy",
            chrono::Utc::now() + chrono::Duration::minutes(30),
        );
        assert!(!is_stale_snapshot(&new, &legacy));
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!((dir, res), (new.clone(), Resolution::New(Migration::NotNeeded)));
        assert!(legacy.exists() && backups(base.path()).is_empty());
        // 改名式遷移的標記不觸發重新同步
        write_marker_at(
            &new,
            &legacy,
            "rename",
            chrono::Utc::now() - chrono::Duration::minutes(30),
        );
        assert!(!is_stale_snapshot(&new, &legacy));
    }

    #[test]
    fn unmarked_snapshot_from_0_2_0_is_resynced() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        // 0.2.0 複製時沒有留標記：agent_id 相同、新目錄最新的檔案比舊目錄舊
        snapshot_of(&legacy, &new);
        assert!(read_marker(&new).is_none());
        assert!(is_stale_snapshot(&new, &legacy));
        assert_eq!(default_dir_with(base.path(), &lock_only), new);
        assert_eq!(
            std::fs::read_to_string(new.join("latest.json")).unwrap(),
            "{\"from\":\"legacy\"}"
        );
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        assert_eq!(backups(base.path()).len(), 1);
        assert!(!legacy.exists());
    }

    #[test]
    fn unmarked_dir_that_is_newer_or_another_agent_is_kept() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, _) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        snapshot_of(&legacy, &new);
        // 新目錄之後有更新（新版已經在用）：不是快照
        std::fs::write(new.join("latest.json"), "{\"from\":\"new\"}").unwrap();
        set_tree_mtime(&legacy, SystemTime::now() - std::time::Duration::from_secs(7200));
        assert!(!is_stale_snapshot(&new, &legacy));
        // 另一個 agent_id（各自獨立的安裝）：不碰
        std::fs::write(new.join("latest.json"), "{}").unwrap();
        set_tree_mtime(&new, SystemTime::now() - std::time::Duration::from_secs(10_000));
        std::fs::write(legacy.join("latest.json"), "{}").unwrap();
        save(
            &new,
            &AgentConfig {
                agent_id: "other-agent".into(),
                ..AgentConfig::default()
            },
        )
        .unwrap();
        set_tree_mtime(&new, SystemTime::now() - std::time::Duration::from_secs(10_000));
        assert!(!is_stale_snapshot(&new, &legacy));
        let (dir, res) = resolve_default_dir(&new, &legacy, &lock_only);
        assert_eq!((dir, res), (new, Resolution::New(Migration::NotNeeded)));
        assert!(backups(base.path()).is_empty());
    }

    #[test]
    fn new_dir_in_use_is_never_a_stale_snapshot() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, _) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        snapshot_of(&legacy, &new);
        assert!(is_stale_snapshot(&new, &legacy));
        let lock = crate::service::instance::InstanceLock::acquire(&new).unwrap().unwrap();
        assert!(!is_stale_snapshot(&new, &legacy));
        drop(lock);
    }

    #[test]
    fn migrate_after_stop_waits_for_the_lock() {
        let base = tempfile::tempdir().unwrap();
        let (legacy, agent_id) = legacy_tree(base.path());
        let new = base.path().join(APP_DIR_NAME);
        let lock = crate::service::instance::InstanceLock::acquire(&legacy)
            .unwrap()
            .unwrap();
        // 一直沒放開：放棄、什麼都不搬
        assert!(migrate_after_stop(&new, &legacy, std::time::Duration::from_millis(300)).is_err());
        assert!(!new.exists());
        // 等待期間放開：照樣搬
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            drop(lock);
        });
        let m = migrate_after_stop(&new, &legacy, std::time::Duration::from_secs(10)).unwrap();
        t.join().unwrap();
        assert_eq!(m, Migration::Renamed);
        assert_eq!(load(&new).unwrap().agent_id, agent_id);
        // 過期快照也在這一步重新同步
        let (legacy2, _) = legacy_tree(&base.path().join("b"));
        let new2 = base.path().join("b").join(APP_DIR_NAME);
        snapshot_of(&legacy2, &new2);
        assert_eq!(
            migrate_after_stop(&new2, &legacy2, std::time::Duration::from_secs(1)).unwrap(),
            Migration::Resynced
        );
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
        // 效能蒐集預設關，要明確開
        assert!(c.dns.enabled && c.dns.upload == DnsUpload::All);
        set_value(&mut c, "dns.upload", "alerts").unwrap();
        assert_eq!(c.dns.upload, DnsUpload::Alerts);
        set_value(&mut c, "dns.enabled", "off").unwrap();
        assert!(!c.dns.enabled);
        assert!(set_value(&mut c, "dns.upload", "some").is_err());
        assert!(!c.metrics.performance);
        set_value(&mut c, "metrics.performance", "true").unwrap();
        assert!(c.metrics.performance);
        set_value(&mut c, "metrics.interval", "2m").unwrap();
        assert_eq!(c.metrics.interval, "2m");
        assert!(set_value(&mut c, "metrics.interval", "10s").is_err(), "min 30s");
        // 舊設定檔沒有 metrics：讀成預設（關）
        let old: AgentConfig = serde_json::from_str(r#"{"schema_version":1,"agent_id":"x"}"#).unwrap();
        assert!(!old.metrics.performance && old.metrics.process_network);
    }

    #[test]
    fn update_mode_and_advertise_url() {
        let mut c = AgentConfig::default();
        assert_eq!(c.update.mode, UpdateMode::Notify);
        set_value(&mut c, "update.mode", "AUTO").unwrap();
        assert_eq!(c.update.mode, UpdateMode::Auto);
        set_value(&mut c, "update.mode", "off").unwrap();
        assert_eq!(c.update.mode, UpdateMode::Off);
        assert!(set_value(&mut c, "update.mode", "sometimes").is_err());
        // 看不懂的值不讓整份設定壞掉：當成預設 notify
        let parsed: AgentConfig = serde_json::from_str(r#"{"update":{"mode":"weekly"}}"#).unwrap();
        assert_eq!(parsed.update.mode, UpdateMode::Notify);
        let parsed: AgentConfig = serde_json::from_str(r#"{"update":{"mode":"auto"}}"#).unwrap();
        assert_eq!(parsed.update.mode, UpdateMode::Auto);
        assert_eq!(serde_json::to_value(&parsed.update).unwrap()["mode"], "auto");

        set_value(&mut c, "hub.advertise_url", "http://192.168.1.10:8088/").unwrap();
        assert_eq!(c.hub_advertise_url.as_deref(), Some("http://192.168.1.10:8088"));
        // 公網 http 不行；off／空白＝不廣播
        assert!(set_value(&mut c, "hub.advertise_url", "http://8.8.8.8:8088").is_err());
        set_value(&mut c, "hub.advertise_url", "off").unwrap();
        assert!(c.hub_advertise_url.is_none());
        set_value(&mut c, "hub_advertise_url", "https://hub.corp.example").unwrap();
        assert_eq!(c.hub_advertise_url.as_deref(), Some("https://hub.corp.example"));
        set_value(&mut c, "hub.advertise_url", "").unwrap();
        assert!(c.hub_advertise_url.is_none());
    }
}
