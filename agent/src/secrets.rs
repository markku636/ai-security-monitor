//! 密鑰儲存：hub client key、情資 API key。永不寫進 `config.json`。
//!
//! 後端：OS keychain（feature `keychain`，Windows Credential Manager / macOS Keychain）→
//! 否則 `<config>/secrets.json`（Unix 0600）。環境變數 `AI_SECURITY_MONITOR_SECRET_<KEY>`（舊名
//! `ASA_SECRET_<KEY>`）一律優先（CI / 容器用）。
//! 服務（LocalSystem / root daemon）沒有使用者 keychain，`AI_SECURITY_MONITOR_SECRETS_BACKEND=file`
//! （舊名 `ASA_SECRETS_BACKEND`）可強制檔案。
//!
//! 改名遷移：keychain 的服務名從 `asa` 改成 `ai-security-monitor`；新服務名讀不到時改讀舊的 `asa` 項目，
//! 讀到就複製一份到新服務名（舊項目保留，舊版仍可讀）。刪除時新舊兩個都刪，免得舊值又被讀回來。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};
use crate::store;

pub const SECRETS_FILE: &str = "secrets.json";
/// 密鑰後端的環境變數（新名）；`CLI --secrets-backend` 也寫這個。舊名 `ASA_SECRETS_BACKEND` 仍讀。
pub const ENV_BACKEND: &str = "AI_SECURITY_MONITOR_SECRETS_BACKEND";
/// 不含前綴的名稱（見 `util::env`）。
const ENV_BACKEND_REST: &str = "SECRETS_BACKEND";
#[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
const KEYCHAIN_SERVICE: &str = "ai-security-monitor";
/// 改名前的 keychain 服務名。
#[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
const LEGACY_KEYCHAIN_SERVICE: &str = "asa";

/// 讀新位置；沒有就讀舊位置，讀到就寫回新位置（失敗不影響回傳值）。
#[cfg_attr(not(all(feature = "keychain", any(windows, target_os = "macos"))), allow(dead_code))]
fn get_with_legacy(
    get_new: impl FnOnce() -> AppResult<Option<String>>,
    get_legacy: impl FnOnce() -> AppResult<Option<String>>,
    set_new: impl FnOnce(&str) -> AppResult<()>,
) -> AppResult<Option<String>> {
    if let Some(v) = get_new()? {
        return Ok(Some(v));
    }
    // 舊項目讀失敗（例如舊 keychain 項目權限問題）當作沒有，不擋新版
    let Ok(Some(v)) = get_legacy() else {
        return Ok(None);
    };
    let _ = set_new(&v);
    Ok(Some(v))
}

/// 目前生效的後端設定（新名優先、舊名次之）。
pub fn backend_env() -> Option<String> {
    crate::util::env::var(ENV_BACKEND_REST)
}

/// 常用鍵名。
pub const KEY_HUB_CLIENT: &str = "hub.client_key";
pub const KEY_HUB_ACTION: &str = "hub.action_key";
pub const KEY_HUB_AGENT_TOKEN: &str = "hub.agent_token";
/// 免金鑰加入申請的密語（只有這台 agent 知道；Hub 只存 sha256）。
pub const KEY_HUB_ENROLL_SECRET: &str = "hub.enroll_request_secret";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Keychain,
    File,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Backend::Keychain => "keychain",
            Backend::File => "file",
        }
    }
}

pub struct SecretStore {
    dir: PathBuf,
    backend: Backend,
}

fn keychain_available() -> bool {
    cfg!(all(feature = "keychain", any(windows, target_os = "macos")))
}

impl SecretStore {
    pub fn open(dir: &Path) -> Self {
        let forced = backend_env().map(|s| s.to_ascii_lowercase());
        let backend = match forced.as_deref() {
            // 單元測試一律用檔案（keychain 項目是全機共用的，測試不能碰到使用者真正的金鑰）
            _ if cfg!(test) => Backend::File,
            Some("file") => Backend::File,
            Some("keychain") if keychain_available() => Backend::Keychain,
            _ if keychain_available() => Backend::Keychain,
            _ => Backend::File,
        };
        Self {
            dir: dir.to_path_buf(),
            backend,
        }
    }

    pub fn with_backend(dir: &Path, backend: Backend) -> Self {
        Self {
            dir: dir.to_path_buf(),
            backend,
        }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// 不含前綴的環境變數名：`hub.client_key` → `SECRET_HUB_CLIENT_KEY`
    /// （讀 `AI_SECURITY_MONITOR_SECRET_HUB_CLIENT_KEY`，再讀 `ASA_SECRET_HUB_CLIENT_KEY`）。
    fn env_rest(key: &str) -> String {
        let mut s = String::from("SECRET_");
        for ch in key.chars() {
            if ch.is_ascii_alphanumeric() {
                s.push(ch.to_ascii_uppercase());
            } else {
                s.push('_');
            }
        }
        s
    }

    #[cfg(test)]
    fn env_name(key: &str) -> String {
        crate::util::env::name(&Self::env_rest(key))
    }

    pub fn get(&self, key: &str) -> AppResult<Option<String>> {
        if let Some(v) = crate::util::env::var(&Self::env_rest(key)) {
            return Ok(Some(v));
        }
        match self.backend {
            Backend::File => Ok(self.read_file()?.get(key).cloned()),
            Backend::Keychain => self.keychain_get(key),
        }
    }

    pub fn set(&self, key: &str, value: &str) -> AppResult<()> {
        match self.backend {
            Backend::File => {
                let mut m = self.read_file()?;
                m.insert(key.to_string(), value.to_string());
                self.write_file(&m)
            }
            Backend::Keychain => self.keychain_set(key, value),
        }
    }

    pub fn delete(&self, key: &str) -> AppResult<()> {
        match self.backend {
            Backend::File => {
                let mut m = self.read_file()?;
                if m.remove(key).is_some() {
                    self.write_file(&m)?;
                }
                Ok(())
            }
            Backend::Keychain => self.keychain_delete(key),
        }
    }

    fn read_file(&self) -> AppResult<BTreeMap<String, String>> {
        store::read_json_in(&self.dir, SECRETS_FILE)
    }

    fn write_file(&self, m: &BTreeMap<String, String>) -> AppResult<()> {
        let bytes = serde_json::to_vec_pretty(m)
            .map_err(|e| AppError::Storage(tf!("序列化 {file} 失敗：{e}", file = SECRETS_FILE, e = e)))?;
        store::ensure_dir(&self.dir)?;
        let path = self.dir.join(SECRETS_FILE);
        store::write_private_atomic(&path, &bytes)?;
        store::restrict_permissions(&path)
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn entry(service: &str, key: &str) -> AppResult<keyring::Entry> {
        keyring::Entry::new(service, key).map_err(|e| AppError::Storage(tf!("keychain 錯誤：{e}", e = e)))
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_read(service: &str, key: &str) -> AppResult<Option<String>> {
        match Self::entry(service, key)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AppError::Storage(tf!("keychain 錯誤：{e}", e = e))),
        }
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_get(&self, key: &str) -> AppResult<Option<String>> {
        get_with_legacy(
            || Self::keychain_read(KEYCHAIN_SERVICE, key),
            || Self::keychain_read(LEGACY_KEYCHAIN_SERVICE, key),
            |v| self.keychain_set(key, v),
        )
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_set(&self, key: &str, value: &str) -> AppResult<()> {
        Self::entry(KEYCHAIN_SERVICE, key)?
            .set_password(value)
            .map_err(|e| AppError::Storage(tf!("keychain 錯誤：{e}", e = e)))
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_delete(&self, key: &str) -> AppResult<()> {
        // 舊服務名的項目也刪：否則下次讀取又會從舊項目遷移回來
        for service in [KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_SERVICE] {
            match Self::entry(service, key)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => return Err(AppError::Storage(tf!("keychain 錯誤：{e}", e = e))),
            }
        }
        Ok(())
    }

    #[cfg(not(all(feature = "keychain", any(windows, target_os = "macos"))))]
    fn keychain_get(&self, _key: &str) -> AppResult<Option<String>> {
        Err(AppError::Unsupported(t!("此平台沒有 keychain 後端").into()))
    }

    #[cfg(not(all(feature = "keychain", any(windows, target_os = "macos"))))]
    fn keychain_set(&self, _key: &str, _value: &str) -> AppResult<()> {
        Err(AppError::Unsupported(t!("此平台沒有 keychain 後端").into()))
    }

    #[cfg(not(all(feature = "keychain", any(windows, target_os = "macos"))))]
    fn keychain_delete(&self, _key: &str) -> AppResult<()> {
        Err(AppError::Unsupported(t!("此平台沒有 keychain 後端").into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backend_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let s = SecretStore::with_backend(dir.path(), Backend::File);
        assert_eq!(s.get("hub.client_key").unwrap(), None);
        s.set("hub.client_key", "abc").unwrap();
        assert_eq!(s.get("hub.client_key").unwrap().as_deref(), Some("abc"));
        s.delete("hub.client_key").unwrap();
        assert_eq!(s.get("hub.client_key").unwrap(), None);
    }

    #[test]
    fn env_name_mapping() {
        assert_eq!(
            SecretStore::env_name("hub.client_key"),
            "AI_SECURITY_MONITOR_SECRET_HUB_CLIENT_KEY"
        );
        assert_eq!(
            SecretStore::env_name("intel.abuseipdb"),
            "AI_SECURITY_MONITOR_SECRET_INTEL_ABUSEIPDB"
        );
        assert_eq!(SecretStore::env_rest("hub.client_key"), "SECRET_HUB_CLIENT_KEY");
    }

    #[test]
    fn env_override_new_then_legacy() {
        // 專屬鍵名，避免與其他測試共用環境變數
        let dir = tempfile::tempdir().unwrap();
        let s = SecretStore::with_backend(dir.path(), Backend::File);
        s.set("zz.envtest", "from-file").unwrap();
        assert_eq!(s.get("zz.envtest").unwrap().as_deref(), Some("from-file"));
        std::env::set_var("ASA_SECRET_ZZ_ENVTEST", "legacy-env");
        assert_eq!(s.get("zz.envtest").unwrap().as_deref(), Some("legacy-env"));
        std::env::set_var("AI_SECURITY_MONITOR_SECRET_ZZ_ENVTEST", "new-env");
        assert_eq!(s.get("zz.envtest").unwrap().as_deref(), Some("new-env"));
        std::env::remove_var("AI_SECURITY_MONITOR_SECRET_ZZ_ENVTEST");
        std::env::remove_var("ASA_SECRET_ZZ_ENVTEST");
        assert_eq!(s.get("zz.envtest").unwrap().as_deref(), Some("from-file"));
    }

    #[test]
    fn legacy_entry_is_read_and_copied_forward() {
        use std::cell::RefCell;
        use std::collections::HashMap;
        // 以記憶體模擬新舊兩個 keychain 服務名
        let new: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        let legacy: HashMap<String, String> = [("hub.client_key".to_string(), "old-k".to_string())].into();
        let get = |k: &str| {
            get_with_legacy(
                || Ok(new.borrow().get(k).cloned()),
                || Ok(legacy.get(k).cloned()),
                |v| {
                    new.borrow_mut().insert(k.to_string(), v.to_string());
                    Ok(())
                },
            )
        };
        assert_eq!(get("hub.client_key").unwrap().as_deref(), Some("old-k"));
        assert_eq!(new.borrow().get("hub.client_key").map(String::as_str), Some("old-k"));
        assert_eq!(legacy.get("hub.client_key").map(String::as_str), Some("old-k"));
        assert_eq!(get("missing").unwrap(), None);
        // 新的有值時不看舊的
        new.borrow_mut().insert("hub.client_key".into(), "new-k".into());
        assert_eq!(get("hub.client_key").unwrap().as_deref(), Some("new-k"));
        // 舊項目讀取失敗當作沒有
        let r = get_with_legacy(|| Ok(None), || Err(AppError::Storage("denied".into())), |_| Ok(()));
        assert_eq!(r.unwrap(), None);
    }
}
