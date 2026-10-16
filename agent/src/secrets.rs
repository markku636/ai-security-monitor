//! 密鑰儲存：hub client key、情資 API key。永不寫進 `config.json`。
//!
//! 後端：OS keychain（feature `keychain`，Windows Credential Manager / macOS Keychain）→
//! 否則 `<config>/secrets.json`（Unix 0600）。環境變數 `ASA_SECRET_<KEY>` 一律優先（CI / 容器用）。
//! 服務（LocalSystem / root daemon）沒有使用者 keychain，`ASA_SECRETS_BACKEND=file` 可強制檔案。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{AppError, AppResult};
use crate::store;

pub const SECRETS_FILE: &str = "secrets.json";
pub const ENV_BACKEND: &str = "ASA_SECRETS_BACKEND";
const KEYCHAIN_SERVICE: &str = "asa";

/// 常用鍵名。
pub const KEY_HUB_CLIENT: &str = "hub.client_key";
pub const KEY_HUB_ACTION: &str = "hub.action_key";

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
        let forced = std::env::var(ENV_BACKEND).ok().map(|s| s.to_ascii_lowercase());
        let backend = match forced.as_deref() {
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

    fn env_name(key: &str) -> String {
        let mut s = String::from("ASA_SECRET_");
        for ch in key.chars() {
            if ch.is_ascii_alphanumeric() {
                s.push(ch.to_ascii_uppercase());
            } else {
                s.push('_');
            }
        }
        s
    }

    pub fn get(&self, key: &str) -> AppResult<Option<String>> {
        if let Ok(v) = std::env::var(Self::env_name(key)) {
            if !v.is_empty() {
                return Ok(Some(v));
            }
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
        store::write_json_in(&self.dir, SECRETS_FILE, m)?;
        store::restrict_permissions(&self.dir.join(SECRETS_FILE))
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn entry(key: &str) -> AppResult<keyring::Entry> {
        keyring::Entry::new(KEYCHAIN_SERVICE, key).map_err(|e| AppError::Storage(tf!("keychain 錯誤：{e}", e = e)))
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_get(&self, key: &str) -> AppResult<Option<String>> {
        match Self::entry(key)?.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AppError::Storage(tf!("keychain 錯誤：{e}", e = e))),
        }
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_set(&self, key: &str, value: &str) -> AppResult<()> {
        Self::entry(key)?
            .set_password(value)
            .map_err(|e| AppError::Storage(tf!("keychain 錯誤：{e}", e = e)))
    }

    #[cfg(all(feature = "keychain", any(windows, target_os = "macos")))]
    fn keychain_delete(&self, key: &str) -> AppResult<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(AppError::Storage(tf!("keychain 錯誤：{e}", e = e))),
        }
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
        assert_eq!(SecretStore::env_name("hub.client_key"), "ASA_SECRET_HUB_CLIENT_KEY");
        assert_eq!(SecretStore::env_name("intel.abuseipdb"), "ASA_SECRET_INTEL_ABUSEIPDB");
    }
}
