//! 設定目錄下的檔案讀寫（path-based，所有入口共用）。寫入一律 temp + rename（原子）。

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{AppError, AppResult};

pub fn ensure_dir(dir: &Path) -> AppResult<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| AppError::Storage(tf!("建立目錄失敗：{path}：{e}", path = dir.display(), e = e)))
}

/// 讀 JSON；檔案不存在回 `Default`。
pub fn read_json_in<T: DeserializeOwned + Default>(dir: &Path, file: &str) -> AppResult<T> {
    Ok(read_json_opt(dir, file)?.unwrap_or_default())
}

/// 讀 JSON；檔案不存在回 `None`。
pub fn read_json_opt<T: DeserializeOwned>(dir: &Path, file: &str) -> AppResult<Option<T>> {
    let path = dir.join(file);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<T>(&bytes)
            .map(Some)
            .map_err(|e| AppError::Storage(tf!("解析 {file} 失敗：{e}", file = file, e = e))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AppError::Storage(tf!("讀取 {file} 失敗：{e}", file = file, e = e))),
    }
}

/// 原子寫入 pretty JSON（人會讀 / diff 的設定檔用）。
pub fn write_json_in<T: Serialize>(dir: &Path, file: &str, value: &T) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| AppError::Storage(tf!("序列化 {file} 失敗：{e}", file = file, e = e)))?;
    write_bytes_in(dir, file, &bytes)
}

/// 原子寫入 compact JSON（機器產生、體積大的資料用）。
pub fn write_json_compact_in<T: Serialize>(dir: &Path, file: &str, value: &T) -> AppResult<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| AppError::Storage(tf!("序列化 {file} 失敗：{e}", file = file, e = e)))?;
    write_bytes_in(dir, file, &bytes)
}

/// 原子寫入任意 bytes（temp + rename）。
pub fn write_bytes_in(dir: &Path, file: &str, bytes: &[u8]) -> AppResult<()> {
    ensure_dir(dir)?;
    let path = dir.join(file);
    write_bytes_atomic(&path, bytes)
}

pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let file = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let tmp: PathBuf = path.with_file_name(format!("{file}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| AppError::Storage(tf!("寫入 {file} 失敗：{e}", file = file, e = e)))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Windows 上目標被鎖時 rename 會失敗；清掉暫存檔再回報。
        let _ = std::fs::remove_file(&tmp);
        return Err(AppError::Storage(tf!("更新 {file} 失敗：{e}", file = file, e = e)));
    }
    Ok(())
}

/// 在 Unix 上把檔案權限收成 0600（密鑰檔用）；其他平台為 no-op。
pub fn restrict_permissions(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
    struct Demo {
        a: u32,
        b: String,
    }

    #[test]
    fn json_roundtrip_and_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing: Demo = read_json_in(dir.path(), "x.json").unwrap();
        assert_eq!(missing, Demo::default());
        let v = Demo { a: 7, b: "hi".into() };
        write_json_in(dir.path(), "x.json", &v).unwrap();
        let back: Demo = read_json_in(dir.path(), "x.json").unwrap();
        assert_eq!(back, v);
        assert!(!dir.path().join("x.json.tmp").exists());
    }

    #[test]
    fn invalid_json_is_a_storage_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.json"), b"{not json").unwrap();
        let r: AppResult<Demo> = read_json_in(dir.path(), "bad.json");
        assert!(matches!(r, Err(AppError::Storage(_))));
    }
}
