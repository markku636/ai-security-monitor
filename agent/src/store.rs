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
    write_atomic(path, bytes, false)
}

/// 原子寫入只有擁有者能讀的檔（密鑰檔）：Unix 上暫存檔一建立就是 0600，寫入與 rename 期間都沒有其他人讀得到的空窗。
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    write_atomic(path, bytes, true)
}

fn write_atomic(path: &Path, bytes: &[u8], private: bool) -> AppResult<()> {
    let file = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let tmp: PathBuf = path.with_file_name(format!("{file}.tmp-{}", std::process::id()));
    write_new(&tmp, bytes, private).map_err(|e| AppError::Storage(tf!("寫入 {file} 失敗：{e}", file = file, e = e)))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Windows 上目標被鎖時 rename 會失敗；清掉暫存檔再回報。
        let _ = std::fs::remove_file(&tmp);
        return Err(AppError::Storage(tf!("更新 {file} 失敗：{e}", file = file, e = e)));
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    if private {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // 上次中斷留下的暫存檔可能是別的權限：刪掉重建，mode 才會生效
        let _ = std::fs::remove_file(path);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        return f.write_all(bytes);
    }
    let _ = private;
    std::fs::write(path, bytes)
}

/// Windows 系統服務的設定目錄（%ProgramData% 底下）預設繼承「Users 可以建立檔案」，一般使用者就能放檔案給以 SYSTEM 執行的服務讀。
/// 改成只有 SYSTEM 與 Administrators 能存取、擁有者改成 Administrators，子項目重設成只繼承這兩個（使用者放進來的檔也失去權限）。
/// 需要系統管理員或 SYSTEM 權限；其他平台不做事（目錄由 root 建立，密鑰檔 0600）。
pub fn harden_system_dir(dir: &Path) -> AppResult<()> {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        ensure_dir(dir)?;
        let icacls = |args: &[&OsStr]| -> AppResult<()> {
            let out = std::process::Command::new("icacls")
                .args(args)
                .output()
                .map_err(|e| AppError::Storage(tf!("執行 icacls 失敗：{e}", e = e)))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(AppError::Storage(tf!(
                    "設定 {path} 的權限失敗：{e}",
                    path = dir.display(),
                    e = String::from_utf8_lossy(&out.stdout).trim()
                )))
            }
        };
        let d = dir.as_os_str();
        icacls(&[
            d,
            OsStr::new("/setowner"),
            OsStr::new("*S-1-5-32-544"),
            OsStr::new("/T"),
            OsStr::new("/C"),
            OsStr::new("/Q"),
        ])?;
        icacls(&[
            d,
            OsStr::new("/inheritance:r"),
            OsStr::new("/grant:r"),
            OsStr::new("*S-1-5-18:(OI)(CI)F"),
            OsStr::new("*S-1-5-32-544:(OI)(CI)F"),
            OsStr::new("/Q"),
        ])?;
        // 子項目拿掉個別設定的權限、只繼承上面兩個（目錄是空的時 icacls 找不到 * 會失敗，忽略）
        let children = dir.join("*");
        let _ = icacls(&[
            children.as_os_str(),
            OsStr::new("/reset"),
            OsStr::new("/T"),
            OsStr::new("/C"),
            OsStr::new("/Q"),
        ]);
    }
    #[cfg(not(windows))]
    let _ = dir;
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
