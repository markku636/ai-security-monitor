//! 提權：判斷是否已是管理員 / root；需要時以管理員身分**重新執行自己**（帶 `--elevated --result-file`），
//! 子行程把結果寫成 JSON 檔，父行程讀回來印出。原則：永不靜默提權——呼叫端一定先過 `--yes` 確認。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

/// 目前行程是否具系統管理員 / root 權限。
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

/// 子行程寫回的結果。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElevatedResult {
    pub ok: bool,
    pub lines: Vec<String>,
    #[serde(default)]
    pub json: serde_json::Value,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

impl ElevatedResult {
    pub fn write(&self, path: &Path) -> AppResult<()> {
        let bytes = serde_json::to_vec(self)?;
        crate::store::write_bytes_atomic(path, &bytes)
    }
}

/// 組出子行程參數：原參數（去掉程式名）＋ `--elevated --result-file X`，必要時補 `--config-dir`
/// （sudo 之後 HOME 變成 root 的，設定目錄要沿用使用者的）。
pub fn child_args(original: &[String], result_file: &Path, config_dir: &Path) -> Vec<String> {
    let mut args: Vec<String> = original.iter().skip(1).cloned().collect();
    args.push("--elevated".into());
    args.push("--result-file".into());
    args.push(result_file.to_string_lossy().to_string());
    if !original
        .iter()
        .any(|a| a == "--config-dir" || a.starts_with("--config-dir="))
    {
        args.push("--config-dir".into());
        args.push(config_dir.to_string_lossy().to_string());
    }
    args
}

/// Windows 命令列參數引號規則（CommandLineToArgvW）。
pub fn quote_win_arg(a: &str) -> String {
    if !a.is_empty() && !a.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return a.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// POSIX shell 單引號包裝。
pub fn quote_sh(a: &str) -> String {
    format!("'{}'", a.replace('\'', "'\\''"))
}

/// 以管理員身分重跑目前指令並取回結果。
pub async fn rerun_elevated(config_dir: &Path) -> AppResult<ElevatedResult> {
    let exe = std::env::current_exe().map_err(|e| AppError::Elevation(e.to_string()))?;
    let dir: PathBuf = config_dir.join("elevated");
    crate::store::ensure_dir(&dir)?;
    let result_file = dir.join(format!("{}.json", uuid::Uuid::new_v4().simple()));
    let original: Vec<String> = std::env::args().collect();
    let args = child_args(&original, &result_file, config_dir);
    eprintln!("{}", t!("此動作需要系統管理員權限，正在請求提權…"));
    let exe2 = exe.clone();
    let args2 = args.clone();
    tokio::task::spawn_blocking(move || imp::run_as_admin(&exe2, &args2))
        .await
        .map_err(|e| AppError::Elevation(e.to_string()))??;
    let bytes = std::fs::read(&result_file).map_err(|_| {
        AppError::Elevation(tf!(
            "提權後的行程沒有回報結果（可能被取消）。也可以手動以管理員身分執行：{cmd}",
            cmd = format!(
                "{} {}",
                exe.display(),
                args.iter()
                    .take(args.len().saturating_sub(4))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        ))
    })?;
    let _ = std::fs::remove_file(&result_file);
    serde_json::from_slice(&bytes).map_err(|e| AppError::Elevation(e.to_string()))
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use crate::error::{AppError, AppResult};

    /// 用 TokenElevation 判斷（`IsUserAnAdmin` 在 UAC 過濾 token 下不可靠）。
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elev as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && elev.TokenIsElevated != 0
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// UAC「以系統管理員身分執行」，隱藏視窗並等待結束。
    pub fn run_as_admin(exe: &Path, args: &[String]) -> AppResult<()> {
        let verb = wide("runas");
        let file = wide(&exe.to_string_lossy());
        let params = wide(
            &args
                .iter()
                .map(|a| super::quote_win_arg(a))
                .collect::<Vec<_>>()
                .join(" "),
        );
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                return Err(AppError::Elevation(t!("提權被取消或失敗（UAC）").into()));
            }
            if !info.hProcess.is_null() {
                WaitForSingleObject(info.hProcess, INFINITE);
                let mut code: u32 = 0;
                GetExitCodeProcess(info.hProcess, &mut code);
                CloseHandle(info.hProcess);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
mod imp {
    use std::io::IsTerminal;
    use std::path::Path;
    use std::process::Command;

    use crate::error::{AppError, AppResult};

    pub fn is_elevated() -> bool {
        // SAFETY: geteuid 無副作用、永遠成功。
        unsafe { libc::geteuid() == 0 }
    }

    /// 有終端機 → `sudo`（可輸入密碼）；macOS 無終端機 → osascript 系統對話框；
    /// Linux 桌面無終端機 → pkexec；都不行就請使用者自己 sudo。
    pub fn run_as_admin(exe: &Path, args: &[String]) -> AppResult<()> {
        let exe_s = exe.to_string_lossy().to_string();
        let status = if std::io::stdin().is_terminal() {
            Command::new("sudo").arg(&exe_s).args(args).status()
        } else if cfg!(target_os = "macos") {
            let cmd = std::iter::once(exe_s.clone())
                .chain(args.iter().cloned())
                .map(|a| super::quote_sh(&a))
                .collect::<Vec<_>>()
                .join(" ");
            let script = format!(
                "do shell script \"{}\" with administrator privileges",
                cmd.replace('\\', "\\\\").replace('"', "\\\"")
            );
            Command::new("osascript").args(["-e", &script]).status()
        } else if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Command::new("pkexec").arg(&exe_s).args(args).status()
        } else {
            return Err(AppError::Elevation(
                t!("沒有終端機可輸入密碼；請改用 sudo 執行同一個指令").into(),
            ));
        };
        match status {
            Ok(_) => Ok(()),
            Err(e) => Err(AppError::Elevation(e.to_string())),
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use std::path::Path;

    use crate::error::{AppError, AppResult};

    pub fn is_elevated() -> bool {
        false
    }

    pub fn run_as_admin(_exe: &Path, _args: &[String]) -> AppResult<()> {
        Err(AppError::Unsupported("elevation".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_args_append_protocol_flags() {
        let orig: Vec<String> = ["asa", "fw", "block", "1.2.3.4", "--yes"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let a = child_args(
            &orig,
            Path::new("/tmp/r.json"),
            Path::new("/home/u/.config/ai-security-agent"),
        );
        assert_eq!(&a[..4], &["fw", "block", "1.2.3.4", "--yes"]);
        assert!(a.contains(&"--elevated".to_string()));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--config-dir" && w[1].ends_with("ai-security-agent")));
        let orig2: Vec<String> = ["asa", "--config-dir", "/x", "fw", "ensure"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let b = child_args(&orig2, Path::new("/tmp/r.json"), Path::new("/y"));
        assert_eq!(b.iter().filter(|x| *x == "--config-dir").count(), 1);
    }

    #[test]
    fn windows_quoting() {
        assert_eq!(quote_win_arg("simple"), "simple");
        assert_eq!(quote_win_arg("C:\\Program Files\\asa"), "\"C:\\Program Files\\asa\"");
        assert_eq!(quote_win_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_win_arg("dir\\ with\\"), "\"dir\\ with\\\\\"");
        assert_eq!(quote_win_arg(""), "\"\"");
    }

    #[test]
    fn sh_quoting() {
        assert_eq!(quote_sh("a b"), "'a b'");
        assert_eq!(quote_sh("it's"), "'it'\\''s'");
    }
}
