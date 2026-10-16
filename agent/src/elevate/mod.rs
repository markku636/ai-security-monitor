//! 提權：判斷是否已是管理員 / root；真正的「以管理員身分重新執行」在第 4 輪補上。
//! 原則：**永不靜默提權**，需要時先回 `NeedsConfirm` 說明，`--yes` 後才重新執行。

/// 目前行程是否具系統管理員 / root 權限。
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
}

#[cfg(unix)]
mod imp {
    pub fn is_elevated() -> bool {
        // SAFETY: geteuid 無副作用、永遠成功。
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    pub fn is_elevated() -> bool {
        false
    }
}
