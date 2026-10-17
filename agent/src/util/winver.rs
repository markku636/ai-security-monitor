//! Windows 版本細節：ProductType（工作站／伺服器／網域控制站）、InstallationType（Client／Server／Server Core）、
//! EditionID、ProductName 與組建編號。直接讀登錄（不開 PowerShell）；非 Windows 一律回空值。
//!
//! - `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`：`WinNT`＝工作站、`ServerNT`＝伺服器、
//!   `LanmanNT`＝網域控制站（與 `Win32_OperatingSystem.ProductType` 的 1／3／2 相同）。
//! - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`：`InstallationType`、`EditionID`、`ProductName`、`CurrentBuildNumber`。

use std::sync::OnceLock;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WinEdition {
    /// `workstation` | `server` | `domain_controller`
    pub product_type: Option<String>,
    /// `Client` | `Server` | `Server Core` | `Nano Server`
    pub installation_type: Option<String>,
    /// 例：`Professional`、`ServerDatacenter`、`ServerStandard`
    pub edition_id: Option<String>,
    /// 例：`Windows Server 2022 Datacenter`
    pub product_name: Option<String>,
    pub build: Option<u32>,
}

/// ProductOptions 的 ProductType → 對外名稱。
pub fn product_type_from_options(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "winnt" => Some("workstation"),
        "servernt" => Some("server"),
        "lanmannt" => Some("domain_controller"),
        _ => None,
    }
}

impl WinEdition {
    pub fn from_values(
        product_options: Option<&str>,
        installation_type: Option<&str>,
        edition_id: Option<&str>,
        product_name: Option<&str>,
        build: Option<&str>,
    ) -> Self {
        let clean = |v: Option<&str>| v.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        Self {
            product_type: product_options.and_then(product_type_from_options).map(str::to_string),
            installation_type: clean(installation_type),
            edition_id: clean(edition_id),
            product_name: clean(product_name),
            build: build.and_then(|b| b.trim().parse().ok()),
        }
    }

    /// 目前這台（只讀一次登錄）。
    pub fn current() -> &'static WinEdition {
        static CACHE: OnceLock<WinEdition> = OnceLock::new();
        CACHE.get_or_init(read_current)
    }

    pub fn is_known(&self) -> bool {
        self.product_type.is_some() || self.installation_type.is_some()
    }

    pub fn is_server(&self) -> bool {
        match self.product_type.as_deref() {
            Some("server" | "domain_controller") => true,
            Some(_) => false,
            None => self
                .installation_type
                .as_deref()
                .is_some_and(|i| i.to_ascii_lowercase().contains("server")),
        }
    }

    /// Server Core／Nano Server：沒有桌面體驗（沒有 Explorer、Shell.Application、設定 App）。
    pub fn is_core(&self) -> bool {
        self.installation_type
            .as_deref()
            .map(|i| i.to_ascii_lowercase())
            .is_some_and(|i| i == "server core" || i == "nano server")
    }

    pub fn is_dc(&self) -> bool {
        self.product_type.as_deref() == Some("domain_controller")
    }

    /// 硬化策略 `editions` 篩選用的標籤：`client`｜`server`＋`core`／`desktop`（＋`dc`）。讀不到版本時回空（不篩選）。
    pub fn tags(&self) -> Vec<String> {
        if !self.is_known() {
            return Vec::new();
        }
        let mut t: Vec<&str> = Vec::new();
        if self.is_server() {
            t.push("server");
            t.push(if self.is_core() { "core" } else { "desktop" });
            if self.is_dc() {
                t.push("dc");
            }
        } else {
            t.push("client");
        }
        t.into_iter().map(str::to_string).collect()
    }

    /// 給人看的版本名，例：`Windows Server 2022 Datacenter (Server Core)`。
    pub fn display(&self) -> Option<String> {
        let name = self.product_name.clone()?;
        Some(if self.is_core() {
            format!(
                "{name} ({})",
                self.installation_type.as_deref().unwrap_or("Server Core")
            )
        } else {
            name
        })
    }
}

#[cfg(windows)]
fn reg_string(subkey: &str, name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (k, n) = (wide(subkey), wide(name));
    let mut len: u32 = 0;
    // SAFETY: 指標都指向本函式持有、以 NUL 結尾的緩衝區；第一次只查長度。
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if rc != 0 || len == 0 || len > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u16; (len as usize).div_ceil(2)];
    // SAFETY: buf 至少 len 位元組。
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            n.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(windows)]
fn read_current() -> WinEdition {
    const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let po = reg_string(r"SYSTEM\CurrentControlSet\Control\ProductOptions", "ProductType");
    let it = reg_string(CV, "InstallationType");
    let ed = reg_string(CV, "EditionID");
    let pn = reg_string(CV, "ProductName");
    let bn = reg_string(CV, "CurrentBuildNumber");
    let mut e = WinEdition::from_values(
        po.as_deref(),
        it.as_deref(),
        ed.as_deref(),
        pn.as_deref(),
        bn.as_deref(),
    );
    // Windows 11 的 ProductName 仍寫「Windows 10」（sysinfo 也這樣修正）
    if !e.is_server() && e.build.is_some_and(|b| b >= 22000) {
        e.product_name = e.product_name.map(|p| p.replace("Windows 10 ", "Windows 11 "));
    }
    e
}

#[cfg(not(windows))]
fn read_current() -> WinEdition {
    WinEdition::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_client_server_core_and_dc() {
        let client = WinEdition::from_values(
            Some("WinNT"),
            Some("Client"),
            Some("Professional"),
            Some("Windows 11 Pro"),
            Some("26200"),
        );
        assert!(!client.is_server());
        assert_eq!(client.tags(), vec!["client"]);
        assert_eq!(client.product_type.as_deref(), Some("workstation"));
        assert_eq!(client.build, Some(26200));

        let core = WinEdition::from_values(
            Some("ServerNT"),
            Some("Server Core"),
            Some("ServerDatacenter"),
            Some("Windows Server 2022 Datacenter"),
            Some("20348"),
        );
        assert!(core.is_server() && core.is_core() && !core.is_dc());
        assert_eq!(core.tags(), vec!["server", "core"]);
        assert_eq!(
            core.display().as_deref(),
            Some("Windows Server 2022 Datacenter (Server Core)")
        );

        let dc = WinEdition::from_values(
            Some("LanmanNT"),
            Some("Server"),
            None,
            Some("Windows Server 2019 Standard"),
            None,
        );
        assert!(dc.is_dc() && dc.is_server());
        assert_eq!(dc.tags(), vec!["server", "desktop", "dc"]);
        assert_eq!(dc.display().as_deref(), Some("Windows Server 2019 Standard"));

        // 只有 InstallationType 也能判斷
        let it_only = WinEdition::from_values(None, Some("Server"), None, None, None);
        assert!(it_only.is_server());
        assert!(WinEdition::default().tags().is_empty());
        assert_eq!(product_type_from_options("garbage"), None);
    }

    #[cfg(windows)]
    #[test]
    fn reads_this_machine() {
        let e = WinEdition::current();
        assert!(e.is_known(), "{e:?}");
        assert!(e.build.is_some(), "{e:?}");
        assert!(e.product_name.is_some(), "{e:?}");
    }
}
