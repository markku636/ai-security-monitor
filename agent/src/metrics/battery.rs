//! 電池（筆電）：電量百分比與是否在充電。讀不到（桌機、伺服器、虛擬機）就回 `None`。
//! - Windows：`GetSystemPowerStatus`；
//! - macOS：`pmset -g batt`；
//! - Linux：`/sys/class/power_supply/*`（type=Battery、不是滑鼠等周邊的 scope=Device）。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Battery {
    /// 0–100。
    pub percent: u8,
    /// 正在充電（插著電但已充飽也算 false）。
    pub charging: bool,
    /// 接著電源。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugged: Option<bool>,
}

/// `pmset -g batt` 的輸出 → 電池狀態。
pub fn parse_pmset(out: &str) -> Option<Battery> {
    let plugged = out
        .contains("'AC Power'")
        .then_some(true)
        .or_else(|| out.contains("'Battery Power'").then_some(false));
    for line in out.lines() {
        if !line.contains("InternalBattery") {
            continue;
        }
        let pct = line.split(['\t', ';']).find_map(|f| {
            let f = f.trim();
            f.strip_suffix('%').and_then(|n| n.trim().parse::<u8>().ok())
        })?;
        let lower = line.to_ascii_lowercase();
        let charging = lower.contains("; charging") && !lower.contains("discharging");
        return Some(Battery {
            percent: pct.min(100),
            charging,
            plugged,
        });
    }
    None
}

/// Linux sysfs 的一個 power_supply：`type`、`scope`、`capacity`、`status`。
pub fn parse_sysfs(kind: &str, scope: Option<&str>, capacity: &str, status: &str) -> Option<Battery> {
    if kind.trim() != "Battery" || scope.is_some_and(|s| s.trim().eq_ignore_ascii_case("device")) {
        return None;
    }
    let percent = capacity.trim().parse::<u8>().ok()?.min(100);
    let st = status.trim();
    Some(Battery {
        percent,
        charging: st == "Charging",
        plugged: match st {
            "Charging" | "Full" | "Not charging" => Some(true),
            "Discharging" => Some(false),
            _ => None,
        },
    })
}

#[cfg(target_os = "linux")]
pub async fn read() -> Option<Battery> {
    let rd = std::fs::read_dir("/sys/class/power_supply").ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let get = |f: &str| std::fs::read_to_string(p.join(f)).ok();
        let (Some(kind), Some(cap)) = (get("type"), get("capacity")) else {
            continue;
        };
        if let Some(b) = parse_sysfs(
            &kind,
            get("scope").as_deref(),
            &cap,
            get("status").as_deref().unwrap_or(""),
        ) {
            return Some(b);
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub async fn read() -> Option<Battery> {
    use crate::util::cmd::{CmdRunner, CmdSpec, RealRunner};
    let out = RealRunner
        .run(&CmdSpec::new("pmset", &["-g", "batt"]).timeout(5_000))
        .await
        .ok()?;
    if !out.ok() {
        return None;
    }
    parse_pmset(&out.stdout)
}

#[cfg(windows)]
pub async fn read() -> Option<Battery> {
    use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
    let mut s = SYSTEM_POWER_STATUS {
        ACLineStatus: 0,
        BatteryFlag: 0,
        BatteryLifePercent: 0,
        SystemStatusFlag: 0,
        BatteryLifeTime: 0,
        BatteryFullLifeTime: 0,
    };
    // SAFETY: 傳入有效的結構指標；函式只寫入這個結構。
    if unsafe { GetSystemPowerStatus(&mut s) } == 0 {
        return None;
    }
    from_power_status(s.ACLineStatus, s.BatteryFlag, s.BatteryLifePercent)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub async fn read() -> Option<Battery> {
    None
}

/// Windows `SYSTEM_POWER_STATUS` 的欄位 → 電池狀態（128＝沒有電池、255＝未知）。
pub fn from_power_status(ac_line: u8, flag: u8, percent: u8) -> Option<Battery> {
    if flag == 128 || flag == 255 || percent == 255 {
        return None;
    }
    Some(Battery {
        percent: percent.min(100),
        charging: flag & 8 != 0,
        plugged: match ac_line {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmset_output() {
        let charging = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=4653155)\t85%; charging; 0:42 remaining present: true\n";
        assert_eq!(
            parse_pmset(charging),
            Some(Battery {
                percent: 85,
                charging: true,
                plugged: Some(true)
            })
        );
        let on_battery = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t41%; discharging; 3:10 remaining present: true\n";
        let b = parse_pmset(on_battery).unwrap();
        assert_eq!((b.percent, b.charging, b.plugged), (41, false, Some(false)));
        // 桌機（Mac mini）：沒有電池那一行
        assert_eq!(parse_pmset("Now drawing from 'AC Power'\n"), None);
    }

    #[test]
    fn sysfs_and_windows() {
        let b = parse_sysfs("Battery\n", None, "77\n", "Discharging\n").unwrap();
        assert_eq!((b.percent, b.charging, b.plugged), (77, false, Some(false)));
        assert!(
            parse_sysfs("Battery", Some("Device"), "50", "Discharging").is_none(),
            "mouse battery"
        );
        assert!(parse_sysfs("Mains", None, "1", "").is_none());
        assert_eq!(
            from_power_status(1, 8, 64),
            Some(Battery {
                percent: 64,
                charging: true,
                plugged: Some(true)
            })
        );
        assert_eq!(from_power_status(1, 128, 255), None, "desktop without battery");
        assert_eq!(from_power_status(255, 255, 255), None);
    }
}
