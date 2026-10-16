//! 軟體清單：Windows（解除安裝登錄機碼＋最近的更新）、macOS（/Applications、Homebrew）、Linux（dpkg／rpm／apk、待更新數、os-release）。
//! 各平台的輸出解析都是純函式，用字串測。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppResult;
use crate::util::cmd::{powershell, CmdRunner, CmdSpec};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Package {
    /// windows | macos-app | brew | dpkg | rpm | apk
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// dpkg／rpm 的原始碼套件（OSV 以它為準）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsInfo {
    /// windows | macos | linux
    pub family: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<u32>,
    #[serde(default)]
    pub server: bool,
    /// Windows EditionID（Enterprise／Education 支援期較長）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    /// Linux os-release 的 ID／VERSION_ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Inventory {
    pub os: OsInfo,
    pub packages: Vec<Package>,
    /// 最近一次安裝 Windows 更新（yyyy-mm-dd）與 KB
    pub last_patch: Option<(String, String)>,
    /// Linux 待更新套件數（其中安全性更新數）
    pub pending_updates: Option<(u32, u32)>,
    pub notes: Vec<String>,
}

impl Inventory {
    pub fn by_ecosystem(&self) -> BTreeMap<String, u32> {
        let mut m = BTreeMap::new();
        for p in &self.packages {
            *m.entry(p.ecosystem.clone()).or_default() += 1;
        }
        m
    }
}

// ---------------- Windows ----------------

pub const WINDOWS_SCRIPT: &str = r#"
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
$apps = foreach ($k in $keys) {
  Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
    ForEach-Object { [pscustomobject]@{ n = [string]$_.DisplayName; v = [string]$_.DisplayVersion; p = [string]$_.Publisher } }
}
$hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
[pscustomobject]@{
  apps = @($apps)
  hotfix_date = $(if ($hf) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { $null })
  hotfix_id = $(if ($hf) { $hf.HotFixID } else { $null })
  caption = [string]$os.Caption
  build = [string]$os.BuildNumber
  ubr = [string]$cv.UBR
  edition = [string]$cv.EditionID
  display = [string]$cv.DisplayVersion
} | ConvertTo-Json -Depth 3 -Compress
"#;

pub fn parse_windows(stdout: &str) -> Inventory {
    let mut inv = Inventory::default();
    let v: Value = serde_json::from_str(stdout.trim_start_matches('\u{feff}').trim()).unwrap_or(Value::Null);
    let apps = match &v["apps"] {
        Value::Array(a) => a.clone(),
        Value::Object(_) => vec![v["apps"].clone()],
        _ => Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for a in apps {
        let name = a["n"].as_str().unwrap_or("").trim().to_string();
        let version = a["v"].as_str().unwrap_or("").trim().to_string();
        if name.is_empty() || !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        inv.packages.push(Package {
            ecosystem: "windows".into(),
            name,
            version,
            vendor: a["p"].as_str().filter(|p| !p.is_empty()).map(str::to_string),
            source: None,
            source_version: None,
        });
    }
    if let (Some(d), Some(id)) = (v["hotfix_date"].as_str(), v["hotfix_id"].as_str()) {
        inv.last_patch = Some((d.to_string(), id.to_string()));
    }
    let caption = v["caption"].as_str().unwrap_or("").to_string();
    inv.os = OsInfo {
        family: "windows".into(),
        server: caption.to_ascii_lowercase().contains("server"),
        name: if caption.is_empty() { "Windows".into() } else { caption },
        version: v["display"].as_str().unwrap_or("").to_string(),
        build: v["build"].as_str().and_then(|b| b.parse().ok()),
        edition: v["edition"].as_str().filter(|e| !e.is_empty()).map(str::to_string),
        ..Default::default()
    };
    inv
}

// ---------------- Linux ----------------

pub fn parse_os_release(text: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut id = None;
    let mut ver = None;
    let mut pretty = None;
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "ID" => id = Some(v.to_ascii_lowercase()),
            "VERSION_ID" => ver = Some(v),
            "PRETTY_NAME" => pretty = Some(v),
            _ => {}
        }
    }
    (id, ver, pretty)
}

/// `dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n'`
pub fn parse_dpkg(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let name = it.next()?.trim().to_string();
            let version = it.next()?.trim().to_string();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            let source = it.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            let source_version = it.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            Some(Package {
                ecosystem: "dpkg".into(),
                name,
                version,
                vendor: None,
                source,
                source_version,
            })
        })
        .collect()
}

/// `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`
pub fn parse_rpm(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let (n, v) = l.split_once('\t')?;
            (!n.trim().is_empty()).then(|| Package {
                ecosystem: "rpm".into(),
                name: n.trim().to_string(),
                version: v.trim().to_string(),
                vendor: None,
                source: None,
                source_version: None,
            })
        })
        .collect()
}

/// `apk info -v`：`musl-1.2.5-r0` → (musl, 1.2.5-r0)
pub fn parse_apk(text: &str) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let parts: Vec<&str> = l.trim().split('-').collect();
            if parts.len() < 3 {
                return None;
            }
            let n = parts.len();
            Some(Package {
                ecosystem: "apk".into(),
                name: parts[..n - 2].join("-"),
                version: format!("{}-{}", parts[n - 2], parts[n - 1]),
                vendor: None,
                source: None,
                source_version: None,
            })
        })
        .collect()
}

/// `apt list --upgradable` → (全部, 安全性)
pub fn parse_apt_upgradable(text: &str) -> (u32, u32) {
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("upgradable from")).collect();
    let sec = lines.iter().filter(|l| l.contains("-security")).count();
    (lines.len() as u32, sec as u32)
}

// ---------------- macOS ----------------

/// `brew list --versions`（formula 或 cask）：`name ver [ver…]` 取最後一個版本。
pub fn parse_brew(text: &str, cask: bool) -> Vec<Package> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?.to_string();
            let version = it.last()?.to_string();
            Some(Package {
                ecosystem: if cask { "brew-cask".into() } else { "brew".into() },
                name,
                version,
                vendor: None,
                source: None,
                source_version: None,
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn mac_apps() -> Vec<Package> {
    let mut out = Vec::new();
    for dir in ["/Applications", "/Applications/Utilities"] {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x != "app").unwrap_or(true) {
                continue;
            }
            let Ok(v) = plist::Value::from_file(p.join("Contents/Info.plist")) else {
                continue;
            };
            let d = match v.as_dictionary() {
                Some(d) => d,
                None => continue,
            };
            let get = |k: &str| d.get(k).and_then(|x| x.as_string()).map(str::to_string);
            let name = get("CFBundleDisplayName")
                .or_else(|| get("CFBundleName"))
                .unwrap_or_else(|| {
                    p.file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default()
                });
            let version = get("CFBundleShortVersionString")
                .or_else(|| get("CFBundleVersion"))
                .unwrap_or_default();
            out.push(Package {
                ecosystem: "macos-app".into(),
                name,
                version,
                vendor: get("CFBundleIdentifier"),
                source: None,
                source_version: None,
            });
        }
    }
    out
}

/// 收集這台機器的清單。指令失敗只記 note，不讓掃描失敗。
pub async fn collect(runner: &dyn CmdRunner) -> AppResult<Inventory> {
    if cfg!(windows) {
        let out = runner.run(&powershell(WINDOWS_SCRIPT).timeout(90_000)).await?;
        let mut inv = parse_windows(&out.stdout);
        if inv.packages.is_empty() {
            inv.notes.push(format!(
                "windows inventory empty: {}",
                crate::util::text::clip(&out.stderr, 200)
            ));
        }
        return Ok(inv);
    }
    let mut inv = Inventory::default();
    if cfg!(target_os = "macos") {
        inv.os = OsInfo {
            family: "macos".into(),
            name: "macOS".into(),
            version: sysinfo::System::os_version().unwrap_or_default(),
            ..Default::default()
        };
        #[cfg(target_os = "macos")]
        inv.packages.extend(mac_apps());
        for (args, cask) in [
            (vec!["list", "--versions"], false),
            (vec!["list", "--cask", "--versions"], true),
        ] {
            if let Ok(o) = runner.run(&CmdSpec::new("brew", &args).timeout(60_000)).await {
                if o.ok() {
                    inv.packages.extend(parse_brew(&o.stdout, cask));
                }
            }
        }
        return Ok(inv);
    }
    // Linux
    let (id, ver, pretty) = parse_os_release(&std::fs::read_to_string("/etc/os-release").unwrap_or_default());
    inv.os = OsInfo {
        family: "linux".into(),
        name: pretty.unwrap_or_else(|| "Linux".into()),
        version: ver.clone().unwrap_or_default(),
        distro: id,
        distro_version: ver,
        ..Default::default()
    };
    type Parser = fn(&str) -> Vec<Package>;
    let tries: [(&str, Vec<&str>, Parser); 3] = [
        (
            "dpkg-query",
            vec![
                "-W",
                "-f",
                "${Package}\t${Version}\t${source:Package}\t${source:Version}\n",
            ],
            parse_dpkg,
        ),
        (
            "rpm",
            vec!["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            parse_rpm,
        ),
        ("apk", vec!["info", "-v"], parse_apk),
    ];
    for (prog, args, parse) in tries {
        if let Ok(o) = runner.run(&CmdSpec::new(prog, &args).timeout(60_000)).await {
            if o.ok() && !o.stdout.trim().is_empty() {
                inv.packages.extend(parse(&o.stdout));
                break;
            }
        }
    }
    if let Ok(o) = runner
        .run(&CmdSpec::new("apt", &["list", "--upgradable"]).timeout(60_000))
        .await
    {
        if o.ok() {
            inv.pending_updates = Some(parse_apt_upgradable(&o.stdout));
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_inventory() {
        let out = r#"{"apps":[{"n":"7-Zip 24.08 (x64)","v":"24.08","p":"Igor Pavlov"},{"n":"Git","v":"2.44.0","p":"The Git Development Community"},{"n":"Git","v":"2.44.0","p":""}],"hotfix_date":"2026-09-10","hotfix_id":"KB5065789","caption":"Microsoft Windows 11 Pro","build":"26200","ubr":"6584","edition":"Professional","display":"25H2"}"#;
        let inv = parse_windows(out);
        assert_eq!(inv.packages.len(), 2);
        assert_eq!(inv.packages[0].vendor.as_deref(), Some("Igor Pavlov"));
        assert_eq!(inv.last_patch, Some(("2026-09-10".into(), "KB5065789".into())));
        assert_eq!(
            (inv.os.build, inv.os.server, inv.os.version.as_str()),
            (Some(26200), false, "25H2")
        );
        // 單一 App 時 ConvertTo-Json 會給物件
        let one = parse_windows(
            r#"{"apps":{"n":"PuTTY release 0.80 (64-bit)","v":"0.80.0.0","p":"Simon Tatham"},"caption":"Microsoft Windows Server 2016 Standard","build":"14393"}"#,
        );
        assert_eq!(one.packages.len(), 1);
        assert!(one.os.server);
        assert!(parse_windows("garbage").packages.is_empty());
    }

    #[test]
    fn linux_parsers() {
        let (id, ver, pretty) =
            parse_os_release("PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n");
        assert_eq!(
            (id.as_deref(), ver.as_deref(), pretty.as_deref()),
            (Some("ubuntu"), Some("24.04"), Some("Ubuntu 24.04.1 LTS"))
        );
        let d = parse_dpkg("openssl\t3.0.13-0ubuntu3.1\topenssl\t3.0.13-0ubuntu3.1\nlibc6\t2.39-0ubuntu8\tglibc\t2.39-0ubuntu8\n\nbad\n");
        assert_eq!(d.len(), 2);
        assert_eq!(d[1].source.as_deref(), Some("glibc"));
        let r = parse_rpm("openssl\t3.0.7-27.el9\nbash\t5.1.8-9.el9\n");
        assert_eq!(r[0].version, "3.0.7-27.el9");
        let a = parse_apk("musl-1.2.5-r0\nca-certificates-bundle-20240705-r0\n");
        assert_eq!(
            (a[1].name.as_str(), a[1].version.as_str()),
            ("ca-certificates-bundle", "20240705-r0")
        );
        let up = "Listing...\nopenssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\nvim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]\n";
        assert_eq!(parse_apt_upgradable(up), (2, 1));
    }

    #[test]
    fn brew_parser() {
        let b = parse_brew("git 2.44.0 2.45.2\nnode 20.11.0\n", false);
        assert_eq!((b[0].name.as_str(), b[0].version.as_str()), ("git", "2.45.2"));
        assert_eq!(
            parse_brew("google-chrome 138.0.7204.50\n", true)[0].ecosystem,
            "brew-cask"
        );
    }
}
