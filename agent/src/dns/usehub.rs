//! `dns use-hub`／`dns restore`：把這台的系統 DNS 指到公司的防護 DNS，記下原本的設定以便還原。
//! - Windows：每張啟用中的網卡 `Set-DnsClientServerAddress`；原本是 DHCP 還是手動從登錄 NameServer 判斷。
//! - macOS：每個啟用中的網路服務 `networksetup -setdnsservers`。
//! - Linux：NetworkManager（`nmcli`，持久）→ systemd-resolved（`resolvectl`，重開機後失效）→ 直接改 `/etc/resolv.conf`。
//!
//! 保險：背景服務每分鐘對這些位址查健康檢查名稱，連續 3 次都查不到就自動還原（不會因為防護 DNS 掛掉而斷網）。
//! 設定存在 `<設定目錄>/dns/use-hub.json`。

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::store;
use crate::util::cmd::{CmdRunner, CmdSpec};

pub const STATE_FILE: &str = "dns/use-hub.json";
/// Hub 下發的防護 DNS 資訊（watch 定期更新；`dns.not_protected` 與 `dns use-hub` 用）。
pub const HUB_FILE: &str = "dns/hub-protect.json";
/// 防護 DNS 一定回答（NOERROR）的名稱；`.invalid` 不會被公共 DNS 解析，用來確認問到的是自己的伺服器。
pub const HEALTH_NAME: &str = "healthcheck.asm-dns.invalid";
/// 連續幾次查不到就自動還原。
pub const RESTORE_AFTER: u32 = 3;

/// 一個介面／網路服務／連線原本的 DNS。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Original {
    /// Windows：介面索引；macOS：網路服務名稱；nmcli：連線 UUID；resolvectl：介面名稱；resolv.conf：檔案路徑。
    pub target: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// 手動設定的 IPv4／IPv6 DNS（空＝自動取得）。
    #[serde(default)]
    pub v4: Vec<String>,
    #[serde(default)]
    pub v6: Vec<String>,
    /// nmcli：原本的 ignore-auto-dns；resolv.conf：原本的完整內容。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseHubState {
    pub servers: Vec<IpAddr>,
    pub applied_at: DateTime<Utc>,
    /// windows／networksetup／nmcli／resolvectl／resolv.conf
    pub method: String,
    pub original: Vec<Original>,
    #[serde(default)]
    pub failures: u32,
}

impl UseHubState {
    pub fn load(config_dir: &Path) -> Option<UseHubState> {
        let text = std::fs::read_to_string(config_dir.join(STATE_FILE)).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        store::ensure_dir(&config_dir.join("dns"))?;
        store::write_json_in(config_dir, STATE_FILE, self)
    }
}

/// Hub 的防護 DNS 資訊（`GET /api/v1/dns/config` 的一部分）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HubProtect {
    pub enabled: bool,
    pub resolver_ips: Vec<IpAddr>,
    /// Hub「防護 DNS」的自訂封鎖（全公司的黑名單）。
    pub block: Vec<String>,
    /// Hub「防護 DNS」的白名單（永遠不擋、不告警）。
    pub allow: Vec<String>,
    pub fetched_at: Option<DateTime<Utc>>,
}

impl HubProtect {
    pub fn load(config_dir: &Path) -> Option<HubProtect> {
        let text = std::fs::read_to_string(config_dir.join(HUB_FILE)).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        store::ensure_dir(&config_dir.join("dns"))?;
        store::write_json_in(config_dir, HUB_FILE, self)
    }

    /// 從 Hub 設定的 JSON 取出需要的欄位。
    pub fn from_config(v: &serde_json::Value) -> HubProtect {
        HubProtect {
            enabled: v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false),
            resolver_ips: v
                .get("resolver_ips")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str()?.parse().ok()).collect())
                .unwrap_or_default(),
            block: v
                .get("block")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .take(10_000)
                        .collect()
                })
                .unwrap_or_default(),
            allow: v
                .get("allow")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .take(10_000)
                        .collect()
                })
                .unwrap_or_default(),
            fetched_at: Some(Utc::now()),
        }
    }
}

/// 對 `server:53` 查健康檢查名稱，有 NOERROR 回答就算活著。
pub async fn probe(server: IpAddr) -> bool {
    probe_addr(SocketAddr::new(server, probe_port())).await
}

/// 探測用的 port（正式一律 53；測試改成確定沒人聽的 port，不受這台有沒有在跑 DNS 影響）。
static PROBE_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(53);

fn probe_port() -> u16 {
    PROBE_PORT.load(std::sync::atomic::Ordering::Relaxed)
}

/// 用 connected UDP 送：沒人聽時（ICMP 不可達）馬上失敗，不必等逾時。
async fn probe_addr(target: SocketAddr) -> bool {
    let server = target.ip();
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else {
        return false;
    };
    if sock.connect(target).await.is_err() {
        return false;
    }
    let id: u16 = rand_id();
    let mut q = vec![(id >> 8) as u8, id as u8, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in HEALTH_NAME.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    if sock.send(&q).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => n >= 12 && buf[0..2] == q[0..2] && buf[3] & 0x0F == 0,
        _ => false,
    }
}

fn rand_id() -> u16 {
    let b = uuid::Uuid::new_v4().into_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// 至少一個位址活著。
pub async fn any_alive(servers: &[IpAddr]) -> bool {
    for s in servers {
        if probe(*s).await {
            return true;
        }
    }
    false
}

/// 這台用的是哪一種方式（依偵測到的網路管理程式）。
pub async fn detect_method(r: &dyn CmdRunner) -> &'static str {
    if cfg!(windows) {
        return "windows";
    }
    if cfg!(target_os = "macos") {
        return "networksetup";
    }
    let nm = r
        .run(&CmdSpec::new("nmcli", &["-t", "-f", "RUNNING", "general"]).timeout(5_000))
        .await;
    if nm.is_ok_and(|o| o.ok() && o.stdout.trim() == "running") {
        return "nmcli";
    }
    let rs = r.run(&CmdSpec::new("resolvectl", &["status"]).timeout(5_000)).await;
    if rs.is_ok_and(|o| o.ok()) {
        return "resolvectl";
    }
    "resolv.conf"
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', ';'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn v4v6(servers: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    (
        servers.iter().filter(|i| i.is_ipv4()).map(|i| i.to_string()).collect(),
        servers.iter().filter(|i| i.is_ipv6()).map(|i| i.to_string()).collect(),
    )
}

fn ps_list(v: &[String]) -> String {
    v.iter()
        .map(|s| format!("'{}'", s.replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------- Windows ----------

/// 啟用中、而且有 DNS 用戶端設定的網卡（有些虛擬網卡是 Up 但沒有 DNS 設定，改它會失敗）。
pub const WIN_CAPTURE: &str = r#"$ErrorActionPreference='Stop'
$dns = @(Get-DnsClient | ForEach-Object { $_.InterfaceIndex })
$out = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $dns -contains $_.ifIndex } | ForEach-Object {
  $g = $_.InterfaceGuid
  $v4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  $v6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$g" -Name NameServer -ErrorAction SilentlyContinue).NameServer
  [pscustomobject]@{ index = [string]$_.ifIndex; alias = $_.Name; v4 = [string]$v4; v6 = [string]$v6 }
})
ConvertTo-Json -InputObject $out -Compress"#;

#[derive(Deserialize)]
struct WinIf {
    index: String,
    alias: String,
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

pub fn parse_win_capture(json: &str) -> Vec<Original> {
    let v: Vec<WinIf> = serde_json::from_str(json.trim()).unwrap_or_default();
    v.into_iter()
        .map(|i| Original {
            target: i.index,
            label: i.alias,
            v4: split_list(&i.v4),
            v6: split_list(&i.v6),
            extra: None,
        })
        .collect()
}

pub fn win_apply_script(orig: &[Original], servers: &[IpAddr]) -> String {
    let list = ps_list(&servers.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let mut s = String::from("$ErrorActionPreference='Stop'\n");
    for o in orig {
        s.push_str(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @({list})\n",
            o.target.parse::<u32>().unwrap_or(0)
        ));
    }
    s.push_str("Clear-DnsClientCache\n");
    s
}

pub fn win_restore_script(orig: &[Original]) -> String {
    let mut s = String::from("$ErrorActionPreference='Continue'\n");
    for o in orig {
        let idx = o.target.parse::<u32>().unwrap_or(0);
        // 先回到自動取得，原本有手動設定的再設回去（IPv4／IPv6 各自保留原狀）
        s.push_str(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses\n"
        ));
        let statics: Vec<String> = o.v4.iter().chain(o.v6.iter()).cloned().collect();
        if !statics.is_empty() {
            s.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({})\n",
                ps_list(&statics)
            ));
        }
    }
    s.push_str("Clear-DnsClientCache\n");
    s
}

// ---------- macOS ----------

pub fn parse_mac_services(out: &str) -> Vec<String> {
    out.lines()
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

pub fn parse_mac_dns(out: &str) -> Vec<String> {
    if out.contains("aren't any DNS Servers") {
        return Vec::new();
    }
    out.lines()
        .map(str::trim)
        .filter(|l| l.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

// ---------- Linux：nmcli ----------

/// `nmcli -t -f UUID,TYPE,DEVICE,NAME connection show --active` → (uuid, device, name)；略過 loopback、橋接、容器網卡。
pub fn parse_nm_active(out: &str) -> Vec<(String, String, String)> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.splitn(4, ':');
            let (uuid, ty, dev, name) = (p.next()?, p.next()?, p.next()?, p.next().unwrap_or(""));
            let skip = ty.contains("loopback")
                || ty == "bridge"
                || dev.is_empty()
                || dev.starts_with("docker")
                || dev.starts_with("veth");
            (!skip).then(|| (uuid.to_string(), dev.to_string(), name.replace("\\:", ":")))
        })
        .collect()
}

// ---------- Linux：resolv.conf ----------

pub fn rewrite_resolv_conf(orig: &str, servers: &[IpAddr]) -> String {
    let mut out = String::from("# ai-security-monitor dns use-hub（dns restore 會還原）\n");
    for s in servers {
        out.push_str(&format!("nameserver {s}\n"));
    }
    for l in orig.lines() {
        let t = l.trim_start();
        if t.starts_with("search") || t.starts_with("domain") || t.starts_with("options") {
            out.push_str(l);
            out.push('\n');
        }
    }
    out
}

fn ensure_ok(o: &crate::util::cmd::CmdOutput, what: &str) -> AppResult<()> {
    if o.ok() {
        return Ok(());
    }
    if o.permission_denied() {
        return Err(AppError::Elevation(tf!("{what} 需要系統管理員權限", what = what)));
    }
    Err(AppError::External(tf!(
        "{what} 失敗：{err}",
        what = what,
        err = o.stderr.trim().lines().last().unwrap_or("").to_string()
    )))
}

/// 記下目前的設定並改成 `servers`；回傳要存檔的狀態。改到一半失敗時，先把已經改過的改回去再回報錯誤。
pub async fn apply(r: &dyn CmdRunner, servers: &[IpAddr]) -> AppResult<UseHubState> {
    let method = detect_method(r).await;
    let mut st = UseHubState {
        servers: servers.to_vec(),
        applied_at: Utc::now(),
        method: method.to_string(),
        original: Vec::new(),
        failures: 0,
    };
    match apply_inner(r, servers, method, &mut st.original).await {
        Ok(()) => Ok(st),
        Err(e) => {
            if !st.original.is_empty() {
                let _ = restore(r, &st).await;
            }
            Err(e)
        }
    }
}

/// 每個目標都先記下原本的設定（`original`）再改，失敗時呼叫端照 `original` 改回。
async fn apply_inner(
    r: &dyn CmdRunner,
    servers: &[IpAddr],
    method: &str,
    original: &mut Vec<Original>,
) -> AppResult<()> {
    let (v4, v6) = v4v6(servers);
    match method {
        "windows" => {
            let o = r.run(&crate::util::cmd::powershell(WIN_CAPTURE)).await?;
            ensure_ok(&o, "Get-NetAdapter")?;
            *original = parse_win_capture(&o.stdout);
            if original.is_empty() {
                return Err(AppError::External(t!("找不到啟用中的網路卡").into()));
            }
            let o = r
                .run(&crate::util::cmd::powershell(&win_apply_script(original, servers)))
                .await?;
            ensure_ok(&o, "Set-DnsClientServerAddress")?;
        }
        "networksetup" => {
            let o = r
                .run(&CmdSpec::new("networksetup", &["-listallnetworkservices"]))
                .await?;
            ensure_ok(&o, "networksetup")?;
            for svc in parse_mac_services(&o.stdout) {
                let cur = r.run(&CmdSpec::new("networksetup", &["-getdnsservers", &svc])).await?;
                let prev = parse_mac_dns(&cur.stdout);
                original.push(Original {
                    target: svc.clone(),
                    label: svc.clone(),
                    v4: prev.iter().filter(|s| s.contains('.')).cloned().collect(),
                    v6: prev.iter().filter(|s| s.contains(':')).cloned().collect(),
                    extra: None,
                });
                let mut args = vec!["-setdnsservers".to_string(), svc];
                args.extend(servers.iter().map(|s| s.to_string()));
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let o = r.run(&CmdSpec::new("networksetup", &a)).await?;
                ensure_ok(&o, "networksetup -setdnsservers")?;
            }
            let _ = r.run(&CmdSpec::new("dscacheutil", &["-flushcache"])).await;
            let _ = r.run(&CmdSpec::new("killall", &["-HUP", "mDNSResponder"])).await;
        }
        "nmcli" => {
            let o = r
                .run(&CmdSpec::new(
                    "nmcli",
                    &["-t", "-f", "UUID,TYPE,DEVICE,NAME", "connection", "show", "--active"],
                ))
                .await?;
            ensure_ok(&o, "nmcli")?;
            for (uuid, dev, name) in parse_nm_active(&o.stdout) {
                let cur = r
                    .run(&CmdSpec::new(
                        "nmcli",
                        &[
                            "-g",
                            "ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns",
                            "connection",
                            "show",
                            &uuid,
                        ],
                    ))
                    .await?;
                let lines: Vec<&str> = cur.stdout.lines().collect();
                let get = |i: usize| lines.get(i).map(|s| s.trim().to_string()).unwrap_or_default();
                original.push(Original {
                    target: uuid.clone(),
                    label: format!("{name} ({dev})"),
                    v4: split_list(&get(0)),
                    v6: split_list(&get(2)),
                    extra: Some(format!("{}|{}", get(1), get(3))),
                });
                let mut args = vec![
                    "connection".to_string(),
                    "modify".into(),
                    uuid.clone(),
                    "ipv4.dns".into(),
                    v4.join(" "),
                    "ipv4.ignore-auto-dns".into(),
                    if v4.is_empty() { "no".into() } else { "yes".into() },
                ];
                if !v6.is_empty() {
                    args.extend([
                        "ipv6.dns".to_string(),
                        v6.join(" "),
                        "ipv6.ignore-auto-dns".into(),
                        "yes".into(),
                    ]);
                }
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let o = r.run(&CmdSpec::new("nmcli", &a)).await?;
                ensure_ok(&o, "nmcli connection modify")?;
                let _ = r.run(&CmdSpec::new("nmcli", &["device", "reapply", &dev])).await;
            }
        }
        "resolvectl" => {
            let o = r.run(&CmdSpec::new("ip", &["-o", "route", "show", "default"])).await?;
            let mut links: Vec<String> = o
                .stdout
                .lines()
                .filter_map(|l| {
                    let w: Vec<&str> = l.split_whitespace().collect();
                    w.iter()
                        .position(|x| *x == "dev")
                        .and_then(|i| w.get(i + 1))
                        .map(|s| s.to_string())
                })
                .collect();
            links.sort();
            links.dedup();
            if links.is_empty() {
                return Err(AppError::External(t!("找不到有預設路由的網路介面").into()));
            }
            for link in links {
                let cur = r.run(&CmdSpec::new("resolvectl", &["dns", &link])).await?;
                // 「Link 2 (eth0): 10.0.0.53 fe80::1%eth0」：冒號後面才是位址（IPv6 本身也有冒號）
                let prev: Vec<String> = cur
                    .stdout
                    .split_once("): ")
                    .map(|(_, r)| split_list(r))
                    .unwrap_or_default();
                original.push(Original {
                    target: link.clone(),
                    label: link.clone(),
                    v4: prev.iter().filter(|s| s.contains('.')).cloned().collect(),
                    v6: prev.iter().filter(|s| s.contains(':')).cloned().collect(),
                    extra: None,
                });
                let mut args = vec!["dns".to_string(), link.clone()];
                args.extend(servers.iter().map(|s| s.to_string()));
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let o = r.run(&CmdSpec::new("resolvectl", &a)).await?;
                ensure_ok(&o, "resolvectl dns")?;
                let _ = r.run(&CmdSpec::new("resolvectl", &["domain", &link, "~."])).await;
            }
            let _ = r.run(&CmdSpec::new("resolvectl", &["flush-caches"])).await;
        }
        _ => {
            let path = "/etc/resolv.conf";
            if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(AppError::Unsupported(
                    t!("/etc/resolv.conf 是由其他程式管理的連結，無法直接修改").into(),
                ));
            }
            let text = std::fs::read_to_string(path)?;
            let new = rewrite_resolv_conf(&text, servers);
            std::fs::write(path, new).map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    AppError::Elevation(t!("修改 /etc/resolv.conf 需要 root").into())
                } else {
                    AppError::from(e)
                }
            })?;
            original.push(Original {
                target: path.into(),
                label: path.into(),
                v4: Vec::new(),
                v6: Vec::new(),
                extra: Some(text),
            });
        }
    }
    Ok(())
}

/// 還原成 `use-hub` 之前的設定。
pub async fn restore(r: &dyn CmdRunner, st: &UseHubState) -> AppResult<()> {
    match st.method.as_str() {
        "windows" => {
            let o = r
                .run(&crate::util::cmd::powershell(&win_restore_script(&st.original)))
                .await?;
            ensure_ok(&o, "Set-DnsClientServerAddress")?;
        }
        "networksetup" => {
            for o in &st.original {
                let mut args = vec!["-setdnsservers".to_string(), o.target.clone()];
                let prev: Vec<String> = o.v4.iter().chain(o.v6.iter()).cloned().collect();
                if prev.is_empty() {
                    args.push("Empty".into());
                } else {
                    args.extend(prev);
                }
                let a: Vec<&str> = args.iter().map(String::as_str).collect();
                let out = r.run(&CmdSpec::new("networksetup", &a)).await?;
                ensure_ok(&out, "networksetup -setdnsservers")?;
            }
            let _ = r.run(&CmdSpec::new("dscacheutil", &["-flushcache"])).await;
            let _ = r.run(&CmdSpec::new("killall", &["-HUP", "mDNSResponder"])).await;
        }
        "nmcli" => {
            for o in &st.original {
                let extra = o.extra.clone().unwrap_or_default();
                let mut it = extra.split('|');
                let (ig4, ig6) = (it.next().unwrap_or("no"), it.next().unwrap_or("no"));
                let v4 = o.v4.join(" ");
                let v6 = o.v6.join(" ");
                let args = [
                    "connection",
                    "modify",
                    o.target.as_str(),
                    "ipv4.dns",
                    v4.as_str(),
                    "ipv4.ignore-auto-dns",
                    if ig4.is_empty() { "no" } else { ig4 },
                    "ipv6.dns",
                    v6.as_str(),
                    "ipv6.ignore-auto-dns",
                    if ig6.is_empty() { "no" } else { ig6 },
                ];
                let out = r.run(&CmdSpec::new("nmcli", &args)).await?;
                ensure_ok(&out, "nmcli connection modify")?;
                let dev = o
                    .label
                    .rsplit('(')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(')')
                    .to_string();
                if !dev.is_empty() {
                    let _ = r.run(&CmdSpec::new("nmcli", &["device", "reapply", &dev])).await;
                }
            }
        }
        "resolvectl" => {
            for o in &st.original {
                let out = r.run(&CmdSpec::new("resolvectl", &["revert", &o.target])).await?;
                ensure_ok(&out, "resolvectl revert")?;
            }
            let _ = r.run(&CmdSpec::new("resolvectl", &["flush-caches"])).await;
        }
        _ => {
            for o in &st.original {
                if let Some(text) = &o.extra {
                    std::fs::write(&o.target, text)?;
                }
            }
        }
    }
    Ok(())
}

/// 自動還原後留下的紀錄（dns 掃描器 24 小時內提醒一次）。
pub const RESTORED_FILE: &str = "dns/use-hub-restored.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Restored {
    pub at: DateTime<Utc>,
    pub servers: Vec<IpAddr>,
}

/// 背景服務每分鐘呼叫：防護 DNS 活著就歸零；連續 [`RESTORE_AFTER`] 次查不到就還原原本的 DNS。回傳要寫進 log 的訊息。
pub async fn watch_tick(config_dir: &Path, r: &dyn CmdRunner, elevated: bool) -> Option<String> {
    let mut st = UseHubState::load(config_dir)?;
    if any_alive(&st.servers).await {
        if st.failures > 0 {
            st.failures = 0;
            let _ = st.save(config_dir);
        }
        return None;
    }
    st.failures += 1;
    let list = st.servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ");
    if st.failures < RESTORE_AFTER {
        let _ = st.save(config_dir);
        return Some(tf!(
            "防護 DNS（{servers}）查不到（第 {n} 次）；連續 {max} 次會自動改回原本的 DNS",
            servers = list,
            n = st.failures,
            max = RESTORE_AFTER
        ));
    }
    if !elevated {
        let _ = st.save(config_dir);
        return Some(t!("防護 DNS 連續查不到，但背景服務沒有系統管理員權限、無法自動還原；請執行 ai-security-monitor dns restore").to_string());
    }
    match restore(r, &st).await {
        Ok(()) => {
            let _ = std::fs::remove_file(config_dir.join(STATE_FILE));
            let _ = store::write_json_in(
                config_dir,
                RESTORED_FILE,
                &Restored {
                    at: Utc::now(),
                    servers: st.servers.clone(),
                },
            );
            Some(tf!(
                "防護 DNS（{servers}）連續 {n} 次查不到，已自動改回原本的 DNS 設定",
                servers = list,
                n = st.failures
            ))
        }
        Err(e) => Some(tf!("自動還原 DNS 失敗：{e}", e = e.message())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cmd::{CmdOutput, FakeRunner};

    #[test]
    fn windows_capture_and_scripts() {
        let orig = parse_win_capture(
            r#"[{"index":"12","alias":"Ethernet","v4":"","v6":""},{"index":"7","alias":"Wi-Fi","v4":"10.0.0.53,1.1.1.1","v6":"fd00::53"}]"#,
        );
        assert_eq!(orig.len(), 2);
        assert_eq!(orig[1].v4, vec!["10.0.0.53", "1.1.1.1"]);
        assert_eq!(orig[1].v6, vec!["fd00::53"]);
        let servers: Vec<IpAddr> = vec!["192.168.1.5".parse().unwrap()];
        let a = win_apply_script(&orig, &servers);
        assert!(a.contains("-InterfaceIndex 12 -ServerAddresses @('192.168.1.5')"));
        let r = win_restore_script(&orig);
        assert!(r.contains("-InterfaceIndex 12 -ResetServerAddresses"));
        assert!(!r.contains("-InterfaceIndex 12 -ServerAddresses"));
        assert!(r.contains("-InterfaceIndex 7 -ServerAddresses @('10.0.0.53','1.1.1.1','fd00::53')"));
        // 單一網卡時 PowerShell 也輸出陣列
        assert_eq!(
            parse_win_capture(r#"[{"index":"3","alias":"Ethernet 2","v4":"","v6":""}]"#).len(),
            1
        );
    }

    #[test]
    fn macos_parsing() {
        let svcs = parse_mac_services(
            "An asterisk (*) denotes that a network service is disabled.\nEthernet\n*Bluetooth PAN\nWi-Fi\n",
        );
        assert_eq!(svcs, vec!["Ethernet", "Wi-Fi"]);
        assert!(parse_mac_dns("There aren't any DNS Servers set on Ethernet.\n").is_empty());
        assert_eq!(
            parse_mac_dns("8.8.8.8\n2001:4860:4860::8888\n"),
            vec!["8.8.8.8", "2001:4860:4860::8888"]
        );
    }

    #[test]
    fn nmcli_active_skips_virtual() {
        let v = parse_nm_active(
            "u1:802-3-ethernet:eth0:Wired connection 1\nu2:loopback:lo:lo\nu3:bridge:docker0:docker0\nu4:802-11-wireless:wlan0:Cafe\\:5G\n",
        );
        assert_eq!(
            v,
            vec![
                ("u1".into(), "eth0".into(), "Wired connection 1".into()),
                ("u4".into(), "wlan0".into(), "Cafe:5G".into())
            ]
        );
    }

    #[test]
    fn resolv_conf_rewrite_keeps_search() {
        let out = rewrite_resolv_conf(
            "nameserver 8.8.8.8\nsearch corp.example\noptions edns0\n",
            &["192.168.1.5".parse().unwrap()],
        );
        assert!(out.contains("nameserver 192.168.1.5\n"));
        assert!(!out.contains("8.8.8.8"));
        assert!(out.contains("search corp.example") && out.contains("options edns0"));
    }

    #[tokio::test]
    async fn nmcli_apply_and_restore_round_trip() {
        if cfg!(windows) || cfg!(target_os = "macos") {
            return;
        }
        let r = FakeRunner::default()
            .on("nmcli -t -f RUNNING general", CmdOutput::success("running\n"))
            .on(
                "nmcli -t -f UUID,TYPE,DEVICE,NAME connection show --active",
                CmdOutput::success("u1:802-3-ethernet:eth0:Wired\n"),
            )
            .on(
                "nmcli -g ipv4.dns,ipv4.ignore-auto-dns,ipv6.dns,ipv6.ignore-auto-dns connection show u1",
                CmdOutput::success("\nno\n\nno\n"),
            )
            .on("nmcli connection modify", CmdOutput::success(""))
            .on("nmcli device reapply", CmdOutput::success(""));
        let st = apply(&r, &["192.168.1.5".parse().unwrap()]).await.unwrap();
        assert_eq!(st.method, "nmcli");
        assert_eq!(st.original[0].extra.as_deref(), Some("no|no"));
        restore(&r, &st).await.unwrap();
        let calls: Vec<String> = r.calls().iter().map(|c| c.match_key()).collect();
        assert!(calls
            .iter()
            .any(|c| c.contains("ipv4.dns 192.168.1.5 ipv4.ignore-auto-dns yes")));
        assert!(calls.iter().any(|c| c.ends_with("ipv6.dns  ipv6.ignore-auto-dns no")));
    }

    #[tokio::test]
    async fn partial_failure_records_what_was_changed() {
        // 第二個網路服務改失敗：第一個已經改了，原設定都要記下來，回滾才改得回去
        let r = FakeRunner::default()
            .on(
                "networksetup -listallnetworkservices",
                CmdOutput::success(
                    "An asterisk (*) denotes that a network service is disabled.
Ethernet
Wi-Fi
",
                ),
            )
            .on(
                "networksetup -getdnsservers Ethernet",
                CmdOutput::success(
                    "There aren't any DNS Servers set on Ethernet.
",
                ),
            )
            .on(
                "networksetup -getdnsservers Wi-Fi",
                CmdOutput::success(
                    "10.0.0.53
",
                ),
            )
            .on(
                "networksetup -setdnsservers Wi-Fi 192.168.1.5",
                CmdOutput::failure(4, "** Error: The parameters were not valid."),
            )
            .on("networksetup -setdnsservers", CmdOutput::success(""))
            .on("dscacheutil", CmdOutput::success(""))
            .on("killall", CmdOutput::success(""));
        let mut orig = Vec::new();
        let err = apply_inner(&r, &["192.168.1.5".parse().unwrap()], "networksetup", &mut orig).await;
        assert!(err.is_err());
        assert_eq!(orig.len(), 2);
        assert_eq!(orig[1].v4, vec!["10.0.0.53"]);
        let st = UseHubState {
            servers: vec!["192.168.1.5".parse().unwrap()],
            applied_at: Utc::now(),
            method: "networksetup".into(),
            original: orig,
            failures: 0,
        };
        restore(&r, &st).await.unwrap_or(());
        let calls: Vec<String> = r.calls().iter().map(|c| c.match_key()).collect();
        assert!(
            calls.iter().any(|c| c == "networksetup -setdnsservers Ethernet Empty"),
            "{calls:?}"
        );
    }

    #[test]
    fn hub_protect_from_config() {
        let p = HubProtect::from_config(
            &serde_json::json!({ "enabled": true, "resolver_ips": ["192.168.1.5", "bad", "fd00::5"] }),
        );
        assert!(p.enabled);
        assert_eq!(p.resolver_ips.len(), 2);
    }

    /// 一個確定沒人在聽的本機 UDP port（綁了再放掉）。
    fn closed_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[tokio::test]
    async fn watch_tick_restores_after_three_misses() {
        PROBE_PORT.store(closed_port(), std::sync::atomic::Ordering::Relaxed);
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("resolv.conf");
        std::fs::write(
            &conf,
            "# changed by use-hub
nameserver 127.0.0.1
",
        )
        .unwrap();
        UseHubState {
            servers: vec!["127.0.0.1".parse().unwrap()],
            applied_at: Utc::now(),
            method: "resolv.conf".into(),
            original: vec![Original {
                target: conf.to_string_lossy().to_string(),
                label: String::new(),
                v4: Vec::new(),
                v6: Vec::new(),
                extra: Some(
                    "nameserver 192.0.2.53
"
                    .into(),
                ),
            }],
            failures: 0,
        }
        .save(dir.path())
        .unwrap();
        let r = FakeRunner::default();
        for n in 1..RESTORE_AFTER {
            let msg = watch_tick(dir.path(), &r, true).await.unwrap();
            assert!(
                msg.contains(&format!("（第 {n} 次）")) || msg.contains(&format!("(attempt {n})")),
                "{msg}"
            );
            assert_eq!(UseHubState::load(dir.path()).unwrap().failures, n);
        }
        // 沒有系統管理員權限：不還原、只提醒
        let mut st = UseHubState::load(dir.path()).unwrap();
        st.failures = RESTORE_AFTER - 1;
        st.save(dir.path()).unwrap();
        watch_tick(dir.path(), &r, false).await.unwrap();
        assert!(UseHubState::load(dir.path()).is_some());
        // 有權限：第 3 次改回原本的設定、移除狀態、留下紀錄
        let mut st = UseHubState::load(dir.path()).unwrap();
        st.failures = RESTORE_AFTER - 1;
        st.save(dir.path()).unwrap();
        watch_tick(dir.path(), &r, true).await.unwrap();
        assert!(UseHubState::load(dir.path()).is_none());
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "nameserver 192.0.2.53
"
        );
        assert!(dir.path().join(RESTORED_FILE).exists());
        // 沒有 use-hub 狀態：什麼都不做
        assert!(watch_tick(dir.path(), &r, true).await.is_none());
    }

    #[tokio::test]
    async fn probe_needs_our_health_answer() {
        // 沒人聽的 port：馬上失敗
        assert!(!probe_addr(SocketAddr::new("127.0.0.1".parse().unwrap(), closed_port())).await);
        // 有回答但不是 NOERROR（一般 DNS 對 .invalid 回 NXDOMAIN）：不算
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = srv.recv_from(&mut buf) {
                buf[2] = 0x81;
                buf[3] = 0x83; // NXDOMAIN
                let _ = srv.send_to(&buf[..n], from);
            }
        });
        assert!(!probe_addr(addr).await);
    }
}
