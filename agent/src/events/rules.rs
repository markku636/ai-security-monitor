//! 規則：`NormEvent` → 當機紀錄（`CrashRecord`）與資安事件（`SecurityHit`）。

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::Duration;

use super::catalog;
use super::model::{CrashRecord, NormEvent, SecurityHit};
use crate::intel::IntelDb;
use crate::model::finding::Severity;
use crate::traffic::summary::IntelRef;
use crate::util::net::classify;

fn src(e: &NormEvent) -> String {
    if e.source == "journal" {
        format!("journal:{}", e.channel)
    } else {
        format!("{}/{}#{}", e.channel, e.provider, e.event_id)
    }
}

fn with_bugcheck(mut c: CrashRecord, code: u32) -> CrashRecord {
    c.code = Some(catalog::code_hex(code));
    if let Some(b) = catalog::lookup_bugcheck(code) {
        let (causes, fix) = catalog::bugcheck_text(&b);
        c.name = Some(b.name);
        c.likely_causes = causes;
        c.remediation = Some(fix);
    }
    c
}

fn prov(e: &NormEvent, p: &str) -> bool {
    e.provider.eq_ignore_ascii_case(p)
}

/// Windows 事件 → 當機紀錄。
fn windows_crash(e: &NormEvent) -> Option<CrashRecord> {
    let id = e.event_id;
    let mk = |kind: &str| CrashRecord::new(kind, e.time, src(e));
    if prov(e, "Microsoft-Windows-Kernel-Power") && id == 41 {
        let code = e.get("BugcheckCode").and_then(catalog::parse_code).unwrap_or(0);
        if code != 0 {
            let mut c = with_bugcheck(mk("bugcheck"), code);
            c.params = (1..=4)
                .filter_map(|i| e.get(&format!("BugcheckParameter{i}")).map(str::to_string))
                .collect();
            return Some(c);
        }
        let mut c = mk("unexpected_shutdown");
        if e.get("PowerButtonTimestamp").map(|v| v != "0").unwrap_or(false) {
            c.name = Some("power button held".into());
        }
        return Some(c);
    }
    if id == 1001 && (prov(e, "Microsoft-Windows-WER-SystemErrorReporting") || prov(e, "BugCheck")) {
        let raw = e.get("param1").or_else(|| e.get("Data0"))?;
        let code = catalog::parse_code(raw)?;
        let mut c = with_bugcheck(mk("bugcheck"), code);
        c.params = raw
            .split_once('(')
            .map(|(_, rest)| {
                rest.trim_end_matches(')')
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        return Some(c);
    }
    if prov(e, "EventLog") && id == 6008 {
        return Some(mk("unexpected_shutdown"));
    }
    if prov(e, "Application Error") && id == 1000 {
        let mut c = mk("app_crash");
        c.process = e.get("AppName").or_else(|| e.get("Data0")).map(str::to_string);
        c.name = c.process.clone();
        c.module = e.get("ModuleName").or_else(|| e.get("Data3")).map(str::to_string);
        c.code = e.get("ExceptionCode").or_else(|| e.get("Data6")).map(|x| {
            if x.starts_with("0x") {
                x.to_string()
            } else {
                format!("0x{x}")
            }
        });
        return Some(c);
    }
    if prov(e, "Application Hang") && id == 1002 {
        let mut c = mk("app_hang");
        c.process = e.get("AppName").or_else(|| e.get("Data0")).map(str::to_string);
        c.name = c.process.clone();
        return Some(c);
    }
    if prov(e, "Service Control Manager") && matches!(id, 7000 | 7001 | 7009 | 7011 | 7022 | 7023 | 7024 | 7031 | 7034)
    {
        let mut c = mk("service_fail");
        // 7009／7011 的 param1 是逾時毫秒數，服務名稱在 param2
        let (k, d) = if matches!(id, 7009 | 7011) {
            ("param2", "Data1")
        } else {
            ("param1", "Data0")
        };
        c.name = e.get(k).or_else(|| e.get(d)).map(str::to_string);
        c.code = Some(id.to_string());
        return Some(c);
    }
    let disk = ["disk", "Ntfs", "storahci", "stornvme", "iaStorA", "iaStorAC", "volmgr"];
    if disk.iter().any(|p| prov(e, p)) && matches!(id, 7 | 11 | 15 | 51 | 55 | 98 | 129 | 153 | 157) {
        let mut c = mk("disk_error");
        c.name = Some(format!("{} #{id}", e.provider));
        c.module = e.get("DeviceName").or_else(|| e.get("Data0")).map(str::to_string);
        return Some(c);
    }
    if prov(e, "Microsoft-Windows-WHEA-Logger") {
        let mut c = mk("whea_hardware");
        c.code = Some(id.to_string());
        c.name = e.get("ErrorSource").or_else(|| e.get("ErrorType")).map(str::to_string);
        return Some(c);
    }
    if prov(e, "Microsoft-Windows-WindowsUpdateClient") && id == 20 {
        let mut c = mk("update_failure");
        c.name = e.get("updateTitle").map(str::to_string);
        c.code = e.get("errorCode").map(str::to_string);
        return Some(c);
    }
    if prov(e, "Display") && id == 4101 {
        let mut c = mk("gpu_reset");
        c.module = e.get("Data0").map(str::to_string);
        return Some(c);
    }
    if prov(e, "Microsoft-Windows-Resource-Exhaustion-Detector") && id == 2004 {
        return Some(mk("low_memory"));
    }
    None
}

/// journal 訊息 → 當機紀錄。
fn journal_crash(e: &NormEvent) -> Option<CrashRecord> {
    let msg = e.get("MESSAGE")?;
    let mk = |kind: &str| CrashRecord::new(kind, e.time, src(e));
    if let Some(rest) = msg.split("Killed process ").nth(1) {
        if msg.contains("Out of memory") || msg.contains("oom-kill") || msg.contains("oom_reaper") {
            let mut c = mk("oom");
            // "4242 (java) total-vm…"
            c.process = rest
                .split_once('(')
                .and_then(|(_, r)| r.split_once(')'))
                .map(|(n, _)| n.to_string());
            c.name = c.process.clone();
            return Some(c);
        }
    }
    if msg.contains("Kernel panic") {
        let mut c = mk("kernel_panic");
        c.name = Some(crate::util::text::clip(msg, 160));
        return Some(c);
    }
    if msg.starts_with("BUG: ") || msg.contains("Oops:") || msg.contains("general protection fault") {
        let mut c = mk("oops");
        c.name = Some(crate::util::text::clip(msg, 160));
        return Some(c);
    }
    if msg.contains(" segfault at ") {
        let mut c = mk("segfault");
        c.process = msg.split('[').next().map(|p| p.trim().to_string());
        c.name = c.process.clone();
        c.module = msg
            .split(" in ")
            .nth(1)
            .map(|m| m.split('[').next().unwrap_or(m).trim().to_string());
        return Some(c);
    }
    if msg.contains("Failed with result")
        || (msg.contains("Main process exited, code=") && !msg.contains("status=0/SUCCESS"))
    {
        let mut c = mk("service_fail");
        c.name = e
            .get("SYSTEMD_UNIT")
            .or_else(|| e.get("UNIT"))
            .map(str::to_string)
            .or_else(|| Some(e.channel.clone()));
        c.code = Some(crate::util::text::clip(msg, 120));
        return Some(c);
    }
    if msg.contains("I/O error")
        || msg.contains("blk_update_request")
        || msg.contains("EXT4-fs error")
        || (msg.contains("XFS (") && msg.contains("error"))
    {
        let mut c = mk("disk_error");
        c.name = Some(crate::util::text::clip(msg, 160));
        return Some(c);
    }
    if msg.contains("Machine check") || msg.starts_with("mce:") || msg.contains("Hardware Error") {
        let mut c = mk("whea_hardware");
        c.name = Some(crate::util::text::clip(msg, 160));
        return Some(c);
    }
    None
}

pub fn crash_from(e: &NormEvent) -> Option<CrashRecord> {
    match e.source.as_str() {
        "windows" => windows_crash(e),
        "journal" => journal_crash(e),
        _ => None,
    }
}

// ---------------- 資安事件 ----------------

/// 失敗登入爆量門檻：10 分鐘內 ≥ 10 次，或整段期間 ≥ 30 次。
pub const BURST_WINDOW_MIN: i64 = 10;
pub const BURST_IN_WINDOW: usize = 10;
pub const BURST_TOTAL: usize = 30;

fn is_local_ip(s: &str) -> bool {
    match s.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => true,
    }
}

/// sshd 訊息 → (失敗/成功, 使用者, 來源 IP)
fn sshd_auth(msg: &str) -> Option<(bool, String, String)> {
    let ip = msg.split(" from ").nth(1)?.split_whitespace().next()?.to_string();
    if msg.starts_with("Failed password for")
        || msg.starts_with("Invalid user")
        || msg.contains("authentication failure")
    {
        let user = msg
            .trim_start_matches("Failed password for ")
            .trim_start_matches("invalid user ")
            .trim_start_matches("Invalid user ")
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        return Some((false, user, ip));
    }
    if msg.starts_with("Accepted ") {
        let user = msg.split(" for ").nth(1)?.split_whitespace().next()?.to_string();
        return Some((true, user, ip));
    }
    None
}

struct Group {
    times: Vec<chrono::DateTime<chrono::Utc>>,
    users: BTreeMap<String, u32>,
    samples: Vec<NormEvent>,
}

fn intel_for(ip: &str, intel: Option<&IntelDb>) -> Vec<IntelRef> {
    match (intel, ip.parse::<IpAddr>()) {
        (Some(db), Ok(addr)) if classify(addr).is_public() => {
            db.match_ip(addr, None).iter().map(IntelRef::from).collect()
        }
        _ => Vec::new(),
    }
}

fn hit(rule: &str, severity: Severity, e: &NormEvent, detail: String) -> SecurityHit {
    SecurityHit {
        rule: rule.into(),
        severity,
        count: 1,
        first: e.time,
        last: e.time,
        source_ip: None,
        user: None,
        detail,
        intel: Vec::new(),
        samples: vec![e.clone()],
    }
}

/// 把同規則、同對象的命中合併。
fn merge(out: &mut Vec<SecurityHit>, h: SecurityHit) {
    if let Some(x) = out
        .iter_mut()
        .find(|x| x.rule == h.rule && x.source_ip == h.source_ip && x.user == h.user && x.detail == h.detail)
    {
        x.count += h.count;
        x.first = x.first.min(h.first);
        x.last = x.last.max(h.last);
        if x.samples.len() < 3 {
            x.samples.extend(h.samples.into_iter().take(3 - x.samples.len()));
        }
    } else {
        out.push(h);
    }
}

fn suspicious_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [
        "\\temp\\",
        "\\appdata\\",
        "\\users\\public\\",
        "\\programdata\\",
        "powershell",
        "cmd.exe /c",
        "rundll32",
        "mshta",
        "regsvr32",
        "/tmp/",
        "/dev/shm/",
    ]
    .iter()
    .any(|n| l.contains(n))
}

/// 服務執行檔路徑（去掉引號與參數）。
fn service_exe(image: &str) -> String {
    let t = image.trim();
    let exe = if let Some(rest) = t.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        // 沒引號：取到 .exe／.sys 為止（路徑可能含空白）
        let l = t.to_ascii_lowercase();
        match [".exe", ".sys"]
            .iter()
            .filter_map(|x| l.find(x).map(|i| i + x.len()))
            .min()
        {
            Some(end) => &t[..end],
            None => t.split_whitespace().next().unwrap_or(t),
        }
    };
    exe.to_ascii_lowercase()
}

/// 新服務的嚴重度：執行檔在暫存／使用者資料夾或是 script host → 高；在系統或 Program Files → 低；其他 → 中。
fn service_severity(image: &str) -> Severity {
    let exe = service_exe(image);
    // script host 可能藏在參數裡（%COMSPEC% /c powershell …），所以看整串
    let full = image.to_ascii_lowercase();
    let lolbin = [
        "powershell",
        "pwsh",
        "cmd.exe",
        "%comspec%",
        "rundll32",
        "mshta",
        "regsvr32",
        "wscript",
        "cscript",
    ]
    .iter()
    .any(|b| full.contains(b));
    if lolbin || suspicious_path(&exe) {
        return Severity::High;
    }
    let trusted = [
        "\\windows\\",
        "system32\\",
        "\\systemroot\\",
        "%systemroot%",
        "\\program files\\",
        "\\program files (x86)\\",
    ];
    if trusted.iter().any(|t| exe.contains(t)) {
        Severity::Low
    } else {
        Severity::Medium
    }
}

pub fn security_hits(events: &[NormEvent], intel: Option<&IntelDb>) -> Vec<SecurityHit> {
    let mut out: Vec<SecurityHit> = Vec::new();
    let mut failed: BTreeMap<String, Group> = BTreeMap::new();
    for e in events {
        let win = e.source == "windows";
        let ch = e.channel.as_str();
        match (win, ch, e.event_id) {
            (true, "Security", 4625) => {
                let ip = e.get("IpAddress").unwrap_or("").to_string();
                if is_local_ip(&ip) {
                    continue;
                }
                let g = failed.entry(ip).or_insert(Group {
                    times: Vec::new(),
                    users: BTreeMap::new(),
                    samples: Vec::new(),
                });
                g.times.push(e.time);
                *g.users
                    .entry(e.get("TargetUserName").unwrap_or("?").to_string())
                    .or_default() += 1;
                if g.samples.len() < 3 {
                    g.samples.push(e.clone());
                }
            }
            (true, "Security", 4624) => {
                // 只看遠端桌面（10）與網路（3）登入、且來源是公網
                let lt = e.get("LogonType").unwrap_or("");
                let ip = e.get("IpAddress").unwrap_or("");
                let public = ip.parse::<IpAddr>().map(|a| classify(a).is_public()).unwrap_or(false);
                if (lt == "10" || lt == "3") && public {
                    let mut h = hit(
                        "remote_logon",
                        Severity::Medium,
                        e,
                        format!("{} logon type {lt}", if lt == "10" { "RDP" } else { "network" }),
                    );
                    h.source_ip = Some(ip.to_string());
                    h.user = e.get("TargetUserName").map(str::to_string);
                    h.intel = intel_for(ip, intel);
                    if !h.intel.is_empty() {
                        h.severity = Severity::Critical;
                    }
                    merge(&mut out, h);
                }
            }
            (true, "Security", 4720) => {
                let mut h = hit("user_created", Severity::Medium, e, String::new());
                h.user = e.get("TargetUserName").map(str::to_string);
                merge(&mut out, h);
            }
            (true, "Security", 4722) => {
                let mut h = hit("user_enabled", Severity::Low, e, String::new());
                h.user = e.get("TargetUserName").map(str::to_string);
                merge(&mut out, h);
            }
            (true, "Security", 4728 | 4732 | 4756) => {
                let group = e.get("TargetUserName").unwrap_or("").to_string();
                let sid = e.get("TargetSid").unwrap_or("");
                let admin = sid == "S-1-5-32-544"
                    || sid.ends_with("-512")
                    || sid.ends_with("-519")
                    || group.to_ascii_lowercase().contains("admin");
                let mut h = hit(
                    if admin {
                        "admin_member_added"
                    } else {
                        "group_member_added"
                    },
                    if admin { Severity::High } else { Severity::Low },
                    e,
                    group,
                );
                h.user = e.get("MemberName").or_else(|| e.get("MemberSid")).map(str::to_string);
                merge(&mut out, h);
            }
            (true, "Security", 4698) => {
                let task = e.get("TaskName").unwrap_or("").to_string();
                let content = e.get("TaskContent").unwrap_or("");
                let sev = if suspicious_path(content) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let mut h = hit("task_created", sev, e, task);
                h.user = e.get("SubjectUserName").map(str::to_string);
                merge(&mut out, h);
            }
            (true, "Security", 1102) => {
                let mut h = hit("audit_log_cleared", Severity::High, e, String::new());
                h.user = e.get("SubjectUserName").map(str::to_string);
                merge(&mut out, h);
            }
            (true, "System", 104) => {
                let mut h = hit(
                    "log_cleared",
                    Severity::Medium,
                    e,
                    e.get("Channel").unwrap_or("").to_string(),
                );
                h.user = e.get("SubjectUserName").map(str::to_string);
                merge(&mut out, h);
            }
            (true, "System", 7045) => {
                let path = e.get("ImagePath").unwrap_or("");
                let sev = service_severity(path);
                let name = e.get("ServiceName").unwrap_or("");
                let h = hit(
                    "service_installed",
                    sev,
                    e,
                    format!("{name} → {}", crate::util::text::clip(path, 160)),
                );
                merge(&mut out, h);
            }
            (true, _, 1116 | 1117) if e.provider.contains("Defender") => {
                let threat = e
                    .get("Threat Name")
                    .or_else(|| e.get("ThreatName"))
                    .unwrap_or("")
                    .to_string();
                let mut h = hit("defender_detection", Severity::High, e, threat);
                h.user = e.get("Path").map(|p| crate::util::text::clip(p, 160));
                merge(&mut out, h);
            }
            (true, _, 5001) if e.provider.contains("Defender") => {
                merge(&mut out, hit("defender_disabled", Severity::High, e, String::new()));
            }
            (false, _, _) if e.provider == "sshd" => {
                let Some((ok, user, ip)) = e.get("MESSAGE").and_then(sshd_auth) else {
                    continue;
                };
                if is_local_ip(&ip) {
                    continue;
                }
                if ok {
                    if ip.parse::<IpAddr>().map(|a| classify(a).is_public()).unwrap_or(false) {
                        let mut h = hit("remote_logon", Severity::Low, e, "ssh".into());
                        h.source_ip = Some(ip.clone());
                        h.user = Some(user);
                        h.intel = intel_for(&ip, intel);
                        if !h.intel.is_empty() {
                            h.severity = Severity::Critical;
                        }
                        merge(&mut out, h);
                    }
                } else {
                    let g = failed.entry(ip).or_insert(Group {
                        times: Vec::new(),
                        users: BTreeMap::new(),
                        samples: Vec::new(),
                    });
                    g.times.push(e.time);
                    *g.users.entry(user).or_default() += 1;
                    if g.samples.len() < 3 {
                        g.samples.push(e.clone());
                    }
                }
            }
            (false, _, _) if matches!(e.provider.as_str(), "useradd" | "usermod" | "gpasswd") => {
                let msg = e.get("MESSAGE").unwrap_or("");
                if msg.starts_with("new user") {
                    merge(
                        &mut out,
                        hit("user_created", Severity::Medium, e, crate::util::text::clip(msg, 160)),
                    );
                } else if (msg.contains("to group") || msg.contains("add '"))
                    && ["sudo", "wheel", "admin", "root"].iter().any(|g| msg.contains(g))
                {
                    merge(
                        &mut out,
                        hit(
                            "admin_member_added",
                            Severity::High,
                            e,
                            crate::util::text::clip(msg, 160),
                        ),
                    );
                }
            }
            _ => {}
        }
    }

    // 失敗登入：同來源 10 分鐘內 ≥ 10 次或總數 ≥ 30 次才算爆量
    for (ip, mut g) in failed {
        g.times.sort();
        let total = g.times.len();
        let window = Duration::minutes(BURST_WINDOW_MIN);
        let mut max_in_window = 0usize;
        let mut j = 0usize;
        for i in 0..total {
            while g.times[i] - g.times[j] > window {
                j += 1;
            }
            max_in_window = max_in_window.max(i - j + 1);
        }
        if max_in_window < BURST_IN_WINDOW && total < BURST_TOTAL {
            continue;
        }
        let public = ip.parse::<IpAddr>().map(|a| classify(a).is_public()).unwrap_or(false);
        let intel_refs = intel_for(&ip, intel);
        let top_users: Vec<String> = {
            let mut u: Vec<(String, u32)> = g.users.into_iter().collect();
            u.sort_by_key(|x| std::cmp::Reverse(x.1));
            u.into_iter().take(5).map(|(n, c)| format!("{n}×{c}")).collect()
        };
        out.push(SecurityHit {
            rule: "failed_logon_burst".into(),
            severity: if !intel_refs.is_empty() || public {
                Severity::High
            } else {
                Severity::Medium
            },
            count: total as u32,
            first: g.times[0],
            last: g.times[total - 1],
            source_ip: Some(ip),
            user: None,
            detail: format!(
                "max {max_in_window} in {BURST_WINDOW_MIN} min · users {}",
                top_users.join(", ")
            ),
            intel: intel_refs,
            samples: g.samples,
        });
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.count.cmp(&a.count))
            .then(a.rule.cmp(&b.rule))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::linux;
    use crate::events::xml::{parse_event, samples::event};

    fn win(provider: &str, id: u32, ch: &str, time: &str, data: &[(&str, &str)]) -> NormEvent {
        parse_event(&event(provider, id, 2, time, ch, data), ch).unwrap()
    }

    #[test]
    fn windows_crash_rules() {
        let bsod = crash_from(&win(
            "Microsoft-Windows-Kernel-Power",
            41,
            "System",
            "2026-10-10T03:00:00Z",
            &[("BugcheckCode", "209"), ("BugcheckParameter1", "0x10")],
        ))
        .unwrap();
        assert_eq!(
            (bsod.kind.as_str(), bsod.code.as_deref(), bsod.name.as_deref()),
            ("bugcheck", Some("0x000000D1"), Some("DRIVER_IRQL_NOT_LESS_OR_EQUAL"))
        );
        assert_eq!(bsod.params, vec!["0x10".to_string()]);
        let power = crash_from(&win(
            "Microsoft-Windows-Kernel-Power",
            41,
            "System",
            "2026-10-10T03:00:00Z",
            &[("BugcheckCode", "0"), ("PowerButtonTimestamp", "1337")],
        ))
        .unwrap();
        assert_eq!(
            (power.kind.as_str(), power.name.as_deref()),
            ("unexpected_shutdown", Some("power button held"))
        );
        let wer = crash_from(&win(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "System",
            "2026-10-10T03:05:00Z",
            &[
                (
                    "param1",
                    "0x00000124 (0x0000000000000000, 0xffffa00000000000, 0x0, 0x0)",
                ),
                ("param2", "C:\\Windows\\Minidump\\x.dmp"),
            ],
        ))
        .unwrap();
        assert_eq!(wer.name.as_deref(), Some("WHEA_UNCORRECTABLE_ERROR"));
        assert_eq!(wer.params.len(), 4);
        let app = crash_from(&win(
            "Application Error",
            1000,
            "Application",
            "2026-10-10T01:00:00Z",
            &[
                ("", "game.exe"),
                ("", "1.0"),
                ("", "0"),
                ("", "nvwgf2umx.dll"),
                ("", "31.0"),
                ("", "0"),
                ("", "c0000005"),
            ],
        ))
        .unwrap();
        assert_eq!(
            (app.process.as_deref(), app.module.as_deref(), app.code.as_deref()),
            (Some("game.exe"), Some("nvwgf2umx.dll"), Some("0xc0000005"))
        );
        assert_eq!(
            crash_from(&win(
                "Service Control Manager",
                7031,
                "System",
                "2026-10-10T01:00:00Z",
                &[("param1", "Spooler")]
            ))
            .unwrap()
            .name
            .as_deref(),
            Some("Spooler")
        );
        assert_eq!(
            crash_from(&win("disk", 153, "System", "2026-10-10T01:00:00Z", &[]))
                .unwrap()
                .kind,
            "disk_error"
        );
        assert_eq!(
            crash_from(&win(
                "Microsoft-Windows-WHEA-Logger",
                18,
                "System",
                "2026-10-10T01:00:00Z",
                &[]
            ))
            .unwrap()
            .kind,
            "whea_hardware"
        );
        assert!(crash_from(&win(
            "Microsoft-Windows-Kernel-General",
            12,
            "System",
            "2026-10-10T01:00:00Z",
            &[]
        ))
        .is_none());
    }

    #[test]
    fn journal_crash_rules() {
        let j = |msg: &str| linux::parse_line(&linux::sample(1_760_000_000_000_000, 3, "kernel", None, msg)).unwrap();
        let oom = crash_from(&j("Out of memory: Killed process 4242 (java) total-vm:123kB")).unwrap();
        assert_eq!((oom.kind.as_str(), oom.process.as_deref()), ("oom", Some("java")));
        let seg = crash_from(&j(
            "nginx[1234]: segfault at 0 ip 00007f sp 00007f error 4 in libc.so.6[7f00+1000]",
        ))
        .unwrap();
        assert_eq!(
            (seg.kind.as_str(), seg.process.as_deref(), seg.module.as_deref()),
            ("segfault", Some("nginx"), Some("libc.so.6"))
        );
        assert_eq!(
            crash_from(&j("BUG: kernel NULL pointer dereference, address: 0"))
                .unwrap()
                .kind,
            "oops"
        );
        assert_eq!(
            crash_from(&j("Kernel panic - not syncing: Fatal exception"))
                .unwrap()
                .kind,
            "kernel_panic"
        );
        assert_eq!(
            crash_from(&j("blk_update_request: I/O error, dev sda, sector 123"))
                .unwrap()
                .kind,
            "disk_error"
        );
        let svc = linux::parse_line(&linux::sample(
            1_760_000_000_000_000,
            3,
            "systemd",
            Some("init.scope"),
            "nginx.service: Failed with result 'exit-code'.",
        ))
        .unwrap();
        assert_eq!(crash_from(&svc).unwrap().kind, "service_fail");
        assert!(crash_from(&j("usb 1-1: new high-speed USB device")).is_none());
    }

    #[test]
    fn brute_force_and_admin_changes() {
        let mut ev = Vec::new();
        for i in 0..12 {
            ev.push(win(
                "Microsoft-Windows-Security-Auditing",
                4625,
                "Security",
                &format!("2026-10-10T03:00:{:02}Z", i * 4),
                &[
                    ("IpAddress", "185.199.108.9"),
                    ("TargetUserName", "administrator"),
                    ("LogonType", "10"),
                ],
            ));
        }
        // 散落、沒爆量的內網來源
        for i in 0..3 {
            ev.push(win(
                "Microsoft-Windows-Security-Auditing",
                4625,
                "Security",
                &format!("2026-10-1{i}T03:00:00Z"),
                &[("IpAddress", "192.168.1.5"), ("TargetUserName", "bob")],
            ));
        }
        ev.push(win(
            "Microsoft-Windows-Security-Auditing",
            4625,
            "Security",
            "2026-10-10T04:00:00Z",
            &[("IpAddress", "-")],
        ));
        ev.push(win(
            "Microsoft-Windows-Security-Auditing",
            4732,
            "Security",
            "2026-10-10T05:00:00Z",
            &[
                ("TargetUserName", "Administrators"),
                ("TargetSid", "S-1-5-32-544"),
                ("MemberName", "CN=mallory"),
            ],
        ));
        ev.push(win(
            "Microsoft-Windows-Security-Auditing",
            4624,
            "Security",
            "2026-10-10T05:01:00Z",
            &[
                ("LogonType", "10"),
                ("IpAddress", "185.199.108.9"),
                ("TargetUserName", "administrator"),
            ],
        ));
        ev.push(win(
            "Service Control Manager",
            7045,
            "System",
            "2026-10-10T05:02:00Z",
            &[
                ("ServiceName", "updsvc"),
                ("ImagePath", "C:\\Users\\a\\AppData\\Local\\Temp\\u.exe"),
            ],
        ));
        ev.push(win(
            "Microsoft-Windows-Eventlog",
            1102,
            "Security",
            "2026-10-10T05:03:00Z",
            &[],
        ));
        let hits = security_hits(&ev, None);
        let rules: Vec<&str> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(rules.contains(&"failed_logon_burst"), "{rules:?}");
        assert!(!hits.iter().any(|h| h.source_ip.as_deref() == Some("192.168.1.5")));
        let burst = hits.iter().find(|h| h.rule == "failed_logon_burst").unwrap();
        assert_eq!(
            (burst.count, burst.severity, burst.source_ip.as_deref()),
            (12, Severity::High, Some("185.199.108.9"))
        );
        assert!(burst.detail.contains("administrator×12"));
        assert_eq!(
            hits.iter()
                .find(|h| h.rule == "admin_member_added")
                .unwrap()
                .user
                .as_deref(),
            Some("CN=mallory")
        );
        assert_eq!(
            hits.iter().find(|h| h.rule == "service_installed").unwrap().severity,
            Severity::High
        );
        assert!(rules.contains(&"audit_log_cleared") && rules.contains(&"remote_logon"));
    }

    #[test]
    fn service_install_severity_looks_at_the_executable() {
        assert_eq!(
            service_severity(
                "\"C:\\Program Files (x86)\\cloudflared\\cloudflared.exe\" --config C:\\ProgramData\\x.yml"
            ),
            Severity::Low
        );
        assert_eq!(
            service_severity("C:\\WINDOWS\\system32\\drivers\\IOMap64.sys"),
            Severity::Low
        );
        assert_eq!(
            service_severity("\\SystemRoot\\System32\\DriverStore\\FileRepository\\a.sys"),
            Severity::Low
        );
        assert_eq!(
            service_severity("C:\\Users\\a\\AppData\\Local\\Temp\\u.exe"),
            Severity::High
        );
        assert_eq!(service_severity("%COMSPEC% /c powershell -enc AAAA"), Severity::High);
        assert_eq!(service_severity("D:\\tools\\agent.exe -run"), Severity::Medium);
        assert_eq!(
            service_exe("C:\\Program Files\\My App\\svc.exe -k"),
            "c:\\program files\\my app\\svc.exe"
        );
    }

    #[test]
    fn sshd_brute_force() {
        let mut ev = Vec::new();
        for i in 0..31 {
            let msg = if i % 2 == 0 {
                "Failed password for root from 203.0.113.50 port 51234 ssh2"
            } else {
                "Invalid user admin from 203.0.113.50 port 51235"
            };
            ev.push(
                linux::parse_line(&linux::sample(
                    1_760_000_000_000_000 + i * 3_600_000_000,
                    6,
                    "sshd",
                    Some("ssh.service"),
                    msg,
                ))
                .unwrap(),
            );
        }
        ev.push(
            linux::parse_line(&linux::sample(
                1_760_000_000_000_000,
                6,
                "sshd",
                Some("ssh.service"),
                "Accepted publickey for deploy from 185.199.108.4 port 2222 ssh2: ED25519",
            ))
            .unwrap(),
        );
        let hits = security_hits(&ev, None);
        let burst = hits.iter().find(|h| h.rule == "failed_logon_burst").unwrap();
        assert_eq!(burst.count, 31);
        assert!(
            burst.detail.contains("root×16") && burst.detail.contains("admin×15"),
            "{}",
            burst.detail
        );
        assert_eq!(
            hits.iter().find(|h| h.rule == "remote_logon").unwrap().user.as_deref(),
            Some("deploy")
        );
    }
}
