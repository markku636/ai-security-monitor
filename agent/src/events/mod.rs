//! 事件與當機分析：
//! - Windows：Get-WinEvent（System／Application／Security／Defender）＋ Minidump 檔頭 → 藍屏、非預期關機、App 當機、
//!   服務失敗、磁碟／WHEA 硬體錯誤、更新失敗；資安事件（暴力破解、RDP 公網登入、新增管理員、新服務、排程、稽核清除、Defender）。
//! - Linux：journalctl（OOM、kernel panic／oops、segfault、服務失敗、I/O 錯誤、MCE；sshd 暴力破解、新帳號、加入 sudo 群組）。
//! - macOS：DiagnosticReports（kernel panic、App 當機）。
//!
//! 全部彙整成 `EventsSummary`（給人看、給 hub、給 AI 分析當機原因），掃描時另外產生 findings。

pub mod catalog;
pub mod linux;
pub mod macos;
pub mod minidump;
pub mod model;
pub mod rules;
pub mod windows;
pub mod xml;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;

use crate::error::{AppError, AppResult};
use crate::intel::IntelDb;
use crate::model::finding::{ActionKind, Evidence, Finding, ProposedAction, ScannerId, Severity};
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};
use crate::util::cmd::CmdRunner;
use model::{CrashRecord, EventsSummary, NormEvent, TopSource, MAX_CRASHES, MAX_TOP};

/// 收集到的原始資料（尚未彙整）。
#[derive(Debug, Default)]
pub struct Collected {
    pub platform: String,
    pub events: Vec<NormEvent>,
    /// 不是來自事件記錄的當機（minidump、macOS 報告）
    pub extra_crashes: Vec<CrashRecord>,
    pub needs_admin: Vec<String>,
    pub notes: Vec<String>,
}

pub async fn collect(runner: &dyn CmdRunner, days: u32) -> AppResult<Collected> {
    let since = Utc::now() - Duration::days(days as i64);
    let mut c = Collected {
        platform: std::env::consts::OS.into(),
        ..Default::default()
    };
    if cfg!(windows) {
        let (events, mut denied) = windows::query(runner, days).await?;
        c.events = events;
        // 非管理員讀 Security 記錄時 Get-WinEvent 只回「找不到事件」，不會報拒絕存取，所以直接看權限。
        if !crate::elevate::is_elevated() && !denied.iter().any(|d| d == "Security") {
            denied.insert(0, "Security".into());
        }
        for d in denied {
            c.needs_admin.push(if d == "Security" {
                t!("Security 事件記錄（失敗登入、帳號與群組變更、稽核清除）").to_string()
            } else {
                d
            });
        }
        let (dumps, dump_denied) = tokio::task::spawn_blocking(move || windows::scan_minidumps(since))
            .await
            .map_err(|e| AppError::Events(e.to_string()))?;
        c.extra_crashes = dumps;
        if dump_denied {
            c.needs_admin.push(t!("Minidump 資料夾（藍屏 dump 檔）").to_string());
        }
    } else if cfg!(target_os = "macos") {
        c.extra_crashes = tokio::task::spawn_blocking(move || macos::scan(since))
            .await
            .map_err(|e| AppError::Events(e.to_string()))?;
        c.notes
            .push("macOS: DiagnosticReports only (kernel panics, app crashes); unified log not analyzed yet".into());
    } else {
        let (events, limited) = linux::query(runner, days).await?;
        c.events = events;
        if limited {
            c.needs_admin
                .push(t!("systemd journal（加入 systemd-journal 群組或用 sudo 執行）").to_string());
        }
    }
    Ok(c)
}

/// 同一次藍屏常同時出現在 Kernel-Power 41、WER 1001 與 minidump：同代碼、相差 15 分鐘內只留一筆（保留資訊最多的）。
fn dedupe_crashes(mut v: Vec<CrashRecord>) -> Vec<CrashRecord> {
    v.sort_by_key(|c| std::cmp::Reverse(c.time));
    let mut out: Vec<CrashRecord> = Vec::new();
    for c in v {
        let near = |o: &CrashRecord| (o.time - c.time).num_minutes().abs() <= 15;
        let same = out.iter_mut().find(|o| {
            near(o)
                && ((o.kind == "bugcheck" && c.kind == "bugcheck" && o.code == c.code)
                    || (o.kind == "unexpected_shutdown" && c.kind == "unexpected_shutdown")
                    || (o.kind == "bugcheck" && c.kind == "unexpected_shutdown"))
        });
        match same {
            Some(o) => {
                if o.params.is_empty() {
                    o.params = c.params.clone();
                }
                if !o.source.contains(&c.source) && o.source.len() < 300 {
                    o.source = format!("{} + {}", o.source, c.source);
                }
            }
            None => {
                // 已有同時段的藍屏，就不必另記一筆非預期關機
                if c.kind == "unexpected_shutdown" && out.iter().any(|o| o.kind == "bugcheck" && near(o)) {
                    continue;
                }
                out.push(c);
            }
        }
    }
    out
}

pub fn summarize(c: Collected, days: u32, intel: Option<&IntelDb>) -> EventsSummary {
    let mut s = EventsSummary {
        platform: c.platform,
        days,
        events_read: c.events.len() as u64,
        needs_admin: c.needs_admin,
        notes: c.notes,
        ..Default::default()
    };
    s.since = c.events.iter().map(|e| e.time).min();
    s.until = c.events.iter().map(|e| e.time).max();
    for e in &c.events {
        *s.counts_by_level.entry(e.level_name().to_string()).or_default() += 1;
    }
    let mut crashes: Vec<CrashRecord> = c.events.iter().filter_map(rules::crash_from).collect();
    crashes.extend(c.extra_crashes);
    let crashes = dedupe_crashes(crashes);
    for cr in &crashes {
        *s.crash_counts.entry(cr.kind.clone()).or_default() += 1;
    }
    s.crashes = crashes.into_iter().take(MAX_CRASHES).collect();
    s.security = rules::security_hits(&c.events, intel);
    s.security.truncate(30);

    let mut top: BTreeMap<(String, u32), TopSource> = BTreeMap::new();
    for e in c.events.iter().filter(|e| e.level <= 2) {
        let t = top
            .entry((e.provider.clone(), e.event_id))
            .or_insert_with(|| TopSource {
                provider: e.provider.clone(),
                event_id: e.event_id,
                level: e.level_name().into(),
                count: 0,
                sample: e.message.clone(),
            });
        t.count += 1;
    }
    let mut top: Vec<TopSource> = top.into_values().collect();
    top.sort_by(|a, b| b.count.cmp(&a.count).then(a.provider.cmp(&b.provider)));
    top.truncate(MAX_TOP);
    s.top_error_sources = top;
    s
}

/// 離線分析：.evtx（Windows）、journalctl -o json 輸出、macOS .ips／.panic、kernel .dmp。
pub async fn analyze_file(runner: &dyn CmdRunner, path: &Path, intel: Option<&IntelDb>) -> AppResult<EventsSummary> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut c = Collected {
        platform: "file".into(),
        ..Default::default()
    };
    if name.ends_with(".evtx") {
        if !cfg!(windows) {
            return Err(AppError::Unsupported(
                t!(".evtx 只能在 Windows 上分析（需要 Get-WinEvent）").into(),
            ));
        }
        c.events = windows::query_file(runner, path).await?;
    } else if name.ends_with(".ips") || name.ends_with(".panic") {
        let modified = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|_| Utc::now());
        c.extra_crashes.extend(macos::read_report(path, modified));
    } else if name.ends_with(".dmp") {
        let modified = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|_| Utc::now());
        match minidump::read_header(path)? {
            Some(h) => c.extra_crashes.push(minidump::to_crash(&h, modified, path)),
            None => {
                return Err(AppError::Parse(
                    t!("不是 Windows kernel dump（只支援 Minidump／MEMORY.DMP）").into(),
                ))
            }
        }
    } else {
        let text = std::fs::read_to_string(path)?;
        c.events = linux::parse_lines(&text);
        if c.events.is_empty() {
            return Err(AppError::Parse(
                t!("無法辨識的檔案：支援 .evtx、journalctl -o json 輸出、.ips／.panic、.dmp").into(),
            ));
        }
    }
    let days = match (
        c.events.iter().map(|e| e.time).min(),
        c.events.iter().map(|e| e.time).max(),
    ) {
        (Some(a), Some(b)) => ((b - a).num_days() + 1) as u32,
        _ => 1,
    };
    let mut s = summarize(c, days, intel);
    s.notes.push(format!("source file: {}", path.display()));
    Ok(s)
}

// ---------------- 掃描器 ----------------

pub const SCAN_DAYS: u32 = 7;

fn crash_title(kind: &str, n: u32, days: u32) -> String {
    match kind {
        "bugcheck" => tf!("近 {days} 天藍屏 {n} 次", days = days, n = n),
        "unexpected_shutdown" => tf!("近 {days} 天非預期關機 {n} 次", days = days, n = n),
        "disk_error" => tf!("近 {days} 天磁碟錯誤 {n} 次", days = days, n = n),
        "whea_hardware" => tf!("近 {days} 天硬體錯誤（WHEA／MCE）{n} 次", days = days, n = n),
        "kernel_panic" => tf!("近 {days} 天 kernel panic {n} 次", days = days, n = n),
        "oops" => tf!("近 {days} 天 kernel oops {n} 次", days = days, n = n),
        "oom" => tf!("近 {days} 天記憶體不足強制結束行程 {n} 次", days = days, n = n),
        "low_memory" => tf!("近 {days} 天系統記憶體不足警告 {n} 次", days = days, n = n),
        "gpu_reset" => tf!("近 {days} 天顯示卡驅動重設 {n} 次", days = days, n = n),
        _ => tf!("近 {days} 天 {kind} {n} 次", days = days, kind = kind, n = n),
    }
}

fn crash_evidence(c: &CrashRecord) -> Evidence {
    Evidence::Crash {
        kind: c.kind.clone(),
        time: c.time.to_rfc3339(),
        code: c.code.clone(),
        name: c.name.clone(),
        module: c.module.clone(),
        params: c.params.clone(),
    }
}

/// 摘要 → findings。
pub fn findings_from(s: &EventsSummary) -> Vec<Finding> {
    let mut out = Vec::new();
    // 藍屏：每個代碼一筆
    let mut by_code: BTreeMap<String, Vec<&CrashRecord>> = BTreeMap::new();
    for c in s.crashes.iter().filter(|c| c.kind == "bugcheck") {
        by_code.entry(c.code.clone().unwrap_or_default()).or_default().push(c);
    }
    for (code, list) in &by_code {
        let latest = list[0];
        let name = latest.name.clone().unwrap_or_else(|| code.clone());
        out.push(
            Finding::new(
                ScannerId::Events,
                "events.bugcheck",
                code,
                if list.len() >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                format!(
                    "{}：{name}（{code}）",
                    crash_title("bugcheck", list.len() as u32, s.days)
                ),
                if latest.likely_causes.is_empty() {
                    t!("查無這個代碼的說明；用 ai-security-monitor ai analyze --events 請 AI 協助判讀").to_string()
                } else {
                    latest.likely_causes.join("；")
                },
                crash_evidence(latest),
                latest.remediation.clone().unwrap_or_default(),
            )
            .with_tag("crash"),
        );
    }
    for (kind, sev, min) in [
        ("unexpected_shutdown", Severity::Medium, 2u32),
        ("disk_error", Severity::High, 1),
        ("whea_hardware", Severity::Medium, 1),
        ("kernel_panic", Severity::High, 1),
        ("oops", Severity::High, 1),
        ("oom", Severity::Medium, 1),
        ("low_memory", Severity::Medium, 3),
        ("gpu_reset", Severity::Medium, 3),
    ] {
        let n = s.crash_counts.get(kind).copied().unwrap_or(0);
        if n < min {
            continue;
        }
        let latest = s.crashes.iter().find(|c| c.kind == kind);
        let rec = match kind {
            "disk_error" => t!("立即備份；檢查磁碟 SMART 狀態與連接線，必要時更換磁碟"),
            "whea_hardware" => t!("恢復 BIOS 預設、取消超頻，檢查溫度、記憶體與電源"),
            "unexpected_shutdown" => t!("確認是否斷電或長按電源鍵；若伴隨藍屏請看藍屏項目"),
            "oom" | "low_memory" => t!("找出吃記憶體的行程（見事件），調整服務記憶體上限或增加記憶體"),
            "gpu_reset" => t!("更新或乾淨重灌顯示卡驅動，檢查顯示卡溫度與電源"),
            _ => t!("查看事件詳細內容；可用 ai-security-monitor ai analyze --events 請 AI 協助判讀"),
        };
        out.push(
            Finding::new(
                ScannerId::Events,
                &format!("events.{kind}"),
                kind,
                sev,
                crash_title(kind, n, s.days),
                latest.and_then(|c| c.name.clone()).unwrap_or_default(),
                latest
                    .map(crash_evidence)
                    .unwrap_or(Evidence::Text { detail: kind.into() }),
                rec,
            )
            .with_tag("crash"),
        );
    }
    // 重複當掉的 App／失敗的服務（同名 ≥ 3 次）
    for kind in ["app_crash", "service_fail"] {
        let mut by: BTreeMap<String, Vec<&CrashRecord>> = BTreeMap::new();
        for c in s.crashes.iter().filter(|c| c.kind == kind) {
            by.entry(c.name.clone().unwrap_or_default()).or_default().push(c);
        }
        for (name, list) in by.into_iter().filter(|(n, l)| !n.is_empty() && l.len() >= 3) {
            let title = if kind == "app_crash" {
                tf!(
                    "{name} 近 {days} 天當掉 {n} 次",
                    name = name,
                    days = s.days,
                    n = list.len()
                )
            } else {
                tf!(
                    "服務 {name} 近 {days} 天失敗 {n} 次",
                    name = name,
                    days = s.days,
                    n = list.len()
                )
            };
            out.push(
                Finding::new(
                    ScannerId::Events,
                    &format!("events.{kind}_repeated"),
                    &name,
                    Severity::Low,
                    title,
                    list[0]
                        .module
                        .clone()
                        .map(|m| tf!("出錯模組：{m}", m = m))
                        .unwrap_or_default(),
                    crash_evidence(list[0]),
                    t!("更新或重新安裝該程式；持續發生可用 ai-security-monitor ai analyze --events 請 AI 協助判讀"),
                )
                .with_tag("crash"),
            );
        }
    }
    // 資安事件（低嚴重度的只留在摘要，例如裝在 Program Files 的新服務）
    for h in s.security.iter().filter(|h| h.severity >= Severity::Medium) {
        let key = format!(
            "{}|{}|{}",
            h.rule,
            h.source_ip.clone().unwrap_or_default(),
            h.user.clone().unwrap_or_default()
        );
        let (title, rec) = match h.rule.as_str() {
            "failed_logon_burst" => (
                tf!(
                    "{ip} 嘗試登入失敗 {n} 次（疑似暴力破解）",
                    ip = h.source_ip.clone().unwrap_or_default(),
                    n = h.count
                ),
                t!("封鎖來源 IP；關閉不需要對外的 RDP／SSH，改用 VPN 或限制來源；啟用帳號鎖定原則"),
            ),
            "ntlm_failure_burst" => (
                tf!("NTLM 驗證失敗 {n} 次（{detail}）", n = h.count, detail = h.detail),
                t!("找出該工作站上用舊密碼或錯誤密碼的程式、服務或對應磁碟機；不是的話視為密碼噴灑並調查"),
            ),
            "account_locked" => (
                tf!(
                    "帳號被鎖定：{user}（來源 {detail}）",
                    user = h.user.clone().unwrap_or_default(),
                    detail = h.detail
                ),
                t!("確認是本人打錯密碼還是有人在猜；同時段的登入失敗來源可以一起封鎖"),
            ),
            "remote_logon" => (
                tf!(
                    "從公網 {ip} 遠端登入成功（{user}）",
                    ip = h.source_ip.clone().unwrap_or_default(),
                    user = h.user.clone().unwrap_or_default()
                ),
                t!("確認是否為本人；不是的話立刻改密碼、檢查新帳號與排程，並封鎖來源"),
            ),
            "admin_member_added" => (
                tf!(
                    "有帳號被加入管理員群組：{user}",
                    user = h.user.clone().unwrap_or_default()
                ),
                t!("確認是否為授權的變更；不是的話移除該成員並調查登入紀錄"),
            ),
            "user_created" => (
                tf!(
                    "建立了新帳號：{user}",
                    user = h.user.clone().unwrap_or(h.detail.clone())
                ),
                t!("確認是否為授權的變更"),
            ),
            "service_installed" => (
                tf!("安裝了新服務：{detail}", detail = h.detail),
                t!("確認服務來源；執行檔在暫存或使用者資料夾特別可疑"),
            ),
            "task_created" => (
                tf!("建立了排程工作：{detail}", detail = h.detail),
                t!("確認排程內容與建立者"),
            ),
            "audit_log_cleared" => (
                t!("安全性稽核紀錄被清除").to_string(),
                t!("清除稽核紀錄是入侵後湮滅證據的典型動作：調查同時段的登入與變更"),
            ),
            "log_cleared" => (
                tf!("事件記錄被清除：{detail}", detail = h.detail),
                t!("確認是誰、為何清除"),
            ),
            "defender_detection" => (
                tf!("Defender 偵測到威脅：{detail}", detail = h.detail),
                t!("確認 Defender 已隔離；檢查該檔案的來源與同時段的連線"),
            ),
            "defender_disabled" => (
                t!("Defender 即時保護被關閉").to_string(),
                t!("重新開啟即時保護並確認是誰關閉的"),
            ),
            other => (other.to_string(), ""),
        };
        let sample = h.samples.first();
        let mut f = Finding::new(
            ScannerId::Events,
            &format!("events.{}", h.rule),
            &key,
            h.severity,
            title,
            h.detail.clone(),
            match sample {
                Some(e) => Evidence::Event {
                    event_id: e.event_id,
                    channel: e.channel.clone(),
                    provider: e.provider.clone(),
                    time: e.time.to_rfc3339(),
                    computer: e.computer.clone(),
                    data: json!(e.data),
                },
                None => Evidence::Text {
                    detail: h.detail.clone(),
                },
            },
            rec,
        )
        .with_tag("security");
        if h.rule == "failed_logon_burst" || h.rule == "remote_logon" {
            f = f.with_tag("inbound");
        }
        // 公網來源的暴力破解：建議封鎖
        if let Some(ip) = h.source_ip.as_deref().filter(|_| h.rule == "failed_logon_burst") {
            if ip
                .parse::<std::net::IpAddr>()
                .map(|a| crate::util::net::classify(a).is_public())
                .unwrap_or(false)
            {
                f = f.with_action(ProposedAction {
                    kind: ActionKind::BlockIp,
                    params: json!({ "ip": ip, "direction": "inbound", "reason": "failed-logon-burst" }),
                    requires_elevation: true,
                    destructive: false,
                    reversible: true,
                    description: tf!("以防火牆封鎖 {ip}（連入）", ip = ip),
                });
            }
        }
        out.push(f);
    }
    out
}

pub struct EventsScanner;

#[async_trait]
impl Scanner for EventsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Events
    }

    fn elevation(&self) -> Elevation {
        // Security 記錄與 Minidump 要管理員；沒有也能跑其他部分。
        Elevation::Preferred
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let collected = collect(ctx.runner.as_ref(), SCAN_DAYS).await?;
        // 有公網的暴力破解來源才載入情資（避免每次掃描都多花幾秒）
        let needs_intel = rules::security_hits(&collected.events, None).iter().any(|h| {
            h.source_ip
                .as_deref()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .map(|a| crate::util::net::classify(a).is_public())
                .unwrap_or(false)
        });
        let intel: Option<Arc<IntelDb>> = if needs_intel {
            crate::hub::watch::load_intel(&ctx.config_dir).await
        } else {
            None
        };
        let summary = summarize(collected, SCAN_DAYS, intel.as_deref());
        let mut warnings = Vec::new();
        for n in &summary.needs_admin {
            warnings.push(tf!("需要系統管理員權限才能讀取：{what}", what = n));
        }
        let findings = findings_from(&summary);
        Ok(ScanOutput {
            findings,
            warnings,
            summary: serde_json::to_value(&summary).ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::xml::{parse_event, samples::event};

    fn ev(provider: &str, id: u32, ch: &str, time: &str, data: &[(&str, &str)]) -> NormEvent {
        parse_event(&event(provider, id, 2, time, ch, data), ch).unwrap()
    }

    #[test]
    fn one_blue_screen_seen_three_ways_is_one_crash() {
        let mut c = Collected {
            platform: "windows".into(),
            events: vec![
                ev(
                    "Microsoft-Windows-Kernel-Power",
                    41,
                    "System",
                    "2026-10-10T03:02:00Z",
                    &[("BugcheckCode", "126")],
                ),
                ev(
                    "Microsoft-Windows-WER-SystemErrorReporting",
                    1001,
                    "System",
                    "2026-10-10T03:03:00Z",
                    &[("param1", "0x0000007e (0xffffffffc0000005, 0x1, 0x2, 0x3)")],
                ),
                ev("EventLog", 6008, "System", "2026-10-10T03:02:30Z", &[]),
                ev(
                    "Microsoft-Windows-Kernel-Power",
                    41,
                    "System",
                    "2026-10-12T08:00:00Z",
                    &[("BugcheckCode", "0")],
                ),
                ev("EventLog", 6008, "System", "2026-10-12T08:00:10Z", &[]),
                ev("EventLog", 6008, "System", "2026-10-13T08:00:10Z", &[]),
            ],
            ..Default::default()
        };
        c.extra_crashes.push(minidump::to_crash(
            &minidump::parse_header(&minidump::sample64(0x7E, 0xc000_0005)).unwrap(),
            DateTime::parse_from_rfc3339("2026-10-10T03:01:30Z")
                .unwrap()
                .with_timezone(&Utc),
            Path::new("C:\\Windows\\Minidump\\101026-1.dmp"),
        ));
        let s = summarize(c, 7, None);
        assert_eq!(s.crash_counts.get("bugcheck"), Some(&1), "{:?}", s.crashes);
        assert_eq!(s.crash_counts.get("unexpected_shutdown"), Some(&2));
        let b = s.crashes.iter().find(|c| c.kind == "bugcheck").unwrap();
        assert_eq!(b.name.as_deref(), Some("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"));
        assert_eq!(b.params.len(), 4);
        let f = findings_from(&s);
        let rules: Vec<&str> = f.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, vec!["events.bugcheck", "events.unexpected_shutdown"]);
        assert!(f[0].title.contains("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"));
        assert!(!f[0].recommendation.is_empty());
        assert_eq!(s.counts_by_level.get("error"), Some(&6));
    }

    #[test]
    fn brute_force_finding_proposes_a_block() {
        let events: Vec<NormEvent> = (0..10)
            .map(|i| {
                ev(
                    "Microsoft-Windows-Security-Auditing",
                    4625,
                    "Security",
                    &format!("2026-10-10T03:0{i}:00Z"),
                    &[("IpAddress", "185.199.108.9"), ("TargetUserName", "admin")],
                )
            })
            .collect();
        let s = summarize(
            Collected {
                platform: "windows".into(),
                events,
                needs_admin: vec!["Minidump".into()],
                ..Default::default()
            },
            7,
            None,
        );
        let f = findings_from(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule, "events.failed_logon_burst");
        assert!(f[0].tags.contains(&"inbound".to_string()));
        assert_eq!(f[0].actions[0].params["ip"], "185.199.108.9");
        assert_eq!(f[0].actions[0].params["direction"], "inbound");
        assert_eq!(s.top_error_sources[0].count, 10);
        assert_eq!(s.needs_admin, vec!["Minidump".to_string()]);
    }

    #[test]
    fn analyzes_journal_and_mac_files() {
        let d = tempfile::tempdir().unwrap();
        let j = d.path().join("journal.json");
        let lines: Vec<String> = [
            "Out of memory: Killed process 1 (java)",
            "Kernel panic - not syncing: VFS",
        ]
        .iter()
        .enumerate()
        .map(|(i, m)| linux::sample(1_760_000_000_000_000 + i as i64 * 1_000_000, 2, "kernel", None, m))
        .collect();
        std::fs::write(&j, lines.join("\n")).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let runner = crate::util::cmd::FakeRunner::new();
        let s = rt.block_on(analyze_file(&runner, &j, None)).unwrap();
        assert_eq!(s.crash_counts.get("oom"), Some(&1));
        assert_eq!(s.crash_counts.get("kernel_panic"), Some(&1));
        let ips = d.path().join("Safari.ips");
        std::fs::write(
            &ips,
            "{\"bug_type\":\"309\",\"app_name\":\"Safari\",\"timestamp\":\"2026-10-10 10:00:00.00 +0000\"}\n{}",
        )
        .unwrap();
        let s = rt.block_on(analyze_file(&runner, &ips, None)).unwrap();
        assert_eq!(s.crashes[0].process.as_deref(), Some("Safari"));
        let bad = d.path().join("x.txt");
        std::fs::write(&bad, "hello").unwrap();
        assert!(rt.block_on(analyze_file(&runner, &bad, None)).is_err());
        let dmp = d.path().join("m.dmp");
        std::fs::write(&dmp, minidump::sample64(0x133, 0)).unwrap();
        let s = rt.block_on(analyze_file(&runner, &dmp, None)).unwrap();
        assert_eq!(s.crashes[0].name.as_deref(), Some("DPC_WATCHDOG_VIOLATION"));
    }
}
