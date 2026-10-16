//! macOS：`DiagnosticReports` 裡的 kernel panic（.panic、bug_type 210）與 App 當機（.ips、bug_type 309）。
//! `.ips` 第一行是 JSON 標頭（bug_type、timestamp、app_name），其後是 JSON 內容。

use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;

use super::model::CrashRecord;

pub fn report_dirs() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/Library/Logs/DiagnosticReports")];
    if let Some(home) = dirs::home_dir() {
        v.push(home.join("Library/Logs/DiagnosticReports"));
    }
    v
}

/// `2026-10-10 10:22:33.00 +0800` → UTC
fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    let (dt, off) = s.rsplit_once(' ')?;
    let naive = NaiveDateTime::parse_from_str(dt, "%Y-%m-%d %H:%M:%S%.f").ok()?;
    let sign = if off.starts_with('-') { -1 } else { 1 };
    let digits = off.trim_start_matches(['+', '-']);
    let (h, m) = (
        digits.get(0..2)?.parse::<i32>().ok()?,
        digits.get(2..4)?.parse::<i32>().ok()?,
    );
    let offset = chrono::FixedOffset::east_opt(sign * (h * 3600 + m * 60))?;
    Some(naive.and_local_timezone(offset).single()?.with_timezone(&Utc))
}

/// 解析一份報告；不是當機類型就回 None。
pub fn parse_report(name: &str, text: &str, fallback_time: DateTime<Utc>) -> Option<CrashRecord> {
    let source = format!("diagnostic-report:{name}");
    if name.ends_with(".panic") || (text.contains("panic(cpu") && !text.trim_start().starts_with('{')) {
        let mut c = CrashRecord::new("kernel_panic", fallback_time, source);
        c.name = text
            .lines()
            .find(|l| l.contains("panic("))
            .map(|l| crate::util::text::clip(l.trim(), 200));
        return Some(c);
    }
    let mut lines = text.splitn(2, '\n');
    let header: Value = serde_json::from_str(lines.next()?.trim()).ok()?;
    let body: Value = lines
        .next()
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null);
    let bug_type = header["bug_type"].as_str().unwrap_or("");
    let time = header["timestamp"].as_str().and_then(parse_ts).unwrap_or(fallback_time);
    match bug_type {
        "210" => {
            let mut c = CrashRecord::new("kernel_panic", time, source);
            c.name = body["panicString"]
                .as_str()
                .or(body["macOSPanicString"].as_str())
                .and_then(|p| p.lines().next())
                .map(|l| crate::util::text::clip(l, 200));
            Some(c)
        }
        "309" => {
            let mut c = CrashRecord::new("app_crash", time, source);
            c.process = header["app_name"]
                .as_str()
                .or(body["procName"].as_str())
                .map(str::to_string);
            c.name = c.process.clone();
            let exc = &body["exception"];
            c.code = exc["type"].as_str().map(|t| match exc["signal"].as_str() {
                Some(sig) => format!("{t} ({sig})"),
                None => t.to_string(),
            });
            Some(c)
        }
        _ => None,
    }
}

/// 掃報告資料夾，只取 `since` 之後修改過的檔案。
pub fn scan(since: DateTime<Utc>) -> Vec<CrashRecord> {
    let mut out = Vec::new();
    for dir in report_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !(name.ends_with(".ips") || name.ends_with(".panic")) {
                continue;
            }
            let modified: DateTime<Utc> = e
                .metadata()
                .and_then(|m| m.modified())
                .map(DateTime::<Utc>::from)
                .unwrap_or_else(|_| Utc::now());
            if modified < since {
                continue;
            }
            if let Some(c) = read_report(&p, modified) {
                out.push(c);
            }
        }
    }
    out
}

pub fn read_report(p: &Path, fallback: DateTime<Utc>) -> Option<CrashRecord> {
    let bytes = std::fs::read(p).ok()?;
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(4 * 1024 * 1024)]);
    let name = p.file_name()?.to_string_lossy().to_string();
    parse_report(&name, &text, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_app_crash_and_panic_reports() {
        let now = Utc::now();
        let ips = "{\"app_name\":\"Safari\",\"timestamp\":\"2026-10-10 10:22:33.00 +0800\",\"bug_type\":\"309\",\"os_version\":\"macOS 15.1\"}\n{\"procName\":\"Safari\",\"exception\":{\"type\":\"EXC_BAD_ACCESS\",\"signal\":\"SIGSEGV\"}}";
        let c = parse_report("Safari-2026-10-10-102233.ips", ips, now).unwrap();
        assert_eq!(
            (c.kind.as_str(), c.process.as_deref(), c.code.as_deref()),
            ("app_crash", Some("Safari"), Some("EXC_BAD_ACCESS (SIGSEGV)"))
        );
        assert_eq!(
            c.time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2026-10-10T02:22:33Z"
        );

        let panic = "{\"bug_type\":\"210\",\"timestamp\":\"2026-10-09 01:00:00.00 -0700\"}\n{\"panicString\":\"panic(cpu 2 caller 0xfffff): watchdog timeout\\nmore\"}";
        let p = parse_report("Kernel-2026.panic.ips", panic, now).unwrap();
        assert_eq!(p.kind, "kernel_panic");
        assert!(p.name.unwrap().starts_with("panic(cpu 2"));

        let legacy = "Anonymous UUID: x\npanic(cpu 0 caller 0x1): Kernel trap\n";
        assert_eq!(
            parse_report("Kernel_2020.panic", legacy, now).unwrap().kind,
            "kernel_panic"
        );
        assert!(parse_report("x.ips", "{\"bug_type\":\"288\"}\n{}", now).is_none());
    }
}
