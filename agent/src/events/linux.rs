//! Linux：`journalctl -o json`（每行一筆 JSON）→ `NormEvent`。
//! 系統錯誤（priority 0–4）一組、登入／帳號相關（sshd、sudo、useradd、usermod、gpasswd）一組。
//! 一般使用者要在 `systemd-journal`／`adm` 群組才看得到系統紀錄，否則列進 needs_admin。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::model::NormEvent;
use crate::error::AppResult;
use crate::util::cmd::{CmdRunner, CmdSpec};

pub const MAX_LINES: u32 = 3000;

fn field(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) => Some(s.clone()),
        // 非 UTF-8 的 MESSAGE 會被輸出成 byte 陣列
        Value::Array(a) => Some(
            String::from_utf8_lossy(
                &a.iter()
                    .filter_map(|b| b.as_u64().map(|b| b as u8))
                    .collect::<Vec<u8>>(),
            )
            .to_string(),
        ),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// 解析一行 journal JSON。
pub fn parse_line(line: &str) -> Option<NormEvent> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    let us: i64 = field(&v, "__REALTIME_TIMESTAMP")?.parse().ok()?;
    let time = DateTime::<Utc>::from_timestamp(us / 1_000_000, ((us % 1_000_000) * 1000) as u32)?;
    let message = field(&v, "MESSAGE").unwrap_or_default();
    let priority: u8 = field(&v, "PRIORITY").and_then(|p| p.parse().ok()).unwrap_or(6);
    let ident = field(&v, "SYSLOG_IDENTIFIER")
        .or_else(|| field(&v, "_COMM"))
        .unwrap_or_default();
    let unit = field(&v, "_SYSTEMD_UNIT").unwrap_or_else(|| {
        if ident == "kernel" {
            "kernel".into()
        } else {
            ident.clone()
        }
    });
    let mut data = BTreeMap::new();
    for k in ["_PID", "_COMM", "_EXE", "_SYSTEMD_UNIT", "UNIT", "_TRANSPORT"] {
        if let Some(x) = field(&v, k) {
            data.insert(k.trim_start_matches('_').to_string(), crate::util::text::clip(&x, 256));
        }
    }
    data.insert("MESSAGE".into(), crate::util::text::clip(&message, 1024));
    Some(NormEvent {
        source: "journal".into(),
        channel: unit,
        provider: ident,
        event_id: 0,
        level: match priority {
            0..=2 => 1,
            3 => 2,
            4 => 3,
            _ => 4,
        },
        time,
        computer: field(&v, "_HOSTNAME").unwrap_or_default(),
        data,
        message: (!message.is_empty()).then(|| crate::util::text::clip(&message, 400)),
    })
}

pub fn parse_lines(text: &str) -> Vec<NormEvent> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(parse_line)
        .collect()
}

/// 讀 journal。回傳 (事件, 是否疑似權限不足)。
pub async fn query(runner: &dyn CmdRunner, days: u32) -> AppResult<(Vec<NormEvent>, bool)> {
    let since = format!("-{days}d");
    let n = MAX_LINES.to_string();
    let errors = CmdSpec::new(
        "journalctl",
        &["-o", "json", "--no-pager", "--since", &since, "-p", "0..4", "-n", &n],
    )
    .timeout(60_000);
    let auth = CmdSpec::new(
        "journalctl",
        &[
            "-o",
            "json",
            "--no-pager",
            "--since",
            &since,
            "-n",
            &n,
            "-t",
            "sshd",
            "-t",
            "sudo",
            "-t",
            "useradd",
            "-t",
            "usermod",
            "-t",
            "gpasswd",
        ],
    )
    .timeout(60_000);
    let mut events = Vec::new();
    let mut limited = false;
    for spec in [errors, auth] {
        let out = runner.run(&spec).await?;
        let low = out.stderr.to_ascii_lowercase();
        if low.contains("not seeing messages from other users")
            || low.contains("insufficient permissions")
            || out.permission_denied()
        {
            limited = true;
        }
        events.extend(parse_lines(&out.stdout));
    }
    let mut seen = std::collections::HashSet::new();
    events.retain(|e| seen.insert((e.time, e.provider.clone(), e.message.clone())));
    events.sort_by_key(|e| std::cmp::Reverse(e.time));
    Ok((events, limited))
}

#[cfg(test)]
pub(crate) fn sample(ts_us: i64, prio: u8, ident: &str, unit: Option<&str>, msg: &str) -> String {
    let mut v = serde_json::json!({
        "__REALTIME_TIMESTAMP": ts_us.to_string(),
        "PRIORITY": prio.to_string(),
        "SYSLOG_IDENTIFIER": ident,
        "MESSAGE": msg,
        "_HOSTNAME": "srv1",
        "_PID": "321",
    });
    if let Some(u) = unit {
        v["_SYSTEMD_UNIT"] = serde_json::json!(u);
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_journal_lines() {
        let l = sample(
            1_760_000_000_123_456,
            3,
            "kernel",
            None,
            "Out of memory: Killed process 4242 (java)",
        );
        let e = parse_line(&l).unwrap();
        assert_eq!(
            (e.source.as_str(), e.channel.as_str(), e.level),
            ("journal", "kernel", 2)
        );
        assert_eq!(e.time.timestamp(), 1_760_000_000);
        assert_eq!(e.computer, "srv1");
        let bytes = r#"{"__REALTIME_TIMESTAMP":"1760000000000000","PRIORITY":"4","SYSLOG_IDENTIFIER":"app","MESSAGE":[104,105]}"#;
        assert_eq!(parse_line(bytes).unwrap().message.as_deref(), Some("hi"));
        assert!(parse_line("{}").is_none());
        assert_eq!(parse_lines(&format!("{l}\n\nnot json\n{l}")).len(), 2);
    }
}
