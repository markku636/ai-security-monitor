//! Windows：一次 PowerShell（Get-WinEvent，UTF-8 JSON）讀 System／Application／Security／Defender 需要的事件，
//! 再掃 Minidump 資料夾的 kernel dump 檔頭。Security 記錄與 Minidump 需要系統管理員：讀不到就列進 needs_admin。

use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::model::{CrashRecord, NormEvent};
use super::{minidump, xml};
use crate::error::{AppError, AppResult};
use crate::util::cmd::{powershell, CmdRunner};

pub const MAX_PER_QUERY: u32 = 1500;

/// 每組查詢：(標籤, FilterHashtable 內容, 最多幾筆)。標籤也用在 needs_admin。
fn queries(days: u32) -> Vec<(&'static str, String, u32)> {
    let since = format!("StartTime=(Get-Date).AddDays(-{days})");
    vec![
        (
            "System",
            format!("LogName='System'; Level=1,2,3; {since}"),
            MAX_PER_QUERY,
        ),
        (
            "System",
            format!("LogName='System'; Id=41,1001,6008,1074,7045,104,19,20,4101; {since}"),
            400,
        ),
        (
            "Application",
            format!("LogName='Application'; Level=1,2; {since}"),
            MAX_PER_QUERY,
        ),
        (
            "Application",
            format!("LogName='Application'; Id=1000,1001,1002; {since}"),
            400,
        ),
        (
            "Security",
            format!("LogName='Security'; Id=4625,4624,4720,4722,4728,4732,4756,4698,1102; {since}"),
            3000,
        ),
        // 伺服器／網域控制站：帳號鎖定、Kerberos 預先驗證失敗、NTLM 驗證。DC 上 4776 量很大（成功也記），
        // 獨立一組並設上限，才不會把上面的 4625 擠掉。
        (
            "Security",
            format!("LogName='Security'; Id=4740,4771,4776; {since}"),
            1000,
        ),
        // 遠端桌面連線（1149：通過網路層級驗證）；非系統管理員也讀得到
        (
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            format!(
                "LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; {since}"
            ),
            300,
        ),
        (
            "Microsoft-Windows-Windows Defender/Operational",
            format!("LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,5001; {since}"),
            200,
        ),
    ]
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// 產生 PowerShell 腳本：輸出 `{"events":[{"l":log,"x":xml,"m":message}],"denied":[log…]}`。
pub fn script(filters: &[(&str, String, u32)]) -> String {
    let mut s = String::from(
        "$out = New-Object System.Collections.Generic.List[object]\n$denied = New-Object System.Collections.Generic.List[string]\n\
function Q($label, $filter, $max) {\n\
  try {\n\
    Get-WinEvent -FilterHashtable $filter -MaxEvents $max -ErrorAction Stop | ForEach-Object {\n\
      $m = $null; try { $m = $_.Message } catch {}\n\
      if ($m) { $m = ($m -replace '\\s+', ' '); if ($m.Length -gt 400) { $m = $m.Substring(0, 400) } }\n\
      $out.Add([pscustomobject]@{ l = $label; x = $_.ToXml(); m = $m })\n\
    }\n\
  } catch {\n\
    $id = [string]$_.FullyQualifiedErrorId\n\
    if ($id -match 'Unauthorized' -or $_.Exception -is [System.UnauthorizedAccessException]) { $denied.Add($label) }\n\
  }\n\
}\n",
    );
    for (label, filter, max) in filters {
        s.push_str(&format!("Q {} @{{ {filter} }} {max}\n", ps_quote(label)));
    }
    s.push_str("[pscustomobject]@{ events = $out; denied = @($denied | Select-Object -Unique) } | ConvertTo-Json -Depth 4 -Compress\n");
    s
}

/// 解析腳本輸出。ConvertTo-Json 單一元素時會輸出物件而不是陣列，兩種都接受。
pub fn parse_output(stdout: &str) -> AppResult<(Vec<NormEvent>, Vec<String>)> {
    let text = stdout.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let v: Value = serde_json::from_str(text).map_err(|e| AppError::Parse(tf!("事件查詢輸出無法解析：{e}", e = e)))?;
    let list = |x: &Value| -> Vec<Value> {
        match x {
            Value::Array(a) => a.clone(),
            Value::Null => Vec::new(),
            other => vec![other.clone()],
        }
    };
    let mut events = Vec::new();
    for item in list(&v["events"]) {
        let label = item["l"].as_str().unwrap_or("");
        let Some(x) = item["x"].as_str() else { continue };
        if let Some(mut e) = xml::parse_event(x, label) {
            if e.message.is_none() {
                e.message = item["m"].as_str().filter(|m| !m.is_empty()).map(str::to_string);
            }
            events.push(e);
        }
    }
    let denied = list(&v["denied"])
        .iter()
        .filter_map(|d| d.as_str().map(str::to_string))
        .collect();
    Ok((events, denied))
}

/// 同一筆事件可能被兩組查詢都撈到（等級＋指定 ID）：以 (記錄檔, 時間, ID, provider) 去重。
pub fn dedupe(events: &mut Vec<NormEvent>) {
    let mut seen = std::collections::HashSet::new();
    events.retain(|e| seen.insert((e.channel.clone(), e.time, e.event_id, e.provider.clone())));
    events.sort_by_key(|e| std::cmp::Reverse(e.time));
}

pub async fn query(runner: &dyn CmdRunner, days: u32) -> AppResult<(Vec<NormEvent>, Vec<String>)> {
    let out = runner
        .run(&powershell(&script(&queries(days))).timeout(120_000))
        .await?;
    if !out.ok() && out.stdout.trim().is_empty() {
        return Err(AppError::External(tf!(
            "讀取事件記錄失敗：{e}",
            e = crate::util::text::clip(&out.stderr, 300)
        )));
    }
    let (mut events, denied) = parse_output(&out.stdout)?;
    dedupe(&mut events);
    Ok((events, denied))
}

/// 離線：讀 .evtx（只在 Windows 上可用，靠 Get-WinEvent -Path）。
pub async fn query_file(runner: &dyn CmdRunner, path: &Path) -> AppResult<Vec<NormEvent>> {
    let filter = vec![(
        "evtx",
        format!("Path={}", ps_quote(&path.display().to_string())),
        20_000,
    )];
    let out = runner.run(&powershell(&script(&filter)).timeout(180_000)).await?;
    let (mut events, _) = parse_output(&out.stdout)?;
    dedupe(&mut events);
    Ok(events)
}

/// 掃 `%SystemRoot%\Minidump\*.dmp` 與 `MEMORY.DMP` 的 kernel dump 檔頭。回傳 (當機紀錄, 是否因權限讀不到)。
pub fn scan_minidumps(since: DateTime<Utc>) -> (Vec<CrashRecord>, bool) {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:\\Windows".into());
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut denied = false;
    match std::fs::read_dir(root.join("Minidump")) {
        Ok(rd) => files.extend(
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x.eq_ignore_ascii_case("dmp")).unwrap_or(false)),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied = true,
        Err(_) => {}
    }
    let full = root.join("MEMORY.DMP");
    if full.is_file() {
        files.push(full);
    }
    let mut out = Vec::new();
    for f in files {
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        let time: DateTime<Utc> = meta
            .modified()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(|_| Utc::now());
        if time < since {
            continue;
        }
        match minidump::read_header(&f) {
            Ok(Some(h)) => out.push(minidump::to_crash(&h, time, &f)),
            Ok(None) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied = true,
            Err(_) => {}
        }
    }
    (out, denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::xml::samples::event;

    #[test]
    fn script_quotes_labels_and_paths() {
        let s = script(&[("evtx", format!("Path={}", ps_quote("C:\\it's\\x.evtx")), 10)]);
        assert!(s.contains("Q 'evtx' @{ Path='C:\\it''s\\x.evtx' } 10"));
        assert!(s.contains("ConvertTo-Json"));
        assert_eq!(queries(7).len(), 8);
    }

    #[test]
    fn parses_array_single_object_and_denied() {
        let x1 = event(
            "Microsoft-Windows-Kernel-Power",
            41,
            1,
            "2026-10-10T03:00:00Z",
            "System",
            &[("BugcheckCode", "0")],
        );
        let x2 = event("EventLog", 6008, 2, "2026-10-10T03:01:00Z", "System", &[]);
        let arr = serde_json::json!({ "events": [{ "l": "System", "x": x1, "m": "msg one" }, { "l": "System", "x": x2, "m": null }], "denied": "Security" });
        let (ev, denied) = parse_output(&arr.to_string()).unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].message.as_deref(), Some("msg one"));
        assert_eq!(denied, vec!["Security".to_string()]);
        let one = serde_json::json!({ "events": { "l": "System", "x": x2 }, "denied": [] });
        let (ev, denied) = parse_output(&format!("\u{feff}{one}")).unwrap();
        assert_eq!((ev.len(), denied.len()), (1, 0));
        assert!(parse_output("not json").is_err());
        assert_eq!(parse_output("").unwrap().0.len(), 0);
    }

    #[test]
    fn dedupes_overlapping_queries() {
        let x = event("EventLog", 6008, 2, "2026-10-10T03:01:00Z", "System", &[]);
        let (mut ev, _) = parse_output(
            &serde_json::json!({ "events": [{ "l": "System", "x": x }, { "l": "System", "x": x }] }).to_string(),
        )
        .unwrap();
        dedupe(&mut ev);
        assert_eq!(ev.len(), 1);
    }
}
