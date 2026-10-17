//! 檔案完整性＋開機自啟監控（掃描器 `files`）。
//!
//! - 監看清單（自己整理的）：hosts、啟動資料夾、排程工作、驅動程式、PowerShell profile（Windows）；
//!   /etc、系統程式目錄、cron、systemd、SSH authorized_keys（Linux）；LaunchAgents／LaunchDaemons、/etc（macOS）；
//!   另加設定 `fim.extra_paths`，`fim.ignore` 排除（路徑前綴或 `*` 萬用字元）。
//! - 每個檔案記大小、修改時間、權限；≤ 1 MiB 的一律算 sha256，大檔只在大小／時間變了才算（當作證據）。
//! - 開機自啟：Windows 登錄 Run／RunOnce、Winlogon Shell／Userinit、服務的執行檔；Linux 已啟用的 systemd 單元。
//! - 第一次只建基準不告警。之後的變更記在 `fim/changes.json`，連續 7 天都會出現在報告裡（或直到 `fim accept`），
//!   基準本身立刻更新（同一個變更不會重複算）。
//! - 規則名稱：`fim.<分類>.<added|modified|deleted|permissions>`、`fim.autorun.<種類>.<added|changed|removed>`；
//!   Hub 依分類對應 MITRE ATT&CK。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::AppResult;
use crate::model::finding::{Evidence, Finding, ScannerId, Severity};
use crate::scan::{Elevation, ScanCtx, ScanOutput, Scanner};
use crate::store;

pub const BASELINE: &str = "fim/baseline.json";
pub const CHANGES: &str = "fim/changes.json";
/// 變更在報告裡保留幾天。
pub const KEEP_DAYS: i64 = 7;
/// 最多監看幾個檔案（超過就停，摘要註明）。
pub const MAX_FILES: usize = 50_000;
/// 一律算雜湊的檔案大小上限。
pub const HASH_ALWAYS: u64 = 1 << 20;
/// 變更時補算雜湊的上限。
pub const HASH_MAX: u64 = 512 << 20;
/// 一次報告最多幾個 FIM 問題（其餘合併成一個）。
pub const MAX_FINDINGS: usize = 100;

/// 監看的位置：分類決定嚴重度與 MITRE 對應。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watch {
    pub path: PathBuf,
    pub category: &'static str,
    pub recursive: bool,
}

fn w(path: impl Into<PathBuf>, category: &'static str, recursive: bool) -> Watch {
    Watch {
        path: path.into(),
        category,
        recursive,
    }
}

/// 這個平台預設監看的位置（不存在的會略過）。
pub fn default_watches() -> Vec<Watch> {
    let mut v = Vec::new();
    let home = dirs::home_dir();
    if cfg!(windows) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let root = PathBuf::from(root);
        v.push(w(root.join(r"System32\drivers\etc\hosts"), "hosts", false));
        v.push(w(root.join(r"System32\Tasks"), "tasks", true));
        v.push(w(root.join(r"System32\drivers"), "drivers", false));
        v.push(w(
            root.join(r"System32\WindowsPowerShell\v1.0\profile.ps1"),
            "profile",
            false,
        ));
        if let Ok(pd) = std::env::var("ProgramData") {
            v.push(w(
                PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
                "startup",
                true,
            ));
        }
        if let Ok(ad) = std::env::var("APPDATA") {
            v.push(w(
                PathBuf::from(ad).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "startup",
                true,
            ));
        }
        if let Some(h) = &home {
            v.push(w(h.join(r"Documents\WindowsPowerShell\profile.ps1"), "profile", false));
            v.push(w(
                h.join(r"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
                "profile",
                false,
            ));
            v.push(w(
                h.join(r"Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
                "profile",
                false,
            ));
        }
    } else if cfg!(target_os = "macos") {
        v.push(w("/etc", "etc_config", true));
        v.push(w("/Library/LaunchAgents", "launchd", true));
        v.push(w("/Library/LaunchDaemons", "launchd", true));
        v.push(w("/usr/local/bin", "system_bin", false));
        if let Some(h) = &home {
            v.push(w(h.join("Library/LaunchAgents"), "launchd", true));
            v.push(w(h.join(".ssh/authorized_keys"), "ssh_keys", false));
        }
    } else {
        v.push(w("/etc/hosts", "hosts", false));
        v.push(w("/etc/crontab", "cron", false));
        v.push(w("/etc/cron.d", "cron", true));
        v.push(w("/var/spool/cron", "cron", true));
        v.push(w("/etc/systemd/system", "systemd", true));
        v.push(w("/etc", "etc_config", true));
        for d in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
            v.push(w(d, "system_bin", false));
        }
        v.push(w("/boot", "boot", false));
        v.push(w("/root/.ssh/authorized_keys", "ssh_keys", false));
        if let Some(h) = &home {
            v.push(w(h.join(".ssh/authorized_keys"), "ssh_keys", false));
        }
    }
    v
}

/// 檔案的屬性快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub category: String,
    pub size: u64,
    /// 修改時間（Unix 秒）。
    pub mtime: i64,
    /// Unix 權限（Windows 為唯讀旗標 0o444／0o644）。
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FimBaseline {
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub files: BTreeMap<String, FileState>,
    /// 開機自啟：`種類|位置|名稱` → 指令。
    pub autoruns: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// 檔案路徑，或開機自啟的 `種類|位置|名稱`。
    pub key: String,
    pub rule: String,
    pub severity: Severity,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub size: u64,
    pub first_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Changes {
    pub items: Vec<Change>,
}

fn mode_of(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        if md.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

fn mtime_of(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `fim.ignore` 的一條：`*` 萬用字元，否則當前綴；不分大小寫（Windows 路徑）。
pub fn ignored(path: &str, patterns: &[String]) -> bool {
    let p = path.to_ascii_lowercase();
    patterns.iter().any(|pat| {
        let pat = pat.trim().to_ascii_lowercase();
        if pat.is_empty() {
            return false;
        }
        if !pat.contains('*') {
            return p.starts_with(&pat);
        }
        // 簡單的萬用字元比對（* 比對任意字元）
        let parts: Vec<&str> = pat.split('*').collect();
        let mut rest = p.as_str();
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            match rest.find(part) {
                Some(at) if i > 0 || at == 0 => rest = &rest[at + part.len()..],
                _ => return false,
            }
        }
        parts.last().is_none_or(|l| l.is_empty() || p.ends_with(l))
    })
}

/// 走過所有監看位置，回傳路徑 → 屬性（不算雜湊）。超過 MAX_FILES 回 truncated=true。
pub fn walk(watches: &[Watch], ignore: &[String]) -> (BTreeMap<String, (String, std::fs::Metadata, PathBuf)>, bool) {
    let mut out = BTreeMap::new();
    let mut truncated = false;
    for wt in watches {
        let mut stack = vec![(wt.path.clone(), 0usize)];
        while let Some((p, depth)) = stack.pop() {
            if out.len() >= MAX_FILES {
                truncated = true;
                break;
            }
            let key = p.to_string_lossy().to_string();
            if ignored(&key, ignore) || out.contains_key(&key) {
                continue;
            }
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if md.is_dir() {
                if depth == 0 || wt.recursive {
                    if let Ok(rd) = std::fs::read_dir(&p) {
                        for e in rd.flatten() {
                            stack.push((e.path(), depth + 1));
                        }
                    }
                }
                continue;
            }
            if md.is_file() || md.file_type().is_symlink() {
                out.insert(key, (wt.category.to_string(), md, p));
            }
        }
    }
    (out, truncated)
}

fn hash(path: &Path) -> Option<String> {
    crate::util::hash::sha256_file(path).ok()
}

/// 依分類決定嚴重度：開機會自動執行、或能改變名稱解析／登入的位置比較嚴重。
pub fn severity_for(category: &str, change: &str) -> Severity {
    let hot = matches!(
        category,
        "startup" | "tasks" | "hosts" | "ssh_keys" | "launchd" | "cron" | "systemd" | "profile" | "drivers" | "boot"
    );
    match (hot, change) {
        (true, "deleted") => Severity::Medium,
        (true, _) => Severity::High,
        (false, "permissions") => Severity::Low,
        (false, _) => Severity::Medium,
    }
}

/// 掃描一次：跟基準比，回傳新的基準與這次新發現的變更。`old` 是空的（第一次）時不產生變更。
pub fn diff_files(
    old: &FimBaseline,
    current: BTreeMap<String, (String, std::fs::Metadata, PathBuf)>,
    now: DateTime<Utc>,
) -> (BTreeMap<String, FileState>, Vec<Change>) {
    let first = old.created_at.is_none();
    let mut files = BTreeMap::new();
    let mut changes = Vec::new();
    for (key, (category, md, path)) in &current {
        let size = md.len();
        let mtime = mtime_of(md);
        let mode = mode_of(md);
        let prev = old.files.get(key);
        let same_attrs = prev.is_some_and(|p| p.size == size && p.mtime == mtime);
        let sha256 = if size <= HASH_ALWAYS {
            // 小檔每次都重算：修改時間只到秒、也可能被刻意改回去，不能拿來省略
            hash(path)
        } else if !first && prev.is_some() && !same_attrs && size <= HASH_MAX {
            hash(path)
        } else {
            None
        };
        let state = FileState {
            category: category.clone(),
            size,
            mtime,
            mode,
            sha256: sha256.clone(),
        };
        if !first {
            let change = match prev {
                None => Some(("added", String::new())),
                Some(p) if p.sha256.is_some() && sha256.is_some() && p.sha256 != sha256 => {
                    Some(("modified", String::new()))
                }
                Some(p) if p.sha256.is_none() && (p.size != size || p.mtime != mtime) => {
                    Some(("modified", String::new()))
                }
                Some(p) if p.mode != mode => Some(("permissions", format!("{:o} → {:o}", p.mode, mode))),
                _ => None,
            };
            if let Some((kind, extra)) = change {
                changes.push(Change {
                    key: key.clone(),
                    rule: format!("fim.{category}.{kind}"),
                    severity: severity_for(category, kind),
                    detail: extra,
                    sha256: sha256.clone(),
                    size,
                    first_seen: now,
                });
            }
        }
        files.insert(key.clone(), state);
    }
    if !first {
        for (key, p) in &old.files {
            if !current.contains_key(key) {
                changes.push(Change {
                    key: key.clone(),
                    rule: format!("fim.{}.deleted", p.category),
                    severity: severity_for(&p.category, "deleted"),
                    detail: String::new(),
                    sha256: p.sha256.clone(),
                    size: p.size,
                    first_seen: now,
                });
            }
        }
    }
    (files, changes)
}

// ---- 開機自啟 ----

/// Windows：登錄 Run／RunOnce（HKLM、HKCU、32 位元）、Winlogon、服務的執行檔。每行「種類<Tab>位置<Tab>名稱<Tab>指令」。
pub const WINDOWS_AUTORUNS_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($k in $keys) {
  $p = Get-ItemProperty -Path $k
  if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "run_key`t$k`t$($_.Name)`t$($_.Value)" } }
}
$wl = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl) { "winlogon`tWinlogon`tShell`t$($wl.Shell)"; "winlogon`tWinlogon`tUserinit`t$($wl.Userinit)" }
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
  $s = Get-ItemProperty -Path $_.PSPath
  if ($s.ImagePath -and ($s.Start -le 2)) { "service`tServices`t$($_.PSChildName)`t$($s.ImagePath)" }
}
"#;

/// 解析成 `種類|位置|名稱` → 指令。
pub fn parse_autoruns(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut it = line.trim_end_matches('\r').splitn(4, '\t');
        let (Some(kind), Some(loc), Some(name), Some(cmd)) = (it.next(), it.next(), it.next(), it.next()) else {
            continue;
        };
        if kind.is_empty() || name.is_empty() {
            continue;
        }
        out.insert(format!("{kind}|{loc}|{name}"), cmd.trim().to_string());
    }
    out
}

/// Linux：`systemctl list-unit-files --state=enabled --no-legend` → `systemd|enabled|單元` → 狀態。
pub fn parse_systemd_enabled(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let unit = it.next()?;
            let state = it.next().unwrap_or("enabled");
            unit.contains('.')
                .then(|| (format!("systemd|enabled|{unit}"), state.to_string()))
        })
        .collect()
}

pub async fn collect_autoruns(runner: &dyn crate::util::cmd::CmdRunner) -> Option<BTreeMap<String, String>> {
    if cfg!(windows) {
        let spec = crate::util::cmd::powershell(WINDOWS_AUTORUNS_SCRIPT).timeout(60_000);
        runner.run(&spec).await.ok().map(|o| parse_autoruns(&o.stdout))
    } else if cfg!(target_os = "linux") {
        let spec = crate::util::cmd::CmdSpec::new(
            "systemctl",
            &["list-unit-files", "--state=enabled", "--no-legend", "--no-pager"],
        )
        .timeout(15_000);
        runner.run(&spec).await.ok().map(|o| parse_systemd_enabled(&o.stdout))
    } else {
        // macOS 的 LaunchAgents／LaunchDaemons 已經在檔案監看裡
        None
    }
}

pub fn diff_autoruns(old: &FimBaseline, current: &BTreeMap<String, String>, now: DateTime<Utc>) -> Vec<Change> {
    if old.created_at.is_none() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mk = |key: &str, kind: &str, change: &str, detail: String, sev: Severity| Change {
        key: key.to_string(),
        rule: format!("fim.autorun.{kind}.{change}"),
        severity: sev,
        detail,
        sha256: None,
        size: 0,
        first_seen: now,
    };
    for (k, v) in current {
        let kind = k.split('|').next().unwrap_or("other");
        match old.autoruns.get(k) {
            None => out.push(mk(k, kind, "added", v.clone(), Severity::High)),
            Some(prev) if prev != v => out.push(mk(k, kind, "changed", format!("{prev} → {v}"), Severity::High)),
            _ => {}
        }
    }
    for (k, v) in &old.autoruns {
        if !current.contains_key(k) {
            let kind = k.split('|').next().unwrap_or("other");
            out.push(mk(k, kind, "removed", v.clone(), Severity::Low));
        }
    }
    out
}

// ---- 掃描器 ----

/// 保留 7 天內、沒被接受的變更；同一個 key＋規則只留最早那筆。
pub fn merge_changes(mut keep: Vec<Change>, new: Vec<Change>, now: DateTime<Utc>) -> Vec<Change> {
    let cutoff = now - Duration::days(KEEP_DAYS);
    keep.retain(|c| c.first_seen >= cutoff);
    for c in new {
        if !keep.iter().any(|k| k.key == c.key && k.rule == c.rule) {
            keep.push(c);
        }
    }
    keep.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.first_seen.cmp(&a.first_seen))
            .then_with(|| a.key.cmp(&b.key))
    });
    keep
}

fn title_of(c: &Change) -> String {
    let parts: Vec<&str> = c.rule.split('.').collect();
    let change = parts.last().copied().unwrap_or("");
    if c.rule.starts_with("fim.autorun.") {
        let name = c.key.rsplit('|').next().unwrap_or(&c.key);
        match change {
            "added" => tf!("新的開機自動執行項目：{name}", name = name),
            "changed" => tf!("開機自動執行項目被改了：{name}", name = name),
            _ => tf!("開機自動執行項目被移除：{name}", name = name),
        }
    } else {
        match change {
            "added" => tf!("監看的位置多了檔案：{path}", path = c.key),
            "modified" => tf!("監看的檔案內容變了：{path}", path = c.key),
            "deleted" => tf!("監看的檔案被刪除：{path}", path = c.key),
            _ => tf!("監看的檔案權限變了：{path}", path = c.key),
        }
    }
}

pub fn to_finding(c: &Change) -> Finding {
    let evidence = if c.rule.starts_with("fim.autorun.") {
        Evidence::Text {
            detail: format!("{} = {}", c.key, c.detail),
        }
    } else {
        Evidence::File {
            path: c.key.clone(),
            sha256: c.sha256.clone(),
            size: c.size,
            rule: None,
            matched_strings: Vec::new(),
        }
    };
    let mut f = Finding::new(
        ScannerId::Files,
        &c.rule,
        &c.key,
        c.severity,
        title_of(c),
        if c.detail.is_empty() { tf!("第一次看到：{at}", at = c.first_seen.format("%Y-%m-%d %H:%M UTC")) } else { c.detail.clone() },
        evidence,
        t!("如果是你自己或軟體更新做的變更，執行 `ai-security-monitor fim accept <路徑>` 確認；不認得就檢查是哪個程式寫入的，必要時隔離這台電腦。"),
    );
    f.first_seen = c.first_seen;
    f.tags.push("fim".into());
    f
}

pub struct FimScanner;

#[async_trait]
impl Scanner for FimScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Files
    }

    fn elevation(&self) -> Elevation {
        // 沒提權也能跑，但讀不到系統排程工作、/root 等位置
        Elevation::Preferred
    }

    async fn run(&self, ctx: &ScanCtx) -> AppResult<ScanOutput> {
        let cfg = ctx.config.fim.clone();
        if !cfg.enabled {
            return Ok(ScanOutput::default());
        }
        let dir = ctx.config_dir.clone();
        let autoruns = collect_autoruns(ctx.runner.as_ref()).await;
        let now = Utc::now();
        let (findings, summary) =
            tokio::task::spawn_blocking(move || -> AppResult<_> { run_once(&dir, &cfg, autoruns, now) })
                .await
                .map_err(|e| crate::error::AppError::Scan(e.to_string()))??;
        Ok(ScanOutput {
            findings,
            warnings: Vec::new(),
            summary: Some(summary),
        })
    }
}

/// 監看清單（預設＋額外的）。
pub fn watches(cfg: &crate::config::FimConfig) -> Vec<Watch> {
    let mut v = default_watches();
    for p in &cfg.extra_paths {
        if !p.trim().is_empty() {
            v.push(w(p.trim(), "custom", true));
        }
    }
    v
}

/// 跑一次比對、存檔，回傳問題與摘要（同步，給 spawn_blocking 與測試用）。
pub fn run_once(
    dir: &Path,
    cfg: &crate::config::FimConfig,
    autoruns: Option<BTreeMap<String, String>>,
    now: DateTime<Utc>,
) -> AppResult<(Vec<Finding>, serde_json::Value)> {
    run_with(dir, &watches(cfg), &cfg.ignore, autoruns, now)
}

pub fn run_with(
    dir: &Path,
    watches: &[Watch],
    ignore: &[String],
    autoruns: Option<BTreeMap<String, String>>,
    now: DateTime<Utc>,
) -> AppResult<(Vec<Finding>, serde_json::Value)> {
    let old: FimBaseline = store::read_json_opt(dir, BASELINE)?.unwrap_or_default();
    let first = old.created_at.is_none();
    let (current, truncated) = walk(watches, ignore);
    let (files, mut new_changes) = diff_files(&old, current, now);
    let mut base = FimBaseline {
        created_at: old.created_at.or(Some(now)),
        updated_at: Some(now),
        files,
        autoruns: old.autoruns.clone(),
    };
    if let Some(a) = &autoruns {
        new_changes.extend(diff_autoruns(&old, a, now));
        base.autoruns = a.clone();
    }
    let prev: Changes = store::read_json_opt(dir, CHANGES)?.unwrap_or_default();
    let changes = Changes {
        items: merge_changes(prev.items, new_changes, now),
    };
    store::ensure_dir(&dir.join("fim"))?;
    store::write_json_compact_in(dir, BASELINE, &base)?;
    store::write_json_compact_in(dir, CHANGES, &changes)?;

    let mut findings: Vec<Finding> = changes.items.iter().take(MAX_FINDINGS).map(to_finding).collect();
    if changes.items.len() > MAX_FINDINGS {
        let rest = changes.items.len() - MAX_FINDINGS;
        findings.push(Finding::new(
            ScannerId::Files,
            "fim.many_changes",
            "many",
            Severity::Medium,
            tf!("還有 {n} 個檔案變更沒列出", n = rest),
            t!("變更太多（常見於系統更新後）。用 `ai-security-monitor fim status` 看完整清單，確認沒問題後 `fim accept --all`。"),
            Evidence::Text { detail: format!("{rest}") },
            t!("確認是系統或軟體更新造成的就全部接受。"),
        ));
    }
    let summary = serde_json::json!({
        "watched_files": base.files.len(),
        "autoruns": base.autoruns.len(),
        "changes": changes.items.len(),
        "baseline_created_at": base.created_at,
        "first_run": first,
        "truncated": truncated,
    });
    Ok((findings, summary))
}

/// `fim accept`：把符合的變更從清單拿掉（`all`＝全部）；回傳拿掉幾個。
pub fn accept(dir: &Path, target: Option<&str>) -> AppResult<usize> {
    let mut ch: Changes = store::read_json_opt(dir, CHANGES)?.unwrap_or_default();
    let before = ch.items.len();
    match target {
        None => ch.items.clear(),
        Some(t) => {
            let t = t.to_ascii_lowercase();
            ch.items.retain(|c| !c.key.to_ascii_lowercase().starts_with(&t));
        }
    }
    store::write_json_compact_in(dir, CHANGES, &ch)?;
    Ok(before - ch.items.len())
}

/// `fim baseline`：丟掉基準與變更清單，下次掃描重新建立。
pub fn reset(dir: &Path) -> AppResult<()> {
    for f in [BASELINE, CHANGES] {
        let p = dir.join(f);
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    Ok(())
}

pub fn load_changes(dir: &Path) -> Changes {
    store::read_json_opt(dir, CHANGES).ok().flatten().unwrap_or_default()
}

pub fn load_baseline(dir: &Path) -> FimBaseline {
    store::read_json_opt(dir, BASELINE).ok().flatten().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("asm-fim-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ignore_patterns_match_prefixes_and_wildcards() {
        let pats = vec![
            "/etc/ssl".to_string(),
            "*.log".to_string(),
            "C:\\Windows\\System32\\Tasks\\Microsoft*".to_string(),
        ];
        assert!(ignored("/etc/ssl/certs/a.pem", &pats));
        assert!(ignored("/var/foo/app.LOG", &pats));
        assert!(ignored(r"c:\windows\system32\tasks\Microsoft\Windows\x", &pats));
        assert!(!ignored("/etc/hosts", &pats));
        assert!(!ignored("/var/foo/app.log.1", &pats));
    }

    #[test]
    fn first_run_builds_baseline_then_reports_changes_until_accepted() {
        let dir = tmp();
        let watched = tmp();
        let a = watched.join("a.conf");
        let b = watched.join("b.conf");
        std::fs::write(&a, "one").unwrap();
        std::fs::write(&b, "keep").unwrap();
        let ws = vec![w(&watched, "startup", true)];
        let t0 = Utc::now();
        let (f, s) = run_with(
            &dir,
            &ws,
            &[],
            Some(BTreeMap::from([("run_key|HKCU|Foo".into(), "foo.exe".into())])),
            t0,
        )
        .unwrap();
        assert!(f.is_empty());
        assert_eq!(s["first_run"], true);
        assert_eq!(s["watched_files"], 2);

        // 改內容（大小相同也抓得到：小檔有雜湊）、新增、刪除、多一個開機自啟
        std::fs::write(&a, "two").unwrap();
        std::fs::remove_file(&b).unwrap();
        std::fs::write(watched.join("evil.lnk"), "x").unwrap();
        let autoruns = BTreeMap::from([
            ("run_key|HKCU|Foo".into(), "foo.exe".into()),
            ("run_key|HKCU|Evil".into(), "evil.exe".into()),
        ]);
        let (f, _) = run_with(&dir, &ws, &[], Some(autoruns.clone()), t0 + Duration::minutes(10)).unwrap();
        let mut rules: Vec<&str> = f.iter().map(|x| x.rule.as_str()).collect();
        rules.sort();
        assert_eq!(
            rules,
            vec![
                "fim.autorun.run_key.added",
                "fim.startup.added",
                "fim.startup.deleted",
                "fim.startup.modified"
            ]
        );
        assert!(f.iter().all(|x| x.scanner == ScannerId::Files));
        assert!(f
            .iter()
            .filter(|x| x.rule.starts_with("fim.startup."))
            .all(|x| x.severity >= Severity::Medium));

        // 沒有新變更：之前的照樣留在報告裡（同一筆不重複）
        let (f, _) = run_with(&dir, &ws, &[], Some(autoruns.clone()), t0 + Duration::minutes(20)).unwrap();
        assert_eq!(f.len(), 4);
        // 接受其中一個路徑
        assert_eq!(accept(&dir, Some(&a.to_string_lossy())).unwrap(), 1);
        let (f, _) = run_with(&dir, &ws, &[], Some(autoruns.clone()), t0 + Duration::minutes(30)).unwrap();
        assert_eq!(f.len(), 3);
        // 7 天後自動過期
        let (f, _) = run_with(&dir, &ws, &[], Some(autoruns), t0 + Duration::days(KEEP_DAYS + 1)).unwrap();
        assert!(f.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&watched);
    }

    #[test]
    fn parses_windows_autoruns_and_systemd() {
        let t = "run_key\tHKCU:\\Run\tOneDrive\t\"C:\\x\\OneDrive.exe\" /background\r\nwinlogon\tWinlogon\tShell\texplorer.exe\r\nbad line\n";
        let m = parse_autoruns(t);
        assert_eq!(m.len(), 2);
        assert_eq!(m["winlogon|Winlogon|Shell"], "explorer.exe");
        let s = parse_systemd_enabled("ssh.service enabled enabled\ncron.service enabled enabled\n\n");
        assert_eq!(
            s.keys().cloned().collect::<Vec<_>>(),
            vec!["systemd|enabled|cron.service", "systemd|enabled|ssh.service"]
        );
    }

    #[test]
    fn autorun_changes_and_removals() {
        let old = FimBaseline {
            created_at: Some(Utc::now()),
            autoruns: BTreeMap::from([
                ("service|Services|A".into(), "a.exe".into()),
                ("service|Services|B".into(), "b.exe".into()),
            ]),
            ..Default::default()
        };
        let cur = BTreeMap::from([("service|Services|A".to_string(), "evil.exe".to_string())]);
        let ch = diff_autoruns(&old, &cur, Utc::now());
        let rules: Vec<&str> = ch.iter().map(|c| c.rule.as_str()).collect();
        assert_eq!(
            rules,
            vec!["fim.autorun.service.changed", "fim.autorun.service.removed"]
        );
        assert_eq!(ch[0].detail, "a.exe → evil.exe");
    }

    #[test]
    fn severity_depends_on_category() {
        assert_eq!(severity_for("hosts", "modified"), Severity::High);
        assert_eq!(severity_for("etc_config", "modified"), Severity::Medium);
        assert_eq!(severity_for("system_bin", "permissions"), Severity::Low);
    }
}
