//! 繁中原文 → 英文對照表。
//!
//! - key 為 `t!` / `tf!` 傳入的**繁中原字面值**（含 `{name}` 佔位符），查無回 `None`。
//! - clap 的 `about` / 參數說明字面值（`src/cli/args.rs`）也收錄於此，`cli::help_tests` 會檢查是否齊全。
//! - 新增使用者可見字串時，於對應分類補一行即可；不需維護排序。
#![allow(clippy::match_same_arms)]

pub fn lookup(zh: &str) -> Option<&'static str> {
    Some(match zh {
        // ---- error.rs ----
        "設定錯誤：{detail}" => "Config error: {detail}",
        "儲存錯誤：{detail}" => "Storage error: {detail}",
        "掃描失敗：{detail}" => "Scan failed: {detail}",
        "情資錯誤：{detail}" => "Threat-intel error: {detail}",
        "防火牆錯誤：{detail}" => "Firewall error: {detail}",
        "需要系統管理員權限：{detail}" => "Administrator privileges required: {detail}",
        "外部工具錯誤：{detail}" => "External tool error: {detail}",
        "解析錯誤：{detail}" => "Parse error: {detail}",
        "Hub 錯誤：{detail}" => "Hub error: {detail}",
        "Hub 拒絕了這把金鑰" => "The hub rejected this key",
        "MCP 錯誤：{detail}" => "MCP error: {detail}",
        "AI 提供者錯誤：{detail}" => "AI provider error: {detail}",
        "抓包錯誤：{detail}" => "Capture error: {detail}",
        "事件錯誤：{detail}" => "Events error: {detail}",
        "更新失敗：{detail}" => "Update failed: {detail}",
        "服務錯誤：{detail}" => "Service error: {detail}",
        "不支援：{detail}" => "Unsupported: {detail}",
        "逾時（{ms} ms）" => "Timed out after {ms} ms",
        "已取消" => "Cancelled",
        "參數錯誤：{detail}" => "Invalid argument: {detail}",

        // ---- store.rs ----
        "建立目錄失敗：{path}：{e}" => "Failed to create directory {path}: {e}",
        "解析 {file} 失敗：{e}" => "Failed to parse {file}: {e}",
        "讀取 {file} 失敗：{e}" => "Failed to read {file}: {e}",
        "序列化 {file} 失敗：{e}" => "Failed to serialize {file}: {e}",
        "寫入 {file} 失敗：{e}" => "Failed to write {file}: {e}",
        "更新 {file} 失敗：{e}" => "Failed to update {file}: {e}",

        // ---- config.rs ----
        "無法取得使用者設定目錄" => "Unable to determine the user config directory",
        "{key} 需要布林值（true/false）" => "{key} expects a boolean (true/false)",
        "{key} 需要時間長度（例 10m、30s）" => "{key} expects a duration (e.g. 10m, 30s)",
        "不支援的語言：{value}" => "Unsupported language: {value}",
        "未知的設定鍵：{key}；可用：{keys}" => "Unknown config key: {key}; available: {keys}",

        // ---- secrets.rs ----
        "keychain 錯誤：{e}" => "Keychain error: {e}",
        "此平台沒有 keychain 後端" => "No keychain backend on this platform",

        // ---- util ----
        "無法解析時間長度：{value}（例 10m、30s、7d）" => "Cannot parse duration: {value} (e.g. 10m, 30s, 7d)",

        // ---- model ----
        "安全" => "Safe",
        "未知" => "Unknown",
        "可疑" => "Suspicious",
        "危險" => "Dangerous",
        "對外" => "Outbound",
        "對內" => "Inbound",
        "監聽" => "Listening",
        "本機" => "Local",
        "白名單值不可為空" => "Allowlist value cannot be empty",
        "不是合法的 IP：{value}" => "Not a valid IP: {value}",
        "不是合法的 CIDR：{value}" => "Not a valid CIDR: {value}",
        "路徑樣式無效：{e}" => "Invalid path pattern: {e}",

        // ---- scan ----
        "此版本沒有掃描器：{id}" => "This build has no scanner named {id}",
        "掃描器相依順序有循環" => "Scanner dependency cycle detected",
        "掃描器 {id} 需要系統管理員權限，已略過" => "Scanner {id} requires administrator privileges; skipped",
        "執行掃描器：{id}" => "Running scanner: {id}",
        "掃描器 {id} 失敗：{e}" => "Scanner {id} failed: {e}",

        // ---- cli/guard.rs ----
        "此動作會改變系統，未執行：{action}。確認無誤請加 --yes{extra}" => {
            "This action changes the system and was NOT executed: {action}. Add --yes{extra} to confirm"
        }
        "此為高破壞動作，未執行：{action}。請再加 --force 確認" => {
            "This is a destructive action and was NOT executed: {action}. Add --force to confirm"
        }

        // ---- cli/render.rs ----
        "序列化失敗：{e}" => "Serialization failed: {e}",
        "掃描完成：{n} 筆發現（嚴重 {crit}／高 {high}／中 {med}／低 {low}／資訊 {info}）；總分 {score}" => {
            "Scan finished: {n} findings (critical {crit} / high {high} / medium {med} / low {low} / info {info}); overall score {score}"
        }
        "面向分數：連線 {c}、曝露 {e}、漏洞 {v}、硬化 {h}；掃描器：{s}" => {
            "Category scores: connections {c}, exposure {e}, vulnerabilities {v}, hardening {h}; scanners: {s}"
        }
        "注意：部分資料因權限不足而缺失（以管理員身分重跑可取得完整結果）" => {
            "Note: some data is missing due to insufficient privileges (re-run as administrator for complete results)"
        }
        "（白名單）" => "(allowlisted)",
        "嚴重度" => "Severity",
        "掃描器" => "Scanner",
        "標題" => "Title",
        "細節" => "Detail",
        "標籤" => "Tags",

        // ---- cli/version_cmd.rs ----
        "版本檢查將隨 self-update 功能一起提供" => "Version check ships together with self-update",

        // ---- cli/config_cmd.rs ----
        "設定目錄：{dir}" => "Config directory: {dir}",
        "已設定 {key} = {value}" => "Set {key} = {value}",

        // ---- cli/allowlist_cmd.rs ----
        "新增白名單 {value}" => "add allowlist entry {value}",
        "已加入白名單：{id}（{kind}）{value}" => "Added to allowlist: {id} ({kind}) {value}",
        "移除白名單 {entry}" => "remove allowlist entry {entry}",
        "已移除：{entry}" => "Removed: {entry}",
        "找不到條目：{entry}" => "Entry not found: {entry}",
        "白名單是空的" => "The allowlist is empty",
        "種類" => "Kind",
        "值" => "Value",
        "備註" => "Note",
        "加入時間" => "Added",

        // ---- cli/baseline_cmd.rs ----
        "以目前狀態更新基準線" => "update the baseline from the current state",
        "基準線已更新：{l} 個 listener、{p} 個網路行程、{d} 個目的地、{f} 筆 finding" => {
            "Baseline updated: {l} listeners, {p} network processes, {d} destinations, {f} findings"
        }
        "尚無基準線；先執行 asa baseline save --yes" => "No baseline yet; run asa baseline save --yes first",
        "與基準線無差異" => "No differences from the baseline",
        "新 listener：{proto} {port}（{bind}）{exe}" => "New listener: {proto} {port} ({bind}) {exe}",
        "新的網路行程：{exe}" => "New process with network activity: {exe}",
        "新目的地：{dest}" => "New destination: {dest}",
        "新 finding：{id}" => "New finding: {id}",
        "已消失的 finding：{id}" => "Resolved finding: {id}",

        // ---- cli/scan_cmd.rs ----
        "設定裡有未知的掃描器：{id}" => "Unknown scanner in config: {id}",
        "報告已寫入 {path}" => "Report written to {path}",
        "基準線已更新" => "Baseline updated",

        // ---- cli/doctor_cmd.rs ----
        "設定目錄可寫" => "Config directory writable",
        "系統管理員權限" => "Administrator privileges",
        "是（可取得完整結果與執行防火牆動作）" => "Yes (full results and firewall actions available)",
        "否（部分掃描結果受限；防火牆動作會按需請求提權）" => {
            "No (some scan results are limited; firewall actions will request elevation on demand)"
        }
        "hub 註冊" => "Hub enrollment",
        "未註冊（asa enroll <HUB_URL> --key …）" => "Not enrolled (asa enroll <HUB_URL> --key …)",
        "密鑰後端：{b}" => "secrets backend: {b}",
        "檢查" => "Check",
        "結果" => "Result",
        "外部工具" => "External tool",
        "路徑" => "Path",
        "用途" => "Purpose",
        "未找到" => "not found",
        "port 探測（選用）" => "port probing (optional)",
        "套件漏洞外掃（選用）" => "package vulnerability scanner (optional)",
        "Claude Code CLI（AI 分析）" => "Claude Code CLI (AI analysis)",
        "Codex CLI（AI 分析）" => "Codex CLI (AI analysis)",
        "防火牆 / 事件 / 清單查詢" => "firewall / events / inventory queries",
        "Windows 事件日誌" => "Windows Event Log",
        "pf 防火牆" => "pf firewall",
        "統一日誌" => "unified log",
        "每行程流量（flow-lite）" => "per-process traffic (flow-lite)",
        "硬化稽核（選用）" => "hardening audit (optional)",
        "nftables 防火牆" => "nftables firewall",
        "iptables 防火牆（退回）" => "iptables firewall (fallback)",
        "ufw 防火牆" => "ufw firewall",
        "firewalld 防火牆" => "firewalld firewall",
        "systemd 日誌" => "systemd journal",
        "每 socket 流量（flow-lite）" => "per-socket traffic (flow-lite)",

        // ---- cli/args.rs：about / help ----
        "AI Security Agent：防禦型資安掃描 agent（連線判定、威脅情資、防火牆、漏洞、硬化、流量、事件、MCP）" => {
            "AI Security Agent: defensive security scanner (connection verdicts, threat intel, firewall, vulnerabilities, hardening, traffic, events, MCP)"
        }
        "介面語言（zh-TW / en）" => "UI language (zh-TW / en)",
        "確認執行會改變系統的動作（否則只預演）" => "Confirm actions that change the system (otherwise dry-run only)",
        "高破壞動作的二次確認" => "Second confirmation for destructive actions",
        "以 JSON 輸出" => "Output as JSON",
        "設定目錄（預設 ASA_CONFIG_DIR 或使用者設定目錄下的 ai-security-agent）" => {
            "Config directory (default: ASA_CONFIG_DIR or ai-security-agent under the user config directory)"
        }
        "安靜模式（不印進度）" => "Quiet mode (no progress output)",
        "顯示版本；--check 查 GitHub 是否有新版" => "Show version; --check looks for a newer GitHub release",
        "查詢 GitHub Release 是否有新版" => "Check GitHub Releases for a newer version",
        "檢查環境：權限、外部工具、情資新鮮度、hub 連線、AI 用戶端" => {
            "Check the environment: privileges, external tools, feed freshness, hub connectivity, AI clients"
        }
        "執行掃描並輸出報告" => "Run a scan and print the report",
        "設定檔" => "Configuration",
        "白名單（ip / cidr / 行程路徑 / 網域 / 規則）" => "Allowlist (ip / cidr / process path / domain / rule)",
        "基準線：記住目前狀態，之後只標出新增項目" => "Baseline: remember the current state so later scans flag only new items",
        "要跑的掃描器（逗號分隔；預設全部可用）" => "Scanners to run (comma-separated; default: all available)",
        "把報告寫到檔案" => "Write the report to a file",
        "掃描後把目前狀態存成基準線" => "Save the current state as the baseline after scanning",
        "不做任何線上查詢" => "Do not perform any online lookups",
        "以表格輸出（預設）" => "Output as a table (default)",
        "顯示目前設定" => "Show the current configuration",
        "設定單一鍵值（例：scan.interval 15m）" => "Set one key (e.g. scan.interval 15m)",
        "鍵名（lang、scan.interval、intel.allow_noncommercial …）" => "Key (lang, scan.interval, intel.allow_noncommercial …)",
        "顯示設定目錄路徑" => "Print the config directory path",
        "新增白名單條目（自動推斷種類，或用 --kind 指定）" => "Add an allowlist entry (kind is inferred, or set --kind)",
        "值：IP、CIDR、行程路徑 glob、網域（*.example.com）、規則（connections.risky_port:3389）" => {
            "Value: IP, CIDR, process path glob, domain (*.example.com) or rule (connections.risky_port:3389)"
        }
        "移除條目（以 id 或值）" => "Remove an entry (by id or value)",
        "條目 id 或原值" => "Entry id or original value",
        "列出全部條目" => "List all entries",
        "以目前狀態建立 / 併入基準線" => "Create or merge the baseline from the current state",
        "比對目前狀態與基準線" => "Compare the current state with the baseline",
        "顯示基準線內容" => "Show the baseline contents",

        _ => return None,
    })
}
