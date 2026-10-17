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
        "Hub 拒收這份資料（不會重送）：{detail}" => "The hub rejected this payload (it will not be retried): {detail}",
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
        "尚無基準線；先執行 ai-security-monitor baseline save --yes" => "No baseline yet; run ai-security-monitor baseline save --yes first",
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
        "未註冊（ai-security-monitor enroll <HUB_URL> --key …）" => "Not enrolled (ai-security-monitor enroll <HUB_URL> --key …)",
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
        "AI Security Monitor：防禦型資安監控工具（連線判定、威脅情資、防火牆、漏洞、硬化、流量、事件、MCP）" => {
            "AI Security Monitor: defensive security monitor (connection verdicts, threat intel, firewall, vulnerabilities, hardening, traffic, events, MCP)"
        }
        "介面語言（zh-TW / en）" => "UI language (zh-TW / en)",
        "確認執行會改變系統的動作（否則只預演）" => "Confirm actions that change the system (otherwise dry-run only)",
        "高破壞動作的二次確認" => "Second confirmation for destructive actions",
        "以 JSON 輸出" => "Output as JSON",
        "設定目錄（預設 AI_SECURITY_MONITOR_CONFIG_DIR 或使用者設定目錄下的 ai-security-monitor）" => {
            "Config directory (default: AI_SECURITY_MONITOR_CONFIG_DIR or ai-security-monitor under the user config directory)"
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

        // ---- connections ----
        "部分 socket 無法對應到行程（需要系統管理員權限）" => "Some sockets could not be mapped to a process (administrator privileges required)",
        "列舉 socket 失敗：{e}" => "Failed to enumerate sockets: {e}",
        "未知行程" => "unknown process",
        "對外連到高風險 port {port}（{name}）" => "Outbound connection to risky port {port} ({name})",
        "{process} 連到 {remote}：{rationale}" => "{process} connects to {remote}: {rationale}",
        "確認該行程是否應有此連線；若非預期，封鎖目的地並檢查該行程" => {
            "Confirm the process should make this connection; if unexpected, block the destination and inspect the process"
        }
        "Shell / 腳本程式有對外連線：{process}" => "Shell / script host with an outbound connection: {process}",
        "{process} 連到公網 {remote}；這類程式對外連線常見於反向 shell 或惡意下載" => {
            "{process} connects to public {remote}; outbound traffic from such programs is typical of reverse shells or malicious downloads"
        }
        "檢查該行程的命令列與父行程；非預期則終止並封鎖目的地" => {
            "Inspect the command line and parent process; terminate it and block the destination if unexpected"
        }
        "暫存／下載目錄的程式有網路連線：{process}" => "Program in a temp/download directory has network activity: {process}",
        "執行檔位於暫存或下載目錄，並連到 {remote}；惡意程式常從這類位置執行" => {
            "The executable lives in a temp or download directory and connects to {remote}; malware often runs from such locations"
        }
        "確認該執行檔來源與雜湊；非預期則隔離檔案並封鎖目的地" => {
            "Verify the executable's origin and hash; quarantine the file and block the destination if unexpected"
        }
        "規律回連（疑似 beacon）：{remote}" => "Periodic reconnects (possible beacon): {remote}",
        "{process} 每約 {period} 秒重新連到 {remote}（{n} 次，抖動 {jitter}）；C2 常以固定週期回報" => {
            "{process} reconnects to {remote} about every {period} s ({n} times, jitter {jitter}); C2 implants often check in on a fixed period"
        }
        "用 AI 解讀此目的地與行程；非已知服務則封鎖並進一步鑑識" => {
            "Ask the AI to explain this destination and process; block it and investigate further unless it is a known service"
        }
        "{name}（{proto} {port}）對外監聽" => "{name} ({proto} {port}) is listening on external interfaces",
        "{process} 綁在 {bind}：{rationale}" => "{process} is bound to {bind}: {rationale}",
        "若不需對外提供，改綁 127.0.0.1 或用防火牆只允許特定來源" => {
            "If it need not be reachable externally, bind to 127.0.0.1 or restrict sources with the firewall"
        }
        "以防火牆封鎖對內 {proto} {port}" => "Block inbound {proto} {port} with the firewall",
        "基準線外的新 listener：{proto} {port}" => "New listener not in the baseline: {proto} {port}",
        "{process} 開始監聽 {proto} {port}，基準線中沒有這個 port" => {
            "{process} started listening on {proto} {port}, which is not in the baseline"
        }
        "確認是否為預期服務；是則執行 ai-security-monitor baseline save --yes 納入基準線" => {
            "Confirm it is an expected service; if so, run ai-security-monitor baseline save --yes to add it to the baseline"
        }
        "以防火牆封鎖 {ip}（雙向）" => "Block {ip} with the firewall (both directions)",

        // ---- cli/connections_cmd.rs ----
        "方向" => "Direction",
        "判定" => "Verdict",
        "協定" => "Proto",
        "本機位址" => "Local",
        "遠端" => "Remote",
        "狀態" => "State",
        "行程" => "Process",
        "原因" => "Reasons",
        "共 {n} 筆（{total} 筆原始 socket）" => "{n} rows ({total} raw sockets)",
        "列出連線：方向、判定（安全／未知／可疑／危險）、行程、原因" => {
            "List connections: direction, verdict (safe / unknown / suspicious / dangerous), process, reasons"
        }
        "只看某方向（outbound / inbound / listening / local）" => "Only one direction (outbound / inbound / listening / local)",
        "只看這些判定（逗號分隔：safe,unknown,suspicious,dangerous）" => {
            "Only these verdicts (comma-separated: safe,unknown,suspicious,dangerous)"
        }
        "包含本機對本機與 loopback listener" => "Include local-to-local connections and loopback listeners",
        "持續刷新" => "Keep refreshing",
        "刷新間隔（--watch）" => "Refresh interval (--watch)",
        "比對威脅情資（需先 ai-security-monitor intel update）" => "Match against threat intel (run ai-security-monitor intel update first)",

        // ---- intel ----
        "內建情資登錄格式錯誤：{e}" => "The built-in feed registry is malformed: {e}",
        "自訂情資 id 不合法，已略過：{id}" => "Invalid custom feed id, skipped: {id}",
        "自訂情資 id 與內建重複，已略過：{id}" => "Custom feed id collides with a built-in feed, skipped: {id}",
        "自訂情資必須使用 https 網址，已略過：{id}" => "Custom feeds must use https URLs, skipped: {id}",
        "沒有這個情資來源：{id}" => "No such threat-intel feed: {id}",
        "下載內容是 HTML 網頁而不是清單" => "The download is an HTML page, not a list",
        "此格式不能當清單解析：{format}" => "This format cannot be parsed as a list: {format}",
        "下載情資：{id}" => "Downloading feed: {id}",
        "下載失敗：{url}：{e}" => "Download failed: {url}: {e}",
        "HTTP {status}：{url}" => "HTTP {status}: {url}",
        "檔案超過大小上限：{url}" => "File exceeds the size limit: {url}",
        "沒有可用的下載網址" => "No usable download URL",
        "解壓縮失敗：{e}" => "Decompression failed: {e}",
        "解壓後超過大小上限" => "Decompressed data exceeds the size limit",
        "GeoIP 資料庫格式錯誤：{e}" => "Malformed GeoIP database: {e}",
        "下載內容沒有任何條目（保留舊資料）" => "The download contains no entries (keeping the previous data)",
        "{provider} 查詢失敗：{e}" => "{provider} lookup failed: {e}",
        "{provider} 拒絕了 API key" => "{provider} rejected the API key",
        "{provider} 已達呼叫上限" => "{provider} rate limit reached",
        "{provider} 回應 HTTP {status}" => "{provider} responded with HTTP {status}",
        "{provider} 回應格式錯誤：{e}" => "{provider} returned an unexpected payload: {e}",
        "{provider} 今日查詢額度已用完（{n}）" => "{provider} daily quota used up ({n})",
        "解析情資 {id} 失敗：{e}" => "Failed to parse feed {id}: {e}",
        "線上名譽服務標記為可疑的 IP：{ip}" => "IP flagged by an online reputation service: {ip}",
        "來自威脅情資列名 IP 的連入：{ip}" => "Inbound connection from a threat-listed IP: {ip}",
        "連到威脅情資列名的 IP：{ip}" => "Connection to a threat-listed IP: {ip}",
        "{process} ↔ {remote}（判定：{verdict}）。來源：{sources}" => "{process} ↔ {remote} (verdict: {verdict}). Sources: {sources}",
        "封鎖此 IP 並檢查相關行程；確認是誤判可加入白名單" => {
            "Block this IP and inspect the related process; add it to the allowlist if it is a false positive"
        }
        "情資 {id} 更新失敗：{e}" => "Feed {id} failed to update: {e}",
        "尚未下載任何威脅情資；執行 ai-security-monitor intel update" => "No threat-intel feeds downloaded yet; run ai-security-monitor intel update",
        "有 {n} 個已啟用的情資來源尚未下載：{ids}" => "{n} enabled feeds have not been downloaded yet: {ids}",

        // ---- cli/intel_cmd.rs ----
        "已更新" => "updated",
        "未變更" => "not modified",
        "仍新鮮" => "still fresh",
        "失敗" => "failed",
        "來源" => "Source",
        "筆數" => "Entries",
        "大小" => "Size",
        "耗時" => "Time",
        "{n} 個來源更新失敗；舊資料仍保留可用" => "{n} feeds failed to update; their previous data is still used",
        "未下載" => "not downloaded",
        "廠商" => "Vendor",
        "距今" => "Age",
        "授權" => "Licence",
        "已啟用：{fresh} 個最新、{stale} 個過期、{missing} 個未下載" => {
            "Enabled: {fresh} fresh, {stale} stale, {missing} not downloaded"
        }
        "類型" => "Kind",
        "網址" => "URL",
        "[NC]＝非商用授權：預設只告警、不用於防火牆封鎖。" => {
            "[NC] = non-commercial licence: alert-only by default, never used for firewall blocking."
        }
        "{ind}（{class}）判定：{verdict}" => "{ind} ({class}) verdict: {verdict}",
        "地理：{country} · AS{asn} {org}" => "Geo: {country} · AS{asn} {org}",
        "沒有命中任何已載入的情資（{n} 個來源）" => "No hits in the loaded threat intel ({n} feeds)",
        "命中" => "Matched",
        "信心" => "Confidence",
        "資料距今" => "Data age",
        "線上名譽：{provider} = {score}（{detail}）" => "Online reputation: {provider} = {score} ({detail})",
        "已知良性清單：{list}" => "Known-good list: {list}",
        "白名單條目：{id}" => "Allowlist entry: {id}",
        "沒有設定任何線上名譽服務的 API key（ai-security-monitor intel key set abuseipdb -）" => {
            "No online reputation API key configured (ai-security-monitor intel key set abuseipdb -)"
        }
        "已啟用 {id}；執行 ai-security-monitor intel update 下載" => "Enabled {id}; run ai-security-monitor intel update to download it",
        "已停用 {id}" => "Disabled {id}",
        "不支援的名譽服務：{id}；可用：{ids}" => "Unsupported reputation service: {id}; available: {ids}",
        "API key 不可為空" => "The API key cannot be empty",
        "已儲存 {id} 的 API key（{backend}）" => "Saved the API key for {id} ({backend})",
        "要讓掃描自動查詢，執行 ai-security-monitor config set intel.online_lookups true" => {
            "To let scans query it automatically, run ai-security-monitor config set intel.online_lookups true"
        }
        "已刪除 {id} 的 API key" => "Deleted the API key for {id}",
        "威脅情資" => "Threat intel",
        "{fresh} 個最新、{stale} 個過期、{missing} 個未下載" => "{fresh} fresh, {stale} stale, {missing} not downloaded",

        // ---- cli/args.rs：intel ----
        "威脅情資：更新、狀態、來源、查詢 IP／網域" => "Threat intel: update, status, sources, IP / domain lookup",
        "下載／更新威脅情資（只抓過期的；--force 全部重抓）" => "Download / refresh threat-intel feeds (only stale ones; --force refetches all)",
        "只更新這些來源 id" => "Only update these feed ids",
        "只用這些來源 id" => "Only use these feed ids",
        "忽略更新間隔，全部重抓" => "Ignore refresh intervals and refetch everything",
        "顯示各來源的筆數、更新時間與狀態" => "Show entries, last update and status for each feed",
        "列出所有情資來源（廠商、授權、網址）" => "List all feeds (vendor, licence, URL)",
        "查詢 IP 或網域：命中哪些情資、地理位置、判定" => "Look up an IP or domain: feed hits, geolocation, verdict",
        "IP 或網域" => "IP or domain",
        "也查詢已設定 API key 的線上名譽服務" => "Also query online reputation services that have an API key configured",
        "啟用來源" => "Enable a feed",
        "停用來源" => "Disable a feed",
        "來源 id" => "Feed id",
        "設定／刪除線上名譽服務的 API key（存進 keychain）" => "Set / delete API keys for online reputation services (stored in the keychain)",
        "設定 API key（值為 - 時從標準輸入讀取）" => "Set an API key (reads stdin when the value is -)",
        "服務 id（abuseipdb、greynoise-community、crowdsec-cti）" => "Service id (abuseipdb, greynoise-community, crowdsec-cti)",
        "API key；- 表示從標準輸入讀取" => "API key; - reads it from stdin",
        "刪除 API key" => "Delete an API key",

        // ---- util/cmd.rs ----
        "找不到指令：{program}" => "Command not found: {program}",
        "無法執行 {program}：{e}" => "Failed to run {program}: {e}",

        // ---- model/connection.rs：Reachability ----
        "僅本機" => "local only",
        "可連入" => "reachable",
        "可連入（規則：{rule}）" => "reachable (rule: {rule})",
        "已阻擋" => "filtered",

        // ---- firewall ----
        "啟用 {profile} 防火牆設定檔" => "Enable the {profile} firewall profile",
        "啟用主機防火牆" => "Enable the host firewall",
        "作用中網路的 {profile} 防火牆設定檔已關閉" => "The {profile} firewall profile of the active network is turned off",
        "目前連線的網路類別是 {profile}，但此設定檔沒有啟用 Windows 防火牆；本機所有對外監聽的服務都能直接從這個網路連入" => {
            "The current network category is {profile}, but Windows Firewall is off for this profile; every service listening on external interfaces is reachable from this network"
        }
        "啟用該設定檔（Set-NetFirewallProfile -Profile <名稱> -Enabled True），再只為需要的服務開例外" => {
            "Turn the profile on (Set-NetFirewallProfile -Profile <name> -Enabled True) and add exceptions only for the services you need"
        }
        "{profile} 防火牆設定檔已關閉（目前非作用中）" => "The {profile} firewall profile is off (not currently active)",
        "切換到 {profile} 類別的網路時將沒有防火牆保護" => "Networks of the {profile} category will have no firewall protection",
        "啟用該設定檔，避免換網路時曝露" => "Turn the profile on so switching networks does not expose the machine",
        "{profile} 設定檔預設允許所有連入" => "The {profile} profile allows all inbound connections by default",
        "預設連入動作是允許：沒有被規則明確阻擋的連入都會通過" => {
            "The default inbound action is allow: any inbound connection not explicitly blocked gets through"
        }
        "把預設連入動作改為封鎖（Set-NetFirewallProfile -DefaultInboundAction Block）" => {
            "Change the default inbound action to block (Set-NetFirewallProfile -DefaultInboundAction Block)"
        }
        "防火牆規則允許任何連入：{name}" => "A firewall rule allows any inbound traffic: {name}",
        "規則「{name}」不限程式、協定、port 與位址，套用於作用中網路（{profiles}）" => {
            "Rule \"{name}\" is not limited by program, protocol, port or address and applies to the active network ({profiles})"
        }
        "確認是否仍需要；需要的話限縮到特定程式、port 或來源位址" => {
            "Confirm it is still needed; if so, restrict it to a specific program, port or source address"
        }
        "macOS 應用程式防火牆已關閉" => "The macOS application firewall is off",
        "系統設定 → 網路 → 防火牆 為關閉；所有對外監聽的服務都能從網路連入" => {
            "System Settings → Network → Firewall is off; every listening service is reachable from the network"
        }
        "開啟應用程式防火牆（socketfilterfw --setglobalstate on），必要時啟用隱形模式" => {
            "Turn the application firewall on (socketfilterfw --setglobalstate on) and enable stealth mode if needed"
        }
        "macOS 防火牆未開啟隱形模式" => "macOS firewall stealth mode is off",
        "未開啟隱形模式時，主機會回應 ping 與連到已關閉 port 的探測，較容易被掃描發現" => {
            "Without stealth mode the host answers pings and probes to closed ports, making it easier to discover"
        }
        "沒有啟用中的主機防火牆（{backend}）" => "No active host firewall ({backend})",
        "沒有偵測到運作中的 nftables / ufw / firewalld / iptables 規則；對外監聽的服務都能直接連入" => {
            "No active nftables / ufw / firewalld / iptables rules detected; listening services are directly reachable"
        }
        "啟用 ufw 或 firewalld，預設拒絕連入，只開放需要的服務" => {
            "Enable ufw or firewalld with default-deny inbound and open only the services you need"
        }
        "{backend} 預設允許所有連入" => "{backend} allows all inbound connections by default",
        "INPUT 預設政策是接受；沒有被規則明確阻擋的連入都會通過" => {
            "The INPUT default policy is accept; any inbound connection not explicitly blocked gets through"
        }
        "把預設連入政策改為 drop / deny，只放行需要的服務" => "Set the default inbound policy to drop / deny and allow only what you need",
        "防火牆（{backend}）規則需要系統管理員權限才能讀取；部分結果為「未知」" => {
            "Reading firewall ({backend}) rules requires administrator privileges; some results are \"unknown\""
        }
        "讀取 Windows 防火牆設定檔與允許連入規則" => "Read Windows Firewall profiles and inbound allow rules",
        "解析防火牆狀態失敗：{e}" => "Failed to parse firewall state: {e}",
        "無法執行 PowerShell" => "Unable to run PowerShell",
        "讀取應用程式防火牆狀態" => "Read the application firewall state",
        "讀取隱形模式" => "Read stealth mode",
        "讀取「阻擋所有連入」" => "Read \"block all incoming\"",
        "讀取 pf 狀態" => "Read pf status",
        "讀取 ai-security-monitor 封鎖表" => "Read the ai-security-monitor block table",
        "讀取 firewalld 狀態" => "Read firewalld state",
        "讀取 firewalld 預設 zone" => "Read the firewalld default zone",
        "讀取 ufw 狀態" => "Read ufw status",
        "讀取 nftables 規則" => "Read nftables rules",
        "讀取 iptables INPUT 鏈" => "Read the iptables INPUT chain",
        "沒有找到 nft / iptables / ufw / firewall-cmd" => "No nft / iptables / ufw / firewall-cmd found",

        // ---- ports ----
        "{name}（{proto} {port}）可從網路連入" => "{name} ({proto} {port}) is reachable from the network",
        "{process} 綁在 {bind}，防火牆沒有阻擋（{why}）：{rationale}" => {
            "{process} is bound to {bind} and the firewall does not block it ({why}): {rationale}"
        }
        "防火牆關閉或預設允許" => "firewall off or default allow",
        "不需對外就改綁 127.0.0.1；需要的話用防火牆只允許特定來源" => {
            "Bind to 127.0.0.1 if it need not be public; otherwise allow only specific sources in the firewall"
        }
        "{name}（{proto} {port}）綁在所有介面，目前被防火牆阻擋" => "{name} ({proto} {port}) is bound to all interfaces but currently filtered by the firewall",
        "{process} 綁在 {bind}；防火牆擋住了連入，但只要規則變動就會曝露：{rationale}" => {
            "{process} is bound to {bind}; the firewall blocks inbound traffic, but any rule change would expose it: {rationale}"
        }
        "縱深防禦：改綁 127.0.0.1 或內部介面" => "Defence in depth: bind to 127.0.0.1 or an internal interface",
        "{name}（{proto} {port}）對外監聽，無法確認防火牆是否阻擋" => "{name} ({proto} {port}) listens externally; cannot confirm whether the firewall blocks it",
        "{process} 綁在 {bind}；讀不到防火牆規則（以系統管理員身分重跑可確認）：{rationale}" => {
            "{process} is bound to {bind}; firewall rules are unreadable (re-run as administrator to confirm): {rationale}"
        }
        "以系統管理員身分執行 ai-security-monitor fw audit 確認是否可連入" => "Run ai-security-monitor fw audit as administrator to confirm reachability",
        "port 範圍格式錯誤：{part}" => "Invalid port range: {part}",
        "一次最多探測 {n} 個 port" => "At most {n} ports per probe",
        "{ip} 是公網位址；只掃描你擁有或已獲授權的主機，確認後加 --allow-public" => {
            "{ip} is a public address; only scan hosts you own or are authorised to test, then add --allow-public"
        }
        "{ip} 不是可探測的單播位址" => "{ip} is not a probeable unicast address",
        "無法解析主機 {host}：{e}" => "Cannot resolve host {host}: {e}",
        "無法解析主機 {host}" => "Cannot resolve host {host}",
        "nmap TCP connect 掃描" => "nmap TCP connect scan",

        // ---- cli/fw_cmd.rs, ports_cmd.rs ----
        "啟用" => "on",
        "關閉" => "off",
        "後端：{backend} · 狀態：{state} · 預設連入：{din} · 允許連入規則：{n} · ai-security-monitor 規則：{ours}" => {
            "Backend: {backend} · state: {state} · default inbound: {din} · inbound allow rules: {n} · ai-security-monitor rules: {ours}"
        }
        "作用中" => "Active",
        "防火牆設定檔" => "Profile",
        "預設連入" => "Default in",
        "預設連出" => "Default out",
        "部分規則需要系統管理員權限才能讀取（sudo ai-security-monitor fw status）" => "Some rules need administrator privileges to read (sudo ai-security-monitor fw status)",
        "規則" => "Rule",
        "程式" => "Program",
        "來源位址" => "Remote",
        "共 {n} 條允許連入規則（{total} 條含 UWP 應用程式規則；--all 全部列出）" => {
            "{n} inbound allow rules ({total} including UWP app rules; --all lists everything)"
        }
        "綁定" => "Bind",
        "可達性" => "Reachability",
        "風險" => "Risk",
        "服務" => "Service",
        "對外監聽 {exposed} 個（可連入 {open}、已阻擋 {filtered}、未知 {unknown}）；共 {n} 個 listener（--all 含僅本機）" => {
            "{exposed} external listeners (reachable {open}, filtered {filtered}, unknown {unknown}); {n} listeners total (--all includes local-only)"
        }
        "探測 {ip} 的 {n} 個 TCP port…" => "Probing {n} TCP ports on {ip}…",
        "nmap 失敗：{e}" => "nmap failed: {e}",
        "{ip}：{open} 個開啟／已探測 {n} 個" => "{ip}: {open} open / {n} probed",

        // ---- cli/args.rs：fw / ports ----

        "對外 port 與可達性；或探測自己網段的主機" => "External ports and reachability; or probe a host on your own network",
        "防火牆後端、啟用狀態、各設定檔與預設動作" => "Firewall backend, state, profiles and default actions",
        "稽核防火牆與對外 port（產生 finding）" => "Audit the firewall and external ports (produces findings)",
        "列出允許連入的規則" => "List inbound allow rules",
        "包含 UWP 應用程式（每使用者）規則" => "Include UWP app (per-user) rules",
        "包含只綁本機的 listener" => "Include local-only listeners",
        "主動探測這台主機的 TCP port（只限自己或私有網段）" => "Actively probe this host's TCP ports (own machine or private networks only)",
        "要探測的 port（例：22,80,8000-8100；預設常見 70 個）" => "Ports to probe (e.g. 22,80,8000-8100; default: ~70 common ports)",
        "每個連線的逾時" => "Per-connection timeout",
        "改用已安裝的 nmap（-sT）" => "Use the installed nmap instead (-sT)",
        "允許探測公網位址（只限你擁有或已獲授權的主機）" => "Allow probing public addresses (only hosts you own or are authorised to test)",

        // ---- elevate ----
        "此動作需要系統管理員權限，正在請求提權…" => "This action needs administrator privileges; requesting elevation…",
        "提權後的行程沒有回報結果（可能被取消）。也可以手動以管理員身分執行：{cmd}" => {
            "The elevated process did not report back (it may have been cancelled). You can also run it as administrator manually: {cmd}"
        }
        "提權被取消或失敗（UAC）" => "Elevation was cancelled or failed (UAC)",
        "沒有終端機可輸入密碼；請改用 sudo 執行同一個指令" => "No terminal to enter a password; run the same command with sudo",

        // ---- firewall/plan.rs ----
        "封鎖 {n} 個位址（{dir}）：{list}" => "block {n} addresses ({dir}): {list}",
        "解除封鎖 {n} 個位址：{list}" => "unblock {n} addresses: {list}",
        "移除 ai-security-monitor 建立的所有防火牆規則" => "remove every firewall rule created by ai-security-monitor",
        "關閉對內 {proto} {port}" => "close inbound {proto} {port}",
        "取消關閉 {proto} {port}" => "reopen {proto} {port}",
        "同步威脅情資黑名單到防火牆（{n} 個網段）" => "sync the threat-intel blocklist into the firewall ({n} networks)",
        "依期望狀態重新套用 ai-security-monitor 規則" => "re-apply ai-security-monitor rules from the desired state",
        "寫入" => "write",
        "附加到" => "append to",
        "從檔案移除" => "remove from",
        "找不到可寫入的防火牆後端（Linux 需要 nft，或 iptables＋ipset）" => {
            "No writable firewall backend found (Linux needs nft, or iptables + ipset)"
        }
        "不支援的設定檔：{profile}" => "Unsupported profile: {profile}",
        "沒有需要重新套用的規則" => "Nothing to re-apply",
        "偵測到 sshd 正在監聽：先放行 22/tcp，避免遠端連線被切斷" => {
            "sshd is listening: allowing 22/tcp first so remote sessions are not cut off"
        }
        "沒有 ufw 或 firewalld；請先安裝其中一個（apt install ufw / dnf install firewalld）" => {
            "Neither ufw nor firewalld is installed; install one first (apt install ufw / dnf install firewalld)"
        }

        // ---- actions ----
        "套用失敗：{detail}" => "Apply failed: {detail}",

        // ---- cli/fw_cmd.rs (write) ----
        "至少要指定一個 IP 或 CIDR" => "Specify at least one IP or CIDR",
        "不是合法的 IP 或 CIDR：{value}" => "Not a valid IP or CIDR: {value}",
        "拒絕封鎖 {net}：loopback / 未指定 / 多播位址" => "Refusing to block {net}: loopback / unspecified / multicast",
        "拒絕封鎖 {net}：範圍太大" => "Refusing to block {net}: range too wide",
        "{net} 包含本機介面位址，封鎖會切斷自己的連線；確定要做請加 --force" => {
            "{net} contains a local interface address and blocking it would cut this machine off; add --force if you are sure"
        }
        "port 格式錯誤：{spec}（例：tcp/6379）" => "Invalid port spec: {spec} (e.g. tcp/6379)",
        "已套用：{action}（後端 {backend}）" => "Applied: {action} (backend {backend})",
        "預演（未執行）：{action}；後端 {backend}" => "Dry run (not executed): {action}; backend {backend}",
        "已嘗試提權但仍不是系統管理員" => "Elevation was attempted but the process is still not an administrator",
        "提權後的動作失敗" => "The elevated action failed",
        "位址" => "Address",
        "已關閉：{proto} {port}" => "Closed: {proto} {port}",
        "情資黑名單：{n} 個網段（來源：{feeds}；同步於 {at}）" => "Threat-intel blocklist: {n} networks (feeds: {feeds}; synced at {at})",
        "選出 {n} 個網段（合併前 {before}）；略過：保留／私網 {reserved}、過寬 {wide}、本機／白名單／已知良性 {local}、信心不足 {low}" => {
            "Selected {n} networks ({before} before merging); skipped: reserved/private {reserved}, too wide {wide}, local/allowlisted/known-good {local}, low confidence {low}"
        }
        "  · 非商用授權來源不用於封鎖：{ids}（config intel.allow_noncommercial true 可改）" => {
            "  · Non-commercial feeds are not used for blocking: {ids} (set config intel.allow_noncommercial true to change)"
        }
        "  · 超過後端上限，只同步前 {n} 個" => "  · Backend limit reached; only the first {n} are synced",

        // ---- cli/args.rs：fw write ----
        "防火牆：狀態、稽核、規則、封鎖與情資同步" => "Firewall: status, audit, rules, blocking and threat-intel sync",
        "只列 ai-security-monitor 建立的封鎖與期望狀態" => "Only list blocks and desired state created by ai-security-monitor",
        "封鎖 IP / 網段（預設雙向；需要系統管理員權限）" => "Block IPs / networks (both directions by default; needs administrator privileges)",
        "IP 或 CIDR" => "IP or CIDR",
        "原因（寫進規則說明）" => "Reason (stored in the rule description)",
        "只顯示會執行的步驟，不執行" => "Only show the steps that would run; do not execute",
        "解除 ai-security-monitor 建立的封鎖" => "Remove blocks created by ai-security-monitor",
        "IP 或 CIDR（用 --all-asa 時可省略）" => "IP or CIDR (optional with --all-asa)",
        "移除 ai-security-monitor 建立的全部規則" => "Remove every rule created by ai-security-monitor",
        "用防火牆關閉對內 port（例：tcp/6379）" => "Close an inbound port with the firewall (e.g. tcp/6379)",
        "協定/port，例：tcp/6379" => "Protocol/port, e.g. tcp/6379",
        "取消 close-port" => "Undo close-port",
        "啟用防火牆（Windows 可指定設定檔）" => "Enable the firewall (Windows: optionally one profile)",
        "Windows 設定檔：domain / private / public（省略＝全部）" => "Windows profile: domain / private / public (omit = all)",
        "把威脅情資黑名單同步到防火牆（只取公網、高信心、可商用來源）" => {
            "Sync the threat-intel blocklist into the firewall (public ranges, high confidence, commercial-use feeds only)"
        }
        "最低信心（0–100）" => "Minimum confidence (0–100)",
        "最多幾個網段（預設依後端上限）" => "Maximum networks (default: backend limit)",
        "依期望狀態重新套用 ai-security-monitor 規則（pf / nftables 開機後需要）" => "Re-apply ai-security-monitor rules from the desired state (needed after boot for pf / nftables)",

        // ---- hub client ----
        "Hub 網址必須是 https（http 只允許本機或私網；確定要用請加 --insecure-http）：{url}" => {
            "The hub URL must be https (http is only allowed for local or private hosts; add --insecure-http if you are sure): {url}"
        }
        "Hub 網址格式錯誤：{url}" => "Invalid hub URL: {url}",
        "上傳內容超過 hub 上限（{n} bytes）" => "Upload exceeds the hub limit ({n} bytes)",
        "連不上 hub：{e}" => "Cannot reach the hub: {e}",
        "hub 要求稍後再傳（{s} 秒後）" => "The hub asked to retry later (in {s} s)",
        "hub 回應 HTTP {status}：{detail}" => "The hub responded HTTP {status}: {detail}",
        "hub 健康檢查失敗（HTTP {status}）" => "Hub health check failed (HTTP {status})",
        "已註冊 hub 但找不到 client 金鑰；重新執行 ai-security-monitor enroll" => "Enrolled in a hub but the client key is missing; run ai-security-monitor enroll again",
        "client 金鑰不可為空" => "The client key cannot be empty",
        "已註冊到 {url}（{hub} {version}）；agent id {id}" => "Enrolled in {url} ({hub} {version}); agent id {id}",
        "下一步：執行 ai-security-monitor watch 開始定期回報（或 ai-security-monitor watch --once 先試一輪）" => {
            "Next: run ai-security-monitor watch to start reporting (or ai-security-monitor watch --once for a single round)"
        }
        "已取消註冊：{url}" => "Unenrolled from {url}",
        "原本就沒有註冊任何 hub" => "Not enrolled in any hub",
        "未註冊" => "not enrolled",
        "client 金鑰" => "Client key",
        "hub 狀態" => "Hub status",
        "待重送" => "Pending uploads",
        "最後一次掃描" => "Last scan",
        "{at} · {n} 筆發現 · 總分 {score}" => "{at} · {n} findings · score {score}",
        "項目" => "Item",
        "已補送暫存報告 {id}" => "Sent queued report {id}",
        "補送失敗，稍後再試：{e}" => "Queued upload failed; will retry: {e}",
        "這些工具唯讀地檢查使用者這台電腦的資安狀態（連線、威脅情資、防火牆、port、流量、事件與當機）。引用情資命中時一律附上來源廠商與 source_url；不確定就說不確定，不要臆測。" => "These tools inspect the security state of the user's computer read-only (connections, threat intel, firewall, ports, traffic, events and crashes). Always cite the vendor and source_url when quoting an intel hit; say when you are unsure instead of guessing.",
        "要封鎖 IP 或關閉 port 時，先呼叫 preview_action，把計畫完整給使用者看並取得明確同意後，才以 review_token 呼叫 execute_action。" => "To block an IP or close a port, call preview_action first, show the full plan to the user and get explicit consent, then call execute_action with the review_token.",
        "未知的工具：{name}" => "Unknown tool: {name}",
        "這個 MCP 伺服器沒有開放防禦動作（啟動時要加 --allow-actions）" => "This MCP server does not allow defensive actions (start it with --allow-actions)",
        "這個 MCP 伺服器沒有開放 {name}（--tools 限制）" => "This MCP server does not expose {name} (restricted by --tools)",
        "這台電腦目前的網路連線（對外／對內／監聽），每條附判定（安全／未知／可疑／危險）與理由，情資命中會列出來源廠商與網址。" => "This computer's current network connections (outbound / inbound / listening), each with a verdict (safe / unknown / suspicious / dangerous) and reasons; intel hits list the source vendor and URL.",
        "用已下載的威脅情資查一個 IP 或網域：判定、命中的來源（廠商、信心、授權、網址）、國家與 ASN；online=true 時另查已設定 API key 的名譽服務。" => "Look up an IP or domain in the downloaded threat intel: verdict, matching sources (vendor, confidence, license, URL), country and ASN; with online=true also query reputation services that have API keys.",
        "對內的可疑來源：目前連進來且判定可疑／危險的 IP，加上事件記錄裡的暴力破解來源（含情資命中）。" => "Inbound threats: IPs currently connected in that are rated suspicious/dangerous, plus brute-force sources from the event logs (with intel hits).",
        "威脅情資來源清單：廠商、類型、信心、授權（能否商用、是否需標註）、最後下載時間與筆數。" => "Threat-intel sources: vendor, type, confidence, license (commercial use, attribution), last download time and entry count.",
        "執行一次完整或部分掃描（connections、intel、firewall、ports、events），回傳分數與發現清單，並存成最新報告。" => "Run a full or partial scan (connections, intel, firewall, ports, events); returns the score and findings and saves it as the latest report.",
        "最新報告裡的發現（沒有報告會先掃描）：嚴重度、規則、標題、說明、建議與情資來源。" => "Findings from the latest report (scans first if there is none): severity, rule, title, details, recommendation and intel sources.",
        "最新完整報告（JSON；太大時省略證據細節）。" => "The latest full report (JSON; evidence omitted when too large).",
        "監聽中的 port 與實際可達性（只有本機／可從網路連入／已被防火牆擋），附行程與高風險服務說明。" => "Listening ports with real reachability (local only / reachable from the network / blocked by the firewall), with the process and notes for risky services.",
        "防火牆狀態：後端、各設定檔是否開啟、預設連入動作、允許連入的規則與 ai-security-monitor 建立的封鎖規則數。" => "Firewall status: backend, whether each profile is on, default inbound action, inbound allow rules and the number of block rules created by ai-security-monitor.",
        "與基準線比較：新出現的監聽 port、新的連網程式、新的目的地與新發現。" => "Compare with the baseline: new listening ports, new networked programs, new destinations and new findings.",
        "環境檢查：權限、hub 註冊、情資新鮮度、封包擷取工具與外部工具。" => "Environment check: privileges, hub enrollment, intel freshness, capture tools and external tools.",
        "觀察即時流量 N 秒（不抓封包）：各行程連到哪些遠端、新連線、介面流量、高風險 port、週期性連線與情資命中。" => "Watch live traffic for N seconds (no packet capture): which process talks to which remote, new connections, interface traffic, risky ports, beaconing and intel hits.",
        "分析 pcap／pcapng 擷取檔：DNS、TLS SNI、HTTP Host、明文協定、大量上傳、週期性連線、可疑 DNS 與情資命中。" => "Analyze a pcap/pcapng capture: DNS, TLS SNI, HTTP Host, plain-text protocols, large uploads, beaconing, suspicious DNS and intel hits.",
        "事件記錄摘要（預設 7 天）：當機（藍屏代碼與可能原因）、資安事件（暴力破解、新帳號、新服務、清除稽核）、最常見的錯誤。" => "Event log summary (7 days by default): crashes (bugcheck codes and likely causes), security events (brute force, new accounts, new services, cleared audit logs) and the most frequent errors.",
        "當機紀錄（預設 30 天）：藍屏、非預期關機、程式當掉、服務失敗、磁碟與硬體錯誤，附可能原因與處置。" => "Crash history (30 days by default): blue screens, unexpected shutdowns, app crashes, service failures, disk and hardware errors, with likely causes and fixes.",
        "解釋藍屏代碼（例 0x7E）或 Windows 事件 ID（例 41、4625）。" => "Explain a bugcheck code (e.g. 0x7E) or a Windows event ID (e.g. 41, 4625).",
        "預覽防禦動作（block_ip、unblock_ip、close_port、open_port）：回傳確切會執行的指令與審查代碼，不會改任何東西。執行前一定要先給使用者看預覽並取得同意。" => "Preview a defensive action (block_ip, unblock_ip, close_port, open_port): returns the exact commands and a review token without changing anything. Always show the preview to the user and get consent before executing.",
        "以 preview_action 回傳的審查代碼執行動作（單次有效、15 分鐘內）。ai-security-monitor mcp 需以系統管理員身分執行才能套用。" => "Execute an action with the review token from preview_action (single use, within 15 minutes). ai-security-monitor mcp must run as administrator to apply it.",
        "缺少 indicator" => "Missing indicator",
        "還沒有報告；先呼叫 scan" => "No report yet; call scan first",
        "尚無基準線；請使用者先執行 ai-security-monitor baseline save --yes" => "No baseline yet; ask the user to run ai-security-monitor baseline save --yes",
        "缺少 path" => "Missing path",
        "缺少 code" => "Missing code",
        "查無 {code}" => "Nothing found for {code}",
        "缺少 kind" => "Missing kind",
        "缺少或錯誤的 port" => "Missing or invalid port",
        "缺少 ip" => "Missing ip",
        "這個 MCP 伺服器不允許破壞性動作（啟動時要加 --allow-destructive）" => "This MCP server does not allow destructive actions (start it with --allow-destructive)",
        "把上面的計畫給使用者看，取得同意後再以 review_token 呼叫 execute_action（15 分鐘內、單次有效）" => "Show the plan above to the user; after they agree, call execute_action with review_token (within 15 minutes, single use)",
        "審查代碼無效或已過期；請重新 preview_action" => "The review token is invalid or expired; call preview_action again",
        "ai-security-monitor mcp 不是以系統管理員身分執行，無法套用防火牆變更；請使用者以系統管理員身分重新啟動 MCP 伺服器，或在終端機執行 ai-security-monitor fw …" => "ai-security-monitor mcp is not running as administrator and cannot change the firewall; ask the user to restart the MCP server as administrator, or run ai-security-monitor fw … in a terminal",
        "沒有設定 token 時 MCP HTTP 只能綁 127.0.0.1／::1（用 --token 或 AI_SECURITY_MONITOR_MCP_TOKEN）" => "Without a token, MCP HTTP may only bind 127.0.0.1 / ::1 (use --token or AI_SECURITY_MONITOR_MCP_TOKEN)",
        "MCP HTTP 已啟動：http://{addr}/mcp" => "MCP HTTP listening at http://{addr}/mcp",
        "VS Code 請用 --project <資料夾>（寫進 .vscode/mcp.json）" => "For VS Code use --project <folder> (writes .vscode/mcp.json)",
        "設定檔不是合法的 JSON：{e}" => "The config file is not valid JSON: {e}",
        "設定檔最外層必須是 JSON 物件" => "The config file must be a JSON object at the top level",
        "{key} 必須是 JSON 物件" => "{key} must be a JSON object",
        "或" => "or",
        "找不到 {cli}；請先安裝並登入（ai-security-monitor ai status 看詳情）" => "{cli} not found; install it and sign in first (see ai-security-monitor ai status)",
        "找不到 Claude Code 或 Codex CLI；請先安裝其中一個並登入（ai-security-monitor ai status 看詳情）" => "Neither Claude Code nor Codex CLI was found; install one and sign in (see ai-security-monitor ai status)",
        "無法啟動 {cli}：{e}" => "Could not start {cli}: {e}",
        "{cli} 執行失敗：{detail}" => "{cli} failed: {detail}",
        "觀察流量 {d}…" => "Observing traffic for {d}…",
        "還沒有報告，先掃描一次…" => "No report yet; scanning first…",
        "送給 AI 的資料：{n} bytes（可在 ai-security-monitor 設定目錄以外的地方檢查內容）" => "Data sent to the AI: {n} bytes",
        "使用 {cli}（{path}）…" => "Using {cli} ({path})…",
        "AI 回報錯誤（見上方輸出）" => "The AI reported an error (see the output above)",
        "未安裝" => "Not installed",
        "可能未登入" => "Possibly not signed in",
        "版本" => "Version",
        "登入" => "Signed in",
        "安裝：npm i -g @anthropic-ai/claude-code（登入：claude）或 npm i -g @openai/codex（登入：codex login）" => "Install: npm i -g @anthropic-ai/claude-code (sign in: claude) or npm i -g @openai/codex (sign in: codex login)",
        "找不到使用者家目錄" => "Home directory not found",
        "把 ai-security-monitor MCP 伺服器寫進 {client} 設定（{path}）" => "Add the ai-security-monitor MCP server to the {client} config ({path})",
        "已寫入 {path}（原檔備份為 .bak）；重新啟動 {client} 後生效" => "Wrote {path} (previous file backed up as .bak); restart {client} to apply",
        "從 {client} 設定移除 ai-security-monitor（{path}）" => "Remove ai-security-monitor from the {client} config ({path})",
        "已從 {path} 移除 ai-security-monitor" => "Removed ai-security-monitor from {path}",
        "位址格式錯誤：{addr}（例 127.0.0.1:7870）" => "Invalid address: {addr} (e.g. 127.0.0.1:7870)",
        "MCP 伺服器：讓 Claude Code／Codex／Cursor／VS Code 查這台電腦的資安狀態" => "MCP server: let Claude Code / Codex / Cursor / VS Code inspect this computer's security state",
        "用 Claude Code 或 Codex CLI 分析：問問題、解讀報告、流量與當機" => "Analyze with Claude Code or Codex CLI: ask questions, interpret reports, traffic and crashes",
        "改用 HTTP（例：127.0.0.1:7870）；預設 stdio" => "Serve over HTTP instead (e.g. 127.0.0.1:7870); stdio by default",
        "HTTP 模式的 Bearer token（沒設時只能綁本機）" => "Bearer token for HTTP mode (without it only loopback is allowed)",
        "只開放這些工具（逗號分隔）" => "Expose only these tools (comma-separated)",
        "開放防禦動作（preview_action → 使用者同意 → execute_action）" => "Allow defensive actions (preview_action → user consent → execute_action)",
        "也開放破壞性動作（關閉 port）" => "Also allow destructive actions (closing ports)",
        "印出給 AI 用戶端的設定片段" => "Print the config snippet for an AI client",
        "AI 用戶端" => "AI client",
        "設定裡加上 --allow-actions" => "Add --allow-actions to the config",
        "寫入 AI 用戶端設定（需要 --yes；原檔備份為 .bak）" => "Write the AI client config (needs --yes; previous file backed up as .bak)",
        "寫進專案設定（.mcp.json、.vscode/mcp.json…）而不是使用者設定" => "Write the project config (.mcp.json, .vscode/mcp.json…) instead of the user config",
        "從 AI 用戶端設定移除 ai-security-monitor（需要 --yes）" => "Remove ai-security-monitor from an AI client config (needs --yes)",
        "專案資料夾" => "Project folder",
        "問 AI 一個資安問題（它會透過 ai-security-monitor 的 MCP 工具自己查這台電腦）" => "Ask the AI a security question (it inspects this computer itself through ai-security-monitor's MCP tools)",
        "問題" => "Question",
        "請 AI 解讀最新報告；--traffic／--events 改看流量或事件" => "Have the AI interpret the latest report; --traffic / --events look at traffic or events instead",
        "報告檔（預設最新一份）" => "Report file (latest by default)",
        "改看即時流量（觀察 --duration）" => "Look at live traffic instead (observe for --duration)",
        "改看事件與當機（近 --since）" => "Look at events and crashes instead (last --since)",
        "流量觀察時間" => "How long to observe traffic",
        "事件範圍" => "Event time range",
        "檢查 Claude Code／Codex CLI 是否安裝與登入" => "Check whether Claude Code / Codex CLI are installed and signed in",
        "用哪個 AI（claude／codex；預設找得到哪個用哪個）" => "Which AI to use (claude / codex; default: whichever is found)",
        "模型名稱（交給 CLI）" => "Model name (passed to the CLI)",
        "最多幾回合工具呼叫" => "Maximum number of tool-calling turns",
        "逾時" => "Timeout",
        "以系統服務身分執行（服務管理器使用）" => "Run as a system service (used by the service manager)",
        "更新或乾淨重灌顯示卡驅動，檢查顯示卡溫度與電源" => "Update or clean-install the GPU driver; check GPU temperature and power",
        "近 {days} 天系統記憶體不足警告 {n} 次" => "{n} low-memory warning(s) in the last {days} days",
        "近 {days} 天顯示卡驅動重設 {n} 次" => "{n} GPU driver reset(s) in the last {days} days",
        "事件與當機原因：藍屏、非預期關機、程式當掉、資安事件（Windows 事件、Linux journal、macOS 當機報告）" => "Events and crash causes: blue screens, unexpected shutdowns, app crashes, security events (Windows events, Linux journal, macOS crash reports)",
        "看多久以前到現在（例：7d、30d，最多 90d）" => "How far back to look (e.g. 7d, 30d; at most 90d)",
        "只看當機：藍屏、非預期關機、程式當掉、服務失敗、磁碟與硬體錯誤" => "Crashes only: blue screens, unexpected shutdowns, app crashes, service failures, disk and hardware errors",
        "看多久以前到現在" => "How far back to look",
        "解釋藍屏代碼（例 0x7E）或事件 ID（例 41、4625）" => "Explain a bugcheck code (e.g. 0x7E) or an event ID (e.g. 41, 4625)",
        "藍屏代碼或事件 ID" => "Bugcheck code or event ID",
        "分析檔案：.evtx（Windows）、journalctl -o json 輸出、macOS .ips／.panic、Windows .dmp" => "Analyze a file: .evtx (Windows), journalctl -o json output, macOS .ips/.panic, Windows .dmp",
        "檔案路徑" => "File path",
        "Security 事件記錄（失敗登入、帳號與群組變更、稽核清除）" => "Security event log (failed logons, account and group changes, audit log clearing)",
        "Minidump 資料夾（藍屏 dump 檔）" => "Minidump folder (blue-screen dump files)",
        "systemd journal（加入 systemd-journal 群組或用 sudo 執行）" => "systemd journal (join the systemd-journal group or run with sudo)",
        ".evtx 只能在 Windows 上分析（需要 Get-WinEvent）" => ".evtx files can only be analyzed on Windows (needs Get-WinEvent)",
        "不是 Windows kernel dump（只支援 Minidump／MEMORY.DMP）" => "Not a Windows kernel dump (only Minidump / MEMORY.DMP are supported)",
        "無法辨識的檔案：支援 .evtx、journalctl -o json 輸出、.ips／.panic、.dmp" => "Unrecognized file: supported are .evtx, journalctl -o json output, .ips/.panic, .dmp",
        "事件查詢輸出無法解析：{e}" => "Could not parse the event query output: {e}",
        "讀取事件記錄失敗：{e}" => "Failed to read the event logs: {e}",
        "近 {days} 天藍屏 {n} 次" => "{n} blue screen(s) in the last {days} days",
        "近 {days} 天非預期關機 {n} 次" => "{n} unexpected shutdown(s) in the last {days} days",
        "近 {days} 天磁碟錯誤 {n} 次" => "{n} disk error(s) in the last {days} days",
        "近 {days} 天硬體錯誤（WHEA／MCE）{n} 次" => "{n} hardware error(s) (WHEA/MCE) in the last {days} days",
        "近 {days} 天 kernel panic {n} 次" => "{n} kernel panic(s) in the last {days} days",
        "近 {days} 天 kernel oops {n} 次" => "{n} kernel oops in the last {days} days",
        "近 {days} 天記憶體不足強制結束行程 {n} 次" => "{n} out-of-memory kill(s) in the last {days} days",
        "近 {days} 天 {kind} {n} 次" => "{n} × {kind} in the last {days} days",
        "查無這個代碼的說明；用 ai-security-monitor ai analyze --events 請 AI 協助判讀" => "No description for this code; use ai-security-monitor ai analyze --events to have the AI interpret it",
        "立即備份；檢查磁碟 SMART 狀態與連接線，必要時更換磁碟" => "Back up now; check the disk’s SMART status and cables, and replace the disk if needed",
        "恢復 BIOS 預設、取消超頻，檢查溫度、記憶體與電源" => "Restore BIOS defaults, remove overclocks, check temperatures, RAM and the PSU",
        "確認是否斷電或長按電源鍵；若伴隨藍屏請看藍屏項目" => "Check for power loss or a held power button; if blue screens accompany it, see the blue-screen finding",
        "找出吃記憶體的行程（見事件），調整服務記憶體上限或增加記憶體" => "Find the memory-hungry process (see the events), cap service memory or add RAM",
        "查看事件詳細內容；可用 ai-security-monitor ai analyze --events 請 AI 協助判讀" => "Review the event details; ai-security-monitor ai analyze --events can help interpret them",
        "{name} 近 {days} 天當掉 {n} 次" => "{name} crashed {n} times in the last {days} days",
        "服務 {name} 近 {days} 天失敗 {n} 次" => "Service {name} failed {n} times in the last {days} days",
        "出錯模組：{m}" => "Faulting module: {m}",
        "更新或重新安裝該程式；持續發生可用 ai-security-monitor ai analyze --events 請 AI 協助判讀" => "Update or reinstall the program; if it keeps happening, ai-security-monitor ai analyze --events can help",
        "{ip} 嘗試登入失敗 {n} 次（疑似暴力破解）" => "{ip} failed to log on {n} times (likely brute force)",
        "封鎖來源 IP；關閉不需要對外的 RDP／SSH，改用 VPN 或限制來源；啟用帳號鎖定原則" => "Block the source IP; close RDP/SSH to the internet unless needed, use a VPN or source restrictions; enable an account lockout policy",
        "從公網 {ip} 遠端登入成功（{user}）" => "Successful remote logon from public IP {ip} ({user})",
        "確認是否為本人；不是的話立刻改密碼、檢查新帳號與排程，並封鎖來源" => "Confirm it was you; if not, change the password now, check for new accounts and scheduled tasks, and block the source",
        "有帳號被加入管理員群組：{user}" => "An account was added to an administrators group: {user}",
        "確認是否為授權的變更；不是的話移除該成員並調查登入紀錄" => "Confirm the change was authorized; if not, remove the member and review logons",
        "建立了新帳號：{user}" => "A new account was created: {user}",
        "確認是否為授權的變更" => "Confirm the change was authorized",
        "安裝了新服務：{detail}" => "A new service was installed: {detail}",
        "確認服務來源；執行檔在暫存或使用者資料夾特別可疑" => "Check where the service came from; executables in temp or user folders are especially suspicious",
        "建立了排程工作：{detail}" => "A scheduled task was created: {detail}",
        "確認排程內容與建立者" => "Check the task’s action and who created it",
        "安全性稽核紀錄被清除" => "The security audit log was cleared",
        "清除稽核紀錄是入侵後湮滅證據的典型動作：調查同時段的登入與變更" => "Clearing the audit log is a classic cover-up after an intrusion: investigate logons and changes around that time",
        "事件記錄被清除：{detail}" => "An event log was cleared: {detail}",
        "確認是誰、為何清除" => "Find out who cleared it and why",
        "Defender 偵測到威脅：{detail}" => "Defender detected a threat: {detail}",
        "確認 Defender 已隔離；檢查該檔案的來源與同時段的連線" => "Make sure Defender quarantined it; check where the file came from and the connections around that time",
        "Defender 即時保護被關閉" => "Defender real-time protection was turned off",
        "重新開啟即時保護並確認是誰關閉的" => "Turn real-time protection back on and find out who disabled it",
        "以防火牆封鎖 {ip}（連入）" => "Block {ip} with the firewall (inbound)",
        "需要系統管理員權限才能讀取：{what}" => "Administrator rights are needed to read: {what}",
        "藍屏" => "Blue screen",
        "非預期關機" => "Unexpected shutdown",
        "程式當掉" => "App crash",
        "程式沒回應" => "App hang",
        "服務失敗" => "Service failure",
        "磁碟錯誤" => "Disk error",
        "硬體錯誤" => "Hardware error",
        "更新失敗" => "Update failure",
        "顯示卡重設" => "GPU reset",
        "記憶體不足" => "Low memory",
        "暴力破解" => "Brute force",
        "NTLM 驗證失敗爆量" => "NTLM failure burst",
        "帳號被鎖定" => "Account locked out",
        "NTLM 驗證失敗 {n} 次（{detail}）" => "{n} failed NTLM authentications ({detail})",
        "找出該工作站上用舊密碼或錯誤密碼的程式、服務或對應磁碟機；不是的話視為密碼噴灑並調查" => "Find the app, service or mapped drive on that workstation using an old or wrong password; if there is none, treat it as password spraying and investigate",
        "帳號被鎖定：{user}（來源 {detail}）" => "Account locked out: {user} (source {detail})",
        "確認是本人打錯密碼還是有人在猜；同時段的登入失敗來源可以一起封鎖" => "Check whether the user mistyped or someone is guessing; failed-logon sources from the same time can be blocked too",
        "公網遠端登入" => "Remote logon from internet",
        "加入管理員群組" => "Added to admins",
        "加入群組" => "Added to group",
        "新帳號" => "New account",
        "啟用帳號" => "Account enabled",
        "新服務" => "New service",
        "新排程" => "New scheduled task",
        "稽核紀錄被清除" => "Audit log cleared",
        "事件記錄被清除" => "Event log cleared",
        "Defender 偵測" => "Defender detection",
        "Defender 被關閉" => "Defender disabled",
        "讀取近 {days} 天的事件…" => "Reading events from the last {days} days…",
        "近 {days} 天：讀了 {n} 筆事件（嚴重 {crit}、錯誤 {err}、警告 {warn}）" => "Last {days} days: read {n} events ({crit} critical, {err} errors, {warn} warnings)",
        "⚠ 需要系統管理員權限才能讀取：{what}" => "⚠ Administrator rights are needed to read: {what}",
        "沒有當機或非預期關機紀錄。" => "No crashes or unexpected shutdowns.",
        "當機與錯誤" => "Crashes and errors",
        "時間" => "Time",
        "代碼／名稱" => "Code / name",
        "模組／程式" => "Module / program",
        "資安事件" => "Security events",
        "來源／帳號" => "Source / account",
        "最後" => "Last",
        "最常出現的錯誤" => "Most frequent errors",
        "訊息" => "Message",
        "查無 {code}：可用藍屏代碼（例 0x7E、0x124）或事件 ID（例 41、4625）" => "Nothing found for {code}: use a bugcheck code (e.g. 0x7E, 0x124) or an event ID (e.g. 41, 4625)",
        "內建封包擷取（轉成 pcapng 給 ai-security-monitor traffic analyze）" => "Built-in packet capture (convert to pcapng for ai-security-monitor traffic analyze)",
        "Wireshark 命令列擷取（選用）" => "Wireshark command-line capture (optional)",
        "封包擷取（存成 pcap 給 ai-security-monitor traffic analyze）" => "Packet capture (save a pcap for ai-security-monitor traffic analyze)",
        "Npcap 已安裝：可用 Wireshark 擷取後 ai-security-monitor traffic analyze <檔案>" => "Npcap is installed: capture with Wireshark, then ai-security-monitor traffic analyze <file>",
        "可用內建 pktmon：pktmon start --capture → pktmon stop → pktmon etl2pcap PktMon.etl（需系統管理員）" => "Built-in pktmon available: pktmon start --capture → pktmon stop → pktmon etl2pcap PktMon.etl (administrator)",
        "這版 pktmon 不能轉 pcapng：pktmon start --capture → pktmon stop，再把 PktMon.etl 拿到 Windows 10 2004／Server 2022 以上用 pktmon etl2pcap 轉檔；或安裝 Npcap／Wireshark：https://npcap.com" => "This pktmon cannot write pcapng: pktmon start --capture → pktmon stop, then convert PktMon.etl with pktmon etl2pcap on Windows 10 2004 / Server 2022 or later; or install Npcap/Wireshark: https://npcap.com",
        "這版 Windows 沒有 pktmon：netsh trace start capture=yes tracefile=cap.etl → netsh trace stop，再用 etl2pcapng（https://github.com/microsoft/etl2pcapng）轉檔；或安裝 Npcap／Wireshark：https://npcap.com" => "This Windows has no pktmon: netsh trace start capture=yes tracefile=cap.etl → netsh trace stop, then convert with etl2pcapng (https://github.com/microsoft/etl2pcapng); or install Npcap/Wireshark: https://npcap.com",
        "沒有擷取工具；即時模式（ai-security-monitor traffic）仍可用。要逐封包分析請安裝 Npcap／Wireshark：https://npcap.com" => "No capture tool; live mode (ai-security-monitor traffic) still works. For packet-level analysis install Npcap / Wireshark: https://npcap.com",
        "可用 tcpdump：sudo tcpdump -w cap.pcap → ai-security-monitor traffic analyze cap.pcap" => "tcpdump available: sudo tcpdump -w cap.pcap → ai-security-monitor traffic analyze cap.pcap",
        "沒有 tcpdump；即時模式（ai-security-monitor traffic）仍可用" => "No tcpdump; live mode (ai-security-monitor traffic) still works",
        "封包擷取" => "Packet capture",
        "流量：即時觀察連線（免抓包）或分析 pcap／pcapng 檔" => "Traffic: watch live connections (no capture) or analyze a pcap/pcapng file",
        "觀察多久（即時模式）" => "How long to observe (live mode)",
        "多久讀一次連線表" => "How often to read the connection table",
        "分析 Wireshark／tcpdump 存的 .pcap／.pcapng（DNS、TLS SNI、明文協定、大量上傳、週期性連線、情資命中）" => "Analyze a .pcap/.pcapng saved by Wireshark or tcpdump (DNS, TLS SNI, plain-text protocols, large uploads, beaconing, intel hits)",
        "擷取檔路徑" => "Capture file path",
        "最多處理幾個封包" => "Maximum number of packets to process",
        "觀察 {d} 中（每 {e} 讀一次連線表；不抓封包、不需要系統管理員權限）…" => "Observing for {d} (reading the connection table every {e}; no packet capture, no admin rights needed)…",
        "情資命中" => "Intel hit",
        "明文協定" => "Plain-text protocol",
        "高風險 port" => "Risky port",
        "大量上傳" => "Large upload",
        "週期性連線" => "Beaconing",
        "可疑 DNS" => "Suspicious DNS",
        "模式 {mode} · 來源 {source} · {secs} 秒 · {flows} 條流 · 送出 {out} · 收到 {inn}" => "Mode {mode} · source {source} · {secs}s · {flows} flows · sent {out} · received {inn}",
        "警示" => "Alerts",
        "對象" => "Target",
        "說明" => "Details",
        "沒有發現可疑流量。" => "No suspicious traffic found.",
        "主要對象" => "Top destinations",
        "網域" => "Domain",
        "送出／收到" => "Sent / received",
        "連線" => "Connections",
        "情資" => "Intel",
        "各行程" => "By process",
        "遠端數" => "Remotes",
        "DNS 查詢" => "DNS queries",
        "名稱" => "Name",
        "次數" => "Count",
        "回應" => "Answers",
        "TLS SNI／HTTP Host" => "TLS SNI / HTTP Host",
        "網路介面" => "Network interfaces",
        "介面" => "Interface",
        "收到" => "Received",
        "送出" => "Sent",
        "高" => "High",
        "中" => "Medium",
        "低" => "Low",
        "無法開啟 {path}：{e}" => "Cannot open {path}: {e}",
        "不是 pcap／pcapng 檔：{e}" => "Not a pcap/pcapng file: {e}",
        "讀取 pcap 失敗：{e}" => "Failed to read the capture: {e}",
        "簽章不符（可能被竄改，或 hub 換了簽署金鑰；請重新註冊）" => "Signature mismatch (tampered, or the hub changed its signing key; enroll again)",
        "這個動作不是給這台 agent 的" => "This action is addressed to a different agent",
        "動作已過期" => "The action has expired",
        "本機設定不允許遠端執行 {kind}" => "Local settings do not allow {kind} as a remote action",
        "本機設定不允許破壞性的遠端動作" => "Local settings do not allow destructive remote actions",
        "缺少 ip 參數" => "Missing ip parameter",
        "{net} 在本機白名單（{id}），不封鎖" => "{net} is on the local allowlist ({id}); not blocking",
        "{net} 屬於已知良好清單（{list}），不封鎖" => "{net} is on a known-good list ({list}); not blocking",
        "proto 必須是 tcp 或 udp" => "proto must be tcp or udp",
        "port 參數錯誤" => "Invalid port parameter",
        "不支援的動作：{kind}" => "Unsupported action: {kind}",
        "注意：hub 沒有提供遠端動作金鑰（hub 版本太舊，或這台 agent 的身分未能釘選），遠端動作不會執行" => "Note: the hub did not provide a remote-action key (old hub, or this agent identity could not be pinned); remote actions will not run",
        "已啟用遠端動作：hub 核准的封鎖會在這台機器執行（需以系統管理員／服務模式執行 ai-security-monitor watch）" => "Remote actions enabled: blocks approved on the hub will run on this machine (ai-security-monitor watch must run as administrator or as a service)",
        "遠端動作：已啟用" => "Remote actions: enabled",
        "遠端動作：hub 沒有提供驗章金鑰，暫不執行" => "Remote actions: the hub did not provide a verification key; not running them",
        "領取遠端動作失敗：{e}" => "Failed to fetch remote actions: {e}",
        "遠端動作 {id}（{kind}）：{result}" => "Remote action {id} ({kind}): {result}",
        "回報遠端動作結果失敗：{e}" => "Failed to report the remote action result: {e}",
        "拒絕執行：{why}" => "Refused: {why}",
        "需要系統管理員權限：請以服務模式（ai-security-monitor service install）或系統管理員身分執行 ai-security-monitor watch" => "Administrator rights required: run ai-security-monitor watch as a service (ai-security-monitor service install) or as administrator",
        "尚未註冊 hub：只在本機掃描（ai-security-monitor enroll <HUB_URL> --key … 後才會上傳）" => {
            "Not enrolled in a hub: scanning locally only (run ai-security-monitor enroll <HUB_URL> --key … to upload)"
        }
        "已連上 {url}（{hub} {version}）" => "Connected to {url} ({hub} {version})",
        "註冊失敗，稍後重試：{e}" => "Registration failed; will retry: {e}",
        "快照已上傳：{n} 條連線（可疑／危險 {bad}）" => "Snapshot uploaded: {n} connections ({bad} suspicious/dangerous)",
        "快照上傳失敗：{e}" => "Snapshot upload failed: {e}",
        "心跳失敗：{e}" => "Heartbeat failed: {e}",
        "快照：{n} 條連線（可疑／危險 {bad}）" => "Snapshot: {n} connections ({bad} suspicious/dangerous)",
        "快照失敗：{e}" => "Snapshot failed: {e}",
        "掃描完成：{n} 筆發現，總分 {score}" => "Scan finished: {n} findings, score {score}",
        "{summary}；已上傳（新 {new}、解決 {resolved}）" => "{summary}; uploaded ({new} new, {resolved} resolved)",
        "{summary}；上傳失敗已暫存：{e}" => "{summary}; upload failed, queued: {e}",
        "掃描失敗：{e}" => "Scan failed: {e}",
        "收到中斷，結束" => "Interrupted; exiting",

        // ---- cli/args.rs：hub ----
        "註冊到 Security Hub（client 金鑰存進 keychain）" => "Enroll in a Security Hub (the client key goes into the keychain)",
        "Hub 網址（https://…；本機或私網可用 http）" => "Hub URL (https://…; http is fine for local or private hosts)",
        "client 金鑰；- 表示從標準輸入讀取" => "Client key; - reads it from stdin",
        "接受 hub 核准的遠端動作（預設關）" => "Accept remote actions approved in the hub (off by default)",
        "允許對公網 hub 使用未加密的 http" => "Allow unencrypted http to a public hub",
        "取消註冊（刪除 hub 設定與金鑰）" => "Unenroll (remove the hub settings and key)",
        "顯示 agent、hub 連線、待重送與最後一次掃描" => "Show the agent, hub connection, pending uploads and last scan",
        "常駐：定期掃描、上傳報告、連線快照與心跳" => "Run continuously: periodic scans, report uploads, connection snapshots and heartbeats",
        "完整掃描間隔（預設取設定 scan.interval）" => "Full scan interval (default: config scan.interval)",
        "連線快照與心跳間隔（預設取設定 scan.snapshot_interval）" => "Snapshot and heartbeat interval (default: config scan.snapshot_interval)",
        "只跑一輪（掃描＋快照＋上傳）就結束" => "Run a single round (scan + snapshot + upload) and exit",
        "不上傳，只在本機掃描" => "Do not upload; scan locally only",

        // vuln
        "尚未下載 CISA KEV（執行 ai-security-monitor intel update），無法標示「已被用於攻擊」的漏洞" => "CISA KEV not downloaded yet (run ai-security-monitor intel update); actively exploited vulnerabilities cannot be flagged",
        "作業系統已停止支援：{product}（{eol}）" => "Operating system is out of support: {product} ({eol})",
        "作業系統即將停止支援：{product}（{eol}，剩 {days} 天）" => "Operating system support ends soon: {product} ({eol}, {days} days left)",
        "停止支援後就不再有安全性更新，新發現的漏洞都不會被修補。" => "After end of support there are no more security updates; newly found vulnerabilities will not be patched.",
        "升級到仍在支援的版本（Windows 用「設定 → Windows Update」，Linux 升級發行版）" => "Upgrade to a supported version (Windows: Settings → Windows Update; Linux: upgrade the distribution release)",
        "已經 {days} 天沒有安裝 Windows 更新" => "No Windows update installed for {days} days",
        "最近一次：{id}（{date}）" => "Most recent: {id} ({date})",
        "到「設定 → Windows Update」檢查並安裝更新" => "Open Settings → Windows Update, check for and install updates",
        "有 {n} 個安全性更新還沒安裝（共 {total} 個待更新）" => "{n} security updates not installed ({total} updates pending)",
        "執行 sudo apt update && sudo apt upgrade（或發行版對應的更新指令）" => "Run sudo apt update && sudo apt upgrade (or your distribution's equivalent)",
        "{app} 已停止支援" => "{app} is out of support",
        "{app} 有已知漏洞（{cves}）" => "{app} has known vulnerabilities ({cves})",
        "{name} {ver} 有 {n} 個已公告漏洞" => "{name} {ver} has {n} published vulnerabilities",
        "更新這個套件（apt／dnf／apk upgrade）" => "Update this package (apt / dnf / apk upgrade)",
        "OSV 查詢失敗：{e}" => "OSV query failed: {e}",
        "OSV 回應 HTTP {status}" => "OSV responded HTTP {status}",
        "讀取已安裝的軟體清單…" => "Reading installed software…",
        "支援中" => "Supported",
        "即將停止支援" => "Ending soon",
        "已停止支援" => "Out of support",
        "嚴重" => "Critical",
        "資訊" => "Info",
        "{os} · 共 {n} 個軟體／套件" => "{os} · {n} programs / packages",
        "發行者" => "Publisher",
        "，剩 {d} 天" => ", {d} days left",
        "作業系統：{os} → {product}：{status}（{eol}{left}）" => "Operating system: {os} → {product}: {status} ({eol}{left})",
        "作業系統：{os}" => "Operating system: {os}",
        "最近一次 Windows 更新：{id}（{date}，{days} 天前）" => "Last Windows update: {id} ({date}, {days} days ago)",
        "待安裝更新：{total} 個（其中安全性 {sec} 個）" => "Pending updates: {total} ({sec} security)",
        "已安裝：{n} 個（{eco}）" => "Installed: {n} ({eco})",
        "內建規則沒有比對到已知漏洞版本的軟體。" => "Built-in rules found no software with known vulnerable versions.",
        "有已知漏洞或已停止支援的軟體" => "Software with known vulnerabilities or out of support",
        "停止支援" => "End of life",
        "軟體" => "Software",
        "已安裝" => "Installed",
        "修正版" => "Fixed in",
        "OSV（{eco}）：查了 {q} 個套件，{n} 個有已公告漏洞" => "OSV ({eco}): queried {q} packages, {n} have published vulnerabilities",
        "套件" => "Package",
        "漏洞數" => "Vulns",
        "⚠ 其中 {n} 個 CVE 在 CISA KEV（已被用於攻擊），請優先更新。" => "⚠ {n} of these CVEs are in CISA KEV (actively exploited); update these first.",
        "漏洞與更新：作業系統是否仍在支援、多久沒更新、已安裝軟體的已知漏洞（Linux 套件查 OSV）" => "Vulnerabilities and updates: OS support status, time since last update, known vulnerabilities in installed software (Linux packages via OSV)",
        "只列出已安裝的軟體清單，不做比對" => "Only list installed software, without matching",
        "不連線查 OSV（只用內建規則）" => "Do not query OSV online (built-in rules only)",
        "清單模式下只列名稱含這段文字的軟體" => "In list mode, only show software whose name contains this text",

        // hardening
        "讀不到設定值（使用系統預設）" => "Setting not found (system default applies)",
        "需要系統管理員／root 權限才能檢查" => "Needs administrator / root to check",
        "這個 Windows 版本不適用（{e}）" => "Not applicable to this Windows edition ({e})",
        "未通過：{title}" => "Failed: {title}",
        "通過" => "Pass",
        "未通過" => "Fail",
        "不適用" => "N/A",
        "錯誤" => "Error",
        "硬化分數 {score}/100 · 通過 {pass} · 未通過 {fail} · 不適用 {na} · 錯誤 {error}" => "Hardening score {score}/100 · pass {pass} · fail {fail} · n/a {na} · error {error}",
        "全部通過。" => "All checks passed.",
        "目前" => "Current",
        "怎麼修" => "How to fix",
        "{n} 項需要系統管理員／root 權限才能檢查：{ids}" => "{n} checks need administrator / root: {ids}",
        "系統硬化檢查：UAC、Defender、BitLocker、SSH、核心參數、自動更新等，給分數與修正方式" => "System hardening checks (UAC, Defender, BitLocker, SSH, kernel settings, automatic updates, …) with a score and fixes",
        "列出全部檢查（預設只列未通過）" => "List every check (default: failures only)",
        "只看這個分類（例：account、remote、kernel、update、encryption）" => "Only this category (e.g. account, remote, kernel, update, encryption)",

        // mcp vuln/hardening
        "漏洞與更新：作業系統是否仍在支援（停止支援日期）、最近一次更新、已知漏洞版本的軟體（附 CVE 與 NVD 連結）、Linux 套件的 OSV 結果、CISA KEV 命中。" => "Vulnerabilities and updates: whether the OS is still supported (end date), last update, software on known-vulnerable versions (with CVE and NVD link), OSV results for Linux packages, CISA KEV matches.",
        "系統硬化檢查：每條檢查的結果（通過／未通過／不適用）、目前值、期望值、修正方式與參考連結，以及加權分數。" => "System hardening checks: each check's result (pass / fail / n/a), current and expected value, fix and references, plus the weighted score.",

        // service
        "寫入 {path}" => "Write {path}",
        "刪除 {path}" => "Delete {path}",
        "結束使用 {dir} 的常駐 ai-security-monitor watch" => "Stop resident ai-security-monitor watch using {dir}",
        // ---- 改名 asa → ai-security-monitor 的遷移 ----
        "無法把 {from} 搬到 {to}：{e}" => "Could not move {from} to {to}: {e}",
        "結束舊版（asa）的常駐 watch" => "Stop the resident watch of the old version (asa)",
        "搬移舊版設定目錄 {from} → {to}" => "Move the old config directory {from} → {to}",
        "已移除舊版（asa）的開機自動啟動；之後只用 ai-security-monitor" => {
            "Removed the start-at-boot entry of the old version (asa); only ai-security-monitor is used from now on"
        }
        "這是舊版（asa）的開機自動啟動；執行 ai-security-monitor service install 換成新名" => {
            "This is the old version's (asa) start-at-boot entry; run ai-security-monitor service install to switch to the new name"
        }
        "✓ 已結束 {n} 個舊版（asa）常駐 watch" => "✓ Stopped {n} resident watch process(es) of the old version (asa)",
        "舊版 asa（service install 會換成新名）" => "Old asa (service install switches it to the new name)",
        "· 舊版 asa 的常駐 watch 還在使用 {legacy}，這次先沿用它；執行 ai-security-monitor service install --yes 換掉舊服務時會搬到 {new}" => {
            "· The old asa resident watch is still using {legacy}, so this run uses it too; it moves to {new} when you replace the old service with ai-security-monitor service install --yes"
        }
        "舊版 asa 還在使用 {dir}，沒有搬移；結束它之後再執行一次 ai-security-monitor service install --yes" => {
            "The old asa is still using {dir}, so it was not moved; stop it and run ai-security-monitor service install --yes again"
        }
        // ---- 在檔案總管雙擊命令列版 ----
        "AI Security Monitor {v}（命令列版）" => "AI Security Monitor {v} (command-line version)",
        "這個檔案是命令列工具，要在終端機（PowerShell 或命令提示字元）裡執行；直接雙擊只會看到這段說明。" => {
            "This file is a command-line tool: run it in a terminal (PowerShell or Command Prompt). Double-clicking it only shows this message."
        }
        "想要視窗介面：請下載桌面版安裝檔" => "For the windowed app, download the desktop installer",
        "一行安裝命令列版（在 PowerShell 貼上執行，會加入 PATH）：" => {
            "Install the command-line version in one line (paste into PowerShell; adds it to PATH):"
        }
        "常用命令：" => "Common commands:",
        "檢查環境與權限" => "check the environment and permissions",
        "完整掃描一次" => "run a full scan",
        "目前的連線，比對威脅情資" => "current connections, matched against threat intel",
        "所有命令" => "all commands",
        "按 Enter 關閉…" => "Press Enter to close…",
        "複製註冊資料 {from} → {to}" => "Copy enrollment {from} → {to}",
        "沒有登入時也要執行（例如伺服器開機後）：sudo loginctl enable-linger $USER，或改用 --system" => "To run without a login session (e.g. right after a server boots): sudo loginctl enable-linger $USER, or use --system",
        "XDG autostart 只在登入桌面時啟動；伺服器請用 --system" => "XDG autostart only starts with a desktop login; use --system on servers",
        "✓ 已在背景啟動（PID {pid}）" => "✓ Started in the background (PID {pid})",
        "✓ 已結束 {n} 個常駐 ai-security-monitor watch" => "✓ Stopped {n} resident ai-security-monitor watch process(es)",
        "· 目前使用者還沒註冊 hub：服務先只在本機掃描（之後以系統管理員執行 ai-security-monitor --config-dir <系統目錄> enroll …）" => "· This user is not enrolled with a hub yet: the service scans locally for now (later run, as admin, ai-security-monitor --config-dir <system dir> enroll …)",
        "無法連上服務控制管理員（這個命令只能由 Windows 服務啟動）：{e}" => "Cannot connect to the Service Control Manager (this command is only started by the Windows service): {e}",
        "安裝開機自動啟動（{how}）：" => "Install start-at-boot ({how}):",
        "移除開機自動啟動（{how}）：" => "Remove start-at-boot ({how}):",
        "安裝開機自動啟動" => "install start-at-boot",
        "移除開機自動啟動" => "remove start-at-boot",
        "完成。log：{dir}（ai-security-monitor service logs{sys}）" => "Done. Logs: {dir} (ai-security-monitor service logs{sys})",
        "系統" => "System",
        "使用者" => "User",
        "是" => "Yes",
        "否" => "No",
        "範圍" => "Scope",
        "方式" => "Method",
        "目前沒有常駐中的 ai-security-monitor watch。" => "No resident ai-security-monitor watch is running.",
        "執行中：PID {pid} {cmd}" => "Running: PID {pid} {cmd}",
        "{dir} 還沒有 log（服務模式的 ai-security-monitor watch 才會寫 log 檔）" => "No logs in {dir} yet (only ai-security-monitor watch in service mode writes log files)",
        "service run 只用於 Windows 服務；其他平台由 systemd／launchd 執行 ai-security-monitor watch --service" => "service run is only for the Windows service; on other platforms systemd/launchd run ai-security-monitor watch --service",
        "設定目錄" => "Config directory",
        "同一個設定目錄已經有常駐的 ai-security-monitor watch，這個不再啟動" => "Another resident ai-security-monitor watch already uses this config directory; not starting a second one",
        "無法建立單一實例鎖：{e}" => "Could not create the single-instance lock: {e}",
        "服務模式啟動（ai-security-monitor {v}，設定目錄 {dir}）" => "Service mode started (ai-security-monitor {v}, config directory {dir})",
        "收到停止訊號，結束" => "Stop signal received, exiting",
        "密鑰存放方式（keychain／file；服務模式用 file）" => "Secret storage (keychain / file; services use file)",
        "開機自動啟動：裝成系統服務（伺服器）或登入時啟動（個人電腦）" => "Start at boot: install as a system service (servers) or start at login (PCs)",
        "安裝並立即啟動（預設 --user：登入時啟動、免系統管理員；--system：開機就啟動的系統服務，需要系統管理員／root）" => "Install and start now (default --user: starts at login, no admin needed; --system: a system service that starts at boot, needs admin/root)",
        "系統服務（Windows 服務／systemd／LaunchDaemon）" => "System service (Windows service / systemd / LaunchDaemon)",
        "使用者層（登入時啟動；預設）" => "Per-user (starts at login; default)",
        "完整掃描間隔（例：10m、1h）" => "Full scan interval (e.g. 10m, 1h)",
        "停止並移除開機自動啟動" => "Stop and remove start-at-boot",
        "移除系統服務" => "Remove the system service",
        "移除使用者層（預設）" => "Remove the per-user entry (default)",
        "系統服務與使用者層的安裝與執行狀態" => "Install and run state of the system service and the per-user entry",
        "看常駐行程的 log" => "Show logs of the resident process",
        "看系統服務的 log" => "Show the system service logs",
        "最後幾行" => "Number of last lines",
        "Windows 服務入口（由服務控制管理員呼叫）" => "Windows service entry point (called by the Service Control Manager)",
        "完整掃描間隔" => "Full scan interval",

        // service
        "命令列 {n} 字元，超過 Windows「執行」機碼的 260 字元上限，登入時可能不會啟動；請把 ai-security-monitor 放到較短的路徑" => "The command line is {n} characters, over the 260-character limit of the Windows Run key, so it may not start at login; move ai-security-monitor to a shorter path",

        // self-update
        "{url} 超過大小上限" => "{url} exceeds the size limit",
        "{url} 不是 Release 資料" => "{url} is not release data",
        "Release {tag} 沒有 SHA256SUMS，拒絕更新" => "Release {tag} has no SHA256SUMS; refusing to update",
        "SHA256SUMS 裡沒有 {name}" => "{name} is not listed in SHA256SUMS",
        "{name} 的 SHA256 不符（預期 {expected}，實際 {actual}），已放棄" => "SHA256 mismatch for {name} (expected {expected}, got {actual}); aborted",
        "無法寫入 {dir}（{e}）；請用有權限的身分執行（例如 sudo ai-security-monitor self-update）" => "Cannot write to {dir} ({e}); run with sufficient rights (e.g. sudo ai-security-monitor self-update)",
        "有新版：{latest}（目前 {current}）→ ai-security-monitor self-update --yes；說明：{url}" => "New version available: {latest} (current {current}) → ai-security-monitor self-update --yes; notes: {url}",
        "已是最新版（{current}）" => "Already up to date ({current})",
        "Release {tag} 沒有這個平台（{os}/{arch}）的執行檔" => "Release {tag} has no executable for this platform ({os}/{arch})",
        "將下載 {name}（{size}）並比對 SHA256SUMS，取代 {exe}" => "Will download {name} ({size}), verify it against SHA256SUMS and replace {exe}",
        "更新到 {v}" => "update to {v}",
        "已更新 {from} → {to}（SHA256 {sha}）" => "Updated {from} → {to} (SHA256 {sha})",
        "常駐中的 ai-security-monitor watch 還是舊版：執行 ai-security-monitor service restart --yes（系統服務加 --system）換成新版" => "The resident ai-security-monitor watch still runs the old version: run ai-security-monitor service restart --yes (add --system for the system service)",
        "還沒安裝開機自動啟動（ai-security-monitor service install）" => "Start-at-boot is not installed (ai-security-monitor service install)",
        "重新啟動常駐行程" => "restart the resident process",
        "重新啟動失敗" => "Restart failed",
        "更新 ai-security-monitor：下載 GitHub Release 的執行檔，比對 SHA256 後替換" => "Update ai-security-monitor: download the GitHub release executable, verify its SHA256 and replace this one",
        "只檢查有沒有新版" => "Only check whether a new version exists",
        "更新（或退回）到指定版本，例：0.2.0" => "Update (or roll back) to this version, e.g. 0.2.0",
        "重新啟動常駐行程（例如更新 ai-security-monitor 之後）" => "Restart the resident process (e.g. after updating ai-security-monitor)",
        "重新啟動系統服務" => "Restart the system service",
        "常駐與開機自動啟動" => "Resident process and start at boot",
        "沒有常駐的 ai-security-monitor watch（ai-security-monitor service install 可設定開機自動啟動）" => "No resident ai-security-monitor watch (ai-security-monitor service install sets up start at boot)",
        "{n} 個常駐中（ai-security-monitor service status 看詳細）" => "{n} running (see ai-security-monitor service status)",

        // self-update
        "找不到版本 {v}（{url}）" => "Version {v} not found ({url})",
        "還沒有發佈任何版本（{url}）" => "No version has been released yet ({url})",

        // service firewall
        "有 ai-security-monitor 防火牆規則要重新套用，但沒有系統管理員權限（請用 ai-security-monitor service install --system）" => "ai-security-monitor firewall rules need to be re-applied but there are no administrator rights (use ai-security-monitor service install --system)",
        "已重新套用防火牆規則：封鎖 {b} 筆、關閉 {p} 個 port、情資網段 {n} 個" => "Re-applied firewall rules: {b} blocked, {p} ports closed, {n} intel networks",
        "重新套用防火牆規則失敗：{e}" => "Re-applying firewall rules failed: {e}",

        // intel sync via hub mirror
        "已註冊 Hub 也不用 Hub 的鏡像，直接找各廠商下載" => "Download straight from each vendor even when enrolled with a Hub (skip the Hub mirror)",
        "情資更新失敗：{e}" => "Threat intel update failed: {e}",
        "情資更新：檢查 {checked} 個、{updated} 個有新資料、{failed} 個失敗（{hub} 個從 Hub）" => "Threat intel: checked {checked}, {updated} updated, {failed} failed ({hub} from the Hub)",
        "Hub 要求立即更新情資" => "Hub asked for an immediate threat intel update",
        "從 Hub 鏡像下載（{n} 個清單）：{url}" => "Downloading from the Hub mirror ({n} lists): {url}",
        "Hub 鏡像不可用，直接找廠商：{e}" => "Hub mirror unavailable, downloading from vendors: {e}",
        "下載自" => "From",

        // ---- hub discovery + keyless enrollment ----
        "Hub 身分使用不支援的演算法：{alg}" => "The Hub identity uses an unsupported algorithm: {alg}",
        "Hub 身分的公鑰格式錯誤" => "The Hub identity public key is malformed",
        "Hub 身分的指紋與公鑰不符" => "The Hub identity fingerprint does not match its public key",
        "Hub 身分回應不是針對這次的查詢（nonce 不符）" => "The Hub identity response was not made for this request (nonce mismatch)",
        "Hub 身分的簽章驗證失敗" => "The Hub identity signature is invalid",
        "查詢 Hub 身分失敗（HTTP {status}）" => "Could not query the Hub identity (HTTP {status})",
        "這個網址不是 Security Hub（身分回應格式不對）" => "This URL is not a Security Hub (unexpected identity response)",
        "Hub 的身分指紋變了：這台電腦記得的是 {pinned}，現在這個 Hub 是 {seen}。可能是 Hub 重新安裝，也可能有人冒充公司的 Hub。請向管理員確認指紋；確定要改加入新的 Hub 請執行 ai-security-monitor enroll --auto --repin" =>
            "The Hub identity fingerprint changed: this computer remembers {pinned}, but this Hub is {seen}. The Hub may have been reinstalled, or someone may be impersonating your company's Hub. Check the fingerprint with your administrator; to join the new Hub anyway run ai-security-monitor enroll --auto --repin",
        "DNS 名稱格式錯誤：{name}" => "Invalid DNS name: {name}",
        "找不到這台電腦使用的 DNS 伺服器" => "Could not find the DNS servers this computer uses",
        "指定的網址" => "Given URL",
        "環境變數" => "Environment variable",
        "公司 DNS（SRV）" => "Company DNS (SRV)",
        "區網廣播（mDNS）" => "Local network (mDNS)",
        "DNS／mDNS 宣告的指紋 {txt} 和 Hub 實際的 {fp} 不符，略過" => "The fingerprint announced in DNS/mDNS ({txt}) does not match the Hub's real one ({fp}); skipped",
        "這個 Hub 版本太舊，不支援免金鑰加入（請用 --key）" => "This Hub is too old for keyless enrollment (use --key)",
        "Hub 核准的不是這台電腦（agent id 不符）" => "The Hub approved a different computer (agent id mismatch)",
        "Hub 回傳的金鑰格式不對" => "The Hub returned a malformed key",
        "核准結果的簽章驗證失敗：不是加入時那個 Hub 發的" => "The approval signature is invalid: it was not issued by the Hub you applied to",
        "這個 Hub 沒有開放免金鑰加入：請向管理員要註冊金鑰（enroll --key）" => "This Hub does not accept keyless enrollment: ask your administrator for an enroll key (enroll --key)",
        "加入申請太頻繁，請稍後再試" => "Too many enrollment requests; try again later",
        "Hub 待核准的申請太多，請管理員先處理" => "The Hub has too many pending requests; ask your administrator to review them first",
        "Hub 回應 HTTP {status}：{code}" => "The hub answered HTTP {status}: {code}",
        "Hub 沒有回傳申請編號" => "The Hub did not return a request id",
        "Hub 指紋：{fp}（已記下，之後 Hub 身分不同會拒絕上傳）" => "Hub fingerprint: {fp} (remembered; uploads stop if the Hub identity ever changes)",
        "用 --key 註冊時要給 Hub 網址（ai-security-monitor enroll <HUB_URL> --key …）" => "Enrolling with --key needs the Hub URL (ai-security-monitor enroll <HUB_URL> --key …)",
        "可加入 · 這台電腦釘選的 Hub" => "Can join · the Hub pinned on this computer",
        "可連線，但不接受免金鑰加入" => "Reachable, but does not accept keyless enrollment",
        "可加入" => "Can join",
        "指紋" => "Fingerprint",
        "正在尋找 Security Hub（公司 DNS、區網廣播）…" => "Looking for a Security Hub (company DNS, local network)…",
        "等候管理員核准… Hub「{name}」（{url}）\n  Hub 指紋：{fp}\n  這台電腦的核對碼：{code}\n  請管理員在 Hub 的「新增主機 → 待核准的主機」核對後按核准。" =>
            "Waiting for an administrator to approve… Hub \"{name}\" ({url})\n  Hub fingerprint: {fp}\n  This computer's check code: {code}\n  Ask your administrator to compare it under Add hosts → Pending hosts in the Hub and click Approve.",
        "要加入這個 Hub 請加 --yes（或用 --hub <網址> 指定）" => "To join this Hub add --yes (or pick it with --hub <url>)",
        "管理員已核准：已加入 {url}（{hub} {version}）；agent id {id}" => "Approved: joined {url} ({hub} {version}); agent id {id}",
        "下一步：執行 ai-security-monitor service install --yes 開機自動回報（或 ai-security-monitor watch --once 先試一輪）" =>
            "Next: run ai-security-monitor service install --yes to report automatically at startup (or ai-security-monitor watch --once to try one round)",
        "這台電腦已經加入 {url}（要改加入別的 Hub 請加 --repin）" => "This computer has already joined {url} (add --repin to join a different Hub)",
        "同一個 Hub（指紋 {fp}）的新網址：已改成 {url}" => "Same Hub (fingerprint {fp}) at a new URL: switched to {url}",
        "這台電腦已經加入 {url}；要改加入 {new} 請加 --repin" => "This computer has already joined {url}; add --repin to join {new} instead",
        "找到的 Hub 都不能用：{detail}" => "None of the Hubs found can be used: {detail}",
        "找到好幾個不同的 Hub：請和管理員確認指紋後，用 ai-security-monitor enroll --hub <網址> 指定" =>
            "Found several different Hubs: confirm the fingerprint with your administrator, then pick one with ai-security-monitor enroll --hub <url>",
        "加入「{name}」（{url}，指紋 {fp}）？" => "Join \"{name}\" ({url}, fingerprint {fp})?",
        "接著等候之前送出的加入申請。" => "Continuing to wait for the enrollment request sent earlier.",
        "管理員拒絕了這台電腦的加入申請：{reason}" => "An administrator rejected this computer's enrollment request: {reason}",
        "管理員拒絕了這台電腦的加入申請" => "An administrator rejected this computer's enrollment request",
        "加入申請已過期或被刪除：請重新執行 ai-security-monitor enroll --auto" => "The enrollment request expired or was removed: run ai-security-monitor enroll --auto again",
        "查詢核准狀態失敗，稍後重試：{e}" => "Could not check the approval status, will retry: {e}",
        "還沒核准。之後再執行 ai-security-monitor enroll --auto 會接著等；已安裝常駐服務（watch）的話，它會在背景繼續等，核准後自動開始回報。" =>
            "Not approved yet. Running ai-security-monitor enroll --auto again continues waiting; if the background service (watch) is installed it keeps waiting and starts reporting once approved.",
        "已中斷等候；申請仍然有效，之後再執行 ai-security-monitor enroll --auto 會接著等。" =>
            "Stopped waiting; the request is still valid, and running ai-security-monitor enroll --auto again continues waiting.",
        "這個 Hub 版本太舊，沒有身分端點，不能廣播" => "This Hub is too old (no identity endpoint) to advertise",
        "正在區網廣播「{name}」→ {url}（指紋 {fp}）。按 Ctrl-C 結束。" => "Advertising \"{name}\" → {url} (fingerprint {fp}) on the local network. Press Ctrl-C to stop.",
        "已停止廣播" => "Stopped advertising",
        "已取消等候中的加入申請（{url}）" => "Cancelled the pending enrollment request ({url})",
        "Hub 指紋" => "Hub fingerprint",
        "加入申請" => "Enrollment request",
        "等候管理員核准 · {url} · 核對碼 {code} · Hub 指紋 {fp}" => "Waiting for approval · {url} · check code {code} · Hub fingerprint {fp}",
        "已記下 Hub 指紋 {fp}" => "Remembered the Hub fingerprint {fp}",
        "Hub 身分不符：停止上傳，直到重新加入" => "Hub identity mismatch: uploads stopped until this computer re-enrolls",
        "這個網址的 Hub 不再提供身分驗證（可能被換掉）：停止上傳，直到重新加入" =>
            "The Hub at this URL no longer proves its identity (it may have been replaced): uploads stopped until this computer re-enrolls",
        "無法確認 Hub 身分：{e}" => "Could not verify the Hub identity: {e}",
        "等候 Hub 管理員核准加入申請：{url}（核對碼 {code}，Hub 指紋 {fp}）" => "Waiting for a Hub administrator to approve the enrollment request: {url} (check code {code}, Hub fingerprint {fp})",
        "尚未註冊 hub：只在本機掃描（ai-security-monitor enroll --auto 自動尋找公司的 Hub，或 enroll <HUB_URL> --key …）" =>
            "Not enrolled with a hub: scanning locally only (ai-security-monitor enroll --auto finds your company's Hub, or enroll <HUB_URL> --key …)",
        "管理員已核准：已加入 {url}（{hub} {version}），開始回報" => "Approved: joined {url} ({hub} {version}); reporting starts now",
        "沒有找到 Security Hub。請管理員在公司 DNS 加 _aisecmon._tcp 的 SRV 紀錄、在區網開啟 Hub 廣播，或直接用 ai-security-monitor enroll --hub <網址>" =>
            "No Security Hub found. Ask your administrator to add an _aisecmon._tcp SRV record to the company DNS or turn on Hub advertising on the local network, or use ai-security-monitor enroll --hub <url>",
        "Hub 身分驗證失敗：{detail}" => "Hub identity check failed: {detail}",
        // clap help
        "註冊到 Security Hub：給 --key 用金鑰；不給金鑰就自動尋找 Hub、送出加入申請等管理員核准" =>
            "Enroll with a Security Hub: with --key use that key; without a key find the Hub automatically and send an enrollment request for an administrator to approve",
        "尋找區網／公司 DNS 上的 Security Hub（只列出，不加入）" => "Look for Security Hubs on the local network / company DNS (list only, does not join)",
        "Security Hub 相關工具（在區網上幫 Hub 廣播）" => "Security Hub tools (advertise the Hub on the local network)",
        "Hub 網址（https://…；本機或私網可用 http）；免金鑰時可省略，改用自動尋找" => "Hub URL (https://…; http allowed for local/private addresses); optional without a key (automatic discovery)",
        "client 金鑰或註冊金鑰；- 表示從標準輸入讀取。不給就送出免金鑰的加入申請" => "Client key or enroll key; - reads it from stdin. Without it a keyless enrollment request is sent",
        "免金鑰加入：自動尋找公司的 Hub（DNS SRV、區網廣播），送出加入申請並等管理員核准" =>
            "Keyless enrollment: find your company's Hub (DNS SRV, local network), send an enrollment request and wait for an administrator to approve it",
        "要加入的 Hub 網址（找到好幾個 Hub 時用它指定；安裝程式會預填）" => "Hub URL to join (use it when several Hubs are found; installers prefill it)",
        "等候管理員核准多久（例：15m、2h；0＝送出申請就結束，之後 watch／服務會繼續等）" => "How long to wait for approval (e.g. 15m, 2h; 0 = send the request and exit, watch/the service keeps waiting)",
        "這台電腦記得的 Hub 指紋和現在找到的不同時，仍改加入新的 Hub（確認過指紋才用）" => "Join the new Hub even though its fingerprint differs from the one this computer remembers (only after checking the fingerprint)",
        "等候區網廣播回應的時間" => "How long to wait for local network (mDNS) answers",
        "不查公司 DNS 的 SRV 紀錄" => "Do not look up SRV records in the company DNS",
        "不用區網廣播（mDNS）尋找" => "Do not search the local network (mDNS)",
        "用 mDNS 在區網上廣播這個 Hub（Hub 在 Docker Desktop／bridge 網路裡時，廣播出不了區網，改在這台執行）" =>
            "Advertise this Hub on the local network via mDNS (use it when the Hub runs in Docker Desktop / bridge networking, whose multicast does not reach the LAN)",
        "Hub 的對外網址（電腦要連的那個，例：https://hub.corp.example 或 http://192.168.1.10:8088）" => "The Hub's public URL (the one computers connect to, e.g. https://hub.corp.example or http://192.168.1.10:8088)",
        "廣播的名稱（預設：Hub 的名稱＋這台電腦的名稱）" => "Advertised name (default: Hub name + this computer's name)",
        "廣播多久就結束（預設一直執行到 Ctrl-C）" => "Stop advertising after this long (default: until Ctrl-C)",

        _ => return None,
    })
}
