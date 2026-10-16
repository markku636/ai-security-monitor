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
        "確認是否為預期服務；是則執行 asa baseline save --yes 納入基準線" => {
            "Confirm it is an expected service; if so, run asa baseline save --yes to add it to the baseline"
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
        "比對威脅情資（需先 asa intel update）" => "Match against threat intel (run asa intel update first)",

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
        "尚未下載任何威脅情資；執行 asa intel update" => "No threat-intel feeds downloaded yet; run asa intel update",
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
        "沒有設定任何線上名譽服務的 API key（asa intel key set abuseipdb -）" => {
            "No online reputation API key configured (asa intel key set abuseipdb -)"
        }
        "已啟用 {id}；執行 asa intel update 下載" => "Enabled {id}; run asa intel update to download it",
        "已停用 {id}" => "Disabled {id}",
        "不支援的名譽服務：{id}；可用：{ids}" => "Unsupported reputation service: {id}; available: {ids}",
        "API key 不可為空" => "The API key cannot be empty",
        "已儲存 {id} 的 API key（{backend}）" => "Saved the API key for {id} ({backend})",
        "要讓掃描自動查詢，執行 asa config set intel.online_lookups true" => {
            "To let scans query it automatically, run asa config set intel.online_lookups true"
        }
        "已刪除 {id} 的 API key" => "Deleted the API key for {id}",
        "威脅情資" => "Threat intel",
        "{fresh} 個最新、{stale} 個過期、{missing} 個未下載" => "{fresh} fresh, {stale} stale, {missing} not downloaded",

        // ---- cli/args.rs：intel ----
        "威脅情資：更新、狀態、來源、查詢 IP／網域" => "Threat intel: update, status, sources, IP / domain lookup",
        "下載／更新威脅情資（只抓過期的；--force 全部重抓）" => "Download / refresh threat-intel feeds (only stale ones; --force refetches all)",
        "只更新這些來源 id" => "Only update these feed ids",
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
        "讀取 asa 封鎖表" => "Read the asa block table",
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
        "以系統管理員身分執行 asa fw audit 確認是否可連入" => "Run asa fw audit as administrator to confirm reachability",
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
        "後端：{backend} · 狀態：{state} · 預設連入：{din} · 允許連入規則：{n} · asa 規則：{ours}" => {
            "Backend: {backend} · state: {state} · default inbound: {din} · inbound allow rules: {n} · asa rules: {ours}"
        }
        "作用中" => "Active",
        "防火牆設定檔" => "Profile",
        "預設連入" => "Default in",
        "預設連出" => "Default out",
        "部分規則需要系統管理員權限才能讀取（sudo asa fw status）" => "Some rules need administrator privileges to read (sudo asa fw status)",
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
        "防火牆：狀態、稽核、規則（本版唯讀）" => "Firewall: status, audit, rules (read-only in this version)",
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

        _ => return None,
    })
}
