# Changelog

## 未發佈

改進：
- Hub 選單改版：分成「要處理的事／網路／弱點／事件／工具」，每項有圖示與一行說明、目前頁面高亮、待處理問題（嚴重＋高）與待核准封鎖的數字；名稱改白話（代理程式→主機、發現→待處理問題、動作→封鎖審核、系統硬化→安全設定、管理→設定與金鑰、安裝代理程式→新增主機），頁面標題與內文一致；手機版選單可收合。README 截圖重拍。
- 用詞：「車隊」一律改成「所有主機」（總覽分數卡、AI 頁、情資查詢）；總覽的危險與可疑連線把同一主機、同一行程連到同一遠端的多條連線合併成一列並標出條數。
- IP 分析頁 `/ip/<ip>`：連線表、總覽、主機頁、流量、事件、暴力破解來源上的 IP 都能點進去，看這個 IP 被哪些情資來源列名（附來源連結）、哪台主機的哪個程式連過、連線狀態、被判可疑的理由與歷史；附 VirusTotal／AbuseIPDB／GreyNoise／Shodan／IPinfo 外部查詢連結（只是連結，hub 不會自動送出 IP）。
- AI 助手新增「分析可疑連線」與「分析單一 IP」範圍，每種範圍都能選特定裝置；連線頁與 IP 頁有「請 AI 分析」按鈕直接帶入。
- 理由標籤分清楚來源：情資命中標「情資」，asa 自己的異常判斷（週期性連線、新目的地等）標「行為」，滑過會說明不是情資來源。
- 所有清單頁都能依裝置篩選：連線、待處理問題、封鎖審核、流量、當機與事件、漏洞、安全設定；主機少時是一排晶片，多時改下拉選單，切換時保留其他篩選；「請 AI 分析」按鈕會帶上目前選的裝置。連線與問題頁搜尋時不再丟掉裝置篩選。
- 同步威脅情資資料庫：Hub 依各來源更新間隔鏡像清單（原檔原樣、保留授權標註），agent 先從 Hub 下載、Hub 沒有才找廠商（`asa intel update --no-hub` 可跳過）；威脅情資頁有「立即同步情資」，同時叫所有主機下次心跳就更新，並列出 Hub 各來源最後同步與每台主機的情資新舊。
- 桌面版（`desktop/`，Tauri 2）：用戶端的視窗介面，系統匣常駐；總覽分數、連線（依判定／方向篩選、點 IP 分析、理由分情資／行為）、掃描結果、威脅情資狀態與更新、AI 分析（本機已登入的 Claude Code／Codex）、設定。直接呼叫 asa 程式庫、共用設定目錄；連線頁唯讀，不寫入連線歷史。執行檔帶命令列參數時就當 asa CLI（AI 的 MCP server 走這條）。CI 新增 desktop job（fmt、clippy、CLI／MCP 直通）。
- 修正：常駐的 `asa watch` 以前從不自動更新情資（只有手動 `asa intel update`），現在每 30 分鐘檢查一次，更新後立即重新載入。
- IP 分析頁新增「外部威脅情資」（參考 at-integration-tools 的 IP 威脅情資）：按「查詢外部情資」才會把 IP 送給 AbuseIPDB、GreyNoise、IPinfo、proxycheck.io，加上 hub 自己的 DNS 反解；算出 0–100 風險分數與等級（低／中／高／極高）、每個理由的加減分、各來源命中 x/N、國家／ASN／用途類型／資料中心／Proxy／VPN／Tor／反解／FCrDNS 明細與原始回應。asa agent 同步的黑名單命中（Spamhaus DROP、FireHOL、IPsum、Tor 出口…）也算進分數。結果快取（各來源 1–30 天），每日額度自我節流，私有／保留位址一律不送出；金鑰在「設定與金鑰 → 外部情資來源」貼上（只寫不讀，稽核不記金鑰）或用 `ASA_HUB_ABUSEIPDB_KEY` 等環境變數；`ASA_HUB_IP_LOOKUPS=off` 可整個關掉。
- 連線頁上方新增「可疑 IP 排名」：曾被判定可疑或危險的遠端 IP 跨主機、跨 port 彙總，依危險程度與累計次數（每次連線快照看到一次加 1）排序，並列出目前快照裡還在連的條數、主機數、方向與 port、行程、國家／組織、最後看到時間；預設前 10 名，可展開到前 50 名，跟著裝置篩選走。

## v0.1.0 — 2026-10-17

**第一個公開版本。** 防禦型資安 agent `asa`（Windows／macOS／Linux）＋ Security Hub（Next.js＋PostgreSQL，Docker）。

重點：
- 對外／對內連線判定（安全／未知／可疑／危險），20 多個開源威脅情資來源，每個命中附廠商、信心、授權與來源網址；情資同步成防火牆封鎖規則（預演、確認、可撤銷）。
- 防火牆與 port 曝露、漏洞與更新（作業系統支援期限、OSV、CISA KEV、常見軟體已知漏洞版本）、60 條跨平台系統硬化檢查。
- 流量（免抓包的 flow-lite 與 pcap／pcapng 分析）、Windows 事件與當機原因（藍屏代碼、WER）、Linux journal、macOS 當機報告。
- Claude Code／Codex CLI 分析與 MCP（agent 與 Hub 兩端）；Hub 有車隊總覽、發現、漏洞、硬化、事件、情資、遠端動作審核、註冊金鑰、唯讀 API token、稽核與 CSV。
- 開機自動啟動（系統服務或使用者層）、`asa self-update`、一行安裝腳本、六個平台的執行檔與 SHA256SUMS、Hub 多架構 Docker 映像。

以下為開發過程（第 0–20 輪）的完整紀錄。

**專案骨架：`asa` Rust agent 的核心模組與 CLI 樹。**

改進：
- `agent/`：error / i18n（zh-TW 字面即 key）/ config / store（原子寫入）/ secrets（keychain 或 0600 檔案）/ embedded feeds。
- 資料契約：Finding（穩定 id）、Verdict（安全／未知／可疑／危險＋理由）、Connection（方向）、Report、Baseline、Allowlist。
- Scanner trait 與 Pipeline（相依排序、白名單、基準線、分數）。
- CLI：`version`、`doctor`、`scan`、`config`、`allowlist`、`baseline`；`--lang en` 全部 help 有英文。
- `feeds/registry.json`：25 個情資／漏洞／地理來源，含授權與來源 URL；`feeds/known-good.json`。
- connections 引擎（第 1 輪）：netstat2＋sysinfo 列出 socket 並接上行程（exe sha256 快取）、方向判定（對外／對內／監聽／本機）、
  風險 port 表（`feeds/vuln/risky-ports.json`）、shell／腳本程式對外、暫存目錄行程、曝露 listener、beacon 偵測（24h 歷史）、
  known-good（公共 DNS 等）與白名單 → 每條連線的安全／未知／可疑／危險判定與理由；`asa connections [--direction] [--verdict] [--watch]`。
- 曝露類 finding 計入「曝露」面向；同 id finding 去重；`.gitattributes` 統一 LF。

- intel 引擎（第 2 輪）：情資登錄（內建＋`<config>/feeds/custom.json` 自訂 https 來源＋啟停狀態）、下載（ETag／Last-Modified、96 MB 上限、
  HTML 錯誤頁或空清單不覆蓋舊資料、DB-IP 月份網址自動回退）、8 種格式解析（純文字、Spamhaus NDJSON、URLhaus、ThreatFox、DShield、IPsum、KEV、mmdb）、
  IpSet 重疊區間二分搜尋（IPv4／IPv6／ip:port／網域含上層／ASN）、DB-IP 國家與 ASN、每筆命中附廠商／授權／來源網址／信心。
- 連線判定接上情資：命中高信心來源 → 危險；Tor／低信心 → 可疑；`intel.outbound_match`／`intel.inbound_match` finding 附封鎖動作。
- 線上名譽查詢（AbuseIPDB、GreyNoise、CrowdSec CTI；需自備 key、預設關）：24h 快取＋每日額度上限。
- CLI：`asa intel update|status|sources|lookup|enable|disable|key`、`asa connections --intel`（顯示國家）、`asa doctor` 情資新鮮度。
- 移除 abuse.ch SSLBL IP 清單（官方已於 2025-01-03 停用）；URLhaus 網域級命中降為可疑（共用 CDN 不整台判死）。

- 防火牆與 port（第 3 輪，唯讀）：Windows（一次 PowerShell 取設定檔、作用中網路類別、允許連入規則＋port／程式／位址篩選，UWP 每使用者規則另計）、
  macOS（應用程式防火牆、隱形模式、pf）、Linux（firewalld → ufw → nftables → iptables 偵測與解析）；listener 可達性（僅本機／可連入／已阻擋／未知）；
  稽核：作用中網路設定檔關閉、預設允許連入、全開規則、macOS 防火牆關閉、Linux 無防火牆；高風險服務可連入時出 `ports.exposed_open`。
- `asa fw status|audit|list`、`asa ports [--all]`、`asa ports --probe HOST`（TCP connect／nmap，預設只限 loopback 與私網，公網需 `--allow-public`）。
- 指令執行層：逾時、Windows 無視窗、PowerShell `-EncodedCommand`（UTF-16LE），FakeRunner 讓解析器用 fixture 測。
- CI：修正無效的 workflow（job 層級 `if` 不能用 `hashFiles`），三平台 agent 測試開始真正執行。

- 防火牆寫入（第 4 輪）：`asa fw block|unblock|close-port|open-port|enable|sync-blocklist|ensure`，全部支援 `--dry-run`；
  Windows（`ASA:` 規則、群組 ASA；大量位址寫成帶 BOM 的 .ps1）、macOS（pf anchor `com.asa`＋持久化表檔）、
  Linux（nft `table inet asa`，與 ufw／firewalld 並存；無 nft 時 iptables＋ipset）；期望狀態檔供開機後 `fw ensure` 重套；動作稽核 `actions.jsonl`。
- 情資黑名單同步護欄：只取公網、v4≥/10、v6≥/19、排除本機介面／known-good／白名單重疊、非商用與 Tor 來源；超過後端上限時先保留高信心來源。
- 提權：永不靜默；`--yes` 後才以管理員身分重跑自己（Windows UAC、sudo、macOS 系統對話框、pkexec），子行程結果檔回報。
- 封鎖目標護欄：拒絕 loopback／多播／過寬網段；含本機介面位址需 `--force`。MCP 用的審查 token 庫（12 碼、15 分鐘、單次、最多 32 筆）。
- CI：三平台實機防火牆 E2E（封鎖 TEST-NET、關 port、驗證 OS 規則、全部移除）；`actions/checkout@v5`。

- Security Hub 骨架（第 5 輪）：Next.js 16（App Router）＋Tailwind 4＋Drizzle＋PostgreSQL；啟動時跑 migration（advisory lock 防兩個 hub 同時跑）；
  `/api/health`（資料庫不通回 503）；管理員登入（HttpOnly＋SameSite=Strict session、資料庫只存 sha256、換金鑰即全部登出、每 IP 每分鐘 5 次失敗上限）；
  admin／client／viewer 三種身分、開放模式（無管理員金鑰＝僅本機）、CSRF（X-ASA-Request＋Sec-Fetch-Site）、`*_FILE` Docker secrets；
  中英文（繁中原文即 key、cookie／Accept-Language、`i18n:check` 閘門）、深色模式、稽核紀錄表；`docker/compose.dev.yml` 開發用 PostgreSQL。
- 測試用記憶體內 PGlite 跑同一份 migration；CI 新增 hub job（typecheck、i18n、vitest、next build，再對 PostgreSQL 服務容器做登入煙霧測試）。

- Hub 接收（第 6 輪）：`/api/v1/agents/register`、`/api/v1/ingest/report`（gzip、壓縮後 4 MB／解壓 24 MB 上限、結構上限與禁止 key、zod、每 agent 最短間隔 429、report_id 冪等）、
  `/api/v1/ingest/snapshot`（最新連線整批替換＋目的地彙總，保留最嚴重判定）、`/api/v1/agents/me/heartbeat`、`GET /api/v1/agents`（公開檢視不露 IP）；
  finding 差異：新增／更新／未變／已解決（只對本次有跑的掃描器）／重新開啟（已解決又出現、已確認但升級、暫停過期）；情資命中保留廠商與來源網址。
- `contract/*.v1.json`：由 Rust 測試產生並比對、Hub 用 zod 驗證同一份 —— 兩邊格式一漂移 CI 就擋。
- 頁面：總覽（代理程式線上／延遲／離線、危險連線數、未處理發現的嚴重度分佈）、`/agents` 列表。CI 的 Hub 煙霧測試加上註冊→gzip 報告→快照→頁面。

- agent ↔ Hub（第 7 輪）：`asa enroll <HUB_URL> --key …`（先驗健康與註冊才存金鑰；https，http 只限本機／私網）、`asa unenroll`、`asa status`、
  `asa watch [--interval] [--snapshot-interval] [--once] [--no-upload]`：每分鐘連線快照＋心跳、每 10 分鐘掃描上傳；
  hub 停機或網路斷時報告暫存 outbox（最多 50 份），恢復後依序補送；被拒收的內容（400／413）直接丟棄不重送；> 16 KB 自動 gzip、遵守 `Retry-After`。
- Hub 限流改依報告完成時間（暫存報告恢復後可一次補送）、收過的報告重送直接回 duplicate 不吃限流，另加每 agent 每分鐘 30 份硬上限。
- `docs/hub-contract.md`（＋英文版）：端點、錯誤處理、`asa watch` 流程。

- Hub 儀表板（第 8 輪）：總覽（車隊平均分數圓環 ×5、危險／可疑連線、情資來源命中排行含授權與來源連結、對內攻擊來源、分數最低主機）；
  `/connections` 車隊級連線（判定／方向篩選晶片附計數、情資來源與國家篩選、關鍵字、分頁；每列方向徽章＋判定晶片＋理由：情資來源徽章可點到原始清單、滑過看信心／授權／抓取時間；DB-IP 標註）；
  `/findings` 篩選＋批次確認／暫停 30 天／重新開啟（寫稽核、即時重算各主機未處理數）；`/agents/[id]` 概況／連線／發現／報告紀錄分頁。
- API：`GET /api/v1/fleet/summary`（公開檢視只給彙總）、`/api/v1/connections`、`/api/v1/connections/inbound-attackers`、`GET|POST /api/v1/findings`（≤500 筆、cookie 身分需同站）、`/api/v1/agents/{id}`。
- 深色模式預設跟隨系統；CI 煙霧測試加上新頁面與 API。

- 遠端動作（第 9 輪）：Hub `/actions` 審核頁（待核准／已核准／已派送／完成／失敗／拒絕／取消／過期，破壞性動作核准要輸入主機名稱）；
  「發現」展開後可把 agent 建議的動作（封鎖 IP、關閉 port）一鍵送審；核准後 hub 用每台 agent 專屬金鑰簽 HMAC token，
  agent 驗章、檢查期限／允許種類／白名單／已知良好／本機位址後才執行，結果回報 hub；背景執行不跳 UAC／sudo，沒權限就回報失敗。
- agent 身分釘選：enroll 時產生隨機 token，hub 第一次看到就記下，之後拿同一把 client 金鑰冒充別台 agent 會被 403；驗章金鑰只發給已釘選的 agent。
- `/intel` 情資頁：26 個來源依威脅指標／地理／漏洞／線上查詢分組，列出廠商、信心、授權（可商用、需標註）、更新頻率、7 天命中；可查 IP／網域在車隊裡的命中、連線與歷史。
- `contract/action.v1.json`：hub（TypeScript）與 agent（Rust）的 canonical JSON 與 HMAC 交叉驗證；`npm run verify` 新增「server 檔不可從 'use client' 模組取函式」靜態檢查。
- CI 新增 e2e job：Linux runner 上 hub＋PostgreSQL＋agent，enroll → 核准封鎖 → agent 以 root 執行 → nft 規則存在 → hub 狀態 succeeded → 冒名 403 → 清除。

- 流量分析（第 10 輪）：`asa traffic [--duration 30s]` 即時 flow-lite（免抓包、免系統管理員：各行程連到哪些遠端、新連線、介面流量、情資命中、高風險 port、24 小時歷史裡的週期性連線）；
  `asa traffic analyze <檔案>` 離線分析 Wireshark／tcpdump／pktmon 存的 pcap 與 pcapng（純 Rust，不需要 Npcap／libpcap）：流彙總、DNS 查詢與回應、TLS SNI、HTTP Host、
  明文協定、大量上傳、週期性連線（beacon）、高熵／少見頂級網域 DNS、情資命中；兩種模式輸出同一份 ≤ 40 KB 的摘要，之後交給 AI 解讀與上傳 hub。
- `asa doctor` 新增封包擷取能力檢查（Windows 內建 pktmon、Npcap、tcpdump）；`docs/traffic.md`（＋英文版）說明三平台怎麼存擷取檔。

- 事件與當機分析（第 11 輪）：`asa events [--since 7d]`、`asa events crashes`、`asa events explain <0x7E|41>`、`asa events analyze <檔案>`；
  Windows 一次 PowerShell（Get-WinEvent → UTF-8 JSON）讀 System／Application／Security／Defender，加上 Minidump 檔頭；Linux 讀 journalctl JSON；macOS 讀 DiagnosticReports。
  當機：藍屏（Kernel-Power 41、WER 1001、minidump 同一次只算一次，附 33 個藍屏代碼的原因與處置）、非預期關機、程式當掉／沒回應、服務失敗、磁碟與 WHEA 硬體錯誤、更新失敗、顯示卡重設、記憶體不足、OOM、kernel panic／oops、segfault。
  資安：暴力破解（10 分鐘 ≥ 10 次或總數 ≥ 30 次，公網來源附情資與封鎖建議）、公網遠端登入、新帳號、加入管理員群組、新服務（依執行檔位置判斷嚴重度）、排程、稽核紀錄清除、Defender 偵測／被關閉。
- 事件掃描器加入 `asa scan`／`asa watch`：近 7 天摘要進報告 `summaries.events` 並上傳 hub；沒有管理員權限的部分列在 `needs_admin`。
- `feeds/events/bugchecks.json`、`feeds/events/known-ids.json`（中英對照）；`docs/events.md`（＋英文版）。

- MCP 與 AI（第 12 輪）：`asa mcp` 伺服器（stdio／`--http`，協定 2025-06-18），16 支唯讀工具：連線、IP／網域情資查詢、對內攻擊來源、情資來源、掃描與報告、
  監聽 port 可達性、防火牆、基準線、doctor、即時流量、pcap 分析、事件摘要、當機紀錄、代碼說明；`--allow-actions` 才出現 preview_action／execute_action
  （審查代碼單次 15 分鐘、白名單與已知良好護欄、需以系統管理員執行才會寫入）。HTTP 模式無 token 只綁本機並檢查 Host／Origin（擋 DNS rebinding），有 token 才能對外。
- `asa mcp config|install|uninstall --client claude-code|codex|cursor|vscode|claude-desktop|windsurf`：保留其他設定、先備份 `.bak`、需 `--yes`。
- `asa ai ask "…"`、`asa ai analyze [--traffic|--events]`、`asa ai status`：交給 Claude Code（stream-json、dontAsk、只允許 asa 唯讀工具、--strict-mcp-config）或 Codex（exec --json、read-only sandbox），
  逐字輸出並顯示工具呼叫；子行程用 Windows Job Object／Unix process group 管理、逾時整棵收掉；npm 的 .cmd 版本改由 stdin 傳系統提示。
- `docs/mcp.md`（＋英文版）；CI 三平台加 MCP stdio 煙霧測試。

- Hub 事件、流量與 MCP（第 13 輪）：報告裡的 `summaries.events` 寫進當機紀錄（去重）與資安事件（同規則同對象一列、次數取最新）、每台最新摘要；
  `/events`（各類當機數、最常見藍屏、暴力破解來源附情資、資安事件、最近當機與可能原因）、`/traffic`（危險目的地、各行程連線長條、24 小時新目的地、最常連的目的地）；
  `/agents/[id]` 新增「事件與當機」「流量」分頁（含需要管理員權限的提示與最常見錯誤）。
- Hub MCP `/api/mcp`（Streamable HTTP）：13 支唯讀工具（車隊總覽、主機、發現、連線、對內攻擊、指標查詢、目的地、當機、資安事件、暴力破解、藍屏說明、動作、情資來源），
  和頁面共用查詢；`ASA_HUB_MCP_TOKEN` 或管理員金鑰，開放模式只收本機。CI 煙霧測試加上新頁面與 MCP。

- Hub AI 分析頁（第 13b 輪）：`/ai` 在 hub 主機上跑 Claude Code 或 Codex，範圍可選整個車隊／單一主機／解讀流量／分析當機與資安事件，回答與工具呼叫以 SSE 即時串流，紀錄存進 `ai_analyses`；
  事件、流量與主機頁有「請 AI …」按鈕。每輪一次性 token 只能呼叫 hub 唯讀 MCP；子行程只拿白名單環境變數（不含管理員金鑰與資料庫網址）；停止或關頁整棵行程收掉；同時最多 2 輪。
- `GET /api/ai/providers`、`POST /api/ai/stream`；`ASA_HUB_CLAUDE_BIN`／`ASA_HUB_CODEX_BIN`（有指定就只用指定的）、`ASA_HUB_INTERNAL_URL`、`ASA_HUB_AI_MAX_CONCURRENT`。

- 漏洞與更新（第 14 輪）：`asa vuln [--no-online] [--inventory-only [--filter]]`；軟體清單（Windows 登錄檔 Uninstall＋最近更新、macOS Info.plist＋Homebrew、Linux dpkg／rpm／apk＋待更新數）；
  作業系統支援期限（`feeds/vuln/os-eol.json`：Windows 10／11 依 build 與版本別、Server 2012 R2–2025、主要 Linux 發行版、macOS）、Windows 超過 45 天沒更新、Linux 待裝安全性更新；
  常見軟體已知漏洞版本（`feeds/vuln/curated-apps.json`：WinRAR、7-Zip、Chrome、Edge、PuTTY、Git、VLC、停止支援的 Node.js／Python，附 NVD 連結）；
  Linux 套件查 OSV（依發行版生態系 querybatch、24 小時快取）；CVE 在 CISA KEV 就升為嚴重並標 `kev`。版本比較支援 epoch、`.windows.1` 尾巴與 rc／beta。
- 漏洞掃描器加入 `asa scan`／`asa watch`：摘要進報告 `summaries.vuln`、清單數填入 `inventory.packages／by_ecosystem`；Hub 保存每台最新漏洞摘要。`docs/vuln.md`（＋英文版）。

- 系統硬化檢查（第 15 輪）：`asa harden [--all] [--category …]`；YAML 策略引擎（`feeds/policies/{windows,linux,macos}.yml`，共 60 條：Windows 20、Linux 25、macOS 15），
  取值方式 registry／PowerShell（Windows 合併成一次呼叫）／指令／檔案／sysctl／sshd_config（含 Include）／systemctl／內建（UID 0、空白密碼、sudo NOPASSWD、PATH 可寫、AppArmor／SELinux）；
  通過／未通過／不適用（例：別家防毒、沒裝 sshd）／需要管理員；嚴重度加權 0–100 分；每個未通過項目一筆 `hardening.<id>` 發現附修正方式與參考連結。
- 自訂策略：`<設定目錄>/policies/*.yml` 可新增或以同 id 取代內建、`disabled: true` 關閉；id 限小寫（Hub 規則名格式）。
- 硬化掃描器加入 `asa scan`／`asa watch`：`summaries.hardening` 帶每條結果與分數；Hub 保存每台最新硬化與漏洞摘要。
- agent MCP 新增 `vuln_summary`、`hardening_status`（共 18 支唯讀工具）。`docs/hardening.md`（＋英文版）。

- Hub 漏洞與硬化頁（第 16 輪）：`/vulns`（作業系統已停止／即將停止支援、KEV 主機、已知漏洞軟體依規則彙總到主機、更新落後、Linux OSV 各主機統計，附 NVD／OSV 連結與資料來源）、
  `/hardening`（平均分數、最常未通過的檢查與受影響主機、各主機分數）；主機頁新增「漏洞與更新」「系統硬化」分頁（每條檢查的目前值、期望值、為什麼與怎麼修、參考連結；只看未通過／全部）與概況的分數趨勢（總分、漏洞、硬化，純 SVG）。
- API：`GET /api/v1/vulns`、`GET /api/v1/hardening`（`?agent_id=` 看單台）；Hub MCP 新增 `vuln_overview`、`hardening_overview`。摘要以寬鬆 zod 解析，壞資料不會拖垮頁面。
- CI：Hub 煙霧測試加新頁面與 API；Linux e2e 驗證真實 runner 的漏洞（>100 個套件）與硬化（≥20 條）摘要有進 Hub。

- 開機自動啟動（第 17 輪）：`asa service install|uninstall|status|logs`，兩種範圍跨三平台：
  `--system`（Windows 服務控制管理員＋失敗自動重啟、systemd unit、launchd LaunchDaemon；需管理員，沒有就請求提權）與預設的使用者層（HKCU Run、systemd --user 或 XDG autostart、launchd LaunchAgent；免管理員）。
  安裝／移除先產生計畫（寫哪個檔、跑哪個指令），沒加 `--yes` 只預覽；安裝系統服務會把目前使用者的 Hub 註冊資料搬到系統目錄（檔案密鑰庫）。
- `asa watch --service`：單一實例鎖、每日 log 檔（保留 14 天）、不寫主控台、Ctrl-C／SIGTERM／Windows 服務停止都會正常結束；Windows 實作 `asa service run`（windows-service）。
- 全域隱藏參數 `--secrets-backend file`（服務命令列使用）。`docs/service.md`（＋英文版）。CI 三平台在拋棄式 runner 上實際安裝→確認執行與 log→移除系統服務與使用者層。

- 自動更新（第 17b 輪）：`asa self-update [--check] [--to VER] --yes`、`asa version --check`：查 GitHub Release（`ASA_UPDATE_URL` 可指向鏡像），下載這個平台的執行檔，一律比對 `SHA256SUMS`（沒有或不符就放棄）後原地替換；Windows 舊檔改名 `.old-*`、下次清掉；還沒有 Release 時給清楚訊息。
- `asa service restart [--system]`（Windows 等服務真的停下再啟動、systemctl restart、launchctl kickstart -k）；Windows 移除服務前先等它停止；常駐中的掃描收到停止訊號會立刻中斷。`asa doctor` 顯示常駐狀態。
- 安裝腳本 `scripts/install.sh`（Linux／macOS）、`scripts/install.ps1`（Windows）：判斷平台、下載、比對 SHA256SUMS、安裝、選用註冊 Hub 與開機自動啟動（`system` 直接註冊到系統設定目錄）；支援鏡像與指定版本。`docs/install.md`（＋英文版）。CI 三平台以本機鏡像實測安裝、重裝與雜湊竄改被拒。

- Hub 管理（第 18 輪）：`/admin` 註冊金鑰（`asa_ek_…`，網頁建立／撤銷，列出用了幾台主機與最後使用）、唯讀 API token（`asa_<8>_<40>`，scope：讀取 API／CSV 匯出／MCP，可設期限、可撤銷，只存 sha256、明文只顯示一次）、稽核紀錄（可依動作篩選）、CSV 匯出（發現、代理程式、動作、稽核；UTF-8 BOM、防試算表公式注入）。
- API token 只能讀：寫入與管理端點一律拒絕；Hub MCP 接受有 mcp scope 的 token。註冊時記下用的是哪把註冊金鑰（`agents.enroll_key_id`）。
- `/install`：建立註冊金鑰並顯示各平台填好的一行指令；`/install.sh`、`/install.ps1` 提供預設註冊到這個 Hub 的安裝腳本（公開、不含金鑰；Host 會驗證，避免被塞進腳本）。新增 `ASA_HUB_PUBLIC_URL`。
- 更新提示：每 6 小時查一次 GitHub 最新版（快取在 settings，`ASA_HUB_UPDATE_CHECK=0` 關閉），有新版時管理員頁面顯示橫幅與更新指令。

- Docker 與發版（第 19 輪）：`docker/Dockerfile`（repo 根目錄為建置環境、Next.js standalone、非 root、HEALTHCHECK、`/data` volume；預設內含 Claude Code／Codex CLI，`--build-arg AI_CLIS=` 建 slim）、
  入口腳本（沒有管理員金鑰就拒絕啟動，容器裡的 loopback 不是主機的）、`docker/compose.yml`（伺服器版）、`docker/compose.standalone.yml`（單機版，只綁 127.0.0.1）、`.env.example`、`.dockerignore`、`docs/docker.md`（＋英文版）。
- `.github/workflows/release.yml`：tag `v*` → 檢查三處版本與 CHANGELOG → 六個平台的 asa（Windows x64／arm64、macOS arm64／x64、Linux x64／arm64 靜態 musl）＋安裝腳本＋SHA256SUMS → GitHub Release；
  GHCR 多架構映像 `:<版本>`、`:latest`、`-slim`。手動執行預設 dry run（只建置）。`scripts/check-version.mjs`、`scripts/changelog-section.mjs`。
- CI 新增 docker job：建 slim 映像、起單機版 compose、健康檢查、安裝腳本網址、註冊金鑰＋契約檔註冊、非 root、沒金鑰拒絕啟動。

- 第一版文件（第 20 輪）：README（中英）重寫：這是什麼、畫面預覽、功能一覽、安裝（一行指令與 Docker）、快速上手、CLI、文件索引；
  `docs/images/` 截圖用 `scripts/demo-seed.mjs`（四台虛構主機、文件保留網段 IP，經正式 ingest API 送入）與 `scripts/capture-screenshots.mjs`（無頭 Chrome／Edge）產生，不含任何真實主機資料。

- `docs/intel.md`、`docs/firewall.md`（＋英文版）：方向與判定規則、各情資來源的信心／預設／授權、封鎖挑選規則、各平台防火牆後端與安全設計。
- 常駐服務（`asa watch --service`）啟動時，若有權限且期望狀態裡有封鎖／關閉的 port／情資網段，就重新套用（pf、nftables 重開機不保留）；CI 三平台的服務測試先封鎖一個 IP、確認服務 log 有重新套用。
- 修正：`--direction` 的可選值說明在英文介面顯示中文；help 測試現在也檢查 ValueEnum 可選值。

> 驗證：`cargo test`（123 passed）、`cargo clippy --all-targets -- -D warnings`；實機 `asa intel update` 16 個來源 3.6 s（IPsum 12.5 萬、blocklist.de 2.5 萬、KEV 1746）；`asa intel lookup` 對 Spamhaus／Feodo 列名 IP 判危險並列出 6 個來源，8.8.8.8 判安全；`asa scan` 含情資 1 s；`asa fw audit` 實機抓到作用中 Public 設定檔關閉與 Redis 6379／SMB 445 可從網路連入，完整掃描 3.3 s；`fw sync-blocklist --dry-run` 從 16052 筆選出 1 萬筆（Windows 上限）0.9 s；本機只做預演，實際寫入由 CI 三平台 E2E 驗證；Hub：vitest 14 passed、`next build` 6 s，本機對 PostgreSQL 18 容器驗證健康檢查、未登入 307、錯誤金鑰 401、登入、中英文頁面與稽核寫入；第 6 輪 vitest 22 passed，本機對 PostgreSQL 以契約檔完成註冊→gzip 報告→快照→頁面顯示；第 7 輪 cargo test 129 passed、vitest 24 passed，本機 agent 註冊到本機 hub，`watch --once` 上傳 345 條連線快照＋10 筆發現，hub 停機時報告進 outbox、恢復後自動補送；第 8 輪 vitest 32 passed，本機以真實 agent 資料（約 300 條連線）驗證所有頁面 200、批次 API、無頭 Edge 截圖檢查淺色／深色／手機寬度版面；第 9 輪 cargo test 133 passed、vitest 43 passed，本機真實 agent enroll（--accept-remote-actions）→ hub 核准封鎖 → agent 驗章通過、因非管理員回報失敗（不動本機防火牆），實際寫入由 CI e2e 驗證；第 10 輪 cargo test 144 passed，合成擷取檔（pcap 與 pcapng、816 個封包）全部偵測命中，本機即時模式 10 秒列出 39 條流與各行程；第 11 輪 cargo test 164 passed，本機 30 天 1980 筆事件 3.6 秒（非管理員），完整掃描含事件 5.8 秒，hub 收到 4 筆事件類發現（記憶體不足 42 次等）；第 12 輪 cargo test 178 passed，stdio／HTTP MCP 實測（lookup_ip、list_connections、explain_code、session、DNS rebinding 403），假 claude CLI 讀取 asa 產生的 MCP 設定並實際呼叫工具，專案層級 install 寫入 .mcp.json；第 13 輪 vitest 48 passed，本機真實 agent 上傳事件摘要後 /events、/traffic、主機分頁皆 200，Hub MCP crash_history 回 50 筆；第 13b 輪 vitest 54 passed（含假 CLI 的 SSE 全流程、env 不外洩、斷線殺行程），本機 hub 以一次性 token 讓 CLI 呼叫 /api/mcp 成功並串流回網頁；第 14 輪 cargo test 188 passed、vitest 54 passed，本機 Windows 11 25H2 讀到 140 個軟體 2.4 秒完成，判定作業系統支援到 2027-10-12、最近更新 KB5127648，抓到 Python 3.10 已停止支援；第 15 輪 cargo test 197 passed、vitest 54 passed，本機 Windows 20 條檢查一次 PowerShell 2.8 秒（81 分：BitLocker、安全開機、AutoRun、LLMNR 未通過），自訂策略關閉內建與新增檢查皆生效，MCP hardening_status／vuln_summary 實測；第 16 輪 vitest 57 passed，本機真實 agent 上傳後 /vulns、/hardening、主機兩個新分頁與 API 皆 200，無頭 Edge 截圖檢查淺色／深色／手機寬度與分數趨勢；第 17 輪 cargo test 207 passed，本機只做預覽與唯讀狀態（不在這台安裝），服務模式 watch 實測單一實例鎖、靜默與 log 檔，實際安裝由 CI 三平台驗證（Windows 服務、systemd、LaunchDaemon 與三種使用者層皆通過安裝→執行→log→移除）；第 17b 輪 cargo test 210 passed，本機以鏡像實測 install.ps1 安裝、重裝改名舊檔、竄改雜湊被拒（exit 1），self-update 對 GitHub 正確回報尚無 Release；第 18 輪 vitest 63 passed，本機以網頁建立的註冊金鑰讓真實 agent 註冊並上傳 19 筆發現（金鑰顯示 1 台主機），export token 下載 CSV、管理端點 403，/install.sh 填入 Hub 網址，截圖檢查管理與安裝頁；第 19 輪本機建置映像 70 秒（含 AI CLI 1.6 GB），單機版 compose 12 秒健康，真實 agent 以網頁建立的註冊金鑰註冊並上傳 19 筆發現，入口腳本缺金鑰／資料庫時拒絕啟動；發版 dry run 六個平台的 asa 都建置成功（含 Windows arm64、Linux musl 靜態檔）；第 20 輪以示範資料截圖 12 張。
