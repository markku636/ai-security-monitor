# Changelog

## 未發佈

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

> 驗證：`cargo test`（123 passed）、`cargo clippy --all-targets -- -D warnings`；實機 `asa intel update` 16 個來源 3.6 s（IPsum 12.5 萬、blocklist.de 2.5 萬、KEV 1746）；`asa intel lookup` 對 Spamhaus／Feodo 列名 IP 判危險並列出 6 個來源，8.8.8.8 判安全；`asa scan` 含情資 1 s；`asa fw audit` 實機抓到作用中 Public 設定檔關閉與 Redis 6379／SMB 445 可從網路連入，完整掃描 3.3 s；`fw sync-blocklist --dry-run` 從 16052 筆選出 1 萬筆（Windows 上限）0.9 s；本機只做預演，實際寫入由 CI 三平台 E2E 驗證；Hub：vitest 14 passed、`next build` 6 s，本機對 PostgreSQL 18 容器驗證健康檢查、未登入 307、錯誤金鑰 401、登入、中英文頁面與稽核寫入；第 6 輪 vitest 22 passed，本機對 PostgreSQL 以契約檔完成註冊→gzip 報告→快照→頁面顯示；第 7 輪 cargo test 129 passed、vitest 24 passed，本機 agent 註冊到本機 hub，`watch --once` 上傳 345 條連線快照＋10 筆發現，hub 停機時報告進 outbox、恢復後自動補送；第 8 輪 vitest 32 passed，本機以真實 agent 資料（約 300 條連線）驗證所有頁面 200、批次 API、無頭 Edge 截圖檢查淺色／深色／手機寬度版面。
