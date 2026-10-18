# Changelog

## 未發佈

- Hub 的 compose 分成兩份：不含防護 DNS（`compose.yml`、`compose.standalone.yml`）與含防護 DNS（`compose.dns.yml`、`compose.standalone.dns.yml`），不再用 `--profile dns`。兩份是同一個專案、同一份資料，可以隨時換；換回不含的那份時加 `--remove-orphans`。含防護 DNS 的那份沒設 `AI_SECURITY_MONITOR_HUB_DNS_TOKEN` 時會直接說明要設，不會起一台連不上 Hub 的 DNS。dns 映像標籤沒另外設時跟 Hub 同一版（也認舊名 `ASA_HUB_IMAGE_TAG`）。
  **升級注意**：之前用 `--profile dns` 跑防護 DNS 的，改用含防護 DNS 的那份（`-f docker/compose.dns.yml`，單機版 `compose.standalone.dns.yml`）。

## v0.7.0 — 2026-10-18

**AI 分析與資安報告改成白話（先講要不要擔心、最後列出要做的事），AI 可直接拿到連線統計；依主機群組集中推送設定（Hub 簽章、主機驗章）；Windows 一鍵開啟各程式的網路流量；情資逐一手動更新；可選區間的資安報告；DNS 黑白名單。** 一般使用者請下載 `AI-Security-Monitor-0.7.0-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；0.6.0 的桌面版會自動提示更新。

**升級注意**：
- 這版沒有新的資料庫 migration。
- 主機預設接受 Hub 的集中設定（`central_config` 預設開）；Hub 沒有替群組設定集中設定時什麼都不變。不想讓 Hub 改這台的掃描間隔等設定：`ai-security-monitor config set central_config false`。
- 修正：停用／啟用自動回應或通知規則、只改群組名稱時，沒改到的欄位（門檻、封鎖時間、分鐘數、成員）會被重設。用 0.6.0 改過規則的話，請檢查一下規則設定是否還正確。

- **DNS 黑白名單**：白名單（含子網域）＝不擋、不告警，跟黑名單一起管：這台電腦 `ai-security-monitor dns allow <網域…>`／`dns unallow`（存在通用白名單 `allowlist`，`x` 與 `*.x` 兩筆），`dns blocklist`（別名 `dns lists`）黑白名單一起列；同一個網域後加的那一邊勝出（`dns block` 會從這台白名單拿掉、`dns allow` 會從這台黑名單拿掉）。白名單上的網域不會出現 `dns.blocklisted`，這台跑的防護 DNS 也不擋（改了 1 分鐘內生效）；Hub 的白名單也隨防護 DNS 設定同步到各台。桌面版 DNS 頁的卡片改成「黑白名單」（加入黑名單／加入白名單、各自移除），每筆查詢有「封鎖」與「放行」。Hub DNS 頁新增「黑白名單」小表單（貼網域直接加、看筆數），網域分析頁可「移出白名單」；DNS 相關的「允許清單」統一改叫「白名單」。
- **AI 分析與資安報告寫得更白話**：AI 回答一律先用一句話說「要不要擔心」，再分「發現了什麼／為什麼要注意／你要做什麼」，短句、日常用語，專有名詞（C2、ASN、CVE、DNS 通道…）第一次出現就用括號解釋，不貼一長串 IP，最後是編號的待辦（附在哪裡按、多急）。Hub「資安報告」開頭多了依輕重上色的一句話結論與「建議你先做」清單，重點裡的術語也改成白話；下載的 Markdown 一樣。
- **AI 分析可以直接拿到連線統計**：新 MCP 工具 `connection_stats`（桌面版／命令列與 Hub 都有）回傳總數，以及依判定、方向、狀態、協定、程式、國家、遠端 port、遠端 IP（Hub 另有主機）分組的條數。AI 不用自己找 jq／PowerShell 去數，三個平台都一樣。
- **桌面版 DNS 頁：設定、黑名單、怎麼用**：右邊多了「設定」：記錄這台的 DNS 查詢、上傳到公司 Hub 的程度（全部／只傳告警／不傳）、比對 DNS 答案、這台當防護 DNS（含監聽位址）、「把這台的 DNS 指到公司的防護 DNS／改回原本的 DNS」（以系統管理員執行命令列版的 `dns use-hub`／`dns restore`，會跳出確認）；每個選項都有白話提示。「黑名單」卡片：貼網域或網址加入（含子網域）、移除這台的條目、看到 Hub 的黑名單（唯讀）；每筆查詢紀錄都有「封鎖」。頁面上方「DNS 防禦怎麼用」四步驟說明；可疑理由也會標出黑名單命中。
- **資安報告（依選定區間）**：總覽右上角「產生資安報告」（最近 7／30／90 天或自訂期間），新頁 `/report`：選開始與結束日期（含當天，最長 366 天）、可限定一台主機；內容有自動整理的重點（新增／處理／期末待處理的問題、平均安全分數的變化、情資命中、危險與可疑 IP、DNS 告警與防護 DNS 擋下的次數、資安事件、自動回應、分數最低的主機）、問題依嚴重度的新增／已處理／期末待處理表、最常出現的問題、新出現的嚴重與高風險問題、安全分數期初→期末與每日走勢、分數最低的主機、情資來源命中與危險 IP（含 IP 備註）、DNS 被擋最多的網域、資安事件、封鎖與遠端動作、MITRE ATT&CK 技術。可以「列印／存成 PDF」（列印時自動換成淺色、隱藏側欄）或「下載 Markdown」；API `GET /api/v1/report?from=&to=[&agent_id=][&format=md|json][&lang=]`（管理員或 read 權杖）。
- **集中設定（依主機群組推送）**：「設定與金鑰 → 自動回應 → 主機群組」每個群組可以設定要推給成員的安全選項（完整掃描間隔、連線快照間隔、檔案與開機自啟監控、額外／不監看的路徑、快照附網域），留空＝不推。多個群組依名稱合併（單一值後蓋前、清單取聯集）。心跳回應帶 `config_version`，agent 版本不同時取 `GET /api/v1/agents/me/config`，用 **Hub Ed25519 身分簽章**、agent 以釘選的公鑰驗章，不認得的欄位整份拒收；存在 `central.json` 疊在本機設定上（不改 config.json），間隔立刻生效，Hub 拿掉就改回本機設定。不推效能蒐集、遠端動作與任何指令；主機可 `config set central_config false` 拒收（[docs/auto-response.md](docs/auto-response.md)）。
- **修正：部分更新會把沒送的欄位洗成預設值**（zod v4 的 `.partial()` 仍套用 `.default()`）：停用／啟用自動回應規則會重設門檻與封鎖時間、停用通知規則會清掉分鐘數／整點、只改群組名稱會清空成員。改成只更新有送的欄位，並加回歸測試。
- **情資可以逐一手動更新**：Hub「威脅情資」每個 Hub 會下載的來源（例 CISA KEV、各黑名單）在「Hub 最後同步」欄多了「立即更新」，每一區標題旁有「這一區全部更新」；按下就不管更新間隔馬上向廠商下載，並叫所有主機下次心跳改用新的。線上 API 類（EPSS、NVD、OSV、AbuseIPDB 等）原本只寫「不鏡像」，改成說明「掃描時即時查詢／查詢時即時取得」：沒有清單可下載，本來就是最新的。API：`POST /api/v1/admin/feeds/sync` 可帶 `only: [來源 id]`。
- **Windows 一鍵開啟各程式的網路流量**：桌面版「流量與效能」量不到各程式流量時，多了「開啟各程式流量」按鈕（跳一次 Windows UAC），背景服務改成「登入時以系統管理員權限啟動」的排程工作（仍用自己的設定目錄、取代 HKCU Run，之後登入不再詢問），就會開始記錄各程式的流量並回報 Hub。命令列：`ai-security-monitor service install --admin-at-logon --yes`（關閉：`service uninstall --admin-at-logon --yes`，換回一般的登入啟動）；`service status` 會顯示是否開啟；更新後的重新啟動也會用排程工作。帳號要是系統管理員群組成員。設定頁的「背景自動回報」也會顯示這個狀態。

- **DNS 黑名單、怎麼用、IP 備註直接編輯、回上一頁**：可以自己加黑名單（條目含子網域）：這台電腦用 `ai-security-monitor dns block <網域…>`（可貼網址、`--note` 備註）／`dns unblock`／`dns blocklist`；全公司在 Hub 網域分析頁按「加入黑名單／移出黑名單／加入允許清單」（新 API：`POST /api/v1/admin/dns-protect` 帶 `block_add`、`block_remove`、`allow_add`、`allow_remove`，只改那幾筆、不蓋掉別人同時加的）。任何一台電腦查到黑名單網域就告警（新規則 `dns.blocklisted`，高；Hub 的黑名單隨防護 DNS 設定每 10 分鐘同步到各台），`dns --suspicious` 也會標出來；防護 DNS 直接擋，跑防護 DNS 的那台自己的黑名單改了 1 分鐘內生效。Hub DNS 頁加「DNS 防禦怎麼用」四步驟說明（沒有紀錄時自動展開）與黑名單筆數；docs/dns.md 加「黑名單」一節。可疑 IP 清單的備註可以直接點著改（Enter 儲存、Esc 取消、清空＝刪除），不必跳到 IP 分析頁。主機、IP 分析、網域分析、可疑 IP 清單等內頁加「← 回上一頁」：從 Hub 裡點進來的回上一頁（篩選與捲動位置保留），直接開網址的回上層頁面。修正：`dns use-hub` 的探測改用 connected UDP（沒人聽時馬上失敗、只收那台回的封包），測試不再受這台有沒有在跑 DNS 影響。
## v0.6.0 — 2026-10-18

**DNS 防禦：每台電腦即時看查了哪些網域、哪個程式查的，偵測 DNS 通道、亂數網域、被竄改的 DNS 與 hosts；選用的防護 DNS 伺服器（自己寫的 Rust，約 12 萬 QPS），由 Hub 開關、暫停、放行，`dns use-hub` 一鍵把電腦指過去、連不上自動改回；另有檔案完整性與開機自啟監控、通知（Email／Slack／Discord／Teams／Webhook／Syslog）、自動回應、MITRE ATT&CK 與法規對照、IP 反查網域。** 一般使用者請下載 `AI-Security-Monitor-0.6.0-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；0.5.0 的桌面版會自動提示更新。防護 DNS 可以用命令列版的 `ai-security-monitor dns-server`，或新的 Docker 映像 `ghcr.io/markku636/ai-security-monitor-dns`（Hub compose 加 `--profile dns`）。

**升級注意**：
- **DNS 查詢紀錄預設會上傳到加入的 Hub**（`dns.enabled` 與 `dns.upload=all` 預設開）。DNS 紀錄等於上網紀錄，公司部署前請先告知員工；那台電腦可以 `ai-security-monitor config set dns.upload alerts`（只傳告警）或 `off`，Hub 保留天數用 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS`（預設 7 天）調整。
- 新掃描器 `files`（檔案完整性＋開機自啟監控）預設開，第一次只建基準、不告警。
- abuse.ch URLhaus／ThreatFox 依 2025-11-04 的新條款改標非商用：照樣告警，但不再拿來自動封鎖。
- Hub 資料庫 migration 0013–0017 會在啟動時自動套用。要用 compose 內建的防護 DNS，`.env` 加 `AI_SECURITY_MONITOR_HUB_DNS_TOKEN`（至少 32 字元）。

- **桌面版「DNS」頁＋文件與授權**：側欄新增「DNS」：這台查了哪些網域、是哪個程式查的、結果、解析到的 IP，可疑的（情資網域、像亂數產生的網域、少見頂級網域、加密 DNS 端點）標出理由，可選期間（15 分鐘到 7 天）、搜尋網域或程式、只看可疑；查詢次數、不同網域、NXDOMAIN 比例、資料來源；查詢最多的網域與程式；公司有防護 DNS 而這台沒用時提示 `dns use-hub`。README 補 DNS 防禦與防護 DNS、命令速查、文件連結與桌面版截圖（重拍全部桌面版截圖）；THIRD_PARTY_NOTICES 補 CERT Polska、HaGeZi（GPL-3.0）、Phishing.Database、Block List Project、Phishing Army、Public Suffix List（MPL-2.0）、Majestic Million（CC BY 3.0），abuse.ch URLhaus／ThreatFox 改標非商用。示範資料（`scripts/demo-seed.mjs`）加 DNS 查詢、fin-laptop-07 的亂數網域與 DNS 通道告警，以及一台連上 Hub 的防護 DNS。修正：`dns use-hub` 在 Windows 只挑有 DNS 用戶端設定的網卡（有些虛擬網卡啟用中卻沒有 DNS 設定，改它會失敗）；任何方式改到一半失敗時，先把已經改過的改回去再回報錯誤。
- **防護 DNS 效能量測＋文件**：新壓測程式 `cargo run --release --example dnsbench`（同一個行程裡起伺服器、本機假上游與 64 個用戶端）：開發機約 12.3 萬 QPS（快取命中＋封鎖混合）、命中 p99 0.56 ms、200 萬筆封鎖清單比對約 300 ns、重建 0.16 秒、常駐記憶體約 40 MB。封鎖比對加了分桶索引（雜湊高位元選桶、桶內二分搜尋；雜湊最後多混一次讓高位元均勻），200 萬筆時從約 1 µs 降到約 0.3 µs。CI 新 job `dnsbench` 每次在 Linux runner 跑 15 秒、把數字寫進 job summary，只有嚴重退步才失敗。新文件 [docs/dns.md](docs/dns.md)（每台電腦的 DNS 監看、規則、竄改偵測、dns-lock、硬化）與 [docs/dns-server.md](docs/dns-server.md)（防護 DNS 的運作、三種部署、`dns use-hub`、Hub 管理、效能、隱私），都有英文版。
- **`dns use-hub`／`dns restore`：把這台的 DNS 指到防護 DNS**：`ai-security-monitor dns use-hub [--server IP,…] [--dry-run]`（省略 `--server`＝Hub「防護 DNS」新設定「裝置要用的 DNS 位址」，設定頁會依在線伺服器建議）先確認防護 DNS 查得到（查不到就不改，避免斷網），照樣預演、確認、提權，記下原本的設定再改：Windows 每張啟用中的網卡 `Set-DnsClientServerAddress`（原本手動還是 DHCP 從登錄判斷）、macOS 每個網路服務 `networksetup`、Linux 依偵測到的管理程式用 NetworkManager（持久）、systemd-resolved（重開機後失效）或直接改 `/etc/resolv.conf`。`dns restore` 改回原狀。**保險**：背景服務每分鐘對這些位址查健康檢查名稱，連續 3 次查不到就自動改回原本的 DNS 並留下紀錄（`dns.protect_restored`，中）。新規則 `dns.not_protected`（低）：Hub 開啟防護 DNS 且設了「裝置要用的 DNS 位址」，但這台的 DNS 不是它（這台自己就是防護 DNS 時指向 loopback 也算）。CI 在 Windows（兩個版本）、macOS、Linux runner 真的切換：本機起一台擋 `www.example.org` 的防護 DNS、`use-hub` 後系統解析被擋、一般網域照常，`restore` 後 DNS 設定跟改之前完全一樣。
- **防護 DNS 的部署方式**：(1) **Hub 的 compose**：`docker compose -f docker/compose.yml --env-file .env --profile dns up -d`（`.env` 設 `AI_SECURITY_MONITOR_HUB_DNS_TOKEN`，至少 32 字元，Hub 與 dns 共用；沒加 `--profile dns` 就不會起）。新映像 `ghcr.io/markku636/ai-security-monitor-dns`：只有 musl 靜態執行檔與 CA 憑證（FROM scratch、amd64＋arm64、以 nobody 執行、健康檢查用 `dns-server --healthcheck`）；只發布到 `AI_SECURITY_MONITOR_HUB_DNS_BIND`（預設 127.0.0.1，給區網用改成這台的區網 IP）與 `AI_SECURITY_MONITOR_HUB_DNS_PORT`。Linux 要看到每個裝置的真實 IP 再加 `-f docker/compose.dns-host.yml`（host 網路）。(2) **任一台常開的電腦**：`ai-security-monitor config set dns.server.enabled true`（可加 `dns.server.listen`），背景服務以子行程帶起 `dns-server`（加入 Hub 時用這台的身分連 Hub、情資交給背景服務更新），結束就自動重啟（連續失敗退避到最多 5 分鐘），設定改了就重啟套用，輸出在 `dns-server/server.log`；Windows 用 Job Object、Unix 用 process group，背景服務停掉時一起收掉。另外：Windows 上綁 53 不需要系統管理員，防護 DNS 改用 `SO_EXCLUSIVEADDRUSE` 獨佔 port（別的程式不能用 `SO_REUSEADDR` 綁同一個位址搶走查詢），UDP 也不再設 `SO_REUSEADDR`。CI 的 docker job 建 musl 映像、用 standalone compose `--profile dns` 實測：容器健康、經加密 DNS 解析、Hub 開封鎖後擋自訂網域、Hub 看得到這台；release 建 amd64＋arm64 映像（版本檢查涵蓋 `docker/Dockerfile.dns`）。
- **防護 DNS 由 Hub 管理**：「設定與金鑰」新增「防護 DNS」分頁：封鎖開關（預設關＝只轉送，正在用它的裝置不會斷網）、暫停 5 分鐘／1 小時（倒數、到期自動恢復）、連上來的伺服器（在線、查詢量、快取命中率、封鎖數、延遲、封鎖清單筆數與還沒下載的清單、上游延遲）、最近 24 小時被擋最多的網域與查詢最多的裝置（對得到主機的直接連過去）、最近被擋的查詢一鍵「放行」、上游、封鎖用的情資清單（不勾＝自動挑可商用、信心夠高的）、自訂封鎖／允許清單、內部網域、iCloud 私密轉送、要不要記錄查詢，以及部署教學（含路由器 DHCP 與 IPv6 RDNSS 也要指過來）。DNS 頁頂端顯示防護 DNS 狀態。`dns-server --hub <網址> --hub-token <權杖>`（API token 新權限「防護 DNS 伺服器」，或 compose 的 `AI_SECURITY_MONITOR_HUB_DNS_TOKEN`）或 `--hub-agent`（用這台加入 Hub 的身分）：每分鐘拉設定（ETag）、每 30 秒心跳、查詢紀錄依（用戶端, 網域, 類型, 結果）每分鐘聚合後分批上傳（Hub 連不上時暫存、恢復後補送），Hub 改了設定下一次心跳就生效；最後一份設定存在本機，重啟時 Hub 連不上也照上次的設定。上游、清單與內部網域在執行中直接替換，不必重啟。dns-server 也會自己下載封鎖用的情資清單（連 Hub 時走 Hub 鏡像；背景服務帶起時用 `--no-feed-update` 交給 watch）。新端點 `GET /api/v1/dns/config`、`POST /api/v1/dns/heartbeat`、`POST /api/v1/dns/queries`（`contract/dns-heartbeat.v1.json`、`dns-resolver.v1.json`），資料庫 migration 0017（`dns_servers`、`dns_resolver_queries`，保留期限同 DNS 原始紀錄）。CI 的 agent↔Hub 端對端測試實際跑一台連 Hub 的防護 DNS：Hub 開封鎖就擋、關掉就只轉送、Hub 收到心跳與被擋的查詢。
- **防護 DNS 伺服器（選用，預設不開）**：新指令 `ai-security-monitor dns-server`，給區網裝置用的 DNS：封鎖情資列名的網域（回 NXDOMAIN＋EDE 15「Blocked」）、上游走加密 DNS（預設 Quad9 與 Cloudflare 的 DoH，HTTP/2 連線複用，兩家錯開 250 毫秒競速）、快取（存原始回應、命中只改 ID 與 TTL；上游全掛時用 1 天內的過期答案頂著、快過期的熱門答案先刷新、同一題同時多人問只送一次上游）。只服務 loopback 與私有網段（`--acl` 可改），每個用戶端每秒 200 題上限；公網名稱回私有 IP 會丟掉（DNS rebinding，`--internal-suffix` 放行內部網域）、ANY 回最小答案、超過 EDNS 大小設 TC 讓用戶端改走 TCP；Firefox 的 `use-application-dns.net` 回 NXDOMAIN（讓 Firefox 不自己走加密 DNS），`--block-private-relay` 另擋 iCloud Private Relay。封鎖清單只用已下載、啟用、可商用且信心 ≥ 75 的網域情資（目前 CERT.PL、HaGeZi TIF mini），每份分開載入、只存 64-bit 雜湊（35 萬筆約 3.4 MB），每 10 分鐘在背景重建後無鎖替換；啟動時先只轉送、清單建好才開始封鎖。`--block`／`--allow` 自訂、`--no-block` 只轉送；查詢紀錄依（用戶端, 網域, 類型, 分鐘）聚合寫進 `<設定目錄>/dns-server/`（`--no-log` 關閉），狀態每 30 秒寫 `dns-server/status.json`（`dns-server --status` 看查詢量、快取命中、封鎖數、延遲分位數、上游延遲）。`dns-server --healthcheck` 查自有測試名稱（`healthcheck.asm-dns.invalid` 應有答案、`blocked-test.asm-dns.invalid` 應被擋）。封包解析自己寫（零配置、不重組封包），有 2 萬次亂資料模糊測試。Linux 每核心一個 SO_REUSEPORT socket、Windows 關掉 SIO_UDP_CONNRESET，`0.0.0.0:53` 被佔（systemd-resolved、ICS）時改綁各網卡位址。CI 在三個平台實際起在高 port：健康檢查、真的上游答案、第二次命中快取、測試網域被擋。三平台命令列版都帶，桌面版不帶。
- **防繞過：`fw dns-lock`／`fw dns-unlock`＋DNS 硬化檢查**：`ai-security-monitor fw dns-lock [--allow IP,…] [--block-doh]` 擋掉程式直接連外部 DNS（53／853），只准連允許的 DNS（省略＝目前在用的，一律含 loopback；Linux 用 systemd-resolved 時讀它真正的上游）；`--block-doh` 另外擋常見加密 DNS 業者（Cloudflare、Google、Quad9、OpenDNS、AdGuard、NextDNS…）的 443。目前在用的 DNS 不在允許清單就拒絕套用（會斷網），除非 `--force`；照樣先預演、確認、提權，寫進期望狀態讓 `fw ensure` 重套。Windows 用允許清單的補集當封鎖規則（封鎖優先於允許）、nftables 用獨立的 `dnslock` chain、iptables＋ipset、macOS pf anchor 都支援。硬化新增 Windows：NetBIOS 名稱解析、智慧型多重主目錄名稱解析（VPN 時 DNS 外洩）、WPAD（`DisableWpad`，不停用 WinHttpAutoProxySvc）、DoH 政策（資訊）、mDNS（資訊）；Linux（systemd-resolved）：LLMNR、mDNS（資訊）、DNS over TLS（資訊）、DNSSEC（資訊）。CI 在 Windows 與 Linux runner 實際套用：直連 8.8.8.8 失敗、系統 DNS 照常、解除後恢復。
- **DNS 竄改偵測**（`dns` 掃描器）：`dns.resolver_changed`（每個網路分開記 DNS 伺服器基準，筆電換網路不誤報；改成未知的公網 DNS＝中、黑名單上的＝高；在那台執行 `ai-security-monitor dns accept` 確認後更新基準）、`dns.resolver_intel`（正在用的 DNS 伺服器被情資列名）、`dns.hosts_tampered`（hosts 檔把熱門網站導到固定位址、擋掉或導走防毒與系統更新網域、有 wpad 條目；只擋廣告的 `0.0.0.0` 條目不算；hosts「有沒有被改」交給檔案完整性監看）、`dns.wpad`（`wpad.*` 查詢有回答）、`dns.nxdomain_hijack`（每個網路每 6 小時查 3 個不存在的亂數網域，≥ 2 個回同一個位址就是 DNS 把查無此網域改成導向）、`dns.answer_mismatch`（新設定 `dns.verify_answers`，預設關：開啟後拿 3 個常見網域的答案跟 Cloudflare 加密 DNS 比對業者）、`dns.rogue_profile`（macOS 裝了加密 DNS 描述檔）。狀態存在 `dns/tamper.json`。
- **自動回應＋主機群組**（[docs/auto-response.md](docs/auto-response.md)，**預設關閉**）：「設定與金鑰」新增「自動回應」分頁。規則觸發條件：暴力破解來源（登入失敗次數門檻）、情資列名的來源連進來、指定的問題規則；符合時 Hub 替主機建立並核准雙向「封鎖 IP」（`auto:<規則>`），到期自動「解除封鎖」，重複觸犯（30 天內）×6、×24。護欄：只封公網 IP、白名單網段永不封、只對同意遠端動作的主機、同一 IP 同時一筆、每輪最多 50 筆；關掉開關後既有封鎖照常到期解除；「目前的封鎖」可立即解除；稽核 `response.blocked`／`response.released`。主機群組可以限定規則範圍（刪群組會停用只套用到它的規則）。資料庫 migration 0016。
- **通知**（[docs/notifications.md](docs/notifications.md)）：「設定與金鑰」新增「通知」分頁。頻道：Email（SMTP，nodemailer）、Slack、Discord、Microsoft Teams（Adaptive Card）、自訂 Webhook（JSON＋選填 HMAC-SHA256 簽章 `x-aism-signature`）、Syslog（UDP／TCP，RFC 5424 或 CEF），都有「送測試訊息」。規則：新的問題（嚴重度門檻）、新的危險連線、主機沒有回報（N 分鐘）、新主機加入、封鎖等待審核、每日摘要（UTC 整點）；可限定某台主機。Hub 每分鐘檢查一次，只通知規則建立之後發生的事，同一件事只送一次、一次檢查的多件合併成一則，失敗重試 3 次，頻道顯示最後的錯誤，最近送出紀錄保留 30 天；多個 Hub 行程用 advisory lock 只送一次。密碼與 webhook 網址以 AES-256-GCM 加密存放（金鑰 `AI_SECURITY_MONITOR_HUB_SECRETS_KEY`，沒設時自動產生存在資料庫），網頁只顯示遮罩、稽核不記內容。訊息語言與連結用的 Hub 網址可設定。資料庫 migration 0015。
- **Hub：DNS 頁、網域分析頁、AI 與 MCP**：側欄「網路」多了「DNS」：查詢次數、不同網域（依可註冊網域）、NXDOMAIN 比例、待處理的 DNS 告警（可直接批次處理）、查詢最多的網域、全隊 24 小時內第一次出現的網域、最近的查詢（搜尋網域或程式、只看查無此網域、點 IP 看 IP 分析）、各主機 DNS 監看狀態（資料來源、有沒有程式資訊、最後一筆）。新頁 `/domain/<網域>`：哪些主機與程式查過、解析到的 IP、結果分布、完整名稱、7 天每小時次數、相關告警、情資紀錄與外部查詢連結（只放連結，Hub 不送出網域）。AI 助手多了「解讀 DNS」範圍，單一指標是網域時改用網域版提示；Hub MCP 新增 `dns_overview`、`dns_queries`、`domain_summary`。`dns.*` 規則對到 MITRE ATT&CK（T1071.004、T1572、T1048.003、T1568.002），技術目錄補上「資料外洩」戰術。新表與保留期限見上一條（`POST /api/v1/ingest/dns`、migration 0014、`AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS`／`_HOURLY_DAYS`）。
- **檔案完整性＋開機自啟監控**（掃描器 `files`，預設開）：每次掃描比對重要位置的檔案（Windows：hosts、啟動資料夾、排程工作、驅動程式、PowerShell profile；Linux：/etc、系統程式目錄、cron、systemd、/boot、SSH authorized_keys；macOS：/etc、LaunchAgents／LaunchDaemons、/usr/local/bin）與開機自動執行項目（Windows 登錄 Run／RunOnce、Winlogon Shell／Userinit、自動啟動的服務；Linux 已啟用的 systemd 單元）。記大小、修改時間、權限，1 MiB 以下的檔案每次都比 sha256。第一次只建基準不告警；之後新增／修改／刪除／權限變更成為問題（`fim.<分類>.<變更>`、`fim.autorun.<種類>.<變更>`，開機會執行的位置是「高」），連續 7 天出現在報告裡或直到在那台電腦 `ai-security-monitor fim accept <路徑>`（`--all`）。新指令 `fim status`／`fim accept`／`fim baseline`；設定 `fim.enabled`、`fim.extra_paths`、`fim.ignore`（前綴或 `*` 萬用字元）。最多監看 5 萬個檔案、一次最多列 100 個問題。Hub：主機總覽顯示監看數與待確認變更，問題對應到 MITRE（啟動資料夾／Run＝T1547.001、服務＝T1543.003、cron＝T1053.003、authorized_keys＝T1098.004…）與 PCI DSS 11.5.2、NIST SI-7。
- **DNS 偵測規則＋上傳 Hub**（新掃描器 `dns`，`dns.*` 規則）：每次掃描看最近 15 分鐘的 DNS 紀錄，以 5 分鐘為一窗、鍵用（程式, 可註冊網域）：`dns.intel_domain`（網域分數 ≥ 60，≥ 80 高、≥ 90 嚴重，附來源網址）、`dns.tunnel`（同一程式對同一網域 5 分鐘 ≥ 100 次且子網域多半不重複又長又亂＝高；≥ 20 次且 TXT／NULL ≥ 30%＝中）、`dns.dga`（≥ 10 個不存在又像亂數產生的網域，排除 Chromium 探測名稱）、`dns.nxdomain_burst`（≥ 50 次 NXDOMAIN、≥ 20 個網域）、`dns.doh_bypass`（瀏覽器與系統以外的程式查加密 DNS 端點）、`dns.tunnel_service`（Cloudflare Tunnel、Dev Tunnels、ngrok）。白名單、known-good 與熱門網域不做推測型告警；情資沿用 intel 掃描已載入的，不重載大型清單。報告多了 `summaries.dns`（查詢量、不同網域、NXDOMAIN、前幾名網域與程式、蒐集狀態），Hub 存成主機摘要。`dns.upload = all` 且加入 Hub 時，背景蒐集把每分鐘紀錄排進 `dns/queue.jsonl`，watch 每分鐘分批送 `POST /api/v1/ingest/dns`（`contract/dns.v1.json`；Hub 還不支援時先存著、之後補送）。
- **攻擊手法與法規（MITRE ATT&CK＋ISO 27001／NIST 800-53／PCI DSS 4／CIS v8）**：Hub 依每個問題的規則對應到 MITRE ATT&CK 技術與法規控制項（對應表自己寫的，在 Hub 端算，所以舊版 agent 的問題也有、改對應表不用重新掃描）。新頁「攻擊手法與法規」（`/mitre`）：戰術欄 × 技術格，顯示待處理問題數與主機數（子技術算進上層技術），可選 7／30 天／全部、篩主機；四個框架各列控制項與問題數。問題清單展開後顯示手法與法規標籤（滑過看白話說明），點標籤或格子＝問題頁 `technique=`／`control=` 篩選（也接受整個框架，例 `control=iso27001`）。對應是參考用，不等於稽核或認證。
- **IP 反查網域**：IP 分析頁新增「這個 IP 上的網域」。一、主機連線時解析過的名稱：Windows 電腦上傳連線快照時，順便讀 DNS 快取，附上**目前有連線**的公網 IP 是從哪個網域解析來的（只送這些、不送整份快取；名稱在電腦上記 24 小時，Hub 保留 30 天）；`ai-security-monitor config set scan.dns_names false` 可關掉。可疑 IP 排名與連線表的 IP 底下也會顯示這個網域。二、反解（PTR）。三、外部被動 DNS 反查：按「查詢網域」才把 IP 送給 HackerTarget（免金鑰，每天次數少）、VirusTotal（要金鑰）、AlienVault OTX（金鑰選填），顯示看過的網域總數與清單（最多 200 個、最後看到時間）。這三個來源不算進風險分數、批次查詢與「查詢全部未分析」不會用到，結果存在自己的快取（清除「外部情資查詢快取」時一起清）。金鑰可在「設定與金鑰 → 外部情資來源」貼上或用 `AI_SECURITY_MONITOR_HUB_VIRUSTOTAL_KEY`／`…_OTX_KEY`／`…_HACKERTARGET_KEY`。資料庫 migration 0013（`ip_domains`、`ip_domain_lookups`）。

## v0.5.0 — 2026-10-18

**桌面版「流量與效能」圖表頁（即時／1 小時／24 小時，含各程式流量與 CPU、記憶體、磁碟）、Hub 各程式的網路流量圖；「加入公司 Hub」併進桌面版設定頁；Hub 加入模式（預設自動允許加入）、在網頁上登入 Claude Code／Codex、清除歷史、可疑 IP 國旗與完整清單、更多網域情資；連線表可排序篩選；立即上傳碰上限流會自動重試。** 一般使用者請下載 `AI-Security-Monitor-0.5.0-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；0.4.0 的桌面版會自動提示更新。**升級注意**：沒設定過加入模式的 Hub 升級後會變成自動允許加入，要維持人工核准請到「新增主機 → 加入模式」選「審核加入」。

- **DNS 監看（Windows 先上）**：背景服務即時記錄這台電腦查了哪些網域、是哪個程式查的（自己開一個私有的 DNS Client ETW session，只收「查詢完成」事件、PID 取事件標頭，不改系統的事件紀錄設定；略過 Dnscache 服務自己與查本機名稱的查詢），每分鐘依（網域, 類型, 結果, 程式）聚合寫進 `<設定目錄>/dns/YYYY-MM-DD.jsonl`，保留 7 天。沒有系統管理員權限時改用 DNS 快取快照（每 30 秒，看不到程式）。事件走有界佇列，忙不過來只會少記、絕不擋住 DNS。新指令 `ai-security-monitor dns`（`--since`、`--suspicious`、`--process`、`--follow` 即時看）與 `dns status`；新設定 `dns.enabled`（預設開）、`dns.upload`（all／alerts／off，給之後上傳 Hub 用）。連線表（命令列與上傳的快照）補上遠端 IP 最近一次解析到的網域，快照的 `dns_names` 也直接用即時對照、不必再讀 DNS 快取。**Linux**：AF_PACKET 監聽 53 port 回應（root），核心過濾器只放行 DNS 回應，用回應的目的 port 對到程式；有 systemd-resolved 時用 stub 回給程式的那筆，resolved 向上游查的那筆扣住 300 毫秒去重（nss-resolve 不經 stub 時照樣記錄）。**macOS**：每張啟用中的網卡（含 VPN `utun*`）開 BPF，查詢由 mDNSResponder 代送，程式改在連線表上反推。
- **「立即上傳」碰上 Hub 限流會自己等一下再傳**：背景服務剛上傳完時按 `upload`（或桌面版「立即掃描並上傳到 Hub」），Hub 會要求幾十秒後再傳；現在照 Hub 給的秒數（90 秒以內）顯示「等一下自動重試…」並重送一次，不再直接失敗。錯誤訊息也不再重複成「Hub 錯誤：Hub 錯誤：…」。
- **可疑 IP：國旗、完整清單頁、一鍵查全部未分析**：國家欄改成國旗＋國家代碼（滑過顯示國名，依介面語言），用在可疑 IP 排名、連線表、事件、指標詳情、總覽「對內攻擊」與主機頁（內建 SVG，Windows 也看得到；`country-flag-icons`，MIT）。新頁「連線 → 可疑 IP 清單」（`/connections/ips`）：完整排名每頁 50 個、可排序、時間範圍、主機與「只看未分析」篩選，勾選換頁也保留（存在這個分頁的 sessionStorage）。排名卡與清單頁都有「查詢全部未分析（N 個）」：不限這一頁，把還沒查過外部情資的公網 IP 依嚴重度、次數每 5 個一批查完（一次最多 500 個），有進度與「停止」，一整批都失敗（多半是當日免費額度用完）就自動停下。排名卡加「看完整清單 →」。
- **桌面版「流量與效能」頁（圖表）**：側欄的「即時流量」改成「流量與效能」，頁內三個分頁：**即時（每秒）**（原本的即時流量頁）、**最近 1 小時**（每分鐘一點）、**最近 24 小時**（每 5 分鐘一點）。歷史分頁有網路速度、各程式的網路流量（前 6 名各一條線＋其他，可切換合計／下載／上傳，附這段期間的前 10 名）；開啟效能蒐集時另有 CPU（24 小時圖附最高值）、記憶體、磁碟讀寫、各磁碟區、最吃 CPU／記憶體的程式、電池；沒開時只畫網路並附說明與開關。量不到各程式時用白話說明（Windows 要以系統管理員執行背景服務：`ai-security-monitor service install --system --yes`；macOS 有、Linux 沒有）。圖表是純 SVG（`desktop/ui/chart.js`，從 Hub 的 TimeChart 移植）：滑過或用鍵盤顯示十字線與各線數值、文字圖例、y 軸刻度好讀（位元組用 1024 倍數）、深淺色各自驗證過的色票、給螢幕閱讀器的表格。總覽的小走勢圖點下去到「最近 1 小時」。
  - **本機 24 小時歷史**（[docs/metrics.md](docs/metrics.md#本機的-24-小時歷史)）：`watch` 每個樣本加進 5 分鐘彙總（`metrics/history-open.json`，每分鐘改寫 1–2 KB），換格時接到 `metrics/history.jsonl`（一行一格、只留 24 小時、約 300 KB）；含網路、各程式（前 12 名＋其他）、CPU 平均／最高、記憶體、磁碟讀寫、磁碟區與電池。壞行略過並在整理時清掉，「這一格」壞了就重新開始。沒加入 Hub 也記；背景服務沒在跑時桌面版開著（含系統匣）就自己每分鐘取樣並寫進同一份歷史。桌面版新指令 `metrics_history`（`1h`／`24h`）。
  - 修正：`hidden` 的元素若有 `display` 樣式（例如右下角的新版提示）按關閉後仍會顯示。
- **網域情資擴充＋abuse.ch 授權改正**（[docs/intel.md](docs/intel.md#網域)）：新增 CERT Polska 警示清單（可商用，信心 85）、HaGeZi Threat Intelligence Feeds mini（GPL-3.0 原樣鏡像，75；medium／full 預設關）、Phishing.Database（MIT，60，只比完全相同）與 HaGeZi 加密 DNS 端點清單（只給 DNS 繞過偵測用，不算威脅）；Block List Project、Phishing Army 可自行開啟。新格式：hosts、一行一個網域、`*.x` 萬用字元、adblock `||x^`；每個來源標明條目是否涵蓋子網域。網域只存 64-bit 雜湊（50 萬筆約 6 MB），網域分數＝最高信心＋每多一個來源 +10。`intel lookup <網域>` 多列可註冊網域（Public Suffix List）、是否熱門（Majestic 前 1 萬名）、像不像亂數產生（DGA）、是否加密 DNS 端點。abuse.ch 自 2025-11-04 起條款改為非營利使用，URLhaus／ThreatFox 改標非商用（照樣告警、不自動封鎖）。Hub 威脅情資頁把網域清單獨立成「惡意網域與加密 DNS 端點」。
- **清除歷史**：「設定與金鑰」新增「資料清除」分頁，三張卡各自顯示筆數、最舊時間與保留期限，可全部清或只清 N 天以前的：AI 分析紀錄（執行中的保留；可勾「一併刪除 AI 程式留下的對話紀錄」＝Claude Code／Codex 在 Hub 資料目錄的 session，不碰登入資料）、連線歷史（可疑 IP 排名的累計，可只清某台主機；IP 備註保留）、外部情資查詢快取。AI 助手「最近的分析」每筆可單獨刪除。自動保留：AI 分析 90 天、外部情資快取 30 天（`AI_SECURITY_MONITOR_HUB_AI_RETENTION_DAYS`／`…_IPINTEL_CACHE_DAYS`，0＝不自動清），跟流量彙總同一支排程。每次清除寫稽核 `history.cleared`／`ai_analysis.deleted`。
- **桌面版即時流量**：側欄新增「即時流量」頁，每秒更新的下載／上傳速率（大字＋Mbps）、最近 60 秒或 5 分鐘折線圖、這次累計，各網路卡速率（虛擬網卡標示），哪個程式在用網路（Windows 以系統管理員執行時、macOS 用 nettop）。用自己的取樣器，不影響背景服務與總覽卡片每分鐘的取樣；只在這頁開著時量、視窗縮到系統匣時暫停、不存檔。
- **連線表：點表頭排序＋更細的篩選**：桌面版「連線」每個欄位（判定、方向、遠端、條數、國家／組織、程式、理由）點表頭就排序、再點反向；新增協定（TCP／UDP）、連線狀態（ESTABLISHED、TIME_WAIT、LISTEN…依實際出現的值）、理由類型（情資／行為／沒有理由）、程式與國家下拉、port、「只看公網位址」「隱藏本機迴路」，可任意組合、一鍵清除。Hub「連線」頁同樣可點表頭排序（server 端 `sort`／`dir`），並加協定、狀態、理由類型、程式（含建議清單）、port、只看公網位址篩選；API `/api/v1/connections` 也接受這些參數。
- **在網頁上登入／登出 AI（Claude Code、Codex）**（[docs/ai-login.md](docs/ai-login.md)）：Hub「AI 助手」最上面新增「AI 帳號」卡，顯示 Hub 主機上兩個程式有沒有安裝、有沒有登入、登入哪個帳號與方案，並標出會蓋過登入的環境變數。「登入」：Claude 啟動官方 `claude auth login`、顯示授權頁面連結，授權後把代碼貼回來就完成；Codex 啟動 `codex login --device-auth`、顯示網址與一次性代碼，到 OpenAI 網站輸入後自動完成。「登出」執行 `claude auth logout`／`codex logout`。Hub 不讀、不存任何 token（授權碼只轉給官方程式、不進 log 與稽核），稽核記 `ai_account.*`。卡片內附「怎麼登入？」說明與手動指令備案；AI 回「請登入」時分析畫面會提示去登入。桌面版「AI 分析」頁也有「AI 帳號」：登入開終端機跑官方登入指令、登出前提醒會一併登出自己平常用的 CLI。
- **各程式的網路流量圖**：Hub 流量頁與主機「流量」分頁在頻寬圖下面多了一張圖，流量最多的 6 個程式各一條線、其餘合併成「其他程式」（虛線），可切換合計／下載／上傳，滑過看各時段的速率。量不到時直接說明怎麼開（Windows 要以系統管理員執行背景服務：`ai-security-monitor service install --system --yes`；macOS 自動有；Linux 量不到）。查詢在 SQL 裡先把前 6 名以外合併，列數固定。示範資料的程式加上各自的使用時段（開會、定時同步、半夜複寫）。
- **桌面版「加入公司 Hub」併進「設定」**：側欄拿掉「加入公司 Hub」，加入、等候核准、更換、離開都在「設定 → 公司的 Security Hub」。還沒加入時這一區自動尋找（在背景跑、不擋其他設定區塊，2 分鐘內回來不重找）並列出找到的 Hub、找到的方式、連不連得到、指紋，可以直接「申請加入」，或輸入網址「測試這個網址」「申請加入」、用註冊金鑰；加入中在同一區顯示等候核准（Hub 指紋、核對碼，自動確認，離開設定頁就停）、被拒絕的原因與「重新尋找」；已加入時顯示網址與指紋、「開啟 Security Hub」「測試連線」「離開這個 Hub」，並可展開「更換 Hub 或重新加入」。第一次開啟、總覽的「尋找公司的 Hub」與舊的 `#join` 連結都會帶到這一區。從找到的清單換到指紋不同的 Hub 時也會先警告並要求確認（以前會直接顯示 `needs_confirm` 錯誤）。命令列 `upload` 沒加入 Hub 時的提示改指向「設定 → 公司的 Security Hub」。
- **加入模式：自動允許加入（預設）／審核加入**：「新增主機」頁新增「加入模式」。自動模式下電腦端送出申請就直接加入（電腦端不再顯示「等候管理員核准」）；填了「自動核准的網段」時只有那些網段自動加入、其他等你核准。審核模式＝以前的行為。環境變數 `AI_SECURITY_MONITOR_HUB_ENROLL_MODE=auto|review` 可鎖定。保護：以前加入過但身分沒釘選或已刪除的主機一律人工核准；自動核准每 10 分鐘最多 60 台、未領取最多 500 台，超過改成等人工核准（稽核 `enroll_request.auto_capped`）。**升級注意：沒設定過加入模式的 Hub 升級後會變成自動允許加入**，要維持人工核准請到「新增主機 → 加入模式」選「審核加入」或設上面的環境變數。
- **專有名詞即時提示＋分數圓環一致**：總覽五個安全分數圓環改成同樣大小（主機頁也是），滑過或用鍵盤聚焦圓環、標籤、卡片標題旁的「?」立即顯示白話說明（總分怎麼算、連線／對外曝露／漏洞／安全設定各代表什麼、扣分方式）；全站既有的「?」提示改成即時、不被表格裁切的樣式化提示。「硬化」統一改稱「安全設定」。

## v0.4.0 — 2026-10-18

**網路流量統計與效能（效能可選開啟）、桌面版與命令列版自動更新（有簽章）、手動更新與「立即上傳到 Hub」、區網更容易找到 Hub；可疑 IP 排名可選時間範圍，週期性連線誤報大幅減少；圖示改成滿版圓角方塊。** 一般使用者請下載 `AI-Security-Monitor-0.4.0-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；`ai-security-monitor-0.4.0-*` 是命令列版。0.3.0 的桌面版沒有自動更新，要手動裝一次 0.4.0，之後就會自動更新。

- **AI 回答改成排版好的畫面**：Hub「AI 助手」（含「最近的分析」）與桌面版「AI 分析」原本直接顯示 Markdown 原文（看得到 `##`、`**`、表格的 `|---|`），現在顯示成標題、粗體、表格、清單、程式碼區塊與連結；串流到一半也正常顯示。不加套件、不經 innerHTML（原文裡的 HTML 會照字面顯示），連結只允許 http(s) 與 Hub 站內路徑。
- **網路流量統計與效能（效能可選開啟）**（[docs/metrics.md](docs/metrics.md)）：每台電腦每分鐘記錄用了多少網路，Hub 畫出頻寬圖、哪台與哪個程式用最多；CPU、記憶體、磁碟要在那台電腦上自己開啟（預設關，Hub 無法從遠端開）。Windows（含 Server Core）、macOS、Linux 都支援。
  - **網路（一律開啟）**：各網卡收發位元組（計數器相減，處理歸零與 32 位元溢位），只把實體網卡加總；VPN、Docker、WSL、Hyper-V 等虛擬網卡照列但標「虛擬」、不算進總量，Windows 網卡上疊的篩選層（`…Filter Driver-0000`）不列。各程式用量：Windows 以系統管理員執行時用 TCP 延伸統計、macOS 用 `nettop`，Linux 沒有（Hub 改看各行程的連線數）。
  - **效能（`metrics.performance`，預設關）**：CPU 與核心數、記憶體、置換空間、各磁碟區用量與讀寫、開機時間、負載（Linux／macOS）、最吃 CPU／記憶體的前 5 個程式（同名合併）、電池（筆電）。開啟：桌面版「設定 → 蒐集這台電腦的效能（CPU、記憶體、磁碟）」或 `ai-security-monitor config set metrics.performance true`；背景服務每輪重讀設定，不用重新啟動。
  - **agent**：`watch` 每 `metrics.interval`（預設 1 分鐘、最短 30 秒）取樣，在背景執行緒做、有逾時，不會卡住掃描與快照；有 Hub 時排進 `metrics/queue.jsonl`（離線最多一天）分批送出，Hub 太舊（404）就留著、升級後補送；本機保留最近 1 小時。新指令 `ai-security-monitor metrics`（`--json`、`--duration`、`--perf` 只在本機量一次），新設定 `metrics.performance`、`metrics.interval`、`metrics.process_network`，MCP 唯讀工具 `get_metrics`。
  - **Hub**：`POST /api/v1/ingest/metrics`（一批最多 240 個樣本，同一樣本重送不重複計算；`contract/metrics.v1.json`）；新表 `host_metrics`、`host_metrics_hourly`（migration 0011），每 10 分鐘彙總成每小時資料（冪等、advisory lock）；原始樣本保留 `AI_SECURITY_MONITOR_HUB_METRICS_RAW_DAYS`（7 天）、每小時彙總 `AI_SECURITY_MONITOR_HUB_METRICS_HOURLY_DAYS`（90 天）。
  - **Hub 畫面**：流量頁多了期間（1 小時／24 小時／7 天／30 天）、所有主機的頻寬圖（下載／上傳，滑過看數值）、流量最多的主機（24 小時與 7 天）、各網卡、各程式的流量；主機頁新增「效能」分頁（CPU、記憶體、磁碟用量與讀寫、網路速率、電池、最吃資源的程式、各磁碟區；沒開啟時說明怎麼開），「流量」分頁加上這台的頻寬；總覽多了 24 小時流量與「資源吃緊的主機」。圖表是純 SVG（不加套件，深淺色、滑過提示、螢幕閱讀器表格）。
  - **待處理問題**：開啟效能蒐集的主機，磁碟 ≥ 90% 或 CPU 連續 15 分鐘 ≥ 90% 會列成「低」（`metrics.disk_full`、`metrics.cpu_sustained`），恢復或關閉蒐集時自動解決。Hub MCP 新增 `fleet_traffic`、`host_performance`，「請 AI 解讀流量」也會看上傳／下載量。
  - **桌面版**：總覽多一排卡片（網路速率與最近 1 小時小圖；開啟效能時另有 CPU、記憶體、磁碟），設定頁新增效能蒐集開關。
  - **CI**：三個平台檢查 `metrics --json` 讀得到介面計數器、效能預設關、開啟後數值合理（Windows 檢查 TCP 延伸統計）；Hub smoke 送契約範例、e2e 確認 `watch --once` 有送樣本。`scripts/demo-seed.mjs` 多了 7 天的流量樣本（三台開啟效能、兩台沒開），README 與文件加上流量頁與主機「效能」分頁截圖。
- **可疑 IP 排名可以選時間範圍（最近 7 天／30 天／全部，預設 30 天）**：依「最後一次被判可疑」的時間篩選，之後判定變好的 IP（例如修正前的 beacon 誤報）過了這段時間就不再列出。目的地表新增 `last_risky_at`（migration 0010，既有的可疑目的地先用最後看到的時間回填）。
- **自動更新（每台電腦一個設定 `update.mode`：關閉／有新版時通知（預設）／自動更新）**（[docs/install.md](docs/install.md#更新)）：
  - **命令列版背景服務**：`ai-security-monitor config set update.mode off|notify|auto`。`watch` 每天最多查一次 GitHub Release（服務啟動後 2～20 分鐘第一次，之後 24 小時＋0～3 小時隨機；照樣支援 `AI_SECURITY_MONITOR_UPDATE_URL` 鏡像與 `asa-*` 舊資產名），結果記在 `<設定目錄>/update-state.json`、放進心跳。`auto` 時背景服務（`--service`）下載、比對 `SHA256SUMS`、原地替換後重新啟動：Windows 服務以失敗結束碼結束讓「失敗時重新啟動」拉起、systemd／launchd 同理、登入時啟動的（`HKCU\…\Run`、XDG autostart）先啟動新版再結束。開發版（debug、`cargo run`、`target/` 底下）與套件管理員裝的（`/usr/bin`、Homebrew、Scoop、winget、Chocolatey、Nix、Snap）只通知不安裝；前景 `watch`、`watch --once` 也只記錄。
  - **手動更新**：`self-update --yes` 更新後自動重新啟動正在用這個執行檔的背景服務（`--no-restart` 不重啟；系統服務沒有系統管理員權限時提示指令）；套件管理員／開發版要加 `--force`；桌面版內建的 agent 一律拒絕（不然會把桌面版換成命令列版）。`version --check`／`self-update --check` 也記下最新版。`status` 多了「自動更新」「上次上傳」「區網廣播」。
  - **桌面版**：用 tauri-plugin-updater 讀 `releases/latest/download/latest.json`，安裝檔有 minisign 簽章、App 內建公鑰驗過才裝。「設定 → 背景自動回報與自動更新」：三種模式（白話說明）、「檢查更新」（目前／最新版本、看更新內容）、「立即更新」（Windows 安裝程式被動模式，裝完自動重新開啟）。通知模式在右下角顯示「有新版 0.x.y，立即更新」；自動模式先下載，從系統匣「結束」或下次開啟時安裝（登入時以系統匣啟動、還沒開過視窗就直接裝）。.deb 安裝要按「立即更新」並輸入密碼才裝。
  - **誰負責更新**：桌面版和它的背景自動回報是同一個執行檔，一律由桌面版的更新器負責；Windows 安裝程式裝完會依 `HKCU\…\Run` 把背景回報重新啟動（NSIS 收尾步驟 `windows/hooks.nsh`），macOS／Linux 由桌面版重新啟動，桌面版啟動時也會把「有登記卻沒在跑」的背景回報拉起來。另外裝的命令列版背景服務列在同一區，照它自己的 `update.mode`，也可以按「更新命令列版」。
  - **Hub**：心跳多了 `update`（模式、誰負責、最新版）與 `advertising` 欄位（migration 0012：`agents.update_info`、`agents.advertising`）；主機清單與主機頁顯示「有新版 0.x.y」（agent 回報的或 Hub 自己查到的最新版，滑鼠移上去說明這台會怎麼更新），主機頁多了「自動更新」「最後上傳」「區網廣播」。
  - **發版**：release.yml 用 GitHub secrets `TAURI_SIGNING_PRIVATE_KEY(_PASSWORD)` 簽桌面版更新檔（NSIS、macOS `.app.tar.gz` x64／arm64、AppImage；.deb 有簽章才加），`scripts/updater-manifest.mjs` 先用 `tauri.conf.json` 的公鑰逐一驗章（金鑰對不上就失敗）再產生 `latest.json`；Release 多了 `latest.json` 與兩個 `.app.tar.gz`。本機 `npx tauri build` 不需要私鑰（更新檔只在 CI 用 `src-tauri/tauri.updater.conf.json` 產生）。
- **手動上傳**：新增 `ai-security-monitor upload`（立即掃描並上傳：先補送 outbox，再上傳連線快照、完整報告與心跳，印出「已上傳，Hub 收到 N 筆」；失敗的報告照樣暫存）。桌面版總覽多了「上傳到 Security Hub」卡片：上次上傳是多久以前、待重送幾份、「立即掃描並上傳到 Hub」與「重新上傳」，有進度與結果。上傳時間記在 `<設定目錄>/upload-state.json`。
- **區網找 Hub 更實用**（[docs/enrollment.md](docs/enrollment.md#mdns-廣播)）：
  - 背景服務可以常駐幫 Hub 做 mDNS 廣播：`config set hub.advertise_url http://<區網 IP>:8088`，或桌面版設定頁「讓區網裡的電腦找到這台的 Hub」（偵測到這台有跑 Hub 才顯示，自動帶這台的區網 IP，開之前確認網址連得到、指紋和這台的 Hub 相同）。每分鐘確認 Hub 身分，TXT 帶 `fp=`，連續 3 次連不到就停止廣播、恢復後自動繼續；設定改了一分鐘內生效；狀態放進心跳。`hub advertise` 前景指令照舊。
  - Hub「新增主機」頁最上面多了「辦公室的電腦找得到這個 Hub 嗎？」：一句白話結論＋逐項（綁定位址、對外網址是不是本機、Hub 自己的 mDNS 與 Docker 限制、哪台電腦在幫忙廣播、公司 DNS 有沒有 SRV），連不到時說明怎麼改成伺服器版或設 `AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0` 與安全提醒。compose 把 `AI_SECURITY_MONITOR_HUB_BIND` 帶進容器；單機版的 port 綁定改成讀這個變數（預設仍是 127.0.0.1），也可以設 `AI_SECURITY_MONITOR_HUB_MDNS`。
  - 桌面版「尋找公司的 Hub」：每一列顯示找到的方式（滑鼠移上去說明）、連不連得到（連不到附原因）、指紋，「重新尋找」；找不到時說明三種解法（問管理員要網址、Hub 要讓區網連得到、Docker Desktop 要有人幫忙廣播）。`discover` 只找到設定檔那一列時提示下一步（JSON 多 `hint`）。
- **背景服務偵測**：桌面版執行檔帶 `watch --service` 的常駐行程現在也認得出來（Windows 上以前認不出，設定頁顯示「沒在跑」、關掉開關也不會結束它）。
- **減少「週期性連線（疑似 beacon）」誤報**：瀏覽器、VS Code、Claude 等一般用戶端反覆開關 keep-alive 連到 Cloudflare、Microsoft、Google 這類服務，以前會被判可疑而佔滿「可疑 IP 排名」。現在週期至少要是快照間隔的 3 倍才算數（間隔只有一兩個快照時，規律其實是取樣造成的），連到已知良好服務或來自一般用戶端（瀏覽器、編輯器、AI 工具、通訊與同步軟體）的週期性不再判可疑；node、python、PowerShell 等通用執行環境與不明程式照樣偵測。
- **圖示改成滿版圓角方塊（參考 db-kit）**：桌面版的應用程式圖示（標題列、工作列、系統匣、安裝檔）與 Hub 的瀏覽器分頁圖示改成深藍圓角方塊、海豹放大到帽子與臉撐滿，小尺寸（16／32px）也看得清楚；側欄的透明背景 logo 不變。
## v0.3.0 — 2026-10-17

**辦公室電腦可以自動找到公司的 Security Hub、免金鑰申請加入並由管理員核准；桌面版多了設定頁（Hub 網址、開機自動啟動）；Hub 可以批次分析 IP、IP 旁顯示風險圖示、可疑 IP 排名可排序；桌面版 logo 放大；README 改寫成新手看得懂的版本。** 一般使用者請下載 `AI-Security-Monitor-0.3.0-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；`ai-security-monitor-0.3.0-*` 是命令列版。

- **自動尋找 Hub、免金鑰加入**（[docs/enrollment.md](docs/enrollment.md)）：辦公室電腦不用金鑰、不用手動設定就能加入公司的 Security Hub。
  - **尋找**：依序用明確給的網址（`enroll --hub`、Hub 預填的安裝指令、`AI_SECURITY_MONITOR_HUB_URL`）→ 公司 DNS 的 SRV 紀錄 `_aisecmon._tcp.<搜尋網域>`（TXT 可帶 `url=`、`fp=`；Windows 讀 DNS 尾碼、Linux `/etc/resolv.conf`、macOS `scutil --dns`）→ 區網 mDNS／DNS-SD `_aisecmon._tcp.local`。新增 `ai-security-monitor discover`（只列出）與 `enroll --auto [--hub URL] [--wait 15m] [--repin]`；`enroll` 沒給 `--key` 就走免金鑰。
  - **服務名稱**：DNS-SD 服務類型是 `_aisecmon._tcp`（服務名稱 9 字，符合 RFC 6335／6763 的 15 字上限，mDNS 用預設限制就能登記）。開發期間用過的 `_ai-security-monitor._tcp`（20 字）mDNS 不再使用；DNS SRV 在新名稱查不到紀錄時仍會查舊名稱。
  - **Hub 身分（TOFU）**：Hub 第一次啟動產生 Ed25519 身分金鑰（存在 `settings`），`GET /api/v1/hub/identity?nonce=` 回名稱、版本、公鑰、指紋（`XXXX-XXXX-XXXX-XXXX-XXXX`）與對 nonce 的簽章。電腦端驗章後才列出，加入時釘選指紋；之後同網址或自動找到的 Hub 指紋不同就拒絕上傳（`watch` 啟動時檢查），要明確 `enroll --auto --repin` 才換。用金鑰註冊的電腦也會釘選（舊電腦升級後第一次連上時補記）。「新增主機」與「設定與金鑰」頁顯示 Hub 指紋。
  - **加入申請**：`POST /api/v1/agents/enroll-request`（不帶金鑰，帶主機資訊與一組隨機密語，Hub 只存雜湊）→ 管理員在「新增主機 → 待核准的主機」核准／拒絕（可多選，側欄有待核准數字），或來源 IP 在「自動核准的網段」（CIDR，預設空白）內就直接核准 → 電腦以密語輪詢 `GET …/enroll-request/{id}`，核准後拿到**綁定這台 agent id** 的註冊金鑰（Hub 簽章，電腦用釘選的公鑰驗），照一般流程註冊。電腦端與管理頁顯示同一組核對碼。自動核准只看 TCP 真正的來源位址（Hub 在 HTTP 伺服器掛勾取得；開了 `TRUST_PROXY` 才看 X-Forwarded-For）。限流、待核准上限 500、7 天過期、領取後停止發金鑰；核准／拒絕／自動核准／修改網段都寫稽核。新表 `enrollment_requests`（migration 0009），`enroll_keys` 多 `bound_agent_id`：綁定的金鑰拿去用別的 agent id 一律 403 `key_bound_to_other_agent`。`AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS=0` 可關閉。
  - **等候可續**：待核准的申請存在設定目錄（密語在金鑰圈／密鑰檔），再執行 `enroll --auto` 或背景服務（`watch`）都會接著等，核准後自動開始回報。
  - **mDNS 廣播**：Hub 伺服器版預設在區網廣播（`AI_SECURITY_MONITOR_HUB_MDNS`，TXT 帶指紋與 `AI_SECURITY_MONITOR_HUB_PUBLIC_URL`）；Docker Desktop／bridge 網路的 multicast 出不了區網，可用 Linux `network_mode: host`，或新的 `ai-security-monitor hub advertise --url <對外網址>` 在區網任一台代為廣播（先驗 Hub 身分）。「新增主機」頁的「自動尋找」卡片顯示廣播狀態，並產生 Windows DNS Server／BIND 的 SRV、TXT 紀錄指令。新設定 `AI_SECURITY_MONITOR_HUB_NAME`。
  - **安裝腳本**：沒給金鑰時預設免金鑰：Hub 提供的 `/install.ps1`、`/install.sh`（已預填網址）會送出加入申請、等 2 分鐘（`AI_SECURITY_MONITOR_ENROLL_WAIT`／`--wait`），還沒核准也照樣裝好背景服務繼續等；通用腳本加 `AI_SECURITY_MONITOR_AUTO_ENROLL=1`（`--auto-enroll`）改用自動尋找。「新增主機」頁有「下載預填此 Hub 的安裝指令（不含金鑰）」。
  - **桌面版**：第一次開啟、還沒加入 Hub 時顯示「尋找公司的 Security Hub」：列出找到的 Hub 與指紋 → 申請加入 → 等候核准（顯示 Hub 指紋與核對碼，自動確認）→ 完成；也可以輸入管理員給的網址。側欄新增「加入公司 Hub」。
  - **相容**：原本的金鑰註冊完全照舊；Hub 的稽核來源 IP 不再在沒開 `TRUST_PROXY` 時採用用戶端可偽造的 `X-Real-IP`。
- **桌面版設定頁：Hub 網址與開機自動啟動**：
  - **Hub**：網址欄、「測試連線」（`/api/health`＋Hub 身分：版本與指紋）、「尋找公司的 Hub」、「申請加入」（免金鑰，等候狀態可續）、進階「我有註冊金鑰」（原本的金鑰註冊）、「離開這個 Hub」（只刪這台的設定與金鑰，Hub 上的主機紀錄不會刪）。要換到指紋和目前不同的 Hub 會清楚警告並要求確認。網址只接受 https，http 限本機與私網。
  - **開機自動啟動**：「開機／登入後在背景自動回報」＝使用者層的 `service install --yes`／`uninstall --yes`（不提權，同一份計畫：會換掉舊版 asa 的登入啟動項目並搬設定目錄），顯示已開啟／執行中／找到舊版 asa；登記的是桌面版執行檔本身（安裝路徑更新後不變；Linux AppImage 改用 `APPIMAGE` 的實際檔案位置）。「登入時開啟桌面版」用 tauri-plugin-autostart 以 `--tray` 啟動，只放系統匣不跳視窗，預設關。
  - `scripts/capture-desktop-screenshots.mjs` 補上新指令的假回應，重新擷取設定頁截圖。

- **桌面版 logo 放大**：系統圖示（標題列、工作列、系統匣、安裝檔）改用裁掉留白的來源重新產生，海豹撐滿圖示高度；側欄品牌圖從 36px 放大到 56px；開啟時先顯示大 logo 的啟動畫面約 1 秒後淡出（系統設定「減少動態效果」時不顯示）。`scripts/capture-desktop-screenshots.mjs` 以減少動態效果擷取，截圖不會拍到啟動畫面。
- **Hub：批次分析 IP、IP 旁的風險圖示**：連線頁「可疑 IP 排名」每列可勾選（含全選本頁），勾選後可「查詢外部情資（N 個）」（每 5 個送一次並顯示「已查 x／y」進度，內網位址自動略過，快取內的不重打，可勾「略過快取重查」）、「請 AI 分析選取的 IP」（最多 20 個，AI 會拿到每個 IP 的連線紀錄、黑名單命中、備註與外部情資快取）或「清除選取」；沒勾時有「全部查詢（前 N 名）」。新增 `POST /api/v1/ip-intel/batch`（`{ ips: string[] ≤ 50, force? }`，管理員＋CSRF，最多同時查 3 個，稽核一筆 `ip_intel.batch`）；每日額度的計數改成排隊寫入，並行查詢不會少算。排名多了可排序的「外部風險」欄（`rsort=risk`）；排名、連線表、總覽卡片、主機頁、事件與流量頁、IP 分析頁的 IP 旁都有外部風險圖示（低 ✓／中 !／高 ▲／極高 ✕／尚未查詢 ?，滑過看分數與查詢時間；內網不顯示），排名上方有圖示說明。AI 助手新增範圍「一次分析多個 IP」（`/ai?scope=ips&ips=…`），MCP 的 `lookup_indicator` 對 IP 也會帶人工備註與快取的外部情資（只讀快取）。

## v0.2.1 — 2026-10-17

**桌面版有安裝檔了（Windows、macOS、Linux），雙擊命令列版不再一閃即逝，並修正從 0.1.x 升級時設定目錄變成過期副本的問題。** 一般使用者請下載 `AI-Security-Monitor-0.2.1-windows-x64-setup.exe`（或 macOS 的 `.dmg`、Linux 的 `.AppImage`／`.deb`）；`ai-security-monitor-0.2.1-*` 是命令列版，給伺服器與自動化用。README 的「安裝」改成「下載哪一個？」表格加上每條路線的步驟。

**桌面版安裝檔**：Release 多了 `AI-Security-Monitor-<版本>-windows-x64-setup.exe`（NSIS，裝到目前使用者）、`…-macos-arm64.dmg`、`…-macos-x64.dmg`、`…-linux-x64.AppImage`、`…-linux-amd64.deb`，都列在 `SHA256SUMS`（安裝腳本與 `self-update` 依檔名精確比對，不受影響）。安裝檔沒有程式碼簽章：Windows 在 SmartScreen 按「其他資訊」→「仍要執行」，macOS 第一次右鍵 →「打開」（或 `xattr -dr com.apple.quarantine`）。裝過 0.1.x 的「AI Security Agent」桌面版要先解除安裝。

**雙擊命令列版**：在檔案總管雙擊 `ai-security-monitor-<版本>-windows-x64.exe`（沒有參數、主控台是它自己開的）時，不再只印 help 就關掉視窗，改成說明這是命令列版、桌面版安裝檔在哪、一行安裝指令與常用命令，按 Enter 才關閉。從終端機執行或帶參數時行為不變。

**修正：舊版常駐 watch 還在跑時的設定目錄遷移**：0.2.0 遇到舊版 `asa watch` 正在使用 `…/ai-security-agent`（`watch.lock` 被占用）時，會把舊目錄整份複製到 `…/ai-security-monitor`；之後舊版繼續寫舊目錄、新版只看新目錄，新目錄就變成一份不再更新的副本，真正換掉舊服務後也不會再搬。現在：
- 舊目錄被占用（鎖檔被占用，或有舊名 `asa` 的常駐 watch 在跑而新目錄沒人用）時**不複製**，這次直接讀寫舊目錄，並提示一行「執行 `ai-security-monitor service install --yes` 換掉舊服務時會搬」。桌面版也一樣沿用舊目錄。
- `service install`（使用者層）會先移除舊的 Run 值／unit／plist、結束舊版常駐行程，等鎖放開（最多 15 秒）再搬目錄，新服務改用新目錄；舊目錄沒被占用時，一般啟動也會照常搬。
- 複製式遷移會在新目錄留 `.migrated-from`（來源、時間、方式）。之後舊目錄又有更新、或新目錄是 0.2.0 留下的副本（沒有標記、`agent_id` 相同、最新的檔案比舊目錄舊），下一次舊目錄沒被占用時重新同步：過期的新目錄改名成 `ai-security-monitor.bak-<時間>` 保留，再重新從舊目錄搬一次。新目錄有常駐行程在用時一律不動。

**Release 說明**：GitHub Release 的說明改由 `scripts/release-notes.mjs` 產生：這版重點、依實際資產名列出的「下載哪一個？」表格、未簽章安裝檔的開啟方式、一行安裝、從 0.1.x／0.2.x 升級，最後才是完整變更；dry run 也會產生並上傳 `release-notes` 供檢查。`scripts/check-version.mjs` 另外檢查桌面版（package(-lock).json、tauri.conf.json、Cargo.toml／lock）、Hub 的 package-lock.json 與 env.ts 預設值、Dockerfile 的 `ASA_HUB_VERSION`。

**Hub**：可疑 IP 排名的表頭可以點著排序。

**文件**：
- README（中英）的「安裝」：目前版本、「下載哪一個？」表格（桌面版、命令列版、Hub、`asa-*` 別名、`SHA256SUMS`）、系統需求，以及桌面版 Windows／macOS／Linux、命令列版 Windows／Windows Server 與 Linux／macOS、Hub（Docker）、把主機加進 Hub、從 0.1.x／0.2.0 升級的步驟，每條都附「怎麼確認裝好了」。`docs/install*.md`、`docs/desktop*.md` 同步加上下載表與桌面版安裝。
- README 加上桌面版截圖、「架構」（mermaid 流程圖）與「資料夾結構」兩節，docs/desktop 加上各頁截圖；新增 `scripts/capture-desktop-screenshots.mjs`（注入示範資料的假 Tauri 回應擷取桌面版畫面）；桌面版設定頁的舊名「asa」改成 ai-security-monitor。

## v0.2.0 — 2026-10-17

**改名為 AI Security Monitor（`ai-security-monitor`），並支援 Windows Server、可疑 IP 排名、IP 人工備註與新 logo。** 從 0.1.x 升級：舊設定、hub 註冊、金鑰與 `ASA_*` 環境變數都自動沿用，`asa self-update` 照樣能升上來；細節見下方「改名」與 README「從 asa／ai-security-agent 升級」。桌面版識別碼改了，要先解除安裝舊版。

**改名：ai-security-agent（`asa`）→ AI Security Monitor（`ai-security-monitor`）。** 從 0.1.x 升級不用重新註冊，舊設定自動沿用：
- 執行檔與命令：`asa` → `ai-security-monitor`（`ai-security-monitor scan`、`ai-security-monitor watch`…）。GitHub repo 改成 `markku636/ai-security-monitor`（舊網址會自動轉址）。
- 環境變數：新前綴 `AI_SECURITY_MONITOR_*`（例 `AI_SECURITY_MONITOR_LANG`、`AI_SECURITY_MONITOR_CONFIG_DIR`、`AI_SECURITY_MONITOR_SECRETS_BACKEND`、`AI_SECURITY_MONITOR_SECRET_<KEY>`、`AI_SECURITY_MONITOR_MCP_TOKEN`、`AI_SECURITY_MONITOR_UPDATE_URL`、`AI_SECURITY_MONITOR_CLAUDE_BIN`／`_CODEX_BIN`）；舊的 `ASA_*` 照樣讀，兩個都設時新名優先。
- 設定目錄：使用者層 `…/ai-security-agent` → `…/ai-security-monitor`（Windows `%APPDATA%`、macOS `~/Library/Application Support`、Linux `~/.config`）。第一次執行新版時，若新目錄還不存在而舊目錄存在，就整個搬過去（改名；舊版常駐行程還開著檔案時改成複製、舊目錄保留），`agent_id`、hub 註冊與金鑰檔、允許清單、基準線、情資、防火牆期望狀態都沿用。用 `--config-dir`／環境變數明確指定的目錄照用、不搬。系統層 `%ProgramData%\ai-security-agent`、`/var/lib/asa`、`/Library/Application Support/ai-security-agent` → `…\ai-security-monitor`、`/var/lib/ai-security-monitor`，在 `service install --system` 時搬過去。log 檔名 `asa-YYYY-MM-DD.log` → `ai-security-monitor-YYYY-MM-DD.log`（舊檔照樣讀、照樣過期清掉）。
- 密鑰：OS keychain（Windows 認證管理員／macOS 鑰匙圈）的服務名 `asa` → `ai-security-monitor`；新名讀不到時讀舊的 `asa` 項目並複製一份到新名（舊項目保留），刪除時兩個都刪。
- 開機自動啟動：Windows 服務 `ai-security-monitor`（顯示名稱 AI Security Monitor）、HKCU Run 值 `ai-security-monitor`、`ai-security-monitor.service`（系統／--user）、`ai-security-monitor.desktop`、launchd `dev.ai-security-monitor.agent`。`service install` 會先偵測並移除舊的 `asa` 服務／Run 值／unit／plist（並結束舊的常駐行程），`service status` 會標出「舊版 asa」，`uninstall`／`restart` 也處理舊安裝；常駐行程偵測同時認 `asa(.exe)` 與 `ai-security-monitor(.exe)`。
- MCP：伺服器名 `asa` → `ai-security-monitor`（工具變成 `mcp__ai-security-monitor__*`）；`mcp install` 寫入新項目並刪掉舊的 `asa` 項目，`mcp uninstall` 兩個都刪。
- 自我更新：查 `markku636/ai-security-monitor` 的 Release，資產名 `ai-security-monitor-<版本>-<平台>`（找不到時退回舊名 `asa-…`）；一律原地替換正在執行的檔案，所以從 0.1.x 更新上來、檔名還是 `asa.exe` 的安裝照樣能用（之後執行 `service install` 換成新的服務名）。
- Release 資產：`ai-security-monitor-<版本>-<平台>`，另附內容相同的 `asa-<版本>-<平台>`（列在 SHA256SUMS）讓 0.1.x 的 `asa self-update` 能升上來。
- 安裝腳本（`install.sh`／`install.ps1`）：下載新檔名、裝成 `ai-security-monitor`；Windows 預設 `%LOCALAPPDATA%\ai-security-monitor\bin`，系統服務（`AI_SECURITY_MONITOR_SERVICE=system`）改裝到 `%ProgramFiles%\ai-security-monitor`（需系統管理員 PowerShell）；Linux／macOS 仍是 `/usr/local/bin` 或 `~/.local/bin`。環境變數 `AI_SECURITY_MONITOR_{VERSION,INSTALL_DIR,HUB_URL,ENROLL_KEY,SERVICE,DOWNLOAD_BASE,NO_MODIFY_PATH}`，舊的 `ASA_*` 照樣有效。找到舊版 `asa` 會提示，系統服務安裝前先把舊的系統設定目錄複製到新位置；舊的開機自動啟動由新版的 `service install` 移除。Hub「新增主機」頁產生的 Windows 指令改用新環境變數名。
- Hub 映像：`ghcr.io/markku636/ai-security-monitor-hub`（`docker/compose*.yml` 已改用新名）；過渡期同時推舊名 `ghcr.io/markku636/ai-security-agent-hub`。compose 專案名與 volume 不變，資料庫沿用。
- 不變（相容與安全考量）：通訊標頭 `x-asa-*`、token 前綴 `asa_`／`asa_ek_`、防火牆物件名（Windows 群組 `ASA`、`ASA: …` 規則、nft `table inet asa`、ipset `asa_*`、pf anchor `com.asa`）、`fw unblock --all-asa`。

**支援 Windows Server**（2016／2019／2022／2025，含 Server Core 與網域控制站）：
- 版本判斷：從登錄讀 ProductType（工作站／伺服器／網域控制站）、InstallationType（Client／Server／Server Core）與 EditionID，隨主機資訊送到 Hub（`os.product_type`、`os.installation_type`、`os.edition`，選填欄位，舊 Hub 照收）。伺服器的版本字串改用產品名稱，Hub 顯示「Windows Server 2022 Datacenter (Server Core, 20348)」，不再誤顯示成「Windows 10／11」。
- 系統硬化：策略新增 `editions` 篩選（`client`／`server`／`core`／`desktop`／`dc`，`not_<標籤>` 排除）與 `remediation_server`（伺服器上改顯示 `Install-WindowsFeature`／`Uninstall-WindowsFeature`、sconfig、伺服器管理員的修法）。Defender 功能被移除時 Defender 三條改為不適用（以前是錯誤）；竄改防護在沒加入 Defender for Endpoint 的伺服器不適用；SmartScreen 在 Server Core 不適用；BitLocker 在 Server Core 改用 `Get-BitLockerVolume`，沒裝 BitLocker 功能時不適用；遠端登錄服務只檢查用戶端；內建 Administrator 在伺服器已改名也算通過，網域控制站上 Guest／內建 Administrator 不適用。`harden --json` 多了 `editions`。
- 作業系統支援期限：補上 Windows Server 2008／2008 R2（2020-01-14），Server 2025 改為官方的 2034-11-14；伺服器先用組建編號比對（名稱沒有年份的 Annual Channel 23H2＝25398 也認得，2025-10-24 停止支援），Server 判斷改看 `Win32_OperatingSystem.ProductType`。
- 事件：另讀 Security 4740（帳號被鎖定）、4771（Kerberos 預先驗證失敗，併入暴力破解）、4776（NTLM 驗證失敗，依工作站計算爆量），獨立上限 1000 筆不擠掉 4625；遠端桌面 1149（RemoteConnectionManager/Operational）從公網登入記為「公網遠端登入」。新規則 `account_locked`、`ntlm_failure_burst`（Hub 事件頁有對應名稱）。
- `doctor`：封包擷取建議依組建編號：19041 起用 `pktmon etl2pcap`，Server 2019（17763）的 pktmon 不能轉檔改提示到新版轉換或裝 Npcap，Server 2016 改提示 `netsh trace`＋etl2pcapng。
- CI：agent 多跑 `windows-2022`（`windows-latest` 是 Server 2025），兩台 Windows Server runner 都驗證 `harden` 判斷成 server、沒有任何檢查出錯，`vuln` 認得作業系統支援期限。
- 示範資料（`scripts/demo-seed.mjs`）新增 Windows Server 2022 Datacenter（Server Core）網域控制站 `dc-01`（RDP 暴力破解、帳號鎖定、NTLM 失敗爆量、伺服器硬化結果），agent 版本改 0.2.0。

**桌面版改名 AI Security Monitor**：視窗標題、系統匣提示、安裝檔名稱改成 AI Security Monitor，執行檔 `ai-security-monitor-desktop.exe`，圖示換成新 logo（戴高帽、拿心跳盾牌的海豹）。
應用程式識別碼 `dev.asa.desktop` → `dev.ai-security-monitor.desktop`，所以**新版不會覆蓋舊版**：請先結束並到「設定 → 應用程式」解除安裝舊的「AI Security Agent」，再安裝新版；
舊的 WebView 快取 `%LOCALAPPDATA%\dev.asa.desktop` 可以刪掉。報告、情資與 Hub 註冊在 agent 設定目錄（`%APPDATA%\ai-security-monitor`），新版直接沿用。詳見 `docs/desktop.md`。

**文件、設定範例與截圖跟著改名**：
- README（中英）頂端放新 logo，標題、徽章（含 Windows Server）、安裝指令、Hub 映像、`ai-security-monitor` 命令全面換新名，新增「從 asa／ai-security-agent 升級」一節（自動搬移的項目、舊環境變數照用、刻意不改的防火牆物件名與標頭、桌面版要手動解除安裝、舊 Hub 映像名過渡期照發）。
- `docs/*.md`（中英）：命令、服務名（`ai-security-monitor.service`、`dev.ai-security-monitor.agent`、Windows 服務 `ai-security-monitor`）、設定目錄、環境變數改新名，並註明舊 `ASA_*` 照樣有效；安裝與開機自動啟動文件新增「從 asa（0.1.x）升級」。
- `.env.example`、`hub/.env.example` 改用 `AI_SECURITY_MONITOR_HUB_*`；`docker/compose.yml`、`compose.standalone.yml` 先讀新名、沒設才讀 `ASA_HUB_*`（只有舊名的 `.env` 展開結果完全相同，CI 會比對），傳進容器的也改成新名。compose 專案名、volume、資料庫 `asa_hub` 不變。
- Hub 容器入口（`docker/entrypoint.sh`）新舊變數名都認；資料庫密碼沒設（連線字串密碼空白）時拒絕啟動並說明要設哪個變數（compose 的巢狀預設值不能再用 `:?` 檢查必填）。
- 截圖用示範資料重拍：側欄是新 logo 與 ai-security-monitor、主機版本 0.2.0，新增 Windows Server 網域控制站 dc-01 的主機頁（`docs/images/agent-server.png`）；`scripts/demo-seed.mjs` 多送一次心跳，讓威脅情資頁有每台主機的情資新舊；`scripts/capture-screenshots.mjs` 也讀 `AI_SECURITY_MONITOR_HUB_ADMIN_SECRET`。

改進：
- Hub 選單改版：分成「要處理的事／網路／弱點／事件／工具」，每項有圖示與一行說明、目前頁面高亮、待處理問題（嚴重＋高）與待核准封鎖的數字；名稱改白話（代理程式→主機、發現→待處理問題、動作→封鎖審核、系統硬化→安全設定、管理→設定與金鑰、安裝代理程式→新增主機），頁面標題與內文一致（主機頁的返回連結「← 主機」、各頁空狀態說明也改稱主機）；手機版選單可收合。README 截圖重拍。
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
- IP 人工備註：IP 分析頁可以替遠端 IP 寫一則備註（例如「公司 VPN 出口，已確認安全」），可疑 IP 排名多一欄備註、連線表有備註的 IP 旁標 📝（滑過看全文）；只有管理員能讀寫，每次修改記在稽核紀錄（`ip_note.set`／`ip_note.delete`）。API：`GET /api/v1/ip-notes?ip=`、`POST /api/v1/ip-notes`（`note` 空字串即刪除）。新增資料表 `ip_notes`（migration 0008，Hub 啟動時自動套用）。

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
