# 連線判定與威脅情資

[English](intel.en.md) | 繁體中文

ai-security-monitor 把每一條連線分成四級：**安全／未知／可疑／危險**，並列出每個判斷的理由與資料來源。

```bash
ai-security-monitor intel update                   # 下載／更新情資（只抓過期的；--force 全部重抓）
ai-security-monitor intel status                   # 每個來源的筆數、最後更新、狀態
ai-security-monitor intel sources                  # 全部來源：廠商、授權、網址
ai-security-monitor intel lookup 203.0.113.66      # 查 IP 或網域：命中哪些來源、國家／ASN、判定
ai-security-monitor intel lookup 1.2.3.4 --online  # 另查已設定 key 的線上名譽服務
ai-security-monitor connections --intel            # 目前連線＋國家／組織
ai-security-monitor connections --direction inbound --verdict suspicious,dangerous
```

## 方向

| 方向 | 意思 |
|---|---|
| 對外（outbound） | 本機主動連出 |
| 對內（inbound） | 遠端連進本機正在監聽的 port |
| 監聽（listening） | 本機開著的 port（另外判斷能不能從網路連入，見 [firewall.md](firewall.md)） |
| 本機（local） | 兩端都是自己 |

## 判定規則

1. 在白名單（`ai-security-monitor allowlist add …`）→ **安全**（使用者明示）。
2. 任一情資命中信心 ≥ 80，或線上名譽分數 ≥ 75 → **危險**。
3. 任一情資命中（較低信心）、名譽 ≥ 40、一個強異常、或兩個以上異常 → **可疑**。
   強異常：從暫存／下載目錄執行的程式、shell 或腳本程式（PowerShell、cmd、bash、python、mshta、rundll32…）連外、週期性 beacon、暴力破解來源。
   週期性連線（beacon）只算「量得到」的週期：至少是快照間隔的 3 倍（每分鐘快照就是 3 分鐘以上）；連到已知良好服務，或是瀏覽器、VS Code／Cursor、Claude／Codex、Teams、Slack、OneDrive 等一般用戶端的週期性屬於 keep-alive 與輪詢，不判可疑。node、python、PowerShell 這類通用執行環境照樣偵測。
   其他異常：高風險 port（4444、Tor 9001、挖礦 3333、Telnet、RDP、SMB、Redis…）、沒看過的目的地、曝露在網路上的 listener 等。
4. 已知良性（公共 DNS、作業系統更新 CDN 等，附來源）、私有網路、loopback 且沒有異常 → **安全**。
5. 其餘 → **未知**。連到沒被列名的 IP 不代表有問題。

每個情資命中都帶：來源 id、名稱、廠商、信心、授權（是否可商用、是否需標註）、抓取時間、來源網址與比中的那一筆。
Hub 與 MCP 回答都會引用 `source_url`；AI 被要求不能自己編來源。

## 來源

| 來源 | 種類 | 方向 | 信心 | 預設 | 授權 |
|---|---|---|---|---|---|
| Spamhaus DROP v4／v6、ASN-DROP | 網段／ASN | 雙向 | 95／90 | 開 | 可商用，需標註 |
| abuse.ch Feodo Tracker | IP（C2） | 對外 | 90 | 開 | CC0 |
| abuse.ch URLhaus | 網域（網域級命中 40） | 對外 | 80 | 開 | **非營利**：只告警，預設不封鎖 |
| abuse.ch ThreatFox | IP:port | 對外 | 85 | 開 | **非營利**：只告警，預設不封鎖 |
| CERT Polska 警示清單 | 網域（含子網域） | 對外 | 85 | 開 | 可商用 |
| HaGeZi Threat Intelligence Feeds mini（medium／full 預設關） | 網域（含子網域） | 對外 | 75（65／55） | 開 | GPL-3.0，原樣鏡像 |
| Phishing.Database | 網域（完全相同才算） | 對外 | 60 | 開 | MIT |
| Block List Project（phishing／ransomware）、Phishing Army | 網域 | 對外 | 40／65 | 關 | Unlicense／上游授權自負 |
| HaGeZi 加密 DNS 端點 | DoH／DoT 網域 | — | — | 開 | GPL-3.0；**不是威脅**，只給 DNS 繞過偵測用 |
| blocklist.de（all；ssh、bruteforcelogin 預設關） | IP | 對內 | 70–75 | 開 | 免費，需標註 |
| CINS Army | IP | 對內 | 70 | 開 | 免費，需標註 |
| Proofpoint ET Open（compromised；block 預設關） | IP／網段 | 雙向 | 75 | 開 | BSD／MIT |
| SANS ISC DShield | 網段 | 對內 | 70 | 開 | **非商用**：只告警，預設不封鎖 |
| Tor 出口節點 | IP | 雙向 | 20 | 開 | 只作資訊，**永不自動封鎖** |
| IPsum | IP | 雙向 | 40＋10×被列名次數（最高 95） | 開 | Unlicense |
| FireHOL level1 | 網段 | 雙向 | 80 | 開 | 依原始來源 |
| DB-IP 國家／ASN lite | 地理 | — | — | 開 | CC BY 4.0，需標註 |
| CISA KEV、OSV（漏洞用，見 [vuln.md](vuln.md)） | CVE | — | — | 開 | 公有領域／依來源 |
| AbuseIPDB、GreyNoise、CrowdSec CTI、OTX | 線上查詢 | — | 70–85 | **關**（自備 key） | 社群方案非商用 |

完整授權見 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

abuse.ch 自 2025-11-04 起的使用條款改為「非營利使用、營利用途需向 Spamhaus 訂閱」，所以 URLhaus 與 ThreatFox 改標為非商用授權（照樣告警、不自動封鎖）；Feodo Tracker 頁面仍寫 CC0，維持原狀。

### 網域

- 網域清單（hosts、一行一個網域、`*.x` 萬用字元、adblock `||x^`）只存 64-bit 雜湊，50 萬筆約 6 MB 記憶體。
- 每個來源標明條目是否涵蓋子網域：CERT.PL、HaGeZi 涵蓋；Phishing.Database、Block List Project 只比完全相同。
- 網域分數＝最高來源信心，每多一個不同來源 +10（上限 100）；熱門網域（內嵌 Majestic Million 前 1 萬名，CC BY 3.0）只對信心 < 70 的命中扣 30。≥ 80 危險、60–79 可疑。
- `intel lookup <網域>` 另外列出可註冊網域（依 Public Suffix List，MPL-2.0）、是否熱門、像不像亂數產生（DGA，字母二元組模型）、是否為加密 DNS 端點。
- 內嵌資料用 `node scripts/update-dns-data.mjs` 更新。

- 下載用 ETag／Last-Modified，只抓過期的；HTML 錯誤頁、空清單或超過 96 MB 不會覆蓋舊資料。
- 自訂來源：`<設定目錄>/feeds/custom.json`（只接受 https）；`ai-security-monitor intel enable|disable <id>` 開關。
- 線上名譽查詢：`ai-security-monitor intel key set abuseipdb -`（從標準輸入讀 key，存在鑰匙圈），結果快取 24 小時並有每日額度上限。
- Hub 的 IP 分析頁（`/ip/<ip>`）另有「外部威脅情資」：管理員按「查詢外部情資」時由 hub 查 AbuseIPDB、GreyNoise、IPinfo、proxycheck.io 與 DNS 反解，連同 agent 回報的黑名單命中算出 0–100 風險分數。分數＝各訊號加權（Spamhaus 30、IPsum 25、FireHOL 20、其他黑名單 20、AbuseIPDB 25×信心分、GreyNoise 惡意 15、Proxy／VPN 12、資料中心 8、Tor 10，GreyNoise 良性 −20）÷ 165，再套下限（Spamhaus DROP ≥ 85、AbuseIPDB ≥ 90 時 ≥ 75、Tor ≥ 40）；≥ 75 極高、≥ 50 高、≥ 25 中。私有／保留位址不送出，hub 不會自動查。

### 同步（Hub 鏡像）

- Hub 依每個來源的更新間隔向廠商下載清單，原檔原樣存在 `/data/feeds/<id>/`（保留檔頭與授權標註；`AI_SECURITY_MONITOR_HUB_FEED_CACHE_DIR` 可改位置，`AI_SECURITY_MONITOR_HUB_FEED_MIRROR=0` 關閉背景同步）。只鏡像預設啟用、可整份下載的清單；即時查詢 API 不鏡像。
- 已註冊的 agent 先從 Hub 拿（`GET /api/v1/feeds/manifest`、`/api/v1/feeds/<id>`，ETag＝sha256，沒變回 304），Hub 沒有或連不上才直接找廠商；`ai-security-monitor intel update --no-hub` 強制直接找廠商。
- 常駐的 `ai-security-monitor watch` 每 30 分鐘檢查一次情資（各清單仍依自己的間隔才真的下載），心跳回報最舊的檢查時間與有資料的清單數；`--once` 不自動更新。
- 威脅情資頁的「立即同步情資」：Hub 立刻重抓全部清單，並在 24 小時內叫還沒更新的主機於下次心跳更新（回應裡的 `commands: ["refresh_feeds"]`）。頁面列出 Hub 每個來源的最後同步時間，以及每台主機情資最後更新時間與來源。
- 鏡像只給 agent（client 金鑰）、admin 與 read token；公開檢視拿不到原檔（各廠商授權內容不對外再散布）。

## 封鎖

情資可以同步成防火牆封鎖規則：`ai-security-monitor fw sync-blocklist --dry-run` 先看會封哪些。只挑公網、夠窄的網段，信心預設 ≥ 80，
排除 Tor、非商用來源（DShield）、本機位址、白名單與已知良性。細節見 [firewall.md](firewall.md)。
