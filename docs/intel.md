# 連線判定與威脅情資

[English](intel.en.md) | 繁體中文

asa 把每一條連線分成四級：**安全／未知／可疑／危險**，並列出每個判斷的理由與資料來源。

```bash
asa intel update                    # 下載／更新情資（只抓過期的；--force 全部重抓）
asa intel status                    # 每個來源的筆數、最後更新、狀態
asa intel sources                   # 全部來源：廠商、授權、網址
asa intel lookup 203.0.113.66       # 查 IP 或網域：命中哪些來源、國家／ASN、判定
asa intel lookup 1.2.3.4 --online   # 另查已設定 key 的線上名譽服務
asa connections --intel             # 目前連線＋國家／組織
asa connections --direction inbound --verdict suspicious,dangerous
```

## 方向

| 方向 | 意思 |
|---|---|
| 對外（outbound） | 本機主動連出 |
| 對內（inbound） | 遠端連進本機正在監聽的 port |
| 監聽（listening） | 本機開著的 port（另外判斷能不能從網路連入，見 [firewall.md](firewall.md)） |
| 本機（local） | 兩端都是自己 |

## 判定規則

1. 在白名單（`asa allowlist add …`）→ **安全**（使用者明示）。
2. 任一情資命中信心 ≥ 80，或線上名譽分數 ≥ 75 → **危險**。
3. 任一情資命中（較低信心）、名譽 ≥ 40、一個強異常、或兩個以上異常 → **可疑**。
   強異常：從暫存／下載目錄執行的程式、shell 或腳本程式（PowerShell、cmd、bash、python、mshta、rundll32…）連外、週期性 beacon、暴力破解來源。
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
| abuse.ch URLhaus | 網域 | 對外 | 80 | 開 | CC0 |
| abuse.ch ThreatFox | IP:port | 對外 | 85 | 開 | CC0 |
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

- 下載用 ETag／Last-Modified，只抓過期的；HTML 錯誤頁、空清單或超過 96 MB 不會覆蓋舊資料。
- 自訂來源：`<設定目錄>/feeds/custom.json`（只接受 https）；`asa intel enable|disable <id>` 開關。
- 線上名譽查詢：`asa intel key set abuseipdb -`（從標準輸入讀 key，存在鑰匙圈），結果快取 24 小時並有每日額度上限。
- Hub 的 IP 分析頁（`/ip/<ip>`）另有「外部威脅情資」：管理員按「查詢外部情資」時由 hub 查 AbuseIPDB、GreyNoise、IPinfo、proxycheck.io 與 DNS 反解，連同 agent 回報的黑名單命中算出 0–100 風險分數。分數＝各訊號加權（Spamhaus 30、IPsum 25、FireHOL 20、其他黑名單 20、AbuseIPDB 25×信心分、GreyNoise 惡意 15、Proxy／VPN 12、資料中心 8、Tor 10，GreyNoise 良性 −20）÷ 165，再套下限（Spamhaus DROP ≥ 85、AbuseIPDB ≥ 90 時 ≥ 75、Tor ≥ 40）；≥ 75 極高、≥ 50 高、≥ 25 中。私有／保留位址不送出，hub 不會自動查。

### 同步（Hub 鏡像）

- Hub 依每個來源的更新間隔向廠商下載清單，原檔原樣存在 `/data/feeds/<id>/`（保留檔頭與授權標註；`ASA_HUB_FEED_CACHE_DIR` 可改位置，`ASA_HUB_FEED_MIRROR=0` 關閉背景同步）。只鏡像預設啟用、可整份下載的清單；即時查詢 API 不鏡像。
- 已註冊的 agent 先從 Hub 拿（`GET /api/v1/feeds/manifest`、`/api/v1/feeds/<id>`，ETag＝sha256，沒變回 304），Hub 沒有或連不上才直接找廠商；`asa intel update --no-hub` 強制直接找廠商。
- 常駐的 `asa watch` 每 30 分鐘檢查一次情資（各清單仍依自己的間隔才真的下載），心跳回報最舊的檢查時間與有資料的清單數；`--once` 不自動更新。
- 威脅情資頁的「立即同步情資」：Hub 立刻重抓全部清單，並在 24 小時內叫還沒更新的主機於下次心跳更新（回應裡的 `commands: ["refresh_feeds"]`）。頁面列出 Hub 每個來源的最後同步時間，以及每台主機情資最後更新時間與來源。
- 鏡像只給 agent（client 金鑰）、admin 與 read token；公開檢視拿不到原檔（各廠商授權內容不對外再散布）。

## 封鎖

情資可以同步成防火牆封鎖規則：`asa fw sync-blocklist --dry-run` 先看會封哪些。只挑公網、夠窄的網段，信心預設 ≥ 80，
排除 Tor、非商用來源（DShield）、本機位址、白名單與已知良性。細節見 [firewall.md](firewall.md)。
