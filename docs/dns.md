# DNS 防禦

[English](dns.en.md) | 繁體中文

DNS 是惡意程式找控制伺服器、偷傳資料、把人騙到假網站最常走的路。ai-security-monitor 在三個層面處理：

| 層面 | 做什麼 | 預設 |
|---|---|---|
| **每台電腦：監看＋告警** | 即時記錄這台查了哪些網域、是哪個程式查的；情資網域、DNS 通道、亂數網域、大量查無此網域、程式自己改走加密 DNS 時告警 | 開（`dns.enabled`） |
| **每台電腦：竄改偵測** | DNS 伺服器被改、hosts 檔被動手腳、WPAD、NXDOMAIN 被導走、答案被偽造、macOS 裝了不明的加密 DNS 描述檔 | 開（答案比對要另外開） |
| **每台電腦：防繞過＋硬化** | `fw dns-lock` 擋程式直接連外部 DNS；硬化檢查 NetBIOS、LLMNR、WPAD、mDNS 等 | 鎖定要自己下指令 |
| **整個區網：防護 DNS** | 擋威脅情資列名的網域、上游走加密 DNS、有快取，由 Hub 管理 | **不開**，見 [dns-server.md](dns-server.md) |

## 即時監看

背景服務（`watch`）即時記錄 DNS 查詢，每分鐘依（網域, 類型, 結果, 程式）聚合寫進 `<設定目錄>/dns/YYYY-MM-DD.jsonl`（保留 7 天）。事件走有界佇列，忙不過來只會少記，絕不擋住 DNS。

| 作業系統 | 來源 | 看得到程式嗎 |
|---|---|---|
| Windows | 私有的 DNS Client ETW session（只收「查詢完成」事件，不改系統的事件紀錄設定）；沒有系統管理員權限時改用 DNS 快取快照 | 系統管理員：✓（PID 取事件標頭） |
| Linux | AF_PACKET 監聽 53 port 的回應（root），核心過濾器只放行 DNS 回應 | ✓（用回應的目的 port 對到程式） |
| macOS | 每張啟用中的網卡開 BPF（root） | 查詢由 mDNSResponder 代送，改在連線表上用「解析出的 IP → 之後誰連過去」反推 |

```sh
ai-security-monitor dns                 # 最近 15 分鐘的查詢
ai-security-monitor dns --suspicious    # 只看可疑的
ai-security-monitor dns --process chrome.exe --since 1h
ai-security-monitor dns --follow        # 即時看
ai-security-monitor dns status          # 資料來源、事件數、最後一筆
```

連線表（命令列與上傳 Hub 的快照）會補上遠端 IP 最近一次解析到的網域。

設定：`dns.enabled`（預設開）、`dns.upload`（`all`／`alerts`／`off`，預設 `all`：加入 Hub 時每分鐘上傳紀錄）。

## 偵測規則（`dns` 掃描器）

每次掃描看最近 15 分鐘的紀錄，以 5 分鐘為一窗、鍵用（程式, 可註冊網域）。門檻參考 Zeek、Sigma、Splunk ESCU 與 Elastic 的規則。

| 規則 | 條件 | ATT&CK |
|---|---|---|
| `dns.intel_domain` | 網域分數 ≥ 60（最高來源信心＋每多一個來源 +10）；≥ 80 高、≥ 90 嚴重 | T1071.004 |
| `dns.tunnel` | 同一程式對同一網域 5 分鐘 ≥ 100 次且子網域多半不重複又長又亂（高）；≥ 20 次且 TXT／NULL ≥ 30%（中） | T1572、T1048.003 |
| `dns.dga` | ≥ 10 個不存在又像亂數產生的網域（排除 Chromium 的探測名稱） | T1568.002 |
| `dns.nxdomain_burst` | ≥ 50 次查無此網域、涉及 ≥ 20 個網域 | T1568.002 |
| `dns.doh_bypass` | 瀏覽器與系統以外的程式查加密 DNS 端點 | T1572 |
| `dns.tunnel_service` | Cloudflare Tunnel、Dev Tunnels、ngrok | T1572 |

白名單、known-good 與熱門網域（Majestic 前 1 萬名）不做推測型告警，但不會蓋掉信心 ≥ 70 的情資命中。可註冊網域依內嵌的 Public Suffix List 計算（`github.io`、`duckdns.org` 這類不會整批放行）。

## 黑名單（自己加網域）

條目一律含子網域。有兩份，效果一樣、合在一起看：

| | 這台電腦的 | Hub 的（全公司） |
|---|---|---|
| 加入 | `ai-security-monitor dns block bad.example`（可以一次好幾個、可以貼網址、`--note` 備註）、桌面版 DNS 頁 | 網域分析頁「加入黑名單」、「設定與金鑰 → 防護 DNS」的自訂封鎖 |
| 移除 | `dns unblock bad.example` | 網域分析頁「移出黑名單」、設定頁 |
| 查看 | `dns blocklist`（兩份都列） | 設定頁；DNS 頁頂端有筆數 |

效果：
- **每台電腦查到就告警**（`dns.blocklisted`，高），就算沒用防護 DNS 也抓得到；Hub 的黑名單每 10 分鐘同步到各台。
- **防護 DNS 直接擋**（回 NXDOMAIN）：Hub 的黑名單在下一次心跳（30 秒內）生效；跑防護 DNS 的那台自己的黑名單 1 分鐘內生效。
- 誤擋了就加進 Hub 的允許清單（網域分析頁「加入允許清單」），防護 DNS 永遠不擋它。

## 竄改偵測

| 規則 | 說明 |
|---|---|
| `dns.resolver_changed` | 每個網路（依閘道所在網段）分開記 DNS 伺服器基準，筆電換網路不誤報；改成未知的公網 DNS＝中、情資列名的＝高。確認沒問題在那台執行 `ai-security-monitor dns accept` |
| `dns.resolver_intel` | 正在用的 DNS 伺服器被情資列名 |
| `dns.hosts_tampered` | hosts 檔把熱門網站導到固定位址、擋掉防毒與系統更新網域、有 wpad 條目（只擋廣告的 `0.0.0.0` 條目不算；有沒有被改交給檔案完整性監看） |
| `dns.wpad` | `wpad.*` 查詢有回答（可能被用來攔截流量） |
| `dns.nxdomain_hijack` | 每個網路每 6 小時查 3 個不存在的亂數網域，≥ 2 個回同一個位址＝DNS 把查無此網域改成導向 |
| `dns.answer_mismatch` | `dns.verify_answers=true` 才做（預設關：會把 3 個常見網域送給 Cloudflare 比對） |
| `dns.rogue_profile` | macOS 裝了加密 DNS 描述檔 |
| `dns.not_protected` | 公司有防護 DNS，這台沒在用（見 [dns-server.md](dns-server.md)） |
| `dns.protect_restored` | 防護 DNS 連不上，背景服務已自動改回原本的 DNS |

## 防繞過：`fw dns-lock`

```sh
ai-security-monitor fw dns-lock --dry-run            # 先看會加哪些規則
ai-security-monitor fw dns-lock --block-doh --yes    # 擋直連外部 DNS（53／853）＋常見加密 DNS 業者的 443
ai-security-monitor fw dns-unlock --yes
```

只准連允許的 DNS（省略 `--allow`＝目前在用的，一律含 loopback）；目前在用的不在允許清單就拒絕套用（會斷網），除非 `--force`。Windows 用允許清單的補集當封鎖規則（封鎖優先於允許）、nftables 用獨立的 `dnslock` chain、iptables＋ipset、macOS pf anchor。細節見 [firewall.md](firewall.md)。

## 硬化

Windows：NetBIOS 名稱解析、智慧型多重主目錄名稱解析（VPN 時 DNS 外洩）、WPAD、DoH 政策（資訊）、mDNS（資訊）、LLMNR。Linux（systemd-resolved）：LLMNR、mDNS、DNS over TLS、DNSSEC（後三項資訊）。見 [hardening.md](hardening.md)。

## Hub

側欄「DNS」：查詢量、不同網域、NXDOMAIN 比例、待處理的 DNS 告警、查詢最多的網域、新出現的網域、最近的查詢、各主機的 DNS 監看狀態、防護 DNS 狀態。網域分析頁 `/domain/<網域>`：哪些主機與程式查過、解析到的 IP、7 天每小時次數、相關告警、情資紀錄。AI 助手有「解讀 DNS」範圍；Hub MCP 有 `dns_overview`、`dns_queries`、`domain_summary`。

## 隱私

DNS 紀錄等於上網紀錄，只有 Hub 管理員看得到。公司部署前請先告知員工；那台電腦可以設 `dns.upload=alerts`（只傳告警）或 `off`；Hub 保留天數用 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS`（每分鐘原始紀錄，預設 7 天）與 `_HOURLY_DAYS`（每小時彙總，預設 90 天）調整。
