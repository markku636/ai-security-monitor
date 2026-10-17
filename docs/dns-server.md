# 防護 DNS 伺服器

[English](dns-server.en.md) | 繁體中文

`ai-security-monitor dns-server` 是給**整個區網**用的 DNS：把電腦、手機、IoT 的 DNS 指到它，
查到威脅情資列名的網域就擋掉（回「查無此網域」），其他照常經加密 DNS 轉送並快取。
**選用、預設不開**；不開時完全沒有成本，其他功能照常（每台電腦自己的 DNS 監看與告警見 [dns.md](dns.md)）。

| | 預設 | 關掉時 |
|---|---|---|
| 部署 | 不起（compose 的 `dns` 服務在 `--profile dns`；原生跑要自己啟動或設 `dns.server.enabled`） | 沒有 DNS 伺服器 |
| Hub「設定與金鑰 → 防護 DNS」封鎖開關 | **關**（只轉送） | 伺服器照常轉送、只是不封鎖，正在用它的裝置不會斷網 |
| 每台電腦 `dns use-hub` | 不動系統 DNS | — |

## 運作方式

```
用戶端 → UDP／TCP 53 → 只服務區網（ACL）→ 每個用戶端限速 → 封鎖比對 → 快取 → 同一題合併 → 上游 DoH（HTTP/2）
                                      │                    │命中：只改 ID 與 TTL
                                      └ 命中：NXDOMAIN＋EDE 15「Blocked」
```

- **封鎖清單**：已下載、啟用、**授權允許商用**、信心 ≥ 75 的網域情資（目前是 CERT Polska 與 HaGeZi TIF mini；可在 Hub 改選或調門檻），每份分開解析、只存 64-bit 雜湊（200 萬筆約 23 MB），加上自訂封鎖。非商用授權的清單（abuse.ch URLhaus、Phishing Army）只拿來告警、不拿來封鎖。允許清單（Hub 的白名單、內建的 known-good 網域、幾個常被誤列的大網站本身）優先。清單每 10 分鐘（或情資更新、Hub 改設定時）在背景重建，建好再無鎖替換，替換期間照常服務。**啟動時先只轉送**，清單建好才開始封鎖，所以重啟只斷不到 1 秒。
- **Firefox 的加密 DNS 暗號** `use-application-dns.net` 一律回 NXDOMAIN，Firefox 就不會自己繞過；`--block-private-relay`（Hub「也擋 iCloud 私密轉送」）另擋 iCloud Private Relay。
- **快取**：存上游的原始回應與 TTL 位置，命中時只改 ID 與 TTL，不重新組封包。負快取最多 1 小時；快過期的熱門答案先刷新；**上游全掛時用過期 1 天內的答案頂著**（RFC 8767），不會因為上游斷線就整個停擺。
- **上游**：預設 Quad9 與 Cloudflare 的 DoH（HTTP/2 連線複用，啟動時用內建的 IP 連，不依賴系統 DNS），兩家錯開 250 毫秒競速、依延遲挑；也可以填 IP（明文 UDP，回應要對上 ID 與問題才收，截斷時改 TCP）。
- **安全**：只服務 loopback 與私有網段（`--acl`），避免變成網際網路上的開放解析器；每個用戶端每秒 200 題；公網名稱回私有 IP 的答案丟掉（DNS rebinding，內部網域用 `--internal-suffix` 或 Hub「內部網域」放行）；ANY 回最小答案（RFC 8482）；EDNS 1232 bytes，超過設 TC 讓用戶端改走 TCP。Windows 上綁 53 不需要系統管理員，所以用 `SO_EXCLUSIVEADDRUSE` 獨佔 port，別的程式不能綁同一個位址搶走查詢。DNSSEC 這版不自己驗，交給加密通道上的上游（Quad9、Cloudflare 會驗）。
- **紀錄**：依（用戶端, 網域, 類型, 結果）每分鐘聚合，寫進 `<設定目錄>/dns-server/dns/`（保留 7 天）；連著 Hub 時另外排進佇列分批上傳，Hub 連不上時暫存、恢復後補送。紀錄走有界佇列，忙不過來只會少記，絕不擋住解析。`--no-log` 或 Hub 關掉「記錄查詢」就只送統計數字。

## 部署

### 1. 一台常開的電腦（建議：看得到每個裝置的真實 IP）

```sh
# 不連 Hub：自己下載情資、照命令列參數
sudo ai-security-monitor dns-server
# 連 Hub：封鎖開關、上游、清單以 Hub 的設定為準
sudo ai-security-monitor dns-server --hub https://hub.example:8088 --hub-token <dns 權杖>
```

dns 權杖在 Hub「設定與金鑰 → API token」建立，權限勾「防護 DNS 伺服器」。也可以交給背景服務帶起（已加入 Hub 時用這台的身分連 Hub，掛掉自動重啟、設定改了自動重啟套用）：

```sh
ai-security-monitor config set dns.server.enabled true
ai-security-monitor config set dns.server.listen 192.168.1.5:53   # 選填
```

輸出在 `<設定目錄>/dns-server/server.log`。`0.0.0.0:53` 被佔用（Linux 的 systemd-resolved、Windows 的網際網路連線共用）時會自動改綁各網卡的位址。要讓區網的裝置連進來，記得在這台的防火牆放行 UDP／TCP 53（背景服務帶起時不會跳出允許視窗）：

```powershell
# Windows（系統管理員 PowerShell）
New-NetFirewallRule -DisplayName "AI Security Monitor DNS (UDP)" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private,Domain
New-NetFirewallRule -DisplayName "AI Security Monitor DNS (TCP)" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Private,Domain
```

Linux 用 `ufw allow 53` 或對應的 nftables 規則；macOS 的應用程式防火牆預設是關的，開著時到「系統設定 → 網路 → 防火牆 → 選項」允許 ai-security-monitor。

### 2. Hub 的 compose

`.env` 設好 `AI_SECURITY_MONITOR_HUB_DNS_TOKEN`（至少 32 字元，Hub 與 dns 共用，例 `openssl rand -hex 24`）與 `AI_SECURITY_MONITOR_HUB_DNS_BIND`（這台的區網 IP），再加 `--profile dns`：

```sh
docker compose -f docker/compose.yml --env-file .env --profile dns up -d
```

映像 `ghcr.io/markku636/ai-security-monitor-dns` 只有 musl 靜態執行檔與 CA 憑證（FROM scratch，amd64／arm64，以 nobody 執行）。bridge 網路看不到裝置的真實 IP（Docker Desktop 全部變成同一個位址）；Linux 要分裝置請再加 `-f docker/compose.dns-host.yml`（host 網路）。

### 3. 把裝置指過去

- **整個辦公室**：路由器 DHCP 的 DNS 伺服器改成防護 DNS 的區網 IP。有 IPv6 的話，路由器通告的 IPv6 DNS（RDNSS）與 DHCPv6 也要指過來，不然裝置會走 IPv6 的 DNS 繞過。
- **個別電腦**：在那台以系統管理員執行 `ai-security-monitor dns use-hub --yes`（位址取自 Hub「裝置要用的 DNS 位址」，或用 `--server IP` 指定）。會先確認防護 DNS 查得到才改，原本的設定存在 `dns/use-hub.json`，`ai-security-monitor dns restore --yes` 改回。背景服務每分鐘檢查，**連續 3 次查不到就自動改回原本的 DNS**（並出現「防護 DNS 連不上，已改回原本的 DNS」提醒），不會因為防護 DNS 掛掉而斷網。

| 作業系統 | `dns use-hub` 怎麼改 |
|---|---|
| Windows | 每張啟用中的網卡 `Set-DnsClientServerAddress`；原本是 DHCP 還是手動從登錄判斷，還原時照原樣 |
| macOS | 每個啟用中的網路服務 `networksetup -setdnsservers` |
| Linux | NetworkManager（`nmcli`，持久）→ systemd-resolved（`resolvectl`，重開機後失效）→ 直接改 `/etc/resolv.conf` |

Hub 開了防護 DNS 且填了「裝置要用的 DNS 位址」時，沒在用它的主機會出現 `dns.not_protected`（低）提醒。

### 測試

```sh
nslookup blocked-test.asm-dns.invalid <DNS IP>   # 應該查無此網域（NXDOMAIN）
nslookup example.com <DNS IP>                    # 應該有答案
ai-security-monitor dns-server --healthcheck --listen <DNS IP>:53
ai-security-monitor dns-server --status          # 查詢量、快取、封鎖、延遲分位數、上游、連 Hub 的狀態
```

## Hub 管理

「設定與金鑰 → 防護 DNS」：封鎖開關、暫停 5 分鐘／1 小時（倒數，到期自動恢復）、連上來的伺服器（在線、查詢量、快取命中率、封鎖數、延遲、清單筆數）、最近 24 小時被擋最多的網域與查詢最多的裝置、最近被擋的查詢（擋錯了按「放行」）、上游、封鎖用的清單、自訂封鎖／允許、內部網域、裝置要用的 DNS 位址。改了設定，伺服器下一次心跳（30 秒內）就生效；Hub 連不上時伺服器照最後一次拿到的設定跑。DNS 頁頂端也有狀態列。API 見 [hub-contract.md](hub-contract.md#防護-dnsdns-server---hub)。

## 效能

`agent/examples/dnsbench.rs` 在同一個行程裡起伺服器（上游是本機的假 DNS，量的是伺服器本身）與多個用戶端：

```sh
cargo run --release --example dnsbench -- --seconds 15 --clients 64
```

| 項目 | 目標 | 開發機（Windows，32 執行緒） |
|---|---|---|
| 快取命中＋封鎖混合 QPS | ≥ 50,000 | 約 123,000 |
| 快取命中延遲 p50／p99／p99.9 | p99 < 1 ms | 246／563／801 µs |
| 未命中（送上游）p50／p99 | — | 132／190 µs（本機假上游） |
| 封鎖比對（200 萬筆） | < 1 µs | 約 300 ns |
| 封鎖清單記憶體／重建 | — ／< 3 秒 | 23 MB／0.16 秒 |
| 行程常駐記憶體（含 200 萬筆清單與快取） | < 150 MB | 約 40 MB |

用戶端與伺服器在同一台機器上互搶 CPU，實際上伺服器能處理的量更高。CI 的 `dnsbench` job 在 Linux runner 每次都跑一次並把數字寫進 job summary，只有嚴重退步（約目標的一半）才失敗。

設計上的取捨：
- 封包自己解析（只看標頭、問題與 OPT），不經過通用 DNS 函式庫組物件、不配置字串；有 2 萬次亂資料模糊測試。
- 封鎖比對：雜湊高位元先查分桶索引（每桶約 16–32 筆）再在桶內二分搜尋，每層只碰幾條 cache line；從完整名稱往上逐層查（含子網域）。
- Linux 每個核心一個 `SO_REUSEPORT` socket，由核心分流；Windows／macOS 多個 task 共用一個 socket。Windows 關掉 `SIO_UDP_CONNRESET`（否則回應送到已關閉的用戶端 port 後，下一次收封包會報錯）。
- 快取用 TinyLFU（moka），熱門項目不會被一次性的大量查詢擠掉。

## 這版不做

用戶端加密連進來（DoH／DoT 伺服器端）、本地 DNSSEC 驗證、RPZ 匯出、雙機備援、Safe Search。

## 隱私

DNS 紀錄等於上網紀錄。公司部署前請先告知員工；Hub 可以關掉「記錄查詢並上傳 Hub」，只留統計數字；紀錄保留期限同 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS`（預設 7 天）。
