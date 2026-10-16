# 防火牆、port 與封鎖

[English](firewall.en.md) | 繁體中文

```bash
asa fw status                         # 後端、是否開啟、網路設定檔、預設動作
asa fw audit                          # 稽核：設定檔關閉、預設允許連入、全開規則、高風險服務可從網路連入
asa fw list                           # 允許連入的規則（--ours 只看 asa 建立的）
asa ports                             # 每個監聽 port 實際能不能從網路連入
asa ports --probe 192.168.1.10        # 探測自己網段的主機（TCP connect；有 nmap 就用 nmap）

asa fw block 203.0.113.66 --reason "C2" --yes   # 封鎖（預設雙向）
asa fw unblock 203.0.113.66 --yes
asa fw close-port tcp/6379 --yes                # 用防火牆擋掉連入
asa fw open-port tcp/6379 --yes
asa fw sync-blocklist --dry-run                 # 預覽情資封鎖清單
asa fw sync-blocklist --yes                     # 同步（只放高信心、可商用來源的公網網段）
asa fw unblock --all-asa --yes                  # 一次清掉 asa 建立的所有規則
asa fw ensure --yes                             # 依期望狀態重新套用（pf／nftables 開機後需要）
```

## 後端

| 平台 | 讀取 | 寫入 |
|---|---|---|
| Windows | 一次 PowerShell 讀設定檔、作用中網路類別、允許連入規則與其 port／程式／位址篩選 | NetSecurity 規則，群組 `ASA`、名稱 `ASA: …`，每條最多 500 個位址 |
| macOS | 應用程式防火牆、隱形模式、pf | pf anchor `com.asa`（tables `asa_block`、`asa_in`、`asa_out`、`asa_feed`），在 `/etc/pf.conf` 以 `# asa-begin／asa-end` 標記插入 |
| Linux | firewalld → ufw → nftables → iptables 依序偵測 | 有 nft 時用自建 `table inet asa`（跟 ufw／firewalld 並存），否則 iptables＋ipset |

`asa fw audit` 與掃描裡的 `firewall`、`ports` 引擎產生發現（例：`ports.exposed_open` — Redis 6379 可從網路連入）。

## 安全設計

- **沒加 `--yes` 只預演**：列出確切會執行的指令；`--dry-run` 也一樣。
- **需要系統管理員**：沒有權限時請求提權重跑同一個命令（Windows UAC、Linux pkexec／sudo、macOS 管理員密碼），**永不靜默提權**。
- **只動自己的規則**：所有規則都有 `ASA` 標記，`unblock --all-asa` 只清 asa 建立的。
- **期望狀態**：`<設定目錄>/firewall/desired.json` 記下封鎖了什麼、關了哪些 port、同步了哪些情資網段；
  pf 與 nftables 重開機不保留，`asa fw ensure` 依這份檔案重新套用（常駐服務啟動時會做）。
- **情資封鎖的挑選**：信心 ≥ 80（`--min-confidence`）、只取公網、v4 至少 /10、v6 至少 /19、排除本機位址／白名單／已知良性、
  排除 Tor（只作資訊）與非商用來源（DShield，除非設定允許），重疊網段合併；超過後端上限（Windows 1 萬）時先留高信心來源。
- **遠端封鎖**：Hub 核准的封鎖動作以 HMAC 簽章派送，agent 驗章、確認主機身分且有 `--accept-remote-actions` 才會執行（見 [hub-contract.md](hub-contract.md)）。

CI 在三個平台的拋棄式 runner 上實際封鎖、關 port、列出、清除，確認規則真的生效又被清乾淨。
