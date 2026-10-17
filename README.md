<p align="center">
  <img src="docs/images/logo.png" alt="ai-security-monitor logo" width="140">
</p>

<h1 align="center">ai-security-monitor</h1>

<p align="center"><b>繁體中文</b> · <a href="./README.en.md">English</a></p>

<p align="center">
  <a href="https://github.com/markku636/ai-security-monitor/actions/workflows/ci.yml"><img src="https://github.com/markku636/ai-security-monitor/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20Windows%20Server%20%7C%20macOS%20%7C%20Linux-informational" alt="platforms">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
</p>

防禦型資安 agent **`ai-security-monitor`**（Rust，單一執行檔，Windows／Windows Server／macOS／Linux）＋ **Security Hub**（Next.js＋Tailwind＋PostgreSQL）。
抓出對外與對內的異常連線、用公開威脅情資判定**安全／未知／可疑／危險**並附上每一筆來源，
檢查防火牆、開放 port、漏洞與系統硬化，整理流量與 Windows 事件／當機原因，再交給 **Claude Code／Codex CLI** 用白話解讀；agent 與 Hub 都是 **MCP server**。

![Security Hub 總覽](docs/images/overview.png)

## 緣起

昨天睡前，讓 AI 做了一個有趣的小專案：
用 Rust 寫的應用，蒐集並分析用戶端的異常連線，做威脅分析。
AI 出現後，系統漏洞變得很明顯；既然攻擊者是 AI，AI 也很懂得怎麼防禦。

**架構**

```
Client Agent → 定時回報 → Server 分析 → AI 判斷風險 → Dashboard 呈現
```

`#支援跨平台`（Windows／Windows Server／macOS／Linux）

## 這是什麼

| | |
|---|---|
| **ai-security-monitor**（agent） | 裝在要保護的電腦或伺服器上（含 Windows Server 2016–2025、Server Core 與網域控制站）。掃描連線、情資、防火牆、port、漏洞、硬化、事件與流量；可以單獨用（CLI、MCP、AI 分析），也可以註冊到 Hub 定期回報、接受核准過的遠端封鎖。開機自動啟動（系統服務或使用者登入時）。 |
| **桌面版**（選用） | 用戶端的視窗介面 AI Security Monitor：系統匣常駐，看這台電腦的連線判定（點 IP 分析）、掃描結果、情資狀態，一鍵掃描／更新情資，並用本機已登入的 Claude Code／Codex 做 AI 分析。和命令列、背景服務共用同一個設定目錄。見 [docs/desktop.md](docs/desktop.md)。 |
| **Security Hub** | 集中看所有主機：連線判定、待處理問題、漏洞、安全設定分數、當機與資安事件、情資來源命中、封鎖審核、AI 分析與 MCP。單機版（只綁本機）或伺服器版（所有主機回報到同一台），Docker 部署。 |

## 畫面預覽

| | |
|---|---|
| ![連線](docs/images/connections.png) 連線：方向、判定、行程、國家／組織、理由與情資來源 | ![主機](docs/images/agent.png) 單台主機：五項分數、趨勢、看過的危險目的地 |
| ![Windows Server](docs/images/agent-server.png) Windows Server：網域控制站 dc-01（Server 2022 Datacenter，Server Core） | ![待處理問題](docs/images/findings.png) 待處理問題：所有主機回報的問題，可依裝置、狀態、嚴重度篩選與批次處理 |
| ![漏洞](docs/images/vulns.png) 漏洞與更新：作業系統支援期限、KEV、已知漏洞軟體 | ![安全設定](docs/images/hardening.png) 安全設定：最常未通過的檢查與各主機分數 |
| ![事件](docs/images/events.png) 當機與事件：藍屏代碼與可能原因、暴力破解來源、帳號鎖定 | ![情資](docs/images/intel.png) 威脅情資：每台主機的情資新舊、來源授權、信心與命中 |
| ![深色](docs/images/agent-hardening-dark.png) 深色模式：每條檢查的目前值、期望值與修正方式 | ![新增主機](docs/images/install.png) 新增主機：建立註冊金鑰並產生一行安裝指令 |

> 截圖用的是 `scripts/demo-seed.mjs` 產生的示範資料（虛構主機、文件保留網段 IP）。

## 功能一覽

- **連線與威脅情資**：每條連線判斷方向（對外／對內／監聽／本機），綜合 Spamhaus DROP、abuse.ch（Feodo、URLhaus、ThreatFox）、blocklist.de、CINS、ET、DShield、Tor、IPsum、FireHOL 等開源情資，
  加上異常行為（暫存目錄行程、shell 對外連線、高風險 port、週期性 beacon、新目的地），判定安全／未知／可疑／危險；每個命中都附廠商、信心、授權與來源網址。可選 AbuseIPDB／GreyNoise／CrowdSec 線上查詢（自備 key）。
- **防火牆與曝露**：讀 Windows 防火牆、macOS pf／應用程式防火牆、Linux nftables／firewalld／ufw／iptables，算出每個監聽 port 實際能不能從網路連入；
  `ai-security-monitor fw block`、`ai-security-monitor fw sync-blocklist` 把高信心情資同步成封鎖規則（預演、確認、可撤銷，非商用授權的來源預設只告警）。
- **漏洞與更新**：軟體清單、作業系統支援期限（含 Windows Server 2008–2025）、Windows 多久沒更新、Linux 待裝安全性更新、常見軟體的已知漏洞版本（WinRAR、7-Zip、Chrome…），Linux 套件查 OSV，CISA KEV 命中升為嚴重。
- **系統硬化**：60 條跨平台檢查（UAC、Defender、BitLocker、SMBv1、RDP NLA、SSH、核心參數、AppArmor／SELinux、FileVault、Gatekeeper…），自動分辨 Windows 用戶端、Server、Server Core 與網域控制站，嚴重度加權分數，可用 YAML 自訂。
- **流量**：不抓封包也能看各行程連到哪裡（flow-lite）；分析 Wireshark／tcpdump 的 pcap／pcapng：DNS、TLS SNI、明文協定、大量上傳、週期性連線。
- **事件與當機**：Windows 事件記錄、minidump 藍屏代碼、WER；Linux journal、macOS 當機報告；整理出可能原因與處置，以及暴力破解（含 Kerberos、NTLM）、帳號鎖定、公網遠端桌面登入、新帳號、新服務、清除稽核等資安事件。
- **AI 與 MCP**：`ai-security-monitor ai ask|analyze` 交給 Claude Code 或 Codex CLI（只開唯讀工具）；`ai-security-monitor mcp` 讓 Claude Code／Codex／Cursor／VS Code 直接查這台電腦；Hub 也有所有主機層級的 MCP 與網頁上的 AI 分析。
- **Hub**：總覽、主機、連線、待處理問題（批次處理）、漏洞、安全設定、流量、事件、情資、封鎖審核（HMAC 簽章、主機身分釘選）、註冊金鑰、唯讀 API token、稽核、CSV 匯出、中英文、深色模式、手機版面。
- **部署與更新**：開機自動啟動（Windows 服務／systemd／launchd 或使用者層）、`ai-security-monitor self-update`（比對 SHA256SUMS）、一行安裝腳本、Hub Docker 映像（amd64／arm64）與 compose。

## 安裝

**agent（ai-security-monitor）**

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

```powershell
# Windows／Windows Server（PowerShell）
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

腳本會比對 Release 的 `SHA256SUMS`，不符就停止。也可以從 [Releases](https://github.com/markku636/ai-security-monitor/releases) 直接下載執行檔。細節見 [docs/install.md](docs/install.md)。

**Security Hub（Docker）**

```bash
git clone https://github.com/markku636/ai-security-monitor && cd ai-security-monitor
cp .env.example .env    # 填 AI_SECURITY_MONITOR_HUB_ADMIN_SECRET、AI_SECURITY_MONITOR_HUB_DB_PASSWORD
docker compose -f docker/compose.standalone.yml --env-file .env up -d   # 單機版：http://127.0.0.1:8088
# 伺服器版：docker compose -f docker/compose.yml --env-file .env up -d
```

映像是 `ghcr.io/markku636/ai-security-monitor-hub`。登入後到「新增主機」建立註冊金鑰，複製各平台的一行安裝指令。細節見 [docs/docker.md](docs/docker.md)。

## 快速上手

```bash
ai-security-monitor doctor                       # 環境檢查：權限、情資新鮮度、外部工具、Hub 連線
ai-security-monitor intel update                 # 下載威脅情資（之後 ai-security-monitor watch 會自動更新）
ai-security-monitor connections --intel          # 目前連線與判定
ai-security-monitor scan                         # 完整掃描（連線、情資、防火牆、port、事件、漏洞、硬化）
ai-security-monitor fw sync-blocklist --dry-run  # 預覽會封鎖哪些高信心情資 IP
ai-security-monitor ai ask "這台電腦有沒有連到危險的地方？"   # 交給 Claude Code／Codex 解讀
ai-security-monitor enroll https://hub.example.com --key asa_ek_…
ai-security-monitor service install --yes        # 開機／登入後自動回報（伺服器加 --system）
```

所有會改變系統的命令（封鎖 IP、關 port、安裝服務、更新）沒加 `--yes` 都只會預覽。

## CLI

| 命令 | 用途 |
|---|---|
| `scan`、`connections`、`ports` | 完整掃描、連線判定、port 可達性 |
| `intel` | 情資更新、來源與授權、查 IP／網域 |
| `fw` | 防火牆狀態、稽核、封鎖／解除、情資同步 |
| `vuln`、`harden` | 漏洞與更新、系統硬化 |
| `traffic`、`events` | 流量觀察與 pcap 分析、事件與當機原因 |
| `ai`、`mcp` | Claude Code／Codex 分析、MCP server 與一鍵設定 |
| `enroll`、`status`、`watch`、`service` | 註冊 Hub、常駐回報、開機自動啟動 |
| `self-update`、`version`、`doctor` | 更新與環境檢查 |
| `allowlist`、`baseline`、`config` | 白名單、基準線（只看新增）、設定 |

`ai-security-monitor --help`、`ai-security-monitor <命令> --help` 看完整參數；`--lang en` 切英文、`--json` 給程式讀。

## 從 asa／ai-security-agent 升級

0.2.0 起專案改名為 ai-security-monitor（執行檔 `asa` → `ai-security-monitor`，GitHub 舊網址會自動轉址），不用重新註冊：

- **自動沿用**：第一次執行新版時，設定目錄 `…/ai-security-agent` 搬到 `…/ai-security-monitor`（`agent_id`、Hub 註冊、白名單、基準線、情資都在），鑰匙圈的 `asa` 項目複製到新名；
  `ai-security-monitor service install` 移除舊的 `asa` 服務／Run 值／unit／plist 換成新名（系統層目錄也一起搬），`ai-security-monitor mcp install` 把舊的 `asa` MCP 項目換掉。舊版可以直接 `asa self-update --yes` 升上來。
- **環境變數**：新前綴 `AI_SECURITY_MONITOR_*`（Hub 是 `AI_SECURITY_MONITOR_HUB_*`），舊的 `ASA_*`／`ASA_HUB_*` 照樣有效，只寫舊名的 `.env` 不用改。
- **刻意不改**：防火牆物件名（Windows 群組 `ASA`、`ASA: …` 規則、nft `table inet asa`、ipset `asa_*`、pf anchor `com.asa`、`fw unblock --all-asa`）、通訊標頭 `x-asa-*`、token 前綴 `asa_`／`asa_ek_`、資料庫 `asa_hub` 與 compose 專案名，舊的規則與資料都認得。
- **桌面版**：應用程式識別碼改了，新版不會覆蓋舊版，請先到「設定 → 應用程式」解除安裝舊的「AI Security Agent」再裝新版（見 [docs/desktop.md](docs/desktop.md)）。
- **Hub 映像**：改名 `ghcr.io/markku636/ai-security-monitor-hub`；舊名 `ghcr.io/markku636/ai-security-agent-hub` 過渡期內照樣發佈。

細節見 [docs/install.md](docs/install.md#從-asa01x升級)、[docs/service.md](docs/service.md#從-asa01x升級) 與 [變更紀錄](CHANGELOG.md)。

## 文件

[連線判定與威脅情資](docs/intel.md) · [防火牆與封鎖](docs/firewall.md) · [安裝與更新](docs/install.md) · [開機自動啟動](docs/service.md) · [桌面版](docs/desktop.md) · [Docker](docs/docker.md) · [MCP 與 AI](docs/mcp.md) · [流量](docs/traffic.md) · [事件與當機](docs/events.md) ·
[漏洞與更新](docs/vuln.md) · [系統硬化](docs/hardening.md) · [Agent ↔ Hub 契約](docs/hub-contract.md) · [變更紀錄](CHANGELOG.md)

## 從原始碼建置

```bash
# agent（Rust 1.85+）
cd agent && cargo build --release && ./target/release/ai-security-monitor doctor

# Hub（Node 22+）
cd hub && npm ci && npm run dev:db && npm run dev    # http://localhost:3000
npm run verify                                        # typecheck、i18n、測試、build

# 桌面版（Tauri 2，介面是 desktop/ui 的純 HTML／JS）
cd desktop && npm ci && npx tauri build              # 產生 NSIS 安裝檔
```

示範資料：`node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <管理員金鑰>`；截圖：`node scripts/capture-screenshots.mjs --hub http://127.0.0.1:3000 --admin <管理員金鑰>`。

## 資料來源與授權

本專案以 MIT 授權。威脅情資、漏洞與地理資料來自各自的提供者並遵守其授權（例如 DShield 為非商用、預設只告警；DB-IP 需標註），
每一筆命中都附來源網址；完整清單見 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。

MIT © 2026 mark.ku（markku636）
