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

裝上去之後，它會告訴你這台電腦在跟誰講話、哪些連線可疑、哪裡沒設好，再請 AI 用白話解釋給你聽。
每一個「可疑」都會附上理由和出處（哪一份公開的壞人名單、哪一種奇怪的行為），不是黑箱打分數。
可以只看自己這台，也可以把辦公室裡好幾台電腦集中到一個網頁看。

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/windows-desktop-hero-dark.png">
    <img src="docs/images/windows-desktop-hero.png" alt="AI Security Monitor 桌面版在 Windows 上：總覽頁顯示安全分數與可疑連線，右下角系統匣有圖示">
  </picture>
</p>

<p align="center"><sub>Windows 桌面版的總覽頁（示範資料）。關掉視窗後會縮到右下角的系統匣繼續待命。</sub></p>

## 適合誰？

- **個人電腦**：想知道自己的 Windows／Mac／Linux 有沒有連到奇怪的地方、有沒有該更新沒更新、安全設定有沒有漏掉。裝桌面版就好。
- **辦公室好幾台電腦**：IT 或老闆想在一個網頁看全部電腦的狀況，有問題可以一起處理，必要時在網頁上核准「封鎖這個 IP」。用 Hub。
- **伺服器**（含 Windows Server、Server Core、網域控制站、Linux）：沒有桌面也能用，裝成開機就跑的背景服務，定時檢查並回報。用命令列版。

幾個會一直出現的詞，先講清楚：

| 詞 | 白話 |
|---|---|
| agent | 裝在每台電腦上、負責檢查的小程式，也就是 `ai-security-monitor` 本身 |
| 威脅情資 | 別人整理好、公開的壞人名單（例如已知的殭屍網路主機、正在暴力破解的 IP） |
| Hub（Security Hub） | 集中看所有電腦的網頁，自己架在公司裡（Docker） |
| 硬化 | 系統安全設定，例如有沒有開磁碟加密、防毒、遠端桌面的保護 |
| MCP | 讓 Claude Code、Codex 這類 AI 工具可以「查資料」的標準接口；這裡只開放查詢，不能改設定 |

## 我該裝哪一個？

所有檔案都在 [Releases（最新版）](https://github.com/markku636/ai-security-monitor/releases/latest)，目前版本 **v0.3.0**。

| 你想要 | 裝這個 | 下載的檔案 |
|---|---|---|
| 在自己電腦上用視窗看 | **桌面版**（雙擊安裝） | Windows 10／11：`AI-Security-Monitor-<版本>-windows-x64-setup.exe`<br>Mac（M1 以後）：`…-macos-arm64.dmg`；Mac（Intel）：`…-macos-x64.dmg`<br>Linux：`…-linux-x64.AppImage`（免安裝）或 `…-linux-amd64.deb` |
| 伺服器、沒有桌面、或想用指令和自動化 | **命令列版** | 用下面的一行安裝指令最省事（會自動比對校驗碼）。也可以直接下載 `ai-security-monitor-<版本>-<平台>`，但它要在終端機裡執行，雙擊只會跳出說明 |
| 一個網頁看全公司的電腦 | **Security Hub** | Docker 映像 `ghcr.io/markku636/ai-security-monitor-hub`，不用下載檔案 |
| （看到 `asa-<版本>-*`） | 不用理它 | 給 0.1.x 舊版自動升級用的，內容和命令列版一樣 |
| （看到 `SHA256SUMS`） | 校驗碼 | 每個檔案的指紋；安裝腳本和 `self-update` 會自動比對，被竄改就不裝 |

桌面版和命令列版可以裝在同一台電腦，兩個會共用同一份設定和掃描結果。

## 5 分鐘上手

### 情境 A：我只想看自己的電腦（Windows）

1. 到 [Releases](https://github.com/markku636/ai-security-monitor/releases/latest) 下載 `AI-Security-Monitor-<版本>-windows-x64-setup.exe`。
2. 雙擊安裝檔。如果跳出藍色的「Windows 已保護您的電腦」，按「**其他資訊**」，再按「**仍要執行**」。
   這是因為安裝檔沒有付費的程式碼簽章，Windows 認不得發行者，不代表檔案有問題；不放心可以先比對 `SHA256SUMS`。
3. 安裝到目前使用者，不需要系統管理員。裝好後從開始功能表打開「AI Security Monitor」。
   第一次開啟會先出現「尋找公司的 Security Hub」，只用在自己電腦的話，按最下面的「先不要，只在這台電腦使用」。
4. 在「總覽」頁先按「**更新情資**」（下載壞人名單），再按「**立即掃描**」。
5. 看結果：
   - 「總覽」：安全分數和最需要注意的連線。
   - 「連線」：這台電腦現在連到哪裡、為什麼被判可疑；點 IP 可以看它在哪個國家、被哪些名單列入。
   - 「掃描結果」：漏洞、沒裝的更新、沒設好的安全設定，每一條都附修正方式。
   - 「AI 分析」：如果這台電腦已經裝好並登入 Claude Code 或 Codex CLI，按一下就會請 AI 用白話解讀（用的是你自己的帳號）。

關掉視窗只是縮到右下角的系統匣，從系統匣選單按「結束」才會真的離開。
想讓它在背景定時檢查，到「設定」頁打開「開機／登入後在背景自動回報」。Mac 和 Linux 的安裝步驟見下方「[安裝](#安裝)」。

### 情境 B：我要管辦公室好幾台

**第一步：架 Hub**（找一台一直開著、有裝 Docker 的電腦或伺服器）

```bash
git clone https://github.com/markku636/ai-security-monitor && cd ai-security-monitor
cp .env.example .env    # 打開 .env，填 AI_SECURITY_MONITOR_HUB_ADMIN_SECRET（登入密碼）、AI_SECURITY_MONITOR_HUB_DB_PASSWORD，
                        # 以及 AI_SECURITY_MONITOR_HUB_PUBLIC_URL（其他電腦連這台用的網址，例如 http://<這台的 IP>:8088）
docker compose -f docker/compose.yml --env-file .env up -d
```

用瀏覽器打開 `http://<這台的 IP>:8088`，用剛剛填的 `AI_SECURITY_MONITOR_HUB_ADMIN_SECRET` 登入。
只想在自己這台試試看的話，把 `compose.yml` 換成 `compose.standalone.yml`，就只開在 `http://127.0.0.1:8088`。

**第二步：把電腦加進來**

**方法一：讓電腦自己找到 Hub，管理員按「核准」（建議，不用發金鑰）**

1. 管理員打開 Hub 左側的「新增主機」，記下最上面的 **Hub 指紋**（一串像 `72AS-YEXT-VNGO-NLC5-W2NM` 的代碼，用來確認是自己公司的 Hub，不是別人架的假貨）。
2. 同事那邊擇一：
   - **桌面版**：第一次開啟就會自動找公司的 Hub。看到的指紋和管理員說的一樣，就按「**申請加入**」。找不到的話，可以輸入管理員給的網址。
   - **命令列版**：執行 `ai-security-monitor enroll --auto`，核對指紋後送出申請，再執行 `ai-security-monitor service install --yes`（還沒核准也可以先裝，它會在背景等）。
   - **還沒裝的電腦**：把「新增主機」頁上的「免金鑰安裝指令」給同事貼上執行，網址已經填好。
3. 管理員在「新增主機 → 待核准的主機」核對主機名稱和核對碼（電腦端也會顯示同一組），按「**核准**」就完成。
   嫌一台一台按太麻煩，可以設定「自動核准的網段」，例如公司內網 `192.168.10.0/24`。

電腦是靠公司 DNS 的 SRV 紀錄或區網廣播（mDNS）找到 Hub 的。Hub 跑在 Docker Desktop 裡時廣播出不了區網，
這時用 `ai-security-monitor hub advertise --url <Hub 網址>` 代為廣播，或直接給網址；細節見 [自動尋找 Hub、免金鑰加入](docs/enrollment.md)。

**方法二：用註冊金鑰**

- 在「新增主機」頁建立一把註冊金鑰，頁面會產生已經填好網址和金鑰的一行安裝指令（Windows、macOS、Linux 各一行），到要加入的電腦上貼上執行。
- 已經裝好命令列版的電腦：

  ```bash
  ai-security-monitor enroll http://<Hub 的 IP>:8088 --key asa_ek_…
  ai-security-monitor service install --yes    # 登入後自動回報；伺服器改用 --system
  ```

- 桌面版：「設定」頁按「我有註冊金鑰」。

幾分鐘內，Hub 的「主機」頁就會出現這台電腦。之後每 1 分鐘回報一次連線、每 10 分鐘一份完整報告；Hub 暫時連不上時，報告會先存著，連上再補送。

### 情境 C：伺服器／Windows Server

Windows Server（2016 到 2025，含 Server Core）用「以系統管理員身分執行」的 PowerShell：

```powershell
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

Linux、macOS：

```bash
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

開一個**新的**終端機視窗，然後：

```bash
ai-security-monitor doctor                          # 看權限、情資、Hub 連線是否正常
ai-security-monitor intel update                    # 下載威脅情資
ai-security-monitor scan                            # 完整檢查一次
ai-security-monitor service install --system --yes  # 裝成開機就跑的系統服務（Linux／macOS 前面加 sudo）
```

沒加 `--yes` 的話，`service install`、封鎖 IP 這類會改系統的指令只會先列出「我打算做什麼」，不會真的動手，看過再加 `--yes`。
要回報到 Hub，照[情境 B](#情境-b我要管辦公室好幾台) 加入即可（伺服器上同樣可以用 `enroll --auto`）。

## 常見問題

<details>
<summary><b>雙擊 .exe 一下就關掉？</b></summary>

你下載到的可能是命令列版 `ai-security-monitor-<版本>-windows-x64.exe`。它是給終端機用的，雙擊只會顯示一頁說明（告訴你桌面版在哪、怎麼一行安裝），按 Enter 就關閉。
要視窗介面請下載 `AI-Security-Monitor-<版本>-windows-x64-setup.exe`；要用命令列版，請在 PowerShell 裡執行，例如 `ai-security-monitor doctor`。
</details>

<details>
<summary><b>SmartScreen 擋住，說「Windows 已保護您的電腦」？</b></summary>

安裝檔沒有付費的程式碼簽章，所以 Windows 不認得發行者。按「其他資訊」→「仍要執行」即可。
想確認檔案沒被動過，可以在 PowerShell 執行 `Get-FileHash .\AI-Security-Monitor-<版本>-windows-x64-setup.exe`，和 Releases 上 `SHA256SUMS` 裡的值比對。
Mac 第一次打開要在「應用程式」裡對它按右鍵 →「打開」，見下方「[安裝](#安裝)」。
</details>

<details>
<summary><b>AI 助手說「Please run /login」？</b></summary>

代表 Claude Code 還沒登入。AI 分析用的是你自己的 Claude Code 或 Codex CLI 帳號，本專案不提供 AI 額度。

- **桌面版、命令列版**：在同一台電腦開終端機執行 `claude`，輸入 `/login` 照指示登入，完成後輸入 `/exit`。Codex 則執行 `codex` 登入。`ai-security-monitor ai status` 可以看兩者有沒有裝好、登入了沒。
- **Hub 網頁上的 AI 助手**：AI 跑在 Hub 的容器裡，要登入容器裡的那一份，見下方「[安裝](#安裝)」的 Hub 步驟。
</details>

<details>
<summary><b>會不會把我的資料送出去？</b></summary>

不會送給我們，本專案沒有任何遙測或回報給作者的功能。會連到外面的只有這些：

- **下載威脅情資**：向 abuse.ch、Spamhaus 等名單提供者下載清單（有 Hub 就先向你自己的 Hub 拿）。這是「下載」，不會上傳你的連線。
- **檢查漏洞**：Linux 會拿已安裝套件的名稱和版本去問 OSV.dev（不想要可以加 `--no-online`）。
- **檢查新版本**：桌面版與背景服務預設每天查一次 GitHub Releases（只是讀取最新版本號，`update.mode` 設 `off` 或桌面版「自動更新」選「關閉」就不查）；`self-update`、`version --check` 也會查；Hub 也會查有沒有新版並在管理頁顯示（`AI_SECURITY_MONITOR_HUB_UPDATE_CHECK=0` 關閉）。
- **你主動按的時候**：IP 線上名譽查詢（`intel lookup --online`，或 Hub 上按「查詢外部情資」，要自己填 API 金鑰；私有網段一律不送）、桌面版的 VirusTotal／AbuseIPDB 連結（只是用瀏覽器打開網頁）。
- **AI 分析**：透過你自己電腦上的 Claude Code／Codex CLI，資料只會照你和 Anthropic／OpenAI 之間的帳號條款處理。
- **你自己的 Hub**：註冊後，報告只送到你指定的 Hub。自動找 Hub 時，只會查公司 DNS 和在區網裡廣播詢問。
</details>

<details>
<summary><b>怎麼更新？自動更新怎麼關？</b></summary>

預設是「有新版時通知我」：每天到 GitHub 查一次，有新版就提醒你（Hub 的主機清單也會標「有新版」），**不會自己裝**。

- **桌面版**：「設定 → 背景自動回報與自動更新」選「關閉」「有新版時通知我」或「自動更新」。按「檢查更新」看目前和最新版本、「立即更新」馬上更新（下載、驗證簽章後安裝，裝完自動重新開啟）。選「自動更新」時，新版會先在背景下載好，下次結束或重新開啟時安裝。背景自動回報用的就是桌面版本身，會跟著一起更新。
- **命令列版**：`ai-security-monitor config set update.mode off`（關閉）／`notify`（預設）／`auto`（背景服務自動下載、比對 SHA256、替換並重新啟動）。手動更新：`ai-security-monitor version --check` 看有沒有新版，`ai-security-monitor self-update --yes` 更新，背景服務會自動重新啟動成新版（系統服務要用系統管理員執行）。用 apt、Homebrew、Scoop、winget 等套件管理員裝的，請用套件管理員更新。
- 公司要用自己的鏡像：設 `AI_SECURITY_MONITOR_UPDATE_URL`（命令列版）。

細節見 [docs/install.md](docs/install.md#更新)。
</details>

<details>
<summary><b>怎麼手動上傳到 Hub？</b></summary>

背景服務本來就會定時回報（預設每 10 分鐘完整掃描、每分鐘連線快照）。想馬上看到結果時：

- **桌面版**：總覽頁的「上傳到 Security Hub」卡片按「立即掃描並上傳到 Hub」。卡片也會顯示上次上傳是多久以前、有幾份報告在等重送（Hub 連不上時先暫存），按「重新上傳」就會先補送。
- **命令列版**：`ai-security-monitor upload`——先補送暫存的報告，再上傳連線快照、完整掃描報告與心跳，最後顯示「已上傳，Hub 收到 N 筆」。
</details>

<details>
<summary><b>為什麼找不到公司的 Hub？</b></summary>

「尋找公司的 Hub」靠公司 DNS 的 SRV 紀錄或區網廣播（mDNS）。找不到通常是這三種情況：

1. **Hub 只開放給它自己那台電腦**：單機版預設只綁 127.0.0.1，辦公室其他電腦連不到也找不到。請管理員改用伺服器版，或在 Hub 的 `.env` 加 `AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0` 與 `AI_SECURITY_MONITOR_HUB_PUBLIC_URL=http://<那台的區網 IP>:8088`（一定要有管理員金鑰，只在公司內網使用）。
2. **Hub 跑在 Docker Desktop 裡**：它的區網廣播出不了 Docker。在跑 Hub 的那台電腦打開桌面版「設定 → 讓區網裡的電腦找到這台的 Hub」，或執行 `ai-security-monitor config set hub.advertise_url http://<那台的區網 IP>:8088`，由背景服務幫忙廣播。
3. **不在同一個網段**：區網廣播過不了路由器，要請管理員在公司 DNS 加 `_aisecmon._tcp` 的 SRV 紀錄（Hub「新增主機」頁有現成指令）。

都不行時，直接跟管理員要 Hub 網址：桌面版填在「或輸入管理員給的 Hub 網址」，命令列 `ai-security-monitor enroll --hub <網址>`。Hub「新增主機」頁的「辦公室的電腦找得到這個 Hub 嗎？」會用白話告訴管理員現在卡在哪一步。
</details>

<details>
<summary><b>可以免費商用嗎？</b></summary>

程式碼是 MIT 授權，可以免費商用。但部分威脅情資來源本身只允許非商業使用（例如 DShield），在公司裡用時要留意哪些來源該關掉，詳見「[資料來源與授權](#資料來源與授權)」。
</details>

<details>
<summary><b>怎麼移除？</b></summary>

- **桌面版**：Windows 到「設定 → 應用程式 → 已安裝的應用程式」找「AI Security Monitor」解除安裝；Mac 把它從「應用程式」拖到垃圾桶；Linux deb 從軟體管理員移除（或 `sudo apt remove` 加上 `apt list --installed` 裡看到的套件名稱），AppImage 直接刪掉檔案。
- **命令列版**：先停掉背景服務 `ai-security-monitor service uninstall --yes`（系統服務加 `--system`），加入過 Hub 的話執行 `ai-security-monitor unenroll` 刪掉金鑰，最後刪掉執行檔（Windows 預設在 `%LOCALAPPDATA%\ai-security-monitor\bin`，系統服務在 `%ProgramFiles%\ai-security-monitor`；Linux／macOS 在 `/usr/local/bin` 或 `~/.local/bin`）。
- **設定和掃描紀錄**：`ai-security-monitor config path` 會告訴你在哪個資料夾，不要了就整個刪掉。
- **Hub**：`docker compose -f docker/compose.yml --env-file .env down`；連資料一起清掉加 `-v`。
</details>

## 畫面預覽

**桌面版（Windows）**

| | |
|---|---|
| ![桌面版連線](docs/images/windows-desktop-connections.png) 連線：每條連線的判定、理由和情資出處，點 IP 看國家、組織和被哪些名單列入 | ![桌面版 AI 分析](docs/images/windows-desktop-ai.png) AI 分析：本機的 Claude Code／Codex 透過唯讀工具查資料，再用白話解釋 |
| ![桌面版掃描結果](docs/images/windows-desktop-findings.png) 掃描結果：依嚴重程度排序，展開看細節和修正方式 | ![桌面版深色模式](docs/images/windows-desktop-overview-dark.png) 深色模式：跟著 Windows 的設定 |

**Security Hub（網頁）**

| | |
|---|---|
| ![Hub 總覽](docs/images/overview.png) 總覽：所有電腦的分數、待處理問題和危險連線 | ![連線](docs/images/connections.png) 連線：方向、判定、程式、國家／組織、理由與情資來源 |
| ![主機](docs/images/agent.png) 單台主機：五項分數、趨勢、連過的危險目的地 | ![待處理問題](docs/images/findings.png) 待處理問題：依裝置、狀態、嚴重度篩選，批次處理 |
| ![Windows Server](docs/images/agent-server.png) Windows Server：網域控制站 dc-01（Server Core） | ![漏洞](docs/images/vulns.png) 漏洞與更新：作業系統支援期限、已被利用的漏洞、有漏洞的軟體 |
| ![安全設定](docs/images/hardening.png) 安全設定：最常沒通過的檢查與各主機分數 | ![事件](docs/images/events.png) 當機與事件：藍屏代碼與可能原因、暴力破解來源 |
| ![情資](docs/images/intel.png) 威脅情資：每台主機的名單新舊、授權、命中 | ![新增主機](docs/images/install.png) 新增主機：建立註冊金鑰並產生一行安裝指令 |
| ![流量](docs/images/traffic.png) 流量：所有主機的頻寬圖、哪台與哪個程式用最多、各網卡 | ![效能](docs/images/agent-perf.png) 主機「效能」分頁（可選開啟）：CPU、記憶體、磁碟、電池、最吃資源的程式 |

> 截圖全部是示範資料（虛構主機、文件專用的保留 IP、example.com），Hub 由 `scripts/demo-seed.mjs` 灌資料，桌面版由 `scripts/capture-desktop-screenshots.mjs` 產生。更多桌面版畫面見 [docs/desktop.md](docs/desktop.md)。

## 功能一覽

- **連線與威脅情資**：每條連線分方向（對外／對內／監聽／本機），比對 Spamhaus DROP、abuse.ch（Feodo、URLhaus、ThreatFox）、blocklist.de、CINS、ET、DShield、Tor、IPsum、FireHOL 等公開名單，
  再加上行為判斷（從暫存資料夾執行的程式、命令列程式直接連外、高風險 port、規律的定時連線、新目的地），判定安全／未知／可疑／危險；每個命中都附廠商、信心、授權與來源網址。可選 AbuseIPDB／GreyNoise／CrowdSec 線上查詢（自備金鑰）。
- **防火牆與曝露**：讀 Windows 防火牆、macOS pf／應用程式防火牆、Linux nftables／firewalld／ufw／iptables，算出每個監聽 port 實際能不能從外面連進來；
  `fw block`、`fw sync-blocklist` 可以把高信心的壞 IP 變成封鎖規則（先預演、確認後才做、可以撤銷；非商用授權的來源預設只告警）。
- **漏洞與更新**：已安裝軟體、作業系統支援期限（含 Windows Server 2008 到 2025）、Windows 多久沒更新、Linux 待裝的安全性更新、常見軟體的已知漏洞版本（WinRAR、7-Zip、Chrome…），Linux 套件查 OSV，已被實際利用的（CISA KEV）升為嚴重。
- **系統安全設定（硬化）**：60 條跨平台檢查（UAC、Defender、BitLocker、SMBv1、遠端桌面 NLA、SSH、核心參數、AppArmor／SELinux、FileVault、Gatekeeper…），自動分辨 Windows 用戶端、Server、Server Core 與網域控制站，可用 YAML 自訂。
- **流量**：不抓封包也能看各程式連到哪裡；也能分析 Wireshark／tcpdump 存的 pcap／pcapng（DNS、TLS SNI、明文協定、大量上傳、定時連線）。
- **流量統計與效能**：每分鐘記錄各網卡、各程式的上傳／下載量，Hub 畫出頻寬圖、哪台與哪個程式用最多；CPU、記憶體、磁碟、電池是**選用**的，預設關，要在那台電腦上自己開（桌面版設定或 `config set metrics.performance true`，Hub 無法從遠端開），磁碟快滿、CPU 長時間滿載會列成待處理問題。
- **事件與當機**：Windows 事件記錄、藍屏 minidump、Linux journal、macOS 當機報告，整理出可能原因與處理方式；也抓暴力破解、帳號鎖定、從公網登入遠端桌面、新帳號、新服務、清除稽核記錄等資安事件。
- **AI 與 MCP**：`ai ask`、`ai analyze` 交給 Claude Code 或 Codex CLI 解讀（只給唯讀工具）；`mcp` 讓 Claude Code／Codex／Cursor／VS Code 直接查這台電腦；Hub 也有全部主機層級的 MCP 和網頁上的 AI 助手。
- **Hub**：總覽、主機、連線、待處理問題、漏洞、安全設定、流量、事件、情資、封鎖審核（簽章、主機身分綁定）、免金鑰加入申請與核准（DNS SRV、區網 mDNS 自動尋找）、註冊金鑰、唯讀 API token、稽核、CSV 匯出、中英文、深色模式、手機版面。
- **部署與更新**：開機自動啟動（Windows 服務／systemd／launchd 或登入時啟動）、`self-update`（比對 SHA256SUMS）、一行安裝腳本、Hub Docker 映像（amd64／arm64）。

## 安裝

這一段是每個平台的完整步驟；只想快速開始的話看上面的「[5 分鐘上手](#5-分鐘上手)」就夠了。

**系統需求**

| | 需求 |
|---|---|
| 桌面版 Windows | Windows 10／11（x64）；需要 Microsoft Edge WebView2（Windows 10／11 內建，沒有的話安裝檔會自動下載） |
| 桌面版 macOS | macOS 10.13 以上（Apple Silicon 或 Intel） |
| 桌面版 Linux | x64，Ubuntu 22.04／Debian 12 以上（glibc 2.35 以上）；deb 會自動裝 WebKitGTK 4.1，系統匣圖示需要桌面支援 AppIndicator |
| 命令列版 | Windows 10／11、Windows Server 2016／2019／2022／2025（含 Server Core），x64 或 ARM64；macOS 11 以上；Linux x64／ARM64（靜態連結，不挑發行版） |
| Security Hub | Docker 24 以上（含 Compose v2），amd64 或 arm64 |

**桌面版：Windows**：見[情境 A](#情境-a我只想看自己的電腦windows)。裝過舊的「AI Security Agent」（0.1.x）要先到「設定 → 應用程式」解除安裝，新版不會覆蓋它。
裝好後視窗會出現「總覽」，右下角系統匣有 AI Security Monitor 圖示。

**桌面版：macOS**

1. Apple Silicon（M1、M2…）下載 `AI-Security-Monitor-<版本>-macos-arm64.dmg`，Intel 下載 `…-macos-x64.dmg`。不確定的話：蘋果選單 →「關於這台 Mac」，看「晶片」或「處理器」。
2. 打開 dmg，把「AI Security Monitor」拖到「應用程式」。
3. 第一次開啟：在「應用程式」對它按右鍵 →「打開」→ 再按「打開」。如果顯示「已損毀，無法打開」，在終端機執行：
   `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"`

**桌面版：Linux**

- AppImage（各發行版通用，免安裝）：`chmod +x AI-Security-Monitor-<版本>-linux-x64.AppImage && ./AI-Security-Monitor-<版本>-linux-x64.AppImage`
- deb（Debian／Ubuntu）：`sudo apt install ./AI-Security-Monitor-<版本>-linux-amd64.deb`，之後從應用程式選單開啟。

**命令列版：Windows、Windows Server**

1. 開 PowerShell。要裝成開機就啟動的系統服務，請用「以系統管理員身分執行」。
2. 執行 `irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex`，預設裝到 `%LOCALAPPDATA%\ai-security-monitor\bin` 並加進 PATH。
3. 開一個**新的** PowerShell 視窗，執行 `ai-security-monitor version`，應該印出 `ai-security-monitor 0.3.0 …`。
4. （選用）登入後自動啟動：`ai-security-monitor service install --yes`；伺服器開機就啟動：`ai-security-monitor service install --system --yes`（系統管理員）。`ai-security-monitor service status` 可以確認。

**命令列版：Linux、macOS**

1. 執行 `curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh`，預設裝到 `/usr/local/bin`，沒有權限就裝到 `~/.local/bin`。
2. 執行 `ai-security-monitor version` 和 `ai-security-monitor doctor` 確認。
3. （選用）`ai-security-monitor service install --yes` 登入後啟動；伺服器用 `sudo ai-security-monitor service install --system --yes`。

安裝腳本會比對 Release 的 `SHA256SUMS`，不符就停止。指定版本、安裝位置、內部鏡像、安裝時順便註冊 Hub 等選項見 [docs/install.md](docs/install.md)。

**Security Hub（Docker）**

1. 照[情境 B](#情境-b我要管辦公室好幾台) 啟動。單機版 `docker/compose.standalone.yml` 只開在本機 `http://127.0.0.1:8088`；伺服器版 `docker/compose.yml` 讓其他電腦回報。
2. 確認：`curl http://127.0.0.1:8088/api/health` 回 `"db":"ok"`，網頁看得到登入頁。
3. （選用）讓 Hub 的「AI 助手」能用：映像裡已經裝好 Claude Code 與 Codex，但要先登入一次（畫面出現「Please run /login」就是還沒登入）。擇一：
   - **用 Claude 訂閱帳號登入**：執行 `docker compose -f docker/compose.yml --env-file .env exec hub claude`（單機版換成 `compose.standalone.yml`），輸入 `/login` → 選 Claude 帳號 → 把網址貼到瀏覽器授權 → 把授權碼貼回來 → 看到登入成功後輸入 `/exit`。
   - **用 token 或 API key**（不用進容器）：在自己電腦跑 `claude setup-token` 產生長效 token，在 `.env` 加 `CLAUDE_CODE_OAUTH_TOKEN=…`；或用 `ANTHROPIC_API_KEY=…`；Codex 用 `OPENAI_API_KEY=…`。改完再執行一次 `up -d`。

   登入資料存在 `hubdata` volume，更新映像或重建容器都會保留。AI 只拿到唯讀工具，看得到 Hub 的資料但不能改。

細節見 [docs/docker.md](docs/docker.md)。

**從舊版升級**：命令列版執行 `ai-security-monitor self-update --yes`（0.1.x 用 `asa self-update --yes`），再執行一次 `ai-security-monitor service install --yes`（系統服務加 `--system`）；桌面版直接裝新版（0.1.x 的「AI Security Agent」要先解除安裝）。見「[從 asa／ai-security-agent 升級](#從-asaai-security-agent-升級)」。

## 運作方式

```mermaid
flowchart LR
  subgraph HOST["每台要保護的電腦／伺服器"]
    direction TB
    CLI["ai-security-monitor<br/>CLI／背景服務 watch"]
    DESK["桌面版 AI Security Monitor<br/>Tauri，共用 agent 程式庫"]
    CFG[("設定目錄<br/>最新報告、情資、離線佇列")]
    CLI --- CFG
    DESK --- CFG
  end

  subgraph HUB["Security Hub"]
    direction TB
    API["Next.js API＋網頁介面"]
    DB[("PostgreSQL")]
    MIRROR["情資鏡像"]
    HMCP["MCP：/api/mcp（唯讀）"]
    API --- DB
  end

  VENDORS["威脅情資廠商<br/>abuse.ch、Spamhaus、blocklist.de…"]
  ADMIN["管理員瀏覽器"]
  AI["Claude Code／Codex CLI"]

  CLI -- "快照＋心跳：每 1 分鐘<br/>完整報告：每 10 分鐘<br/>HTTPS＋每台主機 token" --> API
  API -- "核准過的遠端動作<br/>HMAC 簽章" --> CLI
  VENDORS --> MIRROR
  MIRROR -- "情資：每 30 分鐘檢查" --> CLI
  ADMIN --> API
  AI -- "ai-security-monitor mcp<br/>預設唯讀" --> CLI
  AI -- "唯讀" --> HMCP
```

- **定時回報**：背景服務 `ai-security-monitor watch` 每 1 分鐘拍一次連線快照並送心跳，每 10 分鐘跑一次完整掃描（間隔可用 `config set scan.snapshot_interval`／`scan.interval` 調）。
  上傳走 HTTPS（http 只允許本機或私網），帶註冊時拿到的金鑰和這台主機自己的 token；Hub 第一次看到就綁定，別台冒用會被擋。
- **加入 Hub**：電腦用公司 DNS 的 SRV 紀錄或區網 mDNS 找 Hub，Hub 用自己的金鑰（Ed25519）簽章證明身分，電腦記下 Hub 指紋，之後指紋不符就拒絕上傳；管理員核准後才發給這台專屬的金鑰。
- **離線佇列**：Hub 停機或斷線時，完整報告先存在設定目錄的 `outbox/`（最多 50 份），連得上再依序補送。
- **遠端動作**：管理員在 Hub 送出封鎖並核准後，agent 才去領取；每個動作都有 HMAC-SHA256 簽章，agent 驗章、檢查期限與護欄後才執行。註冊時沒加 `--accept-remote-actions` 的主機完全不領取。
- **情資**：Hub 依 `feeds/registry.json` 向各廠商下載並快取，agent 每 30 分鐘檢查一次，已註冊就先向 Hub 拿，Hub 沒有的才直接找廠商。
- **桌面版**：直接連結 agent 的 Rust 程式庫、讀同一個設定目錄，所以看得到背景服務的最新報告和 Hub 註冊；回報 Hub 仍由背景服務負責。
- **AI**：`ai-security-monitor mcp`（stdio 或 `--http`）預設只有唯讀工具，封鎖等動作要加 `--allow-actions` 才會出現；Hub 的 `/api/mcp` 全部唯讀。
  命令列、桌面版和 Hub 網頁上的 AI 分析，都是呼叫你已登入的 Claude Code／Codex CLI 並掛上這些唯讀工具。

## 命令列速查

```bash
ai-security-monitor doctor                       # 環境檢查：權限、情資新鮮度、外部工具、Hub 連線
ai-security-monitor intel update                 # 下載威脅情資（之後背景服務會自動更新）
ai-security-monitor connections --intel          # 目前連線與判定
ai-security-monitor scan                         # 完整掃描（連線、情資、防火牆、port、事件、漏洞、安全設定）
ai-security-monitor fw sync-blocklist --dry-run  # 預覽會封鎖哪些高信心的壞 IP
ai-security-monitor ai ask "這台電腦有沒有連到危險的地方？"   # 交給 Claude Code／Codex 解讀
ai-security-monitor enroll --auto               # 自動找公司的 Hub、送出加入申請等核准（有金鑰：enroll <網址> --key asa_ek_…）
ai-security-monitor service install --yes        # 登入後自動回報（伺服器加 --system）
```

| 命令 | 用途 |
|---|---|
| `scan`、`connections`、`ports` | 完整掃描、連線判定、port 可達性 |
| `intel` | 情資更新、來源與授權、查 IP／網域 |
| `fw` | 防火牆狀態、稽核、封鎖／解除、情資同步 |
| `vuln`、`harden` | 漏洞與更新、系統安全設定 |
| `traffic`、`events` | 流量觀察與 pcap 分析、事件與當機原因 |
| `metrics` | 現在的上傳／下載速率（各網卡、各程式），開啟效能蒐集時另有 CPU、記憶體、磁碟 |
| `ai`、`mcp` | Claude Code／Codex 分析、MCP server 與一鍵設定 |
| `enroll`、`discover`、`unenroll`、`status`、`watch`、`service` | 找 Hub、加入 Hub、常駐回報、開機自動啟動 |
| `self-update`、`version`、`doctor` | 更新與環境檢查（`config set update.mode off\|notify\|auto` 設定自動更新） |
| `upload` | 立即掃描並上傳到 Hub（先補送暫存的報告） |
| `allowlist`、`baseline`、`config` | 白名單、基準線（只看新增）、設定 |

`ai-security-monitor --help`、`ai-security-monitor <命令> --help` 看完整參數；`--lang en` 切英文、`--json` 給程式讀。

## 從 asa／ai-security-agent 升級

0.2.0 起專案改名為 ai-security-monitor（執行檔 `asa` → `ai-security-monitor`，GitHub 舊網址會自動轉址），不用重新註冊：

- **自動沿用**：第一次執行新版時，設定目錄 `…/ai-security-agent` 會搬到 `…/ai-security-monitor`（agent id、Hub 註冊、白名單、基準線、情資都在），鑰匙圈的 `asa` 項目複製到新名。
  舊版的常駐 watch 還在跑時先沿用舊目錄，等 `service install` 換掉舊服務時才搬；`service install` 會移除舊的 `asa` 服務，`mcp install` 會換掉舊的 MCP 設定。
- **環境變數**：新前綴 `AI_SECURITY_MONITOR_*`（Hub 是 `AI_SECURITY_MONITOR_HUB_*`），舊的 `ASA_*`／`ASA_HUB_*` 照樣有效。
- **刻意不改**：防火牆物件名（Windows 群組 `ASA`、nft `table inet asa`、ipset `asa_*`、pf anchor `com.asa`）、通訊標頭 `x-asa-*`、token 前綴 `asa_`／`asa_ek_`、資料庫 `asa_hub`，舊規則與資料都認得。
- **桌面版**：應用程式識別碼改了，請先解除安裝舊的「AI Security Agent」再裝新版（見 [docs/desktop.md](docs/desktop.md)）。
- **Hub 映像**：改名 `ghcr.io/markku636/ai-security-monitor-hub`；舊名 `ghcr.io/markku636/ai-security-agent-hub` 過渡期內照樣發佈。

細節見 [docs/install.md](docs/install.md#從-asa01x升級)、[docs/service.md](docs/service.md#從-asa01x升級) 與 [變更紀錄](CHANGELOG.md)。

## 文件

[連線判定與威脅情資](docs/intel.md) · [防火牆與封鎖](docs/firewall.md) · [安裝與更新](docs/install.md) · [自動尋找 Hub、免金鑰加入](docs/enrollment.md) · [開機自動啟動](docs/service.md) · [桌面版](docs/desktop.md) · [Docker](docs/docker.md) · [MCP 與 AI](docs/mcp.md) · [流量](docs/traffic.md) · [流量統計與效能](docs/metrics.md) · [事件與當機](docs/events.md) ·
[漏洞與更新](docs/vuln.md) · [系統硬化](docs/hardening.md) · [Agent ↔ Hub 契約](docs/hub-contract.md) · [變更紀錄](CHANGELOG.md)

## 緣起

某天睡前，讓 AI 做了一個小專案：用 Rust 寫一個程式，蒐集並分析用戶端的異常連線，做威脅分析。
AI 出現後，系統漏洞變得很明顯；既然攻擊者會用 AI，防守的一方也可以。整個想法很簡單：

```
每台電腦的 agent → 定時回報 → Hub 分析 → AI 判斷風險 → 網頁呈現
```

## 資料夾結構

```text
ai-security-monitor/
├── agent/                 Rust agent：ai-security-monitor 執行檔＋程式庫（桌面版也連結這份程式庫）
│   ├── src/               各命令（cli/）、掃描（scan/、connections/、intel/、firewall/、ports/、vuln/、hardening/、events/、traffic/）、
│   │                      Hub 客戶端（hub/）、動作（actions/）、MCP（mcp/）、AI（ai/）、開機自動啟動（service/）、self-update（update/）
│   ├── prompts/           AI 分析用的提示詞
│   └── tests/fixtures/    測試資料
├── hub/                   Security Hub（Next.js＋Tailwind）：頁面與 API（app/）、元件、資料庫查詢與業務邏輯（lib/）、PostgreSQL migration（drizzle/）、測試
├── desktop/               桌面版 AI Security Monitor（Tauri 2）：Rust 殼（src-tauri/）＋純 HTML／CSS／JS 介面（ui/）
├── contract/              agent ↔ Hub 的 JSON Schema（註冊、報告、快照、遠端動作）
├── feeds/                 隨執行檔內嵌的資料：情資來源清單、已知良好服務、硬化規則（YAML）、漏洞與藍屏說明
├── docker/                Hub 的 Dockerfile 與 compose（單機版、伺服器版、開發用資料庫）
├── scripts/               一行安裝腳本、示範資料、截圖、版本與變更紀錄檢查
├── docs/                  各主題文件與 README 截圖（docs/images）
└── .github/workflows/     CI 與發佈流程
```

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

示範資料：`node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <管理員金鑰>`；截圖：`node scripts/capture-screenshots.mjs --hub http://127.0.0.1:3000 --admin <管理員金鑰>`；桌面版截圖：`node scripts/capture-desktop-screenshots.mjs`（不需要 Hub；加 `--frame windows` 產生套上 Windows 視窗外框的版本）。

## 資料來源與授權

本專案以 MIT 授權。威脅情資、漏洞與地理資料來自各自的提供者並遵守其授權（例如 DShield 為非商用、預設只告警；DB-IP 需標註），
每一筆命中都附來源網址；完整清單見 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。

MIT © 2026 mark.ku（markku636）
