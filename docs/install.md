# 安裝與更新

[English](install.en.md) | 繁體中文

## 下載哪一個？

目前版本 **v0.5.0**，檔案都在 [Releases](https://github.com/markku636/ai-security-monitor/releases/latest)。

| 你的情況 | 下載 |
|---|---|
| 一般使用者，要視窗介面 | 桌面版：`AI-Security-Monitor-<版本>-windows-x64-setup.exe`、`…-macos-arm64.dmg`（Apple Silicon）、`…-macos-x64.dmg`（Intel）、`…-linux-x64.AppImage`、`…-linux-amd64.deb`，安裝步驟見下方「桌面版」 |
| 伺服器（含 Windows Server／Server Core）、自動化 | 命令列版：用下方「一行安裝」；或直接下載 `ai-security-monitor-<版本>-<平台>`（命令列工具，在終端機執行，雙擊只會顯示說明） |
| 集中看多台主機 | Security Hub（Docker），見 [docker.md](docker.md) |
| `asa-<版本>-*` | 給 0.1.x 的 `asa self-update` 用，請忽略 |
| `SHA256SUMS` | 所有檔案的 SHA256 |

系統需求與每條路線的完整步驟（含怎麼確認裝好了）見 [README「安裝」](../README.md#安裝)。

## 桌面版

安裝檔沒有程式碼簽章，第一次開啟會有警告：

| 平台 | 安裝 | 第一次開啟 |
|---|---|---|
| Windows 10／11 | 雙擊 `AI-Security-Monitor-<版本>-windows-x64-setup.exe`（裝到目前使用者，不需系統管理員） | 「Windows 已保護您的電腦」→「其他資訊」→「仍要執行」 |
| macOS | 建議：`curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh -s -- --desktop`（不會被擋）；或打開 `.dmg`，把 AI Security Monitor 拖到「應用程式」 | 手動安裝的：「系統設定 → 隱私權與安全性」按「強制打開」（macOS 14 以前可右鍵 →「打開」）；顯示已損毀時 `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"` |
| Linux | AppImage：`chmod +x` 後執行；deb：`sudo apt install ./AI-Security-Monitor-<版本>-linux-amd64.deb` | 直接開啟 |

裝過舊的「AI Security Agent」桌面版（0.1.x）要先解除安裝，新版不會覆蓋它（見 [desktop.md](desktop.md)）。

## 一行安裝（命令列版）

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

```powershell
# Windows（PowerShell）
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

腳本會：判斷作業系統與 CPU → 下載 `ai-security-monitor-<版本>-<平台>` → **比對 Release 的 `SHA256SUMS`，不符就停止** → 安裝 →（選用）註冊 Hub、設定開機自動啟動。

| 選項（sh）／環境變數 | 說明 |
|---|---|
| `--version` ／ `AI_SECURITY_MONITOR_VERSION` | 指定版本（預設最新） |
| `--dir` ／ `AI_SECURITY_MONITOR_INSTALL_DIR` | 安裝位置（Linux／macOS 預設 `/usr/local/bin`，沒權限就 `~/.local/bin`；Windows 預設 `%LOCALAPPDATA%\ai-security-monitor\bin` 並加進使用者 PATH，系統服務改裝到 `%ProgramFiles%\ai-security-monitor`、需系統管理員 PowerShell） |
| `--hub URL --key KEY` ／ `AI_SECURITY_MONITOR_HUB_URL`、`AI_SECURITY_MONITOR_ENROLL_KEY` | 安裝後註冊到 Security Hub |
| `--service none\|user\|system` ／ `AI_SECURITY_MONITOR_SERVICE` | 開機自動啟動（見 [service.md](service.md)）；`system` 會直接註冊到系統設定目錄 |
| `AI_SECURITY_MONITOR_DOWNLOAD_BASE` | 內部鏡像：提供 `ai-security-monitor-<版本>-<平台>` 與 `SHA256SUMS` 的網址 |
| `AI_SECURITY_MONITOR_NO_MODIFY_PATH=1` | （Windows）不要改 PATH |

舊的 `ASA_*` 環境變數（`ASA_VERSION`、`ASA_HUB_URL`…）照樣有效，兩個都設時新名優先。
Windows Server 2016／2019／2022／2025（含 Server Core）用同一個 `windows-x64.exe`，安裝方式相同。

例：伺服器安裝並開機就啟動、回報到 Hub：

```bash
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh -s -- --hub https://hub.example.com --key asa_ek_… --service system
```

平台名稱：`windows-x64.exe`、`windows-arm64.exe`、`macos-arm64`、`macos-x64`、`linux-x64`、`linux-arm64`。

## 從 Security Hub 安裝

**免金鑰（建議）**：Hub「新增主機」頁的「免金鑰安裝指令」已預填這個 Hub 的網址，在電腦上執行後會送出加入申請，管理員在同一頁按「核准」即可
（也可以設定自動核准的網段）。電腦也能自己找到 Hub（公司 DNS 的 SRV 紀錄、區網廣播）：`ai-security-monitor enroll --auto`，桌面版第一次開啟就會帶你做。
詳見 [自動尋找 Hub、免金鑰加入](enrollment.md)。

```powershell
$env:AI_SECURITY_MONITOR_SERVICE='user'; irm https://hub.example.com/install.ps1 | iex      # Windows（伺服器用 'system'＋系統管理員 PowerShell）
```

```bash
curl -fsSL https://hub.example.com/install.sh | sh -s -- --service user                     # Linux／macOS（伺服器用 --service system）
```

**用註冊金鑰**：

Hub 的「新增主機」頁（`/install`）會建立一把註冊金鑰，並給出已填好 Hub 網址與金鑰的指令；
`<hub>/install.sh`、`<hub>/install.ps1` 是同一份腳本，只是預設註冊到那個 Hub（腳本公開、不含金鑰）。
註冊金鑰在「設定與金鑰 → 註冊金鑰」列出用了幾台主機、最後使用時間，撤銷後用那把金鑰的主機會被拒絕。

## 更新

### 自動更新（`update.mode`）

每台電腦一個設定，桌面版和命令列版共用（存在設定目錄的 `config.json`）：

| 設定 | 說明 |
|---|---|
| `off` | 不檢查。 |
| `notify`（預設） | 每天查一次 GitHub Releases（服務啟動後 2～20 分鐘第一次，之後每 24 小時再加 0～3 小時隨機）；有新版就記下來（`ai-security-monitor status` 看得到）、放進心跳讓 Hub 的主機清單顯示「有新版」，桌面版跳出提示。**不會自己安裝。** |
| `auto` | 同上，而且背景服務（`watch --service`）會自己下載、比對 `SHA256SUMS`、原地替換，再重新啟動成新版；桌面版則先下載好，結束或重新開啟時安裝。 |

```bash
ai-security-monitor config set update.mode auto   # 或 off／notify
```

- **誰負責更新**：桌面版和它的「背景自動回報」是同一個執行檔，由**桌面版的更新器**負責（安裝檔有 minisign 簽章，App 內建公鑰驗過才裝）；桌面版帶的 agent 不會自我更新，`self-update` 也會拒絕（不然會把桌面版換成命令列版）。另外裝的命令列版由它自己的 `update.mode`／`self-update` 負責。
- **不自動安裝的情況**：開發版（從原始碼建置、`cargo run`）、套件管理員裝的（`/usr/bin`、Homebrew、Scoop、winget、Chocolatey、Nix、Snap）——只通知，請用套件管理員更新；手動 `self-update` 要加 `--force` 才會替換。
- **重新啟動**：Windows 服務以失敗結束碼結束，由服務的「失敗時重新啟動」1 分鐘後拉起；systemd（`Restart=on-failure`）、launchd（`KeepAlive`）同理；登入時啟動的（Windows `HKCU\…\Run`、XDG autostart）先啟動新版再結束自己。
- 前景執行的 `watch`（不是服務）、`watch --once` 不會自動安裝，只記錄有新版。

### 手動更新

```bash
ai-security-monitor version --check               # 有沒有新版（ai-security-monitor self-update --check 也可以）
ai-security-monitor self-update --yes             # 下載、比對 SHA256SUMS、原地替換，並重新啟動用這個執行檔的背景服務
ai-security-monitor self-update --to 0.2.0 --yes  # 指定版本（也可退回）
ai-security-monitor self-update --yes --no-restart  # 只替換，不重新啟動背景服務
```

桌面版：「設定 → 背景自動回報與自動更新」按「檢查更新」看目前與最新版本、「立即更新」馬上更新（裝完自動重新開啟，背景自動回報一起換成新版）。另外裝的命令列版背景服務也會列在那裡，有新版時可以按「更新命令列版」。

- 系統服務（`--system`）要用系統管理員執行 `self-update`，或更新後執行 `ai-security-monitor service restart --system --yes`。
- 一律比對 `SHA256SUMS`；Release 沒有 `SHA256SUMS` 或雜湊不符就放棄。
- Windows 執行中的 exe 不能覆寫：舊檔改名成 `ai-security-monitor.exe.old-<時間>`，下次更新時清掉。
- 安裝在 `/usr/local/bin` 之類需要 root 的位置時，用 `sudo ai-security-monitor self-update --yes`。
- `AI_SECURITY_MONITOR_UPDATE_URL` 可指向相容 GitHub Releases API 的鏡像（`<網址>/latest`、`<網址>/tags/v<版本>`）。

## 從 asa（0.1.x）升級

0.2.0 起執行檔從 `asa` 改名為 `ai-security-monitor`，不用重新註冊：

- 直接 `asa self-update --yes`（Release 另附 `asa-<版本>-<平台>` 給舊版找），或重跑上面的安裝腳本（會裝成 `ai-security-monitor`，找到舊的 `asa` 會提示）。
- 第一次執行新版時，設定目錄 `…/ai-security-agent` 自動搬到 `…/ai-security-monitor`，`agent_id`、Hub 註冊、金鑰、白名單、基準線都沿用；鑰匙圈的 `asa` 項目會複製到新名。
  舊版 `asa` 的常駐 watch 還在跑（`watch.lock` 被占用）時先不搬，這次直接用舊目錄並提示一行；下一步的 `service install` 結束舊版後才搬。0.2.0 在這種情況留下的過期副本（`agent_id` 相同、比舊目錄舊），會在下次搬移時改名成 `ai-security-monitor.bak-<時間>` 保留，再重新從舊目錄搬一次。
- 接著執行 `ai-security-monitor service install --yes`（系統服務加 `--system`）：會移除舊的 `asa` 服務／Run 值／unit／plist，換成新名稱。
- `ai-security-monitor mcp install` 會刪掉舊的 `asa` MCP 項目再寫入新的。
