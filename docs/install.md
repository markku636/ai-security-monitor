# 安裝與更新

[English](install.en.md) | 繁體中文

## 一行安裝

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

Hub 的「新增主機」頁（`/install`）會建立一把註冊金鑰，並給出已填好 Hub 網址與金鑰的指令；
`<hub>/install.sh`、`<hub>/install.ps1` 是同一份腳本，只是預設註冊到那個 Hub（腳本公開、不含金鑰）。
註冊金鑰在「設定與金鑰 → 註冊金鑰」列出用了幾台主機、最後使用時間，撤銷後用那把金鑰的主機會被拒絕。

## 更新

```bash
ai-security-monitor self-update --check           # 有沒有新版（ai-security-monitor version --check 也可以）
ai-security-monitor self-update --yes             # 下載、比對 SHA256SUMS、原地替換
ai-security-monitor self-update --to 0.2.0 --yes  # 指定版本（也可退回）
ai-security-monitor service restart --yes         # 讓常駐的 ai-security-monitor watch 換成新版（系統服務加 --system）
```

- 一律比對 `SHA256SUMS`；Release 沒有 `SHA256SUMS` 或雜湊不符就放棄。
- Windows 執行中的 exe 不能覆寫：舊檔改名成 `ai-security-monitor.exe.old-<時間>`，下次更新時清掉。
- 安裝在 `/usr/local/bin` 之類需要 root 的位置時，用 `sudo ai-security-monitor self-update --yes`。
- `AI_SECURITY_MONITOR_UPDATE_URL` 可指向相容 GitHub Releases API 的鏡像（`<網址>/latest`、`<網址>/tags/v<版本>`）。

## 從 asa（0.1.x）升級

0.2.0 起執行檔從 `asa` 改名為 `ai-security-monitor`，不用重新註冊：

- 直接 `asa self-update --yes`（Release 另附 `asa-<版本>-<平台>` 給舊版找），或重跑上面的安裝腳本（會裝成 `ai-security-monitor`，找到舊的 `asa` 會提示）。
- 第一次執行新版時，設定目錄 `…/ai-security-agent` 自動搬到 `…/ai-security-monitor`，`agent_id`、Hub 註冊、金鑰、白名單、基準線都沿用；鑰匙圈的 `asa` 項目會複製到新名。
- 接著執行 `ai-security-monitor service install --yes`（系統服務加 `--system`）：會移除舊的 `asa` 服務／Run 值／unit／plist，換成新名稱。
- `ai-security-monitor mcp install` 會刪掉舊的 `asa` MCP 項目再寫入新的。
