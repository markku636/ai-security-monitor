# 安裝與更新

[English](install.en.md) | 繁體中文

## 一行安裝

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh
```

```powershell
# Windows（PowerShell）
irm https://github.com/markku636/ai-security-agent/releases/latest/download/install.ps1 | iex
```

腳本會：判斷作業系統與 CPU → 下載 `asa-<版本>-<平台>` → **比對 Release 的 `SHA256SUMS`，不符就停止** → 安裝 →（選用）註冊 Hub、設定開機自動啟動。

| 選項（sh）／環境變數 | 說明 |
|---|---|
| `--version` ／ `ASA_VERSION` | 指定版本（預設最新） |
| `--dir` ／ `ASA_INSTALL_DIR` | 安裝位置（Linux／macOS 預設 `/usr/local/bin`，沒權限就 `~/.local/bin`；Windows 預設 `%LOCALAPPDATA%\asa\bin` 並加進使用者 PATH） |
| `--hub URL --key KEY` ／ `ASA_HUB_URL`、`ASA_ENROLL_KEY` | 安裝後註冊到 Security Hub |
| `--service none\|user\|system` ／ `ASA_SERVICE` | 開機自動啟動（見 [service.md](service.md)）；`system` 會直接註冊到系統設定目錄 |
| `ASA_DOWNLOAD_BASE` | 內部鏡像：提供 `asa-<版本>-<平台>` 與 `SHA256SUMS` 的網址 |
| `ASA_NO_MODIFY_PATH=1` | （Windows）不要改 PATH |

例：伺服器安裝並開機就啟動、回報到 Hub：

```bash
curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh -s -- --hub https://hub.example.com --key asa_ek_… --service system
```

平台名稱：`windows-x64.exe`、`windows-arm64.exe`、`macos-arm64`、`macos-x64`、`linux-x64`、`linux-arm64`。

## 更新

```bash
asa self-update --check     # 有沒有新版（asa version --check 也可以）
asa self-update --yes       # 下載、比對 SHA256SUMS、原地替換
asa self-update --to 0.2.0 --yes   # 指定版本（也可退回）
asa service restart --yes   # 讓常駐的 asa watch 換成新版（系統服務加 --system）
```

- 一律比對 `SHA256SUMS`；Release 沒有 `SHA256SUMS` 或雜湊不符就放棄。
- Windows 執行中的 exe 不能覆寫：舊檔改名成 `asa.exe.old-<時間>`，下次更新時清掉。
- 安裝在 `/usr/local/bin` 之類需要 root 的位置時，用 `sudo asa self-update --yes`。
- `ASA_UPDATE_URL` 可指向相容 GitHub Releases API 的鏡像（`<網址>/latest`、`<網址>/tags/v<版本>`）。
