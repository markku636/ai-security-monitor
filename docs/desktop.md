# 桌面版

[English](desktop.en.md) | 繁體中文

`ai-security-monitor` 本身是命令列和背景服務；桌面版 **AI Security Monitor**（`desktop/`，Tauri 2）是給用戶端看的視窗介面，直接呼叫同一份 ai-security-monitor 程式庫。

## 安裝

從 [Releases](https://github.com/markku636/ai-security-monitor/releases/latest) 下載（目前版本 v0.2.1）：

| 平台 | 檔案 | 第一次開啟（安裝檔沒有程式碼簽章） |
|---|---|---|
| Windows 10／11 | `AI-Security-Monitor-<版本>-windows-x64-setup.exe`，雙擊安裝到目前使用者 | 「Windows 已保護您的電腦」→「其他資訊」→「仍要執行」 |
| macOS Apple Silicon／Intel | `…-macos-arm64.dmg`／`…-macos-x64.dmg`，拖到「應用程式」 | 右鍵 →「打開」→「打開」，或 `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"` |
| Linux | `…-linux-x64.AppImage`（`chmod +x` 後執行）或 `…-linux-amd64.deb`（`sudo apt install ./檔名.deb`） | 直接開啟 |

裝好後視窗會開在「總覽」，系統匣（macOS 是選單列）出現 AI Security Monitor 圖示。
`ai-security-monitor-<版本>-windows-x64.exe` 是命令列版，不是桌面版，雙擊只會顯示說明。

## 畫面

截圖用的是示範資料（虛構主機 fin-laptop-07、文件保留網段 IP），由 `node scripts/capture-desktop-screenshots.mjs` 產生：
它用本機靜態伺服器提供 `desktop/ui`，注入假的 Tauri 指令回應，再用無頭 Chrome／Edge 擷取，不讀真實設定、不跑掃描、不呼叫 AI。

| | |
|---|---|
| ![總覽](images/desktop-overview.png) 總覽：分數、問題數、情資新舊、危險與可疑連線 | ![連線](images/desktop-connections.png) 連線：判定、方向篩選、理由與情資來源，右邊是 IP 分析 |
| ![掃描結果](images/desktop-findings.png) 掃描結果：依嚴重度排序，展開看細節與建議 | ![威脅情資](images/desktop-intel.png) 威脅情資：每個來源的筆數、最後更新、是否從 Hub、授權 |
| ![AI 分析](images/desktop-ai.png) AI 分析：工具呼叫與回答即時顯示 | ![設定](images/desktop-settings.png) 設定：agent id、設定目錄、Hub、背景服務 |
| ![深色模式](images/desktop-overview-dark.png) 深色模式：跟著 Windows 的深色設定 | |

## 功能

| 頁面 | 內容 |
|---|---|
| 總覽 | 安全分數（連線／曝露／漏洞／安全設定）、嚴重＋高問題數、情資新舊、是否註冊 Hub、危險與可疑連線；「立即掃描」「更新情資」「開啟 Security Hub」 |
| 連線 | 目前所有連線，依判定、方向篩選與搜尋，同一程式連到同一遠端合併成一列；理由分「情資」（可點開原始清單）與「行為」（ai-security-monitor 自己的判斷）；可每 10 秒自動更新 |
| IP 分析 | 點連線上的 IP：國家／ASN、哪些情資來源列名、本機哪些程式連它、VirusTotal／AbuseIPDB 連結、「請 AI 分析這個 IP」 |
| 掃描結果 | 最新報告的問題，依嚴重度排序、展開看細節與建議 |
| 威脅情資 | 每個來源的筆數、最後更新、是否從 Hub 下載；更新過期的或全部重抓 |
| AI 分析 | 用本機已登入的 Claude Code 或 Codex CLI（你的訂閱）分析可疑連線、最新報告或自由提問；即時顯示回答與工具呼叫 |
| 設定 | agent id、設定目錄、Hub 網址、背景服務狀態 |

關閉視窗只會縮到系統匣；系統匣選單有「開啟主視窗」「開啟 Security Hub」「結束」。同時只會開一個實例。

## 從「AI Security Agent」桌面版升級

0.2.0 起桌面版改名 **AI Security Monitor**，應用程式識別碼也從 `dev.asa.desktop` 改成 `dev.ai-security-monitor.desktop`，
所以新版安裝檔會裝成另一個應用程式，**不會**覆蓋或移除舊版：

1. 先結束舊版（系統匣圖示 → 結束）。
2. 設定 → 應用程式 → 已安裝的應用程式 → 「AI Security Agent」→ 解除安裝（舊版的開始功能表捷徑一併移除）。
3. 安裝新版 `AI-Security-Monitor-<版本>-windows-x64-setup.exe`。
4. （選用）刪除舊版留下的 WebView 快取 `%LOCALAPPDATA%\dev.asa.desktop`；新版用 `%LOCALAPPDATA%\dev.ai-security-monitor.desktop`。

掃描報告、情資、Hub 註冊與金鑰都放在 agent 的設定目錄，不在上面的資料夾：命令列第一次執行 0.2.0 時會把 `%APPDATA%\ai-security-agent`
搬到 `%APPDATA%\ai-security-monitor`，新版桌面版直接沿用，不用重新註冊。

## 和命令列、背景服務的關係

- 共用同一個設定目錄（`%APPDATA%\ai-security-monitor` 等），所以看得到背景 `ai-security-monitor watch` 的最新報告、情資與 Hub 註冊。
- 連線頁是唯讀快照：**不寫入**連線歷史，避免頻繁重新整理干擾背景服務的週期性連線（beacon）判斷。
- AI 分析掛的是 ai-security-monitor 的唯讀 MCP 工具；MCP server 就是桌面版執行檔本身——帶命令列參數啟動時（例如 `ai-security-monitor-desktop.exe mcp --tools …`）它會當 ai-security-monitor CLI 執行。
- 桌面版不需要系統管理員；部分檢查（Security 事件記錄、minidump）需要系統管理員才讀得到，會在報告裡標示。

## 建置

```bash
cd desktop
npm ci                 # 只有 @tauri-apps/cli
npm run icon           # （選用）由 src-tauri/icons/source.png（專案 logo）重新產生各尺寸圖示
npx tauri build        # Windows：src-tauri/target/release/bundle/nsis/*-setup.exe
```

介面在 `desktop/ui/`，是純 HTML／CSS／JS，沒有前端建置步驟。安裝檔是目前使用者層（不需要系統管理員）。
