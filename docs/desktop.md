# 桌面版

[English](desktop.en.md) | 繁體中文

`asa` 本身是命令列和背景服務；桌面版（`desktop/`，Tauri 2）是給用戶端看的視窗介面，直接呼叫同一份 asa 程式庫。

## 功能

| 頁面 | 內容 |
|---|---|
| 總覽 | 安全分數（連線／曝露／漏洞／安全設定）、嚴重＋高問題數、情資新舊、是否註冊 Hub、危險與可疑連線；「立即掃描」「更新情資」「開啟 Security Hub」 |
| 連線 | 目前所有連線，依判定、方向篩選與搜尋，同一程式連到同一遠端合併成一列；理由分「情資」（可點開原始清單）與「行為」（asa 自己的判斷）；可每 10 秒自動更新 |
| IP 分析 | 點連線上的 IP：國家／ASN、哪些情資來源列名、本機哪些程式連它、VirusTotal／AbuseIPDB 連結、「請 AI 分析這個 IP」 |
| 掃描結果 | 最新報告的問題，依嚴重度排序、展開看細節與建議 |
| 威脅情資 | 每個來源的筆數、最後更新、是否從 Hub 下載；更新過期的或全部重抓 |
| AI 分析 | 用本機已登入的 Claude Code 或 Codex CLI（你的訂閱）分析可疑連線、最新報告或自由提問；即時顯示回答與工具呼叫 |
| 設定 | agent id、設定目錄、Hub 網址、背景服務狀態 |

關閉視窗只會縮到系統匣；系統匣選單有「開啟主視窗」「開啟 Security Hub」「結束」。同時只會開一個實例。

## 和命令列、背景服務的關係

- 共用同一個設定目錄（`%APPDATA%\ai-security-agent` 等），所以看得到背景 `asa watch` 的最新報告、情資與 Hub 註冊。
- 連線頁是唯讀快照：**不寫入**連線歷史，避免頻繁重新整理干擾背景服務的週期性連線（beacon）判斷。
- AI 分析掛的是 asa 的唯讀 MCP 工具；MCP server 就是桌面版執行檔本身——帶命令列參數啟動時（例如 `asa-desktop.exe mcp --tools …`）它會當 asa CLI 執行。
- 桌面版不需要系統管理員；部分檢查（Security 事件記錄、minidump）需要系統管理員才讀得到，會在報告裡標示。

## 建置

```bash
cd desktop
npm ci                 # 只有 @tauri-apps/cli
npm run icon           # （選用）重新產生圖示
npx tauri build        # Windows：src-tauri/target/release/bundle/nsis/*-setup.exe
```

介面在 `desktop/ui/`，是純 HTML／CSS／JS，沒有前端建置步驟。安裝檔是目前使用者層（不需要系統管理員）。
