# AI 登入與登出（Claude Code／Codex）

[English](ai-login.en.md) | 繁體中文

Hub 的「AI 助手」與桌面版的「AI 分析」都是叫用 **Claude Code** 或 **Codex** 這兩個官方程式來分析，要先登入其中一個。
登入的是「跑那個程式的電腦」：Hub 在 Docker 裡就是 Hub 容器裡的程式；桌面版就是你這台電腦上的程式。

## Hub（網頁上登入）

打開 Hub 的「AI 助手」，最上面的「AI 帳號」卡會顯示每個程式：未安裝／未登入／已登入（帳號 email、Claude 訂閱方案或 ChatGPT 帳號）。

### Claude Code

1. 按「登入」。Hub 會啟動官方的 `claude auth login`，並顯示「開啟 Claude 授權頁面」的連結。
2. 點連結，用你的 Claude（Pro／Max）帳號登入並按「授權」。
3. 授權後頁面會顯示一組代碼，複製後貼回 Hub 的欄位，按「完成登入」。
4. 卡片顯示「已登入」就可以用了。整個流程 15 分鐘內要完成，逾時就重新按「登入」。

### Codex

1. 按「登入」。Hub 會啟動官方的 `codex login --device-auth`，並顯示一個網址和一組一次性代碼（15 分鐘內有效）。
2. 在任何裝置（手機也可以）打開那個網址，用你的 ChatGPT 帳號登入，輸入代碼。
3. Hub 每 3 秒確認一次，完成後自動顯示「已登入」。

第一次用 Codex 的裝置碼登入，要先在 ChatGPT 的「設定 → 安全性」開啟「裝置碼登入」（工作區帳號由工作區管理員開啟），否則會看到「還沒開啟裝置碼登入」。
只輸入你自己在 Hub 上開始的代碼；別人給你的代碼不要輸入。

### 登出

按「登出」：Hub 執行 `claude auth logout`／`codex logout`，刪掉 Hub 上該程式存的登入資料。AI 助手要再登入才能用。
**不影響**你自己電腦上的 Claude Code／Codex。

### 網頁按鈕不能用時（手動指令）

在跑 Hub 的主機上執行（伺服器版把 `compose.standalone.yml` 換成 `compose.yml`）：

```bash
docker compose -f docker/compose.standalone.yml --env-file .env exec hub claude auth login     # 照畫面開網址、貼回代碼
docker compose -f docker/compose.standalone.yml --env-file .env exec hub claude auth logout
docker compose -f docker/compose.standalone.yml --env-file .env exec hub codex login --device-auth
docker compose -f docker/compose.standalone.yml --env-file .env exec hub codex logout
```

也可以進互動模式：`docker compose … exec hub claude`，輸入 `/login` 或 `/logout`，完成後 `/exit`。

## 桌面版

「AI 分析」頁下方的「AI 帳號」：

- **登入**：開一個終端機視窗執行 `claude auth login`（或 `codex login`），接著會打開瀏覽器，登入並授權就完成；回到桌面版會自動顯示「已登入」。
- **登出**：執行 `claude auth logout`／`codex logout`。**桌面版用的就是你平常用的 Claude Code／Codex**，登出後你在終端機或編輯器裡用它也要重新登入（按登出前會再提醒一次）。

## 環境變數會蓋過登入

這些環境變數有設時，程式會優先用它們，網頁上的登入／登出管不到（「AI 帳號」卡會標出來）：

| 程式 | 環境變數 |
|---|---|
| Claude Code | `ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`CLAUDE_CODE_OAUTH_TOKEN` |
| Codex | `OPENAI_API_KEY`、`CODEX_API_KEY` |

要改用訂閱登入，就把 Hub（`.env`、compose）裡的這些變數拿掉再重啟。

## 安全與使用條款

- Hub **不讀取、不保存任何 token**：Claude 的授權碼只是直接交給官方的 `claude` 程式；Codex 的代碼是在 OpenAI 網站輸入。登入資料由程式自己存在 Hub 的資料目錄（容器的 `/data/claude`、`/data/codex`）。
- 授權碼不會寫進 log 或稽核紀錄；稽核只記「誰、哪個程式、登入／登出、成功或失敗」（`ai_account.*`）。
- 訂閱帳號（Claude Pro／Max、ChatGPT）只給**你自己**用。多人共用、或把 Hub 當服務提供給別人時，請改用 API key（`ANTHROPIC_API_KEY`／`OPENAI_API_KEY`），依用量計費，也符合兩家的使用條款。
