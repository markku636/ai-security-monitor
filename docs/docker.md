# 用 Docker 跑 Security Hub

[English](docker.en.md) | 繁體中文

Hub 映像：`ghcr.io/markku636/ai-security-agent-hub`（linux/amd64、linux/arm64）。

| 標籤 | 內容 |
|---|---|
| `latest`、`<版本>` | Hub＋Claude Code＋Codex CLI（`/ai` 頁在 Hub 上跑 AI 分析用） |
| `slim`、`<版本>-slim` | 只有 Hub（小約 700 MB；`/ai` 頁會提示找不到 CLI） |

資料庫一律 PostgreSQL（compose 內附 `postgres:18-alpine`）。

## 單機版（只給這台電腦用）

```bash
cp .env.example .env        # 填 ASA_HUB_ADMIN_SECRET、ASA_HUB_DB_PASSWORD（openssl rand -hex 32）
docker compose -f docker/compose.standalone.yml --env-file .env up -d
# 打開 http://127.0.0.1:8088 → 用管理員金鑰登入 →「安裝代理程式」建立註冊金鑰
asa enroll http://127.0.0.1:8088 --key asa_ek_…
asa service install --yes   # 登入時自動回報
```

只綁 `127.0.0.1`；別台電腦連不到。

## 伺服器版（整個車隊回報）

```bash
cp .env.example .env        # 另外設 ASA_HUB_PUBLIC_URL=https://hub.example.com
docker compose -f docker/compose.yml --env-file .env up -d
```

- 預設發佈到 `0.0.0.0:8088`；建議放在反向代理（TLS）後面並設 `ASA_HUB_TRUST_PROXY=1`。
  SSE（`/ai` 串流）要關掉代理的回應緩衝（nginx：`proxy_buffering off;`）。
- PostgreSQL 不對外發佈，只在 compose 的網路裡。
- agent 用 `https://hub.example.com/install` 頁產生的一行指令安裝並註冊。

## 設定

完整清單見 [.env.example](../.env.example)。重點：

| 變數 | 說明 |
|---|---|
| `ASA_HUB_ADMIN_SECRET` | **必填**。容器裡的 127.0.0.1 不是主機的 loopback，所以 Docker 裡不允許沒金鑰的開放模式（要的話設 `ASA_HUB_ALLOW_OPEN_MODE=1`） |
| `ASA_HUB_DB_PASSWORD` | **必填**。compose 用它組 `ASA_HUB_DATABASE_URL` |
| `ASA_HUB_PUBLIC_URL` | 安裝指令與 `/install.sh` 用的對外網址 |
| `ASA_HUB_HOST_PORT`／`ASA_HUB_BIND` | 主機 port（8088）與綁定位址 |
| `ASA_HUB_IMAGE_TAG` | 映像版本（預設 `latest`；可改 `slim`、`0.1.0`） |
| `ANTHROPIC_API_KEY`／`CLAUDE_CODE_OAUTH_TOKEN`／`OPENAI_API_KEY` | `/ai` 頁用；也可以 `docker compose exec hub claude` 登入，登入資料存在 `/data` volume |

`ASA_HUB_ADMIN_SECRET`、`ASA_HUB_CLIENT_SECRETS`、`ASA_HUB_DATABASE_URL`、`ASA_HUB_ACTION_SIGNING_KEY` 也接受 `<名稱>_FILE`（Docker secrets）。

## 更新

```bash
docker compose -f docker/compose.yml --env-file .env pull
docker compose -f docker/compose.yml --env-file .env up -d
```

Hub 啟動時自動跑資料庫 migration（advisory lock，兩個 Hub 同時啟動也安全）。有新版時管理員頁面會顯示橫幅（`ASA_HUB_UPDATE_CHECK=0` 關閉）。

## 備份

資料都在 PostgreSQL 的 volume：

```bash
docker compose -f docker/compose.yml --env-file .env exec -T postgres pg_dump -U asa_hub asa_hub | gzip > asa-hub-$(date +%F).sql.gz
```

## 自己建置

```bash
docker build -f docker/Dockerfile -t ai-security-agent-hub .                 # 含 AI CLI
docker build -f docker/Dockerfile --build-arg AI_CLIS= -t ai-security-agent-hub:slim .
```

建置環境是 repo 根目錄（映像要帶 `feeds/` 與 `scripts/install.*`）。容器以 `node` 使用者執行，`/data` 是可寫的 volume，內建 HEALTHCHECK 打 `/api/health`。
