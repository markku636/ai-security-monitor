# 用 Docker 跑 Security Hub

[English](docker.en.md) | 繁體中文

Hub 映像：`ghcr.io/markku636/ai-security-monitor-hub`（linux/amd64、linux/arm64）。舊名 `ghcr.io/markku636/ai-security-agent-hub` 過渡期內照樣發佈同一份映像。

| 標籤 | 內容 |
|---|---|
| `latest`、`<版本>` | Hub＋Claude Code＋Codex CLI（`/ai` 頁在 Hub 上跑 AI 分析用） |
| `slim`、`<版本>-slim` | 只有 Hub（小約 700 MB；`/ai` 頁會提示找不到 CLI） |

資料庫一律 PostgreSQL（compose 內附 `postgres:18-alpine`）。

## 單機版（只給這台電腦用）

```bash
cp .env.example .env                       # 填 AI_SECURITY_MONITOR_HUB_ADMIN_SECRET、AI_SECURITY_MONITOR_HUB_DB_PASSWORD（openssl rand -hex 32）
docker compose -f docker/compose.standalone.yml --env-file .env up -d
# 打開 http://127.0.0.1:8088 → 用管理員金鑰登入 →「新增主機」建立註冊金鑰
ai-security-monitor enroll http://127.0.0.1:8088 --key asa_ek_…
ai-security-monitor service install --yes  # 登入時自動回報
```

只綁 `127.0.0.1`；別台電腦連不到。

## 伺服器版（整個車隊回報）

```bash
cp .env.example .env        # 另外設 AI_SECURITY_MONITOR_HUB_PUBLIC_URL=https://hub.example.com
docker compose -f docker/compose.yml --env-file .env up -d
```

- 預設發佈到 `0.0.0.0:8088`；建議放在反向代理（TLS）後面並設 `AI_SECURITY_MONITOR_HUB_TRUST_PROXY=1`。
  SSE（`/ai` 串流）要關掉代理的回應緩衝（nginx：`proxy_buffering off;`）。
- PostgreSQL 不對外發佈，只在 compose 的網路裡。
- agent 用 `https://hub.example.com/install` 頁產生的一行指令安裝並註冊。

## 設定

完整清單見 [.env.example](../.env.example)。重點：

| 變數 | 說明 |
|---|---|
| `AI_SECURITY_MONITOR_HUB_ADMIN_SECRET` | **必填**。容器裡的 127.0.0.1 不是主機的 loopback，所以 Docker 裡不允許沒金鑰的開放模式（要的話設 `AI_SECURITY_MONITOR_HUB_ALLOW_OPEN_MODE=1`） |
| `AI_SECURITY_MONITOR_HUB_DB_PASSWORD` | **必填**。compose 用它組 `AI_SECURITY_MONITOR_HUB_DATABASE_URL` |
| `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` | 安裝指令與 `/install.sh` 用的對外網址（也是 mDNS 廣播的 `url=`） |
| `AI_SECURITY_MONITOR_HUB_MDNS` | 區網 mDNS 廣播（伺服器版預設開）。**Docker Desktop 與 bridge 網路不會把 multicast 送到區網**：Linux 用 `network_mode: host`，或在區網任一台執行 `ai-security-monitor hub advertise --url <對外網址>`，見 [enrollment.md](enrollment.md#mdns-廣播) |
| `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS` | `0`＝關閉免金鑰加入申請（預設開） |
| `AI_SECURITY_MONITOR_HUB_NAME` | 電腦端看到的 Hub 名稱（預設 Security Hub） |
| `AI_SECURITY_MONITOR_HUB_HOST_PORT`／`AI_SECURITY_MONITOR_HUB_BIND` | 主機 port（8088）與綁定位址 |
| `AI_SECURITY_MONITOR_HUB_IMAGE_TAG` | 映像版本（預設 `latest`；可改 `slim`、`0.5.0`） |
| `AI_SECURITY_MONITOR_HUB_ABUSEIPDB_KEY`／`AI_SECURITY_MONITOR_HUB_IPINFO_TOKEN`／`AI_SECURITY_MONITOR_HUB_PROXYCHECK_KEY`／`AI_SECURITY_MONITOR_HUB_GREYNOISE_KEY` | IP 分析頁「外部威脅情資」的金鑰（選填，也可在「設定與金鑰 → 外部情資來源」設定）；`AI_SECURITY_MONITOR_HUB_IP_LOOKUPS=off` 完全不對外查詢 |
| `AI_SECURITY_MONITOR_HUB_VIRUSTOTAL_KEY`／`AI_SECURITY_MONITOR_HUB_OTX_KEY`／`AI_SECURITY_MONITOR_HUB_HACKERTARGET_KEY` | IP 分析頁「這個 IP 上的網域」的被動 DNS 反查金鑰（選填；HackerTarget 不用金鑰也能查，每天次數少）。只在按「查詢網域」時送出，不算進風險分數 |
| `AI_SECURITY_MONITOR_HUB_METRICS_RAW_DAYS`／`AI_SECURITY_MONITOR_HUB_METRICS_HOURLY_DAYS` | 網路流量／效能資料保留天數：每分鐘的原始樣本（預設 7，1–90）、每小時彙總（預設 90）；見 [metrics.md](metrics.md) |
| `ANTHROPIC_API_KEY`／`CLAUDE_CODE_OAUTH_TOKEN`／`OPENAI_API_KEY` | `/ai` 頁用；沒設時用訂閱登入：在「AI 助手 → AI 帳號」按「登入」（或 `docker compose exec hub claude auth login`），見 [ai-login.md](ai-login.md)；登入資料存在 `/data` volume |

`AI_SECURITY_MONITOR_HUB_ADMIN_SECRET`、`AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS`、`AI_SECURITY_MONITOR_HUB_DATABASE_URL`、`AI_SECURITY_MONITOR_HUB_ACTION_SIGNING_KEY` 也接受 `<名稱>_FILE`（Docker secrets）。

舊的 `ASA_HUB_*` 變數名照樣有效：compose 會先讀 `AI_SECURITY_MONITOR_HUB_*`，沒設才讀 `ASA_HUB_*`，所以只寫舊名的 `.env` 不用改。compose 專案名（`asa-hub`、`asa-hub-standalone`）、volume 與資料庫名稱 `asa_hub` 刻意不改，升級後資料原地沿用。

## 更新

```bash
docker compose -f docker/compose.yml --env-file .env pull
docker compose -f docker/compose.yml --env-file .env up -d
```

Hub 啟動時自動跑資料庫 migration（advisory lock，兩個 Hub 同時啟動也安全）。有新版時管理員頁面會顯示橫幅（`AI_SECURITY_MONITOR_HUB_UPDATE_CHECK=0` 關閉）。

## 備份

資料都在 PostgreSQL 的 volume：

```bash
docker compose -f docker/compose.yml --env-file .env exec -T postgres pg_dump -U asa_hub asa_hub | gzip > asa-hub-$(date +%F).sql.gz
```

## 自己建置

```bash
docker build -f docker/Dockerfile -t ai-security-monitor-hub .                 # 含 AI CLI
docker build -f docker/Dockerfile --build-arg AI_CLIS= -t ai-security-monitor-hub:slim .
```

建置環境是 repo 根目錄（映像要帶 `feeds/` 與 `scripts/install.*`）。容器以 `node` 使用者執行，`/data` 是可寫的 volume，內建 HEALTHCHECK 打 `/api/health`。
