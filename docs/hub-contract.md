# Agent ↔ Hub 契約

[English](hub-contract.en.md) | 繁體中文

`ai-security-monitor`（agent）與 Security Hub 之間的 HTTP 介面。格式的唯一真源是 `agent/src/hub/contract.rs` 與 `agent/src/model/*`；
`contract/*.v1.json` 由 Rust 測試產生，Hub 的 zod schema（`hub/lib/ingest/schema.ts`）在 vitest 裡驗證同一份檔案，任一邊漂移 CI 就擋。

有意改格式時：

```bash
cd agent && ASA_UPDATE_CONTRACT=1 cargo test contract   # 重新產生 contract/*.v1.json
# 再同步 hub/lib/ingest/schema.ts，跑 cd hub && npm test
```

## 共同規則

| 項目 | 規則 |
|---|---|
| 認證 | `Authorization: Bearer <client 金鑰>`（`AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS` 其中一把；之後的 enroll key 等同） |
| 識別 | `X-ASA-Agent-Id`（必須等於內容裡的 agent id，否則 400 `agent_id_mismatch`）、`X-ASA-Agent-Version` |
| 相容 | 標頭 `X-ASA-*`、token 前綴 `asa_`／`asa_ek_` 改名後刻意不改，0.1.x 的 agent 與新 Hub 互通；Hub 環境變數 `AI_SECURITY_MONITOR_HUB_*` 也接受舊名 `ASA_HUB_*` |
| 身分釘選 | `X-ASA-Agent-Token`：enroll 時產生的隨機 token。hub 第一次看到時記下 sha256，之後不符就 403 `agent_token_mismatch`（client 金鑰是多台共用的，這樣才擋得住冒名）。取消註冊不會刪掉 token |
| 壓縮 | 內容 > 16 KB 時 `Content-Encoding: gzip`；壓縮後 ≤ 4 MB、解壓後 ≤ 24 MB（超過 413） |
| 結構上限 | 深度、節點數、字串長度、陣列長度、key 數；禁止 `__proto__`／`constructor`／`prototype` → 400 並只回規則名 |
| 傳輸 | https；http 只允許 loopback 與私網位址（`ai-security-monitor enroll --insecure-http` 才放行其他） |

錯誤處理（agent 端）：

| 狀態 | 意義 | agent 動作 |
|---|---|---|
| 401／403 | 金鑰被拒 | 停止上傳，請重新 `ai-security-monitor enroll` |
| 400／413／422 | 內容被拒（重送也不會過） | 丟棄，不放進 outbox |
| 429 | 太頻繁（`Retry-After`） | 報告放進 outbox，下一輪再送 |
| 5xx／連不上 | hub 暫時不可用 | 報告放進 outbox（最多保留 50 份，丟最舊） |

## 端點

### `POST /api/v1/agents/register`

內容：`contract/register.v1.json`（`agent` 身分、`accept_remote_actions`、`service_mode`）。
回應：`{ agent_id, created, hub: { name, version, min_report_interval_s, snapshot_interval_s, max_report_bytes, server_time } }`。
`ai-security-monitor enroll` 會先打 `/api/health`，註冊成功才把金鑰存進系統金鑰圈（或 0600 檔案）並寫入設定。

### `POST /api/v1/ingest/report`

內容：`contract/report.v1.json`（完整掃描報告）。
- `report_id` 冪等：收過的報告直接回 `duplicate: true`，**不受限流影響**（outbox 重送才不會卡住）。
- 限流依報告的 `finished_at`：同一 agent 兩份報告的完成時間要相隔 ≥ `AI_SECURITY_MONITOR_HUB_INGEST_MIN_INTERVAL_MS`（預設 60 秒）。
  agent 斷線期間暫存的報告彼此相隔一個掃描週期，恢復後可一次補送；另有每 agent 每分鐘 30 份的硬上限。
- 回應：`{ ok, report_id, duplicate, findings: { new, updated, unchanged, reopened, resolved }, min_interval_ms, server_time }`。

### `POST /api/v1/ingest/snapshot`

內容：`contract/snapshot.v1.json`（目前連線與 listener，每條連線帶方向與判定）。整批替換該 agent 的最新連線，並彙總目的地（保留最嚴重的判定）。選用欄位 `dns_names`（公網遠端 IP → 這台電腦解析過的網域，每個 IP 最多 20 個；只收快照裡真的有連線的 IP）存進 `ip_domains`，IP 分析頁「這個 IP 上的網域」用。
最短間隔 `AI_SECURITY_MONITOR_HUB_SNAPSHOT_MIN_INTERVAL_MS`（預設 10 秒）。未註冊的 agent 回 409。

### `POST /api/v1/ingest/metrics`

內容：`contract/metrics.v1.json` `{ agent_id, performance, samples: [{ ts, interval_s, net: { rx_bytes, tx_bytes, interfaces[], processes?, process_source? }, perf? }] }`，一批 1–240 個樣本、壓縮後 ≤ 1 MB。`performance` 是這台有沒有開啟效能蒐集（Hub 無法從遠端開）；`perf` 只有開啟時才有。
- (agent, `ts`) 唯一：重送（agent 的離線佇列）不重複計算；未來時間夾到現在；比 `AI_SECURITY_MONITOR_HUB_METRICS_RAW_DAYS`（預設 7 天）舊的樣本略過。
- 限流依這批最新樣本的時間（最短間隔同快照），補送的舊批次不會被擋。未註冊的 agent 回 409。
- 回應：`{ ok, stored, duplicate, stale, performance, server_time }`。舊版 Hub 沒有這個端點（404）時，agent 保留樣本、30 分鐘後再試。
- 細節與保留期限見 [metrics.md](metrics.md)。

### `POST /api/v1/ingest/dns`

內容：`contract/dns.v1.json` `{ agent_id, records: [{ ts, name, registrable?, qtype, rcode, process?, exe?, pid?, count, answers[], cnames[], source }] }`，一批 1–1000 列、壓縮後 ≤ 2 MB。每列是背景 DNS 蒐集每分鐘依（網域, 類型, 結果, 程式）聚合的結果；只有 `dns.upload = all` 的主機會送。
- (agent, `ts`, `name`, `qtype`, `rcode`, `process`, `source`) 唯一：重送以新值覆蓋、不重複計算；比 `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS`（預設 7 天）舊的列略過；每小時彙總保留 `AI_SECURITY_MONITOR_HUB_DNS_HOURLY_DAYS`（預設 90 天）。
- `registrable` 是 agent 依 Public Suffix List 算的可註冊網域（沒有時 Hub 取最後兩段）。
- 回應：`{ ok, stored, stale, domains, server_time }`。舊版 Hub 沒有這個端點（404）時，agent 保留紀錄、30 分鐘後再試。

### `POST /api/v1/agents/me/heartbeat`

內容：`{ agent_id, ts, version, uptime_s?, last_scan_at?, elevated, intel_checked_at?, intel_feeds?, update?, advertising? }`。未知 agent 回 404。

- `update`（0.4.0 起）：`{ mode: "off"|"notify"|"auto", owner: "agent"|"desktop", latest?, available, checked_at?, note? }`——自動更新設定、
  誰負責安裝（桌面版內建的 agent 是 `desktop`）、查到的最新版；Hub 存在 `agents.update_info`，主機清單顯示「有新版」。
- `advertising`（0.4.0 起）：`{ url, state: "advertising"|"hub_unreachable"|"starting"|"error", fingerprint?, error?, since? }`——這台的背景服務
  在幫哪個 Hub 做區網廣播（`hub.advertise_url`）；Hub 存在 `agents.advertising`，「新增主機」頁用最近 15 分鐘、指紋相同的列判斷有沒有電腦在廣播。
- 兩者都沒送（舊版 agent、`upload` 的心跳）時保留上一次的值。

### 遠端動作

管理員在 Hub 核准動作（目前：`block_ip`、`unblock_ip`、`close_port`；`close_port` 屬破壞性，核准時要輸入主機名稱）後：

1. agent 註冊時若 `accept_remote_actions: true` 且身分已釘選，回應裡有 `action_key`＝HMAC-SHA256(hub 簽署金鑰, `asa-action-key|<agent_id>`)，存進系統金鑰圈。
2. 心跳回應的 `pending_actions` > 0 時，agent 呼叫 `GET /api/v1/agents/me/actions` 取得 `{action_id, agent_id, kind, params, expires_at, token}`。
3. agent 驗證：`token`＝HMAC-SHA256(action_key, canonical JSON of {action_id, agent_id, kind, params, expires_at})（key 排序、無空白，見 `contract/action.v1.json`）、agent id 相符、未過期（核准後 24 小時）、本機設定允許該種類（預設只有 block_ip／unblock_ip；破壞性要 `allow_destructive`）、目標不在本機白名單或已知良好清單、不含本機介面位址。
4. 背景執行不會跳 UAC／sudo：沒有系統管理員權限就回報失敗。執行結果 `POST /api/v1/agents/me/actions/{id}/result`（`{agent_id, ok, output}`）。派送後 10 分鐘沒回報會重派，agent 以 action id 去重、直接回報上次結果。

簽署金鑰：`AI_SECURITY_MONITOR_HUB_ACTION_SIGNING_KEY`（或 `_FILE`）；沒設就第一次用到時隨機產生並存進資料庫。換金鑰後 agent 要重新註冊才拿得到新的 `action_key`。

### 免金鑰加入

電腦不用註冊金鑰也能加入：送出加入申請，管理員在 Hub 核准（或來源 IP 在自動核准網段內）後，拿到一把綁定自己 agent id 的註冊金鑰。
操作方式見 [enrollment.md](enrollment.md)。二進位值一律 base64url（無補位）；指紋與核對碼用 RFC 4648 base32。

- **Hub 身分**：`GET /api/v1/hub/identity[?nonce=<16–128 字元 [A-Za-z0-9_-]>]`（公開）。回應 `contract/hub-identity.v1.json`
  `{ name, version, edition, algorithm: "ed25519", public_key, fingerprint, enrollment: { keyless, mode }, nonce?, signature? }`（`mode`：`auto`｜`review`，0.5 起）。
  `fingerprint`＝SHA-256(公鑰 32 bytes) 的 base32 前 20 字、每 4 字一組（`72AS-YEXT-VNGO-NLC5-W2NM`）；
  `signature`＝Ed25519 簽 `asa-hub-identity|v1|<nonce>|<fingerprint>`。金鑰第一次用到時產生，存在 `settings.hub_identity`。每 IP 每分鐘 120 次。
- **送出申請**：`POST /api/v1/agents/enroll-request`（不帶 Authorization）。內容 `contract/enroll-request.v1.json`
  `{ agent, accept_remote_actions, request_secret（43–128 字元）, hub_fingerprint? }`。回應 201（同一台、同一個密語重送回 200）：
  `{ request_id, status, auto_approved, request_code, poll_interval_s, expires_at, hub: { name, version, fingerprint } }`。
  `request_code`＝SHA-256(`asa-enroll-code|<request_secret>`) 的 base32 前 8 字（`XXXX-XXXX`），agent 自己也算得出來。
  錯誤：403 `enroll_requests_disabled`（`AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS=0`）、409 `hub_fingerprint_mismatch` `{fingerprint}`、
  429 `too_many_requests`（每 IP 每 10 分鐘 120 個）、503 `too_many_pending`（待核准 500 個）、400 `bad_request` `{rule}`。
  密語只存 SHA-256。自動核准只看 TCP 對端位址（Hub 的 HTTP 伺服器掛勾取得）；開了 `AI_SECURITY_MONITOR_HUB_TRUST_PROXY` 才看 X-Forwarded-For；
  已存在但從沒釘選過 token 的 agent 一律不自動核准。
- **輪詢**：`GET /api/v1/agents/enroll-request/{id}`，`Authorization: Bearer <request_secret>`。回應 `contract/enroll-status.v1.json`
  `{ request_id, status: pending|approved|rejected|expired, request_code, poll_interval_s, expires_at, reason?, credentials? }`。
  不存在與密語錯誤一律 404（常數時間比對）；同一 IP 10 分鐘錯 30 次 → 429。
  `credentials`＝`{ agent_id, client_key, hub_fingerprint, signature }`，只在已核准、金鑰沒被撤銷、還沒被領取（或領取後 10 分鐘內）時給；
  `signature`＝Ed25519 簽 `asa-enroll-approved|v1|<request_id>|<agent_id>|<sha256hex(client_key)>`，agent 用送申請前釘選的公鑰驗。
  `client_key` 是 `asa_ek_…` 註冊金鑰（由 Hub 的密鑰衍生、不存明文），**綁定那台的 agent id**：拿去用別的 agent id 在任何 agent 端點都回 403 `key_bound_to_other_agent`。
- 之後 agent 照一般金鑰流程 `POST /api/v1/agents/register`（`X-ASA-Agent-Token` 釘選不變）；第一次註冊成功就標記為已領取。
  待核准 7 天過期；核准後一直沒領取也會過期（金鑰一併撤銷）。
- **管理**（session＋CSRF，或管理員 Bearer）：`GET /api/v1/admin/enroll-requests?status=pending|all`（不回密語與金鑰）、
  `POST /api/v1/admin/enroll-requests/decide` `{ ids[1..200], decision: approve|reject, reason? }`、
  `GET|PUT /api/v1/admin/enroll-settings` `{ join_mode?: "auto"|"review", auto_approve_cidrs?[≤64] }`（兩欄可單獨送；`join_mode` 被環境變數鎖定時回 409 `locked_by_env`；GET 另回 `join_mode_source: env|settings|default`）（IPv4 前綴至少 /8、IPv6 至少 /16；GET 另外回 mDNS 狀態與要加的 SRV／TXT 紀錄，名稱 `_aisecmon._tcp.<網域>`）。
  稽核：`enroll_request.created|approved|rejected|auto_approved|auto_capped`、`enroll_settings.updated`（`target_id`＝`enroll_join_mode`／`enroll_auto_approve_cidrs`）。自動核准的 `decided_by`：`auto:all`（自動允許模式）或 `auto:<網段>`。
- **agent 端**：Hub 指紋釘選在 `config.json`（`hub.fingerprint`、`hub.public_key`）。`watch` 啟動時查 `/api/v1/hub/identity`，不符就停止上傳；
  等候中的申請存在 `<設定目錄>/hub-enroll-request.json`（密語在系統金鑰圈／密鑰檔），`watch` 會接著輪詢。

## `ai-security-monitor watch` 流程

1. 讀設定與金鑰 → `register`（每次啟動都更新身分與版本）。
2. 每 `snapshot_interval`（預設 1 分鐘）：拍連線快照（含情資判定）→ `ingest/snapshot`，接著 `heartbeat`；有待執行的遠端動作就領取、驗章、執行並回報。
   每 `metrics.interval`（預設 1 分鐘）：取一個流量（＋效能）樣本 → 排進 `metrics/queue.jsonl` → `ingest/metrics`（每輪最多 3 批、每批 120 個）。
3. 每 `interval`（預設 10 分鐘）：先送 outbox 裡的舊報告（遇到可重試錯誤就停）→ 掃描 → `ingest/report`；失敗就放進 outbox。
4. 最新報告存在 `<config>/reports/latest.json`，`ai-security-monitor status` 顯示 hub 狀態、待重送數與最後一次掃描。
5. 自動更新（`update.mode` 不是 `off`）：每天最多查一次 GitHub Release；`auto` 且是背景服務（`--service`）就下載、驗證、替換並重新啟動。
6. `hub.advertise_url` 有設：在背景常駐 mDNS 廣播那個 Hub（每分鐘確認 Hub 的身分，連不到就暫停），狀態放進心跳的 `advertising`。

`--once` 跑一輪就結束（適合排程或測試，不檢查更新、不廣播）；`--no-upload` 只在本機掃描。`ai-security-monitor upload` 是手動的一輪：補送 outbox、
快照、完整報告、心跳，並印出結果。
