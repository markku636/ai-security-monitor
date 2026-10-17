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

內容：`contract/snapshot.v1.json`（目前連線與 listener，每條連線帶方向與判定）。整批替換該 agent 的最新連線，並彙總目的地（保留最嚴重的判定）。
最短間隔 `AI_SECURITY_MONITOR_HUB_SNAPSHOT_MIN_INTERVAL_MS`（預設 10 秒）。未註冊的 agent 回 409。

### `POST /api/v1/agents/me/heartbeat`

內容：`{ agent_id, ts, version, uptime_s?, last_scan_at?, elevated }`。未知 agent 回 404。

### 遠端動作

管理員在 Hub 核准動作（目前：`block_ip`、`unblock_ip`、`close_port`；`close_port` 屬破壞性，核准時要輸入主機名稱）後：

1. agent 註冊時若 `accept_remote_actions: true` 且身分已釘選，回應裡有 `action_key`＝HMAC-SHA256(hub 簽署金鑰, `asa-action-key|<agent_id>`)，存進系統金鑰圈。
2. 心跳回應的 `pending_actions` > 0 時，agent 呼叫 `GET /api/v1/agents/me/actions` 取得 `{action_id, agent_id, kind, params, expires_at, token}`。
3. agent 驗證：`token`＝HMAC-SHA256(action_key, canonical JSON of {action_id, agent_id, kind, params, expires_at})（key 排序、無空白，見 `contract/action.v1.json`）、agent id 相符、未過期（核准後 24 小時）、本機設定允許該種類（預設只有 block_ip／unblock_ip；破壞性要 `allow_destructive`）、目標不在本機白名單或已知良好清單、不含本機介面位址。
4. 背景執行不會跳 UAC／sudo：沒有系統管理員權限就回報失敗。執行結果 `POST /api/v1/agents/me/actions/{id}/result`（`{agent_id, ok, output}`）。派送後 10 分鐘沒回報會重派，agent 以 action id 去重、直接回報上次結果。

簽署金鑰：`AI_SECURITY_MONITOR_HUB_ACTION_SIGNING_KEY`（或 `_FILE`）；沒設就第一次用到時隨機產生並存進資料庫。換金鑰後 agent 要重新註冊才拿得到新的 `action_key`。

## `ai-security-monitor watch` 流程

1. 讀設定與金鑰 → `register`（每次啟動都更新身分與版本）。
2. 每 `snapshot_interval`（預設 1 分鐘）：拍連線快照（含情資判定）→ `ingest/snapshot`，接著 `heartbeat`；有待執行的遠端動作就領取、驗章、執行並回報。
3. 每 `interval`（預設 10 分鐘）：先送 outbox 裡的舊報告（遇到可重試錯誤就停）→ 掃描 → `ingest/report`；失敗就放進 outbox。
4. 最新報告存在 `<config>/reports/latest.json`，`ai-security-monitor status` 顯示 hub 狀態、待重送數與最後一次掃描。

`--once` 跑一輪就結束（適合排程或測試）；`--no-upload` 只在本機掃描。
