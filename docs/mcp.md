# MCP 與 AI 分析

[English](mcp.en.md) | 繁體中文

`ai-security-monitor` 內建 MCP（Model Context Protocol）伺服器，讓 Claude Code、Codex、Cursor、VS Code、Claude Desktop、Windsurf 直接查這台電腦的資安狀態；
`ai-security-monitor ai` 則是一行指令把問題交給 Claude Code 或 Codex CLI，由它們透過這些工具自己調查。

## 接上你的 AI 工具

```bash
ai-security-monitor mcp config --client claude-code   # 印出設定片段與等效的 `claude mcp add` 指令
ai-security-monitor mcp install --client claude-code --yes   # 寫進 ~/.claude.json（原檔備份為 .bak）
ai-security-monitor mcp install --client vscode --project . --yes
ai-security-monitor mcp install --client codex --yes  # ~/.codex/config.toml 的 [mcp_servers.ai-security-monitor] 區塊
ai-security-monitor mcp uninstall --client cursor --yes
```

伺服器名是 `ai-security-monitor`（工具名 `mcp__ai-security-monitor__*`）。從 0.1.x 升級時 `mcp install` 會刪掉舊的 `asa` 項目再寫入新的，`mcp uninstall` 兩個都刪。

支援的用戶端：`claude-code`（使用者或 `--project` 的 `.mcp.json`）、`codex`、`cursor`、`vscode`（只支援 `--project`）、`claude-desktop`、`windsurf`。

## 工具

| 工具 | 內容 |
|---|---|
| `list_connections` | 目前連線（方向、判定、理由、行程、國家／ASN；情資命中附廠商與 `source_url`） |
| `lookup_ip` | 查 IP／網域的情資判定；`online: true` 另查已設定 key 的名譽服務 |
| `inbound_attackers` | 連進來的可疑來源＋事件記錄裡的暴力破解來源 |
| `intel_sources` | 情資來源、授權與下載狀態 |
| `scan`／`list_findings`／`get_report` | 掃描與最新報告 |
| `listening_ports`／`firewall_status` | 監聽 port 的實際可達性、防火牆設定 |
| `baseline_diff`／`doctor` | 基準線差異、環境檢查 |
| `traffic_summary`／`analyze_pcap` | 即時流量（最多 60 秒）、pcap 分析 |
| `events_summary`／`crash_history`／`explain_code` | 事件與當機、藍屏代碼與事件 ID 說明 |
| `vuln_summary` | 作業系統支援期限、最近更新、已知漏洞版本的軟體（CVE、NVD 連結）、Linux 套件 OSV、KEV |
| `hardening_status` | 系統硬化檢查每條結果、目前值、修正方式與加權分數（`only_failed`、`category`） |
| `get_metrics` | 網路流量（各網卡、各程式的上傳／下載）與效能（使用者有開啟才有）：現在的值與最近 1 小時摘要，見 [metrics.md](metrics.md) |
| `preview_action`／`execute_action` | 防禦動作（只在 `--allow-actions` 時出現） |

預設全部唯讀。要讓 AI 能封鎖 IP，伺服器啟動時加 `--allow-actions`（關閉 port 另需 `--allow-destructive`）；
流程固定是 `preview_action` → 使用者同意 → `execute_action`，審查代碼單次有效、15 分鐘過期，最多同時 32 筆。
這些旗標由啟動伺服器的人決定，模型改不了；而且 `ai-security-monitor mcp` 必須以系統管理員身分執行才能真的寫入防火牆，背景不會跳出 UAC。

## HTTP 傳輸

```bash
ai-security-monitor mcp --http 127.0.0.1:7870  # 只限本機（檢查 Host／Origin，擋 DNS rebinding）
AI_SECURITY_MONITOR_MCP_TOKEN=… ai-security-monitor mcp --http 0.0.0.0:7870   # 對外一定要 token（舊名 ASA_MCP_TOKEN 也可以）
claude mcp add --transport http ai-security-monitor http://127.0.0.1:7870/mcp
```

只收 `POST /mcp`；`initialize` 回 `Mcp-Session-Id`；`Accept: text/event-stream` 時回單一 SSE 事件。

## ai-security-monitor ai

```bash
ai-security-monitor ai status                        # 有沒有裝 Claude Code／Codex、有沒有登入
ai-security-monitor ai ask "這台電腦有沒有連到危險的 IP？"
ai-security-monitor ai analyze                       # 解讀最新報告
ai-security-monitor ai analyze --traffic --duration 30s
ai-security-monitor ai analyze --events --since 30d  # 分析當機原因
ai-security-monitor ai ask "…" --provider codex --max-turns 8 --json   # NDJSON 事件
```

- Claude：`claude -p --output-format stream-json --permission-mode dontAsk --allowedTools mcp__ai-security-monitor__… --mcp-config <暫存檔> --strict-mcp-config`，
  只允許 ai-security-monitor 的唯讀工具，不會讀你的其他 MCP 設定；暫存設定檔跑完即刪。
- Codex：`codex exec --json --sandbox read-only`，以 `-c mcp_servers.ai-security-monitor.*` 帶入，不改你的 `~/.codex/config.toml`。
- 子行程放進 Windows Job Object／Unix process group，逾時（預設 10 分鐘）或中斷時整棵收掉。
- `analyze` 會先告訴你送了多少資料給 AI；資料是摘要（各 ≤ 約 40 KB），不含封包內容。
- 不需要額外的 API key：用的是你已經登入的 Claude Code／Codex。

## Hub 的 MCP（整個車隊）

Security Hub 也有 MCP 端點 `/api/mcp`，讓 AI 一次查所有主機：

```bash
claude mcp add --transport http asahub https://<hub>/api/mcp --header "Authorization: Bearer <有 mcp 權限的 API token>"
```

工具（全部唯讀）：`fleet_summary`、`list_agents`、`list_findings`、`list_connections`、`inbound_attackers`、`lookup_indicator`、`top_destinations`、
`crash_history`、`security_events`、`brute_force_sources`、`explain_bugcheck`、`list_actions`、`intel_feeds`、`vuln_overview`、`hardening_overview`、`fleet_traffic`（流量總量、主機排行、各網卡、各程式）、`host_performance`（單台主機的效能，或 ≥ 90% 的主機）。資料與 Hub 頁面同一份查詢。
認證建議用 Hub「設定與金鑰 → API token」建立、勾選 MCP 權限的唯讀 token（可設期限、可撤銷）；也接受 `AI_SECURITY_MONITOR_HUB_MCP_TOKEN` 或管理員金鑰；開放模式（沒設管理員金鑰）只接受本機的 Host／Origin。

## Hub 的 AI 分析頁（/ai）

Hub 也能直接在 hub 主機上跑 Claude Code／Codex：選「整個車隊／單一主機／解讀流量／分析當機與資安事件」，回答與工具呼叫即時串流到網頁，紀錄留在「最近的分析」。
「事件與當機」「流量」頁與主機頁都有「請 AI …」按鈕直接帶入範圍。

- 每一輪產生一次性 token，CLI 只能用它呼叫 hub 的唯讀 MCP；結束即失效。
- 子行程只拿到白名單環境變數（PATH、HOME、Claude／OpenAI 的登入憑證等），**不會**拿到 hub 的管理員金鑰或資料庫網址。
- 網頁按「停止」或關掉分頁就會整棵行程收掉；同時最多跑 `AI_SECURITY_MONITOR_HUB_AI_MAX_CONCURRENT`（預設 2）輪。
- hub 主機要先安裝並登入 Claude Code 或 Codex；Docker 版會把登入狀態放在 `/data`（之後的 Docker 輪次）。CLI 不在 PATH 時用 `AI_SECURITY_MONITOR_HUB_CLAUDE_BIN`／`AI_SECURITY_MONITOR_HUB_CODEX_BIN` 指定；
  hub 不是跑在 3000 port 時設 `AI_SECURITY_MONITOR_HUB_INTERNAL_URL`（例 `http://127.0.0.1:8088`）讓 CLI 連得回 `/api/mcp`。
