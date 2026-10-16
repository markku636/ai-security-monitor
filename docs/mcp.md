# MCP 與 AI 分析

[English](mcp.en.md) | 繁體中文

`asa` 內建 MCP（Model Context Protocol）伺服器，讓 Claude Code、Codex、Cursor、VS Code、Claude Desktop、Windsurf 直接查這台電腦的資安狀態；
`asa ai` 則是一行指令把問題交給 Claude Code 或 Codex CLI，由它們透過這些工具自己調查。

## 接上你的 AI 工具

```bash
asa mcp config --client claude-code          # 印出設定片段與等效的 `claude mcp add` 指令
asa mcp install --client claude-code --yes   # 寫進 ~/.claude.json（原檔備份為 .bak）
asa mcp install --client vscode --project . --yes
asa mcp install --client codex --yes         # ~/.codex/config.toml 的 [mcp_servers.asa] 區塊
asa mcp uninstall --client cursor --yes
```

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
| `preview_action`／`execute_action` | 防禦動作（只在 `--allow-actions` 時出現） |

預設全部唯讀。要讓 AI 能封鎖 IP，伺服器啟動時加 `--allow-actions`（關閉 port 另需 `--allow-destructive`）；
流程固定是 `preview_action` → 使用者同意 → `execute_action`，審查代碼單次有效、15 分鐘過期，最多同時 32 筆。
這些旗標由啟動伺服器的人決定，模型改不了；而且 `asa mcp` 必須以系統管理員身分執行才能真的寫入防火牆，背景不會跳出 UAC。

## HTTP 傳輸

```bash
asa mcp --http 127.0.0.1:7870                 # 只限本機（檢查 Host／Origin，擋 DNS rebinding）
ASA_MCP_TOKEN=… asa mcp --http 0.0.0.0:7870   # 對外一定要 token
claude mcp add --transport http asa http://127.0.0.1:7870/mcp
```

只收 `POST /mcp`；`initialize` 回 `Mcp-Session-Id`；`Accept: text/event-stream` 時回單一 SSE 事件。

## asa ai

```bash
asa ai status                         # 有沒有裝 Claude Code／Codex、有沒有登入
asa ai ask "這台電腦有沒有連到危險的 IP？"
asa ai analyze                        # 解讀最新報告
asa ai analyze --traffic --duration 30s
asa ai analyze --events --since 30d   # 分析當機原因
asa ai ask "…" --provider codex --max-turns 8 --json   # NDJSON 事件
```

- Claude：`claude -p --output-format stream-json --permission-mode dontAsk --allowedTools mcp__asa__… --mcp-config <暫存檔> --strict-mcp-config`，
  只允許 asa 的唯讀工具，不會讀你的其他 MCP 設定；暫存設定檔跑完即刪。
- Codex：`codex exec --json --sandbox read-only`，以 `-c mcp_servers.asa.*` 帶入，不改你的 `~/.codex/config.toml`。
- 子行程放進 Windows Job Object／Unix process group，逾時（預設 10 分鐘）或中斷時整棵收掉。
- `analyze` 會先告訴你送了多少資料給 AI；資料是摘要（各 ≤ 約 40 KB），不含封包內容。
- 不需要額外的 API key：用的是你已經登入的 Claude Code／Codex。
