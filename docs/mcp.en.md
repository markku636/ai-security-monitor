# MCP and AI analysis

English | [繁體中文](mcp.md)

`asa` ships an MCP (Model Context Protocol) server so Claude Code, Codex, Cursor, VS Code, Claude Desktop and Windsurf can inspect this computer's security state directly;
`asa ai` hands a question to Claude Code or Codex CLI in one command and lets them investigate through those tools.

## Connect your AI tools

```bash
asa mcp config --client claude-code          # print the snippet and the equivalent `claude mcp add` command
asa mcp install --client claude-code --yes   # write ~/.claude.json (previous file backed up as .bak)
asa mcp install --client vscode --project . --yes
asa mcp install --client codex --yes         # the [mcp_servers.asa] block in ~/.codex/config.toml
asa mcp uninstall --client cursor --yes
```

Supported clients: `claude-code` (user or `--project` `.mcp.json`), `codex`, `cursor`, `vscode` (`--project` only), `claude-desktop`, `windsurf`.

## Tools

| Tool | What it returns |
|---|---|
| `list_connections` | current connections (direction, verdict, reasons, process, country/ASN; intel hits with vendor and `source_url`) |
| `lookup_ip` | intel verdict for an IP/domain; `online: true` also queries reputation services that have keys |
| `inbound_attackers` | suspicious inbound sources plus brute-force sources from the event logs |
| `intel_sources` | intel sources, licenses and download status |
| `scan` / `list_findings` / `get_report` | scanning and the latest report |
| `listening_ports` / `firewall_status` | real reachability of listening ports, firewall settings |
| `baseline_diff` / `doctor` | baseline differences, environment check |
| `traffic_summary` / `analyze_pcap` | live traffic (up to 60 s), pcap analysis |
| `events_summary` / `crash_history` / `explain_code` | events and crashes, bugcheck codes and event IDs |
| `preview_action` / `execute_action` | defensive actions (listed only with `--allow-actions`) |

Everything is read-only by default. To let the AI block IPs, start the server with `--allow-actions` (closing ports also needs `--allow-destructive`);
the flow is always `preview_action` → user consent → `execute_action`, with single-use review tokens that expire after 15 minutes (at most 32 pending).
Whoever starts the server decides these flags; the model cannot change them. `asa mcp` must also run as administrator to actually change the firewall, and it never pops up UAC in the background.

## HTTP transport

```bash
asa mcp --http 127.0.0.1:7870                 # loopback only (Host/Origin checked against DNS rebinding)
ASA_MCP_TOKEN=… asa mcp --http 0.0.0.0:7870   # a token is mandatory beyond loopback
claude mcp add --transport http asa http://127.0.0.1:7870/mcp
```

Only `POST /mcp` is served; `initialize` returns `Mcp-Session-Id`; with `Accept: text/event-stream` the reply is a single SSE event.

## asa ai

```bash
asa ai status                         # are Claude Code / Codex installed and signed in
asa ai ask "Is this computer talking to any dangerous IP?"
asa ai analyze                        # interpret the latest report
asa ai analyze --traffic --duration 30s
asa ai analyze --events --since 30d   # find crash root causes
asa ai ask "…" --provider codex --max-turns 8 --json   # NDJSON events
```

- Claude: `claude -p --output-format stream-json --permission-mode dontAsk --allowedTools mcp__asa__… --mcp-config <temp file> --strict-mcp-config`;
  only asa's read-only tools are allowed and your other MCP settings are not loaded; the temp config is deleted afterwards.
- Codex: `codex exec --json --sandbox read-only` with `-c mcp_servers.asa.*` overrides; your `~/.codex/config.toml` is untouched.
- The child process tree lives in a Windows Job Object / Unix process group and is killed as a whole on timeout (10 minutes by default) or interruption.
- `analyze` tells you how much data it sends to the AI; the data are summaries (each ≤ about 40 KB) without packet payloads.
- No extra API key is needed: it uses the Claude Code / Codex you are already signed in to.
