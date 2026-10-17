# MCP and AI analysis

English | [繁體中文](mcp.md)

`ai-security-monitor` ships an MCP (Model Context Protocol) server so Claude Code, Codex, Cursor, VS Code, Claude Desktop and Windsurf can inspect this computer's security state directly;
`ai-security-monitor ai` hands a question to Claude Code or Codex CLI in one command and lets them investigate through those tools.

## Connect your AI tools

```bash
ai-security-monitor mcp config --client claude-code   # print the snippet and the equivalent `claude mcp add` command
ai-security-monitor mcp install --client claude-code --yes   # write ~/.claude.json (previous file backed up as .bak)
ai-security-monitor mcp install --client vscode --project . --yes
ai-security-monitor mcp install --client codex --yes  # the [mcp_servers.ai-security-monitor] block in ~/.codex/config.toml
ai-security-monitor mcp uninstall --client cursor --yes
```

The server is named `ai-security-monitor` (tools `mcp__ai-security-monitor__*`). When upgrading from 0.1.x, `mcp install` removes the old `asa` entry before writing the new one, and `mcp uninstall` removes both.

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
| `vuln_summary` | OS support lifetime, last update, software on known-vulnerable versions (CVE, NVD link), Linux OSV results, KEV |
| `hardening_status` | every hardening check with current value, fix and weighted score (`only_failed`, `category`) |
| `get_metrics` | network traffic (upload/download per card and per program) and performance (only when the user turned it on): current values and a summary of the last hour, see [metrics.en.md](metrics.en.md) |
| `preview_action` / `execute_action` | defensive actions (listed only with `--allow-actions`) |

Everything is read-only by default. To let the AI block IPs, start the server with `--allow-actions` (closing ports also needs `--allow-destructive`);
the flow is always `preview_action` → user consent → `execute_action`, with single-use review tokens that expire after 15 minutes (at most 32 pending).
Whoever starts the server decides these flags; the model cannot change them. `ai-security-monitor mcp` must also run as administrator to actually change the firewall, and it never pops up UAC in the background.

## HTTP transport

```bash
ai-security-monitor mcp --http 127.0.0.1:7870  # loopback only (Host/Origin checked against DNS rebinding)
AI_SECURITY_MONITOR_MCP_TOKEN=… ai-security-monitor mcp --http 0.0.0.0:7870   # a token is mandatory beyond loopback (the old ASA_MCP_TOKEN works too)
claude mcp add --transport http ai-security-monitor http://127.0.0.1:7870/mcp
```

Only `POST /mcp` is served; `initialize` returns `Mcp-Session-Id`; with `Accept: text/event-stream` the reply is a single SSE event.

## ai-security-monitor ai

```bash
ai-security-monitor ai status                        # are Claude Code / Codex installed and signed in
ai-security-monitor ai ask "Is this computer talking to any dangerous IP?"
ai-security-monitor ai analyze                       # interpret the latest report
ai-security-monitor ai analyze --traffic --duration 30s
ai-security-monitor ai analyze --events --since 30d  # find crash root causes
ai-security-monitor ai ask "…" --provider codex --max-turns 8 --json   # NDJSON events
```

- Claude: `claude -p --output-format stream-json --permission-mode dontAsk --allowedTools mcp__ai-security-monitor__… --mcp-config <temp file> --strict-mcp-config`;
  only ai-security-monitor's read-only tools are allowed and your other MCP settings are not loaded; the temp config is deleted afterwards.
- Codex: `codex exec --json --sandbox read-only` with `-c mcp_servers.ai-security-monitor.*` overrides; your `~/.codex/config.toml` is untouched.
- The child process tree lives in a Windows Job Object / Unix process group and is killed as a whole on timeout (10 minutes by default) or interruption.
- `analyze` tells you how much data it sends to the AI; the data are summaries (each ≤ about 40 KB) without packet payloads.
- No extra API key is needed: it uses the Claude Code / Codex you are already signed in to.

## The hub's MCP (whole fleet)

Security Hub exposes an MCP endpoint at `/api/mcp` so an AI can query every host at once:

```bash
claude mcp add --transport http asahub https://<hub>/api/mcp --header "Authorization: Bearer <API token with the mcp scope>"
```

Tools (all read-only): `fleet_summary`, `list_agents`, `list_findings`, `list_connections`, `inbound_attackers`, `lookup_indicator`, `top_destinations`,
`crash_history`, `security_events`, `brute_force_sources`, `explain_bugcheck`, `list_actions`, `intel_feeds`, `vuln_overview`, `hardening_overview`, `fleet_traffic` (traffic totals, host ranking, per card, per program), `host_performance` (one host's performance, or hosts at ≥ 90%). They use the same queries as the hub pages.
Authenticate with a read-only API token created under "Settings & keys → API token" with the MCP scope (expiry and revocation supported); `AI_SECURITY_MONITOR_HUB_MCP_TOKEN` or the admin key also work; open mode (no admin key) only accepts loopback Host/Origin.

## The hub's AI page (/ai)

The hub can also run Claude Code / Codex on the hub host: pick "whole fleet / one host / explain traffic / crashes and security events" and the answer and tool calls stream into the page; runs are kept under "Recent analyses".
The Events and Traffic pages and the host page have "Ask AI …" buttons that open it with the scope preselected.

- Each run gets a one-time token that only lets the CLI call the hub's read-only MCP; it expires when the run ends.
- The child process only receives allow-listed environment variables (PATH, HOME, Claude/OpenAI sign-in credentials…), **never** the hub's admin key or database URL.
- Pressing Stop or closing the tab kills the whole process tree; at most `AI_SECURITY_MONITOR_HUB_AI_MAX_CONCURRENT` (default 2) runs at a time.
- Install and sign in to Claude Code or Codex on the hub host first; the Docker image will keep sign-in state under `/data` (later Docker round). Use `AI_SECURITY_MONITOR_HUB_CLAUDE_BIN` / `AI_SECURITY_MONITOR_HUB_CODEX_BIN` when the CLI is not on PATH,
  and set `AI_SECURITY_MONITOR_HUB_INTERNAL_URL` (e.g. `http://127.0.0.1:8088`) when the hub does not listen on port 3000 so the CLI can reach `/api/mcp`.
