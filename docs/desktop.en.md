# Desktop app

English | [繁體中文](desktop.md)

`asa` itself is a CLI and a background service; the desktop app (`desktop/`, Tauri 2) is a windowed client that calls the same asa library directly.

## Pages

| Page | What it shows |
|---|---|
| Overview | Security score (connections / exposure / vulnerabilities / hardening), critical + high count, intel freshness, Hub enrollment, dangerous and suspicious connections; Scan now, Update intel, Open Security Hub |
| Connections | Every current connection, filtered by verdict and direction with search; the same program talking to the same remote is merged into one row; reasons are labeled Intel (click to open the source list) or Behavior (asa's own heuristic); optional 10-second auto refresh |
| IP analysis | Click an IP: country / ASN, which intel sources list it, which local programs talk to it, VirusTotal / AbuseIPDB links, and "Ask AI about this IP" |
| Scan results | Findings from the latest report, sorted by severity, expandable for detail and advice |
| Threat intel | Per source: entries, last update, whether it came from the Hub; update stale lists or refetch everything |
| AI analysis | Uses the Claude Code or Codex CLI you are signed in to (your subscription) to analyze suspicious connections, the latest report, or a free-form question, streaming answers and tool calls |
| Settings | Agent id, config directory, Hub URL, background service status |

Closing the window minimizes it to the system tray; the tray menu has Open, Open Security Hub and Quit. Only one instance runs at a time.

## How it relates to the CLI and service

- It shares the config directory (`%APPDATA%\ai-security-agent` etc.), so it sees the background `asa watch`'s latest report, intel and Hub enrollment.
- The Connections page takes a read-only snapshot: it does **not** append to the connection history, so frequent refreshes don't skew the service's beacon detection.
- AI analysis mounts asa's read-only MCP tools; the MCP server is the desktop executable itself — started with command-line arguments (e.g. `asa-desktop.exe mcp --tools …`) it runs as the asa CLI.
- No administrator rights needed; some checks (Security event log, minidumps) need an administrator and are marked as such in the report.

## Build

```bash
cd desktop
npm ci                 # just @tauri-apps/cli
npm run icon           # (optional) regenerate icons
npx tauri build        # Windows: src-tauri/target/release/bundle/nsis/*-setup.exe
```

The UI lives in `desktop/ui/` as plain HTML/CSS/JS with no frontend build step. The installer is per-user (no administrator needed).
