# Desktop app

English | [繁體中文](desktop.md)

`ai-security-monitor` itself is a CLI and a background service; the desktop app **AI Security Monitor** (`desktop/`, Tauri 2) is a windowed client that calls the same ai-security-monitor library directly.

## Install

Download from [Releases](https://github.com/markku636/ai-security-monitor/releases/latest) (current version v0.5.0):

| Platform | File | First launch (the installers are not code-signed) |
|---|---|---|
| Windows 10/11 | `AI-Security-Monitor-<version>-windows-x64-setup.exe`, double-click; installs for the current user | "Windows protected your PC" → "More info" → "Run anyway" |
| macOS Apple Silicon / Intel | `…-macos-arm64.dmg` / `…-macos-x64.dmg`, drag to Applications; or use the one-line install below (not blocked) | System Settings → Privacy & Security → "Open Anyway" (macOS 14 and earlier: right-click → Open); if it says it is damaged: `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"` |
| Linux | `…-linux-x64.AppImage` (`chmod +x`, then run) or `…-linux-amd64.deb` (`sudo apt install ./<file>.deb`) | Just start it |

One-line install on macOS (0.7.1 and later; downloads the dmg for your chip, verifies SHA256 and copies the app into Applications; files downloaded with curl get no quarantine flag, so Gatekeeper does not block the app):

```bash
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh -s -- --desktop
```

After installing, the window opens on "Overview" and the AI Security Monitor icon appears in the system tray (menu bar on macOS).
`ai-security-monitor-<version>-windows-x64.exe` is the command-line tool, not the desktop app; double-clicking it only shows a help message.

## Screenshots

The screenshots use demo data (fictional host fin-laptop-07, documentation IP ranges) and are produced by `node scripts/capture-desktop-screenshots.mjs`:
it serves `desktop/ui` from a local static server, injects fake Tauri command responses and captures the pages with headless Chrome / Edge, without reading any real config, running a scan or calling an AI.
The UI itself is in Traditional Chinese.

| | |
|---|---|
| ![Overview](images/desktop-overview.png) Overview: scores, finding counts, intel freshness, network rate and performance sparklines, dangerous and suspicious connections | ![Connections](images/desktop-connections.png) Connections: verdicts, direction filters, reasons and intel sources, with IP analysis on the right |
| ![Scan results](images/desktop-findings.png) Scan results: sorted by severity, expand for detail and advice | ![Threat intel](images/desktop-intel.png) Threat intel: entries, last update, whether it came from the Hub, license |
| ![AI analysis](images/desktop-ai.png) AI analysis: tool calls and the answer stream in live | ![Settings](images/desktop-settings.png) Settings: company Security Hub (when joined: URL, fingerprint, switch or leave), background reporting and automatic updates, start automatically, performance collection switch |
| ![Settings: join the company Hub](images/desktop-settings-join.png) Settings → Company Security Hub before joining: the Hubs found, how each was found, whether it is reachable, its fingerprint, and *Request to join* | ![Dark mode](images/desktop-overview-dark.png) Dark mode follows the Windows color setting |
| ![Traffic & performance: live](images/desktop-traffic.png) Traffic & performance → Live (every second): download / upload rate, the last 60 seconds, per adapter and per program | ![Traffic & performance: last hour](images/desktop-usage.png) Traffic & performance → Last hour: network speed (hover for the values at any time) and network traffic per program |
| ![Traffic & performance: CPU, memory, disk](images/desktop-usage-perf.png) With performance collection on: CPU, memory, disk reads/writes, volumes, top programs, battery | ![Traffic & performance: last 24 hours (dark)](images/desktop-usage-dark.png) Last 24 hours (a point every 5 minutes): no data while the laptop slept, so the lines break |

With `--frame windows` the script instead writes versions wrapped in a Windows 11-style window frame (`windows-desktop-*.png`), plus a hero shot with the window on a desktop above a taskbar showing the tray icon (`windows-desktop-hero.png` / `windows-desktop-hero-dark.png`). The frame, wallpaper and taskbar are drawn by the script as an illustration; they are not real screen captures.

![AI Security Monitor on Windows](images/windows-desktop-hero.png)

## Pages

| Page | What it shows |
|---|---|
| Overview | Security score (connections / exposure / vulnerabilities / hardening), critical + high count, intel freshness, Hub enrollment, dangerous and suspicious connections; Scan now, Update intel, Open Security Hub. Network (current download/upload rate and a sparkline of the last hour); with performance collection on also CPU, memory and the fullest volume (red at ≥ 90%), otherwise an "off" card linking to Settings. Uses the background service's per-minute samples when it runs, otherwise the app measures while it is open, including in the tray (the last hour in memory, the 24-hour history in the config directory). Clicking a sparkline opens Traffic & performance → Last hour. See [metrics.en.md](metrics.en.md) |
| Connections | Every current connection; the same program talking to the same remote is merged into one row. Click a column header to sort (verdict, direction, remote, count, country / org, program, reason; click again to reverse). Filters: verdict, direction, protocol, connection state, reason type (intel / behavior / none), program, country, port, public addresses only, hide loopback, keyword, with one-click clear. Reasons are labeled Intel (click to open the source list) or Behavior (ai-security-monitor's own heuristic); optional 10-second auto refresh |
| Traffic & performance | Three tabs; see [Traffic and performance](#traffic-and-performance) below. **Live (every second)**: download / upload rate updated every second (large figures plus Mbps), a chart of the last 60 seconds or 5 minutes, and the running total; per-adapter rates (virtual adapters marked and left out of the total); which programs are using the network (Windows needs the app to run as administrator, macOS uses nettop; on Linux it points to the Connections page). Measured only while this tab is open, never stored, and paused while the window is in the tray. **Last hour / last 24 hours**: network speed and network traffic per program (top 6 plus others, switchable between total / download / upload); with performance collection on, also CPU, memory, disk reads/writes, volumes, top programs and battery. Clicking an Overview sparkline opens *Last hour* |
| IP analysis | Click an IP: country / ASN, which intel sources list it, which local programs talk to it, VirusTotal / AbuseIPDB links, and "Ask AI about this IP" |
| Scan results | Findings from the latest report, sorted by severity, expandable for detail and advice |
| Threat intel | Per source: entries, last update, whether it came from the Hub; update stale lists or refetch everything |
| AI analysis | Uses the Claude Code or Codex CLI you are signed in to (your subscription) to analyze suspicious connections, the latest report, or a free-form question, streaming answers and tool calls. *AI accounts* below shows whether each program is signed in, with sign-in (opens a terminal running the official sign-in command) and sign-out; see [ai-login.en.md](ai-login.en.md) |
| Settings | **Company Security Hub** (joining, waiting for approval, switching and leaving all happen here; see [Joining your company's Hub](#joining-your-companys-hub) below): before joining it searches automatically (without holding up the rest of the page) and lists the Hubs found, or you type a URL and use *Test this URL* / *Request to join*, or *I have an enroll key*; while joining it shows the Hub fingerprint and the check code and keeps checking; once joined it shows the URL and fingerprint with *Open Security Hub*, *Test connection*, *Leave this Hub* (deletes only this computer's settings and key; the host record on the Hub stays until an administrator deletes it) and *Switch Hub or join again*. Switching to a Hub with a different fingerprint shows a clear warning and needs confirmation. **Start automatically**: *Report in the background after startup/sign-in* (= `ai-security-monitor service install --yes`, installed for the current user, no UAC; it also replaces an old asa start-at-login entry and moves its settings) and *Open the desktop app at sign-in* (tray only, no window). **Network traffic and performance**: *Collect this computer's performance (CPU, memory, disk)* (= `metrics.performance`, off by default; data goes only to the Hub this computer joined and the Hub cannot turn it on; with background reporting on, no window is needed and the service re-reads the setting every minute). Plus agent id and config directory |

Closing the window minimizes it to the system tray; the tray menu has Open, Open Security Hub and Quit. Only one instance runs at a time.

## Traffic and performance

*Traffic & performance* (流量與效能) in the sidebar shows this computer in charts, in three tabs (URLs `#traffic`, `#traffic/1h`, `#traffic/24h`):

![Traffic & performance: last hour](images/desktop-usage.png)

- **Live (every second)**: the current speed, measured only while this tab is open and never stored (formerly the separate Live traffic page).
- **Last hour** (a point per minute) and **last 24 hours** (a point every 5 minutes, the average of those 5 minutes):
  - **Network speed**: download / upload rate and the total for the period.
  - **Network traffic per program**: one line for each of the top 6 programs by total over the period (each program keeps its color when you switch between total / download / upload), the rest as a gray dashed "other programs" line, and a table of the top 10 with download, upload and total.
    Windows needs the background service to run as administrator (in an administrator PowerShell: `ai-security-monitor service install --system --yes`), macOS uses the built-in nettop, and Linux cannot measure it; the page explains this in plain words when there is no data.
  - **With performance collection on**: CPU (the 24-hour chart also shows the highest sample in each 5 minutes, dashed), memory (% with used / total), disk read/write rate, volume usage (red at 90% or more), the programs using the most CPU / memory (latest sample) and the laptop battery. When it is off, only the network charts are shown, with an explanation and the same switch as in Settings.
- The charts are plain SVG: hover (or focus with Tab and use the arrow keys) to see a crosshair and every line's value at that time; charts with two or more lines have a text legend; each has a table for screen readers; light and dark modes use their own tuned colors. Periods without data (for example while the computer slept) leave a gap.
- **Where the data comes from**: background reporting's per-minute samples when it is running; otherwise the desktop app samples once a minute while it is open (including in the tray). The 24-hour history is kept on this computer (`<config dir>/metrics/history.jsonl`, one line per 5 minutes, about 300 KB), even without a Hub; see [metrics.en.md](metrics.en.md#local-24-hour-history).

![Traffic & performance: CPU, memory, disk](images/desktop-usage-perf.png)

## Upgrading from the "AI Security Agent" desktop app

From 0.2.0 the desktop app is called **AI Security Monitor** and its application identifier changed from `dev.asa.desktop` to
`dev.ai-security-monitor.desktop`, so the new installer installs a separate app and does **not** replace or remove the old one:

1. Quit the old app (tray icon → Quit).
2. Settings → Apps → Installed apps → "AI Security Agent" → Uninstall (this also removes its Start menu shortcut).
3. Install the new `AI-Security-Monitor-<version>-windows-x64-setup.exe`.
4. (Optional) Delete the old WebView cache `%LOCALAPPDATA%\dev.asa.desktop`; the new app uses `%LOCALAPPDATA%\dev.ai-security-monitor.desktop`.

Scan reports, threat intel, Hub enrollment and keys live in the agent's config directory, not in those folders: the first 0.2.0 command-line run
moves `%APPDATA%\ai-security-agent` to `%APPDATA%\ai-security-monitor`, and the new desktop app picks it up without re-enrolling.

## Automatic updates

Settings → "Background reporting and automatic updates":

![Background reporting and automatic updates in Settings](images/desktop-settings-update.png)

- **Automatic updates**: "Off", "Notify me when a new version is out (recommended, default)", "Update automatically". It checks once a day (first about 30 seconds after start). In notify mode a "New version 0.x.y" notice appears in the bottom-right corner; press "Update now" or dismiss it. In automatic mode the update is downloaded in the background and installed the next time you choose "Quit" from the tray or reopen the app (if the app was started in the tray at sign-in and its window has not been opened yet, it installs right away).
- **Check for updates / Update now** work at any time regardless of the setting, and show the current version, the latest version and a link to the release notes.
- Updates carry a minisign signature checked against the public key built into the app; on Windows the installer runs in passive mode (progress bar only) and the app reopens afterwards.
- **Background reporting is updated with it**: it runs the desktop executable, so it switches to the new version too (on Windows the installer restarts it from `HKCU\…\Run`; on macOS/Linux the app restarts it). A separately installed command-line background service is listed in the same section; it follows its own `update.mode`, and "Update the command-line build" updates it on demand.
- Installed from the .deb: automatic updates are downloaded but only installed when you press "Update now" and enter an administrator password. Development builds (built from source) are not updated.
- The setting is shared with the command line (`update.mode` in `config.json`); see [Install and update](install.en.md#updating).

## Upload to the Hub now

After joining a Hub, the Overview page has an "Upload to Security Hub" card: when the last upload happened, how many reports are waiting to be resent (queued while the Hub is unreachable), and "Scan now and upload to the Hub", which resends queued reports, uploads a connection snapshot, runs a full scan and uploads it, sends a heartbeat, and then reports "Uploaded; the Hub received N findings". The command-line equivalent is `ai-security-monitor upload`.

## Let computers on the LAN find the Hub on this computer

When this computer runs a Security Hub (e.g. the standalone edition in Docker Desktop), Settings shows "Let computers on the LAN find the Hub on this computer": turn it on and enter the URL other computers should use (this computer's LAN IP is filled in, e.g. `http://192.168.1.10:8088`); background reporting then advertises it on the LAN (mDNS, with the Hub fingerprint in TXT) and colleagues see it under "Find your company's Hub". Advertising pauses while the Hub is unreachable and resumes automatically.

- Before turning it on, the app checks that the URL reaches the Hub and that it is the same Hub as the one on this computer. The standalone Hub binds 127.0.0.1 by default and is unreachable from the LAN: set `AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0` in the Hub's `.env` first (see [Find the Hub automatically](enrollment.en.md#mdns-advertising)).
- Background reporting must be on for advertising to keep running. Command-line equivalent: `ai-security-monitor config set hub.advertise_url <url>`.

## Joining your company's Hub

Everything about joining the company Security Hub is in *Settings → Company Security Hub* (設定 → 公司的 Security Hub). The separate "Join company Hub" page in the sidebar has been folded into it, and old `#join` links land here. On first start with no Hub, the app opens this section automatically (unless you clicked *Not now, use it on this computer only*).

![Settings, company Security Hub: the Hubs found before joining](images/desktop-settings-join.png)

- **Not joined**: it searches automatically (company DNS and LAN advertising, about 3–10 seconds, in the background so the rest of Settings is usable; coming back within 2 minutes reuses the result). Each Hub found shows how it was found (with a tooltip), whether it is reachable (with the reason when not) and its fingerprint, with *Request to join*; *Search again* repeats the search. When nothing is found, it explains the three usual fixes: ask the administrator for the Hub URL, make the Hub reachable on the LAN, and have a computer advertise a Hub that runs in Docker Desktop. You can also type the URL your administrator gave you and use *Test this URL* or *Request to join*, or expand *I have an enroll key (advanced)*.
- **Joining**: if the Hub allows automatic joining it completes right away; otherwise it shows *Waiting for administrator approval*, the Hub fingerprint and this computer's check code, and keeps checking (it stops when you leave Settings and resumes when you come back; closing the window is fine, the background service keeps waiting). *Check now* and *Cancel request* are there too. A rejection shows the reason and *Search again*.
- **Joined**: the Hub URL and fingerprint, *Open Security Hub*, *Test connection* and *Leave this Hub*; to move to another Hub or join again, expand *Switch Hub or join again* (same search, URL and enroll-key options).

## How it relates to the CLI and service

- It shares the config directory (`%APPDATA%\ai-security-monitor` etc.), so it sees the background `ai-security-monitor watch`'s latest report, intel and Hub enrollment.
- The Connections page takes a read-only snapshot: it does **not** append to the connection history, so frequent refreshes don't skew the service's beacon detection.
- AI analysis mounts ai-security-monitor's read-only MCP tools; the MCP server is the desktop executable itself — started with command-line arguments (e.g. `ai-security-monitor-desktop.exe mcp --tools …`) it runs as the ai-security-monitor CLI.
- *Report in the background* registers **the desktop executable itself** (`…\AI Security Monitor\ai-security-monitor-desktop.exe watch --service`; on Windows the `ai-security-monitor` value under `HKCU\…\Run`, a LaunchAgent on macOS, systemd --user or XDG autostart on Linux). The installed path does not change on updates, so nothing needs to be redone; a Linux AppImage registers the AppImage file itself (`APPIMAGE`), not the per-run temporary mount. If the command-line service was installed before, turning the switch on points it at the desktop executable.
- *Open the desktop app at sign-in* starts `ai-security-monitor-desktop --tray`: tray icon only, no window (on Windows the "AI Security Monitor" value under `HKCU\…\Run`).
- No administrator rights needed; some checks (Security event log, minidumps) need an administrator and are marked as such in the report.

## Build

```bash
cd desktop
npm ci                 # just @tauri-apps/cli
npm run icon           # (optional) regenerate every icon size from src-tauri/icons/source.png (the project logo)
npx tauri build        # Windows: src-tauri/target/release/bundle/nsis/*-setup.exe
```

The UI lives in `desktop/ui/` as plain HTML/CSS/JS with no frontend build step. The installer is per-user (no administrator needed).
