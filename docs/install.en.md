# Install and update

English | [繁體中文](install.md)

## Which download do I need?

Current version: **v0.3.0**; all files are on [Releases](https://github.com/markku636/ai-security-monitor/releases/latest).

| Your situation | Download |
|---|---|
| Everyday user who wants a window | Desktop app: `AI-Security-Monitor-<version>-windows-x64-setup.exe`, `…-macos-arm64.dmg` (Apple Silicon), `…-macos-x64.dmg` (Intel), `…-linux-x64.AppImage`, `…-linux-amd64.deb`; see "Desktop app" below |
| Servers (including Windows Server / Server Core), automation | Command line: the one-line install below, or download `ai-security-monitor-<version>-<platform>` directly (a command-line tool: run it in a terminal; double-clicking only shows a help message) |
| One place for many hosts | Security Hub (Docker), see [docker.en.md](docker.en.md) |
| `asa-<version>-*` | Only for 0.1.x `asa self-update`; ignore them |
| `SHA256SUMS` | SHA256 of every file |

System requirements and step-by-step instructions for every path (with how to check it worked) are in the [README "Install" section](../README.en.md#install).

## Desktop app

The installers are not code-signed, so the OS warns the first time:

| Platform | Install | First launch |
|---|---|---|
| Windows 10/11 | Double-click `AI-Security-Monitor-<version>-windows-x64-setup.exe` (per-user install, no administrator) | "Windows protected your PC" → "More info" → "Run anyway" |
| macOS | Open the `.dmg` and drag AI Security Monitor to Applications | Right-click → Open → Open; if it says it is damaged: `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"` |
| Linux | AppImage: `chmod +x`, then run; deb: `sudo apt install ./AI-Security-Monitor-<version>-linux-amd64.deb` | Just start it |

Uninstall the old "AI Security Agent" desktop app (0.1.x) first; the new one does not replace it (see [desktop.en.md](desktop.en.md)).

## One-line install (command line)

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

The script detects the OS and CPU → downloads `ai-security-monitor-<version>-<platform>` → **checks it against the release's `SHA256SUMS` and stops on a mismatch** → installs it → optionally enrolls with a Hub and sets up start at boot.

| Option (sh) / environment variable | Meaning |
|---|---|
| `--version` / `AI_SECURITY_MONITOR_VERSION` | Version to install (default: latest) |
| `--dir` / `AI_SECURITY_MONITOR_INSTALL_DIR` | Install location (Linux/macOS: `/usr/local/bin`, or `~/.local/bin` without rights; Windows: `%LOCALAPPDATA%\ai-security-monitor\bin`, added to the user PATH, or `%ProgramFiles%\ai-security-monitor` for the system service, which needs an elevated PowerShell) |
| `--hub URL --key KEY` / `AI_SECURITY_MONITOR_HUB_URL`, `AI_SECURITY_MONITOR_ENROLL_KEY` | Enroll with a Security Hub after installing |
| `--service none\|user\|system` / `AI_SECURITY_MONITOR_SERVICE` | Start at boot (see [service.en.md](service.en.md)); `system` enrolls straight into the system config directory |
| `AI_SECURITY_MONITOR_DOWNLOAD_BASE` | Internal mirror serving `ai-security-monitor-<version>-<platform>` and `SHA256SUMS` |
| `AI_SECURITY_MONITOR_NO_MODIFY_PATH=1` | (Windows) leave PATH unchanged |

The old `ASA_*` variables (`ASA_VERSION`, `ASA_HUB_URL`, …) still work; when both are set the new name wins.
Windows Server 2016 / 2019 / 2022 / 2025 (including Server Core) uses the same `windows-x64.exe` and installs the same way.

Example: install on a server, start at boot, report to a Hub:

```bash
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh -s -- --hub https://hub.example.com --key asa_ek_… --service system
```

Platform names: `windows-x64.exe`, `windows-arm64.exe`, `macos-arm64`, `macos-x64`, `linux-x64`, `linux-arm64`.

## Install from the Security Hub

**Keyless (recommended)**: the *keyless install commands* on the Hub's *Add hosts* page have the Hub URL prefilled. Running one sends an
enrollment request and an administrator clicks **Approve** on the same page (or sets auto-approve networks). Computers can also find the Hub
on their own (company DNS SRV record, local network broadcast): `ai-security-monitor enroll --auto`; the desktop app walks you through it on first start.
See [Automatic Hub discovery and keyless enrollment](enrollment.en.md).

```powershell
$env:AI_SECURITY_MONITOR_SERVICE='user'; irm https://hub.example.com/install.ps1 | iex      # Windows (servers: 'system' + administrator PowerShell)
```

```bash
curl -fsSL https://hub.example.com/install.sh | sh -s -- --service user                     # Linux / macOS (servers: --service system)
```

**With an enroll key**:

The Hub's "Add a host" page (`/install`) creates an enroll key and shows commands with the Hub URL and key filled in;
`<hub>/install.sh` and `<hub>/install.ps1` are the same scripts, defaulting to that Hub (the scripts are public and contain no key).
"Settings & keys → Enroll keys" lists how many hosts use each key and when it was last used; revoking a key rejects the hosts that use it.

## Update

<a id="updating"></a>

### Automatic updates (`update.mode`)

One setting per computer, shared by the desktop app and the command line (stored in `config.json` in the config directory):

| Setting | Meaning |
|---|---|
| `off` | Never check. |
| `notify` (default) | Check GitHub Releases once a day (first 2–20 minutes after the service starts, then every 24 hours plus 0–3 hours of jitter); remember a new version (`ai-security-monitor status` shows it), include it in the heartbeat so the Hub's host list shows "New version", and show a notice in the desktop app. **Nothing is installed automatically.** |
| `auto` | Same, and the background service (`watch --service`) downloads the release, verifies `SHA256SUMS`, replaces itself and restarts on the new version; the desktop app downloads it first and installs it when you quit or reopen it. |

```bash
ai-security-monitor config set update.mode auto   # or off / notify
```

- **Who updates what**: the desktop app and its "background reporting" are the same executable, so the **desktop app's updater** owns it (the installers carry a minisign signature that the app checks against its built-in public key); the agent built into the desktop app never updates itself, and `self-update` refuses there (it would replace the desktop app with the command-line build). A separately installed command-line build follows its own `update.mode` / `self-update`.
- **Never installed automatically**: development builds (built from source, `cargo run`) and package-manager installs (`/usr/bin`, Homebrew, Scoop, winget, Chocolatey, Nix, Snap) are only notified; update those with the package manager (a manual `self-update` needs `--force`).
- **Restart**: the Windows service exits with a failure code and its "restart on failure" action brings it back within a minute; systemd (`Restart=on-failure`) and launchd (`KeepAlive`) likewise; sign-in launches (Windows `HKCU\…\Run`, XDG autostart) start the new version and then exit.
- A foreground `watch` (not a service) and `watch --once` never install; they only record that a new version exists.

### Updating by hand

```bash
ai-security-monitor version --check                 # is there a new version? (ai-security-monitor self-update --check works too)
ai-security-monitor self-update --yes               # download, verify against SHA256SUMS, replace in place, restart background services that use this executable
ai-security-monitor self-update --to 0.2.0 --yes    # a specific version (rollback works too)
ai-security-monitor self-update --yes --no-restart  # replace only, don't restart the background service
```

Desktop app: Settings → "Background reporting and automatic updates" → "Check for updates" shows the current and latest versions, "Update now" updates right away (the app reopens and background reporting switches to the new version). A separately installed command-line background service is listed there too, with "Update the command-line build" when it is out of date.

- For the system service (`--system`) run `self-update` as an administrator, or afterwards `ai-security-monitor service restart --system --yes`.
- `SHA256SUMS` is always checked; a release without it, or a hash mismatch, aborts the update.
- A running exe cannot be overwritten on Windows: the old file is renamed to `ai-security-monitor.exe.old-<time>` and removed on the next update.
- When installed somewhere that needs root, such as `/usr/local/bin`, run `sudo ai-security-monitor self-update --yes`.
- `AI_SECURITY_MONITOR_UPDATE_URL` can point at a mirror compatible with the GitHub Releases API (`<url>/latest`, `<url>/tags/v<version>`).

## Upgrading from asa (0.1.x)

From 0.2.0 the executable is called `ai-security-monitor` instead of `asa`; no need to re-enroll:

- Run `asa self-update --yes` (releases also ship `asa-<version>-<platform>` for old versions to find), or re-run the install script above (it installs `ai-security-monitor` and points out an old `asa`).
- On first run the config directory `…/ai-security-agent` moves to `…/ai-security-monitor`; `agent_id`, Hub enrollment, keys, allowlist and baseline carry over, and the `asa` keychain entry is copied to the new name.
  While an old `asa` resident watch is still running (`watch.lock` held), nothing is moved: that run uses the old directory and prints a one-line hint; the following `service install` stops the old version and then moves it. A stale copy that 0.2.0 left in this situation (same `agent_id`, older than the old directory) is renamed to `ai-security-monitor.bak-<time>` and re-synced from the old directory on the next migration.
- Then run `ai-security-monitor service install --yes` (add `--system` for the system service): it removes the old `asa` service / Run value / unit / plist and installs the new names.
- `ai-security-monitor mcp install` removes the old `asa` MCP entry before writing the new one.
