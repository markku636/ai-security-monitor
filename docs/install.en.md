# Install and update

English | [繁體中文](install.md)

## One-line install

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

The Hub's "Add a host" page (`/install`) creates an enroll key and shows commands with the Hub URL and key filled in;
`<hub>/install.sh` and `<hub>/install.ps1` are the same scripts, defaulting to that Hub (the scripts are public and contain no key).
"Settings & keys → Enroll keys" lists how many hosts use each key and when it was last used; revoking a key rejects the hosts that use it.

## Update

```bash
ai-security-monitor self-update --check           # is there a new version? (ai-security-monitor version --check works too)
ai-security-monitor self-update --yes             # download, verify against SHA256SUMS, replace in place
ai-security-monitor self-update --to 0.2.0 --yes  # a specific version (rollback works too)
ai-security-monitor service restart --yes         # switch the resident ai-security-monitor watch to the new version (add --system for the system service)
```

- `SHA256SUMS` is always checked; a release without it, or a hash mismatch, aborts the update.
- A running exe cannot be overwritten on Windows: the old file is renamed to `ai-security-monitor.exe.old-<time>` and removed on the next update.
- When installed somewhere that needs root, such as `/usr/local/bin`, run `sudo ai-security-monitor self-update --yes`.
- `AI_SECURITY_MONITOR_UPDATE_URL` can point at a mirror compatible with the GitHub Releases API (`<url>/latest`, `<url>/tags/v<version>`).

## Upgrading from asa (0.1.x)

From 0.2.0 the executable is called `ai-security-monitor` instead of `asa`; no need to re-enroll:

- Run `asa self-update --yes` (releases also ship `asa-<version>-<platform>` for old versions to find), or re-run the install script above (it installs `ai-security-monitor` and points out an old `asa`).
- On first run the config directory `…/ai-security-agent` moves to `…/ai-security-monitor`; `agent_id`, Hub enrollment, keys, allowlist and baseline carry over, and the `asa` keychain entry is copied to the new name.
- Then run `ai-security-monitor service install --yes` (add `--system` for the system service): it removes the old `asa` service / Run value / unit / plist and installs the new names.
- `ai-security-monitor mcp install` removes the old `asa` MCP entry before writing the new one.
