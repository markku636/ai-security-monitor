# Install and update

English | [繁體中文](install.md)

## One-line install

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://github.com/markku636/ai-security-agent/releases/latest/download/install.ps1 | iex
```

The script detects the OS and CPU → downloads `asa-<version>-<platform>` → **checks it against the release's `SHA256SUMS` and stops on a mismatch** → installs it → optionally enrolls with a Hub and sets up start at boot.

| Option (sh) / environment variable | Meaning |
|---|---|
| `--version` / `ASA_VERSION` | Version to install (default: latest) |
| `--dir` / `ASA_INSTALL_DIR` | Install location (Linux/macOS: `/usr/local/bin`, or `~/.local/bin` without rights; Windows: `%LOCALAPPDATA%\asa\bin`, added to the user PATH) |
| `--hub URL --key KEY` / `ASA_HUB_URL`, `ASA_ENROLL_KEY` | Enroll with a Security Hub after installing |
| `--service none\|user\|system` / `ASA_SERVICE` | Start at boot (see [service.en.md](service.en.md)); `system` enrolls straight into the system config directory |
| `ASA_DOWNLOAD_BASE` | Internal mirror serving `asa-<version>-<platform>` and `SHA256SUMS` |
| `ASA_NO_MODIFY_PATH=1` | (Windows) leave PATH unchanged |

Example: install on a server, start at boot, report to a Hub:

```bash
curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh -s -- --hub https://hub.example.com --key asa_ek_… --service system
```

Platform names: `windows-x64.exe`, `windows-arm64.exe`, `macos-arm64`, `macos-x64`, `linux-x64`, `linux-arm64`.

## Install from the Security Hub

The Hub's "Install agent" page (`/install`) creates an enroll key and shows commands with the Hub URL and key filled in;
`<hub>/install.sh` and `<hub>/install.ps1` are the same scripts, defaulting to that Hub (the scripts are public and contain no key).
"Admin → Enroll keys" lists how many hosts use each key and when it was last used; revoking a key rejects the hosts that use it.

## Update

```bash
asa self-update --check     # is there a new version? (asa version --check works too)
asa self-update --yes       # download, verify against SHA256SUMS, replace in place
asa self-update --to 0.2.0 --yes   # a specific version (rollback works too)
asa service restart --yes   # switch the resident asa watch to the new version (add --system for the system service)
```

- `SHA256SUMS` is always checked; a release without it, or a hash mismatch, aborts the update.
- A running exe cannot be overwritten on Windows: the old file is renamed to `asa.exe.old-<time>` and removed on the next update.
- When installed somewhere that needs root, such as `/usr/local/bin`, run `sudo asa self-update --yes`.
- `ASA_UPDATE_URL` can point at a mirror compatible with the GitHub Releases API (`<url>/latest`, `<url>/tags/v<version>`).
