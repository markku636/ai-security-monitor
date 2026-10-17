# Start at boot and background service

English | [繁體中文](service.md)

`ai-security-monitor service` makes `ai-security-monitor watch` (periodic scans, Hub uploads, connection snapshots, heartbeats, remote actions) start automatically in the background at boot or login.

```bash
ai-security-monitor service install                 # per-user: starts at login, no admin needed (PCs)
ai-security-monitor service install --system        # system service: starts at boot, needs admin/root (servers)
ai-security-monitor service install --interval 30m  # full scan interval (default: config scan.interval)
ai-security-monitor service status                  # install state of both scopes and running ai-security-monitor watch processes
ai-security-monitor service logs [--system] [--tail 100]
ai-security-monitor service restart [--system]      # e.g. after ai-security-monitor self-update
ai-security-monitor service uninstall [--system]
```

Without `--yes` it only lists every step it would take (which file it writes, which command it runs) and changes nothing; add `--yes` once you agree.
`--system` without admin rights re-runs the same command elevated (Windows UAC, Linux pkexec/sudo, macOS admin password).

## Per platform

| | System service (`--system`) | Per-user (default) |
|---|---|---|
| Windows | Service Control Manager: `sc.exe create ai-security-monitor … start= auto`, restarts on failure (1, 1, 5 minutes), runs `ai-security-monitor service run` as LocalSystem | The `ai-security-monitor` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; started in the background right away and at every login (it closes its own console window) |
| Linux | `/etc/systemd/system/ai-security-monitor.service` (`Restart=on-failure`, `ProtectSystem=full`, only the config dir writable), enabled and restarted | `~/.config/systemd/user/ai-security-monitor.service` when `systemctl --user` works; otherwise `~/.config/autostart/ai-security-monitor.desktop` (desktop logins) plus an immediate background start |
| macOS | `/Library/LaunchDaemons/dev.ai-security-monitor.agent.plist`, `launchctl bootstrap system` | `~/Library/LaunchAgents/dev.ai-security-monitor.agent.plist`, `launchctl bootstrap gui/<uid>` |

## Config directory and secrets

- Per-user uses your own config directory (`ai-security-monitor config path`) and keychain.
- The system service uses a system directory and always the file secret store (LocalSystem/root have no user keychain):
  Windows `C:\ProgramData\ai-security-monitor`, Linux `/var/lib/ai-security-monitor`, macOS `/Library/Application Support/ai-security-monitor`.
- When installing the system service, if the current user has already run `ai-security-monitor enroll`, the enrollment (agent id, Hub URL, client key, identity token, signing key, allowlist, baseline)
  is copied to the system directory, so the Hub still sees the same host. Otherwise run, as admin, `ai-security-monitor --config-dir <system dir> enroll <HUB_URL> --key …` later.

## The resident process

- Only one resident `ai-security-monitor watch` per config directory (`watch.lock` single-instance lock); a second one logs a line and exits.
- Logs go to `<config dir>/logs/ai-security-monitor-YYYY-MM-DD.log` (UTC date) and are kept for 14 days; service mode does not write to the console.
- On Ctrl-C, SIGTERM (systemd/launchd stop) or a Windows service stop/shutdown it finishes the current step and exits.

## Notes

- Linux per-user (systemd --user) only runs while you are logged in; for servers use `--system`, or `sudo loginctl enable-linger $USER`.
- The Windows Run key allows 260 characters: `--config-dir` is omitted when the config directory is the default, and install warns if the command line is still too long.
- No need to reinstall after upgrading ai-security-monitor; the service points at the ai-security-monitor executable's own path.

## Upgrading from asa (0.1.x)

Start-at-boot entries installed by 0.1.x under the `asa` name (Windows service / Run value `asa`, `asa.service`, `asa.desktop`, launchd `dev.asa.agent`) show up in `service status` as "old version (asa)".
Run `ai-security-monitor service install --yes` once (add `--system` for the system service): it removes the old service, stops the old resident process and installs the new names.
The system config directory (`C:\ProgramData\ai-security-agent`, `/var/lib/asa`, `/Library/Application Support/ai-security-agent`) moves to its new location at the same time, and the Hub still sees the same host.
`uninstall` and `restart` handle the old installation too.
