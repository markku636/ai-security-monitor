# Start at boot and background service

English | [繁體中文](service.md)

`asa service` makes `asa watch` (periodic scans, Hub uploads, connection snapshots, heartbeats, remote actions) start automatically in the background at boot or login.

```bash
asa service install                 # per-user: starts at login, no admin needed (PCs)
asa service install --system        # system service: starts at boot, needs admin/root (servers)
asa service install --interval 30m  # full scan interval (default: config scan.interval)
asa service status                  # install state of both scopes and running asa watch processes
asa service logs [--system] [--tail 100]
asa service uninstall [--system]
```

Without `--yes` it only lists every step it would take (which file it writes, which command it runs) and changes nothing; add `--yes` once you agree.
`--system` without admin rights re-runs the same command elevated (Windows UAC, Linux pkexec/sudo, macOS admin password).

## Per platform

| | System service (`--system`) | Per-user (default) |
|---|---|---|
| Windows | Service Control Manager: `sc.exe create asa … start= auto`, restarts on failure (1, 1, 5 minutes), runs `asa service run` as LocalSystem | The `asa` value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; started in the background right away and at every login (it closes its own console window) |
| Linux | `/etc/systemd/system/asa.service` (`Restart=on-failure`, `ProtectSystem=full`, only the config dir writable), enabled and restarted | `~/.config/systemd/user/asa.service` when `systemctl --user` works; otherwise `~/.config/autostart/asa.desktop` (desktop logins) plus an immediate background start |
| macOS | `/Library/LaunchDaemons/dev.asa.agent.plist`, `launchctl bootstrap system` | `~/Library/LaunchAgents/dev.asa.agent.plist`, `launchctl bootstrap gui/<uid>` |

## Config directory and secrets

- Per-user uses your own config directory (`asa config path`) and keychain.
- The system service uses a system directory and always the file secret store (LocalSystem/root have no user keychain):
  Windows `C:\ProgramData\ai-security-agent`, Linux `/var/lib/asa`, macOS `/Library/Application Support/ai-security-agent`.
- When installing the system service, if the current user has already run `asa enroll`, the enrollment (agent id, Hub URL, client key, identity token, signing key, allowlist, baseline)
  is copied to the system directory, so the Hub still sees the same host. Otherwise run, as admin, `asa --config-dir <system dir> enroll <HUB_URL> --key …` later.

## The resident process

- Only one resident `asa watch` per config directory (`watch.lock` single-instance lock); a second one logs a line and exits.
- Logs go to `<config dir>/logs/asa-YYYY-MM-DD.log` (UTC date) and are kept for 14 days; service mode does not write to the console.
- On Ctrl-C, SIGTERM (systemd/launchd stop) or a Windows service stop/shutdown it finishes the current step and exits.

## Notes

- Linux per-user (systemd --user) only runs while you are logged in; for servers use `--system`, or `sudo loginctl enable-linger $USER`.
- The Windows Run key allows 260 characters: `--config-dir` is omitted when the config directory is the default, and install warns if the command line is still too long.
- No need to reinstall after upgrading asa; the service points at the asa executable's own path.
