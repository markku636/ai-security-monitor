# Events and crash analysis

English | [繁體中文](events.md)

`asa events` turns system logs into "what happened, why it probably happened, and what to do", so you do not have to dig through Event Viewer.

```bash
asa events                 # last 7 days: crashes, security events, most frequent errors
asa events --since 30d     # up to 90 days
asa events crashes         # crashes only (30 days by default)
asa events explain 0x7E    # explain a bugcheck code
asa events explain 4625    # explain an event ID
asa events analyze x.evtx  # analyze an exported file (.evtx, journalctl -o json, .ips/.panic, .dmp)
```

`asa scan` / `asa watch` also run the events scanner (last 7 days); the summary goes into the report's `summaries.events` and is uploaded to Security Hub.

## What is read

| Platform | Sources | Needs administrator |
|---|---|---|
| Windows | System, Application (errors and selected IDs), Security (4625, 4624, 4720, 4722, 4728, 4732, 4756, 4698, 1102; plus 4740, 4771, 4776 for servers with their own 1000-event cap), Defender Operational, TerminalServices-RemoteConnectionManager/Operational (1149); headers of `%SystemRoot%\Minidump\*.dmp` | The Security log and Minidump do; without rights everything else still runs and the report lists `needs_admin` |
| Linux | `journalctl -o json`: priority 0–4, sshd / sudo / useradd / usermod / gpasswd | Membership of `systemd-journal` (or `adm`), or sudo |
| macOS | `/Library/Logs/DiagnosticReports`, `~/Library/Logs/DiagnosticReports` (.panic, .ips) | No |

## Crashes

| Kind | Sources |
|---|---|
| Blue screen | Kernel-Power 41 (BugcheckCode ≠ 0), WER 1001, minidump headers; one blue screen seen in all three counts once and carries likely causes and fixes from `feeds/events/bugchecks.json` |
| Unexpected shutdown | Kernel-Power 41 (code 0), EventLog 6008; a held power button is flagged |
| App crash / hang | Application Error 1000 (program, faulting module, exception code), Application Hang 1002; macOS .ips (bug_type 309) |
| Service failure | Service Control Manager 7000, 7001, 7009, 7011, 7022–7024, 7031, 7034; systemd "Failed with result" |
| Disk / hardware | disk 7/51/153, Ntfs 55, storahci/stornvme 129; WHEA-Logger; Linux I/O errors, MCE |
| Other | Windows Update failures (20), GPU resets (Display 4101), low memory (2004), Linux OOM, kernel panic/oops, segfault |

## Security events

| Rule | Description |
|---|---|
| Brute force | ≥ 10 failed logons from one source within 10 minutes, or ≥ 30 in total (Windows 4625, Kerberos pre-authentication failures 4771 on domain controllers, sshd); public sources carry intel hits and a "block IP" proposed action |
| NTLM failure burst | failed 4776 (Status ≠ 0x0) counted per source workstation with the same thresholds; there is no IP, so no block is proposed |
| Account locked out | 4740 (with the caller computer that triggered the lockout) |
| Remote logon from the internet | 4624 LogonType 10/3, Remote Desktop 1149 (readable without administrator) or sshd "Accepted" from a public IP |
| Accounts and groups | new account (4720, useradd), account enabled (4722), added to an administrators group (4728/4732/4756, sudo/wheel) |
| Persistence | new service (7045; severity from the executable's location: temp or user folders and script hosts → high, system or Program Files → low), scheduled task (4698) |
| Covering tracks | audit log cleared (1102), event log cleared (104) |
| Defender | threat detected (1116/1117), real-time protection turned off (5001) |

Low-severity items (such as a new service installed under Program Files) stay in the summary and do not become findings.

## Limitations

- When a non-administrator reads the Windows Security log, the system just reports "no events found", so asa decides from the current privileges and notes it in `needs_admin`.
- The faulting driver of a blue screen needs a full dump parse; asa reads only the header's code and parameters and leaves the rest to the AI or WinDbg.
- The macOS unified log (`log show`) and security events are not analyzed yet.
