# System hardening checks

English | [繁體中文](hardening.md)

`asa harden` checks this machine's security settings one by one, lists what failed with the current value and how to fix it, and gives a 0–100 score.

```bash
asa harden                       # failures only, with fixes
asa harden --all                 # every check and result
asa harden --category remote     # one category (account, remote, kernel, network, update, encryption, malware, …)
asa --json harden                # for scripts or AI
asa scan --scanners hardening    # into the full report (summaries.hardening); asa watch uploads it to the Hub
```

Everything is read-only; nothing is changed. The 20 Windows checks run in a single PowerShell call (about 3 seconds).

## What is checked

| Platform | Checks |
|---|---|
| Windows (20) | UAC and elevation prompt, Defender real-time / signatures / tamper protection (N/A with third-party AV), SmartScreen, SMBv1 client and server, Remote Desktop NLA, BitLocker / Device Encryption, Secure Boot, LSA protection, WDigest, Guest and built-in Administrator, automatic updates not disabled by policy, AutoRun, LLMNR, PowerShell 2.0, Remote Registry |
| Linux (25) | SSH (root login, password login, empty passwords, X11, MaxAuthTries, fail2ban/CrowdSec/sshguard), kernel settings (ASLR, kptr/dmesg restrictions, unprivileged eBPF, symlink/hardlink protection, suid core dumps, SYN cookies, rp_filter, ICMP redirects), AppArmor/SELinux, UID 0 accounts, empty passwords, sudo NOPASSWD, world-writable PATH dirs, automatic security updates (unattended-upgrades on Debian/Ubuntu, dnf-automatic on RHEL-likes), telnet/FTP/rsh, auditd |
| macOS (15) | Gatekeeper, SIP, FileVault, firewall stealth mode, automatic updates (check, security responses, XProtect data, download), guest, auto-login, password hints, screen lock, Remote Login, sudo NOPASSWD, world-writable PATH dirs |

Whether the firewall is on is checked by the firewall engine (`asa fw audit`), not repeated here.

## Results and score

- **Pass** / **Fail** / **N/A** (e.g. no sshd, Remote Desktop off, third-party antivirus) / **Error**.
- Checks that need administrator or root (e.g. `/etc/shadow`, `/etc/sudoers` on Linux) are N/A without those rights and listed in `needs_admin`.
- Score = passes × 2 ÷ (passes × 2 + failure weight), weighted by severity: critical 4, high 3, medium 2, low 1. The report's "hardening" score uses the same formula; allowlisted failures do not count.
- Every failure becomes a `hardening.<id>` finding with the fix and references.

## Custom checks

Drop `.yml` files into `<config dir>/policies/` (see `asa config path`): the same id replaces a built-in check, `disabled: true` turns one off.

```yaml
# turn off a built-in check
- id: win.llmnr.disabled
  severity: low
  title: { zh: x, en: x }
  probe: { registry: { path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', name: EnableMulticast } }
  expect: { op: eq, value: 0 }
  disabled: true

# add one
- id: lin.custom.no_root_cron
  category: account
  severity: low
  title: { zh: "root 沒有排程工作", en: "root has no crontab" }
  remediation: { zh: "crontab -r -u root", en: "crontab -r -u root" }
  references: [ "https://man7.org/linux/man-pages/man5/crontab.5.html" ]
  probe: { file: /var/spool/cron/crontabs/root }
  expect: { op: empty }
  missing: pass
```

Fields:
- `id`: lowercase letters, digits, `.` `_` `-`; the `win.` / `lin.` / `mac.` prefix picks the platform.
- `probe` (exactly one): `registry {path, name}`, `powershell` (returns one value), `command [program, args…]`, `file`, `sysctl`, `sshd {key, default}`,
  `service {names, query: active|enabled}`, `builtin` (`lsm`, `uid0_accounts`, `empty_passwords`, `sudo_nopasswd`, `path_world_writable`);
  `command` / `file` accept `regex` (first capture group) and `stderr: true`.
- `expect.op`: `eq` `ne` `gte` `lte` `contains` `not_contains` `matches` `in` `not_in` `empty` `not_empty`; comparisons ignore case and `"1"` equals `1`.
- `missing`: result when no value can be read, `pass` / `fail` / `na` (default `na`); `na_values`: values meaning not applicable; `distros`: only on these Linux distributions; `only_if_exists`: N/A when the file is absent.

## References

Checks are based on public guidance from the Microsoft security baselines, CIS Benchmarks recommendations, distribution documentation and Apple Platform Security; each check links to its source.
The policy files are written for this project (MIT); no CIS Benchmark text is copied.
