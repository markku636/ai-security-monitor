# Firewall, ports and blocking

English | [繁體中文](firewall.md)

```bash
ai-security-monitor fw status                     # backend, on/off, network profiles, default actions
ai-security-monitor fw audit                      # audit: profiles off, inbound allowed by default, allow-all rules, risky services reachable from the network
ai-security-monitor fw list                       # inbound allow rules (--ours: only rules created by ai-security-monitor)
ai-security-monitor ports                         # whether each listening port is really reachable from the network
ai-security-monitor ports --probe 192.168.1.10    # probe a host on your own network (TCP connect; nmap if installed)

ai-security-monitor fw block 203.0.113.66 --reason "C2" --yes   # block (both directions by default)
ai-security-monitor fw unblock 203.0.113.66 --yes
ai-security-monitor fw close-port tcp/6379 --yes  # block inbound connections with the firewall
ai-security-monitor fw open-port tcp/6379 --yes
ai-security-monitor fw sync-blocklist --dry-run   # preview the threat-intel blocklist
ai-security-monitor fw sync-blocklist --yes       # sync (public networks from high-confidence, commercial-use feeds only)
ai-security-monitor fw unblock --all-asa --yes    # remove every rule ai-security-monitor created
ai-security-monitor fw ensure --yes               # re-apply from the desired state (needed after boot for pf / nftables)
```

## Backends

| Platform | Read | Write |
|---|---|---|
| Windows | one PowerShell call for profiles, active network category, inbound allow rules and their port/program/address filters | NetSecurity rules in group `ASA`, named `ASA: …`, up to 500 addresses per rule |
| macOS | application firewall, stealth mode, pf | pf anchor `com.asa` (tables `asa_block`, `asa_in`, `asa_out`, `asa_feed`), inserted into `/etc/pf.conf` between `# asa-begin / asa-end` markers |
| Linux | detects firewalld → ufw → nftables → iptables | its own `table inet asa` when nft exists (coexists with ufw/firewalld), otherwise iptables + ipset |

`ai-security-monitor fw audit` and the `firewall` and `ports` scanners produce findings (e.g. `ports.exposed_open` — Redis 6379 reachable from the network).

## Safety

- **Preview without `--yes`**: shows the exact commands that would run; `--dry-run` does the same.
- **Needs admin rights**: without them the same command is re-run elevated (Windows UAC, Linux pkexec/sudo, macOS admin password); **never elevates silently**.
- **Only touches its own rules**: every rule carries the `ASA` marker; `unblock --all-asa` only removes what ai-security-monitor created. These object names (Windows group `ASA`, `ASA: …` rules, nft `table inet asa`, ipsets `asa_*`, pf anchor `com.asa`) intentionally survived the rename, so rules created by 0.1.x are still recognised and removed.
- **Desired state**: `<config dir>/firewall/desired.json` records what is blocked, which ports are closed and which intel networks are synced;
  pf and nftables do not persist across reboots, so `ai-security-monitor fw ensure` re-applies from this file (the resident service does this at startup).
- **Intel blocklist selection**: confidence ≥ 80 (`--min-confidence`), public networks only, at least /10 for IPv4 and /19 for IPv6, excluding local addresses / allowlist / known-good,
  excluding Tor (informational) and non-commercial feeds (DShield, unless allowed in config), overlapping networks merged; above the backend limit (10,000 on Windows) higher-confidence feeds win.
- **Remote blocks**: block actions approved on the Hub are sent HMAC-signed; the agent verifies the signature and host identity and only runs them with `--accept-remote-actions` (see [hub-contract.en.md](hub-contract.en.md)).

CI really blocks, closes a port, lists and cleans up on ephemeral runners on all three platforms, checking that the rules take effect and are removed.
