# DNS defense

English | [繁體中文](dns.md)

DNS is the most common path for malware to find its command server, smuggle data out and send people to fake sites. ai-security-monitor covers it on several levels:

| Level | What it does | Default |
|---|---|---|
| **Each computer: monitoring + alerts** | Records which domains this computer looks up and which program asked; alerts on threat-intel domains, DNS tunnels, generated domains, NXDOMAIN bursts and programs switching to their own encrypted DNS | on (`dns.enabled`) |
| **Each computer: tamper detection** | DNS server changes, tampered hosts file, WPAD, NXDOMAIN redirection, forged answers, unknown encrypted DNS profiles on macOS | on (answer verification is opt-in) |
| **Each computer: anti-bypass + hardening** | `fw dns-lock` blocks programs from talking to outside DNS directly; hardening checks NetBIOS, LLMNR, WPAD, mDNS and more | the lock is applied manually |
| **The whole LAN: protective DNS** | Blocks threat-intel domains, encrypted upstream DNS, caching, managed by the Hub | **off**, see [dns-server.en.md](dns-server.en.md) |

## Live monitoring

The background service (`watch`) records DNS lookups live and writes per-minute aggregates by (domain, type, result, program) to `<config dir>/dns/YYYY-MM-DD.jsonl` (kept 7 days). Events go through a bounded queue: under load it records less, it never slows DNS down.

| OS | Source | Program known? |
|---|---|---|
| Windows | a private DNS Client ETW session (only "query completed" events; system event log settings untouched); without administrator rights, DNS cache snapshots | administrator: ✓ (PID from the event header) |
| Linux | AF_PACKET capture of port 53 answers (root), with a kernel filter that only passes DNS answers | ✓ (the answer's destination port maps to the program) |
| macOS | BPF on every active interface (root) | lookups are made by mDNSResponder, so the connection table infers the program from "resolved IP → who connected to it next" |

```sh
ai-security-monitor dns                 # lookups of the last 15 minutes
ai-security-monitor dns --suspicious    # suspicious ones only
ai-security-monitor dns --process chrome.exe --since 1h
ai-security-monitor dns --follow        # live
ai-security-monitor dns status          # source, event count, last record
```

The connection table (command line and the snapshots uploaded to the Hub) shows the domain each remote IP was last resolved from.

Settings: `dns.enabled` (default on), `dns.upload` (`all`/`alerts`/`off`, default `all`: uploads the records every minute when enrolled).

## Detection rules (`dns` scanner)

Each scan looks at the last 15 minutes in 5-minute windows keyed by (program, registrable domain). Thresholds follow Zeek, Sigma, Splunk ESCU and Elastic rules.

| Rule | Condition | ATT&CK |
|---|---|---|
| `dns.intel_domain` | domain score ≥ 60 (highest source confidence + 10 per extra source); ≥ 80 high, ≥ 90 critical | T1071.004 |
| `dns.tunnel` | one program, one domain, ≥ 100 lookups in 5 minutes with mostly unique, long, random subdomains (high); ≥ 20 lookups with ≥ 30% TXT/NULL (medium) | T1572, T1048.003 |
| `dns.dga` | ≥ 10 non-existent, randomly generated-looking domains (Chromium probe names excluded) | T1568.002 |
| `dns.nxdomain_burst` | ≥ 50 NXDOMAIN answers across ≥ 20 domains | T1568.002 |
| `dns.doh_bypass` | a program other than browsers and the system looks up encrypted DNS endpoints | T1572 |
| `dns.tunnel_service` | Cloudflare Tunnel, Dev Tunnels, ngrok | T1572 |

Allow-listed, known-good and popular domains (Majestic top 10,000) are exempt from heuristic alerts, but never from threat-intel hits with confidence ≥ 70. Registrable domains come from the embedded Public Suffix List (so `github.io` or `duckdns.org` subdomains are not allowed wholesale).

## Blocklist and allowlist (your own domains)

Entries always include subdomains. **Blocklist** = blocked and alerted; **allowlist** = never blocked, no alerts (for threat-intel false positives or internal systems). For the same domain, whichever side was added last wins. Each comes in two lists with the same effect, checked together:

| | This computer's | The Hub's (company-wide) |
|---|---|---|
| Blocklist | `ai-security-monitor dns block bad.example` (several at once, URLs fine, `--note`), the desktop app's Settings → DNS, "Block" on a lookup or "Add to blocklist" in domain analysis | DNS page "Blocklist / allowlist", "Add to blocklist" on a domain page, custom blocks under "Settings & keys → Protective DNS" |
| Allowlist | `dns allow ok.example`, the desktop app's Settings → DNS, "Allow" on a lookup or "Add to allowlist" in domain analysis | DNS page "Blocklist / allowlist", "Add to allowlist" on a domain page, the settings page allowlist |
| Remove | `dns unblock` / `dns unallow`, the desktop app's Settings → DNS or "Remove from blocklist / allowlist" in domain analysis | "Remove from blocklist / allowlist" on the domain page, settings page |
| View | `dns blocklist` (both lists, both sources), the desktop app's Settings → DNS | settings page; counts on the DNS page |

Effects:
- **Every computer alerts on lookups** (`dns.blocklisted`, high), even without the protective DNS; the Hub's list is synced to each computer every 10 minutes.
- **The protective DNS blocks them** (NXDOMAIN): the Hub's list takes effect with the next heartbeat (within 30 seconds); the local list of the computer running the protective DNS within a minute.
- Blocked by mistake? Add it to the allowlist ("Add to allowlist" on the domain page or `dns allow`): never blocked, no alerts. This computer's allowlist is the domain entries of the general `allowlist`; `dns allow` adds both `x` and `*.x`.

## Tamper detection

| Rule | Meaning |
|---|---|
| `dns.resolver_changed` | DNS server baselines per network (by the gateway's subnet), so laptops changing networks do not alert; an unknown public DNS = medium, a threat-intel listed one = high. If it is fine, run `ai-security-monitor dns accept` on that computer |
| `dns.resolver_intel` | the DNS server in use is listed by threat intel |
| `dns.hosts_tampered` | the hosts file sends popular sites to fixed addresses, blocks antivirus or update domains, or has a wpad entry (ad-blocking `0.0.0.0` entries are fine; whether it changed at all is file integrity monitoring's job) |
| `dns.wpad` | `wpad.*` lookups get an answer (can be used to intercept traffic) |
| `dns.nxdomain_hijack` | every 6 hours per network, 3 random non-existent names are looked up; ≥ 2 answering the same address = the DNS turns "no such domain" into a redirect |
| `dns.answer_mismatch` | only with `dns.verify_answers=true` (off by default: sends 3 common domains to Cloudflare to compare) |
| `dns.rogue_profile` | an encrypted DNS profile is installed on macOS |
| `dns.not_protected` | the company runs a protective DNS and this computer does not use it (see [dns-server.en.md](dns-server.en.md)) |
| `dns.protect_restored` | the protective DNS stopped answering and the background service switched back to the original DNS |

## Anti-bypass: `fw dns-lock`

```sh
ai-security-monitor fw dns-lock --dry-run            # see the rules first
ai-security-monitor fw dns-lock --block-doh --yes    # block direct outside DNS (53/853) + port 443 of common encrypted DNS providers
ai-security-monitor fw dns-unlock --yes
```

Only allowed DNS servers stay reachable (without `--allow`: the ones in use, always including loopback); if the DNS in use is not allowed it refuses (that would cut off DNS) unless `--force`. Windows blocks the complement of the allow list (block rules win over allow rules), nftables uses a separate `dnslock` chain, iptables + ipset, macOS a pf anchor. Details: [firewall.en.md](firewall.en.md).

## Hardening

Windows: NetBIOS name resolution, smart multi-homed name resolution (DNS leaks on VPN), WPAD, DoH policy (info), mDNS (info), LLMNR. Linux (systemd-resolved): LLMNR, mDNS, DNS over TLS, DNSSEC (the last three info). See [hardening.en.md](hardening.en.md).

## Hub

Sidebar "DNS": query volume, distinct domains, NXDOMAIN share, open DNS alerts, top domains, newly seen domains, recent lookups, each host's DNS monitoring status, protective DNS status. The domain page `/domain/<domain>`: which hosts and programs looked it up, resolved IPs, 7 days of hourly counts, related alerts, threat-intel records. The AI assistant has an "Explain DNS" scope; the Hub MCP has `dns_overview`, `dns_queries`, `domain_summary`.

## Privacy

DNS logs amount to browsing history and only Hub administrators can see them. Tell employees before deploying at work; a computer can set `dns.upload=alerts` (alerts only) or `off`; the Hub keeps them for `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS` (per-minute records, default 7 days) and `_HOURLY_DAYS` (hourly rollups, default 90 days).
