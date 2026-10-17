# Connection verdicts and threat intel

English | [繁體中文](intel.md)

ai-security-monitor rates every connection on four levels — **safe / unknown / suspicious / dangerous** — and lists the reason and data source behind each rating.

```bash
ai-security-monitor intel update                   # download / refresh intel (stale feeds only; --force refetches all)
ai-security-monitor intel status                   # entries, last update and status per feed
ai-security-monitor intel sources                  # every feed: vendor, license, URL
ai-security-monitor intel lookup 203.0.113.66      # look up an IP or domain: feed hits, country/ASN, verdict
ai-security-monitor intel lookup 1.2.3.4 --online  # also query online reputation services that have a key
ai-security-monitor connections --intel            # current connections with country/org
ai-security-monitor connections --direction inbound --verdict suspicious,dangerous
```

## Direction

| Direction | Meaning |
|---|---|
| outbound | this machine connects out |
| inbound | a remote host connects to a port this machine listens on |
| listening | ports open on this machine (whether they are reachable from the network is decided separately, see [firewall.en.md](firewall.en.md)) |
| local | both ends are this machine |

## Rules

1. On the allowlist (`ai-security-monitor allowlist add …`) → **safe** (explicit user decision).
2. Any intel hit with confidence ≥ 80, or an online reputation score ≥ 75 → **dangerous**.
3. Any intel hit with lower confidence, reputation ≥ 40, one strong anomaly, or two or more anomalies → **suspicious**.
   Strong anomalies: programs running from temp/download folders, shells or script hosts (PowerShell, cmd, bash, python, mshta, rundll32, …) with network connections, periodic beacons, brute-force sources.
   A periodic connection (beacon) only counts when the period is measurable: at least 3 snapshot intervals (3 minutes with one-minute snapshots). Periodic connections to known-good services, or from everyday clients such as browsers, VS Code/Cursor, Claude/Codex, Teams, Slack and OneDrive, are keep-alive and polling, not suspicious. Generic runtimes such as node, python and PowerShell are still checked.
   Other anomalies: risky ports (4444, Tor 9001, mining 3333, Telnet, RDP, SMB, Redis, …), never-seen destinations, listeners exposed to the network, and so on.
4. Known-good (public DNS, OS update CDNs and similar, each with a source), private networks or loopback with no anomaly → **safe**.
5. Everything else → **unknown**. Talking to an unlisted IP is not evidence of a problem.

Every intel hit carries the feed id, name, vendor, confidence, license (commercial use allowed, attribution required), fetch time, source URL and the matched entry.
The Hub and MCP answers cite `source_url`, and the AI is told never to invent sources.

## Feeds

| Feed | Kind | Direction | Confidence | Default | License |
|---|---|---|---|---|---|
| Spamhaus DROP v4/v6, ASN-DROP | network / ASN | both | 95 / 90 | on | commercial use, attribution |
| abuse.ch Feodo Tracker | IP (C2) | outbound | 90 | on | CC0 |
| abuse.ch URLhaus | domain (domain-level hits 40) | outbound | 80 | on | **not-for-profit**: alert only, never auto-blocked |
| abuse.ch ThreatFox | IP:port | outbound | 85 | on | **not-for-profit**: alert only, never auto-blocked |
| CERT Polska warning list | domain (incl. subdomains) | outbound | 85 | on | commercial use OK |
| HaGeZi Threat Intelligence Feeds mini (medium / full off by default) | domain (incl. subdomains) | outbound | 75 (65 / 55) | on | GPL-3.0, mirrored unmodified |
| Phishing.Database | domain (exact match) | outbound | 60 | on | MIT |
| Block List Project (phishing / ransomware), Phishing Army | domain | outbound | 40 / 65 | off | Unlicense / upstream terms apply |
| HaGeZi encrypted DNS endpoints | DoH/DoT domains | — | — | on | GPL-3.0; **not a threat list**, only for DNS-bypass detection |
| blocklist.de (all; ssh and bruteforcelogin off by default) | IP | inbound | 70–75 | on | free, attribution |
| CINS Army | IP | inbound | 70 | on | free, attribution |
| Proofpoint ET Open (compromised; block off by default) | IP / network | both | 75 | on | BSD / MIT |
| SANS ISC DShield | network | inbound | 70 | on | **non-commercial**: alerts only, not blocked by default |
| Tor exit nodes | IP | both | 20 | on | informational, **never blocked automatically** |
| IPsum | IP | both | 40 + 10 × times listed (max 95) | on | Unlicense |
| FireHOL level1 | network | both | 80 | on | per upstream source |
| DB-IP country / ASN lite | geo | — | — | on | CC BY 4.0, attribution |
| CISA KEV, OSV (for vulnerabilities, see [vuln.en.md](vuln.en.md)) | CVE | — | — | on | public domain / per source |
| AbuseIPDB, GreyNoise, CrowdSec CTI, OTX | online lookup | — | 70–85 | **off** (bring your own key) | community tiers, non-commercial |

See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for full license details.

Since 2025-11-04 the abuse.ch terms of use restrict free use to not-for-profit purposes (commercial use needs a Spamhaus subscription), so URLhaus and ThreatFox are now marked non-commercial (still alerting, never auto-blocked). Feodo Tracker's own page still says CC0, so it is unchanged.

### Domains

- Domain lists (hosts, one domain per line, `*.x` wildcards, adblock `||x^`) are stored as 64-bit hashes only: about 6 MB of memory for 500k entries.
- Each feed states whether its entries cover subdomains: CERT.PL and HaGeZi do; Phishing.Database and Block List Project match exactly.
- Domain score = the highest feed confidence, +10 for each additional distinct feed (max 100); popular domains (embedded Majestic Million top 10k, CC BY 3.0) lose 30 only when the best hit is below 70. ≥ 80 dangerous, 60–79 suspicious.
- `intel lookup <domain>` also shows the registrable domain (Public Suffix List, MPL-2.0), whether it is popular, whether it looks machine-generated (DGA, character-bigram model), and whether it is an encrypted DNS endpoint.
- Refresh the embedded data with `node scripts/update-dns-data.mjs`.

- Downloads use ETag/Last-Modified and only fetch stale feeds; HTML error pages, empty lists or files over 96 MB never overwrite existing data.
- Custom feeds: `<config dir>/feeds/custom.json` (https only); `ai-security-monitor intel enable|disable <id>` toggles feeds.
- Online reputation: `ai-security-monitor intel key set abuseipdb -` (reads the key from stdin, stored in the keychain); results are cached for 24 hours with a daily quota.
- The Hub IP page (`/ip/<ip>`) adds "External threat intel": when an admin clicks Look up, the hub queries AbuseIPDB, GreyNoise, IPinfo, proxycheck.io and reverse DNS, and combines them with the blocklist hits reported by agents into a 0–100 risk score. Score = weighted signals (Spamhaus 30, IPsum 25, FireHOL 20, other blocklists 20, AbuseIPDB 25×confidence, GreyNoise malicious 15, proxy/VPN 12, data center 8, Tor 10, GreyNoise benign −20) ÷ 165, then floors (Spamhaus DROP ≥ 85, AbuseIPDB ≥ 90 → ≥ 75, Tor ≥ 40); ≥ 75 critical, ≥ 50 high, ≥ 25 medium. Private/reserved addresses are never sent, and the hub never looks anything up on its own.

### Sync (Hub mirror)

- The Hub downloads each list from its vendor on that source's refresh interval and stores the original file unchanged in `/data/feeds/<id>/` (headers and attribution kept; `AI_SECURITY_MONITOR_HUB_FEED_CACHE_DIR` moves it, `AI_SECURITY_MONITOR_HUB_FEED_MIRROR=0` turns background sync off). Only default-enabled, downloadable lists are mirrored; lookup APIs are not.
- Enrolled agents fetch from the Hub first (`GET /api/v1/feeds/manifest`, `/api/v1/feeds/<id>`, ETag = sha256, 304 when unchanged) and fall back to the vendor when the Hub lacks a list or is unreachable; `ai-security-monitor intel update --no-hub` always goes to the vendors.
- The resident `ai-security-monitor watch` checks intel every 30 minutes (each list still downloads only when its own interval is due) and reports its oldest check time and list count in the heartbeat; `--once` does not auto-update.
- "Sync threat intel now" on the Threat intel page makes the Hub refetch every list right away and, for 24 hours, tells hosts that have not updated yet to update on their next heartbeat (`commands: ["refresh_feeds"]` in the response). The page shows each source's last Hub sync and each host's last intel update and source.
- The mirror is served only to agents (client keys), admins and read tokens; the public dashboard cannot download the raw files (vendor-licensed content is not redistributed).

## Blocking

Intel can be synced into firewall block rules: `ai-security-monitor fw sync-blocklist --dry-run` shows what would be blocked. Only public, narrow-enough networks are picked, confidence ≥ 80 by default,
excluding Tor, non-commercial feeds (DShield), local addresses, the allowlist and known-good entries. See [firewall.en.md](firewall.en.md).
