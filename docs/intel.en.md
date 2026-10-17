# Connection verdicts and threat intel

English | [繁體中文](intel.md)

asa rates every connection on four levels — **safe / unknown / suspicious / dangerous** — and lists the reason and data source behind each rating.

```bash
asa intel update                    # download / refresh intel (stale feeds only; --force refetches all)
asa intel status                    # entries, last update and status per feed
asa intel sources                   # every feed: vendor, license, URL
asa intel lookup 203.0.113.66       # look up an IP or domain: feed hits, country/ASN, verdict
asa intel lookup 1.2.3.4 --online   # also query online reputation services that have a key
asa connections --intel             # current connections with country/org
asa connections --direction inbound --verdict suspicious,dangerous
```

## Direction

| Direction | Meaning |
|---|---|
| outbound | this machine connects out |
| inbound | a remote host connects to a port this machine listens on |
| listening | ports open on this machine (whether they are reachable from the network is decided separately, see [firewall.en.md](firewall.en.md)) |
| local | both ends are this machine |

## Rules

1. On the allowlist (`asa allowlist add …`) → **safe** (explicit user decision).
2. Any intel hit with confidence ≥ 80, or an online reputation score ≥ 75 → **dangerous**.
3. Any intel hit with lower confidence, reputation ≥ 40, one strong anomaly, or two or more anomalies → **suspicious**.
   Strong anomalies: programs running from temp/download folders, shells or script hosts (PowerShell, cmd, bash, python, mshta, rundll32, …) with network connections, periodic beacons, brute-force sources.
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
| abuse.ch URLhaus | domain | outbound | 80 | on | CC0 |
| abuse.ch ThreatFox | IP:port | outbound | 85 | on | CC0 |
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

- Downloads use ETag/Last-Modified and only fetch stale feeds; HTML error pages, empty lists or files over 96 MB never overwrite existing data.
- Custom feeds: `<config dir>/feeds/custom.json` (https only); `asa intel enable|disable <id>` toggles feeds.
- Online reputation: `asa intel key set abuseipdb -` (reads the key from stdin, stored in the keychain); results are cached for 24 hours with a daily quota.
- The Hub IP page (`/ip/<ip>`) adds "External threat intel": when an admin clicks Look up, the hub queries AbuseIPDB, GreyNoise, IPinfo, proxycheck.io and reverse DNS, and combines them with the blocklist hits reported by agents into a 0–100 risk score. Score = weighted signals (Spamhaus 30, IPsum 25, FireHOL 20, other blocklists 20, AbuseIPDB 25×confidence, GreyNoise malicious 15, proxy/VPN 12, data center 8, Tor 10, GreyNoise benign −20) ÷ 165, then floors (Spamhaus DROP ≥ 85, AbuseIPDB ≥ 90 → ≥ 75, Tor ≥ 40); ≥ 75 critical, ≥ 50 high, ≥ 25 medium. Private/reserved addresses are never sent, and the hub never looks anything up on its own.

## Blocking

Intel can be synced into firewall block rules: `asa fw sync-blocklist --dry-run` shows what would be blocked. Only public, narrow-enough networks are picked, confidence ≥ 80 by default,
excluding Tor, non-commercial feeds (DShield), local addresses, the allowlist and known-good entries. See [firewall.en.md](firewall.en.md).
