# Third-party notices

`ai-security-monitor` 本身是 MIT 授權。它**下載並使用**下列第三方資料；資料本身不隨本專案散佈，授權以各來源為準。
每一筆情資命中都會帶出 `vendor` / `license` / `source_url`，請在報告與介面中保留。

| Source | Data | Licence / terms | Notes |
|---|---|---|---|
| Spamhaus DROP / DROPv6 / ASN-DROP | hijacked & criminal netblocks | [Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/) | free incl. commercial; keep header/timestamps, attribute "Spamhaus" |
| abuse.ch Feodo Tracker | botnet C2 | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | |
| abuse.ch URLhaus / ThreatFox | malware hosts, IOCs | [abuse.ch terms](https://abuse.ch/terms-of-use/) (since 2025-11-04: free for non-profit use; commercial use via Spamhaus) | marked **non-commercial**: alerts only, never used for blocking or the protective DNS |
| blocklist.de | fail2ban community reports | [free](https://www.blocklist.de/en/index.html) | |
| CINS Army | poor-reputation IPs | [free, attribution](https://cinsscore.com/#list) | |
| Emerging Threats Open (Proofpoint) | compromised IPs, block list | BSD (ruleset) | block list aggregates Spamhaus + DShield |
| DShield (SANS ISC) | recommended block list | [CC BY-NC-SA 2.5](https://isc.sans.edu/termsofuse.html) | **non-commercial**; alert-only by default |
| Tor Project | exit node list | informational | poll ≥ 30 min; never auto-block |
| IPsum (stamparm) | aggregated scored list | [Unlicense](https://github.com/stamparm/ipsum/blob/master/LICENSE) | |
| FireHOL level1 | aggregate netset | per-source | |
| CERT Polska warning list | malicious domains (incl. subdomains) | [terms](https://cert.pl/en/warning-list/) (any use incl. commercial; do not imply endorsement) | |
| HaGeZi DNS blocklists (Threat Intelligence Feeds, DoH) | malicious domains, encrypted DNS endpoints | [GPL-3.0](https://github.com/hagezi/dns-blocklists/blob/main/LICENSE) | mirrored unmodified with its licence, kept as separate files and only combined in memory |
| Phishing.Database | active phishing domains | [MIT](https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE) | alerts only (exact match) |
| The Block List Project (phishing, ransomware) | domains | [Unlicense](https://github.com/blocklistproject/Lists/blob/master/LICENSE) | off by default |
| Phishing Army | phishing domains | upstream sources' terms | off by default; non-commercial |
| Mozilla Public Suffix List | registrable domains (eTLD+1), embedded | [MPL-2.0](https://mozilla.org/MPL/2.0/) | `feeds/dns/public_suffix_list.dat`, unmodified |
| Majestic Million | popular domains (top 10,000), embedded | [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/) | attribution: "Majestic Million, majestic.com"; `feeds/dns/toplist.txt` |
| DB-IP Lite (country / ASN) | IP geolocation | [CC BY 4.0](https://db-ip.com/db/lite.php) | attribution: "IP Geolocation by DB-IP" |
| CISA KEV | known exploited vulnerabilities | public domain (US Gov) | |
| FIRST EPSS | exploit prediction scores | [EPSS user guide](https://www.first.org/epss/user-guide) | attribution |
| NIST NVD | CVE data | [terms of use](https://nvd.nist.gov/developers/terms-of-use) | rate limits apply |
| OSV.dev | open-source vulnerability DB | Apache-2.0 (API) / CC-BY 4.0 (data) | |
| AbuseIPDB / GreyNoise / CrowdSec CTI / AlienVault OTX | IP reputation (API key, opt-in) | each vendor's ToS; community tiers are non-commercial | disabled by default |
| HackerTarget / VirusTotal / AlienVault OTX (Hub "Domains on this IP") | passive DNS: domains seen on an IP | [HackerTarget terms](https://hackertarget.com/terms/), [VirusTotal ToS](https://cloud.google.com/terms/virustotal) (public API: **non-commercial only**), OTX ToS | only sent when an admin presses "Look up domains"; results cached, not redistributed |

Optional rule sets the user may add (not bundled): SigmaHQ (DRL 1.1), Neo23x0 signature-base (DRL), Emerging Threats Suricata rules (BSD). Keep their attribution when importing.

Hub "Attack techniques & compliance": technique IDs and English names from [MITRE ATT&CK®](https://attack.mitre.org/) (© The MITRE Corporation, used under the [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/); ATT&CK is a registered trademark of The MITRE Corporation). The rule → technique / control mapping, Chinese names and summaries are our own; compliance controls are referenced by number with our own short titles only (no standard text is reproduced).

Bundled code in the Hub: country flag SVGs from [`country-flag-icons`](https://gitlab.com/catamphetamine/country-flag-icons) (MIT, © 2020 @catamphetamine).
