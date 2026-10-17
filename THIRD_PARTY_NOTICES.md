# Third-party notices

`ai-security-monitor` 本身是 MIT 授權。它**下載並使用**下列第三方資料；資料本身不隨本專案散佈，授權以各來源為準。
每一筆情資命中都會帶出 `vendor` / `license` / `source_url`，請在報告與介面中保留。

| Source | Data | Licence / terms | Notes |
|---|---|---|---|
| Spamhaus DROP / DROPv6 / ASN-DROP | hijacked & criminal netblocks | [Fair Use Policy](https://www.spamhaus.org/blocklists/drop-fair-use-policy/) | free incl. commercial; keep header/timestamps, attribute "Spamhaus" |
| abuse.ch Feodo Tracker / URLhaus / ThreatFox | botnet C2, malware hosts, IOCs | [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) | |
| blocklist.de | fail2ban community reports | [free](https://www.blocklist.de/en/index.html) | |
| CINS Army | poor-reputation IPs | [free, attribution](https://cinsscore.com/#list) | |
| Emerging Threats Open (Proofpoint) | compromised IPs, block list | BSD (ruleset) | block list aggregates Spamhaus + DShield |
| DShield (SANS ISC) | recommended block list | [CC BY-NC-SA 2.5](https://isc.sans.edu/termsofuse.html) | **non-commercial**; alert-only by default |
| Tor Project | exit node list | informational | poll ≥ 30 min; never auto-block |
| IPsum (stamparm) | aggregated scored list | [Unlicense](https://github.com/stamparm/ipsum/blob/master/LICENSE) | |
| FireHOL level1 | aggregate netset | per-source | |
| DB-IP Lite (country / ASN) | IP geolocation | [CC BY 4.0](https://db-ip.com/db/lite.php) | attribution: "IP Geolocation by DB-IP" |
| CISA KEV | known exploited vulnerabilities | public domain (US Gov) | |
| FIRST EPSS | exploit prediction scores | [EPSS user guide](https://www.first.org/epss/user-guide) | attribution |
| NIST NVD | CVE data | [terms of use](https://nvd.nist.gov/developers/terms-of-use) | rate limits apply |
| OSV.dev | open-source vulnerability DB | Apache-2.0 (API) / CC-BY 4.0 (data) | |
| AbuseIPDB / GreyNoise / CrowdSec CTI / AlienVault OTX | IP reputation (API key, opt-in) | each vendor's ToS; community tiers are non-commercial | disabled by default |

Optional rule sets the user may add (not bundled): SigmaHQ (DRL 1.1), Neo23x0 signature-base (DRL), Emerging Threats Suricata rules (BSD). Keep their attribution when importing.

Bundled code in the Hub: country flag SVGs from [`country-flag-icons`](https://gitlab.com/catamphetamine/country-flag-icons) (MIT, © 2020 @catamphetamine).
