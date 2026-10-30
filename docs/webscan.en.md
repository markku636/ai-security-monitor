# Website scanning

English | [繁體中文](webscan.md)

The Security Hub's website scanning checks **your own websites**: manually ask several open-source scanners
to look for known vulnerabilities, certificate and configuration problems. The results are merged into one findings list, and each
new scan works out what was fixed and what came back.
**Optional and off by default**: `compose.yml` / `compose.standalone.yml` have no scanner; use `compose.webscan.yml` /
`compose.standalone.webscan.yml`, which include it.

> Only scan sites you own or have written permission to test. Actively probing someone else's systems may be illegal; the Hub
> runs scans only when requested by an administrator.

| | Default | Notes |
|---|---|---|
| Scanner (webscan runner) | not started | A separate container: picks up jobs from the Hub, runs the scanners, sends raw output and results back |
| Passive checks | manual | A few browser-like requests: certificate, headers, technologies |
| Active scans | manual; no ownership proof required | Probe requests for known vulnerabilities and misconfigurations; no injection, no DoS, no fuzzing |
| Internal sites | always blocked | Allowed once an administrator adds the range under Settings & keys → Website scanning |

## How it works

```
admin ── adds a URL ──▶ Hub: DNS lookup only, screens the addresses (forbidden ranges, internal allowlist)
                        │ creates a scan job: the screened addresses are pinned into the job
                        ▼
scanner ── claims jobs (only for scanners it has) ──▶ screens the scope again ──▶ runs scanners against the pinned addresses only
   │                                                                             │
   └── heartbeat every 40 s renews the lease ◀───────────────────────────────────┘
   └── uploads each scanner's raw output ──▶ reports completion ──▶ Hub parses, deduplicates, compares with the last scan
```

- **The Hub itself never connects to your websites** and needs no Docker access; all traffic to the sites comes from the scanner.
- Jobs are leased: if a scanner misses heartbeats for 2 minutes the job goes back to the queue (up to 3 attempts); a job nobody
  claims within 24 hours expires. Several scanners can share one job pool without duplicates (PostgreSQL `FOR UPDATE SKIP LOCKED`).
- Raw output (gzip) is stored in the Hub database for 30 days by default (`AI_SECURITY_MONITOR_HUB_WEBSCAN_ARTIFACT_DAYS`), so it
  can be re-parsed when the parsers improve. Findings are never pruned.

## Manual checks

Add a target, open its page, and click **Active check (manual)**. No DNS, file or meta ownership proof is required. Jobs start only when requested; an offline runner leaves them queued.

## Scope and safety guardrails

| Guardrail | How |
|---|---|
| Always-forbidden addresses | loopback, link-local, cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`…), multicast, reserved / documentation ranges, translation ranges with embedded IPv4 (6to4, NAT64, Teredo), the Hub's and the scanner's own addresses; names such as `localhost`, `metadata.google.internal`, `hub`, `postgres` |
| Internal ranges | 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7 only when on the allowlist |
| The whole set must pass | When a name resolves to several addresses, one failure rejects the whole set (no picking the good one) |
| Address pinning | Screened addresses are pinned into the job; the scanner's built-in pinned resolver and `--ip` / `-sni` keep every tool on those addresses, so a later DNS change cannot redirect it (DNS rebinding) |
| Option allowlist | Every scanner's options are typed and an unknown field is rejected; the scanner builds each command line from its own allowlist and never splices in strings from the Hub |
| No data to third parties | nuclei runs without interactsh (`-ni`), update checks (`-duc`) or redirects (`-dr`), only http / ssl templates, templates baked into the image and never auto-updated, and without raw request / response in its JSON (`-or`) |
| Network isolation | The scanner sits only on the `edge` network: it can reach the Hub, not PostgreSQL |
| Resource limits | Requests per second, concurrent connections and maximum scan time (adjustable in settings); read-only root filesystem, `cap_drop: ALL`, memory and process limits |

## Scanners

| Scanner | Checks | Level | Licence |
|---|---|---|---|
| [httpx](https://github.com/projectdiscovery/httpx) | Status code, title, server, technologies; sites without HTTPS | passive | MIT |
| [tlsx](https://github.com/projectdiscovery/tlsx) | Expired / expiring, self-signed and mismatched certificates; negotiated TLS version | passive | MIT |
| [nuclei](https://github.com/projectdiscovery/nuclei) + templates | Known vulnerabilities (including CISA KEV CVEs), misconfigurations, exposed files; intrusive / dos / fuzz templates excluded | active | MIT |
| [testssl.sh](https://github.com/testssl/testssl.sh) | Offered protocols and cipher suites, TLS vulnerabilities (Heartbleed, ROBOT…), HSTS | active | GPL-2.0 |

GPL does not forbid commercial use: testssl.sh runs as an unmodified separate program and its licence text ships in the image.
Later releases add wafw00f, checkdmarc, naabu, katana, MDN HTTP Observatory, OWASP ZAP and more; tools whose terms really restrict
commercial use (such as WPScan) follow the "threat-intel usage" switch and are skipped in commercial mode. nmap and sqlmap treat
programs that run them and parse their output as derivative works, so they are not integrated.

### Passive security-header check (httpx)

The httpx step (passive, runs as soon as a site is added) also checks whether the landing page sets the recommended security headers
(Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
Cross-Origin-Opener-Policy) and reports the missing ones as a **single** `Recommended security headers are missing` finding, calling out
version-disclosing headers (such as `X-Powered-By`) too. It only runs on a content page (not a 3xx redirect).

This finding replaces nuclei's `http-missing-security-headers` (one info finding per missing header, which is noisy) and testssl's
`security_headers`. This is a deliberate curation: it reports the core recommended set above; the situational/legacy headers nuclei also
checks (Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies…) are normal to omit on most sites,
so they are not listed separately to avoid false positives. nuclei's `weak-hsts-detect` (HSTS present but weak) is a different issue and
is kept. Response headers are captured with httpx `-irh`, but secrets such as `Set-Cookie` and `Authorization` are redacted before the
raw output is uploaded (like nuclei's `-or` — secrets never reach the Hub).

## Example report

Below is a findings list from a real scan of **our own site** `esim.226network.com` (the scanners ran with the same hardened flags as
`web-scan-runner`): the passive fingerprint, the TLS configuration, and the merged, severity-ranked list of findings.

![Example website scan report: a real scan of our own site esim.226network.com, showing the passive fingerprint, TLS configuration and severity-ranked findings](images/webscan-report.png)

This site sits behind Cloudflare with a Vercel origin, so active scanning hits the Cloudflare edge and WAF; the findings cluster around
edge TLS-compatibility settings (weaker cipher suites, weak HSTS) and information disclosure (missing headers, `X-Powered-By`), with no
CVE-class hits — things to tune in Cloudflare, not origin weaknesses.

## Deploy

### On the same machine as the Hub (Docker)

```sh
# Also set AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN in .env (at least 32 characters, shared by the Hub and the scanner, e.g. openssl rand -hex 24)
docker compose -f docker/compose.standalone.webscan.yml --env-file .env up -d   # standalone
docker compose -f docker/compose.webscan.yml --env-file .env up -d              # server
```

It is the same project as the file without website scanning (same name, same data), so you can switch at any time; add
`--remove-orphans` when switching back to remove the scanner.

### On another machine (for example to scan a different internal network)

Create a token with "Website scanner" ticked under Settings & keys → API token on the Hub, then on that machine run:

```sh
docker run -d --init --read-only --tmpfs /work --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --memory 1g \
  -e AI_SECURITY_MONITOR_WEBSCAN_HUB_URL=https://hub.example:8088 \
  -e AI_SECURITY_MONITOR_HUB_WEBSCAN_TOKEN=<webscan token> \
  ghcr.io/markku636/ai-security-monitor-webscan:latest
```

Several scanners can serve one Hub; each only claims jobs its installed scanners can run.

## Regulations (Taiwan)

The annex of Taiwan's Regulations on Classification of Cyber Security Responsibility Levels (amended 7 January 2026) requires
"security testing → vulnerability scanning" of all core systems twice a year for level A, once a year for level B and every two
years for level C, and every level must run vulnerability management (fix or mitigate known weaknesses in time). The website
scanning history (time, target, scanners and versions, findings and their status) can serve as evidence for in-house testing and
vulnerability management; reports say a finding is "mapped to" a requirement, not that a requirement is met.

## API

Formats: [Agent ↔ Hub contract](hub-contract.en.md#website-scanner-web-scan-runner). Admin endpoints: `/api/v1/admin/webscan`
(overview), `…/settings`, `…/targets`, `…/jobs`, `…/jobs/{id}`, `…/artifacts/{id}`, `…/findings`.
