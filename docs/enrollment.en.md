# Automatic Hub discovery and keyless enrollment

English | [繁體中文](enrollment.md)

Office computers don't need a key or any manual setup. Once ai-security-monitor (or the desktop app) is installed it finds your company's
Security Hub, sends an *enrollment request*, and is done as soon as an administrator clicks **Approve** in the Hub.
The key-based flow (`enroll <url> --key …`) keeps working unchanged.

## How it works

1. **Find the Hub** (in order; stops at the first source that yields a usable Hub)
   1. An explicit URL: `enroll --hub <url>`, the install command downloaded from the Hub (it has that Hub's URL prefilled), or `AI_SECURITY_MONITOR_HUB_URL`
   2. The company DNS SRV record `_ai-security-monitor._tcp.<company domain>`, using the computer's own DNS search domains (Windows DNS suffixes, Linux `/etc/resolv.conf`, macOS `scutil --dns`)
   3. Local network broadcast (mDNS / DNS-SD) `_ai-security-monitor._tcp.local`, waiting 3 seconds
2. **Make sure it is your company's Hub**: every Hub found must sign a fresh random challenge with its own Ed25519 key. Only verified Hubs are
   listed, together with the Hub **fingerprint** (e.g. `72AS-YEXT-VNGO-NLC5-W2NM`).
3. **Send an enrollment request** with the host name, OS, IPs, version and a random secret that only this computer knows (the Hub stores only its hash).
   The computer and the Hub's admin page show the same **check code** (e.g. `EA2B-3TOV`) so the administrator can tell which computer it is.
4. **The administrator approves**: Hub → *Add hosts → Pending hosts* → **Approve** (multi-select works). Requests from a source IP inside the
   *auto-approve networks* are approved immediately.
5. **Done**: the computer receives an enroll key that belongs to **this computer only** (bound to its agent id — any other agent using it is
   rejected; it is listed and revocable under *Settings & keys → Enroll keys*), registers as usual, pins the Hub fingerprint and starts reporting.

While waiting, `enroll --auto` keeps polling (15 minutes by default, see `--wait`). Interrupting it or timing out is fine: running
`enroll --auto` again, or the installed background service (`watch`), continues waiting and starts reporting once approved.
Requests that nobody handles expire after 7 days.

## What the administrator does

1. Open the Hub's *Add hosts* page and note the **Hub fingerprint** at the top (tell your colleagues so they can compare).
2. Make the Hub findable — any one of these is enough:
   - **Simplest**: hand out the *keyless install commands* from that page (they contain this Hub's URL), or download the prefilled `install.ps1` / `install.sh` and run it with your software-deployment tool.
   - **Company DNS**: add the SRV (+ TXT) record, see *DNS SRV record* below.
   - **Local network broadcast**: the server edition of the Hub advertises by default; if the Hub runs in Docker see *mDNS advertising* below.
3. (Optional) Fill in *auto-approve networks* with your office ranges, e.g. `192.168.10.0/24`, `10.20.0.0/16`. Requests from those networks are
   approved immediately; empty = every request needs a manual approval. Only the real TCP source address counts; behind a reverse proxy set
   `AI_SECURITY_MONITOR_HUB_TRUST_PROXY=1` so the proxy's `X-Forwarded-For` is used instead.
4. When requests arrive, *Add hosts* in the sidebar shows a count. Check host name, IP and check code, then click **Approve** or **Reject**.
   Approvals, rejections, auto-approvals and changes to the networks are written to the audit log.

## What the office user does

- **Desktop app**: on first start, with no Hub configured, it opens *Find your company's Security Hub* → compare the fingerprint with the one
  your administrator gave you → **Request to join** → wait for approval. If nothing is found, type the URL your administrator gave you.
  *Settings* has the same options plus *Test connection*, *I have an enroll key*, *Leave this Hub*, and the two start-at-login switches.
- **Command line**:

  ```bash
  ai-security-monitor enroll --auto            # find the Hub, show its fingerprint, confirm, send the request and wait
  ai-security-monitor discover                 # only list the Hubs found
  ai-security-monitor enroll --hub https://hub.example.com   # pick one Hub (when several are found)
  ai-security-monitor service install --yes    # report automatically at startup (works before approval; it keeps waiting)
  ```

- **One-line install** (copied from the Hub's *Add hosts* page — URL prefilled, no key):

  ```powershell
  # Windows PC (PowerShell); for servers use 'system' and an administrator PowerShell
  $env:AI_SECURITY_MONITOR_SERVICE='user'; irm https://hub.example.com/install.ps1 | iex
  ```

  ```bash
  curl -fsSL https://hub.example.com/install.sh | sh -s -- --service user     # servers: --service system
  ```

  The installer sends the request, waits 2 minutes (`AI_SECURITY_MONITOR_ENROLL_WAIT` / `--wait`) and installs the background service either way;
  the service keeps waiting. The generic installer from GitHub has no URL prefilled: add `AI_SECURITY_MONITOR_AUTO_ENROLL=1` (or `--auto-enroll`) to use discovery.

## Hub fingerprint and trust

- A computer remembers the Hub fingerprint the first time it joins (TOFU, trust on first use). If the same URL — or a discovered Hub — later
  presents a different fingerprint, it **stops uploading** and explains that the Hub may have been reinstalled or someone may be impersonating it.
  Joining the new Hub requires an explicit `enroll --auto --repin` (or a new `enroll --key`).
- The approval itself is signed by the Hub; the computer verifies it with the pinned public key and refuses keys from any other Hub.
- Computers that were enrolled with a key before this feature pin the fingerprint the first time they talk to an upgraded Hub.
- The Hub's identity key is generated on first start and stored in the database (`settings` table); restoring a database backup keeps it.
  A fresh install / new database = a new fingerprint, and computers must re-join.
- Plain http is only recommended inside the company network: the fingerprint stops "wrong Hub / fake Hub", but not someone who can tamper with
  network traffic reading http contents. Use https for anything reachable from outside.

## DNS SRV record

Name `_ai-security-monitor._tcp.<domain>`, pointing at the Hub's host and port. A TXT record with the same name may carry `url=` (the full URL;
computers prefer it) and `fp=` (the Hub fingerprint; mismatches are skipped). Without `url=`: port 443/8443 means https, anything else http
(`proto=https` overrides), and `path=/sub` sets a sub-path.

Windows DNS Server (PowerShell):

```powershell
Add-DnsServerResourceRecord -ZoneName corp.example -Name _ai-security-monitor._tcp -Srv -DomainName hub.corp.example -Port 443 -Priority 0 -Weight 0
Add-DnsServerResourceRecord -ZoneName corp.example -Name _ai-security-monitor._tcp -Txt -DescriptiveText "url=https://hub.corp.example"
Add-DnsServerResourceRecord -ZoneName corp.example -Name _ai-security-monitor._tcp -Txt -DescriptiveText "fp=72AS-YEXT-VNGO-NLC5-W2NM"
```

BIND:

```
_ai-security-monitor._tcp.corp.example. 3600 IN SRV 0 0 443 hub.corp.example.
_ai-security-monitor._tcp.corp.example. 3600 IN TXT "url=https://hub.corp.example" "fp=72AS-YEXT-VNGO-NLC5-W2NM"
```

The Hub's *Add hosts → Automatic discovery* card generates ready-to-copy commands for its own URL and fingerprint. Check with `ai-security-monitor discover --no-mdns`.

## mDNS advertising

- The server edition of the Hub advertises `_ai-security-monitor._tcp` on UDP 5353 by default (`AI_SECURITY_MONITOR_HUB_MDNS=0` turns it off; the
  standalone edition binds 127.0.0.1 and has it off). TXT carries `fp=`, `v=`, `path=`, `proto=`, plus `url=` when
  `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` is set (recommended; computers use it directly).
- **Docker caveat**: Docker Desktop (Windows/macOS) and the default bridge network **do not pass multicast to the LAN**, so advertising from inside
  the container never leaves it. Pick one:
  - Linux host: run the Hub container with `network_mode: host` (drop `ports:` and choose the port with the `PORT` environment variable).
  - Any platform (recommended): on any computer in the LAN (usually the Docker host) run
    `ai-security-monitor hub advertise --url https://hub.corp.example`. It verifies the Hub's identity first and then advertises on its behalf
    (TXT carries `url=`, so it does not have to be the same machine as the Hub). Keep it running with systemd / Task Scheduler, or compose (Linux):

    ```yaml
    services:
      hub-advertise:
        image: debian:bookworm-slim
        network_mode: host
        restart: unless-stopped
        volumes:
          - /usr/local/bin/ai-security-monitor:/usr/local/bin/ai-security-monitor:ro
        command: ["ai-security-monitor", "hub", "advertise", "--url", "https://hub.corp.example"]
    ```

- Firewalls: finding a Hub only sends a multicast query and receives answers (UDP 5353). The advertiser (Hub or `hub advertise`) must accept
  incoming UDP 5353; Windows may show a firewall prompt the first time.
- mDNS only works inside one network segment (one broadcast domain). Across subnets, VPNs or branch offices use DNS SRV or the prefilled install command.

## Hub settings

| Environment variable | Default | Meaning |
|---|---|---|
| `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS` | on | `0` disables keyless enrollment requests (keys only) |
| `AI_SECURITY_MONITOR_HUB_MDNS` | on for server, off for standalone | local network mDNS advertising |
| `AI_SECURITY_MONITOR_HUB_NAME` | `Security Hub` | Hub name shown to computers |
| `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` | – | public URL used by install commands, SRV examples and mDNS `url=` |
| `AI_SECURITY_MONITOR_HUB_TRUST_PROXY` | off | turn on behind a reverse proxy so auto-approve networks see the real client IP |

Abuse limits: at most 120 requests per source IP per 10 minutes and 500 pending requests; 30 wrong poll secrets per 10 minutes block that IP for a
while; the identity endpoint allows 120 requests per minute. API details: [Agent ↔ Hub contract](hub-contract.en.md#keyless-enrollment).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No Security Hub found` | No SRV record, different network segment, or the Hub is in Docker and its broadcast does not leave the container → use `enroll --hub <url>`, or set up SRV / `hub advertise` as above |
| `Found several different Hubs` | More than one Hub on the network (e.g. a test box) → ask for the fingerprint and pick one with `--hub` |
| `The Hub identity fingerprint changed` | The Hub was reinstalled (new database) or someone impersonates it → confirm the new fingerprint with your administrator, then `enroll --auto --repin` |
| `This Hub does not accept keyless enrollment` | The Hub has `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS=0` → ask for an enroll key |
| Auto-approve does nothing | The Hub sits behind a proxy without `TRUST_PROXY` (it sees the proxy's IP), or the networks don't contain the computer's address; the *Source IP* column under *Pending hosts* is what the Hub sees |
