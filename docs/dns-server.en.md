# Protective DNS server

English | [繁體中文](dns-server.md)

`ai-security-monitor dns-server` is a DNS for your **whole LAN**: point computers, phones and IoT devices at it,
and domains listed by threat intel are blocked (answered with "no such domain") while everything else is forwarded
over encrypted DNS and cached. **Optional and off by default**; when it is not running it costs nothing and every other
feature keeps working (each computer's own DNS monitoring and alerts are described in [dns.en.md](dns.en.md)).

| | Default | When off |
|---|---|---|
| Deployment | not started (the compose `dns` service needs `--profile dns`; natively you start it yourself or set `dns.server.enabled`) | no DNS server |
| Hub "Settings & keys → Protective DNS" blocking switch | **off** (forward only) | the server keeps forwarding, it just stops blocking, so devices using it stay online |
| Per computer `dns use-hub` | system DNS untouched | — |

## How it works

```
client → UDP/TCP 53 → LAN only (ACL) → per-client rate limit → blocklist → cache → in-flight coalescing → upstream DoH (HTTP/2)
                                            │                         │hit: only ID and TTL rewritten
                                            └ hit: NXDOMAIN + EDE 15 "Blocked"
```

- **Blocklist**: downloaded, enabled domain feeds whose **license allows commercial use** with confidence ≥ 75 (currently CERT Polska and HaGeZi TIF mini; change the selection or threshold on the Hub), each parsed separately and stored only as 64-bit hashes (2 million entries ≈ 23 MB), plus custom blocks. Non-commercial lists (abuse.ch URLhaus, Phishing Army) only raise alerts and are never used for blocking. The allow list (Hub allow list, built-in known-good domains, a few big sites that often get listed by mistake) wins. Lists are rebuilt in the background every 10 minutes (or after an intel update or a Hub change) and swapped in without locks while serving continues. **At startup it only forwards** until the lists are ready, so a restart interrupts DNS for less than a second.
- **Firefox's encrypted DNS canary** `use-application-dns.net` always gets NXDOMAIN, so Firefox does not bypass it; `--block-private-relay` (Hub "Also block iCloud Private Relay") blocks iCloud Private Relay too.
- **Cache**: stores the upstream's raw response and TTL offsets; a hit rewrites only the ID and TTLs. Negative caching up to 1 hour; popular answers are refreshed before they expire; **when every upstream is down it serves answers expired up to 1 day ago** (RFC 8767) instead of failing.
- **Upstreams**: Quad9 and Cloudflare DoH by default (HTTP/2 connection reuse, connected through built-in IPs so it does not depend on the system DNS), raced 250 ms apart and picked by latency; plain IPs work too (UDP, answers must match the ID and question, TCP on truncation).
- **Safety**: serves only loopback and private ranges (`--acl`) so it never becomes an open resolver; 200 queries per second per client; answers that map public names to private IPs are dropped (DNS rebinding; allow internal domains with `--internal-suffix` or the Hub's "Internal domains"); ANY gets a minimal answer (RFC 8482); EDNS 1232 bytes, larger answers set TC so clients retry over TCP. Binding port 53 on Windows does not need administrator rights, so the server uses `SO_EXCLUSIVEADDRUSE` and no other program can bind the same address to steal queries. DNSSEC is not validated locally in this version; the encrypted upstreams (Quad9, Cloudflare) validate.
- **Logs**: per-minute aggregates by (client, domain, type, result) in `<config dir>/dns-server/dns/` (kept 7 days); when linked to a Hub they are also queued and uploaded in batches, kept while the Hub is unreachable and sent later. Logging uses a bounded queue: under overload it drops log lines, never answers. `--no-log` or turning off "Log queries" on the Hub sends only counters.

## Deployment

### 1. An always-on computer (recommended: sees every device's real IP)

```sh
# without a Hub: downloads its own intel and follows the command line
sudo ai-security-monitor dns-server
# with a Hub: blocking switch, upstreams and lists follow the Hub settings
sudo ai-security-monitor dns-server --hub https://hub.example:8088 --hub-token <dns token>
```

Create the dns token on the Hub under "Settings & keys → API token" with the "Protective DNS server" permission. The background service can also run it (when enrolled it connects to the Hub as this computer, restarts it if it stops and when the settings change):

```sh
ai-security-monitor config set dns.server.enabled true
ai-security-monitor config set dns.server.listen 192.168.1.5:53   # optional
```

Output goes to `<config dir>/dns-server/server.log`. If `0.0.0.0:53` is taken (systemd-resolved on Linux, Internet Connection Sharing on Windows) it binds each interface address instead. For LAN devices to reach it, allow inbound UDP/TCP 53 in this computer's firewall (no prompt appears when the background service starts it):

```powershell
# Windows (administrator PowerShell)
New-NetFirewallRule -DisplayName "AI Security Monitor DNS (UDP)" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow -Profile Private,Domain
New-NetFirewallRule -DisplayName "AI Security Monitor DNS (TCP)" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow -Profile Private,Domain
```

On Linux use `ufw allow 53` or the equivalent nftables rule; the macOS application firewall is off by default; when it is on, allow ai-security-monitor under System Settings → Network → Firewall → Options.

### 2. The Hub's compose

Set `AI_SECURITY_MONITOR_HUB_DNS_TOKEN` (at least 32 characters, shared by the Hub and dns, e.g. `openssl rand -hex 24`) and `AI_SECURITY_MONITOR_HUB_DNS_BIND` (this machine's LAN IP) in `.env`, then add `--profile dns`:

```sh
docker compose -f docker/compose.yml --env-file .env --profile dns up -d
```

The image `ghcr.io/markku636/ai-security-monitor-dns` contains only the musl static binary and CA certificates (FROM scratch, amd64/arm64, runs as nobody). A bridge network hides devices' real IPs (Docker Desktop turns them all into one address); on Linux add `-f docker/compose.dns-host.yml` (host networking) to tell devices apart.

### 3. Point devices at it

- **The whole office**: set the DNS server in the router's DHCP settings to the protective DNS's LAN IP. With IPv6, the router's IPv6 DNS (RDNSS) and DHCPv6 must point there too, or devices bypass it over IPv6.
- **Single computers**: run `ai-security-monitor dns use-hub --yes` as administrator on that computer (addresses come from the Hub's "DNS addresses devices should use", or pass `--server IP`). It first checks that the protective DNS answers; the old settings are saved in `dns/use-hub.json` and `ai-security-monitor dns restore --yes` puts them back. The background service checks every minute and **switches back to the original DNS after 3 failed checks in a row** (with a "Protective DNS unreachable; switched back" notice), so a dead protective DNS never takes the computer offline.

| OS | What `dns use-hub` changes |
|---|---|
| Windows | `Set-DnsClientServerAddress` on every active adapter; DHCP vs static is read from the registry and restored as it was |
| macOS | `networksetup -setdnsservers` on every enabled network service |
| Linux | NetworkManager (`nmcli`, persistent) → systemd-resolved (`resolvectl`, until reboot) → `/etc/resolv.conf` directly |

When the Hub has protective DNS on and "DNS addresses devices should use" filled in, hosts not using it get a `dns.not_protected` (low) notice.

### Testing

```sh
nslookup blocked-test.asm-dns.invalid <DNS IP>   # should return NXDOMAIN
nslookup example.com <DNS IP>                    # should return an answer
ai-security-monitor dns-server --healthcheck --listen <DNS IP>:53
ai-security-monitor dns-server --status          # queries, cache, blocks, latency percentiles, upstreams, Hub link
```

## Managing it from the Hub

"Settings & keys → Protective DNS": blocking switch, pause 5 minutes / 1 hour (countdown, resumes automatically), connected servers (online, queries, cache hit rate, blocks, latency, list size), the most blocked domains and busiest devices of the last 24 hours, recently blocked queries (press "Allow" for false positives), upstreams, blocklists, custom block/allow, internal domains, DNS addresses devices should use. Changes reach the servers with the next heartbeat (within 30 seconds); if the Hub is unreachable the servers keep the last settings they received. The DNS page shows a status line too. API: [hub-contract.en.md](hub-contract.en.md#protective-dns-dns-server---hub).

## Performance

`agent/examples/dnsbench.rs` starts the server (with a local fake upstream, so it measures the server itself) and many clients in one process:

```sh
cargo run --release --example dnsbench -- --seconds 15 --clients 64
```

| Metric | Target | Dev machine (Windows, 32 threads) |
|---|---|---|
| Cache hit + block mix QPS | ≥ 50,000 | about 123,000 |
| Cache hit latency p50 / p99 / p99.9 | p99 < 1 ms | 246 / 563 / 801 µs |
| Cache miss (upstream) p50 / p99 | — | 132 / 190 µs (local fake upstream) |
| Blocklist lookup (2 million entries) | < 1 µs | about 300 ns |
| Blocklist memory / rebuild | — / < 3 s | 23 MB / 0.16 s |
| Process RSS (with the 2-million list and cache) | < 150 MB | about 40 MB |

Clients and server compete for the same CPUs here, so the server alone handles more. The CI `dnsbench` job runs it on a Linux runner for every push and writes the numbers to the job summary; it only fails on severe regressions (about half of the targets).

Design choices:
- Packets are parsed by hand (header, question and OPT only) without building generic DNS objects or allocating strings; fuzzed with 20,000 random inputs.
- Blocklist lookup: the hash's high bits select a bucket (about 16–32 entries), then a binary search inside it, so each label level touches only a few cache lines; checked from the full name upwards (subdomains included).
- Linux uses one `SO_REUSEPORT` socket per core so the kernel spreads the load; Windows/macOS share one socket between several tasks. Windows disables `SIO_UDP_CONNRESET` (otherwise an answer to a closed client port makes the next receive fail).
- The cache is TinyLFU (moka), so a burst of one-off names does not push out popular entries.

## Not in this version

Encrypted client connections (DoH/DoT server side), local DNSSEC validation, RPZ export, high-availability pairs, Safe Search.

## Privacy

DNS logs amount to browsing history. Tell employees before deploying at work; the Hub can turn off "Log queries and upload to the Hub" to keep only counters; logs are kept as long as `AI_SECURITY_MONITOR_HUB_DNS_RAW_DAYS` (default 7 days).
