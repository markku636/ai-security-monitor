# Running the Security Hub with Docker

English | [繁體中文](docker.md)

Hub image: `ghcr.io/markku636/ai-security-monitor-hub` (linux/amd64, linux/arm64). The old name `ghcr.io/markku636/ai-security-agent-hub` keeps receiving the same image for a transition period.

| Tag | Contents |
|---|---|
| `latest`, `<version>` | Hub + Claude Code + Codex CLI (for running AI analysis on the Hub's `/ai` page) |
| `slim`, `<version>-slim` | Hub only (about 700 MB smaller; the `/ai` page reports that no CLI is installed) |

The database is always PostgreSQL (the compose files include `postgres:18-alpine`).

## Standalone (this computer only)

```bash
cp .env.example .env                       # set AI_SECURITY_MONITOR_HUB_ADMIN_SECRET and AI_SECURITY_MONITOR_HUB_DB_PASSWORD (openssl rand -hex 32)
docker compose -f docker/compose.standalone.yml --env-file .env up -d
# open http://127.0.0.1:8088 → sign in with the admin key → "Add a host" to create an enroll key
ai-security-monitor enroll http://127.0.0.1:8088 --key asa_ek_…
ai-security-monitor service install --yes  # report automatically after login
```

It binds to `127.0.0.1` only; other computers cannot reach it.

## Server (the whole fleet reports in)

```bash
cp .env.example .env        # also set AI_SECURITY_MONITOR_HUB_PUBLIC_URL=https://hub.example.com
docker compose -f docker/compose.yml --env-file .env up -d
```

- Published on `0.0.0.0:8088` by default; put it behind a TLS reverse proxy and set `AI_SECURITY_MONITOR_HUB_TRUST_PROXY=1`.
  SSE (`/ai` streaming) needs response buffering off in the proxy (nginx: `proxy_buffering off;`).
- PostgreSQL is not published; it is only reachable inside the compose network.
- Agents install and enroll with the one-liner from `https://hub.example.com/install`.

## Adding protective DNS (optional)

Each file has a variant that includes [protective DNS](dns-server.en.md) (a DNS server that blocks malicious domains): one extra `dns` service, everything else the same, same data.

| Without protective DNS | With protective DNS |
|---|---|
| `compose.standalone.yml` | `compose.standalone.dns.yml` |
| `compose.yml` | `compose.dns.yml` |

```bash
# also set AI_SECURITY_MONITOR_HUB_DNS_TOKEN in .env (openssl rand -hex 24); for the LAN also AI_SECURITY_MONITOR_HUB_DNS_BIND=<this machine's LAN IP>
docker compose -f docker/compose.standalone.dns.yml --env-file .env up -d
# back to the file without protective DNS:
docker compose -f docker/compose.standalone.yml --env-file .env up -d --remove-orphans
```

Blocking switch, pointing devices at it and Linux host networking: see [dns-server.en.md](dns-server.en.md).

## Commercial / non-commercial versions

Some threat intel sources only allow personal or non-profit use (DShield, URLhaus, ThreatFox, …; see the README section [Company or personal use?](../README.en.md#company-or-personal-use-threat-intel-licences)). The Hub defaults to **personal / non-commercial use**; for a company deployment add one more file after any of the compose files above:

| Version | Extra file | Intel the Hub mirrors to computers |
|---|---|---|
| Company / business use | `-f docker/compose.commercial.yml` | Only sources licensed for commercial use |
| Personal / non-commercial use | `-f docker/compose.noncommercial.yml` | Also the non-commercial-only sources |

```bash
docker compose -f docker/compose.yml -f docker/compose.commercial.yml --env-file .env up -d
docker compose -f docker/compose.standalone.dns.yml -f docker/compose.noncommercial.yml --env-file .env up -d
```

With either file the web setting (Threat intel → Threat intel licensing) is locked; without one you choose on the web page. Setting `AI_SECURITY_MONITOR_HUB_INTEL_USAGE=commercial` (or `noncommercial`) in `.env` does the same.

Or use an image with the version built in (locked on the web page): `ghcr.io/markku636/ai-security-monitor-hub:<version>-commercial` (company use) or `:<version>-noncommercial` (personal use); plain `:<version>` follows the web setting (personal use by default). Set `AI_SECURITY_MONITOR_HUB_IMAGE_TAG=<version>-commercial` in `.env` to use it with the compose files.

## Settings

See [.env.example](../.env.example) for the full list. The important ones:

| Variable | Meaning |
|---|---|
| `AI_SECURITY_MONITOR_HUB_ADMIN_SECRET` | **Required.** 127.0.0.1 inside a container is not the host's loopback, so open mode without a key is refused in Docker (set `AI_SECURITY_MONITOR_HUB_ALLOW_OPEN_MODE=1` to override) |
| `AI_SECURITY_MONITOR_HUB_DB_PASSWORD` | **Required.** Used by compose to build `AI_SECURITY_MONITOR_HUB_DATABASE_URL` |
| `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` | Public URL used in install commands and `/install.sh` (also the mDNS `url=`) |
| `AI_SECURITY_MONITOR_HUB_MDNS` | Local network mDNS advertising (on by default for the server edition). **Docker Desktop and bridge networking do not pass multicast to the LAN**: use `network_mode: host` on Linux, or run `ai-security-monitor hub advertise --url <public url>` on any LAN machine, see [enrollment.en.md](enrollment.en.md#mdns-advertising) |
| `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS` | `0` = disable keyless enrollment requests (on by default) |
| `AI_SECURITY_MONITOR_HUB_NAME` | Hub name shown to computers (default Security Hub) |
| `AI_SECURITY_MONITOR_HUB_HOST_PORT` / `AI_SECURITY_MONITOR_HUB_BIND` | Host port (8088) and bind address |
| `AI_SECURITY_MONITOR_HUB_IMAGE_TAG` | Image tag (default `latest`; e.g. `slim`, `0.5.0`) |
| `AI_SECURITY_MONITOR_HUB_ABUSEIPDB_KEY` / `AI_SECURITY_MONITOR_HUB_IPINFO_TOKEN` / `AI_SECURITY_MONITOR_HUB_PROXYCHECK_KEY` / `AI_SECURITY_MONITOR_HUB_GREYNOISE_KEY` | Keys for "External threat intel" on the IP page (optional; can also be set under Settings & keys → Threat intel sources); `AI_SECURITY_MONITOR_HUB_IP_LOOKUPS=off` disables outbound lookups |
| `AI_SECURITY_MONITOR_HUB_VIRUSTOTAL_KEY` / `AI_SECURITY_MONITOR_HUB_OTX_KEY` / `AI_SECURITY_MONITOR_HUB_HACKERTARGET_KEY` | Keys for the passive-DNS lookup under "Domains on this IP" on the IP page (optional; HackerTarget works without a key but allows few lookups a day). Only sent when you press "Look up domains"; not part of the risk score |
| `AI_SECURITY_MONITOR_HUB_SECRETS_KEY` | Encryption key for notification secrets (SMTP passwords, webhook URLs), 32 bytes (`openssl rand -hex 32`); without it the Hub generates one and stores it in the database. Don't change it once set (see [notifications.en.md](notifications.en.md)) |
| `AI_SECURITY_MONITOR_HUB_METRICS_RAW_DAYS` / `AI_SECURITY_MONITOR_HUB_METRICS_HOURLY_DAYS` | How long network traffic / performance data is kept: per-minute raw samples (default 7, 1–90) and hourly rollups (default 90); see [metrics.en.md](metrics.en.md) |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` | For the `/ai` page; without them, sign in with a subscription under *AI assistant → AI accounts* → **Sign in** (or `docker compose exec hub claude auth login`), see [ai-login.en.md](ai-login.en.md); the sign-in is kept in the `/data` volume |

`AI_SECURITY_MONITOR_HUB_ADMIN_SECRET`, `AI_SECURITY_MONITOR_HUB_CLIENT_SECRETS`, `AI_SECURITY_MONITOR_HUB_DATABASE_URL` and `AI_SECURITY_MONITOR_HUB_ACTION_SIGNING_KEY` also accept `<NAME>_FILE` (Docker secrets).

The old `ASA_HUB_*` names still work: compose reads `AI_SECURITY_MONITOR_HUB_*` first and falls back to `ASA_HUB_*`, so an `.env` with only the old names needs no changes. The compose project names (`asa-hub`, `asa-hub-standalone`), volumes and the `asa_hub` database are intentionally unchanged, so data stays in place across the upgrade.

## Update

```bash
docker compose -f docker/compose.yml --env-file .env pull
docker compose -f docker/compose.yml --env-file .env up -d
```

The Hub runs database migrations at startup (with an advisory lock, so two Hubs starting together is safe). Admin pages show a banner when a new version is out (`AI_SECURITY_MONITOR_HUB_UPDATE_CHECK=0` turns that off).

## Backup

All data lives in the PostgreSQL volume:

```bash
docker compose -f docker/compose.yml --env-file .env exec -T postgres pg_dump -U asa_hub asa_hub | gzip > asa-hub-$(date +%F).sql.gz
```

## Build it yourself

```bash
docker build -f docker/Dockerfile -t ai-security-monitor-hub .                 # with AI CLIs
docker build -f docker/Dockerfile --build-arg AI_CLIS= -t ai-security-monitor-hub:slim .
```

The build context is the repo root (the image needs `feeds/` and `scripts/install.*`). The container runs as the `node` user with `/data` as a writable volume, and has a HEALTHCHECK on `/api/health`.
