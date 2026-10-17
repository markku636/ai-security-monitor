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
