# Running the Security Hub with Docker

English | [繁體中文](docker.md)

Hub image: `ghcr.io/markku636/ai-security-agent-hub` (linux/amd64, linux/arm64).

| Tag | Contents |
|---|---|
| `latest`, `<version>` | Hub + Claude Code + Codex CLI (for running AI analysis on the Hub's `/ai` page) |
| `slim`, `<version>-slim` | Hub only (about 700 MB smaller; the `/ai` page reports that no CLI is installed) |

The database is always PostgreSQL (the compose files include `postgres:18-alpine`).

## Standalone (this computer only)

```bash
cp .env.example .env        # set ASA_HUB_ADMIN_SECRET and ASA_HUB_DB_PASSWORD (openssl rand -hex 32)
docker compose -f docker/compose.standalone.yml --env-file .env up -d
# open http://127.0.0.1:8088 → sign in with the admin key → "Install agent" to create an enroll key
asa enroll http://127.0.0.1:8088 --key asa_ek_…
asa service install --yes   # report automatically after login
```

It binds to `127.0.0.1` only; other computers cannot reach it.

## Server (the whole fleet reports in)

```bash
cp .env.example .env        # also set ASA_HUB_PUBLIC_URL=https://hub.example.com
docker compose -f docker/compose.yml --env-file .env up -d
```

- Published on `0.0.0.0:8088` by default; put it behind a TLS reverse proxy and set `ASA_HUB_TRUST_PROXY=1`.
  SSE (`/ai` streaming) needs response buffering off in the proxy (nginx: `proxy_buffering off;`).
- PostgreSQL is not published; it is only reachable inside the compose network.
- Agents install and enroll with the one-liner from `https://hub.example.com/install`.

## Settings

See [.env.example](../.env.example) for the full list. The important ones:

| Variable | Meaning |
|---|---|
| `ASA_HUB_ADMIN_SECRET` | **Required.** 127.0.0.1 inside a container is not the host's loopback, so open mode without a key is refused in Docker (set `ASA_HUB_ALLOW_OPEN_MODE=1` to override) |
| `ASA_HUB_DB_PASSWORD` | **Required.** Used by compose to build `ASA_HUB_DATABASE_URL` |
| `ASA_HUB_PUBLIC_URL` | Public URL used in install commands and `/install.sh` |
| `ASA_HUB_HOST_PORT` / `ASA_HUB_BIND` | Host port (8088) and bind address |
| `ASA_HUB_IMAGE_TAG` | Image tag (default `latest`; e.g. `slim`, `0.1.0`) |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` / `OPENAI_API_KEY` | For the `/ai` page; or sign in with `docker compose exec hub claude` — the login is kept in the `/data` volume |

`ASA_HUB_ADMIN_SECRET`, `ASA_HUB_CLIENT_SECRETS`, `ASA_HUB_DATABASE_URL` and `ASA_HUB_ACTION_SIGNING_KEY` also accept `<NAME>_FILE` (Docker secrets).

## Update

```bash
docker compose -f docker/compose.yml --env-file .env pull
docker compose -f docker/compose.yml --env-file .env up -d
```

The Hub runs database migrations at startup (with an advisory lock, so two Hubs starting together is safe). Admin pages show a banner when a new version is out (`ASA_HUB_UPDATE_CHECK=0` turns that off).

## Backup

All data lives in the PostgreSQL volume:

```bash
docker compose -f docker/compose.yml --env-file .env exec -T postgres pg_dump -U asa_hub asa_hub | gzip > asa-hub-$(date +%F).sql.gz
```

## Build it yourself

```bash
docker build -f docker/Dockerfile -t ai-security-agent-hub .                 # with AI CLIs
docker build -f docker/Dockerfile --build-arg AI_CLIS= -t ai-security-agent-hub:slim .
```

The build context is the repo root (the image needs `feeds/` and `scripts/install.*`). The container runs as the `node` user with `/data` as a writable volume, and has a HEALTHCHECK on `/api/health`.
