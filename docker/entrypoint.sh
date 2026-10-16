#!/bin/sh
# Security Hub 容器入口：檢查必要設定後啟動 Next.js standalone server。
set -eu

has() {
  name="$1"
  eval "v=\${$name:-}"
  eval "f=\${${name}_FILE:-}"
  [ -n "$v" ] || { [ -n "$f" ] && [ -s "$f" ]; }
}

if ! has ASA_HUB_DATABASE_URL; then
  echo "asa-hub: ASA_HUB_DATABASE_URL is required (see docker/compose.yml)" >&2
  exit 1
fi

# 沒有管理員金鑰＝開放模式（所有人都是管理員）。容器裡的 127.0.0.1 不是主機的 loopback，
# 所以預設拒絕；真的要（例如只在 docker network 內用）請明確設 ASA_HUB_ALLOW_OPEN_MODE=1。
if ! has ASA_HUB_ADMIN_SECRET; then
  if [ "${ASA_HUB_ALLOW_OPEN_MODE:-}" != "1" ]; then
    echo "asa-hub: ASA_HUB_ADMIN_SECRET is required in Docker (generate one: openssl rand -hex 32)" >&2
    exit 1
  fi
  echo "asa-hub: open mode — every request is admin; keep this container off untrusted networks" >&2
fi

mkdir -p "${HOME:-/data/home}" "${CLAUDE_CONFIG_DIR:-/data/claude}" "${CODEX_HOME:-/data/codex}" 2>/dev/null || true
exec "$@"
