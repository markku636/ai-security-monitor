#!/bin/sh
# Security Hub 容器入口：檢查必要設定後啟動 Next.js standalone server。
# 每個設定都接受新名 AI_SECURITY_MONITOR_HUB_* 或舊名 ASA_HUB_*（Hub 本身也是新名優先、讀不到讀舊名）。
set -eu

has_one() {
  name="$1"
  eval "v=\${$name:-}"
  eval "f=\${${name}_FILE:-}"
  [ -n "$v" ] || { [ -n "$f" ] && [ -s "$f" ]; }
}

# has X：AI_SECURITY_MONITOR_HUB_X 或 ASA_HUB_X（含 _FILE）有值
has() {
  has_one "AI_SECURITY_MONITOR_HUB_$1" || has_one "ASA_HUB_$1"
}

if ! has DATABASE_URL; then
  echo "ai-security-monitor-hub: AI_SECURITY_MONITOR_HUB_DATABASE_URL is required (see docker/compose.yml)" >&2
  exit 1
fi

# compose 用 AI_SECURITY_MONITOR_HUB_DB_PASSWORD（或 ASA_HUB_DB_PASSWORD）組連線字串；兩個都沒設時密碼是空的。
case "${AI_SECURITY_MONITOR_HUB_DATABASE_URL:-${ASA_HUB_DATABASE_URL:-}}" in
  *://*:@*)
    echo "ai-security-monitor-hub: the database password is empty — set AI_SECURITY_MONITOR_HUB_DB_PASSWORD in .env" >&2
    exit 1
    ;;
esac

# 沒有管理員金鑰＝開放模式（所有人都是管理員）。容器裡的 127.0.0.1 不是主機的 loopback，
# 所以預設拒絕；真的要（例如只在 docker network 內用）請明確設 AI_SECURITY_MONITOR_HUB_ALLOW_OPEN_MODE=1。
if ! has ADMIN_SECRET; then
  if [ "${AI_SECURITY_MONITOR_HUB_ALLOW_OPEN_MODE:-${ASA_HUB_ALLOW_OPEN_MODE:-}}" != "1" ]; then
    echo "ai-security-monitor-hub: AI_SECURITY_MONITOR_HUB_ADMIN_SECRET is required in Docker (generate one: openssl rand -hex 32)" >&2
    exit 1
  fi
  echo "ai-security-monitor-hub: open mode — every request is admin; keep this container off untrusted networks" >&2
fi

mkdir -p "${HOME:-/data/home}" "${CLAUDE_CONFIG_DIR:-/data/claude}" "${CODEX_HOME:-/data/codex}" 2>/dev/null || true
exec "$@"
