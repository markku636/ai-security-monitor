#!/bin/sh
# AI Security Monitor (ai-security-monitor) installer for Linux and macOS.
#
#   curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
#   sh install.sh [--version 0.2.0] [--dir DIR] [--hub URL --key KEY] [--service none|user|system]
#
# Environment variables (same meaning as the options; the old ASA_* names still work):
#   AI_SECURITY_MONITOR_VERSION, AI_SECURITY_MONITOR_INSTALL_DIR, AI_SECURITY_MONITOR_HUB_URL,
#   AI_SECURITY_MONITOR_ENROLL_KEY, AI_SECURITY_MONITOR_SERVICE,
#   AI_SECURITY_MONITOR_DOWNLOAD_BASE  mirror that serves ai-security-monitor-<version>-<os>-<arch> and SHA256SUMS
#
# The binary is verified against the release's SHA256SUMS before it is installed.
set -eu

REPO="markku636/ai-security-monitor"
NAME="ai-security-monitor"
VERSION="${AI_SECURITY_MONITOR_VERSION:-${ASA_VERSION:-}}"
DIR="${AI_SECURITY_MONITOR_INSTALL_DIR:-${ASA_INSTALL_DIR:-}}"
HUB="${AI_SECURITY_MONITOR_HUB_URL:-${ASA_HUB_URL:-}}"
KEY="${AI_SECURITY_MONITOR_ENROLL_KEY:-${ASA_ENROLL_KEY:-}}"
SERVICE="${AI_SECURITY_MONITOR_SERVICE:-${ASA_SERVICE:-none}}"
BASE="${AI_SECURITY_MONITOR_DOWNLOAD_BASE:-${ASA_DOWNLOAD_BASE:-}}"
# Security Hub 提供的 /install.sh 會把自己的網址填在這裡（只給 --key 時註冊到這個 Hub）
DEFAULT_HUB=""

say() { printf 'ai-security-monitor-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --hub) HUB="${2:-}"; shift 2 ;;
    --key) KEY="${2:-}"; shift 2 ;;
    --service) SERVICE="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$SERVICE" in none|user|system) ;; *) die "--service must be none, user or system" ;; esac
if [ -n "$KEY" ] && [ -z "$HUB" ]; then HUB="$DEFAULT_HUB"; fi
if [ -n "$HUB" ] && [ -z "$KEY" ]; then die "--hub needs --key (an enroll key or client key from the Hub)"; fi
if [ -n "$KEY" ] && [ -z "$HUB" ]; then die "--key needs --hub URL"; fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -H 'User-Agent: ai-security-monitor-install' -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "curl or wget is required"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Linux) os=linux; sysdir=/var/lib/ai-security-monitor; legacy_sysdir=/var/lib/asa ;;
  Darwin) os=macos; sysdir="/Library/Application Support/ai-security-monitor"; legacy_sysdir="/Library/Application Support/ai-security-agent" ;;
  *) die "unsupported OS: $os (Windows: use install.ps1)" ;;
esac
case "$arch" in
  x86_64|amd64) arch=x64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported CPU: $arch" ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -z "$VERSION" ]; then
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json"
  VERSION=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)
  [ -n "$VERSION" ] || die "could not find the latest release"
fi
VERSION=${VERSION#v}
asset="$NAME-$VERSION-$os-$arch"
[ -n "$BASE" ] || BASE="https://github.com/$REPO/releases/download/v$VERSION"

say "downloading $asset from $BASE"
fetch "$BASE/$asset" "$tmp/$NAME"
fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS"
expected=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print tolower($1); exit } }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual=$(sha256 "$tmp/$NAME")
[ "$expected" = "$actual" ] || die "SHA256 mismatch for $asset (expected $expected, got $actual)"
chmod 755 "$tmp/$NAME"

if [ -z "$DIR" ]; then
  if [ "$(id -u)" = 0 ] || [ -w /usr/local/bin ]; then DIR=/usr/local/bin; else DIR="$HOME/.local/bin"; fi
fi
SUDO=""
mkdir -p "$DIR" 2>/dev/null || true
if [ ! -w "$DIR" ]; then
  command -v sudo >/dev/null 2>&1 || die "$DIR is not writable"
  SUDO=sudo
  $SUDO mkdir -p "$DIR"
fi
$SUDO mv -f "$tmp/$NAME" "$DIR/$NAME"
bin="$DIR/$NAME"
say "installed $bin ($("$bin" version))"
case ":$PATH:" in *":$DIR:"*) ;; *) say "add $DIR to your PATH to run $NAME directly" ;; esac

# 改名前（0.1.x）的 asa：新版的 service install 會移除舊的 asa 服務；舊執行檔留著不動
for old in /usr/local/bin/asa "$HOME/.local/bin/asa" "$DIR/asa"; do
  if [ -f "$old" ]; then
    say "found the previous version at $old (asa); '$NAME service install' replaces its start-at-boot entry, then you can delete it"
    break
  fi
done

ROOT=""
if [ "$SERVICE" = system ] && [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "--service system needs root (sudo)"
  ROOT=sudo
fi

if [ "$SERVICE" = system ]; then
  # 改名前的系統設定目錄：先複製到新位置（保留 agent_id 與註冊；舊服務在 service install 時移除）
  if [ ! -e "$sysdir" ] && [ -d "$legacy_sysdir" ]; then
    say "copying $legacy_sysdir to $sysdir"
    $ROOT cp -a "$legacy_sysdir" "$sysdir"
  fi
  # 系統服務用系統設定目錄與檔案密鑰庫：直接註冊到那裡
  if [ -n "$HUB" ]; then
    $ROOT "$bin" --config-dir "$sysdir" --secrets-backend file enroll "$HUB" --key "$KEY"
  fi
  $ROOT "$bin" --config-dir "$sysdir" service install --system --yes
else
  if [ -n "$HUB" ]; then "$bin" enroll "$HUB" --key "$KEY"; fi
  if [ "$SERVICE" = user ]; then "$bin" service install --yes; fi
fi
say "done. Next: $NAME doctor · $NAME scan · $NAME service status"
