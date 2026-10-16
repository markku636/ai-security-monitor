#!/bin/sh
# ai-security-agent (asa) installer for Linux and macOS.
#
#   curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh
#   sh install.sh [--version 0.2.0] [--dir DIR] [--hub URL --key KEY] [--service none|user|system]
#
# Environment variables (same meaning as the options):
#   ASA_VERSION, ASA_INSTALL_DIR, ASA_HUB_URL, ASA_ENROLL_KEY, ASA_SERVICE,
#   ASA_DOWNLOAD_BASE  mirror that serves asa-<version>-<os>-<arch> and SHA256SUMS
#
# The binary is verified against the release's SHA256SUMS before it is installed.
set -eu

REPO="markku636/ai-security-agent"
VERSION="${ASA_VERSION:-}"
DIR="${ASA_INSTALL_DIR:-}"
HUB="${ASA_HUB_URL:-}"
KEY="${ASA_ENROLL_KEY:-}"
SERVICE="${ASA_SERVICE:-none}"
BASE="${ASA_DOWNLOAD_BASE:-}"

say() { printf 'asa-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --hub) HUB="${2:-}"; shift 2 ;;
    --key) KEY="${2:-}"; shift 2 ;;
    --service) SERVICE="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$SERVICE" in none|user|system) ;; *) die "--service must be none, user or system" ;; esac
if [ -n "$HUB" ] && [ -z "$KEY" ]; then die "--hub needs --key (an enroll key or client key from the Hub)"; fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -H 'User-Agent: asa-install' -o "$2" "$1"
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
  Linux) os=linux; sysdir=/var/lib/asa ;;
  Darwin) os=macos; sysdir="/Library/Application Support/ai-security-agent" ;;
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
asset="asa-$VERSION-$os-$arch"
[ -n "$BASE" ] || BASE="https://github.com/$REPO/releases/download/v$VERSION"

say "downloading $asset from $BASE"
fetch "$BASE/$asset" "$tmp/asa"
fetch "$BASE/SHA256SUMS" "$tmp/SHA256SUMS"
expected=$(awk -v n="$asset" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print tolower($1); exit } }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual=$(sha256 "$tmp/asa")
[ "$expected" = "$actual" ] || die "SHA256 mismatch for $asset (expected $expected, got $actual)"
chmod 755 "$tmp/asa"

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
$SUDO mv -f "$tmp/asa" "$DIR/asa"
asa="$DIR/asa"
say "installed $asa ($("$asa" version))"
case ":$PATH:" in *":$DIR:"*) ;; *) say "add $DIR to your PATH to run asa directly" ;; esac

ROOT=""
if [ "$SERVICE" = system ] && [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "--service system needs root (sudo)"
  ROOT=sudo
fi

if [ "$SERVICE" = system ]; then
  # 系統服務用系統設定目錄與檔案密鑰庫：直接註冊到那裡
  if [ -n "$HUB" ]; then
    $ROOT "$asa" --config-dir "$sysdir" --secrets-backend file enroll "$HUB" --key "$KEY"
  fi
  $ROOT "$asa" --config-dir "$sysdir" service install --system --yes
else
  if [ -n "$HUB" ]; then "$asa" enroll "$HUB" --key "$KEY"; fi
  if [ "$SERVICE" = user ]; then "$asa" service install --yes; fi
fi
say "done. Next: asa doctor · asa scan · asa service status"
