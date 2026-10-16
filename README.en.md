# ai-security-agent

[繁體中文](./README.md) · **English**

[![ci](https://github.com/markku636/ai-security-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/markku636/ai-security-agent/actions/workflows/ci.yml)
![platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-informational)
![license](https://img.shields.io/badge/license-MIT-green)

A defensive security agent, **`asa`** (Rust, single binary, Windows / macOS / Linux), plus a **Security Hub** (Next.js + Tailwind + PostgreSQL).
It finds unusual outbound and inbound connections, rates them **safe / unknown / suspicious / dangerous** from public threat intel with the source of every hit,
checks the firewall, open ports, vulnerabilities and system hardening, summarizes traffic and Windows events / crash causes, and hands them to **Claude Code / Codex CLI** for a plain-language read. Both the agent and the Hub are **MCP servers**.

![Security Hub overview](docs/images/overview.png)

## What it is

| | |
|---|---|
| **asa** (agent) | Runs on the computer or server you want to protect. Scans connections, intel, firewall, ports, vulnerabilities, hardening, events and traffic. Use it on its own (CLI, MCP, AI analysis) or enroll it with a Hub to report periodically and accept approved remote blocks. Starts at boot (system service or at user login). |
| **Security Hub** | One place for every host: connection verdicts, findings, vulnerabilities, hardening scores, crashes and security events, threat-intel hits, remote action review, AI analysis and MCP. Standalone (local only) or server (the whole fleet), deployed with Docker. |

## Screenshots

| | |
|---|---|
| ![Connections](docs/images/connections.png) Connections: direction, verdict, process, country/org, reasons and intel sources | ![Host](docs/images/agent.png) One host: five scores, trend, dangerous destinations seen |
| ![Vulnerabilities](docs/images/vulns.png) Vulnerabilities & updates: OS support lifetime, KEV, vulnerable software | ![Hardening](docs/images/hardening.png) Hardening: most common failures and scores by host |
| ![Events](docs/images/events.png) Events & crashes: bugcheck codes with likely causes, brute-force sources | ![Intel](docs/images/intel.png) Threat intel: 26 sources with license, confidence and hits |
| ![Dark](docs/images/agent-hardening-dark.png) Dark mode: each check's current value, expected value and fix | ![Install](docs/images/install.png) Install agent: create an enroll key and get one-line commands |

> The screenshots use demo data from `scripts/demo-seed.mjs` (fictional hosts, documentation IP ranges). The UI is available in Traditional Chinese and English.

## Features

- **Connections and threat intel**: every connection gets a direction (outbound / inbound / listening / local). Open feeds — Spamhaus DROP, abuse.ch (Feodo, URLhaus, ThreatFox), blocklist.de, CINS, ET, DShield, Tor, IPsum, FireHOL and more —
  are combined with behavior anomalies (processes in temp dirs, shells with network connections, risky ports, periodic beacons, new destinations) into safe / unknown / suspicious / dangerous; every hit carries vendor, confidence, license and source URL. Optional online lookups via AbuseIPDB / GreyNoise / CrowdSec (bring your own key).
- **Firewall and exposure**: reads Windows Firewall, macOS pf / application firewall, Linux nftables / firewalld / ufw / iptables, and works out whether each listening port is really reachable from the network;
  `asa fw block` and `asa fw sync-blocklist` turn high-confidence intel into block rules (preview, confirm, reversible; non-commercial feeds only alert by default).
- **Vulnerabilities and updates**: software inventory, OS support lifetime, days since the last Windows update, pending Linux security updates, known-vulnerable versions of common software (WinRAR, 7-Zip, Chrome, …), OSV for Linux packages; CISA KEV matches become critical.
- **System hardening**: 60 cross-platform checks (UAC, Defender, BitLocker, SMBv1, RDP NLA, SSH, kernel settings, AppArmor/SELinux, FileVault, Gatekeeper, …) with a severity-weighted score, customizable in YAML.
- **Traffic**: see which process talks to whom without packet capture (flow-lite); analyze Wireshark / tcpdump pcap/pcapng files: DNS, TLS SNI, plaintext protocols, large uploads, periodic connections.
- **Events and crashes**: Windows event logs, minidump bugcheck codes, WER; Linux journal and macOS crash reports — with likely causes and fixes — plus security events such as brute force, new accounts, new services and cleared audit logs.
- **AI and MCP**: `asa ai ask|analyze` hands off to Claude Code or Codex CLI (read-only tools only); `asa mcp` lets Claude Code / Codex / Cursor / VS Code query this computer directly; the Hub has fleet-level MCP and AI analysis in the browser.
- **Hub**: overview, hosts, connections, findings (bulk actions), vulnerabilities, hardening, traffic, events, intel, remote action review (HMAC-signed, host identity pinning), enroll keys, read-only API tokens, audit log, CSV export, Chinese/English, dark mode, mobile layout.
- **Deploy and update**: start at boot (Windows service / systemd / launchd or per-user), `asa self-update` (verified against SHA256SUMS), one-line install scripts, Hub Docker image (amd64/arm64) and compose files.

## Install

**Agent (asa)**

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-agent/releases/latest/download/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://github.com/markku636/ai-security-agent/releases/latest/download/install.ps1 | iex
```

The script checks the release's `SHA256SUMS` and stops on a mismatch. You can also download the binaries from [Releases](https://github.com/markku636/ai-security-agent/releases). See [docs/install.en.md](docs/install.en.md).

**Security Hub (Docker)**

```bash
git clone https://github.com/markku636/ai-security-agent && cd ai-security-agent
cp .env.example .env    # set ASA_HUB_ADMIN_SECRET and ASA_HUB_DB_PASSWORD
docker compose -f docker/compose.standalone.yml --env-file .env up -d   # standalone: http://127.0.0.1:8088
# server: docker compose -f docker/compose.yml --env-file .env up -d
```

Sign in, open "Install agent" to create an enroll key, and copy the one-line command for each platform. See [docs/docker.en.md](docs/docker.en.md).

## Quick start

```bash
asa doctor                       # environment check: privileges, intel freshness, external tools, Hub connection
asa intel update                 # download threat intel (asa watch keeps it fresh afterwards)
asa connections --intel          # current connections and verdicts
asa scan                         # full scan (connections, intel, firewall, ports, events, vulnerabilities, hardening)
asa fw sync-blocklist --dry-run  # preview which high-confidence intel IPs would be blocked
asa ai ask "Is this computer talking to anything dangerous?"   # let Claude Code / Codex explain
asa enroll https://hub.example.com --key asa_ek_…
asa service install --yes        # report automatically after boot/login (add --system on servers)
```

Every command that changes the system (block an IP, close a port, install a service, update) only previews without `--yes`.

## CLI

| Command | Purpose |
|---|---|
| `scan`, `connections`, `ports` | Full scan, connection verdicts, port reachability |
| `intel` | Update intel, sources and licenses, look up an IP/domain |
| `fw` | Firewall status, audit, block/unblock, intel sync |
| `vuln`, `harden` | Vulnerabilities and updates, system hardening |
| `traffic`, `events` | Traffic and pcap analysis, events and crash causes |
| `ai`, `mcp` | Claude Code / Codex analysis, MCP server and one-step client setup |
| `enroll`, `status`, `watch`, `service` | Hub enrollment, resident reporting, start at boot |
| `self-update`, `version`, `doctor` | Updates and environment checks |
| `allowlist`, `baseline`, `config` | Allowlist, baseline (only show what is new), settings |

Run `asa --help` or `asa <command> --help` for every option; `--lang en` for English, `--json` for scripts.

## Docs

[Install & update](docs/install.en.md) · [Start at boot](docs/service.en.md) · [Docker](docs/docker.en.md) · [MCP & AI](docs/mcp.en.md) · [Traffic](docs/traffic.en.md) · [Events & crashes](docs/events.en.md) ·
[Vulnerabilities](docs/vuln.en.md) · [Hardening](docs/hardening.en.md) · [Agent ↔ Hub contract](docs/hub-contract.en.md) · [Changelog](CHANGELOG.md)

## Build from source

```bash
# agent (Rust 1.85+)
cd agent && cargo build --release && ./target/release/asa doctor

# Hub (Node 22+)
cd hub && npm ci && npm run dev:db && npm run dev    # http://localhost:3000
npm run verify                                        # typecheck, i18n, tests, build
```

Demo data: `node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <admin secret>`.

## Data sources and licenses

This project is MIT licensed. Threat intel, vulnerability and geo data come from their providers under their own licenses (for example DShield is non-commercial and only alerts by default; DB-IP requires attribution);
every hit links to its source. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for the full list.

MIT © 2026 mark.ku (markku636)
