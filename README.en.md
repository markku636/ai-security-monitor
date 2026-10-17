<p align="center">
  <img src="docs/images/logo.png" alt="ai-security-monitor logo" width="140">
</p>

<h1 align="center">ai-security-monitor</h1>

<p align="center"><a href="./README.md">繁體中文</a> · <b>English</b></p>

<p align="center">
  <a href="https://github.com/markku636/ai-security-monitor/actions/workflows/ci.yml"><img src="https://github.com/markku636/ai-security-monitor/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20Windows%20Server%20%7C%20macOS%20%7C%20Linux-informational" alt="platforms">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
</p>

A defensive security agent, **`ai-security-monitor`** (Rust, single binary, Windows / Windows Server / macOS / Linux), plus a **Security Hub** (Next.js + Tailwind + PostgreSQL).
It finds unusual outbound and inbound connections, rates them **safe / unknown / suspicious / dangerous** from public threat intel with the source of every hit,
checks the firewall, open ports, vulnerabilities and system hardening, summarizes traffic and Windows events / crash causes, and hands them to **Claude Code / Codex CLI** for a plain-language read. Both the agent and the Hub are **MCP servers**.

![Security Hub overview](docs/images/overview.png)

## Why

Last night before bed I had AI build a fun little project:
a Rust app that collects and analyzes unusual connections on client machines and assesses threats.
Since AI arrived, system vulnerabilities have become very visible; if the attackers are AI, AI also knows a lot about defending.

**Architecture**

```
Client Agent → periodic reports → Server analysis → AI risk assessment → Dashboard
```

`#cross-platform` (Windows / Windows Server / macOS / Linux)

## What it is

| | |
|---|---|
| **ai-security-monitor** (agent) | Runs on the computer or server you want to protect (including Windows Server 2016–2025, Server Core and domain controllers). Scans connections, intel, firewall, ports, vulnerabilities, hardening, events and traffic. Use it on its own (CLI, MCP, AI analysis) or enroll it with a Hub to report periodically and accept approved remote blocks. Starts at boot (system service or at user login). |
| **Desktop app** (optional) | AI Security Monitor, a windowed client: lives in the system tray and shows this computer's connection verdicts (click an IP to analyze it), scan results and intel status, with one-click scan / intel update and AI analysis through the Claude Code / Codex CLI you are signed in to. Shares the config directory with the CLI and background service. See [docs/desktop.en.md](docs/desktop.en.md). |
| **Security Hub** | One place for every host: connection verdicts, findings, vulnerabilities, hardening scores, crashes and security events, threat-intel hits, block review, AI analysis and MCP. Standalone (local only) or server (all hosts report to one place), deployed with Docker. |

## Screenshots

| | |
|---|---|
| ![Connections](docs/images/connections.png) Connections: direction, verdict, process, country/org, reasons and intel sources | ![Host](docs/images/agent.png) One host: five scores, trend, dangerous destinations seen |
| ![Windows Server](docs/images/agent-server.png) Windows Server: domain controller dc-01 (Server 2022 Datacenter, Server Core) | ![Findings](docs/images/findings.png) Findings from every host, filtered by device, status and severity, with bulk actions |
| ![Vulnerabilities](docs/images/vulns.png) Vulnerabilities & updates: OS support lifetime, KEV, vulnerable software | ![Hardening](docs/images/hardening.png) Hardening: most common failures and scores by host |
| ![Events](docs/images/events.png) Events & crashes: bugcheck codes with likely causes, brute-force sources, account lockouts | ![Intel](docs/images/intel.png) Threat intel: intel freshness per host, source licenses, confidence and hits |
| ![Dark](docs/images/agent-hardening-dark.png) Dark mode: each check's current value, expected value and fix | ![Add a host](docs/images/install.png) Add a host: create an enroll key and get one-line install commands |

> The screenshots use demo data from `scripts/demo-seed.mjs` (fictional hosts, documentation IP ranges). The UI is available in Traditional Chinese and English.

## Features

- **Connections and threat intel**: every connection gets a direction (outbound / inbound / listening / local). Open feeds — Spamhaus DROP, abuse.ch (Feodo, URLhaus, ThreatFox), blocklist.de, CINS, ET, DShield, Tor, IPsum, FireHOL and more —
  are combined with behavior anomalies (processes in temp dirs, shells with network connections, risky ports, periodic beacons, new destinations) into safe / unknown / suspicious / dangerous; every hit carries vendor, confidence, license and source URL. Optional online lookups via AbuseIPDB / GreyNoise / CrowdSec (bring your own key).
- **Firewall and exposure**: reads Windows Firewall, macOS pf / application firewall, Linux nftables / firewalld / ufw / iptables, and works out whether each listening port is really reachable from the network;
  `ai-security-monitor fw block` and `ai-security-monitor fw sync-blocklist` turn high-confidence intel into block rules (preview, confirm, reversible; non-commercial feeds only alert by default).
- **Vulnerabilities and updates**: software inventory, OS support lifetime (including Windows Server 2008–2025), days since the last Windows update, pending Linux security updates, known-vulnerable versions of common software (WinRAR, 7-Zip, Chrome, …), OSV for Linux packages; CISA KEV matches become critical.
- **System hardening**: 60 cross-platform checks (UAC, Defender, BitLocker, SMBv1, RDP NLA, SSH, kernel settings, AppArmor/SELinux, FileVault, Gatekeeper, …) that tell Windows clients, Server, Server Core and domain controllers apart, with a severity-weighted score, customizable in YAML.
- **Traffic**: see which process talks to whom without packet capture (flow-lite); analyze Wireshark / tcpdump pcap/pcapng files: DNS, TLS SNI, plaintext protocols, large uploads, periodic connections.
- **Events and crashes**: Windows event logs, minidump bugcheck codes, WER; Linux journal and macOS crash reports — with likely causes and fixes — plus security events such as brute force (including Kerberos and NTLM), account lockouts, Remote Desktop logons from the internet, new accounts, new services and cleared audit logs.
- **AI and MCP**: `ai-security-monitor ai ask|analyze` hands off to Claude Code or Codex CLI (read-only tools only); `ai-security-monitor mcp` lets Claude Code / Codex / Cursor / VS Code query this computer directly; the Hub has MCP across all hosts and AI analysis in the browser.
- **Hub**: overview, hosts, connections, findings (bulk actions), vulnerabilities, hardening, traffic, events, intel, block review (HMAC-signed, host identity pinning), enroll keys, read-only API tokens, audit log, CSV export, Chinese/English, dark mode, mobile layout.
- **Deploy and update**: start at boot (Windows service / systemd / launchd or per-user), `ai-security-monitor self-update` (verified against SHA256SUMS), one-line install scripts, Hub Docker image (amd64/arm64) and compose files.

## Install

**Agent (ai-security-monitor)**

```bash
# Linux / macOS
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

```powershell
# Windows / Windows Server (PowerShell)
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

The script checks the release's `SHA256SUMS` and stops on a mismatch. You can also download the binaries from [Releases](https://github.com/markku636/ai-security-monitor/releases). See [docs/install.en.md](docs/install.en.md).

**Security Hub (Docker)**

```bash
git clone https://github.com/markku636/ai-security-monitor && cd ai-security-monitor
cp .env.example .env    # set AI_SECURITY_MONITOR_HUB_ADMIN_SECRET and AI_SECURITY_MONITOR_HUB_DB_PASSWORD
docker compose -f docker/compose.standalone.yml --env-file .env up -d   # standalone: http://127.0.0.1:8088
# server: docker compose -f docker/compose.yml --env-file .env up -d
```

The image is `ghcr.io/markku636/ai-security-monitor-hub`. Sign in, open "Add a host" to create an enroll key, and copy the one-line command for each platform. See [docs/docker.en.md](docs/docker.en.md).

## Quick start

```bash
ai-security-monitor doctor                       # environment check: privileges, intel freshness, external tools, Hub connection
ai-security-monitor intel update                 # download threat intel (ai-security-monitor watch keeps it fresh afterwards)
ai-security-monitor connections --intel          # current connections and verdicts
ai-security-monitor scan                         # full scan (connections, intel, firewall, ports, events, vulnerabilities, hardening)
ai-security-monitor fw sync-blocklist --dry-run  # preview which high-confidence intel IPs would be blocked
ai-security-monitor ai ask "Is this computer talking to anything dangerous?"   # let Claude Code / Codex explain
ai-security-monitor enroll https://hub.example.com --key asa_ek_…
ai-security-monitor service install --yes        # report automatically after boot/login (add --system on servers)
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

Run `ai-security-monitor --help` or `ai-security-monitor <command> --help` for every option; `--lang en` for English, `--json` for scripts.

## Upgrading from asa / ai-security-agent

From 0.2.0 the project is called ai-security-monitor (the `asa` executable is now `ai-security-monitor`; the old GitHub URL redirects). No need to re-enroll:

- **Migrated automatically**: on first run the config directory `…/ai-security-agent` moves to `…/ai-security-monitor` (`agent_id`, Hub enrollment, allowlist, baseline and intel included) and the `asa` keychain entry is copied to the new name;
  `ai-security-monitor service install` replaces the old `asa` service / Run value / unit / plist with the new names (moving the system config directory too), and `ai-security-monitor mcp install` replaces the old `asa` MCP entry. Old installs can upgrade with `asa self-update --yes`.
- **Environment variables**: the new prefix is `AI_SECURITY_MONITOR_*` (`AI_SECURITY_MONITOR_HUB_*` for the Hub); the old `ASA_*` / `ASA_HUB_*` names still work, so an `.env` with only the old names needs no changes.
- **Intentionally unchanged**: firewall object names (Windows group `ASA`, `ASA: …` rules, nft `table inet asa`, ipsets `asa_*`, pf anchor `com.asa`, `fw unblock --all-asa`), the `x-asa-*` headers, the `asa_` / `asa_ek_` token prefixes, the `asa_hub` database and the compose project names, so existing rules and data are still recognised.
- **Desktop app**: its application identifier changed, so the new version does not replace the old one. Uninstall "AI Security Agent" in Settings → Apps first, then install the new version (see [docs/desktop.en.md](docs/desktop.en.md)).
- **Hub image**: now `ghcr.io/markku636/ai-security-monitor-hub`; the old `ghcr.io/markku636/ai-security-agent-hub` keeps being published for a transition period.

See [docs/install.en.md](docs/install.en.md#upgrading-from-asa-01x), [docs/service.en.md](docs/service.en.md#upgrading-from-asa-01x) and the [changelog](CHANGELOG.md).

## Docs

[Verdicts & threat intel](docs/intel.en.md) · [Firewall & blocking](docs/firewall.en.md) · [Install & update](docs/install.en.md) · [Start at boot](docs/service.en.md) · [Desktop app](docs/desktop.en.md) · [Docker](docs/docker.en.md) · [MCP & AI](docs/mcp.en.md) · [Traffic](docs/traffic.en.md) · [Events & crashes](docs/events.en.md) ·
[Vulnerabilities](docs/vuln.en.md) · [Hardening](docs/hardening.en.md) · [Agent ↔ Hub contract](docs/hub-contract.en.md) · [Changelog](CHANGELOG.md)

## Build from source

```bash
# agent (Rust 1.85+)
cd agent && cargo build --release && ./target/release/ai-security-monitor doctor

# Hub (Node 22+)
cd hub && npm ci && npm run dev:db && npm run dev    # http://localhost:3000
npm run verify                                        # typecheck, i18n, tests, build

# Desktop app (Tauri 2; the UI in desktop/ui is plain HTML/JS)
cd desktop && npm ci && npx tauri build              # builds the NSIS installer
```

Demo data: `node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <admin secret>`; screenshots: `node scripts/capture-screenshots.mjs --hub http://127.0.0.1:3000 --admin <admin secret>`.

## Data sources and licenses

This project is MIT licensed. Threat intel, vulnerability and geo data come from their providers under their own licenses (for example DShield is non-commercial and only alerts by default; DB-IP requires attribution);
every hit links to its source. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for the full list.

MIT © 2026 mark.ku (markku636)
