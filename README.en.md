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

Install it and it tells you who your computer is talking to, which connections look suspicious and what isn't set up safely, then asks an AI to explain it all in plain language.
Every "suspicious" comes with a reason and a source (which public blocklist, which odd behavior), so it is never a black-box score.
Use it on just your own computer, or bring every computer in the office into one web page.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/windows-desktop-hero-dark.png">
    <img src="docs/images/windows-desktop-hero.png" alt="The AI Security Monitor desktop app on Windows: the overview page shows the security score and suspicious connections, with its icon in the system tray">
  </picture>
</p>

<p align="center"><sub>The Windows desktop app's overview page (demo data). Closing the window keeps it running in the system tray.</sub></p>

## Who is it for?

- **Your own computer**: you want to know whether your Windows / Mac / Linux machine talks to strange places, is missing updates, or has a security setting switched off. Install the desktop app.
- **Several computers in an office**: IT (or the boss) wants one web page for every computer, to deal with problems together and, when needed, approve "block this IP" from the browser. Run the Hub.
- **Servers** (including Windows Server, Server Core, domain controllers and Linux): no desktop needed. Install it as a background service that starts at boot, checks on a schedule and reports in. Use the command-line version.

A few words you will see a lot:

| Word | In plain terms |
|---|---|
| agent | The small program on each computer that does the checking, i.e. `ai-security-monitor` itself |
| threat intel | Public lists of known bad actors that other people maintain (known botnet servers, IPs currently brute-forcing logins, …) |
| Hub (Security Hub) | The web page where you see all your computers; you host it yourself (Docker) |
| hardening | Security settings of the system, such as disk encryption, antivirus, Remote Desktop protection |
| MCP | A standard way for AI tools like Claude Code and Codex to look things up; here it only allows reading, never changing settings |

## Which one do I install?

Everything is on the [latest release](https://github.com/markku636/ai-security-monitor/releases/latest); the current version is **v0.5.0**.

| You want to | Install | File |
|---|---|---|
| Look at your own computer in a window | **Desktop app** (double-click to install) | Windows 10 / 11: `AI-Security-Monitor-<version>-windows-x64-setup.exe`<br>Mac (M1 and later): `…-macos-arm64.dmg`; Mac (Intel): `…-macos-x64.dmg`<br>Linux: `…-linux-x64.AppImage` (no install) or `…-linux-amd64.deb` |
| Run it on a server, without a desktop, or from scripts | **Command-line version** | The one-line installer below is easiest (it verifies the checksum for you). You can also download `ai-security-monitor-<version>-<platform>` directly, but it runs in a terminal; double-clicking only shows a help screen |
| See every computer in the company on one page | **Security Hub** | Docker image `ghcr.io/markku636/ai-security-monitor-hub`; nothing to download |
| (You see `asa-<version>-*`) | Ignore it | Used by old 0.1.x installs to update themselves; same content as the command-line version |
| (You see `SHA256SUMS`) | Checksums | A fingerprint of every file; the install scripts and `self-update` check it and refuse tampered files |

The desktop app and the command-line version can live on the same computer; they share the same settings and scan results.

## Get started in 5 minutes

### Scenario A: I just want to check my own computer (Windows)

1. Download `AI-Security-Monitor-<version>-windows-x64-setup.exe` from [Releases](https://github.com/markku636/ai-security-monitor/releases/latest).
2. Double-click it. If a blue "Windows protected your PC" box appears, click "**More info**", then "**Run anyway**".
   This happens because the installer has no paid code-signing certificate, so Windows does not recognise the publisher; it does not mean the file is bad. If you want to be sure, compare it with `SHA256SUMS` first.
3. It installs for the current user; no administrator needed. Open "AI Security Monitor" from the Start menu.
   The first time, it opens Settings → Company Security Hub (設定 → 公司的 Security Hub) and looks for your company's Hub. If it's just for your own computer, click the link at the bottom of that section, "Not now, use it on this computer only" (先不要，只在這台電腦使用).
4. On the "Overview" page click "**Update intel**" (downloads the blocklists), then "**Scan now**". (The app itself is in Traditional Chinese: 更新情資 and 立即掃描.)
5. Read the results:
   - Overview: the security score and the connections that need attention most.
   - Connections: where this computer is connected right now and why something is marked suspicious; click an IP to see its country and which lists include it.
   - Scan results: vulnerabilities, missing updates and weak security settings, each with how to fix it.
   - AI analysis: if Claude Code or Codex CLI is installed and signed in on this computer, one click asks the AI to explain the findings in plain language (using your own account).

Closing the window only hides it to the system tray; choose "結束" (Quit) in the tray menu to really exit.
To have it check in the background on a schedule, turn on "Report in the background after startup / sign-in" (開機／登入後在背景自動回報) on the Settings page. macOS and Linux steps are under [Install](#install).

### Scenario B: I manage several computers in an office

**Step 1: run the Hub** (on a computer or server that is always on and has Docker)

```bash
git clone https://github.com/markku636/ai-security-monitor && cd ai-security-monitor
cp .env.example .env    # edit .env: set AI_SECURITY_MONITOR_HUB_ADMIN_SECRET (your sign-in secret), AI_SECURITY_MONITOR_HUB_DB_PASSWORD,
                        # and AI_SECURITY_MONITOR_HUB_PUBLIC_URL (the address other computers use, e.g. http://<this machine's IP>:8088)
docker compose -f docker/compose.yml --env-file .env up -d
```

Open `http://<this machine's IP>:8088` in a browser and sign in with the `AI_SECURITY_MONITOR_HUB_ADMIN_SECRET` you just set.
Just trying it on your own machine? Use `compose.standalone.yml` instead of `compose.yml`; it only listens on `http://127.0.0.1:8088`.

**Step 2: add computers**

**Option 1: computers find the Hub themselves and an admin clicks "Approve" (recommended, no keys to hand out)**

1. The admin opens "Add a host" in the Hub sidebar and notes the **Hub fingerprint** at the top (a code like `72AS-YEXT-VNGO-NLC5-W2NM` that proves it's your company's Hub and not an impostor).
2. On each computer, one of:
   - **Desktop app**: on first start it looks for the company Hub by itself in Settings → Company Security Hub (設定 → 公司的 Security Hub). If the fingerprint matches what the admin told you, click "**Request to join**" (申請加入). If nothing is found, type in the address the admin gave you in the same section; joining, switching or leaving a Hub later also happens there.
   - **Command line**: run `ai-security-monitor enroll --auto`, check the fingerprint and send the request, then `ai-security-monitor service install --yes` (you can install it before approval; it keeps waiting in the background).
   - **Not installed yet**: give colleagues the "Keyless install commands" from the "Add a host" page; the Hub address is already filled in.
3. The admin compares the host name and check code (the computer shows the same code) under "Add a host → Hosts waiting for approval" and clicks "**Approve**". Done.
   Tired of clicking one by one? Set "Auto-approved networks", e.g. your office LAN `192.168.10.0/24`.

Computers find the Hub through an SRV record in the company DNS or a local-network broadcast (mDNS). A Hub running in Docker Desktop can't broadcast to the LAN;
then run `ai-security-monitor hub advertise --url <Hub URL>` to advertise it, or just hand out the address. Details in [Automatic Hub discovery and keyless enrollment](docs/enrollment.en.md).

**Option 2: an enroll key**

- Create an enroll key on the "Add a host" page; it gives you one-line install commands with the address and key filled in (Windows, macOS and Linux). Paste one on the computer you want to add.
- On a computer that already has the command-line version:

  ```bash
  ai-security-monitor enroll http://<Hub IP>:8088 --key asa_ek_…
  ai-security-monitor service install --yes    # report automatically after login; use --system on servers
  ```

- Desktop app: Settings page → "I have an enroll key" (我有註冊金鑰).

Within a few minutes the computer shows up on the Hub's "Host" page. From then on it reports connections every minute and a full report every 10 minutes; if the Hub is unreachable, reports are kept and sent once it is back.

### Scenario C: servers / Windows Server

Windows Server (2016 to 2025, including Server Core), in PowerShell opened with "Run as administrator":

```powershell
irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex
```

Linux, macOS:

```bash
curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh
```

Open a **new** terminal window, then:

```bash
ai-security-monitor doctor                          # check permissions, intel and Hub connection
ai-security-monitor intel update                    # download threat intel
ai-security-monitor scan                            # run a full check once
ai-security-monitor service install --system --yes  # install as a service that starts at boot (prefix sudo on Linux / macOS)
```

Without `--yes`, commands that change the system (`service install`, blocking an IP, …) only print what they would do and change nothing; add `--yes` once you've read it.
To report to a Hub, join it as in [scenario B](#scenario-b-i-manage-several-computers-in-an-office) (`enroll --auto` works on servers too).

## FAQ

<details>
<summary><b>I double-click the .exe and it closes right away?</b></summary>

You probably downloaded the command-line version, `ai-security-monitor-<version>-windows-x64.exe`. It is meant for a terminal; double-clicking only shows one page of help (where the desktop app is, how to install in one line) and closes when you press Enter.
For the windowed app, download `AI-Security-Monitor-<version>-windows-x64-setup.exe`. To use the command-line version, run it from PowerShell, e.g. `ai-security-monitor doctor`.
</details>

<details>
<summary><b>SmartScreen says "Windows protected your PC"?</b></summary>

The installer has no paid code-signing certificate, so Windows does not recognise the publisher. Click "More info" → "Run anyway".
To make sure the file wasn't altered, run `Get-FileHash .\AI-Security-Monitor-<version>-windows-x64-setup.exe` in PowerShell and compare it with the value in `SHA256SUMS` on the release.
On a Mac, the first time you open it right-click it in Applications → "Open"; see [Install](#install).
</details>

<details>
<summary><b>The AI assistant says "Please run /login"?</b></summary>

Claude Code isn't signed in yet. AI analysis uses your own Claude Code or Codex CLI account; this project does not provide any AI credits.

- **Desktop app, command line**: on the same computer open a terminal, run `claude`, type `/login` and follow the prompts, then `/exit`. For Codex, run `codex` and sign in. `ai-security-monitor ai status` shows whether each is installed and signed in.
- **AI assistant in the Hub web UI**: the AI runs inside the Hub container, so sign in there: click **Sign in** under *AI accounts* at the top of the AI assistant page (Claude: open the authorization page and paste the code back; Codex: enter the code on OpenAI's site). You can sign out there too. Steps and manual commands: [docs/ai-login.en.md](docs/ai-login.en.md).
</details>

<details>
<summary><b>Does it send my data anywhere?</b></summary>

Nothing is sent to us; the project has no telemetry and nothing reports back to the author. The only outside connections are:

- **Downloading threat intel** from list providers such as abuse.ch and Spamhaus (from your own Hub first, if you have one). These are downloads; your connections are not uploaded.
- **Vulnerability checks**: on Linux, installed package names and versions are looked up on OSV.dev (turn off with `--no-online`).
- **Update checks**: the desktop app and the background service check GitHub Releases once a day by default (they only read the latest version number; `update.mode off`, or "Off" under the desktop app's automatic updates, stops it); `self-update` and `version --check` ask too; the Hub also checks for new versions and shows a banner to admins (`AI_SECURITY_MONITOR_HUB_UPDATE_CHECK=0` turns it off).
- **When you click**: online IP reputation lookups (`intel lookup --online`, or "Look up external intel" in the Hub, with API keys you provide; private ranges are never sent), and the desktop app's VirusTotal / AbuseIPDB links (they just open the web page in your browser).
- **AI analysis** goes through the Claude Code / Codex CLI on your own computer, under your account's terms with Anthropic / OpenAI.
- **Your own Hub**: once enrolled, reports go only to the Hub you chose. Looking for a Hub only queries your company DNS and asks on the local network.
</details>

<details>
<summary><b>How do I update? How do I turn automatic updates off?</b></summary>

The default is "notify me when a new version is out": it checks GitHub once a day and tells you (the Hub's host list also shows "New version"); it **does not install anything by itself**.

- **Desktop app**: Settings → "Background reporting and automatic updates": choose Off, Notify me, or Update automatically. "Check for updates" shows the current and latest versions; "Update now" downloads, verifies the signature, installs and reopens the app. With automatic updates the new version is downloaded in the background and installed the next time you quit or reopen the app. Background reporting runs the desktop app itself, so it is updated with it.
- **Command line**: `ai-security-monitor config set update.mode off` / `notify` (default) / `auto` (the background service downloads, checks SHA256, replaces itself and restarts). By hand: `ai-security-monitor version --check`, then `ai-security-monitor self-update --yes`; the background service is restarted on the new version (the system service needs an administrator). If you installed it with apt, Homebrew, Scoop, winget or another package manager, update it there.
- To use your own mirror, set `AI_SECURITY_MONITOR_UPDATE_URL` (command line).

See [docs/install.en.md](docs/install.en.md#updating).
</details>

<details>
<summary><b>How do I upload to the Hub right now?</b></summary>

The background service already reports on a schedule (a full scan every 10 minutes and a connection snapshot every minute by default). To see results immediately:

- **Desktop app**: on the Overview page, the "Upload to Security Hub" card has "Scan now and upload to the Hub". The card also shows when the last upload happened and how many reports are waiting to be resent (they are queued while the Hub is unreachable); "Upload again" resends them first.
- **Command line**: `ai-security-monitor upload` resends queued reports, then uploads a connection snapshot, a full scan report and a heartbeat, and prints "Uploaded; the Hub received N findings".
</details>

<details>
<summary><b>Why can't my computer find the company Hub?</b></summary>

The automatic search in the desktop app's Settings → Company Security Hub (and `enroll --auto` on the command line) relies on an SRV record in the company DNS or on LAN advertising (mDNS). It usually fails for one of three reasons:

1. **The Hub is only open to its own computer**: the standalone edition binds 127.0.0.1 by default, so other office computers can neither reach nor find it. Ask the administrator to switch to the server edition, or add `AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0` and `AI_SECURITY_MONITOR_HUB_PUBLIC_URL=http://<its LAN IP>:8088` to the Hub's `.env` (always with an admin key, and only on the company network).
2. **The Hub runs in Docker Desktop**: its LAN advertising cannot leave Docker. On the computer running the Hub, turn on desktop app Settings → "Let computers on the LAN find the Hub on this computer", or run `ai-security-monitor config set hub.advertise_url http://<its LAN IP>:8088`; the background service then advertises it.
3. **You are on a different subnet**: LAN advertising does not cross routers; the administrator needs to add an `_aisecmon._tcp` SRV record to the company DNS (the Hub's "Add a host" page has ready-made commands).

If nothing works, ask the administrator for the Hub URL: enter it under "Or enter the Hub URL your administrator gave you" in the desktop app, or run `ai-security-monitor enroll --hub <url>`. On the Hub, "Add a host → Can office computers find this Hub?" tells the administrator in plain words which step is missing.
</details>

<details>
<summary><b>Can I use it commercially for free?</b></summary>

The code is MIT licensed, so yes. Some threat intel sources, however, only allow non-commercial use (DShield, for example), so check which ones to turn off in a company setting; see [Data sources and licenses](#data-sources-and-licenses).
</details>

<details>
<summary><b>How do I uninstall it?</b></summary>

- **Desktop app**: on Windows, Settings → Apps → Installed apps → "AI Security Monitor" → Uninstall; on a Mac drag it from Applications to the Trash; on Linux remove the deb with your software manager (or `sudo apt remove` with the package name shown by `apt list --installed`), or just delete the AppImage.
- **Command line**: stop the background service with `ai-security-monitor service uninstall --yes` (add `--system` for the system service), run `ai-security-monitor unenroll` if it was enrolled with a Hub, then delete the executable (on Windows `%LOCALAPPDATA%\ai-security-monitor\bin` by default, or `%ProgramFiles%\ai-security-monitor` for the system service; on Linux / macOS `/usr/local/bin` or `~/.local/bin`).
- **Settings and scan history**: `ai-security-monitor config path` shows the folder; delete it if you don't need it.
- **Hub**: `docker compose -f docker/compose.yml --env-file .env down`; add `-v` to delete its data too.
</details>

## Screenshots

**Desktop app (Windows)**

| | |
|---|---|
| ![Desktop connections](docs/images/windows-desktop-connections.png) Connections: verdict, reasons and intel source for every connection; click an IP for its country, organisation and which lists include it | ![Desktop AI analysis](docs/images/windows-desktop-ai.png) AI analysis: the local Claude Code / Codex looks things up through read-only tools and explains in plain language |
| ![Desktop scan results](docs/images/windows-desktop-findings.png) Scan results: sorted by severity, expand for detail and how to fix | ![Desktop dark mode](docs/images/windows-desktop-overview-dark.png) Dark mode follows the Windows setting |
| ![Desktop: join the company Hub](docs/images/windows-desktop-settings-join.png) Settings → Company Security Hub: finds the company Hub by itself; check the fingerprint and click *Request to join* | ![Desktop settings](docs/images/windows-desktop-settings.png) Settings: the joined Hub, background reporting, automatic updates |
| ![Desktop traffic and performance](docs/images/windows-desktop-usage.png) Traffic & performance: network speed over the last hour and which programs use the most (also live and last 24 hours) | ![Desktop CPU, memory, disk](docs/images/windows-desktop-usage-perf.png) With performance collection on: CPU, memory, disk, top programs, battery |
| ![Desktop DNS](docs/images/windows-desktop-dns.png) DNS: which domains this computer looks up, which program asked, what looks suspicious (generated domains, threat-intel domains, encrypted DNS endpoints), and whether it uses the company protective DNS | ![Desktop threat intel](docs/images/windows-desktop-intel.png) Threat intel: entries, last update and licence of each list, update now |

**Security Hub (web)**

| | |
|---|---|
| ![Hub overview](docs/images/overview.png) Overview: scores, open findings and dangerous connections for every computer | ![Connections](docs/images/connections.png) Connections: direction, verdict, process, country / org, reasons and intel sources |
| ![Host](docs/images/agent.png) A single host: five scores, trends, dangerous destinations it has contacted | ![Findings](docs/images/findings.png) Findings: filter by device, status and severity, handle them in bulk |
| ![Windows Server](docs/images/agent-server.png) Windows Server: domain controller dc-01 (Server Core) | ![Vulnerabilities](docs/images/vulns.png) Vulnerabilities & updates: OS support dates, exploited vulnerabilities, vulnerable software |
| ![Hardening](docs/images/hardening.png) Hardening: the most commonly failed checks and per-host scores | ![Events](docs/images/events.png) Crashes & events: bugcheck codes and likely causes, brute-force sources |
| ![Intel](docs/images/intel.png) Threat intel: list freshness per host, licenses, hits | ![Add a host](docs/images/install.png) Add a host: create an enroll key and get a one-line install command |
| ![Traffic](docs/images/traffic.png) Traffic: fleet bandwidth chart, which hosts and programs use the most, per network card | ![Performance](docs/images/agent-perf.png) Host "Performance" tab (opt-in): CPU, memory, disk, battery, top programs |

> All screenshots use demo data (fictional hosts, documentation-only IP ranges, example.com): the Hub is seeded by `scripts/demo-seed.mjs` and the desktop shots come from `scripts/capture-desktop-screenshots.mjs`. The UI is shown in Traditional Chinese; the Hub also has English. More desktop screens in [docs/desktop.en.md](docs/desktop.en.md).

## Features

- **Connections and threat intel**: every connection gets a direction (outbound / inbound / listening / local) and is checked against public lists such as Spamhaus DROP, abuse.ch (Feodo, URLhaus, ThreatFox), blocklist.de, CINS, ET, DShield, Tor, IPsum and FireHOL,
  plus behavior checks (programs running from a temp folder, command shells talking to the internet, risky ports, regular "beacon" connections, new destinations), and is rated safe / unknown / suspicious / dangerous; every hit carries vendor, confidence, license and source URL. Optional AbuseIPDB / GreyNoise / CrowdSec online lookups (your own keys).
- **Firewall and exposure**: reads Windows Firewall, macOS pf / application firewall and Linux nftables / firewalld / ufw / iptables, and works out whether each listening port is actually reachable from the network;
  `fw block` and `fw sync-blocklist` turn high-confidence bad IPs into block rules (preview first, apply only when confirmed, reversible; sources with non-commercial licenses only alert by default).
- **Vulnerabilities and updates**: installed software, OS support dates (including Windows Server 2008 to 2025), how long Windows has gone without updates, pending Linux security updates, known vulnerable versions of common software (WinRAR, 7-Zip, Chrome, …), OSV lookups for Linux packages; anything in CISA KEV (actively exploited) is raised to critical.
- **Security settings (hardening)**: 60 cross-platform checks (UAC, Defender, BitLocker, SMBv1, Remote Desktop NLA, SSH, kernel parameters, AppArmor / SELinux, FileVault, Gatekeeper, …), aware of Windows client, Server, Server Core and domain controllers, customisable in YAML.
- **Traffic**: see where each program connects without capturing packets; analyze pcap / pcapng files from Wireshark / tcpdump (DNS, TLS SNI, cleartext protocols, large uploads, periodic connections).
- **Traffic statistics and performance**: upload/download per network card and per program every minute, charted on the Hub (bandwidth, which hosts and programs use the most); CPU, memory, disk and battery are **opt-in**, off by default and turned on on the computer itself (desktop Settings or `config set metrics.performance true`; the Hub cannot turn it on); a nearly full disk or a long-maxed-out CPU becomes a finding. The desktop app's *Traffic & performance* page charts this computer: live (every second), the last hour and the last 24 hours (the 24 hours are kept locally even without a Hub).
- **DNS defense** ([docs](docs/dns.en.md)): each computer records which domains it looks up and which program asked (Windows ETW, packet capture on Linux / macOS), and detects threat-intel domains, DNS tunnels, generated domains, NXDOMAIN bursts and programs switching to their own encrypted DNS; it also catches changed DNS servers, tampered hosts files, WPAD and NXDOMAIN redirection; `fw dns-lock` stops programs from talking to outside DNS directly. Domain intel now includes CERT Polska, HaGeZi and Phishing.Database.
- **Protective DNS server** (optional, off by default, [docs](docs/dns-server.en.md)): a DNS for the whole LAN that blocks threat-intel domains, uses encrypted upstream DNS and caches (about 120k QPS, ~0.3 µs lookups in a 2-million-entry blocklist); switched on, paused and corrected from the Hub's "Protective DNS" page; runs on any always-on computer or in the Hub's compose; `dns use-hub` points single computers at it and switches back automatically if it stops answering.
- **Events and crashes**: Windows event logs, bugcheck minidumps, Linux journal and macOS crash reports, summarised into likely causes and what to do; also brute-force attempts, account lockouts, Remote Desktop logons from the internet, new accounts, new services and cleared audit logs.
- **AI and MCP**: `ai ask` / `ai analyze` hand things to Claude Code or Codex CLI (read-only tools only); `mcp` lets Claude Code / Codex / Cursor / VS Code query this computer directly; the Hub has a fleet-wide MCP and an AI assistant in the web UI.
- **Hub**: overview, hosts, connections, findings, vulnerabilities, hardening, traffic, events, intel, block approvals (signed, pinned host identity), keyless join requests with approval (found via DNS SRV or LAN mDNS), enroll keys, read-only API tokens, audit log, CSV export, Chinese and English, dark mode, mobile layout.
- **Deployment and updates**: start at boot (Windows service / systemd / launchd or at login), `self-update` (checks SHA256SUMS), one-line install scripts, Hub Docker image (amd64 / arm64).

## Install

Full steps for every platform. If you just want to get going, [Get started in 5 minutes](#get-started-in-5-minutes) is enough.

**System requirements**

| | Requirement |
|---|---|
| Desktop app, Windows | Windows 10 / 11 (x64); needs Microsoft Edge WebView2 (built into Windows 10 / 11; the installer downloads it if missing) |
| Desktop app, macOS | macOS 10.13 or later (Apple Silicon or Intel) |
| Desktop app, Linux | x64, Ubuntu 22.04 / Debian 12 or later (glibc 2.35+); the deb pulls in WebKitGTK 4.1; the tray icon needs AppIndicator support |
| Command line | Windows 10 / 11, Windows Server 2016 / 2019 / 2022 / 2025 (including Server Core), x64 or ARM64; macOS 11+; Linux x64 / ARM64 (statically linked, any distribution) |
| Security Hub | Docker 24+ (with Compose v2), amd64 or arm64 |
| Protective DNS (optional) | anywhere the command-line version runs, or the Docker image `ghcr.io/markku636/ai-security-monitor-dns` (amd64/arm64) |

**Desktop app: Windows**: see [scenario A](#scenario-a-i-just-want-to-check-my-own-computer-windows). If you had the old "AI Security Agent" (0.1.x), uninstall it first in Settings → Apps; the new version does not replace it.
Once installed the window opens on the overview and the AI Security Monitor icon sits in the system tray.

**Desktop app: macOS**

1. On Apple Silicon (M1, M2, …) download `AI-Security-Monitor-<version>-macos-arm64.dmg`; on Intel `…-macos-x64.dmg`. Not sure? Apple menu → "About This Mac", look at "Chip" or "Processor".
2. Open the dmg and drag "AI Security Monitor" to Applications.
3. First launch: right-click it in Applications → "Open" → "Open". If it says the app "is damaged and can't be opened", run in Terminal:
   `xattr -dr com.apple.quarantine "/Applications/AI Security Monitor.app"`

**Desktop app: Linux**

- AppImage (any distribution, no install): `chmod +x AI-Security-Monitor-<version>-linux-x64.AppImage && ./AI-Security-Monitor-<version>-linux-x64.AppImage`
- deb (Debian / Ubuntu): `sudo apt install ./AI-Security-Monitor-<version>-linux-amd64.deb`, then open it from the applications menu.

**Command line: Windows, Windows Server**

1. Open PowerShell. To install the service that starts at boot, use "Run as administrator".
2. Run `irm https://github.com/markku636/ai-security-monitor/releases/latest/download/install.ps1 | iex`. It installs to `%LOCALAPPDATA%\ai-security-monitor\bin` by default and adds it to your PATH.
3. Open a **new** PowerShell window and run `ai-security-monitor version`; it should print `ai-security-monitor 0.5.0 …`.
4. (Optional) start at login: `ai-security-monitor service install --yes`; start at boot on a server: `ai-security-monitor service install --system --yes` (administrator). Check with `ai-security-monitor service status`.

**Command line: Linux, macOS**

1. Run `curl -fsSL https://github.com/markku636/ai-security-monitor/releases/latest/download/install.sh | sh`. It installs to `/usr/local/bin`, or `~/.local/bin` without permission.
2. Check with `ai-security-monitor version` and `ai-security-monitor doctor`.
3. (Optional) `ai-security-monitor service install --yes` to start at login; on servers `sudo ai-security-monitor service install --system --yes`.

The install scripts verify the release's `SHA256SUMS` and stop on a mismatch. Options for a specific version, install location, internal mirror or enrolling with a Hub during install are in [docs/install.en.md](docs/install.en.md).

**Security Hub (Docker)**

1. Start it as in [scenario B](#scenario-b-i-manage-several-computers-in-an-office). The standalone `docker/compose.standalone.yml` only listens on `http://127.0.0.1:8088`; the server version `docker/compose.yml` lets other computers report in.
2. Check: `curl http://127.0.0.1:8088/api/health` returns `"db":"ok"` and the web page shows the sign-in screen.
3. (Optional) make the Hub's "AI assistant" work: Claude Code and Codex are already in the image but need to be signed in once ("Please run /login" means they aren't). Either:
   - **Sign in on the web page** (easiest): Hub *AI assistant* → *AI accounts* → **Sign in**; for Claude open the authorization page and paste the code back, for Codex enter the code on OpenAI's site. Sign out there too. See [docs/ai-login.en.md](docs/ai-login.en.md).
   - **Sign in with a command**: run `docker compose -f docker/compose.yml --env-file .env exec hub claude auth login` (use `compose.standalone.yml` for the standalone Hub), open the URL in a browser and authorise, then paste the code back; sign out with `… exec hub claude auth logout`.
   - **Use a token or API key** (no need to enter the container): run `claude setup-token` on your own computer to create a long-lived token and add `CLAUDE_CODE_OAUTH_TOKEN=…` to `.env`; or use `ANTHROPIC_API_KEY=…`; for Codex `OPENAI_API_KEY=…`. Then run `up -d` again.

   The sign-in is stored in the `hubdata` volume and survives image updates and container rebuilds. The AI only gets read-only tools: it can see Hub data but not change it.

More in [docs/docker.en.md](docs/docker.en.md).

**Upgrading**: for the command line run `ai-security-monitor self-update --yes` (on 0.1.x, `asa self-update --yes`), then `ai-security-monitor service install --yes` once more (add `--system` for the system service); for the desktop app just install the new version (uninstall the 0.1.x "AI Security Agent" first). See [Upgrading from asa / ai-security-agent](#upgrading-from-asa--ai-security-agent).

## How it works

```mermaid
flowchart LR
  subgraph HOST["Each computer / server you protect"]
    direction TB
    CLI["ai-security-monitor<br/>CLI / background service watch"]
    DESK["Desktop app AI Security Monitor<br/>Tauri, shares the agent library"]
    CFG[("Config directory<br/>latest report, intel, offline queue")]
    CLI --- CFG
    DESK --- CFG
  end

  subgraph HUB["Security Hub"]
    direction TB
    API["Next.js API + web UI"]
    DB[("PostgreSQL")]
    MIRROR["Intel mirror"]
    HMCP["MCP: /api/mcp (read-only)"]
    API --- DB
  end

  VENDORS["Threat intel vendors<br/>abuse.ch, Spamhaus, blocklist.de…"]
  ADMIN["Admin's browser"]
  AI["Claude Code / Codex CLI"]

  CLI -- "snapshot + heartbeat: every 1 min<br/>full report: every 10 min<br/>HTTPS + per-host token" --> API
  API -- "approved remote actions<br/>HMAC-signed" --> CLI
  VENDORS --> MIRROR
  MIRROR -- "intel: checked every 30 min" --> CLI
  ADMIN --> API
  AI -- "ai-security-monitor mcp<br/>read-only by default" --> CLI
  AI -- "read-only" --> HMCP
```

- **Periodic reports**: the background service `ai-security-monitor watch` takes a connection snapshot and sends a heartbeat every minute, and runs a full scan every 10 minutes (tune with `config set scan.snapshot_interval` / `scan.interval`).
  Uploads use HTTPS (plain http only for localhost or private networks) with the key from enrollment and this host's own token; the Hub pins it on first sight, so another machine can't impersonate it.
- **Joining a Hub**: computers find the Hub via an SRV record in the company DNS or LAN mDNS; the Hub proves its identity by signing with its own key (Ed25519), the computer pins the Hub fingerprint and refuses to upload if it ever changes; only after an admin approves does the computer get a key of its own.
- **Offline queue**: when the Hub is down or the network drops, full reports wait in the config directory's `outbox/` (up to 50) and are sent in order once it is reachable.
- **Remote actions**: after an admin requests and approves a block in the Hub, the agent picks it up; every action carries an HMAC-SHA256 signature, and the agent checks the signature, expiry and guardrails before running it. Hosts enrolled without `--accept-remote-actions` never pick up actions.
- **Intel**: the Hub downloads and caches the lists in `feeds/registry.json`; agents check every 30 minutes, getting lists from the Hub first when enrolled and from the vendors only for what the Hub doesn't have.
- **Desktop app**: links the agent's Rust library directly and reads the same config directory, so it sees the background service's latest report and Hub enrollment; reporting to the Hub is still the background service's job.
- **AI**: `ai-security-monitor mcp` (stdio or `--http`) exposes read-only tools by default; actions like blocking only appear with `--allow-actions`. The Hub's `/api/mcp` is entirely read-only.
  AI analysis in the CLI, the desktop app and the Hub web UI all call the Claude Code / Codex CLI you are signed in to, with these read-only tools attached.

## Command-line cheat sheet

```bash
ai-security-monitor doctor                       # environment check: permissions, intel freshness, external tools, Hub connection
ai-security-monitor intel update                 # download threat intel (the background service keeps it fresh afterwards)
ai-security-monitor connections --intel          # current connections and verdicts
ai-security-monitor scan                         # full scan (connections, intel, firewall, ports, events, vulnerabilities, hardening)
ai-security-monitor fw sync-blocklist --dry-run  # preview which high-confidence bad IPs would be blocked
ai-security-monitor ai ask "Is this computer talking to anything dangerous?"   # let Claude Code / Codex explain
ai-security-monitor enroll --auto               # find the company Hub, send a join request and wait for approval (with a key: enroll <url> --key asa_ek_…)
ai-security-monitor service install --yes        # report automatically after login (add --system on servers)
```

| Command | Purpose |
|---|---|
| `scan`, `connections`, `ports` | Full scan, connection verdicts, port reachability |
| `intel` | Intel updates, sources and licenses, look up an IP / domain |
| `fw` | Firewall status, audit, block / unblock, intel sync |
| `vuln`, `harden` | Vulnerabilities and updates, security settings |
| `traffic`, `events` | Traffic watching and pcap analysis, events and crash causes |
| `dns`, `dns-server` | Which domains this computer looks up (`--follow` for live), tamper baselines, `dns use-hub` / `restore`; the protective DNS server |
| `metrics` | Current upload/download rate (per card, per program); with performance collection on also CPU, memory and disk |
| `ai`, `mcp` | Claude Code / Codex analysis, MCP server and one-step client setup |
| `enroll`, `discover`, `unenroll`, `status`, `watch`, `service` | Find a Hub, join it, keep reporting, start at boot |
| `self-update`, `version`, `doctor` | Updates and environment check (`config set update.mode off\|notify\|auto` sets automatic updates) |
| `upload` | Scan now and upload to the Hub (resends queued reports first) |
| `allowlist`, `baseline`, `config` | Allowlist, baseline (only show what's new), settings |

`ai-security-monitor --help` and `ai-security-monitor <command> --help` list every option; `--lang en` switches to English, `--json` gives machine-readable output.

## Upgrading from asa / ai-security-agent

From 0.2.0 the project is called ai-security-monitor (the `asa` executable is now `ai-security-monitor`; the old GitHub URL redirects). No need to re-enroll:

- **Migrated automatically**: on first run the config directory `…/ai-security-agent` moves to `…/ai-security-monitor` (agent id, Hub enrollment, allowlist, baseline and intel included) and the `asa` keychain entry is copied to the new name.
  While an old resident watch is still running the old directory is used in place and moved when `service install` replaces the old service; `service install` removes the old `asa` service and `mcp install` replaces the old MCP entry.
- **Environment variables**: the new prefix is `AI_SECURITY_MONITOR_*` (`AI_SECURITY_MONITOR_HUB_*` for the Hub); the old `ASA_*` / `ASA_HUB_*` names still work.
- **Intentionally unchanged**: firewall object names (Windows group `ASA`, nft `table inet asa`, ipsets `asa_*`, pf anchor `com.asa`), the `x-asa-*` headers, the `asa_` / `asa_ek_` token prefixes and the `asa_hub` database, so existing rules and data are still recognised.
- **Desktop app**: its application identifier changed; uninstall "AI Security Agent" first, then install the new version (see [docs/desktop.en.md](docs/desktop.en.md)).
- **Hub image**: now `ghcr.io/markku636/ai-security-monitor-hub`; the old `ghcr.io/markku636/ai-security-agent-hub` keeps being published for a transition period.

See [docs/install.en.md](docs/install.en.md#upgrading-from-asa-01x), [docs/service.en.md](docs/service.en.md#upgrading-from-asa-01x) and the [changelog](CHANGELOG.md).

## Docs

[Verdicts & threat intel](docs/intel.en.md) · [Firewall & blocking](docs/firewall.en.md) · [Install & update](docs/install.en.md) · [Automatic Hub discovery & keyless enrollment](docs/enrollment.en.md) · [Start at boot](docs/service.en.md) · [Desktop app](docs/desktop.en.md) · [Docker](docs/docker.en.md) · [MCP & AI](docs/mcp.en.md) · [Traffic](docs/traffic.en.md) · [Traffic statistics & performance](docs/metrics.en.md) · [DNS defense](docs/dns.en.md) · [Protective DNS server](docs/dns-server.en.md) · [Events & crashes](docs/events.en.md) ·
[Vulnerabilities](docs/vuln.en.md) · [Hardening](docs/hardening.en.md) · [Agent ↔ Hub contract](docs/hub-contract.en.md) · [Changelog](CHANGELOG.md)

## Why this exists

One night before bed I had an AI build a small project: a Rust program that collects and analyzes unusual connections on client machines and assesses the threat.
Since AI arrived, system vulnerabilities have become very visible; if attackers use AI, defenders can too. The idea is simple:

```
agent on each computer → periodic reports → Hub analysis → AI risk assessment → web dashboard
```

## Repository layout

```text
ai-security-monitor/
├── agent/                 Rust agent: the ai-security-monitor binary + library (the desktop app links this library too)
│   ├── src/               commands (cli/), scanners (scan/, connections/, intel/, firewall/, ports/, vuln/, hardening/, events/, traffic/),
│   │                      Hub client (hub/), actions (actions/), MCP (mcp/), AI (ai/), start at boot (service/), self-update (update/)
│   ├── prompts/           prompts for AI analysis
│   └── tests/fixtures/    test data
├── hub/                   Security Hub (Next.js + Tailwind): pages and API (app/), components, queries and logic (lib/), PostgreSQL migrations (drizzle/), tests
├── desktop/               Desktop app AI Security Monitor (Tauri 2): Rust shell (src-tauri/) + plain HTML / CSS / JS UI (ui/)
├── contract/              JSON Schemas between agent and Hub (enrollment, reports, snapshots, remote actions)
├── feeds/                 data embedded in the binary: intel source list, known-good services, hardening rules (YAML), vulnerability and bugcheck notes
├── docker/                Hub Dockerfile and compose files (standalone, server, dev database)
├── scripts/               one-line installers, demo data, screenshots, version and changelog checks
├── docs/                  topic docs and README screenshots (docs/images)
└── .github/workflows/     CI and release pipelines
```

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

Demo data: `node scripts/demo-seed.mjs --hub http://127.0.0.1:3000 --admin <admin secret>`; screenshots: `node scripts/capture-screenshots.mjs --hub http://127.0.0.1:3000 --admin <admin secret>`; desktop screenshots: `node scripts/capture-desktop-screenshots.mjs` (no Hub needed; add `--frame windows` for the Windows-framed versions).

## Data sources and licenses

This project is MIT licensed. Threat intel, vulnerability and geo data come from their providers under their own licenses (for example DShield is non-commercial and only alerts by default; DB-IP requires attribution);
every hit links to its source. See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for the full list.

MIT © 2026 mark.ku (markku636)
