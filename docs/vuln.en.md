# Vulnerabilities and updates

English | [繁體中文](vuln.md)

`asa vuln` answers three questions: does this operating system still get security updates, how long since the last update, and is any installed software on a version with known vulnerabilities?

```bash
asa vuln                         # OS support, last update, vulnerable software (plus OSV on Linux)
asa vuln --no-online             # offline: built-in rules only
asa vuln --inventory-only        # just list installed software
asa vuln --inventory-only --filter python
asa --json vuln                  # for scripts or AI
asa scan --scanners vuln         # into the full report (summaries.vuln); asa watch uploads it to the Hub
```

## What it reads

| Platform | Software inventory | Update status |
|---|---|---|
| Windows | Registry Uninstall keys (HKLM 64/32-bit, HKCU) in one PowerShell call | Latest `Get-HotFix`, build/UBR from `CurrentVersion`, edition |
| macOS | `Info.plist` under `/Applications` and `/Applications/Utilities`, `brew list --versions` (including casks) | OS version |
| Linux | `dpkg-query` (with source package) → `rpm -qa` → `apk info -v`, whichever exists | `/etc/os-release`, `apt list --upgradable` (security updates counted separately) |

Everything is read-only and needs no administrator rights.

## Rules

- **OS support lifetime** (`feeds/vuln/os-eol.json`): Windows 10/11 by build, with separate dates for Home/Pro and Enterprise/Education;
  Windows Server 2008 / 2008 R2 through 2025 matched by build (2008 / 2008 R2 ended on 2020-01-14, 2025 runs until 2034-11-14),
  including Annual Channel releases whose name has no year (e.g. 23H2, build 25398); servers are recognised by `Win32_OperatingSystem.ProductType`, Server Core included; Ubuntu, Debian, RHEL, Rocky, AlmaLinux, CentOS, Alpine; macOS 13 and earlier (Apple does not publish end dates, so newer versions show as "unknown").
  Expired → `vuln.os_eol` (high); ending within 90 days → `vuln.os_eol_soon` (medium).
- **Stale Windows updates**: last update older than 45 days → `vuln.updates_stale` (medium), older than 90 days is high.
- **Pending Linux security updates** → `vuln.pending_security_updates` (medium).
- **Known vulnerable versions of common software** (`feeds/vuln/curated-apps.json`): WinRAR, 7-Zip, Chrome, Edge, PuTTY, Git, VLC and others with publicly exploited bugs,
  plus end-of-life Node.js / Python releases. Only listed software is matched; version comparison understands `2.45.1.windows.1`, `1:2.43.0-1ubuntu7`, `1.0rc1` and similar.
  Each hit links to NVD → `vuln.app.<rule id>`.
- **OSV (Linux packages, online)**: dpkg/rpm/apk packages are sent to [OSV.dev](https://osv.dev) `querybatch` using the distribution ecosystem
  (`Debian:12`, `Ubuntu:24.04:LTS`, `Alpine:v3.20`, `Rocky Linux:9`, …); details (CVE aliases, severity) are fetched for up to 300 vulnerabilities.
  Results are cached for 24 hours (`<config dir>/vuln/osv-result.json`) → `vuln.osv_package` (one per package, at most 30, low severity omitted).
- **CISA KEV**: `asa intel update` downloads the CISA Known Exploited Vulnerabilities catalog; matching CVEs are raised to **critical** and tagged `kev`.

## Limits

- There is no universal vulnerability database for general Windows/macOS software (names and version formats vary by vendor), so only the curated list is matched, conservatively.
  For full application scanning, use a dedicated tool such as trivy or grype.
- OSV covers distribution packages only; software built from source or installed with pip/npm is not included.
- With `--no-online` or `scan.online = false`, OSV is not queried.

## Sources and licensing

| Source | Used for | License |
|---|---|---|
| [OSV.dev](https://osv.dev) | Linux package vulnerabilities | Per upstream source (mostly CC-BY 4.0); free API |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited CVEs | Public domain |
| [NVD](https://nvd.nist.gov) | CVE reference links for built-in rules | Public domain |
| Microsoft, distributions, Apple | OS support lifetimes | Compiled from official lifecycle pages |
