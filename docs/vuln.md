# 漏洞與更新

[English](vuln.en.md) | 繁體中文

`ai-security-monitor vuln` 回答三個問題：這台的作業系統還有沒有安全性更新？多久沒更新了？裝的軟體有沒有已知漏洞的版本？

```bash
ai-security-monitor vuln                   # 作業系統支援期限、最近一次更新、已知漏洞軟體（Linux 另查 OSV）
ai-security-monitor vuln --no-online       # 不連網，只用內建規則
ai-security-monitor vuln --inventory-only  # 只列出已安裝的軟體
ai-security-monitor vuln --inventory-only --filter python
ai-security-monitor --json vuln            # 給程式或 AI 讀
ai-security-monitor scan --scanners vuln   # 進完整報告（summaries.vuln），ai-security-monitor watch 會一起上傳 Hub
```

## 讀哪些資料

| 平台 | 軟體清單 | 更新狀態 |
|---|---|---|
| Windows | 登錄檔 Uninstall（HKLM 64／32 位元、HKCU），一次 PowerShell 讀完 | `Get-HotFix` 最近一筆、`CurrentVersion` 的 build／UBR、版本別 |
| macOS | `/Applications`、`/Applications/Utilities` 的 `Info.plist`、`brew list --versions`（含 cask） | 系統版本 |
| Linux | `dpkg-query`（含來源套件）→ `rpm -qa` → `apk info -v`，有哪個用哪個 | `/etc/os-release`、`apt list --upgradable`（安全性更新另計） |

全部免系統管理員權限、唯讀。

## 判斷規則

- **作業系統支援期限**（`feeds/vuln/os-eol.json`）：Windows 10／11 依 build 判版本，家用／專業版與企業／教育版的期限不同；
  Windows Server 2008／2008 R2–2025 依組建編號判斷（2008／2008 R2 已於 2020-01-14 停止支援，2025 到 2034-11-14），
  名稱沒有年份的 Annual Channel（例：23H2，組建 25398）也靠組建編號；Server 判斷看 `Win32_OperatingSystem.ProductType`，Server Core 一樣適用；Ubuntu、Debian、RHEL、Rocky、AlmaLinux、CentOS、Alpine；macOS 13 以前（Apple 不公布支援期限，較新的版本顯示「未知」）。
  已過期 → `vuln.os_eol`（高）；90 天內到期 → `vuln.os_eol_soon`（中）。
- **Windows 更新過舊**：最近一次安裝更新超過 45 天 → `vuln.updates_stale`（中），超過 90 天為高。
- **Linux 待安裝的安全性更新** → `vuln.pending_security_updates`（中）。
- **常見軟體的已知漏洞版本**（`feeds/vuln/curated-apps.json`）：WinRAR、7-Zip、Chrome、Edge、PuTTY、Git、VLC 等有公開利用的漏洞，
  以及已停止支援的 Node.js／Python 版本。只比對名單內的軟體，版本比較會處理 `2.45.1.windows.1`、`1:2.43.0-1ubuntu7`、`1.0rc1` 這類寫法。
  每筆都附 NVD 連結 → `vuln.app.<規則 id>`。
- **OSV（Linux 套件，線上）**：把 dpkg／rpm／apk 套件依發行版生態系（`Debian:12`、`Ubuntu:24.04:LTS`、`Alpine:v3.20`、`Rocky Linux:9`…）
  送到 [OSV.dev](https://osv.dev) `querybatch`，再抓前 300 個漏洞的細節（CVE 別名、嚴重度）。結果快取 24 小時（`<設定目錄>/vuln/osv-result.json`）。
  → `vuln.osv_package`（每個套件一筆，最多 30 筆，低嚴重度不列）。
- **CISA KEV**：`ai-security-monitor intel update` 會下載 CISA 已知遭利用漏洞清單；比對到的 CVE 一律升為**嚴重**並標 `kev`。

## 限制

- Windows／macOS 的一般軟體沒有通用的漏洞資料庫可對（名稱、版本格式各家不同），所以只做名單內的保守比對，不會「猜」。
  要完整的應用程式漏洞掃描，可另外用 trivy／grype 之類的工具。
- OSV 只涵蓋發行版套件；自己編譯或用 pip／npm 裝的不在內。
- `--no-online` 或設定 `scan.online = false` 時不查 OSV。

## 資料來源與授權

| 來源 | 用途 | 授權 |
|---|---|---|
| [OSV.dev](https://osv.dev) | Linux 套件漏洞 | 資料依各來源授權（多為 CC-BY 4.0），API 免費 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已遭利用的 CVE | 公有領域 |
| [NVD](https://nvd.nist.gov) | 內建規則的 CVE 參考連結 | 公有領域 |
| 微軟、各發行版、Apple 公告 | 作業系統支援期限 | 整理自官方生命週期頁面 |
