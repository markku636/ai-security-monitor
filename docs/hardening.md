# 系統硬化檢查

[English](hardening.en.md) | 繁體中文

`asa harden` 逐條檢查這台機器的安全設定，列出沒過的項目、目前的值與怎麼修，並給 0–100 分。

```bash
asa harden                       # 只列未通過，附修正方式
asa harden --all                 # 全部檢查與結果
asa harden --category remote     # 只看某一類（account、remote、kernel、network、update、encryption、malware…）
asa --json harden                # 給程式或 AI 讀
asa scan --scanners hardening    # 進完整報告（summaries.hardening），asa watch 會一起上傳 Hub
```

全部唯讀，不會改任何設定。Windows 的 20 條檢查合併成一次 PowerShell 呼叫（約 3 秒）。

## 檢查項目

| 平台 | 項目 |
|---|---|
| Windows（20，含 Windows Server） | UAC 與提升權限提示、Defender 即時保護／病毒碼／竄改防護（裝了別家防毒時不適用）、SmartScreen、SMBv1 用戶端與伺服器、遠端桌面 NLA、BitLocker／裝置加密、安全開機、LSA 保護、WDigest、Guest 與內建 Administrator、自動更新沒被原則關閉、AutoRun、LLMNR、PowerShell 2.0、遠端登錄服務 |
| Linux（25） | SSH（root 登入、密碼登入、空白密碼、X11、MaxAuthTries、fail2ban／CrowdSec／sshguard）、核心參數（ASLR、kptr／dmesg 限制、非特權 eBPF、符號／硬連結保護、suid core dump、SYN cookies、rp_filter、ICMP redirect）、AppArmor／SELinux、UID 0 帳號、空白密碼、sudo NOPASSWD、PATH 可寫目錄、自動安全更新（Debian／Ubuntu unattended-upgrades、RHEL 系 dnf-automatic）、telnet／FTP／rsh、auditd |
| macOS（15） | Gatekeeper、SIP、FileVault、防火牆隱形模式、自動更新（檢查、安全性回應、XProtect 資料、下載）、訪客、自動登入、密碼提示、螢幕鎖定、遠端登入、sudo NOPASSWD、PATH 可寫目錄 |

防火牆是否開啟由防火牆引擎檢查（`asa fw audit`），這裡不重複。

## 結果與分數

- **通過**／**未通過**／**不適用**（例：沒裝 sshd、遠端桌面沒開、用別家防毒）／**錯誤**。
- 需要系統管理員或 root 才讀得到的項目（例：Linux 的 `/etc/shadow`、`/etc/sudoers`）在沒有權限時列為不適用，並在 `needs_admin` 註明。
- 分數＝通過數 ×2 ÷（通過數 ×2＋未通過權重），權重依嚴重度：嚴重 4、高 3、中 2、低 1。報告裡的「硬化」分數同一算法，被白名單壓掉的不扣分。
- 每個未通過項目產生一筆 `hardening.<id>` 發現，附修正方式與參考連結。

## Windows Server

同一份 Windows 策略也用在 Windows Server 2016／2019／2022／2025（含 Server Core 與網域控制站）。
版本從登錄判斷：`ProductOptions\ProductType`（WinNT 工作站／ServerNT 伺服器／LanmanNT 網域控制站）與
`CurrentVersion\InstallationType`（Client／Server／Server Core），`ai-security-monitor --json harden` 的 `editions` 會列出判斷結果
（例：`["server", "core", "dc"]`）。在 Server 上的差異：

| 檢查 | Windows Server 上 |
|---|---|
| Defender 即時保護／病毒碼／竄改防護 | 移除了 Defender 功能（`Uninstall-WindowsFeature Windows-Defender`）時不適用，而不是錯誤；竄改防護要加入 Defender for Endpoint 才能開，沒開算不適用 |
| SmartScreen | Server Core 沒有檔案總管與 SmartScreen → 不適用 |
| BitLocker | Server Core 改用 `Get-BitLockerVolume`（需要系統管理員）；沒裝 BitLocker 功能時不適用 |
| 遠端登錄服務 | 只檢查用戶端：Server 預設就會啟動，伺服器管理員與遠端管理需要它 |
| 內建 Administrator | 伺服器常留作復原帳戶：已改名也算通過（CIS 對成員伺服器要求改名）；網域控制站沒有本機帳戶 → 不適用（Guest 也是） |
| 修正方式 | 改顯示伺服器的做法：`Install-WindowsFeature`／`Uninstall-WindowsFeature`（`FS-SMB1`、`PowerShell-V2`、`BitLocker`）、sconfig、伺服器管理員 |

## 自訂檢查

在 `<設定目錄>/policies/` 放 `.yml` 檔（設定目錄見 `asa config path`）：同 id 會取代內建，`disabled: true` 關掉某條。

```yaml
# 關掉某條內建檢查
- id: win.llmnr.disabled
  severity: low
  title: { zh: x, en: x }
  probe: { registry: { path: 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', name: EnableMulticast } }
  expect: { op: eq, value: 0 }
  disabled: true

# 新增一條
- id: lin.custom.no_root_cron
  category: account
  severity: low
  title: { zh: "root 沒有排程工作", en: "root has no crontab" }
  remediation: { zh: "crontab -r -u root", en: "crontab -r -u root" }
  references: [ "https://man7.org/linux/man-pages/man5/crontab.5.html" ]
  probe: { file: /var/spool/cron/crontabs/root }
  expect: { op: empty }
  missing: pass
```

欄位：
- `id`：小寫英數與 `.` `_` `-`，前綴 `win.`／`lin.`／`mac.` 決定在哪個平台跑。
- `probe`（擇一）：`registry {path, name}`、`powershell`（回傳單一值）、`command [程式, 參數…]`、`file`、`sysctl`、`sshd {key, default}`、
  `service {names, query: active|enabled}`、`builtin`（`lsm`、`uid0_accounts`、`empty_passwords`、`sudo_nopasswd`、`path_world_writable`）；
  `command`／`file` 可加 `regex`（取第一個括號）與 `stderr: true`。
- `expect.op`：`eq` `ne` `gte` `lte` `contains` `not_contains` `matches` `in` `not_in` `empty` `not_empty`；比較不分大小寫，`"1"` 等於 `1`。
- `missing`：讀不到值時算 `pass`／`fail`／`na`（預設 `na`）；`na_values`：這些值代表不適用；`distros`：只在這些 Linux 發行版跑；`only_if_exists`：檔案不存在就不適用。
- `editions`：Windows 版本篩選，標籤 `client`、`server`、`core`（Server Core）、`desktop`（有桌面體驗的 Server）、`dc`（網域控制站），
  `not_<標籤>` 表示排除（例：`[client]`、`[not_core]`、`[server, not_dc]`）；`remediation_server`：Windows Server 上改顯示的修法。

## 參考

檢查項目整理自 Microsoft 安全性基準、CIS Benchmarks 的公開建議、各發行版與 Apple 平台安全性文件；每條都附原始參考連結。
本專案的策略檔為自行撰寫（MIT），沒有複製 CIS Benchmark 內容。
