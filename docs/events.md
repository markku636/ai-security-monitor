# 事件與當機分析

[English](events.en.md) | 繁體中文

`asa events` 把系統記錄整理成「發生了什麼、可能為什麼、該怎麼辦」，不用自己翻事件檢視器。

```bash
asa events                 # 近 7 天：當機、資安事件、最常出現的錯誤
asa events --since 30d     # 最多 90 天
asa events crashes         # 只看當機（預設 30 天）
asa events explain 0x7E    # 解釋藍屏代碼
asa events explain 4625    # 解釋事件 ID
asa events analyze x.evtx  # 分析匯出的檔案（.evtx、journalctl -o json、.ips／.panic、.dmp）
```

`asa scan`／`asa watch` 也會跑事件掃描（近 7 天），摘要放進報告的 `summaries.events`，上傳到 Security Hub。

## 讀哪些資料

| 平台 | 來源 | 需要系統管理員 |
|---|---|---|
| Windows | System、Application（錯誤與指定 ID）、Security（4625、4624、4720、4722、4728、4732、4756、4698、1102；伺服器另讀 4740、4771、4776，獨立上限 1000 筆）、Defender Operational、TerminalServices-RemoteConnectionManager/Operational（1149）；`%SystemRoot%\Minidump\*.dmp` 檔頭 | Security 記錄與 Minidump 需要；沒有權限時其他部分照跑，報告列出 `needs_admin` |
| Linux | `journalctl -o json`：priority 0–4、sshd／sudo／useradd／usermod／gpasswd | 要在 `systemd-journal`（或 `adm`）群組，或用 sudo |
| macOS | `/Library/Logs/DiagnosticReports`、`~/Library/Logs/DiagnosticReports`（.panic、.ips） | 否 |

## 當機

| 類型 | 來源 |
|---|---|
| 藍屏 | Kernel-Power 41（BugcheckCode ≠ 0）、WER 1001、Minidump 檔頭；同一次藍屏在三處出現只算一次，並附 `feeds/events/bugchecks.json` 的可能原因與處置 |
| 非預期關機 | Kernel-Power 41（代碼 0）、EventLog 6008；長按電源鍵會標註 |
| 程式當掉／沒回應 | Application Error 1000（程式、出錯模組、例外代碼）、Application Hang 1002；macOS .ips（bug_type 309） |
| 服務失敗 | Service Control Manager 7000、7001、7009、7011、7022–7024、7031、7034；systemd「Failed with result」 |
| 磁碟／硬體 | disk 7／51／153、Ntfs 55、storahci／stornvme 129；WHEA-Logger；Linux I/O error、MCE |
| 其他 | Windows Update 失敗（20）、顯示卡重設（Display 4101）、記憶體不足（2004）、Linux OOM、kernel panic／oops、segfault |

## 資安事件

| 規則 | 說明 |
|---|---|
| 暴力破解 | 同一來源 10 分鐘內 ≥ 10 次或總共 ≥ 30 次失敗登入（Windows 4625、網域控制站的 Kerberos 預先驗證失敗 4771、sshd）；公網來源附情資命中與「封鎖 IP」建議動作 |
| NTLM 驗證失敗爆量 | 4776 失敗（Status ≠ 0x0）依來源工作站計算，門檻同上；沒有 IP，所以不建議封鎖 |
| 帳號被鎖定 | 4740（附鎖定來源的電腦名稱） |
| 公網遠端登入 | 4624 LogonType 10／3、遠端桌面 1149（不需要系統管理員也讀得到）、sshd Accepted 來自公網 IP |
| 帳號與群組 | 新帳號（4720、useradd）、啟用帳號（4722）、加入管理員群組（4728／4732／4756、sudo／wheel） |
| 常駐手法 | 新服務（7045，依執行檔位置判斷嚴重度：暫存或使用者資料夾、script host → 高；系統或 Program Files → 低）、排程工作（4698） |
| 湮滅證據 | 稽核紀錄被清除（1102）、事件記錄被清除（104） |
| Defender | 偵測到威脅（1116／1117）、即時保護被關閉（5001） |

低嚴重度的項目（例如裝在 Program Files 的新服務）只出現在摘要，不會變成 finding。

## 限制

- 非管理員在 Windows 讀 Security 記錄時，系統只回「找不到事件」，所以 asa 以目前權限判斷並在 `needs_admin` 註明。
- 藍屏的出錯驅動（faulting module）要完整解析 dump 才看得到；目前只讀檔頭的代碼與參數，其餘交給 AI 或 WinDbg。
- macOS 的統一記錄（`log show`）與資安事件尚未納入。
