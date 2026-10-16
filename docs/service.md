# 開機自動啟動與背景服務

[English](service.en.md) | 繁體中文

`asa service` 讓 `asa watch`（定期掃描、上傳 Hub、連線快照、心跳、遠端動作）在開機或登入後自動在背景執行。

```bash
asa service install                 # 使用者層：登入時啟動，不需要系統管理員（個人電腦）
asa service install --system        # 系統服務：開機就啟動，需要系統管理員／root（伺服器）
asa service install --interval 30m  # 完整掃描間隔（預設取設定 scan.interval）
asa service status                  # 兩種範圍的安裝狀態與正在執行的 asa watch
asa service logs [--system] [--tail 100]
asa service restart [--system]     # 例如 asa self-update 之後換成新版
asa service uninstall [--system]
```

沒加 `--yes` 時只列出會執行的每一步（寫哪個檔、跑哪個指令），不會改任何東西；確認後再加 `--yes`。
`--system` 沒有系統管理員權限時，會請求提權重跑同一個命令（Windows UAC、Linux pkexec／sudo、macOS 管理員密碼）。

## 各平台做法

| | 系統服務（`--system`） | 使用者層（預設） |
|---|---|---|
| Windows | 服務控制管理員：`sc.exe create asa … start= auto`，失敗自動重啟（1、1、5 分鐘），以 LocalSystem 執行 `asa service run` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 的 `asa` 值；安裝時立即在背景啟動，登入時自動啟動（啟動後關掉自帶的主控台視窗） |
| Linux | `/etc/systemd/system/asa.service`（`Restart=on-failure`、`ProtectSystem=full`、只開放設定目錄可寫），`systemctl enable` 後重啟 | 有 `systemctl --user` 就用 `~/.config/systemd/user/asa.service`；沒有就用 `~/.config/autostart/asa.desktop`（桌面登入時啟動）並立即在背景啟動 |
| macOS | `/Library/LaunchDaemons/dev.asa.agent.plist`，`launchctl bootstrap system` | `~/Library/LaunchAgents/dev.asa.agent.plist`，`launchctl bootstrap gui/<uid>` |

## 設定目錄與密鑰

- 使用者層用你自己的設定目錄（`asa config path`）與鑰匙圈。
- 系統服務用系統目錄，並一律用檔案密鑰庫（LocalSystem／root 沒有使用者的鑰匙圈）：
  Windows `C:\ProgramData\ai-security-agent`、Linux `/var/lib/asa`、macOS `/Library/Application Support/ai-security-agent`。
- 安裝系統服務時，如果目前使用者已經 `asa enroll`，會把註冊資料（agent id、Hub 網址、client 金鑰、身分 token、驗章金鑰、白名單、基準線）複製到系統目錄，
  Hub 上看到的還是同一台主機。還沒註冊的話，之後以系統管理員執行 `asa --config-dir <系統目錄> enroll <HUB_URL> --key …`。

## 常駐行程

- 同一個設定目錄只會有一個常駐的 `asa watch`（`watch.lock` 單一實例鎖）；第二個會寫一行 log 後直接結束。
- log 寫在 `<設定目錄>/logs/asa-YYYY-MM-DD.log`（UTC 日期），保留 14 天；服務模式不寫主控台。
- 收到 Ctrl-C、SIGTERM（systemd／launchd 停止）或 Windows 服務的停止／關機通知時，做完手上的工作就結束。

## 注意

- Linux 使用者層（systemd --user）預設只在登入期間執行；伺服器要開機就跑，請用 `--system`，或 `sudo loginctl enable-linger $USER`。
- Windows「執行」機碼的命令列上限 260 字元：設定目錄是預設位置時會省略 `--config-dir`；超過時安裝會提醒你把 asa 放到較短的路徑。
- 升級 asa 後不用重裝服務；服務指向的是 asa 執行檔本身的路徑。
