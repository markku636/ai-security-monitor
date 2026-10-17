# 自動尋找 Hub、免金鑰加入

[English](enrollment.en.md) | 繁體中文

辦公室的電腦不用拿金鑰、也不用手動設定：裝好 ai-security-monitor（或桌面版）後，它會自己找到公司的 Security Hub，
送出「加入申請」就完成：Hub 預設是「**自動允許加入**」，申請一送到就核准；改成「**審核加入**」的話，管理員在 Hub 上按「核准」才完成。
原本用註冊金鑰的方式（`enroll <網址> --key …`）照樣可以用，不受加入模式影響。

## 運作方式

1. **找 Hub**（依序，前一種找到能用的就不再往下找）
   1. 明確給的網址：`enroll --hub <網址>`、從 Hub 下載的安裝指令（已預填這個 Hub 的網址）、環境變數 `AI_SECURITY_MONITOR_HUB_URL`
   2. 公司 DNS 的 SRV 紀錄 `_aisecmon._tcp.<公司網域>`（用電腦本身的 DNS 搜尋網域：Windows 的 DNS 尾碼、Linux 的 `/etc/resolv.conf`、macOS 的 `scutil --dns`）
   3. 區網廣播（mDNS／DNS-SD）`_aisecmon._tcp.local`，等 3 秒
2. **確認是公司的 Hub**：每個找到的 Hub 都要用自己的金鑰（Ed25519）對這次的隨機挑戰簽章，電腦端驗過才列出，
   並顯示 Hub 的**指紋**（例：`72AS-YEXT-VNGO-NLC5-W2NM`）。
3. **送出加入申請**：帶上主機名稱、作業系統、IP、版本，以及一組只有這台電腦知道的隨機密語（Hub 只存它的雜湊）。
   電腦端與 Hub 管理頁都會顯示同一組**核對碼**（例：`EA2B-3TOV`），管理員可以確認是哪一台。
4. **核准**（依 Hub 的「加入模式」）：
   - **自動允許加入（預設）**：申請一送到就核准。若「自動核准的網段」有填，只有那些網段自動核准，其他的等管理員。
   - **審核加入**：Hub「新增主機 → 待核准的主機」按「核准」（可多選）；來源 IP 在「自動核准的網段」裡的仍直接核准。
   - 兩種模式下，以前加入過但身分沒有釘選、或已被刪除的主機一律要人工核准；自動核准每 10 分鐘最多 60 台、已核准未領取最多 500 台，超過的改成等人工核准。
5. **完成**：電腦拿到一把**只屬於這台**的註冊金鑰（綁定這台的 agent id，拿去給別台用會被拒絕；在「設定與金鑰 → 註冊金鑰」可以撤銷），
   照一般流程註冊、記下 Hub 指紋，開始回報。

要等核准時，`enroll --auto` 會一直等（預設 15 分鐘，`--wait` 可調）；中斷或逾時都沒關係，
再執行一次 `enroll --auto`，或已安裝的背景服務（`watch`）都會接著等，核准後自動開始回報。申請 7 天沒處理就過期。

## 管理員要做的事

1. 打開 Hub 的「新增主機」頁，記下最上面的 **Hub 指紋**（要告訴同事，讓他們核對）。
2. 讓電腦找得到 Hub，擇一即可：
   - **最簡單**：把頁面上「免金鑰安裝指令」給同事（指令裡已經是這個 Hub 的網址），或下載預填好的 `install.ps1`／`install.sh` 用派送工具執行。
   - **公司 DNS**：加 SRV（＋TXT）紀錄，見下方「DNS SRV 紀錄」。
   - **區網廣播**：伺服器版 Hub 預設會廣播；Hub 跑在 Docker 裡時看下方「mDNS 廣播」。
3. 選「加入模式」：
   - **自動允許加入**（預設）：任何連得到 Hub、知道網址的電腦都能加入。Hub 只在公司內網時最省事；若 Hub 開放到網際網路，建議改審核，或在「自動核准的網段」填公司網路，只讓那些網段自動加入。
   - **審核加入**：每一台都要你核准。要強制審核（網頁上不能改）就設環境變數 `AI_SECURITY_MONITOR_HUB_ENROLL_MODE=review`。
4. （選用）在「自動核准的網段」填公司內網，例如 `192.168.10.0/24`、`10.20.0.0/16`。審核模式下：這些網段送來的直接核准、空白＝全部手動核准；自動模式下：空白＝全部自動、有填＝只有這些網段自動。
   只看 TCP 連線的真正來源位址；Hub 在反向代理後面時要設 `AI_SECURITY_MONITOR_HUB_TRUST_PROXY=1`，才會改用代理給的 `X-Forwarded-For`。
5. 有待核准的申請時側欄「新增主機」會出現數字；核對主機名稱、IP、核對碼後按「核准」或「拒絕」。自動模式下這一區改成「最近加入的主機」。核准、拒絕、自動核准、修改加入模式與網段都會記在稽核紀錄。

## 辦公室電腦要做的事

- **桌面版**：加入、等候核准、更換、離開都在「設定 → 公司的 Security Hub」。第一次開啟、還沒加入 Hub 時會直接帶到這一區並自動尋找 → 確認指紋和管理員給的一樣 → 按「申請加入」→ Hub 允許自動加入就馬上完成，否則等核准（顯示 Hub 指紋與核對碼，自動確認）。
  找不到時可以在同一區輸入管理員給的網址；另有「測試連線」「我有註冊金鑰」「離開這個 Hub」「更換 Hub 或重新加入」。
- **命令列**：

  ```bash
  ai-security-monitor enroll --auto            # 找 Hub、顯示指紋、確認後送出申請並等核准
  ai-security-monitor discover                 # 只列出找到的 Hub
  ai-security-monitor enroll --hub https://hub.example.com   # 指定 Hub（找到好幾個時）
  ai-security-monitor service install --yes    # 開機自動回報（還沒核准也可以先裝，它會在背景等）
  ```

- **一行安裝**（從 Hub「新增主機」頁複製，網址已預填、不含金鑰）：

  ```powershell
  # Windows 個人電腦（PowerShell）；伺服器改成 'system' 並用系統管理員 PowerShell
  $env:AI_SECURITY_MONITOR_SERVICE='user'; irm https://hub.example.com/install.ps1 | iex
  ```

  ```bash
  curl -fsSL https://hub.example.com/install.sh | sh -s -- --service user     # 伺服器：--service system
  ```

  安裝腳本會送出加入申請、等 2 分鐘（`AI_SECURITY_MONITOR_ENROLL_WAIT`／`--wait`），還沒核准就照樣裝好背景服務，由服務繼續等。
  從 GitHub 下載的通用腳本沒有預填網址：加 `AI_SECURITY_MONITOR_AUTO_ENROLL=1`（或 `--auto-enroll`）改用自動尋找。

## Hub 指紋與信任

- 電腦第一次加入時記下 Hub 指紋（TOFU，trust on first use）。之後同一個網址、或自動找到的 Hub 指紋不同，
  就**拒絕上傳**並說明可能是 Hub 重新安裝、也可能有人冒充；要改加入新的 Hub 必須明確執行 `enroll --auto --repin`（或重新 `enroll --key`）。
- Hub 的核准結果也有 Hub 簽章，電腦端用記下的公鑰驗證，不是同一個 Hub 發的金鑰不收。
- 已用金鑰註冊的舊電腦，升級後第一次連上新版 Hub 時會自動記下指紋。
- Hub 的身分金鑰第一次啟動時產生並存在資料庫（`settings` 表）；從備份還原資料庫就會沿用。重新安裝、換掉資料庫＝新指紋，所有電腦要重新加入。
- http 只建議在公司內網用：指紋能擋住「找錯 Hub／有人架假的 Hub」，但擋不住能竄改網路封包的人偷看 http 內容，對外請用 https。

## DNS SRV 紀錄

名稱 `_aisecmon._tcp.<網域>`，指向 Hub 的主機與 port；同名的 TXT 可以帶 `url=`（完整網址，電腦端優先用它）與 `fp=`（Hub 指紋，不符就略過）。
沒有 `url=` 時：port 443／8443 用 https，其他用 http（`proto=https` 可指定），`path=/sub` 可指定子路徑。
服務名稱 `aisecmon` 符合 RFC 6335／6763 的 15 字上限；0.3.0 之前的說明用過 `_ai-security-monitor._tcp`，電腦端在新名稱查不到紀錄時仍會查它，但請改用新名稱。

Windows DNS Server（PowerShell）：

```powershell
Add-DnsServerResourceRecord -ZoneName corp.example -Name _aisecmon._tcp -Srv -DomainName hub.corp.example -Port 443 -Priority 0 -Weight 0
Add-DnsServerResourceRecord -ZoneName corp.example -Name _aisecmon._tcp -Txt -DescriptiveText "url=https://hub.corp.example"
Add-DnsServerResourceRecord -ZoneName corp.example -Name _aisecmon._tcp -Txt -DescriptiveText "fp=72AS-YEXT-VNGO-NLC5-W2NM"
```

BIND：

```
_aisecmon._tcp.corp.example. 3600 IN SRV 0 0 443 hub.corp.example.
_aisecmon._tcp.corp.example. 3600 IN TXT "url=https://hub.corp.example" "fp=72AS-YEXT-VNGO-NLC5-W2NM"
```

Hub「新增主機 → 自動尋找」卡片會依這個 Hub 的網址與指紋產生可直接複製的指令。驗證：`ai-security-monitor discover --no-mdns`。

## mDNS 廣播

- Hub 伺服器版預設在 UDP 5353 廣播 `_aisecmon._tcp`（`AI_SECURITY_MONITOR_HUB_MDNS=0` 關閉；單機版只綁 127.0.0.1，預設關）。
  TXT 帶 `fp=`、`v=`、`path=`、`proto=`，設了 `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` 時另帶 `url=`（建議設，電腦端直接用它）。
- **Docker 注意**：Docker Desktop（Windows／macOS）與預設的 bridge 網路**不會把 multicast 送到區網**，容器裡的廣播出不去。做法擇一：
  - Linux 主機：Hub 容器用 `network_mode: host`（compose 的 `ports:` 要拿掉，改用 `PORT` 環境變數決定 port）。
  - 任何平台（建議）：讓區網上一台電腦（通常就是跑 Docker 的那台）的**背景服務**代為廣播：
    桌面版「設定 → 讓區網裡的電腦找到這台的 Hub」打開，或命令列

    ```bash
    ai-security-monitor config set hub.advertise_url http://192.168.1.10:8088   # 區網的電腦要連的網址
    ```

    背景服務（`watch`）每分鐘確認一次 Hub 的身分端點：連得到才廣播（TXT 帶 `url=` 與 Hub 指紋 `fp=`），連續 3 次連不到就停止廣播，
    Hub 回來再自動恢復；設定改了一分鐘內生效，`off` 關閉。心跳會回報廣播狀態，Hub「新增主機」頁看得到哪台電腦在幫忙廣播。
  - 只想臨時廣播：`ai-security-monitor hub advertise --url https://hub.corp.example`（前景執行到 Ctrl-C）。它會先驗 Hub 的身分，再代為廣播
    （TXT 帶 `url=`，所以不必和 Hub 在同一台）。要用它長期執行可用 systemd／工作排程器，或 compose（Linux）：

    ```yaml
    services:
      hub-advertise:
        image: debian:bookworm-slim
        network_mode: host
        restart: unless-stopped
        volumes:
          - /usr/local/bin/ai-security-monitor:/usr/local/bin/ai-security-monitor:ro
        command: ["ai-security-monitor", "hub", "advertise", "--url", "https://hub.corp.example"]
    ```

- 防火牆：電腦端找 Hub 只送出 multicast 查詢並接收回應（UDP 5353）；廣播端（Hub 或 `hub advertise`）要允許 UDP 5353 進來，Windows 第一次執行可能跳出防火牆詢問。
- mDNS 只在同一個網段（同一個廣播網域）有效；跨網段、VPN、遠端辦公室請用 DNS SRV 或預填網址的安裝指令。
- **單機版只綁 127.0.0.1**：辦公室其他電腦連不到，廣播了也沒用。要給全辦公室用，改用伺服器版（`docker/compose.yml`），或在單機版的 `.env` 設
  `AI_SECURITY_MONITOR_HUB_BIND=0.0.0.0` 與 `AI_SECURITY_MONITOR_HUB_PUBLIC_URL=http://<區網 IP>:8088` 後重新 `docker compose up -d`。
  打開之後同一個網路的任何人都看得到登入頁、也能呼叫上傳 API：一定要有管理員金鑰、只在公司內網使用，對外請放在 https 反向代理後面。

### Hub 上看「辦公室的電腦找得到這個 Hub 嗎？」

Hub「新增主機」頁最上面用一句白話說明現在的狀況（找得到／連得到但還找不到／連不到），並逐項列出：綁定位址（compose 帶進容器的
`AI_SECURITY_MONITOR_HUB_BIND`）、對外網址是不是本機位址、Hub 自己的 mDNS（在 Docker 裡會提醒出不了區網）、有沒有電腦在幫忙廣播
（最近 15 分鐘的心跳，指紋要和這個 Hub 相同）、公司 DNS 有沒有 `_aisecmon._tcp` SRV 紀錄（對外網址是公司網域的名稱才查）。連不到時附上改法與安全提醒。

## Hub 端設定

| 環境變數 | 預設 | 說明 |
|---|---|---|
| `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS` | 開 | `0` 關閉免金鑰加入申請（只能用金鑰） |
| `AI_SECURITY_MONITOR_HUB_ENROLL_MODE` | －（網頁設定，預設 `auto`） | `auto`＝自動允許加入、`review`＝審核加入；有設就鎖定，網頁上不能改 |
| `AI_SECURITY_MONITOR_HUB_MDNS` | 伺服器版開、單機版關 | 區網 mDNS 廣播 |
| `AI_SECURITY_MONITOR_HUB_BIND` | 伺服器版 `0.0.0.0`、單機版 `127.0.0.1` | compose 的主機綁定位址（也帶進容器，讓「新增主機」頁判斷區網連不連得到） |
| `AI_SECURITY_MONITOR_HUB_NAME` | `Security Hub` | 電腦端看到的 Hub 名稱 |
| `AI_SECURITY_MONITOR_HUB_PUBLIC_URL` | － | 對外網址：安裝指令、SRV 範例與 mDNS 的 `url=` 都用它 |
| `AI_SECURITY_MONITOR_HUB_TRUST_PROXY` | 關 | 在反向代理後面時開啟，自動核准網段才看得到真正的來源 IP |

濫用防護：同一來源 IP 每 10 分鐘最多 120 個申請、待核准最多 500 個；自動核准每 10 分鐘最多 60 台、已核准未領取最多 500 台；輪詢密語錯誤 30 次／10 分鐘就暫時封鎖該 IP；身分端點每分鐘 120 次。
API 細節見 [Agent ↔ Hub 契約](hub-contract.md#免金鑰加入)。

## 疑難排解

| 狀況 | 原因與處理 |
|---|---|
| `沒有找到 Security Hub` | DNS 沒有 SRV 紀錄、不在同一個網段、或 Hub 在 Docker 裡沒廣播出來 → 用 `enroll --hub <網址>`，或依上面設定 SRV／`hub.advertise_url` |
| `discover` 只找到「設定檔」那一列 | 這台已經加入的 Hub 連得到，但公司 DNS 與區網廣播都找不到它 → 其他電腦也會找不到；照上面設定 SRV 或 `hub.advertise_url`，並確認 Hub 不是只綁 127.0.0.1 |
| 打開區網廣播後別台還是找不到 | Hub 只綁 127.0.0.1（廣播的網址連不到時會自動暫停，`status`／桌面版會顯示原因）、防火牆擋了 UDP 5353，或不在同一個網段 |
| `找到好幾個不同的 Hub` | 區網上有多個 Hub（例如測試機）→ 問管理員指紋，用 `--hub` 指定 |
| `Hub 的身分指紋變了` | Hub 重新安裝（換了資料庫）或有人冒充 → 先跟管理員確認新指紋，再 `enroll --auto --repin` |
| `這個 Hub 沒有開放免金鑰加入` | Hub 設了 `AI_SECURITY_MONITOR_HUB_ENROLL_REQUESTS=0` → 跟管理員拿註冊金鑰 |
| 自動核准沒生效 | Hub 在反向代理後面但沒開 `TRUST_PROXY`（看到的都是代理的 IP），或網段沒包含電腦的位址；「待核准的主機」的「來源 IP」欄就是 Hub 看到的位址 |
