# 通知（Email、Slack、Discord、Teams、Webhook、Syslog）

Security Hub 每分鐘檢查一次有沒有新的重要事件，依你設的**規則**送到**頻道**。設定在「設定與金鑰 → 通知」。

## 頻道

| 種類 | 需要的設定 | 備註 |
|---|---|---|
| Email | SMTP 伺服器、port、帳號密碼、寄件人、收件人 | 587＝STARTTLS；465 要勾「一連線就使用 TLS」 |
| Slack | Incoming Webhook 網址 | |
| Discord | 頻道的 Webhook 網址 | 訊息超過 2000 字會截斷 |
| Microsoft Teams | Workflows「收到 webhook 要求時張貼到頻道」的網址 | 送 Adaptive Card |
| Webhook | 任何 http(s) 網址，選填簽章金鑰 | 見下方格式 |
| Syslog | 主機、port、UDP／TCP、RFC 5424 或 CEF | facility local0 |

新增後按「送測試訊息」確認收得到。密碼、webhook 網址與簽章金鑰以 AES-256-GCM 加密存在資料庫，網頁只顯示遮罩、稽核紀錄不記內容。
加密金鑰：建議設 `AI_SECURITY_MONITOR_HUB_SECRETS_KEY`（32 bytes，64 個 hex 或 base64；產生：`openssl rand -hex 32`）；沒設時 Hub 第一次用到會自己產生一把存在資料庫（只防「資料庫備份外流」）。**設了之後不要再改**，否則已存的祕密解不開，要重新填。

## 規則

| 事件 | 什麼時候送 |
|---|---|
| 新的問題 | 掃描找到新的問題，嚴重度達到門檻（預設「高」以上） |
| 新的危險連線 | 有主機連到（或被連自）判定危險的位址 |
| 主機沒有回報 | 超過 N 分鐘（預設 30）沒有回報；斷線超過 7 天的不再通知 |
| 新主機加入 | 有新電腦加入 |
| 封鎖等待審核 | 有封鎖 IP／關閉 port 等你核准 |
| 每日摘要 | 每天指定的 UTC 整點：待處理問題、新增問題、沒回報的主機、等待審核的封鎖 |

- 只通知規則**建立之後**發生的事（不會一建立就把舊問題全部送一遍）。
- 同一件事同一條規則只送一次；一次檢查發現好幾件合併成一則（最多列 20 項）。
- 送不出去會重試 3 次（每分鐘一次），頻道上顯示最後的錯誤；紀錄保留 30 天。
- 多個 Hub 行程共用同一個資料庫時，只有一個會送（advisory lock）。

## Webhook 格式

```json
POST <你的網址>
content-type: application/json
x-aism-timestamp: 1792300000
x-aism-signature: sha256=<HMAC-SHA256(簽章金鑰, "<timestamp>.<body>") 的 hex>

{ "event": "finding", "title": "ai-security-monitor：2 個新的問題", "lines": ["[嚴重] demo-host — …"],
  "severity": "critical", "link": "https://hub.example.com/findings", "sent_at": "2026-10-18T01:00:00.000Z" }
```

驗證：用同一把金鑰算 `timestamp + "." + 原始本文` 的 HMAC-SHA256，跟標頭比對，並拒絕時間戳太舊（例如超過 5 分鐘）的請求。

## 語言與連結

「一般設定」可選訊息語言（繁中／English）與 Hub 網址（訊息裡「在 Security Hub 開啟」的連結；收通知的人要連得到）。
