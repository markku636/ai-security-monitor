# 安全性問題回報 · Security policy

## 回報漏洞 · Reporting a vulnerability

請**不要**開公開的 issue。到這個 repo 的 **Security → Report a vulnerability**（GitHub 私下回報）告訴我們：

- 影響哪個元件（桌面版、命令列版 agent、Security Hub、防護 DNS、安裝腳本）和版本；
- 重現步驟或概念驗證；
- 你判斷的影響（例如本機提權、遠端執行、資料外洩）。

我們會在 7 天內回覆，修好後發新版並在 CHANGELOG 註明（你願意的話會列出你的名字）。

Please **do not** open a public issue. Use **Security → Report a vulnerability** (GitHub private reporting) on this repository and include
the affected component and version, steps to reproduce, and the impact you expect. We reply within 7 days and credit you in the CHANGELOG
if you wish.

## 支援的版本 · Supported versions

只修最新的版本（[Releases](https://github.com/markku636/ai-security-monitor/releases/latest)）；請先升級再回報。
Only the latest release receives security fixes.

## 設計上的安全措施 · Security design notes

- 遠端動作（封鎖 IP 等）預設關閉；開啟後每個動作都要 Hub 的 HMAC 簽章、有期限，破壞性的動作要另外允許。
- Hub 的集中設定與加入核准用 Hub 的 Ed25519 身分簽章，主機第一次連線時釘選。
- 桌面版的自動更新檔用 minisign 簽章；命令列版下載後比對 SHA256。
- 執行檔沒有向 Microsoft／Apple 購買程式碼簽章，第一次打開會有系統警告（見 README「安裝」）。
