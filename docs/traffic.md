# 流量分析

[English](traffic.en.md) | 繁體中文

`ai-security-monitor` 的流量功能走「像 Wireshark，但只給重點」的路線：不用看一個個封包，直接告訴你這台機器在跟誰講話、哪些值得注意。
有兩種模式，產生同一種摘要（`TrafficSummary`），之後也是交給 AI 解讀、上傳 Security Hub 的格式。

| 模式 | 指令 | 需要 | 看得到 |
|---|---|---|---|
| 即時（flow-lite） | `ai-security-monitor traffic [--duration 30s]` | 什麼都不用裝、不需要系統管理員 | 每個行程連到哪些遠端、新出現的連線、介面總流量、情資命中、高風險 port、週期性連線（用 24 小時連線歷史） |
| 離線（pcap） | `ai-security-monitor traffic analyze <檔案>` | 一個 `.pcap`／`.pcapng`（任何工具存的都行） | 以上全部，再加上逐連線位元組、DNS 查詢與回應、TLS SNI、HTTP Host、大量上傳、明文協定 |

另外，`watch`（背景服務）每分鐘記錄各網卡、各程式的上傳／下載量並回報 Hub（頻寬圖、哪台與哪個程式用最多），命令列用 `ai-security-monitor metrics` 看現在的速率；見 [metrics.md](metrics.md)。

![Hub 流量頁](images/traffic.png)

`ai-security-monitor` 本身不安裝抓包驅動。要逐封包分析時，用系統內建或你信任的工具存檔，再交給 `ai-security-monitor traffic analyze`：

```powershell
# Windows（內建 pktmon，系統管理員 PowerShell）
pktmon start --capture --pkt-size 256
# …重現問題…
pktmon stop
pktmon etl2pcap PktMon.etl -o cap.pcapng
ai-security-monitor traffic analyze cap.pcapng
```

```bash
# macOS / Linux
sudo tcpdump -i any -s 256 -w cap.pcap   # Ctrl+C 結束
ai-security-monitor traffic analyze cap.pcap
```

也可以直接分析 Wireshark 存的檔案。`--pkt-size 256`／`-s 256` 只留每個封包前 256 bytes，就足夠解析 DNS、SNI 與 HTTP Host，檔案小很多，也不會留下完整內容。
`ai-security-monitor doctor` 會告訴你這台機器有哪些擷取工具可用。

## 偵測項目

| 警示 | 規則 |
|---|---|
| 情資命中 | 遠端 IP 或查詢的網域在已下載的威脅情資裡；附廠商、信心與來源清單網址 |
| 明文協定 | Telnet、FTP、r-services（高）；HTTP、SMTP、POP3、IMAP、LDAP、TFTP、SNMP（低） |
| 高風險 port | 連出到 `feeds/vuln/risky-ports.json` 標為 outbound／any 的 port（4444、23、2375…） |
| 大量上傳 | 對同一個遠端送出 ≥ 50 MB，或 ≥ 1 MB 且送出是收到的 10 倍以上 |
| 週期性連線 | 同一組來源 → 遠端:port 至少 4 次新連線、間隔 ≥ 5 秒、變異係數 ≤ 0.2（典型 C2 beacon） |
| 可疑 DNS | 很長的高熵標籤（DGA／DNS 通道）、少見頂級網域（.zip、.mov、.top、.xyz…） |

摘要裡的清單都有上限（主要對象 15、DNS 50、SNI／Host 30、警示 100），整份 JSON 控制在約 40 KB，適合直接交給 LLM。

## 限制

- 離線模式用「誰先送 SYN」判斷 client／server；擷取開始時已在進行的 UDP 會話用 port 猜，偶爾會反過來。
- SNI 只看 ClientHello 的第一個 TCP 區段；被切成多段（少見）或 TLS 1.3 ECH 時抓不到。
- 即時模式（`traffic`）在 Windows 看不到逐連線位元組；各程式的收發量改由流量統計提供（Windows 需要系統管理員，見 [metrics.md](metrics.md)）。
- 一次最多處理 200 萬個封包、追蹤 2 萬條流；超過的會在 `notes` 註明。
