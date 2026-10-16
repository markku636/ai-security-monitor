# Changelog

## 未發佈

**專案骨架：`asa` Rust agent 的核心模組與 CLI 樹。**

改進：
- `agent/`：error / i18n（zh-TW 字面即 key）/ config / store（原子寫入）/ secrets（keychain 或 0600 檔案）/ embedded feeds。
- 資料契約：Finding（穩定 id）、Verdict（安全／未知／可疑／危險＋理由）、Connection（方向）、Report、Baseline、Allowlist。
- Scanner trait 與 Pipeline（相依排序、白名單、基準線、分數）。
- CLI：`version`、`doctor`、`scan`、`config`、`allowlist`、`baseline`；`--lang en` 全部 help 有英文。
- `feeds/registry.json`：25 個情資／漏洞／地理來源，含授權與來源 URL；`feeds/known-good.json`。
- connections 引擎（第 1 輪）：netstat2＋sysinfo 列出 socket 並接上行程（exe sha256 快取）、方向判定（對外／對內／監聽／本機）、
  風險 port 表（`feeds/vuln/risky-ports.json`）、shell／腳本程式對外、暫存目錄行程、曝露 listener、beacon 偵測（24h 歷史）、
  known-good（公共 DNS 等）與白名單 → 每條連線的安全／未知／可疑／危險判定與理由；`asa connections [--direction] [--verdict] [--watch]`。
- 曝露類 finding 計入「曝露」面向；同 id finding 去重；`.gitattributes` 統一 LF。

- intel 引擎（第 2 輪）：情資登錄（內建＋`<config>/feeds/custom.json` 自訂 https 來源＋啟停狀態）、下載（ETag／Last-Modified、96 MB 上限、
  HTML 錯誤頁或空清單不覆蓋舊資料、DB-IP 月份網址自動回退）、8 種格式解析（純文字、Spamhaus NDJSON、URLhaus、ThreatFox、DShield、IPsum、KEV、mmdb）、
  IpSet 重疊區間二分搜尋（IPv4／IPv6／ip:port／網域含上層／ASN）、DB-IP 國家與 ASN、每筆命中附廠商／授權／來源網址／信心。
- 連線判定接上情資：命中高信心來源 → 危險；Tor／低信心 → 可疑；`intel.outbound_match`／`intel.inbound_match` finding 附封鎖動作。
- 線上名譽查詢（AbuseIPDB、GreyNoise、CrowdSec CTI；需自備 key、預設關）：24h 快取＋每日額度上限。
- CLI：`asa intel update|status|sources|lookup|enable|disable|key`、`asa connections --intel`（顯示國家）、`asa doctor` 情資新鮮度。
- 移除 abuse.ch SSLBL IP 清單（官方已於 2025-01-03 停用）；URLhaus 網域級命中降為可疑（共用 CDN 不整台判死）。

> 驗證：`cargo test`（77 passed）、`cargo clippy --all-targets -- -D warnings`；實機 `asa intel update` 16 個來源 3.6 s（IPsum 12.5 萬、blocklist.de 2.5 萬、KEV 1746）；`asa intel lookup` 對 Spamhaus／Feodo 列名 IP 判危險並列出 6 個來源，8.8.8.8 判安全；`asa scan` 含情資 1 s。
