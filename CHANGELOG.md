# Changelog

## 未發佈

**專案骨架：`asa` Rust agent 的核心模組與 CLI 樹。**

改進：
- `agent/`：error / i18n（zh-TW 字面即 key）/ config / store（原子寫入）/ secrets（keychain 或 0600 檔案）/ embedded feeds。
- 資料契約：Finding（穩定 id）、Verdict（安全／未知／可疑／危險＋理由）、Connection（方向）、Report、Baseline、Allowlist。
- Scanner trait 與 Pipeline（相依排序、白名單、基準線、分數）。
- CLI：`version`、`doctor`、`scan`、`config`、`allowlist`、`baseline`；`--lang en` 全部 help 有英文。
- `feeds/registry.json`：26 個情資／漏洞／地理來源，含授權與來源 URL；`feeds/known-good.json`。
- connections 引擎（第 1 輪）：netstat2＋sysinfo 列出 socket 並接上行程（exe sha256 快取）、方向判定（對外／對內／監聽／本機）、
  風險 port 表（`feeds/vuln/risky-ports.json`）、shell／腳本程式對外、暫存目錄行程、曝露 listener、beacon 偵測（24h 歷史）、
  known-good（公共 DNS 等）與白名單 → 每條連線的安全／未知／可疑／危險判定與理由；`asa connections [--direction] [--verdict] [--watch]`。
- 曝露類 finding 計入「曝露」面向；同 id finding 去重；`.gitattributes` 統一 LF。

> 驗證：`cargo test`（56 passed）、`cargo clippy --all-targets -- -D warnings`、`asa --lang en --help`、`asa doctor`、`asa connections`（實機 521 socket、0.4 s）、`asa scan --json`。
