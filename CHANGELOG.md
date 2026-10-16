# Changelog

## 未發佈

**專案骨架：`asa` Rust agent 的核心模組與 CLI 樹。**

改進：
- `agent/`：error / i18n（zh-TW 字面即 key）/ config / store（原子寫入）/ secrets（keychain 或 0600 檔案）/ embedded feeds。
- 資料契約：Finding（穩定 id）、Verdict（安全／未知／可疑／危險＋理由）、Connection（方向）、Report、Baseline、Allowlist。
- Scanner trait 與 Pipeline（相依排序、白名單、基準線、分數）。
- CLI：`version`、`doctor`、`scan`、`config`、`allowlist`、`baseline`；`--lang en` 全部 help 有英文。
- `feeds/registry.json`：26 個情資／漏洞／地理來源，含授權與來源 URL；`feeds/known-good.json`。

> 驗證：`cargo test`、`cargo clippy --all-targets -- -D warnings`、`asa --lang en --help`、`asa doctor`、`asa scan --json`（尚無掃描器，輸出空報告）。
