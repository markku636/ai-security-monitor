# ai-security-agent

**繁體中文** · [English](./README.en.md)

防禦型資安 agent（`asa`，Rust，Windows / macOS / Linux）＋ Security Hub（Next.js）。

- 抓出**對外與對內的異常連線**，用公開威脅情資判定**安全／未知／可疑／危險**，每一筆都附來源與授權。
- 掃描開放 port、防火牆、漏洞（OSV / NVD / CISA KEV / EPSS）、系統硬化。
- 類 Wireshark 的流量彙整與 Windows 事件／當機分析，交給 **Claude Code / Codex CLI** 解讀。
- agent 與 hub 都是 **MCP server**，可直接從 Claude Code / Codex 查詢。
- 單機版（本機 Hub）與伺服器版（多台 agent 回報），Docker 部署，可自我更新。

> 目前為開發中（第 0 輪：agent 骨架）。完整文件、截圖與安裝方式將隨後續輪次補上。

## 從原始碼建置

```bash
cd agent
cargo build --release
./target/release/asa --help
./target/release/asa doctor
```

## 授權

MIT © 2026 mark.ku（markku636）。第三方情資來源的授權見 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。
