# ai-security-agent

[繁體中文](./README.md) · **English**

A defensive security agent (`asa`, Rust, Windows / macOS / Linux) plus a Security Hub (Next.js).

- Catches **anomalous inbound and outbound connections** and grades them **safe / unknown / suspicious / dangerous** against public threat-intelligence feeds, with the source and licence attached to every hit.
- Scans open ports, firewall state, vulnerabilities (OSV / NVD / CISA KEV / EPSS) and system hardening.
- Wireshark-like traffic summaries and Windows event / crash analysis, explained by **Claude Code / Codex CLI**.
- Both the agent and the hub are **MCP servers**, queryable straight from Claude Code / Codex.
- Standalone (local hub) and server (fleet) editions, Docker deployment, self-update.

> Work in progress (round 0: agent skeleton). Full docs, screenshots and installers land in later rounds.

## Build from source

```bash
cd agent
cargo build --release
./target/release/asa --lang en --help
./target/release/asa --lang en doctor
```

## License

MIT © 2026 mark.ku (markku636). Third-party feed licences are listed in [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
