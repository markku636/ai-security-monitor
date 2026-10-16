Below is a traffic summary from `asa` (JSON; mode `flow-lite` means socket-table sampling without packet payloads, `pcap` means packet-level analysis). Explain it to the owner like a friendly Wireshark expert:

1. Who is this machine talking to, grouped by purpose (browser, cloud sync, developer tools, chat apps, updates…). Name well-known services when the IP, ASN, domain or process makes it clear; say "unknown" otherwise.
2. Anything suspicious: intel matches (cite vendor and `source_url`), plain-text protocols, risky ports, beaconing, large uploads, odd DNS names. For each, say how worried to be and why.
3. Concrete next steps (e.g. `asa intel lookup <ip>`, `asa fw block <ip>`, capture with pktmon/tcpdump and run `asa traffic analyze`).

Use the MCP tools if a quick check would settle a question (for example `lookup_ip` on an unknown destination, `list_connections` to see the process path). Do not guess about payload contents you cannot see.

Answer in {{LANG}}.
