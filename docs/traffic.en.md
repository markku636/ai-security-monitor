# Traffic analysis

English | [繁體中文](traffic.md)

`ai-security-monitor` takes a "Wireshark, but only the highlights" approach: instead of individual packets it tells you who this machine is talking to and what deserves a look.
There are two modes; both produce the same summary (`TrafficSummary`), which is also what gets handed to the AI and uploaded to Security Hub.

| Mode | Command | Needs | Shows |
|---|---|---|---|
| Live (flow-lite) | `ai-security-monitor traffic [--duration 30s]` | nothing to install, no administrator rights | which process talks to which remote, newly opened connections, interface totals, intel hits, risky ports, beaconing (from the 24-hour connection history) |
| Offline (pcap) | `ai-security-monitor traffic analyze <file>` | a `.pcap` / `.pcapng` from any tool | all of the above plus per-connection bytes, DNS queries and answers, TLS SNI, HTTP Host, large uploads, plain-text protocols |

In addition, `watch` (the background service) records upload/download per network card and per program every minute and reports it to the Hub (bandwidth charts, which hosts and programs use the most); on the command line `ai-security-monitor metrics` shows the current rates. See [metrics.en.md](metrics.en.md).

![Hub traffic page](images/traffic.png)

`ai-security-monitor` does not install a capture driver. For packet-level analysis, save a capture with a built-in or trusted tool and hand it to `ai-security-monitor traffic analyze`:

```powershell
# Windows (built-in pktmon, elevated PowerShell)
pktmon start --capture --pkt-size 256
# …reproduce the issue…
pktmon stop
pktmon etl2pcap PktMon.etl -o cap.pcapng
ai-security-monitor traffic analyze cap.pcapng
```

```bash
# macOS / Linux
sudo tcpdump -i any -s 256 -w cap.pcap   # Ctrl+C to stop
ai-security-monitor traffic analyze cap.pcap
```

Files saved by Wireshark work too. `--pkt-size 256` / `-s 256` keeps only the first 256 bytes of each packet: enough for DNS, SNI and HTTP Host, a much smaller file, and no full payloads on disk.
`ai-security-monitor doctor` lists the capture tools available on the machine.

## Detections

| Alert | Rule |
|---|---|
| Intel hit | the remote IP or a queried domain is in the downloaded threat intel; includes vendor, confidence and the source list URL |
| Plain-text protocol | Telnet, FTP, r-services (high); HTTP, SMTP, POP3, IMAP, LDAP, TFTP, SNMP (low) |
| Risky port | outbound to a port marked outbound/any in `feeds/vuln/risky-ports.json` (4444, 23, 2375…) |
| Large upload | ≥ 50 MB sent to one remote, or ≥ 1 MB with 10× more sent than received |
| Beaconing | at least 4 new connections from the same source to the same remote:port, ≥ 5 s apart, coefficient of variation ≤ 0.2 (typical C2 beacon) |
| Suspicious DNS | long high-entropy labels (DGA / DNS tunnelling), rare TLDs (.zip, .mov, .top, .xyz…) |

Every list in the summary is capped (15 top destinations, 50 DNS names, 30 SNI/Host names, 100 alerts) so the JSON stays around 40 KB, small enough to hand straight to an LLM.

## Limitations

- Offline mode decides client/server by who sent the SYN; UDP conversations already in progress when the capture started are guessed from ports and are occasionally reversed.
- SNI is read from the first TCP segment of the ClientHello only; it is missed when the hello is split (rare) or with TLS 1.3 ECH.
- Live mode (`traffic`) cannot see per-connection bytes on Windows; per-program bytes come from the traffic statistics instead (Windows needs administrator rights, see [metrics.en.md](metrics.en.md)).
- At most 2 million packets and 20,000 flows are processed; anything beyond is noted in `notes`.
