# Auto-response and host groups

Settings & keys → Auto-response. **Off by default**; once on, attacking source IPs that match a rule are blocked without manual confirmation and released when the time is up.

## How it works

1. The Hub checks the rules every minute (same scheduler as notifications).
2. For a matching source IP it creates a two-way "block IP" action for that host and approves it directly; `proposed_by` / `reviewed_by` is `auto:<rule id>`. The host picks it up on its next poll, verifies the signature and blocks it in its own firewall (exactly the same path as manually approved actions).
3. When it expires, an "unblock IP" action is created and approved. Turning the global switch off stops new blocks, but existing ones are still released on time.
4. Every step is audited: `response.blocked`, `response.released`.

## Triggers

| Trigger | Meaning |
|---|---|
| Brute-force source | The same source IP reaches the failed-logon threshold in the event logs (Windows logon failures, NTLM failures; default 10) |
| Inbound from an intel-listed source | In the latest connection snapshot, an IP on a threat-intel list is connected inbound |
| Specific finding rule | A finding with the given rule appears (e.g. `intel.inbound_match`, may end with `*`); the IP in the finding is blocked |

Only events after the rule was created and within the last 24 hours count.

## Guard rails

- Only **public** IPs are blocked; private, loopback, CGNAT, documentation and other reserved ranges never are.
- **Allowlisted ranges** are never blocked (office public IPs, partners, monitoring services).
- Only hosts that **accept remote actions** are affected (`remote_actions.accept` on the agent, with `block_ip` allowed); the page lists hosts that don't.
- One block per host and IP at a time; at most 50 new blocks per run.
- Repeat offenders (within 30 days): block time ×6, then ×24 (can be turned off).
- "Blocks" has a "Release now" button.

## Host groups

Group hosts (e.g. servers, shop PCs) so a rule applies to one group only. Deleting a group **disables** the rules limited to it (they never silently start applying to every host).
