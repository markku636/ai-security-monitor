# Notifications (Email, Slack, Discord, Teams, Webhook, Syslog)

Security Hub checks for important new events every minute and sends them to **channels** according to your **rules**. Configure it under Settings & keys → Notifications.

## Channels

| Type | Settings | Notes |
|---|---|---|
| Email | SMTP server, port, username/password, from, to | 587 = STARTTLS; for 465 tick "Use TLS from the start" |
| Slack | Incoming Webhook URL | |
| Discord | Channel webhook URL | Messages over 2000 characters are truncated |
| Microsoft Teams | URL from the Workflows template "Post to a channel when a webhook request is received" | Sends an Adaptive Card |
| Webhook | Any http(s) URL, optional signing key | See the format below |
| Syslog | Host, port, UDP/TCP, RFC 5424 or CEF | Facility local0 |

After adding a channel, press "Send test message". Passwords, webhook URLs and signing keys are stored AES-256-GCM encrypted; the page only shows a mask and the audit log never records them.
Encryption key: set `AI_SECURITY_MONITOR_HUB_SECRETS_KEY` (32 bytes as 64 hex chars or base64; generate with `openssl rand -hex 32`). Without it the Hub generates a key on first use and stores it in the database (this only protects leaked database backups). **Don't change the key once set**, or stored secrets can no longer be decrypted and must be re-entered.

## Rules

| Event | Sent when |
|---|---|
| New finding | A scan finds a new finding at or above the threshold (default: high) |
| New dangerous connection | A host connects to (or is reached from) an address judged dangerous |
| Host stopped checking in | No check-in for N minutes (default 30); hosts offline for more than 7 days are no longer reported |
| New host joined | A new computer joins |
| Block awaiting review | A block-IP / close-port action needs approval |
| Daily digest | At a chosen UTC hour: open findings, new findings, hosts not checking in, blocks awaiting review |

- Only events after the rule was created are sent (creating a rule does not replay old findings).
- Each event is sent once per rule; several events found in one check are combined into one message (up to 20 lines).
- Failed deliveries are retried 3 times (once a minute) and the channel shows the last error; the log is kept for 30 days.
- When several Hub processes share a database, only one sends (advisory lock).

## Webhook format

```json
POST <your URL>
content-type: application/json
x-aism-timestamp: 1792300000
x-aism-signature: sha256=<hex HMAC-SHA256(signing key, "<timestamp>.<body>")>

{ "event": "finding", "title": "ai-security-monitor: 2 new findings", "lines": ["[Critical] demo-host — …"],
  "severity": "critical", "link": "https://hub.example.com/findings", "sent_at": "2026-10-18T01:00:00.000Z" }
```

To verify, compute HMAC-SHA256 over `timestamp + "." + raw body` with the same key, compare it with the header, and reject old timestamps (for example older than 5 minutes).

## Language and links

Under "General" choose the message language (Traditional Chinese / English) and the Hub URL used for the "Open in Security Hub" link (recipients must be able to reach it).
