# AI sign-in and sign-out (Claude Code / Codex)

English | [繁體中文](ai-login.md)

The Hub's *AI assistant* and the desktop app's *AI analysis* both run one of two official programs, **Claude Code** or **Codex**, so one of them must be signed in.
Sign-in belongs to the computer that runs the program: for a Hub in Docker that is the Hub container; for the desktop app it is your own computer.

## Hub (sign in on the web page)

Open *AI assistant* on the Hub. The *AI accounts* card at the top shows each program: not installed / not signed in / signed in (account email, Claude plan or ChatGPT account).

### Claude Code

1. Click **Sign in**. The Hub starts the official `claude auth login` and shows an *Open the Claude authorization page* link.
2. Open it, sign in with your Claude (Pro / Max) account and click **Authorize**.
3. The page then shows a code. Copy it into the Hub's field and click **Finish sign-in**.
4. When the card says *Signed in* you're done. The whole flow has to finish within 15 minutes; otherwise click **Sign in** again.

### Codex

1. Click **Sign in**. The Hub starts the official `codex login --device-auth` and shows a URL and a one-time code (valid for 15 minutes).
2. Open the URL on any device (a phone works), sign in with your ChatGPT account and enter the code.
3. The Hub checks every 3 seconds and shows *Signed in* when it's done.

The first time you use Codex device-code sign-in, turn on *device code login* under ChatGPT *Settings → Security* (for workspace accounts, the workspace admin does this); otherwise you'll see "device code login is not enabled".
Only enter a code you started on the Hub yourself; never enter a code someone else gave you.

### Sign out

Click **Sign out**: the Hub runs `claude auth logout` / `codex logout`, which deletes that program's stored sign-in on the Hub. The AI assistant needs a new sign-in afterwards.
It does **not** affect Claude Code / Codex on your own computer.

### When the buttons don't work (manual commands)

On the machine running the Hub (for the server edition use `compose.yml` instead of `compose.standalone.yml`):

```bash
docker compose -f docker/compose.standalone.yml --env-file .env exec hub claude auth login     # open the URL, paste the code back
docker compose -f docker/compose.standalone.yml --env-file .env exec hub claude auth logout
docker compose -f docker/compose.standalone.yml --env-file .env exec hub codex login --device-auth
docker compose -f docker/compose.standalone.yml --env-file .env exec hub codex logout
```

You can also use the interactive mode: `docker compose … exec hub claude`, type `/login` or `/logout`, then `/exit`.

## Desktop app

*AI accounts* at the bottom of the *AI analysis* page:

- **Sign in** opens a terminal window running `claude auth login` (or `codex login`), which opens your browser; sign in and authorize, and the desktop app shows *Signed in* automatically.
- **Sign out** runs `claude auth logout` / `codex logout`. **The desktop app uses the same Claude Code / Codex you use every day**, so after signing out you also need to sign in again in your terminal or editor (you are reminded before it signs out).

## Environment variables override sign-in

When these are set, the programs use them first and the web sign-in / sign-out can't change that (the *AI accounts* card points it out):

| Program | Environment variables |
|---|---|
| Claude Code | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` |
| Codex | `OPENAI_API_KEY`, `CODEX_API_KEY` |

To use a subscription sign-in instead, remove them from the Hub's `.env` / compose file and restart.

## Security and terms of use

- The Hub **never reads or stores any token**: the Claude authorization code is passed straight to the official `claude` program, and the Codex code is entered on OpenAI's website. The programs keep their own sign-in data in the Hub's data directory (`/data/claude`, `/data/codex` in the container).
- Authorization codes are never written to logs or the audit log; the audit log only records who, which program, sign-in / sign-out, and success or failure (`ai_account.*`).
- Subscription accounts (Claude Pro / Max, ChatGPT) are for **your own** use. If several people share the Hub, or you offer it as a service to others, use API keys instead (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`): billed by usage and within both vendors' terms.
