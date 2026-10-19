# Direct Google login

Create or reuse a Google OAuth web application client. Register the exact callback URL in Google Cloud, for example `https://security.example.com/api/auth/google/callback`.

Set these server-side environment variables (all also support `_FILE`):

- `AI_SECURITY_MONITOR_HUB_GOOGLE_CLIENT_ID`
- `AI_SECURITY_MONITOR_HUB_GOOGLE_CLIENT_SECRET`
- `AI_SECURITY_MONITOR_HUB_GOOGLE_ALLOWED_EMAILS`: comma-separated exact email allowlist; only verified Google emails are accepted.
- `AI_SECURITY_MONITOR_HUB_GOOGLE_ONLY=true`: disable the admin-key web login form and endpoint.
- `AI_SECURITY_MONITOR_HUB_PUBLIC_URL`: the canonical HTTPS origin.

Remove `AI_SECURITY_MONITOR_HUB_KEYCLOAK_*` settings to offer Google alone. Keep the existing admin/client API keys for enrolled agents. No database migration is required. Existing browser sessions are invalidated when authentication configuration changes.

The authorization code flow validates state, PKCE, signed ID tokens, issuer, audience, expiry and nonce before creating the existing Hub session. Google credentials remain server-side. Google login uses `/api/auth/google/login` and `/api/auth/google/callback` without a Keycloak intermediary.
