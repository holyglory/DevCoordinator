# DevOps Console

Web control center for the `vr.ae` VPS. A single Node 20 process (zero
third-party dependencies) that:

- terminates TLS for `*.vr.ae` on 443 (wildcard cert, hot-reloaded) and
  redirects 80 → 443,
- reverse-proxies `https://<slug>.vr.ae` → `http://127.0.0.1:<port>` including
  WebSockets (Vite/webpack HMR works through it),
- gates every subdomain behind **Google sign-in by default**, with a per-route
  *public / login-required* toggle in the control panel,
- serves the control panel at `https://console.vr.ae` — hash-routed pages
  (Projects, Servers, Routes, Docker, Port leases, Performance; tab nav on
  desktop, a hamburger drawer on phones). The default Projects page is a tree
  of repos with their servers, databases and containers: start/stop/restart
  single items or whole projects, live CPU/memory everywhere, and hideable
  idle items that automatically reappear when an agent starts them through
  the coordinator. Other pages cover servers with per-server subdomains
  (grouped by repo), routes, Docker containers, port leases + permanent pins,
  and history charts, all driven by the
  [codex-dev-coordinator](../../skills/codex-dev-coordinator/SKILL.md) HTTP API
  on loopback `127.0.0.1:29876`, authenticated with a private token. Production
  runs it as the dedicated `dev-coordinator.service`; optional local autostart
  remains available. The
  console samples coordinator inventory (default every 10s,
  `METRICS_INTERVAL_MS`) into in-memory ring buffers; every running server and
  container row shows CPU %/memory numbers plus a sparkline, and the
  Performance page renders full history charts (history resets when the
  console restarts).

Architecture and module contracts: [docs/architecture.md](docs/architecture.md).
Coordinator HTTP API map: [docs/coordinator-http-api.json](docs/coordinator-http-api.json).
User journeys: [docs/journeys.md](docs/journeys.md).

## Quick start

```bash
cd apps/DevOpsConsole
cp .env.example .env          # then fill in the values below
node bin/devops-console.mjs --check-config
node bin/devops-console.mjs   # needs CAP_NET_BIND_SERVICE for ports 80/443 — use systemd (below)
```

Run the tests (spawns an isolated coordinator + local OIDC issuer; no network,
no fixed ports):

```bash
node --test test/*.test.mjs
```

## Configuration (`.env`)

See [.env.example](.env.example) for the full annotated list. The important
ones:

| Key | Meaning |
|---|---|
| `DOMAIN` | Base domain (`vr.ae`). Console at `console.<DOMAIN>`, routes at `<slug>.<DOMAIN>`. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Wildcard cert + key PEMs. Watched and hot-reloaded; `systemctl reload devops-console` (SIGHUP) forces it. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client (setup below). Empty = degraded mode: public routes still proxy, everything auth-gated shows a setup page. |
| `ALLOWED_EMAILS` | Comma-separated Google accounts allowed to sign in. Everyone else gets a 403 after Google auth. |
| `SESSION_SECRET` | 64 hex chars (`openssl rand -hex 32`). Rotating it signs everyone out. |
| `COORDINATOR_URL` | Coordinator API, default `http://127.0.0.1:29876`. |
| `COORDINATOR_TOKEN_FILE` | Private mode-0600 bearer token created by the coordinator and read only by the server-side Console client. |
| `COORDINATOR_AUTOSTART` | Optional local fallback; production sets `0` and uses `dev-coordinator.service`. |
| `METRICS_INTERVAL_MS` | CPU/memory sampling cadence for the history charts (default `10000`, floor `2000`). Each sample reads coordinator inventory, which shells out to `docker stats` when Docker is present. |

## Google OAuth client setup (one-time)

1. Google Cloud Console → *APIs & Services* → *OAuth consent screen*:
   external, app name "DevOps Console", your email; publish.
2. *Credentials* → *Create credentials* → *OAuth client ID* → type **Web
   application**:
   - Authorized JavaScript origin: `https://console.vr.ae`
   - Authorized redirect URI: `https://console.vr.ae/auth/callback`
3. Put the client ID/secret in `.env`, `systemctl restart devops-console`.

The login page shows these exact values in degraded mode, so you can copy them
from there too.

## TLS certificate runbook (Let's Encrypt DNS-01, out-of-band)

The app never speaks ACME; it just reads the PEMs in `.env` and hot-reloads
them when the files change. `certs/dev/` is gitignored — the test suite
generates a throwaway self-signed `*.vr.ae` cert there on demand
(`test/helpers/dev-cert.mjs`), and the same generated pair can serve as a
first-boot fallback until real certificates are issued.

### Console + apex cert (HTTP-01, automated — currently live)

The app answers ACME HTTP-01 challenges itself: the plain-HTTP :80 listener
serves `/.well-known/acme-challenge/<token>` from `ACME_WEBROOT`
(default `<STATE_DIR>/acme`) **before** the https redirect, so `certbot`
issues and renews certs while the app keeps port 80. This covers named hosts
(`console.vr.ae`, `vr.ae`) but **not** a wildcard — Let's Encrypt only issues
`*.vr.ae` via DNS-01 (below).

```bash
sudo apt-get install -y certbot
sudo certbot certonly --webroot -w "$HOME/.local/state/devops-console/acme" \
  -d console.vr.ae -d vr.ae \
  --non-interactive --agree-tos -m ja@vr.ae --cert-name vr.ae
sudo setfacl -R -m u:holyglory:rX /etc/letsencrypt/live/vr.ae /etc/letsencrypt/archive/vr.ae
# point .env at the issued files, then RESTART (a path change needs a restart;
# SIGHUP/reload only re-reads the already-configured path):
#   TLS_CERT_FILE=/etc/letsencrypt/live/vr.ae/fullchain.pem
#   TLS_KEY_FILE=/etc/letsencrypt/live/vr.ae/privkey.pem
sudo systemctl restart devops-console
```

Renewal is automatic (certbot's timer); a deploy hook reloads the app so it
picks up the renewed cert without dropping connections:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/devops-console <<'EOF'
#!/bin/sh
systemctl reload devops-console 2>/dev/null || systemctl restart devops-console
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/devops-console
```

### Wildcard cert for proxied subdomains (DNS-01 — currently live)

Proxied `<slug>.vr.ae` hosts are covered by the `*.vr.ae` wildcard. Let's
Encrypt issues wildcards **only** via DNS-01 — a `_acme-challenge.vr.ae` TXT
record at the authoritative DNS (`vr.ae` is hosted at 101domain, which has no
API credential on this box, so the record is published by hand). The live cert
`/etc/letsencrypt/live/vr.ae/{fullchain,privkey}.pem` covers `vr.ae` +
`*.vr.ae`; `.env` points at it and the console serves it for every host.

**Renewal is fully automated via the 101domain REST API** — no manual TXT
steps. certbot's `manual_auth_hook`/`manual_cleanup_hook` create and delete the
`_acme-challenge.vr.ae` TXT record through the API and wait for propagation at
the authoritative nameservers; the certbot systemd timer renews unattended
within 30 days of expiry and the deploy hook reloads the console. Proven with a
real production `certbot renew --force-renewal` (new serial issued, records
auto-cleaned, service reloaded, all hosts still trusted).

Setup (already done on this host; repeat if rebuilding):

```bash
# 1. Store the 101domain API key, root-only, OUTSIDE the repo:
sudo install -d -m 700 /etc/letsencrypt/101domain
printf 'DOMAIN101_API_KEY=%s\n' "<key>" | sudo tee /etc/letsencrypt/101domain/credentials.env >/dev/null
sudo chmod 600 /etc/letsencrypt/101domain/credentials.env
# 2. Install the hooks (versioned in deploy/101domain/, hold no secret):
sudo install -m 700 deploy/101domain/auth-hook.sh deploy/101domain/cleanup-hook.sh /etc/letsencrypt/101domain/
# 3. Wire them into /etc/letsencrypt/renewal/vr.ae.conf under [renewalparams]:
#   manual_auth_hook = /etc/letsencrypt/101domain/auth-hook.sh
#   manual_cleanup_hook = /etc/letsencrypt/101domain/cleanup-hook.sh
# 4. Verify unattended:
sudo certbot renew --cert-name vr.ae --dry-run
```

The API key lives only in the root-only credentials file — never in the repo,
which is public. The hooks read it from there.

Fallback (if the API is ever unavailable), a guided manual helper prints the
exact TXT to add, verifies propagation, issues, and reloads:
`sudo bash deploy/renew-wildcard.sh`.

Cert files are root-owned; the service user reads them via a default ACL
(`sudo setfacl -R -d -m u:holyglory:rX /etc/letsencrypt/{live,archive}`) so
renewed files stay readable. A renewal deploy hook
(`/etc/letsencrypt/renewal-hooks/deploy/devops-console`) reloads the service
(SIGHUP) after any renewal. Note: changing the cert **path** in `.env` needs a
full restart; a same-path renewal only needs a reload.

## Deploy (systemd)

```bash
sudo install -m 0644 deploy/dev-coordinator.service deploy/devops-console.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dev-coordinator.service devops-console.service
systemctl status dev-coordinator.service devops-console.service
```

Both units run as `holyglory`. The coordinator binds only loopback and owns the
external coordinator state and private token. The Console requires that unit,
runs with `CAP_NET_BIND_SERVICE` only (no root), and `ExecReload` sends SIGHUP
for cert reloads. Put private Console configuration in
`~/.config/devops-console/console.env` (mode `0600`) and create
`~/.local/state/devops-console` and `~/.codex/agent-coordinator` with mode
`0700` before starting the units. On startup the Console registers itself with
the coordinator (`server register`, port 443) so it appears in inventory
alongside everything it manages.

## Exposing a dev server

1. Start the server through the coordinator (or the console UI) so it has a
   tracked port. Web servers running as Docker containers (any container
   publishing a non-database TCP port) need nothing extra — they show up on
   the Servers page automatically.
2. Console → *Servers* → "Assign subdomain" on the row (works for both
   coordinator servers and docker containers; a port picker appears when a
   container publishes several ports), or Console → *Routes* → create: pick a
   slug (`myapp` → `https://myapp.vr.ae`), choose the coordinator server
   (port follows the server across restarts), a container (host port follows
   the container across restarts), or a fixed port, and leave access on
   **login required** (default) or explicitly flip to public.
3. WebSockets/HMR pass through. Vite dev servers block unknown hosts with
   "Blocked request. This host … is not allowed" — allow the whole domain
   family once and any assigned slug keeps working after renames:

   ```js
   // vite.config.js / vite.config.ts
   export default { server: { allowedHosts: ['.vr.ae'] } }
   ```

   (The proxy forwards the original `Host` plus `X-Forwarded-Proto/Host/For`.)

## Security model

- The coordinator API on 29876 is loopback-only and bearer-authenticated. The
  token stays in a private external file and is never returned to browser
  JavaScript, logs, URLs, screenshots, or Git.
- Sessions: HMAC-SHA256-signed cookie, `Domain=.vr.ae`, `HttpOnly`, `Secure`,
  `SameSite=Lax`; allowlist re-checked on every request.
- OIDC: authorization code + PKCE, `state`/`nonce` enforced, ID-token
  signature verified against Google's JWKS in-process.
- Unknown subdomains are indistinguishable from protected ones until you log
  in (no route enumeration). New routes default to login-required. Proxy
  targets are always `127.0.0.1`.
- Console API mutations require a same-origin `Origin` header (CSRF).

## Dev mode

`DEV_HTTP=1 HTTP_PORT=<leased port> node bin/devops-console.mjs` serves the
whole router (console + proxying) over plain HTTP on one loopback port — used
by the coordinator dev-runtime declaration and the test suite. Lease ports via
the coordinator per repo policy; never bind fixed dev ports.
