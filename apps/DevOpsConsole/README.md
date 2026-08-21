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
  (Projects, Tests, Open Coordinator bugs, Servers, Routes, Docker, Port
  leases, Performance, Access, Incoming invites, Telegram; tab nav on
  desktop, a hamburger drawer on phones). The default Projects page is a tree
  of original root repos, their direct services, and nested temporary repos
  with their TTL and `KillAfterRun` policy. Root actions affect only the root
  repo runtime; temporary runs remain independently controlled. A missing or
  contradictory repository tree is an explicit contract error that disables
  lifecycle controls; the browser never reconstructs membership from flat
  usage rows, paths, or names. Individual
  servers, databases, and containers expose exact start/stop/restart actions,
  live CPU/memory, and hideable idle items that automatically reappear when an
  agent starts them through the coordinator. Other pages cover servers with
  per-server subdomains (grouped by repo), routes, Docker containers, port
  leases + permanent pins, history charts, owner-only per-account domain
  grants and incoming invite decisions, plus user-owned Telegram bots for
  project event notifications, all driven by the
  [codex-dev-coordinator](../../skills/codex-dev-coordinator/SKILL.md) HTTP API
  on loopback `127.0.0.1:29876`, authenticated with a private token. Production
  runs it as the dedicated `dev-coordinator.service`; optional local autostart
  remains available. The metrics loop is the one periodic host observer. On
  each tick (default every 10s,
  `METRICS_INTERVAL_MS`), the Console reads the coordinator's last committed
  pure inventory into in-memory ring buffers without waiting for host-wide
  observation. When no observation is already in flight or backed off, that
  tick also initiates one attributed observation. Same-project observations
  coalesce; failures back off from completion exponentially up to five minutes
  while pure inventory reads continue every tick. Every current running server
  and container row shows CPU %/memory
  numbers plus a sparkline. The Performance page renders a reconciled
  whole-host stacked history with attributed repositories, measured Agent
  browsers, measured control work, estimated system/unclassified memory, and
  available memory. Repository and Agent-browser detail opens from the legend;
  browser timestamps are explicitly last observed work, not invented
  historical use. History resets when the console restarts.

  The Open Coordinator bugs page is deliberately outside that normal control
  path. Agents write bounded, redacted reproduction records to the shared
  open-only registry; `GET /api/bugs` reads it without contacting Coordinator
  inventory, authority, broker, API, or testd. Every Console user may inspect
  the actionable collection and its exact structured arguments. Configured
  owners may Close a report, which physically removes the open file (and any
  same-fingerprint duplicate) immediately. There is no closed history or
  tombstone to synchronize between Console instances. A failed refresh keeps
  the last collection visible and reports the error inside this page.
  Authenticated users can export the complete open collection as portable JSON;
  owners can import it through the same page. Imported reports remain labelled
  with their originating server and stay distinct from matching local reports,
  so disconnected Coordinator servers can exchange current bugs by copy/paste
  without pretending that they share a live replication channel.

  In the required production unit, metrics and Telegram broker loops start 90
  seconds after the Console's own registration succeeds. This keeps the
  installed 80-second independent registration proof ahead of background host
  observation and event ingestion during restarts. The proof uses one
  trusted-loopback inventory request with the whole remaining startup deadline;
  it never abandons a still-running broker read merely to retry it.

  Supervised workers have explicit start, stop, restart, crash-loop rearm, and
  Keep Alive controls. Keep Alive requests desired-running supervision and
  restarts unexpected exits; turning it off leaves an already-running worker
  running. Permanent removal is a separate review-and-confirm journey that
  first stops and archives the worker, preserves retained crash evidence, and
  keeps the worker absent until an explicit Coordinator reinstall.

  The API and server-wide broker are independently supervised. During a
  rolling deployment, the Console accepts canonical compatibility stats when
  present; otherwise it derives a detached view only after its authenticated
  observation result exactly matches the normalized full-Docker snapshot,
  current immutable resource, available engine, running observation, and
  in-window telemetry. Missing proof renders no utilization, never stale data.

Configured owners get Active/Archived views on Projects, Servers, and Docker
only when `LIFECYCLE_ENABLED=1` explicitly confirms that the broker schema,
generated home access, and cleanup ACLs were migrated and verified together.
The default is disabled and makes no archive request. Once activated, Archive
prepares and applies a coordinator-authored stop-and-fence plan while retaining
the plan's declared data and history. Archived rows can be restored (which
clears the fence but never starts the resource) or removed permanently only
when the coordinator advertises that capability; permanent removal requires
typing the exact phrase returned by the fresh plan. These durable lifecycle
controls are distinct from the cosmetic Hide preference.

Production binds ports 80/443 on the explicit IPv4 wildcard `0.0.0.0` and
uses `127.0.0.1` for coordinator registration and health. This deployment has
IPv4 DNS records; the explicit bind avoids Node's platform-dependent omitted-
host IPv6 dual-stack behavior and keeps listener ownership verifiable.

Architecture and module contracts: [docs/architecture.md](docs/architecture.md).
Coordinator HTTP API map: [docs/coordinator-http-api.json](docs/coordinator-http-api.json).
User journeys: [docs/journeys.md](docs/journeys.md).

## Quick start

```bash
cd apps/DevOpsConsole
install -d -m 700 "$HOME/.config/devops-console" "$HOME/.local/state/devops-console"
if [ ! -e "$HOME/.config/devops-console/console.env" ]; then
  install -m 600 .env.example "$HOME/.config/devops-console/console.env"
fi
# Fill in the external file, then:
node bin/devops-console.mjs --env-file "$HOME/.config/devops-console/console.env" --check-config
node bin/devops-console.mjs --env-file "$HOME/.config/devops-console/console.env"
```

Run the tests (spawns an isolated coordinator + local OIDC issuer; no network,
no fixed ports):

```bash
node --test test/*.test.mjs
```

## Configuration (`console.env`)

See [.env.example](.env.example) for the full annotated list. The important
ones:

| Key | Meaning |
|---|---|
| `DOMAIN` | Base domain (`vr.ae`). Console at `console.<DOMAIN>`, routes at `<slug>.<DOMAIN>`. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Wildcard cert + key PEMs. Watched and hot-reloaded; `systemctl reload devops-console` (SIGHUP) forces it. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client (setup below). Empty = degraded mode: public routes still proxy, everything auth-gated shows a setup page. |
| `ALLOWED_EMAILS` | Comma-separated configured owner accounts. Owners always have full Console/domain access and alone may edit the invited-user list. Keep at least one break-glass owner here. |
| `SESSION_SECRET` | 64 hex chars (`openssl rand -hex 32`). Rotating it signs everyone out. |
| `COORDINATOR_URL` | Coordinator API origin, default `http://127.0.0.1:29876`; only loopback `http(s)` origins without credentials, paths, queries, or fragments are accepted. |
| `COORDINATOR_AUTOSTART` | Optional local fallback; production sets `0` and uses `dev-coordinator.service`. |
| `COORDINATOR_REGISTRATION_REQUIRED` | Production-only fail-closed gate. The unit pins `1`; direct/local runs omit it and log a bounded registration failure without exiting. |
| `DEVCOORDINATOR_BUG_DIR` | Absolute shared open-bug directory. Production uses `/var/lib/devcoordinator-bugs/open`; a missing directory is an honest empty list. One `<bug_id>.json` file means open, and Close removes it instead of creating history. |
| `LIFECYCLE_ENABLED` | Explicit cleanup activation gate (default `0`). Set to `1` only after the matching broker schema, generated home access, cleanup ACLs, and live plan/apply/restore checks are ready. |
| `METRICS_INTERVAL_MS` | CPU/memory observation cadence for the history charts (default `10000`, floor `2000`). Metrics is the sole periodic observer; same-project requests coalesce and failures back off up to five minutes while committed inventory remains readable. |

Telegram bot tokens are registered from the Console UI, not from
`console.env`. They remain server-only in private
`<STATE_DIR>/telegram-control.json` (mode `0600`) and are never returned to the
browser, logs, URLs, screenshots, or Git.

## Google OAuth client setup (one-time)

1. Google Cloud Console → *APIs & Services* → *OAuth consent screen*:
   external, app name "DevOps Console", your email; publish.
2. *Credentials* → *Create credentials* → *OAuth client ID* → type **Web
   application**:
   - Authorized JavaScript origin: `https://console.vr.ae`
   - Authorized redirect URI: `https://console.vr.ae/auth/callback`
3. Put the client ID/secret in
   `$HOME/.config/devops-console/console.env`, then run
   `systemctl restart devops-console`.

The login page shows these exact values in degraded mode, so you can copy them
from there too.

## TLS certificate runbook (Let's Encrypt DNS-01, out-of-band)

The app never speaks ACME; it reads the PEM paths from
`$HOME/.config/devops-console/console.env` and hot-reloads
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
# point $HOME/.config/devops-console/console.env at the issued files, then
# RESTART (a path change needs a restart;
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
`*.vr.ae`; the external `console.env` points at it and the Console serves it
for every host.

**Renewal is fully automated via the 101domain REST API** — no manual TXT
steps. certbot's `manual_auth_hook`/`manual_cleanup_hook` create and delete the
`_acme-challenge.vr.ae` TXT record through the API and wait for propagation at
the authoritative nameservers; the certbot systemd timer renews unattended
within 30 days of expiry and the deploy hook reloads the console. Proven with a
real production `certbot renew --force-renewal` (new serial issued, records
auto-cleaned, service reloaded, all hosts still trusted).

Setup (already done on this host; repeat if rebuilding):

```bash
# 1. Store the 101domain API key OUTSIDE the repo (0600 is hygiene):
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

The API key lives only in the host credential file—never in the repo, which is
public. Any local process that must use it relies on actual readability;
UID/GID/mode metadata is not a second application authorization policy.

Fallback (if the API is ever unavailable), a guided manual helper prints the
exact TXT to add, verifies propagation, issues, and reloads:
`sudo bash deploy/renew-wildcard.sh`.

systemd reads the certificate files and passes them to the service through
`LoadCredential`; no developer group or ACL membership is an application trust
gate. A renewal deploy hook
(`/etc/letsencrypt/renewal-hooks/deploy/devops-console`) reloads the service
(SIGHUP) after any renewal. Note: changing the cert **path** in the external
`console.env` needs a full restart; a same-path renewal only needs a reload.

## Deploy the current systemd release

DevCoordinator ships one immutable, content-addressed release. Use the
repository-owned delivery workflow; do not invoke the installed Coordinator
test or installation clients against this repository.

```bash
sudo python3 scripts/software_owned_delivery.py run \
  --repo "$PWD" \
  --run-root "$PWD/.local/delivery/current" \
  --transaction-root /var/lib/devcoordinator-delivery/current \
  --max-parallel 8 \
  --acceptance-execution-timeout-seconds 600 \
  --acceptance-launch-timeout-seconds 300 \
  --acceptance-wait-timeout-seconds 1200 \
  --reset-test-history
```

The workflow validates source, builds the immutable package, prepares and
atomically activates the current service topology, verifies control-plane and
public Console health, rolls back to the immediately preceding current-format
release on failure, and runs installed browser/client acceptance.

Repository registrations, Console routes, users, grants, settings, secret
references, and project data remain in their existing service-owned stores.
The Test Store and unfinished test work are disposable; `--reset-test-history`
starts the release with an empty current-schema Test Store. Pre-availability
checkout units, handoff listeners, legacy import, fleet adoption, storage split,
and rollback to the old layout are unsupported.
## Manage Google account access

Google verification and Console authorization are deliberately separate. A
successful OIDC callback establishes a signed, verified Google identity even
when that account has no grant. Every protected Console, route, API, proxy,
and WebSocket request still rechecks current policy. If a verified account
opens a protected destination it cannot use, the denial page offers **Request
invite**. The server derives the requested resource from the current host—the
browser cannot choose another email, Console grant, or route—and records one
idempotent pending request for that exact Console or route instance.

1. Sign in as a configured owner from `ALLOWED_EMAILS`, then open Console →
   *Access*. The real owner/invited-user collection is the first content.
2. Choose *Add user*, enter a Gmail or Google Workspace email, and select the
   exact destinations it may open. `DevOps Console` is a separate high-
   privilege grant: it allows all existing server/route operations but does
   not allow access administration.
3. Change a grant from the user card at any time. The next HTTP or WebSocket
   request uses the new policy; no re-login or service restart is required.
   Removing a user invalidates that user's existing signed session immediately.
4. Open the owner-only *Incoming invites* page to review host-derived requests.
   Approve creates or merges only the requested exact grant; Deny records the
   decision without granting access. Route deletion, replacement, or rename
   makes a request for the former immutable route instance stale rather than
   granting a later route that reuses the slug.

Configured owners are intentionally not editable in the web UI. Change them in
the private `console.env` `ALLOWED_EMAILS` value and restart the service. This
provides a recovery path if invited policy is empty or corrupt. Invited state
and bounded request/decision history are private
`<STATE_DIR>/access-control.json` (schema version 2, atomic writes, mode
`0600`; schema version 1 user policy migrates on load).
Public routes remain public regardless of grants; saved grants become effective
again if the route returns to login-required mode.

## Telegram project notifications

Any account with a current Console grant can open *Telegram* and register a
bot token from [BotFather](https://t.me/BotFather). That account owns the bot
and alone may manage its project assignments and authorization queue;
configured Console owners can administer every bot. Registration validates
the token with Telegram. If the bot already has a webhook, registration
refuses it unless the user explicitly confirms **Replace the bot's existing
webhook**. Takeover removes the webhook without discarding pending updates
because this Console uses long polling.

Assign the bot to exact projects from current coordinator inventory. The
durable assignment is the coordinator's immutable `repo_id`, not a display
name or path-derived guess. A Telegram user then sends `/start` to that bot in
a private chat. They appear in the bot-specific authorization queue on the
Telegram page; the bot owner (or a configured Console owner) approves or
denies them. Google/Console access and Telegram subscriber approval are
independent decisions.

Approved subscribers receive events only for the bot's assigned projects:
server and Docker start/stop/restart activity, failures, and observed crashes.
The Console periodically asks the coordinator for an explicit host
observation, reads its durable event journal with an opaque cursor, and writes
each recipient delivery to a durable outbox before advancing that cursor.
Telegram rate limits and transient failures are retried across process
restarts; the token, cursor, subscriber state, and outbox stay only in the
mode-`0600` server-side state file.

## Upstreams that require their own HTTP credentials

A login-required route can use Google as the only browser sign-in even when
its loopback application still requires a Bearer token or Basic credentials.
The Console keeps that backend credential in private
`<STATE_DIR>/upstream-auth.json` (atomic writes, mode `0600`), replaces any
caller-supplied `Authorization` header after the Google/domain-grant check, and
does not return the secret through route views, logs, URLs, or CLI output.
Upstream `WWW-Authenticate`/`Authentication-Info` headers are suppressed on a
Google-protected route. If the injected backend credential is rejected, the
Console discards the upstream response body and renders a branded HTML 502
configuration page—never upstream JSON or a second browser login prompt.
Missing or expired Console identity instead redirects browser navigation to
`/auth/login` with the exact requested URL as `rt`, and successful sign-in
returns there. Public routes retain normal HTTP-auth behavior and never receive
a stored private credential.

Configured owners can rotate a credential live through
`PATCH /api/routes/<slug>/upstream-auth`; non-owner Console users are denied,
and the endpoint accepts only Google-protected routes. The deployment CLI is
the safer shell workflow because the secret is read only from stdin. It writes
the private state for the next Console start:

```bash
DEVCOORDINATOR_ROOT=/home/DevCoordinator
CONSOLE_ENV="$HOME/.config/devops-console/console.env"
cd "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole"
read -r -s BACKEND_TOKEN
printf '%s\n' "$BACKEND_TOKEN" | \
  node bin/devops-console-upstream-auth.mjs \
  --env-file "$CONSOLE_ENV" \
  set prtzn --scheme bearer --secret-stdin
unset BACKEND_TOKEN
sudo systemctl restart devops-console
```

For a Basic-only upstream, use `--scheme basic --username <user>`. `list`
prints only route/scheme metadata; `remove <slug>` deletes the credential.
Route deletion removes its credential, server/container route renames move it,
and changing a route to public erases it. Rotate the Console copy in the same
transaction whenever the upstream token changes, then verify the two private
copies without printing either secret before restarting Console. Private
rollback directories must be mode `0700` and their credential-state files mode
`0600`; the production preflight intentionally refuses looser state.

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

- The coordinator API on 29876 is trusted local infrastructure: it binds only
  to loopback, rejects non-loopback `Host`/`Origin`, and carries no redundant
  application bearer credential. Browser JavaScript reaches it only through
  the authenticated, repository-authorized Console API.
- Sessions: HMAC-SHA256-signed cookie, `Domain=.vr.ae`, `HttpOnly`, `Secure`,
  `SameSite=Lax`; the cookie proves a verified Google identity, while current
  owner/invited membership and the exact Console/domain grant are re-checked
  separately on every HTTP and WebSocket request.
- OIDC: authorization code + PKCE, `state`/`nonce` enforced, ID-token
  signature verified against Google's JWKS in-process.
- Unknown subdomains are indistinguishable from protected ones until you log
  in (no route enumeration). New routes default to login-required. Proxy
  targets are always `127.0.0.1`.
- On Google-protected routes, browser credentials cannot select an upstream
  identity: the edge strips caller `Authorization`, optionally injects the
  route's private backend credential, and suppresses backend HTTP-auth
  challenges. It also replaces caller-supplied local-attribution headers with
  the verified Google email and immutable route ID; these compact on-host
  headers are not a public authentication mechanism. Public routes preserve
  ordinary end-to-end HTTP authentication.
- Console API mutations require a same-origin `Origin` header (CSRF). Access
  list and backend-credential endpoints additionally require a configured
  owner.
- Invite requests are same-origin POSTs carrying a short-lived signed request
  claim bound to the verified Google subject, email, host-derived resource,
  and immutable resource instance. Only configured owners may read or decide
  the incoming queue.
- Telegram tokens are validated and stored only in Console state. New files use
  mode `0600` as hygiene, while reads gate on file shape and content rather than
  local permission metadata. API views expose bot identity and `hasToken`, never the token;
  bot ownership is enforced server-side and configured owners retain the
  recovery/administration override.

## Dev mode

`DEV_HTTP=1 HTTP_PORT=<leased port> node bin/devops-console.mjs` serves the
whole router (console + proxying) over plain HTTP on one loopback port — used
by the coordinator dev-runtime declaration and the test suite. Lease ports via
the coordinator per repo policy; never bind fixed dev ports.
