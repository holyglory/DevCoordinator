# DevOps Console — Architecture Contract

This document is the **binding contract** between modules. Implementation agents
must match these interfaces exactly. Runtime: **Node 20, ESM (`.mjs`), zero
third-party dependencies** — `node:` stdlib only (global `fetch` allowed; it is
stdlib in Node 20). No TypeScript. No build step.

## What the app is

A single Node process that is the public edge of the VPS `vr.ae`:

1. **TLS termination**: HTTPS listener on `HTTPS_PORT` (prod 443) with the
   `*.vr.ae` wildcard cert (paths from `.env`, hot-reloaded on file change and
   SIGHUP). Plain-HTTP listener on `HTTP_PORT` (prod 80) that 301/308-redirects
   everything to `https://` (except `GET /healthz` → `200 ok`).
2. **Host routing**: `console.vr.ae` → control-panel app (auth + API + UI).
   `<slug>.vr.ae` → reverse proxy to `127.0.0.1:<port>` (HTTP + WebSocket/HMR).
   Apex `vr.ae` and `www.vr.ae` → redirect to the console. Foreign hosts → 421.
3. **Google auth (OIDC)**: authorization-code flow + PKCE against
   `https://accounts.google.com`, verified Google email identity, and one
   HMAC-signed session cookie on `Domain=.vr.ae` so a login can cover every
   granted subdomain.
4. **Per-account access control**: `ALLOWED_EMAILS` is the configured owner
   set (full access + access administration). Invited Google accounts and
   exact `console` / `route:<slug>` grants live in private Console state. Each
   route is `google` (default) or `public`; public bypasses identity, while a
   protected route requires its exact grant. **Unknown slugs behave exactly
   like protected ones for anonymous users** so names cannot be enumerated.
5. **Protected upstream credential translation**: after Google identity and
   an exact route grant pass, a route may replace caller `Authorization` with
   a private route-scoped Bearer or Basic credential. The credential never
   enters route/API views; public routes never receive it and retain normal
   end-to-end HTTP authentication.
6. **Coordinator as control engine**: all server/docker/lease state and
   mutations go through the coordinator HTTP API on `127.0.0.1:29876`
   (`docs/coordinator-http-api.json` is the authoritative endpoint map). The
   production `dev-coordinator.service` owns that process. Optional local
   autostart is available only when `COORDINATOR_AUTOSTART=1`.

## Files and ownership (one implementation agent each)

| Agent | Files |
|---|---|
| A core | `package.json`, `bin/devops-console.mjs`, `bin/devops-console-upstream-auth.mjs`, `src/config.mjs`, `src/log.mjs`, `src/certs.mjs`, `src/server.mjs`, `src/router.mjs`, `src/proxy.mjs`, `src/upstream-auth.mjs` |
| B auth | `src/auth/session.mjs`, `src/auth/oidc.mjs`, `src/auth/guard.mjs`, `src/auth/pages.mjs` |
| C control | `src/coordinator.mjs`, `src/routes.mjs`, `src/access.mjs`, `src/api.mjs`, `src/metrics.mjs`, `src/prefs.mjs` |
| D ui | `src/static.mjs`, `src/ui/index.html`, `src/ui/app.css`, `src/ui/app.js`, `docs/journeys.md` |

Nobody else touches another agent's files; the integrator reconciles.

## Config (`src/config.mjs`)

```js
export function loadConfig({ envFile, env = process.env } = {}) // → Config, throws AggregateError listing ALL problems
export class ConfigError extends Error {}
```

Reads `.env` (KEY=VALUE lines; `#` comments; blank lines; values may be
single/double-quoted; no interpolation). **`process.env` wins over the file.**
`envFile` defaults to `<appRoot>/.env` (appRoot = dir above `src/`).

`Config` (all resolved, validated):

```js
{
  domain,                 // 'vr.ae' (lowercase, no dot prefix)
  consoleHost,            // `${CONSOLE_SUBDOMAIN}.${domain}` e.g. 'console.vr.ae'
  consoleOrigin,          // 'https://console.vr.ae' ('http://…' when devInsecureHttp)
  httpPort, httpsPort,    // ints; httpPort may be 0 → plain listener disabled
  tlsCertFile, tlsKeyFile,        // absolute paths (resolved from appRoot)
  google: { clientId, clientSecret },  // may be '' — see "degraded mode" below
  oidcIssuer,             // default 'https://accounts.google.com'
  allowedEmails,          // configured owner Set<string>, lowercased from ALLOWED_EMAILS csv
  sessionSecret,          // Buffer (from 64-hex SESSION_SECRET; required)
  sessionTtlMs,           // from SESSION_TTL_HOURS (default 168h)
  cookieName,             // SESSION_COOKIE_NAME default 'dc_session'
  coordinatorUrl,         // default 'http://127.0.0.1:29876'
  coordinatorAutostart,   // COORDINATOR_AUTOSTART default true ('0' disables)
  coordinatorScript,      // default '<repoRoot>/skills/codex-dev-coordinator/scripts/dev_coordinator.py'
  coordinatorHome,        // CODEX_AGENT_COORDINATOR_HOME passthrough or null
  coordinatorTokenFile,   // absolute private COORDINATOR_TOKEN_FILE
  projectRoot,            // git toplevel containing the app (repo root)
  metricsIntervalMs,      // METRICS_INTERVAL_MS default 10000, floor 2000
  stateDir,               // abs, default '<appRoot>/state'; created on load
  logLevel,               // 'debug'|'info'|'warn'|'error'
  devInsecureHttp,        // DEV_HTTP === '1': single plain-HTTP listener on httpPort,
                          // no TLS, cookies lose `Secure`. For loopback dev/tests only.
  version,                // from package.json
}
```

**Degraded mode**: missing `GOOGLE_CLIENT_ID/SECRET` is NOT a startup error —
the app must still boot, proxy `public` routes, and serve `/auth/login` with a
clear "Google OAuth is not configured yet" banner (setup instructions from
README). Everything auth-gated returns that page. This keeps first-boot real
before the operator creates the OAuth client. Missing/invalid `SESSION_SECRET`,
`DOMAIN`, or unreadable TLS files (when not devInsecureHttp) ARE fatal.

## Logging (`src/log.mjs`)

```js
export function createLogger(level) // → { debug|info|warn|error(msg, fields?) , child(bindings) }
```
One line per event: `2026-07-05T12:00:00.000Z INFO msg key=val key2="v 2"`.
Never log secrets, cookie values, tokens, or full Authorization headers.

## TLS (`src/certs.mjs`)

```js
export async function createCertManager({ certFile, keyFile, log })
// → { getSecureContext(): tls.SecureContext, reload(): Promise<void>,
//     getCredentials(): { cert, key },          // current PEMs (server default context)
//     onSwap(fn): unsubscribe,                  // fires after every successful (re)load
//     info(): { loadedAt, notAfter, subject, issuer, selfSigned }, close() }
```
Loads PEMs; parses metadata via `new crypto.X509Certificate(pem)`. Watches both
files (`fs.watchFile`, 30s interval) and reloads on change; failed reload keeps
the old context and logs the error. `bin/` wires SIGHUP → `reload()`.
`server.mjs` must pass `getCredentials()` into `https.createServer` as the
DEFAULT context (SNICallback never fires for clients that send no SNI — e.g.
curl/health probes against `https://127.0.0.1`) and refresh it on `onSwap` via
`server.setSecureContext(getCredentials())`.

## Listeners (`src/server.mjs`)

```js
export async function startServers({ config, log, certManager, router })
// → { close(): Promise<void> }  (graceful: stop accepting, 10s drain, destroy)
```
- HTTPS server (`https.createServer` with `SNICallback: (_, cb) => cb(null, certManager.getSecureContext())`)
  on `httpsPort`; `'request'` → `router.handleRequest`, `'upgrade'` → `router.handleUpgrade`.
- Plain HTTP server on `httpPort` (if > 0): `GET|HEAD /healthz` → `200 ok`;
  else 301 (GET/HEAD) / 308 (others) to `https://<host><url>` (host
  sanitized: `[a-z0-9.-]` only, port stripped; invalid → 400).
- In `devInsecureHttp` mode: NO https server; the plain server on `httpPort`
  serves `router` directly (no redirect).
- `server.headersTimeout = 65_000`, `requestTimeout = 0` (long-lived SSE/WS
  upstreams must not be killed), `keepAliveTimeout = 65_000`.

## Routing (`src/router.mjs`)

```js
export function createRouter(deps) // → { handleRequest(req,res), handleUpgrade(req,socket,head) }
// deps: { config, log, guard, oidc, sessions, pages, consoleApi, staticServer, routeStore, upstreamAuthStore, coordinator, proxy }
```

Dispatch (both request and upgrade paths):
1. `host` = `Host` header, lowercased, port stripped. Missing/malformed → 400
   (upgrade: destroy socket).
2. `GET|HEAD /healthz` on any host → `200 ok` (no auth).
3. apex / `www.` → 301 `config.consoleOrigin + '/'`.
4. `host === consoleHost` → console app:
   - `/auth/*` → auth endpoints (below), no session required.
   - everything else requires a current known session plus the `console`
     grant (owners always pass). Missing sessions redirect browser GETs to
     login or return JSON 401; known accounts without the grant receive 403.
   - `/api/*` → `consoleApi.handle(req, res, session)`.
   - else `staticServer.handle(req, res)` (UI).
   - upgrades on consoleHost: destroy (no WS on console in v1).
5. `host` ends with `.` + domain and the remainder is a **single label**
   matching `/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/` → slug flow:
   - `route = routeStore.get(slug)`; `needAuth = !route || route.auth !== 'public'`.
   - `needAuth` and no valid session → browser GET/HEAD: 302 to
     `${consoleOrigin}/auth/login?rt=${encodeURIComponent(fullUrl)}`;
     non-browser or upgrade: 401 / socket destroy.
   - a known signed-in account without `route:<slug>` → 403 for both HTTP and
     WebSocket. Owners always pass. Public routes bypass this check.
   - no route (after auth) → `pages.renderNotFound` 404.
   - `target = await routeStore.resolve(slug, coordinator)`;
     unresolvable (linked server stopped) → `pages.renderUpstreamError` 502
     variant explaining the server is not running, with console link.
   - for a protected route, `target.upstreamAuthorization` is resolved only
     from the private upstream-auth store after session/grant authorization;
     a public route always receives `null`.
   - `proxy.forward(req, res, target)` / `proxy.forwardUpgrade(req, socket, head, target)`.
6. anything else → 421 `pages.renderError`.

Auth endpoints (console host only):
- `GET /auth/login?rt=` — login page (authed → 302 rt-or-`/`). Shows Google
  button → `/auth/start?rt=`; degraded mode → setup banner instead.
- `GET /auth/start?rt=` — 302 to Google authorize URL; sets flow cookie.
- `GET /auth/callback` — validates flow, exchanges code, verifies ID token,
  current owner/invited-user membership check → session cookie
  (`Domain=.vr.ae`) → 302 validated `rt` or `/`. Unknown email → 403
  `pages.renderDenied` (no cookie). A known account may then receive a
  resource-specific 403 at its return host. OIDC errors → 400 login page.
- `GET|POST /auth/logout` — expire cookie, 302 `/auth/login`.

`rt` validation (in guard): absolute URL, scheme matches deployment
(`https:` unless devInsecureHttp), hostname === domain or endsWith `.` +
domain. Invalid → fall back to `/`.

## Proxy (`src/proxy.mjs`)

```js
export function createProxy({ log, sessionCookieName }) // → { forward(req, res, target), forwardUpgrade(req, socket, head, target), close() }
// target = { port, slug, host: '127.0.0.1', publicHost, route, upstreamAuthorization? }  (pages via closure? NO —
// proxy takes an `onError(req,res,kind,target)` callback supplied by router at construction:
//   createProxy({ log, renderBadGateway(req, res, { kind: 'connect'|'timeout'|'reset', target }) })
```
- `http.request` to `127.0.0.1:port`, method/path passthrough, **Host header
  preserved** (public host — dev servers see the real vhost; README documents
  Vite `server.allowedHosts`).
- Strip hop-by-hop request AND response headers: `connection` + every token it
  names, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`,
  `trailer`, `transfer-encoding`, `upgrade` (except the upgrade path).
- The domain-wide Console session cookie (`sessionCookieName`) and host-only
  OIDC flow cookie (`dc_flow`) terminate at this trust boundary. Strip only
  those two names from upstream HTTP and WebSocket request `Cookie` headers,
  and remove only those names from every upstream `Set-Cookie` response
  (ordinary HTTP, 101, and upgrade refusal). Preserve unrelated application
  cookies and their attributes exactly. Treat each Node `Set-Cookie` array
  entry as one field; never comma-split because `Expires` contains a comma.
- Add `X-Forwarded-For` (append client IP), `X-Forwarded-Proto: https` (or
  http in dev mode), `X-Forwarded-Host: <original host>`.
- For `route.auth !== 'public'`, delete caller `Authorization` and set it only
  from `target.upstreamAuthorization` when configured. Remove upstream
  `WWW-Authenticate` and `Authentication-Info` on HTTP responses, 101s, and
  upgrade refusals so the Google-authenticated browser never sees a second
  Basic/Digest prompt. For public routes, preserve caller `Authorization`,
  ignore any stored credential, and preserve upstream auth response headers.
- Stream both directions (`req.pipe(upstream)`, `upstreamRes.pipe(res)`); no
  buffering; SSE and chunked responses flow through untouched.
- Connect timeout 5s → 504 page; `ECONNREFUSED`/reset before headers → 502
  page; after headers sent → destroy both sides. Keep-alive agent
  (`new http.Agent({ keepAlive: true, maxSockets: 256 })`).
- `forwardUpgrade`: `http.request` with the original upgrade headers
  (hop-by-hop stripped but `Connection: Upgrade` + `Upgrade` preserved,
  `Sec-WebSocket-*` passthrough); on upstream `'upgrade'` → write
  `HTTP/1.1 101` + upstream headers to client socket, then
  `socket.pipe(upstreamSocket).pipe(socket)` (write `head` first if
  non-empty); on upstream `'response'` (refusal) → serialize status+headers+
  body to the raw socket and end. Errors → destroy both. `socket.setNoDelay(true)`.

## Sessions (`src/auth/session.mjs`)

```js
export function createSessionManager({ secret, ttlMs, cookieName, cookieDomain, secure })
// → { issue(profile): { cookie, session },   // Set-Cookie string value
//     parse(cookieHeader): session | null,   // signature+exp verified
//     clearCookie(): string,
//     signBlob(obj, ttlMs): string, verifyBlob(str): object|null }  // for flow cookie reuse
```
The session value is `base64url(JSON payload) + '.' + base64url(HMAC-SHA256(secret, payloadB64))`,
verified with `crypto.timingSafeEqual`. Payload `{ v:1, sub, email, name, pic, iat, exp }`
(seconds). Cookie attrs: `Domain=.<domain>; Path=/; HttpOnly; SameSite=Lax;
Max-Age=<ttl>` + `Secure` when `secure`. `parse` returns null on any
malformation — never throws.

## OIDC (`src/auth/oidc.mjs`)

```js
export function createOidc({ issuer, clientId, clientSecret, redirectUri, sessions, log })
// → { configured: boolean,
//     loginRedirect(rt): Promise<{ url, flowCookie }>,      // flowCookie: full Set-Cookie string, host-only, 10min, name 'dc_flow'
//     handleCallback(searchParams, flowCookieValue): Promise<{ profile, rt }> } // throws OidcError
export class OidcError extends Error {} // .code: 'state_mismatch'|'exchange_failed'|'bad_id_token'|'not_configured'|…
```
- Discovery from `${issuer}/.well-known/openid-configuration`, cached 24h.
  `http:` issuer allowed **only** for loopback hosts (tests) — else throw at
  construction.
- PKCE S256 + `state` + `nonce` (32 random bytes each, base64url). Flow state
  `{ state, nonce, verifier, rt }` lives in the signed flow cookie
  (`sessions.signBlob`), never server-side.
- Authorize params: `response_type=code`, `scope=openid email profile`,
  `access_type=online`, `prompt=select_account`.
- Token exchange via global `fetch` (10s `AbortSignal.timeout`), then ID-token
  verification **in code, no library**: header `alg` must be RS256; key from
  JWKS (`jwks_uri`, cached 1h, single refetch on unknown `kid`;
  `crypto.createPublicKey({ key: jwk, format: 'jwk' })` +
  `crypto.verify('RSA-SHA256', …)`); claims: `iss` === discovery issuer, `aud`
  === clientId, `exp`/`iat` with 300s skew, `nonce` matches, `email_verified`
  === true. Profile `{ sub, email: lowercased, name, pic }`.

## Guard (`src/auth/guard.mjs`)

```js
export function createGuard({ sessions, access, config, log })
// → { sessionFrom(req): session|null,          // parse + live membership re-check
//     isKnownEmail(email): boolean,
//     isAdmin(sessionOrEmail): boolean,
//     hasAccess(sessionOrEmail, resource): boolean,
//     wantsHtml(req): boolean,
//     loginRedirectUrl(req): string,           // console /auth/login?rt=<abs url of req>
//     validateRt(rt): string,                  // safe return URL or '/'
//     checkOrigin(req): boolean }              // mutation CSRF: Origin/Referer must match consoleOrigin
```
Every mutating console-API request must pass `checkOrigin` (403 otherwise).

## Pages (`src/auth/pages.mjs`)

```js
export function createPages({ config })
// → { renderLogin({ rt, error, degraded }), renderDenied({ email, resource, sessionSet }),
//     renderNotFound({ slug }), renderUpstreamError({ slug, kind, detail, consoleUrl }),
//     renderError({ status, title, detail }) } // each → { status, html }
```
Self-contained dark-theme HTML (inline CSS, no external assets), consistent
branding "DevOps Console — vr.ae". Never echo user input unescaped
(`escapeHtml` mandatory).

## Coordinator client (`src/coordinator.mjs`)

```js
export function createCoordinator({ config, log })
// → { ensureRunning(): Promise<{ ok, autostarted, error? }>,
//     probe(): Promise<boolean>,                       // anonymous GET /healthz, 2s timeout
//     inventory({ maxAgeMs = 5000 } = {}): Promise<Inventory>,   // cached + coalesced
//     serversRaw({ maxAgeMs = 3000 } = {}): Promise<Server[]>,   // GET /v1/servers cached
//     request(method, path, body, { timeoutMs }): Promise<any>,  // throws CoordError
//     leasePort(b), releasePort(b), serverStart(b), serverStop(b), serverRestart(b),
//     serverLogs(b), serverRegister(b), dockerAction(name, action, b), dockerLogs(b),
//     status(): { ok, url, autostarted, lastError, lastOkAt },
//     close() }
export class CoordError extends Error {} // .status (http), .body
```
- Requests may run concurrently; the coordinator serializes only short state
  reservation/commit phases and rejects conflicting lifecycle targets. Per-path timeouts:
  `/v1/projects/*` 300s, `/v1/inventory` 60s, docker 60s, rest 15s. The
  systemd-only readiness gate uses authenticated `GET /v1/inventory/no-docker`
  so exact server/assignment/lease observation is not coupled to Docker CLI or
  daemon availability.
- Error bodies are `{"error": "..."}`; KeyError messages keep quotes
  (`"'agent'"`) — surface `.message` trimmed of surrounding quotes.
- Every `/v1/*` request reads the private `COORDINATOR_TOKEN_FILE` server-side
  and sends `Authorization: Bearer …`; `/healthz` is the only anonymous route.
- `ensureRunning()`: probe; if down and `coordinatorAutostart`, spawn
  `python3 <coordinatorScript> api serve --host 127.0.0.1 --port <from url>`
  with `--token-file <coordinatorTokenFile>` detached (`stdio` → append
  `<stateDir>/logs/coordinator-api.log`, pass `CODEX_AGENT_COORDINATOR_HOME`
  if set), `unref()`, poll probe up to 15s.
  Called at boot and lazily on request failure (max 1 attempt/30s).
- Attribution: every mutation body gets `agent` (`devops-console:<email>` for
  user-initiated, `devops-console` for boot-time) and `project` filled by the
  **caller** (api.mjs) — this client never invents them.
- **Cache invalidation on mutations**: any successful non-GET request except
  `*/logs` clears the `inventory`/`serversRaw` caches, so a post-mutation
  overview never shows pre-mutation state for up to the cache window.

## Metrics history (`src/metrics.mjs`)

```js
export function createMetricsStore({ config, log, coordinator, maxPoints = 720 })
// → { ingest(inventory, { at, dedupe }={}), sampleOnce(): Promise<void>,
//     start(), stop(), history({ limit }={}): HistoryView, intervalMs }
```
In-memory ring buffers of `[epochMs, cpuPercent, memoryBytes]` per entity:
`srv:<id>` (from `server.process_usage`), `dock:<name>` (from
`container.stats`, running containers only) and `proj:<project_key>` (from
`project_usage`). A background `setInterval` sampler (unref'd,
`config.metricsIntervalMs`, default 10s) pulls `coordinator.inventory()`
(cached ≤ interval/2); every successful `/api/overview` inventory fetch is
also ingested. Readings landing inside 0.6×interval replace the last point
instead of appending. Buffers cap at `maxPoints` (oldest dropped); entities
unseen for `maxPoints × interval` are pruned. History resets on process
restart — deliberate: no disk state, no PII, charts say so.

## Route store (`src/routes.mjs`)

```js
export function createRouteStore({ file, config, log })   // file: <stateDir>/routes.json
// → { load(): Promise<void>, list(): Route[], get(slug): Route|null,
//     create(def): Promise<Route>, update(slug, patch): Promise<Route>,
//     remove(slug): Promise<Route>,
//     resolve(slug, coordinator): Promise<{ port: number|null, reason?: string, server?: {id,name,project,status}, container?: {name,status} }> }
export class RouteError extends Error {} // .status 400|404|409
export function parsePublishedPorts(text)      // docker ps Ports → [{hostAddr,hostPort,containerPort}] (tcp, published only)
export function publishedHostPort(mappings, containerPort) // loopback-reachable host port or null (v4 preferred)
export function publishedContainerPorts(text)  // [{containerPort, hostPort}] distinct, reachable, sorted
```
Schema on disk: `{ "version": 1, "routes": { "<slug>": Route } }`, atomic
write (`.tmp` + `rename`). `Route`:
```js
{ slug, kind: 'port'|'server'|'docker',
  port?,                    // kind=port: 1-65535
  project?, serverName?,    // kind=server: coordinator identity key parts
  containerName?, containerPort?, // kind=docker: container + its CONTAINER-side port
  auth: 'google'|'public',  // DEFAULT 'google' — public must be explicit
  title?, createdAt, updatedAt }
```
Slug rules: regex above, single label, NOT in reserved set
`{ console, www, api, auth, static, healthz }` ∪ `{config.consoleHost label}`.
409 on duplicate. `resolve`: `kind=port` → that port; `kind=server` → find in
`coordinator.serversRaw()` by `project`+`name`, prefer `status==='running'`,
else return `{ port: null, reason: 'server stopped'|'server not found' }`;
`kind=docker` → find the container by name in `coordinator.inventory()`
(cached), require an `Up …` status, then map `containerPort` to its published
loopback-reachable HOST port via `parsePublishedPorts` — the durable identity
is container name + container-side port, so remapped host ports keep working.
Every resolved port (all kinds) passes `guardCoordinatorPort` — a route can
never proxy into the coordinator API (invariant #1).

## Upstream credential store (`src/upstream-auth.mjs`)

```js
export function createUpstreamAuthStore({ file, log })
// → { load(), describe(slug), listDescriptions(), authorizationFor(slug),
//     set(slug, { scheme, username?, secret }), remove(slug), move(from, to) }
```

Schema on disk:
`{ "version": 1, "routes": { "<slug>": { "scheme": "bearer", "secret": "…" } } }`
or Basic `{ scheme, username, secret }`. The external file is a real regular
file with no group/world permissions; writes use a mode-`0600` temporary file
and atomic rename. Invalid-permission state fails startup. Malformed state is
preserved as `.corrupt-<timestamp>` and disabled, never partially trusted.
Mutations serialize and publish to the live map only after durable persistence.

`describe`/`listDescriptions` return only `{ configured, scheme }` metadata.
`authorizationFor` is used only inside router/proxy composition and is never
returned through the Console API. Route deletion/publication removes a stored
credential; server/container route rename moves it. The deployment CLI accepts
secrets only on stdin and emits redacted JSON.

## Access policy store (`src/access.mjs`)

```js
export function createAccessStore({ file, adminEmails, routeStore, log })
// file: <stateDir>/access-control.json
// → { load(), isAdmin(email), isKnown(email), canAccess(email, resource), list(),
//     addUser({email,grants}), setGrant(email,resource,allowed), removeUser(email),
//     clearResource(resource), moveResource(fromResource,toResource) }
export const CONSOLE_GRANT = 'console'
export const routeGrant = (slug) => `route:${slug}`
export class AccessError extends Error {} // .status 400|404|409|500
```

Configured `adminEmails` (the normalized `ALLOWED_EMAILS` set) are immutable
owners and are not written to state. Owners are always known, may administer
access, and bypass every resource grant. Invited accounts are stored as
`{version:1,users:{"email":{"grants":[...]}}}` and written atomically at mode
`0600`. Email/grant mutations are serialized as server-side deltas so
concurrent changes merge. A failed write leaves memory unchanged. Invalid
policy is renamed to `.corrupt-<epoch>` and fails closed to owners only.
Successful invitation, grant, and removal mutations are logged with the acting
configured owner and affected account/resource for operator audit trails.

`isKnown` is checked for every signed request, so deleting a user invalidates
an existing cookie immediately. `canAccess` is checked separately for
`console` or `route:<slug>`, so revoking one grant preserves the user's other
sessions/grants. Loading prunes grants for absent routes. Route deletion clears
the resource, new slug creation clears stale grants before the route appears,
and server/container slug renames move grants to the new host.

## Console API (`src/api.mjs`)

```js
export function createConsoleApi({ config, log, coordinator, routeStore, upstreamAuthStore, accessStore, guard, certManager, metrics, prefs })
// → { handle(req, res, session): Promise<void> }   // only called for /api/*
```
JSON in/out; errors `{ "error": "<message>" }` with 400/401/403/404/409/502.
A `CoordError` with a 4xx status (the coordinator answered, the request was
bad — e.g. "matching lease not found") passes through as 400; transport
failures and 5xx surface as 502 with the coordinator's message. Mutations
(POST/PATCH/DELETE) require `guard.checkOrigin` → else 403. Body limit 64KB.

| Method+Path | Behavior |
|---|---|
| `GET /api/overview` | `{ console: { version, domain, consoleHost, now, tls: certManager.info(), devInsecureHttp }, coordinator: coordinator.status(), inventory: Inventory\|null, routes: RouteView[] }`. Inventory from `coordinator.inventory()`; on CoordError → `inventory: null` and `coordinator.ok:false` with error (HTTP still 200 — UI shows degraded state). `RouteView = Route + { url: 'https://<slug>.<domain>', upstreamAuth: { configured, scheme? }, resolved: { port, reason?, serverStatus?, containerStatus? } }` (kind=server resolves via `serversRaw`; kind=docker via the cached `inventory()` — both shared/coalesced). No upstream secret is returned. |
| `GET /api/access` | Owner-only `{ version, users: [{ email, owner, grants }], resources: [{ id, kind, host, title, auth, target }], invitedCount }`. Configured owners appear locked; only owners may read the full email list. |
| `POST /api/access/users` | Owner-only `{ email, grants? }` → 201 full access view. Invites an email identity; the invitation becomes usable only when verified Google OIDC returns that exact address. An empty grant list is allowed. |
| `PATCH /api/access/users/:email` | Owner-only delta `{ resource, allowed: boolean }` → full access view. Configured owners are immutable. |
| `DELETE /api/access/users/:email` | Owner-only removal → full access view; current sessions become unknown immediately. |
| `POST /api/routes` | body `{ slug, kind, port?, project?, serverName?, containerName?, containerPort?, auth?, title? }` → 201 RouteView |
| `PATCH /api/routes/:slug` | any of `{ auth, title, port, project, serverName, containerName, containerPort, kind }` → RouteView |
| `DELETE /api/routes/:slug` | → `{ ok: true }` |
| `PATCH /api/routes/:slug/upstream-auth` | Owner-only body `{ scheme:'bearer', secret }` or `{ scheme:'basic', username, secret }`; Google-protected routes only → redacted `{ slug, upstreamAuth }` |
| `DELETE /api/routes/:slug/upstream-auth` | Owner-only removal → redacted `{ slug, upstreamAuth:{ configured:false } }` |
| `POST /api/servers/action` | `{ id, action: 'stop'\|'restart' }` — looks up server in `serversRaw` by id → coordinator `serverStop/serverRestart` with `{ agent: 'devops-console:'+session.email, project: server.project, name: server.name, reason }` → `{ server }` |
| `POST /api/servers/logs` | `{ id, tail=200 }` → coordinator `serverLogs` `{ server_id: id, tail }` → passthrough |
| `POST /api/docker/action` | `{ name, action: 'start'\|'stop'\|'restart' }`; fresh inventory must provide verified Compose/sidecar project ownership, which is sent as mutation attribution; unattributed containers are refused |
| `POST /api/docker/subdomain` | `{ name, slug, auth?, port? }` — assign/change/remove a container's subdomain in one call (mirrors `/api/servers/subdomain`). Fresh inventory lookup (404 unknown container); `port` is the CONTAINER-side port, required only when the container publishes several (400 lists them), validated against currently-published ports (400 on typo); empty `slug` unassigns → `{ route: null }`. Creates/updates a `kind:'docker'` route → 200/201 `{ route: RouteView }` |
| `POST /api/docker/logs` | `{ name, tail=120 }` → passthrough `{ text }` |
| `GET /api/metrics/history?limit=N` | `metrics.history({ limit })` → `{ now, intervalMs, maxPoints, sampler: { running, lastSampleAt, lastError }, host, entities: [{ key, kind: 'host'\|'server'\|'docker'\|'project', id, name, project, points: [[epochMs, cpuPercent, memBytes], …] }] }`. `host` is the latest whole-machine snapshot from `src/host.mjs` (`{ at, cpuPercent, cores, load[3], uptimeSec, mem: { totalBytes, usedBytes, availableBytes }, disks: [{ mount, totalBytes, usedBytes, availableBytes }] }`, `cpuPercent` null until the second sample; sampled every tick INDEPENDENTLY of coordinator health) and its cpu/mem history rides in `entities` as `kind:'host'`, key `host`. Memory "used" is total minus MemAvailable on Linux (plain free elsewhere); disks come from `fs.statfs` over `/` + home, deduped by device. `limit` caps points per entity (400 on non-positive/garbage). |
| `POST /api/ports/lease` | `{ purpose?, preferred?, ttl?, project? }` → coordinator `leasePort` with `agent: 'devops-console:'+session.email`, `project` defaulting to `config.projectRoot`; a `preferred` port pins `range` to that port → 201 `{ lease }` |
| `POST /api/ports/release` | `{ lease_id }` (required); fresh inventory supplies the owning project and the Console supplies the acting user before coordinator `releasePort` → `{ lease }`. Releasing a lease never removes a durable port pin. |
| `POST /api/ports/unassign` | `{ name, project }` (or `{ port, force? }` for orphan cleanup) → coordinator `unassignPort` with console-user attribution → `{ assignment }` (status `unassigned`). The only console path that frees a durable port pin. |
| `POST /api/projects/action` | `{ project, action: 'start'\|'stop'\|'restart' }` → coordinator `/v1/projects/<action>` with console-user attribution. HTTP 200 reports with `ok:false`/`partial`/`action_errors` remain visible failures, never UI success. |
| `GET /api/prefs` | UI preferences: `{ version, hidden: { servers: [identity keys], docker: [names], projects: [usage_keys] } }` from `<stateDir>/ui-prefs.json` |
| `PATCH /api/prefs` | `{ hide?: { servers?, docker?, projects? }, unhide?: {…} }` — DELTAS only, merged server-side (validated: strings, trimmed, deduped, ≤500 entries × ≤300 chars) → the full prefs. Whole-list replacement is deliberately unsupported so a stale client snapshot can never wipe hides made elsewhere. Origin-guarded like every mutation. |
| `GET /api/session` | `{ email, name, pic, exp, accessAdmin }`; `accessAdmin` is true only for configured owners. |
| anything else | 404 |

`GET /api/overview` also feeds its fresh inventory into `metrics.ingest()`.

## Static UI server (`src/static.mjs`)

```js
export function createStaticServer({ dir, log }) // → { handle(req, res) }
```
Serves `src/ui/`: `/` → `index.html` (Cache-Control: no-cache), assets by
exact name (immutable 1h), correct MIME (`html/css/js/svg/png/ico/json/txt`),
`ETag` (mtime-size), 404 otherwise, no path traversal (resolve + prefix
check), GET/HEAD only.

## UI (`src/ui/`)

Vanilla JS control panel split into hash-routed pages (`#/projects` default,
`#/servers`, `#/routes`, `#/docker`, `#/ports`, `#/performance`, and the
owner-only `#/access`);
unknown/empty hashes fall back to Projects. One sticky SINGLE-ROW header on
every page and viewport: brand + section nav (tabs with live counts inline
≥1024px; a hamburger-toggled drawer dropping below the row on narrower
screens — `aria-controls`/`aria-expanded`, Escape/outside-tap closes) + a
needs-attention badge + a compact account button (popover: email, sign out).
There is NO status sentence and there are no always-on chips: a quiet header
means healthy. `headerProblems()` collects everything wrong — coordinator
unreachable (red), TLS expired (red) / expiring <14d / unknown (amber),
insecure dev HTTP mode, unhealthy servers, routes not resolving, Docker
daemon down, stale live data — and the badge shows the count in the worst
severity's color; its popover explains each problem with facts, an
instruction, and a direct action (Try again / Open page / copyable
`sudo certbot renew` / Refresh now). Action buttons console-wide are
color-coded — Start green, Restart blue, Stop red (disabled drops to
neutral) — and every Projects-tree row renders the same three fixed-width
slots via `treeActionSlots` (inapplicable actions disabled, never hidden) so
buttons align into columns across project headers, servers and containers.
Fetches `/api/overview` every 6s and `/api/metrics/history` every 10s (both
paused when `document.hidden`; the performance page requests a longer
window), optimistic updates on mutations then refetch.

Pages: **Projects** (default; a tree of repos built from the coordinator's
`project_usage` membership — `server_ids`/`container_names`, never re-derived
client-side — with per-item AND per-project CPU/mem + sparklines, per-item
start/stop/restart, whole-project start/stop/restart via
`/api/projects/action`, collapsible nodes), **Servers** (grouped by repo;
expandable rows: health classification, pid, project,
cmd, log tail viewer, stop/restart, per-server subdomain assign/edit/remove —
the primary way routes are managed — plus live CPU%/memory numbers with a
sparkline that opens full history charts; docker-hosted web servers appear
here too as first-class rows — any non-database container publishing a TCP
port on a loopback-reachable address (`0.0.0.0`/`127.0.0.1`; v6-only
publishes are excluded because the proxy dials v4 loopback), or a stopped
one that still has a route — with a `docker` kind tag,
container status badge, published host ports, start/stop/restart via
`/api/docker/action`, container log panel, and the same subdomain control
saving through `/api/docker/subdomain` with a container-port picker when
several ports are published), **Routes** (create form for
fixed-port, managed-server or container targets + table: clickable URL + copy
button, target with "view server" link for server/container-backed routes,
public/login toggle switch, resolved status dot, delete), **Docker** (status,
image, ports, live CPU/mem + sparkline, start/stop/restart, logs, subdomain
control on web-serving containers), **Port leases** (lease
form: purpose/preferred port/TTL/project; table with countdowns and
confirmed release), **Performance** (a "Machine" panel first — whole-box
CPU with cores and load averages, memory used/available, per-disk storage
and uptime as stat tiles with meters, alarm tint above 90%, plus host
CPU/memory history charts — then per-entity CPU and memory history
charts for every sampled server/container + per-project usage bars with
sparklines), **Access** (the real owner/invited-user collection first; each
invited user has exact Console/domain checkboxes; configured owners are locked;
Add user opens a focused in-viewport dialog; remove names the account and
immediate revocation consequence). Docker/Ports lists are grouped by repo with project subheaders.
**Hiding:** stopped servers/containers and idle projects can be hidden
(persisted server-side via `/api/prefs`, shared across devices); anything the
coordinator reports as running is auto-unhidden on the next poll, and every
page with hidden items shows a "Show N hidden items" reveal toggle with
per-row unhide. **Stable ordering:** rows and project groups keep a
deterministic order across polls (running-first, then name/key via
`projectGroupOrder`) — live CPU/memory readings are never an ordering key,
so nothing reshuffles under the pointer between refreshes. Charts are inline
SVG built via `createElementNS` — user data
never goes through `innerHTML`. Must implement the repo's ten
interaction-affordance requirements (badge-detail, row-hit-target,
navigation-cursor, transient-disclosure, disclosure-scrollbar, icon-meaning,
stable-expansion-width, hover-copy, status-summary, message-metadata), plus
loading/empty/error/disabled/focus-visible states, dark theme, and both
1440px desktop and 390px mobile layouts with **no horizontal document
scroll**. No external fonts/CDNs. All API errors surface in a dismissible
error banner with the coordinator's message verbatim. Asset URLs carry a
`?v=<version>` query so the 1h immutable cache never serves a stale
`app.js`/`app.css` against a fresh `index.html`.

## Entry (`bin/devops-console.mjs`)

Composition root: `loadConfig` (respect `--env-file <p>`, `--check-config`
prints redacted config and exits 0) → logger → certManager (skip in
devInsecureHttp) → sessions → oidc → guard → pages → coordinator
(`ensureRunning()` non-fatal) → metrics (`createMetricsStore` + `start()`) →
routeStore (`load()`) → upstreamAuthStore (`load()`) → accessStore (`load()`)
→ consoleApi → static → proxy → router → `startServers`. SIGHUP → cert
reload; SIGTERM/SIGINT →
graceful close (also `metrics.stop()` and `coordinator.close()`). On listen success, log every
public URL. Production listeners bind the explicit IPv4 wildcard `0.0.0.0`;
development listeners bind IPv4 loopback. If `process.env.PORT` is set for an optional coordinator-spawned
dev instance, skip self-registration; required production registration ignores
that inherited value. When `httpsPort === 443`, retry the exact
`serverRegister({ agent: 'devops-console', project: config.projectRoot,
name: 'devops-console', pid: process.pid, port: 443 })` call with a short bound
and reject a response without the same PID, an exact HTTP 200 health response,
healthy status, and active lease. Linux requires exact procfs socket-inode
evidence; non-Linux direct runs accept the coordinator's platform listener
proof without weakening that Linux gate. Local direct
deployments retain an explicitly optional best-effort mode. The production
unit pins `COORDINATOR_REGISTRATION_REQUIRED=1`, so exhausted registration
fails startup instead of serving with a stopped coordinator record and no
active lease.

## Test fixtures (test agents; `test/helpers/`)

- `fixture-issuer.mjs`: real local OIDC issuer (discovery, authorize —
  auto-approves a configurable profile, token, JWKS) with an RSA keypair from
  `crypto.generateKeyPairSync`; issuer URL `http://127.0.0.1:<port>`.
- `ws-echo.mjs`: genuine RFC6455 echo server (handshake `Sec-WebSocket-Accept`,
  frame parse/serialize for text ≤125B is enough) on `net`/`http` upgrade.
- `upstream.mjs`: HTTP upstream echoing method/path/headers/body + an SSE
  endpoint and an operator-credential challenge path.
- Tests run the real stack: real coordinator (`api serve`, ephemeral port,
  `CODEX_AGENT_COORDINATOR_HOME=<tmp>`), real console (spawned or in-process),
  ephemeral ports, dev certs from `certs/dev/` (`rejectUnauthorized:false`,
  `Host` header set manually — no DNS needed).

## Security invariants (review will check these)

1. Coordinator API is loopback-only and bearer-authenticated; the token never
   enters browser state. The console still refuses proxy routes to its port and
   exposes only fixed server-side calls behind session + Origin checks.
2. Default-deny: new routes default `auth:'google'`; unknown slugs
   indistinguishable from protected ones to anonymous users.
3. Proxy targets are always `127.0.0.1` — a route can never point elsewhere.
4. `rt` open-redirect guard; flow cookie signed; `state`+`nonce`+PKCE all
   enforced; ID-token signature verified against Google JWKS.
5. Cookies: HttpOnly, Secure (prod), SameSite=Lax, HMAC-SHA256, timing-safe
   compare. Session parse re-checks current policy membership on every request;
   protected HTTP and WebSocket traffic then checks its exact resource grant.
   Only configured owners may inspect or mutate the access list. The edge
   consumes `cookieName` and `dc_flow` for authentication but never forwards
   them to routed HTTP/WebSocket projects or accepts those names from upstream
   `Set-Cookie`; unrelated project cookies remain end-to-end.
6. Protected routes strip caller `Authorization`, may inject only their
   private mode-`0600` route credential after exact Google authorization, and
   suppress backend HTTP-auth challenges. Public routes receive no stored
   credential and preserve ordinary HTTP-auth headers. Only configured owners
   may change the credential; route/API/CLI views never expose it.
7. No secrets in logs; no directory traversal; HTML escaping in every page.
