// Boots the WHOLE console stack in-process for e2e tests:
//   - fixture OIDC issuer, HTTP echo upstream, RFC6455 ws-echo (all port 0)
//   - a REAL codex-dev-coordinator (`api serve --port 0`) with an isolated
//     CODEX_AGENT_COORDINATOR_HOME under mkdtemp
//   - the real console via bin/devops-console.mjs start(): real TLS from
//     certs/dev/, DOMAIN=vr.ae, DEV mode OFF, listeners on OS-assigned ports
//     bound to 127.0.0.1.
//
// Also provides browser-ish request helpers: they connect to
// https://127.0.0.1:<edge port> with rejectUnauthorized:false and an
// arbitrary Host header, follow redirects manually, and keep cookies in a
// jar keyed by domain suffix like a browser (Domain=.vr.ae is sent to
// console.vr.ae AND app.vr.ae).

import { execFile, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import { promises as fsp, readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { start as startConsole } from '../../bin/devops-console.mjs';
import { startIssuer } from './fixture-issuer.mjs';
import { startUpstream } from './upstream.mjs';
import { startWsEcho } from './ws-echo.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
export const COORDINATOR_SCRIPT = path.join(
  REPO_ROOT,
  'skills',
  'codex-dev-coordinator',
  'scripts',
  'dev_coordinator.py',
);

import { DEV_CERT, DEV_KEY, ensureDevCert } from './dev-cert.mjs';

const execFileAsync = promisify(execFile);
const INVENTORY_WIRE_SCHEMA_VERSION = 2;
// The real-stack fixture runs the Coordinator from this checkout. Read its
// canonical schema declaration so a valid migration does not strand browser
// verification on an obsolete duplicated number.
const COORDINATOR_SCHEMA_SOURCE = readFileSync(path.join(
  REPO_ROOT, 'skills', 'codex-dev-coordinator', 'scripts',
  'devcoordinator', 'schema.py',
), 'utf8');
const COORDINATOR_STORE_SCHEMA_VERSION = Number(
  COORDINATOR_SCHEMA_SOURCE.match(/^SCHEMA_VERSION\s*=\s*(\d+)$/m)?.[1],
);
if (!Number.isInteger(COORDINATOR_STORE_SCHEMA_VERSION)) {
  throw new Error('canonical Coordinator store schema version is unreadable');
}

async function assertFixtureEntry(target, expectedKind, label) {
  const info = await fsp.lstat(target);
  const actualKind = info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other';
  if (info.isSymbolicLink() || actualKind !== expectedKind) {
    throw new Error(`${label} is not a real ${expectedKind}: ${target}`);
  }
}

export async function canonicalTempDir(prefix) {
  // Select the first canonical writable local base. Each repository fixture
  // creates its own nearer .git identity; an unrelated ancestor marker must
  // not make the entire server temp area unusable.
  const candidates = [
    process.env.DEVCOORDINATOR_TEST_TMP_ROOT,
    os.homedir(),
    os.tmpdir(),
  ].filter(Boolean);
  for (const candidate of [...new Set(candidates)]) {
    let base;
    let created;
    try {
      base = await fsp.realpath(candidate);
      created = await fsp.mkdtemp(path.join(base, prefix));
    } catch (error) {
      if (!['EACCES', 'ENOENT', 'EROFS'].includes(error?.code)) throw error;
      continue;
    }
    const canonical = await fsp.realpath(created);
    await assertFixtureEntry(canonical, 'directory', 'E2E temporary root');
    return canonical;
  }
  throw new Error('no writable canonical test temp root');
}

export async function assertFixtureRepositorySecurity(repositoryRoot) {
  const canonical = await fsp.realpath(repositoryRoot);
  if (canonical !== path.resolve(repositoryRoot)) {
    throw new Error(`E2E repository fixture is not canonical: ${repositoryRoot}`);
  }
  await assertFixtureEntry(canonical, 'directory', 'E2E repository root');
  await assertFixtureEntry(
    path.join(canonical, '.git'),
    'directory',
    'E2E repository .git metadata',
  );
  await assertFixtureEntry(
    path.join(canonical, '.git', 'config'),
    'file',
    'E2E repository config metadata',
  );

  // Use the production repository resolver for canonical identity. Local
  // UID/GID/mode/ACL metadata is deliberately not a same-server trust gate.
  const verifier = String.raw`
import json
import sys

sys.path.insert(0, sys.argv[1])
from devcoordinator.repository_context import resolve_repository_context

context = resolve_repository_context(root_repo=sys.argv[2], temporary_repo=None)
print(json.dumps({
    "root": context.root.canonical_root,
    "git_dir": context.root.git_dir,
    "git_common_dir": context.root.git_common_dir,
}))
`;
  const { stdout } = await execFileAsync(
    'python3',
    ['-c', verifier, path.dirname(COORDINATOR_SCRIPT), canonical],
    {
      env: { ...process.env },
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    },
  );
  let evidence;
  try {
    evidence = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `E2E production repository proof emitted invalid JSON: ${error}; stdout=${JSON.stringify(stdout)}`,
    );
  }
  if (
    evidence?.root !== canonical
    || evidence?.git_dir !== path.join(canonical, '.git')
    || evidence?.git_common_dir !== path.join(canonical, '.git')
  ) {
    throw new Error(`E2E production repository proof contradicted the fixture: ${JSON.stringify(evidence)}`);
  }
  return canonical;
}

export async function initializeFixtureGitRepository(repositoryRoot) {
  const canonical = await fsp.realpath(repositoryRoot);
  if (canonical !== path.resolve(repositoryRoot)) {
    throw new Error(`E2E repository fixture is not canonical: ${repositoryRoot}`);
  }
  await execFileAsync('git', ['-C', canonical, 'init', '-q']);
  return assertFixtureRepositorySecurity(canonical);
}

export async function canonicalGitTempDir(prefix) {
  const root = await canonicalTempDir(prefix);
  return initializeFixtureGitRepository(root);
}

// ---------------------------------------------------------------------------
// Cookie jar (browser-style: Domain cookies match by suffix, ports ignored)
// ---------------------------------------------------------------------------

export function makeJar() {
  const store = new Map(); // `${name}|${domain}|${path}` -> cookie

  function parseSetCookie(line, requestHostname) {
    const parts = String(line).split(';');
    const eq = parts[0].indexOf('=');
    if (eq <= 0) return null;
    const cookie = {
      name: parts[0].slice(0, eq).trim(),
      value: parts[0].slice(eq + 1).trim(),
      domain: requestHostname.toLowerCase(),
      hostOnly: true,
      path: '/',
      secure: false,
      httpOnly: false,
      expired: false,
      raw: String(line),
    };
    for (const attrRaw of parts.slice(1)) {
      const attr = attrRaw.trim();
      const attrEq = attr.indexOf('=');
      const key = (attrEq === -1 ? attr : attr.slice(0, attrEq)).trim().toLowerCase();
      const value = attrEq === -1 ? '' : attr.slice(attrEq + 1).trim();
      if (key === 'domain' && value) {
        cookie.domain = value.replace(/^\./, '').toLowerCase();
        cookie.hostOnly = false;
      } else if (key === 'path' && value) {
        cookie.path = value;
      } else if (key === 'secure') {
        cookie.secure = true;
      } else if (key === 'httponly') {
        cookie.httpOnly = true;
      } else if (key === 'max-age') {
        if (Number(value) <= 0) cookie.expired = true;
      } else if (key === 'expires') {
        const t = Date.parse(value);
        if (Number.isFinite(t) && t <= Date.now()) cookie.expired = true;
      }
    }
    return cookie;
  }

  return {
    store(setCookieLines, requestHost) {
      const hostname = String(requestHost).split(':')[0];
      for (const line of [].concat(setCookieLines ?? [])) {
        const cookie = parseSetCookie(line, hostname);
        if (!cookie) continue;
        const key = `${cookie.name}|${cookie.domain}|${cookie.path}`;
        if (cookie.expired) store.delete(key);
        else store.set(key, cookie);
      }
    },
    headerFor(host, pathname = '/', secure = true) {
      const hostname = String(host).split(':')[0].toLowerCase();
      const send = [];
      for (const c of store.values()) {
        const domainMatch = c.hostOnly
          ? hostname === c.domain
          : hostname === c.domain || hostname.endsWith(`.${c.domain}`);
        const cookiePath = c.path.endsWith('/') ? c.path : `${c.path}/`;
        const pathMatch = c.path === '/' || pathname === c.path || pathname.startsWith(cookiePath);
        if (!domainMatch || !pathMatch) continue;
        if (c.secure && !secure) continue;
        send.push(`${c.name}=${c.value}`);
      }
      return send.join('; ');
    },
    get(name) {
      for (const c of store.values()) if (c.name === name) return c;
      return null;
    },
    all() {
      return [...store.values()];
    },
  };
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

function targetFor(stack, u) {
  if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') {
    // Direct request (fixture issuer, coordinator) — not through the edge.
    return {
      transport: u.protocol === 'https:' ? 'https' : 'http',
      connectHost: u.hostname,
      connectPort: Number(u.port || (u.protocol === 'https:' ? 443 : 80)),
    };
  }
  // Anything else is dialed to the loopback edge with the URL's Host header.
  return u.protocol === 'https:'
    ? { transport: 'https', connectHost: '127.0.0.1', connectPort: stack.httpsPort }
    : { transport: 'http', connectHost: '127.0.0.1', connectPort: stack.httpPort };
}

/** One request; no redirect following. Stores response cookies in opts.jar. */
export function fetchUrl(stack, urlString, opts = {}) {
  const u = new URL(urlString);
  const { method = 'GET', headers = {}, body, jar, timeoutMs = 15_000 } = opts;
  const { transport, connectHost, connectPort } = targetFor(stack, u);

  const finalHeaders = { host: u.host, ...headers };
  if (jar) {
    const cookie = jar.headerFor(u.hostname, u.pathname, u.protocol === 'https:');
    if (cookie) finalHeaders.cookie = finalHeaders.cookie ? `${finalHeaders.cookie}; ${cookie}` : cookie;
  }

  return new Promise((resolve, reject) => {
    const lib = transport === 'https' ? https : http;
    const req = lib.request(
      {
        host: connectHost,
        port: connectPort,
        method,
        path: `${u.pathname}${u.search}`,
        headers: finalHeaders,
        agent: false,
        ...(transport === 'https' ? { rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('error', reject);
        res.on('end', () => {
          const setCookies = res.headers['set-cookie'] ?? [];
          if (jar) jar.store(setCookies, u.hostname);
          const bodyBuf = Buffer.concat(chunks);
          resolve({
            url: u.href,
            status: res.statusCode,
            headers: res.headers,
            setCookies,
            body: bodyBuf,
            text: bodyBuf.toString('utf8'),
          });
        });
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`request timed out: ${method} ${u.href}`)));
    req.on('error', reject);
    if (body != null) req.write(body);
    req.end();
  });
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Follow redirects manually (like a browser), carrying the jar along. */
export async function browse(stack, urlString, opts = {}) {
  const { maxRedirects = 10, ...requestOpts } = opts;
  let current = urlString;
  const hops = [];
  let res = null;
  for (let i = 0; i <= maxRedirects; i++) {
    const first = i === 0;
    res = await fetchUrl(stack, current, {
      ...requestOpts,
      method: first ? requestOpts.method ?? 'GET' : 'GET',
      body: first ? requestOpts.body : undefined,
      headers: first ? requestOpts.headers : { accept: requestOpts.headers?.accept ?? 'text/html' },
    });
    hops.push({ url: current, status: res.status, location: res.headers.location ?? null, setCookies: res.setCookies });
    if (!REDIRECT_STATUSES.has(res.status) || !res.headers.location) {
      return { ...res, hops, finalUrl: current };
    }
    current = new URL(res.headers.location, current).href;
  }
  throw new Error(`too many redirects starting from ${urlString}; trail: ${hops.map((h) => h.url).join(' -> ')}`);
}

/** Full OIDC login through the real console + fixture issuer. */
export async function login(stack, jar, { rt } = {}) {
  const target = rt ?? `${stack.consoleOrigin}/`;
  const startUrl = `${stack.consoleOrigin}/auth/start?rt=${encodeURIComponent(target)}`;
  return browse(stack, startUrl, { jar, headers: { accept: 'text/html' } });
}

/** JSON helper for the console API through the edge. */
export async function apiCall(stack, jar, method, apiPath, body, extraHeaders = {}, opts = {}) {
  const res = await fetchUrl(stack, `${stack.consoleOrigin}${apiPath}`, {
    method,
    jar,
    headers: {
      accept: 'application/json',
      ...(body != null ? { 'content-type': 'application/json' } : {}),
      ...extraHeaders,
    },
    body: body != null ? JSON.stringify(body) : undefined,
    // Slow endpoints (whole-project actions run up to 300s in the
    // coordinator) need more than fetchUrl's 15s default on loaded runners.
    ...opts,
  });
  let json = null;
  try {
    json = JSON.parse(res.text);
  } catch {
    // leave json null; caller can inspect res.text
  }
  return { ...res, json };
}

// ---------------------------------------------------------------------------
// Real coordinator (isolated home, OS-assigned port)
// ---------------------------------------------------------------------------

async function runNormalizedObservation({
  home,
  extraEnv,
  legacySeedHome,
  agent,
  project,
}) {
  const { stdout } = await execFileAsync(
    'python3',
    [
      COORDINATOR_SCRIPT,
      'observe',
      '--agent',
      agent,
      '--project',
      project,
      '--max-age-seconds',
      '0',
      '--legacy-home',
      legacySeedHome,
      '--compact-json',
    ],
    {
      env: {
        ...process.env,
        ...extraEnv,
        CODEX_AGENT_COORDINATOR_HOME: home,
        DEVCOORDINATOR_STATE_BACKEND: 'sqlite',
      },
      timeout: 120_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  try {
    return JSON.parse(stdout);
  } catch (err) {
    throw new Error(`normalized coordinator observation emitted invalid JSON: ${err}; stdout=${JSON.stringify(stdout.slice(0, 600))}`);
  }
}

async function enrollFixtureRepositoryOwners(home, roots, extraEnv = {}) {
  if (!Array.isArray(roots) || roots.length === 0) return;
  const ownerUid = process.getuid?.();
  if (!Number.isInteger(ownerUid) || ownerUid <= 0) {
    throw new Error('E2E repository owner authority requires a positive non-root UID');
  }
  const script = String.raw`
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from devcoordinator.repository_lifecycle import RepositoryLifecycle
from devcoordinator.schema import establish_repository_owner_authority
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import AccountStore, deterministic_id, utc_timestamp

home = Path(sys.argv[2])
owner_uid = int(sys.argv[3])
roots = json.loads(sys.argv[4])
with AccountStore.open_default(home) as store:
    host_id = store.ensure_local_host()
    for raw_root in roots:
        root = Path(raw_root).resolve(strict=True)
        marker = root / '.git'
        if not marker.exists() or marker.is_symlink():
            raise RuntimeError(f'fixture repository is not a canonical Git worktree: {root}')
        repository_id = deterministic_id('repository', host_id, str(root))
        timestamp = utc_timestamp()
        with store.immediate_transaction() as connection:
            existing = connection.execute(
                '''
                SELECT repository.repo_id, repository.generation,
                       owner.owner_uid, owner.repository_generation
                FROM repositories repository
                LEFT JOIN repository_owners owner USING(repo_id)
                WHERE repository.host_id = ? AND repository.canonical_root = ?
                ''',
                (host_id, str(root)),
            ).fetchone()
            if existing is None:
                connection.execute(
                    '''
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
                    ''',
                    (repository_id, host_id, str(root), root.name or str(root), timestamp, timestamp),
                )
                establish_repository_owner_authority(
                    connection,
                    repository_id=repository_id,
                    owner_uid=owner_uid,
                    repository_generation=0,
                    operation_id=str(uuid.uuid4()),
                    actor='devops-console-e2e-bootstrap',
                    reason='explicit E2E fixture repository enrollment',
                    timestamp=timestamp,
                    evidence={
                        'kind': 'devops-console-e2e-repository-owner',
                        'repository_id': repository_id,
                        'canonical_root': str(root),
                        'repository_generation': 0,
                        'owner_uid': owner_uid,
                    },
                )
            elif (
                str(existing['repo_id']) != repository_id
                or int(existing['owner_uid']) != owner_uid
                or int(existing['repository_generation']) != int(existing['generation'])
            ):
                raise RuntimeError(f'fixture repository owner authority conflicts for {root}')
        persistence = SQLiteLifecyclePersistence(store)
        with store.read_transaction() as connection:
            installed = connection.execute(
                'SELECT 1 FROM repository_installations WHERE repo_id = ?',
                (repository_id,),
            ).fetchone()
        if installed is None:
            RepositoryLifecycle(persistence, object()).install_repository(
                repository_id,
                actor='devops-console-e2e-bootstrap',
                reason='explicit E2E fixture repository enrollment',
                explicit=True,
            )
`;
  await execFileAsync(
    'python3',
    ['-c', script, path.dirname(COORDINATOR_SCRIPT), home, String(ownerUid), JSON.stringify(roots)],
    {
      env: { ...process.env, ...extraEnv, CODEX_AGENT_COORDINATOR_HOME: home },
      timeout: 60_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
}

async function initializeNormalizedCoordinator(
  home,
  extraEnv = {},
  { expectDocker = false, repositoryOwnerRoots = [] } = {},
) {
  // A production SQLite mutation deliberately discovers every eligible
  // same-UID legacy home before it establishes authority. E2E must not import
  // the developer/runner's real coordinator state, so create one exact,
  // isolated legacy source through the public compatibility CLI and name only
  // that source on the explicit normalized observation.
  const legacySeedHome = path.join(home, 'legacy-seed');
  const baseEnv = { ...process.env, ...extraEnv };
  await execFileAsync(
    'python3',
    [
      COORDINATOR_SCRIPT,
      'state',
      'reset',
      '--force',
      '--agent',
      'devops-console-e2e-bootstrap',
      '--project',
      REPO_ROOT,
    ],
    {
      env: {
        ...baseEnv,
        CODEX_AGENT_COORDINATOR_HOME: legacySeedHome,
        DEVCOORDINATOR_STATE_BACKEND: 'legacy-json-test-only',
      },
      timeout: 60_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );

  // Observation deliberately never invents execution ownership from Docker
  // labels or filesystem UID. Test Docker projects therefore use the same
  // explicit owner-authority boundary as production enrollment.
  await enrollFixtureRepositoryOwners(home, repositoryOwnerRoots, extraEnv);

  const observation = await runNormalizedObservation({
    home,
    extraEnv,
    legacySeedHome,
    agent: 'devops-console-e2e-bootstrap',
    project: REPO_ROOT,
  });

  const imported = observation?.imported;
  if (
    observation?.schema_version !== INVENTORY_WIRE_SCHEMA_VERSION
    || observation?.status !== 'completed'
    || observation?.observer_domain !== 'host-runtime-v2:full-docker'
    || imported?.committed !== true
    || imported?.source_count !== 1
    || imported?.blocking_conflict_count !== 0
  ) {
    throw new Error(
      `E2E coordinator bootstrap must commit one conflict-free legacy seed into a wire-schema-v${INVENTORY_WIRE_SCHEMA_VERSION} full-Docker observation: ${JSON.stringify(observation)}`,
    );
  }
  if (expectDocker && observation?.observed !== true) {
    throw new Error(`E2E fake Docker was not freshly observed: ${JSON.stringify(observation)}`);
  }
  return { observation, legacySeedHome };
}

async function assertNormalizedCoordinatorAuthority(coordinator, initialization, { expectDocker = false } = {}) {
  const inventory = await coordinator.api('GET', '/v1/inventory');
  const canonicalHome = await fsp.realpath(coordinator.home);
  const completedFullDockerSnapshot = (inventory?.observations?.snapshots || []).some(
    (snapshot) => snapshot?.observer_domain === 'host-runtime-v2:full-docker' && snapshot?.status === 'completed',
  );
  if (
    initialization?.observation?.imported?.blocking_conflict_count !== 0
    || inventory?.schema_version !== INVENTORY_WIRE_SCHEMA_VERSION
    || inventory?.store?.schema_version !== COORDINATOR_STORE_SCHEMA_VERSION
    || inventory?.store?.authority_mode !== 'sqlite'
    || inventory?.store?.migration_state !== 'ready'
    || inventory?.coordinator_home !== canonicalHome
    || inventory?.state_path !== path.join(canonicalHome, 'coordinator.sqlite3')
    || !completedFullDockerSnapshot
  ) {
    throw new Error(
      `E2E coordinator authority guard failed (expected inventory wire schema v${INVENTORY_WIRE_SCHEMA_VERSION}, store schema v${COORDINATOR_STORE_SCHEMA_VERSION}, sqlite/ready, no blocking migration conflicts, and one committed full-Docker snapshot): ${JSON.stringify({ initialization, inventory })}`,
    );
  }
  if (expectDocker && inventory?.docker?.available !== true) {
    throw new Error(`E2E fake Docker observation is unavailable in normalized inventory: ${JSON.stringify(inventory?.docker)}`);
  }
}

async function spawnCoordinator(
  home,
  extraEnv = {},
  { expectDocker = false, repositoryOwnerRoots = [] } = {},
) {
  const initialization = await initializeNormalizedCoordinator(home, extraEnv, {
    expectDocker,
    repositoryOwnerRoots,
  });
  const proc = spawn(
    'python3',
    [COORDINATOR_SCRIPT, 'api', 'serve', '--host', '127.0.0.1', '--port', '0'],
    {
      env: { ...process.env, CODEX_AGENT_COORDINATOR_HOME: home, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stderrTail = '';
  proc.stderr.on('data', (chunk) => {
    stderrTail = (stderrTail + chunk).slice(-16_384);
  });

  // Cold CI runners (macOS, 3 cores) start python noticeably slower while
  // node --test floods the box with parallel test files — allow a full
  // minute. CRITICAL: every failure path must kill the child. An orphaned
  // coordinator keeps this worker's stdio pipes open, which wedges the whole
  // `node --test` run until the CI job timeout (observed: a 29-minute silent
  // hang after a readiness timeout).
  let port;
  try {
    port = await new Promise((resolve, reject) => {
      let out = '';
      const timer = setTimeout(
        () => reject(new Error(
          `coordinator did not print readiness JSON in 60s; stdout: ${JSON.stringify(out.slice(0, 400))}; stderr: ${stderrTail}`,
        )),
        60_000,
      );
      timer.unref();
      proc.stdout.on('data', (chunk) => {
        out += chunk;
        const nl = out.indexOf('\n');
        if (nl === -1) return;
        clearTimeout(timer);
        try {
          const parsed = JSON.parse(out.slice(0, nl));
          if (!Number.isInteger(parsed.port) || parsed.port <= 0) {
            reject(new Error(`coordinator readiness line has no usable port: ${out.slice(0, nl)}`));
          } else {
            resolve(parsed.port);
          }
        } catch (err) {
          reject(new Error(`unparseable coordinator readiness line ${JSON.stringify(out.slice(0, nl))}: ${err}`));
        }
      });
      proc.on('exit', (code, signal) => {
        clearTimeout(timer);
        reject(new Error(`coordinator exited early (code=${code} signal=${signal}); stderr: ${stderrTail}`));
      });
      proc.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  } catch (err) {
    await stopProcess(proc);
    throw err;
  }

  const url = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const res = await fetch(`${url}/v1/ports`, { signal: AbortSignal.timeout(1000) });
      await res.arrayBuffer().catch(() => {});
      if (res.status === 200) break;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      await stopProcess(proc);
      throw new Error(`coordinator never answered /v1/ports; stderr: ${stderrTail}`);
    }
    await delay(100);
  }

  async function api(method, apiPath, body, { timeoutMs = 60_000 } = {}) {
    const headers = {};
    if (body != null) headers['content-type'] = 'application/json';
    const res = await fetch(url + apiPath, {
      method,
      headers,
      body: body != null ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
    if (res.status !== 200) {
      const err = new Error(`coordinator ${method} ${apiPath} -> HTTP ${res.status}: ${text.slice(0, 400)}`);
      err.status = res.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  async function observe({
    agent = 'devops-console-e2e-observer',
    project = REPO_ROOT,
  } = {}) {
    const result = await runNormalizedObservation({
      home,
      extraEnv,
      legacySeedHome: initialization.legacySeedHome,
      agent,
      project,
    });
    if (
      result?.schema_version !== INVENTORY_WIRE_SCHEMA_VERSION
      || result?.status !== 'completed'
      || result?.observer_domain !== 'host-runtime-v2:full-docker'
      || (result?.imported?.blocking_conflict_count ?? 0) !== 0
    ) {
      throw new Error(`E2E normalized observation failed its authority guard: ${JSON.stringify(result)}`);
    }
    return result;
  }

  const coordinator = { proc, port, url, home, api, observe };
  try {
    await assertNormalizedCoordinatorAuthority(coordinator, initialization, { expectDocker });
  } catch (err) {
    await stopProcess(proc);
    throw err;
  }
  return { ...coordinator, initialization };
}

async function stopProcess(proc) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = once(proc, 'exit');
  proc.kill('SIGTERM');
  const result = await Promise.race([exited.then(() => 'exited'), delay(3000).then(() => 'timeout')]);
  if (result === 'timeout') {
    proc.kill('SIGKILL');
    await exited.catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// The stack
// ---------------------------------------------------------------------------

/**
 * @param {object} options
 * @param {string[]} [options.allowedEmails]
 * @param {object}   [options.claims]  fixture issuer claims override
 * @param {object[]|Function} [options.routes]  routes seeded into
 *   <stateDir>/routes.json; may be a function of ({ issuer, upstream, wsEcho,
 *   coordinator }) so seeds can reference the fixtures' OS-assigned ports.
 * @param {object} [options.coordinatorEnv]  extra env for the coordinator
 *   process only (e.g. a PATH with a fake `docker` first).
 * @param {boolean} [options.expectDocker] require the supplied Docker fixture
 *   to be available in the committed normalized observation.
 * @param {string[]} [options.repositoryOwnerRoots] explicitly enrolled E2E
 *   repository roots needed by pre-existing observed resources.
 */
export async function startStack({
  domain = 'vr.ae',
  allowedEmails = ['ja@vr.ae'],
  claims,
  routes = [],
  coordinatorEnv = {},
  expectDocker = false,
  repositoryOwnerRoots = [],
} = {}) {
  ensureDevCert(); // fresh clones (CI) generate the throwaway TLS fixture
  const cleanups = []; // LIFO
  const runCleanups = async () => {
    for (const fn of cleanups.reverse()) {
      try {
        await fn();
      } catch {
        // best effort — never mask the original failure
      }
    }
  };

  try {
    const stateDir = await canonicalTempDir('devops-console-e2e-state-');
    cleanups.push(() => fsp.rm(stateDir, { recursive: true, force: true }));
    const coordHome = await canonicalTempDir('devops-console-e2e-coord-');
    cleanups.push(() => fsp.rm(coordHome, { recursive: true, force: true }));

    const issuer = await startIssuer({ clientId: 'test-client', clientSecret: 'test-secret', claims });
    cleanups.push(() => issuer.close());
    const upstream = await startUpstream();
    cleanups.push(() => upstream.close());
    const wsEcho = await startWsEcho();
    cleanups.push(() => wsEcho.close());

    const coordinator = await spawnCoordinator(coordHome, coordinatorEnv, {
      expectDocker,
      repositoryOwnerRoots,
    });
    cleanups.push(async () => {
      // Stop any servers the coordinator still manages (e.g. a test failed
      // between servers/start and servers/stop), then the coordinator itself.
      try {
        const servers = await coordinator.api('GET', '/v1/servers', null, { timeoutMs: 5000 });
        for (const server of Array.isArray(servers) ? servers : []) {
          if (server?.status === 'stopped') continue;
          await coordinator
            .api('POST', '/v1/servers/stop', {
              agent: 'e2e-cleanup',
              server_id: server.id,
              reason: 'test teardown',
            }, { timeoutMs: 15_000 })
            .catch(() => {});
        }
      } catch {
        // coordinator may already be gone
      }
      await stopProcess(coordinator.proc);
    });

    // Seed the route store file before the console loads it.
    const routeDefs = typeof routes === 'function' ? routes({ issuer, upstream, wsEcho, coordinator }) : routes;
    if (routeDefs.length > 0) {
      const now = new Date().toISOString();
      const routesObj = {};
      for (const route of routeDefs) {
        routesObj[route.slug] = { createdAt: now, updatedAt: now, auth: 'google', ...route };
      }
      await fsp.writeFile(
        path.join(stateDir, 'routes.json'),
        `${JSON.stringify({ version: 1, routes: routesObj }, null, 2)}\n`,
        'utf8',
      );
    }

    // Hermetic env file so the developer's real <appRoot>/.env cannot leak in.
    const envFile = path.join(stateDir, 'test.env');
    await fsp.writeFile(
      envFile,
      [
        `DOMAIN=${domain}`,
        // Semantic ports (non-zero keeps the plain HTTP redirect listener
        // enabled); actual binds are OS-assigned via listenPorts below.
        'HTTP_PORT=8080',
        'HTTPS_PORT=8443',
        `TLS_CERT_FILE=${DEV_CERT}`,
        `TLS_KEY_FILE=${DEV_KEY}`,
        'GOOGLE_CLIENT_ID=test-client',
        'GOOGLE_CLIENT_SECRET=test-secret',
        `OIDC_ISSUER=http://127.0.0.1:${issuer.port}`,
        `ALLOWED_EMAILS=${allowedEmails.join(',')}`,
        `SESSION_SECRET=${crypto.randomBytes(32).toString('hex')}`,
        `COORDINATOR_URL=http://127.0.0.1:${coordinator.port}`,
        'COORDINATOR_AUTOSTART=0',
        `CODEX_AGENT_COORDINATOR_HOME=${coordHome}`,
        `STATE_DIR=${stateDir}`,
        'LOG_LEVEL=error',
        '',
      ].join('\n'),
      'utf8',
    );

    const handle = await startConsole({
      envFile,
      env: {}, // block process.env so the run is fully hermetic
      overrides: { bindHost: '127.0.0.1' },
      listenPorts: { https: 0, http: 0 },
    });
    cleanups.push(() => handle.close());

    const httpsPort = handle.addresses.find((a) => a.name === 'https')?.port;
    const httpPort = handle.addresses.find((a) => a.name === 'http-redirect')?.port;
    if (!httpsPort || !httpPort) {
      throw new Error(`console did not report both listeners: ${JSON.stringify(handle.addresses)}`);
    }

    return {
      domain: handle.config.domain,
      consoleHost: handle.config.consoleHost,
      consoleOrigin: handle.config.consoleOrigin,
      httpsPort,
      httpPort,
      issuer,
      upstream,
      wsEcho,
      coordinator,
      handle,
      config: handle.config,
      stateDir,
      close: runCleanups,
    };
  } catch (err) {
    await runCleanups();
    throw err;
  }
}
