// Loopback client for the codex-dev-coordinator HTTP API (see
// docs/coordinator-http-api.json). Credentials are read only by this server-side
// client and are never exposed to browser JavaScript, URLs, or logs.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const DOCKER_ACTIONS = new Set(['start', 'stop', 'restart']);
const PROJECT_ACTIONS = new Set(['start', 'stop', 'restart']);
const TOKEN_MAX_BYTES = 4096;
const CONSOLE_INVENTORY_KEYS = Object.freeze([
  'coordinator_home',
  'state_path',
  'project',
  'urls',
  'servers',
  'leases',
  'port_assignments',
  'recent_events',
  'docker',
  'postgres',
  'backups',
  'project_usage',
]);

// Connection-level failure codes where the request never reached the
// coordinator, making a single retry after autostart safe even for mutations.
const RETRYABLE_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
]);

export class CoordError extends Error {
  constructor(message, { status = 0, body = null } = {}) {
    super(message);
    this.name = 'CoordError';
    this.status = status; // 0 = transport-level failure (unreachable/timeout)
    this.body = body;
  }
}

// Coordinator KeyError messages arrive with their Python quotes intact,
// e.g. {"error":"'agent'"} — strip matched surrounding quote pairs.
function cleanMessage(raw) {
  let msg = String(raw ?? '').trim();
  while (
    msg.length >= 2 &&
    ((msg.startsWith("'") && msg.endsWith("'")) ||
      (msg.startsWith('"') && msg.endsWith('"')))
  ) {
    msg = msg.slice(1, -1).trim();
  }
  return msg || 'coordinator error';
}

function timeoutFor(apiPath) {
  if (apiPath === '/v1/lifecycle/apply') return 600_000;
  if (apiPath.startsWith('/v1/lifecycle/')) return 300_000;
  if (apiPath.startsWith('/v1/projects/')) return 300_000; // compose up can run minutes
  if (apiPath === '/v1/inventory') return 60_000; // shells out to docker
  if (apiPath.startsWith('/v1/docker/')) return 60_000;
  return 15_000;
}

function failureCode(err) {
  const seen = new Set();
  const stack = [err];
  while (stack.length > 0) {
    const e = stack.pop();
    if (!e || typeof e !== 'object' || seen.has(e)) continue;
    seen.add(e);
    if (typeof e.code === 'string' && e.code) return e.code;
    if (e.cause) stack.push(e.cause);
    if (Array.isArray(e.errors)) stack.push(...e.errors);
  }
  return null;
}

// Schema v2 keeps normalized identities at the top level and isolates the
// legacy Console read model under v1_compatibility. Existing Console journeys
// deliberately consume that declared projection: overlay only its known keys
// into a new view, retaining the normalized graph as non-conflicting evidence
// and never mutating the cached wire response.
function consoleInventoryView(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schema_version !== 2) {
    return value;
  }
  const compatibility = value.v1_compatibility;
  if (!compatibility || typeof compatibility !== 'object' || Array.isArray(compatibility)) {
    throw new CoordError('coordinator schema-v2 inventory compatibility projection is incomplete', {
      status: 502,
    });
  }
  const missing = CONSOLE_INVENTORY_KEYS.filter(
    (key) => !Object.prototype.hasOwnProperty.call(compatibility, key),
  );
  if (missing.length > 0) {
    throw new CoordError('coordinator schema-v2 inventory compatibility projection is incomplete', {
      status: 502,
    });
  }
  const projected = { ...value };
  for (const key of CONSOLE_INVENTORY_KEYS) projected[key] = compatibility[key];
  return projected;
}

export function createCoordinator({ config, log }) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'coordinator' }) : log;
  const baseUrl = String(config.coordinatorUrl).replace(/\/+$/, '');

  const pendingAborts = new Set();
  let closed = false;

  let ok = false;
  let autostarted = false;
  let lastError = null;
  let lastOkAt = null;
  let lastSpawnAt = 0; // autostart rate limit: max one spawn attempt per 30s
  let ensureInflight = null;

  const invCache = { value: undefined, at: 0, inflight: null, generation: 0 };
  const srvCache = { value: undefined, at: 0, inflight: null, generation: 0 };

  function noteAlive() {
    ok = true;
    lastOkAt = new Date().toISOString();
    lastError = null;
  }

  function noteDown(err) {
    ok = false;
    lastError = err?.message ? String(err.message) : String(err);
  }

  function autostartLogPath() {
    return path.join(config.stateDir, 'logs', 'coordinator-api.log');
  }

  function readToken() {
    const tokenFile = String(config.coordinatorTokenFile || '').trim();
    if (!tokenFile) return null;
    const noFollow = fs.constants.O_NOFOLLOW;
    if (!Number.isInteger(noFollow) || noFollow <= 0) {
      throw new CoordError('coordinator credential cannot be opened safely on this platform', {
        status: 503,
      });
    }

    // Open the caller-named path once and inspect/read that descriptor. A
    // separate lstat(path) followed by readFile(path) lets the final component
    // be replaced with a symlink between validation and use. O_NONBLOCK keeps
    // a malicious FIFO from hanging this server-side request path.
    const flags = fs.constants.O_RDONLY | noFollow | (fs.constants.O_NONBLOCK ?? 0);
    let fd = null;
    try {
      fd = fs.openSync(tokenFile, flags);
    } catch (err) {
      if (err?.code === 'ENOENT') return null;
      if (err?.code === 'ELOOP') {
        throw new CoordError('coordinator credential must be a regular non-symlink file', { status: 503 });
      }
      throw new CoordError(`coordinator credential cannot be opened: ${err?.code ?? err?.message ?? err}`, {
        status: 503,
      });
    }

    try {
      const before = fs.fstatSync(fd);
      if (!before.isFile()) {
        throw new CoordError('coordinator credential must be a regular non-symlink file', { status: 503 });
      }
      if ((before.mode & 0o777) !== 0o600) {
        throw new CoordError('coordinator credential permissions are unsafe; expected mode 0600', { status: 503 });
      }
      if (before.size > TOKEN_MAX_BYTES) {
        throw new CoordError('coordinator credential file is oversized', { status: 503 });
      }

      const bytes = Buffer.alloc(TOKEN_MAX_BYTES + 1);
      let length = 0;
      while (length < bytes.length) {
        const count = fs.readSync(fd, bytes, length, bytes.length - length, null);
        if (count === 0) break;
        length += count;
      }
      if (length > TOKEN_MAX_BYTES) {
        throw new CoordError('coordinator credential file is oversized', { status: 503 });
      }

      const after = fs.fstatSync(fd);
      if (
        !after.isFile()
        || after.dev !== before.dev
        || after.ino !== before.ino
        || after.size !== before.size
        || after.size !== length
      ) {
        throw new CoordError('coordinator credential changed while being read', { status: 503 });
      }
      if ((after.mode & 0o777) !== 0o600) {
        throw new CoordError('coordinator credential permissions are unsafe; expected mode 0600', { status: 503 });
      }

      const token = bytes.subarray(0, length).toString('utf8').trim();
      if (token.length < 32) {
        throw new CoordError('coordinator credential is empty or too short', { status: 503 });
      }
      return token;
    } catch (err) {
      if (err instanceof CoordError) throw err;
      throw new CoordError(`coordinator credential cannot be read: ${err?.code ?? err?.message ?? err}`, {
        status: 503,
      });
    } finally {
      fs.closeSync(fd);
    }
  }

  async function fetchJson(method, apiPath, body, timeoutMs) {
    const ac = new AbortController();
    pendingAborts.add(ac);
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      let res;
      try {
        const token = apiPath.startsWith('/v1/') ? readToken() : null;
        const headers = {};
        if (body != null) headers['content-type'] = 'application/json';
        if (token) headers.authorization = `Bearer ${token}`;
        res = await fetch(baseUrl + apiPath, {
          method,
          headers: Object.keys(headers).length ? headers : undefined,
          body: body == null ? undefined : JSON.stringify(body),
          signal: ac.signal,
        });
      } catch (err) {
        if (err instanceof CoordError) {
          noteDown(err);
          throw err;
        }
        let coordErr;
        if (ac.signal.aborted) {
          coordErr = new CoordError(
            `coordinator request timed out after ${timeoutMs}ms (${method} ${apiPath})`,
          );
        } else {
          const code = failureCode(err);
          coordErr = new CoordError(
            `coordinator unreachable at ${baseUrl}: ${code ?? err?.message ?? err}`,
          );
          coordErr.retryable = code !== null && RETRYABLE_CODES.has(code);
        }
        coordErr.cause = err;
        noteDown(coordErr);
        throw coordErr;
      }
      let text = '';
      try {
        text = await res.text();
      } catch (err) {
        const coordErr = new CoordError(
          `coordinator response read failed (${method} ${apiPath}): ${err?.message ?? err}`,
        );
        coordErr.cause = err;
        noteDown(coordErr);
        throw coordErr;
      }
      let data = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
      }
      if (res.status !== 200) {
        const raw =
          data && typeof data === 'object' && typeof data.error === 'string'
            ? data.error
            : `coordinator returned HTTP ${res.status}`;
        const message = res.status === 401
          ? 'coordinator authentication failed; verify COORDINATOR_TOKEN_FILE'
          : cleanMessage(raw);
        const coordErr = new CoordError(message, { status: res.status, body: data });
        if (res.status === 401) noteDown(coordErr);
        else noteAlive();
        throw coordErr;
      }
      noteAlive();
      return data;
    } finally {
      clearTimeout(timer);
      pendingAborts.delete(ac);
    }
  }

  async function attempt(method, apiPath, body, timeoutMs) {
    try {
      return await fetchJson(method, apiPath, body, timeoutMs);
    } catch (err) {
      const canRetry =
        err instanceof CoordError && err.status === 0 && err.retryable === true && !closed;
      if (!canRetry) throw err;
      // Lazy autostart on connection failure (rate-limited inside).
      const revived = await ensureRunning();
      if (!revived.ok) throw err;
      return fetchJson(method, apiPath, body, timeoutMs);
    }
  }

  function invalidateCaches() {
    for (const cache of [invCache, srvCache]) {
      cache.generation += 1;
      cache.value = undefined;
      cache.at = 0;
      // Detach an older GET instead of returning it to a caller that asked
      // after the mutation committed. The request may finish normally, but
      // its captured generation prevents it from repopulating this cache.
      cache.inflight = null;
    }
  }

  // Every POST except log reads mutates coordinator state (leases, servers,
  // docker). Cached inventory/servers snapshots must not outlive a mutation,
  // or the UI shows pre-mutation state until the cache window expires.
  function isMutation(method, apiPath) {
    return method !== 'GET' && !apiPath.endsWith('/logs');
  }

  async function request(method, apiPath, body, { timeoutMs } = {}) {
    if (closed) throw new CoordError('coordinator client is closed');
    const ms = timeoutMs ?? timeoutFor(apiPath);
    const result = await attempt(method, apiPath, body ?? null, ms);
    if (isMutation(method, apiPath)) invalidateCaches();
    return result;
  }

  // Liveness is intentionally anonymous and independent of credential state.
  async function probe() {
    try {
      const res = await fetch(`${baseUrl}/healthz`, {
        method: 'GET',
        signal: AbortSignal.timeout(2000),
      });
      await res.arrayBuffer().catch(() => {});
      if (res.status === 200) {
        noteAlive();
        return true;
      }
      return false;
    } catch (err) {
      noteDown(new CoordError(`coordinator probe failed: ${failureCode(err) ?? err?.message ?? err}`));
      return false;
    }
  }

  function spawnCoordinator() {
    const url = new URL(config.coordinatorUrl);
    const port = url.port || (url.protocol === 'https:' ? '443' : '80');
    const logFile = autostartLogPath();
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const outFd = fs.openSync(logFile, 'a');
    const env = { ...process.env };
    if (config.coordinatorHome) env.CODEX_AGENT_COORDINATOR_HOME = config.coordinatorHome;
    let child;
    try {
      const args = [
        config.coordinatorScript,
        'api',
        'serve',
        '--host',
        '127.0.0.1',
        '--port',
        String(port),
      ];
      if (config.coordinatorTokenFile) args.push('--token-file', config.coordinatorTokenFile);
      child = spawn(
        'python3',
        args,
        { detached: true, stdio: ['ignore', outFd, outFd], env },
      );
    } finally {
      // spawn dups the fd; our copy is no longer needed.
      fs.closeSync(outFd);
    }
    child.on('error', (err) => {
      ok = false;
      lastError = `coordinator autostart process error: ${err?.message ?? err}`;
      clog?.warn?.('coordinator autostart process error', { error: String(err?.message ?? err) });
    });
    child.unref();
    return child;
  }

  async function ensureRunningInner() {
    if (closed) return { ok: false, autostarted: false, error: 'coordinator client is closed' };
    if (await probe()) return { ok: true, autostarted: false };
    if (!config.coordinatorAutostart) {
      return {
        ok: false,
        autostarted: false,
        error: lastError ?? 'coordinator is not running and autostart is disabled',
      };
    }
    const now = Date.now();
    if (now - lastSpawnAt < 30_000) {
      return {
        ok: false,
        autostarted: false,
        error: 'coordinator is not running; autostart was already attempted in the last 30s',
      };
    }
    lastSpawnAt = now;
    let child;
    try {
      child = spawnCoordinator();
    } catch (err) {
      const msg = `coordinator autostart failed: ${err?.message ?? err}`;
      ok = false;
      lastError = msg;
      clog?.error?.('coordinator autostart spawn failed', { error: String(err?.message ?? err) });
      return { ok: false, autostarted: false, error: msg };
    }
    autostarted = true;
    clog?.info?.('coordinator autostarted', {
      pid: child.pid ?? null,
      port: new URL(config.coordinatorUrl).port || null,
      log: autostartLogPath(),
    });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      await delay(500);
      if (closed) return { ok: false, autostarted: true, error: 'coordinator client is closed' };
      if (await probe()) return { ok: true, autostarted: true };
    }
    const msg = `coordinator did not become ready within 15s after autostart (log: ${autostartLogPath()})`;
    ok = false;
    lastError = msg;
    return { ok: false, autostarted: true, error: msg };
  }

  function ensureRunning() {
    if (!ensureInflight) {
      ensureInflight = ensureRunningInner().finally(() => {
        ensureInflight = null;
      });
    }
    return ensureInflight;
  }

  function cachedGet(cache, apiPath, maxAgeMs) {
    if (cache.value !== undefined && Date.now() - cache.at <= maxAgeMs) {
      return Promise.resolve(cache.value);
    }
    if (cache.inflight) return cache.inflight; // coalesce concurrent callers
    const generation = cache.generation;
    const inflight = request('GET', apiPath)
      .then((value) => {
        if (cache.generation === generation) {
          cache.value = value;
          cache.at = Date.now();
        }
        return value;
      })
      .finally(() => {
        if (cache.inflight === inflight) cache.inflight = null;
      });
    cache.inflight = inflight;
    return inflight;
  }

  function inventory({ maxAgeMs = 5000 } = {}) {
    return cachedGet(invCache, '/v1/inventory', maxAgeMs).then(consoleInventoryView);
  }

  function serversRaw({ maxAgeMs = 3000 } = {}) {
    return cachedGet(srvCache, '/v1/servers', maxAgeMs);
  }

  function events({ after = null, limit = 100 } = {}) {
    if (after !== null && (typeof after !== 'string' || !after || after.length > 1024)) {
      throw new CoordError('event cursor must be a bounded non-empty string', { status: 400 });
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      throw new CoordError('event limit must be an integer from 1 through 500', { status: 400 });
    }
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== null) query.set('after', after);
    return request('GET', `/v1/events?${query.toString()}`);
  }

  async function dockerAction(name, action, body = {}) {
    // Defense in depth for the "fixed endpoint set" invariant: only these
    // three container actions may form a coordinator path.
    if (!DOCKER_ACTIONS.has(action)) {
      throw new CoordError(`unsupported docker action '${action}'`, { status: 400 });
    }
    return request('POST', `/v1/docker/${action}`, { container: name, ...body });
  }

  async function projectAction(action, body = {}) {
    // Same invariant: only the three whole-project runtime verbs form a path.
    if (!PROJECT_ACTIONS.has(action)) {
      throw new CoordError(`unsupported project action '${action}'`, { status: 400 });
    }
    const result = await request('POST', `/v1/projects/${action}`, body);
    if (result?.ok === false) {
      const details = Array.isArray(result.action_errors)
        ? result.action_errors
          .map((item) => item?.error || item?.classification || item?.name)
          .filter(Boolean)
          .join('; ')
        : '';
      const state = result.partial ? 'partially completed' : result.preflight_failed ? 'failed preflight' : 'failed';
      throw new CoordError(
        `project ${action} ${state}: ${details || result.classification || 'coordinator reported failure'}`,
        { status: 409, body: result },
      );
    }
    return result;
  }

  function lifecycleResult(action, result) {
    const status = String(result?.status ?? '').toLowerCase();
    const failedStatus = new Set(['blocked', 'failed', 'needs_attention', 'partial']);
    if (
      result?.ok === false
      || result?.partial === true
      || result?.needs_attention === true
      || failedStatus.has(status)
    ) {
      const errors = Array.isArray(result?.action_errors)
        ? result.action_errors
          .map((item) => item?.error || item?.message || item?.classification || item?.name)
          .filter(Boolean)
        : [];
      if (Array.isArray(result?.errors)) {
        errors.push(...result.errors
          .map((item) => typeof item === 'string' ? item : item?.error || item?.message || item?.code)
          .filter(Boolean));
      }
      const blockers = Array.isArray(result?.blockers)
        ? result.blockers
          .map((item) => typeof item === 'string' ? item : item?.message || item?.error || item?.code)
          .filter(Boolean)
        : [];
      throw new CoordError(
        `lifecycle ${action} ${status || 'failed'}: ${[...errors, ...blockers].join('; ') || 'coordinator reported incomplete work'}`,
        { status: 409, body: result },
      );
    }
    return result;
  }

  function status() {
    return { ok, url: baseUrl, autostarted, lastError, lastOkAt };
  }

  function close() {
    closed = true;
    for (const ac of pendingAborts) ac.abort();
    pendingAborts.clear();
  }

  return {
    ensureRunning,
    probe,
    inventory,
    serversRaw,
    events,
    observeHost: (b = {}) => request('POST', '/v1/observe', b),
    request,
    leasePort: (b = {}) => request('POST', '/v1/ports/lease', b),
    releasePort: (b = {}) => request('POST', '/v1/ports/release', b),
    unassignPort: (b = {}) => request('POST', '/v1/ports/unassign', b),
    serverStart: (b = {}) => request('POST', '/v1/servers/start', b),
    serverStop: (b = {}) => request('POST', '/v1/servers/stop', b),
    serverRestart: (b = {}) => request('POST', '/v1/servers/restart', b),
    serverLogs: (b = {}) => request('POST', '/v1/servers/logs', b),
    serverRegister: (b = {}) => request('POST', '/v1/servers/register', b),
    dockerAction,
    projectAction,
    projectStatus: (b = {}) => request('POST', '/v1/projects/status', b),
    dockerLogs: (b = {}) => request('POST', '/v1/docker/logs', b),
    lifecycleArchives: () => request('GET', '/v1/archives'),
    lifecyclePlan: (b = {}) => request('POST', '/v1/lifecycle/plan', b),
    lifecycleApply: async (b = {}) => lifecycleResult(
      'apply', await request('POST', '/v1/lifecycle/apply', b),
    ),
    lifecycleRestore: async (b = {}) => lifecycleResult(
      'restore', await request('POST', '/v1/lifecycle/restore', b),
    ),
    status,
    close,
  };
}
