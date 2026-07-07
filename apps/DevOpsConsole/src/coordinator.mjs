// Loopback client for the codex-dev-coordinator HTTP API (see
// docs/coordinator-http-api.json). The coordinator takes an exclusive file
// lock around every request, so all calls serialize through an internal FIFO
// queue here — issuing them in parallel would only pile them up server-side.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const DOCKER_ACTIONS = new Set(['start', 'stop', 'restart']);
const PROJECT_ACTIONS = new Set(['start', 'stop', 'restart']);

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

export function createCoordinator({ config, log }) {
  const clog = typeof log?.child === 'function' ? log.child({ mod: 'coordinator' }) : log;
  const baseUrl = String(config.coordinatorUrl).replace(/\/+$/, '');

  let queue = Promise.resolve();
  const pendingAborts = new Set();
  let closed = false;

  let ok = false;
  let autostarted = false;
  let lastError = null;
  let lastOkAt = null;
  let lastSpawnAt = 0; // autostart rate limit: max one spawn attempt per 30s
  let ensureInflight = null;

  const invCache = { value: undefined, at: 0, inflight: null };
  const srvCache = { value: undefined, at: 0, inflight: null };

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

  async function fetchJson(method, apiPath, body, timeoutMs) {
    const ac = new AbortController();
    pendingAborts.add(ac);
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    try {
      let res;
      try {
        res = await fetch(baseUrl + apiPath, {
          method,
          headers: body == null ? undefined : { 'content-type': 'application/json' },
          body: body == null ? undefined : JSON.stringify(body),
          signal: ac.signal,
        });
      } catch (err) {
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
      // Any HTTP response — including a 400 — means the coordinator is alive.
      noteAlive();
      if (res.status !== 200) {
        const raw =
          data && typeof data === 'object' && typeof data.error === 'string'
            ? data.error
            : `coordinator returned HTTP ${res.status}`;
        throw new CoordError(cleanMessage(raw), { status: res.status, body: data });
      }
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

  function enqueue(task) {
    const run = queue.then(task, task);
    queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function invalidateCaches() {
    invCache.value = undefined;
    invCache.at = 0;
    srvCache.value = undefined;
    srvCache.at = 0;
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
    const result = await enqueue(() => attempt(method, apiPath, body ?? null, ms));
    if (isMutation(method, apiPath)) invalidateCaches();
    return result;
  }

  // Liveness probe. Deliberately NOT routed through the FIFO queue: it must
  // answer within 2s even while a long queued call (projects/* up to 300s)
  // is in flight, and ensureRunning() polls it from inside queue tasks.
  async function probe() {
    try {
      const res = await fetch(`${baseUrl}/v1/ports`, {
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
      child = spawn(
        'python3',
        [config.coordinatorScript, 'api', 'serve', '--host', '127.0.0.1', '--port', String(port)],
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
    cache.inflight = request('GET', apiPath)
      .then((value) => {
        cache.value = value;
        cache.at = Date.now();
        return value;
      })
      .finally(() => {
        cache.inflight = null;
      });
    return cache.inflight;
  }

  function inventory({ maxAgeMs = 5000 } = {}) {
    return cachedGet(invCache, '/v1/inventory', maxAgeMs);
  }

  function serversRaw({ maxAgeMs = 3000 } = {}) {
    return cachedGet(srvCache, '/v1/servers', maxAgeMs);
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
    return request('POST', `/v1/projects/${action}`, body);
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
    status,
    close,
  };
}
