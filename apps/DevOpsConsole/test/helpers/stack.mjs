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

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

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
export async function apiCall(stack, jar, method, apiPath, body, extraHeaders = {}) {
  const res = await fetchUrl(stack, `${stack.consoleOrigin}${apiPath}`, {
    method,
    jar,
    headers: {
      accept: 'application/json',
      ...(body != null ? { 'content-type': 'application/json' } : {}),
      ...extraHeaders,
    },
    body: body != null ? JSON.stringify(body) : undefined,
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

async function spawnCoordinator(home) {
  const proc = spawn(
    'python3',
    [COORDINATOR_SCRIPT, 'api', 'serve', '--host', '127.0.0.1', '--port', '0'],
    {
      env: { ...process.env, CODEX_AGENT_COORDINATOR_HOME: home },
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
    const res = await fetch(url + apiPath, {
      method,
      headers: body != null ? { 'content-type': 'application/json' } : undefined,
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

  return { proc, port, url, home, api };
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
 */
export async function startStack({ allowedEmails = ['ja@vr.ae'], claims, routes = [] } = {}) {
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
    const stateDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-state-'));
    cleanups.push(() => fsp.rm(stateDir, { recursive: true, force: true }));
    const coordHome = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-coord-'));
    cleanups.push(() => fsp.rm(coordHome, { recursive: true, force: true }));

    const issuer = await startIssuer({ clientId: 'test-client', clientSecret: 'test-secret', claims });
    cleanups.push(() => issuer.close());
    const upstream = await startUpstream();
    cleanups.push(() => upstream.close());
    const wsEcho = await startWsEcho();
    cleanups.push(() => wsEcho.close());

    const coordinator = await spawnCoordinator(coordHome);
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
        'DOMAIN=vr.ae',
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
