// .env parsing + validation. Throws AggregateError listing ALL problems so the
// operator can fix the whole file in one pass. Missing Google OAuth credentials
// are intentionally NOT an error (degraded mode: app boots, proxies public
// routes, and /auth/login shows setup instructions).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

// appRoot = directory above src/
const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function resolveConfiguredPath(value) {
  const raw = String(value);
  const expanded = raw === '~'
    ? os.homedir()
    : raw.startsWith('~/')
      ? path.join(os.homedir(), raw.slice(2))
      : raw;
  return path.resolve(APP_ROOT, expanded);
}

const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const COOKIE_NAME_RE = /^[A-Za-z0-9_-]+$/;

export class ConfigError extends Error {
  constructor(key, message) {
    super(key ? `${key} ${message}` : message);
    this.name = 'ConfigError';
    this.key = key ?? null;
  }
}

// KEY=VALUE lines; `#` comment lines; blank lines; values may be single- or
// double-quoted; no interpolation, no escape processing.
function parseEnvText(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    out[match[1]] = value;
  }
  return out;
}

function gitToplevel(startDir) {
  try {
    const out = execFileSync('git', ['-C', startDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      timeout: 3000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return out || null;
  } catch {
    return null;
  }
}

export function loadConfig({ envFile, env = process.env, initializeRuntimePaths = true } = {}) {
  const problems = [];
  const fail = (key, message) => problems.push(new ConfigError(key, message));

  const resolvedEnvFile = envFile ? path.resolve(envFile) : path.join(APP_ROOT, '.env');
  let fileVars = {};
  if (fs.existsSync(resolvedEnvFile)) {
    try {
      fileVars = parseEnvText(fs.readFileSync(resolvedEnvFile, 'utf8'));
    } catch (err) {
      fail(null, `cannot read env file ${resolvedEnvFile}: ${err.message}`);
    }
  } else if (envFile) {
    // An explicitly requested env file that does not exist is an operator error;
    // a missing default .env just means "configure via process.env".
    fail(null, `env file not found: ${resolvedEnvFile}`);
  }

  // process.env wins over the file.
  const get = (key) => {
    const fromEnv = env[key];
    const raw = fromEnv !== undefined ? fromEnv : fileVars[key];
    return typeof raw === 'string' ? raw.trim() : '';
  };

  // systemd credentials stay out of both the process environment and the
  // generated non-secret Console configuration.  Only explicitly supported
  // secrets may use the KEY_FILE convention; the referenced file must be a
  // bounded, non-replaceable regular file.
  const getCredential = (key) => {
    const direct = get(key);
    if (direct) return direct;
    const file = get(`${key}_FILE`);
    if (!file) return '';
    if (!path.isAbsolute(file)) {
      fail(`${key}_FILE`, 'must be an absolute systemd credential path');
      return '';
    }
    try {
      const info = fs.lstatSync(file);
      if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > 64 * 1024) {
        throw new Error('credential must be one bounded regular file');
      }
      return fs.readFileSync(file, 'utf8').trim();
    } catch (error) {
      fail(`${key}_FILE`, `cannot be read safely: ${error.message}`);
      return '';
    }
  };

  // --- domain / hosts ------------------------------------------------------
  const rawDomain = get('DOMAIN');
  let domain = '';
  if (!rawDomain) {
    fail('DOMAIN', 'is required (e.g. DOMAIN=vr.ae)');
  } else {
    domain = rawDomain.toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '');
    if (!DOMAIN_RE.test(domain)) {
      fail('DOMAIN', `is not a valid DNS name: ${rawDomain}`);
      domain = '';
    }
  }

  const consoleSubdomain = (get('CONSOLE_SUBDOMAIN') || 'console').toLowerCase();
  if (!DNS_LABEL_RE.test(consoleSubdomain)) {
    fail('CONSOLE_SUBDOMAIN', `is not a valid DNS label: ${get('CONSOLE_SUBDOMAIN')}`);
  }

  // --- listeners -----------------------------------------------------------
  const parsePort = (key, fallback, { allowZero }) => {
    const raw = get(key);
    if (!raw) return fallback;
    if (!/^\d{1,5}$/.test(raw)) {
      fail(key, `must be an integer port: ${raw}`);
      return fallback;
    }
    const n = Number(raw);
    if (n > 65535 || (!allowZero && n === 0)) {
      fail(key, `is out of range: ${raw}`);
      return fallback;
    }
    return n;
  };

  const httpPort = parsePort('HTTP_PORT', 80, { allowZero: true });
  const httpsPort = parsePort('HTTPS_PORT', 443, { allowZero: false });
  const devInsecureHttp = get('DEV_HTTP') === '1';
  if (devInsecureHttp && httpPort === 0) {
    fail('HTTP_PORT', 'must be > 0 when DEV_HTTP=1 (it is the only listener)');
  }

  // --- TLS -----------------------------------------------------------------
  const rawCert = get('TLS_CERT_FILE');
  const rawKey = get('TLS_KEY_FILE');
  const tlsCertFile = rawCert ? resolveConfiguredPath(rawCert) : null;
  const tlsKeyFile = rawKey ? resolveConfiguredPath(rawKey) : null;
  if (!devInsecureHttp) {
    for (const [key, raw, resolved] of [
      ['TLS_CERT_FILE', rawCert, tlsCertFile],
      ['TLS_KEY_FILE', rawKey, tlsKeyFile],
    ]) {
      if (!raw) {
        fail(key, 'is required unless DEV_HTTP=1');
        continue;
      }
      try {
        fs.accessSync(resolved, fs.constants.R_OK);
      } catch {
        fail(key, `is not readable: ${resolved}`);
      }
    }
  }

  // --- auth ----------------------------------------------------------------
  // Degraded mode: empty clientId/clientSecret is allowed by design.
  const google = {
    clientId: getCredential('GOOGLE_CLIENT_ID'),
    clientSecret: getCredential('GOOGLE_CLIENT_SECRET'),
  };

  let oidcIssuer = get('OIDC_ISSUER') || 'https://accounts.google.com';
  try {
    const u = new URL(oidcIssuer);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('bad scheme');
    oidcIssuer = oidcIssuer.replace(/\/+$/, '');
  } catch {
    fail('OIDC_ISSUER', `must be an http(s) URL: ${oidcIssuer}`);
  }

  const allowedEmails = new Set(
    (get('ALLOWED_EMAILS') || '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean),
  );

  const rawSecret = getCredential('SESSION_SECRET');
  let sessionSecret = null;
  if (!rawSecret) {
    fail('SESSION_SECRET', 'is required (64 hex chars; generate with: openssl rand -hex 32)');
  } else if (!/^[0-9a-fA-F]{64}$/.test(rawSecret)) {
    fail('SESSION_SECRET', 'must be exactly 64 hex characters');
  } else {
    sessionSecret = Buffer.from(rawSecret, 'hex');
  }

  let sessionTtlMs = 168 * 3_600_000;
  const rawTtl = get('SESSION_TTL_HOURS');
  if (rawTtl) {
    const hours = Number(rawTtl);
    if (!Number.isFinite(hours) || hours <= 0) {
      fail('SESSION_TTL_HOURS', `must be a positive number of hours: ${rawTtl}`);
    } else {
      sessionTtlMs = Math.round(hours * 3_600_000);
    }
  }

  const cookieName = get('SESSION_COOKIE_NAME') || 'dc_session';
  if (!COOKIE_NAME_RE.test(cookieName)) {
    fail('SESSION_COOKIE_NAME', `contains invalid characters: ${cookieName}`);
  }

  // --- coordinator ---------------------------------------------------------
  let coordinatorUrl = get('COORDINATOR_URL') || 'http://127.0.0.1:29876';
  try {
    const u = new URL(coordinatorUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('bad scheme');
    if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') {
      throw new Error('coordinator must be loopback');
    }
    if (u.username || u.password || u.search || u.hash || (u.pathname && u.pathname !== '/')) {
      throw new Error('coordinator URL must name the loopback origin only');
    }
    coordinatorUrl = coordinatorUrl.replace(/\/+$/, '');
  } catch {
    fail('COORDINATOR_URL', `must be a loopback http(s) origin: ${coordinatorUrl}`);
  }

  const rawAutostart = get('COORDINATOR_AUTOSTART');
  const coordinatorAutostart = !(rawAutostart === '0' || rawAutostart.toLowerCase() === 'false');
  const retainedInventory = get('COORDINATOR_RETAINED_INVENTORY') === '1';

  // Stable-edge publication is enabled only for replaceable production
  // Console slots. Development/test instances keep serving their own edge
  // unless an explicit Unix socket is supplied. Production marks the
  // dependency required so a missing socket cannot silently acknowledge a
  // route/access mutation that never became live.
  const rawPublicationRequired = get('DEVCOORDINATOR_EDGE_PUBLICATION_REQUIRED').toLowerCase();
  let edgePublicationRequired = false;
  if (rawPublicationRequired === '1' || rawPublicationRequired === 'true') {
    edgePublicationRequired = true;
  } else if (
    rawPublicationRequired
    && rawPublicationRequired !== '0'
    && rawPublicationRequired !== 'false'
  ) {
    fail('DEVCOORDINATOR_EDGE_PUBLICATION_REQUIRED', 'must be exactly 1, true, 0, or false');
  }
  const edgePublicationSocket = get('DEVCOORDINATOR_EDGE_PUBLICATION_SOCKET');
  if (edgePublicationSocket && (!path.isAbsolute(edgePublicationSocket) || /[\0\r\n]/.test(edgePublicationSocket))) {
    fail('DEVCOORDINATOR_EDGE_PUBLICATION_SOCKET', 'must be one absolute Unix socket path');
  }
  if (edgePublicationRequired && !edgePublicationSocket) {
    fail('DEVCOORDINATOR_EDGE_PUBLICATION_SOCKET', 'is required when stable-edge publication is required');
  }
  const edgeReleaseRoot = get('DEVCOORDINATOR_EDGE_RELEASE_ROOT') || '/opt/devcoordinator/releases';
  if (!path.isAbsolute(edgeReleaseRoot) || /[\0\r\n]/.test(edgeReleaseRoot)) {
    fail('DEVCOORDINATOR_EDGE_RELEASE_ROOT', 'must be one absolute directory');
  }
  let edgePublicationTimeoutMs = 5_000;
  const rawEdgePublicationTimeout = get('DEVCOORDINATOR_EDGE_PUBLICATION_TIMEOUT_MS');
  if (rawEdgePublicationTimeout) {
    const timeout = Number(rawEdgePublicationTimeout);
    if (!Number.isInteger(timeout) || timeout < 100 || timeout > 30_000) {
      fail('DEVCOORDINATOR_EDGE_PUBLICATION_TIMEOUT_MS', 'must be an integer from 100 through 30000');
    } else {
      edgePublicationTimeoutMs = timeout;
    }
  }

  const projectRoot = gitToplevel(APP_ROOT) || APP_ROOT;
  const coordinatorScript = resolveConfiguredPath(
    get('COORDINATOR_SCRIPT') ||
      path.join(projectRoot, 'skills', 'codex-dev-coordinator', 'scripts', 'dev_coordinator.py'),
  );
  const coordinatorHome = get('CODEX_AGENT_COORDINATOR_HOME') || null;

  // How often the console samples coordinator inventory for CPU/memory
  // history charts. Every sample can shell out to `docker stats` inside the
  // coordinator, so the floor is 2 seconds.
  let metricsIntervalMs = 10_000;
  const rawMetricsInterval = get('METRICS_INTERVAL_MS');
  if (rawMetricsInterval) {
    const ms = Number(rawMetricsInterval);
    if (!Number.isFinite(ms) || ms < 2000) {
      fail('METRICS_INTERVAL_MS', `must be a number of milliseconds >= 2000: ${rawMetricsInterval}`);
    } else {
      metricsIntervalMs = Math.round(ms);
    }
  }

  // Destructive cleanup is a separately activated broker capability. Console
  // ownership alone must never imply that archive/restore/purge grants and
  // their production migration are ready.
  const rawLifecycleEnabled = get('LIFECYCLE_ENABLED').toLowerCase();
  let lifecycleEnabled = false;
  if (rawLifecycleEnabled === '1' || rawLifecycleEnabled === 'true') {
    lifecycleEnabled = true;
  } else if (
    rawLifecycleEnabled
    && rawLifecycleEnabled !== '0'
    && rawLifecycleEnabled !== 'false'
  ) {
    fail('LIFECYCLE_ENABLED', 'must be exactly 1, true, 0, or false');
  }

  // --- misc ----------------------------------------------------------------
  const stateDir = resolveConfiguredPath(get('STATE_DIR') || 'state');
  // Open Coordinator bugs are deliberately outside the Coordinator RPC path,
  // so the Console can remain a useful diagnosis surface during an outage.
  // Production supplies the shared server-wide directory explicitly; local
  // and test instances stay isolated under their own STATE_DIR by default.
  const bugReportDir = resolveConfiguredPath(
    get('DEVCOORDINATOR_BUG_DIR') || path.join(stateDir, 'bugs', 'open'),
  );

  // Webroot the plain-HTTP listener serves ACME HTTP-01 challenges from, so a
  // Let's Encrypt client (certbot --webroot) can validate + auto-renew certs
  // while the app permanently owns port 80. Default: <stateDir>/acme.
  const acmeWebroot = resolveConfiguredPath(get('ACME_WEBROOT') || path.join(stateDir, 'acme'));

  let logLevel = (get('LOG_LEVEL') || 'info').toLowerCase();
  if (!LOG_LEVELS.has(logLevel)) {
    fail('LOG_LEVEL', `must be one of debug|info|warn|error: ${logLevel}`);
    logLevel = 'info';
  }

  let version = '0.0.0';
  try {
    version = String(JSON.parse(fs.readFileSync(path.join(APP_ROOT, 'package.json'), 'utf8')).version || '0.0.0');
  } catch (err) {
    fail(null, `cannot read package.json: ${err.message}`);
  }

  const consoleHost = `${consoleSubdomain}.${domain}`;
  let consoleOrigin = devInsecureHttp
    ? `http://${consoleHost}${httpPort === 80 ? '' : `:${httpPort}`}`
    : `https://${consoleHost}${httpsPort === 443 ? '' : `:${httpsPort}`}`;
  const publishedOrigin = get('PUBLIC_CONSOLE_ORIGIN');
  if (publishedOrigin) {
    try {
      const parsed = new URL(publishedOrigin);
      if (
        parsed.protocol !== 'https:'
        || parsed.hostname !== consoleHost
        || parsed.username
        || parsed.password
        || parsed.search
        || parsed.hash
        || (parsed.pathname && parsed.pathname !== '/')
      ) throw new Error('public origin must be the canonical HTTPS Console origin');
      consoleOrigin = parsed.origin;
    } catch {
      fail(
        'PUBLIC_CONSOLE_ORIGIN',
        `must be an HTTPS origin for ${consoleHost} without credentials, path, query, or fragment`,
      );
    }
  }

  if (problems.length > 0) {
    throw new AggregateError(
      problems,
      `invalid configuration (${problems.length} problem${problems.length === 1 ? '' : 's'}):\n` +
        problems.map((p) => `  - ${p.message}`).join('\n'),
    );
  }

  if (initializeRuntimePaths) {
    try {
      fs.mkdirSync(path.join(stateDir, 'logs'), { recursive: true });
      fs.mkdirSync(path.join(acmeWebroot, '.well-known', 'acme-challenge'), { recursive: true });
    } catch (err) {
      const problem = new ConfigError('STATE_DIR', `cannot be created at ${stateDir}: ${err.message}`);
      throw new AggregateError([problem], `invalid configuration (1 problem):\n  - ${problem.message}`);
    }
  }

  return {
    domain,
    consoleHost,
    consoleOrigin,
    httpPort,
    httpsPort,
    tlsCertFile,
    tlsKeyFile,
    google,
    oidcIssuer,
    allowedEmails,
    sessionSecret,
    sessionTtlMs,
    cookieName,
    coordinatorUrl,
    coordinatorAutostart,
    retainedInventory,
    coordinatorScript,
    coordinatorHome,
    edgePublication: edgePublicationSocket ? {
      socketPath: edgePublicationSocket,
      releaseRoot: edgeReleaseRoot,
      timeoutMs: edgePublicationTimeoutMs,
      required: edgePublicationRequired,
    } : null,
    projectRoot,
    metricsIntervalMs,
    lifecycleEnabled,
    stateDir,
    bugReportDir,
    acmeWebroot,
    logLevel,
    devInsecureHttp,
    version,
  };
}
