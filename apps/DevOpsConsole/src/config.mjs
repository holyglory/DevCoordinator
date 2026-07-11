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

export function loadConfig({ envFile, env = process.env } = {}) {
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
    clientId: get('GOOGLE_CLIENT_ID'),
    clientSecret: get('GOOGLE_CLIENT_SECRET'),
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

  const rawSecret = get('SESSION_SECRET');
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
    coordinatorUrl = coordinatorUrl.replace(/\/+$/, '');
  } catch {
    fail('COORDINATOR_URL', `must be an http(s) URL: ${coordinatorUrl}`);
  }

  const rawAutostart = get('COORDINATOR_AUTOSTART');
  const coordinatorAutostart = !(rawAutostart === '0' || rawAutostart.toLowerCase() === 'false');

  const projectRoot = gitToplevel(APP_ROOT) || APP_ROOT;
  const coordinatorScript = resolveConfiguredPath(
    get('COORDINATOR_SCRIPT') ||
      path.join(projectRoot, 'skills', 'codex-dev-coordinator', 'scripts', 'dev_coordinator.py'),
  );
  const coordinatorHome = get('CODEX_AGENT_COORDINATOR_HOME') || null;
  const coordinatorTokenFile = resolveConfiguredPath(
    get('COORDINATOR_TOKEN_FILE')
      || path.join(coordinatorHome || path.join(os.homedir(), '.codex', 'agent-coordinator'), 'api-token'),
  );

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

  // --- misc ----------------------------------------------------------------
  const stateDir = resolveConfiguredPath(get('STATE_DIR') || 'state');

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
  const consoleOrigin = devInsecureHttp
    ? `http://${consoleHost}${httpPort === 80 ? '' : `:${httpPort}`}`
    : `https://${consoleHost}${httpsPort === 443 ? '' : `:${httpsPort}`}`;

  if (problems.length > 0) {
    throw new AggregateError(
      problems,
      `invalid configuration (${problems.length} problem${problems.length === 1 ? '' : 's'}):\n` +
        problems.map((p) => `  - ${p.message}`).join('\n'),
    );
  }

  try {
    fs.mkdirSync(path.join(stateDir, 'logs'), { recursive: true });
    fs.mkdirSync(path.join(acmeWebroot, '.well-known', 'acme-challenge'), { recursive: true });
  } catch (err) {
    const problem = new ConfigError('STATE_DIR', `cannot be created at ${stateDir}: ${err.message}`);
    throw new AggregateError([problem], `invalid configuration (1 problem):\n  - ${problem.message}`);
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
    coordinatorScript,
    coordinatorHome,
    coordinatorTokenFile,
    projectRoot,
    metricsIntervalMs,
    stateDir,
    acmeWebroot,
    logLevel,
    devInsecureHttp,
    version,
  };
}
