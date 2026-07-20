#!/usr/bin/env node
// Composition root: loads config, wires every module, starts listeners.
// Flags: --env-file <path>, --check-config, --help.
// Also exports start(options) so tests can boot the full stack in-process.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from '../src/config.mjs';
import { createLogger } from '../src/log.mjs';
import { createProcessLifecycle, runCleanupSteps } from '../src/process-lifecycle.mjs';
import { createCertManager } from '../src/certs.mjs';
import { startServers } from '../src/server.mjs';
import { createRouter } from '../src/router.mjs';
import { createProxy } from '../src/proxy.mjs';
import { createSessionManager } from '../src/auth/session.mjs';
import { createOidc } from '../src/auth/oidc.mjs';
import { createGuard } from '../src/auth/guard.mjs';
import { createPages } from '../src/auth/pages.mjs';
import { createCoordinator } from '../src/coordinator.mjs';
import { createMetricsStore } from '../src/metrics.mjs';
import { createPrefsStore } from '../src/prefs.mjs';
import { createRouteStore } from '../src/routes.mjs';
import { createUpstreamAuthStore } from '../src/upstream-auth.mjs';
import { createAccessStore } from '../src/access.mjs';
import { createConsoleApi } from '../src/api.mjs';
import { createStaticServer } from '../src/static.mjs';
import { createTelegramService } from '../src/telegram.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const USAGE = `Usage: devops-console [options]

Options:
  --env-file <path>   Load configuration from <path> instead of <appRoot>/.env
  --check-config      Validate configuration, print it (redacted), and exit
  -h, --help          Show this help
`;

function parseArgs(argv) {
  const args = { envFile: undefined, checkConfig: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--env-file') {
      args.envFile = argv[++i];
      if (args.envFile === undefined) {
        process.stderr.write('--env-file requires a path argument\n');
        process.exit(2);
      }
    } else if (arg.startsWith('--env-file=')) {
      args.envFile = arg.slice('--env-file='.length);
    } else if (arg === '--check-config') {
      args.checkConfig = true;
    } else if (arg === '--help' || arg === '-h') {
      process.stdout.write(USAGE);
      process.exit(0);
    } else {
      process.stderr.write(`unknown argument: ${arg}\n${USAGE}`);
      process.exit(2);
    }
  }
  return args;
}

function redactedConfig(config) {
  return {
    ...config,
    sessionSecret: `<redacted ${config.sessionSecret.length} bytes>`,
    google: {
      clientId: config.google.clientId || '(unset)',
      clientSecret: config.google.clientSecret ? '<redacted>' : '(unset)',
    },
    allowedEmails: [...config.allowedEmails],
  };
}

export function productionRegistrationPlan({ config, env = process.env }) {
  const required = env.COORDINATOR_REGISTRATION_REQUIRED === '1';
  const productionEdge = config.httpsPort === 443 && !config.devInsecureHttp;
  if (required && !productionEdge) {
    throw new Error('required coordinator registration needs the production TLS edge on port 443');
  }
  return {
    required,
    shouldRegister: productionEdge && (required || !env.PORT),
  };
}

export async function registerProductionEdge({
  coordinator,
  config,
  pid = process.pid,
  cwd = process.cwd(),
  platform = process.platform,
  attempts = 5,
  delayMs = 200,
}) {
  const identityMatches = (identity) => {
    const proofMatches = platform === 'linux'
      ? (
        identity?.source === 'proc_pid_fd'
        && Array.isArray(identity?.listener_inodes)
        && identity.listener_inodes.length > 0
        && identity.listener_inodes.every((value) => /^\d+$/.test(value))
      )
      : (
        identity?.source === 'platform_listener_probe'
        && Array.isArray(identity?.listener_inodes)
      );
    return identity?.ok === true
    && identity.pid === pid
    && identity.project === config.projectRoot
    && identity.host === '127.0.0.1'
    && identity.port === 443
    && (identity.cwd === config.projectRoot || identity.cwd?.startsWith(`${config.projectRoot}/`))
    && proofMatches;
  };
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const registered = await coordinator.serverRegister({
        agent: 'devops-console',
        project: config.projectRoot,
        name: 'devops-console',
        cwd,
        pid,
        port: 443,
        url: 'https://127.0.0.1:443',
        health_url: 'https://127.0.0.1:443/healthz',
      });
      if (
        registered?.pid !== pid
        || registered?.status !== 'running'
        || registered?.health?.ok !== true
        || registered?.health?.classification !== 'healthy'
        || registered?.health?.check?.status !== 200
        || !registered?.lease_id
        || !identityMatches(registered?.registration_identity)
        || !identityMatches(registered?.health?.identity)
      ) {
        throw new Error('coordinator returned an incomplete or mismatched registration graph');
      }
      return registered;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await delay(delayMs);
    }
  }
  throw new Error(
    `coordinator self-registration failed after ${attempts} attempts: ${lastError?.message || String(lastError)}`,
    { cause: lastError },
  );
}

export async function completeProductionRegistration({ coordinator, config, log, required = false, attempts, delayMs }) {
  try {
    const result = await registerProductionEdge({ coordinator, config, attempts, delayMs });
    log.info('registered with coordinator', { name: 'devops-console', port: 443 });
    return result;
  } catch (error) {
    if (required) throw error;
    log.warn('coordinator self-registration failed (continuing)', {
      error: error?.message || String(error),
    });
    return null;
  }
}

// The proxy's error page renderer is shared by main() and start().
function buildProxy({ log, pages, config }) {
  return createProxy({
    log,
    sessionCookieName: config.cookieName,
    renderBadGateway: (req, res, { kind, target }) => {
      const detail =
        kind === 'timeout'
          ? `Timed out connecting to 127.0.0.1:${target.port} after 5 seconds.`
          : kind === 'connect'
            ? `Nothing is listening on 127.0.0.1:${target.port} — the dev server is not running.`
            : `The upstream on 127.0.0.1:${target.port} closed the connection before responding.`;
      const page = pages.renderUpstreamError({
        slug: target.slug,
        kind,
        detail,
        consoleUrl: config.consoleOrigin + '/',
      });
      const status =
        kind === 'timeout' ? 504 : Number.isInteger(page?.status) && page.status >= 400 ? page.status : 502;
      res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(page?.html ?? '');
    },
  });
}

function buildTelegram({ config, log, coordinator, accessStore }) {
  return createTelegramService({
    file: path.join(config.stateDir, 'telegram-control.json'),
    log,
    isAdmin: (email) => accessStore.isAdmin(email),
    coordinator: {
      async hasProject(repoId) {
        const inventory = await coordinator.inventory({ maxAgeMs: 0 });
        return Array.isArray(inventory?.repositories)
          && inventory.repositories.some((repository) => repository?.repo_id === repoId);
      },
      observeHost: () => coordinator.observeHost({
        agent: 'devops-console:telegram',
        project: config.projectRoot,
      }),
      readEvents: ({ after, limit }) => coordinator.events({ after, limit }),
    },
  });
}

/**
 * Boot the whole console in-process (test harness / embedding entry point).
 * Unlike main(): no signal handlers, no process.exit, no self-registration,
 * and listeners can bind OS-assigned ports via listenPorts { https: 0, http: 0 }
 * — the real bound ports are patched back into config (httpPort/httpsPort/
 * consoleOrigin) before the auth stack captures the console origin.
 *
 * @param {object} options
 * @param {string} [options.envFile]      env file for loadConfig
 * @param {object} [options.env]          env object for loadConfig (defaults to process.env)
 * @param {object} [options.overrides]    shallow config overrides (e.g. bindHost)
 * @param {object} [options.listenPorts]  { https?, http? } bind-port overrides
 * @returns {Promise<{ config, log, addresses, sessions, coordinator, routeStore, accessStore, close }>}
 */
export async function start({ envFile, env, overrides = {}, listenPorts } = {}) {
  const config = loadConfig({ envFile, env });
  Object.assign(config, overrides);
  const log = createLogger(config.logLevel);

  const certManager = config.devInsecureHttp
    ? null
    : await createCertManager({ certFile: config.tlsCertFile, keyFile: config.tlsKeyFile, log });

  const sessions = createSessionManager({
    secret: config.sessionSecret, // public-artifact-guard: allow text-secret -- runtime config reference, never literal credential material
    ttlMs: config.sessionTtlMs,
    cookieName: config.cookieName,
    cookieDomain: `.${config.domain}`,
    secure: !config.devInsecureHttp,
  });
  const coordinator = createCoordinator({ config, log });
  try {
    await coordinator.ensureRunning();
  } catch (err) {
    log.warn('coordinator unavailable at boot', { error: err?.message || String(err) });
  }

  const metrics = createMetricsStore({ config, log, coordinator });
  metrics.start();

  const routeStore = createRouteStore({ file: path.join(config.stateDir, 'routes.json'), config, log });
  await routeStore.load();
  const upstreamAuthStore = createUpstreamAuthStore({
    file: path.join(config.stateDir, 'upstream-auth.json'),
    log,
  });
  await upstreamAuthStore.load();
  const accessStore = createAccessStore({
    file: path.join(config.stateDir, 'access-control.json'),
    adminEmails: config.allowedEmails,
    routeStore,
    log,
  });
  await accessStore.load();
  const guard = createGuard({ sessions, access: accessStore, config, log });
  const telegram = buildTelegram({ config, log, coordinator, accessStore });
  await telegram.load();

  // Listen first (router attaches afterwards) so OS-assigned ports are known
  // before any consoleOrigin-derived value is captured.
  const routerRef = { current: null };
  const routerFacade = {
    handleRequest(req, res) {
      if (!routerRef.current) {
        res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('starting');
        return;
      }
      routerRef.current.handleRequest(req, res);
    },
    handleUpgrade(req, socket, head) {
      if (!routerRef.current) {
        socket.destroy();
        return;
      }
      routerRef.current.handleUpgrade(req, socket, head);
    },
  };
  const servers = await startServers({ config, log, certManager, router: routerFacade, listenPorts });

  const portOf = (name) => servers.addresses.find((a) => a.name === name)?.port;
  const httpsPort = portOf('https');
  const devHttpPort = portOf('dev-http');
  const redirectPort = portOf('http-redirect');
  if (httpsPort !== undefined) config.httpsPort = httpsPort;
  if (devHttpPort !== undefined) config.httpPort = devHttpPort;
  if (redirectPort !== undefined) config.httpPort = redirectPort;
  config.consoleOrigin = config.devInsecureHttp
    ? `http://${config.consoleHost}${config.httpPort === 80 ? '' : `:${config.httpPort}`}`
    : `https://${config.consoleHost}${config.httpsPort === 443 ? '' : `:${config.httpsPort}`}`;

  // Everything that captures consoleOrigin is constructed after the patch.
  const pages = createPages({ config });
  const oidc = createOidc({
    issuer: config.oidcIssuer,
    clientId: config.google.clientId,
    clientSecret: config.google.clientSecret,
    redirectUri: `${config.consoleOrigin}/auth/callback`,
    sessions,
    log,
  });
  const prefs = createPrefsStore({ file: path.join(config.stateDir, 'ui-prefs.json'), log });
  const consoleApi = createConsoleApi({
    config, log, coordinator, routeStore, upstreamAuthStore, accessStore, guard, certManager, metrics, prefs, telegram,
  });
  const staticServer = createStaticServer({ dir: path.join(APP_ROOT, 'src', 'ui'), log });
  const proxy = buildProxy({ log, pages, config });

  routerRef.current = createRouter({
    config,
    log,
    guard,
    oidc,
    sessions,
    pages,
    consoleApi,
    staticServer,
    routeStore,
    accessStore,
    upstreamAuthStore,
    coordinator,
    proxy,
  });
  await telegram.start();

  let closed = false;
  async function close() {
    if (closed) return;
    closed = true;
    metrics.stop();
    await telegram.stop();
    await servers.close();
    try {
      proxy.close();
    } catch {
      // ignore
    }
    try {
      certManager?.close();
    } catch {
      // ignore
    }
    try {
      coordinator.close();
    } catch {
      // ignore
    }
  }

  return {
    config,
    log,
    addresses: servers.addresses,
    sessions,
    coordinator,
    routeStore,
    upstreamAuthStore,
    accessStore,
    telegram,
    close,
  };
}

let directRunLifecycle = null;

async function main() {
  const args = parseArgs(process.argv.slice(2));

  let config;
  try {
    config = loadConfig({ envFile: args.envFile });
  } catch (err) {
    if (err instanceof AggregateError) {
      process.stderr.write('Configuration is invalid:\n');
      for (const problem of err.errors) process.stderr.write(`  - ${problem.message}\n`);
    } else {
      process.stderr.write(`${err?.stack || String(err)}\n`);
    }
    process.exit(1);
  }

  if (args.checkConfig) {
    process.stdout.write(JSON.stringify(redactedConfig(config), null, 2) + '\n');
    process.exit(0);
  }

  const log = createLogger(config.logLevel);
  let certManager = null;
  let coordinator = null;
  let metrics = null;
  let telegram = null;
  let proxy = null;
  let servers = null;
  const lifecycle = createProcessLifecycle({
    log,
    cleanup: () => runCleanupSteps([
      { name: 'metrics', run: () => metrics?.stop() },
      { name: 'telegram', run: () => telegram?.stop() },
      { name: 'listeners', run: () => servers?.close() },
      { name: 'proxy', run: () => proxy?.close() },
      { name: 'certificate-manager', run: () => certManager?.close() },
      { name: 'coordinator-client', run: () => coordinator?.close() },
    ]),
  });
  directRunLifecycle = lifecycle;
  lifecycle.install();

  log.info('devops-console starting', {
    version: config.version,
    domain: config.domain,
    console: config.consoleHost,
    devInsecureHttp: config.devInsecureHttp,
  });

  // TLS (skipped entirely in DEV_HTTP mode — single plain listener).
  certManager = config.devInsecureHttp
    ? null
    : await createCertManager({ certFile: config.tlsCertFile, keyFile: config.tlsKeyFile, log });

  // Auth stack.
  const sessions = createSessionManager({
    secret: config.sessionSecret, // public-artifact-guard: allow text-secret -- runtime config reference, never literal credential material
    ttlMs: config.sessionTtlMs,
    cookieName: config.cookieName,
    cookieDomain: `.${config.domain}`,
    secure: !config.devInsecureHttp,
  });
  const oidc = createOidc({
    issuer: config.oidcIssuer,
    clientId: config.google.clientId,
    clientSecret: config.google.clientSecret,
    redirectUri: `${config.consoleOrigin}/auth/callback`,
    sessions,
    log,
  });
  const pages = createPages({ config });

  // Control engine.
  coordinator = createCoordinator({ config, log });
  try {
    const result = await coordinator.ensureRunning();
    log.info('coordinator', { ok: result.ok, autostarted: result.autostarted, error: result.error });
  } catch (err) {
    // Non-fatal: the console must boot and serve routes even without it.
    log.warn('coordinator unavailable at boot', { error: err?.message || String(err) });
  }

  metrics = createMetricsStore({ config, log, coordinator });
  metrics.start();

  const routeStore = createRouteStore({ file: path.join(config.stateDir, 'routes.json'), config, log });
  await routeStore.load();
  const upstreamAuthStore = createUpstreamAuthStore({
    file: path.join(config.stateDir, 'upstream-auth.json'),
    log,
  });
  await upstreamAuthStore.load();
  const accessStore = createAccessStore({
    file: path.join(config.stateDir, 'access-control.json'),
    adminEmails: config.allowedEmails,
    routeStore,
    log,
  });
  await accessStore.load();
  const guard = createGuard({ sessions, access: accessStore, config, log });
  telegram = buildTelegram({ config, log, coordinator, accessStore });
  await telegram.load();

  const prefs = createPrefsStore({ file: path.join(config.stateDir, 'ui-prefs.json'), log });
  const consoleApi = createConsoleApi({
    config, log, coordinator, routeStore, upstreamAuthStore, accessStore, guard, certManager, metrics, prefs, telegram,
  });
  const staticServer = createStaticServer({ dir: path.join(APP_ROOT, 'src', 'ui'), log });

  proxy = buildProxy({ log, pages, config });

  const router = createRouter({
    config,
    log,
    guard,
    oidc,
    sessions,
    pages,
    consoleApi,
    staticServer,
    routeStore,
    accessStore,
    upstreamAuthStore,
    coordinator,
    proxy,
  });

  servers = await startServers({ config, log, certManager, router });
  await telegram.start();

  const scheme = config.devInsecureHttp ? 'http' : 'https';
  const publicPort = config.devInsecureHttp ? config.httpPort : config.httpsPort;
  const portSuffix =
    (scheme === 'https' && publicPort === 443) || (scheme === 'http' && publicPort === 80) ? '' : `:${publicPort}`;
  log.info('public url', { url: `${config.consoleOrigin}/` });
  log.info('public url', { url: `${scheme}://${config.domain}${portSuffix}/` });
  log.info('public url', { url: `${scheme}://<slug>.${config.domain}${portSuffix}/` });

  // SIGHUP → certificate reload (no-op in dev mode).
  process.on('SIGHUP', () => {
    if (certManager) {
      log.info('SIGHUP received; reloading TLS certificate');
      certManager.reload();
    } else {
      log.info('SIGHUP received; no TLS in DEV_HTTP mode, ignoring');
    }
  });

  // Required production registration cannot be bypassed by a preserved PORT
  // value in the external environment file. Optional coordinator-spawned dev
  // instances retain the PORT-based skip.
  const registrationPlan = productionRegistrationPlan({ config });
  if (registrationPlan.shouldRegister) {
    await completeProductionRegistration({
      coordinator,
      config,
      log,
      required: registrationPlan.required,
    });
  }
  lifecycle.markReady({
    version: config.version,
    httpsPort: servers.addresses.find((entry) => entry.name === 'https')?.port,
    httpPort: servers.addresses.find((entry) => entry.name === 'http-redirect')?.port,
    registration: registrationPlan.shouldRegister
      ? registrationPlan.required ? 'required' : 'optional'
      : 'skipped',
  });
}

// Run main() only when this file is the executed entry script — importing it
// (e.g. from the test harness for start()) must not boot the daemon.
const isDirectRun = (() => {
  try {
    return process.argv[1] ? pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url : false;
  } catch {
    return false;
  }
})();

if (isDirectRun) {
  main().catch((err) => {
    if (directRunLifecycle) {
      return directRunLifecycle.fatal('top-level-failure', err);
    }
    const fallbackLog = createLogger('info');
    fallbackLog.error('fatal before process lifecycle initialization', {
      error: err?.stack || String(err),
      pid: process.pid,
    });
    process.exit(1);
  });
}
