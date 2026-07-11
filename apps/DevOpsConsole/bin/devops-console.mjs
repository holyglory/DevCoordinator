#!/usr/bin/env node
// Composition root: loads config, wires every module, starts listeners.
// Flags: --env-file <path>, --check-config, --help.
// Also exports start(options) so tests can boot the full stack in-process.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadConfig } from '../src/config.mjs';
import { createLogger } from '../src/log.mjs';
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
import { createConsoleApi } from '../src/api.mjs';
import { createStaticServer } from '../src/static.mjs';

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
 * @returns {Promise<{ config, log, addresses, sessions, coordinator, routeStore, close }>}
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
  const guard = createGuard({ sessions, allowedEmails: config.allowedEmails, config, log });

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
  const consoleApi = createConsoleApi({ config, log, coordinator, routeStore, guard, certManager, metrics, prefs });
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
    coordinator,
    proxy,
  });

  let closed = false;
  async function close() {
    if (closed) return;
    closed = true;
    metrics.stop();
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

  return { config, log, addresses: servers.addresses, sessions, coordinator, routeStore, close };
}

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
  log.info('devops-console starting', {
    version: config.version,
    domain: config.domain,
    console: config.consoleHost,
    devInsecureHttp: config.devInsecureHttp,
  });

  // TLS (skipped entirely in DEV_HTTP mode — single plain listener).
  const certManager = config.devInsecureHttp
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
  const guard = createGuard({ sessions, allowedEmails: config.allowedEmails, config, log });
  const pages = createPages({ config });

  // Control engine.
  const coordinator = createCoordinator({ config, log });
  try {
    const result = await coordinator.ensureRunning();
    log.info('coordinator', { ok: result.ok, autostarted: result.autostarted, error: result.error });
  } catch (err) {
    // Non-fatal: the console must boot and serve routes even without it.
    log.warn('coordinator unavailable at boot', { error: err?.message || String(err) });
  }

  const metrics = createMetricsStore({ config, log, coordinator });
  metrics.start();

  const routeStore = createRouteStore({ file: path.join(config.stateDir, 'routes.json'), config, log });
  await routeStore.load();

  const prefs = createPrefsStore({ file: path.join(config.stateDir, 'ui-prefs.json'), log });
  const consoleApi = createConsoleApi({ config, log, coordinator, routeStore, guard, certManager, metrics, prefs });
  const staticServer = createStaticServer({ dir: path.join(APP_ROOT, 'src', 'ui'), log });

  const proxy = buildProxy({ log, pages, config });

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
    coordinator,
    proxy,
  });

  const servers = await startServers({ config, log, certManager, router });

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

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) {
      log.warn('forced exit', { signal });
      process.exit(1);
    }
    shuttingDown = true;
    log.info('shutting down', { signal });
    metrics.stop();
    try {
      await servers.close();
    } catch (err) {
      log.warn('listener close failed', { error: err?.message || String(err) });
    }
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
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    log.error('uncaught exception', { error: err?.stack || String(err) });
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    log.error('unhandled rejection', { error: reason?.stack || String(reason) });
  });

  // Self-registration with the coordinator: only for the real prod edge.
  // Coordinator-spawned dev instances (PORT set) and DEV_HTTP runs skip it.
  if (!process.env.PORT && config.httpsPort === 443 && !config.devInsecureHttp) {
    try {
      await coordinator.serverRegister({
        agent: 'devops-console',
        project: config.projectRoot,
        name: 'devops-console',
        port: 443,
        url: 'https://127.0.0.1:443',
        health_url: 'https://127.0.0.1:443/healthz',
      });
      log.info('registered with coordinator', { name: 'devops-console', port: 443 });
    } catch (err) {
      log.warn('coordinator self-registration failed (continuing)', { error: err?.message || String(err) });
    }
  }
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
    process.stderr.write(`fatal: ${err?.stack || String(err)}\n`);
    process.exit(1);
  });
}
