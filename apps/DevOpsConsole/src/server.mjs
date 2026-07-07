// Public listeners. Prod: HTTPS (TLS termination via certManager) + a plain
// HTTP listener that only answers /healthz and redirects everything else to
// https. Dev (DEV_HTTP=1): a single plain listener serving the router.

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';

const DRAIN_TIMEOUT_MS = 10_000;
const ACME_PREFIX = '/.well-known/acme-challenge/';

// Serve an ACME HTTP-01 challenge token from the webroot, if one matches.
// Returns true when it handled the request. Tokens are [A-Za-z0-9_-] only, so
// there is no path-traversal surface, but we still resolve + prefix-check.
function tryServeAcmeChallenge(req, res, config, log) {
  if (!config.acmeWebroot) return false;
  const url = req.url || '/';
  const q = url.indexOf('?');
  const pathname = q === -1 ? url : url.slice(0, q);
  if (!pathname.startsWith(ACME_PREFIX)) return false;
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;

  const token = decodeURIComponent(pathname.slice(ACME_PREFIX.length));
  if (!token || !/^[A-Za-z0-9_-]+$/.test(token)) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('not found');
    return true;
  }
  const dir = path.join(config.acmeWebroot, '.well-known', 'acme-challenge');
  const file = path.join(dir, token);
  if (path.relative(dir, file).includes('..')) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('not found');
    return true;
  }
  fs.readFile(file, (err, body) => {
    if (err) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('not found');
      return;
    }
    log?.info?.('served acme challenge', { token });
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(req.method === 'HEAD' ? undefined : body);
  });
  return true;
}

function sanitizeRedirectHost(raw) {
  if (typeof raw !== 'string') return null;
  let host = raw.trim().toLowerCase();
  // Bracketed IPv6 literals are never valid public hosts for this deployment.
  if (!host || host.startsWith('[')) return null;
  const colon = host.indexOf(':');
  if (colon !== -1) host = host.slice(0, colon);
  if (host.length === 0 || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) return null;
  return host;
}

function createRedirectHandler(config, log) {
  return (req, res) => {
    const url = req.url || '/';
    const q = url.indexOf('?');
    const pathname = q === -1 ? url : url.slice(0, q);
    const isRead = req.method === 'GET' || req.method === 'HEAD';

    // ACME HTTP-01 challenges must be answered over plain HTTP on port 80,
    // BEFORE the https redirect, so Let's Encrypt can validate/renew certs.
    if (tryServeAcmeChallenge(req, res, config, log)) return;

    if (isRead && pathname === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('ok');
      return;
    }

    // Sanitize before echoing into Location: strips ports, rejects anything
    // outside [a-z0-9.-] so a hostile Host header cannot poison the redirect.
    const host = sanitizeRedirectHost(req.headers.host);
    if (!host) {
      res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('bad request');
      return;
    }

    const portSuffix = config.httpsPort === 443 ? '' : `:${config.httpsPort}`;
    try {
      res.writeHead(isRead ? 301 : 308, { location: `https://${host}${portSuffix}${url}` });
      res.end();
    } catch {
      if (!res.headersSent) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('bad request');
      } else {
        res.destroy();
      }
    }
  };
}

export async function startServers({ config, log, certManager, router, listenPorts = {} }) {
  // listenPorts lets a test harness bind OS-assigned ports (0) while the
  // config keeps its semantic ports (config.httpPort === 0 still means "plain
  // listener disabled"). Absent overrides, behavior is unchanged.
  const httpsBindPort = listenPorts.https ?? config.httpsPort;
  const httpBindPort = listenPorts.http ?? config.httpPort;
  const entries = [];
  const requestListener = (req, res) => router.handleRequest(req, res);
  // Over TLS, advertise HSTS so browsers pin https for the whole *.vr.ae zone
  // (every host here is https-only). setHeader before dispatch; Node merges it
  // with each handler's writeHead headers.
  const tlsRequestListener = (req, res) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    router.handleRequest(req, res);
  };
  const upgradeListener = (req, socket, head) => router.handleUpgrade(req, socket, head);

  if (config.devInsecureHttp) {
    const server = http.createServer(requestListener);
    server.on('upgrade', upgradeListener);
    entries.push({ name: 'dev-http', server, port: httpBindPort });
  } else {
    const httpsServer = https.createServer(
      {
        // SNI clients (every real browser) always get the manager's current
        // context, so cert hot-reloads apply to new handshakes immediately.
        SNICallback: (_servername, cb) => cb(null, certManager.getSecureContext()),
        // Non-SNI clients (curl to https://127.0.0.1, IP health probes) use
        // the DEFAULT context, which SNICallback never covers — seed it with
        // the current PEMs or those handshakes fail outright.
        ...certManager.getCredentials(),
      },
      tlsRequestListener,
    );
    // Keep the default (non-SNI) context fresh across hot-reloads too.
    certManager.onSwap(() => {
      try {
        httpsServer.setSecureContext(certManager.getCredentials());
      } catch (err) {
        log.warn('failed to refresh default TLS context', { error: err?.message || String(err) });
      }
    });
    httpsServer.on('upgrade', upgradeListener);
    entries.push({ name: 'https', server: httpsServer, port: httpsBindPort });

    if (config.httpPort > 0) {
      entries.push({ name: 'http-redirect', server: http.createServer(createRedirectHandler(config, log)), port: httpBindPort });
    }
  }

  for (const { server } of entries) {
    server.headersTimeout = 65_000;
    // Long-lived SSE/WS upstreams must not be killed by the request timeout.
    server.requestTimeout = 0;
    server.keepAliveTimeout = 65_000;
    // Track raw connections so close() can destroy even hijacked (upgraded)
    // sockets that closeAllConnections() may not cover.
    const sockets = new Set();
    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });
    server._trackedSockets = sockets;
  }

  const listen = ({ name, server, port }) =>
    new Promise((resolve, reject) => {
      const onError = (err) => reject(err);
      server.once('error', onError);
      // Dev mode is loopback-only by design; prod binds all interfaces unless
      // config.bindHost narrows it (used by the in-process test harness).
      server.listen(port, config.devInsecureHttp ? '127.0.0.1' : config.bindHost ?? undefined, () => {
        server.removeListener('error', onError);
        log.info('listener started', { name, port: server.address().port });
        resolve();
      });
    });

  const started = [];
  try {
    for (const entry of entries) {
      await listen(entry);
      started.push(entry);
    }
  } catch (err) {
    await Promise.all(started.map(({ server }) => new Promise((resolve) => server.close(() => resolve()))));
    throw err;
  }

  async function close() {
    log.info('closing listeners');
    await Promise.all(
      entries.map(
        ({ name, server }) =>
          new Promise((resolve) => {
            let settled = false;
            const finish = () => {
              if (!settled) {
                settled = true;
                resolve();
              }
            };
            server.close(finish);
            server.closeIdleConnections?.();
            const killTimer = setTimeout(() => {
              log.warn('drain timeout; destroying remaining connections', { name });
              server.closeAllConnections?.();
              for (const socket of server._trackedSockets) socket.destroy();
            }, DRAIN_TIMEOUT_MS);
            killTimer.unref();
            // Failsafe so close() can never hang the shutdown path.
            const failsafe = setTimeout(finish, DRAIN_TIMEOUT_MS + 1_000);
            failsafe.unref();
          }),
      ),
    );
  }

  return {
    close,
    // Actual bound ports (meaningful when listenPorts requested port 0).
    addresses: entries.map(({ name, server }) => ({ name, port: server.address().port })),
  };
}
