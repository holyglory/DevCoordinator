import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { startEdge } from '../edge/devcoordinator-edge.mjs';
import { atomicWriteEnvelope, sealPublication } from '../edge/publication.mjs';
import { createSessionManager } from '../src/auth/session.mjs';
import { ensureDevCert } from './helpers/dev-cert.mjs';
import { startIssuer } from './helpers/fixture-issuer.mjs';

const DIGEST = 'b'.repeat(64);

function startServer(server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve({
        port: server.address().port,
        close: () => new Promise((done) => {
          for (const socket of sockets) socket.destroy();
          server.close(() => done());
        }),
      });
    });
  });
}

function echoServer(factory) {
  return factory((req, res) => {
    const payload = Buffer.from(JSON.stringify({
      path: req.url,
      cookie: req.headers.cookie ?? null,
      assertion: req.headers['x-devops-console-assertion'] ?? null,
      email: req.headers['x-devops-console-email'] ?? null,
      routeId: req.headers['x-devops-console-route-id'] ?? null,
      authorization: req.headers.authorization ?? null,
    }));
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': payload.length });
    res.end(payload);
  });
}

function request({ port, host, path: requestPath = '/', cookie }) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1',
      port,
      path: requestPath,
      method: 'GET',
      servername: host,
      rejectUnauthorized: false,
      headers: {
        host,
        connection: 'close',
        ...(cookie ? { cookie } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('stable edge retains Console shell and HTTP/HTTPS project routes without a Console backend', async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'edge-isolation-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const releaseRoot = path.join(root, 'releases');
  const assetRoot = path.join(releaseRoot, DIGEST, 'apps/DevOpsConsole/src/ui');
  const state = path.join(root, 'edge-state');
  const acme = path.join(state, 'acme');
  await fsp.mkdir(assetRoot, { recursive: true, mode: 0o700 });
  await fsp.mkdir(acme, { recursive: true, mode: 0o700 });
  await fsp.writeFile(path.join(assetRoot, 'index.html'), '<!doctype html><title>retained shell</title>', { mode: 0o600 });
  await fsp.writeFile(path.join(assetRoot, 'app.js'), 'globalThis.edgeShell=true;', { mode: 0o600 });
  await fsp.writeFile(path.join(assetRoot, 'app.css'), ':root{color-scheme:dark}', { mode: 0o600 });

  const certs = ensureDevCert();
  const certPem = await fsp.readFile(certs.cert);
  const keyPem = await fsp.readFile(certs.key);
  const httpUpstream = await startServer(echoServer((handler) => http.createServer(handler)));
  t.after(httpUpstream.close);
  const httpsUpstream = await startServer(echoServer((handler) => https.createServer({
    cert: certPem,
    key: keyPem,
  }, handler)));
  t.after(httpsUpstream.close);
  const issuer = await startIssuer({
    clientId: 'edge-client',
    clientSecret: 'edge-secret',
    claims: { email: 'guest@example.com' },
  });
  t.after(() => issuer.close());

  const secret = Buffer.alloc(32, 7);
  const secretFile = path.join(state, 'session-secret');
  await fsp.writeFile(secretFile, secret.toString('hex'), { mode: 0o640 });
  const oidcClientIdFile = path.join(state, 'oidc-client-id');
  const oidcClientSecretFile = path.join(state, 'oidc-client-secret');
  await fsp.writeFile(oidcClientIdFile, 'edge-client', { mode: 0o640 });
  await fsp.writeFile(oidcClientSecretFile, 'edge-secret', { mode: 0o640 });
  const publicationFile = path.join(state, 'routes.publication');
  const publication = {
    schema_version: 1,
    generation: 1,
    published_at: '2026-07-28T01:00:00.000Z',
    domain: 'vr.ae',
    console_host: 'console.vr.ae',
    release_digest: DIGEST,
    maintenance: { active: false, deployment_id: null, retry_after_seconds: 0, started_at: null },
    session: { cookie_name: 'dc_session' },
    console: {
      asset_root: assetRoot,
      // No process owns this port: the shell and project routes must still work.
      upstream: {
        host: '127.0.0.1', port: 61999, scheme: 'https',
        tls_server_name: 'console.vr.ae', tls_verify: true,
      },
    },
    routes: {
      public: {
        auth: 'public', instance_id: 'public-instance', title: null,
        upstream: {
          host: '127.0.0.1', port: httpUpstream.port, scheme: 'http',
          tls_server_name: null, tls_verify: true,
        },
        upstream_authorization: null,
      },
      offline: {
        auth: 'public', instance_id: 'offline-instance', title: 'Offline',
        upstream: {
          status: 'unavailable', scheme: 'http',
          tls_server_name: null, tls_verify: true,
        },
        upstream_authorization: null,
      },
      secure: {
        auth: 'google', instance_id: 'secure-instance', title: 'Secure',
        upstream: {
          host: '127.0.0.1', port: httpsUpstream.port, scheme: 'https',
          tls_server_name: 'secure.vr.ae', tls_verify: false,
        },
        upstream_authorization: 'Bearer edge-private-value',
      },
    },
    access: {
      owners: ['owner@example.com'],
      grants: { 'guest@example.com': ['console', 'route:secure'] },
    },
  };
  const envelope = sealPublication(publication, { releaseRoot });
  await atomicWriteEnvelope(publicationFile, envelope, { validation: { releaseRoot } });

  const edge = await startEdge({
    systemdSockets: false,
    bindHost: '127.0.0.1',
    listenHttp: 0,
    listenHttps: 0,
    publication: publicationFile,
    sessionSecretFile: secretFile,
    tlsCert: certs.cert,
    tlsKey: certs.key,
    acmeWebroot: acme,
    releaseRoot,
    oidcIssuer: issuer.url,
    oidcClientIdFile,
    oidcClientSecretFile,
    refreshMs: 60_000,
    logLevel: 'error',
  });
  t.after(() => edge.close());
  const port = edge.httpsServer.address().port;
  const sessions = createSessionManager({
    secret,
    ttlMs: 60_000,
    cookieName: 'dc_session',
    cookieDomain: '.vr.ae',
    secure: true,
  });
  const cookie = sessions.issue({ sub: 'subject', email: 'guest@example.com' }).cookie.split(';', 1)[0];

  const shell = await request({ port, host: 'console.vr.ae', cookie });
  assert.equal(shell.status, 200);
  assert.match(shell.body, /retained shell/);

  const publicRoute = await request({ port, host: 'public.vr.ae', path: '/ready' });
  assert.equal(publicRoute.status, 200);
  assert.equal(JSON.parse(publicRoute.body).cookie, null);

  const offlineRoute = await request({ port, host: 'offline.vr.ae', path: '/ready' });
  assert.equal(offlineRoute.status, 502);
  assert.equal(offlineRoute.headers['retry-after'], '2');
  assert.deepEqual(JSON.parse(offlineRoute.body), {
    ok: false,
    code: 'upstream_unavailable',
    resource: 'route:offline',
    retryable: true,
  });

  const secureRoute = await request({ port, host: 'secure.vr.ae', path: '/secure', cookie });
  assert.equal(secureRoute.status, 200);
  const securePayload = JSON.parse(secureRoute.body);
  assert.equal(securePayload.cookie, null, 'edge session leaked to project upstream');
  assert.equal(securePayload.authorization, 'Bearer edge-private-value');
  assert.equal(securePayload.assertion, null, 'retired local JWT assertion leaked to project upstream');
  assert.equal(securePayload.email, 'guest@example.com');
  assert.equal(securePayload.routeId, 'secure-instance');

  const api = await request({ port, host: 'console.vr.ae', path: '/api/session', cookie });
  assert.equal(api.status, 502, 'missing Console backend was hidden');

  const loginStart = await request({
    port,
    host: 'console.vr.ae',
    path: '/auth/start?rt=https%3A%2F%2Fsecure.vr.ae%2Fafter-login',
  });
  assert.equal(loginStart.status, 302);
  assert.equal(new URL(loginStart.headers.location).origin, issuer.url);
  assert.equal(new URL(loginStart.headers.location).pathname, '/authorize');
  const flowSetCookie = loginStart.headers['set-cookie']?.find((value) => value.startsWith('dc_flow='));
  assert.ok(flowSetCookie, 'stable edge did not issue the OIDC flow cookie');
  const flowCookie = flowSetCookie.split(';', 1)[0];
  const authorized = await fetch(loginStart.headers.location, { redirect: 'manual' });
  assert.equal(authorized.status, 302);
  const callbackUrl = new URL(authorized.headers.get('location'));
  assert.equal(callbackUrl.hostname, 'console.vr.ae');
  assert.equal(callbackUrl.pathname, '/auth/callback');
  const callback = await request({
    port,
    host: 'console.vr.ae',
    path: `${callbackUrl.pathname}${callbackUrl.search}`,
    cookie: flowCookie,
  });
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.location, 'https://secure.vr.ae/after-login');
  const edgeSessionSetCookie = callback.headers['set-cookie']
    ?.find((value) => value.startsWith('dc_session='));
  assert.ok(edgeSessionSetCookie, 'stable edge callback did not issue a session');
  const edgeSessionCookie = edgeSessionSetCookie.split(';', 1)[0];
  const authenticatedDuringConsoleOutage = await request({
    port,
    host: 'secure.vr.ae',
    path: '/after-login',
    cookie: edgeSessionCookie,
  });
  assert.equal(authenticatedDuringConsoleOutage.status, 200);
  assert.equal(JSON.parse(authenticatedDuringConsoleOutage.body).cookie, null);

  await fsp.writeFile(publicationFile, '{invalid', { mode: 0o600 });
  assert.equal((await edge.publicationStore.refresh()).ok, false);
  const retained = await request({ port, host: 'public.vr.ae', path: '/after-bad-refresh' });
  assert.equal(retained.status, 200);
});
