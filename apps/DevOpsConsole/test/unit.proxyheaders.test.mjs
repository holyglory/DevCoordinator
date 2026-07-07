// Component tests for src/proxy.mjs header logic — exercised through a REAL
// in-process edge server running proxy.forward/forwardUpgrade against a REAL
// upstream HTTP server, both on OS-assigned loopback ports (never fixed).
// Covers: hop-by-hop stripping (standard set + Connection-named extras) in
// both directions, X-Forwarded-For/-Proto/-Host correctness, Host=publicHost
// preservation, upgrade-path Connection handling, and the connect-error page.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createProxy } from '../src/proxy.mjs';
import { ensureDevCert } from './helpers/dev-cert.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const devCertPaths = ensureDevCert();
const DEV_CERT = fs.readFileSync(devCertPaths.cert);
const DEV_KEY = fs.readFileSync(devCertPaths.key);

const silentLog = {
  debug() {},
  info() {},
  warn() {},
  error() {},
  child() {
    return this;
  },
};

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}

// Real upstream: echoes method/url/headers/body as JSON with explicit
// Content-Length. /resp-hop responses carry hop-by-hop headers that the proxy
// must strip on the way back. Upgrade requests get a real 101.
async function startUpstream(t) {
  const state = { upgrades: [] };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const payload = JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const headers = {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-resp-keep': 'kept',
      };
      if (req.url.startsWith('/resp-hop')) {
        headers['x-resp-hop'] = 'resp-secret';
        headers.connection = 'x-resp-hop'; // names the extra to strip
        headers['keep-alive'] = 'timeout=7';
      }
      res.writeHead(200, headers);
      res.end(payload);
    });
  });
  server.on('upgrade', (req, socket) => {
    state.upgrades.push(req.headers);
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: test-accept\r\n' +
        '\r\n',
    );
    socket.end();
  });
  state.port = await listen(server);
  t.after(() => closeServer(server));
  return state;
}

// Real edge wired to a fresh proxy instance per test (isolated keep-alive pool).
async function startEdge(t, { upstreamPort, publicHost = 'slug.vr.ae', tls = false }) {
  const badGatewayCalls = [];
  const proxy = createProxy({
    log: silentLog,
    renderBadGateway: (req, res, { kind }) => {
      badGatewayCalls.push(kind);
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`bad gateway: ${kind}`);
    },
  });
  const target = { port: upstreamPort, slug: 'slug', host: '127.0.0.1', publicHost, route: { slug: 'slug' } };
  const handler = (req, res) => proxy.forward(req, res, target);
  const server = tls ? https.createServer({ cert: DEV_CERT, key: DEV_KEY }, handler) : http.createServer(handler);
  server.on('upgrade', (req, socket, head) => proxy.forwardUpgrade(req, socket, head, target));
  const port = await listen(server);
  t.after(async () => {
    proxy.close();
    await closeServer(server);
  });
  return { port, badGatewayCalls };
}

// Raw-socket exchange: full control over the exact request headers sent.
function rawExchange(port, text) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1');
    const chunks = [];
    sock.setNoDelay(true);
    sock.on('connect', () => sock.write(text));
    sock.on('data', (c) => chunks.push(c));
    sock.on('error', () => {}); // teardown RST after data is fine
    sock.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    setTimeout(() => {
      sock.destroy();
      reject(new Error('rawExchange timed out'));
    }, 10_000).unref();
  });
}

function bodyOf(raw) {
  const i = raw.indexOf('\r\n\r\n');
  assert.notEqual(i, -1, `no header terminator in response: ${JSON.stringify(raw.slice(0, 200))}`);
  return raw.slice(i + 4);
}

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const mod = opts.tls ? https : http;
    const req = mod.request(
      { host: '127.0.0.1', agent: false, ...opts },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('request direction: hop-by-hop headers stripped, incl. Connection-named extras', async (t) => {
  const upstream = await startUpstream(t);
  const edge = await startEdge(t, { upstreamPort: upstream.port, publicHost: 'slug.vr.ae' });

  const raw = await rawExchange(
    edge.port,
    [
      'GET /echo?a=1 HTTP/1.1',
      'Host: edgehost.vr.ae',
      'Connection: close, x-hop', // 'x-hop' becomes hop-by-hop by being named here
      'X-Hop: super-secret',
      'Keep-Alive: timeout=5',
      'Proxy-Authorization: Basic Zm9vOmJhcg==',
      'Proxy-Authenticate: Basic',
      'TE: trailers',
      'Trailer: Expires',
      'X-Forwarded-For: 10.0.0.1',
      'X-Keep: yes',
      '',
      '',
    ].join('\r\n'),
  );

  assert.match(raw, /^HTTP\/1\.1 200 /);
  const echo = JSON.parse(bodyOf(raw));
  const h = echo.headers;

  // Standard hop-by-hop set never crosses the proxy.
  assert.equal(h['keep-alive'], undefined);
  assert.equal(h['proxy-authorization'], undefined);
  assert.equal(h['proxy-authenticate'], undefined);
  assert.equal(h.te, undefined);
  assert.equal(h.trailer, undefined);
  // Connection-named extra stripped; the client's Connection tokens do not leak.
  assert.equal(h['x-hop'], undefined);
  assert.ok(!String(h.connection ?? '').includes('x-hop'), `connection leaked tokens: ${h.connection}`);
  assert.ok(!String(h.connection ?? '').includes('close'), `client Connection passed through: ${h.connection}`);

  // End-to-end headers survive.
  assert.equal(h['x-keep'], 'yes');

  // Host preserved as the PUBLIC host (dev servers see the real vhost)…
  assert.equal(h.host, 'slug.vr.ae');
  // …while X-Forwarded-* reports the original request faithfully.
  assert.equal(h['x-forwarded-host'], 'edgehost.vr.ae');
  assert.equal(h['x-forwarded-proto'], 'http');
  assert.equal(h['x-forwarded-for'], '10.0.0.1, 127.0.0.1'); // client IP APPENDED

  assert.equal(echo.method, 'GET');
  assert.equal(echo.url, '/echo?a=1'); // path + query passthrough
});

test('X-Forwarded-For starts fresh when the client sent none; method/body stream through', async (t) => {
  const upstream = await startUpstream(t);
  const edge = await startEdge(t, { upstreamPort: upstream.port, publicHost: 'slug.vr.ae' });

  const res = await request(
    {
      port: edge.port,
      method: 'POST',
      path: '/post/here?x=2',
      headers: { host: 'other.vr.ae', connection: 'close', 'content-type': 'text/plain' },
    },
    'hello upstream',
  );

  assert.equal(res.status, 200);
  const echo = JSON.parse(res.body);
  assert.equal(echo.method, 'POST');
  assert.equal(echo.url, '/post/here?x=2');
  assert.equal(echo.body, 'hello upstream');
  assert.equal(echo.headers['x-forwarded-for'], '127.0.0.1');
  assert.equal(echo.headers['x-forwarded-host'], 'other.vr.ae');
  assert.equal(echo.headers.host, 'slug.vr.ae');
});

test('response direction: hop-by-hop headers stripped, incl. Connection-named extras', async (t) => {
  const upstream = await startUpstream(t);
  const edge = await startEdge(t, { upstreamPort: upstream.port });

  const res = await request({
    port: edge.port,
    method: 'GET',
    path: '/resp-hop',
    headers: { host: 'edgehost.vr.ae', connection: 'close' },
  });

  assert.equal(res.status, 200);
  assert.equal(res.headers['x-resp-hop'], undefined, 'Connection-named response header must be stripped');
  assert.equal(res.headers['keep-alive'], undefined, 'Keep-Alive response header must be stripped');
  assert.equal(res.headers['x-resp-keep'], 'kept', 'end-to-end response headers must survive');
  assert.equal(res.headers['content-type'], 'application/json');
  JSON.parse(res.body); // body intact
});

test('X-Forwarded-Proto is https when the edge terminates TLS', async (t) => {
  const upstream = await startUpstream(t);
  const edge = await startEdge(t, { upstreamPort: upstream.port, publicHost: 'slug.vr.ae', tls: true });

  const res = await request({
    tls: true,
    port: edge.port,
    method: 'GET',
    path: '/echo',
    rejectUnauthorized: false, // dev cert
    headers: { host: 'slug.vr.ae', connection: 'close' },
  });

  assert.equal(res.status, 200);
  const echo = JSON.parse(res.body);
  assert.equal(echo.headers['x-forwarded-proto'], 'https');
  assert.equal(echo.headers['x-forwarded-host'], 'slug.vr.ae');
  assert.equal(echo.headers.host, 'slug.vr.ae');
});

test('upgrade path: Connection: Upgrade preserved, extras stripped, 101 relayed', async (t) => {
  const upstream = await startUpstream(t);
  const edge = await startEdge(t, { upstreamPort: upstream.port, publicHost: 'slug.vr.ae' });

  const raw = await rawExchange(
    edge.port,
    [
      'GET /ws HTTP/1.1',
      'Host: edgehost.vr.ae',
      'Connection: Upgrade, x-hop',
      'Upgrade: websocket',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
      'X-Hop: sneak',
      '',
      '',
    ].join('\r\n'),
  );

  // Client got the genuine 101 from upstream.
  assert.match(raw, /^HTTP\/1\.1 101 /);
  assert.match(raw, /Sec-WebSocket-Accept: test-accept/);

  // Upstream saw a proper upgrade request with the hop-extras removed.
  assert.equal(upstream.upgrades.length, 1);
  const h = upstream.upgrades[0];
  assert.equal(h.connection, 'Upgrade', 'the Upgrade hop itself must be carried across');
  assert.equal(h.upgrade, 'websocket');
  assert.equal(h['sec-websocket-key'], 'dGhlIHNhbXBsZSBub25jZQ==');
  assert.equal(h['sec-websocket-version'], '13');
  assert.equal(h['x-hop'], undefined, 'Connection-named extra must not reach upstream');
  assert.equal(h.host, 'slug.vr.ae');
  assert.equal(h['x-forwarded-proto'], 'http');
  assert.equal(h['x-forwarded-host'], 'edgehost.vr.ae');
});

test('dead upstream port → onError callback renders the 502 (kind=connect)', async (t) => {
  // Reserve an ephemeral port the OS just proved free, then close it so
  // nothing is listening there. No fixed ports involved.
  const placeholder = net.createServer();
  const deadPort = await new Promise((resolve, reject) => {
    placeholder.once('error', reject);
    placeholder.listen(0, '127.0.0.1', () => {
      const p = placeholder.address().port;
      placeholder.close(() => resolve(p));
    });
  });

  const edge = await startEdge(t, { upstreamPort: deadPort });
  const res = await request({
    port: edge.port,
    method: 'GET',
    path: '/x',
    headers: { host: 'edgehost.vr.ae', connection: 'close' },
  });

  assert.equal(res.status, 502);
  assert.equal(res.body, 'bad gateway: connect');
  assert.deepEqual(edge.badGatewayCalls, ['connect']);
});
