#!/usr/bin/env node
// Stable TLS/auth/project proxy.  Public descriptors are owned by systemd;
// process replacement cannot remove ports 80/443 from the host.

import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { createCertManager } from '../src/certs.mjs';
import { createLogger } from '../src/log.mjs';
import { PublicationStore, sealPublication } from './publication.mjs';
import { createEdgeRouter } from './router.mjs';

const ACME_PREFIX = '/.well-known/acme-challenge/';
const DRAIN_TIMEOUT_MS = 30_000;

function usage() {
  return `Usage: devcoordinator-edge [options]

Required:
  --route-publication PATH
  --session-secret-file PATH
  --oidc-client-id-file PATH
  --oidc-client-secret-file PATH
  --tls-cert PATH
  --tls-key PATH

Listener mode (choose one):
  --systemd-sockets
  --listen-http PORT --listen-https PORT [--bind-host ADDRESS]

Optional:
  --oidc-issuer URL             default https://accounts.google.com
  --identity-state-dir PATH      retired no-op accepted during state migration
  --acme-webroot PATH            default /var/lib/devcoordinator-edge/acme
  --release-root PATH            default /opt/devcoordinator/releases
  --refresh-ms N                 default 1000
  --log-level LEVEL              debug|info|warn|error
`;
}

export function parseArgs(argv) {
  const result = {
    systemdSockets: false,
    bindHost: '127.0.0.1',
    listenHttp: null,
    listenHttps: null,
    publication: null,
    sessionSecretFile: null,
    oidcIssuer: 'https://accounts.google.com',
    oidcClientIdFile: null,
    oidcClientSecretFile: null,
    tlsCert: null,
    tlsKey: null,
    identityStateDir: '/var/lib/devcoordinator-edge/identity',
    acmeWebroot: '/var/lib/devcoordinator-edge/acme',
    releaseRoot: '/opt/devcoordinator/releases',
    refreshMs: 1000,
    logLevel: 'info',
  };
  const value = (index, flag) => {
    const found = argv[index + 1];
    if (found === undefined || found.startsWith('--')) throw new Error(`${flag} requires one value`);
    return found;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--systemd-sockets') result.systemdSockets = true;
    else if (flag === '--route-publication') result.publication = value(index++, flag);
    else if (flag === '--session-secret-file') result.sessionSecretFile = value(index++, flag);
    else if (flag === '--oidc-issuer') result.oidcIssuer = value(index++, flag);
    else if (flag === '--oidc-client-id-file') result.oidcClientIdFile = value(index++, flag);
    else if (flag === '--oidc-client-secret-file') result.oidcClientSecretFile = value(index++, flag);
    else if (flag === '--tls-cert') result.tlsCert = value(index++, flag);
    else if (flag === '--tls-key') result.tlsKey = value(index++, flag);
    else if (flag === '--identity-state-dir') result.identityStateDir = value(index++, flag);
    else if (flag === '--acme-webroot') result.acmeWebroot = value(index++, flag);
    else if (flag === '--release-root') result.releaseRoot = value(index++, flag);
    else if (flag === '--bind-host') result.bindHost = value(index++, flag);
    else if (flag === '--listen-http') result.listenHttp = Number(value(index++, flag));
    else if (flag === '--listen-https') result.listenHttps = Number(value(index++, flag));
    else if (flag === '--refresh-ms') result.refreshMs = Number(value(index++, flag));
    else if (flag === '--log-level') result.logLevel = value(index++, flag);
    else if (flag === '--help' || flag === '-h') return { help: true };
    else throw new Error(`unknown option: ${flag}`);
  }
  for (const [name, current] of [
    ['--route-publication', result.publication],
    ['--session-secret-file', result.sessionSecretFile],
    ['--oidc-client-id-file', result.oidcClientIdFile],
    ['--oidc-client-secret-file', result.oidcClientSecretFile],
    ['--tls-cert', result.tlsCert],
    ['--tls-key', result.tlsKey],
  ]) {
    if (!current || !path.isAbsolute(current)) throw new Error(`${name} requires one absolute path`);
  }
  try {
    const issuer = new URL(result.oidcIssuer);
    if (!['http:', 'https:'].includes(issuer.protocol)) throw new Error('bad protocol');
  } catch {
    throw new Error('--oidc-issuer must be one http(s) origin');
  }
  for (const [name, current] of [
    ['--identity-state-dir', result.identityStateDir],
    ['--acme-webroot', result.acmeWebroot],
    ['--release-root', result.releaseRoot],
  ]) {
    if (!path.isAbsolute(current)) throw new Error(`${name} requires one absolute path`);
  }
  if (!Number.isInteger(result.refreshMs) || result.refreshMs < 100 || result.refreshMs > 60_000) {
    throw new Error('--refresh-ms must be an integer from 100 through 60000');
  }
  if (!['debug', 'info', 'warn', 'error'].includes(result.logLevel)) throw new Error('--log-level is invalid');
  const direct = result.listenHttp !== null || result.listenHttps !== null;
  if (result.systemdSockets === direct) throw new Error('select exactly one listener mode');
  if (direct) {
    for (const [name, port] of [['--listen-http', result.listenHttp], ['--listen-https', result.listenHttps]]) {
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`${name} must be a TCP port`);
    }
    if (!['127.0.0.1', '::1'].includes(result.bindHost)) {
      throw new Error('direct listener mode is test-only and must bind loopback');
    }
  }
  return result;
}

function inheritedSockets(env = process.env, pid = process.pid) {
  const count = Number(env.LISTEN_FDS);
  if (Number(env.LISTEN_PID) !== pid || ![2, 3].includes(count)) {
    throw new Error('systemd must pass the exact public descriptors and optional publication descriptor');
  }
  const names = String(env.LISTEN_FDNAMES || '').split(':');
  const wanted = count === 2 ? ['http', 'https'] : ['http', 'https', 'publication'];
  if (names.length !== count || new Set(names).size !== count || wanted.some((name) => !names.includes(name))) {
    throw new Error(`systemd descriptor names must be exactly ${wanted.join(', ')}`);
  }
  return Object.fromEntries(names.map((name, index) => [name, 3 + index]));
}

export async function handlePublicationRequest({
  request,
  publicationStore,
  releaseRoot,
}) {
  if (!request || request.schema_version !== 1 || typeof request.operation !== 'string') {
    throw new Error('publication request contract is invalid');
  }
  const expectedFields = request.operation === 'describe'
    ? 'operation,schema_version'
    : request.operation === 'adopt'
      ? 'expected_payload_sha256,operation,publication,schema_version'
      : null;
  if (
    expectedFields === null
    || Object.keys(request).sort().join(',') !== expectedFields
    || (
      request.operation === 'adopt'
      && (
        typeof request.expected_payload_sha256 !== 'string'
        || !/^[a-f0-9]{64}$/.test(request.expected_payload_sha256)
      )
    )
  ) throw new Error('publication request contract is invalid');
  return request.operation === 'describe'
    ? { ok: true, envelope: publicationStore.description() }
    : publicationStore.adopt(
        sealPublication(request.publication, { releaseRoot }),
        { expectedPayloadSha256: request.expected_payload_sha256 },
      );
}

export function createPublicationServer({ publicationStore, releaseRoot, log }) {
  // A successful local AF_UNIX connection is sufficient transport access on
  // this single-developer host. The exact request contract and generation CAS,
  // not peer UID/group/socket mode, are the protocol boundary.
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    let body = '';
    socket.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > 2 * 1024 * 1024) socket.destroy(new Error('proposal is oversized'));
    });
    socket.once('end', () => {
      void (async () => {
        const request = JSON.parse(body);
        const result = await handlePublicationRequest({
          request,
          publicationStore,
          releaseRoot,
        });
        socket.end(`${JSON.stringify(result)}\n`);
      })().catch((error) => {
        log?.warn?.('edge publication proposal rejected', { error: error?.message || String(error) });
        if (!socket.destroyed) socket.end(`${JSON.stringify({ ok: false, error: error?.message || String(error) })}\n`);
      });
    });
    socket.on('error', () => {});
  });
  return server;
}

async function readSessionSecret(file) {
  const handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 16 || metadata.size > 4096) {
      throw new Error('session credential must be one bounded regular file');
    }
    const raw = (await handle.readFile()).toString('utf8').trim();
    if (/^[a-fA-F0-9]{64}$/.test(raw)) return Buffer.from(raw, 'hex');
    const bytes = Buffer.from(raw, 'utf8');
    if (bytes.length < 16) throw new Error('session credential is too short');
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readPrivateTextCredential(file, label) {
  const handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = await handle.stat();
    if (
      !metadata.isFile()
      || metadata.size < 1
      || metadata.size > 16 * 1024
    ) {
      throw new Error(`${label} credential must be one bounded regular file`);
    }
    const value = (await handle.readFile()).toString('utf8').trim();
    if (!value || /[\r\n\0]/.test(value)) throw new Error(`${label} credential is invalid`);
    return value;
  } finally {
    await handle.close();
  }
}

function safeRedirectHost(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 300 || /[\r\n\s]/.test(value)) return null;
  const host = value.toLowerCase().replace(/:\d{1,5}$/, '');
  return /^[a-z0-9.-]+$/.test(host) ? host : null;
}

async function acmeResponse(req, res, webroot) {
  const pathname = new URL(req.url || '/', 'http://localhost').pathname;
  if (!pathname.startsWith(ACME_PREFIX) || !['GET', 'HEAD'].includes(req.method || 'GET')) return false;
  const token = pathname.slice(ACME_PREFIX.length);
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(token)) {
    res.writeHead(404, { 'content-length': '0' });
    res.end();
    return true;
  }
  const file = path.join(webroot, '.well-known', 'acme-challenge', token);
  try {
    const metadata = await fsp.lstat(file);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 64 * 1024) throw new Error('invalid challenge');
    const body = await fsp.readFile(file);
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch {
    res.writeHead(404, { 'content-length': '0' });
    res.end();
  }
  return true;
}

function redirectHandler({ publicationStore, acmeWebroot, log }) {
  return (req, res) => {
    void (async () => {
      if (await acmeResponse(req, res, acmeWebroot)) return;
      const snapshot = publicationStore.current();
      const pathname = new URL(req.url || '/', 'http://localhost').pathname;
      if (['GET', 'HEAD'].includes(req.method || 'GET') && pathname === '/healthz') {
        const body = Buffer.from(`${JSON.stringify({ ok: true, role: 'edge', generation: snapshot.generation })}\n`);
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length, 'cache-control': 'no-store' });
        res.end(req.method === 'HEAD' ? undefined : body);
        return;
      }
      const host = safeRedirectHost(req.headers.host);
      if (!host) {
        res.writeHead(400, { 'content-length': '0' });
        res.end();
        return;
      }
      const status = ['GET', 'HEAD'].includes(req.method || 'GET') ? 301 : 308;
      res.writeHead(status, { location: `https://${host}${String(req.url || '/')}`, 'content-length': '0' });
      res.end();
    })().catch((error) => {
      log?.error?.('plain HTTP handler failed', { error: error?.message || String(error) });
      if (!res.headersSent) res.writeHead(500, { 'content-length': '0' });
      res.end();
    });
  };
}

function trackConnections(server) {
  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.headersTimeout = 65_000;
  server.requestTimeout = 0;
  server.keepAliveTimeout = 65_000;
  return sockets;
}

function listen(server, target) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(target, () => {
      server.removeListener('error', reject);
      resolve(server.address());
    });
  });
}

function closeServer(server, sockets) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    const complete = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    server.close(complete);
    server.closeIdleConnections?.();
    if (settled) return;
    timer = setTimeout(() => {
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections?.();
      complete();
    }, DRAIN_TIMEOUT_MS);
    timer.unref?.();
  });
}

export async function startEdge(options) {
  const log = createLogger(options.logLevel ?? 'info');
  const publicationStore = new PublicationStore({
    file: options.publication,
    log,
    validation: { releaseRoot: options.releaseRoot },
  });
  await publicationStore.loadInitial();
  publicationStore.start({ intervalMs: options.refreshMs });

  const sessionSecret = await readSessionSecret(options.sessionSecretFile);
  const oidcClientId = options.oidcClientId
    ?? (options.oidcClientIdFile
      ? await readPrivateTextCredential(options.oidcClientIdFile, 'OIDC client ID')
      : '');
  const oidcClientSecret = options.oidcClientSecret
    ?? (options.oidcClientSecretFile
      ? await readPrivateTextCredential(options.oidcClientSecretFile, 'OIDC client secret')
      : '');
  const router = await createEdgeRouter({
    publicationStore,
    sessionSecret,
    oidcIssuer: options.oidcIssuer ?? 'https://accounts.google.com',
    oidcClientId,
    oidcClientSecret,
    log,
  });
  const certManager = await createCertManager({ certFile: options.tlsCert, keyFile: options.tlsKey, log });
  const httpsServer = https.createServer({
    ...certManager.getCredentials(),
    SNICallback: (_servername, callback) => callback(null, certManager.getSecureContext()),
  }, router.handleRequest);
  certManager.onSwap(() => httpsServer.setSecureContext(certManager.getCredentials()));
  httpsServer.on('upgrade', router.handleUpgrade);
  const httpServer = http.createServer(redirectHandler({ publicationStore, acmeWebroot: options.acmeWebroot, log }));
  const publicationServer = createPublicationServer({
    publicationStore,
    releaseRoot: options.releaseRoot,
    log,
  });
  const httpsSockets = trackConnections(httpsServer);
  const httpSockets = trackConnections(httpServer);
  let targets;
  if (options.systemdSockets) {
    const inherited = inheritedSockets();
    targets = { http: { fd: inherited.http }, https: { fd: inherited.https } };
    if (inherited.publication) targets.publication = { fd: inherited.publication };
  } else {
    targets = {
      http: { port: options.listenHttp, host: options.bindHost },
      https: { port: options.listenHttps, host: options.bindHost },
    };
  }
  try {
    const [httpAddress, httpsAddress] = await Promise.all([
      listen(httpServer, targets.http),
      listen(httpsServer, targets.https),
      ...(targets.publication ? [listen(publicationServer, targets.publication)] : []),
    ]);
    log.info('stable edge ready', {
      generation: publicationStore.current().generation,
      http: httpAddress,
      https: httpsAddress,
      socketActivated: Boolean(options.systemdSockets),
    });
  } catch (error) {
    httpServer.close();
    httpsServer.close();
    publicationServer.close();
    router.close();
    certManager.close();
    publicationStore.close();
    throw error;
  }

  let closing = null;
  async function close() {
    if (closing) return closing;
    closing = (async () => {
      publicationStore.close();
      await Promise.all([
        closeServer(httpServer, httpSockets),
        closeServer(httpsServer, httpsSockets),
        ...(targets.publication ? [new Promise((resolve) => publicationServer.close(resolve))] : []),
      ]);
      router.close();
      certManager.close();
    })();
    return closing;
  }
  return { close, publicationStore, httpServer, httpsServer, publicationServer };
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n${usage()}`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(usage());
    return;
  }
  const edge = await startEdge(options);
  let stopping = false;
  const stop = (signal) => {
    if (stopping) return;
    stopping = true;
    void edge.close().then(() => {
      process.stdout.write(`${JSON.stringify({ level: 'info', message: 'edge stopped', signal })}\n`);
    }, (error) => {
      process.stderr.write(`${error?.stack || String(error)}\n`);
      process.exitCode = 1;
    });
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}

const direct = process.argv[1] && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url;
if (direct) {
  main().catch((error) => {
    process.stderr.write(`${error?.stack || String(error)}\n`);
    process.exit(1);
  });
}
