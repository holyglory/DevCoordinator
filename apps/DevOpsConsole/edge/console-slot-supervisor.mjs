#!/usr/bin/env node
// Single-writer Console slot supervisor.
//
// Every release slot exposes a warm TLS proxy. Exactly one slot owns the
// writer lease and therefore exactly one mutable Console child. Standby slots
// proxy to the retained active-slot pointer. During promotion, new requests
// are queued while existing HTTP streams drain, the old child is demoted, and
// the candidate becomes healthy before queued requests are released.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { loadConfig } from '../src/config.mjs';
import { createCertManager } from '../src/certs.mjs';
import { createLogger } from '../src/log.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONSOLE_ENTRY = path.resolve(HERE, '../bin/devops-console.mjs');
const RELEASE_RE = /^[a-f0-9]{64}$/;
const MAX_CONTROL_BYTES = 64 * 1024;
const MAX_QUEUED_REQUESTS = 256;
const DEFAULT_TRANSITION_TIMEOUT_MS = 30_000;

function fail(message) {
  throw new Error(message);
}

function requiredEnv(name, env = process.env) {
  const value = String(env[name] ?? '').trim();
  if (!value) fail(`${name} is required`);
  return value;
}

function exactPort(value, label) {
  if (!/^\d{1,5}$/.test(String(value ?? ''))) fail(`${label} must be one TCP port`);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) fail(`${label} is out of range`);
  return port;
}

function processStartTime(pid) {
  try {
    const value = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const close = value.lastIndexOf(')');
    if (close < 0) return null;
    const fields = value.slice(close + 2).trim().split(/\s+/);
    return fields[19] || null;
  } catch {
    return null;
  }
}

async function atomicJson(file, value) {
  const parent = path.dirname(file);
  await fsp.mkdir(parent, { recursive: true, mode: 0o700 });
  const temporary = path.join(parent, `.${path.basename(file)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  const handle = await fsp.open(temporary, 'wx', 0o600);
  try {
    await handle.writeFile(payload, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fsp.chmod(temporary, 0o600);
  await fsp.rename(temporary, file);
  const directory = await fsp.open(parent, 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export class WriterLease {
  constructor({ directory, releaseDigest }) {
    this.directory = directory;
    this.releaseDigest = releaseDigest;
    this.token = null;
  }

  async acquire() {
    if (this.token) return;
    const token = crypto.randomUUID();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        await fsp.mkdir(this.directory, { mode: 0o700 });
        const startTime = processStartTime(process.pid);
        if (!startTime) fail('cannot prove Console supervisor process identity');
        await atomicJson(path.join(this.directory, 'owner.json'), {
          schema_version: 1,
          pid: process.pid,
          process_start_time: startTime,
          release_digest: this.releaseDigest,
          token,
        });
        this.token = token;
        return;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }

      let owner;
      try {
        owner = JSON.parse(await fsp.readFile(path.join(this.directory, 'owner.json'), 'utf8'));
      } catch {
        fail('Console writer lease exists without valid owner evidence');
      }
      const live = Number.isInteger(owner?.pid)
        && owner.pid > 1
        && typeof owner.process_start_time === 'string'
        && processStartTime(owner.pid) === owner.process_start_time;
      if (live) fail(`Console writer lease is held by live pid ${owner.pid}`);
      const stale = `${this.directory}.stale.${crypto.randomUUID()}`;
      try {
        await fsp.rename(this.directory, stale);
      } catch (error) {
        if (error?.code === 'ENOENT') continue;
        throw error;
      }
      await fsp.rm(stale, { recursive: true, force: false });
    }
    fail('Console writer lease could not be acquired');
  }

  async release() {
    if (!this.token) return;
    const ownerFile = path.join(this.directory, 'owner.json');
    const owner = JSON.parse(await fsp.readFile(ownerFile, 'utf8'));
    if (owner?.token !== this.token || owner?.pid !== process.pid) {
      fail('Console writer lease identity changed before release');
    }
    await fsp.unlink(ownerFile);
    await fsp.rmdir(this.directory);
    this.token = null;
  }
}

function normalizeActivePointer(value) {
  if (
    !value
    || value.schema_version !== 1
    || typeof value.release_digest !== 'string'
    || !RELEASE_RE.test(value.release_digest)
    || !Number.isInteger(value.port)
    || value.port < 1024
    || value.port > 65535
  ) return null;
  return { releaseDigest: value.release_digest, port: value.port };
}

async function readActivePointer(file) {
  try {
    const info = await fsp.lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) return null;
    return normalizeActivePointer(JSON.parse(await fsp.readFile(file, 'utf8')));
  } catch {
    return null;
  }
}

function isLongLivedHttpResponse(response) {
  const contentType = String(response.headers['content-type'] || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
  return contentType === 'text/event-stream';
}

function proxyRequest({ req, res, target, config, lifecycle }) {
  const transport = target.scheme === 'https' ? https : http;
  let upstreamResponse = null;
  const upstream = transport.request({
    host: '127.0.0.1',
    port: target.port,
    method: req.method,
    path: req.url,
    headers: {
      ...req.headers,
      host: config.consoleHost,
      'x-forwarded-for': req.socket.remoteAddress || '127.0.0.1',
      'x-forwarded-host': config.consoleHost,
      'x-forwarded-proto': 'https',
    },
    ...(target.scheme === 'https' ? {
      rejectUnauthorized: true,
      servername: config.consoleHost,
    } : {}),
  });
  lifecycle.setCloser(() => {
    upstreamResponse?.unpipe(res);
    upstreamResponse?.destroy();
    upstream.destroy();
    if (!res.destroyed && !res.writableEnded) res.end();
  });
  upstream.on('response', (response) => {
    upstreamResponse = response;
    if (isLongLivedHttpResponse(response)) lifecycle.markLongLived();
    res.writeHead(response.statusCode || 502, response.headers);
    response.pipe(res);
    response.once('end', lifecycle.finish);
    response.once('close', () => {
      if (!res.destroyed && !res.writableEnded) res.end();
      lifecycle.finish();
    });
    response.once('error', () => {
      if (!res.destroyed) res.destroy();
      lifecycle.finish();
    });
  });
  upstream.once('error', (error) => {
    lifecycle.finish();
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      res.end(`Console backend unavailable: ${error.code || 'upstream_error'}`);
    } else {
      res.destroy(error);
    }
  });
  req.once('aborted', () => {
    upstream.destroy();
    lifecycle.finish();
  });
  res.once('close', () => {
    if (!res.writableEnded) {
      upstreamResponse?.destroy();
      upstream.destroy();
    }
    lifecycle.finish();
  });
  req.pipe(upstream);
}

function proxyUpgrade({ req, socket: client, head, target, config, lifecycle }) {
  const transport = target.scheme === 'https' ? https : http;
  let upstream = null;
  const upstreamRequest = transport.request({
    host: '127.0.0.1',
    port: target.port,
    method: req.method,
    path: req.url,
    headers: { ...req.headers, host: config.consoleHost, 'x-forwarded-proto': 'https' },
    ...(target.scheme === 'https' ? { rejectUnauthorized: true, servername: config.consoleHost } : {}),
  });
  lifecycle.setCloser(() => {
    upstreamRequest.destroy();
    upstream?.destroy();
    client.destroy();
  });
  upstreamRequest.once('upgrade', (upstreamResponse, upgraded, upstreamHead) => {
    upstream = upgraded;
    lifecycle.markLongLived();
    const status = upstreamResponse.statusCode || 101;
    const lines = [`HTTP/1.1 ${status} ${upstreamResponse.statusMessage || 'Switching Protocols'}`];
    for (const [name, value] of Object.entries(upstreamResponse.headers)) {
      if (Array.isArray(value)) for (const item of value) lines.push(`${name}: ${item}`);
      else if (value !== undefined) lines.push(`${name}: ${value}`);
    }
    client.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (upstreamHead.length) client.write(upstreamHead);
    if (head.length) upstream.write(head);
    client.pipe(upstream).pipe(client);
    client.once('close', () => {
      upstream.destroy();
      lifecycle.finish();
    });
    upstream.once('close', () => {
      client.destroy();
      lifecycle.finish();
    });
    client.once('error', () => {
      upstream.destroy();
      lifecycle.finish();
    });
    upstream.once('error', () => {
      client.destroy();
      lifecycle.finish();
    });
  });
  upstreamRequest.once('response', (upstreamResponse) => {
    client.write(`HTTP/1.1 ${upstreamResponse.statusCode || 502} ${upstreamResponse.statusMessage || ''}\r\n\r\n`);
    client.destroy();
    lifecycle.finish();
  });
  upstreamRequest.once('error', () => {
    client.destroy();
    lifecycle.finish();
  });
  client.once('close', () => {
    upstreamRequest.destroy();
    upstream?.destroy();
    lifecycle.finish();
  });
  upstreamRequest.end();
}

async function waitForInner(port, timeoutMs, servername) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const status = await new Promise((resolve, reject) => {
        const request = https.get({
          host: '127.0.0.1',
          port,
          path: '/healthz',
          timeout: 500,
          rejectUnauthorized: true,
          servername,
        }, (response) => {
          response.resume();
          response.once('end', () => resolve(response.statusCode));
        });
        request.once('timeout', () => request.destroy(new Error('timeout')));
        request.once('error', reject);
      });
      if (status === 200) return;
    } catch {
      // Candidate is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail('Console child did not become healthy before the promotion deadline');
}

function controlCall(socketPath, request, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let body = '';
    const timer = setTimeout(() => socket.destroy(new Error('control timeout')), timeoutMs);
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.end(`${JSON.stringify(request)}\n`));
    socket.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_CONTROL_BYTES) socket.destroy(new Error('oversized control reply'));
    });
    socket.once('error', reject);
    socket.once('close', () => {
      clearTimeout(timer);
      try {
        const response = JSON.parse(body);
        if (response?.ok !== true) reject(new Error(response?.error || 'control operation failed'));
        else resolve(response);
      } catch (error) {
        reject(error);
      }
    });
  });
}

export async function runConsoleSlot({
  argv = process.argv.slice(2),
  env = process.env,
  consoleEntry = CONSOLE_ENTRY,
} = {}) {
  if (typeof consoleEntry !== 'string' || !path.isAbsolute(consoleEntry)) {
    fail('Console child entry must be an absolute path');
  }
  let consoleEntryInfo;
  try {
    consoleEntryInfo = await fsp.lstat(consoleEntry);
  } catch {
    fail('Console child entry is unavailable');
  }
  if (!consoleEntryInfo.isFile() || consoleEntryInfo.isSymbolicLink()) {
    fail('Console child entry must be a regular file');
  }
  let envFile;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--env-file') envFile = argv[++index];
    else fail(`unknown Console slot argument: ${argv[index]}`);
  }
  if (!envFile) fail('--env-file is required');
  const releaseDigest = requiredEnv('DEVCOORDINATOR_RELEASE_DIGEST', env);
  if (!RELEASE_RE.test(releaseDigest)) fail('DEVCOORDINATOR_RELEASE_DIGEST is invalid');
  const innerPort = exactPort(requiredEnv('DEVCOORDINATOR_CONSOLE_INNER_PORT', env), 'inner port');
  const controlSocket = requiredEnv('DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET', env);
  const stateRoot = path.resolve(requiredEnv('DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE', env));
  const runtimeRoot = path.resolve(requiredEnv('DEVCOORDINATOR_CONSOLE_RUNTIME', env));
  const bootstrapActive = String(env.DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE || '') === '1';
  const config = loadConfig({ envFile, env });
  if (config.devInsecureHttp) fail('Console slot outer listener requires TLS');
  if (innerPort === config.httpsPort) fail('Console inner and outer ports must differ');
  const log = createLogger(config.logLevel);
  const activePointerFile = path.join(stateRoot, 'active-slot.json');
  const writerLease = new WriterLease({
    directory: path.join(runtimeRoot, 'writer.lock'),
    releaseDigest,
  });
  await fsp.mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  await fsp.mkdir(stateRoot, { recursive: true, mode: 0o700 });

  let mode = 'standby';
  let child = null;
  let inFlight = 0;
  let drainBlocking = 0;
  let transition = Promise.resolve();
  const queued = [];
  const longLived = new Set();

  const selfTarget = { scheme: 'https', port: config.httpsPort };
  const innerTarget = { scheme: 'https', port: innerPort };

  async function target() {
    if (mode === 'active') return innerTarget;
    const pointer = await readActivePointer(activePointerFile);
    if (!pointer || pointer.releaseDigest === releaseDigest) return null;
    return { scheme: 'https', port: pointer.port };
  }

  function beginLifecycle() {
    let finished = false;
    let isLongLived = false;
    let closer = null;
    inFlight += 1;
    drainBlocking += 1;
    const lifecycle = {
      setCloser(callback) {
        closer = callback;
      },
      markLongLived() {
        if (finished || isLongLived) return;
        isLongLived = true;
        drainBlocking -= 1;
        longLived.add(lifecycle);
      },
      finish() {
        if (finished) return;
        finished = true;
        inFlight -= 1;
        if (isLongLived) longLived.delete(lifecycle);
        else drainBlocking -= 1;
      },
      retire() {
        if (finished || !isLongLived) return;
        try {
          closer?.();
        } finally {
          lifecycle.finish();
        }
      },
    };
    return lifecycle;
  }

  function retireLongLived() {
    for (const lifecycle of [...longLived]) lifecycle.retire();
  }

  async function dispatch(item) {
    const selected = await target();
    if (!selected) {
      if (item.kind === 'upgrade') item.socket.destroy();
      else {
        item.res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '1' });
        item.res.end('Console slot is not active');
      }
      return;
    }
    const lifecycle = beginLifecycle();
    if (item.kind === 'upgrade') {
      item.socket.resume();
      proxyUpgrade({ ...item, target: selected, config, lifecycle });
    } else {
      item.req.resume();
      proxyRequest({ ...item, target: selected, config, lifecycle });
    }
  }

  function enqueue(item) {
    if (queued.length >= MAX_QUEUED_REQUESTS) {
      if (item.kind === 'upgrade') item.socket.destroy();
      else {
        item.res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '1' });
        item.res.end('Console promotion queue is full');
      }
      return;
    }
    if (item.kind === 'upgrade') item.socket.pause();
    else item.req.pause();
    queued.push(item);
  }

  async function flushQueue() {
    const pending = queued.splice(0);
    await Promise.all(pending.map((item) => dispatch(item)));
  }

  async function waitForDrain(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (drainBlocking > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    if (drainBlocking > 0) fail(`${drainBlocking} Console request(s) have not drained`);
  }

  async function startChild(timeoutMs) {
    if (child) return;
    child = spawn(process.execPath, [consoleEntry, '--env-file', envFile], {
      stdio: 'inherit',
      env: {
        ...env,
        DEV_HTTP: '0',
        HTTP_PORT: '0',
        HTTPS_PORT: String(innerPort),
        PUBLIC_CONSOLE_ORIGIN: `https://${config.consoleHost}`,
        COORDINATOR_AUTOSTART: '0',
        COORDINATOR_REGISTRATION_REQUIRED: '0',
      },
    });
    const launched = child;
    launched.once('exit', (code, signal) => {
      if (child !== launched) return;
      child = null;
      if (mode === 'active') {
        log.error('active Console child exited', { code, signal });
        void writerLease.release().finally(() => process.exit(1));
      }
    });
    try {
      await waitForInner(innerPort, timeoutMs, config.consoleHost);
    } catch (error) {
      launched.kill('SIGTERM');
      child = null;
      throw error;
    }
  }

  async function stopChild(timeoutMs) {
    if (!child) return;
    const stopping = child;
    const ended = new Promise((resolve) => stopping.once('exit', resolve));
    child = null;
    stopping.kill('SIGTERM');
    await Promise.race([
      ended,
      new Promise((resolve) => setTimeout(resolve, Math.min(timeoutMs, 10_000))),
    ]);
    if (stopping.exitCode === null && stopping.signalCode === null) stopping.kill('SIGKILL');
  }

  async function becomeActive(timeoutMs) {
    await writerLease.acquire();
    try {
      await startChild(timeoutMs);
      await atomicJson(activePointerFile, {
        schema_version: 1,
        release_digest: releaseDigest,
        port: config.httpsPort,
        published_at: new Date().toISOString(),
      });
      mode = 'active';
    } catch (error) {
      await stopChild(timeoutMs);
      await writerLease.release();
      throw error;
    }
  }

  async function demote(timeoutMs, { holdForHandoff = false } = {}) {
    if (mode !== 'active') return;
    mode = 'quiescing';
    try {
      await waitForDrain(timeoutMs);
      retireLongLived();
      await stopChild(timeoutMs);
      await writerLease.release();
      // During a coordinated promotion the old slot must keep accepting and
      // queueing traffic until the candidate has acquired the writer lease
      // and atomically published its active pointer.  Flushing here would
      // resolve the still-old pointer back to this now-childless slot and
      // return a transient 503.
      if (holdForHandoff) return;
      mode = 'standby';
      await flushQueue();
    } catch (error) {
      mode = child ? 'active' : 'standby';
      await flushQueue();
      throw error;
    }
  }

  async function completeDemotion() {
    if (mode !== 'quiescing' || child) fail('Console demotion is not awaiting handoff');
    mode = 'standby';
    await flushQueue();
  }

  async function promote(oldControl, timeoutMs) {
    if (mode === 'active') return;
    mode = 'quiescing';
    try {
      await waitForDrain(timeoutMs);
      if (oldControl) {
        await controlCall(
          oldControl,
          { operation: 'demote', hold_for_handoff: true, timeout_ms: timeoutMs },
          timeoutMs + 1000,
        );
      }
      await becomeActive(timeoutMs);
      if (oldControl) {
        await controlCall(
          oldControl,
          { operation: 'complete-demotion', timeout_ms: timeoutMs },
          timeoutMs + 1000,
        );
      }
      await flushQueue();
    } catch (error) {
      // A failure after this candidate acquired the writer (for example, an
      // unreachable old control socket during demotion completion) must not
      // leave two mutable children or a leaked writer lease before rollback.
      if (child || mode === 'active') {
        mode = 'quiescing';
        try {
          await waitForDrain(timeoutMs);
          retireLongLived();
          await stopChild(timeoutMs);
          await writerLease.release();
        } catch (cleanupError) {
          log.error('failed Console candidate cleanup before rollback', {
            error: cleanupError.message,
          });
        }
      }
      if (oldControl) {
        try {
          await controlCall(oldControl, { operation: 'promote', timeout_ms: timeoutMs }, timeoutMs + 1000);
        } catch (rollbackError) {
          log.error('Console writer rollback failed', { error: rollbackError.message });
        }
      }
      mode = 'standby';
      await flushQueue();
      throw error;
    }
  }

  const initialPointer = await readActivePointer(activePointerFile);
  if (bootstrapActive || initialPointer?.releaseDigest === releaseDigest) {
    await becomeActive(DEFAULT_TRANSITION_TIMEOUT_MS);
  }

  const certManager = await createCertManager({
    certFile: config.tlsCertFile,
    keyFile: config.tlsKeyFile,
    log,
  });
  const tlsServer = https.createServer({
    ...certManager.getCredentials(),
    SNICallback: (_name, callback) => callback(null, certManager.getSecureContext()),
  }, (req, res) => {
    if (req.url === '/_devcoordinator/slot-health') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(`${JSON.stringify({
        ok: true,
        mode,
        release_digest: releaseDigest,
        in_flight: inFlight,
        drain_blocking: drainBlocking,
        long_lived: longLived.size,
        queued: queued.length,
      })}\n`);
      return;
    }
    const item = { kind: 'request', req, res };
    if (mode === 'quiescing') enqueue(item);
    else void dispatch(item);
  });
  tlsServer.on('upgrade', (req, socket, head) => {
    const item = { kind: 'upgrade', req, socket, head };
    if (mode === 'quiescing') enqueue(item);
    else void dispatch(item);
  });
  tlsServer.headersTimeout = 65_000;
  tlsServer.requestTimeout = 0;
  tlsServer.keepAliveTimeout = 65_000;
  await new Promise((resolve, reject) => {
    tlsServer.once('error', reject);
    tlsServer.listen(config.httpsPort, '127.0.0.1', resolve);
  });

  await fsp.mkdir(path.dirname(controlSocket), { recursive: true, mode: 0o755 });
  try { await fsp.unlink(controlSocket); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  const controlServer = net.createServer({ allowHalfOpen: true }, (socket) => {
    socket.setEncoding('utf8');
    let body = '';
    socket.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_CONTROL_BYTES) socket.destroy();
    });
    socket.once('end', () => {
      transition = transition.then(async () => {
        const request = JSON.parse(body);
        const timeoutMs = Number.isInteger(request.timeout_ms)
          ? Math.max(1000, Math.min(120_000, request.timeout_ms))
          : DEFAULT_TRANSITION_TIMEOUT_MS;
        if (request.operation === 'status') return;
        if (request.operation === 'promote') await promote(request.old_control || null, timeoutMs);
        else if (request.operation === 'demote') {
          await demote(timeoutMs, { holdForHandoff: request.hold_for_handoff === true });
        } else if (request.operation === 'complete-demotion') await completeDemotion();
        else fail('unknown Console slot control operation');
      });
      void transition.then(
        () => socket.end(`${JSON.stringify({
          ok: true,
          mode,
          release_digest: releaseDigest,
          port: config.httpsPort,
          in_flight: inFlight,
          drain_blocking: drainBlocking,
          long_lived: longLived.size,
        })}\n`),
        (error) => socket.end(`${JSON.stringify({
          ok: false,
          error: error.message,
          mode,
          in_flight: inFlight,
          drain_blocking: drainBlocking,
          long_lived: longLived.size,
        })}\n`),
      );
    });
  });
  await new Promise((resolve, reject) => {
    controlServer.once('error', reject);
    controlServer.listen(controlSocket, resolve);
  });
  // Any local developer account may coordinate a verified slot transition.
  // The bounded operation contract, not Unix ownership/mode, is the gate.
  await fsp.chmod(controlSocket, 0o666);

  let closing = false;
  async function close() {
    if (closing) return;
    closing = true;
    await new Promise((resolve) => controlServer.close(resolve));
    retireLongLived();
    await new Promise((resolve) => tlsServer.close(resolve));
    await stopChild(10_000);
    await writerLease.release();
    certManager.close();
    try { await fsp.unlink(controlSocket); } catch { /* already removed */ }
  }
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.once(signal, () => void close().then(() => process.exit(0), () => process.exit(1)));
  }
  log.info('Console slot supervisor ready', {
    releaseDigest,
    port: config.httpsPort,
    innerPort,
    mode,
    controlSocket,
  });
  return { close, mode: () => mode, port: config.httpsPort, controlSocket };
}

const direct = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (direct) {
  runConsoleSlot().catch((error) => {
    process.stderr.write(`${error?.stack || error}\n`);
    process.exit(1);
  });
}
