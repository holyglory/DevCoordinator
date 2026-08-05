import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DEV_CERT, DEV_KEY, ensureDevCert } from './helpers/dev-cert.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, '..');
const SUPERVISOR = path.join(APP, 'edge', 'console-slot-supervisor.mjs');
const FIXTURE_SUPERVISOR = path.join(APP, 'test', 'helpers', 'console-slot-fixture-supervisor.mjs');
const CONTROL = path.join(APP, 'edge', 'console-slot-control.mjs');
const RELEASE_A = 'a'.repeat(64);
const RELEASE_B = 'b'.repeat(64);
const SECRET = 'ab'.repeat(32);
// Promotion deliberately queues new HTTPS requests while the old child drains
// and the candidate publishes its pointer.  The generic one-second helper
// timeout is therefore shorter than a valid handoff under a parallel test
// load.  Keep the continuity request bounded above the complete cutover, and
// independently cap the cutover itself so a stalled queue cannot pass.
const CONTINUITY_PROBE_TIMEOUT_MS = 10_000;
const FIXTURE_PROMOTION_MAX_MS = 8_000;

async function reservePort() {
  // Do not ask the kernel for port 0 here.  Those values come from the
  // ephemeral client-port range; the Console performs an outbound
  // Coordinator probe before binding its listener, so the kernel can reuse
  // the just-released port for that client socket and make the subsequent
  // listen fail with EADDRINUSE.  Reserve a non-ephemeral development port
  // instead and retain it until the owning slot spawns.
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const server = net.createServer();
    const port = randomInt(12_000, 28_000);
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
      });
      return {
        port,
        close: () => new Promise((resolve, reject) => server.close((error) => {
          if (error) reject(error);
          else resolve();
        })),
      };
    } catch (error) {
      if (error?.code !== 'EADDRINUSE') throw error;
    }
  }
  throw new Error('could not reserve a non-ephemeral Console fixture port');
}

function startSlot({ envFile, env, fixture = false }) {
  const output = [];
  const child = spawn(process.execPath, [fixture ? FIXTURE_SUPERVISOR : SUPERVISOR, '--env-file', envFile], {
    env: { ...process.env, ...env, NODE_EXTRA_CA_CERTS: DEV_CERT },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (chunk) => output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => output.push(chunk.toString()));
  return { child, output };
}

async function openSse(port) {
  const ca = await fsp.readFile(DEV_CERT);
  return new Promise((resolve, reject) => {
    const request = https.get({
      host: '127.0.0.1',
      port,
      path: '/stream',
      ca,
      servername: 'console.vr.ae',
    }, (response) => {
      const closed = new Promise((closedResolve) => response.once('close', closedResolve));
      response.once('data', () => resolve({ request, response, closed }));
      response.once('error', reject);
    });
    request.once('error', reject);
  });
}

async function waitCounters(port, predicate, label) {
  const deadline = Date.now() + 5_000;
  let status = null;
  while (Date.now() < deadline) {
    status = await httpsJson(port);
    if (predicate(status)) return status;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`${label}: ${JSON.stringify(status)}`);
}

async function httpsJson(port, pathname = '/_devcoordinator/slot-health', timeout = 1000) {
  const ca = await fsp.readFile(DEV_CERT);
  return new Promise((resolve, reject) => {
    const request = https.get({
      host: '127.0.0.1',
      port,
      path: pathname,
      ca,
      servername: 'console.vr.ae',
      timeout,
    }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.once('end', () => {
        if (response.statusCode !== 200) reject(new Error(`HTTP ${response.statusCode}: ${body}`));
        else {
          try { resolve(JSON.parse(body)); } catch { resolve(body); }
        }
      });
    });
    request.once('timeout', () => request.destroy(new Error('timeout')));
    request.once('error', reject);
  });
}

async function waitHealth(port, expectedMode, child, output) {
  const deadline = Date.now() + 30_000;
  let last;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`slot exited ${child.exitCode}:\n${output.join('')}`);
    try {
      const status = await httpsJson(port);
      if (status.mode === expectedMode) return status;
      last = new Error(`mode is ${status.mode}`);
    } catch (error) {
      last = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`slot did not reach ${expectedMode}: ${last?.message}\n${output.join('')}`);
}

async function control(args, environment) {
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CONTROL, ...args], {
      env: { ...process.env, ...environment },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('exit', (code) => {
      if (code === 0) resolve(JSON.parse(stdout));
      else reject(new Error(stderr || stdout || `control exited ${code}`));
    });
  });
  assert.equal(result.ok, true);
  return result;
}

async function stopSlot(slot) {
  if (slot.child.exitCode !== null) return;
  slot.child.kill('SIGTERM');
  await Promise.race([
    new Promise((resolve) => slot.child.once('exit', resolve)),
    new Promise((resolve) => setTimeout(resolve, 15_000)),
  ]);
  if (slot.child.exitCode === null && slot.child.signalCode === null) slot.child.kill('SIGKILL');
}

test('Console cutover keeps a warm proxy while transferring the sole mutable child', async (t) => {
  ensureDevCert();
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'console-slot-cutover-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const envFile = path.join(root, 'console.env');
  await fsp.writeFile(envFile, '', 'utf8');
  // Reserve every listener until the exact slot that owns it is ready to
  // spawn.  The complete Console suite runs test files concurrently; merely
  // asking the kernel for a free port and closing it immediately leaves a
  // large race in which another fixture can claim the same port.
  const reservations = await Promise.all([
    reservePort(), reservePort(), reservePort(), reservePort(),
  ]);
  t.after(() => Promise.all(reservations.map((reservation) => reservation.close().catch(() => {}))));
  const ports = reservations.map((reservation) => reservation.port);
  assert.equal(new Set(ports).size, 4);
  const runtime = path.join(root, 'runtime');
  const supervisorState = path.join(root, 'supervisor');
  const appState = path.join(root, 'app-state');
  const common = {
    DOMAIN: 'vr.ae',
    CONSOLE_SUBDOMAIN: 'console',
    SESSION_SECRET: SECRET,
    TLS_CERT_FILE: DEV_CERT,
    TLS_KEY_FILE: DEV_KEY,
    HTTP_PORT: '0',
    DEV_HTTP: '0',
    STATE_DIR: appState,
    ACME_WEBROOT: path.join(root, 'acme'),
    COORDINATOR_AUTOSTART: '0',
    COORDINATOR_REGISTRATION_REQUIRED: '0',
    COORDINATOR_URL: 'http://127.0.0.1:29876',
    DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE: supervisorState,
    DEVCOORDINATOR_CONSOLE_RUNTIME: runtime,
    LOG_LEVEL: 'error',
  };
  // Keep fixture AF_UNIX names comfortably below sockaddr_un.sun_path; the
  // production /run paths include the full digest and remain below the Linux
  // bound as asserted by the release renderer.
  const controlA = path.join(runtime, 'a.sock');
  const controlB = path.join(runtime, 'b.sock');
  await Promise.all([reservations[0].close(), reservations[1].close()]);
  const slotA = startSlot({
    envFile,
    fixture: true,
    env: {
      ...common,
      HTTPS_PORT: String(ports[0]),
      DEVCOORDINATOR_RELEASE_DIGEST: RELEASE_A,
      DEVCOORDINATOR_CONSOLE_INNER_PORT: String(ports[1]),
      DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET: controlA,
      DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE: '1',
    },
  });
  await waitHealth(ports[0], 'active', slotA.child, slotA.output);

  await Promise.all([reservations[2].close(), reservations[3].close()]);
  const slotB = startSlot({
    envFile,
    fixture: true,
    env: {
      ...common,
      HTTPS_PORT: String(ports[2]),
      DEVCOORDINATOR_RELEASE_DIGEST: RELEASE_B,
      DEVCOORDINATOR_CONSOLE_INNER_PORT: String(ports[3]),
      DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET: controlB,
      DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE: '0',
    },
  });
  t.after(() => Promise.all([stopSlot(slotA), stopSlot(slotB)]));

  await waitHealth(ports[2], 'standby', slotB.child, slotB.output);
  const proxiedBefore = await httpsJson(ports[2], '/healthz');
  assert.equal(proxiedBefore, 'ok');

  // A standby slot may already be carrying SSE traffic to the active slot.
  // That stream cannot be migrated to a different child, but it must not
  // veto promotion.  Ordinary requests still drain before the stream is
  // cleanly retired at the old active boundary.
  const retainedStream = await openSse(ports[2]);
  await waitCounters(
    ports[2],
    (status) => status.long_lived === 1 && status.drain_blocking === 0,
    'standby did not classify its SSE stream',
  );
  await waitCounters(
    ports[0],
    (status) => status.long_lived === 1 && status.drain_blocking === 0,
    'active slot did not classify the forwarded SSE stream',
  );
  const delayed = httpsJson(ports[2], '/delay?ms=800', 3_000);
  await waitCounters(
    ports[2],
    (status) => status.long_lived === 1 && status.drain_blocking === 1,
    'standby did not retain the ordinary request in its drain set',
  );

  const continuity = {
    stopped: false,
    failures: [],
    counts: new Map([[ports[0], 0], [ports[2], 0]]),
  };
  async function continuousProbe(port) {
    while (!continuity.stopped) {
      try {
        const response = await httpsJson(
          port,
          '/healthz',
          CONTINUITY_PROBE_TIMEOUT_MS,
        );
        if (response !== 'ok') throw new Error(`unexpected health body: ${response}`);
        continuity.counts.set(port, continuity.counts.get(port) + 1);
      } catch (error) {
        continuity.failures.push({ port, message: error.message, code: error.code ?? null });
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  const probes = [continuousProbe(ports[0]), continuousProbe(ports[2])];

  let promoted;
  const promotionStarted = Date.now();
  try {
    promoted = await control([
      'promote', '--socket', controlB, '--old-socket', controlA, '--timeout-seconds', '45',
    ]);
  } catch (error) {
    throw new Error(`${error.message}\nslot A:\n${slotA.output.join('')}\nslot B:\n${slotB.output.join('')}`);
  }
  const promotionElapsed = Date.now() - promotionStarted;
  assert.deepEqual(await delayed, { ok: true, delay_ms: 800 });
  assert.ok(promotionElapsed >= 500, `promotion skipped ordinary request drain (${promotionElapsed}ms)`);
  assert.ok(
    promotionElapsed < FIXTURE_PROMOTION_MAX_MS,
    `promotion exceeded its fixture latency budget (${promotionElapsed}ms)`,
  );
  await Promise.race([
    retainedStream.closed,
    new Promise((_, reject) => setTimeout(() => reject(new Error('retained SSE stream did not close')), 2_000)),
  ]);
  assert.equal(promoted.mode, 'active');
  await waitHealth(ports[2], 'active', slotB.child, slotB.output);
  await waitHealth(ports[0], 'standby', slotA.child, slotA.output);
  const proxiedAfter = await httpsJson(ports[0], '/healthz');
  assert.equal(proxiedAfter, 'ok');
  continuity.stopped = true;
  await Promise.all(probes);
  assert.deepEqual(continuity.failures, [], 'Console slot promotion interrupted HTTPS traffic');
  assert.ok(continuity.counts.get(ports[0]) > 0, 'old slot was not continuously probed');
  assert.ok(continuity.counts.get(ports[2]) > 0, 'new slot was not continuously probed');
  await waitCounters(
    ports[0],
    (status) => status.in_flight === 0 && status.drain_blocking === 0 && status.long_lived === 0,
    'old slot retained stream accounting after promotion',
  );
  await waitCounters(
    ports[2],
    (status) => status.in_flight === 0 && status.drain_blocking === 0 && status.long_lived === 0,
    'new slot retained stream accounting after promotion',
  );

  // A downstream abort must tear the stream down in both the standby proxy
  // and active slot; otherwise the next promotion would inherit ghost work.
  const abortedStream = await openSse(ports[0]);
  await waitCounters(
    ports[0],
    (status) => status.long_lived === 1,
    'standby did not account for the abort fixture stream',
  );
  await waitCounters(
    ports[2],
    (status) => status.long_lived === 1,
    'active slot did not account for the abort fixture stream',
  );
  abortedStream.response.destroy();
  await Promise.race([
    abortedStream.closed,
    new Promise((_, reject) => setTimeout(() => reject(new Error('aborted SSE stream did not close')), 2_000)),
  ]);
  await waitCounters(
    ports[0],
    (status) => status.in_flight === 0 && status.drain_blocking === 0 && status.long_lived === 0,
    'standby retained an aborted downstream stream',
  );
  await waitCounters(
    ports[2],
    (status) => status.in_flight === 0 && status.drain_blocking === 0 && status.long_lived === 0,
    'active slot retained an aborted downstream stream',
  );

  const owner = JSON.parse(await fsp.readFile(path.join(runtime, 'writer.lock', 'owner.json'), 'utf8'));
  assert.equal(owner.release_digest, RELEASE_B);
  const pointer = JSON.parse(await fsp.readFile(path.join(supervisorState, 'active-slot.json'), 'utf8'));
  assert.equal(pointer.release_digest, RELEASE_B);
});
