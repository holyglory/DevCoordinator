import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';
import { CoordError, createCoordinator } from '../src/coordinator.mjs';

const TOKEN = 'fixture-runtime-artifact-token-0123456789abcdef';
const SERVICE_ID = '11111111-1111-4111-8111-111111111111';
const RUN_ID = '22222222-2222-4222-8222-222222222222';
const EXACT_LIMIT_ID = '33333333-3333-4333-8333-333333333333';
const OVERSIZED_ID = '44444444-4444-4444-8444-444444444444';
const ARTIFACT_LIMIT = 1024 * 1024;

test('coordinator artifact reads use the private bearer and a fixed typed UUID path', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'console-runtime-artifact-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const tokenFile = path.join(directory, 'api-token');
  await fs.writeFile(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
  await fs.chmod(tokenFile, 0o600);
  const requests = [];
  const upstream = http.createServer((req, res) => {
    requests.push({ path: req.url, authorization: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    if (req.url?.endsWith(`/${EXACT_LIMIT_ID}`)) {
      res.end(Buffer.alloc(ARTIFACT_LIMIT, 'x'));
    } else if (req.url?.endsWith(`/${OVERSIZED_ID}`)) {
      res.write(Buffer.alloc(ARTIFACT_LIMIT, 'x'));
      res.end('x');
    } else {
      res.end('fixture log');
    }
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const client = createCoordinator({
    config: {
      coordinatorUrl: `http://127.0.0.1:${upstream.address().port}`,
      coordinatorTokenFile: tokenFile,
      coordinatorAutostart: false,
      coordinatorScript: '/unused/dev_coordinator.py',
      coordinatorHome: directory,
      stateDir: directory,
    },
    log: null,
  });
  t.after(() => client.close());

  const artifact = await client.runtimeArtifact('service', SERVICE_ID.toUpperCase());
  assert.equal(artifact.text, 'fixture log');
  assert.deepEqual(requests, [{
    path: `/v1/runtime/artifacts/service/${SERVICE_ID}`,
    authorization: `Bearer ${TOKEN}`,
  }]);
  assert.throws(
    () => client.runtimeArtifact('service', '../etc/passwd'),
    (error) => error instanceof CoordError && error.status === 400,
  );
  assert.throws(
    () => client.runtimeArtifact('filesystem', SERVICE_ID),
    (error) => error instanceof CoordError && error.status === 400,
  );
  assert.equal(requests.length, 1, 'invalid paths must fail before an upstream request');

  await client.runtimeArtifact('diagnostic', RUN_ID);
  assert.equal(
    requests[1].path,
    `/v1/runtime/artifacts/diagnostic/${RUN_ID}`,
  );
  assert.equal(requests[1].authorization, `Bearer ${TOKEN}`);

  await client.runtimeArtifact('worker_attempt', RUN_ID);
  assert.equal(
    requests[2].path,
    `/v1/runtime/artifacts/worker_attempt/${RUN_ID}`,
  );

  const exact = await client.runtimeArtifact('run', EXACT_LIMIT_ID);
  assert.equal(Buffer.byteLength(exact.text), ARTIFACT_LIMIT);
  await assert.rejects(
    () => client.runtimeArtifact('run', OVERSIZED_ID),
    (error) => error instanceof CoordError
      && error.status === 502
      && /oversized runtime log artifact/.test(error.message),
  );
});

async function apiFixture(t) {
  const calls = [];
  const coordinator = {
    runtimeArtifact: async (kind, id) => {
      calls.push({ kind, id });
      if (id === RUN_ID) {
        throw new CoordError('runtime log artifact not found', { status: 404 });
      }
      return {
        path: '/private/host/layout/must-not-reach-browser.log',
        text: 'first line\nsecond line\n',
        tail: 2000,
      };
    },
  };
  const api = createConsoleApi({
    config: {
      consoleOrigin: 'https://console.example.test',
      consoleHost: 'console.example.test',
      domain: 'example.test',
    },
    log: null,
    coordinator,
    routeStore: { list: () => [] },
    upstreamAuthStore: null,
    accessStore: { isAdmin: () => false },
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
  });
  const server = http.createServer((req, res) => {
    const session = req.headers['x-no-session'] === '1'
      ? null
      : { email: 'user@example.test' };
    api.handle(req, res, session);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { calls, coordinator, origin };
}

test('Console artifact proxy is session-authenticated and never exposes host paths', async (t) => {
  const { calls, origin } = await apiFixture(t);
  const unauthorized = await fetch(
    `${origin}/api/runtime/artifacts/service/${SERVICE_ID}`,
    { headers: { 'x-no-session': '1' } },
  );
  assert.equal(unauthorized.status, 401);
  assert.equal(calls.length, 0);

  const response = await fetch(`${origin}/api/runtime/artifacts/service/${SERVICE_ID}`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /^text\/plain/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.match(response.headers.get('content-disposition'), /service-11111111/);
  const text = await response.text();
  assert.equal(text, 'first line\nsecond line\n');
  assert.doesNotMatch(text, /private\/host|must-not-reach-browser/);
  assert.deepEqual(calls, [{ kind: 'service', id: SERVICE_ID }]);
});

test('Console serves an exact runtime diagnostic without exposing its account path', async (t) => {
  const { coordinator, origin } = await apiFixture(t);
  const seen = [];
  coordinator.runtimeArtifact = async (kind, id) => {
    seen.push({ kind, id });
    return {
      path: '/private/account/logs/runtime-diagnostic-must-not-reach-browser.log',
      text: 'container exited with status 2\ndatabase startup failed\n',
      tail: 2000,
      max_bytes: ARTIFACT_LIMIT,
    };
  };
  const response = await fetch(
    `${origin}/api/runtime/artifacts/diagnostic/${RUN_ID}`,
  );
  assert.equal(response.status, 200);
  assert.equal(
    await response.text(),
    'container exited with status 2\ndatabase startup failed\n',
  );
  assert.deepEqual(seen, [{ kind: 'diagnostic', id: RUN_ID }]);
  assert.doesNotMatch(
    response.headers.get('content-disposition') ?? '',
    /private|account|must-not-reach-browser/,
  );
});

test('Console artifact proxy rejects traversal before lookup and preserves missing-file 404', async (t) => {
  const { calls, origin } = await apiFixture(t);
  const traversal = await fetch(
    `${origin}/api/runtime/artifacts/service/%2e%2e%2Fetc%2Fpasswd`,
  );
  assert.equal(traversal.status, 404);
  assert.equal(calls.length, 0);

  const unsupported = await fetch(
    `${origin}/api/runtime/artifacts/filesystem/${SERVICE_ID}`,
  );
  assert.equal(unsupported.status, 404);
  assert.equal(calls.length, 0);

  const dockerArtifact = await fetch(
    `${origin}/api/runtime/artifacts/docker/${SERVICE_ID}`,
  );
  assert.equal(dockerArtifact.status, 200);
  assert.equal(await dockerArtifact.text(), 'first line\nsecond line\n');
  assert.match(
    dockerArtifact.headers.get('content-disposition') ?? '',
    /docker-11111111/,
  );
  assert.deepEqual(calls, [{ kind: 'docker', id: SERVICE_ID }]);

  const databaseArtifact = await fetch(
    `${origin}/api/runtime/artifacts/database_stack/${SERVICE_ID}`,
  );
  assert.equal(databaseArtifact.status, 200);
  assert.equal(await databaseArtifact.text(), 'first line\nsecond line\n');
  assert.deepEqual(calls[1], { kind: 'database_stack', id: SERVICE_ID });

  const workerArtifact = await fetch(
    `${origin}/api/runtime/artifacts/worker_attempt/${SERVICE_ID}`,
  );
  assert.equal(workerArtifact.status, 200);
  assert.equal(await workerArtifact.text(), 'first line\nsecond line\n');
  assert.deepEqual(calls[2], { kind: 'worker_attempt', id: SERVICE_ID });

  const missing = await fetch(`${origin}/api/runtime/artifacts/run/${RUN_ID}`);
  assert.equal(missing.status, 404);
  assert.match((await missing.json()).error, /unavailable/);
  assert.deepEqual(calls[3], { kind: 'run', id: RUN_ID });
});

test('Console artifact proxy fails closed on malformed or oversized upstream payloads', async (t) => {
  const { coordinator, origin } = await apiFixture(t);
  coordinator.runtimeArtifact = async () => ({
    path: '/private/logs/exists-but-contract-is-invalid.log',
  });
  const malformed = await fetch(
    `${origin}/api/runtime/artifacts/service/${SERVICE_ID}`,
  );
  assert.equal(malformed.status, 502);
  assert.match((await malformed.json()).error, /invalid runtime log artifact/);

  coordinator.runtimeArtifact = async () => ({
    text: 'x'.repeat(1024 * 1024),
  });
  const exact = await fetch(
    `${origin}/api/runtime/artifacts/service/${SERVICE_ID}`,
  );
  assert.equal(exact.status, 200);
  assert.equal((await exact.arrayBuffer()).byteLength, 1024 * 1024);

  coordinator.runtimeArtifact = async () => ({
    path: '/private/logs/oversized.log',
    text: 'x'.repeat(1024 * 1024 + 1),
  });
  const oversized = await fetch(
    `${origin}/api/runtime/artifacts/service/${SERVICE_ID}`,
  );
  assert.equal(oversized.status, 502);
  assert.match((await oversized.json()).error, /oversized runtime log artifact/);
});
