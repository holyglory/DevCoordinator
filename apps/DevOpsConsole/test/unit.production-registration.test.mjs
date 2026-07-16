import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  completeProductionRegistration,
  productionRegistrationPlan,
  registerProductionEdge,
} from '../bin/devops-console.mjs';

const config = { projectRoot: '/home/DevCoordinator' };

test('production coordinator definition probes the Console through TLS', async () => {
  const runtime = JSON.parse(
    await readFile(new URL('../../../.codex/dev-runtime.json', import.meta.url), 'utf8'),
  );
  const definition = runtime.servers?.find((server) => server.name === 'devops-console');
  assert.ok(definition, 'devops-console coordinator definition must exist');
  assert.equal(definition.health_url, 'https://127.0.0.1:{port}/healthz');
});

test('production registration retries and sends the exact edge identity', async () => {
  const calls = [];
  const coordinator = {
    async serverRegister(payload) {
      calls.push(payload);
      if (calls.length < 3) throw new Error('coordinator still starting');
      return {
        id: 'server-id',
        pid: 4242,
        status: 'running',
        lease_id: 'replacement-lease',
        health: {
          ok: true,
          classification: 'healthy',
          check: { ok: true, status: 200 },
          identity: {
            ok: true,
            pid: 4242,
            cwd: '/home/DevCoordinator/apps/DevOpsConsole',
            project: '/home/DevCoordinator',
            host: '127.0.0.1',
            port: 443,
            source: 'proc_pid_fd',
            listener_inodes: ['123456'],
          },
        },
        registration_identity: {
          ok: true,
          pid: 4242,
          cwd: '/home/DevCoordinator/apps/DevOpsConsole',
          project: '/home/DevCoordinator',
          host: '127.0.0.1',
          port: 443,
          source: 'proc_pid_fd',
          listener_inodes: ['123456'],
        },
      };
    },
  };
  const result = await registerProductionEdge({
    coordinator,
    config,
    pid: 4242,
    cwd: '/home/DevCoordinator/apps/DevOpsConsole',
    platform: 'linux',
    attempts: 3,
    delayMs: 0,
  });
  assert.equal(result.id, 'server-id');
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2], {
    agent: 'devops-console',
    project: '/home/DevCoordinator',
    name: 'devops-console',
    cwd: '/home/DevCoordinator/apps/DevOpsConsole',
    pid: 4242,
    port: 443,
    url: 'https://127.0.0.1:443',
    health_url: 'https://127.0.0.1:443/healthz',
  });
});

test('required production registration ignores a preserved PORT bypass', () => {
  assert.deepEqual(
    productionRegistrationPlan({
      config: { httpsPort: 443, devInsecureHttp: false },
      env: { COORDINATOR_REGISTRATION_REQUIRED: '1', PORT: '3000' },
    }),
    { required: true, shouldRegister: true },
  );
  assert.throws(
    () => productionRegistrationPlan({
      config: { httpsPort: 8443, devInsecureHttp: false },
      env: { COORDINATOR_REGISTRATION_REQUIRED: '1' },
    }),
    /production TLS edge on port 443/,
  );
  assert.deepEqual(
    productionRegistrationPlan({
      config: { httpsPort: 443, devInsecureHttp: false },
      env: { PORT: '3000' },
    }),
    { required: false, shouldRegister: false },
  );
});

test('production registration rejects a mismatched success response', async () => {
  await assert.rejects(
    registerProductionEdge({
      coordinator: { async serverRegister() { return { status: 'running', pid: 999 }; } },
      config,
      pid: 4242,
      cwd: '/home/DevCoordinator/apps/DevOpsConsole',
      platform: 'linux',
      attempts: 1,
      delayMs: 0,
    }),
    /incomplete or mismatched registration graph/,
  );
});

test('production registration rejects a redirecting health endpoint', async () => {
  const identity = {
    ok: true,
    pid: 4242,
    cwd: '/home/DevCoordinator/apps/DevOpsConsole',
    project: '/home/DevCoordinator',
    host: '127.0.0.1',
    port: 443,
    source: 'proc_pid_fd',
    listener_inodes: ['123456'],
  };
  await assert.rejects(
    registerProductionEdge({
      coordinator: {
        async serverRegister() {
          return {
            pid: 4242,
            status: 'running',
            lease_id: 'replacement-lease',
            registration_identity: identity,
            health: {
              ok: true,
              classification: 'healthy',
              check: { ok: true, status: 302 },
              identity,
            },
          };
        },
      },
      config,
      pid: 4242,
      cwd: '/home/DevCoordinator/apps/DevOpsConsole',
      platform: 'linux',
      attempts: 1,
      delayMs: 0,
    }),
    /incomplete or mismatched registration graph/,
  );
});

test('non-Linux direct registration accepts the platform listener proof without weakening Linux', async () => {
  const platformIdentity = {
    ok: true,
    pid: 4242,
    cwd: '/home/DevCoordinator/apps/DevOpsConsole',
    project: '/home/DevCoordinator',
    host: '127.0.0.1',
    port: 443,
    source: 'platform_listener_probe',
    listener_inodes: [],
  };
  const coordinator = {
    async serverRegister() {
      return {
        pid: 4242,
        status: 'running',
        lease_id: 'local-lease',
        registration_identity: platformIdentity,
        health: {
          ok: true,
          classification: 'healthy',
          check: { ok: true, status: 200 },
          identity: platformIdentity,
        },
      };
    },
  };
  const accepted = await registerProductionEdge({
    coordinator,
    config,
    pid: 4242,
    cwd: '/home/DevCoordinator/apps/DevOpsConsole',
    platform: 'darwin',
    attempts: 1,
    delayMs: 0,
  });
  assert.equal(accepted.lease_id, 'local-lease');
  await assert.rejects(
    registerProductionEdge({
      coordinator,
      config,
      pid: 4242,
      cwd: '/home/DevCoordinator/apps/DevOpsConsole',
      platform: 'linux',
      attempts: 1,
      delayMs: 0,
    }),
    /incomplete or mismatched registration graph/,
  );
});

test('required production registration fails startup after bounded retries', async () => {
  let attempts = 0;
  const coordinator = {
    async serverRegister() {
      attempts += 1;
      throw new Error('listener ownership unavailable');
    },
  };
  const messages = [];
  const log = {
    info() {},
    warn(message) { messages.push(message); },
  };
  await assert.rejects(
    completeProductionRegistration({
      coordinator,
      config,
      log,
      required: true,
      attempts: 2,
      delayMs: 0,
    }),
    /failed after 2 attempts: listener ownership unavailable/,
  );
  assert.equal(attempts, 2);
  assert.deepEqual(messages, []);
});

test('explicitly optional registration retains the local best-effort mode', async () => {
  const coordinator = { async serverRegister() { throw new Error('offline'); } };
  const messages = [];
  const log = {
    info() {},
    warn(message, detail) { messages.push([message, detail]); },
  };
  const result = await completeProductionRegistration({
    coordinator,
    config,
    log,
    required: false,
    attempts: 1,
    delayMs: 0,
  });
  assert.equal(result, null);
  assert.equal(messages.length, 1);
  assert.match(messages[0][0], /continuing/);
  assert.match(messages[0][1].error, /failed after 1 attempts: offline/);
});
