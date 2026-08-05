import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

import { EdgePublicationProducerError } from '../edge/publication-producer.mjs';
import { createAccessStore } from '../src/access.mjs';
import { createConsoleApi } from '../src/api.mjs';
import { createRouteStore } from '../src/routes.mjs';
import { createUpstreamAuthStore } from '../src/upstream-auth.mjs';

async function fixture(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'edge-publication-api-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const config = {
    consoleOrigin: 'https://console.vr.ae',
    consoleHost: 'console.vr.ae',
    domain: 'vr.ae',
    coordinatorUrl: 'http://127.0.0.1:29876',
    lifecycleEnabled: false,
  };
  const routeStore = createRouteStore({ file: path.join(root, 'routes.json'), config, log: null });
  await routeStore.load();
  const upstreamAuthStore = createUpstreamAuthStore({ file: path.join(root, 'upstream-auth.json'), log: null });
  await upstreamAuthStore.load();
  const accessStore = createAccessStore({
    file: path.join(root, 'access-control.json'),
    adminEmails: new Set(['owner@gmail.com']),
    routeStore,
    log: null,
  });
  await accessStore.load();
  const reasons = [];
  let failNext = false;
  let mutationStarted = null;
  let blockedMutation = null;
  const edgePublication = {
    async mutate(operation, { reason }) {
      reasons.push(reason);
      const result = await operation();
      mutationStarted?.();
      if (blockedMutation) {
        const blocked = blockedMutation;
        blockedMutation = null;
        await blocked;
      }
      if (failNext) {
        failNext = false;
        throw new EdgePublicationProducerError('fixture edge unavailable', {
          code: 'edge_publication_unavailable',
        });
      }
      return { result, publication: { ok: true, changed: true } };
    },
    async reconcile({ reason }) {
      reasons.push(reason);
      return { ok: true, changed: true, generation: 2, payload_sha256: 'b'.repeat(64) };
    },
  };
  const coordinator = {
    inventory: async () => ({ servers: [], docker: { available: true, containers: [] } }),
    status: () => ({ ok: true }),
  };
  const api = createConsoleApi({
    config,
    log: null,
    coordinator,
    routeStore,
    upstreamAuthStore,
    accessStore,
    guard: { checkOrigin: () => true },
    certManager: null,
    metrics: null,
    prefs: null,
    edgePublication,
  });
  const server = http.createServer((req, res) => api.handle(req, res, {
    email: req.headers['x-fixture-email'] || 'owner@gmail.com',
  }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function request(pathname, { method = 'GET', body, email = 'owner@gmail.com' } = {}) {
    const response = await fetch(`${origin}${pathname}`, {
      method,
      headers: {
        'x-fixture-email': email,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, json: await response.json() };
  }
  return {
    accessStore,
    blockNextMutation() {
      let startedResolve;
      const started = new Promise((resolve) => { startedResolve = resolve; });
      mutationStarted = startedResolve;
      let releaseResolve;
      blockedMutation = new Promise((resolve) => { releaseResolve = resolve; });
      return {
        started,
        release() {
          releaseResolve();
          mutationStarted = null;
        },
      };
    },
    failNext: () => { failNext = true; },
    reasons,
    request,
    routeStore,
  };
}

test('async access authorization failures remain typed JSON responses', async (t) => {
  const value = await fixture(t);
  const response = await value.request('/api/access', { email: 'viewer@gmail.com' });

  assert.equal(response.status, 403);
  assert.deepEqual(response.json, {
    error: 'only configured Console owners can manage access',
  });
});

test('route and access HTTP success wait for stable-edge publication acknowledgement', async (t) => {
  const value = await fixture(t);
  const gate = value.blockNextMutation();
  const pending = value.request('/api/routes', {
    method: 'POST', body: { slug: 'app', kind: 'port', port: 31000, auth: 'google' },
  });
  await gate.started;
  const early = await Promise.race([
    pending.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 25)),
  ]);
  assert.equal(early, false, 'the API acknowledged before the edge completed its CAS adoption');
  gate.release();
  const route = await pending;
  assert.equal(route.status, 201);
  assert.equal(route.json.slug, 'app');

  const access = await value.request('/api/access/users', {
    method: 'POST',
    body: { email: 'viewer@gmail.com', grants: ['route:app'] },
  });
  assert.equal(access.status, 201);
  assert.equal(value.accessStore.canAccess('viewer@gmail.com', 'route:app'), true);
  assert.deepEqual(value.reasons, ['route-created', 'access-user-added']);
});

test('publication failure is typed and local, and publication-only retry does not replay the mutation', async (t) => {
  const value = await fixture(t);
  value.failNext();
  const response = await value.request('/api/routes', {
    method: 'POST', body: { slug: 'saved', kind: 'port', port: 31001, auth: 'public' },
  });
  assert.equal(response.status, 503);
  assert.deepEqual(response.json, {
    error: 'The change was saved, but the public edge could not activate it. Existing public routes remain unchanged.',
    code: 'edge_publication_unavailable',
    classification: 'edge_publication',
    scope: 'local',
    saved: true,
    retryable: true,
    retryPath: '/api/edge-publication/reconcile',
  });
  assert.equal(value.routeStore.get('saved')?.port, 31001, 'the durable local mutation was lost');

  const retried = await value.request(response.json.retryPath, { method: 'POST' });
  assert.equal(retried.status, 200);
  assert.equal(retried.json.publication.generation, 2);
  assert.equal(value.reasons.filter((reason) => reason === 'route-created').length, 1,
    'publication-only retry replayed the already-saved route mutation');
  assert.equal(value.reasons.at(-1), 'user-publication-retry');
});
