import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

import { EdgePublicationClientError } from '../edge/publication-client.mjs';
import { createEdgePublicationProducer } from '../edge/publication-producer.mjs';
import { sealPublication } from '../edge/publication.mjs';

const DIGEST = 'a'.repeat(64);

function initialPublication(releaseRoot) {
  return {
    schema_version: 1,
    generation: 1,
    published_at: '2026-07-28T00:00:00.000Z',
    domain: 'vr.ae',
    console_host: 'console.vr.ae',
    release_digest: DIGEST,
    maintenance: {
      active: false,
      deployment_id: null,
      retry_after_seconds: 0,
      started_at: null,
    },
    session: { cookie_name: 'dc_session' },
    console: {
      asset_root: path.join(releaseRoot, DIGEST, 'apps/DevOpsConsole/src/ui'),
      upstream: {
        host: '127.0.0.1', port: 30444, scheme: 'https',
        tls_server_name: 'console.vr.ae', tls_verify: true,
      },
    },
    routes: {},
    access: { owners: ['owner@gmail.com'], grants: {} },
  };
}

async function fixture(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'edge-producer-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const releaseRoot = path.join(root, 'releases');
  await fsp.mkdir(path.join(releaseRoot, DIGEST, 'apps/DevOpsConsole/src/ui'), { recursive: true });
  let envelope = sealPublication(initialPublication(releaseRoot), { releaseRoot });
  const routes = [];
  const users = [{ email: 'owner@gmail.com', owner: true, grants: [] }];
  const calls = [];
  let rejectNextAdopt = false;
  const client = {
    async describe() {
      calls.push({ method: 'describe', generation: envelope.publication.generation });
      return structuredClone(envelope);
    },
    async adopt(publication, { expectedPayloadSha256 }) {
      calls.push({ method: 'adopt', generation: publication.generation, expectedPayloadSha256 });
      if (rejectNextAdopt) {
        rejectNextAdopt = false;
        const advanced = structuredClone(envelope.publication);
        advanced.generation += 1;
        advanced.published_at = new Date(Date.parse(advanced.published_at) + 1_000).toISOString();
        envelope = sealPublication(advanced, { releaseRoot });
        throw new EdgePublicationClientError('active publication changed', {
          code: 'edge_publication_rejected',
        });
      }
      assert.equal(expectedPayloadSha256, envelope.payload_sha256);
      envelope = sealPublication(publication, { releaseRoot });
      return {
        ok: true,
        generation: publication.generation,
        payload_sha256: envelope.payload_sha256,
      };
    },
  };
  const producer = createEdgePublicationProducer({
    client,
    config: { domain: 'vr.ae', releaseRoot },
    coordinator: { inventory: async () => ({ servers: [], docker: { available: true, containers: [] } }) },
    routeStore: {
      list: () => structuredClone(routes),
      resolve: async (slug) => {
        const route = routes.find((item) => item.slug === slug);
        return route?.kind === 'port' ? { port: route.port } : { port: null, reason: 'not observed' };
      },
    },
    upstreamAuthStore: { authorizationFor: () => null },
    accessStore: { list: () => structuredClone(users) },
  });
  return {
    calls,
    client,
    envelope: () => structuredClone(envelope),
    producer,
    rejectOnce: () => { rejectNextAdopt = true; },
    routes,
    users,
  };
}

test('mutation is acknowledged only after its complete route/access snapshot is adopted', async (t) => {
  const value = await fixture(t);
  const mutation = value.producer.mutate(async () => {
    value.routes.push({
      slug: 'app', kind: 'port', port: 31000, auth: 'google',
      instanceId: crypto.randomUUID(), title: 'Application',
    });
    value.users.push({ email: 'viewer@gmail.com', owner: false, grants: ['route:app'] });
    return { saved: true };
  }, { reason: 'fixture-route-access-change' });

  const completed = await mutation;
  assert.deepEqual(completed.result, { saved: true });
  assert.equal(completed.publication.changed, true);
  const active = value.envelope().publication;
  assert.equal(active.routes.app.upstream.port, 31000);
  assert.deepEqual(active.access.grants['viewer@gmail.com'], ['route:app']);
});

test('CAS conflict re-reads the edge once and preserves the concurrent generation', async (t) => {
  const value = await fixture(t);
  value.rejectOnce();
  value.routes.push({
    slug: 'app', kind: 'port', port: 31000, auth: 'public',
    instanceId: crypto.randomUUID(), title: null,
  });

  const result = await value.producer.reconcile({ reason: 'cas-fixture' });
  assert.equal(result.changed, true);
  assert.equal(value.calls.filter((call) => call.method === 'describe').length, 2);
  assert.equal(value.envelope().publication.generation, 3);
  assert.equal(value.envelope().publication.routes.app.auth, 'public');
});

test('a new unresolved route is published explicitly unavailable without blocking the snapshot', async (t) => {
  const value = await fixture(t);
  const completed = await value.producer.mutate(async () => {
    value.routes.push({
      slug: 'missing', kind: 'server', auth: 'google',
      instanceId: crypto.randomUUID(), title: null,
    });
    return true;
  });
  assert.equal(completed.publication.changed, true);
  assert.deepEqual(value.envelope().publication.routes.missing.upstream, {
    status: 'unavailable',
    scheme: 'http',
    tls_server_name: null,
    tls_verify: true,
  });
});
