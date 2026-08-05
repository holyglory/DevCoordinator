import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';

import {
  handlePublicationRequest,
} from '../edge/devcoordinator-edge.mjs';
import { createEdgePublicationClient } from '../edge/publication-client.mjs';

import {
  PublicationError,
  PublicationStore,
  atomicWriteEnvelope,
  loadPublicationFile,
  sealPublication,
} from '../edge/publication.mjs';

const DIGEST = 'a'.repeat(64);
const CLI = new URL('../edge/publication-cli.mjs', import.meta.url).pathname;
const execFileAsync = promisify(execFile);

async function fixture() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'edge-publication-'));
  const releaseRoot = path.join(root, 'releases');
  const assetRoot = path.join(releaseRoot, DIGEST, 'apps/DevOpsConsole/src/ui');
  const state = path.join(root, 'state');
  await fsp.mkdir(assetRoot, { recursive: true, mode: 0o700 });
  await fsp.mkdir(state, { mode: 0o700 });
  const publication = {
    schema_version: 1,
    generation: 1,
    published_at: '2026-07-28T00:00:00.000Z',
    domain: 'vr.ae',
    console_host: 'console.vr.ae',
    release_digest: DIGEST,
    maintenance: { active: false, deployment_id: null, retry_after_seconds: 0, started_at: null },
    session: { cookie_name: 'dc_session' },
    console: {
      asset_root: assetRoot,
      upstream: {
        host: '127.0.0.1',
        port: 30443,
        scheme: 'https',
        tls_server_name: 'console.vr.ae',
        tls_verify: true,
      },
    },
    routes: {
      app: {
        auth: 'google',
        instance_id: 'route-instance-1',
        title: 'App',
        upstream: {
          host: '127.0.0.1',
          port: 31000,
          scheme: 'http',
          tls_server_name: null,
          tls_verify: true,
        },
        upstream_authorization: 'Bearer private-upstream-value',
      },
      public: {
        auth: 'public',
        instance_id: 'route-instance-2',
        title: null,
        upstream: {
          host: '127.0.0.1',
          port: 31443,
          scheme: 'https',
          tls_server_name: 'public.vr.ae',
          tls_verify: false,
        },
        upstream_authorization: null,
      },
    },
    access: {
      owners: ['owner@example.com'],
      grants: {
        'guest@example.com': ['route:app'],
        'viewer@example.com': ['console'],
      },
    },
  };
  return {
    root,
    releaseRoot,
    state,
    file: path.join(state, 'routes.publication'),
    publication,
  };
}

test('publication envelope is exact, checksummed, bounded, and private', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const envelope = sealPublication(value.publication, { releaseRoot: value.releaseRoot });
  await atomicWriteEnvelope(value.file, envelope, {
    validation: { releaseRoot: value.releaseRoot },
  });
  const loaded = await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot });
  assert.equal(loaded.payload_sha256, envelope.payload_sha256);
  assert.equal(loaded.publication.routes.app.upstream.port, 31000);
  assert.equal((await fsp.stat(value.file)).mode & 0o777, 0o600);

  const tampered = JSON.parse(await fsp.readFile(value.file, 'utf8'));
  tampered.publication.routes.app.upstream.port = 31001;
  await fsp.writeFile(value.file, `${JSON.stringify(tampered)}\n`, { mode: 0o600 });
  await assert.rejects(
    loadPublicationFile(value.file, { releaseRoot: value.releaseRoot }),
    (error) => error instanceof PublicationError && error.code === 'publication_digest_mismatch',
  );
});

test('publication preserves one explicit unavailable route with an exact protocol policy', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  value.publication.routes.offline = {
    auth: 'public',
    instance_id: 'offline-route-instance',
    title: 'Offline application',
    upstream: {
      status: 'unavailable',
      scheme: 'https',
      tls_server_name: 'offline.vr.ae',
      tls_verify: true,
    },
    upstream_authorization: null,
  };
  const envelope = sealPublication(value.publication, { releaseRoot: value.releaseRoot });
  assert.deepEqual(envelope.publication.routes.offline.upstream, {
    status: 'unavailable',
    scheme: 'https',
    tls_server_name: 'offline.vr.ae',
    tls_verify: true,
  });

  for (const mutate of [
    (upstream) => { upstream.port = 31000; },
    (upstream) => { upstream.status = 'stopped'; },
    (upstream) => { upstream.tls_server_name = 'WRONG.vr.ae'; },
  ]) {
    const copy = structuredClone(value.publication);
    mutate(copy.routes.offline.upstream);
    assert.throws(
      () => sealPublication(copy, { releaseRoot: value.releaseRoot }),
      PublicationError,
    );
  }
});

test('invalid control-plane targets, grants, TLS policy, and release roots fail closed', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const cases = [
    (copy) => { copy.routes.app.upstream.port = 29876; },
    (copy) => { copy.access.grants['guest@example.com'] = ['route:missing']; },
    (copy) => { copy.routes.app.upstream.tls_verify = false; },
    (copy) => { copy.console.asset_root = path.join(value.root, 'mutable-ui'); },
    (copy) => { copy.routes.public = { ...copy.routes.app, auth: 'public' }; },
  ];
  for (const mutate of cases) {
    const copy = structuredClone(value.publication);
    mutate(copy);
    assert.throws(
      () => sealPublication(copy, { releaseRoot: value.releaseRoot }),
      PublicationError,
    );
  }
});

test('store retains last-known-good across invalid refresh, restart, and generation rollback', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const first = sealPublication(value.publication, { releaseRoot: value.releaseRoot });
  await atomicWriteEnvelope(value.file, first, { validation: { releaseRoot: value.releaseRoot } });
  const store = new PublicationStore({
    file: value.file,
    validation: { releaseRoot: value.releaseRoot },
  });
  await store.loadInitial();
  assert.equal(store.current().generation, 1);

  await fsp.writeFile(value.file, '{broken', { mode: 0o600 });
  assert.equal((await store.refresh()).ok, false);
  assert.equal(store.current().generation, 1);

  await fsp.unlink(value.file);
  const restarted = new PublicationStore({
    file: value.file,
    validation: { releaseRoot: value.releaseRoot },
  });
  await restarted.loadInitial();
  assert.equal(restarted.current().generation, 1);

  const newerDocument = structuredClone(value.publication);
  newerDocument.generation = 2;
  newerDocument.published_at = '2026-07-28T00:01:00.000Z';
  const newer = sealPublication(newerDocument, { releaseRoot: value.releaseRoot });
  await atomicWriteEnvelope(value.file, newer, { validation: { releaseRoot: value.releaseRoot } });
  assert.deepEqual(await store.refresh(), { ok: true, changed: true });
  assert.equal(store.current().generation, 2);

  await atomicWriteEnvelope(value.file, first, { validation: { releaseRoot: value.releaseRoot } });
  assert.equal((await store.refresh()).ok, false);
  assert.equal(store.current().generation, 2);
});

test('publication symlinks are rejected while local permission metadata is ignored', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const target = path.join(value.state, 'target');
  const envelope = sealPublication(value.publication, { releaseRoot: value.releaseRoot });
  await fsp.writeFile(target, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
  await fsp.symlink(target, value.file);
  await assert.rejects(loadPublicationFile(value.file, { releaseRoot: value.releaseRoot }));
  await fsp.unlink(value.file);
  await fsp.writeFile(value.file, `${JSON.stringify(envelope)}\n`, { mode: 0o644 });
  await fsp.chmod(value.file, 0o644);
  assert.equal(
    (await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot })).payload_sha256,
    envelope.payload_sha256,
  );
});

test('publication CLI switches one verified Console candidate with optimistic concurrency', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const input = path.join(value.state, 'publication.json');
  await fsp.writeFile(input, `${JSON.stringify(value.publication)}\n`, { mode: 0o600 });
  await fsp.chmod(input, 0o600);
  await execFileAsync(process.execPath, [
    CLI, 'seal', '--input', input, '--output', value.file, '--release-root', value.releaseRoot,
  ]);
  const current = await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot });
  const candidateDigest = 'c'.repeat(64);
  await fsp.mkdir(
    path.join(value.releaseRoot, candidateDigest, 'apps/DevOpsConsole/src/ui'),
    { recursive: true, mode: 0o700 },
  );
  await execFileAsync(process.execPath, [
    CLI,
    'switch-console',
    '--file', value.file,
    '--release-root', value.releaseRoot,
    '--expected-payload-sha256', current.payload_sha256,
    '--release-digest', candidateDigest,
    '--port', '30444',
    '--published-at', '2026-07-28T00:02:00.000Z',
  ]);
  const loaded = await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot });
  assert.equal(loaded.publication.generation, 2);
  assert.equal(loaded.publication.release_digest, candidateDigest);
  assert.equal(loaded.publication.console.upstream.port, 30444);

  await assert.rejects(execFileAsync(process.execPath, [
    CLI,
    'switch-console',
    '--file', value.file,
    '--release-root', value.releaseRoot,
    '--expected-payload-sha256', current.payload_sha256,
    '--release-digest', DIGEST,
    '--port', '30445',
    '--published-at', '2026-07-28T00:03:00.000Z',
  ]));
  const retained = await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot });
  assert.equal(retained.payload_sha256, loaded.payload_sha256);
});

test('local publication boundary describes and atomically adopts exact next generation', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const first = sealPublication(value.publication, { releaseRoot: value.releaseRoot });
  await atomicWriteEnvelope(value.file, first, { validation: { releaseRoot: value.releaseRoot } });
  const store = new PublicationStore({
    file: value.file,
    validation: { releaseRoot: value.releaseRoot },
  });
  await store.loadInitial();
  const describeRequest = {
    schema_version: 1,
    operation: 'describe',
  };
  const describedResponse = await handlePublicationRequest({
    request: describeRequest,
    publicationStore: store,
    releaseRoot: value.releaseRoot,
  });
  const described = describedResponse.envelope;
  assert.equal(described.payload_sha256, first.payload_sha256);
  assert.equal(described.publication.generation, 1);

  const candidate = structuredClone(described.publication);
  candidate.generation = 2;
  candidate.published_at = '2026-07-28T00:04:00.000Z';
  candidate.routes.app.title = 'Renamed';
  const adoptRequest = {
    schema_version: 1,
    operation: 'adopt',
    expected_payload_sha256: described.payload_sha256,
    publication: candidate,
  };
  const adopted = await handlePublicationRequest({
    request: adoptRequest,
    publicationStore: store,
    releaseRoot: value.releaseRoot,
  });
  assert.equal(adopted.generation, 2);
  const persisted = await loadPublicationFile(value.file, { releaseRoot: value.releaseRoot });
  assert.equal(persisted.payload_sha256, adopted.payload_sha256);
  assert.equal(persisted.publication.routes.app.title, 'Renamed');
  assert.equal(store.current().routes.app.title, 'Renamed');

  await assert.rejects(
    handlePublicationRequest({
      request: adoptRequest,
      publicationStore: store,
      releaseRoot: value.releaseRoot,
    }),
    /active publication changed|generation must advance/,
  );
  const requestWithUnexpectedField = { ...describeRequest, unexpected: true };
  await assert.rejects(handlePublicationRequest({
    request: requestWithUnexpectedField,
    publicationStore: store,
    releaseRoot: value.releaseRoot,
  }), /request contract is invalid/);
});

test('publication client requires only a reachable Unix socket and bounded transport options', async (t) => {
  const value = await fixture();
  t.after(() => fsp.rm(value.root, { recursive: true, force: true }));
  const socketPath = path.join(value.root, 'publish.sock');
  assert.doesNotThrow(() => createEdgePublicationClient({
    socketPath,
    releaseRoot: value.releaseRoot,
    timeoutMs: 500,
  }));
  assert.throws(
    () => createEdgePublicationClient({ socketPath: 'publish.sock', releaseRoot: value.releaseRoot }),
    /must be one absolute path/,
  );
});
