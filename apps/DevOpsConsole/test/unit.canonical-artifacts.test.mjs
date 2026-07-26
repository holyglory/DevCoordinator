import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { verifyArtifactPair } from '../Tools/canonical-artifacts.mjs';
import {
  CANONICAL_OVERVIEW,
  CANONICAL_SESSION,
} from '../Tools/canonical-api-fixtures.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(APP_ROOT, 'Artifacts', 'Canonical', 'login-mobile.png');
let tmp;
let png;
let sidecar;
let cleanProvenance;

before(async () => {
  tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'console-canonical-artifacts-'));
  png = path.join(tmp, 'login-mobile.png');
  sidecar = `${png}.provenance.json`;
  await fsp.copyFile(SOURCE, png);
  await fsp.copyFile(`${SOURCE}.provenance.json`, sidecar);
  cleanProvenance = await fsp.readFile(sidecar, 'utf8');
});

after(async () => {
  await fsp.rm(tmp, { recursive: true, force: true });
});

test('canonical artifact verifier accepts a matching isolated fixture and provenance', async () => {
  const provenance = await verifyArtifactPair(png);
  assert.equal(provenance.source, 'isolated-test-fixture');
  assert.equal(provenance.width, 390);
  assert.equal(provenance.height, 844);
});

test('canonical artifact verifier rejects a missing provenance sidecar', async () => {
  await fsp.unlink(sidecar);
  await assert.rejects(verifyArtifactPair(png), /missing or invalid provenance sidecar/);
  await fsp.writeFile(sidecar, cleanProvenance, 'utf8');
});

test('canonical artifact verifier rejects tampered provenance', async () => {
  const tampered = JSON.parse(cleanProvenance);
  tampered.sha256 = '0'.repeat(64);
  await fsp.writeFile(sidecar, `${JSON.stringify(tampered, null, 2)}\n`, 'utf8');
  await assert.rejects(verifyArtifactPair(png), /provenance hash mismatch/);
  await fsp.writeFile(sidecar, cleanProvenance, 'utf8');
});

test('canonical Projects fixture covers the authoritative tree and supervised worker journey', () => {
  const inventory = CANONICAL_OVERVIEW.inventory;
  assert.equal(CANONICAL_SESSION.accessAdmin, true,
    'the owner-only worker removal control must be present in canonical evidence');
  assert.equal(inventory.repository_trees.length, 1);
  const tree = inventory.repository_trees[0];
  assert.deepEqual(tree.scopes.map((scope) => scope.kind), ['root', 'temporary']);
  assert.equal(tree.scopes[1].kill_after_run, true);
  assert.ok(tree.scopes[1].expires_at);
  const worker = inventory.servers.find((server) => server.supervision);
  assert.ok(worker, 'canonical inventory must contain one supervised worker');
  assert.equal(worker.supervision.keep_alive, true);
  assert.equal(worker.supervision.desired_state, 'running');
});
