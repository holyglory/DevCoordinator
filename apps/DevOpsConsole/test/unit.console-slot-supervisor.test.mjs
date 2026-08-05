import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { WriterLease } from '../edge/console-slot-supervisor.mjs';

const RELEASE_A = 'a'.repeat(64);
const RELEASE_B = 'b'.repeat(64);

async function fixture(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'console-slot-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  return root;
}

test('Console writer lease admits exactly one live release and transfers after release', async (t) => {
  const root = await fixture(t);
  const directory = path.join(root, 'writer.lock');
  const first = new WriterLease({ directory, releaseDigest: RELEASE_A });
  const second = new WriterLease({ directory, releaseDigest: RELEASE_B });
  await first.acquire();
  await assert.rejects(() => second.acquire(), /held by live pid/);
  const owner = JSON.parse(await fsp.readFile(path.join(directory, 'owner.json'), 'utf8'));
  assert.equal(owner.release_digest, RELEASE_A);
  assert.equal(owner.pid, process.pid);
  await first.release();
  await second.acquire();
  const replacement = JSON.parse(await fsp.readFile(path.join(directory, 'owner.json'), 'utf8'));
  assert.equal(replacement.release_digest, RELEASE_B);
  await second.release();
});

test('Console writer lease reclaims only a process-identity-proven stale owner', async (t) => {
  const root = await fixture(t);
  const directory = path.join(root, 'writer.lock');
  await fsp.mkdir(directory, { mode: 0o700 });
  await fsp.writeFile(path.join(directory, 'owner.json'), `${JSON.stringify({
    schema_version: 1,
    pid: 2_000_000_000,
    process_start_time: 'stale',
    release_digest: RELEASE_A,
    token: 'fixture-stale-token',
  })}\n`, { mode: 0o600 });
  const lease = new WriterLease({ directory, releaseDigest: RELEASE_B });
  await lease.acquire();
  const owner = JSON.parse(await fsp.readFile(path.join(directory, 'owner.json'), 'utf8'));
  assert.equal(owner.release_digest, RELEASE_B);
  await lease.release();
});
