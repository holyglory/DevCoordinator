// Unit tests for the UI prefs store (src/prefs.mjs): delta merge semantics,
// validation, REAL on-disk durability (read the file back, not the cache),
// write-failure propagation with in-memory rollback, and corrupt recovery.

import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import { createPrefsStore, PrefsError } from '../src/prefs.mjs';

async function tmpFile() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-prefs-'));
  return path.join(dir, 'ui-prefs.json');
}

describe('prefs store', () => {
  it('applies hide/unhide deltas as a server-side merge and persists to disk', async () => {
    const file = await tmpFile();
    const store = createPrefsStore({ file, log: null });

    await store.applyHiddenDelta({ hide: { servers: ['/a::web', ' /a::web ', '/b::api'] } });
    await store.applyHiddenDelta({ hide: { docker: ['pg'] }, unhide: { servers: ['/b::api', '/never'] } });
    assert.deepEqual(store.get().hidden.servers, ['/a::web']);
    assert.deepEqual(store.get().hidden.docker, ['pg']);

    // Durability must be provable from DISK, not the in-process cache.
    const onDisk = JSON.parse(await fsp.readFile(file, 'utf8'));
    assert.deepEqual(onDisk.hidden.servers, ['/a::web']);
    assert.deepEqual(onDisk.hidden.docker, ['pg']);

    // A fresh store instance sees the persisted state.
    const reloaded = createPrefsStore({ file, log: null });
    assert.deepEqual(reloaded.get().hidden.servers, ['/a::web']);
  });

  it('rejects malformed deltas without changing anything', async () => {
    const file = await tmpFile();
    const store = createPrefsStore({ file, log: null });
    await store.applyHiddenDelta({ hide: { projects: ['path:/x'] } });

    for (const bad of [
      {},
      { hide: 'nope' },
      { hide: { unknown: [] } },
      { hide: { servers: 'x' } },
      { hide: { servers: [12] } },
      { unhide: { servers: [''] } },
    ]) {
      await assert.rejects(() => store.applyHiddenDelta(bad), PrefsError);
    }
    assert.deepEqual(store.get().hidden.projects, ['path:/x']);
  });

  it('propagates write failures as PrefsError 500 and rolls back memory', async () => {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-prefs-'));
    const file = path.join(dir, 'nested', 'missing', 'ui-prefs.json'); // unwritable path
    const store = createPrefsStore({ file, log: null });

    await assert.rejects(
      () => store.applyHiddenDelta({ hide: { servers: ['/a::web'] } }),
      (err) => err instanceof PrefsError && err.status === 500,
    );
    // Memory must not claim what disk refused.
    assert.deepEqual(store.get().hidden.servers, []);
  });

  it('caps list growth and recovers from a corrupt file', async () => {
    const file = await tmpFile();
    await fsp.writeFile(file, '{ not json', 'utf8');
    const store = createPrefsStore({ file, log: null });
    assert.deepEqual(store.get().hidden, { servers: [], docker: [], projects: [] });

    const many = Array.from({ length: 500 }, (_, i) => `k${i}`);
    await store.applyHiddenDelta({ hide: { servers: many } });
    await assert.rejects(
      () => store.applyHiddenDelta({ hide: { servers: ['one-too-many'] } }),
      /would exceed 500/,
    );
    assert.equal(store.get().hidden.servers.length, 500, 'failed delta must not partially apply');
  });
});
