// Unit tests for the CPU/memory history store (src/metrics.mjs):
// ingestion from a coordinator inventory payload, sub-interval dedupe,
// ring-buffer trimming, retention pruning, history limits, and the sampler.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { createMetricsStore, METRICS_MAX_POINTS } from '../src/metrics.mjs';

const INTERVAL = 10_000;

function makeStore(overrides = {}) {
  return createMetricsStore({
    config: { metricsIntervalMs: INTERVAL },
    log: null,
    coordinator: overrides.coordinator ?? null,
    maxPoints: overrides.maxPoints ?? METRICS_MAX_POINTS,
  });
}

function inventoryFixture() {
  return {
    servers: [
      {
        id: 'srv-1',
        name: 'web',
        project: '/repos/webapp',
        status: 'running',
        process_usage: { cpu_percent: 12.5, memory_bytes: 104_857_600, rss_bytes: 104_857_600 },
      },
      // Registered but not running: no process_usage -> no reading.
      { id: 'srv-2', name: 'api', project: '/repos/api', status: 'stopped' },
    ],
    docker: {
      available: true,
      containers: [
        {
          name: 'pg',
          id: 'abc123',
          status: 'Up 3 hours',
          project: '/repos/webapp',
          stats: { cpu_percent: 1.2, memory_usage_bytes: 52_428_800 },
        },
        // Exited container: stats may linger in the payload but must be ignored.
        {
          name: 'old-redis',
          status: 'Exited (0) 2 days ago',
          stats: { cpu_percent: 0, memory_usage_bytes: 0 },
        },
      ],
    },
    project_usage: [
      { project: '/repos/webapp', project_key: 'path:/repos/webapp', name: 'webapp', cpu_percent: 13.7, memory_bytes: 157_286_400 },
    ],
  };
}

describe('metrics store: ingest', () => {
  it('records running servers, running containers and project usage; skips dead ones', () => {
    const store = makeStore();
    const t = 1_000_000;
    store.ingest(inventoryFixture(), { at: t });

    const view = store.history();
    const keys = view.entities.map((e) => e.key);
    assert.deepEqual(keys, ['dock:pg', 'proj:path:/repos/webapp', 'srv:srv-1']);

    const srv = view.entities.find((e) => e.key === 'srv:srv-1');
    assert.equal(srv.kind, 'server');
    assert.equal(srv.name, 'web');
    assert.equal(srv.project, '/repos/webapp');
    assert.deepEqual(srv.points, [[t, 12.5, 104_857_600]]);

    const dock = view.entities.find((e) => e.key === 'dock:pg');
    assert.equal(dock.kind, 'docker');
    assert.deepEqual(dock.points, [[t, 1.2, 52_428_800]]);

    const proj = view.entities.find((e) => e.key === 'proj:path:/repos/webapp');
    assert.equal(proj.kind, 'project');
    assert.deepEqual(proj.points, [[t, 13.7, 157_286_400]]);
  });

  it('replaces the last point instead of appending when a reading lands inside the sampling window', () => {
    const store = makeStore();
    const t0 = 1_000_000;
    store.ingest(inventoryFixture(), { at: t0 });

    const fresher = inventoryFixture();
    fresher.servers[0].process_usage.cpu_percent = 50;
    store.ingest(fresher, { at: t0 + Math.floor(INTERVAL * 0.3) });

    const srv = store.history().entities.find((e) => e.key === 'srv:srv-1');
    assert.equal(srv.points.length, 1, 'sub-interval reading must replace, not append');
    assert.equal(srv.points[0][1], 50);

    // A reading beyond the window appends normally.
    store.ingest(inventoryFixture(), { at: t0 + INTERVAL });
    assert.equal(store.history().entities.find((e) => e.key === 'srv:srv-1').points.length, 2);
  });

  it('trims each ring buffer to maxPoints, dropping the oldest readings', () => {
    const store = makeStore({ maxPoints: 5 });
    const t0 = 1_000_000;
    for (let i = 0; i < 9; i++) {
      store.ingest(inventoryFixture(), { at: t0 + i * INTERVAL });
    }
    const srv = store.history().entities.find((e) => e.key === 'srv:srv-1');
    assert.equal(srv.points.length, 5);
    assert.equal(srv.points[0][0], t0 + 4 * INTERVAL, 'oldest points must be dropped first');
  });

  it('prunes entities that have not been seen for the whole retention window', () => {
    const store = makeStore({ maxPoints: 5 }); // retention = 5 * INTERVAL
    const t0 = 1_000_000;
    store.ingest(inventoryFixture(), { at: t0 });

    // Later inventories no longer contain the container.
    const withoutDocker = inventoryFixture();
    withoutDocker.docker.containers = [];
    store.ingest(withoutDocker, { at: t0 + 6 * INTERVAL });

    const keys = store.history().entities.map((e) => e.key);
    assert.ok(!keys.includes('dock:pg'), 'aged-out entity must be pruned');
    assert.ok(keys.includes('srv:srv-1'));
  });

  it('keys project series by unique usage_key so same-named repos never merge histories', () => {
    const store = makeStore();
    // Two repos both named "app": identical display project_key, distinct
    // usage_key identities. Keying by project_key merged their charts (the
    // confirmed 2026-07-07 collision bug); usage_key must keep them apart.
    store.ingest({
      servers: [],
      docker: { available: false, containers: [] },
      project_usage: [
        { usage_key: 'path:/home/example/work/app', project_key: 'app', project: '/home/example/work/app', name: 'app', cpu_percent: 10, memory_bytes: 100 },
        { usage_key: 'path:/home/example/tmp/app', project_key: 'app', project: '/home/example/tmp/app', name: 'app', cpu_percent: 20, memory_bytes: 200 },
      ],
    }, { at: 1_000_000 });

    const keys = store.history().entities.map((e) => e.key).sort();
    assert.deepEqual(keys, ['proj:path:/home/example/tmp/app', 'proj:path:/home/example/work/app'],
      'each usage_key gets its own history series');
    const work = store.history().entities.find((e) => e.key === 'proj:path:/home/example/work/app');
    assert.deepEqual(work.points, [[1_000_000, 10, 100]], 'series must not merge same-named projects');
  });

  it('ignores malformed payloads without throwing', () => {
    const store = makeStore();
    store.ingest(null);
    store.ingest('nonsense');
    store.ingest({ servers: 'nope', docker: { available: true, containers: [{}] }, project_usage: [{}] });
    assert.deepEqual(store.history().entities, []);
  });
});

describe('metrics store: history view', () => {
  it('caps points per entity at the requested limit and reports sampler state', () => {
    const store = makeStore();
    const t0 = 1_000_000;
    for (let i = 0; i < 6; i++) store.ingest(inventoryFixture(), { at: t0 + i * INTERVAL });

    const view = store.history({ limit: 3 });
    assert.equal(view.intervalMs, INTERVAL);
    assert.equal(view.maxPoints, METRICS_MAX_POINTS);
    assert.equal(view.sampler.running, false);
    for (const entity of view.entities) {
      assert.ok(entity.points.length <= 3, `${entity.key} returned ${entity.points.length} points`);
    }
    const srv = view.entities.find((e) => e.key === 'srv:srv-1');
    assert.equal(srv.points[srv.points.length - 1][0], t0 + 5 * INTERVAL, 'limit keeps the newest points');
  });
});

describe('metrics store: sampler', () => {
  it('sampleOnce ingests the coordinator inventory and records failures without throwing', async () => {
    let fail = false;
    const coordinator = {
      inventory: async () => {
        if (fail) throw new Error('coordinator unreachable');
        return inventoryFixture();
      },
    };
    const store = makeStore({ coordinator });

    await store.sampleOnce();
    assert.ok(store.history().entities.length > 0);
    assert.equal(store.history().sampler.lastError, null);

    fail = true;
    await store.sampleOnce();
    assert.match(String(store.history().sampler.lastError), /unreachable/);
    // Existing history survives a failed sample.
    assert.ok(store.history().entities.length > 0);
  });
});

// ---------------------------------------------------------------------------
// Whole-machine health (src/host.mjs + the store's host wiring)
// ---------------------------------------------------------------------------

describe('host health', () => {
  it('cpu math: aggregate + delta between snapshots, clamped to 0-100', async () => {
    const { aggregateCpuTimes, cpuPercentBetween } = await import('../src/host.mjs');
    const cpus = (idle, busy) => [{ times: { idle, user: busy, sys: 0 } }];
    const a = aggregateCpuTimes(cpus(1000, 1000));
    const b = aggregateCpuTimes(cpus(1500, 2500)); // +500 idle over +2000 total
    assert.equal(cpuPercentBetween(a, b), 75);
    assert.equal(cpuPercentBetween(null, b), null, 'first sample has no delta');
    assert.equal(cpuPercentBetween(a, a), null, 'zero elapsed must not divide by zero');
    assert.equal(aggregateCpuTimes([]), null);
  });

  it('memory: MemAvailable wins over plain free; missing meminfo falls back', async () => {
    const { memoryFromMeminfo } = await import('../src/host.mjs');
    const linux = memoryFromMeminfo('MemTotal: 16000 kB\nMemAvailable:    4096 kB\n', 16_000 * 1024, 100 * 1024);
    assert.equal(linux.availableBytes, 4096 * 1024);
    assert.equal(linux.usedBytes, (16_000 - 4096) * 1024);
    const fallback = memoryFromMeminfo(null, 1000, 400);
    assert.equal(fallback.availableBytes, 400);
    assert.equal(fallback.usedBytes, 600);
  });

  it('probe: second sample carries cpu%, disks dedupe by device, meminfo errors degrade', async () => {
    const { createHostProbe } = await import('../src/host.mjs');
    let tick = 0;
    const probe = createHostProbe({
      cpusFn: () => [{ times: { idle: 1000 + tick * 500, user: 1000 + tick * 1500 } }],
      loadavgFn: () => [0.5, 0.4, 0.3],
      uptimeFn: () => 3600,
      totalmemFn: () => 8 * 1024 ** 3,
      freememFn: () => 2 * 1024 ** 3,
      readMeminfo: async () => { throw new Error('not linux'); },
      statFn: async (mount) => ({ dev: mount === '/home' ? 1 : 1 }), // same device
      statfsFn: async () => ({ bsize: 4096, blocks: 1000, bfree: 400, bavail: 300 }),
      mounts: ['/', '/home'],
    });
    const first = await probe.sample();
    assert.equal(first.cpuPercent, null, 'no delta on the very first sample');
    assert.equal(first.mem.usedBytes, 6 * 1024 ** 3, 'fallback used = total - free');
    assert.equal(first.disks.length, 1, 'same-device mounts collapse to one disk');
    assert.equal(first.disks[0].totalBytes, 4096 * 1000);
    assert.deepEqual(first.load, [0.5, 0.4, 0.3]);

    tick = 1; // +500 idle over +2000 total -> 75%
    const second = await probe.sample();
    assert.equal(second.cpuPercent, 75);
  });

  it('store: host readings are recorded even while the coordinator is down', async () => {
    const store = makeStore({
      coordinator: { inventory: async () => { throw new Error('coordinator down'); } },
    });
    // Not started (no timer): drive one tick by hand with an injected probe.
    const hosted = createMetricsStore({
      config: { metricsIntervalMs: INTERVAL },
      coordinator: { inventory: async () => { throw new Error('coordinator down'); } },
      host: {
        sample: async () => ({
          at: Date.now(),
          cpuPercent: 33,
          cores: 4,
          load: [1, 1, 1],
          uptimeSec: 60,
          mem: { totalBytes: 1000, usedBytes: 250, availableBytes: 750 },
          disks: [{ mount: '/', totalBytes: 10_000, usedBytes: 9_500, availableBytes: 500 }],
        }),
      },
    });
    await hosted.sampleOnce();
    const view = hosted.history();
    assert.equal(view.host.cpuPercent, 33, 'snapshot survives a coordinator failure');
    assert.equal(view.host.disks[0].usedBytes, 9_500);
    const hostEnt = view.entities.find((e) => e.key === 'host');
    assert.ok(hostEnt, 'host history entity must exist');
    assert.equal(hostEnt.kind, 'host');
    assert.deepEqual(hostEnt.points[0].slice(1), [33, 250]);
    assert.match(String(view.sampler.lastError), /coordinator down/);
    void store;
  });
});
