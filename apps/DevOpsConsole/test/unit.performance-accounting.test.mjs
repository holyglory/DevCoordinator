import assert from 'node:assert/strict';
import test from 'node:test';

import {
  cgroupCpuPercentBetween,
  cgroupCpuUsageFromFile,
  cgroupEventsFromFile,
  cgroupMemoryFromFiles,
  memoryDiagnosticsFromMeminfo,
  passwdAccountsFromFile,
} from '../src/host.mjs';
import { buildPerformanceSnapshot, createMetricsStore } from '../src/metrics.mjs';

const GIB = 1024 ** 3;
const SAMPLE_AT = Date.parse('2026-08-02T10:15:00.000Z');
const INTERVAL_MS = 10_000;

function hostFixture(overrides = {}) {
  return {
    at: SAMPLE_AT,
    cpuPercent: 50,
    cores: 8,
    load: [1, 1, 1],
    mem: {
      usedBytes: 10 * GIB,
      totalBytes: 20 * GIB,
      availableBytes: 10 * GIB,
    },
    disks: [],
    uptimeSec: 100,
    ...overrides,
  };
}

function family({ id, name, memoryBytes, cpuRawPercent, sampledAt = SAMPLE_AT, scopes = [] }) {
  return {
    family_id: id,
    root_repository: {
      repo_id: `root-${id}`,
      display_name: name,
      canonical_root: `/private/${name.toLowerCase()}`,
    },
    usage: {
      memory_bytes: memoryBytes,
      cpu_percent: cpuRawPercent,
      sampled_at: sampledAt,
    },
    scopes,
  };
}

function snapshot({ host = hostFixture(), inventory = {}, at = SAMPLE_AT } = {}) {
  return buildPerformanceSnapshot({
    host,
    inventory: {
      servers: [],
      docker: { available: true, containers: [] },
      repository_trees: [],
      project_usage: [],
      unassigned_resources: [],
      lifecycle_violations: [],
      ...inventory,
    },
    at,
    intervalMs: INTERVAL_MS,
  });
}

function segment(result, key) {
  const found = result.segments.find((item) => item.key === key);
  assert.ok(found, `missing performance segment ${key}`);
  return found;
}

function sumUsedMemory(result) {
  return result.segments
    .filter((item) => item.key !== 'available')
    .reduce((total, item) => total + Number(item.current?.stackMemoryBytes || 0), 0);
}

function sumUsedCpu(result) {
  return result.segments
    .filter((item) => item.key !== 'available')
    .reduce((total, item) => total + Number(item.current?.stackCpuPercent || 0), 0);
}

test('one authoritative family segment reconciles memory and CPU without root/family double counting', () => {
  const result = snapshot({
    inventory: {
      repository_trees: [family({
        id: 'family-aurora-private-id',
        name: 'Aurora',
        memoryBytes: 6 * GIB,
        cpuRawPercent: 80,
        scopes: [{
          kind: 'root',
          repo_id: 'repo-aurora-private-id',
          usage: { memory_bytes: 5 * GIB, cpu_percent: 70, sampled_at: SAMPLE_AT },
        }, {
          kind: 'temporary',
          repo_id: 'repo-aurora-preview-private-id',
          usage: { memory_bytes: 1 * GIB, cpu_percent: 10, sampled_at: SAMPLE_AT },
        }],
      })],
      // This compatibility row describes the same family and must be ignored
      // whenever the authoritative repository tree exists.
      project_usage: [{
        usage_key: 'path:/private/aurora',
        name: 'Aurora duplicate',
        memory_bytes: 6 * GIB,
        cpu_percent: 80,
        sampled_at: SAMPLE_AT,
      }],
    },
  });

  const projects = result.segments.filter((item) => item.kind === 'project-family');
  assert.deepEqual(projects.map((item) => item.key), ['family:family-aurora-private-id']);
  assert.equal(projects[0].current.memoryBytes, 6 * GIB);
  assert.equal(projects[0].current.cpuPercent, 10,
    '80 process-percent points on eight cores must occupy 10% of host capacity');
  assert.equal(result.segments.some((item) => item.key.startsWith('repo:')), false);
  assert.equal(result.segments.some((item) => item.key.startsWith('proj:')), false);

  assert.equal(sumUsedMemory(result), 10 * GIB,
    'attributed and explicit residual memory must reconcile to host used');
  assert.equal(sumUsedCpu(result), 50,
    'attributed and residual CPU must reconcile to normalized whole-host CPU');
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 4 * GIB);
  assert.equal(segment(result, 'available').current.memoryBytes, 10 * GIB);
  assert.equal(
    sumUsedMemory(result) + segment(result, 'available').current.stackMemoryBytes,
    20 * GIB,
    'used plus available must reconcile to MemTotal',
  );
  assert.equal(
    sumUsedCpu(result) + segment(result, 'available').current.stackCpuPercent,
    100,
    'busy plus idle CPU must reconcile to whole-host capacity',
  );
  assert.equal(result.sampleSkewMs, 0);
});

test('measured non-project agent browsers reduce the residual without double-counting project runtimes', () => {
  const result = snapshot({
    inventory: {
      repository_trees: [family({
        id: 'family-agent-work',
        name: 'Agent work',
        memoryBytes: 3 * GIB,
        cpuRawPercent: 80,
      })],
      agent_browsers: {
        schema_version: 1,
        sampled_at: SAMPLE_AT,
        policy: { idle_timeout_seconds: 900, termination_grace_seconds: 30 },
        totals: {
          session_count: 2,
          process_count: 7,
          memory_bytes: 2 * GIB,
          cpu_percent: 120,
          idle_session_count: 1,
          protected_session_count: 1,
          reaped_total: 4,
          reclaimed_memory_bytes: 5 * GIB,
        },
        sessions: [{
          session_id: 'browser-a',
          state: 'active',
          uid: 1000,
          cgroup_class: 'agent-browser',
          agent: 'codex',
          repository_name: 'Agent work',
          first_seen_at: SAMPLE_AT - 60_000,
          last_observed_at: SAMPLE_AT,
          last_observed_work_at: SAMPLE_AT - 5_000,
          idle_seconds: 5,
          process_count: 4,
          memory_bytes: 1536 * 1024 ** 2,
          cpu_percent: 100,
          reap_eligible: false,
        }],
        recent_reaps: [{
          session_id: 'browser-old',
          agent: 'claude',
          repository_name: 'Other work',
          reaped_at: SAMPLE_AT - 120_000,
          reason: 'idle timeout',
          process_count: 3,
          reclaimed_memory_bytes: GIB,
        }],
      },
    },
  });

  const browsers = segment(result, 'agent-browsers');
  assert.equal(browsers.kind, 'agent-browsers');
  assert.equal(browsers.current.memoryBytes, 2 * GIB);
  assert.equal(browsers.current.cpuRawPercent, 120);
  assert.equal(browsers.current.cpuPercent, 15,
    'raw process CPU must be normalized only when compared with whole-host capacity');
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 5 * GIB,
    'project and producer-excluded non-project browser totals are each subtracted exactly once');
  assert.equal(segment(result, 'system-unclassified').current.cpuPercent, 25);
  assert.equal(browsers.agentBrowsers.sessions[0].lastObservedWorkAt, SAMPLE_AT - 5_000);
  assert.equal(browsers.agentBrowsers.recentReaps[0].reclaimedMemoryBytes, GIB);
  assert.match(result.semantics.agentBrowsers, /producer excludes sessions.*repository runtime/i);
  assert.equal(sumUsedMemory(result), 10 * GIB);
  assert.equal(sumUsedCpu(result), 50);
});

test('malformed agent-browser accounting stays in the residual instead of becoming invented usage', () => {
  const result = snapshot({
    inventory: {
      agent_browsers: {
        schema_version: 1,
        sampled_at: SAMPLE_AT,
        policy: { idle_timeout_seconds: 900 },
        totals: { memory_bytes: 8 * GIB, cpu_percent: 400 },
        sessions: [],
        recent_reaps: [],
      },
    },
  });

  assert.equal(result.segments.some((item) => item.key === 'agent-browsers'), false);
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 10 * GIB);
  assert.ok(result.issues.some((issue) => issue.code === 'agent-browser-accounting-invalid'));
});

test('over-attribution is scaled only for the displayed stack and residuals never go negative', () => {
  const result = snapshot({
    inventory: {
      repository_trees: [family({
        id: 'family-overage',
        name: 'Overage',
        memoryBytes: 12 * GIB,
        cpuRawPercent: 480,
      })],
    },
  });
  const project = segment(result, 'family:family-overage');
  const residual = segment(result, 'system-unclassified');

  assert.equal(project.current.memoryBytes, 12 * GIB,
    'coverage keeps the incompatible observed sum visible');
  assert.ok(project.current.stackMemoryBytes < project.current.memoryBytes,
    'only the reconciled visual stack may scale an over-attributed observation');
  assert.equal(residual.current.memoryBytes, 0);
  assert.equal(residual.current.cpuPercent, 0);
  assert.ok(result.memory.overageBytes > 0);
  assert.ok(result.cpu.overagePercent > 0);
  assert.equal(result.exact, false);
  assert.equal(sumUsedMemory(result), 10 * GIB);
  assert.equal(sumUsedCpu(result), 50);
  for (const item of result.segments) {
    assert.ok(item.current.stackMemoryBytes >= 0, `${item.key} memory stack went negative`);
    assert.ok(item.current.stackCpuPercent >= 0, `${item.key} CPU stack went negative`);
  }
  assert.match(JSON.stringify(result.semantics), /shared memory/i,
    'the residual explanation must cover the measured user-session shared-memory gap');
  assert.match(JSON.stringify(result.semantics), /missing telemetry|work outside/i,
    'the residual must not imply every unattributed byte has one known cause');
});

test('missing and delayed sample boundaries remain visibly inexact with coverage evidence', () => {
  const result = snapshot({
    inventory: {
      repository_trees: [
        family({
          id: 'family-stale',
          name: 'Stale',
          memoryBytes: 2 * GIB,
          cpuRawPercent: 16,
          sampledAt: SAMPLE_AT - 60_000,
        }),
        family({
          id: 'family-missing-time',
          name: 'Missing time',
          memoryBytes: 1 * GIB,
          cpuRawPercent: 8,
          sampledAt: null,
        }),
      ],
    },
  });

  assert.equal(result.exact, false);
  assert.equal(segment(result, 'family:family-stale').exact, false);
  assert.equal(segment(result, 'family:family-missing-time').exact, false);
  assert.equal(segment(result, 'family:family-missing-time').fresh, null,
    'a missing timestamp must remain unknown, not silently fresh');
  assert.equal(result.sampleSkewMs, 60_000);
  assert.match(JSON.stringify(result.coverage), /stale/i,
    'coverage must enumerate stale observations instead of claiming exact accounting');
  assert.match(JSON.stringify(result.coverage), /missing/i,
    'coverage must enumerate missing sample timestamps');
  assert.ok(Number.isFinite(result.memory.coverageRatio));
  assert.ok(Number.isFinite(result.cpu.coverageRatio));
});

test('control/other attribution requires an explicit immutable unassigned-resource match', () => {
  const result = snapshot({
    inventory: {
      servers: [{
        id: 'server-explicitly-unassigned',
        name: 'Coordinator worker',
        process_usage: {
          memory_bytes: 1 * GIB,
          cpu_percent: 16,
          sampled_at: SAMPLE_AT,
        },
      }, {
        id: 'server-merely-unclaimed',
        name: 'Unproved process',
        process_usage: {
          memory_bytes: 3 * GIB,
          cpu_percent: 24,
          sampled_at: SAMPLE_AT,
        },
      }],
      unassigned_resources: [{
        resource_kind: 'server',
        resource_id: 'server-explicitly-unassigned',
      }],
    },
  });
  const control = segment(result, 'control-other');

  assert.equal(control.current.memoryBytes, 1 * GIB);
  assert.equal(control.current.cpuPercent, 2);
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 9 * GIB,
    'unproved processes stay in the honest host residual');
});

test('an ownership-problem container contributes exactly once outside its former family', () => {
  const problemId = 'container-ownership-problem';
  const result = snapshot({
    inventory: {
      docker: {
        available: true,
        containers: [{
          host_resource_id: 'container-healthy',
          name: 'healthy worker',
          status: 'running',
          stats: {
            timestamp: SAMPLE_AT,
            memory_usage_bytes: 2 * GIB,
            cpu_percent: 16,
          },
        }, {
          host_resource_id: problemId,
          name: 'ownership problem worker',
          status: 'running',
          stats: {
            timestamp: SAMPLE_AT,
            memory_usage_bytes: 3 * GIB,
            cpu_percent: 24,
          },
        }],
      },
      repository_trees: [family({
        id: 'family-problem-partition',
        name: 'Partitioned',
        memoryBytes: 2 * GIB,
        cpuRawPercent: 16,
        scopes: [{
          kind: 'root',
          repo_id: 'root-family-problem-partition',
          container_resource_ids: ['container-healthy'],
        }],
      })],
      unassigned_resources: [{
        resource_kind: 'container',
        resource_id: problemId,
      }],
    },
  });

  const project = segment(result, 'family:family-problem-partition');
  const control = segment(result, 'control-other');
  assert.equal(project.current.memoryBytes, 2 * GIB);
  assert.deepEqual(project.contributors.map((item) => item.id), ['container-healthy']);
  assert.equal(control.current.memoryBytes, 3 * GIB);
  assert.deepEqual(control.contributors.map((item) => item.id), [problemId]);
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 5 * GIB);
  assert.equal(sumUsedMemory(result), 10 * GIB,
    'the ownership-problem resource must not be counted in both family and control/other');
});

test('host diagnostic parsers retain meminfo and cgroup working/anon/shmem evidence', () => {
  const meminfo = memoryDiagnosticsFromMeminfo([
    'MemTotal:       20971520 kB',
    'MemAvailable:   10485760 kB',
    'Shmem:           3145728 kB',
    'AnonPages:       5242880 kB',
    'SUnreclaim:       524288 kB',
    'Slab:             786432 kB',
    'PageTables:       131072 kB',
    'KernelStack:       65536 kB',
  ].join('\n'));
  assert.deepEqual(meminfo, {
    available: true,
    shmemBytes: 3 * GIB,
    anonPagesBytes: 5 * GIB,
    sUnreclaimBytes: 512 * 1024 ** 2,
    slabBytes: 768 * 1024 ** 2,
    pageTablesBytes: 128 * 1024 ** 2,
    kernelStackBytes: 64 * 1024 ** 2,
  });

  assert.deepEqual(cgroupMemoryFromFiles(String(7 * GIB), [
    `inactive_file ${1 * GIB}`,
    `anon ${4 * GIB}`,
    `shmem ${3 * GIB}`,
    `file ${2 * GIB}`,
    `kernel ${512 * 1024 ** 2}`,
    `slab ${256 * 1024 ** 2}`,
    `pagetables ${64 * 1024 ** 2}`,
    `kernel_stack ${32 * 1024 ** 2}`,
    `sock ${16 * 1024 ** 2}`,
  ].join('\n')), {
    currentBytes: 7 * GIB,
    inactiveFileBytes: 1 * GIB,
    workingBytes: 6 * GIB,
    anonBytes: 4 * GIB,
    shmemBytes: 3 * GIB,
    fileBytes: 2 * GIB,
    kernelBytes: 512 * 1024 ** 2,
    slabBytes: 256 * 1024 ** 2,
    pageTablesBytes: 64 * 1024 ** 2,
    kernelStackBytes: 32 * 1024 ** 2,
    socketBytes: 16 * 1024 ** 2,
  });
  assert.equal(cgroupMemoryFromFiles('not-a-number', 'anon 1'), null);
  assert.equal(cgroupMemoryFromFiles('', 'anon 1'), null,
    'a missing memory.current file must stay unavailable instead of becoming zero');

  assert.equal(cgroupCpuUsageFromFile('usage_usec 2500000\nuser_usec 2000000'), 2_500_000);
  assert.equal(cgroupCpuUsageFromFile('usage_usec nope'), null);
  assert.equal(cgroupCpuPercentBetween(
    { at: 1_000, usageUsec: 1_000_000 },
    { at: 2_000, usageUsec: 2_500_000 },
  ), 150, 'one cgroup may truthfully use more than one CPU core');
  assert.deepEqual(cgroupEventsFromFile('populated 1\nfrozen 0'), {
    populated: true,
    frozen: false,
  });
  assert.deepEqual([...passwdAccountsFromFile([
    'root:x:0:0:root:/root:/bin/bash',
    'developer:x:1000:1000::/home/developer:/bin/bash',
    'broken-line',
  ].join('\n')).entries()], [[0, 'root'], [1000, 'developer']]);
});

test('schema-2 performance accounting stacks disjoint cgroup roots and keeps repositories as drilldowns', () => {
  const cgroup = (role, workingBytes, cpuRawPercent, processCount, extra = {}) => ({
    key: role,
    role,
    label: role,
    available: true,
    additive: true,
    sampledAt: SAMPLE_AT,
    currentBytes: workingBytes,
    inactiveFileBytes: 0,
    workingBytes,
    anonBytes: workingBytes,
    shmemBytes: 0,
    kernelBytes: 0,
    cpuRawPercent,
    processCount,
    populated: processCount > 0,
    activeChildCount: 0,
    childrenAvailable: true,
    children: [],
    ...extra,
  });
  const result = snapshot({
    host: hostFixture({
      mem: {
        basis: 'MemTotal-MemAvailable',
        usedBytes: 10 * GIB,
        totalBytes: 20 * GIB,
        availableBytes: 10 * GIB,
        diagnostics: {
          schemaVersion: 2,
          meminfo: { available: true },
          cgroups: [
            cgroup('project-runtimes', 3 * GIB, 80, 8),
            cgroup('coordinator-control', 1 * GIB, 16, 3),
            cgroup('coordinator-background', 1 * GIB, 8, 2),
            cgroup('active-test-executions', 2 * GIB, 24, 4, { activeChildCount: 2 }),
            cgroup('developer-sessions', 1 * GIB, 32, 5),
            { ...cgroup('system-services', 7 * GIB, 10, 20), additive: false },
          ],
        },
      },
    }),
    inventory: {
      repository_trees: [family({
        id: 'family-split',
        name: 'Repository crosscheck',
        memoryBytes: 4 * GIB,
        cpuRawPercent: 160,
      })],
      agent_browsers: {
        schema_version: 1,
        sampled_at: SAMPLE_AT,
        policy: { idle_timeout_seconds: 900, termination_grace_seconds: 30 },
        totals: {
          session_count: 1,
          process_count: 4,
          memory_bytes: 512 * 1024 ** 2,
          cpu_percent: 20,
          idle_session_count: 0,
          protected_session_count: 0,
          reaped_total: 0,
          reclaimed_memory_bytes: 0,
        },
        sessions: [],
        recent_reaps: [],
      },
    },
  });

  for (const key of [
    'project-runtimes', 'coordinator-control', 'coordinator-background',
    'active-test-executions', 'developer-sessions',
  ]) {
    assert.equal(segment(result, key).additive, true, `${key} must be in the host stack`);
  }
  assert.equal(segment(result, 'family:family-split').additive, false);
  assert.equal(segment(result, 'family:family-split').current.stackMemoryBytes, 0,
    'repository telemetry is a crosscheck over project-runtimes, never another stack layer');
  assert.equal(segment(result, 'agent-browsers').additive, false,
    'browser detail is already contained by a disjoint host root');
  assert.equal(segment(result, 'agent-browsers').current.stackMemoryBytes, 0);
  assert.equal(result.segments.some((item) => item.key === 'system-services'), false,
    'overlapping system.slice diagnostics must not become a stack segment');
  assert.equal(segment(result, 'system-unclassified').current.memoryBytes, 2 * GIB);
  assert.equal(segment(result, 'system-unclassified').current.cpuPercent, 30);
  assert.equal(sumUsedMemory(result), 10 * GIB);
  assert.equal(sumUsedCpu(result), 50);
  assert.equal(result.residual.diagnostics.projectRuntimeCrosscheck.repositoryMemoryBytes, 4 * GIB);
  assert.equal(result.residual.diagnostics.projectRuntimeCrosscheck.projectRuntimeBytes, 3 * GIB);
  assert.equal(result.residual.diagnostics.projectRuntimeCrosscheck.differenceBytes, -1 * GIB);
  assert.ok(result.issues.some((issue) => issue.code === 'project-runtime-attribution-gap'));
  assert.match(result.semantics.cgroupAccounting, /disjoint cgroup-v2 roots.*added once/i);
});

test('overlapping user-session/shared-memory diagnostics explain but never inflate the residual stack', () => {
  const inventory = {
    repository_trees: [family({
      id: 'family-diagnostics',
      name: 'Diagnostics',
      memoryBytes: 3 * GIB,
      cpuRawPercent: 80,
    })],
  };
  const withoutDiagnostics = snapshot({ inventory });
  const withDiagnostics = snapshot({
    inventory,
    host: hostFixture({
      mem: {
        usedBytes: 10 * GIB,
        totalBytes: 20 * GIB,
        availableBytes: 10 * GIB,
        diagnostics: {
          additive: true,
          stackContributionBytes: 99 * GIB,
          meminfo: {
            available: true,
            shmemBytes: 6 * GIB,
            anonPagesBytes: 8 * GIB,
            sUnreclaimBytes: 1 * GIB,
            slabBytes: 2 * GIB,
            pageTablesBytes: 512 * 1024 ** 2,
            kernelStackBytes: 128 * 1024 ** 2,
          },
          cgroups: [{
            key: 'user.slice',
            label: 'Developer / user sessions',
            available: true,
            currentBytes: 12 * GIB,
            inactiveFileBytes: 2 * GIB,
            workingBytes: 10 * GIB,
            anonBytes: 7 * GIB,
            shmemBytes: 6 * GIB,
          }],
        },
      },
    }),
  });

  assert.equal(withDiagnostics.residual.memoryBytes, withoutDiagnostics.residual.memoryBytes);
  assert.equal(sumUsedMemory(withDiagnostics), sumUsedMemory(withoutDiagnostics));
  assert.equal(withDiagnostics.residual.diagnostics.additive, false);
  assert.equal(withDiagnostics.residual.diagnostics.overlapping, true);
  assert.equal(withDiagnostics.residual.diagnostics.stackContributionBytes, 0);
  assert.equal(withDiagnostics.residual.diagnostics.meminfo.shmemBytes, 6 * GIB);
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].key, 'user.slice');
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].label,
    'Developer / user sessions');
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].available, true);
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].additive, false,
    'schema-1 diagnostics remain overlapping clues');
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].workingBytes, 10 * GIB);
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].anonBytes, 7 * GIB);
  assert.equal(withDiagnostics.residual.diagnostics.cgroups[0].shmemBytes, 6 * GIB);
  assert.ok(
    withDiagnostics.residual.diagnostics.cgroups[0].workingBytes
      > withDiagnostics.residual.memoryBytes,
    'overlap may exceed the residual and therefore must remain a clue, never an additive component',
  );
});

test('metrics history retains compact reconciled samples for refresh-stable project detail', async () => {
  let clock = SAMPLE_AT;
  let host = hostFixture();
  let inventory = {
    servers: [],
    docker: { available: true, containers: [] },
    repository_trees: [family({
      id: 'family-aurora-history',
      name: 'Aurora',
      memoryBytes: 2 * GIB,
      cpuRawPercent: 40,
    })],
    project_usage: [],
    unassigned_resources: [],
    lifecycle_violations: [],
  };
  const store = createMetricsStore({
    config: { metricsIntervalMs: INTERVAL_MS, retainedInventory: true, projectRoot: '/repo' },
    now: () => clock,
    host: { sample: async () => host },
    coordinator: { inventory: async () => inventory },
  });

  await store.sampleOnce();
  clock += INTERVAL_MS;
  host = hostFixture({ at: clock, cpuPercent: 55 });
  inventory = structuredClone(inventory);
  inventory.repository_trees[0].usage = {
    memory_bytes: 3 * GIB,
    cpu_percent: 48,
    sampled_at: clock,
  };
  await store.sampleOnce();

  const performance = store.history().performance;
  assert.equal(performance.segments.filter((item) => item.kind === 'project-family').length, 1);
  assert.equal(performance.samples.length, 2);
  assert.deepEqual(performance.samples.map((item) => item.at), [SAMPLE_AT, clock]);
  for (const sample of performance.samples) {
    assert.equal(
      sample.memory.segments
        .filter((item) => item.key !== 'available')
        .reduce((total, item) => total + item.value, 0),
      sample.memory.usedBytes,
    );
    assert.equal(
      sample.cpu.segments
        .filter((item) => item.key !== 'available')
        .reduce((total, item) => total + item.value, 0),
      sample.cpu.usedPercent,
    );
  }
});
