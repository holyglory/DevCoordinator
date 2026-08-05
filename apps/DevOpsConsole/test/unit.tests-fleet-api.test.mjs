import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import test from 'node:test';

import { createConsoleApi } from '../src/api.mjs';

const ORIGINAL_SOURCE = Object.freeze({
  schema_version: 1,
  kind: 'original',
  repository_id: 'repo-visible',
  repository_generation: 4,
});
const TEMPORARY_SOURCE = Object.freeze({
  schema_version: 1,
  kind: 'temporary',
  repository_id: 'repo-visible-worktree',
  repository_generation: 2,
});
const MEMORY_WAIT = Object.freeze({
  code: 'host_memory',
  since: 1_775_000_000,
  required_mib: 16_384,
  available_mib: null,
  reserve_mib: 2_048,
  observed_at: 1_775_000_010,
  source: 'learned_peak',
});
const MEASURED_USAGE = Object.freeze({
  available: true,
  peak_memory_mib: 13_824.5,
  cpu_seconds: 912.25,
  measured_attempts: 1,
  total_attempts: 1,
});

function responseRecorder() {
  return {
    status: null,
    headersSent: false,
    body: '',
    writeHead(status) {
      this.status = status;
      this.headersSent = true;
    },
    end(body = '') {
      this.body += String(body);
    },
  };
}

function fixture({
  grants = new Set(['tests:read:repo-visible', 'tests:read:repo-idle']),
  runActor = 'google:viewer@example.test',
  admin = false,
  coordinatorOverrides = {},
} = {}) {
  const calls = [];
  const hour = '2026-07-28T00:00:00Z';
  const payload = {
    schema_version: 2,
    window: { hours: 24 },
    snapshot: { generated_at: '2026-07-28T00:00:00Z' },
    summary: {
      repository_count: 2,
      test_count: 1000,
      p95_queue_wait_seconds: 91,
      avoided_work: { available: true, test_count: 640, test_seconds: 4_200 },
    },
    hours: [hour],
    repositories: [
      {
        repo_id: 'repo-visible', display_name: 'Visible', state: 'healthy',
        summary: {
          run_count: 1, attempt_count: 1, test_count: 7, test_seconds: 120,
          wall_seconds: 60, passed_count: 7, test_failure_count: 0,
          infrastructure_failure_count: 0,
        },
        hourly: [{
          hour_start: hour, test_seconds: 120, test_count: 7,
          failure_count: 0, infrastructure_count: 0,
        }],
      },
      {
        repo_id: 'repo-hidden', display_name: 'Hidden', state: 'failing',
        summary: {
          run_count: 99, attempt_count: 99, test_count: 993, test_seconds: 9000,
          wall_seconds: 90, failure_count: 42, test_failure_count: 42,
          infrastructure_failure_count: 0,
        },
        hourly: [{
          hour_start: hour, test_seconds: 9000, test_count: 993,
          failure_count: 42, infrastructure_count: 0,
        }],
      },
    ],
    capacity: [{
      hour_start: hour,
      test_seconds: 9120,
      test_count: 1000,
      failure_count: 42,
      infrastructure_count: 0,
      p95_queue_wait_seconds: 73,
      runner_capacity: 16,
    }],
    attention: [{ repo_id: 'repo-hidden', title: 'secret failure' }],
  };
  const coordinator = {
    async testRepositories() {
      return {
        schema_version: 1,
        repositories: [
          { repo_id: 'repo-visible', canonical_root: '/private/visible', display_name: 'Visible' },
          { repo_id: 'repo-hidden', canonical_root: '/private/hidden', display_name: 'Hidden' },
          { repo_id: 'repo-idle', canonical_root: '/private/idle', display_name: 'Idle', manifest_status: 'missing' },
        ],
      };
    },
    async testFleet(options) {
      calls.push(options);
      return payload;
    },
    async inventory(options) {
      calls.push({ inventory: options });
      return {
        schema_version: 2,
        repositories: [
          {
            repo_id: 'repo-visible', canonical_root: '/private/visible',
            display_name: 'Visible', generation: 4,
          },
          {
            repo_id: 'repo-visible-worktree', canonical_root: '/private/visible-worktree',
            display_name: 'Visible review worktree', generation: 2,
          },
        ],
        repository_trees: [{
          family_id: 'family-visible',
          root_repository: {
            repo_id: 'repo-visible', canonical_root: '/private/visible', display_name: 'Visible',
          },
          scopes: [
            {
              repo_id: 'repo-visible', kind: 'root', canonical_root: '/private/visible',
              display_name: 'Visible',
            },
            {
              repo_id: 'repo-visible-worktree', kind: 'temporary',
              canonical_root: '/private/visible-worktree', display_name: 'Visible review worktree',
              expires_at: '2026-07-29T12:00:00Z',
            },
          ],
        }],
      };
    },
    async testPlan(options) {
      calls.push({ plan: options });
      return {
        repository_id: options.repoId,
        intent: options.intent,
        plan_id: 'plan-1',
        operation_id: options.operationId,
        plan: {
          source: {
            repository_id: options.repoId,
            temporary_root: options.source.temporaryRoot,
          },
        },
      };
    },
    async submitTestRun(options) {
      calls.push({ submit: options });
      return { repository_id: options.repoId, run_id: 'run-1' };
    },
    async testRuns(options) {
      calls.push({ runs: options });
      return {
        repository_id: options.repoId,
        runs: [{
          run_id: 'run-1', repository_id: options.repoId, actor: runActor, state: 'failed',
          owner_uid: 1001, internal_ticket: 'must-not-leak',
          wait: { ...MEMORY_WAIT, internal_sample: 'must-not-leak' },
          usage: {
            available: false, peak_memory_mib: null, cpu_seconds: null,
            internal_sample: 'must-not-leak',
          },
        }],
        next_cursor: options.after ? null : 'run-1',
      };
    },
    async testRunStatus({ runId }) {
      calls.push({ status: runId });
      return {
        run_id: runId, repository_id: 'repo-visible', actor: runActor, state: 'failed', owner_uid: 1001,
        wait: { ...MEMORY_WAIT, internal_sample: 'must-not-leak' },
        usage: { ...MEASURED_USAGE, internal_sample: 'must-not-leak' },
        targets: [{
          target_name: 'unit', state: 'test_failed', worktree_key: '/private/worktree',
          cpu_millis: 8_000, memory_mib: 32_768, pids: 2_048,
          wait: { ...MEMORY_WAIT, internal_sample: 'must-not-leak' },
          usage: { ...MEASURED_USAGE, internal_sample: 'must-not-leak' },
          attempts: [{
            attempt_id: 'attempt-1', state: 'test_failed',
            usage: { ...MEASURED_USAGE, internal_sample: 'must-not-leak' },
            runtime_id: 'private-runtime-id',
          }],
        }],
      };
    },
    async testRunSummary({ runId }) {
      calls.push({ summary: runId });
      return {
        run_id: runId, repository_id: 'repo-visible', conclusion: 'test_failed',
        usage: { ...MEASURED_USAGE, internal_sample: 'must-not-leak' },
      };
    },
    async testRunFailures({ runId, after, limit }) {
      calls.push({ failures: { runId, after, limit } });
      return { run_id: runId, repository_id: 'repo-visible', failures: [], next: null };
    },
    async testRunArtifacts({ runId }) {
      return { run_id: runId, repository_id: 'repo-visible', artifacts: [], next: null };
    },
    async testRunCases({ runId, after, limit }) {
      calls.push({ cases: { runId, after, limit } });
      return { run_id: runId, repository_id: 'repo-visible', cases: [], next: null };
    },
    async cancelTestRun(options) {
      calls.push({ cancel: options });
      return { run_id: options.runId, repository_id: 'repo-visible', state: 'cancelling' };
    },
    async retryTestRun(options) {
      calls.push({ retry: options });
      return { run_id: 'run-retry', repository_id: 'repo-visible', state: 'queued' };
    },
    async testRepositorySetup({ repoId }) {
      return {
        repository_id: repoId, status: 'ready',
        targets: [{
          name: 'integration', driver: 'pytest', reporter: 'pytest-events',
          network: 'loopback', fixtures: ['postgres'], depends_on: [],
          resources: {
            cpu_millis: 1000, memory_mib: 1024, pids: 128,
            secret: 'fixture-resource-secret', path: '/private/must-not-leak',
          },
        }],
        repository: '/private/visible', manifest: '/private/visible/.codex/tests.json',
        fixtures: { postgres: { secret: 'fixture-postgres-secret' } },
        isolation: {
          network: 'loopback', private_scratch: true, kill_after_run: true,
          cpu_millis: 8_000, memory_mib: 32_768, pids: 2_048,
        },
        capability_policy: {
          ok: false, policy_fingerprint: 'must-not-leak', repository_generation: 4,
          requested: ['fixture.postgres', 'network.loopback'],
          missing: ['fixture.postgres'], repository_grant: true, generation_match: true,
        },
      };
    },
    async testEvents({ repoId }) {
      return { repository_id: repoId, events: [], next: null };
    },
    ...coordinatorOverrides,
  };
  const api = createConsoleApi({
    config: {
      version: 'test', domain: 'example.test', consoleHost: 'console.example.test',
      consoleOrigin: 'https://console.example.test', lifecycleEnabled: false,
    },
    log: null,
    coordinator,
    routeStore: { list: () => [] },
    upstreamAuthStore: { describe: () => ({ configured: false }) },
    accessStore: { isAdmin: () => admin, canAccess: (_email, grant) => grants.has(grant) },
    guard: { checkOrigin: () => true },
    certManager: { info: () => null },
    metrics: { ingest: () => {}, history: () => ({ entities: [], host: null }) },
    prefs: null,
  });
  return { api, calls, payload };
}

function jsonRequest(url, value) {
  return {
    method: 'POST', url, headers: {},
    [Symbol.asyncIterator]: async function* () {
      yield Buffer.from(JSON.stringify(value));
    },
  };
}

function p99(values) {
  return [...values].sort((left, right) => left - right)[Math.ceil(values.length * 0.99) - 1];
}

test('fleet Tests endpoint scopes rollups and joins never-tested enrolled repos', async () => {
  const { api, calls } = fixture();
  const req = { method: 'GET', url: '/api/tests/fleet?hours=24', headers: {} };
  const res = responseRecorder();
  await api.handle(req, res, { email: 'viewer@example.test' });

  assert.equal(res.status, 200);
  const result = JSON.parse(res.body);
  assert.deepEqual(result.repositories.map((item) => item.repo_id), ['repo-visible', 'repo-idle']);
  assert.equal(result.repositories[1].state, 'idle');
  assert.equal(result.repositories[1].setup_status, 'missing');
  assert.equal(result.summary.repository_count, 2);
  assert.equal(result.summary.repositories_with_activity, 1);
  assert.equal(result.summary.test_count, 7);
  assert.equal(result.summary.attempt_count, 1);
  assert.equal(result.summary.test_failure_count, 0);
  assert.equal(result.summary.infrastructure_failure_count, 0);
  assert.equal(result.summary.p95_queue_wait_seconds, null);
  assert.deepEqual(result.summary.avoided_work, {
    available: false, test_count: null, test_seconds: null,
  });
  assert.equal(result.capacity[0].test_seconds, 120);
  assert.equal(result.capacity[0].infrastructure_count, 0);
  assert.equal(result.capacity[0].p95_queue_wait_seconds, null);
  assert.equal(result.capacity[0].runner_capacity, undefined);
  assert.deepEqual(result.attention, []);
  assert.doesNotMatch(JSON.stringify(result), /repo-hidden|secret failure|private\/hidden/);
  assert.deepEqual(calls, [{ hours: 24 }]);
});

test('fleet Tests preserves non-additive efficiency and capacity metrics for full-fleet readers', async () => {
  const grants = new Set([
    'tests:read:repo-visible',
    'tests:read:repo-hidden',
    'tests:read:repo-idle',
  ]);
  const { api } = fixture({ grants });
  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/fleet?hours=24', headers: {} },
    response,
    { email: 'fleet-reader@example.test' },
  );

  assert.equal(response.status, 200);
  const result = JSON.parse(response.body);
  assert.deepEqual(
    result.repositories.map((item) => item.repo_id),
    ['repo-visible', 'repo-hidden', 'repo-idle'],
  );
  assert.equal(result.summary.p95_queue_wait_seconds, 91);
  assert.deepEqual(result.summary.avoided_work, {
    available: true, test_count: 640, test_seconds: 4_200,
  });
  assert.equal(result.capacity[0].p95_queue_wait_seconds, 73);
  assert.equal(result.capacity[0].runner_capacity, 16);
  assert.equal(result.capacity[0].test_seconds, 9_120);
  assert.equal(result.summary.test_failure_count, 42);
  assert.equal(result.summary.infrastructure_failure_count, 0);
  assert.equal(result.summary.failed_run_count, 42);
  assert.equal(result.summary.infrastructure_count, 0);
});

test('fleet Tests aggregates legacy failure counter names into current aliases', async () => {
  const { api, payload } = fixture();
  const visible = payload.repositories.find((repository) => repository.repo_id === 'repo-visible');
  delete visible.summary.test_failure_count;
  delete visible.summary.infrastructure_failure_count;
  visible.summary.failed_run_count = 3;
  visible.summary.infrastructure_count = 2;

  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/fleet?hours=24', headers: {} },
    response,
    { email: 'legacy-reader@example.test' },
  );

  assert.equal(response.status, 200);
  const result = JSON.parse(response.body);
  assert.equal(result.summary.test_failure_count, 3);
  assert.equal(result.summary.infrastructure_failure_count, 2);
  assert.equal(result.summary.failed_run_count, 3);
  assert.equal(result.summary.infrastructure_count, 2);
});

test('fleet Tests starts retained catalog and rollup reads concurrently', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = new Set();
  let bothStarted;
  const ready = new Promise((resolve) => { bothStarted = resolve; });
  const mark = (name) => {
    started.add(name);
    if (started.size === 2) bothStarted();
  };
  const { api } = fixture({
    coordinatorOverrides: {
      async testRepositories() {
        mark('catalog');
        await gate;
        return { schema_version: 1, repositories: [] };
      },
      async testFleet() {
        mark('fleet');
        await gate;
        return {
          schema_version: 2, summary: {}, repositories: [], capacity: [], attention: [],
        };
      },
    },
  });
  const response = responseRecorder();
  const pending = api.handle(
    { method: 'GET', url: '/api/tests/fleet?hours=24', headers: {} },
    response,
    { email: 'viewer@example.test' },
  );
  await Promise.race([
    bothStarted,
    new Promise((_, reject) => setTimeout(() => reject(new Error('fleet reads were serialized')), 500)),
  ]);
  assert.deepEqual([...started].sort(), ['catalog', 'fleet']);
  release();
  await pending;
  assert.equal(response.status, 200);
});

test('cached fleet Tests API handler p99 remains below 100ms for 50 repositories', async () => {
  const hour = '2026-07-28T00:00:00Z';
  const repositories = Array.from({ length: 50 }, (_, index) => ({
    repo_id: `repo-${String(index).padStart(2, '0')}`,
    canonical_root: `/private/repo-${index}`,
    display_name: `Repository ${index}`,
  }));
  const fleetRepositories = repositories.map((repository, index) => ({
    repo_id: repository.repo_id,
    display_name: repository.display_name,
    state: index % 13 === 0 ? 'failing' : 'healthy',
    summary: {
      run_count: 20,
      test_count: 2_000 + index,
      test_seconds: 3_600 + index,
      wall_seconds: 600,
      passed_count: 1_999 + index,
      failure_count: 1,
    },
    hourly: [{ hour_start: hour, test_seconds: 3_600 + index, test_count: 2_000 + index, failure_count: 1 }],
  }));
  const fleet = {
    schema_version: 2,
    window: { hours: 24 },
    snapshot: { generated_at: hour },
    summary: { repository_count: 50, test_count: 101_225 },
    hours: [hour],
    repositories: fleetRepositories,
    capacity: [{ hour_start: hour, test_seconds: 181_225, test_count: 101_225, failure_count: 50 }],
    attention: [],
  };
  const { api } = fixture({
    admin: true,
    grants: new Set(),
    coordinatorOverrides: {
      async testRepositories() { return { schema_version: 1, repositories }; },
      async testFleet() { return fleet; },
    },
  });
  const request = { method: 'GET', url: '/api/tests/fleet?hours=24', headers: {} };
  const warm = responseRecorder();
  await api.handle(request, warm, { email: 'owner@example.test' });
  assert.equal(warm.status, 200);

  const durations = [];
  for (let sample = 0; sample < 40; sample += 1) {
    const response = responseRecorder();
    const started = performance.now();
    await api.handle(request, response, { email: 'owner@example.test' });
    durations.push(performance.now() - started);
    assert.equal(response.status, 200);
    assert.equal(JSON.parse(response.body).repositories.length, 50);
  }
  const elapsedP99 = p99(durations);
  assert.ok(elapsedP99 < 100,
    `cached fleet Tests API handler p99 was ${elapsedP99.toFixed(1)}ms`);
});

test('fleet Tests endpoint rejects unbounded windows before Coordinator access', async () => {
  const { api, calls } = fixture();
  const req = { method: 'GET', url: '/api/tests/fleet?hours=169', headers: {} };
  const res = responseRecorder();
  await api.handle(req, res, { email: 'viewer@example.test' });

  assert.equal(res.status, 400);
  assert.match(JSON.parse(res.body).error, /hours must be an integer/);
  assert.deepEqual(calls, []);
});

test('repository catalog hides paths and repositories without a test grant', async () => {
  const { api } = fixture();
  const res = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories', headers: {} },
    res,
    { email: 'viewer@example.test' },
  );
  assert.equal(res.status, 200);
  const payload = JSON.parse(res.body);
  assert.deepEqual(payload.repositories.map((item) => item.repo_id), ['repo-visible', 'repo-idle']);
  assert.equal(payload.repositories[0].canonical_root, undefined);
  assert.doesNotMatch(res.body, /repo-hidden|\/private\//);
});

test('repository catalog never exposes host paths, including to Console owners', async () => {
  const { api } = fixture({ admin: true, grants: new Set() });
  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories', headers: {} },
    response,
    { email: 'owner@example.test' },
  );
  assert.equal(response.status, 200);
  assert.doesNotMatch(response.body, /canonical_root|\/private\//);
});

test('manual planning accepts only declared target names and resolves an exact server-authorized source', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = '4d4f45a8-1df0-4d25-a2ae-4f50f77b1bf3';
  const planRes = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/plan', {
      repo_id: 'repo-visible', intent: 'manual', operation_id: operationId,
      source: ORIGINAL_SOURCE,
      requested_targets: ['unit', 'integration'],
    }),
    planRes,
    { email: 'viewer@example.test' },
  );
  assert.equal(planRes.status, 200);
  assert.deepEqual(calls.slice(-2), [{ inventory: { maxAgeMs: 0 } }, {
    plan: {
      repoId: 'repo-visible', intent: 'manual', requestedTargets: ['unit', 'integration'],
      operationId,
      source: {
        schemaVersion: 1,
        kind: 'original',
        repositoryId: 'repo-visible',
        repositoryGeneration: 4,
        temporaryRoot: null,
      },
    },
  }]);
  const planBody = JSON.parse(planRes.body);
  assert.deepEqual(planBody.source_selector, ORIGINAL_SOURCE);
  assert.equal(planBody.source_label, 'Original repository');

  const runRes = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/runs', {
      repo_id: 'repo-visible', plan_id: 'plan-1', operation_id: operationId,
    }),
    runRes,
    { email: 'viewer@example.test' },
  );
  assert.equal(runRes.status, 202);
  assert.deepEqual(calls.at(-1), {
    submit: {
      repoId: 'repo-visible', planId: 'plan-1', operationId,
      actor: 'google:viewer@example.test',
    },
  });

  const rejected = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/plan', {
      repo_id: 'repo-visible', intent: 'manual', operation_id: operationId, source: 'live',
    }),
    rejected,
    { email: 'viewer@example.test' },
  );
  assert.equal(rejected.status, 400);
  assert.match(JSON.parse(rejected.body).error, /typed repository source selector/);
});

test('test planning denies a repository without an exact immutable grant', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = 'b38ba7f7-82de-414a-9455-dd4e43e0e0e7';
  const res = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/plan', {
      repo_id: 'repo-hidden', intent: 'manual', operation_id: operationId,
      source: {
        schema_version: 1, kind: 'original', repository_id: 'repo-hidden', repository_generation: 1,
      },
    }),
    res,
    { email: 'viewer@example.test' },
  );
  assert.equal(res.status, 403);
  assert.equal(calls.length, 0);
});

test('test planning rejects malformed or arbitrary browser source before coordinator access', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = '9bfca90a-feba-45a5-b491-796673131208';
  const planRes = responseRecorder();
  await api.handle(jsonRequest('/api/tests/plan', {
    repo_id: 'repo-visible', intent: 'manual', operation_id: operationId, source: 'live',
  }), planRes, { email: 'viewer@example.test' });
  assert.equal(planRes.status, 400);
  assert.match(JSON.parse(planRes.body).error, /typed repository source selector/);
  assert.equal(calls.length, 0);
});

test('test source catalog exposes opaque authorized identities without host paths', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const response = responseRecorder();
  await api.handle({
    method: 'GET', url: '/api/tests/repositories/repo-visible/sources', headers: {},
  }, response, { email: 'viewer@example.test' });
  assert.equal(response.status, 200);
  const body = JSON.parse(response.body);
  assert.deepEqual(body.default_source, ORIGINAL_SOURCE);
  assert.deepEqual(body.sources.map((source) => source.selector), [ORIGINAL_SOURCE, TEMPORARY_SOURCE]);
  assert.doesNotMatch(response.body, /\/private\//);
  assert.deepEqual(calls, [{ inventory: { maxAgeMs: 0 } }]);
});

test('test source catalog requires repository run authorization before inventory access', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:read:repo-visible']) });
  const response = responseRecorder();
  await api.handle({
    method: 'GET', url: '/api/tests/repositories/repo-visible/sources', headers: {},
  }, response, { email: 'viewer@example.test' });
  assert.equal(response.status, 403);
  assert.equal(calls.length, 0);
});

test('malformed source authority fails as stale server evidence, not a browser request error', async () => {
  const { api } = fixture({
    grants: new Set(['tests:run:repo-visible']),
    coordinatorOverrides: {
      async inventory() {
        return {
          repositories: [
            {
              repo_id: 'repo-visible', canonical_root: '/private/visible', generation: 4,
            },
          ],
          repository_trees: [{
            family_id: 'family-visible',
            root_repository: { repo_id: 'repo-visible', canonical_root: '/private/visible' },
            scopes: [
              { repo_id: 'repo-visible', kind: 'root', canonical_root: '/private/visible' },
              { repo_id: '../forged', kind: 'temporary', canonical_root: '/private/forged' },
            ],
          }],
        };
      },
    },
  });
  const response = responseRecorder();
  await api.handle({
    method: 'GET', url: '/api/tests/repositories/repo-visible/sources', headers: {},
  }, response, { email: 'viewer@example.test' });
  assert.equal(response.status, 409);
  assert.match(JSON.parse(response.body).error, /authority is malformed/);
});

test('temporary source planning is generation-bound and broker/profile authorized', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = '0a907e6e-03ca-4a74-9bb5-c634460ce94c';
  const response = responseRecorder();
  await api.handle(jsonRequest('/api/tests/plan', {
    repo_id: 'repo-visible', intent: 'manual', operation_id: operationId,
    source: TEMPORARY_SOURCE, requested_targets: ['integration'],
  }), response, { email: 'viewer@example.test' });
  assert.equal(response.status, 200);
  assert.deepEqual(calls.slice(-2), [{ inventory: { maxAgeMs: 0 } }, {
    plan: {
      repoId: 'repo-visible', intent: 'manual', requestedTargets: ['integration'],
      operationId,
      source: {
        schemaVersion: 1,
        kind: 'temporary',
        repositoryId: 'repo-visible-worktree',
        repositoryGeneration: 2,
        temporaryRoot: '/private/visible-worktree',
      },
    },
  }]);
  const body = JSON.parse(response.body);
  assert.deepEqual(body.source_selector, TEMPORARY_SOURCE);
  assert.equal(body.source_label, 'Visible review worktree');
});

test('stale or cross-family temporary source identity fails before test planning', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = 'ca0ded39-e154-4706-bdd7-e09ae36275cd';
  for (const source of [
    { ...ORIGINAL_SOURCE, repository_generation: 3 },
    { ...TEMPORARY_SOURCE, repository_generation: 1 },
    { ...TEMPORARY_SOURCE, repository_id: 'repo-hidden' },
  ]) {
    const response = responseRecorder();
    await api.handle(jsonRequest('/api/tests/plan', {
      repo_id: 'repo-visible', intent: 'manual', operation_id: operationId, source,
    }), response, { email: 'viewer@example.test' });
    assert.equal(response.status, 409);
    assert.match(JSON.parse(response.body).error, /stale or no longer authorized/);
  }
  assert.equal(calls.filter((call) => call.plan).length, 0);
});

test('test planning rejects target selection outside manual intent before coordinator access', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = 'b22de76b-5bc9-442f-8e17-d66c263713e8';
  const response = responseRecorder();
  await api.handle(jsonRequest('/api/tests/plan', {
    repo_id: 'repo-visible', intent: 'change', operation_id: operationId,
    source: ORIGINAL_SOURCE,
    requested_targets: ['unit'],
  }), response, { email: 'viewer@example.test' });
  assert.equal(response.status, 400);
  assert.match(JSON.parse(response.body).error, /only for manual intent/);
  assert.equal(calls.length, 0);
});

test('run history and detail remain scoped to the repository grant', async () => {
  const { api, calls } = fixture();
  const history = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible&limit=25', headers: {} },
    history,
    { email: 'viewer@example.test' },
  );
  assert.equal(history.status, 200);
  const historyBody = JSON.parse(history.body);
  assert.equal(historyBody.runs[0].run_id, 'run-1');
  assert.equal(historyBody.runs[0].can_retry, false,
    'read access must not expose an enabled mutation affordance');
  assert.equal(historyBody.next_cursor, 'run-1');
  assert.deepEqual(historyBody.runs[0].wait, MEMORY_WAIT);
  assert.deepEqual(historyBody.runs[0].usage, {
    available: false, peak_memory_mib: null, cpu_seconds: null,
  }, 'unavailable measurements must remain null rather than becoming zero');
  assert.doesNotMatch(history.body, /owner_uid|internal_ticket|must-not-leak/);
  assert.deepEqual(calls.at(-1), {
    runs: { repoId: 'repo-visible', after: null, limit: 25, state: null },
  });

  const detail = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories/repo-visible/runs/run-1', headers: {} },
    detail,
    { email: 'viewer@example.test' },
  );
  assert.equal(detail.status, 200);
  const result = JSON.parse(detail.body);
  assert.equal(result.repository_id, 'repo-visible');
  assert.equal(result.summary.conclusion, 'test_failed');
  assert.deepEqual(result.wait, MEMORY_WAIT);
  assert.deepEqual(result.usage, MEASURED_USAGE);
  assert.deepEqual(result.summary.usage, MEASURED_USAGE);
  assert.deepEqual(result.targets[0].wait, MEMORY_WAIT);
  assert.deepEqual(result.targets[0].usage, MEASURED_USAGE);
  assert.deepEqual(result.targets[0].attempts[0].usage, MEASURED_USAGE);
  assert.equal(result.targets[0].cpu_millis, undefined);
  assert.equal(result.targets[0].memory_mib, undefined);
  assert.equal(result.targets[0].pids, undefined);
  assert.equal(result.targets[0].attempts[0].runtime_id, undefined);
  assert.doesNotMatch(detail.body, /owner_uid|worktree_key|private\/worktree|must-not-leak|private-runtime-id/);
});

test('run history forwards and returns one bounded opaque cursor', async () => {
  const { api, calls } = fixture();
  const response = responseRecorder();
  await api.handle(
    {
      method: 'GET',
      url: '/api/tests/runs?repo_id=repo-visible&after=run-1&limit=50',
      headers: {},
    },
    response,
    { email: 'viewer@example.test' },
  );
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).next_cursor, null);
  assert.deepEqual(calls.at(-1), {
    runs: { repoId: 'repo-visible', after: 'run-1', limit: 50, state: null },
  });
});

test('run lookup authorizes the repository before querying a user-supplied run id', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:read:repo-visible']) });
  const response = responseRecorder();
  await api.handle(
    {
      method: 'GET',
      url: '/api/tests/repositories/repo-idle/runs/run-1',
      headers: {},
    },
    response,
    { email: 'viewer@example.test' },
  );
  assert.equal(response.status, 403);
  assert.equal(calls.some((item) => item.status), false,
    'an unauthorized repository must not become a run-existence oracle');
});

test('repository setup returns policy metadata without host paths or fixture secrets', async () => {
  const { api } = fixture();
  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories/repo-visible/setup', headers: {} },
    response,
    { email: 'viewer@example.test' },
  );
  assert.equal(response.status, 200);
  const body = JSON.parse(response.body);
  assert.deepEqual(body.fixtures, ['postgres']);
  assert.deepEqual(body.targets[0].fixtures, ['postgres']);
  assert.equal(body.targets[0].resources, undefined,
    'repository declarations are not scheduler quotas and must not be shown as enforced resources');
  assert.deepEqual(body.isolation, {
    network: 'loopback', private_scratch: true, kill_after_run: true,
  });
  assert.deepEqual(body.capability_policy, {
    ok: false,
    repository_grant: true,
    generation_match: true,
    requested: ['fixture.postgres', 'network.loopback'],
    missing: ['fixture.postgres'],
    repository_generation: 4,
  });
  assert.doesNotMatch(response.body, /\/private\/|must-not-leak|"secret"|cpu_millis|memory_mib|"pids"/);
});

test('run reads omit malformed capacity and measurement evidence', async () => {
  const { api } = fixture({
    coordinatorOverrides: {
      async testRuns({ repoId }) {
        return {
          repository_id: repoId,
          runs: [{
            run_id: 'run-malformed', repository_id: repoId, state: 'queued',
            wait: { code: 'cpu_quota', required_mib: 'a lot' },
            usage: { available: 'yes', peak_memory_mib: -1 },
          }],
          next_cursor: null,
        };
      },
    },
  });
  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible', headers: {} },
    response,
    { email: 'viewer@example.test' },
  );
  assert.equal(response.status, 200);
  const run = JSON.parse(response.body).runs[0];
  assert.equal(run.wait, undefined);
  assert.equal(run.usage, undefined);
});

test('run history exposes operations only to the requester or tests:operate users', async () => {
  const own = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const ownResponse = responseRecorder();
  await own.api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible', headers: {} },
    ownResponse,
    { email: 'viewer@example.test' },
  );
  assert.equal(JSON.parse(ownResponse.body).runs[0].can_retry, true);

  const foreign = fixture({
    grants: new Set(['tests:run:repo-visible']),
    runActor: 'google:someone-else@example.test',
  });
  const foreignResponse = responseRecorder();
  await foreign.api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible', headers: {} },
    foreignResponse,
    { email: 'viewer@example.test' },
  );
  assert.equal(JSON.parse(foreignResponse.body).runs[0].can_retry, false);

  const operator = fixture({
    grants: new Set(['tests:operate:repo-visible']),
    runActor: 'google:someone-else@example.test',
  });
  const operatorResponse = responseRecorder();
  await operator.api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible', headers: {} },
    operatorResponse,
    { email: 'viewer@example.test' },
  );
  assert.equal(JSON.parse(operatorResponse.body).runs[0].can_retry, true);
});

test('test mutation ownership uses only the canonical actor from the authenticated session', async () => {
  const legacyOwnedRun = {
    run_id: 'run-1', repository_id: 'repo-visible', state: 'failed',
    actor: 'GOOGLE:VIEWER@EXAMPLE.TEST',
    requested_by: 'google:viewer@example.test',
    requested_by_actor: 'google:viewer@example.test',
  };
  const { api, calls } = fixture({
    grants: new Set(['tests:run:repo-visible']),
    coordinatorOverrides: {
      async testRuns({ repoId }) {
        return { repository_id: repoId, runs: [legacyOwnedRun], next_cursor: null };
      },
      async testRunStatus() {
        return legacyOwnedRun;
      },
    },
  });

  const history = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/runs?repo_id=repo-visible', headers: {} },
    history,
    { email: 'viewer@example.test' },
  );
  assert.equal(history.status, 200);
  const visibleRun = JSON.parse(history.body).runs[0];
  assert.equal(visibleRun.can_retry, false);
  assert.equal(visibleRun.requested_by, undefined);
  assert.equal(visibleRun.requested_by_actor, undefined);

  const retry = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/repositories/repo-visible/runs/run-1/retry', {
      failed_only: true,
      operation_id: '31a5d3a7-adf8-489e-96ce-ff1aa7c31d71',
    }),
    retry,
    { email: 'viewer@example.test' },
  );
  assert.equal(retry.status, 403);
  assert.equal(calls.some((item) => item.retry), false);

  const spoofedSubmission = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/runs', {
      repo_id: 'repo-visible',
      plan_id: 'plan-1',
      operation_id: 'f83f37c2-74ee-4d09-8a0f-246fbc863108',
      actor: 'google:someone-else@example.test',
    }),
    spoofedSubmission,
    { email: 'viewer@example.test' },
  );
  assert.equal(spoofedSubmission.status, 400);
  assert.equal(calls.some((item) => item.submit), false);
});

test('case evidence uses a bounded numeric cursor', async () => {
  const { api, calls } = fixture();
  const response = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories/repo-visible/runs/run-1/cases?after=17&limit=25', headers: {} },
    response,
    { email: 'viewer@example.test' },
  );
  assert.equal(response.status, 200);
  assert.deepEqual(calls.at(-1), { cases: { runId: 'run-1', after: 17, limit: 25 } });

  const rejected = responseRecorder();
  await api.handle(
    { method: 'GET', url: '/api/tests/repositories/repo-visible/runs/run-1/cases?after=opaque', headers: {} },
    rejected,
    { email: 'viewer@example.test' },
  );
  assert.equal(rejected.status, 400);
});

test('a requester may cancel their own run with tests:run access', async () => {
  const { api, calls } = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const operationId = '9a62e192-6892-4faf-a17c-c1a304dc5ee5';
  const res = responseRecorder();
  await api.handle(
    jsonRequest('/api/tests/repositories/repo-visible/runs/run-1/cancel', {
      reason: 'No longer required', operation_id: operationId,
    }),
    res,
    { email: 'viewer@example.test' },
  );
  assert.equal(res.status, 200);
  assert.deepEqual(calls.at(-1), {
    cancel: {
      repoId: 'repo-visible', runId: 'run-1', reason: 'No longer required', operationId,
      actor: 'google:viewer@example.test',
    },
  });
});

test('operating another actor run requires tests:operate', async () => {
  const operationId = '8c086de1-3d9a-4f02-92e3-cb89b80377ce';
  const deniedFixture = fixture({
    grants: new Set(['tests:run:repo-visible']),
    runActor: 'google:owner@example.test',
  });
  const denied = responseRecorder();
  await deniedFixture.api.handle(
    jsonRequest('/api/tests/repositories/repo-visible/runs/run-1/retry', {
      failed_only: true, operation_id: operationId,
    }),
    denied,
    { email: 'viewer@example.test' },
  );
  assert.equal(denied.status, 403);
  assert.equal(deniedFixture.calls.some((item) => item.retry), false);

  const allowedFixture = fixture({
    grants: new Set(['tests:operate:repo-visible']),
    runActor: 'google:owner@example.test',
  });
  const allowed = responseRecorder();
  await allowedFixture.api.handle(
    jsonRequest('/api/tests/repositories/repo-visible/runs/run-1/retry', {
      failed_only: true, operation_id: operationId,
    }),
    allowed,
    { email: 'viewer@example.test' },
  );
  assert.equal(allowed.status, 202);
  assert.equal(allowedFixture.calls.some((item) => item.retry), true);
});

test('release planning is reserved for Console owners', async () => {
  const operationId = '291269e6-d81c-4ba5-982a-96f686166012';
  const userFixture = fixture({ grants: new Set(['tests:run:repo-visible']) });
  const denied = responseRecorder();
  await userFixture.api.handle(
    jsonRequest('/api/tests/plan', {
      repo_id: 'repo-visible', intent: 'release', operation_id: operationId,
      source: ORIGINAL_SOURCE,
    }),
    denied,
    { email: 'viewer@example.test' },
  );
  assert.equal(denied.status, 403);
  assert.equal(userFixture.calls.some((item) => item.plan), false);

  const ownerFixture = fixture({ admin: true, grants: new Set() });
  const allowed = responseRecorder();
  await ownerFixture.api.handle(
    jsonRequest('/api/tests/plan', {
      repo_id: 'repo-visible', intent: 'release', operation_id: operationId,
      source: ORIGINAL_SOURCE,
    }),
    allowed,
    { email: 'owner@example.test' },
  );
  assert.equal(allowed.status, 200);
  assert.equal(ownerFixture.calls.some((item) => item.plan), true);
});
