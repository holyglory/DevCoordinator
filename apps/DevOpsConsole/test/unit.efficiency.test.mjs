import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createEfficiencyStore } from '../src/efficiency.mjs';

const REPOSITORY_ID = '123e4567-e89b-42d3-a456-426614174000';
const TOKEN_KEYS = ['input', 'cached_input', 'output', 'reasoning_output', 'tool', 'other'];
const PHASES = ['planning', 'implementation', 'testing', 'deployment', 'reporting', 'unattributed'];
const TOOL_CATEGORIES = ['shell', 'patch', 'mcp', 'web', 'agent', 'local', 'other'];

const counter = (value = '0', tasks = 1) => ({
  known_sum: value,
  known_task_count: value === null ? 0 : tasks,
  task_count: tasks,
  coverage: value === null ? 'unknown' : 'complete',
});

function summary(input, { opportunities = [] } = {}) {
  return {
    project_id: `id_${'1'.repeat(32)}`,
    task_count: 1,
    complete_task_count: 1,
    outcomes: { complete: 1 },
    causes: { 'not-applicable': 1 },
    tokens: Object.fromEntries(TOKEN_KEYS.map((key) => [key, counter(key === 'input' ? input : '1')])),
    tokens_by_phase: Object.fromEntries(PHASES.map((phase) => [phase, {
      ...Object.fromEntries(TOKEN_KEYS.map((key) => [key, counter(phase === 'implementation' && key === 'input' ? input : '0')])),
      usage_event_count: phase === 'implementation' ? 1 : 0,
    }])),
    request_to_delivery_ns: counter('10'),
    execution_to_delivery_ns: counter('8'),
    automation_opportunities: opportunities,
  };
}

function opportunity() {
  return {
    kind: 'deterministic-workflow-candidate', task_type: 'implementation',
    scope_size: 'small', current_method: 'direct', occurrence_count: 3,
    input_tokens: counter('12', 3),
    tool_category_counts: Object.fromEntries(TOOL_CATEGORIES.map((key) => [key, 0])),
    basis: 'at least three comparable non-automated terminal declarations',
    recommendation: 'review the repeated sequence for a script, harness, verifier, or reusable tool boundary',
  };
}

async function tempRoot(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-efficiency-'));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  return root;
}

async function writeSnapshot(root, accountId, value) {
  const directory = path.join(root, accountId, 'repositories');
  await fsp.mkdir(directory, { recursive: true });
  await fsp.writeFile(path.join(directory, `${REPOSITORY_ID}.json`), JSON.stringify({
    schema_version: 1,
    account_id: accountId,
    repository_id: REPOSITORY_ID,
    recorded_at_utc: '2026-08-12T20:00:00Z',
    summary: value,
  }));
}

test('missing optional projection reports unavailable and no repositories', async (t) => {
  const root = await tempRoot(t);
  const value = await createEfficiencyStore({ root: path.join(root, 'absent') }).list();
  assert.deepEqual(value, { schema_version: 1, available: false, repositories: [] });
});

test('per-account snapshots merge exact counters without inventing totals', async (t) => {
  const root = await tempRoot(t);
  await writeSnapshot(root, 'uid-1000', summary('10', { opportunities: [opportunity()] }));
  const unknown = summary(null);
  await writeSnapshot(root, 'uid-1001', unknown);

  const value = await createEfficiencyStore({ root }).list();

  assert.equal(value.available, true);
  assert.equal(value.repositories.length, 1);
  const repository = value.repositories[0];
  assert.equal(repository.task_count, 2);
  assert.deepEqual(repository.tokens.input, {
    known_sum: '10', known_task_count: 1, task_count: 2, coverage: 'partial',
  });
  assert.equal(repository.accounts.length, 2);
  assert.deepEqual(repository.accounts.map((account) => account.account_id), ['uid-1000', 'uid-1001']);
  assert.equal(repository.automation_opportunities.length, 1);
});

test('malformed and privacy-expanding snapshots are isolated', async (t) => {
  const root = await tempRoot(t);
  const invalid = summary('10');
  invalid.repository_path = '/home/private/repository';
  await writeSnapshot(root, 'uid-1000', invalid);
  await fsp.mkdir(path.join(root, 'uid-1001', 'repositories'), { recursive: true });
  await fsp.writeFile(path.join(root, 'uid-1001', 'repositories', `${REPOSITORY_ID}.json`), '{ nope');

  const warnings = [];
  const value = await createEfficiencyStore({ root, log: { warn: (...args) => warnings.push(args) } }).list();

  assert.equal(value.available, true);
  assert.deepEqual(value.repositories, []);
  assert.equal(value.invalid_projection_count, 2);
  assert.equal(warnings.length, 2);
  assert.doesNotMatch(JSON.stringify(warnings), /private\/repository|uid-100[01]/);
});
