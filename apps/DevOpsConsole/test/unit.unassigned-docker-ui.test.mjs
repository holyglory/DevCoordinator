import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  const bodyStart = source.indexOf('{', start + header.length);
  assert.notEqual(bodyStart, -1, `app.js no longer has a body for "${header}"`);
  for (let i = bodyStart; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
}

test('container ownership presentation fails closed and preserves coordinator evidence', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const source = extractFunction(app, 'function containerOwnershipState(c)');
  // eslint-disable-next-line no-new-func
  const containerOwnershipState = new Function(`${source}; return containerOwnershipState;`)();

  assert.deepEqual(containerOwnershipState({
    project: '/worktrees/example',
    metadata_source: 'docker_labels',
    attribution: null,
  }), {
    verified: true, genericLifecycle: true, ephemeral: false, attribution: null,
  },
  'an exact Compose working-directory attribution must remain controllable');

  assert.deepEqual(containerOwnershipState({
    project: '/worktrees/example',
    metadata_source: 'coordinator_ephemeral',
    attribution: null,
  }), {
    verified: true, genericLifecycle: false, ephemeral: true, attribution: null,
  },
  'an exact ephemeral attribution is visible but cannot bypass its TTL-aware lifecycle');

  const unassigned = containerOwnershipState({
    project: null,
    metadata_source: 'none',
    attribution: {
      reason_code: 'name_only',
      explanation: 'Only the container name was observed.',
      recommended_next_step: 'Attach it to a verified repository or retire it.',
      can_attach: true,
      can_retire: true,
    },
  });
  assert.equal(unassigned.verified, false);
  assert.equal(unassigned.attribution.reason_code, 'name_only');
  assert.equal(unassigned.attribution.explanation, 'Only the container name was observed.');
  assert.equal(unassigned.attribution.recommended_next_step,
    'Attach it to a verified repository or retire it.');
  assert.equal(unassigned.attribution.can_attach, true);
  assert.equal(unassigned.attribution.can_retire, true);

  const incomplete = containerOwnershipState({ project: '/worktrees/example' });
  assert.equal(incomplete.verified, false,
    'a project-like string without an authoritative metadata source must not enable mutation');
  assert.equal(incomplete.attribution.reason_code, 'unverified_ownership');
  assert.match(incomplete.attribution.explanation, /could not prove/i);

  const fenced = containerOwnershipState({
    project: '/worktrees/example',
    metadata_source: 'coordinator_sidecar',
    attribution: {
      reason_code: 'start_fence_violated',
      explanation: 'The container crossed a completed start fence.',
      lifecycle_violation: true,
      can_attach: false,
      can_retire: false,
    },
  });
  assert.equal(fenced.verified, false,
    'lifecycle violations must fail closed even when older ownership fields look complete');
});

test('every active container surface gates mutation and retains read-only logs', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const rowFunctions = [
    extractFunction(app, 'function dockerServerItem(o, c, hiddenRow = false)'),
    extractFunction(app, 'function dockerItem(o, c, hiddenRow = false, webish = false)'),
    extractFunction(app, 'function treeContainerRow(o, c, isDb, hiddenRow, webish = false)'),
  ];

  for (const source of rowFunctions) {
    assert.match(source, /containerOwnershipState\(c\)/,
      'container controls must use the shared fail-closed ownership contract');
    assert.match(source, /unverifiedOwnershipNote\(ownership\)/,
      'unverified ownership must be visibly explained at the affected row');
    assert.match(source, /ownership\.genericLifecycle[\s\S]*archiveTarget/,
      'Archive must exclude broker-owned ephemeral containers');
    assert.doesNotMatch(source, /api\([^)]*(?:attach|retire)/i,
      'the browser must not invent attach/retire authority that its Console API does not expose');
  }

  const dockerRow = rowFunctions[1];
  assert.match(dockerRow, /ownership\.genericLifecycle[\s\S]*act\('restart'/,
    'Restart/Stop must exclude broker-owned ephemeral containers');
  assert.match(dockerRow, /blockedContainerAction/,
    'unverified runtime actions must remain visibly disabled');
  assert.match(dockerRow, /`dock-logs:\$\{name\}`/,
    'the Docker page must retain its read-only log disclosure');
});

test('Testcontainers dependencies do not become repository ownership incidents', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const source = extractFunction(app, 'function authoritativeInventoryProblemsOf(o)');
  // eslint-disable-next-line no-new-func
  const authoritativeInventoryProblemsOf = new Function(
    'repositoryTreeContractProblemsOf', 'isContainerActive', 'isTransientTestContainer',
    `${source}; return authoritativeInventoryProblemsOf;`,
  )(
    () => [],
    (container) => !/^(?:exited|created|dead|stopped)\b/i.test(String(container.status || '')),
    (container) => container?.transient_test === true,
  );
  const inventory = {
    repository_trees: [],
    resources: { databases: [] },
    unassigned_resources: [{
      resource_kind: 'container', resource_id: 'testcontainers-postgres',
      display_name: 'testcontainers-postgres', reason_code: 'name_only', transient_test: true,
    }],
    lifecycle_violations: [],
    servers: [],
    docker: {
      available: true,
      containers: [{
        host_resource_id: 'testcontainers-postgres', name: 'testcontainers-postgres',
        status: 'running', transient_test: true,
      }],
    },
  };
  assert.deepEqual(authoritativeInventoryProblemsOf({ inventory }), [],
    'a disposable test dependency must not trigger an ownership warning');

  inventory.unassigned_resources[0].transient_test = false;
  inventory.docker.containers[0].transient_test = false;
  assert.equal(authoritativeInventoryProblemsOf({ inventory }).length, 1,
    'a normal unassigned container must remain visible to the operator');
});
