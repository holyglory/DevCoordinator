// The browser must consume the coordinator's complete repository_trees model.
// Flat names, paths, and resource rows are lookup data only and must never
// synthesize repository membership when that authoritative model is absent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';

const APP_JS_URL = new URL('../src/ui/app.js', import.meta.url);

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
  return '';
}

async function loadProjectGroupsOf() {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const contractSource = extractFunction(appJs, 'function repositoryTreeContractProblemsOf(inv)');
  const source = extractFunction(appJs, 'function projectGroupsOf(o)');
  const problemsSource = extractFunction(appJs, 'function authoritativeInventoryProblemsOf(o)');
  // eslint-disable-next-line no-new-func
  const repositoryTreeContractProblemsOf = new Function(
    `${contractSource}; return repositoryTreeContractProblemsOf;`,
  )();
  // eslint-disable-next-line no-new-func
  const projectGroupsOf = new Function(
    'isServerRunning', 'isOperationalServer', 'isContainerActive', 'projectTail',
    'projectGroupOrder', 'repositoryTreeContractProblemsOf',
    `${source}; return projectGroupsOf;`,
  )(
    (server) => ['running', 'starting', 'unhealthy'].includes(server.status),
    (server) => ['running', 'starting', 'unhealthy', 'stopping', 'stopped'].includes(server.status),
    (container) => container.status !== 'stopped',
    (project) => String(project || '').split('/').filter(Boolean).at(-1) || '—',
    (a, b) => String(a.name).localeCompare(String(b.name)),
    repositoryTreeContractProblemsOf,
  );
  // eslint-disable-next-line no-new-func
  const authoritativeInventoryProblemsOf = new Function(
    'isServerRunning', 'isContainerActive', 'repositoryTreeContractProblemsOf',
    `${problemsSource}; return authoritativeInventoryProblemsOf;`,
  )(
    (server) => server.status !== 'stopped',
    (container) => !/^\s*(exited|created|dead|stopped)\b/i.test(String(container.status || '')),
    repositoryTreeContractProblemsOf,
  );
  return {
    appJs, projectGroupsOf, authoritativeInventoryProblemsOf, repositoryTreeContractProblemsOf,
  };
}

function minimalAuthoritativeInventory() {
  return {
    repositories: [{
      repo_id: 'repo', host_id: 'host', canonical_root: '/repo', display_name: 'Repo',
    }],
    memberships: [],
    resources: {
      servers: [{ server_definition_id: 'server', repo_id: 'repo' }],
      docker: [],
      databases: [],
    },
    observations: { docker: [], databases: [] },
    unassigned_resources: [],
    lifecycle_violations: [],
    servers: [{ id: 'server', name: 'web', status: 'running' }],
    docker: { available: true, containers: [], postgres: [] },
    repository_trees: [{
      family_id: 'family',
      root_repository: { repo_id: 'repo', canonical_root: '/repo', display_name: 'Repo' },
      usage: {},
      scopes: [{
        repo_id: 'repo', kind: 'root', canonical_root: '/repo', display_name: 'Repo',
        usage: {}, server_ids: ['server'], container_resource_ids: [], database_binding_ids: [],
      }],
    }],
  };
}

test('repository trees group one root repo with exact nested temporary scopes', async () => {
  const { projectGroupsOf } = await loadProjectGroupsOf();
  const rootServer = {
    id: 'server-root', key: '/repos/Nevod::api', name: 'api', project: '/repos/Nevod', status: 'running',
  };
  const temporaryServer = {
    id: 'server-temp', key: '/tmp/Nevod-run::web', name: 'web', project: '/tmp/Nevod-run', status: 'running',
  };
  const pathLookalike = {
    id: 'server-lookalike', key: '/repos/Nevod-copy::web', name: 'web-copy',
    project: '/repos/Nevod-copy', status: 'stopped',
  };
  const database = {
    name: 'nevod-db', host_resource_id: 'docker-db', status: 'running',
  };
  const temporaryContainer = {
    name: 'preview-cache', host_resource_id: 'docker-temp', status: 'running',
  };

  const groups = projectGroupsOf({ inventory: {
    repositories: [
      { repo_id: 'repo-root', host_id: 'host', canonical_root: '/repos/Nevod', display_name: 'Nevod' },
      { repo_id: 'repo-temp', host_id: 'host', canonical_root: '/tmp/Nevod-run', display_name: 'Nevod browser test' },
    ],
    memberships: [
      { resource_kind: 'container', host_resource_id: 'docker-db', repo_id: 'repo-root' },
      { resource_kind: 'container', host_resource_id: 'docker-temp', repo_id: 'repo-temp' },
    ],
    servers: [rootServer, temporaryServer, pathLookalike],
    docker: {
      available: true,
      containers: [database, temporaryContainer],
      postgres: [{ database_binding_id: 'binding-db', name: 'nevod-db' }],
    },
    resources: {
      servers: [
        { server_definition_id: 'server-root', repo_id: 'repo-root' },
        { server_definition_id: 'server-temp', repo_id: 'repo-temp' },
      ],
      docker: [
        { docker_resource_id: 'docker-db' },
        { docker_resource_id: 'docker-temp' },
      ],
      databases: [{
        database_binding_id: 'binding-db', docker_resource_id: 'docker-db',
        repo_id: 'repo-root', database_name: 'nevod',
      }],
    },
    observations: {
      docker: [
        { docker_resource_id: 'docker-db' },
        { docker_resource_id: 'docker-temp' },
      ],
      databases: [{ database_binding_id: 'binding-db' }],
    },
    unassigned_resources: [],
    lifecycle_violations: [],
    repository_trees: [{
      family_id: 'family-nevod',
      root_repository: {
        repo_id: 'repo-root', canonical_root: '/repos/Nevod', display_name: 'Nevod',
      },
      usage: { cpu_percent: 4.5, memory_bytes: 1000, process_count: 2 },
      scopes: [
        {
          repo_id: 'repo-root', kind: 'root', canonical_root: '/repos/Nevod', display_name: 'Nevod',
          run_id: null, expires_at: null, kill_after_run: false,
          usage: { cpu_percent: 2, memory_bytes: 600, process_count: 1 },
          server_ids: ['server-root'], container_resource_ids: ['docker-db'],
          database_binding_ids: ['binding-db'],
        },
        {
          repo_id: 'repo-temp', kind: 'temporary', canonical_root: '/tmp/Nevod-run',
          display_name: 'Nevod browser test', run_id: 'run-1', expires_at: '2026-07-26T10:00:00Z',
          kill_after_run: true, usage: { cpu_percent: 2.5, memory_bytes: 400, process_count: 1 },
          server_ids: ['server-temp'], container_resource_ids: ['docker-temp'], database_binding_ids: [],
        },
      ],
    }],
    // These deliberately contradictory flat rows must be ignored whenever
    // the authoritative field exists; they reproduce the old tripled repo.
    project_usage: [
      { usage_key: 'legacy-1', name: 'Nevod', project: '/repos/Nevod', server_ids: ['server-root'] },
      { usage_key: 'legacy-2', name: 'Nevod', project: '/repos/Nevod', server_ids: ['server-temp'] },
      { usage_key: 'legacy-3', name: 'Nevod', project: '/repos/Nevod-copy', server_ids: ['server-lookalike'] },
    ],
  } });

  const family = groups.find((group) => group.key === 'family-nevod');
  assert.ok(family, 'the producer-owned family ID must be the top-level identity');
  assert.equal(groups.filter((group) => group.name === 'Nevod').length, 1,
    'flat compatibility rows cannot duplicate an authoritative family');
  assert.deepEqual(family.rootScope.members.servers, [rootServer]);
  assert.deepEqual(family.rootScope.members.containers, [database],
    'an exact database binding may contribute its exact backing Docker resource');
  assert.deepEqual([...family.rootScope.dbNames], ['nevod-db']);
  assert.equal(family.temporaryScopes.length, 1);
  assert.equal(family.temporaryScopes[0].repoId, 'repo-temp');
  assert.equal(family.temporaryScopes[0].killAfterRun, true);
  assert.deepEqual(family.temporaryScopes[0].members.servers, [temporaryServer]);
  assert.deepEqual(family.temporaryScopes[0].members.containers, [temporaryContainer]);
  assert.deepEqual(family.members.servers, [rootServer, temporaryServer]);
  assert.deepEqual(family.members.containers, [database, temporaryContainer]);

  assert.equal(groups.some((group) => group.name === 'Unassigned Resources'), false,
    'authoritative leftovers must never be synthesized into another project');
  assert.equal(family.members.servers.includes(pathLookalike), false,
    'a similar path/name must never imply repository-family membership');
});

test('an authoritative empty repository tree does not fall back to flat project rows', async () => {
  const { projectGroupsOf } = await loadProjectGroupsOf();
  const groups = projectGroupsOf({ inventory: {
    repositories: [], memberships: [],
    resources: { servers: [], docker: [], databases: [] },
    observations: { docker: [], databases: [] },
    unassigned_resources: [], lifecycle_violations: [],
    servers: [],
    docker: { available: true, containers: [], postgres: [] },
    repository_trees: [],
    project_usage: [{ usage_key: 'legacy', name: 'Legacy', project: '/legacy' }],
  } });
  assert.deepEqual(groups, [], 'field presence, including an empty array, selects the authoritative contract');
});

test('unassigned active authoritative resources block lifecycle rendering', async () => {
  const {
    appJs, projectGroupsOf, authoritativeInventoryProblemsOf, repositoryTreeContractProblemsOf,
  } = await loadProjectGroupsOf();
  const inventory = {
    repositories: [{
      repo_id: 'repo', host_id: 'host', canonical_root: '/repo', display_name: 'Repo',
    }],
    memberships: [{
      resource_kind: 'container', host_resource_id: 'claimed-container', repo_id: 'repo',
    }],
    servers: [
      { id: 'claimed-server', name: 'claimed', status: 'running' },
      { id: 'unclaimed-server', name: 'orphan web', status: 'running' },
      { id: 'retained-server', name: 'retained', status: 'stopped' },
    ],
    docker: {
      available: true,
      containers: [
        { host_resource_id: 'claimed-container', name: 'claimed db', status: 'running' },
        { host_resource_id: 'unclaimed-container', name: 'orphan cache', status: 'running' },
        { host_resource_id: 'retained-container', name: 'retained image', status: 'stopped' },
      ],
      postgres: [],
    },
    resources: {
      servers: [
        { server_definition_id: 'claimed-server', repo_id: 'repo' },
        { server_definition_id: 'unclaimed-server', repo_id: null },
      ],
      docker: [
        { docker_resource_id: 'claimed-container' },
        { docker_resource_id: 'unclaimed-container' },
      ],
      databases: [{
        database_binding_id: 'claimed-db', docker_resource_id: 'claimed-container',
        repo_id: 'repo', database_name: 'claimed database', lifecycle: 'running',
      }, {
        database_binding_id: 'unclaimed-db', docker_resource_id: 'unclaimed-container',
        database_name: 'orphan database', lifecycle: 'running',
      }],
    },
    observations: {
      docker: [
        { docker_resource_id: 'claimed-container' },
        { docker_resource_id: 'unclaimed-container' },
      ],
      databases: [
        { database_binding_id: 'claimed-db' },
        { database_binding_id: 'unclaimed-db' },
      ],
    },
    unassigned_resources: [
      {
        resource_kind: 'server', resource_id: 'unclaimed-server', display_name: 'orphan web',
        reason_code: 'missing_repo', explanation: 'Its recorded repository no longer exists.',
        recommended_next_step: 'Register the server from its current root repository.',
      },
      {
        resource_kind: 'container', resource_id: 'unclaimed-container', display_name: 'orphan cache',
        reason_code: 'name_only', explanation: 'Only a container name was observed.',
        recommended_next_step: 'Attach or retire this exact container.',
      },
      {
        resource_kind: 'database', resource_id: 'unclaimed-db', display_name: 'orphan database',
        reason_code: 'missing_repo', explanation: 'Its database binding has no repository.',
        recommended_next_step: 'Bind the database stack to its root repository.',
      },
    ],
    lifecycle_violations: [],
    repository_trees: [{
      family_id: 'family',
      root_repository: { repo_id: 'repo', canonical_root: '/repo', display_name: 'Repo' },
      usage: {},
      scopes: [{
        repo_id: 'repo', kind: 'root', canonical_root: '/repo', display_name: 'Repo',
        usage: {}, server_ids: ['claimed-server'], container_resource_ids: ['claimed-container'],
        database_binding_ids: ['claimed-db'],
      }],
    }],
  };

  const groups = projectGroupsOf({ inventory });
  assert.deepEqual(repositoryTreeContractProblemsOf(inventory), [],
    'producer-reported unassigned resources are blocking diagnostics, not a malformed tree');
  assert.equal(groups.length, 1, 'the truthful assigned tree remains available read-only');
  assert.equal(groups.some((group) => group.name === 'Unassigned Resources'), false);
  assert.deepEqual(authoritativeInventoryProblemsOf({ inventory }), [
    {
      kind: 'server', name: 'orphan web', reason: 'Its recorded repository no longer exists.',
      nextStep: 'Register the server from its current root repository.',
    },
    {
      kind: 'container', name: 'orphan cache', reason: 'Only a container name was observed.',
      nextStep: 'Attach or retire this exact container.',
    },
    {
      kind: 'database', name: 'orphan database', reason: 'Its database binding has no repository.',
      nextStep: 'Bind the database stack to its root repository.',
    },
  ]);
  const errorPanel = extractFunction(appJs, 'function authoritativeInventoryErrorPanel(o)');
  assert.doesNotMatch(errorPanel, /h\('button'/,
    'the blocking inventory state must not expose lifecycle controls');
  for (const builder of ['buildProjects', 'buildServers', 'buildDocker', 'buildUsage']) {
    const source = extractFunction(appJs, `function ${builder}(o)`);
    assert.match(source, /authoritativeInventoryErrorPanel\(o\)/,
      `${builder} must stop before rendering lifecycle controls`);
  }
  for (const guard of [
    'function buildArchivedCollection(page)',
    'function openLifecycleDialog(action, target, trigger)',
    'async function submitLifecycleDialog()',
  ]) {
    const source = extractFunction(appJs, guard);
    assert.match(source, /authoritativeInventoryProblemsOf|authoritativeInventoryErrorPanel/,
      `${guard} must fail closed if a stale surface survives an inventory error`);
  }
  assert.match(appJs,
    /async function runAction\(busyKey, fn,[\s\S]{0,180}authoritativeInventoryProblemsOf\(state\.overview\)/,
    'the shared mutation runner must fail closed if stale controls survive an inventory error');
  assert.match(appJs, /Rerun Coordinator installation for the original root repository/,
    'ownership diagnostics without a producer next step must still tell the user how to resolve them');
});

test('malformed authoritative repository trees fail closed instead of rendering duplicate controls', async () => {
  const { projectGroupsOf, repositoryTreeContractProblemsOf } = await loadProjectGroupsOf();
  const cases = [
    ['missing repository tree', (inventory) => { delete inventory.repository_trees; }],
    ['null repository tree', (inventory) => { inventory.repository_trees = null; }],
    ['missing family ID', (inventory) => { inventory.repository_trees[0].family_id = ''; }],
    ['duplicate family ID', (inventory) => {
      inventory.repository_trees.push(structuredClone(inventory.repository_trees[0]));
    }],
    ['unknown scope kind', (inventory) => { inventory.repository_trees[0].scopes[0].kind = 'checkout'; }],
    ['inconsistent root', (inventory) => {
      inventory.repository_trees[0].root_repository.canonical_root = '/other';
    }],
    ['duplicate resource claim', (inventory) => {
      inventory.repositories.push({
        repo_id: 'repo-temp', host_id: 'host', canonical_root: '/tmp/repo', display_name: 'Repo run',
      });
      inventory.repository_trees[0].scopes.push({
        repo_id: 'repo-temp', kind: 'temporary', canonical_root: '/tmp/repo', display_name: 'Repo run',
        usage: {}, server_ids: ['server'], container_resource_ids: [], database_binding_ids: [],
      });
    }],
  ];
  for (const [label, mutate] of cases) {
    const inventory = minimalAuthoritativeInventory();
    mutate(inventory);
    assert.equal(repositoryTreeContractProblemsOf(inventory)[0]?.kind, 'inventory', label);
    assert.deepEqual(projectGroupsOf({ inventory }), [], `${label} must not render action targets`);
  }
});

test('authoritative root rows label root-only actions and show family totals separately', async () => {
  const { appJs } = await loadProjectGroupsOf();
  const source = extractFunction(appJs, 'function projectNode(o, group, hiddenProject, revealing, hiddenServers, hiddenDocker)');
  assert.match(source, /root services running/);
  assert.match(source, /Root repository/);
  assert.match(source, /Family total/);
  assert.match(source, /temporary repo/);
});

test('flat project usage and names never synthesize a repository hierarchy', async () => {
  const { projectGroupsOf, authoritativeInventoryProblemsOf } = await loadProjectGroupsOf();
  const inventory = minimalAuthoritativeInventory();
  delete inventory.repository_trees;
  inventory.project_usage = [{
    usage_key: 'path:/repo', name: 'Repo', project: '/repo',
    server_ids: ['server'], container_names: ['same-name-container'],
  }];
  inventory.docker.containers = [{
    name: 'same-name-container', host_resource_id: 'container', status: 'running',
  }];

  assert.deepEqual(projectGroupsOf({ inventory }), []);
  assert.equal(authoritativeInventoryProblemsOf({ inventory })[0]?.kind, 'inventory');
  assert.match(
    authoritativeInventoryProblemsOf({ inventory })[0]?.name || '',
    /authoritative repository tree is missing/i,
  );
});

test('project membership excludes control-only port lease definitions from operational collections', async () => {
  const { projectGroupsOf } = await loadProjectGroupsOf();
  const live = { id: 'live', name: 'web', status: 'running' };
  const stopped = { id: 'stopped', name: 'worker', status: 'stopped' };
  const leaseTarget = {
    id: 'lease-only', name: 'smoke-caddy-http', role: 'validation-port-lease',
    status: 'unobserved', pid: null, port: null,
  };
  const inventory = minimalAuthoritativeInventory();
  inventory.servers = [live, stopped, leaseTarget];
  inventory.resources.servers = [live, stopped, leaseTarget].map((server) => ({
    server_definition_id: server.id,
    repo_id: 'repo',
  }));
  inventory.repository_trees[0].scopes[0].server_ids = [
    'live', 'stopped', 'lease-only',
  ];
  const groups = projectGroupsOf({ inventory });

  const rendered = groups.flatMap((group) => group.members.servers);
  assert.deepEqual(rendered, [live, stopped]);
  assert.equal(groups.find((group) => group.name === 'Repo').runningCount, 1);
  assert.equal(groups.some((group) => group.members.servers.includes(leaseTarget)), false,
    'an ACL/port-policy target is not a server instance and must not fall into Unassigned Resources');
});
