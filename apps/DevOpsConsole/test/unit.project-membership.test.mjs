// The browser must consume the coordinator's immutable container membership
// when it is available. Retained Docker records can reuse a name across
// identities, so name matching is only a compatibility path for older rows
// that do not publish container_resource_ids at all.

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
  const source = extractFunction(appJs, 'function projectGroupsOf(o)');
  // eslint-disable-next-line no-new-func
  const projectGroupsOf = new Function(
    'isServerRunning', 'isContainerActive', 'projectTail', 'projectGroupOrder',
    `${source}; return projectGroupsOf;`,
  )(
    (server) => server.status !== 'stopped',
    (container) => container.status !== 'stopped',
    (project) => String(project || '').split('/').filter(Boolean).at(-1) || '—',
    (a, b) => String(a.name).localeCompare(String(b.name)),
  );
  return { appJs, projectGroupsOf };
}

test('project membership prefers immutable container IDs and names only legacy rows', async () => {
  const { projectGroupsOf } = await loadProjectGroupsOf();
  const retainedOld = { name: 'gf-api', host_resource_id: 'docker:old', status: 'stopped' };
  const current = { name: 'gf-api', host_resource_id: 'docker:current', status: 'running' };
  const legacy = { name: 'legacy-worker', host_resource_id: 'docker:legacy', status: 'running' };
  const nameMustNotOverrideIds = { name: 'id-aware-name', host_resource_id: 'docker:not-claimed', status: 'stopped' };

  const groups = projectGroupsOf({ inventory: {
    servers: [],
    docker: { available: true, containers: [retainedOld, current, legacy, nameMustNotOverrideIds], postgres: [] },
    project_usage: [
      {
        usage_key: 'path:/repos/GlobalFinance',
        name: 'GlobalFinance',
        project: '/repos/GlobalFinance',
        container_resource_ids: ['docker:current'],
        container_names: ['gf-api'],
      },
      {
        usage_key: 'path:/repos/Legacy',
        name: 'Legacy',
        project: '/repos/Legacy',
        container_names: ['legacy-worker'],
      },
      {
        usage_key: 'path:/repos/IdAwareEmpty',
        name: 'IdAwareEmpty',
        project: '/repos/IdAwareEmpty',
        container_resource_ids: [],
        container_names: ['id-aware-name'],
      },
    ],
  } });

  const byName = new Map(groups.map((group) => [group.name, group]));
  assert.deepEqual(byName.get('GlobalFinance').members.containers, [current],
    'a same-name retained identity must not be co-claimed by an ID-aware row');
  assert.deepEqual(byName.get('Legacy').members.containers, [legacy],
    'rows without the ID field retain the compatibility name match');
  assert.deepEqual(byName.get('IdAwareEmpty').members.containers, [],
    'an explicitly empty ID list must not fall back to names');

  const unassigned = byName.get('Unassigned Resources');
  assert.ok(unassigned, 'unclaimed evidence needs an honest visible fallback group');
  assert.equal(unassigned.key, 'other', 'the established fallback identity remains stable');
  assert.deepEqual(unassigned.members.containers, [retainedOld, nameMustNotOverrideIds]);

  const rendered = groups.flatMap((group) => group.members.containers);
  assert.equal(rendered.length, 4);
  assert.equal(new Set(rendered).size, 4, 'every physical container record renders exactly once');
});

test('project membership detector catches same-name co-claiming', async () => {
  const { projectGroupsOf } = await loadProjectGroupsOf();
  const old = { name: 'shared', host_resource_id: 'old', status: 'stopped' };
  const live = { name: 'shared', host_resource_id: 'live', status: 'running' };
  const groups = projectGroupsOf({ inventory: {
    servers: [],
    docker: { available: true, containers: [old, live], postgres: [] },
    project_usage: [{
      usage_key: 'path:/repo', name: 'Repo', project: '/repo',
      container_resource_ids: ['live'], container_names: ['shared'],
    }],
  } });
  assert.deepEqual(groups.find((group) => group.name === 'Repo').members.containers, [live]);
  assert.deepEqual(groups.find((group) => group.name === 'Unassigned Resources').members.containers, [old]);
});
