// Real-browser regression for the Servers project accordion. This deliberately
// loads the Console's shipped index.html, app.css, and app.js through the real
// HTTPS stack. API reads are deterministic browser-route fixtures so the test
// can exercise a host-sized project without depending on a developer machine's
// running coordinator inventory.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CANONICAL_METRICS,
  CANONICAL_OVERVIEW,
  CANONICAL_PREFS,
  CANONICAL_SESSION,
} from '../Tools/canonical-api-fixtures.mjs';
import { canonicalTempDir, login, makeJar, startStack } from './helpers/stack.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const LONG_DOCKER_NAME =
  'gf-v2-smoke-20260722084715-555830-10721-alert-log-receiver-1';

function loadLockedPlaywright() {
  const require = createRequire(import.meta.url);
  const locked = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
  const roots = [
    ...String(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean),
    path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules'),
  ];
  for (const root of roots) {
    try {
      const manifest = require(path.join(root, 'playwright', 'package.json'));
      if (manifest.version !== locked.dependencies.playwright) {
        throw new Error(`Playwright ${manifest.version} does not match locked ${locked.dependencies.playwright}`);
      }
      return require(path.join(root, 'playwright'));
    } catch (error) {
      if (String(error.message).includes('does not match locked')) throw error;
    }
  }
  throw new Error(
    'locked Playwright runtime not found; run npm ci --ignore-scripts --prefix ci/playwright and set NODE_PATH=ci/playwright/node_modules',
  );
}

async function launchChromium(chromium, args) {
  const configured = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  const platformPaths = process.platform === 'darwin'
    ? [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
      ]
    : process.platform === 'win32'
      ? [
          process.env.PROGRAMFILES && path.join(process.env.PROGRAMFILES, 'Google/Chrome/Application/chrome.exe'),
          process.env['PROGRAMFILES(X86)']
            && path.join(process.env['PROGRAMFILES(X86)'], 'Google/Chrome/Application/chrome.exe'),
        ]
      : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const attempts = [
    { name: 'Playwright-managed Chromium', options: {} },
    ...[configured, ...platformPaths]
      .filter((item, index, list) => item && list.indexOf(item) === index && fs.existsSync(item))
      .map((executablePath) => ({ name: executablePath, options: { executablePath } })),
  ];
  const failures = [];
  for (const attempt of attempts) {
    try {
      return await chromium.launch({ headless: true, args, ...attempt.options });
    } catch (error) {
      failures.push(`${attempt.name}: ${String(error.message).split('\n')[0]}`);
    }
  }
  throw new Error(`could not launch a real Chromium browser:\n${failures.join('\n')}`);
}

async function writeEmptyDockerFixture(directory) {
  // Browser geometry does not exercise Docker. Keep its normalized coordinator
  // observation independent of whatever containers another project starts or
  // stops on the host while this test runs, while still satisfying the real
  // full-ID/exhaustive-asset parser with a complete empty observation.
  const executable = path.join(directory, 'docker');
  await fs.promises.writeFile(executable, `#!/usr/bin/env python3
import sys

args = sys.argv[1:]
if args[:1] in (["ps"], ["stats"]):
    pass
elif args[:2] in (["network", "ls"], ["volume", "ls"]):
    pass
else:
    sys.exit(1)
`, { encoding: 'utf8', mode: 0o755 });
}

function server(project, index) {
  const ordinal = String(index).padStart(3, '0');
  const name = `${path.basename(project)}-${ordinal}`;
  return {
    id: `fixture-${path.basename(project)}-${ordinal}`,
    key: `${project}::${name}`,
    name,
    role: 'web',
    project,
    agent: 'browser-fixture',
    status: 'running',
    pid: 42_000 + index,
    port: 10_000 + index,
    url: `http://127.0.0.1:${10_000 + index}`,
    url_is_current: true,
    missing_command: false,
    log_path: `/var/log/devcoordinator/${name}.log`,
    health: { ok: true, classification: 'healthy', status: 200 },
    process_usage: { cpu_percent: 1.5, memory_bytes: 16_777_216 },
  };
}

function container(project, repoId, name, index) {
  return {
    ...structuredClone(CANONICAL_OVERVIEW.inventory.docker.containers[0]),
    id: `fixture-container-${index}`,
    host_resource_id: `fixture-container-${index}`,
    repo_id: repoId,
    name,
    project,
    compose_project: path.basename(project),
    metadata_source: 'docker_labels',
    // A visible container-only port keeps this fixture off the Servers page.
    ports: `${25_000 + index}/tcp`,
  };
}

function unassignedContainer(resourceId = 'fixture-container-202') {
  return {
    ...container('/fixtures/unassigned', null, 'gnt-artifact-pg', 202),
    id: resourceId,
    host_resource_id: resourceId,
    project: null,
    compose_project: null,
    metadata_source: 'none',
    ports: '127.0.0.1:55439->5432/tcp',
    attribution: {
      reason_code: 'name_only',
      explanation: 'The host resource has an exact controller, but only its name—not a repository path—was observed.',
      recommended_next_step: null,
      can_attach: true,
      can_retire: true,
    },
  };
}

function fixtureOverview(revision, {
  archivedServerIds = new Set(), removedServerIds = new Set(),
  restoredServerIds = new Set(), includeUnassigned = false,
  unassignedResourceId = 'fixture-container-202',
  includeDatabaseOwnershipProblem = false, databaseContainerVerified = false,
  activeRoutes = [], activeLeases = [],
} = {}) {
  const overview = structuredClone(CANONICAL_OVERVIEW);
  const alphaProject = '/fixtures/projects/alpha';
  const betaProject = '/fixtures/projects/beta';
  const idleProject = '/fixtures/projects/idle';
  const alpha = Array.from({ length: 82 }, (_, index) => server(alphaProject, index + 1))
    .filter((item) => !archivedServerIds.has(item.id) && !removedServerIds.has(item.id));
  const beta = [server(betaProject, 1)];
  beta[0].name = 'smoke-caddy-http';
  beta[0].log_path = null;
  beta[0].supervision = {
    desired_state: 'running',
    state: 'running',
    keep_alive: true,
    breaker: { state: 'armed', crash_count_in_window: 0, window_seconds: 300 },
  };
  for (const item of [...alpha, ...beta]) {
    if (!restoredServerIds.has(item.id)) continue;
    item.status = 'stopped';
    item.pid = null;
    item.url = null;
    item.health = { ok: false, classification: 'stopped', status: null };
    item.process_usage = null;
  }
  // A real sample changes both the per-process and project rollups. Changing
  // the server value guarantees the Servers section signature rebuilds, while
  // the project value gives the replacement node an observable revision.
  beta[0].process_usage.cpu_percent = revision === 0 ? 1.5 : 2.5;

  overview.routes = structuredClone(activeRoutes);
  overview.inventory.servers = [...alpha, ...beta];
  overview.inventory.port_assignments = [];
  overview.inventory.leases = structuredClone(activeLeases);
  const globalFinanceProject = '/fixtures/projects/global-finance';
  const xfoilProject = '/fixtures/projects/xfoil';
  const globalFinance = Array.from({ length: 85 }, (_, index) => container(
    globalFinanceProject,
    'repo-global-finance',
    index === 0 ? LONG_DOCKER_NAME : `global-finance-${String(index + 1).padStart(3, '0')}`,
    index + 1,
  ));
  const xfoil = [container(xfoilProject, 'repo-xfoil', 'xfoil-solver-1', 101)];
  const dockerContainer = {
    ...structuredClone(CANONICAL_OVERVIEW.inventory.docker.containers[0]),
    host_resource_id: 'fixture-container-sample-api-db',
    repo_id: 'repo-db',
    project: '/fixtures/projects/db',
    compose_project: 'sample-api',
    metadata_source: databaseContainerVerified ? 'docker_labels' : 'none',
  };
  const unassigned = includeUnassigned ? unassignedContainer(unassignedResourceId) : null;
  const databaseResources = includeDatabaseOwnershipProblem
    ? [
        {
          database_binding_id: 'fixture-database-binding',
          docker_resource_id: unassigned.host_resource_id,
          repo_id: null,
          database_name: 'sample_api',
          lifecycle: 'running',
        },
        {
          database_binding_id: 'fixture-database-binding-audit',
          docker_resource_id: unassigned.host_resource_id,
          repo_id: null,
          database_name: 'sample_audit',
          lifecycle: 'running',
        },
      ]
    : [{
        database_binding_id: 'fixture-database-binding',
        docker_resource_id: dockerContainer.host_resource_id,
        repo_id: 'repo-db',
        database_name: 'sample_api',
        lifecycle: 'running',
      }];
  const dockerResources = [
    ...globalFinance, ...xfoil, dockerContainer, ...(unassigned ? [unassigned] : []),
  ];
  overview.inventory.docker = {
    available: true,
    error: null,
    stats_error: null,
    observation_revision: revision,
    postgres: databaseResources.map((database) => ({
      database_binding_id: database.database_binding_id,
      name: includeDatabaseOwnershipProblem ? unassigned.name : dockerContainer.name,
    })),
    containers: dockerResources,
  };
  overview.inventory.repositories = [
    { repo_id: 'repo-alpha', host_id: 'fixture-host', canonical_root: alphaProject, display_name: 'Alpha' },
    { repo_id: 'repo-beta', host_id: 'fixture-host', canonical_root: betaProject, display_name: 'Beta' },
    {
      repo_id: 'repo-beta-run', host_id: 'fixture-host', canonical_root: '/fixtures/runs/beta-1',
      display_name: 'Beta browser run',
    },
    {
      repo_id: 'repo-db', host_id: 'fixture-host', canonical_root: '/fixtures/projects/db',
      display_name: 'Database',
    },
    {
      repo_id: 'repo-idle', host_id: 'fixture-host', canonical_root: idleProject,
      display_name: 'Idle prototype',
    },
    {
      repo_id: 'repo-global-finance', host_id: 'fixture-host',
      canonical_root: globalFinanceProject, display_name: 'GlobalFinance',
    },
    {
      repo_id: 'repo-xfoil', host_id: 'fixture-host',
      canonical_root: xfoilProject, display_name: 'XFoil',
    },
  ];
  overview.inventory.resources = {
    servers: [
      ...alpha.map((item) => ({ server_definition_id: item.id, repo_id: 'repo-alpha' })),
      ...beta.map((item) => ({ server_definition_id: item.id, repo_id: 'repo-beta-run' })),
    ],
    docker: dockerResources.map((item) => ({
      docker_resource_id: item.host_resource_id,
      repo_id: globalFinance.includes(item) ? 'repo-global-finance'
        : xfoil.includes(item) ? 'repo-xfoil'
          : item === dockerContainer ? 'repo-db' : null,
    })),
    databases: databaseResources,
  };
  overview.inventory.observations = {
    docker: dockerResources.map((item) => ({
      docker_resource_id: item.host_resource_id,
    })),
    databases: databaseResources.map((database) => ({
      database_binding_id: database.database_binding_id,
    })),
  };
  overview.inventory.unassigned_resources = [
    ...(unassigned ? [{
      resource_kind: 'container', resource_id: unassigned.host_resource_id,
      display_name: unassigned.name,
      reason_code: unassigned.attribution.reason_code,
      explanation: unassigned.attribution.explanation,
      recommended_next_step: 'Attach this exact container to its original root repository, or retire it.',
    }] : []),
    ...(includeDatabaseOwnershipProblem ? databaseResources.map((database) => ({
      resource_kind: 'database', resource_id: database.database_binding_id,
      display_name: database.database_name,
      reason_code: unassigned.attribution.reason_code,
      explanation: `The database belongs to unassigned container ${unassigned.name}. ${unassigned.attribution.explanation}`,
      parent_resource_kind: 'container',
      parent_resource_id: unassigned.host_resource_id,
      parent_display_name: unassigned.name,
      can_attach: false,
      can_retire: false,
      recommended_next_step: `Resolve repository ownership for container ${unassigned.name}; the Coordinator will bind this database on the next observation.`,
    })) : []),
  ];
  overview.inventory.lifecycle_violations = [];
  overview.inventory.project_usage = [
    {
      usage_key: `path:${alphaProject}`,
      project_key: 'alpha',
      name: 'Alpha',
      project: alphaProject,
      cpu_percent: 3.2,
      memory_bytes: 82 * 16_777_216,
      process_count: alpha.length,
      server_count: alpha.length,
      container_count: 0,
      server_ids: alpha.map((item) => item.id),
      container_resource_ids: [],
    },
    {
      usage_key: `path:${betaProject}`,
      project_key: 'beta',
      name: 'Beta',
      project: betaProject,
      cpu_percent: revision === 0 ? 4.4 : 12.5,
      memory_bytes: 16_777_216,
      process_count: beta.length,
      server_count: beta.length,
      container_count: 0,
      server_ids: beta.map((item) => item.id),
      container_resource_ids: [],
    },
    {
      usage_key: `path:${globalFinanceProject}`,
      project_key: 'global-finance',
      repo_id: 'repo-global-finance',
      name: 'GlobalFinance',
      project: globalFinanceProject,
      cpu_percent: 93.5,
      memory_bytes: globalFinance.length * 48_234_496,
      process_count: globalFinance.length,
      server_count: 0,
      container_count: globalFinance.length,
      server_ids: [],
      container_resource_ids: globalFinance.map((item) => item.host_resource_id),
    },
    {
      usage_key: `path:${xfoilProject}`,
      project_key: 'xfoil',
      repo_id: 'repo-xfoil',
      name: 'XFoil',
      project: xfoilProject,
      cpu_percent: 1.1,
      memory_bytes: 48_234_496,
      process_count: 1,
      server_count: 0,
      container_count: 1,
      server_ids: [],
      container_resource_ids: xfoil.map((item) => item.host_resource_id),
    },
    {
      usage_key: 'path:/fixtures/projects/db',
      project_key: 'db',
      repo_id: 'repo-db',
      name: 'Database',
      project: '/fixtures/projects/db',
      cpu_percent: dockerContainer.stats.cpu_percent,
      memory_bytes: dockerContainer.stats.memory_usage_bytes,
      process_count: 1,
      server_count: 0,
      container_count: 1,
      server_ids: [],
      container_resource_ids: [dockerContainer.host_resource_id],
    },
  ];
  overview.inventory.repository_trees = [
    {
      family_id: `path:${alphaProject}`,
      root_repository: { repo_id: 'repo-alpha', canonical_root: alphaProject, display_name: 'Alpha' },
      usage: {
        cpu_percent: 3.2, memory_bytes: 82 * 16_777_216, process_count: alpha.length,
      },
      scopes: [{
        repo_id: 'repo-alpha', kind: 'root', canonical_root: alphaProject, display_name: 'Alpha',
        run_id: null, expires_at: null, kill_after_run: false,
        usage: { cpu_percent: 3.2, memory_bytes: 82 * 16_777_216, process_count: alpha.length },
        server_ids: alpha.map((item) => item.id), container_resource_ids: [], database_binding_ids: [],
      }],
    },
    {
      family_id: `path:${betaProject}`,
      root_repository: { repo_id: 'repo-beta', canonical_root: betaProject, display_name: 'Beta' },
      usage: {
        cpu_percent: revision === 0 ? 4.4 : 12.5,
        memory_bytes: 16_777_216,
        process_count: beta.length,
      },
      scopes: [
        {
          repo_id: 'repo-beta', kind: 'root', canonical_root: betaProject, display_name: 'Beta',
          run_id: null, expires_at: null, kill_after_run: false,
          usage: { cpu_percent: 0, memory_bytes: 0, process_count: 0 },
          server_ids: [], container_resource_ids: [], database_binding_ids: [],
        },
        {
          repo_id: 'repo-beta-run', kind: 'temporary', canonical_root: '/fixtures/runs/beta-1',
          display_name: 'Beta browser run', run_id: 'fixture-run',
          expires_at: '2099-01-01T00:00:00Z', kill_after_run: true,
          usage: {
            cpu_percent: revision === 0 ? 4.4 : 12.5,
            memory_bytes: 16_777_216,
            process_count: beta.length,
          },
          server_ids: beta.map((item) => item.id), container_resource_ids: [], database_binding_ids: [],
        },
      ],
    },
    {
      family_id: `path:${idleProject}`,
      root_repository: {
        repo_id: 'repo-idle', canonical_root: idleProject, display_name: 'Idle prototype',
      },
      usage: { cpu_percent: 0, memory_bytes: 0, process_count: 0 },
      scopes: [{
        repo_id: 'repo-idle', kind: 'root', canonical_root: idleProject,
        display_name: 'Idle prototype', run_id: null, expires_at: null, kill_after_run: false,
        usage: { cpu_percent: 0, memory_bytes: 0, process_count: 0 },
        server_ids: [], container_resource_ids: [], database_binding_ids: [],
      }],
    },
    {
      family_id: `path:${globalFinanceProject}`,
      root_repository: {
        repo_id: 'repo-global-finance', canonical_root: globalFinanceProject,
        display_name: 'GlobalFinance',
      },
      usage: {
        cpu_percent: 93.5,
        memory_bytes: globalFinance.length * 48_234_496,
        process_count: globalFinance.length,
      },
      scopes: [{
        repo_id: 'repo-global-finance', kind: 'root',
        canonical_root: globalFinanceProject, display_name: 'GlobalFinance',
        run_id: null, expires_at: null, kill_after_run: false,
        usage: {
          cpu_percent: 93.5,
          memory_bytes: globalFinance.length * 48_234_496,
          process_count: globalFinance.length,
        },
        server_ids: [],
        container_resource_ids: globalFinance.map((item) => item.host_resource_id),
        database_binding_ids: [],
      }],
    },
    {
      family_id: `path:${xfoilProject}`,
      root_repository: {
        repo_id: 'repo-xfoil', canonical_root: xfoilProject, display_name: 'XFoil',
      },
      usage: { cpu_percent: 1.1, memory_bytes: 48_234_496, process_count: 1 },
      scopes: [{
        repo_id: 'repo-xfoil', kind: 'root', canonical_root: xfoilProject,
        display_name: 'XFoil', run_id: null, expires_at: null, kill_after_run: false,
        usage: { cpu_percent: 1.1, memory_bytes: 48_234_496, process_count: 1 },
        server_ids: [],
        container_resource_ids: xfoil.map((item) => item.host_resource_id),
        database_binding_ids: [],
      }],
    },
    {
      family_id: 'path:/fixtures/projects/db',
      root_repository: {
        repo_id: 'repo-db', canonical_root: '/fixtures/projects/db', display_name: 'Database',
      },
      usage: {
        cpu_percent: dockerContainer.stats.cpu_percent,
        memory_bytes: dockerContainer.stats.memory_usage_bytes,
        process_count: 1,
      },
      scopes: [{
        repo_id: 'repo-db', kind: 'root', canonical_root: '/fixtures/projects/db', display_name: 'Database',
        run_id: null, expires_at: null, kill_after_run: false,
        usage: {
          cpu_percent: dockerContainer.stats.cpu_percent,
          memory_bytes: dockerContainer.stats.memory_usage_bytes,
          process_count: 1,
        },
        server_ids: [], container_resource_ids: [dockerContainer.host_resource_id],
        database_binding_ids: includeDatabaseOwnershipProblem ? [] : ['fixture-database-binding'],
      }],
    },
  ];
  return overview;
}

function fixtureMetrics() {
  const points = [
    [1_721_650_000_000, 93.5, 4_032_000_000],
    [1_721_650_010_000, 103.3, 4_096_000_000],
  ];
  return {
    ...CANONICAL_METRICS,
    host: null,
    entities: [
      {
        key: 'proj:path:/fixtures/projects/global-finance',
        kind: 'project',
        name: 'GlobalFinance',
        project: '/fixtures/projects/global-finance',
        points,
      },
      {
        key: 'repo:repo-global-finance',
        kind: 'repository',
        id: 'repo-global-finance',
        name: 'GlobalFinance',
        project: '/fixtures/projects/global-finance',
        points,
      },
      {
        key: 'family:path:/fixtures/projects/global-finance',
        kind: 'project-family',
        id: 'path:/fixtures/projects/global-finance',
        name: 'GlobalFinance',
        project: '/fixtures/projects/global-finance',
        points,
      },
      {
        key: `dock:${LONG_DOCKER_NAME}`,
        kind: 'docker',
        name: LONG_DOCKER_NAME,
        project: '/fixtures/projects/global-finance',
        points,
      },
    ],
  };
}

async function assertAdjacentCellsDoNotOverlap(
  parent, leftSelector, rightSelector, message,
) {
  const boxes = await parent.evaluate((node, selectors) => {
    const left = node.querySelector(selectors.left);
    const right = node.querySelector(selectors.right);
    if (!left || !right) return null;
    const leftRect = left.getBoundingClientRect();
    const rightRect = right.getBoundingClientRect();
    return {
      left: {
        x: leftRect.x,
        width: leftRect.width,
        rendered: left.getClientRects().length > 0,
      },
      right: {
        x: rightRect.x,
        width: rightRect.width,
        rendered: right.getClientRects().length > 0,
      },
    };
  }, { left: leftSelector, right: rightSelector });
  assert.ok(
    boxes?.left.rendered && boxes?.right.rendered,
    `${message}: both cells must be rendered`,
  );
  assert.ok(boxes.left.x + boxes.left.width <= boxes.right.x, message);
}

async function assertElementsDoNotOverlap(first, second, message) {
  const [a, b] = await Promise.all([first.boundingBox(), second.boundingBox()]);
  assert.ok(a && b, `${message}: both elements must be rendered`);
  const overlapsX = a.x < b.x + b.width && b.x < a.x + a.width;
  const overlapsY = a.y < b.y + b.height && b.y < a.y + a.height;
  assert.equal(overlapsX && overlapsY, false, message);
}

async function projectKindEvidence(trigger) {
  return trigger.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    const hiddenLabel = node.querySelector('.visually-hidden');
    const hiddenRect = hiddenLabel?.getBoundingClientRect();
    return {
      tag: node.tagName,
      kind: node.dataset.resourceKind,
      accessibleName: node.getAttribute('aria-label'),
      describedBy: node.getAttribute('aria-describedby'),
      pressed: node.getAttribute('aria-pressed'),
      directText: [...node.childNodes]
        .filter((child) => child.nodeType === Node.TEXT_NODE)
        .map((child) => child.textContent.trim())
        .filter(Boolean),
      hiddenLabel: hiddenLabel?.textContent?.trim() || '',
      hiddenLabelWidth: hiddenRect?.width ?? null,
      hiddenLabelHeight: hiddenRect?.height ?? null,
      iconMarkup: node.querySelector('svg')?.outerHTML || '',
      width: rect.width,
      height: rect.height,
    };
  });
}

async function assertResourceKindTooltip(page, expectedLabel, expectedHint, message) {
  const tooltip = page.locator('#resource-kind-tooltip');
  await tooltip.waitFor({ state: 'visible' });
  const evidence = await tooltip.evaluate((node) => {
    const rect = node.getBoundingClientRect();
    return {
      role: node.getAttribute('role'),
      parent: node.parentElement?.tagName,
      label: node.querySelector('.resource-kind-tooltip-label')?.textContent?.trim() || '',
      hint: node.querySelector('.resource-kind-tooltip-copy')?.textContent?.trim() || '',
      left: rect.left,
      right: rect.right,
      top: rect.top,
      bottom: rect.bottom,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
    };
  });
  assert.equal(evidence.role, 'tooltip', `${message}: the shared hint must keep tooltip semantics`);
  assert.equal(evidence.parent, 'BODY', `${message}: the hint must overlay the page rather than resize a row`);
  assert.equal(evidence.label, expectedLabel, `${message}: the hint must identify the exact resource kind`);
  assert.equal(evidence.hint, expectedHint, `${message}: the hint must explain the exact resource kind`);
  assert.ok(evidence.left >= 7 && evidence.right <= evidence.viewportWidth - 7,
    `${message}: the hint must remain horizontally viewport-bounded: ${JSON.stringify(evidence)}`);
  assert.ok(evidence.top >= 7 && evidence.bottom <= evidence.viewportHeight - 7,
    `${message}: the hint must remain vertically viewport-bounded: ${JSON.stringify(evidence)}`);
  return evidence;
}

async function expandedCount(page) {
  return page.locator('#servers-body .server-project-toggle').evaluateAll(
    (buttons) => buttons.filter((button) => button.getAttribute('aria-expanded') === 'true').length,
  );
}

async function activeFocusKey(page) {
  return page.evaluate(() => document.activeElement?.getAttribute('data-fk') || null);
}

test('real Servers and Docker UI keep project disclosures exclusive, focused, and losslessly paged',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-dockerbin-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    let context;
    try {
      stack = await startStack({
        allowedEmails: ['operator@example.test'],
        claims: { email: 'operator@example.test', name: 'Fixture Operator' },
        coordinatorEnv: {
          PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH ?? ''}`,
        },
      });
      const jar = makeJar();
      const loginResult = await login(stack, jar);
      const sessionCookie = jar.get('dc_session');
      assert.equal(loginResult.status, 200, 'fixture operator must complete the real OIDC/session flow');
      assert.ok(sessionCookie, 'fixture login must issue the Console session cookie');

      browser = await launchChromium(
        chromium,
        [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
      );
      context = await browser.newContext({
        viewport: { width: 1135, height: 919 },
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'UTC',
        colorScheme: 'dark',
        reducedMotion: 'reduce',
      });
      await context.addCookies([{
        name: sessionCookie.name,
        value: sessionCookie.value,
        domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
        path: sessionCookie.path,
        secure: sessionCookie.secure,
        httpOnly: sessionCookie.httpOnly,
        sameSite: 'Lax',
      }]);

      const page = await context.newPage();
      const browserErrors = [];
      const unexpectedRequests = [];
      let overviewRevision = 0;
      let overviewRequests = 0;
      let includeUnassigned = false;
      let unassignedResourceId = 'fixture-container-202';
      let includeDatabaseOwnershipProblem = false;
      let databaseContainerVerified = false;
      let structuralInventoryContradiction = false;
      let maintenanceMode = false;
      let dockerLogAttempts = 0;
      let serverLogAttempts = 0;
      const archivedServerIds = new Set();
      const removedServerIds = new Set();
      const restoredServerIds = new Set();
      const activeLeases = Array.from({ length: 32 }, (_, index) => ({
        id: `fixture-lease-${index + 1}`,
        port: 3100 + index,
        purpose: `Fixture service ${index + 1}`,
        project: '/fixtures/projects/alpha',
        agent: 'browser-fixture',
        expires_at: null,
        expires_at_iso: null,
      }));
      const activeRoutes = Array.from({ length: 32 }, (_, index) => ({
        slug: `fixture-route-${String(index + 1).padStart(2, '0')}`,
        kind: 'port',
        port: 4100 + index,
        auth: index === 0 ? 'public' : 'google',
        title: `Fixture route ${index + 1}`,
        url: `https://fixture-route-${String(index + 1).padStart(2, '0')}.vr.ae`,
        resolved: { port: 4100 + index },
        createdAt: '2026-01-15T12:00:00.000Z',
        updatedAt: '2026-01-15T12:00:00.000Z',
      }));
      let archives = [];
      const plans = new Map();
      const telegramBots = [{
        id: 'fixture-telegram-bot',
        label: 'Operations',
        ownerEmail: CANONICAL_SESSION.email,
        username: 'fixture_operations_bot',
        enabled: true,
        projectIds: [],
        authorizations: [],
        hasToken: true,
      }];
      page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') browserErrors.push(`console: ${message.text()}`);
      });
      await page.route('**/api/**', async (route) => {
        const request = route.request();
        const pathname = new URL(request.url()).pathname;
        let body;
        if (
          maintenanceMode
          && request.method() === 'GET'
          && ['/api/access', '/api/access/requests', '/api/telegram'].includes(pathname)
        ) {
          await route.fulfill({
            status: 503,
            contentType: 'application/json',
            body: JSON.stringify({
              error: 'Live controls are temporarily paused for maintenance.',
              code: 'maintenance_in_progress',
              classification: 'maintenance',
              retryAfterSeconds: 30,
            }),
          });
          return;
        }
        if (request.method() === 'GET' && pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin: true, lifecycleAvailable: true };
        }
        else if (request.method() === 'GET' && pathname === '/api/access') {
          body = {
            version: 1,
            users: [{ email: CANONICAL_SESSION.email, owner: true, grants: [] }],
            resources: [],
            invitedCount: 0,
          };
        }
        else if (request.method() === 'GET' && pathname === '/api/access/requests') {
          body = { version: 1, pendingCount: 0, requests: [] };
        }
        else if (request.method() === 'GET' && pathname === '/api/telegram') {
          body = { version: 1, bots: telegramBots, projects: [] };
        }
        else if (request.method() === 'GET' && pathname === '/api/bugs') {
          body = { schema_version: 1, revision: 'fixture-empty-bugs', bugs: [] };
        }
        else if (request.method() === 'GET' && pathname === '/api/prefs') body = CANONICAL_PREFS;
        else if (request.method() === 'GET' && pathname === '/api/overview') {
          overviewRequests += 1;
          if (maintenanceMode) {
            body = fixtureOverview(overviewRevision, {
              archivedServerIds, removedServerIds, restoredServerIds, includeUnassigned,
              unassignedResourceId,
              includeDatabaseOwnershipProblem, databaseContainerVerified,
              activeRoutes, activeLeases,
            });
            body.coordinator = {
              ...body.coordinator,
              ok: false,
              failureKind: 'maintenance',
              errorStatus: 500,
              lastError: null,
              inventoryState: 'error',
              maintenance: { active: true, retryAfterSeconds: 30 },
            };
            body.inventory = null;
          } else {
            body = fixtureOverview(overviewRevision, {
              archivedServerIds, removedServerIds, restoredServerIds, includeUnassigned,
              unassignedResourceId,
              includeDatabaseOwnershipProblem, databaseContainerVerified,
              activeRoutes, activeLeases,
            });
            if (structuralInventoryContradiction) {
              const xfoilScope = body.inventory.repository_trees
                .find((tree) => tree.root_repository.repo_id === 'repo-xfoil').scopes[0];
              xfoilScope.container_resource_ids.push('fixture-container-sample-api-db');
            }
          }
        } else if (request.method() === 'GET' && pathname === '/api/metrics/history') {
          body = fixtureMetrics();
        } else if (request.method() === 'POST' && pathname === '/api/docker/logs') {
          assert.equal(typeof request.postDataJSON()?.resource_id, 'string');
          dockerLogAttempts += 1;
          if (dockerLogAttempts === 1) {
            await route.fulfill({
              status: 409,
              contentType: 'application/json',
              body: JSON.stringify({ error: 'The exact container log is temporarily unavailable.' }),
            });
            return;
          }
          body = { text: '2026-07-21T06:55:05Z validation failed safely' };
        } else if (request.method() === 'POST' && pathname === '/api/servers/logs') {
          assert.equal(typeof request.postDataJSON()?.id, 'string');
          serverLogAttempts += 1;
          if (serverLogAttempts === 1) {
            await route.fulfill({
              status: 409,
              contentType: 'application/json',
              body: JSON.stringify({ error: 'The exact server log is temporarily unavailable.' }),
            });
            return;
          }
          body = { text: '2026-07-21T06:56:05Z server recovered safely' };
        } else if (request.method() === 'POST' && pathname === '/api/routes') {
          const requestBody = request.postDataJSON();
          const created = {
            ...requestBody,
            title: requestBody.title || '',
            url: `https://${requestBody.slug}.vr.ae`,
            resolved: { port: requestBody.port || 10_001 },
            createdAt: '2026-01-15T12:10:00.000Z',
            updatedAt: '2026-01-15T12:10:00.000Z',
          };
          activeRoutes.push(created);
          body = created;
        } else if (request.method() === 'PATCH' && pathname.startsWith('/api/routes/')) {
          const slug = decodeURIComponent(pathname.slice('/api/routes/'.length));
          const existing = activeRoutes.find((candidate) => candidate.slug === slug);
          assert.ok(existing, `route fixture ${slug} must exist before it is managed`);
          Object.assign(existing, request.postDataJSON(), {
            updatedAt: '2026-01-15T12:11:00.000Z',
          });
          body = existing;
        } else if (request.method() === 'POST' && pathname === '/api/ports/lease') {
          const requestBody = request.postDataJSON();
          const lease = {
            id: 'fixture-lease-created',
            port: requestBody.preferred || 3456,
            purpose: requestBody.purpose || 'manual',
            project: requestBody.project || '/fixtures/projects/alpha',
            agent: 'browser-fixture',
            expires_at: 4_102_444_800,
            expires_at_iso: '2100-01-01T00:00:00Z',
          };
          activeLeases.push(lease);
          body = { lease };
        } else if (request.method() === 'GET' && pathname === '/api/lifecycle/list') {
          body = { archives };
        } else if (request.method() === 'POST' && pathname === '/api/lifecycle/plan') {
          const requestBody = request.postDataJSON();
          const planId = `plan-${requestBody.action}-${plans.size + 1}`;
          const phrase = requestBody.action === 'purge'
            ? 'PURGE SERVER alpha-001' : null;
          const plan = {
            plan_id: planId,
            plan_fingerprint: `fingerprint-${planId}`,
            target: {
              target_kind: requestBody.target_kind,
              target_id: requestBody.target_id,
              display_name: 'alpha-001',
            },
            effects: requestBody.action === 'archive'
              ? ['Stop alpha-001', 'Fence future starts'] : ['Delete the archived server record'],
            retained: requestBody.action === 'archive' ? ['Operation history', 'Log evidence'] : [],
            deleted: requestBody.action === 'purge' ? ['Archived server record'] : [],
            blockers: [],
            ...(phrase ? { confirmation_phrase: phrase } : {}),
          };
          plans.set(planId, { action: requestBody.action, targetId: requestBody.target_id, phrase });
          body = { plan };
        } else if (request.method() === 'POST' && pathname === '/api/lifecycle/apply') {
          const requestBody = request.postDataJSON();
          const plan = plans.get(requestBody.plan_id);
          if (!plan || requestBody.plan_fingerprint !== `fingerprint-${requestBody.plan_id}`) {
            await route.fulfill({
              status: 409,
              contentType: 'application/json',
              body: '{"error":"stale lifecycle plan"}',
            });
            return;
          }
          if (plan.action === 'purge' && requestBody.confirmation_phrase !== plan.phrase) {
            await route.fulfill({
              status: 409,
              contentType: 'application/json',
              body: '{"error":"confirmation phrase mismatch"}',
            });
            return;
          }
          if (plan.action === 'archive') {
            archivedServerIds.add(plan.targetId);
            restoredServerIds.delete(plan.targetId);
            archives = [{
              target_kind: 'server',
              target_id: plan.targetId,
              display_name: 'alpha-001',
              project_id: 'repo-alpha',
              project_display_name: 'Alpha',
              archived_at: '2026-01-15T12:05:00.000Z',
              reason: 'Browser lifecycle regression',
              actor: 'devops-console:operator@example.test',
              status: 'archived',
              restorable: true,
              removable: true,
              effects: ['Stopped and fenced'],
              retained: ['Operation history', 'Log evidence'],
              blockers: [],
            }];
          } else {
            archivedServerIds.delete(plan.targetId);
            removedServerIds.add(plan.targetId);
            archives = archives.filter((item) => item.target_id !== plan.targetId);
          }
          body = { result: { ok: true, status: 'completed', partial: false, needs_attention: false } };
        } else if (request.method() === 'POST' && pathname === '/api/lifecycle/restore') {
          const requestBody = request.postDataJSON();
          archivedServerIds.delete(requestBody.target_id);
          restoredServerIds.add(requestBody.target_id);
          archives = archives.filter((item) => item.target_id !== requestBody.target_id);
          body = { result: { ok: true, status: 'completed', partial: false, needs_attention: false } };
        } else {
          unexpectedRequests.push(`${request.method()} ${pathname}`);
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: '{"error":"unexpected browser fixture request"}',
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'cache-control': 'no-store' },
          body: JSON.stringify(body),
        });
      });

      const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
      await page.goto(`${origin}/#/projects`, { waitUntil: 'networkidle' });
      const projectHead = page.locator('#projects-body .tree-head').first();
      await projectHead.waitFor().catch(async (error) => {
        const body = String(await page.locator('body').innerText().catch(() => ''))
          .replace(/\s+/g, ' ').slice(0, 1000);
        throw new Error(
          `${error.message}\nbrowser errors: ${JSON.stringify(browserErrors)}`
          + `\nunexpected requests: ${JSON.stringify(unexpectedRequests)}`
          + `\nrendered body: ${body}`,
        );
      });
      await assertAdjacentCellsDoNotOverlap(
        projectHead, '.c-status', '.actions',
        'project running count must not be covered by lifecycle and runtime actions',
      );
      assert.equal(
        await page.locator('#projects-body .tree-head .proj-name', { hasText: 'Beta' }).count(),
        1,
        'one authoritative root repo must render as one top-level project',
      );
      assert.equal(await page.locator('#projects-body .tree-head .kind-tag.k-root').count(), 0,
        'Projects must not repeat an internal ROOT hierarchy label on every repository');
      assert.equal(
        (await page.locator('#projects-body .tree-head').allTextContents())
          .some((text) => /\bROOT\b/.test(text)),
        false,
        'the redundant ROOT label must not reappear under a different presentation class',
      );
      const activeProjectBlock = page.locator('.tree-node').filter({
        has: page.locator('[data-fk="tree-x:path:/fixtures/projects/alpha"]'),
      });
      const idleProjectBlock = page.locator('.tree-node').filter({
        has: page.locator('[data-fk="tree-x:path:/fixtures/projects/idle"]'),
      });
      assert.equal(await activeProjectBlock.locator('[data-fk^="hide:projects:"]').count(), 0,
        'a running project must not expose the idle-only visibility action');
      assert.equal(await idleProjectBlock.locator('[data-fk^="hide:projects:"]').count(), 1,
        'an idle project retains the actionable visibility control');
      const activeVisibilityPlaceholder = activeProjectBlock.locator('.project-actions > .ghost');
      assert.equal(await activeVisibilityPlaceholder.count(), 1,
        'a running project retains one inert visibility-layout placeholder');
      assert.deepEqual(await activeVisibilityPlaceholder.evaluate((node) => ({
        tag: node.tagName, hiddenFromAccessibility: node.getAttribute('aria-hidden'),
        tabIndex: node.getAttribute('tabindex'),
      })), { tag: 'SPAN', hiddenFromAccessibility: 'true', tabIndex: null },
      'the layout placeholder must never become a focusable or announced fake control');
      for (const width of [1135, 763, 390, 320]) {
        await page.setViewportSize({ width, height: 919 });
        await page.waitForFunction((expected) => window.innerWidth === expected, width);
        const actionGeometry = await page.evaluate(() => {
          const rowFor = (key) => document.querySelector(`[data-fk="tree-x:${key}"]`)
            ?.closest('.tree-head');
          const positions = (row) => [
            '[data-fk^="proj-start:"]',
            '[data-fk^="proj-restart:"]',
            '[data-fk^="proj-stop:"]',
            '[data-fk^="archive:project:"]',
          ].map((selector) => {
            const rect = row.querySelector(selector).getBoundingClientRect();
            return { left: rect.left, width: rect.width };
          });
          const active = rowFor('path:/fixtures/projects/alpha');
          const idle = rowFor('path:/fixtures/projects/idle');
          const activeActions = active.querySelector('.project-actions');
          const activeActionStyle = getComputedStyle(activeActions);
          return {
            viewport: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            actions: {
              width: activeActions.getBoundingClientRect().width,
              scrollWidth: activeActions.scrollWidth,
              display: activeActionStyle.display,
              columns: activeActionStyle.gridTemplateColumns,
              gap: activeActionStyle.columnGap,
            },
            active: positions(active),
            idle: positions(idle),
          };
        });
        assert.ok(actionGeometry.documentWidth <= actionGeometry.viewport,
          `${width}px project controls must not create document overflow: ${JSON.stringify(actionGeometry)}`);
        for (let index = 0; index < actionGeometry.active.length; index += 1) {
          assert.ok(Math.abs(actionGeometry.active[index].left - actionGeometry.idle[index].left) <= 1,
            `${width}px lifecycle action ${index + 1} must align with and without the visibility control: ${JSON.stringify(actionGeometry)}`);
          assert.ok(Math.abs(actionGeometry.active[index].width - actionGeometry.idle[index].width) <= 1,
            `${width}px lifecycle action ${index + 1} must retain equal width: ${JSON.stringify(actionGeometry)}`);
        }
      }
      await page.setViewportSize({ width: 1135, height: 919 });
      const kindIconMarkup = new Map();
      const kindExpectations = {
        server: ['Server', 'A host process registered to this repository.'],
        worker: ['Worker', 'A supervised host process that the Coordinator can keep alive.'],
        container: ['Container', 'A Docker container attributed to this repository.'],
        database: ['Database', 'A database service running in an attributed Docker container.'],
        temporary: ['Temporary repository', 'An isolated repository scope with its own expiry and cleanup policy.'],
      };
      const recordKind = async (trigger, kind) => {
        const evidence = await projectKindEvidence(trigger);
        const [label, hint] = kindExpectations[kind];
        assert.deepEqual({
          tag: evidence.tag,
          kind: evidence.kind,
          accessibleName: evidence.accessibleName,
          describedBy: evidence.describedBy,
          pressed: evidence.pressed,
          directText: evidence.directText,
          hiddenLabel: evidence.hiddenLabel,
        }, {
          tag: 'BUTTON',
          kind,
          accessibleName: `${label}: ${hint}`,
          describedBy: 'resource-kind-tooltip',
          pressed: 'false',
          directText: [],
          hiddenLabel: label,
        }, `${kind} must be an icon-only button with an exact accessible explanation`);
        assert.ok(evidence.iconMarkup.startsWith('<svg'), `${kind} must render a real icon`);
        assert.ok(evidence.hiddenLabelWidth <= 1.1 && evidence.hiddenLabelHeight <= 1.1,
          `${kind} text must remain available to assistive technology without becoming a visible pill`);
        assert.ok(evidence.width <= 44.5 && evidence.height <= 44.5,
          `${kind} must retain a compact bounded identity track`);
        kindIconMarkup.set(kind, evidence.iconMarkup);
        return evidence;
      };

      const activeProjectToggle = activeProjectBlock.locator(
        '[data-fk="tree-x:path:/fixtures/projects/alpha"]',
      );
      await activeProjectToggle.click();
      const serverKindTrigger = activeProjectBlock.locator(
        '.tree-children > .tree-item .resource-kind-trigger[data-resource-kind="server"]',
      ).first();
      await serverKindTrigger.waitFor();
      await recordKind(serverKindTrigger, 'server');
      assert.equal(await activeProjectBlock.locator('.tree-children .kind-tag').count(), 0,
        'Projects server rows must not retain visible uppercase kind pills');

      await serverKindTrigger.hover();
      await assertResourceKindTooltip(page, ...kindExpectations.server,
        'hovering a server kind icon');
      await page.mouse.move(1125, 10);
      await page.waitForFunction(() => document.querySelector('#resource-kind-tooltip')?.hidden === true);

      await serverKindTrigger.focus();
      await assertResourceKindTooltip(page, ...kindExpectations.server,
        'focusing a server kind icon');
      await page.keyboard.press('Escape');
      await page.waitForFunction(() => document.querySelector('#resource-kind-tooltip')?.hidden === true);
      assert.equal(await serverKindTrigger.evaluate((node) => document.activeElement === node), true,
        'Escape must dismiss the hint without stealing focus from its kind icon');

      await serverKindTrigger.click();
      assert.equal(await serverKindTrigger.getAttribute('aria-pressed'), 'true',
        'clicking a kind icon must expose a pinned hint for mouse and touch users');
      await page.evaluate(() => {
        const heading = document.querySelector('#projects-h');
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
      });
      await assertResourceKindTooltip(page, ...kindExpectations.server,
        'a pinned server kind hint after its trigger loses focus');
      await page.keyboard.press('Escape');
      await page.waitForFunction(() => document.querySelector('#resource-kind-tooltip')?.hidden === true);
      assert.equal(await serverKindTrigger.getAttribute('aria-pressed'), 'false',
        'Escape must also clear the pinned state');
      await serverKindTrigger.click();
      await page.locator('#projects-h').click();
      await page.waitForFunction(() => document.querySelector('#resource-kind-tooltip')?.hidden === true);
      assert.equal(await serverKindTrigger.getAttribute('aria-pressed'), 'false',
        'outside activation must dismiss a pinned hint');

      const globalFinanceProjectToggle = page.locator(
        '[data-fk="tree-x:path:/fixtures/projects/global-finance"]',
      );
      const globalFinanceProjectBlock = page.locator('.tree-node').filter({ has: globalFinanceProjectToggle });
      await globalFinanceProjectToggle.click();
      const containerKindTrigger = globalFinanceProjectBlock.locator(
        '.tree-children > .tree-item .resource-kind-trigger[data-resource-kind="container"]',
      ).first();
      await containerKindTrigger.waitFor();
      await recordKind(containerKindTrigger, 'container');
      assert.equal(await globalFinanceProjectBlock.locator('.tree-children .kind-tag').count(), 0,
        'Projects container rows must not retain visible uppercase kind pills');

      for (const width of [1135, 763, 390, 320]) {
        await page.setViewportSize({ width, height: 919 });
        await page.waitForFunction((expected) => window.innerWidth === expected, width);
        const geometry = await page.evaluate((focusKey) => {
          const toggle = document.querySelector(`[data-fk="${CSS.escape(focusKey)}"]`);
          const block = toggle?.closest('.tree-node');
          const body = document.querySelector('#projects-body');
          const section = document.querySelector('#sec-projects');
          const rows = [...(block?.querySelectorAll('.tree-children > .tree-item') || [])].slice(0, 6);
          const bodyRect = body.getBoundingClientRect();
          return {
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            bodyClientWidth: body.clientWidth,
            bodyScrollWidth: body.scrollWidth,
            sectionClientWidth: section.clientWidth,
            sectionScrollWidth: section.scrollWidth,
            rows: rows.map((row) => {
              const rowRect = row.getBoundingClientRect();
              const actions = row.querySelector(':scope > .actions');
              const actionsRect = actions.getBoundingClientRect();
              const actionStyle = getComputedStyle(actions);
              return {
                clientWidth: row.clientWidth,
                scrollWidth: row.scrollWidth,
                left: rowRect.left,
                right: rowRect.right,
                bodyLeft: bodyRect.left,
                bodyRight: bodyRect.right,
                actionDisplay: actionStyle.display,
                actionColumns: actionStyle.gridTemplateColumns,
                actionWidth: actionsRect.width,
                actionScrollWidth: actions.scrollWidth,
                slots: [...actions.children].map((child) => {
                  const rect = child.getBoundingClientRect();
                  const style = getComputedStyle(child);
                  return {
                    left: Math.round((rect.left - actionsRect.left) * 10) / 10,
                    top: Math.round((rect.top - actionsRect.top) * 10) / 10,
                    width: Math.round(rect.width * 10) / 10,
                    display: style.display,
                    visibility: style.visibility,
                  };
                }),
              };
            }),
          };
        }, 'tree-x:path:/fixtures/projects/global-finance');
        assert.equal(geometry.rows.length, 6,
          `${width}px regression must compare several real child rows`);
        assert.ok(geometry.documentWidth <= geometry.viewportWidth + 1,
          `${width}px Projects children must not create document overflow: ${JSON.stringify(geometry)}`);
        assert.ok(geometry.bodyScrollWidth <= geometry.bodyClientWidth + 1,
          `${width}px Projects body must not overflow its collection`);
        assert.ok(geometry.sectionScrollWidth <= geometry.sectionClientWidth + 1,
          `${width}px Projects section must not overflow its card`);
        const reference = geometry.rows[0];
        assert.equal(reference.slots.length, 5,
          `${width}px every resource row must reserve three lifecycle and two utility slots`);
        for (const [rowIndex, row] of geometry.rows.entries()) {
          assert.ok(row.scrollWidth <= row.clientWidth + 1,
            `${width}px child row ${rowIndex + 1} must not hide content horizontally`);
          assert.ok(row.left >= row.bodyLeft - 1 && row.right <= row.bodyRight + 1,
            `${width}px child row ${rowIndex + 1} must stay inside Projects`);
          assert.equal(row.actionDisplay, 'grid');
          assert.equal(row.actionColumns, reference.actionColumns,
            `${width}px child row ${rowIndex + 1} must use the shared action grid`);
          assert.ok(row.actionScrollWidth <= row.actionWidth + 1,
            `${width}px child row ${rowIndex + 1} action rail must remain bounded`);
          assert.equal(row.slots.length, 5,
            `${width}px child row ${rowIndex + 1} must preserve every fixed slot`);
          for (let slotIndex = 0; slotIndex < reference.slots.length; slotIndex += 1) {
            assert.ok(Math.abs(row.slots[slotIndex].left - reference.slots[slotIndex].left) <= 1,
              `${width}px child action ${slotIndex + 1} must snap to one shared track: ${JSON.stringify(geometry)}`);
            assert.ok(Math.abs(row.slots[slotIndex].width - reference.slots[slotIndex].width) <= 1,
              `${width}px child action ${slotIndex + 1} must retain one shared width: ${JSON.stringify(geometry)}`);
          }
        }
        if (width === 320) {
          const narrowContainerKind = globalFinanceProjectBlock.locator(
            '.tree-children > .tree-item .resource-kind-trigger[data-resource-kind="container"]',
          ).first();
          await narrowContainerKind.focus();
          await assertResourceKindTooltip(page, ...kindExpectations.container,
            'focusing a container kind icon at 320px');
          await page.keyboard.press('Escape');
        }
      }
      await page.setViewportSize({ width: 1135, height: 919 });
      const globalFinanceUsage = globalFinanceProjectBlock.locator('.tree-head .usage-btn');
      await globalFinanceUsage.click();
      const usageHistory = page.locator('#popover');
      await usageHistory.waitFor();
      assert.equal(await usageHistory.getAttribute('hidden'), null,
        'a root repository with sampled metrics must open its usage history');
      assert.equal(await usageHistory.locator('.chart-block').count(), 2,
        'root repository usage must resolve both CPU and memory chart series');
      assert.doesNotMatch(String(await usageHistory.textContent()), /No history yet/,
        'the usage popover must not lose authoritative root metrics to a key mismatch');
      await globalFinanceUsage.click();
      assert.equal(await usageHistory.getAttribute('hidden'), '',
        'the history control remains a conventional toggle after rendering the chart');
      const betaProjectToggle = page.locator('[data-fk="tree-x:path:/fixtures/projects/beta"]');
      const betaProjectBlock = page.locator('.tree-node').filter({ has: betaProjectToggle });
      assert.match(await betaProjectBlock.locator('.tree-head .tree-count').textContent(),
        /0 of 0 root services running/,
        'the root action row must not present temporary services as root action targets');
      assert.match(await betaProjectBlock.locator('.repository-family-summary').textContent(),
        /Family total.*root \+ 1 temporary repo.*1 of 1 services running/,
        'family-wide totals must be visibly separate from the root-only action row');
      assert.match(await betaProjectBlock.locator('[data-fk^="proj-stop:"]').getAttribute('title'),
        /root repository runtime only.*temporary repository runs stay separate/i,
        'project controls must state their exact root-only action scope');
      await betaProjectBlock.locator('.tree-head .proj-name').click();
      assert.equal(await betaProjectToggle.getAttribute('aria-expanded'), 'true',
        'the project name area must be part of the disclosure hit target');
      assert.equal(
        await betaProjectBlock.getByText('No services registered directly under this root repo.').count(),
        1,
        'temporary services must not be flattened into the root repo member list',
      );
      const temporaryToggle = page.locator(
        '[data-fk="temporary-scope:path:/fixtures/projects/beta:repo-beta-run"]',
      );
      await temporaryToggle.waitFor();
      const temporaryKindTrigger = betaProjectBlock.locator(
        '.temporary-scope-head > .resource-kind-trigger[data-resource-kind="temporary"]',
      );
      await recordKind(temporaryKindTrigger, 'temporary');
      assert.equal(await temporaryToggle.getAttribute('aria-expanded'), 'false');
      assert.match(await temporaryToggle.textContent(), /Beta browser run/);
      assert.match(await temporaryToggle.textContent(), /cleanup after run/);
      await temporaryToggle.click();
      assert.equal(await temporaryToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(
        await betaProjectBlock.locator('.temporary-scope-items .tree-item strong', { hasText: 'smoke-caddy-http' }).count(),
        1,
        'the temporary repo disclosure must reveal only its exact-ID service membership',
      );
      const workerRow = betaProjectBlock.locator('.temporary-scope-items .tree-item').filter({
        has: page.locator('strong', { hasText: 'smoke-caddy-http' }),
      });
      await recordKind(workerRow.locator(
        '.resource-kind-trigger[data-resource-kind="worker"]',
      ), 'worker');
      assert.equal(await betaProjectBlock.locator('.kind-tag').count(), 0,
        'temporary repository and worker kinds must remain icon-only');
      assert.equal(await workerRow.locator('.tree-act').count(), 3,
        'a supervised worker must retain fixed Start, Restart and Stop slots');
      assert.equal(await workerRow.locator('[data-fk^="tree-worker-start:"]').isDisabled(), true);
      assert.equal(await workerRow.locator('[data-fk^="tree-worker-restart:"]').isEnabled(), true);
      assert.equal(await workerRow.locator('[data-fk^="tree-worker-stop:"]').isEnabled(), true);

      // The Projects destination must remain decision-readable at the exact
      // 320px supported minimum, and an ownership explanation must not be
      // squeezed into a one-word-wide identity cell at ordinary phone width.
      const databaseProjectToggle = page.locator('[data-fk="tree-x:path:/fixtures/projects/db"]');
      const databaseProjectBlock = page.locator('.tree-node').filter({ has: databaseProjectToggle });
      await databaseProjectToggle.click();
      const unverifiedProjectRow = databaseProjectBlock.locator('.tree-item.ownership-unverified');
      await unverifiedProjectRow.waitFor();
      await recordKind(unverifiedProjectRow.locator(
        '.resource-kind-trigger[data-resource-kind="database"]',
      ), 'database');
      assert.equal(await databaseProjectBlock.locator('.kind-tag').count(), 0,
        'database rows must not retain visible uppercase kind pills');
      assert.equal(kindIconMarkup.size, 5,
        'the real Projects fixture must exercise every disclosed resource kind');
      assert.equal(new Set(kindIconMarkup.values()).size, 5,
        'server, worker, container, database and temporary repository must use distinct icon shapes');
      for (const width of [390, 320]) {
        await page.setViewportSize({ width, height: 844 });
        await page.waitForFunction((expected) => window.innerWidth === expected, width);
        const geometry = await page.evaluate(() => {
          const projectBody = document.querySelector('#projects-body');
          const projectBodyRect = projectBody.getBoundingClientRect();
          const unverifiedRow = projectBody.querySelector('.tree-item.ownership-unverified');
          const warning = unverifiedRow.querySelector('.ownership-warning');
          const warningCopy = warning.querySelector('.ownership-warning-copy');
          const warningTitle = warning.querySelector('.ownership-warning-title');
          const projectName = projectBody.querySelector('.tree-head .proj-name');
          const projectNameStyle = getComputedStyle(projectName);
          const projectNameLineHeight = Number.parseFloat(projectNameStyle.lineHeight)
            || Number.parseFloat(projectNameStyle.fontSize) * 1.2;
          const actionCells = [...projectBody.querySelectorAll('.tree-grid > .actions')];
          const projectActions = projectBody.querySelector('.tree-head > .project-actions');
          const projectActionStyle = getComputedStyle(projectActions);
          return {
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            projectBodyClientWidth: projectBody.clientWidth,
            projectBodyScrollWidth: projectBody.scrollWidth,
            rowClientWidth: unverifiedRow.clientWidth,
            rowScrollWidth: unverifiedRow.scrollWidth,
            warningWidth: warning.getBoundingClientRect().width,
            warningCopyWidth: warningCopy.getBoundingClientRect().width,
            warningTitleWidth: warningTitle.getBoundingClientRect().width,
            projectNameLines: projectName.getBoundingClientRect().height / projectNameLineHeight,
            projectActionDisplay: projectActionStyle.display,
            projectActionColumns: projectActionStyle.gridTemplateColumns,
            projectActionGap: projectActionStyle.columnGap,
            projectActionChildren: [...projectActions.children].map((child) => ({
              display: getComputedStyle(child).display,
              width: child.getBoundingClientRect().width,
              scrollWidth: child.scrollWidth,
            })),
            escapingActions: actionCells.filter((cell) => {
              const rect = cell.getBoundingClientRect();
              return rect.left < 0 || rect.right > window.innerWidth + 1;
            }).length,
            overflowingElements: [...document.querySelectorAll('body *')]
              .map((node) => {
                const rect = node.getBoundingClientRect();
                return {
                  selector: node.id ? `#${node.id}` : `${node.tagName.toLowerCase()}.${node.className}`,
                  left: Math.round(rect.left),
                  right: Math.round(rect.right),
                  width: Math.round(rect.width),
                };
              })
              .filter((item) => item.width > 0 && (item.left < -1 || item.right > window.innerWidth + 1))
              .slice(0, 12),
            escapingProjectBody: [...projectBody.querySelectorAll('*')]
              .map((node) => {
                const rect = node.getBoundingClientRect();
                return {
                  selector: node.id ? `#${node.id}` : `${node.tagName.toLowerCase()}.${node.className}`,
                  left: Math.round(rect.left),
                  right: Math.round(rect.right),
                  width: Math.round(rect.width),
                  scrollWidth: node.scrollWidth,
                  clientWidth: node.clientWidth,
                };
              })
              .filter((item) => item.width > 0 && (
                item.left < projectBodyRect.left - 1
                || item.right > projectBodyRect.right + 1
                || item.scrollWidth > item.clientWidth + 1
              ))
              .slice(0, 20),
          };
        });
        assert.ok(geometry.documentWidth <= geometry.viewportWidth,
          `${width}px Projects must not create document-level horizontal overflow: ${JSON.stringify(geometry)}`);
        assert.ok(geometry.projectBodyScrollWidth <= geometry.projectBodyClientWidth,
          `${width}px Projects content must stay inside its collection`);
        assert.ok(geometry.rowScrollWidth <= geometry.rowClientWidth,
          `${width}px ownership rows must not hide content horizontally`);
        assert.ok(geometry.warningWidth >= Math.min(180, geometry.rowClientWidth * .7),
          `${width}px ownership explanations must retain a readable content width: ${JSON.stringify(geometry)}`);
        assert.ok(geometry.warningCopyWidth >= 140 && geometry.warningTitleWidth >= 140,
          `${width}px ownership copy must not collapse into one-word lines: ${JSON.stringify(geometry)}`);
        assert.ok(geometry.projectNameLines <= 2.1,
          `${width}px project names must remain readable rather than vertically clipped`);
        assert.equal(geometry.escapingActions, 0,
          `${width}px project action groups must remain inside the viewport`);
      }
      await page.setViewportSize({ width: 1135, height: 919 });
      // The preceding Projects check intentionally exercises the warning for
      // an unverified container. Subsequent journeys use the same repository
      // as a healthy unrelated control, so publish the verified Docker-label
      // evidence before navigating away. This keeps the two assertions about
      // distinct producer states instead of asking one fixture row to be both.
      databaseContainerVerified = true;
      overviewRevision += 1;

      await page.goto(`${origin}/#/routes`, { waitUntil: 'networkidle' });
      await page.locator('#routes-body [data-route-slug]').first().waitFor();
      assert.equal(await page.locator('#routes-body [data-route-slug]').count(), 32,
        'Routes must lead with the complete real collection');
      assert.equal(await page.locator('#route-dialog').getAttribute('open'), null);

      await page.locator('#route-add').click();
      assert.equal(await page.locator('#route-dialog').getAttribute('open'), '');
      await page.waitForFunction(() => document.activeElement?.id === 'rf-slug');
      const wideRouteDialogGeometry = await page.locator('#route-dialog').evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return {
          left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
          viewportWidth: window.innerWidth, viewportHeight: window.innerHeight,
        };
      });
      assert.ok(wideRouteDialogGeometry.left >= 0
        && wideRouteDialogGeometry.right <= wideRouteDialogGeometry.viewportWidth
        && wideRouteDialogGeometry.top >= 0
        && wideRouteDialogGeometry.bottom <= wideRouteDialogGeometry.viewportHeight,
      'the route form must open inside the current desktop viewport');
      await page.locator('input[name="rf-kind"][value="server"]').check();
      assert.equal(await page.locator('#rf-server-wrap').isVisible(), true,
        'managed-server creation must remain available in the dialog');
      assert.ok(await page.locator('#rf-server option').count() > 1,
        'managed-server creation must retain the current coordinator targets');
      await page.locator('input[name="rf-kind"][value="docker"]').check();
      assert.equal(await page.locator('#rf-container-wrap').isVisible(), true,
        'container creation must remain available in the dialog');
      await page.locator('input[name="rf-kind"][value="port"]').check();
      assert.equal(await page.locator('#rf-port-wrap').isVisible(), true,
        'fixed-port creation must remain available in the dialog');
      await page.locator('#route-cancel').click();
      await page.waitForFunction(() => document.activeElement?.id === 'route-add');

      const managedRoute = page.locator('[data-route-slug="fixture-route-01"]');
      const managedAccess = managedRoute.locator('[data-fk="route-auth:fixture-route-01"]');
      assert.equal(await managedAccess.getAttribute('aria-checked'), 'false');
      await managedAccess.click();
      await page.waitForFunction(() => (
        document.querySelector('[data-fk="route-auth:fixture-route-01"]')
          ?.getAttribute('aria-checked') === 'true'
      ));
      assert.match(await managedAccess.textContent(), /Login/,
        'an existing route must remain manageable from the collection');

      for (const width of [676, 390, 320]) {
        await page.setViewportSize({ width, height: 844 });
        await page.waitForFunction((expected) => window.innerWidth === expected, width);
        const routeGeometry = await managedRoute.locator('.row.routes-grid').evaluate((row) => {
          const cells = [...row.children];
          const boxes = cells.map((cell) => {
            const rect = cell.getBoundingClientRect();
            return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom };
          });
          const rowRect = row.getBoundingClientRect();
          return {
            viewportWidth: window.innerWidth,
            documentWidth: document.documentElement.scrollWidth,
            rowClientWidth: row.clientWidth,
            rowScrollWidth: row.scrollWidth,
            rowLeft: rowRect.left,
            rowRight: rowRect.right,
            rowHeight: rowRect.height,
            boxes,
            labelDisplay: getComputedStyle(cells[0], '::before').display,
          };
        });
        assert.ok(routeGeometry.documentWidth <= routeGeometry.viewportWidth + 1,
          `${width}px Routes must not create document-level horizontal overflow: ${JSON.stringify(routeGeometry)}`);
        assert.ok(routeGeometry.rowScrollWidth <= routeGeometry.rowClientWidth + 1,
          `${width}px route card content must remain reachable without horizontal scrolling`);
        assert.ok(routeGeometry.boxes.every((box) => (
          box.left >= routeGeometry.rowLeft - 1 && box.right <= routeGeometry.rowRight + 1
        )), `${width}px route controls must remain inside their card: ${JSON.stringify(routeGeometry)}`);
        assert.ok(routeGeometry.rowHeight <= 140,
          `${width}px route cards must stay compact instead of stacking five labeled rows: ${JSON.stringify(routeGeometry)}`);
        assert.equal(routeGeometry.labelDisplay, 'none',
          `${width}px route cards must not repeat desktop column labels`);
        assert.ok(Math.abs(routeGeometry.boxes[0].top - routeGeometry.boxes[4].top) <= 8,
          `${width}px route identity and remove action must share the first band`);
        assert.ok(Math.abs(routeGeometry.boxes[2].top - routeGeometry.boxes[3].top) <= 8,
          `${width}px route health and access must share the final band`);
      }

      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForFunction(() => window.innerWidth === 390);
      await page.locator('#route-add').click();
      await page.waitForFunction(() => document.activeElement?.id === 'rf-slug');
      const mobileRouteDialogGeometry = await page.locator('#route-dialog').evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return {
          left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
          viewportWidth: window.innerWidth, viewportHeight: window.innerHeight,
        };
      });
      assert.ok(mobileRouteDialogGeometry.left >= 0
        && mobileRouteDialogGeometry.right <= mobileRouteDialogGeometry.viewportWidth
        && mobileRouteDialogGeometry.top >= 0
        && mobileRouteDialogGeometry.bottom <= mobileRouteDialogGeometry.viewportHeight,
      'the route form must open inside the current mobile viewport');
      await page.locator('#rf-slug').fill('created-after-long-list');
      await page.locator('#rf-port').fill('4567');
      await page.locator('#rf-title').fill('Created after a long route list');
      await page.locator('#rf-submit').click();
      const createdRouteRow = page.locator('[data-route-slug="created-after-long-list"]');
      await createdRouteRow.waitFor();
      await page.waitForTimeout(1_000);
      const routeFocusState = await page.evaluate(() => ({
        activeRouteSlug: document.activeElement?.dataset?.routeSlug || null,
        activeTag: document.activeElement?.tagName || null,
        dialogOpen: document.querySelector('#route-dialog')?.open === true,
        rowTabIndex: document.querySelector('[data-route-slug="created-after-long-list"]')?.tabIndex,
      }));
      assert.equal(routeFocusState.activeRouteSlug, 'created-after-long-list',
        `successful creation must focus the new route row: ${JSON.stringify(routeFocusState)}`);
      assert.equal(await page.locator('#route-dialog').getAttribute('open'), null);
      const createdRouteGeometry = await createdRouteRow.evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return { top: rect.top, bottom: rect.bottom, viewportHeight: window.innerHeight };
      });
      assert.ok(createdRouteGeometry.top >= 0
        && createdRouteGeometry.bottom <= createdRouteGeometry.viewportHeight,
      `successful creation must reveal the new route in collection context: ${JSON.stringify(createdRouteGeometry)}`);
      await page.locator('#route-add').click();
      await page.locator('#route-cancel').click();
      await page.waitForFunction(() => document.activeElement?.id === 'route-add');
      await page.setViewportSize({ width: 1135, height: 919 });

      await page.goto(`${origin}/#/ports`, { waitUntil: 'networkidle' });
      await page.locator('#leases-body [data-lease-id]').first().waitFor();
      assert.equal(await page.locator('#leases-body [data-lease-id]').count(), 32,
        'Port leases must lead with the real collection');
      assert.equal(await page.locator('#lease-dialog').getAttribute('open'), null);
      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForFunction(() => window.innerWidth === 390);
      await page.locator('#lease-add').click();
      assert.equal(await page.locator('#lease-dialog').getAttribute('open'), '');
      await page.waitForFunction(() => document.activeElement?.id === 'lf-purpose');
      const leaseDialogGeometry = await page.locator('#lease-dialog').evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return {
          left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom,
          viewportWidth: window.innerWidth, viewportHeight: window.innerHeight,
        };
      });
      assert.ok(leaseDialogGeometry.left >= 0
        && leaseDialogGeometry.right <= leaseDialogGeometry.viewportWidth
        && leaseDialogGeometry.top >= 0
        && leaseDialogGeometry.bottom <= leaseDialogGeometry.viewportHeight,
      'the lease form must open inside the current mobile viewport');
      await page.locator('#lf-purpose').fill('Created after a long list');
      await page.locator('#lf-preferred').fill('3456');
      await page.locator('#lf-project').fill('/fixtures/projects/alpha');
      await page.locator('#lf-submit').click();
      const createdLeaseRow = page.locator('[data-lease-id="fixture-lease-created"]');
      await createdLeaseRow.waitFor();
      await page.waitForTimeout(1_000);
      const leaseFocusState = await page.evaluate(() => ({
        activeId: document.activeElement?.id || null,
        activeLeaseId: document.activeElement?.dataset?.leaseId || null,
        activeTag: document.activeElement?.tagName || null,
        dialogOpen: document.querySelector('#lease-dialog')?.open === true,
        rowTabIndex: document.querySelector('[data-lease-id="fixture-lease-created"]')?.tabIndex,
      }));
      assert.equal(leaseFocusState.activeLeaseId, 'fixture-lease-created',
        `successful creation must focus the new lease row: ${JSON.stringify(leaseFocusState)}`);
      assert.equal(await page.locator('#lease-dialog').getAttribute('open'), null);
      const createdLeaseGeometry = await createdLeaseRow.evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return { top: rect.top, bottom: rect.bottom, viewportHeight: window.innerHeight };
      });
      assert.ok(createdLeaseGeometry.top >= 0
        && createdLeaseGeometry.bottom <= createdLeaseGeometry.viewportHeight,
      `successful creation must reveal the new lease in collection context: ${JSON.stringify(createdLeaseGeometry)}`);
      await page.locator('#lease-add').click();
      await page.locator('#lease-cancel').click();
      await page.waitForFunction(() => document.activeElement?.id === 'lease-add');
      await page.setViewportSize({ width: 1135, height: 919 });

      await page.goto(`${origin}/#/docker`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelectorAll('#docker-body [data-fk^="dock-group:"]').length === 3
        && !document.querySelector('#docker-body .skel')
      ));
      const globalFinanceKey = 'dock-group:path:/fixtures/projects/global-finance';
      const xfoilKey = 'dock-group:path:/fixtures/projects/xfoil';
      const globalFinanceToggle = page.locator(`[data-fk="${globalFinanceKey}"]`);
      const xfoilToggle = page.locator(`[data-fk="${xfoilKey}"]`);
      const globalFinanceBlock = page.locator('.docker-project-block').filter({ has: globalFinanceToggle });

      assert.deepEqual(
        await page.locator('#docker-body [data-fk^="dock-group:"]').evaluateAll(
          (buttons) => buttons.map((button) => button.getAttribute('aria-expanded')),
        ),
        ['false', 'false', 'false'],
        'all Docker project groups must default closed',
      );
      assert.equal(await page.locator('#docker-body .docker-group-items:not([hidden])').count(), 0,
        'closed Docker groups must mount no visible member region');

      await globalFinanceToggle.click();
      assert.equal(await globalFinanceToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await xfoilToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(
        await page.locator('#docker-body [data-fk^="dock-group:"][aria-expanded="true"]').count(),
        1,
        'opening GlobalFinance must disclose exactly one Docker project',
      );
      assert.equal(await globalFinanceBlock.locator('.docker-group-items > .item').count(), 75,
        'only the first bounded page of the 85-container project may be mounted');

      const dockerLogToggle = globalFinanceBlock.locator('[data-fk^="dock-logs:"]').first();
      const dockerPanelId = await dockerLogToggle.getAttribute('aria-controls');
      const dockerPanel = page.locator(`[id="${dockerPanelId}"]`);
      const dockerScrollBefore = await page.evaluate(() => window.scrollY);
      await dockerLogToggle.click();
      await dockerPanel.locator('.log-empty.err').waitFor();
      assert.match(await dockerPanel.textContent(), /exact container log is temporarily unavailable/i);
      assert.equal(await dockerLogToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await page.locator('#banner-slot .banner').count(), 0,
        'a resource-local Docker log failure must not create a global banner');
      assert.ok(Math.abs(await page.evaluate(() => window.scrollY) - dockerScrollBefore) <= 1,
        'a Docker log error must preserve document scroll context');
      const dockerRefresh = dockerPanel.locator('[data-fk^="dock-logs-refresh:"]');
      await dockerRefresh.click();
      await dockerPanel.getByText('validation failed safely', { exact: false }).waitFor();
      assert.equal(await dockerPanel.locator('.log-empty.err').count(), 0);
      assert.equal(await dockerRefresh.evaluate((node) => document.activeElement === node), true,
        'successful Docker log refresh must retain focus on Refresh');
      assert.equal(dockerLogAttempts, 2);
      await dockerLogToggle.click();

      // Archive polling can replace the whole Docker section between separate
      // locator reads. Resolve the active disclosure, row, geometry and usage
      // evidence from one connected DOM snapshot so a detached row cannot
      // masquerade as a responsive-layout failure.
      const intermediateRowHandle = await page.waitForFunction(({ focusKey, containerName }) => {
        const toggleNode = document.querySelector(
          `[data-fk="${CSS.escape(focusKey)}"]`,
        );
        if (!toggleNode?.isConnected || toggleNode.getAttribute('aria-expanded') !== 'true') {
          return false;
        }
        const blockNode = toggleNode.closest('.docker-project-block');
        if (!blockNode?.isConnected) return false;
        const rowNode = [...blockNode.querySelectorAll('.row.dock-grid.expandable')]
          .find((candidate) => (
            candidate.querySelector('[data-label="Container"] strong')?.textContent?.trim()
            === containerName
          ));
        if (!rowNode?.isConnected) return false;
        const nameCell = rowNode.querySelector('[data-label="Container"]');
        const name = nameCell?.querySelector('strong');
        const ports = rowNode.querySelector('[data-label="Ports"]');
        const actions = rowNode.querySelector('.actions');
        const usage = rowNode.querySelector('[data-label="CPU / Mem"] button');
        if (![nameCell, name, ports, actions, usage].every((node) => node?.isConnected)) {
          return false;
        }
        const nameCellRect = nameCell.getBoundingClientRect();
        const nameRect = name.getBoundingClientRect();
        const portsRect = ports.getBoundingClientRect();
        const actionsRect = actions.getBoundingClientRect();
        const nameStyle = getComputedStyle(name);
        const lineHeight = Number.parseFloat(nameStyle.lineHeight)
          || Number.parseFloat(nameStyle.fontSize) * 1.2;
        if (nameCellRect.width <= 0 || nameRect.height <= 0 || lineHeight <= 0) return false;
        return {
          nameWidth: nameCellRect.width,
          nameLines: nameRect.height / lineHeight,
          portsActionsOverlap: !(
            portsRect.right <= actionsRect.left
            || actionsRect.right <= portsRect.left
            || portsRect.bottom <= actionsRect.top
            || actionsRect.bottom <= portsRect.top
          ),
          blockClientWidth: blockNode.clientWidth,
          blockScrollWidth: blockNode.scrollWidth,
          usageLabel: usage.getAttribute('aria-label'),
        };
      }, {
        focusKey: globalFinanceKey,
        containerName: LONG_DOCKER_NAME,
      }, { timeout: 5_000 });
      const intermediateRow = await intermediateRowHandle.jsonValue();
      await intermediateRowHandle.dispose();
      assert.ok(intermediateRow.nameWidth >= 220,
        `the reported intermediate viewport must reserve at least 220px for container names: ${JSON.stringify(intermediateRow)}`);
      assert.ok(intermediateRow.nameLines <= 5,
        'the long container name must not collapse into one character per line');
      assert.equal(intermediateRow.portsActionsOverlap, false,
        'Docker port mappings must not be covered by lifecycle and runtime actions');
      assert.ok(intermediateRow.blockScrollWidth <= intermediateRow.blockClientWidth,
        'the intermediate Docker layout must remain inside its project block');
      assert.match(intermediateRow.usageLabel, /CPU 1\.1%, memory 46\.0 MiB/,
        'a running Docker row must expose its observed CPU and memory utilization');

      // Exercise the exact reported 319px width with real SVG history
      // sparklines. The previous 390px/empty-metrics fixture could not detect
      // a fixed-width chart escaping a stacked Docker card.
      for (const width of [319, 390]) {
        await page.setViewportSize({ width, height: width === 319 ? 1804 : 844 });
        await page.waitForFunction(() => matchMedia('(max-width: 719px)').matches);

        // Inventory polling can replace the whole Docker section between
        // locator resolution and evaluate(). A detached button has an all-zero
        // DOMRect, which is not evidence of the rendered 390px layout. Measure
        // one current, connected header atomically; a genuinely hidden header
        // remains a timeout/failure instead of becoming a false pass.
        const headerGeometryHandle = await page.waitForFunction((focusKey) => {
          const toggleNode = document.querySelector(
            `[data-fk="${CSS.escape(focusKey)}"]`,
          );
          if (!toggleNode?.isConnected) return false;
          const tolerance = 1;
          const outer = toggleNode.getBoundingClientRect();
          const name = toggleNode.querySelector('.proj-name');
          if (!name?.isConnected) return false;
          const nameRect = name.getBoundingClientRect();
          if (outer.width <= 0 || outer.height <= 0 || nameRect.width <= 0 || nameRect.height <= 0) {
            return false;
          }
          const style = getComputedStyle(name);
          const lineHeight = Number.parseFloat(style.lineHeight)
            || Number.parseFloat(style.fontSize) * 1.2;
          const visibleParts = [...toggleNode.querySelectorAll(
            '.proj-name, .server-group-count, .proj-usage, .spark',
          )].filter((node) => {
            const nodeStyle = getComputedStyle(node);
            const rect = node.getBoundingClientRect();
            return nodeStyle.display !== 'none' && rect.width > 0 && rect.height > 0;
          });
          const escaping = visibleParts.map((node) => {
            const rect = node.getBoundingClientRect();
            return {
              className: node.getAttribute('class'),
              left: rect.left,
              right: rect.right,
            };
          }).filter((rect) => (
            rect.left < outer.left - tolerance || rect.right > outer.right + tolerance
          ));
          return {
            clientWidth: toggleNode.clientWidth,
            scrollWidth: toggleNode.scrollWidth,
            outerLeft: outer.left,
            outerRight: outer.right,
            parentLeft: toggleNode.parentElement.getBoundingClientRect().left,
            parentRight: toggleNode.parentElement.getBoundingClientRect().right,
            gridTemplateColumns: getComputedStyle(toggleNode).gridTemplateColumns,
            paddingInline: `${getComputedStyle(toggleNode).paddingLeft} ${getComputedStyle(toggleNode).paddingRight}`,
            nameWidth: nameRect.width,
            nameLines: nameRect.height / lineHeight,
            escaping,
            visibleHeaderSparks: visibleParts.filter((node) => node.matches('.spark')).length,
          };
        }, globalFinanceKey, { timeout: 5_000 });
        const headerGeometry = await headerGeometryHandle.jsonValue();
        await headerGeometryHandle.dispose();
        assert.ok(headerGeometry.nameWidth >= 96,
          `${width}px Docker project names must retain a readable track: ${JSON.stringify(headerGeometry)}`);
        assert.ok(headerGeometry.nameLines <= 2.1,
          `${width}px Docker project names must not collapse into one character per line`);
        assert.deepEqual(headerGeometry.escaping, [],
          `${width}px Docker project summary content must stay inside its disclosure: ${JSON.stringify(headerGeometry)}`);
        assert.ok(headerGeometry.scrollWidth <= headerGeometry.clientWidth,
          `${width}px Docker project disclosures must not overflow horizontally`);
        assert.equal(headerGeometry.visibleHeaderSparks, 0,
          `${width}px Docker project summaries must hide the redundant inline sparkline`);

        // Resolve the current row and measure it atomically. Inventory polling
        // may replace the section between separate locator/evaluate calls; an
        // all-zero detached or temporarily hidden DOMRect is not layout
        // evidence. A genuinely collapsed/missing row still times out here.
        const rowGeometryHandle = await page.waitForFunction(({ focusKey, containerName }) => {
          const toggleNode = document.querySelector(
            `[data-fk="${CSS.escape(focusKey)}"]`,
          );
          if (!toggleNode?.isConnected || toggleNode.getAttribute('aria-expanded') !== 'true') {
            return false;
          }
          const blockNode = toggleNode.closest('.docker-project-block');
          if (!blockNode?.isConnected) return false;
          const rowNode = [...blockNode.querySelectorAll('.row.dock-grid.expandable')]
            .find((candidate) => (
              candidate.querySelector('[data-label="Container"] strong')?.textContent?.trim()
              === containerName
            ));
          if (!rowNode?.isConnected) return false;
          const tolerance = 1;
          const row = rowNode.getBoundingClientRect();
          const block = blockNode.getBoundingClientRect();
          const selectors = [
            '[data-label="CPU / Mem"]',
            '[data-label="CPU / Mem"] .usage-btn',
            '[data-label="CPU / Mem"] .spark',
            '[data-label="Ports"]',
            '.actions',
          ];
          const escaping = selectors.flatMap((selector) => (
            [...rowNode.querySelectorAll(selector)].map((node) => {
              const rect = node.getBoundingClientRect();
              return { selector, left: rect.left, right: rect.right };
            }).filter((rect) => (
              rect.left < row.left - tolerance
              || rect.right > row.right + tolerance
              || rect.left < block.left - tolerance
              || rect.right > block.right + tolerance
            ))
          ));
          const name = rowNode.querySelector('[data-label="Container"] strong');
          if (!name?.isConnected) return false;
          const nameStyle = getComputedStyle(name);
          const nameLineHeight = Number.parseFloat(nameStyle.lineHeight)
            || Number.parseFloat(nameStyle.fontSize) * 1.2;
          const nameRect = name.getBoundingClientRect();
          const geometry = {
            rowClientWidth: rowNode.clientWidth,
            rowScrollWidth: rowNode.scrollWidth,
            blockClientWidth: blockNode.clientWidth,
            blockScrollWidth: blockNode.scrollWidth,
            nameWidth: nameRect.width,
            nameLines: nameRect.height / nameLineHeight,
            escaping,
          };
          return geometry.rowClientWidth > 0
            && geometry.blockClientWidth > 0
            && geometry.nameWidth > 0
            ? geometry : false;
        }, {
          focusKey: globalFinanceKey,
          containerName: LONG_DOCKER_NAME,
        }, { timeout: 5_000 });
        const rowGeometry = await rowGeometryHandle.jsonValue();
        await rowGeometryHandle.dispose();
        assert.ok(rowGeometry.rowClientWidth > 0
          && rowGeometry.blockClientWidth > 0
          && rowGeometry.nameWidth > 0,
        `${width}px Docker row must be rendered while its geometry is verified: ${JSON.stringify(rowGeometry)}`);
        assert.deepEqual(rowGeometry.escaping, [],
          `${width}px Docker row controls and chart must stay inside the card`);
        assert.ok(rowGeometry.rowScrollWidth <= rowGeometry.rowClientWidth,
          `${width}px Docker rows must not create hidden horizontal overflow`);
        assert.ok(rowGeometry.blockScrollWidth <= rowGeometry.blockClientWidth,
          `${width}px Docker project blocks must contain every expanded row`);
        assert.ok(rowGeometry.nameLines <= 6,
          `${width}px long container names must remain readable without vertical character stacking`);
      }
      await page.setViewportSize({ width: 1135, height: 919 });

      await xfoilToggle.focus();
      await xfoilToggle.press('Enter');
      assert.equal(await globalFinanceToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(await xfoilToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await page.locator('#docker-body .docker-group-items:not([hidden])').count(), 1,
        'keyboard activation must close the old Docker project');
      assert.equal(await activeFocusKey(page), xfoilKey,
        'the keyboard-activated Docker disclosure must retain focus after rerender');

      // Producer-reported ownership problems stay contained: healthy repository
      // groups and controls remain available, while only the exact affected
      // resource is mutation-blocked. A database problem also fences its exact
      // backing container without disabling the containing repository.
      includeUnassigned = true;
      includeDatabaseOwnershipProblem = true;
      overviewRevision += 1;
      await page.reload({ waitUntil: 'networkidle' });
      const ownershipDiagnostics = page.locator('#docker-body .inventory-diagnostics');
      await ownershipDiagnostics.waitFor();
      assert.match(await ownershipDiagnostics.textContent(),
        /1 ownership issue needs attention.*1 actionable issue affects 3 resources.*gnt-artifact-pg.*2 databases affected.*only its name—not a repository path—was observed.*sample_api.*sample_audit/is);
      assert.equal(await page.locator('#docker-body .repository-inventory-error').count(), 0,
        'explicit ownership problems must not masquerade as a malformed inventory contract');
      assert.equal(await page.locator('#docker-body .inventory-diagnostic-group').count(), 1,
        'database children must roll up under their one actionable parent-container issue');
      assert.equal(await page.locator('#docker-body .docker-project-block').count(), 3,
        'all healthy repository groups must remain visible beside ownership diagnostics');

      // Inventory is polled continuously. A changed observation rebuilds the
      // section, but it must not collapse the native disclosure that the user
      // opened, steal focus from its summary, or jump the document while they
      // are reading the evidence.
      const parentDisclosureKey = 'inventory-diagnostic:container:fixture-container-202';
      const databaseDisclosureKey = `${parentDisclosureKey}:children`;
      const parentDiagnostics = page.locator(
        `#docker-body [data-section-disclosure="${parentDisclosureKey}"]`,
      );
      await parentDiagnostics.locator(`[data-fk="${parentDisclosureKey}"]`).click();
      const databaseDiagnostics = page.locator(
        `#docker-body [data-section-disclosure="${databaseDisclosureKey}"]`,
      );
      const databaseDiagnosticsSummary = databaseDiagnostics.locator(
        `[data-fk="${databaseDisclosureKey}"]`,
      );
      await databaseDiagnosticsSummary.click();
      assert.equal(await databaseDiagnostics.getAttribute('open'), '',
        'the exact projected database evidence must open normally');
      assert.equal(await databaseDiagnostics.locator('li').count(), 2,
        'every projected child binding must remain available behind the disclosure');
      await databaseDiagnosticsSummary.evaluate((summary) => {
        summary.focus({ preventScroll: true });
        window.scrollTo(0, 120);
      });
      const scrollBeforeDiagnosticPoll = await page.evaluate(() => window.scrollY);
      const oldDatabaseDiagnostics = await databaseDiagnostics.elementHandle();
      const requestsBeforeDiagnosticPoll = overviewRequests;
      // The observer may replace an opaque host-resource ID while retaining
      // the same name-only ownership finding. This previously made the
      // disclosure key change, so a live refresh collapsed the evidence the
      // user was reading despite no meaningful diagnosis changing.
      unassignedResourceId = 'fixture-container-202-reobserved';
      overviewRevision += 1;
      await page.waitForFunction(
        (node) => !node.isConnected,
        oldDatabaseDiagnostics,
        { timeout: 9_000 },
      );
      await oldDatabaseDiagnostics.dispose();
      assert.ok(overviewRequests > requestsBeforeDiagnosticPoll,
        'the six-second inventory poll must have rebuilt the diagnostic fixture');
      const refreshedParentDisclosureKey = 'inventory-diagnostic:container:fixture-container-202-reobserved';
      const refreshedDatabaseDisclosureKey = `${refreshedParentDisclosureKey}:children`;
      const refreshedParentDiagnostics = page.locator(
        `#docker-body [data-section-disclosure="${refreshedParentDisclosureKey}"]`,
      );
      const refreshedDatabaseDiagnostics = page.locator(
        `#docker-body [data-section-disclosure="${refreshedDatabaseDisclosureKey}"]`,
      );
      assert.equal(await refreshedParentDiagnostics.getAttribute('open'), '',
        'the parent ownership issue must survive a polling rerender that replaces its opaque ID');
      assert.equal(await refreshedDatabaseDiagnostics.getAttribute('open'), '',
        'expanded exact database evidence must survive a polling rerender that replaces its opaque ID');
      assert.equal(await activeFocusKey(page), refreshedDatabaseDisclosureKey,
        'the focused child-evidence summary must regain focus through its stable diagnostic match');
      const scrollAfterDiagnosticPoll = await page.evaluate(() => window.scrollY);
      assert.ok(Math.abs(scrollAfterDiagnosticPoll - scrollBeforeDiagnosticPoll) <= 1,
        'polling must preserve the document scroll position while ownership evidence is open');

      const healthyDockerToggle = page.locator(
        '[data-fk="dock-group:path:/fixtures/projects/global-finance"]',
      );
      assert.equal(await healthyDockerToggle.isEnabled(), true,
        'an unrelated healthy repository disclosure must remain operable');
      await healthyDockerToggle.click();
      const healthyDockerRow = page.locator('#docker-body .docker-project-block')
        .filter({ has: healthyDockerToggle })
        .locator('[data-lifecycle-target^="container:"]').first();
      await healthyDockerRow.waitFor();
      assert.equal(await healthyDockerRow.locator('button[data-fk^="dock-restart:"]').isEnabled(), true,
        'an unrelated healthy container restart must remain enabled');
      assert.equal(await healthyDockerRow.locator('button[data-fk^="dock-stop:"]').isEnabled(), true,
        'an unrelated healthy container stop must remain enabled');

      const databaseDockerToggle = page.locator(
        '[data-fk="dock-group:path:/fixtures/projects/db"]',
      );
      assert.equal(await databaseDockerToggle.isEnabled(), true,
        'an unrelated database repository must remain navigable');
      await databaseDockerToggle.click();
      const unaffectedDockerRow = page.locator('#docker-body .docker-project-block')
        .filter({ has: databaseDockerToggle })
        .locator('.row.dock-grid').first();
      await unaffectedDockerRow.waitFor();
      assert.equal(await unaffectedDockerRow.locator('button[data-fk^="dock-restart:"]').isEnabled(), true,
        'a projected child problem must not disable restart on an unrelated container');
      assert.equal(await unaffectedDockerRow.locator('button[data-fk^="dock-stop:"]').isEnabled(), true,
        'a projected child problem must not disable stop on an unrelated container');

      // Contradictory structural evidence remains a global fail-closed boundary:
      // this exact container is deliberately assigned to two repository scopes.
      includeUnassigned = false;
      includeDatabaseOwnershipProblem = false;
      structuralInventoryContradiction = true;
      await page.reload({ waitUntil: 'networkidle' });
      const assignmentError = page.locator('#docker-body .repository-inventory-error');
      await assignmentError.waitFor();
      assert.match(await assignmentError.textContent(),
        /Repository inventory contract is invalid.*container is missing, duplicated, or assigned to the wrong repository scope/is);
      assert.equal(await page.locator('#docker-body .docker-project-block').count(), 0,
        'contradictory repository association must remove every lifecycle target');
      assert.equal(await page.locator('#docker-body button').count(), 0,
        'a structural contradiction must expose no stale lifecycle mutation');

      structuralInventoryContradiction = false;
      overviewRevision = 0;
      await page.reload({ waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelectorAll('#docker-body [data-fk^="dock-group:"]').length === 3
        && !document.querySelector('#docker-body .repository-inventory-error')
      ));

      await page.goto(`${origin}/#/telegram`, { waitUntil: 'networkidle' });
      await page.locator('#telegram-body [data-telegram-bot="fixture-telegram-bot"]').waitFor();
      assert.equal(await page.locator('#nav-count-telegram').textContent(), '1',
        'the Telegram navigation badge must count registered bots, not pending users');
      assert.equal(await page.locator('#telegram-count').textContent(), '1',
        'the Telegram collection count must agree with the navigation badge');
      assert.equal(await page.getByRole('heading', { name: 'Bot authorization queue' }).count(), 1,
        'an empty authorization queue must stay separately and truthfully labeled');

      await page.goto(`${origin}/#/servers`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelectorAll('#servers-body .server-project-toggle').length === 2
        && !document.querySelector('#servers-body .skel')
      ));

      const alphaKey = 'srv-group:path:/fixtures/projects/alpha';
      const betaKey = 'srv-group:path:/fixtures/projects/beta';
      const alphaToggle = page.locator(`[data-fk="${alphaKey}"]`);
      const betaToggle = page.locator(`[data-fk="${betaKey}"]`);
      const alphaBlock = page.locator('.server-project-block').filter({ has: alphaToggle });

      assert.deepEqual(
        await page.locator('#servers-body .server-project-toggle').evaluateAll(
          (buttons) => buttons.map((button) => button.getAttribute('aria-expanded')),
        ),
        ['false', 'false'],
        'both real project groups must default closed',
      );
      assert.equal(
        await page.locator('#servers-body .server-group-items:not([hidden])').count(),
        0,
        'closed groups must mount no visible member region',
      );

      await alphaToggle.click();
      assert.equal(await alphaToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await betaToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(await expandedCount(page), 1, 'mouse activation must open exactly one project');
      assert.equal(await activeFocusKey(page), alphaKey,
        'the replacement disclosure button must retain focus after mouse-triggered rerender');

      await page.setViewportSize({ width: 390, height: 844 });
      const serverLogToggle = alphaBlock.locator('[data-fk^="srv-x:"]').first();
      const serverPanelId = await serverLogToggle.getAttribute('aria-controls');
      const serverPanel = page.locator(`[id="${serverPanelId}"]`);
      await serverLogToggle.scrollIntoViewIfNeeded();
      const serverScrollBefore = await page.evaluate(() => window.scrollY);
      await serverLogToggle.click();
      await serverPanel.locator('.log-empty.err').waitFor();
      assert.match(await serverPanel.textContent(), /exact server log is temporarily unavailable/i);
      assert.equal(await serverLogToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await page.locator('#banner-slot .banner').count(), 0,
        'a resource-local server log failure must not create a global banner');
      assert.ok(Math.abs(await page.evaluate(() => window.scrollY) - serverScrollBefore) <= 1,
        'a server log error must preserve document scroll context');
      const serverRefresh = serverPanel.locator('[data-fk^="srv-logs-refresh:"]');
      await serverRefresh.click();
      await serverPanel.getByText('server recovered safely', { exact: false }).waitFor();
      assert.equal(await serverPanel.locator('.log-empty.err').count(), 0);
      assert.equal(await serverRefresh.evaluate((node) => document.activeElement === node), true,
        'successful server log refresh must retain focus on Refresh');
      assert.equal(serverLogAttempts, 2);
      await serverLogToggle.click();
      assert.ok(browserErrors.every((message) => /409 \(Conflict\)/.test(message)),
        `only the two intentional resource-local 409 responses may reach browser diagnostics: ${JSON.stringify(browserErrors)}`);
      browserErrors.length = 0;
      await page.setViewportSize({ width: 1135, height: 919 });

      await betaToggle.focus();
      await betaToggle.press('Enter');
      assert.equal(await alphaToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(await betaToggle.getAttribute('aria-expanded'), 'true');
      assert.equal(await expandedCount(page), 1, 'keyboard activation must close the old project');
      assert.equal(await activeFocusKey(page), betaKey,
        'the keyboard-activated disclosure must retain focus after rerender');

      // Reproduce the reported 787px Servers row, where the fixed port,
      // utilization, status, warning, and action columns previously consumed
      // the entire row and collapsed "smoke-caddy-http" character-by-character.
      await page.setViewportSize({ width: 787, height: 919 });
      const betaRow = page.locator('.server-project-block').filter({ has: betaToggle })
        .locator('.row.srv-grid.expandable').filter({ hasText: 'smoke-caddy-http' });
      await betaRow.waitFor();
      const betaDetailsToggle = betaRow.locator('[data-fk^="srv-x:"]');
      assert.equal(await betaDetailsToggle.getAttribute('data-log-capable'), null,
        'a service without an authoritative log source must not advertise log capability');
      const noLogPanelId = await betaDetailsToggle.getAttribute('aria-controls');
      const noLogAttemptsBefore = serverLogAttempts;
      await betaDetailsToggle.click();
      const noLogPanel = page.locator(`[id="${noLogPanelId}"]`);
      await noLogPanel.getByText('No authoritative log source is registered', { exact: false }).waitFor();
      assert.equal(await noLogPanel.locator('[data-fk^="srv-logs-refresh:"]').count(), 0,
        'details without a log source must expose no doomed Refresh action');
      assert.equal(serverLogAttempts, noLogAttemptsBefore,
        'opening useful server details must not request a nonexistent log artifact');
      await betaDetailsToggle.click();
      await betaToggle.focus();
      const betaGeometry = await betaRow.evaluate((rowNode) => {
        const tolerance = 1;
        const row = rowNode.getBoundingClientRect();
        const blockNode = rowNode.closest('.server-project-block');
        const block = blockNode.getBoundingClientRect();
        const nameTrack = rowNode.querySelector('.c-primary').getBoundingClientRect();
        const name = rowNode.querySelector('.srv-name strong');
        const nameStyle = getComputedStyle(name);
        const lineHeight = Number.parseFloat(nameStyle.lineHeight)
          || Number.parseFloat(nameStyle.fontSize) * 1.2;
        const nameRect = name.getBoundingClientRect();
        const status = rowNode.querySelector('.srv-status')?.getBoundingClientRect();
        const actions = rowNode.querySelector('.srv-actions')?.getBoundingClientRect();
        const selectors = [
          '[data-label="Port"]',
          '[data-label="CPU / Mem"]',
          '[data-label="Status"]',
          '.actions',
        ];
        const escaping = selectors.flatMap((selector) => (
          [...rowNode.querySelectorAll(selector)].map((node) => {
            const rect = node.getBoundingClientRect();
            return { selector, left: rect.left, right: rect.right };
          }).filter((rect) => (
            rect.left < row.left - tolerance
            || rect.right > row.right + tolerance
            || rect.left < block.left - tolerance
            || rect.right > block.right + tolerance
          ))
        ));
        return {
          rowClientWidth: rowNode.clientWidth,
          rowScrollWidth: rowNode.scrollWidth,
          blockClientWidth: blockNode.clientWidth,
          blockScrollWidth: blockNode.scrollWidth,
          nameTrackWidth: nameTrack.width,
          nameLines: nameRect.height / lineHeight,
          statusTop: status?.top ?? null,
          actionsTop: actions?.top ?? null,
          serverHeaderDisplay: getComputedStyle(
            document.querySelector('#servers-body .grid-head.srv-grid'),
          ).display,
          escaping,
        };
      });
      assert.ok(betaGeometry.nameTrackWidth >= 180,
        '787px Servers rows must reserve at least 180px for the server identity');
      assert.ok(betaGeometry.nameLines <= 2.1,
        'the server name must not collapse into one character per line');
      assert.equal(betaGeometry.serverHeaderDisplay, 'none',
        'tablet server cards must not render a detached desktop column header');
      assert.ok(Math.abs(betaGeometry.statusTop - betaGeometry.actionsTop) <= 2,
        'tablet server controls must stay next to the status they affect');
      assert.deepEqual(betaGeometry.escaping, [],
        '787px server controls and utilization must remain inside the project block');
      assert.ok(betaGeometry.rowScrollWidth <= betaGeometry.rowClientWidth,
        '787px server rows must not create hidden horizontal overflow');
      assert.ok(betaGeometry.blockScrollWidth <= betaGeometry.blockClientWidth,
        '787px server project blocks must contain every expanded row');

      // Reproduce the reported 620px card where every field previously became
      // a separate labeled line and inflated one server to several hundred
      // pixels. Keep a very narrow control as an adjacent responsive case.
      for (const width of [620, 390]) {
        await page.setViewportSize({ width, height: 919 });
        await page.waitForFunction(() => matchMedia('(max-width: 719px)').matches);
        const compactGeometry = await betaRow.evaluate((rowNode) => {
          const tolerance = 1;
          const row = rowNode.getBoundingClientRect();
          const blockNode = rowNode.closest('.server-project-block');
          const block = blockNode.getBoundingClientRect();
          const selectors = [
            '[data-label="Server"]',
            '[data-label="Port"]',
            '[data-label="CPU / Mem"]',
            '[data-label="Status"]',
            '.actions',
          ];
          const escaping = selectors.flatMap((selector) => (
            [...rowNode.querySelectorAll(selector)].map((node) => {
              const rect = node.getBoundingClientRect();
              return { selector, left: rect.left, right: rect.right };
            }).filter((rect) => (
              rect.left < row.left - tolerance
              || rect.right > row.right + tolerance
              || rect.left < block.left - tolerance
              || rect.right > block.right + tolerance
            ))
          ));
          const labelDisplays = [...rowNode.querySelectorAll('.cell[data-label]')]
            .map((node) => getComputedStyle(node, '::before').display);
          const status = rowNode.querySelector('.srv-status')?.getBoundingClientRect();
          const actions = rowNode.querySelector('.srv-actions')?.getBoundingClientRect();
          return {
            height: row.height,
            rowClientWidth: rowNode.clientWidth,
            rowScrollWidth: rowNode.scrollWidth,
            blockClientWidth: blockNode.clientWidth,
            blockScrollWidth: blockNode.scrollWidth,
            labelDisplays,
            statusTop: status?.top ?? null,
            actionsTop: actions?.top ?? null,
            escaping,
          };
        });
        assert.ok(compactGeometry.height <= (width === 620 ? 150 : 180),
          `${width}px server rows must not waste a full line on every secondary field`);
        assert.deepEqual(compactGeometry.escaping, [],
          `${width}px compact server facts and actions must stay inside the project block`);
        assert.ok(compactGeometry.rowScrollWidth <= compactGeometry.rowClientWidth,
          `${width}px compact server rows must not create hidden horizontal overflow`);
        assert.ok(compactGeometry.blockScrollWidth <= compactGeometry.blockClientWidth,
          `${width}px compact project blocks must contain every server control`);
        assert.equal(compactGeometry.labelDisplays.every((display) => display === 'none'), true,
          `${width}px server facts must not regain redundant stacked labels`);
        if (width === 620) {
          assert.ok(Math.abs(compactGeometry.statusTop - compactGeometry.actionsTop) <= 2,
            '620px server cards must keep status beside its controls');
        } else {
          assert.ok(compactGeometry.actionsTop >= compactGeometry.statusTop,
            'phone cards may use a final action band, but it must follow the status');
        }
      }
      await page.setViewportSize({ width: 1135, height: 919 });

      const oldBetaNode = await betaToggle.elementHandle();
      const requestsBeforePoll = overviewRequests;
      overviewRevision = 1;
      await page.waitForFunction(
        () => document.querySelector('[data-fk="srv-group:path:/fixtures/projects/beta"]')
          ?.getAttribute('aria-label')?.includes('CPU 12.5%'),
        null,
        { timeout: 9_000 },
      );
      assert.ok(overviewRequests > requestsBeforePoll, 'the six-second overview poll must have run');
      assert.equal(await oldBetaNode.evaluate((node) => node.isConnected), false,
        'changed poll data must replace the rendered disclosure node');
      await oldBetaNode.dispose();
      assert.equal(await betaToggle.getAttribute('aria-expanded'), 'true',
        'the open project must survive a real polling rerender');
      assert.equal(await alphaToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(await expandedCount(page), 1, 'polling must not reopen another project');
      assert.equal(await activeFocusKey(page), betaKey,
        'focused disclosure must regain focus after a polling rerender');

      await alphaToggle.click();
      assert.equal(await expandedCount(page), 1);
      const alphaItems = alphaBlock.locator('.server-group-items > .item');
      assert.equal(await alphaItems.count(), 75,
        'only the first bounded page of a host-sized project may be mounted');
      assert.equal(await alphaBlock.locator('.resource-page-status').textContent(),
        'Showing 1–75 of 82 visible project servers');
      assert.equal(await alphaBlock.locator('.srv-name strong', { hasText: 'alpha-001' }).count(), 1);
      assert.equal(await alphaBlock.locator('.srv-name strong', { hasText: 'alpha-076' }).count(), 0);

      await alphaBlock.getByRole('button', { name: 'Next project servers page' }).click();
      assert.equal(await alphaItems.count(), 7,
        'the final member page must mount every remaining server and no prior-page rows');
      assert.equal(await alphaBlock.locator('.resource-page-status').textContent(),
        'Showing 76–82 of 82 visible project servers');
      assert.equal(await alphaBlock.locator('.srv-name strong', { hasText: 'alpha-001' }).count(), 0);
      assert.equal(await alphaBlock.locator('.srv-name strong', { hasText: 'alpha-076' }).count(), 1);
      assert.equal(await alphaBlock.locator('.srv-name strong', { hasText: 'alpha-082' }).count(), 1);
      assert.equal(await activeFocusKey(page), 'pager:servers:prev',
        'terminal Next must hand keyboard focus to the enabled Previous control');

      await page.keyboard.press('Enter');
      assert.equal(await alphaItems.count(), 75,
        'the focused Previous control must return to the complete first member page');
      assert.equal(await alphaBlock.locator('.resource-page-status').textContent(),
        'Showing 1–75 of 82 visible project servers');
      assert.equal(await activeFocusKey(page), 'pager:servers:next',
        'terminal Previous must hand focus forward instead of losing it to the document');

      const targetSelector = '[data-lifecycle-target="server:fixture-alpha-001"]';
      const targetRow = () => page.locator(`#servers-body ${targetSelector}`);
      await targetRow().getByRole('button', { name: 'Archive alpha-001' }).click();
      await page.locator('#lifecycle-dialog').waitFor({ state: 'visible' });
      assert.match(await page.locator('#lifecycle-target').textContent(), /alpha-001Server managed by/);
      assert.doesNotMatch(await page.locator('#lifecycle-target').textContent(), /fixture-alpha-001/,
        'the exact immutable ID must stay in the hidden request identity');
      await page.locator('#lifecycle-reason').fill('Browser lifecycle regression');
      await page.getByRole('button', { name: 'Review archive' }).click();
      await page.getByText('Fence future starts', { exact: true }).waitFor();
      assert.match(await page.locator('#lifecycle-plan').textContent(), /Operation history/);
      assert.match(await page.locator('#lifecycle-plan').textContent(), /Log evidence/);
      await page.locator('#lifecycle-dialog')
        .getByRole('button', { name: 'Archive', exact: true }).click();

      await page.waitForFunction((selector) => {
        const row = document.querySelector(`#servers-body ${selector}`);
        return row?.classList.contains('archive-row')
          && document.activeElement === row;
      }, targetSelector);
      assert.equal(
        await page.locator('[data-lifecycle-filter="servers"] [data-lifecycle-view="archived"]')
          .getAttribute('aria-pressed'),
        'true',
        'archive success must switch to the authoritative Archived collection',
      );
      assert.match(await targetRow().textContent(), /Stopped and fenced/);
      assert.match(await targetRow().textContent(), /Operation history/);

      await targetRow().getByRole('button', { name: 'Restore' }).click();
      assert.match(await page.locator('#lifecycle-dialog-summary').textContent(), /does not start/);
      await page.locator('#lifecycle-dialog')
        .getByRole('button', { name: 'Restore', exact: true }).click();
      try {
        await page.waitForFunction((selector) => {
          const row = document.querySelector(`#servers-body ${selector}`);
          return row?.classList.contains('srv-grid')
            && row.textContent.includes('stopped')
            && document.activeElement === row;
        }, targetSelector);
      } catch (error) {
        const diagnostic = await page.evaluate((selector) => {
          const row = document.querySelector(`#servers-body ${selector}`);
          return {
            activeFilter: document.querySelector(
              '[data-lifecycle-filter="servers"] [aria-pressed="true"]',
            )?.getAttribute('data-lifecycle-view') || null,
            activeFocusKey: document.activeElement?.getAttribute('data-fk') || null,
            activeTag: document.activeElement?.tagName || null,
            rowClass: row?.className || null,
            rowText: row?.textContent || null,
            serverBodyText: document.querySelector('#servers-body')?.textContent || null,
          };
        }, targetSelector);
        throw new Error(`restore did not reveal and focus the stopped server: ${JSON.stringify(diagnostic)}`, {
          cause: error,
        });
      }
      assert.equal(
        await page.locator('[data-lifecycle-filter="servers"] [data-lifecycle-view="active"]')
          .getAttribute('aria-pressed'),
        'true',
        'restore success must return to Active and reveal the still-stopped row',
      );

      // Permanent removal remains an archived-only, plan-bound journey.
      await targetRow().getByRole('button', { name: 'Archive alpha-001' }).click();
      await page.getByRole('button', { name: 'Review archive' }).click();
      await page.locator('#lifecycle-dialog')
        .getByRole('button', { name: 'Archive', exact: true }).click();
      await targetRow().getByRole('button', { name: 'Remove permanently' }).click();
      await page.getByRole('button', { name: 'Review removal' }).click();
      const remove = page.locator('#lifecycle-dialog')
        .getByRole('button', { name: 'Remove permanently', exact: true });
      await page.locator('#lifecycle-confirm-phrase').getByText('PURGE SERVER alpha-001').waitFor();
      assert.equal(await remove.isDisabled(), true);
      await page.locator('#lifecycle-confirm').fill('PURGE SERVER alpha-00');
      assert.equal(await remove.isDisabled(), true, 'near matches must remain blocked');
      await page.locator('#lifecycle-confirm').fill('PURGE SERVER alpha-001');
      assert.equal(await remove.isEnabled(), true);
      await remove.click();
      await page.getByText('No archived servers yet.', { exact: true }).waitFor();
      assert.equal(await targetRow().count(), 0);
      assert.equal(await page.locator('#servers-archived-count').textContent(), '0',
        'zero is truthful only after the authoritative collection has loaded');
      assert.deepEqual(browserErrors, [],
        'the normal real-asset journey must produce no browser errors before maintenance');

      await page.locator('[data-lifecycle-filter="servers"] [data-lifecycle-view="active"]').click();
      await page.locator('#servers-body .proj-head').first().waitFor();

      // Planned broker maintenance is one calm, decision-oriented status.
      // Unrelated background collection failures must not replace it with
      // operator task text, false urgency, or a useless Retry action.
      maintenanceMode = true;
      await page.waitForTimeout(7_000);
      const maintenanceBanner = page.locator('#banner-slot .banner.maintenance');
      await assert.doesNotReject(async () => {
        await page.locator('#servers-body .proj-head').first().waitFor();
      });
      assert.equal(await maintenanceBanner.count(), 0,
        'retained inventory must not be covered by a global maintenance banner');
      assert.equal(await page.locator('.hdr-alert').count(), 0,
        'planned maintenance must not increment the needs-attention badge');
      assert.doesNotMatch(await page.locator('body').innerText(), /GlobalFinance|OKX collector|fresh runtime/);
      assert.ok(browserErrors.every(
        (message) => /status of 503 \(Service Unavailable\)/.test(message),
      ), 'any background maintenance response must be the expected bounded 503');
      browserErrors.length = 0;

      await page.setViewportSize({ width: 390, height: 844 });
      const horizontalOverflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      assert.ok(horizontalOverflow <= 1,
        `maintenance status must fit the mobile viewport (overflow ${horizontalOverflow}px)`);

      assert.deepEqual(unexpectedRequests, [], 'the rendered journey must use only declared API fixtures');
      assert.deepEqual(browserErrors, [], 'the real Console assets must produce no browser errors');
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });

test('lifecycle-disabled admin sessions never request archives or surface an authorization error',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-lifecycle-gate-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    let context;
    try {
      stack = await startStack({
        allowedEmails: ['operator@example.test'],
        claims: { email: 'operator@example.test', name: 'Fixture Operator' },
        coordinatorEnv: {
          PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH ?? ''}`,
        },
      });
      const jar = makeJar();
      const loginResult = await login(stack, jar);
      const sessionCookie = jar.get('dc_session');
      assert.equal(loginResult.status, 200);
      assert.ok(sessionCookie);

      browser = await launchChromium(
        chromium,
        [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
      );
      context = await browser.newContext({
        viewport: { width: 1135, height: 919 },
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'UTC',
        colorScheme: 'dark',
        reducedMotion: 'reduce',
      });
      await context.addCookies([{
        name: sessionCookie.name,
        value: sessionCookie.value,
        domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
        path: sessionCookie.path,
        secure: sessionCookie.secure,
        httpOnly: sessionCookie.httpOnly,
        sameSite: 'Lax',
      }]);

      const page = await context.newPage();
      const browserErrors = [];
      const unexpectedRequests = [];
      const lifecycleRequests = [];
      page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') browserErrors.push(`console: ${message.text()}`);
      });
      await page.route('**/api/**', async (route) => {
        const request = route.request();
        const pathname = new URL(request.url()).pathname;
        let body;
        if (pathname.startsWith('/api/lifecycle/')) {
          lifecycleRequests.push(`${request.method()} ${pathname}`);
          await route.fulfill({
            status: 403,
            contentType: 'application/json',
            body: '{"error":"The authenticated account is not authorized to read archives."}',
          });
          return;
        }
        if (request.method() === 'GET' && pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin: true, lifecycleAvailable: false };
        } else if (request.method() === 'GET' && pathname === '/api/access') {
          body = {
            version: 1,
            users: [{ email: CANONICAL_SESSION.email, owner: true, grants: [] }],
            resources: [],
            invitedCount: 0,
          };
        } else if (request.method() === 'GET' && pathname === '/api/access/requests') {
          body = { version: 1, pendingCount: 0, requests: [] };
        } else if (request.method() === 'GET' && pathname === '/api/telegram') {
          body = { version: 1, bots: [], projects: [] };
        } else if (request.method() === 'GET' && pathname === '/api/bugs') {
          body = { schema_version: 1, revision: 'fixture-empty-bugs', bugs: [] };
        } else if (request.method() === 'GET' && pathname === '/api/prefs') {
          body = CANONICAL_PREFS;
        } else if (request.method() === 'GET' && pathname === '/api/overview') {
          body = fixtureOverview(0);
        } else if (request.method() === 'GET' && pathname === '/api/metrics/history') {
          body = { ...CANONICAL_METRICS, host: null, entities: [] };
        } else {
          unexpectedRequests.push(`${request.method()} ${pathname}`);
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: '{"error":"unexpected browser fixture request"}',
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'cache-control': 'no-store' },
          body: JSON.stringify(body),
        });
      });

      const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
      await page.goto(`${origin}/#/docker`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelectorAll('#docker-body [data-fk^="dock-group:"]').length === 3
        && !document.querySelector('#docker-body .skel')
      )).catch(async (error) => {
        const body = String(await page.locator('body').innerText().catch(() => ''))
          .replace(/\s+/g, ' ').slice(0, 1000);
        throw new Error(
          `${error.message}\nbrowser errors: ${JSON.stringify(browserErrors)}`
          + `\nunexpected requests: ${JSON.stringify(unexpectedRequests)}`
          + `\nrendered body: ${body}`,
        );
      });

      const archived = page.locator(
        '[data-lifecycle-filter="docker"] [data-lifecycle-view="archived"]',
      );
      const active = page.locator(
        '[data-lifecycle-filter="docker"] [data-lifecycle-view="active"]',
      );
      assert.equal(await archived.isDisabled(), true,
        'Archived must remain visible but unavailable until lifecycle activation is complete');
      assert.equal(await archived.getAttribute('aria-disabled'), 'true');
      assert.equal(await archived.getAttribute('title'),
        'Archive management is not activated on this Console');
      assert.equal(await active.getAttribute('aria-pressed'), 'true');
      assert.equal(await page.locator('#banner-slot .banner').count(), 0,
        'the disabled feature must not surface a misleading archive authorization error');
      assert.deepEqual(lifecycleRequests, [],
        'the browser must never poll archive APIs when the server reports lifecycle unavailable');
      assert.deepEqual(unexpectedRequests, []);
      assert.deepEqual(browserErrors, []);
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });

test('Performance paints retained metrics within one second while current inventory is slow',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-performance-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    let context;
    try {
      stack = await startStack({
        allowedEmails: ['operator@example.test'],
        claims: { email: 'operator@example.test', name: 'Fixture Operator' },
        coordinatorEnv: { PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH ?? ''}` },
      });
      const jar = makeJar();
      assert.equal((await login(stack, jar)).status, 200);
      const sessionCookie = jar.get('dc_session');
      assert.ok(sessionCookie);

      browser = await launchChromium(
        chromium,
        [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
      );
      context = await browser.newContext({
        viewport: { width: 1135, height: 919 },
        ignoreHTTPSErrors: true,
        colorScheme: 'dark',
        reducedMotion: 'reduce',
      });
      await context.addCookies([{
        name: sessionCookie.name,
        value: sessionCookie.value,
        domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
        path: sessionCookie.path,
        secure: sessionCookie.secure,
        httpOnly: sessionCookie.httpOnly,
        sameSite: 'Lax',
      }]);
      await context.addInitScript(() => {
        window.__consoleLcp = 0;
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) window.__consoleLcp = Math.max(window.__consoleLcp, entry.startTime);
        }).observe({ type: 'largest-contentful-paint', buffered: true });
      });

      const page = await context.newPage();
      const unexpectedRequests = [];
      let appEncoding = null;
      page.on('response', (response) => {
        if (new URL(response.url()).pathname === '/app.js') {
          appEncoding = response.headers()['content-encoding'] || null;
        }
      });
      await page.route('**/api/**', async (route) => {
        const request = route.request();
        const pathname = new URL(request.url()).pathname;
        let body;
        if (pathname === '/api/overview') {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          body = CANONICAL_OVERVIEW;
        } else if (pathname === '/api/metrics/history') body = CANONICAL_METRICS;
        else if (pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin: false, lifecycleAvailable: false };
        } else if (pathname === '/api/prefs') body = CANONICAL_PREFS;
        else if (pathname === '/api/telegram') {
          body = { bots: [], pendingAuthorizations: [], authorizedChats: [] };
        } else if (pathname === '/api/bugs') {
          body = { schema_version: 1, revision: 'fixture-empty-bugs', bugs: [] };
        } else {
          unexpectedRequests.push(`${request.method()} ${pathname}`);
          body = {};
        }
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
      });

      // The product gate is for the cached Console shell. Establish the
      // same-origin TLS connection before timing the real application
      // navigation, while meaningful paint and LCP below still measure that
      // complete navigation and render.
      await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/healthz`, {
        waitUntil: 'domcontentloaded',
      });
      const startedAt = Date.now();
      await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/performance`, {
        waitUntil: 'domcontentloaded',
      });
      await page.locator('#perf-body .performance-dashboard').waitFor({ state: 'visible' });
      await page.locator('#perf-memory-chart').waitFor({ state: 'visible' });
      const meaningfulPaintMs = Date.now() - startedAt;
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const timing = await page.evaluate(() => ({
        ttfb: performance.getEntriesByType('navigation')[0]?.responseStart ?? Infinity,
        lcp: window.__consoleLcp,
      }));

      assert.ok(timing.ttfb < 100, `fixture document TTFB was ${timing.ttfb.toFixed(1)}ms`);
      assert.ok(meaningfulPaintMs < 1000,
        `Performance metrics became visible after ${meaningfulPaintMs}ms`);
      assert.ok(timing.lcp > 0 && timing.lcp < 1000,
        `fixture LCP was ${Number(timing.lcp).toFixed(1)}ms`);
      assert.equal(appEncoding, 'br', 'Chromium should receive the immutable app bundle over Brotli');
      await page.getByRole('link', { name: 'Test dashboards' }).waitFor({ state: 'visible' });
      assert.deepEqual(unexpectedRequests, []);
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
