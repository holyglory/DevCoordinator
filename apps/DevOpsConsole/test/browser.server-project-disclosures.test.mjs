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

function unassignedContainer() {
  return {
    ...container('/fixtures/unassigned', null, 'gnt-artifact-pg', 202),
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
} = {}) {
  const overview = structuredClone(CANONICAL_OVERVIEW);
  const alphaProject = '/fixtures/projects/alpha';
  const betaProject = '/fixtures/projects/beta';
  const alpha = Array.from({ length: 82 }, (_, index) => server(alphaProject, index + 1))
    .filter((item) => !archivedServerIds.has(item.id) && !removedServerIds.has(item.id));
  const beta = [server(betaProject, 1)];
  beta[0].name = 'smoke-caddy-http';
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

  overview.routes = [];
  overview.inventory.servers = [...alpha, ...beta];
  overview.inventory.port_assignments = [];
  overview.inventory.leases = [];
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
  };
  const unassigned = includeUnassigned ? unassignedContainer() : null;
  const dockerResources = [
    ...globalFinance, ...xfoil, dockerContainer, ...(unassigned ? [unassigned] : []),
  ];
  overview.inventory.docker = {
    available: true,
    error: null,
    stats_error: null,
    postgres: [{ database_binding_id: 'fixture-database-binding', name: dockerContainer.name }],
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
      repo_id: 'repo-global-finance', host_id: 'fixture-host',
      canonical_root: globalFinanceProject, display_name: 'GlobalFinance',
    },
    {
      repo_id: 'repo-xfoil', host_id: 'fixture-host',
      canonical_root: xfoilProject, display_name: 'XFoil',
    },
  ];
  overview.inventory.memberships = [
    ...globalFinance.map((item) => ({
      resource_kind: 'container', host_resource_id: item.host_resource_id,
      repo_id: 'repo-global-finance',
    })),
    ...xfoil.map((item) => ({
      resource_kind: 'container', host_resource_id: item.host_resource_id,
      repo_id: 'repo-xfoil',
    })),
    {
      resource_kind: 'container', host_resource_id: dockerContainer.host_resource_id,
      repo_id: 'repo-db',
    },
  ];
  overview.inventory.resources = {
    servers: [
      ...alpha.map((item) => ({ server_definition_id: item.id, repo_id: 'repo-alpha' })),
      ...beta.map((item) => ({ server_definition_id: item.id, repo_id: 'repo-beta-run' })),
    ],
    docker: dockerResources.map((item) => ({
      docker_resource_id: item.host_resource_id,
    })),
    databases: [{
      database_binding_id: 'fixture-database-binding',
      docker_resource_id: dockerContainer.host_resource_id,
      repo_id: 'repo-db',
      database_name: 'sample_api',
      lifecycle: 'running',
    }],
  };
  overview.inventory.observations = {
    docker: dockerResources.map((item) => ({
      docker_resource_id: item.host_resource_id,
    })),
    databases: [{ database_binding_id: 'fixture-database-binding' }],
  };
  overview.inventory.unassigned_resources = unassigned ? [{
    resource_kind: 'container', resource_id: unassigned.host_resource_id,
    display_name: unassigned.name,
    reason_code: unassigned.attribution.reason_code,
    explanation: unassigned.attribution.explanation,
    recommended_next_step: 'Attach this exact container to its original root repository, or retire it.',
  }] : [];
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
        database_binding_ids: ['fixture-database-binding'],
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
        key: `dock:${LONG_DOCKER_NAME}`,
        kind: 'docker',
        name: LONG_DOCKER_NAME,
        project: '/fixtures/projects/global-finance',
        points,
      },
    ],
  };
}

async function assertAdjacentCellsDoNotOverlap(leftCell, rightCell, message) {
  const boxes = await Promise.all([leftCell.boundingBox(), rightCell.boundingBox()]);
  assert.ok(boxes[0] && boxes[1], `${message}: both cells must be rendered`);
  assert.ok(boxes[0].x + boxes[0].width <= boxes[1].x, message);
}

async function assertElementsDoNotOverlap(first, second, message) {
  const [a, b] = await Promise.all([first.boundingBox(), second.boundingBox()]);
  assert.ok(a && b, `${message}: both elements must be rendered`);
  const overlapsX = a.x < b.x + b.width && b.x < a.x + a.width;
  const overlapsY = a.y < b.y + b.height && b.y < a.y + a.height;
  assert.equal(overlapsX && overlapsY, false, message);
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
      let maintenanceMode = false;
      const archivedServerIds = new Set();
      const removedServerIds = new Set();
      const restoredServerIds = new Set();
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
        else if (request.method() === 'GET' && pathname === '/api/prefs') body = CANONICAL_PREFS;
        else if (request.method() === 'GET' && pathname === '/api/overview') {
          overviewRequests += 1;
          if (maintenanceMode) {
            body = fixtureOverview(overviewRevision, {
              archivedServerIds, removedServerIds, restoredServerIds, includeUnassigned,
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
            });
          }
        } else if (request.method() === 'GET' && pathname === '/api/metrics/history') {
          body = fixtureMetrics();
        } else if (request.method() === 'POST' && pathname === '/api/docker/logs') {
          assert.equal(request.postDataJSON().name, 'gnt-artifact-pg');
          body = { text: '2026-07-21T06:55:05Z validation failed safely' };
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
        projectHead.locator('.c-status'), projectHead.locator('.actions'),
        'project running count must not be covered by lifecycle and runtime actions',
      );
      assert.equal(
        await page.locator('#projects-body .tree-head .proj-name', { hasText: 'Beta' }).count(),
        1,
        'one authoritative root repo must render as one top-level project',
      );
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
      await betaProjectToggle.click();
      assert.equal(
        await betaProjectBlock.getByText('No services registered directly under this root repo.').count(),
        1,
        'temporary services must not be flattened into the root repo member list',
      );
      const temporaryToggle = page.locator(
        '[data-fk="temporary-scope:path:/fixtures/projects/beta:repo-beta-run"]',
      );
      await temporaryToggle.waitFor();
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

      const dockerRow = globalFinanceBlock.locator('.row.dock-grid.expandable')
        .filter({ hasText: LONG_DOCKER_NAME });
      await dockerRow.waitFor();
      const nameCell = dockerRow.locator('[data-label="Container"]');
      const nameBox = await nameCell.boundingBox();
      assert.ok(nameBox && nameBox.width >= 220,
        'the reported intermediate viewport must reserve at least 220px for container names');
      const nameGeometry = await nameCell.locator('strong').evaluate((node) => {
        const style = getComputedStyle(node);
        const lineHeight = Number.parseFloat(style.lineHeight)
          || Number.parseFloat(style.fontSize) * 1.2;
        return { height: node.getBoundingClientRect().height, lineHeight };
      });
      assert.ok(nameGeometry.height <= nameGeometry.lineHeight * 5,
        'the long container name must not collapse into one character per line');
      await assertElementsDoNotOverlap(
        dockerRow.locator('[data-label="Ports"]'), dockerRow.locator('.actions'),
        'Docker port mappings must not be covered by lifecycle and runtime actions',
      );
      assert.equal(
        await globalFinanceBlock.evaluate((node) => node.scrollWidth <= node.clientWidth),
        true,
        'the intermediate Docker layout must remain inside its project block',
      );
      assert.match(
        await dockerRow.locator('[data-label="CPU / Mem"] button').getAttribute('aria-label'),
        /CPU 1\.1%, memory 46\.0 MiB/,
        'a running Docker row must expose its observed CPU and memory utilization',
      );

      // Exercise the exact reported 319px width with real SVG history
      // sparklines. The previous 390px/empty-metrics fixture could not detect
      // a fixed-width chart escaping a stacked Docker card.
      for (const width of [319, 390]) {
        await page.setViewportSize({ width, height: width === 319 ? 1804 : 844 });
        await page.waitForFunction(() => matchMedia('(max-width: 719px)').matches);

        const headerGeometry = await globalFinanceToggle.evaluate((toggleNode) => {
          const tolerance = 1;
          const outer = toggleNode.getBoundingClientRect();
          const name = toggleNode.querySelector('.proj-name');
          const nameRect = name.getBoundingClientRect();
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
            nameWidth: nameRect.width,
            nameLines: nameRect.height / lineHeight,
            escaping,
            visibleHeaderSparks: visibleParts.filter((node) => node.matches('.spark')).length,
          };
        });
        assert.ok(headerGeometry.nameWidth >= 96,
          `${width}px Docker project names must retain a readable track`);
        assert.ok(headerGeometry.nameLines <= 2.1,
          `${width}px Docker project names must not collapse into one character per line`);
        assert.deepEqual(headerGeometry.escaping, [],
          `${width}px Docker project summary content must stay inside its disclosure`);
        assert.ok(headerGeometry.scrollWidth <= headerGeometry.clientWidth,
          `${width}px Docker project disclosures must not overflow horizontally`);
        assert.equal(headerGeometry.visibleHeaderSparks, 0,
          `${width}px Docker project summaries must hide the redundant inline sparkline`);

        const rowGeometry = await dockerRow.evaluate((rowNode) => {
          const tolerance = 1;
          const row = rowNode.getBoundingClientRect();
          const blockNode = rowNode.closest('.docker-project-block');
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
          const nameStyle = getComputedStyle(name);
          const nameLineHeight = Number.parseFloat(nameStyle.lineHeight)
            || Number.parseFloat(nameStyle.fontSize) * 1.2;
          const nameRect = name.getBoundingClientRect();
          return {
            rowClientWidth: rowNode.clientWidth,
            rowScrollWidth: rowNode.scrollWidth,
            blockClientWidth: blockNode.clientWidth,
            blockScrollWidth: blockNode.scrollWidth,
            nameLines: nameRect.height / nameLineHeight,
            escaping,
          };
        });
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

      // A producer-reported ownership problem is a global lifecycle fence,
      // not another actionable pseudo-project. The exact diagnosis and repair
      // replace every stale control, then normal rendering recovers after the
      // authoritative inventory is corrected.
      includeUnassigned = true;
      overviewRevision += 1;
      await page.reload({ waitUntil: 'networkidle' });
      const assignmentError = page.locator('#docker-body .repository-inventory-error');
      await assignmentError.waitFor();
      assert.match(await assignmentError.textContent(),
        /Repository assignment is incomplete.*gnt-artifact-pg.*only its name—not a repository path—was observed.*Attach this exact container to its original root repository, or retire it/is);
      assert.equal(await page.locator('#docker-body .docker-project-block').count(), 0,
        'no repository lifecycle target may survive an ownership error');
      assert.equal(await page.locator('#docker-body button').count(), 0,
        'the blocking diagnosis must expose no stale lifecycle mutation');

      includeUnassigned = false;
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
          escaping,
        };
      });
      assert.ok(betaGeometry.nameTrackWidth >= 180,
        '787px Servers rows must reserve at least 180px for the server identity');
      assert.ok(betaGeometry.nameLines <= 2.1,
        'the server name must not collapse into one character per line');
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
          return {
            height: row.height,
            rowClientWidth: rowNode.clientWidth,
            rowScrollWidth: rowNode.scrollWidth,
            blockClientWidth: blockNode.clientWidth,
            blockScrollWidth: blockNode.scrollWidth,
            labelDisplays,
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
        } else {
          unexpectedRequests.push(`${request.method()} ${pathname}`);
          body = {};
        }
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
      });

      const startedAt = Date.now();
      await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/performance`, {
        waitUntil: 'domcontentloaded',
      });
      await page.locator('#perf-body .perf-card').first().waitFor({ state: 'visible' });
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

test('Tests loads repository data within one second while current inventory is slow',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-tests-performance-');
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
        viewport: { width: 1486, height: 1059 },
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

      const page = await context.newPage();
      let overviewCompleted = false;
      let testsStartedBeforeOverview = false;
      let testsMaintenance = false;
      const utcDay = (offset) => {
        const date = new Date();
        date.setUTCHours(0, 0, 0, 0);
        date.setUTCDate(date.getUTCDate() + offset);
        return date.toISOString().slice(0, 10);
      };
      const hourly = Array.from({ length: 7 }, (_, dayIndex) => (
        Array.from({ length: 24 }, (_, hour) => ({
          day: utcDay(dayIndex - 6),
          hour,
          test_seconds: [0, 720, 1_800, 3_600, 5_400, 7_200, 10_800][
            (dayIndex * 3 + hour) % 7
          ],
          failure_count: (dayIndex + hour) % 19 === 0 ? 1 : 0,
        }))
      )).flat();
      const daily = Array.from({ length: 30 }, (_, index) => ({
        day: utcDay(index - 29),
        test_seconds: 7_200 + ((index * 2_137) % 18_000),
      }));
      const previousDaily = Array.from({ length: 30 }, (_, index) => ({
        day: utcDay(index - 59),
        test_seconds: 6_400 + ((index * 1_743) % 14_000),
      }));
      const testStats = {
        schema_version: 1,
        repo_id: 'repo-tests',
        days: 30,
        summary: {
          test_count: 12,
          run_count: 2,
          run_seconds: 4,
          test_seconds: 10_800,
          passed_count: 10,
          failed_count: 2,
          error_count: 0,
          running_count: 0,
          failed_run_count: 1,
        },
        comparison_summary: { test_seconds: 7_200 },
        hourly,
        daily,
        previous_daily: previousDaily,
        dynamics: [
          ['visual-regression', 48_600, 32_400, 50, 2],
          ['integration', 37_800, 46_200, -18.2, 0],
          ['unit', 28_200, 25_800, 9.3, 1],
          ['lint-and-contracts', 12_900, 18_300, -29.5, 0],
        ].map(([suite, current_seconds, previous_seconds, change_percent, failure_count]) => ({
          suite,
          current_seconds,
          previous_seconds,
          change_percent,
          failure_count,
          last_run: `${utcDay(-1)}T11:30:00Z`,
        })),
      };
      await page.route('**/api/**', async (route) => {
        const pathname = new URL(route.request().url()).pathname;
        let body;
        let status = 200;
        if (pathname === '/api/overview') {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          overviewCompleted = true;
          body = CANONICAL_OVERVIEW;
        } else if (pathname === '/api/tests/repositories') {
          // Prove the rolling-deployment fallback works against the currently
          // running Console process before its new backend endpoint is active.
          status = 404;
          body = { error: 'not found' };
        } else if (pathname === '/api/tests') {
          testsStartedBeforeOverview = !overviewCompleted;
          if (testsMaintenance) {
            status = 503;
            body = {
              error: 'Controls are updating',
              code: 'maintenance_in_progress',
              classification: 'maintenance',
              retry_after_seconds: 30,
            };
          } else {
            body = testStats;
          }
        } else if (pathname === '/api/metrics/history') body = CANONICAL_METRICS;
        else if (pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin: false, lifecycleAvailable: false };
        } else if (pathname === '/api/prefs') body = CANONICAL_PREFS;
        else if (pathname === '/api/telegram') {
          body = { bots: [], pendingAuthorizations: [], authorizedChats: [] };
        } else body = {};
        await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
      });

      const startedAt = Date.now();
      await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/tests`, {
        waitUntil: 'domcontentloaded',
      });
      await page.getByRole('heading', { name: 'Testing time by hour' }).waitFor({ state: 'visible' });
      const meaningfulPaintMs = Date.now() - startedAt;

      assert.ok(meaningfulPaintMs < 1000,
        `Tests data became visible after ${meaningfulPaintMs}ms`);
      assert.equal(testsStartedBeforeOverview, true,
        'Tests must request repository statistics before heavyweight inventory completes');
      assert.equal(await page.locator('#tests-project option').count(), 1);
      assert.equal(await page.locator('#tests-pass-rate').textContent(), '83.3%');
      assert.equal(await page.locator('#tests-failed-runs').textContent(), '1');
      assert.ok(await page.locator('.test-heat-cell.has-failure').count() > 0);
      assert.match(await page.locator('.test-heat-cell').nth(6).getAttribute('title'), /180\.0 aggregate test-minutes/);
      await page.locator('.test-heat-cell').nth(6).hover();
      const desktopTooltip = page.locator('#test-heat-tooltip');
      await desktopTooltip.waitFor({ state: 'visible' });
      assert.match(await desktopTooltip.textContent(), /180\.0 test-min/);
      assert.match(await desktopTooltip.textContent(), /10800 aggregate seconds/);
      const desktopTooltipGeometry = await desktopTooltip.evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return { left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom };
      });
      assert.ok(desktopTooltipGeometry.left >= 0
        && desktopTooltipGeometry.right <= 1486
        && desktopTooltipGeometry.top >= 0
        && desktopTooltipGeometry.bottom <= 1059,
      'the exact-value hover badge must stay inside the desktop viewport');
      const desktopGeometry = await page.evaluate(() => ({
        viewportWidth: window.innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        sections: [...document.querySelectorAll('#tests-body > section, #tests-body > div')].map((node) => {
          const rect = node.getBoundingClientRect();
          return { left: rect.left, right: rect.right };
        }),
        overflowers: [...document.querySelectorAll('body *')].flatMap((node) => {
          const rect = node.getBoundingClientRect();
          return rect.right > window.innerWidth + 1
            ? [{ tag: node.tagName, className: node.className?.baseVal ?? node.className, right: rect.right }]
            : [];
        }).slice(0, 12),
      }));
      if (process.env.TESTS_DESIGN_SCREENSHOT) {
        await page.screenshot({ path: process.env.TESTS_DESIGN_SCREENSHOT, fullPage: true });
      }
      assert.ok(desktopGeometry.documentWidth <= desktopGeometry.viewportWidth,
        `Tests dashboard overflowed desktop by ${desktopGeometry.documentWidth - desktopGeometry.viewportWidth}px: ${JSON.stringify(desktopGeometry.overflowers)}`);
      assert.ok(desktopGeometry.sections.every((section) => (
        section.left >= 0 && section.right <= desktopGeometry.viewportWidth
      )), 'every Tests panel must stay inside the desktop viewport');

      await page.setViewportSize({ width: 981, height: 964 });
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const narrowGeometry = await page.evaluate(() => {
        const heatScroll = document.querySelector('.test-heat-scroll');
        return {
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth: window.innerWidth,
          heatClientWidth: heatScroll?.clientWidth,
          heatScrollWidth: heatScroll?.scrollWidth,
          summaryDisplay: getComputedStyle(document.querySelector('.test-summary')).display,
          compactSummaryDisplay: getComputedStyle(document.querySelector('.test-summary-compact')).display,
        };
      });
      assert.ok(narrowGeometry.documentWidth <= narrowGeometry.viewportWidth,
        'the annotated 981px Tests layout must not overflow');
      assert.ok(narrowGeometry.heatScrollWidth <= narrowGeometry.heatClientWidth,
        'the annotated 981px heatmap must not have a horizontal scrollbar');
      assert.equal(narrowGeometry.summaryDisplay, 'none',
        'the right summary panel must not consume narrow-screen space');
      assert.notEqual(narrowGeometry.compactSummaryDisplay, 'none',
        'the narrow-screen heatmap must preserve its summary facts');
      if (process.env.TESTS_DESIGN_NARROW_SCREENSHOT) {
        await page.screenshot({ path: process.env.TESTS_DESIGN_NARROW_SCREENSHOT, fullPage: true });
      }

      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForFunction(() => window.innerWidth === 390 && (
        [...document.querySelectorAll('.test-heat-hour')]
          .filter((node) => getComputedStyle(node).visibility === 'visible').length === 12
      ));
      const mobileGeometry = await page.evaluate(() => {
        const heatScroll = document.querySelector('.test-heat-scroll');
        const heatRect = heatScroll?.getBoundingClientRect();
        return {
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          heatScroll: heatScroll ? {
            left: heatRect.left,
            right: heatRect.right,
            clientWidth: heatScroll.clientWidth,
            scrollWidth: heatScroll.scrollWidth,
          } : null,
          heatmap: document.querySelector('.test-heatmap')?.getBoundingClientRect().toJSON(),
          summaryDisplay: getComputedStyle(document.querySelector('.test-summary')).display,
          compactSummaryDisplay: getComputedStyle(document.querySelector('.test-summary-compact')).display,
          visibleHourLabels: [...document.querySelectorAll('.test-heat-hour')]
            .filter((node) => getComputedStyle(node).visibility === 'visible').length,
        };
      });
      assert.ok(mobileGeometry.documentWidth <= mobileGeometry.viewportWidth,
        `Tests dashboard overflowed mobile by ${mobileGeometry.documentWidth - mobileGeometry.viewportWidth}px`);
      assert.ok(mobileGeometry.heatScroll);
      assert.ok(mobileGeometry.heatScroll.left >= 0
        && mobileGeometry.heatScroll.right <= mobileGeometry.viewportWidth,
      'the heatmap viewport must stay on screen');
      assert.ok(mobileGeometry.heatScroll.scrollWidth <= mobileGeometry.heatScroll.clientWidth,
        'the 24-hour heatmap must fit without a nested horizontal scrollbar');
      assert.ok(mobileGeometry.heatmap.left >= mobileGeometry.heatScroll.left
        && mobileGeometry.heatmap.right <= mobileGeometry.heatScroll.right + 1,
      'the heatmap table must fit inside its panel');
      assert.equal(mobileGeometry.summaryDisplay, 'none',
        'the separate summary panel must be removed on narrow screens');
      assert.notEqual(mobileGeometry.compactSummaryDisplay, 'none',
        'narrow screens must retain summary facts in a compact strip');
      assert.equal(mobileGeometry.visibleHourLabels, 12,
        'mobile should label every other hour while retaining all 24 data cells');
      await page.locator('.test-heat-cell').nth(23).hover();
      const mobileTooltipGeometry = await page.locator('#test-heat-tooltip').evaluate((node) => {
        const rect = node.getBoundingClientRect();
        return {
          hidden: node.hidden,
          left: rect.left,
          right: rect.right,
          top: rect.top,
          bottom: rect.bottom,
          text: node.textContent,
        };
      });
      assert.equal(mobileTooltipGeometry.hidden, false);
      assert.match(mobileTooltipGeometry.text, /aggregate seconds/);
      assert.ok(mobileTooltipGeometry.left >= 0
        && mobileTooltipGeometry.right <= 390
        && mobileTooltipGeometry.top >= 0
        && mobileTooltipGeometry.bottom <= 844,
      'the right-edge hover badge must clamp inside the mobile viewport');

      await page.setViewportSize({ width: 320, height: 844 });
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const smallMobileGeometry = await page.evaluate(() => {
        const heatScroll = document.querySelector('.test-heat-scroll');
        return {
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          heatClientWidth: heatScroll?.clientWidth,
          heatScrollWidth: heatScroll?.scrollWidth,
          visibleHourLabels: [...document.querySelectorAll('.test-heat-hour')]
            .filter((node) => getComputedStyle(node).visibility === 'visible').length,
        };
      });
      assert.ok(smallMobileGeometry.documentWidth <= smallMobileGeometry.viewportWidth,
        'the Tests dashboard must fit a 320px mobile viewport');
      assert.ok(smallMobileGeometry.heatScrollWidth <= smallMobileGeometry.heatClientWidth,
        'the heatmap must not scroll at 320px');
      assert.equal(smallMobileGeometry.visibleHourLabels, 4,
        'small mobile should label six-hour intervals while retaining all 24 data cells');
      if (process.env.TESTS_DESIGN_MOBILE_SCREENSHOT) {
        await page.screenshot({ path: process.env.TESTS_DESIGN_MOBILE_SCREENSHOT, fullPage: true });
      }

      testsMaintenance = true;
      const maintenanceResponse = page.waitForResponse((response) => (
        new URL(response.url()).pathname === '/api/tests' && response.status() === 503
      ));
      await page.locator('#tests-days').selectOption('7');
      await maintenanceResponse;
      assert.equal(await page.locator('#banner-slot .banner').count(), 0,
        'planned test-data maintenance must not create a non-actionable text badge');
      assert.doesNotMatch(await page.locator('body').innerText(),
        /No action needed|nothing is required from (?:the )?user|running services stay online/i);
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
