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

function fixtureOverview(revision, { archivedServerIds = new Set(), removedServerIds = new Set(), restoredServerIds = new Set() } = {}) {
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
  const unassigned = unassignedContainer();
  overview.inventory.docker = {
    available: true,
    error: null,
    stats_error: null,
    postgres: [{ name: unassigned.name }],
    containers: [...globalFinance, ...xfoil, unassigned],
  };
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
          body = fixtureOverview(overviewRevision, {
            archivedServerIds, removedServerIds, restoredServerIds,
          });
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
      await projectHead.waitFor();
      await assertAdjacentCellsDoNotOverlap(
        projectHead.locator('.c-status'), projectHead.locator('.actions'),
        'project running count must not be covered by lifecycle and runtime actions',
      );

      await page.goto(`${origin}/#/docker`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelectorAll('#docker-body [data-fk^="dock-group:"]').length === 3
        && !document.querySelector('#docker-body .skel')
      ));
      const globalFinanceKey = 'dock-group:path:/fixtures/projects/global-finance';
      const xfoilKey = 'dock-group:path:/fixtures/projects/xfoil';
      const unassignedKey = 'dock-group:other';
      const globalFinanceToggle = page.locator(`[data-fk="${globalFinanceKey}"]`);
      const xfoilToggle = page.locator(`[data-fk="${xfoilKey}"]`);
      const unassignedToggle = page.locator(`[data-fk="${unassignedKey}"]`);
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

      await unassignedToggle.click();
      assert.equal(await xfoilToggle.getAttribute('aria-expanded'), 'false');
      assert.equal(await unassignedToggle.getAttribute('aria-expanded'), 'true');
      const unassignedBlock = page.locator('.docker-project-block').filter({ has: unassignedToggle });
      const unassignedRow = unassignedBlock.locator('.row.dock-grid[data-ownership="unverified"]');
      await unassignedRow.waitFor();
      assert.equal(await unassignedRow.getAttribute('data-lifecycle-target'), null,
        'unverified ownership must not become an Archive target in the browser');
      assert.match(await unassignedRow.locator('.ownership-warning').textContent(),
        /Ownership not verified.*only its name—not a repository path—was observed.*attach it to a verified project or retire it as a standalone resource/is,
        'the affected row must explain the exact coordinator reason and available repair journeys');
      for (const action of ['Restart', 'Stop', 'Archive']) {
        const button = unassignedRow.getByRole('button', {
          name: new RegExp(`^${action} unavailable`),
        });
        assert.equal(await button.isDisabled(), true,
          `${action} must fail closed while container ownership is unverified`);
      }
      const logs = unassignedRow.getByRole('button', { name: 'Logs' });
      assert.equal(await logs.isEnabled(), true, 'read-only container logs must remain available');
      await logs.click();
      await unassignedBlock.getByText('validation failed safely').waitFor();

      await page.setViewportSize({ width: 319, height: 900 });
      const ownershipGeometry = await unassignedRow.evaluate((rowNode) => {
        const row = rowNode.getBoundingClientRect();
        const note = rowNode.querySelector('.ownership-warning').getBoundingClientRect();
        return {
          rowClientWidth: rowNode.clientWidth,
          rowScrollWidth: rowNode.scrollWidth,
          noteInside: note.left >= row.left - 1 && note.right <= row.right + 1,
        };
      });
      assert.equal(ownershipGeometry.noteInside, true,
        'the ownership explanation must remain inside the narrow Docker card');
      assert.ok(ownershipGeometry.rowScrollWidth <= ownershipGeometry.rowClientWidth,
        'the unassigned row must not create hidden horizontal overflow');
      await page.setViewportSize({ width: 1135, height: 919 });

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
      ));

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
