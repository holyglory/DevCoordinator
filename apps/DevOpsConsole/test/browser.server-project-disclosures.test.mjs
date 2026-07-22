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

function fixtureOverview(revision, { archivedServerIds = new Set(), removedServerIds = new Set(), restoredServerIds = new Set() } = {}) {
  const overview = structuredClone(CANONICAL_OVERVIEW);
  const alphaProject = '/fixtures/projects/alpha';
  const betaProject = '/fixtures/projects/beta';
  const alpha = Array.from({ length: 82 }, (_, index) => server(alphaProject, index + 1))
    .filter((item) => !archivedServerIds.has(item.id) && !removedServerIds.has(item.id));
  const beta = [server(betaProject, 1)];
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
  const dockerContainer = {
    ...structuredClone(CANONICAL_OVERVIEW.inventory.docker.containers[0]),
    host_resource_id: 'fixture-container-sample-api-db',
    repo_id: 'repo-db',
    project: '/fixtures/projects/db',
    compose_project: 'sample-api',
  };
  overview.inventory.docker = {
    available: true,
    error: null,
    stats_error: null,
    postgres: [{ name: dockerContainer.name }],
    containers: [dockerContainer],
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
      usage_key: 'path:/fixtures/projects/db',
      project_key: 'db',
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
  return overview;
}

async function assertAdjacentCellsDoNotOverlap(leftCell, rightCell, message) {
  const boxes = await Promise.all([leftCell.boundingBox(), rightCell.boundingBox()]);
  assert.ok(boxes[0] && boxes[1], `${message}: both cells must be rendered`);
  assert.ok(boxes[0].x + boxes[0].width <= boxes[1].x, message);
}

async function expandedCount(page) {
  return page.locator('#servers-body .server-project-toggle').evaluateAll(
    (buttons) => buttons.filter((button) => button.getAttribute('aria-expanded') === 'true').length,
  );
}

async function activeFocusKey(page) {
  return page.evaluate(() => document.activeElement?.getAttribute('data-fk') || null);
}

test('real Servers UI keeps project disclosures exclusive, persistent, focused, and losslessly paged',
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
        viewport: { width: 1280, height: 900 },
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
          body = { ...CANONICAL_SESSION, accessAdmin: true };
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
          body = { ...CANONICAL_METRICS, host: null, entities: [] };
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
      const dockerRow = page.locator('#docker-body .row.dock-grid.expandable').first();
      await dockerRow.waitFor();
      await assertAdjacentCellsDoNotOverlap(
        dockerRow.locator('[data-label="Ports"]'), dockerRow.locator('.actions'),
        'Docker port mappings must not be covered by lifecycle and runtime actions',
      );
      assert.match(
        await dockerRow.locator('[data-label="CPU / Mem"] button').getAttribute('aria-label'),
        /CPU 1\.1%, memory 46\.0 MiB/,
        'a running Docker row must expose its observed CPU and memory utilization',
      );

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
