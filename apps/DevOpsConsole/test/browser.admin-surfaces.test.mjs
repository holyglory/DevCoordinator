// Full real-browser route and owner-journey gate. The shipped Console assets
// run through the real HTTPS/session stack while every API dependency is a
// populated deterministic Playwright fixture. It verifies every destination
// without touching a live project, Telegram bot, lifecycle target or port.

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
const SYNTHETIC_TELEGRAM_TOKEN = 'fixture-telegram-token';

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
        throw new Error(
          `Playwright ${manifest.version} does not match locked ${locked.dependencies.playwright}`,
        );
      }
      return require(path.join(root, 'playwright'));
    } catch (error) {
      if (String(error.message).includes('does not match locked')) throw error;
    }
  }
  throw new Error(
    'locked Playwright runtime not found; run npm ci --ignore-scripts '
    + '--prefix ci/playwright and set NODE_PATH=ci/playwright/node_modules',
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
          process.env.PROGRAMFILES
            && path.join(process.env.PROGRAMFILES, 'Google/Chrome/Application/chrome.exe'),
          process.env['PROGRAMFILES(X86)']
            && path.join(
              process.env['PROGRAMFILES(X86)'],
              'Google/Chrome/Application/chrome.exe',
            ),
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
      return await chromium.launch({
        headless: true,
        args,
        ...attempt.options,
      });
    } catch (error) {
      failures.push(`${attempt.name}: ${String(error.message).split('\n')[0]}`);
    }
  }
  throw new Error(`could not launch a real Chromium browser:\n${failures.join('\n')}`);
}

async function writeEmptyDockerFixture(directory) {
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

function accessFixture() {
  const resources = Array.from({ length: 8 }, (_, index) => ({
    id: index === 0 ? 'console' : `route:fixture-${index}`,
    host: index === 0 ? 'console.vr.ae' : `fixture-${index}.vr.ae`,
    title: index === 0 ? 'DevOps Console' : `Fixture route ${index}`,
    target: index === 0
      ? 'Full server, Docker, route and port control'
      : `web · /fixtures/projects/service-${index}`,
    auth: index === 7 ? 'public' : 'google',
  }));
  const invited = Array.from({ length: 9 }, (_, index) => ({
    email: `viewer-${String(index + 1).padStart(2, '0')}@example.test`,
    owner: false,
    grants: index % 2 === 0 ? [resources[(index % 7) + 1].id] : [],
  }));
  return {
    version: 2,
    users: [
      { email: CANONICAL_SESSION.email, owner: true, grants: [] },
      ...invited,
    ],
    resources,
    invitedCount: invited.length,
  };
}

function inviteFixture() {
  const pending = Array.from({ length: 2 }, (_, index) => ({
    id: `invite-pending-${index + 1}`,
    email: `requester-${index + 1}@example.test`,
    resource: index === 0 ? 'console' : 'route:fixture-1',
    host: index === 0 ? 'console.vr.ae' : 'fixture-1.vr.ae',
    title: index === 0 ? 'DevOps Console' : 'Fixture route 1',
    target: index === 0
      ? 'Full server, Docker, route and port control'
      : 'web · /fixtures/projects/service-1',
    status: 'pending',
    requestedAt: `2026-07-28T10:0${index}:00.000Z`,
  }));
  const resolved = Array.from({ length: 7 }, (_, index) => ({
    id: `invite-resolved-${index + 1}`,
    email: `resolved-${index + 1}@example.test`,
    resource: 'route:fixture-2',
    host: 'fixture-2.vr.ae',
    title: 'Fixture route 2',
    target: 'web · /fixtures/projects/service-2',
    status: index % 2 === 0 ? 'approved' : 'denied',
    requestedAt: `2026-07-27T09:0${index}:00.000Z`,
    resolvedAt: `2026-07-27T09:1${index}:00.000Z`,
    resolvedBy: CANONICAL_SESSION.email,
  }));
  return { version: 2, requests: [...pending, ...resolved] };
}

function telegramProjects() {
  return Array.from({ length: 8 }, (_, index) => ({
    id: `repo-fixture-${index + 1}`,
    name: `Fixture project ${index + 1}`,
    path: `/fixtures/projects/service-${index + 1}`,
  }));
}

function registeredTelegramFixture(projects) {
  return {
    version: 1,
    registeredBotId: 'fixture-bot-operations',
    projects,
    bots: [{
      id: 'fixture-bot-operations',
      label: 'Operations fixture',
      ownerEmail: CANONICAL_SESSION.email,
      username: 'fixture_operations_bot',
      enabled: true,
      projectIds: [projects[0].id],
      hasToken: true,
      authorizations: [
        {
          id: 'telegram-auth-pending',
          firstName: 'Avery',
          lastName: 'Fixture',
          username: 'avery_fixture',
          telegramUserId: '700000001',
          status: 'pending',
          requestedAt: '2026-07-28T10:20:00.000Z',
        },
        {
          id: 'telegram-auth-approved',
          firstName: 'River',
          username: 'river_fixture',
          telegramUserId: '700000002',
          status: 'approved',
          requestedAt: '2026-07-27T10:20:00.000Z',
        },
      ],
    }],
  };
}

function archiveFixture() {
  return Array.from({ length: 4 }, (_, index) => ({
    target_kind: 'server',
    target_id: `fixture-archived-server-${index + 1}`,
    display_name: `archived-worker-${index + 1}`,
    project_id: 'fixture-repo-sample-api',
    project_display_name: 'Sample API',
    archived_at: `2026-07-28T08:0${index}:00.000Z`,
    reason: index === 0 ? 'Repeated crash investigation' : 'Browser lifecycle fixture',
    actor: `devops-console:${CANONICAL_SESSION.email}`,
    status: 'archived',
    restorable: true,
    removable: index !== 0,
    effects: ['Stopped and fenced from automatic restart'],
    retained: ['Operation history', 'Crash and log evidence'],
    blockers: [],
  }));
}

function testHourStarts() {
  const end = new Date();
  end.setUTCMinutes(0, 0, 0);
  return Array.from({ length: 24 }, (_, index) => (
    new Date(end.getTime() - ((23 - index) * 3_600_000)).toISOString()
  ));
}

function testRepositoriesFixture() {
  return [
    {
      repo_id: 'fixture-repo-sample-api',
      canonical_root: '/fixtures/projects/sample-api',
      display_name: 'Sample API',
    },
    {
      repo_id: 'fixture-repo-sample-api-preview',
      canonical_root: '/fixtures/worktrees/sample-api-preview',
      display_name: 'Sample API preview',
    },
  ];
}

function testFleetFixture() {
  const hours = testHourStarts();
  const repositories = testRepositoriesFixture().map((repository, repositoryIndex) => ({
    ...repository,
    state: 'healthy',
    last_activity_at: new Date().toISOString(),
    summary: {
      test_count: 1_280 - (repositoryIndex * 320),
      test_seconds: 21_600 - (repositoryIndex * 7_200),
      wall_seconds: 3_600,
      parallel_efficiency_ratio: repositoryIndex === 0 ? 6 : 4,
      pass_rate: 1,
      p95_queue_wait_seconds: 4 + repositoryIndex,
    },
    hourly: hours.map((hour_start, index) => ({
      hour_start,
      test_seconds: index % (repositoryIndex + 3) === 0 ? 2_700 : 180,
      test_count: index % (repositoryIndex + 3) === 0 ? 160 : 12,
      failure_count: 0,
    })),
  }));
  return {
    schema_version: 2,
    window: { hours: 24, start: hours[0], end: hours.at(-1), timezone: 'UTC' },
    snapshot: {
      generated_at: new Date().toISOString(),
      observed_through: new Date().toISOString(),
      source: 'console-route-smoke-fixture',
    },
    summary: {
      repository_count: repositories.length,
      repositories_with_activity: repositories.length,
      run_count: 36,
      running_count: 2,
      test_count: 2_240,
      test_seconds: 36_000,
      wall_seconds: 7_200,
      parallel_efficiency_ratio: 5,
      p95_queue_wait_seconds: 5,
      passed_count: 2_240,
      failure_count: 0,
      pass_rate: 1,
      flaky_test_count: 0,
      flake_rate: 0,
      avoided_work: { available: true, test_count: 420, test_seconds: 1_800 },
    },
    hours,
    repositories,
    capacity: hours.map((hour_start, index) => ({
      hour_start,
      test_seconds: index % 3 === 0 ? 5_400 : 360,
      test_count: index % 3 === 0 ? 320 : 24,
      failure_count: 0,
      active_repository_count: 2,
      p95_queue_wait_seconds: 5,
    })),
    attention: [],
  };
}

function testStatsFixture(repoId) {
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const daily = Array.from({ length: 7 }, (_, index) => ({
    day: new Date(today.getTime() - ((6 - index) * 86_400_000)).toISOString().slice(0, 10),
    test_seconds: 3_600 + (index * 180),
    run_seconds: 900,
    passed_count: 180 + index,
    failure_count: 0,
    flaky_test_count: 0,
  }));
  return {
    schema_version: 1,
    repo_id: repoId,
    days: 30,
    summary: {
      test_count: 1_280,
      run_count: 18,
      run_seconds: 7_200,
      test_seconds: 36_000,
      passed_count: 1_280,
      failed_count: 0,
      error_count: 0,
      running_count: 1,
      failed_run_count: 0,
      p95_queue_wait_seconds: 5,
    },
    comparison_summary: { test_seconds: 31_000 },
    hourly: [],
    daily,
    previous_daily: daily.map((row) => ({ ...row, test_seconds: row.test_seconds - 240 })),
    dynamics: [{
      suite: 'API integration', current_seconds: 1_240, previous_seconds: 1_160,
      change_percent: 6.9, failure_count: 0, last_run: new Date().toISOString(),
    }],
    health: { pass_rate: 1, flake_rate: 0 },
    efficiency: { parallel_efficiency_ratio: 5, p95_queue_wait_seconds: 5 },
    avoided_work: { available: true, test_count: 420 },
  };
}

function testSetupFixture(repoId) {
  return {
    schema_version: 1,
    repo_id: repoId,
    status: 'ready',
    manifest_schema: 2,
    manifest_fingerprint: 'a'.repeat(64),
    targets: [
      { name: 'unit', depends_on: [], network: 'none', fixtures: [] },
      { name: 'integration', depends_on: ['unit'], network: 'loopback', fixtures: [] },
    ],
    capability_policy: { requested: ['network.loopback'], missing: [] },
    evidence_policies: { handoff: 'Exact immutable source and all required targets pass.' },
    fixtures: {},
  };
}

function populatedOverview(stack) {
  const overview = structuredClone(CANONICAL_OVERVIEW);
  overview.console = {
    ...overview.console,
    domain: 'vr.ae',
    consoleHost: stack.consoleHost,
    consoleOrigin: `https://${stack.consoleHost}:${stack.httpsPort}`,
  };
  const expiry = Math.floor(Date.now() / 1000) + 3_600;
  overview.inventory.leases = [{
    id: 'fixture-lease-preview',
    port: 3456,
    purpose: 'UI preview',
    project: '/fixtures/projects/sample-api',
    agent: 'fixture-agent',
    expires_at: expiry,
    expires_at_iso: new Date(expiry * 1000).toISOString(),
  }];
  overview.inventory.port_assignments = overview.inventory.port_assignments.map((assignment) => ({
    ...assignment,
    key: `${assignment.project}::${assignment.name}`,
    created_at: '2026-01-15T11:00:00.000Z',
    server_status: 'running',
  }));
  return overview;
}

function populatedMetrics() {
  const metrics = structuredClone(CANONICAL_METRICS);
  metrics.host = {
    cpuPercent: 32.5,
    cores: 8,
    load: [1.2, 1.1, 0.9],
    mem: {
      usedBytes: 8_589_934_592,
      totalBytes: 34_359_738_368,
      availableBytes: 25_769_803_776,
    },
    disks: [{
      mount: '/',
      usedBytes: 214_748_364_800,
      totalBytes: 1_099_511_627_776,
      availableBytes: 884_763_262_976,
    }],
    uptimeSec: 432_000,
  };
  metrics.entities.unshift({
    key: 'host', kind: 'host', name: 'Machine', project: null,
    points: [
      [Date.now() - 20_000, 28.2, 8_321_499_136],
      [Date.now() - 10_000, 30.1, 8_455_716_864],
      [Date.now(), 32.5, 8_589_934_592],
    ],
  });
  return metrics;
}

function adminState() {
  return {
    access: accessFixture(),
    invites: inviteFixture(),
    telegram: { version: 1, bots: [], projects: telegramProjects() },
    archives: archiveFixture(),
    lifecycleAvailable: false,
    lifecycleFailure: false,
    lifecycleRequests: [],
    unexpectedRequests: [],
    accessCreateFailures: 1,
    inviteDecisionFailures: 1,
    telegramWebhookFailures: 1,
    testFleet: testFleetFixture(),
  };
}

async function fulfillJson(route, status, body) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'cache-control': 'no-store' },
    body: JSON.stringify(body),
  });
}

async function installAdminRoutes(page, fixture, stack) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;
    let body;

    if (method === 'GET' && pathname === '/api/session') {
      body = {
        ...CANONICAL_SESSION,
        accessAdmin: true,
        lifecycleAvailable: fixture.lifecycleAvailable,
      };
    } else if (method === 'GET' && pathname === '/api/access') {
      body = fixture.access;
    } else if (method === 'POST' && pathname === '/api/access/users') {
      const submitted = request.postDataJSON();
      if (fixture.accessCreateFailures > 0) {
        fixture.accessCreateFailures -= 1;
        await fulfillJson(route, 409, {
          error: 'That Google account already has an outstanding invitation.',
          code: 'access_user_conflict',
        });
        return;
      }
      const email = String(submitted.email).trim().toLowerCase();
      fixture.access.users.push({
        email,
        owner: false,
        grants: [...submitted.grants],
      });
      fixture.access.invitedCount += 1;
      body = fixture.access;
    } else if (
      method === 'POST'
      && /^\/api\/access\/requests\/[^/]+\/decision$/.test(pathname)
    ) {
      if (fixture.inviteDecisionFailures > 0) {
        fixture.inviteDecisionFailures -= 1;
        await fulfillJson(route, 409, {
          error: 'This request was resolved by another owner. Refresh before deciding.',
          code: 'access_request_stale',
        });
        return;
      }
      const id = decodeURIComponent(pathname.split('/')[4]);
      const submitted = request.postDataJSON();
      const item = fixture.invites.requests.find((candidate) => candidate.id === id);
      assert.ok(item, `invite fixture ${id} must exist`);
      item.status = submitted.decision === 'approve' ? 'approved' : 'denied';
      item.resolvedAt = '2026-07-28T10:30:00.000Z';
      item.resolvedBy = CANONICAL_SESSION.email;
      body = { request: item, access: fixture.access };
    } else if (method === 'GET' && pathname === '/api/access/requests') {
      body = {
        ...fixture.invites,
        pendingCount: fixture.invites.requests.filter(
          (item) => item.status === 'pending',
        ).length,
      };
    } else if (method === 'GET' && pathname === '/api/telegram') {
      body = fixture.telegram;
    } else if (method === 'GET' && pathname === '/api/bugs') {
      body = { schema_version: 1, revision: 'fixture-empty-bugs', bugs: [] };
    } else if (method === 'POST' && pathname === '/api/telegram/bots') {
      const submitted = request.postDataJSON();
      assert.equal(submitted.token, SYNTHETIC_TELEGRAM_TOKEN);
      if (!submitted.takeOver && fixture.telegramWebhookFailures > 0) {
        fixture.telegramWebhookFailures -= 1;
        await fulfillJson(route, 409, {
          error: 'The fixture bot already has an active webhook.',
          code: 'telegram_webhook_active',
        });
        return;
      }
      assert.equal(submitted.takeOver, true);
      fixture.telegram = registeredTelegramFixture(fixture.telegram.projects);
      body = fixture.telegram;
    } else if (
      method === 'PATCH'
      && /^\/api\/telegram\/bots\/[^/]+\/projects$/.test(pathname)
    ) {
      const submitted = request.postDataJSON();
      fixture.telegram.bots[0].projectIds = [...submitted.projectIds];
      body = fixture.telegram;
    } else if (method === 'GET' && pathname === '/api/lifecycle/list') {
      fixture.lifecycleRequests.push(`${method} ${pathname}`);
      if (!fixture.lifecycleAvailable) {
        await fulfillJson(route, 403, {
          error: 'Lifecycle management is not activated for this fixture.',
          code: 'lifecycle_unavailable',
        });
        return;
      }
      if (fixture.lifecycleFailure) {
        await fulfillJson(route, 503, {
          error: 'The lifecycle registry is temporarily unavailable.',
          code: 'lifecycle_registry_unavailable',
          classification: 'dependency_unavailable',
        });
        return;
      }
      body = { archives: fixture.archives };
    } else if (method === 'GET' && pathname === '/api/prefs') {
      body = CANONICAL_PREFS;
    } else if (method === 'GET' && pathname === '/api/overview') {
      body = populatedOverview(stack);
    } else if (method === 'GET' && pathname === '/api/metrics/history') {
      body = populatedMetrics();
    } else if (method === 'GET' && pathname === '/api/tests/repositories') {
      body = { schema_version: 1, repositories: testRepositoriesFixture() };
    } else if (method === 'GET' && pathname === '/api/tests/fleet') {
      body = fixture.testFleet;
    } else if (method === 'GET' && pathname === '/api/tests') {
      body = testStatsFixture(new URL(request.url()).searchParams.get('project'));
    } else if (method === 'GET' && pathname === '/api/tests/runs') {
      const repoId = new URL(request.url()).searchParams.get('repo_id');
      body = {
        schema_version: 1,
        repo_id: repoId,
        runs: [{
          repo_id: repoId,
          run_id: 'fixture-completed-run',
          state: 'succeeded',
          intent: 'change',
          actor: 'agent:fixture',
          source_mode: 'immutable',
          queued_at: new Date(Date.now() - 120_000).toISOString(),
          finished_at: new Date(Date.now() - 60_000).toISOString(),
          target_count: 2,
          completed_target_count: 2,
          wall_seconds: 60,
          can_cancel: false,
          can_retry: false,
        }],
      };
    } else {
      const sourcesMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/sources$/);
      const setupMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/setup$/);
      if (method === 'GET' && sourcesMatch) {
        const repoId = decodeURIComponent(sourcesMatch[1]);
        const selector = {
          schema_version: 1,
          kind: 'original',
          repository_id: repoId,
          repository_generation: 1,
        };
        body = {
          schema_version: 1,
          repository_id: repoId,
          default_source: selector,
          sources: [{ selector, label: 'Original repository', detail: 'Canonical fixture' }],
        };
      } else if (method === 'GET' && setupMatch) {
        body = testSetupFixture(decodeURIComponent(setupMatch[1]));
      } else {
        fixture.unexpectedRequests.push(`${method} ${pathname}`);
        await fulfillJson(route, 500, {
          error: `Unexpected admin browser fixture request: ${method} ${pathname}`,
        });
        return;
      }
    }
    await fulfillJson(route, 200, body);
  });
}

async function navigateTo(page, destination, mobile) {
  if (mobile) {
    const toggle = page.locator('#nav-toggle');
    await toggle.click();
    assert.equal(await toggle.getAttribute('aria-expanded'), 'true');
  }
  const link = page.locator(`[data-nav="${destination}"]`);
  await link.click();
  const sectionId = destination === 'ports' ? 'leases'
    : destination === 'performance' ? 'perf'
      : destination;
  const section = page.locator(`#sec-${sectionId}`);
  await section.waitFor({ state: 'visible' });
  assert.equal(await link.getAttribute('aria-current'), 'page');
  if (mobile) {
    assert.equal(await page.locator('#nav-toggle').getAttribute('aria-expanded'), 'false');
  }
  return section;
}

async function assertFocused(locator, message) {
  assert.equal(
    await locator.evaluate((element) => element === document.activeElement),
    true,
    message,
  );
}

async function assertRenderedFit(page, selector, label, { dialog = false } = {}) {
  const result = await page.evaluate(({ targetSelector, isDialog }) => {
    const root = document.querySelector(targetSelector);
    if (!root) return { missing: true };
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none'
        && style.visibility !== 'hidden'
        && rect.width > 0
        && rect.height > 0;
    };
    const candidates = [
      root,
      ...root.querySelectorAll(
        'article, details[open], form, fieldset, button, input, select, textarea, '
        + '.queue-actions, .telegram-project, .archive-row',
      ),
    ].filter(visible);
    const horizontalCuts = candidates
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          element: element.id || element.className || element.tagName,
          left: rect.left,
          right: rect.right,
        };
      })
      .filter((entry) => entry.left < -1 || entry.right > window.innerWidth + 1);
    const rect = root.getBoundingClientRect();
    const style = getComputedStyle(root);
    const documentOverflowers = [...document.querySelectorAll('body *')].flatMap((element) => {
      if (!visible(element)) return [];
      const child = element.getBoundingClientRect();
      if (child.left >= -1 && child.right <= window.innerWidth + 1) return [];
      return [{
        element: element.id || element.className || element.tagName,
        left: Math.round(child.left),
        right: Math.round(child.right),
        width: Math.round(child.width),
      }];
    }).slice(0, 12);
    const rootOverflowers = [...root.querySelectorAll('*')].flatMap((element) => {
      if (!visible(element)) return [];
      const child = element.getBoundingClientRect();
      const overflows = child.left < rect.left - 1 || child.right > rect.right + 1;
      const scrolls = element.scrollWidth > element.clientWidth + 1;
      if (!overflows && !scrolls) return [];
      return [{
        element: element.id || element.className || element.tagName,
        left: Math.round(child.left),
        right: Math.round(child.right),
        clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth,
      }];
    }).slice(0, 12);
    return {
      missing: false,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      documentOverflow:
        document.documentElement.scrollWidth - document.documentElement.clientWidth,
      documentOverflowers,
      rootOverflow: root.scrollWidth - root.clientWidth,
      rootOverflowers,
      horizontalCuts,
      dialogTop: rect.top,
      dialogBottom: rect.bottom,
      dialogScrollable:
        root.scrollHeight <= root.clientHeight + 1
        || ['auto', 'scroll'].includes(style.overflowY),
      isDialog,
    };
  }, { targetSelector: selector, isDialog: dialog });
  assert.equal(result.missing, false, `${label} must render`);
  assert.ok(
    result.documentOverflow <= 1,
    `${label} must not widen the document: ${JSON.stringify(result)}`,
  );
  assert.ok(
    result.rootOverflow <= 1,
    `${label} must not require horizontal scrolling: ${JSON.stringify(result)}`,
  );
  assert.deepEqual(
    result.horizontalCuts,
    [],
    `${label} controls and decision content must fit the viewport`,
  );
  if (dialog) {
    assert.ok(
      result.dialogTop >= -1 && result.dialogBottom <= result.viewportHeight + 1,
      `${label} must open inside the current viewport: ${JSON.stringify(result)}`,
    );
    assert.equal(
      result.dialogScrollable,
      true,
      `${label} must retain a vertical path to long dialog content`,
    );
  }
}

async function assertHealthyRoute(page, sectionSelector, label, deferredFailures = null) {
  try {
    await assertRenderedFit(page, sectionSelector, label);
    const failures = await page.locator([
      `${sectionSelector} .repository-inventory-error`,
      `${sectionSelector} .degraded`,
      `${sectionSelector} .test-local-failure`,
      '#banner-slot .banner',
    ].join(', ')).evaluateAll((nodes) => nodes.filter((node) => {
      const style = getComputedStyle(node);
      const rect = node.getBoundingClientRect();
      return !node.hidden && style.display !== 'none' && style.visibility !== 'hidden'
        && rect.width > 0 && rect.height > 0;
    }).map((node) => (node.textContent || '').replace(/\s+/g, ' ').trim()));
    assert.deepEqual(failures, [], `${label} must not render a contract, dependency or global error`);
    assert.doesNotMatch(
      await page.locator(sectionSelector).innerText(),
      /Repository inventory contract is invalid|authoritative repository tree is missing|cover every normalized resource exactly once/i,
      `${label} must accept the populated authoritative inventory contract`,
    );
  } catch (error) {
    if (!Array.isArray(deferredFailures)) throw error;
    deferredFailures.push(error);
  }
}

async function flipDisclosure(locator, label) {
  const before = await locator.getAttribute('aria-expanded');
  assert.ok(before === 'true' || before === 'false', `${label} must expose disclosure state`);
  await locator.click();
  assert.equal(
    await locator.getAttribute('aria-expanded'),
    before === 'true' ? 'false' : 'true',
    `${label} must toggle once`,
  );
  await locator.click();
  assert.equal(await locator.getAttribute('aria-expanded'), before, `${label} must toggle back`);
}

async function exercisePrimaryConsoleRoutes(page, mobile, label, deferredFailures) {
  let section = await navigateTo(page, 'projects', mobile);
  const projectToggle = section.locator('[data-fk^="tree-x:"]').first();
  await projectToggle.waitFor();
  await flipDisclosure(projectToggle, `${label} Projects repository`);
  await assertHealthyRoute(page, '#sec-projects', `${label} Projects`, deferredFailures);

  section = await navigateTo(page, 'tests', mobile);
  await section.locator('.test-fleet-summary').waitFor();
  assert.equal(await section.locator('.test-fleet-mobile-row, .test-fleet-row').count() > 0, true);
  await page.locator('#tests-search').fill('Sample API');
  await page.waitForFunction(() => (
    [...document.querySelectorAll('.test-fleet-mobile-row, .test-fleet-row')]
      .some((node) => getComputedStyle(node).display !== 'none')
  ));
  await page.locator('#tests-search').fill('');
  const repositoryButton = mobile
    ? section.locator('.test-fleet-mobile-row').first()
    : section.locator('.test-repository-button').first();
  await repositoryButton.click();
  const detail = page.locator('#test-detail-dialog');
  await detail.waitFor({ state: 'visible' });
  await detail.getByRole('heading', { name: 'Throughput & efficiency' }).waitFor();
  await detail.getByRole('tab', { name: 'Runs' }).click();
  await detail.locator('.test-run-history-card').waitFor();
  await detail.getByRole('tab', { name: 'Setup' }).click();
  await detail.getByRole('heading', { name: 'Manifest · ready' }).waitFor();
  await page.locator('#test-detail-close').click();
  await detail.waitFor({ state: 'hidden' });
  await page.locator('#tests-run').click();
  const runDialog = page.locator('#test-run-dialog');
  await runDialog.waitFor({ state: 'visible' });
  await runDialog.locator('#test-run-source option').first().waitFor({ state: 'attached' });
  try {
    await assertRenderedFit(page, '#test-run-dialog', `${label} Run tests dialog`, { dialog: true });
  } catch (error) {
    // Finish the route matrix before failing so one layout regression cannot
    // hide untested destinations later in the same viewport.
    deferredFailures.push(error);
  }
  await page.locator('#test-run-cancel').click();
  await runDialog.waitFor({ state: 'hidden' });
  assert.deepEqual(
    await section.locator('.test-fleet-hour').allTextContents(),
    Array.from({ length: 24 }, (_, hour) => `${String(hour).padStart(2, '0')}:00`),
    `${label} Tests must keep a local 00:00 through 23:00 data order`,
  );
  assert.equal(
    await section.locator('.test-fleet-matrix-wrap').isHidden(),
    mobile,
    `${label} Tests must replace the dense heatmap with repository cards only on mobile`,
  );
  await assertHealthyRoute(page, '#sec-tests', `${label} Tests`, deferredFailures);

  section = await navigateTo(page, 'servers', mobile);
  const serverToggle = section.locator('.server-project-toggle').first();
  await serverToggle.waitFor();
  await flipDisclosure(serverToggle, `${label} Servers repository`);
  await assertHealthyRoute(page, '#sec-servers', `${label} Servers`, deferredFailures);

  section = await navigateTo(page, 'routes', mobile);
  await section.locator('[data-route-slug]').first().waitFor();
  await page.locator('#route-add').click();
  const routeDialog = page.locator('#route-dialog');
  await routeDialog.waitFor({ state: 'visible' });
  await assertRenderedFit(page, '#route-dialog', `${label} Create route dialog`, { dialog: true });
  await page.locator('#route-cancel').click();
  await routeDialog.waitFor({ state: 'hidden' });
  await assertHealthyRoute(page, '#sec-routes', `${label} Routes`, deferredFailures);

  section = await navigateTo(page, 'docker', mobile);
  const dockerToggle = section.locator('.server-project-toggle').first();
  await dockerToggle.waitFor();
  await flipDisclosure(dockerToggle, `${label} Docker repository`);
  await assertHealthyRoute(page, '#sec-docker', `${label} Docker`, deferredFailures);

  section = await navigateTo(page, 'ports', mobile);
  await section.locator('[data-lease-id="fixture-lease-preview"]').waitFor();
  await page.locator('#assignments-body .item').first().waitFor();
  await page.locator('#lease-add').click();
  const leaseDialog = page.locator('#lease-dialog');
  await leaseDialog.waitFor({ state: 'visible' });
  await page.locator('#lf-preferred').fill('70000');
  await page.locator('#lf-submit').click();
  await page.locator('#lf-error').getByText(
    'Preferred port must be between 1 and 65535.', { exact: true },
  ).waitFor();
  await page.locator('#lease-cancel').click();
  await leaseDialog.waitFor({ state: 'hidden' });
  await assertHealthyRoute(page, '#sec-leases', `${label} Port leases`, deferredFailures);
  await assertHealthyRoute(page, '#sec-assignments', `${label} Pinned ports`, deferredFailures);

  section = await navigateTo(page, 'performance', mobile);
  await section.locator('.performance-dashboard').waitFor();
  await section.locator('#perf-memory-chart').waitFor();
  await section.locator('#perf-cpu-chart').waitFor();
  assert.equal(await section.locator('.perf-card').count(), 0,
    `${label} Performance must render one host stack instead of repeated resource cards`);
  await assertHealthyRoute(page, '#sec-perf', `${label} Performance`, deferredFailures);
  await section.getByRole('link', { name: 'Test dashboards' }).click();
  await page.locator('#sec-tests').waitFor({ state: 'visible' });

  section = await navigateTo(page, 'access', mobile);
  await section.locator('.access-user').first().waitFor();
  await page.locator('#access-add').click();
  await page.locator('#access-dialog').waitFor({ state: 'visible' });
  await page.locator('#access-cancel').click();
  await assertHealthyRoute(page, '#sec-access', `${label} Access`, deferredFailures);

  section = await navigateTo(page, 'invites', mobile);
  await section.locator('[data-invite-id="invite-pending-1"]').waitFor();
  await page.locator('#invites-refresh').click();
  await section.locator('[data-invite-id="invite-pending-1"]').waitFor();
  await assertHealthyRoute(page, '#sec-invites', `${label} Invites`, deferredFailures);

  section = await navigateTo(page, 'telegram', mobile);
  await section.locator('.telegram-empty').waitFor();
  await page.locator('#telegram-add').click();
  await page.locator('#telegram-dialog').waitFor({ state: 'visible' });
  await page.locator('#telegram-cancel').click();
  await assertHealthyRoute(page, '#sec-telegram', `${label} Telegram`, deferredFailures);
}

async function exerciseAccess(page, mobile, label) {
  const section = await navigateTo(page, 'access', mobile);
  await section.locator('.access-user').first().waitFor();
  assert.equal(await section.locator('.access-user').count(), 10);
  assert.equal(
    await section.locator('.access-user').first().locator('.access-owner-badge').textContent(),
    'Owner',
  );
  await assertRenderedFit(page, '#sec-access', `${label} populated Access`);

  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await page.locator('#access-add').click();
  const dialog = page.locator('#access-dialog');
  await dialog.waitFor({ state: 'visible' });
  await assertFocused(page.locator('#access-email'), `${label} Access dialog must focus email`);
  await assertRenderedFit(page, '#access-dialog', `${label} Access dialog`, { dialog: true });
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  await assertFocused(
    page.locator('#access-add'),
    `${label} Access Escape must restore the invoking control`,
  );

  await page.locator('#access-add').click();
  await page.locator('#access-email').fill('new-viewer@example.test');
  await page.locator('#access-resource-picker input').first().check();
  await dialog.getByRole('button', { name: 'Add user' }).click();
  const error = page.locator('#access-form-error');
  await error.getByText(
    'That Google account already has an outstanding invitation.',
    { exact: true },
  ).waitFor();
  assert.equal(await dialog.getAttribute('open'), '');
  assert.equal(await page.locator('#access-email').inputValue(), 'new-viewer@example.test');
  await dialog.getByRole('button', { name: 'Add user' }).click();
  await dialog.waitFor({ state: 'hidden' });
  const added = page.locator('[data-access-user="new-viewer@example.test"]');
  await added.waitFor();
  await assertFocused(added, `${label} Access success must focus the real new row`);
  assert.match(await added.innerText(), /console\.vr\.ae/);
  assert.equal(await page.locator('#live').textContent(), 'new-viewer@example.test added');
  await assertRenderedFit(page, '#sec-access', `${label} Access success`);
}

async function exerciseInvites(page, mobile, label) {
  const section = await navigateTo(page, 'invites', mobile);
  await section.locator('[data-invite-id="invite-pending-1"]').waitFor();
  assert.match(await section.locator('.queue-summary').textContent(), /2 verified requests/);
  assert.match(await section.locator('.queue-row').first().innerText(), /requester-1@example\.test/);
  const history = section.locator('details.queue-history');
  assert.match(await history.locator('summary').textContent(), /Recent decisions \(7\)/);
  const widthBefore = await section.evaluate((element) => element.getBoundingClientRect().width);
  await history.locator('summary').click();
  const widthAfter = await section.evaluate((element) => element.getBoundingClientRect().width);
  assert.ok(Math.abs(widthAfter - widthBefore) <= 1, `${label} invite history must keep stable width`);
  await assertRenderedFit(page, '#sec-invites', `${label} populated Invites`);

  const first = section.locator('[data-invite-id="invite-pending-1"]');
  await first.getByRole('button', { name: 'Approve' }).click();
  await page.locator('#banner-slot .banner-msg').getByText(
    'This request was resolved by another owner. Refresh before deciding.',
    { exact: true },
  ).waitFor();
  assert.equal(await first.getByRole('button', { name: 'Deny' }).isEnabled(), true);
  await first.getByRole('button', { name: 'Deny' }).click();
  await section.locator('[data-invite-id="invite-pending-2"]')
    .getByRole('button', { name: 'Approve' }).click();
  await section.getByText('No access requests are waiting.', { exact: true }).waitFor();
  assert.equal(await section.locator('.queue-actions').count(), 0);
  assert.equal(await page.locator('#live').textContent(), 'Access request approved');
  await assertRenderedFit(page, '#sec-invites', `${label} empty pending Invites`);
}

async function exerciseTelegram(page, mobile, label) {
  const section = await navigateTo(page, 'telegram', mobile);
  await section.locator('.telegram-empty').waitFor();
  assert.match(await section.innerText(), /No Telegram bots are registered/);
  await assertRenderedFit(page, '#sec-telegram', `${label} empty Telegram`);

  await page.locator('#telegram-add').click();
  const dialog = page.locator('#telegram-dialog');
  await dialog.waitFor({ state: 'visible' });
  await assertFocused(
    page.locator('#telegram-label'),
    `${label} Telegram dialog must focus the first field`,
  );
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  await assertFocused(
    page.locator('#telegram-add'),
    `${label} Telegram Escape must restore the invoking control`,
  );

  await page.locator('#telegram-add').click();
  await page.locator('#telegram-label').fill('Operations fixture');
  await page.locator('#telegram-token').fill(SYNTHETIC_TELEGRAM_TOKEN);
  await assertRenderedFit(page, '#telegram-dialog', `${label} Telegram dialog`, { dialog: true });
  await dialog.getByRole('button', { name: 'Register bot' }).click();
  const takeover = page.locator('#telegram-takeover');
  await takeover.waitFor({ state: 'visible' });
  await assertFocused(takeover, `${label} webhook conflict must focus the explicit takeover`);
  assert.match(
    await page.locator('#telegram-form-error').textContent(),
    /already sends updates to another webhook/,
  );
  assert.equal(await page.locator('#telegram-token').inputValue(), SYNTHETIC_TELEGRAM_TOKEN);
  await takeover.check();
  await dialog.getByRole('button', { name: 'Register bot' }).click();
  await dialog.waitFor({ state: 'hidden' });

  const bot = section.locator('[data-telegram-bot="fixture-bot-operations"]');
  await bot.waitFor();
  await assertFocused(bot, `${label} Telegram success must focus the registered bot`);
  assert.match(await bot.innerText(), /Operations fixture/);
  assert.match(await bot.innerText(), /Bot authorization queue \(1\)/);
  assert.doesNotMatch(await page.locator('body').innerText(), new RegExp(SYNTHETIC_TELEGRAM_TOKEN));
  assert.equal(await page.locator('#telegram-token').inputValue(), '');
  const unassigned = bot.locator('input[data-project-id="repo-fixture-2"]');
  await unassigned.check();
  await page.waitForFunction(
    () => document.querySelector(
      '[data-telegram-bot="fixture-bot-operations"] '
      + 'input[data-project-id="repo-fixture-2"]',
    )?.checked === true,
  );
  const recent = bot.locator('details.queue-history');
  const widthBefore = await bot.evaluate((element) => element.getBoundingClientRect().width);
  await recent.locator('summary').click();
  const widthAfter = await bot.evaluate((element) => element.getBoundingClientRect().width);
  assert.ok(Math.abs(widthAfter - widthBefore) <= 1, `${label} Telegram history must keep stable width`);
  await assertRenderedFit(page, '#sec-telegram', `${label} populated Telegram`);
}

async function exerciseLifecycle(page, mobile, label, fixture) {
  const section = await navigateTo(page, 'servers', mobile);
  await section.locator('#servers-body .server-project-toggle').first().waitFor();
  const archived = section.locator(
    '[data-lifecycle-filter="servers"] [data-lifecycle-view="archived"]',
  );
  assert.equal(await archived.isDisabled(), true);
  assert.equal(await archived.getAttribute('aria-disabled'), 'true');
  assert.equal(
    await archived.getAttribute('title'),
    'Archive management is not activated on this Console',
  );
  assert.deepEqual(
    fixture.lifecycleRequests,
    [],
    `${label} disabled lifecycle state must make no archive request`,
  );
  await assertRenderedFit(page, '#sec-servers', `${label} disabled lifecycle`);

  fixture.lifecycleAvailable = true;
  fixture.lifecycleFailure = true;
  await page.reload({ waitUntil: 'networkidle' });
  await archived.waitFor();
  assert.equal(await archived.isEnabled(), true);
  assert.equal(await page.locator('#servers-archived-count').isHidden(), true);
  await archived.click();
  await page.locator('#banner-slot .banner-msg').getByText(
    'The lifecycle registry is temporarily unavailable.',
    { exact: true },
  ).waitFor();
  assert.equal(await archived.getAttribute('aria-pressed'), 'true');
  fixture.lifecycleFailure = false;
  await page.locator('#banner-slot').getByRole('button', { name: 'Retry' }).click();
  await section.getByText(
    'Archived resources are stopped and fenced. Restore clears the fence but never starts anything.',
    { exact: true },
  ).waitFor();
  assert.equal(await page.locator('#servers-archived-count').textContent(), '4');
  const group = section.locator('[data-fk^="archive-group:servers:"]').first();
  await group.click();
  await section.locator('[data-lifecycle-target="server:fixture-archived-server-1"]').waitFor();
  assert.match(await section.innerText(), /Repeated crash investigation/);
  assert.match(await section.innerText(), /Crash and log evidence/);
  await assertRenderedFit(page, '#sec-servers', `${label} populated lifecycle`);

  fixture.archives = [];
  await page.reload({ waitUntil: 'networkidle' });
  await section.locator(
    '[data-lifecycle-filter="servers"] [data-lifecycle-view="archived"]',
  ).click();
  await section.getByText('No archived servers yet.', { exact: true }).waitFor();
  assert.equal(await page.locator('#servers-archived-count').textContent(), '0');
  await assertRenderedFit(page, '#sec-servers', `${label} empty lifecycle`);
}

async function exerciseAdminViewport(browser, stack, sessionCookie, viewport) {
  const fixture = adminState();
  const deferredFailures = [];
  const context = await browser.newContext({
    viewport: { width: viewport.width, height: viewport.height },
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    // A non-UTC user timezone proves the Tests heatmap is genuinely local,
    // while still requiring a stable 00:00 through 23:00 column order.
    timezoneId: 'Asia/Dubai',
    colorScheme: 'dark',
    reducedMotion: 'reduce',
  });
  try {
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
    const pageErrors = [];
    const consoleErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('console', (message) => {
      if (message.type() === 'error') consoleErrors.push(message.text());
    });
    await installAdminRoutes(page, fixture, stack);

    const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
    // Start on Tests so the first explicit Projects navigation exercises a
    // real hash transition on mobile instead of re-selecting the active link.
    await page.goto(`${origin}/#/tests`, { waitUntil: 'networkidle' });
    await page.waitForFunction(
      () => document.querySelector('#nav-access')?.hidden === false,
    );
    await exercisePrimaryConsoleRoutes(
      page, viewport.mobile, viewport.label, deferredFailures,
    );
    await exerciseAccess(page, viewport.mobile, viewport.label);
    await exerciseInvites(page, viewport.mobile, viewport.label);
    await exerciseTelegram(page, viewport.mobile, viewport.label);
    await exerciseLifecycle(page, viewport.mobile, viewport.label, fixture);

    assert.deepEqual(fixture.unexpectedRequests, []);
    assert.deepEqual(pageErrors, []);
    assert.deepEqual(
      consoleErrors.filter(
        (message) => !/status of (409|503) \(/.test(message),
      ),
      [],
      `${viewport.label} must produce only the deliberately exercised error responses`,
    );
    if (deferredFailures.length) {
      throw new AggregateError(
        deferredFailures,
        `${viewport.label} route matrix found ${deferredFailures.length} layout failure(s):\n`
          + deferredFailures.map((error, index) => `${index + 1}. ${error.message}`).join('\n'),
      );
    }
  } finally {
    await context.close();
  }
}

test('every Console route and essential owner journey stays healthy and fits desktop/mobile',
  { timeout: 180_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-admin-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    try {
      stack = await startStack({
        allowedEmails: [CANONICAL_SESSION.email],
        claims: { email: CANONICAL_SESSION.email, name: CANONICAL_SESSION.name },
        coordinatorEnv: {
          PATH: `${fakeDockerDir}${path.delimiter}${process.env.PATH ?? ''}`,
        },
      });
      const jar = makeJar();
      const loginResult = await login(stack, jar);
      const sessionCookie = jar.get('dc_session');
      assert.equal(loginResult.status, 200);
      assert.ok(sessionCookie, 'real login must issue the Console session cookie');

      browser = await launchChromium(
        chromium,
        [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
      );
      for (const viewport of [
        { label: 'desktop 1440px', width: 1440, height: 900, mobile: false },
        { label: 'mobile 390px', width: 390, height: 844, mobile: true },
      ]) {
        // Keep both contexts strictly sequential so one fixture cannot mask
        // focus, state, or route behavior in the other viewport.
        await exerciseAdminViewport(browser, stack, sessionCookie, viewport);
      }
    } finally {
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
