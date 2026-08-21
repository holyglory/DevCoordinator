// Real-browser regression for the Run tests journey. The shipped Console
// shell and HTTPS stack are real; every test API response is a bounded,
// deterministic browser-route fixture so no live scheduler or repository is
// mutated while repository, plan, operation, target, and run identities are
// still checked end to end.

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
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
const PRIMARY_REPO = 'repo-rendered-run';
const BLOCKED_REPO = 'repo-rendered-blocked';
const PRIMARY_ORIGINAL_SOURCE = Object.freeze({
  schema_version: 1, kind: 'original', repository_id: PRIMARY_REPO, repository_generation: 7,
});
const PRIMARY_TEMPORARY_SOURCE = Object.freeze({
  schema_version: 1, kind: 'temporary', repository_id: 'repo-rendered-run-worktree',
  repository_generation: 3,
});
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPERATION_IDS = Object.freeze({
  desktopPlan: '00000000-0000-4000-8000-000000000001',
  desktopSubmit: '00000000-0000-4000-8000-000000000002',
  mobilePlan: '00000000-0000-4000-8000-000000000003',
  mobileSubmit: '00000000-0000-4000-8000-000000000004',
  blockedPlan: '00000000-0000-4000-8000-000000000005',
});

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

function setupFixture(repoId) {
  return {
    schema_version: 1,
    repo_id: repoId,
    status: 'ready',
    manifest_schema: 2,
    manifest_fingerprint: 'a'.repeat(64),
    targets: [
      { name: 'integration', depends_on: ['unit'], network: 'loopback', fixtures: [] },
      { name: 'lint', depends_on: [], network: 'none', fixtures: [] },
      { name: 'unit', depends_on: [], network: 'none', fixtures: [] },
    ],
    fixtures: {},
  };
}

async function assertDialogInsideViewport(page, label) {
  const geometry = await page.locator('#test-run-dialog').evaluate((node) => {
    const rect = node.getBoundingClientRect();
    return {
      left: rect.left,
      right: rect.right,
      top: rect.top,
      bottom: rect.bottom,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      documentWidth: document.documentElement.scrollWidth,
    };
  });
  assert.ok(geometry.left >= 0
    && geometry.right <= geometry.viewportWidth
    && geometry.top >= 0
    && geometry.bottom <= geometry.viewportHeight,
  `${label} Run tests dialog must stay inside the viewport: ${JSON.stringify(geometry)}`);
  assert.ok(geometry.documentWidth <= geometry.viewportWidth,
    `${label} Run tests journey must not cause document overflow: ${JSON.stringify(geometry)}`);
}

test('Current repositories run tests on desktop and mobile, then render a blocked planner',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-test-run-');
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
      await context.addInitScript((operationIds) => {
        let cursor = 0;
        Object.defineProperty(globalThis.crypto, 'randomUUID', {
          configurable: true,
          value: () => {
            if (cursor >= operationIds.length) {
              throw new Error('rendered Run tests fixture exhausted deterministic operation identities');
            }
            const value = operationIds[cursor];
            cursor += 1;
            return value;
          },
        });
      }, [
        OPERATION_IDS.desktopPlan,
        OPERATION_IDS.desktopSubmit,
        OPERATION_IDS.mobilePlan,
        OPERATION_IDS.mobileSubmit,
        OPERATION_IDS.blockedPlan,
      ]);

      const page = await context.newPage();
      const browserErrors = [];
      const unexpectedRequests = [];
      const planRequests = [];
      const submittedRequests = [];
      const plans = new Map();
      const runs = [];
      let planOrdinal = 0;
      page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') browserErrors.push(`console: ${message.text()}`);
      });

      await page.route('**/api/**', async (route) => {
        const request = route.request();
        const requestUrl = new URL(request.url());
        const pathname = requestUrl.pathname;
        const method = request.method();
        let body;
        let status = 200;

        if (method === 'GET' && pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin: false, lifecycleAvailable: false };
        } else if (method === 'GET' && pathname === '/api/prefs') {
          body = CANONICAL_PREFS;
        } else if (method === 'GET' && pathname === '/api/overview') {
          body = CANONICAL_OVERVIEW;
        } else if (method === 'GET' && pathname === '/api/metrics/history') {
          body = CANONICAL_METRICS;
        } else if (method === 'GET' && pathname === '/api/telegram') {
          body = { bots: [], pendingAuthorizations: [], authorizedChats: [] };
        } else if (method === 'GET' && pathname === '/api/bugs') {
          body = { schema_version: 1, revision: 'fixture-empty-bugs', bugs: [] };
        } else if (method === 'GET' && pathname === '/api/tests/repositories') {
          body = {
            schema_version: 1,
            repositories: [
              {
                repo_id: PRIMARY_REPO,
                canonical_root: '/fixtures/rendered-run',
                display_name: 'Rendered Run Repository',
              },
              {
                repo_id: BLOCKED_REPO,
                canonical_root: '/fixtures/rendered-blocked',
                display_name: 'Blocked Planner Repository',
              },
            ],
          };
        } else {
          const sourcesMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/sources$/);
          const setupMatch = pathname.match(/^\/api\/tests\/repositories\/([^/]+)\/setup$/);
          const evidenceMatch = pathname.match(
            /^\/api\/tests\/repositories\/([^/]+)\/runs\/([^/]+)(?:\/(failures|artifacts))?$/,
          );
          if (method === 'GET' && sourcesMatch) {
            const repoId = decodeURIComponent(sourcesMatch[1]);
            const original = repoId === PRIMARY_REPO
              ? PRIMARY_ORIGINAL_SOURCE
              : { schema_version: 1, kind: 'original', repository_id: repoId, repository_generation: 2 };
            body = {
              schema_version: 1,
              repository_id: repoId,
              default_source: original,
              sources: repoId === PRIMARY_REPO ? [
                { selector: original, label: 'Original repository', detail: 'Rendered Run Repository' },
                {
                  selector: PRIMARY_TEMPORARY_SOURCE,
                  label: 'Agent review worktree',
                  detail: 'Server-authorized worktree',
                },
              ] : [{ selector: original, label: 'Original repository', detail: 'Blocked repository' }],
            };
          } else if (method === 'GET' && setupMatch) {
            body = setupFixture(decodeURIComponent(setupMatch[1]));
          } else if (method === 'POST' && pathname === '/api/tests/plan') {
            const requestBody = request.postDataJSON();
            planRequests.push(structuredClone(requestBody));
            assert.match(requestBody.operation_id, UUID_RE);
            assert.deepEqual(requestBody.requested_targets, ['integration', 'unit']);
            if (requestBody.repo_id === BLOCKED_REPO) {
              status = 503;
              body = {
                error: 'Test planning is blocked while scheduler capacity is unavailable.',
                code: 'test_scheduler_pending',
                classification: 'unavailable',
              };
            } else {
              assert.equal(requestBody.repo_id, PRIMARY_REPO);
              planOrdinal += 1;
              const planId = `fixture-plan-${planOrdinal}`;
              plans.set(planId, {
                repo_id: requestBody.repo_id,
                operation_id: requestBody.operation_id,
                requested_targets: requestBody.requested_targets,
                source: requestBody.source,
              });
              body = {
                repo_id: requestBody.repo_id,
                repository_id: requestBody.repo_id,
                plan_id: planId,
                operation_id: requestBody.operation_id,
                source_selector: requestBody.source,
                source_label: requestBody.source.kind === 'temporary'
                  ? 'Agent review worktree' : 'Original repository',
                estimated_seconds: 42,
                plan: {
                  source: {
                    repository_id: requestBody.repo_id,
                    temporary_root: requestBody.source.kind === 'temporary'
                      ? '/fixtures/rendered-run-worktree' : null,
                  },
                  targets: requestBody.requested_targets,
                  selection_reasons: ['Explicit manual target selection', 'Dependency closure verified'],
                  waves: [['unit'], ['integration']],
                  parallelism: 2,
                  network: 'loopback',
                },
              };
            }
          } else if (method === 'POST' && pathname === '/api/tests/runs') {
            const requestBody = request.postDataJSON();
            submittedRequests.push(structuredClone(requestBody));
            const planned = plans.get(requestBody.plan_id);
            assert.ok(planned, `submission plan ${requestBody.plan_id} must be the exact previewed plan`);
            assert.equal(requestBody.repo_id, planned.repo_id);
            assert.equal(requestBody.repo_id, PRIMARY_REPO);
            assert.match(requestBody.operation_id, UUID_RE);
            const run = {
              repo_id: requestBody.repo_id,
              run_id: `fixture-run-${submittedRequests.length}`,
              state: 'queued',
              intent: 'manual',
              actor: 'google:operator@example.test',
              source_mode: 'live',
              queued_at: new Date().toISOString(),
              target_count: planned.requested_targets.length,
              completed_target_count: 0,
              wait: {
                code: 'host_memory',
                since: new Date().toISOString(),
                required_mib: 16_384,
                available_mib: 9_216,
                reserve_mib: 2_048,
                observed_at: new Date().toISOString(),
                source: 'fixed_default',
              },
              can_cancel: true,
            };
            runs.unshift(run);
            status = 202;
            body = { repo_id: requestBody.repo_id, run_id: run.run_id, state: run.state };
          } else if (method === 'GET' && pathname === '/api/tests/runs') {
            const repoId = requestUrl.searchParams.get('repo_id');
            body = { repo_id: repoId, runs: runs.filter((run) => run.repo_id === repoId) };
          } else if (method === 'GET' && evidenceMatch) {
            const repoId = decodeURIComponent(evidenceMatch[1]);
            const runId = decodeURIComponent(evidenceMatch[2]);
            const run = runs.find((candidate) => candidate.repo_id === repoId && candidate.run_id === runId);
            assert.ok(run, `run evidence must remain bound to ${repoId}/${runId}`);
            if (evidenceMatch[3] === 'failures') {
              body = { repo_id: repoId, run_id: runId, failures: [] };
            } else if (evidenceMatch[3] === 'artifacts') {
              body = { repo_id: repoId, run_id: runId, artifacts: [] };
            } else {
              body = {
                ...run,
                usage: {
                  available: true,
                  peak_memory_mib: 14_336,
                  cpu_seconds: 912.25,
                  measured_attempts: 2,
                  total_attempts: 2,
                },
                summary: {
                  queue_seconds: 0,
                  aggregate_test_seconds: 0,
                  failure_record_count: 0,
                  artifact_count: 0,
                },
              };
            }
          } else {
            unexpectedRequests.push(`${method} ${pathname}`);
            status = 500;
            body = { error: 'unexpected rendered test-run fixture request' };
          }
        }

        await route.fulfill({
          status,
          contentType: 'application/json',
          headers: { 'cache-control': 'no-store' },
          body: JSON.stringify(body),
        });
      });

      const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
      await page.goto(`${origin}/#/tests`, { waitUntil: 'networkidle' });
      await page.locator('.test-current-repositories').waitFor();
      await page.getByRole('button', { name: /Rendered Run Repository/ }).click();
      await page.locator('#test-run-targets input').first().waitFor();
      await page.locator('#test-run-source').waitFor({ state: 'visible' });
      assert.equal(await page.locator('#test-run-dialog').getAttribute('open'), '');
      assert.equal(await page.locator('#test-run-project').inputValue(), PRIMARY_REPO);
      assert.deepEqual(
        await page.locator('#test-run-targets input:checked').evaluateAll(
          (inputs) => inputs.map((input) => input.value),
        ),
        ['integration', 'lint', 'unit'],
      );
      await assertDialogInsideViewport(page, 'desktop');
      await page.locator('#test-run-source').focus();
      await page.locator('#test-run-source').selectOption(
        `temporary:${PRIMARY_TEMPORARY_SOURCE.repository_id}:${PRIMARY_TEMPORARY_SOURCE.repository_generation}`,
      );
      assert.equal(await page.evaluate(() => document.activeElement?.id), 'test-run-source',
        'source selection must not replace the focused control');
      await page.locator('#test-run-targets input[value="lint"]').uncheck();
      await page.locator('#test-run-preview-button').click();
      await page.locator('#test-run-submit').waitFor({ state: 'visible' });
      await page.waitForFunction(() => document.querySelector('#test-run-submit')?.disabled === false);
      assert.equal(planRequests.length, 1);
      assert.equal(planRequests[0].repo_id, PRIMARY_REPO);
      assert.equal(planRequests[0].intent, 'manual');
      assert.equal(planRequests[0].operation_id, OPERATION_IDS.desktopPlan);
      assert.deepEqual(planRequests[0].source, PRIMARY_TEMPORARY_SOURCE);
      assert.deepEqual(planRequests[0].requested_targets, ['integration', 'unit']);
      assert.match(await page.locator('#test-run-preview').textContent(), /2 selected targets/);
      assert.match(await page.locator('#test-run-preview').textContent(), /2\s*Waves|Waves\s*2/);
      assert.match(await page.locator('#test-run-preview').textContent(), /loopback/);
      assert.match(await page.locator('#test-run-preview').textContent(), /Agent review worktree/);

      await page.locator('#test-run-submit').click();
      await page.locator('#test-detail-dialog').waitFor({ state: 'visible' });
      assert.equal(await page.locator('#test-run-dialog').getAttribute('open'), null);
      assert.equal(submittedRequests.length, 1);
      assert.equal(submittedRequests[0].repo_id, PRIMARY_REPO);
      assert.equal(submittedRequests[0].plan_id, 'fixture-plan-1');
      assert.equal(submittedRequests[0].operation_id, OPERATION_IDS.desktopSubmit);
      assert.notEqual(submittedRequests[0].operation_id, planRequests[0].operation_id,
        'submission must carry its own idempotency operation while retaining the exact previewed plan');
      assert.match(await page.locator('#test-detail-h').textContent(), /Rendered Run Repository/);
      await page.locator('.test-run-history-card').first().waitFor();
      assert.match(await page.locator('.test-run-history-card').first().textContent(), /Queued/);
      assert.match(await page.locator('.test-run-history-card').first().textContent(), /0\/2 targets/);
      assert.match(
        await page.locator('.test-run-history-card').first().textContent(),
        /Waiting for memory.*16\.0 GiB needed.*9\.0 GiB available/,
      );
      assert.doesNotMatch(await page.locator('#banner-slot').textContent(), /Waiting for memory/,
        'ordinary scheduler waits must never become a global Console banner');
      assert.doesNotMatch(await page.locator('#tests-body').textContent(), /Waiting for memory/,
        'ordinary scheduler waits must stay inside the current-run surface');
      await page.locator('.test-run-history-evidence summary').first().click();
      await page.getByText('fixture-run-1', { exact: true }).waitFor();
      const expandedEvidence = page.locator('.test-run-history-evidence-body').first();
      assert.match(await expandedEvidence.textContent(), /Peak memory14\.0 GiB/);
      assert.match(await expandedEvidence.textContent(), /CPU time15m 12s/);
      assert.match(await expandedEvidence.textContent(), /Measurements2 of 2 attempts/);
      assert.doesNotMatch(await expandedEvidence.textContent(), /null/,
        'absent evidence sections must not be coerced into literal null text nodes');
      const evidenceGeometry = await expandedEvidence.evaluate((node) => {
        const card = node.closest('.test-run-history-card');
        const detail = document.querySelector('#test-detail-dialog');
        return {
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          cardClientWidth: card?.clientWidth,
          cardScrollWidth: card?.scrollWidth,
          detailClientWidth: detail?.clientWidth,
          detailScrollWidth: detail?.scrollWidth,
        };
      });
      assert.ok(evidenceGeometry.documentWidth <= evidenceGeometry.viewportWidth,
        `expanded run evidence must not overflow the desktop document: ${JSON.stringify(evidenceGeometry)}`);
      assert.equal(evidenceGeometry.cardScrollWidth, evidenceGeometry.cardClientWidth,
        `expanded run evidence must fit its card: ${JSON.stringify(evidenceGeometry)}`);
      assert.equal(evidenceGeometry.detailScrollWidth, evidenceGeometry.detailClientWidth,
        `expanded run evidence must fit the repository sheet: ${JSON.stringify(evidenceGeometry)}`);
      await page.locator('#test-detail-close').click();

      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForFunction(() => window.innerWidth === 390);
      await page.getByRole('button', { name: /Rendered Run Repository/ }).click();
      await page.locator('#test-run-targets input').first().waitFor();
      await assertDialogInsideViewport(page, '390px');
      assert.equal(
        await page.locator('#test-run-source').inputValue(),
        `temporary:${PRIMARY_TEMPORARY_SOURCE.repository_id}:${PRIMARY_TEMPORARY_SOURCE.repository_generation}`,
        'the server-authorized source choice must survive dialog close/reopen',
      );
      await page.locator('#test-run-targets input[value="lint"]').uncheck();
      await page.locator('#test-run-preview-button').click();
      await page.waitForFunction(() => document.querySelector('#test-run-submit')?.disabled === false);
      assert.equal(planRequests.length, 2);
      assert.equal(planRequests[1].repo_id, PRIMARY_REPO);
      assert.equal(planRequests[1].operation_id, OPERATION_IDS.mobilePlan);
      assert.deepEqual(planRequests[1].source, PRIMARY_TEMPORARY_SOURCE);
      assert.deepEqual(planRequests[1].requested_targets, ['integration', 'unit']);
      assert.match(await page.locator('#test-run-preview').textContent(), /2 selected targets/);
      await page.locator('#test-run-submit').click();
      await page.locator('#test-detail-dialog').waitFor({ state: 'visible' });
      assert.equal(submittedRequests.length, 2);
      assert.equal(submittedRequests[1].plan_id, 'fixture-plan-2');
      assert.equal(submittedRequests[1].repo_id, PRIMARY_REPO);
      assert.equal(submittedRequests[1].operation_id, OPERATION_IDS.mobileSubmit);
      await page.locator('.test-run-history-card').first().waitFor();
      assert.equal(await page.locator('.test-run-history-card').count(), 2);
      assert.match(await page.locator('.test-run-history-card').first().textContent(), /Queued/);
      assert.match(
        await page.locator('.test-run-history-card').first().textContent(),
        /Waiting for memory.*16\.0 GiB needed.*9\.0 GiB available/,
      );
      await page.locator('.test-run-history-evidence summary').first().click();
      await page.getByText('fixture-run-2', { exact: true }).waitFor();
      assert.match(
        await page.locator('.test-run-history-evidence-body').first().textContent(),
        /Peak memory14\.0 GiB.*CPU time15m 12s.*Measurements2 of 2 attempts/s,
      );
      await page.locator('#test-detail-close').click();

      await page.getByRole('button', { name: /Blocked Planner Repository/ }).click();
      await page.locator('#test-run-targets input').first().waitFor();
      await page.waitForFunction((repoId) => (
        document.querySelector('#test-run-project')?.value === repoId
        && document.querySelectorAll('#test-run-targets input').length === 3
      ), BLOCKED_REPO);
      await page.locator('#test-run-targets input[value="lint"]').uncheck();
      await page.locator('#test-run-preview-button').click();
      await page.locator('#test-run-error').waitFor({ state: 'visible' });
      assert.match(
        await page.locator('#test-run-error').textContent(),
        /Test planning is blocked while scheduler capacity is unavailable/,
      );
      assert.equal(await page.locator('#test-run-submit').isDisabled(), true);
      assert.equal(await page.locator('#test-run-dialog').getAttribute('open'), '',
        'a blocked planner must keep the exact choices visible for correction or retry');
      assert.equal(planRequests.length, 3);
      assert.equal(planRequests[2].repo_id, BLOCKED_REPO);
      assert.equal(planRequests[2].operation_id, OPERATION_IDS.blockedPlan);
      assert.deepEqual(planRequests[2].requested_targets, ['integration', 'unit']);
      assert.equal(submittedRequests.length, 2,
        'a blocked plan must never reach test submission');
      await page.locator('#test-run-cancel').click();

      assert.deepEqual(unexpectedRequests, []);
      const expectedBlockedResponses = browserErrors.filter((message) => (
        message.includes('Failed to load resource')
        && message.includes('503 (Service Unavailable)')
      ));
      assert.equal(expectedBlockedResponses.length, 1,
        `the one deliberate blocked-plan response must remain visible to Chromium: ${JSON.stringify(browserErrors)}`);
      assert.deepEqual(
        browserErrors.filter((message) => !expectedBlockedResponses.includes(message)),
        [],
        'the rendered journey must have no browser errors beyond its deliberate 503 fixture',
      );
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
