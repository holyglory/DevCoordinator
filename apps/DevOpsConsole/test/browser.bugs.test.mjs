// Real-browser regression for the open Coordinator bug collection. The
// shipped Console shell is real; bounded API fixtures keep the journey
// deterministic and prove that a failed Coordinator inventory refresh cannot
// clear or banner the independently retained bug registry.

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CANONICAL_ACCESS,
  CANONICAL_ARCHIVES,
  CANONICAL_INVITES,
  CANONICAL_METRICS,
  CANONICAL_PREFS,
  CANONICAL_SESSION,
  CANONICAL_TELEGRAM,
} from '../Tools/canonical-api-fixtures.mjs';
import { canonicalTempDir, login, makeJar, startStack } from './helpers/stack.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const BUG_ID = 'bug-11111111111111111111111111111111';
const IMPORTED_BUG_ID = 'bug-22222222222222222222222222222222';

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
  throw new Error('locked Playwright runtime is unavailable');
}

async function launchChromium(chromium, args) {
  const configured = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  const candidates = [
    null,
    configured,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter((item, index, values) => item === null || (item && values.indexOf(item) === index));
  const failures = [];
  for (const executablePath of candidates) {
    if (executablePath && !fs.existsSync(executablePath)) continue;
    try {
      return await chromium.launch({
        headless: true,
        args,
        ...(executablePath ? { executablePath } : {}),
      });
    } catch (error) {
      failures.push(String(error.message).split('\n')[0]);
    }
  }
  throw new Error(`could not launch Chromium: ${failures.join('; ')}`);
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

function openBugPayload(bugs) {
  return {
    schema_version: 1,
    generated_at: '2026-08-04T11:00:00.000Z',
    revision: bugs.length ? 'revision-open' : 'revision-empty',
    bugs,
  };
}

function bugFixture() {
  return {
    bug_id: BUG_ID,
    fingerprint: '2'.repeat(64),
    component: 'test runner launch',
    summary: 'Immutable runner could not resolve the declared Python toolchain',
    expected: 'The selected target starts inside the immutable test materialization.',
    actual: 'The runner rejected the dependency path before any test case executed.',
    reproduction_steps: [
      'Validate the repository test manifest.',
      'Plan an immutable change run for the repository.',
      'Submit the plan and inspect the first target attempt.',
    ],
    command_argv: [
      'devcoordinator-test', 'plan', '--root-repo', '$REPOSITORY',
      '--token', '[redacted]', '--intent', 'change',
    ],
    reporter: 'codex',
    peer_uid: 1000,
    first_seen_at: '2026-08-04T10:50:00.000Z',
    last_seen_at: '2026-08-04T10:59:00.000Z',
    occurrence_count: 3,
    surface: 'test plan',
    stage: 'admission',
    classification: 'infrastructure_failure',
    code: 'dependency_path_unavailable',
    operation: 'test.plan',
    repository: 'GlobalFinance',
    release_digest: '3'.repeat(64),
    instance_id: 'console-blue',
    correlations: {
      call_id: 'call-example',
      operation_id: 'operation-example',
      run_id: 'run-example',
      attempt_id: 'attempt-example',
    },
    local_fallback: {
      status: 'passed',
      summary: 'A focused local unit run passed while the shared harness was unavailable.',
      advisory: true,
      coordinator_evidence: false,
      command_argv: ['npm', 'test', '--', '--runInBand'],
    },
    origin: {
      kind: 'local',
      server_id: 'console.example.test',
      bug_id: BUG_ID,
      fingerprint: '2'.repeat(64),
    },
  };
}

function importedBugFixture() {
  return {
    ...bugFixture(),
    bug_id: IMPORTED_BUG_ID,
    fingerprint: '4'.repeat(64),
    component: 'remote test runner',
    summary: 'Remote immutable runner could not materialize dependencies',
    origin: {
      kind: 'remote',
      server_id: 'remote.example.test',
      bug_id: `bug-${'9'.repeat(32)}`,
      fingerprint: '9'.repeat(64),
    },
  };
}

function exportPayload(bugs) {
  return {
    schema_version: 1,
    kind: 'devcoordinator-open-bugs',
    exporting_server: 'console.example.test',
    exported_at: '2026-08-05T10:00:00.000Z',
    bugs,
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

async function exerciseViewport(browser, stack, sessionCookie, viewport) {
  const context = await browser.newContext({
    viewport,
    ignoreHTTPSErrors: true,
    colorScheme: 'dark',
    reducedMotion: 'reduce',
  });
  const fixture = {
    bugs: [bugFixture()],
    failBugs: false,
    deleteCount: 0,
    importCount: 0,
    overviewFailures: 0,
    bugRefreshFailures: 0,
    unexpected: [],
  };
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
    const browserErrors = [];
    page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`));
    page.on('console', (message) => {
      if (message.type() !== 'error') return;
      const text = message.text();
      // Chromium logs expected non-2xx resource responses even though the app
      // handles them. The exact 503 counts below prove these two intentional
      // failure paths while every other browser error remains fatal.
      if (/Failed to load resource: .*503 \(Service Unavailable\)/.test(text)) return;
      browserErrors.push(`console: ${text}`);
    });
    await page.route('**/api/**', async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const method = request.method();
      if (method === 'GET' && pathname === '/api/session') {
        await fulfillJson(route, 200, { ...CANONICAL_SESSION, lifecycleAvailable: false });
      } else if (method === 'GET' && pathname === '/api/prefs') {
        await fulfillJson(route, 200, CANONICAL_PREFS);
      } else if (method === 'GET' && pathname === '/api/overview') {
        fixture.overviewFailures += 1;
        await fulfillJson(route, 503, {
          error: 'Coordinator inventory is unavailable in this browser fixture.',
          code: 'coordinator_unavailable',
        });
      } else if (method === 'GET' && pathname === '/api/metrics/history') {
        await fulfillJson(route, 200, CANONICAL_METRICS);
      } else if (method === 'GET' && pathname === '/api/access') {
        await fulfillJson(route, 200, CANONICAL_ACCESS);
      } else if (method === 'GET' && pathname === '/api/access/requests') {
        await fulfillJson(route, 200, CANONICAL_INVITES);
      } else if (method === 'GET' && pathname === '/api/telegram') {
        await fulfillJson(route, 200, CANONICAL_TELEGRAM);
      } else if (method === 'GET' && pathname === '/api/lifecycle/list') {
        await fulfillJson(route, 200, CANONICAL_ARCHIVES);
      } else if (method === 'GET' && pathname === '/api/bugs') {
        if (fixture.failBugs) {
          fixture.bugRefreshFailures += 1;
          await fulfillJson(route, 503, {
            error: 'The open-bug registry is temporarily unavailable.',
            code: 'bug_store_unavailable',
          });
        } else {
          await fulfillJson(route, 200, openBugPayload(fixture.bugs));
        }
      } else if (method === 'GET' && pathname === '/api/bugs/export') {
        await fulfillJson(route, 200, exportPayload(fixture.bugs));
      } else if (method === 'POST' && pathname === '/api/bugs/import') {
        const body = request.postDataJSON();
        assert.equal(body.kind, 'devcoordinator-open-bugs');
        fixture.importCount += 1;
        fixture.bugs.push(importedBugFixture());
        await fulfillJson(route, 200, {
          ...openBugPayload(fixture.bugs),
          import_result: { received: 1, imported: 1, already_present: 0 },
        });
      } else if (method === 'DELETE' && pathname === `/api/bugs/${BUG_ID}`) {
        fixture.deleteCount += 1;
        fixture.bugs = fixture.bugs.filter((bug) => bug.bug_id !== BUG_ID);
        await fulfillJson(route, 200, openBugPayload(fixture.bugs));
      } else if (method === 'DELETE' && pathname === `/api/bugs/${IMPORTED_BUG_ID}`) {
        fixture.deleteCount += 1;
        fixture.bugs = fixture.bugs.filter((bug) => bug.bug_id !== IMPORTED_BUG_ID);
        await fulfillJson(route, 200, openBugPayload(fixture.bugs));
      } else {
        fixture.unexpected.push(`${method} ${pathname}`);
        await fulfillJson(route, 404, { error: 'Unexpected browser fixture request.' });
      }
    });

    await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/bugs`, {
      waitUntil: 'domcontentloaded',
    });
    const card = page.locator(`[data-bug-id="${BUG_ID}"]`);
    await card.waitFor();
    assert.equal(await page.locator('#bugs-body .bug-card').count(), 1);
    assert.match(await card.innerText(), /test runner launch/i);
    assert.match(await card.innerText(), /3 occurrences/i);
    assert.equal(await page.locator('#banner-slot .banner').count(), 0,
      'a Coordinator inventory failure must not become a global Bugs banner');

    await page.locator('#bugs-export').click();
    const exportDialog = page.locator('#bugs-export-dialog');
    await exportDialog.waitFor({ state: 'visible' });
    const exportedText = await page.locator('#bugs-export-json').inputValue();
    assert.match(exportedText, /"kind": "devcoordinator-open-bugs"/);
    assert.match(exportedText, new RegExp(BUG_ID));
    await page.locator('#bugs-export-copy').click();
    const selection = await page.locator('#bugs-export-json').evaluate((node) => ({
      start: node.selectionStart,
      end: node.selectionEnd,
      length: node.value.length,
    }));
    assert.deepEqual(selection, { start: 0, end: selection.length, length: selection.length },
      'the full JSON stays selected for manual copying when clipboard access is unavailable');
    await page.locator('#bugs-export-cancel').click();
    assert.equal(await page.locator('#bugs-export').evaluate((node) => document.activeElement === node), true,
      'closing export restores focus to its trigger');

    await page.locator('#bugs-import').click();
    const importDialog = page.locator('#bugs-import-dialog');
    await importDialog.waitFor({ state: 'visible' });
    await page.locator('#bugs-import-json').fill(JSON.stringify(exportPayload([importedBugFixture()])));
    await page.locator('#bugs-import-submit').click();
    await page.locator(`[data-bug-id="${IMPORTED_BUG_ID}"]`).waitFor();
    assert.match(
      await page.locator(`[data-bug-id="${IMPORTED_BUG_ID}"]`).innerText(),
      /Imported from remote\.example\.test/i,
    );
    assert.equal(fixture.importCount, 1);

    const details = card.locator('details.bug-details');
    await details.locator(':scope > summary').click();
    assert.equal(await details.evaluate((node) => node.open), true);
    const detailText = await details.innerText();
    for (const expected of [
      'Expected',
      'Actual',
      'Reproduce',
      'Coordinator command',
      'Coordinator release',
      'Coordinator instance',
      'console-blue',
      'Local fallback',
      'A focused local unit run passed',
      'Advisory local check only — this is not governed Coordinator evidence.',
    ]) {
      assert.match(detailText, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
    }
    assert.equal(await details.locator('.bug-reproduction li').count(), 3);
    assert.match(detailText, /\[redacted\]/,
      'the visible reproduction must use the already-redacted command');
    const argv = details.locator('.bug-argv-disclosure').first();
    await argv.locator('summary').click();
    assert.equal(await argv.locator('li').count(), 8,
      'the UI must preserve structured Coordinator argument boundaries');

    fixture.failBugs = true;
    await page.locator('#bugs-refresh').click();
    await page.locator('#bugs-retained:not([hidden])').waitFor();
    assert.match(await page.locator('#bugs-retained').innerText(), /showing 2 retained open reports/i);
    assert.equal(await page.locator('#bugs-body .bug-card').count(), 2,
      'a refresh error must retain the previously rendered open collection');
    assert.equal(await details.evaluate((node) => node.open), true,
      'a refresh must preserve the user-opened reproducer');
    assert.equal(await page.locator('#banner-slot .banner').count(), 0,
      'a local bug-registry refresh error must remain inside the Bugs page');

    const geometry = await page.evaluate(() => ({
      viewport: window.innerWidth,
      document: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
      section: document.querySelector('#sec-bugs').scrollWidth,
      sectionClient: document.querySelector('#sec-bugs').clientWidth,
    }));
    assert.ok(geometry.document <= geometry.viewport + 1,
      `${viewport.width}px Bugs page must not overflow the document: ${JSON.stringify(geometry)}`);
    assert.ok(geometry.section <= geometry.sectionClient + 1,
      `${viewport.width}px Bugs collection must not overflow its card: ${JSON.stringify(geometry)}`);

    fixture.failBugs = false;
    page.once('dialog', (dialog) => dialog.accept());
    await card.locator('button[aria-label^="Close Coordinator bug:"]').click();
    page.once('dialog', (dialog) => dialog.accept());
    await page.locator(`[data-bug-id="${IMPORTED_BUG_ID}"] button[aria-label^="Close Coordinator bug:"]`).click();
    await page.locator('.bugs-empty').waitFor();
    assert.equal(fixture.deleteCount, 2);
    assert.ok(fixture.overviewFailures >= 1,
      'the journey must exercise an unavailable Coordinator inventory API');
    assert.equal(fixture.bugRefreshFailures, 1,
      'the journey must exercise exactly one retained-state refresh failure');
    assert.equal(await page.locator('#bugs-body .bug-card').count(), 0);
    assert.equal(await page.locator('#nav-count-bugs').evaluate((node) => node.hidden), true,
      'the Bugs navigation badge must be hidden at zero');
    assert.match(await page.locator('.bugs-empty').innerText(), /No open Coordinator bugs/i);
    assert.deepEqual(fixture.unexpected, []);
    assert.deepEqual(browserErrors, []);
  } finally {
    await context.close();
  }
}

test('Open bugs stay actionable during Coordinator failure on desktop and 320px mobile',
  { timeout: 150_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    const fakeDockerDir = await canonicalTempDir('devops-console-browser-bugs-');
    await writeEmptyDockerFixture(fakeDockerDir);
    let stack;
    let browser;
    try {
      stack = await startStack({
        allowedEmails: [CANONICAL_SESSION.email],
        claims: { email: CANONICAL_SESSION.email, name: CANONICAL_SESSION.name },
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
      const failures = [];
      for (const viewport of [{ width: 981, height: 900 }, { width: 320, height: 900 }]) {
        try {
          await exerciseViewport(browser, stack, sessionCookie, viewport);
        } catch (error) {
          failures.push(new Error(`${viewport.width}px: ${error.message}`, { cause: error }));
        }
      }
      if (failures.length) {
        throw new AggregateError(
          failures,
          `Bugs browser matrix found ${failures.length} independent failure(s):\n`
            + failures.map((error, index) => `${index + 1}. ${error.message}`).join('\n'),
        );
      }
    } finally {
      await browser?.close();
      await stack?.close();
      await fs.promises.rm(fakeDockerDir, { recursive: true, force: true });
    }
  });
