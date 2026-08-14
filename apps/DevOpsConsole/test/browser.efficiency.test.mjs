import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { login, makeJar, startStack } from './helpers/stack.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const REPOSITORY_ID = '123e4567-e89b-42d3-a456-426614174000';
const TOKEN_KEYS = ['input', 'cached_input', 'output', 'reasoning_output', 'tool', 'other'];
const PHASES = ['planning', 'implementation', 'testing', 'deployment', 'reporting', 'unattributed'];

function loadChromium() {
  const require = createRequire(import.meta.url);
  const locked = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
  for (const root of [path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules'), ...String(process.env.NODE_PATH || '').split(path.delimiter)]) {
    if (!root) continue;
    try {
      const manifest = require(path.join(root, 'playwright', 'package.json'));
      if (manifest.version !== locked.dependencies.playwright) continue;
      return require(path.join(root, 'playwright')).chromium;
    } catch { /* try next locked runtime location */ }
  }
  throw new Error('locked Playwright runtime is unavailable');
}

async function launch(chromium, stack) {
  for (const executablePath of [process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, '/usr/bin/google-chrome', '/usr/bin/chromium']) {
    if (executablePath && !fs.existsSync(executablePath)) continue;
    try {
      return await chromium.launch({
        headless: true,
        args: [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
        ...(executablePath ? { executablePath } : {}),
      });
    } catch { /* try the next installed browser */ }
  }
  return chromium.launch({ headless: true, args: [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`] });
}

const counter = (value, tasks = 4) => ({ known_sum: value, known_task_count: tasks, task_count: tasks, coverage: 'complete' });

function projection() {
  const tokens = Object.fromEntries(TOKEN_KEYS.map((key) => [key, counter(key === 'input' ? '12345' : key === 'output' ? '678' : '0')]));
  return {
    schema_version: 1,
    available: true,
    sampled_at_utc: '2026-08-12T20:00:00Z',
    invalid_projection_count: 0,
    repositories: [{
      repository_id: REPOSITORY_ID,
      display_name: 'Holy Skills',
      task_count: 4,
      complete_task_count: 3,
      outcomes: { complete: 3, incomplete: 1 },
      causes: { 'not-applicable': 4 },
      tokens,
      tokens_by_phase: Object.fromEntries(PHASES.map((phase) => [phase, {
        ...Object.fromEntries(TOKEN_KEYS.map((key) => [key, counter(phase === 'implementation' && key === 'input' ? '8000' : '0')])),
        usage_event_count: phase === 'unattributed' ? 1 : phase === 'implementation' ? 3 : 0,
      }])),
      request_to_delivery_ns: counter('4000000000'),
      execution_to_delivery_ns: counter('3000000000'),
      automation_opportunities: [{
        kind: 'deterministic-workflow-candidate', task_type: 'implementation',
        scope_size: 'small', current_method: 'direct', occurrence_count: 3,
        input_tokens: counter('10000', 3), tool_category_counts: {}, account_id: 'uid-1000',
        basis: 'at least three comparable non-automated terminal declarations',
        recommendation: 'review the repeated sequence for a script, harness, verifier, or reusable tool boundary',
      }],
      accounts: [{ account_id: 'uid-1000', recorded_at_utc: '2026-08-12T20:00:00Z', task_count: 4, complete_task_count: 3, tokens }],
    }],
  };
}

test('repository-first efficiency statistics and details work at desktop and mobile widths', { timeout: 150_000 }, async () => {
  const stack = await startStack({
    allowedEmails: ['operator@example.test'],
    claims: { email: 'operator@example.test', name: 'Operator' },
    enableEfficiency: true,
  });
  const jar = makeJar();
  let browser;
  try {
    assert.equal((await login(stack, jar)).status, 200);
    const cookie = jar.get('dc_session');
    browser = await launch(loadChromium(), stack);
    for (const viewport of [{ width: 981, height: 850 }, { width: 320, height: 850 }]) {
      const context = await browser.newContext({ viewport, ignoreHTTPSErrors: true, reducedMotion: 'reduce' });
      try {
        await context.addCookies([{
          name: cookie.name,
          value: cookie.value,
          domain: cookie.hostOnly ? cookie.domain : `.${cookie.domain}`,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: 'Lax',
        }]);
        const page = await context.newPage();
        const pageErrors = [];
        page.on('pageerror', (error) => pageErrors.push(String(error?.stack || error)));
        let requests = 0;
        await page.route('**/api/efficiency', async (route) => {
          requests += 1;
          await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(projection()) });
        });
        await page.goto(`https://${stack.consoleHost}:${stack.httpsPort}/#/efficiency`, { waitUntil: 'domcontentloaded' });
        try {
          await page.locator('#efficiency-body .efficiency-row').waitFor({ timeout: 10_000 });
        } catch (error) {
          const diagnostic = await page.evaluate(() => ({
            href: location.href,
            title: document.title,
            body: document.querySelector('#efficiency-body')?.innerText || null,
            sectionHidden: document.querySelector('#sec-efficiency')?.hidden ?? null,
            navHidden: document.querySelector('#nav-efficiency')?.hidden ?? null,
          }));
          throw new Error(`efficiency page did not render: ${JSON.stringify({ requests, pageErrors, diagnostic })}`, { cause: error });
        }
        assert.equal(await page.locator('#efficiency-body .efficiency-row').count(), 1);
        assert.match(await page.locator('#efficiency-body').innerText(), /Holy Skills/);
        assert.doesNotMatch(await page.locator('#efficiency-body').innerText(), new RegExp(REPOSITORY_ID));
        await page.locator('#efficiency-body .efficiency-row').click();
        await page.locator('#efficiency-detail-dialog').waitFor({ state: 'visible' });
        const detail = await page.locator('#efficiency-detail-dialog').innerText();
        assert.match(detail, /Provider token categories/);
        assert.match(detail, /Tokens by phase/);
        assert.match(detail, /Accounts/);
        assert.match(detail, /Automation candidates/);
        await page.locator('#efficiency-detail-close').click();
        assert.equal(await page.locator('#efficiency-detail-dialog').isVisible(), false);
        await page.locator('#efficiency-refresh').click();
        assert.ok(requests >= 2);
        const geometry = await page.evaluate(() => ({
          viewport: innerWidth,
          document: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
          section: document.querySelector('#sec-efficiency').scrollWidth,
          sectionClient: document.querySelector('#sec-efficiency').clientWidth,
        }));
        assert.ok(geometry.document <= geometry.viewport + 1, JSON.stringify(geometry));
        assert.ok(geometry.section <= geometry.sectionClient + 1, JSON.stringify(geometry));
      } finally {
        await context.close();
      }
    }
  } finally {
    await browser?.close();
    await stack.close();
  }
});
