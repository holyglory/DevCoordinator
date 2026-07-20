#!/usr/bin/env node

import { createRequire } from 'node:module';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalTempDir, makeJar, login, startStack } from '../test/helpers/stack.mjs';
import {
  CANONICAL_FIXTURE_ID,
  CANONICAL_NOW,
  canonicalApiResponse,
} from './canonical-api-fixtures.mjs';
import { verifyArtifactPair, writeProvenance } from './canonical-artifacts.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const OUTPUT_ROOT = path.join(APP_ROOT, 'Artifacts', 'Canonical');
const GENERATOR = 'apps/DevOpsConsole/Tools/capture-canonical-artifacts.mjs';
const SOURCE_FILES = [
  GENERATOR,
  'apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs',
  'apps/DevOpsConsole/Tools/canonical-artifacts.mjs',
  'apps/DevOpsConsole/src/auth/pages.mjs',
  'apps/DevOpsConsole/src/ui/app.css',
  'apps/DevOpsConsole/src/ui/app.js',
  'apps/DevOpsConsole/src/ui/index.html',
  'apps/DevOpsConsole/test/helpers/stack.mjs',
  'ci/playwright/package-lock.json',
  'ci/playwright/package.json',
];

const CAPTURES = [
  { name: 'login-desktop.png', page: 'login', viewport: { width: 1440, height: 900 } },
  { name: 'login-mobile.png', page: 'login', viewport: { width: 390, height: 844 } },
  { name: 'projects-desktop.png', page: 'projects', viewport: { width: 1440, height: 900 } },
  { name: 'projects-mobile.png', page: 'projects', viewport: { width: 390, height: 844 } },
];

function loadLockedPlaywright() {
  const require = createRequire(import.meta.url);
  const roots = [
    ...String(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean),
    path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules'),
  ];
  for (const root of roots) {
    try {
      const manifest = require(path.join(root, 'playwright', 'package.json'));
      const locked = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
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

async function preparePage(context, unexpectedRequests, browserErrors) {
  const page = await context.newPage();
  page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') browserErrors.push(`console: ${message.text()}`);
  });
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const fixture = canonicalApiResponse(request.url(), request.method());
    if (fixture === null) {
      unexpectedRequests.push(`${request.method()} ${new URL(request.url()).pathname}`);
      await route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"unexpected fixture request"}' });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'cache-control': 'no-store' },
      body: JSON.stringify(fixture),
    });
  });
  return page;
}

async function settle(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

async function captureOne({ browser, stack, sessionCookie, definition }) {
  const browserErrors = [];
  const unexpectedRequests = [];
  const context = await browser.newContext({
    viewport: definition.viewport,
    deviceScaleFactor: 1,
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    timezoneId: 'UTC',
    colorScheme: 'dark',
    reducedMotion: 'reduce',
  });
  try {
    await context.addInitScript((fixedNow) => {
      const RealDate = Date;
      class FixedDate extends RealDate {
        constructor(...args) { super(...(args.length ? args : [fixedNow])); }
        static now() { return fixedNow; }
      }
      globalThis.Date = FixedDate;
    }, CANONICAL_NOW);
    if (definition.page === 'projects') {
      await context.addCookies([{
        name: sessionCookie.name,
        value: sessionCookie.value,
        domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
        path: sessionCookie.path,
        secure: sessionCookie.secure,
        httpOnly: sessionCookie.httpOnly,
        sameSite: 'Lax',
      }]);
    }
    const page = await preparePage(context, unexpectedRequests, browserErrors);
    const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
    if (definition.page === 'login') {
      await page.goto(`${origin}/auth/login`, { waitUntil: 'networkidle' });
      await page.waitForSelector('h1', { state: 'visible' });
    } else {
      await page.goto(`${origin}/#/projects`, { waitUntil: 'networkidle' });
      await page.waitForFunction(() => (
        document.querySelector('#projects-body .tree-node')
        && !document.querySelector('#projects-body .skel')
      ));
    }
    await settle(page);
    if (unexpectedRequests.length || browserErrors.length) {
      throw new Error([...unexpectedRequests.map((item) => `unexpected request: ${item}`), ...browserErrors].join('\n'));
    }
    const output = path.join(OUTPUT_ROOT, definition.name);
    await page.screenshot({ path: output, fullPage: false, animations: 'disabled' });
    await writeProvenance({
      pngPath: output,
      repoRoot: REPO_ROOT,
      fixtureId: `${CANONICAL_FIXTURE_ID}:${definition.page}:${definition.viewport.width}x${definition.viewport.height}`,
      generator: GENERATOR,
      viewport: definition.viewport,
      sourceFiles: SOURCE_FILES,
    });
    const provenance = await verifyArtifactPair(output);
    process.stdout.write(`${path.relative(REPO_ROOT, output)} ${provenance.sha256}\n`);
  } finally {
    await context.close();
  }
}

async function main() {
  const { chromium } = loadLockedPlaywright();
  await fsp.mkdir(OUTPUT_ROOT, { recursive: true });
  // The canonical renderer must never discover the developer host's real
  // Docker inventory. Mask only the semantic Docker executable with an empty,
  // successful fixture; the coordinator still exercises its full-Docker
  // observation contract, but the snapshot is deterministic and private host
  // resources cannot leak into capture state or failure output.
  const fakeBin = await canonicalTempDir('devops-console-canonical-dockerbin-');
  await fsp.writeFile(
    path.join(fakeBin, 'docker'),
    '#!/bin/sh\nexit 0\n',
    { encoding: 'utf8', mode: 0o755 },
  );
  let stack;
  let browser;
  try {
    stack = await startStack({
      allowedEmails: ['operator@example.test'],
      claims: { email: 'operator@example.test', name: 'Fixture Operator' },
      coordinatorEnv: { PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}` },
      expectDocker: true,
    });
    const jar = makeJar();
    const loginResult = await login(stack, jar);
    const sessionCookie = jar.get('dc_session');
    if (loginResult.status !== 200 || !sessionCookie) {
      throw new Error(`isolated fixture login failed with HTTP ${loginResult.status}`);
    }
    browser = await chromium.launch({
      headless: true,
      args: [`--host-resolver-rules=MAP ${stack.consoleHost} 127.0.0.1`],
    });
    for (const definition of CAPTURES) {
      await captureOne({ browser, stack, sessionCookie, definition });
    }
  } finally {
    if (browser) await browser.close();
    if (stack) await stack.close();
    await fsp.rm(fakeBin, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
