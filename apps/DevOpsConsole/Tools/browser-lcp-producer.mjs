#!/usr/bin/env node
// Produce bounded, secret-free browser timing observations for the immutable
// availability cutover.  The Python acceptance wrapper validates every input,
// pins the runtime, checks the live edge identity, seals the result, and owns
// the final attestation.  This driver never serializes cookies, storage state,
// response bodies, page text, console output, or arbitrary errors.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const REQUEST_KIND = 'devcoordinator-browser-lcp-request';
const OBSERVATION_KIND = 'devcoordinator-browser-lcp-observation';
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_TIMEOUT_MS = 30_000;
const REQUIRED_WIDTHS = [320, 390, 768, 981, 1440];
const TESTS_REPOSITORY_CONTROL_SELECTOR = [
  '#tests-body .test-repository-button:visible',
  '#tests-body .test-fleet-mobile-row:visible',
].join(', ');
const EXACT_REQUEST_FIELDS = new Set([
  'schema_version',
  'kind',
  'operation_id',
  'playwright_module',
  'playwright_version',
  'browser_executable',
  'browser_product_version',
  'storage_state',
  'console_url',
  'tests_url',
  'viewports',
  'navigation_timeout_ms',
  'retained_warm_delay_ms',
]);

function fail(message) {
  throw new Error(message);
}

function exactFields(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const keys = Object.keys(value);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) fail(`${label} fields are invalid`);
}

function canonicalAbsolute(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\0') || !path.isAbsolute(value)) {
    fail(`${label} must be one absolute path`);
  }
  const resolved = fs.realpathSync(value);
  if (resolved !== path.resolve(value)) fail(`${label} must already be canonical`);
  return resolved;
}

function readBoundedJson(file, maximum, label) {
  const absolute = canonicalAbsolute(file, label);
  const info = fs.lstatSync(absolute);
  if (!info.isFile() || info.isSymbolicLink() || info.size > maximum) fail(`${label} is not one bounded regular file`);
  let value;
  try {
    value = JSON.parse(fs.readFileSync(absolute, 'utf8'));
  } catch {
    fail(`${label} is not valid JSON`);
  }
  return value;
}

function parseArgs(argv) {
  if (argv.length !== 4 || argv[0] !== '--request' || argv[2] !== '--output') {
    fail('usage: browser-lcp-producer.mjs --request PATH --output PATH');
  }
  return { request: argv[1], output: argv[3] };
}

function validateUrl(value, expectedHash, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} is invalid`);
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.pathname !== '/'
    || parsed.hash !== expectedHash
  ) fail(`${label} is not the exact HTTPS Console route`);
  return parsed;
}

function validateRequest(value) {
  exactFields(value, EXACT_REQUEST_FIELDS, 'browser request');
  if (value.schema_version !== 1 || value.kind !== REQUEST_KIND) fail('browser request contract is unsupported');
  if (typeof value.operation_id !== 'string' || !/^[a-f0-9-]{36}$/.test(value.operation_id)) {
    fail('browser request operation id is invalid');
  }
  const consoleUrl = validateUrl(value.console_url, '', 'console URL');
  const testsUrl = validateUrl(value.tests_url, '#/tests', 'Tests URL');
  if (consoleUrl.origin !== testsUrl.origin) fail('Console and Tests URLs must have one origin');
  const playwrightModule = canonicalAbsolute(value.playwright_module, 'Playwright module');
  const browserExecutable = canonicalAbsolute(value.browser_executable, 'browser executable');
  const storageState = canonicalAbsolute(value.storage_state, 'storage state');
  if (typeof value.playwright_version !== 'string' || !/^\d+\.\d+\.\d+$/.test(value.playwright_version)) {
    fail('Playwright version is invalid');
  }
  if (typeof value.browser_product_version !== 'string' || !/^\d+(?:\.\d+){1,4}$/.test(value.browser_product_version)) {
    fail('browser product version is invalid');
  }
  if (
    !Number.isInteger(value.navigation_timeout_ms)
    || value.navigation_timeout_ms < 1_000
    || value.navigation_timeout_ms > MAX_TIMEOUT_MS
  ) fail('navigation timeout is invalid');
  if (
    !Number.isInteger(value.retained_warm_delay_ms)
    || value.retained_warm_delay_ms < 15_000
    || value.retained_warm_delay_ms > 20_000
  ) fail('retained warm delay is invalid');
  if (!Array.isArray(value.viewports) || value.viewports.length !== REQUIRED_WIDTHS.length) {
    fail('browser request viewports are incomplete');
  }
  const widths = [];
  for (const viewport of value.viewports) {
    exactFields(viewport, new Set(['width', 'height']), 'browser viewport');
    if (
      !Number.isInteger(viewport.width)
      || !Number.isInteger(viewport.height)
      || viewport.height < 600
      || viewport.height > 1400
    ) fail('browser viewport dimensions are invalid');
    widths.push(viewport.width);
  }
  if (JSON.stringify(widths) !== JSON.stringify(REQUIRED_WIDTHS)) fail('browser viewport widths are invalid');
  return {
    ...value,
    consoleUrl,
    testsUrl,
    playwrightModule,
    browserExecutable,
    storageState,
  };
}

function assertOutputParent(output) {
  if (typeof output !== 'string' || !path.isAbsolute(output) || output.includes('\0')) {
    fail('browser observation output must be absolute');
  }
  const parent = fs.realpathSync(path.dirname(output));
  if (parent !== path.resolve(path.dirname(output))) fail('browser observation parent must already be canonical');
  const info = fs.lstatSync(parent);
  if (!info.isDirectory() || info.isSymbolicLink()) fail('browser observation parent must be a real directory');
  if (fs.existsSync(output)) fail('browser observation output already exists');
  return path.join(parent, path.basename(output));
}

function atomicPrivateWrite(output, value) {
  const payload = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (payload.length > MAX_OUTPUT_BYTES) fail('browser observation exceeds its byte bound');
  const temporary = path.join(path.dirname(output), `.${path.basename(output)}.${process.pid}.${Date.now()}.partial`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, payload);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.linkSync(temporary, output);
    fs.unlinkSync(temporary);
    const parent = fs.openSync(path.dirname(output), fs.constants.O_RDONLY);
    try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch { /* no retained partial */ }
  }
}

function installLcpObserver(page) {
  return page.addInitScript(() => {
    globalThis.__devcoordinatorLcp = { value: null, entries: 0 };
    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          const value = Number(entry.renderTime || entry.loadTime || entry.startTime);
          if (Number.isFinite(value) && value >= 0) {
            globalThis.__devcoordinatorLcp.value = value;
            globalThis.__devcoordinatorLcp.entries += 1;
          }
        }
      });
      observer.observe({ type: 'largest-contentful-paint', buffered: true });
      globalThis.__devcoordinatorLcpObserver = observer;
    } catch {
      globalThis.__devcoordinatorLcp = { value: null, entries: 0 };
    }
  });
}

async function authenticated(page) {
  return page.evaluate(async () => {
    try {
      const response = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) return false;
      const value = await response.json();
      return typeof value?.email === 'string' && value.email.length > 3;
    } catch {
      return false;
    }
  });
}

async function settleLcp(page) {
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await page.waitForTimeout(250);
  const lcp = await page.evaluate(() => ({
    value: globalThis.__devcoordinatorLcp?.value ?? null,
    entries: globalThis.__devcoordinatorLcp?.entries ?? 0,
  }));
  if (!Number.isFinite(lcp.value) || lcp.value < 0 || !Number.isInteger(lcp.entries) || lcp.entries < 1) {
    fail('native Largest Contentful Paint was not observed');
  }
  return { lcp_ms: Math.round(lcp.value * 100) / 100, lcp_entry_count: lcp.entries };
}

async function newContext(browser, request, viewport) {
  const context = await browser.newContext({
    viewport,
    storageState: request.storageState,
    locale: 'en-US',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    acceptDownloads: false,
    serviceWorkers: 'block',
  });
  await context.route('**/*', async (route) => {
    const target = new URL(route.request().url());
    if (target.origin === request.consoleUrl.origin || target.protocol === 'data:' || target.protocol === 'blob:') {
      await route.continue();
    } else {
      await route.abort('blockedbyclient');
    }
  });
  return context;
}

async function warmRetainedTests(browser, request) {
  const context = await newContext(browser, request, request.viewports[0]);
  const page = await context.newPage();
  page.setDefaultTimeout(request.navigation_timeout_ms);
  try {
    const fleetResponse = page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/api/tests/fleet',
      { timeout: request.navigation_timeout_ms },
    );
    await page.goto(request.tests_url, { waitUntil: 'domcontentloaded', timeout: request.navigation_timeout_ms });
    const response = await fleetResponse;
    if (response.status() !== 200 || !(await authenticated(page))) fail('retained Tests warm-up was not authenticated');
    const payload = await response.json();
    const state = payload?.snapshot?.delivery?.state;
    if (state !== 'retained') await page.waitForTimeout(request.retained_warm_delay_ms);
  } finally {
    await context.close();
  }
}

async function measure(browser, request, viewport, journey) {
  const context = await newContext(browser, request, viewport);
  const page = await context.newPage();
  page.setDefaultTimeout(request.navigation_timeout_ms);
  await installLcpObserver(page);
  try {
    let fleetResponse = null;
    if (journey === 'tests') {
      fleetResponse = page.waitForResponse(
        (response) => new URL(response.url()).pathname === '/api/tests/fleet',
        { timeout: request.navigation_timeout_ms },
      );
    }
    const exactUrl = journey === 'tests' ? request.tests_url : request.console_url;
    const navigation = await page.goto(exactUrl, {
      waitUntil: 'domcontentloaded',
      timeout: request.navigation_timeout_ms,
    });
    if (!navigation || navigation.status() !== 200 || page.url() !== exactUrl) {
      fail('browser navigation did not retain the exact accepted URL');
    }
    const isAuthenticated = await authenticated(page);
    if (!isAuthenticated || new URL(page.url()).pathname.startsWith('/auth/')) {
      fail('browser navigation is not authenticated');
    }

    let fleetDeliveryState = null;
    let retainedTests = false;
    let state;
    let apiStatus = null;
    if (journey === 'tests') {
      const response = await fleetResponse;
      apiStatus = response.status();
      if (apiStatus !== 200) fail('retained Tests projection was unavailable');
      const contentLength = Number(response.headers()['content-length'] || 0);
      if (contentLength > 8 * 1024 * 1024) fail('retained Tests projection exceeded its byte bound');
      const fleet = await response.json();
      fleetDeliveryState = fleet?.snapshot?.delivery?.state ?? null;
      if (
        fleet?.schema_version !== 2
        || !Array.isArray(fleet?.repositories)
        || fleet.repositories.length < 1
        || fleetDeliveryState !== 'retained'
      ) fail('Tests did not render from the retained authenticated projection');
      await page.waitForSelector('#sec-tests:not([hidden])', { state: 'visible' });
      await page.waitForSelector('#tests-body .test-fleet-summary', { state: 'visible' });
      await page.waitForSelector(TESTS_REPOSITORY_CONTROL_SELECTOR, { state: 'visible' });
      const invalidState = await page.locator('#tests-body .skel, #tests-body .test-local-failure').count();
      if (invalidState !== 0) fail('Tests retained state still contains loading or failure content');
      retainedTests = true;
      state = 'authenticated_retained_tests';
    } else {
      await page.waitForSelector('header', { state: 'visible' });
      await page.waitForSelector('main', { state: 'visible' });
      state = 'authenticated_console_shell';
    }
    const lcp = await settleLcp(page);
    return {
      journey,
      url: exactUrl,
      final_url: page.url(),
      viewport: { width: viewport.width, height: viewport.height },
      navigation_status: navigation.status(),
      api_status: apiStatus,
      authenticated: true,
      retained_tests: retainedTests,
      fleet_delivery_state: fleetDeliveryState,
      state,
      ...lcp,
      observed_at: new Date().toISOString(),
    };
  } finally {
    await context.close();
  }
}

async function run(request) {
  const imported = await import(pathToFileURL(request.playwrightModule).href);
  if (!imported?.chromium || typeof imported.chromium.launch !== 'function') fail('pinned Playwright module has no Chromium launcher');
  const browser = await imported.chromium.launch({
    executablePath: request.browserExecutable,
    headless: true,
  });
  try {
    if (browser.version() !== request.browser_product_version) fail('launched browser version differs from the runtime lock');
    await warmRetainedTests(browser, request);
    // Tests samples start together so all five consume the retained projection
    // before its one background refresh can replace the cache generation.
    const testSamples = await Promise.all(request.viewports.map((viewport) => measure(browser, request, viewport, 'tests')));
    const consoleSamples = await Promise.all(request.viewports.map((viewport) => measure(browser, request, viewport, 'console')));
    const byWidth = new Map(request.viewports.map((viewport, index) => [
      viewport.width,
      [consoleSamples[index], testSamples[index]],
    ]));
    return request.viewports.flatMap((viewport) => byWidth.get(viewport.width));
  } finally {
    await browser.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const request = validateRequest(readBoundedJson(args.request, MAX_REQUEST_BYTES, 'browser request'));
  const output = assertOutputParent(args.output);
  const startedAt = new Date().toISOString();
  const deadlineMs = request.navigation_timeout_ms * 3 + request.retained_warm_delay_ms;
  let timer;
  try {
    const samples = await Promise.race([
      run(request),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('browser acceptance deadline exceeded')), deadlineMs);
      }),
    ]);
    const document = {
      schema_version: 1,
      kind: OBSERVATION_KIND,
      operation_id: request.operation_id,
      playwright_version: request.playwright_version,
      browser_product_version: request.browser_product_version,
      console_url: request.console_url,
      tests_url: request.tests_url,
      samples,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
    };
    atomicPrivateWrite(output, document);
    process.stdout.write('{"ok":true,"sample_count":10}\n');
  } finally {
    if (timer) clearTimeout(timer);
  }
}

main().catch(() => {
  // Deliberately omit raw browser, page, authentication, and path errors from
  // stdout/stderr.  The parent emits one fixed failure classification.
  process.stderr.write('browser LCP observation failed\n');
  process.exitCode = 1;
});
