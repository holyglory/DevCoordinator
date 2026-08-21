#!/usr/bin/env node

// Production-safe, read-only Console acceptance. The browser is prevented from
// issuing mutations: only GET/HEAD/OPTIONS and the two log-read POST endpoints
// are allowed. Dialogs are opened and cancelled without submitting forms.

import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const TOOL_PATH = fileURLToPath(import.meta.url);
const APP_ROOT = path.resolve(path.dirname(TOOL_PATH), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');

export const VIEWPORTS = Object.freeze([
  Object.freeze({ width: 320, height: 900 }),
  Object.freeze({ width: 390, height: 900 }),
  Object.freeze({ width: 768, height: 1000 }),
  Object.freeze({ width: 981, height: 1000 }),
  Object.freeze({ width: 1440, height: 1000 }),
]);

export const KNOWN_ROUTES = Object.freeze([
  'projects',
  'tests',
  'bugs',
  'servers',
  'routes',
  'docker',
  'ports',
  'performance',
  'access',
  'invites',
  'telegram',
]);

// These nodes intentionally use the standard screen-reader-only clipping
// technique.  They remain part of the accessibility tree, but their 1px box
// is not visual text-fit evidence.
export const GEOMETRY_IGNORED_CLASSES = Object.freeze(['visually-hidden']);

const REPORT_KIND = 'devops-console-production-playwright-acceptance';
const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const MAX_STORAGE_STATE_BYTES = 2 * 1024 * 1024;
const MAX_ITEMS = 20;
const MAX_TEXT_BYTES = 320;
const NAVIGATION_TIMEOUT_MS = 20_000;
const LOADING_TIMEOUT_MS = 20_000;
const JOURNEY_ACTION_TIMEOUT_MS = 2_000;
const TRANSIENT_NAVIGATION_ATTEMPTS = 2;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const SAFE_READ_POST_PATHS = new Set(['/api/servers/logs', '/api/docker/logs']);
const STATEFUL_GET_PREFIXES = Object.freeze(['/auth/']);

function fail(message) {
  throw new Error(message);
}

function text(value, maximumBytes = MAX_TEXT_BYTES) {
  const payload = Buffer.from(String(value ?? ''), 'utf8');
  if (payload.length <= maximumBytes) return payload.toString('utf8');
  const suffix = Buffer.from('…[truncated]', 'utf8');
  return Buffer.concat([
    payload.subarray(0, Math.max(0, maximumBytes - suffix.length)),
    suffix,
  ]).toString('utf8');
}

export function isTransientNavigationError(value) {
  return /net::ERR_(?:NETWORK_CHANGED|CONNECTION_RESET|CONNECTION_CLOSED|CONNECTION_ABORTED)/i
    .test(String(value || ''));
}

function collector(limit = MAX_ITEMS) {
  const items = [];
  let suppressed = 0;
  return {
    push(value) {
      if (items.length < limit) items.push(value);
      else suppressed += 1;
    },
    report() {
      return { items, suppressed };
    },
  };
}

function oneAbsolute(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\0') || !path.isAbsolute(value)) {
    fail(`${label} must be one absolute path`);
  }
  return path.resolve(value);
}

export function normalizeBaseUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('--base-url must be one valid URL');
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
  ) {
    fail('--base-url must be one credential-free HTTPS URL without query or hash');
  }
  if (!parsed.pathname.endsWith('/')) parsed.pathname += '/';
  return parsed;
}

export function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--base-url', '--storage-state', '--output-dir'].includes(flag) || value === undefined) {
      fail('usage: production-console-acceptance.mjs --base-url URL --storage-state PATH --output-dir PATH');
    }
    if (Object.hasOwn(values, flag)) fail(`${flag} was provided more than once`);
    values[flag] = value;
  }
  if (Object.keys(values).length !== 3) {
    fail('usage: production-console-acceptance.mjs --base-url URL --storage-state PATH --output-dir PATH');
  }
  return {
    baseUrl: normalizeBaseUrl(values['--base-url']),
    storageState: oneAbsolute(values['--storage-state'], '--storage-state'),
    outputDir: oneAbsolute(values['--output-dir'], '--output-dir'),
  };
}

export function isPermittedRequest(method, requestUrl, baseUrl) {
  const normalizedMethod = String(method || '').toUpperCase();
  let target;
  try {
    target = new URL(requestUrl);
  } catch {
    return false;
  }
  const base = baseUrl instanceof URL ? baseUrl : normalizeBaseUrl(baseUrl);
  if (target.origin !== base.origin) return false;
  if (normalizedMethod === 'GET') {
    return !STATEFUL_GET_PREFIXES.some((prefix) => target.pathname.startsWith(prefix));
  }
  if (SAFE_METHODS.has(normalizedMethod)) return true;
  return normalizedMethod === 'POST' && SAFE_READ_POST_PATHS.has(target.pathname);
}

function validateStorageState(storageState) {
  const info = fs.lstatSync(storageState);
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_STORAGE_STATE_BYTES) {
    fail('--storage-state must be one bounded regular JSON file');
  }
  const payload = fs.readFileSync(storageState);
  try {
    const document = JSON.parse(payload);
    if (!document || typeof document !== 'object' || Array.isArray(document)) {
      fail('--storage-state must contain one JSON object');
    }
  } catch (error) {
    if (String(error.message).startsWith('--storage-state')) throw error;
    fail('--storage-state is not valid JSON');
  }
  return {
    size: payload.length,
    sha256: crypto.createHash('sha256').update(payload).digest('hex'),
  };
}

function prepareOutputDirectory(outputDir) {
  fs.mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(outputDir);
  if (!info.isDirectory() || info.isSymbolicLink()) fail('--output-dir must be one real directory');
  const screenshots = path.join(outputDir, 'screenshots');
  fs.mkdirSync(screenshots, { mode: 0o700 });
  for (const destination of [path.join(outputDir, 'report.json')]) {
    if (fs.existsSync(destination)) fail(`output already exists: ${destination}`);
  }
  return screenshots;
}

function loadLockedPlaywright() {
  const require = createRequire(import.meta.url);
  const lockedManifest = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
  const expected = lockedManifest?.dependencies?.playwright;
  if (typeof expected !== 'string' || !/^\d+\.\d+\.\d+$/.test(expected)) {
    fail('locked Playwright manifest is invalid');
  }
  const roots = [
    ...String(process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean),
    path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules'),
  ];
  for (const root of roots) {
    try {
      const manifest = require(path.join(root, 'playwright', 'package.json'));
      if (manifest.version !== expected) {
        fail(`Playwright ${manifest.version} does not match locked ${expected}`);
      }
      return { playwright: require(path.join(root, 'playwright')), version: expected };
    } catch (error) {
      if (String(error.message).includes('does not match locked')) throw error;
    }
  }
  fail(
    'locked Playwright runtime not found; run npm ci --ignore-scripts --prefix ci/playwright '
    + 'and set NODE_PATH=ci/playwright/node_modules',
  );
}

async function launchChromium(chromium) {
  const configured = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  const candidates = [
    configured,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter((item, index, values) => item && values.indexOf(item) === index && fs.existsSync(item));
  const attempts = [
    { name: 'Playwright-managed Chromium', options: {} },
    ...candidates.map((executablePath) => ({ name: executablePath, options: { executablePath } })),
  ];
  const failures = [];
  for (const attempt of attempts) {
    try {
      const browser = await chromium.launch({
        headless: true,
        args: ['--disable-dev-shm-usage'],
        ...attempt.options,
      });
      return { browser, launcher: attempt.name };
    } catch (error) {
      failures.push(`${attempt.name}: ${text(String(error.message).split('\n')[0])}`);
    }
  }
  fail(`could not launch locked Chromium: ${failures.join('; ')}`);
}

function pageCollectors() {
  const evidence = {
    javascript: collector(),
    failedApi: collector(),
    failedRequests: collector(),
    blockedRequests: collector(),
  };
  // A blue/green edge switch can invalidate one in-flight asset request just
  // after a healthy backend has become active. Keep the event as retry input
  // rather than hiding a later page-level error in the acceptance report.
  Object.defineProperty(evidence, 'transientNavigationErrors', {
    value: 0,
    writable: true,
    enumerable: false,
  });
  return evidence;
}

async function instrumentPage(page, baseUrl, evidence) {
  page.on('pageerror', (error) => {
    evidence.javascript.push({ type: 'pageerror', message: text(error.message) });
  });
  page.on('console', (message) => {
    if (message.type() === 'error') {
      const detail = text(message.text());
      if (isTransientNavigationError(detail)) {
        evidence.transientNavigationErrors += 1;
      } else {
        evidence.javascript.push({ type: 'console', message: detail });
      }
    }
  });
  page.on('response', (response) => {
    const request = response.request();
    const target = new URL(response.url());
    if (target.origin === baseUrl.origin && target.pathname.startsWith('/api/') && response.status() >= 400) {
      evidence.failedApi.push({
        method: request.method(),
        path: text(`${target.pathname}${target.search}`, 500),
        status: response.status(),
      });
    }
  });
  page.on('requestfailed', (request) => {
    const target = new URL(request.url());
    const failure = request.failure()?.errorText || 'request failed';
    // Closing a disclosure or dialog can intentionally abandon an in-flight
    // read. Chromium reports that as ERR_ABORTED; it is not an API outage.
    if (
      failure !== 'net::ERR_ABORTED'
      && target.origin === baseUrl.origin
      && target.pathname.startsWith('/api/')
    ) {
      evidence.failedRequests.push({
        method: request.method(),
        path: text(`${target.pathname}${target.search}`, 500),
        error: text(failure),
      });
    }
  });
  await page.route('**/*', async (route) => {
    const request = route.request();
    if (!isPermittedRequest(request.method(), request.url(), baseUrl)) {
      const target = new URL(request.url());
      evidence.blockedRequests.push({
        method: request.method(),
        origin: target.origin,
        path: text(`${target.pathname}${target.search}`, 500),
      });
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });
}

async function waitForSettledRoute(page, route) {
  await page.waitForFunction((routeName) => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden'
        && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const sections = [...document.querySelectorAll(`[data-page="${CSS.escape(routeName)}"]`)]
      .filter((element) => !element.hidden && visible(element));
    if (sections.length === 0) return false;
    const pending = sections.flatMap((section) => [...section.querySelectorAll(
      '.skel,[aria-busy="true"],.loading',
    )]).filter(visible);
    const textPending = sections.flatMap((section) => [...section.querySelectorAll('p,span,div')])
      .filter(visible)
      .some((element) => /^(loading|waiting for data|reading live|refreshing)(?:\s|…|\.)/i
        .test(String(element.textContent || '').trim()));
    return pending.length === 0 && !textPending;
  }, route, { timeout: LOADING_TIMEOUT_MS });
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

async function navigateToSettledRoute(page, url, route, evidence) {
  let observedTransientErrors = evidence.transientNavigationErrors;
  let lastError = null;
  for (let attempt = 0; attempt < TRANSIENT_NAVIGATION_ATTEMPTS; attempt += 1) {
    try {
      const response = await page.goto(url.href, {
        waitUntil: 'domcontentloaded',
        timeout: NAVIGATION_TIMEOUT_MS,
      });
      if (!response || response.status() >= 400) fail(`navigation returned HTTP ${response?.status() ?? 'none'}`);
      if (new URL(page.url()).origin !== url.origin) fail('navigation left the Console origin');
      await waitForSettledRoute(page, route);
      return;
    } catch (error) {
      lastError = error;
      const changedDuringAttempt = evidence.transientNavigationErrors > observedTransientErrors;
      if (attempt + 1 >= TRANSIENT_NAVIGATION_ATTEMPTS
          || (!changedDuringAttempt && !isTransientNavigationError(error?.message))) {
        throw error;
      }
      observedTransientErrors = evidence.transientNavigationErrors;
      await page.waitForTimeout(250 * (attempt + 1));
    }
  }
  throw lastError;
}

async function loadingEvidence(page, route) {
  return page.evaluate((routeName) => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden'
        && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const sections = [...document.querySelectorAll(`[data-page="${CSS.escape(routeName)}"]`)]
      .filter((element) => !element.hidden && visible(element));
    return sections.flatMap((section) => [...section.querySelectorAll(
      '.skel,[aria-busy="true"],.loading,p,span',
    )]).filter((element) => visible(element) && (
      element.matches('.skel,[aria-busy="true"],.loading')
      || /loading|waiting for data|reading live|refreshing/i.test(String(element.textContent || ''))
    )).slice(0, 20).map((element) => ({
      tag: element.tagName.toLowerCase(),
      class: String(element.className || '').slice(0, 120),
      text: String(element.textContent || '').trim().slice(0, 200),
    }));
  }, route);
}

async function healthEvidence(page) {
  return page.evaluate(() => {
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden'
        && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const candidates = [...document.querySelectorAll(
      '[role="alert"],.degraded,.repository-inventory-error,.fatal,.banner',
    )].filter(visible);
    return candidates.slice(0, 20).map((element) => ({
      tag: element.tagName.toLowerCase(),
      role: element.getAttribute('role'),
      class: String(element.className || '').slice(0, 160),
      text: String(element.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 300),
      inventoryContract: /repository inventory contract|authoritative repository tree|inventory.*malformed/i
        .test(String(element.textContent || '')),
    }));
  });
}

async function scrollDocument(page) {
  await page.evaluate(async () => {
    const step = Math.max(300, Math.floor(window.innerHeight * 0.8));
    let position = 0;
    for (let count = 0; count < 100; count += 1) {
      const maximum = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
      if (position >= maximum) break;
      position = Math.min(maximum, position + step);
      window.scrollTo(0, position);
      await new Promise((resolve) => requestAnimationFrame(resolve));
    }
    // Recompute after the incremental pass because lazy rendering may have
    // extended the document.  The bottom edge must be observed at least once.
    window.scrollTo(0, Math.max(0, document.documentElement.scrollHeight - window.innerHeight));
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    window.scrollTo(0, 0);
    await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

async function geometryEvidence(page, route) {
  return page.evaluate(({ routeName, maximumItems, ignoredClassNames }) => {
    const root = document.documentElement;
    const visible = (element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== 'none' && style.visibility !== 'hidden'
        && Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const describe = (element) => ({
      tag: element.tagName.toLowerCase(),
      id: element.id || null,
      class: String(element.className || '').slice(0, 140),
      text: String(element.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 180),
      rect: (() => {
        const value = element.getBoundingClientRect();
        return {
          x: Math.round(value.x * 10) / 10,
          y: Math.round(value.y * 10) / 10,
          width: Math.round(value.width * 10) / 10,
          height: Math.round(value.height * 10) / 10,
        };
      })(),
    });
    const sections = [...document.querySelectorAll(`[data-page="${CSS.escape(routeName)}"]`)]
      .filter((element) => !element.hidden && visible(element));
    const intentionallyNonVisual = (element) => (
      element.closest('details:not([open])') !== null
      || ignoredClassNames.some(
        (className) => element.closest(`.${CSS.escape(className)}`) !== null,
      )
    );
    const meaningful = sections.flatMap((section) => [...section.querySelectorAll(
      'h1,h2,h3,h4,p,span,a,button,label,input,select,textarea,code,td,th,[role="button"],[role="tab"]',
    )]).filter((element, index, values) => (
      visible(element)
      && !intentionallyNonVisual(element)
      && values.indexOf(element) === index
    ));
    const clipped = [];
    const allowedTruncation = [];
    const offscreen = [];
    const scrollbars = [];
    for (const element of meaningful) {
      const style = getComputedStyle(element);
      const ownX = element.scrollWidth > element.clientWidth + 1;
      const ownY = element.scrollHeight > element.clientHeight + 1;
      const allowed = element.hasAttribute('data-ui-allow-truncation')
        || style.textOverflow === 'ellipsis'
        || (style.webkitLineClamp && style.webkitLineClamp !== 'none');
      const clipsX = ownX && ['hidden', 'clip'].includes(style.overflowX);
      const clipsY = ownY && ['hidden', 'clip'].includes(style.overflowY);
      if (clipsX || clipsY) {
        const finding = { ...describe(element), clipped_x: clipsX, clipped_y: clipsY };
        (allowed ? allowedTruncation : clipped).push(finding);
      }
      const rect = element.getBoundingClientRect();
      let horizontalScrollPath = false;
      let scrollAncestor = element.parentElement;
      while (scrollAncestor && scrollAncestor !== document.body) {
        const ancestorStyle = getComputedStyle(scrollAncestor);
        if (
          scrollAncestor.scrollWidth > scrollAncestor.clientWidth + 1
          && ['auto', 'scroll'].includes(ancestorStyle.overflowX)
        ) {
          horizontalScrollPath = true;
          break;
        }
        scrollAncestor = scrollAncestor.parentElement;
      }
      if (
        !horizontalScrollPath
        && (rect.left < -1 || rect.right > window.innerWidth + 1)
      ) {
        offscreen.push(describe(element));
      }
      if ((ownX && ['auto', 'scroll'].includes(style.overflowX))
        || (ownY && ['auto', 'scroll'].includes(style.overflowY))) {
        scrollbars.push({ ...describe(element), horizontal: ownX, vertical: ownY });
      }
      let ancestor = element.parentElement;
      while (ancestor && ancestor !== document.body) {
        const ancestorStyle = getComputedStyle(ancestor);
        if (['hidden', 'clip'].includes(ancestorStyle.overflowX)
          || ['hidden', 'clip'].includes(ancestorStyle.overflowY)) {
          const ancestorRect = ancestor.getBoundingClientRect();
          const cutX = ['hidden', 'clip'].includes(ancestorStyle.overflowX)
            && (rect.left < ancestorRect.left - 1 || rect.right > ancestorRect.right + 1);
          const cutY = ['hidden', 'clip'].includes(ancestorStyle.overflowY)
            && (rect.top < ancestorRect.top - 1 || rect.bottom > ancestorRect.bottom + 1);
          if (cutX || cutY) {
            clipped.push({
              ...describe(element),
              clipped_by_ancestor: describe(ancestor),
              clipped_x: cutX,
              clipped_y: cutY,
            });
            break;
          }
        }
        ancestor = ancestor.parentElement;
      }
    }
    const bounded = (values) => ({ items: values.slice(0, maximumItems), suppressed: Math.max(0, values.length - maximumItems) });
    return {
      viewport: { width: window.innerWidth, height: window.innerHeight },
      document: {
        client_width: root.clientWidth,
        scroll_width: root.scrollWidth,
        client_height: root.clientHeight,
        scroll_height: root.scrollHeight,
        horizontal_overflow_px: Math.max(0, root.scrollWidth - root.clientWidth),
      },
      active_sections: sections.map(describe),
      text_fit_failures: bounded(clipped),
      allowed_truncations: bounded(allowedTruncation),
      horizontal_offscreen: bounded(offscreen),
      visible_scrollbars: bounded(scrollbars),
    };
  }, {
    routeName: route,
    maximumItems: MAX_ITEMS,
    ignoredClassNames: GEOMETRY_IGNORED_CLASSES,
  });
}

async function clickTwice(page, selector, name, journeys, { required = false } = {}) {
  const target = page.locator(selector).filter({ visible: true }).first();
  if (await target.count() === 0) {
    journeys.push({ name, status: required ? 'failed' : 'not_applicable', detail: 'no matching control' });
    return;
  }
  try {
    const before = await target.getAttribute('aria-expanded');
    await target.click();
    await page.waitForTimeout(100);
    const after = await page.locator(selector).filter({ visible: true }).first().getAttribute('aria-expanded');
    if (before !== null && after === before) fail(`${name} did not change disclosure state`);
    await page.locator(selector).filter({ visible: true }).first().click();
    await page.waitForTimeout(100);
    const restored = await page.locator(selector).filter({ visible: true }).first().getAttribute('aria-expanded');
    if (before !== null && restored !== before) fail(`${name} did not restore disclosure state`);
    journeys.push({ name, status: 'passed' });
  } catch (error) {
    journeys.push({ name, status: 'failed', detail: text(error.message) });
  }
}

async function openAndCancel(page, definition, journeys) {
  const trigger = page.locator(definition.trigger).filter({ visible: true }).first();
  if (await trigger.count() === 0 || await trigger.isDisabled()) {
    journeys.push({ name: definition.name, status: 'failed', detail: 'trigger is absent or disabled' });
    return;
  }
  try {
    await trigger.click();
    await page.locator(definition.dialog).waitFor({ state: 'visible', timeout: 5_000 });
    const open = await page.locator(definition.dialog).evaluate((dialog) => dialog.open === true);
    if (!open) fail('dialog did not enter its open state');
    await page.locator(definition.cancel).filter({ visible: true }).click();
    await page.waitForFunction((selector) => !document.querySelector(selector)?.open, definition.dialog, { timeout: 5_000 });
    journeys.push({ name: definition.name, status: 'passed' });
  } catch (error) {
    journeys.push({ name: definition.name, status: 'failed', detail: text(error.message) });
    await page.keyboard.press('Escape').catch(() => {});
  }
}

export function classifyLifecycleTabState(tabs) {
  if (!Array.isArray(tabs) || tabs.length < 2) {
    return {
      status: 'not_applicable',
      detail: 'lifecycle tabs are absent on this page',
    };
  }
  if (tabs.some((tab) => tab?.disabled === true || tab?.ariaDisabled === 'true')) {
    return {
      status: 'unavailable',
      detail: 'lifecycle tabs are present, but archive lifecycle is unavailable',
    };
  }
  return null;
}

async function exerciseLifecycleTabs(page, route, journeys) {
  const selector = `[data-page="${route}"]:not([hidden]) [data-lifecycle-filter]:not([hidden]) button[data-lifecycle-view]`;
  const tabs = page.locator(selector).filter({ visible: true });
  const tabState = await tabs.evaluateAll((elements) => elements.map((element) => ({
    disabled: element.disabled === true,
    ariaDisabled: element.getAttribute('aria-disabled'),
  })));
  const disposition = classifyLifecycleTabState(tabState);
  if (disposition) {
    journeys.push({ name: 'active/archived tabs', ...disposition });
    return;
  }
  const count = tabState.length;
  try {
    for (let index = 1; index < count; index += 1) {
      const tab = page.locator(selector).filter({ visible: true }).nth(index);
      if (await tab.isDisabled()) {
        journeys.push({
          name: 'active/archived tabs',
          status: 'unavailable',
          detail: 'archive lifecycle became unavailable before interaction',
        });
        return;
      }
      await tab.click({ timeout: JOURNEY_ACTION_TIMEOUT_MS });
      await page.waitForTimeout(100);
    }
    await page.locator(selector).filter({ visible: true }).first().click({
      timeout: JOURNEY_ACTION_TIMEOUT_MS,
    });
    await page.waitForTimeout(100);
    journeys.push({ name: 'active/archived tabs', status: 'passed' });
  } catch (error) {
    journeys.push({ name: 'active/archived tabs', status: 'failed', detail: text(error.message) });
  }
}

async function exerciseTestTabs(page, journeys) {
  const repository = page.locator('#sec-tests .test-current-repository')
    .filter({ visible: true }).first();
  if (await repository.count() === 0) {
    journeys.push({ name: 'current test repositories', status: 'failed', detail: 'no repository catalog row' });
    return;
  }
  try {
    journeys.push({
      name: 'current test repositories',
      status: 'passed',
      detail: 'authenticated current repository catalog rendered without history',
    });
  } catch (error) {
    journeys.push({ name: 'current test repositories', status: 'failed', detail: text(error.message) });
  }
}

async function exerciseLogs(page, route, journeys) {
  const groupSelector = route === 'servers'
    ? '#sec-servers .server-project-toggle'
    : '#sec-docker .server-project-toggle';
  const logSelector = route === 'servers'
    ? '#sec-servers [data-fk^="srv-x:"][data-log-capable="true"],#sec-servers [data-fk^="srv-dock-x:"][data-log-capable="true"]'
    : '#sec-docker [data-fk^="dock-logs:"]';
  let openedGroupIndex = null;
  let logToggle = page.locator(logSelector).filter({ visible: true }).first();
  if (await logToggle.count() === 0) {
    const groups = page.locator(groupSelector).filter({ visible: true });
    const groupCount = await groups.count();
    for (let index = 0; index < groupCount; index += 1) {
      let group = page.locator(groupSelector).filter({ visible: true }).nth(index);
      if (await group.getAttribute('aria-expanded') !== 'false') continue;
      await group.click();
      await page.waitForTimeout(100);
      logToggle = page.locator(logSelector).filter({ visible: true }).first();
      if (await logToggle.count()) {
        openedGroupIndex = index;
        break;
      }
      group = page.locator(groupSelector).filter({ visible: true }).nth(index);
      if (await group.getAttribute('aria-expanded') === 'true') await group.click();
    }
  }
  if (await logToggle.count() === 0) {
    journeys.push({ name: 'log disclosure', status: 'not_applicable', detail: 'no visible runtime resource' });
    return;
  }
  try {
    const panelId = await logToggle.getAttribute('aria-controls');
    await logToggle.click();
    await page.waitForFunction(() => ![...document.querySelectorAll('.log-empty')]
      .some((element) => element.getClientRects().length && /loading/i.test(element.textContent || '')), null, { timeout: 10_000 });
    const panel = panelId
      ? page.locator(`[id="${String(panelId).replaceAll('"', '\\"')}"]`)
      : page.locator('.panel').filter({ visible: true }).last();
    const inlineError = panel.locator('.log-empty.err').filter({ visible: true });
    if (await inlineError.count()) {
      throw new Error(`log disclosure failed: ${text(await inlineError.first().textContent())}`);
    }
    await logToggle.click();
    journeys.push({ name: 'log disclosure', status: 'passed' });
  } catch (error) {
    journeys.push({ name: 'log disclosure', status: 'failed', detail: text(error.message) });
  } finally {
    if (openedGroupIndex !== null) {
      const group = page.locator(groupSelector).filter({ visible: true }).nth(openedGroupIndex);
      if (await group.getAttribute('aria-expanded') === 'true') {
        await group.click().catch(() => {});
      }
    }
  }
}

async function exerciseBugRegistry(page, journeys) {
  try {
    const api = await page.evaluate(async () => {
      const response = await fetch('/api/bugs', {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      let payload = null;
      try {
        payload = await response.json();
      } catch {
        // The status and malformed payload are reported below without leaking
        // response contents into the acceptance artifact.
      }
      return {
        status: response.status,
        schemaVersion: payload?.schema_version ?? null,
        bugCount: Array.isArray(payload?.bugs) ? payload.bugs.length : null,
      };
    });
    if (api.status !== 200 || api.schemaVersion !== 1 || !Number.isInteger(api.bugCount) || api.bugCount < 0) {
      fail(`authenticated /api/bugs is invalid (status ${api.status}, count ${api.bugCount})`);
    }
    const empty = page.locator('#bugs-body .bugs-empty p').filter({ visible: true });
    const cardCount = await page.locator('#bugs-body .bug-card').filter({ visible: true }).count();
    if (api.bugCount === 0) {
      if (await empty.count() !== 1) fail('rendered Bugs page lacks its unique empty state');
      if ((await empty.first().innerText()).trim() !== 'No open Coordinator bugs.') {
        fail('rendered Bugs page empty-state copy is not exact');
      }
      if (cardCount !== 0) fail('rendered Bugs page still contains an open report card');
    } else {
      if (await empty.count() !== 0) fail('rendered Bugs page shows an empty state for open reports');
      if (cardCount !== api.bugCount) {
        fail(`rendered Bugs page/API count mismatch (${cardCount}/${api.bugCount})`);
      }
    }
    journeys.push({
      name: 'open bug registry parity',
      status: 'passed',
      detail: `authenticated API and rendered page agree on ${api.bugCount} open report${api.bugCount === 1 ? '' : 's'}`,
    });
  } catch (error) {
    journeys.push({
      name: 'open bug registry parity',
      status: 'failed',
      detail: text(error.message),
    });
  }
}

async function exerciseJourneys(page, route) {
  const journeys = [];
  await exerciseLifecycleTabs(page, route, journeys);
  if (route === 'projects') {
    await clickTwice(
      page,
      '#sec-projects [data-fk^="tree-x:"]',
      'project collapse/expand',
      journeys,
      { required: true },
    );
    const project = page.locator('#sec-projects [data-fk^="tree-x:"]').filter({ visible: true }).first();
    if (await project.count() && await project.getAttribute('aria-expanded') === 'false') {
      await project.click();
      await clickTwice(
        page,
        '#sec-projects .temporary-scope-toggle',
        'temporary repository collapse/expand',
        journeys,
      );
      await page.locator('#sec-projects [data-fk^="tree-x:"]').filter({ visible: true }).first().click();
    }
  }
  if (route === 'servers' || route === 'docker') {
    await clickTwice(
      page,
      route === 'servers' ? '#sec-servers .server-project-toggle' : '#sec-docker .server-project-toggle',
      'repository group collapse/expand',
      journeys,
    );
    await exerciseLogs(page, route, journeys);
  }
  if (route === 'tests') {
    await exerciseTestTabs(page, journeys);
    await openAndCancel(page, {
      name: 'run-tests dialog open/cancel',
      trigger: '#tests-run',
      dialog: '#test-run-dialog',
      cancel: '#test-run-cancel',
    }, journeys);
  }
  if (route === 'bugs') await exerciseBugRegistry(page, journeys);
  const dialogs = {
    routes: { name: 'create-route dialog open/cancel', trigger: '#route-add', dialog: '#route-dialog', cancel: '#route-cancel' },
    ports: { name: 'lease-port dialog open/cancel', trigger: '#lease-add', dialog: '#lease-dialog', cancel: '#lease-cancel' },
    access: { name: 'add-user dialog open/cancel', trigger: '#access-add', dialog: '#access-dialog', cancel: '#access-cancel' },
    telegram: { name: 'register-bot dialog open/cancel', trigger: '#telegram-add', dialog: '#telegram-dialog', cancel: '#telegram-cancel' },
  };
  if (dialogs[route]) await openAndCancel(page, dialogs[route], journeys);
  return journeys;
}

function captureReporters(evidence) {
  return Object.fromEntries(Object.entries(evidence).map(([name, value]) => [name, value.report()]));
}

function evidenceHasItems(value) {
  return value.items.length > 0 || value.suppressed > 0;
}

async function checkRoute({ browser, baseUrl, storageState, outputDir, route, viewport }) {
  const evidence = pageCollectors();
  const journeys = [];
  const navigation = { ok: false, error: null, indefinite_loading: [] };
  let health = [];
  let geometry = null;
  let screenshot = null;
  const context = await browser.newContext({
    viewport,
    storageState,
    locale: 'en-US',
    colorScheme: 'dark',
    reducedMotion: 'reduce',
    acceptDownloads: false,
    serviceWorkers: 'block',
  });
  const page = await context.newPage();
  try {
    await instrumentPage(page, baseUrl, evidence);
    const url = new URL(baseUrl.href);
    url.hash = `#/` + route;
    try {
      await navigateToSettledRoute(page, url, route, evidence);
      navigation.ok = true;
    } catch (error) {
      navigation.error = text(error.message);
      navigation.indefinite_loading = await loadingEvidence(page, route).catch(() => []);
    }
    if (navigation.ok) {
      health = await healthEvidence(page);
      journeys.push(...await exerciseJourneys(page, route));
      await scrollDocument(page);
      health = [...health, ...await healthEvidence(page)].slice(0, MAX_ITEMS);
      geometry = await geometryEvidence(page, route);
    }
    const filename = `${viewport.width}x${viewport.height}-${route}.png`;
    const absoluteScreenshot = path.join(outputDir, filename);
    await page.screenshot({ path: absoluteScreenshot, fullPage: true, animations: 'disabled' });
    await fsp.chmod(absoluteScreenshot, 0o600);
    screenshot = `screenshots/${filename}`;
  } catch (error) {
    if (!navigation.error) navigation.error = text(error.message);
  } finally {
    await context.close();
  }
  const reporters = captureReporters(evidence);
  const journeyFailures = journeys.filter((journey) => journey.status === 'failed');
  const geometryFailure = geometry && (
    geometry.document.horizontal_overflow_px > 1
    || evidenceHasItems(geometry.text_fit_failures)
    || evidenceHasItems(geometry.horizontal_offscreen)
  );
  return {
    route,
    viewport,
    ok: navigation.ok
      && navigation.error === null
      && health.length === 0
      && !Object.values(reporters).some(evidenceHasItems)
      && journeyFailures.length === 0
      && !geometryFailure
      && geometry !== null
      && screenshot !== null,
    navigation,
    health,
    journeys,
    errors: reporters,
    geometry,
    screenshot,
  };
}

async function discoverRoutes(browser, baseUrl, storageState) {
  const evidence = pageCollectors();
  const context = await browser.newContext({
    viewport: VIEWPORTS[VIEWPORTS.length - 1],
    storageState,
    locale: 'en-US',
    reducedMotion: 'reduce',
    serviceWorkers: 'block',
  });
  const page = await context.newPage();
  let routes = [];
  let error = null;
  try {
    await instrumentPage(page, baseUrl, evidence);
    const url = new URL(baseUrl.href);
    url.hash = '#/projects';
    await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
    await page.waitForSelector('#site-nav a[href^="#/"]', { timeout: NAVIGATION_TIMEOUT_MS });
    routes = await page.locator('#site-nav a[href^="#/"]').evaluateAll((links) => [...new Set(
      links.map((link) => /^#\/([a-z][a-z-]*)$/.exec(link.getAttribute('href') || '')?.[1]).filter(Boolean),
    )].sort());
  } catch (caught) {
    error = text(caught.message);
  } finally {
    await context.close();
  }
  return { routes, error, errors: captureReporters(evidence) };
}

function compactReport(report) {
  return {
    ...report,
    report_truncated: true,
    pages: report.pages.map((page) => ({
      route: page.route,
      viewport: page.viewport,
      ok: page.ok,
      navigation: page.navigation,
      health: page.health.slice(0, 3),
      journeys: page.journeys,
      errors: Object.fromEntries(Object.entries(page.errors).map(([name, value]) => [name, {
        items: value.items.slice(0, 3),
        suppressed: value.suppressed + Math.max(0, value.items.length - 3),
      }])),
      geometry: page.geometry && {
        viewport: page.geometry.viewport,
        document: page.geometry.document,
        active_sections: page.geometry.active_sections,
        text_fit_failures: page.geometry.text_fit_failures,
        horizontal_offscreen: page.geometry.horizontal_offscreen,
        visible_scrollbars: page.geometry.visible_scrollbars,
      },
      screenshot: page.screenshot,
    })),
  };
}

async function atomicReport(outputDir, report) {
  let document = report;
  let payload = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
  if (payload.length > MAX_REPORT_BYTES) {
    document = compactReport(report);
    payload = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
  }
  if (payload.length > MAX_REPORT_BYTES) fail('bounded acceptance report still exceeds 2 MiB');
  const destination = path.join(outputDir, 'report.json');
  const temporary = path.join(outputDir, `.report.${process.pid}.${Date.now()}.partial`);
  await fsp.writeFile(temporary, payload, { flag: 'wx', mode: 0o600 });
  await fsp.rename(temporary, destination);
  await fsp.chmod(destination, 0o600);
  return { destination, bytes: payload.length, document };
}

async function run(options) {
  const storage = validateStorageState(options.storageState);
  const screenshotDir = prepareOutputDirectory(options.outputDir);
  const locked = loadLockedPlaywright();
  const launched = await launchChromium(locked.playwright.chromium);
  const startedAt = new Date().toISOString();
  const pages = [];
  let discovery;
  let browserVersion;
  try {
    browserVersion = launched.browser.version();
    discovery = await discoverRoutes(launched.browser, options.baseUrl, options.storageState);
    const routes = [...new Set([...KNOWN_ROUTES, ...discovery.routes])].sort();
    for (const viewport of VIEWPORTS) {
      for (const route of routes) {
        try {
          pages.push(await checkRoute({
            browser: launched.browser,
            baseUrl: options.baseUrl,
            storageState: options.storageState,
            outputDir: screenshotDir,
            route,
            viewport,
          }));
        } catch (error) {
          pages.push({
            route,
            viewport,
            ok: false,
            navigation: { ok: false, error: text(error.message), indefinite_loading: [] },
            health: [],
            journeys: [],
            errors: {},
            geometry: null,
            screenshot: null,
          });
        }
      }
    }
  } finally {
    await launched.browser.close();
  }
  const routes = [...new Set([...KNOWN_ROUTES, ...(discovery?.routes || [])])].sort();
  const expectedChecks = routes.length * VIEWPORTS.length;
  const discoveryErrors = discovery ? Object.values(discovery.errors).some(evidenceHasItems) : true;
  const report = {
    schema_version: 1,
    kind: REPORT_KIND,
    ok: discovery?.error === null
      && !discoveryErrors
      && pages.length === expectedChecks
      && pages.every((page) => page.ok),
    base_url: options.baseUrl.href,
    storage_state: storage,
    playwright_version: locked.version,
    browser_version: browserVersion,
    browser_launcher: launched.launcher,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    viewports: VIEWPORTS,
    route_coverage: {
      explicit: [...KNOWN_ROUTES],
      discovered: discovery?.routes || [],
      union: routes,
      expected_checks: expectedChecks,
      completed_checks: pages.length,
      discovery_error: discovery?.error || null,
      discovery_browser_errors: discovery?.errors || {},
    },
    summary: {
      passed: pages.filter((page) => page.ok).length,
      failed: pages.filter((page) => !page.ok).length,
      screenshots: pages.filter((page) => page.screenshot).length,
    },
    pages,
  };
  return atomicReport(options.outputDir, report);
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = await run(options);
    process.stdout.write(`${JSON.stringify({
      ok: result.document.ok,
      report: result.destination,
      report_bytes: result.bytes,
      passed: result.document.summary.passed,
      failed: result.document.summary.failed,
    })}\n`);
    process.exitCode = result.document.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      ok: false,
      error_code: 'production_console_acceptance_failed',
      error: text(error.message, 1000),
    })}\n`);
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === TOOL_PATH) {
  await main();
}
