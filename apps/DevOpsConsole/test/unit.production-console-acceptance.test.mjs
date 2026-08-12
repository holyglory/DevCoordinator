import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  GEOMETRY_IGNORED_CLASSES,
  KNOWN_ROUTES,
  VIEWPORTS,
  classifyLifecycleTabState,
  isTransientNavigationError,
  isPermittedRequest,
  normalizeBaseUrl,
  parseArgs,
} from '../Tools/production-console-acceptance.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const TOOL = path.join(APP_ROOT, 'Tools', 'production-console-acceptance.mjs');

test('production acceptance uses the exact responsive viewport and route coverage', () => {
  assert.deepEqual(VIEWPORTS.map((viewport) => viewport.width), [320, 390, 768, 981, 1440]);
  assert.deepEqual(KNOWN_ROUTES, [
    'projects', 'tests', 'bugs', 'servers', 'routes', 'docker', 'ports',
    'performance', 'access', 'invites', 'telegram',
  ]);
});

test('production acceptance CLI requires exact explicit inputs', () => {
  const values = parseArgs([
    '--base-url', 'https://console.example.test/',
    '--storage-state', '/tmp/storage.json',
    '--output-dir', '/tmp/acceptance',
  ]);
  assert.equal(values.baseUrl.href, 'https://console.example.test/');
  assert.equal(values.storageState, '/tmp/storage.json');
  assert.equal(values.outputDir, '/tmp/acceptance');
  assert.throws(() => parseArgs(['--base-url', 'https://console.example.test/']), /usage/);
  assert.throws(() => normalizeBaseUrl('http://console.example.test/'), /HTTPS/);
  assert.throws(() => normalizeBaseUrl('https://user:secret@console.example.test/'), /credential-free/);
});

test('production acceptance blocks all mutations except exact log reads', () => {
  const base = new URL('https://console.example.test/');
  assert.equal(isPermittedRequest('GET', 'https://console.example.test/api/overview', base), true);
  assert.equal(isPermittedRequest('GET', 'https://console.example.test/auth/logout', base), false);
  assert.equal(isPermittedRequest('GET', 'https://console.example.test/auth/login', base), false);
  assert.equal(isPermittedRequest('POST', 'https://console.example.test/api/servers/logs', base), true);
  assert.equal(isPermittedRequest('POST', 'https://console.example.test/api/docker/logs', base), true);
  for (const request of [
    ['POST', 'https://console.example.test/api/tests/submit'],
    ['POST', 'https://console.example.test/api/projects/action'],
    ['PATCH', 'https://console.example.test/api/routes/gf'],
    ['DELETE', 'https://console.example.test/api/routes/gf'],
    ['GET', 'https://other.example.test/api/overview'],
  ]) {
    assert.equal(isPermittedRequest(request[0], request[1], base), false, request.join(' '));
  }
});

test('production acceptance retries only an edge handoff network change', () => {
  assert.equal(isTransientNavigationError('net::ERR_NETWORK_CHANGED'), true);
  assert.equal(isTransientNavigationError('net::ERR_CONNECTION_RESET'), true);
  assert.equal(isTransientNavigationError('page.waitForFunction: Timeout 20000ms exceeded.'), false);
  assert.equal(isTransientNavigationError('server responded HTTP 500'), false);
});

test('production geometry keeps screen-reader text accessible without treating it as clipped visual copy', () => {
  assert.deepEqual(GEOMETRY_IGNORED_CLASSES, ['visually-hidden']);
  const source = fs.readFileSync(TOOL, 'utf8');
  assert.match(source, /element\.closest\('details:not\(\[open\]\)'\)/,
    'closed disclosure contents must not be measured as clipped visual copy');
  assert.match(source, /element\.closest\(`\.\$\{CSS\.escape\(className\)\}`\)/,
    'the visual geometry pass must omit the explicit assistive-only subtree');
  assert.match(source, /ignoredClassNames: GEOMETRY_IGNORED_CLASSES/,
    'the browser pass must receive the exact reviewed ignore class list');
});

test('production lifecycle journey distinguishes absent, unavailable and interactive tabs', () => {
  assert.deepEqual(classifyLifecycleTabState([]), {
    status: 'not_applicable',
    detail: 'lifecycle tabs are absent on this page',
  });
  assert.deepEqual(classifyLifecycleTabState([
    { disabled: false, ariaDisabled: 'false' },
    { disabled: true, ariaDisabled: 'true' },
  ]), {
    status: 'unavailable',
    detail: 'lifecycle tabs are present, but archive lifecycle is unavailable',
  });
  assert.equal(classifyLifecycleTabState([
    { disabled: false, ariaDisabled: 'false' },
    { disabled: false, ariaDisabled: 'false' },
  ]), null);
  const source = fs.readFileSync(TOOL, 'utf8');
  assert.match(source, /JOURNEY_ACTION_TIMEOUT_MS = 2_000/,
    'a control-state race must fail quickly instead of consuming Playwright\'s 30-second default');
  assert.match(source, /await tab\.isDisabled\(\)/,
    'the journey must recheck availability immediately before interaction');
});

test('production test journey proves every supported live statistics window', () => {
  const source = fs.readFileSync(TOOL, 'utf8');
  assert.match(source, /for \(const days of \['7', '30', '90'\]\)/,
    'the authenticated journey must request every supported statistics window');
  assert.match(source, /requestUrl\.searchParams\.get\('days'\) === days/,
    'each selection must be bound to its exact successful API response');
  assert.match(source, /period === `Last \$\{expected\} days`/,
    'the exact live period must become visible in the repository throughput surface');
});

test('production acceptance source retains fail-closed health, loading, geometry and journey gates', () => {
  const source = fs.readFileSync(TOOL, 'utf8');
  for (const required of [
    'repository-inventory-error',
    'indefinite_loading',
    'horizontal_overflow_px',
    'text_fit_failures',
    'project collapse/expand',
    'repository group collapse/expand',
    'log disclosure',
    'data-log-capable="true"',
    '.log-empty.err',
    'run-tests dialog open/cancel',
    'create-route dialog open/cancel',
    'lease-port dialog open/cancel',
    'open bug registry empty',
    "fetch('/api/bugs'",
    "'No open Coordinator bugs.'",
    "page.on('pageerror'",
    "page.on('response'",
    'MAX_REPORT_BYTES',
    'TRANSIENT_NAVIGATION_ATTEMPTS = 2',
    'navigateToSettledRoute',
    'navigation.error === null',
    'geometry !== null',
    'screenshot !== null',
    'document.documentElement.scrollHeight - window.innerHeight',
    "ci', 'playwright', 'package.json",
  ]) {
    assert.match(source, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(source, /\.click\([^\n]*#(?:test-run-submit|route-submit|lease-submit)/);
});
