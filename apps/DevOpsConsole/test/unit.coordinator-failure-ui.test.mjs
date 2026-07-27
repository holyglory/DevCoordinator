import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

import { coordinatorOverviewView } from '../src/api.mjs';

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  const bodyStart = source.indexOf('{', start + header.length);
  assert.notEqual(bodyStart, -1, `app.js no longer has a body for "${header}"`);
  for (let i = bodyStart; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
}

test('overview distinguishes Coordinator HTTP failures from transport failures', () => {
  const base = { ok: true, url: 'http://127.0.0.1:8765', lastOkAt: '2026-07-24T21:00:00Z' };
  const serverFailure = new Error('repository profile fields are invalid');
  serverFailure.status = 500;
  assert.deepEqual(coordinatorOverviewView(base, serverFailure), {
    ...base,
    ok: false,
    failureKind: 'request',
    errorStatus: 500,
    lastError: 'repository profile fields are invalid',
  });

  const transportFailure = new Error('connect ECONNREFUSED 127.0.0.1:8765');
  transportFailure.status = 0;
  assert.deepEqual(coordinatorOverviewView(base, transportFailure), {
    ...base,
    ok: false,
    failureKind: 'transport',
    errorStatus: null,
    lastError: 'connect ECONNREFUSED 127.0.0.1:8765',
  });

  assert.deepEqual(coordinatorOverviewView(base), {
    ...base,
    failureKind: null,
    errorStatus: null,
  });
});

test('planned maintenance is a typed wait state without operator-only detail', () => {
  const base = { ok: true, url: 'http://127.0.0.1:8765', lastOkAt: '2026-07-27T22:01:53Z' };
  const maintenance = new Error('Publishing GlobalFinance OKX collector on fresh runtime');
  maintenance.status = 500;
  maintenance.classification = 'maintenance';
  maintenance.retryAfterSeconds = 30;

  const view = coordinatorOverviewView(base, maintenance);
  assert.equal(view.failureKind, 'maintenance');
  assert.equal(view.lastError, null, 'operator task text must not cross into the browser view');
  assert.deepEqual(view.maintenance, { active: true, retryAfterSeconds: 30 });
});

test('visible failure labels remain truthful for HTTP and transport errors', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const titleSource = extractFunction(app, 'function coordinatorFailureTitle(o)');
  // eslint-disable-next-line no-new-func
  const title = new Function(`${titleSource}; return coordinatorFailureTitle;`)();

  assert.equal(title({ coordinator: { failureKind: 'request' } }), 'Coordinator request failed');
  assert.equal(title({ coordinator: { failureKind: 'transport' } }), 'Coordinator unreachable');
  assert.equal(title({ coordinator: { failureKind: 'maintenance' } }), 'Controls temporarily paused');
  assert.equal(title({ coordinator: {} }), 'Coordinator unreachable');

  const header = extractFunction(app, 'function headerProblems(o)');
  const degraded = extractFunction(app, 'function degradedPanel(o)');
  assert.match(header, /title: coordinatorFailureTitle\(o\)/,
    'the header must use the reachability-aware title');
  assert.match(header, /coordinatorFailureHint\(o\)/,
    'the header guidance must explain the actual failure class');
  assert.match(degraded, /coordinatorFailureTitle\(o\)/,
    'the page-level degraded panel must use the same truthful title');
  assert.match(degraded, /role: maintenance \? 'status' : null/,
    'planned maintenance must be an informational status, not an alert');
  assert.match(degraded, /maintenance \? h\('p',[\s\S]*coordinatorFailureHint\(o\)/,
    'planned maintenance must explain automatic recovery without a retry action');

  const banner = extractFunction(app, 'function showBanner(value, retry, key = \'action\')');
  assert.match(banner, /No action needed/);
  assert.match(banner, /running services stay online/);
  assert.match(banner, /retry && !maintenance/,
    'Retry cannot be offered for an operation the user cannot influence');
  assert.match(banner, /role: maintenance \? 'status' : 'alert'/,
    'maintenance must not increment urgency by presenting as an error alert');

  const problems = extractFunction(app, 'function headerProblems(o)');
  assert.match(problems, /c\.failureKind !== 'maintenance'/,
    'planned maintenance must not produce the red needs-attention badge');
  assert.doesNotMatch(app, /showBanner\(err\.message/,
    'typed Coordinator failures must never be flattened before banner classification');
  assert.match(app, /if \(data\.inventory\)[\s\S]*clearBanner\('maintenance'\)/,
    'a retained healthy inventory must not be covered by a global maintenance banner');

  const regressed = titleSource.replace("o?.coordinator?.failureKind === 'request'", 'false');
  // eslint-disable-next-line no-new-func
  const brokenTitle = new Function(`${regressed}; return coordinatorFailureTitle;`)();
  assert.notEqual(brokenTitle({ coordinator: { failureKind: 'request' } }), 'Coordinator request failed',
    'the must-catch fixture must prove the test detects an HTTP failure mislabeled as unreachable');
});
