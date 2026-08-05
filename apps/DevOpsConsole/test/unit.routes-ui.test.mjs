import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI = new URL('../src/ui/', import.meta.url);

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  const bodyStart = source.indexOf('{', start + header.length);
  assert.notEqual(bodyStart, -1, `app.js no longer has a body for "${header}"`);
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, index + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
}

test('Routes leads with its real collection and opens a focused creation dialog', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  const section = html.slice(
    html.indexOf('<section id="sec-routes"'),
    html.indexOf('<section id="sec-docker"'),
  );
  assert.match(section, /id="route-add"[^>]*>Create route</);
  assert.match(section, /id="routes-body"/);
  assert.doesNotMatch(section, /id="route-form"/,
    'the creation form must not precede or displace the route collection');
  assert.ok(html.indexOf('id="routes-body"') < html.indexOf('id="route-dialog"'));
  assert.match(html, /<dialog id="route-dialog"[^>]*>[\s\S]*<form id="route-form"/);
  assert.match(css, /#access-dialog,[^\n]*#route-dialog/);
  assert.match(css, /#route-dialog::backdrop/);

  const open = extractFunction(js, 'function openRouteDialog()');
  const close = extractFunction(js, 'function closeRouteDialog(focusTarget = null)');
  const restore = extractFunction(js, 'function focusAfterRouteDialog(target)');
  const restoreCreated = extractFunction(js, 'function restorePendingCreatedRouteFocus()');
  const requestCreated = extractFunction(js, 'function requestCreatedRouteFocus(slug)');
  const waitForRow = extractFunction(js, 'async function waitForCreatedRouteRow(slug, timeoutMs = 5_000)');
  const submit = extractFunction(js, 'async function onCreateRoute(e)');
  const build = extractFunction(js, 'function buildRoutes(o)');
  assert.match(open, /dialog\.showModal\(\)/);
  assert.match(open, /queueMicrotask\(\(\) => \$\('#rf-slug'\)\.focus\(\)\)/);
  assert.match(close, /const target = focusTarget \|\| routeDialogReturnFocus/);
  assert.match(close, /focusAfterRouteDialog\(target\)/);
  assert.match(restore, /target\.scrollIntoView\(\{ block: 'nearest' \}\)/);
  assert.match(restore, /target\.focus\(\{ preventScroll: true \}\)/);
  assert.match(waitForRow, /createdRouteRow\(slug\)/);
  assert.match(waitForRow, /row && !fetching && !refetchQueued/);
  assert.match(waitForRow, /row\.isConnected && !fetching && !refetchQueued/,
    'focus must bind only after all coalesced overview renders settle');
  assert.match(restoreCreated, /createdRouteRow\(pending\.slug\)/);
  assert.match(restoreCreated, /row\.focus\(\{ preventScroll: true \}\)/);
  assert.match(requestCreated, /pendingCreatedRouteFocus = pending/);
  assert.match(js, /setSection\('routes-body'[\s\S]*restorePendingCreatedRouteFocus\(\)/,
    'later forced renders must restore focus if they replace the newly created row');
  assert.match(submit, /await refreshOverview\(\{ force: true, fresh: true \}\)/);
  assert.match(submit, /await waitForCreatedRouteRow\(slug\)/);
  assert.match(submit, /closeRouteDialog\(createdRow \|\| \$\('#route-add'\)\)/);
  assert.match(submit, /requestCreatedRouteFocus\(slug\)/,
    'successful creation must return to and reveal the created collection row');
  assert.match(js, /'data-route-slug': r\.slug/);
  assert.doesNotMatch(build, /form above/,
    'the empty state must point to the visible creation action, not a displaced form');
});

test('the route dialog retains every target type and restores focus when cancelled', async () => {
  const [html, js] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
  ]);
  const dialog = html.slice(
    html.indexOf('<dialog id="route-dialog"'),
    html.indexOf('<dialog id="test-detail-dialog"'),
  );
  assert.match(dialog, /name="rf-kind" value="port" checked/);
  assert.match(dialog, /name="rf-kind" value="server"/);
  assert.match(dialog, /name="rf-kind" value="docker"/);
  assert.match(dialog, /id="rf-port"/);
  assert.match(dialog, /id="rf-server"/);
  assert.match(dialog, /id="rf-container"/);

  const fields = extractFunction(js, 'function updateRouteTargetFields()');
  const wire = extractFunction(js, 'function wireForm()');
  const submit = extractFunction(js, 'async function onCreateRoute(e)');
  assert.match(fields, /#rf-port-wrap'\)\.hidden = kind !== 'port'/);
  assert.match(fields, /#rf-server-wrap'\)\.hidden = kind !== 'server'/);
  assert.match(fields, /#rf-container-wrap'\)\.hidden = kind !== 'docker'/);
  assert.match(wire, /#route-cancel'\)\.addEventListener\('click', \(\) => closeRouteDialog\(\)\)/);
  assert.match(wire, /#route-dialog'\)\.addEventListener\('cancel'/);
  assert.match(submit, /if \(kind === 'port'\)/);
  assert.match(submit, /else if \(kind === 'docker'\)/);
  assert.match(submit, /state\.overview\?\.inventory\?\.servers/);
});

test('narrow route rows remain compact without changing the desktop collection', async () => {
  const css = await fsp.readFile(new URL('app.css', UI), 'utf8');
  assert.match(css, /\.routes-grid \{ grid-template-columns: minmax\(0, 1\.8fr\) minmax\(0, 1\.4fr\) 96px 150px 70px; \}/,
    'desktop routes must retain their aligned five-column collection');
  assert.match(css, /@media \(max-width: 719px\)[\s\S]*?\.routes-grid \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\) auto;[\s\S]*?grid-template-rows: auto auto auto;/,
    'mobile routes must use a compact three-band card instead of five full-width rows');
  assert.match(css, /\.routes-grid > :nth-child\(2\) \{ grid-column: 1 \/ 3; grid-row: 2;/,
    'the route target must keep the full readable card width');
  assert.match(css, /\.routes-grid > :nth-child\(5\) \{[\s\S]*?grid-column: 2;[\s\S]*?grid-row: 1;/,
    'the remove action must share the identity band instead of adding a row');
  assert.match(css, /\.routes-grid > \.cell\[data-label\]::before \{ display: none; \}/,
    'redundant table labels must not dominate compact cards');
});
