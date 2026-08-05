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

test('Port leases leads with the real collection and opens a focused creation dialog', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  const section = html.slice(
    html.indexOf('<section id="sec-leases"'),
    html.indexOf('<section id="sec-assignments"'),
  );
  assert.match(section, /id="lease-add"[^>]*>Lease port</);
  assert.match(section, /id="leases-body"/);
  assert.doesNotMatch(section, /id="lease-form"/,
    'the creation form must not precede or displace the lease collection');
  assert.ok(html.indexOf('id="leases-body"') < html.indexOf('id="lease-dialog"'));
  assert.match(html, /<dialog id="lease-dialog"[^>]*>[\s\S]*<form id="lease-form"/);
  assert.match(css, /#lease-dialog(?:,|\s*\{)/,
    'the lease dialog may share its complete dialog rule with peer dialogs');
  assert.match(css, /#lease-dialog::backdrop(?:,|\s*\{)/,
    'the lease backdrop may share its complete backdrop rule with peer dialogs');

  const open = extractFunction(js, 'function openLeaseDialog()');
  const close = extractFunction(js, 'function closeLeaseDialog(focusTarget = null)');
  const restore = extractFunction(js, 'function focusAfterLeaseDialog(target)');
  const findCreated = extractFunction(js, 'function createdLeaseRow(lease)');
  const restoreCreated = extractFunction(js, 'function restorePendingCreatedLeaseFocus()');
  const requestCreated = extractFunction(js, 'function requestCreatedLeaseFocus(lease)');
  const waitForRow = extractFunction(js, 'async function waitForCreatedLeaseRow(lease, timeoutMs = 5_000)');
  const submit = extractFunction(js, 'async function onLeasePort(e)');
  const build = extractFunction(js, 'function buildLeases(o)');
  assert.match(open, /dialog\.showModal\(\)/);
  assert.match(open, /queueMicrotask\(\(\) => \$\('#lf-purpose'\)\.focus\(\)\)/);
  assert.match(close, /const target = focusTarget \|\| leaseDialogReturnFocus/);
  assert.match(close, /focusAfterLeaseDialog\(target\)/);
  assert.match(restore, /target\.scrollIntoView\(\{ block: 'nearest' \}\)/);
  assert.match(restore, /target\.focus\(\{ preventScroll: true \}\)/);
  assert.match(findCreated, /#leases-body \[data-lease-id\]/);
  assert.match(waitForRow, /createdLeaseRow\(lease\)/);
  assert.match(waitForRow, /row && !fetching && !refetchQueued/);
  assert.match(waitForRow, /row\.isConnected && !fetching && !refetchQueued/,
    'focus must bind only after all coalesced overview renders settle');
  assert.match(restoreCreated, /createdLeaseRow\(pending\.lease\)/);
  assert.match(restoreCreated, /row\.focus\(\{ preventScroll: true \}\)/);
  assert.match(requestCreated, /pendingCreatedLeaseFocus = pending/);
  assert.match(js, /setSection\('assignments-body'[\s\S]*restorePendingCreatedLeaseFocus\(\)/,
    'later forced renders must restore focus if they replace the newly created row');
  assert.match(waitForRow, /await new Promise\(\(resolve\) => setTimeout\(resolve, 50\)\)/,
    'a coalesced overview refresh must settle before focus returns to collection context');
  assert.match(submit, /await refreshOverview\(\{ force: true, fresh: true \}\)/);
  assert.match(submit, /await waitForCreatedLeaseRow\(lease\)/);
  assert.match(submit, /requestCreatedLeaseFocus\(lease\)/);
  assert.match(submit, /closeLeaseDialog\(createdRow \|\| \$\('#lease-add'\)\)/,
    'successful creation must return to and reveal the created collection row');
  assert.doesNotMatch(build, /form above/,
    'the empty state must point to the visible creation action, not a displaced form');
});
