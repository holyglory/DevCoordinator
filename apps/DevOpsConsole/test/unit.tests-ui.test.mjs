import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI = new URL('../src/ui/', import.meta.url);

test('Tests destination leads with repository-scoped real statistics and bounded tables', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  assert.match(html, /data-nav="tests">Tests/);
  assert.match(html, /data-page="tests"/);
  assert.ok(html.indexOf('id="tests-h"') < html.indexOf('id="tests-body"'));
  assert.match(js, /function loadTests\(/);
  assert.match(js, /\/api\/tests\?project=/);
  for (const promisedView of [
    'By day', 'Time by test set', 'Individual test duration', 'Recent runs',
  ]) {
    assert.ok(js.includes(promisedView), promisedView);
  }
  assert.match(js, /cell\.dataset\.label = headers\[index\]/);
  assert.match(js, /cell\.setAttribute\('aria-label'/);
  assert.match(css, /\.test-table td::before/);
  assert.match(css, /content: attr\(data-label\)/);
});
