// Immutable browser assets must be addressed by their actual content. A
// stale manual version leaves an already-open Console on old JavaScript for
// up to an hour, which can hide a deployed UI correction during verification.

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { promises as fsp } from 'node:fs';

const UI_URL = new URL('../src/ui/', import.meta.url);

test('immutable UI asset query matches the deployed CSS and JavaScript content', async () => {
  const [index, css, js] = await Promise.all([
    fsp.readFile(new URL('index.html', UI_URL), 'utf8'),
    fsp.readFile(new URL('app.css', UI_URL)),
    fsp.readFile(new URL('app.js', UI_URL)),
  ]);
  const expected = crypto.createHash('sha256').update(css).update(js).digest('hex').slice(0, 12);
  const cssVersion = index.match(/href="\/app\.css\?v=([a-f0-9]+)"/)?.[1];
  const jsVersion = index.match(/src="\/app\.js\?v=([a-f0-9]+)"/)?.[1];
  assert.equal(cssVersion, expected,
    'app.css immutable URL must change whenever the stylesheet content changes');
  assert.equal(jsVersion, expected,
    'app.js immutable URL must change whenever the browser code changes');
});
