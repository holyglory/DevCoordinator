import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';

const CSS_URL = new URL('../src/ui/app.css', import.meta.url);

test('every Console CSS custom-property reference has a local definition', async () => {
  const css = await fs.readFile(CSS_URL, 'utf8');
  const definitions = new Set(
    [...css.matchAll(/(?:^|[;{]\s*)(--[a-z0-9_-]+)\s*:/gim)]
      .map((match) => match[1]),
  );
  const references = new Set(
    [...css.matchAll(/var\(\s*(--[a-z0-9_-]+)/gim)]
      .map((match) => match[1]),
  );
  const missing = [...references].filter((name) => !definitions.has(name)).sort();

  assert.deepEqual(
    missing,
    [],
    'undefined custom properties silently invalidate maintenance and warning declarations',
  );
});
