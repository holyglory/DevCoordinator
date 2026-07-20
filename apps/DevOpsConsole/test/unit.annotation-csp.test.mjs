// Codex in-app annotations need both dynamically positioned style attributes
// and renderer-owned inline style elements, including inside an inherited
// about:blank/srcdoc document. Keep those permissions split into CSP Level 3
// attr/elem directives so Console scripts and the broad style-src fallback
// remain strict.

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';

const INDEX_URL = new URL('../src/ui/index.html', import.meta.url);

function metaCsp(html) {
  const match = html.match(
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"\s*>/i,
  );
  assert.ok(match, 'Console index must retain an explicit Content Security Policy');
  return match[1];
}

function directives(csp) {
  return new Map(
    csp.split(';')
      .map((part) => part.trim().split(/\s+/))
      .filter((tokens) => tokens[0])
      .map(([name, ...sources]) => [name.toLowerCase(), sources]),
  );
}

function annotationPolicyErrors(csp) {
  const policy = directives(csp);
  const styleAttrSources = policy.get('style-src-attr')
    ?? policy.get('style-src')
    ?? policy.get('default-src')
    ?? [];
  const styleElementSources = policy.get('style-src-elem')
    ?? policy.get('style-src')
    ?? policy.get('default-src')
    ?? [];
  const broadStyleSources = policy.get('style-src') ?? [];
  const scriptSources = policy.get('script-src') ?? policy.get('default-src') ?? [];
  const errors = [];
  if (!styleAttrSources.includes("'unsafe-inline'")) {
    errors.push('annotation overlay style attributes are blocked');
  }
  if (!styleElementSources.includes("'unsafe-inline'")) {
    errors.push('annotation renderer style elements are blocked');
  }
  if (broadStyleSources.includes("'unsafe-inline'")) {
    errors.push('broad inline styles are allowed');
  }
  if (scriptSources.includes("'unsafe-inline'")) {
    errors.push('inline page scripts are allowed');
  }
  return errors;
}

test('annotation CSP detector catches blocked renderer styles without weakening scripts', () => {
  const incident = "default-src 'self'; img-src 'self' data:";
  assert.deepEqual(
    annotationPolicyErrors(incident),
    [
      'annotation overlay style attributes are blocked',
      'annotation renderer style elements are blocked',
    ],
    'the detector must catch both style boundaries in the original incident policy',
  );

  const attrOnly = "default-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; script-src 'self'";
  assert.deepEqual(
    annotationPolicyErrors(attrOnly),
    ['annotation renderer style elements are blocked'],
    'the detector must catch the deployed attr-only policy that the user proved incomplete',
  );

  const overbroad = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'";
  assert.deepEqual(
    annotationPolicyErrors(overbroad),
    ['broad inline styles are allowed', 'inline page scripts are allowed'],
    'annotation compatibility must not weaken broad style or script fallbacks',
  );

  const compatible = "default-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; style-src-elem 'self' 'unsafe-inline'; script-src 'self'";
  assert.deepEqual(annotationPolicyErrors(compatible), [],
    'split style attr/elem exceptions are the valid false-positive control');
});

test('Console policy supports annotation renderer styles and keeps scripts external', async () => {
  const csp = metaCsp(await fsp.readFile(INDEX_URL, 'utf8'));
  assert.deepEqual(annotationPolicyErrors(csp), []);
});
