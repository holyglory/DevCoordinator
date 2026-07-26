import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const html = fs.readFileSync(path.join(APP_ROOT, 'src', 'ui', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(APP_ROOT, 'src', 'ui', 'app.js'), 'utf8');

test('route creation states the real TLS-termination and HTTP-upstream boundary', () => {
  assert.match(
    html,
    /Console terminates public HTTPS, then forwards plain HTTP to this target/,
    'the main route form must explain that target ports speak HTTP',
  );
  assert.match(
    html,
    /Choose the app's HTTP listener, not its HTTPS\/TLS listener/,
    'the main route form must tell operators how to avoid assigning a TLS-only port',
  );
});

test('Docker subdomain editing and route status keep the upstream protocol explicit', () => {
  assert.match(app, /HTTP container port/);
  assert.match(app, /The Console terminates public HTTPS and forwards plain HTTP/);
  assert.match(app, /http:\/\/127\.0\.0\.1:/);
});
