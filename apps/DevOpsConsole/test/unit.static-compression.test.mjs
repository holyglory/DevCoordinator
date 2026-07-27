import assert from 'node:assert/strict';
import { brotliDecompressSync, gunzipSync } from 'node:zlib';
import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { finished } from 'node:stream/promises';
import test from 'node:test';

import { createStaticServer } from '../src/static.mjs';

async function fixture(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'console-static-compression-'));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const source = 'const dashboard = "fast";\n'.repeat(5000);
  await fsp.writeFile(path.join(dir, 'app.js'), source);
  const files = createStaticServer({ dir, log: null });
  return { source, files };
}

class ResponseRecorder extends Writable {
  constructor() {
    super();
    this.status = null;
    this.headers = {};
    this.headersSent = false;
    this.chunks = [];
  }

  writeHead(status, headers) {
    this.status = status;
    this.headers = headers;
    this.headersSent = true;
  }

  _write(chunk, _encoding, callback) {
    this.chunks.push(Buffer.from(chunk));
    callback();
  }
}

async function get(files, headers = {}) {
  const response = new ResponseRecorder();
  const done = finished(response);
  await files.handle({ method: 'GET', url: '/app.js', headers }, response);
  await done;
  return { response, body: Buffer.concat(response.chunks) };
}

test('compressible immutable assets negotiate Brotli and gzip with representation validators', async (t) => {
  const { source, files } = await fixture(t);
  const br = await get(files, { 'accept-encoding': 'br' });
  assert.equal(br.response.headers['content-encoding'], 'br');
  assert.equal(br.response.headers.vary, 'Accept-Encoding');
  assert.equal(brotliDecompressSync(br.body).toString(), source);

  const gzip = await get(files, { 'accept-encoding': 'gzip' });
  assert.equal(gzip.response.headers['content-encoding'], 'gzip');
  assert.equal(gunzipSync(gzip.body).toString(), source);
  assert.notEqual(br.response.headers.etag, gzip.response.headers.etag);
  assert.ok(br.body.length < Buffer.byteLength(source) / 5, 'browser JavaScript should transfer compactly');
});
