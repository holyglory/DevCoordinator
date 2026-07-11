import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import test from 'node:test';
import tls from 'node:tls';

import { startServers } from '../src/server.mjs';
import { DEV_CERT, DEV_KEY, ensureDevCert } from './helpers/dev-cert.mjs';

test('production TLS binds the explicit IPv4 wildcard and answers IPv4 health', async () => {
  ensureDevCert();
  const credentials = {
    cert: fs.readFileSync(DEV_CERT),
    key: fs.readFileSync(DEV_KEY),
  };
  const certManager = {
    getCredentials: () => credentials,
    getSecureContext: () => tls.createSecureContext(credentials),
    onSwap() {},
  };
  const router = {
    handleRequest(_request, response) {
      const body = Buffer.from('{"ok":true}\n');
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-length': body.length,
      });
      response.end(body);
    },
    handleUpgrade(_request, socket) { socket.destroy(); },
  };
  const log = { info() {}, warn() {} };
  const servers = await startServers({
    config: {
      devInsecureHttp: false,
      httpsPort: 443,
      httpPort: 0,
    },
    log,
    certManager,
    router,
    listenPorts: { https: 0 },
  });
  try {
    const endpoint = servers.addresses.find((item) => item.name === 'https');
    assert.equal(endpoint?.host, '0.0.0.0');
    assert.equal(endpoint?.family, 'IPv4');
    const response = await new Promise((resolve, reject) => {
      const request = https.get({
        host: '127.0.0.1',
        port: endpoint.port,
        path: '/healthz',
        rejectUnauthorized: false,
      }, resolve);
      request.on('error', reject);
    });
    const body = await new Promise((resolve, reject) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      response.on('error', reject);
    });
    assert.equal(response.statusCode, 200);
    assert.equal(JSON.parse(body).ok, true);
  } finally {
    await servers.close();
  }
});
