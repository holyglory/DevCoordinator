// End-to-end tests against the WHOLE console stack booted in-process:
// real TLS edge (dev wildcard cert, OS-assigned ports on 127.0.0.1), real
// fixture OIDC issuer, real HTTP/SSE/WebSocket upstreams, and a REAL
// codex-dev-coordinator (`api serve`) with an isolated state home.
//
// Run: node --test test/e2e.stack.test.mjs

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { promises as fsp } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import tls from 'node:tls';

import {
  apiCall,
  browse,
  fetchUrl,
  login,
  makeJar,
  startStack,
} from './helpers/stack.mjs';
import { wsAcceptFor } from './helpers/ws-echo.mjs';

const FIXTURE_EMAIL = 'ja@vr.ae';

// macOS CI runners hang `python3 -m http.server` in getfqdn() before it ever
// listens; this equivalent fixture uses plain socketserver.TCPServer (same
// directory listing, no name resolution). {port} is the coordinator template.
const PY_HTTP_FIXTURE = "python3 -c 'import socketserver, http.server, sys; socketserver.TCPServer.allow_reuse_address = True; socketserver.TCPServer((\"127.0.0.1\", int(sys.argv[1])), http.server.SimpleHTTPRequestHandler).serve_forever()' {port}";

describe('e2e: full console stack', () => {
  /** @type {Awaited<ReturnType<typeof startStack>>} */
  let stack;
  let userJar; // authed after the login test; later tests re-login defensively
  let dockerWeb; // real listener standing in for the docker-published web app
  let dockerCallsLog; // fake docker appends start/stop/restart argv here
  const extraTempDirs = [];
  const openSockets = new Set();

  // The stack's coordinator sees a FAKE docker CLI (first on its PATH): one
  // healthy web container whose published host port is a real local listener
  // (so docker-kind routes proxy to something live), one multi-port container
  // for the port-disambiguation contract, and an action log for start/stop/
  // restart wiring proof. Postgres-looking containers are deliberately absent.
  async function startDockerWebBackend() {
    const listenOnce = () => new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('docker-web ok');
      });
      server.listen(0, '127.0.0.1', () => resolve({
        port: server.address().port,
        close: () => new Promise((done) => {
          // Drop kept-alive proxy connections first or close() can stall.
          server.closeAllConnections?.();
          server.close(done);
        }),
      }));
      server.on('error', reject);
    });
    // The coordinator classifies anything whose ports string CONTAINS
    // "5432" as postgres — an OS-assigned port like 54321 would silently
    // demote the fixture to a database. Redraw until clean.
    for (;;) {
      const backend = await listenOnce();
      if (!String(backend.port).includes('5432')) return backend;
      await backend.close();
    }
  }

  async function writeFakeDocker(binDir, webHostPort, callsLog) {
    const projectDir = path.join(binDir, 'e2eweb-project');
    await fsp.mkdir(projectDir, { recursive: true });
    const labels = {
      'com.docker.compose.project': 'e2eweb',
      'com.docker.compose.project.working_dir': projectDir,
      'com.docker.compose.service': 'app',
    };
    const psRows = [
      {
        ID: 'eeeb00000001', Names: 'e2eweb-app-1', Image: 'e2eweb-app',
        Status: 'Up 2 minutes (healthy)',
        // Container port 3000 published on the fixture listener's host port —
        // different numbers on purpose, so resolution must use the mapping.
        Ports: `0.0.0.0:${webHostPort}->3000/tcp, :::${webHostPort}->3000/tcp`,
      },
      {
        ID: 'eeea00000002', Names: 'e2emulti-app-1', Image: 'e2emulti-app',
        Status: 'Up 2 minutes',
        Ports: '0.0.0.0:19998->3000/tcp, 0.0.0.0:19999->9000/tcp',
      },
      {
        // Dedicated to the stale-route lifecycle test: a seeded route points
        // at container port 4000, which this container does NOT publish.
        ID: 'eeea00000003', Names: 'e2estale-app-1', Image: 'e2estale-app',
        Status: 'Up 2 minutes',
        Ports: '0.0.0.0:19997->3000/tcp',
      },
    ];
    const inspectMap = {};
    for (const row of psRows) {
      const full = { Id: `${row.ID}deadbeef`, Name: `/${row.Names}`, Config: { Labels: labels } };
      inspectMap[row.ID] = full;
      inspectMap[row.Names] = full;
    }
    const script = `#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
ps_rows = json.loads(${JSON.stringify(JSON.stringify(psRows))})
inspect_map = json.loads(${JSON.stringify(JSON.stringify(inspectMap))})
if args[:1] == ["ps"]:
    for row in ps_rows:
        print(json.dumps(row))
elif args[:3] == ["inspect", "--format", "{{json .State}}"]:
    for _ in args[3:]:
        print(json.dumps({"Status": "running", "Running": True}))
elif args[:3] == ["inspect", "--format", "{{json .}}"]:
    for key in args[3:]:
        print(json.dumps(inspect_map[key]))
elif args[:1] == ["stats"]:
    pass
elif args[:1] == ["logs"]:
    print("e2e fake container log line")
elif args[:1] in (["start"], ["stop"], ["restart"]):
    with open(${JSON.stringify(callsLog)}, "a") as fh:
        fh.write(" ".join(args) + "\\n")
else:
    sys.exit(1)
`;
    const fakeDocker = path.join(binDir, 'docker');
    await fsp.writeFile(fakeDocker, script, { encoding: 'utf8', mode: 0o755 });
  }

  before(async () => {
    dockerWeb = await startDockerWebBackend();
    const fakeBin = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-dockerbin-'));
    extraTempDirs.push(fakeBin);
    dockerCallsLog = path.join(fakeBin, 'docker-calls.log');
    await writeFakeDocker(fakeBin, dockerWeb.port, dockerCallsLog);

    stack = await startStack({
      allowedEmails: [FIXTURE_EMAIL],
      coordinatorEnv: { PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}` },
      routes: ({ upstream, wsEcho }) => [
        // app -> ws-echo (answers plain GET too) — protected by default.
        { slug: 'app', kind: 'port', port: wsEcho.port },
        // echo -> HTTP echo upstream — protected (exercised with a session).
        { slug: 'echo', kind: 'port', port: upstream.port },
        // pub -> HTTP echo upstream — explicitly public.
        { slug: 'pub', kind: 'port', port: upstream.port, auth: 'public' },
        // A docker route whose container port is NOT currently published —
        // auth changes and renames must keep working on it (test 17).
        { slug: 'dockstale', kind: 'docker', containerName: 'e2estale-app-1', containerPort: 4000 },
      ],
    });
  });

  after(async () => {
    for (const socket of openSockets) {
      try {
        socket.destroy();
      } catch {
        // already gone
      }
    }
    if (stack) await stack.close();
    // The docker-web fixture listener refs the event loop — leaving it open
    // wedges `node --test` (and therefore validate.py/CI) after a green run.
    if (dockerWeb) await dockerWeb.close();
    for (const dir of extraTempDirs) {
      await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  });

  async function freshLogin() {
    const jar = makeJar();
    stack.issuer.setClaims({ email: FIXTURE_EMAIL, email_verified: true });
    const res = await login(stack, jar);
    assert.equal(res.status, 200, `login flow should end 200, got ${res.status}: ${res.text.slice(0, 200)}`);
    return jar;
  }

  async function authedJar() {
    if (!userJar) userJar = await freshLogin();
    return userJar;
  }

  function edgeTlsSocket() {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host: '127.0.0.1', port: stack.httpsPort, rejectUnauthorized: false },
        () => resolve(socket),
      );
      socket.once('error', reject);
      openSockets.add(socket);
      socket.on('close', () => openSockets.delete(socket));
    });
  }

  function readUntil(socket, predicate, { timeoutMs = 8000 } = {}) {
    return new Promise((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`readUntil timed out; got ${JSON.stringify(buf.toString('latin1').slice(0, 300))}`));
      }, timeoutMs);
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (predicate(buf)) {
          cleanup();
          resolve(buf);
        }
      };
      const onEnd = () => {
        if (predicate(buf)) {
          cleanup();
          resolve(buf);
        } else {
          cleanup();
          reject(new Error(`socket ended early; got ${JSON.stringify(buf.toString('latin1').slice(0, 300))}`));
        }
      };
      const cleanup = () => {
        clearTimeout(timer);
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onEnd);
      };
      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onEnd);
    });
  }

  function maskedFrame(opcode, payload) {
    const mask = crypto.randomBytes(4);
    const out = Buffer.alloc(2 + 4 + payload.length);
    out[0] = 0x80 | opcode;
    out[1] = 0x80 | payload.length;
    mask.copy(out, 2);
    for (let i = 0; i < payload.length; i++) out[6 + i] = payload[i] ^ mask[i % 4];
    return out;
  }

  // -------------------------------------------------------------------------

  it('1. /healthz answers 200 on both listeners; plain HTTP 301s to https preserving host+path', async () => {
    const httpsHealth = await fetchUrl(stack, 'https://console.vr.ae/healthz');
    assert.equal(httpsHealth.status, 200);
    assert.equal(httpsHealth.text, 'ok');

    const httpHealth = await fetchUrl(stack, 'http://console.vr.ae/healthz');
    assert.equal(httpHealth.status, 200);
    assert.equal(httpHealth.text, 'ok');

    const redirect = await fetchUrl(stack, 'http://foo.vr.ae/x/y?q=1&z=%20two');
    assert.equal(redirect.status, 301);
    assert.equal(redirect.headers.location, `https://foo.vr.ae:${stack.httpsPort}/x/y?q=1&z=%20two`);

    // Non-GET must use 308 so the method survives the redirect.
    const post = await fetchUrl(stack, 'http://foo.vr.ae/hook', { method: 'POST', body: '{}' });
    assert.equal(post.status, 308);
    assert.equal(post.headers.location, `https://foo.vr.ae:${stack.httpsPort}/hook`);
  });

  it('1b. ACME HTTP-01 challenge is served over plain HTTP without redirect', async () => {
    const dir = path.join(stack.stateDir, 'acme', '.well-known', 'acme-challenge');
    await fsp.mkdir(dir, { recursive: true });
    const token = 'tok_' + crypto.randomBytes(8).toString('hex');
    const body = token + '.keyauth-value';
    await fsp.writeFile(path.join(dir, token), body);

    // Served as 200 over plain HTTP (Let's Encrypt validates on port 80),
    // NOT redirected to https — even for an arbitrary/unknown vhost.
    const served = await fetchUrl(stack, `http://any.vr.ae/.well-known/acme-challenge/${token}`);
    assert.equal(served.status, 200);
    assert.equal(served.text, body);

    // A missing token is a 404, not a redirect.
    const missing = await fetchUrl(stack, 'http://any.vr.ae/.well-known/acme-challenge/does-not-exist');
    assert.equal(missing.status, 404);

    // Traversal attempts never escape the challenge dir.
    const traversal = await fetchUrl(stack, 'http://any.vr.ae/.well-known/acme-challenge/..%2f..%2f..%2fetc%2fpasswd');
    assert.equal(traversal.status, 404);
  });

  it('2. anonymous protected slug 302s to console login with rt; anonymous public route proxies 200', async () => {
    const protectedRes = await fetchUrl(stack, 'https://echo.vr.ae/', { headers: { accept: 'text/html' } });
    assert.equal(protectedRes.status, 302);
    assert.equal(
      protectedRes.headers.location,
      `${stack.consoleOrigin}/auth/login?rt=${encodeURIComponent('https://echo.vr.ae/')}`,
    );

    const publicRes = await fetchUrl(stack, 'https://pub.vr.ae/hello-public', { headers: { accept: 'text/html' } });
    assert.equal(publicRes.status, 200);
    const echoed = JSON.parse(publicRes.text);
    assert.equal(echoed.method, 'GET');
    assert.equal(echoed.path, '/hello-public');
  });

  it('3. full login: console -> issuer -> callback; Domain=.vr.ae session works across subdomains', async () => {
    const jar = makeJar();
    stack.issuer.setClaims({ email: FIXTURE_EMAIL, email_verified: true });

    // Anonymous console visit redirects to the login page.
    const anon = await fetchUrl(stack, `${stack.consoleOrigin}/`, { jar, headers: { accept: 'text/html' } });
    assert.equal(anon.status, 302);
    assert.ok(
      anon.headers.location.startsWith(`${stack.consoleOrigin}/auth/login?rt=`),
      `unexpected login redirect: ${anon.headers.location}`,
    );

    // Kick off the OIDC flow.
    const start = await fetchUrl(stack, `${stack.consoleOrigin}/auth/start?rt=${encodeURIComponent(`${stack.consoleOrigin}/`)}`, {
      jar,
      headers: { accept: 'text/html' },
    });
    assert.equal(start.status, 302);
    const authorizeUrl = new URL(start.headers.location);
    assert.equal(authorizeUrl.origin, stack.issuer.url, 'authorize must point at the fixture issuer');
    assert.equal(authorizeUrl.searchParams.get('client_id'), 'test-client');
    assert.equal(authorizeUrl.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(authorizeUrl.searchParams.get('nonce'), 'authorize carries a nonce');
    assert.ok(start.setCookies.some((c) => c.startsWith('dc_flow=')), 'flow cookie set');

    // Issuer auto-approves and bounces straight back with code & state.
    const issuerHop = await fetchUrl(stack, authorizeUrl.href, { jar });
    assert.equal(issuerHop.status, 302);
    const callbackUrl = new URL(issuerHop.headers.location);
    assert.equal(callbackUrl.hostname, stack.consoleHost);
    assert.equal(callbackUrl.pathname, '/auth/callback');
    assert.equal(callbackUrl.searchParams.get('state'), authorizeUrl.searchParams.get('state'));
    assert.ok(callbackUrl.searchParams.get('code'), 'authorization code present');

    // Callback verifies everything and issues the session cookie.
    const callback = await fetchUrl(stack, callbackUrl.href, { jar, headers: { accept: 'text/html' } });
    assert.equal(callback.status, 302);
    const sessionSetCookie = callback.setCookies.find((c) => c.startsWith('dc_session='));
    assert.ok(sessionSetCookie, `expected dc_session cookie, got: ${callback.setCookies.join(' | ')}`);
    assert.match(sessionSetCookie, /;\s*Domain=\.vr\.ae/i, 'session cookie must span *.vr.ae');
    assert.match(sessionSetCookie, /;\s*HttpOnly/i);
    assert.match(sessionSetCookie, /;\s*Secure/i);
    assert.match(sessionSetCookie, /;\s*SameSite=Lax/i);

    // Session identifies the fixture user.
    const sessionInfo = await apiCall(stack, jar, 'GET', '/api/session');
    assert.equal(sessionInfo.status, 200);
    assert.equal(sessionInfo.json.email, FIXTURE_EMAIL);

    // The SAME jar now reaches a protected app subdomain: cross-subdomain SSO.
    const app = await fetchUrl(stack, 'https://app.vr.ae/', { jar, headers: { accept: 'text/html' } });
    assert.equal(app.status, 200);
    assert.equal(app.text, 'ws-echo online');

    userJar = jar;
  });

  it('4. disallowed email gets the 403 denied page and NO session cookie', async () => {
    const jar = makeJar();
    stack.issuer.setClaims({ email: 'intruder@evil.example', email_verified: true });
    try {
      const res = await login(stack, jar);
      assert.equal(res.status, 403);
      assert.match(res.text, /Access denied/);
      assert.match(res.text, /intruder@evil\.example/);
      const allSetCookies = res.hops.flatMap((h) => h.setCookies);
      assert.ok(
        !allSetCookies.some((c) => c.startsWith('dc_session=') && !/Max-Age=0/i.test(c)),
        `no session cookie may be issued: ${allSetCookies.join(' | ')}`,
      );
      assert.equal(jar.get('dc_session'), null, 'jar must hold no session');

      // And the cookieless jar still cannot reach protected content.
      const probe = await fetchUrl(stack, 'https://echo.vr.ae/', { jar, headers: { accept: 'text/html' } });
      assert.equal(probe.status, 302);
    } finally {
      stack.issuer.setClaims({ email: FIXTURE_EMAIL, email_verified: true });
    }
  });

  it('5. proxy correctness: method/path/query/body echo, Host preserved, X-Forwarded-*, hop-by-hop stripped, SSE streams', async () => {
    const jar = await authedJar();

    const body = JSON.stringify({ hello: 'world', n: 42 });
    const res = await fetchUrl(stack, 'https://echo.vr.ae/some/path?x=1&y=%20two', {
      method: 'POST',
      jar,
      body,
      headers: {
        'content-type': 'application/json',
        te: 'trailers',
        'proxy-authorization': 'Basic c2VjcmV0',
        'x-hop': 'do-not-forward',
        connection: 'x-hop', // names x-hop as hop-by-hop
        'x-end-to-end': 'keep-me',
      },
    });
    assert.equal(res.status, 200);
    const echoed = JSON.parse(res.text);
    assert.equal(echoed.method, 'POST');
    assert.equal(echoed.path, '/some/path?x=1&y=%20two');
    assert.equal(echoed.body, body);
    // Host preserved end-to-end (dev servers see the public vhost).
    assert.equal(echoed.headers.host, 'echo.vr.ae');
    assert.equal(echoed.headers['x-forwarded-proto'], 'https');
    assert.equal(echoed.headers['x-forwarded-host'], 'echo.vr.ae');
    assert.equal(echoed.headers['x-forwarded-for'], '127.0.0.1');
    // Hop-by-hop request headers must not cross the proxy.
    assert.equal(echoed.headers.te, undefined, 'te is hop-by-hop');
    assert.equal(echoed.headers['proxy-authorization'], undefined, 'proxy-authorization is hop-by-hop');
    assert.equal(echoed.headers['x-hop'], undefined, 'headers named by Connection are hop-by-hop');
    // End-to-end headers do cross.
    assert.equal(echoed.headers['x-end-to-end'], 'keep-me');
    // The session cookie rides along to the upstream like any browser cookie.
    assert.match(String(echoed.headers.cookie ?? ''), /dc_session=/);

    // SSE: three events must arrive incrementally, not as one buffered blob.
    const sse = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: stack.httpsPort,
          path: '/sse',
          headers: {
            host: 'echo.vr.ae',
            accept: 'text/event-stream',
            cookie: `dc_session=${jar.get('dc_session').value}`,
          },
          rejectUnauthorized: false,
          agent: false,
        },
        (response) => {
          const chunks = [];
          response.on('data', (chunk) => chunks.push({ at: Date.now(), text: chunk.toString('utf8') }));
          response.on('end', () =>
            resolve({ status: response.statusCode, headers: response.headers, chunks }),
          );
          response.on('error', reject);
        },
      );
      req.setTimeout(10_000, () => req.destroy(new Error('SSE request timed out')));
      req.on('error', reject);
      req.end();
    });
    assert.equal(sse.status, 200);
    assert.match(String(sse.headers['content-type']), /text\/event-stream/);
    const fullText = sse.chunks.map((c) => c.text).join('');
    assert.match(fullText, /data: event-1/);
    assert.match(fullText, /data: event-2/);
    assert.match(fullText, /data: event-3/);
    assert.ok(sse.chunks.length >= 2, `expected incremental chunks, got ${sse.chunks.length}`);
    assert.ok(
      !sse.chunks[0].text.includes('event-3'),
      'first chunk arriving with the last event means the proxy buffered the stream',
    );
    const spreadMs = sse.chunks.at(-1).at - sse.chunks[0].at;
    assert.ok(spreadMs >= 100, `chunks arrived ${spreadMs}ms apart; a buffered stream would arrive at once`);
  });

  it('6. WebSocket end-to-end through the TLS edge; anonymous upgrade is refused before 101', async () => {
    const jar = await authedJar();
    const token = jar.get('dc_session').value;

    // --- authenticated upgrade to the protected app slug ---
    const socket = await edgeTlsSocket();
    const wsKey = crypto.randomBytes(16).toString('base64');
    socket.write(
      [
        'GET /live HTTP/1.1',
        'Host: app.vr.ae',
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Version: 13',
        `Sec-WebSocket-Key: ${wsKey}`,
        `Cookie: dc_session=${token}`,
        '',
        '',
      ].join('\r\n'),
    );

    const handshake = await readUntil(socket, (buf) => buf.includes('\r\n\r\n'));
    const headerEnd = handshake.indexOf('\r\n\r\n') + 4;
    const rawHeader = handshake.subarray(0, headerEnd).toString('latin1');
    assert.match(rawHeader, /^HTTP\/1\.1 101 /, `expected 101, got: ${rawHeader.split('\r\n')[0]}`);
    const acceptLine = rawHeader.split('\r\n').find((l) => /^sec-websocket-accept:/i.test(l));
    assert.ok(acceptLine, 'Sec-WebSocket-Accept header present');
    assert.equal(acceptLine.split(':')[1].trim(), wsAcceptFor(wsKey));

    // Send masked 'ping' text; expect the unmasked echo 0x81 0x04 'ping'.
    let leftover = handshake.subarray(headerEnd);
    socket.write(maskedFrame(0x1, Buffer.from('ping')));
    const expectEcho = Buffer.concat([Buffer.from([0x81, 0x04]), Buffer.from('ping')]);
    const echoedBuf = await readUntil(
      socket,
      (buf) => Buffer.concat([leftover, buf]).includes(expectEcho),
    );
    assert.ok(Buffer.concat([leftover, echoedBuf]).includes(expectEcho), 'echoed text frame received');

    // Close handshake: masked close out, close frame back.
    socket.write(maskedFrame(0x8, Buffer.alloc(0)));
    const closeBuf = await readUntil(socket, (buf) => {
      for (let i = 0; i + 1 < buf.length; i++) if ((buf[i] & 0x0f) === 0x8 && (buf[i] & 0x80) !== 0) return true;
      return false;
    });
    assert.ok(closeBuf.length >= 2, 'close frame received');
    socket.destroy();

    // --- anonymous upgrade must be refused before any 101 ---
    const anonSocket = await edgeTlsSocket();
    anonSocket.write(
      [
        'GET /live HTTP/1.1',
        'Host: app.vr.ae',
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Version: 13',
        `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}`,
        '',
        '',
      ].join('\r\n'),
    );
    const refusal = await readUntil(anonSocket, (buf) => buf.includes('\r\n') || buf.length > 0);
    const firstLine = refusal.toString('latin1').split('\r\n')[0];
    assert.match(firstLine, /^HTTP\/1\.1 401 /, `anonymous upgrade must be 401, got: ${firstLine}`);
    assert.ok(!refusal.toString('latin1').includes(' 101 '), 'no 101 for anonymous upgrade');
    anonSocket.destroy();
  });

  it('7. PATCH /api/routes/:slug flips public/login live; Origin is enforced on mutations', async () => {
    const jar = await authedJar();

    // Create a protected route through the console API (with proper Origin).
    const created = await apiCall(stack, jar, 'POST', '/api/routes', {
      slug: 'toggle',
      kind: 'port',
      port: stack.upstream.port,
    }, { origin: stack.consoleOrigin });
    assert.equal(created.status, 201, created.text);
    assert.equal(created.json.auth, 'google', 'routes must default to login-protected');

    // Anonymous request: redirected to login.
    const before = await fetchUrl(stack, 'https://toggle.vr.ae/', { headers: { accept: 'text/html' } });
    assert.equal(before.status, 302);

    // Mutations without Origin (or with a foreign one) are rejected.
    const noOrigin = await apiCall(stack, jar, 'PATCH', '/api/routes/toggle', { auth: 'public' });
    assert.equal(noOrigin.status, 403);
    const foreignOrigin = await apiCall(stack, jar, 'PATCH', '/api/routes/toggle', { auth: 'public' }, {
      origin: 'https://evil.example',
    });
    assert.equal(foreignOrigin.status, 403);
    // Still protected: the rejected PATCHes must not have taken effect.
    const stillProtected = await fetchUrl(stack, 'https://toggle.vr.ae/', { headers: { accept: 'text/html' } });
    assert.equal(stillProtected.status, 302);

    // Legitimate PATCH flips the live behavior without any restart.
    const patched = await apiCall(stack, jar, 'PATCH', '/api/routes/toggle', { auth: 'public' }, {
      origin: stack.consoleOrigin,
    });
    assert.equal(patched.status, 200, patched.text);
    assert.equal(patched.json.auth, 'public');

    const after = await fetchUrl(stack, 'https://toggle.vr.ae/now-public', { headers: { accept: 'text/html' } });
    assert.equal(after.status, 200);
    assert.equal(JSON.parse(after.text).path, '/now-public');
  });

  it('8. unknown slug: 404 page for authed users, login redirect indistinguishable from protected for anonymous', async () => {
    const jar = await authedJar();

    const authed = await fetchUrl(stack, 'https://nosuchroute.vr.ae/', { jar, headers: { accept: 'text/html' } });
    assert.equal(authed.status, 404);
    assert.match(authed.text, /Route not found/);
    assert.match(authed.text, /nosuchroute\.vr\.ae/);

    // Anonymous: unknown and protected-but-existing must be the same shape.
    const anonUnknown = await fetchUrl(stack, 'https://nosuchroute.vr.ae/', { headers: { accept: 'text/html' } });
    const anonProtected = await fetchUrl(stack, 'https://echo.vr.ae/', { headers: { accept: 'text/html' } });
    assert.equal(anonUnknown.status, anonProtected.status);
    assert.equal(anonUnknown.status, 302);
    const shape = (location) => String(location).replace(/rt=[^&]+/, 'rt=X');
    assert.equal(shape(anonUnknown.headers.location), shape(anonProtected.headers.location));
    assert.equal(
      decodeURIComponent(anonUnknown.headers.location.split('rt=')[1]),
      'https://nosuchroute.vr.ae/',
    );
  });

  it('9. coordinator-backed route: servers/start -> kind=server route -> proxied 200 -> stop -> styled 502', { timeout: 120_000 }, async () => {
    const jar = await authedJar();

    // A real throwaway project repo for coordinator attribution.
    const projectDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-project-'));
    extraTempDirs.push(projectDir);
    execFileSync('git', ['-C', projectDir, 'init', '-q']);
    const toplevel = execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
    }).trim();

    // Start a real server THROUGH the coordinator (isolated home, leased
    // port). The lease window is randomized per run and the start is retried:
    // concurrent suites use isolated coordinator homes, so two coordinators
    // can bind-test the same free port at the same instant — the losing
    // child dies at bind time and shows up as 'unhealthy'. A retry re-leases
    // (the winner now occupies the port, so the bind test skips it).
    const rangeBase = 22000 + crypto.randomInt(0, 70) * 100;
    let server = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      server = await stack.coordinator.api('POST', '/v1/servers/start', {
        agent: 'e2e',
        project: toplevel,
        name: 'e2e-web',
        cmd: PY_HTTP_FIXTURE,
        range: `${rangeBase}-${rangeBase + 99}`,
        health_timeout: 20,
      }, { timeoutMs: 60_000 });
      if (server.status === 'running') break;
    }
    assert.equal(server.status, 'running', `coordinator server should be running: ${JSON.stringify(server.health)}`);
    assert.ok(Number.isInteger(server.port));

    // Wire a kind=server route to it via the console API.
    const created = await apiCall(stack, jar, 'POST', '/api/routes', {
      slug: 'coord',
      kind: 'server',
      project: toplevel,
      serverName: 'e2e-web',
    }, { origin: stack.consoleOrigin });
    assert.equal(created.status, 201, created.text);

    // Fetch through the edge; allow a few retries while the raw-servers cache
    // (3s) picks up the fresh record.
    let proxied = null;
    for (let attempt = 0; attempt < 40; attempt++) {
      proxied = await fetchUrl(stack, 'https://coord.vr.ae/', { jar, headers: { accept: 'text/html' } });
      if (proxied.status === 200) break;
      await delay(250);
    }
    assert.equal(proxied.status, 200, `expected python http.server listing, got ${proxied.status}: ${proxied.text.slice(0, 200)}`);
    assert.match(proxied.text, /Directory listing/i);

    // Stop the server via the console API (attributed coordinator mutation).
    const stopped = await apiCall(stack, jar, 'POST', '/api/servers/action', {
      id: server.id,
      action: 'stop',
      reason: 'e2e teardown of coordinator-backed route',
    }, { origin: stack.consoleOrigin });
    assert.equal(stopped.status, 200, stopped.text);
    assert.equal(stopped.json.server.status, 'stopped');

    // The route must now render the styled upstream-unavailable page.
    let blocked = null;
    for (let attempt = 0; attempt < 40; attempt++) {
      blocked = await fetchUrl(stack, 'https://coord.vr.ae/', { jar, headers: { accept: 'text/html' } });
      if (blocked.status === 502) break;
      await delay(250);
    }
    assert.equal(blocked.status, 502, `expected 502 after stop, got ${blocked.status}`);
    assert.match(blocked.text, /Upstream unavailable/);
    assert.match(blocked.text, /coord\.vr\.ae/);
    assert.match(blocked.text, /DevOps Console/);
  });

  it('9b. per-server subdomain: assign / change / remove via /api/servers/subdomain; Origin enforced', { timeout: 120_000 }, async () => {
    const jar = await authedJar();

    const projectDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-subdomain-'));
    extraTempDirs.push(projectDir);
    execFileSync('git', ['-C', projectDir, 'init', '-q']);
    const toplevel = execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();

    const rangeBase = 23000 + crypto.randomInt(0, 60) * 100;
    let server = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      server = await stack.coordinator.api('POST', '/v1/servers/start', {
        agent: 'e2e', project: toplevel, name: 'sub-web',
        cmd: PY_HTTP_FIXTURE,
        range: `${rangeBase}-${rangeBase + 99}`, health_timeout: 20,
      }, { timeoutMs: 60_000 });
      if (server.status === 'running') break;
    }
    assert.equal(server.status, 'running', `server should be running: ${JSON.stringify(server.health)}`);

    // Origin is enforced on this mutation just like the others.
    const noOrigin = await apiCall(stack, jar, 'POST', '/api/servers/subdomain', { id: server.id, slug: 'srvsub' });
    assert.equal(noOrigin.status, 403, noOrigin.text);

    // Unknown server id -> 404.
    const missing = await apiCall(stack, jar, 'POST', '/api/servers/subdomain',
      { id: 'nope-nope', slug: 'srvsub' }, { origin: stack.consoleOrigin });
    assert.equal(missing.status, 404, missing.text);

    // Assign a public subdomain to the server.
    const assigned = await apiCall(stack, jar, 'POST', '/api/servers/subdomain',
      { id: server.id, slug: 'srvsub', auth: 'public' }, { origin: stack.consoleOrigin });
    assert.equal(assigned.status, 201, assigned.text);
    assert.equal(assigned.json.route.slug, 'srvsub');
    assert.equal(assigned.json.route.kind, 'server');
    assert.equal(assigned.json.route.serverName, 'sub-web');
    assert.equal(assigned.json.route.auth, 'public');

    // Overview reflects exactly one route mapped to this server.
    const ov1 = await apiCall(stack, jar, 'GET', '/api/overview');
    const mapped1 = ov1.json.routes.filter((r) => r.kind === 'server' && r.serverName === 'sub-web');
    assert.equal(mapped1.length, 1);
    assert.equal(mapped1[0].slug, 'srvsub');

    // Public route is reachable anonymously through the edge.
    let proxied = null;
    for (let attempt = 0; attempt < 40; attempt++) {
      proxied = await fetchUrl(stack, 'https://srvsub.vr.ae/', { headers: { accept: 'text/html' } });
      if (proxied.status === 200) break;
      await delay(250);
    }
    assert.equal(proxied.status, 200, `expected proxied 200, got ${proxied?.status}`);

    // Change the subdomain: new slug created, old one removed atomically.
    const changed = await apiCall(stack, jar, 'POST', '/api/servers/subdomain',
      { id: server.id, slug: 'srvsub2' }, { origin: stack.consoleOrigin });
    assert.equal(changed.status, 201, changed.text);
    assert.equal(changed.json.route.slug, 'srvsub2');
    assert.equal(changed.json.route.auth, 'public', 'access carries over when only the slug changes');

    const ov2 = await apiCall(stack, jar, 'GET', '/api/overview');
    const slugs = ov2.json.routes.map((r) => r.slug);
    assert.ok(slugs.includes('srvsub2'), 'new slug present');
    assert.ok(!slugs.includes('srvsub'), 'old slug removed');
    assert.equal(ov2.json.routes.filter((r) => r.serverName === 'sub-web').length, 1, 'exactly one mapping remains');

    // Remove the subdomain entirely.
    const removed = await apiCall(stack, jar, 'POST', '/api/servers/subdomain',
      { id: server.id, slug: '' }, { origin: stack.consoleOrigin });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json.route, null);

    const ov3 = await apiCall(stack, jar, 'GET', '/api/overview');
    assert.equal(ov3.json.routes.filter((r) => r.serverName === 'sub-web').length, 0, 'mapping gone after removal');

    await stack.coordinator.api('POST', '/v1/servers/stop',
      { agent: 'e2e', project: toplevel, name: 'sub-web', reason: 'e2e subdomain teardown' }, { timeoutMs: 30_000 });
  });

  it('10. 421 for foreign hosts, 400 for missing Host, 301 for apex and www', async () => {
    const foreign = await fetchUrl(stack, 'https://evil.example/anything', { headers: { accept: 'text/html' } });
    assert.equal(foreign.status, 421);
    assert.match(foreign.text, /Misdirected/i);

    // Missing Host: raw TLS socket so no Host header is ever added.
    const socket = await edgeTlsSocket();
    socket.write('GET /x HTTP/1.0\r\nConnection: close\r\n\r\n');
    const raw = await readUntil(socket, (buf) => buf.includes('\r\n'));
    assert.match(raw.toString('latin1').split('\r\n')[0], /^HTTP\/1\.[01] 400 /);
    socket.destroy();

    const apex = await fetchUrl(stack, 'https://vr.ae/', { headers: { accept: 'text/html' } });
    assert.equal(apex.status, 301);
    assert.equal(apex.headers.location, `${stack.consoleOrigin}/`);

    const www = await fetchUrl(stack, 'https://www.vr.ae/deep/link', { headers: { accept: 'text/html' } });
    assert.equal(www.status, 301);
    assert.equal(www.headers.location, `${stack.consoleOrigin}/`);
  });

  it('11. port leases via console API: lease -> visible in overview -> Origin enforced -> release', async () => {
    const jar = await authedJar();

    const created = await apiCall(stack, jar, 'POST', '/api/ports/lease', {
      purpose: 'e2e lease',
      ttl: 120,
    }, { origin: stack.consoleOrigin });
    assert.equal(created.status, 201, created.text);
    const lease = created.json?.lease;
    assert.ok(lease?.id, `lease response must carry an id: ${created.text}`);
    assert.ok(Number.isInteger(lease.port) && lease.port > 0);
    assert.equal(lease.purpose, 'e2e lease');
    assert.match(String(lease.agent), /^devops-console:/, 'lease must be attributed to the console user');

    // The active lease shows up in the overview inventory.
    const overview = await apiCall(stack, jar, 'GET', '/api/overview');
    assert.equal(overview.status, 200);
    assert.ok(
      (overview.json.inventory?.leases || []).some((l) => l.id === lease.id),
      'leased port must appear in the overview inventory',
    );

    // Mutations without a same-origin Origin header are rejected and change nothing.
    const forged = await apiCall(stack, jar, 'POST', '/api/ports/release', { lease_id: lease.id }, {
      origin: 'https://evil.example',
    });
    assert.equal(forged.status, 403);

    const released = await apiCall(stack, jar, 'POST', '/api/ports/release', { lease_id: lease.id }, {
      origin: stack.consoleOrigin,
    });
    assert.equal(released.status, 200, released.text);
    assert.equal(released.json?.lease?.status, 'released');

    const after = await apiCall(stack, jar, 'GET', '/api/overview');
    assert.ok(
      !(after.json.inventory?.leases || []).some((l) => l.id === lease.id),
      'released lease must disappear from the overview inventory',
    );

    // Releasing a nonexistent lease surfaces the coordinator error cleanly.
    const missing = await apiCall(stack, jar, 'POST', '/api/ports/release', { lease_id: lease.id }, {
      origin: stack.consoleOrigin,
    });
    assert.equal(missing.status, 400);
    assert.match(String(missing.json?.error ?? ''), /matching lease not found/);
  });

  it('12. GET /api/metrics/history: well-formed, samples coordinator-backed servers, validates limit', { timeout: 120_000 }, async () => {
    const jar = await authedJar();

    // The metrics sampler and the overview piggyback both feed the store; a
    // running coordinator server must eventually produce a charted entity.
    const projectDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-metrics-'));
    extraTempDirs.push(projectDir);
    execFileSync('git', ['-C', projectDir, 'init', '-q']);
    const toplevel = execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
    }).trim();

    // Same port-range randomization + retry as test 9: concurrent suites can
    // bind-test the same free port; the loser retries on a fresh lease.
    const rangeBase = 23000 + crypto.randomInt(0, 70) * 100;
    let server = null;
    try {
      for (let attempt = 0; attempt < 3; attempt++) {
        server = await stack.coordinator.api('POST', '/v1/servers/start', {
          agent: 'e2e-metrics',
          project: toplevel,
          name: 'metrics-target',
          cmd: PY_HTTP_FIXTURE,
          range: `${rangeBase}-${rangeBase + 99}`,
          health_timeout: 20,
        }, { timeoutMs: 60_000 });
        if (server.status === 'running') break;
      }
      assert.equal(server.status, 'running', `metrics target should run: ${JSON.stringify(server?.health)}`);

      let entity = null;
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline && !entity) {
        // Overview ingests the fresh inventory into the metrics store.
        await apiCall(stack, jar, 'GET', '/api/overview');
        const hist = await apiCall(stack, jar, 'GET', '/api/metrics/history?limit=50');
        assert.equal(hist.status, 200, hist.text);
        assert.ok(Number.isInteger(hist.json.intervalMs) && hist.json.intervalMs >= 2000);
        assert.ok(Array.isArray(hist.json.entities));
        entity = hist.json.entities.find((e) => e.kind === 'server' && e.name === 'metrics-target') ?? null;
        if (!entity) await delay(1000);
      }
      assert.ok(entity, 'running coordinator server must appear in metrics history');
      assert.ok(entity.points.length >= 1);
      const [t, cpu, mem] = entity.points[entity.points.length - 1];
      assert.ok(Number.isFinite(t) && t > 0);
      assert.ok(Number.isFinite(cpu) && cpu >= 0);
      assert.ok(Number.isFinite(mem) && mem > 0, 'a live python process must report positive RSS');

      // Whole-machine health rides on the same endpoint: a real snapshot of
      // this box with memory capacity and at least one readable disk.
      const hist = await apiCall(stack, jar, 'GET', '/api/metrics/history');
      const host = hist.json.host;
      assert.ok(host, 'metrics history must carry a host snapshot');
      assert.ok(host.mem?.totalBytes > 0, 'host memory capacity must be real');
      assert.ok(host.mem.usedBytes > 0 && host.mem.usedBytes <= host.mem.totalBytes);
      assert.ok(Array.isArray(host.disks) && host.disks.length >= 1, 'at least one disk must be readable');
      assert.ok(host.disks[0].totalBytes > 0);
      assert.ok(Array.isArray(host.load) && host.load.length === 3);
      assert.ok(host.uptimeSec > 0);
      if (host.cpuPercent !== null) {
        assert.ok(host.cpuPercent >= 0 && host.cpuPercent <= 100);
      }
    } finally {
      if (server?.id) {
        await stack.coordinator.api('POST', '/v1/servers/stop', {
          agent: 'e2e-metrics',
          server_id: server.id,
          reason: 'metrics e2e teardown',
        }, { timeoutMs: 30_000 }).catch(() => {});
      }
    }

    // limit validation
    const bad = await apiCall(stack, jar, 'GET', '/api/metrics/history?limit=0');
    assert.equal(bad.status, 400);
    const alsoBad = await apiCall(stack, jar, 'GET', '/api/metrics/history?limit=abc');
    assert.equal(alsoBad.status, 400);

    // Anonymous access is rejected like every other console API.
    const anon = await fetchUrl(stack, `${stack.consoleOrigin}/api/metrics/history`, {
      headers: { accept: 'application/json' },
    });
    assert.equal(anon.status, 401);
  });

  it('13. durable port pins: server start pins its port -> survives stop -> unassign via console API', { timeout: 120_000 }, async () => {
    const jar = await authedJar();

    const projectDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-pins-'));
    extraTempDirs.push(projectDir);
    execFileSync('git', ['-C', projectDir, 'init', '-q']);
    const toplevel = execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
    }).trim();

    const rangeBase = 24000 + crypto.randomInt(0, 70) * 100;
    let server = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      server = await stack.coordinator.api('POST', '/v1/servers/start', {
        agent: 'e2e-pins',
        project: toplevel,
        name: 'pin-target',
        cmd: PY_HTTP_FIXTURE,
        range: `${rangeBase}-${rangeBase + 99}`,
        health_timeout: 20,
      }, { timeoutMs: 60_000 });
      if (server.status === 'running') break;
    }
    assert.equal(server.status, 'running', `pin target should run: ${JSON.stringify(server?.health)}`);
    const pinnedPort = server.port;

    const findPin = (overviewJson) =>
      (overviewJson.inventory?.port_assignments || []).find(
        (a) => a.name === 'pin-target' && a.project === toplevel,
      );

    // The mutations above went DIRECTLY to the coordinator, bypassing the
    // console client, so the console's 5s inventory cache may serve
    // pre-mutation state. Poll past the cache window instead of asserting on
    // one snapshot.
    async function overviewUntil(predicate, label) {
      const deadline = Date.now() + 15_000;
      let last = null;
      for (;;) {
        last = await apiCall(stack, jar, 'GET', '/api/overview');
        if (predicate(last.json)) return last;
        if (Date.now() > deadline) {
          assert.fail(`${label} — last overview: ${JSON.stringify(last.json.inventory?.port_assignments)}`);
        }
        await delay(500);
      }
    }

    // The pin appears in the console overview inventory.
    let overview = await overviewUntil(
      (o) => findPin(o)?.port === pinnedPort,
      'starting a coordinator server must surface a durable port pin in the overview',
    );

    // Stop the server: the lease disappears, the pin stays.
    await stack.coordinator.api('POST', '/v1/servers/stop', {
      agent: 'e2e-pins',
      server_id: server.id,
      reason: 'pin e2e stop',
    }, { timeoutMs: 30_000 });
    overview = await overviewUntil(
      (o) => !(o.inventory?.leases || []).some((l) => l.port === pinnedPort && l.status === 'active')
        && findPin(o)?.server_status === 'stopped',
      'after stop the lease must be released while the durable pin survives as stopped',
    );
    assert.equal(findPin(overview.json).port, pinnedPort);

    // The pinned port cannot be leased by anyone else through the console.
    const steal = await apiCall(stack, jar, 'POST', '/api/ports/lease', {
      purpose: 'pin steal attempt',
      preferred: pinnedPort,
      ttl: 60,
    }, { origin: stack.consoleOrigin });
    assert.equal(steal.status, 400, steal.text);
    assert.match(String(steal.json?.error ?? ''), /durably assigned/);

    // Unassign: Origin enforced, then the pin disappears and the port frees up.
    const forged = await apiCall(stack, jar, 'POST', '/api/ports/unassign', {
      name: 'pin-target',
      project: toplevel,
    }, { origin: 'https://evil.example' });
    assert.equal(forged.status, 403);

    const unassigned = await apiCall(stack, jar, 'POST', '/api/ports/unassign', {
      name: 'pin-target',
      project: toplevel,
    }, { origin: stack.consoleOrigin });
    assert.equal(unassigned.status, 200, unassigned.text);
    assert.equal(unassigned.json?.assignment?.status, 'unassigned');

    overview = await apiCall(stack, jar, 'GET', '/api/overview');
    assert.ok(!findPin(overview.json), 'unassigned pin must disappear from the overview');

    // Concurrent suites can transiently bind-test the same OS port, so retry
    // the exact-port lease briefly (same tolerance test 9 applies).
    let reuse = null;
    for (let attempt = 0; attempt < 8; attempt++) {
      reuse = await apiCall(stack, jar, 'POST', '/api/ports/lease', {
        purpose: 'pin freed',
        preferred: pinnedPort,
        ttl: 60,
      }, { origin: stack.consoleOrigin });
      if (reuse.status === 201) break;
      await delay(500);
    }
    assert.equal(reuse.status, 201, reuse.text);
    assert.equal(reuse.json?.lease?.port, pinnedPort);
    await apiCall(stack, jar, 'POST', '/api/ports/release', { lease_id: reuse.json.lease.id }, {
      origin: stack.consoleOrigin,
    });
  });

  it('14. UI prefs: hide/unhide deltas merge server-side, persist, validate input, enforce Origin', async () => {
    const jar = await authedJar();

    const initial = await apiCall(stack, jar, 'GET', '/api/prefs');
    assert.equal(initial.status, 200, initial.text);
    assert.deepEqual(initial.json.hidden, { servers: [], docker: [], projects: [] });

    // PATCH without Origin is a mutation and must be refused.
    const forged = await apiCall(stack, jar, 'PATCH', '/api/prefs', {
      hide: { servers: ['/repo::web'] },
    });
    assert.equal(forged.status, 403);

    const hidden = await apiCall(stack, jar, 'PATCH', '/api/prefs', {
      hide: { servers: ['/repo::web', '/repo::web', '  /other::api  '], projects: ['path:/repo'] },
    }, { origin: stack.consoleOrigin });
    assert.equal(hidden.status, 200, hidden.text);
    assert.deepEqual(hidden.json.hidden.servers, ['/repo::web', '/other::api'], 'entries deduped and trimmed');
    assert.deepEqual(hidden.json.hidden.projects, ['path:/repo']);
    assert.deepEqual(hidden.json.hidden.docker, [], 'untouched lists stay');

    // Deltas MERGE: a second hide from a stale client must not wipe the first
    // (this is the whole reason PATCH is not whole-list replacement).
    const merged = await apiCall(stack, jar, 'PATCH', '/api/prefs', {
      hide: { servers: ['/third::worker'] },
    }, { origin: stack.consoleOrigin });
    assert.deepEqual(
      [...merged.json.hidden.servers].sort(),
      ['/other::api', '/repo::web', '/third::worker'],
      'a hide delta merges with existing hides instead of replacing them',
    );

    // Unhide removes exactly the named keys; unknown keys are a no-op.
    const unhidden = await apiCall(stack, jar, 'PATCH', '/api/prefs', {
      unhide: { servers: ['/repo::web', '/never-hidden::x'] },
    }, { origin: stack.consoleOrigin });
    assert.deepEqual([...unhidden.json.hidden.servers].sort(), ['/other::api', '/third::worker']);

    // Persistence: a fresh GET returns the stored lists.
    const readBack = await apiCall(stack, jar, 'GET', '/api/prefs');
    assert.deepEqual([...readBack.json.hidden.servers].sort(), ['/other::api', '/third::worker']);

    // Validation: wrong shapes are 400 and change nothing.
    for (const bad of [
      { hide: { servers: 'nope' } },
      { hide: { servers: [42] } },
      { hide: { unknown: [] } },
      { hidden: { servers: ['x'] } }, // the old whole-list shape is gone
      {},
    ]) {
      const res = await apiCall(stack, jar, 'PATCH', '/api/prefs', bad, { origin: stack.consoleOrigin });
      assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(bad)}: ${res.text}`);
    }
    const after = await apiCall(stack, jar, 'GET', '/api/prefs');
    assert.deepEqual([...after.json.hidden.servers].sort(), ['/other::api', '/third::worker']);

    // Cleanup for other tests.
    await apiCall(stack, jar, 'PATCH', '/api/prefs', {
      unhide: { servers: ['/other::api', '/third::worker'], projects: ['path:/repo'] },
    }, { origin: stack.consoleOrigin });
  });

  it('15. project runtime control via console: start whole project -> members running -> stop', { timeout: 180_000 }, async () => {
    const jar = await authedJar();

    const projectDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'devops-console-e2e-projact-'));
    extraTempDirs.push(projectDir);
    execFileSync('git', ['-C', projectDir, 'init', '-q']);
    const toplevel = execFileSync('git', ['-C', projectDir, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
    }).trim();
    // Bind-checked OS-assigned port: a fixed random window would collide with
    // the coordinator-leased ranges other tests use (the suite's documented
    // flake mode).
    const runtimePort = await new Promise((resolve, reject) => {
      const srv = net.createServer();
      srv.listen(0, '127.0.0.1', () => {
        const { port } = srv.address();
        srv.close((err) => (err ? reject(err) : resolve(port)));
      });
      srv.on('error', reject);
    });
    await fsp.mkdir(path.join(toplevel, '.codex'), { recursive: true });
    await fsp.writeFile(
      path.join(toplevel, '.codex', 'dev-runtime.json'),
      JSON.stringify({
        name: 'projact',
        servers: [{
          name: 'web',
          role: 'web',
          port: runtimePort,
          cwd: '.',
          cmd: PY_HTTP_FIXTURE,
          health_url: 'http://127.0.0.1:{port}/',
        }],
      }),
      'utf8',
    );

    // Origin is enforced on project mutations.
    const forged = await apiCall(stack, jar, 'POST', '/api/projects/action', {
      project: toplevel,
      action: 'start',
    });
    assert.equal(forged.status, 403);

    const started = await apiCall(stack, jar, 'POST', '/api/projects/action', {
      project: toplevel,
      action: 'start',
    }, { origin: stack.consoleOrigin }, { timeoutMs: 330_000 });
    assert.equal(started.status, 200, started.text);
    assert.equal(started.json?.result?.ok, true, `project start should succeed: ${started.text}`);

    try {
      // The started member shows up in overview with project membership.
      let member = null;
      const deadline = Date.now() + 15_000;
      while (Date.now() < deadline && !member) {
        const overview = await apiCall(stack, jar, 'GET', '/api/overview');
        member = (overview.json.inventory?.servers || []).find(
          (s) => s.name === 'web' && s.project === toplevel && s.status === 'running',
        ) ?? null;
        if (member) {
          const row = (overview.json.inventory?.project_usage || []).find(
            (r) => (r.server_ids || []).includes(member.id),
          );
          assert.ok(row, 'project usage row must claim the started server via server_ids');
        }
        if (!member) await delay(500);
      }
      assert.ok(member, 'project start must yield a running member visible in the overview');
      assert.equal(member.port, runtimePort);

      const badAction = await apiCall(stack, jar, 'POST', '/api/projects/action', {
        project: toplevel,
        action: 'destroy',
      }, { origin: stack.consoleOrigin }, { timeoutMs: 330_000 });
      assert.equal(badAction.status, 400);

      // Unknown project paths are refused before reaching the coordinator.
      const unknown = await apiCall(stack, jar, 'POST', '/api/projects/action', {
        project: '/tmp/definitely-not-a-tracked-project',
        action: 'start',
      }, { origin: stack.consoleOrigin }, { timeoutMs: 330_000 });
      assert.equal(unknown.status, 404, unknown.text);
      assert.match(String(unknown.json?.error ?? ''), /unknown project/);
    } finally {
      const stopped = await apiCall(stack, jar, 'POST', '/api/projects/action', {
        project: toplevel,
        action: 'stop',
      }, { origin: stack.consoleOrigin }, { timeoutMs: 330_000 });
      assert.equal(stopped.status, 200, stopped.text);
    }

    // Stopping an already-stopped project is a calm no-op, not an error.
    const stopAgain = await apiCall(stack, jar, 'POST', '/api/projects/action', {
      project: toplevel,
      action: 'stop',
    }, { origin: stack.consoleOrigin }, { timeoutMs: 330_000 });
    assert.equal(stopAgain.status, 200, stopAgain.text);
    assert.equal(stopAgain.json?.result?.ok, true);
  });

  it('16. docker-hosted web servers: inventory row -> subdomain -> proxied 200 -> actions -> unassign', { timeout: 120_000 }, async () => {
    const jar = await authedJar();

    async function overviewUntil(predicate, label) {
      const deadline = Date.now() + 20_000;
      let last = null;
      for (;;) {
        last = await apiCall(stack, jar, 'GET', '/api/overview');
        if (predicate(last.json)) return last;
        if (Date.now() > deadline) {
          assert.fail(`${label} — docker inventory: ${JSON.stringify(last.json?.inventory?.docker)?.slice(0, 600)}`);
        }
        await delay(500);
      }
    }

    // The fake-docker container reaches the console's inventory with its
    // published mapping intact.
    const overview = await overviewUntil(
      (o) => o?.inventory?.docker?.available === true
        && (o.inventory.docker.containers || []).some((c) => c?.name === 'e2eweb-app-1'),
      'coordinator must surface the docker web container in the console overview',
    );
    const container = overview.json.inventory.docker.containers.find((c) => c.name === 'e2eweb-app-1');
    assert.match(String(container.ports), /->3000\/tcp/);

    // Assign a subdomain: single published port, so no port choice needed.
    const assigned = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name: 'e2eweb-app-1',
      slug: 'dockweb',
    }, { origin: stack.consoleOrigin });
    assert.equal(assigned.status, 201, assigned.text);
    assert.equal(assigned.json.route.kind, 'docker');
    assert.equal(assigned.json.route.containerName, 'e2eweb-app-1');
    assert.equal(assigned.json.route.containerPort, 3000);
    assert.equal(assigned.json.route.resolved.port, dockerWeb.port,
      'route must resolve to the published HOST port, not the container port');

    // The route serves the real backend through the TLS edge (with session).
    const viaEdge = await fetchUrl(stack, `https://dockweb.${stack.domain}/`, { jar });
    assert.equal(viaEdge.status, 200, viaEdge.text);
    assert.equal(viaEdge.text, 'docker-web ok');

    // Default-deny stands: no session -> no upstream access.
    const anon = await fetchUrl(stack, `https://dockweb.${stack.domain}/`, {
      headers: { accept: 'application/json' },
    });
    assert.equal(anon.status, 401);

    // Container actions from the console hit docker (argv proves the wiring).
    const restarted = await apiCall(stack, jar, 'POST', '/api/docker/action', {
      name: 'e2eweb-app-1',
      action: 'restart',
    }, { origin: stack.consoleOrigin });
    assert.equal(restarted.status, 200, restarted.text);
    const calls = await fsp.readFile(dockerCallsLog, 'utf8');
    assert.match(calls, /restart e2eweb-app-1/);

    // Multi-port containers demand an explicit container-port choice…
    const ambiguous = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name: 'e2emulti-app-1',
      slug: 'dockmulti',
    }, { origin: stack.consoleOrigin });
    assert.equal(ambiguous.status, 400, ambiguous.text);
    assert.match(ambiguous.json.error, /several ports/);
    assert.match(ambiguous.json.error, /3000, 9000/);

    // …and honor it, resolving through the chosen mapping.
    const chosen = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name: 'e2emulti-app-1',
      slug: 'dockmulti',
      port: 9000,
    }, { origin: stack.consoleOrigin });
    assert.equal(chosen.status, 201, chosen.text);
    assert.equal(chosen.json.route.containerPort, 9000);
    assert.equal(chosen.json.route.resolved.port, 19999);

    // A typo'd port cannot create a dead route.
    const badPort = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name: 'e2emulti-app-1',
      slug: 'dockmulti',
      port: 8081,
    }, { origin: stack.consoleOrigin });
    assert.equal(badPort.status, 400, badPort.text);
    assert.match(badPort.json.error, /does not publish port 8081/);

    // Container logs flow end to end through the console endpoint.
    const logsRes = await apiCall(stack, jar, 'POST', '/api/docker/logs', {
      name: 'e2eweb-app-1',
      tail: 50,
    }, { origin: stack.consoleOrigin });
    assert.equal(logsRes.status, 200, logsRes.text);
    assert.match(logsRes.json.text, /e2e fake container log line/);

    // Unassign both — twice each: repeating must stay a calm { route: null },
    // not an error (the idempotent-unassign contract).
    for (const name of ['e2eweb-app-1', 'e2emulti-app-1']) {
      for (let round = 0; round < 2; round += 1) {
        const removed = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
          name,
          slug: '',
        }, { origin: stack.consoleOrigin });
        assert.equal(removed.status, 200, removed.text);
        assert.equal(removed.json.route, null);
      }
    }
    const gone = await fetchUrl(stack, `https://dockweb.${stack.domain}/`, { jar });
    assert.equal(gone.status, 404);
  });

  it('17. docker subdomain lifecycle: auth changes and renames survive an unpublished container port', { timeout: 60_000 }, async () => {
    const jar = await authedJar();
    const name = 'e2estale-app-1';

    // The seeded route points at container port 4000; the container only
    // publishes 3000 — so the route must exist but resolve dead, honestly.
    const ov = await apiCall(stack, jar, 'GET', '/api/overview');
    const stale = (ov.json.routes || []).find((r) => r.slug === 'dockstale');
    assert.ok(stale, 'seeded dockstale route must appear in the overview');
    assert.equal(stale.containerPort, 4000);
    assert.equal(stale.resolved.port, null);
    assert.match(String(stale.resolved.reason), /does not publish port 4000/);

    // Auth-only update: no port in the body — must succeed AND must not
    // silently repoint containerPort to the currently-published 3000.
    const authOnly = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: 'dockstale',
      auth: 'public',
    }, { origin: stack.consoleOrigin });
    assert.equal(authOnly.status, 200, authOnly.text);
    assert.equal(authOnly.json.route.auth, 'public');
    assert.equal(authOnly.json.route.containerPort, 4000, 'auth change must not repoint the container port');

    // Rename: keeps the (unpublished) port, drops the old slug.
    const renamed = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: 'dockstale2',
    }, { origin: stack.consoleOrigin });
    assert.equal(renamed.status, 201, renamed.text);
    assert.equal(renamed.json.route.containerPort, 4000, 'rename must keep the existing container port');
    assert.equal(renamed.json.route.auth, 'public', 'rename must keep the access level');
    const afterRename = await apiCall(stack, jar, 'GET', '/api/overview');
    assert.ok(!(afterRename.json.routes || []).some((r) => r.slug === 'dockstale'), 'old slug removed');

    // Re-sending the route's own (unpublished) port is a no-op, not a 400.
    const samePort = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: 'dockstale2',
      port: 4000,
    }, { origin: stack.consoleOrigin });
    assert.equal(samePort.status, 200, samePort.text);
    assert.equal(samePort.json.route.containerPort, 4000);

    // An explicit CHANGE must still name a published port…
    const badChange = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: 'dockstale2',
      port: 8081,
    }, { origin: stack.consoleOrigin });
    assert.equal(badChange.status, 400, badChange.text);
    assert.match(badChange.json.error, /does not publish port 8081/);

    // …and repointing to the real published port brings the route live.
    const repointed = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: 'dockstale2',
      port: 3000,
    }, { origin: stack.consoleOrigin });
    assert.equal(repointed.status, 200, repointed.text);
    assert.equal(repointed.json.route.containerPort, 3000);
    assert.equal(repointed.json.route.resolved.port, 19997);

    // Cleanup.
    const removed = await apiCall(stack, jar, 'POST', '/api/docker/subdomain', {
      name,
      slug: '',
    }, { origin: stack.consoleOrigin });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json.route, null);
  });
});
