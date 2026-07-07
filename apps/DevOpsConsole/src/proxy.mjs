// Streaming reverse proxy to loopback dev servers: plain HTTP (SSE/chunked
// flow through untouched) plus a genuine WebSocket/HMR upgrade path (101
// relay + bidirectional pipe). Targets are pinned to 127.0.0.1 — a route can
// never point the edge anywhere else (security invariant #3).

import http from 'node:http';

const LOOPBACK = '127.0.0.1';
const CONNECT_TIMEOUT_MS = 5_000;

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

// Errors that mean "nothing is accepting connections on that port".
const CONNECT_ERROR_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL', 'ENOTFOUND']);

// Strips hop-by-hop headers plus every header named by the Connection header.
function stripHopByHop(headers) {
  const named = new Set();
  const connectionHeader = headers.connection;
  if (typeof connectionHeader === 'string') {
    for (const token of connectionHeader.split(',')) named.add(token.trim().toLowerCase());
  }
  const out = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || named.has(lower)) continue;
    out[lower] = value;
  }
  return out;
}

export function createProxy({ log, renderBadGateway }) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 256 });

  function buildRequestHeaders(req, target, { upgrade }) {
    const headers = stripHopByHop(req.headers);
    // Host preserved: dev servers see the real vhost (Vite server.allowedHosts).
    headers.host = target.publicHost;
    const clientIp = req.socket.remoteAddress || '';
    headers['x-forwarded-for'] = headers['x-forwarded-for']
      ? `${headers['x-forwarded-for']}, ${clientIp}`
      : clientIp;
    headers['x-forwarded-proto'] = req.socket.encrypted ? 'https' : 'http';
    headers['x-forwarded-host'] = req.headers.host || target.publicHost;
    if (upgrade) {
      // Re-add the one hop we intentionally carry across: the upgrade itself.
      headers.connection = 'Upgrade';
      if (req.headers.upgrade) headers.upgrade = req.headers.upgrade;
      // Sec-WebSocket-* are end-to-end headers and already passed through.
    }
    return headers;
  }

  function forward(req, res, target) {
    const upstreamReq = http.request({
      host: LOOPBACK,
      port: target.port,
      method: req.method,
      path: req.url,
      headers: buildRequestHeaders(req, target, { upgrade: false }),
      agent,
      setHost: false,
    });

    let upstreamRes = null;
    let settled = false; // the client response's fate has been decided

    const fail = (kind) => {
      if (settled) return;
      settled = true;
      clearTimeout(connectTimer);
      if (res.headersSent || res.writableEnded || res.destroyed) {
        res.destroy();
        return;
      }
      try {
        renderBadGateway(req, res, { kind, target });
      } catch (err) {
        log.error('renderBadGateway failed', { error: err.message });
        try {
          res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('bad gateway');
        } catch {
          res.destroy();
        }
      }
    };

    const connectTimer = setTimeout(() => {
      fail('timeout');
      upstreamReq.destroy(new Error('upstream connect timeout'));
    }, CONNECT_TIMEOUT_MS);
    connectTimer.unref();

    upstreamReq.on('socket', (socket) => {
      if (socket.connecting) socket.once('connect', () => clearTimeout(connectTimer));
      else clearTimeout(connectTimer); // reused keep-alive socket
    });

    upstreamReq.on('response', (r) => {
      upstreamRes = r;
      if (settled) {
        r.destroy();
        return;
      }
      settled = true;
      clearTimeout(connectTimer);
      try {
        res.writeHead(r.statusCode || 502, r.statusMessage || '', stripHopByHop(r.headers));
      } catch (err) {
        log.warn('proxy response relay failed', { slug: target.slug, error: err.message });
        r.destroy();
        res.destroy();
        return;
      }
      r.pipe(res); // streaming: no buffering, SSE and chunked bodies flow through
      r.on('error', () => res.destroy());
    });

    upstreamReq.on('error', (err) => {
      if (upstreamRes) {
        // Failure mid-body: headers are gone, tear both sides down.
        res.destroy();
        return;
      }
      if (!settled) {
        log.warn('proxy upstream error', {
          slug: target.slug,
          port: target.port,
          code: err.code || err.message,
        });
      }
      fail(CONNECT_ERROR_CODES.has(err.code) ? 'connect' : 'reset');
    });

    // Client went away → stop upstream work.
    res.on('close', () => {
      if (upstreamRes && !upstreamRes.readableEnded) upstreamRes.destroy();
      if (!res.writableEnded) upstreamReq.destroy();
    });
    req.on('error', () => upstreamReq.destroy());

    req.pipe(upstreamReq);
  }

  function forwardUpgrade(req, socket, head, target) {
    socket.setNoDelay(true);
    const upstreamReq = http.request({
      host: LOOPBACK,
      port: target.port,
      method: req.method || 'GET',
      path: req.url,
      headers: buildRequestHeaders(req, target, { upgrade: true }),
      agent: false, // hijacked sockets must not enter the keep-alive pool
      setHost: false,
    });

    let done = false;

    const bail = (err) => {
      if (done) return;
      done = true;
      clearTimeout(connectTimer);
      log.warn('proxy upgrade failed', {
        slug: target.slug,
        port: target.port,
        code: err?.code || err?.message || 'error',
      });
      if (!socket.destroyed && socket.writable) {
        try {
          socket.write('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        } catch {
          // best effort only
        }
      }
      socket.destroy();
      upstreamReq.destroy();
    };

    const connectTimer = setTimeout(() => bail({ code: 'ETIMEDOUT' }), CONNECT_TIMEOUT_MS);
    connectTimer.unref();
    upstreamReq.on('socket', (s) => {
      if (s.connecting) s.once('connect', () => clearTimeout(connectTimer));
      else clearTimeout(connectTimer);
    });

    upstreamReq.on('error', bail);
    socket.on('error', () => {
      if (!done) {
        done = true;
        upstreamReq.destroy();
      }
    });
    socket.on('close', () => {
      if (!done) upstreamReq.destroy();
    });

    upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
      clearTimeout(connectTimer);
      if (done || socket.destroyed) {
        upstreamSocket.destroy();
        return;
      }
      done = true;
      upstreamSocket.setNoDelay(true);

      // Relay the 101 verbatim (rawHeaders keeps casing, duplicates, and the
      // Connection/Upgrade/Sec-WebSocket-Accept hop this path must preserve).
      const lines = [
        `HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage || 'Switching Protocols'}`,
      ];
      const raw = upstreamRes.rawHeaders;
      for (let i = 0; i < raw.length; i += 2) lines.push(`${raw[i]}: ${raw[i + 1]}`);
      try {
        socket.write(lines.join('\r\n') + '\r\n\r\n');
        if (upstreamHead && upstreamHead.length > 0) socket.write(upstreamHead);
        if (head && head.length > 0) upstreamSocket.write(head);
      } catch {
        socket.destroy();
        upstreamSocket.destroy();
        return;
      }

      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
      const teardown = () => {
        socket.destroy();
        upstreamSocket.destroy();
      };
      socket.on('close', teardown);
      socket.on('error', teardown);
      upstreamSocket.on('close', teardown);
      upstreamSocket.on('error', teardown);
      log.debug('websocket upgraded', { slug: target.slug, port: target.port });
    });

    // Upstream answered with a normal response (upgrade refused): serialize it
    // onto the raw socket with close-delimited framing and end.
    upstreamReq.on('response', (upstreamRes) => {
      clearTimeout(connectTimer);
      if (done || socket.destroyed) {
        upstreamRes.destroy();
        return;
      }
      done = true;
      const status = upstreamRes.statusCode || 502;
      const reason = upstreamRes.statusMessage || http.STATUS_CODES[status] || 'Error';
      const lines = [`HTTP/1.1 ${status} ${reason}`];
      const raw = upstreamRes.rawHeaders;
      for (let i = 0; i < raw.length; i += 2) {
        const lower = raw[i].toLowerCase();
        // Body is re-framed as close-delimited, so drop framing headers.
        if (
          lower === 'connection' ||
          lower === 'keep-alive' ||
          lower === 'transfer-encoding' ||
          lower === 'content-length' ||
          lower === 'upgrade'
        ) {
          continue;
        }
        lines.push(`${raw[i]}: ${raw[i + 1]}`);
      }
      lines.push('Connection: close');
      try {
        socket.write(lines.join('\r\n') + '\r\n\r\n');
      } catch {
        socket.destroy();
        upstreamRes.destroy();
        return;
      }
      upstreamRes.pipe(socket); // ends the socket when the body ends
      upstreamRes.on('error', () => socket.destroy());
    });

    upstreamReq.end();
  }

  return {
    forward,
    forwardUpgrade,
    close: () => agent.destroy(),
  };
}
