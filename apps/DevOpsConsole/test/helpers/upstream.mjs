// Plain-HTTP upstream fixture: echoes every request as JSON
// { method, path, headers, body } so proxy tests can assert exactly what
// crossed the edge, plus GET /sse which streams 3 Server-Sent Events with
// real gaps between them (event-1 immediately, then event-2/event-3 at
// `gapMs` intervals) so incremental delivery is observable.

import http from 'node:http';

export const FIXTURE_UPSTREAM_AUTHORIZATION = 'Bearer fixture-e2e-upstream-credential';

export async function startUpstream({
  gapMs = 300,
  requiredAuthorization = FIXTURE_UPSTREAM_AUTHORIZATION,
} = {}) {
  const server = http.createServer((req, res) => {
    const pathname = (req.url ?? '/').split('?')[0];

    if (req.method === 'GET' && pathname === '/sse') {
      res.writeHead(200, {
        'content-type': 'text/event-stream',
        'cache-control': 'no-cache',
      });
      let n = 1;
      res.write(`id: 1\ndata: event-1\n\n`);
      const timer = setInterval(() => {
        n += 1;
        res.write(`id: ${n}\ndata: event-${n}\n\n`);
        if (n >= 3) {
          clearInterval(timer);
          res.end();
        }
      }, gapMs);
      res.on('close', () => clearInterval(timer));
      return;
    }

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (
        pathname === '/requires-upstream-auth'
        && requiredAuthorization
        && req.headers.authorization !== requiredAuthorization
      ) {
        const body = JSON.stringify({ error: 'upstream authentication required' });
        res.writeHead(401, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          'www-authenticate': 'Basic realm="fixture-upstream"',
        });
        res.end(body);
        return;
      }
      const payload = JSON.stringify({
        method: req.method,
        path: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      });
      res.end(payload);
    });
    req.on('error', () => res.destroy());
  });

  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  return {
    port: server.address().port,
    gapMs,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
