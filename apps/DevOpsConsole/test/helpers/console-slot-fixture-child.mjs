#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import https from 'node:https';

const port = Number(process.env.HTTPS_PORT);
const sockets = new Set();
const server = https.createServer({
  cert: readFileSync(process.env.TLS_CERT_FILE),
  key: readFileSync(process.env.TLS_KEY_FILE),
}, (req, res) => {
  const url = new URL(req.url || '/', 'https://console.vr.ae');
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('ok');
    return;
  }
  if (url.pathname === '/stream') {
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    });
    res.write('data: ready\n\n');
    return;
  }
  if (url.pathname === '/delay') {
    const milliseconds = Math.max(0, Math.min(5_000, Number(url.searchParams.get('ms')) || 0));
    setTimeout(() => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(`${JSON.stringify({ ok: true, delay_ms: milliseconds })}\n`);
    }, milliseconds);
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

server.on('connection', (socket) => {
  sockets.add(socket);
  socket.once('close', () => sockets.delete(socket));
});
server.listen(port, '127.0.0.1');

let closing = false;
function close() {
  if (closing) return;
  closing = true;
  server.close(() => process.exit(0));
  for (const socket of sockets) socket.destroy();
  setTimeout(() => process.exit(0), 1_000).unref();
}
process.once('SIGTERM', close);
process.once('SIGINT', close);
