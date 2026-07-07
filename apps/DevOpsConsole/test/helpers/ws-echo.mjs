// Genuine RFC 6455 WebSocket echo server for proxy tests — no libraries.
//
// Handshake: validates Upgrade/Sec-WebSocket-Key, answers 101 with the real
// Sec-WebSocket-Accept (base64(SHA1(key + GUID))). Frames: parses masked
// client frames (payloads <= 125 bytes — enough per the contract), echoes
// text frames back unmasked, answers ping with pong and close with close.
// Unmasked client frames are a protocol violation and drop the connection.
//
// Plain (non-upgrade) HTTP requests get a 200 marker response so the same
// upstream can also serve ordinary proxied GETs.

import crypto from 'node:crypto';
import http from 'node:http';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export function wsAcceptFor(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

function frame(opcode, payload) {
  if (payload.length > 125) throw new Error('fixture supports payloads <= 125 bytes');
  return Buffer.concat([Buffer.from([0x80 | opcode, payload.length]), payload]);
}

export async function startWsEcho({ port = 0 } = {}) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('ws-echo online');
  });

  const sockets = new Set();
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  server.on('upgrade', (req, socket, head) => {
    socket.on('error', () => socket.destroy());
    const key = req.headers['sec-websocket-key'];
    const upgrade = String(req.headers.upgrade ?? '').toLowerCase();
    if (upgrade !== 'websocket' || typeof key !== 'string' || key === '') {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${wsAcceptFor(key)}\r\n` +
        '\r\n',
    );

    let buf = head && head.length > 0 ? Buffer.from(head) : Buffer.alloc(0);

    const processFrames = () => {
      for (;;) {
        if (buf.length < 2) return;
        const fin = (buf[0] & 0x80) !== 0;
        const opcode = buf[0] & 0x0f;
        const masked = (buf[1] & 0x80) !== 0;
        const len = buf[1] & 0x7f;
        if (len > 125) {
          // Extended lengths are out of scope for this fixture.
          socket.destroy();
          return;
        }
        const headerLen = 2 + (masked ? 4 : 0);
        if (buf.length < headerLen + len) return; // wait for more bytes
        let payload = buf.subarray(headerLen, headerLen + len);
        if (masked) {
          const maskKey = buf.subarray(2, 6);
          const unmasked = Buffer.alloc(len);
          for (let i = 0; i < len; i++) unmasked[i] = payload[i] ^ maskKey[i % 4];
          payload = unmasked;
        }
        buf = buf.subarray(headerLen + len);

        if (!masked) {
          // RFC 6455 §5.1: client-to-server frames MUST be masked.
          socket.destroy();
          return;
        }
        if (opcode === 0x8) {
          // Close: echo the close frame, then end.
          try {
            socket.write(frame(0x8, payload));
          } catch {
            // socket already gone
          }
          socket.end();
          return;
        }
        if (opcode === 0x9) {
          socket.write(frame(0xa, payload)); // ping -> pong
          continue;
        }
        if (opcode === 0x1 && fin) {
          socket.write(frame(0x1, payload)); // text -> unmasked text echo
          continue;
        }
        // Anything else (continuations, binary) is out of scope: ignore.
      }
    };

    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        processFrames();
      } catch {
        socket.destroy();
      }
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  return {
    port: server.address().port,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}
