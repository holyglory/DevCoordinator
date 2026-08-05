#!/usr/bin/env node
// Administrative client for one same-UID Console slot control socket.

import net from 'node:net';
import process from 'node:process';

const MAX_REPLY_BYTES = 64 * 1024;

function usage() {
  return `Usage:
  console-slot-control status --socket PATH
  console-slot-control promote --socket PATH [--old-socket PATH] [--timeout-seconds N]
  console-slot-control demote --socket PATH [--timeout-seconds N]
`;
}

function parse(argv) {
  const operation = argv.shift();
  if (!['status', 'promote', 'demote'].includes(operation)) throw new Error(usage());
  const result = { operation, socket: null, oldControl: null, timeoutMs: 30_000 };
  while (argv.length) {
    const flag = argv.shift();
    if (flag === '--socket') result.socket = argv.shift();
    else if (flag === '--old-socket') result.oldControl = argv.shift();
    else if (flag === '--timeout-seconds') {
      const raw = argv.shift();
      if (!/^\d+$/.test(String(raw))) throw new Error('--timeout-seconds must be an integer');
      result.timeoutMs = Number(raw) * 1000;
    } else throw new Error(`unknown argument: ${flag}\n${usage()}`);
  }
  if (!result.socket?.startsWith('/')) throw new Error('--socket must be an absolute path');
  if (result.oldControl && !result.oldControl.startsWith('/')) throw new Error('--old-socket must be absolute');
  if (result.operation !== 'promote' && result.oldControl) throw new Error('--old-socket is valid only for promote');
  if (!Number.isInteger(result.timeoutMs) || result.timeoutMs < 1000 || result.timeoutMs > 120_000) {
    throw new Error('--timeout-seconds must be from 1 through 120');
  }
  return result;
}

function call(options) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(options.socket);
    socket.setEncoding('utf8');
    let body = '';
    const timer = setTimeout(
      () => socket.destroy(new Error('Console slot control timed out')),
      options.timeoutMs + 1000,
    );
    socket.once('connect', () => socket.end(`${JSON.stringify({
      operation: options.operation,
      old_control: options.oldControl,
      timeout_ms: options.timeoutMs,
    })}\n`));
    socket.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_REPLY_BYTES) socket.destroy(new Error('oversized control reply'));
    });
    socket.once('error', reject);
    socket.once('close', () => {
      clearTimeout(timer);
      try { resolve(JSON.parse(body)); } catch (error) { reject(error); }
    });
  });
}

try {
  const response = await call(parse(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(response, null, 2)}\n`);
  if (response?.ok !== true) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: error.message })}\n`);
  process.exitCode = 1;
}
