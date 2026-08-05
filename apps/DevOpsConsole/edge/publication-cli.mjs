#!/usr/bin/env node
// Offline/cooperative publisher for retained stable-edge snapshots.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import {
  atomicWriteEnvelope,
  loadPublicationFile,
  sealPublication,
} from './publication.mjs';

function parse(argv) {
  const command = argv.shift();
  if (!['seal', 'verify', 'switch-console', 'switch-maintenance'].includes(command)) throw new Error('command must be seal, verify, switch-console, or switch-maintenance');
  const options = { command };
  while (argv.length) {
    const flag = argv.shift();
    if (!flag.startsWith('--')) throw new Error(`unexpected argument: ${flag}`);
    const value = argv.shift();
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} requires one value`);
    options[flag.slice(2).replaceAll('-', '_')] = value;
  }
  const required = command === 'seal'
    ? ['input', 'output', 'release_root']
    : command === 'verify'
      ? ['file', 'release_root']
      : command === 'switch-console' ? [
          'file',
          'release_root',
          'expected_payload_sha256',
          'release_digest',
          'port',
          'published_at',
        ] : [
          'file',
          'release_root',
          'expected_payload_sha256',
          'active',
          'deployment_id',
          'retry_after_seconds',
          'published_at',
        ];
  for (const name of required) {
    if (!options[name]) throw new Error(`--${name.replaceAll('_', '-')} is required`);
  }
  for (const name of ['input', 'output', 'file', 'release_root']) {
    if (options[name] && !path.isAbsolute(options[name])) throw new Error(`--${name.replaceAll('_', '-')} must be absolute`);
  }
  return options;
}

async function readBoundedJson(file) {
  const handle = await fsp.open(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size < 2 || info.size > 2 * 1024 * 1024) {
      throw new Error(`input must be one bounded regular file: ${file}`);
    }
    return JSON.parse(await handle.readFile('utf8'));
  } finally {
    await handle.close();
  }
}

async function withPublicationLock(file, operation) {
  const lock = `${file}.publisher.lock`;
  let handle;
  try {
    handle = await fsp.open(
      lock,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(`${JSON.stringify({ pid: process.pid, operation_id: crypto.randomUUID() })}\n`);
    await handle.sync();
    return await operation();
  } finally {
    await handle?.close().catch(() => {});
    if (handle) await fsp.unlink(lock).catch(() => {});
  }
}

async function run(options) {
  const validation = {
    releaseRoot: options.release_root,
  };
  if (options.command === 'seal') {
    const publication = await readBoundedJson(options.input);
    const envelope = sealPublication(publication, validation);
    await withPublicationLock(options.output, () => atomicWriteEnvelope(
      options.output,
      envelope,
      { validation },
    ));
    return { ok: true, file: options.output, ...envelope };
  }
  if (options.command === 'verify') {
    const envelope = await loadPublicationFile(options.file, validation);
    return {
      ok: true,
      file: options.file,
      generation: envelope.publication.generation,
      payload_sha256: envelope.payload_sha256,
      release_digest: envelope.publication.release_digest,
      routes: Object.keys(envelope.publication.routes).length,
    };
  }
  return withPublicationLock(options.file, async () => {
    const before = await fsp.lstat(options.file);
    const current = await loadPublicationFile(options.file, validation);
    const afterRead = await fsp.lstat(options.file);
    if (
      before.dev !== afterRead.dev
      || before.ino !== afterRead.ino
      || before.size !== afterRead.size
      || before.mtimeMs !== afterRead.mtimeMs
    ) throw new Error('active publication identity changed during verification');
    if (current.payload_sha256 !== options.expected_payload_sha256) {
      throw new Error('active publication changed; refusing a stale Console switch');
    }
    if (options.command === 'switch-maintenance') {
      if (!['true', 'false'].includes(options.active)) throw new Error('--active must be true or false');
      const active = options.active === 'true';
      const retry = Number(options.retry_after_seconds);
      const candidate = structuredClone(current.publication);
      candidate.generation += 1;
      candidate.published_at = options.published_at;
      candidate.maintenance = active
        ? {
            active: true,
            deployment_id: options.deployment_id,
            retry_after_seconds: retry,
            started_at: options.published_at,
          }
        : { active: false, deployment_id: null, retry_after_seconds: 0, started_at: null };
      if (!active && options.deployment_id !== current.publication.maintenance.deployment_id) {
        throw new Error('maintenance clear belongs to another deployment');
      }
      const envelope = sealPublication(candidate, validation);
      await atomicWriteEnvelope(options.file, envelope, {
        validation,
      });
      return {
        ok: true,
        file: options.file,
        previous_generation: current.publication.generation,
        generation: envelope.publication.generation,
        previous_payload_sha256: current.payload_sha256,
        payload_sha256: envelope.payload_sha256,
        maintenance_active: active,
        deployment_id: active ? options.deployment_id : null,
        retry_after_seconds: active ? retry : 0,
      };
    }
    if (!/^[a-f0-9]{64}$/.test(options.release_digest)) throw new Error('--release-digest is invalid');
    const port = Number(options.port);
    if (!Number.isInteger(port) || port < 30000 || port > 60999) throw new Error('--port must be 30000-60999');
    const candidateAssetRoot = path.join(
      options.release_root,
      options.release_digest,
      'apps/DevOpsConsole/src/ui',
    );
    const candidate = structuredClone(current.publication);
    candidate.generation += 1;
    candidate.published_at = options.published_at;
    candidate.release_digest = options.release_digest;
    candidate.console = {
      asset_root: candidateAssetRoot,
      upstream: {
        host: '127.0.0.1',
        port,
        scheme: 'https',
        tls_server_name: candidate.console_host,
        tls_verify: true,
      },
    };
    const envelope = sealPublication(candidate, validation);
    await atomicWriteEnvelope(options.file, envelope, {
      validation,
    });
    return {
      ok: true,
      file: options.file,
      previous_generation: current.publication.generation,
      generation: envelope.publication.generation,
      previous_payload_sha256: current.payload_sha256,
      payload_sha256: envelope.payload_sha256,
      release_digest: options.release_digest,
      port,
    };
  });
}

try {
  const result = await run(parse(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: error?.message || String(error) })}\n`);
  process.exitCode = 1;
}
