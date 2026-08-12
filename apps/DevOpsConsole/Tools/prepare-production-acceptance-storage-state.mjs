#!/usr/bin/env node

// Create the short-lived authenticated browser state used by the read-only
// production Console acceptance crawler. Any local account that can read the
// configured files may run it; Unix ownership metadata is not an authorization
// boundary on this single-developer host. The cookie never leaves the output.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { createSessionManager } from '../src/auth/session.mjs';
import { loadConfig } from '../src/config.mjs';

const TOOL_PATH = fileURLToPath(import.meta.url);

export const DEFAULT_ENV_FILE = '/etc/devcoordinator/console.env';
export const DEFAULT_OUTPUT = '/var/lib/devcoordinator/browser/storage-state.json';
export const MAX_ACCEPTANCE_SESSION_TTL_MS = 60 * 60 * 1000;
export const PRODUCTION_CREDENTIAL_FILES = Object.freeze({
  sessionSecret: '/etc/devcoordinator/edge/session-secret',
  tlsCert: '/etc/letsencrypt/live/vr.ae/fullchain.pem',
  tlsKey: '/etc/letsencrypt/live/vr.ae/privkey.pem',
});

const USAGE = 'usage: prepare-production-acceptance-storage-state.mjs '
  + '[--env-file ABSOLUTE_PATH] [--output ABSOLUTE_PATH] '
  + '[--owner-uid UID --owner-gid GID]';

function fail(message) {
  throw new Error(message);
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || !value || value.includes('\0') || !path.isAbsolute(value)) {
    fail(`${label} must be one absolute path`);
  }
  const resolved = path.resolve(value);
  if (resolved === path.parse(resolved).root) fail(`${label} must name a file`);
  return resolved;
}

function localIdentity(value, label) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    fail(`${label} must be a non-negative integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) fail(`${label} is outside the supported range`);
  return parsed;
}

export function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--env-file', '--output', '--owner-uid', '--owner-gid'].includes(flag)
        || value === undefined) fail(USAGE);
    if (Object.hasOwn(values, flag)) fail(`${flag} was provided more than once`);
    values[flag] = value;
  }
  const ownerWasProvided = Object.hasOwn(values, '--owner-uid')
    || Object.hasOwn(values, '--owner-gid');
  if (ownerWasProvided
      && !(Object.hasOwn(values, '--owner-uid') && Object.hasOwn(values, '--owner-gid'))) {
    fail('--owner-uid and --owner-gid must be provided together');
  }
  const ownerUid = localIdentity(values['--owner-uid'] ?? process.getuid(), '--owner-uid');
  const ownerGid = localIdentity(values['--owner-gid'] ?? process.getgid(), '--owner-gid');
  if ((ownerUid !== process.getuid() || ownerGid !== process.getgid())
      && process.geteuid() !== 0) {
    fail('only the privileged session preparer may hand storage state to another local identity');
  }
  return {
    envFile: absolutePath(values['--env-file'] || DEFAULT_ENV_FILE, '--env-file'),
    output: absolutePath(values['--output'] || DEFAULT_OUTPUT, '--output'),
    ownerUid,
    ownerGid,
  };
}

export function productionCredentialEnvironment(files = PRODUCTION_CREDENTIAL_FILES) {
  return {
    SESSION_SECRET_FILE: absolutePath(files.sessionSecret, 'session credential'),
    TLS_CERT_FILE: absolutePath(files.tlsCert, 'TLS certificate credential'),
    TLS_KEY_FILE: absolutePath(files.tlsKey, 'TLS key credential'),
  };
}

export function loadProductionConsoleConfig({
  envFile,
  credentialFiles = PRODUCTION_CREDENTIAL_FILES,
} = {}) {
  return loadConfig({
    envFile: absolutePath(envFile || DEFAULT_ENV_FILE, '--env-file'),
    env: productionCredentialEnvironment(credentialFiles),
    initializeRuntimePaths: false,
  });
}

export function selectConfiguredOwner(allowedEmails) {
  const owners = [...(allowedEmails || [])]
    .map((value) => String(value).trim().toLowerCase())
    .filter(Boolean)
    .sort();
  if (owners.length === 0) fail('the Console must have at least one configured owner');
  return owners[0];
}

export function buildStorageState(config) {
  const owner = selectConfiguredOwner(config.allowedEmails);
  const ttlMs = Math.min(Number(config.sessionTtlMs), MAX_ACCEPTANCE_SESSION_TTL_MS);
  if (!Number.isFinite(ttlMs) || ttlMs < 1000) fail('the configured session lifetime is invalid');

  const sessions = createSessionManager({
    secret: config.sessionSecret, // public-artifact-guard: allow text-secret -- in-memory config reference only
    ttlMs,
    cookieName: config.cookieName,
    cookieDomain: `.${config.domain}`,
    secure: !config.devInsecureHttp,
  });
  const issued = sessions.issue({
    sub: 'local-production-playwright-acceptance',
    email: owner,
    name: 'Production acceptance',
  });
  const separator = issued.cookie.indexOf('=');
  const terminator = issued.cookie.indexOf(';', separator + 1);
  if (separator < 1 || terminator < separator) fail('the session manager returned an invalid cookie');

  return {
    storageState: {
      cookies: [{
        name: config.cookieName,
        value: issued.cookie.slice(separator + 1, terminator),
        domain: `.${config.domain}`,
        path: '/',
        expires: issued.session.exp,
        httpOnly: true,
        secure: !config.devInsecureHttp,
        sameSite: 'Lax',
      }],
      origins: [],
    },
    expiresAt: issued.session.exp,
  };
}

export function atomicWriteStorageState(output, storageState, {
  ownerUid = process.getuid(),
  ownerGid = process.getgid(),
} = {}) {
  const destination = absolutePath(output, '--output');
  const parent = path.dirname(destination);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    parent,
    `.${path.basename(destination)}.${process.pid}.${crypto.randomUUID()}.partial`,
  );
  const payload = Buffer.from(`${JSON.stringify(storageState)}\n`, 'utf8');
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    fs.writeFileSync(descriptor, payload);
    fs.fchownSync(
      descriptor,
      localIdentity(ownerUid, 'storage-state owner UID'),
      localIdentity(ownerGid, 'storage-state owner GID'),
    );
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, destination);
    const directory = fs.openSync(parent, fs.constants.O_RDONLY);
    try {
      fs.fsyncSync(directory);
    } finally {
      fs.closeSync(directory);
    }
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try {
      fs.unlinkSync(temporary);
    } catch {
      // A successful rename consumes the temporary path; failed writes leave
      // no partial credential material behind.
    }
  }
  return { bytes: payload.length, output: destination };
}

export function prepareProductionAcceptanceSession({ config, output, ownerUid, ownerGid }) {
  const issued = buildStorageState(config);
  const published = atomicWriteStorageState(
    output,
    issued.storageState,
    { ownerUid, ownerGid },
  );
  return {
    ok: true,
    storage_state: published.output,
    expires_at: new Date(issued.expiresAt * 1000).toISOString(),
  };
}

export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const config = loadProductionConsoleConfig({ envFile: options.envFile });
  const receipt = prepareProductionAcceptanceSession({
    config,
    output: options.output,
    ownerUid: options.ownerUid,
    ownerGid: options.ownerGid,
  });
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === TOOL_PATH) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`production browser session preparation failed: ${error?.message || String(error)}\n`);
    process.exitCode = 1;
  }
}
