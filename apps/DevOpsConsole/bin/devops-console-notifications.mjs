#!/usr/bin/env node
// Dedicated Telegram control worker. This process alone owns Telegram state,
// long polling and delivery; Console reaches it through bounded Unix IPC.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

import { createCoordinator } from '../src/coordinator.mjs';
import { createLogger } from '../src/log.mjs';
import {
  createTelegramIpcServer,
  validateTelegramIpcConfig,
} from '../src/telegram-ipc.mjs';
import { createTelegramService } from '../src/telegram.mjs';

const USAGE = `Usage: devcoordinator-notifications [--check]\n`;

function requiredAbsolute(value, name) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value)) {
    throw new Error(`${name} must be an absolute path`);
  }
  return path.normalize(value);
}

function requiredText(value, name, maximum = 4096) {
  if (typeof value !== 'string' || !value || value.length > maximum || /[\0\r\n]/.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function parseArgs(argv) {
  if (argv.some((value) => value === '--help' || value === '-h')) {
    process.stdout.write(USAGE);
    return { help: true, check: false };
  }
  if (argv.some((value) => value !== '--check')) throw new Error(USAGE.trim());
  return { help: false, check: argv.includes('--check') };
}

export function loadNotificationConfig(env = process.env) {
  const stateFile = requiredAbsolute(
    env.DEVCOORDINATOR_NOTIFICATION_STATE ?? '/var/lib/devcoordinator-notifications/telegram-control.json',
    'DEVCOORDINATOR_NOTIFICATION_STATE',
  );
  const socketPath = requiredAbsolute(
    env.DEVCOORDINATOR_NOTIFICATION_SOCKET ?? '/run/devcoordinator-notifications/notifications.sock',
    'DEVCOORDINATOR_NOTIFICATION_SOCKET',
  );
  const projectRoot = requiredAbsolute(
    env.DEVCOORDINATOR_NOTIFICATION_PROJECT,
    'DEVCOORDINATOR_NOTIFICATION_PROJECT',
  );
  const coordinatorUrl = new URL(env.COORDINATOR_URL ?? 'http://127.0.0.1:29876');
  if (!['http:', 'https:'].includes(coordinatorUrl.protocol)) {
    throw new Error('COORDINATOR_URL protocol is invalid');
  }
  const allowedEmails = new Set(
    String(env.DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS ?? '')
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const email of allowedEmails) {
    if (email.length > 320 || !email.includes('@') || /[\0\r\n]/.test(email)) {
      throw new Error('DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS is invalid');
    }
  }
  if (allowedEmails.size === 0) {
    throw new Error('DEVCOORDINATOR_NOTIFICATION_ADMIN_EMAILS must contain an administrator');
  }
  const logLevel = requiredText(env.LOG_LEVEL ?? 'info', 'LOG_LEVEL', 16).toLowerCase();
  if (!new Set(['debug', 'info', 'warn', 'error']).has(logLevel)) {
    throw new Error('LOG_LEVEL must be one of debug|info|warn|error');
  }
  return {
    stateFile,
    stateDir: path.dirname(stateFile),
    socketPath,
    projectRoot,
    coordinatorUrl: coordinatorUrl.toString(),
    allowedEmails,
    logLevel,
  };
}

export function composeNotificationWorker({ config, log }) {
  const coordinator = createCoordinator({
    config: {
      coordinatorUrl: config.coordinatorUrl,
      coordinatorAutostart: false,
      coordinatorHome: config.stateDir,
      coordinatorScript: '/nonexistent',
      stateDir: config.stateDir,
    },
    log,
  });
  const telegram = createTelegramService({
    file: config.stateFile,
    log,
    isAdmin: (email) => config.allowedEmails.has(String(email).toLowerCase()),
    coordinator: {
      async hasProject(repoId) {
        const inventory = await coordinator.inventory({ maxAgeMs: 0 });
        return Array.isArray(inventory?.repositories)
          && inventory.repositories.some((repository) => repository?.repo_id === repoId);
      },
      observeHost: () => coordinator.observeHost({
        agent: 'devops-console:telegram',
        project: config.projectRoot,
      }),
      readEvents: ({ after, limit }) => coordinator.events({ after, limit }),
    },
  });
  const ipc = createTelegramIpcServer({
    socketPath: config.socketPath,
    service: telegram,
    log,
    // A notification process without its management socket is not healthy.
    // Exit nonzero and let systemd's bounded restart policy recover it; the
    // Console remains available and reports typed notification unavailability.
    onFatal(error) {
      setImmediate(() => { throw error; });
    },
  });
  return { coordinator, telegram, ipc };
}

export async function runNotificationWorker({ env = process.env, argv = process.argv.slice(2) } = {}) {
  const args = parseArgs(argv);
  if (args.help) return { checked: false, running: false };
  const config = loadNotificationConfig(env);
  const log = createLogger(config.logLevel);
  const worker = composeNotificationWorker({ config, log });
  await worker.telegram.load();
  await validateTelegramIpcConfig({ socketPath: config.socketPath });
  if (args.check) {
    worker.coordinator.close();
    return { checked: true, running: false };
  }
  // Publish IPC before polling. Console management calls can observe the
  // worker as soon as its durable state is loaded.
  await worker.ipc.start();
  await worker.telegram.start();
  return { checked: true, running: true, ...worker };
}

async function main() {
  const worker = await runNotificationWorker();
  if (!worker.running) return;
  let stopping = false;
  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    await worker.telegram.stop().catch(() => {});
    await worker.ipc.close().catch(() => {});
    worker.coordinator.close();
    if (signal) process.exit(0);
  };
  process.once('SIGTERM', () => { void stop('SIGTERM'); });
  process.once('SIGINT', () => { void stop('SIGINT'); });
}

const isDirectRun = (() => {
  try {
    return process.argv[1] && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (isDirectRun) {
  main().catch((error) => {
    process.stderr.write(`${error?.stack || String(error)}\n`);
    process.exit(1);
  });
}
