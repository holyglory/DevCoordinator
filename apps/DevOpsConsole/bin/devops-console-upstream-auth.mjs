#!/usr/bin/env node

import path from 'node:path';
import process from 'node:process';

import { loadConfig } from '../src/config.mjs';
import { createUpstreamAuthStore } from '../src/upstream-auth.mjs';

const USAGE = `Usage:
  devops-console-upstream-auth [--env-file PATH] list
  devops-console-upstream-auth [--env-file PATH] set SLUG --scheme bearer --secret-stdin
  devops-console-upstream-auth [--env-file PATH] set SLUG --scheme basic --username USER --secret-stdin
  devops-console-upstream-auth [--env-file PATH] remove SLUG

Secrets are accepted only on stdin and are never printed.
`;

function parseArgs(argv) {
  const options = { envFile: undefined, scheme: undefined, username: undefined, secretStdin: false };
  const positionals = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--env-file') options.envFile = argv[++i];
    else if (arg.startsWith('--env-file=')) options.envFile = arg.slice('--env-file='.length);
    else if (arg === '--scheme') options.scheme = argv[++i];
    else if (arg.startsWith('--scheme=')) options.scheme = arg.slice('--scheme='.length);
    else if (arg === '--username') options.username = argv[++i];
    else if (arg.startsWith('--username=')) options.username = arg.slice('--username='.length);
    else if (arg === '--secret-stdin') options.secretStdin = true;
    else if (arg === '-h' || arg === '--help') {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option: ${arg}`);
    } else positionals.push(arg);
  }
  if (!options.envFile && argv.some((arg) => arg === '--env-file')) {
    throw new Error('--env-file requires a path');
  }
  if (!options.scheme && argv.some((arg) => arg === '--scheme')) {
    throw new Error('--scheme requires a value');
  }
  if (!options.username && argv.some((arg) => arg === '--username')) {
    throw new Error('--username requires a value');
  }
  return { options, positionals };
}

async function readSecret() {
  let text = '';
  for await (const chunk of process.stdin) {
    text += chunk.toString('utf8');
    if (text.length > 8 * 1024 + 2) throw new Error('secret on stdin is too long');
  }
  return text.replace(/\r?\n$/, '');
}

async function main() {
  const { options, positionals } = parseArgs(process.argv.slice(2));
  const [command, slug, ...extra] = positionals;
  if (!command || extra.length > 0 || !['list', 'set', 'remove'].includes(command)) {
    throw new Error('expected list, set SLUG, or remove SLUG');
  }
  if (command !== 'list' && !slug) throw new Error(`${command} requires a route slug`);
  if (command === 'list' && slug) throw new Error('list does not accept a route slug');

  const config = loadConfig({ envFile: options.envFile });
  const store = createUpstreamAuthStore({ file: path.join(config.stateDir, 'upstream-auth.json') });
  await store.load();

  if (command === 'set') {
    if (!options.secretStdin) throw new Error('set requires --secret-stdin');
    if (options.scheme !== 'bearer' && options.scheme !== 'basic') {
      throw new Error("set requires --scheme bearer or --scheme basic");
    }
    if (options.scheme === 'basic' && !options.username) {
      throw new Error('basic credentials require --username');
    }
    if (options.scheme === 'bearer' && options.username) {
      throw new Error('--username is valid only with --scheme basic');
    }
    const secret = await readSecret();
    const result = await store.set(slug, {
      scheme: options.scheme,
      ...(options.scheme === 'basic' ? { username: options.username } : {}),
      secret,
    });
    process.stdout.write(`${JSON.stringify({ slug, ...result })}\n`);
    return;
  }

  if (options.scheme || options.username || options.secretStdin) {
    throw new Error(`credential options are valid only with set`);
  }
  if (command === 'remove') {
    const removed = await store.remove(slug);
    process.stdout.write(`${JSON.stringify({ slug, removed })}\n`);
    return;
  }

  process.stdout.write(`${JSON.stringify({ routes: store.listDescriptions() })}\n`);
}

main().catch((err) => {
  process.stderr.write(`upstream-auth: ${err?.message || String(err)}\n${USAGE}`);
  process.exit(1);
});
