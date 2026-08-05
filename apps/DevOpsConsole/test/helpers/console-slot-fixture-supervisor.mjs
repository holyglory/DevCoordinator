#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runConsoleSlot } from '../../edge/console-slot-supervisor.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const consoleEntry = path.join(HERE, 'console-slot-fixture-child.mjs');

runConsoleSlot({ consoleEntry }).catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exit(1);
});
