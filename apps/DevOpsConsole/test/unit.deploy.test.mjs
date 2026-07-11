import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('production units split coordinator ownership and keep runtime data outside Git', async () => {
  const coordinator = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'dev-coordinator.service'), 'utf8');
  const consoleUnit = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'devops-console.service'), 'utf8');

  assert.match(coordinator, /api serve --host 127\.0\.0\.1 --port 29876/);
  assert.match(coordinator, /--token-file %h\/\.codex\/agent-coordinator\/api-token/);
  assert.match(coordinator, /CODEX_AGENT_COORDINATOR_HOME=%h\/\.codex\/agent-coordinator/);
  assert.doesNotMatch(coordinator, /0\.0\.0\.0|holyskills/i);

  assert.match(consoleUnit, /Requires=dev-coordinator\.service/);
  assert.match(consoleUnit, /After=.*dev-coordinator\.service/);
  assert.match(consoleUnit, /EnvironmentFile=%h\/\.config\/devops-console\/console\.env/);
  assert.match(consoleUnit, /COORDINATOR_AUTOSTART=0/);
  assert.match(consoleUnit, /COORDINATOR_TOKEN_FILE=%h\/\.codex\/agent-coordinator\/api-token/);
  assert.match(consoleUnit, /ReadWritePaths=%h\/\.local\/state\/devops-console/);
  assert.doesNotMatch(consoleUnit, /holyskills|spawn python3/i);
});
