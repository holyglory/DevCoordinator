import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fsp from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execFileAsync = promisify(execFile);

test('production units split coordinator ownership and keep runtime data outside Git', async () => {
  const coordinator = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'dev-coordinator.service'), 'utf8');
  const consoleUnit = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'devops-console.service'), 'utf8');

  assert.match(coordinator, /api serve --host 127\.0\.0\.1 --port 29876/);
  assert.match(coordinator, /WorkingDirectory=\/home\/DevCoordinator/);
  assert.match(coordinator, /\/home\/DevCoordinator\/skills\/codex-dev-coordinator\/scripts\/dev_coordinator\.py/);
  assert.match(coordinator, /--token-file %h\/\.codex\/agent-coordinator\/api-token/);
  assert.match(coordinator, /CODEX_AGENT_COORDINATOR_HOME=%h\/\.codex\/agent-coordinator/);
  assert.match(coordinator, /^KillMode=process$/m);
  assert.doesNotMatch(coordinator, /^KillMode=(?:control-group|mixed)$/m);
  assert.doesNotMatch(
    coordinator,
    /^(?:PrivateTmp|ProtectSystem|ReadWritePaths|NoNewPrivileges|UMask)=/m,
    'coordinator children must not inherit API-unit sandbox or umask semantics',
  );
  assert.doesNotMatch(coordinator, /0\.0\.0\.0|holyskills/i);

  assert.match(consoleUnit, /Requires=dev-coordinator\.service/);
  assert.match(consoleUnit, /After=.*dev-coordinator\.service/);
  assert.match(consoleUnit, /EnvironmentFile=%h\/\.config\/devops-console\/console\.env/);
  assert.match(consoleUnit, /WorkingDirectory=\/home\/DevCoordinator\/apps\/DevOpsConsole/);
  assert.match(consoleUnit, /ExecStartPre=\/usr\/bin\/python3 \/home\/DevCoordinator\/scripts\/check_production_layout\.py/);
  assert.match(consoleUnit, /ExecStartPre=.*--require-token --wait-token-seconds 10/);
  assert.match(consoleUnit, /ExecStart=\/usr\/bin\/env DEVCOORDINATOR_ROOT=\/home\/DevCoordinator/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_AUTOSTART=0/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_URL=http:\/\/127\.0\.0\.1:29876/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_SCRIPT=\/home\/DevCoordinator\/skills\/codex-dev-coordinator\/scripts\/dev_coordinator\.py/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_TOKEN_FILE=%h\/\.codex\/agent-coordinator\/api-token/);
  assert.match(consoleUnit, /ExecStart=.*CODEX_AGENT_COORDINATOR_HOME=%h\/\.codex\/agent-coordinator/);
  assert.match(consoleUnit, /ExecStart=.*STATE_DIR=%h\/\.local\/state\/devops-console/);
  assert.match(consoleUnit, /ExecStart=.*ACME_WEBROOT=%h\/\.local\/state\/devops-console\/acme/);
  assert.match(consoleUnit, /--env-file %h\/\.config\/devops-console\/console\.env/);
  assert.doesNotMatch(consoleUnit, /^Environment=(?:DEVCOORDINATOR_ROOT|COORDINATOR_|CODEX_AGENT_COORDINATOR_HOME|STATE_DIR)/m);
  assert.match(consoleUnit, /ReadWritePaths=%h\/\.local\/state\/devops-console/);
  assert.match(consoleUnit, /UMask=0077/);
  assert.match(consoleUnit, /^KillMode=control-group$/m);
  assert.match(consoleUnit, /^PrivateTmp=true$/m);
  assert.match(consoleUnit, /^ProtectSystem=full$/m);
  assert.match(consoleUnit, /^ProtectHome=read-only$/m);
  assert.match(consoleUnit, /^NoNewPrivileges=true$/m);
  assert.doesNotMatch(`${coordinator}\n${consoleUnit}`, /\/home\/holyglory\/holyskills|apps\/DevOpsConsole\/\.env/i);
  assert.doesNotMatch(consoleUnit, /holyskills|spawn python3/i);
});

test('ExecStart assignments override malicious EnvironmentFile values', async () => {
  const consoleUnit = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'devops-console.service'), 'utf8');
  const line = consoleUnit.split('\n').find((value) => value.startsWith('ExecStart=/usr/bin/env '));
  assert.ok(line);
  const assignments = line
    .slice('ExecStart=/usr/bin/env '.length)
    .split(' ')
    .filter((value) => /^[A-Z][A-Z0-9_]*=/.test(value));
  const expected = Object.fromEntries(assignments.map((value) => value.split(/=(.*)/s).slice(0, 2)));
  const malicious = Object.fromEntries(Object.keys(expected).map((key) => [key, `/home/DevCoordinator/${key.toLowerCase()}`]));
  const { stdout } = await execFileAsync('/usr/bin/env', [...assignments, '/usr/bin/env'], {
    env: { ...process.env, ...malicious },
  });
  const actual = Object.fromEntries(
    stdout.split('\n').filter(Boolean).map((value) => value.split(/=(.*)/s).slice(0, 2)),
  );
  for (const [key, value] of Object.entries(expected)) assert.equal(actual[key], value, key);
  assert.equal(actual.COORDINATOR_AUTOSTART, '0');
  assert.equal(actual.COORDINATOR_URL, 'http://127.0.0.1:29876');
  assert.equal(actual.STATE_DIR, '%h/.local/state/devops-console');
});

test('deployment runbook preserves an existing production environment file', async () => {
  const readme = await fsp.readFile(path.join(APP_ROOT, 'README.md'), 'utf8');
  const deploy = readme.split('## Deploy (systemd)')[1]?.split('## Exposing a dev server')[0] ?? '';
  assert.match(deploy, /cp -a "\$CONSOLE_ENV" "\$CUTOVER_BACKUP\/console\.env"/);
  assert.match(deploy, /chmod 600 "\$CONSOLE_ENV"/);
  assert.match(deploy, /legacy-migration-initial" --env-only/);

  let createIfAbsent = false;
  let templateInstallCount = 0;
  for (const rawLine of deploy.split('\n')) {
    const line = rawLine.trim();
    if (line === 'if [ ! -e "$CONSOLE_ENV" ]; then') createIfAbsent = true;
    if (line.includes('.env.example') && line.includes('"$CONSOLE_ENV"')) {
      templateInstallCount += 1;
      assert.equal(createIfAbsent, true, 'template install must be inside the create-if-absent guard');
    }
    if (line === 'fi') createIfAbsent = false;
  }
  assert.equal(templateInstallCount, 1, 'deploy instructions should contain one guarded template install');
  assert.doesNotMatch(readme, /Put the client ID\/secret in `\.env`|point \.env at the issued files/);
  assert.match(readme, /\$HOME\/\.config\/devops-console\/console\.env/);
});

test('existing-host runbook models the legacy Console child-coordinator topology', async () => {
  const readme = await fsp.readFile(path.join(APP_ROOT, 'README.md'), 'utf8');
  const cutover = readme.split('### Existing-host checkout cutover')[1]?.split('Both units run as')[0] ?? '';

  for (const marker of [
    'ControlGroup --value devops-console.service',
    'legacy-processes.json',
    '"console": consoles[0]',
    'current_start == item["start_ticks"]',
    'command != item["command"]',
    'if len(records) != 2:',
    '90-cutover-killmode.conf',
    'KillMode --value devops-console.service',
    'legacy cgroup still has managed processes; refusing to reuse unit name',
    'pre-cutover-identities.json',
    '"server_id": servers[0]["id"]',
    '--sync-state-only',
    'captured legacy process is still alive',
    'legacy listener still accepts connections',
    'post-cutover Console server did not reuse the exact relocated identity',
    'systemctl disable dev-coordinator.service',
    'dev-coordinator.service.preexisting',
    'sudo rm -f /etc/systemd/system/dev-coordinator.service',
    'systemctl reset-failed dev-coordinator.service devops-console.service',
  ]) assert.ok(cutover.includes(marker), marker);

  assert.doesNotMatch(cutover, /systemctl restart dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /MainPID --value dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /\[ -s [^\n]*cgroup\.procs/);
  assert.match(cutover, /grep -q '\[0-9\]' "\/sys\/fs\/cgroup\$\{OLD_CONSOLE_CGROUP\}\/cgroup\.procs"/);
  assert.equal(
    (cutover.match(/sudo rm -f \/run\/systemd\/system\/devops-console\.service\.d\/90-cutover-killmode\.conf/g) ?? []).length,
    2,
    'normal cutover and rollback must both remove the temporary KillMode override',
  );
  const stopLegacy = cutover.indexOf('systemctl stop devops-console.service');
  const safeKillOverride = cutover.indexOf('90-cutover-killmode.conf');
  const relocate = cutover.indexOf('port relocate --agent');
  const installUnits = cutover.indexOf('sudo install -m 0644');
  const startCoordinator = cutover.indexOf('systemctl start dev-coordinator.service');
  const startConsole = cutover.indexOf('systemctl start devops-console.service');
  assert.ok(
    safeKillOverride >= 0 && safeKillOverride < stopLegacy
      && stopLegacy < relocate && relocate < installUnits
      && installUnits < startCoordinator && startCoordinator < startConsole,
    'legacy cgroup must stop and relocate before split units start',
  );
});
