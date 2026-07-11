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

test('cutover process identity and signaling are Linux-format and PID-reuse safe', async () => {
  const scripts = path.resolve(APP_ROOT, '..', '..', 'scripts');
  const parser = await fsp.readFile(path.join(scripts, 'linux_proc_identity.py'), 'utf8');
  const sampler = await fsp.readFile(path.join(scripts, 'verify_legacy_cutover_boundary.py'), 'utf8');
  const terminator = await fsp.readFile(path.join(scripts, 'terminate_captured_legacy_process.py'), 'utf8');
  const authBoundary = await fsp.readFile(path.join(scripts, 'check_coordinator_auth_boundary.py'), 'utf8');
  assert.match(parser, /stat_text\.rfind\("\)"\)/);
  assert.match(parser, /after_comm\[19\]/);
  assert.doesNotMatch(`${parser}\n${sampler}\n${terminator}`, /split\(\)\[21\]/);
  assert.match(terminator, /os, "pidfd_open"/);
  assert.match(terminator, /signal, "pidfd_send_signal"/);
  assert.doesNotMatch(terminator, /os\.kill\(/);
  assert.match(authBoundary, /if observed != expected:/);
  assert.doesNotMatch(authBoundary, /\bassert\b/);
});

test('existing-host runbook models the legacy Console child-coordinator topology', async () => {
  const readme = await fsp.readFile(path.join(APP_ROOT, 'README.md'), 'utf8');
  const cutover = readme.split('### Existing-host checkout cutover')[1]?.split('Both units run as')[0] ?? '';

  for (const marker of [
    'ControlGroup --value devops-console.service',
    'legacy-processes.json',
    '"console": consoles[0]',
    'stat_text.rfind(")")',
    'if len(records) != 2:',
    'verify_legacy_cutover_boundary.py',
    'terminate_captured_legacy_process.py',
    'check_legacy_cutover_stopped.py',
    '--samples 5 --interval-seconds 1',
    '--samples 1 --interval-seconds 0',
    'cgroup-samples.stable.json',
    'cgroup-samples.prestop-final.json',
    'find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type f -exec chmod 600 {} +',
    '90-cutover-killmode.conf',
    'KillMode --value devops-console.service',
    'pre-cutover-identities.json',
    '"server_id": servers[0]["id"]',
    '--sync-state-only',
    'coordinator-state.poststop.json',
    'coordinator-state.pre-relocate.json',
    'state-migration.attempted',
    'relocation.attempted',
    'no state mutation phase marker; preserving current coordinator state',
    'trap cleanup_cutover_override EXIT',
    'trap - EXIT',
    'restore_enablement devops-console.service',
    'post-cutover Console server did not reuse the exact relocated identity',
    'systemctl disable dev-coordinator.service',
    'dev-coordinator.service.preexisting',
    'sudo rm -f /etc/systemd/system/dev-coordinator.service',
    'systemctl reset-failed dev-coordinator.service devops-console.service',
    'check_coordinator_auth_boundary.py',
    'sha256sum --check SHA256SUMS',
  ]) assert.ok(cutover.includes(marker), marker);

  assert.doesNotMatch(cutover, /systemctl restart dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /MainPID --value dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /\[ -s [^\n]*cgroup\.procs/);
  assert.doesNotMatch(cutover, /assert status\(/);
  assert.equal((cutover.match(/\.rfind\("\)"\)/g) ?? []).length, 1);
  assert.match(cutover, /--samples 1 --interval-seconds 0\nsudo systemctl stop devops-console\.service/);
  assert.equal(
    (cutover.match(/sudo rm -f \/run\/systemd\/system\/devops-console\.service\.d\/90-cutover-killmode\.conf/g) ?? []).length,
    3,
    'normal cutover, failure trap, and rollback must remove the temporary KillMode override',
  );
  assert.equal(
    (cutover.match(/scripts\/terminate_captured_legacy_process\.py/g) ?? []).length,
    2,
    'normal stop and rollback must share the exact guarded termination helper',
  );
  assert.equal(
    (cutover.match(/scripts\/check_legacy_cutover_stopped\.py/g) ?? []).length,
    2,
    'normal cutover and rollback must both prove captured processes, cgroup, and listeners stopped',
  );
  const bashBlocks = [...cutover.matchAll(/```bash\n([\s\S]*?)```/g)].map((match) => match[1]);
  for (const marker of [
    'legacy-processes.json',
    'cgroup-samples.stable.json',
    'systemctl stop devops-console.service',
    'systemctl start dev-coordinator.service',
    'ROLLBACK_STATE=',
  ]) {
    const block = bashBlocks.find((candidate) => candidate.includes(marker));
    assert.ok(block, `missing executable cutover block for ${marker}`);
    assert.match(block, /^set -euo pipefail\n/, `${marker} block must fail closed`);
  }

  const stopBlock = bashBlocks.find((candidate) => candidate.includes('systemctl stop devops-console.service'));
  const shellGuard = stopBlock.split('\n', 1)[0];
  let failClosedResult;
  try {
    await execFileAsync('/bin/bash', [
      '-c',
      `${shellGuard}\nverify_post_stop() { return 23; }\nrelocate() { printf 'relocation-sentinel'; }\nverify_post_stop\nrelocate`,
    ]);
    assert.fail('a failing post-stop verifier unexpectedly reached the next command');
  } catch (error) {
    failClosedResult = error;
  }
  assert.equal(failClosedResult.code, 23);
  assert.doesNotMatch(failClosedResult.stdout ?? '', /relocation-sentinel/);

  const stopLegacy = cutover.indexOf('systemctl stop devops-console.service');
  const safeKillOverride = cutover.indexOf('90-cutover-killmode.conf');
  const stableSamples = cutover.indexOf('cgroup-samples.stable.json');
  const finalSamples = cutover.indexOf('cgroup-samples.prestop-final.json');
  const poststopCheckpoint = cutover.indexOf('coordinator-state.poststop.json');
  const trapCleared = cutover.indexOf('trap - EXIT');
  const stoppedBoundaryChecks = [...cutover.matchAll(/scripts\/check_legacy_cutover_stopped\.py/g)]
    .map((match) => match.index);
  const relocate = cutover.indexOf('port relocate --agent');
  const finalModeRepair = cutover.indexOf('find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type f -exec chmod 600 {} +');
  const finalLayoutPreflight = cutover.indexOf('scripts/check_production_layout.py', finalModeRepair);
  const migrationMarker = cutover.indexOf('state-migration.attempted');
  const finalSync = cutover.indexOf('--sync-state-only');
  const preRelocateCheckpoint = cutover.indexOf('coordinator-state.pre-relocate.json');
  const relocationMarker = cutover.indexOf('relocation.attempted');
  const installUnits = cutover.indexOf('sudo install -m 0644', relocate);
  const startCoordinator = cutover.indexOf('systemctl start dev-coordinator.service', installUnits);
  const startConsole = cutover.indexOf('systemctl start devops-console.service', startCoordinator);
  const rollbackStateDecision = cutover.indexOf('ROLLBACK_STATE=');
  assert.ok(
    stableSamples >= 0 && stableSamples < safeKillOverride && safeKillOverride < finalSamples
      && finalSamples < stopLegacy
      && stopLegacy < poststopCheckpoint && poststopCheckpoint < trapCleared
      && trapCleared < finalModeRepair && finalModeRepair < finalLayoutPreflight
      && finalLayoutPreflight < migrationMarker && migrationMarker < finalSync
      && finalSync < preRelocateCheckpoint && preRelocateCheckpoint < relocationMarker
      && relocationMarker < relocate && relocate < installUnits
      && installUnits < startCoordinator && startCoordinator < startConsole,
    'legacy cgroup must stop and relocate before split units start',
  );
  assert.equal(stoppedBoundaryChecks.length, 2);
  assert.ok(
    stopLegacy < stoppedBoundaryChecks[0] && stoppedBoundaryChecks[0] < poststopCheckpoint
      && stoppedBoundaryChecks[1] < rollbackStateDecision,
    'rollback must recheck the old cgroup before any state restoration decision',
  );
});
