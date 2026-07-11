import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fsp from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const execFileAsync = promisify(execFile);

function isSafeGitExecutableMode(mode) {
  const permissions = mode & 0o777;
  return permissions === 0o755 || permissions === 0o775;
}

test('production units split coordinator ownership and keep runtime data outside Git', async () => {
  const coordinator = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'dev-coordinator.service'), 'utf8');
  const consoleUnit = await fsp.readFile(path.join(APP_ROOT, 'deploy', 'devops-console.service'), 'utf8');

  assert.match(coordinator, /api serve --host 127\.0\.0\.1 --port 29876/);
  assert.deepEqual(coordinator.split('\n').filter((line) => line.startsWith('Type=')), ['Type=simple']);
  assert.match(coordinator, /^User=holyglory$/m);
  assert.match(coordinator, /^Group=holyglory$/m);
  assert.match(coordinator, /WorkingDirectory=\/home\/DevCoordinator/);
  assert.match(coordinator, /\/home\/DevCoordinator\/skills\/codex-dev-coordinator\/scripts\/dev_coordinator\.py/);
  assert.match(coordinator, /--token-file \/home\/holyglory\/\.codex\/agent-coordinator\/api-token/);
  assert.deepEqual(
    coordinator.split('\n').filter((line) => line.startsWith('ExecStartPost=')),
    [
      'ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py --token-file /home/holyglory/.codex/agent-coordinator/api-token --host 127.0.0.1 --port 29876 --wait-seconds 10 --poll-interval-seconds 0.1',
    ],
    'coordinator readiness must use exactly one pinned authenticated loopback probe',
  );
  assert.deepEqual(
    coordinator.split('\n').filter((line) => line.startsWith('TimeoutStartSec=')),
    ['TimeoutStartSec=20'],
    'coordinator startup must have one exact bounded deadline',
  );
  assert.match(coordinator, /CODEX_AGENT_COORDINATOR_HOME=\/home\/holyglory\/\.codex\/agent-coordinator/);
  assert.match(coordinator, /^AmbientCapabilities=CAP_NET_BIND_SERVICE$/m);
  assert.doesNotMatch(coordinator, /^CapabilityBoundingSet=/m);
  assert.match(coordinator, /^KillMode=process$/m);
  assert.doesNotMatch(coordinator, /^KillMode=(?:control-group|mixed)$/m);
  assert.doesNotMatch(
    coordinator,
    /^(?:PrivateTmp|ProtectSystem|ReadWritePaths|NoNewPrivileges|UMask)=/m,
    'coordinator children must not inherit API-unit sandbox or umask semantics',
  );
  assert.doesNotMatch(coordinator, /0\.0\.0\.0|holyskills/i);

  assert.match(consoleUnit, /Requires=dev-coordinator\.service/);
  assert.deepEqual(consoleUnit.split('\n').filter((line) => line.startsWith('Type=')), ['Type=simple']);
  assert.match(consoleUnit, /After=.*dev-coordinator\.service/);
  assert.match(consoleUnit, /^User=holyglory$/m);
  assert.match(consoleUnit, /^Group=holyglory$/m);
  assert.match(consoleUnit, /EnvironmentFile=\/home\/holyglory\/\.config\/devops-console\/console\.env/);
  assert.match(consoleUnit, /WorkingDirectory=\/home\/DevCoordinator\/apps\/DevOpsConsole/);
  assert.match(consoleUnit, /ExecStartPre=\/usr\/bin\/python3 \/home\/DevCoordinator\/scripts\/check_production_layout\.py/);
  const preflightLine = consoleUnit.split('\n').find((value) => value.startsWith('ExecStartPre='));
  assert.ok(preflightLine);
  for (const expectedPath of [
    '/home/holyglory',
    '/home/holyglory/.config/devops-console/console.env',
    '/home/holyglory/.local/state/devops-console',
    '/home/holyglory/.local/state/devops-console/acme',
    '/home/holyglory/.codex/agent-coordinator',
    '/home/holyglory/.codex/agent-coordinator/api-token',
  ]) assert.ok(preflightLine.includes(expectedPath), expectedPath);
  assert.match(consoleUnit, /ExecStartPre=.*--require-token --wait-token-seconds 10/);
  assert.match(consoleUnit, /ExecStart=\/usr\/bin\/env DEVCOORDINATOR_ROOT=\/home\/DevCoordinator/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_AUTOSTART=0/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_REGISTRATION_REQUIRED=1/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_URL=http:\/\/127\.0\.0\.1:29876/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_SCRIPT=\/home\/DevCoordinator\/skills\/codex-dev-coordinator\/scripts\/dev_coordinator\.py/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_TOKEN_FILE=\/home\/holyglory\/\.codex\/agent-coordinator\/api-token/);
  assert.match(consoleUnit, /ExecStart=.*CODEX_AGENT_COORDINATOR_HOME=\/home\/holyglory\/\.codex\/agent-coordinator/);
  assert.match(consoleUnit, /ExecStart=.*STATE_DIR=\/home\/holyglory\/\.local\/state\/devops-console/);
  assert.match(consoleUnit, /ExecStart=.*ACME_WEBROOT=\/home\/holyglory\/\.local\/state\/devops-console\/acme/);
  assert.match(consoleUnit, /--env-file \/home\/holyglory\/\.config\/devops-console\/console\.env/);
  assert.deepEqual(
    consoleUnit.split('\n').filter((line) => line.startsWith('ExecStartPost=')),
    [
      'ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_console_registration_ready.py --unit devops-console.service --main-pid $MAINPID --token-file /home/holyglory/.codex/agent-coordinator/api-token --project /home/DevCoordinator --name devops-console --port 443 --host 127.0.0.1 --coordinator-port 29876 --expected-executable /usr/bin/node --expected-script bin/devops-console.mjs --env-file /home/holyglory/.config/devops-console/console.env --expected-working-directory /home/DevCoordinator/apps/DevOpsConsole --wait-seconds 80 --poll-interval-seconds 0.1',
    ],
    'Console startup must have one exact MainPID-bound registration readiness gate',
  );
  assert.deepEqual(
    consoleUnit.split('\n').filter((line) => line.startsWith('TimeoutStartSec=')),
    ['TimeoutStartSec=90'],
    'Console startup must bound its 80-second registration observation',
  );
  assert.doesNotMatch(consoleUnit, /^Environment=(?:DEVCOORDINATOR_ROOT|COORDINATOR_|CODEX_AGENT_COORDINATOR_HOME|STATE_DIR)/m);
  assert.match(consoleUnit, /ReadWritePaths=\/home\/holyglory\/\.local\/state\/devops-console/);
  assert.match(consoleUnit, /UMask=0077/);
  assert.match(consoleUnit, /^KillMode=control-group$/m);
  assert.match(consoleUnit, /^PrivateTmp=true$/m);
  assert.match(consoleUnit, /^ProtectSystem=full$/m);
  assert.match(consoleUnit, /^ProtectHome=read-only$/m);
  assert.match(consoleUnit, /^NoNewPrivileges=true$/m);
  assert.match(consoleUnit, /^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$/m);
  assert.doesNotMatch(`${coordinator}\n${consoleUnit}`, /\/home\/holyglory\/holyskills|apps\/DevOpsConsole\/\.env/i);
  assert.doesNotMatch(`${coordinator}\n${consoleUnit}`, /%h|\/root\//, 'system units must not resolve runtime paths from the manager home');
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
  assert.equal(actual.COORDINATOR_REGISTRATION_REQUIRED, '1');
  assert.equal(actual.COORDINATOR_URL, 'http://127.0.0.1:29876');
  assert.equal(actual.STATE_DIR, '/home/holyglory/.local/state/devops-console');
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
  const registrationReadyPath = path.join(scripts, 'check_console_registration_ready.py');
  const registrationReady = await fsp.readFile(registrationReadyPath, 'utf8');
  assert.match(parser, /stat_text\.rfind\("\)"\)/);
  assert.match(parser, /after_comm\[19\]/);
  assert.doesNotMatch(`${parser}\n${sampler}\n${terminator}`, /split\(\)\[21\]/);
  assert.match(terminator, /os, "pidfd_open"/);
  assert.match(terminator, /signal, "pidfd_send_signal"/);
  assert.doesNotMatch(terminator, /os\.kill\(/);
  assert.match(authBoundary, /if observed != expected:/);
  assert.doesNotMatch(authBoundary, /\bassert\b/);
  assert.doesNotMatch(registrationReady, /\bassert\b/);
  for (const mode of [0o755, 0o775]) {
    assert.equal(isSafeGitExecutableMode(mode), true, `safe checkout mode ${mode.toString(8)}`);
  }
  for (const mode of [0o111, 0o311, 0o644, 0o664, 0o757, 0o777]) {
    assert.equal(isSafeGitExecutableMode(mode), false, `unsafe checkout mode ${mode.toString(8)}`);
  }
  const registrationMode = (await fsp.stat(registrationReadyPath)).mode & 0o777;
  assert.equal(
    isSafeGitExecutableMode(registrationMode),
    true,
    `registration helper mode ${registrationMode.toString(8)} must be 755 or 775`,
  );
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
    '--continuous-clean-seconds 5',
    '--wait-timeout-seconds 30 --poll-interval-seconds 0.02',
    '--wait-timeout-seconds 30 --poll-interval-seconds 0.01',
    '--max-observation-gap-seconds 0.1',
    'cgroup-samples.stable.json',
    'cgroup-samples.prestop-final.json',
    'find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type f -exec chmod 600 {} +',
    '90-cutover-killmode.conf',
    'KillMode --value devops-console.service',
    'pre-cutover-identities.json',
    '"server_id": servers[0]["id"]',
    '--sync-state-only',
    'user-runtime.writer-free/routes.json',
    'user-runtime.writer-free/ui-prefs.json',
    'sha256sum --check "$CUTOVER_BACKUP/console.env.sha256"',
    'coordinator-state.poststop.json',
    'coordinator-state.pre-relocate.json',
    'state-migration.attempted',
    'relocation.attempted',
    'no state mutation phase marker; preserving current coordinator state',
    'trap cleanup_cutover_override EXIT',
    'trap - EXIT',
    'restore_enablement devops-console.service',
    'verify_legacy_console_rollback_ready.py',
    'rollback-readiness.json',
    '--main-pid "$ROLLBACK_MAIN_PID" --cgroup "$ROLLBACK_CGROUP"',
    '--inventory-url http://127.0.0.1:29876/v1/inventory',
    '--expected-identities "$CUTOVER_BACKUP/pre-cutover-identities.json"',
    '--project "$OLD_PROJECT" --name devops-console --port 443',
    'captured lease ID still dangling after `locked_state` pruned',
    'Clean absence and an assignment-only unregistered state fail',
    'no inventory row with that captured lease ID may survive',
    'listener-owner snapshot after the inventory response',
    'Raw inventory is never persisted to rollback evidence',
    '--timeout-seconds 30 --poll-interval-seconds 0.1',
    'verify_post_cutover_registration.py',
    'post-cutover-registration-graph.json',
    '--expected-identities "$CUTOVER_BACKUP/pre-cutover-identities.json"',
    'systemctl show --property MainPID --value devops-console.service',
    '--main-pid "$CONSOLE_MAIN_PID"',
    'systemctl disable dev-coordinator.service',
    'dev-coordinator.service.preexisting',
    'sudo rm -f /etc/systemd/system/dev-coordinator.service',
    'systemctl reset-failed dev-coordinator.service devops-console.service',
    'check_coordinator_auth_boundary.py',
    '--inventory-output "$CUTOVER_BACKUP/post-cutover-inventory.json"',
    "grep -Eq '^status=200 remote=[^[:space:]]+ tls=0$'",
    'check_loaded_systemd_paths.py',
    'resolved-unit-paths.json',
    'sha256sum --check SHA256SUMS',
    'For every real attempt, create a new timestamped private backup path',
    'Retain the backup, script, ledgers, and manifest after success or failure',
    'not a kernel-continuous monitor',
    'can leave the ledger `running` or otherwise incomplete',
    '`cutover-run-started`, `service-stop-attempted`',
    '`state-migration-attempted`, `relocation-attempted`, and `cutover-success`',
    'Shell syntax is not helper-interface validation',
  ]) assert.ok(cutover.includes(marker), marker);

  assert.doesNotMatch(cutover, /systemctl restart dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /sleep 2/, 'registration correctness must not depend on a timing sleep');
  assert.doesNotMatch(cutover, /MainPID --value dev-coordinator\.service/);
  assert.doesNotMatch(cutover, /\[ -s [^\n]*cgroup\.procs/);
  assert.doesNotMatch(cutover, /assert status\(/);
  assert.doesNotMatch(cutover, /--samples(?:\s|=)/, 'cutover must not use point-sample mode');
  assert.equal((cutover.match(/\.rfind\("\)"\)/g) ?? []).length, 1);
  assert.equal(
    (cutover.match(/--continuous-clean-seconds 5/g) ?? []).length,
    2,
    'both pre-override and final pre-stop gates require five observed-clean seconds',
  );
  assert.equal(
    (cutover.match(/--max-observation-gap-seconds 0\.1/g) ?? []).length,
    2,
    'both observed-clean gates enforce the same explicit maximum observation gap',
  );
  assert.match(
    cutover,
    /--continuous-clean-seconds 5 \\\n  --wait-timeout-seconds 30 --poll-interval-seconds 0\.01 \\\n  --max-observation-gap-seconds 0\.1\nsudo systemctl stop devops-console\.service/,
  );
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
  const trapCleared = cutover.indexOf('trap - EXIT', poststopCheckpoint);
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
  const resolvedUnitPaths = cutover.indexOf('check_loaded_systemd_paths.py', installUnits);
  const startConsole = cutover.indexOf('systemctl start devops-console.service', startCoordinator);
  const rollbackStateDecision = cutover.indexOf('ROLLBACK_STATE=');
  const rollbackStart = cutover.indexOf(
    'sudo systemctl start devops-console.service',
    rollbackStateDecision,
  );
  const rollbackMainIdentity = cutover.indexOf(
    'ROLLBACK_MAIN_PID="$(systemctl show --property MainPID --value devops-console.service)"',
    rollbackStart,
  );
  const rollbackCgroupIdentity = cutover.indexOf(
    'ROLLBACK_CGROUP="$(systemctl show --property ControlGroup --value devops-console.service)"',
    rollbackStart,
  );
  const rollbackReady = cutover.indexOf(
    'verify_legacy_console_rollback_ready.py',
    rollbackStart,
  );
  assert.ok(
    stableSamples >= 0 && stableSamples < safeKillOverride && safeKillOverride < finalSamples
      && finalSamples < stopLegacy
      && stopLegacy < poststopCheckpoint && poststopCheckpoint < trapCleared
      && trapCleared < finalModeRepair && finalModeRepair < finalLayoutPreflight
      && finalLayoutPreflight < migrationMarker && migrationMarker < finalSync
      && finalSync < preRelocateCheckpoint && preRelocateCheckpoint < relocationMarker
      && relocationMarker < relocate && relocate < installUnits
      && installUnits < resolvedUnitPaths && resolvedUnitPaths < startCoordinator
      && startCoordinator < startConsole,
    'legacy cgroup must stop and relocate before split units start',
  );
  assert.equal(stoppedBoundaryChecks.length, 2);
  assert.ok(
    stopLegacy < stoppedBoundaryChecks[0] && stoppedBoundaryChecks[0] < poststopCheckpoint
      && stoppedBoundaryChecks[1] < rollbackStateDecision,
    'rollback must recheck the old cgroup before any state restoration decision',
  );
  assert.ok(
    rollbackStateDecision < rollbackStart
      && rollbackStart < rollbackMainIdentity
      && rollbackStart < rollbackCgroupIdentity
      && rollbackMainIdentity < rollbackReady
      && rollbackCgroupIdentity < rollbackReady,
    'rollback must bind its restored systemd identity before the bounded readiness verifier',
  );
  assert.doesNotMatch(
    cutover.slice(rollbackStart, rollbackReady),
    /\bsleep\s+\d/,
    'rollback readiness must not depend on a fixed post-start sleep',
  );
});
