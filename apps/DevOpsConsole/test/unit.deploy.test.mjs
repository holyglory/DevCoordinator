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
  assert.doesNotMatch(coordinator, /--token-file|api-token|COORDINATOR_TOKEN_FILE/);
  assert.deepEqual(
    coordinator.split('\n').filter((line) => line.startsWith('ExecStartPost=')),
    [
      'ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py --host 127.0.0.1 --port 29876 --wait-seconds 10 --poll-interval-seconds 0.1',
    ],
    'coordinator readiness must use exactly one pinned trusted-loopback probe',
  );
  assert.deepEqual(
    coordinator.split('\n').filter((line) => line.startsWith('TimeoutStartSec=')),
    ['TimeoutStartSec=20'],
    'coordinator startup must have one exact bounded deadline',
  );
  assert.doesNotMatch(
    coordinator,
    /^Requires=.*devcoordinator-broker\.service/m,
    'a broker maintenance stop must not tear down the authenticated API listener',
  );
  assert.match(
    coordinator,
    /^Wants=.*devcoordinator-broker\.service/m,
    'API boot should still request the server-wide broker',
  );
  assert.match(coordinator, /^Environment=DEVCOORDINATOR_AUTHORITY=system$/m);
  assert.match(coordinator, /CODEX_AGENT_COORDINATOR_HOME=\/var\/lib\/devcoordinator-clients\/1000/);
  assert.match(coordinator, /^AmbientCapabilities=CAP_NET_BIND_SERVICE$/m);
  assert.doesNotMatch(coordinator, /^CapabilityBoundingSet=/m);
  assert.match(coordinator, /^KillMode=process$/m);
  assert.deepEqual(
    coordinator.split('\n').filter((line) => line.startsWith('Restart=')),
    ['Restart=always'],
    'unexpected clean and failed API exits must both be supervised',
  );
  assert.match(coordinator, /^RestartSec=3$/m);
  assert.match(coordinator, /^StandardOutput=journal$/m);
  assert.match(coordinator, /^StandardError=journal$/m);
  assert.match(coordinator, /^SyslogIdentifier=dev-coordinator$/m);
  assert.match(coordinator, /^LogRateLimitIntervalSec=30s$/m);
  assert.match(coordinator, /^LogRateLimitBurst=10000$/m);
  assert.doesNotMatch(coordinator, /^KillMode=(?:control-group|mixed)$/m);
  assert.doesNotMatch(
    coordinator,
    /^(?:PrivateTmp|ProtectSystem|ReadWritePaths|NoNewPrivileges|UMask)=/m,
    'coordinator children must not inherit API-unit sandbox or umask semantics',
  );
  assert.doesNotMatch(coordinator, /0\.0\.0\.0|holyskills/i);

  assert.doesNotMatch(
    consoleUnit,
    /^Requires=.*dev-coordinator\.service/m,
    'the public TLS edge must survive a coordinator API maintenance stop',
  );
  assert.match(
    consoleUnit,
    /^Wants=.*dev-coordinator\.service/m,
    'Console boot should still request the coordinator API',
  );
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
  ]) assert.ok(preflightLine.includes(expectedPath), expectedPath);
  assert.doesNotMatch(preflightLine, /--token-file|--require-token|--wait-token-seconds/);
  assert.match(consoleUnit, /ExecStart=\/usr\/bin\/env DEVCOORDINATOR_ROOT=\/home\/DevCoordinator/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_AUTOSTART=0/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_REGISTRATION_REQUIRED=1/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_URL=http:\/\/127\.0\.0\.1:29876/);
  assert.match(consoleUnit, /ExecStart=.*COORDINATOR_SCRIPT=\/home\/DevCoordinator\/skills\/codex-dev-coordinator\/scripts\/dev_coordinator\.py/);
  assert.doesNotMatch(consoleUnit, /COORDINATOR_TOKEN_FILE|api-token|--token-file/);
  assert.match(consoleUnit, /ExecStart=.*DEVCOORDINATOR_AUTHORITY=system/);
  assert.match(consoleUnit, /ExecStart=.*CODEX_AGENT_COORDINATOR_HOME=\/var\/lib\/devcoordinator-clients\/1000/);
  assert.match(consoleUnit, /ExecStart=.*STATE_DIR=\/home\/holyglory\/\.local\/state\/devops-console/);
  assert.match(consoleUnit, /ExecStart=.*ACME_WEBROOT=\/home\/holyglory\/\.local\/state\/devops-console\/acme/);
  assert.match(consoleUnit, /--env-file \/home\/holyglory\/\.config\/devops-console\/console\.env/);
  assert.deepEqual(
    consoleUnit.split('\n').filter((line) => line.startsWith('ExecStartPost=')),
    [
      'ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_console_registration_ready.py --unit devops-console.service --main-pid $MAINPID --project /home/DevCoordinator --name devops-console --port 443 --host 127.0.0.1 --coordinator-port 29876 --expected-executable /usr/bin/node --expected-script bin/devops-console.mjs --env-file /home/holyglory/.config/devops-console/console.env --expected-working-directory /home/DevCoordinator/apps/DevOpsConsole --wait-seconds 80 --poll-interval-seconds 0.1',
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
  assert.deepEqual(
    consoleUnit.split('\n').filter((line) => line.startsWith('Restart=')),
    ['Restart=always'],
    'unexpected clean and failed Console exits must both be supervised',
  );
  assert.match(consoleUnit, /^RestartSec=3$/m);
  assert.match(consoleUnit, /^StandardOutput=journal$/m);
  assert.match(consoleUnit, /^StandardError=journal$/m);
  assert.match(consoleUnit, /^SyslogIdentifier=devops-console$/m);
  assert.match(consoleUnit, /^LogRateLimitIntervalSec=30s$/m);
  assert.match(consoleUnit, /^LogRateLimitBurst=10000$/m);
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
  const quickStart = readme.split('## Quick start')[1]?.split('## Configuration')[0] ?? '';
  const deploy = readme
    .split('## Deploy the current systemd release')[1]
    ?.split('## Manage Google account access')[0] ?? '';

  assert.match(deploy, /scripts\/software_owned_delivery\.py run/);
  assert.match(deploy, /one immutable, content-addressed release/);
  assert.match(
    deploy,
    /Console routes, users, grants, settings, secret\s+references, and project data remain in their existing service-owned stores/,
  );
  assert.match(deploy, /The Test Store and unfinished test work are disposable/);
  assert.doesNotMatch(
    deploy,
    /(?:install|cp|mv|rm)[^\n]*(?:console\.env|\.env\.example)/,
    'the current delivery runbook must not replace or remove the external production environment',
  );

  let createIfAbsent = false;
  let templateInstallCount = 0;
  for (const rawLine of quickStart.split('\n')) {
    const line = rawLine.trim();
    if (line === 'if [ ! -e "$HOME/.config/devops-console/console.env" ]; then') createIfAbsent = true;
    if (line.includes('.env.example') && line.includes('"$HOME/.config/devops-console/console.env"')) {
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

test('deployment runbook models the current single Console topology', async () => {
  const readme = await fsp.readFile(path.join(APP_ROOT, 'README.md'), 'utf8');
  const deploy = readme
    .split('## Deploy the current systemd release')[1]
    ?.split('## Manage Google account access')[0] ?? '';
  const normalizedDeploy = deploy.replace(/\s+/g, ' ');

  for (const marker of [
    'one immutable, content-addressed release',
    'scripts/software_owned_delivery.py run',
    'atomically activates the current service topology',
    'rolls back to the immediately preceding current-format release',
    'Repository registrations, Console routes, users, grants, settings, secret',
    'The Test Store and unfinished test work are disposable',
    'Pre-availability checkout units, handoff listeners, legacy import, fleet adoption, storage split,',
    'and rollback to the old layout are unsupported',
  ]) assert.ok(normalizedDeploy.includes(marker), marker);

  assert.equal((deploy.match(/scripts\/software_owned_delivery\.py run/g) ?? []).length, 1);
  assert.doesNotMatch(readme, /### Existing-host checkout cutover/);
  assert.doesNotMatch(
    deploy,
    /child-coordinator|legacy-processes\.json|90-cutover-killmode|verify_legacy_cutover_boundary|CUTOVER_BACKUP/,
  );
  assert.doesNotMatch(deploy, /systemctl (?:start|stop|restart|disable) dev-coordinator\.service/);
});
