import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import {
  assertFixtureRepositorySecurity,
  canonicalTempDir,
  initializeFixtureGitRepository,
} from './helpers/stack.mjs';

test('E2E Git fixtures ignore local permission metadata but reject structural substitution', async (t) => {
  const root = await canonicalTempDir('devops-console-fixture-security-');
  t.after(() => fsp.rm(root, { recursive: true, force: true }));

  await fsp.chmod(root, 0o770);
  await initializeFixtureGitRepository(root);

  const gitDirectory = path.join(root, '.git');
  const gitConfig = path.join(gitDirectory, 'config');
  await fsp.chmod(root, 0o777);
  await fsp.chmod(gitDirectory, 0o770);
  await fsp.chmod(gitConfig, 0o666);
  assert.equal(await assertFixtureRepositorySecurity(root), root);

  const original = `${gitConfig}.real`;
  await fsp.rename(gitConfig, original);
  await fsp.symlink(original, gitConfig);
  await assert.rejects(assertFixtureRepositorySecurity(root), /not a real file/);
  await fsp.unlink(gitConfig);
  await fsp.rename(original, gitConfig);
  assert.equal(await assertFixtureRepositorySecurity(root), root);
});
