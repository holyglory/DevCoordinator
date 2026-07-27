import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  const bodyStart = source.indexOf('{', start + header.length);
  assert.notEqual(bodyStart, -1, `app.js no longer has a body for "${header}"`);
  for (let i = bodyStart; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
}

test('lifecycle dialog promises human context without rendering opaque coordinator IDs', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const dialog = extractFunction(app, 'function renderLifecycleDialog()');
  const label = extractFunction(app, 'function lifecycleKindLabel(kind)');

  assert.match(dialog, /target\.display_name/);
  assert.match(dialog, /lifecycleKindLabel\(target\.target_kind\)/);
  assert.doesNotMatch(dialog, /target\.target_id/,
    'opaque target IDs must remain exact hidden request data, not ordinary interface content');
  assert.match(label, /Project/);
  assert.match(label, /Docker container/);
  assert.doesNotMatch(app, /lifecycleTarget\('repository'/,
    'new UI actions must emit canonical project targets');
  assert.match(app, /lifecycleTarget\('project', group\.repoId/);
  assert.doesNotMatch(app, /lifecycleTarget\('container',[\s\S]{0,120}'servers'/,
    'Docker-backed web servers must reveal lifecycle results in canonical Docker views');
  const targetFactory = extractFunction(app, 'function lifecycleTarget(kind, id, displayName, page, extras = {})');
  assert.doesNotMatch(targetFactory, /displayName \|\| String\(id\)/,
    'missing active labels must not fall back to opaque identifiers');
  const displayName = extractFunction(app, 'function archiveDisplayName(row)');
  const archivedGroups = extractFunction(app, 'function archivedGroups(page)');
  assert.doesNotMatch(displayName, /target_id/,
    'archive rows without a display name must use an honest generic label, not an opaque ID');
  assert.doesNotMatch(archivedGroups, /`Project \$\{parent\}`/,
    'archive group labels must not expose opaque parent IDs');
  const planSection = extractFunction(app, 'function lifecyclePlanSection(title, values, blocked = false)');
  assert.match(planSection, /'None'/,
    'every exact plan section must stay visible even when the coordinator reports an empty list');
  const submit = extractFunction(app, 'async function submitLifecycleDialog()');
  assert.doesNotMatch(submit, /window\.confirm/,
    'durable lifecycle actions must use the reviewed plan dialog, never a generic confirm');
  assert.match(submit, /\['effects', 'retained', 'deleted', 'blockers'\]\.every/);
  assert.match(submit, /confirmation_phrase: phrase \? \$\('#lifecycle-confirm'\)\.value : ''/,
    'archive and purge apply must always send the exact three-field broker contract');
});

test('archive counts never claim zero before the owner-only archive list loads', async () => {
  const [html, app] = await Promise.all([
    fsp.readFile(new URL('../src/ui/index.html', import.meta.url), 'utf8'),
    fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8'),
  ]);

  for (const page of ['projects', 'servers', 'docker']) {
    assert.match(html, new RegExp(`id="${page}-archived-count" hidden><\\/span>`));
    assert.doesNotMatch(html, new RegExp(`id="${page}-archived-count"[^>]*>0<`));
  }
  const sync = extractFunction(app, 'function syncLifecycleFilters()');
  assert.match(sync, /Array\.isArray\(state\.archives\)/,
    'the count must be derived only from an authoritative loaded collection');
  assert.match(sync, /: null\)/,
    'an unknown archive count must be omitted rather than coerced to zero');
  assert.match(app, /async function loadArchives\(\{ force = false \} = \{\}\)[\s\S]*archivesRequestedGeneration/);
  assert.match(app, /while \(archivesCompletedGeneration < requestedGeneration\)/,
    'a forced post-mutation refresh must wait past any older archive read');
});

test('post-lifecycle focus waits until inventory and archive refreshes settle', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const refresh = extractFunction(app, 'async function refreshOverview({ force = false, fresh = false } = {})');
  const focus = extractFunction(app, 'function focusLifecycleTarget()');

  assert.match(refresh, /!lifecycleRefreshInFlight[\s\S]*loadArchives\(\{ force: true \}\)/,
    'the mutation-owned archive refresh must not be duplicated by overview refresh');
  assert.match(focus, /if \(lifecycleRefreshInFlight\) return;/,
    'result focus must be deferred until every mutation refresh has settled');
});

test('archive UI and polling require explicit backend lifecycle readiness', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const capability = extractFunction(app, 'function lifecycleAvailable()');
  const sync = extractFunction(app, 'function syncLifecycleVisibility()');
  const load = extractFunction(app, 'async function loadArchives({ force = false } = {})');
  const button = extractFunction(app, 'function archiveButton(target, { compact = false } = {})');
  const refresh = extractFunction(app, 'async function refreshOverview({ force = false, fresh = false } = {})');
  const boot = extractFunction(app, 'async function boot()');

  assert.match(capability, /accessAdmin === true/);
  assert.match(capability, /lifecycleAvailable === true/,
    'configured Gmail ownership and broker cleanup readiness are separate facts');
  assert.match(sync, /const available = lifecycleAvailable\(\)/);
  assert.match(sync, /button\.disabled = !available/,
    'Archived controls must be visibly disabled while production activation is blocked');
  assert.match(load, /if \(!lifecycleAvailable\(\)\) return;/,
    'unavailable lifecycle must never generate archive-list traffic');
  assert.match(button, /!lifecycleAvailable\(\)/,
    'unavailable lifecycle must not expose per-resource Archive actions');
  assert.match(refresh, /lifecycleAvailable\(\)[\s\S]*loadArchives\(\{ force: true \}\)/,
    'background overview polls must not probe unavailable cleanup authorization');
  assert.match(boot, /lifecycleAvailable\(\)[\s\S]*loadArchives\(\)/,
    'boot must not repeatedly call a deliberately unavailable archive endpoint');
});

test('worktrees are disclosed only when the backend advertises removable archived children', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const groups = extractFunction(app, 'function archivedGroups(page)');

  assert.match(groups, /row\?\.target_kind === 'worktree' && row\?\.removable === true/);
  assert.match(groups, /archivedParentId\(row\) === String\(project\.target_id\)/);
});

test('lifecycle controls retain 44px mobile targets without widening archived rows', async () => {
  const css = await fsp.readFile(new URL('../src/ui/app.css', import.meta.url), 'utf8');
  assert.match(css, /\.lifecycle-filter \.btn \{[^}]*min-height: 44px;/s);
  assert.match(css, /\.archive-actions \.btn \{ min-height: 44px; \}/);
  assert.match(css, /\.iconbtn\[data-fk\^="archive:"\], \.iconbtn\[data-fk\^="worker-remove:"\], #lifecycle-dialog-close \{\s*width: 44px;\s*height: 44px;/s);
  assert.match(css, /\.iconbtn\[data-fk\^="worker-remove:"\]/,
    'worker removal must keep the same coarse-pointer target as archive controls');
  assert.match(css, /\.archive-row \{ grid-template-columns: minmax\(0, 1fr\); \}/,
    'narrow archived rows must stack instead of overflowing horizontally');
});

test('supervised workers expose exact crash evidence, policy controls and staged removal', async () => {
  const app = await fsp.readFile(new URL('../src/ui/app.js', import.meta.url), 'utf8');
  const css = await fsp.readFile(new URL('../src/ui/app.css', import.meta.url), 'utf8');
  const index = await fsp.readFile(new URL('../src/ui/index.html', import.meta.url), 'utf8');
  const status = extractFunction(app, 'function serverStatusMeta(s)');
  const message = extractFunction(app, 'function workerCrashLoopMessage(supervision)');
  const panel = extractFunction(app, 'function workerSupervisionPanel(s)');
  const controls = extractFunction(app, 'function workerControlButtons(server, busy, prefix = \'srv\')');
  const treeRow = extractFunction(app, 'function treeServerRow(o, s, hiddenRow)');
  const dialog = extractFunction(app, 'function renderLifecycleDialog()');
  const removal = extractFunction(app, 'async function submitLifecycleDialog()');

  assert.match(status, /breaker\?\.state === 'tripped'/);
  assert.match(status, /crash loop stopped/);
  assert.match(message, /crash_count_in_window/);
  assert.match(message, /window_seconds/);
  assert.match(panel, /Keep alive/);
  assert.match(panel, /Turning this off does not stop a worker that is already running/);
  assert.match(panel, /\/api\/runtime\/artifacts\/worker_attempt\//);
  assert.match(panel, /Retained crash traces/);
  assert.match(controls, /Start and re-arm/);
  assert.match(controls, /rearmCrashLoop: true/);
  assert.match(controls, /desired state to stopped/);
  assert.match(treeRow, /supervised \? 'worker' : 'server'/,
    'the Projects tree must identify a supervised service as a worker');
  assert.match(treeRow, /Keep alive on/,
    'the Projects tree must disclose the worker restart policy');
  assert.match(index, /project actions affect only the root runtime/,
    'Projects help must state the exact root-only action boundary');
  assert.match(css,
    /\.tree-grid \{\s*grid-template-columns: 84px minmax\(0, 1fr\) 180px 180px 352px;/,
    'the desktop running-count column must fit root-scope wording without entering actions');

  assert.match(removal, /model\.action === 'worker-remove'/);
  assert.match(dialog, /no-resurrection tombstone/,
    'permanent removal must disclose retained safety and crash evidence');
  assert.doesNotMatch(dialog, /deletes its retained coordinator record/,
    'the UI must not claim retained tombstone and crash evidence is deleted');
  assert.match(removal, /remove_plan_id = plan\.plan_id/);
  assert.match(removal, /remove_plan_fingerprint = plan\.plan_fingerprint \|\| plan\.fingerprint/);
  assert.match(removal, /model\.archivedInThisJourney = true;[\s\S]*model\.plan = null;[\s\S]*checkedPlan\(await workerRequest\(\)\)/,
    'after archive the dialog may fetch only a new read-only plan');
  assert.doesNotMatch(removal, /workerRequest\(model\.plan\)[\s\S]*workerRequest\(model\.plan\)/,
    'one submit must never apply archive and permanent removal plans in sequence');
});
