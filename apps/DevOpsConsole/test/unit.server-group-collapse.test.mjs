// Regression guard for the Servers-page project disclosure contract. The
// host-wide inventory can contain many projects and hundreds of retained
// resources, so every nonempty project must remain discoverable while only
// one explicitly opened project's bounded member slice is mounted.

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';

const APP_JS_URL = new URL('../src/ui/app.js', import.meta.url);
const APP_CSS_URL = new URL('../src/ui/app.css', import.meta.url);

function extractFunction(source, header) {
  const start = source.indexOf(header);
  assert.notEqual(start, -1, `app.js no longer contains "${header}"`);
  let depth = 0;
  for (let i = source.indexOf('{', start); i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    else if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  assert.fail(`unbalanced braces extracting ${header}`);
  return '';
}

function assertAccessibleDisclosure(source) {
  assert.match(source, /h\('h3',/,
    'each project block needs a real heading');
  assert.match(source, /h\('button', \{/,
    'the whole visible project header must be a native button');
  assert.match(source, /type: 'button'/,
    'the disclosure must not acquire form-submit behavior');
  assert.match(source, /'data-fk': `srv-group:\$\{entry\.group\.key\}`/,
    'the disclosure needs a stable focus-restoration key');
  assert.match(source, /'aria-expanded': String\(expanded\)/,
    'the disclosure must expose its current state');
  assert.match(source, /'aria-controls': panelId/,
    'the disclosure must identify the controlled member region');
  assert.match(source, /hidden: expanded \? undefined : true/,
    'the controlled member region must remain present and honestly hidden when closed');
}

function assertGroupLocalPaging(buildServers, serverProjectBlock) {
  assert.match(buildServers,
    /for \(const entry of groups\) out\.push\(serverProjectBlock\(o, entry\)\);/,
    'every nonempty project header must render independently of expansion state');
  assert.doesNotMatch(buildServers, /pageSlice\(entries, ui\.resourcePages\.servers\)/,
    'the cross-project flat list must not be paged before project disclosure');
  assert.match(serverProjectBlock,
    /if \(expanded\) \{[\s\S]*pageSlice\(entry\.entries, ui\.resourcePages\.servers\)/,
    'only the explicitly expanded project may mount a bounded member page');
}

function assertIntermediateServerLayout(css) {
  const block = css.match(
    /@media \(min-width: 720px\) and \(max-width: 1023px\) \{[\s\S]*?\n\}/,
  )?.[0] || '';
  assert.match(block,
    /\.srv-grid\s*\{[\s\S]*grid-template-columns:\s*26px minmax\(180px, 1fr\) minmax\(180px, 210px\) 118px;[\s\S]*grid-template-rows:\s*auto auto;/,
    'intermediate Servers rows must reserve a readable name track and use two bounded rows');
  assert.match(block,
    /\.srv-grid > :nth-child\(2\)\s*\{[\s\S]*grid-column:\s*2;[\s\S]*grid-row:\s*1;/,
    'the server identity must stay in the readable first-row name track');
  assert.match(block,
    /\.srv-grid > :nth-child\(7\)\s*\{[\s\S]*grid-column:\s*3 \/ 5;[\s\S]*grid-row:\s*1;/,
    'actions must occupy their own bounded first-row zone');
  assert.match(block,
    /\.srv-grid > :nth-child\(4\)\s*\{[\s\S]*grid-column:\s*3;[\s\S]*grid-row:\s*2;/,
    'CPU and memory must move below actions instead of crushing the server name');
}

function assertCompactMobileServerLayout(css) {
  const block = css.match(
    /@media \(max-width: 719px\) \{[\s\S]*?\n\}/,
  )?.[0] || '';
  assert.match(block,
    /\.srv-grid\s*\{[\s\S]*grid-template-columns:\s*24px minmax\(0, \.45fr\) minmax\(150px, 1fr\) auto;/,
    'mobile Servers rows must use one compact four-track summary grid');
  assert.match(block,
    /\.srv-grid > :nth-child\(2\)\s*\{[\s\S]*grid-column:\s*2 \/ 5;[\s\S]*grid-row:\s*1;/,
    'server identity and subdomain must share the first compact row');
  assert.match(block,
    /\.srv-grid > :nth-child\(3\)\s*\{[\s\S]*grid-column:\s*2;[\s\S]*grid-row:\s*2;/,
    'port must join the secondary summary row instead of consuming a line');
  assert.match(block,
    /\.srv-grid > :nth-child\(4\)\s*\{[\s\S]*grid-column:\s*3;[\s\S]*grid-row:\s*2;/,
    'utilization must join the secondary summary row instead of consuming a line');
  assert.match(block,
    /\.srv-grid > :nth-child\(5\)\s*\{[\s\S]*grid-column:\s*4;[\s\S]*grid-row:\s*2;/,
    'status must join the secondary summary row instead of consuming a line');
  assert.match(block,
    /\.srv-grid > :nth-child\(7\)\s*\{[\s\S]*grid-column:\s*2 \/ 5;[\s\S]*grid-row:\s*3;/,
    'actions must occupy one compact final row');
  assert.match(block,
    /\.srv-grid > \.cell\[data-label\]::before\s*\{\s*display:\s*none;/,
    'redundant field labels must not recreate one blank line per value');
}

test('Servers disclosure: default closed and exactly one project opens at a time', async () => {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  assert.match(appJs, /serverGroupsExpanded: new Set\(\)/,
    'Servers project disclosure state must be transient and empty at boot');

  const source = extractFunction(appJs, 'function setExclusiveExpansion(expandedKeys, key)');
  // eslint-disable-next-line no-new-func
  const setExclusiveExpansion = new Function(`${source}; return setExclusiveExpansion;`)();
  const expanded = new Set();

  assert.deepEqual([...expanded], [], 'all projects begin closed');
  setExclusiveExpansion(expanded, 'path:/repo/a');
  assert.deepEqual([...expanded], ['path:/repo/a']);
  setExclusiveExpansion(expanded, 'path:/repo/b');
  assert.deepEqual([...expanded], ['path:/repo/b'], 'opening B must close A');
  setExclusiveExpansion(expanded, 'path:/repo/b');
  assert.deepEqual([...expanded], [], 'activating the open header closes it');

  // Must-catch control: independent toggles allow two large groups to remain
  // mounted, recreating the reported stacked-list problem.
  const nonExclusive = (keys, key) => {
    if (keys.has(key)) keys.delete(key); else keys.add(key);
  };
  const broken = new Set();
  nonExclusive(broken, 'a');
  nonExclusive(broken, 'b');
  assert.notDeepEqual([...broken], ['b'],
    'the fixture must remain capable of reproducing non-exclusive expansion');
});

test('Servers disclosure: accessible header and group-local paging stay wired', async () => {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const buildServers = extractFunction(appJs, 'function buildServers(o)');
  const serverProjectBlock = extractFunction(appJs, 'function serverProjectBlock(o, entry)');

  assertAccessibleDisclosure(serverProjectBlock);
  assertGroupLocalPaging(buildServers, serverProjectBlock);
  assert.match(serverProjectBlock, /setExclusiveExpansion\(ui\.serverGroupsExpanded, entry\.group\.key\)/,
    'the header must use the exclusive disclosure transition');
  assert.match(serverProjectBlock, /ui\.resourcePages\.servers = 0/,
    'switching projects must begin at the first member page');

  const missingExpanded = serverProjectBlock.replace("'aria-expanded': String(expanded),", '');
  assert.throws(() => assertAccessibleDisclosure(missingExpanded), /current state/,
    'the accessibility detector must catch a missing expanded state');

  const flatPaging = buildServers.replace(
    'for (const entry of groups) out.push(serverProjectBlock(o, entry));',
    'pageSlice(groups.flatMap((entry) => entry.entries), ui.resourcePages.servers);',
  );
  assert.throws(() => assertGroupLocalPaging(flatPaging, serverProjectBlock),
    /every nonempty project header/,
    'the paging detector must catch a regression to one flat cross-project list');
});

test('Servers running counts fail closed for unobserved control-only definitions', async () => {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const declaration = appJs.match(/const isServerRunning = \(s\) => ([^;]+);/);
  assert.ok(declaration, 'the Servers collection needs one explicit running-state predicate');
  // eslint-disable-next-line no-new-func
  const isServerRunning = new Function('s', `return ${declaration[1]};`);

  for (const status of ['running', 'starting', 'unhealthy']) {
    assert.equal(isServerRunning({ status }), true, `${status} is active work`);
  }
  for (const status of ['stopping', 'stopped', 'unobserved', undefined]) {
    assert.equal(isServerRunning({ status }), false,
      `${String(status)} must never inflate the project running count`);
  }
});

test('Servers disclosure: narrow headers remain compact, tappable, and overflow-safe', async () => {
  const css = await fsp.readFile(APP_CSS_URL, 'utf8');
  assert.match(css, /\.server-project-toggle\s*\{[\s\S]*grid-template-columns:\s*24px minmax\(0, 1fr\) auto 72px auto/,
    'wide project headers need an explicit bounded grid');
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*\.server-project-toggle\s*\{[\s\S]*min-height:\s*44px/,
    'narrow project headers need a full touch target');
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*\.server-project-toggle \.spark\s*\{\s*display:\s*none;/,
    'the decorative sparkline must yield space on narrow screens');
  assert.match(css, /\.server-group-items\[hidden\],\s*\.docker-group-items\[hidden\]\s*\{\s*display:\s*none;/,
    'closed member regions must not be made visible by layout CSS');
});

test('Servers disclosure: intermediate rows protect names from fixed side columns', async () => {
  const css = await fsp.readFile(APP_CSS_URL, 'utf8');
  assertIntermediateServerLayout(css);

  const regressed = css.replace(
    '26px minmax(180px, 1fr) minmax(180px, 210px) 118px',
    '26px minmax(0, 1fr) 70px 210px 118px 22px 206px',
  );
  assert.throws(() => assertIntermediateServerLayout(regressed), /readable name track/,
    'the must-catch fixture must detect the reported one-character-per-line regression');
});

test('Servers disclosure: mobile rows keep identity, facts, and actions compact', async () => {
  const css = await fsp.readFile(APP_CSS_URL, 'utf8');
  assertCompactMobileServerLayout(css);

  const regressed = css.replace(
    '24px minmax(0, .45fr) minmax(150px, 1fr) auto',
    '26px minmax(0, 1fr)',
  );
  assert.throws(() => assertCompactMobileServerLayout(regressed), /compact four-track summary grid/,
    'the must-catch fixture must detect a regression to one full-width line per field');
});
