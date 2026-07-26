// Regression guard for the Docker-page project disclosure and mid-width row
// geometry. Every project header must remain discoverable while only one
// bounded member page is mounted, and the six-column desktop table must not
// collapse long container names at the reported 1135px viewport.

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
    'each Docker project block needs a real heading');
  assert.match(source, /h\('button', \{/,
    'the whole visible Docker project header must be a native button');
  assert.match(source, /type: 'button'/,
    'the Docker disclosure must not acquire form-submit behavior');
  assert.match(source, /'data-fk': `dock-group:\$\{entry\.group\.key\}`/,
    'the Docker disclosure needs a stable focus-restoration key');
  assert.match(source, /'aria-expanded': String\(expanded\)/,
    'the Docker disclosure must expose its current state');
  assert.match(source, /'aria-controls': panelId/,
    'the Docker disclosure must identify the controlled member region');
  assert.match(source, /hidden: expanded \? undefined : true/,
    'the controlled Docker member region must remain honestly hidden when closed');
}

function assertGroupLocalPaging(buildDocker, dockerProjectBlock) {
  assert.match(buildDocker,
    /for \(const entry of groups\) out\.push\(dockerProjectBlock\(o, entry\)\);/,
    'every nonempty Docker project header must render independently of expansion state');
  assert.doesNotMatch(buildDocker, /pageSlice\(entries, ui\.resourcePages\.docker\)/,
    'the cross-project Docker list must not be paged before project disclosure');
  assert.match(dockerProjectBlock,
    /if \(expanded\) \{[\s\S]*pageSlice\(entry\.entries, ui\.resourcePages\.docker\)/,
    'only the explicitly expanded Docker project may mount a bounded member page');
}

test('Docker disclosure starts closed and opens exactly one project at a time', async () => {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  assert.match(appJs, /dockerGroupsExpanded: new Set\(\)/,
    'Docker project disclosure state must be transient and empty at boot');

  const source = extractFunction(appJs, 'function setExclusiveExpansion(expandedKeys, key)');
  // eslint-disable-next-line no-new-func
  const setExclusiveExpansion = new Function(`${source}; return setExclusiveExpansion;`)();
  const expanded = new Set();

  assert.deepEqual([...expanded], [], 'all Docker projects begin closed');
  setExclusiveExpansion(expanded, 'path:/repo/a');
  assert.deepEqual([...expanded], ['path:/repo/a']);
  setExclusiveExpansion(expanded, 'path:/repo/b');
  assert.deepEqual([...expanded], ['path:/repo/b'], 'opening B must close A');
  setExclusiveExpansion(expanded, 'path:/repo/b');
  assert.deepEqual([...expanded], [], 'activating the open header closes it');

  const nonExclusive = (keys, key) => {
    if (keys.has(key)) keys.delete(key); else keys.add(key);
  };
  const broken = new Set();
  nonExclusive(broken, 'a');
  nonExclusive(broken, 'b');
  assert.notDeepEqual([...broken], ['b'],
    'the fixture must remain capable of reproducing non-exclusive expansion');
});

test('Docker disclosure keeps accessible headers and project-local paging wired', async () => {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const buildDocker = extractFunction(appJs, 'function buildDocker(o)');
  const dockerProjectBlock = extractFunction(appJs, 'function dockerProjectBlock(o, entry)');

  assertAccessibleDisclosure(dockerProjectBlock);
  assertGroupLocalPaging(buildDocker, dockerProjectBlock);
  assert.match(dockerProjectBlock,
    /setExclusiveExpansion\(ui\.dockerGroupsExpanded, entry\.group\.key\)/,
    'the Docker header must use the exclusive disclosure transition');
  assert.match(dockerProjectBlock, /ui\.resourcePages\.docker = 0/,
    'switching Docker projects must begin at the first member page');

  const missingExpanded = dockerProjectBlock.replace("'aria-expanded': String(expanded),", '');
  assert.throws(() => assertAccessibleDisclosure(missingExpanded), /current state/,
    'the accessibility detector must catch a missing expanded state');

  const flatPaging = buildDocker.replace(
    'for (const entry of groups) out.push(dockerProjectBlock(o, entry));',
    'pageSlice(groups.flatMap((entry) => entry.entries), ui.resourcePages.docker);',
  );
  assert.throws(() => assertGroupLocalPaging(flatPaging, dockerProjectBlock),
    /every nonempty Docker project header/,
    'the paging detector must catch a regression to one flat cross-project list');
});

test('Docker rows have an explicit intermediate layout for long names', async () => {
  const css = await fsp.readFile(APP_CSS_URL, 'utf8');
  const mid = /@media \(min-width: 720px\) and \(max-width: 1279px\) \{[\s\S]*?\n\}/;
  assert.match(css, mid,
    'Docker needs a dedicated intermediate-width layout between desktop and stacked mobile');
  const block = css.match(mid)?.[0] || '';
  assert.match(block,
    /\.dock-grid\s*\{[\s\S]*grid-template-columns:\s*20px minmax\(220px, 1fr\) 210px minmax\(140px, 180px\)/,
    'the intermediate grid must reserve a usable minimum for the container name');
  assert.match(block,
    /\.dock-grid > :nth-child\(6\)\s*\{[\s\S]*grid-column:\s*3 \/ 5;[\s\S]*grid-row:\s*1;/,
    'actions must occupy the upper bounded zone instead of squeezing the name track');
  assert.match(block,
    /\.dock-grid > :nth-child\(3\)\s*\{[\s\S]*grid-column:\s*2;[\s\S]*grid-row:\s*2;/,
    'image details must move below the name at intermediate widths');

  const desktopTracks = /\.dock-grid\s*\{\s*grid-template-columns:\s*20px minmax\(0, 1fr\) minmax\(0, 260px\) 210px minmax\(0, 200px\) 300px;\s*\}/;
  assert.match(css, desktopTracks,
    'wide screens must retain the aligned six-column Docker table');
});
