// Regression guard for the browser-performance failure caused by mounting the
// complete host-wide inventory (including hidden pages) in one document.
// Resource lists must stay losslessly pageable and only the active hash page
// may retain a dynamic body. The live-browser verification covers the actual
// element budget; annotation compatibility has a separate CSP regression
// guard because DOM reduction alone did not fix the reported annotation path.

import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';

const APP_JS_URL = new URL('../src/ui/app.js', import.meta.url);

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

async function loadDomBudgetContract() {
  const appJs = await fsp.readFile(APP_JS_URL, 'utf8');
  const sizeMatch = appJs.match(/const RESOURCE_PAGE_SIZE = (\d+);/);
  assert.ok(sizeMatch, 'app.js must declare a fixed resource-page DOM budget');
  const resourcePageSize = Number(sizeMatch[1]);
  const pageSliceSource = extractFunction(appJs, 'function pageSlice(items, requestedPage)');
  // eslint-disable-next-line no-new-func
  const pageSlice = new Function(
    'RESOURCE_PAGE_SIZE', `${pageSliceSource}; return pageSlice;`,
  )(resourcePageSize);
  return { appJs, pageSlice, resourcePageSize };
}

function assertPagedDockerServers(buildServersSource, serverProjectBlockSource) {
  assert.match(buildServersSource,
    /entries\.push\(\{ group, extraText, kind: 'docker', item: c, isHidden \}\);/,
    'Docker web servers must enter the bounded Servers collection');
  assert.match(serverProjectBlockSource,
    /: dockerServerItem\(o, member\.item, member\.isHidden\)\);/,
    'typed Docker entries must render as Docker-backed server rows');
}

test('resource pagination: the 474-container incident stays bounded without losing an item', async () => {
  const { pageSlice, resourcePageSize } = await loadDomBudgetContract();
  assert.ok(resourcePageSize > 0 && resourcePageSize <= 75,
    'one mounted resource page must remain at or below the verified 75-row budget');

  const incidentInventory = Array.from({ length: 474 }, (_, id) => ({ id }));
  const first = pageSlice(incidentInventory, 0);
  assert.equal(first.items.length, resourcePageSize);
  assert.equal(first.total, 474);
  assert.equal(first.start, 1);
  assert.equal(first.end, resourcePageSize);

  const recovered = [];
  for (let page = 0; page < first.pageCount; page += 1) {
    const slice = pageSlice(incidentInventory, page);
    assert.ok(slice.items.length <= resourcePageSize, `page ${page + 1} exceeded the DOM row budget`);
    recovered.push(...slice.items);
  }
  assert.deepEqual(recovered, incidentInventory,
    'pagination must make every real inventory row reachable exactly once');
});

test('resource pagination: a stale page index clamps after hiding or inventory shrink', async () => {
  const { pageSlice } = await loadDomBudgetContract();
  const reduced = Array.from({ length: 11 }, (_, id) => id);
  const slice = pageSlice(reduced, 99);
  assert.equal(slice.page, 0);
  assert.deepEqual(slice.items, reduced);
  assert.deepEqual({ start: slice.start, end: slice.end }, { start: 1, end: 11 });
});

test('render wiring: hidden pages unmount and every inventory-heavy surface is bounded', async () => {
  const { appJs } = await loadDomBudgetContract();
  const renderAll = extractFunction(appJs, 'function renderAll(force = false)');
  const buildServers = extractFunction(appJs, 'function buildServers(o)');
  const serverProjectBlock = extractFunction(appJs, 'function serverProjectBlock(o, entry)');
  const buildDocker = extractFunction(appJs, 'function buildDocker(o)');
  const projectNode = extractFunction(appJs, 'function projectNode(o, group, hiddenProject, revealing, hiddenServers, hiddenDocker)');

  assert.match(renderAll, /unmountInactiveSections\(page\)/,
    'poll rendering must remove dynamic bodies belonging to hidden hash pages');
  assert.match(buildServers,
    /for \(const entry of groups\) out\.push\(serverProjectBlock\(o, entry\)\);/,
    'Servers must keep every nonempty project header discoverable');
  assert.match(serverProjectBlock,
    /pageSlice\(entry\.entries, ui\.resourcePages\.servers\)/,
    'the expanded Servers project must not mount its complete member inventory');
  assert.doesNotMatch(buildServers, /pageSlice\(entries, ui\.resourcePages\.servers\)/,
    'Servers must not page one flat cross-project list before disclosure');
  assert.match(buildDocker, /const requestedPage = focusIndex >= 0[\s\S]*ui\.resourcePages\.docker;/,
    'post-restore focus may select a page only from the exact bounded Docker collection');
  assert.match(buildDocker, /pageSlice\(entries, requestedPage\)/,
    'Docker must not mount its complete host-wide inventory');
  assert.match(projectNode, /const collapsed = !ui\.treeExpanded\.has\(group\.key\);/,
    'Projects must start as the promised project collection, with members disclosed on demand');
  assert.match(projectNode, /pageSlice\(entries, ui\.resourcePages\.projects\)/,
    'an expanded project must not recreate the complete host-wide inventory DOM');
  assert.match(projectNode, /ui\.treeExpanded\.clear\(\)/,
    'only one project member collection may be mounted at a time');
  assert.doesNotMatch(appJs, /treeCollapsed/,
    'newly discovered projects must default closed instead of silently expanding on the next poll');
});

test('Servers Docker-row detector catches either half of a broken paged rendering path', async () => {
  const { appJs } = await loadDomBudgetContract();
  const source = extractFunction(appJs, 'function buildServers(o)');
  const block = extractFunction(appJs, 'function serverProjectBlock(o, entry)');
  assert.doesNotThrow(() => assertPagedDockerServers(source, block),
    'the valid paged representation is the false-positive control');

  const missingEntry = source.replace(
    "entries.push({ group, extraText, kind: 'docker', item: c, isHidden });", '',
  );
  assert.throws(() => assertPagedDockerServers(missingEntry, block),
    /must enter the bounded Servers collection/,
    'must catch a Docker resource dropped before pagination');

  const missingRender = block.replace(
    ': dockerServerItem(o, member.item, member.isHidden));', ': serverItem(o, member.item, member.isHidden));',
  );
  assert.throws(() => assertPagedDockerServers(source, missingRender),
    /must render as Docker-backed server rows/,
    'must catch a typed Docker entry rendered through the wrong row path');
});
