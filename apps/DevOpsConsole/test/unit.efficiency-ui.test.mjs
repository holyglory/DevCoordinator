import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const APP_URL = new URL('../src/ui/app.js', import.meta.url);
const HTML_URL = new URL('../src/ui/index.html', import.meta.url);

test('efficiency navigation is optional and loads only from the session capability', async () => {
  const [app, html] = await Promise.all([fsp.readFile(APP_URL, 'utf8'), fsp.readFile(HTML_URL, 'utf8')]);
  assert.match(html, /id="nav-efficiency" hidden/);
  assert.match(app, /if \(s\.efficiencyAvailable === true\) loadEfficiency\(\)/);
  assert.doesNotMatch(app, /const initialEfficiency = loadEfficiency/);
  assert.match(app, /capability|get\("efficiency"\)|efficiencyAvailable/i);
});

test('the repository collection is the first substantial efficiency content', async () => {
  const html = await fsp.readFile(HTML_URL, 'utf8');
  const section = html.slice(html.indexOf('<section id="sec-efficiency"'), html.indexOf('</section>', html.indexOf('<section id="sec-efficiency"')));
  assert.ok(section.indexOf('id="efficiency-h"') < section.indexOf('id="efficiency-body"'));
  assert.doesNotMatch(section, /<form|synthetic|example data/i);
  assert.match(section, /id="efficiency-body"/);
  assert.ok(html.indexOf('id="efficiency-body"') < html.indexOf('id="efficiency-detail-dialog"'));
});

test('all visible efficiency controls have real handlers and detail uses a modal surface', async () => {
  const app = await fsp.readFile(APP_URL, 'utf8');
  for (const evidence of [
    /efficiency-refresh.*loadEfficiency/,
    /efficiency-detail-close.*closeEfficiencyDetail/,
    /onclick: \(event\) => openEfficiencyDetail/,
    /efficiency-detail-dialog.*showModal/,
    /efficiency-detail-dialog.*cancel[\s\S]{0,180}closeEfficiencyDetail/,
  ]) assert.match(app, evidence);
});
