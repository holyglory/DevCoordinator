// Structural guard for the owner invite queue and user-owned Telegram bot
// journeys. Runtime API/store behavior has focused tests; this file protects
// the collection-first navigation, exact action labels, secret input, and
// narrow-screen rules in the dependency-free browser bundle.

import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const HTML_URL = new URL('../src/ui/index.html', import.meta.url);
const JS_URL = new URL('../src/ui/app.js', import.meta.url);
const CSS_URL = new URL('../src/ui/app.css', import.meta.url);

test('incoming invites are an owner-only collection with exact approve and deny actions', async () => {
  const [html, js] = await Promise.all([
    fsp.readFile(HTML_URL, 'utf8'),
    fsp.readFile(JS_URL, 'utf8'),
  ]);

  assert.match(html, /href="#\/invites"[^>]+id="nav-invites" hidden/);
  assert.match(html, /<section id="sec-invites"[\s\S]*?<div id="invites-body"/);
  assert.match(js, /\(id === 'access' \|\| id === 'invites'\)[\s\S]*accessAdmin/,
    'nonowners must not navigate to the access-request queue');
  assert.match(js, /api\('\/api\/access\/requests\?status=all'\)/);
  assert.match(js, /body: \{ decision \}/);
  assert.match(js, /'Approve'/);
  assert.match(js, /'Deny'/);
  assert.match(js, /Approving Console access grants full server, Docker, route and port control/,
    'the high-impact Console grant must be explained beside the exact request');
});

test('Telegram page lists existing bots before opening its secondary registration dialog', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(HTML_URL, 'utf8'),
    fsp.readFile(JS_URL, 'utf8'),
    fsp.readFile(CSS_URL, 'utf8'),
  ]);

  const section = html.indexOf('<section id="sec-telegram"');
  const collection = html.indexOf('<div id="telegram-body"', section);
  const dialog = html.indexOf('<dialog id="telegram-dialog"');
  assert.ok(section >= 0 && collection > section && dialog > collection,
    'the real bot collection must precede the invoked registration surface');
  assert.match(html, /id="telegram-token"[^>]+type="password"/,
    'a bot token must not use a visible ordinary text input');
  assert.match(html, /Replace the bot's existing webhook/,
    'webhook takeover must require a visible explicit choice');
  assert.match(js, /\/api\/telegram\/bots/);
  assert.match(js, /projectIds: \[\.\.\.selected\]/,
    'project assignment must send exact IDs selected from coordinator inventory');
  assert.match(js, /\/authorizations\/\$\{encodeURIComponent\(authId\)\}\/decision/);
  assert.match(css, /@media \(max-width: 719px\)[\s\S]*\.queue-row-head, \.telegram-bot-head \{ flex-direction: column; \}/,
    'approval actions and bot metadata need an explicit narrow-screen layout');
});

test('browser code never reads or renders a Telegram token from a bot view', async () => {
  const js = await fsp.readFile(JS_URL, 'utf8');
  assert.doesNotMatch(js, /bot\.(?:token|secret)/,
    'Telegram list views must never expect a credential from the API');
  assert.doesNotMatch(js, /state\.telegram[\s\S]{0,80}(?:token|secret)/,
    'Telegram state must contain descriptors only');
});
