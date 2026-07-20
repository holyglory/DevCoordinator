import assert from 'node:assert/strict';
import test from 'node:test';

import { createPages } from '../src/auth/pages.mjs';

const pages = createPages({
  config: { domain: 'vr.ae', consoleOrigin: 'https://console.vr.ae' },
});

test('denied page offers Request invite only for a server-issued request token', () => {
  const withRequest = pages.renderDenied({
    email: 'viewer@gmail.com',
    resource: 'app.vr.ae',
    sessionSet: true,
    requestToken: 'signed.token',
  });
  assert.equal(withRequest.status, 403);
  assert.match(withRequest.html, />Request invite</);
  assert.match(withRequest.html, /method="post" action="\/auth\/request-invite"/);
  assert.match(withRequest.html, /name="request_token" value="signed\.token"/);

  const withoutRequest = pages.renderDenied({ email: 'viewer@gmail.com' });
  assert.doesNotMatch(withoutRequest.html, />Request invite</);
  assert.doesNotMatch(withoutRequest.html, /request_token/);
});

test('denied and result pages escape every caller-provided field', () => {
  const denied = pages.renderDenied({
    email: '<img src=x onerror=1>@example.test',
    resource: '<script>alert(1)</script>',
    sessionSet: true,
    requestToken: 'x"><script>alert(1)</script>',
  });
  assert.doesNotMatch(denied.html, /<script>alert\(1\)<\/script>/);
  assert.match(denied.html, /&lt;script&gt;/);
  assert.match(denied.html, /value="x&quot;&gt;&lt;script&gt;/);

  const failed = pages.renderInviteResult({ status: 429, error: '<b>no</b>', retryAfter: 123 });
  assert.equal(failed.status, 429);
  assert.doesNotMatch(failed.html, /<b>no<\/b>/);
  assert.match(failed.html, /&lt;b&gt;no&lt;\/b&gt;/);
  assert.match(failed.html, /123 seconds/);
});

test('invite result distinguishes a new request from an idempotent duplicate', () => {
  const created = pages.renderInviteResult({ status: 202 });
  assert.match(created.html, /Invite requested/);
  const duplicate = pages.renderInviteResult({ status: 202, duplicate: true });
  assert.match(duplicate.html, /Request already pending/);
});
