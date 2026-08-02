import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CANONICAL_METRICS,
  CANONICAL_OVERVIEW,
  CANONICAL_PREFS,
  CANONICAL_SESSION,
} from '../Tools/canonical-api-fixtures.mjs';
import { login, makeJar, startStack } from './helpers/stack.mjs';

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(APP_ROOT, '..', '..');
const HOST_ID = '00000000-0000-4000-8000-000000000001';
const AWAITING_HOST_ID = '00000000-0000-4000-8000-000000000002';
const CELL_ID = '00000000-0000-4000-8000-000000000010';
const VM_A = '00000000-0000-4000-8000-000000000101';
const VM_B = '00000000-0000-4000-8000-000000000102';
const VM_MISSING = '00000000-0000-4000-8000-000000000103';
const VM_UNAPPROVED = '00000000-0000-4000-8000-000000000104';

function loadLockedPlaywright() {
  const require = createRequire(import.meta.url);
  const locked = require(path.join(REPO_ROOT, 'ci', 'playwright', 'package.json'));
  const manifest = require(path.join(
    REPO_ROOT,
    'ci',
    'playwright',
    'node_modules',
    'playwright',
    'package.json',
  ));
  assert.equal(manifest.version, locked.dependencies.playwright);
  return require(path.join(REPO_ROOT, 'ci', 'playwright', 'node_modules', 'playwright'));
}

async function launchChromium(chromium) {
  const options = {
    headless: true,
    args: ['--host-resolver-rules=MAP console.vr.ae 127.0.0.1'],
  };
  try {
    return await chromium.launch(options);
  } catch (managedError) {
    for (const executablePath of ['/usr/bin/google-chrome', '/usr/bin/chromium']) {
      if (!fs.existsSync(executablePath)) continue;
      try {
        return await chromium.launch({ ...options, executablePath });
      } catch {
        // Report the managed-browser failure below if neither system browser works.
      }
    }
    throw managedError;
  }
}

function virtualMachine(vmId, name, role, state, heartbeat) {
  return {
    vm_id: vmId,
    observation_id: '00000000-0000-4000-8000-000000000901',
    name,
    role,
    state,
    generation: 2,
    vcpu: 4,
    startup_memory_bytes: 8 * 1024 ** 3,
    assigned_memory_bytes: state === 'running' ? 8 * 1024 ** 3 : 0,
    ip_addresses: state === 'running' ? ['172.28.210.11'] : [],
    heartbeat,
    automatic_checkpoints: false,
    replication: 'disabled',
    first_seen_at: '2026-07-29T12:00:00Z',
    last_seen_at: '2026-07-29T12:05:00Z',
  };
}

function infrastructureProjection({ partial = false, hasMore = false, empty = false } = {}) {
  return {
    schema: 'spectre.infrastructure.projection.v1',
    generated_at: '2026-07-29T12:08:00Z',
    observation_cadence_seconds: 60,
    stale_after_seconds: 180,
    sort: 'host_id',
    after_host_id: null,
    host_limit: 100,
    vm_limit_per_host: 256,
    rejection_limit_per_host: 20,
    hosts: empty ? [] : [{
      host_id: HOST_ID,
      cell: {
        cell_id: CELL_ID,
        name: 'SPECTRE laboratory',
        region: 'lab',
        classification_label: 'test-only',
        enabled: false,
      },
      display_name: 'SPECTRE Hyper-V laboratory',
      failure_domain_label: 'single host; loss stops the whole laboratory',
      platform: 'windows-hyperv',
      enrollment_enabled: false,
      last_contact_at: '2026-07-29T12:07:58Z',
      last_captured_at: '2026-07-29T12:05:00Z',
      last_accepted_at: '2026-07-29T12:05:04Z',
      contact_freshness: {
        status: 'fresh',
        age_seconds: 2,
        stale_after_seconds: 180,
      },
      capture_freshness: {
        status: 'stale',
        age_seconds: 180,
        stale_after_seconds: 180,
      },
      acceptance_freshness: {
        status: 'fresh',
        age_seconds: 176,
        stale_after_seconds: 180,
      },
      accepted_observation_id: '00000000-0000-4000-8000-000000000901',
      signature_verified: true,
      evidence_available: false,
      verification: {
        certificate_generation: 1,
        canonical_payload_sha256: 'a'.repeat(64),
        observer_version: '1.0.0',
      },
      snapshot: {
        hostname: 'SERVER-WORKII',
        platform_version: 'Windows Server 2022 build 20348',
        management_addresses: ['10.0.10.211'],
        logical_cpu: 40,
        physical_memory_bytes: 137_372_676_096,
        uptime_seconds: 3600,
        roster_complete: !partial,
        roster_error_code: partial ? 'vm_discovery_incomplete' : null,
      },
      current_vm_count: 3,
      approved_vm_count: 3,
      missing_approved_virtual_machines: [{
        vm_id: VM_MISSING,
        approved_role: 'load',
      }],
      missing_approved_projection_truncated: false,
      virtual_machines: [
        virtualMachine(VM_A, 'SPECTRE-LAB-INGRESS-01', 'ingress', 'running', 'ok'),
        virtualMachine(VM_B, 'SPECTRE-LAB-HUB-01', 'hub', 'off', 'not-running'),
        virtualMachine(VM_UNAPPROVED, 'SPECTRE-LAB-UTILITY-01', null, 'running', 'ok'),
      ],
      vm_projection_truncated: false,
      recent_rejections: [{
        audit_id: '00000000-0000-4000-8000-000000000801',
        broker_operation_id: '00000000-0000-4000-8000-000000000802',
        code: 'invalid_signature',
        message: 'The signed report did not match the enrolled verification key.',
        received_at: '2026-07-29T12:04:00Z',
      }],
    }, {
      host_id: AWAITING_HOST_ID,
      cell: {
        cell_id: CELL_ID,
        name: 'SPECTRE laboratory',
        region: 'lab',
        classification_label: 'test-only',
        enabled: true,
      },
      display_name: 'Awaiting first observation',
      failure_domain_label: 'independent fixture host',
      platform: 'windows-hyperv',
      enrollment_enabled: true,
      last_contact_at: null,
      last_captured_at: null,
      last_accepted_at: null,
      contact_freshness: {
        status: 'never',
        age_seconds: null,
        stale_after_seconds: 180,
      },
      capture_freshness: {
        status: 'never',
        age_seconds: null,
        stale_after_seconds: 180,
      },
      acceptance_freshness: {
        status: 'never',
        age_seconds: null,
        stale_after_seconds: 180,
      },
      accepted_observation_id: null,
      signature_verified: false,
      evidence_available: false,
      verification: null,
      snapshot: null,
      current_vm_count: 0,
      approved_vm_count: 0,
      missing_approved_virtual_machines: [],
      missing_approved_projection_truncated: false,
      virtual_machines: [],
      vm_projection_truncated: false,
      recent_rejections: [],
    }],
    has_more: hasMore,
    next_after_host_id: hasMore ? AWAITING_HOST_ID : null,
  };
}

test('real Infrastructure UI is collection-first, truthful, read-only, and bounded on desktop/mobile',
  { timeout: 120_000 }, async () => {
    const { chromium } = loadLockedPlaywright();
    let stack;
    let browser;
    let context;
    try {
      stack = await startStack({
        allowedEmails: ['operator@example.test'],
        claims: { email: 'operator@example.test', name: 'Fixture Operator' },
      });
      const jar = makeJar();
      assert.equal((await login(stack, jar)).status, 200);
      const sessionCookie = jar.get('dc_session');
      assert.ok(sessionCookie);

      browser = await launchChromium(chromium);
      context = await browser.newContext({
        viewport: { width: 1440, height: 900 },
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        timezoneId: 'UTC',
        colorScheme: 'dark',
        reducedMotion: 'reduce',
      });
      await context.addCookies([{
        name: sessionCookie.name,
        value: sessionCookie.value,
        domain: sessionCookie.hostOnly ? sessionCookie.domain : `.${sessionCookie.domain}`,
        path: sessionCookie.path,
        secure: sessionCookie.secure,
        httpOnly: sessionCookie.httpOnly,
        sameSite: 'Lax',
      }]);

      const page = await context.newPage();
      await page.clock.install({ time: new Date('2026-07-29T12:08:00Z') });
      let partial = false;
      let unavailable = false;
      let hasMore = false;
      let empty = false;
      let accessAdmin = true;
      let holdInfrastructure = true;
      let releaseInfrastructure;
      const infrastructureHold = new Promise((resolve) => {
        releaseInfrastructure = resolve;
      });
      const infrastructureMethods = [];
      const infrastructureUrls = [];
      const unexpectedRequests = [];
      await page.route('**/api/**', async (route) => {
        const request = route.request();
        const pathname = new URL(request.url()).pathname;
        let body;
        if (pathname === '/api/infrastructure') {
          infrastructureMethods.push(request.method());
          infrastructureUrls.push(request.url());
          if (holdInfrastructure) await infrastructureHold;
          if (unavailable) {
            await route.fulfill({
              status: 502,
              contentType: 'application/json',
              body: JSON.stringify({ error: 'fixture infrastructure broker unavailable' }),
            });
            return;
          }
          body = infrastructureProjection({ partial, hasMore, empty });
        } else if (request.method() === 'GET' && pathname === '/api/session') {
          body = { ...CANONICAL_SESSION, accessAdmin, lifecycleAvailable: false };
        } else if (request.method() === 'GET' && pathname === '/api/access') {
          body = {
            version: 1,
            users: [{ email: CANONICAL_SESSION.email, owner: true, grants: [] }],
            resources: [],
            invitedCount: 0,
          };
        } else if (request.method() === 'GET' && pathname === '/api/access/requests') {
          body = { version: 1, pendingCount: 0, requests: [] };
        } else if (request.method() === 'GET' && pathname === '/api/overview') {
          body = structuredClone(CANONICAL_OVERVIEW);
        } else if (request.method() === 'GET' && pathname === '/api/metrics/history') {
          body = structuredClone(CANONICAL_METRICS);
        } else if (request.method() === 'GET' && pathname === '/api/prefs') {
          body = structuredClone(CANONICAL_PREFS);
        } else if (request.method() === 'GET' && pathname === '/api/telegram') {
          body = { version: 1, bots: [], projects: [] };
        } else {
          unexpectedRequests.push(`${request.method()} ${pathname}`);
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: '{"error":"unexpected browser fixture request"}',
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'cache-control': 'no-store' },
          body: JSON.stringify(body),
        });
      });

      const origin = `https://${stack.consoleHost}:${stack.httpsPort}`;
      await page.goto(`${origin}/#/servers`, { waitUntil: 'domcontentloaded' });
      const serversInfrastructure = page.getByRole('region', { name: 'Hyper-V infrastructure' });
      await serversInfrastructure.waitFor();
      await serversInfrastructure.getByText('Loading Hyper-V infrastructure…').waitFor();
      assert.equal(
        await page.locator('#servers-infrastructure-body').getAttribute('aria-busy'),
        'true',
      );
      assert.equal(await page.locator('#nav-infrastructure').evaluate((node) => node.hidden), false);

      holdInfrastructure = false;
      releaseInfrastructure();
      const serverPreviewHost = page.locator(
        `[data-servers-infrastructure-host="${HOST_ID}"]`,
      );
      await serverPreviewHost.waitFor();
      assert.equal(
        await page.locator('#servers-infrastructure-body').getAttribute('aria-busy'),
        'false',
      );
      assert.match(await serversInfrastructure.textContent(), /2 enrolled hosts on this page/);
      assert.match(await serversInfrastructure.textContent(), /1 active · 1 disabled/);
      assert.match(await serverPreviewHost.textContent(), /Disabled/);
      assert.match(await serverPreviewHost.textContent(), /Cell and host enrollment disabled/);
      assert.match(await serverPreviewHost.textContent(), /3 current \/ 3 approved VMs/);
      assert.match(
        await serverPreviewHost.textContent(),
        /single host; loss stops the whole laboratory/,
      );
      const serversOrder = await page.evaluate(() => ({
        infrastructureBeforeServers:
          Boolean(document.querySelector('#servers-infrastructure').compareDocumentPosition(
            document.querySelector('#servers-body'),
          ) & Node.DOCUMENT_POSITION_FOLLOWING),
        infrastructureTop: document.querySelector('#servers-infrastructure').getBoundingClientRect().top,
        serversTop: document.querySelector('#servers-body').getBoundingClientRect().top,
      }));
      assert.equal(serversOrder.infrastructureBeforeServers, true);
      assert.ok(serversOrder.infrastructureTop < serversOrder.serversTop);

      await page.evaluate(() => { location.hash = '#/projects'; });
      await page.locator('#sec-projects:not([hidden])').waitFor();
      const readsBeforeStaleReentry = infrastructureMethods.length;
      await page.clock.fastForward(15_001);
      const staleReentryRefresh = page.waitForResponse((response) => (
        new URL(response.url()).pathname === '/api/infrastructure'
        && response.request().method() === 'GET'
      ));
      await page.evaluate(() => { location.hash = '#/servers'; });
      await staleReentryRefresh;
      assert.equal(
        infrastructureMethods.length,
        readsBeforeStaleReentry + 1,
        'route re-entry must refresh an infrastructure page older than one poll interval',
      );
      await serverPreviewHost.waitFor();

      empty = true;
      await page.locator('#servers-infrastructure-refresh').click();
      await serversInfrastructure.getByText(
        'No enrolled Hyper-V hosts are available in this authority.',
      ).waitFor();
      assert.equal(await page.locator('[data-servers-infrastructure-host]').count(), 0);

      empty = false;
      await page.locator('#servers-infrastructure-refresh').click();
      await serverPreviewHost.waitFor();

      unavailable = true;
      await page.locator('#servers-infrastructure-refresh').click();
      await serversInfrastructure.getByText(
        'Hyper-V refresh failed — retained host state remains visible',
      ).waitFor();
      assert.equal(await serverPreviewHost.count(), 1);

      unavailable = false;
      await page.locator('#servers-infrastructure-refresh').click();
      await page.getByRole('link', { name: 'Open infrastructure details' }).click();
      await page.locator('#sec-infrastructure:not([hidden])').waitFor();
      const host = page.locator(`[data-infrastructure-host="${HOST_ID}"]`);
      await host.waitFor();
      const awaitingHost = page.locator(`[data-infrastructure-host="${AWAITING_HOST_ID}"]`);
      await awaitingHost.waitFor();
      assert.equal(await page.locator('#main > section:not([hidden])').count(), 1);
      assert.equal(await page.locator('#sec-infrastructure:not([hidden])').count(), 1);
      assert.match(await host.textContent(), /3 current \/ 3 approved VMs/);
      assert.match(await host.textContent(), /Complete roster report/);
      assert.equal(await host.getAttribute('data-infrastructure-active'), 'false');
      assert.match(await host.textContent(), /Disabled/);
      assert.match(await host.textContent(), /Cell and host enrollment disabled/);
      assert.match(await host.textContent(), /This host is not active for new observations/);
      assert.match(await host.textContent(), /Enrollment activity/);
      assert.match(await host.textContent(), /Complete report is missing centrally approved VMs/);
      assert.match(await host.textContent(), /1 approved VM does not have a current row/);
      assert.match(await host.textContent(), new RegExp(VM_MISSING));
      for (const label of [
        'Last transport-verified contact',
        'Transport contact freshness',
        'Fresh · 2s old',
        'Last observer capture',
        'Observer capture freshness',
        'Stale · 3m 0s old',
        'Last accepted',
        'Accepted signature',
        'Retained signed evidence artifact',
        'Unavailable',
        'single host; loss stops the whole laboratory',
      ]) {
        assert.ok((await host.textContent()).includes(label), label);
      }
      assert.match(await awaitingHost.textContent(), /Never/);

      const forbiddenControls = await page.locator('#sec-infrastructure button').evaluateAll(
        (buttons) => buttons.map((button) => button.textContent.trim()).filter(
          (text) => /^(Start|Stop|Restart|Checkpoint|Console|Delete)$/i.test(text),
        ),
      );
      assert.deepEqual(forbiddenControls, []);
      assert.equal(await host.locator('.infra-vm').count(), 0,
        'collapsed hosts must not construct hidden VM cards');
      assert.equal(await host.locator('.infra-rejections').count(), 0,
        'collapsed hosts must not construct hidden rejection details');
      await host.locator('.infra-host-toggle').click();
      assert.equal(await host.locator('.infra-host-toggle').getAttribute('aria-expanded'), 'true');
      assert.deepEqual(
        await host.locator('.infra-vm').evaluateAll(
          (rows) => rows.map((row) => row.getAttribute('data-vm-guid')),
        ),
        [VM_A, VM_B, VM_UNAPPROVED],
      );
      assert.match(await host.locator('.infra-rejections').textContent(), /invalid_signature/);

      const desktop = await page.evaluate(() => ({
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: document.documentElement.clientWidth,
        headingBottom: document.querySelector('#sec-infrastructure .sec-head').getBoundingClientRect().bottom,
        firstHostTop: document.querySelector('.infra-host').getBoundingClientRect().top,
      }));
      assert.ok(desktop.documentWidth <= desktop.viewportWidth);
      assert.ok(desktop.headingBottom <= desktop.firstHostTop,
        'the enrolled-host collection must immediately follow its compact heading');

      partial = true;
      await page.locator('#infrastructure-refresh').click();
      await page.locator('.infra-badge.partial').waitFor();
      assert.match(await host.textContent(), /Partial VM discovery/);
      assert.match(await host.textContent(), /vm_discovery_incomplete/);
      assert.match(await host.textContent(), /Previously current VM rows are retained/);

      unavailable = true;
      await page.locator('#infrastructure-refresh').click();
      await page.getByText('Refresh failed — retained infrastructure snapshot remains visible').waitFor();
      assert.equal(await page.locator(`[data-infrastructure-host="${HOST_ID}"]`).count(), 1);
      assert.equal(await host.locator('.infra-badge', { hasText: 'offline' }).count(), 0);

      unavailable = false;
      partial = false;
      hasMore = true;
      await page.locator('#infrastructure-refresh').click();
      const nextHosts = page.getByRole('button', { name: 'Next hosts' });
      await nextHosts.waitFor();
      assert.equal(await nextHosts.isEnabled(), true);

      unavailable = true;
      await nextHosts.click();
      await page.getByText('Infrastructure is unavailable').waitFor();
      const previousHosts = page.getByRole('button', { name: 'Previous hosts' });
      assert.equal(await previousHosts.isEnabled(), true);
      assert.ok(
        infrastructureUrls.some((url) => new URL(url).searchParams.get('after') === AWAITING_HOST_ID),
        'the failed next-page request must use the immutable host cursor',
      );

      unavailable = false;
      hasMore = false;
      await previousHosts.click();
      await page.locator(`[data-infrastructure-host="${HOST_ID}"]`).waitFor();

      for (const width of [720, 768, 820]) {
        await page.setViewportSize({ width, height: 844 });
        const tablet = await page.evaluate(() => {
          const toggle = document.querySelector('.infra-host-toggle');
          const badges = [...toggle.querySelectorAll('.infra-badge')];
          return {
            documentWidth: document.documentElement.scrollWidth,
            viewportWidth: document.documentElement.clientWidth,
            toggleOverflow: toggle.scrollWidth - toggle.clientWidth,
            badgeOverflows: badges.map((badge) => badge.scrollWidth - badge.clientWidth),
          };
        });
        assert.ok(tablet.documentWidth <= tablet.viewportWidth,
          `Infrastructure overflowed the ${width}px document`);
        assert.ok(tablet.toggleOverflow <= 1,
          `Infrastructure host toggle overflowed ${width}px by ${tablet.toggleOverflow}px`);
        assert.ok(tablet.badgeOverflows.every((overflow) => overflow <= 1),
          `Infrastructure badges clipped at ${width}px: ${tablet.badgeOverflows.join(', ')}`);
      }

      await page.setViewportSize({ width: 390, height: 844 });
      const mobile = await page.evaluate(() => {
        const viewportWidth = document.documentElement.clientWidth;
        const escaping = [...document.querySelectorAll(
          '#sec-infrastructure .infra-host, #sec-infrastructure .infra-vm, '
          + '#sec-infrastructure button, #sec-infrastructure code',
        )].map((node) => {
          const rect = node.getBoundingClientRect();
          return { tag: node.tagName, left: rect.left, right: rect.right };
        }).filter((rect) => rect.left < -1 || rect.right > viewportWidth + 1);
        return {
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth,
          escaping,
        };
      });
      assert.ok(mobile.documentWidth <= mobile.viewportWidth,
        `Infrastructure overflowed mobile by ${mobile.documentWidth - mobile.viewportWidth}px`);
      assert.deepEqual(mobile.escaping, []);

      await page.evaluate(() => { location.hash = '#/servers'; });
      await page.locator('#sec-servers:not([hidden])').waitFor();
      await serversInfrastructure.waitFor();
      const serversMobile = await page.evaluate(() => {
        const viewportWidth = document.documentElement.clientWidth;
        const escaping = [...document.querySelectorAll(
          '#servers-infrastructure, #servers-infrastructure button, '
          + '#servers-infrastructure a, #servers-infrastructure code',
        )].map((node) => {
          const rect = node.getBoundingClientRect();
          return {
            tag: node.tagName,
            text: node.textContent.trim(),
            left: rect.left,
            right: rect.right,
          };
        }).filter((rect) => rect.left < -1 || rect.right > viewportWidth + 1);
        const panel = document.querySelector('#servers-infrastructure');
        const body = document.querySelector('#servers-infrastructure-body');
        return {
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth,
          escaping,
          labelledBy: panel.getAttribute('aria-labelledby'),
          live: body.getAttribute('aria-live'),
          busy: body.getAttribute('aria-busy'),
        };
      });
      assert.ok(serversMobile.documentWidth <= serversMobile.viewportWidth,
        `Servers Hyper-V block overflowed mobile by ${
          serversMobile.documentWidth - serversMobile.viewportWidth
        }px`);
      assert.deepEqual(serversMobile.escaping, []);
      assert.equal(serversMobile.labelledBy, 'servers-infrastructure-h');
      assert.equal(serversMobile.live, 'polite');
      assert.equal(serversMobile.busy, 'false');
      await page.locator('#servers-infrastructure-refresh').focus();
      assert.equal(
        await page.locator('#servers-infrastructure-refresh').evaluate(
          (node) => node === document.activeElement,
        ),
        true,
      );
      assert.equal(
        await page.locator('#servers-infrastructure-refresh').getAttribute('type'),
        'button',
      );

      const ownerInfrastructureReads = infrastructureMethods.length;
      accessAdmin = false;
      await page.reload({ waitUntil: 'networkidle' });
      assert.equal(
        await page.locator('#nav-infrastructure').evaluate((node) => node.hidden),
        true,
      );
      assert.equal(
        await page.locator('#servers-infrastructure').evaluate((node) => node.hidden),
        true,
      );
      assert.equal(infrastructureMethods.length, ownerInfrastructureReads,
        'a Console non-owner must not issue an infrastructure read');
      await page.evaluate(() => { location.hash = '#/infrastructure'; });
      await page.locator('#sec-projects:not([hidden])').waitFor();
      assert.equal(await page.locator('#sec-infrastructure:not([hidden])').count(), 0);
      assert.equal(infrastructureMethods.length, ownerInfrastructureReads,
        'direct non-owner hash navigation must not reveal or fetch infrastructure');

      assert.ok(infrastructureMethods.length >= 3);
      assert.ok(infrastructureMethods.every((method) => method === 'GET'));
      assert.deepEqual(unexpectedRequests, []);
    } finally {
      await context?.close();
      await browser?.close();
      await stack?.close();
    }
  });
