import assert from 'node:assert/strict';
import { promises as fsp } from 'node:fs';
import test from 'node:test';

const UI = new URL('../src/ui/', import.meta.url);

test('owner Infrastructure is read-only and also leads the existing Servers destination', async () => {
  const [html, js, css] = await Promise.all([
    fsp.readFile(new URL('index.html', UI), 'utf8'),
    fsp.readFile(new URL('app.js', UI), 'utf8'),
    fsp.readFile(new URL('app.css', UI), 'utf8'),
  ]);
  assert.match(
    html,
    /href="#\/infrastructure" data-nav="infrastructure" id="nav-infrastructure" hidden>Infrastructure/,
  );
  assert.match(html, /data-page="infrastructure"/);
  const section = html.match(
    /<section id="sec-infrastructure"[\s\S]*?<\/section>/,
  )?.[0];
  assert.ok(section, 'the Infrastructure section must be present');
  assert.ok(
    section.indexOf('id="infrastructure-h"') < section.indexOf('id="infrastructure-body"'),
    'the collection heading must precede its real rows/loading/error/empty state',
  );
  assert.doesNotMatch(
    section,
    />\s*(Start|Stop|Restart|Checkpoint|Console|Delete)\s*</i,
    'remote lifecycle controls must not exist in the page source',
  );
  assert.match(section, /id="infrastructure-refresh"[^>]*>Refresh<\/button>/);
  assert.match(section, /id="infrastructure-body"[^>]*aria-live="polite"[^>]*aria-busy="true"/);

  const servers = html.match(
    /<section id="sec-servers"[\s\S]*?<section id="sec-routes"/,
  )?.[0];
  assert.ok(servers, 'the Servers section must be present');
  assert.ok(
    servers.indexOf('id="servers-infrastructure"')
      < servers.indexOf('id="servers-body"'),
    'real Hyper-V infrastructure must precede the Coordinator server collection',
  );
  assert.match(servers, /id="servers-infrastructure"[^>]*hidden/);
  assert.match(servers, /Hyper-V infrastructure/);
  assert.match(servers, /href="#\/infrastructure">Open infrastructure details/);
  assert.match(servers, /Loading Hyper-V infrastructure…/);
  assert.match(
    servers,
    /id="servers-infrastructure-body"[^>]*aria-live="polite"[^>]*aria-busy="true"/,
  );

  for (const truthfulLabel of [
    'Last transport-verified contact',
    'Transport contact freshness',
    'Last observer capture',
    'Observer capture freshness',
    'Last accepted',
    'Acceptance freshness',
    'Fresh ·',
    'Stale ·',
    'Never',
    'Accepted signature',
    'Retained signed evidence artifact',
    'current /',
    'approved VMs',
    'Complete report is missing centrally approved VMs',
    'Partial VM discovery',
    'Failure domain',
    'Enrollment activity',
    'Host enrollment disabled',
    'Cell and host enrollment disabled',
    'This host is not active for new observations',
    'No enrolled Hyper-V hosts are available in this authority.',
    'Loading Hyper-V infrastructure…',
    'Hyper-V infrastructure is unavailable',
  ]) {
    assert.ok(js.includes(truthfulLabel), truthfulLabel);
  }
  assert.match(js, /id === 'access' \|\| id === 'invites' \|\| id === 'infrastructure'/);
  assert.match(js, /\['infrastructure', 'servers'\]\.includes\(currentPage\(\)\)/);
  assert.match(js, /\$\('#nav-infrastructure'\)\.hidden = !admin/);
  assert.match(js, /\$\('#servers-infrastructure'\)\.hidden = !admin/);
  assert.match(js, /state\.session\?\.accessAdmin !== true[\s\S]*loadInfrastructure/);
  assert.match(js, /Refresh failed — retained infrastructure snapshot remains visible/);
  assert.match(js, /not being relabelled offline/);
  assert.match(js, /!state\.infrastructure && state\.infrastructureHistory\.length[\s\S]*Previous hosts/);
  assert.match(js, /cachedAgeMs[\s\S]*cachedPageIsFresh[\s\S]*INFRASTRUCTURE_POLL_MS/);
  assert.match(js, /missingCountText[\s\S]*At least \$\{missingCount\} approved VM/);
  assert.match(js, /hidden: !expanded[\s\S]*expanded[\s\S]*host\.virtual_machines\.map/);
  assert.match(js, /data-vm-guid/);
  assert.match(css, /@media \(min-width: 720px\) and \(max-width: 899px\)[\s\S]*\.infra-host-toggle/);
  assert.match(css, /@media \(max-width: 719px\)[\s\S]*\.infra-host-toggle/);
  assert.match(css, /@media \(max-width: 719px\)[\s\S]*\.servers-infrastructure-host/);
  assert.match(css, /\.servers-infrastructure-host[\s\S]*grid-template-columns/);
  assert.match(css, /\.infra-guid[\s\S]*overflow-wrap: anywhere/);
});
