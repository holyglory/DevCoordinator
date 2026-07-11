# DevOps Console

Web control center for the `vr.ae` VPS. A single Node 20 process (zero
third-party dependencies) that:

- terminates TLS for `*.vr.ae` on 443 (wildcard cert, hot-reloaded) and
  redirects 80 → 443,
- reverse-proxies `https://<slug>.vr.ae` → `http://127.0.0.1:<port>` including
  WebSockets (Vite/webpack HMR works through it),
- gates every subdomain behind **Google sign-in by default**, with a per-route
  *public / login-required* toggle in the control panel,
- serves the control panel at `https://console.vr.ae` — hash-routed pages
  (Projects, Servers, Routes, Docker, Port leases, Performance; tab nav on
  desktop, a hamburger drawer on phones). The default Projects page is a tree
  of repos with their servers, databases and containers: start/stop/restart
  single items or whole projects, live CPU/memory everywhere, and hideable
  idle items that automatically reappear when an agent starts them through
  the coordinator. Other pages cover servers with per-server subdomains
  (grouped by repo), routes, Docker containers, port leases + permanent pins,
  and history charts, all driven by the
  [codex-dev-coordinator](../../skills/codex-dev-coordinator/SKILL.md) HTTP API
  on loopback `127.0.0.1:29876`, authenticated with a private token. Production
  runs it as the dedicated `dev-coordinator.service`; optional local autostart
  remains available. The
  console samples coordinator inventory (default every 10s,
  `METRICS_INTERVAL_MS`) into in-memory ring buffers; every running server and
  container row shows CPU %/memory numbers plus a sparkline, and the
  Performance page renders full history charts (history resets when the
  console restarts).

Production binds ports 80/443 on the explicit IPv4 wildcard `0.0.0.0` and
uses `127.0.0.1` for coordinator registration and health. This deployment has
IPv4 DNS records; the explicit bind avoids Node's platform-dependent omitted-
host IPv6 dual-stack behavior and keeps listener ownership verifiable.

Architecture and module contracts: [docs/architecture.md](docs/architecture.md).
Coordinator HTTP API map: [docs/coordinator-http-api.json](docs/coordinator-http-api.json).
User journeys: [docs/journeys.md](docs/journeys.md).

## Quick start

```bash
cd apps/DevOpsConsole
install -d -m 700 "$HOME/.config/devops-console" "$HOME/.local/state/devops-console"
if [ ! -e "$HOME/.config/devops-console/console.env" ]; then
  install -m 600 .env.example "$HOME/.config/devops-console/console.env"
fi
# Fill in the external file, then:
node bin/devops-console.mjs --env-file "$HOME/.config/devops-console/console.env" --check-config
node bin/devops-console.mjs --env-file "$HOME/.config/devops-console/console.env"
```

Run the tests (spawns an isolated coordinator + local OIDC issuer; no network,
no fixed ports):

```bash
node --test test/*.test.mjs
```

## Configuration (`console.env`)

See [.env.example](.env.example) for the full annotated list. The important
ones:

| Key | Meaning |
|---|---|
| `DOMAIN` | Base domain (`vr.ae`). Console at `console.<DOMAIN>`, routes at `<slug>.<DOMAIN>`. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Wildcard cert + key PEMs. Watched and hot-reloaded; `systemctl reload devops-console` (SIGHUP) forces it. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth client (setup below). Empty = degraded mode: public routes still proxy, everything auth-gated shows a setup page. |
| `ALLOWED_EMAILS` | Comma-separated Google accounts allowed to sign in. Everyone else gets a 403 after Google auth. |
| `SESSION_SECRET` | 64 hex chars (`openssl rand -hex 32`). Rotating it signs everyone out. |
| `COORDINATOR_URL` | Coordinator API origin, default `http://127.0.0.1:29876`; only loopback `http(s)` origins without credentials, paths, queries, or fragments are accepted. |
| `COORDINATOR_TOKEN_FILE` | Private mode-0600 bearer token created by the coordinator and read only by the server-side Console client. |
| `COORDINATOR_AUTOSTART` | Optional local fallback; production sets `0` and uses `dev-coordinator.service`. |
| `COORDINATOR_REGISTRATION_REQUIRED` | Production-only fail-closed gate. The unit pins `1`; direct/local runs omit it and log a bounded registration failure without exiting. |
| `METRICS_INTERVAL_MS` | CPU/memory sampling cadence for the history charts (default `10000`, floor `2000`). Each sample reads coordinator inventory, which shells out to `docker stats` when Docker is present. |

## Google OAuth client setup (one-time)

1. Google Cloud Console → *APIs & Services* → *OAuth consent screen*:
   external, app name "DevOps Console", your email; publish.
2. *Credentials* → *Create credentials* → *OAuth client ID* → type **Web
   application**:
   - Authorized JavaScript origin: `https://console.vr.ae`
   - Authorized redirect URI: `https://console.vr.ae/auth/callback`
3. Put the client ID/secret in
   `$HOME/.config/devops-console/console.env`, then run
   `systemctl restart devops-console`.

The login page shows these exact values in degraded mode, so you can copy them
from there too.

## TLS certificate runbook (Let's Encrypt DNS-01, out-of-band)

The app never speaks ACME; it reads the PEM paths from
`$HOME/.config/devops-console/console.env` and hot-reloads
them when the files change. `certs/dev/` is gitignored — the test suite
generates a throwaway self-signed `*.vr.ae` cert there on demand
(`test/helpers/dev-cert.mjs`), and the same generated pair can serve as a
first-boot fallback until real certificates are issued.

### Console + apex cert (HTTP-01, automated — currently live)

The app answers ACME HTTP-01 challenges itself: the plain-HTTP :80 listener
serves `/.well-known/acme-challenge/<token>` from `ACME_WEBROOT`
(default `<STATE_DIR>/acme`) **before** the https redirect, so `certbot`
issues and renews certs while the app keeps port 80. This covers named hosts
(`console.vr.ae`, `vr.ae`) but **not** a wildcard — Let's Encrypt only issues
`*.vr.ae` via DNS-01 (below).

```bash
sudo apt-get install -y certbot
sudo certbot certonly --webroot -w "$HOME/.local/state/devops-console/acme" \
  -d console.vr.ae -d vr.ae \
  --non-interactive --agree-tos -m ja@vr.ae --cert-name vr.ae
sudo setfacl -R -m u:holyglory:rX /etc/letsencrypt/live/vr.ae /etc/letsencrypt/archive/vr.ae
# point $HOME/.config/devops-console/console.env at the issued files, then
# RESTART (a path change needs a restart;
# SIGHUP/reload only re-reads the already-configured path):
#   TLS_CERT_FILE=/etc/letsencrypt/live/vr.ae/fullchain.pem
#   TLS_KEY_FILE=/etc/letsencrypt/live/vr.ae/privkey.pem
sudo systemctl restart devops-console
```

Renewal is automatic (certbot's timer); a deploy hook reloads the app so it
picks up the renewed cert without dropping connections:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/devops-console <<'EOF'
#!/bin/sh
systemctl reload devops-console 2>/dev/null || systemctl restart devops-console
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/devops-console
```

### Wildcard cert for proxied subdomains (DNS-01 — currently live)

Proxied `<slug>.vr.ae` hosts are covered by the `*.vr.ae` wildcard. Let's
Encrypt issues wildcards **only** via DNS-01 — a `_acme-challenge.vr.ae` TXT
record at the authoritative DNS (`vr.ae` is hosted at 101domain, which has no
API credential on this box, so the record is published by hand). The live cert
`/etc/letsencrypt/live/vr.ae/{fullchain,privkey}.pem` covers `vr.ae` +
`*.vr.ae`; the external `console.env` points at it and the Console serves it
for every host.

**Renewal is fully automated via the 101domain REST API** — no manual TXT
steps. certbot's `manual_auth_hook`/`manual_cleanup_hook` create and delete the
`_acme-challenge.vr.ae` TXT record through the API and wait for propagation at
the authoritative nameservers; the certbot systemd timer renews unattended
within 30 days of expiry and the deploy hook reloads the console. Proven with a
real production `certbot renew --force-renewal` (new serial issued, records
auto-cleaned, service reloaded, all hosts still trusted).

Setup (already done on this host; repeat if rebuilding):

```bash
# 1. Store the 101domain API key, root-only, OUTSIDE the repo:
sudo install -d -m 700 /etc/letsencrypt/101domain
printf 'DOMAIN101_API_KEY=%s\n' "<key>" | sudo tee /etc/letsencrypt/101domain/credentials.env >/dev/null
sudo chmod 600 /etc/letsencrypt/101domain/credentials.env
# 2. Install the hooks (versioned in deploy/101domain/, hold no secret):
sudo install -m 700 deploy/101domain/auth-hook.sh deploy/101domain/cleanup-hook.sh /etc/letsencrypt/101domain/
# 3. Wire them into /etc/letsencrypt/renewal/vr.ae.conf under [renewalparams]:
#   manual_auth_hook = /etc/letsencrypt/101domain/auth-hook.sh
#   manual_cleanup_hook = /etc/letsencrypt/101domain/cleanup-hook.sh
# 4. Verify unattended:
sudo certbot renew --cert-name vr.ae --dry-run
```

The API key lives only in the root-only credentials file — never in the repo,
which is public. The hooks read it from there.

Fallback (if the API is ever unavailable), a guided manual helper prints the
exact TXT to add, verifies propagation, issues, and reloads:
`sudo bash deploy/renew-wildcard.sh`.

Cert files are root-owned; the service user reads them via a default ACL
(`sudo setfacl -R -d -m u:holyglory:rX /etc/letsencrypt/{live,archive}`) so
renewed files stay readable. A renewal deploy hook
(`/etc/letsencrypt/renewal-hooks/deploy/devops-console`) reloads the service
(SIGHUP) after any renewal. Note: changing the cert **path** in the external
`console.env` needs a full restart; a same-path renewal only needs a reload.

## Deploy (systemd)

Production source lives at `/home/DevCoordinator`; mutable data and secrets do
not. Never copy `.env.example` over an existing production environment. Before
changing units or processes, capture coordinator inventory and make a private,
checksummed rollback copy:

On an existing host the first migration phase is deliberately `--env-only`:
it preserves secrets and rewrites external path keys without reading the live
legacy state/log tree. The exact, checksum-verified state sync runs only after
the legacy cgroup and listeners are stopped.

```bash
DEVCOORDINATOR_ROOT=/home/DevCoordinator
set -euo pipefail
test "$(id -un)" = holyglory
test "$HOME" = /home/holyglory
test "$(getent passwd holyglory | cut -d: -f6)" = /home/holyglory
LEGACY_ROOT="$HOME/holyskills"
LEGACY_ENV="$LEGACY_ROOT/apps/DevOpsConsole/.env"
LEGACY_STATE="$LEGACY_ROOT/apps/DevOpsConsole/state"
CONSOLE_ENV="$HOME/.config/devops-console/console.env"
CONSOLE_STATE="$HOME/.local/state/devops-console"
COORDINATOR_HOME="$HOME/.codex/agent-coordinator"
ACME_WEBROOT="$CONSOLE_STATE/acme"
BACKUP_ROOT="$HOME/.local/state/devcoordinator-cutover-backups"
CUTOVER_BACKUP="$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ)"

umask 077
install -d -m 700 \
  "$HOME/.config/devops-console" "$CONSOLE_STATE" "$ACME_WEBROOT" \
  "$COORDINATOR_HOME" "$BACKUP_ROOT" "$CUTOVER_BACKUP"
if [ ! -e "$CONSOLE_ENV" ]; then
  if [ -f "$LEGACY_ENV" ]; then
    python3 "$DEVCOORDINATOR_ROOT/scripts/migrate_legacy_console_runtime.py" \
      --legacy-env "$LEGACY_ENV" --legacy-state "$LEGACY_STATE" \
      --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
      --coordinator-home "$COORDINATOR_HOME" \
      --devcoordinator-root "$DEVCOORDINATOR_ROOT" \
      --backup-dir "$CUTOVER_BACKUP/legacy-migration-initial" --env-only
  else
    install -m 600 "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/.env.example" "$CONSOLE_ENV"
  fi
fi
chmod 600 "$CONSOLE_ENV"
find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type d -exec chmod 700 {} +
find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type f -exec chmod 600 {} +

cp -a "$CONSOLE_ENV" "$CUTOVER_BACKUP/console.env"
sha256sum "$CONSOLE_ENV" > "$CUTOVER_BACKUP/console.env.sha256"
cp -a "$CONSOLE_STATE" "$CUTOVER_BACKUP/devops-console-state"
cp -a "$COORDINATOR_HOME" "$CUTOVER_BACKUP/agent-coordinator"
if [ -d "$LEGACY_STATE" ]; then
  cp -a "$LEGACY_STATE" "$CUTOVER_BACKUP/legacy-console-state.initial"
fi
for unit in dev-coordinator.service devops-console.service; do
  if [ -f "/etc/systemd/system/$unit" ]; then
    cp -a "/etc/systemd/system/$unit" "$CUTOVER_BACKUP/$unit.previous"
    printf 'present\n' > "$CUTOVER_BACKUP/$unit.preexisting"
  else
    printf 'absent\n' > "$CUTOVER_BACKUP/$unit.preexisting"
  fi
  systemctl is-enabled "$unit" > "$CUTOVER_BACKUP/$unit.enabled" 2>&1 || true
done
MANIFEST_TMP="$(mktemp "$CUTOVER_BACKUP/.SHA256SUMS.XXXXXX")"
cleanup_manifest_tmp() { rm -f "$MANIFEST_TMP"; }
trap cleanup_manifest_tmp EXIT
(cd "$CUTOVER_BACKUP" && find . -type f ! -name SHA256SUMS \
  ! -name '.SHA256SUMS.*' -print0 | LC_ALL=C sort -z | \
  xargs -0 -r sha256sum > "$MANIFEST_TMP")
(cd "$CUTOVER_BACKUP" && sha256sum --check "$MANIFEST_TMP" >/dev/null)
chmod 600 "$MANIFEST_TMP"
mv -f "$MANIFEST_TMP" "$CUTOVER_BACKUP/SHA256SUMS"
trap - EXIT
(cd "$CUTOVER_BACKUP" && sha256sum --check SHA256SUMS >/dev/null)
chmod -R go-rwx "$CUTOVER_BACKUP"
```

Validate the external layout before starting either service, then verify both
candidate units. `systemd-analyze verify` is a syntax gate; after installation,
also inspect systemd's resolved path properties because syntax validation does
not prove which account home a specifier selects. Do not install/reload them over a running legacy service; the
existing-host sequence below installs them only after the old cgroup is down.
The first preflight intentionally does not require the API token because the
coordinator creates it on first start.

```bash
set -euo pipefail
python3 "$DEVCOORDINATOR_ROOT/scripts/check_production_layout.py" \
  --repo-root "$DEVCOORDINATOR_ROOT" --home "$HOME" \
  --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
  --acme-webroot "$ACME_WEBROOT" --coordinator-home "$COORDINATOR_HOME" \
  --token-file "$COORDINATOR_HOME/api-token"

sudo systemd-analyze verify \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/dev-coordinator.service" \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/devops-console.service"
```

For a fresh host, start only the coordinator, rerun the token-required
preflight, verify the anonymous/authenticated API boundary, and then start the
Console:

```bash
set -euo pipefail
umask 077
sudo install -m 0644 \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/dev-coordinator.service" \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/devops-console.service" \
  /etc/systemd/system/
sudo systemctl daemon-reload
python3 "$DEVCOORDINATOR_ROOT/scripts/check_loaded_systemd_paths.py" \
  --evidence "$CUTOVER_BACKUP/resolved-unit-paths.json"
sudo systemctl enable dev-coordinator.service devops-console.service
sudo systemctl start dev-coordinator.service
python3 "$DEVCOORDINATOR_ROOT/scripts/check_production_layout.py" \
  --repo-root "$DEVCOORDINATOR_ROOT" --home "$HOME" \
  --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
  --acme-webroot "$ACME_WEBROOT" --coordinator-home "$COORDINATOR_HOME" \
  --token-file "$COORDINATOR_HOME/api-token" --require-token --wait-token-seconds 10

python3 "$DEVCOORDINATOR_ROOT/scripts/check_coordinator_auth_boundary.py" \
  --token-file "$COORDINATOR_HOME/api-token" --host 127.0.0.1 --port 29876

sudo systemctl start devops-console.service
systemctl status dev-coordinator.service devops-console.service
```

`dev-coordinator.service` does not finish starting merely because its Python
process exists. Its pinned `ExecStartPost` probe waits for the loopback API and
requires the complete anonymous/authenticated `200/401/200` contract within the
unit's bounded start timeout. The explicit probe above records the same
contract at the deployment boundary.

### Existing-host checkout cutover

The deployed legacy topology has one `devops-console.service`; its Node process
autostarts the coordinator as a detached child in the same systemd cgroup.
There is no old `dev-coordinator.service` to restart. Before stopping anything,
capture the Console main PID, cgroup, exact child coordinator PID/start time/
command, listener evidence, exact lease ID, and exact Console server ID.

For every real attempt, create a new timestamped private backup path and
assemble these phases into one `0600` script inside that fresh backup. Never
reuse or amend a prior attempt's path. Run `bash -n` on those exact bytes, hash
the script into the verified backup manifest, and execute that same hash via
`/bin/bash "$CUTOVER_BACKUP/cutover.sh" "$CUTOVER_BACKUP"`; the private
artifact is intentionally readable only by its owner, not executable.
Retain the backup, script, ledgers, and manifest after success or failure; a
retry starts with another fresh path. The transaction handler
must cover `ERR`, `INT`, `TERM`, `HUP`, and incomplete `EXIT`: before the stop
marker it removes the runtime override, reloads systemd, proves the old unit and
public TLS are healthy, and after the marker it runs phase-aware rollback. Run
rollback itself with strict fail-fast semantics, require all captured writers
and listeners to be gone before restoring state, and verify the restored exact
Node/old-coordinator cgroup and listener topology. Remove any success marker on
failure; create it only after a complete manifest verification, then bind that
marker with one final verified manifest refresh.

Shell syntax is not helper-interface validation. Before the script may touch a
service, use a throwaway private directory to run the exact deployed
`write_cutover_phase_marker.py` CLI for every phase the transaction uses:
`cutover-run-started`, `service-stop-attempted`,
`state-migration-attempted`, `relocation-attempted`, and `cutover-success`.
Likewise run `--help` or a no-mutation fixture for every other repo helper's
exact subcommand and required flags. A candidate whose helper CLI matrix has
not passed against the pinned commit is not executable cutover evidence.

```bash
set -euo pipefail
OLD_PROJECT="$LEGACY_ROOT"
OLD_COORDINATOR="$OLD_PROJECT/skills/codex-dev-coordinator/scripts/dev_coordinator.py"
umask 077
python3 "$OLD_COORDINATOR" inventory --project "$OLD_PROJECT" --no-docker \
  > "$CUTOVER_BACKUP/pre-cutover-inventory.json"
python3 - "$CUTOVER_BACKUP/pre-cutover-inventory.json" "$OLD_PROJECT" \
  "$CUTOVER_BACKUP/pre-cutover-identities.json" <<'PY'
import json, sys
inventory = json.load(open(sys.argv[1], encoding="utf-8"))
leases = [
    item for item in inventory.get("leases", [])
    if item.get("status") == "active"
    and item.get("project") == sys.argv[2]
    and int(item.get("port") or 0) == 443
    and item.get("purpose") == "server:devops-console"
]
servers = [
    item for item in inventory.get("servers", [])
    if item.get("project") == sys.argv[2]
    and item.get("name") == "devops-console"
    and int(item.get("port") or 0) == 443
]
if len(leases) != 1 or len(servers) != 1:
    raise SystemExit(f"expected one exact lease/server, found {len(leases)}/{len(servers)}")
with open(sys.argv[3], "x", encoding="utf-8") as handle:
    json.dump({"lease_id": leases[0]["id"], "server_id": servers[0]["id"]}, handle)
    handle.write("\n")
PY
chmod 600 "$CUTOVER_BACKUP/pre-cutover-identities.json"

OLD_CONSOLE_PID="$(systemctl show --property MainPID --value devops-console.service)"
OLD_CONSOLE_CGROUP="$(systemctl show --property ControlGroup --value devops-console.service)"
test "$OLD_CONSOLE_PID" -gt 1
test -n "$OLD_CONSOLE_CGROUP"
python3 - "$OLD_CONSOLE_PID" "$OLD_CONSOLE_CGROUP" "$OLD_COORDINATOR" \
  "$CUTOVER_BACKUP/legacy-processes.json" <<'PY'
import json, os, sys
from pathlib import Path

console_pid, cgroup, expected_script, output = int(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4])
members = Path("/sys/fs/cgroup", cgroup.lstrip("/"), "cgroup.procs")
if not members.is_file():
    raise SystemExit(f"legacy cgroup process list is unavailable: {members}")
records = []
for raw in members.read_text(encoding="utf-8").splitlines():
    pid = int(raw)
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        command = [part.decode("utf-8", errors="replace") for part in command if part]
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        opening = stat_text.find("(")
        closing = stat_text.rfind(")")
        after_comm = stat_text[closing + 1:].split() if opening > 0 and closing > opening else []
        if len(after_comm) < 20 or not after_comm[19].isdigit():
            raise ValueError(f"invalid /proc stat for PID {pid}")
        start_ticks = after_comm[19]
    except (FileNotFoundError, ProcessLookupError):
        continue
    records.append({"pid": pid, "start_ticks": start_ticks, "command": command})
consoles = [item for item in records if item["pid"] == console_pid]
if len(consoles) != 1:
    raise SystemExit("systemd Console MainPID is not in its reported cgroup")
coordinators = [
    item for item in records
    if expected_script in item["command"] and "api" in item["command"] and "serve" in item["command"]
]
if len(coordinators) != 1:
    raise SystemExit(f"expected one legacy child coordinator, found {len(coordinators)}")
if len(records) != 2:
    raise SystemExit(
        "legacy Console cgroup contains additional managed processes; "
        "classify/move those attributed process trees before cutover"
    )
with output.open("x", encoding="utf-8") as handle:
    json.dump({
        "console": consoles[0],
        "cgroup": cgroup,
        "coordinator": coordinators[0],
    }, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.chmod(output, 0o600)
PY
sudo ss -ltnp '( sport = :80 or sport = :443 or sport = :29876 )' \
  > "$CUTOVER_BACKUP/pre-cutover-listeners.txt"
chmod 600 "$CUTOVER_BACKUP/pre-cutover-listeners.txt"
```

Immediately before applying the runtime override, require one five-second
observed-clean legacy cgroup window. The verifier uses bounded user-space
polling every 20 ms; this is not a kernel-continuous monitor and cannot prove
the absence of a process that starts and exits entirely between observations.
It writes a private independently checksummed JSON ledger for every observed
membership/identity transition and one-second checkpoint, and resets the
candidate window whenever an extra child appears or an observation is delayed
beyond its bound. Extra children are attributed evidence, never allowlisted. A
membership pass is followed by stable identity reads, a confirming membership
pass, and confirmed identity rereads, so PID reuse between those reads fails
unsafe. A missing/reused captured process fails immediately; a workload that never
supplies the full clean window fails at the bounded timeout. This distinguishes
a true inter-cycle quiet window from shorter observed gaps inside the Console's
normal inventory burst without relying on lucky point samples.
Only a terminal successful ledger counts as proof. `SIGKILL`, host power loss,
or storage loss can leave the ledger `running` or otherwise incomplete; such a
ledger must never be accepted as success.
Refresh the backup manifest after adding the later process, listener, identity,
and clean-window evidence.

```bash
set -euo pipefail
python3 "$DEVCOORDINATOR_ROOT/scripts/verify_legacy_cutover_boundary.py" \
  --evidence "$CUTOVER_BACKUP/legacy-processes.json" \
  --ledger "$CUTOVER_BACKUP/cgroup-samples.stable.json" \
  --continuous-clean-seconds 5 \
  --wait-timeout-seconds 30 --poll-interval-seconds 0.02 \
  --max-observation-gap-seconds 0.1

MANIFEST_TMP="$(mktemp "$CUTOVER_BACKUP/.SHA256SUMS.XXXXXX")"
cleanup_manifest_tmp() { rm -f "$MANIFEST_TMP"; }
trap cleanup_manifest_tmp EXIT
(cd "$CUTOVER_BACKUP" && find . -type f ! -name SHA256SUMS \
  ! -name '.SHA256SUMS.*' -print0 | LC_ALL=C sort -z | \
  xargs -0 -r sha256sum > "$MANIFEST_TMP")
(cd "$CUTOVER_BACKUP" && sha256sum --check "$MANIFEST_TMP" >/dev/null)
chmod 600 "$MANIFEST_TMP"
mv -f "$MANIFEST_TMP" "$CUTOVER_BACKUP/SHA256SUMS"
trap - EXIT
(cd "$CUTOVER_BACKUP" && sha256sum --check SHA256SUMS >/dev/null)
```

Before stopping the legacy unit, apply a runtime-only `KillMode=process`
override and verify it loaded. This prevents an agent-created process appearing
after the cgroup snapshot from being silently killed. Stop terminates only the
Console main process; the guarded cleanup sends TERM (then bounded KILL) only
when the captured coordinator PID still has the captured start time and exact
command. After the override reload, the verifier requires a five-second
observed-clean window and returns at its end, binding a second
checksummed ledger as closely as possible to the actual stop boundary. The
verifier return and `systemctl stop` remain two distinct operations, so bounded
polling cannot eliminate that residual interval. `KillMode=process` prevents a
new child in that interval from being implicitly killed with the Console, and
the immediate post-stop exact identity/cgroup/listener verifier rejects any
unexpected survivor before state is copied. Together those checks make the
residual race fail closed rather than pretending it does not exist.
The following check requires both exact process instances, all three
listeners, and the old cgroup to be empty. Any extra survivor is a hard blocker:
move its attributed process tree to a dedicated scope or stop/restart it
explicitly with health evidence before reusing the unit name. Then remove the
runtime override and perform the final staged state sync.

From the successful stop boundary until relocation completes, this is an
operator-exclusive coordinator mutation window. Do not run another coordinator
API or CLI against `COORDINATOR_HOME`; a same-user process outside the stopped
service cgroup is not covered by the process gate. If that exclusivity cannot
be guaranteed, abort and restore the legacy unit before continuing.

```bash
set -euo pipefail
OVERRIDE_ACTIVE=0
cleanup_cutover_override() {
  exit_status="$?"
  if [ "$OVERRIDE_ACTIVE" -eq 1 ]; then
    set +e
    sudo rm -f /run/systemd/system/devops-console.service.d/90-cutover-killmode.conf
    sudo systemctl daemon-reload
  fi
  exit "$exit_status"
}
trap cleanup_cutover_override EXIT
sudo install -d -m 0755 /run/systemd/system/devops-console.service.d
OVERRIDE_ACTIVE=1
printf '[Service]\nKillMode=process\n' | \
  sudo tee /run/systemd/system/devops-console.service.d/90-cutover-killmode.conf >/dev/null
sudo systemctl daemon-reload
test "$(systemctl show --property KillMode --value devops-console.service)" = process
python3 "$DEVCOORDINATOR_ROOT/scripts/verify_legacy_cutover_boundary.py" \
  --evidence "$CUTOVER_BACKUP/legacy-processes.json" \
  --ledger "$CUTOVER_BACKUP/cgroup-samples.prestop-final.json" \
  --continuous-clean-seconds 5 \
  --wait-timeout-seconds 30 --poll-interval-seconds 0.01 \
  --max-observation-gap-seconds 0.1
sudo systemctl stop devops-console.service
python3 "$DEVCOORDINATOR_ROOT/scripts/terminate_captured_legacy_process.py" \
  --evidence "$CUTOVER_BACKUP/legacy-processes.json" --role coordinator \
  --timeout-seconds 5
python3 "$DEVCOORDINATOR_ROOT/scripts/check_legacy_cutover_stopped.py" \
  --evidence "$CUTOVER_BACKUP/legacy-processes.json" --ports 80 443 29876

install -d -m 700 "$CUTOVER_BACKUP/user-runtime.writer-free"
for name in routes.json ui-prefs.json; do
  test -f "$LEGACY_STATE/$name"
  install -m 600 "$LEGACY_STATE/$name" \
    "$CUTOVER_BACKUP/user-runtime.writer-free/$name"
done
sha256sum "$CUTOVER_BACKUP/user-runtime.writer-free/routes.json" \
  "$CUTOVER_BACKUP/user-runtime.writer-free/ui-prefs.json" \
  > "$CUTOVER_BACKUP/user-runtime.writer-free.sha256"

# This is the first lossless state checkpoint: every captured legacy writer
# and listener has been proved stopped, so the state cannot change underneath
# the copy.
install -m 600 "$COORDINATOR_HOME/state.json" \
  "$CUTOVER_BACKUP/coordinator-state.poststop.json"
sha256sum "$CUTOVER_BACKUP/coordinator-state.poststop.json" \
  > "$CUTOVER_BACKUP/coordinator-state.poststop.sha256"
sha256sum --check "$CUTOVER_BACKUP/coordinator-state.poststop.sha256"
sync -f "$CUTOVER_BACKUP"
sudo rm -f /run/systemd/system/devops-console.service.d/90-cutover-killmode.conf
sudo systemctl daemon-reload
OVERRIDE_ACTIVE=0
trap - EXIT

# The legacy processes may have rewritten external state after the initial
# preparation. Normalize and validate only after every legacy writer is gone.
find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type d -exec chmod 700 {} +
find "$CONSOLE_STATE" "$COORDINATOR_HOME" -type f -exec chmod 600 {} +
python3 "$DEVCOORDINATOR_ROOT/scripts/check_production_layout.py" \
  --repo-root "$DEVCOORDINATOR_ROOT" --home "$HOME" \
  --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
  --acme-webroot "$ACME_WEBROOT" --coordinator-home "$COORDINATOR_HOME" \
  --token-file "$COORDINATOR_HOME/api-token"

python3 "$DEVCOORDINATOR_ROOT/scripts/write_cutover_phase_marker.py" \
  --marker "$CUTOVER_BACKUP/state-migration.attempted" \
  --phase state-migration-attempted
python3 "$DEVCOORDINATOR_ROOT/scripts/migrate_legacy_console_runtime.py" \
  --legacy-env "$LEGACY_ENV" --legacy-state "$LEGACY_STATE" \
  --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
  --coordinator-home "$COORDINATOR_HOME" \
  --devcoordinator-root "$DEVCOORDINATOR_ROOT" \
  --backup-dir "$CUTOVER_BACKUP/legacy-migration-final" --sync-state-only
cmp -s "$CUTOVER_BACKUP/user-runtime.writer-free/routes.json" \
  "$CONSOLE_STATE/routes.json"
cmp -s "$CUTOVER_BACKUP/user-runtime.writer-free/ui-prefs.json" \
  "$CONSOLE_STATE/ui-prefs.json"

install -m 600 "$COORDINATOR_HOME/state.json" \
  "$CUTOVER_BACKUP/coordinator-state.pre-relocate.json"
sha256sum "$CUTOVER_BACKUP/coordinator-state.pre-relocate.json" \
  > "$CUTOVER_BACKUP/coordinator-state.pre-relocate.sha256"
sha256sum --check "$CUTOVER_BACKUP/coordinator-state.pre-relocate.sha256"
sync -f "$CUTOVER_BACKUP"

LEASE_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["lease_id"])' \
  "$CUTOVER_BACKUP/pre-cutover-identities.json")"
python3 "$DEVCOORDINATOR_ROOT/scripts/write_cutover_phase_marker.py" \
  --marker "$CUTOVER_BACKUP/relocation.attempted" \
  --phase relocation-attempted
python3 "$DEVCOORDINATOR_ROOT/skills/codex-dev-coordinator/scripts/dev_coordinator.py" \
  port relocate --agent "$USER" \
  --old-project "$OLD_PROJECT" --new-project "$DEVCOORDINATOR_ROOT" \
  --name devops-console --port 443 --lease-id "$LEASE_ID" \
  > "$CUTOVER_BACKUP/relocation-result.json"
```

Only now install the split units and start (not restart) the new coordinator.
Run the token-required layout preflight and the anonymous/authenticated probe
from the fresh-host section before starting the new Console.

```bash
set -euo pipefail
umask 077
sudo install -m 0644 \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/dev-coordinator.service" \
  "$DEVCOORDINATOR_ROOT/apps/DevOpsConsole/deploy/devops-console.service" \
  /etc/systemd/system/
sudo systemctl daemon-reload
python3 "$DEVCOORDINATOR_ROOT/scripts/check_loaded_systemd_paths.py" \
  --evidence "$CUTOVER_BACKUP/resolved-unit-paths.json"
sudo systemctl enable dev-coordinator.service devops-console.service
sudo systemctl start dev-coordinator.service

python3 "$DEVCOORDINATOR_ROOT/scripts/check_production_layout.py" \
  --repo-root "$DEVCOORDINATOR_ROOT" --home "$HOME" \
  --env-file "$CONSOLE_ENV" --state-dir "$CONSOLE_STATE" \
  --acme-webroot "$ACME_WEBROOT" --coordinator-home "$COORDINATOR_HOME" \
  --token-file "$COORDINATOR_HOME/api-token" --require-token --wait-token-seconds 10
python3 "$DEVCOORDINATOR_ROOT/scripts/check_coordinator_auth_boundary.py" \
  --token-file "$COORDINATOR_HOME/api-token" --host 127.0.0.1 --port 29876
sudo systemctl start devops-console.service
sleep 2
python3 "$DEVCOORDINATOR_ROOT/scripts/check_coordinator_auth_boundary.py" \
  --token-file "$COORDINATOR_HOME/api-token" --host 127.0.0.1 --port 29876 \
  --inventory-output "$CUTOVER_BACKUP/post-cutover-inventory.json"
CONSOLE_MAIN_PID="$(systemctl show --property MainPID --value devops-console.service)"
test "$CONSOLE_MAIN_PID" -gt 1
python3 "$DEVCOORDINATOR_ROOT/scripts/verify_post_cutover_registration.py" \
  --inventory "$CUTOVER_BACKUP/post-cutover-inventory.json" \
  --expected-identities "$CUTOVER_BACKUP/pre-cutover-identities.json" \
  --project "$DEVCOORDINATOR_ROOT" --old-project "$OLD_PROJECT" \
  --name devops-console --port 443 --main-pid "$CONSOLE_MAIN_PID" \
  > "$CUTOVER_BACKUP/post-cutover-registration-graph.json"
systemctl --no-pager --full status dev-coordinator.service devops-console.service \
  | tee "$CUTOVER_BACKUP/post-cutover-systemd-status.txt"
journalctl --no-pager -u dev-coordinator.service -u devops-console.service --since '-5 minutes' \
  | tee "$CUTOVER_BACKUP/post-cutover-journal.txt"
curl --fail --silent --show-error --output /dev/null \
  --write-out 'status=%{http_code} remote=%{remote_ip} tls=%{ssl_verify_result}\n' \
  https://console.vr.ae/healthz > "$CUTOVER_BACKUP/post-cutover-public-health.txt"
grep -Eq '^status=200 remote=[^[:space:]]+ tls=0$' \
  "$CUTOVER_BACKUP/post-cutover-public-health.txt"
sha256sum --check "$CUTOVER_BACKUP/console.env.sha256"
cmp -s "$CUTOVER_BACKUP/user-runtime.writer-free/routes.json" \
  "$CONSOLE_STATE/routes.json"
cmp -s "$CUTOVER_BACKUP/user-runtime.writer-free/ui-prefs.json" \
  "$CONSOLE_STATE/ui-prefs.json"
python3 - "$CONSOLE_STATE" "$CUTOVER_BACKUP/user-runtime-counts.json" <<'PY'
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
routes = json.loads((state / "routes.json").read_text(encoding="utf-8"))["routes"]
hidden = json.loads((state / "ui-prefs.json").read_text(encoding="utf-8"))["hidden"]
if not isinstance(routes, dict) or not isinstance(hidden, dict):
    raise SystemExit("invalid route or UI-preference schema after cutover")
result = {
    "routes": len(routes),
    "hidden_preference_owners": len(hidden),
    "hidden_preferences": sum(len(value) for value in hidden.values() if isinstance(value, list)),
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
chmod 600 "$CUTOVER_BACKUP"/post-cutover-*.txt

MANIFEST_TMP="$(mktemp "$CUTOVER_BACKUP/.SHA256SUMS.XXXXXX")"
cleanup_manifest_tmp() { rm -f "$MANIFEST_TMP"; }
trap cleanup_manifest_tmp EXIT
(cd "$CUTOVER_BACKUP" && find . -type f ! -name SHA256SUMS \
  ! -name '.SHA256SUMS.*' -print0 | LC_ALL=C sort -z | \
  xargs -0 -r sha256sum > "$MANIFEST_TMP")
(cd "$CUTOVER_BACKUP" && sha256sum --check "$MANIFEST_TMP" >/dev/null)
chmod 600 "$MANIFEST_TMP"
mv -f "$MANIFEST_TMP" "$CUTOVER_BACKUP/SHA256SUMS"
trap - EXIT
(cd "$CUTOVER_BACKUP" && sha256sum --check SHA256SUMS >/dev/null)
sync -f "$CUTOVER_BACKUP"
```

The verifier requires the exact assignment, reused server ID, running and
healthy systemd MainPID, and one new active lease for port 443 to form a
bidirectionally linked graph under `/home/DevCoordinator`. It also rejects any
current assignment, server, or active lease owned by the retired checkout.
Separately confirm no current process, unit, helper, or environment value
references that checkout. Historical events may retain the old path as
evidence.

On any failure, stop every possible writer and choose state restoration by the
durable phase marker. If relocation was attempted, restore `pre-relocate`; if
only final migration was attempted, restore the exact writer-free `poststop`
checkpoint. Before either marker, leave the current state untouched—an
active-writer snapshot is never treated as lossless. A required but invalid
checkpoint is a hard blocker rather than a reason to guess. Restore the exact
unit topology captured before cutover. In particular, the real
legacy host had no `dev-coordinator.service`; rollback must disable and remove
that new-only unit before the old Console is allowed to autostart its child
coordinator:

```bash
set -euo pipefail
sudo systemctl stop devops-console.service
test "$(systemctl is-active devops-console.service || true)" != active
COORDINATOR_LOAD_STATE="$(systemctl show --property LoadState --value \
  dev-coordinator.service 2>/dev/null || true)"
if [ "$COORDINATOR_LOAD_STATE" != not-found ] && [ -n "$COORDINATOR_LOAD_STATE" ]; then
  sudo systemctl stop dev-coordinator.service
  test "$(systemctl is-active dev-coordinator.service || true)" != active
fi
if [ -f "$CUTOVER_BACKUP/legacy-processes.json" ]; then
  python3 "$DEVCOORDINATOR_ROOT/scripts/terminate_captured_legacy_process.py" \
    --evidence "$CUTOVER_BACKUP/legacy-processes.json" --role coordinator \
    --timeout-seconds 5
fi
python3 "$DEVCOORDINATOR_ROOT/scripts/check_legacy_cutover_stopped.py" \
  --evidence "$CUTOVER_BACKUP/legacy-processes.json" --ports 80 443 29876
if grep -qx absent "$CUTOVER_BACKUP/dev-coordinator.service.preexisting" && \
   systemctl cat dev-coordinator.service >/dev/null 2>&1; then
  sudo systemctl disable dev-coordinator.service
fi
sudo rm -f /run/systemd/system/devops-console.service.d/90-cutover-killmode.conf

ROLLBACK_STATE=
if [ -f "$CUTOVER_BACKUP/relocation.attempted" ]; then
  test -f "$CUTOVER_BACKUP/coordinator-state.pre-relocate.json"
  test -f "$CUTOVER_BACKUP/coordinator-state.pre-relocate.sha256"
  sha256sum --check "$CUTOVER_BACKUP/coordinator-state.pre-relocate.sha256"
  ROLLBACK_STATE="$CUTOVER_BACKUP/coordinator-state.pre-relocate.json"
elif [ -f "$CUTOVER_BACKUP/state-migration.attempted" ]; then
  test -f "$CUTOVER_BACKUP/coordinator-state.poststop.json"
  test -f "$CUTOVER_BACKUP/coordinator-state.poststop.sha256"
  sha256sum --check "$CUTOVER_BACKUP/coordinator-state.poststop.sha256"
  ROLLBACK_STATE="$CUTOVER_BACKUP/coordinator-state.poststop.json"
else
  echo "no state mutation phase marker; preserving current coordinator state"
fi
if [ -n "$ROLLBACK_STATE" ]; then
  install -m 600 "$ROLLBACK_STATE" \
    "$COORDINATOR_HOME/.state.json.rollback"
  mv -f "$COORDINATOR_HOME/.state.json.rollback" "$COORDINATOR_HOME/state.json"
fi

if grep -qx present "$CUTOVER_BACKUP/dev-coordinator.service.preexisting"; then
  sudo install -m 0644 "$CUTOVER_BACKUP/dev-coordinator.service.previous" \
    /etc/systemd/system/dev-coordinator.service
else
  sudo rm -f /etc/systemd/system/dev-coordinator.service
fi
sudo install -m 0644 "$CUTOVER_BACKUP/devops-console.service.previous" \
  /etc/systemd/system/devops-console.service
sudo systemctl daemon-reload

restore_enablement() {
  unit="$1"
  state="$(head -n 1 "$CUTOVER_BACKUP/$unit.enabled")"
  case "$state" in
    enabled) sudo systemctl enable "$unit" ;;
    enabled-runtime) sudo systemctl enable --runtime "$unit" ;;
    disabled) sudo systemctl disable "$unit" ;;
    static|indirect|generated|transient|alias) ;;
    *) echo "unsupported captured enablement for $unit: $state" >&2; return 1 ;;
  esac
}
restore_enablement devops-console.service
if grep -qx present "$CUTOVER_BACKUP/dev-coordinator.service.preexisting"; then
  restore_enablement dev-coordinator.service
fi
sudo systemctl reset-failed dev-coordinator.service devops-console.service || true
sudo systemctl start devops-console.service
ROLLBACK_MAIN_PID="$(systemctl show --property MainPID --value devops-console.service)"
ROLLBACK_CGROUP="$(systemctl show --property ControlGroup --value devops-console.service)"
test "$ROLLBACK_MAIN_PID" -gt 1
test -n "$ROLLBACK_CGROUP"
python3 "$DEVCOORDINATOR_ROOT/scripts/verify_legacy_console_rollback_ready.py" \
  --unit devops-console.service \
  --main-pid "$ROLLBACK_MAIN_PID" --cgroup "$ROLLBACK_CGROUP" \
  --old-coordinator-script "$OLD_COORDINATOR" \
  --health-url https://console.vr.ae/healthz \
  --evidence "$CUTOVER_BACKUP/rollback-readiness.json" \
  --timeout-seconds 30 --poll-interval-seconds 0.1
```

The rollback readiness verifier fixes the systemd MainPID and cgroup at start,
then revalidates both process start/argv identities on every observation. A
temporarily missing child coordinator, transient attributed child, missing
listener, or pre-bind TLS transport is retried only within the bounded timeout.
Wrong, ambiguous, or unobservable listener ownership and any fixed identity
change fail immediately. Success requires ports 80 and 443 to belong only to
the restored Node MainPID, port 29876 to belong only to its exact old-checkout
coordinator child, and the locally owned TLS listener to answer the public
hostname with exactly HTTP 200 and successful certificate verification. The
probe bypasses proxies and DNS routing, preserves SNI with the public hostname,
and records an exact `127.0.0.1` remote address; externally routed public
reachability remains a separate post-rollback check. The complete observation
ledger and terminal result remain private and checksummed beside the rollback
evidence. `SIGINT`, `SIGTERM`, and `SIGHUP` produce terminal `interrupted`
evidence. `SIGKILL`, power loss, or storage failure can still leave `running`
or incomplete evidence, which must never be accepted as rollback readiness.

Also verify the split coordinator unit is absent or restored to its recorded
prior state. Re-run login before ending rollback. Retain the old checkout and
the immutable private backup after every attempted cutover, whether it succeeds
or fails. Never reuse a failed attempt's backup path for a retry.

Both units run as `holyglory`. The coordinator binds only loopback and owns the
external coordinator state and private token. The Console requires that unit,
runs with `CAP_NET_BIND_SERVICE` only (no root), and `ExecReload` sends SIGHUP
for cert reloads. On startup it registers itself with the coordinator (`server
register`, port 443) so it appears in inventory alongside everything it
manages.

`dev-coordinator.service` deliberately uses `KillMode=process`. Managed dev
servers are independent attributed resources; `start_new_session` separates
their signals but does not move them out of the service cgroup. The default
control-group kill would therefore terminate every coordinator-launched server
when restarting only the API. Project/server stop actions remain the explicit
way to terminate those managed processes.

The coordinator unit intentionally does not set `PrivateTmp`, `ProtectSystem`,
`ReadWritePaths`, `NoNewPrivileges`, or a unit-wide `UMask`. Systemd applies
those properties to every child in the service cgroup, and
`start_new_session` changes only process-session/signal relationships. A
generic coordinator must not silently give launched apps a private `/tmp`, a
restricted filesystem, disabled privilege transitions, or an unexpected
creation mask; surviving children would also retain an obsolete private mount
namespace after an API restart. Workloads that need stronger isolation must be
launched into their own explicitly configured transient systemd scopes/units,
not inherit policy from the coordinator API unit. The Console remains hardened
because it owns no managed children when `COORDINATOR_AUTOSTART=0`.

## Exposing a dev server

1. Start the server through the coordinator (or the console UI) so it has a
   tracked port. Web servers running as Docker containers (any container
   publishing a non-database TCP port) need nothing extra — they show up on
   the Servers page automatically.
2. Console → *Servers* → "Assign subdomain" on the row (works for both
   coordinator servers and docker containers; a port picker appears when a
   container publishes several ports), or Console → *Routes* → create: pick a
   slug (`myapp` → `https://myapp.vr.ae`), choose the coordinator server
   (port follows the server across restarts), a container (host port follows
   the container across restarts), or a fixed port, and leave access on
   **login required** (default) or explicitly flip to public.
3. WebSockets/HMR pass through. Vite dev servers block unknown hosts with
   "Blocked request. This host … is not allowed" — allow the whole domain
   family once and any assigned slug keeps working after renames:

   ```js
   // vite.config.js / vite.config.ts
   export default { server: { allowedHosts: ['.vr.ae'] } }
   ```

   (The proxy forwards the original `Host` plus `X-Forwarded-Proto/Host/For`.)

## Security model

- The coordinator API on 29876 is loopback-only and bearer-authenticated. The
  token stays in a private external file and is never returned to browser
  JavaScript, logs, URLs, screenshots, or Git.
- Sessions: HMAC-SHA256-signed cookie, `Domain=.vr.ae`, `HttpOnly`, `Secure`,
  `SameSite=Lax`; allowlist re-checked on every request.
- OIDC: authorization code + PKCE, `state`/`nonce` enforced, ID-token
  signature verified against Google's JWKS in-process.
- Unknown subdomains are indistinguishable from protected ones until you log
  in (no route enumeration). New routes default to login-required. Proxy
  targets are always `127.0.0.1`.
- Console API mutations require a same-origin `Origin` header (CSRF).

## Dev mode

`DEV_HTTP=1 HTTP_PORT=<leased port> node bin/devops-console.mjs` serves the
whole router (console + proxying) over plain HTTP on one loopback port — used
by the coordinator dev-runtime declaration and the test suite. Lease ports via
the coordinator per repo policy; never bind fixed dev ports.
