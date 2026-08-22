#!/usr/bin/env python3
"""Focused regressions for the routine same-schema release switch."""

from __future__ import annotations

import inspect
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import switch_same_schema_release as switch  # noqa: E402
from devcoordinator.server_credentials import server_credential_id  # noqa: E402
from devcoordinator.schema import initialize_schema  # noqa: E402
from devcoordinator.worker_control import quiesce_worker_registration  # noqa: E402
from devcoordinator.worker_native import NativeWorkerState  # noqa: E402


DIGEST = "a" * 64


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Response:
    def __init__(self, status: int, body: bytes = b"{}\n") -> None:
        self.status = status
        self.body = body

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _maximum: int) -> bytes:
        return self.body


class FakeRunner:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []

    def require(self, argv: list[str], _label: str) -> str:
        self.commands.append(list(argv))
        return ""


def worker_cutover_database(
    path: Path,
    *,
    schema_version: int,
    running: bool,
    role: str = "web",
) -> dict[str, object]:
    worker_id = "11111111-1111-4111-8111-111111111111"
    repo_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    host_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    attempt_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    stamp = "2026-08-21T00:00:00.000Z"
    credential_id = server_credential_id(worker_id, "DATABASE_URL")
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        initialize_schema(
            connection,
            database_generation="worker-cutover-generation",
            timestamp=stamp,
        )
        connection.execute(
            "INSERT INTO hosts VALUES (?,?,?,?,?,?)",
            (host_id, "machine", "linux", "host", stamp, stamp),
        )
        connection.execute(
            "INSERT INTO repositories VALUES (?,?,?,?,?,?,?,?)",
            (repo_id, host_id, "/srv/repository", "Repository", "active", 2, stamp, stamp),
        )
        connection.execute(
            "INSERT INTO repository_installations(repo_id,status,startup_fenced,generation,actor,updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (repo_id, "installed", 0, 1, "owner", stamp),
        )
        connection.execute(
            "INSERT INTO server_definitions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                worker_id,
                repo_id,
                "credentialized-web",
                role,
                "/srv/repository",
                None,
                None,
                "definition-fingerprint",
                8 if schema_version == 16 else 7,
                stamp,
                stamp,
            ),
        )
        if schema_version == 16:
            connection.execute(
                "INSERT INTO server_environment_credentials VALUES (?,?,?,?,?)",
                (worker_id, "DATABASE_URL", credential_id, stamp, stamp),
            )
        connection.execute(
            """
            INSERT INTO worker_policies(
                server_definition_id,repo_id,execution_uid,keep_alive,
                desired_state,breaker_state,crash_limit,crash_window_seconds,
                generation,requested_by,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                worker_id,
                repo_id,
                os.geteuid() or 1000,
                1,
                "running",
                "armed",
                5,
                60,
                5 if schema_version == 16 else 4,
                "owner",
                stamp,
                stamp,
            ),
        )
        if running:
            connection.execute(
                """
                INSERT INTO worker_attempts(
                    attempt_id,begin_request_id,server_definition_id,repo_id,
                    definition_generation,policy_generation,
                    supervisor_generation,supervisor_epoch,state,
                    launch_report_id,pid,process_start_time,process_fingerprint,
                    reserved_at,launched_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    attempt_id,
                    "begin-worker-cutover",
                    worker_id,
                    repo_id,
                    8 if schema_version == 16 else 7,
                    5 if schema_version == 16 else 4,
                    3,
                    "worker-cutover-epoch",
                    "running",
                    "launch-worker-cutover",
                    42424,
                    "process-start",
                    "process-fingerprint",
                    stamp,
                    stamp,
                    stamp,
                    stamp,
                ),
            )
        connection.execute(
            """
            INSERT INTO worker_supervisor_states(
                server_definition_id,repo_id,state,supervisor_epoch,
                supervisor_generation,current_attempt_id,updated_at
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (
                worker_id,
                repo_id,
                "running" if running else "idle",
                "worker-cutover-epoch" if running else None,
                3 if running else 0,
                attempt_id if running else None,
                stamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO server_observations(
                server_definition_id,lifecycle,pid,process_start_time,
                process_fingerprint,listener_observable,health_classification,
                health_ok,sampled_at,observation_fingerprint
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                worker_id,
                "running" if running else "stopped",
                42424 if running else None,
                "process-start" if running else None,
                "process-fingerprint" if running else None,
                None,
                "supervised_process_running" if running else "stopped",
                1 if running else None,
                stamp,
                "observation-fingerprint",
            ),
        )
        connection.execute(
            "UPDATE schema_metadata SET schema_version=?,state_revision=7",
            (schema_version,),
        )
        connection.commit()
    finally:
        connection.close()
    return {
        "worker_id": worker_id,
        "repo_id": repo_id,
        "attempt_id": attempt_id,
        "credential_id": credential_id,
    }


class BrowserCleanupRunner(FakeRunner):
    def __init__(
        self,
        result: dict[str, object] | None = None,
        failure: switch.SwitchError | None = None,
    ) -> None:
        super().__init__()
        self.result = result
        self.failure = failure

    def require_json(self, argv: list[str], _label: str) -> dict[str, object]:
        self.commands.append(list(argv))
        if self.failure is not None:
            raise self.failure
        if self.result is None:
            raise AssertionError("browser cleanup result was not configured")
        return dict(self.result)


class HistoryRunner(FakeRunner):
    def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, "", "")

    def require_json(self, argv: list[str], _label: str) -> dict[str, object]:
        self.commands.append(list(argv))
        if "initialize-fresh" in argv:
            attestation = argv[argv.index("--attestation-output") + 1]
            return {
                "ok": True,
                "action": "test-store-initialize-fresh",
                "branch": "attested-fresh",
                "attestation": attestation,
                "attestation_fingerprint": "c" * 64,
                "store_generation": "forward-generation",
                "schema_version": 7,
                "discarded_existing": True,
                "replayed": False,
            }
        if "create" in argv:
            database = argv[argv.index("--test-database") + 1]
            return {
                "ok": True,
                "action": "create",
                "test_database": database,
                "schema_version": 5,
                "store_generation": "rollback-generation",
            }
        raise AssertionError(f"unexpected history command: {argv}")


def exercise_slot_payload() -> None:
    payload = switch.candidate_slot_payload(DIGEST, 35001, 35002).decode("utf-8")
    values = switch.parse_slot(payload)
    expect(values["DEVCOORDINATOR_RELEASE_DIGEST"] == DIGEST, "slot lost release")
    expect(values["HTTPS_PORT"] == "35001", "slot lost outer port")
    expect(values["DEVCOORDINATOR_CONSOLE_INNER_PORT"] == "35002", "slot lost inner port")
    expect(values["DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE"] == "0", "candidate bootstrapped active")
    try:
        switch.candidate_slot_payload(DIGEST, 35001, 35001)
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("candidate slot accepted one shared listener port")


def exercise_http_is_strict_2xx() -> None:
    url = "http://127.0.0.1:1/healthz"
    with mock.patch.object(switch, "urlopen", return_value=Response(204)):
        expect(switch.http_health(url, 2.0)["ok"] is True, "204 health was rejected")
    with mock.patch.object(switch, "urlopen", return_value=Response(404)):
        expect(switch.http_health(url, 2.0)["ok"] is False, "404 health was accepted")


def exercise_edge_health_uses_live_generation() -> None:
    stale = Response(
        200,
        b'{"ok":true,"role":"edge","generation":3,"release":"'
        + DIGEST.encode()
        + b'"}\n',
    )
    current = Response(
        200,
        b'{"ok":true,"role":"edge","generation":4,"release":"'
        + DIGEST.encode()
        + b'"}\n',
    )
    with (
        mock.patch.object(switch, "urlopen", side_effect=[stale, current]) as request,
        mock.patch.object(switch.time, "sleep"),
    ):
        observed = switch.wait_edge_publication(
            "https://console.vr.ae/healthz",
            release_digest=DIGEST,
            generation=4,
            timeout_seconds=1,
        )
    expect(request.call_count == 2, "live edge generation was not polled")
    expect(observed["document"]["generation"] == 4, "stale edge generation was accepted")


def exercise_stopped_published_console_recovers_exactly() -> None:
    published_digest = "b" * 64

    class RecoveryRunner(FakeRunner):
        def __init__(self) -> None:
            super().__init__()
            self.discovery_count = 0

        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if "list-units" in argv:
                self.discovery_count += 1
                if self.discovery_count == 1:
                    return ""
                return f"devcoordinator-console@{published_digest}.service loaded active running\n"
            return ""

    with tempfile.TemporaryDirectory(prefix="same-schema-console-recovery-") as raw:
        slots = Path(raw)
        (slots / f"{published_digest}.env").write_bytes(
            switch.candidate_slot_payload(published_digest, 35001, 35002)
        )
        runner = RecoveryRunner()
        with (
            mock.patch.object(switch, "SLOT_ROOT", slots),
            mock.patch.object(
                switch,
                "publication_snapshot",
                return_value={
                    "payload_sha256": "c" * 64,
                    "release_digest": published_digest,
                    "generation": 7,
                    "port": 35001,
                },
            ),
        ):
            unit, digest = switch.active_console(runner)
    expected_unit = f"devcoordinator-console@{published_digest}.service"
    expect((unit, digest) == (expected_unit, published_digest), "published slot was not recovered")
    expect(
        ["/usr/bin/systemctl", "start", switch.API_SOCKET] in runner.commands,
        "stable API socket was not recovered before the Console",
    )
    expect(
        ["/usr/bin/systemctl", "start", expected_unit] in runner.commands,
        "published Console instance was not recovered",
    )


def exercise_ambiguous_console_topology_never_recovers() -> None:
    runner = FakeRunner()
    runner.require = mock.Mock(
        return_value=(
            f"devcoordinator-console@{'b' * 64}.service loaded active running\n"
            f"devcoordinator-console@{'c' * 64}.service loaded active running\n"
        )
    )
    with mock.patch.object(switch, "recover_published_console") as recover:
        try:
            switch.active_console(runner)
        except switch.SwitchError as error:
            expect("exactly one active" in str(error), "ambiguous topology error lost its cause")
        else:
            raise AssertionError("ambiguous Console topology was accepted")
    recover.assert_not_called()


def exercise_local_path_materialization() -> None:
    with tempfile.TemporaryDirectory(prefix="same-schema-paths-") as raw:
        root = Path(raw)
        profile = root / "client-profiles.json"
        profile.write_text("{}\n", encoding="utf-8")
        profile.chmod(0o660)
        maintenance_root = root / "maintenance"
        maintenance_root.mkdir()
        maintenance_marker = maintenance_root / "maintenance.json"
        maintenance_marker.write_text("stale\n", encoding="utf-8")
        private_runtime_lock = root / "private-runtime-lock.json"
        public_runtime_lock = root / "public" / "browser-runtime-lock.json"
        runtime_document = {"document_sha256": "d" * 64}
        runtime_payload = json.dumps(runtime_document).encode("utf-8") + b"\n"
        private_runtime_lock.write_bytes(runtime_payload)
        private_runtime_lock.chmod(0o600)
        authority_state = root / "authority-state"
        authority_state.mkdir(mode=0o700)
        lifecycle_state = authority_state / "browser-lifecycle.json"
        lifecycle_lock = authority_state / "browser-lifecycle.json.lock"
        lifecycle_state.write_text("{}\n", encoding="utf-8")
        lifecycle_lock.write_text("", encoding="utf-8")
        lifecycle_state.chmod(0o600)
        lifecycle_lock.chmod(0o600)
        runner = FakeRunner()
        with (
            mock.patch.object(switch, "CLIENT_PROFILE", profile),
            mock.patch.object(switch, "SYSUSERS_ROOT", root / "sysusers"),
            mock.patch.object(switch, "TMPFILES_ROOT", root / "tmpfiles"),
            mock.patch.object(switch, "MAINTENANCE_ROOT", maintenance_root),
            mock.patch.object(switch, "MAINTENANCE_MARKER", maintenance_marker),
            mock.patch.object(
                switch, "BROWSER_RUNTIME_LOCK_PRIVATE", private_runtime_lock
            ),
            mock.patch.object(
                switch, "BROWSER_RUNTIME_LOCK_PUBLIC", public_runtime_lock
            ),
            mock.patch.object(switch, "BROWSER_LIFECYCLE_ROOT", authority_state),
            mock.patch.object(switch, "BROWSER_LIFECYCLE_STATE", lifecycle_state),
            mock.patch.object(switch, "BROWSER_LIFECYCLE_LOCK", lifecycle_lock),
            mock.patch.object(
                switch.browser_lcp,
                "verify_runtime_lock_document",
                return_value=runtime_document,
            ),
        ):
            switch.normalize_local_paths(runner)
            runtime_evidence = switch.verify_public_browser_runtime_inventory()
            publication_evidence = switch.verify_browser_lifecycle_publication()
            authority_state.chmod(0o700)
            private_publication_evidence = switch.verify_browser_lifecycle_publication()
            authority_state.chmod(0o755)
        expect(stat.S_IMODE(profile.stat().st_mode) == 0o644, "non-secret profile was not published read-only")
        expect(not maintenance_marker.exists(), "abandoned maintenance marker was retained")
        expect(stat.S_IMODE(maintenance_root.stat().st_mode) == 0o755, "maintenance directory stayed private")
        expect(
            stat.S_IMODE(authority_state.stat().st_mode) == 0o755
            and stat.S_IMODE(lifecycle_state.stat().st_mode) == 0o644
            and stat.S_IMODE(lifecycle_lock.stat().st_mode) == 0o644,
            "actual-caller lifecycle telemetry remained inaccessible",
        )
        expect(
            public_runtime_lock.read_bytes() == runtime_payload
            and stat.S_IMODE(public_runtime_lock.stat().st_mode) == 0o644
            and runtime_evidence["document_sha256"] == "d" * 64,
            "non-secret browser runtime inventory was not published read-only",
        )
        expect(
            publication_evidence["ok"] is True,
            "actual-caller lifecycle publication was not verified",
        )
        expect(
            private_publication_evidence["ok"] is False,
            "private lifecycle parent was accepted by health verification",
        )
        flattened = [item for command in runner.commands for item in command]
        expect("/usr/bin/systemd-sysusers" in flattened, "sysusers was not materialized")
        expect("/usr/bin/systemd-tmpfiles" in flattened, "tmpfiles was not materialized")
        expect(
            str(root / "tmpfiles/devcoordinator.conf") in flattened
            and str(root / "tmpfiles/devcoordinator-availability.tmpfiles.conf")
            in flattened,
            "canonical and availability tmpfiles policies were not applied together",
        )


def exercise_blue_green_order() -> None:
    source = inspect.getsource(switch.apply)
    required = (
        "candidate Console start",
        "candidate Console promotion",
        "switch_publication(",
        "wait_edge_publication(",
        "previous Console drain",
    )
    positions = [source.index(token) for token in required]
    expect(positions == sorted(positions), "same-schema switch does not start/promote/publish/verify/drain in order")
    expect("previous Console stop" not in source, "old Console is stopped before blue/green handoff")
    expect(
        "previous_status is None and previous_is_published" in source,
        "a published old slot with a lost control socket blocks standalone promotion",
    )


def exercise_first_capable_browser_cleanup() -> None:
    with mock.patch.object(
        switch.installer,
        "verify_release",
        return_value={"capabilities": {}},
    ):
        expect(
            switch.release_capability(
                Path("/opt/devcoordinator/releases") / ("b" * 64),
                switch.BROWSER_ACCOUNTING_CAPABILITY,
            )
            is False,
            "an old release with no browser capability was not treated as incapable",
        )
    with tempfile.TemporaryDirectory(prefix="same-schema-browser-cleanup-") as raw:
        root = Path(raw)
        release = root / DIGEST
        previous_digest = "b" * 64

        def capability(path: Path, name: str) -> bool:
            expect(
                name == switch.BROWSER_ACCOUNTING_CAPABILITY,
                "browser cleanup queried an unrelated capability",
            )
            return path == release

        with (
            mock.patch.object(switch, "release_capability", side_effect=capability),
            mock.patch.object(
                switch, "retiring_release_capability", side_effect=capability
            ),
        ):
            plan = switch.headless_browser_cleanup_plan(
                release,
                previous_release_digest=previous_digest,
            )
            expect(
                plan["required"] is True and plan["status"] == "pending",
                "first browser-aware release did not plan one cleanup",
            )
            document: dict[str, object] = {
                "schema_version": switch.VERSION,
                "kind": switch.KIND,
                "phase": "applying",
                "release": str(release),
                "release_digest": DIGEST,
                "previous_release_digest": previous_digest,
                "headless_browser_cleanup": plan,
            }
            journal = root / "journal.json"
            switch.atomic_json(journal, document)
            runner = BrowserCleanupRunner(
                {
                    "ok": True,
                    "observed_session_count": 7,
                    "terminated_session_count": 7,
                    "terminated_process_count": 29,
                    "reclaimed_memory_bytes": 12_345_678,
                    "remaining_session_count": 0,
                    "sampled_at": "2026-08-03T12:00:00Z",
                    "unbounded_internal_details": "x" * 100_000,
                }
            )
            result = switch.perform_headless_browser_cleanup(
                release,
                document,
                journal,
                runner,
            )
            expect(
                result == {
                    "ok": True,
                    "remaining_session_count": 0,
                    "observed_session_count": 7,
                    "terminated_session_count": 7,
                    "terminated_process_count": 29,
                    "reclaimed_memory_bytes": 12_345_678,
                    "sampled_at": "2026-08-03T12:00:00Z",
                },
                "browser cleanup did not retain one bounded result",
            )
            expected_command = [
                str(release / "bin" / switch.BROWSER_ACCOUNTING_WRAPPER),
                "cleanup-all",
                "--state",
                str(switch.BROWSER_LIFECYCLE_STATE),
                "--quiescence-seconds",
                "2",
                "--json",
            ]
            expect(
                runner.commands == [expected_command],
                "first-capable cleanup command was not exact",
            )
            persisted = switch.load_journal(journal)
            cleanup = persisted["headless_browser_cleanup"]
            expect(
                isinstance(cleanup, dict)
                and cleanup.get("status") == "complete"
                and len(switch.canonical(cleanup["result"]))
                <= switch.BROWSER_CLEANUP_RESULT_MAX_BYTES,
                "successful browser cleanup was not durably bounded",
            )
            switch.perform_headless_browser_cleanup(
                release,
                document,
                journal,
                runner,
            )
            expect(
                runner.commands == [expected_command],
                "completed browser cleanup ran twice on replay",
            )


def exercise_retiring_release_ignores_generated_bytecode() -> None:
    entries = [
        {
            "path": "bin/devcoordinator-browser-accounting",
            "sha256": "0" * 64,
            "size": 1,
            "mode": "0555",
            "kind": "wrapper",
        },
        {
            "path": (
                "skills/codex-dev-coordinator/scripts/devcoordinator/"
                "browser_lifecycle.py"
            ),
            "sha256": "1" * 64,
            "size": 1,
            "mode": "0444",
            "kind": "source",
        },
    ]
    digest = switch.installer.release_digest(entries)
    with tempfile.TemporaryDirectory(prefix="same-schema-retiring-release-") as raw:
        release = Path(raw) / digest
        cache = (
            release
            / "skills/codex-dev-coordinator/scripts/devcoordinator/__pycache__"
        )
        cache.mkdir(parents=True)
        (cache / "legacy.cpython-313.pyc").write_bytes(b"generated")
        cache.chmod(0o700)
        manifest = {
            "schema_version": switch.installer.RELEASE_SCHEMA,
            "release_digest": digest,
            "files": entries,
            "capabilities": {switch.BROWSER_ACCOUNTING_CAPABILITY: True},
        }
        (release / "release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        expect(
            switch.retiring_release_capability(
                release, switch.BROWSER_ACCOUNTING_CAPABILITY
            )
            is True,
            "generated bytecode in a retiring release blocked replacement",
        )


def exercise_previous_release_requires_current_format() -> None:
    required_paths = (
        "bin/devcoordinator-browser-accounting",
        "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
        "bin/devcoordinator-same-schema-switch",
        "bin/devcoordinator-retained-control",
        "scripts/switch_same_schema_release.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/retained_control.py",
        "deploy/devcoordinator-api.socket",
        "deploy/devcoordinator-authority.socket",
        "deploy/devcoordinator-edge.service",
        "deploy/devcoordinator-console@.service",
    )

    def entry(path: str, index: int) -> dict[str, object]:
        return {
            "path": path,
            "sha256": f"{index:064x}",
            "size": index + 1,
            "mode": "0555" if path.startswith("bin/") else "0444",
            "kind": "wrapper" if path.startswith("bin/") else "source",
        }

    with tempfile.TemporaryDirectory(prefix="same-schema-current-format-") as raw:
        root = Path(raw)
        for selected, accepted in (
            (required_paths, True),
            (required_paths[:-1], False),
        ):
            entries = [entry(path, index) for index, path in enumerate(selected, 1)]
            digest = switch.installer.release_digest(entries)
            release = root / digest
            release.mkdir()
            manifest = {
                "schema_version": switch.installer.RELEASE_SCHEMA,
                "release_digest": digest,
                "files": entries,
                "capabilities": {
                    switch.BROWSER_ACCOUNTING_CAPABILITY: True,
                    "current_format_delivery": accepted,
                },
            }
            (release / "release-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            cache = release / "generated/__pycache__"
            cache.mkdir(parents=True)
            (cache / "residue.pyc").write_bytes(b"generated")
            if accepted:
                switch.require_previous_current_format_release(release)
            else:
                try:
                    switch.require_previous_current_format_release(release)
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError("old-layout predecessor passed the current-format gate")


def exercise_browser_cleanup_skip_failure_and_malformed_result() -> None:
    with tempfile.TemporaryDirectory(prefix="same-schema-browser-cases-") as raw:
        root = Path(raw)
        release = root / DIGEST
        previous_digest = "b" * 64

        with (
            mock.patch.object(switch, "release_capability", return_value=True),
            mock.patch.object(
                switch, "retiring_release_capability", return_value=True
            ),
        ):
            plan = switch.headless_browser_cleanup_plan(
                release,
                previous_release_digest=previous_digest,
            )
            expect(
                plan["required"] is False and plan["status"] == "not-required",
                "browser-aware predecessor repeated the one-time cleanup",
            )
            document: dict[str, object] = {
                "phase": "applying",
                "previous_release_digest": previous_digest,
                "headless_browser_cleanup": plan,
            }
            journal = root / "skip.json"
            switch.atomic_json(journal, {
                "schema_version": switch.VERSION,
                "kind": switch.KIND,
                **document,
            })
            runner = BrowserCleanupRunner({"ok": True, "remaining_session_count": 0})
            expect(
                switch.perform_headless_browser_cleanup(
                    release, document, journal, runner
                )
                is None
                and not runner.commands,
                "already-capable predecessor invoked browser cleanup",
            )

        def first_capability(path: Path, _name: str) -> bool:
            return path == release

        for label, runner in (
            (
                "command failure",
                BrowserCleanupRunner(
                    failure=switch.SwitchError("cleanup command failed")
                ),
            ),
            (
                "malformed result",
                BrowserCleanupRunner({"ok": True}),
            ),
        ):
            with (
                mock.patch.object(
                    switch, "release_capability", side_effect=first_capability
                ),
                mock.patch.object(
                    switch,
                    "retiring_release_capability",
                    side_effect=first_capability,
                ),
            ):
                plan = switch.headless_browser_cleanup_plan(
                    release,
                    previous_release_digest=previous_digest,
                )
                document = {
                    "phase": "applying",
                    "previous_release_digest": previous_digest,
                    "headless_browser_cleanup": plan,
                }
                journal = root / f"{label.replace(' ', '-')}.json"
                switch.atomic_json(journal, {
                    "schema_version": switch.VERSION,
                    "kind": switch.KIND,
                    **document,
                })
                try:
                    switch.perform_headless_browser_cleanup(
                        release, document, journal, runner
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(f"browser cleanup accepted {label}")
                calls = len(runner.commands)
                expect(
                    document["headless_browser_cleanup"]["status"] == "failed",
                    f"browser cleanup did not journal {label}",
                )
                try:
                    switch.perform_headless_browser_cleanup(
                        release, document, journal, runner
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(
                        f"browser cleanup replay accepted {label}"
                    )
                expect(
                    len(runner.commands) == calls,
                    f"browser cleanup replay reran after {label}",
                )


def exercise_browser_cleanup_activation_order() -> None:
    source = inspect.getsource(switch.apply)
    prepare_source = inspect.getsource(switch.prepare)
    expect(
        prepare_source.count('"headless_browser_cleanup": browser_cleanup') == 2,
        "same-schema prepare does not bind browser cleanup for both active and candidate paths",
    )
    positions = [
        source.index("retire_legacy_control_plane("),
        source.index("install_rendered_destinations("),
        source.index("perform_headless_browser_cleanup("),
        source.index("require_current_authority_schema("),
        source.index("restart_services("),
        source.index("candidate Console start"),
    ]
    expect(
        positions == sorted(positions),
        "browser cleanup is not candidate-stage-first and pre-activation",
    )
    rollback_source = inspect.getsource(switch.rollback)
    expect(
        "restore_authority_migration(" not in rollback_source
        and "restore_rollback_control_plane(" in rollback_source,
        "same-schema rollback must restore only the current-format release graph",
    )


def exercise_already_active_health_has_rendered_contract() -> None:
    source = inspect.getsource(switch.prepare)
    expect(
        source.index("rendered = render_release(release, transaction_root)")
        < source.index("if current_digest == release.name:"),
        "already-active preparation does not render the immutable health contract",
    )
    expect(
        source.count('"rendered_units": rendered["rendered_units"]') == 2
        and '"rendered_units": None' not in source,
        "already-active health can receive an absent rendered-unit contract",
    )


def exercise_current_transaction_durability() -> None:
    with tempfile.TemporaryDirectory(prefix="same-schema-atomic-bytes-") as raw:
        target = Path(raw) / "journal.json"
        with mock.patch.object(switch.os, "fsync", wraps=os.fsync) as synced:
            switch.atomic_bytes(target, b"{}\n", 0o600)
        expect(target.read_bytes() == b"{}\n", "atomic write changed its payload")
        expect(
            stat.S_IMODE(target.stat().st_mode) == 0o600 and synced.call_count >= 2,
            "atomic write did not fsync both file and parent directory",
        )
    source = inspect.getsource(switch.require_transaction_root)
    prepare_source = inspect.getsource(switch.prepare)
    expect(
        "absolute.name != release_digest" in source
        and "info.st_uid != 0" in source
        and "stat.S_IMODE(info.st_mode) != 0o700" in source,
        "same-schema journal is not bound to a root-private digest directory",
    )
    expect(
        "plan_sha256" not in prepare_source
        and prepare_source.index("require_previous_current_format_release(")
        < prepare_source.index("current_slot ="),
        "prepare retains a transaction self-hash or trusts an old-layout predecessor",
    )


def exercise_legacy_control_plane_is_durably_retired() -> None:
    with tempfile.TemporaryDirectory(prefix="legacy-control-plane-retirement-") as raw:
        root = Path(raw)
        marker = root / "enable-legacy"
        marker.write_text("stale\n", encoding="utf-8")
        runner = FakeRunner()
        with (
            mock.patch.object(switch, "UNIT_ROOT", root / "systemd"),
            mock.patch.object(switch, "LEGACY_ENABLE_MARKER", marker),
        ):
            switch.retire_legacy_control_plane(runner)
            guards = {
                unit: switch.legacy_retirement_path(unit).read_bytes()
                for unit in switch.LEGACY_CONTROL_PLANE_SERVICES
            }
        expected_commands = [["/usr/bin/systemctl", "daemon-reload"]]
        for unit in switch.LEGACY_CONTROL_PLANE_SERVICES:
            expected_commands.extend(
                [
                    ["/usr/bin/systemctl", "disable", "--now", unit],
                    ["/usr/bin/systemctl", "reset-failed", unit],
                ]
            )
        expect(
            runner.commands == expected_commands,
            "same-schema delivery did not stop and disable both obsolete units",
        )
        expect(not marker.exists(), "legacy enable marker survived retirement")
        expect(
            all(payload == switch.LEGACY_RETIREMENT_PAYLOAD for payload in guards.values()),
            "stale reverse dependencies can reactivate the obsolete control plane",
        )


def exercise_internal_socket_rebind_order() -> None:
    runner = FakeRunner()

    switch.restart_services(runner)

    enable_count = len(switch.REQUIRED_SOCKETS) + len(switch.SERVICE_ORDER)
    enable_commands = runner.commands[:enable_count]
    restart_commands = runner.commands[enable_count:]
    enabled_units = [command[-1] for command in enable_commands]
    units = [command[-1] for command in restart_commands]
    expect(
        enabled_units == [*switch.REQUIRED_SOCKETS, *switch.SERVICE_ORDER],
        "required sockets and services were not repaired for boot",
    )
    expect(
        all(command[1:3] == ["enable", "--now"] for command in enable_commands),
        "required unit repair did not make activation durable",
    )
    expected = [*switch.RUNTIME_SOCKET_REBIND_ORDER, *switch.SERVICE_ORDER]
    expect(units == expected, "internal sockets were not rebound before services")
    expect(
        all(command[1] == "restart" for command in restart_commands),
        "socket/service replacement did not use one deterministic restart path",
    )


def exercise_rollback_restores_control_plane_before_background_services() -> None:
    class BackgroundFailureRunner(FakeRunner):
        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if argv[-1] == "devcoordinator-observer.service":
                raise switch.SwitchError("observer start deadline exceeded")
            return ""

    runner = BackgroundFailureRunner()
    switch.restore_rollback_control_plane(runner)
    try:
        switch.restore_rollback_background_services(runner)
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("background rollback failure was not injected")

    authority_restart = [
        "/usr/bin/systemctl",
        "restart",
        "devcoordinator-authority.service",
    ]
    api_restart = [
        "/usr/bin/systemctl",
        "restart",
        "devcoordinator-api.service",
    ]
    observer_failure = next(
        index
        for index, command in enumerate(runner.commands)
        if command[-1] == "devcoordinator-observer.service"
    )
    expect(
        runner.commands.index(authority_restart) < observer_failure
        and runner.commands.index(api_restart) < observer_failure,
        "background rollback failure occurred before stable authority/API recovery",
    )

    rollback_source = inspect.getsource(switch.rollback)
    completion_source = inspect.getsource(
        switch.complete_rollback_after_control_plane
    )
    ordering = [
        rollback_source.index("restore_destination_backups(backups)"),
        rollback_source.index("restore_rollback_control_plane(runner)"),
        rollback_source.index('"previous Console restore"'),
        rollback_source.rindex('"rollback-control-plane-restored"'),
        rollback_source.rindex("complete_rollback_after_control_plane("),
    ]
    expect(
        ordering == sorted(ordering),
        "rollback does not checkpoint a coherent previous control plane before background restore",
    )
    expect(
        completion_source.index("restore_rollback_background_services(runner)")
        < completion_source.index('"rollback-background-restored"')
        < completion_source.index("require_retained_worker_policy_convergence("),
        "rollback completion does not checkpoint background restore before convergence",
    )


def exercise_slot_readiness_waits_for_supervisor_socket() -> None:
    runner = FakeRunner()
    ready = {"ok": True, "release_digest": DIGEST, "mode": "standby"}
    with (
        mock.patch.object(
            switch,
            "slot_status",
            side_effect=[
                switch.SwitchError("connect ENOENT /run/devcoordinator-console/candidate.sock"),
                switch.SwitchError("connect ENOENT /run/devcoordinator-console/candidate.sock"),
                ready,
            ],
        ) as status,
        mock.patch.object(switch.time, "sleep"),
    ):
        observed = switch.wait_slot_status(
            runner,
            Path("/opt/devcoordinator/releases") / DIGEST,
            "/run/devcoordinator-console/candidate.sock",
            f"devcoordinator-console@{DIGEST}.service",
            "candidate Console status",
            timeout_seconds=1,
        )
    expect(observed == ready, "slot readiness changed the successful status")
    expect(status.call_count == 3, "slot readiness did not retry transient ENOENT")


def exercise_release_packaging_contract() -> None:
    expect(
        switch.COORDINATOR_SCHEMA_VERSION == 16
        and all(
            "--expected-schema 16" in (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "deploy/devcoordinator-authority.service",
                "deploy/devcoordinator-test-snapshotd.service",
            )
        ),
        "schema-16 release can start with a stale unit preflight",
    )
    expect(
        Path("scripts/switch_same_schema_release.py") in switch.installer.SOURCE_FILES,
        "same-schema switch source is absent from immutable releases",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-same-schema-switch")
        == ("python", "scripts/switch_same_schema_release.py", ()),
        "same-schema immutable wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-retained-control")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/retained_control.py",
            (),
        ),
        "semantic retained-control wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-test-store")
        == ("python", "scripts/manage_test_store.py", ()),
        "Test Store reset wrapper is absent from immutable releases",
    )
    expect(
        switch.installer.WRAPPERS.get(switch.BROWSER_ACCOUNTING_WRAPPER)
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
            (),
        ),
        "headless browser accounting wrapper is absent from immutable releases",
    )
    expect(
        Path("deploy/devcoordinator-read-only.rules")
        in switch.installer.SOURCE_FILES,
        "Codex read-only client rule is absent from immutable releases",
    )
    expect(
        Path("deploy/devcoordinator-test.rules") in switch.installer.SOURCE_FILES,
        "Codex test allow rule is absent from immutable releases",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
            (),
        ),
        "immutable stable agent wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-call-log")
        == ("python", "scripts/read_coordinator_call_log.py", ()),
        "immutable call-log compatibility wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-mcp")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_mcp.py",
            (),
        ),
        "immutable MCP wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-bug")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/bug_registry.py",
            (),
        ),
        "immutable outage-safe bug wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-test")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
            ("test",),
        ),
        "immutable test lifecycle wrapper is missing or too broad",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-image")
        == (
            "python",
            "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
            ("broker", "publish-image"),
        ),
        "immutable image publication wrapper is missing or too broad",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-codex-test-access-verify")
        == ("python", "scripts/verify_codex_test_access.py", ()),
        "non-root Codex test access verifier is absent from immutable releases",
    )
    wrapper = switch.installer.wrapper_payload(
        "devcoordinator-test",
        *switch.installer.WRAPPERS["devcoordinator-test"],
    )
    expect(
        b"'devcoordinator.agent_cli' 'test' \"$@\"" in wrapper,
        "immutable test lifecycle wrapper does not fix the test command",
    )
    expect(
        switch.CLIENT_LAUNCHER == Path("/usr/local/bin/devcoordinator")
        and switch.MCP_LAUNCHER == Path("/usr/local/bin/devcoordinator-mcp")
        and switch.BUG_LAUNCHER == Path("/usr/local/bin/devcoordinator-bug")
        and switch.TEST_LAUNCHER == Path("/usr/local/bin/devcoordinator-test")
        and switch.CALL_LOG_LAUNCHER
        == Path("/usr/local/bin/devcoordinator-call-log")
        and switch.SYSTEMD_UNIT_LAUNCHER
        == Path("/usr/local/bin/devcoordinator-systemd-unit")
        and switch.IMAGE_LAUNCHER == Path("/usr/local/bin/devcoordinator-image")
        and switch.EDGE_CERT_REFRESH_LAUNCHER
        == Path("/usr/local/bin/devcoordinator-edge-cert-refresh")
        and switch.READ_ONLY_RULE
        == Path("/etc/codex/rules/devcoordinator-read-only.rules")
        and switch.TEST_RULE == Path("/etc/codex/rules/devcoordinator-test.rules"),
        "Coordinator client destinations are not stable system paths",
    )
    expect(
        switch.STABLE_LAUNCHERS.get(switch.MCP_LAUNCHER_RENDERED)
        == (switch.MCP_LAUNCHER, "devcoordinator-mcp"),
        "MCP launcher is absent from the stable activation transaction",
    )
    expect(
        switch.STABLE_LAUNCHERS.get(switch.BUG_LAUNCHER_RENDERED)
        == (switch.BUG_LAUNCHER, "devcoordinator-bug"),
        "bug launcher is absent from the stable activation transaction",
    )
    expect(
        switch.STABLE_LAUNCHERS.get(
            switch.SYSTEMD_UNIT_LAUNCHER_RENDERED
        )
        == (switch.SYSTEMD_UNIT_LAUNCHER, "devcoordinator-systemd-unit"),
        "systemd commissioning launcher is absent from the stable activation transaction",
    )
    expect(
        switch.STABLE_LAUNCHERS.get(switch.IMAGE_LAUNCHER_RENDERED)
        == (switch.IMAGE_LAUNCHER, "devcoordinator-image"),
        "image publication launcher is absent from the stable activation transaction",
    )
    expect(
        switch.STABLE_LAUNCHERS.get(
            switch.EDGE_CERT_REFRESH_LAUNCHER_RENDERED
        )
        == (
            switch.EDGE_CERT_REFRESH_LAUNCHER,
            "devcoordinator-edge-cert-refresh",
        )
        and switch.destination_mode(switch.CERTBOT_HOOK_RENDERED) == 0o700,
        "TLS renewal is not bound to the stable current-format transaction",
    )
    expect(
        all(
            switch.destination_mode(name) == 0o755
            for name in switch.STABLE_LAUNCHERS
        )
        and switch.destination_mode(switch.READ_ONLY_RULE_RENDERED) == 0o644
        and switch.destination_mode(switch.TEST_RULE_RENDERED) == 0o644,
        "Coordinator client artifacts have unsafe installation modes",
    )
    expect(
        switch.codex_directory_mode(switch.CODEX_ROOT) == 0o755
        and switch.codex_directory_mode(switch.CODEX_RULE_ROOT) == 0o755,
        "Codex rule ancestry is not readable by agent accounts",
    )
    rule = (ROOT / "deploy/devcoordinator-test.rules").read_text(encoding="utf-8")
    for command in ("plan", "submit", "summary", "failures", "artifact", "wait"):
        expect(f'"{command}"' in rule, f"Codex test rule omits {command}")
    expect(
        '"manifest"' not in rule and '"runtime"' not in rule,
        "Codex test rule permits a non-lifecycle surface",
    )
    unit = (ROOT / "deploy/devcoordinator-console@.service").read_text(encoding="utf-8")
    expect(
        "RuntimeDirectoryPreserve=yes" in unit,
        "one slot stop can still delete another live slot's control socket",
    )


def exercise_stable_client_destination_transaction() -> None:
    with tempfile.TemporaryDirectory(prefix="same-schema-client-paths-") as raw:
        root = Path(raw)
        rendered = root / "rendered"
        rendered.mkdir()
        stable = {
            switch.CLIENT_LAUNCHER_RENDERED: (
                root / "bin/devcoordinator",
                "devcoordinator",
            ),
            switch.MCP_LAUNCHER_RENDERED: (
                root / "bin/devcoordinator-mcp",
                "devcoordinator-mcp",
            ),
            switch.BUG_LAUNCHER_RENDERED: (
                root / "bin/devcoordinator-bug",
                "devcoordinator-bug",
            ),
            switch.TEST_LAUNCHER_RENDERED: (
                root / "bin/devcoordinator-test",
                "devcoordinator-test",
            ),
            switch.CALL_LOG_LAUNCHER_RENDERED: (
                root / "bin/devcoordinator-call-log",
                "devcoordinator-call-log",
            ),
        }
        rule = root / "codex/rules/devcoordinator-test.rules"
        read_only_rule = root / "codex/rules/devcoordinator-read-only.rules"
        sysusers = root / "sysusers"
        tmpfiles = root / "tmpfiles"
        hook_root = root / "certbot-hooks"
        hook_root.mkdir(mode=0o755)
        hook = hook_root / "devcoordinator-edge"
        rendered_names = (
            *stable,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
            switch.MAIN_TMPFILES_RENDERED,
            switch.CERTBOT_HOOK_RENDERED,
            switch.READ_ONLY_RULE_RENDERED,
            switch.TEST_RULE_RENDERED,
        )
        for index, name in enumerate(rendered_names):
            (rendered / name).write_bytes(f"candidate-{index}\n".encode())

        with (
            mock.patch.object(switch, "STABLE_LAUNCHERS", stable),
            mock.patch.object(switch, "TOPOLOGY_FILES", ()),
            mock.patch.object(switch, "SYSUSERS_ROOT", sysusers),
            mock.patch.object(switch, "TMPFILES_ROOT", tmpfiles),
            mock.patch.object(switch, "CERTBOT_HOOK_ROOT", hook_root),
            mock.patch.object(switch, "CERTBOT_HOOK", hook),
            mock.patch.object(switch, "READ_ONLY_RULE", read_only_rule),
            mock.patch.object(switch, "TEST_RULE", rule),
        ):
            mapping = switch.destinations(rendered)
            expect(
                {
                    *stable,
                    switch.MAIN_TMPFILES_RENDERED,
                    "devcoordinator-availability.tmpfiles.conf",
                    switch.CERTBOT_HOOK_RENDERED,
                    switch.READ_ONLY_RULE_RENDERED,
                    switch.TEST_RULE_RENDERED,
                }.issubset(mapping),
                "stable client or policy destinations were omitted from the transaction",
            )
            existed: dict[Path, tuple[bytes, int]] = {}
            for index, destination in enumerate(mapping.values()):
                if index % 2:
                    continue
                payload = f"previous-{index}\n".encode()
                mode = 0o700 if destination in {
                    value[0] for value in stable.values()
                } else 0o640
                switch.atomic_bytes(destination, payload, mode)
                existed[destination] = (payload, mode)
            document = {
                "rendered_units": str(rendered),
                "expected_destinations": {
                    str(destination): (
                        switch.digest_file(destination)
                        if destination.exists()
                        else None
                    )
                    for destination in mapping.values()
                },
            }
            backups = switch.backup_destinations(document, root / "transaction")
            expect(
                set(backups) == {str(item) for item in mapping.values()},
                "backup did not bind every stable client destination",
            )
            switch.install_rendered_destinations(rendered)
            for name, destination in mapping.items():
                expect(
                    destination.read_bytes() == (rendered / name).read_bytes()
                    and stat.S_IMODE(destination.stat().st_mode)
                    == switch.destination_mode(name),
                    f"candidate destination was not installed exactly: {name}",
                )
            switch.restore_destination_backups(backups)
            for destination in mapping.values():
                if destination in existed:
                    payload, mode = existed[destination]
                    expect(
                        destination.read_bytes() == payload
                        and stat.S_IMODE(destination.stat().st_mode) == mode,
                        f"rollback did not restore {destination}",
                    )
                else:
                    expect(
                        not destination.exists(),
                        f"rollback retained newly installed {destination}",
                    )


def exercise_codex_execpolicy_boundary() -> None:
    codex = shutil.which("codex")
    if codex is None:
        return
    test_rule = ROOT / "deploy/devcoordinator-test.rules"
    read_only_rule = ROOT / "deploy/devcoordinator-read-only.rules"

    def decision(rule: Path, argv: list[str]) -> str | None:
        completed = subprocess.run(
            [codex, "execpolicy", "check", "--rules", str(rule), "--", *argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        expect(
            completed.returncode == 0,
            f"Codex rejected {rule.name}: {completed.stderr}",
        )
        value = json.loads(completed.stdout)
        return value.get("decision")

    expect(
        decision(
            test_rule,
            ["devcoordinator-test", "submit", "--plan-id", "example"],
        )
        == "allow",
        "test submission is not allowed without a prompt",
    )
    expect(
        decision(
            test_rule,
            [
                "/usr/local/bin/devcoordinator-test",
                "summary",
                "--run-id",
                "example",
            ]
        )
        == "allow",
        "absolute test launcher is not allowed without a prompt",
    )
    expect(
        decision(test_rule, ["devcoordinator-test", "manifest", "init"])
        is None,
        "manifest authoring unexpectedly bypasses approval",
    )
    expect(
        decision(
            test_rule,
            [
                "python3",
                "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
                "test",
                "submit",
            ]
        )
        is None,
        "mutable source entrypoint unexpectedly bypasses approval",
    )

    must_allow = (
        ["devcoordinator", "capabilities"],
        ["/usr/local/bin/devcoordinator", "targets", "service-id"],
        ["devcoordinator", "runtime", "status", "service-id"],
        [
            "/usr/local/bin/devcoordinator",
            "runtime",
            "capture_logs",
            "service-id",
        ],
        ["devcoordinator", "test", "follow", "dc1:run:example"],
        [
            "devcoordinator",
            "operation",
            "follow",
            "dc1:operation:12345678-1234-4234-8234-123456789abc",
        ],
        [
            "/usr/local/bin/devcoordinator",
            "operation",
            "follow",
            "12345678-1234-4234-8234-123456789abc",
        ],
        ["devcoordinator-call-log", "--limit", "5"],
        ["/usr/local/bin/devcoordinator-call-log", "--failures-only"],
        ["devcoordinator", "bug", "list", "--limit", "5"],
        [
            "/usr/local/bin/devcoordinator",
            "bug",
            "report",
            "--component",
            "testd",
        ],
        ["devcoordinator", "bug", "close", "bug-" + "a" * 32],
        ["devcoordinator-bug", "list", "--limit", "5"],
        [
            "/usr/local/bin/devcoordinator-bug",
            "report",
            "--component",
            "testd",
        ],
        ["devcoordinator-bug", "close", "bug-" + "a" * 32],
    )
    for argv in must_allow:
        expect(
            decision(read_only_rule, argv) == "allow",
            f"bounded read-only client call requires approval: {argv}",
        )

    must_not_allow = (
        ["devcoordinator", "--project", "/tmp/project", "capabilities"],
        ["devcoordinator", "runtime", "ensure", "service-id"],
        ["devcoordinator", "runtime", "start", "service-id"],
        ["devcoordinator", "runtime", "stop", "service-id"],
        ["devcoordinator", "runtime", "restart", "service-id"],
        ["devcoordinator", "test", "enqueue"],
        ["devcoordinator", "test", "submit", "dc1:plan:example"],
        [
            "devcoordinator",
            "--project",
            "/tmp/project",
            "operation",
            "follow",
            "12345678-1234-4234-8234-123456789abc",
        ],
        [
            "python3",
            "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
            "capabilities",
        ],
        ["python3", "scripts/read_coordinator_call_log.py"],
        ["devcoordinator-mcp", "--help"],
        ["/usr/local/bin/devcoordinator-mcp", "--version"],
    )
    for argv in must_not_allow:
        expect(
            decision(read_only_rule, argv) is None,
            f"non-read-only or mutable-source call bypassed approval: {argv}",
        )


def exercise_codex_directory_transaction() -> None:
    with tempfile.TemporaryDirectory(prefix="same-schema-codex-rules-") as raw:
        root = Path(raw) / "codex"
        rules = root / "rules"
        rules.mkdir(parents=True)
        root.chmod(0o700)
        rules.chmod(0o700)
        with (
            mock.patch.object(switch, "CODEX_ROOT", root),
            mock.patch.object(switch, "CODEX_RULE_ROOT", rules),
        ):
            prior = switch.codex_directory_states()
            switch.prepare_codex_directories(prior)
            expect(
                stat.S_IMODE(root.stat().st_mode) == 0o755
                and stat.S_IMODE(rules.stat().st_mode) == 0o755,
                "Codex rule ancestry remained unreadable to agent accounts",
            )
            switch.restore_codex_directories(prior)
            expect(
                stat.S_IMODE(root.stat().st_mode) == 0o700
                and stat.S_IMODE(rules.stat().st_mode) == 0o700,
                "Codex rule ancestry modes were not restored exactly",
            )

    with tempfile.TemporaryDirectory(prefix="same-schema-codex-create-") as raw:
        root = Path(raw) / "codex"
        rules = root / "rules"
        with (
            mock.patch.object(switch, "CODEX_ROOT", root),
            mock.patch.object(switch, "CODEX_RULE_ROOT", rules),
        ):
            prior = switch.codex_directory_states()
            switch.prepare_codex_directories(prior)
            expect(root.is_dir() and rules.is_dir(), "Codex rule ancestry was not created")
            switch.restore_codex_directories(prior)
            expect(not root.exists(), "new Codex rule ancestry survived rollback")


def exercise_opt_in_test_history_reset_and_previous_release_rollback() -> None:
    forward_source = inspect.getsource(switch.reset_test_history_for_release)
    rollback_source = inspect.getsource(switch.reset_test_history_for_rollback)
    expect(
        forward_source.index("stop_test_plane(")
        < forward_source.index("discard_test_spool(")
        < forward_source.index("run_test_history_command("),
        "forward reset does not stop testd before replacing spool and store",
    )
    expect(
        rollback_source.index("stop_test_plane(")
        < rollback_source.index("discard_test_spool(")
        < rollback_source.index("discard_test_store_triplet("),
        "rollback does not stop testd before replacing spool and store",
    )
    with tempfile.TemporaryDirectory(prefix="same-schema-test-reset-") as raw:
        root = Path(raw)
        releases = root / "releases"
        current = releases / DIGEST
        previous = releases / ("b" * 64)
        for release in (current, previous):
            wrapper = release / "bin" / switch.TEST_HISTORY_WRAPPER
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            wrapper.chmod(0o755)
        database = root / "testd" / "tests.sqlite3"
        database.parent.mkdir()
        spool = database.parent / "spool"
        spool.mkdir()
        (spool / "legacy-attempt.json").write_text("disposable", encoding="utf-8")
        journal = root / "journal.json"
        runner = HistoryRunner()
        with (
            mock.patch.object(switch, "TEST_DATABASE", database),
            mock.patch.object(switch, "TEST_SPOOL", spool),
            mock.patch.object(switch, "testd_uid", return_value=1234),
            mock.patch.object(switch.os, "chown"),
        ):
            document: dict[str, object] = {
                "schema_version": switch.VERSION,
                "kind": switch.KIND,
                "phase": "prepared",
                "release": str(current),
                "release_digest": DIGEST,
                "previous_release_digest": "b" * 64,
            }
            document["test_history_reset"] = switch.test_history_reset_intent(
                current, previous_release_digest="b" * 64
            )
            switch.atomic_json(journal, document)
            switch.reset_test_history_for_release(
                current, document, journal, runner
            )
            reset = document["test_history_reset"]
            expect(
                isinstance(reset, dict) and reset.get("status") == "complete",
                "forward test-history reset was not journaled",
            )
            expect(
                reset["forward_evidence"]["schema_version"] == 7,
                "forward reset did not attest schema 7",
            )
            expect(
                reset["forward_evidence"]["spool"]["fresh"] is True,
                "forward reset did not attest a fresh attempt spool",
            )
            expect(
                {path.name for path in spool.iterdir()}
                == set(switch.TEST_SPOOL_QUEUES)
                and all(not any(path.iterdir()) for path in spool.iterdir()),
                "forward reset retained disposable attempt evidence",
            )
            initialize = next(
                command
                for command in runner.commands
                if "initialize-fresh" in command
            )
            stop = next(
                command
                for command in runner.commands
                if command[:3] == ["/usr/bin/systemctl", "stop", switch.TESTD_SOCKET]
            )
            expect(
                runner.commands.index(stop) < runner.commands.index(initialize),
                "test-history reset ran before testd/socket were stopped",
            )
            expect(
                str(current / "bin" / switch.TEST_HISTORY_WRAPPER) in initialize
                and "discard-test-history" in initialize,
                "forward reset did not use the packaged explicit-discard wrapper",
            )

            unrelated = database.parent / "authority.sqlite3"
            unrelated.write_text("preserve", encoding="utf-8")
            for path in switch.test_store_paths():
                path.write_text("disposable", encoding="utf-8")
            (spool / "active" / "new-release-attempt.json").write_text(
                "also disposable", encoding="utf-8"
            )
            runner.commands.clear()
            switch.reset_test_history_for_rollback(document, journal, runner)
            reset = document["test_history_reset"]
            expect(
                isinstance(reset, dict) and reset.get("status") == "rolled-back",
                "rollback test-history reset was not journaled",
            )
            expect(unrelated.read_text(encoding="utf-8") == "preserve", "rollback touched another store")
            expect(
                all(not path.exists() for path in switch.test_store_paths()),
                "rollback retained a member of the disposable test-store triplet",
            )
            expect(
                {path.name for path in spool.iterdir()}
                == set(switch.TEST_SPOOL_QUEUES)
                and all(not any(path.iterdir()) for path in spool.iterdir()),
                "rollback retained disposable attempt spool evidence",
            )
            create = next(command for command in runner.commands if "create" in command)
            expect(
                str(previous / "bin" / switch.TEST_HISTORY_WRAPPER) in create,
                "rollback did not require the previous current-format test-store wrapper",
            )
            expect(
                reset["rollback_evidence"]["schema_version"] == 5,
                "rollback did not initialize an empty schema-5 store",
            )


def exercise_reset_cli_is_explicit() -> None:
    for action in (
        "prepare",
        "apply",
        "rollback",
        "verify",
        "acceptance-begin",
        "finalize",
    ):
        arguments = [
            action,
            "--release",
            f"/opt/devcoordinator/releases/{DIGEST}",
            "--transaction-root",
            "/tmp/transaction",
            "--reset-test-history",
        ]
        parsed = switch.parser().parse_args(arguments)
        expect(parsed.reset_test_history is True, f"{action} lost explicit reset flag")


def exercise_software_delivery_fence_lifecycle() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    with tempfile.TemporaryDirectory(prefix="same-schema-delivery-fence-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        release = root / "releases" / DIGEST
        release.mkdir(parents=True)
        release_b = root / "releases" / ("b" * 64)
        release_b.mkdir()
        lock = root / "installer.lock"
        claim_root = root / "claims"
        claim_root.mkdir(mode=0o700)
        claim = claim_root / "installer-claim.json"
        slot_root = root / "slots"
        unit_root = root / "units"
        slot_root.mkdir(mode=0o700)
        unit_root.mkdir(mode=0o700)
        publication_file = root / "routes.publication"
        transaction_a = root / "run-a" / DIGEST
        transaction_b = root / "run-b" / release_b.name
        for transaction in (transaction_a, transaction_b):
            transaction.mkdir(parents=True, mode=0o700)
            transaction.parent.chmod(0o700)
            transaction.chmod(0o700)

        crashed, _identity = switch.acquire_delivery_fence(
            transaction_a,
            release_digest=DIGEST,
            action="prepare",
            expected_uid=uid,
            expected_gid=gid,
            lock_path=lock,
            claim_path=claim,
        )
        crashed.close(command_succeeded=False)
        recovered, _identity = switch.acquire_delivery_fence(
            transaction_a,
            release_digest=DIGEST,
            action="recover",
            expected_uid=uid,
            expected_gid=gid,
            lock_path=lock,
            claim_path=claim,
        )
        recovered.close(command_succeeded=True)

        prepare_calls: list[Path] = []
        rollback_calls: list[Path] = []
        active: dict[str, str | None] = {"release": None}
        healthy = {"value": True}

        def prepared(selected_release, transaction, _runner, **_kwargs):
            prepare_calls.append(transaction)
            return {
                "phase": "prepared",
                "release": str(selected_release),
                "release_digest": selected_release.name,
            }

        def applied(selected_release, transaction, _runner, **_kwargs):
            active["release"] = str(selected_release)
            outer = 41001 if selected_release == release else 42001
            inner = outer + 1
            rendered = transaction / "rendered-units"
            rendered.mkdir(mode=0o700, exist_ok=True)
            unit_payload = f"release={selected_release.name}\n".encode("ascii")
            switch.atomic_bytes(
                rendered / "devcoordinator-console@.service", unit_payload, 0o644
            )
            switch.atomic_bytes(
                unit_root / "devcoordinator-console@.service", unit_payload, 0o644
            )
            switch.atomic_bytes(
                slot_root / f"{selected_release.name}.env",
                switch.candidate_slot_payload(selected_release.name, outer, inner),
                0o644,
            )
            switch.atomic_json(
                publication_file,
                {
                    "payload_sha256": "f" * 64,
                    "publication": {
                        "release_digest": selected_release.name,
                        "generation": 7,
                        "console": {"upstream": {"port": outer}},
                    },
                },
            )
            value = {
                "phase": "applied",
                "release": str(selected_release),
                "release_digest": selected_release.name,
                "candidate_console_unit": (
                    f"devcoordinator-console@{selected_release.name}.service"
                ),
                "candidate_console_slot": str(
                    slot_root / f"{selected_release.name}.env"
                ),
                "candidate_outer_port": outer,
                "candidate_inner_port": inner,
                "candidate_control_socket": (
                    f"/run/devcoordinator-console/{selected_release.name}.sock"
                ),
                "rendered_units": str(rendered),
            }
            switch.atomic_json(
                transaction / "journal.json",
                {"schema_version": switch.VERSION, "kind": switch.KIND, **value},
            )
            return value

        def rolled_back(selected_release, transaction, _runner, **_kwargs):
            rollback_calls.append(transaction)
            active["release"] = None
            value = {
                "phase": "rolled-back",
                "release": str(selected_release),
                "release_digest": selected_release.name,
            }
            switch.atomic_json(
                transaction / "journal.json",
                {"schema_version": switch.VERSION, "kind": switch.KIND, **value},
            )
            return value

        def verified(selected_release, _transaction, _runner, **_kwargs):
            return {
                "ok": (
                    active["release"] == str(selected_release)
                    and healthy["value"]
                ),
                "phase": "verified",
                "release_digest": selected_release.name,
            }

        root_args = {
            "expected_uid": uid,
            "expected_gid": gid,
            "lock_path": lock,
            "claim_path": claim,
        }
        transaction_passthrough = mock.patch.object(
            switch,
            "require_transaction_root",
            side_effect=lambda path, **_kwargs: path,
        )
        with transaction_passthrough, mock.patch.object(
            switch, "prepare", side_effect=prepared
        ), mock.patch.object(switch, "apply", side_effect=applied), mock.patch.object(
            switch, "rollback", side_effect=rolled_back
        ), mock.patch.object(
            switch, "verify", side_effect=verified
        ), mock.patch.object(
            switch, "SLOT_ROOT", slot_root
        ), mock.patch.object(
            switch, "UNIT_ROOT", unit_root
        ), mock.patch.object(
            switch, "PUBLICATION_FILE", publication_file
        ):
            switch.execute_fenced_switch_action(
                "prepare", release, transaction_a, FakeRunner(), **root_args
            )
            try:
                switch.execute_fenced_switch_action(
                    "prepare", release_b, transaction_b, FakeRunner(), **root_args
                )
            except switch.installer_fence.InstallerFenceError:
                pass
            else:
                raise AssertionError("a distinct delivery entered prepare")
            expect(
                prepare_calls == [transaction_a],
                "the second run reached prepare before obtaining the host claim",
            )
            switch.execute_fenced_switch_action(
                "apply", release, transaction_a, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "rollback", release, transaction_a, FakeRunner(), **root_args
            )

            switch.execute_fenced_switch_action(
                "prepare", release_b, transaction_b, FakeRunner(), **root_args
            )
            with mock.patch.object(
                switch, "rollback", side_effect=switch.SwitchError("rollback failed")
            ):
                try:
                    switch.execute_fenced_switch_action(
                        "rollback", release_b, transaction_b, FakeRunner(), **root_args
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError("failed rollback unexpectedly succeeded")
            try:
                switch.execute_fenced_switch_action(
                    "prepare", release, transaction_a, FakeRunner(), **root_args
                )
            except switch.installer_fence.InstallerFenceError:
                pass
            else:
                raise AssertionError("failed rollback released the host claim")
            switch.execute_fenced_switch_action(
                "rollback", release_b, transaction_b, FakeRunner(), **root_args
            )

            switch.execute_fenced_switch_action(
                "prepare", release, transaction_a, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "apply", release, transaction_a, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "finalize", release, transaction_a, FakeRunner(), **root_args
            )

            real_acquire = switch.acquire_delivery_fence

            def acquire_then_change_terminal(*args, **kwargs):
                handle, identity = real_acquire(*args, **kwargs)
                switch.delivery_fence_terminal(
                    transaction_a,
                    identity,
                    expected_uid=uid,
                    expected_gid=gid,
                    publish_outcome="rolled-back",
                )
                return handle, identity

            with mock.patch.object(
                switch,
                "acquire_delivery_fence",
                side_effect=acquire_then_change_terminal,
            ):
                try:
                    switch.execute_fenced_switch_action(
                        "acceptance-begin",
                        release,
                        transaction_a,
                        FakeRunner(),
                        **root_args,
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError("changed acceptance terminal was accepted")
            probe, _identity = switch.acquire_delivery_fence(
                transaction_b,
                release_digest=release_b.name,
                action="prepare",
                expected_uid=uid,
                expected_gid=gid,
                lock_path=lock,
                claim_path=claim,
            )
            probe.mark_complete()
            probe.close(command_succeeded=True)
            switch.execute_fenced_switch_action(
                "finalize", release, transaction_a, FakeRunner(), **root_args
            )

            switch.execute_fenced_switch_action(
                "prepare", release_b, transaction_b, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "apply", release_b, transaction_b, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "finalize", release_b, transaction_b, FakeRunner(), **root_args
            )
            stale_acceptance = switch.execute_fenced_switch_action(
                "acceptance-begin",
                release,
                transaction_a,
                FakeRunner(),
                **root_args,
            )
            expect(
                stale_acceptance.get("ok") is False,
                "stale acceptance did not retain its failed verification",
            )
            try:
                switch.execute_fenced_switch_action(
                    "finalize", release, transaction_a, FakeRunner(), **root_args
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("stale finalize unexpectedly succeeded")
            rollback_count = len(rollback_calls)
            try:
                switch.execute_fenced_switch_action(
                    "rollback", release, transaction_a, FakeRunner(), **root_args
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("late stale rollback unexpectedly started")
            expect(
                len(rollback_calls) == rollback_count
                and active["release"] == str(release_b),
                "late stale rollback mutated the current release",
            )
            switch.execute_fenced_switch_action(
                "finalize", release_b, transaction_b, FakeRunner(), **root_args
            )

            healthy["value"] = False
            rollback_count = len(rollback_calls)
            switch.execute_fenced_switch_action(
                "rollback", release_b, transaction_b, FakeRunner(), **root_args
            )
            expect(
                len(rollback_calls) == rollback_count + 1,
                "unhealthy exact-live release did not enter late rollback",
            )
            switch.execute_fenced_switch_action(
                "rollback", release_b, transaction_b, FakeRunner(), **root_args
            )
            expect(
                len(rollback_calls) == rollback_count + 1,
                "idempotent rollback repeated host mutation",
            )
            healthy["value"] = True
            switch.execute_fenced_switch_action(
                "prepare", release_b, transaction_b, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "apply", release_b, transaction_b, FakeRunner(), **root_args
            )
            switch.execute_fenced_switch_action(
                "finalize", release_b, transaction_b, FakeRunner(), **root_args
            )
            healthy["value"] = False

            def fail_after_rollback_mutation(
                _release, transaction, _runner, **_kwargs
            ):
                rollback_calls.append(transaction)
                active["release"] = None
                raise switch.SwitchError("rollback failed after mutation")

            with mock.patch.object(
                switch, "rollback", side_effect=fail_after_rollback_mutation
            ):
                try:
                    switch.execute_fenced_switch_action(
                        "rollback", release_b, transaction_b, FakeRunner(), **root_args
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError("post-mutation rollback unexpectedly succeeded")
            try:
                switch.execute_fenced_switch_action(
                    "prepare", release, transaction_a, FakeRunner(), **root_args
                )
            except switch.installer_fence.InstallerFenceError:
                pass
            else:
                raise AssertionError("post-mutation rollback failure released its claim")
            switch.execute_fenced_switch_action(
                "rollback", release_b, transaction_b, FakeRunner(), **root_args
            )


def exercise_retained_control_transaction_boundary() -> None:
    apply_source = inspect.getsource(switch.apply_retained_control_rebaseline)
    rollback_source = inspect.getsource(switch.restore_retained_control_rebaseline)
    switch_source = inspect.getsource(switch.apply)
    verify_source = inspect.getsource(switch.verify)
    expect(
        apply_source.index("stop_authority_writers(runner)")
        < apply_source.index("prepare_rebaseline("),
        "retained-control export can run while authority/API writers are live",
    )
    expect(
        apply_source.index("stop_console_writers(document, runner)")
        < apply_source.index("prepare_rebaseline("),
        "Console controls can be exported while a Console writer is live",
    )
    expect(
        "_retained_backup_destinations(transaction_root)" in apply_source
        and apply_source.index("_retained_backup_destinations(transaction_root)")
        < apply_source.index("prepare_rebaseline("),
        "retained-control preparation is not preceded by exact DB/profile backups",
    )
    expect(
        "apply_retained_control_rebaseline(" in switch_source
        and switch_source.index("apply_retained_control_rebaseline(")
        < switch_source.index("restart_services(runner)"),
        "retained-control publication is not inside the stopped-writer switch window",
    )
    expect(
        apply_source.index("stop_authority_writers(runner)")
        < apply_source.index("bind_source_worker_quiescence(")
        < apply_source.index("post_stop_proof = source_worker_quiescence_proof(")
        < apply_source.index("_checkpoint_authority_database()"),
        "source worker proof is not frozen after writer shutdown",
    )
    expect(
        switch_source.index("stop_authority_writers(runner)")
        < switch_source.index("bind_source_worker_quiescence(")
        < switch_source.index("install_rendered_destinations(rendered)")
        and switch_source.index("stop_authority_writers(runner)")
        < switch_source.index("install_rendered_destinations(rendered)")
        < switch_source.index("perform_headless_browser_cleanup("),
        "writer freeze and worker proof run after apply-time destination mutation",
    )
    expect(
        "_server_credential_backup_destinations(" in apply_source
        and apply_source.index("_server_credential_backup_destinations(")
        < apply_source.index('"status": "prepared"')
        and apply_source.index("_publish_server_credentials(")
        < apply_source.index("_publish_owned_copy(\n            AUTHORITY_DATABASE,"),
        "retained server credentials are not backup-bound before atomic publication",
    )
    expect(
        "stop_authority_writers(runner)" in rollback_source
        and "_restore_retained_files(backups, credentials)" in rollback_source,
        "retained-control rollback does not restore exact backups while writers are stopped",
    )
    expect(
        {
            "devcoordinator-testd.socket",
            "devcoordinator-test-snapshotd.socket",
            "devcoordinator-testd.service",
            "devcoordinator-test-snapshotd.service",
        }.issubset(switch.AUTHORITY_WRITER_UNITS),
        "retained-control replacement leaves a direct authority reader or caller live",
    )
    expect(
        "_restore_retained_files(backups, credentials)" in apply_source
        and apply_source.index("_restore_retained_files(backups, credentials)")
        < apply_source.index("_publish_server_credentials("),
        "partial retained-control publication does not converge from the exact backup",
    )
    expect(
        "unlink_regular_and_fsync" in inspect.getsource(switch._restore_exact_file),
        "absent-file rollback is not durably fsynced",
    )
    expect(
        "_cleanup_server_credential_temporaries(" in apply_source
        and "_cleanup_server_credential_temporaries("
        in rollback_source
        and "_cleanup_server_credential_temporaries("
        in inspect.getsource(switch._require_exact_live_retained_target),
        "credential atomic remnants are not cleaned on replay, rollback, and verify",
    )
    expect(
        switch_source.index("candidate_already_active = unit_active")
        < switch_source.index("bind_exact_ports(ports)")
        and "reservations = [] if candidate_already_active else" in switch_source,
        "candidate-start crash replay still collides with its own exact ports",
    )
    expect(
        'document.get("phase") != "applied"' in verify_source
        and "_load_bound_retained_manifest(" in verify_source
        and "_require_live_retained_generation(manifest)" in verify_source,
        "verification can accept an applying or generation-unbound rebaseline",
    )

    with tempfile.TemporaryDirectory(prefix="retained-control-exact-backup-") as raw:
        root = Path(raw)
        source = root / "source"
        backup = root / "backup"
        staged = root / "staged"
        source.write_bytes(b"exact-before" * 300_000)
        staged.write_bytes(b"current-after" * 300_000)
        source.chmod(0o640)
        old_digest = switch.digest_file(source)
        new_digest = switch.digest_file(staged)
        original_read_bytes = Path.read_bytes

        def bounded_read_bytes(path: Path) -> bytes:
            if path in {source, backup, staged}:
                raise AssertionError("authority DB path used unbounded read_bytes")
            return original_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", bounded_read_bytes):
            evidence = switch._backup_exact_file(source, backup, required=True)
            switch._publish_owned_copy(
                source,
                staged,
                evidence,
                expected_sha256=new_digest,
            )
            expect(
                switch.digest_file(source) == new_digest,
                "retained authority publication did not install the staged database",
            )
            # Model a failure immediately after database publication: exact
            # rollback restores the predecessor, and the same prepared target
            # remains safe to replay.
            switch._restore_exact_file(source, evidence)
            expect(
                switch.digest_file(source) == old_digest,
                "failure-after-publication rollback changed authority bytes",
            )
            switch._publish_owned_copy(
                source,
                staged,
                evidence,
                expected_sha256=new_digest,
            )
        expect(
            switch.digest_file(source) == new_digest,
            "retained authority replay did not reproduce the staged database",
        )
        expect(
            stat.S_IMODE(source.stat().st_mode) == 0o640,
            "exact rollback changed file mode",
        )


def exercise_retained_server_credential_transaction() -> None:
    secret = "postgresql://synthetic:never-journal-this@database.invalid/app"
    old_secret = b"predecessor-credential"
    server_a = "server-a"
    server_b = "server-b"
    name_a = "DATABASE_URL"
    name_b = "API_TOKEN"
    credential_a = server_credential_id(server_a, name_a)
    credential_b = server_credential_id(server_b, name_b)

    with tempfile.TemporaryDirectory(prefix="retained-server-credentials-") as raw:
        root = Path(raw)
        transaction = root / "transaction"
        transaction.mkdir(mode=0o700)
        retained = transaction / "retained-control"
        retained.mkdir(mode=0o700)
        staged_root = retained / "server-credentials"
        staged_root.mkdir(mode=0o700)
        backup_parent = transaction / "retained-control-backups"
        backup_parent.mkdir(mode=0o700)
        live_root = root / "live-server-credentials"
        live_root.mkdir(mode=0o700)

        staged_values = {
            credential_a: secret.encode("utf-8"),
            credential_b: b"synthetic-api-token",
        }
        staged_paths: dict[str, Path] = {}
        for credential_id, payload in staged_values.items():
            path = staged_root / f"{credential_id}.credential"
            path.write_bytes(payload)
            path.chmod(0o600)
            staged_paths[credential_id] = path

        def manifest() -> dict[str, object]:
            values = [
                {
                    "server_definition_id": server_a,
                    "name": name_a,
                    "credential_id": credential_a,
                    "material": switch.exact_file_identity(
                        staged_paths[credential_a]
                    ),
                },
                {
                    "server_definition_id": server_b,
                    "name": name_b,
                    "credential_id": credential_b,
                    "material": switch.exact_file_identity(
                        staged_paths[credential_b]
                    ),
                },
            ]
            return {"server_credentials": values}

        failures: list[str] = []

        def must_reject(callback, label: str) -> None:
            try:
                callback()
            except switch.SwitchError as error:
                failures.append(str(error))
            else:
                raise AssertionError(label)

        baseline = manifest()
        reversed_manifest = {
            "server_credentials": list(
                reversed(baseline["server_credentials"])
            )
        }
        must_reject(
            lambda: switch._server_credentials_from_manifest(
                reversed_manifest, transaction
            ),
            "unordered staged server credential evidence was accepted",
        )
        noncanonical = manifest()
        noncanonical["server_credentials"][0]["credential_id"] = (
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        )
        must_reject(
            lambda: switch._server_credentials_from_manifest(
                noncanonical, transaction
            ),
            "noncanonical staged server credential identity was accepted",
        )

        class ExcessiveCredentialList(list):
            def __len__(self) -> int:
                return switch.retained_control.MAX_ROWS_PER_COLLECTION + 1

        must_reject(
            lambda: switch._server_credentials_from_manifest(
                {"server_credentials": ExcessiveCredentialList()}, transaction
            ),
            "excessive staged server credential evidence was accepted",
        )

        baseline = manifest()
        staged_paths[credential_b].unlink()
        must_reject(
            lambda: switch._server_credentials_from_manifest(
                baseline, transaction
            ),
            "missing staged server credential was accepted",
        )
        staged_paths[credential_b].write_bytes(staged_values[credential_b])
        staged_paths[credential_b].chmod(0o600)

        baseline = manifest()
        staged_paths[credential_b].write_bytes(b"changed-staged-credential")
        must_reject(
            lambda: switch._server_credentials_from_manifest(
                baseline, transaction
            ),
            "changed staged server credential was accepted",
        )
        staged_paths[credential_b].write_bytes(staged_values[credential_b])
        staged_paths[credential_b].chmod(0o600)

        external = root / "external-credential"
        external.write_bytes(staged_values[credential_b])
        external.chmod(0o600)
        baseline = manifest()
        staged_paths[credential_b].unlink()
        staged_paths[credential_b].symlink_to(external)
        must_reject(
            lambda: switch._server_credentials_from_manifest(
                baseline, transaction
            ),
            "symlinked staged server credential was accepted",
        )
        staged_paths[credential_b].unlink()
        staged_paths[credential_b].write_bytes(staged_values[credential_b])
        staged_paths[credential_b].chmod(0o600)

        current_manifest = manifest()
        expect(secret not in json.dumps(current_manifest), "manifest contains a credential value")
        with mock.patch.object(
            switch, "SERVER_CREDENTIAL_MATERIAL_ROOT", live_root
        ):
            credentials = switch._server_credentials_from_manifest(
                current_manifest, transaction
            )
            live_a = live_root / f"{credential_a}.credential"
            live_b = live_root / f"{credential_b}.credential"
            live_a.write_bytes(old_secret)
            live_a.chmod(0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                backups = switch._server_credential_backup_destinations(
                    credentials, transaction
                )
                expect(
                    secret not in json.dumps(backups),
                    "credential backup evidence contains credential bytes",
                )
                backup_root = (
                    transaction
                    / "retained-control-backups/server-credentials"
                )
                live_orphan = live_root / (
                    f".{credential_a}.credential.123."
                    + "a" * 32
                    + ".tmp"
                )
                backup_orphan = backup_root / (
                    f".{credential_b}.credential.456."
                    + "b" * 32
                    + ".tmp"
                )
                for orphan in (live_orphan, backup_orphan):
                    orphan.write_bytes(b"partial-secret-bytes")
                    orphan.chmod(0o600)
                removed = switch._cleanup_server_credential_temporaries(
                    credentials, transaction
                )
                expect(
                    removed == 2
                    and not live_orphan.exists()
                    and not backup_orphan.exists(),
                    "credential replay did not remove exact atomic remnants",
                )
                unsafe_orphan = live_root / (
                    f".{credential_a}.credential.789."
                    + "c" * 32
                    + ".tmp"
                )
                unsafe_orphan.symlink_to(staged_paths[credential_a])
                must_reject(
                    lambda: switch._cleanup_server_credential_temporaries(
                        credentials, transaction
                    ),
                    "unsafe credential atomic remnant was removed",
                )
                unsafe_orphan.unlink()

                authority_root = root / "authority"
                profile_root = root / "profile"
                console_root = root / "console"
                for directory in (authority_root, profile_root, console_root):
                    directory.mkdir(mode=0o700)
                authority = authority_root / "authority.sqlite3"
                profile = profile_root / "client-profiles.json"
                authority.write_bytes(b"old-authority")
                profile.write_bytes(b"old-profile")
                console_paths = {
                    name: console_root / name
                    for name in switch.retained_control.CONSOLE_FILES
                }
                for name, path in console_paths.items():
                    path.write_bytes(f"old-{name}".encode("utf-8"))
                with (
                    mock.patch.object(switch, "AUTHORITY_DATABASE", authority),
                    mock.patch.object(switch, "CLIENT_PROFILE", profile),
                    mock.patch.object(switch, "CONSOLE_STATE_ROOT", console_root),
                ):
                    core_backups = {
                        str(authority): switch._backup_exact_file(
                            authority,
                            backup_parent / "authority.sqlite3",
                            required=True,
                        ),
                        str(profile): switch._backup_exact_file(
                            profile,
                            backup_parent / "client-profiles.json",
                            required=True,
                        ),
                        **{
                            str(path): switch._backup_exact_file(
                                path,
                                backup_parent / f"console-{name}",
                                required=False,
                            )
                            for name, path in console_paths.items()
                        },
                    }
                    bound_backups = {**core_backups, **backups}
                    intent = {
                        "backups": bound_backups,
                        "manifest": str(retained / "retained-control.json"),
                    }
                    expect(
                        secret not in json.dumps(intent),
                        "credential transaction journal contains credential bytes",
                    )
                    switch.validate_retained_rebaseline_paths(
                        intent, transaction
                    )
                    binding_manifest = {
                        **current_manifest,
                        "source": {
                            "schema_version": switch.retained_control.REBASELINE_SOURCE_SCHEMA,
                            "database": core_backups[str(authority)]["source"],
                            "profile": core_backups[str(profile)]["source"],
                        },
                        "console_sources": {
                            name: core_backups[str(path)]["source"]
                            for name, path in console_paths.items()
                        },
                    }
                    switch._validate_manifest_backup_binding(
                        binding_manifest, bound_backups, credentials
                    )
                    incomplete = dict(bound_backups)
                    incomplete.pop(str(live_b))
                    must_reject(
                        lambda: switch._validate_manifest_backup_binding(
                            binding_manifest, incomplete, credentials
                        ),
                        "credential manifest accepted an incomplete backup set",
                    )

                # Model a process loss after the first credential publication.
                switch._publish_server_credentials(
                    {credential_a: credentials[credential_a]}, backups
                )
                expect(
                    live_a.read_bytes() == staged_values[credential_a],
                    "partial credential publication did not publish the exact first file",
                )
                switch._restore_server_credentials(credentials, backups)
                expect(
                    live_a.read_bytes() == old_secret and not live_b.exists(),
                    "partial credential recovery did not restore the exact predecessor",
                )

                # Exact restore followed by publication is replay-safe.
                for _index in range(2):
                    switch._restore_server_credentials(credentials, backups)
                    switch._publish_server_credentials(credentials, backups)
                    switch._require_exact_live_server_credentials(credentials)

                live_b.unlink()
                must_reject(
                    lambda: switch._require_exact_live_server_credentials(
                        credentials
                    ),
                    "missing live server credential was accepted",
                )
                switch._restore_server_credentials(credentials, backups)
                switch._publish_server_credentials(credentials, backups)

                live_b.write_bytes(b"changed-live-credential")
                live_b.chmod(0o600)
                must_reject(
                    lambda: switch._require_exact_live_server_credentials(
                        credentials
                    ),
                    "changed live server credential was accepted",
                )
                switch._restore_server_credentials(credentials, backups)
                switch._publish_server_credentials(credentials, backups)

                live_b.unlink()
                live_b.symlink_to(live_a)
                must_reject(
                    lambda: switch._require_exact_live_server_credentials(
                        credentials
                    ),
                    "symlinked live server credential was accepted",
                )
                live_b.unlink()
                switch._restore_server_credentials(credentials, backups)
                switch._publish_server_credentials(credentials, backups)

                extra = live_root / f"{credential_a}.credential.partial"
                extra.write_bytes(b"partial")
                extra.chmod(0o600)
                must_reject(
                    lambda: switch._require_exact_live_server_credentials(
                        credentials
                    ),
                    "extra affected server credential material was accepted",
                )
                extra.unlink()

                switch._restore_server_credentials(credentials, backups)
                expect(
                    live_a.read_bytes() == old_secret and not live_b.exists(),
                    "credential rollback did not restore/remove exact destinations",
                )
                expect(
                    stat.S_IMODE(live_a.stat().st_mode) == 0o600,
                    "credential rollback changed the predecessor mode",
                )
            expect(not output.getvalue(), "credential transaction wrote to stdout")

        expect(
            all(secret not in failure for failure in failures),
            "credential validation error disclosed credential bytes",
        )


def exercise_rebaseline_quiesces_exact_managed_workers() -> None:
    worker_a = "11111111-1111-4111-8111-111111111111"
    worker_b = "22222222-2222-4222-8222-222222222222"

    class InventoryRunner(FakeRunner):
        def __init__(self, output: str) -> None:
            super().__init__()
            self.output = output

        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            return self.output

    unrelated = InventoryRunner(
        "postgresql.service loaded active running database\n"
        "devcoordinator-authority.service loaded active running authority\n"
    )
    expect(
        switch.loaded_managed_worker_ids(unrelated) == (),
        "unrelated services became managed-worker rebaseline blockers",
    )

    active = InventoryRunner(
        f"devcoordinator-worker-{worker_b}.service loaded active running worker\n"
        f"● devcoordinator-worker-{worker_a}.service loaded failed failed worker\n"
    )
    expect(
        switch.loaded_managed_worker_ids(active) == (worker_a, worker_b),
        "managed-worker inventory lost exact canonical identities",
    )
    malformed = InventoryRunner(
        "devcoordinator-worker-not-a-uuid.service loaded active running worker\n"
    )
    try:
        switch.loaded_managed_worker_ids(malformed)
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("malformed managed-worker identity was ignored")

    class CutoverManager:
        def __init__(self, worker_id: str, cgroup_root: Path) -> None:
            self.worker_id = worker_id
            self.loaded = True
            self.active = True
            self.control_group = f"/workers/{worker_id}"
            self.cgroup_root = cgroup_root
            self.remove_timeouts: list[float] = []
            events = cgroup_root.joinpath(
                *self.control_group.split("/")[1:]
            ) / "cgroup.events"
            events.parent.mkdir(parents=True)
            events.write_text("populated 1\n", encoding="ascii")

        def status(
            self, *, worker_id: str, allow_missing: bool = False
        ) -> NativeWorkerState:
            del allow_missing
            expect(worker_id == self.worker_id, "cutover manager targeted another worker")
            return NativeWorkerState(
                worker_id=worker_id,
                manager="systemd",
                unit=f"devcoordinator-worker-{worker_id}.service",
                loaded=self.loaded,
                active=self.active,
                state="running" if self.loaded else "not-found",
                pid=31313 if self.loaded else None,
                exit_status=None,
                control_group=self.control_group if self.loaded else None,
                cgroup_populated=True if self.loaded else None,
            )

        def require_project_isolation(
            self, *, worker_id: str, uid: int, repository_id: str
        ) -> str:
            expect(worker_id == self.worker_id, "isolation used another worker")
            expect(uid > 0 and bool(repository_id), "isolation omitted attribution")
            return switch.project_repository_slice(
                uid=uid, repository_id=repository_id
            )

        def remove(
            self, *, worker_id: str, timeout_seconds: float
        ) -> NativeWorkerState:
            expect(worker_id == self.worker_id, "removal targeted another worker")
            self.remove_timeouts.append(timeout_seconds)
            self.loaded = False
            self.active = False
            events = self.cgroup_root.joinpath(
                *self.control_group.split("/")[1:]
            ) / "cgroup.events"
            events.write_text("populated 0\n", encoding="ascii")
            return self.status(worker_id=worker_id, allow_missing=True)

        def require_control_group_empty(self, control_group: str) -> bool:
            expect(control_group == self.control_group, "cgroup proof changed identity")
            events = self.cgroup_root.joinpath(
                *control_group.split("/")[1:]
            ) / "cgroup.events"
            expect(
                events.read_text(encoding="ascii") == "populated 0\n",
                "cutover accepted a populated cgroup",
            )
            return True

    class ManagedRunner(FakeRunner):
        def __init__(self, manager: CutoverManager) -> None:
            super().__init__()
            self.manager = manager

        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if "list-units" in argv and self.manager.loaded:
                return (
                    f"devcoordinator-worker-{self.manager.worker_id}.service "
                    "loaded active running worker\n"
                )
            return ""

    with tempfile.TemporaryDirectory(prefix="active-worker-cutover-") as raw:
        root = Path(raw)
        database = root / "authority.sqlite3"
        identities = worker_cutover_database(
            database, schema_version=15, running=True
        )
        manager = CutoverManager(str(identities["worker_id"]), root / "cgroup")
        runner = ManagedRunner(manager)
        journal = root / "journal.json"
        document: dict[str, object] = {
            "phase": "prepared",
            "release": str(ROOT),
        }
        intent: dict[str, object] = {}
        with (
            mock.patch.object(switch, "AUTHORITY_DATABASE", database),
            mock.patch.object(
                switch,
                "_candidate_coordinator_script",
                return_value=ROOT / "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
            ),
            mock.patch.object(
                switch,
                "_worker_native_factory",
                return_value=lambda **_values: manager,
            ),
        ):
            proof = switch.bind_source_worker_quiescence(
                document,
                intent,
                journal,
                runner,
                process_observer=lambda _pid, _started: "absent",
                cgroup_root=root / "cgroup",
            )
            expect(
                switch._valid_source_worker_quiescence(proof),
                "active source worker did not produce a valid quiescence proof",
            )
            replay = switch.bind_source_worker_quiescence(
                document,
                intent,
                journal,
                runner,
                process_observer=lambda _pid, _started: "absent",
                cgroup_root=root / "cgroup",
            )
            expect(replay == proof, "source worker quiescence was not replayable")
            intent["status"] = "planned"
            manager.loaded = True
            manager.active = True
            manager.cgroup_root.joinpath(
                *manager.control_group.split("/")[1:]
            ).joinpath("cgroup.events").write_text(
                "populated 1\n", encoding="ascii"
            )
            try:
                switch.bind_source_worker_quiescence(
                    document,
                    intent,
                    journal,
                    runner,
                    process_observer=lambda _pid, _started: "absent",
                    cgroup_root=root / "cgroup",
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("frozen worker proof was refreshed on replay")
        expect(
            manager.remove_timeouts == [45.0],
            "cutover stop was not bounded above 30s",
        )
        connection = sqlite3.connect(database)
        policy = connection.execute(
            "SELECT keep_alive,desired_state,breaker_state,generation "
            "FROM worker_policies WHERE server_definition_id=?",
            (identities["worker_id"],),
        ).fetchone()
        attempt = connection.execute(
            "SELECT state,exit_report_id,crash_event_id FROM worker_attempts "
            "WHERE attempt_id=?",
            (identities["attempt_id"],),
        ).fetchone()
        connection.close()
        expect(
            policy == (1, "running", "armed", 4)
            and attempt == ("running", None, None),
            "writer-frozen quiescence changed policy or recorded a false crash",
        )

        race_database = root / "race-authority.sqlite3"
        race_ids = worker_cutover_database(
            race_database, schema_version=15, running=True
        )
        race_manager = CutoverManager(
            str(race_ids["worker_id"]), root / "race-cgroup"
        )

        class RacingRunner(ManagedRunner):
            def __init__(self, manager: CutoverManager) -> None:
                super().__init__(manager)
                self.inventory_reads = 0

            def require(self, argv: list[str], _label: str) -> str:
                self.commands.append(list(argv))
                if "list-units" not in argv:
                    return ""
                self.inventory_reads += 1
                if self.inventory_reads <= 2 or not self.manager.loaded:
                    return (
                        f"devcoordinator-worker-{self.manager.worker_id}.service "
                        "loaded active running worker\n"
                    )
                return ""

        race_runner = RacingRunner(race_manager)
        race_document: dict[str, object] = {
            "phase": "prepared",
            "release": str(ROOT),
        }
        with (
            mock.patch.object(switch, "AUTHORITY_DATABASE", race_database),
            mock.patch.object(
                switch,
                "_candidate_coordinator_script",
                return_value=ROOT / "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
            ),
            mock.patch.object(
                switch,
                "_worker_native_factory",
                return_value=lambda **_values: race_manager,
            ),
        ):
            try:
                switch.bind_source_worker_quiescence(
                    race_document,
                    {},
                    root / "race-journal.json",
                    race_runner,
                    process_observer=lambda _pid, _started: "absent",
                    cgroup_root=root / "race-cgroup",
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("worker unit restart race passed quiescence")

        missing = CutoverManager(str(identities["worker_id"]), root / "missing-cgroup")
        missing.loaded = False
        missing.active = False
        termination_calls: list[tuple[int, str, float]] = []
        fallback = quiesce_worker_registration(
            manager=missing,
            worker_id=str(identities["worker_id"]),
            execution_uid=os.geteuid() or 1000,
            repository_id=str(identities["repo_id"]),
            process_identities=[
                {"pid": 42424, "process_start_time": "process-start"}
            ],
            timeout_seconds=45.0,
            observer=lambda _pid, _started: "alive",
            terminator=lambda **values: (
                termination_calls.append(
                    (
                        int(values["pid"]),
                        str(values["process_start_time"]),
                        float(values["timeout_seconds"]),
                    )
                )
                or "absent"
            ),
        )
        expect(
            fallback["process_proofs"][0]["state"] == "absent"
            and termination_calls == [(42424, "process-start", 45.0)],
            "missing-runner fallback did not terminate the exact attempt identity",
        )
        receipt = quiesce_worker_registration(
            manager=missing,
            worker_id=str(identities["worker_id"]),
            execution_uid=os.geteuid() or 1000,
            repository_id=str(identities["repo_id"]),
            process_identities=[
                {"pid": 42424, "process_start_time": "process-start"}
            ],
            timeout_seconds=45.0,
            observer=lambda _pid, _started: "mismatch",
        )
        expect(
            receipt["process_proofs"] == [
                {
                    "pid": 42424,
                    "process_start_time": "process-start",
                    "state": "pid_reused",
                }
            ],
            "missing-runner PID reuse was not terminal absence",
        )
        unobservable = CutoverManager(
            str(identities["worker_id"]), root / "unobservable-cgroup"
        )
        unobservable.loaded = False
        unobservable.active = False
        try:
            quiesce_worker_registration(
                manager=unobservable,
                worker_id=str(identities["worker_id"]),
                execution_uid=os.geteuid() or 1000,
                repository_id=str(identities["repo_id"]),
                process_identities=[
                    {"pid": 42424, "process_start_time": "process-start"}
                ],
                timeout_seconds=45.0,
                observer=lambda _pid, _started: "unknown",
            )
        except switch.WorkerControlError:
            pass
        else:
            raise AssertionError("unobservable process identity passed cutover")

    one_policy = InventoryRunner(
        f"devcoordinator-worker-{worker_a}.service loaded active running worker\n"
        f"devcoordinator-worker-{worker_b}.service loaded active running worker\n"
    )
    with tempfile.TemporaryDirectory(prefix="unknown-worker-cutover-") as raw:
        database = Path(raw) / "authority.sqlite3"
        worker_cutover_database(database, schema_version=15, running=False)
        with mock.patch.object(switch, "AUTHORITY_DATABASE", database):
            try:
                switch.quiesce_source_workers({"release": str(ROOT)}, one_policy)
            except switch.SwitchError as error:
                expect(worker_b in str(error), "unknown worker blocker omitted exact identity")
            else:
                raise AssertionError("unattributed managed unit was stopped or ignored")


def exercise_source_worker_quiescence_is_exact_and_race_safe() -> None:
    class EmptyWorkerRunner(FakeRunner):
        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if "list-units" in argv:
                return "postgresql.service loaded active running database\n"
            return ""

    with tempfile.TemporaryDirectory(prefix="worker-source-proof-") as raw:
        root = Path(raw)
        database = root / "authority.sqlite3"
        identities = worker_cutover_database(
            database, schema_version=15, running=False
        )
        runner = EmptyWorkerRunner()
        journal = root / "journal.json"
        document: dict[str, object] = {"phase": "prepared"}
        intent: dict[str, object] = {}
        with mock.patch.object(switch, "AUTHORITY_DATABASE", database):
            proof = switch.source_worker_quiescence_proof(runner)
            intent["source_worker_quiescence"] = proof
            document["retained_control_rebaseline"] = intent
            expect(
                switch._valid_source_worker_quiescence(proof),
                "source worker quiescence proof is not self-validating",
            )
            replayed = switch.bind_source_worker_quiescence(
                document, intent, journal, runner
            )
            expect(replayed == proof, "exact frozen worker proof did not replay")
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE schema_metadata SET state_revision=state_revision+2"
            )
            connection.commit()
            connection.close()
            for bound_status in ("planned", "backed-up", "prepared"):
                try:
                    switch.bind_source_worker_quiescence(
                        {"phase": "applying"},
                        {
                            "status": bound_status,
                            "source_worker_quiescence": proof,
                        },
                        root / f"bind-{bound_status}.json",
                        runner,
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(
                        f"{bound_status} replay accepted frozen-proof drift"
                    )
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE schema_metadata SET state_revision=state_revision-2"
            )
            connection.execute(
                "UPDATE worker_policies SET generation=generation+1 "
                "WHERE server_definition_id=?",
                (identities["worker_id"],),
            )
            connection.commit()
            connection.close()
            try:
                switch.bind_source_worker_quiescence(
                    document, intent, journal, runner
                )
            except switch.SwitchError as error:
                expect(
                    "changed" in str(error),
                    "source race returned an unrelated diagnostic",
                )
            else:
                raise AssertionError("source worker race did not invalidate its proof")

            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE worker_policies SET generation=generation-1 "
                "WHERE server_definition_id=?",
                (identities["worker_id"],),
            )
            connection.execute(
                "UPDATE worker_supervisor_states SET state='fenced' "
                "WHERE server_definition_id=?",
                (identities["worker_id"],),
            )
            connection.commit()
            connection.close()
            fenced = switch.source_worker_quiescence_proof(runner)
            expect(
                fenced["current_attempts"] == [],
                "attempt-free fenced worker was treated as active",
            )

            class ActiveRunner(EmptyWorkerRunner):
                def require(self, argv: list[str], _label: str) -> str:
                    self.commands.append(list(argv))
                    if "list-units" in argv:
                        return (
                            f"devcoordinator-worker-{identities['worker_id']}.service "
                            "loaded active running worker\n"
                        )
                    return ""

            active = ActiveRunner()
            try:
                switch.source_worker_quiescence_proof(active)
            except switch.SwitchError as error:
                expect(
                    str(identities["worker_id"]) in str(error),
                    "source worker blocker omitted its exact identity",
                )
            else:
                raise AssertionError("loaded source worker passed quiescence proof")


def exercise_credentialized_web_worker_convergence() -> None:
    class ConvergenceRunner(FakeRunner):
        def __init__(self, worker_id: str, worker_slice: str, control_group: str) -> None:
            super().__init__()
            self.worker_id = worker_id
            self.worker_slice = worker_slice
            self.control_group = control_group
            self.loaded = True

        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if "list-units" in argv:
                if not self.loaded:
                    return ""
                return (
                    f"devcoordinator-worker-{self.worker_id}.service "
                    "loaded active running worker\n"
                )
            return ""

        def run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(argv))
            if "show" in argv and self.loaded:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "\n".join(
                        (
                            "LoadState=loaded",
                            "ActiveState=active",
                            "SubState=running",
                            "MainPID=41414",
                            f"ControlGroup={self.control_group}",
                            f"Slice={self.worker_slice}",
                        )
                    ),
                    "",
                )
            return subprocess.CompletedProcess(argv, 1, "LoadState=not-found\n", "not found")

    with tempfile.TemporaryDirectory(prefix="credential-worker-convergence-") as raw:
        root = Path(raw)
        source_database = root / "source.sqlite3"
        source_ids = worker_cutover_database(
            source_database, schema_version=15, running=False, role="web"
        )

        class EmptyRunner(FakeRunner):
            def require(self, argv: list[str], _label: str) -> str:
                self.commands.append(list(argv))
                return ""

        with mock.patch.object(switch, "AUTHORITY_DATABASE", source_database):
            source_proof = switch.source_worker_quiescence_proof(EmptyRunner())

        target_database = root / "target.sqlite3"
        target_ids = worker_cutover_database(
            target_database, schema_version=16, running=True, role="web"
        )
        expect(source_ids["worker_id"] == target_ids["worker_id"], "worker fixture drifted")
        transaction = root / "transaction"
        transaction.mkdir(mode=0o700)
        retained = transaction / "retained-control"
        retained.mkdir(mode=0o700)
        staged_root = retained / "server-credentials"
        staged_root.mkdir(mode=0o700)
        staged = staged_root / f"{target_ids['credential_id']}.credential"
        staged.write_bytes(b"synthetic-database-url")
        staged.chmod(0o600)
        manifest = {
            "server_credentials": [
                {
                    "server_definition_id": target_ids["worker_id"],
                    "name": "DATABASE_URL",
                    "credential_id": target_ids["credential_id"],
                    "material": switch.exact_file_identity(staged),
                }
            ]
        }
        live_root = root / "live-credentials"
        live_root.mkdir(mode=0o700)
        control_group = (
            "/devcoordinator.slice/"
            f"devcoordinator-worker-{target_ids['worker_id']}.service"
        )
        cgroup_root = root / "cgroup"
        events = cgroup_root.joinpath(*control_group.split("/")[1:]) / "cgroup.events"
        events.parent.mkdir(parents=True, mode=0o700)
        events.write_text("populated 1\n", encoding="ascii")
        worker_slice = switch.project_repository_slice(
            uid=os.geteuid() or 1000,
            repository_id=str(target_ids["repo_id"]),
        )
        runner = ConvergenceRunner(
            str(target_ids["worker_id"]), worker_slice, control_group
        )
        clock_value = [0.0]

        def clock() -> float:
            return clock_value[0]

        def sleeper(seconds: float) -> None:
            clock_value[0] += seconds

        refresh_calls: list[tuple[str, str, float]] = []

        def status_refresher(
            target: object, timeout_seconds: float
        ) -> dict[str, object]:
            expect(isinstance(target, dict), "status refresh target is not a row")
            refresh_calls.append(
                (
                    str(target["server_definition_id"]),
                    str(target["canonical_root"]),
                    timeout_seconds,
                )
            )
            return {
                "server_definition_id": str(target["server_definition_id"]),
                "repo_id": str(target["repo_id"]),
                "name": str(target["name"]),
                "current_attempt_id": target["current_attempt_id"],
                "keep_alive": True,
                "desired_state": "running",
                "breaker_state": "armed",
                "supervisor_state": "running",
                "ready": True,
                "supervision_ready": True,
                "endpoint_ready": True,
                "state": "running",
            }

        with (
            mock.patch.object(switch, "AUTHORITY_DATABASE", target_database),
            mock.patch.object(
                switch, "SERVER_CREDENTIAL_MATERIAL_ROOT", live_root
            ),
        ):
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
            )
            expect(blockers == (), "credentialized web worker did not converge")
            policy_blockers, _policy_fingerprint = (
                switch._retained_worker_policy_blockers(
                    runner,
                    source_proof=source_proof,
                    target_schema_version=16,
                    generation_offset=1,
                    cgroup_root=cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                )
            )
            expect(
                policy_blockers == (),
                "candidate did not restart the retained desired-running policy",
            )
            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE server_observations SET lifecycle='stopped',pid=NULL,"
                "process_start_time=NULL,process_fingerprint=NULL,health_ok=NULL "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            policy_blockers, _policy_fingerprint = (
                switch._retained_worker_policy_blockers(
                    runner,
                    source_proof=source_proof,
                    target_schema_version=16,
                    generation_offset=1,
                    cgroup_root=cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                )
            )
            credential_blockers, _credential_fingerprint = (
                switch._credentialized_worker_blockers(
                    manifest,
                    transaction,
                    runner,
                    source_proof=source_proof,
                    cgroup_root=cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                )
            )
            expect(
                policy_blockers == ()
                and credential_blockers == (),
                "stale observation re-entered process-supervision proof",
            )
            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE server_observations SET lifecycle='running',pid=42424,"
                "process_start_time='process-start',"
                "process_fingerprint='process-fingerprint',health_ok=1 "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            switch.require_credentialized_worker_convergence(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                timeout_seconds=5.0,
                stable_seconds=2.0,
                clock=clock,
                sleeper=sleeper,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
                status_refresher=status_refresher,
            )
            expect(
                clock_value[0] >= 2.0,
                "credentialized worker passed without a stable-running interval",
            )
            expect(
                len(refresh_calls) == 3
                and all(
                    worker_id == str(target_ids["worker_id"])
                    and root == "/srv/repository"
                    for worker_id, root, _timeout in refresh_calls
                )
                and refresh_calls[0][2] == 5.0
                and all(
                    earlier[2] > later[2]
                    for earlier, later in zip(refresh_calls, refresh_calls[1:])
                ),
                "credentialized convergence did not sample exact status through stability",
            )

            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE worker_attempts SET policy_generation=4 WHERE attempt_id=?",
                (target_ids["attempt_id"],),
            )
            connection.commit()
            connection.close()
            clock_value[0] = 0.0
            refresh_calls.clear()

            def repairing_status_refresher(
                target: object, timeout_seconds: float
            ) -> dict[str, object]:
                evidence = status_refresher(target, timeout_seconds)
                connection = sqlite3.connect(target_database)
                connection.execute(
                    "UPDATE worker_attempts SET policy_generation=5 WHERE attempt_id=?",
                    (target_ids["attempt_id"],),
                )
                connection.commit()
                connection.close()
                return evidence

            switch.require_credentialized_worker_convergence(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                timeout_seconds=5.0,
                stable_seconds=2.0,
                clock=clock,
                sleeper=sleeper,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
                status_refresher=repairing_status_refresher,
            )
            expect(
                len(refresh_calls) == 3,
                "credentialized convergence did not re-read after exact refresh",
            )

            clock_value[0] = 0.0
            refresh_calls.clear()

            def non_ready_status_refresher(
                target: object, timeout_seconds: float
            ) -> dict[str, object]:
                evidence = status_refresher(target, timeout_seconds)
                evidence.update(
                    {
                        "ready": False,
                        "endpoint_ready": False,
                        "state": "starting",
                    }
                )
                return evidence

            try:
                switch.require_credentialized_worker_convergence(
                    manifest,
                    transaction,
                    runner,
                    source_proof=source_proof,
                    timeout_seconds=1.5,
                    stable_seconds=0.2,
                    clock=clock,
                    sleeper=sleeper,
                    cgroup_root=cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                    status_refresher=non_ready_status_refresher,
                )
            except switch.SwitchError as error:
                expect(
                    "did not converge" in str(error),
                    "non-ready exact refresh returned an unrelated failure",
                )
            else:
                raise AssertionError("non-ready refreshed worker passed health proof")
            expect(
                len(refresh_calls) >= 2,
                "non-ready credentialized worker was not retried",
            )

            clock_value[0] = 0.0
            refresh_calls.clear()
            refresh_row = switch._credentialized_worker_rows()[0][
                str(target_ids["worker_id"])
            ]
            second_row = dict(refresh_row)
            second_row.update(
                {
                    "server_definition_id": "22222222-2222-4222-8222-222222222222",
                    "name": "second-credentialized-worker",
                }
            )

            def exhausted_status_refresher(
                target: object, timeout_seconds: float
            ) -> dict[str, object]:
                evidence = status_refresher(target, timeout_seconds)
                clock_value[0] += timeout_seconds
                return evidence

            with mock.patch.object(
                switch,
                "_credentialized_worker_refresh_targets",
                return_value=(refresh_row, second_row),
            ):
                try:
                    switch.require_credentialized_worker_convergence(
                        manifest,
                        transaction,
                        runner,
                        source_proof=source_proof,
                        timeout_seconds=1.5,
                        stable_seconds=0.2,
                        clock=clock,
                        sleeper=sleeper,
                        cgroup_root=cgroup_root,
                        process_observer=lambda _pid, _started: "alive",
                        status_refresher=exhausted_status_refresher,
                    )
                except switch.SwitchError as error:
                    expect(
                        "deadline" in str(error),
                        "multi-worker refresh returned an unrelated timeout",
                    )
                else:
                    raise AssertionError(
                        "multi-worker refresh exceeded the shared deadline"
                    )
            expect(
                len(refresh_calls) == 1 and refresh_calls[0][2] == 1.5,
                "credentialized refresh gave each worker a fresh deadline",
            )

            clock_value[0] = 0.0
            switch.require_retained_worker_policy_convergence(
                runner,
                source_proof=source_proof,
                target_schema_version=16,
                generation_offset=1,
                timeout_seconds=5.0,
                stable_seconds=2.0,
                clock=clock,
                sleeper=sleeper,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
            )

        rollback_database = root / "rollback.sqlite3"
        rollback_ids = worker_cutover_database(
            rollback_database, schema_version=15, running=True, role="web"
        )
        rollback_control_group = (
            "/devcoordinator.slice/"
            f"devcoordinator-worker-{rollback_ids['worker_id']}.service"
        )
        rollback_cgroup_root = root / "rollback-cgroup"
        rollback_events = rollback_cgroup_root.joinpath(
            *rollback_control_group.split("/")[1:]
        ) / "cgroup.events"
        rollback_events.parent.mkdir(parents=True, mode=0o700)
        rollback_events.write_text("populated 1\n", encoding="ascii")
        stale_receipt = switch._absent_worker_receipt(
            source_proof["policy_expectations"][0]
        )
        stale_receipt["process_proofs"] = [
            {
                "pid": 42424,
                "process_start_time": "process-start",
                "state": "absent",
            }
        ]

        class AbsentRollbackRunner(FakeRunner):
            def require(self, argv: list[str], _label: str) -> str:
                self.commands.append(list(argv))
                return ""

        with mock.patch.object(switch, "AUTHORITY_DATABASE", rollback_database):
            stale_backup_proof = switch.source_worker_quiescence_proof(
                AbsentRollbackRunner(),
                quiesced_workers=[stale_receipt],
                process_observer=lambda _pid, _started: "absent",
                cgroup_root=rollback_cgroup_root,
            )
        expect(
            switch._valid_source_worker_quiescence(stale_backup_proof),
            "writer-frozen stale attempt was not safe to back up",
        )
        rollback_runner = ConvergenceRunner(
            str(rollback_ids["worker_id"]), worker_slice, rollback_control_group
        )
        connection = sqlite3.connect(rollback_database)
        connection.execute(
            "UPDATE server_observations SET lifecycle='stopped',pid=NULL,"
            "process_start_time=NULL,process_fingerprint=NULL,health_ok=NULL "
            "WHERE server_definition_id=?",
            (rollback_ids["worker_id"],),
        )
        connection.commit()
        connection.close()
        with mock.patch.object(switch, "AUTHORITY_DATABASE", rollback_database):
            rollback_blockers, _rollback_fingerprint = (
                switch._retained_worker_policy_blockers(
                    rollback_runner,
                    source_proof=source_proof,
                    target_schema_version=15,
                    generation_offset=0,
                    cgroup_root=rollback_cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                )
            )
            mismatched_process, _mismatched_fingerprint = (
                switch._retained_worker_policy_blockers(
                    rollback_runner,
                    source_proof=source_proof,
                    target_schema_version=15,
                    generation_offset=0,
                    cgroup_root=rollback_cgroup_root,
                    process_observer=lambda _pid, _started: "mismatch",
                )
            )
        expect(
            rollback_blockers == ()
            and mismatched_process == (rollback_ids["worker_id"],),
            "rollback restart proof used stale health or lost exact process identity",
        )

        with (
            mock.patch.object(switch, "AUTHORITY_DATABASE", target_database),
            mock.patch.object(
                switch, "SERVER_CREDENTIAL_MATERIAL_ROOT", live_root
            ),
        ):
            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE server_observations SET health_ok=NULL "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
            )
            expect(
                blockers == (),
                "worker without a health contract required synthetic health",
            )

            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE server_definitions SET health_url_template='/healthz' "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
            )
            observed_rows = switch._credentialized_worker_rows()
            target_row = observed_rows[0][str(target_ids["worker_id"])]
            unavailable_endpoint = status_refresher(target_row, 5.0)
            unavailable_endpoint["endpoint_ready"] = False
            live_blockers, _live_fingerprint = (
                switch._credentialized_live_status_blockers(
                    observed_rows[0],
                    {str(target_ids["worker_id"])},
                    {str(target_ids["worker_id"]): unavailable_endpoint},
                )
            )
            expect(
                blockers == ()
                and live_blockers == (target_ids["worker_id"],),
                "fresh credentialized status accepted an unavailable endpoint",
            )

            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE server_definitions SET health_url_template=NULL "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.execute(
                "UPDATE worker_attempts SET policy_generation=4 "
                "WHERE attempt_id=?",
                (target_ids["attempt_id"],),
            )
            connection.commit()
            connection.close()
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "alive",
            )
            policy_blockers, _policy_fingerprint = (
                switch._retained_worker_policy_blockers(
                    runner,
                    source_proof=source_proof,
                    target_schema_version=16,
                    generation_offset=1,
                    cgroup_root=cgroup_root,
                    process_observer=lambda _pid, _started: "alive",
                )
            )
            expect(
                blockers == (target_ids["worker_id"],)
                and policy_blockers == (target_ids["worker_id"],),
                "stale worker attempt generation was accepted",
            )

            connection = sqlite3.connect(target_database)
            connection.execute(
                "UPDATE worker_supervisor_states SET state='tripped',"
                "current_attempt_id=NULL WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.execute(
                "DELETE FROM worker_attempts WHERE attempt_id=?",
                (target_ids["attempt_id"],),
            )
            connection.execute(
                "UPDATE worker_policies SET desired_state='running',breaker_state='tripped' "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.execute(
                "UPDATE server_observations SET lifecycle='running',pid=99999,"
                "process_start_time='stale-start',"
                "process_fingerprint='stale-fingerprint',health_ok=1 "
                "WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            runner.loaded = False
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=source_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "absent",
            )
            expect(blockers == (), "tripped credentialized web worker did not remain absent")

            connection = sqlite3.connect(target_database)
            connection.execute(
                "DELETE FROM worker_supervisor_states WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.execute(
                "DELETE FROM worker_policies WHERE server_definition_id=?",
                (target_ids["worker_id"],),
            )
            connection.commit()
            connection.close()
            no_policy_proof = dict(source_proof)
            no_policy_proof["policy_expectations"] = []
            no_policy_proof["policy_count"] = 0
            no_policy_proof["supervisor_count"] = 0
            no_policy_proof["observation_count"] = 0
            blockers, _fingerprint = switch._credentialized_worker_blockers(
                manifest,
                transaction,
                runner,
                source_proof=no_policy_proof,
                cgroup_root=cgroup_root,
                process_observer=lambda _pid, _started: "absent",
            )
            expect(
                blockers == (),
                "never-started credentialized definition was required to have a policy",
            )


def exercise_candidate_worker_rollback_cleanup() -> None:
    policy_worker = "11111111-1111-4111-8111-111111111111"
    policyless_worker = "22222222-2222-4222-8222-222222222222"
    inactive_worker = "33333333-3333-4333-8333-333333333333"
    source_proof = {
        "schema_version": 15,
        "database_generation": "source-generation",
        "state_revision": 0,
        "worker_units": [],
        "active_supervisors": [],
        "current_attempts": [],
        "active_observations": [],
        "policy_expectations": [],
        "quiesced_workers": [],
        "policy_count": 0,
        "supervisor_count": 0,
        "observation_count": 0,
        "worker_state_sha256": "a" * 64,
    }
    expect(
        switch._valid_source_worker_quiescence(source_proof),
        "candidate cleanup fixture lacks a valid empty-source proof",
    )
    rows = {
        policy_worker: {
            "server_definition_id": policy_worker,
            "name": "worker",
            "canonical_root": "/srv/repository",
            "execution_uid": os.geteuid() or 1000,
        },
        policyless_worker: {
            "server_definition_id": policyless_worker,
            "name": "orphan",
            "canonical_root": "/srv/repository",
            "execution_uid": None,
        },
        inactive_worker: {
            "server_definition_id": inactive_worker,
            "name": "inactive",
            "canonical_root": "/srv/repository",
            "execution_uid": os.geteuid() or 1000,
        },
    }
    calls: list[tuple[str, str]] = []

    class StoreContext:
        def __enter__(self) -> object:
            return object()

        def __exit__(self, *_values: object) -> None:
            return None

    class Controller:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def stop(self, *, worker_id: str, **_values: object) -> dict[str, object]:
            calls.append(("controller", worker_id))
            return {"ok": True}

    class Manager:
        def remove(self, *, worker_id: str) -> SimpleNamespace:
            calls.append(("native", worker_id))
            return SimpleNamespace(loaded=False, active=False)

    loaded_reads = [
        (policyless_worker,),
        (),
    ]
    state_reads = [
        (rows, (policy_worker,)),
        ({}, ()),
    ]
    with (
        mock.patch.object(
            switch,
            "loaded_managed_worker_ids",
            side_effect=loaded_reads,
        ),
        mock.patch.object(
            switch,
            "_candidate_worker_cleanup_rows",
            side_effect=state_reads,
        ),
        mock.patch.object(
            switch, "_candidate_coordinator_script", return_value=Path(__file__)
        ),
        mock.patch.object(
            switch.AccountStore, "open", return_value=StoreContext()
        ),
        mock.patch.object(switch, "WorkerController", Controller),
        mock.patch.object(
            switch,
            "_worker_native_factory",
            return_value=lambda **_values: Manager(),
        ),
    ):
        stopped = switch.stop_candidate_workers_for_rollback(
            {"release": "/candidate"},
            {"source_worker_quiescence": source_proof},
            FakeRunner(),
        )
    expect(
        stopped == (policy_worker, policyless_worker),
        "candidate cleanup did not cover exact post-source workers",
    )
    expect(
        calls == [
            ("controller", policy_worker),
            ("native", policyless_worker),
        ],
        "candidate cleanup bypassed controller fallback or policyless native removal",
    )

    class BoundedRunner(FakeRunner):
        def __init__(self) -> None:
            super().__init__()
            self.timeouts: list[float] = []

        def run_bounded(
            self, argv: list[str], *, timeout_seconds: float
        ) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(argv))
            self.timeouts.append(timeout_seconds)
            return subprocess.CompletedProcess(argv, 0, "", "")

    bounded_runner = BoundedRunner()
    manager = switch._worker_native_factory(bounded_runner)(
        coordinator_script=(
            ROOT / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        ),
        state_root=None,
    )
    manager.runner(["/usr/bin/systemctl", "stop", "example.service"])
    expect(
        bounded_runner.timeouts == [45.0],
        "candidate native cleanup is not bounded above TimeoutStopSec",
    )

    class FailingController(Controller):
        def stop(self, *, worker_id: str, **_values: object) -> dict[str, object]:
            raise switch.WorkerControlError("injected candidate cleanup failure")

    with (
        mock.patch.object(
            switch, "loaded_managed_worker_ids", return_value=()
        ),
        mock.patch.object(
            switch,
            "_candidate_worker_cleanup_rows",
            return_value=(rows, (policy_worker,)),
        ),
        mock.patch.object(
            switch, "_candidate_coordinator_script", return_value=Path(__file__)
        ),
        mock.patch.object(
            switch.AccountStore, "open", return_value=StoreContext()
        ),
        mock.patch.object(switch, "WorkerController", FailingController),
        mock.patch.object(
            switch,
            "_worker_native_factory",
            return_value=lambda **_values: Manager(),
        ),
    ):
        try:
            switch.stop_candidate_workers_for_rollback(
                {"release": "/candidate"},
                {"source_worker_quiescence": source_proof},
                FakeRunner(),
            )
        except switch.SwitchError as error:
            expect(
                policy_worker in str(error),
                "candidate cleanup failure omitted exact worker identity",
            )
        else:
            raise AssertionError("candidate cleanup failure allowed source restoration")

    order: list[str] = []
    intent = {
        "required": True,
        "status": "applied",
        "backups": {"exact": {}},
        "source_worker_quiescence": source_proof,
    }
    document = {"retained_control_rebaseline": intent}
    with tempfile.TemporaryDirectory(prefix="candidate-rollback-order-") as raw:
        journal = Path(raw) / "journal.json"
        with (
            mock.patch.object(
                switch, "retained_rebaseline_intent", return_value=intent
            ),
            mock.patch.object(
                switch, "validate_retained_rebaseline_paths"
            ),
            mock.patch.object(
                switch,
                "stop_authority_writers",
                side_effect=lambda _runner: order.append("authority"),
            ),
            mock.patch.object(
                switch,
                "stop_candidate_workers_for_rollback",
                side_effect=lambda *_args: order.append("candidate") or (),
            ),
            mock.patch.object(
                switch,
                "stop_console_writers",
                side_effect=lambda *_args: order.append("console"),
            ),
            mock.patch.object(
                switch,
                "_load_bound_retained_manifest",
                return_value={"server_credentials": []},
            ),
            mock.patch.object(
                switch, "_server_credentials_from_manifest", return_value={}
            ),
            mock.patch.object(
                switch,
                "_restore_retained_files",
                side_effect=lambda *_args: order.append("restore"),
            ),
            mock.patch.object(
                switch,
                "source_worker_quiescence_proof",
                return_value=source_proof,
            ),
            mock.patch.object(switch, "save_phase"),
        ):
            switch.restore_retained_control_rebaseline(
                document, journal, Path(raw), FakeRunner()
            )
        expect(
            order == ["authority", "candidate", "console", "restore"],
            "candidate rollback cleanup did not precede source restoration",
        )

        order.clear()
        intent["status"] = "applied"
        with (
            mock.patch.object(
                switch, "retained_rebaseline_intent", return_value=intent
            ),
            mock.patch.object(
                switch, "validate_retained_rebaseline_paths"
            ),
            mock.patch.object(
                switch,
                "stop_authority_writers",
                side_effect=lambda _runner: order.append("authority"),
            ),
            mock.patch.object(
                switch,
                "stop_candidate_workers_for_rollback",
                side_effect=switch.SwitchError("injected candidate failure"),
            ),
            mock.patch.object(
                switch,
                "_restore_retained_files",
                side_effect=lambda *_args: order.append("restore"),
            ),
        ):
            try:
                switch.restore_retained_control_rebaseline(
                    document, journal, Path(raw), FakeRunner()
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("candidate rollback failure was ignored")
    expect(
        order == ["authority"],
        "candidate cleanup failure allowed source restoration",
    )


def exercise_credentialized_status_refresh_is_exact_and_bounded() -> None:
    worker_id = "11111111-1111-4111-8111-111111111111"
    repo_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    target = {
        "server_definition_id": worker_id,
        "name": "credentialized-web",
        "canonical_root": "/srv/repository",
        "repo_id": repo_id,
    }
    payload = {
        "action": "status",
        "ok": True,
        "outcome": "certain",
        "mutation_performed": False,
        "name": "credentialized-web",
        "ready": False,
        "supervision_ready": True,
        "endpoint_ready": False,
        "state": "starting",
        "target": {"id": worker_id, "kind": "service"},
        "resource": {
            "id": worker_id,
            "kind": "service",
            "repo_id": repo_id,
            "name": "credentialized-web",
            "state": "starting",
            "ready": False,
        },
        "supervision": {
            "current_attempt_id": "attempt-one",
            "keep_alive": True,
            "desired_state": "running",
            "breaker_state": "armed",
            "supervisor_state": "running",
        },
    }

    class BoundedRunner(FakeRunner):
        def __init__(self, document: object, returncode: int = 0) -> None:
            super().__init__()
            self.document = document
            self.returncode = returncode
            self.timeouts: list[float] = []

        def run_bounded(
            self, argv: list[str], *, timeout_seconds: float
        ) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(argv))
            self.timeouts.append(timeout_seconds)
            return subprocess.CompletedProcess(
                argv,
                self.returncode,
                json.dumps(self.document, sort_keys=True),
                "",
            )

    runner = BoundedRunner(payload)
    evidence = switch._refresh_credentialized_worker_status(
        runner, target, timeout_seconds=7.5
    )
    expect(
        runner.commands
        == [
            [
                str(switch.CLIENT_LAUNCHER),
                "runtime",
                "status",
                worker_id,
                "--kind",
                "service",
                "--project",
                "/srv/repository",
            ]
        ]
        and runner.timeouts == [7.5]
        and evidence["ready"] is False
        and evidence["current_attempt_id"] == "attempt-one",
        "credentialized refresh was not exact and bounded",
    )

    wrong = json.loads(json.dumps(payload))
    wrong["resource"]["id"] = "22222222-2222-4222-8222-222222222222"
    try:
        switch._refresh_credentialized_worker_status(
            BoundedRunner(wrong), target, timeout_seconds=7.5
        )
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("credentialized refresh accepted another resource")

    failed = json.loads(json.dumps(payload))
    failed["ok"] = False
    failed["ready"] = True
    failed["resource"]["ready"] = True
    try:
        switch._refresh_credentialized_worker_status(
            BoundedRunner(failed), target, timeout_seconds=7.5
        )
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("credentialized refresh accepted failed readiness")

    excessive = BoundedRunner(payload)

    def excessive_result(
        argv: list[str], *, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        excessive.commands.append(list(argv))
        excessive.timeouts.append(timeout_seconds)
        return subprocess.CompletedProcess(argv, 0, "x" * 8193, "")

    excessive.run_bounded = excessive_result  # type: ignore[method-assign]
    try:
        switch._refresh_credentialized_worker_status(
            excessive, target, timeout_seconds=7.5
        )
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("credentialized refresh accepted oversized output")
    stable_client_source = (
        ROOT
        / "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py"
    ).read_text(encoding="utf-8")
    expect(
        "if len(encoded) + 1 > MAX_AGENT_RESULT_BYTES:" in stable_client_source
        and "final serialized output exceeds the 8192-byte agent contract"
        in stable_client_source,
        "stable status client no longer bounds output before emission",
    )


def exercise_rollback_resume_preserves_restored_control_plane() -> None:
    source_proof = {
        "schema_version": 15,
        "database_generation": "rollback-source-generation",
        "state_revision": 4,
        "worker_units": [],
        "active_supervisors": [],
        "current_attempts": [],
        "active_observations": [],
        "policy_expectations": [],
        "quiesced_workers": [],
        "policy_count": 0,
        "supervisor_count": 0,
        "observation_count": 0,
        "worker_state_sha256": "a" * 64,
    }
    intent = {
        "required": True,
        "source_schema_version": 15,
        "target_schema_version": 16,
        "status": "planned",
        "source_worker_quiescence": source_proof,
    }
    with tempfile.TemporaryDirectory(prefix="rollback-resume-") as raw:
        root = Path(raw)
        journal = root / "journal.json"
        document: dict[str, object] = {
            "phase": "rollback-control-plane-restored",
            "release_digest": DIGEST,
            "retained_control_rebaseline": intent,
        }
        background_calls: list[str] = []
        convergence_calls: list[str] = []

        def converge(*_args: object, **_kwargs: object) -> None:
            convergence_calls.append("converge")
            if len(convergence_calls) == 1:
                raise switch.SwitchError("injected late worker")

        with (
            mock.patch.object(switch, "SLOT_ROOT", root / "slots"),
            mock.patch.object(
                switch,
                "restore_rollback_background_services",
                side_effect=lambda _runner: background_calls.append("background"),
            ),
            mock.patch.object(
                switch,
                "require_retained_worker_policy_convergence",
                side_effect=converge,
            ),
        ):
            try:
                switch.complete_rollback_after_control_plane(
                    document, journal, FakeRunner()
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("injected rollback convergence failure was ignored")
            expect(
                document["phase"] == "rollback-background-restored",
                "rollback did not checkpoint background restoration before waiting",
            )
            switch.complete_rollback_after_control_plane(
                document, journal, FakeRunner()
            )
        expect(
            background_calls == ["background"]
            and convergence_calls == ["converge", "converge"]
            and document["phase"] == "rolled-back",
            "rollback replay restarted restored services or skipped convergence",
        )

        release = root / DIGEST
        release.mkdir()
        resumed_document: dict[str, object] = {
            "phase": "rollback-background-restored",
            "release": str(release),
            "release_digest": DIGEST,
            "previous_release_digest": "b" * 64,
            "candidate_console_unit": f"devcoordinator-console@{DIGEST}.service",
            "previous_console_unit": "devcoordinator-console@" + "b" * 64 + ".service",
            "candidate_control_socket": "/run/candidate.sock",
            "previous_control_socket": "/run/previous.sock",
            "candidate_outer_port": 41001,
            "previous_outer_port": 41002,
            "backups": {"unit": {}},
            "retained_control_rebaseline": intent,
        }
        marker = {"phase": "rolled-back"}
        with (
            mock.patch.object(
                switch, "require_transaction_root", return_value=root
            ),
            mock.patch.object(switch, "load_journal", return_value=resumed_document),
            mock.patch.object(
                switch, "require_test_history_reset_mode", return_value=None
            ),
            mock.patch.object(
                switch,
                "publication_snapshot",
                return_value={
                    "release_digest": "b" * 64,
                    "port": 41002,
                },
            ),
            mock.patch.object(
                switch,
                "complete_rollback_after_control_plane",
                return_value=marker,
            ) as resumed,
            mock.patch.object(
                switch,
                "restore_retained_control_rebaseline",
                side_effect=AssertionError("resumed rollback restored control plane again"),
            ),
        ):
            result = switch.rollback(release, root, FakeRunner())
        expect(
            result is marker and resumed.call_count == 1,
            "rollback dispatcher did not resume after restored control plane",
        )

        partial_intent = dict(intent)
        partial_intent.pop("source_worker_quiescence")
        partial_document: dict[str, object] = {
            "phase": "applying",
            "release": str(release),
            "release_digest": DIGEST,
            "retained_control_rebaseline": partial_intent,
        }
        partial_order: list[str] = []
        stale_expectations = {
            "policy_expectations": [],
            "policy_count": 0,
        }

        def verify_partial_convergence(
            _runner: object, *, source_proof: object, **_values: object
        ) -> None:
            expect(
                source_proof is stale_expectations,
                "partial rollback lost source policy expectations",
            )
            partial_order.append("converge")

        def finish_partial(
            _path: object, value: dict[str, object], phase: str, **_values: object
        ) -> None:
            value["phase"] = phase

        with (
            mock.patch.object(
                switch, "require_transaction_root", return_value=root
            ),
            mock.patch.object(switch, "load_journal", return_value=partial_document),
            mock.patch.object(
                switch, "require_test_history_reset_mode", return_value=None
            ),
            mock.patch.object(
                switch,
                "source_worker_policy_expectations",
                side_effect=lambda _runner: (
                    partial_order.append("expectations") or stale_expectations
                ),
            ),
            mock.patch.object(
                switch,
                "restart_services",
                side_effect=lambda _runner: partial_order.append("restart"),
            ),
            mock.patch.object(
                switch,
                "require_retained_worker_policy_convergence",
                side_effect=verify_partial_convergence,
            ),
            mock.patch.object(
                switch,
                "restart_previous_console",
                side_effect=lambda *_args: partial_order.append("console"),
            ),
            mock.patch.object(switch, "save_phase", side_effect=finish_partial),
        ):
            partial_result = switch.rollback(release, root, FakeRunner())
        expect(
            partial_result is partial_document
            and partial_document["phase"] == "rolled-back"
            and partial_order
            == ["expectations", "restart", "converge", "console"],
            "partial quiescence failure did not restart and settle stale policy",
        )


def exercise_verification_requires_boot_enablement() -> None:
    source = inspect.getsource(switch.verify)
    rollback_source = inspect.getsource(switch.rollback)
    retained_rollback_source = inspect.getsource(
        switch.restore_retained_control_rebaseline
    )
    retained_completion_source = inspect.getsource(
        switch.complete_retained_control_rebaseline
    )
    rollback_completion_source = inspect.getsource(
        switch.complete_rollback_after_control_plane
    )
    main_source = inspect.getsource(switch.main)
    expect(
        "enabled_states = {unit: unit_enabled" in source
        and "all(enabled_states.values())" in source
        and '"services_enabled": enabled_states' in source,
        "same-schema verification can accept active but boot-disabled units",
    )
    unit = (ROOT / "deploy/devcoordinator-console@.service").read_text(
        encoding="utf-8"
    )
    expect(
        "[Install]\nWantedBy=multi-user.target" in unit,
        "promoted Console instance has no reboot activation contract",
    )
    expect(
        "verify_public_browser_runtime_inventory()" in source
        and '"browser_runtime_inventory": browser_runtime_inventory' in source,
        "same-schema verification omits actual-caller browser runtime inventory",
    )
    expect(
        "verify_browser_lifecycle_publication()" in source
        and '"browser_lifecycle_publication": browser_lifecycle_publication' in source
        and '"installed_host_contracts": installed_host_contracts' in source,
        "same-schema health can omit live telemetry modes or installed tmpfiles identity",
    )
    expect(
        "d /var/lib/devcoordinator 0711 root root -"
        in (ROOT / "deploy/devcoordinator.tmpfiles.conf").read_text(encoding="utf-8"),
        "canonical server-wide tmpfiles policy still re-privatizes shared telemetry",
    )
    expect(
        (ROOT / "deploy/devcoordinator.tmpfiles.conf")
        .read_text(encoding="utf-8")
        .splitlines()
        .count("d /var/lib/devcoordinator/server-credentials 0700 root root -")
        == 1,
        "canonical server-wide tmpfiles policy omits the private credential root",
    )
    expect(
        "legacy_control_plane_retired = (" in source
        and "and legacy_control_plane_retired" in source
        and '"legacy_broker_retired": legacy_broker_retired' in source,
        "same-schema verification can accept an active, enabled, or unguarded legacy unit",
    )
    expect(
        "retire_legacy_control_plane(runner)" in rollback_source,
        "post-promotion rollback can revive the obsolete control plane",
    )
    expect(
        rollback_source.index("restore_retained_control_rebaseline(")
        < rollback_source.index('"previous Console restore"')
        and retained_rollback_source.index("stop_authority_writers(runner)")
        < retained_rollback_source.index("stop_candidate_workers_for_rollback(")
        < retained_rollback_source.index("stop_console_writers(document, runner)")
        < retained_rollback_source.index("_restore_retained_files(")
        and '["/usr/bin/systemctl", "disable", candidate]' in rollback_source,
        "post-promotion rollback starts a Console before stopping writers and restoring retained data",
    )
    expect(
        retained_completion_source.index(
            "require_retained_worker_policy_convergence("
        )
        < retained_completion_source.index(
            "require_credentialized_worker_convergence("
        )
        and rollback_completion_source.index(
            "restore_rollback_background_services(runner)"
        )
        < rollback_completion_source.index(
            "require_retained_worker_policy_convergence("
        ),
        "candidate or rollback can complete before retained workers restart",
    )
    expect(
        'args.action in {"verify", "acceptance-begin"}' in main_source
        and 'value.get("ok") is not True' in main_source
        and "public_switch_result(args.action, value)" in main_source
        and 'raise SwitchError("same-schema control-plane health failed")'
        not in source,
        "failed health verification hides its structured invariant evidence",
    )


def exercise_cli_result_excludes_private_transaction_evidence() -> None:
    credential_sha = "f" * 64
    value = {
        "phase": "applied",
        "release_digest": DIGEST,
        "previous_release_digest": "b" * 64,
        "backups": {
            "/private/credential": {
                "source": {
                    "path": "/private/credential",
                    "sha256": credential_sha,
                }
            }
        },
        "retained_control_rebaseline": {
            "required": True,
            "status": "applied",
            "source_schema_version": 15,
            "target_schema_version": 16,
            "backups": {"credential_sha256": credential_sha},
            "manifest": "/private/retained-control.json",
        },
    }
    public = switch.public_switch_result("apply", value)
    encoded = json.dumps(public, sort_keys=True)
    expect(public["ok"] is True and public["phase"] == "applied", "public result lost status")
    for forbidden in (credential_sha, "/private", "backups", "manifest", "sha256"):
        expect(forbidden not in encoded, f"public result disclosed private {forbidden}")
    acceptance = switch.public_switch_result(
        "acceptance-begin", {"ok": False, "release_digest": DIGEST}
    )
    expect(
        acceptance["ok"] is False,
        "acceptance-begin public result hid failed live verification",
    )


def main() -> int:
    exercise_slot_payload()
    exercise_http_is_strict_2xx()
    exercise_edge_health_uses_live_generation()
    exercise_stopped_published_console_recovers_exactly()
    exercise_ambiguous_console_topology_never_recovers()
    exercise_local_path_materialization()
    exercise_blue_green_order()
    exercise_first_capable_browser_cleanup()
    exercise_retiring_release_ignores_generated_bytecode()
    exercise_previous_release_requires_current_format()
    exercise_browser_cleanup_skip_failure_and_malformed_result()
    exercise_browser_cleanup_activation_order()
    exercise_already_active_health_has_rendered_contract()
    exercise_current_transaction_durability()
    exercise_legacy_control_plane_is_durably_retired()
    exercise_internal_socket_rebind_order()
    exercise_rollback_restores_control_plane_before_background_services()
    exercise_slot_readiness_waits_for_supervisor_socket()
    exercise_release_packaging_contract()
    exercise_stable_client_destination_transaction()
    exercise_codex_execpolicy_boundary()
    exercise_codex_directory_transaction()
    exercise_opt_in_test_history_reset_and_previous_release_rollback()
    exercise_reset_cli_is_explicit()
    exercise_software_delivery_fence_lifecycle()
    exercise_retained_control_transaction_boundary()
    exercise_retained_server_credential_transaction()
    exercise_rebaseline_quiesces_exact_managed_workers()
    exercise_source_worker_quiescence_is_exact_and_race_safe()
    exercise_credentialized_web_worker_convergence()
    exercise_credentialized_status_refresh_is_exact_and_bounded()
    exercise_candidate_worker_rollback_cleanup()
    exercise_rollback_resume_preserves_restored_control_plane()
    exercise_verification_requires_boot_enablement()
    exercise_cli_result_excludes_private_transaction_evidence()
    print("same-schema release switch self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
