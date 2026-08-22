#!/usr/bin/env python3
"""Focused regressions for the routine same-schema release switch."""

from __future__ import annotations

import hashlib
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
    def __init__(
        self,
        *,
        rollback_schema: int = switch.RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION,
    ) -> None:
        super().__init__()
        self.rollback_schema = rollback_schema

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
                "schema_version": switch.CURRENT_TEST_STORE_SCHEMA_VERSION,
                "discarded_existing": True,
                "replayed": False,
            }
        if "create" in argv:
            database = argv[argv.index("--test-database") + 1]
            return {
                "ok": True,
                "action": "create",
                "test_database": database,
                "schema_version": self.rollback_schema,
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
    class ActivationRaceRunner(FakeRunner):
        def __init__(self) -> None:
            super().__init__()
            self.coalesced_retry = False

        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if argv[1] == "enable":
                expect(
                    "--now" not in argv,
                    "socket activation became visible before the service graph job",
                )
            elif argv[1] == "restart":
                expected = [*switch.REQUIRED_SOCKETS, *switch.SERVICE_ORDER]
                expect(
                    argv[2:] == expected
                    and switch.AUTHORITY_SERVICE in argv
                    and switch.API_SOCKET in argv,
                    "retrying client was not coalesced with the exact service graph",
                )
                self.coalesced_retry = True
            return ""

    runner = ActivationRaceRunner()

    ready_after_graph: list[bool] = []
    switch.restart_services(
        runner,
        ready_waiter=lambda _runner: ready_after_graph.append(
            runner.coalesced_retry
        ),
    )

    enable_count = len(switch.REQUIRED_SOCKETS) + len(switch.SERVICE_ORDER)
    enable_commands = runner.commands[:enable_count]
    restart_commands = runner.commands[enable_count:]
    enabled_units = [command[-1] for command in enable_commands]
    expect(
        enabled_units == [*switch.REQUIRED_SOCKETS, *switch.SERVICE_ORDER],
        "required sockets and services were not repaired for boot",
    )
    expect(
        all(command[1] == "enable" and "--now" not in command for command in enable_commands),
        "required sockets/services did not preserve durable single-start ordering",
    )
    expect(
        restart_commands
        == [[
            "/usr/bin/systemctl",
            "restart",
            *switch.REQUIRED_SOCKETS,
            *switch.SERVICE_ORDER,
        ]]
        and runner.coalesced_retry
        and ready_after_graph == [True],
        "socket/service replacement did not use one coalesced restart transaction",
    )
    authority_commands = [
        command
        for command in runner.commands
        if switch.AUTHORITY_SERVICE in command
    ]
    expect(
        authority_commands
        == [
            ["/usr/bin/systemctl", "enable", switch.AUTHORITY_SERVICE],
            restart_commands[0],
        ],
        "authority replacement created more than one startup epoch",
    )


def exercise_retained_worker_deadlines_are_nested() -> None:
    expect(
        switch.RETAINED_WORKER_CONVERGENCE_SECONDS
        == switch.WORKER_STARTUP_CONVERGENCE_SECONDS
        + switch.RETAINED_WORKER_CONVERGENCE_MARGIN_SECONDS
        and switch.RETAINED_WORKER_CONVERGENCE_MARGIN_SECONDS
        == switch.WORKER_STARTUP_NATIVE_COMMAND_MAX_SECONDS
        + switch.RETAINED_WORKER_STABILITY_SECONDS
        + switch.RETAINED_WORKER_OBSERVATION_MARGIN_SECONDS
        and switch.RETAINED_WORKER_OBSERVATION_MARGIN_SECONDS >= 5.0,
        "retained worker proof deadline does not contain startup plus stability",
    )
    clock_value = 0.0

    def clock() -> float:
        return clock_value

    def sleeper(seconds: float) -> None:
        nonlocal clock_value
        clock_value += seconds

    def delayed_blockers(*_args, **_kwargs):
        if clock_value < switch.WORKER_STARTUP_CONVERGENCE_SECONDS:
            return (("worker-still-starting",), "starting")
        return ((), "exact-running")

    with mock.patch.object(
        switch,
        "_retained_worker_policy_blockers",
        side_effect=delayed_blockers,
    ):
        switch.require_retained_worker_policy_convergence(
            FakeRunner(),
            source_proof={},
            target_schema_version=16,
            generation_offset=1,
            clock=clock,
            sleeper=sleeper,
        )
    expect(
        clock_value
        >= switch.WORKER_STARTUP_CONVERGENCE_SECONDS
        + switch.RETAINED_WORKER_STABILITY_SECONDS
        and clock_value < switch.RETAINED_WORKER_CONVERGENCE_SECONDS,
        "outer retained worker proof expired before legal inner convergence stabilized",
    )


def exercise_authority_ready_is_invocation_bound() -> None:
    invocation_a = "a" * 32
    invocation_b = "b" * 32

    def state(invocation: str, *, active: bool = True) -> str:
        return "\n".join(
            (
                f"InvocationID={invocation}",
                "MainPID=4312",
                f"ActiveState={'active' if active else 'inactive'}",
                f"SubState={'running' if active else 'dead'}",
            )
        )

    ready = json.dumps(
        {
            "status": "ready",
            "service_uid": 0,
            "socket": switch.AUTHORITY_SOCKET_PATH,
            "socket_activated": True,
            "database": str(switch.AUTHORITY_DATABASE),
            "wire_identity": "opaque_normalized_ids_only",
        },
        sort_keys=True,
    )
    schema_ready = json.dumps(
        {
            "ok": True,
            "kind": "schema",
            "database": str(switch.AUTHORITY_DATABASE),
            "schema_version": switch.COORDINATOR_SCHEMA_VERSION,
            "read_only": True,
        },
        sort_keys=True,
    )
    ready_journal = schema_ready + "\n" + ready

    class ReadyRunner(FakeRunner):
        def __init__(self, states: list[str], journals: list[str]) -> None:
            super().__init__()
            self.states = list(states)
            self.journals = list(journals)
            self.timeouts: list[float] = []

        def run_bounded(
            self, argv: list[str], *, timeout_seconds: float
        ) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(argv))
            self.timeouts.append(timeout_seconds)
            if "systemctl" in argv[0]:
                output = self.states.pop(0) if len(self.states) > 1 else self.states[0]
            else:
                raw_output = (
                    self.journals.pop(0)
                    if len(self.journals) > 1
                    else self.journals[0]
                )
                grep = next(
                    (
                        argument.removeprefix("--grep=")
                        for argument in argv
                        if argument.startswith("--grep=")
                    ),
                    None,
                )
                output = "\n".join(
                    line
                    for line in raw_output.splitlines()
                    if grep is None or grep in line
                )
            return subprocess.CompletedProcess(argv, 0, output, "")

    noisy_ready_journal = "\n".join(
        [
            schema_ready,
            ready,
            *(
                json.dumps({"event": "worker.startup_reconciled", "index": index})
                for index in range(100)
            ),
        ]
    )
    runner = ReadyRunner(
        [state(invocation_a), state(invocation_a)], [noisy_ready_journal]
    )
    evidence = switch.wait_authority_ready(runner, timeout_seconds=1.0)
    expect(
        evidence["ready"] is True
        and evidence["invocation_id"] == invocation_a
        and all(0 < timeout <= switch.AUTHORITY_READY_COMMAND_TIMEOUT_SECONDS for timeout in runner.timeouts)
        and any(
            argument == "_SYSTEMD_INVOCATION_ID=" + invocation_a
            for argument in runner.commands[1]
        )
        and all("--lines=2" in command for command in runner.commands[1:3])
        and any(
            argument == '--grep="status": "ready"'
            for argument in runner.commands[2]
        ),
        "authority readiness was not bound to its exact invocation",
    )

    for states, journals, label in (
        (
            [state(invocation_a), state(invocation_b)],
            [ready_journal],
            "invocation change",
        ),
        (
            [state(invocation_a)],
            ['{"status": "ready"'],
            "malformed journal",
        ),
        (
            [state(invocation_a)],
            [
                json.dumps(
                    {
                        **json.loads(schema_ready),
                        "schema_version": 15,
                    },
                    sort_keys=True,
                )
                + "\n"
                + ready
            ],
            "wrong schema preflight",
        ),
        (
            [state(invocation_a)],
            [schema_ready + "\n" + ready + "\n" + ready],
            "duplicate ready record",
        ),
        (
            [state(invocation_a)],
            [
                '"status": "ready"'
                + "x" * switch.AUTHORITY_READY_OUTPUT_MAX_BYTES
            ],
            "excessive journal",
        ),
        (
            [state(invocation_a), state(invocation_a, active=False)],
            [""],
            "shutdown before ready",
        ),
    ):
        try:
            switch.wait_authority_ready(
                ReadyRunner(states, journals), timeout_seconds=1.0
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError(f"authority readiness accepted {label}")

    clock_value = 0.0

    def clock() -> float:
        return clock_value

    def sleeper(seconds: float) -> None:
        nonlocal clock_value
        clock_value += seconds

    try:
        switch.wait_authority_ready(
            ReadyRunner([state(invocation_a)], [""]),
            timeout_seconds=0.3,
            clock=clock,
            sleeper=sleeper,
        )
    except switch.SwitchError as error:
        expect("timed out" in str(error), "ready timeout returned another error")
    else:
        raise AssertionError("authority readiness exceeded its bounded timeout")


def exercise_authority_writer_stop_is_bounded_and_exact() -> None:
    control_group = "/system.slice/devcoordinator-authority.service"
    with tempfile.TemporaryDirectory(prefix="authority-stop-") as raw:
        cgroup_root = Path(raw) / "cgroup"
        events = cgroup_root.joinpath(
            *control_group.split("/")[1:]
        ) / "cgroup.events"
        events.parent.mkdir(parents=True)
        events.write_text("populated 1\n", encoding="ascii")
        class AuthorityRunner(FakeRunner):
            def __init__(self) -> None:
                super().__init__()
                self.killed = False
                self.timeouts: list[float] = []

            def run_bounded(
                self, argv: list[str], *, timeout_seconds: float
            ) -> subprocess.CompletedProcess[str]:
                self.commands.append(list(argv))
                self.timeouts.append(timeout_seconds)
                if "show" in argv:
                    active = not self.killed
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "\n".join(
                            (
                                "LoadState=loaded",
                                f"ActiveState={'active' if active else 'inactive'}",
                                f"SubState={'running' if active else 'dead'}",
                                f"MainPID={4312 if active else 0}",
                                f"ControlGroup={control_group}",
                            )
                        ),
                        "",
                    )
                if "--signal=KILL" in argv:
                    self.killed = True
                    events.write_text("populated 0\n", encoding="ascii")
                return subprocess.CompletedProcess(argv, 0, "", "")

        clock_value = [0.0]

        def clock() -> float:
            return clock_value[0]

        def sleeper(seconds: float) -> None:
            clock_value[0] += seconds

        runner = AuthorityRunner()
        evidence = switch.stop_authority_service_bounded(
            runner,
            cgroup_root=cgroup_root,
            process_start_reader=lambda pid: "process-start" if pid == 4312 else "",
            process_observer=lambda pid, started: (
                "absent" if runner.killed and pid == 4312 and started == "process-start" else "alive"
            ),
            clock=clock,
            sleeper=sleeper,
            grace_seconds=0.2,
        )
        expect(
            evidence["status"] == "stopped"
            and evidence["process"] == "absent"
            and all(timeout == 5.0 for timeout in runner.timeouts),
            "bounded authority stop lost terminal identity evidence",
        )
        expect(
            [
                command
                for command in runner.commands
                if "show" not in command
            ]
            == [
                [
                    "/usr/bin/systemctl",
                    "--no-block",
                    "stop",
                    switch.AUTHORITY_SERVICE,
                ],
                [
                    "/usr/bin/systemctl",
                    "kill",
                    "--kill-whom=all",
                    "--signal=TERM",
                    switch.AUTHORITY_SERVICE,
                ],
                [
                    "/usr/bin/systemctl",
                    "kill",
                    "--kill-whom=all",
                    "--signal=KILL",
                    switch.AUTHORITY_SERVICE,
                ],
            ],
            "authority stop did not use bounded stop then exact TERM/KILL",
        )

        class PidOneRunner(AuthorityRunner):
            def run_bounded(
                self, argv: list[str], *, timeout_seconds: float
            ) -> subprocess.CompletedProcess[str]:
                result = super().run_bounded(argv, timeout_seconds=timeout_seconds)
                if "show" in argv:
                    return subprocess.CompletedProcess(
                        argv, result.returncode, result.stdout.replace("MainPID=4312", "MainPID=1"), result.stderr
                    )
                return result

        events.write_text("populated 1\n", encoding="ascii")
        try:
            switch.stop_authority_service_bounded(
                PidOneRunner(),
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                grace_seconds=0.1,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("PID 1 was accepted as authority process identity")

        events.write_text("populated 1\n", encoding="ascii")
        unsafe = AuthorityRunner()
        try:
            switch.stop_authority_service_bounded(
                unsafe,
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "alive",
                clock=clock,
                sleeper=sleeper,
                grace_seconds=0.1,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("authority stop accepted an unproved process exit")

        class LostReplyRunner(AuthorityRunner):
            def __init__(self, *, timeout: bool) -> None:
                super().__init__()
                self.timeout = timeout

            def run_bounded(
                self, argv: list[str], *, timeout_seconds: float
            ) -> subprocess.CompletedProcess[str]:
                if "--no-block" in argv:
                    self.commands.append(list(argv))
                    self.timeouts.append(timeout_seconds)
                    self.killed = True
                    events.write_text("populated 0\n", encoding="ascii")
                    if self.timeout:
                        raise switch.SwitchError("injected timeout")
                    return subprocess.CompletedProcess(argv, 1, "", "lost reply")
                return super().run_bounded(argv, timeout_seconds=timeout_seconds)

        for timeout in (False, True):
            events.write_text("populated 1\n", encoding="ascii")
            lost = LostReplyRunner(timeout=timeout)
            reconciled = switch.stop_authority_service_bounded(
                lost,
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                grace_seconds=0.1,
            )
            expect(
                reconciled["status"] == "stopped",
                "lost authority stop reply lacked exact terminal reconciliation",
            )

    source = inspect.getsource(switch.stop_authority_writers)
    expect(
        switch.AUTHORITY_WRITER_UNITS[-1] == switch.AUTHORITY_SERVICE
        and "stop_authority_service_bounded(" in source,
        "bounded authority stop changed writer ordering",
    )


def exercise_writer_stop_malformed_replay_and_race_guards() -> None:
    class StatusRunner(FakeRunner):
        def __init__(self, output: str, returncode: int = 0) -> None:
            super().__init__()
            self.output = output
            self.returncode = returncode

        def run_bounded(
            self, argv: list[str], *, timeout_seconds: float
        ) -> subprocess.CompletedProcess[str]:
            self.commands.append(list(argv))
            return subprocess.CompletedProcess(
                argv, self.returncode, self.output, ""
            )

    valid = (
        "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        "MainPID=0\nControlGroup=\n"
    )
    socket_output = (
        "LoadState=loaded\nActiveState=active\nSubState=listening\n"
    )
    socket_state = switch._writer_unit_state(
        StatusRunner(socket_output), switch.AUTHORITY_WRITER_UNITS[0]
    )
    expect(
        socket_state["active"] is True
        and socket_state["pid"] is None
        and socket_state["control_group"] is None,
        "real socket status required synthetic service properties",
    )
    for output in (
        valid + "LoadState=loaded\n",
        valid.replace("LoadState=loaded", "LoadState=not-found"),
        valid.replace("ActiveState=inactive", "ActiveState=unknown"),
    ):
        try:
            switch._writer_unit_state(
                StatusRunner(output), switch.AUTHORITY_SERVICE
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("malformed or missing writer status was accepted")
    try:
        switch._writer_unit_state(
            StatusRunner(valid, returncode=1), switch.AUTHORITY_SERVICE
        )
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("failed writer status command was accepted")

    with tempfile.TemporaryDirectory(prefix="writer-cgroup-guards-") as raw:
        root = Path(raw)
        group = "/system.slice/devcoordinator-authority.service"
        events = root.joinpath(*group.split("/")[1:]) / "cgroup.events"
        events.parent.mkdir(parents=True)
        events.write_text("populated 0\npopulated 1\n", encoding="ascii")
        try:
            switch._writer_cgroup_populated(
                group, cgroup_root=root, allow_missing=False
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("duplicate cgroup populated evidence was accepted")
        events.unlink()
        target = root / "real-events"
        target.write_text("populated 0\n", encoding="ascii")
        events.symlink_to(target)
        try:
            switch._writer_cgroup_populated(
                group, cgroup_root=root, allow_missing=False
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("symlinked cgroup evidence bypassed O_NOFOLLOW")
        events.unlink()
        events.write_text("populated 0\n", encoding="ascii")
        original_read = os.read
        swapped = [False]

        def swapping_read(descriptor: int, maximum: int) -> bytes:
            if not swapped[0]:
                swapped[0] = True
                displaced = events.with_name("cgroup.events.displaced")
                events.rename(displaced)
                events.write_text("populated 0\n", encoding="ascii")
            return original_read(descriptor, maximum)

        with mock.patch.object(switch.os, "read", side_effect=swapping_read):
            try:
                switch._writer_cgroup_populated(
                    group, cgroup_root=root, allow_missing=False
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("replaced cgroup path retained stale fd authority")

        unsafe_root = root / "unsafe-root"
        real_slice = root / "real-slice"
        real_unit = real_slice / "devcoordinator-authority.service"
        real_unit.mkdir(parents=True)
        (real_unit / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        unsafe_root.mkdir()
        (unsafe_root / "system.slice").symlink_to(real_slice, target_is_directory=True)
        try:
            switch._writer_cgroup_populated(
                group, cgroup_root=unsafe_root, allow_missing=False
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("symlinked cgroup ancestry was accepted")

    with tempfile.TemporaryDirectory(prefix="all-writer-stop-") as raw:
        cgroup_root = Path(raw) / "cgroup"
        authority_group = "/system.slice/devcoordinator-authority.service"
        events = cgroup_root.joinpath(
            *authority_group.split("/")[1:]
        ) / "cgroup.events"
        events.parent.mkdir(parents=True)
        events.write_text("populated 1\n", encoding="ascii")
        service_groups = {
            unit: f"/system.slice/{unit}"
            for unit in switch.AUTHORITY_WRITER_UNITS
            if unit.endswith(".service")
        }
        for group in service_groups.values():
            service_events = cgroup_root.joinpath(
                *group.split("/")[1:]
            ) / "cgroup.events"
            service_events.parent.mkdir(parents=True, exist_ok=True)
            service_events.write_text("populated 1\n", encoding="ascii")

        class AllWriterRunner(FakeRunner):
            def __init__(
                self,
                *,
                restart_race: bool = False,
                inactive_drift: bool = False,
                failed_stop_unit: str | None = None,
                terminal_on_failure: bool = True,
            ) -> None:
                super().__init__()
                self.active = {unit: True for unit in switch.AUTHORITY_WRITER_UNITS}
                self.show_counts = {unit: 0 for unit in switch.AUTHORITY_WRITER_UNITS}
                self.stop_units: list[str] = []
                self.restart_race = restart_race
                self.inactive_drift = inactive_drift
                self.failed_stop_unit = failed_stop_unit
                self.terminal_on_failure = terminal_on_failure

            def run_bounded(
                self, argv: list[str], *, timeout_seconds: float
            ) -> subprocess.CompletedProcess[str]:
                self.commands.append(list(argv))
                if "show" in argv:
                    unit = argv[2]
                    self.show_counts[unit] += 1
                    active = self.active[unit]
                    if (
                        self.restart_race
                        and unit == switch.AUTHORITY_WRITER_UNITS[0]
                        and self.show_counts[unit] >= 3
                    ):
                        active = True
                    service = unit.endswith(".service")
                    pid = 4312 if active and service else 0
                    substate = "running" if active else "dead"
                    if (
                        self.inactive_drift
                        and unit == switch.AUTHORITY_WRITER_UNITS[0]
                        and self.show_counts[unit] >= 3
                    ):
                        substate = "failed"
                    properties = [
                        "LoadState=loaded",
                        f"ActiveState={'active' if active else 'inactive'}",
                        f"SubState={substate}",
                    ]
                    if service:
                        properties.extend(
                            (
                                f"MainPID={pid}",
                                f"ControlGroup={service_groups[unit]}",
                            )
                        )
                    return subprocess.CompletedProcess(
                        argv,
                        0,
                        "\n".join(properties),
                        "",
                    )
                if "stop" in argv:
                    unit = argv[-1]
                    self.stop_units.append(unit)
                    failed = unit == self.failed_stop_unit
                    if not failed or self.terminal_on_failure:
                        self.active[unit] = False
                    if unit in service_groups:
                        service_events = cgroup_root.joinpath(
                            *service_groups[unit].split("/")[1:]
                        ) / "cgroup.events"
                        if not failed or self.terminal_on_failure:
                            service_events.write_text("populated 0\n", encoding="ascii")
                    if failed:
                        return subprocess.CompletedProcess(argv, 1, "", "lost reply")
                return subprocess.CompletedProcess(argv, 0, "", "")

        clock_value = [0.0]

        def clock() -> float:
            return clock_value[0]

        def sleeper(seconds: float) -> None:
            clock_value[0] += seconds

        runner = AllWriterRunner()
        switch.stop_authority_writers(
            runner,
            cgroup_root=cgroup_root,
            process_start_reader=lambda _pid: "process-start",
            process_observer=lambda _pid, _started: "absent",
            clock=clock,
            sleeper=sleeper,
            settle_seconds=0.2,
        )
        expect(
            runner.stop_units == list(switch.AUTHORITY_WRITER_UNITS),
            "bounded writer stop changed socket/service ordering",
        )
        before_replay = list(runner.stop_units)
        switch.stop_authority_writers(
            runner,
            cgroup_root=cgroup_root,
            process_start_reader=lambda _pid: "process-start",
            process_observer=lambda _pid, _started: "absent",
            clock=clock,
            sleeper=sleeper,
            settle_seconds=0.2,
        )
        expect(
            runner.stop_units == before_replay,
            "inactive writer replay issued another stop",
        )

        lost_unit = switch.AUTHORITY_WRITER_UNITS[0]
        events.write_text("populated 1\n", encoding="ascii")
        reconciled = AllWriterRunner(failed_stop_unit=lost_unit)
        switch.stop_authority_writers(
            reconciled,
            cgroup_root=cgroup_root,
            process_start_reader=lambda _pid: "process-start",
            process_observer=lambda _pid, _started: "absent",
            clock=clock,
            sleeper=sleeper,
            settle_seconds=0.2,
        )
        expect(
            lost_unit in reconciled.stop_units,
            "nonzero writer stop reply was not terminally reconciled",
        )

        events.write_text("populated 1\n", encoding="ascii")
        unresolved = AllWriterRunner(
            failed_stop_unit=lost_unit, terminal_on_failure=False
        )
        try:
            switch.stop_authority_writers(
                unresolved,
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                settle_seconds=0.2,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("nonterminal failed writer stop was reconciled")

        events.write_text("populated 1\n", encoding="ascii")
        racing = AllWriterRunner(restart_race=True)
        try:
            switch.stop_authority_writers(
                racing,
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                settle_seconds=0.2,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("writer restart race passed stable inactive proof")

        drifted = AllWriterRunner(inactive_drift=True)
        events.write_text("populated 1\n", encoding="ascii")
        try:
            switch.stop_authority_writers(
                drifted,
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                settle_seconds=0.2,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("inactive writer state drift passed stable proof")

        class PopulatedRunner(AllWriterRunner):
            def run_bounded(
                self, argv: list[str], *, timeout_seconds: float
            ) -> subprocess.CompletedProcess[str]:
                result = super().run_bounded(argv, timeout_seconds=timeout_seconds)
                retained_unit = "devcoordinator-api.service"
                if "stop" in argv and argv[-1] == retained_unit:
                    retained_events = cgroup_root.joinpath(
                        *service_groups[retained_unit].split("/")[1:]
                    ) / "cgroup.events"
                    retained_events.write_text("populated 1\n", encoding="ascii")
                return result

        events.write_text("populated 1\n", encoding="ascii")
        try:
            switch.stop_authority_writers(
                PopulatedRunner(),
                cgroup_root=cgroup_root,
                process_start_reader=lambda _pid: "process-start",
                process_observer=lambda _pid, _started: "absent",
                clock=clock,
                sleeper=sleeper,
                settle_seconds=0.2,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("populated non-authority service cgroup was accepted")


def exercise_rollback_restores_control_plane_before_background_services() -> None:
    class BackgroundFailureRunner(FakeRunner):
        def require(self, argv: list[str], _label: str) -> str:
            self.commands.append(list(argv))
            if argv[-1] == "devcoordinator-observer.service":
                raise switch.SwitchError("observer start deadline exceeded")
            return ""

    runner = BackgroundFailureRunner()
    switch.restore_rollback_control_plane(
        runner, ready_waiter=lambda _runner: None
    )
    try:
        switch.restore_rollback_background_services(runner)
    except switch.SwitchError:
        pass
    else:
        raise AssertionError("background rollback failure was not injected")

    critical_restart = [
        "/usr/bin/systemctl",
        "--job-mode=ignore-requirements",
        "restart",
        *switch.ROLLBACK_CRITICAL_SOCKETS,
        *switch.ROLLBACK_CRITICAL_SERVICES,
    ]
    observer_failure = next(
        index
        for index, command in enumerate(runner.commands)
        if command[-1] == "devcoordinator-observer.service"
    )
    expect(
        runner.commands.index(critical_restart) < observer_failure,
        "background rollback failure occurred before stable authority/API recovery",
    )

    order_runner = FakeRunner()
    switch.restore_rollback_control_plane(
        order_runner, ready_waiter=lambda _runner: None
    )
    switch.restore_rollback_background_services(order_runner)
    critical_enable = [
        ["/usr/bin/systemctl", "enable", unit]
        for unit in (
            *switch.ROLLBACK_CRITICAL_SOCKETS,
            *switch.ROLLBACK_CRITICAL_SERVICES,
        )
    ]
    background_enable = [
        ["/usr/bin/systemctl", "enable", unit]
        for unit in (
            *switch.ROLLBACK_BACKGROUND_SOCKETS,
            *switch.ROLLBACK_BACKGROUND_SERVICES,
        )
    ]
    background_restart = [
        "/usr/bin/systemctl",
        "restart",
        *switch.ROLLBACK_BACKGROUND_SOCKETS,
        *switch.ROLLBACK_BACKGROUND_SERVICES,
    ]
    expect(
        order_runner.commands
        == [
            *critical_enable,
            critical_restart,
            *background_enable,
            background_restart,
        ]
        and set(switch.ROLLBACK_CRITICAL_SOCKETS)
        .isdisjoint(switch.ROLLBACK_BACKGROUND_SOCKETS)
        and set(switch.ROLLBACK_CRITICAL_SOCKETS)
        | set(switch.ROLLBACK_BACKGROUND_SOCKETS)
        == set(switch.REQUIRED_SOCKETS)
        and "--job-mode=ignore-requirements" in critical_restart
        and "--job-mode=ignore-dependencies" not in critical_restart,
        "rollback did not use disjoint critical/background service transactions",
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
                "retained_control_rebaseline": {
                    "required": True,
                    "source_schema_version": 15,
                    "target_schema_version": 16,
                    "status": "planned",
                },
            }
            document["test_history_reset"] = switch.test_history_reset_intent(
                current,
                previous_release_digest="b" * 64,
                source_authority_schema_version=15,
            )
            expect(
                document["test_history_reset"][
                    "expected_previous_test_store_schema_version"
                ]
                == switch.RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION
                == 6,
                "one-time rebaseline did not bind the schema-6 predecessor",
            )
            document["test_history_reset"][
                "expected_previous_test_store_schema_version"
            ] = 5
            try:
                switch.require_test_history_reset_mode(document, requested=True)
            except switch.SwitchError:
                pass
            else:
                raise AssertionError(
                    "test-history reset accepted a stale journal-bound predecessor schema"
                )
            document["test_history_reset"][
                "expected_previous_test_store_schema_version"
            ] = switch.RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION

            current_format_document: dict[str, object] = {
                "release": str(current),
                "previous_release_digest": "b" * 64,
                "retained_control_rebaseline": {
                    "required": False,
                    "source_schema_version": 16,
                    "target_schema_version": 16,
                    "status": "planned",
                },
            }
            current_format_document["test_history_reset"] = (
                switch.test_history_reset_intent(
                    current,
                    previous_release_digest="b" * 64,
                    source_authority_schema_version=16,
                )
            )
            current_format_reset = switch.require_test_history_reset_mode(
                current_format_document, requested=True
            )
            expect(
                current_format_reset is not None
                and current_format_reset[
                    "expected_previous_test_store_schema_version"
                ]
                == switch.CURRENT_TEST_STORE_SCHEMA_VERSION
                == 8,
                "current-format reset did not bind the merged schema-8 contract",
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
                reset["forward_evidence"]["schema_version"]
                == switch.CURRENT_TEST_STORE_SCHEMA_VERSION
                == 8,
                "forward reset did not attest the merged schema-8 store",
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
            wrong_schema = HistoryRunner(rollback_schema=5)
            try:
                switch.reset_test_history_for_rollback(
                    document, journal, wrong_schema
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError(
                    "rollback accepted a Test Store schema outside the exact predecessor contract"
                )
            expect(
                document["test_history_reset"]["status"]
                == "rollback-resetting",
                "wrong predecessor schema did not retain replayable rollback state",
            )
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
                reset["rollback_evidence"]["schema_version"]
                == switch.RETAINED_PREDECESSOR_TEST_STORE_SCHEMA_VERSION,
                "rollback did not initialize the exact schema-6 predecessor store",
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


def exercise_prepared_supersession_clears_only_exact_claim() -> None:
    candidate_digest = "a" * 64
    previous_digest = "b" * 64
    current_digest = "c" * 64
    uid, gid = os.geteuid(), os.getegid()

    def prepared_document(candidate: Path) -> dict[str, object]:
        return {
            "schema_version": switch.VERSION,
            "kind": switch.KIND,
            "phase": "prepared",
            "release": str(candidate),
            "release_digest": candidate.name,
            "previous_release_digest": previous_digest,
            "backups": {},
            "candidate_started": False,
            "promoted": False,
            "publication_switched": False,
            "completed_at": None,
            "retained_control_rebaseline": {
                "required": True,
                "source_schema_version": 15,
                "target_schema_version": 16,
                "status": "planned",
            },
        }

    with tempfile.TemporaryDirectory(prefix="prepared-supersession-") as raw:
        root = Path(raw)
        releases = root / "releases"
        candidate = releases / candidate_digest
        current = releases / current_digest
        candidate.mkdir(parents=True)
        current.mkdir()
        transaction = root / "run" / candidate_digest
        transaction.mkdir(parents=True, mode=0o700)
        transaction.parent.chmod(0o700)
        journal = transaction / "journal.json"
        document = prepared_document(candidate)
        switch.atomic_json(journal, document)
        journal_before = switch.exact_file_identity(journal)
        lock = root / "installer.lock"
        claim_root = root / "claims"
        claim_root.mkdir(mode=0o700)
        claim = claim_root / "claim.json"
        held, identity = switch.acquire_delivery_fence(
            transaction,
            release_digest=candidate_digest,
            action="prepare",
            expected_uid=uid,
            expected_gid=gid,
            lock_path=lock,
            claim_path=claim,
        )
        held.close(command_succeeded=False)
        runner = FakeRunner()
        root_args = {
            "expected_uid": uid,
            "expected_gid": gid,
            "lock_path": lock,
            "claim_path": claim,
            "expected_current_release_digest": current_digest,
        }
        with (
            mock.patch.object(
                switch, "require_transaction_root", return_value=transaction
            ),
            mock.patch.object(
                switch,
                "require_current_live_release_identity",
                return_value={"evidence_sha256": "d" * 64},
            ),
        ):
            result = switch.execute_fenced_switch_action(
                "supersede-prepared",
                candidate,
                transaction,
                runner,
                **root_args,
            )
            replay = switch.execute_fenced_switch_action(
                "supersede-prepared",
                candidate,
                transaction,
                runner,
                **root_args,
            )
        expect(
            result["phase"] == "superseded-before-mutation"
            and replay["successor_release_digest"] == current_digest
            and not claim.exists()
            and runner.commands == []
            and switch.exact_file_identity(journal) == journal_before,
            "prepared supersession mutated product state or was not replayable",
        )
        parsed = switch.parser().parse_args(
            [
                "supersede-prepared",
                "--release",
                str(candidate),
                "--transaction-root",
                str(transaction),
                "--expected-current-release-digest",
                current_digest,
            ]
        )
        expect(
            parsed.expected_current_release_digest == current_digest,
            "prepared supersession CLI lost explicit successor identity",
        )
        with (
            mock.patch.object(
                switch, "require_transaction_root", return_value=transaction
            ),
            mock.patch.object(
                switch,
                "require_current_live_release_identity",
                return_value={"evidence_sha256": "d" * 64},
            ),
        ):
            try:
                switch.execute_fenced_switch_action(
                    "supersede-prepared",
                    candidate,
                    transaction,
                    FakeRunner(),
                    **{
                        **root_args,
                        "expected_current_release_digest": previous_digest,
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("prepared supersession accepted previous release")
        expect(not claim.exists(), "failed replay left a borrowed claim")
        terminal = switch.delivery_fence_terminal(
            transaction,
            identity,
            expected_uid=uid,
            expected_gid=gid,
        )
        expect(
            terminal is not None
            and terminal["outcome"] == "superseded-before-mutation"
            and terminal["successor_release_digest"] == current_digest,
            "prepared supersession terminal lost successor evidence",
        )
        terminal_path = transaction / switch.DELIVERY_FENCE_TERMINAL_NAME
        terminal_before = terminal_path.read_bytes()
        journal_payload_before = journal.read_bytes()
        for stale_action in ("prepare", "apply"):
            stale_runner = FakeRunner()
            with (
                mock.patch.object(
                    switch, "require_transaction_root", return_value=transaction
                ),
                mock.patch.object(
                    switch,
                    stale_action,
                    side_effect=AssertionError(
                        f"stale {stale_action} reached product mutation"
                    ),
                ) as forbidden,
            ):
                try:
                    switch.execute_fenced_switch_action(
                        stale_action,
                        candidate,
                        transaction,
                        stale_runner,
                        **root_args,
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(
                        f"stale {stale_action} resumed a superseded transaction"
                    )
            expect(
                not forbidden.called
                and not claim.exists()
                and stale_runner.commands == []
                and journal.read_bytes() == journal_payload_before
                and terminal_path.read_bytes() == terminal_before,
                f"stale {stale_action} changed supersession evidence or product state",
            )

        for field, value in (
            ("phase", "applying"),
            ("backups", {"changed": {}}),
            ("candidate_started", True),
            ("promoted", True),
            ("publication_switched", True),
        ):
            changed = prepared_document(candidate)
            changed[field] = value
            switch.atomic_json(journal, changed)
            try:
                switch.require_supersedable_prepared_journal(
                    journal,
                    candidate_release=candidate,
                    successor_release_digest=current_digest,
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError(f"prepared supersession accepted {field} drift")
        changed = prepared_document(candidate)
        changed["retained_control_rebaseline"] = {
            **changed["retained_control_rebaseline"],
            "source_worker_quiescence": {},
        }
        switch.atomic_json(journal, changed)
        try:
            switch.require_supersedable_prepared_journal(
                journal,
                candidate_release=candidate,
                successor_release_digest=current_digest,
            )
        except switch.SwitchError:
            pass
        else:
            raise AssertionError("prepared supersession accepted worker proof mutation")
        switch.atomic_json(journal, document)

        live_failure_transaction = root / "failed" / candidate_digest
        live_failure_transaction.mkdir(parents=True, mode=0o700)
        live_failure_transaction.parent.chmod(0o700)
        switch.atomic_json(
            live_failure_transaction / "journal.json", prepared_document(candidate)
        )
        failed_handle, _failed_identity = switch.acquire_delivery_fence(
            live_failure_transaction,
            release_digest=candidate_digest,
            action="prepare",
            expected_uid=uid,
            expected_gid=gid,
            lock_path=lock,
            claim_path=claim,
        )
        failed_handle.close(command_succeeded=False)
        with (
            mock.patch.object(
                switch,
                "require_transaction_root",
                return_value=live_failure_transaction,
            ),
            mock.patch.object(
                switch,
                "require_current_live_release_identity",
                side_effect=switch.SwitchError("live release mismatch"),
            ),
        ):
            try:
                switch.execute_fenced_switch_action(
                    "supersede-prepared",
                    candidate,
                    live_failure_transaction,
                    FakeRunner(),
                    **root_args,
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live mismatch cleared prepared claim")
        expect(claim.exists(), "failed supersession released durable owner")

        unit_root = root / "units"
        slot_root = root / "slots"
        unit_root.mkdir()
        slot_root.mkdir()
        publication = root / "publication.json"
        outer, inner = 41001, 41002
        switch.atomic_json(
            publication,
            {
                "schema_version": 1,
                "payload_sha256": "e" * 64,
                "publication": {
                    "release_digest": current_digest,
                    "generation": 9,
                    "console": {"upstream": {"port": outer}},
                },
            },
        )
        switch.atomic_bytes(
            slot_root / f"{current_digest}.env",
            switch.candidate_slot_payload(current_digest, outer, inner),
            0o644,
        )
        launchers = {
            rendered_name: (root / "bin" / destination.name, immutable_name)
            for rendered_name, (
                destination,
                immutable_name,
            ) in switch.STABLE_LAUNCHERS.items()
        }
        required_launchers = set(launchers) - set(
            switch.RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS
        )
        expect(
            switch.RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS
            == {switch.EDGE_CERT_REFRESH_LAUNCHER_RENDERED}
            and required_launchers
            == set(switch.RETAINED_PREDECESSOR_REQUIRED_LAUNCHERS)
            and len(required_launchers) == 7,
            "retained predecessor launcher boundary is not exactly seven required and one optional",
        )
        for rendered_name, (destination, immutable_name) in launchers.items():
            if rendered_name in switch.RETAINED_PREDECESSOR_OPTIONAL_LAUNCHERS:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            switch.atomic_bytes(
                destination,
                (
                    "#!/bin/sh\nset -eu\n"
                    f"exec '{current / 'bin' / immutable_name}' \"$@\"\n"
                ).encode("utf-8"),
                0o755,
            )
        for name in (
            "devcoordinator-api.service",
            "devcoordinator-authority.service",
            "devcoordinator-edge.service",
            "devcoordinator-notifications.service",
            "devcoordinator-observer.service",
            "devcoordinator-test-snapshotd.service",
            "devcoordinator-testd.service",
        ):
            switch.atomic_bytes(
                unit_root / name,
                f"ExecStart=/opt/devcoordinator/releases/{current_digest}/bin/tool\n".encode(),
                0o644,
            )
        with (
            mock.patch.object(switch, "UNIT_ROOT", unit_root),
            mock.patch.object(switch, "SLOT_ROOT", slot_root),
            mock.patch.object(switch, "PUBLICATION_FILE", publication),
            mock.patch.object(switch, "STABLE_LAUNCHERS", launchers),
        ):
            schema_reads: list[int] = []

            def stable_schema() -> int:
                schema_reads.append(15)
                return 15

            evidence = switch.require_current_live_release_identity(
                current,
                schema_reader=stable_schema,
                release_verifier=lambda selected: {
                    "release_digest": selected.name
                },
            )
            replayed_evidence = switch.require_current_live_release_identity(
                current,
                schema_reader=stable_schema,
                release_verifier=lambda selected: {
                    "release_digest": selected.name
                },
            )
            expect(
                evidence["release_digest"] == current_digest
                and replayed_evidence == evidence
                and schema_reads == [15, 15, 15, 15]
                and evidence["launchers"][
                    str(
                        launchers[switch.EDGE_CERT_REFRESH_LAUNCHER_RENDERED][0]
                    )
                ]
                is None,
                "current live release evidence lost exact deterministic identity",
            )
            optional_destination, optional_name = launchers[
                switch.EDGE_CERT_REFRESH_LAUNCHER_RENDERED
            ]
            expected_optional_launcher = (
                "#!/bin/sh\nset -eu\n"
                f"exec '{current / 'bin' / optional_name}' \"$@\"\n"
            ).encode("utf-8")
            switch.atomic_bytes(
                optional_destination, expected_optional_launcher, 0o755
            )
            present_optional = switch.require_current_live_release_identity(
                current,
                schema_reader=lambda: 15,
                release_verifier=lambda selected: {
                    "release_digest": selected.name
                },
            )
            expect(
                present_optional["launchers"][str(optional_destination)]
                == hashlib.sha256(expected_optional_launcher).hexdigest(),
                "matching optional predecessor launcher was not evidence-bound",
            )
            switch.atomic_bytes(
                optional_destination, b"wrong optional launcher\n", 0o755
            )
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError(
                    "live release verifier accepted mismatched optional launcher"
                )
            switch.atomic_bytes(
                optional_destination, expected_optional_launcher, 0o755
            )
            switch.atomic_bytes(
                unit_root / "devcoordinator-api.service",
                f"ExecStart=/opt/devcoordinator/releases/{previous_digest}/bin/tool\n".encode(),
                0o644,
            )
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live release verifier accepted mixed units")
            switch.atomic_bytes(
                unit_root / "devcoordinator-api.service",
                f"ExecStart=/opt/devcoordinator/releases/{current_digest}/bin/tool\n".encode(),
                0o644,
            )
            switch.atomic_bytes(
                unit_root / "devcoordinator-edge.service",
                f"ExecStart=/opt/devcoordinator/releases/{previous_digest}/bin/tool\n".encode(),
                0o644,
            )
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live release verifier accepted mixed edge unit")
            switch.atomic_bytes(
                unit_root / "devcoordinator-edge.service",
                f"ExecStart=/opt/devcoordinator/releases/{current_digest}/bin/tool\n".encode(),
                0o644,
            )
            launcher_destination, launcher_name = launchers[
                switch.CLIENT_LAUNCHER_RENDERED
            ]
            expected_launcher = (
                "#!/bin/sh\nset -eu\n"
                f"exec '{current / 'bin' / launcher_name}' \"$@\"\n"
            ).encode("utf-8")
            launcher_destination.unlink()
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError(
                    "live release verifier accepted missing required launcher"
                )
            switch.atomic_bytes(launcher_destination, expected_launcher, 0o755)
            switch.atomic_bytes(launcher_destination, b"wrong launcher\n", 0o755)
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live release verifier accepted mixed launcher")
            switch.atomic_bytes(launcher_destination, expected_launcher, 0o755)

            switch.atomic_json(
                publication,
                {
                    "schema_version": 1,
                    "payload_sha256": "e" * 64,
                    "publication": {
                        "release_digest": previous_digest,
                        "generation": 9,
                        "console": {"upstream": {"port": outer}},
                    },
                },
            )
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live release verifier accepted mixed publication")
            switch.atomic_json(
                publication,
                {
                    "schema_version": 1,
                    "payload_sha256": "e" * 64,
                    "publication": {
                        "release_digest": current_digest,
                        "generation": 9,
                        "console": {"upstream": {"port": outer}},
                    },
                },
            )

            switch.atomic_bytes(
                slot_root / f"{current_digest}.env",
                switch.candidate_slot_payload(previous_digest, outer, inner),
                0o644,
            )
            try:
                switch.require_current_live_release_identity(
                    current,
                    schema_reader=lambda: 15,
                    release_verifier=lambda selected: {
                        "release_digest": selected.name
                    },
                )
            except switch.SwitchError:
                pass
            else:
                raise AssertionError("live release verifier accepted mixed Console slot")
            switch.atomic_bytes(
                slot_root / f"{current_digest}.env",
                switch.candidate_slot_payload(current_digest, outer, inner),
                0o644,
            )

            race_cases = (
                (
                    "publication",
                    lambda: switch.atomic_json(
                        publication,
                        {
                            "schema_version": 1,
                            "payload_sha256": "e" * 64,
                            "publication": {
                                "release_digest": current_digest,
                                "generation": 10,
                                "console": {"upstream": {"port": outer}},
                            },
                        },
                    ),
                    lambda: switch.atomic_json(
                        publication,
                        {
                            "schema_version": 1,
                            "payload_sha256": "e" * 64,
                            "publication": {
                                "release_digest": current_digest,
                                "generation": 9,
                                "console": {"upstream": {"port": outer}},
                            },
                        },
                    ),
                ),
                (
                    "Console slot",
                    lambda: switch.atomic_bytes(
                        slot_root / f"{current_digest}.env",
                        switch.candidate_slot_payload(
                            current_digest, outer, inner + 1
                        ),
                        0o644,
                    ),
                    lambda: switch.atomic_bytes(
                        slot_root / f"{current_digest}.env",
                        switch.candidate_slot_payload(current_digest, outer, inner),
                        0o644,
                    ),
                ),
                (
                    "launcher",
                    lambda: switch.atomic_bytes(
                        launcher_destination, b"changed between snapshots\n", 0o755
                    ),
                    lambda: switch.atomic_bytes(
                        launcher_destination, expected_launcher, 0o755
                    ),
                ),
                (
                    "unit",
                    lambda: switch.atomic_bytes(
                        unit_root / "devcoordinator-edge.service",
                        (
                            "# changed between snapshots\n"
                            f"ExecStart=/opt/devcoordinator/releases/{current_digest}/bin/tool\n"
                        ).encode(),
                        0o644,
                    ),
                    lambda: switch.atomic_bytes(
                        unit_root / "devcoordinator-edge.service",
                        f"ExecStart=/opt/devcoordinator/releases/{current_digest}/bin/tool\n".encode(),
                        0o644,
                    ),
                ),
            )
            for label, mutate, restore in race_cases:
                reads = 0

                def mutate_after_first_snapshot() -> int:
                    nonlocal reads
                    reads += 1
                    if reads == 1:
                        mutate()
                    return 15

                try:
                    switch.require_current_live_release_identity(
                        current,
                        schema_reader=mutate_after_first_snapshot,
                        release_verifier=lambda selected: {
                            "release_digest": selected.name
                        },
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(
                        f"live release verifier accepted {label} snapshot race"
                    )
                finally:
                    restore()

            for label, target in (
                ("publication", publication),
                ("Console slot", slot_root / f"{current_digest}.env"),
                ("launcher", launcher_destination),
                ("unit", unit_root / "devcoordinator-edge.service"),
            ):
                original = target.read_bytes()
                target_info = target.lstat()
                original_read = os.read
                swapped = False

                def swap_path_after_read(descriptor: int, size: int) -> bytes:
                    nonlocal swapped
                    payload = original_read(descriptor, size)
                    opened = os.fstat(descriptor)
                    if not swapped and (opened.st_dev, opened.st_ino) == (
                        target_info.st_dev,
                        target_info.st_ino,
                    ):
                        switch.atomic_bytes(
                            target, original, stat.S_IMODE(target_info.st_mode)
                        )
                        swapped = True
                    return payload

                with mock.patch.object(
                    switch.os, "read", side_effect=swap_path_after_read
                ):
                    try:
                        switch.require_current_live_release_identity(
                            current,
                            schema_reader=lambda: 15,
                            release_verifier=lambda selected: {
                                "release_digest": selected.name
                            },
                        )
                    except switch.SwitchError:
                        pass
                    else:
                        raise AssertionError(
                            f"live release verifier accepted {label} path swap"
                        )
                expect(swapped, f"{label} path-swap fixture did not execute")

            for schema_reader, release_verifier, label in (
                (
                    lambda: 16,
                    lambda selected: {"release_digest": selected.name},
                    "schema",
                ),
                (
                    lambda: 15,
                    lambda _selected: {"release_digest": previous_digest},
                    "immutable release",
                ),
            ):
                try:
                    switch.require_current_live_release_identity(
                        current,
                        schema_reader=schema_reader,
                        release_verifier=release_verifier,
                    )
                except switch.SwitchError:
                    pass
                else:
                    raise AssertionError(
                        f"live release verifier accepted mixed {label}"
                    )


def exercise_retained_control_transaction_boundary() -> None:
    apply_source = inspect.getsource(switch.apply_retained_control_rebaseline)
    completion_source = inspect.getsource(
        switch.complete_retained_control_rebaseline
    )
    post_start_source = inspect.getsource(
        switch._require_post_start_retained_target
    )
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
        apply_source.count("_require_exact_live_retained_target(") == 1
        and apply_source.index("_require_exact_live_retained_target(")
        < apply_source.index('intent.update({"status": "published"')
        and "_require_post_start_retained_target(" in apply_source
        and "_require_exact_live_retained_target(" not in completion_source
        and "_require_post_start_retained_target(" in completion_source
        and switch_source.index("restart_services(runner)")
        < switch_source.index("complete_retained_control_rebaseline("),
        "stopped-writer bytes and post-start semantics are checked in the wrong phases",
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
        in inspect.getsource(switch._require_exact_live_retained_target)
        and "_require_exact_live_server_credentials(" in post_start_source,
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
        and "_require_post_start_retained_target(" in verify_source,
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


def exercise_post_start_retained_target_semantics() -> None:
    generation = "post-start-generation"

    def must_reject(callback, label: str) -> None:
        try:
            callback()
        except switch.SwitchError:
            pass
        else:
            raise AssertionError(label)

    with tempfile.TemporaryDirectory(prefix="retained-post-start-") as raw:
        root = Path(raw)
        authority_root = root / "authority"
        profile_root = root / "profile"
        console_root = root / "console"
        transaction = root / "transaction"
        for directory in (
            authority_root,
            profile_root,
            console_root,
            transaction,
        ):
            directory.mkdir(mode=0o700)
        authority = authority_root / "authority.sqlite3"
        profile = profile_root / "client-profiles.json"
        connection = sqlite3.connect(authority)
        try:
            connection.execute(
                "CREATE TABLE schema_metadata("
                "singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL,"
                "database_generation TEXT NOT NULL,state_revision INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO schema_metadata VALUES(1,16,?,0)",
                (generation,),
            )
            connection.commit()
        finally:
            connection.close()
        authority.chmod(0o600)
        profile_document = {
            "version": 2,
            "service": {
                "socket": "/run/devcoordinator-authority/authority.sock",
                "database_generation": generation,
            },
        }
        console_documents = {
            "routes.json": {"version": 1, "routes": {}},
            "access-control.json": {
                "version": 3,
                "users": {},
                "requests": {},
            },
            "ui-prefs.json": {
                "version": 1,
                "hidden": {"servers": [], "docker": [], "projects": []},
            },
        }
        switch.atomic_json(profile, profile_document)
        console_paths: dict[str, Path] = {}
        for name, document in console_documents.items():
            path = console_root / name
            switch.atomic_json(path, document)
            console_paths[name] = path

        def backup(path: Path) -> dict[str, object]:
            return {
                "existed": True,
                "source": switch.exact_file_identity(path),
            }

        backups = {
            str(authority): backup(authority),
            str(profile): backup(profile),
            **{str(path): backup(path) for path in console_paths.values()},
        }
        manifest = {
            "target": {
                "database": switch.exact_file_identity(authority),
                "profile": switch.exact_file_identity(profile),
                "database_generation": generation,
            },
            "console_files": {
                name: switch.exact_file_identity(path)
                for name, path in console_paths.items()
            },
            "server_credentials": [],
        }

        def prove() -> None:
            switch._require_post_start_retained_target(
                manifest, backups, transaction
            )

        def update_authority(
            *, schema: int = 16, current_generation: str = generation
        ) -> None:
            connection = sqlite3.connect(authority)
            try:
                connection.execute(
                    "UPDATE schema_metadata SET schema_version=?,"
                    "database_generation=?,state_revision=state_revision+1 "
                    "WHERE singleton=1",
                    (schema, current_generation),
                )
                connection.commit()
            finally:
                connection.close()

        with (
            mock.patch.object(switch, "AUTHORITY_DATABASE", authority),
            mock.patch.object(switch, "CLIENT_PROFILE", profile),
            mock.patch.object(switch, "CONSOLE_STATE_ROOT", console_root),
        ):
            prove()
            staged_sha256 = manifest["target"]["database"]["sha256"]
            update_authority()
            expect(
                switch.digest_file(authority) != staged_sha256,
                "startup mutation fixture did not change authority bytes",
            )
            prove()
            must_reject(
                lambda: switch._require_exact_live_retained_target(
                    manifest, backups, transaction
                ),
                "stopped-writer byte proof accepted a post-start database mutation",
            )

            update_authority(schema=17)
            must_reject(prove, "post-start proof accepted another authority schema")
            update_authority()
            update_authority(current_generation="another-generation")
            must_reject(prove, "post-start proof accepted another authority generation")
            update_authority()

            saved_authority = authority.with_name("authority.saved.sqlite3")
            replacement_authority = authority.with_name(
                "authority.replacement.sqlite3"
            )
            shutil.copy2(authority, saved_authority)
            shutil.copy2(authority, replacement_authority)
            real_connect = sqlite3.connect
            swapped = False

            def swap_authority_after_sqlite_open(*args, **kwargs):
                nonlocal swapped
                connection = real_connect(*args, **kwargs)
                if not swapped:
                    os.replace(replacement_authority, authority)
                    swapped = True
                return connection

            try:
                with mock.patch.object(
                    switch.sqlite3,
                    "connect",
                    side_effect=swap_authority_after_sqlite_open,
                ):
                    must_reject(
                        prove,
                        "post-start proof combined identity and generation from different authority files",
                    )
                expect(swapped, "authority path-swap fixture did not execute")
            finally:
                os.replace(saved_authority, authority)
                replacement_authority.unlink(missing_ok=True)

            authority.chmod(0o640)
            must_reject(prove, "post-start proof accepted another authority mode")
            authority.chmod(0o600)
            moved_authority = authority.with_name("authority.real")
            authority.rename(moved_authority)
            os.mkfifo(authority, 0o600)
            try:
                must_reject(
                    prove,
                    "post-start proof accepted a FIFO authority target",
                )
            finally:
                authority.unlink()
                moved_authority.rename(authority)
            moved_authority = authority.with_name("authority.real")
            authority.rename(moved_authority)
            authority.symlink_to(moved_authority)
            try:
                must_reject(
                    prove,
                    "post-start proof accepted a symlinked authority target",
                )
            finally:
                authority.unlink()
                moved_authority.rename(authority)
            live_contract = switch._live_regular_file_contract(authority)
            with mock.patch.object(
                switch,
                "_live_regular_file_contract",
                return_value={
                    **live_contract,
                    "uid": int(live_contract["uid"]) + 1,
                },
            ):
                must_reject(prove, "post-start proof accepted another authority owner")

            switch.atomic_json(
                profile,
                {
                    **profile_document,
                    "service": {
                        **profile_document["service"],
                        "database_generation": "another-generation",
                    },
                },
            )
            must_reject(prove, "post-start proof accepted changed exact profile")
            switch.atomic_json(profile, profile_document)

            preferences = console_paths["ui-prefs.json"]
            switch.atomic_json(
                preferences,
                {
                    "version": 1,
                    "hidden": {
                        "servers": ["changed"],
                        "docker": [],
                        "projects": [],
                    },
                },
            )
            must_reject(prove, "post-start proof accepted changed exact Console state")
            switch.atomic_json(preferences, console_documents["ui-prefs.json"])

            with mock.patch.object(
                switch,
                "_require_exact_live_server_credentials",
                side_effect=switch.SwitchError("credential drift"),
            ):
                must_reject(prove, "post-start proof accepted changed credentials")
            prove()


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
    exercise_retained_worker_deadlines_are_nested()
    exercise_authority_ready_is_invocation_bound()
    exercise_authority_writer_stop_is_bounded_and_exact()
    exercise_writer_stop_malformed_replay_and_race_guards()
    exercise_rollback_restores_control_plane_before_background_services()
    exercise_slot_readiness_waits_for_supervisor_socket()
    exercise_release_packaging_contract()
    exercise_stable_client_destination_transaction()
    exercise_codex_execpolicy_boundary()
    exercise_codex_directory_transaction()
    exercise_opt_in_test_history_reset_and_previous_release_rollback()
    exercise_reset_cli_is_explicit()
    exercise_software_delivery_fence_lifecycle()
    exercise_prepared_supersession_clears_only_exact_claim()
    exercise_retained_control_transaction_boundary()
    exercise_post_start_retained_target_semantics()
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
