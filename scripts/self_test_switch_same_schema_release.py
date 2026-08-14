#!/usr/bin/env python3
"""Focused regressions for the routine same-schema release switch."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import switch_same_schema_release as switch  # noqa: E402


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
        if "testd-initialize-fresh" in argv:
            attestation = argv[argv.index("--attestation-output") + 1]
            return {
                "ok": True,
                "action": "testd-initialize-fresh",
                "branch": "attested-fresh-v5",
                "attestation": attestation,
                "attestation_fingerprint": "c" * 64,
                "store_generation": "forward-generation",
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
                switch.activation.browser_lcp,
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
        source.index("migrate_trusted_local_authority("),
        source.index("restart_services("),
        source.index("candidate Console start"),
    ]
    expect(
        positions == sorted(positions),
        "browser cleanup is not candidate-stage-first and pre-activation",
    )
    rollback_source = inspect.getsource(switch.rollback)
    expect(
        rollback_source.index("restore_authority_migration(")
        < rollback_source.index("restore_rollback_control_plane("),
        "rollback can start the prior release before restoring its authority schema",
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
    ordering = [
        rollback_source.index("restore_destination_backups(backups)"),
        rollback_source.index("restore_rollback_control_plane(runner)"),
        rollback_source.index('"previous Console restore"'),
        rollback_source.index('"rollback-control-plane-restored"'),
        rollback_source.index("restore_rollback_background_services(runner)"),
    ]
    expect(
        ordering == sorted(ordering),
        "rollback does not checkpoint a coherent previous control plane before background restore",
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
        Path("scripts/switch_same_schema_release.py") in switch.installer.SOURCE_FILES,
        "same-schema switch source is absent from immutable releases",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-same-schema-switch")
        == ("python", "scripts/switch_same_schema_release.py", ()),
        "same-schema immutable wrapper is missing or points elsewhere",
    )
    expect(
        switch.installer.WRAPPERS.get("devcoordinator-test-history")
        == ("python", "scripts/migrate_universal_test_history.py", ()),
        "test-history reset wrapper is absent from immutable releases",
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
            "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
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
        b"dev_coordinator.py\" 'test' \"$@\"" in wrapper,
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
        rendered_names = (
            *stable,
            "devcoordinator-availability.sysusers.conf",
            "devcoordinator-availability.tmpfiles.conf",
            switch.MAIN_TMPFILES_RENDERED,
            switch.READ_ONLY_RULE_RENDERED,
            switch.TEST_RULE_RENDERED,
        )
        for index, name in enumerate(rendered_names):
            (rendered / name).write_bytes(f"candidate-{index}\n".encode())

        with (
            mock.patch.object(switch, "STABLE_LAUNCHERS", stable),
            mock.patch.object(switch.activation, "TOPOLOGY_FILES", ()),
            mock.patch.object(switch, "SYSUSERS_ROOT", sysusers),
            mock.patch.object(switch, "TMPFILES_ROOT", tmpfiles),
            mock.patch.object(switch, "READ_ONLY_RULE", read_only_rule),
            mock.patch.object(switch, "TEST_RULE", rule),
        ):
            mapping = switch.destinations(rendered)
            expect(
                {
                    *stable,
                    switch.MAIN_TMPFILES_RENDERED,
                    "devcoordinator-availability.tmpfiles.conf",
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
                reset["forward_evidence"]["schema_version"] == 5,
                "forward reset did not attest schema 5",
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
                if "testd-initialize-fresh" in command
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
                "rollback did not use the previous release's test-history wrapper",
            )
            expect(
                reset["rollback_evidence"]["schema_version"] == 5,
                "rollback did not initialize an empty schema-5 store",
            )


def exercise_reset_cli_is_explicit() -> None:
    for action in ("prepare", "apply", "rollback", "verify"):
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


def exercise_verification_requires_boot_enablement() -> None:
    source = inspect.getsource(switch.verify)
    rollback_source = inspect.getsource(switch.rollback)
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
        'promotion.extend(["--old-socket", candidate_control])' in rollback_source,
        "post-promotion rollback does not transfer the candidate writer lease",
    )
    expect(
        'args.action == "verify" and value.get("ok") is not True' in main_source
        and 'raise SwitchError("same-schema control-plane health failed")'
        not in source,
        "failed health verification hides its structured invariant evidence",
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
    exercise_browser_cleanup_skip_failure_and_malformed_result()
    exercise_browser_cleanup_activation_order()
    exercise_already_active_health_has_rendered_contract()
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
    exercise_verification_requires_boot_enablement()
    print("same-schema release switch self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
