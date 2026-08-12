from __future__ import annotations

import errno
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from devcoordinator import first_use_acceptance


class _Response:
    def __init__(self, *, status: int, payload: bytes) -> None:
        self.status = status
        self._payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _maximum: int) -> bytes:
        return self._payload


def _serve_result(*, execution_uid: int = 1000) -> dict[str, object]:
    return {
        "ok": True,
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "continuation": "dc1:operation:00000000-0000-4000-8000-000000000001",
        "service_id": "service-1234567890abcdef",
        "session_id": "session-1234567890abcdef",
        "repository_id": "repo-123",
        "repository_generation": 1,
        "name": "prototype",
        "state": "running",
        "main_pid": 42,
        "execution_uid": execution_uid,
        "port": 4173,
        "url": "http://127.0.0.1:4173/",
        "expires_at": "2026-08-04T12:00:20Z",
        "cleanup": {
            "owner": "systemd",
            "kill_mode": "control-group",
            "ttl_seconds": 20,
            "kill_after_run": False,
        },
        "isolation": {
            "manager": "systemd",
            "slice": "devcoordinator-projects-1000-repo123.slice",
            "control_group": "/devcoordinator.slice/devcoordinator-projects-1000-repo123.slice/devcoordinator-dev.service",
            "listener_owner_proven": True,
            "execution_uid": execution_uid,
            "actual_caller_uid_proven": True,
        },
    }


class _FakeClient:
    initial_state = "unconfigured"

    def __init__(
        self,
        _executable: Path,
        project: Path,
        caller_user: str | None = None,
    ) -> None:
        self.project = project
        self.caller_user = caller_user or "current-test-caller"
        self.caller_uid = 1000
        self.served = False
        self.exact_target_reads = 0
        self.status_reads = 0
        self.service_name: str | None = None
        self.collision_name: str | None = None
        self.port = 4173

    def call(
        self,
        arguments: tuple[str, ...],
        *,
        expect_ok: bool | None,
        timeout: float = 90.0,
    ) -> dict[str, object]:
        del timeout
        if arguments[0] == "capabilities":
            return {
                "ok": True,
                "repository": {
                    "state": "configured" if self.served else self.initial_state
                },
            }
        if arguments[0] == "targets":
            if len(arguments) > 1 and arguments[1] == self.collision_name:
                self._assert_expectation(expect_ok, False)
                return {
                    "ok": False,
                    "code": "target_not_found",
                    "message": "target selector matched no active resource",
                }
            exact = len(arguments) > 1 and arguments[1].startswith("service-")
            if exact:
                self.exact_target_reads += 1
                if self.exact_target_reads > 1:
                    self._assert_expectation(expect_ok, False)
                    return {
                        "ok": False,
                        "code": "target_not_found",
                        "message": "target selector matched no active resource",
                    }
                self._assert_expectation(expect_ok, True)
                selected = {
                    "kind": "service",
                    "id": "service-1234567890abcdef",
                    "name": self.service_name,
                    "state": "running",
                    "ready": True,
                }
                return {
                    "ok": True,
                    "target_count": 1,
                    "targets": [selected],
                    "selected": selected,
                }
            return {
                "ok": True,
                "target_count": 0 if self.initial_state == "unconfigured" else 1,
                "targets": [],
            }
        if arguments[:2] == ("operation", "follow"):
            return {"ok": True, "operation": {"state": "completed"}}
        if arguments[:2] == ("runtime", "serve"):
            name = arguments[2]
            if name.endswith("-collision"):
                self.collision_name = name
                self._assert_expectation(expect_ok, False)
                return {
                    "ok": False,
                    "code": "port_in_use",
                    "classification": "resource_conflict",
                    "message": (
                        "The exact requested port is already in use; "
                        "no fallback port was selected."
                    ),
                    "broker_contacted": True,
                    "mutation_performed": False,
                    "outcome": "certain",
                    "retryable": False,
                    "next_action": (
                        "Coordinator did not choose another port. Stop or wait for "
                        "the known owner, then retry the same port."
                    ),
                }
            self._assert_expectation(expect_ok, True)
            self.served = True
            self.service_name = name
            port_index = arguments.index("--port")
            self.port = int(arguments[port_index + 1])
            return {
                **_serve_result(execution_uid=self.caller_uid),
                "name": name,
                "port": self.port,
                "url": f"http://127.0.0.1:{self.port}/",
            }
        if arguments[:2] == ("runtime", "status"):
            self.status_reads += 1
            if self.status_reads == 1:
                return {
                    "ok": True,
                    "classification": "ready",
                    "ready": True,
                    "target": {
                        "kind": "service",
                        "id": "service-1234567890abcdef",
                    },
                    "name": self.service_name,
                    "url": f"http://127.0.0.1:{self.port}/",
                    "expires_at": "2026-08-04T12:00:20Z",
                    "session_id": "session-1234567890abcdef",
                    "cleanup": {
                        "owner": "systemd",
                        "kill_mode": "control-group",
                        "ttl_seconds": 20,
                        "kill_after_run": False,
                    },
                }
            return {
                "ok": True,
                "classification": "expired",
                "ready": False,
                "target": {
                    "kind": "service",
                    "id": "service-1234567890abcdef",
                },
            }
        raise AssertionError(f"unexpected client call: {arguments!r}")

    @staticmethod
    def _assert_expectation(actual: bool | None, expected: bool) -> None:
        if actual is None:
            return
        if actual is not expected:
            raise AssertionError("test acceptance expectation is contradictory")


class FirstUseAcceptanceTests(unittest.TestCase):
    def test_ttl_terminal_visibility_retries_a_stale_active_projection(self) -> None:
        class StaleTargetClient(_FakeClient):
            def call(
                self,
                arguments: tuple[str, ...],
                *,
                expect_ok: bool | None,
                timeout: float = 90.0,
            ) -> dict[str, object]:
                if (
                    arguments[0] == "targets"
                    and len(arguments) > 1
                    and arguments[1].startswith("service-")
                    and self.exact_target_reads == 1
                ):
                    del timeout
                    self.exact_target_reads += 1
                    selected = {
                        "kind": "service",
                        "id": "service-1234567890abcdef",
                        "name": self.service_name,
                        "state": "running",
                        "ready": True,
                    }
                    return {
                        "ok": True,
                        "target_count": 1,
                        "targets": [selected],
                        "selected": selected,
                    }
                return super().call(
                    arguments,
                    expect_ok=expect_ok,
                    timeout=timeout,
                )

        client = StaleTargetClient(Path("/client"), Path("/project"))
        client.service_name = "prototype"
        client.exact_target_reads = 1
        client.status_reads = 1
        with mock.patch.object(first_use_acceptance.time, "sleep") as sleep:
            targets, status = first_use_acceptance._wait_for_ttl_terminal_visibility(
                client=client,
                common=("--project", "/project"),
                service_id="service-1234567890abcdef",
                deadline=first_use_acceptance.time.monotonic() + 1,
            )

        self.assertEqual(targets["code"], "target_not_found")
        self.assertEqual(status["classification"], "expired")
        sleep.assert_called_once_with(0.2)

    def test_root_requires_an_explicit_non_root_caller(self) -> None:
        with mock.patch.object(
            first_use_acceptance.os, "geteuid", return_value=0
        ), self.assertRaisesRegex(
            first_use_acceptance.FirstUseAcceptanceError,
            "--caller-user",
        ):
            first_use_acceptance._caller_account(None)

    def test_explicit_caller_is_not_derived_from_repository_ownership(self) -> None:
        account = mock.Mock(pw_uid=1000, pw_gid=1003, pw_name="holygloryTT")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            executable = root / "devcoordinator"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            project = root / "root-owned-repository"
            project.mkdir()
            (project / ".git").mkdir()
            with (
                mock.patch.object(
                    first_use_acceptance.os, "geteuid", return_value=0
                ),
                mock.patch.object(
                    first_use_acceptance.pwd,
                    "getpwnam",
                    return_value=account,
                ) as getpwnam,
            ):
                client = first_use_acceptance.Client(
                    executable,
                    project,
                    "holygloryTT",
                )

        self.assertEqual(client.caller_user, "holygloryTT")
        self.assertEqual(client.caller_uid, 1000)
        self.assertIn("--reuid=1000", client.prefix)
        self.assertIn("--regid=1003", client.prefix)
        getpwnam.assert_called_once_with("holygloryTT")

    def test_installed_client_failure_preserves_typed_adoption_envelope(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000099"
        document = {
            "schema_version": 1,
            "ok": False,
            "code": "repository_context_changed",
            "classification": "repository_adoption_failed",
            "phase": "repository_adoption",
            "stage": "repository_adoption",
            "message": "The proven repository context changed before adoption.",
            "broker_contacted": True,
            "mutation_performed": False,
            "outcome": "certain",
            "retryable": False,
            "operation_id": operation_id,
            "continuation": f"dc1:operation:{operation_id}",
            "next_command": (
                "devcoordinator operation follow "
                f"dc1:operation:{operation_id}"
            ),
            "next_action": "Follow the exact adoption operation, then retry.",
            "action": "follow_operation",
            "evidence": {"adoption_stage": "repository.ensure"},
        }
        client = object.__new__(first_use_acceptance.Client)
        client.prefix = ("/release/bin/devcoordinator",)
        client.project = Path("/repo")
        completed = subprocess.CompletedProcess(
            args=[*client.prefix, "runtime", "serve"],
            returncode=1,
            stdout=json.dumps(document) + "\n",
            stderr="",
        )

        with mock.patch.object(
            first_use_acceptance.subprocess, "run", return_value=completed
        ), self.assertRaises(
            first_use_acceptance.CoordinatorClientFailure
        ) as raised:
            client.call(("runtime", "serve", "prototype"), expect_ok=True)

        self.assertEqual(raised.exception.document, document)
        self.assertIn("repository_context_changed", str(raised.exception))

    def test_main_emits_the_original_typed_client_failure(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000099"
        document = {
            "schema_version": 1,
            "ok": False,
            "code": "repository_context_changed",
            "classification": "repository_adoption_failed",
            "phase": "repository_adoption",
            "message": "The proven repository context changed before adoption.",
            "broker_contacted": True,
            "mutation_performed": False,
            "outcome": "certain",
            "retryable": False,
            "operation_id": operation_id,
            "continuation": f"dc1:operation:{operation_id}",
            "next_action": "Follow the exact adoption operation, then retry.",
        }
        output = io.StringIO()
        with mock.patch.object(
            first_use_acceptance,
            "run",
            side_effect=first_use_acceptance.CoordinatorClientFailure(document),
        ), mock.patch("sys.stdout", output):
            self.assertEqual(first_use_acceptance.main(), 1)

        self.assertEqual(json.loads(output.getvalue()), document)

    def test_fetch_rejects_http_error_empty_and_unexpected_pages(self) -> None:
        cases = (
            (_Response(status=500, payload=b'<div id="root"></div>'), "HTTP 500"),
            (_Response(status=200, payload=b""), "empty page"),
            (_Response(status=200, payload=b"not this prototype"), "unexpected page"),
        )
        for response, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                first_use_acceptance, "urlopen", return_value=response
            ), self.assertRaisesRegex(
                first_use_acceptance.FirstUseAcceptanceError, expected
            ):
                first_use_acceptance._fetch(4173)

    def test_fetch_requires_the_expected_vite_root(self) -> None:
        payload = b'<html><div id="root"></div></html>'
        with mock.patch.object(
            first_use_acceptance,
            "urlopen",
            return_value=_Response(status=200, payload=payload),
        ):
            self.assertEqual(first_use_acceptance._fetch(4173), payload)

    def test_cold_page_fetch_retries_timeout_within_one_deadline(self) -> None:
        payload = b'<html><div id="root"></div></html>'
        with (
            mock.patch.object(
                first_use_acceptance,
                "_fetch",
                side_effect=(TimeoutError("timed out"), payload),
            ) as fetch,
            mock.patch.object(
                first_use_acceptance.time,
                "monotonic",
                side_effect=(0.0, 0.1),
            ),
            mock.patch.object(first_use_acceptance.time, "sleep"),
        ):
            self.assertEqual(
                first_use_acceptance._fetch_when_ready(4173, deadline=1.0),
                payload,
            )
        self.assertEqual(fetch.call_count, 2)

    def test_cleanup_proof_uses_tcp_refusal_not_http_behavior(self) -> None:
        with (
            mock.patch.object(
                first_use_acceptance, "_tcp_listener_present", return_value=True
            ),
            mock.patch.object(first_use_acceptance, "_fetch") as fetch,
            mock.patch.object(
                first_use_acceptance.time,
                "monotonic",
                side_effect=(0.0, 1.0),
            ),
            mock.patch.object(first_use_acceptance.time, "sleep"),
        ):
            self.assertFalse(
                first_use_acceptance._wait_for_cleanup(4173, deadline=0.5)
            )
        fetch.assert_not_called()

    def test_tcp_cleanup_requires_connection_refused(self) -> None:
        refused = OSError(errno.ECONNREFUSED, "refused")
        with mock.patch.object(
            first_use_acceptance.socket, "create_connection", side_effect=refused
        ):
            self.assertFalse(first_use_acceptance._tcp_listener_present(4173))

        unproven = OSError(errno.ETIMEDOUT, "timed out")
        with mock.patch.object(
            first_use_acceptance.socket, "create_connection", side_effect=unproven
        ), self.assertRaisesRegex(
            first_use_acceptance.FirstUseAcceptanceError, "could not prove"
        ):
            first_use_acceptance._tcp_listener_present(4173)

    def test_launch_contract_requires_exact_project_cgroup_ownership(self) -> None:
        valid = _serve_result()
        service_id, url = first_use_acceptance._require_temporary_service_contract(
            valid, port=4173, ttl_seconds=20, caller_uid=1000
        )
        self.assertEqual(service_id, valid["service_id"])
        self.assertEqual(url, "http://127.0.0.1:4173/")

        invalid = {**valid, "isolation": {**valid["isolation"], "listener_owner_proven": False}}
        with self.assertRaisesRegex(
            first_use_acceptance.FirstUseAcceptanceError,
            "project-cgroup listener ownership",
        ):
            first_use_acceptance._require_temporary_service_contract(
                invalid, port=4173, ttl_seconds=20, caller_uid=1000
            )

        mismatched = {**valid, "execution_uid": 1001}
        with self.assertRaisesRegex(
            first_use_acceptance.FirstUseAcceptanceError,
            "exact running listener",
        ):
            first_use_acceptance._require_temporary_service_contract(
                mismatched, port=4173, ttl_seconds=20, caller_uid=1000
            )

    def test_first_unconfigured_run_reports_adoption_truthfully(self) -> None:
        class UnconfiguredClient(_FakeClient):
            initial_state = "unconfigured"

        with (
            mock.patch.object(first_use_acceptance, "Client", UnconfiguredClient),
            mock.patch.object(first_use_acceptance, "_fetch", return_value=b"ok"),
            mock.patch.object(
                first_use_acceptance, "_wait_for_cleanup", return_value=True
            ),
        ):
            result = first_use_acceptance.run(
                (
                    "--client",
                    "/release/bin/devcoordinator",
                    "--project",
                    "/home/developer/DesignDocEngine/prototype",
                )
            )

        self.assertEqual(result["acceptance_mode"], "first-use-adoption")
        self.assertTrue(result["repository_adoption_exercised"])
        self.assertTrue(result["first_use_runtime_proved"])

    def test_repeat_run_reports_configured_smoke_not_first_use(self) -> None:
        class ConfiguredClient(_FakeClient):
            initial_state = "configured"

        with (
            mock.patch.object(first_use_acceptance, "Client", ConfiguredClient),
            mock.patch.object(first_use_acceptance, "_fetch", return_value=b"ok"),
            mock.patch.object(
                first_use_acceptance, "_wait_for_cleanup", return_value=True
            ),
        ):
            result = first_use_acceptance.run(
                (
                    "--client",
                    "/release/bin/devcoordinator",
                    "--project",
                    "/home/developer/DesignDocEngine/prototype",
                )
            )

        self.assertEqual(result["acceptance_mode"], "configured-repository-smoke")
        self.assertFalse(result["repository_adoption_exercised"])
        self.assertFalse(result["first_use_runtime_proved"])
        self.assertTrue(result["http_ready"])
        self.assertTrue(result["ttl_listener_cleanup"])

    def test_auto_port_excludes_the_documented_application_port(self) -> None:
        first = mock.MagicMock()
        first.__enter__.return_value.getsockname.return_value = (
            "0.0.0.0",
            first_use_acceptance.DEFAULT_APPLICATION_PORT,
        )
        second = mock.MagicMock()
        second.__enter__.return_value.getsockname.return_value = (
            "0.0.0.0",
            43173,
        )

        with mock.patch.object(
            first_use_acceptance.socket,
            "socket",
            side_effect=(first, second),
        ):
            self.assertEqual(
                first_use_acceptance._select_ephemeral_port(),
                43173,
            )

    def test_auto_port_excludes_every_previously_attempted_candidate(self) -> None:
        repeated = mock.MagicMock()
        repeated.__enter__.return_value.getsockname.return_value = (
            "0.0.0.0",
            43173,
        )
        replacement = mock.MagicMock()
        replacement.__enter__.return_value.getsockname.return_value = (
            "0.0.0.0",
            43174,
        )

        with mock.patch.object(
            first_use_acceptance.socket,
            "socket",
            side_effect=(repeated, replacement),
        ):
            self.assertEqual(
                first_use_acceptance._select_ephemeral_port(
                    excluded=frozenset(
                        {first_use_acceptance.DEFAULT_APPLICATION_PORT, 43173}
                    )
                ),
                43174,
            )

    def test_launch_timeout_is_validated_before_client_or_runtime_work(self) -> None:
        for value in (0, 301):
            with self.subTest(value=value), self.assertRaisesRegex(
                first_use_acceptance.FirstUseAcceptanceError,
                "launch timeout",
            ):
                first_use_acceptance.run(
                    (
                        "--client",
                        "/does/not/matter",
                        "--project",
                        "/does/not/matter",
                        "--launch-timeout-seconds",
                        str(value),
                    )
                )

    def test_application_cwd_must_remain_inside_the_repository(self) -> None:
        for value in ("/tmp/prototype", "../prototype"):
            with self.subTest(value=value), self.assertRaisesRegex(
                first_use_acceptance.FirstUseAcceptanceError,
                "working directory",
            ):
                first_use_acceptance.run(
                    (
                        "--client",
                        "/does/not/matter",
                        "--project",
                        "/does/not/matter",
                        "--cwd",
                        value,
                    )
                )

    def test_nested_application_cwd_is_used_for_both_exact_port_launches(self) -> None:
        class ConfiguredClient(_FakeClient):
            initial_state = "configured"

            def call(
                self,
                arguments: tuple[str, ...],
                *,
                expect_ok: bool,
                timeout: float = 90.0,
            ) -> dict[str, object]:
                if arguments[:2] == ("runtime", "serve"):
                    cwd_index = arguments.index("--cwd")
                    if arguments[cwd_index + 1] != "prototype":
                        raise AssertionError("acceptance lost the nested application cwd")
                return super().call(
                    arguments,
                    expect_ok=expect_ok,
                    timeout=timeout,
                )

        with (
            mock.patch.object(first_use_acceptance, "Client", ConfiguredClient),
            mock.patch.object(first_use_acceptance, "_fetch", return_value=b"ok"),
            mock.patch.object(
                first_use_acceptance, "_wait_for_cleanup", return_value=True
            ),
        ):
            result = first_use_acceptance.run(
                (
                    "--client",
                    "/release/bin/devcoordinator",
                    "--project",
                    "/home/developer/DesignDocEngine",
                    "--cwd",
                    "prototype",
                )
            )

        self.assertEqual(result["application_cwd"], "prototype")

    def test_auto_port_is_selected_once_and_remains_exact(self) -> None:
        class ConfiguredClient(_FakeClient):
            initial_state = "configured"

            def call(
                self,
                arguments: tuple[str, ...],
                *,
                expect_ok: bool,
                timeout: float = 90.0,
            ) -> dict[str, object]:
                result = super().call(
                    arguments,
                    expect_ok=expect_ok,
                    timeout=timeout,
                )
                if arguments[:2] == ("runtime", "serve"):
                    self.assert_port(arguments, 43173)
                    if not arguments[2].endswith("-collision"):
                        result = {
                            **result,
                            "port": 43173,
                            "url": "http://127.0.0.1:43173/",
                        }
                if arguments[:2] == ("runtime", "status") and self.status_reads == 1:
                    # The compact status projection intentionally treats the
                    # root URL with and without a trailing slash identically.
                    result = {**result, "url": "http://127.0.0.1:43173"}
                return result

            @staticmethod
            def assert_port(arguments: tuple[str, ...], expected: int) -> None:
                values = tuple(
                    arguments[index + 1]
                    for index, value in enumerate(arguments[:-1])
                    if value == "--port"
                )
                if values != (str(expected), str(expected)):
                    raise AssertionError("acceptance changed its selected exact port")

        fetched: list[int] = []
        cleaned: list[tuple[int, float]] = []

        with (
            mock.patch.object(first_use_acceptance, "Client", ConfiguredClient),
            mock.patch.object(
                first_use_acceptance,
                "_select_ephemeral_port",
                return_value=43173,
            ) as select_port,
            mock.patch.object(
                first_use_acceptance,
                "_fetch",
                side_effect=lambda port: fetched.append(port) or b"ok",
            ),
            mock.patch.object(
                first_use_acceptance,
                "_wait_for_cleanup",
                side_effect=lambda port, **kwargs: cleaned.append(
                    (port, kwargs["deadline"])
                )
                or True,
            ),
            mock.patch.object(
                first_use_acceptance.time,
                "monotonic",
                return_value=1000.0,
            ),
        ):
            result = first_use_acceptance.run(
                (
                    "--client",
                    "/release/bin/devcoordinator",
                    "--project",
                    "/home/developer/DesignDocEngine/prototype",
                    "--auto-port",
                )
            )

        select_port.assert_called_once_with()
        self.assertEqual(fetched, [43173, 43173])
        self.assertEqual(cleaned, [(43173, 1040.0)])
        self.assertEqual(result["exact_port"], 43173)
        self.assertEqual(result["port_selection"], "ephemeral-test")
        self.assertEqual(result["port_selection_attempts"], 1)
        self.assertTrue(str(result["service_name"]).startswith("acceptance-"))
        self.assertNotEqual(result["service_name"], "prototype")

    def test_auto_port_retries_only_a_prelaunch_port_race(self) -> None:
        class RacingClient(_FakeClient):
            initial_state = "configured"

            def __init__(
                self,
                executable: Path,
                project: Path,
                caller_user: str | None = None,
            ) -> None:
                super().__init__(executable, project, caller_user)
                self.initial_launches = 0

            def call(
                self,
                arguments: tuple[str, ...],
                *,
                expect_ok: bool,
                timeout: float = 90.0,
            ) -> dict[str, object]:
                if (
                    arguments[:2] == ("runtime", "serve")
                    and not arguments[2].endswith("-collision")
                ):
                    self.initial_launches += 1
                    if self.initial_launches == 1:
                        raise first_use_acceptance.CoordinatorClientFailure(
                            {
                                "ok": False,
                                "code": "port_in_use",
                                "classification": "resource_conflict",
                                "message": "no fallback port was selected",
                                "broker_contacted": True,
                                "mutation_performed": False,
                                "outcome": "certain",
                                "retryable": False,
                            }
                        )
                return super().call(
                    arguments,
                    expect_ok=expect_ok,
                    timeout=timeout,
                )

        fetched: list[int] = []
        with (
            mock.patch.object(first_use_acceptance, "Client", RacingClient),
            mock.patch.object(
                first_use_acceptance,
                "_select_ephemeral_port",
                side_effect=(43173, 43174),
            ) as select_port,
            mock.patch.object(
                first_use_acceptance,
                "_fetch",
                side_effect=lambda port: fetched.append(port) or b"ok",
            ),
            mock.patch.object(
                first_use_acceptance,
                "_wait_for_cleanup",
                return_value=True,
            ),
        ):
            result = first_use_acceptance.run(
                (
                    "--client",
                    "/release/bin/devcoordinator",
                    "--project",
                    "/home/developer/DesignDocEngine/prototype",
                    "--auto-port",
                )
            )

        self.assertEqual(select_port.call_count, 2)
        self.assertEqual(select_port.call_args_list[0], mock.call())
        self.assertEqual(
            select_port.call_args_list[1],
            mock.call(
                excluded=frozenset(
                    {first_use_acceptance.DEFAULT_APPLICATION_PORT, 43173}
                )
            ),
        )
        self.assertEqual(result["exact_port"], 43174)
        self.assertEqual(result["port_selection_attempts"], 2)
        self.assertEqual(fetched, [43174, 43174])

    def test_auto_port_does_not_retry_false_positive_conflict_envelopes(self) -> None:
        valid = {
            "ok": False,
            "code": "port_in_use",
            "classification": "resource_conflict",
            "message": "no fallback port was selected",
            "broker_contacted": True,
            "mutation_performed": False,
            "outcome": "certain",
            "retryable": False,
        }
        cases = (
            {**valid, "classification": "infrastructure_failure"},
            {**valid, "broker_contacted": False},
            {**valid, "mutation_performed": True},
            {**valid, "outcome": "uncertain"},
            {**valid, "retryable": True},
        )
        for envelope in cases:
            with self.subTest(envelope=envelope):
                class MisleadingClient(_FakeClient):
                    initial_state = "configured"

                    def call(
                        self,
                        arguments: tuple[str, ...],
                        *,
                        expect_ok: bool,
                        timeout: float = 90.0,
                    ) -> dict[str, object]:
                        if (
                            arguments[:2] == ("runtime", "serve")
                            and not arguments[2].endswith("-collision")
                        ):
                            raise first_use_acceptance.CoordinatorClientFailure(
                                envelope
                            )
                        return super().call(
                            arguments,
                            expect_ok=expect_ok,
                            timeout=timeout,
                        )

                with (
                    mock.patch.object(
                        first_use_acceptance, "Client", MisleadingClient
                    ),
                    mock.patch.object(
                        first_use_acceptance,
                        "_select_ephemeral_port",
                        return_value=43173,
                    ) as select_port,
                    self.assertRaises(
                        first_use_acceptance.CoordinatorClientFailure
                    ),
                ):
                    first_use_acceptance.run(
                        (
                            "--client",
                            "/release/bin/devcoordinator",
                            "--project",
                            "/home/developer/DesignDocEngine/prototype",
                            "--auto-port",
                        )
                    )
                select_port.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
