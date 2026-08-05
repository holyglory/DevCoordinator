#!/usr/bin/env python3
"""Exercise the production development-server journey end to end.

The acceptance deliberately uses a fresh client process for every step.  It
proves that a normal non-root developer caller can start a bounded service, recover the
durable operation from a second process, receive an exact-port collision error,
and rely on broker-owned TTL cleanup.  When the production fixture is not yet
enrolled the same run also proves first-use adoption.  Later deployments report
an enrolled-repository smoke honestly instead of claiming to repeat adoption.
Source tests exercise both states without adding disposable broker records.

The acceptance never calls systemd or inspects broker storage directly.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import time
import uuid
from typing import Any, Mapping, Sequence
from urllib.request import urlopen


DEFAULT_APPLICATION_PORT = 4173
MAX_AUTO_PORT_ATTEMPTS = 5


class FirstUseAcceptanceError(RuntimeError):
    pass


class CoordinatorClientFailure(FirstUseAcceptanceError):
    """One already-bounded typed failure returned by the installed client."""

    def __init__(self, document: Mapping[str, Any]) -> None:
        self.document = dict(document)
        code = self.document.get("code")
        message = self.document.get("message")
        super().__init__(
            "Coordinator client returned "
            + (str(code) if isinstance(code, str) and code else "a typed failure")
            + (f": {message}" if isinstance(message, str) and message else "")
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument(
        "--caller-user",
        help=(
            "non-root Unix account that exercises the installed client; "
            "required when the acceptance itself runs as root"
        ),
    )
    parser.add_argument(
        "--cwd",
        default=".",
        help="repository-relative application working directory (default: .)",
    )
    port = parser.add_mutually_exclusive_group()
    port.add_argument(
        "--port",
        type=int,
        help="one exact acceptance port (default: 4173)",
    )
    port.add_argument(
        "--auto-port",
        action="store_true",
        help=(
            "select one dedicated ephemeral port for this acceptance run; "
            "the selected port remains exact and is never changed after launch"
        ),
    )
    parser.add_argument("--ttl-seconds", type=int, default=20)
    parser.add_argument("--launch-timeout-seconds", type=int, default=20)
    return parser


def _select_ephemeral_port(
    *, excluded: frozenset[int] = frozenset({DEFAULT_APPLICATION_PORT})
) -> int:
    """Ask the kernel for a currently unused localhost test port.

    This is an acceptance-fixture allocation, not product fallback.  The
    returned number is passed to Coordinator as one exact strict port and is
    reused unchanged for readiness, collision, and cleanup verification.
    """

    for _attempt in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            # A wildcard reservation catches conflicts on every local
            # interface, not only 127.0.0.1.  The socket is released before
            # Coordinator launches the real fixture; the bounded retry in
            # ``run`` handles the remaining release-to-launch race.
            reservation.bind(("0.0.0.0", 0))
            selected = int(reservation.getsockname()[1])
        if 1 <= selected <= 65535 and selected not in excluded:
            return selected
    raise FirstUseAcceptanceError(
        "the operating system did not select a dedicated acceptance port"
    )


def _bounded(value: object, maximum: int = 1200) -> str:
    text = str(value).strip()
    return text if len(text) <= maximum else text[: maximum - 1] + "…"


def _json_document(completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise FirstUseAcceptanceError(
            "Coordinator client returned no JSON document: "
            + _bounded(completed.stderr)
        )
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise FirstUseAcceptanceError(
            "Coordinator client returned malformed JSON: " + _bounded(lines[-1])
        ) from error
    if not isinstance(value, Mapping):
        raise FirstUseAcceptanceError("Coordinator client result is not an object")
    return dict(value)


def _caller_account(caller_user: str | None) -> pwd.struct_passwd:
    effective_uid = os.geteuid()
    if caller_user is None:
        if effective_uid == 0:
            raise FirstUseAcceptanceError(
                "root must name the actual non-root acceptance caller with --caller-user"
            )
        try:
            account = pwd.getpwuid(effective_uid)
        except KeyError as error:
            raise FirstUseAcceptanceError(
                "the current acceptance caller has no Unix account"
            ) from error
    else:
        try:
            account = pwd.getpwnam(caller_user)
        except KeyError as error:
            raise FirstUseAcceptanceError(
                "the requested acceptance caller does not exist"
            ) from error
        if effective_uid != 0 and account.pw_uid != effective_uid:
            raise FirstUseAcceptanceError(
                "a non-root acceptance process cannot impersonate another caller"
            )
    if account.pw_uid <= 0:
        raise FirstUseAcceptanceError(
            "first-use acceptance requires an actual non-root caller"
        )
    return account


def _is_exact_prelaunch_port_conflict(document: Mapping[str, Any]) -> bool:
    expected = {
        "code": "port_in_use",
        "classification": "resource_conflict",
        "broker_contacted": True,
        "mutation_performed": False,
        "outcome": "certain",
        "retryable": False,
    }
    return all(document.get(key) == value for key, value in expected.items())


class Client:
    def __init__(
        self,
        executable: Path,
        project: Path,
        caller_user: str | None = None,
    ) -> None:
        executable = executable.expanduser().resolve(strict=True)
        project = project.expanduser().resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise FirstUseAcceptanceError("immutable Coordinator client is not executable")
        if not (project / ".git").exists():
            raise FirstUseAcceptanceError("first-use acceptance project is not a Git repository")
        account = _caller_account(caller_user)
        self.executable = executable
        self.project = project
        self.caller_user = account.pw_name
        self.caller_uid = account.pw_uid
        if os.geteuid() == 0:
            self.prefix = (
                "/usr/bin/setpriv",
                "--reuid=" + str(account.pw_uid),
                "--regid=" + str(account.pw_gid),
                "--init-groups",
                "--reset-env",
                str(executable),
            )
        else:
            self.prefix = (str(executable),)

    def call(
        self,
        arguments: Sequence[str],
        *,
        expect_ok: bool,
        timeout: float = 90.0,
    ) -> dict[str, Any]:
        completed = subprocess.run(
            [*self.prefix, *arguments],
            cwd=self.project,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
        document = _json_document(completed)
        actual_ok = completed.returncode == 0 and document.get("ok") is True
        if actual_ok != expect_ok:
            if document.get("ok") is False:
                # The client already validated and bounded this public error
                # envelope.  Preserve it verbatim so an acceptance failure does
                # not erase the broker code, operation continuation, or exact
                # recovery instructions behind one generic wrapper message.
                raise CoordinatorClientFailure(document)
            raise FirstUseAcceptanceError(
                "Coordinator client outcome contradicted acceptance expectation: "
                + _bounded(document)
            )
        return document


def _fetch(
    port: int,
    *,
    timeout: float = 2.0,
    expected_content: bytes = b'id="root"',
) -> bytes:
    with urlopen(f"http://127.0.0.1:{port}/", timeout=timeout) as response:
        if not 200 <= response.status < 400:
            raise FirstUseAcceptanceError(
                f"temporary development server returned HTTP {response.status}"
            )
        payload = response.read(64 * 1024)
    if not payload:
        raise FirstUseAcceptanceError("temporary development server returned an empty page")
    if expected_content not in payload:
        raise FirstUseAcceptanceError(
            "temporary development server returned an unexpected page"
        )
    return payload


def _tcp_listener_present(port: int, *, timeout: float = 0.25) -> bool:
    """Return whether localhost accepts TCP connections on the exact port.

    Cleanup is proven only by a refused TCP connection.  An HTTP error, empty
    response, protocol mismatch, or read timeout can all come from a listener
    that is still alive and therefore must never count as cleanup.
    """

    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as error:
        if error.errno == errno.ECONNREFUSED:
            return False
        raise FirstUseAcceptanceError(
            "could not prove whether the exact TCP listener was removed: "
            + _bounded(error)
        ) from error
    connection.close()
    return True


def _wait_for_cleanup(port: int, *, deadline: float) -> bool:
    while time.monotonic() < deadline:
        if not _tcp_listener_present(port):
            return True
        time.sleep(0.2)
    return False


def _require_temporary_service_contract(
    document: Mapping[str, Any],
    *,
    port: int,
    ttl_seconds: int,
    caller_uid: int,
) -> tuple[str, str]:
    """Validate the bounded service and isolation evidence returned at launch."""

    service_id = document.get("service_id")
    if not isinstance(service_id, str) or not service_id.startswith("service-"):
        raise FirstUseAcceptanceError("temporary service omitted its immutable service ID")
    expected_url = f"http://127.0.0.1:{port}/"
    if (
        document.get("state") != "running"
        or document.get("port") != port
        or document.get("url") != expected_url
        or type(document.get("main_pid")) is not int
        or int(document["main_pid"]) <= 0
        or document.get("execution_uid") != caller_uid
    ):
        raise FirstUseAcceptanceError(
            "temporary service launch result did not prove the exact running listener"
        )
    expires_at = document.get("expires_at")
    if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
        raise FirstUseAcceptanceError("temporary service omitted its TTL expiry")
    cleanup = document.get("cleanup")
    if not isinstance(cleanup, Mapping) or cleanup != {
        "owner": "systemd",
        "kill_mode": "control-group",
        "ttl_seconds": ttl_seconds,
        "kill_after_run": False,
    }:
        raise FirstUseAcceptanceError(
            "temporary service cleanup contract is missing or contradictory"
        )
    isolation = document.get("isolation")
    if (
        not isinstance(isolation, Mapping)
        or isolation.get("manager") != "systemd"
        or isolation.get("listener_owner_proven") is not True
        or isolation.get("execution_uid") != caller_uid
        or isolation.get("actual_caller_uid_proven") is not True
        or not isinstance(isolation.get("slice"), str)
        or not str(isolation["slice"]).startswith("devcoordinator-projects-")
        or not str(isolation["slice"]).endswith(".slice")
        or not isinstance(isolation.get("control_group"), str)
        or not str(isolation["control_group"]).startswith("/")
    ):
        raise FirstUseAcceptanceError(
            "temporary service did not prove exact project-cgroup listener ownership"
        )
    return service_id, expected_url


def _require_fresh_running_visibility(
    *,
    targets: Mapping[str, Any],
    status: Mapping[str, Any],
    serve: Mapping[str, Any],
    service_id: str,
    expected_url: str,
) -> None:
    """Prove another client can resolve the running service and its lifetime."""

    selected = targets.get("selected")
    required_target = {
        "kind": "service",
        "id": service_id,
        "name": serve.get("name", "prototype"),
        "state": "running",
        "ready": True,
    }
    if not isinstance(selected, Mapping) or any(
        selected.get(key) != value for key, value in required_target.items()
    ):
        raise FirstUseAcceptanceError(
            "fresh targets lookup did not publish the exact running temporary service"
        )
    status_url = status.get("url")
    if (
        status.get("classification") != "ready"
        or status.get("ready") is not True
        or status_url not in {expected_url, expected_url.rstrip("/")}
        or status.get("expires_at") != serve.get("expires_at")
        or status.get("session_id") != serve.get("session_id")
        or status.get("cleanup") != serve.get("cleanup")
    ):
        raise FirstUseAcceptanceError(
            "fresh runtime status did not preserve the running service URL, TTL, and cleanup contract"
        )


def _require_ttl_terminal_visibility(
    *,
    targets: Mapping[str, Any],
    status: Mapping[str, Any],
    service_id: str,
) -> None:
    """Require the expired service to leave active targets but retain typed status."""

    if targets.get("code") != "target_not_found" or targets.get("ok") is not False:
        raise FirstUseAcceptanceError(
            "expired temporary service remained in the active target catalog"
        )
    target = status.get("target")
    if (
        status.get("classification") != "expired"
        or status.get("ready") is not False
        or not isinstance(target, Mapping)
        or target.get("id") != service_id
    ):
        raise FirstUseAcceptanceError(
            "expired temporary service omitted its retained typed terminal status"
        )


def run(argv: Sequence[str] | None = None) -> dict[str, Any]:
    args = _parser().parse_args(argv)
    application_cwd = Path(args.cwd)
    if application_cwd.is_absolute() or ".." in application_cwd.parts:
        raise FirstUseAcceptanceError(
            "acceptance working directory must stay inside the repository"
        )
    requested_port = DEFAULT_APPLICATION_PORT if args.port is None else args.port
    if not args.auto_port and not 1 <= requested_port <= 65535:
        raise FirstUseAcceptanceError("acceptance port must be one exact TCP port")
    if not 5 <= args.ttl_seconds <= 120:
        raise FirstUseAcceptanceError("acceptance TTL must be from 5 through 120 seconds")
    if not 1 <= args.launch_timeout_seconds <= 300:
        raise FirstUseAcceptanceError(
            "acceptance launch timeout must be from 1 through 300 seconds"
        )
    client = Client(args.client, args.project, args.caller_user)
    common = ("--project", str(client.project))
    initial = client.call(("capabilities", *common), expect_ok=True)
    repository = initial.get("repository")
    if not isinstance(repository, Mapping) or repository.get("state") not in {
        "enrolled",
        "unenrolled",
    }:
        raise FirstUseAcceptanceError("pure discovery did not return repository enrollment state")
    initial_state = str(repository["state"])
    adoption_exercised = initial_state == "unenrolled"
    targets = client.call(("targets", *common), expect_ok=True)
    if adoption_exercised and targets.get("target_count") != 0:
        raise FirstUseAcceptanceError("unenrolled pure discovery invented runtime targets")

    port = _select_ephemeral_port() if args.auto_port else requested_port
    attempted_ports: set[int] = set()
    service_name = "acceptance-" + uuid.uuid4().hex[:12]
    collision_name = service_name + "-collision"
    selection_attempts = 0
    cleanup_deadline: float | None = None
    serve: dict[str, Any] | None = None
    service_id: str | None = None
    expected_url: str | None = None
    cleanup_proved = False
    try:
        while serve is None:
            selection_attempts += 1
            attempted_ports.add(port)
            try:
                serve = client.call(
                    (
                        "runtime",
                        "serve",
                        service_name,
                        "--cwd",
                        str(application_cwd),
                        "--port",
                        str(port),
                        "--ttl-seconds",
                        str(args.ttl_seconds),
                        "--kill-after-run",
                        "false",
                        "--launch-timeout-seconds",
                        str(args.launch_timeout_seconds),
                        *common,
                        "--",
                        "/usr/bin/npm",
                        "run",
                        "dev",
                        "--",
                        "--host",
                        "0.0.0.0",
                        "--port",
                        str(port),
                        "--strictPort",
                    ),
                    expect_ok=True,
                    timeout=float(args.launch_timeout_seconds + 60),
                )
            except CoordinatorClientFailure as error:
                if (
                    args.auto_port
                    and _is_exact_prelaunch_port_conflict(error.document)
                    and selection_attempts < MAX_AUTO_PORT_ATTEMPTS
                ):
                    port = _select_ephemeral_port(
                        excluded=frozenset(
                            {DEFAULT_APPLICATION_PORT, *attempted_ports}
                        )
                    )
                    continue
                raise
            cleanup_deadline = time.monotonic() + args.ttl_seconds + 20
        service_id, expected_url = _require_temporary_service_contract(
            serve,
            port=port,
            ttl_seconds=args.ttl_seconds,
            caller_uid=client.caller_uid,
        )
        _fetch(port)
        continuation = serve.get("continuation")
        if not isinstance(continuation, str):
            raise FirstUseAcceptanceError("temporary service omitted its operation continuation")

        fresh = client.call(("capabilities", *common), expect_ok=True)
        fresh_repository = fresh.get("repository")
        if not isinstance(fresh_repository, Mapping) or fresh_repository.get("state") != "enrolled":
            raise FirstUseAcceptanceError("fresh client did not observe first-use repository adoption")
        visible_targets = client.call(
            ("targets", service_id, "--kind", "service", *common),
            expect_ok=True,
        )
        visible_status = client.call(
            ("runtime", "status", service_id, "--kind", "service", *common),
            expect_ok=True,
        )
        _require_fresh_running_visibility(
            targets=visible_targets,
            status=visible_status,
            serve=serve,
            service_id=service_id,
            expected_url=expected_url,
        )
        followed = client.call(
            ("operation", "follow", continuation, *common), expect_ok=True
        )
        if followed.get("operation") is None:
            raise FirstUseAcceptanceError("fresh client could not recover the durable launch operation")

        collision = client.call(
            (
                "runtime",
                "serve",
                collision_name,
                "--cwd",
                str(application_cwd),
                "--port",
                str(port),
                "--ttl-seconds",
                str(args.ttl_seconds),
                "--kill-after-run",
                "false",
                "--launch-timeout-seconds",
                "5",
                *common,
                "--",
                "/usr/bin/npm",
                "run",
                "dev",
                "--",
                "--host",
                "0.0.0.0",
                "--port",
                str(port),
                "--strictPort",
            ),
            expect_ok=False,
            timeout=40.0,
        )
        if collision.get("code") != "port_in_use":
            raise FirstUseAcceptanceError(
                "exact-port collision did not return typed port_in_use: "
                + _bounded(collision)
            )
        expected_collision = {
            "classification": "resource_conflict",
            "broker_contacted": True,
            "mutation_performed": False,
            "outcome": "certain",
            "retryable": False,
        }
        if any(
            collision.get(key) != value
            for key, value in expected_collision.items()
        ):
            raise FirstUseAcceptanceError(
                "exact-port collision returned contradictory public semantics"
            )
        message = str(collision.get("message") or "")
        next_action = str(collision.get("next_action") or "")
        if (
            "no fallback port" not in message.lower()
            or "did not choose another" not in next_action.lower()
            or "same port" not in next_action.lower()
        ):
            raise FirstUseAcceptanceError(
                "exact-port collision omitted its no-hop recovery guidance"
            )
        collision_target = client.call(
            ("targets", collision_name, "--kind", "service", *common),
            expect_ok=False,
        )
        if collision_target.get("code") != "target_not_found":
            raise FirstUseAcceptanceError(
                "exact-port collision published a fallback runtime target"
            )
        _fetch(port)
    finally:
        if serve is not None:
            if cleanup_deadline is None:
                raise FirstUseAcceptanceError(
                    "temporary development server cleanup deadline was not retained"
                )
            cleanup_proved = _wait_for_cleanup(port, deadline=cleanup_deadline)
    if serve is None:
        raise FirstUseAcceptanceError("temporary development server did not start")
    if service_id is None:
        raise FirstUseAcceptanceError("temporary development server identity was not proven")
    if expected_url is None:
        raise FirstUseAcceptanceError("temporary development server URL was not proven")
    if not cleanup_proved:
        raise FirstUseAcceptanceError(
            "broker-owned TTL cleanup did not remove the exact TCP listener"
        )
    expired_target = client.call(
        ("targets", service_id, "--kind", "service", *common),
        expect_ok=False,
    )
    expired_status = client.call(
        ("runtime", "status", service_id, "--kind", "service", *common),
        expect_ok=True,
    )
    _require_ttl_terminal_visibility(
        targets=expired_target,
        status=expired_status,
        service_id=service_id,
    )
    return {
        "ok": True,
        "kind": "devcoordinator-development-server-acceptance",
        "acceptance_mode": (
            "first-use-adoption"
            if adoption_exercised
            else "enrolled-repository-smoke"
        ),
        "project": client.project.name,
        "caller_user": client.caller_user,
        "caller_uid": client.caller_uid,
        "initial_repository_state": initial_state,
        "fresh_repository_state": "enrolled",
        "repository_adoption_exercised": adoption_exercised,
        "first_use_runtime_proved": adoption_exercised,
        "service_id": service_id,
        "exact_port": port,
        "port_selection": "ephemeral-test" if args.auto_port else "explicit",
        "port_selection_attempts": selection_attempts,
        "service_name": service_name,
        "application_cwd": str(application_cwd),
        "http_ready": True,
        "project_cgroup_listener_ownership": True,
        "actual_caller_execution_proved": True,
        "fresh_client_running_visibility": True,
        "fresh_client_recovery": True,
        "collision_fail_closed": True,
        "ttl_listener_cleanup": True,
        "ttl_terminal_visibility": True,
    }


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True, separators=(",", ":")))
        return 0
    except CoordinatorClientFailure as error:
        print(json.dumps(error.document, sort_keys=True, separators=(",", ":")))
        return 1
    except (FirstUseAcceptanceError, OSError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {"ok": False, "error": _bounded(error)},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
