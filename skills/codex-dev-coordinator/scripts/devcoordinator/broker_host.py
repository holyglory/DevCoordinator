"""Typed host effects for the authorized cross-user broker service.

Only exact normalized container identities and bounded port candidates reach
this module.  It deliberately has no command-string, shell, path, or display-
name interface.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
from typing import Any, Callable, Mapping, Optional

from .broker import BrokerBackendError
from .broker_persistence import (
    ComposeMutationTarget,
    DatabaseMutationTarget,
    DockerMutationTarget,
    RegisteredDatabaseBackup,
)


DOCKER_ACTIONS = frozenset({"start", "stop", "restart"})
DOCKER_LOCATIONS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/usr/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
)


def _postgres_backup_tool() -> Path:
    candidate = (
        Path(__file__).resolve().parents[3]
        / "postgres-docker-backup"
        / "scripts"
        / "postgres_docker_backup.py"
    )
    if not candidate.is_file() or candidate.is_symlink():
        raise RuntimeError("canonical PostgreSQL backup skill executable is unavailable")
    return candidate


def _validate_database_target(target: DatabaseMutationTarget) -> str:
    full_id = str(target.full_container_id).lower()
    if len(full_id) != 64 or any(
        character not in "0123456789abcdef" for character in full_id
    ):
        raise ValueError("broker PostgreSQL target requires a full immutable container ID")
    if (
        not isinstance(target.database_name, str)
        or not target.database_name
        or target.database_name != target.database_name.strip()
        or len(target.database_name.encode("utf-8")) > 128
        or "\x00" in target.database_name
    ):
        raise ValueError("broker PostgreSQL target requires one bounded database name")
    return full_id


def _require_service_output_root(value: str) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise ValueError("service PostgreSQL output root must be absolute")
    root = Path(value)
    if root.exists():
        metadata = root.lstat()
        if root.is_symlink() or not root.is_dir():
            raise PermissionError("service PostgreSQL output root must be a real directory")
    else:
        parent = root.parent
        parent_metadata = parent.lstat()
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError("service PostgreSQL output parent must be a real directory")
        if parent_metadata.st_uid != os.geteuid() or parent_metadata.st_mode & 0o077:
            raise PermissionError("service PostgreSQL output parent must be private and service-owned")
        root.mkdir(mode=0o700)
        metadata = root.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise PermissionError("service PostgreSQL output root must be private and service-owned")
    return root


class LocalBrokerHostMutations:
    """Bounded host implementation for the broker's typed mutation protocol."""

    def __init__(
        self,
        *,
        docker_executable: str | None = None,
        docker_timeout_seconds: float = 45.0,
        docker_runner: Callable[[tuple[str, ...], float], subprocess.CompletedProcess[str]]
        | None = None,
        compose_runner: Callable[
            [tuple[str, ...], str, float], subprocess.CompletedProcess[str]
        ]
        | None = None,
        port_probe: Callable[[int, str], bool] | None = None,
        listener_verifier: Callable[[int, str], Mapping[str, Any]] | None = None,
        postgres_timeout_seconds: float = 1_800.0,
        postgres_runner: Callable[
            [tuple[str, ...], float, Mapping[str, str]],
            subprocess.CompletedProcess[str],
        ]
        | None = None,
    ) -> None:
        if docker_timeout_seconds <= 0 or docker_timeout_seconds > 600:
            raise ValueError("docker_timeout_seconds must be greater than 0 and at most 600")
        self._docker_executable = docker_executable
        self._docker_timeout_seconds = float(docker_timeout_seconds)
        self._docker_runner = docker_runner or self._run_docker
        self._compose_runner = compose_runner or self._run_compose
        self._port_probe = port_probe or _port_available
        self._listener_verifier = listener_verifier or _verify_owned_tcp_listener
        if postgres_timeout_seconds <= 0 or postgres_timeout_seconds > 3_600:
            raise ValueError(
                "postgres_timeout_seconds must be greater than 0 and at most 3600"
            )
        self._postgres_timeout_seconds = float(postgres_timeout_seconds)
        self._postgres_runner = postgres_runner or self._run_postgres_tool

    def select_available_port(
        self, *, candidates: tuple[int, ...], protocol: str
    ) -> Optional[int]:
        if protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        if not isinstance(candidates, tuple) or any(
            type(port) is not int or not 1 <= port <= 65535 for port in candidates
        ):
            raise ValueError("candidates must be a tuple of valid host ports")
        if len(set(candidates)) != len(candidates):
            raise ValueError("port candidates must be unique")
        for port in candidates:
            if self._port_probe(port, protocol):
                return port
        return None

    def verify_owned_tcp_listener(
        self, *, port: int, canonical_root: str
    ) -> Mapping[str, Any]:
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("listener port must be an integer from 1 through 65535")
        evidence = self._listener_verifier(port, canonical_root)
        if not isinstance(evidence, Mapping):
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "Host listener verifier returned invalid ownership evidence.",
            )
        normalized = dict(evidence)
        if (
            type(normalized.get("pid")) is not int
            or int(normalized["pid"]) <= 0
            or normalized.get("canonical_root") != canonical_root
            or normalized.get("cwd") is None
            or int(normalized.get("port") or 0) != port
        ):
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "Host listener verifier did not prove the exact enrolled repository listener.",
            )
        return normalized

    def docker_start(self, target: DockerMutationTarget) -> Mapping[str, Any]:
        return self._docker(target, "start")

    def docker_stop(self, target: DockerMutationTarget) -> Mapping[str, Any]:
        return self._docker(target, "stop")

    def docker_restart(self, target: DockerMutationTarget) -> Mapping[str, Any]:
        return self._docker(target, "restart")

    def compose_up(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "up")

    def compose_down(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "down")

    def postgres_backup(
        self, target: DatabaseMutationTarget, *, output_root: str
    ) -> Mapping[str, Any]:
        full_id = _validate_database_target(target)
        root = _require_service_output_root(output_root)
        base = (
            sys.executable,
            str(_postgres_backup_tool()),
        )
        backup = self._postgres_command(
            (
                *base,
                "backup",
                "--container",
                full_id,
                "--expect-container-id",
                full_id,
                "--database",
                target.database_name,
                "--format",
                "custom",
                "--scope",
                "database",
                "--out-dir",
                str(root),
            )
        )
        artifact = backup.get("backup")
        manifest = backup.get("manifest")
        if not isinstance(artifact, str) or not isinstance(manifest, str):
            raise RuntimeError("PostgreSQL backup tool omitted published artifact evidence")
        verification = self._postgres_command(
            (
                *base,
                "verify",
                "--container",
                full_id,
                "--expect-container-id",
                full_id,
                "--database",
                target.database_name,
                "--file",
                artifact,
                "--test-restore",
            )
        )
        if verification.get("ok") is not True or not verification.get("test_restore"):
            raise RuntimeError("PostgreSQL backup strong verification did not complete")
        return {
            "backup": artifact,
            "manifest": manifest,
            "sha256": backup.get("sha256"),
            "verification": verification,
        }

    def postgres_restore(
        self,
        target: DatabaseMutationTarget,
        backup: RegisteredDatabaseBackup,
        *,
        safety_output_root: str,
    ) -> Mapping[str, Any]:
        full_id = _validate_database_target(target)
        if backup.database_binding_id != target.database_binding_id:
            raise ValueError("registered backup belongs to another database binding")
        safety_root = _require_service_output_root(safety_output_root)
        return self._postgres_command(
            (
                sys.executable,
                str(_postgres_backup_tool()),
                "restore",
                "--container",
                full_id,
                "--expect-container-id",
                full_id,
                "--database",
                target.database_name,
                "--file",
                backup.artifact_path,
                "--confirm-restore",
                "--safety-out-dir",
                str(safety_root),
            )
        )

    def _postgres_command(self, command: tuple[str, ...]) -> dict[str, Any]:
        environment = dict(os.environ)
        environment["DEVCOORDINATOR_BACKUP_REGISTRY"] = "off"
        environment["DEVCOORDINATOR_BROKER_INTERNAL"] = "1"
        completed = self._postgres_runner(
            command, self._postgres_timeout_seconds, environment
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "service-owned PostgreSQL action failed with exit "
                f"{completed.returncode}: "
                f"{_bounded_output(completed.stderr) or 'no diagnostic output'}"
            )
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "service-owned PostgreSQL action returned invalid JSON evidence"
            ) from exc
        if not isinstance(value, dict):
            raise RuntimeError(
                "service-owned PostgreSQL action returned an invalid result"
            )
        return value

    def _docker(self, target: DockerMutationTarget, action: str) -> Mapping[str, Any]:
        if action not in DOCKER_ACTIONS:
            raise ValueError("unsupported Docker broker action")
        full_id = str(target.full_container_id).lower()
        if len(full_id) != 64 or any(character not in "0123456789abcdef" for character in full_id):
            raise ValueError("broker Docker target must carry a full immutable container ID")
        executable = self._docker_executable or _resolve_docker_executable()
        command = (executable, action, full_id)
        completed = self._docker_runner(command, self._docker_timeout_seconds)
        if completed.returncode != 0:
            raise RuntimeError(
                f"exact Docker {action} failed with exit {completed.returncode}: "
                f"{_bounded_output(completed.stderr) or 'no diagnostic output'}"
            )
        return {
            "resource_id": target.docker_resource_id,
            "full_container_id": full_id,
            "action": action,
            "observation_revision": target.observation_revision,
            "control_generation": target.control_generation,
            "stdout": _bounded_output(completed.stdout),
        }

    def _compose(
        self, target: ComposeMutationTarget, action: str
    ) -> Mapping[str, Any]:
        if action not in {"up", "down"}:
            raise ValueError("unsupported Compose broker action")
        try:
            _validate_compose_target(target)
        except BrokerBackendError:
            raise
        except (TypeError, ValueError) as exc:
            raise BrokerBackendError(
                "compose_definition_invalid",
                "Service-owned Compose definition is invalid; rerun Coordinator skill installation.",
            ) from exc
        executable = self._docker_executable or _resolve_docker_executable()
        command: list[str] = [
            executable,
            "compose",
            "--project-directory",
            target.cwd,
            "--project-name",
            target.project_name,
        ]
        for file_path in target.compose_files:
            command.extend(("--file", file_path))
        command.append(action)
        if action == "up":
            command.append("--detach")
            command.extend(target.services)
        completed = self._compose_runner(
            tuple(command), target.cwd, self._docker_timeout_seconds
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"exact Docker Compose {action} failed with exit {completed.returncode}: "
                f"{_bounded_output(completed.stderr) or 'no diagnostic output'}"
            )
        return {
            "compose_definition_id": target.compose_definition_id,
            "action": action,
            "status": "completed",
            "definition_fingerprint": target.definition_fingerprint,
            "definition_generation": target.definition_generation,
            "repository_generation": target.repository_generation,
            "stdout": _bounded_output(completed.stdout),
        }

    @staticmethod
    def _run_docker(
        command: tuple[str, ...], timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

    @staticmethod
    def _run_compose(
        command: tuple[str, ...], cwd: str, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

    @staticmethod
    def _run_postgres_tool(
        command: tuple[str, ...],
        timeout_seconds: float,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(environment),
            timeout=timeout_seconds,
            check=False,
        )


def _resolve_docker_executable() -> str:
    configured = str(os.environ.get("CODEX_DOCKER_CLI") or "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute() or not _executable_file(candidate):
            raise RuntimeError("CODEX_DOCKER_CLI must name an absolute executable file")
        return str(candidate)
    discovered = shutil.which("docker", path=str(os.environ.get("PATH") or ""))
    if discovered and _executable_file(Path(discovered)):
        return str(Path(discovered).absolute())
    for raw in DOCKER_LOCATIONS:
        candidate = Path(raw)
        if _executable_file(candidate):
            return str(candidate)
    raise RuntimeError("Docker CLI is unavailable to the broker service")


def _executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


_COMPOSE_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_COMPOSE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _validate_compose_target(target: ComposeMutationTarget) -> None:
    if not isinstance(target, ComposeMutationTarget):
        raise TypeError("Compose target must be a persisted typed definition")
    if not 1 <= len(target.compose_files) <= 16:
        raise ValueError("Compose target must contain bounded persisted files")
    if len(target.services) > 128 or len(set(target.services)) != len(target.services):
        raise ValueError("Compose target services are invalid")
    if _COMPOSE_PROJECT_NAME.fullmatch(target.project_name) is None:
        raise ValueError("Compose target project identity is invalid")
    if any(_COMPOSE_SERVICE_NAME.fullmatch(item) is None for item in target.services):
        raise ValueError("Compose target contains an invalid service identity")

    canonical_root = _strict_current_path(
        target.canonical_root, directory=True, field="repository root"
    )
    canonical_cwd = _strict_current_path(target.cwd, directory=True, field="Compose cwd")
    if os.path.commonpath((canonical_cwd, canonical_root)) != canonical_root:
        raise ValueError("Compose cwd escaped its persisted repository")
    canonical_files = tuple(
        _strict_current_path(item, directory=False, field="Compose file")
        for item in target.compose_files
    )
    if not (
        len(target.compose_file_sha256s)
        == len(target.compose_file_sizes)
        == len(canonical_files)
    ):
        raise ValueError("Compose target file evidence is incomplete")
    if len(set(canonical_files)) != len(canonical_files):
        raise ValueError("Compose target contains duplicate files")
    if any(
        os.path.commonpath((item, canonical_root)) != canonical_root
        for item in canonical_files
    ):
        raise ValueError("Compose file escaped its persisted repository")
    actual_evidence = tuple(_compose_file_evidence(item) for item in canonical_files)
    expected_evidence = tuple(
        {"content_sha256": digest, "byte_size": byte_size}
        for digest, byte_size in zip(
            target.compose_file_sha256s, target.compose_file_sizes
        )
    )
    if actual_evidence != expected_evidence:
        raise BrokerBackendError(
            "compose_definition_drift",
            "Compose files changed after service-owned provisioning; rerun Coordinator skill installation.",
        )
    encoded = json.dumps(
        {
            "repo_id": target.repo_id,
            "cwd": canonical_cwd,
            "files": list(canonical_files),
            "file_evidence": list(expected_evidence),
            "services": list(target.services),
            "project_name": target.project_name,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if expected != target.definition_fingerprint:
        raise ValueError("Compose target fields do not match the persisted fingerprint")


def _strict_current_path(value: str, *, directory: bool, field: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{field} is not absolute")
    absolute = Path(os.path.abspath(value))
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{field} is missing or unreadable") from exc
    if absolute != resolved:
        raise ValueError(f"{field} contains a symbolic-link component")
    if directory and not resolved.is_dir():
        raise ValueError(f"{field} is not a directory")
    if not directory and not resolved.is_file():
        raise ValueError(f"{field} is not a regular file")
    return str(resolved)


def _bounded_output(value: Any, *, limit: int = 4096) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _compose_file_evidence(path: str) -> dict[str, Any]:
    maximum_bytes = 8 * 1024 * 1024
    digest = hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum_bytes:
                    raise ValueError("Compose files must not exceed 8 MiB")
                digest.update(chunk)
    except OSError as exc:
        raise ValueError("Compose file could not be read") from exc
    return {"content_sha256": digest.hexdigest(), "byte_size": size}


def _port_available(port: int, protocol: str) -> bool:
    socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    probes: list[socket.socket] = []
    try:
        for family, address in (
            (socket.AF_INET, ("0.0.0.0", port)),
            (socket.AF_INET6, ("::", port)),
        ):
            try:
                probe = socket.socket(family, socket_type)
            except OSError:
                if family == socket.AF_INET6:
                    continue
                return False
            probes.append(probe)
            probe.set_inheritable(False)
            if family == socket.AF_INET6:
                with contextlib.suppress(OSError):
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                probe.bind(address)
            except OSError:
                return False
        return True
    finally:
        for probe in probes:
            probe.close()


def _verify_owned_tcp_listener(port: int, canonical_root: str) -> Mapping[str, Any]:
    """Prove one exact TCP listener belongs to the enrolled worktree.

    The broker service—not the client—performs both listener and cwd
    observation.  A missing tool, permission denial, multiple listeners, PID
    reuse, zombie, or path ambiguity is an unknown ownership result and fails
    closed.
    """

    root = _strict_current_path(
        canonical_root, directory=True, field="repository root"
    )
    lsof = _resolve_lsof_executable()
    first = _listener_pids(lsof, port)
    if len(first) != 1:
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "Existing listener adoption requires exactly one observable TCP listener.",
        )
    pid = next(iter(first))
    identity_before = _process_identity(pid)
    owner_uid_before = _process_owner_uid(pid)
    cwd = _process_cwd(lsof, pid)
    if os.path.commonpath((cwd, root)) != root:
        raise BrokerBackendError(
            "listener_project_mismatch",
            "The existing listener belongs to another repository.",
        )
    identity_after = _process_identity(pid)
    owner_uid_after = _process_owner_uid(pid)
    second = _listener_pids(lsof, port)
    if (
        identity_before != identity_after
        or owner_uid_before != owner_uid_after
        or second != {pid}
    ):
        raise BrokerBackendError(
            "listener_identity_changed",
            "The existing listener identity changed during broker verification.",
        )
    return {
        "pid": pid,
        "owner_uid": owner_uid_after,
        "process_identity": identity_after,
        "cwd": cwd,
        "canonical_root": root,
        "port": port,
        "protocol": "tcp",
    }


def _resolve_lsof_executable() -> str:
    candidates = [shutil.which("lsof"), "/usr/sbin/lsof", "/usr/bin/lsof"]
    for raw in candidates:
        if raw and _executable_file(Path(raw)):
            return str(Path(raw).absolute())
    raise BrokerBackendError(
        "listener_observer_unavailable",
        "The broker service cannot observe listener ownership because lsof is unavailable.",
    )


def _listener_pids(lsof: str, port: int) -> set[int]:
    completed = subprocess.run(
        [lsof, "-nP", "-a", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    if completed.returncode not in {0, 1} or (
        completed.returncode == 1 and completed.stderr.strip()
    ):
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service could not inspect the exact TCP listener.",
        )
    result: set[int] = set()
    for line in completed.stdout.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            result.add(int(line[1:]))
    return result


def _process_identity(pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except OSError as exc:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The broker service cannot read the listener process identity.",
            ) from exc
        delimiter = stat_text.rfind(")")
        if delimiter < 0:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The listener process identity is malformed.",
            )
        fields = stat_text[delimiter + 2 :].split()
        if len(fields) < 20 or fields[0] == "Z":
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The listener process is missing or is an unreaped zombie.",
            )
        return f"linux:{pid}:{fields[19]}"
    completed = subprocess.run(
        ["/bin/ps", "-o", "lstart=", "-p", str(pid)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    started = completed.stdout.strip()
    if completed.returncode != 0 or not started:
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service cannot read the listener process identity.",
        )
    return f"process:{pid}:{started}"


def _process_owner_uid(pid: int) -> int:
    """Read a stable kernel/account owner for the already-identified process."""

    if sys.platform.startswith("linux"):
        try:
            metadata = os.stat(f"/proc/{pid}", follow_symlinks=False)
        except OSError as exc:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The broker service cannot read the listener process owner.",
            ) from exc
        return int(metadata.st_uid)
    completed = subprocess.run(
        ["/bin/ps", "-o", "uid=", "-p", str(pid)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    raw = completed.stdout.strip()
    if completed.returncode != 0 or not raw.isdigit():
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service cannot read the listener process owner.",
        )
    return int(raw)


def _process_cwd(lsof: str, pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            raw = os.readlink(f"/proc/{pid}/cwd")
        except OSError as exc:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The broker service cannot read the listener process cwd.",
            ) from exc
        return _strict_current_path(raw, directory=True, field="listener cwd")
    completed = subprocess.run(
        [lsof, "-nP", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5.0,
        check=False,
    )
    paths = [line[1:] for line in completed.stdout.splitlines() if line.startswith("n")]
    if completed.returncode != 0 or len(paths) != 1:
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service cannot read one exact listener process cwd.",
        )
    return _strict_current_path(paths[0], directory=True, field="listener cwd")
