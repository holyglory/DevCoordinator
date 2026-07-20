"""Typed host effects for the authorized cross-user broker service.

Only exact normalized container identities and bounded port candidates reach
this module.  It deliberately has no command-string, shell, path, or display-
name interface.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Any, Callable, Iterator, Mapping, Optional

from .broker import (
    BrokerBackendError,
    DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS,
)
from .compose_contract import (
    bounded_compose_environment as _bounded_compose_environment,
    compose_directory_identity,
    compose_relative_parts,
    open_anchored_compose_root,
    open_compose_directory_beneath,
    read_anchored_compose_file,
    require_effective_compose_model,
    require_sealable_compose_payload,
)
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


class ComposeMutationOutcomeUncertain(RuntimeError):
    """A Compose runner was invoked but did not prove a complete outcome."""

    def __init__(
        self,
        *,
        action: str,
        failed_phase: str,
        completed_phases: tuple[str, ...],
        cleanup_failed: bool = False,
    ) -> None:
        super().__init__(
            f"Docker Compose {action} did not prove completion during {failed_phase}"
        )
        self.action = action
        self.failed_phase = failed_phase
        self.completed_phases = completed_phases
        self.cleanup_failed = cleanup_failed


def _postgres_backup_tool() -> Path:
    candidate = (
        Path(__file__).resolve().parents[3]
        / "postgres-docker-backup"
        / "scripts"
        / "postgres_docker_backup.py"
    )
    if not candidate.is_file() or candidate.is_symlink():
        raise RuntimeError(
            "canonical PostgreSQL backup skill executable is unavailable"
        )
    return candidate


def _validate_database_target(target: DatabaseMutationTarget) -> str:
    full_id = str(target.full_container_id).lower()
    if len(full_id) != 64 or any(
        character not in "0123456789abcdef" for character in full_id
    ):
        raise ValueError(
            "broker PostgreSQL target requires a full immutable container ID"
        )
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
            raise PermissionError(
                "service PostgreSQL output root must be a real directory"
            )
    else:
        parent = root.parent
        parent_metadata = parent.lstat()
        if parent.is_symlink() or not parent.is_dir():
            raise PermissionError(
                "service PostgreSQL output parent must be a real directory"
            )
        if parent_metadata.st_uid != os.geteuid() or parent_metadata.st_mode & 0o077:
            raise PermissionError(
                "service PostgreSQL output parent must be private and service-owned"
            )
        root.mkdir(mode=0o700)
        metadata = root.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise PermissionError(
            "service PostgreSQL output root must be private and service-owned"
        )
    return root


class LocalBrokerHostMutations:
    """Bounded host implementation for the broker's typed mutation protocol."""

    def __init__(
        self,
        *,
        docker_executable: str | None = None,
        docker_timeout_seconds: float = 45.0,
        docker_runner: Callable[
            [tuple[str, ...], float], subprocess.CompletedProcess[str]
        ]
        | None = None,
        compose_runner: Callable[
            [tuple[str, ...], str, float, Mapping[str, str]],
            subprocess.CompletedProcess[str],
        ]
        | None = None,
        compose_model_renderer: Callable[..., bytes] | None = None,
        port_probe: Callable[[int, str], bool] | None = None,
        listener_verifier: Callable[[int, str], Mapping[str, Any]] | None = None,
        postgres_timeout_seconds: float = DEFAULT_POSTGRES_COMMAND_TIMEOUT_SECONDS,
        postgres_runner: Callable[
            [tuple[str, ...], float, Mapping[str, str]],
            subprocess.CompletedProcess[str],
        ]
        | None = None,
    ) -> None:
        if docker_timeout_seconds <= 0 or docker_timeout_seconds > 600:
            raise ValueError(
                "docker_timeout_seconds must be greater than 0 and at most 600"
            )
        self._docker_executable = docker_executable
        self._docker_timeout_seconds = float(docker_timeout_seconds)
        self._docker_runner = docker_runner or self._run_docker
        self._compose_runner = compose_runner or self._run_compose
        self._compose_model_renderer = compose_model_renderer
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

    def compose_stop(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "stop")

    def compose_restart(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "restart")

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
            raise RuntimeError(
                "PostgreSQL backup tool omitted published artifact evidence"
            )
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
        if len(full_id) != 64 or any(
            character not in "0123456789abcdef" for character in full_id
        ):
            raise ValueError(
                "broker Docker target must carry a full immutable container ID"
            )
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

    def _compose(self, target: ComposeMutationTarget, action: str) -> Mapping[str, Any]:
        if action not in {"up", "stop", "restart", "down"}:
            raise ValueError("unsupported Compose broker action")
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            with _validated_compose_target(target) as (
                compose_payloads,
                env_payloads,
                pinned_cwd,
            ):
                renderer = self._compose_model_renderer
                renderer_arguments: dict[str, Any] = {
                    "compose_payloads": compose_payloads,
                    "env_payloads": env_payloads,
                    "profiles": target.profiles,
                    "declared_services": target.services,
                    "project_name": target.project_name,
                    "pinned_cwd": pinned_cwd,
                    "docker_executable": executable,
                }
                if renderer is None:
                    renderer = render_compose_effective_model
                    renderer_arguments["runner"] = self._compose_runner
                rendered = renderer(**renderer_arguments)
                runtime_evidence = require_effective_compose_model(
                    rendered,
                    declared_services=target.services,
                    declared_profiles=target.profiles,
                    project_name=target.project_name,
                    host_access_approved=target.effective_host_access_approved,
                )
                if (
                    runtime_evidence.model_sha256 != target.effective_model_sha256
                    or runtime_evidence.host_access_risks
                    != target.effective_host_access_risks
                    or runtime_evidence.service_replicas != target.service_replicas
                ):
                    raise BrokerBackendError(
                        "compose_effective_model_drift",
                        "Docker Compose now renders a different effective model; rerun Coordinator skill installation.",
                    )
                command: list[str] = [
                    executable,
                    "compose",
                    "--project-directory",
                    ".",
                    "--project-name",
                    target.project_name,
                ]
                environment = _bounded_compose_environment(executable)
                with _sealed_compose_input_snapshots(
                    compose_payloads=compose_payloads,
                    env_payloads=env_payloads,
                    action=action,
                ) as (snapshot_compose_files, snapshot_env_files):
                    for env_file in snapshot_env_files:
                        command.extend(("--env-file", env_file))
                    for profile in target.profiles:
                        command.extend(("--profile", profile))
                    for file_path in snapshot_compose_files:
                        command.extend(("--file", file_path))
                    phases = ("stop", "up") if action == "restart" else (action,)
                    completed_phases: list[str] = []
                    for phase in phases:
                        if not _compose_target_paths_are_current(target):
                            if completed_phases:
                                raise ComposeMutationOutcomeUncertain(
                                    action=action,
                                    failed_phase=f"{phase}_path_precheck",
                                    completed_phases=tuple(completed_phases),
                                )
                            raise BrokerBackendError(
                                "compose_definition_drift",
                                "Compose repository directory changed before host invocation; rerun Coordinator skill installation.",
                            )
                        phase_command = [*command, phase]
                        if phase == "up":
                            # The persisted service allowlist is the complete
                            # authorized scope.  Compose otherwise expands a
                            # requested service through ``depends_on`` and
                            # ``links``, allowing undeclared containers to be
                            # created by a root-owned broker invocation.
                            phase_command.extend(("--detach", "--no-deps"))
                        if phase in {"up", "stop"}:
                            phase_command.extend(target.services)
                        try:
                            completed = self._compose_runner(
                                tuple(phase_command),
                                pinned_cwd,
                                self._docker_timeout_seconds,
                                environment,
                            )
                        except Exception as exc:
                            # Once the runner has been invoked, a timeout or
                            # transport failure cannot prove that Compose made
                            # no host changes.
                            raise ComposeMutationOutcomeUncertain(
                                action=action,
                                failed_phase=phase,
                                completed_phases=tuple(completed_phases),
                            ) from exc
                        if completed.returncode != 0:
                            # Compose can echo interpolated secrets in
                            # diagnostics. Results never retain subprocess text.
                            raise ComposeMutationOutcomeUncertain(
                                action=action,
                                failed_phase=phase,
                                completed_phases=tuple(completed_phases),
                            )
                        completed_phases.append(phase)
                        if not _compose_target_paths_are_current(target):
                            raise ComposeMutationOutcomeUncertain(
                                action=action,
                                failed_phase=f"{phase}_path_recheck",
                                completed_phases=tuple(completed_phases),
                            )
        except BrokerBackendError:
            raise
        except ComposeMutationOutcomeUncertain:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise BrokerBackendError(
                "compose_definition_invalid",
                "Service-owned Compose definition is invalid; rerun Coordinator skill installation.",
            ) from exc
        return {
            "compose_definition_id": target.compose_definition_id,
            "action": action,
            "status": "completed",
            "definition_fingerprint": target.definition_fingerprint,
            "definition_generation": target.definition_generation,
            "repository_generation": target.repository_generation,
            "phases": completed_phases,
            "output_suppressed": True,
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
        command: tuple[str, ...],
        cwd: str,
        timeout_seconds: float,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(environment),
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
_COMPOSE_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@contextlib.contextmanager
def _validated_compose_target(
    target: ComposeMutationTarget,
) -> Iterator[tuple[tuple[bytes, ...], tuple[bytes, ...], str]]:
    """Pin one provisioned repository tree through the whole host mutation."""

    if not isinstance(target, ComposeMutationTarget):
        raise TypeError("Compose target must be a persisted typed definition")
    if not 1 <= len(target.compose_files) <= 16:
        raise ValueError("Compose target must contain bounded persisted files")
    if not 1 <= len(target.services) <= 128 or len(set(target.services)) != len(
        target.services
    ):
        raise ValueError("Compose target services are invalid")
    if len(target.env_files) > 16 or len(set(target.env_files)) != len(
        target.env_files
    ):
        raise ValueError("Compose target environment files are invalid")
    if len(target.profiles) > 64 or len(set(target.profiles)) != len(target.profiles):
        raise ValueError("Compose target profiles are invalid")
    if _COMPOSE_PROJECT_NAME.fullmatch(target.project_name) is None:
        raise ValueError("Compose target project identity is invalid")
    if any(_COMPOSE_SERVICE_NAME.fullmatch(item) is None for item in target.services):
        raise ValueError("Compose target contains an invalid service identity")
    if any(_COMPOSE_PROFILE_NAME.fullmatch(item) is None for item in target.profiles):
        raise ValueError("Compose target contains an invalid profile identity")
    if any(
        type(value) is not int or value < minimum
        for value, minimum in (
            (target.root_device, 0),
            (target.root_inode, 1),
            (target.cwd_device, 0),
            (target.cwd_inode, 1),
        )
    ):
        raise ValueError("Compose target directory identity is invalid")

    canonical_root = target.canonical_root
    compose_relative_parts(
        canonical_root,
        canonical_root=canonical_root,
        field="repository root",
    )
    cwd_parts = compose_relative_parts(
        target.cwd,
        canonical_root=canonical_root,
        field="Compose cwd",
    )
    canonical_files = tuple(target.compose_files)
    compose_file_parts = tuple(
        compose_relative_parts(
            item,
            canonical_root=canonical_root,
            field="Compose file",
        )
        for item in canonical_files
    )
    if not (
        len(target.compose_file_sha256s)
        == len(target.compose_file_sizes)
        == len(canonical_files)
    ):
        raise ValueError("Compose target file evidence is incomplete")
    if len(set(canonical_files)) != len(canonical_files):
        raise ValueError("Compose target contains duplicate files")
    canonical_env_files = tuple(target.env_files)
    env_file_parts = tuple(
        compose_relative_parts(
            item,
            canonical_root=canonical_root,
            field="Compose environment file",
        )
        for item in canonical_env_files
    )
    if len(set(canonical_env_files)) != len(canonical_env_files):
        raise ValueError("Compose target contains duplicate environment files")
    if not (
        len(target.env_file_sha256s)
        == len(target.env_file_sizes)
        == len(canonical_env_files)
    ):
        raise ValueError("Compose target environment-file evidence is incomplete")
    expected_evidence = tuple(
        {"content_sha256": digest, "byte_size": byte_size}
        for digest, byte_size in zip(
            target.compose_file_sha256s, target.compose_file_sizes
        )
    )
    expected_env_evidence = tuple(
        {"content_sha256": digest, "byte_size": byte_size}
        for digest, byte_size in zip(target.env_file_sha256s, target.env_file_sizes)
    )
    root_descriptor = -1
    cwd_descriptor = -1
    try:
        root_descriptor = open_anchored_compose_root(canonical_root)
        root_identity = compose_directory_identity(root_descriptor)
        if (root_identity.device, root_identity.inode) != (
            target.root_device,
            target.root_inode,
        ):
            raise BrokerBackendError(
                "compose_definition_drift",
                "Compose repository identity changed after provisioning; rerun Coordinator skill installation.",
            )
        cwd_descriptor = open_compose_directory_beneath(
            root_descriptor,
            cwd_parts,
        )
        cwd_identity = compose_directory_identity(cwd_descriptor)
        if (cwd_identity.device, cwd_identity.inode) != (
            target.cwd_device,
            target.cwd_inode,
        ):
            raise BrokerBackendError(
                "compose_definition_drift",
                "Compose working-directory identity changed after provisioning; rerun Coordinator skill installation.",
            )
        root_owner_uid = int(os.fstat(root_descriptor).st_uid)
        actual_file_material = tuple(
            read_anchored_compose_file(
                root_descriptor,
                parts,
                maximum_bytes=8 * 1024 * 1024,
            )
            for parts in compose_file_parts
        )
        for _evidence, payload in actual_file_material:
            require_sealable_compose_payload(payload)
        actual_evidence = tuple(item[0] for item in actual_file_material)
        if actual_evidence != expected_evidence:
            raise BrokerBackendError(
                "compose_definition_drift",
                "Compose files changed after service-owned provisioning; rerun Coordinator skill installation.",
            )
        actual_env_material = tuple(
            read_anchored_compose_file(
                root_descriptor,
                parts,
                maximum_bytes=1024 * 1024,
                require_private=True,
                allowed_owner_uids=frozenset({0, root_owner_uid}),
            )
            for parts in env_file_parts
        )
        actual_env_evidence = tuple(item[0] for item in actual_env_material)
        if actual_env_evidence != expected_env_evidence:
            raise BrokerBackendError(
                "compose_definition_drift",
                "Compose environment files changed after service-owned provisioning; "
                "rerun Coordinator skill installation.",
            )
        encoded = json.dumps(
            {
                "repo_id": target.repo_id,
                "canonical_root": canonical_root,
                "root_identity": {
                    "device": target.root_device,
                    "inode": target.root_inode,
                },
                "cwd": target.cwd,
                "cwd_identity": {
                    "device": target.cwd_device,
                    "inode": target.cwd_inode,
                },
                "files": list(canonical_files),
                "file_evidence": list(expected_evidence),
                "env_files": list(canonical_env_files),
                "env_file_evidence": list(expected_env_evidence),
                "profiles": list(target.profiles),
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
            raise ValueError(
                "Compose target fields do not match the persisted fingerprint"
            )
        if not Path("/proc/self/fd").is_dir():
            raise RuntimeError(
                "stable Compose working-directory handles are unavailable"
            )
        pinned_cwd = f"/proc/{os.getpid()}/fd/{cwd_descriptor}"
        yield (
            tuple(item[1] for item in actual_file_material),
            tuple(item[1] for item in actual_env_material),
            pinned_cwd,
        )
    finally:
        if cwd_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(cwd_descriptor)
        if root_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(root_descriptor)


def _compose_target_paths_are_current(target: ComposeMutationTarget) -> bool:
    root_descriptor = -1
    cwd_descriptor = -1
    try:
        root_descriptor = open_anchored_compose_root(target.canonical_root)
        root_identity = compose_directory_identity(root_descriptor)
        if (root_identity.device, root_identity.inode) != (
            target.root_device,
            target.root_inode,
        ):
            return False
        cwd_descriptor = open_compose_directory_beneath(
            root_descriptor,
            compose_relative_parts(
                target.cwd,
                canonical_root=target.canonical_root,
                field="Compose cwd",
            ),
        )
        cwd_identity = compose_directory_identity(cwd_descriptor)
        return (cwd_identity.device, cwd_identity.inode) == (
            target.cwd_device,
            target.cwd_inode,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    finally:
        if cwd_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(cwd_descriptor)
        if root_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(root_descriptor)


def _strict_current_path(value: str, *, directory: bool, field: str) -> str:
    """Validate non-Compose paths that are not executed as privileged roots."""

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


def render_compose_effective_model(
    *,
    compose_payloads: tuple[bytes, ...],
    env_payloads: tuple[bytes, ...],
    profiles: tuple[str, ...],
    declared_services: tuple[str, ...],
    project_name: str,
    pinned_cwd: str,
    docker_executable: str | None = None,
    runner: Callable[
        [tuple[str, ...], str, float, Mapping[str, str]],
        subprocess.CompletedProcess[str],
    ]
    | None = None,
    timeout_seconds: float = 30.0,
) -> bytes:
    """Render the exact merged Compose model without mutating Docker state."""

    if not compose_payloads or len(compose_payloads) > 16:
        raise ValueError("effective Compose rendering requires bounded input files")
    if len(env_payloads) > 16:
        raise ValueError("effective Compose rendering has too many environment files")
    if _COMPOSE_PROJECT_NAME.fullmatch(project_name) is None:
        raise ValueError("effective Compose project identity is invalid")
    if any(_COMPOSE_PROFILE_NAME.fullmatch(item) is None for item in profiles):
        raise ValueError("effective Compose profile identity is invalid")
    if not declared_services or any(
        _COMPOSE_SERVICE_NAME.fullmatch(item) is None for item in declared_services
    ):
        raise ValueError("effective Compose declared service scope is invalid")
    for payload in compose_payloads:
        require_sealable_compose_payload(payload)
    executable = docker_executable or _resolve_docker_executable()
    invoke = runner or LocalBrokerHostMutations._run_compose
    command: list[str] = [
        executable,
        "compose",
        "--project-directory",
        ".",
        "--project-name",
        project_name,
    ]
    environment = _bounded_compose_environment(executable)
    with _sealed_compose_input_snapshots(
        compose_payloads=compose_payloads,
        env_payloads=env_payloads,
        action="config",
    ) as (compose_files, env_files):
        for env_file in env_files:
            command.extend(("--env-file", env_file))
        for profile in profiles:
            command.extend(("--profile", profile))
        for file_path in compose_files:
            command.extend(("--file", file_path))
        command.extend(("config", "--format", "json"))
        try:
            completed = invoke(tuple(command), pinned_cwd, timeout_seconds, environment)
        except Exception as exc:
            raise BrokerBackendError(
                "compose_effective_model_unavailable",
                "Docker Compose could not render the merged enrollment model.",
            ) from exc
        if completed.returncode != 0:
            raise BrokerBackendError(
                "compose_effective_model_invalid",
                "Docker Compose rejected the merged enrollment model.",
            )
        payload = completed.stdout.encode("utf-8")
        if len(payload) > 16 * 1024 * 1024:
            raise BrokerBackendError(
                "compose_effective_model_invalid",
                "Docker Compose rendered an oversized enrollment model.",
            )
        return payload


@contextlib.contextmanager
def _sealed_compose_input_snapshots(
    *,
    compose_payloads: tuple[bytes, ...],
    env_payloads: tuple[bytes, ...],
    action: str,
) -> Iterator[tuple[tuple[str, ...], tuple[str, ...]]]:
    """Expose immutable inputs without a named plaintext file on Linux."""

    if hasattr(os, "memfd_create") and Path("/proc/self/fd").is_dir():
        descriptors: list[int] = []

        def snapshot(payload: bytes, label: str) -> str:
            flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
            descriptor = os.memfd_create(
                f"devcoordinator-{label}",
                flags,
            )
            descriptors.append(descriptor)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("sealed Compose input write made no progress")
                view = view[written:]
            os.lseek(descriptor, 0, os.SEEK_SET)
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0)
                | getattr(fcntl, "F_SEAL_SHRINK", 0)
                | getattr(fcntl, "F_SEAL_GROW", 0)
                | getattr(fcntl, "F_SEAL_WRITE", 0)
            )
            if not seals or not hasattr(fcntl, "F_ADD_SEALS"):
                raise RuntimeError("Linux Compose input sealing is unavailable")
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            return f"/proc/{os.getpid()}/fd/{descriptor}"

        body_error: BaseException | None = None
        body_completed = False
        try:
            compose_paths = tuple(
                snapshot(payload, f"compose-{ordinal}")
                for ordinal, payload in enumerate(compose_payloads)
            )
            # An explicit CLI environment file suppresses Compose's implicit
            # project-local .env lookup. Always put a sealed empty baseline
            # first, including when the definition declares no environment
            # files, so this guarantee does not depend solely on the
            # process-level COMPOSE_DISABLE_ENV_FILE compatibility switch.
            env_paths = (
                snapshot(b"", "env-defaults"),
                *(
                    snapshot(payload, f"env-{ordinal}")
                    for ordinal, payload in enumerate(env_payloads)
                ),
            )
            yield compose_paths, env_paths
            body_completed = True
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            cleanup_failed = False
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True
            if cleanup_failed:
                if isinstance(body_error, ComposeMutationOutcomeUncertain):
                    raise ComposeMutationOutcomeUncertain(
                        action=body_error.action,
                        failed_phase=body_error.failed_phase,
                        completed_phases=body_error.completed_phases,
                        cleanup_failed=True,
                    ) from body_error
                if body_completed and action == "config":
                    raise RuntimeError(
                        "Compose validation input cleanup failed after rendering"
                    )
                if body_completed:
                    completed = ("stop", "up") if action == "restart" else (action,)
                    raise ComposeMutationOutcomeUncertain(
                        action=action,
                        failed_phase="cleanup",
                        completed_phases=completed,
                        cleanup_failed=True,
                    )
                cleanup_error = RuntimeError(
                    "Compose sealed-input cleanup failed before host invocation"
                )
                if body_error is not None:
                    raise cleanup_error from body_error
                raise cleanup_error
        return

    directory = Path(tempfile.mkdtemp(prefix="devcoordinator-compose-input-"))
    os.chmod(directory, 0o700)
    paths: list[Path] = []

    def private_snapshot(payload: bytes, label: str, ordinal: int) -> str:
        path = directory / f"{label}-{ordinal:04d}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        paths.append(path)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("private Compose input write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return str(path)

    body_error: BaseException | None = None
    body_completed = False
    try:
        compose_paths = tuple(
            private_snapshot(payload, "compose", ordinal)
            for ordinal, payload in enumerate(compose_payloads)
        )
        env_paths = (
            private_snapshot(b"", "env-defaults", 0),
            *(
                private_snapshot(payload, "env", ordinal)
                for ordinal, payload in enumerate(env_payloads, start=1)
            ),
        )
        yield compose_paths, env_paths
        body_completed = True
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        cleanup_errors: list[str] = []
        for path in reversed(paths):
            try:
                path.unlink()
            except OSError:
                cleanup_errors.append("input unlink failed")
        try:
            directory.rmdir()
        except OSError:
            cleanup_errors.append("snapshot directory removal failed")
        if cleanup_errors:
            if isinstance(body_error, ComposeMutationOutcomeUncertain):
                raise ComposeMutationOutcomeUncertain(
                    action=body_error.action,
                    failed_phase=body_error.failed_phase,
                    completed_phases=body_error.completed_phases,
                    cleanup_failed=True,
                ) from body_error
            if body_completed and action == "config":
                raise RuntimeError(
                    "Compose validation input cleanup failed after rendering"
                )
            if body_completed:
                completed = ("stop", "up") if action == "restart" else (action,)
                raise ComposeMutationOutcomeUncertain(
                    action=action,
                    failed_phase="cleanup",
                    completed_phases=completed,
                    cleanup_failed=True,
                )
            cleanup_error = RuntimeError(
                "Compose input cleanup failed before host invocation"
            )
            if body_error is not None:
                raise cleanup_error from body_error
            raise cleanup_error


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

    root = _strict_current_path(canonical_root, directory=True, field="repository root")
    lsof = None if sys.platform.startswith("linux") else _resolve_lsof_executable()
    first = _platform_listener_pids(port, lsof=lsof)
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
    second = _platform_listener_pids(port, lsof=lsof)
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


def _platform_listener_pids(port: int, *, lsof: str | None) -> set[int]:
    if sys.platform.startswith("linux"):
        return _linux_proc_listener_pids(port)
    if lsof is None:
        raise BrokerBackendError(
            "listener_observer_unavailable",
            "The broker service has no platform listener observer.",
        )
    return _listener_pids(lsof, port)


def _linux_proc_listener_pids(port: int) -> set[int]:
    """Resolve every owner of the exact Linux TCP LISTEN socket set.

    ``/proc/net/tcp{,6}`` is the kernel socket inventory; PID fd links bind
    those socket inodes to processes.  Every matching inode must be accounted
    for, so permission gaps and process races remain unknown rather than being
    coerced to a clean no-match.
    """

    inodes: set[str] = set()
    for raw_path in ("/proc/net/tcp", "/proc/net/tcp6"):
        path = Path(raw_path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
        except OSError as exc:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The broker service cannot read the Linux TCP listener table.",
            ) from exc
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                raise BrokerBackendError(
                    "listener_identity_unobservable",
                    "The Linux TCP listener table is malformed.",
                )
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError) as exc:
                raise BrokerBackendError(
                    "listener_identity_unobservable",
                    "The Linux TCP listener endpoint is malformed.",
                ) from exc
            if local_port == int(port) and fields[3] == "0A":
                inode = fields[9]
                if not inode.isdigit() or inode == "0":
                    raise BrokerBackendError(
                        "listener_identity_unobservable",
                        "The Linux TCP listener inode is malformed.",
                    )
                inodes.add(inode)
    if not inodes:
        return set()

    targets = {f"socket:[{inode}]": inode for inode in inodes}
    owners: dict[str, set[int]] = {inode: set() for inode in inodes}
    try:
        processes = tuple(Path("/proc").iterdir())
    except OSError as exc:
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service cannot enumerate Linux processes.",
        ) from exc
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            descriptors = tuple(os.scandir(process / "fd"))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor.path)
            except OSError:
                continue
            inode = targets.get(target)
            if inode is not None:
                owners[inode].add(int(process.name))
    missing = sorted(inode for inode, pids in owners.items() if not pids)
    if missing:
        raise BrokerBackendError(
            "listener_identity_unobservable",
            "The broker service could not bind every Linux listener inode to a process.",
        )
    return {pid for pids in owners.values() for pid in pids}


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


def _process_cwd(lsof: str | None, pid: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            raw = os.readlink(f"/proc/{pid}/cwd")
        except OSError as exc:
            raise BrokerBackendError(
                "listener_identity_unobservable",
                "The broker service cannot read the listener process cwd.",
            ) from exc
        return _strict_current_path(raw, directory=True, field="listener cwd")
    if lsof is None:
        raise BrokerBackendError(
            "listener_observer_unavailable",
            "The broker service cannot inspect the listener process cwd.",
        )
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
