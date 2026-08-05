"""Typed host effects for the authorized cross-user broker service.

Only exact normalized container identities and bounded port candidates reach
this module.  It deliberately has no command-string, shell, path, or display-
name interface.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable, Iterator, Mapping, Optional
import uuid

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
    stable_compose_descriptor_path,
)
from .broker_persistence import (
    ComposeMutationTarget,
    ComposeRunOnceMutationTarget,
    DatabaseMutationTarget,
    DockerMutationTarget,
    EphemeralImageTarget,
    RegisteredDatabaseBackup,
    RuntimeDockerMutationTarget,
    RuntimeServiceLogTarget,
)
from .runtime_artifacts import RUNTIME_LOG_MAX_BYTES, RUNTIME_LOG_MAX_LINES
from .compose_run_once import (
    MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES,
    PublishedReceipt,
    compose_run_once_policies_document,
    validate_published_receipt,
)
from .ephemeral_secrets import EphemeralSecretMount
from .worker_native import project_repository_slice


_LOGGER = logging.getLogger(__name__)


DOCKER_ACTIONS = frozenset({"start", "stop", "restart"})
EPHEMERAL_DOCKER_LABELS = (
    "io.devcoordinator.ephemeral.run_id",
    "io.devcoordinator.ephemeral.creation_nonce",
    "io.devcoordinator.repository_id",
    "io.devcoordinator.ephemeral.template_id",
    "io.devcoordinator.ephemeral.definition_fingerprint",
)
DOCKER_LOCATIONS = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/usr/bin/docker",
    "/Applications/Docker.app/Contents/Resources/bin/docker",
    "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
)
_PROJECT_CONTAINER_MEMORY_LIMIT = "20g"
_PROJECT_CONTAINER_CPU_LIMIT = "8.0"
_PROJECT_CONTAINER_PIDS_LIMIT = 4096
_COMPOSE_RUN_ONCE_LABELS = (
    "io.devcoordinator.run_once.operation_id",
    "io.devcoordinator.run_once.repository_id",
    "io.devcoordinator.run_once.definition_id",
    "io.devcoordinator.run_once.service",
    "io.devcoordinator.run_once.policy_fingerprint",
    "io.devcoordinator.run_once.image_id",
)


def _project_slice(*, owner_uid: int | None, repository_id: str | None) -> str:
    try:
        if owner_uid is None or repository_id is None:
            raise ValueError("project isolation identity is missing")
        return project_repository_slice(
            uid=owner_uid,
            repository_id=repository_id,
        )
    except ValueError as error:
        raise BrokerBackendError(
            "project_isolation_identity_unavailable",
            "The repository cannot be attributed to a bounded project cgroup.",
        ) from error


def _compose_isolation_override(
    target: ComposeMutationTarget,
    *,
    services: tuple[str, ...] | None = None,
    immutable_images: Mapping[str, str] | None = None,
) -> bytes:
    cgroup_parent = _project_slice(
        owner_uid=target.owner_uid,
        repository_id=target.repo_id,
    )
    selected_services = target.services if services is None else services
    image_overrides = dict(immutable_images or {})
    return (
        json.dumps(
            {
                "services": {
                    service: {
                        "cgroup_parent": cgroup_parent,
                        "cpus": _PROJECT_CONTAINER_CPU_LIMIT,
                        "mem_limit": _PROJECT_CONTAINER_MEMORY_LIMIT,
                        "pids_limit": _PROJECT_CONTAINER_PIDS_LIMIT,
                        **(
                            {
                                "image": image_overrides[service],
                                "pull_policy": "never",
                                "restart": "no",
                                "stdin_open": False,
                                "tty": False,
                            }
                            if service in image_overrides
                            else {}
                        ),
                    }
                    for service in selected_services
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


@dataclass(frozen=True)
class EphemeralDockerIdentity:
    """Persisted identity copied into immutable Docker labels.

    These are the only labels used to rediscover a create whose caller or
    broker died after Docker accepted the request. A display name is never an
    ownership signal.
    """

    run_id: str
    creation_nonce: str
    repository_id: str
    template_id: str
    definition_fingerprint: str


@dataclass(frozen=True)
class EphemeralDockerCreateTarget:
    """Sealed, broker-resolved input for one stopped ephemeral container."""

    identity: EphemeralDockerIdentity
    owner_uid: int
    container_name: str
    image_ref: str
    command: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    memory_bytes: int
    cpu_limit: str | float
    host_tcp_port: int | None
    container_tcp_port: int | None
    network_container_id: str | None = None
    secret_mount: EphemeralSecretMount | None = None


@dataclass(frozen=True)
class EphemeralDockerContainerTarget:
    """Persisted immutable identity required before every later mutation."""

    identity: EphemeralDockerIdentity
    full_container_id: str
    secret_mount: EphemeralSecretMount | None = None
    # The exact digest is copied from the durable run/template snapshot.
    # Cleanup remains identity-only, but normal profile checks need it to
    # prove image-created anonymous volumes.
    image_ref: str | None = None
    network_container_id: str | None = None


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


@dataclass(frozen=True)
class ComposeRunOnceOutputEvidence:
    """Bounded public receipt plus private stream integrity evidence."""

    published_receipt: PublishedReceipt
    stdout_sha256: str
    stdout_byte_size: int
    stderr_sha256: str
    stderr_byte_size: int


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
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PermissionError(
                "service PostgreSQL output root must be a real directory"
            )
    else:
        parent = root.parent
        parent_metadata = parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            raise PermissionError(
                "service PostgreSQL output parent must be a real directory"
            )
        # Every local account belongs to the same developer.  Reachability,
        # not owner/mode metadata, is the local trust boundary; the backup
        # tool still owns artifact integrity and verification.
        root.mkdir(mode=0o755)
        metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError(
            "service PostgreSQL output root must be a real directory"
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
        docker_log_runner: Callable[
            [tuple[str, ...], float, int], tuple[bytes, int]
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
        self._docker_log_runner = docker_log_runner or self._run_bounded_docker_logs
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
                "Host listener verifier returned invalid repository evidence.",
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

    def docker_capture_logs(
        self, target: RuntimeDockerMutationTarget
    ) -> tuple[bytes, int]:
        """Capture one bounded tail using only an immutable full container ID."""

        full_id = str(target.full_container_id).lower()
        if re.fullmatch(r"[0-9a-f]{64}", full_id) is None:
            raise BrokerBackendError(
                "runtime_log_identity_invalid",
                "Runtime log capture requires one immutable full container ID.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        command = (
            executable,
            "logs",
            "--tail",
            str(RUNTIME_LOG_MAX_LINES),
            "--timestamps",
            full_id,
        )
        try:
            return self._docker_log_runner(
                command,
                self._docker_timeout_seconds,
                RUNTIME_LOG_MAX_BYTES + 64 * 1024,
            )
        except BrokerBackendError:
            raise
        except OSError as error:
            raise BrokerBackendError(
                "runtime_docker_log_capture_failed",
                "Docker log capture could not start for the exact container.",
            ) from error

    def service_capture_logs(
        self, target: RuntimeServiceLogTarget
    ) -> tuple[bytes, int, str]:
        """Read one bounded log from the exact enrolled service definition."""

        if (
            not target.server_definition_id
            or not target.repo_id
            or not target.definition_fingerprint.startswith("sha256:")
        ):
            raise BrokerBackendError(
                "runtime_log_identity_invalid",
                "Service log capture requires one exact enrolled definition.",
            )
        return self._read_bounded_service_log(
            target.log_path,
            maximum_buffer=RUNTIME_LOG_MAX_BYTES + 64 * 1024,
        )

    @staticmethod
    def _read_bounded_service_log(
        raw_path: str, *, maximum_buffer: int
    ) -> tuple[bytes, int, str]:
        path = Path(raw_path)
        if (
            not path.is_absolute()
            or path == Path("/")
            or any(part in {"", ".", ".."} for part in path.parts[1:])
            or not hasattr(os, "O_NOFOLLOW")
        ):
            raise BrokerBackendError(
                "service_log_unavailable",
                "The exact service log path is unavailable or unsafe.",
            )
        directory_flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_fd = os.open("/", directory_flags)
        descriptor = -1
        try:
            for component in path.parts[1:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            file_flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                file_flags |= os.O_NONBLOCK
            descriptor = os.open(path.name, file_flags, dir_fd=directory_fd)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise BrokerBackendError(
                    "service_log_unavailable",
                    "The exact service log is not a regular file.",
                )
            amount = min(int(before.st_size), maximum_buffer)
            offset = int(before.st_size) - amount
            chunks: list[bytes] = []
            remaining = amount
            while remaining:
                chunk = os.pread(descriptor, min(64 * 1024, remaining), offset)
                if not chunk:
                    break
                chunks.append(chunk)
                offset += len(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(payload) != amount
                or not stat.S_ISREG(after.st_mode)
                or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or after.st_size < before.st_size
            ):
                raise BrokerBackendError(
                    "service_log_changed",
                    "The exact service log was replaced or truncated during capture.",
                )
            identity = "sha256:" + hashlib.sha256(
                (
                    f"{before.st_dev}:{before.st_ino}:"
                    f"{before.st_size}:{before.st_mtime_ns}"
                ).encode("ascii")
            ).hexdigest()
            return payload, int(before.st_size) - amount, identity
        except BrokerBackendError:
            raise
        except OSError as error:
            raise BrokerBackendError(
                "service_log_unavailable",
                "The exact service log could not be opened safely.",
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(directory_fd)

    @staticmethod
    def _run_bounded_docker_logs(
        command: tuple[str, ...], timeout: float, maximum_buffer: int
    ) -> tuple[bytes, int]:
        tail = bytearray()
        discarded = 0
        reader_error: list[BaseException] = []
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        def drain() -> None:
            nonlocal discarded
            try:
                assert process.stdout is not None
                while True:
                    chunk = process.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    tail.extend(chunk)
                    overflow = len(tail) - maximum_buffer
                    if overflow > 0:
                        del tail[:overflow]
                        discarded += overflow
            except BaseException as error:  # pragma: no cover - pipe boundary
                reader_error.append(error)

        reader = threading.Thread(
            target=drain,
            name="broker-docker-log-reader",
            daemon=True,
        )
        reader.start()
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait(timeout=5)
        finally:
            reader.join(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        if reader.is_alive() or reader_error:
            raise BrokerBackendError(
                "runtime_docker_log_capture_failed",
                "Docker log capture did not reach a bounded terminal state.",
            )
        if timed_out:
            raise BrokerBackendError(
                "runtime_log_capture_timeout",
                "Docker log capture exceeded its bounded timeout.",
            )
        if returncode != 0:
            _LOGGER.warning(
                "exact Docker log capture failed returncode=%s target=%s",
                returncode,
                command[-1],
            )
            raise BrokerBackendError(
                "runtime_docker_log_capture_failed",
                "Docker could not capture logs for the exact container.",
            )
        return bytes(tail), discarded

    def docker_inspect_ephemeral_image(
        self, target: EphemeralImageTarget
    ) -> Mapping[str, Any]:
        """Prove the exact sealed template image is locally available."""

        image_ref = _validate_ephemeral_image_target(target)
        executable = self._docker_executable or _resolve_docker_executable()
        completed = self._run_ephemeral_image_inspect(
            (
                executable,
                "image",
                "inspect",
                "--format",
                "{{json .}}",
                image_ref,
            ),
            image_ref=image_ref,
        )
        if completed is None:
            return {"cached": False, "image_ref": image_ref}
        return _parse_ephemeral_image_inspection(
            completed.stdout, image_ref=image_ref
        )

    def docker_prefetch_ephemeral_image(
        self, target: EphemeralImageTarget
    ) -> Mapping[str, Any]:
        """Pull only a sealed absent digest, then require exact local proof."""

        before = self.docker_inspect_ephemeral_image(target)
        if before["cached"] is True:
            return {**before, "cache_origin": "already_present", "changed": False}
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            self._run_ephemeral_docker(
                (executable, "pull", "--quiet", target.image_ref),
                phase="image_prefetch",
                outcome_may_have_changed=True,
            )
            after = self.docker_inspect_ephemeral_image(target)
        except BrokerBackendError as error:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The sealed image pull did not prove its exact local cache outcome; retry with the same operation ID for reconciliation.",
            ) from error
        if after["cached"] is not True:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "The sealed image pull returned without exact local cache proof; retry with the same operation ID for reconciliation.",
            )
        return {**after, "cache_origin": "pulled", "changed": True}

    def docker_create_ephemeral(
        self, target: EphemeralDockerCreateTarget
    ) -> Mapping[str, Any]:
        """Create, but never start, one sealed ephemeral container."""

        normalized = _validate_ephemeral_create_target(target)
        executable = self._docker_executable or _resolve_docker_executable()
        command = [
            executable,
            "create",
            "--name",
            target.container_name,
            "--pull",
            "never",
            "--restart",
            "no",
            "--network",
            (
                "bridge"
                if target.network_container_id is None
                else "container:" + target.network_container_id
            ),
            "--memory",
            str(target.memory_bytes),
            "--cpus",
            normalized["cpu_limit"],
            "--pids-limit",
            str(_PROJECT_CONTAINER_PIDS_LIMIT),
            "--cgroup-parent",
            _project_slice(
                owner_uid=target.owner_uid,
                repository_id=target.identity.repository_id,
            ),
        ]
        for name, value in normalized["labels"]:
            command.extend(("--label", f"{name}={value}"))
        if target.host_tcp_port is not None:
            command.extend(
                (
                    "--publish",
                    "127.0.0.1:"
                    f"{target.host_tcp_port}:{target.container_tcp_port}/tcp",
                )
            )
        secret_mount = normalized["secret_mount"]
        if secret_mount is not None:
            command.extend(
                (
                    "--mount",
                    "type=bind,src="
                    + str(secret_mount.source_directory)
                    + ",dst="
                    + secret_mount.container_directory
                    + ",readonly",
                )
            )
        with _sealed_ephemeral_environment(normalized["environment_payload"]) as env:
            command.extend(("--env-file", env, target.image_ref, *target.command))
            completed = self._run_ephemeral_docker(
                tuple(command), phase="create", outcome_may_have_changed=True
            )
        full_id = _require_exact_container_id_output(completed.stdout)
        container_target = EphemeralDockerContainerTarget(
            identity=target.identity,
            full_container_id=full_id,
            secret_mount=target.secret_mount,
            image_ref=target.image_ref,
            network_container_id=target.network_container_id,
        )
        observed = self.docker_inspect_ephemeral(container_target)
        if observed["running"] is not False or observed["status"] != "created":
            raise BrokerBackendError(
                "ephemeral_docker_create_outcome_unknown",
                "Docker created an ephemeral container but its stopped state was not proved.",
            )
        return {
            **observed,
            "action": "create",
            "container_name": target.container_name,
        }

    def docker_find_ephemeral(
        self, identity: EphemeralDockerIdentity
    ) -> Mapping[str, Any]:
        """Recover one create by all persisted labels, never by its name."""

        labels = _validate_ephemeral_identity(identity)
        executable = self._docker_executable or _resolve_docker_executable()
        command: list[str] = [
            executable,
            "container",
            "ls",
            "--all",
            "--no-trunc",
        ]
        for name, value in labels:
            command.extend(("--filter", f"label={name}={value}"))
        command.extend(("--format", "{{.ID}}"))
        completed = self._run_ephemeral_docker(
            tuple(command), phase="find", outcome_may_have_changed=False
        )
        output = _require_bounded_ephemeral_output(completed.stdout)
        candidates = tuple(line.strip().lower() for line in output.splitlines() if line.strip())
        if not candidates:
            return {"found": False, "labels": dict(labels)}
        if len(candidates) != 1 or not _is_full_container_id(candidates[0]):
            raise BrokerBackendError(
                "ephemeral_docker_identity_ambiguous",
                "Docker did not return exactly one immutable container for the "
                "persisted creation identity.",
            )
        target = EphemeralDockerContainerTarget(
            identity=identity,
            full_container_id=candidates[0],
        )
        observed = self._docker_inspect_ephemeral_identity(target)
        return {"found": True, **_ephemeral_public_observation(observed)}

    def docker_inspect_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]:
        """Prove exact ID, all ownership labels, and the sealed safety profile."""

        evidence = self._docker_inspect_ephemeral_identity(target)
        image_volume_destinations = self._image_volume_destinations_for_profile(
            image_ref=target.image_ref,
            mounts=evidence["mounts"],
        )
        _require_ephemeral_safe_profile(
            evidence,
            secret_mount=target.secret_mount,
            image_volume_destinations=image_volume_destinations,
            expected_network_mode=(
                "bridge"
                if target.network_container_id is None
                else "container:" + target.network_container_id
            ),
        )
        return _ephemeral_public_observation(evidence)

    def _image_volume_destinations_for_profile(
        self, *, image_ref: str | None, mounts: object
    ) -> tuple[str, ...]:
        """Bind implicit-volume acceptance to the exact cached image digest.

        The broker never supplies a volume argument to ``docker create``. An
        image may nevertheless declare ``Config.Volumes`` and Docker then
        creates anonymous volumes on its behalf. They are allowed only after a
        fresh inspection proves the destinations of the exact pinned image
        from the durable template/run snapshot.
        """

        if not _contains_volume_mount(mounts):
            return ()
        if (
            not isinstance(image_ref, str)
            or _EPHEMERAL_PINNED_IMAGE_REF.fullmatch(image_ref) is None
        ):
            raise BrokerBackendError(
                "ephemeral_docker_safety_profile_mismatch",
                "Docker profile evidence has an implicit volume but no exact pinned image proof.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        completed = self._run_ephemeral_image_inspect(
            (
                executable,
                "image",
                "inspect",
                "--format",
                "{{json .}}",
                image_ref,
            ),
            image_ref=image_ref,
        )
        if completed is None:
            raise BrokerBackendError(
                "ephemeral_docker_safety_profile_mismatch",
                "Docker profile evidence has an implicit volume but the exact pinned image is unavailable.",
            )
        _parse_ephemeral_image_inspection(completed.stdout, image_ref=image_ref)
        return _parse_ephemeral_image_volume_destinations(completed.stdout)

    def _docker_inspect_ephemeral_identity(
        self, target: EphemeralDockerContainerTarget
    ) -> dict[str, Any]:
        """Prove only immutable identity; cleanup deliberately tolerates drift."""

        full_id, labels = _validate_ephemeral_container_target(target)
        executable = self._docker_executable or _resolve_docker_executable()
        completed = self._run_ephemeral_docker(
            (
                executable,
                "inspect",
                "--type",
                "container",
                "--format",
                _EPHEMERAL_INSPECT_FORMAT,
                full_id,
            ),
            phase="inspect",
            outcome_may_have_changed=False,
        )
        evidence = _parse_ephemeral_inspection(completed.stdout)
        if evidence["full_container_id"] != full_id:
            raise BrokerBackendError(
                "ephemeral_docker_identity_mismatch",
                "Docker inspect did not prove the persisted immutable container identity.",
            )
        observed_labels = evidence["all_labels"]
        if any(observed_labels.get(name) != value for name, value in labels):
            raise BrokerBackendError(
                "ephemeral_docker_identity_mismatch",
                "Docker inspect did not prove every persisted ephemeral ownership label.",
            )
        return {
            "full_container_id": full_id,
            "status": evidence["status"],
            "running": evidence["running"],
            "restart_policy": evidence["restart_policy"],
            "labels": dict(labels),
            "privileged": evidence["privileged"],
            "binds": evidence["binds"],
            "mounts": evidence["mounts"],
            "cap_add": evidence["cap_add"],
            "devices": evidence["devices"],
            "network_mode": evidence["network_mode"],
            "pid_mode": evidence["pid_mode"],
            "state_pid": evidence["state_pid"],
            "networks": evidence["networks"],
        }

    def docker_test_fixture_namespace(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]:
        """Return race-checked namespace evidence for one exact running fixture."""

        evidence = self._docker_inspect_ephemeral_identity(target)
        pid = evidence["state_pid"]
        if evidence["running"] is not True or type(pid) is not int or pid <= 1:
            raise BrokerBackendError(
                "test_fixture_namespace_unavailable",
                "The exact test fixture has no running network namespace.",
            )
        identity_before = _process_identity(pid)
        namespace_path = Path(f"/proc/{pid}/ns/net")
        try:
            namespace_before = namespace_path.stat()
        except OSError as error:
            raise BrokerBackendError(
                "test_fixture_namespace_unavailable",
                "The exact test fixture network namespace is unavailable.",
            ) from error
        confirmed = self._docker_inspect_ephemeral_identity(target)
        identity_after = _process_identity(pid)
        namespace_after = namespace_path.stat()
        if (
            confirmed["running"] is not True
            or confirmed["state_pid"] != pid
            or identity_before != identity_after
            or (namespace_before.st_dev, namespace_before.st_ino)
            != (namespace_after.st_dev, namespace_after.st_ino)
        ):
            raise BrokerBackendError(
                "test_fixture_namespace_changed",
                "The exact test fixture network namespace changed during proof.",
            )
        return {
            "full_container_id": target.full_container_id,
            "pid": pid,
            "process_identity": identity_after,
            "namespace_path": str(namespace_path),
            "namespace_device": namespace_after.st_dev,
            "namespace_inode": namespace_after.st_ino,
        }

    def docker_start_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]:
        before = self.docker_inspect_ephemeral(target)
        if before["running"] is True:
            return {**before, "action": "start", "changed": False}
        full_id = str(before["full_container_id"])
        executable = self._docker_executable or _resolve_docker_executable()
        self._run_ephemeral_docker(
            (executable, "start", full_id),
            phase="start",
            outcome_may_have_changed=True,
        )
        after = self.docker_inspect_ephemeral(target)
        if after["running"] is not True:
            raise BrokerBackendError(
                "ephemeral_docker_start_outcome_unknown",
                "Docker start returned but the exact ephemeral container was not proved running.",
            )
        return {**after, "action": "start", "changed": True}

    def docker_stop_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]:
        before, restart_policy_changed = self._prepare_ephemeral_cleanup(target)
        if before["running"] is False:
            return {
                **_ephemeral_public_observation(before),
                "action": "stop",
                "changed": restart_policy_changed,
                "restart_policy_changed": restart_policy_changed,
            }
        full_id = str(before["full_container_id"])
        executable = self._docker_executable or _resolve_docker_executable()
        self._run_ephemeral_docker(
            (executable, "stop", "--time", "10", full_id),
            phase="stop",
            outcome_may_have_changed=True,
        )
        after = self._docker_inspect_ephemeral_identity(target)
        if after["running"] is not False:
            raise BrokerBackendError(
                "ephemeral_docker_stop_outcome_unknown",
                "Docker stop returned but the exact ephemeral container was not proved stopped.",
            )
        return {
            **_ephemeral_public_observation(after),
            "action": "stop",
            "changed": True,
            "restart_policy_changed": restart_policy_changed,
        }

    def docker_remove_ephemeral(
        self, target: EphemeralDockerContainerTarget
    ) -> Mapping[str, Any]:
        before, restart_policy_changed = self._prepare_ephemeral_cleanup(target)
        if before["running"] is not False:
            raise BrokerBackendError(
                "ephemeral_docker_remove_requires_stopped",
                "The exact ephemeral container must be stopped before removal.",
            )
        full_id = str(before["full_container_id"])
        executable = self._docker_executable or _resolve_docker_executable()
        self._run_ephemeral_docker(
            (executable, "rm", "--volumes", full_id),
            phase="remove",
            outcome_may_have_changed=True,
        )
        return {
            "full_container_id": full_id,
            "labels": before["labels"],
            "action": "remove",
            "removed": True,
            "restart_policy_changed": restart_policy_changed,
        }

    def _prepare_ephemeral_cleanup(
        self, target: EphemeralDockerContainerTarget
    ) -> tuple[dict[str, Any], bool]:
        """Prove identity and defeat restart drift before destructive cleanup."""

        before = self._docker_inspect_ephemeral_identity(target)
        if before["restart_policy"] == "no":
            return before, False
        full_id = str(before["full_container_id"])
        executable = self._docker_executable or _resolve_docker_executable()
        self._run_ephemeral_docker(
            (executable, "update", "--restart", "no", full_id),
            phase="restart_policy_update",
            outcome_may_have_changed=True,
        )
        after = self._docker_inspect_ephemeral_identity(target)
        if after["restart_policy"] != "no":
            raise BrokerBackendError(
                "ephemeral_docker_restart_policy_update_outcome_unknown",
                "Docker update returned but restart suppression was not proved "
                "for the exact ephemeral container.",
            )
        return after, True

    def compose_up(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "up")

    def compose_stop(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "stop")

    def compose_restart(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "restart")

    def compose_down(self, target: ComposeMutationTarget) -> Mapping[str, Any]:
        return self._compose(target, "down")

    def compose_run_once_bind_image(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(target)
        self._require_current_compose_model(target.compose)
        image_id = self._inspect_compose_run_once_image(target.service_image_ref)
        return {
            "image_ref": target.service_image_ref,
            "image_id": image_id,
        }

    def compose_run_once_find_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any] | None:
        _require_compose_run_once_target(target)
        executable = self._docker_executable or _resolve_docker_executable()
        command = (
            executable,
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            f"name=^/{target.container_name}$",
            "--format",
            "{{.ID}}",
        )
        completed = self._run_compose_run_once_docker(
            command,
            phase="container_lookup",
            timeout_seconds=self._docker_timeout_seconds,
        )
        identifiers = tuple(
            line.strip()
            for line in str(completed.stdout or "").splitlines()
            if line.strip()
        )
        if not identifiers:
            return None
        if (
            len(identifiers) != 1
            or re.fullmatch(r"[0-9a-fA-F]{64}", identifiers[0]) is None
        ):
            raise BrokerBackendError(
                "compose_run_once_container_ambiguous",
                "Compose run-once container name does not resolve to one immutable identity.",
            )
        return self.compose_run_once_inspect_container(
            target,
            full_container_id=identifiers[0].lower(),
        )

    def compose_run_once_create_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
        )
        existing = self.compose_run_once_find_container(target)
        if existing is not None:
            return existing
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            with _validated_compose_target(target.compose) as (
                compose_payloads,
                env_payloads,
                pinned_cwd,
            ):
                self._require_current_compose_model(
                    target.compose,
                    material=(compose_payloads, env_payloads, pinned_cwd),
                )
                current_image_id = self._inspect_compose_run_once_image(
                    target.service_image_ref
                )
                if current_image_id != target.expected_image_id:
                    raise BrokerBackendError(
                        "compose_run_once_image_binding_stale",
                        "Compose run-once image reference changed after immutable binding.",
                    )
                with _sealed_compose_input_snapshots(
                    compose_payloads=(
                        *compose_payloads,
                        _compose_isolation_override(
                            target.compose,
                            services=(target.service_name,),
                            immutable_images={
                                target.service_name: target.expected_image_id
                            },
                        ),
                    ),
                    env_payloads=env_payloads,
                    action="run_once_create",
                ) as (snapshot_compose_files, snapshot_env_files):
                    command: list[str] = [
                        executable,
                        "compose",
                        "--project-directory",
                        ".",
                        "--project-name",
                        target.compose.project_name,
                    ]
                    for env_file in snapshot_env_files:
                        command.extend(("--env-file", env_file))
                    for profile in target.compose.profiles:
                        command.extend(("--profile", profile))
                    for file_path in snapshot_compose_files:
                        command.extend(("--file", file_path))
                    command.extend(
                        (
                            "run",
                            "--no-deps",
                            "--no-TTY",
                            "--no-start",
                            "--name",
                            target.container_name,
                        )
                    )
                    for name, value in _compose_run_once_labels(target):
                        command.extend(("--label", f"{name}={value}"))
                    command.append(target.service_name)
                    try:
                        completed = self._compose_runner(
                            tuple(command),
                            pinned_cwd,
                            self._docker_timeout_seconds,
                            _bounded_compose_environment(executable),
                        )
                        if not isinstance(completed, subprocess.CompletedProcess):
                            raise TypeError(
                                "Compose runner returned an invalid result"
                            )
                        _require_bounded_ephemeral_output(completed.stdout)
                        _require_bounded_ephemeral_output(completed.stderr)
                    except Exception as exc:
                        raise BrokerBackendError(
                            "compose_run_once_create_unresolved",
                            "Compose one-shot container creation did not prove an exact outcome.",
                        ) from exc
                    if completed.returncode != 0:
                        raise BrokerBackendError(
                            "compose_run_once_create_unresolved",
                            "Compose one-shot container creation did not prove an exact outcome.",
                        )
        except ComposeMutationOutcomeUncertain as exc:
            raise BrokerBackendError(
                "compose_run_once_create_unresolved",
                "Compose one-shot input cleanup left container creation unresolved.",
            ) from exc
        created = self.compose_run_once_find_container(target)
        if created is None:
            raise BrokerBackendError(
                "compose_run_once_create_unresolved",
                "Compose reported success without one exact one-shot container.",
            )
        return created

    def compose_run_once_inspect_container(
        self,
        target: ComposeRunOnceMutationTarget,
        *,
        full_container_id: str | None = None,
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(target)
        container_id = (
            target.full_container_id
            if full_container_id is None
            else str(full_container_id).lower()
        )
        if container_id is None or re.fullmatch(
            r"[0-9a-f]{64}", container_id
        ) is None:
            raise ValueError("Compose run-once immutable container ID is invalid")
        executable = self._docker_executable or _resolve_docker_executable()
        template = "\n".join(
            (
                "{{.Id}}",
                "{{.Name}}",
                "{{.Image}}",
                "{{.State.Status}}",
                "{{.State.ExitCode}}",
                "{{.HostConfig.CgroupParent}}",
                "{{.HostConfig.Memory}}",
                "{{.HostConfig.NanoCpus}}",
                "{{.HostConfig.PidsLimit}}",
                "{{.HostConfig.RestartPolicy.Name}}",
                "{{.Config.OpenStdin}}",
                "{{.Config.Tty}}",
                *(
                    '{{index .Config.Labels "' + label + '"}}'
                    for label in _COMPOSE_RUN_ONCE_LABELS
                ),
            )
        )
        completed = self._run_compose_run_once_docker(
            (
                executable,
                "container",
                "inspect",
                "--format",
                template,
                container_id,
            ),
            phase="container_inspect",
            timeout_seconds=self._docker_timeout_seconds,
        )
        output = str(completed.stdout or "")
        if len(output.encode("utf-8")) > 16 * 1024:
            raise BrokerBackendError(
                "compose_run_once_container_unobservable",
                "Compose run-once container inspection was oversized.",
            )
        lines = output.rstrip("\n").split("\n")
        if len(lines) != 12 + len(_COMPOSE_RUN_ONCE_LABELS):
            raise BrokerBackendError(
                "compose_run_once_container_unobservable",
                "Compose run-once container inspection was incomplete.",
            )
        (
            observed_id,
            name,
            image_id,
            status,
            raw_exit_code,
            cgroup_parent,
            raw_memory,
            raw_nano_cpus,
            raw_pids_limit,
            restart_policy,
            raw_open_stdin,
            raw_tty,
            *raw_labels,
        ) = lines
        expected_labels = dict(_compose_run_once_labels(target))
        observed_labels = dict(zip(_COMPOSE_RUN_ONCE_LABELS, raw_labels))
        try:
            exit_code = int(raw_exit_code)
            memory_bytes = int(raw_memory)
            nano_cpus = int(raw_nano_cpus)
            pids_limit = int(raw_pids_limit)
        except ValueError as exc:
            raise BrokerBackendError(
                "compose_run_once_container_unobservable",
                "Compose run-once exit state is invalid.",
            ) from exc
        if (
            observed_id.lower() != container_id
            or name != "/" + target.container_name
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
            or status
            not in {
                "created",
                "running",
                "paused",
                "restarting",
                "removing",
                "exited",
                "dead",
            }
            or observed_labels != expected_labels
            or cgroup_parent
            != _project_slice(
                owner_uid=target.compose.owner_uid,
                repository_id=target.compose.repo_id,
            )
            or memory_bytes != 20 * 1024 * 1024 * 1024
            or nano_cpus != 8_000_000_000
            or pids_limit != _PROJECT_CONTAINER_PIDS_LIMIT
            or restart_policy != "no"
            or raw_open_stdin != "false"
            or raw_tty != "false"
            or (
                target.expected_image_id is not None
                and image_id != target.expected_image_id
            )
        ):
            raise BrokerBackendError(
                "compose_run_once_container_identity_mismatch",
                "Compose run-once container does not match its sealed identity.",
            )
        return {
            "full_container_id": container_id,
            "image_id": image_id,
            "status": status,
            "exit_code": exit_code,
        }

    def compose_run_once_start_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
            require_container_id=True,
        )
        before = self.compose_run_once_inspect_container(target)
        if before["status"] == "created":
            executable = self._docker_executable or _resolve_docker_executable()
            self._run_compose_run_once_docker(
                (executable, "start", str(target.full_container_id)),
                phase="container_start",
                timeout_seconds=self._docker_timeout_seconds,
                outcome_may_have_changed=True,
            )
            return self.compose_run_once_inspect_container(target)
        if before["status"] in {"running", "exited", "dead"}:
            return before
        raise BrokerBackendError(
            "compose_run_once_start_unresolved",
            "Compose run-once container is in an unsafe start state.",
        )

    def compose_run_once_wait_container(
        self,
        target: ComposeRunOnceMutationTarget,
        *,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
            require_container_id=True,
        )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < float(timeout_seconds) <= target.timeout_seconds
        ):
            raise ValueError("Compose run-once wait timeout is invalid")
        before = self.compose_run_once_inspect_container(target)
        if before["status"] in {"exited", "dead"}:
            return {"timed_out": False, **dict(before)}
        if before["status"] != "running":
            raise BrokerBackendError(
                "compose_run_once_wait_unresolved",
                "Compose run-once container is not in a waitable state.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            completed = self._docker_runner(
                (executable, "wait", str(target.full_container_id)),
                float(timeout_seconds),
            )
        except subprocess.TimeoutExpired:
            current = self.compose_run_once_inspect_container(target)
            return {"timed_out": True, **dict(current)}
        except Exception as exc:
            current = self.compose_run_once_inspect_container(target)
            if current["status"] in {"exited", "dead"}:
                return {"timed_out": False, **dict(current)}
            raise BrokerBackendError(
                "compose_run_once_wait_unresolved",
                "Compose run-once wait did not prove a terminal state.",
            ) from exc
        if completed.returncode != 0:
            current = self.compose_run_once_inspect_container(target)
            if current["status"] in {"exited", "dead"}:
                return {"timed_out": False, **dict(current)}
            raise BrokerBackendError(
                "compose_run_once_wait_unresolved",
                "Compose run-once wait did not prove a terminal state.",
            )
        current = self.compose_run_once_inspect_container(target)
        if current["status"] not in {"exited", "dead"}:
            raise BrokerBackendError(
                "compose_run_once_wait_unresolved",
                "Docker wait returned before the exact container became terminal.",
            )
        return {"timed_out": False, **dict(current)}

    def compose_run_once_stop_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
            require_container_id=True,
        )
        before = self.compose_run_once_inspect_container(target)
        if before["status"] in {"exited", "dead"}:
            return before
        if before["status"] not in {"running", "paused", "restarting"}:
            raise BrokerBackendError(
                "compose_run_once_stop_unresolved",
                "Compose run-once container is not in a stoppable state.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            self._run_compose_run_once_docker(
                (
                    executable,
                    "stop",
                    "--time",
                    "10",
                    str(target.full_container_id),
                ),
                phase="container_stop",
                timeout_seconds=min(self._docker_timeout_seconds, 30.0),
                outcome_may_have_changed=True,
            )
        except BrokerBackendError:
            current = self.compose_run_once_inspect_container(target)
            if current["status"] in {"exited", "dead"}:
                return current
            raise
        current = self.compose_run_once_inspect_container(target)
        if current["status"] not in {"exited", "dead"}:
            raise BrokerBackendError(
                "compose_run_once_stop_unresolved",
                "Compose run-once stop did not prove a terminal state.",
            )
        return current

    def compose_run_once_capture_evidence(
        self, target: ComposeRunOnceMutationTarget
    ) -> ComposeRunOnceOutputEvidence:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
            require_container_id=True,
        )
        current = self.compose_run_once_inspect_container(target)
        if current["status"] not in {"exited", "dead"}:
            raise BrokerBackendError(
                "compose_run_once_evidence_unavailable",
                "Compose run-once evidence requires a terminal exact container.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        return _capture_compose_run_once_logs(
            (
                executable,
                "logs",
                str(target.full_container_id),
            ),
            timeout_seconds=min(self._docker_timeout_seconds, 60.0),
            contract=target.receipt_contract,
            environment=_bounded_compose_environment(executable),
        )

    def compose_run_once_remove_container(
        self, target: ComposeRunOnceMutationTarget
    ) -> Mapping[str, Any]:
        _require_compose_run_once_target(
            target,
            require_image_id=True,
            require_container_id=True,
        )
        existing = self.compose_run_once_find_container(target)
        if existing is None:
            # Cleanup intent is already durable. Absence is the desired
            # terminal outcome and must be replayable after a broker crash
            # between Docker removal and the cleaned phase commit.
            return {
                "removed": True,
                "full_container_id": target.full_container_id,
            }
        if existing.get("full_container_id") != target.full_container_id:
            raise BrokerBackendError(
                "compose_run_once_remove_unresolved",
                "Compose run-once cleanup found a different container identity.",
            )
        executable = self._docker_executable or _resolve_docker_executable()
        try:
            self._run_compose_run_once_docker(
                (
                    executable,
                    "container",
                    "rm",
                    "--volumes",
                    str(target.full_container_id),
                ),
                phase="container_remove",
                timeout_seconds=self._docker_timeout_seconds,
                outcome_may_have_changed=True,
            )
        except BrokerBackendError:
            if self.compose_run_once_find_container(target) is None:
                return {
                    "removed": True,
                    "full_container_id": target.full_container_id,
                }
            raise
        if self.compose_run_once_find_container(target) is not None:
            raise BrokerBackendError(
                "compose_run_once_remove_unresolved",
                "Compose run-once cleanup did not prove container removal.",
            )
        return {
            "removed": True,
            "full_container_id": target.full_container_id,
        }

    def _require_current_compose_model(
        self,
        target: ComposeMutationTarget,
        *,
        material: tuple[tuple[bytes, ...], tuple[bytes, ...], str] | None = None,
    ) -> None:
        executable = self._docker_executable or _resolve_docker_executable()
        if material is None:
            with _validated_compose_target(target) as current_material:
                self._require_current_compose_model(
                    target,
                    material=current_material,
                )
            return
        compose_payloads, env_payloads, pinned_cwd = material
        renderer = self._compose_model_renderer
        renderer_arguments: dict[str, Any] = {
            "compose_payloads": compose_payloads,
            "env_payloads": env_payloads,
            "profiles": target.profiles,
            "declared_services": target.model_services,
            "project_name": target.project_name,
            "pinned_cwd": pinned_cwd,
            "docker_executable": executable,
        }
        if renderer is None:
            renderer = render_compose_effective_model
            renderer_arguments["runner"] = self._compose_runner
        rendered = renderer(**renderer_arguments)
        evidence = require_effective_compose_model(
            rendered,
            declared_services=target.model_services,
            declared_profiles=target.profiles,
            project_name=target.project_name,
            host_access_approved=target.effective_host_access_approved,
        )
        if (
            evidence.model_sha256 != target.effective_model_sha256
            or evidence.host_access_risks != target.effective_host_access_risks
            or evidence.service_replicas != target.model_service_replicas
            or evidence.service_images != target.model_service_images
        ):
            raise BrokerBackendError(
                "compose_effective_model_drift",
                "Docker Compose now renders a different effective model; rerun Coordinator skill installation.",
            )

    def _inspect_compose_run_once_image(self, image_ref: str) -> str:
        executable = self._docker_executable or _resolve_docker_executable()
        completed = self._run_compose_run_once_docker(
            (
                executable,
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                image_ref,
            ),
            phase="image_inspect",
            timeout_seconds=self._docker_timeout_seconds,
        )
        image_id = str(completed.stdout or "").strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
            raise BrokerBackendError(
                "compose_run_once_image_unobservable",
                "Compose run-once image reference did not resolve to one immutable image ID.",
            )
        return image_id

    def _run_compose_run_once_docker(
        self,
        command: tuple[str, ...],
        *,
        phase: str,
        timeout_seconds: float,
        outcome_may_have_changed: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        try:
            completed = self._docker_runner(command, timeout_seconds)
        except Exception as exc:
            suffix = "unresolved" if outcome_may_have_changed else "unavailable"
            raise BrokerBackendError(
                f"compose_run_once_{phase}_{suffix}",
                "Compose run-once Docker operation did not prove its exact outcome.",
            ) from exc
        try:
            if not isinstance(completed, subprocess.CompletedProcess):
                raise TypeError("Docker runner returned an invalid result")
            stdout = _require_bounded_ephemeral_output(completed.stdout)
            stderr = _require_bounded_ephemeral_output(completed.stderr)
        except (TypeError, ValueError) as exc:
            suffix = "unresolved" if outcome_may_have_changed else "unavailable"
            raise BrokerBackendError(
                f"compose_run_once_{phase}_{suffix}",
                "Compose run-once Docker operation returned invalid bounded evidence.",
            ) from exc
        if completed.returncode != 0:
            suffix = "unresolved" if outcome_may_have_changed else "unavailable"
            raise BrokerBackendError(
                f"compose_run_once_{phase}_{suffix}",
                "Compose run-once Docker operation did not prove its exact outcome.",
            )
        return subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            stdout,
            stderr,
        )

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
        cgroup_parent: str | None = None
        if action in {"start", "restart"}:
            cgroup_parent = _project_slice(
                owner_uid=target.owner_uid,
                repository_id=target.repo_id,
            )
            inspect_command = (
                executable,
                "inspect",
                "--format",
                "{{json .HostConfig.CgroupParent}}",
                full_id,
            )
            try:
                inspected = self._docker_runner(
                    inspect_command, self._docker_timeout_seconds
                )
                observed_parent = json.loads(str(inspected.stdout or "").strip())
            except Exception as exc:
                raise BrokerBackendError(
                    "project_isolation_unobservable",
                    "Docker cgroup attribution could not be proved before start.",
                ) from exc
            if (
                inspected.returncode != 0
                or not isinstance(observed_parent, str)
                or observed_parent != cgroup_parent
            ):
                raise BrokerBackendError(
                    "project_isolation_mismatch",
                    "Docker start was refused because the container is outside its repository cgroup.",
                )
        command = (executable, action, full_id)
        try:
            completed = self._docker_runner(command, self._docker_timeout_seconds)
        except Exception as exc:
            # Once the runner is invoked, neither an exception nor a CLI
            # failure proves that Docker did not accept the daemon request.
            # Keep diagnostics in service logs and require observation-based
            # reconciliation before the same durable operation can settle.
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Docker lifecycle did not prove a terminal outcome after invocation; authoritative reconciliation is required.",
            ) from exc
        if completed.returncode != 0:
            raise BrokerBackendError(
                "operation_outcome_uncertain",
                "Docker lifecycle did not prove a terminal outcome after invocation; authoritative reconciliation is required.",
            )
        return {
            "resource_id": target.docker_resource_id,
            "full_container_id": full_id,
            "action": action,
            "observation_revision": target.observation_revision,
            "control_generation": target.control_generation,
            "stdout": _bounded_output(completed.stdout),
            "cgroup_parent": cgroup_parent,
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
                    "declared_services": target.model_services,
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
                    declared_services=target.model_services,
                    declared_profiles=target.profiles,
                    project_name=target.project_name,
                    host_access_approved=target.effective_host_access_approved,
                )
                if (
                    runtime_evidence.model_sha256 != target.effective_model_sha256
                    or runtime_evidence.host_access_risks
                    != target.effective_host_access_risks
                    or runtime_evidence.service_replicas
                    != target.model_service_replicas
                    or runtime_evidence.service_images
                    != target.model_service_images
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
                    compose_payloads=(
                        *compose_payloads,
                        _compose_isolation_override(target),
                    ),
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
                            # Enrollment may retain ``build:`` as non-executed
                            # model metadata, but lifecycle control consumes
                            # only pre-existing images.  Both direct up and
                            # restart's start phase must therefore suppress
                            # Compose's implicit build path.
                            phase_command.append("--no-build")
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
                            _LOGGER.error(
                                "Compose host call failed action=%s phase=%s exception=%s",
                                action,
                                phase,
                                type(exc).__name__,
                            )
                            raise ComposeMutationOutcomeUncertain(
                                action=action,
                                failed_phase=phase,
                                completed_phases=tuple(completed_phases),
                            ) from exc
                        if completed.returncode != 0:
                            # Compose can echo interpolated secrets in
                            # diagnostics. Results never retain subprocess text;
                            # keep only non-sensitive operational metadata in
                            # the service journal for later reconciliation.
                            _LOGGER.error(
                                "Compose host call failed action=%s phase=%s returncode=%s stdout_bytes=%s stderr_bytes=%s",
                                action,
                                phase,
                                completed.returncode,
                                len(str(completed.stdout or "")),
                                len(str(completed.stderr or "")),
                            )
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

    def _run_ephemeral_image_inspect(
        self,
        command: tuple[str, ...],
        *,
        image_ref: str,
    ) -> subprocess.CompletedProcess[str] | None:
        """Inspect one exact image without exposing Docker diagnostics."""

        try:
            completed = self._docker_runner(command, self._docker_timeout_seconds)
        except Exception as error:
            _LOGGER.error(
                "ephemeral image inspect host call failed exception=%s",
                type(error).__name__,
            )
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "The service could not prove the exact sealed image cache state.",
            ) from error
        if not isinstance(completed, subprocess.CompletedProcess):
            _LOGGER.error("ephemeral image inspect returned invalid runner evidence")
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "The service could not prove the exact sealed image cache state.",
            )
        try:
            stdout = _require_bounded_ephemeral_output(completed.stdout)
            stderr = _require_bounded_ephemeral_output(completed.stderr)
        except (TypeError, ValueError) as error:
            _LOGGER.error(
                "ephemeral image inspect returned invalid bounded evidence exception=%s",
                type(error).__name__,
            )
            raise BrokerBackendError(
                "ephemeral_image_inspect_unobservable",
                "The service could not prove the exact sealed image cache state.",
            ) from error
        if completed.returncode == 0:
            return completed
        if stdout.strip() == "" and stderr.strip() in {
            f"Error response from daemon: No such image: {image_ref}",
            f"Error: No such image: {image_ref}",
        }:
            return None
        _LOGGER.error(
            "ephemeral image inspect failed returncode=%s stdout_bytes=%s stderr_bytes=%s",
            completed.returncode,
            len(stdout),
            len(stderr),
        )
        raise BrokerBackendError(
            "ephemeral_image_inspect_unobservable",
            "The service could not prove the exact sealed image cache state.",
        )

    def _run_ephemeral_docker(
        self,
        command: tuple[str, ...],
        *,
        phase: str,
        outcome_may_have_changed: bool,
    ) -> subprocess.CompletedProcess[str]:
        """Run one fixed-argv Docker operation with client-safe failures."""

        try:
            completed = self._docker_runner(command, self._docker_timeout_seconds)
        except Exception as exc:
            _LOGGER.error(
                "ephemeral Docker host call failed phase=%s outcome_may_have_changed=%s exception=%s",
                phase,
                outcome_may_have_changed,
                type(exc).__name__,
            )
            suffix = "outcome_unknown" if outcome_may_have_changed else "unobservable"
            raise BrokerBackendError(
                f"ephemeral_docker_{phase}_{suffix}",
                _ephemeral_failure_message(phase, outcome_may_have_changed),
            ) from exc
        if not isinstance(completed, subprocess.CompletedProcess):
            _LOGGER.error(
                "ephemeral Docker host call returned invalid evidence phase=%s outcome_may_have_changed=%s",
                phase,
                outcome_may_have_changed,
            )
            suffix = "outcome_unknown" if outcome_may_have_changed else "unobservable"
            raise BrokerBackendError(
                f"ephemeral_docker_{phase}_{suffix}",
                "The service-owned Docker runner returned invalid bounded evidence.",
            )
        try:
            _require_bounded_ephemeral_output(completed.stdout)
            _require_bounded_ephemeral_output(completed.stderr)
        except (TypeError, ValueError) as exc:
            _LOGGER.error(
                "ephemeral Docker host call returned oversized or invalid output phase=%s outcome_may_have_changed=%s exception=%s",
                phase,
                outcome_may_have_changed,
                type(exc).__name__,
            )
            suffix = "outcome_unknown" if outcome_may_have_changed else "unobservable"
            raise BrokerBackendError(
                f"ephemeral_docker_{phase}_{suffix}",
                "The service-owned Docker runner returned invalid bounded evidence.",
            ) from exc
        if completed.returncode != 0:
            _LOGGER.error(
                "ephemeral Docker host call failed phase=%s outcome_may_have_changed=%s returncode=%s",
                phase,
                outcome_may_have_changed,
                completed.returncode,
            )
            suffix = "outcome_unknown" if outcome_may_have_changed else "unobservable"
            raise BrokerBackendError(
                f"ephemeral_docker_{phase}_{suffix}",
                _ephemeral_failure_message(phase, outcome_may_have_changed),
            )
        return completed

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


_EPHEMERAL_LABEL_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_EPHEMERAL_CONTAINER_NAME = re.compile(
    r"^devcoordinator-[a-z0-9][a-z0-9_.-]{0,94}-[0-9a-f]{32}$"
)
_EPHEMERAL_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,511}$")
_EPHEMERAL_PINNED_IMAGE_REF = re.compile(
    r"^[a-z0-9][a-z0-9._/:+-]*@sha256:[0-9a-f]{64}$"
)
_EPHEMERAL_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_EPHEMERAL_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_EPHEMERAL_IMAGE_VOLUME_DESTINATION = re.compile(
    r"^/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}))*$"
)
_EPHEMERAL_ANONYMOUS_VOLUME_NAME = re.compile(r"[0-9a-f]{64}")
_MAX_EPHEMERAL_IMAGE_DECLARED_VOLUMES = 8
_EPHEMERAL_INSPECT_FIELDS = (
    "full_container_id",
    "status",
    "running",
    "restart_policy",
    "all_labels",
    "privileged",
    "binds",
    "mounts",
    "cap_add",
    "devices",
    "network_mode",
    "pid_mode",
    "state_pid",
    "networks",
)
_EPHEMERAL_INSPECT_FORMAT = "\t".join(
    (
        "{{json .Id}}",
        "{{json .State.Status}}",
        "{{json .State.Running}}",
        "{{json .HostConfig.RestartPolicy.Name}}",
        "{{json .Config.Labels}}",
        "{{json .HostConfig.Privileged}}",
        "{{json .HostConfig.Binds}}",
        # The realized container mount schema uses Destination/RW. The
        # HostConfig intent schema instead uses Target/ReadOnly and cannot
        # prove the sealed bind mount as Docker applied it.
        "{{json .Mounts}}",
        "{{json .HostConfig.CapAdd}}",
        "{{json .HostConfig.Devices}}",
        "{{json .HostConfig.NetworkMode}}",
        "{{json .HostConfig.PidMode}}",
        "{{json .State.Pid}}",
        "{{json .NetworkSettings.Networks}}",
    )
)


def _canonical_uuid(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"ephemeral Docker {field} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(
            f"ephemeral Docker {field} must be a canonical UUID"
        ) from exc
    if value != str(parsed):
        raise ValueError(f"ephemeral Docker {field} must be a canonical UUID")
    return value


def _validate_ephemeral_identity(
    identity: EphemeralDockerIdentity,
) -> tuple[tuple[str, str], ...]:
    if type(identity) is not EphemeralDockerIdentity:
        raise TypeError("ephemeral Docker identity must be a sealed typed value")
    run_id = _canonical_uuid(identity.run_id, field="run ID")
    creation_nonce = _canonical_uuid(
        identity.creation_nonce, field="creation nonce"
    )
    if creation_nonce == run_id:
        raise ValueError("ephemeral Docker creation nonce must be distinct")
    for field, value in (
        ("repository ID", identity.repository_id),
        ("template ID", identity.template_id),
    ):
        if (
            not isinstance(value, str)
            or _EPHEMERAL_LABEL_VALUE.fullmatch(value) is None
        ):
            raise ValueError(f"ephemeral Docker {field} is invalid")
    fingerprint = identity.definition_fingerprint
    if (
        not isinstance(fingerprint, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint) is None
    ):
        raise ValueError("ephemeral Docker definition fingerprint is invalid")
    return tuple(
        zip(
            EPHEMERAL_DOCKER_LABELS,
            (
                run_id,
                creation_nonce,
                identity.repository_id,
                identity.template_id,
                fingerprint,
            ),
        )
    )


def _validate_ephemeral_image_target(target: EphemeralImageTarget) -> str:
    """Accept only a persistence-resolved immutable Linux image identity."""

    if type(target) is not EphemeralImageTarget:
        raise TypeError("ephemeral image target must be a sealed typed value")
    if (
        not isinstance(target.template_id, str)
        or not target.template_id
        or not isinstance(target.repo_id, str)
        or not target.repo_id
        or not isinstance(target.image_ref, str)
        or _EPHEMERAL_PINNED_IMAGE_REF.fullmatch(target.image_ref) is None
        or not isinstance(target.template_fingerprint, str)
        or _EPHEMERAL_IMAGE_ID.fullmatch(target.template_fingerprint) is None
    ):
        raise ValueError("ephemeral image target is invalid")
    return target.image_ref


def _parse_ephemeral_image_inspection(
    output: Any, *, image_ref: str
) -> dict[str, Any]:
    """Validate Docker JSON against the exact sealed repository digest."""

    try:
        text = _require_bounded_ephemeral_output(output)
        decoded = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise BrokerBackendError(
            "ephemeral_image_inspect_unobservable",
            "The service did not return valid exact image cache evidence.",
        ) from error
    if not isinstance(decoded, dict):
        raise BrokerBackendError(
            "ephemeral_image_inspect_unobservable",
            "The service did not return valid exact image cache evidence.",
        )
    image_id = decoded.get("Id")
    repo_digests = decoded.get("RepoDigests")
    if (
        not isinstance(image_id, str)
        or _EPHEMERAL_IMAGE_ID.fullmatch(image_id) is None
        or not isinstance(repo_digests, list)
        or any(not isinstance(item, str) for item in repo_digests)
        or image_ref not in repo_digests
        or decoded.get("Os") != "linux"
        or decoded.get("Architecture") != "amd64"
    ):
        raise BrokerBackendError(
            "ephemeral_image_inspect_unobservable",
            "The service did not prove the exact sealed image cache identity.",
        )
    return {
        "cached": True,
        "image_ref": image_ref,
        "image_id": image_id,
        "repo_digest": image_ref,
        "os": "linux",
        "architecture": "amd64",
    }


def _parse_ephemeral_image_volume_destinations(output: Any) -> tuple[str, ...]:
    """Read only bounded declared-volume destinations from proven image JSON."""

    try:
        decoded = json.loads(_require_bounded_ephemeral_output(output))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise BrokerBackendError(
            "ephemeral_docker_safety_profile_mismatch",
            "Docker profile evidence did not expose a valid image-volume declaration.",
        ) from error
    config = decoded.get("Config") if isinstance(decoded, Mapping) else None
    if not isinstance(config, Mapping):
        raise BrokerBackendError(
            "ephemeral_docker_safety_profile_mismatch",
            "Docker profile evidence did not expose a valid image-volume declaration.",
        )
    declared = config.get("Volumes")
    if declared is None:
        return ()
    if (
        not isinstance(declared, Mapping)
        or len(declared) > _MAX_EPHEMERAL_IMAGE_DECLARED_VOLUMES
    ):
        raise BrokerBackendError(
            "ephemeral_docker_safety_profile_mismatch",
            "Docker profile evidence has an invalid image-volume declaration.",
        )
    destinations: list[str] = []
    for destination, options in declared.items():
        if (
            not isinstance(destination, str)
            or len(destination.encode("utf-8")) > 256
            or _EPHEMERAL_IMAGE_VOLUME_DESTINATION.fullmatch(destination) is None
            or options != {}
        ):
            raise BrokerBackendError(
                "ephemeral_docker_safety_profile_mismatch",
                "Docker profile evidence has an invalid image-volume declaration.",
            )
        destinations.append(destination)
    return tuple(sorted(destinations))


def _contains_volume_mount(value: object) -> bool:
    return isinstance(value, list) and any(
        isinstance(item, Mapping) and item.get("Type") == "volume" for item in value
    )


def _normalize_cpu_limit(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, float)):
        raise ValueError("ephemeral Docker CPU limit must be a decimal value")
    if isinstance(value, str) and (
        not value or value != value.strip() or len(value) > 32
    ):
        raise ValueError("ephemeral Docker CPU limit must be a decimal value")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(
            "ephemeral Docker CPU limit must be a decimal value"
        ) from exc
    if not decimal_value.is_finite() or decimal_value <= 0 or decimal_value > 1024:
        raise ValueError("ephemeral Docker CPU limit is outside the safe range")
    normalized = format(decimal_value.normalize(), "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return normalized


def _validate_ephemeral_create_target(
    target: EphemeralDockerCreateTarget,
) -> dict[str, Any]:
    if type(target) is not EphemeralDockerCreateTarget:
        raise TypeError("ephemeral Docker create target must be a sealed typed value")
    if type(target.owner_uid) is not int or target.owner_uid <= 0:
        raise ValueError("ephemeral Docker owner UID must be a non-root account")
    labels = _validate_ephemeral_identity(target.identity)
    expected_suffix = "-" + uuid.UUID(target.identity.run_id).hex
    if (
        not isinstance(target.container_name, str)
        or _EPHEMERAL_CONTAINER_NAME.fullmatch(target.container_name) is None
        or not target.container_name.endswith(expected_suffix)
    ):
        raise ValueError("ephemeral Docker container name is invalid")
    if (
        not isinstance(target.image_ref, str)
        or _EPHEMERAL_IMAGE_REF.fullmatch(target.image_ref) is None
    ):
        raise ValueError("ephemeral Docker image reference is invalid")
    if (
        type(target.command) is not tuple
        or len(target.command) > 256
        or any(
            not isinstance(item, str)
            or "\x00" in item
            or len(item.encode("utf-8")) > 4096
            for item in target.command
        )
        or sum(len(item.encode("utf-8")) for item in target.command) > 128 * 1024
    ):
        raise ValueError("ephemeral Docker command is invalid or oversized")
    if type(target.environment) is not tuple or len(target.environment) > 256:
        raise ValueError("ephemeral Docker environment is invalid or oversized")
    environment: list[tuple[str, str]] = []
    seen_names: set[str] = set()
    total_environment_bytes = 0
    for item in target.environment:
        if (
            type(item) is not tuple
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or _EPHEMERAL_ENVIRONMENT_NAME.fullmatch(item[0]) is None
            or any(character in item[1] for character in ("\x00", "\r", "\n"))
            or len(item[1].encode("utf-8")) > 16 * 1024
            or item[0] in seen_names
        ):
            raise ValueError("ephemeral Docker environment is invalid or oversized")
        seen_names.add(item[0])
        total_environment_bytes += len(item[0].encode("utf-8")) + 1 + len(
            item[1].encode("utf-8")
        )
        environment.append(item)
    if total_environment_bytes > 128 * 1024:
        raise ValueError("ephemeral Docker environment is invalid or oversized")
    if (
        type(target.memory_bytes) is not int
        or not 4 * 1024 * 1024 <= target.memory_bytes <= 1 << 50
    ):
        raise ValueError("ephemeral Docker memory limit is outside the safe range")
    if (target.host_tcp_port is None) != (target.container_tcp_port is None):
        raise ValueError("ephemeral Docker TCP mapping must be complete")
    for value in (target.host_tcp_port, target.container_tcp_port):
        if value is not None and (type(value) is not int or not 1 <= value <= 65535):
            raise ValueError("ephemeral Docker TCP mapping is invalid")
    if target.network_container_id is not None:
        if (
            not _is_full_container_id(target.network_container_id)
            or target.host_tcp_port is not None
        ):
            raise ValueError("ephemeral Docker shared network target is invalid")
    secret_mount = _validate_ephemeral_secret_mount(
        target.secret_mount, require_material=True
    )
    environment_payload = b"".join(
        name.encode("utf-8") + b"=" + value.encode("utf-8") + b"\n"
        for name, value in environment
    )
    return {
        "labels": labels,
        "cpu_limit": _normalize_cpu_limit(target.cpu_limit),
        "environment_payload": environment_payload,
        "secret_mount": secret_mount,
    }


def _is_full_container_id(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_ephemeral_container_target(
    target: EphemeralDockerContainerTarget,
) -> tuple[str, tuple[tuple[str, str], ...]]:
    if type(target) is not EphemeralDockerContainerTarget:
        raise TypeError("ephemeral Docker container target must be a sealed typed value")
    labels = _validate_ephemeral_identity(target.identity)
    full_id = target.full_container_id
    if not _is_full_container_id(full_id):
        raise ValueError(
            "ephemeral Docker container target requires a lowercase immutable ID"
        )
    if target.network_container_id is not None and not _is_full_container_id(
        target.network_container_id
    ):
        raise ValueError("ephemeral Docker shared network identity is invalid")
    return full_id, labels


def _validate_ephemeral_secret_mount(
    value: EphemeralSecretMount | None, *, require_material: bool
) -> EphemeralSecretMount | None:
    """Accept only the manager's one read-only PostgreSQL password directory."""

    if value is None:
        return None
    if type(value) is not EphemeralSecretMount:
        raise TypeError("ephemeral Docker secret mount must be a sealed typed value")
    if (
        not value.source_directory.is_absolute()
        or value.container_directory != "/run/devcoordinator-credentials"
        or value.filename != "postgres-initdb-password"
        or value.environment
        != (("POSTGRES_PASSWORD_FILE", value.container_password_path),)
    ):
        raise ValueError("ephemeral Docker secret mount is invalid")
    if not require_material:
        return value
    try:
        directory = value.source_directory.lstat()
        password = (value.source_directory / value.filename).lstat()
    except OSError as exc:
        raise BrokerBackendError(
            "secret_delivery_unavailable",
            "The broker-owned PostgreSQL credential file is unavailable.",
        ) from exc
    if (
        stat.S_ISLNK(directory.st_mode)
        or not stat.S_ISDIR(directory.st_mode)
        or stat.S_ISLNK(password.st_mode)
        or not stat.S_ISREG(password.st_mode)
    ):
        raise BrokerBackendError(
            "secret_delivery_unavailable",
            "The local PostgreSQL credential path has an invalid file type.",
        )
    return value


def _require_bounded_ephemeral_output(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("ephemeral Docker output must be text")
    if len(value.encode("utf-8")) > 64 * 1024:
        raise ValueError("ephemeral Docker output exceeded its fixed bound")
    return value


def _require_exact_container_id_output(value: Any) -> str:
    output = _require_bounded_ephemeral_output(value).strip()
    if not _is_full_container_id(output):
        raise BrokerBackendError(
            "ephemeral_docker_create_outcome_unknown",
            "Docker create did not return one immutable container identity.",
        )
    return output


def _parse_ephemeral_inspection(value: Any) -> dict[str, Any]:
    output = _require_bounded_ephemeral_output(value).strip()
    parts = output.split("\t")
    if len(parts) != len(_EPHEMERAL_INSPECT_FIELDS):
        raise BrokerBackendError(
            "ephemeral_docker_inspect_unobservable",
            "Docker inspect returned invalid bounded identity evidence.",
        )
    try:
        decoded = [json.loads(item) for item in parts]
    except (json.JSONDecodeError, TypeError) as exc:
        raise BrokerBackendError(
            "ephemeral_docker_inspect_unobservable",
            "Docker inspect returned invalid bounded identity evidence.",
        ) from exc
    evidence = dict(zip(_EPHEMERAL_INSPECT_FIELDS, decoded))
    if (
        not _is_full_container_id(evidence["full_container_id"])
        or not isinstance(evidence["status"], str)
        or type(evidence["running"]) is not bool
        or not isinstance(evidence["restart_policy"], str)
        or not isinstance(evidence["all_labels"], dict)
        or type(evidence["privileged"]) is not bool
        or not isinstance(evidence["network_mode"], str)
        or type(evidence["state_pid"]) is not int
        or evidence["state_pid"] < 0
        or not isinstance(evidence["networks"], dict)
    ):
        raise BrokerBackendError(
            "ephemeral_docker_inspect_unobservable",
            "Docker inspect returned invalid bounded identity evidence.",
        )
    return evidence


def _require_ephemeral_safe_profile(
    evidence: Mapping[str, Any],
    *,
    secret_mount: EphemeralSecretMount | None,
    image_volume_destinations: tuple[str, ...] = (),
    expected_network_mode: str = "bridge",
) -> None:
    mounts_safe = _sealed_ephemeral_mounts_safe(
        evidence["mounts"],
        secret_mount=secret_mount,
        image_volume_destinations=image_volume_destinations,
    )
    if (
        evidence["restart_policy"] != "no"
        or evidence["privileged"] is not False
        or evidence["binds"] not in (None, [])
        or not mounts_safe
        or evidence["cap_add"] not in (None, [])
        or evidence["devices"] not in (None, [])
        or evidence["network_mode"] != expected_network_mode
        or evidence["pid_mode"] not in ("", None)
    ):
        raise BrokerBackendError(
            "ephemeral_docker_safety_profile_mismatch",
            "Docker inspect did not prove the sealed unprivileged "
            "ephemeral-container profile.",
        )


def _sealed_ephemeral_mounts_safe(
    value: object,
    *,
    secret_mount: EphemeralSecretMount | None,
    image_volume_destinations: tuple[str, ...],
) -> bool:
    """Accept only exact broker bind material plus image-created volumes."""

    if value is None:
        mounts: tuple[Mapping[str, Any], ...] = ()
    elif isinstance(value, list) and all(isinstance(item, Mapping) for item in value):
        mounts = tuple(value)
    else:
        return False
    if (
        type(image_volume_destinations) is not tuple
        or len(image_volume_destinations) > _MAX_EPHEMERAL_IMAGE_DECLARED_VOLUMES
        or len(set(image_volume_destinations)) != len(image_volume_destinations)
        or any(
            not isinstance(destination, str)
            or _EPHEMERAL_IMAGE_VOLUME_DESTINATION.fullmatch(destination) is None
            for destination in image_volume_destinations
        )
        or (
            secret_mount is not None
            and secret_mount.container_directory in image_volume_destinations
        )
    ):
        return False
    expected_count = len(image_volume_destinations) + (secret_mount is not None)
    if len(mounts) != expected_count:
        return False
    used: set[int] = set()
    if secret_mount is not None:
        matches = [
            index
            for index, mount in enumerate(mounts)
            if _matches_ephemeral_secret_mount(mount, secret_mount)
        ]
        if len(matches) != 1:
            return False
        used.add(matches[0])
    for destination in image_volume_destinations:
        matches = [
            index
            for index, mount in enumerate(mounts)
            if index not in used
            and _matches_ephemeral_anonymous_volume(mount, destination)
        ]
        if len(matches) != 1:
            return False
        used.add(matches[0])
    return len(used) == len(mounts)


def _matches_ephemeral_secret_mount(
    mount: Mapping[str, Any], secret_mount: EphemeralSecretMount
) -> bool:
    return (
        mount.get("Type") == "bind"
        and mount.get("Source") == str(secret_mount.source_directory)
        and mount.get("Destination") == secret_mount.container_directory
        and mount.get("RW") is False
    )


def _matches_ephemeral_anonymous_volume(
    mount: Mapping[str, Any], destination: str
) -> bool:
    name = mount.get("Name")
    source = mount.get("Source")
    return (
        mount.get("Type") == "volume"
        and isinstance(name, str)
        and _EPHEMERAL_ANONYMOUS_VOLUME_NAME.fullmatch(name) is not None
        and isinstance(source, str)
        and source.endswith("/volumes/" + name + "/_data")
        and mount.get("Destination") == destination
        and mount.get("Driver") == "local"
        and mount.get("RW") is True
    )


def _ephemeral_public_observation(
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Return bounded lifecycle evidence without exposing drifted host paths."""

    return {
        "full_container_id": evidence["full_container_id"],
        "status": evidence["status"],
        "running": evidence["running"],
        "restart_policy": evidence["restart_policy"],
        "labels": dict(evidence["labels"]),
    }


def _ephemeral_failure_message(phase: str, outcome_may_have_changed: bool) -> str:
    if outcome_may_have_changed:
        return (
            f"The service-owned Docker {phase} operation did not prove its host "
            "outcome; reconciliation by persisted labels is required."
        )
    return (
        f"The service-owned Docker {phase} observation did not return valid "
        "bounded evidence."
    )


def _ephemeral_environment_cleanup_failure(
    body_error: BaseException | None,
    *,
    body_completed: bool,
) -> BrokerBackendError:
    cleanup_message = "The private ephemeral Docker environment also could not be removed."
    if isinstance(body_error, BrokerBackendError):
        return BrokerBackendError(
            body_error.code + "_and_environment_cleanup_failed",
            body_error.message + " " + cleanup_message,
        )
    if body_error is not None:
        return BrokerBackendError(
            "ephemeral_docker_operation_and_environment_cleanup_failed",
            "The ephemeral Docker operation failed. " + cleanup_message,
        )
    if body_completed:
        return BrokerBackendError(
            "ephemeral_docker_create_outcome_unknown_and_environment_cleanup_failed",
            "Docker create may have produced a stopped container. " + cleanup_message,
        )
    return BrokerBackendError(
        "ephemeral_docker_environment_cleanup_failed",
        "The private ephemeral Docker environment could not be removed.",
    )


@contextlib.contextmanager
def _sealed_ephemeral_environment(payload: bytes) -> Iterator[str]:
    """Expose bounded environment values without placing them in process argv."""

    if not isinstance(payload, bytes) or len(payload) > 128 * 1024:
        raise ValueError("ephemeral Docker environment payload is invalid")
    if hasattr(os, "memfd_create") and Path("/proc/self/fd").is_dir():
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        descriptor = os.memfd_create("devcoordinator-ephemeral-env", flags)
        body_error: BaseException | None = None
        body_completed = False
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("sealed ephemeral environment write made no progress")
                view = view[written:]
            os.lseek(descriptor, 0, os.SEEK_SET)
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0)
                | getattr(fcntl, "F_SEAL_SHRINK", 0)
                | getattr(fcntl, "F_SEAL_GROW", 0)
                | getattr(fcntl, "F_SEAL_WRITE", 0)
            )
            if not seals or not hasattr(fcntl, "F_ADD_SEALS"):
                raise RuntimeError("Linux ephemeral environment sealing is unavailable")
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            yield f"/proc/{os.getpid()}/fd/{descriptor}"
            body_completed = True
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            try:
                os.close(descriptor)
            except OSError as cleanup_error:
                raise _ephemeral_environment_cleanup_failure(
                    body_error,
                    body_completed=body_completed,
                ) from (body_error or cleanup_error)
        return

    directory = Path(tempfile.mkdtemp(prefix="devcoordinator-ephemeral-env-"))
    os.chmod(directory, 0o700)
    path = directory / "environment"
    descriptor = -1
    body_error: BaseException | None = None
    body_completed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private ephemeral environment write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        yield str(path)
        body_completed = True
    except BaseException as exc:
        body_error = exc
        raise
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        cleanup_error: OSError | None = None
        try:
            path.unlink(missing_ok=True)
            directory.rmdir()
        except OSError as exc:
            cleanup_error = exc
        if cleanup_error is not None:
            failure = _ephemeral_environment_cleanup_failure(
                body_error,
                body_completed=body_completed,
            )
            if body_error is not None:
                raise failure from body_error
            raise failure from cleanup_error


_COMPOSE_PROJECT_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_COMPOSE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_COMPOSE_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _require_compose_run_once_target(
    target: ComposeRunOnceMutationTarget,
    *,
    require_image_id: bool = False,
    require_container_id: bool = False,
) -> None:
    if not isinstance(target, ComposeRunOnceMutationTarget):
        raise TypeError("Compose run-once target must be a persisted typed target")
    try:
        canonical_operation_id = str(uuid.UUID(target.operation_id))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Compose run-once operation ID is invalid") from exc
    expected_name = "devcoordinator-once-" + canonical_operation_id.replace("-", "")
    policy = next(
        (
            item
            for item in target.compose.run_once_policies
            if item.name == target.service_name
        ),
        None,
    )
    if (
        policy is None
        or policy.fingerprint != target.policy_fingerprint
        or policy.receipt != target.receipt_contract
        or target.timeout_seconds > policy.max_timeout_seconds
        or target.container_name != expected_name
        or dict(target.compose.model_service_images).get(target.service_name)
        != target.service_image_ref
        or not 1 <= target.timeout_seconds <= 3_600
        or type(target.deadline_epoch) is not int
        or target.deadline_epoch <= 0
    ):
        raise ValueError("Compose run-once target does not match its sealed policy")
    if require_image_id and (
        not isinstance(target.expected_image_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", target.expected_image_id) is None
    ):
        raise ValueError("Compose run-once target lacks an immutable image ID")
    if require_container_id and (
        not isinstance(target.full_container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", target.full_container_id) is None
    ):
        raise ValueError("Compose run-once target lacks an immutable container ID")


def _compose_run_once_labels(
    target: ComposeRunOnceMutationTarget,
) -> tuple[tuple[str, str], ...]:
    _require_compose_run_once_target(target, require_image_id=True)
    values = (
        target.operation_id,
        target.compose.repo_id,
        target.compose.compose_definition_id,
        target.service_name,
        target.policy_fingerprint,
        str(target.expected_image_id),
    )
    if any(
        not value
        or "\x00" in value
        or "\n" in value
        or len(value.encode("utf-8")) > 512
        for value in values
    ):
        raise ValueError("Compose run-once label value is invalid")
    return tuple(zip(_COMPOSE_RUN_ONCE_LABELS, values))


@dataclass
class _StreamDigest:
    digest: Any
    byte_size: int
    capture: bytearray
    capture_limit: int
    error: BaseException | None = None


def _capture_compose_run_once_logs(
    command: tuple[str, ...],
    *,
    timeout_seconds: float,
    contract: Any,
    environment: Mapping[str, str],
) -> ComposeRunOnceOutputEvidence:
    """Hash complete streams while retaining only a bounded receipt candidate."""

    if (
        not command
        or not 0 < timeout_seconds <= 60
        or not isinstance(environment, Mapping)
        or any(
            not isinstance(name, str)
            or not isinstance(value, str)
            or "\x00" in name
            or "\x00" in value
            for name, value in environment.items()
        )
    ):
        raise ValueError("Compose run-once log capture arguments are invalid")
    stdout_state = _StreamDigest(
        hashlib.sha256(),
        0,
        bytearray(),
        MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES + 1,
    )
    stderr_state = _StreamDigest(hashlib.sha256(), 0, bytearray(), 0)
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            close_fds=True,
            env=dict(environment),
        )
    except Exception as exc:
        raise BrokerBackendError(
            "compose_run_once_evidence_unavailable",
            "Compose run-once logs could not be opened for bounded capture.",
        ) from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise BrokerBackendError(
            "compose_run_once_evidence_unavailable",
            "Compose run-once log pipes are unavailable.",
        )

    def drain(stream: Any, state: _StreamDigest) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                if not isinstance(chunk, bytes):
                    raise TypeError("log stream returned text")
                state.digest.update(chunk)
                state.byte_size += len(chunk)
                remaining = state.capture_limit - len(state.capture)
                if remaining > 0:
                    state.capture.extend(chunk[:remaining])
        except BaseException as exc:
            state.error = exc
        finally:
            with contextlib.suppress(Exception):
                stream.close()

    stdout_thread = threading.Thread(
        target=drain,
        args=(process.stdout, stdout_state),
        name="compose-run-once-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr, stderr_state),
        name="compose-run-once-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        with contextlib.suppress(Exception):
            process.wait(timeout=5)
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        raise BrokerBackendError(
            "compose_run_once_evidence_unavailable",
            "Compose run-once log capture exceeded its bounded timeout.",
        ) from exc
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if (
        stdout_thread.is_alive()
        or stderr_thread.is_alive()
        or stdout_state.error is not None
        or stderr_state.error is not None
        or return_code != 0
    ):
        raise BrokerBackendError(
            "compose_run_once_evidence_unavailable",
            "Compose run-once logs did not produce complete bounded evidence.",
        )
    truncated = (
        stdout_state.byte_size > MAX_COMPOSE_RUN_ONCE_RECEIPT_BYTES
    )
    published = validate_published_receipt(
        bytes(stdout_state.capture),
        contract=contract,
        truncated=truncated,
    )
    return ComposeRunOnceOutputEvidence(
        published_receipt=published,
        stdout_sha256="sha256:" + stdout_state.digest.hexdigest(),
        stdout_byte_size=stdout_state.byte_size,
        stderr_sha256="sha256:" + stderr_state.digest.hexdigest(),
        stderr_byte_size=stderr_state.byte_size,
    )


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
    expected_model_services = tuple(
        sorted(
            (
                *target.services,
                *(policy.name for policy in target.run_once_policies),
            )
        )
    )
    if (
        target.model_services != expected_model_services
        or any(
            _COMPOSE_SERVICE_NAME.fullmatch(item) is None
            for item in target.model_services
        )
        or tuple(name for name, _count in target.model_service_replicas)
        != target.model_services
        or not set(dict(target.model_service_images)) <= set(target.model_services)
        or any(
            policy.name not in dict(target.model_service_images)
            for policy in target.run_once_policies
        )
    ):
        raise ValueError("Compose target merged service evidence is invalid")
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
        fingerprint_document: dict[str, Any] = {
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
        }
        if target.run_once_policies:
            fingerprint_document["run_once_services"] = (
                compose_run_once_policies_document(target.run_once_policies)
            )
        encoded = json.dumps(
            fingerprint_document,
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
        pinned_cwd = stable_compose_descriptor_path(cwd_descriptor)
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
        # Enrollment needs the effective service graph and host-capability
        # shape, not project secrets.  Keep variable expressions opaque so a
        # repository can be enrolled and observed even when role-specific
        # runtime values are injected only by its actual launcher.
        command.extend(("config", "--no-interpolate", "--format", "json"))
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
    """Prove one exact TCP listener runs from the enrolled worktree.

    The broker service—not the client—performs both listener and cwd
    observation. A missing tool, multiple listeners, PID reuse, zombie, or
    path ambiguity is an unknown resource identity and fails closed. Unix
    ownership metadata is deliberately not part of local authorization.
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
    cwd = _process_cwd(lsof, pid)
    if os.path.commonpath((cwd, root)) != root:
        raise BrokerBackendError(
            "listener_project_mismatch",
            "The existing listener belongs to another repository.",
        )
    identity_after = _process_identity(pid)
    second = _platform_listener_pids(port, lsof=lsof)
    if identity_before != identity_after or second != {pid}:
        raise BrokerBackendError(
            "listener_identity_changed",
            "The existing listener identity changed during broker verification.",
        )
    return {
        "pid": pid,
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
        "The broker service cannot observe listener identity because lsof is unavailable.",
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
