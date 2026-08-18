"""Broker-owned transient runtime boundary for universal test attempts.

The test scheduler never invokes systemd or a project command.  It submits a
generation-fenced descriptor to the root broker.  This module validates and
retains that descriptor, starts one transient unit as the repository owner,
and exposes only bounded observation/cancellation evidence back to testd.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field, replace
import base64
import hashlib
import json
import logging
import math
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import time
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable
import uuid
import zipfile

from .universal_test_artifacts import package_directory
from .universal_test_contract import (
    NON_AUTHORITATIVE_RESOURCES,
    deterministic_fingerprint,
)
from .universal_test_repository_binding import (
    publish_immutable_repository_binding,
)
from .universal_test_snapshot import (
    nuget_locked_package_source_paths,
    nuget_locked_package_requirements,
    nuget_package_archive_file_digests,
    nuget_package_metadata_content_hash,
    nuget_package_sha512_digest,
    snapshot_regular_file_digest,
)
from .universal_test_store import TestStoreConflict, TestStoreContractError


_LOGGER = logging.getLogger(__name__)


MAX_TEST_ATTEMPT_TTL_SECONDS = 7 * 24 * 60 * 60
# The repository process still receives the exact requested TTL.  The native
# unit needs a bounded publication margin so the runner can write and fsync its
# terminal result after stopping a child at that deadline.
TEST_ATTEMPT_RESULT_PUBLICATION_GRACE_SECONDS = 30
MAX_TEST_ATTEMPT_ARGUMENTS = 256
MAX_TEST_ATTEMPT_ARGUMENT_BYTES = 32 * 1024
MAX_TEST_ATTEMPT_ENVIRONMENT = 128
TEST_ATTEMPT_ACCOUNT_ID = "devcoordinator-testd"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL)(?:_|$)"
)
_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "env",
    }
)
_SYSTEMD_BIND_PATH = re.compile(r"^/[A-Za-z0-9_./@+\-]+$")
_OPERATIONAL_CREDENTIAL_ALIAS = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_ENVIRONMENT_NAMES = frozenset({".venv-v2", ".venv", "venv"})
_IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT = Path(
    "/tmp/devcoordinator-immutable-python-toolchain"
)
_SYSTEM_PYTHON_TOOLCHAIN_ROOTS = frozenset({Path("/usr"), Path("/usr/local")})
_DOTNET_PACKAGES_DESTINATION = ".devcoordinator-dependencies/nuget-source"
_MAX_DEPENDENCY_IDENTITY_BYTES = 64 * 1024 * 1024
_MAX_DEPENDENCY_IDENTITY_FILES = 8_192
_MAX_NUGET_SOURCE_IDENTITY_BYTES = (1 << 63) - 1
_DEPENDENCY_BINDING_KINDS = frozenset(
    {"python-venv", "node-modules", "dotnet-packages"}
)


def _safe_fixture_provider_failure(error: BaseException) -> str:
    """Project one trusted typed host failure without exposing raw exceptions."""

    code = getattr(error, "code", None)
    message = getattr(error, "message", None)
    if (
        isinstance(code, str)
        and _SAFE_ID.fullmatch(code) is not None
        and isinstance(message, str)
        and message
        and len(message.encode("utf-8")) <= 1024
        and not any(character in message for character in "\x00\r\n")
    ):
        return f"{code}: {message}"
    return type(error).__name__


_INSTALLATION_MANIFEST_KINDS = frozenset(
    {
        "python-dist-info",
        "python-toolchain",
        "dotnet-toolchain",
        "node-package-lock",
        "nuget-package-source",
    }
)


class TestAttemptRuntimeNotFound(TestStoreConflict):
    """The exact native attempt has neither retained launch evidence nor a unit.

    This narrow type is intentionally distinct from a generic contract error.
    A caller may use it only as the first half of an absence proof, followed by
    a fresh native status observation that confirms the exact deterministic
    runtime is both unloaded and inactive.
    """


class TestAttemptLaunchUncertain(TestStoreConflict):
    """A replay cannot yet prove whether the deterministic runtime started."""


def _runtime_id_for_attempt(attempt_id: object) -> str:
    normalized = _safe_id("attempt_id", attempt_id)
    suffix = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]
    return "devcoordinator-test-" + suffix


def _validated_peak_memory_bytes(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise TestStoreContractError("test peak memory measurement is invalid")
    return value


def _validated_cpu_seconds(value: object) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
        or float(value) > 31_536_000
    ):
        raise TestStoreContractError("test CPU measurement is invalid")
    return float(value)


def _validated_output_progress(
    value: object,
) -> Mapping[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "stdout_bytes",
        "stderr_bytes",
        "stdout_retained_bytes",
        "stderr_retained_bytes",
        "stdout_truncated",
        "stderr_truncated",
        "last_output_at",
        "observed_at",
    }:
        raise TestStoreContractError("test output progress fields are invalid")
    stdout_bytes = value["stdout_bytes"]
    stderr_bytes = value["stderr_bytes"]
    stdout_retained_bytes = value["stdout_retained_bytes"]
    stderr_retained_bytes = value["stderr_retained_bytes"]
    stdout_truncated = value["stdout_truncated"]
    stderr_truncated = value["stderr_truncated"]
    last_output_at = value["last_output_at"]
    observed_at = value["observed_at"]
    if (
        type(stdout_bytes) is not int
        or type(stderr_bytes) is not int
        or not 0 <= stdout_bytes <= (1 << 63) - 1
        or not 0 <= stderr_bytes <= (1 << 63) - 1
        or type(stdout_retained_bytes) is not int
        or type(stderr_retained_bytes) is not int
        or not 0 <= stdout_retained_bytes <= 4 * 1024 * 1024
        or not 0 <= stderr_retained_bytes <= 4 * 1024 * 1024
        or type(stdout_truncated) is not bool
        or type(stderr_truncated) is not bool
        or stdout_retained_bytes > stdout_bytes
        or stderr_retained_bytes > stderr_bytes
        or stdout_truncated != (stdout_bytes > stdout_retained_bytes)
        or stderr_truncated != (stderr_bytes > stderr_retained_bytes)
        or isinstance(observed_at, bool)
        or not isinstance(observed_at, (int, float))
        or not math.isfinite(float(observed_at))
        or float(observed_at) < 0
        or (
            last_output_at is not None
            and (
                isinstance(last_output_at, bool)
                or not isinstance(last_output_at, (int, float))
                or not math.isfinite(float(last_output_at))
                or float(last_output_at) < 0
            )
        )
    ):
        raise TestStoreContractError("test output progress is invalid")
    return {
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_retained_bytes": stdout_retained_bytes,
        "stderr_retained_bytes": stderr_retained_bytes,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "last_output_at": (
            None if last_output_at is None else float(last_output_at)
        ),
        "observed_at": float(observed_at),
    }


def _systemd_counter(value: str | None, *, field: str) -> int | None:
    if value in {None, "", "[not set]", "n/a", "infinity"}:
        return None
    if re.fullmatch(r"[0-9]+", value) is None:
        raise TestStoreConflict(f"native test attempt {field} is invalid")
    parsed = int(value)
    # systemd uses UINT64_MAX when an accounting value is unavailable.
    return None if parsed == (1 << 64) - 1 else parsed


def _runner_resource_usage(
    result: Mapping[str, object] | None,
) -> tuple[int | None, float | None]:
    if result is None:
        return None, None
    has_peak = "peak_memory_bytes" in result
    has_cpu = "cpu_seconds" in result
    if not has_peak and not has_cpu:
        return None, None
    if not has_peak or not has_cpu:
        raise TestStoreContractError("test runner resource measurements are incomplete")
    return (
        _validated_peak_memory_bytes(result["peak_memory_bytes"]),
        _validated_cpu_seconds(result["cpu_seconds"]),
    )


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _single_line(field: str, value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _absolute_path(field: str, value: object) -> str:
    text = _single_line(field, value, maximum=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != (text.rstrip("/") or "/")
    ):
        raise TestStoreContractError(f"{field} must be one normalized absolute path")
    return str(path)


def _relative_path(field: str, value: object) -> str:
    text = _single_line(field, value, maximum=4096)
    if text == ".":
        return text
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != text
    ):
        raise TestStoreContractError(f"{field} must be repository-relative")
    return text


def _systemd_bind_path(field: str, value: Path) -> str:
    """Serialize one exact bind path without invoking systemd's list parser.

    ``BindPaths=`` uses spaces to separate entries, colons for source/destination
    mappings, backslashes for escaping and percent specifiers in unit values.
    Passing an arbitrary repository path through ``systemd-run --property`` can
    therefore broaden the mount set.  Restrict the property form to a proven
    literal subset and return a typed blocker for every other path.
    """

    text = str(value)
    if (
        _SYSTEMD_BIND_PATH.fullmatch(text) is None
        or "//" in text
        or any(character in text for character in ("%", "\\", ":"))
    ):
        raise TestStoreConflict(
            f"{field} cannot be represented safely as a systemd bind property"
        )
    return text


def _systemd_bind_mapping(field: str, source: Path, destination: Path) -> str:
    """Serialize one exact source/destination pair from two literal paths."""

    return (
        _systemd_bind_path(f"{field} source", source)
        + ":"
        + _systemd_bind_path(f"{field} destination", destination)
    )


def _linux_process_identity(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError as error:
        raise TestStoreConflict("test fixture process identity is unavailable") from error
    delimiter = raw.rfind(")")
    fields = raw[delimiter + 2 :].split() if delimiter >= 0 else []
    if len(fields) < 20 or fields[0] == "Z":
        raise TestStoreConflict("test fixture process identity is invalid")
    return f"linux:{pid}:{fields[19]}"


def _validate_fixture_namespace(lease: TestFixtureLease) -> None:
    namespace = lease.network_namespace
    if namespace is None:
        raise TestStoreConflict("test fixture lease has no protected network namespace")
    namespace_path = Path(str(namespace["path"]))
    try:
        observed = namespace_path.stat()
    except OSError as error:
        raise TestStoreConflict("test fixture network namespace is unavailable") from error
    if (
        (observed.st_dev, observed.st_ino) != (namespace["device"], namespace["inode"])
        or namespace_path != Path(f"/proc/{namespace['pid']}/ns/net")
        or _linux_process_identity(int(namespace["pid"])) != namespace["process_identity"]
    ):
        raise TestStoreConflict("test fixture network namespace changed")


def _positive_integer(field: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TestStoreContractError(f"{field} must be from 1 through {maximum}")
    return value


def _nonnegative_integer(field: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise TestStoreContractError(f"{field} must be non-negative")
    return value


def _argv(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or not value
        or len(value) > MAX_TEST_ATTEMPT_ARGUMENTS
    ):
        raise TestStoreContractError("test attempt argv is invalid")
    result = tuple(_single_line("argv item", item, maximum=8192) for item in value)
    if sum(len(item.encode("utf-8")) for item in result) > MAX_TEST_ATTEMPT_ARGUMENT_BYTES:
        raise TestStoreContractError("test attempt argv exceeds its byte bound")
    if PurePosixPath(result[0]).name.lower() in _FORBIDDEN_EXECUTABLES:
        raise TestStoreContractError("test attempt cannot invoke a shell or env trampoline")
    if any("{" in item or "}" in item for item in result):
        raise TestStoreContractError("test attempt argv has an unresolved placeholder")
    return result


def _environment(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > MAX_TEST_ATTEMPT_ENVIRONMENT:
        raise TestStoreContractError("test attempt environment is invalid")
    result: dict[str, str] = {}
    for key, raw in value.items():
        if (
            not isinstance(key, str)
            or _ENVIRONMENT_NAME.fullmatch(key) is None
            or _SECRET_ENVIRONMENT_NAME.search(key)
        ):
            raise TestStoreContractError("test attempt environment name is unsafe")
        result[key] = _single_line(f"environment {key}", raw, maximum=4096)
    if sum(len(key) + len(item) for key, item in result.items()) > 32 * 1024:
        raise TestStoreContractError("test attempt environment exceeds its byte bound")
    return dict(sorted(result.items()))


@dataclass(frozen=True)
class TestAttemptDescriptor:
    attempt_id: str
    target_id: str
    run_id: str
    repository_id: str
    repository_generation: int
    owner_uid: int
    generation: int
    source_mode: str
    snapshot_id: str | None
    original_root: str
    temporary_root: str | None
    execution_root: str
    worktree_key: str
    target_name: str
    shard_index: int
    shard_count: int
    argv: tuple[str, ...]
    cwd: str
    environment: Mapping[str, str]
    driver: str
    reporter: str
    artifacts: tuple[Mapping[str, object], ...]
    fixtures: tuple[str, ...]
    network: str
    ttl_seconds: int
    cpu_millis: int
    memory_mib: int
    pids: int
    source_provenance: Mapping[str, object] = field(default_factory=dict)
    dependency_bindings: tuple[Mapping[str, object], ...] = ()
    toolchain_bindings: tuple[Mapping[str, object], ...] = ()
    supplementary_gids: tuple[int, ...] = ()
    fixture_bindings: tuple[Mapping[str, object], ...] = ()
    intent: str = "change"
    credentials: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("attempt_id", "target_id", "run_id", "repository_id"):
            object.__setattr__(self, name, _safe_id(name, getattr(self, name)))
        object.__setattr__(
            self,
            "repository_generation",
            _nonnegative_integer("repository_generation", self.repository_generation),
        )
        object.__setattr__(self, "owner_uid", _positive_integer("owner_uid", self.owner_uid, maximum=2**31 - 1))
        object.__setattr__(self, "generation", _positive_integer("generation", self.generation, maximum=2**31 - 1))
        if self.intent not in {"change", "checkpoint", "handoff", "release", "manual"}:
            raise TestStoreContractError("test attempt intent is invalid")
        if self.source_mode not in {"live", "immutable"}:
            raise TestStoreContractError("test attempt source_mode is invalid")
        if self.source_mode == "immutable":
            _safe_id("snapshot_id", self.snapshot_id)
            if self.temporary_root is not None:
                raise TestStoreContractError("immutable test attempts cannot use a temporary root")
        elif self.snapshot_id is not None:
            raise TestStoreContractError("live test attempts cannot claim a snapshot")
        object.__setattr__(self, "original_root", _absolute_path("original_root", self.original_root))
        if self.temporary_root is not None:
            object.__setattr__(self, "temporary_root", _absolute_path("temporary_root", self.temporary_root))
        object.__setattr__(self, "execution_root", _absolute_path("execution_root", self.execution_root))
        object.__setattr__(self, "worktree_key", _absolute_path("worktree_key", self.worktree_key))
        object.__setattr__(self, "target_name", _single_line("target_name", self.target_name, maximum=256))
        if type(self.shard_index) is not int or type(self.shard_count) is not int or not 0 <= self.shard_index < self.shard_count <= 64:
            raise TestStoreContractError("test attempt shard identity is invalid")
        object.__setattr__(self, "argv", _argv(self.argv))
        object.__setattr__(self, "cwd", _relative_path("cwd", self.cwd))
        object.__setattr__(self, "environment", _environment(self.environment))
        if self.driver not in {"pytest", "node", "dotnet", "automation"}:
            raise TestStoreContractError("test attempt driver is invalid")
        if any(argument.startswith("--test-shard") for argument in self.argv[1:]):
            raise TestStoreContractError(
                "node shard selection is owned by the trusted test adapter"
            )
        if self.shard_count > 1:
            node_test = self.driver == "node" and any(
                argument == "--test" or argument.startswith("--test=")
                for argument in self.argv[1:]
            )
            if self.driver != "pytest" and not node_test:
                raise TestStoreContractError(
                    "test attempt has no trusted distinct shard selector"
                )
        reporters = {
            "pytest": {"pytest-events"},
            "node": {"jsonl"},
            "dotnet": {"trx"},
            "automation": {"jsonl", "automation-events"},
        }
        if self.reporter not in reporters[self.driver]:
            raise TestStoreContractError("test attempt reporter is invalid")
        normalized_artifacts: list[Mapping[str, object]] = []
        artifact_fields = {"name", "path", "kind", "required", "max_bytes"}
        for raw in self.artifacts:
            if not isinstance(raw, Mapping) or set(raw) != artifact_fields:
                raise TestStoreContractError("test attempt artifact fields are invalid")
            if raw["kind"] not in {
                "log", "jsonl", "junit", "trx", "coverage", "trace", "directory"
            } or type(raw["required"]) is not bool:
                raise TestStoreContractError("test attempt artifact policy is invalid")
            normalized_artifacts.append(
                {
                    "name": _safe_id("artifact.name", raw["name"]),
                    "path": _relative_path("artifact.path", raw["path"]),
                    "kind": str(raw["kind"]),
                    "required": raw["required"],
                    "max_bytes": _positive_integer(
                        "artifact.max_bytes", raw["max_bytes"], maximum=1024**3
                    ),
                }
            )
        object.__setattr__(self, "artifacts", tuple(normalized_artifacts))
        normalized_fixtures = tuple(
            _safe_id("fixture", fixture) for fixture in self.fixtures
        )
        if len(normalized_fixtures) > 32 or len(set(normalized_fixtures)) != len(
            normalized_fixtures
        ):
            raise TestStoreContractError("test attempt fixtures are invalid")
        object.__setattr__(self, "fixtures", normalized_fixtures)
        normalized_credentials = tuple(
            _single_line("operational credential binding", credential, maximum=128)
            for credential in self.credentials
        )
        if (
            len(normalized_credentials) > 16
            or len(set(normalized_credentials)) != len(normalized_credentials)
            or any(
                _OPERATIONAL_CREDENTIAL_ALIAS.fullmatch(credential) is None
                for credential in normalized_credentials
            )
        ):
            raise TestStoreContractError(
                "test attempt operational credentials are invalid"
            )
        if normalized_credentials and self.intent != "manual":
            raise TestStoreContractError(
                "operational credentials require manual test intent"
            )
        object.__setattr__(self, "credentials", normalized_credentials)
        normalized_bindings: list[Mapping[str, object]] = []
        for raw in self.fixture_bindings:
            if not isinstance(raw, Mapping) or set(raw) != {"name", "template", "network"}:
                raise TestStoreContractError("test attempt fixture bindings are invalid")
            name = _safe_id("fixture binding name", raw["name"])
            template = _safe_id("fixture template", raw["template"])
            network = raw["network"]
            if network not in {"loopback", "external"}:
                raise TestStoreContractError("test attempt fixture binding network is invalid")
            normalized_bindings.append(
                {"name": name, "template": template, "network": str(network)}
            )
        if normalized_bindings and tuple(
            item["name"] for item in normalized_bindings
        ) != normalized_fixtures:
            raise TestStoreContractError(
                "test attempt fixture bindings do not cover declared fixtures"
            )
        object.__setattr__(self, "fixture_bindings", tuple(normalized_bindings))
        if self.network not in {
            "none",
            "loopback",
            "host-loopback",
            "external",
        }:
            raise TestStoreContractError("test attempt network is invalid")
        if self.network == "host-loopback" and (
            self.intent != "manual"
            or normalized_fixtures
            or normalized_bindings
        ):
            raise TestStoreContractError(
                "host-loopback requires manual intent without fixtures"
            )
        object.__setattr__(self, "ttl_seconds", _positive_integer("ttl_seconds", self.ttl_seconds, maximum=MAX_TEST_ATTEMPT_TTL_SECONDS))
        # These fields remain only for schema compatibility. Never validate or
        # retain repository declarations as though they were executable limits.
        object.__setattr__(
            self, "cpu_millis", NON_AUTHORITATIVE_RESOURCES.cpu_millis
        )
        object.__setattr__(
            self, "memory_mib", NON_AUTHORITATIVE_RESOURCES.memory_mib
        )
        object.__setattr__(self, "pids", NON_AUTHORITATIVE_RESOURCES.pids)
        raw_provenance = self.source_provenance
        if not isinstance(raw_provenance, Mapping):
            raise TestStoreContractError("test attempt source provenance is invalid")
        if raw_provenance:
            fields = {
                "complete",
                "content_fingerprint",
                "manifest_fingerprint",
                "dependency_locks",
                "toolchain",
            }
            locks = raw_provenance.get("dependency_locks")
            toolchain = raw_provenance.get("toolchain")
            sha256 = re.compile(r"^[0-9a-f]{64}$")
            if (
                set(raw_provenance) != fields
                or type(raw_provenance.get("complete")) is not bool
                or not isinstance(raw_provenance.get("content_fingerprint"), str)
                or sha256.fullmatch(str(raw_provenance["content_fingerprint"])) is None
                or not isinstance(raw_provenance.get("manifest_fingerprint"), str)
                or sha256.fullmatch(str(raw_provenance["manifest_fingerprint"])) is None
                or not isinstance(locks, Mapping)
                or len(locks) > 128
                or any(
                    not isinstance(path, str)
                    or _relative_path("dependency lock", path) != path
                    or not isinstance(digest, str)
                    or sha256.fullmatch(digest) is None
                    for path, digest in locks.items()
                )
                or not isinstance(toolchain, Mapping)
                or len(toolchain) > 64
                or any(
                    not isinstance(name, str)
                    or _safe_id("toolchain name", name) != name
                    or not isinstance(value, str)
                    or _single_line("toolchain value", value, maximum=4096) != value
                    for name, value in toolchain.items()
                )
            ):
                raise TestStoreContractError("test attempt source provenance is invalid")
            raw_provenance = {
                "complete": raw_provenance["complete"],
                "content_fingerprint": raw_provenance["content_fingerprint"],
                "manifest_fingerprint": raw_provenance["manifest_fingerprint"],
                "dependency_locks": dict(sorted(locks.items())),
                "toolchain": dict(sorted(toolchain.items())),
            }
        object.__setattr__(self, "source_provenance", dict(raw_provenance))
        normalized_dependencies: list[Mapping[str, object]] = []
        dependency_fields = {
            "kind",
            "source_root",
            "source_device",
            "source_inode",
            "destination",
            "locks",
            "marker_path",
            "marker_sha256",
            "executable",
            "installation_kind",
            "installation_sha256",
            "installation_files",
            "installation_bytes",
            "toolchain",
        }
        staged_dependency_fields = {
            "staged_root",
            "staged_device",
            "staged_inode",
        }
        for raw in self.dependency_bindings:
            if (
                not isinstance(raw, Mapping)
                or not dependency_fields <= set(raw)
                or set(raw) - dependency_fields - staged_dependency_fields
            ):
                raise TestStoreContractError(
                    "test attempt dependency binding fields are invalid"
                )
            kind = raw["kind"]
            if kind not in _DEPENDENCY_BINDING_KINDS:
                raise TestStoreContractError(
                    "test attempt dependency binding kind is invalid"
                )
            source_root = _absolute_path(
                "dependency binding source_root", raw["source_root"]
            )
            source_device = _nonnegative_integer(
                "dependency binding source_device", raw["source_device"]
            )
            source_inode = _positive_integer(
                "dependency binding source_inode",
                raw["source_inode"],
                maximum=(1 << 63) - 1,
            )
            raw_staged_root = raw.get("staged_root")
            raw_staged_device = raw.get("staged_device")
            raw_staged_inode = raw.get("staged_inode")
            if (
                raw_staged_root is None
                or raw_staged_device is None
                or raw_staged_inode is None
            ):
                if not (
                    raw_staged_root is None
                    and raw_staged_device is None
                    and raw_staged_inode is None
                ):
                    raise TestStoreContractError(
                        "test attempt staged dependency identity is incomplete"
                    )
                staged_root = None
                staged_device = None
                staged_inode = None
            else:
                staged_root = _absolute_path(
                    "dependency binding staged_root", raw_staged_root
                )
                staged_device = _nonnegative_integer(
                    "dependency binding staged_device", raw_staged_device
                )
                staged_inode = _positive_integer(
                    "dependency binding staged_inode",
                    raw_staged_inode,
                    maximum=(1 << 63) - 1,
                )
            destination = _relative_path(
                "dependency binding destination", raw["destination"]
            )
            if destination == ".":
                raise TestStoreContractError(
                    "test attempt dependency binding destination is invalid"
                )
            locks = raw["locks"]
            if (
                not isinstance(locks, Mapping)
                or not locks
                or len(locks) > 64
                or any(
                    not isinstance(path, str)
                    or _relative_path("dependency binding lock", path) != path
                    or not isinstance(digest, str)
                    or _SHA256.fullmatch(digest) is None
                    for path, digest in locks.items()
                )
            ):
                raise TestStoreContractError(
                    "test attempt dependency binding locks are invalid"
                )
            marker_path = raw["marker_path"]
            marker_sha256 = raw["marker_sha256"]
            executable = raw["executable"]
            installation_kind = raw["installation_kind"]
            installation_sha256 = raw["installation_sha256"]
            installation_files = _positive_integer(
                "dependency binding installation_files",
                raw["installation_files"],
                maximum=_MAX_DEPENDENCY_IDENTITY_FILES,
            )
            installation_bytes = _positive_integer(
                "dependency binding installation_bytes",
                raw["installation_bytes"],
                maximum=(
                    _MAX_NUGET_SOURCE_IDENTITY_BYTES
                    if kind == "dotnet-packages"
                    else _MAX_DEPENDENCY_IDENTITY_BYTES
                ),
            )
            if (
                installation_kind not in _INSTALLATION_MANIFEST_KINDS
                or not isinstance(installation_sha256, str)
                or _SHA256.fullmatch(installation_sha256) is None
            ):
                raise TestStoreContractError(
                    "test attempt dependency installation identity is invalid"
                )
            toolchain = raw["toolchain"]
            normalized_toolchain: Mapping[str, object] | None = None
            if toolchain is not None:
                toolchain_fields = {
                    "link_target",
                    "resolved_executable",
                    "source_root",
                    "source_device",
                    "source_inode",
                    "installation_kind",
                    "installation_sha256",
                    "installation_files",
                    "installation_bytes",
                }
                if not isinstance(toolchain, Mapping) or set(toolchain) != toolchain_fields:
                    raise TestStoreContractError(
                        "test attempt dependency toolchain fields are invalid"
                    )
                toolchain_root = _absolute_path(
                    "dependency toolchain source_root", toolchain["source_root"]
                )
                resolved_executable = _absolute_path(
                    "dependency toolchain resolved_executable",
                    toolchain["resolved_executable"],
                )
                raw_link_target = toolchain["link_target"]
                link_target = (
                    None
                    if raw_link_target is None
                    else _absolute_path(
                        "dependency toolchain link_target", raw_link_target
                    )
                )
                toolchain_device = _nonnegative_integer(
                    "dependency toolchain source_device", toolchain["source_device"]
                )
                toolchain_inode = _positive_integer(
                    "dependency toolchain source_inode",
                    toolchain["source_inode"],
                    maximum=(1 << 63) - 1,
                )
                toolchain_files = _positive_integer(
                    "dependency toolchain installation_files",
                    toolchain["installation_files"],
                    maximum=_MAX_DEPENDENCY_IDENTITY_FILES,
                )
                toolchain_bytes = _positive_integer(
                    "dependency toolchain installation_bytes",
                    toolchain["installation_bytes"],
                    maximum=_MAX_DEPENDENCY_IDENTITY_BYTES,
                )
                if (
                    toolchain["installation_kind"]
                    not in {"python-toolchain", "dotnet-toolchain"}
                    or not isinstance(toolchain["installation_sha256"], str)
                    or _SHA256.fullmatch(toolchain["installation_sha256"]) is None
                    or Path(toolchain_root) not in Path(resolved_executable).parents
                    or (
                        toolchain["installation_kind"] == "python-toolchain"
                        and link_target is None
                    )
                    or (
                        toolchain["installation_kind"] == "dotnet-toolchain"
                        and link_target is not None
                    )
                ):
                    raise TestStoreContractError(
                        "test attempt dependency toolchain identity is invalid"
                    )
                normalized_toolchain = {
                    "link_target": link_target,
                    "resolved_executable": resolved_executable,
                    "source_root": toolchain_root,
                    "source_device": toolchain_device,
                    "source_inode": toolchain_inode,
                    "installation_kind": toolchain["installation_kind"],
                    "installation_sha256": toolchain["installation_sha256"],
                    "installation_files": toolchain_files,
                    "installation_bytes": toolchain_bytes,
                }
            if marker_path is None or marker_sha256 is None:
                if marker_path is not None or marker_sha256 is not None:
                    raise TestStoreContractError(
                        "test attempt dependency binding marker is incomplete"
                    )
            else:
                marker_path = _relative_path(
                    "dependency binding marker", marker_path
                )
                if (
                    marker_path == "."
                    or not isinstance(marker_sha256, str)
                    or _SHA256.fullmatch(marker_sha256) is None
                ):
                    raise TestStoreContractError(
                        "test attempt dependency binding marker is invalid"
                    )
            if executable is not None:
                executable = _relative_path(
                    "dependency binding executable", executable
                )
                if executable == ".":
                    raise TestStoreContractError(
                        "test attempt dependency binding executable is invalid"
                    )
            destination_path = PurePosixPath(destination)
            source_path = PurePosixPath(source_root)
            if kind == "python-venv":
                if (
                    destination_path.name not in _PYTHON_ENVIRONMENT_NAMES
                    or marker_path != "pyvenv.cfg"
                    or executable not in {"bin/python", "bin/python3"}
                    or installation_kind != "python-dist-info"
                    or source_path != PurePosixPath(self.original_root) / destination_path
                    or (
                        normalized_toolchain is not None
                        and normalized_toolchain["installation_kind"]
                        != "python-toolchain"
                    )
                ):
                    raise TestStoreContractError(
                        "test attempt Python dependency binding is invalid"
                    )
                if staged_root is not None and Path(staged_root) == Path(source_root):
                    raise TestStoreContractError(
                        "test attempt staged Python dependency is not isolated"
                    )
            elif kind == "node-modules":
                if (
                    destination_path.name != "node_modules"
                    or marker_path != ".package-lock.json"
                    or executable is not None
                    or installation_kind != "node-package-lock"
                    or source_path != PurePosixPath(self.original_root) / destination_path
                    or normalized_toolchain is not None
                ):
                    raise TestStoreContractError(
                        "test attempt Node dependency binding is invalid"
                    )
                if staged_root is not None:
                    raise TestStoreContractError(
                        "test attempt Node dependency cannot claim staging"
                    )
            elif (
                destination != _DOTNET_PACKAGES_DESTINATION
                or marker_path is not None
                or marker_sha256 is not None
                or executable is not None
                or installation_kind != "nuget-package-source"
                or (
                    normalized_toolchain is not None
                    and normalized_toolchain["installation_kind"]
                    != "dotnet-toolchain"
                )
            ):
                raise TestStoreContractError(
                    "test attempt .NET dependency binding is invalid"
                )
            elif staged_root is not None:
                raise TestStoreContractError(
                    "test attempt .NET dependency cannot claim staging"
                )
            if kind == "dotnet-packages":
                local_package_roots = {
                    Path(account.pw_dir) / ".nuget" / "packages"
                    for account in pwd.getpwall()
                    if account.pw_uid > 0 and Path(account.pw_dir).is_absolute()
                }
                if Path(source_root) not in local_package_roots:
                    raise TestStoreContractError(
                        "test attempt .NET dependency binding is invalid"
                    )
            normalized_dependencies.append(
                {
                    "kind": str(kind),
                    "source_root": source_root,
                    "source_device": source_device,
                    "source_inode": source_inode,
                    "staged_root": staged_root,
                    "staged_device": staged_device,
                    "staged_inode": staged_inode,
                    "destination": destination,
                    "locks": dict(sorted(locks.items())),
                    "marker_path": marker_path,
                    "marker_sha256": marker_sha256,
                    "executable": executable,
                    "installation_kind": str(installation_kind),
                    "installation_sha256": installation_sha256,
                    "installation_files": installation_files,
                    "installation_bytes": installation_bytes,
                    "toolchain": normalized_toolchain,
                }
            )
        if (
            len(normalized_dependencies) > 3
            or len({item["kind"] for item in normalized_dependencies})
            != len(normalized_dependencies)
            or len({item["destination"] for item in normalized_dependencies})
            != len(normalized_dependencies)
        ):
            raise TestStoreContractError(
                "test attempt dependency bindings are ambiguous"
            )
        if normalized_dependencies and self.source_mode != "immutable":
            raise TestStoreContractError(
                "live test attempts cannot bind immutable dependency roots"
            )
        object.__setattr__(
            self, "dependency_bindings", tuple(normalized_dependencies)
        )
        normalized_standalone_toolchains: list[Mapping[str, object]] = []
        standalone_fields = {
            "resolved_executable",
            "source_root",
            "source_device",
            "source_inode",
            "installation_kind",
            "installation_sha256",
            "installation_files",
            "installation_bytes",
        }
        for raw in self.toolchain_bindings:
            if not isinstance(raw, Mapping) or set(raw) != standalone_fields:
                raise TestStoreContractError(
                    "test attempt standalone toolchain fields are invalid"
                )
            source_root = _absolute_path(
                "standalone toolchain source_root", raw["source_root"]
            )
            resolved_executable = _absolute_path(
                "standalone toolchain resolved_executable",
                raw["resolved_executable"],
            )
            source_device = _nonnegative_integer(
                "standalone toolchain source_device", raw["source_device"]
            )
            source_inode = _positive_integer(
                "standalone toolchain source_inode",
                raw["source_inode"],
                maximum=(1 << 63) - 1,
            )
            installation_files = _positive_integer(
                "standalone toolchain installation_files",
                raw["installation_files"],
                maximum=_MAX_DEPENDENCY_IDENTITY_FILES,
            )
            installation_bytes = _positive_integer(
                "standalone toolchain installation_bytes",
                raw["installation_bytes"],
                maximum=_MAX_DEPENDENCY_IDENTITY_BYTES,
            )
            if (
                raw["installation_kind"] != "dotnet-toolchain"
                or not isinstance(raw["installation_sha256"], str)
                or _SHA256.fullmatch(raw["installation_sha256"]) is None
                or Path(source_root) not in Path(resolved_executable).parents
            ):
                raise TestStoreContractError(
                    "test attempt standalone toolchain identity is invalid"
                )
            normalized_standalone_toolchains.append(
                {
                    "resolved_executable": resolved_executable,
                    "source_root": source_root,
                    "source_device": source_device,
                    "source_inode": source_inode,
                    "installation_kind": "dotnet-toolchain",
                    "installation_sha256": raw["installation_sha256"],
                    "installation_files": installation_files,
                    "installation_bytes": installation_bytes,
                }
            )
        if len(normalized_standalone_toolchains) > 1:
            raise TestStoreContractError(
                "test attempt standalone toolchains are ambiguous"
            )
        if normalized_standalone_toolchains and self.source_mode != "immutable":
            raise TestStoreContractError(
                "live test attempts cannot bind immutable toolchains"
            )
        object.__setattr__(
            self, "toolchain_bindings", tuple(normalized_standalone_toolchains)
        )
        supplementary_gids = tuple(
            sorted(
                {
                    _nonnegative_integer(
                        "test attempt supplementary group", value
                    )
                    for value in self.supplementary_gids
                }
            )
        )
        if len(supplementary_gids) > 64 or any(
            value > 2**31 - 1 for value in supplementary_gids
        ):
            raise TestStoreContractError(
                "test attempt supplementary groups are excessive"
            )
        object.__setattr__(self, "supplementary_gids", supplementary_gids)
        if self.source_mode == "live" and self.execution_root not in {
            self.original_root,
            self.temporary_root,
        }:
            raise TestStoreConflict("live test execution root is not the exact authoritative worktree")

    @classmethod
    def from_document(
        cls, value: Mapping[str, object], *, repository_generation: int | None = None
    ) -> "TestAttemptDescriptor":
        fields = set(cls.__dataclass_fields__)
        raw = dict(value)
        raw.setdefault("source_provenance", {})
        raw.setdefault("dependency_bindings", ())
        raw.setdefault("toolchain_bindings", ())
        raw.setdefault("supplementary_gids", ())
        raw.setdefault("fixture_bindings", ())
        raw.setdefault("intent", "change")
        raw.setdefault("credentials", ())
        if repository_generation is not None:
            if (
                "repository_generation" in raw
                and raw["repository_generation"] not in {0, repository_generation}
            ):
                raise TestStoreConflict("repository generation is contradictory")
            raw["repository_generation"] = repository_generation
        if set(raw) != fields:
            raise TestStoreContractError("test attempt descriptor fields are invalid")
        raw["argv"] = tuple(raw["argv"]) if isinstance(raw["argv"], Sequence) and not isinstance(raw["argv"], (str, bytes)) else raw["argv"]
        return cls(**raw)  # type: ignore[arg-type]

    def to_document(self) -> dict[str, object]:
        return {
            "attempt_id": self.attempt_id,
            "target_id": self.target_id,
            "run_id": self.run_id,
            "repository_id": self.repository_id,
            "repository_generation": self.repository_generation,
            "owner_uid": self.owner_uid,
            "generation": self.generation,
            "source_mode": self.source_mode,
            "intent": self.intent,
            "snapshot_id": self.snapshot_id,
            "original_root": self.original_root,
            "temporary_root": self.temporary_root,
            "execution_root": self.execution_root,
            "worktree_key": self.worktree_key,
            "target_name": self.target_name,
            "shard_index": self.shard_index,
            "shard_count": self.shard_count,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "environment": dict(self.environment),
            "driver": self.driver,
            "reporter": self.reporter,
            "artifacts": [dict(item) for item in self.artifacts],
            "fixtures": list(self.fixtures),
            "network": self.network,
            "ttl_seconds": self.ttl_seconds,
            "cpu_millis": self.cpu_millis,
            "memory_mib": self.memory_mib,
            "pids": self.pids,
            "source_provenance": dict(self.source_provenance),
            "dependency_bindings": [dict(item) for item in self.dependency_bindings],
            "toolchain_bindings": [dict(item) for item in self.toolchain_bindings],
            "supplementary_gids": list(self.supplementary_gids),
            "fixture_bindings": [dict(item) for item in self.fixture_bindings],
            "credentials": list(self.credentials),
        }

    @property
    def fingerprint(self) -> str:
        return deterministic_fingerprint(self.to_document())


@dataclass(frozen=True)
class TestFixtureLease:
    """Broker-owned fixture lease exposed to the attempt launcher.

    The provider retains all native container/database identities.  The runner
    receives only bounded, non-secret connection coordinates. Cleanup is
    fenced by the deterministic runtime ID and exact attempt descriptor
    fingerprint; neither value is an authentication secret.
    """

    runtime_id: str
    descriptor_fingerprint: str
    fixtures: tuple[str, ...]
    environment: Mapping[str, str]
    credential_files: tuple[Mapping[str, object], ...] = ()
    network_namespace: Mapping[str, object] | None = None
    provenance: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "runtime_id", _safe_id("runtime_id", self.runtime_id))
        if re.fullmatch(r"[0-9a-f]{64}", self.descriptor_fingerprint) is None:
            raise TestStoreContractError(
                "fixture lease descriptor fingerprint is invalid"
            )
        normalized = tuple(_safe_id("fixture", value) for value in self.fixtures)
        if not normalized or len(normalized) > 32 or len(set(normalized)) != len(normalized):
            raise TestStoreContractError("fixture lease identities are invalid")
        object.__setattr__(self, "fixtures", normalized)
        object.__setattr__(self, "environment", _environment(self.environment))
        credentials: list[Mapping[str, object]] = []
        for raw in self.credential_files:
            if not isinstance(raw, Mapping) or set(raw) != {
                "name", "source_path", "sha256", "size_bytes"
            }:
                raise TestStoreContractError("fixture credential fields are invalid")
            name = _safe_id("fixture credential name", raw["name"])
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) is None:
                raise TestStoreContractError("fixture credential name is invalid")
            source_path = _absolute_path("fixture credential path", raw["source_path"])
            digest = raw["sha256"]
            size_bytes = raw["size_bytes"]
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or type(size_bytes) is not int
                or not 0 <= size_bytes <= 1024 * 1024
            ):
                raise TestStoreContractError("fixture credential identity is invalid")
            credentials.append(
                {
                    "name": name,
                    "source_path": source_path,
                    "sha256": digest,
                    "size_bytes": size_bytes,
                }
            )
        if len(credentials) > 34 or len({item["name"] for item in credentials}) != len(credentials):
            raise TestStoreContractError("fixture credential identities are invalid")
        object.__setattr__(self, "credential_files", tuple(credentials))
        if self.network_namespace is not None:
            raw = self.network_namespace
            if not isinstance(raw, Mapping) or set(raw) != {
                "path", "device", "inode", "pid", "process_identity"
            }:
                raise TestStoreContractError("fixture network namespace fields are invalid")
            path = _absolute_path("fixture network namespace path", raw["path"])
            if not re.fullmatch(r"/proc/[1-9][0-9]*/ns/net", path):
                raise TestStoreContractError("fixture network namespace path is invalid")
            if any(type(raw[name]) is not int or int(raw[name]) <= 0 for name in ("device", "inode", "pid")):
                raise TestStoreContractError("fixture network namespace identity is invalid")
            process_identity = _single_line(
                "fixture process identity", raw["process_identity"], maximum=512
            )
            object.__setattr__(
                self,
                "network_namespace",
                {
                    "path": path,
                    "device": raw["device"],
                    "inode": raw["inode"],
                    "pid": raw["pid"],
                    "process_identity": process_identity,
                },
            )
        normalized_provenance: list[Mapping[str, object]] = []
        for raw in self.provenance:
            if not isinstance(raw, Mapping):
                raise TestStoreContractError("fixture provenance is invalid")
            payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if len(payload.encode("utf-8")) > 16 * 1024:
                raise TestStoreContractError("fixture provenance is excessive")
            normalized_provenance.append(dict(raw))
        object.__setattr__(self, "provenance", tuple(normalized_provenance))


@dataclass(frozen=True)
class TestCredentialLease:
    """One-attempt operational credential lease.

    File identities point only into a root-owned runtime directory.  They are
    broker-internal and never enter a public descriptor, ticket, result, or
    evidence document.
    """

    runtime_id: str
    descriptor_fingerprint: str
    bindings: tuple[str, ...]
    rotation_generations: tuple[int, ...]
    credential_files: tuple[Mapping[str, object], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "runtime_id", _safe_id("runtime_id", self.runtime_id))
        if re.fullmatch(r"[0-9a-f]{64}", self.descriptor_fingerprint) is None:
            raise TestStoreContractError(
                "credential lease descriptor fingerprint is invalid"
            )
        bindings = tuple(
            _single_line("credential binding", value, maximum=128)
            for value in self.bindings
        )
        if (
            not bindings
            or len(bindings) > 16
            or len(set(bindings)) != len(bindings)
            or any(
                _OPERATIONAL_CREDENTIAL_ALIAS.fullmatch(value) is None
                for value in bindings
            )
        ):
            raise TestStoreContractError("credential lease bindings are invalid")
        object.__setattr__(self, "bindings", bindings)
        generations = tuple(
            _positive_integer(
                "credential rotation generation", value, maximum=2**31 - 1
            )
            for value in self.rotation_generations
        )
        if len(generations) != len(bindings):
            raise TestStoreContractError("credential lease generations are invalid")
        object.__setattr__(self, "rotation_generations", generations)
        credentials: list[Mapping[str, object]] = []
        for raw in self.credential_files:
            if not isinstance(raw, Mapping) or set(raw) != {
                "name",
                "source_path",
                "sha256",
                "size_bytes",
            }:
                raise TestStoreContractError("credential lease file fields are invalid")
            name = _safe_id("credential lease file name", raw["name"])
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) is None:
                raise TestStoreContractError("credential lease file name is invalid")
            source_path = _absolute_path(
                "credential lease file path", raw["source_path"]
            )
            digest = raw["sha256"]
            size_bytes = raw["size_bytes"]
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or type(size_bytes) is not int
                or not 1 <= size_bytes <= 64 * 1024
            ):
                raise TestStoreContractError("credential lease file identity is invalid")
            credentials.append(
                {
                    "name": name,
                    "source_path": source_path,
                    "sha256": digest,
                    "size_bytes": size_bytes,
                }
            )
        if (
            len(credentials) != len(bindings)
            or len({item["name"] for item in credentials}) != len(credentials)
        ):
            raise TestStoreContractError("credential lease files are invalid")
        object.__setattr__(self, "credential_files", tuple(credentials))


@runtime_checkable
class TestFixtureProvider(Protocol):
    """Durable sealed-template provisioner owned by the root broker."""

    def provision(
        self, descriptor: TestAttemptDescriptor, *, runtime_id: str
    ) -> TestFixtureLease: ...

    def cleanup(
        self, *, runtime_id: str, descriptor_fingerprint: str, reason: str
    ) -> None: ...


@runtime_checkable
class TestCredentialProvider(Protocol):
    """Root-owned operational credential provider for one exact attempt."""

    def provision(
        self, descriptor: TestAttemptDescriptor, *, runtime_id: str
    ) -> TestCredentialLease: ...

    def cleanup(
        self, *, runtime_id: str, descriptor_fingerprint: str, reason: str
    ) -> None: ...



@dataclass(frozen=True)
class NativeTestAttemptState:
    runtime_id: str
    loaded: bool
    active: bool
    state: str
    exit_status: int | None
    started_at: float | None = None
    finished_at: float | None = None
    result_document: Mapping[str, object] | None = None
    systemd_result: str | None = None
    exec_main_code: int | None = None
    termination_reason: str | None = None
    oom_killed: bool = False
    peak_memory_bytes: int | None = None
    cpu_seconds: float | None = None
    current_memory_bytes: int | None = None
    output_progress: Mapping[str, object] | None = None


@runtime_checkable
class NativeTestAttemptManager(Protocol):
    def start(self, descriptor: TestAttemptDescriptor) -> NativeTestAttemptState: ...

    def status(self, runtime_id: str) -> NativeTestAttemptState: ...

    def read_result_chunk(
        self, runtime_id: str, chunk_index: int
    ) -> Mapping[str, object] | None: ...

    def cancel(self, runtime_id: str) -> NativeTestAttemptState: ...

    def collect(self, runtime_id: str) -> None: ...


Runner = Callable[..., subprocess.CompletedProcess[str]]


class SystemdTestAttemptManager:
    """Launch exact descriptors in transient per-UID systemd units."""

    def __init__(
        self,
        *,
        systemd_run: str = "/usr/bin/systemd-run",
        systemctl: str = "/usr/bin/systemctl",
        copy: str = "/usr/bin/cp",
        python: str = "/usr/bin/python3",
        runner_script: Path | None = None,
        snapshot_root: Path = Path("/var/lib/devcoordinator-test-snapshots"),
        attempt_root: Path = Path("/var/lib/devcoordinator-test-runs"),
        artifact_root: Path = Path("/var/lib/devcoordinator-test-artifacts"),
        fixture_provider: TestFixtureProvider | None = None,
        credential_provider: TestCredentialProvider | None = None,
        runner: Runner = subprocess.run,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.systemd_run = self._trusted_executable(systemd_run)
        self.systemctl = self._trusted_executable(systemctl)
        self.copy = self._trusted_executable(copy)
        self.python = self._trusted_executable(python)
        self.runner_script = Path(
            runner_script
            if runner_script is not None
            else Path(__file__).with_name("universal_test_runner.py")
        ).absolute()
        self.snapshot_root = Path(snapshot_root).absolute()
        self.attempt_root = Path(attempt_root).absolute()
        self.artifact_root = Path(artifact_root).absolute()
        if fixture_provider is not None and not isinstance(
            fixture_provider, TestFixtureProvider
        ):
            raise TestStoreContractError("test fixture provider is invalid")
        self.fixture_provider = fixture_provider
        if credential_provider is not None and not isinstance(
            credential_provider, TestCredentialProvider
        ):
            raise TestStoreContractError(
                "test operational credential provider is invalid"
            )
        self.credential_provider = credential_provider
        self.runner = runner
        self.clock = clock
        self._started: dict[str, float] = {}
        self._materialized: dict[str, Path] = {}
        self._fixture_leases: dict[str, TestFixtureLease] = {}
        self._credential_leases: dict[str, TestCredentialLease] = {}

    def _provision_fixture_descriptor(
        self, descriptor: TestAttemptDescriptor, *, runtime_id: str
    ) -> TestAttemptDescriptor:
        if not descriptor.fixtures:
            return descriptor
        provider = self.fixture_provider
        if provider is None:
            raise TestStoreConflict(
                "test fixtures require a configured broker-owned fixture provider"
            )
        try:
            lease = provider.provision(descriptor, runtime_id=runtime_id)
        except TestStoreConflict:
            raise
        except Exception as error:
            raise TestStoreConflict(
                "test fixture provisioning failed ("
                + _safe_fixture_provider_failure(error)
                + ")"
            ) from error
        if not isinstance(lease, TestFixtureLease):
            raise TestStoreConflict("test fixture lease identity is invalid")
        if (
            lease.runtime_id != runtime_id
            or lease.descriptor_fingerprint != descriptor.fingerprint
            or lease.fixtures != descriptor.fixtures
            or set(lease.environment) & set(descriptor.environment)
            or runtime_id in self._fixture_leases
        ):
            # Provision commits before it returns. Even a contradictory reply
            # therefore receives an exact idempotent cleanup before rejection.
            try:
                provider.cleanup(
                    runtime_id=lease.runtime_id,
                    descriptor_fingerprint=lease.descriptor_fingerprint,
                    reason="invalid_fixture_lease",
                )
            except Exception as error:
                raise TestStoreConflict(
                    "invalid test fixture lease could not be cleaned"
                ) from error
            raise TestStoreConflict("test fixture lease identity is invalid")
        self._fixture_leases[runtime_id] = lease
        return replace(
            descriptor,
            environment={**descriptor.environment, **lease.environment},
        )

    def _cleanup_fixtures(self, runtime_id: str, *, reason: str) -> None:
        lease = self._fixture_leases.get(runtime_id)
        provider = self.fixture_provider
        if lease is None and provider is not None:
            recover = getattr(provider, "recover_for_cleanup", None)
            if not callable(recover):
                recover = getattr(provider, "recover", None)
            if callable(recover):
                try:
                    recovered = recover(runtime_id=runtime_id)
                except Exception as error:
                    raise TestStoreConflict("test fixture lease recovery failed") from error
                if recovered is not None:
                    if not isinstance(recovered, TestFixtureLease) or recovered.runtime_id != runtime_id:
                        raise TestStoreConflict("recovered test fixture lease is invalid")
                    lease = recovered
                    self._fixture_leases[runtime_id] = recovered
        if lease is None:
            return
        if provider is None:
            raise TestStoreConflict("test fixture cleanup provider is unavailable")
        try:
            provider.cleanup(
                runtime_id=runtime_id,
                descriptor_fingerprint=lease.descriptor_fingerprint,
                reason=_single_line("fixture cleanup reason", reason, maximum=256),
            )
        except TestStoreConflict:
            raise
        except Exception as error:
            # Retain the lease so the next observation/reaper pass retries the
            # idempotent cleanup rather than losing ownership evidence.
            raise TestStoreConflict("test fixture cleanup failed") from error
        self._fixture_leases.pop(runtime_id, None)

    def _provision_credential_descriptor(
        self, descriptor: TestAttemptDescriptor, *, runtime_id: str
    ) -> TestAttemptDescriptor:
        if not descriptor.credentials:
            return descriptor
        provider = self.credential_provider
        if provider is None:
            raise TestStoreConflict(
                "operational credentials require a configured broker-owned provider"
            )
        try:
            lease = provider.provision(descriptor, runtime_id=runtime_id)
        except TestStoreConflict:
            raise
        except Exception as error:
            raise TestStoreConflict(
                "operational credential provisioning failed"
            ) from error
        if (
            not isinstance(lease, TestCredentialLease)
            or lease.runtime_id != runtime_id
            or lease.descriptor_fingerprint != descriptor.fingerprint
            or lease.bindings != descriptor.credentials
            or runtime_id in self._credential_leases
        ):
            if isinstance(lease, TestCredentialLease):
                try:
                    provider.cleanup(
                        runtime_id=lease.runtime_id,
                        descriptor_fingerprint=lease.descriptor_fingerprint,
                        reason="invalid_credential_lease",
                    )
                except Exception as error:
                    raise TestStoreConflict(
                        "invalid operational credential lease could not be cleaned"
                    ) from error
            raise TestStoreConflict(
                "operational credential lease identity is invalid"
            )
        self._credential_leases[runtime_id] = lease
        return descriptor

    def _cleanup_credentials(self, runtime_id: str, *, reason: str) -> None:
        lease = self._recover_credential_lease(runtime_id)
        provider = self.credential_provider
        if lease is None:
            return
        if provider is None:
            raise TestStoreConflict(
                "operational credential cleanup provider is unavailable"
            )
        try:
            provider.cleanup(
                runtime_id=runtime_id,
                descriptor_fingerprint=lease.descriptor_fingerprint,
                reason=_single_line(
                    "credential cleanup reason", reason, maximum=256
                ),
            )
        except TestStoreConflict:
            raise
        except Exception as error:
            raise TestStoreConflict(
                "operational credential cleanup failed"
            ) from error
        self._credential_leases.pop(runtime_id, None)

    def _recover_credential_lease(
        self, runtime_id: str
    ) -> TestCredentialLease | None:
        lease = self._credential_leases.get(runtime_id)
        provider = self.credential_provider
        if lease is not None or provider is None:
            return lease
        recover = getattr(provider, "recover_for_cleanup", None)
        if not callable(recover):
            recover = getattr(provider, "recover", None)
        if not callable(recover):
            raise TestStoreConflict(
                "operational credential lease recovery is unavailable"
            )
        try:
            recovered = recover(runtime_id=runtime_id)
        except Exception as error:
            raise TestStoreConflict(
                "operational credential lease recovery failed"
            ) from error
        if recovered is None:
            return None
        if (
            not isinstance(recovered, TestCredentialLease)
            or recovered.runtime_id != runtime_id
        ):
            raise TestStoreConflict(
                "recovered operational credential lease is invalid"
            )
        self._credential_leases[runtime_id] = recovered
        return recovered

    def _credential_artifact_sequences(
        self,
        runtime_id: str,
        descriptor: TestAttemptDescriptor,
    ) -> tuple[bytes, ...]:
        if not descriptor.credentials:
            return ()
        lease = self._recover_credential_lease(runtime_id)
        if (
            lease is None
            or lease.descriptor_fingerprint != descriptor.fingerprint
            or lease.bindings != descriptor.credentials
        ):
            raise TestStoreConflict(
                "operational credential lease is unavailable for artifact inspection"
            )
        variants: set[bytes] = set()
        for raw in lease.credential_files:
            source = Path(str(raw["source_path"]))
            try:
                before_path = source.lstat()
                descriptor_fd = os.open(
                    source,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                )
            except OSError as error:
                raise TestStoreConflict(
                    "operational credential is unavailable for artifact inspection"
                ) from error
            payload = bytearray()
            try:
                before = os.fstat(descriptor_fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_ISLNK(before.st_mode)
                    or before.st_size != raw["size_bytes"]
                ):
                    raise TestStoreConflict(
                        "operational credential is unsafe for artifact inspection"
                    )
                while True:
                    chunk = os.read(descriptor_fd, 64 * 1024)
                    if not chunk:
                        break
                    payload.extend(chunk)
                    if len(payload) > 64 * 1024:
                        raise TestStoreConflict(
                            "operational credential is excessive"
                        )
                os.lseek(descriptor_fd, 0, os.SEEK_SET)
                verification = bytearray()
                while True:
                    chunk = os.read(descriptor_fd, 64 * 1024)
                    if not chunk:
                        break
                    verification.extend(chunk)
                    if len(verification) > 64 * 1024:
                        raise TestStoreConflict(
                            "operational credential is excessive"
                        )
                after = os.fstat(descriptor_fd)
            finally:
                os.close(descriptor_fd)
            try:
                after_path = source.lstat()
            except OSError as error:
                raise TestStoreConflict(
                    "operational credential changed during artifact inspection"
                ) from error
            value = bytes(payload)
            if (
                _stable_file_identity(before)
                != _stable_file_identity(after)
                or _stable_file_identity(after)
                != _stable_file_identity(before_path)
                or _stable_file_identity(before_path)
                != _stable_file_identity(after_path)
                or payload != verification
                or len(value) != raw["size_bytes"]
                or hashlib.sha256(value).hexdigest() != raw["sha256"]
            ):
                raise TestStoreConflict(
                    "operational credential changed during artifact inspection"
                )
            variants.update(
                {
                    value,
                    base64.b64encode(value),
                    base64.urlsafe_b64encode(value).rstrip(b"="),
                    value.hex().encode("ascii"),
                }
            )
        return tuple(sorted(variants, key=lambda value: (-len(value), value)))

    def _cleanup_attempt_resources(self, runtime_id: str, *, reason: str) -> None:
        failures: list[Exception] = []
        for cleanup in (self._cleanup_credentials, self._cleanup_fixtures):
            try:
                cleanup(runtime_id, reason=reason)
            except Exception as error:
                failures.append(error)
        if failures:
            first = failures[0]
            if isinstance(first, TestStoreConflict):
                raise first
            raise TestStoreConflict("test attempt resource cleanup failed") from first

    def _trusted_runner_script(self) -> str:
        try:
            resolved = self.runner_script.resolve(strict=True)
            metadata = resolved.lstat()
        except OSError as error:
            raise TestStoreContractError("trusted test runner is unavailable") from error
        if (
            resolved != self.runner_script
            or not stat.S_ISREG(metadata.st_mode)
        ):
            raise TestStoreContractError("trusted test runner is not a regular file")
        return str(resolved)

    @staticmethod
    def _trusted_executable(value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            raise TestStoreContractError("native manager executable must be absolute")
        try:
            resolved = path.resolve(strict=True)
            metadata = resolved.lstat()
        except OSError as error:
            raise TestStoreContractError("native manager executable is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise TestStoreContractError("native manager executable is unavailable")
        return str(resolved)

    @staticmethod
    def _unit(runtime_id: str) -> str:
        _safe_id("runtime_id", runtime_id)
        return runtime_id + ".service"

    @staticmethod
    def _runtime_id(descriptor: TestAttemptDescriptor) -> str:
        return _runtime_id_for_attempt(descriptor.attempt_id)

    @staticmethod
    def _repository_slice(descriptor: TestAttemptDescriptor) -> str:
        repository = hashlib.sha256(
            descriptor.repository_id.encode("utf-8")
        ).hexdigest()[:20]
        # Dash-separated slice components form a per-UID/per-repository
        # accounting hierarchy under devcoordinator-tests.slice. Test attempts
        # remain attributable without inheriting the background daemon's CPU,
        # memory, or process ceilings.
        return (
            f"devcoordinator-tests-uid{descriptor.owner_uid}"
            f"-repo{repository}.slice"
        )

    @staticmethod
    def _require_real_directory(path: Path, *, field: str) -> os.stat_result:
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        if (
            resolved != path
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise TestStoreConflict(f"{field} is unsafe")
        return metadata

    @staticmethod
    def _dependency_file_bytes(
        root: Path, relative: str, *, field: str
    ) -> tuple[bytes, os.stat_result]:
        """Read one exact regular file below a real dependency authority root."""

        candidate = root.joinpath(*PurePosixPath(relative).parts)
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            resolved_root = root.resolve(strict=True)
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or resolved != candidate
            or (resolved != resolved_root and resolved_root not in resolved.parents)
            or metadata.st_size > 64 * 1024 * 1024
        ):
            raise TestStoreConflict(f"{field} is unsafe")
        try:
            data = candidate.read_bytes()
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        return data, metadata

    @classmethod
    def _dependency_file_digest(
        cls, root: Path, relative: str, *, field: str
    ) -> str:
        data, metadata = cls._dependency_file_bytes(root, relative, field=field)
        return snapshot_regular_file_digest(
            data, executable=bool(metadata.st_mode & 0o111)
        )

    @classmethod
    def _installation_manifest_identity(
        cls,
        source_root: Path,
        *,
        kind: str,
        required_paths: Sequence[PurePosixPath] = (),
    ) -> tuple[str, int, int]:
        candidates: list[Path] = []
        if kind == "python-dist-info":
            for site_packages in sorted(
                source_root.glob("lib/python*/site-packages"), key=str
            ):
                candidates.extend(site_packages.glob("*.dist-info/RECORD"))
                candidates.extend(site_packages.glob("*.dist-info/METADATA"))
        elif kind == "python-toolchain":
            candidates.extend(source_root.glob("bin/python*"))
            for standard_library in source_root.glob("lib/python*"):
                candidates.extend(
                    standard_library / name
                    for name in ("os.py", "site.py", "sysconfig.py")
                    if (standard_library / name).exists()
                )
        elif kind == "dotnet-toolchain":
            candidates.append(source_root / "dotnet")
            candidates.extend(source_root.glob("sdk/*/.version"))
            candidates.extend(source_root.glob("shared/*/*/.version"))
            candidates.extend(source_root.glob("host/fxr/*/.version"))
        elif kind == "node-package-lock":
            candidates.append(source_root / ".package-lock.json")
        elif kind == "nuget-package-source":
            if not required_paths:
                raise TestStoreConflict(
                    "test .NET package identity has no locked packages"
                )
            candidates.extend(source_root.joinpath(*path.parts) for path in required_paths)
        else:
            raise TestStoreConflict(
                "test dependency installation manifest kind is invalid"
            )
        if kind == "python-toolchain":
            candidates = [candidate for candidate in candidates if not candidate.is_symlink()]
        unique = sorted(set(candidates), key=str)
        if not unique or len(unique) > _MAX_DEPENDENCY_IDENTITY_FILES:
            raise TestStoreConflict(
                "test dependency installation manifest is missing or excessive"
            )
        identity = hashlib.sha256()
        total_bytes = 0
        for candidate in unique:
            try:
                relative = candidate.relative_to(source_root)
                metadata = candidate.lstat()
            except (OSError, ValueError) as error:
                raise TestStoreConflict(
                    "test dependency installation manifest is unsafe"
                ) from error
            total_bytes += metadata.st_size
            if (
                kind != "nuget-package-source"
                and total_bytes > _MAX_DEPENDENCY_IDENTITY_BYTES
            ):
                raise TestStoreConflict(
                    "test dependency installation manifest is excessive"
                )
            relative_path = PurePosixPath(relative.as_posix())
            if kind == "nuget-package-source" and relative_path.suffix == ".nupkg":
                try:
                    file_digest, _raw_sha512, _size = (
                        nuget_package_archive_file_digests(
                            source_root, relative_path
                        )
                    )
                except TestStoreContractError as error:
                    raise TestStoreConflict(
                        "test .NET package archive identity is invalid"
                    ) from error
            else:
                file_digest = cls._dependency_file_digest(
                    source_root,
                    relative.as_posix(),
                    field="test dependency installation manifest file",
                )
            identity.update(relative.as_posix().encode("utf-8"))
            identity.update(b"\0")
            identity.update(str(metadata.st_size).encode("ascii"))
            identity.update(b"\0")
            identity.update(file_digest.encode("ascii"))
            identity.update(b"\n")
        return identity.hexdigest(), len(unique), total_bytes

    @classmethod
    def _validate_dependency_binding(
        cls,
        descriptor: TestAttemptDescriptor,
        binding: Mapping[str, object],
        *,
        execution_root: Path,
        require_destination: bool,
    ) -> tuple[Path, Path]:
        """Revalidate one broker-derived immutable dependency mapping."""

        original_root = Path(descriptor.original_root)
        cls._require_real_directory(
            original_root, field="test dependency repository root"
        )
        cls._require_real_directory(
            execution_root, field="test dependency execution root"
        )
        source_root = Path(str(binding["source_root"]))
        destination = execution_root.joinpath(
            *PurePosixPath(str(binding["destination"])).parts
        )
        kind = str(binding["kind"])
        if kind in {"python-venv", "node-modules"}:
            expected_source = original_root.joinpath(
                *PurePosixPath(str(binding["destination"])).parts
            )
            if source_root != expected_source:
                raise TestStoreConflict(
                    "test dependency root differs from the authoritative repository"
                )
        source_metadata = cls._require_real_directory(
            source_root, field="test dependency root"
        )
        if (
            source_metadata.st_dev != binding["source_device"]
            or source_metadata.st_ino != binding["source_inode"]
        ):
            raise TestStoreConflict(
                "test dependency root was substituted after planning"
            )
        locks = binding["locks"]
        if not isinstance(locks, Mapping):
            raise TestStoreConflict("test dependency lock evidence is invalid")
        original_lock_documents: list[bytes] = []
        for path, expected_digest in locks.items():
            relative = str(path)
            for root, label in (
                (original_root, "original test dependency lock"),
                (execution_root, "materialized test dependency lock"),
            ):
                if cls._dependency_file_digest(
                    root, relative, field=label
                ) != str(expected_digest):
                    raise TestStoreConflict(
                        "test dependency lock changed after immutable capture"
                    )
            if kind == "dotnet-packages":
                payload, _metadata = cls._dependency_file_bytes(
                    original_root,
                    relative,
                    field="original .NET dependency lock",
                )
                original_lock_documents.append(payload)
        marker_path = binding["marker_path"]
        marker_sha256 = binding["marker_sha256"]
        if marker_path is not None and (
            cls._dependency_file_digest(
                source_root,
                str(marker_path),
                field="test dependency installation marker",
            )
            != marker_sha256
        ):
            raise TestStoreConflict(
                "test dependency installation changed after planning"
            )
        required_installation_paths: tuple[PurePosixPath, ...] = ()
        if kind == "dotnet-packages":
            try:
                requirements = nuget_locked_package_requirements(
                    original_lock_documents
                )
                required_installation_paths = nuget_locked_package_source_paths(
                    original_lock_documents
                )
            except TestStoreContractError as error:
                raise TestStoreConflict(
                    "test .NET dependency lock contract is invalid"
                ) from error
            for archive_path, sha_path, metadata_path, content_hash in requirements:
                package = str(archive_path.parent)
                try:
                    sha_payload, _sha_metadata = cls._dependency_file_bytes(
                        source_root,
                        sha_path.as_posix(),
                        field="test .NET package archive identity",
                    )
                    metadata_payload, _metadata = cls._dependency_file_bytes(
                        source_root,
                        metadata_path.as_posix(),
                        field="test .NET package restore identity",
                    )
                except TestStoreConflict as error:
                    raise TestStoreConflict(
                        f"test .NET package {package} is missing source identity files"
                    ) from error
                try:
                    _archive_digest, raw_sha512, _archive_size = (
                        nuget_package_archive_file_digests(
                            source_root, archive_path
                        )
                    )
                    expected_sha512 = nuget_package_sha512_digest(sha_payload)
                    installed_content_hash = nuget_package_metadata_content_hash(
                        metadata_payload
                    )
                except TestStoreContractError as error:
                    raise TestStoreConflict(
                        f"test .NET package {package} source metadata is invalid"
                    ) from error
                if raw_sha512 != expected_sha512:
                    raise TestStoreConflict(
                        f"test .NET package {package} archive does not match its checksum"
                    )
                if installed_content_hash != content_hash:
                    raise TestStoreConflict(
                        f"test .NET package {package} source does not match recorded locks"
                    )
        (
            installation_sha256,
            installation_files,
            installation_bytes,
        ) = cls._installation_manifest_identity(
            source_root,
            kind=str(binding["installation_kind"]),
            required_paths=required_installation_paths,
        )
        if (
            installation_sha256 != binding["installation_sha256"]
            or installation_files != binding["installation_files"]
            or installation_bytes != binding["installation_bytes"]
        ):
            raise TestStoreConflict(
                "test dependency installation identity changed after planning"
            )
        executable = binding["executable"]
        if executable is not None:
            candidate = source_root.joinpath(
                *PurePosixPath(str(executable)).parts
            )
            try:
                lexical = candidate.lstat()
                resolved = candidate.resolve(strict=True)
                resolved_metadata = resolved.lstat()
            except OSError as error:
                raise TestStoreConflict(
                    "test dependency executable is unavailable"
                ) from error
            if (
                not (stat.S_ISREG(lexical.st_mode) or stat.S_ISLNK(lexical.st_mode))
                or not stat.S_ISREG(resolved_metadata.st_mode)
                or not os.access(resolved, os.X_OK)
            ):
                raise TestStoreConflict("test dependency executable is unsafe")
        toolchain = binding.get("toolchain")
        if toolchain is not None:
            if not isinstance(toolchain, Mapping):
                raise TestStoreConflict("test dependency toolchain evidence is invalid")
            toolchain_root = Path(str(toolchain["source_root"]))
            toolchain_metadata = cls._require_real_directory(
                toolchain_root, field="test dependency toolchain root"
            )
            if (
                toolchain_metadata.st_dev != toolchain["source_device"]
                or toolchain_metadata.st_ino != toolchain["source_inode"]
            ):
                raise TestStoreConflict(
                    "test dependency toolchain root was substituted after planning"
                )
            resolved_executable = Path(str(toolchain["resolved_executable"]))
            try:
                resolved_metadata = resolved_executable.lstat()
            except OSError as error:
                raise TestStoreConflict(
                    "test dependency toolchain executable is unavailable"
                ) from error
            if (
                not stat.S_ISREG(resolved_metadata.st_mode)
                or stat.S_ISLNK(resolved_metadata.st_mode)
                or resolved_executable.resolve(strict=True) != resolved_executable
                or toolchain_root not in resolved_executable.parents
                or not os.access(resolved_executable, os.X_OK)
            ):
                raise TestStoreConflict(
                    "test dependency toolchain executable is unsafe"
                )
            if toolchain["installation_kind"] == "python-toolchain":
                if executable is None:
                    raise TestStoreConflict(
                        "test Python toolchain has no environment executable"
                    )
                lexical = source_root.joinpath(
                    *PurePosixPath(str(executable)).parts
                )
                try:
                    current_link_target = os.readlink(lexical)
                except OSError as error:
                    raise TestStoreConflict(
                        "test Python toolchain link is unavailable"
                    ) from error
                if (
                    current_link_target != toolchain["link_target"]
                    or not Path(current_link_target).is_absolute()
                    or (
                        Path(current_link_target).is_symlink()
                        and toolchain_root not in _SYSTEM_PYTHON_TOOLCHAIN_ROOTS
                    )
                    or lexical.resolve(strict=True) != resolved_executable
                ):
                    raise TestStoreConflict(
                        "test Python toolchain link changed after planning"
                    )
            toolchain_identity = cls._installation_manifest_identity(
                toolchain_root,
                kind=str(toolchain["installation_kind"]),
            )
            if toolchain_identity != (
                toolchain["installation_sha256"],
                toolchain["installation_files"],
                toolchain["installation_bytes"],
            ):
                raise TestStoreConflict(
                    "test dependency toolchain identity changed after planning"
                )
        if require_destination:
            cls._require_real_directory(
                destination, field="test dependency mount destination"
            )
            resolved_execution_root = execution_root.resolve(strict=True)
            if (
                destination == resolved_execution_root
                or resolved_execution_root not in destination.parents
            ):
                raise TestStoreConflict(
                    "test dependency mount destination escapes execution root"
                )
        mount_source = source_root
        if kind == "python-venv":
            raw_staged_root = binding.get("staged_root")
            if raw_staged_root is None:
                raise TestStoreConflict(
                    "immutable Python dependency has no root-staged source"
                )
            staged_root = Path(str(raw_staged_root))
            expected_parent = Path(descriptor.worktree_key).parent / ".dependencies"
            if staged_root.parent != expected_parent:
                raise TestStoreConflict(
                    "staged immutable Python dependency escapes its snapshot"
                )
            staged_metadata = cls._require_real_directory(
                staged_root, field="staged immutable Python dependency"
            )
            if (
                staged_metadata.st_dev != binding.get("staged_device")
                or staged_metadata.st_ino != binding.get("staged_inode")
            ):
                raise TestStoreConflict(
                    "staged immutable Python dependency was substituted"
                )
            if marker_path is not None and (
                cls._dependency_file_digest(
                    staged_root,
                    str(marker_path),
                    field="staged immutable Python dependency marker",
                )
                != marker_sha256
            ):
                raise TestStoreConflict(
                    "staged immutable Python dependency identity differs"
                )
            staged_identity = cls._installation_manifest_identity(
                staged_root, kind=str(binding["installation_kind"])
            )
            if staged_identity != (
                binding["installation_sha256"],
                binding["installation_files"],
                binding["installation_bytes"],
            ):
                raise TestStoreConflict(
                    "staged immutable Python dependency identity differs"
                )
            mount_source = staged_root
        return mount_source, destination

    @classmethod
    def _prepare_dependency_mountpoints(
        cls,
        descriptor: TestAttemptDescriptor,
        *,
        execution_root: Path,
        owner_gid: int,
    ) -> None:
        for binding in descriptor.dependency_bindings:
            _source, destination = cls._validate_dependency_binding(
                descriptor,
                binding,
                execution_root=execution_root,
                require_destination=False,
            )
            parent = destination.parent
            if str(binding["kind"]) == "dotnet-packages":
                dependency_parent = execution_root / ".devcoordinator-dependencies"
                if parent != dependency_parent:
                    raise TestStoreConflict(
                        ".NET dependency destination is contradictory"
                    )
                try:
                    dependency_parent.mkdir(mode=0o700)
                    os.chown(dependency_parent, descriptor.owner_uid, owner_gid)
                except FileExistsError:
                    cls._require_real_directory(
                        dependency_parent,
                        field="test dependency mount parent",
                    )
            cls._require_real_directory(
                parent, field="test dependency mount parent"
            )
            try:
                destination.lstat()
            except FileNotFoundError:
                pass
            else:
                raise TestStoreConflict(
                    "test dependency mount destination collides with immutable source"
                )
            try:
                destination.mkdir(mode=0o700)
                os.chown(destination, descriptor.owner_uid, owner_gid)
            except OSError as error:
                raise TestStoreConflict(
                    "test dependency mount destination could not be prepared"
                ) from error
            cls._validate_dependency_binding(
                descriptor,
                binding,
                execution_root=execution_root,
                require_destination=True,
            )

    def _remove_materialization(self, path: Path) -> None:
        if path.parent != self.attempt_root or not path.name.startswith(
            "devcoordinator-test-"
        ):
            raise TestStoreConflict("test attempt cleanup path is outside its store")
        try:
            if path.exists():
                shutil.rmtree(path)
        except OSError as error:
            raise TestStoreConflict("test attempt materialization cleanup failed") from error

    def _prepare_attempt_state(self, runtime_id: str) -> Path:
        # security-assumptions.md defines local Unix accounts as attribution,
        # not authorization, domains.  The repository-owned transient process
        # must be able to traverse this non-secret root after systemd drops
        # privileges; per-attempt directories still prevent enumeration.
        self.attempt_root.mkdir(mode=0o711, parents=True, exist_ok=True)
        self._require_real_directory(
            self.attempt_root, field="test attempt store"
        )
        try:
            # This is a functional setup action, not an authorization check.
            # Apply it unconditionally so an old installation's root-only mode
            # cannot strand repository-UID runners after an upgrade.
            self.attempt_root.chmod(0o711)
        except OSError as error:
            raise TestStoreConflict("test attempt store is not traversable") from error
        state = self.attempt_root / runtime_id
        try:
            state.mkdir(mode=0o700)
            state.chmod(0o711)
        except FileExistsError as error:
            raise TestStoreConflict("test attempt state already exists") from error
        self._materialized[runtime_id] = state
        return state

    def _prepare_attempt_root(
        self,
        descriptor: TestAttemptDescriptor,
        *,
        state: Path,
        owner_gid: int,
    ) -> Path:
        source = Path(descriptor.execution_root)
        metadata = self._require_real_directory(
            source, field="immutable test execution root"
        )
        expected = self.snapshot_root / str(descriptor.snapshot_id) / "root"
        if (
            source != expected
        ):
            raise TestStoreConflict(
                "immutable test execution root is not the selected snapshot"
            )
        snapshot_directory = state / str(descriptor.snapshot_id)
        try:
            snapshot_directory.mkdir(mode=0o711)
            # The authority service runs with a restrictive umask. This parent
            # is a non-secret routing context and must remain traversable after
            # systemd drops to the repository owner's UID; the attempt root
            # itself remains owner-private below it.
            snapshot_directory.chmod(0o711)
        except FileExistsError as error:
            raise TestStoreConflict(
                "test attempt snapshot context already exists"
            ) from error
        except OSError as error:
            raise TestStoreConflict(
                "test attempt snapshot context is not traversable"
            ) from error
        destination = snapshot_directory / "root"
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as error:
            raise TestStoreConflict("test attempt materialization already exists") from error
        try:
            # Prefer a copy-on-write clone, but remain portable across
            # filesystems that do not implement reflinks. The snapshot is
            # already bounded before this private attempt copy is created;
            # clone capability is an optimization, not an admission gate.
            self._run(
                [
                    self.copy,
                    "--archive",
                    "--reflink=auto",
                    "--",
                    str(source) + "/.",
                    str(destination),
                ]
            )
            for directory, child_directories, files in os.walk(
                destination, topdown=True, followlinks=False
            ):
                current = Path(directory)
                current_metadata = current.lstat()
                if not stat.S_ISDIR(current_metadata.st_mode):
                    raise TestStoreConflict(
                        "test attempt materialization contains an unsafe directory"
                    )
                os.chown(current, descriptor.owner_uid, owner_gid)
                current.chmod(stat.S_IMODE(current_metadata.st_mode) | 0o700)
                for name in files:
                    path = current / name
                    item = path.lstat()
                    if stat.S_ISLNK(item.st_mode):
                        os.chown(
                            path,
                            descriptor.owner_uid,
                            owner_gid,
                            follow_symlinks=False,
                        )
                    elif stat.S_ISREG(item.st_mode):
                        os.chown(path, descriptor.owner_uid, owner_gid)
                        path.chmod(stat.S_IMODE(item.st_mode) | 0o600)
                    else:
                        raise TestStoreConflict(
                            "test attempt materialization contains a special or linked file"
                        )
                child_directories[:] = [
                    name
                    for name in child_directories
                    if not (current / name).is_symlink()
                ]
            self._prepare_dependency_mountpoints(
                descriptor,
                execution_root=destination,
                owner_gid=owner_gid,
            )
            self._stage_dotnet_package_source(
                descriptor,
                state=state,
                execution_root=destination,
            )
            content_fingerprint = descriptor.source_provenance.get(
                "content_fingerprint"
            )
            if not isinstance(content_fingerprint, str):
                raise TestStoreConflict(
                    "immutable test content identity is unavailable"
                )
            publish_immutable_repository_binding(
                snapshot_directory,
                snapshot_id=str(descriptor.snapshot_id),
                repository_id=descriptor.repository_id,
                original_root=descriptor.original_root,
                materialized_root=str(destination),
                content_fingerprint=content_fingerprint,
            )
            return destination
        except Exception:
            self._remove_materialization(state)
            raise

    @classmethod
    def _dotnet_source_requirements(
        cls, descriptor: TestAttemptDescriptor, binding: Mapping[str, object]
    ) -> tuple[tuple[PurePosixPath, PurePosixPath, PurePosixPath, str], ...]:
        lock_documents: list[bytes] = []
        original_root = Path(descriptor.original_root)
        locks = binding.get("locks")
        if not isinstance(locks, Mapping):
            raise TestStoreConflict("test dependency lock evidence is invalid")
        for relative in sorted(locks):
            payload, _metadata = cls._dependency_file_bytes(
                original_root,
                str(relative),
                field="original .NET dependency lock",
            )
            lock_documents.append(payload)
        try:
            return nuget_locked_package_requirements(lock_documents)
        except TestStoreContractError as error:
            raise TestStoreConflict(
                "test .NET dependency lock contract is invalid"
            ) from error

    @classmethod
    def _stage_dotnet_package_source(
        cls,
        descriptor: TestAttemptDescriptor,
        *,
        state: Path,
        execution_root: Path,
    ) -> None:
        for binding in descriptor.dependency_bindings:
            if binding["kind"] != "dotnet-packages":
                continue
            source_root, _destination = cls._validate_dependency_binding(
                descriptor,
                binding,
                execution_root=execution_root,
                require_destination=True,
            )
            requirements = cls._dotnet_source_requirements(descriptor, binding)
            staged = state / "nuget-source"
            try:
                staged.mkdir(mode=0o700)
            except FileExistsError as error:
                raise TestStoreConflict(
                    "test .NET staged source already exists"
                ) from error
            for archive_path, sha_path, metadata_path, _content_hash in requirements:
                sha_payload, _sha_metadata = cls._dependency_file_bytes(
                    source_root,
                    sha_path.as_posix(),
                    field="test .NET package archive identity",
                )
                try:
                    expected_sha512 = nuget_package_sha512_digest(sha_payload)
                except TestStoreContractError as error:
                    raise TestStoreConflict(
                        "test .NET package archive checksum is invalid"
                    ) from error
                target = staged.joinpath(*archive_path.parts)
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = source_root.joinpath(*archive_path.parts)
                try:
                    with source.open("rb") as input_stream, target.open("xb") as output_stream:
                        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
                    target.chmod(0o644)
                    _canonical, actual_sha512, _size = (
                        nuget_package_archive_file_digests(
                            staged, archive_path
                        )
                    )
                except (OSError, TestStoreContractError) as error:
                    raise TestStoreConflict(
                        "test .NET package source could not be staged"
                    ) from error
                if actual_sha512 != expected_sha512:
                    raise TestStoreConflict(
                        "test .NET staged package differs from its checksum"
                    )
                nuspec_payload = cls._nuget_nuspec_payload(target)
                nuspec = target.parent / f"{archive_path.parts[-3]}.nuspec"
                try:
                    nuspec.write_bytes(nuspec_payload)
                    nuspec.chmod(0o644)
                    staged_sha = staged.joinpath(*sha_path.parts)
                    staged_sha.write_bytes(sha_payload)
                    staged_sha.chmod(0o644)
                    metadata_payload, _metadata = cls._dependency_file_bytes(
                        source_root,
                        metadata_path.as_posix(),
                        field="test .NET package restore identity",
                    )
                    staged_metadata = staged.joinpath(*metadata_path.parts)
                    staged_metadata.write_bytes(metadata_payload)
                    staged_metadata.chmod(0o644)
                except OSError as error:
                    raise TestStoreConflict(
                        "test .NET package manifest could not be staged"
                    ) from error
            for directory, child_directories, _files in os.walk(
                staged, topdown=False, followlinks=False
            ):
                current = Path(directory)
                if current.is_symlink() or not current.is_dir():
                    raise TestStoreConflict("test .NET staged source is unsafe")
                current.chmod(0o755)
                child_directories[:] = [
                    name for name in child_directories if not (current / name).is_symlink()
                ]

    @classmethod
    def _validated_staged_dotnet_source(
        cls,
        descriptor: TestAttemptDescriptor,
        binding: Mapping[str, object],
        *,
        state: Path,
    ) -> Path:
        staged = state / "nuget-source"
        cls._require_real_directory(staged, field="test .NET staged package source")
        requirements = cls._dotnet_source_requirements(descriptor, binding)
        expected_files = {
            relative
            for archive_path, *_rest in requirements
            for relative in (
                archive_path.as_posix(),
                str(_rest[0]),
                str(_rest[1]),
                str(archive_path.parent / f"{archive_path.parts[-3]}.nuspec"),
            )
        }
        actual_files: set[str] = set()
        for directory, child_directories, files in os.walk(
            staged, topdown=True, followlinks=False
        ):
            current = Path(directory)
            if current.is_symlink() or not current.is_dir():
                raise TestStoreConflict("test .NET staged source is unsafe")
            for name in files:
                candidate = current / name
                try:
                    metadata = candidate.lstat()
                    relative = candidate.relative_to(staged).as_posix()
                except (OSError, ValueError) as error:
                    raise TestStoreConflict(
                        "test .NET staged source is unsafe"
                    ) from error
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise TestStoreConflict("test .NET staged source is unsafe")
                actual_files.add(relative)
            child_directories[:] = [
                name for name in child_directories if not (current / name).is_symlink()
            ]
        if actual_files != expected_files:
            raise TestStoreConflict("test .NET staged source is incomplete")
        source_root = Path(str(binding["source_root"]))
        for archive_path, sha_path, metadata_path, _content_hash in requirements:
            sha_payload, _sha_metadata = cls._dependency_file_bytes(
                source_root,
                sha_path.as_posix(),
                field="test .NET package archive identity",
            )
            try:
                expected_sha512 = nuget_package_sha512_digest(sha_payload)
                _canonical, actual_sha512, _size = (
                    nuget_package_archive_file_digests(staged, archive_path)
                )
            except TestStoreContractError as error:
                raise TestStoreConflict(
                    "test .NET staged package identity is invalid"
                ) from error
            if actual_sha512 != expected_sha512:
                raise TestStoreConflict(
                    "test .NET staged package differs from its checksum"
                )
            metadata_payload, _metadata = cls._dependency_file_bytes(
                source_root,
                metadata_path.as_posix(),
                field="test .NET package restore identity",
            )
            try:
                staged_sha_payload = staged.joinpath(*sha_path.parts).read_bytes()
                staged_metadata_payload = staged.joinpath(
                    *metadata_path.parts
                ).read_bytes()
            except OSError as error:
                raise TestStoreConflict(
                    "test .NET staged package identity is unavailable"
                ) from error
            if (
                staged_sha_payload != sha_payload
                or staged_metadata_payload != metadata_payload
            ):
                raise TestStoreConflict(
                    "test .NET staged package identity is invalid"
                )
            nuspec = staged.joinpath(
                *archive_path.parent.parts,
                f"{archive_path.parts[-3]}.nuspec",
            )
            try:
                expected_nuspec = cls._nuget_nuspec_payload(
                    staged.joinpath(*archive_path.parts)
                )
                actual_nuspec = nuspec.read_bytes()
            except OSError as error:
                raise TestStoreConflict(
                    "test .NET staged package manifest is unavailable"
                ) from error
            if actual_nuspec != expected_nuspec:
                raise TestStoreConflict(
                    "test .NET staged package manifest is invalid"
                )
        return staged

    @staticmethod
    def _nuget_nuspec_payload(archive: Path) -> bytes:
        try:
            with zipfile.ZipFile(archive) as package:
                candidates = [
                    item
                    for item in package.infolist()
                    if "/" not in item.filename.strip("/")
                    and item.filename.lower().endswith(".nuspec")
                    and not item.is_dir()
                ]
                if (
                    len(candidates) != 1
                    or candidates[0].file_size <= 0
                    or candidates[0].file_size > 4 * 1024 * 1024
                ):
                    raise TestStoreConflict(
                        "test .NET package manifest is missing or excessive"
                    )
                payload = package.read(candidates[0])
        except (OSError, zipfile.BadZipFile, RuntimeError) as error:
            raise TestStoreConflict(
                "test .NET package archive is not a readable NuGet package"
            ) from error
        if len(payload) != candidates[0].file_size:
            raise TestStoreConflict("test .NET package manifest is incomplete")
        return payload

    def _publish_runner_launch(
        self,
        descriptor: TestAttemptDescriptor,
        *,
        state: Path,
        execution_root: Path,
        owner_gid: int,
        launch_ticket_id: str | None = None,
    ) -> tuple[Path, Path]:
        output = state / "output"
        output.mkdir(mode=0o700)
        os.chown(output, descriptor.owner_uid, owner_gid)
        result_path = output / "result.json"
        launch_path = state / "launch.json"
        runtime_environment = dict(descriptor.environment)
        for binding in descriptor.dependency_bindings:
            if binding["kind"] == "dotnet-packages":
                destination = execution_root.joinpath(
                    *PurePosixPath(str(binding["destination"])).parts
                )
                runtime_environment["DEVCOORDINATOR_NUGET_SOURCE"] = str(destination)
        runtime_descriptor = replace(
            descriptor,
            execution_root=str(execution_root),
            environment=runtime_environment,
        )
        document: dict[str, object] = {
            "schema_version": 1 if launch_ticket_id is None else 2,
            "descriptor": runtime_descriptor.to_document(),
            "descriptor_fingerprint": runtime_descriptor.fingerprint,
            "output_root": str(output),
            "result_path": str(result_path),
        }
        if launch_ticket_id is not None:
            launch_ticket_id = _safe_id("launch_ticket_id", launch_ticket_id)
            if not launch_ticket_id.startswith("test-ticket-"):
                raise TestStoreContractError("test launch ticket identity is invalid")
            document["launch_ticket_id"] = launch_ticket_id
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > 256 * 1024:
            raise TestStoreContractError("test runner launch descriptor is excessive")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        # security-assumptions.md defines local Unix accounts as attribution
        # domains for one trusted developer. This bounded descriptor contains
        # no credentials; publish it root-owned and readable, but never
        # writable, by repository accounts. Secrets remain in LoadCredential.
        descriptor_fd = os.open(launch_path, flags, 0o444)
        try:
            os.fchmod(descriptor_fd, 0o444)
            os.write(descriptor_fd, payload)
            os.fsync(descriptor_fd)
        finally:
            os.close(descriptor_fd)
        return launch_path, result_path

    def _recover_launch_evidence(
        self, runtime_id: str
    ) -> tuple[TestAttemptDescriptor, str | None]:
        runtime_id = _safe_id("runtime_id", runtime_id)
        state = self.attempt_root / runtime_id
        if state.parent != self.attempt_root:
            raise TestStoreConflict("test attempt runtime is outside its store")
        launch_path = state / "launch.json"
        try:
            metadata = launch_path.lstat()
            payload = launch_path.read_bytes()
            current = launch_path.lstat()
        except FileNotFoundError as error:
            raise TestAttemptRuntimeNotFound(
                "test attempt launch evidence is absent"
            ) from error
        except OSError as error:
            raise TestStoreConflict("test attempt launch evidence is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > 256 * 1024
            or (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (current.st_dev, current.st_ino, current.st_size)
        ):
            raise TestStoreConflict("test attempt launch evidence is unsafe")
        try:
            document = json.loads(payload)
            common_fields = {
                "schema_version",
                "descriptor",
                "descriptor_fingerprint",
                "output_root",
                "result_path",
            }
            if (
                not isinstance(document, Mapping)
                or document.get("schema_version") not in {1, 2}
                or set(document)
                != (
                    common_fields
                    if document.get("schema_version") == 1
                    else common_fields | {"launch_ticket_id"}
                )
            ):
                raise ValueError("invalid fields")
            descriptor = TestAttemptDescriptor.from_document(document["descriptor"])
            launch_ticket_id = (
                None
                if document["schema_version"] == 1
                else _safe_id("launch_ticket_id", document["launch_ticket_id"])
            )
            if launch_ticket_id is not None and not launch_ticket_id.startswith(
                "test-ticket-"
            ):
                raise ValueError("invalid launch ticket")
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            TestStoreContractError,
        ) as error:
            raise TestStoreConflict("test attempt launch evidence is invalid") from error
        output_root = state / "output"
        if (
            document["descriptor_fingerprint"] != descriptor.fingerprint
            or document["output_root"] != str(output_root)
            or document["result_path"] != str(output_root / "result.json")
            or self._runtime_id(descriptor) != runtime_id
        ):
            raise TestStoreConflict("test attempt launch identity is contradictory")
        return descriptor, launch_ticket_id

    def recover_descriptor(self, runtime_id: str) -> TestAttemptDescriptor:
        """Recover exact runtime ownership from the protected launch record."""

        descriptor, _launch_ticket_id = self._recover_launch_evidence(runtime_id)
        return descriptor

    def recover_launch_binding(
        self, runtime_id: str
    ) -> tuple[TestAttemptDescriptor, str | None]:
        """Recover the descriptor and broker ticket bound before native start."""

        return self._recover_launch_evidence(runtime_id)

    def _read_runner_result(self, runtime_id: str) -> Mapping[str, object] | None:
        state = self.attempt_root / runtime_id
        launch_path = state / "launch.json"
        result_path = state / "output" / "result.json"
        try:
            launch_info = launch_path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(launch_info.st_mode)
            or stat.S_ISLNK(launch_info.st_mode)
            or launch_info.st_size > 256 * 1024
        ):
            raise TestStoreConflict("test runner launch evidence is unsafe")
        try:
            launch = json.loads(launch_path.read_bytes())
            if not isinstance(launch, Mapping):
                raise ValueError("not an object")
            descriptor = TestAttemptDescriptor.from_document(launch["descriptor"])
            result_info = result_path.lstat()
        except FileNotFoundError:
            return None
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner launch evidence is invalid") from error
        if (
            not stat.S_ISREG(result_info.st_mode)
            or stat.S_ISLNK(result_info.st_mode)
            or result_info.st_size > 2 * 1024 * 1024
        ):
            raise TestStoreConflict("test runner result evidence is unsafe")
        try:
            value = json.loads(result_path.read_bytes())
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner result evidence is invalid") from error
        if not isinstance(value, Mapping):
            raise TestStoreConflict("test runner result evidence is invalid")
        return dict(value)

    def _runner_output_progress(
        self, runtime_id: str
    ) -> Mapping[str, object] | None:
        """Observe bounded capture growth without reading repository output text."""

        launch_path = self.attempt_root / runtime_id / "launch.json"
        try:
            launch_metadata = launch_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise TestStoreConflict("test runner launch evidence is invalid") from error
        try:
            if (
                not stat.S_ISREG(launch_metadata.st_mode)
                or stat.S_ISLNK(launch_metadata.st_mode)
                or launch_metadata.st_size > 256 * 1024
            ):
                raise ValueError("unsafe launch evidence")
            launch = json.loads(launch_path.read_bytes())
            if not isinstance(launch, Mapping):
                raise ValueError("invalid launch evidence")
            descriptor = TestAttemptDescriptor.from_document(launch["descriptor"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner launch evidence is invalid") from error
        output = self.attempt_root / runtime_id / "output"
        progress: dict[str, object] = {}
        latest_output_at: float | None = None
        for stream in ("stdout", "stderr"):
            path = output / f"{descriptor.attempt_id}-{stream}.log"
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                retained_bytes = 0
                capture_mtime = None
            except OSError as error:
                raise TestStoreConflict(
                    "test runner output progress is unavailable"
                ) from error
            else:
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_size < 0
                    or metadata.st_size > 4 * 1024 * 1024
                ):
                    raise TestStoreConflict("test runner output progress is unsafe")
                retained_bytes = int(metadata.st_size)
                capture_mtime = float(metadata.st_mtime)
            progress_path = path.with_name(path.name + ".progress.json")
            try:
                progress_metadata = progress_path.lstat()
            except FileNotFoundError:
                observed_bytes = retained_bytes
                truncated = False
                stream_last_output_at = (
                    capture_mtime if retained_bytes else None
                )
            except OSError as error:
                raise TestStoreConflict(
                    "test runner output progress is unavailable"
                ) from error
            else:
                if (
                    not stat.S_ISREG(progress_metadata.st_mode)
                    or stat.S_ISLNK(progress_metadata.st_mode)
                    or not 1 <= progress_metadata.st_size <= 4_096
                ):
                    raise TestStoreConflict("test runner output progress is unsafe")
                try:
                    raw_progress = json.loads(progress_path.read_bytes())
                except (OSError, ValueError, json.JSONDecodeError) as error:
                    raise TestStoreConflict(
                        "test runner output progress is invalid"
                    ) from error
                if not isinstance(raw_progress, Mapping) or set(raw_progress) != {
                    "schema_version",
                    "observed_bytes",
                    "retained_bytes",
                    "truncated",
                    "last_output_at",
                }:
                    raise TestStoreConflict("test runner output progress is invalid")
                observed_bytes = raw_progress["observed_bytes"]
                published_retained = raw_progress["retained_bytes"]
                truncated = raw_progress["truncated"]
                stream_last_output_at = raw_progress["last_output_at"]
                if (
                    raw_progress["schema_version"] != 1
                    or type(observed_bytes) is not int
                    or not 0 <= observed_bytes <= (1 << 63) - 1
                    or type(published_retained) is not int
                    or published_retained != retained_bytes
                    or type(truncated) is not bool
                    or truncated != (observed_bytes > retained_bytes)
                    or (
                        stream_last_output_at is None
                        and observed_bytes > 0
                    )
                    or (
                        stream_last_output_at is not None
                        and (
                            isinstance(stream_last_output_at, bool)
                            or not isinstance(stream_last_output_at, (int, float))
                            or not math.isfinite(float(stream_last_output_at))
                            or float(stream_last_output_at) < 0
                        )
                    )
                ):
                    raise TestStoreConflict("test runner output progress is invalid")
            progress[f"{stream}_bytes"] = observed_bytes
            progress[f"{stream}_retained_bytes"] = retained_bytes
            progress[f"{stream}_truncated"] = truncated
            if stream_last_output_at is not None:
                latest_output_at = max(
                    latest_output_at or float(stream_last_output_at),
                    float(stream_last_output_at),
                )
        return {
            **progress,
            "last_output_at": latest_output_at,
            "observed_at": float(self.clock()),
        }

    def read_result_chunk(
        self, runtime_id: str, chunk_index: int
    ) -> Mapping[str, object] | None:
        """Read one digest-bound owner-private chunk without exposing its path."""

        runtime_id = _safe_id("runtime_id", runtime_id)
        if type(chunk_index) is not int or not 0 <= chunk_index < 4_096:
            raise TestStoreContractError("test result chunk index is invalid")
        result = self._read_runner_result(runtime_id)
        if result is None:
            return None
        manifest = result.get("chunk_manifest")
        if (
            not isinstance(manifest, list)
            or len(manifest) > 4_096
            or chunk_index >= len(manifest)
        ):
            return None
        item = manifest[chunk_index]
        if not isinstance(item, Mapping) or set(item) != {
            "chunk_id",
            "chunk_index",
            "file_name",
            "sha256",
            "size_bytes",
            "reporter_complete",
        }:
            raise TestStoreConflict("test runner chunk manifest is invalid")
        file_name = item["file_name"]
        digest = item["sha256"]
        size_bytes = item["size_bytes"]
        if (
            item["chunk_index"] != chunk_index
            or not isinstance(file_name, str)
            or file_name != f"result-chunk-{chunk_index:06d}.json"
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size_bytes) is not int
            or not 1 <= size_bytes <= 240 * 1024
            or type(item["reporter_complete"]) is not bool
        ):
            raise TestStoreConflict("test runner chunk manifest is invalid")
        launch_path = self.attempt_root / runtime_id / "launch.json"
        try:
            launch = json.loads(launch_path.read_bytes())
            descriptor = TestAttemptDescriptor.from_document(launch["descriptor"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner launch evidence is invalid") from error
        path = self.attempt_root / runtime_id / "output" / file_name
        try:
            before = path.lstat()
        except OSError as error:
            raise TestStoreConflict("test runner result chunk is unavailable") from error
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size != size_bytes
        ):
            raise TestStoreConflict("test runner result chunk evidence is unsafe")
        try:
            payload = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise TestStoreConflict("test runner result chunk is unavailable") from error
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or hashlib.sha256(payload).hexdigest() != digest
        ):
            raise TestStoreConflict("test runner result chunk changed during read")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner result chunk JSON is invalid") from error
        if (
            not isinstance(value, Mapping)
            or value.get("chunk_id") != item["chunk_id"]
            or value.get("chunk_index") != chunk_index
            or value.get("reporter_complete") != item["reporter_complete"]
        ):
            raise TestStoreConflict("test runner result chunk identity is invalid")
        return dict(value)

    @staticmethod
    def _artifact_identity(storage_handle: object) -> tuple[str, str]:
        if not isinstance(storage_handle, str):
            raise TestStoreContractError("test artifact handle is invalid")
        matched = re.fullmatch(
            r"test-artifact://(artifact-[0-9a-f]{32})/([0-9a-f]{64})",
            storage_handle,
        )
        if matched is None:
            raise TestStoreContractError("test artifact handle is invalid")
        return matched.group(1), matched.group(2)

    def _artifact_file(self, artifact_id: str, digest: str) -> Path:
        return self.artifact_root / f"{artifact_id}-{digest}.blob"

    def _ensure_artifact_root(self) -> None:
        self.artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self._require_real_directory(
            self.artifact_root, field="test artifact store"
        )

    def _collect_result_artifacts(
        self,
        runtime_id: str,
        result: Mapping[str, object],
    ) -> None:
        raw_sources = result.get("artifact_sources")
        if not isinstance(raw_sources, list) or len(raw_sources) > 64:
            raise TestStoreConflict("test artifact source manifest is invalid")
        launch_path = self.attempt_root / runtime_id / "launch.json"
        try:
            launch = json.loads(launch_path.read_bytes())
            descriptor = TestAttemptDescriptor.from_document(launch["descriptor"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise TestStoreConflict("test runner launch evidence is invalid") from error
        self._ensure_artifact_root()
        credential_sequences: tuple[bytes, ...] | None = None
        seen: set[str] = set()
        for raw in raw_sources:
            if not isinstance(raw, Mapping) or set(raw) != {
                "artifact_id",
                "storage_handle",
                "kind",
                "scope",
                "relative_path",
                "packaged_from",
                "sha256",
                "size_bytes",
            }:
                raise TestStoreConflict("test artifact source fields are invalid")
            artifact_id, handle_digest = self._artifact_identity(
                raw["storage_handle"]
            )
            relative = raw["relative_path"]
            kind = raw["kind"]
            packaged_from = raw["packaged_from"]
            size_bytes = raw["size_bytes"]
            if (
                raw["artifact_id"] != artifact_id
                or raw["sha256"] != handle_digest
                or artifact_id in seen
                or raw["scope"] not in {"output", "execution"}
                or kind not in {
                    "log", "jsonl", "junit", "trx", "coverage", "trace", "directory"
                }
                or not isinstance(relative, str)
                or not relative
                or PurePosixPath(relative).is_absolute()
                or any(part in {".", ".."} for part in PurePosixPath(relative).parts)
                or type(size_bytes) is not int
                or not 0 <= size_bytes <= 32 * 1024 * 1024
                or (
                    kind == "directory"
                    and (
                        not isinstance(packaged_from, str)
                        or not packaged_from
                        or PurePosixPath(packaged_from).is_absolute()
                        or any(
                            part in {".", ".."}
                            for part in PurePosixPath(packaged_from).parts
                        )
                    )
                )
                or (kind != "directory" and packaged_from is not None)
            ):
                raise TestStoreConflict("test artifact source identity is invalid")
            seen.add(artifact_id)
            source_root = (
                self.attempt_root / runtime_id / "output"
                if raw["scope"] == "output"
                else Path(descriptor.execution_root)
            )
            source = source_root / relative
            try:
                resolved = source.resolve(strict=True)
                root_resolved = source_root.resolve(strict=True)
                before = source.lstat()
            except OSError as error:
                raise TestStoreConflict("test artifact source is unavailable") from error
            if (
                resolved != source
                or (resolved != root_resolved and root_resolved not in resolved.parents)
                or not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_size != size_bytes
            ):
                raise TestStoreConflict("test artifact source is unsafe")
            destination = self._artifact_file(artifact_id, handle_digest)
            if destination.exists():
                self.resolve_artifact(
                    str(raw["storage_handle"]),
                    expected_size=size_bytes,
                )
                continue
            if kind == "directory":
                if credential_sequences is None:
                    credential_sequences = self._credential_artifact_sequences(
                        runtime_id,
                        descriptor,
                    )
                if any(
                    value in os.fsencode(str(packaged_from))
                    for value in credential_sequences
                ):
                    raise TestStoreConflict(
                        "test directory artifact path contains credential material"
                    )
                directory_source = Path(descriptor.execution_root) / str(packaged_from)
                try:
                    directory_resolved = directory_source.resolve(strict=True)
                    execution_resolved = Path(descriptor.execution_root).resolve(strict=True)
                except OSError as error:
                    raise TestStoreConflict(
                        "test directory artifact source is unavailable"
                    ) from error
                if (
                    directory_resolved != directory_source
                    or (
                        directory_resolved != execution_resolved
                        and execution_resolved not in directory_resolved.parents
                    )
                ):
                    raise TestStoreConflict("test directory artifact source is unsafe")
                destination_fd = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    with os.fdopen(os.dup(destination_fd), "wb", closefd=True) as output:
                        evidence = package_directory(
                            directory_source,
                            output,
                            expected_uid=descriptor.owner_uid,
                            maximum_bytes=size_bytes,
                            prohibited_sequences=credential_sequences,
                        )
                        output.flush()
                    os.fsync(destination_fd)
                except Exception:
                    destination.unlink(missing_ok=True)
                    raise
                finally:
                    os.close(destination_fd)
                if evidence.sha256 != handle_digest or evidence.size_bytes != size_bytes:
                    destination.unlink(missing_ok=True)
                    raise TestStoreConflict(
                        "test directory artifact differs from protected packaging"
                    )
                continue
            source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                destination_fd = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                digest = hashlib.sha256()
                copied = 0
                try:
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > size_bytes:
                            raise TestStoreConflict("test artifact source grew during collection")
                        digest.update(chunk)
                        view = memoryview(chunk)
                        written = 0
                        while written < len(view):
                            written += os.write(destination_fd, view[written:])
                    os.fsync(destination_fd)
                finally:
                    os.close(destination_fd)
            except Exception:
                destination.unlink(missing_ok=True)
                raise
            finally:
                os.close(source_fd)
            after = source.lstat()
            if (
                copied != size_bytes
                or digest.hexdigest() != handle_digest
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
            ):
                destination.unlink(missing_ok=True)
                raise TestStoreConflict("test artifact source changed during collection")
        directory_fd = os.open(
            self.artifact_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def resolve_artifact(
        self,
        storage_handle: str,
        *,
        expected_size: int | None = None,
    ) -> Path:
        """Resolve an exact opaque handle only after identity/integrity checks."""

        artifact_id, digest = self._artifact_identity(storage_handle)
        path = self._artifact_file(artifact_id, digest)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise TestStoreConflict("test artifact is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (expected_size is not None and metadata.st_size != expected_size)
        ):
            raise TestStoreConflict("test artifact evidence is invalid")
        try:
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError as error:
            raise TestStoreConflict("test artifact is unavailable") from error
        observed = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                observed.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (path_after.st_dev, path_after.st_ino)
            or observed.hexdigest() != digest
        ):
            raise TestStoreConflict("test artifact evidence is invalid")
        return path

    def _execution_directory(
        self,
        descriptor: TestAttemptDescriptor,
        *,
        execution_root: Path | None = None,
    ) -> str:
        root = execution_root or Path(descriptor.execution_root)
        metadata = self._require_real_directory(root, field="test execution root")
        if descriptor.source_mode != "live" and execution_root is None:
            raise TestStoreConflict(
                "immutable test execution root is not an attempt materialization"
            )
        cwd = (root / descriptor.cwd).resolve(strict=True)
        if cwd != root and root not in cwd.parents:
            raise TestStoreConflict("test working directory escapes execution root")
        if not cwd.is_dir() or cwd.is_symlink():
            raise TestStoreConflict("test working directory is unsafe")
        return str(cwd)

    def _run(self, argv: Sequence[str], *, allow_failure: bool = False) -> subprocess.CompletedProcess[str]:
        try:
            completed = self.runner(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise TestStoreConflict("native test attempt manager is unavailable") from error
        if len(completed.stdout or "") + len(completed.stderr or "") > 1024 * 1024:
            raise TestStoreConflict("native test attempt manager returned excessive output")
        if completed.returncode != 0 and not allow_failure:
            detail = " ".join(
                str(completed.stderr or completed.stdout or "").split()
            )[:1024]
            _LOGGER.error(
                "native test attempt manager refused operation executable=%s "
                "returncode=%s detail=%s",
                Path(str(argv[0])).name if argv else "unknown",
                completed.returncode,
                detail or "no diagnostic output",
            )
            raise TestStoreConflict(
                "native test attempt manager refused the operation"
                + (f": {detail}" if detail else "")
            )
        return completed

    @staticmethod
    def _external_toolchain_roots(
        executable: Path, *, execution_root: Path
    ) -> tuple[Path, Path] | None:
        """Return the exact package-manager source and lexical mount target.

        ProtectHome hides local homes. Repository-local virtual environments
        may nevertheless use an absolute symlink into a package manager's
        versioned toolchain. Bind the resolved versioned directory at the
        symlink's stable lexical directory so the interpreter, standard
        library, and shared objects resolve without exposing the account home.
        """

        unresolved_executable = executable
        raw_link_target: Path | None = None
        try:
            if unresolved_executable.is_symlink():
                raw_link_target = Path(os.readlink(unresolved_executable))
                if not raw_link_target.is_absolute():
                    raw_link_target = unresolved_executable.parent / raw_link_target
            executable = unresolved_executable.resolve(strict=True)
            execution_root = execution_root.resolve(strict=True)
        except OSError:
            # The trusted runner will publish the bounded bootstrap failure.
            return None
        if executable == execution_root or execution_root in executable.parents:
            return None
        parts = executable.parts
        if len(parts) >= 4 and parts[:2] == ("/", "home"):
            home_root = Path("/", "home", parts[2])
        elif len(parts) >= 3 and parts[:2] == ("/", "root"):
            home_root = Path("/root")
        else:
            return None
        parent = executable.parent
        source_root = (
            parent.parent
            if parent.name == "bin" and parent.parent != home_root
            else parent
        )
        if source_root == home_root or home_root not in source_root.parents:
            return None
        destination_root = source_root
        if raw_link_target is not None:
            raw_parent = raw_link_target.parent
            destination_root = (
                raw_parent.parent
                if raw_parent.name == "bin" and raw_parent.parent != home_root
                else raw_parent
            )
            try:
                relative_destination = destination_root.relative_to(home_root)
            except ValueError:
                return None
            if len(relative_destination.parts) < 2:
                return None
        try:
            source_metadata = source_root.lstat()
            resolved_source = source_root.resolve(strict=True)
        except OSError:
            return None
        if (
            not stat.S_ISDIR(source_metadata.st_mode)
            or stat.S_ISLNK(source_metadata.st_mode)
            or resolved_source != source_root
        ):
            return None
        return source_root, destination_root

    @classmethod
    def _validate_standalone_toolchain(
        cls, binding: Mapping[str, object]
    ) -> Path:
        source_root = Path(str(binding["source_root"]))
        source_metadata = cls._require_real_directory(
            source_root, field="standalone test toolchain root"
        )
        if (
            source_metadata.st_dev != binding["source_device"]
            or source_metadata.st_ino != binding["source_inode"]
        ):
            raise TestStoreConflict(
                "standalone test toolchain was substituted after planning"
            )
        executable = Path(str(binding["resolved_executable"]))
        try:
            executable_metadata = executable.lstat()
        except OSError as error:
            raise TestStoreConflict(
                "standalone test toolchain executable is unavailable"
            ) from error
        if (
            not stat.S_ISREG(executable_metadata.st_mode)
            or stat.S_ISLNK(executable_metadata.st_mode)
            or executable.resolve(strict=True) != executable
            or source_root not in executable.parents
            or not os.access(executable, os.X_OK)
        ):
            raise TestStoreConflict(
                "standalone test toolchain executable is unsafe"
            )
        identity = cls._installation_manifest_identity(
            source_root, kind=str(binding["installation_kind"])
        )
        if identity != (
            binding["installation_sha256"],
            binding["installation_files"],
            binding["installation_bytes"],
        ):
            raise TestStoreConflict(
                "standalone test toolchain identity changed after planning"
            )
        return source_root

    @classmethod
    def _external_toolchain_bind(
        cls,
        descriptor: TestAttemptDescriptor,
        *,
        execution_root: Path,
        state_root: Path,
    ) -> tuple[str, ...]:
        if descriptor.source_mode == "immutable":
            for toolchain in descriptor.toolchain_bindings:
                source = cls._validate_standalone_toolchain(toolchain)
                return (_systemd_bind_path("immutable .NET toolchain", source),)
            for binding in descriptor.dependency_bindings:
                toolchain = binding.get("toolchain")
                if not isinstance(toolchain, Mapping):
                    continue
                cls._validate_dependency_binding(
                    descriptor,
                    binding,
                    execution_root=execution_root,
                    require_destination=True,
                )
                source = Path(str(toolchain["source_root"]))
                if toolchain["installation_kind"] == "python-toolchain":
                    if source in _SYSTEM_PYTHON_TOOLCHAIN_ROOTS:
                        # The service-owned system toolchain is already visible
                        # inside the isolated unit. Its exact link, inode and
                        # bounded installation identity were revalidated above;
                        # copying all of /usr would be wasteful and less faithful.
                        return ()
                    # security-assumptions.md confirms one trusted local
                    # developer across host accounts while requiring process
                    # isolation and no public source exposure.  Mount the exact
                    # fingerprinted toolchain into this unit's PrivateTmp view
                    # so an absolute venv symlink never depends on traversing a
                    # separately attributed account home.
                    staged = state_root / "immutable-python-toolchain"
                    try:
                        shutil.copytree(
                            source,
                            staged,
                            symlinks=True,
                            copy_function=shutil.copy2,
                        )
                    except OSError as error:
                        raise TestStoreConflict(
                            "immutable Python toolchain could not be staged"
                        ) from error
                    try:
                        identity = pwd.getpwuid(descriptor.owner_uid)
                    except KeyError as error:
                        raise TestStoreConflict(
                            "test attempt owner has no local account"
                        ) from error
                    try:
                        for directory, child_directories, files in os.walk(
                            staged, followlinks=False
                        ):
                            os.chown(directory, identity.pw_uid, identity.pw_gid)
                            for name in (*child_directories, *files):
                                os.chown(
                                    Path(directory) / name,
                                    identity.pw_uid,
                                    identity.pw_gid,
                                    follow_symlinks=False,
                                )
                    except OSError as error:
                        raise TestStoreConflict(
                            "immutable Python toolchain ownership could not be staged"
                        ) from error
                    staged_identity = cls._installation_manifest_identity(
                        staged, kind="python-toolchain"
                    )
                    if staged_identity != (
                        toolchain["installation_sha256"],
                        toolchain["installation_files"],
                        toolchain["installation_bytes"],
                    ):
                        raise TestStoreConflict(
                            "staged immutable Python toolchain identity differs"
                        )
                    link_target = Path(str(toolchain["link_target"]))
                    link_destination = (
                        link_target.parent.parent
                        if link_target.parent.name == "bin"
                        else link_target.parent
                    )
                    return (
                        _systemd_bind_mapping(
                            "immutable Python toolchain",
                            staged,
                            _IMMUTABLE_PYTHON_TOOLCHAIN_MOUNT,
                        ),
                        _systemd_bind_mapping(
                            "immutable Python environment link",
                            staged,
                            link_destination,
                        ),
                    )
                return (_systemd_bind_path("immutable .NET toolchain", source),)
            return ()
        executable: Path | None = None
        if executable is None:
            raw = descriptor.argv[0]
            if "/" not in raw:
                return ()
            executable = Path(raw)
            if not executable.is_absolute():
                executable = execution_root / descriptor.cwd / executable
        roots = cls._external_toolchain_roots(
            executable, execution_root=execution_root
        )
        if roots is None:
            return ()
        source, destination = roots
        if source == destination:
            return (_systemd_bind_path("external test toolchain", source),)
        return (
            _systemd_bind_mapping(
                "external test toolchain", source, destination
            ),
        )

    @classmethod
    def _systemd_properties(
        cls,
        descriptor: TestAttemptDescriptor,
        *,
        execution_root: Path,
        output_root: Path,
        fixture_lease: TestFixtureLease | None = None,
        credential_lease: TestCredentialLease | None = None,
    ) -> list[str]:
        exact_execution_root = _systemd_bind_path(
            "test execution root", execution_root
        )
        exact_output_root = _systemd_bind_path("test output root", output_root)
        properties = [
            "--property=Type=exec",
            "--property=CollectMode=inactive-or-failed",
            "--property=CPUAccounting=yes",
            "--property=MemoryAccounting=yes",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=30s",
            "--property=NoNewPrivileges=yes",
            "--property=PrivateTmp=yes",
            "--property=PrivateDevices=yes",
            # Repository tests never receive direct host-container authority.
            # Docker/Compose/database fixtures must be provisioned through a
            # broker-issued fixture capability and exact cleanup ticket.
            "--property=InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock -/run/podman/podman.sock -/var/run/podman/podman.sock -/run/containerd/containerd.sock",
            "--property=ProtectSystem=strict",
            # Keep homes hidden. A repository executable that resolves into a
            # trusted local package-manager toolchain receives one exact,
            # read-only bind below; no account home is exposed wholesale.
            "--property=ProtectHome=tmpfs",
            f"--property=BindPaths={exact_execution_root}",
            (
                "--property=ReadWritePaths="
                f"{exact_execution_root} {exact_output_root}"
            ),
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=UMask=0077",
            "--property=RuntimeMaxSec="
            f"{descriptor.ttl_seconds + TEST_ATTEMPT_RESULT_PUBLICATION_GRACE_SECONDS}s",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
        ]
        if descriptor.supplementary_gids:
            properties.append(
                "--property=SupplementaryGroups="
                + " ".join(str(value) for value in descriptor.supplementary_gids)
            )
        external_toolchains = cls._external_toolchain_bind(
            descriptor,
            execution_root=execution_root,
            state_root=output_root.parent,
        )
        for external_toolchain in external_toolchains:
            properties.append(
                f"--property=BindReadOnlyPaths={external_toolchain}"
            )
        for binding in descriptor.dependency_bindings:
            source, destination = cls._validate_dependency_binding(
                descriptor,
                binding,
                execution_root=execution_root,
                require_destination=True,
            )
            if binding["kind"] == "dotnet-packages":
                source = cls._validated_staged_dotnet_source(
                    descriptor,
                    binding,
                    state=output_root.parent,
                )
            properties.append(
                "--property=BindReadOnlyPaths="
                + _systemd_bind_mapping(
                    "test dependency", source, destination
                )
            )
        credential_files: list[Mapping[str, object]] = []
        if descriptor.network == "host-loopback" and fixture_lease is not None:
            raise TestStoreConflict(
                "host-loopback attempts cannot use a fixture network namespace"
            )
        if fixture_lease is not None:
            namespace = fixture_lease.network_namespace
            _validate_fixture_namespace(fixture_lease)
            if namespace is None:
                raise TestStoreConflict("test fixture network namespace is unavailable")
            namespace_path = Path(str(namespace["path"]))
            properties.append(f"--property=NetworkNamespacePath={namespace_path}")
            credential_files.extend(fixture_lease.credential_files)
        elif descriptor.network in {"none", "loopback"}:
            properties.append("--property=PrivateNetwork=yes")
        if credential_lease is not None:
            credential_files.extend(credential_lease.credential_files)
        names: set[str] = set()
        for raw in credential_files:
            name = str(raw["name"])
            if name in names:
                raise TestStoreConflict("test credential destination name is duplicated")
            names.add(name)
            source = Path(str(raw["source_path"]))
            try:
                path_before = source.lstat()
                descriptor_fd = os.open(
                    source,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                )
            except OSError as error:
                raise TestStoreConflict("test credential is unavailable") from error
            digest = hashlib.sha256()
            verification_digest = hashlib.sha256()
            observed = 0
            try:
                metadata = os.fstat(descriptor_fd)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_size != raw["size_bytes"]
                ):
                    raise TestStoreConflict("test credential is unsafe")
                while True:
                    chunk = os.read(descriptor_fd, 64 * 1024)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > 1024 * 1024:
                        raise TestStoreConflict("test credential is excessive")
                    digest.update(chunk)
                os.lseek(descriptor_fd, 0, os.SEEK_SET)
                verification_observed = 0
                while True:
                    chunk = os.read(descriptor_fd, 64 * 1024)
                    if not chunk:
                        break
                    verification_observed += len(chunk)
                    if verification_observed > 1024 * 1024:
                        raise TestStoreConflict("test credential is excessive")
                    verification_digest.update(chunk)
                current_fd = os.fstat(descriptor_fd)
            finally:
                os.close(descriptor_fd)
            try:
                current_path = source.lstat()
            except OSError as error:
                raise TestStoreConflict("test credential changed") from error
            if (
                _stable_file_identity(metadata)
                != _stable_file_identity(current_fd)
                or _stable_file_identity(current_fd)
                != _stable_file_identity(path_before)
                or _stable_file_identity(path_before)
                != _stable_file_identity(current_path)
                or observed != raw["size_bytes"]
                or verification_observed != observed
                or digest.hexdigest() != raw["sha256"]
                or verification_digest.hexdigest() != raw["sha256"]
            ):
                raise TestStoreConflict("test credential is unsafe")
            properties.append(
                "--property=LoadCredential="
                f"{name}:{_systemd_bind_path('test credential path', source)}"
            )
        if descriptor.network == "none":
            properties.extend(
                (
                    "--property=IPAddressDeny=any",
                    "--property=RestrictAddressFamilies=AF_UNIX",
                )
            )
        elif descriptor.network in {"loopback", "host-loopback"}:
            properties.extend(
                (
                    "--property=IPAddressDeny=any",
                    "--property=IPAddressAllow=localhost",
                    "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                )
            )
        return properties

    def start(self, descriptor: TestAttemptDescriptor) -> NativeTestAttemptState:
        """Compatibility entrypoint for isolated managers without broker binding."""

        return self._start(descriptor, launch_ticket_id=None)

    def start_bound(
        self, descriptor: TestAttemptDescriptor, *, launch_ticket_id: str
    ) -> NativeTestAttemptState:
        """Persist the broker ticket before starting the native runtime."""

        launch_ticket_id = _safe_id("launch_ticket_id", launch_ticket_id)
        if not launch_ticket_id.startswith("test-ticket-"):
            raise TestStoreContractError("test launch ticket identity is invalid")
        return self._start(descriptor, launch_ticket_id=launch_ticket_id)

    def _start(
        self,
        descriptor: TestAttemptDescriptor,
        *,
        launch_ticket_id: str | None,
    ) -> NativeTestAttemptState:
        try:
            identity = pwd.getpwuid(descriptor.owner_uid)
        except KeyError as error:
            raise TestStoreConflict("test attempt owner has no local account") from error
        trusted_runner = self._trusted_runner_script()
        runtime_id = self._runtime_id(descriptor)
        effective_descriptor = self._provision_fixture_descriptor(
            descriptor, runtime_id=runtime_id
        )
        try:
            effective_descriptor = self._provision_credential_descriptor(
                effective_descriptor, runtime_id=runtime_id
            )
        except Exception:
            self._cleanup_attempt_resources(
                runtime_id, reason="credential_provisioning_failed"
            )
            raise
        state: Path | None = None
        try:
            state = self._prepare_attempt_state(runtime_id)
            execution_root = (
                Path(effective_descriptor.execution_root)
                if effective_descriptor.source_mode == "live"
                else self._prepare_attempt_root(
                    effective_descriptor,
                    state=state,
                    owner_gid=identity.pw_gid,
                )
            )
            self._execution_directory(
                effective_descriptor, execution_root=execution_root
            )
            launch_path, _result_path = self._publish_runner_launch(
                effective_descriptor,
                state=state,
                execution_root=execution_root,
                owner_gid=identity.pw_gid,
                launch_ticket_id=launch_ticket_id,
            )
        except Exception:
            if state is not None:
                self._remove_materialization(state)
            self._materialized.pop(runtime_id, None)
            self._cleanup_attempt_resources(
                runtime_id, reason="launch_preparation_failed"
            )
            raise
        output_root = state / "output"
        try:
            properties = self._systemd_properties(
                effective_descriptor,
                execution_root=execution_root,
                output_root=output_root,
                fixture_lease=self._fixture_leases.get(runtime_id),
                credential_lease=self._credential_leases.get(runtime_id),
            )
        except Exception:
            self._remove_materialization(state)
            self._materialized.pop(runtime_id, None)
            self._cleanup_attempt_resources(
                runtime_id, reason="launch_property_validation_failed"
            )
            raise
        argv = [
            self.systemd_run,
            "--quiet",
            "--collect",
            f"--unit={runtime_id}",
            f"--uid={identity.pw_uid}",
            f"--gid={identity.pw_gid}",
            f"--slice={self._repository_slice(effective_descriptor)}",
            f"--working-directory={output_root}",
            *properties,
            "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
            "--setenv=HOME=/tmp/devcoordinator-test-home",
            "--setenv=LANG=C.UTF-8",
            "--setenv=LC_ALL=C.UTF-8",
        ]
        argv.extend(
            (
                "--",
                self.python,
                "-I",
                trusted_runner,
                "--launch",
                str(launch_path),
            )
        )
        try:
            credential_lease = self._credential_leases.get(runtime_id)
            provider = self.credential_provider
            launch_guard = (
                None if provider is None else getattr(provider, "launch_guard", None)
            )
            if credential_lease is not None and not callable(launch_guard):
                raise TestStoreConflict(
                    "operational credential launch guard is unavailable"
                )
            guard = (
                nullcontext()
                if credential_lease is None
                else launch_guard(effective_descriptor, credential_lease)
            )
            with guard:
                self._run(argv)
            lease = self._fixture_leases.get(runtime_id)
            if lease is not None:
                try:
                    _validate_fixture_namespace(lease)
                except Exception:
                    self._run(
                        [self.systemctl, "stop", self._unit(runtime_id)],
                        allow_failure=True,
                    )
                    raise
        except Exception:
            self._remove_materialization(state)
            self._materialized.pop(runtime_id, None)
            self._cleanup_attempt_resources(runtime_id, reason="launch_failed")
            raise
        started_at = float(self.clock())
        self._started[runtime_id] = started_at
        # A successful Type=exec systemd-run reply is the launch
        # acknowledgement. Observing the transient unit is heartbeat work: a
        # temporarily unavailable observer must not turn one accepted native
        # start into a launch rejection that the broker could replay.
        return NativeTestAttemptState(
            runtime_id=runtime_id,
            loaded=True,
            active=True,
            state="running",
            exit_status=None,
            started_at=started_at,
        )

    def _collected_status(self, runtime_id: str) -> NativeTestAttemptState:
        """Drain a durable result after systemd has collected its unit."""

        result_document = self._read_runner_result(runtime_id)
        if result_document is None:
            self._cleanup_attempt_resources(
                runtime_id,
                reason="attempt_not_found_terminal",
            )
            return NativeTestAttemptState(
                runtime_id, False, False, "not-found", None
            )
        returncode = result_document.get("returncode")
        if type(returncode) is not int:
            raise TestStoreConflict("retained test runner result is invalid")
        peak_memory_bytes, cpu_seconds = _runner_resource_usage(result_document)
        try:
            self._collect_result_artifacts(runtime_id, result_document)
        finally:
            self._cleanup_attempt_resources(
                runtime_id, reason="attempt_terminal"
            )
        return NativeTestAttemptState(
            runtime_id=runtime_id,
            loaded=False,
            active=False,
            state="collected",
            exit_status=returncode,
            started_at=self._started.get(runtime_id),
            finished_at=float(self.clock()),
            result_document=result_document,
            systemd_result="success" if returncode == 0 else "exit-code",
            exec_main_code=1,
            termination_reason="success" if returncode == 0 else "exit_code",
            oom_killed=False,
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=cpu_seconds,
        )

    def status(self, runtime_id: str) -> NativeTestAttemptState:
        unit = self._unit(runtime_id)
        completed = self._run(
            [
                self.systemctl,
                "show",
                unit,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=Result",
                "--property=ExecMainCode",
                "--property=ExecMainStatus",
                "--property=OOMKilled",
                "--property=CPUUsageNSec",
                "--property=MemoryPeak",
                "--property=MemoryCurrent",
                "--property=ActiveEnterTimestampMonotonic",
                "--property=InactiveEnterTimestampMonotonic",
                # systemctl suppresses empty properties by default. A newly
                # starting unit legitimately has no terminal status yet, so
                # request the selected empty fields instead of misclassifying
                # a valid launch as a malformed observation.
                "--all",
                "--no-pager",
            ],
            allow_failure=True,
        )
        if completed.returncode != 0:
            # ``systemd-run --collect`` may unload the transient unit before a
            # restarted broker/testd observes it. The root-protected launch
            # record and owner-private, generation-bound runner result remain
            # authoritative and must be drained rather than downgraded to an
            # infrastructure failure merely because the unit was collected.
            return self._collected_status(runtime_id)
        fields: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "=" in line:
                name, value = line.split("=", 1)
                fields[name] = value
        required = {"LoadState", "ActiveState", "SubState"}
        missing = sorted(required - set(fields))
        if missing:
            raise TestStoreConflict(
                "native test attempt observation is incomplete: missing "
                + ", ".join(missing)
            )
        # ``systemctl show`` can itself succeed after ``--collect`` has
        # unloaded a transient unit. In that case it returns a synthetic
        # not-found record whose success/zero exit fields are defaults, not
        # terminal evidence. Drain the generation-bound durable result just as
        # when the observation command fails.
        if fields["LoadState"] == "not-found":
            return self._collected_status(runtime_id)
        # ``deactivating`` is a transitional state, not terminal evidence.
        # systemd can expose Result=success/ExecMainCode=0 while the unit is
        # still draining and before the runner has atomically published its
        # result document.  Treating that window as exited loses the result and
        # turns a healthy attempt into a fabricated infrastructure failure.
        active = fields["ActiveState"] in {
            "active",
            "activating",
            "deactivating",
            "reloading",
        }
        status = fields.get("ExecMainStatus", "")
        exit_status = int(status) if status.lstrip("-").isdigit() else None
        raw_code = fields.get("ExecMainCode", "")
        exec_main_code = int(raw_code) if raw_code.lstrip("-").isdigit() else None
        raw_oom = fields.get("OOMKilled", "")
        if raw_oom not in {"", "yes", "no"}:
            raise TestStoreConflict("native test attempt OOM observation is invalid")
        oom_killed = raw_oom == "yes"
        systemd_result = fields.get("Result", "")
        peak_memory_bytes = _systemd_counter(
            fields.get("MemoryPeak"), field="peak memory measurement"
        )
        cpu_usage_nsec = _systemd_counter(
            fields.get("CPUUsageNSec"), field="CPU measurement"
        )
        cpu_seconds = (
            None if cpu_usage_nsec is None else float(cpu_usage_nsec) / 1_000_000_000
        )
        current_memory_bytes = _systemd_counter(
            fields.get("MemoryCurrent"), field="current memory measurement"
        )
        termination_reason = None
        if not active:
            if oom_killed or systemd_result == "oom-kill":
                termination_reason = "oom_kill"
            elif systemd_result == "timeout":
                termination_reason = "timeout"
            elif systemd_result in {"signal", "core-dump", "watchdog"} or exec_main_code in {2, 3}:
                termination_reason = "signal"
            elif systemd_result == "exit-code" or (
                exec_main_code == 1 and exit_status not in {None, 0}
            ):
                termination_reason = "exit_code"
            elif systemd_result == "success" and exit_status == 0:
                termination_reason = "success"
            elif systemd_result == "resources":
                termination_reason = "resource_failure"
            elif systemd_result == "start-limit-hit":
                termination_reason = "start_limit"
            elif systemd_result == "protocol":
                termination_reason = "protocol_failure"
            else:
                termination_reason = "systemd_failure"
        started = self._started.get(runtime_id)
        output_progress = self._runner_output_progress(runtime_id) if active else None
        result_document = self._read_runner_result(runtime_id) if active else None
        if not active:
            try:
                result_document = self._read_runner_result(runtime_id)
                if result_document is not None:
                    self._collect_result_artifacts(runtime_id, result_document)
            finally:
                self._cleanup_attempt_resources(
                    runtime_id, reason="attempt_terminal"
                )
            runner_peak_memory, runner_cpu_seconds = _runner_resource_usage(
                result_document
            )
            # Cgroup accounting covers the entire transient unit and is the
            # authoritative measurement when systemd provides it. The
            # owner-written getrusage values are a durable fallback for
            # collected units or unavailable accounting fields.
            if peak_memory_bytes is None and runner_peak_memory is not None:
                peak_memory_bytes = runner_peak_memory
            if cpu_seconds is None and runner_cpu_seconds is not None:
                cpu_seconds = runner_cpu_seconds
        return NativeTestAttemptState(
            runtime_id=runtime_id,
            loaded=fields["LoadState"] == "loaded",
            active=active,
            state=fields["SubState"],
            exit_status=None if active else exit_status,
            started_at=started,
            finished_at=None if active or started is None else float(self.clock()),
            result_document=result_document,
            systemd_result=None if active else systemd_result,
            exec_main_code=None if active else exec_main_code,
            termination_reason=termination_reason,
            oom_killed=False if active else oom_killed,
            peak_memory_bytes=peak_memory_bytes,
            cpu_seconds=cpu_seconds,
            current_memory_bytes=(current_memory_bytes if active else None),
            output_progress=output_progress,
        )

    def cancel(self, runtime_id: str) -> NativeTestAttemptState:
        unit = self._unit(runtime_id)
        self._run([self.systemctl, "stop", unit], allow_failure=True)
        state = self.status(runtime_id)
        if state.active:
            # A runner can leave a descendant or obsolete release process in
            # its exact transient cgroup after the main result is complete.
            # Cancellation owns this deterministic unit, so escalate only its
            # control group and then require one fresh observation.
            self._run(
                [
                    self.systemctl,
                    "kill",
                    "--kill-whom=all",
                    "--signal=KILL",
                    unit,
                ],
                allow_failure=True,
            )
            self._run([self.systemctl, "stop", unit], allow_failure=True)
            state = self.status(runtime_id)
        return state

    def collect(self, runtime_id: str) -> None:
        state = self.status(runtime_id)
        if state.active:
            raise TestStoreConflict("active test attempt cannot be collected")
        self._run([self.systemctl, "reset-failed", self._unit(runtime_id)], allow_failure=True)
        materialized = self._materialized.pop(runtime_id, None)
        if materialized is None:
            candidate = self.attempt_root / runtime_id
            if candidate.exists():
                materialized = candidate
        if materialized is not None:
            self._remove_materialization(materialized)
        self._started.pop(runtime_id, None)


@dataclass(frozen=True)
class _TicketRecord:
    ticket_id: str
    descriptor: TestAttemptDescriptor
    issued_at: float
    expires_at: float
    runtime_id: str | None = None


class BrokerTestAttemptCoordinator:
    """Exact transient-runtime coordinator with protected launch recovery."""

    def __init__(
        self,
        manager: NativeTestAttemptManager,
        *,
        clock: Callable[[], float] = time.time,
        ticket_seconds: int = 60,
    ) -> None:
        if not isinstance(manager, NativeTestAttemptManager):
            raise TestStoreContractError("native test attempt manager is invalid")
        self.manager = manager
        self.clock = clock
        self.ticket_seconds = _positive_integer("ticket_seconds", ticket_seconds, maximum=300)
        self._tickets: dict[str, _TicketRecord] = {}
        self._runtimes: dict[str, str] = {}
        self._recovered_runtimes: dict[str, TestAttemptDescriptor] = {}

    def issue(
        self,
        descriptor: TestAttemptDescriptor,
        *,
        launch_timeout_seconds: int | None = None,
    ) -> dict[str, object]:
        now = float(self.clock())
        if launch_timeout_seconds is not None:
            launch_timeout_seconds = _positive_integer(
                "launch_timeout_seconds", launch_timeout_seconds, maximum=3_600
            )
        ticket_lifetime = (
            self.ticket_seconds
            if launch_timeout_seconds is None
            else max(self.ticket_seconds, launch_timeout_seconds + 30)
        )
        ticket_id = "test-ticket-" + uuid.uuid4().hex
        public = {
            "ticket_id": ticket_id,
            "attempt_id": descriptor.attempt_id,
            "target_id": descriptor.target_id,
            "run_id": descriptor.run_id,
            "repository_id": descriptor.repository_id,
            "repository_generation": descriptor.repository_generation,
            "owner_uid": descriptor.owner_uid,
            "generation": descriptor.generation,
            "intent": descriptor.intent,
            "root_repo": descriptor.original_root,
            "temporary_repo": descriptor.temporary_root,
            "execution_root": descriptor.execution_root,
            "argv": list(descriptor.argv),
            "cwd": descriptor.cwd,
            "environment": dict(descriptor.environment),
            "driver": descriptor.driver,
            "reporter": descriptor.reporter,
            "artifacts": [dict(item) for item in descriptor.artifacts],
            "fixtures": list(descriptor.fixtures),
            "credentials": list(descriptor.credentials),
            "network": descriptor.network,
            "ttl_seconds": descriptor.ttl_seconds,
            "kill_after_run": True,
            "resources": {
                "cpu_millis": descriptor.cpu_millis,
                "memory_mib": descriptor.memory_mib,
                "pids": descriptor.pids,
            },
            "worktree_key": descriptor.worktree_key,
            "issued_at": now,
            "expires_at": now + ticket_lifetime,
        }
        record = _TicketRecord(
            ticket_id=ticket_id,
            descriptor=descriptor,
            issued_at=now,
            expires_at=now + ticket_lifetime,
        )
        self._tickets[ticket_id] = record
        return public

    def launch(
        self,
        *,
        ticket_id: str,
        attempt_id: str,
        generation: int,
        expected_repository_id: str | None = None,
        expected_repository_generation: int | None = None,
    ) -> dict[str, object]:
        ticket_id = _safe_id("ticket_id", ticket_id)
        attempt_id = _safe_id("attempt_id", attempt_id)
        if expected_repository_id is not None:
            expected_repository_id = _safe_id(
                "expected_repository_id", expected_repository_id
            )
        if expected_repository_generation is not None and (
            type(expected_repository_generation) is not int
            or expected_repository_generation < 0
        ):
            raise TestStoreContractError(
                "expected_repository_generation must be non-negative"
            )
        record = self._tickets.get(ticket_id)
        if record is None:
            return self._recover_launched_runtime(
                ticket_id=ticket_id,
                attempt_id=attempt_id,
                generation=generation,
                expected_repository_id=expected_repository_id,
                expected_repository_generation=expected_repository_generation,
            )
        if (
            record.descriptor.attempt_id != attempt_id
            or type(generation) is not int
            or record.descriptor.generation != generation
        ):
            raise TestStoreConflict("test attempt ticket generation is stale")
        self._require_launch_request_binding(
            record.descriptor,
            expected_repository_id=expected_repository_id,
            expected_repository_generation=expected_repository_generation,
        )
        if record.runtime_id is not None:
            return {
                "runtime_id": record.runtime_id,
                "launch_ack_id": "test-launch-" + record.ticket_id.removeprefix("test-ticket-"),
            }
        if record.expires_at <= float(self.clock()):
            raise TestStoreConflict("test attempt ticket expired")
        start_bound = getattr(self.manager, "start_bound", None)
        state = (
            start_bound(record.descriptor, launch_ticket_id=ticket_id)
            if callable(start_bound)
            else self.manager.start(record.descriptor)
        )
        expected_runtime_id = _runtime_id_for_attempt(attempt_id)
        state = self._require_exact_native_state(expected_runtime_id, state)
        replacement = _TicketRecord(**{**record.__dict__, "runtime_id": state.runtime_id})
        self._tickets[ticket_id] = replacement
        self._runtimes[state.runtime_id] = ticket_id
        return {
            "runtime_id": state.runtime_id,
            "launch_ack_id": "test-launch-" + record.ticket_id.removeprefix("test-ticket-"),
        }

    @staticmethod
    def _require_launch_request_binding(
        descriptor: TestAttemptDescriptor,
        *,
        expected_repository_id: str | None,
        expected_repository_generation: int | None,
    ) -> None:
        if (
            expected_repository_id is not None
            and (
                descriptor.repository_id != expected_repository_id
                or descriptor.repository_generation
                != expected_repository_generation
            )
        ):
            raise TestStoreConflict(
                "test attempt launch request binding is contradictory"
            )

    def _recover_launched_runtime(
        self,
        *,
        ticket_id: str,
        attempt_id: str,
        generation: int,
        expected_repository_id: str | None,
        expected_repository_generation: int | None,
    ) -> dict[str, object]:
        if (
            expected_repository_id is None
            or expected_repository_generation is None
        ):
            raise TestAttemptLaunchUncertain(
                "test attempt ticket is unknown and lacks recovery binding"
            )
        runtime_id = _runtime_id_for_attempt(attempt_id)
        recover_binding = getattr(self.manager, "recover_launch_binding", None)
        try:
            if callable(recover_binding):
                recovered = recover_binding(runtime_id)
                if (
                    not isinstance(recovered, tuple)
                    or len(recovered) != 2
                    or not isinstance(recovered[0], TestAttemptDescriptor)
                    or (
                        recovered[1] is not None
                        and not isinstance(recovered[1], str)
                    )
                ):
                    raise TestStoreConflict(
                        "recovered test attempt launch binding is invalid"
                    )
                descriptor, bound_ticket_id = recovered
            else:
                recover_descriptor = getattr(self.manager, "recover_descriptor", None)
                if not callable(recover_descriptor):
                    raise TestAttemptRuntimeNotFound(
                        "test attempt launch evidence is absent"
                    )
                descriptor = recover_descriptor(runtime_id)
                bound_ticket_id = None
        except TestAttemptRuntimeNotFound as error:
            raise TestAttemptLaunchUncertain(
                "test attempt launch outcome is not yet observable"
            ) from error

        if (
            descriptor.attempt_id != attempt_id
            or type(generation) is not int
            or descriptor.generation != generation
        ):
            raise TestStoreConflict(
                "recovered test attempt generation is contradictory"
            )
        self._require_launch_request_binding(
            descriptor,
            expected_repository_id=expected_repository_id,
            expected_repository_generation=expected_repository_generation,
        )
        if bound_ticket_id is not None and bound_ticket_id != ticket_id:
            raise TestStoreConflict(
                "recovered test attempt ticket identity is contradictory"
            )
        state = self._require_exact_native_state(
            runtime_id, self.manager.status(runtime_id)
        )
        if (
            not state.loaded
            and not state.active
            and state.result_document is None
            and state.state == "not-found"
        ):
            raise TestAttemptLaunchUncertain(
                "test attempt native launch outcome is not yet observable"
            )

        now = float(self.clock())
        recovered_record = _TicketRecord(
            ticket_id=ticket_id,
            descriptor=descriptor,
            issued_at=now,
            expires_at=now + self.ticket_seconds,
            runtime_id=runtime_id,
        )
        self._tickets[ticket_id] = recovered_record
        self._runtimes[runtime_id] = ticket_id
        self._recovered_runtimes[runtime_id] = descriptor
        return {
            "runtime_id": runtime_id,
            "launch_ack_id": "test-launch-"
            + ticket_id.removeprefix("test-ticket-"),
        }

    def ticket_descriptor(self, ticket_id: str) -> TestAttemptDescriptor:
        ticket_id = _safe_id("ticket_id", ticket_id)
        record = self._tickets.get(ticket_id)
        if record is None:
            raise TestStoreConflict("test attempt ticket is unknown")
        return record.descriptor

    def runtime_descriptor(self, runtime_id: str) -> TestAttemptDescriptor:
        runtime_id = _safe_id("runtime_id", runtime_id)
        ticket_id = self._runtimes.get(runtime_id)
        if ticket_id is not None and ticket_id in self._tickets:
            return self._tickets[ticket_id].descriptor
        recovered = self._recovered_runtimes.get(runtime_id)
        if recovered is not None:
            return recovered
        recover = getattr(self.manager, "recover_descriptor", None)
        if not callable(recover):
            raise TestAttemptRuntimeNotFound("test attempt runtime is unknown")
        descriptor = recover(runtime_id)
        if not isinstance(descriptor, TestAttemptDescriptor):
            raise TestStoreConflict("recovered test attempt descriptor is invalid")
        self._recovered_runtimes[runtime_id] = descriptor
        return descriptor

    @staticmethod
    def _require_exact_native_state(
        runtime_id: str, state: NativeTestAttemptState
    ) -> NativeTestAttemptState:
        if (
            not isinstance(state, NativeTestAttemptState)
            or state.runtime_id != runtime_id
            or type(state.loaded) is not bool
            or type(state.active) is not bool
        ):
            raise TestStoreConflict("native test attempt state identity is invalid")
        return state

    def observe(
        self, runtime_id: str, *, result_chunk_index: int = 0
    ) -> dict[str, object]:
        runtime_id = _safe_id("runtime_id", runtime_id)
        if type(result_chunk_index) is not int or not 0 <= result_chunk_index < 4_096:
            raise TestStoreContractError("test result chunk index is invalid")
        state = self.manager.status(runtime_id)
        descriptor = self.runtime_descriptor(runtime_id)
        result_summary: dict[str, object] | None = None
        result_chunk: Mapping[str, object] | None = None
        if state.result_document is not None:
            result = state.result_document
            if not isinstance(result, Mapping) or set(result) != {
                "schema_version",
                "attempt_id",
                "generation",
                "returncode",
                "duration_seconds",
                "peak_memory_bytes",
                "cpu_seconds",
                "incomplete_reporting",
                "terminal_outcome",
                "captures",
                "artifact_sources",
                "chunk_manifest",
            }:
                raise TestStoreConflict("test runner result fields are invalid")
            manifest = result["chunk_manifest"]
            if (
                result["schema_version"] != 3
                or result["attempt_id"] != descriptor.attempt_id
                or result["generation"] != descriptor.generation
                or type(result["returncode"]) is not int
                or type(result["incomplete_reporting"]) is not bool
                or result["terminal_outcome"] not in {
                    "succeeded",
                    "test_failed",
                    "infrastructure_failed",
                    "timed_out",
                    "incomplete",
                }
                or not isinstance(result["captures"], Mapping)
                or not isinstance(result["artifact_sources"], list)
                or not isinstance(manifest, list)
                or not 1 <= len(manifest) <= 4_096
            ):
                raise TestStoreConflict("test runner result identity is invalid")
            result_summary = {
                "schema_version": 3,
                "attempt_id": descriptor.attempt_id,
                "generation": descriptor.generation,
                "returncode": result["returncode"],
                "duration_seconds": result["duration_seconds"],
                "incomplete_reporting": result["incomplete_reporting"],
                "terminal_outcome": result["terminal_outcome"],
                "captures": dict(result["captures"]),
                "chunk_count": len(manifest),
            }
            if result_chunk_index < len(manifest):
                result_chunk = self.manager.read_result_chunk(
                    runtime_id, result_chunk_index
                )
                if result_chunk is None:
                    raise TestStoreConflict("test runner result chunk is unavailable")
        termination_reason = state.termination_reason
        systemd_result = state.systemd_result
        exec_main_code = state.exec_main_code
        peak_memory_bytes = _validated_peak_memory_bytes(
            state.peak_memory_bytes
        )
        cpu_seconds = _validated_cpu_seconds(state.cpu_seconds)
        current_memory_bytes = _validated_peak_memory_bytes(
            state.current_memory_bytes
        )
        terminal_from_result = result_summary is not None
        result_stream_complete = (
            terminal_from_result
            and result_chunk_index >= int(result_summary["chunk_count"])
        )
        if terminal_from_result and state.active and result_stream_complete:
            # The owner publishes result.json atomically only after every
            # digest-bound chunk. That exact evidence is terminal even when a
            # descendant or obsolete release keeps the native cgroup active.
            # Preserve the result directory until the caller has drained the
            # complete declared stream: the native stop path collects and
            # removes those files. Stop only on the manifest-complete
            # observation, then let the caller commit its terminal envelope.
            self.manager.cancel(runtime_id)
        effective_active = state.active and not terminal_from_result
        output_progress = (
            _validated_output_progress(state.output_progress)
            if effective_active
            else None
        )
        if terminal_from_result:
            runner_peak_memory, runner_cpu_seconds = _runner_resource_usage(result)
            if peak_memory_bytes is None and runner_peak_memory is not None:
                peak_memory_bytes = runner_peak_memory
            if cpu_seconds is None and runner_cpu_seconds is not None:
                cpu_seconds = runner_cpu_seconds
            exit_status = int(result["returncode"])
            terminal_outcome = str(result["terminal_outcome"])
            termination_reason = (
                "success"
                if terminal_outcome == "succeeded"
                else "timeout"
                if terminal_outcome == "timed_out"
                else "exit_code"
            )
            systemd_result = "success" if exit_status == 0 else "exit-code"
            exec_main_code = 1
        else:
            exit_status = state.exit_status
        if not effective_active and termination_reason is None:
            # Protocol fakes and alternate native managers may not expose the
            # richer systemd fields. Preserve the old interface without
            # silently claiming OOM/timeout evidence that was not observed.
            termination_reason = (
                "success" if state.exit_status == 0 else "exit_code"
                if type(state.exit_status) is int else "systemd_failure"
            )
            systemd_result = (
                "success" if state.exit_status == 0 else "exit-code"
                if type(state.exit_status) is int else "unknown"
            )
            exec_main_code = 1 if type(state.exit_status) is int else 0
        return {
            "runtime_id": runtime_id,
            "attempt_id": descriptor.attempt_id,
            "repository_id": descriptor.repository_id,
            "repository_generation": descriptor.repository_generation,
            "state": "running" if effective_active else "exited",
            "exit_status": exit_status,
            "started_at": state.started_at,
            "finished_at": (
                float(self.clock())
                if terminal_from_result and state.finished_at is None
                else state.finished_at
            ),
            "result": result_summary,
            "result_chunk": (
                None if result_chunk is None else dict(result_chunk)
            ),
            "termination": (
                None
                if effective_active
                else {
                    "reason": termination_reason,
                    "systemd_result": systemd_result,
                    "exec_main_code": exec_main_code,
                    "oom_killed": state.oom_killed,
                }
            ),
            "resource_usage": (
                {"current_memory_bytes": current_memory_bytes}
                if effective_active
                else {
                    "peak_memory_bytes": peak_memory_bytes,
                    "cpu_seconds": cpu_seconds,
                }
            ),
            "progress": output_progress,
        }

    def cancel(
        self,
        runtime_id: str,
        *,
        reason: str,
        expected_attempt_id: str | None = None,
        expected_repository_id: str | None = None,
        expected_repository_generation: int | None = None,
    ) -> dict[str, object]:
        del reason
        runtime_id = _safe_id("runtime_id", runtime_id)
        if expected_attempt_id is not None:
            expected_attempt_id = _safe_id("expected_attempt_id", expected_attempt_id)
            if runtime_id != _runtime_id_for_attempt(expected_attempt_id):
                raise TestStoreConflict(
                    "test attempt cancellation runtime identity is contradictory"
                )
        if expected_repository_id is not None:
            expected_repository_id = _safe_id(
                "expected_repository_id", expected_repository_id
            )
        if expected_repository_generation is not None and (
            type(expected_repository_generation) is not int
            or expected_repository_generation < 0
        ):
            raise TestStoreContractError(
                "expected_repository_generation must be non-negative"
            )

        try:
            descriptor = self.runtime_descriptor(runtime_id)
        except TestAttemptRuntimeNotFound:
            # Absence is a typed success only for a broker request that binds
            # the exact deterministic runtime to its attempt. A fresh native
            # observation must independently prove that no unit is loaded or
            # active; a generic descriptor/contract failure is never enough.
            if (
                expected_attempt_id is None
                or expected_repository_id is None
                or expected_repository_generation is None
            ):
                raise
            state = self._require_exact_native_state(
                runtime_id, self.manager.status(runtime_id)
            )
            if state.loaded or state.active:
                raise TestStoreConflict(
                    "test attempt is active without recoverable launch evidence"
                )
            return {"runtime_id": runtime_id, "cancelled": True, "absent": True}

        if (
            expected_attempt_id is not None
            and (
                descriptor.attempt_id != expected_attempt_id
                or descriptor.repository_id != expected_repository_id
                or descriptor.repository_generation
                != expected_repository_generation
            )
        ):
            raise TestStoreConflict(
                "test attempt cancellation binding is contradictory"
            )
        state = self._require_exact_native_state(
            runtime_id, self.manager.cancel(runtime_id)
        )
        absent = not state.loaded and not state.active
        return {
            "runtime_id": runtime_id,
            "cancelled": not state.active,
            "absent": absent,
        }


__all__ = [
    "BrokerTestAttemptCoordinator",
    "MAX_TEST_ATTEMPT_TTL_SECONDS",
    "NativeTestAttemptManager",
    "NativeTestAttemptState",
    "SystemdTestAttemptManager",
    "TEST_ATTEMPT_ACCOUNT_ID",
    "TestAttemptDescriptor",
    "TestAttemptLaunchUncertain",
    "TestAttemptRuntimeNotFound",
    "TestCredentialLease",
    "TestCredentialProvider",
    "TestFixtureLease",
    "TestFixtureProvider",
]
