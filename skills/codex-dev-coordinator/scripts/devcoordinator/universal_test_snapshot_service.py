"""Snapshot authority and fixed local helper transport.

testd can request only an authority-bound immutable preview or one descriptor
for an already selected attempt. Read-only repository inspection runs in a
fixed Python helper as the protected control plane; repository content is never
executed there. Catalog integrity comes from bounded content-addressed records
rather than Unix ownership or mode gates.
"""

from __future__ import annotations

import contextvars
from dataclasses import asdict
import grp
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import pwd
import socket
import stat
import struct
import subprocess
import tempfile
import time
from typing import Callable, Mapping, Sequence
import uuid

from .call_journal import (
    RollingCallJournal,
    diagnostic_for_exception,
    event_record,
    monotonic_started,
)
from .store import CoordinatorStore
from .schema import SCHEMA_VERSION
from .universal_test_broker import RepositoryLaunchDescriptorResolver
from .universal_test_runtime import TestAttemptDescriptor
from .universal_test_planner import TestPlanError, TestPlanTimeouts
from .universal_testd import LiveSourceChanged
from .universal_test_service import (
    RepositoryUIDPlanPreviewer,
    decode_repository_setup_document,
    decode_test_plan_document,
)
from .universal_test_snapshot import (
    FilesystemSnapshotMaterializer,
    GitSnapshotSource,
    SnapshotMaterializationError,
    SnapshotMaterializationRequest,
    SnapshotScan,
    SnapshotSource,
    nuget_locked_package_source_paths,
    nuget_locked_package_requirements,
    nuget_package_archive_file_digests,
    nuget_package_metadata_content_hash,
    nuget_package_sha512_digest,
    snapshot_regular_file_digest,
)
from .universal_test_store import (
    LeaseGrant,
    RunnableTarget,
    TestStoreConflict,
    TestStoreContractError,
)


SNAPSHOT_SERVICE_SCHEMA_VERSION = 1
MAX_SNAPSHOT_SERVICE_FRAME_BYTES = 64 * 1024 * 1024
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_DEPENDENCY_IDENTITY_BYTES = 64 * 1024 * 1024
MAX_DEPENDENCY_IDENTITY_FILES = 8_192
_PYTHON_ENVIRONMENT_NAMES = (".venv-v2", ".venv", "venv")
_PYTHON_LOCK_NAMES = frozenset({"uv.lock", "poetry.lock", "pipfile.lock"})
_NODE_EXECUTABLES = frozenset({"{node}", "node", "npm", "npmjs", "npx"})
_DOTNET_PACKAGES_DESTINATION = ".devcoordinator-dependencies/nuget-source"
_INSTALLATION_MANIFEST_KINDS = frozenset(
    {
        "python-dist-info",
        "python-toolchain",
        "dotnet-toolchain",
        "node-package-lock",
        "nuget-package-source",
    }
)
_SNAPSHOT_PREVIEW_DEADLINE: contextvars.ContextVar[float | None] = (
    contextvars.ContextVar("devcoordinator_snapshot_preview_deadline", default=None)
)
_CONTROL_PLANE_READ_OPERATIONS = frozenset(
    {
        "setup",
        "adoption_inspect",
        "adoption_catalog",
        "adoption_safety_identity",
        "manifest",
        "scan",
        "live_plan",
        "plan",
    }
)


def _snapshot_preview_timeout(maximum_seconds: float) -> float:
    """Return one transport/work slice within the aggregate launch deadline."""

    deadline = _SNAPSHOT_PREVIEW_DEADLINE.get()
    if deadline is None:
        return float(maximum_seconds)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SnapshotMaterializationError(
            "snapshot preview exceeded the caller launch deadline"
        )
    return max(0.001, min(float(maximum_seconds), remaining))


def _snapshot_preview_remaining() -> float:
    return _snapshot_preview_timeout(3_600.0)


def _json(value: object, *, maximum: int) -> bytes:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if not payload or len(payload) > maximum:
        raise TestStoreContractError("snapshot service document exceeds its bound")
    return payload


def _read_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    while size:
        chunk = connection.recv(size)
        if not chunk:
            raise TestStoreContractError("snapshot service frame is incomplete")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def _receive(connection: socket.socket) -> Mapping[str, object]:
    size = struct.unpack("!I", _read_exact(connection, 4))[0]
    if not 1 <= size <= MAX_SNAPSHOT_SERVICE_FRAME_BYTES:
        raise TestStoreContractError("snapshot service frame size is invalid")
    value = json.loads(_read_exact(connection, size))
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise TestStoreContractError("snapshot service frame must be an object")
    return value


def _send(connection: socket.socket, value: Mapping[str, object]) -> None:
    payload = _json(value, maximum=MAX_SNAPSHOT_SERVICE_FRAME_BYTES)
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _peer_identity(
    connection: socket.socket,
) -> tuple[int | None, int | None, int | None]:
    """Return best-effort local PID/UID/GID attribution, never authorization."""

    option = getattr(socket, "SO_PEERCRED", None)
    if connection.family != socket.AF_UNIX or option is None:
        return None, None, None
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, option, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", raw)
        return (
            int(pid) if int(pid) >= 0 else None,
            int(uid) if int(uid) >= 0 else None,
            int(gid) if int(gid) >= 0 else None,
        )
    except (OSError, struct.error, ValueError):
        return None, None, None


def _peer_uid(connection: socket.socket) -> int | None:
    """Compatibility wrapper returning only the attributed UID."""

    return _peer_identity(connection)[1]


def _snapshot_correlations(
    arguments: object,
) -> tuple[str | None, str | None, str | None]:
    """Extract only public identities from a snapshot request envelope."""

    if not isinstance(arguments, Mapping):
        return None, None, None
    candidate = arguments.get("candidate")
    lease = arguments.get("lease")
    plan = arguments.get("plan")
    repository_id = arguments.get("repository_id")
    run_id = None
    attempt_id = None
    if isinstance(candidate, Mapping):
        repository_id = candidate.get("repository_id", repository_id)
        run_id = candidate.get("run_id")
    if isinstance(plan, Mapping):
        repository_id = plan.get("repository_id", repository_id)
    if isinstance(lease, Mapping):
        run_id = lease.get("run_id", run_id)
        attempt_id = lease.get("attempt_id")
    return (
        repository_id if isinstance(repository_id, str) else None,
        run_id if isinstance(run_id, str) else None,
        attempt_id if isinstance(attempt_id, str) else None,
    )


def _snapshot_failure_stage(operation: str | None, error: BaseException) -> str:
    text = str(error).lower()
    prefix = (
        operation
        if operation in {"setup", "preview", "resolve", "observe"}
        else "receive"
    )
    if "immutable python" in text:
        return f"{prefix}.python_dependency"
    if "immutable node" in text:
        return f"{prefix}.node_dependency"
    if "immutable .net" in text or "dotnet" in text:
        return f"{prefix}.dotnet_dependency"
    if "deadline" in text or "timed out" in text or isinstance(error, TimeoutError):
        return f"{prefix}.timeout"
    if isinstance(error, PermissionError):
        return f"{prefix}.source_read"
    return f"{prefix}.execution"


def _snapshot_failure_code(error: BaseException) -> str:
    text = str(error).lower()
    if "immutable python" in text:
        if "unsafe" in text or "escapes" in text:
            return "snapshot_python_dependency_unsafe"
        return "snapshot_python_dependency_unavailable"
    if "immutable node" in text:
        return "snapshot_node_dependency_unavailable"
    if "immutable .net" in text or "dotnet" in text:
        return "snapshot_dotnet_dependency_unavailable"
    if "deadline" in text or "timed out" in text or isinstance(error, TimeoutError):
        return "snapshot_timeout"
    diagnostic = diagnostic_for_exception(
        error, stage=_snapshot_failure_stage(None, error)
    )
    if diagnostic.get("errno") in {"EACCES", "EPERM"}:
        return "snapshot_source_unreadable"
    if isinstance(error, SnapshotMaterializationError):
        return "snapshot_materialization_failed"
    if isinstance(error, TestStoreConflict):
        return "snapshot_conflict"
    if isinstance(error, TestStoreContractError):
        return "snapshot_contract_invalid"
    return "snapshot_failed"


class SnapshotServiceRemoteError(SnapshotMaterializationError):
    """Typed snapshotd failure preserved across the local transport."""

    def __init__(
        self,
        code: str,
        message: str,
        diagnostic: Mapping[str, object] | None = None,
    ) -> None:
        self.code = code
        self.diagnostic = dict(diagnostic or {})
        super().__init__(message)


class UIDHelperRunner:
    """Invoke one fixed helper under the operation's narrow identity.

    Read-only parsing and capture run as the protected control plane so local
    account traversal and ACL differences cannot block the one developer's
    test harness. Repository writes remain owner-UID operations, and repository
    commands are never accepted by this helper.
    """

    def __init__(
        self,
        helper: Path,
        *,
        python: str = "/usr/bin/python3",
        runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
        expected_helper_uid: int = 0,
    ) -> None:
        self.helper = Path(helper).absolute()
        self.python = str(Path(python).resolve(strict=True))
        self.runner = runner
        helper_metadata = self.helper.lstat()
        python_metadata = Path(self.python).lstat()
        if (
            not stat.S_ISREG(helper_metadata.st_mode)
            or not stat.S_ISREG(python_metadata.st_mode)
            or not python_metadata.st_mode & 0o111
        ):
            raise TestStoreContractError("repository UID helper identity is unsafe")
        del expected_helper_uid

    def call(
        self,
        operation: str,
        *,
        owner_uid: int,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]:
        if type(owner_uid) is not int or owner_uid <= 0:
            raise TestStoreContractError("repository helper owner UID is invalid")
        try:
            owner_identity = pwd.getpwuid(owner_uid)
        except KeyError as error:
            raise TestStoreContractError("repository helper owner does not exist") from error
        read_only = operation in _CONTROL_PLANE_READ_OPERATIONS
        if read_only:
            try:
                identity = pwd.getpwuid(0)
            except KeyError as error:
                raise TestStoreContractError(
                    "control-plane helper identity does not exist"
                ) from error
            supplementary_groups: tuple[int, ...] = ()
        else:
            identity = owner_identity
            try:
                supplementary_groups = tuple(
                    sorted(
                        group_id
                        for group_id in set(
                            os.getgrouplist(identity.pw_name, identity.pw_gid)
                        ).union(
                            account.pw_gid
                            for account in pwd.getpwall()
                            # Local login accounts are attribution identities
                            # for one developer. This union remains useful for
                            # owner-UID write operations; read-only capture does
                            # not depend on it.
                            if 1_000 <= account.pw_uid < 60_000
                        )
                        if group_id != identity.pw_gid
                    )
                )
            except OSError as error:
                raise TestStoreContractError(
                    "repository helper owner groups are unavailable"
                ) from error
        request = _json(
            {
                "operation": operation,
                "owner_uid": owner_uid,
                "arguments": dict(arguments),
            },
            maximum=512 * 1024,
        )
        try:
            completed = self.runner(
                [self.python, "-I", "-B", str(self.helper)],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=_snapshot_preview_timeout(180),
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                user=identity.pw_uid,
                group=identity.pw_gid,
                # A repository may intentionally be shared by several local
                # accounts owned by the same developer.  Git then writes
                # objects for the shared group, so stripping the repository
                # owner's normal supplementary groups makes a valid HEAD
                # intermittently unreadable after another account commits.
                extra_groups=supplementary_groups,
            )
        except subprocess.TimeoutExpired as error:
            if _SNAPSHOT_PREVIEW_DEADLINE.get() is None:
                raise SnapshotMaterializationError(
                    "repository UID helper timed out"
                ) from error
            raise SnapshotMaterializationError(
                "repository UID helper exceeded the caller launch deadline"
            ) from error
        except (OSError, subprocess.SubprocessError) as error:
            raise SnapshotMaterializationError("repository UID helper failed") from error
        if len(completed.stdout) > MAX_SNAPSHOT_SERVICE_FRAME_BYTES or len(
            completed.stderr
        ) > 64 * 1024:
            raise SnapshotMaterializationError("repository UID helper output is excessive")
        try:
            response = json.loads(completed.stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SnapshotMaterializationError("repository UID helper response is invalid") from error
        if not isinstance(response, Mapping) or type(response.get("ok")) is not bool:
            raise SnapshotMaterializationError("repository UID helper response is invalid")
        if not response["ok"] or completed.returncode != 0:
            error = response.get("error")
            message = error.get("message") if isinstance(error, Mapping) else None
            raise SnapshotMaterializationError(
                str(message or "repository UID helper refused the request")
            )
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise SnapshotMaterializationError("repository UID helper result is invalid")
        return result


class UIDDelegatedSnapshotSource(SnapshotSource):
    """Owner-UID scanning with protected root-side anchored file copies."""

    def __init__(self, helper: UIDHelperRunner) -> None:
        self.helper = helper
        self.copy_source = GitSnapshotSource(enforce_process_uid=False)

    def scan(self, request: SnapshotMaterializationRequest) -> SnapshotScan:
        result = self.helper.call(
            "scan",
            # Authority and eventual test execution remain bound to owner_uid.
            # Read-only capture uses the authenticated local caller because a
            # cross-account repository may grant that account named ACL access
            # that cannot be represented by one synthetic supplementary-group
            # union without changing POSIX ACL class selection.
            owner_uid=request.inspection_uid,
            arguments={
                "repository_id": request.repository_id,
                "original_root": request.original_root,
                "temporary_root": request.temporary_root,
                "manifest_fingerprint": request.manifest_fingerprint,
                "intent": request.intent,
            },
        )
        if set(result) != {"scan"} or not isinstance(result["scan"], Mapping):
            raise SnapshotMaterializationError("repository UID scan result is invalid")
        return SnapshotScan.from_document(result["scan"])

    def copy_file(self, request, source, destination) -> str:
        return self.copy_source.copy_file(request, source, destination)


class SnapshotAuthority:
    def __init__(self, database: Path, *, expected_uid: int = 0) -> None:
        self.database = Path(database)
        self.expected_uid = expected_uid

    def repository(
        self, *, repository_id: str
    ) -> Mapping[str, object]:
        """Resolve one current repository from the trusted local catalog."""

        with CoordinatorStore.open_read_only(
            self.database, expected_uid=self.expected_uid
        ) as store:
            with store.read_transaction() as connection:
                metadata = connection.execute(
                    """
                    SELECT schema_version, migration_state
                    FROM schema_metadata WHERE singleton = 1
                    """
                ).fetchone()
                rows = connection.execute(
                    """
                    SELECT repository.canonical_root, repository.generation,
                           repository.state, installation.status,
                           installation.startup_fenced
                    FROM repositories repository
                    JOIN repository_installations installation USING(repo_id)
                    WHERE repository.repo_id = ?
                    """,
                    (repository_id,),
                ).fetchall()
        row = rows[0] if len(rows) == 1 else None
        if (
            metadata is None
            or int(metadata["schema_version"]) != SCHEMA_VERSION
            or str(metadata["migration_state"]) != "ready"
            or row is None
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
        ):
            raise TestStoreContractError("test_repository_unavailable")
        return {
            "repository_id": repository_id,
            "canonical_root": str(row["canonical_root"]),
            "generation": int(row["generation"]),
        }

    def live_execution_root(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        temporary_root: str | None,
    ) -> Mapping[str, object]:
        if type(owner_uid) is not int or owner_uid <= 0:
            raise TestStoreContractError("test execution UID is invalid")
        root = self.repository(repository_id=repository_id)
        if temporary_root is None:
            return {**root, "execution_root": root["canonical_root"]}
        with CoordinatorStore.open_read_only(
            self.database, expected_uid=self.expected_uid
        ) as store:
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT repository.canonical_root, repository.generation,
                           repository.state, installation.status,
                           installation.startup_fenced
                    FROM repository_families AS family
                    JOIN repository_scopes AS scope
                      ON scope.family_id = family.family_id
                    JOIN repositories AS repository
                      ON repository.repo_id = scope.repo_id
                    JOIN repository_installations AS installation
                      ON installation.repo_id = repository.repo_id
                    WHERE family.root_repo_id = ?
                      AND scope.project_kind = 'temporary'
                      AND repository.canonical_root = ?
                    """,
                    (repository_id, temporary_root),
                ).fetchone()
        if (
            row is None
            or str(row["state"]) != "active"
            or str(row["status"]) != "installed"
            or bool(row["startup_fenced"])
        ):
            raise TestStoreContractError(
                "temporary live source is not an active authoritative worktree"
            )
        return {
            **root,
            "execution_root": str(row["canonical_root"]),
            "temporary_generation": int(row["generation"]),
        }


class RootSnapshotService:
    def __init__(
        self,
        *,
        authority: SnapshotAuthority,
        helper: UIDHelperRunner,
        snapshot_root: Path,
        catalog_root: Path,
    ) -> None:
        self.authority = authority
        self.helper = helper
        self.snapshot_root = Path(snapshot_root).absolute()
        self.catalog_root = Path(catalog_root).absolute()
        self.catalog_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.catalog_root.is_symlink() or not self.catalog_root.is_dir():
            raise TestStoreContractError("snapshot launch catalog is not a real directory")
        self.materializer = FilesystemSnapshotMaterializer(
            self.snapshot_root,
            source=UIDDelegatedSnapshotSource(helper),
        )
        # Owners may traverse only an already-accepted content-addressed
        # path; they cannot list or mutate the root-owned store.
        self.snapshot_root.chmod(0o711)

    def setup(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if set(arguments) != {"repository_id", "owner_uid"}:
            raise TestStoreContractError("snapshot setup arguments are invalid")
        repository_id = arguments["repository_id"]
        owner_uid = arguments["owner_uid"]
        if not isinstance(repository_id, str) or not repository_id:
            raise TestStoreContractError("snapshot setup repository is invalid")
        if type(owner_uid) is not int:
            raise TestStoreContractError("snapshot setup owner is invalid")
        authority = self.authority.repository(repository_id=repository_id)
        setup = self.helper.call(
            "setup",
            owner_uid=owner_uid,
            arguments={"repository_root": authority["canonical_root"]},
        )
        if "repository_id" in setup:
            raise SnapshotMaterializationError(
                "repository UID setup result contains forbidden identity"
            )
        return decode_repository_setup_document(
            {"repository_id": repository_id, **setup},
            expected_repository_id=repository_id,
        )

    def preview(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        """Preview using one caller-defined deadline across every nested step."""

        try:
            timeouts = TestPlanTimeouts(
                execution_seconds=arguments.get("execution_timeout_seconds"),
                launch_seconds=arguments.get("launch_timeout_seconds", 300),
            )
        except TestPlanError as error:
            raise TestStoreContractError(
                "snapshot preview timeouts are invalid"
            ) from error
        inherited_deadline = arguments.get("launch_deadline_monotonic")
        if inherited_deadline is not None and (
            isinstance(inherited_deadline, bool)
            or not isinstance(inherited_deadline, (int, float))
            or not math.isfinite(float(inherited_deadline))
            or float(inherited_deadline) <= 0
        ):
            raise TestStoreContractError(
                "snapshot preview launch deadline is invalid"
            )
        now = time.monotonic()
        deadline = now + timeouts.launch_seconds
        if inherited_deadline is not None:
            # Never let a forwarded deadline extend the caller's declared
            # launch budget.  A deadline already consumed in the outer
            # test-plane process remains consumed here.
            deadline = min(deadline, float(inherited_deadline))
        token = _SNAPSHOT_PREVIEW_DEADLINE.set(deadline)
        try:
            return self._preview(arguments)
        finally:
            _SNAPSHOT_PREVIEW_DEADLINE.reset(token)

    def _preview(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        # Reject an already-consumed outer deadline before repository lookup or
        # any helper/materialization work can obscure the real launch outcome.
        _snapshot_preview_remaining()
        required = {"repository_id", "intent", "actor", "owner_uid"}
        allowed = required | {
            "temporary_root",
            "requested_targets",
            "access_uid",
            "execution_timeout_seconds",
            "launch_timeout_seconds",
            "launch_deadline_monotonic",
        }
        if not required <= set(arguments) or set(arguments) - allowed:
            raise TestStoreContractError("snapshot preview arguments are invalid")
        del_actor = arguments["actor"]
        if not isinstance(del_actor, str) or not del_actor:
            raise TestStoreContractError("snapshot preview actor is invalid")
        repository_id = str(arguments["repository_id"])
        intent = str(arguments["intent"])
        owner_uid = arguments["owner_uid"]
        if type(owner_uid) is not int:
            raise TestStoreContractError("snapshot preview owner is invalid")
        access_uid = arguments.get("access_uid")
        if access_uid is not None and (
            type(access_uid) is not int or access_uid <= 0
        ):
            raise TestStoreContractError("snapshot preview access UID is invalid")
        temporary_root = arguments.get("temporary_root")
        if temporary_root is not None and not isinstance(temporary_root, str):
            raise TestStoreContractError("snapshot preview temporary root is invalid")
        requested_targets = arguments.get("requested_targets", ())
        if (
            not isinstance(requested_targets, Sequence)
            or isinstance(requested_targets, (str, bytes))
            or len(requested_targets) > 256
            or any(not isinstance(item, str) for item in requested_targets)
            or len(set(requested_targets)) != len(requested_targets)
        ):
            raise TestStoreContractError("snapshot preview targets are invalid")
        if requested_targets and intent != "manual":
            raise TestStoreContractError(
                "snapshot preview targets require manual intent"
            )
        try:
            timeouts = TestPlanTimeouts(
                execution_seconds=arguments.get("execution_timeout_seconds"),
                launch_seconds=arguments.get("launch_timeout_seconds", 300),
            )
        except TestPlanError as error:
            raise TestStoreContractError("snapshot preview timeouts are invalid") from error
        authority = self.authority.live_execution_root(
            repository_id=repository_id,
            owner_uid=owner_uid,
            temporary_root=temporary_root,
        )
        execution_root = str(authority["execution_root"])
        manifest = self.helper.call(
            "manifest",
            owner_uid=owner_uid,
            arguments={
                "repository_root": execution_root,
                "intent": intent,
            },
        )
        if (
            set(manifest) != {"manifest_fingerprint", "source_mode"}
            or manifest["source_mode"] not in {"live", "immutable"}
        ):
            raise SnapshotMaterializationError("snapshot preview intent is invalid")
        provenance = None
        if manifest["source_mode"] == "live":
            planned = self.helper.call(
                "live_plan",
                owner_uid=owner_uid,
                arguments={
                    "repository_id": repository_id,
                    "original_root": authority["canonical_root"],
                    "execution_root": execution_root,
                    "intent": intent,
                    "requested_targets": list(requested_targets),
                    "timeouts": timeouts.to_document(),
                },
            )
        else:
            request = SnapshotMaterializationRequest(
                repository_id=repository_id,
                original_root=str(authority["canonical_root"]),
                temporary_root=(execution_root if temporary_root is not None else None),
                manifest_fingerprint=str(manifest["manifest_fingerprint"]),
                intent=intent,
                owner_uid=owner_uid,
                access_uid=access_uid,
            )
            materialize_with_timeout = getattr(
                self.materializer, "materialize_with_timeout", None
            )
            if callable(materialize_with_timeout):
                provenance = materialize_with_timeout(
                    request,
                    timeout_seconds=_snapshot_preview_remaining(),
                )
            else:
                # Kept only for injected test doubles.  The production
                # FilesystemSnapshotMaterializer always exposes the bounded
                # entrypoint above.
                provenance = self.materializer.materialize(request)
            planned = self.helper.call(
                "plan",
                owner_uid=owner_uid,
                arguments={
                    "snapshot_root": provenance.materialized_root,
                    "source": provenance.source_identity().to_document(),
                    "intent": intent,
                    "requested_targets": list(requested_targets),
                    "timeouts": timeouts.to_document(),
                },
            )
        if set(planned) != {"plan", "target_resources", "launch_catalog"}:
            raise SnapshotMaterializationError("snapshot plan result is invalid")
        plan = decode_test_plan_document(planned["plan"])  # type: ignore[arg-type]
        if (
            plan.repository_id != repository_id
            or plan.intent != intent
            or plan.timeouts != timeouts
            or plan.manifest_fingerprint != manifest["manifest_fingerprint"]
        ):
            raise SnapshotMaterializationError("snapshot plan identity is contradictory")
        if manifest["source_mode"] == "immutable":
            if provenance is None or plan.source != provenance.source_identity():
                raise SnapshotMaterializationError(
                    "snapshot plan source is contradictory"
                )
        elif (
            plan.source.mode.value != "live"
            or plan.source.original_root != authority["canonical_root"]
            or plan.source.temporary_root
            != (execution_root if temporary_root is not None else None)
            or plan.source.snapshot_id is not None
        ):
            raise SnapshotMaterializationError("live plan source is contradictory")
        source_catalog_id = self._source_catalog_id(plan)
        source_provenance = {
            "complete": provenance is not None,
            "content_fingerprint": plan.source.content_fingerprint,
            "manifest_fingerprint": plan.manifest_fingerprint,
            "dependency_locks": (
                {} if provenance is None else dict(provenance.dependency_locks)
            ),
            "toolchain": {} if provenance is None else dict(provenance.toolchain),
        }
        self._publish_catalog(
            plan_id=plan.plan_id,
            snapshot_id=source_catalog_id,
            value={
                "schema_version": 1,
                "plan": plan.to_document(),
                "repository_generation": authority["generation"],
                "owner_uid": owner_uid,
                "launch_catalog": planned["launch_catalog"],
                "target_resources": planned["target_resources"],
                "source_provenance": source_provenance,
            },
        )
        launch_catalog = planned["launch_catalog"]
        if not isinstance(launch_catalog, Mapping):
            raise SnapshotMaterializationError("snapshot launch catalog is invalid")
        networks: set[str] = set()
        fixtures: set[str] = set()
        credentials: set[str] = set()
        for target_name in plan.selected_targets:
            launch = launch_catalog.get(target_name)
            if not isinstance(launch, Mapping):
                raise SnapshotMaterializationError(
                    "snapshot launch catalog target is missing"
                )
            network = launch.get("network")
            target_fixtures = launch.get("fixtures")
            target_credentials = launch.get("credentials", ())
            if (
                network
                not in {"none", "loopback", "host-loopback", "external"}
                or not isinstance(target_fixtures, Sequence)
                or isinstance(target_fixtures, (str, bytes))
                or any(not isinstance(item, str) for item in target_fixtures)
                or not isinstance(target_credentials, Sequence)
                or isinstance(target_credentials, (str, bytes))
                or any(not isinstance(item, str) for item in target_credentials)
            ):
                raise SnapshotMaterializationError(
                    "snapshot launch capability requests are invalid"
                )
            networks.add(str(network))
            fixtures.update(target_fixtures)
            credentials.update(target_credentials)
        return {
            "plan": plan.to_document(),
            "target_resources": planned["target_resources"],
            "capability_requests": {
                "networks": sorted(networks),
                "fixtures": sorted(fixtures),
                "credentials": sorted(credentials),
            },
        }

    @staticmethod
    def _source_catalog_id(plan) -> str:
        if plan.source.snapshot_id is not None:
            return plan.source.snapshot_id
        identity = hashlib.sha256(
            (
                plan.repository_id
                + "\0"
                + plan.source.content_fingerprint
            ).encode("utf-8")
        ).hexdigest()[:32]
        return "live-" + identity

    @staticmethod
    def _requested_targets(plan) -> list[str]:
        return [
            target
            for target, selection in plan.selection.items()
            if "requested" in selection.reasons
        ]

    def _catalog_path(self, snapshot_id: str, plan_id: str) -> Path:
        prefix = (
            "snapshot-"
            if snapshot_id.startswith("snapshot-")
            else "live-" if snapshot_id.startswith("live-") else None
        )
        if (
            prefix is None
            or len(snapshot_id) != len(prefix) + 32
            or any(character not in "0123456789abcdef" for character in snapshot_id[len(prefix):])
            or not plan_id.startswith("plan-")
        ):
            raise TestStoreContractError("snapshot catalog identity is invalid")
        directory = self.catalog_root / snapshot_id
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.is_symlink() or not directory.is_dir():
            raise TestStoreContractError("snapshot catalog directory is not real")
        return directory / f"{plan_id}.json"

    def _publish_catalog(self, *, plan_id: str, snapshot_id: str, value: Mapping[str, object]) -> None:
        payload = _json(value, maximum=MAX_CATALOG_BYTES)
        destination = self._catalog_path(snapshot_id, plan_id)
        if destination.exists():
            if destination.read_bytes() != payload:
                raise TestStoreContractError("snapshot launch catalog identity collided")
            return
        descriptor, name = tempfile.mkstemp(prefix=".catalog-", dir=destination.parent)
        stage = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.link(stage, destination)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            stage.unlink(missing_ok=True)

    def _load_catalog(self, plan_document: Mapping[str, object]) -> Mapping[str, object]:
        plan = decode_test_plan_document(plan_document)
        path = self._catalog_path(self._source_catalog_id(plan), plan.plan_id)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_CATALOG_BYTES
        ):
            raise TestStoreContractError("snapshot launch catalog is unsafe")
        value = json.loads(path.read_bytes())
        if not isinstance(value, Mapping) or value.get("plan") != plan.to_document():
            raise TestStoreContractError("snapshot launch catalog is contradictory")
        return value

    @staticmethod
    def _dependency_relative(value: object, *, field: str) -> PurePosixPath:
        if not isinstance(value, str) or not value:
            raise TestStoreConflict(f"{field} is invalid")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise TestStoreConflict(f"{field} escapes the repository")
        return path

    @staticmethod
    def _real_dependency_directory(path: Path, *, field: str) -> os.stat_result:
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or resolved != path
        ):
            raise TestStoreConflict(f"{field} is unsafe")
        return metadata

    @classmethod
    def _dependency_file_bytes(
        cls, root: Path, relative: PurePosixPath, *, field: str
    ) -> tuple[bytes, os.stat_result]:
        cls._real_dependency_directory(root, field=f"{field} root")
        candidate = root.joinpath(*relative.parts)
        try:
            metadata = candidate.lstat()
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or resolved != candidate
            or (resolved != root and root not in resolved.parents)
            or metadata.st_size > MAX_DEPENDENCY_IDENTITY_BYTES
        ):
            raise TestStoreConflict(f"{field} is unsafe")
        try:
            data = candidate.read_bytes()
        except OSError as error:
            raise TestStoreConflict(f"{field} is unavailable") from error
        return data, metadata

    @classmethod
    def _dependency_file_digest(
        cls, root: Path, relative: PurePosixPath, *, field: str
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
        if kind not in _INSTALLATION_MANIFEST_KINDS:
            raise TestStoreConflict(
                "immutable dependency installation manifest kind is invalid"
            )
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
        else:
            if not required_paths:
                raise TestStoreConflict(
                    "immutable .NET package identity has no locked packages"
                )
            candidates.extend(source_root.joinpath(*path.parts) for path in required_paths)
        if kind == "python-toolchain":
            candidates = [candidate for candidate in candidates if not candidate.is_symlink()]
        unique = sorted(set(candidates), key=str)
        if not unique or len(unique) > MAX_DEPENDENCY_IDENTITY_FILES:
            raise TestStoreConflict(
                "immutable dependency installation manifest is missing or excessive"
            )
        identity = hashlib.sha256()
        total_bytes = 0
        for candidate in unique:
            try:
                relative = candidate.relative_to(source_root)
                metadata = candidate.lstat()
            except (OSError, ValueError) as error:
                raise TestStoreConflict(
                    "immutable dependency installation manifest is unsafe"
                ) from error
            total_bytes += metadata.st_size
            if (
                kind != "nuget-package-source"
                and total_bytes > MAX_DEPENDENCY_IDENTITY_BYTES
            ):
                raise TestStoreConflict(
                    "immutable dependency installation manifest is excessive"
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
                        "immutable .NET package archive identity is invalid"
                    ) from error
            else:
                file_digest = cls._dependency_file_digest(
                    source_root,
                    relative_path,
                    field="immutable dependency installation manifest file",
                )
            identity.update(relative.as_posix().encode("utf-8"))
            identity.update(b"\0")
            identity.update(str(metadata.st_size).encode("ascii"))
            identity.update(b"\0")
            identity.update(file_digest.encode("ascii"))
            identity.update(b"\n")
        return identity.hexdigest(), len(unique), total_bytes

    @classmethod
    def _validated_dependency_locks(
        cls,
        *,
        dependency_locks: Mapping[str, object],
        lock_paths: Sequence[PurePosixPath],
        original_root: Path,
        materialized_root: Path,
    ) -> Mapping[str, str]:
        if not lock_paths:
            raise TestStoreConflict(
                "immutable dependency root has no recorded dependency lock"
            )
        validated: dict[str, str] = {}
        for lock_path in sorted(set(lock_paths), key=str):
            expected = dependency_locks.get(str(lock_path))
            if not isinstance(expected, str) or len(expected) != 64:
                raise TestStoreConflict(
                    "immutable dependency lock is absent from snapshot provenance"
                )
            for root, field in (
                (original_root, "original immutable dependency lock"),
                (materialized_root, "materialized immutable dependency lock"),
            ):
                if cls._dependency_file_digest(
                    root, lock_path, field=field
                ) != expected:
                    raise TestStoreConflict(
                        "immutable dependency lock changed after snapshot capture"
                    )
            validated[str(lock_path)] = expected
        return validated

    @classmethod
    def _dependency_destination_is_empty(
        cls, materialized_root: Path, destination: PurePosixPath
    ) -> None:
        cls._real_dependency_directory(
            materialized_root, field="immutable dependency materialization"
        )
        candidate = materialized_root.joinpath(*destination.parts)
        try:
            candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise TestStoreConflict(
                "immutable dependency destination is unavailable"
            ) from error
        else:
            raise TestStoreConflict(
                "immutable dependency destination collides with captured source"
            )
        parent = candidate.parent
        try:
            resolved_parent = parent.resolve(strict=True)
        except OSError:
            # The fixed .NET cache destination has one broker-owned parent
            # that is created later in the private attempt materialization.
            if destination != PurePosixPath(_DOTNET_PACKAGES_DESTINATION):
                raise TestStoreConflict(
                    "immutable dependency destination parent is unavailable"
                )
            return
        if resolved_parent != parent or (
            resolved_parent != materialized_root
            and materialized_root not in resolved_parent.parents
        ):
            raise TestStoreConflict(
                "immutable dependency destination escapes materialized source"
            )

    @classmethod
    def _python_dependency(
        cls,
        *,
        launch: Mapping[str, object],
        original_root: Path,
        materialized_root: Path,
        dependency_locks: Mapping[str, object],
        account_uids: Sequence[int],
    ) -> tuple[Mapping[str, object] | None, str | None]:
        argv = launch.get("argv")
        cwd_raw = launch.get("cwd")
        if (
            not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes))
            or not argv
            or not isinstance(argv[0], str)
        ):
            raise TestStoreConflict("immutable target argv is invalid")
        cwd = (
            PurePosixPath(".")
            if cwd_raw == "."
            else cls._dependency_relative(cwd_raw, field="immutable target cwd")
        )
        raw_executable = str(argv[0])
        destination: PurePosixPath | None = None
        executable_name: str | None = None
        if raw_executable == "{python}":
            candidates: list[PurePosixPath] = []
            parents = [cwd]
            if cwd != PurePosixPath("."):
                parents.append(PurePosixPath("."))
            for parent in parents:
                for name in _PYTHON_ENVIRONMENT_NAMES:
                    candidate = parent / name
                    source = original_root.joinpath(*candidate.parts)
                    if source.exists() or source.is_symlink():
                        candidates.append(candidate)
            candidates = list(dict.fromkeys(candidates))
            if len(candidates) > 1:
                raise TestStoreConflict(
                    "immutable Python environment selection is ambiguous"
                )
            if candidates:
                destination = candidates[0]
                for name in ("python", "python3"):
                    candidate = original_root.joinpath(
                        *destination.parts, "bin", name
                    )
                    if candidate.exists() or candidate.is_symlink():
                        executable_name = f"bin/{name}"
                        break
            else:
                python_lock_exists = any(
                    PurePosixPath(path).name.lower() in _PYTHON_LOCK_NAMES
                    and PurePosixPath(path).parent in parents
                    for path in dependency_locks
                )
                if python_lock_exists:
                    raise TestStoreConflict(
                        "immutable Python dependency environment is missing"
                    )
                return None, None
        else:
            executable_path = cls._dependency_relative(
                raw_executable, field="immutable Python executable"
            )
            combined = cwd / executable_path
            if (
                len(combined.parts) < 3
                or combined.parts[-2] != "bin"
                or combined.parts[-1] not in {"python", "python3"}
                or combined.parts[-3] not in _PYTHON_ENVIRONMENT_NAMES
            ):
                return None, None
            destination = PurePosixPath(*combined.parts[:-2])
            executable_name = "/".join(combined.parts[-2:])
        if destination is None or executable_name is None:
            raise TestStoreConflict(
                "immutable Python dependency executable is missing"
            )
        source_root = original_root.joinpath(*destination.parts)
        source_metadata = cls._real_dependency_directory(
            source_root, field="immutable Python dependency root"
        )
        executable = source_root.joinpath(*PurePosixPath(executable_name).parts)
        try:
            executable_metadata = executable.lstat()
            resolved_executable = executable.resolve(strict=True)
            resolved_metadata = resolved_executable.lstat()
        except OSError as error:
            raise TestStoreConflict(
                "immutable Python dependency executable is unavailable"
            ) from error
        if (
            not (
                stat.S_ISREG(executable_metadata.st_mode)
                or stat.S_ISLNK(executable_metadata.st_mode)
            )
            or not stat.S_ISREG(resolved_metadata.st_mode)
            or not os.access(resolved_executable, os.X_OK)
        ):
            raise TestStoreConflict(
                "immutable Python dependency executable is unsafe"
            )
        toolchain: Mapping[str, object] | None = None
        if source_root not in resolved_executable.parents:
            if not stat.S_ISLNK(executable_metadata.st_mode):
                raise TestStoreConflict(
                    "immutable Python executable escapes its environment"
                )
            try:
                link_target = os.readlink(executable)
            except OSError as error:
                raise TestStoreConflict(
                    "immutable Python toolchain link is unavailable"
                ) from error
            direct_target = Path(link_target)
            try:
                target_metadata = direct_target.lstat()
            except OSError as error:
                raise TestStoreConflict(
                    "immutable Python toolchain target is unavailable"
                ) from error
            allowed_homes: list[Path] = []
            for uid in account_uids:
                try:
                    allowed_homes.append(Path(pwd.getpwuid(uid).pw_dir))
                except KeyError:
                    continue
            if (
                not direct_target.is_absolute()
                or stat.S_ISLNK(target_metadata.st_mode)
                or not stat.S_ISREG(target_metadata.st_mode)
                or not any(
                    home in direct_target.parents and home in resolved_executable.parents
                    for home in allowed_homes
                )
            ):
                raise TestStoreConflict(
                    "immutable Python toolchain target is unsafe"
                )
            toolchain_root = (
                resolved_executable.parent.parent
                if resolved_executable.parent.name == "bin"
                else resolved_executable.parent
            )
            toolchain_metadata = cls._real_dependency_directory(
                toolchain_root, field="immutable Python toolchain root"
            )
            (
                toolchain_sha256,
                toolchain_files,
                toolchain_bytes,
            ) = cls._installation_manifest_identity(
                toolchain_root, kind="python-toolchain"
            )
            toolchain = {
                "link_target": link_target,
                "resolved_executable": str(resolved_executable),
                "source_root": str(toolchain_root),
                "source_device": toolchain_metadata.st_dev,
                "source_inode": toolchain_metadata.st_ino,
                "installation_kind": "python-toolchain",
                "installation_sha256": toolchain_sha256,
                "installation_files": toolchain_files,
                "installation_bytes": toolchain_bytes,
            }
        lock_paths = [
            PurePosixPath(path)
            for path in dependency_locks
            if PurePosixPath(path).parent == destination.parent
            and PurePosixPath(path).name.lower() in _PYTHON_LOCK_NAMES
        ]
        locks = cls._validated_dependency_locks(
            dependency_locks=dependency_locks,
            lock_paths=lock_paths,
            original_root=original_root,
            materialized_root=materialized_root,
        )
        marker_path = PurePosixPath("pyvenv.cfg")
        marker_sha256 = cls._dependency_file_digest(
            source_root,
            marker_path,
            field="immutable Python dependency marker",
        )
        installation_sha256, installation_files, installation_bytes = (
            cls._installation_manifest_identity(
                source_root, kind="python-dist-info"
            )
        )
        cls._dependency_destination_is_empty(materialized_root, destination)
        cwd_path = Path(*cwd.parts) if cwd != PurePosixPath(".") else Path(".")
        executable_relative = os.path.relpath(
            str(Path(*destination.parts) / Path(executable_name)),
            start=str(cwd_path),
        )
        return (
            {
                "kind": "python-venv",
                "source_root": str(source_root),
                "source_device": source_metadata.st_dev,
                "source_inode": source_metadata.st_ino,
                "destination": str(destination),
                "locks": locks,
                "marker_path": str(marker_path),
                "marker_sha256": marker_sha256,
                "executable": executable_name,
                "installation_kind": "python-dist-info",
                "installation_sha256": installation_sha256,
                "installation_files": installation_files,
                "installation_bytes": installation_bytes,
                "toolchain": toolchain,
            },
            executable_relative,
        )

    @classmethod
    def _node_dependency(
        cls,
        *,
        launch: Mapping[str, object],
        original_root: Path,
        materialized_root: Path,
        dependency_locks: Mapping[str, object],
    ) -> Mapping[str, object] | None:
        argv = launch.get("argv")
        cwd_raw = launch.get("cwd")
        if (
            not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes))
            or not argv
            or not isinstance(argv[0], str)
            or (
                launch.get("driver") != "node"
                and PurePosixPath(str(argv[0])).name not in _NODE_EXECUTABLES
            )
        ):
            return None
        cwd = (
            PurePosixPath(".")
            if cwd_raw == "."
            else cls._dependency_relative(cwd_raw, field="immutable Node cwd")
        )
        lock_path = cwd / "package-lock.json"
        if str(lock_path) not in dependency_locks:
            if PurePosixPath(str(argv[0])).name in {"npm", "npmjs", "npx"}:
                raise TestStoreConflict(
                    "immutable Node dependency lock is not recorded"
                )
            return None
        destination = cwd / "node_modules"
        source_root = original_root.joinpath(*destination.parts)
        source_metadata = cls._real_dependency_directory(
            source_root, field="immutable Node dependency root"
        )
        locks = cls._validated_dependency_locks(
            dependency_locks=dependency_locks,
            lock_paths=[lock_path],
            original_root=original_root,
            materialized_root=materialized_root,
        )
        marker_path = PurePosixPath(".package-lock.json")
        marker_sha256 = cls._dependency_file_digest(
            source_root,
            marker_path,
            field="immutable Node dependency marker",
        )
        installation_sha256, installation_files, installation_bytes = (
            cls._installation_manifest_identity(
                source_root, kind="node-package-lock"
            )
        )
        cls._dependency_destination_is_empty(materialized_root, destination)
        return {
            "kind": "node-modules",
            "source_root": str(source_root),
            "source_device": source_metadata.st_dev,
            "source_inode": source_metadata.st_ino,
            "destination": str(destination),
            "locks": locks,
            "marker_path": str(marker_path),
            "marker_sha256": marker_sha256,
            "executable": None,
            "installation_kind": "node-package-lock",
            "installation_sha256": installation_sha256,
            "installation_files": installation_files,
            "installation_bytes": installation_bytes,
            "toolchain": None,
        }

    @classmethod
    def _dotnet_dependency(
        cls,
        *,
        launch: Mapping[str, object],
        original_root: Path,
        materialized_root: Path,
        dependency_locks: Mapping[str, object],
        owner_uid: int,
        account_uids: Sequence[int],
    ) -> tuple[
        Mapping[str, object] | None,
        str | None,
        Mapping[str, object] | None,
    ]:
        argv = launch.get("argv")
        if (
            not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes))
            or not argv
            or not isinstance(argv[0], str)
            or (
                launch.get("driver") != "dotnet"
                and PurePosixPath(str(argv[0])).name not in {"{dotnet}", "dotnet"}
            )
        ):
            return None, None, None
        ordered_uids = tuple(dict.fromkeys((owner_uid, *sorted(account_uids))))
        requested_sdk: str | None = None
        global_json_paths = sorted(
            (
                PurePosixPath(path)
                for path in dependency_locks
                if PurePosixPath(path).name.lower() == "global.json"
            ),
            key=lambda path: (-len(path.parts), str(path)),
        )
        for global_json_path in global_json_paths:
            try:
                payload, _metadata = cls._dependency_file_bytes(
                    original_root,
                    global_json_path,
                    field="immutable .NET SDK policy",
                )
                document = json.loads(payload)
            except (TestStoreConflict, ValueError):
                continue
            sdk = document.get("sdk") if isinstance(document, Mapping) else None
            version = sdk.get("version") if isinstance(sdk, Mapping) else None
            if (
                isinstance(version, str)
                and 0 < len(version) <= 128
                and PurePosixPath(version).name == version
                and version not in {".", ".."}
            ):
                requested_sdk = version
                break
        dotnet_executable: str | None = None
        dotnet_toolchain: Mapping[str, object] | None = None
        candidates: list[tuple[Path, bool]] = []
        for uid in ordered_uids:
            try:
                candidate = Path(pwd.getpwuid(uid).pw_dir) / ".dotnet" / "dotnet"
            except KeyError:
                continue
            try:
                metadata = candidate.lstat()
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            else:
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and resolved == candidate
                    and os.access(candidate, os.X_OK)
                ):
                    exact_sdk = requested_sdk is None
                    if requested_sdk is not None:
                        try:
                            cls._real_dependency_directory(
                                candidate.parent / "sdk" / requested_sdk,
                                field="requested .NET SDK",
                            )
                        except TestStoreConflict:
                            exact_sdk = False
                        else:
                            exact_sdk = True
                    candidates.append((candidate, exact_sdk))
        if candidates:
            candidate = next(
                (path for path, exact in candidates if exact),
                candidates[0][0],
            )
            dotnet_executable = str(candidate)
            toolchain_root = candidate.parent
            toolchain_metadata = cls._real_dependency_directory(
                toolchain_root, field="immutable .NET toolchain root"
            )
            (
                toolchain_sha256,
                toolchain_files,
                toolchain_bytes,
            ) = cls._installation_manifest_identity(
                toolchain_root, kind="dotnet-toolchain"
            )
            dotnet_toolchain = {
                "link_target": None,
                "resolved_executable": str(candidate),
                "source_root": str(toolchain_root),
                "source_device": toolchain_metadata.st_dev,
                "source_inode": toolchain_metadata.st_ino,
                "installation_kind": "dotnet-toolchain",
                "installation_sha256": toolchain_sha256,
                "installation_files": toolchain_files,
                "installation_bytes": toolchain_bytes,
            }
        lock_paths = [
            PurePosixPath(path)
            for path in dependency_locks
            if PurePosixPath(path).name.lower() == "packages.lock.json"
        ]
        if not lock_paths:
            standalone_toolchain = (
                None
                if dotnet_toolchain is None
                else {
                    key: value
                    for key, value in dotnet_toolchain.items()
                    if key != "link_target"
                }
            )
            return None, dotnet_executable, standalone_toolchain
        locks = cls._validated_dependency_locks(
            dependency_locks=dependency_locks,
            lock_paths=lock_paths,
            original_root=original_root,
            materialized_root=materialized_root,
        )
        lock_documents = [
            cls._dependency_file_bytes(
                original_root,
                lock_path,
                field="immutable .NET dependency lock",
            )[0]
            for lock_path in sorted(set(lock_paths), key=str)
        ]
        try:
            requirements = nuget_locked_package_requirements(lock_documents)
            required_paths = nuget_locked_package_source_paths(lock_documents)
        except TestStoreContractError as error:
            raise TestStoreConflict(
                "immutable .NET dependency lock contract is invalid"
            ) from error
        selected: tuple[Path, os.stat_result, tuple[str, int, int]] | None = None
        cache_failures: list[str] = []
        for uid in ordered_uids:
            try:
                home = Path(pwd.getpwuid(uid).pw_dir)
            except KeyError:
                continue
            source_root = home / ".nuget" / "packages"
            try:
                source_metadata = cls._real_dependency_directory(
                    source_root, field="immutable .NET package root"
                )
                for archive_path, sha_path, metadata_path, content_hash in requirements:
                    package = str(archive_path.parent)
                    # NuGet's lock hash is stored in .nupkg.metadata, while
                    # the neighbouring sha512 file authenticates the exact
                    # raw archive that the local source will serve.
                    try:
                        sha_payload, _sha_metadata = cls._dependency_file_bytes(
                            source_root,
                            sha_path,
                            field="immutable .NET package archive identity",
                        )
                        metadata_payload, _metadata = cls._dependency_file_bytes(
                            source_root,
                            metadata_path,
                            field="immutable .NET package restore identity",
                        )
                    except TestStoreConflict as error:
                        raise TestStoreConflict(
                            f"package {package} is missing source identity files"
                        ) from error
                    try:
                        _archive_digest, raw_sha512, _archive_size = (
                            nuget_package_archive_file_digests(
                                source_root, archive_path
                            )
                        )
                        expected_sha512 = nuget_package_sha512_digest(sha_payload)
                    except TestStoreContractError as error:
                        raise TestStoreConflict(
                            f"package {package} archive checksum is invalid"
                        ) from error
                    if raw_sha512 != expected_sha512:
                        raise TestStoreConflict(
                            f"package {package} archive does not match its checksum"
                        )
                    if (
                        nuget_package_metadata_content_hash(metadata_payload)
                        != content_hash
                    ):
                        raise TestStoreConflict(
                            f"package {package} metadata content differs from lock"
                        )
                installation_identity = cls._installation_manifest_identity(
                    source_root,
                    kind="nuget-package-source",
                    required_paths=required_paths,
                )
            except (TestStoreConflict, TestStoreContractError) as error:
                if len(cache_failures) < 8:
                    detail = " ".join(str(error).split())[:256]
                    cache_failures.append(f"uid {uid}: {detail}")
                continue
            selected = (source_root, source_metadata, installation_identity)
            break
        if selected is None:
            detail = "; ".join(cache_failures)
            raise TestStoreConflict(
                "immutable .NET package cache does not satisfy recorded locks"
                + (f" ({detail})" if detail else "")
            )
        source_root, source_metadata, installation_identity = selected
        installation_sha256, installation_files, installation_bytes = installation_identity
        destination = PurePosixPath(_DOTNET_PACKAGES_DESTINATION)
        cls._dependency_destination_is_empty(materialized_root, destination)
        return (
            {
                "kind": "dotnet-packages",
                "source_root": str(source_root),
                "source_device": source_metadata.st_dev,
                "source_inode": source_metadata.st_ino,
                "destination": str(destination),
                "locks": locks,
                "marker_path": None,
                "marker_sha256": None,
                "executable": None,
                "installation_kind": "nuget-package-source",
                "installation_sha256": installation_sha256,
                "installation_files": installation_files,
                "installation_bytes": installation_bytes,
                "toolchain": dotnet_toolchain,
            },
            dotnet_executable,
            None,
        )

    @classmethod
    def _immutable_dependencies(
        cls,
        *,
        launch: Mapping[str, object],
        original_root: str,
        materialized_root: str,
        source_provenance: Mapping[str, object],
        owner_uid: int,
        account_uids: Sequence[int] = (),
    ) -> tuple[
        tuple[Mapping[str, object], ...],
        str | None,
        str | None,
        tuple[Mapping[str, object], ...],
    ]:
        if source_provenance.get("complete") is not True:
            raise TestStoreConflict(
                "immutable dependency provenance is incomplete"
            )
        dependency_locks = source_provenance.get("dependency_locks")
        if not isinstance(dependency_locks, Mapping):
            raise TestStoreConflict(
                "immutable dependency lock provenance is invalid"
            )
        original = Path(original_root)
        materialized = Path(materialized_root)
        cls._real_dependency_directory(
            original, field="immutable dependency repository"
        )
        cls._real_dependency_directory(
            materialized, field="immutable dependency materialization"
        )
        bindings: list[Mapping[str, object]] = []
        python, python_executable = cls._python_dependency(
            launch=launch,
            original_root=original,
            materialized_root=materialized,
            dependency_locks=dependency_locks,
            account_uids=account_uids,
        )
        if python is not None:
            bindings.append(python)
        node = cls._node_dependency(
            launch=launch,
            original_root=original,
            materialized_root=materialized,
            dependency_locks=dependency_locks,
        )
        if node is not None:
            bindings.append(node)
        dotnet, dotnet_executable, standalone_dotnet_toolchain = cls._dotnet_dependency(
            launch=launch,
            original_root=original,
            materialized_root=materialized,
            dependency_locks=dependency_locks,
            owner_uid=owner_uid,
            account_uids=account_uids,
        )
        if dotnet is not None:
            bindings.append(dotnet)
        toolchains = (
            ()
            if standalone_dotnet_toolchain is None
            else (standalone_dotnet_toolchain,)
        )
        return tuple(bindings), python_executable, dotnet_executable, toolchains

    @staticmethod
    def _supplementary_developer_gids(
        account_uids: Sequence[int],
    ) -> tuple[int, ...]:
        gids: set[int] = set()
        for uid in account_uids:
            try:
                gids.add(int(pwd.getpwuid(uid).pw_gid))
            except KeyError:
                continue
        try:
            gids.add(int(grp.getgrnam("nogroup").gr_gid))
        except KeyError:
            pass
        return tuple(sorted(gid for gid in gids if gid >= 0))

    @staticmethod
    def _argv(
        values: Sequence[object],
        *,
        attempt_id: str,
        shard_index: int,
        shard_count: int,
        python_executable: str | None = None,
        dotnet_executable: str | None = None,
    ) -> tuple[str, ...]:
        replacements = {
            "{python}": python_executable or "/usr/bin/python3",
            "{node}": "/usr/bin/node",
            "{dotnet}": dotnet_executable or "/usr/bin/dotnet",
            "{events}": f".devcoordinator-test/{attempt_id}-events.jsonl",
            "{results}": f".devcoordinator-test/{attempt_id}-results.json",
            "{shard_index}": str(shard_index),
            "{shard_count}": str(shard_count),
        }
        result: list[str] = []
        for raw in values:
            if not isinstance(raw, str):
                raise TestStoreContractError("launch argv item is invalid")
            value = raw
            for placeholder, replacement in replacements.items():
                value = value.replace(placeholder, replacement)
            if "{" in value or "}" in value:
                raise TestStoreContractError("launch argv has an unresolved placeholder")
            result.append(value)
        return tuple(result)

    def resolve(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if set(arguments) != {"candidate", "lease", "plan"}:
            raise TestStoreContractError("snapshot resolve arguments are invalid")
        candidate_raw, lease_raw, plan_raw = (
            arguments["candidate"], arguments["lease"], arguments["plan"]
        )
        if not isinstance(candidate_raw, Mapping) or not isinstance(lease_raw, Mapping) or not isinstance(plan_raw, Mapping):
            raise TestStoreContractError("snapshot resolve documents are invalid")
        candidate = RunnableTarget(**candidate_raw)  # type: ignore[arg-type]
        lease = LeaseGrant(**lease_raw)  # type: ignore[arg-type]
        plan = decode_test_plan_document(plan_raw)
        catalog = None
        try:
            catalog = self._load_catalog(plan_raw)
        except FileNotFoundError:
            if plan.source.mode.value != "live":
                raise
        if (
            candidate.run_id != lease.run_id
            or candidate.target_id != lease.target_id
            or candidate.target_name not in plan.selected_targets
            or candidate.repository_id != plan.repository_id
            or candidate.source_mode != plan.source.mode.value
        ):
            raise TestStoreContractError("attempt selection identity is contradictory")
        authority = self.authority.live_execution_root(
            repository_id=candidate.repository_id,
            owner_uid=candidate.owner_uid,
            temporary_root=plan.source.temporary_root,
        )
        if (
            plan.source.original_root != authority["canonical_root"]
            or (
                plan.source.mode.value == "live"
                and candidate.worktree_key != authority["execution_root"]
            )
        ):
            raise TestStoreContractError("test plan source authority changed")
        if catalog is not None and (
            authority["generation"] != catalog["repository_generation"]
            or candidate.owner_uid != catalog["owner_uid"]
        ):
            raise TestStoreContractError("snapshot repository authority changed")
        launch_source = catalog
        if plan.source.mode.value == "live":
            fresh = self.helper.call(
                "live_plan",
                owner_uid=candidate.owner_uid,
                arguments={
                    "repository_id": candidate.repository_id,
                    "original_root": authority["canonical_root"],
                    "execution_root": (
                        plan.source.temporary_root
                        or authority["canonical_root"]
                    ),
                    "intent": plan.intent,
                    "requested_targets": self._requested_targets(plan),
                    "timeouts": plan.timeouts.to_document(),
                },
            )
            if set(fresh) != {"plan", "target_resources", "launch_catalog"}:
                raise TestStoreContractError("live prelaunch plan is incomplete")
            observed_plan = decode_test_plan_document(fresh["plan"])  # type: ignore[arg-type]
            if observed_plan.source.content_fingerprint != plan.source.content_fingerprint:
                raise LiveSourceChanged(observed_plan.source.content_fingerprint)
            if observed_plan.to_document() != plan.to_document():
                raise TestStoreConflict("live prelaunch plan is contradictory")
            if catalog is None:
                # Agent-created live plans are registered through testd rather
                # than previewed by snapshotd, so they do not yet have a
                # protected launch catalog.  Publish only the catalog that was
                # regenerated under the authoritative repository UID and
                # matched the admitted plan exactly.  This makes a later
                # snapshotd restart deterministic without trusting the agent's
                # manifest or launch descriptor.
                self._publish_catalog(
                    plan_id=plan.plan_id,
                    snapshot_id=self._source_catalog_id(plan),
                    value={
                        "schema_version": 1,
                        "plan": plan.to_document(),
                        "repository_generation": authority["generation"],
                        "owner_uid": candidate.owner_uid,
                        "launch_catalog": fresh["launch_catalog"],
                        "target_resources": fresh["target_resources"],
                        "source_provenance": {
                            "complete": False,
                            "content_fingerprint": plan.source.content_fingerprint,
                            "manifest_fingerprint": plan.manifest_fingerprint,
                            "dependency_locks": {},
                            "toolchain": {},
                        },
                    },
                )
            launch_source = fresh
        if launch_source is None:
            raise TestStoreContractError("snapshot launch catalog is unavailable")
        launch_catalog = launch_source["launch_catalog"]
        resources = launch_source["target_resources"]
        if not isinstance(launch_catalog, Mapping) or not isinstance(resources, Mapping):
            raise TestStoreContractError("snapshot launch catalog is incomplete")
        launch = launch_catalog.get(candidate.target_name)
        admitted = resources.get(candidate.target_name)
        if not isinstance(launch, Mapping) or not isinstance(admitted, Mapping):
            raise TestStoreContractError("snapshot target launch catalog is missing")
        # CPU, memory, and PID declarations are legacy descriptive metadata.
        # They are deliberately excluded from launch admission: current host
        # MemAvailable and learned peak memory govern capacity in testd.
        if (
            type(admitted.get("shard_count")) is not int
            or not 1 <= candidate.shard_count <= int(admitted["shard_count"])
            or candidate.worktree_key != admitted.get("worktree_key")
            or tuple(candidate.exclusive_resources)
            != tuple(admitted.get("exclusive_resources", ()))
        ):
            raise TestStoreContractError("snapshot target launch identity differs from plan")
        source_provenance = (
            dict(catalog.get("source_provenance", {}))
            if isinstance(catalog, Mapping)
            else {}
        )
        dependency_bindings: tuple[Mapping[str, object], ...] = ()
        toolchain_bindings: tuple[Mapping[str, object], ...] = ()
        python_executable: str | None = None
        dotnet_executable: str | None = None
        account_uids = (candidate.owner_uid,)
        supplementary_gids = self._supplementary_developer_gids(account_uids)
        if plan.source.mode.value == "immutable":
            (
                dependency_bindings,
                python_executable,
                dotnet_executable,
                toolchain_bindings,
            ) = self._immutable_dependencies(
                launch=launch,
                original_root=plan.source.original_root,
                materialized_root=candidate.worktree_key,
                source_provenance=source_provenance,
                owner_uid=candidate.owner_uid,
                account_uids=account_uids,
            )
        descriptor = TestAttemptDescriptor(
            attempt_id=lease.attempt_id,
            target_id=candidate.target_id,
            run_id=candidate.run_id,
            repository_id=candidate.repository_id,
            repository_generation=int(authority["generation"]),
            owner_uid=candidate.owner_uid,
            generation=lease.generation,
            source_mode=plan.source.mode.value,
            intent=plan.intent,
            snapshot_id=plan.source.snapshot_id,
            original_root=plan.source.original_root,
            temporary_root=plan.source.temporary_root,
            execution_root=candidate.worktree_key,
            worktree_key=candidate.worktree_key,
            target_name=candidate.target_name,
            shard_index=candidate.shard_index,
            shard_count=candidate.shard_count,
            argv=self._argv(
                launch["argv"],  # type: ignore[arg-type]
                attempt_id=lease.attempt_id,
                shard_index=candidate.shard_index,
                shard_count=candidate.shard_count,
                python_executable=python_executable,
                dotnet_executable=dotnet_executable,
            ),
            cwd=launch["cwd"],  # type: ignore[arg-type]
            environment=launch["environment"],  # type: ignore[arg-type]
            driver=launch["driver"],  # type: ignore[arg-type]
            reporter=launch["reporter"],  # type: ignore[arg-type]
            artifacts=tuple(launch["artifacts"]),  # type: ignore[arg-type]
            fixtures=tuple(launch["fixtures"]),  # type: ignore[arg-type]
            credentials=tuple(launch.get("credentials", ())),  # type: ignore[arg-type]
            fixture_bindings=tuple(launch.get("fixture_bindings", ())),  # type: ignore[arg-type]
            network=launch["network"],  # type: ignore[arg-type]
            ttl_seconds=launch["timeout_seconds"],  # type: ignore[arg-type]
            cpu_millis=candidate.cpu_millis,
            memory_mib=candidate.memory_mib,
            pids=candidate.pids,
            source_provenance=source_provenance,
            dependency_bindings=dependency_bindings,
            toolchain_bindings=toolchain_bindings,
            supplementary_gids=supplementary_gids,
        )
        return descriptor.to_document()

    def observe(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        if set(arguments) != {"repository_id", "owner_uid", "plan"}:
            raise TestStoreContractError("live observation arguments are invalid")
        repository_id = arguments["repository_id"]
        owner_uid = arguments["owner_uid"]
        plan_raw = arguments["plan"]
        if (
            not isinstance(repository_id, str)
            or type(owner_uid) is not int
            or not isinstance(plan_raw, Mapping)
        ):
            raise TestStoreContractError("live observation identity is invalid")
        plan = decode_test_plan_document(plan_raw)
        if plan.repository_id != repository_id or plan.source.mode.value != "live":
            raise TestStoreContractError("live observation plan is contradictory")
        catalog = None
        try:
            catalog = self._load_catalog(plan_raw)
        except FileNotFoundError:
            pass
        authority = self.authority.live_execution_root(
            repository_id=repository_id,
            owner_uid=owner_uid,
            temporary_root=plan.source.temporary_root,
        )
        if (
            authority["canonical_root"] != plan.source.original_root
            or authority["execution_root"]
            != (plan.source.temporary_root or plan.source.original_root)
            or (
                catalog is not None
                and (
                    authority["generation"] != catalog["repository_generation"]
                    or owner_uid != catalog["owner_uid"]
                )
            )
        ):
            raise TestStoreContractError("live observation authority changed")
        fresh = self.helper.call(
            "live_plan",
            owner_uid=owner_uid,
            arguments={
                "repository_id": repository_id,
                "original_root": authority["canonical_root"],
                "execution_root": (
                    plan.source.temporary_root
                    or authority["canonical_root"]
                ),
                "intent": plan.intent,
                "requested_targets": self._requested_targets(plan),
            },
        )
        if set(fresh) != {"plan", "target_resources", "launch_catalog"}:
            raise TestStoreContractError("live observation result is incomplete")
        observed = decode_test_plan_document(fresh["plan"])  # type: ignore[arg-type]
        if (
            observed.repository_id != repository_id
            or observed.intent != plan.intent
            or observed.source.mode.value != "live"
            or observed.source.original_root != plan.source.original_root
        ):
            raise TestStoreContractError("live observation result is contradictory")
        return {"source_fingerprint": observed.source.content_fingerprint}


class UnixSnapshotServiceClient(RepositoryUIDPlanPreviewer, RepositoryLaunchDescriptorResolver):
    def __init__(
        self,
        socket_path: Path,
        *,
        expected_server_uid: int = 0,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        del expected_server_uid
        self.last_peer_uid: int | None = None
        self.call_journal = call_journal

    def _record(
        self,
        *,
        phase: str,
        call_id: str,
        operation: str,
        request_id: str,
        arguments: object,
        started_at: float,
        outcome: str,
        code: str | None = None,
        message: str | None = None,
        diagnostic: Mapping[str, object] | None = None,
    ) -> None:
        call_journal = getattr(self, "call_journal", None)
        if call_journal is None:
            return
        repository_id, run_id, attempt_id = _snapshot_correlations(arguments)
        call_journal.record(
            event_record(
                boundary="snapshot_client",
                phase=phase,
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_uid=getattr(self, "last_peer_uid", None),
                duration_seconds=(
                    None
                    if phase == "received"
                    else time.monotonic() - started_at
                ),
                outcome=outcome,
                code=code,
                message=message,
                repository_id=repository_id,
                run_id=run_id,
                attempt_id=attempt_id,
                diagnostic=diagnostic,
            )
        )

    def _call(
        self,
        operation: str,
        arguments: Mapping[str, object],
        *,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        request_id = str(uuid.uuid4())
        call_id = str(uuid.uuid4())
        started_at = monotonic_started()
        self.last_peer_uid = None
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or float(timeout_seconds) <= 0
        ):
            raise TestStoreContractError("snapshot service timeout is invalid")
        request_timeout = (
            180.0 if timeout_seconds is None else float(timeout_seconds)
        )
        if operation == "preview":
            try:
                timeouts = TestPlanTimeouts(
                    launch_seconds=arguments.get("launch_timeout_seconds", 300)
                )
            except TestPlanError as error:
                raise TestStoreContractError(
                    "snapshot preview timeouts are invalid"
                ) from error
            # The semantic work remains bounded by launch_seconds.  This
            # transport-only margin lets snapshotd return its typed terminal
            # result instead of racing the client socket deadline.
            request_timeout = (
                float(timeouts.launch_seconds + 30)
                if timeout_seconds is None
                else min(request_timeout, float(timeouts.launch_seconds + 30))
            )
        self._record(
            phase="received",
            call_id=call_id,
            operation=operation,
            request_id=request_id,
            arguments=arguments,
            started_at=started_at,
            outcome="received",
        )
        stage = "connect"
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with connection:
                connection.settimeout(request_timeout)
                connection.connect(str(self.socket_path))
                # Preserve best-effort peer attribution without using a local UID
                # as a tenancy boundary on this single-developer host.
                self.last_peer_uid = _peer_uid(connection)
                stage = "send"
                _send(
                    connection,
                    {
                        "schema_version": SNAPSHOT_SERVICE_SCHEMA_VERSION,
                        "request_id": request_id,
                        "operation": operation,
                        "arguments": dict(arguments),
                    },
                )
                stage = "receive"
                response = _receive(connection)
            stage = "validate"
            if (
                response.get("request_id") != request_id
                or type(response.get("ok")) is not bool
            ):
                raise TestStoreContractError(
                    "snapshot service response identity is invalid"
                )
            if not response["ok"]:
                error = response.get("error")
                if (
                    isinstance(error, Mapping)
                    and error.get("code") == "live_source_changed"
                    and isinstance(error.get("observed_source_fingerprint"), str)
                ):
                    raise LiveSourceChanged(
                        str(error["observed_source_fingerprint"])
                    )
                code = (
                    str(error.get("code"))
                    if isinstance(error, Mapping)
                    and isinstance(error.get("code"), str)
                    else "snapshot_failed"
                )
                diagnostic = (
                    error.get("diagnostic")
                    if isinstance(error, Mapping)
                    and isinstance(error.get("diagnostic"), Mapping)
                    else None
                )
                raise SnapshotServiceRemoteError(
                    code,
                    str(
                        error.get("message")
                        if isinstance(error, Mapping)
                        else "snapshot service failed"
                    ),
                    diagnostic,
                )
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise TestStoreContractError("snapshot service result is invalid")
        except Exception as error:
            if isinstance(error, SnapshotServiceRemoteError):
                outcome = "rejected"
                code = error.code
                message = "snapshot service rejected the call"
                diagnostic = error.diagnostic
                phase = "rejected"
            elif isinstance(error, LiveSourceChanged):
                outcome = "rejected"
                code = "live_source_changed"
                message = "live source changed during snapshot processing"
                diagnostic = diagnostic_for_exception(
                    error, stage=f"snapshot_client.{stage}"
                )
                phase = "rejected"
            elif isinstance(error, (socket.timeout, TimeoutError)):
                outcome = "timeout"
                code = "snapshot_transport_timeout"
                message = f"snapshot service {stage} timed out"
                diagnostic = diagnostic_for_exception(
                    error, stage=f"snapshot_client.{stage}"
                )
                phase = "completed"
            elif isinstance(error, OSError):
                outcome = "unavailable"
                code = "snapshot_transport_unavailable"
                message = f"snapshot service {stage} is unavailable"
                diagnostic = diagnostic_for_exception(
                    error, stage=f"snapshot_client.{stage}"
                )
                phase = "completed"
            else:
                outcome = "failed"
                code = "snapshot_response_invalid"
                message = "snapshot service response is invalid"
                diagnostic = diagnostic_for_exception(
                    error, stage=f"snapshot_client.{stage}"
                )
                phase = "completed"
            self._record(
                phase=phase,
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                arguments=arguments,
                started_at=started_at,
                outcome=outcome,
                code=code,
                message=message,
                diagnostic=diagnostic,
            )
            raise
        self._record(
            phase="completed",
            call_id=call_id,
            operation=operation,
            request_id=request_id,
            arguments=arguments,
            started_at=started_at,
            outcome="ok",
        )
        return result

    def preview_as_owner(self, **arguments) -> Mapping[str, object]:
        return self._call("preview", arguments)

    def setup_as_owner(self, **arguments) -> Mapping[str, object]:
        return self._call("setup", arguments)

    def resolve_as_owner(
        self,
        *,
        candidate,
        lease,
        plan_document,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        return self._call(
            "resolve",
            {
                "candidate": asdict(candidate),
                "lease": asdict(lease),
                "plan": dict(plan_document),
            },
            timeout_seconds=timeout_seconds,
        )

    def observe_live_source_as_owner(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        plan_document: Mapping[str, object],
    ) -> str:
        result = self._call(
            "observe",
            {
                "repository_id": repository_id,
                "owner_uid": owner_uid,
                "plan": dict(plan_document),
            },
        )
        if set(result) != {"source_fingerprint"} or not isinstance(
            result["source_fingerprint"], str
        ):
            raise TestStoreContractError("live source observation result is invalid")
        return str(result["source_fingerprint"])


class UnixSnapshotServiceServer:
    def __init__(
        self,
        listener: socket.socket,
        service: RootSnapshotService,
        *,
        allowed_peer_uid: int,
        call_journal: RollingCallJournal | None = None,
    ) -> None:
        self.listener = listener
        self.service = service
        del allowed_peer_uid
        self.last_peer_uid: int | None = None
        self.call_journal = call_journal

    def _record(
        self,
        *,
        phase: str,
        call_id: str,
        operation: str | None,
        request_id: str | None,
        peer_pid: int | None,
        peer_uid: int | None,
        peer_gid: int | None,
        arguments: object,
        started_at: float,
        outcome: str,
        code: str | None = None,
        message: str | None = None,
        diagnostic: Mapping[str, object] | None = None,
    ) -> None:
        if self.call_journal is None:
            return
        repository_id, run_id, attempt_id = _snapshot_correlations(arguments)
        self.call_journal.record(
            event_record(
                boundary="snapshotd",
                phase=phase,
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                duration_seconds=(
                    None
                    if phase == "received"
                    else time.monotonic() - started_at
                ),
                outcome=outcome,
                code=code,
                message=message,
                repository_id=repository_id,
                run_id=run_id,
                attempt_id=attempt_id,
                diagnostic=diagnostic,
            )
        )

    def serve_connection(self, connection: socket.socket) -> None:
        call_id = str(uuid.uuid4())
        started_at = monotonic_started()
        request_id: str | None = None
        operation: str | None = None
        arguments: object = None
        peer_pid: int | None = None
        peer_uid: int | None = None
        peer_gid: int | None = None
        received_recorded = False
        try:
            # Capture local attribution only.  AF_UNIX connectivity is the
            # trust boundary; all local accounts belong to one developer.
            peer_pid, peer_uid, peer_gid = _peer_identity(connection)
            if peer_uid is None:
                peer_uid = _peer_uid(connection)
            self.last_peer_uid = peer_uid
            request = _receive(connection)
            request_id = request.get("request_id")
            if (
                request.get("schema_version") != SNAPSHOT_SERVICE_SCHEMA_VERSION
                or not isinstance(request_id, str)
                or not isinstance(request.get("arguments"), Mapping)
            ):
                raise TestStoreContractError("snapshot service request is invalid")
            operation = request.get("operation")
            arguments = request.get("arguments")
            self._record(
                phase="received",
                call_id=call_id,
                operation=operation if isinstance(operation, str) else None,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                arguments=arguments,
                started_at=started_at,
                outcome="received",
            )
            received_recorded = True
            if operation == "setup":
                result = self.service.setup(request["arguments"])
            elif operation == "preview":
                result = self.service.preview(request["arguments"])
            elif operation == "resolve":
                result = self.service.resolve(request["arguments"])
            elif operation == "observe":
                result = self.service.observe(request["arguments"])
            else:
                raise TestStoreContractError("snapshot service operation is unsupported")
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "ok": True,
                "result": result,
            }
            self._record(
                phase="completed",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                arguments=arguments,
                started_at=started_at,
                outcome="ok",
            )
        except LiveSourceChanged as error:
            if not received_recorded:
                self._record(
                    phase="received",
                    call_id=call_id,
                    operation=operation,
                    request_id=request_id,
                    peer_pid=peer_pid,
                    peer_uid=peer_uid,
                    peer_gid=peer_gid,
                    arguments=arguments,
                    started_at=started_at,
                    outcome="received",
                )
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": "live_source_changed",
                    "message": str(error),
                    "observed_source_fingerprint": error.observed_source_fingerprint,
                },
            }
            self._record(
                phase="rejected",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                arguments=arguments,
                started_at=started_at,
                outcome="rejected",
                code="live_source_changed",
                message=str(error),
                diagnostic=diagnostic_for_exception(
                    error, stage=_snapshot_failure_stage(operation, error)
                ),
            )
        except Exception as error:
            code = _snapshot_failure_code(error)
            diagnostic = diagnostic_for_exception(
                error, stage=_snapshot_failure_stage(operation, error)
            )
            if not received_recorded:
                self._record(
                    phase="received",
                    call_id=call_id,
                    operation=operation,
                    request_id=request_id,
                    peer_pid=peer_pid,
                    peer_uid=peer_uid,
                    peer_gid=peer_gid,
                    arguments=arguments,
                    started_at=started_at,
                    outcome="received",
                )
            response = {
                "schema_version": 1,
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": code,
                    "message": str(error)[:2048],
                    "diagnostic": diagnostic,
                },
            }
            self._record(
                phase="rejected",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                arguments=arguments,
                started_at=started_at,
                outcome=("timeout" if code == "snapshot_timeout" else "rejected"),
                code=code,
                message=str(error),
                diagnostic=diagnostic,
            )
        try:
            _send(connection, response)
        except (OSError, TestStoreContractError, TypeError, ValueError) as error:
            # The request has already been handled.  A local client may time
            # out or cancel before it reads the reply; that ends only this
            # connection and must not escape into serve_forever.
            self._record(
                phase="completed",
                call_id=call_id,
                operation=operation,
                request_id=request_id,
                peer_pid=peer_pid,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                arguments=arguments,
                started_at=started_at,
                outcome=(
                    "timeout"
                    if isinstance(error, (socket.timeout, TimeoutError))
                    else "unavailable"
                ),
                code=(
                    "reply_delivery_timeout"
                    if isinstance(error, (socket.timeout, TimeoutError))
                    else "reply_delivery_failed"
                ),
                message="snapshot service reply could not be delivered",
                diagnostic=diagnostic_for_exception(
                    error, stage="snapshotd.reply_delivery"
                ),
            )
            return

    def serve_forever(self) -> None:
        while True:
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            with connection:
                self.serve_connection(connection)


__all__ = [
    "RootSnapshotService",
    "SnapshotAuthority",
    "SnapshotServiceRemoteError",
    "UIDDelegatedSnapshotSource",
    "UIDHelperRunner",
    "UnixSnapshotServiceClient",
    "UnixSnapshotServiceServer",
]
