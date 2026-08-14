#!/usr/bin/python3
"""Fixed inspection helper for authority-bound immutable test snapshots.

The root snapshot service launches read-only operations as the protected
control plane and repository-writing adoption operations as the repository
owner. The helper may parse repository metadata, but it never executes
repository content or writes the protected snapshot store.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Mapping, Sequence

# The helper imports from an immutable, root-owned release.  Root can bypass
# directory mode bits, so suppress bytecode explicitly before package imports.
sys.dont_write_bytecode = True

if __package__ in {None, ""}:
    # In the source tree this helper lives below ``scripts/devcoordinator``;
    # immutable releases also publish the same bytes at ``libexec``.  Locate
    # the package from either fixed layout without inheriting PYTHONPATH (the
    # privileged caller deliberately uses ``python -I``).
    helper_path = Path(__file__).resolve()
    package_roots = (
        helper_path.parents[1],
        helper_path.parents[1]
        / "skills"
        / "codex-dev-coordinator"
        / "scripts",
    )
    for package_root in package_roots:
        if (package_root / "devcoordinator").is_dir():
            sys.path.insert(0, str(package_root))
            break

from devcoordinator.universal_test_contract import (  # type: ignore[import-not-found]
    MAX_MANIFEST_BYTES,
    ManifestContractError,
    SourceMode,
    TestManifest,
    parse_test_manifest,
    repository_glob_matches,
    safe_history_shard_ceiling,
)
from devcoordinator.universal_test_planner import (  # type: ignore[import-not-found]
    DEFAULT_LAUNCH_TIMEOUT_SECONDS,
    MAX_EXECUTION_TIMEOUT_SECONDS,
    MAX_LAUNCH_TIMEOUT_SECONDS,
    SourceIdentity,
    create_test_plan,
)
from devcoordinator.universal_test_snapshot import (  # type: ignore[import-not-found]
    GitSnapshotSource,
    MAX_GIT_METADATA_BYTES,
    MAX_SNAPSHOT_FILES,
    SnapshotMaterializationError,
    SnapshotMaterializationRequest,
)


MAX_HELPER_REQUEST_BYTES = 512 * 1024
MAX_HELPER_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_SETUP_RESULT_BYTES = 192 * 1024
MAX_UNREADABLE_ENTRIES = 256
MAX_SETUP_INPUT_COVERAGE_PATH_GAPS = 128
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

_UNMAPPED_INPUT_MESSAGE = (
    "repository path is not mapped by global inputs or target inputs"
)
_UNMAPPED_INPUT_DETAIL = (
    "changes to this path select the complete required intent"
)
_TRUNCATED_INPUT_MESSAGE = (
    "additional repository paths are not mapped by global inputs or target inputs"
)
_TRUNCATED_INPUT_DETAIL = (
    "the bounded Setup projection omits additional unmapped paths"
)
_INCOMPLETE_INPUT_MESSAGE = "repository input coverage could not be fully inspected"
_INCOMPLETE_INPUT_DETAIL = (
    "unmapped paths may exist; uncertain changes still select the complete required intent"
)


def _read_fd_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise SnapshotMaterializationError("existing test manifest is too large")


def _manifest_payload(document: object, *, root: Path) -> tuple[bytes, str]:
    if not isinstance(document, Mapping):
        raise SnapshotMaterializationError(
            "manifest adoption requires an explicit final manifest document"
        )
    manifest = parse_test_manifest(document, repository_root=root)
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise SnapshotMaterializationError("proposed test manifest is too large")
    return payload, manifest.fingerprint


def _manifest_directory(root: Path, *, owner_uid: int, create: bool) -> Path | None:
    directory = root / ".codex"
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        if not create:
            return None
        directory.mkdir(mode=0o755)
        metadata = directory.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or directory.resolve(strict=True) != directory
    ):
        raise SnapshotMaterializationError("test manifest directory is unsafe")
    return directory


def _manifest_state(
    root: Path, *, owner_uid: int, include_valid_document: bool = False
) -> dict[str, object]:
    directory = _manifest_directory(root, owner_uid=owner_uid, create=False)
    if directory is None:
        result: dict[str, object] = {
            "status": "missing",
            "current_digest": None,
            "current_mode": None,
            "current_payload_base64": None,
        }
        if include_valid_document:
            result["current_manifest"] = None
        return result
    path = directory / "tests.json"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        result = {
            "status": "missing",
            "current_digest": None,
            "current_mode": None,
            "current_payload_base64": None,
        }
        if include_valid_document:
            result["current_manifest"] = None
        return result
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_MANIFEST_BYTES
    ):
        raise SnapshotMaterializationError("existing test manifest is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            raise SnapshotMaterializationError("existing test manifest identity changed")
        payload = _read_fd_bounded(descriptor, MAX_MANIFEST_BYTES)
    finally:
        os.close(descriptor)
    if len(payload) != metadata.st_size or len(payload) > MAX_MANIFEST_BYTES:
        raise SnapshotMaterializationError("existing test manifest changed while reading")
    digest = hashlib.sha256(payload).hexdigest()
    document: object | None = None
    try:
        document = json.loads(payload.decode("utf-8"))
        parse_test_manifest(document, repository_root=root)
        status = "ready"
    except Exception:
        status = "invalid"
    result: dict[str, object] = {
        "status": status,
        "current_digest": digest,
        "current_mode": stat.S_IMODE(metadata.st_mode),
        "current_payload_base64": (
            base64.b64encode(payload).decode("ascii") if status == "invalid" else None
        ),
    }
    if include_valid_document:
        result["current_manifest"] = document if status == "ready" else None
    return result


def _adoption_catalog(root: Path, *, owner_uid: int) -> Mapping[str, object]:
    """Return bounded manifest state without exposing invalid repository bytes."""

    try:
        state = _manifest_state(
            root, owner_uid=owner_uid, include_valid_document=True
        )
    except (OSError, SnapshotMaterializationError) as error:
        # One unsafe repository must not erase the fleet-wide census.  Return a
        # bounded classification, without paths, metadata, or repository bytes;
        # request preparation still refuses these rows until an administrator
        # repairs their ownership/mode separately.
        problem = {
            "test manifest directory is unsafe": "unsafe_manifest_directory",
            "existing test manifest is unsafe": "unsafe_manifest_file",
            "existing test manifest identity changed": "unstable_manifest_file",
            "existing test manifest changed while reading": "unstable_manifest_file",
        }.get(str(error), "manifest_inspection_failed")
        return {
            "status": "invalid",
            "current_digest": None,
            "current_mode": None,
            "current_manifest": None,
            "problem_code": problem,
        }
    status = str(state["status"])
    return {
        "status": status,
        "current_digest": state["current_digest"],
        "current_mode": state["current_mode"],
        "current_manifest": state["current_manifest"],
        "problem_code": (
            "invalid_manifest_document" if status == "invalid" else None
        ),
    }


def _metadata_identity(path: Path) -> Mapping[str, object]:
    metadata = path.lstat()
    kind = (
        "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "regular"
        if stat.S_ISREG(metadata.st_mode)
        else "symlink"
        if stat.S_ISLNK(metadata.st_mode)
        else "special"
    )
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "kind": kind,
        "nlink": metadata.st_nlink,
        "size": metadata.st_size,
    }


def _optional_metadata_identity(path: Path) -> Mapping[str, object] | None:
    try:
        return _metadata_identity(path)
    except FileNotFoundError:
        return None


def _adoption_safety_identity(
    root: Path, *, owner_uid: int
) -> Mapping[str, object]:
    """Return bounded, owner-observed evidence for exact metadata repair.

    This operation never changes the worktree.  It proves that the authority
    root is the current Git top-level and counts tracked entries that the
    repository owner cannot read.  Samples are hashes, not repository paths.
    """

    root_identity = _metadata_identity(root)
    git_marker = root / ".git"
    git_marker_identity = _optional_metadata_identity(git_marker)
    if git_marker_identity is None:
        return {
            "root_identity": root_identity,
            "git_marker_identity": None,
            "git_head": None,
            "tracked_entry_count": None,
            "deletion_scan_complete": False,
            "deleted_tracked_count": None,
            "unreadable_tracked_count": None,
            "unreadable_tracked_sample": [],
            "unreadable_tracked_entries_complete": False,
            "unreadable_tracked_entries": [],
            "codex_identity": _optional_metadata_identity(root / ".codex"),
            "manifest_identity": None,
            "manifest_sha256": None,
            "problem_code": "git_marker_missing",
        }
    try:
        top = GitSnapshotSource._git(
            root, ["rev-parse", "--show-toplevel"], maximum_bytes=4096
        ).decode("utf-8", errors="strict").strip()
        if Path(top).resolve(strict=True) != root:
            raise SnapshotMaterializationError(
                "repository is not the exact Git worktree root"
            )
        head = GitSnapshotSource._git(
            root, ["rev-parse", "--verify", "HEAD"], maximum_bytes=1024
        ).decode("ascii", errors="strict").strip().lower()
        if (
            len(head) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in head)
        ):
            raise SnapshotMaterializationError("repository Git HEAD is invalid")
        tracked = GitSnapshotSource._paths(
            GitSnapshotSource._git(
                root,
                ["ls-files", "-z", "--cached"],
                maximum_bytes=MAX_GIT_METADATA_BYTES,
            ),
            "tracked path",
        )
        if len(tracked) > MAX_SNAPSHOT_FILES:
            raise SnapshotMaterializationError(
                "repository tracked entry count exceeds its bound"
            )
    except (OSError, UnicodeError, SnapshotMaterializationError):
        return {
            "root_identity": root_identity,
            "git_marker_identity": git_marker_identity,
            "git_head": None,
            "tracked_entry_count": None,
            "deletion_scan_complete": False,
            "deleted_tracked_count": None,
            "unreadable_tracked_count": None,
            "unreadable_tracked_sample": [],
            "unreadable_tracked_entries_complete": False,
            "unreadable_tracked_entries": [],
            "codex_identity": _optional_metadata_identity(root / ".codex"),
            "manifest_identity": None,
            "manifest_sha256": None,
            "problem_code": "git_inspection_failed",
        }

    try:
        deleted = GitSnapshotSource._paths(
            GitSnapshotSource._git(
                root,
                ["diff", "--name-only", "-z", "--diff-filter=D", "HEAD", "--"],
                maximum_bytes=MAX_GIT_METADATA_BYTES,
            ),
            "deleted path",
        )
        if not deleted <= tracked:
            raise SnapshotMaterializationError(
                "repository deleted paths are not a subset of tracked paths"
            )
        deletion_scan_complete = True
    except (OSError, UnicodeError, SnapshotMaterializationError):
        # Preserve the independently established Git identity and enumerate
        # unreadable content. The safety assessment still blocks because a
        # deletion cannot be distinguished from incomplete content.
        deleted = set()
        deletion_scan_complete = False

    unreadable: list[str] = []
    unreadable_entries: list[dict[str, object]] = []
    # A Git-proven deletion is a valid change input. Match the immutable
    # snapshot scanner exactly: only content that should still exist must be
    # readable by the repository owner. A missing skip-worktree entry remains
    # incomplete and therefore fails closed.
    for relative in sorted(tracked - deleted):
        candidate = root / relative
        try:
            metadata = candidate.lstat()
            readable = (
                True
                if stat.S_ISLNK(metadata.st_mode)
                else os.access(
                    candidate,
                    os.R_OK
                    | (os.X_OK if stat.S_ISDIR(metadata.st_mode) else 0),
                    effective_ids=True,
                )
            )
        except OSError:
            readable = False
        if not readable:
            path_hash = hashlib.sha256(relative.encode("utf-8")).hexdigest()[:16]
            unreadable.append(path_hash)
            if len(unreadable_entries) < MAX_UNREADABLE_ENTRIES:
                try:
                    identity = _metadata_identity(candidate)
                except OSError:
                    identity = None
                unreadable_entries.append(
                    {
                        "relative_path": relative,
                        "path_hash": path_hash,
                        "identity": identity,
                    }
                )

    codex = root / ".codex"
    codex_identity = _optional_metadata_identity(codex)
    manifest_identity: Mapping[str, object] | None = None
    manifest_sha256: str | None = None
    if codex_identity is not None and codex_identity["kind"] == "directory":
        manifest = codex / "tests.json"
        manifest_identity = _optional_metadata_identity(manifest)
        if (
            manifest_identity is not None
            and manifest_identity["kind"] == "regular"
            and manifest_identity["nlink"] == 1
            and int(manifest_identity["size"]) <= MAX_MANIFEST_BYTES
        ):
            try:
                descriptor = os.open(
                    manifest, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    payload = _read_fd_bounded(descriptor, MAX_MANIFEST_BYTES)
                finally:
                    os.close(descriptor)
                if len(payload) == manifest_identity["size"]:
                    manifest_sha256 = hashlib.sha256(payload).hexdigest()
            except OSError:
                manifest_sha256 = None

    return {
        "root_identity": root_identity,
        "git_marker_identity": git_marker_identity,
        "git_head": head,
        "tracked_entry_count": len(tracked),
        "deletion_scan_complete": deletion_scan_complete,
        "deleted_tracked_count": len(deleted) if deletion_scan_complete else None,
        "unreadable_tracked_count": len(unreadable),
        "unreadable_tracked_sample": unreadable[:8],
        "unreadable_tracked_entries_complete": (
            len(unreadable_entries) == len(unreadable)
        ),
        "unreadable_tracked_entries": unreadable_entries,
        "codex_identity": codex_identity,
        "manifest_identity": manifest_identity,
        "manifest_sha256": manifest_sha256,
        "problem_code": None,
    }


def _adoption_inspect(
    root: Path, *, owner_uid: int, proposed_manifest: object
) -> Mapping[str, object]:
    state = _manifest_state(root, owner_uid=owner_uid)
    try:
        payload, fingerprint = _manifest_payload(proposed_manifest, root=root)
    except SnapshotMaterializationError:
        raise
    except Exception as error:
        raise SnapshotMaterializationError(
            "proposed final test manifest is invalid"
        ) from error
    status = str(state["status"])
    proposed_digest = hashlib.sha256(payload).hexdigest()
    return {
        **state,
        "action": (
            "preserve_valid"
            if status == "ready"
            else "initialize" if status == "missing" else "migrate"
        ),
        "proposed_digest": proposed_digest,
        "proposed_fingerprint": fingerprint,
        "proposed_matches": state["current_digest"] == proposed_digest,
    }


def _write_manifest(
    directory: Path,
    *,
    payload: bytes,
    mode: int,
    require_missing: bool,
) -> None:
    path = directory / "tests.json"
    descriptor, name = tempfile.mkstemp(prefix=".tests.json.adoption-", dir=directory)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if require_missing:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError as error:
                raise SnapshotMaterializationError(
                    "test manifest appeared after adoption preflight"
                ) from error
        else:
            os.replace(temporary, path)
        directory_descriptor = os.open(
            directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _adoption_apply(
    root: Path, *, owner_uid: int, arguments: Mapping[str, object]
) -> Mapping[str, object]:
    expected = {
        "repository_root",
        "expected_status",
        "expected_current_digest",
        "proposed_manifest",
        "expected_proposed_digest",
        "operation_id",
    }
    if set(arguments) != expected:
        raise SnapshotMaterializationError("manifest adoption apply arguments are invalid")
    try:
        __import__("uuid").UUID(str(arguments["operation_id"]))
    except (TypeError, ValueError) as error:
        raise SnapshotMaterializationError("manifest adoption operation identity is invalid") from error
    directory = _manifest_directory(root, owner_uid=owner_uid, create=True)
    if directory is None:
        raise SnapshotMaterializationError("test manifest directory is unavailable")
    directory_descriptor = os.open(
        directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        fcntl.flock(directory_descriptor, fcntl.LOCK_EX)
        inspection = _adoption_inspect(
            root,
            owner_uid=owner_uid,
            proposed_manifest=arguments["proposed_manifest"],
        )
        if (
            inspection["status"] != arguments["expected_status"]
            or inspection["current_digest"] != arguments["expected_current_digest"]
            or inspection["proposed_digest"] != arguments["expected_proposed_digest"]
        ):
            raise SnapshotMaterializationError("test manifest changed after adoption preflight")
        if inspection["status"] == "ready":
            raise SnapshotMaterializationError("valid final test manifest cannot be overwritten")
        payload, fingerprint = _manifest_payload(
            arguments["proposed_manifest"], root=root
        )
        _write_manifest(
            directory,
            payload=payload,
            mode=0o644,
            require_missing=inspection["status"] == "missing",
        )
        final = _manifest_state(root, owner_uid=owner_uid)
        final_digest = hashlib.sha256(payload).hexdigest()
        if final["status"] != "ready" or final["current_digest"] != final_digest:
            raise SnapshotMaterializationError("adopted test manifest failed verification")
        return {
            "status": "ready",
            "final_digest": final_digest,
            "manifest_fingerprint": fingerprint,
        }
    finally:
        os.close(directory_descriptor)


def _adoption_rollback(
    root: Path, *, owner_uid: int, arguments: Mapping[str, object]
) -> Mapping[str, object]:
    expected = {
        "repository_root",
        "expected_final_digest",
        "original_status",
        "original_digest",
        "original_mode",
        "original_payload_base64",
        "operation_id",
    }
    if set(arguments) != expected:
        raise SnapshotMaterializationError("manifest adoption rollback arguments are invalid")
    try:
        __import__("uuid").UUID(str(arguments["operation_id"]))
    except (TypeError, ValueError) as error:
        raise SnapshotMaterializationError(
            "manifest adoption rollback operation identity is invalid"
        ) from error
    directory = _manifest_directory(root, owner_uid=owner_uid, create=False)
    if directory is None:
        raise SnapshotMaterializationError("adopted test manifest directory disappeared")
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = _manifest_state(root, owner_uid=owner_uid)
        if (
            current["status"] != "ready"
            or current["current_digest"] != arguments["expected_final_digest"]
        ):
            raise SnapshotMaterializationError("adopted test manifest drifted before rollback")
        original_status = arguments["original_status"]
        if original_status == "missing":
            if (
                arguments["original_digest"] is not None
                or arguments["original_mode"] is not None
                or arguments["original_payload_base64"] is not None
            ):
                raise SnapshotMaterializationError("missing rollback evidence is contradictory")
            (directory / "tests.json").unlink()
            os.fsync(descriptor)
        elif original_status == "invalid":
            digest = arguments["original_digest"]
            mode = arguments["original_mode"]
            encoded = arguments["original_payload_base64"]
            if (
                not isinstance(digest, str)
                or type(mode) is not int
                or not isinstance(encoded, str)
            ):
                raise SnapshotMaterializationError("invalid rollback evidence is incomplete")
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as error:
                raise SnapshotMaterializationError("invalid rollback payload is malformed") from error
            if hashlib.sha256(payload).hexdigest() != digest or len(payload) > MAX_MANIFEST_BYTES:
                raise SnapshotMaterializationError("invalid rollback payload digest is wrong")
            _write_manifest(
                directory,
                payload=payload,
                mode=mode,
                require_missing=False,
            )
        else:
            raise SnapshotMaterializationError("valid final manifests are not rollback targets")
        restored = _manifest_state(root, owner_uid=owner_uid)
        if (
            restored["status"] != original_status
            or restored["current_digest"] != arguments["original_digest"]
        ):
            raise SnapshotMaterializationError("test manifest rollback failed verification")
        return restored
    finally:
        os.close(descriptor)


def _setup_status(status: str, *, code: str | None = None) -> dict[str, object]:
    issues: list[dict[str, str]] = []
    if code is not None:
        issues.append(
            {
                "code": code,
                "message": (
                    "repository test manifest is missing"
                    if code == "manifest_missing"
                    else "repository test manifest is invalid"
                ),
            }
        )
    return {
        "schema_version": 1,
        "ok": status == "ready",
        "status": status,
        "manifest_schema": None,
        "manifest_fingerprint": None,
        "targets": [],
        "target_graph": {},
        "input_coverage": {
            "global_input_count": 0,
            "target_input_count": 0,
            "targets_with_inputs": 0,
        },
        "input_coverage_gaps": [],
        "intents": [],
        "evidence_policies": [],
        "fixtures": [],
        "credentials": [],
        "network_requirements": [],
        "isolation": {
            "network": "none",
            "cpu_millis": 0,
            "memory_mib": 0,
            "pids": 0,
            "private_scratch": True,
            "kill_after_run": True,
        },
        "issues": issues,
    }


def _repository_input_paths(root: Path) -> tuple[str, ...]:
    """Return the bounded Git-visible repository paths used by change planning.

    Setup is advisory inventory, so it enumerates path identities only.  It
    never opens repository content or walks ignored build/dependency trees.
    Tracked paths remain present when deleted because their deletion is still
    a planning input; non-ignored untracked paths are included because the live
    planner includes them too.
    """

    top = GitSnapshotSource._git(
        root,
        ["rev-parse", "--show-toplevel"],
        maximum_bytes=4096,
    )
    try:
        top_path = Path(top.decode("utf-8", errors="strict").strip())
        if top_path.resolve(strict=True) != root:
            raise SnapshotMaterializationError(
                "repository is not the exact Git worktree root"
            )
    except (OSError, UnicodeError) as error:
        raise SnapshotMaterializationError(
            "repository Git root is invalid"
        ) from error

    current_paths = GitSnapshotSource._paths(
        GitSnapshotSource._git(
            root,
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            maximum_bytes=MAX_GIT_METADATA_BYTES,
        ),
        "repository input path",
    )
    baseline_paths = GitSnapshotSource._paths(
        GitSnapshotSource._git(
            root,
            ["ls-tree", "-r", "--name-only", "-z", "HEAD", "--"],
            maximum_bytes=MAX_GIT_METADATA_BYTES,
        ),
        "repository baseline input path",
    )
    paths = current_paths | baseline_paths
    if len(paths) > MAX_SNAPSHOT_FILES:
        raise SnapshotMaterializationError(
            "repository input path count exceeds its bound"
        )
    return tuple(sorted(paths))


def _input_coverage_gaps(
    root: Path, manifest: TestManifest
) -> list[dict[str, str]]:
    """Project truthful, bounded unmapped-path evidence for Console Setup.

    A path is covered when a validated global pattern or at least one target
    input pattern matches it.  No claim is made about behavioral test coverage;
    this projection only identifies paths that force the planner's complete
    intent fallback.  Inspection failure is itself explicit rather than being
    misreported as an empty gap list.
    """

    try:
        paths = _repository_input_paths(root)
        patterns = (
            *manifest.global_inputs,
            *(
                pattern
                for target in manifest.targets.values()
                for pattern in target.inputs
            ),
        )
        unmapped = tuple(
            path
            for path in paths
            if not any(repository_glob_matches(pattern, path) for pattern in patterns)
        )
    except Exception:
        # Git/repository details are repository-controlled and must not cross
        # this UID boundary.  Preserve only the fixed fail-closed consequence.
        return [
            {
                "code": "input_coverage_inspection_incomplete",
                "message": _INCOMPLETE_INPUT_MESSAGE,
                "detail": _INCOMPLETE_INPUT_DETAIL,
            }
        ]

    gaps = [
        {
            "code": "unmapped_repository_path",
            "message": _UNMAPPED_INPUT_MESSAGE,
            "path": path,
            "detail": _UNMAPPED_INPUT_DETAIL,
        }
        for path in unmapped[:MAX_SETUP_INPUT_COVERAGE_PATH_GAPS]
    ]
    if len(unmapped) > MAX_SETUP_INPUT_COVERAGE_PATH_GAPS:
        gaps.append(
            {
                "code": "unmapped_repository_paths_omitted",
                "message": _TRUNCATED_INPUT_MESSAGE,
                "detail": _TRUNCATED_INPUT_DETAIL,
            }
        )
    return gaps


def _setup(root: Path) -> Mapping[str, object]:
    manifest_path = root / ".codex" / "tests.json"
    try:
        manifest_path.lstat()
    except FileNotFoundError:
        return _setup_status("missing", code="manifest_missing")
    except OSError:
        return _setup_status("invalid", code="manifest_invalid")
    try:
        manifest = _manifest(root)
    except Exception:
        # Repository-controlled parser or filesystem details must not cross the
        # repository-UID boundary.  The status and fixed code are sufficient.
        return _setup_status("invalid", code="manifest_invalid")

    targets = [
        {
            "name": name,
            "driver": target.driver,
            "reporter": target.reporter,
            "network": target.network,
            "fixtures": sorted(target.fixtures),
            "credentials": sorted(
                manifest.credentials[name].binding for name in target.credentials
            ),
            "depends_on": sorted(target.depends_on),
            "resources": {
                "cpu_millis": target.resources.cpu_millis,
                "memory_mib": target.resources.memory_mib,
                "pids": target.resources.pids,
            },
        }
        for name, target in sorted(manifest.targets.items())
    ]
    network_rank = {
        "none": 0,
        "loopback": 1,
        "host-loopback": 2,
        "external": 3,
    }
    networks = sorted(
        {
            *(target.network for target in manifest.targets.values()),
            *(fixture.network for fixture in manifest.fixtures.values()),
        },
        key=network_rank.__getitem__,
    )
    document: Mapping[str, object] = {
        "schema_version": 1,
        "ok": True,
        "status": "ready",
        "manifest_schema": manifest.schema_version,
        "manifest_fingerprint": manifest.fingerprint,
        "targets": targets,
        "target_graph": {
            name: sorted(target.depends_on)
            for name, target in sorted(manifest.targets.items())
        },
        "input_coverage": {
            "global_input_count": len(manifest.global_inputs),
            "target_input_count": sum(
                len(target.inputs) for target in manifest.targets.values()
            ),
            # Manifest validation requires at least one input for every target.
            "targets_with_inputs": sum(
                bool(target.inputs) for target in manifest.targets.values()
            ),
        },
        "input_coverage_gaps": _input_coverage_gaps(root, manifest),
        "intents": sorted(manifest.intents),
        "evidence_policies": sorted(manifest.evidence_policies),
        "fixtures": sorted(manifest.fixtures),
        "credentials": sorted(
            credential.binding for credential in manifest.credentials.values()
        ),
        "network_requirements": networks,
        "isolation": {
            "network": max(networks, key=network_rank.__getitem__),
            "cpu_millis": max(
                target.resources.cpu_millis for target in manifest.targets.values()
            ),
            "memory_mib": max(
                target.resources.memory_mib for target in manifest.targets.values()
            ),
            "pids": max(target.resources.pids for target in manifest.targets.values()),
            "private_scratch": True,
            "kill_after_run": True,
        },
        "issues": [],
    }
    if len(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ) > MAX_SETUP_RESULT_BYTES:
        return _setup_status("invalid", code="manifest_setup_too_large")
    return document


def _request() -> Mapping[str, object]:
    raw = sys.stdin.buffer.read(MAX_HELPER_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_HELPER_REQUEST_BYTES:
        raise SnapshotMaterializationError("UID helper request is empty or too large")
    value = json.loads(raw)
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise SnapshotMaterializationError("UID helper request must be an object")
    return value


def _emit(value: Mapping[str, object]) -> None:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(payload) > MAX_HELPER_RESPONSE_BYTES:
        raise SnapshotMaterializationError("UID helper response is too large")
    sys.stdout.buffer.write(payload)


def _root(value: object, *, owner_uid: int, protected: bool = False) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        raise SnapshotMaterializationError("UID helper root is invalid")
    root = Path(value)
    metadata = root.lstat()
    if root.resolve(strict=True) != root or not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotMaterializationError("UID helper root is unsafe")
    # UID selects the execution context; filesystem ownership/mode is not a
    # second authorization layer on a single-developer server.
    return root


def _manifest(root: Path):
    entry = GitSnapshotSource._read_file(root, ".codex/tests.json", tracked=True)
    raw = GitSnapshotSource._read_exact_regular(
        root, entry, maximum_bytes=MAX_MANIFEST_BYTES
    )
    try:
        document = json.loads(raw.decode("utf-8"))
        return parse_test_manifest(document, repository_root=root)
    except ManifestContractError as error:
        raise SnapshotMaterializationError(
            f"snapshot test manifest is invalid: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise SnapshotMaterializationError(
            "snapshot test manifest is invalid: "
            f"JSON {error.msg} at line {error.lineno}, column {error.colno}"
        ) from error
    except UnicodeError as error:
        raise SnapshotMaterializationError(
            "snapshot test manifest is invalid"
        ) from error


def _source(value: object) -> SourceIdentity:
    if not isinstance(value, Mapping):
        raise SnapshotMaterializationError("snapshot source identity is invalid")
    expected = {
        "mode", "repository_id", "content_fingerprint", "original_root",
        "temporary_root", "snapshot_id",
    }
    if set(value) != expected or value["mode"] != "immutable":
        raise SnapshotMaterializationError("snapshot source identity is invalid")
    return SourceIdentity(
        mode=SourceMode.IMMUTABLE,
        repository_id=value["repository_id"],  # type: ignore[arg-type]
        content_fingerprint=value["content_fingerprint"],  # type: ignore[arg-type]
        original_root=value["original_root"],  # type: ignore[arg-type]
        temporary_root=value["temporary_root"],  # type: ignore[arg-type]
        snapshot_id=value["snapshot_id"],  # type: ignore[arg-type]
    )


def _requested_targets(value: object, *, intent: str) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) > 256
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 128
            or any(character in item for character in "\x00\r\n")
            for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise SnapshotMaterializationError("requested test targets are invalid")
    if value and intent != "manual":
        raise SnapshotMaterializationError(
            "requested test targets require manual intent"
        )
    return tuple(value)


def _plan_timeouts(value: object) -> tuple[int | None, int]:
    if value is None:
        return None, DEFAULT_LAUNCH_TIMEOUT_SECONDS
    if not isinstance(value, Mapping) or set(value) != {
        "execution_seconds",
        "launch_seconds",
    }:
        raise SnapshotMaterializationError("test plan timeouts are invalid")
    execution = value["execution_seconds"]
    launch = value["launch_seconds"]
    if execution is not None and (
        type(execution) is not int
        or not 1 <= execution <= MAX_EXECUTION_TIMEOUT_SECONDS
    ):
        raise SnapshotMaterializationError("test execution timeout is invalid")
    if (
        type(launch) is not int
        or not 1 <= launch <= MAX_LAUNCH_TIMEOUT_SECONDS
    ):
        raise SnapshotMaterializationError("test launch timeout is invalid")
    return execution, launch


def _plan_documents(manifest, plan, execution_root: Path) -> Mapping[str, object]:
    resources: dict[str, object] = {}
    catalog: dict[str, object] = {}
    for name in plan.selected_targets:
        target = manifest.targets[name]
        execution_timeout = (
            target.timeout_seconds
            if plan.timeouts.execution_seconds is None
            else plan.timeouts.execution_seconds
        )
        resources[name] = {
            "cpu_millis": target.resources.cpu_millis,
            "memory_mib": target.resources.memory_mib,
            "pids": target.resources.pids,
            "estimated_seconds": float(execution_timeout),
            # This is a policy ceiling. Testd lowers it to a history-backed
            # effective count before submission; one shard still covers all
            # selected cases.
            "shard_count": safe_history_shard_ceiling(target),
            "max_attempts": target.retry.max_attempts,
            "worktree_key": str(execution_root),
            "exclusive_resources": list(target.exclusive_resources),
        }
        catalog[name] = {
            "driver": target.driver,
            "reporter": target.reporter,
            "argv": list(target.argv),
            "cwd": target.cwd,
            "environment": dict(target.environment),
            "network": target.network,
            "timeout_seconds": execution_timeout,
            "resources": {
                "cpu_millis": target.resources.cpu_millis,
                "memory_mib": target.resources.memory_mib,
                "pids": target.resources.pids,
            },
            "fixtures": list(target.fixtures),
            "credentials": [
                manifest.credentials[name].binding for name in target.credentials
            ],
            "fixture_bindings": [
                {
                    "name": fixture_name,
                    "template": manifest.fixtures[fixture_name].template,
                    "network": manifest.fixtures[fixture_name].network,
                }
                for fixture_name in target.fixtures
            ],
            "artifacts": [
                {
                    "name": artifact.name,
                    "path": artifact.path,
                    "kind": artifact.kind,
                    "required": artifact.required,
                    "max_bytes": artifact.max_bytes,
                }
                for artifact in target.artifacts
            ],
        }
    return {
        "plan": plan.to_document(),
        "target_resources": resources,
        "launch_catalog": catalog,
    }


def execute(request: Mapping[str, object]) -> Mapping[str, object]:
    if set(request) != {"operation", "owner_uid", "arguments"}:
        raise SnapshotMaterializationError("UID helper request fields are invalid")
    operation = request["operation"]
    if not isinstance(operation, str):
        raise SnapshotMaterializationError("UID helper operation is invalid")
    owner_uid = request["owner_uid"]
    effective_uid = os.geteuid()
    if type(owner_uid) is not int or owner_uid <= 0 or not (
        effective_uid == owner_uid
        or (
            effective_uid == 0
            and operation in _CONTROL_PLANE_READ_OPERATIONS
        )
    ):
        raise SnapshotMaterializationError("UID helper execution identity is invalid")
    arguments = request["arguments"]
    if not isinstance(arguments, Mapping):
        raise SnapshotMaterializationError("UID helper arguments are invalid")

    if operation == "setup":
        if set(arguments) != {"repository_root"}:
            raise SnapshotMaterializationError("setup helper arguments are invalid")
        root = _root(arguments["repository_root"], owner_uid=owner_uid)
        return _setup(root)

    if operation == "adoption_inspect":
        if set(arguments) != {"repository_root", "proposed_manifest"}:
            raise SnapshotMaterializationError(
                "manifest adoption inspection arguments are invalid"
            )
        root = _root(arguments["repository_root"], owner_uid=owner_uid)
        return _adoption_inspect(
            root,
            owner_uid=owner_uid,
            proposed_manifest=arguments["proposed_manifest"],
        )

    if operation == "adoption_catalog":
        if set(arguments) != {"repository_root"}:
            raise SnapshotMaterializationError(
                "manifest adoption catalog arguments are invalid"
            )
        root = _root(arguments["repository_root"], owner_uid=owner_uid)
        return _adoption_catalog(root, owner_uid=owner_uid)

    if operation == "adoption_safety_identity":
        if set(arguments) != {"repository_root"}:
            raise SnapshotMaterializationError(
                "manifest safety identity arguments are invalid"
            )
        root = _root(arguments["repository_root"], owner_uid=owner_uid)
        return _adoption_safety_identity(root, owner_uid=owner_uid)

    if operation == "adoption_apply":
        root = _root(arguments.get("repository_root"), owner_uid=owner_uid)
        return _adoption_apply(root, owner_uid=owner_uid, arguments=arguments)

    if operation == "adoption_rollback":
        root = _root(arguments.get("repository_root"), owner_uid=owner_uid)
        return _adoption_rollback(root, owner_uid=owner_uid, arguments=arguments)

    if operation == "manifest":
        if set(arguments) != {"repository_root", "intent"}:
            raise SnapshotMaterializationError("manifest helper arguments are invalid")
        root = _root(arguments["repository_root"], owner_uid=owner_uid)
        manifest = _manifest(root)
        intent = arguments["intent"]
        if not isinstance(intent, str) or intent not in manifest.intents:
            raise SnapshotMaterializationError("manifest intent is invalid")
        return {
            "manifest_fingerprint": manifest.fingerprint,
            "source_mode": manifest.intents[intent].source_mode.value,
        }

    if operation == "scan":
        required = {
            "repository_id", "original_root", "temporary_root",
            "manifest_fingerprint", "intent",
        }
        if set(arguments) != required:
            raise SnapshotMaterializationError("scan helper arguments are invalid")
        request_value = SnapshotMaterializationRequest(
            repository_id=arguments["repository_id"],  # type: ignore[arg-type]
            original_root=arguments["original_root"],  # type: ignore[arg-type]
            temporary_root=arguments["temporary_root"],  # type: ignore[arg-type]
            manifest_fingerprint=arguments["manifest_fingerprint"],  # type: ignore[arg-type]
            intent=arguments["intent"],  # type: ignore[arg-type]
            owner_uid=owner_uid,
        )
        _root(str(request_value.source_root), owner_uid=owner_uid)
        return {
            "scan": GitSnapshotSource(
                enforce_process_uid=effective_uid != 0
            ).scan(request_value).to_document()
        }

    if operation == "live_plan":
        required = {
            "repository_id",
            "original_root",
            "execution_root",
            "intent",
        }
        if not required <= set(arguments) or set(arguments) - (
            required | {"requested_targets", "timeouts"}
        ):
            raise SnapshotMaterializationError(
                "live plan helper arguments are invalid"
            )
        original_root = _root(arguments["original_root"], owner_uid=owner_uid)
        root = _root(arguments["execution_root"], owner_uid=owner_uid)
        manifest = _manifest(root)
        intent = arguments["intent"]
        if (
            not isinstance(intent, str)
            or intent not in manifest.intents
            or manifest.intents[intent].source_mode is not SourceMode.LIVE
        ):
            raise SnapshotMaterializationError("plan intent is not live")
        requested_targets = _requested_targets(
            arguments.get("requested_targets", ()), intent=intent
        )
        execution_timeout, launch_timeout = _plan_timeouts(arguments.get("timeouts"))
        scan_request = SnapshotMaterializationRequest(
            repository_id=arguments["repository_id"],  # type: ignore[arg-type]
            original_root=str(original_root),
            temporary_root=(str(root) if root != original_root else None),
            manifest_fingerprint=manifest.fingerprint,
            intent=intent,
            owner_uid=owner_uid,
        )
        source_reader = GitSnapshotSource(
            enforce_process_uid=effective_uid != 0
        )
        scan = source_reader.scan(scan_request)
        source = SourceIdentity(
            mode=SourceMode.LIVE,
            repository_id=scan_request.repository_id,
            content_fingerprint=scan.content_fingerprint,
            original_root=str(original_root),
            temporary_root=(str(root) if root != original_root else None),
            snapshot_id=None,
        )
        plan = create_test_plan(
            manifest,
            intent=intent,
            source=source,
            changes=source_reader.discover_live_changes(scan_request),
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout,
            launch_timeout_seconds=launch_timeout,
        )
        return _plan_documents(manifest, plan, root)

    if operation == "plan":
        required = {"snapshot_root", "source", "intent"}
        if not required <= set(arguments) or set(arguments) - (
            required | {"requested_targets", "timeouts"}
        ):
            raise SnapshotMaterializationError("plan helper arguments are invalid")
        snapshot_root = _root(
            arguments["snapshot_root"], owner_uid=owner_uid, protected=True
        )
        manifest = _manifest(snapshot_root)
        source = _source(arguments["source"])
        intent = arguments["intent"]
        if (
            not isinstance(intent, str)
            or intent not in manifest.intents
            or manifest.intents[intent].source_mode is not SourceMode.IMMUTABLE
        ):
            raise SnapshotMaterializationError("plan intent is not immutable")
        requested_targets = _requested_targets(
            arguments.get("requested_targets", ()), intent=intent
        )
        execution_timeout, launch_timeout = _plan_timeouts(arguments.get("timeouts"))
        plan = create_test_plan(
            manifest,
            intent=intent,
            source=source,
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout,
            launch_timeout_seconds=launch_timeout,
        )
        return _plan_documents(manifest, plan, snapshot_root)

    raise SnapshotMaterializationError("UID helper operation is unsupported")


def main() -> int:
    try:
        _emit({"ok": True, "result": execute(_request())})
        return 0
    except Exception as error:
        _emit(
            {
                "ok": False,
                "error": {
                    "code": "uid_helper_failed",
                    "message": str(error)[:2048],
                },
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
