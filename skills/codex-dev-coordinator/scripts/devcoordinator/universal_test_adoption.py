"""Evidence-bound adoption of repository test manifests on one trusted host.

The adoption manager never scans for repositories and never invents commands.
An administrator supplies one explicit final manifest for each exact configured
repository identity. Repository inspection and mutation run through the fixed
UID helper so framework commands execute in the repository's account context.
Filesystem metadata is not an authorization model. Adoption attempts real
reads and reports unreadable content without changing repository metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
import tempfile
from time import time
from typing import Mapping, Protocol, Sequence
import uuid

from .store import ensure_private_store_directory, refuse_symlink_components
from .universal_test_store import TestStoreConflict, TestStoreContractError


ADOPTION_SCHEMA_VERSION = 1
MAX_ADOPTION_REPOSITORIES = 512
MAX_ADOPTION_PLAN_BYTES = 64 * 1024 * 1024
AUTHORITY_REPOSITORY_EXPORT_KIND = "devcoordinator-authority-repository-export"
AUTHORITY_REPOSITORY_EXPORT_FIELDS = frozenset(
    {"authority_generation", "repositories", "exported_at"}
)
_REPOSITORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_PLAN_ID = re.compile(r"^manifest-(?:adoption|safety-repair)-[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHORT_SHA256 = re.compile(r"^[0-9a-f]{16}$")
_METADATA_IDENTITY_FIELDS = frozenset(
    {"device", "inode", "kind", "size"}
)
_OBSOLETE_METADATA_DIAGNOSTIC_FIELDS = frozenset({"uid", "gid", "mode", "nlink"})
_SAFETY_IDENTITY_FIELDS = frozenset(
    {
        "root_identity",
        "git_marker_identity",
        "git_head",
        "tracked_entry_count",
        "deletion_scan_complete",
        "deleted_tracked_count",
        "unreadable_tracked_count",
        "unreadable_tracked_sample",
        "unreadable_tracked_entries_complete",
        "unreadable_tracked_entries",
        "codex_identity",
        "manifest_identity",
        "manifest_sha256",
        "problem_code",
    }
)


class AdoptionAuthority(Protocol):
    def repository(self, *, repository_id: str) -> Mapping[str, object]: ...


class AdoptionUIDHelper(Protocol):
    def call(
        self,
        operation: str,
        *,
        owner_uid: int,
        arguments: Mapping[str, object],
    ) -> Mapping[str, object]: ...


def _json_bytes(value: object, *, maximum: int = MAX_ADOPTION_PLAN_BYTES) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise TestStoreContractError("manifest adoption evidence is not bounded JSON") from error
    if not payload or len(payload) > maximum:
        raise TestStoreContractError("manifest adoption evidence exceeds its byte bound")
    return payload


def _digest(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise TestStoreContractError("manifest adoption evidence exceeds its byte bound")


def _safe_repository_id(value: object) -> str:
    if not isinstance(value, str) or _REPOSITORY_ID.fullmatch(value) is None:
        raise TestStoreContractError("manifest adoption repository identity is invalid")
    return value


def _positive_integer(field: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise TestStoreContractError(f"manifest adoption {field} is invalid")
    return value


def _nonnegative_integer(field: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise TestStoreContractError(f"manifest adoption {field} is invalid")
    return value


def _safe_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\\" in value
        or "\x00" in value
    ):
        raise TestStoreContractError("manifest safety relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TestStoreContractError("manifest safety relative path is invalid")
    return path.as_posix()


def _metadata_identity_from_stat(metadata: os.stat_result) -> dict[str, object]:
    mode = metadata.st_mode
    kind = (
        "regular"
        if stat.S_ISREG(mode)
        else "directory"
        if stat.S_ISDIR(mode)
        else "symlink"
        if stat.S_ISLNK(mode)
        else "special"
    )
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "kind": kind,
        "size": metadata.st_size,
    }


def _validate_authority_export(value: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "schema_version",
        "kind",
        "document_sha256",
        *AUTHORITY_REPOSITORY_EXPORT_FIELDS,
    }
    if (
        set(value) != expected
        or value.get("schema_version") != 1
        or value.get("kind") != AUTHORITY_REPOSITORY_EXPORT_KIND
    ):
        raise TestStoreContractError(
            "manifest adoption authority export fields are invalid"
        )
    digest = value.get("document_sha256")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if (
        not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
        or _digest(unsigned) != digest
    ):
        raise TestStoreContractError(
            "manifest adoption authority export digest is invalid"
        )
    generation = value.get("authority_generation")
    exported_at = value.get("exported_at")
    repositories = value.get("repositories")
    if (
        not isinstance(generation, str)
        or not generation
        or len(generation.encode("utf-8")) > 256
        or not isinstance(exported_at, str)
        or not exported_at
        or len(exported_at.encode("utf-8")) > 128
        or not isinstance(repositories, list)
        or not 1 <= len(repositories) <= MAX_ADOPTION_REPOSITORIES
    ):
        raise TestStoreContractError(
            "manifest adoption authority export is invalid"
        )
    normalized: list[dict[str, object]] = []
    identities: list[str] = []
    for item in repositories:
        if not isinstance(item, Mapping) or set(item) != {
            "repository_id",
            "repository_generation",
        }:
            raise TestStoreContractError(
                "manifest adoption authority export entry is invalid"
            )
        repository_id = _safe_repository_id(item["repository_id"])
        identities.append(repository_id)
        normalized.append(
            {
                "repository_id": repository_id,
                "repository_generation": _nonnegative_integer(
                    "repository generation", item["repository_generation"]
                ),
            }
        )
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise TestStoreContractError(
            "manifest adoption authority export repositories are not exact and sorted"
        )
    return {
        **dict(value),
        "repositories": normalized,
    }


def _validate_catalog_state(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != {
        "status",
        "current_digest",
        "current_mode",
        "current_manifest",
        "problem_code",
    }:
        raise TestStoreContractError("manifest adoption catalog fields are invalid")
    status = value.get("status")
    digest = value.get("current_digest")
    mode = value.get("current_mode")
    manifest = value.get("current_manifest")
    problem = value.get("problem_code")
    if status not in {"ready", "missing", "invalid"}:
        raise TestStoreContractError("manifest adoption catalog status is invalid")
    if digest is not None and (
        not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
    ):
        raise TestStoreContractError("manifest adoption catalog digest is invalid")
    if mode is not None and (type(mode) is not int or not 0 <= mode <= 0o777):
        raise TestStoreContractError("manifest adoption catalog mode is invalid")
    if status == "ready":
        if (
            not isinstance(manifest, Mapping)
            or digest is None
            or mode is None
            or problem is not None
        ):
            raise TestStoreContractError(
                "manifest adoption ready catalog omitted its final document"
            )
    elif status == "missing":
        if any(item is not None for item in (digest, mode, manifest, problem)):
            raise TestStoreContractError(
                "manifest adoption missing catalog state is contradictory"
            )
    elif manifest is not None:
        raise TestStoreContractError(
            "manifest adoption non-ready catalog exposed a document"
        )
    elif problem == "invalid_manifest_document":
        if digest is None or mode is None:
            raise TestStoreContractError(
                "invalid manifest document omitted its content evidence"
            )
    elif problem in {
        "unsafe_manifest_directory",
        "unsafe_manifest_file",
        "unstable_manifest_file",
        "manifest_inspection_failed",
    }:
        if digest is not None or mode is not None:
            raise TestStoreContractError(
                "unsafe manifest catalog exposed untrusted content evidence"
            )
    else:
        raise TestStoreContractError(
            "manifest adoption invalid catalog problem is unsupported"
        )
    return dict(value)


def _validate_inspection(value: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "status",
        "action",
        "current_digest",
        "current_mode",
        "current_payload_base64",
        "proposed_digest",
        "proposed_fingerprint",
        "proposed_matches",
    }
    if set(value) != expected:
        raise TestStoreContractError("manifest adoption inspection fields are invalid")
    status = value["status"]
    action = value["action"]
    if status not in {"ready", "missing", "invalid"} or action not in {
        "preserve_valid",
        "initialize",
        "migrate",
    }:
        raise TestStoreContractError("manifest adoption inspection state is invalid")
    current_digest = value["current_digest"]
    if current_digest is not None and (
        not isinstance(current_digest, str) or _SHA256.fullmatch(current_digest) is None
    ):
        raise TestStoreContractError("manifest adoption current digest is invalid")
    if status == "missing" and current_digest is not None:
        raise TestStoreContractError("missing manifest has contradictory content evidence")
    if status != "missing" and current_digest is None:
        raise TestStoreContractError("existing manifest omitted its content evidence")
    mode = value["current_mode"]
    if mode is not None and (type(mode) is not int or not 0 <= mode <= 0o777):
        raise TestStoreContractError("manifest adoption current mode is invalid")
    payload = value["current_payload_base64"]
    if (status == "invalid") != isinstance(payload, str):
        raise TestStoreContractError("manifest adoption backup evidence is contradictory")
    for field in ("proposed_digest", "proposed_fingerprint"):
        item = value[field]
        if not isinstance(item, str) or _SHA256.fullmatch(item) is None:
            raise TestStoreContractError(f"manifest adoption {field} is invalid")
    if type(value["proposed_matches"]) is not bool:
        raise TestStoreContractError("manifest adoption comparison evidence is invalid")
    if status == "ready" and action != "preserve_valid":
        raise TestStoreContractError("valid final manifest must be preserved")
    if status == "missing" and action != "initialize":
        raise TestStoreContractError("missing manifest action is contradictory")
    if status == "invalid" and action != "migrate":
        raise TestStoreContractError("invalid manifest action is contradictory")
    return dict(value)


def _validate_metadata_identity(
    value: object, *, field: str
) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TestStoreContractError(
            f"manifest safety {field} identity fields are invalid"
        )
    fields = frozenset(value)
    if fields not in {
        _METADATA_IDENTITY_FIELDS,
        _METADATA_IDENTITY_FIELDS | _OBSOLETE_METADATA_DIAGNOSTIC_FIELDS,
    }:
        raise TestStoreContractError(
            f"manifest safety {field} identity fields are invalid"
        )
    for name in ("device", "inode", "size"):
        item = value[name]
        if type(item) is not int or item < 0:
            raise TestStoreContractError(
                f"manifest safety {field} identity is invalid"
            )
    if value["kind"] not in {
        "directory",
        "regular",
        "symlink",
        "special",
    }:
        raise TestStoreContractError(
            f"manifest safety {field} identity is invalid"
        )
    # UID/GID/mode/link count from older helpers are diagnostics only.  They
    # never enter a sealed identity, comparison, or evidence digest.
    return {name: value[name] for name in _METADATA_IDENTITY_FIELDS}


def _validate_safety_identity(value: Mapping[str, object]) -> dict[str, object]:
    if set(value) != _SAFETY_IDENTITY_FIELDS:
        raise TestStoreContractError("manifest safety identity fields are invalid")
    root = _validate_metadata_identity(value["root_identity"], field="root")
    if root is None or root["kind"] != "directory":
        raise TestStoreContractError("manifest safety root identity is invalid")
    marker = _validate_metadata_identity(
        value["git_marker_identity"], field="Git marker"
    )
    codex = _validate_metadata_identity(value["codex_identity"], field=".codex")
    manifest = _validate_metadata_identity(
        value["manifest_identity"], field="manifest"
    )
    problem = value["problem_code"]
    if problem not in {None, "git_marker_missing", "git_inspection_failed"}:
        raise TestStoreContractError("manifest safety problem code is invalid")
    head = value["git_head"]
    tracked = value["tracked_entry_count"]
    deletion_scan_complete = value["deletion_scan_complete"]
    deleted = value["deleted_tracked_count"]
    unreadable = value["unreadable_tracked_count"]
    sample = value["unreadable_tracked_sample"]
    entries_complete = value["unreadable_tracked_entries_complete"]
    raw_entries = value["unreadable_tracked_entries"]
    if (
        not isinstance(sample, list)
        or len(sample) > 8
        or any(not isinstance(item, str) or _SHORT_SHA256.fullmatch(item) is None for item in sample)
    ):
        raise TestStoreContractError("manifest safety unreadable sample is invalid")
    if (
        type(entries_complete) is not bool
        or not isinstance(raw_entries, list)
        or len(raw_entries) > 256
    ):
        raise TestStoreContractError("manifest safety unreadable entries are invalid")
    entries: list[dict[str, object]] = []
    paths: list[str] = []
    for item in raw_entries:
        if not isinstance(item, Mapping) or set(item) != {
            "relative_path",
            "path_hash",
            "identity",
        }:
            raise TestStoreContractError("manifest safety unreadable entry is invalid")
        relative_path = _safe_relative_path(item["relative_path"])
        path_hash = item["path_hash"]
        identity = _validate_metadata_identity(
            item["identity"], field="unreadable tracked entry"
        )
        if (
            not isinstance(path_hash, str)
            or _SHORT_SHA256.fullmatch(path_hash) is None
            or hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:16]
            != path_hash
        ):
            raise TestStoreContractError("manifest safety unreadable entry is invalid")
        paths.append(relative_path)
        entries.append(
            {
                "relative_path": relative_path,
                "path_hash": path_hash,
                "identity": identity,
            }
        )
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise TestStoreContractError(
            "manifest safety unreadable entries must be unique and sorted"
        )
    if problem is None:
        if (
            marker is None
            or not isinstance(head, str)
            or len(head) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in head)
            or type(tracked) is not int
            or not 0 <= tracked <= 100_000
            or type(unreadable) is not int
            or not 0 <= unreadable <= tracked
            or type(deletion_scan_complete) is not bool
            or (
                deletion_scan_complete
                and (type(deleted) is not int or not 0 <= deleted <= tracked)
            )
            or (not deletion_scan_complete and deleted is not None)
            or len(sample) > unreadable
            or len(entries) > unreadable
            or (entries_complete and len(entries) != unreadable)
        ):
            raise TestStoreContractError("manifest safety Git evidence is invalid")
    elif (
        deletion_scan_complete is not False
        or any(item is not None for item in (head, tracked, deleted, unreadable))
        or sample
        or entries_complete is not False
        or entries
    ):
        raise TestStoreContractError(
            "manifest safety failed Git evidence is contradictory"
        )
    manifest_sha = value["manifest_sha256"]
    if manifest_sha is not None and (
        not isinstance(manifest_sha, str) or _SHA256.fullmatch(manifest_sha) is None
    ):
        raise TestStoreContractError("manifest safety content digest is invalid")
    if manifest is None and manifest_sha is not None:
        raise TestStoreContractError(
            "manifest safety digest exists without a manifest identity"
        )
    return {
        **dict(value),
        "root_identity": root,
        "git_marker_identity": marker,
        "codex_identity": codex,
        "manifest_identity": manifest,
        "unreadable_tracked_entries": entries,
    }


def _assess_safety_identity(
    identity: Mapping[str, object], *, execution_uid: int
) -> dict[str, object]:
    """Classify repository readability without treating metadata as authority."""

    del execution_uid
    blockers: list[str] = []
    if identity["problem_code"] is not None:
        blockers.append(str(identity["problem_code"]))
    marker = identity["git_marker_identity"]
    if not isinstance(marker, Mapping) or marker.get("kind") not in {
        "directory",
        "regular",
    }:
        blockers.append("git_marker_type_invalid")
    unreadable_count = int(identity.get("unreadable_tracked_count") or 0)
    unreadable_entries = identity.get("unreadable_tracked_entries")
    if unreadable_count > 0:
        blockers.append("unreadable_tracked_entries")
    if (
        identity.get("problem_code") is None
        and identity.get("deletion_scan_complete") is not True
    ):
        blockers.append("git_deletion_inspection_failed")

    codex = identity["codex_identity"]
    manifest = identity["manifest_identity"]
    if codex is not None:
        if not isinstance(codex, Mapping):
            raise TestStoreContractError("manifest safety .codex identity is invalid")
        if codex.get("kind") != "directory":
            blockers.append("manifest_directory_type_invalid")
    if manifest is not None:
        if not isinstance(manifest, Mapping):
            raise TestStoreContractError("manifest safety file identity is invalid")
        if (
            manifest.get("kind") != "regular"
            or int(manifest.get("size", MAX_ADOPTION_PLAN_BYTES + 1))
            > 512 * 1024
        ):
            blockers.append("manifest_file_type_invalid")
        elif identity["manifest_sha256"] is None:
            blockers.append("manifest_file_unreadable")
    blockers = sorted(set(blockers))
    return {
        "identity": dict(identity),
        "actions": [],
        "blockers": blockers,
        "status": "blocked" if blockers else "clean",
    }


class TestManifestAdoptionManager:
    """Plan, apply, and roll back exact manifest adoption transactions."""

    def __init__(
        self,
        *,
        authority: AdoptionAuthority,
        helper: AdoptionUIDHelper,
        evidence_root: Path,
        execution_uid: int,
        expected_evidence_uid: int = 0,
    ) -> None:
        self.authority = authority
        self.helper = helper
        self.evidence_root = Path(evidence_root).absolute()
        ensure_private_store_directory(
            self.evidence_root, expected_uid=expected_evidence_uid
        )
        refuse_symlink_components(self.evidence_root)
        metadata = self.evidence_root.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise TestStoreContractError("manifest adoption evidence root is unsafe")
        self.expected_evidence_uid = expected_evidence_uid
        self.execution_uid = _positive_integer("execution UID", execution_uid)

    def _directory(self, plan_id: str, *, create: bool = False) -> Path:
        if _PLAN_ID.fullmatch(plan_id) is None:
            raise TestStoreContractError("manifest adoption plan identity is invalid")
        directory = self.evidence_root / plan_id
        if create:
            directory.mkdir(mode=0o700)
        refuse_symlink_components(directory)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise TestStoreContractError("manifest adoption plan directory is unsafe")
        return directory

    def _write_once(self, path: Path, value: Mapping[str, object]) -> str:
        payload = _json_bytes(value)
        descriptor, name = tempfile.mkstemp(prefix=".adoption-", dir=path.parent)
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.link(temporary, path, follow_symlinks=False)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileExistsError as error:
            raise TestStoreConflict("manifest adoption evidence already exists") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
        return hashlib.sha256(payload).hexdigest()

    def _read(self, path: Path, *, expected_sha256: str | None = None) -> Mapping[str, object]:
        refuse_symlink_components(path)
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_ADOPTION_PLAN_BYTES
        ):
            raise TestStoreContractError("manifest adoption evidence file is unsafe")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                raise TestStoreConflict("manifest adoption evidence identity changed")
            payload = _read_bounded(descriptor, MAX_ADOPTION_PLAN_BYTES)
        finally:
            os.close(descriptor)
        if len(payload) != metadata.st_size:
            raise TestStoreConflict("manifest adoption evidence changed while reading")
        digest = hashlib.sha256(payload).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            raise TestStoreConflict("manifest adoption evidence digest changed")
        try:
            value = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("manifest adoption evidence is invalid") from error
        if not isinstance(value, Mapping):
            raise TestStoreContractError("manifest adoption evidence must be an object")
        return value

    @staticmethod
    def _file_sha256(path: Path) -> str:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            return hashlib.sha256(
                _read_bounded(descriptor, MAX_ADOPTION_PLAN_BYTES)
            ).hexdigest()
        finally:
            os.close(descriptor)

    @staticmethod
    def _public_apply(
        result: Mapping[str, object], *, result_sha256: str
    ) -> Mapping[str, object]:
        applied = result.get("applied")
        rollback = result.get("automatic_rollback")
        return {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "ok": result.get("ok"),
            "state": result.get("state"),
            "plan_id": result.get("plan_id"),
            "plan_sha256": result.get("plan_sha256"),
            "result_sha256": result_sha256,
            "excluded_repositories": result.get("excluded_repositories", []),
            "applied": [
                {
                    "repository_id": item.get("repository_id"),
                    "repository_generation": item.get("repository_generation"),
                    "final_digest": item.get("final_digest"),
                }
                for item in applied
                if isinstance(item, Mapping)
            ]
            if isinstance(applied, list)
            else [],
            "automatic_rollback": [
                {
                    "repository_id": item.get("repository_id"),
                    "restored_status": item.get("restored_status"),
                    "restored_digest": item.get("restored_digest"),
                }
                for item in rollback
                if isinstance(item, Mapping)
            ]
            if isinstance(rollback, list)
            else [],
            "error": result.get("error"),
            "rollback_error": result.get("rollback_error"),
        }

    @staticmethod
    def _request_entries(request: Mapping[str, object]) -> list[Mapping[str, object]]:
        if set(request) != {
            "schema_version",
            "operation_id",
            "repositories",
            "excluded_repositories",
        }:
            raise TestStoreContractError("manifest adoption request fields are invalid")
        if request["schema_version"] != ADOPTION_SCHEMA_VERSION:
            raise TestStoreContractError("manifest adoption request schema is unsupported")
        try:
            uuid.UUID(str(request["operation_id"]))
        except (ValueError, TypeError) as error:
            raise TestStoreContractError("manifest adoption operation identity is invalid") from error
        repositories = request["repositories"]
        if (
            not isinstance(repositories, Sequence)
            or isinstance(repositories, (str, bytes))
            or len(repositories) > MAX_ADOPTION_REPOSITORIES
            or any(not isinstance(item, Mapping) for item in repositories)
        ):
            raise TestStoreContractError("manifest adoption repositories are invalid")
        entries = list(repositories)  # type: ignore[arg-type]
        identities: list[str] = []
        for item in entries:
            if set(item) != {
                "repository_id",
                "repository_generation",
                "execution_uid",
                "manifest",
            }:
                raise TestStoreContractError("manifest adoption repository fields are invalid")
            identities.append(_safe_repository_id(item["repository_id"]))
            _nonnegative_integer(
                "repository generation", item["repository_generation"]
            )
            _positive_integer("execution UID", item["execution_uid"])
            if not isinstance(item["manifest"], Mapping):
                raise TestStoreContractError(
                    "manifest adoption requires an explicit final manifest document"
                )
        if identities != sorted(identities) or len(set(identities)) != len(identities):
            raise TestStoreContractError(
                "manifest adoption repositories must be unique and sorted by immutable ID"
            )
        exclusions = request["excluded_repositories"]
        if (
            not isinstance(exclusions, list)
            or len(exclusions) > MAX_ADOPTION_REPOSITORIES
        ):
            raise TestStoreContractError(
                "manifest adoption excluded repositories are invalid"
            )
        excluded_ids: list[str] = []
        for item in exclusions:
            if not isinstance(item, Mapping) or set(item) != {
                "repository_id",
                "repository_generation",
                "execution_uid",
                "classification",
                "readability_status",
                "readability_blocker_codes",
            }:
                raise TestStoreContractError(
                    "manifest adoption excluded repository is invalid"
                )
            repository_id = _safe_repository_id(item["repository_id"])
            excluded_ids.append(repository_id)
            _nonnegative_integer(
                "repository generation", item["repository_generation"]
            )
            _positive_integer("execution UID", item["execution_uid"])
            blockers = item["readability_blocker_codes"]
            if (
                item["classification"] not in {"missing", "invalid"}
                or item["readability_status"] != "blocked"
                or not isinstance(blockers, list)
                or not blockers
                or any(not isinstance(code, str) or not code for code in blockers)
            ):
                raise TestStoreContractError(
                    "manifest adoption excluded repository evidence is invalid"
                )
        if (
            excluded_ids != sorted(excluded_ids)
            or len(excluded_ids) != len(set(excluded_ids))
            or set(excluded_ids) & set(identities)
            or not excluded_ids and not identities
            or len(excluded_ids) + len(identities) > MAX_ADOPTION_REPOSITORIES
        ):
            raise TestStoreContractError(
                "manifest adoption repository coverage is invalid"
            )
        _json_bytes(request)
        return entries

    def _authority(
        self,
        *,
        repository_id: str,
        generation: int,
        execution_uid: int | None = None,
    ) -> Mapping[str, object]:
        if execution_uid is not None and execution_uid != self.execution_uid:
            raise TestStoreConflict("manifest adoption execution identity changed")
        authority = self.authority.repository(repository_id=repository_id)
        if (
            authority.get("repository_id") != repository_id
            or authority.get("generation") != generation
            or not isinstance(authority.get("canonical_root"), str)
        ):
            raise TestStoreConflict("manifest adoption repository authority changed")
        return authority

    def _catalog_export(
        self, authority_export: Mapping[str, object]
    ) -> tuple[dict[str, object], list[dict[str, object]]]:
        exported = _validate_authority_export(authority_export)
        rows: list[dict[str, object]] = []
        for item in exported["repositories"]:  # type: ignore[assignment]
            if not isinstance(item, Mapping):
                raise TestStoreContractError(
                    "manifest adoption authority export entry is invalid"
                )
            repository_id = _safe_repository_id(item["repository_id"])
            execution_uid = self.execution_uid
            generation = _nonnegative_integer(
                "repository generation", item["repository_generation"]
            )
            authority = self._authority(
                repository_id=repository_id,
                generation=generation,
            )
            state = _validate_catalog_state(
                self.helper.call(
                    "adoption_catalog",
                    owner_uid=execution_uid,
                    arguments={"repository_root": authority["canonical_root"]},
                )
            )
            safety = _assess_safety_identity(
                _validate_safety_identity(
                    self.helper.call(
                        "adoption_safety_identity",
                        owner_uid=execution_uid,
                        arguments={"repository_root": authority["canonical_root"]},
                    )
                ),
                execution_uid=execution_uid,
            )
            rows.append(
                {
                    "repository_id": repository_id,
                    "repository_generation": generation,
                    "execution_uid": execution_uid,
                    "canonical_root": authority["canonical_root"],
                    "state": state,
                    "safety": safety,
                }
            )
        return exported, rows

    def catalog(self, authority_export: Mapping[str, object]) -> Mapping[str, object]:
        """Inspect every exact repository in one sealed authority export."""

        exported, rows = self._catalog_export(authority_export)
        counts = {"ready": 0, "missing": 0, "invalid": 0}
        for row in rows:
            state = row["state"]
            if not isinstance(state, Mapping):
                raise TestStoreContractError("manifest adoption catalog state is invalid")
            counts[str(state["status"])] += 1
        return {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "ok": True,
            "authority_generation": exported["authority_generation"],
            "authority_export_sha256": exported["document_sha256"],
            "counts": counts,
            "repositories": [
                {
                    "repository_id": row["repository_id"],
                    "repository_generation": row["repository_generation"],
                    "execution_uid": row["execution_uid"],
                    "status": row["state"]["status"],  # type: ignore[index]
                    "current_digest": row["state"]["current_digest"],  # type: ignore[index]
                    "problem_code": row["state"]["problem_code"],  # type: ignore[index]
                    "adoption_ready": row["state"]["status"] == "ready"  # type: ignore[index]
                    and row["safety"]["status"] == "clean",  # type: ignore[index]
                    "requires_explicit_manifest": row["state"]["status"]  # type: ignore[index]
                    != "ready",
                    "has_readability_blockers": row["safety"]["status"]  # type: ignore[index]
                    != "clean",
                    "readability_status": row["safety"]["status"],  # type: ignore[index]
                    "readability_blocker_codes": row["safety"]["blockers"],  # type: ignore[index]
                    "unreadable_tracked_count": row["safety"]["identity"]["unreadable_tracked_count"],  # type: ignore[index]
                    "deletion_scan_complete": row["safety"]["identity"]["deletion_scan_complete"],  # type: ignore[index]
                    "deleted_tracked_count": row["safety"]["identity"]["deleted_tracked_count"],  # type: ignore[index]
                }
                for row in rows
            ],
        }


    def prepare_request(
        self,
        authority_export: Mapping[str, object],
        manifest_set: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Build a complete request without ever deriving a test command.

        Existing valid documents are retained exactly. Every missing or invalid
        repository must have one administrator-supplied explicit final document.
        """

        exported, rows = self._catalog_export(authority_export)
        if set(manifest_set) != {
            "schema_version",
            "authority_export_sha256",
            "operation_id",
            "manifests",
        } or manifest_set.get("schema_version") != ADOPTION_SCHEMA_VERSION:
            raise TestStoreContractError(
                "manifest adoption explicit manifest-set fields are invalid"
            )
        if manifest_set.get("authority_export_sha256") != exported["document_sha256"]:
            raise TestStoreConflict(
                "manifest adoption explicit documents belong to another authority export"
            )
        try:
            operation_id = str(uuid.UUID(str(manifest_set["operation_id"])))
        except (ValueError, TypeError) as error:
            raise TestStoreContractError(
                "manifest adoption operation identity is invalid"
            ) from error
        manifests = manifest_set.get("manifests")
        if not isinstance(manifests, list) or len(manifests) > len(rows):
            raise TestStoreContractError(
                "manifest adoption explicit manifest set is invalid"
            )
        supplied: dict[str, Mapping[str, object]] = {}
        identities: list[str] = []
        for item in manifests:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"repository_id", "manifest"}
                or not isinstance(item.get("manifest"), Mapping)
            ):
                raise TestStoreContractError(
                    "manifest adoption explicit manifest entry is invalid"
                )
            repository_id = _safe_repository_id(item["repository_id"])
            identities.append(repository_id)
            supplied[repository_id] = dict(item["manifest"])
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise TestStoreContractError(
                "manifest adoption explicit manifests must be unique and sorted"
            )

        expected_explicit = {
            str(row["repository_id"])
            for row in rows
            if row["state"]["status"] != "ready"  # type: ignore[index]
            and row["safety"]["status"] == "clean"  # type: ignore[index]
        }
        if set(supplied) != expected_explicit:
            missing = sorted(expected_explicit - set(supplied))
            unexpected = sorted(set(supplied) - expected_explicit)
            raise TestStoreContractError(
                "manifest adoption requires explicit documents exactly for non-ready "
                "repositories "
                f"(missing_count={len(missing)}, missing_sample={missing[:8]}, "
                f"unexpected_count={len(unexpected)}, "
                f"unexpected_sample={unexpected[:8]})"
            )

        request_rows: list[dict[str, object]] = []
        excluded_rows: list[dict[str, object]] = []
        for row in rows:
            repository_id = str(row["repository_id"])
            state = row["state"]
            safety = row["safety"]
            if not isinstance(state, Mapping):
                raise TestStoreContractError("manifest adoption catalog state is invalid")
            if not isinstance(safety, Mapping):
                raise TestStoreContractError("manifest adoption safety state is invalid")
            if safety["status"] != "clean":
                blockers = safety["blockers"]
                if safety["status"] != "blocked" or not isinstance(blockers, list) or not blockers:
                    raise TestStoreContractError(
                        "manifest adoption cannot inspect unreadable repository content"
                    )
                excluded_rows.append(
                    {
                        "repository_id": repository_id,
                        "repository_generation": row["repository_generation"],
                        "execution_uid": row["execution_uid"],
                        "classification": (
                            state["status"]
                            if state["status"] in {"missing", "invalid"}
                            else "invalid"
                        ),
                        "readability_status": "blocked",
                        "readability_blocker_codes": list(blockers),
                    }
                )
                continue
            final_manifest = (
                dict(state["current_manifest"])
                if state["status"] == "ready" and isinstance(state["current_manifest"], Mapping)
                else supplied[repository_id]
            )
            # Reparse every final document under the repository execution UID before
            # it can enter the root-owned request.
            inspection = _validate_inspection(
                self.helper.call(
                    "adoption_inspect",
                    owner_uid=int(row["execution_uid"]),
                    arguments={
                        "repository_root": row["canonical_root"],
                        "proposed_manifest": final_manifest,
                    },
                )
            )
            if any(
                inspection[field] != state[field]
                for field in ("status", "current_digest", "current_mode")
            ):
                raise TestStoreConflict(
                    "manifest adoption repository content changed during request preparation"
                )
            request_rows.append(
                {
                    "repository_id": repository_id,
                    "repository_generation": row["repository_generation"],
                    "execution_uid": row["execution_uid"],
                    "manifest": final_manifest,
                }
            )
        request = {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "operation_id": operation_id,
            "excluded_repositories": excluded_rows,
            "repositories": request_rows,
        }
        self._request_entries(request)
        _json_bytes(request)
        return request

    def _validate_excluded_repository(
        self, item: Mapping[str, object]
    ) -> dict[str, object]:
        repository_id = _safe_repository_id(item.get("repository_id"))
        execution_uid = _positive_integer("execution UID", item.get("execution_uid"))
        generation = _nonnegative_integer(
            "repository generation", item.get("repository_generation")
        )
        authority = self._authority(
            repository_id=repository_id,
            execution_uid=execution_uid,
            generation=generation,
        )
        state = _validate_catalog_state(
            self.helper.call(
                "adoption_catalog",
                owner_uid=execution_uid,
                arguments={"repository_root": authority["canonical_root"]},
            )
        )
        safety = _assess_safety_identity(
            _validate_safety_identity(
                self.helper.call(
                    "adoption_safety_identity",
                    owner_uid=execution_uid,
                    arguments={"repository_root": authority["canonical_root"]},
                )
            ),
            execution_uid=execution_uid,
        )
        classification = state["status"] if state["status"] != "ready" else "invalid"
        if (
            safety["status"] != "blocked"
            or classification != item.get("classification")
            or safety["blockers"] != item.get("readability_blocker_codes")
            or item.get("readability_status") != "blocked"
        ):
            raise TestStoreConflict(
                "manifest adoption excluded repository evidence drifted"
            )
        return {
            "repository_id": repository_id,
            "repository_generation": generation,
            "execution_uid": execution_uid,
            "classification": classification,
            "readability_status": "blocked",
            "readability_blocker_codes": list(safety["blockers"]),
        }

    def plan(self, request: Mapping[str, object]) -> Mapping[str, object]:
        self._request_entries(request)
        exclusions_value = request["excluded_repositories"]
        if not isinstance(exclusions_value, list):
            raise TestStoreContractError(
                "manifest adoption excluded repositories are invalid"
            )
        exclusions = [
            self._validate_excluded_repository(item)
            for item in exclusions_value
            if isinstance(item, Mapping)
        ]
        if len(exclusions) != len(exclusions_value):
            raise TestStoreContractError(
                "manifest adoption excluded repository is invalid"
            )
        entries: list[dict[str, object]] = []
        for item in self._request_entries(request):
            repository_id = _safe_repository_id(item["repository_id"])
            execution_uid = _positive_integer("execution UID", item["execution_uid"])
            generation = _nonnegative_integer(
                "repository generation", item["repository_generation"]
            )
            authority = self._authority(
                repository_id=repository_id,
                execution_uid=execution_uid,
                generation=generation,
            )
            inspection = _validate_inspection(
                self.helper.call(
                    "adoption_inspect",
                    owner_uid=execution_uid,
                    arguments={
                        "repository_root": authority["canonical_root"],
                        "proposed_manifest": dict(item["manifest"]),
                    },
                )
            )
            entries.append(
                {
                    "repository_id": repository_id,
                    "repository_generation": generation,
                    "execution_uid": execution_uid,
                    "canonical_root": authority["canonical_root"],
                    "proposed_manifest": dict(item["manifest"]),
                    "inspection": inspection,
                }
            )
        plan_id = "manifest-adoption-" + uuid.uuid4().hex
        plan = {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "plan_id": plan_id,
            "operation_id": str(request["operation_id"]),
            "created_at_epoch": int(time()),
            "excluded_repositories": exclusions,
            "repositories": entries,
        }
        directory = self._directory(plan_id, create=True)
        plan_sha256 = self._write_once(directory / "plan.json", plan)
        return {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "ok": True,
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "excluded_repositories": exclusions,
            "repositories": [
                {
                    "repository_id": entry["repository_id"],
                    "repository_generation": entry["repository_generation"],
                    "execution_uid": entry["execution_uid"],
                    "status": entry["inspection"]["status"],  # type: ignore[index]
                    "action": entry["inspection"]["action"],  # type: ignore[index]
                    "proposed_matches": entry["inspection"]["proposed_matches"],  # type: ignore[index]
                }
                for entry in entries
            ],
        }

    def _load_plan(self, plan_id: str, plan_sha256: str) -> Mapping[str, object]:
        if _SHA256.fullmatch(plan_sha256) is None:
            raise TestStoreContractError("manifest adoption plan digest is invalid")
        plan = self._read(
            self._directory(plan_id) / "plan.json", expected_sha256=plan_sha256
        )
        if (
            plan.get("schema_version") != ADOPTION_SCHEMA_VERSION
            or plan.get("plan_id") != plan_id
            or not isinstance(plan.get("repositories"), list)
        ):
            raise TestStoreContractError("manifest adoption plan is invalid")
        return plan

    @staticmethod
    def _same_inspection(
        expected: Mapping[str, object], observed: Mapping[str, object]
    ) -> bool:
        return _digest(expected) == _digest(observed)

    @staticmethod
    def _applied_evidence(
        entry: Mapping[str, object], *, final_digest: object
    ) -> dict[str, object]:
        inspection = entry["inspection"]
        if not isinstance(inspection, Mapping):
            raise TestStoreContractError("manifest adoption inspection is invalid")
        if not isinstance(final_digest, str) or _SHA256.fullmatch(final_digest) is None:
            raise TestStoreContractError("manifest adoption final digest is invalid")
        return {
            "repository_id": entry["repository_id"],
            "repository_generation": entry["repository_generation"],
            "execution_uid": entry["execution_uid"],
            "canonical_root": entry["canonical_root"],
            "original_status": inspection["status"],
            "original_digest": inspection["current_digest"],
            "original_mode": inspection["current_mode"],
            "original_payload_base64": inspection["current_payload_base64"],
            "final_digest": final_digest,
        }

    def _restore_entry(
        self, item: Mapping[str, object], *, operation_id: object
    ) -> dict[str, object]:
        execution_uid = _positive_integer("execution UID", item.get("execution_uid"))
        current = _validate_catalog_state(
            self.helper.call(
                "adoption_catalog",
                owner_uid=execution_uid,
                arguments={"repository_root": item.get("canonical_root")},
            )
        )
        original_status = item.get("original_status")
        original_digest = item.get("original_digest")
        original_mode = item.get("original_mode")
        already_restored = (
            original_status == "missing"
            and current["status"] == "missing"
            and original_digest is None
            and original_mode is None
        ) or (
            original_status == "invalid"
            and current["status"] == "invalid"
            and current["current_digest"] == original_digest
            and current["current_mode"] == original_mode
        )
        if not already_restored:
            restored = self.helper.call(
                "adoption_rollback",
                owner_uid=execution_uid,
                arguments={
                    "repository_root": item.get("canonical_root"),
                    "expected_final_digest": item.get("final_digest"),
                    "original_status": original_status,
                    "original_digest": original_digest,
                    "original_mode": original_mode,
                    "original_payload_base64": item.get("original_payload_base64"),
                    "operation_id": operation_id,
                },
            )
            current = {
                "status": restored.get("status"),
                "current_digest": restored.get("current_digest"),
                "current_mode": restored.get("current_mode"),
                "current_manifest": None,
            }
        if original_status == "missing":
            exact = (
                current["status"] == "missing"
                and current["current_digest"] is None
                and current["current_mode"] is None
            )
        elif original_status == "invalid":
            exact = (
                current["status"] == "invalid"
                and current["current_digest"] == original_digest
                and current["current_mode"] == original_mode
            )
        else:
            raise TestStoreContractError(
                "manifest adoption applied entry has invalid original state"
            )
        if not exact:
            raise TestStoreConflict(
                "manifest adoption rollback did not restore exact original content"
            )
        return {
            "repository_id": item.get("repository_id"),
            "restored_status": current["status"],
            "restored_digest": current["current_digest"],
        }

    def apply(self, *, plan_id: str, plan_sha256: str) -> Mapping[str, object]:
        directory = self._directory(plan_id)
        result_path = directory / "apply-result.json"
        if result_path.exists():
            result = self._read(result_path)
            if result.get("plan_sha256") != plan_sha256:
                raise TestStoreConflict("manifest adoption apply identity changed")
            return self._public_apply(
                result, result_sha256=self._file_sha256(result_path)
            )
        plan = self._load_plan(plan_id, plan_sha256)
        repositories = plan["repositories"]
        if not isinstance(repositories, list):
            raise TestStoreContractError("manifest adoption repositories are invalid")
        exclusions_value = plan.get("excluded_repositories")
        if not isinstance(exclusions_value, list):
            raise TestStoreContractError(
                "manifest adoption excluded repositories are invalid"
            )
        exclusions = [
            self._validate_excluded_repository(item)
            for item in exclusions_value
            if isinstance(item, Mapping)
        ]
        if len(exclusions) != len(exclusions_value):
            raise TestStoreContractError(
                "manifest adoption excluded repository is invalid"
            )

        # Complete preflight before the first write. This prevents a stale
        # generation or manifest from producing a partially applied fleet.
        applied: list[dict[str, object]] = []
        resumed: set[str] = set()
        for entry in repositories:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("inspection"), Mapping):
                raise TestStoreContractError("manifest adoption plan entry is invalid")
            authority = self._authority(
                repository_id=_safe_repository_id(entry.get("repository_id")),
                execution_uid=_positive_integer("execution UID", entry.get("execution_uid")),
                generation=_nonnegative_integer(
                    "repository generation", entry.get("repository_generation")
                ),
            )
            if authority["canonical_root"] != entry.get("canonical_root"):
                raise TestStoreConflict("manifest adoption canonical root changed")
            observed = _validate_inspection(
                self.helper.call(
                    "adoption_inspect",
                    owner_uid=int(entry["execution_uid"]),
                    arguments={
                        "repository_root": entry["canonical_root"],
                        "proposed_manifest": entry["proposed_manifest"],
                    },
                )
            )
            expected_inspection = entry["inspection"]
            if self._same_inspection(expected_inspection, observed):
                continue
            if (
                expected_inspection.get("action") != "preserve_valid"
                and observed["status"] == "ready"
                and observed["current_digest"] == expected_inspection.get("proposed_digest")
            ):
                # A prior root process may have died after the execution-UID atomic
                # replace but before sealing apply-result.json. Exact intended
                # bytes are safe to resume and retain the original plan backup.
                repository_id = str(entry["repository_id"])
                resumed.add(repository_id)
                applied.append(
                    self._applied_evidence(
                        entry, final_digest=observed["current_digest"]
                    )
                )
                continue
            else:
                raise TestStoreConflict("manifest adoption repository content drifted")

        failure: Exception | None = None
        for entry in repositories:
            if not isinstance(entry, Mapping):
                raise TestStoreContractError("manifest adoption plan entry is invalid")
            inspection = entry["inspection"]
            if not isinstance(inspection, Mapping):
                raise TestStoreContractError("manifest adoption inspection is invalid")
            if (
                inspection["action"] == "preserve_valid"
                or entry["repository_id"] in resumed
            ):
                continue
            try:
                applied_result = self.helper.call(
                    "adoption_apply",
                    owner_uid=int(entry["execution_uid"]),
                    arguments={
                        "repository_root": entry["canonical_root"],
                        "expected_status": inspection["status"],
                        "expected_current_digest": inspection["current_digest"],
                        "proposed_manifest": entry["proposed_manifest"],
                        "expected_proposed_digest": inspection["proposed_digest"],
                        "operation_id": plan["operation_id"],
                    },
                )
                if (
                    set(applied_result) != {"status", "final_digest", "manifest_fingerprint"}
                    or applied_result["status"] != "ready"
                    or not isinstance(applied_result["final_digest"], str)
                    or _SHA256.fullmatch(str(applied_result["final_digest"])) is None
                ):
                    raise TestStoreContractError("manifest adoption apply result is invalid")
                applied.append(
                    self._applied_evidence(
                        entry, final_digest=applied_result["final_digest"]
                    )
                )
            except Exception as error:  # exact rollback is handled below
                try:
                    observed = _validate_inspection(
                        self.helper.call(
                            "adoption_inspect",
                            owner_uid=int(entry["execution_uid"]),
                            arguments={
                                "repository_root": entry["canonical_root"],
                                "proposed_manifest": entry["proposed_manifest"],
                            },
                        )
                    )
                    if (
                        observed["status"] == "ready"
                        and observed["current_digest"] == inspection["proposed_digest"]
                    ):
                        applied.append(
                            self._applied_evidence(
                                entry, final_digest=observed["current_digest"]
                            )
                        )
                except Exception:
                    pass
                failure = error
                break

        rollback: list[dict[str, object]] = []
        rollback_failure: Exception | None = None
        if failure is not None:
            for item in reversed(applied):
                try:
                    rollback.append(
                        self._restore_entry(item, operation_id=plan["operation_id"])
                    )
                except Exception as error:
                    rollback_failure = error
                    break

        state = (
            "applied"
            if failure is None
            else "rolled_back"
            if rollback_failure is None and len(rollback) == len(applied)
            else "rollback_incomplete"
        )
        result = {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "ok": failure is None,
            "state": state,
            "plan_id": plan_id,
            "plan_sha256": plan_sha256,
            "operation_id": plan["operation_id"],
            "excluded_repositories": exclusions,
            "applied": applied,
            "automatic_rollback": rollback,
            "error": None if failure is None else str(failure)[:2048],
            "rollback_error": (
                None if rollback_failure is None else str(rollback_failure)[:2048]
            ),
        }
        result_sha256 = self._write_once(result_path, result)
        return self._public_apply(result, result_sha256=result_sha256)

    def rollback(
        self, *, plan_id: str, result_sha256: str
    ) -> Mapping[str, object]:
        if _SHA256.fullmatch(result_sha256) is None:
            raise TestStoreContractError("manifest adoption result digest is invalid")
        directory = self._directory(plan_id)
        prior_path = directory / "apply-result.json"
        result = self._read(prior_path, expected_sha256=result_sha256)
        if result.get("state") not in {"applied", "rollback_incomplete"} or not isinstance(
            result.get("applied"), list
        ):
            raise TestStoreConflict("manifest adoption result is not rollback-eligible")
        rollback_path = directory / "rollback-result.json"
        if rollback_path.exists():
            return self._read(rollback_path)
        restored: list[dict[str, object]] = []
        for item in reversed(result["applied"]):
            if not isinstance(item, Mapping):
                raise TestStoreContractError("manifest adoption rollback entry is invalid")
            self._authority(
                repository_id=_safe_repository_id(item.get("repository_id")),
                execution_uid=_positive_integer("execution UID", item.get("execution_uid")),
                generation=_nonnegative_integer(
                    "repository generation", item.get("repository_generation")
                ),
            )
            value = self._restore_entry(
                item, operation_id=result.get("operation_id")
            )
            restored.append(
                {
                    "repository_id": item["repository_id"],
                    "status": value.get("restored_status"),
                    "current_digest": value.get("restored_digest"),
                }
            )
        rollback_result = {
            "schema_version": ADOPTION_SCHEMA_VERSION,
            "ok": True,
            "state": "rolled_back",
            "plan_id": plan_id,
            "apply_result_sha256": result_sha256,
            "restored": restored,
        }
        digest = self._write_once(rollback_path, rollback_result)
        return {**rollback_result, "rollback_sha256": digest}


__all__ = [
    "ADOPTION_SCHEMA_VERSION",
    "TestManifestAdoptionManager",
]
