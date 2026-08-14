"""Public non-authorizing routing context for immutable test snapshots."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping


IMMUTABLE_REPOSITORY_BINDING_NAME = "repository-context.json"
_KIND = "devcoordinator-immutable-repository-context"
_MAX_BYTES = 4096
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_SNAPSHOT_ID = re.compile(r"snapshot-[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class ImmutableRepositoryBindingError(ValueError):
    """An authority-published immutable repository route is contradictory."""


@dataclass(frozen=True)
class ImmutableRepositoryBinding:
    snapshot_id: str
    repository_id: str
    original_root: str
    materialized_root: str
    content_fingerprint: str
    context_fingerprint: str


@dataclass(frozen=True)
class ImmutableRepositoryRouteScope:
    canonical_root: str


@dataclass(frozen=True)
class ImmutableRepositoryRouteContext:
    root: ImmutableRepositoryRouteScope
    effective: ImmutableRepositoryRouteScope
    temporary: None = None

    @property
    def project_kind(self) -> str:
        return "primary"


def _canonical_absolute(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 2048
        or "\x00" in value
        or not Path(value).is_absolute()
    ):
        raise ImmutableRepositoryBindingError(f"immutable {field} is invalid")
    normalized = os.path.abspath(value)
    if normalized != value:
        raise ImmutableRepositoryBindingError(f"immutable {field} is not canonical")
    return normalized


def _base_document(
    *,
    snapshot_id: str,
    repository_id: str,
    original_root: str,
    materialized_root: str,
    content_fingerprint: str,
) -> dict[str, object]:
    if _SNAPSHOT_ID.fullmatch(snapshot_id) is None:
        raise ImmutableRepositoryBindingError("immutable snapshot identity is invalid")
    if _SAFE_ID.fullmatch(repository_id) is None:
        raise ImmutableRepositoryBindingError("immutable repository identity is invalid")
    if _SHA256.fullmatch(content_fingerprint) is None:
        raise ImmutableRepositoryBindingError("immutable content identity is invalid")
    return {
        "schema_version": 1,
        "kind": _KIND,
        "snapshot_id": snapshot_id,
        "repository_id": repository_id,
        "original_root": _canonical_absolute(original_root, field="original root"),
        "materialized_root": _canonical_absolute(
            materialized_root, field="materialized root"
        ),
        "content_fingerprint": content_fingerprint,
    }


def _encoded_document(**values: str) -> bytes:
    base = _base_document(**values)
    fingerprint = hashlib.sha256(
        json.dumps(
            base,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    payload = json.dumps(
        {**base, "context_fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    if len(payload) > _MAX_BYTES:
        raise ImmutableRepositoryBindingError(
            "immutable repository context exceeds its byte bound"
        )
    return payload


def publish_immutable_repository_binding(
    directory: Path,
    *,
    snapshot_id: str,
    repository_id: str,
    original_root: str,
    materialized_root: str,
    content_fingerprint: str,
) -> Path:
    """Publish one read-only route beside an authority-owned sealed snapshot."""

    payload = _encoded_document(
        snapshot_id=snapshot_id,
        repository_id=repository_id,
        original_root=original_root,
        materialized_root=materialized_root,
        content_fingerprint=content_fingerprint,
    )
    path = directory / IMMUTABLE_REPOSITORY_BINDING_NAME
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o444,
        )
    except FileExistsError:
        try:
            if path.read_bytes() != payload:
                raise ImmutableRepositoryBindingError(
                    "immutable repository context contradicts snapshot provenance"
                )
        except OSError as error:
            raise ImmutableRepositoryBindingError(
                "immutable repository context is unavailable"
            ) from error
        return path
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ImmutableRepositoryBindingError(
                    "immutable repository context write was incomplete"
                )
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _decode(payload: bytes) -> ImmutableRepositoryBinding:
    if not payload or len(payload) > _MAX_BYTES:
        raise ImmutableRepositoryBindingError(
            "immutable repository context has an invalid size"
        )
    try:
        raw = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImmutableRepositoryBindingError(
            "immutable repository context is not valid JSON"
        ) from error
    fields = {
        "schema_version",
        "kind",
        "snapshot_id",
        "repository_id",
        "original_root",
        "materialized_root",
        "content_fingerprint",
        "context_fingerprint",
    }
    if (
        not isinstance(raw, Mapping)
        or set(raw) != fields
        or raw.get("schema_version") != 1
        or raw.get("kind") != _KIND
    ):
        raise ImmutableRepositoryBindingError(
            "immutable repository context fields are invalid"
        )
    base = _base_document(
        snapshot_id=raw.get("snapshot_id"),
        repository_id=raw.get("repository_id"),
        original_root=raw.get("original_root"),
        materialized_root=raw.get("materialized_root"),
        content_fingerprint=raw.get("content_fingerprint"),
    )
    expected = hashlib.sha256(
        json.dumps(
            base,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if raw.get("context_fingerprint") != expected:
        raise ImmutableRepositoryBindingError(
            "immutable repository context fingerprint is invalid"
        )
    return ImmutableRepositoryBinding(
        snapshot_id=str(base["snapshot_id"]),
        repository_id=str(base["repository_id"]),
        original_root=str(base["original_root"]),
        materialized_root=str(base["materialized_root"]),
        content_fingerprint=str(base["content_fingerprint"]),
        context_fingerprint=expected,
    )


def resolve_immutable_repository_binding(
    project: str | Path,
) -> ImmutableRepositoryBinding | None:
    """Map a snapshot path to its original route without making an access decision."""

    try:
        # This is a recognition layer in front of the ordinary repository
        # resolver. A nonexistent ordinary fixture/path is not an immutable
        # binding error; let the owning resolver report it in its own terms.
        resolved = Path(project).expanduser().resolve()
        resolved_is_directory = resolved.is_dir()
    except (OSError, RuntimeError):
        # An inaccessible ordinary absolute repository is still a valid opaque
        # route on this single-developer host. It simply cannot be an immutable
        # snapshot binding discoverable from the caller's filesystem view.
        return None
    candidate = resolved if resolved_is_directory else resolved.parent
    root = next(
        (
            ancestor
            for ancestor in (candidate, *candidate.parents)
            if ancestor.name == "root"
            and (ancestor.parent / IMMUTABLE_REPOSITORY_BINDING_NAME).exists()
        ),
        None,
    )
    if root is None:
        return None
    parent = root.parent
    path = parent / IMMUTABLE_REPOSITORY_BINDING_NAME
    try:
        parent_metadata = parent.stat(follow_symlinks=False)
        path_metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or path_metadata.st_size <= 0
            or path_metadata.st_size > _MAX_BYTES
        ):
            raise ImmutableRepositoryBindingError(
                "immutable repository context identity is invalid"
            )
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != path_metadata.st_dev
                or opened.st_ino != path_metadata.st_ino
                or opened.st_size != path_metadata.st_size
            ):
                raise ImmutableRepositoryBindingError(
                    "immutable repository context changed while opening"
                )
            payload = os.read(descriptor, _MAX_BYTES + 1)
            if os.read(descriptor, 1):
                raise ImmutableRepositoryBindingError(
                    "immutable repository context changed while reading"
                )
        finally:
            os.close(descriptor)
    except ImmutableRepositoryBindingError:
        raise
    except OSError as error:
        raise ImmutableRepositoryBindingError(
            "immutable repository context is unavailable"
        ) from error
    binding = _decode(payload)
    if (
        parent.name != binding.snapshot_id
        or str(root) != binding.materialized_root
        or resolved != root
        and root not in resolved.parents
    ):
        raise ImmutableRepositoryBindingError(
            "immutable repository context does not bind this snapshot path"
        )
    return binding


def immutable_repository_route_context(
    binding: ImmutableRepositoryBinding,
) -> ImmutableRepositoryRouteContext:
    return repository_route_context(binding.original_root)


def repository_route_context(canonical_root: str) -> ImmutableRepositoryRouteContext:
    """Return one non-authorizing route for an explicit absolute repository."""

    canonical = _canonical_absolute(canonical_root, field="repository route")
    scope = ImmutableRepositoryRouteScope(canonical_root=canonical)
    return ImmutableRepositoryRouteContext(root=scope, effective=scope)
