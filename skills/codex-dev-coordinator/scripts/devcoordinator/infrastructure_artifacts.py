"""Content-addressed signed-envelope evidence for infrastructure observations.

The public ingress owns only a private staging CAS.  The broker independently
opens the exact digest-derived staging path, proves its owner/mode/type/size
and digest, then publishes a broker-owned CAS copy before the observation can
be accepted.  Database rows retain only the digest and an opaque locator; no
caller-controlled filesystem path crosses the broker protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time
from typing import Any, Mapping
import uuid

from .store import refuse_symlink_components


SIGNED_ENVELOPE_ARTIFACT_SCHEMA = (
    "spectre.infrastructure.signed-envelope-artifact.v1"
)
SIGNED_ENVELOPE_LOCATOR_PREFIX = "sha256:"
MAX_SIGNED_ENVELOPE_BYTES = 768 * 1024
SYSTEM_INGRESS_STAGING_ROOT = Path(
    "/var/lib/devcoordinator-infrastructure-ingress/envelopes"
)
SYSTEM_BROKER_ARTIFACT_ROOT = Path(
    "/var/lib/devcoordinator/infrastructure-envelope-artifacts"
)

_HEX = frozenset("0123456789abcdef")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)


class InfrastructureArtifactError(RuntimeError):
    """Signed-envelope evidence is missing, unsafe, or inconsistent."""


@dataclass(frozen=True)
class SignedEnvelopeArtifact:
    sha256: str
    size_bytes: int

    @classmethod
    def from_value(cls, value: Any) -> "SignedEnvelopeArtifact":
        if not isinstance(value, Mapping) or set(value) != {
            "schema",
            "sha256",
            "size_bytes",
        }:
            raise InfrastructureArtifactError(
                "signed-envelope artifact descriptor fields are invalid"
            )
        if value.get("schema") != SIGNED_ENVELOPE_ARTIFACT_SCHEMA:
            raise InfrastructureArtifactError(
                "signed-envelope artifact schema is unsupported"
            )
        digest = value.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in _HEX for character in digest)
        ):
            raise InfrastructureArtifactError(
                "signed-envelope artifact SHA-256 is invalid"
            )
        size = value.get("size_bytes")
        if (
            type(size) is not int
            or size < 1
            or size > MAX_SIGNED_ENVELOPE_BYTES
        ):
            raise InfrastructureArtifactError(
                "signed-envelope artifact size is outside the v1 bound"
            )
        return cls(sha256=digest, size_bytes=size)

    @property
    def locator(self) -> str:
        return SIGNED_ENVELOPE_LOCATOR_PREFIX + self.sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SIGNED_ENVELOPE_ARTIFACT_SCHEMA,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class PublishedSignedEnvelope:
    sha256: str
    size_bytes: int
    locator: str
    payload: bytes

    def binding(self, *, owner_uid: int) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "locator": self.locator,
            "owner_uid": int(owner_uid),
            "mode": "0400",
            "verified": True,
        }


@dataclass(frozen=True)
class VerifiedStagedSignedEnvelope:
    """Descriptor-bound bytes safely reopened from the ingress staging CAS."""

    sha256: str
    size_bytes: int
    locator: str
    payload: bytes


def ensure_private_artifact_root(path: Path, *, expected_uid: int) -> None:
    """Create one missing leaf below an existing expected-UID directory."""

    root = _absolute(path)
    if root.exists() or root.is_symlink():
        descriptor = _open_private_directory(root, expected_uid=expected_uid)
        os.close(descriptor)
        return
    parent = root.parent
    refuse_symlink_components(parent)
    parent_metadata = parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
    ):
        raise InfrastructureArtifactError(
            "artifact root parent must be an expected-UID real directory"
        )
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = _open_private_directory(root, expected_uid=expected_uid)
    os.close(descriptor)


def stage_signed_envelope(
    staging_root: Path,
    payload: bytes,
    *,
    expected_uid: int | None = None,
) -> SignedEnvelopeArtifact:
    """Publish one ingress-owned mode-0400 CAS object without replacement."""

    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_SIGNED_ENVELOPE_BYTES:
        raise InfrastructureArtifactError(
            "signed envelope bytes are outside the v1 artifact bound"
        )
    uid = os.geteuid() if expected_uid is None else int(expected_uid)
    digest = hashlib.sha256(payload).hexdigest()
    artifact = SignedEnvelopeArtifact(sha256=digest, size_bytes=len(payload))
    root_fd = _open_private_directory(_absolute(staging_root), expected_uid=uid)
    try:
        algorithm_fd = _open_or_create_child_directory(
            root_fd, "sha256", expected_uid=uid
        )
        try:
            prefix_fd = _open_or_create_child_directory(
                algorithm_fd, digest[:2], expected_uid=uid
            )
            try:
                _publish_bytes(
                    prefix_fd,
                    f"{digest}.jws",
                    payload,
                    expected_uid=uid,
                )
            finally:
                os.close(prefix_fd)
        finally:
            os.close(algorithm_fd)
    finally:
        os.close(root_fd)
    return artifact


def publish_staged_signed_envelope(
    *,
    staging_root: Path,
    broker_artifact_root: Path,
    descriptor: Mapping[str, Any],
    staging_uid: int,
    broker_uid: int,
) -> PublishedSignedEnvelope:
    """Verify staging evidence and publish the broker-owned immutable copy."""

    staged = read_staged_signed_envelope(
        staging_root=staging_root,
        descriptor=descriptor,
        staging_uid=staging_uid,
    )
    return publish_verified_staged_signed_envelope(
        broker_artifact_root=broker_artifact_root,
        staged=staged,
        broker_uid=broker_uid,
    )


def read_staged_signed_envelope(
    *,
    staging_root: Path,
    descriptor: Mapping[str, Any],
    staging_uid: int,
) -> VerifiedStagedSignedEnvelope:
    """Safely read one descriptor-bound ingress object without publishing it."""

    artifact = SignedEnvelopeArtifact.from_value(descriptor)
    payload = _read_cas_object(
        _absolute(staging_root),
        artifact,
        expected_uid=int(staging_uid),
    )
    return VerifiedStagedSignedEnvelope(
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        locator=artifact.locator,
        payload=payload,
    )


def publish_verified_staged_signed_envelope(
    *,
    broker_artifact_root: Path,
    staged: VerifiedStagedSignedEnvelope,
    broker_uid: int,
) -> PublishedSignedEnvelope:
    """Publish bytes already reopened and verified by the broker caller."""

    if not isinstance(staged, VerifiedStagedSignedEnvelope):
        raise InfrastructureArtifactError(
            "broker publication requires verified staged envelope bytes"
        )
    artifact = SignedEnvelopeArtifact(
        sha256=staged.sha256,
        size_bytes=staged.size_bytes,
    )
    if (
        hashlib.sha256(staged.payload).hexdigest() != artifact.sha256
        or len(staged.payload) != artifact.size_bytes
    ):
        raise InfrastructureArtifactError(
            "verified staged envelope bytes no longer match their descriptor"
        )
    ensure_private_artifact_root(
        _absolute(broker_artifact_root), expected_uid=int(broker_uid)
    )
    root_fd = _open_private_directory(
        _absolute(broker_artifact_root), expected_uid=int(broker_uid)
    )
    try:
        algorithm_fd = _open_or_create_child_directory(
            root_fd, "sha256", expected_uid=int(broker_uid)
        )
        try:
            prefix_fd = _open_or_create_child_directory(
                algorithm_fd, artifact.sha256[:2], expected_uid=int(broker_uid)
            )
            try:
                _publish_bytes(
                    prefix_fd,
                    f"{artifact.sha256}.jws",
                    staged.payload,
                    expected_uid=int(broker_uid),
                )
            finally:
                os.close(prefix_fd)
        finally:
            os.close(algorithm_fd)
    finally:
        os.close(root_fd)
    # Reopen the broker copy instead of trusting the successful publication.
    broker_payload = _read_cas_object(
        _absolute(broker_artifact_root),
        artifact,
        expected_uid=int(broker_uid),
    )
    if broker_payload != staged.payload:
        raise InfrastructureArtifactError(
            "broker signed-envelope artifact changed after publication"
        )
    return PublishedSignedEnvelope(
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        locator=artifact.locator,
        payload=broker_payload,
    )


def _absolute(path: Path) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute() or ".." in value.parts:
        raise InfrastructureArtifactError(
            "artifact root must be an absolute path without traversal"
        )
    return value


def _require_safe_primitives() -> None:
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
    ):
        raise InfrastructureArtifactError(
            "descriptor-relative no-follow artifact access is unavailable"
        )


def _open_private_directory(path: Path, *, expected_uid: int) -> int:
    _require_safe_primitives()
    refuse_symlink_components(path)
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except OSError as error:
        raise InfrastructureArtifactError(
            "private artifact root cannot be opened safely"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise InfrastructureArtifactError(
                "private artifact root owner or mode is invalid"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_or_create_child_directory(
    parent_fd: int, name: str, *, expected_uid: int
) -> int:
    if not name or "/" in name or name in {".", ".."}:
        raise InfrastructureArtifactError("artifact directory name is invalid")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise InfrastructureArtifactError(
            "artifact directory cannot be opened safely"
        ) from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise InfrastructureArtifactError(
            "artifact directory owner or mode is invalid"
        )
    return descriptor


def _publish_bytes(
    parent_fd: int,
    name: str,
    payload: bytes,
    *,
    expected_uid: int,
) -> None:
    existing: bytes | None = None
    for attempt in range(20):
        try:
            existing = _read_private_file(
                parent_fd,
                name,
                expected_uid=expected_uid,
                maximum_bytes=MAX_SIGNED_ENVELOPE_BYTES,
            )
            break
        except FileNotFoundError:
            existing = None
            break
        except InfrastructureArtifactError:
            # Another same-UID publisher may have linked the final inode and
            # not yet removed its temporary name (st_nlink == 2).  The final
            # proof still requires one link; this bounded retry never accepts
            # the transient or repairs an attacker-controlled object.
            if attempt == 19:
                raise
            time.sleep(0.002)
    if existing is not None:
        if existing != payload:
            raise InfrastructureArtifactError(
                "content-addressed artifact path contains different bytes"
            )
        return

    temporary = f".{name}.{uuid.uuid4()}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
    try:
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(payload)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise InfrastructureArtifactError(
                        "signed-envelope artifact write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            winner = _read_private_file_after_publication(
                parent_fd, name, expected_uid=expected_uid
            )
            if winner != payload:
                raise InfrastructureArtifactError(
                    "concurrent content-addressed artifact differs"
                )
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
    verified = _read_private_file_after_publication(
        parent_fd, name, expected_uid=expected_uid
    )
    if verified != payload:
        raise InfrastructureArtifactError(
            "signed-envelope artifact failed post-publication verification"
        )


def _read_private_file_after_publication(
    parent_fd: int, name: str, *, expected_uid: int
) -> bytes:
    for attempt in range(20):
        try:
            return _read_private_file(
                parent_fd,
                name,
                expected_uid=expected_uid,
                maximum_bytes=MAX_SIGNED_ENVELOPE_BYTES,
            )
        except InfrastructureArtifactError:
            if attempt == 19:
                raise
            time.sleep(0.002)
    raise AssertionError("bounded artifact publication retry did not terminate")


def _read_cas_object(
    root: Path,
    artifact: SignedEnvelopeArtifact,
    *,
    expected_uid: int,
) -> bytes:
    root_fd = _open_private_directory(root, expected_uid=expected_uid)
    try:
        algorithm_fd = _open_child_directory(
            root_fd, "sha256", expected_uid=expected_uid
        )
        try:
            prefix_fd = _open_child_directory(
                algorithm_fd, artifact.sha256[:2], expected_uid=expected_uid
            )
            try:
                payload = _read_private_file(
                    prefix_fd,
                    f"{artifact.sha256}.jws",
                    expected_uid=expected_uid,
                    maximum_bytes=MAX_SIGNED_ENVELOPE_BYTES,
                )
            finally:
                os.close(prefix_fd)
        finally:
            os.close(algorithm_fd)
    finally:
        os.close(root_fd)
    if len(payload) != artifact.size_bytes:
        raise InfrastructureArtifactError(
            "signed-envelope artifact size does not match its descriptor"
        )
    if hashlib.sha256(payload).hexdigest() != artifact.sha256:
        raise InfrastructureArtifactError(
            "signed-envelope artifact digest does not match its descriptor"
        )
    return payload


def _open_child_directory(
    parent_fd: int, name: str, *, expected_uid: int
) -> int:
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise InfrastructureArtifactError(
            "artifact CAS directory is missing or unsafe"
        ) from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise InfrastructureArtifactError(
            "artifact CAS directory owner or mode is invalid"
        )
    return descriptor


def _read_private_file(
    parent_fd: int,
    name: str,
    *,
    expected_uid: int,
    maximum_bytes: int,
) -> bytes:
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise InfrastructureArtifactError(
            "signed-envelope artifact is unavailable or unsafe"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise InfrastructureArtifactError(
                "signed-envelope artifact owner, mode, links, or size is invalid"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise InfrastructureArtifactError(
                    "signed-envelope artifact was truncated during read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise InfrastructureArtifactError(
                "signed-envelope artifact grew during read"
            )
        after = os.fstat(descriptor)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or after.st_nlink != 1
            or stat.S_IMODE(after.st_mode) != 0o400
            or after.st_uid != expected_uid
        ):
            raise InfrastructureArtifactError(
                "signed-envelope artifact changed during verification"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


__all__ = [
    "InfrastructureArtifactError",
    "MAX_SIGNED_ENVELOPE_BYTES",
    "PublishedSignedEnvelope",
    "SIGNED_ENVELOPE_ARTIFACT_SCHEMA",
    "SYSTEM_BROKER_ARTIFACT_ROOT",
    "SYSTEM_INGRESS_STAGING_ROOT",
    "SignedEnvelopeArtifact",
    "ensure_private_artifact_root",
    "publish_staged_signed_envelope",
    "stage_signed_envelope",
]
