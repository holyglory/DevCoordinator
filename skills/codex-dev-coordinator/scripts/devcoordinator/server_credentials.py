"""Persistent managed-server credentials outside ordinary Coordinator state.

Only opaque, deterministic bindings may enter SQLite, broker documents, and
worker launch candidates.  Secret bytes remain in exact root-owned material
files and cross into a managed worker only through systemd ``LoadCredential``.

Security basis: ``security-assumptions.md`` requires secret-bearing transport
to remain separate from ordinary coordination metadata while local Unix
identities remain attribution and execution domains for one trusted developer.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence
import uuid
from urllib.parse import urlsplit

from .store import deterministic_id


SERVER_CREDENTIAL_MATERIAL_ROOT = Path(
    "/var/lib/devcoordinator/server-credentials"
)
MAX_SERVER_CREDENTIAL_BYTES = 8192
SERVER_CREDENTIAL_FILE_SUFFIX = ".credential"

_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,255}$")
_SECRET_NAME = re.compile(
    r"(?:^|_)(?:secret|password|passwd|token|credential|private_key|api_key|access_key|authorization)(?:$|_)",
    re.IGNORECASE,
)
_STANDARD_SECRET_ENVIRONMENT = frozenset({"PGPASSWORD", "MYSQL_PWD"})
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/=-]{8,}|[a-z][a-z0-9+.-]*://[^\s/@:]*:[^\s/@]+@)",
    re.IGNORECASE,
)
_SECRET_QUERY = re.compile(
    r"[?&](?:secret|client_secret|password|passwd|token|access_token|credential|api_key|access_key)=[^&#\s]+",
    re.IGNORECASE,
)
_CONNECTION_SECRET = re.compile(
    r"(?:^|[;,\s])(?:password|pwd|token|secret)\s*=\s*[^;,\s]+",
    re.IGNORECASE,
)
_SECRET_ARGUMENT_OPTION = re.compile(
    r"^--?(?:(?:database|db|client)[-_])?"
    r"(?:password|passwd|pwd|token|secret|credential|api[-_]key|access[-_]key)"
    r"(?:=(.*))?$",
    re.IGNORECASE,
)
_SECRET_FILE_OPTION = re.compile(
    r"^--?(?:(?:database|db|client)[-_])?"
    r"(?:password|passwd|pwd|token|secret|credential|api[-_]key|access[-_]key)"
    r"[-_](?:file|path)(?:=(.*))?$",
    re.IGNORECASE,
)
_REFERENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")


class ServerCredentialError(RuntimeError):
    """A managed-server credential binding or material file is unsafe."""


def _environment_name(value: object) -> str:
    if not isinstance(value, str) or _ENVIRONMENT_NAME.fullmatch(value) is None:
        raise ServerCredentialError("server credential environment name is invalid")
    return value


def _server_definition_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 512
        or any(character in value for character in "\x00\r\n")
    ):
        raise ServerCredentialError("server credential server identity is invalid")
    return value


def _credential_id(value: object) -> str:
    if not isinstance(value, str):
        raise ServerCredentialError("server credential identity is invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ServerCredentialError(
            "server credential identity must be a canonical UUID"
        ) from error
    canonical = str(parsed)
    if value != canonical:
        raise ServerCredentialError(
            "server credential identity must be a canonical UUID"
        )
    return canonical


def secret_environment_literal(name: object, value: object) -> bool:
    """Return whether one ordinary environment entry looks credential-bearing.

    A familiar name alone is intentionally insufficient for connection URLs:
    a credential-free local endpoint remains ordinary configuration.  Names
    that explicitly promise a secret are rejected regardless of their current
    value, while credential-bearing URLs, bearer values, and private keys are
    detected from the value.
    """

    normalized_name = _environment_name(name)
    if not isinstance(value, str) or "\x00" in value:
        raise ServerCredentialError("server credential literal is invalid")
    upper_name = normalized_name.upper()
    reference = _environment_reference(upper_name, value)
    secret_name = bool(
        upper_name in _STANDARD_SECRET_ENVIRONMENT
        or (
            not upper_name.startswith("PUBLIC_")
            and _SECRET_NAME.search(upper_name)
            and not reference
        )
    )
    return bool(
        secret_name
        or _SECRET_VALUE.search(value)
        or _SECRET_QUERY.search(value)
        or _CONNECTION_SECRET.search(value)
    )


def _environment_reference(name: str, value: str) -> bool:
    if name.endswith(("_URL", "_URI", "_ENDPOINT")):
        try:
            parsed = urlsplit(value)
        except ValueError:
            return False
        return bool(parsed.scheme and (parsed.netloc or parsed.scheme == "file"))
    if name.endswith("_ID"):
        return _REFERENCE_ID.fullmatch(value) is not None
    return False


def secret_argument_literal(value: object) -> bool:
    """Return whether one argv item carries credential bytes inline.

    Secret-shaped file/path flags are also rejected: persistent servers have
    exactly one reviewed transport, the managed binding delivered through
    systemd ``LoadCredential``.
    """

    if not isinstance(value, str) or "\x00" in value:
        raise ServerCredentialError("server credential argument is invalid")
    file_option = _SECRET_FILE_OPTION.fullmatch(value)
    if file_option is not None:
        return True
    if _SECRET_ARGUMENT_OPTION.fullmatch(value) is not None:
        return True
    return bool(
        _SECRET_VALUE.search(value)
        or _SECRET_QUERY.search(value)
        or _CONNECTION_SECRET.search(value)
    )


def secret_argument_sequence(values: object) -> bool:
    """Detect inline credentials across one complete structured argv."""

    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Sequence):
        raise ServerCredentialError("server credential argv is invalid")
    if len(values) > 256:
        raise ServerCredentialError("server credential argv is excessive")
    arguments: list[str] = []
    for value in values:
        if not isinstance(value, str) or "\x00" in value:
            raise ServerCredentialError("server credential argv is invalid")
        arguments.append(value)
    index = 0
    while index < len(arguments):
        value = arguments[index]
        file_option = _SECRET_FILE_OPTION.fullmatch(value)
        if file_option is not None and file_option.group(1) is None:
            return True
        if secret_argument_literal(value):
            return True
        index += 1
    return False


def server_credential_id(server_definition_id: object, name: object) -> str:
    """Return the stable opaque binding for one server environment key."""

    return deterministic_id(
        "server-environment-credential",
        _server_definition_id(server_definition_id),
        _environment_name(name),
    )


def staged_material_path(root: Path | str, credential_id: object) -> Path:
    """Return one lexically contained material path below an explicit root."""

    candidate_root = Path(root).expanduser()
    if not candidate_root.is_absolute() or candidate_root != Path(
        os.path.abspath(candidate_root)
    ):
        raise ServerCredentialError("server credential material root is not canonical")
    canonical_id = _credential_id(credential_id)
    result = candidate_root / f"{canonical_id}{SERVER_CREDENTIAL_FILE_SUFFIX}"
    if result.parent != candidate_root:
        raise ServerCredentialError("server credential material path escaped its root")
    return result


@dataclass(frozen=True)
class ServerCredentialBinding:
    """One non-secret environment-name to credential-file binding."""

    name: str
    credential_id: str

    def to_document(self) -> dict[str, str]:
        return {"name": self.name, "credential_id": self.credential_id}


def validate_server_credential_binding(
    server_definition_id: object, value: object
) -> ServerCredentialBinding:
    """Validate one exact deterministic binding document."""

    server_id = _server_definition_id(server_definition_id)
    if not isinstance(value, Mapping) or set(value) != {"name", "credential_id"}:
        raise ServerCredentialError(
            "server credential binding fields are invalid"
        )
    name = _environment_name(value["name"])
    credential_id = _credential_id(value["credential_id"])
    if credential_id != server_credential_id(server_id, name):
        raise ServerCredentialError(
            "server credential binding does not match its server and environment"
        )
    return ServerCredentialBinding(name=name, credential_id=credential_id)


def validate_server_credential_bindings(
    server_definition_id: object, values: object
) -> tuple[ServerCredentialBinding, ...]:
    """Validate one ordered, duplicate-free binding collection."""

    server_id = _server_definition_id(server_definition_id)
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Sequence):
        raise ServerCredentialError("server credential bindings must be an array")
    if len(values) > 128:
        raise ServerCredentialError("server credential binding collection is excessive")
    bindings = tuple(
        validate_server_credential_binding(server_id, value) for value in values
    )
    if tuple(binding.name for binding in bindings) != tuple(
        sorted(binding.name for binding in bindings)
    ):
        raise ServerCredentialError("server credential bindings are not ordered")
    if len({binding.name for binding in bindings}) != len(bindings) or len(
        {binding.credential_id for binding in bindings}
    ) != len(bindings):
        raise ServerCredentialError("server credential bindings contain duplicates")
    return bindings


def validate_server_credential_material(
    root: Path | str,
    credential_id: object,
    *,
    expected_uid: int = 0,
) -> str:
    """Read one exact stable root-owned UTF-8 material file.

    The returned value is secret and must remain in memory only.  Callers must
    never put it into a broker document, result, fingerprint, or log.
    """

    if type(expected_uid) is not int or expected_uid < 0:
        raise ServerCredentialError("server credential owner identity is invalid")
    path = staged_material_path(root, credential_id)
    material_root = path.parent
    try:
        root_before = material_root.lstat()
        resolved_root = material_root.resolve(strict=True)
    except OSError as error:
        raise ServerCredentialError(
            "server credential material root is unavailable"
        ) from error
    if (
        resolved_root != material_root
        or stat.S_ISLNK(root_before.st_mode)
        or not stat.S_ISDIR(root_before.st_mode)
        or root_before.st_uid != expected_uid
        or stat.S_IMODE(root_before.st_mode) != 0o700
    ):
        raise ServerCredentialError("server credential material root is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ServerCredentialError("server credential material is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_SERVER_CREDENTIAL_BYTES
        ):
            raise ServerCredentialError("server credential material is unsafe")
        payload = bytearray()
        while len(payload) <= MAX_SERVER_CREDENTIAL_BYTES:
            block = os.read(
                descriptor,
                min(65536, MAX_SERVER_CREDENTIAL_BYTES + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        root_after = material_root.lstat()
        path_after = path.lstat()
    except OSError as error:
        raise ServerCredentialError("server credential material changed") from error
    if (
        len(payload) != before.st_size
        or len(payload) > MAX_SERVER_CREDENTIAL_BYTES
        or (
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
        or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_nlink,
        )
        != (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
            stat.S_IMODE(path_after.st_mode),
            path_after.st_uid,
            path_after.st_nlink,
        )
        or (root_before.st_dev, root_before.st_ino, root_before.st_mtime_ns)
        != (root_after.st_dev, root_after.st_ino, root_after.st_mtime_ns)
    ):
        raise ServerCredentialError("server credential material changed")
    try:
        value = bytes(payload).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ServerCredentialError("server credential material is not UTF-8") from error
    if not value or "\x00" in value:
        raise ServerCredentialError("server credential material is invalid")
    return value


def load_server_credential_environment(
    bindings: Sequence[ServerCredentialBinding],
    credential_directory: Path | str | None,
    *,
    expected_uid: int,
) -> dict[str, str]:
    """Read exactly the systemd-delivered files for validated bindings.

    systemd exposes credential copies by credential ID, without the persistent
    material suffix.  Extra files are rejected so a unit cannot smuggle an
    unbound value into runner memory.  Returned values are secret and must be
    used only for child execution and in-memory output redaction.
    """

    if type(expected_uid) is not int or expected_uid < 0:
        raise ServerCredentialError("server credential runner identity is invalid")
    expected = {binding.credential_id for binding in bindings}
    if credential_directory is None:
        if expected:
            raise ServerCredentialError("server credential directory is unavailable")
        return {}
    raw_root = Path(credential_directory)
    if not raw_root.is_absolute() or raw_root != Path(os.path.abspath(raw_root)):
        raise ServerCredentialError("server credential directory is not canonical")
    try:
        root_info = raw_root.lstat()
        resolved_root = raw_root.resolve(strict=True)
    except OSError as error:
        raise ServerCredentialError(
            "server credential directory is unavailable"
        ) from error
    if (
        resolved_root != raw_root
        or stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid not in {0, expected_uid}
        or stat.S_IMODE(root_info.st_mode) & 0o077
    ):
        raise ServerCredentialError("server credential directory is unsafe")
    try:
        entries = tuple(raw_root.iterdir())
    except OSError as error:
        raise ServerCredentialError(
            "server credential directory is unreadable"
        ) from error
    observed = {entry.name for entry in entries}
    if observed != expected:
        raise ServerCredentialError(
            "server credential directory does not match exact bindings"
        )
    environment: dict[str, str] = {}
    by_id = {binding.credential_id: binding for binding in bindings}
    for entry in entries:
        binding = by_id[entry.name]
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(entry, flags)
        except OSError as error:
            raise ServerCredentialError(
                "server credential runtime material is unavailable"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid not in {0, expected_uid}
                or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_nlink != 1
                or not 1 <= before.st_size <= MAX_SERVER_CREDENTIAL_BYTES
            ):
                raise ServerCredentialError(
                    "server credential runtime material is unsafe"
                )
            payload = bytearray()
            while len(payload) <= MAX_SERVER_CREDENTIAL_BYTES:
                block = os.read(
                    descriptor,
                    min(65536, MAX_SERVER_CREDENTIAL_BYTES + 1 - len(payload)),
                )
                if not block:
                    break
                payload.extend(block)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            current = entry.lstat()
        except OSError as error:
            raise ServerCredentialError(
                "server credential runtime material changed"
            ) from error
        if (
            len(payload) != before.st_size
            or len(payload) > MAX_SERVER_CREDENTIAL_BYTES
        or (
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
        or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            stat.S_IMODE(after.st_mode),
            after.st_uid,
            after.st_nlink,
        )
        != (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
            current.st_nlink,
        )
        ):
            raise ServerCredentialError(
                "server credential runtime material changed"
            )
        try:
            value = bytes(payload).decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ServerCredentialError(
                "server credential runtime material is not UTF-8"
            ) from error
        if not value or "\x00" in value:
            raise ServerCredentialError(
                "server credential runtime material is invalid"
            )
        environment[binding.name] = value
    return dict(sorted(environment.items()))


__all__ = [
    "MAX_SERVER_CREDENTIAL_BYTES",
    "SERVER_CREDENTIAL_FILE_SUFFIX",
    "SERVER_CREDENTIAL_MATERIAL_ROOT",
    "ServerCredentialBinding",
    "ServerCredentialError",
    "secret_environment_literal",
    "secret_argument_literal",
    "secret_argument_sequence",
    "server_credential_id",
    "staged_material_path",
    "load_server_credential_environment",
    "validate_server_credential_binding",
    "validate_server_credential_bindings",
    "validate_server_credential_material",
]
