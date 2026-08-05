"""Broker-owned operational credentials for exact universal-test attempts.

Repository manifests can name an administrator-sealed binding, but cannot
provide a credential value, source path, destination filename, or grant. A
local administrator imports one value from a descriptor-checked dotenv file
into this module's Coordinator-managed material store. The broker
then copies that value into a one-attempt runtime lease and systemd delivers it
with ``LoadCredential=``.

Secret bytes deliberately never enter the registry JSON, broker SQLite state,
the attempt descriptor, command arguments, ordinary environment variables,
logs, result evidence, or any path readable by the repository owner.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from types import MappingProxyType
from typing import Callable, Iterator, Mapping, Sequence

from .universal_test_runtime import (
    MAX_TEST_ATTEMPT_TTL_SECONDS,
    TestAttemptDescriptor,
    TestCredentialLease,
)
from .universal_test_store import TestStoreConflict, TestStoreContractError


DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH = Path(
    "/etc/devcoordinator/test-execution-credentials.json"
)
DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT = Path(
    "/var/lib/devcoordinator/test-execution-credentials"
)
DEFAULT_TEST_CREDENTIAL_RUNTIME_ROOT = Path(
    "/run/devcoordinator/test-execution-credential-leases"
)
MAX_TEST_CREDENTIAL_SOURCE_BYTES = 1024 * 1024
MAX_TEST_CREDENTIAL_BYTES = 64 * 1024
_REGISTRY_SCHEMA_VERSION = 1
_LEASE_SCHEMA_VERSION = 3
_SAFE_ALIAS = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SAFE_REPOSITORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/+ -]{0,255}$")
_SAFE_CREDENTIAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SAFE_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SAFE_MATERIAL_ID = re.compile(r"^material-[0-9a-f]{64}$")
_SAFE_LEASE_MATERIAL_NAME = re.compile(r"^credential-[0-9a-f]{64}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _single_line(field: str, value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _positive_integer(field: str, value: object, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _nonnegative_integer(field: str, value: object) -> int:
    if type(value) is not int or value < 0:
        raise TestStoreContractError(f"{field} is invalid")
    return value


def _require_regular_file(field: str, metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise TestStoreConflict(f"{field} is unsafe")


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return content/leaf identity used around descriptor reads.

    Unix ownership, mode, ACL and link count are deliberately not local trust
    inputs. Device/inode, size and timestamps still detect path replacement or
    mutation while a file is being read.
    """

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _lstat_optional(path: Path, *, field: str) -> os.stat_result | None:
    """Observe exact leaf presence without following a dangling symlink."""

    try:
        return Path(path).lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise TestStoreConflict(f"{field} is unavailable") from error


def _fsync_directory(path: Path, *, field: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
    except OSError as error:
        raise TestStoreConflict(f"{field} is unavailable") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise TestStoreConflict(f"{field} cannot be synchronized") from error
    finally:
        os.close(descriptor)


def _require_private_directory(
    path: Path,
    *,
    expected_uid: int,
    create: bool,
) -> None:
    del expected_uid
    path = Path(path)
    if not path.is_absolute():
        raise TestStoreContractError("credential directory must be absolute")
    metadata = _lstat_optional(path, field="credential directory")
    if metadata is None:
        if not create:
            raise TestStoreConflict("credential directory is unavailable")
        parent = path.parent
        try:
            parent_metadata = parent.lstat()
            parent_resolved = parent.resolve(strict=True)
        except OSError as error:
            raise TestStoreConflict("credential directory parent is unavailable") from error
        if (
            parent_resolved != parent
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
        ):
            raise TestStoreConflict("credential directory parent is unsafe")
        try:
            path.mkdir(mode=0o700)
        except OSError as error:
            raise TestStoreConflict("credential directory cannot be created") from error
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise TestStoreConflict("credential directory is unavailable") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
    ):
        raise TestStoreConflict("credential directory is unsafe")


def _require_safe_parent_directory(path: Path, *, expected_uid: int) -> None:
    del expected_uid
    path = Path(path)
    if not path.is_absolute():
        raise TestStoreContractError("credential registry parent must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise TestStoreConflict("credential registry parent is unavailable") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
    ):
        raise TestStoreConflict("credential registry parent is unsafe")


def _read_private_file(
    path: Path,
    *,
    expected_uid: int,
    allowed_modes: set[int],
    maximum_bytes: int,
    field: str,
) -> tuple[bytes, os.stat_result]:
    del expected_uid, allowed_modes
    path = Path(path)
    if not path.is_absolute():
        raise TestStoreContractError(f"{field} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        before_path = path.lstat()
    except OSError as error:
        raise TestStoreConflict(f"{field} is unavailable") from error
    if resolved != path:
        raise TestStoreConflict(f"{field} path is unsafe")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise TestStoreConflict(f"{field} is unavailable") from error
    payload = bytearray()
    try:
        before = os.fstat(descriptor)
        _require_regular_file(field, before)
        if before.st_size > maximum_bytes:
            raise TestStoreConflict(f"{field} is unsafe")
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum_bytes:
                raise TestStoreConflict(f"{field} is excessive")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as error:
            raise TestStoreConflict(f"{field} cannot be revalidated") from error
        verification = bytearray()
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - len(verification)),
            )
            if not chunk:
                break
            verification.extend(chunk)
            if len(verification) > maximum_bytes:
                raise TestStoreConflict(f"{field} is excessive")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise TestStoreConflict(f"{field} changed during import") from error
    identity = _stable_file_identity(before)
    if (
        identity != _stable_file_identity(after)
        or identity != _stable_file_identity(before_path)
        or identity != _stable_file_identity(after_path)
        or payload != verification
    ):
        raise TestStoreConflict(f"{field} changed during import")
    return bytes(payload), before


def _decode_dotenv_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise TestStoreContractError("credential source value is empty")
    if value[0] == "'":
        if len(value) < 2 or value[-1] != "'":
            raise TestStoreContractError("credential source quoting is invalid")
        value = value[1:-1]
    elif value[0] == '"':
        if len(value) < 2 or value[-1] != '"':
            raise TestStoreContractError("credential source quoting is invalid")
        source = value[1:-1]
        decoded: list[str] = []
        escaped = False
        for character in source:
            if escaped:
                if character not in {'"', "\\"}:
                    raise TestStoreContractError(
                        "credential source uses an unsupported escape"
                    )
                decoded.append(character)
                escaped = False
            elif character == "\\":
                escaped = True
            else:
                decoded.append(character)
        if escaped:
            raise TestStoreContractError("credential source quoting is invalid")
        value = "".join(decoded)
    if (
        not value
        or not 16 <= len(value.encode("utf-8")) <= MAX_TEST_CREDENTIAL_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise TestStoreContractError("credential source value is invalid")
    return value


def _dotenv_value(payload: bytes, *, key: str) -> bytes:
    if _SAFE_ENV_KEY.fullmatch(key) is None:
        raise TestStoreContractError("credential source key is invalid")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TestStoreContractError("credential source is not UTF-8") from error
    if "\x00" in text:
        raise TestStoreContractError("credential source contains NUL")
    matches: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        name, separator, raw_value = stripped.partition("=")
        if not separator:
            continue
        if name.strip() == key:
            matches.append(_decode_dotenv_value(raw_value))
    if len(matches) != 1:
        raise TestStoreContractError(
            "credential source must contain the named key exactly once"
        )
    return matches[0].encode("utf-8")


def _write_new_private_file(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    expected_uid: int,
) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
    except OSError as error:
        raise TestStoreConflict("credential material cannot be created") from error
    try:
        metadata = os.fstat(descriptor)
        _require_regular_file("credential material", metadata)
        # Creation mode is an operational default, not an authorization gate.
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise TestStoreConflict("credential material write made no progress")
            view = view[count:]
        os.fsync(descriptor)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def _atomic_private_json(
    path: Path,
    document: Mapping[str, object],
    *,
    expected_uid: int,
) -> None:
    parent = path.parent
    _require_safe_parent_directory(parent, expected_uid=expected_uid)
    payload = _canonical_json(document)
    if len(payload) > 1024 * 1024:
        raise TestStoreContractError("credential registry is excessive")
    metadata = _lstat_optional(path, field="credential registry")
    if metadata is not None:
        _require_regular_file("credential registry", metadata)
    temporary = parent / f".{path.name}.tmp-{secrets.token_hex(16)}"
    _write_new_private_file(
        temporary,
        payload,
        mode=0o600,
        expected_uid=expected_uid,
    )
    try:
        os.replace(temporary, path)
        _fsync_directory(parent, field="credential registry directory")
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class OperationalCredentialBinding:
    alias: str
    repository_id: str
    repository_generation: int
    target_name: str
    intent: str
    owner_uid: int
    credential_name: str
    max_ttl_seconds: int
    rotation_generation: int
    status: str
    material_id: str
    material_sha256: str
    material_size_bytes: int
    imported_at_epoch: int
    source_identity: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.alias, str) or _SAFE_ALIAS.fullmatch(self.alias) is None:
            raise TestStoreContractError("credential binding alias is invalid")
        if (
            not isinstance(self.repository_id, str)
            or _SAFE_REPOSITORY_ID.fullmatch(self.repository_id) is None
        ):
            raise TestStoreContractError("credential binding repository is invalid")
        _nonnegative_integer(
            "credential binding repository generation", self.repository_generation
        )
        if (
            not isinstance(self.target_name, str)
            or _SAFE_TARGET.fullmatch(self.target_name) is None
        ):
            raise TestStoreContractError("credential binding target is invalid")
        if self.intent != "manual":
            raise TestStoreContractError(
                "operational credentials are restricted to manual intent"
            )
        _positive_integer("credential binding owner UID", self.owner_uid, maximum=2**31 - 1)
        if (
            not isinstance(self.credential_name, str)
            or _SAFE_CREDENTIAL_NAME.fullmatch(self.credential_name) is None
        ):
            raise TestStoreContractError("credential destination name is invalid")
        _positive_integer(
            "credential binding TTL",
            self.max_ttl_seconds,
            maximum=MAX_TEST_ATTEMPT_TTL_SECONDS,
        )
        _positive_integer(
            "credential rotation generation",
            self.rotation_generation,
            maximum=2**31 - 1,
        )
        if self.status not in {"active", "revoked"}:
            raise TestStoreContractError("credential binding status is invalid")
        if (
            not isinstance(self.material_id, str)
            or _SAFE_MATERIAL_ID.fullmatch(self.material_id) is None
            or not isinstance(self.material_sha256, str)
            or _HEX_SHA256.fullmatch(self.material_sha256) is None
        ):
            raise TestStoreContractError("credential material identity is invalid")
        _positive_integer(
            "credential material size",
            self.material_size_bytes,
            maximum=MAX_TEST_CREDENTIAL_BYTES,
        )
        _positive_integer(
            "credential import time", self.imported_at_epoch, maximum=2**63 - 1
        )
        source = self.source_identity
        fields = {
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "size_bytes",
            "sha256",
            "path_sha256",
            "key",
        }
        if (
            not isinstance(source, Mapping)
            or set(source) != fields
            or any(
                type(source[field]) is not int or int(source[field]) < 0
                for field in ("device", "inode", "uid", "gid", "mode", "size_bytes")
            )
            or not isinstance(source["sha256"], str)
            or _HEX_SHA256.fullmatch(str(source["sha256"])) is None
            or not isinstance(source["path_sha256"], str)
            or _HEX_SHA256.fullmatch(str(source["path_sha256"])) is None
            or not isinstance(source["key"], str)
            or _SAFE_ENV_KEY.fullmatch(str(source["key"])) is None
        ):
            raise TestStoreContractError("credential source identity is invalid")
        object.__setattr__(self, "source_identity", MappingProxyType(dict(source)))

    def to_document(self) -> dict[str, object]:
        return {
            "alias": self.alias,
            "repository_id": self.repository_id,
            "repository_generation": self.repository_generation,
            "target_name": self.target_name,
            "intent": self.intent,
            "owner_uid": self.owner_uid,
            "credential_name": self.credential_name,
            "max_ttl_seconds": self.max_ttl_seconds,
            "rotation_generation": self.rotation_generation,
            "status": self.status,
            "material_id": self.material_id,
            "material_sha256": self.material_sha256,
            "material_size_bytes": self.material_size_bytes,
            "imported_at_epoch": self.imported_at_epoch,
            "source_identity": dict(self.source_identity),
        }


@dataclass(frozen=True)
class SealedOperationalCredentialRegistry:
    authority_generation: int
    bindings: Mapping[str, OperationalCredentialBinding]
    fingerprint: str

    @classmethod
    def empty(cls) -> "SealedOperationalCredentialRegistry":
        document = {
            "schema_version": _REGISTRY_SCHEMA_VERSION,
            "authority_generation": 0,
            "bindings": [],
        }
        return cls(
            authority_generation=0,
            bindings=MappingProxyType({}),
            fingerprint=hashlib.sha256(_canonical_json(document)).hexdigest(),
        )

    @classmethod
    def from_document(
        cls, document: object
    ) -> "SealedOperationalCredentialRegistry":
        if (
            not isinstance(document, Mapping)
            or set(document)
            != {"schema_version", "authority_generation", "bindings"}
            or document["schema_version"] != _REGISTRY_SCHEMA_VERSION
            or type(document["authority_generation"]) is not int
            or int(document["authority_generation"]) < 0
            or not isinstance(document["bindings"], list)
            or len(document["bindings"]) > 10_000
        ):
            raise TestStoreContractError("credential registry fields are invalid")
        bindings: dict[str, OperationalCredentialBinding] = {}
        expected_fields = set(OperationalCredentialBinding.__dataclass_fields__)
        for raw in document["bindings"]:
            if not isinstance(raw, Mapping) or set(raw) != expected_fields:
                raise TestStoreContractError("credential registry binding is invalid")
            binding = OperationalCredentialBinding(**raw)  # type: ignore[arg-type]
            if binding.alias in bindings:
                raise TestStoreContractError("credential registry alias is duplicated")
            bindings[binding.alias] = binding
        encoded = _canonical_json(document)
        return cls(
            authority_generation=int(document["authority_generation"]),
            bindings=MappingProxyType(dict(sorted(bindings.items()))),
            fingerprint=hashlib.sha256(encoded).hexdigest(),
        )

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": _REGISTRY_SCHEMA_VERSION,
            "authority_generation": self.authority_generation,
            "bindings": [
                binding.to_document() for binding in self.bindings.values()
            ],
        }


class AdministratorOperationalCredentialStore:
    """Local registration, rotation, and revocation authority."""

    def __init__(
        self,
        *,
        registry_path: Path = DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH,
        material_root: Path = DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT,
        expected_authority_uid: int = 0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.registry_path = Path(registry_path)
        self.material_root = Path(material_root)
        self.expected_authority_uid = expected_authority_uid
        self.clock = clock
        if (
            not self.registry_path.is_absolute()
            or not self.material_root.is_absolute()
            or type(expected_authority_uid) is not int
            or expected_authority_uid < 0
        ):
            raise TestStoreContractError("credential store configuration is invalid")

    @property
    def _lock_path(self) -> Path:
        return self.material_root / ".registry.lock"

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        _require_private_directory(
            self.material_root,
            expected_uid=self.expected_authority_uid,
            create=True,
        )
        try:
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR
                | os.O_CREAT
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except OSError as error:
            raise TestStoreConflict("credential registry lock is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            _require_regular_file("credential registry lock", metadata)
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _load_unlocked(
        self, *, allow_missing: bool
    ) -> SealedOperationalCredentialRegistry:
        metadata = _lstat_optional(
            self.registry_path,
            field="credential registry",
        )
        if metadata is None:
            if allow_missing:
                return SealedOperationalCredentialRegistry.empty()
            raise TestStoreConflict("credential registry is missing")
        payload, _ = _read_private_file(
            self.registry_path,
            expected_uid=self.expected_authority_uid,
            allowed_modes={0o600},
            maximum_bytes=1024 * 1024,
            field="credential registry",
        )
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("credential registry is invalid") from error
        return SealedOperationalCredentialRegistry.from_document(document)

    def load(self, *, allow_missing: bool = True) -> SealedOperationalCredentialRegistry:
        with self._locked(exclusive=False):
            return self._load_unlocked(allow_missing=allow_missing)

    def _import_source(
        self,
        *,
        source_path: Path,
        source_key: str,
        source_uid: int,
    ) -> tuple[bytes, Mapping[str, object]]:
        payload, metadata = _read_private_file(
            Path(source_path),
            expected_uid=source_uid,
            allowed_modes={0o400, 0o600},
            maximum_bytes=MAX_TEST_CREDENTIAL_SOURCE_BYTES,
            field="credential source",
        )
        value = _dotenv_value(payload, key=source_key)
        source_identity = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size_bytes": metadata.st_size,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "path_sha256": hashlib.sha256(
                str(Path(source_path)).encode("utf-8")
            ).hexdigest(),
            "key": source_key,
        }
        return value, MappingProxyType(source_identity)

    def _new_material(self, value: bytes) -> tuple[str, str]:
        digest = hashlib.sha256(value).hexdigest()
        material_id = "material-" + hashlib.sha256(
            value + secrets.token_bytes(32)
        ).hexdigest()
        _write_new_private_file(
            self.material_root / material_id,
            value,
            mode=0o400,
            expected_uid=self.expected_authority_uid,
        )
        _fsync_directory(
            self.material_root,
            field="credential material directory",
        )
        return material_id, digest

    def _publish(
        self,
        previous: SealedOperationalCredentialRegistry,
        bindings: Mapping[str, OperationalCredentialBinding],
    ) -> SealedOperationalCredentialRegistry:
        replacement = SealedOperationalCredentialRegistry.from_document(
            {
                "schema_version": _REGISTRY_SCHEMA_VERSION,
                "authority_generation": previous.authority_generation + 1,
                "bindings": [
                    binding.to_document()
                    for binding in sorted(bindings.values(), key=lambda item: item.alias)
                ],
            }
        )
        _require_safe_parent_directory(
            self.registry_path.parent, expected_uid=self.expected_authority_uid
        )
        _atomic_private_json(
            self.registry_path,
            replacement.to_document(),
            expected_uid=self.expected_authority_uid,
        )
        return replacement

    def _remove_material_unlocked(self, material_id: str) -> None:
        path = self.material_root / material_id
        metadata = _lstat_optional(path, field="credential material")
        if metadata is None:
            return
        _require_regular_file("credential material", metadata)
        try:
            path.unlink()
        except OSError as error:
            raise TestStoreConflict("credential material cannot be removed") from error
        _fsync_directory(
            self.material_root,
            field="credential material directory",
        )

    def _reconcile_material_unlocked(
        self, registry: SealedOperationalCredentialRegistry
    ) -> None:
        retained = {
            binding.material_id
            for binding in registry.bindings.values()
            if binding.status == "active"
        }
        try:
            entries = tuple(self.material_root.iterdir())
        except OSError as error:
            raise TestStoreConflict("credential material inventory is unavailable") from error
        removed = False
        for path in entries:
            if path.name == self._lock_path.name or path.name in retained:
                continue
            if _SAFE_MATERIAL_ID.fullmatch(path.name) is None:
                continue
            metadata = _lstat_optional(path, field="credential material")
            if metadata is None:
                continue
            _require_regular_file("credential material", metadata)
            try:
                path.unlink()
            except OSError as error:
                raise TestStoreConflict(
                    "credential material cannot be reconciled"
                ) from error
            removed = True
        for binding in registry.bindings.values():
            if binding.status != "active":
                continue
            payload, _ = _read_private_file(
                self.material_root / binding.material_id,
                expected_uid=self.expected_authority_uid,
                allowed_modes={0o400},
                maximum_bytes=MAX_TEST_CREDENTIAL_BYTES,
                field="credential material",
            )
            if (
                len(payload) != binding.material_size_bytes
                or hashlib.sha256(payload).hexdigest()
                != binding.material_sha256
            ):
                raise TestStoreConflict("credential material changed")
        if removed:
            _fsync_directory(
                self.material_root,
                field="credential material directory",
            )

    def _cleanup_unpublished_material_unlocked(self, material_id: str) -> None:
        """Never remove material after an uncertain registry commit."""

        current = self._load_unlocked(allow_missing=True)
        if any(
            binding.material_id == material_id
            for binding in current.bindings.values()
        ):
            return
        self._remove_material_unlocked(material_id)

    def register(
        self,
        *,
        alias: str,
        repository_id: str,
        repository_generation: int,
        target_name: str,
        intent: str,
        owner_uid: int,
        credential_name: str,
        max_ttl_seconds: int,
        source_path: Path,
        source_key: str,
        source_uid: int,
    ) -> OperationalCredentialBinding:
        with self._locked(exclusive=True):
            registry = self._load_unlocked(allow_missing=True)
            self._reconcile_material_unlocked(registry)
            if alias in registry.bindings:
                raise TestStoreConflict("credential binding alias already exists")
            value, source_identity = self._import_source(
                source_path=source_path,
                source_key=source_key,
                source_uid=source_uid,
            )
            material_id, digest = self._new_material(value)
            try:
                binding = OperationalCredentialBinding(
                    alias=alias,
                    repository_id=repository_id,
                    repository_generation=repository_generation,
                    target_name=target_name,
                    intent=intent,
                    owner_uid=owner_uid,
                    credential_name=credential_name,
                    max_ttl_seconds=max_ttl_seconds,
                    rotation_generation=1,
                    status="active",
                    material_id=material_id,
                    material_sha256=digest,
                    material_size_bytes=len(value),
                    imported_at_epoch=int(self.clock()),
                    source_identity=source_identity,
                )
                replacement = self._publish(
                    registry, {**registry.bindings, alias: binding}
                )
            except Exception:
                self._cleanup_unpublished_material_unlocked(material_id)
                raise
            self._reconcile_material_unlocked(replacement)
            return binding

    def rotate(
        self,
        *,
        alias: str,
        expected_rotation_generation: int,
        source_path: Path,
        source_key: str,
        source_uid: int,
    ) -> OperationalCredentialBinding:
        with self._locked(exclusive=True):
            registry = self._load_unlocked(allow_missing=False)
            self._reconcile_material_unlocked(registry)
            existing = registry.bindings.get(alias)
            if existing is None:
                raise TestStoreConflict("credential binding alias is unknown")
            if existing.rotation_generation != expected_rotation_generation:
                raise TestStoreConflict("credential binding rotation generation changed")
            value, source_identity = self._import_source(
                source_path=source_path,
                source_key=source_key,
                source_uid=source_uid,
            )
            material_id, digest = self._new_material(value)
            try:
                replacement_binding = OperationalCredentialBinding(
                    **{
                        **existing.to_document(),
                        "rotation_generation": existing.rotation_generation + 1,
                        "status": "active",
                        "material_id": material_id,
                        "material_sha256": digest,
                        "material_size_bytes": len(value),
                        "imported_at_epoch": int(self.clock()),
                        "source_identity": source_identity,
                    }
                )
                replacement = self._publish(
                    registry,
                    {**registry.bindings, alias: replacement_binding},
                )
            except Exception:
                self._cleanup_unpublished_material_unlocked(material_id)
                raise
            self._reconcile_material_unlocked(replacement)
            return replacement_binding

    def revoke(
        self, *, alias: str, expected_rotation_generation: int
    ) -> OperationalCredentialBinding:
        with self._locked(exclusive=True):
            registry = self._load_unlocked(allow_missing=False)
            self._reconcile_material_unlocked(registry)
            existing = registry.bindings.get(alias)
            if existing is None:
                raise TestStoreConflict("credential binding alias is unknown")
            if existing.rotation_generation != expected_rotation_generation:
                raise TestStoreConflict("credential binding rotation generation changed")
            if existing.status == "revoked":
                return existing
            replacement_binding = OperationalCredentialBinding(
                **{**existing.to_document(), "status": "revoked"}
            )
            replacement = self._publish(
                registry, {**registry.bindings, alias: replacement_binding}
            )
            self._reconcile_material_unlocked(replacement)
            return replacement_binding


class BrokerOperationalCredentialProvider:
    """Resolve sealed bindings and publish one private attempt credential lease."""

    def __init__(
        self,
        *,
        registry_path: Path = DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH,
        material_root: Path = DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT,
        runtime_root: Path = DEFAULT_TEST_CREDENTIAL_RUNTIME_ROOT,
        expected_authority_uid: int = 0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = AdministratorOperationalCredentialStore(
            registry_path=registry_path,
            material_root=material_root,
            expected_authority_uid=expected_authority_uid,
            clock=clock,
        )
        self.runtime_root = Path(runtime_root)
        self.expected_authority_uid = expected_authority_uid
        if not self.runtime_root.is_absolute():
            raise TestStoreContractError("credential lease root must be absolute")

    def _runtime_directory(self, runtime_id: str) -> Path:
        if (
            not isinstance(runtime_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}", runtime_id)
            is None
            or "/" in runtime_id
        ):
            raise TestStoreContractError("credential lease runtime identity is invalid")
        return self.runtime_root / runtime_id

    @staticmethod
    def _binding_matches(
        binding: OperationalCredentialBinding,
        descriptor: TestAttemptDescriptor,
    ) -> bool:
        return (
            binding.status == "active"
            and binding.repository_id == descriptor.repository_id
            and binding.repository_generation == descriptor.repository_generation
            and binding.target_name == descriptor.target_name
            and binding.intent == descriptor.intent
            and binding.owner_uid == descriptor.owner_uid
            and descriptor.ttl_seconds <= binding.max_ttl_seconds
        )

    def _resolve(
        self,
        descriptor: TestAttemptDescriptor,
        registry: SealedOperationalCredentialRegistry,
    ) -> tuple[OperationalCredentialBinding, ...]:
        if not descriptor.credentials:
            raise TestStoreContractError("credential bindings are required")
        bindings: list[OperationalCredentialBinding] = []
        names: set[str] = set()
        for alias in descriptor.credentials:
            binding = registry.bindings.get(alias)
            if binding is None or not self._binding_matches(binding, descriptor):
                raise TestStoreConflict(
                    "operational credential binding is not authorized for this attempt"
                )
            if binding.credential_name in names:
                raise TestStoreConflict(
                    "operational credential destination name is duplicated"
                )
            names.add(binding.credential_name)
            bindings.append(binding)
        return tuple(bindings)

    def _material(self, binding: OperationalCredentialBinding) -> bytes:
        payload, _ = _read_private_file(
            self.store.material_root / binding.material_id,
            expected_uid=self.expected_authority_uid,
            allowed_modes={0o400},
            maximum_bytes=MAX_TEST_CREDENTIAL_BYTES,
            field="operational credential material",
        )
        if (
            len(payload) != binding.material_size_bytes
            or hashlib.sha256(payload).hexdigest() != binding.material_sha256
        ):
            raise TestStoreConflict("operational credential material changed")
        return payload

    def _state_path(self, runtime_id: str) -> Path:
        return self._runtime_directory(runtime_id) / "lease.json"

    def _prepared_state_path(self, runtime_id: str) -> Path:
        suffix = hashlib.sha256(runtime_id.encode("utf-8")).hexdigest()
        return self.runtime_root / f".lease-prepared-{suffix}.json"

    @staticmethod
    def _binding_documents(
        bindings: Sequence[OperationalCredentialBinding],
    ) -> list[dict[str, object]]:
        return [
            {
                "alias": binding.alias,
                "rotation_generation": binding.rotation_generation,
                "credential_name": binding.credential_name,
            }
            for binding in bindings
        ]

    def _credential_file_documents(
        self,
        *,
        runtime_id: str,
        bindings: Sequence[OperationalCredentialBinding],
    ) -> list[dict[str, object]]:
        directory = self._runtime_directory(runtime_id)
        files: list[dict[str, object]] = []
        for binding in bindings:
            opaque_name = "credential-" + hashlib.sha256(
                (
                    runtime_id
                    + "\x1f"
                    + binding.alias
                    + "\x1f"
                    + str(binding.rotation_generation)
                ).encode("utf-8")
            ).hexdigest()
            files.append(
                {
                    "name": binding.credential_name,
                    "source_path": str(directory / opaque_name),
                    "sha256": binding.material_sha256,
                    "size_bytes": binding.material_size_bytes,
                }
            )
        return files

    def _write_state(
        self,
        path: Path,
        *,
        phase: str,
        runtime_id: str,
        descriptor: TestAttemptDescriptor,
        bindings: Sequence[OperationalCredentialBinding],
        credential_files: Sequence[Mapping[str, object]],
        registry_fingerprint: str,
    ) -> None:
        if phase not in {"prepared", "active"}:
            raise TestStoreContractError("credential lease phase is invalid")
        state = {
            "schema_version": _LEASE_SCHEMA_VERSION,
            "phase": phase,
            "runtime_id": runtime_id,
            "descriptor_fingerprint": descriptor.fingerprint,
            "registry_fingerprint": registry_fingerprint,
            "bindings": self._binding_documents(bindings),
            "credential_files": [dict(item) for item in credential_files],
        }
        _atomic_private_json(
            path,
            state,
            expected_uid=self.expected_authority_uid,
        )

    def _read_state_path(
        self,
        path: Path,
        *,
        runtime_id: str,
        expected_phase: str,
    ) -> Mapping[str, object] | None:
        if _lstat_optional(path, field="credential lease state") is None:
            return None
        payload, _ = _read_private_file(
            path,
            expected_uid=self.expected_authority_uid,
            allowed_modes={0o600},
            maximum_bytes=256 * 1024,
            field="credential lease state",
        )
        try:
            state = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TestStoreContractError("credential lease state is invalid") from error
        required = {
            "schema_version",
            "phase",
            "runtime_id",
            "descriptor_fingerprint",
            "registry_fingerprint",
            "bindings",
            "credential_files",
        }
        if (
            not isinstance(state, Mapping)
            or set(state) != required
            or state["schema_version"] != _LEASE_SCHEMA_VERSION
            or state["phase"] != expected_phase
            or state["runtime_id"] != runtime_id
            or not isinstance(state["descriptor_fingerprint"], str)
            or _HEX_SHA256.fullmatch(state["descriptor_fingerprint"]) is None
            or not isinstance(state["registry_fingerprint"], str)
            or _HEX_SHA256.fullmatch(state["registry_fingerprint"]) is None
            or not isinstance(state["bindings"], list)
            or not isinstance(state["credential_files"], list)
        ):
            raise TestStoreContractError("credential lease state is invalid")
        try:
            lease = self._lease({**state, "phase": "active"})
        except (KeyError, TypeError, ValueError, TestStoreContractError) as error:
            raise TestStoreContractError("credential lease state is invalid") from error
        if (
            [item["credential_name"] for item in state["bindings"]]
            != [item["name"] for item in state["credential_files"]]
            or lease.descriptor_fingerprint != state["descriptor_fingerprint"]
        ):
            raise TestStoreContractError("credential lease state is invalid")
        return state

    def _read_state(self, runtime_id: str) -> Mapping[str, object] | None:
        return self._read_state_path(
            self._state_path(runtime_id),
            runtime_id=runtime_id,
            expected_phase="active",
        )

    def _read_prepared_state(
        self, runtime_id: str
    ) -> Mapping[str, object] | None:
        return self._read_state_path(
            self._prepared_state_path(runtime_id),
            runtime_id=runtime_id,
            expected_phase="prepared",
        )

    @staticmethod
    def _state_matches(
        state: Mapping[str, object],
        *,
        descriptor: TestAttemptDescriptor,
        bindings: Sequence[OperationalCredentialBinding],
        credential_files: Sequence[Mapping[str, object]],
    ) -> bool:
        return (
            state.get("descriptor_fingerprint") == descriptor.fingerprint
            and state.get("bindings")
            == BrokerOperationalCredentialProvider._binding_documents(bindings)
            and state.get("credential_files")
            == [dict(item) for item in credential_files]
        )

    def _lease(self, state: Mapping[str, object]) -> TestCredentialLease:
        if state.get("phase") != "active":
            raise TestStoreContractError("credential lease is not active")
        bindings = state["bindings"]
        files = state["credential_files"]
        if not isinstance(bindings, list) or not isinstance(files, list):
            raise TestStoreContractError("credential lease state is incomplete")
        if any(
            not isinstance(item, Mapping)
            or set(item) != {
                "alias",
                "rotation_generation",
                "credential_name",
            }
            for item in bindings
        ):
            raise TestStoreContractError("credential lease bindings are invalid")
        if any(not isinstance(item, Mapping) for item in files):
            raise TestStoreContractError("credential lease files are invalid")
        return TestCredentialLease(
            runtime_id=str(state["runtime_id"]),
            descriptor_fingerprint=str(state["descriptor_fingerprint"]),
            bindings=tuple(str(item["alias"]) for item in bindings),
            rotation_generations=tuple(
                item["rotation_generation"] for item in bindings
            ),
            credential_files=tuple(dict(item) for item in files),
        )

    def _remove_prepared_state(self, runtime_id: str) -> None:
        path = self._prepared_state_path(runtime_id)
        metadata = _lstat_optional(path, field="credential lease preparation")
        if metadata is None:
            return
        _require_regular_file("credential lease preparation", metadata)
        try:
            path.unlink()
        except OSError as error:
            raise TestStoreConflict(
                "credential lease preparation cannot be removed"
            ) from error
        _fsync_directory(
            self.runtime_root,
            field="credential lease root",
        )

    def _remove_runtime_directory(self, directory: Path) -> None:
        metadata = _lstat_optional(
            directory,
            field="credential lease directory",
        )
        if metadata is None:
            return
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise TestStoreConflict("credential lease directory is unsafe")
        for path in tuple(directory.iterdir()):
            item = path.lstat()
            if (
                not stat.S_ISREG(item.st_mode)
                or stat.S_ISLNK(item.st_mode)
                or (
                    path.name != "lease.json"
                    and _SAFE_LEASE_MATERIAL_NAME.fullmatch(path.name) is None
                )
            ):
                raise TestStoreConflict("credential lease material is unsafe")
        for path in tuple(directory.iterdir()):
            path.unlink()
        directory.rmdir()
        _fsync_directory(
            self.runtime_root,
            field="credential lease root",
        )

    def _validate_state_files(self, state: Mapping[str, object]) -> None:
        directory = self._runtime_directory(str(state["runtime_id"]))
        metadata = _lstat_optional(
            directory,
            field="credential lease directory",
        )
        if (
            metadata is None
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise TestStoreConflict("credential lease directory is unsafe")
        raw_files = state.get("credential_files")
        if not isinstance(raw_files, list):
            raise TestStoreContractError("credential lease files are invalid")
        expected_paths = {self._state_path(str(state["runtime_id"]))}
        for raw in raw_files:
            if not isinstance(raw, Mapping):
                raise TestStoreContractError("credential lease files are invalid")
            source = Path(str(raw.get("source_path")))
            if (
                source.parent != directory
                or _SAFE_LEASE_MATERIAL_NAME.fullmatch(source.name) is None
            ):
                raise TestStoreContractError("credential lease file path is invalid")
            payload, _ = _read_private_file(
                source,
                expected_uid=self.expected_authority_uid,
                allowed_modes={0o400},
                maximum_bytes=MAX_TEST_CREDENTIAL_BYTES,
                field="credential lease material",
            )
            if (
                len(payload) != raw.get("size_bytes")
                or hashlib.sha256(payload).hexdigest() != raw.get("sha256")
            ):
                raise TestStoreConflict("credential lease material changed")
            expected_paths.add(source)
        try:
            observed_paths = set(directory.iterdir())
        except OSError as error:
            raise TestStoreConflict(
                "credential lease directory is unavailable"
            ) from error
        if observed_paths != expected_paths:
            raise TestStoreConflict("credential lease directory is inconsistent")

    def _recover_prepared_state(
        self,
        *,
        runtime_id: str,
        state: Mapping[str, object],
    ) -> None:
        if state.get("runtime_id") != runtime_id:
            raise TestStoreContractError("credential lease preparation is invalid")
        self._remove_runtime_directory(self._runtime_directory(runtime_id))
        self._remove_prepared_state(runtime_id)

    def provision(
        self, descriptor: TestAttemptDescriptor, *, runtime_id: str
    ) -> TestCredentialLease:
        directory = self._runtime_directory(runtime_id)
        _require_private_directory(
            self.runtime_root,
            expected_uid=self.expected_authority_uid,
            create=True,
        )
        with self.store._locked(exclusive=False):
            registry = self.store._load_unlocked(allow_missing=False)
            bindings = self._resolve(descriptor, registry)
            credential_files = self._credential_file_documents(
                runtime_id=runtime_id,
                bindings=bindings,
            )
            state = self._read_state(runtime_id)
            prepared = self._read_prepared_state(runtime_id)
            if state is not None:
                if self._state_matches(
                    state,
                    descriptor=descriptor,
                    bindings=bindings,
                    credential_files=credential_files,
                ):
                    self._validate_state_files(state)
                    if prepared is not None:
                        if not self._state_matches(
                            prepared,
                            descriptor=descriptor,
                            bindings=bindings,
                            credential_files=credential_files,
                        ):
                            raise TestStoreConflict(
                                "credential lease preparation is inconsistent"
                            )
                        self._remove_prepared_state(runtime_id)
                    return self._lease(state)
                raise TestStoreConflict(
                    "credential lease runtime identity is already bound"
                )
            if prepared is not None:
                if prepared.get("descriptor_fingerprint") != descriptor.fingerprint:
                    raise TestStoreConflict(
                        "credential lease runtime identity is already bound"
                    )
                self._recover_prepared_state(
                    runtime_id=runtime_id,
                    state=prepared,
                )
            elif _lstat_optional(
                directory,
                field="credential lease directory",
            ) is not None:
                raise TestStoreConflict(
                    "credential lease directory has no preparation journal"
                )
            self._write_state(
                self._prepared_state_path(runtime_id),
                phase="prepared",
                runtime_id=runtime_id,
                descriptor=descriptor,
                bindings=bindings,
                credential_files=credential_files,
                registry_fingerprint=registry.fingerprint,
            )
            directory_created = False
            try:
                directory.mkdir(mode=0o700)
                directory_created = True
            except OSError as error:
                self._remove_prepared_state(runtime_id)
                raise TestStoreConflict(
                    "credential lease directory cannot be created"
                ) from error
            try:
                for binding, raw in zip(bindings, credential_files):
                    payload = self._material(binding)
                    source = Path(str(raw["source_path"]))
                    _write_new_private_file(
                        source,
                        payload,
                        mode=0o400,
                        expected_uid=self.expected_authority_uid,
                    )
                self._write_state(
                    self._state_path(runtime_id),
                    phase="active",
                    runtime_id=runtime_id,
                    descriptor=descriptor,
                    bindings=bindings,
                    credential_files=credential_files,
                    registry_fingerprint=registry.fingerprint,
                )
                state = self._read_state(runtime_id)
                if state is None:
                    raise TestStoreConflict("credential lease was not published")
                self._validate_state_files(state)
                self._remove_prepared_state(runtime_id)
                return self._lease(state)
            except Exception:
                if directory_created:
                    self._remove_runtime_directory(directory)
                self._remove_prepared_state(runtime_id)
                raise

    def recover(self, *, runtime_id: str) -> TestCredentialLease | None:
        self._runtime_directory(runtime_id)
        if _lstat_optional(
            self.runtime_root,
            field="credential lease root",
        ) is None:
            return None
        _require_private_directory(
            self.runtime_root,
            expected_uid=self.expected_authority_uid,
            create=False,
        )
        with self.store._locked(exclusive=False):
            state = self._read_state(runtime_id)
            prepared = self._read_prepared_state(runtime_id)
            if state is None:
                if prepared is not None:
                    self._recover_prepared_state(
                        runtime_id=runtime_id,
                        state=prepared,
                    )
                elif _lstat_optional(
                    self._runtime_directory(runtime_id),
                    field="credential lease directory",
                ) is not None:
                    raise TestStoreConflict(
                        "credential lease directory has no preparation journal"
                    )
                return None
            self._validate_state_files(state)
            if prepared is not None:
                if (
                    prepared.get("descriptor_fingerprint")
                    != state.get("descriptor_fingerprint")
                    or prepared.get("bindings") != state.get("bindings")
                    or prepared.get("credential_files")
                    != state.get("credential_files")
                ):
                    raise TestStoreConflict(
                        "credential lease preparation is inconsistent"
                    )
                self._remove_prepared_state(runtime_id)
            return self._lease(state)

    def recover_for_cleanup(self, *, runtime_id: str) -> TestCredentialLease | None:
        return self.recover(runtime_id=runtime_id)

    def cleanup(
        self, *, runtime_id: str, descriptor_fingerprint: str, reason: str
    ) -> None:
        del reason
        self._runtime_directory(runtime_id)
        if _lstat_optional(
            self.runtime_root,
            field="credential lease root",
        ) is None:
            return
        _require_private_directory(
            self.runtime_root,
            expected_uid=self.expected_authority_uid,
            create=False,
        )
        with self.store._locked(exclusive=False):
            state = self._read_state(runtime_id)
            prepared = self._read_prepared_state(runtime_id)
            fingerprints = {
                value["descriptor_fingerprint"]
                for value in (state, prepared)
                if value is not None
            }
            if fingerprints and fingerprints != {descriptor_fingerprint}:
                raise TestStoreConflict(
                    "credential lease descriptor fingerprint is stale"
                )
            if state is None and prepared is None:
                if _lstat_optional(
                    self._runtime_directory(runtime_id),
                    field="credential lease directory",
                ) is not None:
                    raise TestStoreConflict(
                        "credential lease directory has no preparation journal"
                    )
                return
            self._remove_runtime_directory(
                self._runtime_directory(runtime_id)
            )
            self._remove_prepared_state(runtime_id)

    def _validate_lease(
        self,
        descriptor: TestAttemptDescriptor,
        lease: TestCredentialLease,
        registry: SealedOperationalCredentialRegistry,
    ) -> None:
        bindings = self._resolve(descriptor, registry)
        if (
            lease.bindings != tuple(binding.alias for binding in bindings)
            or lease.rotation_generations
            != tuple(binding.rotation_generation for binding in bindings)
            or tuple(item["name"] for item in lease.credential_files)
            != tuple(binding.credential_name for binding in bindings)
        ):
            raise TestStoreConflict("operational credential lease became stale")
        for raw, binding in zip(lease.credential_files, bindings):
            payload, _ = _read_private_file(
                Path(str(raw["source_path"])),
                expected_uid=self.expected_authority_uid,
                allowed_modes={0o400},
                maximum_bytes=MAX_TEST_CREDENTIAL_BYTES,
                field="credential lease material",
            )
            if (
                len(payload) != binding.material_size_bytes
                or hashlib.sha256(payload).hexdigest()
                != binding.material_sha256
            ):
                raise TestStoreConflict("credential lease material changed")

    @contextmanager
    def launch_guard(
        self,
        descriptor: TestAttemptDescriptor,
        lease: TestCredentialLease,
    ) -> Iterator[None]:
        """Serialize rotate/revoke against the final systemd credential copy."""

        with self.store._locked(exclusive=False):
            registry = self.store._load_unlocked(allow_missing=False)
            self._validate_lease(descriptor, lease, registry)
            yield


def public_binding_document(
    binding: OperationalCredentialBinding,
) -> Mapping[str, object]:
    """Return a path-, digest-, and secret-free administrator result."""

    return MappingProxyType(
        {
            "alias": binding.alias,
            "repository_id": binding.repository_id,
            "repository_generation": binding.repository_generation,
            "target_name": binding.target_name,
            "intent": binding.intent,
            "owner_uid": binding.owner_uid,
            "credential_name": binding.credential_name,
            "max_ttl_seconds": binding.max_ttl_seconds,
            "rotation_generation": binding.rotation_generation,
            "status": binding.status,
        }
    )


__all__ = [
    "AdministratorOperationalCredentialStore",
    "BrokerOperationalCredentialProvider",
    "DEFAULT_TEST_CREDENTIAL_MATERIAL_ROOT",
    "DEFAULT_TEST_CREDENTIAL_REGISTRY_PATH",
    "DEFAULT_TEST_CREDENTIAL_RUNTIME_ROOT",
    "OperationalCredentialBinding",
    "SealedOperationalCredentialRegistry",
    "public_binding_document",
]
