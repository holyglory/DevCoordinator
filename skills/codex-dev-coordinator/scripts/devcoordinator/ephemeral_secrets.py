"""Volatile broker-owned material for narrowly typed ephemeral credentials.

This module deliberately keeps password bytes out of broker SQLite state,
profiles, logs, command arguments, and ordinary environment values.  The
broker creates a root-owned runtime file only after an accepted run has a
durable identity, mounts its material directory read-only into that one
container, and can release one read-only copy to its exact owning runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from typing import Any, Callable
import uuid


POSTGRES_INITDB_PASSWORD_FILE_V1 = "postgres_initdb_password_file_v1"
_SUPPORTED_POLICIES = frozenset({POSTGRES_INITDB_PASSWORD_FILE_V1})
_RUNTIME_STATE_VERSION = 1
_MATERIAL_DIRECTORY_NAME = "material"
_PASSWORD_FILENAME = "postgres-initdb-password"
_STATE_FILENAME = "state.json"
_CONTAINER_DIRECTORY = "/run/devcoordinator-credentials"
_MAX_ACCOUNT_ID_BYTES = 256
_MAX_IDENTIFIER_BYTES = 512


class EphemeralSecretError(RuntimeError):
    """Base failure for volatile credential lifecycle enforcement."""


class SecretGrantDenied(EphemeralSecretError):
    """The supplied principal/run binding does not match material state."""


class SecretGrantExpired(EphemeralSecretError):
    """The material has passed its run-bound expiry."""


class SecretGrantReplay(EphemeralSecretError):
    """A runner credential retrieval was already consumed once."""


class SecretGrantNotFound(EphemeralSecretError):
    """No volatile material is available for the exact run."""


@dataclass(frozen=True)
class EphemeralSecretPolicy:
    """Public, non-secret policy and opaque binding for one template."""

    kind: str
    binding_id: str

    def __post_init__(self) -> None:
        normalized_kind = normalize_ephemeral_secret_policy(self.kind)
        if normalized_kind is None:
            raise ValueError("ephemeral secret policy is required")
        object.__setattr__(self, "kind", normalized_kind)
        object.__setattr__(
            self,
            "binding_id",
            _canonical_uuid(self.binding_id, field="secret binding id"),
        )


@dataclass(frozen=True)
class EphemeralSecretMount:
    """Broker-internal bind-mount descriptor; it contains no password bytes."""

    policy: EphemeralSecretPolicy
    source_directory: Path = field(repr=False)
    container_directory: str = _CONTAINER_DIRECTORY
    filename: str = _PASSWORD_FILENAME

    @property
    def container_password_path(self) -> str:
        return self.container_directory + "/" + self.filename

    @property
    def environment(self) -> tuple[tuple[str, str], ...]:
        return (("POSTGRES_PASSWORD_FILE", self.container_password_path),)


@dataclass(frozen=True, repr=False)
class EphemeralSecretMaterial:
    """One runner delivery payload; bytes are intentionally redacted in repr."""

    value: bytes
    expires_at_epoch: int
    request_id: uuid.UUID

    def __repr__(self) -> str:
        return (
            "EphemeralSecretMaterial("
            f"expires_at_epoch={self.expires_at_epoch!r}, "
            f"request_id={str(self.request_id)!r}, value=<redacted>)"
        )


def normalize_ephemeral_secret_policy(value: Any) -> str | None:
    """Accept exactly the currently reviewed non-secret policy vocabulary."""

    if value is None:
        return None
    if not isinstance(value, str) or value not in _SUPPORTED_POLICIES:
        raise ValueError("ephemeral secret policy is unsupported")
    return value


def deterministic_secret_binding_id(
    *, repository_id: str, template_id: str, policy: str
) -> str:
    """Return an opaque stable ID without treating it as a credential."""

    normalized_policy = normalize_ephemeral_secret_policy(policy)
    if normalized_policy is None:
        raise ValueError("ephemeral secret policy is required")
    _bounded_identifier(repository_id, field="repository id")
    _bounded_identifier(template_id, field="template id")
    material = "\x1f".join(
        (
            "devcoordinator-ephemeral-secret-binding-v1",
            repository_id,
            template_id,
            normalized_policy,
        )
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, material))


class VolatileRunSecretManager:
    """Root-owned, runtime-only secret material manager.

    The manager stores only an opaque policy/binding and one consumed-request
    tombstone alongside the password in a private runtime directory.  That
    state is deliberately outside SQLite and outside every client profile; it
    survives a broker process restart on the same host solely so a running
    container can be recovered or its credential can be delivered exactly
    once.  A host reboot clears the runtime root and the broker fails closed.
    """

    def __init__(
        self,
        *,
        runtime_root: str | os.PathLike[str] = "/run/devcoordinator/ephemeral-secrets",
        expected_uid: int | None = None,
        clock: Callable[[], float] = time.time,
        password_factory: Callable[[], bytes] | None = None,
    ) -> None:
        root = Path(runtime_root)
        if not root.is_absolute():
            raise ValueError("ephemeral secret runtime root must be absolute")
        self._root = root
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        if type(self._expected_uid) is not int or self._expected_uid < 0:
            raise ValueError("ephemeral secret expected uid is invalid")
        self._clock = clock
        self._password_factory = password_factory or _new_password
        self._lock = threading.RLock()

    @property
    def runtime_root(self) -> Path:
        """Return the private runtime root without exposing material paths."""

        return self._root

    def provision_for_start(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        expires_at_epoch: int,
        now_epoch: int | None = None,
    ) -> EphemeralSecretMount:
        """Generate one password after durable start admission, or reuse it.

        This is broker-internal only.  No client or protocol surface may call
        it with bytes; the manager creates the password itself.
        """

        now = self._now(now_epoch)
        identity = _MaterialIdentity.build(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            expires_at_epoch=expires_at_epoch,
        )
        if identity.expires_at_epoch <= now:
            raise SecretGrantExpired("ephemeral credential run has already expired")
        with self._lock:
            self._ensure_root()
            state_path = self._state_path(identity.run_id)
            if state_path.exists():
                state = self._read_state(state_path)
                self._require_identity(state, identity, now=now)
                self._require_password_file(identity.run_id)
                return self._mount(identity)
            self._write_new_material(identity)
            return self._mount(identity)

    def mount_for_run(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        expires_at_epoch: int,
        now_epoch: int | None = None,
        require_material: bool,
    ) -> EphemeralSecretMount:
        """Resolve a previously provisioned descriptor for create/recovery.

        ``require_material=False`` is deliberately limited to Docker identity
        and cleanup inspection: it yields the deterministic expected mount
        shape but never permits a fresh start with a missing source file.
        """

        now = self._now(now_epoch)
        identity = _MaterialIdentity.build(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            expires_at_epoch=expires_at_epoch,
        )
        with self._lock:
            if not require_material:
                # Cleanup and exact Docker identity inspection must remain
                # possible after reboot, tampering, or an interrupted expiry
                # transition. The deterministic path carries no password and
                # cannot authorize a new start or descriptor delivery.
                return self._mount(identity)
            state_path = self._state_path(identity.run_id)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            self._require_identity(state, identity, now=now)
            if self._expiry_renewal_transition(state) is not None:
                raise SecretGrantDenied("ephemeral credential renewal is unresolved")
            self._require_password_file(identity.run_id)
            return self._mount(identity)

    def prepare_expiry_renewal(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
        now_epoch: int | None = None,
    ) -> None:
        """Durably record a pending expiry change while old expiry stays effective."""

        now = self._now(now_epoch)
        old, new = self._renewal_identities(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            old_expires_at_epoch=old_expires_at_epoch,
            new_expires_at_epoch=new_expires_at_epoch,
        )
        if old.expires_at_epoch <= now or new.expires_at_epoch <= now:
            raise SecretGrantExpired("ephemeral credential renewal is already expired")
        with self._lock:
            state_path = self._state_path(old.run_id)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            self._require_identity_binding(state, old)
            self._require_password_file(old.run_id)
            expected = (old.expires_at_epoch, new.expires_at_epoch)
            existing = self._expiry_renewal_transition(state)
            if existing is not None and existing != expected:
                raise SecretGrantDenied(
                    "ephemeral credential renewal conflicts with retained state"
                )
            if existing is None:
                state["expiry_renewal"] = {
                    "old_expires_at_epoch": old.expires_at_epoch,
                    "new_expires_at_epoch": new.expires_at_epoch,
                }
                self._write_state(state_path, state)

    def commit_expiry_renewal(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
        now_epoch: int | None = None,
    ) -> None:
        """Make a previously journaled expiry transition effective."""

        now = self._now(now_epoch)
        old, new = self._renewal_identities(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            old_expires_at_epoch=old_expires_at_epoch,
            new_expires_at_epoch=new_expires_at_epoch,
        )
        if new.expires_at_epoch <= now:
            raise SecretGrantExpired("ephemeral credential renewal is already expired")
        with self._lock:
            state_path = self._state_path(old.run_id)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            self._require_identity_binding(state, old)
            self._require_password_file(old.run_id)
            if self._expiry_renewal_transition(state) != (
                old.expires_at_epoch,
                new.expires_at_epoch,
            ):
                raise SecretGrantDenied(
                    "ephemeral credential renewal transition is unavailable"
                )
            state["expires_at_epoch"] = new.expires_at_epoch
            state.pop("expiry_renewal", None)
            self._write_state(state_path, state)

    def rollback_expiry_renewal(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
    ) -> None:
        """Discard one durable pending transition without changing expiry."""

        old, new = self._renewal_identities(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            old_expires_at_epoch=old_expires_at_epoch,
            new_expires_at_epoch=new_expires_at_epoch,
        )
        with self._lock:
            state_path = self._state_path(old.run_id)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            self._require_identity_binding(state, old)
            self._require_password_file(old.run_id)
            if self._expiry_renewal_transition(state) != (
                old.expires_at_epoch,
                new.expires_at_epoch,
            ):
                raise SecretGrantDenied(
                    "ephemeral credential renewal transition is unavailable"
                )
            state.pop("expiry_renewal", None)
            self._write_state(state_path, state)

    def inspect_expiry_renewal(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
    ) -> str:
        """Return only a non-secret recovery state for one expected renewal."""

        old, new = self._renewal_identities(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            old_expires_at_epoch=old_expires_at_epoch,
            new_expires_at_epoch=new_expires_at_epoch,
        )
        with self._lock:
            state_path = self._state_path(old.run_id)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            self._require_password_file(old.run_id)
            actual = _MaterialIdentity.from_state(state)
            transition = self._expiry_renewal_transition(state)
            expected = (old.expires_at_epoch, new.expires_at_epoch)
            if actual == old:
                if transition is None:
                    return "old"
                if transition == expected:
                    return "prepared"
            if actual == new and transition is None:
                return "new"
            raise SecretGrantDenied("ephemeral credential renewal state is invalid")

    def consume_run_secret(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        request_id: uuid.UUID,
        now_epoch: int | None = None,
    ) -> EphemeralSecretMaterial:
        """Atomically consume one runner-delivery grant for an exact run."""

        now = self._now(now_epoch)
        run = _canonical_uuid(run_id, field="run id")
        request = _as_uuid(request_id, field="secret request id")
        with self._lock:
            state_path = self._state_path(run)
            if not state_path.exists():
                raise SecretGrantNotFound(
                    "ephemeral credential material is unavailable for this run"
                )
            state = self._read_state(state_path)
            identity = _MaterialIdentity.from_state(state)
            if self._expiry_renewal_transition(state) is not None:
                raise SecretGrantDenied(
                    "ephemeral credential renewal is unresolved"
                )
            self._require_identity(
                state,
                identity.with_request(
                    peer_uid=peer_uid,
                    account_id=account_id,
                    repository_id=repository_id,
                    template_id=template_id,
                    run_id=run,
                ),
                now=now,
            )
            consumed = state.get("consumed_request_id")
            if consumed is not None:
                raise SecretGrantReplay(
                    "the runner credential delivery was already consumed; do not retry"
                )
            value = self._read_password(run)
            state["consumed_request_id"] = str(request)
            self._write_state(state_path, state)
            return EphemeralSecretMaterial(
                value=value,
                expires_at_epoch=identity.expires_at_epoch,
                request_id=request,
            )

    def release_run_secret(self, *, run_id: uuid.UUID) -> None:
        """Remove exactly one private runtime material tree after Docker absence."""

        run = _canonical_uuid(run_id, field="run id")
        with self._lock:
            run_directory = self._run_directory(run)
            if not run_directory.exists():
                return
            self._require_private_directory(run_directory)
            material = run_directory / _MATERIAL_DIRECTORY_NAME
            state = run_directory / _STATE_FILENAME
            if material.exists():
                self._require_private_directory(material)
                password = material / _PASSWORD_FILENAME
                if password.exists():
                    self._require_private_file(password, mode=0o400)
                    password.unlink()
                unexpected = tuple(material.iterdir())
                if unexpected:
                    raise SecretGrantDenied(
                        "ephemeral secret material directory has unexpected entries"
                    )
                material.rmdir()
            if state.exists():
                self._require_private_file(state, mode=0o600)
                state.unlink()
            unexpected_root = tuple(run_directory.iterdir())
            if unexpected_root:
                raise SecretGrantDenied(
                    "ephemeral secret runtime directory has unexpected entries"
                )
            run_directory.rmdir()

    def _write_new_material(self, identity: "_MaterialIdentity") -> None:
        run_directory = self._run_directory(identity.run_id)
        if run_directory.exists():
            raise SecretGrantDenied("ephemeral secret runtime identity already exists")
        run_directory.mkdir(mode=0o700)
        try:
            self._require_private_directory(run_directory)
            material = run_directory / _MATERIAL_DIRECTORY_NAME
            material.mkdir(mode=0o700)
            self._require_private_directory(material)
            password = _validate_password(self._password_factory())
            self._write_password(material / _PASSWORD_FILENAME, password)
            self._write_state(
                run_directory / _STATE_FILENAME,
                {
                    "version": _RUNTIME_STATE_VERSION,
                    **identity.to_state(),
                    "consumed_request_id": None,
                },
            )
            _fsync_directory(material)
            _fsync_directory(run_directory)
            _fsync_directory(self._root)
        except BaseException:
            try:
                self.release_run_secret(run_id=uuid.UUID(identity.run_id))
            except BaseException:
                pass
            raise

    def _ensure_root(self) -> None:
        if self._root.exists():
            self._require_private_directory(self._root)
            return
        parent = self._root.parent
        if not parent.exists():
            raise SecretGrantNotFound(
                "ephemeral secret runtime parent is unavailable"
            )
        self._require_runtime_parent(parent)
        self._root.mkdir(mode=0o700)
        self._require_private_directory(self._root)

    def _read_state(self, path: Path) -> dict[str, Any]:
        self._require_private_file(path, mode=0o600)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise SecretGrantNotFound(
                "ephemeral credential runtime state cannot be read"
            ) from exc
        if len(payload) > 16 * 1024:
            raise SecretGrantDenied("ephemeral credential runtime state is oversized")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretGrantDenied("ephemeral credential runtime state is invalid") from exc
        if not isinstance(value, dict):
            raise SecretGrantDenied("ephemeral credential runtime state is invalid")
        return value

    def _write_state(self, path: Path, value: dict[str, Any]) -> None:
        encoded = json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(encoded) > 16 * 1024:
            raise SecretGrantDenied("ephemeral credential runtime state is oversized")
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists():
            raise SecretGrantDenied("ephemeral credential runtime state temp exists")
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if path.exists():
                self._require_private_file(path, mode=0o600)
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            self._require_private_file(path, mode=0o600)
            _fsync_directory(path.parent)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary.exists():
                temporary.unlink()

    def _write_password(self, path: Path, value: bytes) -> None:
        descriptor = -1
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o400)
            _write_all(descriptor, value)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            self._require_private_file(path, mode=0o400)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _read_password(self, run_id: str) -> bytes:
        path = self._password_path(run_id)
        self._require_private_file(path, mode=0o400)
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            value = os.read(descriptor, 512)
            if os.read(descriptor, 1):
                raise SecretGrantDenied("ephemeral credential material is oversized")
            return _validate_password(value)
        except OSError as exc:
            raise SecretGrantNotFound(
                "ephemeral credential material cannot be read"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _require_password_file(self, run_id: str) -> None:
        self._require_private_file(self._password_path(run_id), mode=0o400)

    def _require_identity(
        self, state: dict[str, Any], identity: "_MaterialIdentity", *, now: int
    ) -> None:
        actual = _MaterialIdentity.from_state(state)
        if actual != identity:
            raise SecretGrantDenied("ephemeral credential binding does not match")
        if actual.expires_at_epoch <= now:
            raise SecretGrantExpired("ephemeral credential run has expired")

    def _renewal_identities(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        old_expires_at_epoch: int,
        new_expires_at_epoch: int,
    ) -> tuple["_MaterialIdentity", "_MaterialIdentity"]:
        old = _MaterialIdentity.build(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            expires_at_epoch=old_expires_at_epoch,
        )
        new = _MaterialIdentity.build(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=run_id,
            policy=policy,
            expires_at_epoch=new_expires_at_epoch,
        )
        if old.expires_at_epoch == new.expires_at_epoch:
            raise SecretGrantDenied("ephemeral credential renewal has no expiry change")
        return old, new

    def _require_identity_binding(
        self, state: dict[str, Any], identity: "_MaterialIdentity"
    ) -> None:
        if _MaterialIdentity.from_state(state) != identity:
            raise SecretGrantDenied("ephemeral credential binding does not match")

    @staticmethod
    def _expiry_renewal_transition(
        state: dict[str, Any],
    ) -> tuple[int, int] | None:
        raw = state.get("expiry_renewal")
        if raw is None:
            return None
        if (
            not isinstance(raw, dict)
            or set(raw) != {"old_expires_at_epoch", "new_expires_at_epoch"}
            or type(raw["old_expires_at_epoch"]) is not int
            or type(raw["new_expires_at_epoch"]) is not int
            or raw["old_expires_at_epoch"] <= 0
            or raw["new_expires_at_epoch"] <= 0
            or raw["old_expires_at_epoch"] == raw["new_expires_at_epoch"]
        ):
            raise SecretGrantDenied("ephemeral credential renewal state is invalid")
        return (raw["old_expires_at_epoch"], raw["new_expires_at_epoch"])

    def _mount(self, identity: "_MaterialIdentity") -> EphemeralSecretMount:
        return EphemeralSecretMount(
            policy=identity.policy,
            source_directory=self._material_directory(identity.run_id),
        )

    def _run_directory(self, run_id: str) -> Path:
        return self._root / run_id

    def _material_directory(self, run_id: str) -> Path:
        return self._run_directory(run_id) / _MATERIAL_DIRECTORY_NAME

    def _password_path(self, run_id: str) -> Path:
        return self._material_directory(run_id) / _PASSWORD_FILENAME

    def _state_path(self, run_id: str) -> Path:
        return self._run_directory(run_id) / _STATE_FILENAME

    def _require_private_directory(self, path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SecretGrantNotFound("ephemeral credential runtime directory is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise SecretGrantDenied("ephemeral credential runtime directory is unsafe")

    def _require_runtime_parent(self, path: Path) -> None:
        """Accept one real runtime parent without treating metadata as auth."""

        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SecretGrantNotFound("ephemeral credential runtime parent is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise SecretGrantDenied("ephemeral credential runtime parent is unsafe")

    def _require_private_file(self, path: Path, *, mode: int) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SecretGrantNotFound("ephemeral credential material is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
        ):
            raise SecretGrantDenied("ephemeral credential material is unsafe")

    def _now(self, supplied: int | None) -> int:
        now = int(self._clock()) if supplied is None else supplied
        if type(now) is not int or now < 0:
            raise ValueError("ephemeral credential clock is invalid")
        return now


@dataclass(frozen=True)
class _MaterialIdentity:
    peer_uid: int
    account_id: str
    repository_id: str
    template_id: str
    run_id: str
    policy: EphemeralSecretPolicy
    expires_at_epoch: int

    @classmethod
    def build(
        cls,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: uuid.UUID,
        policy: EphemeralSecretPolicy,
        expires_at_epoch: int,
    ) -> "_MaterialIdentity":
        if type(peer_uid) is not int or peer_uid < 0:
            raise ValueError("ephemeral secret peer uid is invalid")
        account = _bounded_identifier(account_id, field="account id", maximum=_MAX_ACCOUNT_ID_BYTES)
        repository = _bounded_identifier(repository_id, field="repository id")
        template = _bounded_identifier(template_id, field="template id")
        if not isinstance(policy, EphemeralSecretPolicy):
            raise TypeError("ephemeral secret policy must be typed")
        run = _canonical_uuid(run_id, field="run id")
        if type(expires_at_epoch) is not int or expires_at_epoch <= 0:
            raise ValueError("ephemeral secret expiry is invalid")
        return cls(
            peer_uid=peer_uid,
            account_id=account,
            repository_id=repository,
            template_id=template,
            run_id=run,
            policy=policy,
            expires_at_epoch=expires_at_epoch,
        )

    @classmethod
    def from_state(cls, value: dict[str, Any]) -> "_MaterialIdentity":
        if value.get("version") != _RUNTIME_STATE_VERSION:
            raise SecretGrantDenied("ephemeral credential runtime state version is invalid")
        policy = EphemeralSecretPolicy(
            kind=value.get("policy"), binding_id=value.get("binding_id")
        )
        run = _as_uuid(value.get("run_id"), field="run id")
        return cls.build(
            peer_uid=value.get("peer_uid"),
            account_id=value.get("account_id"),
            repository_id=value.get("repository_id"),
            template_id=value.get("template_id"),
            run_id=run,
            policy=policy,
            expires_at_epoch=value.get("expires_at_epoch"),
        )

    def with_request(
        self,
        *,
        peer_uid: int,
        account_id: str,
        repository_id: str,
        template_id: str,
        run_id: str,
    ) -> "_MaterialIdentity":
        return _MaterialIdentity.build(
            peer_uid=peer_uid,
            account_id=account_id,
            repository_id=repository_id,
            template_id=template_id,
            run_id=_as_uuid(run_id, field="run id"),
            policy=self.policy,
            expires_at_epoch=self.expires_at_epoch,
        )

    def to_state(self) -> dict[str, Any]:
        return {
            "peer_uid": self.peer_uid,
            "account_id": self.account_id,
            "repository_id": self.repository_id,
            "template_id": self.template_id,
            "run_id": self.run_id,
            "policy": self.policy.kind,
            "binding_id": self.policy.binding_id,
            "expires_at_epoch": self.expires_at_epoch,
        }


def _new_password() -> bytes:
    return secrets.token_urlsafe(48).encode("ascii")


def _validate_password(value: Any) -> bytes:
    if (
        not isinstance(value, bytes)
        or not 32 <= len(value) <= 256
        or any(byte < 33 or byte > 126 for byte in value)
    ):
        raise SecretGrantDenied("broker-generated PostgreSQL password is invalid")
    return value


def _canonical_uuid(value: Any, *, field: str) -> str:
    return str(_as_uuid(value, field=field))


def _as_uuid(value: Any, *, field: str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    if not isinstance(value, str):
        raise ValueError(f"ephemeral secret {field} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"ephemeral secret {field} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"ephemeral secret {field} must be a canonical UUID")
    return parsed


def _bounded_identifier(value: Any, *, field: str, maximum: int = _MAX_IDENTIFIER_BYTES) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"ephemeral secret {field} is invalid")
    return value


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("ephemeral secret write made no progress")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
