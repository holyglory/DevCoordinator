"""Durable broker-owned sealed fixture provider for universal-test attempts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import time
from typing import Any, Mapping
import uuid

from .broker import BrokerBackendError, BrokerError
from .broker_host import (
    EphemeralDockerContainerTarget,
    EphemeralDockerCreateTarget,
    EphemeralDockerIdentity,
)
from .broker_persistence import (
    BrokerPersistence,
    EphemeralImageTarget,
    SealedTestFixtureTemplate,
    _normalize_ephemeral_image_cache_proof,
)
from .ephemeral_secrets import EphemeralSecretError, VolatileRunSecretManager
from .universal_test_runtime import (
    TEST_ATTEMPT_ACCOUNT_ID,
    TestAttemptDescriptor,
    TestFixtureLease,
)
from .universal_test_store import TestStoreConflict, TestStoreContractError


_RUNTIME_ID = re.compile(r"^devcoordinator-test-[0-9a-f]{32}$")
_FULL_ID = re.compile(r"^[0-9a-f]{64}$")
_MAX_FIXTURES = 8
_MAX_FIXTURE_MEMORY = 8 * 1024 * 1024 * 1024
_MAX_FIXTURE_CPU_MILLIS = 8_000


class BrokerSealedFixtureProvider:
    """Provision exact sealed containers with a restart-durable cleanup journal."""

    def __init__(
        self,
        persistence: BrokerPersistence,
        host: Any,
        *,
        secret_manager: VolatileRunSecretManager,
        state_root: Path = Path("/var/lib/devcoordinator-test-fixtures"),
        credential_root: Path = Path("/run/devcoordinator/test-fixture-credentials"),
        clock: Any = time.time,
        reaper_interval_seconds: float = 15.0,
    ) -> None:
        if not isinstance(persistence, BrokerPersistence):
            raise TypeError("fixture provider persistence is invalid")
        if not isinstance(secret_manager, VolatileRunSecretManager):
            raise TypeError("fixture provider secret manager is invalid")
        if not state_root.is_absolute() or not credential_root.is_absolute():
            raise ValueError("fixture provider roots must be absolute")
        self.persistence = persistence
        self.host = host
        self.secret_manager = secret_manager
        self.state_root = state_root
        self.credential_root = credential_root
        self.clock = clock
        self.reaper_interval_seconds = float(reaper_interval_seconds)
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def _runtime(runtime_id: str) -> str:
        if not isinstance(runtime_id, str) or _RUNTIME_ID.fullmatch(runtime_id) is None:
            raise TestStoreContractError("fixture runtime identity is invalid")
        return runtime_id

    def _ensure_root(self, root: Path) -> None:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.lstat()
        if (
            root.resolve(strict=True) != root
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
        ):
            raise TestStoreConflict("fixture provider root is unsafe")

    def _state_path(self, runtime_id: str) -> Path:
        return self.state_root / (self._runtime(runtime_id) + ".json")

    def _write_state(self, state: Mapping[str, object]) -> None:
        runtime_id = self._runtime(str(state.get("runtime_id")))
        payload = json.dumps(
            state, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
        if len(payload) > 512 * 1024:
            raise TestStoreContractError("fixture journal exceeds its bound")
        self._ensure_root(self.state_root)
        destination = self._state_path(runtime_id)
        descriptor, name = tempfile.mkstemp(prefix=".fixture-", dir=self.state_root)
        stage = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(stage, destination)
            directory = os.open(
                self.state_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            stage.unlink(missing_ok=True)

    def _read_state(self, runtime_id: str) -> dict[str, object] | None:
        path = self._state_path(runtime_id)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > 512 * 1024
        ):
            raise TestStoreConflict("fixture journal is unsafe")
        try:
            value = json.loads(path.read_bytes())
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TestStoreConflict("fixture journal is invalid") from error
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 2
            or value.get("runtime_id") != runtime_id
        ):
            raise TestStoreConflict("fixture journal identity is invalid")
        return value

    @staticmethod
    def _identity(raw: Mapping[str, object]) -> EphemeralDockerIdentity:
        return EphemeralDockerIdentity(
            run_id=str(raw["run_uuid"]),
            creation_nonce=str(raw["creation_nonce"]),
            repository_id=str(raw["repository_id"]),
            template_id=str(raw["template_id"]),
            definition_fingerprint=str(raw["template_fingerprint"]),
        )

    def _secret_mount(self, raw: Mapping[str, object], *, require_material: bool):
        policy = raw.get("secret_policy")
        if policy is None:
            return None
        from .ephemeral_secrets import EphemeralSecretPolicy

        if not isinstance(policy, Mapping) or set(policy) != {"kind", "binding_id"}:
            raise TestStoreConflict("fixture secret policy journal is invalid")
        try:
            return self.secret_manager.mount_for_run(
                peer_uid=int(raw["owner_uid"]),
                account_id=TEST_ATTEMPT_ACCOUNT_ID,
                repository_id=str(raw["repository_id"]),
                template_id=str(raw["template_id"]),
                run_id=uuid.UUID(str(raw["run_uuid"])),
                policy=EphemeralSecretPolicy(
                    kind=str(policy["kind"]), binding_id=str(policy["binding_id"])
                ),
                expires_at_epoch=int(raw["expires_at_epoch"]),
                require_material=require_material,
            )
        except (EphemeralSecretError, ValueError, KeyError) as error:
            raise TestStoreConflict("fixture secret material is unavailable") from error

    def _container_target(self, raw: Mapping[str, object], *, require_material: bool) -> EphemeralDockerContainerTarget:
        full_id = raw.get("full_container_id")
        if not isinstance(full_id, str) or _FULL_ID.fullmatch(full_id) is None:
            raise TestStoreConflict("fixture container identity is unavailable")
        anchor = raw.get("network_container_id")
        if anchor is not None and (not isinstance(anchor, str) or _FULL_ID.fullmatch(anchor) is None):
            raise TestStoreConflict("fixture network anchor identity is invalid")
        return EphemeralDockerContainerTarget(
            identity=self._identity(raw),
            full_container_id=full_id,
            secret_mount=self._secret_mount(raw, require_material=require_material),
            image_ref=str(raw["image_ref"]),
            network_container_id=anchor,
        )

    @staticmethod
    def _container_name(template: SealedTestFixtureTemplate, run_uuid: str) -> str:
        slug = re.sub(r"[^a-z0-9_.-]+", "-", template.name.lower()).strip("-.")
        slug = (slug or "fixture")[:48].rstrip("-.")
        return f"devcoordinator-{slug}-{uuid.UUID(run_uuid).hex}"

    def _fixture_record(
        self,
        descriptor: TestAttemptDescriptor,
        binding: Mapping[str, object],
        *,
        runtime_id: str,
        ordinal: int,
        expires: int,
    ) -> dict[str, object]:
        template = self.persistence.sealed_test_fixture_template(
            repo_id=descriptor.repository_id,
            owner_uid=descriptor.owner_uid,
            repository_generation=descriptor.repository_generation,
            template=str(binding["template"]),
            operation_id=descriptor.execution_id,
        )
        run_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "devcoordinator-test-fixture-v1\x1f"
                + runtime_id
                + "\x1f"
                + str(binding["name"]),
            )
        )
        secret_policy = (
            None
            if template.secret_policy is None
            else {
                "kind": template.secret_policy.kind,
                "binding_id": template.secret_policy.binding_id,
            }
        )
        return {
            "name": binding["name"],
            "requested_template": binding["template"],
            "network": binding["network"],
            "ordinal": ordinal,
            "run_uuid": run_uuid,
            "creation_nonce": str(uuid.uuid4()),
            "repository_id": descriptor.repository_id,
            "repository_generation": descriptor.repository_generation,
            "owner_uid": descriptor.owner_uid,
            "template_id": template.template_id,
            "template_fingerprint": template.definition_fingerprint,
            "image_ref": template.image_ref,
            "command": list(template.command),
            "environment": [list(item) for item in template.environment],
            "secret_policy": secret_policy,
            "container_tcp_port": template.container_tcp_port,
            "memory_bytes": template.memory_bytes,
            "cpu_millis": template.cpu_millis,
            "expires_at_epoch": min(expires, int(self.clock()) + template.max_ttl_seconds),
            "container_name": self._container_name(template, run_uuid),
            "network_container_id": None,
            "full_container_id": None,
            "status": "reserved",
        }

    def _create_or_recover(self, state: dict[str, object], ordinal: int) -> None:
        fixtures = state["fixtures"]
        if not isinstance(fixtures, list) or not isinstance(fixtures[ordinal], dict):
            raise TestStoreConflict("fixture journal entries are invalid")
        raw = fixtures[ordinal]
        identity = self._identity(raw)
        full_id = raw.get("full_container_id")
        if full_id is None:
            found = self.host.docker_find_ephemeral(identity)
            if found.get("found") is True:
                full_id = found.get("full_container_id")
            else:
                image_target = EphemeralImageTarget(
                    template_id=str(raw["template_id"]),
                    repo_id=str(raw["repository_id"]),
                    image_ref=str(raw["image_ref"]),
                    template_fingerprint=str(raw["template_fingerprint"]),
                )
                image = self.host.docker_inspect_ephemeral_image(
                    image_target
                )
                if not isinstance(image, Mapping):
                    raise TestStoreConflict("sealed fixture image cache is unobservable")
                if image.get("cached") is not True:
                    prefetch = getattr(
                        self.host, "docker_prefetch_ephemeral_image", None
                    )
                    if not callable(prefetch):
                        raise TestStoreConflict(
                            "sealed fixture image prefetch is unavailable"
                        )
                    image = prefetch(image_target)
                    if not isinstance(image, Mapping):
                        raise TestStoreConflict(
                            "sealed fixture image cache is unobservable"
                        )
                proof = {
                    key: image.get(key)
                    for key in (
                        "cached",
                        "image_ref",
                        "image_id",
                        "repo_digest",
                        "os",
                        "architecture",
                    )
                }
                try:
                    _normalize_ephemeral_image_cache_proof(
                        proof, target=image_target
                    )
                except BrokerError as error:
                    raise TestStoreConflict(error.message) from error
                secret_mount = None
                if raw.get("secret_policy") is not None:
                    from .ephemeral_secrets import EphemeralSecretPolicy

                    policy = raw["secret_policy"]
                    if not isinstance(policy, Mapping):
                        raise TestStoreConflict("fixture secret policy is invalid")
                    secret_mount = self.secret_manager.provision_for_start(
                        peer_uid=int(raw["owner_uid"]),
                        account_id=TEST_ATTEMPT_ACCOUNT_ID,
                        repository_id=str(raw["repository_id"]),
                        template_id=str(raw["template_id"]),
                        run_id=uuid.UUID(str(raw["run_uuid"])),
                        policy=EphemeralSecretPolicy(
                            kind=str(policy["kind"]), binding_id=str(policy["binding_id"])
                        ),
                        expires_at_epoch=int(raw["expires_at_epoch"]),
                    )
                environment = tuple(tuple(item) for item in raw["environment"])
                if secret_mount is not None:
                    if any(name == "POSTGRES_PASSWORD_FILE" for name, _ in environment):
                        raise TestStoreConflict(
                            "sealed fixture conflicts with broker secret delivery"
                        )
                    environment = (*environment, *secret_mount.environment)
                create_target = EphemeralDockerCreateTarget(
                    identity=identity,
                    owner_uid=int(raw["owner_uid"]),
                    container_name=str(raw["container_name"]),
                    image_ref=str(raw["image_ref"]),
                    command=tuple(raw["command"]),
                    environment=environment,
                    memory_bytes=int(raw["memory_bytes"]),
                    cpu_limit=(
                        f"{int(raw['cpu_millis']) // 1000}"
                        if int(raw["cpu_millis"]) % 1000 == 0
                        else f"{int(raw['cpu_millis']) / 1000:.3f}".rstrip("0").rstrip(".")
                    ),
                    host_tcp_port=None,
                    container_tcp_port=None,
                    network_container_id=raw.get("network_container_id"),
                    secret_mount=secret_mount,
                )
                try:
                    created = self.host.docker_create_ephemeral(create_target)
                except BrokerBackendError as error:
                    if error.code != "ephemeral_docker_create_outcome_unknown":
                        raise
                    # Docker may have created the exact label-bound container
                    # before its reply was lost. Reconcile once by immutable
                    # identity and persist the full ID before any start/cleanup
                    # path can proceed.
                    recovered = self.host.docker_find_ephemeral(identity)
                    if recovered.get("found") is False:
                        raise
                    if recovered.get("found") is not True:
                        raise TestStoreConflict(
                            "fixture create reconciliation is unobservable"
                        ) from error
                    created = recovered
                full_id = created.get("full_container_id")
            if not isinstance(full_id, str) or _FULL_ID.fullmatch(full_id) is None:
                raise TestStoreConflict("fixture create did not prove an immutable container")
            raw["full_container_id"] = full_id
            raw["status"] = "created"
            if ordinal == 0:
                for following in fixtures[1:]:
                    if isinstance(following, dict):
                        following["network_container_id"] = full_id
            self._write_state(state)
        target = self._container_target(raw, require_material=True)
        started = self.host.docker_start_ephemeral(target)
        if started.get("running") is not True:
            raise TestStoreConflict("fixture start did not prove a running container")
        raw["status"] = "running"
        self._write_state(state)

    @staticmethod
    def _credential_name(prefix: str, name: str) -> str:
        suffix = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}-{suffix}"

    def _write_credential(self, directory: Path, name: str, payload: bytes) -> dict[str, object]:
        path = directory / name
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise TestStoreConflict("fixture credential write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return {
            "name": name,
            "source_path": str(path),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }

    def _publish_credentials(self, state: dict[str, object]) -> list[dict[str, object]]:
        runtime_id = str(state["runtime_id"])
        self._ensure_root(self.credential_root)
        directory = self.credential_root / runtime_id
        if directory.exists():
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise TestStoreConflict("fixture credential directory is unsafe")
            existing = state.get("credential_files")
            if isinstance(existing, list):
                return [dict(item) for item in existing if isinstance(item, Mapping)]
            raise TestStoreConflict("fixture credential journal is incomplete")
        directory.mkdir(mode=0o700)
        credentials: list[dict[str, object]] = []
        connections: list[dict[str, object]] = []
        provenance: list[dict[str, object]] = []
        fixtures = state["fixtures"]
        if not isinstance(fixtures, list):
            raise TestStoreConflict("fixture journal entries are invalid")
        for raw in fixtures:
            if not isinstance(raw, Mapping):
                raise TestStoreConflict("fixture journal entry is invalid")
            secret_name = None
            if raw.get("secret_policy") is not None:
                secret_name = self._credential_name("fixture-secret", str(raw["name"]))
                material = self.secret_manager.consume_run_secret(
                    peer_uid=int(raw["owner_uid"]),
                    account_id=TEST_ATTEMPT_ACCOUNT_ID,
                    repository_id=str(raw["repository_id"]),
                    template_id=str(raw["template_id"]),
                    run_id=uuid.UUID(str(raw["run_uuid"])),
                    request_id=uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "devcoordinator-test-fixture-secret-v1\x1f" + str(raw["run_uuid"]),
                    ),
                )
                credentials.append(self._write_credential(directory, secret_name, material.value))
            connections.append(
                {
                    "name": raw["name"],
                    "host": "127.0.0.1",
                    "port": raw["container_tcp_port"],
                    "secret_credential": secret_name,
                }
            )
            provenance.append(
                {
                    "name": raw["name"],
                    "template_id": raw["template_id"],
                    "template_fingerprint": raw["template_fingerprint"],
                    "image_ref": raw["image_ref"],
                    "full_container_id": raw["full_container_id"],
                    "network": (
                        "external" if raw["network"] == "external" else "private-loopback"
                    ),
                    "secret_delivery": secret_name is not None,
                }
            )
        credentials.append(
            self._write_credential(
                directory,
                "fixtures.json",
                json.dumps(connections, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )
        )
        credentials.append(
            self._write_credential(
                directory,
                "fixture-provenance.json",
                json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )
        )
        state["credential_files"] = credentials
        state["provenance"] = provenance
        self._write_state(state)
        return credentials

    def _lease(self, state: Mapping[str, object]) -> TestFixtureLease:
        fixtures = state.get("fixtures")
        namespace = state.get("network_namespace")
        credentials = state.get("credential_files")
        provenance = state.get("provenance")
        if (
            not isinstance(fixtures, list)
            or not isinstance(namespace, Mapping)
            or not isinstance(credentials, list)
            or not isinstance(provenance, list)
        ):
            raise TestStoreConflict("fixture lease journal is incomplete")
        return TestFixtureLease(
            runtime_id=str(state["runtime_id"]),
            descriptor_fingerprint=str(state["descriptor_fingerprint"]),
            fixtures=tuple(str(item["name"]) for item in fixtures if isinstance(item, Mapping)),
            environment={},
            credential_files=tuple(dict(item) for item in credentials if isinstance(item, Mapping)),
            network_namespace=dict(namespace),
            provenance=tuple(dict(item) for item in provenance if isinstance(item, Mapping)),
        )

    def _cleanup_lease(self, state: Mapping[str, object]) -> TestFixtureLease:
        """Recover only durable cleanup authority, even after a fixture crash."""

        fixtures = state.get("fixtures")
        if not isinstance(fixtures, list) or not fixtures:
            raise TestStoreConflict("fixture cleanup journal is invalid")
        credentials = state.get("credential_files")
        namespace = state.get("network_namespace")
        provenance = state.get("provenance")
        return TestFixtureLease(
            runtime_id=str(state["runtime_id"]),
            descriptor_fingerprint=str(state["descriptor_fingerprint"]),
            fixtures=tuple(
                str(item["name"]) for item in fixtures if isinstance(item, Mapping)
            ),
            environment={},
            credential_files=(
                ()
                if not isinstance(credentials, list)
                else tuple(
                    dict(item) for item in credentials if isinstance(item, Mapping)
                )
            ),
            network_namespace=(
                None if not isinstance(namespace, Mapping) else dict(namespace)
            ),
            provenance=(
                ()
                if not isinstance(provenance, list)
                else tuple(
                    dict(item) for item in provenance if isinstance(item, Mapping)
                )
            ),
        )

    def provision(self, descriptor: TestAttemptDescriptor, *, runtime_id: str) -> TestFixtureLease:
        runtime_id = self._runtime(runtime_id)
        if (
            not descriptor.fixtures
            or len(descriptor.fixtures) > _MAX_FIXTURES
            or len(descriptor.fixture_bindings) != len(descriptor.fixtures)
        ):
            raise TestStoreConflict("sealed fixture bindings are incomplete")
        with self._lock:
            existing = self._read_state(runtime_id)
            if existing is not None:
                if existing.get("descriptor_fingerprint") != descriptor.fingerprint:
                    raise TestStoreConflict("fixture runtime identity collided")
                if existing.get("status") == "running":
                    recovered = self.recover(runtime_id=runtime_id)
                    if recovered is None:
                        raise TestStoreConflict("fixture lease could not be recovered")
                    return recovered
                if existing.get("status") == "cleaned":
                    raise TestStoreConflict("fixture runtime was already cleaned")
                state = existing
            else:
                expires = int(self.clock()) + descriptor.ttl_seconds
                records = [
                    self._fixture_record(
                        descriptor, binding, runtime_id=runtime_id, ordinal=index, expires=expires
                    )
                    for index, binding in enumerate(descriptor.fixture_bindings)
                ]
                if (
                    sum(int(item["memory_bytes"]) for item in records) > _MAX_FIXTURE_MEMORY
                    or sum(int(item["cpu_millis"]) for item in records) > _MAX_FIXTURE_CPU_MILLIS
                ):
                    raise TestStoreConflict("sealed fixtures exceed the test-plane host budget")
                state = {
                    "schema_version": 2,
                    "runtime_id": runtime_id,
                    "descriptor_fingerprint": descriptor.fingerprint,
                    "repository_id": descriptor.repository_id,
                    "repository_generation": descriptor.repository_generation,
                    "owner_uid": descriptor.owner_uid,
                    "expires_at_epoch": expires,
                    "status": "provisioning",
                    "fixtures": records,
                    "credential_files": None,
                    "provenance": None,
                    "network_namespace": None,
                }
                self._write_state(state)
            try:
                for ordinal in range(len(descriptor.fixtures)):
                    self._create_or_recover(state, ordinal)
                anchor = state["fixtures"][0]
                target = self._container_target(anchor, require_material=True)
                observer = getattr(self.host, "docker_test_fixture_namespace", None)
                if not callable(observer):
                    raise TestStoreConflict("host fixture namespace observer is unavailable")
                evidence = observer(target)
                namespace = {
                    "path": evidence["namespace_path"],
                    "device": evidence["namespace_device"],
                    "inode": evidence["namespace_inode"],
                    "pid": evidence["pid"],
                    "process_identity": evidence["process_identity"],
                }
                state["network_namespace"] = namespace
                self._publish_credentials(state)
                state["status"] = "running"
                self._write_state(state)
                self._wake.set()
                return self._lease(state)
            except Exception:
                state["status"] = "cleanup_pending"
                self._write_state(state)
                try:
                    self.cleanup(
                        runtime_id=runtime_id,
                        descriptor_fingerprint=str(
                            state["descriptor_fingerprint"]
                        ),
                        reason="fixture_provision_failed",
                    )
                except Exception:
                    pass
                raise

    def recover(self, *, runtime_id: str) -> TestFixtureLease | None:
        runtime_id = self._runtime(runtime_id)
        with self._lock:
            state = self._read_state(runtime_id)
            if state is None or state.get("status") == "cleaned":
                return None
            if int(state.get("expires_at_epoch", 0)) <= int(self.clock()):
                self.cleanup(
                    runtime_id=runtime_id,
                    descriptor_fingerprint=str(state["descriptor_fingerprint"]),
                    reason="fixture_lease_expired",
                )
                return None
            if state.get("status") != "running":
                raise TestStoreConflict("fixture lease recovery requires cleanup")
            fixtures = state.get("fixtures")
            if not isinstance(fixtures, list) or not fixtures:
                raise TestStoreConflict("fixture lease journal is invalid")
            anchor = fixtures[0]
            if not isinstance(anchor, Mapping):
                raise TestStoreConflict("fixture anchor journal is invalid")
            anchor_id = anchor.get("full_container_id")
            for ordinal, raw in enumerate(fixtures):
                if not isinstance(raw, Mapping):
                    raise TestStoreConflict("fixture lease journal is invalid")
                expected_anchor = None if ordinal == 0 else anchor_id
                if raw.get("network_container_id") != expected_anchor:
                    raise TestStoreConflict("fixture network membership changed")
                observed = self.host.docker_inspect_ephemeral(
                    self._container_target(raw, require_material=True)
                )
                if observed.get("running") is not True:
                    raise TestStoreConflict("fixture lease is not running")
            observer = getattr(self.host, "docker_test_fixture_namespace", None)
            if not callable(observer):
                raise TestStoreConflict("host fixture namespace observer is unavailable")
            evidence = observer(self._container_target(anchor, require_material=True))
            state["network_namespace"] = {
                "path": evidence["namespace_path"],
                "device": evidence["namespace_device"],
                "inode": evidence["namespace_inode"],
                "pid": evidence["pid"],
                "process_identity": evidence["process_identity"],
            }
            self._write_state(state)
            return self._lease(state)

    def recover_for_cleanup(self, *, runtime_id: str) -> TestFixtureLease | None:
        """Recover exact cleanup identity without requiring a live fixture."""

        runtime_id = self._runtime(runtime_id)
        with self._lock:
            state = self._read_state(runtime_id)
            if state is None or state.get("status") == "cleaned":
                return None
            return self._cleanup_lease(state)

    def cleanup(
        self, *, runtime_id: str, descriptor_fingerprint: str, reason: str
    ) -> None:
        runtime_id = self._runtime(runtime_id)
        if (
            not isinstance(descriptor_fingerprint, str)
            or _FULL_ID.fullmatch(descriptor_fingerprint) is None
        ):
            raise TestStoreContractError(
                "fixture cleanup descriptor fingerprint is invalid"
            )
        del reason
        with self._lock:
            state = self._read_state(runtime_id)
            if state is None:
                raise TestStoreConflict("fixture cleanup journal is unavailable")
            if state.get("descriptor_fingerprint") != descriptor_fingerprint:
                raise TestStoreConflict(
                    "fixture cleanup descriptor fingerprint is stale"
                )
            if state.get("status") == "cleaned":
                return
            state["status"] = "cleanup_pending"
            self._write_state(state)
            fixtures = state.get("fixtures")
            if not isinstance(fixtures, list):
                raise TestStoreConflict("fixture cleanup journal is invalid")
            for raw in reversed(fixtures):
                if not isinstance(raw, dict):
                    raise TestStoreConflict("fixture cleanup entry is invalid")
                if raw.get("full_container_id") is not None:
                    target = self._container_target(raw, require_material=False)
                    found = self.host.docker_find_ephemeral(target.identity)
                    if found.get("found") is True:
                        if found.get("full_container_id") != target.full_container_id:
                            raise TestStoreConflict(
                                "fixture cleanup found a contradictory container identity"
                            )
                        observed = self.host.docker_inspect_ephemeral(target)
                        if observed.get("running") is True:
                            self.host.docker_stop_ephemeral(target)
                        self.host.docker_remove_ephemeral(target)
                        absent = self.host.docker_find_ephemeral(target.identity)
                        if absent.get("found") is True:
                            raise TestStoreConflict(
                                "fixture cleanup did not prove absence"
                            )
                    elif found.get("found") is not False:
                        raise TestStoreConflict(
                            "fixture cleanup absence proof is invalid"
                        )
                if raw.get("secret_policy") is not None:
                    try:
                        self.secret_manager.release_run_secret(
                            run_id=uuid.UUID(str(raw["run_uuid"]))
                        )
                    except EphemeralSecretError as error:
                        raise TestStoreConflict("fixture secret cleanup failed") from error
                raw["status"] = "cleaned"
                self._write_state(state)
            directory = self.credential_root / runtime_id
            try:
                directory_metadata = directory.lstat()
            except FileNotFoundError:
                directory_metadata = None
            if directory_metadata is not None:
                if (
                    directory.resolve(strict=True) != directory
                    or not stat.S_ISDIR(directory_metadata.st_mode)
                    or stat.S_ISLNK(directory_metadata.st_mode)
                ):
                    raise TestStoreConflict(
                        "fixture credential cleanup directory is unsafe"
                    )
                for child in directory.iterdir():
                    metadata = child.lstat()
                    if (
                        child.parent != directory
                        or not stat.S_ISREG(metadata.st_mode)
                        or stat.S_ISLNK(metadata.st_mode)
                    ):
                        raise TestStoreConflict("fixture credential cleanup path is unsafe")
                    child.unlink()
                directory.rmdir()
            state["credential_files"] = []
            state["status"] = "cleaned"
            state["cleaned_at_epoch"] = int(self.clock())
            self._write_state(state)

    def recover_startup(self) -> Mapping[str, object]:
        self._ensure_root(self.state_root)
        cleaned = 0
        attention = 0
        with self._lock:
            for path in sorted(self.state_root.glob("devcoordinator-test-*.json"))[:256]:
                runtime_id = path.stem
                try:
                    state = self._read_state(runtime_id)
                    if state is None or state.get("status") == "cleaned":
                        continue
                    # Running attempts are recovered lazily by their exact
                    # systemd observation; incomplete/expired provisioning is
                    # cleanup-fenced immediately after a broker restart.
                    if state.get("status") != "running" or int(state.get("expires_at_epoch", 0)) <= int(self.clock()):
                        self.cleanup(
                            runtime_id=runtime_id,
                            descriptor_fingerprint=str(
                                state["descriptor_fingerprint"]
                            ),
                            reason="fixture_startup_recovery",
                        )
                        cleaned += 1
                except Exception:
                    attention += 1
        return {"cleaned": cleaned, "attention": attention}

    def reap_once(self) -> Mapping[str, object]:
        return self.recover_startup()

    def start_reaper(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.is_set():
                self.reap_once()
                self._wake.wait(self.reaper_interval_seconds)
                self._wake.clear()

        self._thread = threading.Thread(
            target=loop, name="devcoordinator-test-fixture-reaper", daemon=True
        )
        self._thread.start()

    def request_reaper_stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def wait_reaper_stopped(self, timeout_seconds: float) -> None:
        thread = self._thread
        if thread is None:
            return
        thread.join(timeout_seconds)
        if thread.is_alive():
            raise TestStoreConflict("test fixture reaper did not stop")
        self._thread = None


__all__ = ["BrokerSealedFixtureProvider"]
