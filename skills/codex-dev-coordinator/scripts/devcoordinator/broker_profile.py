"""Root-provisioned client profile and fail-closed broker calls.

The standard CLI never discovers a broker by probing and never accepts a
client-writable profile as a trust anchor.  A host administrator installs one
root-owned profile document.  The authenticated UID selects its own account
and exact normalized resource IDs from that document; only those opaque IDs
cross the Unix-socket protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Mapping, Optional

from .broker import (
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS,
    DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS,
)
from .ephemeral_secrets import EphemeralSecretPolicy, normalize_ephemeral_secret_policy


PROFILE_VERSION = 1
HOST_OBSERVE_CLIENT_TIMEOUT_SECONDS = 11 * 60.0
INVENTORY_READ_CLIENT_TIMEOUT_SECONDS = 60.0
SYSTEM_PROFILE_PATH = Path(
    "/private/etc/devcoordinator/client-profiles.json"
    if sys.platform == "darwin"
    else "/etc/devcoordinator/client-profiles.json"
)
PROFILE_PATH_ENV = "DEVCOORDINATOR_BROKER_PROFILE"
_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)


class BrokerProfileError(RuntimeError):
    """A configured broker profile is missing, stale, or unsafe."""


@dataclass(frozen=True)
class BrokerServiceProfile:
    socket_path: Path
    service_uid: int
    socket_gid: int
    socket_mode: int
    database_generation: str


@dataclass(frozen=True)
class EphemeralSecretPolicyProfile:
    """Public non-secret policy/binding metadata for one named template."""

    policy: str
    binding_id: str

    def __post_init__(self) -> None:
        validated = EphemeralSecretPolicy(
            kind=normalize_ephemeral_secret_policy(self.policy),
            binding_id=self.binding_id,
        )
        object.__setattr__(self, "policy", validated.kind)
        object.__setattr__(self, "binding_id", validated.binding_id)


@dataclass(frozen=True)
class BrokerRepositoryProfile:
    canonical_root: str
    repo_id: str
    generation: int
    server_ids: Mapping[str, str]
    container_ids: Mapping[str, str]
    compose_definition_id: Optional[str]
    ephemeral_templates: Mapping[str, str] = field(default_factory=dict)
    ephemeral_image_prefetch_template_ids: frozenset[str] = field(
        default_factory=frozenset
    )
    ephemeral_secret_policies: Mapping[str, EphemeralSecretPolicyProfile] = field(
        default_factory=dict
    )
    account_id: Optional[str] = None
    enabled: bool = True
    issued_at: str = ""
    valid_until_epoch: int = 2**63 - 1

    def require_account(self, *, account_id: str) -> None:
        """Bind even retained cleanup calls to the profile's exact account."""

        if self.account_id is not None and self.account_id != account_id:
            raise BrokerProfileError(
                "repository broker enrollment belongs to another account"
            )

    def require_current(self, *, account_id: str) -> None:
        self.require_account(account_id=account_id)
        if not self.enabled:
            raise BrokerProfileError(
                "repository broker enrollment is disabled; rerun Coordinator skill installation"
            )
        if int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "repository broker enrollment has expired; rerun Coordinator skill installation"
            )

    def server_id(self, name: str) -> str:
        value = self.server_ids.get(str(name))
        if value is None:
            raise BrokerProfileError(
                f"server {name!r} is not enrolled with the host coordinator broker; "
                "rerun Coordinator skill installation as the host administrator"
            )
        return value

    def require_server_id(self, resource_id: str) -> str:
        """Require an exact opaque server ID already present in this enrollment."""

        candidate = str(resource_id)
        if candidate not in self.server_ids.values():
            raise BrokerProfileError(
                f"server identity {candidate!r} is not enrolled with the host coordinator broker; "
                "rerun Coordinator skill installation as the host administrator"
            )
        return candidate

    def container_id(self, identity: str) -> str:
        value = self.container_ids.get(str(identity))
        if value is None:
            raise BrokerProfileError(
                f"Docker resource {identity!r} is not enrolled with the host coordinator broker; "
                "refresh service observation and rerun Coordinator skill installation"
            )
        return value

    def compose_id(self) -> str:
        if self.compose_definition_id is None:
            raise BrokerProfileError(
                "this repository has no service-owned Compose definition; "
                "rerun Coordinator skill installation after declaring Compose in the runtime manifest"
            )
        return self.compose_definition_id

    def ephemeral_template_id(self, name: str) -> str:
        value = self.ephemeral_templates.get(str(name))
        if value is None:
            raise BrokerProfileError(
                f"ephemeral template {name!r} is not enrolled with the host "
                "coordinator broker; rerun Coordinator skill installation as "
                "the host administrator"
            )
        return value

    def ephemeral_image_prefetch_template_id(self, name: str) -> str:
        """Return one template only when the root profile explicitly permits pull."""

        value = self.ephemeral_template_id(name)
        if value not in self.ephemeral_image_prefetch_template_ids:
            raise BrokerProfileError(
                f"ephemeral image prefetch for template {name!r} is not explicitly "
                "enrolled; rerun Coordinator skill installation with the reviewed "
                "image-prefetch grant"
            )
        return value

    def ephemeral_secret_policy(
        self, name: str
    ) -> EphemeralSecretPolicyProfile | None:
        """Return public credential-delivery policy, never credential material."""

        return self.ephemeral_secret_policies.get(str(name))


@dataclass(frozen=True)
class BrokerClientProfile:
    service: BrokerServiceProfile
    client_uid: int
    account_id: str
    issued_at: str
    valid_until_epoch: int
    repositories: Mapping[str, BrokerRepositoryProfile]

    def repository(self, canonical_root: str) -> BrokerRepositoryProfile:
        if int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "host broker enrollment has expired; rerun Coordinator skill installation"
            )
        canonical = str(Path(canonical_root).expanduser().resolve())
        value = self.repositories.get(canonical)
        if value is None:
            raise BrokerProfileError(
                f"repository {canonical} is not enrolled with the configured host broker; "
                "local fallback is disabled while a broker profile is installed"
            )
        value.require_current(account_id=self.account_id)
        return value

    def retained_ephemeral_repository(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile:
        """Resolve one recorded repo for owner-only status/cleanup calls.

        This deliberately does not discover repositories or revive an expired
        enrollment.  The protected profile supplies only the exact opaque repo
        identity; the broker still proves the run belongs to the authenticated
        UID/account and permits only ``ephemeral.status`` or
        ``ephemeral.finish`` after revocation.
        """

        canonical = str(Path(canonical_root).expanduser().resolve())
        value = self.repositories.get(canonical)
        if value is None:
            raise BrokerProfileError(
                f"repository {canonical} is not recorded in the configured host "
                "broker profile; retained ephemeral cleanup cannot discover it"
            )
        value.require_account(account_id=self.account_id)
        return value

    def repository_for_server_id(self, server_id: str) -> BrokerRepositoryProfile:
        """Resolve one fixed runner ID only through current protected enrollments."""

        candidate = str(server_id)
        matches: list[BrokerRepositoryProfile] = []
        for repository in self.repositories.values():
            try:
                repository.require_current(account_id=self.account_id)
            except BrokerProfileError:
                continue
            if candidate in repository.server_ids.values():
                matches.append(repository)
        if not matches:
            raise BrokerProfileError(
                f"server identity {candidate!r} is not present in a current host broker enrollment"
            )
        if len(matches) != 1:
            raise BrokerProfileError(
                f"server identity {candidate!r} is ambiguous across protected repository enrollments"
            )
        return matches[0]

    def call(
        self,
        *,
        repository: BrokerRepositoryProfile,
        resource_id: str,
        operation: BrokerOperation,
        arguments: Optional[Mapping[str, Any]] = None,
        operation_id: Optional[str] = None,
    ) -> tuple[str, dict[str, Any]]:
        retained_ephemeral = operation in {
            BrokerOperation.EPHEMERAL_STATUS,
            BrokerOperation.EPHEMERAL_FINISH,
        }
        if not retained_ephemeral and int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "host broker enrollment has expired; rerun Coordinator skill installation"
            )
        if retained_ephemeral:
            repository.require_account(account_id=self.account_id)
        else:
            repository.require_current(account_id=self.account_id)
        return call_broker(
            service=self.service,
            account_id=self.account_id,
            repo_id=repository.repo_id,
            repository_generation=repository.generation,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
        )

    def worker_call(
        self,
        *,
        repository: BrokerRepositoryProfile,
        server_id: str,
        operation: BrokerOperation,
        arguments: Optional[Mapping[str, Any]] = None,
        operation_id: Optional[str] = None,
    ) -> tuple[str, dict[str, Any]]:
        """Call only the fixed worker protocol for one exactly enrolled server."""

        if operation not in {
            BrokerOperation.WORKER_LAUNCH_TICKET,
            BrokerOperation.WORKER_LAUNCHED,
            BrokerOperation.WORKER_EXIT,
            BrokerOperation.WORKER_POLICY_READ,
            BrokerOperation.WORKER_ATTEMPT_READ,
        }:
            raise ValueError("operation is not a worker broker operation")
        resource_id = repository.require_server_id(server_id)
        return self.call(
            repository=repository,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
        )

    def inventory(self, *, canonical_root: str | None = None) -> dict[str, Any]:
        """Read host authority through the requested or a current enrollment.

        A project-scoped caller must identify its exact repository so the
        broker authorization request cannot be routed through an unrelated
        enrollment. Host-wide callers retain the deterministic current-
        enrollment selection because they have no project scope to prefer.
        """

        if int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "host broker enrollment has expired; rerun Coordinator skill installation"
            )
        if canonical_root is not None:
            repository = self.repository(canonical_root)
        elif not self.repositories:
            raise BrokerProfileError(
                "authenticated account has no enrolled repository for host inventory access"
            )
        else:
            current: list[BrokerRepositoryProfile] = []
            for candidate in self.repositories.values():
                try:
                    candidate.require_current(account_id=self.account_id)
                except BrokerProfileError:
                    continue
                current.append(candidate)
            if not current:
                raise BrokerProfileError(
                    "authenticated account has no current repository enrollment for host inventory access"
                )
            repository = min(current, key=lambda item: item.canonical_root)
        _operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.INVENTORY_READ,
            arguments={},
        )
        return result

    def events(
        self, *, after: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        """Read the host-wide durable event journal through one enrollment."""

        if int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "host broker enrollment has expired; rerun Coordinator skill installation"
            )
        if not self.repositories:
            raise BrokerProfileError(
                "authenticated account has no enrolled repository for host event access"
            )
        repository = min(
            self.repositories.values(), key=lambda item: item.canonical_root
        )
        arguments: dict[str, Any] = {"limit": limit}
        if after is not None:
            arguments["after"] = after
        _operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.EVENTS_READ,
            arguments=arguments,
        )
        return result


def call_broker(
    *,
    service: BrokerServiceProfile,
    account_id: str,
    repo_id: str,
    resource_id: str,
    operation: BrokerOperation,
    repository_generation: int = 0,
    arguments: Optional[Mapping[str, Any]] = None,
    operation_id: Optional[str] = None,
) -> tuple[str, dict[str, Any]]:
    request = BrokerRequest.create(
        account_id=account_id,
        project_id=repo_id,
        repository_generation=repository_generation,
        resource_id=resource_id,
        operation=operation,
        arguments=arguments,
        operation_id=operation_id,
        authority_generation=service.database_generation,
    )
    client = BrokerClient(
        service.socket_path,
        expected_broker_uid=service.service_uid,
        expected_socket_gid=service.socket_gid,
        expected_socket_mode=service.socket_mode,
        timeout_seconds=(
            (
                (
                    DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS
                    if operation == BrokerOperation.DATABASE_BACKUP
                    else DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS
                )
                if operation in {
                    BrokerOperation.DATABASE_BACKUP,
                    BrokerOperation.DATABASE_RESTORE,
                }
                else (
                    HOST_OBSERVE_CLIENT_TIMEOUT_SECONDS
                    if operation == BrokerOperation.HOST_OBSERVE
                    else (
                        INVENTORY_READ_CLIENT_TIMEOUT_SECONDS
                        if operation == BrokerOperation.INVENTORY_READ
                        else (
                            5 * 60.0
                            if operation
                            in {
                                BrokerOperation.EPHEMERAL_START,
                                BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
                                BrokerOperation.EPHEMERAL_FINISH,
                                BrokerOperation.COMPOSE_UP,
                                BrokerOperation.COMPOSE_STOP,
                                BrokerOperation.COMPOSE_RESTART,
                                BrokerOperation.COMPOSE_DOWN,
                            }
                            else 60.0
                        )
                    )
                )
            )
            if operation
            in {
                BrokerOperation.REPOSITORY_REMOVE,
                BrokerOperation.RESOURCE_ATTACH,
                BrokerOperation.RESOURCE_RETIRE,
                BrokerOperation.HOST_OBSERVE,
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
                BrokerOperation.INVENTORY_READ,
                BrokerOperation.EPHEMERAL_START,
                BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
                BrokerOperation.EPHEMERAL_FINISH,
                BrokerOperation.RUNTIME_REQUEST,
                BrokerOperation.COMPOSE_UP,
                BrokerOperation.COMPOSE_STOP,
                BrokerOperation.COMPOSE_RESTART,
                BrokerOperation.COMPOSE_DOWN,
            }
            else 10.0
        ),
    )
    reply = client.call(request)
    if not bool(reply.get("ok")):
        error = reply.get("error")
        if not isinstance(error, dict):
            raise BrokerError(
                "invalid_reply",
                "Broker returned an invalid failure payload.",
                operation_id=request.operation_id,
            )
        raise BrokerError(
            str(error.get("code") or "invalid_reply"),
            str(error.get("message") or "Broker mutation failed."),
            operation_id=request.operation_id,
        )
    result = reply.get("result")
    if not isinstance(result, dict):
        raise BrokerError(
            "invalid_reply",
            "Broker returned an invalid success payload.",
            operation_id=request.operation_id,
        )
    return request.operation_id, dict(result)


def configured_profile_path() -> Path:
    raw = str(os.environ.get(PROFILE_PATH_ENV) or "").strip()
    return Path(raw) if raw else SYSTEM_PROFILE_PATH


def load_broker_profile(
    *,
    path: Path | None = None,
    effective_uid: int | None = None,
    required: bool = False,
    trusted_owner_uid: int = 0,
    allow_expired_for_ephemeral_cleanup: bool = False,
) -> BrokerClientProfile | None:
    configured_by_environment = bool(str(os.environ.get(PROFILE_PATH_ENV) or "").strip())
    explicitly_configured = path is not None or configured_by_environment
    candidate = (path or configured_profile_path()).expanduser()
    uid = os.geteuid() if effective_uid is None else int(effective_uid)
    try:
        metadata = _validate_profile_file(candidate, trusted_owner_uid=trusted_owner_uid)
    except FileNotFoundError:
        if required or explicitly_configured:
            raise BrokerProfileError(
                f"required root-provisioned broker profile is missing: {candidate}"
            ) from None
        return None
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BrokerProfileError(f"broker profile cannot be decoded: {error}") from error
    # Recheck identity after the read so a replacement cannot be trusted.
    after = candidate.lstat()
    if (metadata.st_dev, metadata.st_ino) != (after.st_dev, after.st_ino):
        raise BrokerProfileError("broker profile identity changed while it was read")
    return profile_from_document(
        document,
        effective_uid=uid,
        allow_expired_for_ephemeral_cleanup=allow_expired_for_ephemeral_cleanup,
    )


def profile_from_document(
    document: Any,
    *,
    effective_uid: int,
    allow_expired_for_ephemeral_cleanup: bool = False,
) -> BrokerClientProfile:
    if not isinstance(document, dict) or set(document) != {
        "version",
        "service",
        "clients",
    }:
        raise BrokerProfileError("broker profile fields are invalid")
    if document.get("version") != PROFILE_VERSION:
        raise BrokerProfileError("broker profile version is unsupported")
    service_raw = document.get("service")
    if not isinstance(service_raw, dict) or set(service_raw) != {
        "socket",
        "uid",
        "gid",
        "mode",
        "database_generation",
    }:
        raise BrokerProfileError("broker service profile fields are invalid")
    socket_path = Path(str(service_raw.get("socket") or ""))
    if not socket_path.is_absolute() or ".." in socket_path.parts:
        raise BrokerProfileError("broker socket must be an absolute path without traversal")
    service_uid = _nonnegative_int(service_raw.get("uid"), "service uid")
    socket_gid = _nonnegative_int(service_raw.get("gid"), "socket gid")
    try:
        socket_mode = int(str(service_raw.get("mode")), 8)
    except ValueError as error:
        raise BrokerProfileError("broker socket mode must be octal") from error
    if socket_mode != 0o660:
        raise BrokerProfileError("broker socket mode must be exactly 0660")
    generation = _identifier(service_raw.get("database_generation"), "database generation")

    clients = document.get("clients")
    if not isinstance(clients, dict):
        raise BrokerProfileError("broker clients must be an object")
    raw = clients.get(str(effective_uid))
    if not isinstance(raw, dict) or set(raw) != {
        "account_id",
        "issued_at",
        "valid_until_epoch",
        "repositories",
    }:
        raise BrokerProfileError(
            f"authenticated uid {effective_uid} has no valid broker enrollment"
        )
    account_id = _identifier(raw.get("account_id"), "account id")
    valid_until = _positive_int(raw.get("valid_until_epoch"), "profile expiry")
    if (
        not allow_expired_for_ephemeral_cleanup
        and int(time.time()) >= valid_until
    ):
        raise BrokerProfileError("host broker enrollment has expired")
    repositories_raw = raw.get("repositories")
    if not isinstance(repositories_raw, list) or not repositories_raw:
        raise BrokerProfileError("broker client has no enrolled repositories")
    repositories: dict[str, BrokerRepositoryProfile] = {}
    for item in repositories_raw:
        repository = _repository_from_document(
            item,
            account_id=account_id,
            fallback_issued_at=str(raw.get("issued_at") or ""),
            fallback_valid_until_epoch=valid_until,
        )
        if repository.canonical_root in repositories:
            raise BrokerProfileError("broker profile duplicates a canonical repository root")
        repositories[repository.canonical_root] = repository
    if not allow_expired_for_ephemeral_cleanup and not any(
        repository.enabled
        and repository.account_id == account_id
        and int(time.time()) < repository.valid_until_epoch
        for repository in repositories.values()
    ):
        raise BrokerProfileError("host broker enrollment has expired")
    return BrokerClientProfile(
        service=BrokerServiceProfile(
            socket_path=socket_path,
            service_uid=service_uid,
            socket_gid=socket_gid,
            socket_mode=socket_mode,
            database_generation=generation,
        ),
        client_uid=effective_uid,
        account_id=account_id,
        issued_at=str(raw.get("issued_at") or ""),
        valid_until_epoch=valid_until,
        repositories=repositories,
    )


def _repository_from_document(
    value: Any,
    *,
    account_id: str,
    fallback_issued_at: str,
    fallback_valid_until_epoch: int,
) -> BrokerRepositoryProfile:
    legacy_fields = {
        "canonical_root",
        "repo_id",
        "generation",
        "servers",
        "containers",
        "compose_definition_id",
    }
    repository_fields = legacy_fields | {
        "account_id",
        "enabled",
        "issued_at",
        "valid_until_epoch",
    }
    ephemeral_fields = {
        "ephemeral_templates",
        "ephemeral_secret_policies",
        "ephemeral_image_prefetch_templates",
    }
    accepted_fields = {
        frozenset(base | subset)
        for base in (legacy_fields, repository_fields)
        for subset in (
            set(),
            {"ephemeral_templates"},
            {"ephemeral_secret_policies"},
            {"ephemeral_image_prefetch_templates"},
            {"ephemeral_templates", "ephemeral_secret_policies"},
            {"ephemeral_templates", "ephemeral_image_prefetch_templates"},
            {"ephemeral_secret_policies", "ephemeral_image_prefetch_templates"},
            ephemeral_fields,
        )
    }
    if not isinstance(value, dict) or frozenset(value) not in accepted_fields:
        raise BrokerProfileError("broker repository profile fields are invalid")
    canonical_root = str(Path(str(value.get("canonical_root") or "")).expanduser().resolve())
    if not Path(canonical_root).is_absolute():
        raise BrokerProfileError("enrolled repository root must be absolute")
    servers = _identifier_mapping(value.get("servers"), "server")
    containers = _identifier_mapping(value.get("containers"), "container")
    ephemeral_templates = _identifier_mapping(
        value.get("ephemeral_templates", {}), "ephemeral template"
    )
    ephemeral_secret_policies = _ephemeral_secret_policy_mapping(
        value.get("ephemeral_secret_policies", {})
    )
    ephemeral_image_prefetch_template_ids = _ephemeral_image_prefetch_template_ids(
        value.get("ephemeral_image_prefetch_templates", []),
        template_ids=frozenset(ephemeral_templates.values()),
    )
    if not set(ephemeral_secret_policies) <= set(ephemeral_templates):
        raise BrokerProfileError(
            "ephemeral credential policy references an unknown template"
        )
    compose_raw = value.get("compose_definition_id")
    compose = None if compose_raw is None else _identifier(compose_raw, "Compose definition")
    if repository_fields <= set(value):
        repository_account_id = _identifier(
            value.get("account_id"), "repository account id"
        )
        if repository_account_id != account_id:
            raise BrokerProfileError(
                "broker repository profile belongs to another account"
            )
        enabled = value.get("enabled")
        if type(enabled) is not bool:
            raise BrokerProfileError("repository enrollment enabled must be boolean")
        issued_at = str(value.get("issued_at") or "")
        valid_until_epoch = _positive_int(
            value.get("valid_until_epoch"), "repository profile expiry"
        )
    else:
        repository_account_id = account_id
        enabled = True
        issued_at = fallback_issued_at
        valid_until_epoch = fallback_valid_until_epoch
    return BrokerRepositoryProfile(
        canonical_root=canonical_root,
        repo_id=_identifier(value.get("repo_id"), "repository id"),
        generation=_nonnegative_int(value.get("generation"), "repository generation"),
        server_ids=servers,
        container_ids=containers,
        compose_definition_id=compose,
        ephemeral_templates=ephemeral_templates,
        ephemeral_image_prefetch_template_ids=ephemeral_image_prefetch_template_ids,
        ephemeral_secret_policies=ephemeral_secret_policies,
        account_id=repository_account_id,
        enabled=enabled,
        issued_at=issued_at,
        valid_until_epoch=valid_until_epoch,
    )


def _identifier_mapping(value: Any, label: str) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise BrokerProfileError(f"broker {label} mapping must be an object")
    result: dict[str, str] = {}
    for display, resource_id in value.items():
        key = str(display)
        if not key or len(key) > 512:
            raise BrokerProfileError(f"broker {label} display identity is invalid")
        result[key] = _identifier(resource_id, f"{label} resource id")
    return result


def _ephemeral_secret_policy_mapping(
    value: Any,
) -> Mapping[str, EphemeralSecretPolicyProfile]:
    """Parse only public policy and opaque binding IDs from a root profile."""

    if not isinstance(value, dict):
        raise BrokerProfileError("broker ephemeral credential policy mapping must be an object")
    result: dict[str, EphemeralSecretPolicyProfile] = {}
    for template_name, raw in value.items():
        name = str(template_name)
        if not name or len(name.encode("utf-8")) > 512:
            raise BrokerProfileError("ephemeral credential policy template name is invalid")
        if not isinstance(raw, dict) or set(raw) != {"policy", "binding_id"}:
            raise BrokerProfileError("ephemeral credential policy fields are invalid")
        try:
            result[name] = EphemeralSecretPolicyProfile(
                policy=str(raw.get("policy") or ""),
                binding_id=str(raw.get("binding_id") or ""),
            )
        except (TypeError, ValueError) as exc:
            raise BrokerProfileError("ephemeral credential policy is invalid") from exc
    return result


def _ephemeral_image_prefetch_template_ids(
    value: Any, *, template_ids: frozenset[str]
) -> frozenset[str]:
    """Parse only a root-declared subset of enrolled opaque template IDs."""

    if not isinstance(value, list):
        raise BrokerProfileError(
            "broker ephemeral image prefetch templates must be a list"
        )
    result = tuple(
        _identifier(item, "ephemeral image prefetch template id") for item in value
    )
    if len(set(result)) != len(result):
        raise BrokerProfileError(
            "broker ephemeral image prefetch template list has duplicates"
        )
    if not set(result) <= template_ids:
        raise BrokerProfileError(
            "broker ephemeral image prefetch template is not enrolled"
        )
    return frozenset(result)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise BrokerProfileError(f"{label} must be a non-empty opaque identifier")
    if any(character not in _IDENTIFIER_CHARS for character in value):
        raise BrokerProfileError(f"{label} contains unsupported characters")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise BrokerProfileError(f"{label} must be a non-negative integer")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise BrokerProfileError(f"{label} must be a positive integer")
    return value


def _validate_profile_file(path: Path, *, trusted_owner_uid: int) -> os.stat_result:
    if not path.is_absolute() or ".." in path.parts:
        raise BrokerProfileError("broker profile path must be absolute without traversal")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BrokerProfileError("broker profile path contains a non-directory or symlink")
        if metadata.st_uid not in {0, trusted_owner_uid}:
            raise BrokerProfileError("broker profile path has an untrusted owner")
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise BrokerProfileError("broker profile path has a replaceable ancestor")
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokerProfileError("broker profile must be a regular non-symlink file")
    if metadata.st_uid != trusted_owner_uid:
        raise BrokerProfileError("broker profile is not owned by the trusted administrator")
    if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        raise BrokerProfileError("broker profile must not be group/world writable")
    if metadata.st_size > 1024 * 1024:
        raise BrokerProfileError("broker profile exceeds the one-megabyte bound")
    return metadata
