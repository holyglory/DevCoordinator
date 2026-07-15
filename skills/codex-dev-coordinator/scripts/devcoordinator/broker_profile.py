"""Root-provisioned client profile and fail-closed broker calls.

The standard CLI never discovers a broker by probing and never accepts a
client-writable profile as a trust anchor.  A host administrator installs one
root-owned profile document.  The authenticated UID selects its own account
and exact normalized resource IDs from that document; only those opaque IDs
cross the Unix-socket protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Mapping, Optional

from .broker import BrokerClient, BrokerError, BrokerOperation, BrokerRequest


PROFILE_VERSION = 1
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
class BrokerRepositoryProfile:
    canonical_root: str
    repo_id: str
    generation: int
    server_ids: Mapping[str, str]
    container_ids: Mapping[str, str]
    compose_definition_id: Optional[str]

    def server_id(self, name: str) -> str:
        value = self.server_ids.get(str(name))
        if value is None:
            raise BrokerProfileError(
                f"server {name!r} is not enrolled with the host coordinator broker; "
                "rerun Coordinator skill installation as the host administrator"
            )
        return value

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


@dataclass(frozen=True)
class BrokerClientProfile:
    service: BrokerServiceProfile
    client_uid: int
    account_id: str
    issued_at: str
    valid_until_epoch: int
    repositories: Mapping[str, BrokerRepositoryProfile]

    def repository(self, canonical_root: str) -> BrokerRepositoryProfile:
        canonical = str(Path(canonical_root).expanduser().resolve())
        value = self.repositories.get(canonical)
        if value is None:
            raise BrokerProfileError(
                f"repository {canonical} is not enrolled with the configured host broker; "
                "local fallback is disabled while a broker profile is installed"
            )
        if int(time.time()) >= self.valid_until_epoch:
            raise BrokerProfileError(
                "host broker enrollment has expired; rerun Coordinator skill installation"
            )
        return value

    def call(
        self,
        *,
        repository: BrokerRepositoryProfile,
        resource_id: str,
        operation: BrokerOperation,
        arguments: Optional[Mapping[str, Any]] = None,
        operation_id: Optional[str] = None,
    ) -> tuple[str, dict[str, Any]]:
        return call_broker(
            service=self.service,
            account_id=self.account_id,
            repo_id=repository.repo_id,
            resource_id=resource_id,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
        )


def call_broker(
    *,
    service: BrokerServiceProfile,
    account_id: str,
    repo_id: str,
    resource_id: str,
    operation: BrokerOperation,
    arguments: Optional[Mapping[str, Any]] = None,
    operation_id: Optional[str] = None,
) -> tuple[str, dict[str, Any]]:
    request = BrokerRequest.create(
        account_id=account_id,
        project_id=repo_id,
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
                1_800.0
                if operation
                in {
                    BrokerOperation.DATABASE_BACKUP,
                    BrokerOperation.DATABASE_RESTORE,
                }
                else 60.0
            )
            if operation
            in {
                BrokerOperation.REPOSITORY_REMOVE,
                BrokerOperation.RESOURCE_ATTACH,
                BrokerOperation.RESOURCE_RETIRE,
                BrokerOperation.DATABASE_BACKUP,
                BrokerOperation.DATABASE_RESTORE,
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
    return profile_from_document(document, effective_uid=uid)


def profile_from_document(
    document: Any, *, effective_uid: int
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
    if int(time.time()) >= valid_until:
        raise BrokerProfileError("host broker enrollment has expired")
    repositories_raw = raw.get("repositories")
    if not isinstance(repositories_raw, list) or not repositories_raw:
        raise BrokerProfileError("broker client has no enrolled repositories")
    repositories: dict[str, BrokerRepositoryProfile] = {}
    for item in repositories_raw:
        repository = _repository_from_document(item)
        if repository.canonical_root in repositories:
            raise BrokerProfileError("broker profile duplicates a canonical repository root")
        repositories[repository.canonical_root] = repository
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


def _repository_from_document(value: Any) -> BrokerRepositoryProfile:
    if not isinstance(value, dict) or set(value) != {
        "canonical_root",
        "repo_id",
        "generation",
        "servers",
        "containers",
        "compose_definition_id",
    }:
        raise BrokerProfileError("broker repository profile fields are invalid")
    canonical_root = str(Path(str(value.get("canonical_root") or "")).expanduser().resolve())
    if not Path(canonical_root).is_absolute():
        raise BrokerProfileError("enrolled repository root must be absolute")
    servers = _identifier_mapping(value.get("servers"), "server")
    containers = _identifier_mapping(value.get("containers"), "container")
    compose_raw = value.get("compose_definition_id")
    compose = None if compose_raw is None else _identifier(compose_raw, "Compose definition")
    return BrokerRepositoryProfile(
        canonical_root=canonical_root,
        repo_id=_identifier(value.get("repo_id"), "repository id"),
        generation=_nonnegative_int(value.get("generation"), "repository generation"),
        server_ids=servers,
        container_ids=containers,
        compose_definition_id=compose,
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
