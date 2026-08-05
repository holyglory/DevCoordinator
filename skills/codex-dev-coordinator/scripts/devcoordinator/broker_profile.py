"""Server-published client profile and broker calls.

The standard CLI never discovers a broker by probing.  On a managed host,
Unix accounts are attribution identities for one trusted developer rather
than separate security tenants, so file ownership and mode bits are not
profile authorization evidence. Profiles published for local accounts are
merged; each repository still carries its exact configured account and
normalized resource IDs.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Mapping, Optional, Sequence

from .broker import (
    BrokerClient,
    BrokerError,
    BrokerOperation,
    BrokerRequest,
    DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS,
    DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS,
)
from .ephemeral_secrets import EphemeralSecretPolicy, normalize_ephemeral_secret_policy
from .universal_test_contract import TestManifest, manifest_to_document
from .universal_test_planner import TestPlan


PROFILE_VERSION = 1
REPOSITORY_PROFILE_FIELDS = frozenset(
    {
        "canonical_root",
        "repo_id",
        "generation",
        "owner_uid",
        "servers",
        "containers",
        "compose_definition_id",
        "compose_container_ids",
        "compose_run_once_services",
        "ephemeral_templates",
        "ephemeral_image_prefetch_templates",
        "ephemeral_secret_policies",
        "account_id",
        "enabled",
        "issued_at",
        "valid_until_epoch",
    }
)
REPOSITORY_ENSURE_EVIDENCE_FIELDS = frozenset(
    {"execution_uid", "filesystem_owner_uid"}
)
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
_COMPOSE_SERVICE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _canonical_repository_lookup_root(value: str) -> str:
    """Normalize an authority root without using local traversal as admission.

    Broker-issued repository roots are absolute opaque identities.  A protected
    client may legitimately be unable to traverse another trusted local
    account's home, so resolving an already-absolute authority path through the
    client filesystem would turn local permissions into an unintended gate.
    Relative interactive input keeps the existing filesystem resolution.
    """

    expanded = Path(value).expanduser()
    if expanded.is_absolute():
        return os.path.normpath(str(expanded))
    return str(expanded.resolve())


class BrokerProfileError(RuntimeError):
    """A configured broker profile is missing, stale, or unsafe."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        classification: str | None = None,
        phase: str = "client",
    ) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        if classification is not None:
            self.classification = classification
        self.phase = phase


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
    owner_uid: int
    server_ids: Mapping[str, str]
    container_ids: Mapping[str, str]
    compose_definition_id: Optional[str]
    compose_container_ids: frozenset[str]
    compose_run_once_services: Mapping[str, int]
    ephemeral_templates: Mapping[str, str]
    ephemeral_image_prefetch_template_ids: frozenset[str]
    ephemeral_secret_policies: Mapping[str, EphemeralSecretPolicyProfile]
    account_id: str
    enabled: bool
    issued_at: str
    valid_until_epoch: int
    execution_uid: Optional[int] = None
    filesystem_owner_uid: Optional[int] = None

    def require_account(self, *, account_id: str) -> None:
        """Bind even retained cleanup calls to the profile's exact account."""

        if self.account_id != account_id:
            raise BrokerProfileError(
                "repository broker enrollment belongs to another account"
            )

    def require_current(self, *, account_id: str) -> None:
        self.require_account(account_id=account_id)
        if not self.enabled:
            raise BrokerProfileError(
                "repository broker enrollment is disabled; rerun Coordinator skill installation"
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

    def compose_run_once_timeout(
        self,
        service: str,
        *,
        timeout_seconds: int,
    ) -> int:
        name = str(service)
        maximum = self.compose_run_once_services.get(name)
        if maximum is None:
            raise BrokerProfileError(
                f"Compose run-once service {name!r} is not explicitly enrolled; "
                "rerun Coordinator skill installation with the reviewed service grant"
            )
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= maximum
        ):
            raise BrokerProfileError(
                f"Compose run-once timeout must be from one through {maximum} seconds"
            )
        return timeout_seconds

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

    def repository_account_id(self, repository: BrokerRepositoryProfile) -> str:
        """Return the repository's declared account in the merged host view."""

        return repository.account_id

    def _require_repository_current(
        self, repository: BrokerRepositoryProfile
    ) -> None:
        repository.require_current(
            account_id=self.repository_account_id(repository)
        )

    def _require_repository_account(
        self, repository: BrokerRepositoryProfile
    ) -> None:
        repository.require_account(
            account_id=self.repository_account_id(repository)
        )

    def _current_transport_anchor(self) -> BrokerRepositoryProfile:
        current: list[BrokerRepositoryProfile] = []
        for candidate in self.repositories.values():
            try:
                self._require_repository_current(candidate)
            except BrokerProfileError:
                continue
            current.append(candidate)
        if not current:
            raise BrokerProfileError(
                "authenticated account has no current repository enrollment for broker access"
            )
        return min(current, key=lambda item: (item.repo_id, item.canonical_root))

    def repository_if_enrolled(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile | None:
        """Return one exact current enrollment without treating absence as failure.

        Repository discovery is a pure client-side lookup.  Callers use this
        distinction to report a valid Git root as ``unenrolled`` while keeping
        first-use adoption on a start-like broker mutation.
        """

        # Broker-issued absolute roots are opaque authority identities. Never
        # make a protected client's ability to traverse another trusted local
        # account's home a prerequisite for this read-only lookup.
        canonical = _canonical_repository_lookup_root(canonical_root)
        value = self.repositories.get(canonical)
        if value is None:
            return None
        self._require_repository_current(value)
        return value

    def repository(self, canonical_root: str) -> BrokerRepositoryProfile:
        value = self.repository_if_enrolled(canonical_root)
        if value is None:
            canonical = _canonical_repository_lookup_root(canonical_root)
            raise BrokerProfileError(
                f"repository {canonical} is not enrolled; this eligible first-use "
                "Git root has not yet been adopted. Local fallback is intentionally "
                "disabled, so use "
                "`devcoordinator runtime serve --help` and submit one structured serve call",
                code="repository_unenrolled",
                classification="repository_bootstrap_required",
            )
        return value

    def resolve_repository(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile | None:
        """Read an adopted repository that is newer than the installed profile."""

        canonical = _canonical_repository_lookup_root(canonical_root)
        existing = self.repository_if_enrolled(canonical)
        if existing is not None:
            return existing
        return self.refresh_repository(canonical)

    def refresh_repository(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile | None:
        """Refresh one repository's retained broker-issued runtime identities.

        Installed profiles are deliberately immutable.  Temporary services are
        created after installation, so exact retained status calls need a
        small authority refresh even after the service has aged out of the
        normal active inventory projection.
        """

        canonical = _canonical_repository_lookup_root(canonical_root)
        anchor = self._current_transport_anchor()
        _operation_id, result = self.call(
            repository=anchor,
            resource_id=anchor.repo_id,
            operation=BrokerOperation.REPOSITORY_RESOLVE,
            arguments={"canonical_root": canonical},
        )
        state = result.get("state")
        if state == "unenrolled":
            return None
        if state != "enrolled":
            raise BrokerProfileError(
                "repository exists but is not eligible for first-use runtime access"
            )
        repository_document = result.get("repository")
        repository_account_id = (
            str(repository_document.get("account_id") or "")
            if isinstance(repository_document, dict)
            else ""
        )
        # The protected client can dynamically merge one broker-issued route
        # owned by another trusted local account.  The physical caller remains
        # the kernel peer; this account value only selects the already-enabled
        # typed policy for the exact repository and resource identities.
        repository = _repository_from_document(
            repository_document, account_id=repository_account_id
        )
        if repository.canonical_root != canonical:
            raise BrokerProfileError(
                "repository resolution returned another canonical root"
            )
        if not isinstance(self.repositories, dict):
            raise BrokerProfileError(
                "broker profile repository view cannot accept dynamic enrollment"
            )
        self.repositories[canonical] = repository
        return repository

    def retained_ephemeral_repository(
        self, canonical_root: str
    ) -> BrokerRepositoryProfile:
        """Resolve one recorded repo for retained status/cleanup calls.

        This deliberately does not discover repositories or revive a disabled
        enrollment. The protected profile supplies only the exact opaque repo
        identity; the broker still proves the run belongs to the exact
        configured account/repository and permits only ``ephemeral.status`` or
        ``ephemeral.finish`` after revocation.
        """

        canonical = str(Path(canonical_root).expanduser().resolve())
        value = self.repositories.get(canonical)
        if value is None:
            raise BrokerProfileError(
                f"repository {canonical} is not recorded in the configured host "
                "broker profile; retained ephemeral cleanup cannot discover it"
            )
        self._require_repository_account(value)
        return value

    def repository_for_server_id(self, server_id: str) -> BrokerRepositoryProfile:
        """Resolve one fixed runner ID only through current protected enrollments."""

        candidate = str(server_id)
        matches: list[BrokerRepositoryProfile] = []
        for repository in self.repositories.values():
            try:
                self._require_repository_current(repository)
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

    def repository_by_id(self, repo_id: str) -> BrokerRepositoryProfile:
        """Resolve one immutable repository id through current enrollments."""

        matches: list[BrokerRepositoryProfile] = []
        for repository in self.repositories.values():
            try:
                self._require_repository_current(repository)
            except BrokerProfileError:
                continue
            if repository.repo_id == str(repo_id):
                matches.append(repository)
        if len(matches) != 1:
            raise BrokerProfileError(
                "repository identity is not uniquely present in the protected enrollment"
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
        transport_timeout_seconds: float | None = None,
    ) -> tuple[str, dict[str, Any]]:
        retained_ephemeral = operation in {
            BrokerOperation.EPHEMERAL_STATUS,
            BrokerOperation.EPHEMERAL_FINISH,
        }
        if retained_ephemeral:
            self._require_repository_account(repository)
        else:
            self._require_repository_current(repository)
        call_arguments: dict[str, Any] = {
            "service": self.service,
            "account_id": self.repository_account_id(repository),
            "repo_id": repository.repo_id,
            "repository_generation": repository.generation,
            "resource_id": resource_id,
            "operation": operation,
            "arguments": arguments,
            "operation_id": operation_id,
        }
        if transport_timeout_seconds is not None:
            call_arguments["transport_timeout_seconds"] = transport_timeout_seconds
        return call_broker(**call_arguments)

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
                    self._require_repository_current(candidate)
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

    def operation_follow(
        self,
        *,
        repository: BrokerRepositoryProfile,
        operation_id: str,
    ) -> dict[str, Any]:
        """Read one durable operation through its exact current repository."""

        _request_operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.OPERATION_FOLLOW,
            arguments={"operation_id": operation_id},
        )
        return result

    def ensure_repository(
        self,
        *,
        canonical_root: str,
        owner_uid: int,
        project_kind: str,
        agent: str,
        operation_id: str,
    ) -> BrokerRepositoryProfile:
        repository, _changed = self.ensure_repository_with_outcome(
            canonical_root=canonical_root,
            owner_uid=owner_uid,
            project_kind=project_kind,
            agent=agent,
            operation_id=operation_id,
        )
        return repository

    def ensure_repository_with_outcome(
        self,
        *,
        canonical_root: str,
        owner_uid: int,
        project_kind: str,
        agent: str,
        operation_id: str,
    ) -> tuple[BrokerRepositoryProfile, bool]:
        """Adopt a proven Git root through one existing transport anchor.

        This method is intentionally called only from a start-like command.
        It contacts the broker even when the repository is already visible so
        an older partial adoption can idempotently reconcile its execution-owner
        enrollment before launch. The returned profile is added to this
        process's merged host view so the immediately following runtime mutation
        uses the broker-issued immutable repository identity without writing an
        installed profile.
        """

        existing = self.resolve_repository(canonical_root)
        anchor = existing if existing is not None else self._current_transport_anchor()
        submitted_operation_id, result = self.call(
            repository=anchor,
            resource_id=anchor.repo_id,
            operation=BrokerOperation.REPOSITORY_ENSURE,
            arguments={
                "agent": agent,
                "canonical_root": canonical_root,
                "owner_uid": owner_uid,
                "project_kind": project_kind,
            },
            operation_id=operation_id,
        )
        if result.get("operation_id") != submitted_operation_id:
            raise BrokerProfileError(
                "repository ensure returned a contradictory operation identity"
            )
        changed = result.get("changed")
        if type(changed) is not bool:
            raise BrokerProfileError(
                "repository ensure omitted its exact mutation outcome"
            )
        repository_document = result.get("repository")
        repository = _repository_from_document(
            repository_document,
            account_id=anchor.account_id,
        )
        expected_root = _canonical_repository_lookup_root(canonical_root)
        if repository.canonical_root != expected_root:
            raise BrokerProfileError(
                "repository ensure returned another canonical root"
            )
        if not isinstance(self.repositories, dict):
            raise BrokerProfileError(
                "broker profile repository view cannot accept first-use enrollment"
            )
        self.repositories[repository.canonical_root] = repository
        return repository, changed

    def runtime_ensure(
        self,
        *,
        repository: BrokerRepositoryProfile,
        resource_id: str,
        target_kind: str,
        desired_state: str,
        agent: str,
        root_repo_id: str,
        temporary_repo_id: str | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        """Ensure one exact enrolled runtime target through broker policy."""

        submitted_operation_id, result = self.call(
            repository=repository,
            resource_id=resource_id,
            operation=BrokerOperation.RUNTIME_ENSURE,
            arguments={
                "agent": agent,
                "root_repo_id": root_repo_id,
                "temporary_repo_id": temporary_repo_id,
                "target_kind": target_kind,
                "desired_state": desired_state,
            },
            operation_id=operation_id,
        )
        if result.get("operation_id") != submitted_operation_id:
            raise BrokerError(
                "invalid_reply",
                "Runtime ensure result does not match the submitted operation ID.",
                operation_id=submitted_operation_id,
            )
        return result

    def capabilities(self, *, canonical_root: str | None = None) -> dict[str, Any]:
        """Read the active authority contract through one exact enrollment."""

        if canonical_root is not None:
            repository = self.repository(canonical_root)
        else:
            repository = self._current_transport_anchor()
        _operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.CAPABILITIES_READ,
            arguments={},
        )
        return result

    def events(
        self, *, after: str | None = None, limit: int = 100
    ) -> dict[str, Any]:
        """Read the host-wide durable event journal through one enrollment."""

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

    def fleet_test_statistics(self, *, hours: int = 24) -> dict[str, Any]:
        """Read one host-wide bounded test projection through one enrollment."""

        current: list[BrokerRepositoryProfile] = []
        for candidate in self.repositories.values():
            try:
                self._require_repository_current(candidate)
            except BrokerProfileError:
                continue
            current.append(candidate)
        if not current:
            raise BrokerProfileError(
                "authenticated account has no current repository enrollment for fleet test access"
            )
        repository = min(current, key=lambda item: item.canonical_root)
        _operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.TEST_FLEET_STATS_READ,
            arguments={"hours": hours},
        )
        return result

    def test_health(self) -> dict[str, Any]:
        """Read protected testd/store identity through authenticated broker ACLs."""

        return self._test_call(
            operation=BrokerOperation.TEST_HEALTH,
            arguments={},
        )

    def test_repository_catalog(self) -> dict[str, Any]:
        """Read the exact enrolled catalog joined to retained testd setup state."""

        repository = self._test_namespace_anchor()
        _operation_id, result = self.call(
            repository=repository,
            resource_id=repository.repo_id,
            operation=BrokerOperation.TEST_REPOSITORY_CATALOG,
            arguments={},
        )
        rows = result.get("repositories")
        if not isinstance(rows, list):
            raise BrokerProfileError("broker returned an invalid test repository catalog")
        return result

    def _test_namespace_anchor(self) -> BrokerRepositoryProfile:
        """Select only a transport anchor for an opaque plan or run identity.

        Plan and run identifiers intentionally do not encode a repository.  The
        broker resolves their immutable repository in testd and then performs a
        second, exact authorization against the current protected enrollment
        before returning data or mutating state.  This deterministic anchor is
        therefore not treated as ownership evidence.
        """

        current: list[BrokerRepositoryProfile] = []
        for candidate in self.repositories.values():
            try:
                self._require_repository_current(candidate)
            except BrokerProfileError:
                continue
            current.append(candidate)
        if not current:
            raise BrokerProfileError(
                "authenticated account has no current repository enrollment for test access"
            )
        return min(current, key=lambda item: (item.repo_id, item.canonical_root))

    def _test_call(
        self,
        *,
        operation: BrokerOperation,
        arguments: Mapping[str, Any],
        operation_id: str | None = None,
        repository: BrokerRepositoryProfile | None = None,
        expose_operation_id: bool = False,
        transport_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        anchor = repository or self._test_namespace_anchor()
        call_arguments: dict[str, Any] = {
            "repository": anchor,
            "resource_id": anchor.repo_id,
            "operation": operation,
            "arguments": arguments,
            "operation_id": operation_id,
        }
        if transport_timeout_seconds is not None:
            call_arguments["transport_timeout_seconds"] = transport_timeout_seconds
        returned_operation_id, result = self.call(**call_arguments)
        if not expose_operation_id:
            return result
        exposed = dict(result)
        embedded = exposed.get("operation_id")
        if embedded is not None and embedded != returned_operation_id:
            raise BrokerProfileError(
                "broker test mutation returned a contradictory operation identity"
            )
        exposed["operation_id"] = returned_operation_id
        return exposed

    def _test_run_call(
        self,
        *,
        repository: str,
        operation: BrokerOperation,
        arguments: Mapping[str, Any],
        operation_id: str | None = None,
        expose_operation_id: bool = False,
        transport_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Bind one opaque run operation to its caller-supplied repository."""

        enrolled = self.repository_by_id(repository)
        result = self._test_call(
            repository=enrolled,
            operation=operation,
            arguments=arguments,
            operation_id=operation_id,
            expose_operation_id=expose_operation_id,
            transport_timeout_seconds=transport_timeout_seconds,
        )
        if result.get("repository_id") != enrolled.repo_id:
            raise BrokerProfileError(
                "broker test run operation belongs to another repository"
            )
        return result

    def register_test_plan(
        self,
        *,
        plan: TestPlan,
        manifest: TestManifest,
        actor: str,
        operation_id: str,
    ) -> dict[str, Any]:
        """Register a locally constructed typed plan through one exact repo."""

        if not isinstance(plan, TestPlan) or not isinstance(manifest, TestManifest):
            raise BrokerProfileError("test plan registration requires typed contracts")
        repository = self.repository(plan.source.original_root)
        if plan.repository_id != repository.repo_id:
            raise BrokerProfileError(
                "test plan repository identity does not match the protected enrollment"
            )
        return self._test_call(
            repository=repository,
            operation=BrokerOperation.TEST_PLAN_REGISTER,
            arguments={
                "plan": plan.to_document(),
                "manifest": manifest_to_document(manifest),
                "actor": str(actor),
            },
            operation_id=str(operation_id),
            expose_operation_id=True,
        )

    def preview_test_plan(
        self,
        *,
        repository: str,
        intent: str,
        temporary_root: str | None = None,
        requested_targets: Sequence[str] = (),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = 300,
        operation_id: str,
    ) -> dict[str, Any]:
        enrolled = self.repository_by_id(repository)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_PLAN_PREVIEW,
            arguments={
                "intent": str(intent),
                "temporary_root": (
                    None if temporary_root is None else str(temporary_root)
                ),
                "requested_targets": [str(item) for item in requested_targets],
                "execution_timeout_seconds": execution_timeout_seconds,
                "launch_timeout_seconds": launch_timeout_seconds,
            },
            operation_id=str(operation_id),
            expose_operation_id=True,
        )

    def submit_test_plan(
        self,
        *,
        repository: str,
        plan_id: str,
        operation_id: str,
        actor: str,
    ) -> dict[str, Any]:
        """Submit only if testd resolves the plan to this exact repository."""

        enrolled = self.repository_by_id(repository)
        arguments = {
            "plan_id": str(plan_id),
            "expected_repository_id": enrolled.repo_id,
            "actor": str(actor),
        }
        return self._test_run_call(
            repository=enrolled.repo_id,
            operation=BrokerOperation.TEST_RUN_SUBMIT,
            arguments=arguments,
            operation_id=str(operation_id),
            expose_operation_id=True,
        )

    def test_run_status(
        self,
        *,
        run_id: str,
        repository: str,
        transport_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_STATUS,
            arguments={"run_id": str(run_id)},
            transport_timeout_seconds=transport_timeout_seconds,
        )

    def test_runs(
        self,
        *,
        repository: str,
        after: str | None = None,
        limit: int = 50,
        state: str | None = None,
    ) -> dict[str, Any]:
        enrolled = self.repository_by_id(repository)
        arguments: dict[str, Any] = {"limit": limit}
        if after is not None:
            arguments["after"] = str(after)
        if state is not None:
            arguments["state"] = str(state)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_RUN_LIST,
            arguments=arguments,
        )

    def test_run_summary(self, *, repository: str, run_id: str) -> dict[str, Any]:
        result = self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_SUMMARY,
            arguments={"run_id": str(run_id)},
        )
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(encoded) > 8 * 1024:
            raise BrokerProfileError("broker test summary exceeds the 8 KiB contract")
        return result

    def test_run_failures(
        self,
        *,
        repository: str,
        run_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {"run_id": str(run_id), "limit": limit}
        if after is not None:
            arguments["after"] = str(after)
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_FAILURES, arguments=arguments
        )

    def test_run_artifacts(
        self,
        *,
        repository: str,
        run_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {"run_id": str(run_id), "limit": limit}
        if after is not None:
            arguments["after"] = str(after)
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_ARTIFACTS, arguments=arguments
        )

    def test_artifact(
        self, *, repository: str, run_id: str, artifact_id: str
    ) -> dict[str, Any]:
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_ARTIFACT_RESOLVE,
            arguments={"run_id": str(run_id), "artifact_id": str(artifact_id)},
        )

    def test_run_cases(
        self, *, repository: str, run_id: str, after: int = 0, limit: int = 25
    ) -> dict[str, Any]:
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_CASES,
            arguments={"run_id": str(run_id), "after": after, "limit": limit},
        )

    def test_events(
        self,
        *,
        repository: str,
        after_event_id: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        enrolled = self.repository_by_id(repository)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_EVENTS_READ,
            arguments={"after_event_id": after_event_id, "limit": limit},
        )

    def test_repository_setup(self, *, repository: str) -> dict[str, Any]:
        enrolled = self.repository_by_id(repository)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_REPOSITORY_SETUP,
            arguments={},
        )

    def cancel_test_run(
        self,
        *,
        repository: str,
        run_id: str,
        reason: str,
        operation_id: str,
        actor: str,
    ) -> dict[str, Any]:
        arguments = {
            "run_id": str(run_id),
            "reason": str(reason),
            "actor": str(actor),
        }
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_CANCEL,
            arguments=arguments,
            operation_id=str(operation_id),
        )

    def retry_test_run(
        self,
        *,
        repository: str,
        run_id: str,
        failed_only: bool,
        operation_id: str,
        actor: str,
    ) -> dict[str, Any]:
        arguments = {
            "run_id": str(run_id),
            "failed_only": failed_only,
            "actor": str(actor),
        }
        return self._test_run_call(
            repository=repository,
            operation=BrokerOperation.TEST_RUN_RETRY,
            arguments=arguments,
            operation_id=str(operation_id),
        )

    def wait_test_run(
        self, *, repository: str, run_id: str, timeout_seconds: int
    ) -> dict[str, Any]:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 0 <= timeout_seconds <= 86_400
        ):
            raise BrokerProfileError("test wait timeout must be 0..86400 seconds")
        deadline = time.monotonic() + timeout_seconds
        terminal = {
            "succeeded",
            "failed",
            "test_failed",
            "infrastructure_failed",
            "timed_out",
            "cancelled",
            "incomplete",
            "abandoned",
            "superseded",
        }
        status: dict[str, Any] | None = None

        def timed_out() -> dict[str, Any]:
            if status is None:
                return {
                    "schema_version": 1,
                    "repository_id": repository,
                    "run_id": str(run_id),
                    "wait_timed_out": True,
                    "status_observed": False,
                }
            return {**status, "wait_timed_out": True}

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return timed_out()
            try:
                status_arguments: dict[str, Any] = {
                    "repository": repository,
                    "run_id": run_id,
                    "transport_timeout_seconds": max(
                        0.001,
                        min(
                            _broker_client_timeout_seconds(
                                BrokerOperation.TEST_RUN_STATUS,
                                arguments={"run_id": str(run_id)},
                            ),
                            remaining,
                        ),
                    ),
                }
                status = self.test_run_status(**status_arguments)
            except BrokerError as error:
                if error.code != "request_timeout":
                    raise
                if deadline - time.monotonic() <= 0:
                    return timed_out()
                continue
            except TimeoutError:
                if deadline - time.monotonic() <= 0:
                    return timed_out()
                continue
            if str(status.get("state") or status.get("status") or "") in terminal:
                return status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return timed_out()
            time.sleep(min(0.25, remaining))

    def check_test_evidence(
        self, *, repository: str, policy: str, snapshot: str
    ) -> dict[str, Any]:
        enrolled = self.repository(repository)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_EVIDENCE_CHECK,
            arguments={
                "snapshot_id": str(snapshot),
                "policy_name": str(policy),
            },
        )

    def consume_test_evidence(
        self,
        *,
        repository: str,
        policy: str,
        snapshot: str,
        operation_id: str,
    ) -> dict[str, Any]:
        enrolled = self.repository(repository)
        return self._test_call(
            repository=enrolled,
            operation=BrokerOperation.TEST_EVIDENCE_CONSUME,
            arguments={
                "snapshot_id": str(snapshot),
                "policy_name": str(policy),
            },
            operation_id=str(operation_id),
        )


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
    transport_timeout_seconds: float | None = None,
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
    if transport_timeout_seconds is not None and (
        isinstance(transport_timeout_seconds, bool)
        or not isinstance(transport_timeout_seconds, (int, float))
        or not math.isfinite(float(transport_timeout_seconds))
        or float(transport_timeout_seconds) <= 0
    ):
        raise BrokerProfileError("broker client timeout must be positive and finite")
    client = BrokerClient(
        service.socket_path,
        expected_broker_uid=service.service_uid,
        expected_socket_gid=service.socket_gid,
        expected_socket_mode=service.socket_mode,
        timeout_seconds=(
            _broker_client_timeout_seconds(operation, arguments=arguments)
            if transport_timeout_seconds is None
            else float(transport_timeout_seconds)
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


def _broker_client_timeout_seconds(
    operation: BrokerOperation,
    *,
    arguments: Optional[Mapping[str, Any]],
) -> float:
    if operation is BrokerOperation.TEST_PLAN_PREVIEW:
        requested = (
            None if arguments is None else arguments.get("launch_timeout_seconds")
        )
        if type(requested) is not int or not 1 <= requested <= 3_600:
            raise BrokerProfileError(
                "Test-plan preview requires a valid launch_timeout_seconds argument"
            )
        # The test-plane call uses the caller's semantic materialization
        # deadline.  Leave a small outer-transport margin so its typed timeout
        # response can reach the calling agent instead of being replaced by a
        # generic ten-second broker timeout.
        # The nested test-plane hop retains a 60-second response margin around
        # the semantic launch deadline. Keep a further broker response margin.
        return float(requested + 90)
    if operation is BrokerOperation.COMPOSE_RUN_ONCE:
        requested = None if arguments is None else arguments.get("timeout_seconds")
        if type(requested) is not int or not 1 <= requested <= 3_600:
            raise BrokerProfileError(
                "Compose run-once call requires a valid timeout_seconds argument"
            )
        return float(requested + 120)
    if operation is BrokerOperation.DATABASE_BACKUP:
        return DATABASE_BACKUP_CLIENT_TIMEOUT_SECONDS
    if operation is BrokerOperation.DATABASE_RESTORE:
        return DATABASE_RESTORE_CLIENT_TIMEOUT_SECONDS
    if operation is BrokerOperation.HOST_OBSERVE:
        return HOST_OBSERVE_CLIENT_TIMEOUT_SECONDS
    if operation is BrokerOperation.INVENTORY_READ:
        return INVENTORY_READ_CLIENT_TIMEOUT_SECONDS
    if operation in {
        BrokerOperation.EPHEMERAL_START,
        BrokerOperation.EPHEMERAL_IMAGE_PREFETCH,
        BrokerOperation.EPHEMERAL_FINISH,
        BrokerOperation.COMPOSE_UP,
        BrokerOperation.COMPOSE_STOP,
        BrokerOperation.COMPOSE_RESTART,
        BrokerOperation.COMPOSE_DOWN,
    }:
        return 5 * 60.0
    if operation in {
        BrokerOperation.REPOSITORY_REMOVE,
        BrokerOperation.RESOURCE_ATTACH,
        BrokerOperation.RESOURCE_RETIRE,
        BrokerOperation.RUNTIME_ENSURE,
        BrokerOperation.RUNTIME_REQUEST,
    }:
        return 60.0
    return 10.0


def configured_profile_path() -> Path:
    raw = str(os.environ.get(PROFILE_PATH_ENV) or "").strip()
    return Path(raw) if raw else SYSTEM_PROFILE_PATH


def _load_broker_profile(
    *,
    path: Path | None = None,
    effective_uid: int | None = None,
    required: bool = False,
    trusted_owner_uid: int = 0,
    host_view: bool,
) -> BrokerClientProfile | None:
    configured_by_environment = bool(str(os.environ.get(PROFILE_PATH_ENV) or "").strip())
    explicitly_configured = path is not None or configured_by_environment
    candidate = (path or configured_profile_path()).expanduser()
    uid = os.geteuid() if effective_uid is None else int(effective_uid)
    try:
        metadata = _validate_profile_file(
            candidate,
            trusted_owner_uid=trusted_owner_uid,
            allow_unmapped_owner=(
                candidate == SYSTEM_PROFILE_PATH and not explicitly_configured
            ),
        )
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
    parser = host_profile_from_document if host_view else profile_from_document
    return parser(
        document,
        effective_uid=uid,
    )


def load_broker_profile(
    *,
    path: Path | None = None,
    effective_uid: int | None = None,
    required: bool = False,
    trusted_owner_uid: int = 0,
) -> BrokerClientProfile | None:
    """Load the same-developer host routing view used by local clients."""

    return _load_broker_profile(
        path=path,
        effective_uid=effective_uid,
        required=required,
        trusted_owner_uid=trusted_owner_uid,
        host_view=True,
    )


def load_exact_broker_profile(
    *,
    path: Path | None = None,
    effective_uid: int | None = None,
    required: bool = False,
    trusted_owner_uid: int = 0,
) -> BrokerClientProfile | None:
    """Load one UID enrollment for a proof that explicitly requires it."""

    return _load_broker_profile(
        path=path,
        effective_uid=effective_uid,
        required=required,
        trusted_owner_uid=trusted_owner_uid,
        host_view=False,
    )


def profile_from_document(
    document: Any,
    *,
    effective_uid: int | None = None,
) -> BrokerClientProfile:
    """Parse exactly one UID enrollment for services and administrative proofs."""

    uid = os.geteuid() if effective_uid is None else int(effective_uid)
    if not isinstance(document, dict):
        raise BrokerProfileError("broker profile fields are invalid")
    clients = document.get("clients")
    raw_client = clients.get(str(uid)) if isinstance(clients, dict) else None
    if raw_client is None:
        raise BrokerProfileError(
            "broker profile has no enrollment for the effective local client"
        )
    _profile_from_document(document, effective_uid=uid)
    scoped = dict(document)
    scoped["clients"] = {str(uid): raw_client}
    return _profile_from_document(
        scoped,
        effective_uid=uid,
    )


def host_profile_from_document(
    document: Any,
    *,
    effective_uid: int | None = None,
) -> BrokerClientProfile:
    """Parse all valid local enrollments as one repository-routing view."""

    return _profile_from_document(
        document,
        effective_uid=effective_uid,
    )


def _profile_from_document(
    document: Any,
    *,
    effective_uid: int | None = None,
) -> BrokerClientProfile:
    effective_uid = os.geteuid() if effective_uid is None else int(effective_uid)
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
    if not 0 <= socket_mode <= 0o7777:
        raise BrokerProfileError("broker socket mode must be a valid permission mode")
    generation = _identifier(service_raw.get("database_generation"), "database generation")

    clients = document.get("clients")
    if not isinstance(clients, dict) or not clients:
        raise BrokerProfileError("broker clients must be an object")

    # All Unix accounts on this host are one developer trust domain. Parse the
    # atomically published client set and expose its repository grants as one
    # view; the effective UID remains attribution only.
    parsed_clients: list[tuple[int, str, str, int, list[Any]]] = []
    required_client_fields = {
        "account_id",
        "issued_at",
        "valid_until_epoch",
        "repositories",
    }
    for raw_uid, raw in clients.items():
        try:
            client_uid = int(str(raw_uid), 10)
        except (TypeError, ValueError) as error:
            raise BrokerProfileError("broker profile client UID is invalid") from error
        if client_uid < 0 or str(client_uid) != str(raw_uid):
            raise BrokerProfileError("broker profile client UID is invalid")
        if not isinstance(raw, dict) or set(raw) != required_client_fields:
            raise BrokerProfileError("broker client profile fields are invalid")
        client_account_id = _identifier(raw.get("account_id"), "account id")
        client_valid_until = _positive_int(
            raw.get("valid_until_epoch"), "profile expiry"
        )
        client_issued_at = raw.get("issued_at")
        if not isinstance(client_issued_at, str) or not client_issued_at:
            raise BrokerProfileError("broker client profile issued-at is invalid")
        repositories_raw = raw.get("repositories")
        if not isinstance(repositories_raw, list) or not repositories_raw:
            raise BrokerProfileError(
                "broker client profile repositories must be a non-empty list"
            )
        parsed_clients.append(
            (
                client_uid,
                client_account_id,
                client_issued_at,
                client_valid_until,
                repositories_raw,
            )
        )
    if not parsed_clients:
        raise BrokerProfileError("broker profile has no valid local client enrollment")

    selected = next(
        (item for item in parsed_clients if item[0] == effective_uid),
        None,
    )
    if selected is None:
        selected = max(
            parsed_clients,
            key=lambda item: (
                item[3],
                item[2],
                -item[0],
            ),
        )
    _selected_uid, account_id, issued_at, valid_until, _selected_repositories = (
        selected
    )
    repositories: dict[str, BrokerRepositoryProfile] = {}
    repository_ranks: dict[str, tuple[bool, int, bool, bool, int, int]] = {}
    for (
        client_uid,
        client_account,
        _client_issued_at,
        _client_expiry,
        items,
    ) in parsed_clients:
        for item in items:
            repository = _repository_from_document(
                item,
                account_id=client_account,
            )
            rank = (
                repository.enabled,
                repository.generation,
                client_uid == effective_uid,
                client_uid == repository.owner_uid,
                repository.valid_until_epoch,
                -client_uid,
            )
            if rank > repository_ranks.get(
                repository.canonical_root, (False, -1, False, False, -1, 0)
            ):
                repositories[repository.canonical_root] = repository
                repository_ranks[repository.canonical_root] = rank
    if not repositories:
        raise BrokerProfileError("broker profile has no enrolled repositories")
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
        issued_at=issued_at,
        valid_until_epoch=valid_until,
        repositories=repositories,
    )


def _repository_from_document(
    value: Any,
    *,
    account_id: str,
) -> BrokerRepositoryProfile:
    if not isinstance(value, dict):
        raise BrokerProfileError("broker repository profile fields are invalid")
    fields = set(value)
    if fields not in {
        REPOSITORY_PROFILE_FIELDS,
        REPOSITORY_PROFILE_FIELDS | REPOSITORY_ENSURE_EVIDENCE_FIELDS,
    }:
        raise BrokerProfileError("broker repository profile fields are invalid")
    execution_uid: int | None = None
    filesystem_owner_uid: int | None = None
    if REPOSITORY_ENSURE_EVIDENCE_FIELDS <= fields:
        execution_uid = _nonnegative_int(value["execution_uid"], "execution UID")
        filesystem_owner_uid = _nonnegative_int(
            value["filesystem_owner_uid"], "filesystem owner UID"
        )
    canonical_root = _canonical_repository_lookup_root(
        str(value.get("canonical_root") or "")
    )
    if not Path(canonical_root).is_absolute():
        raise BrokerProfileError("enrolled repository root must be absolute")
    servers = _identifier_mapping(value["servers"], "server")
    containers = _identifier_mapping(value["containers"], "container")
    ephemeral_templates = _identifier_mapping(
        value["ephemeral_templates"], "ephemeral template"
    )
    ephemeral_secret_policies = _ephemeral_secret_policy_mapping(
        value["ephemeral_secret_policies"]
    )
    ephemeral_image_prefetch_template_ids = _ephemeral_image_prefetch_template_ids(
        value["ephemeral_image_prefetch_templates"],
        template_ids=frozenset(ephemeral_templates.values()),
    )
    if not set(ephemeral_secret_policies) <= set(ephemeral_templates):
        raise BrokerProfileError(
            "ephemeral credential policy references an unknown template"
        )
    compose_raw = value["compose_definition_id"]
    compose = None if compose_raw is None else _identifier(compose_raw, "Compose definition")
    compose_run_once_services = _compose_run_once_service_mapping(
        value["compose_run_once_services"]
    )
    compose_container_ids = _compose_container_id_set(
        value["compose_container_ids"],
        enrolled_container_ids=frozenset(containers.values()),
    )
    if compose_run_once_services and compose is None:
        raise BrokerProfileError(
            "Compose run-once services require one enrolled Compose definition"
        )
    if compose_container_ids and compose is None:
        raise BrokerProfileError(
            "Compose-owned containers require one enrolled Compose definition"
        )
    repository_account_id = _identifier(
        value["account_id"], "repository account id"
    )
    if repository_account_id != account_id:
        raise BrokerProfileError(
            "broker repository profile belongs to another account"
        )
    enabled = value["enabled"]
    if type(enabled) is not bool:
        raise BrokerProfileError("repository enrollment enabled must be boolean")
    issued_at = str(value["issued_at"] or "")
    if not issued_at:
        raise BrokerProfileError("repository profile issued-at is invalid")
    valid_until_epoch = _positive_int(
        value["valid_until_epoch"], "repository profile expiry"
    )
    owner_uid = _positive_int(value["owner_uid"], "repository owner UID")
    if execution_uid is not None and execution_uid != owner_uid:
        raise BrokerProfileError(
            "repository execution evidence contradicts its execution owner"
        )
    return BrokerRepositoryProfile(
        canonical_root=canonical_root,
        repo_id=_identifier(value["repo_id"], "repository id"),
        generation=_nonnegative_int(value["generation"], "repository generation"),
        owner_uid=owner_uid,
        server_ids=servers,
        container_ids=containers,
        compose_definition_id=compose,
        compose_container_ids=compose_container_ids,
        compose_run_once_services=compose_run_once_services,
        ephemeral_templates=ephemeral_templates,
        ephemeral_image_prefetch_template_ids=ephemeral_image_prefetch_template_ids,
        ephemeral_secret_policies=ephemeral_secret_policies,
        account_id=repository_account_id,
        enabled=enabled,
        issued_at=issued_at,
        valid_until_epoch=valid_until_epoch,
        execution_uid=execution_uid,
        filesystem_owner_uid=filesystem_owner_uid,
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


def _compose_run_once_service_mapping(value: Any) -> Mapping[str, int]:
    if not isinstance(value, dict) or len(value) > 32:
        raise BrokerProfileError(
            "broker Compose run-once service mapping must be a bounded object"
        )
    result: dict[str, int] = {}
    for raw_name, raw_timeout in value.items():
        if (
            not isinstance(raw_name, str)
            or _COMPOSE_SERVICE_NAME.fullmatch(raw_name) is None
            or type(raw_timeout) is not int
            or not 600 <= raw_timeout <= 3_600
        ):
            raise BrokerProfileError(
                "broker Compose run-once service policy is invalid"
            )
        result[raw_name] = raw_timeout
    return result


def _compose_container_id_set(
    value: Any, *, enrolled_container_ids: frozenset[str]
) -> frozenset[str]:
    """Parse the exact subset owned by the enrolled Compose definition."""

    if not isinstance(value, list) or len(value) > 4_096:
        raise BrokerProfileError(
            "broker Compose-owned container IDs must be a bounded list"
        )
    result = tuple(
        _identifier(item, "Compose-owned container resource id") for item in value
    )
    if len(set(result)) != len(result):
        raise BrokerProfileError(
            "broker Compose-owned container resource ID list has duplicates"
        )
    if not set(result) <= enrolled_container_ids:
        raise BrokerProfileError(
            "broker Compose-owned container resource is not enrolled"
        )
    return frozenset(result)


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


def _validate_profile_file(
    path: Path,
    *,
    trusted_owner_uid: int,
    allow_unmapped_owner: bool = False,
) -> os.stat_result:
    del trusted_owner_uid, allow_unmapped_owner
    if not path.is_absolute() or ".." in path.parts:
        raise BrokerProfileError("broker profile path must be absolute without traversal")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BrokerProfileError("broker profile path contains a non-directory or symlink")
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokerProfileError("broker profile must be a regular non-symlink file")
    if metadata.st_size > 1024 * 1024:
        raise BrokerProfileError("broker profile exceeds the one-megabyte bound")
    return metadata
