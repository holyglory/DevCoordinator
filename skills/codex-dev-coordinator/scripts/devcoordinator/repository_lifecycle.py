"""Crash-resumable repository and exact-resource lifecycle orchestration.

This module owns lifecycle policy, not host discovery or persistence plumbing.
The injected persistence implementation must make every method documented as
atomic one database transaction.  The injected host adapter must operate on
immutable host-resource identities; display names are intentionally absent
from every mutation contract.

The important ordering invariant is::

    durable start fence -> disable every startup policy -> stop exact targets
    -> verify stopped boundaries -> deactivate leases/assignments -> hide

Slow host operations never run inside a database transaction.  A crash after
an external effect is safe because each phase re-observes the exact target and
recognises an already-completed effect before repeating it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
import hashlib
import json
from typing import Any, Callable, Mapping, Protocol, Sequence, Union
import uuid


SCHEMA_VERSION = 1
RETAINED_DATA = (
    "repository_files",
    "containers",
    "volumes",
    "databases",
    "backups",
    "audit_history",
)


class LifecycleError(RuntimeError):
    """Base class for an expected, fail-closed lifecycle refusal."""


class PlanDriftError(LifecycleError):
    """The repository/resource no longer matches the immutable plan."""


class OwnershipError(LifecycleError):
    """Exact control ownership could not be proved."""


class ActionFencedError(LifecycleError):
    """A repository or resource is not installed/enabled for mutation."""


class ConcurrentLifecycleError(LifecycleError):
    """Another lifecycle action owns the target boundary."""


class ExplicitConfirmationRequired(LifecycleError):
    """A caller attempted reinstall without the explicit skill journey."""


class ResourceKind(str, Enum):
    SERVER = "server"
    CONTAINER = "container"
    SUPERVISOR = "supervisor"


class PolicyKind(str, Enum):
    DOCKER_RESTART = "docker_restart"
    COMPOSE = "compose"
    SUPERVISOR = "supervisor"
    COORDINATOR = "coordinator"


class AllocationKind(str, Enum):
    LEASE = "lease"
    PORT_ASSIGNMENT = "port_assignment"


class RepositoryAction(str, Enum):
    START = "start"
    STOP = "stop"
    REGISTER = "register"
    COMPOSE = "compose"
    LEASE = "lease"


class TargetPhase(IntEnum):
    PENDING = 0
    POLICIES_DISABLED = 10
    STOPPED = 20
    VERIFIED = 30
    ALLOCATIONS_DEACTIVATED = 40
    COMPLETE = 50


class OperationStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    NEEDS_ATTENTION = "needs_attention"


class RunningState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    ZOMBIE = "zombie"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StartupPolicyRef:
    policy_id: str
    kind: PolicyKind
    immutable_fingerprint: str
    disabled_value: str

    def __post_init__(self) -> None:
        _require_identity("policy_id", self.policy_id)
        _require_identity("policy immutable_fingerprint", self.immutable_fingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "kind": self.kind.value,
            "immutable_fingerprint": self.immutable_fingerprint,
            "disabled_value": self.disabled_value,
        }


@dataclass(frozen=True)
class AllocationRef:
    allocation_id: str
    kind: AllocationKind
    immutable_fingerprint: str

    def __post_init__(self) -> None:
        _require_identity("allocation_id", self.allocation_id)
        _require_identity("allocation immutable_fingerprint", self.immutable_fingerprint)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allocation_id": self.allocation_id,
            "kind": self.kind.value,
            "immutable_fingerprint": self.immutable_fingerprint,
        }


@dataclass(frozen=True)
class ExactResourceRef:
    """A mutation identity.  A name is deliberately not part of this type."""

    resource_id: str
    kind: ResourceKind
    immutable_fingerprint: str
    control_binding_id: str
    ownership_fingerprint: str
    policies: tuple[StartupPolicyRef, ...] = ()
    allocations: tuple[AllocationRef, ...] = ()
    native_identity: tuple[tuple[str, str], ...] = ()
    # Stable controller identity excluding observation-generation churn.  The
    # generation-bearing ownership_fingerprint remains the exact snapshot
    # identity used by a single host action; this contract is what permits a
    # later observation to prove that the same controller still owns it.
    control_contract_fingerprint: str = ""

    def __post_init__(self) -> None:
        _require_identity("resource_id", self.resource_id)
        _require_identity("immutable_fingerprint", self.immutable_fingerprint)
        _require_identity("control_binding_id", self.control_binding_id)
        _require_identity("ownership_fingerprint", self.ownership_fingerprint)
        if len({item.policy_id for item in self.policies}) != len(self.policies):
            raise ValueError("duplicate startup policy identity")
        if len({(item.kind, item.allocation_id) for item in self.allocations}) != len(
            self.allocations
        ):
            raise ValueError("duplicate allocation identity")
        native_keys = [str(key) for key, _value in self.native_identity]
        if len(set(native_keys)) != len(native_keys):
            raise ValueError("duplicate native identity field")

    @property
    def ledger_key(self) -> tuple[str, str]:
        return (self.kind.value, self.resource_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.resource_id,
            "kind": self.kind.value,
            "host_resource_id": self.resource_id,
            "immutable_fingerprint": self.immutable_fingerprint,
            "control_binding_id": self.control_binding_id,
            "ownership_fingerprint": self.ownership_fingerprint,
            "control_contract_fingerprint": self.control_contract_fingerprint,
            "native_identity": {
                str(key): str(value) for key, value in self.native_identity
            },
            "policies": [item.to_dict() for item in self.policies],
            "allocations": [item.to_dict() for item in self.allocations],
        }


@dataclass(frozen=True)
class RepositorySnapshot:
    repo_id: str
    repository_fingerprint: str
    installation_generation: int
    installation_status: str
    startup_fenced: bool
    hidden: bool
    targets: tuple[ExactResourceRef, ...]
    repository_allocations: tuple[AllocationRef, ...] = ()
    unresolved_conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class StandaloneSnapshot:
    resource: ExactResourceRef
    retirement_status: str | None
    attached_repo_id: str | None
    authority_state: str


@dataclass(frozen=True)
class RepositoryDecommissionPlan:
    plan_id: str
    repo_id: str
    repository_fingerprint: str
    installation_generation: int
    fingerprint: str
    created_at: str
    actor: str
    reason: str
    targets: tuple[ExactResourceRef, ...]
    repository_allocations: tuple[AllocationRef, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "repository_decommission",
            "plan_id": self.plan_id,
            "repo_id": self.repo_id,
            "repository_fingerprint": self.repository_fingerprint,
            "installation_generation": self.installation_generation,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "actor": self.actor,
            "reason": self.reason,
            "retained_data": list(RETAINED_DATA),
            "targets": [item.to_dict() for item in self.targets],
            "repository_allocations": [
                item.to_dict() for item in self.repository_allocations
            ],
        }


@dataclass(frozen=True)
class StandaloneRetirementPlan:
    plan_id: str
    fingerprint: str
    created_at: str
    actor: str
    reason: str
    target: ExactResourceRef
    # Canonical archive plans may target an exact resource that remains
    # attached to its repository.  Legacy standalone retirement plans keep
    # this unset and retain their historical rejection of attached resources.
    repo_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "standalone_resource_retirement",
            "plan_id": self.plan_id,
            "resource_id": self.target.resource_id,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "actor": self.actor,
            "reason": self.reason,
            "repo_id": self.repo_id,
            "retained_data": list(RETAINED_DATA),
            "targets": [self.target.to_dict()],
        }


LifecyclePlan = Union[RepositoryDecommissionPlan, StandaloneRetirementPlan]


@dataclass(frozen=True)
class PolicyObservation:
    policy_id: str
    immutable_fingerprint: str | None
    observable: bool
    disabled: bool | None
    value: str | None
    docker_restart_policy: str | None = None
    supervisor_manager: str | None = None
    supervisor_unit_file_state: str | None = None
    supervisor_loaded: bool | None = None
    supervisor_enabled: bool | None = None


@dataclass(frozen=True)
class CapturedStartupPolicyState:
    """Authoritative pre-disable state retained for an exact later restore.

    The normalized store, rather than diagnostic operation JSON, owns these
    values.  ``native_identity_fingerprint`` binds the capture to the exact
    container/unit identity that was observed before the policy mutation.
    """

    policy_id: str
    repo_id: str | None
    resource_kind: ResourceKind
    resource_id: str
    policy_kind: PolicyKind
    policy_immutable_fingerprint: str
    target_immutable_fingerprint: str
    control_binding_id: str
    ownership_fingerprint: str
    native_identity_fingerprint: str
    captured_value: str
    restore_required: bool
    status: str
    docker_restart_policy: str | None = None
    supervisor_manager: str | None = None
    supervisor_unit_file_state: str | None = None
    supervisor_loaded: bool | None = None
    supervisor_enabled: bool | None = None


@dataclass(frozen=True)
class StartupPolicyRestorationResult:
    repo_id: str
    permit_id: str
    restored_policy_ids: tuple[str, ...]
    already_restored_policy_ids: tuple[str, ...]
    not_required_policy_ids: tuple[str, ...]
    host_may_have_started: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "repo_id": self.repo_id,
            "permit_id": self.permit_id,
            "restored_policy_ids": list(self.restored_policy_ids),
            "already_restored_policy_ids": list(self.already_restored_policy_ids),
            "not_required_policy_ids": list(self.not_required_policy_ids),
            "host_may_have_started": self.host_may_have_started,
        }


@dataclass(frozen=True)
class ResourceObservation:
    resource_id: str
    kind: ResourceKind
    identity_observable: bool
    immutable_fingerprint: str | None
    ownership_observable: bool
    ownership_fingerprint: str | None
    running_state: RunningState
    listener_active: bool | None = None
    container_running: bool | None = None
    supervisor_active: bool | None = None
    replacement_fingerprint: str | None = None
    policies: Mapping[str, PolicyObservation] = field(default_factory=dict)


@dataclass(frozen=True)
class TargetProgress:
    target_kind: ResourceKind
    target_id: str
    phase: TargetPhase
    status: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    error: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class OperationProgress:
    operation_id: str
    status: OperationStatus
    fence_retained: bool
    hidden: bool
    targets: Mapping[tuple[str, str], TargetProgress]
    errors: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True)
class ActionPermit:
    permit_id: str
    repo_id: str | None
    resource_id: str | None
    action: RepositoryAction
    generation: int


@dataclass(frozen=True)
class InstallationResult:
    repo_id: str
    status: str
    hidden: bool
    started: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "repo_id": self.repo_id,
            "status": self.status,
            "hidden": self.hidden,
            "started": self.started,
        }


@dataclass(frozen=True)
class AttachResult:
    repo_id: str
    resource_id: str
    resource_kind: ResourceKind
    attached: bool
    started: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "repo_id": self.repo_id,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind.value,
            "attached": self.attached,
            "started": self.started,
        }


@dataclass(frozen=True)
class LifecycleResult:
    operation_id: str
    plan: LifecyclePlan
    status: str
    fence: str
    hidden: bool
    progress: OperationProgress

    def to_dict(self) -> dict[str, Any]:
        repo_id = self.plan.repo_id
        resource_id = (
            self.plan.target.resource_id if isinstance(self.plan, StandaloneRetirementPlan) else None
        )
        target_results = []
        for target in self.plan.targets if isinstance(self.plan, RepositoryDecommissionPlan) else (self.plan.target,):
            state = self.progress.targets[target.ledger_key]
            target_results.append(
                {
                    "target_id": target.resource_id,
                    "kind": target.kind.value,
                    "status": state.status,
                    "phase": state.phase.name.lower(),
                    "evidence": dict(state.evidence),
                    "error": dict(state.error) if state.error else None,
                }
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "plan_id": self.plan.plan_id,
            "plan_fingerprint": self.plan.fingerprint,
            "kind": (
                "repository_decommission"
                if isinstance(self.plan, RepositoryDecommissionPlan)
                else "standalone_resource_retirement"
            ),
            "repo_id": repo_id,
            "resource_id": resource_id,
            "status": self.status,
            "fence": self.fence,
            "hidden": self.hidden,
            "started": False,
            "retained_data": list(RETAINED_DATA),
            "targets": target_results,
            "errors": [dict(item) for item in self.progress.errors],
        }


class HostLifecycleAdapter(Protocol):
    """Exact host effects. Implementations must never resolve by display name."""

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        ...

    def disable_startup_policy(
        self, target: ExactResourceRef, policy: StartupPolicyRef
    ) -> Mapping[str, Any]:
        ...

    def restore_startup_policy(
        self,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
    ) -> Mapping[str, Any]:
        """Restore only the exact, durably captured pre-disable policy."""
        ...

    def stop_exact(self, target: ExactResourceRef) -> Mapping[str, Any]:
        ...


class LifecyclePersistence(Protocol):
    """Transactional persistence boundary used by :class:`RepositoryLifecycle`.

    Implementations must use one immediate transaction for each ``save_*``,
    ``fence_*``, ``advance_*``, ``deactivate_*``, ``complete_*``, guard,
    install, attach, and reinstall call.  In particular, a fence and all target
    ledger rows must become durable in the same transaction.
    """

    def repository_snapshot(self, repo_id: str) -> RepositorySnapshot:
        ...

    def standalone_snapshot(self, resource: ExactResourceRef) -> StandaloneSnapshot:
        ...

    def save_repository_plan(
        self, plan: RepositoryDecommissionPlan
    ) -> RepositoryDecommissionPlan:
        ...

    def save_retirement_plan(self, plan: StandaloneRetirementPlan) -> StandaloneRetirementPlan:
        ...

    def load_plan(self, plan_id: str) -> LifecyclePlan:
        ...

    def fence_repository(
        self, plan: RepositoryDecommissionPlan, *, actor: str
    ) -> OperationProgress:
        ...

    def fence_resource(
        self, plan: StandaloneRetirementPlan, *, actor: str
    ) -> OperationProgress:
        ...

    def operation_progress(self, operation_id: str) -> OperationProgress:
        ...

    def begin_target_phase(
        self, operation_id: str, target: ExactResourceRef, phase: TargetPhase
    ) -> OperationProgress:
        ...

    def advance_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        evidence: Mapping[str, Any],
    ) -> OperationProgress:
        ...

    def capture_startup_policy_state(
        self,
        operation_id: str,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        observation: PolicyObservation,
    ) -> CapturedStartupPolicyState:
        """Persist observed pre-disable state before any host-side mutation."""
        ...

    def fail_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        error: Mapping[str, Any],
    ) -> OperationProgress:
        ...

    def mark_needs_attention(self, operation_id: str) -> OperationProgress:
        ...

    def deactivate_allocations(
        self,
        operation_id: str,
        target: ExactResourceRef,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        ...

    def deactivate_repository_allocations(
        self,
        operation_id: str,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        ...

    def fail_repository_allocations(
        self,
        operation_id: str,
        error: Mapping[str, Any],
    ) -> OperationProgress:
        ...

    def complete_repository_decommission(
        self, plan: RepositoryDecommissionPlan
    ) -> OperationProgress:
        ...

    def complete_resource_retirement(
        self, plan: StandaloneRetirementPlan
    ) -> OperationProgress:
        ...

    def begin_resource_archive_restore(
        self,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> str:
        ...

    def resource_archive_restoration_plan(
        self,
        operation_id: str,
        resource: ExactResourceRef,
    ) -> Sequence[tuple[StartupPolicyRef, CapturedStartupPolicyState]]:
        ...

    def mark_resource_archive_policy_restored(
        self,
        operation_id: str,
        resource: ExactResourceRef,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
        evidence: Mapping[str, Any],
    ) -> None:
        ...

    def complete_resource_archive_restore(
        self,
        operation_id: str,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> Mapping[str, Any]:
        ...

    def install_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        ...

    def reinstall_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        ...

    def list_removed_repositories(self) -> Sequence[Mapping[str, Any]]:
        ...

    def attach_resource(
        self,
        repo_id: str,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> AttachResult:
        ...

    def reserve_repository_action(
        self,
        repo_id: str,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        ...

    def reserve_resource_action(
        self,
        resource: ExactResourceRef,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        ...

    def release_action_permit(self, permit: ActionPermit, *, outcome: str) -> None:
        ...

    def startup_policy_restoration_plan(
        self, permit: ActionPermit
    ) -> Sequence[tuple[ExactResourceRef, StartupPolicyRef, CapturedStartupPolicyState]]:
        """Return exact pending restoration work for a guarded explicit start."""
        ...

    def mark_startup_policy_restored(
        self,
        permit: ActionPermit,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
        evidence: Mapping[str, Any],
    ) -> None:
        ...


class RepositoryLifecycle:
    """Plan and execute repository/resource retirement without name inference."""

    def __init__(
        self,
        persistence: LifecyclePersistence,
        adapter: HostLifecycleAdapter,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._persistence = persistence
        self._adapter = adapter
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))

    def plan_repository_decommission(
        self, repo_id: str, *, actor: str, reason: str
    ) -> RepositoryDecommissionPlan:
        snapshot = self._persistence.repository_snapshot(repo_id)
        if snapshot.unresolved_conflicts:
            raise OwnershipError(
                "repository has unresolved control conflicts: "
                + ", ".join(snapshot.unresolved_conflicts)
            )
        if snapshot.installation_status != "installed" or snapshot.startup_fenced:
            raise ActionFencedError(
                f"repository {repo_id} is not an installed, unfenced repository"
            )
        targets = tuple(sorted(snapshot.targets, key=lambda item: item.ledger_key))
        repository_allocations = tuple(
            sorted(
                snapshot.repository_allocations,
                key=lambda item: (item.kind.value, item.allocation_id),
            )
        )
        for target in targets:
            _require_exact_target(target)
        fingerprint = _fingerprint(
            {
                "kind": "repository_decommission",
                "repo_id": repo_id,
                "repository_fingerprint": snapshot.repository_fingerprint,
                "installation_generation": snapshot.installation_generation,
                "targets": [item.to_dict() for item in targets],
                "repository_allocations": [
                    item.to_dict() for item in repository_allocations
                ],
                "retained_data": list(RETAINED_DATA),
            }
        )
        plan = RepositoryDecommissionPlan(
            plan_id=self._id_factory(),
            repo_id=repo_id,
            repository_fingerprint=snapshot.repository_fingerprint,
            installation_generation=snapshot.installation_generation,
            fingerprint=fingerprint,
            created_at=self._now(),
            actor=actor,
            reason=reason,
            targets=targets,
            repository_allocations=repository_allocations,
        )
        return self._persistence.save_repository_plan(plan)

    def apply_repository_decommission(
        self, plan_id: str, fingerprint: str, *, actor: str
    ) -> LifecycleResult:
        plan = self._persistence.load_plan(plan_id)
        if not isinstance(plan, RepositoryDecommissionPlan):
            raise LifecycleError(f"plan {plan_id} is not a repository decommission")
        _require_plan_fingerprint(plan, fingerprint)
        progress = self._persistence.fence_repository(plan, actor=actor)
        if progress.status is OperationStatus.SUCCEEDED:
            return self._result(plan, progress, already_complete=True)
        progress = self._run_phases(plan, progress)
        if progress.status is OperationStatus.NEEDS_ATTENTION:
            return self._result(plan, progress)
        progress = self._persistence.complete_repository_decommission(plan)
        return self._result(plan, progress)

    def plan_standalone_retirement(
        self, resource: ExactResourceRef, *, actor: str, reason: str
    ) -> StandaloneRetirementPlan:
        _require_exact_target(resource)
        snapshot = self._persistence.standalone_snapshot(resource)
        if snapshot.attached_repo_id is not None:
            raise OwnershipError(
                f"resource is attached to repository {snapshot.attached_repo_id}; "
                "remove it through that repository"
            )
        if snapshot.authority_state != "authoritative":
            raise OwnershipError("standalone resource has no unique authoritative controller")
        if snapshot.retirement_status in {"disabling", "retired"}:
            raise ActionFencedError("standalone resource is already fenced or retired")
        fingerprint = _fingerprint(
            {
                "kind": "standalone_resource_retirement",
                "target": resource.to_dict(),
                "retained_data": list(RETAINED_DATA),
            }
        )
        plan = StandaloneRetirementPlan(
            plan_id=self._id_factory(),
            fingerprint=fingerprint,
            created_at=self._now(),
            actor=actor,
            reason=reason,
            target=resource,
        )
        return self._persistence.save_retirement_plan(plan)

    def plan_resource_archive(
        self,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
        repo_id: str | None = None,
    ) -> StandaloneRetirementPlan:
        """Plan a reversible archive for one exact attached or standalone resource."""

        _require_exact_target(resource)
        snapshot = self._persistence.standalone_snapshot(resource)
        if snapshot.attached_repo_id != repo_id:
            raise OwnershipError("resource repository attachment changed before archive planning")
        if snapshot.authority_state != "authoritative":
            raise OwnershipError("resource has no unique authoritative controller")
        if snapshot.retirement_status in {"disabling", "retired"}:
            raise ActionFencedError("resource is already archived or archive is in progress")
        fingerprint = _fingerprint(
            {
                "kind": "resource_archive",
                "repo_id": repo_id,
                "target": resource.to_dict(),
                "retained_data": list(RETAINED_DATA),
            }
        )
        return self._persistence.save_retirement_plan(
            StandaloneRetirementPlan(
                plan_id=self._id_factory(),
                fingerprint=fingerprint,
                created_at=self._now(),
                actor=actor,
                reason=reason,
                target=resource,
                repo_id=repo_id,
            )
        )

    def apply_standalone_retirement(
        self, plan_id: str, fingerprint: str, *, actor: str
    ) -> LifecycleResult:
        plan = self._persistence.load_plan(plan_id)
        if not isinstance(plan, StandaloneRetirementPlan):
            raise LifecycleError(f"plan {plan_id} is not a standalone retirement")
        _require_plan_fingerprint(plan, fingerprint)
        progress = self._persistence.fence_resource(plan, actor=actor)
        if progress.status is OperationStatus.SUCCEEDED:
            return self._result(plan, progress, already_complete=True)
        progress = self._run_phases(plan, progress)
        if progress.status is OperationStatus.NEEDS_ATTENTION:
            return self._result(plan, progress)
        progress = self._persistence.complete_resource_retirement(plan)
        return self._result(plan, progress)

    def restore_resource_archive(
        self,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> Mapping[str, Any]:
        """Restore exact captured policies, then clear the archive fence last."""

        _require_exact_target(resource)
        observation = self._adapter.observe_exact(resource)
        self._verify_exact_identity(resource, observation)
        if observation.running_state not in {RunningState.STOPPED, RunningState.ZOMBIE}:
            raise LifecycleError("an archived resource must remain stopped before restore")
        if resource.kind is ResourceKind.SERVER and observation.listener_active is not False:
            raise LifecycleError(
                "an archived server listener must be proved absent before restore"
            )
        operation_id = self._persistence.begin_resource_archive_restore(
            resource, actor=actor, reason=reason
        )
        for policy, captured in self._persistence.resource_archive_restoration_plan(
            operation_id, resource
        ):
            if captured.status == "restored" or not captured.restore_required:
                continue
            before = self._adapter.observe_exact(resource)
            self._verify_exact_identity(resource, before)
            if before.running_state not in {RunningState.STOPPED, RunningState.ZOMBIE}:
                raise LifecycleError("resource started during archive policy restoration")
            if resource.kind is ResourceKind.SERVER and before.listener_active is not False:
                raise LifecycleError("server listener activated during archive policy restoration")
            if policy.kind not in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
                try:
                    self._verify_policy_restored(
                        policy, captured, before.policies.get(policy.policy_id)
                    )
                except LifecycleError:
                    pass
                else:
                    self._persistence.mark_resource_archive_policy_restored(
                        operation_id,
                        resource,
                        policy,
                        captured,
                        {"restore": "already_applied_and_verified"},
                    )
                    continue
            self._verify_policy_restore_precondition(
                policy, captured, before.policies.get(policy.policy_id)
            )
            effect = self._adapter.restore_startup_policy(resource, policy, captured)
            if effect.get("host_may_have_started"):
                raise LifecycleError("startup-policy restoration may have started the resource")
            after = self._adapter.observe_exact(resource)
            self._verify_exact_identity(resource, after)
            if after.running_state not in {RunningState.STOPPED, RunningState.ZOMBIE}:
                raise LifecycleError("resource started during archive policy restoration")
            if resource.kind is ResourceKind.SERVER and after.listener_active is not False:
                raise LifecycleError("server listener activated during archive policy restoration")
            if policy.kind not in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
                self._verify_policy_restored(
                    policy, captured, after.policies.get(policy.policy_id)
                )
            self._persistence.mark_resource_archive_policy_restored(
                operation_id, resource, policy, captured, effect
            )
        final_observation = self._adapter.observe_exact(resource)
        self._verify_exact_identity(resource, final_observation)
        if final_observation.running_state not in {RunningState.STOPPED, RunningState.ZOMBIE}:
            raise LifecycleError("resource must remain stopped until restore commits")
        if (
            resource.kind is ResourceKind.SERVER
            and final_observation.listener_active is not False
        ):
            raise LifecycleError("server listener must remain absent until restore commits")
        result = dict(
            self._persistence.complete_resource_archive_restore(
                operation_id,
                resource,
                actor=actor,
                reason=reason,
            )
        )
        if result.get("started"):
            raise LifecycleError("resource restore must never start the runtime")
        return result

    def install_repository(
        self, repo_id: str, *, actor: str, reason: str, explicit: bool
    ) -> InstallationResult:
        _require_explicit(explicit)
        result = self._persistence.install_repository(repo_id, actor=actor, reason=reason)
        if result.started:
            raise LifecycleError("repository installation must never start its runtime")
        return result

    def reinstall_repository(
        self, repo_id: str, *, actor: str, reason: str, explicit: bool
    ) -> InstallationResult:
        _require_explicit(explicit)
        result = self._persistence.reinstall_repository(repo_id, actor=actor, reason=reason)
        if result.started:
            raise LifecycleError("repository reinstallation must never start its runtime")
        return result

    def list_removed_repositories(self) -> Sequence[Mapping[str, Any]]:
        return self._persistence.list_removed_repositories()

    def attach_resource(
        self,
        repo_id: str,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> AttachResult:
        _require_exact_target(resource)
        observation = self._adapter.observe_exact(resource)
        self._verify_exact_identity(resource, observation)
        snapshot = self._persistence.standalone_snapshot(resource)
        if snapshot.authority_state != "authoritative":
            raise OwnershipError("resource controller is not uniquely authoritative")
        if snapshot.attached_repo_id is not None and snapshot.attached_repo_id != repo_id:
            raise OwnershipError(f"resource already belongs to {snapshot.attached_repo_id}")
        if snapshot.retirement_status in {"disabling", "retired"}:
            raise ActionFencedError("retired resources require an explicit restore journey")
        result = self._persistence.attach_resource(
            repo_id, resource, actor=actor, reason=reason
        )
        if result.started:
            raise LifecycleError("attaching a resource must never start it")
        return result

    def reserve_repository_action(
        self,
        repo_id: str,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        """Atomically guard and reserve start/register/Compose/lease mutation."""

        return self._persistence.reserve_repository_action(
            repo_id, action, request_id=request_id, actor=actor
        )

    def reserve_resource_action(
        self,
        resource: ExactResourceRef,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        _require_exact_target(resource)
        return self._persistence.reserve_resource_action(
            resource, action, request_id=request_id, actor=actor
        )

    def release_action_permit(self, permit: ActionPermit, *, outcome: str) -> None:
        self._persistence.release_action_permit(permit, outcome=outcome)

    def restore_startup_policies_for_start(
        self, permit: ActionPermit
    ) -> StartupPolicyRestorationResult:
        """Restore captured policy state inside an already-guarded start.

        Reinstallation deliberately does not call this method.  A caller must
        first reserve the explicit repository ``start`` action, then invoke
        this method before starting any process, container, Compose project,
        or supervisor.  Unknown or incomplete capture is rejected by the
        persistence boundary before a host mutation occurs.
        """

        if permit.repo_id is None or permit.action is not RepositoryAction.START:
            raise LifecycleError(
                "startup policy restoration requires a repository start permit"
            )
        restored: list[str] = []
        already: list[str] = []
        not_required: list[str] = []
        host_may_have_started = False
        work = self._persistence.startup_policy_restoration_plan(permit)
        for target, policy, captured in work:
            if captured.status == "restored":
                if policy.kind not in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
                    observed = self._adapter.observe_exact(target)
                    self._verify_exact_identity(target, observed)
                    self._verify_policy_restored(
                        policy, captured, observed.policies.get(policy.policy_id)
                    )
                already.append(policy.policy_id)
                continue
            if not captured.restore_required:
                not_required.append(policy.policy_id)
                continue
            before = self._adapter.observe_exact(target)
            self._verify_exact_identity(target, before)
            if policy.kind not in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
                try:
                    self._verify_policy_restored(
                        policy, captured, before.policies.get(policy.policy_id)
                    )
                except LifecycleError:
                    pass
                else:
                    self._persistence.mark_startup_policy_restored(
                        permit,
                        target,
                        policy,
                        captured,
                        {"restore": "already_applied_and_verified"},
                    )
                    restored.append(policy.policy_id)
                    continue
            self._verify_policy_restore_precondition(
                policy, captured, before.policies.get(policy.policy_id)
            )
            effect = self._adapter.restore_startup_policy(
                target, policy, captured
            )
            after = self._adapter.observe_exact(target)
            self._verify_exact_identity(target, after)
            if policy.kind not in {PolicyKind.COORDINATOR, PolicyKind.COMPOSE}:
                self._verify_policy_restored(
                    policy, captured, after.policies.get(policy.policy_id)
                )
            self._persistence.mark_startup_policy_restored(
                permit, target, policy, captured, effect
            )
            restored.append(policy.policy_id)
            host_may_have_started = host_may_have_started or bool(
                effect.get("host_may_have_started", False)
            )
        return StartupPolicyRestorationResult(
            permit.repo_id,
            permit.permit_id,
            tuple(restored),
            tuple(already),
            tuple(not_required),
            host_may_have_started,
        )

    def _run_phases(
        self, plan: LifecyclePlan, progress: OperationProgress
    ) -> OperationProgress:
        targets = plan.targets if isinstance(plan, RepositoryDecommissionPlan) else (plan.target,)
        phases = (
            (TargetPhase.POLICIES_DISABLED, self._disable_policies),
            (TargetPhase.STOPPED, self._stop),
            (TargetPhase.VERIFIED, self._verify_stopped),
            (TargetPhase.ALLOCATIONS_DEACTIVATED, self._deactivate_allocations),
            (TargetPhase.COMPLETE, self._complete_target),
        )
        for phase, effect in phases:
            phase_failed = False
            for target in targets:
                current = self._persistence.operation_progress(plan.plan_id)
                target_progress = current.targets[target.ledger_key]
                if target_progress.phase >= phase:
                    continue
                self._persistence.begin_target_phase(plan.plan_id, target, phase)
                try:
                    evidence = effect(plan.plan_id, target)
                    self._persistence.advance_target(
                        plan.plan_id, target, phase, evidence
                    )
                except Exception as exc:  # a BaseException models a real crash in tests
                    phase_failed = True
                    self._persistence.fail_target(
                        plan.plan_id,
                        target,
                        phase,
                        {
                            "code": _error_code(exc),
                            "message": str(exc),
                            "phase": phase.name.lower(),
                        },
                    )
            if phase_failed:
                return self._persistence.mark_needs_attention(plan.plan_id)
            if (
                phase is TargetPhase.ALLOCATIONS_DEACTIVATED
                and isinstance(plan, RepositoryDecommissionPlan)
                and plan.repository_allocations
            ):
                try:
                    self._persistence.deactivate_repository_allocations(
                        plan.plan_id, plan.repository_allocations
                    )
                except Exception as exc:
                    # A repository-level allocation has no host resource to
                    # which it can honestly be attached.  Keep it on the
                    # synthetic repository ledger and retain the fence.
                    self._persistence.fail_repository_allocations(
                        plan.plan_id,
                        {
                            "code": _error_code(exc),
                            "message": str(exc),
                            "phase": "allocations_deactivated",
                        },
                    )
                    return self._persistence.mark_needs_attention(plan.plan_id)
        return self._persistence.operation_progress(plan.plan_id)

    def _disable_policies(
        self, _operation_id: str, target: ExactResourceRef
    ) -> Mapping[str, Any]:
        observation = self._adapter.observe_exact(target)
        self._verify_exact_identity(target, observation)
        results: list[Mapping[str, Any]] = []
        for policy in target.policies:
            current = observation.policies.get(policy.policy_id)
            self._verify_policy_identity(policy, current)
            self._persistence.capture_startup_policy_state(
                _operation_id, target, policy, current
            )
            if current is not None and current.disabled:
                results.append(
                    {"policy_id": policy.policy_id, "status": "already_disabled"}
                )
                continue
            effect = self._adapter.disable_startup_policy(target, policy)
            results.append({"policy_id": policy.policy_id, "status": "disabled", **effect})
            observation = self._adapter.observe_exact(target)
            self._verify_exact_identity(target, observation)
            self._verify_policy_disabled(policy, observation.policies.get(policy.policy_id))
        final = self._adapter.observe_exact(target)
        self._verify_exact_identity(target, final)
        for policy in target.policies:
            self._verify_policy_disabled(policy, final.policies.get(policy.policy_id))
        return {"policies": results}

    def _stop(self, _operation_id: str, target: ExactResourceRef) -> Mapping[str, Any]:
        observation = self._adapter.observe_exact(target)
        self._verify_exact_identity(target, observation)
        if self._is_stopped(target, observation, require_listener=False):
            return {"stop": "already_stopped"}
        effect = self._adapter.stop_exact(target)
        return {"stop": "requested", **effect}

    def _verify_stopped(
        self, _operation_id: str, target: ExactResourceRef
    ) -> Mapping[str, Any]:
        observation = self._adapter.observe_exact(target)
        self._verify_exact_identity(target, observation)
        for policy in target.policies:
            self._verify_policy_disabled(policy, observation.policies.get(policy.policy_id))
        if not self._is_stopped(target, observation, require_listener=True):
            raise LifecycleError(f"exact {target.kind.value} target remains active")
        return {
            "verified": True,
            "running_state": observation.running_state.value,
            "listener_active": observation.listener_active,
            "container_running": observation.container_running,
            "supervisor_active": observation.supervisor_active,
            "policies_disabled": [item.policy_id for item in target.policies],
        }

    def _deactivate_allocations(
        self, operation_id: str, target: ExactResourceRef
    ) -> Mapping[str, Any]:
        # Persistence verifies every immutable allocation fingerprint and
        # deactivates them in the same transaction as this target checkpoint.
        return self._persistence.deactivate_allocations(
            operation_id, target, target.allocations
        )

    def _complete_target(
        self, _operation_id: str, _target: ExactResourceRef
    ) -> Mapping[str, Any]:
        return {"complete": True}

    def _verify_exact_identity(
        self, target: ExactResourceRef, observation: ResourceObservation
    ) -> None:
        if observation.resource_id != target.resource_id or observation.kind is not target.kind:
            raise PlanDriftError("observer returned a different resource identity")
        if not observation.identity_observable:
            raise OwnershipError("resource identity is unobservable")
        if observation.immutable_fingerprint != target.immutable_fingerprint:
            raise PlanDriftError("resource immutable identity changed")
        if observation.replacement_fingerprint not in {None, target.immutable_fingerprint}:
            raise PlanDriftError("resource was replaced by a different immutable identity")
        if not observation.ownership_observable:
            raise OwnershipError("resource ownership is unobservable")
        if observation.ownership_fingerprint != target.ownership_fingerprint:
            raise OwnershipError("resource ownership binding changed")

    @staticmethod
    def _verify_policy_identity(
        policy: StartupPolicyRef, observation: PolicyObservation | None
    ) -> None:
        if observation is None or not observation.observable:
            raise OwnershipError(f"startup policy {policy.policy_id} is unobservable")
        if observation.immutable_fingerprint != policy.immutable_fingerprint:
            raise PlanDriftError(f"startup policy {policy.policy_id} identity changed")

    @classmethod
    def _verify_policy_disabled(
        cls, policy: StartupPolicyRef, observation: PolicyObservation | None
    ) -> None:
        cls._verify_policy_identity(policy, observation)
        if observation is None or observation.disabled is not True:
            raise LifecycleError(f"startup policy {policy.policy_id} remains enabled")
        if observation.value != policy.disabled_value:
            raise LifecycleError(
                f"startup policy {policy.policy_id} has value {observation.value!r}, "
                f"expected {policy.disabled_value!r}"
            )

    @classmethod
    def _verify_policy_restore_precondition(
        cls,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
        observation: PolicyObservation | None,
    ) -> None:
        """Accept only the disabled boundary or a proved composite restore prefix."""

        try:
            cls._verify_policy_disabled(policy, observation)
            return
        except LifecycleError as disabled_error:
            cls._verify_policy_identity(policy, observation)
            if observation is None or policy.kind is not PolicyKind.SUPERVISOR:
                raise disabled_error
            if (
                captured.supervisor_manager == "systemd"
                and observation.supervisor_manager == "systemd"
                and observation.supervisor_unit_file_state == "disabled"
                and observation.supervisor_enabled is False
                and captured.supervisor_unit_file_state
                in {"enabled", "enabled-runtime", "masked-runtime"}
            ):
                # `unmask` completed but the exact enable/runtime-mask step did
                # not. Replaying LocalHostLifecycleBackend.restore_supervisor
                # is idempotent and re-verifies the captured final state.
                return
            raise disabled_error

    @staticmethod
    def _verify_policy_restored(
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
        observation: PolicyObservation | None,
    ) -> None:
        RepositoryLifecycle._verify_policy_identity(policy, observation)
        if observation is None or not observation.observable:
            raise LifecycleError(
                f"startup policy {policy.policy_id} restore is unobservable"
            )
        if observation.value != captured.captured_value:
            raise LifecycleError(
                f"startup policy {policy.policy_id} restored to "
                f"{observation.value!r}, expected exact captured value "
                f"{captured.captured_value!r}"
            )
        if policy.kind is PolicyKind.DOCKER_RESTART:
            if observation.docker_restart_policy != captured.docker_restart_policy:
                raise LifecycleError("Docker restart policy restore verification failed")
        if policy.kind is PolicyKind.SUPERVISOR:
            observed_state = [
                observation.supervisor_manager,
                observation.supervisor_unit_file_state,
                observation.supervisor_enabled,
            ]
            captured_state = [
                captured.supervisor_manager,
                captured.supervisor_unit_file_state,
                captured.supervisor_enabled,
            ]
            if observed_state != captured_state:
                raise LifecycleError("supervisor policy restore verification failed")

    @staticmethod
    def _is_stopped(
        target: ExactResourceRef,
        observation: ResourceObservation,
        *,
        require_listener: bool,
    ) -> bool:
        if observation.running_state is RunningState.UNKNOWN:
            raise OwnershipError("process lifecycle is unobservable")
        process_stopped = observation.running_state in {
            RunningState.STOPPED,
            RunningState.ZOMBIE,
        }
        if target.kind is ResourceKind.SERVER:
            if require_listener and observation.listener_active is None:
                raise OwnershipError("server listener boundary is unobservable")
            return process_stopped and (
                not require_listener or observation.listener_active is False
            )
        if target.kind is ResourceKind.CONTAINER:
            if observation.container_running is None:
                raise OwnershipError("container runtime state is unobservable")
            return process_stopped and observation.container_running is False
        if observation.supervisor_active is None:
            raise OwnershipError("supervisor state is unobservable")
        return process_stopped and observation.supervisor_active is False

    @staticmethod
    def _result(
        plan: LifecyclePlan,
        progress: OperationProgress,
        *,
        already_complete: bool = False,
    ) -> LifecycleResult:
        if already_complete:
            status = "already_complete"
        elif progress.status is OperationStatus.SUCCEEDED:
            status = "succeeded"
        elif progress.status is OperationStatus.NEEDS_ATTENTION:
            status = "needs_attention"
        else:
            status = progress.status.value
        return LifecycleResult(
            operation_id=progress.operation_id,
            plan=plan,
            status=status,
            fence=("disabled" if progress.status is OperationStatus.SUCCEEDED else "retained"),
            hidden=progress.hidden,
            progress=progress,
        )

    def _now(self) -> str:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("lifecycle clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_identity(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty immutable identity")


def _require_exact_target(target: ExactResourceRef) -> None:
    _require_identity("resource_id", target.resource_id)
    _require_identity("immutable_fingerprint", target.immutable_fingerprint)
    _require_identity("control_binding_id", target.control_binding_id)
    _require_identity("ownership_fingerprint", target.ownership_fingerprint)


def _require_explicit(explicit: bool) -> None:
    if explicit is not True:
        raise ExplicitConfirmationRequired(
            "repository installation is available only through an explicit Coordinator journey"
        )


def _require_plan_fingerprint(plan: LifecyclePlan, fingerprint: str) -> None:
    if not fingerprint or fingerprint != plan.fingerprint:
        raise PlanDriftError("plan fingerprint does not match the durable plan")


def _fingerprint(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _error_code(error: Exception) -> str:
    name = error.__class__.__name__
    chars = []
    for index, char in enumerate(name):
        if char.isupper() and index:
            chars.append("_")
        chars.append(char.lower())
    return "lifecycle_" + "".join(chars)


__all__ = [
    "ActionFencedError",
    "ActionPermit",
    "AllocationKind",
    "AllocationRef",
    "AttachResult",
    "CapturedStartupPolicyState",
    "ConcurrentLifecycleError",
    "ExactResourceRef",
    "ExplicitConfirmationRequired",
    "HostLifecycleAdapter",
    "InstallationResult",
    "LifecycleError",
    "LifecyclePersistence",
    "LifecycleResult",
    "OperationProgress",
    "OperationStatus",
    "OwnershipError",
    "PlanDriftError",
    "PolicyKind",
    "PolicyObservation",
    "RepositoryAction",
    "RepositoryDecommissionPlan",
    "RepositoryLifecycle",
    "RepositorySnapshot",
    "ResourceKind",
    "ResourceObservation",
    "RunningState",
    "StandaloneRetirementPlan",
    "StandaloneSnapshot",
    "StartupPolicyRef",
    "StartupPolicyRestorationResult",
    "TargetPhase",
    "TargetProgress",
]
