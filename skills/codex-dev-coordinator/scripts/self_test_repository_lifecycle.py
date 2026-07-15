#!/usr/bin/env python3
"""Failure-shaped tests for repository decommission and resource retirement."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import sys
import threading
from typing import Any, Mapping, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from devcoordinator.repository_lifecycle import (  # noqa: E402
    ActionFencedError,
    ActionPermit,
    AllocationKind,
    AllocationRef,
    AttachResult,
    CapturedStartupPolicyState,
    ConcurrentLifecycleError,
    ExactResourceRef,
    ExplicitConfirmationRequired,
    InstallationResult,
    LifecycleError,
    OperationProgress,
    OperationStatus,
    OwnershipError,
    PlanDriftError,
    PolicyKind,
    PolicyObservation,
    RepositoryAction,
    RepositoryDecommissionPlan,
    RepositoryLifecycle,
    RepositorySnapshot,
    ResourceKind,
    ResourceObservation,
    RunningState,
    StandaloneRetirementPlan,
    StandaloneSnapshot,
    StartupPolicyRef,
    TargetPhase,
    TargetProgress,
)


class SimulatedCrash(BaseException):
    pass


def expect(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


@dataclass
class HostState:
    ref: ExactResourceRef
    running_state: RunningState
    listener_active: bool | None
    container_running: bool | None
    supervisor_active: bool | None
    policy_values: dict[str, tuple[bool, str]]
    identity_observable: bool = True
    ownership_observable: bool = True
    fingerprint: str | None = None
    ownership_fingerprint: str | None = None
    replacement_fingerprint: str | None = None


class FakeAdapter:
    def __init__(self, states: Sequence[HostState]) -> None:
        self.states = {state.ref.ledger_key: state for state in states}
        self.calls: list[str] = []
        self.fail_disable: set[str] = set()
        self.fail_stop: set[str] = set()
        self.crash_after_disable: set[str] = set()
        self.crash_after_stop: set[str] = set()

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        state = self.states[target.ledger_key]
        policies = {
            policy.policy_id: PolicyObservation(
                policy_id=policy.policy_id,
                immutable_fingerprint=policy.immutable_fingerprint,
                observable=True,
                disabled=state.policy_values[policy.policy_id][0],
                value=state.policy_values[policy.policy_id][1],
                docker_restart_policy=(
                    state.policy_values[policy.policy_id][1]
                    if policy.kind is PolicyKind.DOCKER_RESTART
                    else None
                ),
            )
            for policy in target.policies
        }
        return ResourceObservation(
            resource_id=target.resource_id,
            kind=target.kind,
            identity_observable=state.identity_observable,
            immutable_fingerprint=state.fingerprint or target.immutable_fingerprint,
            ownership_observable=state.ownership_observable,
            ownership_fingerprint=(
                state.ownership_fingerprint or target.ownership_fingerprint
            ),
            running_state=state.running_state,
            listener_active=state.listener_active,
            container_running=state.container_running,
            supervisor_active=state.supervisor_active,
            replacement_fingerprint=state.replacement_fingerprint,
            policies=policies,
        )

    def disable_startup_policy(
        self, target: ExactResourceRef, policy: StartupPolicyRef
    ) -> Mapping[str, Any]:
        key = f"{target.resource_id}:{policy.policy_id}"
        self.calls.append(f"disable:{key}")
        if key in self.fail_disable:
            raise LifecycleError("injected policy failure")
        state = self.states[target.ledger_key]
        state.policy_values[policy.policy_id] = (True, policy.disabled_value)
        if key in self.crash_after_disable:
            self.crash_after_disable.remove(key)
            raise SimulatedCrash("after policy external effect")
        return {"value": policy.disabled_value}

    def stop_exact(self, target: ExactResourceRef) -> Mapping[str, Any]:
        self.calls.append(f"stop:{target.resource_id}")
        if target.resource_id in self.fail_stop:
            raise LifecycleError("injected stop failure")
        state = self.states[target.ledger_key]
        state.running_state = RunningState.STOPPED
        if target.kind is ResourceKind.SERVER:
            state.listener_active = False
        elif target.kind is ResourceKind.CONTAINER:
            state.container_running = False
        else:
            state.supervisor_active = False
        if target.resource_id in self.crash_after_stop:
            self.crash_after_stop.remove(target.resource_id)
            raise SimulatedCrash("after stop external effect")
        return {"signalled": True}


class FakePersistence:
    """Locked fake that models the database transaction boundaries."""

    def __init__(
        self,
        repo_id: str,
        targets: Sequence[ExactResourceRef],
        *,
        standalone: Sequence[ExactResourceRef] = (),
    ) -> None:
        self.lock = threading.RLock()
        self.repo_id = repo_id
        self.repository_fingerprint = "repo-fingerprint-1"
        self.installation_generation = 7
        self.installation_status = "installed"
        self.startup_fenced = False
        self.hidden = False
        self.targets = {item.ledger_key: item for item in targets}
        self.plans: dict[str, RepositoryDecommissionPlan | StandaloneRetirementPlan] = {}
        self.progress: dict[str, OperationProgress] = {}
        self.plan_operation_for_repo: str | None = None
        self.retirements: dict[tuple[str, str], str | None] = {
            item.ledger_key: None for item in standalone
        }
        self.standalone = {item.ledger_key: item for item in standalone}
        self.attached: dict[tuple[str, str], str | None] = {
            item.ledger_key: None for item in standalone
        }
        self.authority: dict[tuple[str, str], str] = {
            item.ledger_key: "authoritative" for item in standalone
        }
        self.allocation_active: dict[tuple[str, str], tuple[str, bool]] = {}
        for item in [*targets, *standalone]:
            for allocation in item.allocations:
                self.allocation_active[(allocation.kind.value, allocation.allocation_id)] = (
                    allocation.immutable_fingerprint,
                    True,
                )
        self.permits: dict[str, ActionPermit] = {}
        self.captured_policies: dict[str, CapturedStartupPolicyState] = {}
        self.crash_after_fence = False
        self.crash_after_advance: set[TargetPhase] = set()
        self.crash_after_allocations = False
        self.crash_after_finalization = False

    def repository_snapshot(self, repo_id: str) -> RepositorySnapshot:
        with self.lock:
            if repo_id != self.repo_id:
                raise LifecycleError("unknown repository")
            return RepositorySnapshot(
                repo_id=repo_id,
                repository_fingerprint=self.repository_fingerprint,
                installation_generation=self.installation_generation,
                installation_status=self.installation_status,
                startup_fenced=self.startup_fenced,
                hidden=self.hidden,
                targets=tuple(self.targets.values()),
            )

    def standalone_snapshot(self, resource: ExactResourceRef) -> StandaloneSnapshot:
        with self.lock:
            stored = self.standalone.get(resource.ledger_key)
            if stored != resource:
                raise PlanDriftError("standalone identity changed")
            return StandaloneSnapshot(
                resource=stored,
                retirement_status=self.retirements[resource.ledger_key],
                attached_repo_id=self.attached[resource.ledger_key],
                authority_state=self.authority[resource.ledger_key],
            )

    def save_repository_plan(
        self, plan: RepositoryDecommissionPlan
    ) -> RepositoryDecommissionPlan:
        with self.lock:
            for existing in self.plans.values():
                if (
                    isinstance(existing, RepositoryDecommissionPlan)
                    and existing.repo_id == plan.repo_id
                    and existing.fingerprint == plan.fingerprint
                    and self.progress[existing.plan_id].status is OperationStatus.PLANNED
                ):
                    return existing
            self.plans[plan.plan_id] = plan
            self.progress[plan.plan_id] = _new_progress(plan.plan_id, plan.targets)
            return plan

    def save_retirement_plan(
        self, plan: StandaloneRetirementPlan
    ) -> StandaloneRetirementPlan:
        with self.lock:
            self.plans[plan.plan_id] = plan
            self.progress[plan.plan_id] = _new_progress(plan.plan_id, (plan.target,))
            return plan

    def load_plan(self, plan_id: str) -> RepositoryDecommissionPlan | StandaloneRetirementPlan:
        with self.lock:
            return self.plans[plan_id]

    def fence_repository(
        self, plan: RepositoryDecommissionPlan, *, actor: str
    ) -> OperationProgress:
        del actor
        with self.lock:
            progress = self.progress[plan.plan_id]
            if progress.status is OperationStatus.SUCCEEDED:
                return progress
            if self.plan_operation_for_repo == plan.plan_id and self.startup_fenced:
                return self._set_operation_status(plan.plan_id, OperationStatus.RUNNING)
            if self.permits:
                raise ConcurrentLifecycleError("repository action already reserved")
            if (
                self.installation_status != "installed"
                or self.startup_fenced
                or self.repository_fingerprint != plan.repository_fingerprint
                or self.installation_generation != plan.installation_generation
                or set(self.targets) != {item.ledger_key for item in plan.targets}
                or any(self.targets[item.ledger_key] != item for item in plan.targets)
            ):
                raise PlanDriftError("repository changed after planning")
            self.installation_status = "disabling"
            self.startup_fenced = True
            self.installation_generation += 1
            self.plan_operation_for_repo = plan.plan_id
            progress = self._set_operation_status(plan.plan_id, OperationStatus.RUNNING)
            if self.crash_after_fence:
                self.crash_after_fence = False
                raise SimulatedCrash("after durable fence")
            return progress

    def fence_resource(
        self, plan: StandaloneRetirementPlan, *, actor: str
    ) -> OperationProgress:
        del actor
        with self.lock:
            progress = self.progress[plan.plan_id]
            if progress.status is OperationStatus.SUCCEEDED:
                return progress
            key = plan.target.ledger_key
            if self.retirements[key] == "disabling":
                return self._set_operation_status(plan.plan_id, OperationStatus.RUNNING)
            if self.retirements[key] == "retired":
                raise ActionFencedError("resource already retired by another operation")
            if self.attached[key] is not None or self.authority[key] != "authoritative":
                raise OwnershipError("standalone ownership changed")
            if self.standalone[key] != plan.target:
                raise PlanDriftError("standalone identity changed")
            self.retirements[key] = "disabling"
            progress = self._set_operation_status(plan.plan_id, OperationStatus.RUNNING)
            if self.crash_after_fence:
                self.crash_after_fence = False
                raise SimulatedCrash("after durable resource fence")
            return progress

    def operation_progress(self, operation_id: str) -> OperationProgress:
        with self.lock:
            return self.progress[operation_id]

    def begin_target_phase(
        self, operation_id: str, target: ExactResourceRef, phase: TargetPhase
    ) -> OperationProgress:
        del phase
        with self.lock:
            current = self.progress[operation_id]
            states = dict(current.targets)
            old = states[target.ledger_key]
            states[target.ledger_key] = replace(old, status="running", error=None)
            self.progress[operation_id] = replace(
                current,
                status=OperationStatus.RUNNING,
                targets=states,
                errors=(),
            )
            return self.progress[operation_id]

    def advance_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        evidence: Mapping[str, Any],
    ) -> OperationProgress:
        with self.lock:
            current = self.progress[operation_id]
            states = dict(current.targets)
            previous = states[target.ledger_key]
            merged = dict(previous.evidence)
            merged[phase.name.lower()] = dict(evidence)
            states[target.ledger_key] = replace(
                previous,
                phase=phase,
                status="succeeded" if phase is TargetPhase.COMPLETE else "running",
                evidence=merged,
                error=None,
            )
            self.progress[operation_id] = replace(current, targets=states)
            if phase in self.crash_after_advance:
                self.crash_after_advance.remove(phase)
                raise SimulatedCrash(f"after {phase.name.lower()} checkpoint")
            return self.progress[operation_id]

    def capture_startup_policy_state(
        self,
        operation_id: str,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        observation: PolicyObservation,
    ) -> CapturedStartupPolicyState:
        with self.lock:
            existing = self.captured_policies.get(policy.policy_id)
            if existing is not None:
                return existing
            captured = CapturedStartupPolicyState(
                policy.policy_id,
                self.repo_id if isinstance(self.plans[operation_id], RepositoryDecommissionPlan) else None,
                target.kind,
                target.resource_id,
                policy.kind,
                policy.immutable_fingerprint,
                target.immutable_fingerprint,
                target.control_binding_id,
                target.ownership_fingerprint,
                "native-fingerprint",
                str(observation.value),
                observation.value != policy.disabled_value,
                "captured" if observation.value != policy.disabled_value else "not_required",
                docker_restart_policy=observation.docker_restart_policy,
            )
            self.captured_policies[policy.policy_id] = captured
            return captured

    def fail_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        error: Mapping[str, Any],
    ) -> OperationProgress:
        del phase
        with self.lock:
            current = self.progress[operation_id]
            states = dict(current.targets)
            previous = states[target.ledger_key]
            states[target.ledger_key] = replace(
                previous, status="failed", error=dict(error)
            )
            self.progress[operation_id] = replace(
                current,
                targets=states,
                errors=(*current.errors, dict(error)),
            )
            return self.progress[operation_id]

    def mark_needs_attention(self, operation_id: str) -> OperationProgress:
        with self.lock:
            return self._set_operation_status(
                operation_id, OperationStatus.NEEDS_ATTENTION
            )

    def deactivate_allocations(
        self,
        operation_id: str,
        target: ExactResourceRef,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        del operation_id, target
        with self.lock:
            results = []
            for allocation in allocations:
                key = (allocation.kind.value, allocation.allocation_id)
                fingerprint, active = self.allocation_active[key]
                if fingerprint != allocation.immutable_fingerprint:
                    raise PlanDriftError("allocation identity changed")
                self.allocation_active[key] = (fingerprint, False)
                results.append(
                    {
                        "allocation_id": allocation.allocation_id,
                        "kind": allocation.kind.value,
                        "status": "deactivated" if active else "already_inactive",
                    }
                )
            if self.crash_after_allocations:
                self.crash_after_allocations = False
                raise SimulatedCrash("after allocation transaction")
            return {"allocations": results}

    def deactivate_repository_allocations(
        self,
        operation_id: str,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        synthetic = ExactResourceRef(
            f"repository:{self.repo_id}",
            ResourceKind.SUPERVISOR,
            f"repository:{self.repo_id}",
            f"repository:{self.repo_id}",
            f"repository:{self.repo_id}",
        )
        return self.deactivate_allocations(operation_id, synthetic, allocations)

    def fail_repository_allocations(
        self, operation_id: str, error: Mapping[str, Any]
    ) -> OperationProgress:
        with self.lock:
            current = self.progress[operation_id]
            self.progress[operation_id] = replace(
                current, errors=(*current.errors, dict(error))
            )
            return self.progress[operation_id]

    def complete_repository_decommission(
        self, plan: RepositoryDecommissionPlan
    ) -> OperationProgress:
        with self.lock:
            progress = self.progress[plan.plan_id]
            if any(item.phase is not TargetPhase.COMPLETE for item in progress.targets.values()):
                raise LifecycleError("target ledger is incomplete")
            if any(active for _fingerprint, active in self.allocation_active.values()):
                raise LifecycleError("an allocation remains active")
            if set(self.targets) != {item.ledger_key for item in plan.targets}:
                raise PlanDriftError("repository membership changed while fenced")
            self.installation_status = "disabled"
            self.hidden = True
            progress = replace(
                progress,
                status=OperationStatus.SUCCEEDED,
                fence_retained=True,
                hidden=True,
            )
            self.progress[plan.plan_id] = progress
            if self.crash_after_finalization:
                self.crash_after_finalization = False
                raise SimulatedCrash("after repository finalization")
            return progress

    def complete_resource_retirement(
        self, plan: StandaloneRetirementPlan
    ) -> OperationProgress:
        with self.lock:
            progress = self.progress[plan.plan_id]
            if progress.targets[plan.target.ledger_key].phase is not TargetPhase.COMPLETE:
                raise LifecycleError("target ledger is incomplete")
            self.retirements[plan.target.ledger_key] = "retired"
            progress = replace(
                progress,
                status=OperationStatus.SUCCEEDED,
                fence_retained=True,
                hidden=True,
            )
            self.progress[plan.plan_id] = progress
            if self.crash_after_finalization:
                self.crash_after_finalization = False
                raise SimulatedCrash("after retirement finalization")
            return progress

    def install_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        del actor, reason
        with self.lock:
            if repo_id != self.repo_id or self.installation_status not in {
                "uninstalled",
                "disabled",
            }:
                raise LifecycleError("repository cannot be installed from its current state")
            self.installation_status = "installed"
            self.startup_fenced = False
            self.hidden = False
            self.installation_generation += 1
            return InstallationResult(repo_id, "installed", False, False)

    def reinstall_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        del actor, reason
        with self.lock:
            if repo_id != self.repo_id or self.installation_status != "disabled":
                raise LifecycleError("complete decommission before reinstalling")
            self.installation_status = "installed"
            self.startup_fenced = False
            self.hidden = False
            self.installation_generation += 1
            return InstallationResult(repo_id, "installed", False, False)

    def list_removed_repositories(self) -> Sequence[Mapping[str, Any]]:
        with self.lock:
            if self.installation_status != "disabled":
                return ()
            return (
                {
                    "repo_id": self.repo_id,
                    "status": "disabled",
                    "hidden": True,
                },
            )

    def attach_resource(
        self,
        repo_id: str,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> AttachResult:
        del actor, reason
        with self.lock:
            if (
                repo_id != self.repo_id
                or self.installation_status != "installed"
                or self.startup_fenced
            ):
                raise ActionFencedError("repository is not installed")
            key = resource.ledger_key
            if self.standalone[key] != resource or self.retirements[key] is not None:
                raise PlanDriftError("standalone resource changed")
            current = self.attached[key]
            if current not in {None, repo_id}:
                raise OwnershipError("resource has another repository owner")
            self.attached[key] = repo_id
            self.targets[key] = resource
            self.repository_fingerprint += ":attached"
            return AttachResult(repo_id, resource.resource_id, resource.kind, True, False)

    def reserve_repository_action(
        self,
        repo_id: str,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        del actor
        with self.lock:
            if (
                repo_id != self.repo_id
                or self.installation_status != "installed"
                or self.startup_fenced
            ):
                raise ActionFencedError("repository start fence is active")
            if self.plan_operation_for_repo is not None:
                raise ConcurrentLifecycleError("repository lifecycle is active")
            permit = ActionPermit(
                request_id,
                repo_id,
                None,
                action,
                self.installation_generation,
            )
            self.permits[request_id] = permit
            return permit

    def reserve_resource_action(
        self,
        resource: ExactResourceRef,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        del actor
        with self.lock:
            if self.retirements[resource.ledger_key] in {"disabling", "retired"}:
                raise ActionFencedError("resource retirement fence is active")
            permit = ActionPermit(request_id, None, resource.resource_id, action, 1)
            self.permits[request_id] = permit
            return permit

    def release_action_permit(self, permit: ActionPermit, *, outcome: str) -> None:
        del outcome
        with self.lock:
            self.permits.pop(permit.permit_id, None)

    def _set_operation_status(
        self, operation_id: str, status: OperationStatus
    ) -> OperationProgress:
        progress = replace(
            self.progress[operation_id],
            status=status,
            fence_retained=(status is not OperationStatus.PLANNED),
            hidden=self.hidden,
        )
        self.progress[operation_id] = progress
        return progress


def _new_progress(
    operation_id: str, targets: Sequence[ExactResourceRef]
) -> OperationProgress:
    return OperationProgress(
        operation_id=operation_id,
        status=OperationStatus.PLANNED,
        fence_retained=False,
        hidden=False,
        targets={
            target.ledger_key: TargetProgress(
                target.kind, target.resource_id, TargetPhase.PENDING, "pending"
            )
            for target in targets
        },
    )


def docker_target(
    resource_id: str = "sha256:container-a",
    *,
    running: bool = True,
    restart: str = "always",
    allocation: bool = True,
) -> tuple[ExactResourceRef, HostState]:
    policy = StartupPolicyRef(
        f"policy:{resource_id}",
        PolicyKind.DOCKER_RESTART,
        f"policy-identity:{resource_id}",
        "no",
    )
    allocations = (
        AllocationRef(
            f"lease:{resource_id}", AllocationKind.LEASE, f"lease-fp:{resource_id}"
        ),
    ) if allocation else ()
    ref = ExactResourceRef(
        resource_id,
        ResourceKind.CONTAINER,
        f"container-identity:{resource_id}",
        f"binding:{resource_id}",
        f"ownership:{resource_id}",
        (policy,),
        allocations,
    )
    disabled = restart == "no"
    state = HostState(
        ref,
        RunningState.RUNNING if running else RunningState.STOPPED,
        None,
        running,
        None,
        {policy.policy_id: (disabled, restart)},
    )
    return ref, state


def server_target(resource_id: str = "server:source-a:web") -> tuple[ExactResourceRef, HostState]:
    policy = StartupPolicyRef(
        f"policy:{resource_id}",
        PolicyKind.SUPERVISOR,
        f"policy-identity:{resource_id}",
        "disabled",
    )
    allocation = AllocationRef(
        f"assignment:{resource_id}",
        AllocationKind.PORT_ASSIGNMENT,
        f"assignment-fp:{resource_id}",
    )
    ref = ExactResourceRef(
        resource_id,
        ResourceKind.SERVER,
        f"server-identity:{resource_id}",
        f"binding:{resource_id}",
        f"ownership:{resource_id}",
        (policy,),
        (allocation,),
    )
    state = HostState(
        ref,
        RunningState.RUNNING,
        True,
        None,
        None,
        {policy.policy_id: (False, "enabled")},
    )
    return ref, state


def lifecycle_case(
    targets: Sequence[tuple[ExactResourceRef, HostState]],
    *,
    standalone: bool = False,
) -> tuple[RepositoryLifecycle, FakePersistence, FakeAdapter]:
    refs = [item[0] for item in targets]
    adapter = FakeAdapter([item[1] for item in targets])
    store = FakePersistence(
        "repo-1", () if standalone else refs, standalone=refs if standalone else ()
    )
    ids = iter([f"plan-{index}" for index in range(1, 100)])
    lifecycle = RepositoryLifecycle(
        store,
        adapter,
        clock=lambda: datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc),
        id_factory=lambda: next(ids),
    )
    return lifecycle, store, adapter


def plan_and_apply(
    lifecycle: RepositoryLifecycle,
) -> tuple[RepositoryDecommissionPlan, Mapping[str, Any]]:
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove from Board"
    )
    result = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    return plan, result.to_dict()


def test_restart_always_is_disabled_before_stop() -> None:
    target, state = docker_target()
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    plan, result = plan_and_apply(lifecycle)
    expect(result["status"] == "succeeded", result)
    expect(
        adapter.calls
        == [
            f"disable:{target.resource_id}:{target.policies[0].policy_id}",
            f"stop:{target.resource_id}",
        ],
        adapter.calls,
    )
    expect(state.policy_values[target.policies[0].policy_id] == (True, "no"), state.policy_values)
    expect(state.container_running is False, state.container_running)
    expect(store.installation_status == "disabled" and store.hidden, store.installation_status)
    expect(not store.allocation_active[("lease", target.allocations[0].allocation_id)][1], store.allocation_active)
    expect(result["targets"][0]["phase"] == "complete", result)
    expect(result["plan_fingerprint"] == plan.fingerprint, result)


def test_stopped_restart_no_is_control_not_false_positive() -> None:
    target, state = docker_target(running=False, restart="no")
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    _plan, result = plan_and_apply(lifecycle)
    expect(result["status"] == "succeeded", result)
    expect(adapter.calls == [], adapter.calls)
    expect(store.hidden, store.hidden)


def test_all_policies_are_disabled_before_any_stop_and_partial_rolls_forward() -> None:
    first, first_state = docker_target("sha256:first", allocation=False)
    second, second_state = docker_target("sha256:second", allocation=False)
    lifecycle, store, adapter = lifecycle_case(
        ((first, first_state), (second, second_state))
    )
    adapter.fail_disable.add(f"{second.resource_id}:{second.policies[0].policy_id}")
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove"
    )
    result = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(result.status == "needs_attention", result.to_dict())
    expect(store.startup_fenced and not store.hidden, store.installation_status)
    expect(not any(call.startswith("stop:") for call in adapter.calls), adapter.calls)
    adapter.fail_disable.clear()
    result = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(result.status == "succeeded", result.to_dict())
    expect(store.hidden, store.installation_status)


def test_crash_after_each_durable_or_external_phase_resumes() -> None:
    scenarios = (
        "fence",
        "policy_effect",
        "policy_checkpoint",
        "stop_effect",
        "stop_checkpoint",
        "verify_checkpoint",
        "allocation_effect",
        "allocation_checkpoint",
        "complete_checkpoint",
        "finalization",
    )
    for scenario in scenarios:
        target, state = docker_target()
        lifecycle, store, adapter = lifecycle_case(((target, state),))
        plan = lifecycle.plan_repository_decommission(
            "repo-1", actor="tester", reason=scenario
        )
        if scenario == "fence":
            store.crash_after_fence = True
        elif scenario == "policy_effect":
            adapter.crash_after_disable.add(
                f"{target.resource_id}:{target.policies[0].policy_id}"
            )
        elif scenario == "policy_checkpoint":
            store.crash_after_advance.add(TargetPhase.POLICIES_DISABLED)
        elif scenario == "stop_effect":
            adapter.crash_after_stop.add(target.resource_id)
        elif scenario == "stop_checkpoint":
            store.crash_after_advance.add(TargetPhase.STOPPED)
        elif scenario == "verify_checkpoint":
            store.crash_after_advance.add(TargetPhase.VERIFIED)
        elif scenario == "allocation_effect":
            store.crash_after_allocations = True
        elif scenario == "allocation_checkpoint":
            store.crash_after_advance.add(TargetPhase.ALLOCATIONS_DEACTIVATED)
        elif scenario == "complete_checkpoint":
            store.crash_after_advance.add(TargetPhase.COMPLETE)
        else:
            store.crash_after_finalization = True
        try:
            lifecycle.apply_repository_decommission(
                plan.plan_id, plan.fingerprint, actor="tester"
            )
        except SimulatedCrash:
            pass
        else:
            raise AssertionError(f"{scenario} did not crash")
        expect(store.startup_fenced, scenario)
        result = lifecycle.apply_repository_decommission(
            plan.plan_id, plan.fingerprint, actor="tester"
        )
        expect(
            result.status in {"succeeded", "already_complete"},
            (scenario, result.to_dict()),
        )
        expect(store.hidden, scenario)
        expect(
            adapter.calls.count(f"stop:{target.resource_id}") <= 1,
            (scenario, adapter.calls),
        )
        expect(
            adapter.calls.count(
                f"disable:{target.resource_id}:{target.policies[0].policy_id}"
            )
            <= 1,
            (scenario, adapter.calls),
        )


def test_plan_drift_blocks_before_fence() -> None:
    target, state = docker_target()
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove"
    )
    store.repository_fingerprint = "changed"
    try:
        lifecycle.apply_repository_decommission(
            plan.plan_id, plan.fingerprint, actor="tester"
        )
    except PlanDriftError:
        pass
    else:
        raise AssertionError("drifted repository was fenced")
    expect(not store.startup_fenced and not adapter.calls, adapter.calls)


def test_immutable_container_recreation_and_unknown_ownership_fail_closed() -> None:
    target, state = docker_target()
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove"
    )
    state.replacement_fingerprint = "container-identity:replacement"
    result = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(result.status == "needs_attention", result.to_dict())
    expect(store.startup_fenced and not store.hidden, store.installation_status)
    expect(not adapter.calls, adapter.calls)

    target2, state2 = docker_target("sha256:unknown")
    state2.ownership_observable = False
    lifecycle2, store2, adapter2 = lifecycle_case(((target2, state2),))
    _plan, result2 = plan_and_apply(lifecycle2)
    expect(result2["status"] == "needs_attention", result2)
    expect(store2.startup_fenced and not store2.hidden, store2.installation_status)
    expect(not adapter2.calls, adapter2.calls)


def test_listener_boundary_and_zombie_semantics() -> None:
    target, state = server_target()
    state.running_state = RunningState.STOPPED
    state.policy_values[target.policies[0].policy_id] = (True, "disabled")
    # A stopped PID with a still-live listener is not a verified stopped server.
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    _plan, result = plan_and_apply(lifecycle)
    expect(result["status"] == "needs_attention", result)
    expect(store.startup_fenced and not store.hidden, store.installation_status)
    expect(not adapter.calls, adapter.calls)

    target2, state2 = server_target("server:zombie")
    state2.running_state = RunningState.ZOMBIE
    state2.listener_active = False
    state2.policy_values[target2.policies[0].policy_id] = (True, "disabled")
    lifecycle2, store2, adapter2 = lifecycle_case(((target2, state2),))
    _plan2, result2 = plan_and_apply(lifecycle2)
    expect(result2["status"] == "succeeded", result2)
    expect(not adapter2.calls and store2.hidden, adapter2.calls)


def test_apply_is_idempotent() -> None:
    target, state = docker_target()
    lifecycle, _store, adapter = lifecycle_case(((target, state),))
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove"
    )
    first = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    calls = list(adapter.calls)
    second = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(first.status == "succeeded", first.to_dict())
    expect(second.status == "already_complete", second.to_dict())
    expect(adapter.calls == calls, adapter.calls)


def test_guard_race_has_one_winner() -> None:
    for index in range(40):
        target, state = docker_target(f"sha256:race-{index}", allocation=False)
        lifecycle, store, _adapter = lifecycle_case(((target, state),))
        plan = lifecycle.plan_repository_decommission(
            "repo-1", actor="tester", reason="race"
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def guard() -> None:
            barrier.wait()
            try:
                lifecycle.reserve_repository_action(
                    "repo-1",
                    RepositoryAction.START,
                    request_id=f"start-{index}",
                    actor="tester",
                )
                outcomes.append("guard")
            except (ActionFencedError, ConcurrentLifecycleError):
                outcomes.append("guard-blocked")

        def fence() -> None:
            barrier.wait()
            try:
                store.fence_repository(plan, actor="tester")
                outcomes.append("fence")
            except (ActionFencedError, ConcurrentLifecycleError):
                outcomes.append("fence-blocked")

        threads = [threading.Thread(target=guard), threading.Thread(target=fence)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        expect(
            sorted(outcomes)
            in (["fence", "guard-blocked"], ["fence-blocked", "guard"]),
            outcomes,
        )
        expect(not (store.startup_fenced and bool(store.permits)), outcomes)


def test_reinstall_is_explicit_never_starts_and_incomplete_is_blocked() -> None:
    target, state = docker_target()
    lifecycle, store, adapter = lifecycle_case(((target, state),))
    try:
        lifecycle.reinstall_repository(
            "repo-1", actor="tester", reason="restore", explicit=False
        )
    except ExplicitConfirmationRequired:
        pass
    else:
        raise AssertionError("implicit reinstall succeeded")

    adapter.fail_stop.add(target.resource_id)
    plan = lifecycle.plan_repository_decommission(
        "repo-1", actor="tester", reason="remove"
    )
    result = lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(result.status == "needs_attention", result.to_dict())
    try:
        lifecycle.reinstall_repository(
            "repo-1", actor="tester", reason="restore", explicit=True
        )
    except LifecycleError:
        pass
    else:
        raise AssertionError("incomplete decommission was re-enabled")
    adapter.fail_stop.clear()
    lifecycle.apply_repository_decommission(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    calls = list(adapter.calls)
    installed = lifecycle.reinstall_repository(
        "repo-1", actor="tester", reason="restore", explicit=True
    )
    expect(installed.status == "installed" and not installed.started, installed)
    expect(not installed.hidden and not store.startup_fenced, installed)
    expect(adapter.calls == calls, adapter.calls)


def test_exact_attach_and_standalone_retirement() -> None:
    target, state = docker_target("sha256:standalone")
    lifecycle, store, adapter = lifecycle_case(((target, state),), standalone=True)
    # The repository exists and is installed even though this resource is not a member.
    result = lifecycle.attach_resource(
        "repo-1", target, actor="tester", reason="operator chose repository"
    )
    expect(result.attached and not result.started and not adapter.calls, result)
    expect(store.attached[target.ledger_key] == "repo-1", store.attached)

    target2, state2 = docker_target("sha256:retire")
    lifecycle2, store2, adapter2 = lifecycle_case(((target2, state2),), standalone=True)
    plan = lifecycle2.plan_standalone_retirement(
        target2, actor="tester", reason="retire standalone resource"
    )
    retired = lifecycle2.apply_standalone_retirement(
        plan.plan_id, plan.fingerprint, actor="tester"
    )
    expect(retired.status == "succeeded" and retired.hidden, retired.to_dict())
    expect(store2.retirements[target2.ledger_key] == "retired", store2.retirements)
    expect(adapter2.calls[0].startswith("disable:"), adapter2.calls)
    expect(adapter2.calls[1] == f"stop:{target2.resource_id}", adapter2.calls)
    try:
        lifecycle2.reserve_resource_action(
            target2,
            RepositoryAction.START,
            request_id="start-retired",
            actor="tester",
        )
    except ActionFencedError:
        pass
    else:
        raise AssertionError("retired exact resource was allowed to start")

    try:
        ExactResourceRef("", ResourceKind.CONTAINER, "fp", "binding", "owner")
    except ValueError:
        pass
    else:
        raise AssertionError("name-only resource became an actionable identity")


def test_standalone_unknown_authority_is_not_retired() -> None:
    target, state = docker_target("sha256:unowned")
    lifecycle, store, adapter = lifecycle_case(((target, state),), standalone=True)
    store.authority[target.ledger_key] = "conflicting"
    try:
        lifecycle.plan_standalone_retirement(
            target, actor="tester", reason="unsafe"
        )
    except OwnershipError:
        pass
    else:
        raise AssertionError("conflicting standalone ownership produced a plan")
    expect(store.retirements[target.ledger_key] is None and not adapter.calls, store.retirements)


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"repository lifecycle self-test passed ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
