"""SQLite persistence for :mod:`devcoordinator.repository_lifecycle`.

Plan authority is normalized across operations, targets, and typed target
parameters.  JSON columns contain diagnostic evidence only; they are never
read to decide which host resource may be mutated.
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
import re
import sqlite3
from typing import Any, Mapping, Sequence

from .repository_lifecycle import (
    ActionFencedError,
    ActionPermit,
    AllocationKind,
    AllocationRef,
    AttachResult,
    CapturedStartupPolicyState,
    ConcurrentLifecycleError,
    ExactResourceRef,
    InstallationResult,
    LifecycleError,
    LifecyclePlan,
    OperationProgress,
    OperationStatus,
    OwnershipError,
    PlanDriftError,
    PolicyKind,
    PolicyObservation,
    RepositoryAction,
    RepositoryDecommissionPlan,
    RepositorySnapshot,
    ResourceKind,
    StandaloneRetirementPlan,
    StandaloneSnapshot,
    StartupPolicyRef,
    TargetPhase,
    TargetProgress,
)
from .store import CoordinatorStore, canonical_json, deterministic_id, fingerprint, utc_timestamp


REPOSITORY_TARGET_KIND = "repository"
REPOSITORY_TARGET_ACTION = "fence_and_decommission"
_RESTORABLE_SYSTEMD_STATES = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "static",
        "indirect",
        "generated",
        "transient",
        "alias",
    }
)


class SQLiteLifecyclePersistence:
    """Production lifecycle persistence backed by one ``CoordinatorStore``."""

    def __init__(self, store: CoordinatorStore) -> None:
        self.store = store

    def repository_snapshot(self, repo_id: str) -> RepositorySnapshot:
        with self.store.read_transaction() as connection:
            return self._repository_snapshot(connection, repo_id)

    def standalone_snapshot(self, resource: ExactResourceRef) -> StandaloneSnapshot:
        with self.store.read_transaction() as connection:
            return self._standalone_snapshot(connection, resource)

    def resolve_standalone_resource(
        self,
        resource_kind: ResourceKind,
        resource_id: str,
        control_binding_id: str,
    ) -> ExactResourceRef:
        """Resolve exact normalized IDs to a mutation ref without name inference."""

        with self.store.read_transaction() as connection:
            unassigned = connection.execute(
                """
                SELECT unassigned_id FROM unassigned_resources
                WHERE resource_kind = ? AND resource_id = ? AND status = 'active'
                LIMIT 1
                """,
                (resource_kind.value, resource_id),
            ).fetchone()
            if unassigned is None:
                raise LifecycleError("resource is not an active unassigned host resource")
            binding = connection.execute(
                """
                SELECT * FROM control_bindings
                WHERE binding_id = ? AND resource_kind = ? AND resource_id = ?
                """,
                (control_binding_id, resource_kind.value, resource_id),
            ).fetchone()
            if binding is None or binding["authority_state"] != "authoritative":
                raise OwnershipError("resource has no exact authoritative control binding")
            native_identity, conflict = self._native_identity(
                connection, resource_kind, resource_id
            )
            if conflict:
                raise PlanDriftError(conflict)
            policies = tuple(
                self._policies_by_resource(
                    connection,
                    resource_kind=resource_kind.value,
                    resource_id=resource_id,
                ).get((resource_kind.value, resource_id), ())
            )
            immutable = _standalone_immutable_fingerprint(
                resource_kind, resource_id, native_identity
            )
            return ExactResourceRef(
                resource_id=resource_id,
                kind=resource_kind,
                immutable_fingerprint=immutable,
                control_binding_id=control_binding_id,
                ownership_fingerprint=_binding_fingerprint(binding),
                policies=policies,
                allocations=(),
                native_identity=native_identity,
                control_contract_fingerprint=_binding_control_contract(binding),
            )

    def save_repository_plan(
        self, plan: RepositoryDecommissionPlan
    ) -> RepositoryDecommissionPlan:
        with self.store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT operation_id FROM operations
                WHERE repo_id = ? AND kind = 'repository_decommission'
                  AND status = 'planned' AND request_fingerprint = ?
                ORDER BY created_at LIMIT 1
                """,
                (plan.repo_id, plan.fingerprint),
            ).fetchone()
            if existing is not None:
                loaded = self._load_plan(connection, str(existing["operation_id"]))
                if not isinstance(loaded, RepositoryDecommissionPlan):
                    raise LifecycleError("stored repository plan has the wrong kind")
                return loaded
            timestamp = plan.created_at
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, kind, status, phase, generation,
                    request_fingerprint, owner_uid, actor, created_at, updated_at
                ) VALUES (?, ?, 'repository_decommission', 'planned', 'planned', 0,
                          ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.repo_id,
                    plan.fingerprint,
                    os.geteuid(),
                    plan.actor,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO operation_targets(
                    operation_id, ordinal, target_kind, target_id, action,
                    immutable_fingerprint, phase, status
                ) VALUES (?, 0, ?, ?, ?, ?, 'planned', 'pending')
                """,
                (
                    plan.plan_id,
                    REPOSITORY_TARGET_KIND,
                    plan.repo_id,
                    REPOSITORY_TARGET_ACTION,
                    plan.repository_fingerprint,
                ),
            )
            repository_parameters: dict[str, Any] = {
                "repository_fingerprint": plan.repository_fingerprint,
                "installation_generation": plan.installation_generation,
                "reason": plan.reason,
                "created_at": plan.created_at,
            }
            _encode_allocations(
                repository_parameters,
                "allocation",
                plan.repository_allocations,
            )
            _insert_parameters(connection, plan.plan_id, 0, repository_parameters)
            for ordinal, target in enumerate(plan.targets, 1):
                self._insert_resource_target(connection, plan.plan_id, ordinal, target)
                connection.execute(
                    """
                    INSERT INTO operation_target_dependencies(
                        operation_id, target_ordinal, depends_on_ordinal
                    ) VALUES (?, ?, 0)
                    """,
                    (plan.plan_id, ordinal),
                )
            return plan

    def save_retirement_plan(
        self, plan: StandaloneRetirementPlan
    ) -> StandaloneRetirementPlan:
        with self.store.immediate_transaction() as connection:
            existing = connection.execute(
                """
                SELECT o.operation_id
                FROM operations o
                JOIN operation_targets t USING(operation_id)
                WHERE o.kind = 'standalone_resource_retirement'
                  AND o.status = 'planned' AND o.request_fingerprint = ?
                  AND t.ordinal = 0 AND t.target_kind = ? AND t.target_id = ?
                ORDER BY o.created_at LIMIT 1
                """,
                (plan.fingerprint, plan.target.kind.value, plan.target.resource_id),
            ).fetchone()
            if existing is not None:
                loaded = self._load_plan(connection, str(existing["operation_id"]))
                if not isinstance(loaded, StandaloneRetirementPlan):
                    raise LifecycleError("stored retirement plan has the wrong kind")
                return loaded
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, kind, status, phase, generation,
                    request_fingerprint, owner_uid, actor, created_at, updated_at
                ) VALUES (?, 'standalone_resource_retirement', 'planned', 'planned', 0,
                          ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.fingerprint,
                    os.geteuid(),
                    plan.actor,
                    plan.created_at,
                    plan.created_at,
                ),
            )
            self._insert_resource_target(connection, plan.plan_id, 0, plan.target)
            _insert_parameters(
                connection,
                plan.plan_id,
                0,
                {"reason": plan.reason, "created_at": plan.created_at},
            )
            return plan

    def load_plan(self, plan_id: str) -> LifecyclePlan:
        with self.store.read_transaction() as connection:
            return self._load_plan(connection, plan_id)

    def resolve_lifecycle_plan(self, plan_id: str) -> LifecyclePlan:
        """Follow a durable observation-refresh successor chain.

        The operator-confirmed plan stays immutable.  A fresh observation may
        require a new generation-bearing exact plan; this link makes retries
        using the confirmed ID converge on that execution plan after response
        loss or an interrupted lifecycle.
        """

        with self.store.read_transaction() as connection:
            current = str(plan_id)
            visited: set[str] = set()
            while True:
                if current in visited:
                    raise LifecycleError("lifecycle plan successor chain contains a cycle")
                visited.add(current)
                if len(visited) > 64:
                    raise LifecycleError("lifecycle plan successor chain is unreasonably deep")
                row = connection.execute(
                    """
                    SELECT value FROM operation_target_parameters
                    WHERE operation_id = ? AND target_ordinal = 0
                      AND name = 'lifecycle.successor_plan_id'
                    """,
                    (current,),
                ).fetchone()
                if row is None:
                    return self._load_plan(connection, current)
                successor = str(row["value"] or "")
                if not successor:
                    raise LifecycleError("lifecycle plan successor identity is empty")
                current = successor

    def bind_lifecycle_plan_successor(
        self, predecessor: LifecyclePlan, successor: LifecyclePlan
    ) -> None:
        """Atomically bind one immutable confirmed plan to its refreshed plan."""

        if predecessor.plan_id == successor.plan_id:
            return
        if type(predecessor) is not type(successor):
            raise PlanDriftError("lifecycle plan successor has a different operation kind")
        if isinstance(predecessor, RepositoryDecommissionPlan):
            if predecessor.repo_id != successor.repo_id:
                raise PlanDriftError("repository plan successor targets another repository")
        else:
            if predecessor.target.ledger_key != successor.target.ledger_key:
                raise PlanDriftError("retirement plan successor targets another resource")
        with self.store.immediate_transaction() as connection:
            predecessor_row = _operation_row(connection, predecessor.plan_id)
            successor_row = _operation_row(connection, successor.plan_id)
            if str(predecessor_row["request_fingerprint"]) != predecessor.fingerprint:
                raise PlanDriftError("confirmed lifecycle plan fingerprint changed")
            if str(successor_row["request_fingerprint"]) != successor.fingerprint:
                raise PlanDriftError("successor lifecycle plan fingerprint changed")
            if (
                predecessor_row["kind"] != successor_row["kind"]
                or predecessor_row["repo_id"] != successor_row["repo_id"]
            ):
                raise PlanDriftError("lifecycle plan successor authority changed")
            existing = connection.execute(
                """
                SELECT value FROM operation_target_parameters
                WHERE operation_id = ? AND target_ordinal = 0
                  AND name = 'lifecycle.successor_plan_id'
                """,
                (predecessor.plan_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["value"]) != successor.plan_id:
                    raise PlanDriftError(
                        "confirmed lifecycle plan already has another durable successor"
                    )
                if predecessor_row["status"] != "cancelled":
                    raise PlanDriftError(
                        "linked lifecycle predecessor is not durably superseded"
                    )
                # Idempotent replay: the successor may now be planned, active,
                # complete, or itself superseded by a later fresh observation.
                return
            else:
                if predecessor_row["status"] != "planned":
                    raise PlanDriftError(
                        "only a planned lifecycle operation can gain a successor"
                    )
                if successor_row["status"] != "planned":
                    raise PlanDriftError(
                        "a new lifecycle successor must be an unapplied plan"
                    )
                nested = connection.execute(
                    """
                    SELECT 1 FROM operation_target_parameters
                    WHERE operation_id = ? AND target_ordinal = 0
                      AND name = 'lifecycle.successor_plan_id'
                    """,
                    (successor.plan_id,),
                ).fetchone()
                if nested is not None:
                    raise PlanDriftError(
                        "a new lifecycle successor cannot already be superseded"
                    )
                connection.execute(
                    """
                    INSERT INTO operation_target_parameters(
                        operation_id, target_ordinal, name, value, value_type
                    ) VALUES (?, 0, 'lifecycle.successor_plan_id', ?, 'text')
                    """,
                    (predecessor.plan_id, successor.plan_id),
                )
            timestamp = utc_timestamp()
            changed = connection.execute(
                """
                UPDATE operations
                SET status = 'cancelled', phase = 'superseded',
                    generation = generation + 1, result_json = ?,
                    error_code = NULL, error_message = NULL, updated_at = ?
                WHERE operation_id = ? AND status = 'planned'
                """,
                (
                    canonical_json(
                        {
                            "status": "superseded",
                            "successor_plan_id": successor.plan_id,
                            "successor_plan_fingerprint": successor.fingerprint,
                        }
                    ),
                    timestamp,
                    predecessor.plan_id,
                ),
            ).rowcount
            if changed != 1:
                raise PlanDriftError(
                    "only an unapplied confirmed lifecycle plan can gain a successor"
                )

    def fence_repository(
        self, plan: RepositoryDecommissionPlan, *, actor: str
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, plan.plan_id)
            _verify_operation_fingerprint(operation, plan.fingerprint)
            if operation["status"] == "succeeded":
                pass
            elif operation["status"] in {"running", "needs_attention", "partial", "failed"}:
                installation = _installation_row(connection, plan.repo_id)
                if (
                    installation["startup_fenced"] != 1
                    or installation["operation_id"] != plan.plan_id
                ):
                    raise ConcurrentLifecycleError("repository fence belongs to another operation")
                connection.execute(
                    """
                    UPDATE operations SET status = 'running', error_code = NULL,
                        error_message = NULL, updated_at = ? WHERE operation_id = ?
                    """,
                    (utc_timestamp(), plan.plan_id),
                )
            elif operation["status"] == "planned":
                current = self._repository_snapshot(connection, plan.repo_id)
                if (
                    current.repository_fingerprint != plan.repository_fingerprint
                    or current.installation_generation != plan.installation_generation
                    or tuple(sorted(current.targets, key=lambda item: item.ledger_key))
                    != plan.targets
                    or tuple(
                        sorted(
                            current.repository_allocations,
                            key=lambda item: (item.kind.value, item.allocation_id),
                        )
                    )
                    != plan.repository_allocations
                ):
                    raise PlanDriftError("repository changed after the plan was recorded")
                conflict = connection.execute(
                    """
                    SELECT operation_id FROM operations
                    WHERE repo_id = ? AND status = 'running' AND operation_id != ?
                    LIMIT 1
                    """,
                    (plan.repo_id, plan.plan_id),
                ).fetchone()
                if conflict is not None:
                    raise ConcurrentLifecycleError(
                        f"repository action {conflict['operation_id']} is already running"
                    )
                installation = _installation_row(connection, plan.repo_id)
                if installation["status"] != "installed" or installation["startup_fenced"]:
                    raise ActionFencedError("repository is not installed and startable")
                timestamp = utc_timestamp()
                changed = connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabling', startup_fenced = 1,
                        generation = generation + 1, operation_id = ?, reason = ?,
                        actor = ?, updated_at = ?
                    WHERE repo_id = ? AND status = 'installed' AND startup_fenced = 0
                      AND generation = ?
                    """,
                    (
                        plan.plan_id,
                        plan.reason,
                        actor,
                        timestamp,
                        plan.repo_id,
                        plan.installation_generation,
                    ),
                ).rowcount
                if changed != 1:
                    raise PlanDriftError("repository installation changed while fencing")
                connection.execute(
                    """
                    UPDATE operations SET status = 'running', phase = 'fenced',
                        generation = generation + 1, actor = ?, updated_at = ?
                    WHERE operation_id = ? AND status = 'planned'
                    """,
                    (actor, timestamp, plan.plan_id),
                )
                connection.execute(
                    """
                    UPDATE operation_targets SET phase = 'fenced', status = 'succeeded',
                        started_at = COALESCE(started_at, ?), finished_at = ?,
                        result_json = ?
                    WHERE operation_id = ? AND ordinal = 0
                    """,
                    (
                        timestamp,
                        timestamp,
                        canonical_json({"startup_fenced": True}),
                        plan.plan_id,
                    ),
                )
            else:
                raise LifecycleError(f"operation cannot be resumed from {operation['status']}")
        return self.operation_progress(plan.plan_id)

    def fence_resource(
        self, plan: StandaloneRetirementPlan, *, actor: str
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, plan.plan_id)
            _verify_operation_fingerprint(operation, plan.fingerprint)
            if operation["status"] == "succeeded":
                pass
            elif operation["status"] in {"running", "needs_attention", "partial", "failed"}:
                retirement = connection.execute(
                    "SELECT * FROM resource_retirements WHERE host_resource_id = ?",
                    (plan.target.resource_id,),
                ).fetchone()
                if (
                    retirement is None
                    or retirement["operation_id"] != plan.plan_id
                    or retirement["status"] != "disabling"
                ):
                    raise ConcurrentLifecycleError("resource fence belongs to another operation")
                connection.execute(
                    "UPDATE operations SET status = 'running', updated_at = ? WHERE operation_id = ?",
                    (utc_timestamp(), plan.plan_id),
                )
            elif operation["status"] == "planned":
                current = self._standalone_snapshot(connection, plan.target)
                if current.resource != plan.target:
                    raise PlanDriftError("standalone resource changed after planning")
                if current.attached_repo_id is not None:
                    raise OwnershipError("standalone resource became repository-owned")
                if current.authority_state != "authoritative":
                    raise OwnershipError("standalone resource controller is not authoritative")
                active_guard = connection.execute(
                    """
                    SELECT o.operation_id FROM operations o
                    JOIN operation_targets t USING(operation_id)
                    WHERE o.status = 'running' AND o.operation_id != ?
                      AND t.target_kind = ? AND t.target_id = ? LIMIT 1
                    """,
                    (plan.plan_id, plan.target.kind.value, plan.target.resource_id),
                ).fetchone()
                if active_guard is not None:
                    raise ConcurrentLifecycleError(
                        f"resource action {active_guard['operation_id']} is already running"
                    )
                timestamp = utc_timestamp()
                try:
                    connection.execute(
                        """
                        INSERT INTO resource_retirements(
                            host_resource_id, resource_kind, immutable_fingerprint,
                            status, operation_id, reason, actor, started_at, updated_at
                        ) VALUES (?, ?, ?, 'disabling', ?, ?, ?, ?, ?)
                        """,
                        (
                            plan.target.resource_id,
                            plan.target.kind.value,
                            plan.target.immutable_fingerprint,
                            plan.plan_id,
                            plan.reason,
                            actor,
                            timestamp,
                            timestamp,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise ConcurrentLifecycleError("resource already has a retirement fence") from error
                connection.execute(
                    """
                    UPDATE operations SET status = 'running', phase = 'fenced',
                        generation = generation + 1, actor = ?, updated_at = ?
                    WHERE operation_id = ? AND status = 'planned'
                    """,
                    (actor, timestamp, plan.plan_id),
                )
            else:
                raise LifecycleError(f"operation cannot be resumed from {operation['status']}")
        return self.operation_progress(plan.plan_id)

    def operation_progress(self, operation_id: str) -> OperationProgress:
        with self.store.read_transaction() as connection:
            return self._operation_progress(connection, operation_id)

    def begin_target_phase(
        self, operation_id: str, target: ExactResourceRef, phase: TargetPhase
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            _require_target_row(connection, operation_id, target)
            connection.execute(
                """
                UPDATE operation_targets SET status = 'running', error_json = NULL,
                    started_at = COALESCE(started_at, ?)
                WHERE operation_id = ? AND target_kind = ? AND target_id = ?
                """,
                (utc_timestamp(), operation_id, target.kind.value, target.resource_id),
            )
            connection.execute(
                """
                UPDATE operations SET status = 'running', error_code = NULL,
                    error_message = NULL, updated_at = ? WHERE operation_id = ?
                """,
                (utc_timestamp(), operation_id),
            )
        return self.operation_progress(operation_id)

    def advance_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        evidence: Mapping[str, Any],
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            row = _require_target_row(connection, operation_id, target)
            old_phase = _phase_from_text(str(row["phase"]))
            if old_phase < phase:
                if phase is TargetPhase.POLICIES_DISABLED:
                    for policy in target.policies:
                        changed = connection.execute(
                            """
                            UPDATE startup_policies
                            SET current_value = desired_disabled_value,
                                generation = generation + 1, updated_at = ?
                            WHERE policy_id = ? AND resource_kind = ? AND resource_id = ?
                              AND immutable_fingerprint = ?
                            """,
                            (
                                utc_timestamp(),
                                policy.policy_id,
                                target.kind.value,
                                target.resource_id,
                                policy.immutable_fingerprint,
                            ),
                        ).rowcount
                        if changed != 1:
                            raise PlanDriftError(
                                f"startup policy {policy.policy_id} changed during decommission"
                            )
                merged = _merge_evidence(row["result_json"], phase, evidence)
                connection.execute(
                    """
                    UPDATE operation_targets
                    SET phase = ?, status = ?, result_json = ?, error_json = NULL,
                        finished_at = CASE WHEN ? = 'complete' THEN ? ELSE finished_at END
                    WHERE operation_id = ? AND target_kind = ? AND target_id = ?
                    """,
                    (
                        phase.name.lower(),
                        "succeeded" if phase is TargetPhase.COMPLETE else "running",
                        canonical_json(merged),
                        phase.name.lower(),
                        utc_timestamp(),
                        operation_id,
                        target.kind.value,
                        target.resource_id,
                    ),
                )
            connection.execute(
                "UPDATE operations SET phase = ?, updated_at = ? WHERE operation_id = ?",
                (phase.name.lower(), utc_timestamp(), operation_id),
            )
        return self.operation_progress(operation_id)

    def capture_startup_policy_state(
        self,
        operation_id: str,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        observation: PolicyObservation,
    ) -> CapturedStartupPolicyState:
        """Durably bind pre-disable policy state before the host mutation."""

        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, operation_id)
            _require_target_row(connection, operation_id, target)
            policy_row = connection.execute(
                """
                SELECT * FROM startup_policies
                WHERE policy_id = ? AND resource_kind = ? AND resource_id = ?
                  AND policy_kind = ? AND immutable_fingerprint = ?
                """,
                (
                    policy.policy_id,
                    target.kind.value,
                    target.resource_id,
                    policy.kind.value,
                    policy.immutable_fingerprint,
                ),
            ).fetchone()
            if policy_row is None:
                raise PlanDriftError(
                    f"startup policy {policy.policy_id} changed before capture"
                )
            native_fingerprint = _sha(dict(target.native_identity))
            existing = connection.execute(
                "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
                (policy.policy_id,),
            ).fetchone()
            if existing is not None:
                retained = _captured_policy_state(existing)
                _verify_capture_identity(
                    retained,
                    operation["repo_id"],
                    target,
                    policy,
                    native_fingerprint,
                )
                # A reinstall followed by another remove before any start must
                # not overwrite the original enabled state with the currently
                # disabled host state.  The original capture remains the only
                # truthful restoration authority.
                if retained.status == "captured":
                    if observation.value in {
                        retained.captured_value,
                        policy.disabled_value,
                    }:
                        return retained
                    raise PlanDriftError(
                        f"startup policy {policy.policy_id} drifted after capture"
                    )
                if retained.status == "not_required":
                    if observation.value == policy.disabled_value:
                        return retained
                    if str(existing["captured_operation_id"]) == operation_id:
                        raise PlanDriftError(
                            f"startup policy {policy.policy_id} drifted after capture"
                        )
            if not observation.observable or observation.value is None:
                raise OwnershipError(
                    f"startup policy {policy.policy_id} pre-disable state is unobservable"
                )
            captured_value = str(observation.value)
            docker_policy: str | None = None
            supervisor_manager: str | None = None
            supervisor_state: str | None = None
            supervisor_loaded: bool | None = None
            supervisor_enabled: bool | None = None
            if policy.kind is PolicyKind.DOCKER_RESTART:
                docker_policy = observation.docker_restart_policy
                if docker_policy is None or docker_policy != captured_value:
                    raise OwnershipError("Docker restart policy state is incomplete")
                if not _known_docker_restart_policy(docker_policy):
                    raise LifecycleError(
                        f"Docker restart policy {docker_policy!r} cannot be restored exactly"
                    )
            elif policy.kind is PolicyKind.SUPERVISOR:
                supervisor_manager = observation.supervisor_manager
                supervisor_state = observation.supervisor_unit_file_state
                supervisor_loaded = observation.supervisor_loaded
                supervisor_enabled = observation.supervisor_enabled
                if (
                    supervisor_manager not in {"systemd", "launchd"}
                    or supervisor_state is None
                    or supervisor_loaded is None
                    or supervisor_enabled is None
                ):
                    raise OwnershipError("supervisor pre-disable state is incomplete")
                if (
                    not observation.disabled
                    and supervisor_manager == "systemd"
                    and supervisor_state not in _RESTORABLE_SYSTEMD_STATES
                ):
                    raise LifecycleError(
                        f"systemd state {supervisor_state!r} cannot be restored exactly"
                    )
            else:
                # Coordinator/Compose state lives in the normalized row.  The
                # durable repository fence is already active by this phase, so
                # a host observation correctly reports disabled and cannot be
                # used to reconstruct the value that preceded the fence.
                captured_value = str(policy_row["current_value"])
            restore_required = captured_value != policy.disabled_value
            timestamp = utc_timestamp()
            status = "captured" if restore_required else "not_required"
            connection.execute(
                """
                INSERT INTO startup_policy_restore_states(
                    policy_id, repo_id, resource_kind, resource_id, policy_kind,
                    policy_immutable_fingerprint, target_immutable_fingerprint,
                    control_binding_id, ownership_fingerprint,
                    native_identity_fingerprint, captured_value,
                    restore_required, status, docker_restart_policy,
                    supervisor_manager, supervisor_unit_file_state,
                    supervisor_loaded, supervisor_enabled,
                    captured_operation_id, capture_generation,
                    captured_at, restored_at, last_restore_permit_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          COALESCE((SELECT capture_generation + 1
                                    FROM startup_policy_restore_states
                                    WHERE policy_id = ?), 0),
                          ?, NULL, NULL, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    repo_id = excluded.repo_id,
                    resource_kind = excluded.resource_kind,
                    resource_id = excluded.resource_id,
                    policy_kind = excluded.policy_kind,
                    policy_immutable_fingerprint = excluded.policy_immutable_fingerprint,
                    target_immutable_fingerprint = excluded.target_immutable_fingerprint,
                    control_binding_id = excluded.control_binding_id,
                    ownership_fingerprint = excluded.ownership_fingerprint,
                    native_identity_fingerprint = excluded.native_identity_fingerprint,
                    captured_value = excluded.captured_value,
                    restore_required = excluded.restore_required,
                    status = excluded.status,
                    docker_restart_policy = excluded.docker_restart_policy,
                    supervisor_manager = excluded.supervisor_manager,
                    supervisor_unit_file_state = excluded.supervisor_unit_file_state,
                    supervisor_loaded = excluded.supervisor_loaded,
                    supervisor_enabled = excluded.supervisor_enabled,
                    captured_operation_id = excluded.captured_operation_id,
                    capture_generation = startup_policy_restore_states.capture_generation + 1,
                    captured_at = excluded.captured_at,
                    restored_at = NULL,
                    last_restore_permit_id = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    policy.policy_id,
                    operation["repo_id"],
                    target.kind.value,
                    target.resource_id,
                    policy.kind.value,
                    policy.immutable_fingerprint,
                    target.immutable_fingerprint,
                    target.control_binding_id,
                    target.ownership_fingerprint,
                    native_fingerprint,
                    captured_value,
                    int(restore_required),
                    status,
                    docker_policy,
                    supervisor_manager,
                    supervisor_state,
                    _optional_bool(supervisor_loaded),
                    _optional_bool(supervisor_enabled),
                    operation_id,
                    policy.policy_id,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
                (policy.policy_id,),
            ).fetchone()
            if row is None:
                raise LifecycleError("startup policy capture was not persisted")
            return _captured_policy_state(row)

    def fail_target(
        self,
        operation_id: str,
        target: ExactResourceRef,
        phase: TargetPhase,
        error: Mapping[str, Any],
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            _require_target_row(connection, operation_id, target)
            payload = dict(error)
            payload.setdefault("attempted_phase", phase.name.lower())
            connection.execute(
                """
                UPDATE operation_targets SET status = 'failed', error_json = ?
                WHERE operation_id = ? AND target_kind = ? AND target_id = ?
                """,
                (
                    canonical_json(payload),
                    operation_id,
                    target.kind.value,
                    target.resource_id,
                ),
            )
        return self.operation_progress(operation_id)

    def mark_needs_attention(self, operation_id: str) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            errors = [
                _json_mapping(row["error_json"])
                for row in connection.execute(
                    """
                    SELECT error_json FROM operation_targets
                    WHERE operation_id = ? AND error_json IS NOT NULL ORDER BY ordinal
                    """,
                    (operation_id,),
                )
            ]
            connection.execute(
                """
                UPDATE operations SET status = 'needs_attention',
                    error_code = 'target_failure',
                    error_message = 'one or more exact lifecycle targets need attention',
                    result_json = ?, updated_at = ? WHERE operation_id = ?
                """,
                (canonical_json({"errors": errors}), utc_timestamp(), operation_id),
            )
        return self.operation_progress(operation_id)

    def deactivate_allocations(
        self,
        operation_id: str,
        target: ExactResourceRef,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        _ = target
        with self.store.immediate_transaction() as connection:
            _operation_row(connection, operation_id)
            return self._deactivate_allocations(connection, allocations)

    def deactivate_repository_allocations(
        self,
        operation_id: str,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        with self.store.immediate_transaction() as connection:
            evidence = self._deactivate_allocations(connection, allocations)
            row = connection.execute(
                "SELECT result_json FROM operation_targets WHERE operation_id = ? AND ordinal = 0",
                (operation_id,),
            ).fetchone()
            merged = _merge_evidence(
                row["result_json"] if row else None,
                TargetPhase.ALLOCATIONS_DEACTIVATED,
                evidence,
            )
            connection.execute(
                """
                UPDATE operation_targets SET phase = 'allocations_deactivated',
                    status = 'succeeded', result_json = ?, error_json = NULL
                WHERE operation_id = ? AND ordinal = 0
                """,
                (canonical_json(merged), operation_id),
            )
            return evidence

    def fail_repository_allocations(
        self, operation_id: str, error: Mapping[str, Any]
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            connection.execute(
                """
                UPDATE operation_targets SET status = 'failed', error_json = ?
                WHERE operation_id = ? AND ordinal = 0
                """,
                (canonical_json(dict(error)), operation_id),
            )
        return self.operation_progress(operation_id)

    def complete_repository_decommission(
        self, plan: RepositoryDecommissionPlan
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, plan.plan_id)
            _verify_operation_fingerprint(operation, plan.fingerprint)
            if operation["status"] == "succeeded":
                pass
            else:
                incomplete = connection.execute(
                    """
                    SELECT target_kind, target_id FROM operation_targets
                    WHERE operation_id = ? AND ordinal > 0
                      AND (phase != 'complete' OR status != 'succeeded') LIMIT 1
                    """,
                    (plan.plan_id,),
                ).fetchone()
                if incomplete is not None:
                    raise LifecycleError("repository target ledger is incomplete")
                self._verify_no_active_allocations(connection, plan.repo_id)
                self._verify_policies_disabled(connection, repo_id=plan.repo_id)
                self._verify_policy_captures(connection, repo_id=plan.repo_id)
                current_memberships = {
                    (row["resource_kind"], row["host_resource_id"], row["immutable_fingerprint"])
                    for row in connection.execute(
                        """
                        SELECT resource_kind, host_resource_id, immutable_fingerprint
                        FROM repository_memberships WHERE repo_id = ?
                        """,
                        (plan.repo_id,),
                    )
                }
                planned_memberships = {
                    (item.kind.value, item.resource_id, item.immutable_fingerprint)
                    for item in plan.targets
                }
                if current_memberships != planned_memberships:
                    raise PlanDriftError("repository membership changed while fenced")
                timestamp = utc_timestamp()
                for target in plan.targets:
                    self._record_verified_stopped(
                        connection,
                        target,
                        timestamp=timestamp,
                        reason="repository decommission verified stopped",
                    )
                if plan.targets:
                    connection.execute(
                        """
                        UPDATE schema_metadata
                        SET observation_revision = observation_revision + 1
                        WHERE singleton = 1
                        """
                    )
                changed = connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'disabled', startup_fenced = 1,
                        generation = generation + 1, disabled_at = ?, updated_at = ?
                    WHERE repo_id = ? AND status = 'disabling'
                      AND startup_fenced = 1 AND operation_id = ?
                    """,
                    (timestamp, timestamp, plan.repo_id, plan.plan_id),
                ).rowcount
                if changed != 1:
                    raise ConcurrentLifecycleError("repository fence changed before completion")
                connection.execute(
                    """
                    UPDATE operation_targets SET phase = 'complete', status = 'succeeded',
                        finished_at = COALESCE(finished_at, ?)
                    WHERE operation_id = ? AND ordinal = 0
                    """,
                    (timestamp, plan.plan_id),
                )
                connection.execute(
                    """
                    UPDATE operations SET status = 'succeeded', phase = 'complete',
                        result_json = ?, error_code = NULL, error_message = NULL,
                        updated_at = ? WHERE operation_id = ?
                    """,
                    (
                        canonical_json(
                            {
                                "repo_id": plan.repo_id,
                                "hidden": True,
                                "startup_fenced": True,
                            }
                        ),
                        timestamp,
                        plan.plan_id,
                    ),
                )
        return self.operation_progress(plan.plan_id)

    def complete_resource_retirement(
        self, plan: StandaloneRetirementPlan
    ) -> OperationProgress:
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, plan.plan_id)
            _verify_operation_fingerprint(operation, plan.fingerprint)
            if operation["status"] != "succeeded":
                target = _require_target_row(connection, plan.plan_id, plan.target)
                if target["phase"] != "complete" or target["status"] != "succeeded":
                    raise LifecycleError("resource target ledger is incomplete")
                self._verify_policies_disabled(
                    connection,
                    resource_kind=plan.target.kind.value,
                    resource_id=plan.target.resource_id,
                )
                self._verify_policy_captures(
                    connection,
                    resource_kind=plan.target.kind.value,
                    resource_id=plan.target.resource_id,
                )
                timestamp = utc_timestamp()
                self._record_verified_stopped(
                    connection,
                    plan.target,
                    timestamp=timestamp,
                    reason="standalone retirement verified stopped",
                )
                connection.execute(
                    """
                    UPDATE schema_metadata
                    SET observation_revision = observation_revision + 1
                    WHERE singleton = 1
                    """
                )
                changed = connection.execute(
                    """
                    UPDATE resource_retirements SET status = 'retired', retired_at = ?,
                        updated_at = ?
                    WHERE host_resource_id = ? AND operation_id = ?
                      AND immutable_fingerprint = ? AND status = 'disabling'
                    """,
                    (
                        timestamp,
                        timestamp,
                        plan.target.resource_id,
                        plan.plan_id,
                        plan.target.immutable_fingerprint,
                    ),
                ).rowcount
                if changed != 1:
                    raise PlanDriftError("resource retirement fence changed")
                connection.execute(
                    """
                    UPDATE control_bindings SET authority_state = 'retired',
                        generation = generation + 1, updated_at = ?
                    WHERE binding_id = ? AND authority_state = 'authoritative'
                    """,
                    (timestamp, plan.target.control_binding_id),
                )
                connection.execute(
                    """
                    UPDATE unassigned_resources SET status = 'retired', updated_at = ?
                    WHERE resource_kind = ? AND resource_id = ? AND status = 'active'
                    """,
                    (timestamp, plan.target.kind.value, plan.target.resource_id),
                )
                connection.execute(
                    """
                    UPDATE operations SET status = 'succeeded', phase = 'complete',
                        result_json = ?, error_code = NULL, error_message = NULL,
                        updated_at = ? WHERE operation_id = ?
                    """,
                    (
                        canonical_json(
                            {
                                "resource_id": plan.target.resource_id,
                                "hidden": True,
                            }
                        ),
                        timestamp,
                        plan.plan_id,
                    ),
                )
        return self.operation_progress(plan.plan_id)

    def _record_verified_stopped(
        self,
        connection: sqlite3.Connection,
        target: ExactResourceRef,
        *,
        timestamp: str,
        reason: str,
    ) -> None:
        """Persist the exact stopped boundary already proved by the host adapter.

        Lifecycle completion is a host observation as well as a control-state
        transition.  Keeping the previous ``running`` observation would make a
        later explicit reinstall truthfully visible but falsely running.
        """

        if target.kind is ResourceKind.CONTAINER:
            previous = connection.execute(
                """
                SELECT health, restart_policy, ports_fingerprint, labels_fingerprint
                FROM docker_observations WHERE docker_resource_id = ?
                """,
                (target.resource_id,),
            ).fetchone()
            restart_policy = next(
                (
                    policy.disabled_value
                    for policy in target.policies
                    if policy.kind is PolicyKind.DOCKER_RESTART
                ),
                previous["restart_policy"] if previous is not None else None,
            )
            evidence = {
                "resource_kind": target.kind.value,
                "resource_id": target.resource_id,
                "immutable_fingerprint": target.immutable_fingerprint,
                "lifecycle": "stopped",
                "restart_policy": restart_policy,
                "reason": reason,
                "sampled_at": timestamp,
            }
            connection.execute(
                """
                INSERT INTO docker_observations(
                    docker_resource_id, lifecycle, health, restart_policy,
                    ports_fingerprint, labels_fingerprint, sampled_at,
                    observation_fingerprint
                ) VALUES (?, 'stopped', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(docker_resource_id) DO UPDATE SET
                    lifecycle = excluded.lifecycle,
                    restart_policy = excluded.restart_policy,
                    sampled_at = excluded.sampled_at,
                    observation_fingerprint = excluded.observation_fingerprint
                """,
                (
                    target.resource_id,
                    previous["health"] if previous is not None else None,
                    restart_policy,
                    previous["ports_fingerprint"] if previous is not None else None,
                    previous["labels_fingerprint"] if previous is not None else None,
                    timestamp,
                    fingerprint(evidence),
                ),
            )
            return

        if target.kind is ResourceKind.SERVER:
            previous = connection.execute(
                """
                SELECT source_resource_id, listener_host, listener_port
                FROM server_observations WHERE server_definition_id = ?
                """,
                (target.resource_id,),
            ).fetchone()
            evidence = {
                "resource_kind": target.kind.value,
                "resource_id": target.resource_id,
                "immutable_fingerprint": target.immutable_fingerprint,
                "lifecycle": "stopped",
                "reason": reason,
                "sampled_at": timestamp,
            }
            connection.execute(
                """
                INSERT INTO server_observations(
                    server_definition_id, source_resource_id, lifecycle,
                    pid, process_start_time, process_fingerprint,
                    listener_host, listener_port, listener_observable,
                    health_classification, health_ok, stopped_at,
                    stopped_reason, sampled_at, observation_fingerprint
                ) VALUES (?, ?, 'stopped', NULL, NULL, NULL, ?, ?, 1,
                          'stopped', NULL, ?, ?, ?, ?)
                ON CONFLICT(server_definition_id) DO UPDATE SET
                    lifecycle = excluded.lifecycle,
                    pid = NULL,
                    process_start_time = NULL,
                    process_fingerprint = NULL,
                    listener_observable = 1,
                    health_classification = 'stopped',
                    health_ok = NULL,
                    stopped_at = excluded.stopped_at,
                    stopped_reason = excluded.stopped_reason,
                    sampled_at = excluded.sampled_at,
                    observation_fingerprint = excluded.observation_fingerprint
                """,
                (
                    target.resource_id,
                    previous["source_resource_id"] if previous is not None else None,
                    previous["listener_host"] if previous is not None else None,
                    previous["listener_port"] if previous is not None else None,
                    timestamp,
                    reason,
                    timestamp,
                    fingerprint(evidence),
                ),
            )

    def install_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        with self.store.immediate_transaction() as connection:
            repository = _repository_row(connection, repo_id)
            if repository["state"] != "active":
                raise ActionFencedError("only an active canonical repository can be installed")
            existing = connection.execute(
                "SELECT status FROM repository_installations WHERE repo_id = ?",
                (repo_id,),
            ).fetchone()
            if existing is not None:
                raise LifecycleError("repository installation already exists; use reinstall")
            timestamp = utc_timestamp()
            connection.execute(
                """
                INSERT INTO repository_installations(
                    repo_id, status, startup_fenced, generation, reason,
                    actor, updated_at
                ) VALUES (?, 'installed', 0, 0, ?, ?, ?)
                """,
                (repo_id, reason, actor, timestamp),
            )
        return InstallationResult(repo_id, "installed", False, False)

    def reinstall_repository(
        self, repo_id: str, *, actor: str, reason: str
    ) -> InstallationResult:
        with self.store.immediate_transaction() as connection:
            installation = _installation_row(connection, repo_id)
            if installation["status"] != "disabled" or not installation["startup_fenced"]:
                raise LifecycleError("repository must complete decommission before reinstall")
            pending = connection.execute(
                """
                SELECT operation_id FROM operations
                WHERE repo_id = ? AND status IN ('planned','running','needs_attention','partial')
                LIMIT 1
                """,
                (repo_id,),
            ).fetchone()
            if pending is not None:
                raise ConcurrentLifecycleError("repository still has an incomplete lifecycle operation")
            timestamp = utc_timestamp()
            connection.execute(
                """
                UPDATE repository_installations
                SET status = 'installed', startup_fenced = 0,
                    generation = generation + 1, operation_id = NULL,
                    reinstalled_at = ?, reason = ?, actor = ?, updated_at = ?
                WHERE repo_id = ?
                """,
                (timestamp, reason, actor, timestamp, repo_id),
            )
        return InstallationResult(repo_id, "installed", False, False)

    def list_removed_repositories(self) -> Sequence[Mapping[str, Any]]:
        with self.store.read_transaction() as connection:
            return tuple(
                dict(row)
                for row in connection.execute(
                    """
                    SELECT r.repo_id, r.canonical_root, r.display_name,
                           i.status, i.disabled_at, i.reason, i.actor
                    FROM repositories r JOIN repository_installations i USING(repo_id)
                    WHERE i.status = 'disabled'
                    ORDER BY i.disabled_at DESC, lower(r.display_name)
                    """
                )
            )

    def attach_resource(
        self,
        repo_id: str,
        resource: ExactResourceRef,
        *,
        actor: str,
        reason: str,
    ) -> AttachResult:
        with self.store.immediate_transaction() as connection:
            installation = _installation_row(connection, repo_id)
            if installation["status"] != "installed" or installation["startup_fenced"]:
                raise ActionFencedError("repository is not installed and startable")
            current = self._standalone_snapshot(connection, resource)
            if current.resource != resource:
                raise PlanDriftError("standalone resource changed before attachment")
            if current.attached_repo_id not in {None, repo_id}:
                raise OwnershipError("standalone resource belongs to another repository")
            if current.retirement_status is not None:
                raise ActionFencedError("retired resource requires an explicit restore")
            if current.authority_state != "authoritative":
                raise OwnershipError("standalone controller is not authoritative")
            timestamp = utc_timestamp()
            membership_id = deterministic_id(
                "membership", repo_id, resource.kind.value, resource.resource_id
            )
            connection.execute(
                """
                INSERT INTO repository_memberships(
                    membership_id, repo_id, resource_kind, host_resource_id,
                    immutable_fingerprint, control_binding_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(resource_kind, host_resource_id) DO UPDATE SET
                    repo_id = excluded.repo_id,
                    immutable_fingerprint = excluded.immutable_fingerprint,
                    control_binding_id = excluded.control_binding_id
                """,
                (
                    membership_id,
                    repo_id,
                    resource.kind.value,
                    resource.resource_id,
                    resource.immutable_fingerprint,
                    resource.control_binding_id,
                    timestamp,
                ),
            )
            connection.execute(
                """
                UPDATE control_bindings SET repo_id = ?, generation = generation + 1,
                    provenance = 'operator_attach', updated_at = ?
                WHERE binding_id = ? AND authority_state = 'authoritative'
                """,
                (repo_id, timestamp, resource.control_binding_id),
            )
            connection.execute(
                """
                UPDATE startup_policies SET repo_id = ?, generation = generation + 1,
                    updated_at = ?
                WHERE resource_kind = ? AND resource_id = ? AND repo_id IS NULL
                """,
                (repo_id, timestamp, resource.kind.value, resource.resource_id),
            )
            changed = connection.execute(
                """
                UPDATE unassigned_resources SET status = 'attached', updated_at = ?
                WHERE resource_kind = ? AND resource_id = ? AND status = 'active'
                """,
                (timestamp, resource.kind.value, resource.resource_id),
            ).rowcount
            if changed < 1:
                raise PlanDriftError("resource is no longer an active unassigned resource")
            connection.execute(
                "UPDATE repositories SET generation = generation + 1, updated_at = ? WHERE repo_id = ?",
                (timestamp, repo_id),
            )
            connection.execute(
                """
                INSERT INTO events(event_id, repo_id, event_kind, code, message,
                                   diagnostic_json, occurred_at)
                VALUES (?, ?, 'resource.attached', 'explicit_operator_attachment', ?, ?, ?)
                """,
                (
                    deterministic_id("event", membership_id, timestamp),
                    repo_id,
                    "Exact host resource attached to repository",
                    canonical_json(
                        {
                            "resource_kind": resource.kind.value,
                            "resource_id": resource.resource_id,
                            "reason": reason,
                            "actor": actor,
                        }
                    ),
                    timestamp,
                ),
            )
        return AttachResult(repo_id, resource.resource_id, resource.kind, True, False)

    def reserve_repository_action(
        self,
        repo_id: str,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        with self.store.immediate_transaction() as connection:
            installation = _installation_row(connection, repo_id)
            if installation["status"] != "installed" or installation["startup_fenced"]:
                raise ActionFencedError("repository start fence is active")
            pending_restore = connection.execute(
                """
                SELECT policy_id FROM startup_policy_restore_states
                WHERE repo_id = ? AND restore_required = 1 AND status = 'captured'
                LIMIT 1
                """,
                (repo_id,),
            ).fetchone()
            if pending_restore is not None and action is not RepositoryAction.START:
                raise ActionFencedError(
                    "repository startup policies require a guarded explicit start first"
                )
            existing = connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?",
                (request_id,),
            ).fetchone()
            request_fingerprint = _sha(
                {
                    "repo_id": repo_id,
                    "action": action.value,
                    "generation": int(installation["generation"]),
                }
            )
            if existing is not None:
                if (
                    existing["repo_id"] == repo_id
                    and existing["kind"] == f"guard:{action.value}"
                    and existing["status"] == "running"
                    and existing["request_fingerprint"] == request_fingerprint
                ):
                    return ActionPermit(
                        request_id,
                        repo_id,
                        None,
                        action,
                        int(installation["generation"]),
                    )
                raise ConcurrentLifecycleError("action request id is already in use")
            conflict = connection.execute(
                """
                SELECT operation_id FROM operations
                WHERE repo_id = ? AND status IN ('running','needs_attention','partial')
                LIMIT 1
                """,
                (repo_id,),
            ).fetchone()
            if conflict is not None:
                raise ConcurrentLifecycleError(
                    f"repository operation {conflict['operation_id']} is already active"
                )
            timestamp = utc_timestamp()
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, repo_id, kind, status, phase, generation,
                    request_fingerprint, owner_uid, actor, created_at, updated_at
                ) VALUES (?, ?, ?, 'running', 'guarded', 0, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    repo_id,
                    f"guard:{action.value}",
                    request_fingerprint,
                    os.geteuid(),
                    actor,
                    timestamp,
                    timestamp,
                ),
            )
            return ActionPermit(
                request_id,
                repo_id,
                None,
                action,
                int(installation["generation"]),
            )

    def reserve_resource_action(
        self,
        resource: ExactResourceRef,
        action: RepositoryAction,
        *,
        request_id: str,
        actor: str,
    ) -> ActionPermit:
        with self.store.immediate_transaction() as connection:
            retirement = connection.execute(
                """
                SELECT status FROM resource_retirements
                WHERE host_resource_id = ? AND resource_kind = ?
                """,
                (resource.resource_id, resource.kind.value),
            ).fetchone()
            if retirement is not None and retirement["status"] in {"disabling", "retired"}:
                raise ActionFencedError("resource retirement fence is active")
            current = self._standalone_snapshot(connection, resource)
            if current.authority_state != "authoritative":
                raise OwnershipError("resource controller is not authoritative")
            conflict = connection.execute(
                """
                SELECT o.operation_id FROM operations o
                JOIN operation_targets t USING(operation_id)
                WHERE o.status IN ('running','needs_attention','partial')
                  AND t.target_kind = ? AND t.target_id = ? LIMIT 1
                """,
                (resource.kind.value, resource.resource_id),
            ).fetchone()
            if conflict is not None:
                raise ConcurrentLifecycleError(
                    f"resource operation {conflict['operation_id']} is already active"
                )
            request_fingerprint = _sha(
                {
                    "resource_kind": resource.kind.value,
                    "resource_id": resource.resource_id,
                    "immutable_fingerprint": resource.immutable_fingerprint,
                    "action": action.value,
                }
            )
            timestamp = utc_timestamp()
            connection.execute(
                """
                INSERT INTO operations(
                    operation_id, kind, status, phase, generation,
                    request_fingerprint, owner_uid, actor, created_at, updated_at
                ) VALUES (?, ?, 'running', 'guarded', 0, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    f"guard:{action.value}",
                    request_fingerprint,
                    os.geteuid(),
                    actor,
                    timestamp,
                    timestamp,
                ),
            )
            self._insert_resource_target(connection, request_id, 0, resource, action=action.value)
            return ActionPermit(request_id, None, resource.resource_id, action, 0)

    def release_action_permit(self, permit: ActionPermit, *, outcome: str) -> None:
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, permit.permit_id)
            if operation["status"] != "running":
                return
            status = "succeeded" if outcome == "succeeded" else "failed"
            result = _json_mapping(operation["result_json"])
            result["outcome"] = outcome
            connection.execute(
                """
                UPDATE operations SET status = ?, phase = 'released', result_json = ?,
                    updated_at = ? WHERE operation_id = ? AND status = 'running'
                """,
                (
                    status,
                    canonical_json(result),
                    utc_timestamp(),
                    permit.permit_id,
                ),
            )
            connection.execute(
                """
                UPDATE operation_targets SET status = ?, phase = 'released',
                    finished_at = ? WHERE operation_id = ?
                """,
                (status, utc_timestamp(), permit.permit_id),
            )

    def startup_policy_restoration_plan(
        self, permit: ActionPermit
    ) -> Sequence[tuple[ExactResourceRef, StartupPolicyRef, CapturedStartupPolicyState]]:
        if permit.repo_id is None or permit.action is not RepositoryAction.START:
            raise LifecycleError("startup restoration requires a repository start permit")
        with self.store.read_transaction() as connection:
            operation = _operation_row(connection, permit.permit_id)
            installation = _installation_row(connection, permit.repo_id)
            if (
                operation["status"] != "running"
                or operation["kind"] != "guard:start"
                or operation["repo_id"] != permit.repo_id
                or installation["status"] != "installed"
                or bool(installation["startup_fenced"])
                or int(installation["generation"]) != permit.generation
            ):
                raise ConcurrentLifecycleError("repository start permit is no longer active")
            snapshot = self._repository_snapshot(connection, permit.repo_id)
            target_by_policy: dict[str, tuple[ExactResourceRef, StartupPolicyRef]] = {}
            for target in snapshot.targets:
                for policy in target.policies:
                    target_by_policy[policy.policy_id] = (target, policy)
            policy_rows = list(
                connection.execute(
                    "SELECT * FROM startup_policies WHERE repo_id = ? ORDER BY policy_id",
                    (permit.repo_id,),
                )
            )
            work: list[
                tuple[ExactResourceRef, StartupPolicyRef, CapturedStartupPolicyState]
            ] = []
            for row in policy_rows:
                pair = target_by_policy.get(str(row["policy_id"]))
                if pair is None:
                    raise OwnershipError(
                        f"startup policy {row['policy_id']} has no exact repository target"
                    )
                target, policy = pair
                capture_row = connection.execute(
                    "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
                    (policy.policy_id,),
                ).fetchone()
                if capture_row is None:
                    if (
                        installation["reinstalled_at"] is not None
                        and str(row["current_value"])
                        == str(row["desired_disabled_value"])
                    ):
                        raise LifecycleError(
                            f"startup policy {policy.policy_id} has no captured pre-disable state"
                        )
                    continue
                captured = _captured_policy_state(capture_row)
                _verify_capture_identity(
                    captured,
                    permit.repo_id,
                    target,
                    policy,
                    _sha(dict(target.native_identity)),
                )
                if (
                    captured.status == "restored"
                    and capture_row["last_restore_permit_id"] != permit.permit_id
                ):
                    # A completed prior explicit start consumed this capture.
                    # A later owner-approved policy change must not be reset to
                    # historical state by every subsequent start.
                    continue
                if captured.status == "restored":
                    if str(row["current_value"]) != captured.captured_value:
                        raise PlanDriftError(
                            f"restored policy {policy.policy_id} normalized value drifted"
                        )
                elif str(row["current_value"]) != str(row["desired_disabled_value"]):
                    raise PlanDriftError(
                        f"pending policy {policy.policy_id} is not durably disabled"
                    )
                work.append((target, policy, captured))
            return tuple(work)

    def mark_startup_policy_restored(
        self,
        permit: ActionPermit,
        target: ExactResourceRef,
        policy: StartupPolicyRef,
        captured: CapturedStartupPolicyState,
        evidence: Mapping[str, Any],
    ) -> None:
        if permit.repo_id is None or permit.action is not RepositoryAction.START:
            raise LifecycleError("startup restoration requires a repository start permit")
        with self.store.immediate_transaction() as connection:
            operation = _operation_row(connection, permit.permit_id)
            installation = _installation_row(connection, permit.repo_id)
            if (
                operation["status"] != "running"
                or operation["kind"] != "guard:start"
                or operation["repo_id"] != permit.repo_id
                or installation["status"] != "installed"
                or bool(installation["startup_fenced"])
                or int(installation["generation"]) != permit.generation
            ):
                raise ConcurrentLifecycleError("repository start permit is no longer active")
            row = connection.execute(
                "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
                (policy.policy_id,),
            ).fetchone()
            if row is None:
                raise LifecycleError("startup policy capture disappeared")
            current = _captured_policy_state(row)
            if current != captured:
                raise PlanDriftError("startup policy capture changed during restore")
            _verify_capture_identity(
                current,
                permit.repo_id,
                target,
                policy,
                _sha(dict(target.native_identity)),
            )
            if current.status == "restored":
                return
            if not current.restore_required:
                raise LifecycleError("not-required policy cannot be marked restored")
            timestamp = utc_timestamp()
            changed = connection.execute(
                """
                UPDATE startup_policies
                SET current_value = ?, generation = generation + 1, updated_at = ?
                WHERE policy_id = ? AND repo_id = ? AND resource_kind = ?
                  AND resource_id = ? AND policy_kind = ?
                  AND immutable_fingerprint = ?
                  AND current_value = desired_disabled_value
                """,
                (
                    current.captured_value,
                    timestamp,
                    policy.policy_id,
                    permit.repo_id,
                    target.kind.value,
                    target.resource_id,
                    policy.kind.value,
                    policy.immutable_fingerprint,
                ),
            ).rowcount
            if changed != 1:
                raise PlanDriftError("startup policy normalized value changed during restore")
            connection.execute(
                """
                UPDATE startup_policy_restore_states
                SET status = 'restored', last_restore_permit_id = ?,
                    restored_at = ?, updated_at = ?
                WHERE policy_id = ? AND status = 'captured'
                """,
                (permit.permit_id, timestamp, timestamp, policy.policy_id),
            )
            previous_result = _json_mapping(operation["result_json"])
            restorations = list(previous_result.get("startup_policy_restorations", []))
            restorations.append(
                {
                    "policy_id": policy.policy_id,
                    "resource_kind": target.kind.value,
                    "resource_id": target.resource_id,
                    "evidence": dict(evidence),
                }
            )
            previous_result["startup_policy_restorations"] = restorations
            connection.execute(
                "UPDATE operations SET result_json = ?, updated_at = ? WHERE operation_id = ?",
                (canonical_json(previous_result), timestamp, permit.permit_id),
            )

    def _repository_snapshot(
        self, connection: sqlite3.Connection, repo_id: str
    ) -> RepositorySnapshot:
        repository = _repository_row(connection, repo_id)
        installation = _installation_row(connection, repo_id)
        membership_rows = list(
            connection.execute(
                """
                SELECT m.*, b.authority_state, b.resource_kind AS binding_kind,
                       b.resource_id AS binding_resource_id, b.source_id,
                       b.source_resource_id AS binding_source_resource_id,
                       b.capability, b.provenance, b.priority AS binding_priority,
                       b.generation AS binding_generation,
                       b.repo_id AS binding_repo_id
                FROM repository_memberships m
                LEFT JOIN control_bindings b ON b.binding_id = m.control_binding_id
                WHERE m.repo_id = ? ORDER BY m.resource_kind, m.host_resource_id
                """,
                (repo_id,),
            )
        )
        policies = self._policies_by_resource(connection, repo_id=repo_id)
        allocations_by_target, repository_allocations, allocation_rows = (
            self._repository_allocations(connection, repo_id)
        )
        targets: list[ExactResourceRef] = []
        conflicts: list[str] = []
        binding_rows: list[Mapping[str, Any]] = []
        policy_rows: list[Mapping[str, Any]] = []
        for row in membership_rows:
            key = (str(row["resource_kind"]), str(row["host_resource_id"]))
            if row["control_binding_id"] is None or row["authority_state"] != "authoritative":
                conflicts.append(f"{key[0]}:{key[1]} has no authoritative binding")
            elif (
                row["binding_kind"] != row["resource_kind"]
                or row["binding_resource_id"] != row["host_resource_id"]
                or row["binding_repo_id"] not in {None, repo_id}
            ):
                conflicts.append(f"{key[0]}:{key[1]} binding conflicts with membership")
            binding = dict(row)
            binding_rows.append(binding)
            target_policies = tuple(policies.get(key, ()))
            policy_rows.extend(item.to_dict() for item in target_policies)
            native_identity, native_conflict = self._native_identity(
                connection, ResourceKind(key[0]), key[1]
            )
            if ResourceKind(key[0]) is ResourceKind.CONTAINER:
                docker_boundary = connection.execute(
                    """
                    SELECT e.capability_state, o.restart_policy,
                           o.observation_fingerprint, o.sampled_at
                    FROM docker_resources d
                    JOIN docker_engines e USING(engine_id)
                    LEFT JOIN docker_observations o USING(docker_resource_id)
                    WHERE d.docker_resource_id = ?
                    """,
                    (key[1],),
                ).fetchone()
                docker_policies = tuple(
                    policy
                    for policy in target_policies
                    if policy.kind is PolicyKind.DOCKER_RESTART
                )
                if docker_boundary is None or docker_boundary["capability_state"] != "available":
                    conflicts.append(
                        f"container:{key[1]} has no current available Docker observation"
                    )
                elif docker_boundary["restart_policy"] is None:
                    conflicts.append(
                        f"container:{key[1]} restart policy is unobservable"
                    )
                if len(docker_policies) != 1:
                    conflicts.append(
                        f"container:{key[1]} requires exactly one Docker restart policy"
                    )
                policy_rows.append(
                    {
                        "container_observation": key[1],
                        "capability_state": (
                            str(docker_boundary["capability_state"])
                            if docker_boundary is not None
                            else None
                        ),
                        "restart_policy": (
                            str(docker_boundary["restart_policy"])
                            if docker_boundary is not None
                            and docker_boundary["restart_policy"] is not None
                            else None
                        ),
                        "observation_fingerprint": (
                            str(docker_boundary["observation_fingerprint"])
                            if docker_boundary is not None
                            and docker_boundary["observation_fingerprint"] is not None
                            else None
                        ),
                        "sampled_at": (
                            str(docker_boundary["sampled_at"])
                            if docker_boundary is not None
                            and docker_boundary["sampled_at"] is not None
                            else None
                        ),
                    }
                )
            if ResourceKind(key[0]) is ResourceKind.SUPERVISOR:
                native_identity = _supervisor_native_identity(
                    native_identity,
                    str(row["capability"] or ""),
                    str(row["provenance"] or ""),
                )
            if native_conflict:
                conflicts.append(native_conflict)
            ownership_fingerprint = _binding_fingerprint(row)
            targets.append(
                ExactResourceRef(
                    resource_id=key[1],
                    kind=ResourceKind(key[0]),
                    immutable_fingerprint=str(row["immutable_fingerprint"]),
                    control_binding_id=str(row["control_binding_id"] or ""),
                    ownership_fingerprint=ownership_fingerprint,
                    policies=target_policies,
                    allocations=tuple(allocations_by_target.get(key, ())),
                    native_identity=native_identity,
                    control_contract_fingerprint=_binding_control_contract(row),
                )
            )
        repository_fingerprint = _sha(
            {
                "repository": dict(repository),
                "installation": dict(installation),
                "memberships": [dict(row) for row in membership_rows],
                "bindings": binding_rows,
                "policies": policy_rows,
                "allocations": allocation_rows,
            }
        )
        return RepositorySnapshot(
            repo_id=repo_id,
            repository_fingerprint=repository_fingerprint,
            installation_generation=int(installation["generation"]),
            installation_status=str(installation["status"]),
            startup_fenced=bool(installation["startup_fenced"]),
            hidden=str(installation["status"]) == "disabled",
            targets=tuple(targets),
            repository_allocations=tuple(repository_allocations),
            unresolved_conflicts=tuple(conflicts),
        )

    def _standalone_snapshot(
        self, connection: sqlite3.Connection, resource: ExactResourceRef
    ) -> StandaloneSnapshot:
        binding = connection.execute(
            """
            SELECT * FROM control_bindings
            WHERE binding_id = ? AND resource_kind = ? AND resource_id = ?
            """,
            (resource.control_binding_id, resource.kind.value, resource.resource_id),
        ).fetchone()
        if binding is None:
            raise OwnershipError("exact standalone control binding does not exist")
        ownership_fingerprint = _binding_fingerprint(binding)
        native_identity, native_conflict = self._native_identity(
            connection, resource.kind, resource.resource_id
        )
        if resource.kind is ResourceKind.SUPERVISOR:
            native_identity = _supervisor_native_identity(
                native_identity,
                str(binding["capability"] or ""),
                str(binding["provenance"] or ""),
            )
        if native_conflict:
            raise PlanDriftError(native_conflict)
        policies = tuple(
            self._policies_by_resource(
                connection,
                resource_kind=resource.kind.value,
                resource_id=resource.resource_id,
            ).get((resource.kind.value, resource.resource_id), ())
        )
        if resource.kind is ResourceKind.CONTAINER:
            docker_boundary = connection.execute(
                """
                SELECT e.capability_state, o.restart_policy
                FROM docker_resources d
                JOIN docker_engines e USING(engine_id)
                LEFT JOIN docker_observations o USING(docker_resource_id)
                WHERE d.docker_resource_id = ?
                """,
                (resource.resource_id,),
            ).fetchone()
            docker_policies = tuple(
                policy for policy in policies if policy.kind is PolicyKind.DOCKER_RESTART
            )
            if docker_boundary is None or docker_boundary["capability_state"] != "available":
                raise OwnershipError(
                    "standalone container has no current available Docker observation"
                )
            if docker_boundary["restart_policy"] is None:
                raise OwnershipError("standalone container restart policy is unobservable")
            if len(docker_policies) != 1:
                raise OwnershipError(
                    "standalone container requires exactly one Docker restart policy"
                )
        rebuilt = replace(
            resource,
            ownership_fingerprint=ownership_fingerprint,
            policies=policies,
            native_identity=native_identity,
            control_contract_fingerprint=_binding_control_contract(binding),
        )
        expected_immutable = _standalone_immutable_fingerprint(
            resource.kind, resource.resource_id, native_identity
        )
        if resource.immutable_fingerprint != expected_immutable:
            raise PlanDriftError("standalone immutable host identity changed")
        if rebuilt != resource:
            raise PlanDriftError("exact standalone resource fingerprint or policy set changed")
        membership = connection.execute(
            """
            SELECT repo_id FROM repository_memberships
            WHERE resource_kind = ? AND host_resource_id = ?
            """,
            (resource.kind.value, resource.resource_id),
        ).fetchone()
        retirement = connection.execute(
            """
            SELECT status FROM resource_retirements
            WHERE host_resource_id = ? AND resource_kind = ?
            """,
            (resource.resource_id, resource.kind.value),
        ).fetchone()
        return StandaloneSnapshot(
            resource=resource,
            retirement_status=str(retirement["status"]) if retirement else None,
            attached_repo_id=str(membership["repo_id"]) if membership else None,
            authority_state=str(binding["authority_state"]),
        )

    def _load_plan(self, connection: sqlite3.Connection, plan_id: str) -> LifecyclePlan:
        operation = _operation_row(connection, plan_id)
        target_rows = list(
            connection.execute(
                "SELECT * FROM operation_targets WHERE operation_id = ? ORDER BY ordinal",
                (plan_id,),
            )
        )
        params = _parameters_by_ordinal(connection, plan_id)
        if operation["kind"] == "repository_decommission":
            synthetic = next(
                (row for row in target_rows if row["target_kind"] == REPOSITORY_TARGET_KIND),
                None,
            )
            if synthetic is None:
                raise LifecycleError("repository plan has no repository target")
            repository_params = params[int(synthetic["ordinal"])]
            targets = tuple(
                self._decode_target(row, params[int(row["ordinal"])])
                for row in target_rows
                if row["target_kind"] != REPOSITORY_TARGET_KIND
            )
            return RepositoryDecommissionPlan(
                plan_id=plan_id,
                repo_id=str(operation["repo_id"]),
                repository_fingerprint=str(
                    repository_params["repository_fingerprint"]
                ),
                installation_generation=int(
                    repository_params["installation_generation"]
                ),
                fingerprint=str(operation["request_fingerprint"]),
                created_at=str(repository_params["created_at"]),
                actor=str(operation["actor"]),
                reason=str(repository_params["reason"]),
                targets=targets,
                repository_allocations=_decode_allocations(
                    repository_params, "allocation"
                ),
            )
        if operation["kind"] == "standalone_resource_retirement":
            if len(target_rows) != 1:
                raise LifecycleError("standalone retirement must contain one exact target")
            row = target_rows[0]
            target_params = params[int(row["ordinal"])]
            return StandaloneRetirementPlan(
                plan_id=plan_id,
                fingerprint=str(operation["request_fingerprint"]),
                created_at=str(target_params["created_at"]),
                actor=str(operation["actor"]),
                reason=str(target_params["reason"]),
                target=self._decode_target(row, target_params),
            )
        raise LifecycleError(f"operation {plan_id} is not a lifecycle plan")

    def _operation_progress(
        self, connection: sqlite3.Connection, operation_id: str
    ) -> OperationProgress:
        operation = _operation_row(connection, operation_id)
        status = _operation_status(str(operation["status"]))
        targets: dict[tuple[str, str], TargetProgress] = {}
        errors: list[Mapping[str, Any]] = []
        synthetic_errors = connection.execute(
            """
            SELECT error_json FROM operation_targets
            WHERE operation_id = ? AND target_kind = ? AND error_json IS NOT NULL
            """,
            (operation_id, REPOSITORY_TARGET_KIND),
        )
        errors.extend(_json_mapping(row["error_json"]) for row in synthetic_errors)
        for row in connection.execute(
            """
            SELECT * FROM operation_targets WHERE operation_id = ?
              AND target_kind != ? ORDER BY ordinal
            """,
            (operation_id, REPOSITORY_TARGET_KIND),
        ):
            try:
                kind = ResourceKind(str(row["target_kind"]))
            except ValueError:
                continue
            error = _json_mapping(row["error_json"]) if row["error_json"] else None
            if error:
                errors.append(error)
            evidence = _json_mapping(row["result_json"]) if row["result_json"] else {}
            target = TargetProgress(
                kind,
                str(row["target_id"]),
                _phase_from_text(str(row["phase"])),
                str(row["status"]),
                evidence,
                error,
            )
            targets[(kind.value, target.target_id)] = target
        hidden = False
        fence = status is not OperationStatus.PLANNED
        if operation["repo_id"] is not None:
            installation = connection.execute(
                "SELECT status, startup_fenced FROM repository_installations WHERE repo_id = ?",
                (operation["repo_id"],),
            ).fetchone()
            if installation is not None:
                fence = bool(installation["startup_fenced"])
                hidden = installation["status"] == "disabled"
        elif operation["kind"] == "standalone_resource_retirement":
            target_row = connection.execute(
                "SELECT target_id FROM operation_targets WHERE operation_id = ? LIMIT 1",
                (operation_id,),
            ).fetchone()
            retirement = connection.execute(
                "SELECT status FROM resource_retirements WHERE host_resource_id = ?",
                (target_row["target_id"],),
            ).fetchone() if target_row else None
            fence = retirement is not None
            hidden = retirement is not None and retirement["status"] == "retired"
        return OperationProgress(
            operation_id,
            status,
            fence,
            hidden,
            targets,
            tuple(errors),
        )

    def _insert_resource_target(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        ordinal: int,
        target: ExactResourceRef,
        *,
        action: str = "disable_stop_verify",
    ) -> None:
        connection.execute(
            """
            INSERT INTO operation_targets(
                operation_id, ordinal, target_kind, target_id, action,
                immutable_fingerprint, phase, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 'pending')
            """,
            (
                operation_id,
                ordinal,
                target.kind.value,
                target.resource_id,
                action,
                target.immutable_fingerprint,
            ),
        )
        parameters: dict[str, Any] = {
            "control_binding_id": target.control_binding_id,
            "ownership_fingerprint": target.ownership_fingerprint,
            "control_contract_fingerprint": target.control_contract_fingerprint,
        }
        for key, value in target.native_identity:
            parameters[f"native.{key}"] = value
        _encode_policies(parameters, target.policies)
        _encode_allocations(parameters, "allocation", target.allocations)
        _insert_parameters(connection, operation_id, ordinal, parameters)

    @staticmethod
    def _decode_target(
        row: sqlite3.Row, parameters: Mapping[str, Any]
    ) -> ExactResourceRef:
        native_identity = tuple(
            sorted(
                (key[7:], str(value))
                for key, value in parameters.items()
                if key.startswith("native.")
            )
        )
        return ExactResourceRef(
            resource_id=str(row["target_id"]),
            kind=ResourceKind(str(row["target_kind"])),
            immutable_fingerprint=str(row["immutable_fingerprint"]),
            control_binding_id=str(parameters["control_binding_id"]),
            ownership_fingerprint=str(parameters["ownership_fingerprint"]),
            policies=_decode_policies(parameters),
            allocations=_decode_allocations(parameters, "allocation"),
            native_identity=native_identity,
            control_contract_fingerprint=str(
                parameters.get("control_contract_fingerprint") or ""
            ),
        )

    def _policies_by_resource(
        self,
        connection: sqlite3.Connection,
        *,
        repo_id: str | None = None,
        resource_kind: str | None = None,
        resource_id: str | None = None,
    ) -> dict[tuple[str, str], list[StartupPolicyRef]]:
        clauses: list[str] = []
        values: list[Any] = []
        if repo_id is not None:
            clauses.append("repo_id = ?")
            values.append(repo_id)
        if resource_kind is not None:
            clauses.append("resource_kind = ?")
            values.append(resource_kind)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            values.append(resource_id)
        sql = "SELECT * FROM startup_policies"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY resource_kind, resource_id, policy_kind"
        result: dict[tuple[str, str], list[StartupPolicyRef]] = {}
        for row in connection.execute(sql, tuple(values)):
            key = (str(row["resource_kind"]), str(row["resource_id"]))
            result.setdefault(key, []).append(
                StartupPolicyRef(
                    str(row["policy_id"]),
                    PolicyKind(str(row["policy_kind"])),
                    str(row["immutable_fingerprint"]),
                    str(row["desired_disabled_value"]),
                )
            )
        return result

    def _repository_allocations(
        self, connection: sqlite3.Connection, repo_id: str
    ) -> tuple[
        dict[tuple[str, str], list[AllocationRef]],
        list[AllocationRef],
        list[Mapping[str, Any]],
    ]:
        target_map: dict[tuple[str, str], list[AllocationRef]] = {}
        repository: list[AllocationRef] = []
        raw_rows: list[Mapping[str, Any]] = []
        servers = {
            str(row["server_definition_id"]): str(row["name"])
            for row in connection.execute(
                "SELECT server_definition_id, name FROM server_definitions WHERE repo_id = ?",
                (repo_id,),
            )
        }
        server_by_name = {name: server_id for server_id, name in servers.items()}
        for row in connection.execute(
            "SELECT * FROM leases WHERE repo_id = ? AND status = 'active' ORDER BY lease_id",
            (repo_id,),
        ):
            raw_rows.append(dict(row))
            item = AllocationRef(
                str(row["lease_id"]), AllocationKind.LEASE, _allocation_fingerprint(row)
            )
            server_id = row["server_definition_id"]
            if server_id is not None and str(server_id) in servers:
                target_map.setdefault((ResourceKind.SERVER.value, str(server_id)), []).append(item)
            else:
                repository.append(item)
        for row in connection.execute(
            """
            SELECT * FROM port_assignments
            WHERE repo_id = ? AND status = 'active' ORDER BY assignment_id
            """,
            (repo_id,),
        ):
            raw_rows.append(dict(row))
            item = AllocationRef(
                str(row["assignment_id"]),
                AllocationKind.PORT_ASSIGNMENT,
                _allocation_fingerprint(row),
            )
            server_id = server_by_name.get(str(row["server_name"]))
            if server_id is not None:
                target_map.setdefault((ResourceKind.SERVER.value, server_id), []).append(item)
            else:
                repository.append(item)
        return target_map, repository, raw_rows

    def _native_identity(
        self,
        connection: sqlite3.Connection,
        kind: ResourceKind,
        resource_id: str,
    ) -> tuple[tuple[tuple[str, str], ...], str | None]:
        if kind is ResourceKind.CONTAINER:
            row = connection.execute(
                """
                SELECT docker_resource_id, engine_id, full_container_id
                FROM docker_resources WHERE docker_resource_id = ?
                """,
                (resource_id,),
            ).fetchone()
            if row is None:
                return (), f"container:{resource_id} has no immutable Docker resource"
            return (
                ("docker_resource_id", str(row["docker_resource_id"])),
                ("engine_id", str(row["engine_id"])),
                ("full_container_id", str(row["full_container_id"])),
            ), None
        if kind is ResourceKind.SERVER:
            definition = connection.execute(
                "SELECT server_definition_id FROM server_definitions WHERE server_definition_id = ?",
                (resource_id,),
            ).fetchone()
            if definition is None:
                return (), f"server:{resource_id} has no exact definition"
            observation = connection.execute(
                "SELECT * FROM server_observations WHERE server_definition_id = ?",
                (resource_id,),
            ).fetchone()
            values: list[tuple[str, str]] = [("server_definition_id", resource_id)]
            if observation is not None:
                for source, destination in (
                    ("pid", "pid"),
                    ("process_start_time", "process_start_time"),
                    ("process_fingerprint", "process_fingerprint"),
                    ("listener_host", "listener_host"),
                    ("listener_port", "listener_port"),
                ):
                    if observation[source] is not None:
                        values.append((destination, str(observation[source])))
            return tuple(values), None
        # A supervisor's resource_id is its exact unit identity.  The control
        # capability determines which manager may act; missing manager evidence
        # remains observable but the host adapter will fail closed.
        return (("unit", resource_id),), None

    def _deactivate_allocations(
        self,
        connection: sqlite3.Connection,
        allocations: Sequence[AllocationRef],
    ) -> Mapping[str, Any]:
        results: list[Mapping[str, Any]] = []
        timestamp = utc_timestamp()
        for allocation in allocations:
            table, id_column = (
                ("leases", "lease_id")
                if allocation.kind is AllocationKind.LEASE
                else ("port_assignments", "assignment_id")
            )
            row = connection.execute(
                f"SELECT * FROM {table} WHERE {id_column} = ?",
                (allocation.allocation_id,),
            ).fetchone()
            if row is None or _allocation_fingerprint(row) != allocation.immutable_fingerprint:
                raise PlanDriftError(
                    f"{allocation.kind.value} {allocation.allocation_id} identity changed"
                )
            active = row["status"] == "active"
            if active:
                status = "released" if allocation.kind is AllocationKind.LEASE else "inactive"
                connection.execute(
                    f"""
                    UPDATE {table} SET status = ?, generation = generation + 1,
                        deactivated_at = ?, updated_at = ? WHERE {id_column} = ?
                    """,
                    (status, timestamp, timestamp, allocation.allocation_id),
                )
            results.append(
                {
                    "allocation_id": allocation.allocation_id,
                    "kind": allocation.kind.value,
                    "status": "deactivated" if active else "already_inactive",
                }
            )
        return {"allocations": results}

    @staticmethod
    def _verify_no_active_allocations(
        connection: sqlite3.Connection, repo_id: str
    ) -> None:
        lease = connection.execute(
            "SELECT lease_id FROM leases WHERE repo_id = ? AND status = 'active' LIMIT 1",
            (repo_id,),
        ).fetchone()
        assignment = connection.execute(
            """
            SELECT assignment_id FROM port_assignments
            WHERE repo_id = ? AND status = 'active' LIMIT 1
            """,
            (repo_id,),
        ).fetchone()
        if lease is not None or assignment is not None:
            raise LifecycleError("repository retains an active lease or port assignment")

    @staticmethod
    def _verify_policies_disabled(
        connection: sqlite3.Connection,
        *,
        repo_id: str | None = None,
        resource_kind: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        clauses = ["current_value != desired_disabled_value"]
        values: list[Any] = []
        if repo_id is not None:
            clauses.append("repo_id = ?")
            values.append(repo_id)
        if resource_kind is not None:
            clauses.append("resource_kind = ?")
            values.append(resource_kind)
        if resource_id is not None:
            clauses.append("resource_id = ?")
            values.append(resource_id)
        row = connection.execute(
            "SELECT policy_id FROM startup_policies WHERE " + " AND ".join(clauses) + " LIMIT 1",
            tuple(values),
        ).fetchone()
        if row is not None:
            raise LifecycleError(f"startup policy {row['policy_id']} remains enabled")

    @staticmethod
    def _verify_policy_captures(
        connection: sqlite3.Connection,
        *,
        repo_id: str | None = None,
        resource_kind: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        clauses: list[str] = []
        values: list[Any] = []
        if repo_id is not None:
            clauses.append("p.repo_id = ?")
            values.append(repo_id)
        if resource_kind is not None:
            clauses.append("p.resource_kind = ?")
            values.append(resource_kind)
        if resource_id is not None:
            clauses.append("p.resource_id = ?")
            values.append(resource_id)
        where = " AND ".join(clauses) or "1 = 1"
        row = connection.execute(
            f"""
            SELECT p.policy_id FROM startup_policies p
            LEFT JOIN startup_policy_restore_states r USING(policy_id)
            WHERE {where} AND r.policy_id IS NULL LIMIT 1
            """,
            tuple(values),
        ).fetchone()
        if row is not None:
            raise LifecycleError(
                f"startup policy {row['policy_id']} has no durable pre-disable capture"
            )


def _captured_policy_state(row: Mapping[str, Any]) -> CapturedStartupPolicyState:
    return CapturedStartupPolicyState(
        policy_id=str(row["policy_id"]),
        repo_id=str(row["repo_id"]) if row["repo_id"] is not None else None,
        resource_kind=ResourceKind(str(row["resource_kind"])),
        resource_id=str(row["resource_id"]),
        policy_kind=PolicyKind(str(row["policy_kind"])),
        policy_immutable_fingerprint=str(row["policy_immutable_fingerprint"]),
        target_immutable_fingerprint=str(row["target_immutable_fingerprint"]),
        control_binding_id=str(row["control_binding_id"]),
        ownership_fingerprint=str(row["ownership_fingerprint"]),
        native_identity_fingerprint=str(row["native_identity_fingerprint"]),
        captured_value=str(row["captured_value"]),
        restore_required=bool(row["restore_required"]),
        status=str(row["status"]),
        docker_restart_policy=(
            str(row["docker_restart_policy"])
            if row["docker_restart_policy"] is not None
            else None
        ),
        supervisor_manager=(
            str(row["supervisor_manager"])
            if row["supervisor_manager"] is not None
            else None
        ),
        supervisor_unit_file_state=(
            str(row["supervisor_unit_file_state"])
            if row["supervisor_unit_file_state"] is not None
            else None
        ),
        supervisor_loaded=(
            bool(row["supervisor_loaded"])
            if row["supervisor_loaded"] is not None
            else None
        ),
        supervisor_enabled=(
            bool(row["supervisor_enabled"])
            if row["supervisor_enabled"] is not None
            else None
        ),
    )


def _verify_capture_identity(
    captured: CapturedStartupPolicyState,
    repo_id: object,
    target: ExactResourceRef,
    policy: StartupPolicyRef,
    native_identity_fingerprint: str,
) -> None:
    expected_repo = str(repo_id) if repo_id is not None else None
    if (
        captured.repo_id != expected_repo
        or captured.resource_kind is not target.kind
        or captured.resource_id != target.resource_id
        or captured.policy_kind is not policy.kind
        or captured.policy_immutable_fingerprint != policy.immutable_fingerprint
        or captured.target_immutable_fingerprint != target.immutable_fingerprint
        or captured.control_binding_id != target.control_binding_id
        or captured.ownership_fingerprint != target.ownership_fingerprint
        or captured.native_identity_fingerprint != native_identity_fingerprint
    ):
        raise PlanDriftError("captured startup policy provenance changed")


def _known_docker_restart_policy(value: str) -> bool:
    return value == "no" or bool(
        re.fullmatch(r"(?:always|unless-stopped|on-failure(?::[1-9][0-9]*)?)", value)
    )


def _optional_bool(value: bool | None) -> int | None:
    return None if value is None else int(value)


def _operation_row(connection: sqlite3.Connection, operation_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
    ).fetchone()
    if row is None:
        raise LifecycleError(f"unknown lifecycle operation {operation_id}")
    return row


def _repository_row(connection: sqlite3.Connection, repo_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM repositories WHERE repo_id = ?", (repo_id,)
    ).fetchone()
    if row is None:
        raise LifecycleError(f"unknown repository {repo_id}")
    return row


def _installation_row(connection: sqlite3.Connection, repo_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM repository_installations WHERE repo_id = ?", (repo_id,)
    ).fetchone()
    if row is None:
        raise ActionFencedError(f"repository {repo_id} is not installed")
    return row


def _verify_operation_fingerprint(row: sqlite3.Row, expected: str) -> None:
    if str(row["request_fingerprint"]) != expected:
        raise PlanDriftError("operation request fingerprint does not match the plan")


def _require_target_row(
    connection: sqlite3.Connection,
    operation_id: str,
    target: ExactResourceRef,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT * FROM operation_targets
        WHERE operation_id = ? AND target_kind = ? AND target_id = ?
        """,
        (operation_id, target.kind.value, target.resource_id),
    ).fetchone()
    if row is None or row["immutable_fingerprint"] != target.immutable_fingerprint:
        raise PlanDriftError("operation target immutable identity changed")
    return row


def _operation_status(value: str) -> OperationStatus:
    if value == "planned":
        return OperationStatus.PLANNED
    if value == "running":
        return OperationStatus.RUNNING
    if value == "succeeded":
        return OperationStatus.SUCCEEDED
    return OperationStatus.NEEDS_ATTENTION


def _phase_from_text(value: str) -> TargetPhase:
    normalized = value.upper()
    if normalized in TargetPhase.__members__:
        return TargetPhase[normalized]
    return TargetPhase.PENDING


def _sha(value: Any) -> str:
    return "sha256:" + fingerprint(value)


def _binding_fingerprint(row: Mapping[str, Any]) -> str:
    return _sha(
        {
            "binding_id": row["control_binding_id"] if "control_binding_id" in row.keys() else row["binding_id"],
            "resource_kind": row["binding_kind"] if "binding_kind" in row.keys() else row["resource_kind"],
            "resource_id": row["binding_resource_id"] if "binding_resource_id" in row.keys() else row["resource_id"],
            "source_id": row["source_id"],
            "capability": row["capability"],
            "provenance": row["provenance"],
            "authority_state": row["authority_state"],
            "generation": row["binding_generation"] if "binding_generation" in row.keys() else row["generation"],
        }
    )


def _binding_control_contract(row: Mapping[str, Any]) -> str:
    """Controller meaning, deliberately excluding refresh-only generation."""

    keys = row.keys()
    return _sha(
        {
            "binding_id": (
                row["control_binding_id"]
                if "control_binding_id" in keys
                else row["binding_id"]
            ),
            "repo_id": (
                row["binding_repo_id"] if "binding_repo_id" in keys else row["repo_id"]
            ),
            "source_resource_id": (
                row["binding_source_resource_id"]
                if "binding_source_resource_id" in keys
                else row["source_resource_id"]
            ),
            "resource_kind": (
                row["binding_kind"] if "binding_kind" in keys else row["resource_kind"]
            ),
            "resource_id": (
                row["binding_resource_id"]
                if "binding_resource_id" in keys
                else row["resource_id"]
            ),
            "source_id": row["source_id"],
            "capability": row["capability"],
            "provenance": row["provenance"],
            "authority_state": row["authority_state"],
            "priority": (
                row["binding_priority"] if "binding_priority" in keys else row["priority"]
            ),
        }
    )


def _allocation_fingerprint(row: Mapping[str, Any]) -> str:
    keys = row.keys()
    if "lease_id" in keys:
        value = {
            "kind": "lease",
            "lease_id": row["lease_id"],
            "host_id": row["host_id"],
            "repo_id": row["repo_id"],
            "server_definition_id": row["server_definition_id"],
            "port": row["port"],
        }
    else:
        value = {
            "kind": "port_assignment",
            "assignment_id": row["assignment_id"],
            "host_id": row["host_id"],
            "repo_id": row["repo_id"],
            "server_name": row["server_name"],
            "port": row["port"],
        }
    return _sha(value)


def _standalone_immutable_fingerprint(
    kind: ResourceKind,
    resource_id: str,
    native_identity: Sequence[tuple[str, str]],
) -> str:
    return _sha(
        {
            "resource_kind": kind.value,
            "resource_id": resource_id,
            "native_identity": {key: value for key, value in native_identity},
        }
    )


def _supervisor_native_identity(
    native_identity: Sequence[tuple[str, str]],
    capability: str,
    provenance: str,
) -> tuple[tuple[str, str], ...]:
    values = dict(native_identity)
    combined = f"{capability} {provenance}".lower()
    if "systemd" in combined:
        values["manager"] = "systemd"
        values["scope"] = "user" if "user" in combined else "system"
    elif "launchd" in combined:
        values["manager"] = "launchd"
        if "domain=" in provenance:
            values["domain"] = provenance.split("domain=", 1)[1].split(",", 1)[0]
        if "plist_path=" in provenance:
            values["plist_path"] = provenance.split("plist_path=", 1)[1].split(",", 1)[0]
        if "plist_sha256=" in provenance:
            values["plist_sha256"] = provenance.split("plist_sha256=", 1)[1].split(",", 1)[0]
    return tuple(sorted((str(key), str(value)) for key, value in values.items()))


def _insert_parameters(
    connection: sqlite3.Connection,
    operation_id: str,
    ordinal: int,
    parameters: Mapping[str, Any],
) -> None:
    for name, value in sorted(parameters.items()):
        if value is None:
            encoded, kind = "", "null"
        elif isinstance(value, bool):
            encoded, kind = ("1" if value else "0"), "boolean"
        elif isinstance(value, int):
            encoded, kind = str(value), "integer"
        else:
            encoded, kind = str(value), "text"
        connection.execute(
            """
            INSERT INTO operation_target_parameters(
                operation_id, target_ordinal, name, value, value_type
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (operation_id, ordinal, name, encoded, kind),
        )


def _parameters_by_ordinal(
    connection: sqlite3.Connection, operation_id: str
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for row in connection.execute(
        """
        SELECT * FROM operation_target_parameters
        WHERE operation_id = ? ORDER BY target_ordinal, name
        """,
        (operation_id,),
    ):
        kind = row["value_type"]
        raw = row["value"]
        if kind == "integer":
            value: Any = int(raw)
        elif kind == "boolean":
            value = raw == "1"
        elif kind == "null":
            value = None
        else:
            value = str(raw)
        result.setdefault(int(row["target_ordinal"]), {})[str(row["name"])] = value
    return result


def _encode_policies(
    parameters: dict[str, Any], policies: Sequence[StartupPolicyRef]
) -> None:
    for index, policy in enumerate(policies):
        prefix = f"policy.{index:04d}"
        parameters[f"{prefix}.id"] = policy.policy_id
        parameters[f"{prefix}.kind"] = policy.kind.value
        parameters[f"{prefix}.fingerprint"] = policy.immutable_fingerprint
        parameters[f"{prefix}.disabled_value"] = policy.disabled_value


def _decode_policies(parameters: Mapping[str, Any]) -> tuple[StartupPolicyRef, ...]:
    indexes = sorted(
        {key.split(".", 2)[1] for key in parameters if key.startswith("policy.")}
    )
    return tuple(
        StartupPolicyRef(
            str(parameters[f"policy.{index}.id"]),
            PolicyKind(str(parameters[f"policy.{index}.kind"])),
            str(parameters[f"policy.{index}.fingerprint"]),
            str(parameters[f"policy.{index}.disabled_value"]),
        )
        for index in indexes
    )


def _encode_allocations(
    parameters: dict[str, Any],
    namespace: str,
    allocations: Sequence[AllocationRef],
) -> None:
    for index, allocation in enumerate(allocations):
        prefix = f"{namespace}.{index:04d}"
        parameters[f"{prefix}.id"] = allocation.allocation_id
        parameters[f"{prefix}.kind"] = allocation.kind.value
        parameters[f"{prefix}.fingerprint"] = allocation.immutable_fingerprint


def _decode_allocations(
    parameters: Mapping[str, Any], namespace: str
) -> tuple[AllocationRef, ...]:
    indexes = sorted(
        {
            key.split(".", 2)[1]
            for key in parameters
            if key.startswith(f"{namespace}.")
        }
    )
    return tuple(
        AllocationRef(
            str(parameters[f"{namespace}.{index}.id"]),
            AllocationKind(str(parameters[f"{namespace}.{index}.kind"])),
            str(parameters[f"{namespace}.{index}.fingerprint"]),
        )
        for index in indexes
    )


def _json_mapping(value: Any) -> Mapping[str, Any]:
    if not value:
        return {}
    decoded = json.loads(str(value))
    if not isinstance(decoded, dict):
        raise LifecycleError("lifecycle evidence JSON is not an object")
    return decoded


def _merge_evidence(
    existing: Any, phase: TargetPhase, evidence: Mapping[str, Any]
) -> dict[str, Any]:
    result = dict(_json_mapping(existing)) if existing else {}
    result[phase.name.lower()] = dict(evidence)
    return result


__all__ = ["SQLiteLifecyclePersistence"]
