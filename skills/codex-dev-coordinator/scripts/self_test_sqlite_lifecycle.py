#!/usr/bin/env python3
"""SQLite integration tests for normalized lifecycle plans and fences."""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import threading
from typing import Any, Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from devcoordinator.repository_lifecycle import (  # noqa: E402
    ActionFencedError,
    ExactResourceRef,
    PolicyKind,
    PolicyObservation,
    RepositoryAction,
    RepositoryLifecycle,
    ResourceKind,
    ResourceObservation,
    RunningState,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence  # noqa: E402
from devcoordinator.store import AccountStore, CoordinatorStore, utc_timestamp  # noqa: E402


HOST_ID = "host-test"
SOURCE_ID = "source-test"
REPO_ID = "repo-test"
CONTAINER_ID = "a" * 64
DOCKER_RESOURCE_ID = "docker-repo"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class ExactStateAdapter:
    def __init__(self) -> None:
        self.running: dict[str, bool] = {}
        self.policy_disabled: dict[str, bool] = {}
        self.calls: list[str] = []

    def add(self, target: ExactResourceRef, *, running: bool, disabled: bool) -> None:
        self.running[target.resource_id] = running
        self.policy_disabled[target.resource_id] = disabled

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        disabled = self.policy_disabled[target.resource_id]
        policies = {
            policy.policy_id: PolicyObservation(
                policy.policy_id,
                policy.immutable_fingerprint,
                True,
                disabled,
                policy.disabled_value if disabled else "always",
                docker_restart_policy=(
                    (policy.disabled_value if disabled else "always")
                    if policy.kind is PolicyKind.DOCKER_RESTART else None
                ),
            )
            for policy in target.policies
        }
        running = self.running[target.resource_id]
        return ResourceObservation(
            target.resource_id,
            target.kind,
            True,
            target.immutable_fingerprint,
            True,
            target.ownership_fingerprint,
            RunningState.RUNNING if running else RunningState.STOPPED,
            container_running=running if target.kind is ResourceKind.CONTAINER else None,
            supervisor_active=running if target.kind is ResourceKind.SUPERVISOR else None,
            listener_active=running if target.kind is ResourceKind.SERVER else None,
            policies=policies,
        )

    def disable_startup_policy(
        self, target: ExactResourceRef, _policy: Any
    ) -> Mapping[str, Any]:
        self.calls.append(f"disable:{target.resource_id}")
        self.policy_disabled[target.resource_id] = True
        return {"disabled": True}

    def restore_startup_policy(
        self, target: ExactResourceRef, _policy: Any, captured: Any
    ) -> Mapping[str, Any]:
        self.calls.append(f"restore:{target.resource_id}:{captured.captured_value}")
        self.policy_disabled[target.resource_id] = False
        return {"restored": captured.captured_value, "host_may_have_started": False}

    def stop_exact(self, target: ExactResourceRef) -> Mapping[str, Any]:
        self.calls.append(f"stop:{target.resource_id}")
        self.running[target.resource_id] = False
        return {"stopped": True}


def seed_base(connection: Any) -> None:
    now = utc_timestamp()
    connection.execute(
        "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
        (HOST_ID, "machine-test", "test", "localhost", now, now),
    )
    connection.execute(
        """
        INSERT INTO coordinator_sources(
            source_id, host_id, canonical_home, state_path, effective_uid,
            status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'imported', ?, ?)
        """,
        (SOURCE_ID, HOST_ID, "/private/source", "/private/source/state.json", 0, now, now),
    )
    connection.execute(
        """
        INSERT INTO repositories(
            repo_id, host_id, canonical_root, display_name, state,
            generation, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'active', 0, ?, ?)
        """,
        (REPO_ID, HOST_ID, "/repo/test", "test", now, now),
    )
    connection.execute(
        """
        INSERT INTO repository_installations(
            repo_id, status, startup_fenced, generation, actor, updated_at
        ) VALUES (?, 'installed', 0, 3, 'seed', ?)
        """,
        (REPO_ID, now),
    )
    connection.execute(
        """
        INSERT INTO docker_engines(
            engine_id, host_id, context_identity, daemon_identity,
            capability_state, created_at, updated_at
        ) VALUES ('engine-test', ?, 'default', 'daemon-test', 'available', ?, ?)
        """,
        (HOST_ID, now, now),
    )


def seed_container(
    connection: Any,
    *,
    resource_id: str,
    full_id: str,
    binding_id: str,
    repo_id: str | None,
    membership: bool,
    unassigned: bool,
) -> None:
    now = utc_timestamp()
    source_resource_id = f"source-resource:{resource_id}"
    connection.execute(
        """
        INSERT INTO source_resources(
            source_resource_id, source_id, resource_kind, native_id,
            repo_id, payload_sha256, created_at
        ) VALUES (?, ?, 'container', ?, ?, ?, ?)
        """,
        (source_resource_id, SOURCE_ID, full_id, repo_id, f"payload:{full_id}", now),
    )
    connection.execute(
        """
        INSERT INTO docker_resources(
            docker_resource_id, engine_id, full_container_id, current_name,
            image, created_at, updated_at
        ) VALUES (?, 'engine-test', ?, ?, 'postgres:16', ?, ?)
        """,
        (resource_id, full_id, f"container-{resource_id}", now, now),
    )
    connection.execute(
        """
        INSERT INTO docker_observations(
            docker_resource_id, lifecycle, restart_policy, sampled_at,
            observation_fingerprint
        ) VALUES (?, 'running', 'always', ?, ?)
        """,
        (resource_id, now, f"observation:{full_id}"),
    )
    connection.execute(
        """
        INSERT INTO control_bindings(
            binding_id, repo_id, source_resource_id, resource_kind,
            resource_id, source_id, capability, provenance,
            authority_state, priority, generation, created_at, updated_at
        ) VALUES (?, ?, ?, 'container', ?, ?, 'docker', 'legacy',
                  'authoritative', 10, 0, ?, ?)
        """,
        (binding_id, repo_id, source_resource_id, resource_id, SOURCE_ID, now, now),
    )
    connection.execute(
        """
        INSERT INTO startup_policies(
            policy_id, repo_id, resource_kind, resource_id, policy_kind,
            current_value, desired_disabled_value, immutable_fingerprint,
            generation, updated_at
        ) VALUES (?, ?, 'container', ?, 'docker_restart',
                  'always', 'no', ?, 0, ?)
        """,
        (f"policy:{resource_id}", repo_id, resource_id, f"policy-fp:{resource_id}", now),
    )
    if membership:
        connection.execute(
            """
            INSERT INTO repository_memberships(
                membership_id, repo_id, resource_kind, host_resource_id,
                immutable_fingerprint, control_binding_id, created_at
            ) VALUES (?, ?, 'container', ?, ?, ?, ?)
            """,
            (
                f"membership:{resource_id}",
                repo_id,
                resource_id,
                f"membership-fp:{resource_id}",
                binding_id,
                now,
            ),
        )
    if unassigned:
        connection.execute(
            """
            INSERT INTO unassigned_resources(
                unassigned_id, host_id, source_resource_id, resource_kind,
                resource_id, display_name, reason_code, status,
                created_at, updated_at
            ) VALUES (?, ?, ?, 'container', ?, ?, 'ambiguous_control',
                      'active', ?, ?)
            """,
            (
                f"unassigned:{resource_id}",
                HOST_ID,
                source_resource_id,
                resource_id,
                f"container-{resource_id}",
                now,
                now,
            ),
        )


def open_seeded_store(root: Path) -> AccountStore:
    root.mkdir(mode=0o700)
    store = AccountStore.open(root / "coordinator.sqlite3")
    with store.immediate_transaction() as connection:
        seed_base(connection)
        seed_container(
            connection,
            resource_id=DOCKER_RESOURCE_ID,
            full_id=CONTAINER_ID,
            binding_id="binding-repo",
            repo_id=REPO_ID,
            membership=True,
            unassigned=False,
        )
        now = utc_timestamp()
        connection.execute(
            """
            INSERT INTO leases(
                lease_id, host_id, repo_id, port, owner, agent, purpose,
                status, generation, created_at, updated_at
            ) VALUES ('lease-manual', ?, ?, 3456, 'tester', 'tester',
                      'manual', 'active', 0, ?, ?)
            """,
            (HOST_ID, REPO_ID, now, now),
        )
        connection.execute(
            """
            INSERT INTO port_assignments(
                assignment_id, host_id, repo_id, server_name, port, status,
                generation, created_at, updated_at
            ) VALUES ('pin-manual', ?, ?, 'manual', 3457, 'active', 0, ?, ?)
            """,
            (HOST_ID, REPO_ID, now, now),
        )
    return store


def test_repository_plan_apply_reinstall_and_normalized_ledger() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            persistence = SQLiteLifecyclePersistence(store)
            initial_inventory = store.inventory_v2()
            expect(
                [item["repo_id"] for item in initial_inventory["repositories"]] == [REPO_ID],
                "one normalized repository did not produce one active project",
            )
            expect(
                [item["host_resource_id"] for item in initial_inventory["docker"]["containers"]]
                == [DOCKER_RESOURCE_ID],
                "installed repository container is missing from active inventory",
            )
            snapshot = persistence.repository_snapshot(REPO_ID)
            expect(len(snapshot.targets) == 1, "repository target was not normalized")
            expect(
                len(snapshot.repository_allocations) == 2,
                "unmatched lease/pin were not retained on repository ledger",
            )
            target = snapshot.targets[0]
            native = dict(target.native_identity)
            expect(native.get("full_container_id") == CONTAINER_ID, "full Docker ID missing")
            adapter = ExactStateAdapter()
            adapter.add(target, running=True, disabled=False)
            lifecycle = RepositoryLifecycle(
                persistence, adapter, id_factory=lambda: "plan-repository"
            )
            plan = lifecycle.plan_repository_decommission(
                REPO_ID, actor="tester", reason="remove from Board"
            )
            with store.read_transaction() as connection:
                operation = connection.execute(
                    "SELECT * FROM operations WHERE operation_id = ?", (plan.plan_id,)
                ).fetchone()
                expect(operation["request_fingerprint"] == plan.fingerprint, "plan hash missing")
                expect(operation["result_json"] is None, "JSON became plan authority")
                parameter_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM operation_target_parameters
                    WHERE operation_id = ?
                    """,
                    (plan.plan_id,),
                ).fetchone()[0]
                expect(parameter_count >= 12, "normalized target parameters are incomplete")
            loaded = persistence.load_plan(plan.plan_id)
            expect(loaded == plan, "normalized plan did not round-trip")
            result = lifecycle.apply_repository_decommission(
                plan.plan_id, plan.fingerprint, actor="tester"
            )
            expect(result.status == "succeeded", f"repository removal failed: {result.to_dict()}")
            expect(adapter.calls == [f"disable:{DOCKER_RESOURCE_ID}", f"stop:{DOCKER_RESOURCE_ID}"], "host effect order changed")
            with store.read_transaction() as connection:
                installation = connection.execute(
                    "SELECT * FROM repository_installations WHERE repo_id = ?", (REPO_ID,)
                ).fetchone()
                expect(installation["status"] == "disabled", "repository was not disabled")
                expect(installation["startup_fenced"] == 1, "durable fence was cleared")
                expect(
                    connection.execute("SELECT status FROM leases WHERE lease_id='lease-manual'").fetchone()[0]
                    == "released",
                    "manual lease remained active",
                )
                expect(
                    connection.execute("SELECT status FROM port_assignments WHERE assignment_id='pin-manual'").fetchone()[0]
                    == "inactive",
                    "port assignment remained active",
                )
                expect(
                    connection.execute("SELECT current_value FROM startup_policies WHERE policy_id=?", (f"policy:{DOCKER_RESOURCE_ID}",)).fetchone()[0]
                    == "no",
                    "restart policy evidence remained enabled",
                )
                expect(
                    not connection.execute("SELECT 1 FROM operation_targets WHERE operation_id=? AND status!='succeeded'", (plan.plan_id,)).fetchall(),
                    "operation retained an incomplete target",
                )
            removed = lifecycle.list_removed_repositories()
            expect(len(removed) == 1 and removed[0]["repo_id"] == REPO_ID, "removed list is wrong")
            hidden_inventory = store.inventory_v2()
            expect(not hidden_inventory["repositories"], "disabled repository remained active")
            expect(not hidden_inventory["project_usage"], "disabled project usage remained active")
            expect(not hidden_inventory["docker"]["containers"], "disabled container remained active")
            expect(not hidden_inventory["resources"]["docker"], "disabled v2 resource remained active")
            expect(
                not hidden_inventory["lifecycle_violations"],
                "truthfully stopped disabled resource was reported as a fence violation",
            )
            with store.read_transaction() as connection:
                retained = connection.execute(
                    """
                    SELECT d.full_container_id, o.lifecycle, o.restart_policy
                    FROM docker_resources d
                    JOIN docker_observations o USING(docker_resource_id)
                    WHERE d.docker_resource_id = ?
                    """,
                    (DOCKER_RESOURCE_ID,),
                ).fetchone()
                expect(retained is not None, "disabled repository resource evidence was deleted")
                expect(retained["full_container_id"] == CONTAINER_ID, "immutable ID changed")
                expect(retained["lifecycle"] == "stopped", "verified stop was not persisted")
                expect(retained["restart_policy"] == "no", "disabled restart policy was not persisted")
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE docker_observations SET lifecycle='running', sampled_at=?,
                        observation_fingerprint='violation-running'
                    WHERE docker_resource_id=?
                    """,
                    (utc_timestamp(), DOCKER_RESOURCE_ID),
                )
            violation_inventory = store.inventory_v2()
            expect(not violation_inventory["repositories"], "fence violation resurrected project")
            expect(not violation_inventory["project_usage"], "fence violation resurrected usage row")
            expect(
                len(violation_inventory["lifecycle_violations"]) == 1,
                "running disabled resource did not create one critical violation",
            )
            violation = violation_inventory["lifecycle_violations"][0]
            expect(violation["reason_code"] == "start_fence_violated", violation)
            expect(violation["affected_repo_id"] == REPO_ID, violation)
            expect(not violation["can_attach"] and not violation["can_retire"], violation)
            visible_container = violation_inventory["docker"]["containers"][0]
            expect(visible_container["project"] is None, "violation recreated project identity")
            expect(
                visible_container["attribution"]["lifecycle_violation"],
                "compatibility container omitted violation attribution",
            )
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE docker_observations SET lifecycle='stopped', sampled_at=?,
                        observation_fingerprint='violation-cleared'
                    WHERE docker_resource_id=?
                    """,
                    (utc_timestamp(), DOCKER_RESOURCE_ID),
                )
            cleared_inventory = store.inventory_v2()
            expect(not cleared_inventory["lifecycle_violations"], "stopped control stayed critical")
            expect(not cleared_inventory["docker"]["containers"], "stopped disabled row stayed visible")
            installed = lifecycle.reinstall_repository(
                REPO_ID, actor="tester", reason="explicit restore", explicit=True
            )
            expect(not installed.started and not installed.hidden, "reinstall started or hid project")
            expect(adapter.calls == [f"disable:{DOCKER_RESOURCE_ID}", f"stop:{DOCKER_RESOURCE_ID}"], "reinstall touched host")
            restored_inventory = store.inventory_v2()
            expect(
                [item["repo_id"] for item in restored_inventory["repositories"]] == [REPO_ID],
                "reinstalled repository did not return exactly once",
            )
            expect(
                restored_inventory["docker"]["containers"][0]["status"] == "stopped",
                "reinstalled repository returned with a stale running status",
            )
        finally:
            store.close()


def test_reinstall_defers_exact_policy_restore_until_guarded_explicit_start() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            persistence = SQLiteLifecyclePersistence(store)
            target = persistence.repository_snapshot(REPO_ID).targets[0]
            adapter = ExactStateAdapter()
            adapter.add(target, running=True, disabled=False)
            lifecycle = RepositoryLifecycle(
                persistence, adapter, id_factory=lambda: "restore-plan"
            )
            plan = lifecycle.plan_repository_decommission(
                REPO_ID, actor="tester", reason="capture exact policy"
            )
            result = lifecycle.apply_repository_decommission(
                plan.plan_id, plan.fingerprint, actor="tester"
            )
            expect(result.status == "succeeded", result.to_dict())
            with store.read_transaction() as connection:
                capture = connection.execute(
                    "SELECT * FROM startup_policy_restore_states WHERE policy_id = ?",
                    (f"policy:{DOCKER_RESOURCE_ID}",),
                ).fetchone()
                expect(capture is not None, "pre-disable policy state was not retained")
                expect(capture["captured_value"] == "always", dict(capture))
                expect(capture["docker_restart_policy"] == "always", dict(capture))
                expect(capture["status"] == "captured", dict(capture))
                expect(capture["target_immutable_fingerprint"] == target.immutable_fingerprint, dict(capture))
                expect(capture["control_binding_id"] == target.control_binding_id, dict(capture))
                expect(capture["native_identity_fingerprint"], dict(capture))
            calls_after_remove = list(adapter.calls)
            installed = lifecycle.reinstall_repository(
                REPO_ID, actor="tester", reason="explicit reinstall", explicit=True
            )
            expect(not installed.started, installed.to_dict())
            expect(adapter.calls == calls_after_remove, "reinstall restored or started host policy")
            with store.read_transaction() as connection:
                expect(
                    connection.execute(
                        "SELECT current_value FROM startup_policies WHERE policy_id = ?",
                        (f"policy:{DOCKER_RESOURCE_ID}",),
                    ).fetchone()[0]
                    == "no",
                    "reinstall changed policy before explicit start",
                )
            try:
                lifecycle.reserve_repository_action(
                    REPO_ID,
                    RepositoryAction.COMPOSE,
                    request_id="bypass-policy-restore",
                    actor="tester",
                )
            except ActionFencedError:
                pass
            else:
                raise AssertionError("Compose bypassed pending startup policy restore")
            permit = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="guarded-explicit-start",
                actor="tester",
            )
            restored = lifecycle.restore_startup_policies_for_start(permit)
            expect(
                restored.restored_policy_ids == (f"policy:{DOCKER_RESOURCE_ID}",),
                restored.to_dict(),
            )
            expect(adapter.calls[-1] == f"restore:{DOCKER_RESOURCE_ID}:always", adapter.calls)
            with store.read_transaction() as connection:
                row = connection.execute(
                    """
                    SELECT p.current_value, r.status, r.last_restore_permit_id
                    FROM startup_policies p
                    JOIN startup_policy_restore_states r USING(policy_id)
                    WHERE p.policy_id = ?
                    """,
                    (f"policy:{DOCKER_RESOURCE_ID}",),
                ).fetchone()
                expect(tuple(row) == ("always", "restored", permit.permit_id), tuple(row))
            call_count = len(adapter.calls)
            repeated = lifecycle.restore_startup_policies_for_start(permit)
            expect(
                repeated.already_restored_policy_ids
                == (f"policy:{DOCKER_RESOURCE_ID}",),
                repeated.to_dict(),
            )
            expect(len(adapter.calls) == call_count, "idempotent check repeated a mutation")
            lifecycle.release_action_permit(permit, outcome="succeeded")
            later = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="later-explicit-start",
                actor="tester",
            )
            later_result = lifecycle.restore_startup_policies_for_start(later)
            expect(not later_result.restored_policy_ids, later_result.to_dict())
            expect(len(adapter.calls) == call_count, "historical policy was restored again")
            lifecycle.release_action_permit(later, outcome="succeeded")
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE startup_policies SET current_value = 'unless-stopped' WHERE policy_id = ?",
                    (f"policy:{DOCKER_RESOURCE_ID}",),
                )
            owner_changed = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="owner-policy-change-start",
                actor="tester",
            )
            owner_result = lifecycle.restore_startup_policies_for_start(owner_changed)
            expect(not owner_result.restored_policy_ids, owner_result.to_dict())
            expect(len(adapter.calls) == call_count, "historical capture overwrote owner policy")
            lifecycle.release_action_permit(owner_changed, outcome="succeeded")
        finally:
            store.close()


def test_missing_pre_disable_capture_blocks_start_without_host_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            persistence = SQLiteLifecyclePersistence(store)
            target = persistence.repository_snapshot(REPO_ID).targets[0]
            adapter = ExactStateAdapter()
            adapter.add(target, running=False, disabled=True)
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE startup_policies SET current_value = desired_disabled_value WHERE repo_id = ?",
                    (REPO_ID,),
                )
                connection.execute(
                    """
                    UPDATE repository_installations
                    SET status = 'installed', startup_fenced = 0,
                        generation = generation + 1, reinstalled_at = ?
                    WHERE repo_id = ?
                    """,
                    (utc_timestamp(), REPO_ID),
                )
            lifecycle = RepositoryLifecycle(persistence, adapter)
            permit = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="missing-capture-start",
                actor="tester",
            )
            try:
                lifecycle.restore_startup_policies_for_start(permit)
            except Exception as error:
                expect("no captured pre-disable state" in str(error), error)
            else:
                raise AssertionError("start proceeded without pre-disable capture")
            expect(not adapter.calls, "missing capture performed a host mutation")
        finally:
            store.close()


def test_never_decommissioned_disabled_policy_is_a_safe_restore_noop() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            persistence = SQLiteLifecyclePersistence(store)
            target = persistence.repository_snapshot(REPO_ID).targets[0]
            adapter = ExactStateAdapter()
            adapter.add(target, running=False, disabled=True)
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE startup_policies SET current_value = desired_disabled_value WHERE repo_id = ?",
                    (REPO_ID,),
                )
            lifecycle = RepositoryLifecycle(persistence, adapter)
            permit = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="never-removed-start",
                actor="tester",
            )
            result = lifecycle.restore_startup_policies_for_start(permit)
            expect(result.restored_policy_ids == (), result.to_dict())
            expect(not adapter.calls, "no-op restore mutated host")
        finally:
            store.close()


def test_exact_unassigned_attach_and_retire() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            with store.immediate_transaction() as connection:
                seed_container(
                    connection,
                    resource_id="docker-attach",
                    full_id="b" * 64,
                    binding_id="binding-attach",
                    repo_id=None,
                    membership=False,
                    unassigned=True,
                )
                seed_container(
                    connection,
                    resource_id="docker-retire",
                    full_id="c" * 64,
                    binding_id="binding-retire",
                    repo_id=None,
                    membership=False,
                    unassigned=True,
                )
            persistence = SQLiteLifecyclePersistence(store)
            attach_ref = persistence.resolve_standalone_resource(
                ResourceKind.CONTAINER, "docker-attach", "binding-attach"
            )
            retire_ref = persistence.resolve_standalone_resource(
                ResourceKind.CONTAINER, "docker-retire", "binding-retire"
            )
            expect(bool(attach_ref.ownership_fingerprint), "ownership fingerprint missing")
            projected_attach = next(
                item
                for item in store.inventory_v2()["unassigned_resources"]
                if item["resource_id"] == "docker-attach"
            )
            expect(
                projected_attach["immutable_fingerprint"] == attach_ref.immutable_fingerprint,
                "Board projection immutable fingerprint does not match lifecycle authority",
            )
            expect(
                projected_attach["ownership_fingerprint"] == attach_ref.ownership_fingerprint,
                "Board projection ownership fingerprint does not match lifecycle authority",
            )
            adapter = ExactStateAdapter()
            adapter.add(attach_ref, running=False, disabled=False)
            adapter.add(retire_ref, running=True, disabled=False)
            lifecycle = RepositoryLifecycle(
                persistence,
                adapter,
                id_factory=iter(("retire-plan", "unused")).__next__,
            )
            attached = lifecycle.attach_resource(
                REPO_ID,
                attach_ref,
                actor="tester",
                reason="explicit repository choice",
            )
            expect(attached.attached and not attached.started, "attach was not passive")
            with store.read_transaction() as connection:
                membership = connection.execute(
                    """
                    SELECT repo_id FROM repository_memberships
                    WHERE resource_kind='container' AND host_resource_id='docker-attach'
                    """
                ).fetchone()
                expect(membership["repo_id"] == REPO_ID, "exact attachment not persisted")
                policy_owner = connection.execute(
                    """
                    SELECT repo_id FROM startup_policies
                    WHERE resource_kind='container' AND resource_id='docker-attach'
                    """
                ).fetchone()
                expect(
                    policy_owner["repo_id"] == REPO_ID,
                    "attached startup policy remained outside repository lifecycle",
                )
            plan = lifecycle.plan_standalone_retirement(
                retire_ref, actor="tester", reason="retire orphan"
            )
            persistence.fence_resource(plan, actor="tester")
            fenced_inventory = store.inventory_v2()
            fenced_row = next(
                item
                for item in fenced_inventory["unassigned_resources"]
                if item["resource_id"] == "docker-retire"
            )
            expect(
                any(
                    item["host_resource_id"] == "docker-retire"
                    for item in fenced_inventory["docker"]["containers"]
                ),
                "partially retired resource disappeared before verified completion",
            )
            expect(not fenced_row["can_retire"], "in-progress retirement still offered retire")
            retired = lifecycle.apply_standalone_retirement(
                plan.plan_id, plan.fingerprint, actor="tester"
            )
            expect(retired.status == "succeeded" and retired.hidden, "retirement failed")
            retired_inventory = store.inventory_v2()
            expect(
                not any(
                    item["resource_id"] == "docker-retire"
                    for item in retired_inventory["unassigned_resources"]
                ),
                "retired resource remained in unassigned inventory",
            )
            expect(
                not any(
                    item["host_resource_id"] == "docker-retire"
                    for item in retired_inventory["docker"]["containers"]
                ),
                "retired resource remained in compatibility inventory",
            )
            expect(
                not any(
                    item["docker_resource_id"] == "docker-retire"
                    for item in retired_inventory["resources"]["docker"]
                ),
                "retired resource remained in active v2 resources",
            )
            with store.read_transaction() as connection:
                expect(
                    connection.execute(
                        "SELECT lifecycle FROM docker_observations WHERE docker_resource_id='docker-retire'"
                    ).fetchone()[0]
                    == "stopped",
                    "retired resource did not retain its verified stopped evidence",
                )
                expect(
                    connection.execute(
                        "SELECT status FROM resource_retirements WHERE host_resource_id='docker-retire'"
                    ).fetchone()[0]
                    == "retired",
                    "retirement ledger was deleted",
                )
            expect(
                not retired_inventory["lifecycle_violations"],
                "truthfully stopped retired resource was reported as a violation",
            )
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE docker_observations SET lifecycle='running', sampled_at=?,
                        observation_fingerprint='retired-running'
                    WHERE docker_resource_id='docker-retire'
                    """,
                    (utc_timestamp(),),
                )
            retired_violation_inventory = store.inventory_v2()
            retired_violation = next(
                item
                for item in retired_violation_inventory["lifecycle_violations"]
                if item["resource_id"] == "docker-retire"
            )
            expect(
                retired_violation["corrective_action"] == "standalone_retirement",
                retired_violation,
            )
            retired_container = next(
                item
                for item in retired_violation_inventory["docker"]["containers"]
                if item["host_resource_id"] == "docker-retire"
            )
            expect(retired_container["project"] is None, retired_container)
            expect(retired_container["attribution"]["lifecycle_violation"], retired_container)
            with store.immediate_transaction(revision_kind="observation") as connection:
                connection.execute(
                    """
                    UPDATE docker_observations SET lifecycle='stopped', sampled_at=?,
                        observation_fingerprint='retired-stopped-again'
                    WHERE docker_resource_id='docker-retire'
                    """,
                    (utc_timestamp(),),
                )
            expect(
                not any(
                    item["resource_id"] == "docker-retire"
                    for item in store.inventory_v2()["lifecycle_violations"]
                ),
                "stopped retired false-positive remained",
            )
            try:
                lifecycle.reserve_resource_action(
                    retire_ref,
                    RepositoryAction.START,
                    request_id="start-retired",
                    actor="tester",
                )
            except ActionFencedError:
                pass
            else:
                raise AssertionError("retired resource received a start permit")
        finally:
            store.close()


def test_repository_action_guard_blocks_decommission_until_released() -> None:
    with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-", dir=Path.home()) as raw:
        store = open_seeded_store(Path(raw).resolve() / "state")
        try:
            persistence = SQLiteLifecyclePersistence(store)
            target = persistence.repository_snapshot(REPO_ID).targets[0]
            adapter = ExactStateAdapter()
            adapter.add(target, running=False, disabled=True)
            lifecycle = RepositoryLifecycle(
                persistence, adapter, id_factory=lambda: "guard-plan"
            )
            plan = lifecycle.plan_repository_decommission(
                REPO_ID, actor="tester", reason="guard race"
            )
            permit = lifecycle.reserve_repository_action(
                REPO_ID,
                RepositoryAction.START,
                request_id="start-guard",
                actor="tester",
            )
            try:
                lifecycle.apply_repository_decommission(
                    plan.plan_id, plan.fingerprint, actor="tester"
                )
            except Exception as error:
                expect(
                    error.__class__.__name__ == "ConcurrentLifecycleError",
                    f"wrong guard error: {error!r}",
                )
            else:
                raise AssertionError("decommission raced through an active start permit")
            lifecycle.release_action_permit(permit, outcome="failed")
            result = lifecycle.apply_repository_decommission(
                plan.plan_id, plan.fingerprint, actor="tester"
            )
            expect(result.status == "succeeded", "decommission did not roll forward")
            try:
                lifecycle.reserve_repository_action(
                    REPO_ID,
                    RepositoryAction.START,
                    request_id="start-after-fence",
                    actor="tester",
                )
            except ActionFencedError:
                pass
            else:
                raise AssertionError("disabled repository received a start permit")
        finally:
            store.close()


def test_sqlite_guard_and_fence_race_serializes_one_winner() -> None:
    for index in range(12):
        with tempfile.TemporaryDirectory(prefix=".sqlite-lifecycle-race-", dir=Path.home()) as raw:
            database_root = Path(raw).resolve() / "state"
            owner_store = open_seeded_store(database_root)
            try:
                owner_persistence = SQLiteLifecyclePersistence(owner_store)
                target = owner_persistence.repository_snapshot(REPO_ID).targets[0]
                adapter = ExactStateAdapter()
                adapter.add(target, running=False, disabled=True)
                lifecycle = RepositoryLifecycle(
                    owner_persistence,
                    adapter,
                    id_factory=lambda: f"race-plan-{index}",
                )
                plan = lifecycle.plan_repository_decommission(
                    REPO_ID, actor="tester", reason="real SQLite race"
                )
                barrier = threading.Barrier(2)
                outcomes: list[str] = []
                errors: list[str] = []

                def guard() -> None:
                    local = CoordinatorStore.open(database_root / "coordinator.sqlite3")
                    try:
                        barrier.wait()
                        persistence = SQLiteLifecyclePersistence(local)
                        persistence.reserve_repository_action(
                            REPO_ID,
                            RepositoryAction.START,
                            request_id=f"race-start-{index}",
                            actor="tester",
                        )
                        outcomes.append("guard")
                    except (ActionFencedError, Exception) as error:
                        if error.__class__.__name__ in {
                            "ActionFencedError",
                            "ConcurrentLifecycleError",
                        }:
                            outcomes.append("guard-blocked")
                        else:
                            errors.append(f"guard:{error!r}")
                    finally:
                        local.close()

                def fence() -> None:
                    local = CoordinatorStore.open(database_root / "coordinator.sqlite3")
                    try:
                        barrier.wait()
                        SQLiteLifecyclePersistence(local).fence_repository(
                            plan, actor="tester"
                        )
                        outcomes.append("fence")
                    except Exception as error:
                        if error.__class__.__name__ in {
                            "ActionFencedError",
                            "ConcurrentLifecycleError",
                        }:
                            outcomes.append("fence-blocked")
                        else:
                            errors.append(f"fence:{error!r}")
                    finally:
                        local.close()

                threads = [threading.Thread(target=guard), threading.Thread(target=fence)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                expect(not errors, errors)
                expect(
                    sorted(outcomes)
                    in (["fence", "guard-blocked"], ["fence-blocked", "guard"]),
                    outcomes,
                )
                with owner_store.read_transaction() as connection:
                    fenced = bool(
                        connection.execute(
                            """
                            SELECT startup_fenced FROM repository_installations
                            WHERE repo_id = ?
                            """,
                            (REPO_ID,),
                        ).fetchone()[0]
                    )
                    active_guard = bool(
                        connection.execute(
                            """
                            SELECT 1 FROM operations
                            WHERE kind = 'guard:start' AND status = 'running'
                            """
                        ).fetchone()
                    )
                    expect(not (fenced and active_guard), outcomes)
            finally:
                owner_store.close()


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"SQLite lifecycle self-test passed ({len(tests)} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
