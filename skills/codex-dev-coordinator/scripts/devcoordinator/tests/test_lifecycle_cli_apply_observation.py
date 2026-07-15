from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from devcoordinator.broker_profile import (
    BrokerClientProfile,
    BrokerProfileError,
    BrokerRepositoryProfile,
    BrokerServiceProfile,
)
from devcoordinator.host_observation import commit_host_inventory_observation
from devcoordinator.lifecycle_cli import (
    FULL_DOCKER_OBSERVER_DOMAIN,
    _require_plan_target_identity_unchanged,
    _require_target_semantically_unchanged,
    add_lifecycle_parsers,
    handle_lifecycle_cli,
)
from devcoordinator.observer import SingleFlightObserver
from devcoordinator.repository_lifecycle import (
    AllocationKind,
    AllocationRef,
    ExactResourceRef,
    LifecycleError,
    PlanDriftError,
    PolicyKind,
    PolicyObservation,
    ResourceKind,
    ResourceObservation,
    RunningState,
    StartupPolicyRef,
)
from devcoordinator.sqlite_lifecycle import SQLiteLifecyclePersistence
from devcoordinator.store import AccountStore, utc_timestamp


def _parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    add_lifecycle_parsers(value.add_subparsers(dest="group", required=True))
    return value


class RecordingAdapter:
    """Exact fake host boundary; only disable/stop calls count as effects."""

    def __init__(self) -> None:
        self.effects: list[tuple[str, str]] = []
        self.containers: dict[str, dict[str, object]] = {}

    def add_container(
        self, full_id: str, *, running: bool = True, restart_policy: str = "always"
    ) -> None:
        self.containers[full_id] = {
            "running": running,
            "restart_policy": restart_policy,
        }

    def observe_exact(self, target: ExactResourceRef) -> ResourceObservation:
        native = dict(target.native_identity)
        full_id = native.get("full_container_id", "")
        state = self.containers.get(full_id)
        observable = state is not None
        running = bool(state and state["running"])
        policy_value = str(state["restart_policy"]) if state else None
        policies: dict[str, PolicyObservation] = {}
        for policy in target.policies:
            policies[policy.policy_id] = PolicyObservation(
                policy.policy_id,
                policy.immutable_fingerprint,
                observable,
                policy_value == policy.disabled_value if observable else None,
                policy_value,
                docker_restart_policy=(
                    policy_value if policy.kind is PolicyKind.DOCKER_RESTART else None
                ),
            )
        return ResourceObservation(
            target.resource_id,
            target.kind,
            observable,
            target.immutable_fingerprint if observable else None,
            observable,
            target.ownership_fingerprint if observable else None,
            RunningState.RUNNING if running else RunningState.STOPPED,
            container_running=running if observable else None,
            policies=policies,
        )

    def disable_startup_policy(
        self, target: ExactResourceRef, policy: StartupPolicyRef
    ) -> dict[str, object]:
        full_id = dict(target.native_identity)["full_container_id"]
        self.effects.append(("disable", full_id))
        self.containers[full_id]["restart_policy"] = policy.disabled_value
        return {"disabled": True}

    def restore_startup_policy(self, *_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("restore is not part of retirement")

    def stop_exact(self, target: ExactResourceRef) -> dict[str, object]:
        full_id = dict(target.native_identity)["full_container_id"]
        self.effects.append(("stop", full_id))
        self.containers[full_id]["running"] = False
        return {"stopped": True}


class LifecycleApplyObservationTests(unittest.TestCase):
    A = "a" * 64
    A_REPLACEMENT = "1" * 64
    B = "b" * 64
    B_REPLACEMENT = "2" * 64
    C = "c" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "coordinator-home"
        self.repo_a = self._repository("repo-a")
        self.repo_b = self._repository("repo-b")
        self.request_repo = self._repository("request-repo")
        self.adapter = RecordingAdapter()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _repository(self, name: str) -> Path:
        value = self.root / name
        value.mkdir()
        (value / ".git").mkdir()
        return value.resolve()

    @staticmethod
    def _container(full_id: str, *, project: Path | None = None) -> dict[str, object]:
        value: dict[str, object] = {
            "id": full_id[:12],
            "full_id": full_id,
            "name": f"fixture-{full_id[0]}",
            "image": "postgres:16",
            "status": "Up 1 minute",
            "restart_policy": "always",
            "metadata_source": "coordinator_sidecar" if project is not None else "none",
            "labels": {},
            "port_bindings": [],
            "databases": [],
        }
        if project is not None:
            value["project"] = str(project)
        return value

    @staticmethod
    def _sample(*containers: dict[str, object], available: bool = True) -> dict[str, object]:
        return {
            "sampled_at": utc_timestamp(),
            "inventory": {
                "servers": [],
                "docker": {
                    "available": available,
                    "containers": list(containers) if available else [],
                    "postgres": [],
                },
            },
        }

    def _commit_observation(self, sample: dict[str, object]):
        with AccountStore.open_default(self.home) as store:
            host_id = store.ensure_local_host()
            return SingleFlightObserver(store).observe(
                host_id=host_id,
                observer_domain=FULL_DOCKER_OBSERVER_DOMAIN,
                sampler=lambda: sample,
                commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    observed,
                    host_id=host_id,
                    coordinator_home=str(self.home),
                ),
            )

    def _callback(self, sample: dict[str, object]):
        def observe(project: str, agent: str) -> dict[str, object]:
            outcome = self._commit_observation(sample)
            return {
                "status": "completed",
                "observed": True,
                "joined": bool(outcome.joined),
                "snapshot_id": outcome.snapshot_id,
                "host_id": outcome.host_id,
                "observer_domain": outcome.observer_domain,
                "material_fingerprint": outcome.material_fingerprint,
                "completed_at": outcome.completed_at,
                "max_age_seconds": 0,
                "request": {"project": project, "agent": agent},
            }

        return observe

    def _handle(self, args: argparse.Namespace, **callbacks: object):
        with mock.patch(
            "devcoordinator.lifecycle_cli.load_broker_profile", return_value=None
        ):
            return handle_lifecycle_cli(
                args,
                coordinator_home=self.home,
                canonical_project=lambda value: str(Path(value).resolve()),
                bootstrap_legacy_import=lambda _store: {
                    "attempted": False,
                    "committed": False,
                    "late_writer_sources": [],
                },
                adapter_factory=lambda: self.adapter,
                **callbacks,
            )

    def _plan_repository(self) -> dict[str, object]:
        sample = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        self._commit_observation(sample)
        args = _parser().parse_args(
            [
                "repository",
                "plan-remove",
                "--project",
                str(self.repo_a),
                "--agent",
                "test-agent",
                "--reason",
                "remove repo A",
            ]
        )
        return self._handle(args, observe_before_plan=self._callback(sample))

    def _repository_remove_args(self, plan: dict[str, object]) -> argparse.Namespace:
        return _parser().parse_args(
            [
                "repository",
                "remove",
                "--project",
                str(self.repo_a),
                "--agent",
                "test-agent",
                "--plan-id",
                str(plan["plan_id"]),
                "--plan-fingerprint",
                str(plan.get("fingerprint") or plan["plan_fingerprint"]),
            ]
        )

    def test_repository_replacement_drift_is_rejected_before_host_effects(self) -> None:
        plan = self._plan_repository()
        changed = self._sample(
            self._container(self.A_REPLACEMENT, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        with self.assertRaisesRegex(
            PlanDriftError, "resources changed|control became ambiguous"
        ):
            self._handle(
                self._repository_remove_args(plan),
                observe_before_apply=self._callback(changed),
            )
        self.assertEqual(self.adapter.effects, [])
        with AccountStore.open_default(self.home) as store:
            installation = store.connection.execute(
                "SELECT status, startup_fenced FROM repository_installations WHERE repo_id=?",
                (plan["repo_id"],),
            ).fetchone()
            self.assertEqual(tuple(installation), ("installed", 0))

    def test_unrelated_repository_drift_does_not_block_confirmed_remove(self) -> None:
        plan = self._plan_repository()
        self.adapter.add_container(self.A)
        unrelated_change = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B_REPLACEMENT, project=self.repo_b),
        )
        result = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unrelated_change),
        )
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["hidden"])
        self.assertEqual(result["confirmed_plan"]["plan_id"], plan["plan_id"])
        self.assertNotEqual(result["plan_id"], plan["plan_id"])
        self.assertEqual(
            result["pre_apply_observation"]["observer_domain"],
            FULL_DOCKER_OBSERVER_DOMAIN,
        )
        self.assertEqual(
            self.adapter.effects,
            [("disable", self.A), ("stop", self.A)],
        )

    def test_resume_revalidates_replacement_drift_before_further_host_effects(self) -> None:
        plan = self._plan_repository()
        unchanged = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        interrupted = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )
        self.assertEqual(interrupted["status"], "needs_attention")
        self.assertEqual(self.adapter.effects, [])

        replacement = self._sample(
            self._container(self.A_REPLACEMENT, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        with self.assertRaisesRegex(
            PlanDriftError, "resources changed|control became ambiguous"
        ):
            self._handle(
                self._repository_remove_args(interrupted),
                observe_before_apply=self._callback(replacement),
            )
        self.assertEqual(self.adapter.effects, [])

    def test_retrying_confirmed_plan_returns_durable_successor_without_more_effects(self) -> None:
        plan = self._plan_repository()
        unchanged = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        self.adapter.add_container(self.A)
        first = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )
        self.assertEqual(first["status"], "succeeded")
        self.assertNotEqual(first["plan_id"], plan["plan_id"])
        effects = list(self.adapter.effects)

        repeated = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=lambda *_args: self.fail(
                "completed successor retry must not observe or touch the host"
            ),
        )

        self.assertEqual(repeated["status"], "already_complete")
        self.assertEqual(repeated["plan_id"], first["plan_id"])
        self.assertEqual(repeated["confirmed_plan"]["plan_id"], plan["plan_id"])
        self.assertEqual(self.adapter.effects, effects)
        reinstall = _parser().parse_args(
            [
                "repository",
                "reinstall",
                "--project",
                str(self.repo_a),
                "--agent",
                "test-agent",
                "--reason",
                "retry regression reinstall",
                "--explicit",
            ]
        )
        restored = self._handle(reinstall)
        self.assertEqual(restored["status"], "installed")
        with AccountStore.open_default(self.home) as store:
            rows = list(
                store.connection.execute(
                    """
                    SELECT operation_id, status FROM operations
                    WHERE operation_id IN (?, ?) ORDER BY operation_id
                    """,
                    (plan["plan_id"], first["plan_id"]),
                )
            )
            incomplete = store.connection.execute(
                """
                SELECT COUNT(*) FROM operations
                WHERE repo_id = ? AND status IN (
                    'planned', 'running', 'needs_attention', 'partial'
                )
                """,
                (plan["repo_id"],),
            ).fetchone()[0]
        self.assertEqual({row["status"] for row in rows}, {"cancelled", "succeeded"})
        self.assertEqual(incomplete, 0)

    def test_successor_binding_validates_first_bind_and_idempotent_replay_states(self) -> None:
        plans = [self._plan_repository() for _index in range(4)]
        plan_ids = [str(plan["plan_id"]) for plan in plans]
        with AccountStore.open_default(self.home) as store:
            persistence = SQLiteLifecyclePersistence(store)
            loaded = [persistence.load_plan(plan_id) for plan_id in plan_ids]

            persistence.bind_lifecycle_plan_successor(loaded[0], loaded[1])
            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE operations SET status = 'running' WHERE operation_id = ?",
                    (plan_ids[1],),
                )

            # An exact replay is valid after the successor has progressed.
            persistence.bind_lifecycle_plan_successor(loaded[0], loaded[1])
            with self.assertRaisesRegex(
                PlanDriftError, "planned lifecycle operation"
            ):
                persistence.bind_lifecycle_plan_successor(loaded[1], loaded[2])

            with store.immediate_transaction() as connection:
                connection.execute(
                    "UPDATE operations SET status = 'running' WHERE operation_id = ?",
                    (plan_ids[3],),
                )
            with self.assertRaisesRegex(PlanDriftError, "unapplied plan"):
                persistence.bind_lifecycle_plan_successor(loaded[2], loaded[3])

            with store.read_transaction() as connection:
                rows = list(
                    connection.execute(
                        """
                        SELECT operation_id, status FROM operations
                        WHERE operation_id IN (?, ?, ?, ?)
                        ORDER BY operation_id
                        """,
                        tuple(plan_ids),
                    )
                )
                links = list(
                    connection.execute(
                        """
                        SELECT operation_id, value FROM operation_target_parameters
                        WHERE name = 'lifecycle.successor_plan_id'
                          AND operation_id IN (?, ?, ?, ?)
                        """,
                        tuple(plan_ids),
                    )
                )
        statuses = {str(row["operation_id"]): str(row["status"]) for row in rows}
        self.assertEqual(statuses[plan_ids[0]], "cancelled")
        self.assertEqual(statuses[plan_ids[1]], "running")
        self.assertEqual(statuses[plan_ids[2]], "planned")
        self.assertEqual(statuses[plan_ids[3]], "running")
        self.assertEqual(
            [(str(row["operation_id"]), str(row["value"])) for row in links],
            [(plan_ids[0], plan_ids[1])],
        )

    def test_retrying_confirmed_plan_resumes_successor_after_attention(self) -> None:
        plan = self._plan_repository()
        unchanged = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        interrupted = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )
        self.assertEqual(interrupted["status"], "needs_attention")
        self.assertNotEqual(interrupted["plan_id"], plan["plan_id"])
        self.adapter.add_container(self.A)

        resumed = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )

        self.assertEqual(resumed["status"], "succeeded")
        self.assertEqual(resumed["plan_id"], interrupted["plan_id"])
        self.assertEqual(
            self.adapter.effects,
            [("disable", self.A), ("stop", self.A)],
        )

    def test_resume_rejects_controller_change_that_precedes_observation(self) -> None:
        plan = self._plan_repository()
        unchanged = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        interrupted = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )
        self.assertEqual(interrupted["status"], "needs_attention")
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE control_bindings SET capability = 'changed-controller'
                    WHERE repo_id = ?
                    """,
                    (plan["repo_id"],),
                )
        self.adapter.add_container(self.A)

        with self.assertRaisesRegex(PlanDriftError, "resources changed"):
            self._handle(
                self._repository_remove_args(plan),
                observe_before_apply=self._callback(unchanged),
            )

        self.assertEqual(self.adapter.effects, [])

    def test_resume_allows_refresh_only_controller_generation_churn(self) -> None:
        plan = self._plan_repository()
        unchanged = self._sample(
            self._container(self.A, project=self.repo_a),
            self._container(self.B, project=self.repo_b),
        )
        interrupted = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )
        self.assertEqual(interrupted["status"], "needs_attention")
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE control_bindings SET generation = generation + 1
                    WHERE repo_id = ?
                    """,
                    (plan["repo_id"],),
                )
        self.adapter.add_container(self.A)

        resumed = self._handle(
            self._repository_remove_args(plan),
            observe_before_apply=self._callback(unchanged),
        )

        self.assertEqual(resumed["status"], "succeeded")
        self.assertEqual(
            self.adapter.effects,
            [("disable", self.A), ("stop", self.A)],
        )

    def test_apply_fails_closed_for_timeout_malformed_or_unavailable_observation(self) -> None:
        plan = self._plan_repository()
        args = self._repository_remove_args(plan)

        def timeout(_project: str, _agent: str):
            raise TimeoutError("bounded observer timed out")

        with self.assertRaisesRegex(TimeoutError, "timed out"):
            self._handle(args, observe_before_apply=timeout)
        with self.assertRaisesRegex(RuntimeError, "not a fresh successful"):
            self._handle(
                args,
                observe_before_apply=lambda project, agent: {
                    "status": "completed",
                    "observed": True,
                    "joined": False,
                    "snapshot_id": "missing-snapshot",
                    "host_id": "missing-host",
                    "observer_domain": FULL_DOCKER_OBSERVER_DOMAIN,
                    "material_fingerprint": "sha256:missing",
                    "completed_at": utc_timestamp(),
                    "max_age_seconds": 300,
                    "request": {"project": project, "agent": agent},
                },
            )
        with self.assertRaisesRegex(RuntimeError, "Docker is unavailable"):
            self._handle(
                args,
                observe_before_apply=self._callback(self._sample(available=False)),
            )
        self.assertEqual(self.adapter.effects, [])

    def _standalone_exact(self) -> ExactResourceRef:
        with AccountStore.open_default(self.home) as store:
            inventory = store.inventory_v2()
            row = next(
                item
                for item in inventory["unassigned_resources"]
                if item["resource_kind"] == "container"
            )
            return SQLiteLifecyclePersistence(store).resolve_standalone_resource(
                ResourceKind(str(row["resource_kind"])),
                str(row["resource_id"]),
                str(row["control_binding_id"]),
            )

    def _plan_standalone(self) -> tuple[dict[str, object], dict[str, object]]:
        sample = self._sample(self._container(self.C))
        self._commit_observation(sample)
        exact = self._standalone_exact()
        args = _parser().parse_args(
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                exact.kind.value,
                "--resource-id",
                exact.resource_id,
                "--immutable-fingerprint",
                exact.immutable_fingerprint,
                "--control-binding-id",
                exact.control_binding_id,
                "--ownership-fingerprint",
                exact.ownership_fingerprint,
                "--request-project",
                str(self.request_repo),
                "--agent",
                "test-agent",
                "--reason",
                "retire standalone C",
            ]
        )
        return self._handle(args, observe_before_plan=self._callback(sample)), sample

    def test_standalone_plan_rejects_controller_change_during_observation(self) -> None:
        sample = self._sample(self._container(self.C))
        self._commit_observation(sample)
        exact = self._standalone_exact()
        args = _parser().parse_args(
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                exact.kind.value,
                "--resource-id",
                exact.resource_id,
                "--immutable-fingerprint",
                exact.immutable_fingerprint,
                "--control-binding-id",
                exact.control_binding_id,
                "--ownership-fingerprint",
                exact.ownership_fingerprint,
                "--request-project",
                str(self.request_repo),
                "--agent",
                "test-agent",
                "--reason",
                "reject changed standalone controller",
            ]
        )
        observe = self._callback(sample)

        def changed_controller(project: str, agent: str) -> dict[str, object]:
            result = observe(project, agent)
            with AccountStore.open_default(self.home) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE control_bindings
                        SET capability = 'changed-controller',
                            generation = generation + 1, updated_at = ?
                        WHERE binding_id = ?
                        """,
                        (utc_timestamp(), exact.control_binding_id),
                    )
            return result

        with self.assertRaisesRegex(
            PlanDriftError, "standalone resource changed"
        ):
            self._handle(args, observe_before_plan=changed_controller)
        with AccountStore.open_default(self.home) as store:
            planned = store.connection.execute(
                """
                SELECT COUNT(*) FROM operations
                WHERE kind = 'standalone_resource_retirement'
                """
            ).fetchone()[0]
        self.assertEqual(planned, 0)
        self.assertEqual(self.adapter.effects, [])

    def test_standalone_plan_rejects_native_identity_change_during_observation(self) -> None:
        sample = self._sample(self._container(self.C))
        self._commit_observation(sample)
        exact = self._standalone_exact()
        args = _parser().parse_args(
            [
                "resource",
                "plan-retire",
                "--resource-kind",
                exact.kind.value,
                "--resource-id",
                exact.resource_id,
                "--immutable-fingerprint",
                exact.immutable_fingerprint,
                "--control-binding-id",
                exact.control_binding_id,
                "--ownership-fingerprint",
                exact.ownership_fingerprint,
                "--request-project",
                str(self.request_repo),
                "--agent",
                "test-agent",
                "--reason",
                "reject changed standalone native identity",
            ]
        )
        observe = self._callback(sample)

        def changed_native_identity(project: str, agent: str) -> dict[str, object]:
            result = observe(project, agent)
            with AccountStore.open_default(self.home) as store:
                with store.immediate_transaction() as connection:
                    connection.execute(
                        """
                        UPDATE docker_resources
                        SET full_container_id = ?, updated_at = ?
                        WHERE docker_resource_id = ?
                        """,
                        ("d" * 64, utc_timestamp(), exact.resource_id),
                    )
            return result

        with self.assertRaisesRegex(
            PlanDriftError, "standalone resource changed"
        ):
            self._handle(args, observe_before_plan=changed_native_identity)
        with AccountStore.open_default(self.home) as store:
            planned = store.connection.execute(
                """
                SELECT COUNT(*) FROM operations
                WHERE kind = 'standalone_resource_retirement'
                """
            ).fetchone()[0]
        self.assertEqual(planned, 0)
        self.assertEqual(self.adapter.effects, [])

    def test_plan_identity_accepts_fresh_action_data_but_rejects_resource_change(self) -> None:
        sample = self._sample(self._container(self.C))
        self._commit_observation(sample)
        exact = self._standalone_exact()
        fresh_action_data = replace(
            exact,
            allocations=(
                AllocationRef(
                    "fresh-lease",
                    AllocationKind.LEASE,
                    "sha256:" + "7" * 64,
                ),
            ),
        )

        _require_plan_target_identity_unchanged(exact, fresh_action_data)
        with self.assertRaisesRegex(
            PlanDriftError, "standalone resource changed"
        ):
            _require_target_semantically_unchanged(exact, fresh_action_data)
        with self.assertRaisesRegex(
            PlanDriftError, "standalone resource changed"
        ):
            _require_plan_target_identity_unchanged(
                exact,
                replace(exact, resource_id="replacement-resource"),
            )

    def _resource_retire_args(self, plan: dict[str, object]) -> argparse.Namespace:
        target = plan["targets"][0]
        return _parser().parse_args(
            [
                "resource",
                "retire",
                "--resource-kind",
                str(target["kind"]),
                "--resource-id",
                str(target["host_resource_id"]),
                "--immutable-fingerprint",
                str(target["immutable_fingerprint"]),
                "--control-binding-id",
                str(target["control_binding_id"]),
                "--ownership-fingerprint",
                str(target["ownership_fingerprint"]),
                "--request-project",
                str(self.request_repo),
                "--agent",
                "test-agent",
                "--plan-id",
                str(plan["plan_id"]),
                "--plan-fingerprint",
                str(plan["fingerprint"]),
            ]
        )

    def test_standalone_attachment_drift_is_rejected_before_host_effects(self) -> None:
        plan, _sample = self._plan_standalone()
        attached = self._sample(self._container(self.C, project=self.request_repo))
        with self.assertRaisesRegex(LifecycleError, "active unassigned"):
            self._handle(
                self._resource_retire_args(plan),
                observe_before_apply=self._callback(attached),
            )
        self.assertEqual(self.adapter.effects, [])

    def test_standalone_retire_replans_after_identical_fresh_observation(self) -> None:
        plan, sample = self._plan_standalone()
        self.adapter.add_container(self.C)
        result = self._handle(
            self._resource_retire_args(plan),
            observe_before_apply=self._callback(sample),
        )
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["hidden"])
        self.assertNotEqual(result["plan_id"], plan["plan_id"])
        self.assertEqual(
            self.adapter.effects,
            [("disable", self.C), ("stop", self.C)],
        )

        repeated = self._handle(
            self._resource_retire_args(plan),
            observe_before_apply=lambda *_args: self.fail(
                "completed retirement successor retry must not observe"
            ),
        )
        self.assertEqual(repeated["status"], "already_complete")
        self.assertEqual(repeated["plan_id"], result["plan_id"])
        self.assertEqual(
            self.adapter.effects,
            [("disable", self.C), ("stop", self.C)],
        )

    def test_expired_broker_profile_cannot_list_removed_repositories(self) -> None:
        repository = BrokerRepositoryProfile(
            canonical_root=str(self.repo_a),
            repo_id="repo-expired",
            generation=1,
            server_ids={},
            container_ids={},
            compose_definition_id=None,
        )
        profile = BrokerClientProfile(
            service=BrokerServiceProfile(
                socket_path=self.root / "broker.sock",
                service_uid=0,
                socket_gid=0,
                socket_mode=0o660,
                database_generation="generation-expired",
            ),
            client_uid=0,
            account_id="account-expired",
            issued_at=utc_timestamp(),
            valid_until_epoch=0,
            repositories={str(self.repo_a): repository},
        )
        args = _parser().parse_args(["repository", "list-removed"])
        with mock.patch(
            "devcoordinator.lifecycle_cli.load_broker_profile", return_value=profile
        ), self.assertRaisesRegex(BrokerProfileError, "expired"):
            handle_lifecycle_cli(
                args,
                coordinator_home=self.home,
                canonical_project=lambda value: str(Path(value).resolve()),
                bootstrap_legacy_import=lambda _store: {},
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
