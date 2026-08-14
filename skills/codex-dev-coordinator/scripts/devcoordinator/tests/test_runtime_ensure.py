"""Focused contracts for broker-owned idempotent runtime ensure."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator.broker import (  # noqa: E402
    BrokerError,
    BrokerOperation,
    BrokerRequest,
)
from devcoordinator import broker_backend as broker_backend_module  # noqa: E402
from devcoordinator.runtime_ensure import (  # noqa: E402
    RUNTIME_ENSURE_RESULT_MAX_BYTES,
    build_runtime_ensure_result,
    decide_runtime_ensure,
)
from devcoordinator.store import CoordinatorStore, utc_timestamp  # noqa: E402
from devcoordinator.tests.test_broker import (  # noqa: E402
    ACCOUNT_ID,
    CONTAINER_ID,
    DATABASE_ID,
    HOST_ID,
    PROJECT_ID,
    SERVER_ID,
    peer_for,
    request_for,
    seed_postgres_database,
)
from devcoordinator.tests import (  # noqa: E402
    test_broker_runtime as broker_runtime_tests,
)


def ensure_arguments(
    *,
    desired_state: str = "ready",
    target_kind: str = "docker",
    temporary_repo_id: str | None = None,
) -> dict[str, object]:
    return {
        "agent": "runtime-ensure-test-agent",
        "root_repo_id": PROJECT_ID,
        "temporary_repo_id": temporary_repo_id,
        "target_kind": target_kind,
        "desired_state": desired_state,
    }


class RuntimeEnsureContractTests(unittest.TestCase):
    def test_wire_is_exact_and_rejects_ttl_or_lifecycle_options(self) -> None:
        request = request_for(
            BrokerOperation.RUNTIME_ENSURE,
            resource_id=CONTAINER_ID,
            arguments=ensure_arguments(),
        )
        self.assertEqual(request.arguments, ensure_arguments())

        for field, value in (
            ("ttl_seconds", None),
            ("kill_after_run", False),
            ("action", "start"),
            ("purpose", "development"),
            ("argv", ["forbidden"]),
        ):
            with self.subTest(field=field), self.assertRaises(BrokerError) as raised:
                request_for(
                    BrokerOperation.RUNTIME_ENSURE,
                    resource_id=CONTAINER_ID,
                    arguments={**ensure_arguments(), field: value},
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")

        for desired_state in ("running", "unknown", ""):
            with self.subTest(desired_state=desired_state), self.assertRaises(
                BrokerError
            ) as raised:
                request_for(
                    BrokerOperation.RUNTIME_ENSURE,
                    resource_id=CONTAINER_ID,
                    arguments=ensure_arguments(desired_state=desired_state),
                )
            self.assertEqual(raised.exception.code, "invalid_arguments")

    def test_decision_and_result_are_path_free_and_bounded(self) -> None:
        observation = {
            "exact": True,
            "resource_kind": "docker",
            "resource_id": CONTAINER_ID,
            "lifecycle": "stopped",
        }
        decision = decide_runtime_ensure(
            observation, desired_state="stopped", family_classified=True
        )
        result = build_runtime_ensure_result(
            operation_id="33333333-3333-4333-8333-333333333333",
            repository_id=PROJECT_ID,
            repository_generation=0,
            resource_kind="docker",
            resource_id=CONTAINER_ID,
            desired_state="stopped",
            decision=decision,
            mutation_performed=False,
            terminal_observation=observation,
            snapshot_id="44444444-4444-4444-8444-444444444444",
            proof_source="broker_host_observation",
        )
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), RUNTIME_ENSURE_RESULT_MAX_BYTES)
        self.assertNotIn(b"/repos/", encoded)
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["classification"], "already_stopped")

    def test_unknown_and_unhealthy_targets_never_select_a_mutation(self) -> None:
        cases = (
            (
                {
                    "exact": False,
                    "resource_kind": "docker",
                    "lifecycle": "stopped",
                },
                "target_unknown",
            ),
            (
                {
                    "exact": True,
                    "resource_kind": "docker",
                    "lifecycle": "running",
                    "health": "unhealthy",
                },
                "target_unhealthy",
            ),
            (
                {
                    "exact": True,
                    "resource_kind": "service",
                    "lifecycle": "stopped",
                    "breaker_state": "tripped",
                },
                "target_unhealthy",
            ),
            (
                {
                    "exact": True,
                    "resource_kind": "service",
                    "lifecycle": "unobserved",
                    "pid": 4242,
                    "listener_observable": None,
                },
                "target_unknown",
            ),
            (
                {
                    "exact": True,
                    "resource_kind": "service",
                    "lifecycle": "unobserved",
                    "pid": None,
                    "listener_observable": True,
                },
                "target_unknown",
            ),
        )
        for observation, reason in cases:
            with self.subTest(reason=reason, observation=observation):
                decision = decide_runtime_ensure(
                    observation,
                    desired_state="ready",
                    family_classified=True,
                )
                self.assertTrue(decision.attention_required)
                self.assertIsNone(decision.action)
                self.assertEqual(decision.reason, reason)

    def test_exact_never_started_service_can_be_bootstrapped_to_ready(self) -> None:
        decision = decide_runtime_ensure(
            {
                "exact": True,
                "resource_kind": "service",
                "resource_id": SERVER_ID,
                "lifecycle": "unobserved",
                "health_classification": "unobserved",
                "pid": None,
                "listener_observable": None,
                "sampled_at": "2026-08-12T07:44:31Z",
            },
            desired_state="ready",
            family_classified=True,
        )

        self.assertEqual(decision.observed_state, "stopped")
        self.assertEqual(decision.action, "start")
        self.assertEqual(decision.classification, "mutation_required")

    def test_database_terminal_mismatch_preserves_probe_and_lifecycle_cause(self) -> None:
        before = {
            "exact": True,
            "resource_kind": "database_stack",
            "lifecycle": "stopped",
            "docker_lifecycle": "stopped",
            "database_available": False,
        }
        decision = decide_runtime_ensure(
            before, desired_state="ready", family_classified=True
        )
        terminal = {
            **before,
            "lifecycle": "running",
            "docker_lifecycle": "running",
        }

        result = build_runtime_ensure_result(
            operation_id="35353535-3535-4353-8353-353535353535",
            repository_id=PROJECT_ID,
            repository_generation=0,
            resource_kind="database_stack",
            resource_id=DATABASE_ID,
            desired_state="ready",
            decision=decision,
            mutation_performed=True,
            terminal_observation=terminal,
            snapshot_id="45454545-4545-4454-8454-454545454545",
            proof_source="broker_host_observation",
        )

        self.assertEqual(
            result["attention_reason"], "database_probe_unavailable"
        )
        self.assertEqual(result["terminal_proof"]["lifecycle"], "running")
        self.assertFalse(result["terminal_proof"]["database_available"])


class RuntimeEnsureBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = broker_runtime_tests.BrokerRuntimeTests(
            "test_authorized_status_returns_concise_rich_repository_report"
        )
        self.fixture.setUp()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _request(
        self,
        *,
        desired_state: str = "ready",
        target_kind: str = "docker",
        resource_id: str = CONTAINER_ID,
        operation_id: str | None = None,
        repository_generation: int = 0,
    ) -> BrokerRequest:
        return BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=PROJECT_ID,
            repository_generation=repository_generation,
            resource_id=resource_id,
            operation=BrokerOperation.RUNTIME_ENSURE,
            arguments=ensure_arguments(
                desired_state=desired_state,
                target_kind=target_kind,
            ),
            operation_id=operation_id,
            authority_generation=self.fixture.authority_generation,
        )

    def _reply(
        self,
        *,
        request: BrokerRequest,
        service=None,
    ) -> dict[str, object]:
        return (service or self.fixture._service()).reply_for_document(
            peer_for(), request.to_wire()
        )

    def _follow(self, operation_id: str) -> dict[str, object]:
        request = BrokerRequest.create(
            account_id=ACCOUNT_ID,
            project_id=PROJECT_ID,
            repository_generation=0,
            resource_id=PROJECT_ID,
            operation=BrokerOperation.OPERATION_FOLLOW,
            arguments={"operation_id": operation_id},
            authority_generation=self.fixture.authority_generation,
        )
        return self.fixture._service().reply_for_document(
            peer_for(), request.to_wire()
        )

    def test_stopped_to_ready_mutates_once_and_returns_terminal_proof(self) -> None:
        request = self._request(
            operation_id="11111111-1111-4111-8111-111111111111"
        )

        reply = self._reply(request=request)

        self.assertTrue(reply["ok"], reply)
        result = reply["result"]
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["classification"], "ensured_ready")
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["action"], "start")
        self.assertEqual(result["terminal_proof"]["observed_state"], "ready")
        self.assertTrue(result["terminal_proof"]["certain"])
        self.assertEqual([call[0] for call in self.fixture.actions.calls], ["start"])
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), RUNTIME_ENSURE_RESULT_MAX_BYTES)
        self.assertNotIn(b"/repos/", encoded)

    def test_already_stopped_is_durable_noop_replay_and_conflict_safe(self) -> None:
        operation_id = "22222222-2222-4222-8222-222222222222"
        request = self._request(
            desired_state="stopped", operation_id=operation_id
        )

        first = self._reply(request=request)
        replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first, replay)
        self.assertEqual(first["result"]["classification"], "already_stopped")
        self.assertFalse(first["result"]["mutation_performed"])
        self.assertEqual(self.fixture.actions.calls, [])

        conflict = self._reply(
            request=self._request(
                desired_state="ready", operation_id=operation_id
            )
        )
        self.assertFalse(conflict["ok"], conflict)
        self.assertEqual(conflict["error"]["code"], "operation_id_conflict")
        self.assertEqual(self.fixture.actions.calls, [])

    def test_running_to_stopped_invokes_only_stop(self) -> None:

        def observer(store: CoordinatorStore) -> dict[str, object]:
            lifecycle = "running" if not self.fixture.actions.calls else None
            return self.fixture._runtime_observer(store, lifecycle=lifecycle)

        service = self.fixture._service(observer=observer)
        reply = self._reply(
            request=self._request(
                desired_state="stopped",
                operation_id="55555555-5555-4555-8555-555555555555",
            ),
            service=service,
        )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_stopped")
        self.assertEqual([call[0] for call in self.fixture.actions.calls], ["stop"])

    def test_database_binding_uses_exact_container_and_database_readiness(
        self,
    ) -> None:
        seed_postgres_database(self.fixture.persistence)

        def observer(store: CoordinatorStore) -> dict[str, object]:
            started = bool(self.fixture.actions.calls)
            return self.fixture._runtime_observer(
                store,
                lifecycle="running" if started else "stopped",
                database_available=True if started else False,
            )

        reply = self._reply(
            request=self._request(
                target_kind="database_stack",
                resource_id=DATABASE_ID,
                operation_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ),
            service=self.fixture._service(observer=observer),
        )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_ready")
        self.assertEqual(
            reply["result"]["resource"],
            {"kind": "database_stack", "id": DATABASE_ID},
        )
        self.assertEqual(
            self.fixture.actions.calls,
            [("start", CONTAINER_ID, "a" * 64)],
        )

    def test_database_start_waits_for_fresh_readiness_convergence(self) -> None:
        seed_postgres_database(self.fixture.persistence)
        after_start_observations = 0

        def observer(store: CoordinatorStore) -> dict[str, object]:
            nonlocal after_start_observations
            started = bool(self.fixture.actions.calls)
            if started:
                after_start_observations += 1
            ready = started and after_start_observations >= 3
            return self.fixture._runtime_observer(
                store,
                lifecycle="running" if started else "stopped",
                database_available=ready,
            )

        with mock.patch.object(broker_backend_module.time, "sleep") as sleep:
            reply = self._reply(
                request=self._request(
                    target_kind="database_stack",
                    resource_id=DATABASE_ID,
                    operation_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                ),
                service=self.fixture._service(observer=observer),
            )

        self.assertTrue(reply["result"]["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_ready")
        self.assertGreaterEqual(after_start_observations, 3)
        self.assertGreaterEqual(sleep.call_count, 2)
        self.assertEqual(len(self.fixture.actions.calls), 1)

    def test_unclassified_family_requires_attention_without_host_mutation(self) -> None:
        now = utc_timestamp()
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO unassigned_resources(
                        unassigned_id, host_id, resource_kind, resource_id,
                        display_name, reason_code, status, created_at, updated_at
                    ) VALUES ('ensure-unassigned', ?, 'process',
                              'ensure-orphan', 'orphan', 'name_only',
                              'active', ?, ?)
                    """,
                    (HOST_ID, now, now),
                )

        reply = self._reply(
            request=self._request(
                operation_id="66666666-6666-4666-8666-666666666666"
            )
        )

        self.assertTrue(reply["ok"], reply)
        self.assertFalse(reply["result"]["ok"])
        self.assertEqual(reply["result"]["classification"], "attention_required")
        self.assertEqual(
            reply["result"]["attention_reason"],
            "repository_family_unclassified",
        )
        self.assertFalse(reply["result"]["mutation_performed"])
        self.assertEqual(self.fixture.actions.calls, [])
        followed = self._follow(
            "66666666-6666-4666-8666-666666666666"
        )
        self.assertEqual(followed["result"]["status"], "needs_attention")
        self.assertEqual(followed["result"]["next_transition"], "reconcile")

    def test_invocation_error_reconciles_to_exact_ready_state(
        self,
    ) -> None:
        operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = self._request(operation_id=operation_id)

        def fail_after_invocation(target):
            self.fixture.actions.calls.append(
                ("start", target.docker_resource_id, target.full_container_id)
            )
            raise RuntimeError("injected uncertain host boundary")

        with mock.patch.object(
            self.fixture.actions,
            "docker_start",
            side_effect=fail_after_invocation,
        ):
            first = self._reply(request=request)
            replay = self._reply(request=request)

        self.assertTrue(first["ok"], first)
        self.assertEqual(first, replay)
        result = first["result"]
        self.assertTrue(result["ok"])
        self.assertEqual(result["classification"], "ensured_ready")
        self.assertTrue(result["mutation_performed"])
        self.assertTrue(result["terminal_proof"]["certain"])
        self.assertEqual(len(self.fixture.actions.calls), 1)

        followed = self._follow(operation_id)
        self.assertTrue(followed["ok"], followed)
        projection = followed["result"]
        self.assertEqual(projection["status"], "succeeded")
        self.assertEqual(projection["outcome_certainty"], "certain")

    def test_invoked_outcome_stays_uncertain_when_reconciliation_is_unavailable(
        self,
    ) -> None:
        operation_id = "abababab-abab-4bab-8bab-abababababab"
        request = self._request(operation_id=operation_id)

        def fail_after_invocation(target):
            self.fixture.actions.calls.append(
                ("start", target.docker_resource_id, target.full_container_id)
            )
            raise RuntimeError("injected uncertain host boundary")

        def observer(store: CoordinatorStore) -> dict[str, object]:
            if self.fixture.actions.calls:
                raise RuntimeError("injected reconciliation outage")
            return self.fixture._runtime_observer(store, lifecycle="stopped")

        with mock.patch.object(
            self.fixture.actions,
            "docker_start",
            side_effect=fail_after_invocation,
        ):
            first = self._reply(
                request=request,
                service=self.fixture._service(observer=observer),
            )

        result = first["result"]
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "attention_required")
        self.assertEqual(
            result["attention_reason"], "mutation_outcome_uncertain"
        )
        self.assertTrue(result["mutation_performed"])
        self.assertFalse(result["terminal_proof"]["certain"])

        followed = self._follow(operation_id)
        self.assertEqual(followed["result"]["status"], "needs_attention")
        self.assertEqual(
            followed["result"]["outcome_certainty"], "uncertain"
        )

    def test_docker_isolation_preflight_rejection_is_certain_and_nonmutating(
        self,
    ) -> None:
        with mock.patch.object(
            self.fixture.actions,
            "docker_start",
            side_effect=broker_backend_module.BrokerBackendError(
                "project_isolation_mismatch",
                "container is outside its repository cgroup",
            ),
        ):
            reply = self._reply(
                request=self._request(
                    operation_id="acacacac-acac-4cac-8cac-acacacacacac"
                )
            )

        result = reply["result"]
        self.assertFalse(result["ok"])
        self.assertEqual(result["classification"], "attention_required")
        self.assertEqual(
            result["attention_reason"], "mutation_preflight_failed"
        )
        self.assertFalse(result["mutation_performed"])
        self.assertTrue(result["terminal_proof"]["certain"])

    def test_non_worker_service_is_ensured_by_exact_peer_uid_supervisor(self) -> None:
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                self.fixture._seed_stopped_worker_observation(connection)
        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(self, _store, **kwargs):
                calls.append(("init", kwargs["execution_uid"]))

            def start(self, **kwargs):
                calls.append(("start", kwargs["keep_alive"]))
                return {
                    "status": "running",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {"breaker_state": "armed"},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                request=self._request(
                    target_kind="service",
                    resource_id=SERVER_ID,
                    operation_id="77777777-7777-4777-8777-777777777777",
                )
            )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_ready")
        self.assertTrue(reply["result"]["mutation_performed"])
        self.assertEqual(
            calls,
            [("init", os.geteuid()), ("start", False)],
        )
        self.assertEqual(self.fixture.actions.calls, [])

    def test_never_started_service_is_ensured_by_exact_peer_uid_supervisor(
        self,
    ) -> None:
        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(self, _store, **kwargs):
                calls.append(("init", kwargs["execution_uid"]))

            def start(self, **kwargs):
                calls.append(("start", kwargs["keep_alive"]))
                return {
                    "status": "running",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {"breaker_state": "armed"},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                request=self._request(
                    target_kind="service",
                    resource_id=SERVER_ID,
                    operation_id="12121212-1212-4212-8212-121212121212",
                )
            )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_ready")
        self.assertTrue(reply["result"]["mutation_performed"])
        self.assertEqual(calls, [("init", os.geteuid()), ("start", False)])

    def test_network_service_ensure_rolls_back_when_listener_identity_is_wrong(
        self,
    ) -> None:
        with CoordinatorStore.open(
            self.fixture.persistence.database_path, expected_uid=os.geteuid()
        ) as store:
            with store.immediate_transaction() as connection:
                now = utc_timestamp()
                self.fixture._seed_stopped_worker_observation(connection)
                connection.execute(
                    """
                    INSERT INTO port_assignments(
                        assignment_id, host_id, repo_id, server_name, port,
                        status, generation, created_at, updated_at
                    ) VALUES ('ensure-network-web', ?, ?, 'web', 3112,
                              'active', 0, ?, ?)
                    """,
                    (HOST_ID, PROJECT_ID, now, now),
                )
        self.fixture.actions.listener_evidence = {
            "pid": 99_998,
            "process_identity": "linux:99998:unrelated",
            "cwd": "/repos/alpha",
            "canonical_root": "/repos/alpha",
            "port": 3112,
            "protocol": "tcp",
        }
        calls: list[str] = []

        class FakeController:
            def __init__(self, _store, **_kwargs):
                pass

            def start(self, **_kwargs):
                calls.append("start")
                return {
                    "status": "running",
                    "pid": 42_006,
                    "process_start_time": "ensure-listener-start",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {"breaker_state": "armed"},
                }

            def stop(self, **_kwargs):
                calls.append("stop")
                return {
                    "status": "stopped",
                    "health": {"ok": False, "classification": "stopped"},
                    "supervision": {"breaker_state": "armed"},
                    "terminal_process_proof": {
                        "certain": True,
                        "state": "absent",
                    },
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                request=self._request(
                    target_kind="service",
                    resource_id=SERVER_ID,
                    operation_id="78787878-7878-4878-8878-787878787878",
                )
            )

        self.assertTrue(reply["ok"], reply)
        self.assertFalse(reply["result"]["ok"])
        self.assertEqual(reply["result"]["classification"], "attention_required")
        self.assertEqual(
            reply["result"]["terminal_proof"]["observed_state"], "stopped"
        )
        self.assertTrue(reply["result"]["terminal_proof"]["certain"])
        self.assertEqual(calls, ["start", "stop"])

    def test_stale_repository_generation_is_rejected_before_observation(self) -> None:

        reply = self._reply(
            request=self._request(
                repository_generation=1,
                operation_id="88888888-8888-4888-8888-888888888888",
            )
        )

        self.assertFalse(reply["ok"], reply)
        self.assertEqual(reply["error"]["code"], "project_generation_stale")
        self.assertEqual(self.fixture.actions.calls, [])

    def test_supervised_worker_start_does_not_rearm_or_replace_policy(self) -> None:
        self.fixture._prepare_worker_replacement()
        calls: list[tuple[object, ...]] = []

        class FakeController:
            def __init__(self, _store, **kwargs):
                calls.append(("init", kwargs["execution_uid"]))

            def start(self, **kwargs):
                calls.append(
                    (
                        "start",
                        kwargs["keep_alive"],
                        kwargs["crash_limit"],
                        kwargs["crash_window_seconds"],
                        kwargs["rearm"],
                    )
                )
                return {
                    "status": "running",
                    "health": {
                        "ok": True,
                        "classification": "supervised_process_running",
                    },
                    "supervision": {"breaker_state": "armed"},
                }

        with mock.patch.object(
            broker_backend_module, "WorkerController", FakeController
        ):
            reply = self._reply(
                request=self._request(
                    target_kind="service",
                    resource_id=SERVER_ID,
                    operation_id="99999999-9999-4999-8999-999999999999",
                )
            )

        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["classification"], "ensured_ready")
        self.assertEqual(
            calls,
            [("init", os.geteuid()), ("start", None, None, None, False)],
        )
        encoded = json.dumps(reply["result"], sort_keys=True).encode("utf-8")
        self.assertNotIn(str(self.fixture.root).encode("utf-8"), encoded)


if __name__ == "__main__":
    unittest.main()
