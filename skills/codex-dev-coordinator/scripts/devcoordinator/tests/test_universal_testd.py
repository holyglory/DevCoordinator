from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from devcoordinator.tests.test_universal_test_plane import MutableClock, plan
from devcoordinator.universal_test_contract import SourceMode
from devcoordinator.universal_test_scheduler import (
    HostMemorySnapshot,
    WeightedFairScheduler,
)
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_spool import (
    AttemptExitEnvelope,
    AttemptResultChunkEnvelope,
    DurableAttemptSpool,
)
from devcoordinator.universal_test_store import (
    AttemptConclusion,
    TargetResources,
    UniversalTestStore,
)
from devcoordinator.universal_test_transport import (
    TEST_HEALTH,
    TEST_PLAN_REGISTER,
    TestPlaneDispatcher,
)
from devcoordinator.universal_testd import (
    BrokerLaunchTicket,
    LiveSourceChanged,
    RunnerHandle,
    RunnerObservation,
    TestdEngine,
    TestdLaunchAdapter,
)
from devcoordinator.universal_test_broker import (
    BrokerConnection,
    CoordinatorRuntimeRequestSubmitter,
)
from devcoordinator.universal_testd_main import build_parser, inherited_systemd_listener, main


def operation_id() -> str:
    return str(uuid.uuid4())


class FakeTicketIssuer:
    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock
        self.mutate = None
        self.prelaunch_source_fingerprint = None
        self.observed_source_fingerprint = None
        self.observe_error = None
        self.issue_delay_seconds = 0.0
        self.launch_deadlines = []

    def issue(self, *, candidate, lease, plan_document, launch_deadline):
        self.launch_deadlines.append(launch_deadline)
        self.clock.advance(self.issue_delay_seconds)
        if self.prelaunch_source_fingerprint is not None:
            raise LiveSourceChanged(self.prelaunch_source_fingerprint)
        source = plan_document["source"]
        values = {
            "ticket_id": "ticket-" + lease.attempt_id,
            "attempt_id": lease.attempt_id,
            "target_id": candidate.target_id,
            "run_id": candidate.run_id,
            "repository_id": candidate.repository_id,
            "owner_uid": candidate.owner_uid,
            "generation": lease.generation,
            "root_repo": source["original_root"],
            "temporary_repo": source["temporary_root"],
            "argv": ["/usr/bin/python3", "-m", "pytest", "tests"],
            "cwd": ".",
            "environment": {"PYTHONUNBUFFERED": "1"},
            "intent": plan_document["intent"],
            "network": "none",
            "ttl_seconds": 300,
            "cpu_millis": candidate.cpu_millis,
            "memory_mib": candidate.memory_mib,
            "pids": candidate.pids,
            "worktree_key": candidate.worktree_key,
            "issued_at": self.clock(),
            "expires_at": self.clock() + 60,
        }
        if self.mutate is not None:
            self.mutate(values)
        return BrokerLaunchTicket.issue(**values)

    def observe_live_source(
        self, *, repository_id, owner_uid, plan_document
    ):
        del repository_id, owner_uid
        if self.observe_error is not None:
            raise self.observe_error
        return (
            self.observed_source_fingerprint
            or plan_document["source"]["content_fingerprint"]
        )


class FakeLauncher:
    def __init__(self, *, observations=None) -> None:
        self.requests = []
        self.observations = {} if observations is None else observations
        self.cancelled = []
        self.recoveries = []
        self.fail_launch = False

    def launch(self, request):
        if self.fail_launch:
            raise RuntimeError("injected launch failure")
        self.requests.append(request)
        handle = RunnerHandle(
            runtime_id="runtime-" + request.ticket.attempt_id,
            launch_ack_id="ack-" + request.ticket.attempt_id,
        )
        self.observations[handle.runtime_id] = RunnerObservation("running")
        return handle

    def observe(self, handle):
        observed = self.observations[handle.runtime_id]
        if isinstance(observed, list):
            return observed.pop(0)
        return observed

    def recover(self, handle, *, context):
        if handle.runtime_id not in self.observations:
            self.observations[handle.runtime_id] = RunnerObservation("running")
        self.recoveries.append((handle, context))

    def cancel(self, handle, *, reason):
        self.cancelled.append((handle.runtime_id, reason))
        return True


class EngineFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = MutableClock()
        root = Path(self.temporary.name)
        self.store = UniversalTestStore.create(root / "tests.sqlite3", clock=self.clock)
        self.spool = DurableAttemptSpool.create(root / "spool")
        self.issuer = FakeTicketIssuer(self.clock)
        self.launcher = FakeLauncher()
        self.scheduler = WeightedFairScheduler(
            memory_probe=lambda: HostMemorySnapshot(
                total_mib=65_536,
                available_mib=65_536,
                observed_at=self.clock(),
            )
        )
        self.engine = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=self.launcher,
            spool=self.spool,
            clock=self.clock,
        )

    def submit_live(self, *, launch_timeout_seconds: int = 300):
        selected = plan(
            mode=SourceMode.LIVE,
            fingerprint=uuid.uuid4().hex * 2,
            launch_timeout_seconds=launch_timeout_seconds,
        )
        return self.store.submit_plan(
            selected,
            operation_id=operation_id(),
            actor="codex:testd",
            owner_uid=1001,
            target_resources={
                "lint": TargetResources(
                    cpu_millis=1_000,
                    memory_mib=1_024,
                    pids=128,
                    worktree_key="/home/example/worktree",
                ),
                "unit": TargetResources(
                    cpu_millis=1_000,
                    memory_mib=1_024,
                    pids=128,
                    worktree_key="/home/example/worktree",
                ),
            },
        )


class TestdEngineTests(EngineFixture):
    def test_store_discards_declared_capacity_values(self) -> None:
        selected = plan(mode=SourceMode.LIVE, fingerprint=uuid.uuid4().hex * 2)
        submitted = self.store.submit_plan(
            selected,
            operation_id=operation_id(),
            actor="codex:testd",
            owner_uid=1001,
            target_resources={
                name: TargetResources(
                    cpu_millis=-1,
                    memory_mib=1_000_000_000,
                    pids=0,
                    worktree_key="/home/example/worktree",
                )
                for name in selected.selected_targets
            },
        )

        candidate = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == submitted.run_id
        )
        self.assertEqual(candidate.cpu_millis, TargetResources.cpu_millis)
        self.assertEqual(candidate.memory_mib, TargetResources.memory_mib)
        self.assertEqual(candidate.pids, TargetResources.pids)

    def test_host_loopback_ticket_for_nonmanual_plan_fails_closed(self) -> None:
        submitted = self.submit_live()
        self.issuer.mutate = lambda values: values.update(
            {"network": "host-loopback"}
        )

        result = self.engine.schedule(launch_batch=1)

        self.assertEqual(result["launched_target_ids"], [])
        self.assertEqual(
            result["launch_failures"][0]["error_type"],
            "TestStoreContractError",
        )
        self.assertEqual(
            result["launch_failures"][0]["error_code"],
            "TestStoreContractError",
        )
        self.assertEqual(result["launch_failures"][0]["stage"], "launch")
        self.assertEqual(self.launcher.requests, [])
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        failures = self.store.failures(run_id=submitted.run_id)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["classification"], "infrastructure_failure")
        self.assertEqual(failures[0]["location"], "launch/descriptor")
        self.assertIn("host-loopback", failures[0]["message"])
        metrics = self.store.run_metrics(submitted.run_id)
        self.assertEqual(metrics["failure_record_count"], 1)
        self.assertEqual(metrics["artifact_count"], 0)

    def test_prelaunch_live_replan_change_is_superseded_not_infrastructure(self) -> None:
        submitted = self.submit_live()
        self.issuer.prelaunch_source_fingerprint = "b" * 64
        result = self.engine.schedule(launch_batch=1)
        self.assertEqual(result["launched_target_ids"], [])
        self.assertEqual(
            result["launch_failures"][0]["error_type"], "LiveSourceChanged"
        )
        self.assertEqual(self.launcher.requests, [])
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "superseded")
        self.assertEqual(run["failure_classification"], "superseded")
        self.assertEqual(run["targets"][0]["state"], "superseded")

    def test_midrun_live_source_change_cancels_and_terminalizes_superseded(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        self.clock.advance(6)
        self.issuer.observed_source_fingerprint = "c" * 64
        heartbeat = self.engine.heartbeat()
        self.assertEqual(len(heartbeat["completed_attempt_ids"]), 1)
        self.assertEqual(heartbeat["failures"], [])
        self.assertEqual(len(self.launcher.cancelled), 1)
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "superseded")
        self.assertEqual(run["failure_classification"], "superseded")

    def test_short_live_run_is_rechecked_before_terminal_result_is_accepted(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        runtime_id = "runtime-" + request.ticket.attempt_id
        self.launcher.observations[runtime_id] = RunnerObservation(
            "exited",
            AttemptExitEnvelope(
                envelope_id="short-live-exit",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.SUCCEEDED,
                duration_seconds=0.1,
            ),
        )
        self.issuer.observed_source_fingerprint = "d" * 64

        heartbeat = self.engine.heartbeat()

        self.assertEqual(
            heartbeat["completed_attempt_ids"], [request.ticket.attempt_id]
        )
        self.assertEqual(heartbeat["failures"], [])
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "superseded")
        self.assertEqual(run["failure_classification"], "superseded")

    def test_terminal_live_result_waits_for_source_observer_recovery(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        runtime_id = "runtime-" + request.ticket.attempt_id
        self.launcher.observations[runtime_id] = RunnerObservation(
            "exited",
            AttemptExitEnvelope(
                envelope_id="observer-recovery-exit",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED,
                duration_seconds=0.1,
            ),
        )
        self.issuer.observe_error = RuntimeError("source helper unavailable")

        unavailable = self.engine.heartbeat()

        self.assertEqual(unavailable["completed_attempt_ids"], [])
        self.assertEqual(unavailable["failures"][0]["error_type"], "RuntimeError")
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "running")

        self.issuer.observe_error = None
        recovered = self.engine.heartbeat()
        self.assertEqual(
            recovered["completed_attempt_ids"], [request.ticket.attempt_id]
        )
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")

    def test_launch_request_is_exact_bounded_and_has_no_bearer_secrets(self) -> None:
        submitted = self.submit_live()
        result = self.engine.schedule(launch_batch=1)
        self.assertEqual(len(result["launched_target_ids"]), 1)
        request = self.launcher.requests[0]
        document = request.to_document()
        self.assertEqual(document["lifecycle"], {
            "purpose": "test",
            "ttl_seconds": 300,
            "launch_timeout_seconds": 300,
            "kill_after_run": True,
        })
        self.assertTrue(document["isolation"]["clean_environment"])
        self.assertEqual(document["isolation"]["cpu_millis"], 1_000)
        self.assertEqual(document["command"]["environment"], {"PYTHONUNBUFFERED": "1"})
        self.assertEqual(document["ticket"]["intent"], "change")
        self.assertEqual(document["ticket"]["credentials"], [])
        encoded = json.dumps(document)
        self.assertNotIn("lease_token", encoded)
        self.assertNotIn("ticket_token", encoded)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "running")

    def test_caller_launch_timeout_reaches_transient_runner_request(self) -> None:
        self.submit_live(launch_timeout_seconds=987)

        result = self.engine.schedule(launch_batch=1)

        self.assertEqual(len(result["launched_target_ids"]), 1)
        self.assertEqual(self.launcher.requests[0].launch_timeout_seconds, 987)
        self.assertEqual(
            self.launcher.requests[0].to_document()["lifecycle"][
                "launch_timeout_seconds"
            ],
            987,
        )

    def test_ticket_work_consumes_the_same_caller_launch_deadline(self) -> None:
        started_at = self.clock()
        self.issuer.issue_delay_seconds = 12
        self.submit_live(launch_timeout_seconds=90)

        result = self.engine.schedule(launch_batch=1)

        self.assertEqual(len(result["launched_target_ids"]), 1)
        self.assertEqual(self.issuer.launch_deadlines, [started_at + 90])
        self.assertEqual(self.launcher.requests[0].launch_timeout_seconds, 78)

    def test_pending_launch_lease_covers_deadline_then_shrinks_after_confirmation(self) -> None:
        class PendingLauncher(FakeLauncher):
            def __init__(self, clock: MutableClock) -> None:
                super().__init__()
                self.clock = clock

            def launch(self, request):
                self.requests.append(request)
                self.clock.advance(20)
                runtime_id = "runtime-" + request.ticket.attempt_id
                self.observations[runtime_id] = RunnerObservation(
                    "running", launch_confirmed=True
                )
                return RunnerHandle(
                    runtime_id=runtime_id,
                    launch_ack_id="ack-" + request.ticket.attempt_id,
                    launch_ticket_id="ticket-pending-lease",
                    launch_operation_id=str(uuid.uuid4()),
                    launch_timeout_seconds=request.launch_timeout_seconds,
                    launch_confirmed=False,
                )

        self.launcher = PendingLauncher(self.clock)
        self.engine.launcher = self.launcher
        launch_started_at = self.clock()
        self.submit_live(launch_timeout_seconds=3_600)

        result = self.engine.schedule(launch_batch=1)

        self.assertEqual(len(result["launched_target_ids"]), 1)
        attempt_id = self.launcher.requests[0].ticket.attempt_id
        pending = self.store.get_attempt(attempt_id)
        self.assertEqual(pending["state"], "leased")
        self.assertEqual(
            pending["lease_expires_at"],
            launch_started_at + 3_600 + 30,
        )

        heartbeat = self.engine.heartbeat()

        self.assertEqual(heartbeat["running_attempt_ids"], [attempt_id])
        confirmed = self.store.get_attempt(attempt_id)
        self.assertEqual(confirmed["state"], "running")
        self.assertEqual(confirmed["lease_expires_at"], self.clock() + 30)

    def test_declared_ticket_resources_do_not_gate_or_throttle_launch(self) -> None:
        submitted = self.submit_live()
        self.issuer.mutate = lambda values: values.update(
            cpu_millis=64_000,
            memory_mib=262_144,
            pids=32_768,
        )

        result = self.engine.schedule(launch_batch=1)

        self.assertEqual(len(result["launched_target_ids"]), 1)
        self.assertEqual(result["launch_failures"], [])
        self.assertEqual(len(self.launcher.requests), 1)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "running")

    def test_exact_worktree_remains_serialized_across_runs(self) -> None:
        self.submit_live()
        self.submit_live()
        self.engine.schedule(launch_batch=1)
        second = self.engine.schedule(launch_batch=4)
        reasons = {item["reason"] for item in second["rejected"]}
        self.assertIn("exact_worktree_busy", reasons)
        self.assertEqual(len(self.launcher.requests), 1)

    def test_just_launched_memory_commitment_survives_later_scheduler_tick(self) -> None:
        self.engine.scheduler = WeightedFairScheduler(
            memory_probe=lambda: HostMemorySnapshot(
                total_mib=8_192,
                available_mib=1_800,
                observed_at=self.clock(),
            )
        )
        for fingerprint in ("1" * 64, "2" * 64):
            self.store.submit_plan(
                plan(fingerprint=fingerprint),
                operation_id=operation_id(),
                actor="codex:testd",
                owner_uid=1001,
            )

        first = self.engine.schedule(launch_batch=1)
        self.assertEqual(len(first["launched_target_ids"]), 1)
        request = self.launcher.requests[0]
        runtime_id = "runtime-" + request.ticket.attempt_id
        self.launcher.observations[runtime_id] = RunnerObservation(
            state="running",
            current_memory_bytes=64 * 1024 * 1024,
        )
        self.engine.heartbeat()

        later = self.engine.schedule(launch_batch=1)

        self.assertEqual(later["launched_target_ids"], [])
        self.assertEqual(later["memory"]["active_memory_reservation_mib"], 448)
        self.assertIn("host_memory", {item["reason"] for item in later["rejected"]})
        allocation = self.store.active_allocations()[0]
        self.assertEqual(allocation["memory_commitment_mib"], 512)

    def test_mismatched_broker_ticket_fails_before_launcher(self) -> None:
        submitted = self.submit_live()
        self.issuer.mutate = lambda values: values.update(owner_uid=9999)
        with self.assertLogs(
            "devcoordinator.universal_testd", level="ERROR"
        ) as captured:
            result = self.engine.schedule(launch_batch=1)
        self.assertEqual(result["launched_target_ids"], [])
        self.assertEqual(result["launch_failures"][0]["error_type"], "TestStoreConflict")
        self.assertIn("test attempt launch failed", "\n".join(captured.output))
        self.assertEqual(self.launcher.requests, [])
        failed = self.store.get_run(submitted.run_id)
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["failure_classification"], "infrastructure_failure")
        failures = self.store.failures(run_id=submitted.run_id)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["location"], "launch/descriptor")
        self.assertIn("TestStoreConflict", failures[0]["message"])
        self.assertEqual(self.store.artifacts(run_id=submitted.run_id), ())

    def test_prelaunch_failure_replays_after_chunk_ingestion_recovers(self) -> None:
        submitted = self.submit_live()
        self.issuer.mutate = lambda values: values.update(owner_uid=9999)

        with (
            mock.patch.object(
                self.store,
                "append_result_chunk",
                side_effect=RuntimeError("injected result-store outage"),
            ),
            self.assertLogs("devcoordinator.universal_testd", level="ERROR"),
        ):
            self.engine.schedule(launch_batch=1)

        self.assertEqual(self.store.failures(run_id=submitted.run_id), ())
        self.assertNotEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        self.assertEqual(len(tuple(self.spool.result_pending.iterdir())), 1)
        self.assertEqual(len(tuple(self.spool.pending.iterdir())), 1)

        replay = self.engine.replay_spool()

        self.assertEqual(len(replay["result_chunks"]["imported_envelope_ids"]), 1)
        self.assertEqual(len(replay["imported_envelope_ids"]), 1)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        self.assertEqual(len(self.store.failures(run_id=submitted.run_id)), 1)

    def test_prelaunch_failure_replays_terminal_after_chunk_commit(self) -> None:
        submitted = self.submit_live()
        self.issuer.mutate = lambda values: values.update(owner_uid=9999)
        real_terminalize = self.store.terminalize_attempt

        with (
            mock.patch.object(
                self.store,
                "terminalize_attempt",
                side_effect=RuntimeError("injected terminal-store outage"),
            ),
            self.assertLogs("devcoordinator.universal_testd", level="ERROR"),
        ):
            self.engine.schedule(launch_batch=1)

        failures = self.store.failures(run_id=submitted.run_id)
        self.assertEqual(len(failures), 1)
        self.assertNotEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        self.assertEqual(len(tuple(self.spool.pending.iterdir())), 1)

        with mock.patch.object(
            self.store, "terminalize_attempt", wraps=real_terminalize
        ):
            replay = self.engine.replay_spool()

        self.assertEqual(len(replay["imported_envelope_ids"]), 1)
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "failed")
        self.assertEqual(len(self.store.failures(run_id=submitted.run_id)), 1)

    def test_restart_reconciles_terminal_prior_wave_with_queued_downstream(self) -> None:
        submitted = self.submit_live()
        lint = next(
            target
            for target in self.store.runnable_targets()
            if target.run_id == submitted.run_id and target.target_name == "lint"
        )
        lease = self.store.lease_target(
            lint.target_id,
            lease_owner="retired-testd",
            operation_id=operation_id(),
        )
        # Synthesize retained state written before run reconciliation was part
        # of terminalization: wave zero is terminal, wave one remains queued,
        # and there is no active attempt for either scheduler or reaper to see.
        with mock.patch.object(self.store, "_reconcile_run", return_value=None):
            self.store.terminalize_attempt(
                lease.attempt_id,
                generation=lease.generation,
                conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED,
                duration_seconds=0,
                operation_id=operation_id(),
            )
        retained = self.store.get_run(submitted.run_id)
        self.assertEqual(retained["state"], "running")
        self.assertEqual(
            [target["state"] for target in retained["targets"]],
            ["infrastructure_failed", "queued"],
        )
        self.assertEqual(self.store.runnable_targets(), ())

        TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=FakeLauncher(),
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )

        repaired = self.store.get_run(submitted.run_id)
        self.assertEqual(repaired["state"], "failed")
        self.assertEqual(
            repaired["failure_classification"], "infrastructure_failure"
        )
        self.assertEqual(
            [target["state"] for target in repaired["targets"]],
            ["infrastructure_failed", "cancelled"],
        )
        self.assertEqual(self.store.runnable_targets(), ())

    def test_restart_reconciliation_preserves_a_valid_queued_run(self) -> None:
        submitted = self.submit_live()

        TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=FakeLauncher(),
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )

        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "queued")
        self.assertEqual(
            [target.run_id for target in self.store.runnable_targets()],
            [submitted.run_id],
        )

    def test_heartbeat_and_cancel_use_injected_launcher(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        heartbeat = self.engine.heartbeat()
        self.assertEqual(len(heartbeat["running_attempt_ids"]), 1)
        cancelled = self.engine.cancel_run(
            run_id=submitted.run_id,
            actor="user@example.com",
            reason="manual cancellation",
            operation_id=operation_id(),
        )
        self.assertEqual(len(cancelled["cancelled_attempt_ids"]), 1)
        self.assertEqual(cancelled["unresolved_attempt_ids"], [])
        self.assertEqual(self.store.get_run(submitted.run_id)["state"], "cancelled")

    def test_durable_exit_replays_after_testd_crash(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        self.spool.append(
            AttemptExitEnvelope(
                envelope_id="exit-after-crash",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.TEST_FAILED,
                duration_seconds=2.5,
                peak_memory_bytes=96 * 1024 * 1024,
                cpu_seconds=1.75,
            )
        )
        replacement = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=FakeLauncher(),
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )
        replay = replacement.replay_spool()
        self.assertEqual(replay["imported_envelope_ids"], ["exit-after-crash"])
        failed = self.store.get_run(submitted.run_id)
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["failure_classification"], "test_failure")
        attempt = self.store.get_attempt(request.ticket.attempt_id)
        self.assertEqual(attempt["peak_memory_bytes"], 96 * 1024 * 1024)
        self.assertEqual(attempt["cpu_seconds"], 1.75)
        self.assertEqual(failed["usage"]["peak_memory_mib"], 96.0)
        self.assertEqual(failed["usage"]["cpu_seconds"], 1.75)

        followup = self.submit_live()
        learned = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == followup.run_id and item.target_name == "lint"
        )
        self.assertEqual(learned.memory_estimate_mib, 96)
        self.assertEqual(learned.memory_estimate_source, "learned_peak")
        self.assertEqual(learned.memory_sample_count, 1)

    def test_unavailable_usage_stays_null_and_does_not_poison_learning(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        self.spool.append(
            AttemptExitEnvelope(
                envelope_id="exit-without-usage",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.INFRASTRUCTURE_FAILED,
                duration_seconds=0.0,
            )
        )

        replay = self.engine.replay_spool()

        self.assertEqual(replay["imported_envelope_ids"], ["exit-without-usage"])
        attempt = self.store.get_attempt(request.ticket.attempt_id)
        self.assertIsNone(attempt["peak_memory_bytes"])
        self.assertIsNone(attempt["cpu_seconds"])
        failed = self.store.get_run(submitted.run_id)
        self.assertFalse(failed["usage"]["available"])
        self.assertIsNone(failed["usage"]["peak_memory_mib"])
        self.assertIsNone(failed["usage"]["cpu_seconds"])

        followup = self.submit_live()
        cold = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == followup.run_id and item.target_name == "lint"
        )
        self.assertEqual(cold.memory_estimate_source, "cold_start_default")
        self.assertEqual(cold.memory_sample_count, 0)

    def test_result_chunk_and_exit_replay_after_testd_crash(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        chunk = {
            "chunk_id": "chunk-after-crash",
            "chunk_index": 0,
            "cases": [
                {
                    "case_id": "case-after-crash",
                    "display_name": "survives restart",
                    "status": "passed",
                    "duration_seconds": 0.5,
                    "location": None,
                }
            ],
            "failures": [],
            "artifacts": [],
            "reporter_complete": True,
        }
        self.spool.append_result_chunk(
            AttemptResultChunkEnvelope(
                envelope_id="result-000000-after-crash",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                chunk=chunk,
            )
        )
        self.spool.append(
            AttemptExitEnvelope(
                envelope_id="exit-result-after-crash",
                attempt_id=request.ticket.attempt_id,
                generation=request.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.SUCCEEDED,
                duration_seconds=0.5,
                result_chunk_ids=("chunk-after-crash",),
            )
        )
        replacement = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=FakeLauncher(),
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )
        replay = replacement.replay_spool()
        self.assertEqual(
            replay["result_chunks"]["imported_envelope_ids"],
            ["result-000000-after-crash"],
        )
        self.assertEqual(replay["imported_envelope_ids"], ["exit-result-after-crash"])
        attempt = self.store.get_attempt(request.ticket.attempt_id)
        self.assertEqual(attempt["state"], "succeeded")
        self.assertEqual(attempt["passed_count"], 1)

    def test_runtime_exit_while_testd_is_absent_is_recovered_exactly_once(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        request = self.launcher.requests[0]
        runtime_id = "runtime-" + request.ticket.attempt_id
        chunk = {
            "chunk_id": "chunk-produced-without-testd",
            "chunk_index": 0,
            "cases": [
                {
                    "case_id": "case-produced-without-testd",
                    "display_name": "survives the absent collector window",
                    "status": "passed",
                    "duration_seconds": 0.25,
                    "location": None,
                }
            ],
            "failures": [],
            "artifacts": [],
            "reporter_complete": True,
        }
        # No TestdEngine observes this transition. The retained runtime reaches
        # result and exit while its original scheduler process is absent.
        self.launcher.observations[runtime_id] = [
            RunnerObservation("result", result_chunk=chunk),
            RunnerObservation(
                "exited",
                AttemptExitEnvelope(
                    envelope_id="exit-produced-without-testd",
                    attempt_id=request.ticket.attempt_id,
                    generation=request.ticket.generation,
                    operation_id=operation_id(),
                    conclusion=AttemptConclusion.SUCCEEDED,
                    duration_seconds=0.25,
                    result_chunk_ids=("chunk-produced-without-testd",),
                ),
            ),
        ]
        replacement_launcher = FakeLauncher(
            observations=self.launcher.observations
        )
        replacement = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=replacement_launcher,
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )

        self.assertEqual(len(replacement_launcher.recoveries), 1)
        first = replacement.heartbeat()
        second = replacement.heartbeat()
        terminal = self.store.get_attempt(request.ticket.attempt_id)
        terminal_operation_id = terminal["terminal_operation_id"]
        third = replacement.heartbeat()

        self.assertEqual(first["running_attempt_ids"], [request.ticket.attempt_id])
        self.assertEqual(second["completed_attempt_ids"], [request.ticket.attempt_id])
        self.assertEqual(third["completed_attempt_ids"], [])
        self.assertEqual(terminal["state"], "succeeded")
        self.assertEqual(terminal["passed_count"], 1)
        self.assertEqual(
            self.store.get_attempt(request.ticket.attempt_id)["terminal_operation_id"],
            terminal_operation_id,
        )
        self.assertEqual(replacement.spool.active_envelopes(), ())
        self.assertEqual(replacement.spool.pending_result_chunks(), ())
        self.assertEqual(replacement.spool.pending_envelopes(), ())

    def test_launched_attempt_is_abandoned_not_duplicated_after_lost_heartbeat(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        self.clock.advance(31)
        reaped = self.engine.reap()
        self.assertEqual(len(reaped["abandoned_attempt_ids"]), 1)
        self.assertEqual(reaped["requeued_attempt_ids"], [])
        self.assertEqual(reaped["lease_expired_before_launch_attempt_ids"], [])
        self.assertEqual(
            reaped["running_heartbeat_lost_attempt_ids"],
            reaped["abandoned_attempt_ids"],
        )
        self.assertEqual(
            reaped["outcomes"][0]["reason"], "running_heartbeat_lost"
        )
        run = self.store.get_run(submitted.run_id)
        self.assertEqual(run["state"], "abandoned")
        self.assertEqual(
            run["lease_expiry_evidence"]["events"][0]["reason"],
            "running_heartbeat_lost",
        )


class FakeSubmitter:
    def __init__(self) -> None:
        self.submitted = []
        self.prepared = None

    def prepare(self, document):
        self.submitted.append(document)
        self.prepared = {
            "runtime_id": "runtime-1",
            "launch_ack_id": "ack-1",
            "launch_ticket_id": "ticket-1",
            "launch_operation_id": str(uuid.uuid4()),
            "launch_timeout_seconds": document["lifecycle"][
                "launch_timeout_seconds"
            ],
            "launch_confirmed": False,
        }
        return dict(self.prepared)

    def launch_prepared(self, runtime_id):
        if self.prepared is None or runtime_id != self.prepared["runtime_id"]:
            raise AssertionError("prepared runtime identity changed")
        return {**self.prepared, "launch_confirmed": True}

    def submit(self, document):
        prepared = self.prepare(document)
        return self.launch_prepared(prepared["runtime_id"])

    def observe(self, runtime_id):
        return {
            "state": "running",
            "exit_envelope": None,
            "result_chunk": None,
            "current_memory_bytes": 96 * 1024 * 1024,
        }

    def recover(self, runtime_id, *, context):
        del runtime_id, context

    def cancel(self, runtime_id, *, reason):
        return {"cancelled": True}


class TestdLaunchAdapterTests(EngineFixture):
    def test_adapter_emits_request_without_calling_a_process_manager(self) -> None:
        submitter = FakeSubmitter()
        adapter = TestdLaunchAdapter(submitter)
        self.engine.launcher = adapter
        self.submit_live()
        self.engine.schedule(launch_batch=1)
        document = submitter.submitted[0]
        self.assertEqual(document["target"]["kind"], "test_attempt")
        self.assertTrue(document["lifecycle"]["kill_after_run"])
        self.assertNotIn("lease_token", json.dumps(document))
        self.assertNotIn("ticket_token", json.dumps(document))

    def test_pending_identity_is_spooled_before_first_rpc_and_recovers_exactly(self) -> None:
        launch_requests = []
        active_at_rpc = []
        host_starts = 0

        class Client:
            def __init__(self, _path, **_kwargs):
                pass

            def call(client_self, request):
                nonlocal host_starts
                if request.operation.value == "test.attempt_launch":
                    launch_requests.append(request)
                    active_at_rpc.append(self.spool.active_envelopes())
                    if len(launch_requests) == 1:
                        # Model a testd process dying inside its first authority
                        # call. The broker outcome is unknown, but the exact
                        # identity must already be durable at this boundary.
                        raise RuntimeError("simulated process death at launch RPC")
                    host_starts += 1
                    attempt_id = str(request.arguments["attempt_id"])
                    ticket_id = str(request.arguments["ticket_id"])
                    return {
                        "ok": True,
                        "result": {
                            "runtime_id": "devcoordinator-test-"
                            + hashlib.sha256(
                                attempt_id.encode("utf-8")
                            ).hexdigest()[:32],
                            "launch_ack_id": "test-launch-"
                            + ticket_id.removeprefix("test-ticket-"),
                        },
                    }
                if request.operation.value == "test.attempt_status":
                    return {
                        "ok": True,
                        "result": {
                            "state": "running",
                            "exit_status": None,
                            "result": None,
                            "result_chunk": None,
                            "termination": None,
                            "resource_usage": {"current_memory_bytes": None},
                        },
                    }
                raise AssertionError(f"unexpected operation: {request.operation}")

        connection = BrokerConnection(
            Path("/tmp/devcoordinator-unused.sock"), "authority-test"
        )
        submitter = CoordinatorRuntimeRequestSubmitter(
            connection,
            client_factory=Client,
            clock=self.clock,
        )
        self.engine.launcher = TestdLaunchAdapter(submitter)
        self.submit_live(launch_timeout_seconds=90)

        first = self.engine.schedule(launch_batch=1)

        self.assertEqual(first["launched_target_ids"], [])
        self.assertEqual(len(first["launch_failures"]), 1)
        self.assertEqual(len(active_at_rpc), 1)
        self.assertEqual(len(active_at_rpc[0]), 1)
        retained = active_at_rpc[0][0]
        self.assertFalse(retained.launch_confirmed)
        self.assertIsNotNone(retained.launch_ticket_id)
        self.assertIsNotNone(retained.launch_operation_id)
        self.assertEqual(
            self.store.get_attempt(retained.attempt_id)["state"], "leased"
        )

        replacement_submitter = CoordinatorRuntimeRequestSubmitter(
            connection,
            client_factory=Client,
            clock=self.clock,
        )
        replacement = TestdEngine(
            store=self.store,
            scheduler=self.scheduler,
            ticket_issuer=self.issuer,
            launcher=TestdLaunchAdapter(replacement_submitter),
            spool=DurableAttemptSpool.open(self.spool.root),
            clock=self.clock,
        )
        heartbeat = replacement.heartbeat()

        self.assertEqual(heartbeat["running_attempt_ids"], [retained.attempt_id])
        self.assertEqual(heartbeat["failures"], [])
        self.assertEqual(host_starts, 1)
        self.assertEqual(len(launch_requests), 2)
        self.assertEqual(
            {request.operation_id for request in launch_requests},
            {retained.launch_operation_id},
        )
        self.assertTrue(
            all(
                request.to_wire() == launch_requests[0].to_wire()
                for request in launch_requests
            )
        )
        replayed = replacement.spool.active_envelopes()[0]
        self.assertEqual(replayed.runtime_id, retained.runtime_id)
        self.assertEqual(replayed.launch_ack_id, retained.launch_ack_id)
        self.assertTrue(replayed.launch_confirmed)

    def test_adapter_preserves_active_current_memory_measurement(self) -> None:
        adapter = TestdLaunchAdapter(FakeSubmitter())

        observation = adapter.observe(RunnerHandle("runtime-1", "ack-1"))

        self.assertEqual(observation.state, "running")
        self.assertEqual(observation.current_memory_bytes, 96 * 1024 * 1024)


class UnixTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.store = UniversalTestStore.create(root / "tests.sqlite3")
        self.service = StoreTestPlaneAdapter(self.store)
        self.dispatcher = TestPlaneDispatcher(self.service)

    def _dispatch(self, operation, arguments, *, peer_uid=None):
        request_id = operation_id()
        payload = json.dumps(
            {
                "schema_version": 1,
                "request_id": request_id,
                "operation": operation,
                "arguments": arguments,
            },
            separators=(",", ":"),
        ).encode()
        return self.dispatcher.dispatch(
            payload,
            peer_uid=os.geteuid() if peer_uid is None else peer_uid,
        )

    def test_fixed_operation_round_trip(self) -> None:
        selected = plan()
        registered = self._dispatch(
            TEST_PLAN_REGISTER, {"plan_document": selected.to_document()}
        )["result"]
        self.assertEqual(registered["repository_id"], "repo-tests")
        resolved = self._dispatch(
            "test.plan_repository",
            {
                "plan_id": selected.plan_id,
                "repository_id": "repo-tests",
            },
        )["result"]
        self.assertEqual(resolved["repository_id"], "repo-tests")
        submitted = self._dispatch(
            "test.run_submit",
            {
                "plan_id": selected.plan_id,
                "repository_id": "repo-tests",
                "operation_id": operation_id(),
                "actor": "codex:transport",
                "owner_uid": 1001,
                "priority": 0,
                "target_resources": None,
            },
        )["result"]
        status = self._dispatch(
            "test.run_status",
            {
                "run_id": submitted["run_id"],
                "repository_id": "repo-tests",
            },
        )["result"]
        self.assertEqual(status["state"], "queued")

    def test_unknown_operation_and_argument_shape_fail_closed_for_any_peer(self) -> None:
        request = json.dumps(
            {
                "schema_version": 1,
                "request_id": operation_id(),
                "operation": "test.not_real",
                "arguments": {},
            },
            separators=(",", ":"),
        ).encode()
        response = self.dispatcher.dispatch(request, peer_uid=os.geteuid())
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "unsupported_operation")
        extra = self._dispatch(
            TEST_PLAN_REGISTER,
            {"plan_document": plan().to_document(), "unexpected": True},
        )
        self.assertFalse(extra["ok"])
        self.assertEqual(extra["error"]["code"], "invalid_request")
        attributed = self._dispatch(
            TEST_PLAN_REGISTER,
            {"plan_document": plan().to_document()},
            peer_uid=-1,
        )
        self.assertTrue(attributed["ok"])

    def test_dispatch_journal_detail_is_structured_and_sanitized(self) -> None:
        with mock.patch.object(
            self.service,
            "health",
            side_effect=RuntimeError("secret repository detail"),
        ):
            with self.assertLogs(
                "devcoordinator.universal_test_transport", level="WARNING"
            ) as captured:
                response = self._dispatch(TEST_HEALTH, {})

        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "internal_error")
        journal = "\n".join(captured.output)
        self.assertIn("code=internal_error", journal)
        self.assertIn("exception=RuntimeError", journal)
        self.assertIn("operation=test.health", journal)
        self.assertNotIn("secret repository detail", journal)

    def test_daemon_check_verifies_writability_and_listener_env_fails_closed(self) -> None:
        with mock.patch.object(
            UniversalTestStore, "verify_writable", autospec=True
        ) as verify_writable:
            self.assertEqual(main(["--database", str(self.store.path), "--check"]), 0)
            fresh_spool = Path(self.temporary.name) / "check-spool"
            fresh_spool.mkdir(mode=0o700)
            self.assertEqual(
                main(
                    [
                        "--database",
                        str(self.store.path),
                        "--spool",
                        str(fresh_spool),
                        "--check",
                    ]
                ),
                0,
            )
        self.assertEqual(verify_writable.call_count, 2)
        self.assertTrue((fresh_spool / "pending").is_dir())
        self.assertIsNone(
            inherited_systemd_listener({"LISTEN_PID": "0", "LISTEN_FDS": "0"})
        )
        with self.assertRaisesRegex(Exception, "exactly one"):
            inherited_systemd_listener(
                {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "1"}
            )
        with self.assertRaisesRegex(Exception, "LISTEN_FDNAMES"):
            inherited_systemd_listener(
                {
                    "LISTEN_PID": str(os.getpid()),
                    "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "wrong",
                }
            )

    def test_testd_uses_the_installed_trusted_local_authority_socket_contract(self) -> None:
        arguments = build_parser().parse_args(
            [
                "--database",
                str(self.store.path),
                "--broker-socket",
                "/run/devcoordinator-authority.sock",
            ]
        )
        connection = BrokerConnection(
            arguments.broker_socket,
            authority_generation="broker-current-testd",
            expected_broker_uid=arguments.broker_uid,
            expected_socket_gid=arguments.broker_socket_gid,
            expected_socket_mode=arguments.broker_socket_mode,
        )

        self.assertEqual(connection.expected_broker_uid, 0)
        self.assertEqual(connection.expected_socket_gid, 0)
        self.assertEqual(connection.expected_socket_mode, 0o666)


if __name__ == "__main__":
    unittest.main()
