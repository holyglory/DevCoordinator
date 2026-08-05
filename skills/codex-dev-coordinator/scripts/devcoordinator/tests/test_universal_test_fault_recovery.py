from __future__ import annotations

from devcoordinator.tests.test_universal_testd import EngineFixture, operation_id
from devcoordinator.universal_test_service import StoreTestPlaneAdapter
from devcoordinator.universal_test_spool import (
    AttemptExitEnvelope,
    AttemptResultChunkEnvelope,
)
from devcoordinator.universal_test_store import AttemptConclusion


class UniversalTestFaultRecoveryTests(EngineFixture):
    def test_late_spool_after_lost_heartbeat_cannot_corrupt_retry(self) -> None:
        submitted = self.submit_live()
        self.engine.schedule(launch_batch=1)
        stale = self.launcher.requests[0]

        self.clock.advance(31)
        reaped = self.engine.reap()
        self.assertEqual(
            reaped["abandoned_attempt_ids"], [stale.ticket.attempt_id]
        )
        self.assertEqual(reaped["lease_expired_before_launch_attempt_ids"], [])
        self.assertEqual(
            reaped["running_heartbeat_lost_attempt_ids"],
            [stale.ticket.attempt_id],
        )
        self.assertEqual(
            reaped["outcomes"],
            [
                {
                    "attempt_id": stale.ticket.attempt_id,
                    "run_id": submitted.run_id,
                    "reason": "running_heartbeat_lost",
                    "requeued": False,
                }
            ],
        )
        status = StoreTestPlaneAdapter(self.store).status(
            run_id=submitted.run_id,
            repository_id="repo-tests",
        )
        self.assertEqual(
            status["lease_expiry_evidence"]["events"][0]["reason"],
            "running_heartbeat_lost",
        )
        retry = self.store.retry_run(
            submitted.run_id,
            actor="codex:retry-after-heartbeat-loss",
            failed_only=True,
            operation_id=operation_id(),
        )
        candidate = next(
            item
            for item in self.store.runnable_targets()
            if item.run_id == retry.run_id
        )
        replacement = self.store.lease_target(
            candidate.target_id,
            lease_owner="replacement-testd",
            operation_id=operation_id(),
        )
        self.store.acknowledge_launch(
            replacement.attempt_id,
            generation=replacement.generation,
            launch_ack_id="launch-replacement-after-heartbeat-loss",
            operation_id=operation_id(),
        )

        stale_chunk = {
            "chunk_id": "chunk-late-after-heartbeat-loss",
            "chunk_index": 0,
            "cases": [],
            "failures": [],
            "artifacts": [],
            "reporter_complete": True,
        }
        self.spool.append_result_chunk(
            AttemptResultChunkEnvelope(
                envelope_id="result-late-after-heartbeat-loss",
                attempt_id=stale.ticket.attempt_id,
                generation=stale.ticket.generation,
                chunk=stale_chunk,
            )
        )
        self.spool.append(
            AttemptExitEnvelope(
                envelope_id="exit-late-after-heartbeat-loss",
                attempt_id=stale.ticket.attempt_id,
                generation=stale.ticket.generation,
                operation_id=operation_id(),
                conclusion=AttemptConclusion.SUCCEEDED,
                duration_seconds=1.0,
                result_chunk_ids=(stale_chunk["chunk_id"],),
            )
        )

        replay = self.engine.replay_spool()
        self.assertEqual(replay["result_chunks"]["imported_envelope_ids"], [])
        self.assertEqual(replay["imported_envelope_ids"], [])
        self.assertEqual(
            replay["result_chunks"]["failed"][0]["error_type"],
            "TestStoreConflict",
        )
        self.assertEqual(replay["failed"][0]["error_type"], "TestStoreConflict")
        self.assertEqual(len(self.spool.pending_result_chunks()), 1)
        self.assertEqual(len(self.spool.pending_envelopes()), 1)

        source_run = self.store.get_run(submitted.run_id)
        self.assertEqual(source_run["state"], "abandoned")
        self.assertEqual(
            source_run["lease_expiry_evidence"],
            status["lease_expiry_evidence"],
        )
        self.assertEqual(self.store.get_run(retry.run_id)["state"], "running")
        self.assertEqual(
            self.store.get_attempt(replacement.attempt_id)["state"], "running"
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
