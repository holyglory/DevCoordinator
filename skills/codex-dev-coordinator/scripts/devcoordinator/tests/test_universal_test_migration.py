from __future__ import annotations

from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping
import unittest
from unittest import mock
import uuid

from devcoordinator.store import CoordinatorStore
from devcoordinator.universal_test_admission import (
    LEGACY_TEST_ADMISSION_SCHEMA,
    build_legacy_test_admission_drain_proof,
)
from devcoordinator.universal_test_migration import (
    LegacyMigrationState,
    LegacyTestHistoryMigrator,
    load_migration_state,
    save_migration_state,
)
from devcoordinator.universal_test_store import (
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)


START = "2026-07-28T01:00:00+00:00"
FINISH = "2026-07-28T01:00:04+00:00"


class _RepositoryCLIUnavailable:
    def __init__(self, filename: str) -> None:
        self.filename = filename

    def __getattr__(self, name: str):
        del name
        raise unittest.SkipTest(
            f"repository-only CLI {self.filename} is unavailable in a standalone skill copy"
        )


def _load_repository_cli(*, test_file: Path, filename: str, module_name: str):
    """Load a repository CLI only when this skill belongs to that source tree."""

    skill_root = test_file.resolve().parents[3]
    repository_root = skill_root.parent.parent
    configured_skill = repository_root / "skills" / skill_root.name
    cli_path = repository_root / "scripts" / filename
    try:
        source_tree_matches = configured_skill.samefile(skill_root)
    except OSError:
        source_tree_matches = False
    if not source_tree_matches or not cli_path.is_file():
        return _RepositoryCLIUnavailable(filename)
    spec = importlib.util.spec_from_file_location(module_name, cli_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load repository CLI {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MIGRATION_CLI = _load_repository_cli(
    test_file=Path(__file__),
    filename="migrate_universal_test_history.py",
    module_name="migrate_universal_test_history",
)


class LegacyTestHistoryMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="universal-test-migration-")
        self.root = Path(self.temporary.name)
        self.authority_path = self.root / "authority" / "authority.sqlite3"
        self.authority_path.parent.mkdir(mode=0o700)
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    "INSERT INTO hosts VALUES ('host-a', 'machine-a', 'linux', 'test', ?, ?)",
                    (START, START),
                )
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES ('repo-a', 'host-a', '/srv/repo-a', 'Repo A', 'active', 1, ?, ?)
                    """,
                    (START, START),
                )
        self.test_path = self.root / "testd" / "tests.sqlite3"
        self.test_path.parent.mkdir(mode=0o700)
        self.test_store = UniversalTestStore.create(self.test_path)
        self.migrator = LegacyTestHistoryMigrator(
            self.authority_path,
            self.test_store,
            expected_authority_uid=os.geteuid(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def insert_run(
        self,
        run_id: str,
        *,
        status: str,
        run_kind: str = "test",
        case_statuses: tuple[str, ...] = (),
    ) -> None:
        completed = status != "running"
        counts = {
            name: sum(1 for item in case_statuses if item == name)
            for name in ("passed", "failed", "skipped", "error")
        }
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    """
                    INSERT INTO test_runs(
                        run_id, repo_id, parent_run_id, owner_uid, account_id,
                        actor, suite, run_kind, selection_json,
                        command_fingerprint, status, client_started_at,
                        admitted_at, client_finished_at, recorded_finished_at,
                        duration_seconds, exit_code, case_count, passed_count,
                        failed_count, skipped_count, error_count,
                        finished_operation_id, result_fingerprint,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        "repo-a",
                        None,
                        os.geteuid(),
                        "account-a",
                        "codex",
                        "unit",
                        run_kind,
                        "[]",
                        "sha256:" + run_id,
                        status,
                        START,
                        START,
                        FINISH if completed else None,
                        FINISH if completed else None,
                        4.0 if completed else None,
                        0 if status == "passed" else (1 if completed else None),
                        len(case_statuses),
                        counts["passed"],
                        counts["failed"],
                        counts["skipped"],
                        counts["error"],
                        str(uuid.uuid5(uuid.NAMESPACE_URL, "finish:" + run_id)) if completed else None,
                        "sha256:" + run_id if completed else None,
                        START,
                        FINISH if completed else START,
                    ),
                )
                for ordinal, case_status in enumerate(case_statuses):
                    connection.execute(
                        """
                        INSERT INTO test_case_results(
                            run_id, ordinal, test_id, display_name, status,
                            started_at, finished_at, duration_seconds
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            ordinal,
                            f"case-{ordinal}",
                            f"Case {ordinal}",
                            case_status,
                            START,
                            FINISH,
                            1.25 + ordinal,
                        ),
                    )

    def finish_running(self, run_id: str, *, status: str = "passed") -> None:
        case_status = "passed" if status == "passed" else "failed"
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    """
                    INSERT INTO test_case_results(
                        run_id, ordinal, test_id, display_name, status,
                        started_at, finished_at, duration_seconds
                    ) VALUES (?, 0, 'late-case', 'Late case', ?, ?, ?, 2.5)
                    """,
                    (run_id, case_status, START, FINISH),
                )
                connection.execute(
                    """
                    UPDATE test_runs SET status = ?, client_finished_at = ?,
                        recorded_finished_at = ?, duration_seconds = 4.0,
                        exit_code = ?, case_count = 1, passed_count = ?,
                        failed_count = ?, skipped_count = 0, error_count = 0,
                        finished_operation_id = ?, result_fingerprint = ?,
                        updated_at = ? WHERE run_id = ?
                    """,
                    (
                        status,
                        FINISH,
                        FINISH,
                        0 if status == "passed" else 1,
                        int(status == "passed"),
                        int(status == "failed"),
                        str(uuid.uuid5(uuid.NAMESPACE_URL, "finish:" + run_id)),
                        "sha256:" + run_id,
                        FINISH,
                        run_id,
                    ),
                )

    def install_drain_proof(self, proof_path: Path) -> Mapping[str, object]:
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(LEGACY_TEST_ADMISSION_SCHEMA)
                generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
                proof = build_legacy_test_admission_drain_proof(
                    drain_id=str(uuid.uuid4()),
                    authority_generation=generation,
                    activated_at_epoch=100,
                    activated_by_uid=os.geteuid(),
                    drained_at_epoch=101,
                    broker_instance_id="broker-test-instance",
                )
                connection.execute(
                    """
                    INSERT INTO broker_test_admission_fences(
                        singleton, schema_version, purpose, drain_id,
                        authority_generation, activated_at_epoch,
                        activated_by_uid, drained_at_epoch, broker_instance_id,
                        observed_inflight_submissions, active, proof_sha256
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proof["schema_version"], proof["purpose"], proof["drain_id"],
                        proof["authority_generation"], proof["activated_at_epoch"],
                        proof["activated_by_uid"], proof["drained_at_epoch"],
                        proof["broker_instance_id"], proof["observed_inflight_submissions"],
                        proof["active"], proof["proof_sha256"],
                    ),
                )
        proof_path.write_text(json.dumps(dict(proof)) + "\n", encoding="utf-8")
        proof_path.chmod(0o600)
        return proof

    def prepare_finalized_cutover(
        self, name: str
    ) -> tuple[Path, Path, Mapping[str, object]]:
        self.insert_run(f"run-{name}", status="passed", case_statuses=("passed",))
        state_path = self.root / f"{name}-cutover.json"
        MIGRATION_CLI.capture(
            authority_database=self.authority_path,
            test_database=self.test_path,
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        MIGRATION_CLI.copy_batches(
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        proof_path = self.root / f"{name}-drain-proof.json"
        proof = self.install_drain_proof(proof_path)
        MIGRATION_CLI.finalize(
            state_path=state_path,
            proof_path=proof_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        return state_path, proof_path, proof

    def prepare_verified_cutover(
        self, name: str
    ) -> tuple[Path, Path, Mapping[str, object]]:
        state_path, proof_path, proof = self.prepare_finalized_cutover(name)
        MIGRATION_CLI.verify(
            state_path=state_path,
            proof_path=proof_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
        )
        return state_path, proof_path, proof

    def destination_states(self) -> dict[str, str]:
        connection = self.test_store._connect(readonly=True)
        try:
            return {
                str(row["run_id"]): str(row["state"])
                for row in connection.execute(
                    "SELECT run_id, state FROM test_runs ORDER BY run_id"
                ).fetchall()
            }
        finally:
            connection.close()

    def test_repository_cli_discovery_fails_closed_after_skill_relocation(self) -> None:
        relocated = self.root / "standalone" / "codex-dev-coordinator"
        relocated_test = (
            relocated
            / "scripts"
            / "devcoordinator"
            / "tests"
            / Path(__file__).name
        )
        relocated_test.parent.mkdir(parents=True)
        relocated_test.touch()
        unavailable = _load_repository_cli(
            test_file=relocated_test,
            filename="migrate_universal_test_history.py",
            module_name="relocated_migrate_universal_test_history",
        )
        with self.assertRaises(unittest.SkipTest):
            unavailable.capture

    def test_first_pass_copies_terminal_rows_and_defers_running(self) -> None:
        self.insert_run("run-passed", status="passed", case_statuses=("passed", "passed"))
        self.insert_run("run-running", status="running")
        self.insert_run("session-wrapper", status="passed", run_kind="session")

        watermark = self.migrator.capture_watermark()
        self.assertEqual(watermark.eligible_run_count, 2)
        self.assertEqual(watermark.terminal_run_count, 1)
        self.assertEqual(watermark.running_run_count, 1)
        self.assertEqual(watermark.excluded_session_count, 1)

        result = self.migrator.import_watermark(watermark, finalize_running=False)
        self.assertEqual(result.imported_run_count, 1)
        self.assertEqual(result.imported_case_count, 2)
        self.assertEqual(result.deferred_running_count, 1)
        self.assertEqual(result.source_digest, result.destination_digest)
        self.assertEqual(self.destination_states(), {"run-passed": "succeeded"})
        self.assertGreaterEqual(result.rollups["hourly"], 1)

    def test_final_rescan_captures_in_place_completion_and_abandons_remainder(self) -> None:
        self.insert_run("run-first", status="passed", case_statuses=("passed",))
        self.insert_run("run-late-completion", status="running")
        first = self.migrator.capture_watermark()
        self.migrator.import_watermark(first, finalize_running=False)

        self.finish_running("run-late-completion")
        self.insert_run("run-tail-running", status="running")
        final = self.migrator.capture_watermark()
        result = self.migrator.import_watermark(final, finalize_running=True)

        self.assertEqual(result.imported_run_count, 3)
        self.assertEqual(result.abandoned_running_count, 1)
        self.assertEqual(result.source_digest, result.destination_digest)
        self.assertEqual(
            self.destination_states(),
            {
                "run-first": "succeeded",
                "run-late-completion": "succeeded",
                "run-tail-running": "abandoned",
            },
        )

    def test_changed_authority_snapshot_is_rejected_before_copy(self) -> None:
        self.insert_run("run-changing", status="running")
        watermark = self.migrator.capture_watermark()
        self.finish_running("run-changing")
        with self.assertRaisesRegex(TestStoreConflict, "changed after its watermark"):
            self.migrator.import_watermark(watermark, finalize_running=False)
        self.assertEqual(self.destination_states(), {})

    def test_same_import_is_idempotent_and_digest_verified(self) -> None:
        self.insert_run("run-repeat", status="failed", case_statuses=("failed",))
        watermark = self.migrator.capture_watermark()
        first = self.migrator.import_watermark(watermark, finalize_running=False)
        second = self.migrator.import_watermark(watermark, finalize_running=False)
        self.assertEqual(first.source_digest, second.source_digest)
        self.assertEqual(first.destination_digest, second.destination_digest)
        self.assertEqual(self.destination_states(), {"run-repeat": "failed"})

    def test_case_count_mismatch_rolls_back_the_entire_batch(self) -> None:
        self.insert_run("run-corrupt", status="passed", case_statuses=("passed",))
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(
                    "UPDATE test_runs SET case_count = 2 WHERE run_id = 'run-corrupt'"
                )
        watermark = self.migrator.capture_watermark()
        with self.assertRaisesRegex(TestStoreConflict, "case_count"):
            self.migrator.import_watermark(watermark, finalize_running=False)
        self.assertEqual(self.destination_states(), {})

    def test_batched_copy_resumes_after_interruption_without_duplicate_rows(self) -> None:
        for index in range(5):
            self.insert_run(f"run-{index}", status="passed", case_statuses=("passed",))
        watermark = self.migrator.capture_watermark()
        self.migrator.validate_watermark(watermark)
        first = self.migrator.import_next_batch(
            watermark, finalize_running=False, after_rowid=0, batch_size=2
        )
        self.assertFalse(first.complete)
        self.assertEqual(first.imported_run_count, 2)

        reopened = UniversalTestStore.open(self.test_path)
        resumed = LegacyTestHistoryMigrator(
            self.authority_path, reopened, expected_authority_uid=os.geteuid()
        )
        replay = resumed.import_next_batch(
            watermark, finalize_running=False, after_rowid=0, batch_size=2
        )
        self.assertEqual(replay, first)
        cursor = first.next_rowid
        while cursor < watermark.maximum_rowid:
            batch = resumed.import_next_batch(
                watermark,
                finalize_running=False,
                after_rowid=cursor,
                batch_size=2,
            )
            cursor = batch.next_rowid
        verified = resumed.verify_import(watermark, finalize_running=False)
        self.assertEqual(verified.imported_run_count, 5)
        self.assertEqual(len(self.destination_states()), 5)

    def test_capacity_failure_occurs_before_destination_mutation(self) -> None:
        self.insert_run("run-capacity", status="passed", case_statuses=("passed",))
        watermark = self.migrator.capture_watermark()
        constrained = LegacyTestHistoryMigrator(
            self.authority_path,
            self.test_store,
            expected_authority_uid=os.geteuid(),
            capacity_probe=lambda _path: 0,
        )
        with self.assertRaisesRegex(TestStoreConflict, "free bytes"):
            constrained.import_watermark(watermark, finalize_running=False)
        self.assertEqual(self.destination_states(), {})

    def test_atomic_state_file_requires_generation_compare_and_swap(self) -> None:
        self.insert_run("run-state", status="passed")
        watermark = self.migrator.capture_watermark()
        now = "2026-07-28T02:00:00+00:00"
        state = LegacyMigrationState(
            migration_id="migration-a",
            authority_database=str(self.authority_path),
            test_database=str(self.test_path),
            test_store_generation=str(self.test_store.verify()["store_generation"]),
            batch_size=2,
            phase="captured",
            initial_watermark=watermark,
            initial_cursor=0,
            final_watermark=None,
            final_cursor=0,
            drain_proof_fingerprint=None,
            verification=None,
            seal=None,
            created_at=now,
            updated_at=now,
            state_generation=0,
        )
        state_path = self.root / "migration-state.json"
        save_migration_state(
            state_path, state, expected_uid=os.geteuid(), create=True
        )
        self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_migration_state(state_path, expected_uid=os.geteuid()), state)

        updated = replace(state, phase="copying", state_generation=1)
        save_migration_state(
            state_path,
            updated,
            expected_uid=os.geteuid(),
            create=False,
            expected_generation=0,
        )
        with self.assertRaisesRegex(TestStoreConflict, "generation changed"):
            save_migration_state(
                state_path,
                replace(state, phase="copied", state_generation=1),
                expected_uid=os.geteuid(),
                create=False,
                expected_generation=0,
            )
        self.assertEqual(
            load_migration_state(state_path, expected_uid=os.geteuid()).phase,
            "copying",
        )

    def test_source_history_is_retained_for_rollback(self) -> None:
        self.insert_run("run-retained", status="passed", case_statuses=("passed",))
        watermark = self.migrator.capture_watermark()
        self.migrator.import_watermark(watermark, finalize_running=False)
        with CoordinatorStore.open_read_only(
            self.authority_path, expected_uid=os.geteuid()
        ) as store:
            with store.read_transaction() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM test_runs WHERE run_id = 'run-retained'"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM test_case_results WHERE run_id = 'run-retained'"
                    ).fetchone()[0],
                    1,
                )

    def test_admin_workflow_resumes_final_tail_verifies_and_seals(self) -> None:
        self.insert_run("run-initial", status="passed", case_statuses=("passed",))
        state_path = self.root / "cutover.json"
        captured = MIGRATION_CLI.capture(
            authority_database=self.authority_path,
            test_database=self.test_path,
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        self.assertEqual(captured["phase"], "captured")
        copied = MIGRATION_CLI.copy_batches(
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        self.assertEqual(copied["phase"], "copied")

        self.insert_run("run-final-tail", status="running")
        proof_path = self.root / "drain-proof.json"
        proof_path.write_text("{}\n", encoding="utf-8")
        proof_path.chmod(0o600)
        proof = ({"drain_id": "drain-a", "active": True}, "a" * 64)
        with mock.patch.object(MIGRATION_CLI, "_verify_drain_proof", return_value=proof):
            partial = MIGRATION_CLI.finalize(
                state_path=state_path,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                max_batches=1,
            )
            self.assertEqual(partial["phase"], "finalizing")
            finalized = MIGRATION_CLI.finalize(
                state_path=state_path,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                max_batches=None,
            )
            self.assertEqual(finalized["phase"], "finalized")
            verified = MIGRATION_CLI.verify(
                state_path=state_path,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
            )
        self.assertEqual(verified["phase"], "verified")
        self.assertEqual(verified["imported_run_count"], 2)
        self.assertEqual(verified["imported_case_count"], 1)
        self.assertEqual(verified["source_digest"], verified["destination_digest"])
        self.assertEqual(
            self.destination_states(),
            {"run-final-tail": "abandoned", "run-initial": "succeeded"},
        )

        seal_path = self.root / "activation-seal.json"
        with mock.patch.object(MIGRATION_CLI, "_verify_drain_proof", return_value=proof):
            sealed = MIGRATION_CLI.seal(
                state_path=state_path,
                output=seal_path,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
            )
        self.assertEqual(sealed["phase"], "sealed")
        self.assertEqual(seal_path.stat().st_mode & 0o777, 0o600)
        final_state = load_migration_state(state_path, expected_uid=os.geteuid())
        self.assertEqual(final_state.phase, "sealed")
        self.assertTrue(dict(final_state.verification or {})["legacy_source_retained"])

    def test_admin_copy_recovers_when_state_publish_is_interrupted(self) -> None:
        self.insert_run("run-state-gap", status="passed", case_statuses=("passed",))
        state_path = self.root / "interrupted-cutover.json"
        MIGRATION_CLI.capture(
            authority_database=self.authority_path,
            test_database=self.test_path,
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        real_save = MIGRATION_CLI.save_migration_state
        with mock.patch.object(
            MIGRATION_CLI,
            "save_migration_state",
            side_effect=OSError("simulated state publication interruption"),
        ):
            with self.assertRaisesRegex(OSError, "simulated"):
                MIGRATION_CLI.copy_batches(
                    state_path=state_path,
                    expected_authority_uid=os.geteuid(),
                    expected_test_uid=os.geteuid(),
                    max_batches=None,
                )
        self.assertEqual(self.destination_states(), {"run-state-gap": "succeeded"})
        self.assertEqual(
            load_migration_state(state_path, expected_uid=os.geteuid()).initial_cursor,
            0,
        )
        with mock.patch.object(MIGRATION_CLI, "save_migration_state", real_save):
            resumed = MIGRATION_CLI.copy_batches(
                state_path=state_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                max_batches=None,
            )
        self.assertEqual(resumed["phase"], "copied")
        self.assertEqual(self.destination_states(), {"run-state-gap": "succeeded"})

    def test_verify_rechecks_bound_drain_after_long_digest_pass(self) -> None:
        state_path, proof_path, _proof = self.prepare_finalized_cutover(
            "verify-drain-cleared"
        )
        real_verify = LegacyTestHistoryMigrator.verify_import

        def verify_then_clear(
            migrator: LegacyTestHistoryMigrator,
            watermark: object,
            *,
            finalize_running: bool,
        ) -> object:
            result = real_verify(
                migrator, watermark, finalize_running=finalize_running  # type: ignore[arg-type]
            )
            with CoordinatorStore.open(self.authority_path) as store:
                with store.immediate_transaction(check_invariants=False) as connection:
                    connection.execute("DELETE FROM broker_test_admission_fences")
            return result

        with mock.patch.object(
            LegacyTestHistoryMigrator,
            "verify_import",
            new=verify_then_clear,
        ):
            with self.assertRaisesRegex(
                TestStoreContractError, "no active test drain proof"
            ):
                MIGRATION_CLI.verify(
                    state_path=state_path,
                    proof_path=proof_path,
                    expected_authority_uid=os.geteuid(),
                    expected_test_uid=os.geteuid(),
                )
        self.assertEqual(
            load_migration_state(state_path, expected_uid=os.geteuid()).phase,
            "finalized",
        )

    def test_seal_rejects_drain_cleared_after_verification(self) -> None:
        state_path, proof_path, _proof = self.prepare_verified_cutover(
            "seal-drain-cleared"
        )
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute("DELETE FROM broker_test_admission_fences")
        output = self.root / "cleared-fence-seal.json"
        with self.assertRaisesRegex(
            TestStoreContractError, "no active test drain proof"
        ):
            MIGRATION_CLI.seal(
                state_path=state_path,
                output=output,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
            )
        self.assertFalse(output.exists())

    def test_seal_rejects_legacy_tail_inserted_after_verification(self) -> None:
        state_path, proof_path, _proof = self.prepare_verified_cutover(
            "seal-tail-inserted"
        )
        self.insert_run(
            "run-after-final-watermark",
            status="passed",
            case_statuses=("passed",),
        )
        output = self.root / "tail-inserted-seal.json"
        with self.assertRaisesRegex(TestStoreConflict, "gained rows"):
            MIGRATION_CLI.seal(
                state_path=state_path,
                output=output,
                proof_path=proof_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
            )
        self.assertFalse(output.exists())

    def test_split_identity_export_import_attestation_cutover(self) -> None:
        self.insert_run("run-split", status="passed", case_statuses=("passed",))
        initial_package = self.root / "initial-package"
        final_package = self.root / "final-package"
        initial_package.mkdir(mode=0o700)
        final_package.mkdir(mode=0o700)
        state_path = self.root / "split-state.json"
        store_generation = str(self.test_store.verify()["store_generation"])

        with mock.patch.object(
            MIGRATION_CLI.UniversalTestStore,
            "open",
            side_effect=AssertionError("authority lane opened the test store"),
        ):
            MIGRATION_CLI.authority_capture_split(
                authority_database=self.authority_path,
                test_database=self.test_path,
                test_store_generation=store_generation,
                state_path=state_path,
                initial_package_directory=initial_package,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                batch_size=1,
            )
            initial = MIGRATION_CLI.authority_export_initial_split(
                state_path=state_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                max_batches=None,
            )
        initial_attestation = self.root / "initial-import.json"
        with mock.patch.object(
            CoordinatorStore,
            "open_read_only",
            side_effect=AssertionError("testd lane opened the authority store"),
        ):
            imported_initial = MIGRATION_CLI.testd_import_split(
                manifest_path=Path(str(initial["manifest"])),
                expected_export_fingerprint=str(initial["manifest_fingerprint"]),
                test_database=self.test_path,
                attestation_output=initial_attestation,
                expected_test_uid=os.geteuid(),
            )
        self.assertEqual(imported_initial["run_count"], 1)

        proof_path = self.root / "split-drain-proof.json"
        self.install_drain_proof(proof_path)
        finalized = MIGRATION_CLI.authority_finalize_split(
            state_path=state_path,
            final_package_directory=final_package,
            proof_path=proof_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        final_attestation = self.root / "final-import.json"
        imported_final = MIGRATION_CLI.testd_import_split(
            manifest_path=Path(str(finalized["manifest"])),
            expected_export_fingerprint=str(finalized["manifest_fingerprint"]),
            test_database=self.test_path,
            attestation_output=final_attestation,
            expected_test_uid=os.geteuid(),
        )
        seal_path = self.root / "split-seal.json"
        sealed = MIGRATION_CLI.authority_seal_split(
            state_path=state_path,
            proof_path=proof_path,
            attestation_path=final_attestation,
            expected_attestation_fingerprint=str(
                imported_final["attestation_fingerprint"]
            ),
            output=seal_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
        )
        self.assertEqual(sealed["phase"], "sealed")
        self.assertTrue(seal_path.exists())
        self.assertEqual(self.destination_states(), {"run-split": "succeeded"})

    def test_testd_prepares_private_split_package_directories_idempotently(self) -> None:
        operation_id = str(uuid.uuid4())
        package_root = self.test_path.parent / f"history-migration-{operation_id}"
        first = MIGRATION_CLI.testd_prepare_package_directories(
            package_root=package_root,
            operation_id=operation_id,
            expected_test_uid=os.geteuid(),
        )
        second = MIGRATION_CLI.testd_prepare_package_directories(
            package_root=package_root,
            operation_id=operation_id,
            expected_test_uid=os.geteuid(),
        )

        self.assertTrue(first["created_root"])
        self.assertFalse(second["created_root"])
        self.assertEqual(first["attestation_sha256"], second["attestation_sha256"])
        for name in ("initial", "final"):
            directory = package_root / name
            self.assertTrue(directory.is_dir())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        attestation = json.loads(
            (package_root / MIGRATION_CLI.PACKAGE_PREPARATION_FILE).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(attestation["operation_id"], operation_id)
        self.assertEqual(attestation["expected_test_uid"], os.geteuid())

    def test_testd_package_preparation_rejects_identity_and_binding_drift(self) -> None:
        operation_id = str(uuid.uuid4())
        package_root = self.test_path.parent / f"history-migration-{operation_id}"
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "testd UID"
        ):
            MIGRATION_CLI.testd_prepare_package_directories(
                package_root=package_root,
                operation_id=operation_id,
                expected_test_uid=os.geteuid() + 1,
            )

        MIGRATION_CLI.testd_prepare_package_directories(
            package_root=package_root,
            operation_id=operation_id,
            expected_test_uid=os.geteuid(),
        )
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "another migration"
        ):
            MIGRATION_CLI.testd_prepare_package_directories(
                package_root=package_root,
                operation_id=str(uuid.uuid4()),
                expected_test_uid=os.geteuid(),
            )

    def test_split_lane_rejects_stale_export_and_forged_attestation(self) -> None:
        self.insert_run("run-split-forgery", status="passed", case_statuses=("passed",))
        initial_package = self.root / "forgery-initial"
        final_package = self.root / "forgery-final"
        initial_package.mkdir(mode=0o700)
        final_package.mkdir(mode=0o700)
        state_path = self.root / "forgery-state.json"
        MIGRATION_CLI.authority_capture_split(
            authority_database=self.authority_path,
            test_database=self.test_path,
            test_store_generation=str(self.test_store.verify()["store_generation"]),
            state_path=state_path,
            initial_package_directory=initial_package,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        initial = MIGRATION_CLI.authority_export_initial_split(
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "expected fingerprint"
        ):
            MIGRATION_CLI.testd_import_split(
                manifest_path=Path(str(initial["manifest"])),
                expected_export_fingerprint="0" * 64,
                test_database=self.test_path,
                attestation_output=self.root / "stale-import.json",
                expected_test_uid=os.geteuid(),
            )

        proof_path = self.root / "forgery-proof.json"
        self.install_drain_proof(proof_path)
        final = MIGRATION_CLI.authority_finalize_split(
            state_path=state_path,
            final_package_directory=final_package,
            proof_path=proof_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        attestation_path = self.root / "valid-final-attestation.json"
        imported = MIGRATION_CLI.testd_import_split(
            manifest_path=Path(str(final["manifest"])),
            expected_export_fingerprint=str(final["manifest_fingerprint"]),
            test_database=self.test_path,
            attestation_output=attestation_path,
            expected_test_uid=os.geteuid(),
        )
        valid = dict(
            MIGRATION_CLI._read_private_json(
                attestation_path, expected_uid=os.geteuid()
            )
        )
        forged_values = {
            key: value
            for key, value in valid.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        forged_values["export_fingerprint"] = "f" * 64
        forged = MIGRATION_CLI._seal_document(
            MIGRATION_CLI.IMPORT_ATTESTATION_KIND,
            forged_values,
        )
        forged_path = self.root / "forged-final-attestation.json"
        forged_path.write_text(json.dumps(forged) + "\n", encoding="utf-8")
        forged_path.chmod(0o600)
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "does not match final export"
        ):
            MIGRATION_CLI.authority_seal_split(
                state_path=state_path,
                proof_path=proof_path,
                attestation_path=forged_path,
                expected_attestation_fingerprint=str(forged["document_sha256"]),
                output=self.root / "forged-seal.json",
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
            )
        self.assertEqual(len(str(imported["attestation_fingerprint"])), 64)

    def test_split_role_gates_reject_wrong_service_identity(self) -> None:
        package = self.root / "wrong-role-package"
        package.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "authority UID"
        ):
            MIGRATION_CLI.authority_capture_split(
                authority_database=self.authority_path,
                test_database=self.test_path,
                test_store_generation=str(self.test_store.verify()["store_generation"]),
                state_path=self.root / "wrong-role-state.json",
                initial_package_directory=package,
                expected_authority_uid=os.geteuid() + 1,
                expected_test_uid=os.geteuid(),
                batch_size=1,
            )
        with self.assertRaisesRegex(
            MIGRATION_CLI.MigrationCommandError, "testd UID"
        ):
            MIGRATION_CLI.testd_import_split(
                manifest_path=self.root / "missing.json",
                expected_export_fingerprint="0" * 64,
                test_database=self.test_path,
                attestation_output=self.root / "wrong-role-attestation.json",
                expected_test_uid=os.geteuid() + 1,
            )

    def test_split_export_resumes_after_chunk_publish_before_state_cas(self) -> None:
        self.insert_run("run-split-resume-a", status="passed", case_statuses=("passed",))
        self.insert_run("run-split-resume-b", status="passed", case_statuses=("passed",))
        package = self.root / "resume-package"
        package.mkdir(mode=0o700)
        state_path = self.root / "resume-state.json"
        MIGRATION_CLI.authority_capture_split(
            authority_database=self.authority_path,
            test_database=self.test_path,
            test_store_generation=str(self.test_store.verify()["store_generation"]),
            state_path=state_path,
            initial_package_directory=package,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        real_replace = MIGRATION_CLI._replace_private_json
        with mock.patch.object(
            MIGRATION_CLI,
            "_replace_private_json",
            side_effect=OSError("state CAS interrupted"),
        ):
            with self.assertRaisesRegex(OSError, "state CAS interrupted"):
                MIGRATION_CLI.authority_export_initial_split(
                    state_path=state_path,
                    expected_authority_uid=os.geteuid(),
                    expected_test_uid=os.geteuid(),
                    max_batches=None,
                )
        self.assertTrue((package / "chunk-00000000.json").exists())
        with mock.patch.object(MIGRATION_CLI, "_replace_private_json", real_replace):
            resumed = MIGRATION_CLI.authority_export_initial_split(
                state_path=state_path,
                expected_authority_uid=os.geteuid(),
                expected_test_uid=os.geteuid(),
                max_batches=None,
            )
        self.assertEqual(resumed["phase"], "initial_exported")
        imported = MIGRATION_CLI.testd_import_split(
            manifest_path=Path(str(resumed["manifest"])),
            expected_export_fingerprint=str(resumed["manifest_fingerprint"]),
            test_database=self.test_path,
            attestation_output=self.root / "resume-attestation.json",
            expected_test_uid=os.geteuid(),
        )
        self.assertEqual(imported["run_count"], 2)

    def test_split_import_capacity_failure_precedes_destination_mutation(self) -> None:
        self.insert_run("run-split-capacity", status="passed", case_statuses=("passed",))
        package = self.root / "capacity-package"
        package.mkdir(mode=0o700)
        state_path = self.root / "capacity-state.json"
        MIGRATION_CLI.authority_capture_split(
            authority_database=self.authority_path,
            test_database=self.test_path,
            test_store_generation=str(self.test_store.verify()["store_generation"]),
            state_path=state_path,
            initial_package_directory=package,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            batch_size=1,
        )
        exported = MIGRATION_CLI.authority_export_initial_split(
            state_path=state_path,
            expected_authority_uid=os.geteuid(),
            expected_test_uid=os.geteuid(),
            max_batches=None,
        )
        with mock.patch.object(
            MIGRATION_CLI.shutil,
            "disk_usage",
            return_value=mock.Mock(free=0),
        ):
            with self.assertRaisesRegex(TestStoreConflict, "free bytes"):
                MIGRATION_CLI.testd_import_split(
                    manifest_path=Path(str(exported["manifest"])),
                    expected_export_fingerprint=str(
                        exported["manifest_fingerprint"]
                    ),
                    test_database=self.test_path,
                    attestation_output=self.root / "capacity-attestation.json",
                    expected_test_uid=os.geteuid(),
                )
        self.assertEqual(self.destination_states(), {})

    def test_admin_finalize_accepts_only_authority_backed_drain_proof(self) -> None:
        with CoordinatorStore.open(self.authority_path) as store:
            with store.immediate_transaction(check_invariants=False) as connection:
                connection.execute(LEGACY_TEST_ADMISSION_SCHEMA)
                generation = str(
                    connection.execute(
                        "SELECT database_generation FROM schema_metadata WHERE singleton = 1"
                    ).fetchone()[0]
                )
                proof = build_legacy_test_admission_drain_proof(
                    drain_id=str(uuid.uuid4()),
                    authority_generation=generation,
                    activated_at_epoch=100,
                    activated_by_uid=os.geteuid(),
                    drained_at_epoch=101,
                    broker_instance_id="broker-test-instance",
                )
                connection.execute(
                    """
                    INSERT INTO broker_test_admission_fences(
                        singleton, schema_version, purpose, drain_id,
                        authority_generation, activated_at_epoch,
                        activated_by_uid, drained_at_epoch, broker_instance_id,
                        observed_inflight_submissions, active, proof_sha256
                    ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        proof["schema_version"], proof["purpose"], proof["drain_id"],
                        proof["authority_generation"], proof["activated_at_epoch"],
                        proof["activated_by_uid"], proof["drained_at_epoch"],
                        proof["broker_instance_id"], proof["observed_inflight_submissions"],
                        proof["active"], proof["proof_sha256"],
                    ),
                )
        proof_path = self.root / "authority-drain-proof.json"
        proof_path.write_text(json.dumps(dict(proof)) + "\n", encoding="utf-8")
        proof_path.chmod(0o600)
        normalized, fingerprint = MIGRATION_CLI._verify_drain_proof(
            self.authority_path, proof_path, expected_uid=os.geteuid()
        )
        self.assertEqual(dict(normalized), dict(proof))
        self.assertEqual(len(fingerprint), 64)

        forged = dict(proof)
        forged["drain_id"] = str(uuid.uuid4())
        forged = dict(
            build_legacy_test_admission_drain_proof(
                drain_id=forged["drain_id"],
                authority_generation=generation,
                activated_at_epoch=100,
                activated_by_uid=os.geteuid(),
                drained_at_epoch=101,
                broker_instance_id="broker-test-instance",
            )
        )
        proof_path.write_text(json.dumps(forged) + "\n", encoding="utf-8")
        proof_path.chmod(0o600)
        with self.assertRaisesRegex(TestStoreContractError, "does not match authority"):
            MIGRATION_CLI._verify_drain_proof(
                self.authority_path, proof_path, expected_uid=os.geteuid()
            )


if __name__ == "__main__":
    unittest.main()
