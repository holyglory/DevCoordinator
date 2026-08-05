from __future__ import annotations

import errno
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
import uuid
from unittest import mock

from devcoordinator.call_journal import (
    CallJournalPageError,
    MAX_CALL_JOURNAL_PAGE_BYTES,
    MAX_CALL_JOURNAL_RECORD_BYTES,
    RollingCallJournal,
    bounded_call_record_page,
    call_record,
    configured_call_journal,
    diagnostic_for_exception,
    event_record,
    read_call_snapshot,
    read_call_records,
)


def _write_across_data_replacement(
    path_value: str,
    ready: object,
    proceed: object,
    results: object,
) -> None:
    path = Path(path_value)
    journal = RollingCallJournal(path)
    first = journal.record(
        event_record(
            boundary="authority",
            phase="completed",
            call_id="child-before-replacement",
            operation="inventory",
            outcome="ok",
        )
    )
    ready.set()  # type: ignore[attr-defined]
    continued = proceed.wait(10)  # type: ignore[attr-defined]
    second = (
        journal.record(
            event_record(
                boundary="authority",
                phase="completed",
                call_id="child-after-replacement",
                operation="inventory",
                outcome="ok",
            )
        )
        if continued
        else None
    )
    results.put((first, second))  # type: ignore[attr-defined]


class CallJournalTests(unittest.TestCase):
    def test_reader_page_is_cursor_bounded_and_pairs_exact_lifecycle(self) -> None:
        records = [
            event_record(
                boundary="test_plane",
                phase="completed",
                call_id=f"unrelated-{index}",
                operation="test.status",
                run_id=f"run-{index}",
                outcome="ok",
            )
            for index in range(6)
        ]
        records.extend(
            [
                event_record(
                    boundary="test_plane",
                    phase="received",
                    call_id="exact-call",
                    operation="test.summary",
                    outcome="received",
                ),
                event_record(
                    boundary="test_plane",
                    phase="rejected",
                    call_id="exact-call",
                    operation="test.summary",
                    operation_id="exact-operation",
                    run_id="exact-run",
                    outcome="failed",
                    code="summary_failed",
                ),
            ]
        )
        encoded = bounded_call_record_page(
            records,
            filters={"run_id": "exact-run"},
            retained_byte_count=123,
            retained_file_count=2,
        )
        self.assertLessEqual(len(encoded), MAX_CALL_JOURNAL_PAGE_BYTES)
        self.assertTrue(encoded.endswith(b"\n"))
        page = json.loads(encoded)
        self.assertEqual(
            [item["call_id"] for item in page["records"]],
            ["exact-call", "exact-call"],
        )
        self.assertEqual(page["pairing"], "exact_call_lifecycle")
        self.assertEqual(page["matched_count"], 1)
        self.assertEqual(page["correlated_record_count"], 2)
        self.assertEqual(page["returned_count"], 2)
        self.assertEqual(page["omitted_count"], 0)
        self.assertEqual(page["retained_byte_count"], 123)
        self.assertEqual(page["retained_file_count"], 2)
        self.assertNotIn("journal", page)
        self.assertNotIn("retained_files", page)

        all_page = json.loads(
            bounded_call_record_page(records, limit=3, retained_file_count=2)
        )
        self.assertEqual(all_page["matched_count"], 8)
        self.assertEqual(all_page["returned_count"], 3)
        self.assertEqual(all_page["omitted_count"], 5)
        cursor = all_page["next_cursor"]
        older = json.loads(
            bounded_call_record_page(records, limit=3, before=cursor)
        )
        self.assertEqual(older["matched_count"], 8)
        self.assertEqual(older["eligible_count"], 5)
        self.assertEqual(older["returned_count"], 3)
        self.assertEqual(older["omitted_count"], 2)

    def test_reader_page_sanitizes_and_bounds_json_and_jsonl_exact_bytes(self) -> None:
        records = []
        for index in range(20):
            record = event_record(
                boundary="authority",
                phase="rejected",
                call_id=f"call-{index}",
                operation="test.plan_preview",
                operation_id=f"operation-{index}",
                run_id=f"run-{index}",
                outcome="failed",
                code="snapshot_failed",
                message=(
                    f"failed at /private/repository/source-{index}.py "
                    "token=top-secret "
                    + ("x" * 2_000)
                ),
            )
            record["raw_payload"] = {
                "source_path": "/must/not/escape",
                "password": "also-secret",
            }
            records.append(record)
        for output_format in ("json", "jsonl"):
            with self.subTest(output_format=output_format):
                encoded = bounded_call_record_page(
                    records,
                    limit=20,
                    output_format=output_format,
                    retained_byte_count=999_999,
                    retained_file_count=5,
                )
                self.assertLessEqual(len(encoded), MAX_CALL_JOURNAL_PAGE_BYTES)
                self.assertTrue(encoded.endswith(b"\n"))
                self.assertNotIn(b"/private/", encoded)
                self.assertNotIn(b"top-secret", encoded)
                self.assertNotIn(b"also-secret", encoded)
                self.assertNotIn(b"raw_payload", encoded)
                if output_format == "json":
                    metadata = json.loads(encoded)
                else:
                    metadata = json.loads(encoded.splitlines()[0])
                self.assertTrue(metadata["fields_truncated"])
                self.assertEqual(metadata["matched_count"], 20)
                self.assertEqual(
                    metadata["returned_count"] + metadata["omitted_count"],
                    20,
                )

    def test_reader_page_rejects_expired_or_unbounded_requests(self) -> None:
        record = event_record(
            boundary="authority",
            phase="completed",
            call_id="call-safe",
            operation="inventory",
            outcome="ok",
        )
        with self.assertRaisesRegex(CallJournalPageError, "cursor"):
            bounded_call_record_page([record], before="missing-record")
        with self.assertRaisesRegex(CallJournalPageError, "1 through 20"):
            bounded_call_record_page([record], limit=21)

    def test_call_record_keeps_only_allowlisted_correlation_and_redacts(self) -> None:
        operation_id = str(uuid.uuid4())
        record = call_record(
            peer_uid=1001,
            peer_gid=1001,
            peer_pid=123,
            document={
                "operation_id": operation_id,
                "operation": "test.plan_preview",
                "account_id": "account-current",
                "project_id": "repo-current",
                "arguments": {
                    "run_id": "run-safe",
                    "argv": ["--password=do-not-record"],
                    "environment": {"TOKEN": "do-not-record"},
                },
            },
            reply={
                "ok": False,
                "operation_id": operation_id,
                "error": {
                    "code": "snapshot_failed",
                    "message": (
                        "token=do-not-record at /home/developer/repo; "
                        "Bearer abc.def"
                    ),
                },
            },
            duration_seconds=0.25,
            call_id="call-safe",
        )
        encoded = json.dumps(record, sort_keys=True)
        self.assertEqual(record["request"], {"run_id": "run-safe"})
        self.assertNotIn("do-not-record", encoded)
        self.assertNotIn("/home/developer/repo", encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertIn("[PATH]", encoded)

    def test_message_redacts_relative_source_paths_and_quoted_secrets(self) -> None:
        record = event_record(
            boundary="snapshotd",
            phase="completed",
            call_id="call-redacted",
            operation="snapshot.resolve",
            outcome="failed",
            code="snapshot_failed",
            message=(
                "snapshot dependency bootstrap failed at "
                "tests/fixtures/private/input.json and .venv-v2/bin/python; "
                "nested/project/source.py; "
                'credentials={"password": "json-value", '
                '"client_secret":"client-value"}; '
                "TOKEN='shell value'; api_key: \"yaml value\"; "
                "--authorization 'command value'; "
                '"github_token":"prefixed value"; retry is safe'
            ),
        )
        message = record["message"]
        self.assertIsInstance(message, str)
        assert isinstance(message, str)
        for forbidden in (
            "tests/fixtures/private/input.json",
            ".venv-v2/bin/python",
            "nested/project/source.py",
            "json-value",
            "client-value",
            "shell value",
            "yaml value",
            "command value",
            "prefixed value",
        ):
            self.assertNotIn(forbidden, message)
        self.assertGreaterEqual(message.count("[PATH]"), 3)
        self.assertGreaterEqual(message.count("[REDACTED]"), 5)
        self.assertIn("snapshot dependency bootstrap failed", message)
        self.assertIn("retry is safe", message)

    def test_append_boundary_resanitizes_message_from_direct_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            self.assertTrue(
                journal.record(
                    {
                        "schema_version": 1,
                        "message": (
                            "tests/private/input.json "
                            'PASSWORD="must-not-appear" useful detail'
                        ),
                    }
                )
            )
            [record] = list(read_call_records(path))
            encoded = json.dumps(record)
            self.assertNotIn("tests/private/input.json", encoded)
            self.assertNotIn("must-not-appear", encoded)
            self.assertIn("useful detail", encoded)

    def test_rotation_is_fixed_and_all_retained_lines_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(
                path, max_bytes=MAX_CALL_JOURNAL_RECORD_BYTES, backups=2
            )
            for index in range(200):
                self.assertTrue(
                    journal.record(
                        event_record(
                            boundary="snapshot",
                            phase="completed",
                            call_id=str(uuid.uuid4()),
                            operation="resolve",
                            request_id=str(uuid.uuid4()),
                            outcome="failed",
                            code="snapshot_failed",
                            message=f"bounded failure {index} " + ("x" * 300),
                        )
                    )
                )
            retained = journal.retained_paths()
            self.assertLessEqual(len(retained), 3)
            self.assertLessEqual(
                sum(item.stat().st_size for item in retained),
                journal.retained_byte_ceiling,
            )
            self.assertTrue(list(read_call_records(path, backups=2)))
            for item in retained:
                self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o666)
                for line in item.read_text(encoding="utf-8").splitlines():
                    self.assertIsInstance(json.loads(line), dict)

    def test_snapshot_reader_is_strictly_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "calls.jsonl"
            journal = RollingCallJournal(path)
            journal.append(
                event_record(
                    boundary="authority",
                    phase="completed",
                    call_id="read-only-call",
                    operation="inventory",
                    outcome="ok",
                )
            )
            lock_path = path.with_name(path.name + ".lock")
            path.chmod(0o444)
            lock_path.chmod(0o444)
            before = {
                item.name: (
                    item.stat().st_ino,
                    item.stat().st_size,
                    stat.S_IMODE(item.stat().st_mode),
                )
                for item in root.iterdir()
            }
            root.chmod(0o555)
            try:
                with (
                    mock.patch(
                        "devcoordinator.call_journal.os.open",
                        wraps=os.open,
                    ) as open_call,
                    mock.patch(
                        "devcoordinator.call_journal.os.fchmod",
                        wraps=os.fchmod,
                    ) as fchmod_call,
                    mock.patch(
                        "devcoordinator.call_journal.fcntl.flock",
                        wraps=fcntl.flock,
                    ) as flock_call,
                ):
                    records, files = read_call_snapshot(path)
                self.assertEqual(
                    [record["call_id"] for record in records],
                    ["read-only-call"],
                )
                self.assertEqual(len(files), 1)
                fchmod_call.assert_not_called()
                self.assertEqual(flock_call.call_args_list[0].args[1], fcntl.LOCK_SH)
                self.assertEqual(flock_call.call_args_list[-1].args[1], fcntl.LOCK_UN)
                self.assertTrue(open_call.call_args_list)
                for call in open_call.call_args_list:
                    flags = call.args[1]
                    self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
                    self.assertFalse(flags & os.O_CREAT)
                after = {
                    item.name: (
                        item.stat().st_ino,
                        item.stat().st_size,
                        stat.S_IMODE(item.stat().st_mode),
                    )
                    for item in root.iterdir()
                }
                self.assertEqual(after, before)
            finally:
                root.chmod(0o755)

    def test_snapshot_reader_missing_journal_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "calls.jsonl"
            root.chmod(0o555)
            try:
                self.assertEqual(read_call_snapshot(path), ([], []))
                self.assertEqual(tuple(root.iterdir()), ())
                self.assertFalse(path.with_name(path.name + ".lock").exists())
            finally:
                root.chmod(0o755)

    def test_snapshot_reader_without_lock_returns_empty_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "calls.jsonl"
            path.write_text(
                json.dumps(
                    event_record(
                        boundary="authority",
                        phase="completed",
                        call_id="unlocked-call",
                        operation="inventory",
                        outcome="ok",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o444)
            root.chmod(0o555)
            try:
                self.assertEqual(read_call_snapshot(path), ([], []))
                self.assertFalse(path.with_name(path.name + ".lock").exists())
            finally:
                root.chmod(0o755)

    def test_concurrent_writers_keep_one_json_object_per_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            journals = [RollingCallJournal(path) for _ in range(8)]

            def write(worker: int) -> None:
                for index in range(100):
                    journals[worker].record(
                        event_record(
                            boundary="authority",
                            phase="completed",
                            call_id=f"call-{worker}-{index}",
                            operation="inventory",
                            outcome="ok",
                        )
                    )

            workers = [threading.Thread(target=write, args=(index,)) for index in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            records = list(read_call_records(path))
            self.assertEqual(len(records), 800)
            self.assertEqual(len({record["call_id"] for record in records}), 800)

    def test_separate_process_writer_rejects_replaced_data_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "calls.jsonl"
            victim = root / "must-not-change.txt"
            victim.write_text("protected\n", encoding="utf-8")
            victim.chmod(0o600)
            context = multiprocessing.get_context("fork")
            ready = context.Event()
            proceed = context.Event()
            results = context.Queue()
            process = context.Process(
                target=_write_across_data_replacement,
                args=(str(path), ready, proceed, results),
            )
            process.start()
            self.assertTrue(ready.wait(10))
            os.replace(path, root / "calls-before-replacement.jsonl")
            path.symlink_to(victim)
            proceed.set()
            first, second = results.get(timeout=10)
            process.join(timeout=10)
            self.assertEqual(process.exitcode, 0)
            self.assertTrue(first)
            self.assertFalse(second)
            self.assertEqual(victim.read_text(encoding="utf-8"), "protected\n")
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o600)

    def test_rejects_symlink_nonregular_and_hardlinked_targets(self) -> None:
        cases = (
            "lock_symlink",
            "data_symlink",
            "data_fifo",
            "data_hardlink",
            "rotation_symlink",
            "rotation_directory",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "calls.jsonl"
                victim = root / "must-not-change.txt"
                victim.write_text("protected\n", encoding="utf-8")
                victim.chmod(0o600)
                target = (
                    path.with_name(path.name + ".lock")
                    if case == "lock_symlink"
                    else path.with_name(path.name + ".1")
                    if case.startswith("rotation_")
                    else path
                )
                if case.endswith("symlink"):
                    target.symlink_to(victim)
                elif case == "data_fifo":
                    os.mkfifo(target)
                elif case == "data_hardlink":
                    os.link(victim, target)
                elif case == "rotation_directory":
                    target.mkdir()
                journal = RollingCallJournal(path, backups=2)
                self.assertFalse(
                    journal.record(
                        event_record(
                            boundary="authority",
                            phase="completed",
                            call_id=f"call-{case}",
                            operation="inventory",
                            outcome="ok",
                        )
                    )
                )
                self.assertEqual(victim.read_text(encoding="utf-8"), "protected\n")
                expected_links = 2 if case == "data_hardlink" else 1
                self.assertEqual(victim.stat().st_nlink, expected_links)
                self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o600)

    def test_backup_decrease_prunes_every_excess_numbered_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            path.write_text("", encoding="utf-8")
            path.with_name(f"{path.name}.1").write_text("x" * 100, encoding="utf-8")
            path.with_name(f"{path.name}.2").write_text(
                "x" * (MAX_CALL_JOURNAL_RECORD_BYTES + 1),
                encoding="utf-8",
            )
            for index in (3, 4, 9, 31):
                path.with_name(f"{path.name}.{index}").write_text(
                    "x" * 100,
                    encoding="utf-8",
                )
            path.with_name(f"{path.name}.0009").write_text(
                "x" * 100,
                encoding="utf-8",
            )
            journal = RollingCallJournal(
                path,
                max_bytes=MAX_CALL_JOURNAL_RECORD_BYTES,
                backups=2,
            )
            self.assertTrue(
                journal.record(
                    event_record(
                        boundary="authority",
                        phase="completed",
                        call_id="call-after-backup-decrease",
                        operation="inventory",
                        outcome="ok",
                    )
                )
            )
            self.assertTrue(path.with_name(f"{path.name}.1").exists())
            self.assertFalse(path.with_name(f"{path.name}.2").exists())
            for index in (3, 4, 9, 31, "0009"):
                self.assertFalse(path.with_name(f"{path.name}.{index}").exists())
            retained = journal.retained_paths()
            self.assertLessEqual(len(retained), 3)
            self.assertLessEqual(
                sum(item.stat().st_size for item in retained),
                journal.retained_byte_ceiling,
            )

    def test_logging_failure_is_best_effort_and_recovery_records_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            record = event_record(
                boundary="authority",
                phase="completed",
                call_id="call-one",
                operation="inventory",
                outcome="ok",
            )
            original = journal.append
            with mock.patch.object(journal, "append", side_effect=OSError("full")):
                self.assertFalse(journal.record(record))
            with mock.patch.object(journal, "append", wraps=original):
                self.assertTrue(journal.record(record))
            records = list(read_call_records(path))
            self.assertEqual([item["code"] for item in records], ["logging_gap", None])

    def test_gap_partial_success_does_not_double_count_omitted_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            record = event_record(
                boundary="authority",
                phase="completed",
                call_id="call-gap-partial",
                operation="inventory",
                outcome="ok",
            )
            with mock.patch.object(journal, "append", side_effect=OSError("full")):
                self.assertFalse(journal.record(record))
            original = journal.append
            calls = 0

            def append_gap_then_fail(value: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    original(value)  # type: ignore[arg-type]
                    return
                raise OSError("full after gap")

            with mock.patch.object(journal, "append", side_effect=append_gap_then_fail):
                self.assertFalse(journal.record(record))
            self.assertTrue(journal.record(record))
            records = list(read_call_records(path))
            gaps = [item for item in records if item.get("code") == "logging_gap"]
            self.assertEqual(len(gaps), 2)
            self.assertEqual(
                [item["message"] for item in gaps],
                [
                    "1 bounded call records could not be written",
                    "1 bounded call records could not be written",
                ],
            )

    def test_exception_diagnostic_keeps_stage_subject_and_errno_without_path(self) -> None:
        try:
            try:
                raise PermissionError(errno.EACCES, "denied", "/private/path")
            except PermissionError as cause:
                raise RuntimeError(
                    "immutable Python dependency executable is unavailable"
                ) from cause
        except RuntimeError as error:
            diagnostic = diagnostic_for_exception(
                error, stage="snapshot.python_dependency"
            )
        self.assertEqual(diagnostic["subject"], "python_dependency_executable")
        self.assertEqual(diagnostic["errno"], "EACCES")
        self.assertEqual(diagnostic["root_exception_type"], "PermissionError")
        self.assertNotIn("/private/path", json.dumps(diagnostic))

    def test_installed_service_configuration_is_explicit_and_bounded(self) -> None:
        self.assertIsNone(configured_call_journal({}))
        configured = configured_call_journal(
            {
                "DEVCOORDINATOR_CALL_LOG": "/var/log/devcoordinator/calls.jsonl",
                "DEVCOORDINATOR_CALL_LOG_MAX_BYTES": "16384",
                "DEVCOORDINATOR_CALL_LOG_BACKUPS": "2",
            }
        )
        self.assertIsNotNone(configured)
        assert configured is not None
        self.assertEqual(configured.max_bytes, 16384)
        self.assertEqual(configured.backups, 2)


if __name__ == "__main__":
    unittest.main()
