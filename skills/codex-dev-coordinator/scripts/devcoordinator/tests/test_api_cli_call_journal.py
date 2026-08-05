from __future__ import annotations

import argparse
import errno
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dev_coordinator
from devcoordinator.call_journal import RollingCallJournal, read_call_records


class _MemoryWriter:
    def __init__(self) -> None:
        self.body = bytearray()
        self.flushed = False

    def write(self, value: bytes) -> int:
        self.body.extend(value)
        return len(value)

    def flush(self) -> None:
        self.flushed = True


class _BrokenWriter(_MemoryWriter):
    def write(self, value: bytes) -> int:
        raise BrokenPipeError(errno.EPIPE, "fixture client disconnected")


class _FlushBrokenWriter(_MemoryWriter):
    def flush(self) -> None:
        raise ConnectionResetError(errno.ECONNRESET, "fixture reset during flush")


class _ExplodingJournal:
    def record(self, _record: object) -> bool:
        raise OSError("fixture journal unavailable")


def _handler(path: str, writer: _MemoryWriter) -> dev_coordinator.ApiHandler:
    handler = object.__new__(dev_coordinator.ApiHandler)
    handler.command = "GET"
    handler.path = path
    handler.close_connection = False
    handler.wfile = writer
    handler.send_response = mock.Mock()
    handler.send_header = mock.Mock()
    handler.end_headers = mock.Mock()
    return handler


class ApiCallJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="devcoordinator-api-call-journal-", dir="/tmp"
        )
        self.path = Path(self.temporary.name) / "calls.jsonl"
        self.journal = RollingCallJournal(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _records(self) -> list[dict[str, object]]:
        return list(read_call_records(self.path))

    def test_success_is_recorded_only_after_body_flush_with_safe_run_id(self) -> None:
        writer = _MemoryWriter()
        handler = _handler(
            "/v1/test-runs/run-abc/summary?token=must-not-appear", writer
        )
        with (
            mock.patch.object(
                dev_coordinator, "COORDINATOR_CALL_JOURNAL", self.journal
            ),
            mock.patch.object(
                dev_coordinator.ApiHandler,
                "_dispatch_request",
                lambda current: current._send(
                    200,
                    {
                        "ok": True,
                        "code": "successful-payload-code-must-not-appear",
                        "secret": "must-not-appear",
                    },
                ),
            ),
        ):
            handler._handle_request()

        records = self._records()
        self.assertTrue(writer.flushed)
        self.assertEqual(
            [record["phase"] for record in records], ["received", "completed"]
        )
        self.assertEqual(records[0]["run_id"], "run-abc")
        self.assertEqual(records[1]["run_id"], "run-abc")
        self.assertEqual(records[1]["outcome"], "ok")
        self.assertIsNone(records[1]["code"])
        retained = self.path.read_text(encoding="utf-8")
        self.assertNotIn("must-not-appear", retained)
        self.assertNotIn("successful-payload-code", retained)
        self.assertNotIn("token", retained)

    def test_disconnect_is_a_linked_terminal_delivery_failure(self) -> None:
        handler = _handler("/v1/test-runs/run-broken/failures", _BrokenWriter())
        with (
            mock.patch.object(
                dev_coordinator, "COORDINATOR_CALL_JOURNAL", self.journal
            ),
            mock.patch.object(
                dev_coordinator.ApiHandler,
                "_dispatch_request",
                lambda current: current._send(200, {"ok": True}),
            ),
        ):
            handler._handle_request()

        received, completed = self._records()
        self.assertEqual(received["call_id"], completed["call_id"])
        self.assertEqual(completed["run_id"], "run-broken")
        self.assertEqual(completed["outcome"], "unavailable")
        self.assertEqual(completed["code"], "http_response_delivery_failed")
        self.assertEqual(completed["diagnostic"]["errno"], "EPIPE")
        self.assertTrue(handler.close_connection)

    def test_flush_failure_cannot_be_recorded_as_success(self) -> None:
        handler = _handler("/v1/test-runs/run-reset/summary", _FlushBrokenWriter())
        with (
            mock.patch.object(
                dev_coordinator, "COORDINATOR_CALL_JOURNAL", self.journal
            ),
            mock.patch.object(
                dev_coordinator.ApiHandler,
                "_dispatch_request",
                lambda current: current._send(200, {"ok": True}),
            ),
        ):
            handler._handle_request()

        completed = self._records()[-1]
        self.assertEqual(completed["outcome"], "unavailable")
        self.assertEqual(completed["code"], "http_response_delivery_failed")
        self.assertEqual(completed["diagnostic"]["errno"], "ECONNRESET")

    def test_dynamic_repository_correlation_never_uses_a_raw_route(self) -> None:
        route, run_id, repository_id = dev_coordinator._api_call_journal_context(
            "/v1/test-repositories/repo-123/setup"
        )
        self.assertEqual(route, "v1.tests.resource")
        self.assertIsNone(run_id)
        self.assertEqual(repository_id, "repo-123")

        route, run_id, repository_id = dev_coordinator._api_call_journal_context(
            "/v1/test-repositories/repo%2Fprivate/setup"
        )
        self.assertEqual(route, "v1.tests.resource")
        self.assertIsNone(run_id)
        self.assertIsNone(repository_id)


class CliCallJournalTests(unittest.TestCase):
    @staticmethod
    def _arguments() -> argparse.Namespace:
        return argparse.Namespace(
            group="test",
            action="catalog",
            operation_id=None,
            run_id=None,
        )

    def test_journal_failure_never_changes_cli_result(self) -> None:
        parser = mock.Mock()
        parser.parse_args.return_value = self._arguments()
        with (
            mock.patch.object(dev_coordinator, "build_parser", return_value=parser),
            mock.patch.object(dev_coordinator, "_main_parsed", return_value=0),
            mock.patch.object(
                dev_coordinator, "COORDINATOR_CALL_JOURNAL", _ExplodingJournal()
            ),
        ):
            self.assertEqual(dev_coordinator.main(["test", "catalog"]), 0)

    def test_received_record_exists_before_argument_parsing(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-cli-call-journal-", dir="/tmp"
        ) as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            parser = mock.Mock()

            def parse_arguments(_argv: object) -> argparse.Namespace:
                records = list(read_call_records(path))
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["phase"], "received")
                self.assertEqual(records[0]["operation"], "cli.unknown")
                return self._arguments()

            parser.parse_args.side_effect = parse_arguments
            with (
                mock.patch.object(
                    dev_coordinator, "build_parser", return_value=parser
                ),
                mock.patch.object(dev_coordinator, "_main_parsed", return_value=0),
                mock.patch.object(
                    dev_coordinator, "COORDINATOR_CALL_JOURNAL", journal
                ),
            ):
                self.assertEqual(dev_coordinator.main(["test", "catalog"]), 0)

            received, completed = list(read_call_records(path))
            self.assertEqual(received["call_id"], completed["call_id"])
            self.assertEqual(completed["operation"], "cli.test.catalog")

    def test_malformed_arguments_are_linked_and_use_unknown_operation(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-cli-call-journal-", dir="/tmp"
        ) as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            parser = mock.Mock()
            parser.parse_args.side_effect = SystemExit(2)
            with (
                mock.patch.object(
                    dev_coordinator, "build_parser", return_value=parser
                ),
                mock.patch.object(
                    dev_coordinator, "COORDINATOR_CALL_JOURNAL", journal
                ),
            ):
                with self.assertRaises(SystemExit) as raised:
                    dev_coordinator.main(["not-a-command", "--secret", "hidden"])

            self.assertEqual(raised.exception.code, 2)
            received, completed = list(read_call_records(path))
            self.assertEqual(received["call_id"], completed["call_id"])
            self.assertEqual(received["operation"], "cli.unknown")
            self.assertEqual(completed["operation"], "cli.unknown")
            self.assertEqual(completed["outcome"], "rejected")
            self.assertEqual(completed["code"], "cli_argument_error")
            self.assertEqual(
                completed["diagnostic"]["stage"], "argument_parsing"
            )
            self.assertEqual(
                completed["diagnostic"]["exception_type"], "SystemExit"
            )
            retained = path.read_text(encoding="utf-8")
            self.assertNotIn("not-a-command", retained)
            self.assertNotIn("hidden", retained)

    def test_typed_execution_failure_survives_exit_code_flattening(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-cli-call-journal-", dir="/tmp"
        ) as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            parser = mock.Mock()
            parser.parse_args.return_value = self._arguments()
            failure = dev_coordinator.StructuredCoordinatorError(
                (
                    "immutable Python dependency executable "
                    "/home/example/.venv-v2/bin/python token=must-not-appear"
                ),
                {
                    "code": "python_dependency_unavailable",
                    "classification": "unhealthy_process",
                },
            )
            with (
                mock.patch.object(
                    dev_coordinator, "build_parser", return_value=parser
                ),
                mock.patch.object(dev_coordinator, "handle_cli", side_effect=failure),
                mock.patch("builtins.print"),
                mock.patch.object(
                    dev_coordinator, "COORDINATOR_CALL_JOURNAL", journal
                ),
            ):
                self.assertEqual(dev_coordinator.main(["test", "catalog"]), 1)

            completed = list(read_call_records(path))[-1]
            self.assertEqual(completed["outcome"], "failed")
            self.assertEqual(completed["code"], "python_dependency_unavailable")
            self.assertEqual(
                completed["diagnostic"]["stage"], "command_execution"
            )
            self.assertEqual(
                completed["diagnostic"]["subject"],
                "python_dependency_executable",
            )
            self.assertEqual(
                completed["diagnostic"]["exception_type"],
                "StructuredCoordinatorError",
            )
            retained = path.read_text(encoding="utf-8")
            self.assertNotIn("/home/example", retained)
            self.assertNotIn("must-not-appear", retained)
            self.assertNotIn("cli_exit_1", retained)

    def test_parse_result_is_unchanged_when_event_building_fails(self) -> None:
        parser = mock.Mock()
        parser.parse_args.side_effect = SystemExit(2)
        with (
            mock.patch.object(dev_coordinator, "build_parser", return_value=parser),
            mock.patch.object(
                dev_coordinator, "COORDINATOR_CALL_JOURNAL", _ExplodingJournal()
            ),
            mock.patch.object(
                dev_coordinator,
                "event_record",
                side_effect=RuntimeError("fixture event builder failed"),
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                dev_coordinator.main(["invalid"])
        self.assertEqual(raised.exception.code, 2)

    def test_successful_cli_terminal_record_has_no_error_code(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="devcoordinator-cli-call-journal-", dir="/tmp"
        ) as directory:
            path = Path(directory) / "calls.jsonl"
            journal = RollingCallJournal(path)
            parser = mock.Mock()
            parser.parse_args.return_value = self._arguments()
            with (
                mock.patch.object(
                    dev_coordinator, "build_parser", return_value=parser
                ),
                mock.patch.object(dev_coordinator, "_main_parsed", return_value=0),
                mock.patch.object(
                    dev_coordinator, "COORDINATOR_CALL_JOURNAL", journal
                ),
            ):
                self.assertEqual(dev_coordinator.main(["test", "catalog"]), 0)
            records = list(read_call_records(path))
            self.assertEqual(records[0]["phase"], "received")
            self.assertEqual(records[0]["operation"], "cli.unknown")
            self.assertEqual(records[-1]["outcome"], "ok")
            self.assertEqual(records[-1]["operation"], "cli.test.catalog")
            self.assertIsNone(records[-1]["code"])


if __name__ == "__main__":
    unittest.main()
