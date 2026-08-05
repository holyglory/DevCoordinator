from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from devcoordinator import agent_cli, bug_registry


class BugRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bug_dir = Path(self.temporary.name) / "shared" / "open"

    def _report(self, **overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "component": "testd",
            "summary": "attempt could not launch",
            "expected": "the immutable test attempt starts",
            "actual": "request_timeout before launch",
            "reproduction_steps": [
                "validate the manifest",
                "submit one immutable run",
            ],
            "command_argv": ["devcoordinator", "test", "enqueue"],
            "reporter": "codex:thread-1",
            "surface": "agent_cli",
            "operation": "test.enqueue",
            "classification": "infrastructure_failure",
            "code": "request_timeout",
            "stage": "launch",
            "repository": "/home/developer/project",
            "correlations": {"run_id": "run-1"},
            "bug_dir": self.bug_dir,
        }
        arguments.update(overrides)
        return bug_registry.report_bug(**arguments)

    def test_report_list_close_and_post_close_recurrence(self) -> None:
        first = self._report()
        bug_id = first["bug"]["bug_id"]
        path = self.bug_dir / f"{bug_id}.json"
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o666)
        self.assertEqual(self.bug_dir.stat().st_mode & 0o777, 0o777)

        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 1)
        self.assertEqual(listing["bugs"][0]["bug_id"], bug_id)
        self.assertFalse(listing["truncated"])

        closed = bug_registry.close_bug(bug_id=bug_id, bug_dir=self.bug_dir)
        self.assertTrue(closed["removed"])
        self.assertFalse(path.exists())
        repeated = bug_registry.close_bug(bug_id=bug_id, bug_dir=self.bug_dir)
        self.assertFalse(repeated["removed"])

        recurrence = self._report()
        self.assertNotEqual(recurrence["bug"]["bug_id"], bug_id)

    def test_same_open_fingerprint_dedupes_across_release_and_instance(self) -> None:
        first = self._report(
            release_digest="1" * 64,
            instance_id="blue",
            correlations={"call_id": "call-1"},
        )
        second = self._report(
            release_digest="2" * 64,
            instance_id="green",
            correlations={"call_id": "call-2"},
        )
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(first["bug"]["bug_id"], second["bug"]["bug_id"])
        self.assertEqual(second["bug"]["occurrence_count"], 2)
        stored = json.loads(
            (self.bug_dir / f"{first['bug']['bug_id']}.json").read_text()
        )
        self.assertEqual(stored["release_digest"], "2" * 64)
        self.assertEqual(stored["instance_id"], "green")
        self.assertEqual(stored["correlations"], {"call_id": "call-2"})

    def test_imported_origin_is_portable_and_never_swallows_a_local_report(self) -> None:
        local = self._report()
        local_path = self.bug_dir / f"{local['bug']['bug_id']}.json"
        imported = json.loads(local_path.read_text(encoding="utf-8"))
        local_path.unlink()
        imported["bug_id"] = "bug-" + "e" * 32
        imported["origin"] = {
            "kind": "remote",
            "server_id": "remote.example.test",
            "bug_id": local["bug"]["bug_id"],
            "fingerprint": imported["fingerprint"],
        }
        imported["fingerprint"] = bug_registry._fingerprint(imported)
        imported_path = self.bug_dir / f"{imported['bug_id']}.json"
        imported_path.write_bytes(bug_registry._canonical_bytes(imported))

        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 1)
        self.assertEqual(
            listing["bugs"][0]["origin"],
            {
                "kind": "remote",
                "server_id": "remote.example.test",
                "bug_id": local["bug"]["bug_id"],
                "fingerprint": local["bug"]["fingerprint"],
            },
        )

        observed_here = self._report()
        self.assertFalse(observed_here["deduplicated"])
        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 2)
        self.assertEqual(
            {"remote" if "origin" in bug else "local" for bug in listing["bugs"]},
            {"local", "remote"},
        )

    def test_concurrent_identical_reports_converge(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _index: self._report(), range(24)))
        identities = {result["bug"]["bug_id"] for result in results}
        self.assertEqual(len(identities), 1)
        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 1)
        self.assertEqual(listing["bugs"][0]["occurrence_count"], 24)

    def test_concurrent_readers_never_observe_partial_writer_files(self) -> None:
        start = threading.Event()
        reader_results: list[dict[str, object]] = []

        def writer(index: int) -> None:
            start.wait()
            self._report(
                summary=f"attempt could not launch {index}",
                correlations={"attempt_id": f"attempt-{index}"},
            )

        def reader() -> None:
            start.wait()
            for _index in range(40):
                reader_results.append(
                    bug_registry.list_bugs(limit=20, bug_dir=self.bug_dir)
                )

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(writer, index) for index in range(32)]
            futures.extend(pool.submit(reader) for _index in range(3))
            start.set()
            for future in futures:
                future.result()

        self.assertTrue(reader_results)
        self.assertTrue(
            all(result["malformed_count"] == 0 for result in reader_results)
        )
        listing = bug_registry.list_bugs(limit=20, bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 32)
        self.assertTrue(listing["truncated"])

    def test_secrets_are_redacted_in_text_and_structured_argv(self) -> None:
        result = self._report(
            actual=(
                'authorization=super-secret Bearer abc.def '
                '{"access_token":"sk-secret","token_count":12} '
                'AWS_SECRET_ACCESS_KEY=aws-secret tokens_processed=9'
            ),
            command_argv=[
                "client",
                "--token",
                "secret-value",
                "--password=another-secret",
                "--header",
                "Authorization: Basic dXNlcjpwYXNzd29yZA==",
                "https://user:password@example.invalid/path",
            ],
            local_fallback={
                "status": "failed",
                "command_argv": ["pytest", "--api-key", "secret-key"],
                "summary": "token=still-secret",
            },
        )
        raw = (
            self.bug_dir / f"{result['bug']['bug_id']}.json"
        ).read_text(encoding="utf-8")
        for secret in (
            "super-secret",
            "abc.def",
            "secret-value",
            "another-secret",
            "dXNlcjpwYXNzd29yZA==",
            "user:password",
            "secret-key",
            "still-secret",
            "sk-secret",
            "aws-secret",
        ):
            self.assertNotIn(secret, raw)
        stored = json.loads(raw)
        self.assertIn("token_count", stored["actual"])
        self.assertIn("tokens_processed=9", stored["actual"])
        self.assertEqual(stored["command_argv"][2], "[REDACTED]")
        self.assertTrue(stored["local_fallback"]["advisory"])
        self.assertFalse(stored["local_fallback"]["coordinator_evidence"])

    def test_malformed_or_noncanonical_files_are_isolated(self) -> None:
        self.bug_dir.mkdir(parents=True)
        malformed = self.bug_dir / ("bug-" + "a" * 32 + ".json")
        malformed.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "bug_id": "bug-" + "a" * 32,
                    "fingerprint": "b" * 64,
                    "component": "testd",
                    "summary": "token=secret",
                }
            ),
            encoding="utf-8",
        )
        before = malformed.read_bytes()
        reported = self._report()
        self.assertFalse(reported["deduplicated"])
        self.assertEqual(malformed.read_bytes(), before)
        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["malformed_count"], 1)
        self.assertEqual(listing["open_count"], 1)
        self.assertNotIn("secret", json.dumps(listing))

    def test_oversized_file_is_isolated_and_never_returned(self) -> None:
        self.bug_dir.mkdir(parents=True)
        oversized = self.bug_dir / ("bug-" + "c" * 32 + ".json")
        oversized.write_bytes(b"{" + b"x" * bug_registry.MAX_BUG_FILE_BYTES + b"}")
        listing = bug_registry.list_bugs(bug_dir=self.bug_dir)
        self.assertEqual(listing["open_count"], 0)
        self.assertEqual(listing["malformed_count"], 1)
        self.assertEqual(listing["bugs"], [])

    def test_result_bound_includes_the_launcher_newline(self) -> None:
        empty_size = len(bug_registry._canonical_bytes({"value": ""}))
        exact_payload = {
            "value": "x" * (bug_registry.MAX_RESULT_BYTES - empty_size)
        }
        self.assertEqual(
            len(bug_registry._canonical_bytes(exact_payload)),
            bug_registry.MAX_RESULT_BYTES,
        )
        with self.assertRaisesRegex(
            bug_registry.BugRegistryError,
            "bounded contract",
        ):
            bug_registry._bounded_result(exact_payload)

        wire_sized = {
            "value": "x" * (bug_registry.MAX_RESULT_BYTES - empty_size - 1)
        }
        self.assertEqual(
            len(bug_registry._canonical_bytes(wire_sized)) + 1,
            bug_registry.MAX_RESULT_BYTES,
        )
        self.assertEqual(bug_registry._bounded_result(wire_sized), wire_sized)

    def test_agent_cli_bug_command_bypasses_repository_profile_and_authority(self) -> None:
        namespace = agent_cli._parser().parse_args(
            [
                "bug",
                "report",
                "--component",
                "authority",
                "--summary",
                "socket unavailable",
                "--expected",
                "authority replies",
                "--actual",
                "ECONNREFUSED",
                "--step",
                "run capabilities",
            ]
        )
        with (
            mock.patch.dict(
                os.environ,
                {bug_registry.BUG_REGISTRY_DIR_ENV: str(self.bug_dir)},
                clear=False,
            ),
            mock.patch.object(
                agent_cli,
                "_repository_context",
                side_effect=AssertionError("repository lookup must not run"),
            ),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                side_effect=AssertionError("profile lookup must not run"),
            ),
        ):
            result = agent_cli._execute(namespace)
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "bug_reported")

    def test_integrated_main_does_not_require_call_journal_or_profile(self) -> None:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        with (
            mock.patch.dict(
                os.environ,
                {bug_registry.BUG_REGISTRY_DIR_ENV: str(self.bug_dir)},
                clear=False,
            ),
            mock.patch.object(agent_cli.sys, "stdout", stream),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
            ) as configured_call_journal,
            mock.patch.object(
                agent_cli,
                "_repository_context",
                side_effect=AssertionError("repository lookup must not run"),
            ),
            mock.patch.object(
                agent_cli,
                "_profile_and_capabilities",
                side_effect=AssertionError("profile lookup must not run"),
            ),
        ):
            returncode = agent_cli.main(
                [
                    "bug",
                    "report",
                    "--component",
                    "api",
                    "--summary",
                    "API unavailable",
                    "--expected",
                    "API replies",
                    "--actual",
                    "socket refused",
                    "--step",
                    "run capabilities",
                ]
            )
        self.assertEqual(returncode, 0)
        configured_call_journal.assert_not_called()
        result = json.loads(stream.buffer.getvalue())
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "bug_reported")

    def test_dedicated_main_does_not_require_call_journal(self) -> None:
        stream = mock.Mock()
        stream.buffer = io.BytesIO()
        stream.flush = mock.Mock()
        with (
            mock.patch.dict(
                os.environ,
                {bug_registry.BUG_REGISTRY_DIR_ENV: str(self.bug_dir)},
                clear=False,
            ),
            mock.patch.object(bug_registry.sys, "stdout", stream),
            mock.patch(
                "devcoordinator.call_journal.configured_call_journal",
            ) as configured_call_journal,
        ):
            returncode = bug_registry.main(
                [
                    "report",
                    "--component",
                    "testd",
                    "--summary",
                    "worker unavailable",
                    "--expected",
                    "worker leases attempt",
                    "--actual",
                    "no lease",
                    "--step",
                    "submit one run",
                ]
            )
        self.assertEqual(returncode, 0)
        configured_call_journal.assert_not_called()
        raw = stream.buffer.getvalue()
        self.assertLessEqual(len(raw), bug_registry.MAX_RESULT_BYTES)
        self.assertTrue(json.loads(raw)["ok"])


if __name__ == "__main__":
    unittest.main()
