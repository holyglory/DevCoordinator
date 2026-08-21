from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator import agent_cli, agent_mcp  # noqa: E402


def _message(method: str, *, identity: object = 1, params: object = None) -> bytes:
    document = {"jsonrpc": "2.0", "id": identity, "method": method}
    if params is not None:
        document["params"] = params
    return json.dumps(document, separators=(",", ":")).encode("utf-8") + b"\n"


def _initialized_session(*requests: bytes) -> bytes:
    initialize = _message(
        "initialize",
        params={
            "protocolVersion": agent_mcp.MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1"},
        },
    )
    initialized = b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    return initialize + initialized + b"".join(requests)


def _responses(raw: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in raw.splitlines()]


class AgentMcpProtocolTests(unittest.TestCase):
    def test_help_never_starts_stdio_server(self) -> None:
        with (
            mock.patch.object(agent_mcp, "serve") as serve,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            with self.assertRaises(SystemExit) as raised:
                agent_mcp.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        serve.assert_not_called()

    def test_only_the_current_protocol_version_is_accepted(self) -> None:
        session = agent_mcp.McpSession()
        accepted = session.handle(
            {
                "jsonrpc": "2.0",
                "id": "current-version",
                "method": "initialize",
                "params": {
                    "protocolVersion": agent_mcp.MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "client", "version": "1"},
                },
            }
        )
        self.assertEqual(
            accepted["result"]["protocolVersion"], agent_mcp.MCP_PROTOCOL_VERSION
        )
        self.assertEqual(
            accepted["result"]["capabilities"]["tools"],
            {"listChanged": False},
        )

        for version in ("2025-06-18", "2099-01-01"):
            with self.subTest(version=version):
                rejected_session = agent_mcp.McpSession()
                rejected = rejected_session.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": "unsupported-version",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": version,
                            "capabilities": {},
                            "clientInfo": {"name": "client", "version": "1"},
                        },
                    }
                )
                self.assertNotIn("result", rejected)
                self.assertEqual(rejected["error"]["code"], -32602)
                self.assertEqual(
                    rejected["error"]["data"],
                    {
                        "code": "protocol_version_unsupported",
                        "requested": version,
                        "supported": agent_mcp.MCP_PROTOCOL_VERSION,
                    },
                )
                self.assertIsNone(rejected_session.protocol_version)
                self.assertFalse(rejected_session.initialize_replied)
                self.assertLessEqual(
                    len(json.dumps(rejected, separators=(",", ":")).encode()),
                    512,
                )

    def test_initialized_notification_is_required_before_tools(self) -> None:
        session = agent_mcp.McpSession()
        before = session.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(before["error"]["code"], -32002)
        initialization = session.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {
                    "protocolVersion": agent_mcp.MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "client", "version": "1"},
                },
            }
        )
        self.assertIn("result", initialization)
        waiting = session.handle(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        )
        self.assertEqual(waiting["error"]["code"], -32002)
        notification = session.handle(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        self.assertIsNone(notification)
        listed = session.handle(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}
        )
        self.assertEqual(len(listed["result"]["tools"]), 12)

    def test_stdio_emits_only_one_finite_json_rpc_line_per_response(self) -> None:
        input_stream = io.BytesIO(
            _initialized_session(
                _message("ping", identity="ping", params={}),
                _message("tools/list", identity="tools", params={}),
            )
        )
        output_stream = io.BytesIO()
        self.assertEqual(agent_mcp.serve(input_stream, output_stream), 0)
        raw = output_stream.getvalue()
        documents = _responses(raw)
        self.assertEqual([item["id"] for item in documents], [1, "ping", "tools"])
        for line in raw.splitlines(keepends=True):
            self.assertTrue(line.endswith(b"\n"))
            self.assertLessEqual(len(line), agent_mcp.MAX_MCP_RESPONSE_BYTES)
            self.assertEqual(json.loads(line)["jsonrpc"], "2.0")

    def test_malformed_json_is_bounded_and_does_not_poison_next_line(self) -> None:
        input_stream = io.BytesIO(b"{invalid\n" + _message("ping", identity=9))
        output_stream = io.BytesIO()
        self.assertEqual(agent_mcp.serve(input_stream, output_stream), 0)
        replies = _responses(output_stream.getvalue())
        self.assertEqual(replies[0]["error"]["code"], -32700)
        self.assertEqual(replies[1], {"id": 9, "jsonrpc": "2.0", "result": {}})

    def test_oversized_request_fails_once_without_treating_suffix_as_a_message(self) -> None:
        input_stream = io.BytesIO(b"x" * (agent_mcp.MAX_MCP_REQUEST_BYTES + 2) + b"\n")
        output_stream = io.BytesIO()
        self.assertEqual(agent_mcp.serve(input_stream, output_stream), 1)
        replies = _responses(output_stream.getvalue())
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], -32700)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self) -> None:
        raw = (
            b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n'
            b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}\n'
        )
        output = io.BytesIO()
        self.assertEqual(agent_mcp.serve(io.BytesIO(raw), output), 0)
        replies = _responses(output.getvalue())
        self.assertEqual([item["error"]["code"] for item in replies], [-32700, -32700])


class AgentMcpToolTests(unittest.TestCase):
    def test_tool_catalog_is_complete_path_free_and_truthfully_annotated(self) -> None:
        tools = {tool["name"]: tool for tool in agent_mcp.TOOLS}
        self.assertEqual(
            set(tools),
            {
                "capabilities",
                "targets",
                "runtime_status",
                "runtime_ensure",
                "operation_follow",
                "test_run",
                "test_follow",
                "test_cancel",
                "test_artifact",
                "bug_report",
                "bug_list",
                "bug_close",
            },
        )
        for tool in tools.values():
            self.assertEqual(tool["inputSchema"]["additionalProperties"], False)
            self.assertEqual(tool["outputSchema"], {"type": "object"})
            self.assertFalse(tool["annotations"]["openWorldHint"])
            properties = tool["inputSchema"].get("properties", {})
            self.assertTrue(
                {"project", "root_repo", "temporary_repo", "path"}.isdisjoint(
                    properties
                )
            )
        for name in (
            "capabilities",
            "targets",
            "runtime_status",
            "operation_follow",
            "test_follow",
            "test_artifact",
            "bug_list",
        ):
            annotations = tools[name]["annotations"]
            self.assertTrue(annotations["readOnlyHint"])
            self.assertFalse(annotations["destructiveHint"])
            self.assertTrue(annotations["idempotentHint"])
        self.assertEqual(
            tools["runtime_ensure"]["annotations"],
            {
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        )
        for name in ("test_run",):
            self.assertFalse(tools[name]["annotations"]["readOnlyHint"])
            self.assertFalse(tools[name]["annotations"]["destructiveHint"])
            self.assertFalse(tools[name]["annotations"]["idempotentHint"])
        self.assertEqual(
            tools["bug_close"]["annotations"],
            {
                "readOnlyHint": False,
                "destructiveHint": True,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        )
        self.assertFalse(tools["bug_report"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["bug_report"]["annotations"]["idempotentHint"])

    def test_success_is_returned_as_matching_structured_and_compact_text(self) -> None:
        expected = {"schema_version": 1, "ok": True, "value": "small"}
        with mock.patch.object(agent_cli, "_execute", return_value=expected):
            result = agent_mcp._call_tool("capabilities", {})
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"], expected)
        self.assertEqual(json.loads(result["content"][0]["text"]), expected)
        self.assertNotIn("\n", result["content"][0]["text"])

    def test_test_run_generates_mutation_uuid_before_execute(self) -> None:
        seen = {}

        def execute(namespace):
            seen["namespace"] = namespace
            return {
                "schema_version": 1,
                "ok": True,
                "operation_id": namespace.operation_id,
            }

        with mock.patch.object(agent_cli, "_execute", side_effect=execute):
            result = agent_mcp._call_tool("test_run", {"intent": "change"})
        operation_id = seen["namespace"].operation_id
        self.assertEqual(str(uuid.UUID(operation_id)), operation_id)
        self.assertEqual(result["structuredContent"]["operation_id"], operation_id)

    def test_runtime_ensure_generates_mutation_uuid_before_execute(self) -> None:
        seen = {}

        def execute(namespace):
            seen["namespace"] = namespace
            return {
                "schema_version": 1,
                "ok": True,
                "operation_id": namespace.operation_id,
            }

        with mock.patch.object(agent_cli, "_execute", side_effect=execute):
            result = agent_mcp._call_tool(
                "runtime_ensure", {"selector": "server-1", "desired": "ready"}
            )
        namespace = seen["namespace"]
        self.assertEqual(namespace.command, "runtime")
        self.assertEqual(namespace.action, "ensure")
        self.assertEqual(namespace.desired, "ready")
        self.assertEqual(str(uuid.UUID(namespace.operation_id)), namespace.operation_id)
        self.assertEqual(
            result["structuredContent"]["operation_id"], namespace.operation_id
        )

    def test_explicit_replay_uuid_is_preserved(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"

        def execute(namespace):
            return {
                "schema_version": 1,
                "ok": True,
                "operation_id": namespace.operation_id,
            }

        with mock.patch.object(agent_cli, "_execute", side_effect=execute):
            result = agent_mcp._call_tool(
                "test_run",
                {"intent": "manual", "targets": ["unit"], "operation_id": operation_id},
            )
        self.assertEqual(result["structuredContent"]["operation_id"], operation_id)

    def test_operation_follow_uses_exact_stable_parser_form(self) -> None:
        captured = {}

        def execute(namespace):
            captured["namespace"] = namespace
            return {"schema_version": 1, "ok": True}

        handle = "dc1:operation:00000000-0000-4000-8000-000000000001"
        with mock.patch.object(agent_cli, "_execute", side_effect=execute):
            result = agent_mcp._call_tool(
                "operation_follow", {"operation": handle}
            )
        self.assertFalse(result["isError"])
        self.assertEqual(captured["namespace"].command, "operation")
        self.assertEqual(captured["namespace"].action, "follow")
        self.assertEqual(captured["namespace"].operation, handle)

    def test_runtime_ensure_builds_the_exact_stable_cli_shape(self) -> None:
        operation_id = "00000000-0000-4000-8000-000000000001"
        self.assertEqual(
            agent_mcp._argv_for_tool(
                "runtime_ensure",
                {
                    "selector": "server-1",
                    "desired": "stopped",
                    "kind": "service",
                    "operation_id": operation_id,
                },
            ),
            [
                "runtime",
                "ensure",
                "server-1",
                "--desired",
                "stopped",
                "--kind",
                "service",
                "--operation-id",
                operation_id,
            ],
        )

    def test_bug_report_is_out_of_band_and_uses_structured_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.dict(
                    os.environ,
                    {"DEVCOORDINATOR_BUG_DIR": str(Path(temporary) / "open")},
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
                mock.patch(
                    "devcoordinator.call_journal.configured_call_journal",
                ) as configured_call_journal,
            ):
                result = agent_mcp._call_tool(
                    "bug_report",
                    {
                        "component": "testd",
                        "summary": "attempt did not launch",
                        "expected": "attempt starts",
                        "actual": "request_timeout",
                        "steps": ["submit one immutable run"],
                        "command_argv": [
                            "devcoordinator",
                            "test",
                            "enqueue",
                            "--token",
                            "secret",
                        ],
                        "run_id": "run-1",
                        "local_fallback": {
                            "status": "passed",
                            "command_argv": ["python", "-m", "pytest"],
                            "summary": "isolated tests passed",
                        },
                    },
                )
                configured_call_journal.assert_not_called()
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["action"], "bug_reported")

    def test_bug_tool_cli_shapes_are_stable(self) -> None:
        self.assertEqual(
            agent_mcp._argv_for_tool(
                "bug_list", {"component": "testd", "limit": 3}
            ),
            ["bug", "list", "--limit", "3", "--component", "testd"],
        )
        self.assertEqual(
            agent_mcp._argv_for_tool(
                "bug_close", {"bug_id": "bug-" + "a" * 32}
            ),
            ["bug", "close", "bug-" + "a" * 32],
        )

    def test_parser_contract_mismatch_preserves_current_client_error(self) -> None:
        parser = mock.Mock()
        parser.parse_args.side_effect = agent_cli.AgentCliError(
            "invalid_arguments", "ensure is not installed"
        )
        with mock.patch.object(agent_cli, "_parser", return_value=parser):
            result = agent_mcp._call_tool(
                "runtime_ensure", {"selector": "server-1", "desired": "ready"}
            )
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["code"], "invalid_arguments"
        )
        self.assertEqual(
            result["structuredContent"]["classification"],
            "invalid_request",
        )

    def test_agent_failure_uses_existing_bounded_error_envelope(self) -> None:
        with mock.patch.object(
            agent_cli,
            "_execute",
            side_effect=agent_cli.AgentCliError(
                "target_not_found", "no exact authoritative target"
            ),
        ):
            result = agent_mcp._call_tool(
                "runtime_status", {"selector": "missing"}
            )
        self.assertTrue(result["isError"])
        error = result["structuredContent"]
        self.assertEqual(error["code"], "target_not_found")
        self.assertEqual(error["classification"], "invalid_request")
        self.assertEqual(json.loads(result["content"][0]["text"]), error)
        self.assertLessEqual(
            len(result["content"][0]["text"].encode("utf-8")), 8192
        )

    def test_mutation_transport_failure_preserves_recovery_operation(self) -> None:
        seen = {}

        def fail(namespace):
            seen["operation_id"] = namespace.operation_id
            raise OSError("broker reply was lost")

        with mock.patch.object(agent_cli, "_execute", side_effect=fail):
            result = agent_mcp._call_tool(
                "test_run", {"intent": "checkpoint"}
            )
        error = result["structuredContent"]
        self.assertTrue(result["isError"])
        self.assertEqual(error["code"], "transport_failure")
        self.assertEqual(error["outcome"], "uncertain")
        self.assertIsNone(error["mutation_performed"])
        self.assertEqual(error["operation_id"], seen["operation_id"])
        self.assertEqual(
            error["continuation"], "dc1:operation:" + seen["operation_id"]
        )

    def test_mutation_call_journal_records_generated_identity_before_execute(self) -> None:
        from devcoordinator import call_journal

        journal = mock.Mock()

        def execute(namespace):
            return {
                "schema_version": 1,
                "ok": True,
                "operation_id": namespace.operation_id,
            }

        with (
            mock.patch.object(
                call_journal, "configured_call_journal", return_value=journal
            ),
            mock.patch.object(agent_cli, "_execute", side_effect=execute),
        ):
            result = agent_mcp._call_tool(
                "test_run", {"intent": "change"}
            )
        records = [call.args[0] for call in journal.record.call_args_list]
        self.assertEqual([record["phase"] for record in records], ["received", "completed"])
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(
            records[0]["operation_id"],
            result["structuredContent"]["operation_id"],
        )
        self.assertEqual(records[1]["outcome"], "ok")

    def test_argument_validation_is_bounded_and_does_not_execute(self) -> None:
        with mock.patch.object(agent_cli, "_execute") as execute:
            result = agent_mcp._call_tool(
                "targets", {"limit": True, "unknown": "value"}
            )
        execute.assert_not_called()
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["code"], "invalid_arguments")

    def test_tools_call_protocol_wraps_tool_errors_in_call_result(self) -> None:
        request = _message(
            "tools/call",
            identity="call",
            params={"name": "targets", "arguments": {"limit": 0}},
        )
        output = io.BytesIO()
        with mock.patch.object(agent_cli, "_execute") as execute:
            self.assertEqual(
                agent_mcp.serve(io.BytesIO(_initialized_session(request)), output),
                0,
            )
        execute.assert_not_called()
        replies = _responses(output.getvalue())
        call = replies[-1]
        self.assertNotIn("error", call)
        self.assertTrue(call["result"]["isError"])
        self.assertEqual(
            call["result"]["structuredContent"]["code"], "invalid_arguments"
        )


if __name__ == "__main__":
    unittest.main()
