"""Dependency-free MCP stdio adapter for the bounded agent client.

The adapter deliberately contains no Coordinator business logic.  It maps a
small, path-free MCP tool vocabulary onto :mod:`devcoordinator.agent_cli`, so
repository discovery, authority negotiation, exact target binding, mutation
replay, and result projection retain one implementation.  Standard output is
reserved exclusively for newline-delimited JSON-RPC messages.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import sys
import time
from typing import Any, BinaryIO
import uuid

from .agent_contract import (
    MAX_AGENT_RESULT_BYTES,
    canonical_json_bytes,
)


MCP_PROTOCOL_VERSION = "2025-11-25"
MCP_SERVER_VERSION = "1.0.0"

# These ceilings include complete serialized messages, not model tokens.  The
# largest agent result is eight KiB; a tool response contains that document
# twice (structured result and protocol-required content mirror), while
# tools/list is also finite and comfortably below this response limit.
MAX_MCP_REQUEST_BYTES = 32 * 1024
MAX_MCP_RESPONSE_BYTES = 32 * 1024

_JSONRPC_PARSE_ERROR = -32700
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS = -32602
_JSONRPC_INTERNAL_ERROR = -32603
_SERVER_NOT_INITIALIZED = -32002

_RESOURCE_KINDS = ("service", "docker", "database_stack")
_OPERATION_ID_PATTERN = (
    "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    "[0-9a-f]{4}-[0-9a-f]{12}$"
)


class AgentMcpError(ValueError):
    """One tool invocation cannot satisfy the stable agent contract."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        classification: str = "invalid_request",
        phase: str = "client",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.classification = classification
        self.phase = phase


def _object_schema(
    properties: Mapping[str, Any] | None = None,
    *,
    required: Sequence[str] = (),
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": dict(properties or {}),
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    return schema


def _string_schema(description: str, *, maximum: int = 256) -> dict[str, Any]:
    return {
        "type": "string",
        "description": description,
        "minLength": 1,
        "maxLength": maximum,
    }


def _operation_id_schema() -> dict[str, Any]:
    return {
        "type": "string",
        "description": "Optional canonical UUID for an exact mutation replay.",
        "pattern": _OPERATION_ID_PATTERN,
    }


def _annotations(
    *,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
) -> dict[str, bool]:
    return {
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        # The authority is the closed set of locally configured repositories,
        # targets, durable operations, and test runs; none of these tools search
        # or mutate an unbounded external entity space.
        "openWorldHint": False,
    }


_OUTPUT_SCHEMA = {"type": "object"}


def _tool(
    name: str,
    title: str,
    description: str,
    input_schema: Mapping[str, Any],
    *,
    read_only: bool,
    destructive: bool = False,
    idempotent: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": dict(input_schema),
        "outputSchema": dict(_OUTPUT_SCHEMA),
        "annotations": _annotations(
            read_only=read_only,
            destructive=destructive,
            idempotent=idempotent,
        ),
    }


_SELECTOR = _string_schema(
    "Exact immutable target ID or unique configured display name."
)
_KIND = {
    "type": "string",
    "description": "Optional configured target kind filter.",
    "enum": list(_RESOURCE_KINDS),
}
_HANDLE = _string_schema(
    "Typed dc1 continuation handle or exact service-owned identity.", maximum=256
)

TOOLS: tuple[dict[str, Any], ...] = (
    _tool(
        "capabilities",
        "Coordinator capabilities",
        "Validate the active authority/client contract for the current Git worktree.",
        _object_schema(),
        read_only=True,
    ),
    _tool(
        "targets",
        "Coordinator targets",
        "List a bounded target set or resolve one exact repository-owned target.",
        _object_schema(
            {
                "selector": _SELECTOR,
                "kind": _KIND,
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 16,
                    "default": 4,
                },
            }
        ),
        read_only=True,
    ),
    _tool(
        "runtime_status",
        "Runtime status",
        "Read fresh bounded status for one exact configured runtime target.",
        _object_schema(
            {"selector": _SELECTOR, "kind": _KIND}, required=("selector",)
        ),
        read_only=True,
    ),
    _tool(
        "runtime_ensure",
        "Ensure runtime state",
        "Ensure one exact target is ready or stopped; no-op when already desired.",
        _object_schema(
            {
                "selector": _SELECTOR,
                "desired": {
                    "type": "string",
                    "enum": ["ready", "stopped"],
                },
                "kind": _KIND,
                "operation_id": _operation_id_schema(),
            },
            required=("selector", "desired"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "operation_follow",
        "Follow operation",
        "Recover the bounded durable outcome for one exact mutation operation.",
        _object_schema({"operation": _HANDLE}, required=("operation",)),
        read_only=True,
    ),
    _tool(
        "test_enqueue",
        "Enqueue tests",
        "Plan and enqueue a policy-derived asynchronous test workflow.",
        _object_schema(
            {
                "intent": {
                    "type": "string",
                    "enum": [
                        "change",
                        "checkpoint",
                        "handoff",
                        "release",
                        "manual",
                    ],
                    "default": "change",
                },
                "targets": {
                    "type": "array",
                    "items": _string_schema(
                        "Exact manifest test target.", maximum=256
                    ),
                    "maxItems": 256,
                    "uniqueItems": True,
                    "default": [],
                },
                "execution_timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86_400,
                },
                "launch_timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3_600,
                    "default": 300,
                },
                "operation_id": _operation_id_schema(),
            }
        ),
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    _tool(
        "test_submit",
        "Submit reviewed test plan",
        "Submit one explicitly reviewed plan as an asynchronous test run.",
        _object_schema(
            {"plan": _HANDLE, "operation_id": _operation_id_schema()},
            required=("plan",),
        ),
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    _tool(
        "test_follow",
        "Follow test run",
        "Read or wait for one exact asynchronous run and return its next decision.",
        _object_schema(
            {
                "run": _HANDLE,
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 300,
                    "default": 0,
                },
            },
            required=("run",),
        ),
        read_only=True,
    ),
    _tool(
        "test_cancel",
        "Cancel test run",
        "Request idempotent cancellation of one exact asynchronous test run.",
        _object_schema(
            {
                "run": _HANDLE,
                "reason": _string_schema(
                    "Bounded single-line cancellation reason.", maximum=500
                ),
                "operation_id": _operation_id_schema(),
            },
            required=("run", "reason"),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
    _tool(
        "test_artifact",
        "Read test artifact",
        "Resolve verified metadata and bounded text for one exact test artifact.",
        _object_schema(
            {"run": _HANDLE, "artifact": _HANDLE},
            required=("run", "artifact"),
        ),
        read_only=True,
    ),
    _tool(
        "bug_report",
        "Report Coordinator bug",
        (
            "Atomically report one bounded reproducible Coordinator defect through "
            "the out-of-band registry; no broker, profile, repository configuration, "
            "API, or testd connection is required."
        ),
        _object_schema(
            {
                "component": _string_schema("Failing Coordinator component."),
                "summary": _string_schema("Concise defect summary.", maximum=512),
                "expected": _string_schema("Expected observable behavior.", maximum=512),
                "actual": _string_schema("Actual typed failure.", maximum=1024),
                "steps": {
                    "type": "array",
                    "description": "Ordered reproducible steps.",
                    "items": _string_schema("One reproduction step.", maximum=512),
                    "minItems": 1,
                    "maxItems": 8,
                },
                "command_argv": {
                    "type": "array",
                    "description": "Optional shell-free reproducer argv.",
                    "items": _string_schema("One argv item."),
                    "maxItems": 64,
                    "default": [],
                },
                "reporter": _string_schema("Optional agent identity."),
                "surface": _string_schema("Optional failing surface."),
                "operation": _string_schema("Optional failing operation."),
                "classification": _string_schema("Optional failure classification."),
                "code": _string_schema("Optional typed failure code."),
                "stage": _string_schema("Optional failure stage."),
                "repository": _string_schema(
                    "Optional repository identity or local path.", maximum=512
                ),
                "release_digest": {
                    "type": "string",
                    "description": "Optional immutable release SHA-256.",
                    "pattern": "^[0-9a-f]{64}$",
                },
                "instance_id": _string_schema("Optional Coordinator instance identity."),
                "call_id": _string_schema("Optional call-journal correlation."),
                "operation_id": _string_schema("Optional operation correlation."),
                "run_id": _string_schema("Optional test-run correlation."),
                "attempt_id": _string_schema("Optional test-attempt correlation."),
                "local_fallback": _object_schema(
                    {
                        "status": {
                            "type": "string",
                            "enum": ["not_run", "passed", "failed", "incomplete"],
                        },
                        "command_argv": {
                            "type": "array",
                            "items": _string_schema("One local-test argv item."),
                            "maxItems": 64,
                            "default": [],
                        },
                        "summary": _string_schema(
                            "Optional advisory local-test summary.", maximum=512
                        ),
                    },
                    required=("status",),
                ),
            },
            required=("component", "summary", "expected", "actual", "steps"),
        ),
        read_only=False,
        destructive=False,
        idempotent=False,
    ),
    _tool(
        "bug_list",
        "List open Coordinator bugs",
        "List bounded open bug summaries without contacting Coordinator services.",
        _object_schema(
            {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "default": 8,
                },
                "component": _string_schema("Optional exact component filter."),
            }
        ),
        read_only=True,
    ),
    _tool(
        "bug_close",
        "Close Coordinator bug",
        "Physically remove one resolved open bug; repeating close is a no-op.",
        _object_schema(
            {"bug_id": _string_schema("Canonical bug-UUID identity.")},
            required=("bug_id",),
        ),
        read_only=False,
        destructive=True,
        idempotent=True,
    ),
)

_TOOLS_BY_NAME = {tool["name"]: tool for tool in TOOLS}
_MUTATING_TOOLS = frozenset(
    {"runtime_ensure", "test_enqueue", "test_submit", "test_cancel"}
)


def _arguments(value: Any, *, allowed: frozenset[str]) -> dict[str, Any]:
    if value is None:
        document: dict[str, Any] = {}
    elif isinstance(value, dict):
        document = dict(value)
    else:
        raise AgentMcpError("invalid_arguments", "tool arguments must be an object")
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise AgentMcpError(
            "invalid_arguments",
            "tool arguments contain unsupported fields: " + ", ".join(unknown[:4]),
        )
    return document


def _string(
    document: Mapping[str, Any],
    name: str,
    *,
    required: bool = False,
    maximum_bytes: int = 256,
) -> str | None:
    value = document.get(name)
    if value is None and not required:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum_bytes
        or "\x00" in value
        or any(not character.isprintable() for character in value)
    ):
        raise AgentMcpError(
            "invalid_arguments",
            f"{name} must be a non-empty printable string of at most {maximum_bytes} bytes",
        )
    return value


def _choice(
    document: Mapping[str, Any],
    name: str,
    choices: Sequence[str],
    *,
    required: bool = False,
    default: str | None = None,
) -> str | None:
    value = document.get(name, default)
    if value is None and not required:
        return None
    if not isinstance(value, str) or value not in choices:
        raise AgentMcpError(
            "invalid_arguments", f"{name} must be one of {', '.join(choices)}"
        )
    return value


def _integer(
    document: Mapping[str, Any],
    name: str,
    *,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int | None:
    value = document.get(name, default)
    if value is None:
        return None
    if type(value) is not int or not minimum <= value <= maximum:
        raise AgentMcpError(
            "invalid_arguments",
            f"{name} must be an integer from {minimum} through {maximum}",
        )
    return value


def _operation_id(document: Mapping[str, Any]) -> str | None:
    return _string(document, "operation_id", maximum_bytes=36)


def _argv_for_tool(name: str, raw_arguments: Any) -> list[str]:
    """Validate one advertised schema and build a shell-free CLI argument list."""

    if name == "capabilities":
        _arguments(raw_arguments, allowed=frozenset())
        return ["capabilities"]

    if name == "targets":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"selector", "kind", "limit"})
        )
        selector = _string(arguments, "selector")
        kind = _choice(arguments, "kind", _RESOURCE_KINDS)
        limit = _integer(arguments, "limit", minimum=1, maximum=16, default=4)
        argv = ["targets"]
        if selector is not None:
            argv.append(selector)
        if kind is not None:
            argv.extend(("--kind", kind))
        argv.extend(("--limit", str(limit)))
        return argv

    if name == "runtime_status":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"selector", "kind"})
        )
        selector = _string(arguments, "selector", required=True)
        kind = _choice(arguments, "kind", _RESOURCE_KINDS)
        argv = ["runtime", "status", str(selector)]
        if kind is not None:
            argv.extend(("--kind", kind))
        return argv

    if name == "runtime_ensure":
        arguments = _arguments(
            raw_arguments,
            allowed=frozenset(
                {"selector", "desired", "kind", "operation_id"}
            ),
        )
        selector = _string(arguments, "selector", required=True)
        desired = _choice(
            arguments, "desired", ("ready", "stopped"), required=True
        )
        kind = _choice(arguments, "kind", _RESOURCE_KINDS)
        operation_id = _operation_id(arguments)
        argv = [
            "runtime",
            "ensure",
            str(selector),
            "--desired",
            str(desired),
        ]
        if kind is not None:
            argv.extend(("--kind", kind))
        if operation_id is not None:
            argv.extend(("--operation-id", operation_id))
        return argv

    if name == "operation_follow":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"operation"})
        )
        operation = _string(arguments, "operation", required=True)
        return ["operation", "follow", str(operation)]

    if name == "test_enqueue":
        arguments = _arguments(
            raw_arguments,
            allowed=frozenset(
                {
                    "intent",
                    "targets",
                    "execution_timeout_seconds",
                    "launch_timeout_seconds",
                    "operation_id",
                }
            ),
        )
        intent = _choice(
            arguments,
            "intent",
            ("change", "checkpoint", "handoff", "release", "manual"),
            default="change",
        )
        targets = arguments.get("targets", [])
        if (
            not isinstance(targets, list)
            or len(targets) > 256
            or any(not isinstance(item, str) for item in targets)
            or len(set(targets)) != len(targets)
        ):
            raise AgentMcpError(
                "invalid_arguments",
                "targets must be a unique array of at most 256 strings",
            )
        validated_targets = []
        for index, target in enumerate(targets):
            validated = _string(
                {"target": target}, "target", required=True, maximum_bytes=256
            )
            if validated is None:  # defensive; required=True excludes this
                raise AgentMcpError(
                    "invalid_arguments", f"targets[{index}] is invalid"
                )
            validated_targets.append(validated)
        execution_timeout = _integer(
            arguments,
            "execution_timeout_seconds",
            minimum=1,
            maximum=86_400,
        )
        launch_timeout = _integer(
            arguments,
            "launch_timeout_seconds",
            minimum=1,
            maximum=3_600,
            default=300,
        )
        operation_id = _operation_id(arguments)
        argv = [
            "test",
            "enqueue",
            "--intent",
            str(intent),
            "--launch-timeout-seconds",
            str(launch_timeout),
        ]
        if execution_timeout is not None:
            argv.extend(("--execution-timeout-seconds", str(execution_timeout)))
        if operation_id is not None:
            argv.extend(("--operation-id", operation_id))
        for target in validated_targets:
            argv.append("--target=" + target)
        return argv

    if name == "test_submit":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"plan", "operation_id"})
        )
        plan = _string(arguments, "plan", required=True)
        operation_id = _operation_id(arguments)
        argv = ["test", "submit", str(plan)]
        if operation_id is not None:
            argv.extend(("--operation-id", operation_id))
        return argv

    if name == "test_follow":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"run", "wait_seconds"})
        )
        run = _string(arguments, "run", required=True)
        wait_seconds = _integer(
            arguments,
            "wait_seconds",
            minimum=0,
            maximum=300,
            default=0,
        )
        return [
            "test",
            "follow",
            str(run),
            "--wait-seconds",
            str(wait_seconds),
        ]

    if name == "test_cancel":
        arguments = _arguments(
            raw_arguments,
            allowed=frozenset({"run", "reason", "operation_id"}),
        )
        run = _string(arguments, "run", required=True)
        reason = _string(
            arguments, "reason", required=True, maximum_bytes=500
        )
        operation_id = _operation_id(arguments)
        argv = ["test", "cancel", str(run), "--reason", str(reason)]
        if operation_id is not None:
            argv.extend(("--operation-id", operation_id))
        return argv

    if name == "test_artifact":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"run", "artifact"})
        )
        run = _string(arguments, "run", required=True)
        artifact = _string(arguments, "artifact", required=True)
        return ["test", "artifact", str(run), str(artifact)]

    if name == "bug_report":
        allowed = frozenset(
            {
                "component",
                "summary",
                "expected",
                "actual",
                "steps",
                "command_argv",
                "reporter",
                "surface",
                "operation",
                "classification",
                "code",
                "stage",
                "repository",
                "release_digest",
                "instance_id",
                "call_id",
                "operation_id",
                "run_id",
                "attempt_id",
                "local_fallback",
            }
        )
        arguments = _arguments(raw_arguments, allowed=allowed)
        argv = ["bug", "report"]
        text_fields = (
            ("component", 256, True),
            ("summary", 512, True),
            ("expected", 512, True),
            ("actual", 1024, True),
            ("reporter", 256, False),
            ("surface", 256, False),
            ("operation", 256, False),
            ("classification", 256, False),
            ("code", 256, False),
            ("stage", 256, False),
            ("repository", 512, False),
            ("release_digest", 64, False),
            ("instance_id", 256, False),
            ("call_id", 256, False),
            ("operation_id", 256, False),
            ("run_id", 256, False),
            ("attempt_id", 256, False),
        )
        for field, maximum, required in text_fields:
            value = _string(
                arguments,
                field,
                required=required,
                maximum_bytes=maximum,
            )
            if value is not None:
                argv.extend(("--" + field.replace("_", "-"), value))
        steps = arguments.get("steps")
        if (
            not isinstance(steps, list)
            or not 1 <= len(steps) <= 8
            or any(not isinstance(item, str) for item in steps)
        ):
            raise AgentMcpError(
                "invalid_arguments", "steps must contain 1 through 8 strings"
            )
        for item in steps:
            step = _string(
                {"step": item}, "step", required=True, maximum_bytes=512
            )
            argv.extend(("--step", str(step)))
        command_argv = arguments.get("command_argv", [])
        if (
            not isinstance(command_argv, list)
            or len(command_argv) > 64
            or any(not isinstance(item, str) for item in command_argv)
        ):
            raise AgentMcpError(
                "invalid_arguments", "command_argv must contain at most 64 strings"
            )
        for item in command_argv:
            argument = _string(
                {"argument": item},
                "argument",
                required=True,
                maximum_bytes=256,
            )
            argv.append("--command-arg=" + str(argument))
        fallback = arguments.get("local_fallback")
        if fallback is not None:
            fallback_document = _arguments(
                fallback,
                allowed=frozenset({"status", "command_argv", "summary"}),
            )
            status = _choice(
                fallback_document,
                "status",
                ("not_run", "passed", "failed", "incomplete"),
                required=True,
            )
            argv.extend(("--local-fallback-status", str(status)))
            fallback_summary = _string(
                fallback_document, "summary", maximum_bytes=512
            )
            if fallback_summary is not None:
                argv.extend(("--local-fallback-summary", fallback_summary))
            fallback_argv = fallback_document.get("command_argv", [])
            if (
                not isinstance(fallback_argv, list)
                or len(fallback_argv) > 64
                or any(not isinstance(item, str) for item in fallback_argv)
            ):
                raise AgentMcpError(
                    "invalid_arguments",
                    "local_fallback.command_argv must contain at most 64 strings",
                )
            for item in fallback_argv:
                argument = _string(
                    {"argument": item},
                    "argument",
                    required=True,
                    maximum_bytes=256,
                )
                argv.append("--local-test-command-arg=" + str(argument))
        return argv

    if name == "bug_list":
        arguments = _arguments(
            raw_arguments, allowed=frozenset({"limit", "component"})
        )
        limit = _integer(arguments, "limit", minimum=1, maximum=20, default=8)
        component = _string(arguments, "component")
        argv = ["bug", "list", "--limit", str(limit)]
        if component is not None:
            argv.extend(("--component", component))
        return argv

    if name == "bug_close":
        arguments = _arguments(raw_arguments, allowed=frozenset({"bug_id"}))
        bug_id = _string(arguments, "bug_id", required=True)
        return ["bug", "close", str(bug_id)]

    raise AgentMcpError("tool_not_found", "requested tool is not advertised")


def _call_tool(name: str, raw_arguments: Any) -> dict[str, Any]:
    """Invoke one tool and always return a valid MCP ``CallToolResult``."""

    from . import agent_cli

    started = time.monotonic()
    call_id = str(uuid.uuid4())
    namespace: argparse.Namespace | None = None
    failure: BaseException | None = None
    journal: Any = None
    event_record: Any = None
    diagnostic_for_exception: Any = None
    bug_tool = name in {"bug_report", "bug_list", "bug_close"}
    if not bug_tool:
        try:
            from .call_journal import (
                configured_call_journal,
                diagnostic_for_exception as journal_diagnostic,
                event_record as build_event_record,
            )

            journal = configured_call_journal()
            event_record = build_event_record
            diagnostic_for_exception = journal_diagnostic
        except BaseException:
            journal = None

    def record(phase: str, outcome: str, *, error: BaseException | None = None) -> None:
        if journal is None or event_record is None:
            return
        operation_id = (
            getattr(namespace, "operation_id", None)
            if namespace is not None
            else None
        )
        code = getattr(error, "code", None) if error is not None else None
        diagnostic = (
            diagnostic_for_exception(error, stage="agent_mcp")
            if error is not None and diagnostic_for_exception is not None
            else None
        )
        try:
            journal.record(
                event_record(
                    boundary="agent_mcp",
                    phase=phase,
                    call_id=call_id,
                    operation=f"agent_mcp.{name}",
                    operation_id=(
                        operation_id if isinstance(operation_id, str) else None
                    ),
                    duration_seconds=(
                        None if phase == "received" else time.monotonic() - started
                    ),
                    outcome=outcome,
                    code=code if isinstance(code, str) else None,
                    message=str(error) if error is not None else None,
                    diagnostic=diagnostic,
                )
            )
        except BaseException:
            return

    try:
        if name not in _TOOLS_BY_NAME:
            raise AgentMcpError("tool_not_found", "requested tool is not advertised")
        argv = _argv_for_tool(name, raw_arguments)
        namespace = agent_cli._parser().parse_args(argv)
        if name in _MUTATING_TOOLS:
            namespace.operation_id = agent_cli._canonical_operation_id(
                getattr(namespace, "operation_id", None), mutate=True
            )
        # Mirror agent_cli: persist the generated identity before repository
        # discovery or transport so a lost MCP reply remains recoverable from
        # the bounded paired call journal.
        record("received", "received")
        result = agent_cli._execute(namespace)
        if not isinstance(result, Mapping):
            raise AgentMcpError(
                "agent_result_invalid", "agent client result is not an object"
            )
        document = dict(result)
        if len(canonical_json_bytes(document)) > MAX_AGENT_RESULT_BYTES:
            raise AgentMcpError(
                "agent_result_too_large",
                "agent client result exceeds its bounded contract",
                classification="client_contract_failure",
                phase="serialization",
            )
    except (KeyboardInterrupt, GeneratorExit):
        raise
    except BaseException as error:
        failure = error
        document = agent_cli._failure(
            error,
            mutation_attempted=agent_cli._command_mutates(namespace),
            operation_id_hint=(
                getattr(namespace, "operation_id", None)
                if namespace is not None
                else None
            ),
        )

    record(
        "completed",
        "ok" if document.get("ok") is True else "failed",
        error=failure,
    )

    encoded = canonical_json_bytes(document).decode("utf-8")
    return {
        "content": [{"type": "text", "text": encoded}],
        "structuredContent": document,
        "isError": document.get("ok") is not True,
    }


def _valid_request_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 256
        and "\x00" not in value
    ) or (type(value) in {int, float} and value == value and abs(value) != float("inf"))


def _error_response(
    request_id: Any, code: int, message: str, *, data: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = dict(data)
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _result_response(request_id: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": dict(result)}


def _params(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AgentMcpError("invalid_params", "request params must be an object")
    return dict(value)


class McpSession:
    """One stateful MCP stdio connection."""

    def __init__(self) -> None:
        self.initialize_replied = False
        self.initialized = False
        self.protocol_version: str | None = None

    def _initialize(self, request_id: Any, raw_params: Any) -> dict[str, Any]:
        if self.initialize_replied:
            return _error_response(
                request_id, _JSONRPC_INVALID_REQUEST, "server is already initialized"
            )
        try:
            params = _params(raw_params)
            allowed = {"protocolVersion", "capabilities", "clientInfo", "_meta"}
            if set(params) - allowed:
                raise AgentMcpError(
                    "invalid_params", "initialize params contain unsupported fields"
                )
            requested = params.get("protocolVersion")
            capabilities = params.get("capabilities")
            client_info = params.get("clientInfo")
            if (
                not isinstance(requested, str)
                or len(requested.encode("utf-8")) > 64
                or not isinstance(capabilities, dict)
                or not isinstance(client_info, dict)
                or not isinstance(client_info.get("name"), str)
                or not isinstance(client_info.get("version"), str)
            ):
                raise AgentMcpError(
                    "invalid_params", "initialize params are incomplete or malformed"
                )
            if requested != MCP_PROTOCOL_VERSION:
                return _error_response(
                    request_id,
                    _JSONRPC_INVALID_PARAMS,
                    "unsupported MCP protocol version",
                    data={
                        "code": "protocol_version_unsupported",
                        "requested": requested,
                        "supported": MCP_PROTOCOL_VERSION,
                    },
                )
        except AgentMcpError as error:
            return _error_response(
                request_id, _JSONRPC_INVALID_PARAMS, str(error)
            )
        self.protocol_version = MCP_PROTOCOL_VERSION
        self.initialize_replied = True
        return _result_response(
            request_id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "devcoordinator",
                    "title": "DevCoordinator",
                    "version": MCP_SERVER_VERSION,
                    "description": (
                        "Bounded tools for exact local runtime and asynchronous test intents."
                    ),
                },
                "instructions": (
                    "Use continuation handles from tool results; never guess resource, "
                    "operation, plan, or run identities."
                ),
            },
        )

    def handle(self, message: Any) -> dict[str, Any] | None:
        """Handle one decoded JSON-RPC message without emitting side channels."""

        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error_response(
                None, _JSONRPC_INVALID_REQUEST, "invalid JSON-RPC request"
            )
        if "method" not in message:
            # This server sends no requests, so a syntactically valid response
            # from a client has no outstanding correlation and is ignored.
            if "result" in message or "error" in message:
                return None
            return _error_response(
                None, _JSONRPC_INVALID_REQUEST, "request method is required"
            )
        method = message.get("method")
        if not isinstance(method, str) or not method or len(method) > 128:
            return _error_response(
                None, _JSONRPC_INVALID_REQUEST, "request method is invalid"
            )
        notification = "id" not in message
        request_id = message.get("id")
        if not notification and not _valid_request_id(request_id):
            return _error_response(
                None, _JSONRPC_INVALID_REQUEST, "request id is invalid"
            )
        if set(message) - {"jsonrpc", "id", "method", "params"}:
            return (
                None
                if notification
                else _error_response(
                    request_id,
                    _JSONRPC_INVALID_REQUEST,
                    "request contains unsupported fields",
                )
            )

        if method == "initialize":
            if notification:
                return None
            return self._initialize(request_id, message.get("params"))

        if method == "notifications/initialized":
            if not notification:
                return _error_response(
                    request_id,
                    _JSONRPC_INVALID_REQUEST,
                    "notifications/initialized must be a notification",
                )
            if self.initialize_replied:
                self.initialized = True
            return None

        if method == "ping":
            if notification:
                return None
            try:
                params = _params(message.get("params"))
                if set(params) - {"_meta"}:
                    raise AgentMcpError("invalid_params", "ping params must be empty")
            except AgentMcpError as error:
                return _error_response(
                    request_id, _JSONRPC_INVALID_PARAMS, str(error)
                )
            return _result_response(request_id, {})

        if not self.initialized:
            return (
                None
                if notification
                else _error_response(
                    request_id,
                    _SERVER_NOT_INITIALIZED,
                    "server initialization is not complete",
                )
            )

        if method == "tools/list":
            if notification:
                return None
            try:
                params = _params(message.get("params"))
                if set(params) - {"_meta"}:
                    raise AgentMcpError(
                        "invalid_params", "this finite tool list is not paginated"
                    )
            except AgentMcpError as error:
                return _error_response(
                    request_id, _JSONRPC_INVALID_PARAMS, str(error)
                )
            return _result_response(request_id, {"tools": list(TOOLS)})

        if method == "tools/call":
            if notification:
                return None
            try:
                params = _params(message.get("params"))
                if set(params) - {"name", "arguments", "_meta"}:
                    raise AgentMcpError(
                        "invalid_params", "tools/call params contain unsupported fields"
                    )
                name = params.get("name")
                if not isinstance(name, str) or name not in _TOOLS_BY_NAME:
                    raise AgentMcpError(
                        "invalid_params", "tools/call names no advertised tool"
                    )
            except AgentMcpError as error:
                return _error_response(
                    request_id, _JSONRPC_INVALID_PARAMS, str(error)
                )
            return _result_response(
                request_id, _call_tool(name, params.get("arguments"))
            )

        if notification:
            return None
        return _error_response(
            request_id, _JSONRPC_METHOD_NOT_FOUND, "method not found"
        )


def _decode_message(raw: bytes) -> Any:
    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON constant {value} is forbidden")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key is forbidden")
            result[key] = value
        return result

    return json.loads(
        raw.decode("utf-8", errors="strict"),
        parse_constant=reject_constant,
        object_pairs_hook=unique_object,
    )


def _write_message(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    encoded = canonical_json_bytes(message)
    if len(encoded) + 1 > MAX_MCP_RESPONSE_BYTES:
        request_id = message.get("id") if isinstance(message, Mapping) else None
        encoded = canonical_json_bytes(
            _error_response(
                request_id,
                _JSONRPC_INTERNAL_ERROR,
                "bounded MCP response contract exceeded",
            )
        )
    if len(encoded) + 1 > MAX_MCP_RESPONSE_BYTES:  # defensive fixed fallback
        raise AgentMcpError("mcp_response_too_large", "MCP response is too large")
    stream.write(encoded + b"\n")
    stream.flush()


def serve(stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Serve one finite newline-delimited MCP stdio connection until EOF."""

    session = McpSession()
    while True:
        raw = stdin.readline(MAX_MCP_REQUEST_BYTES + 2)
        if raw == b"":
            return 0
        if len(raw) > MAX_MCP_REQUEST_BYTES + 1 or not raw.endswith(b"\n"):
            _write_message(
                stdout,
                _error_response(
                    None,
                    _JSONRPC_PARSE_ERROR,
                    "MCP request exceeds its finite line contract",
                ),
            )
            # The unread suffix cannot be safely correlated as a new message.
            return 1
        payload = raw[:-1]
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        if len(payload) > MAX_MCP_REQUEST_BYTES:
            _write_message(
                stdout,
                _error_response(
                    None, _JSONRPC_PARSE_ERROR, "MCP request is too large"
                ),
            )
            return 1
        try:
            message = _decode_message(payload)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            _write_message(
                stdout,
                _error_response(
                    None, _JSONRPC_PARSE_ERROR, "invalid finite UTF-8 JSON message"
                ),
            )
            continue
        try:
            response = session.handle(message)
        except (KeyboardInterrupt, GeneratorExit):
            raise
        except BaseException:
            request_id = (
                message.get("id")
                if isinstance(message, dict)
                and _valid_request_id(message.get("id"))
                else None
            )
            response = _error_response(
                request_id, _JSONRPC_INTERNAL_ERROR, "internal MCP server error"
            )
        if response is not None:
            _write_message(stdout, response)


def _main_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devcoordinator-mcp",
        description=(
            "Serve the stable bounded DevCoordinator agent tools over MCP stdio. "
            "Standard output is protocol-only while serving."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {MCP_SERVER_VERSION}"
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> int:
    """CLI entry suitable for one immutable ``devcoordinator-mcp`` wrapper."""

    _main_parser().parse_args(list(argv) if argv is not None else None)
    input_stream: BinaryIO
    output_stream: BinaryIO
    if stdin is None:
        input_stream = getattr(sys.stdin, "buffer", sys.stdin)
    else:
        input_stream = stdin
    if stdout is None:
        output_stream = getattr(sys.stdout, "buffer", sys.stdout)
    else:
        output_stream = stdout
    return serve(input_stream, output_stream)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_MCP_REQUEST_BYTES",
    "MAX_MCP_RESPONSE_BYTES",
    "MCP_PROTOCOL_VERSION",
    "MCP_SERVER_VERSION",
    "McpSession",
    "TOOLS",
    "main",
    "serve",
]
