"""Small, bounded contracts for model-facing Coordinator calls.

The service protocols retain their complete typed documents.  This module owns
only the compact continuation and result envelope returned to a calling agent;
it is deliberately independent of runtime, test, and host mutation semantics.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any
import uuid


AGENT_RESULT_SCHEMA_VERSION = 1
MAX_AGENT_RESULT_BYTES = 8 * 1024
MAX_AGENT_DOCUMENT_BYTES = MAX_AGENT_RESULT_BYTES - 1
MAX_AGENT_MESSAGE_BYTES = 512
MAX_NEXT_COMMAND_BYTES = 512
MAX_NEXT_ACTION_BYTES = 512

_HANDLE = re.compile(
    r"^dc1:(operation|run|plan|artifact):"
    r"([A-Za-z0-9][A-Za-z0-9_.:@-]{0,127})$"
)


class AgentContractError(ValueError):
    """One caller-facing document cannot satisfy the bounded contract."""


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one deterministic finite JSON value."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise AgentContractError("agent result is not finite bounded JSON") from error


def bounded_text(value: object, *, maximum_bytes: int = MAX_AGENT_MESSAGE_BYTES) -> str:
    """Return printable single-line text with a deterministic truncation seal."""

    if type(maximum_bytes) is not int or maximum_bytes < 64:
        raise AgentContractError("text bound must be an integer of at least 64 bytes")
    printable = "".join(
        character if character.isprintable() and ord(character) != 127 else " "
        for character in str(value)
    )
    normalized = " ".join(printable.split()) or "unavailable"
    encoded = normalized.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return normalized
    seal = hashlib.sha256(encoded).hexdigest()[:16]
    suffix = f"...[truncated sha256:{seal}]"
    budget = maximum_bytes - len(suffix.encode("utf-8"))
    if budget <= 0:
        raise AgentContractError("text bound cannot contain its truncation seal")
    return encoded[:budget].decode("utf-8", errors="ignore") + suffix


def continuation_handle(kind: str, identity: str) -> str:
    """Build one non-secret handle for service-owned state.

    The handle is a compact reference, not an authorization credential.  The
    referenced operation, run, plan, or artifact remains authoritative and is
    reauthorized when followed.
    """

    candidate = f"dc1:{kind}:{identity}"
    if _HANDLE.fullmatch(candidate) is None or ".." in identity:
        raise AgentContractError("continuation identity is not a bounded opaque ID")
    if kind == "operation":
        try:
            canonical = str(uuid.UUID(identity))
        except (ValueError, AttributeError) as error:
            raise AgentContractError(
                "operation continuation requires a canonical UUID"
            ) from error
        if canonical != identity:
            raise AgentContractError("operation continuation UUID is not canonical")
    return candidate


def parse_continuation_handle(value: str) -> tuple[str, str]:
    """Validate and split one continuation handle."""

    match = _HANDLE.fullmatch(value) if isinstance(value, str) else None
    if match is None or ".." in value:
        raise AgentContractError("continuation handle is invalid")
    kind, identity = match.groups()
    if kind == "operation":
        try:
            canonical = str(uuid.UUID(identity))
        except (ValueError, AttributeError) as error:
            raise AgentContractError("continuation operation ID is invalid") from error
        if canonical != identity:
            raise AgentContractError("continuation operation ID is not canonical")
    return kind, identity


def require_agent_result(
    value: Mapping[str, Any],
    *,
    surface: str,
    maximum_bytes: int = MAX_AGENT_DOCUMENT_BYTES,
) -> dict[str, Any]:
    """Return a copied result only when encoding plus its newline is bounded."""

    if not isinstance(value, Mapping):
        raise AgentContractError(f"{surface} result must be an object")
    document = dict(value)
    encoded = canonical_json_bytes(document)
    if len(encoded) > maximum_bytes:
        raise AgentContractError(
            f"{surface} exceeds the {maximum_bytes}-byte agent result contract"
        )
    return document


def agent_error_result(
    *,
    code: str,
    message: object,
    classification: str,
    phase: str,
    operation_id: str | None = None,
    continuation: str | None = None,
    broker_contacted: bool | None = False,
    mutation_performed: bool | None = False,
    outcome: str = "certain",
    retryable: bool = False,
    retry_after_seconds: int | None = None,
    next_command: str | None = None,
    next_action: str | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the common safe error shape used by the thin caller surface."""

    if outcome not in {"certain", "uncertain", "attention_required"}:
        raise AgentContractError("agent error outcome is invalid")
    if mutation_performed not in {True, False, None}:
        raise AgentContractError("mutation_performed must be true, false, or null")
    if broker_contacted not in {True, False, None}:
        raise AgentContractError("broker_contacted must be true, false, or null")
    if operation_id is not None:
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError
        except (ValueError, AttributeError) as error:
            raise AgentContractError("agent error operation ID is invalid") from error
    if continuation is not None:
        parse_continuation_handle(continuation)
    if retry_after_seconds is not None and (
        type(retry_after_seconds) is not int or retry_after_seconds <= 0
    ):
        raise AgentContractError("retry_after_seconds must be a positive integer")
    document: dict[str, Any] = {
        "schema_version": AGENT_RESULT_SCHEMA_VERSION,
        "ok": False,
        "code": bounded_text(code, maximum_bytes=96),
        "classification": bounded_text(classification, maximum_bytes=96),
        "phase": bounded_text(phase, maximum_bytes=96),
        "message": bounded_text(message),
        "broker_contacted": broker_contacted,
        "mutation_performed": mutation_performed,
        "outcome": outcome,
        "retryable": retryable,
    }
    if operation_id is not None:
        document["operation_id"] = operation_id
    if continuation is not None:
        document["continuation"] = continuation
    if retry_after_seconds is not None:
        document["retry_after_seconds"] = retry_after_seconds
    if next_command is not None:
        document["next_command"] = bounded_text(
            next_command, maximum_bytes=MAX_NEXT_COMMAND_BYTES
        )
    if next_action is not None:
        document["next_action"] = bounded_text(
            next_action, maximum_bytes=MAX_NEXT_ACTION_BYTES
        )
    if evidence is not None:
        document["evidence"] = dict(evidence)
    return require_agent_result(document, surface="agent error")


__all__ = [
    "AGENT_RESULT_SCHEMA_VERSION",
    "AgentContractError",
    "MAX_AGENT_RESULT_BYTES",
    "agent_error_result",
    "bounded_text",
    "canonical_json_bytes",
    "continuation_handle",
    "parse_continuation_handle",
    "require_agent_result",
]
