"""Compact active-release capabilities shared by the broker and thin client."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any


CAPABILITIES_SCHEMA_VERSION = 1
AGENT_RESULT_SCHEMA_VERSION = 1
SUPPORTED_BROKER_PROTOCOL_VERSION = 1
MAX_CAPABILITY_DOCUMENT_BYTES = 2 * 1024


class CapabilityMismatchError(RuntimeError):
    """The active authority cannot safely serve this thin client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.classification = "incompatible_authority"
        self.phase = "handshake"


def release_digest(module_path: Path | None = None) -> str | None:
    """Return an exact configured/immutable release digest when available."""

    configured = os.environ.get("DEVCOORDINATOR_RELEASE_DIGEST")
    if isinstance(configured, str) and re.fullmatch(r"[0-9a-f]{64}", configured):
        return configured
    try:
        resolved = (module_path or Path(__file__)).resolve(strict=True)
    except OSError:
        return None
    release_root = Path("/opt/devcoordinator/releases")
    for parent in resolved.parents:
        if parent.parent == release_root and re.fullmatch(r"[0-9a-f]{64}", parent.name):
            return parent.name
    return None


def broker_capabilities(
    *,
    protocol_version: int,
    authority_schema_version: int,
    authority_generation: str,
    active_release_digest: str | None = None,
) -> dict[str, Any]:
    """Publish only caller-relevant capabilities of the active authority."""

    return {
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "status": "ok",
        "protocol_version": protocol_version,
        "authority_schema_version": authority_schema_version,
        "authority_generation": authority_generation,
        "release_digest": active_release_digest,
        "agent_result_schema_version": AGENT_RESULT_SCHEMA_VERSION,
        "limits": {
            "agent_result_bytes": 8 * 1024,
            "target_result_bytes": 2 * 1024,
            "status_result_bytes": 2 * 1024,
            "test_result_bytes": 4 * 1024,
            "operation_follow_bytes": 2 * 1024,
        },
        "interfaces": {
            "cli": "devcoordinator",
            "mcp_stdio": "devcoordinator-mcp",
        },
        "runtime": {
            "target_kinds": ["service", "docker", "database_stack"],
            "actions": [
                "capture_logs",
                "replace",
                "restart",
                "serve",
                "start",
                "status",
                "stop",
            ],
            "ensure_states": ["ready", "stopped"],
            "operation_replay": True,
            "broker_ttl_cleanup": True,
        },
        "repository": {
            "bootstrap_on_start": True,
            "ensure_operation": "repository.ensure",
            "resolve_operation": "repository.resolve",
        },
        "storage": {
            "actions": ["apply", "inventory", "plan", "remove"],
            "target_kinds": ["container", "image", "volume", "build_cache"],
            "direct_remove_target_kinds": ["container"],
            "plan_apply_target_kinds": ["volume"],
            "project_attribution": True,
            "exact_reclaim_plans": True,
            "durable_confirmation_bound_apply": True,
        },
        "database": ["backup", "retire"],
        "compose": {
            "actions": ["recreate-service"],
        },
        "ephemeral_image": ["prefetch", "status"],
        "image_publication": {
            "actions": ["status", "plan", "build", "apply", "rollback"],
            "cli": "devcoordinator-image",
        },
        "route_publication": {
            "actions": ["inspect", "publish"],
            "surface": "console:#/routes",
        },
        "process_isolation": {
            "termination": "systemd-unit",
            "empty_proof": "populated=0",
        },
        "tests": {
            "actions": [
                "artifact",
                "artifact-export",
                "cancel",
                "cases",
                "enqueue",
                "failures",
                "follow",
                "queue-status",
                "retry",
                "submit",
            ],
            "enqueue_intents": [
                "change",
                "checkpoint",
                "handoff",
                "release",
                "manual",
            ],
        },
        "continuations": {"operation_follow": True, "run_follow": True},
        "efficiency": {
            "actions": ["ingest"],
            "schema_version": 1,
            "project_attribution": True,
            "per_account": True,
            "console_projection": True,
        },
        "administration": {
            "systemd_unit": {
                "cli": "devcoordinator-systemd-unit",
                "confirmation_bound": True,
                "project_sealed": True,
            }
        },
    }


def validate_client_capabilities(
    document: Any,
    *,
    expected_authority_generation: str,
    client_release_digest: str | None = None,
) -> dict[str, Any]:
    """Validate the small compatibility handshake before any dependent call.

    The protected profile and broker response must name the same authority
    generation.  Immutable clients also require the active broker to come from
    the same content-addressed release; source checkouts deliberately have no
    release digest and therefore retain a development-only compatibility path.
    """

    if not isinstance(document, dict):
        raise CapabilityMismatchError(
            "capability_reply_invalid", "authority capabilities are not an object"
        )
    if document.get("schema_version") != CAPABILITIES_SCHEMA_VERSION:
        raise CapabilityMismatchError(
            "capability_schema_unsupported",
            "authority capability schema is not supported by this client",
        )
    if document.get("status") != "ok":
        raise CapabilityMismatchError(
            "capability_reply_invalid", "authority capability status is not ok"
        )
    if document.get("protocol_version") != SUPPORTED_BROKER_PROTOCOL_VERSION:
        raise CapabilityMismatchError(
            "broker_protocol_unsupported",
            "authority broker protocol is not supported by this client",
        )
    authority_schema = document.get("authority_schema_version")
    if type(authority_schema) is not int or authority_schema <= 0:
        raise CapabilityMismatchError(
            "capability_reply_invalid",
            "authority schema version is not a positive integer",
        )
    if document.get("agent_result_schema_version") != AGENT_RESULT_SCHEMA_VERSION:
        raise CapabilityMismatchError(
            "agent_result_schema_unsupported",
            "authority and client agent-result schemas do not match",
        )
    if document.get("authority_generation") != expected_authority_generation:
        raise CapabilityMismatchError(
            "authority_generation_mismatch",
            "protected profile and active authority generations do not match",
        )
    authority_release = document.get("release_digest")
    if authority_release is not None and (
        not isinstance(authority_release, str)
        or re.fullmatch(r"[0-9a-f]{64}", authority_release) is None
    ):
        raise CapabilityMismatchError(
            "capability_reply_invalid", "authority release digest is malformed"
        )
    if client_release_digest is not None and authority_release != client_release_digest:
        raise CapabilityMismatchError(
            "release_mismatch",
            "stable client and active authority are from different releases",
        )
    limits = document.get("limits")
    if not isinstance(limits, dict) or limits.get("agent_result_bytes") != 8 * 1024:
        raise CapabilityMismatchError(
            "agent_result_limit_unsupported",
            "authority does not publish the required bounded agent result contract",
        )
    try:
        encoded = json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CapabilityMismatchError(
            "capability_reply_invalid", "authority capabilities are not finite JSON"
        ) from error
    if len(encoded) > MAX_CAPABILITY_DOCUMENT_BYTES:
        raise CapabilityMismatchError(
            "capability_reply_too_large",
            "authority capability reply exceeds the client handshake bound",
        )
    return dict(document)


__all__ = [
    "AGENT_RESULT_SCHEMA_VERSION",
    "CAPABILITIES_SCHEMA_VERSION",
    "MAX_CAPABILITY_DOCUMENT_BYTES",
    "SUPPORTED_BROKER_PROTOCOL_VERSION",
    "CapabilityMismatchError",
    "broker_capabilities",
    "release_digest",
    "validate_client_capabilities",
]
