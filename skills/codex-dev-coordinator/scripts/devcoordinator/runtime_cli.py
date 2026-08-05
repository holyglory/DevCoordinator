"""Shell-friendly transport adapter for the canonical runtime request API.

This module deliberately owns no lifecycle semantics.  It converts explicit
command-line values into the JSON-shaped request and delegates every domain
rule to :func:`validate_runtime_request`.
"""

from __future__ import annotations

import argparse
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .runtime_api import (
    RUNTIME_ACTIONS,
    RUNTIME_OPTION_KEYS,
    RUNTIME_PURPOSES,
    RUNTIME_REQUEST_KEYS,
    RUNTIME_TARGET_KINDS,
    RuntimeRequestError,
    load_runtime_request,
    runtime_request_error_context,
    validate_runtime_request,
)
from .worker_supervision import (
    DEFAULT_CRASH_LIMIT,
    DEFAULT_CRASH_WINDOW_SECONDS,
)


RUNTIME_SIMPLE_ACTIONS = frozenset(
    {"status", "start", "stop", "restart", "remove"}
)


@dataclass(frozen=True)
class CanonicalPolicyFlag:
    """A CLI spelling whose storage location is owned by the request schema."""

    field: str
    flag: str
    value_kind: str
    location: str


_POLICY_FLAG_CANDIDATES = (
    ("keep_alive", "--keep-alive", "boolean"),
    ("restart_limit", "--restart-limit", "integer"),
    ("restart_window_seconds", "--restart-window-seconds", "integer"),
    ("rearm_crash_loop", "--rearm-crash-loop", "boolean"),
)


def canonical_policy_flags(
    *,
    request_keys: Iterable[str] = RUNTIME_REQUEST_KEYS,
    option_keys: Iterable[str] = RUNTIME_OPTION_KEYS,
) -> tuple[CanonicalPolicyFlag, ...]:
    """Return only policy flags already exposed by the canonical validator.

    Supervision policy may ultimately live at the request or options level.
    Looking up the canonical key sets keeps this transport neutral and makes a
    later schema addition visible without adding parallel CLI validation.
    """

    request_fields = frozenset(request_keys)
    option_fields = frozenset(option_keys)
    result: list[CanonicalPolicyFlag] = []
    for field, flag, value_kind in _POLICY_FLAG_CANDIDATES:
        if field in request_fields:
            location = "request"
        elif field in option_fields:
            location = "options"
        else:
            continue
        result.append(
            CanonicalPolicyFlag(
                field=field,
                flag=flag,
                value_kind=value_kind,
                location=location,
            )
        )
    return tuple(result)


def add_runtime_cli_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach legacy JSON inputs and the explicit flag adapter to ``parser``."""

    parser.add_argument(
        "runtime_action",
        nargs="?",
        metavar="ACTION",
        help=(
            "flag-mode action for an existing target: "
            + "|".join(sorted(RUNTIME_SIMPLE_ACTIONS & RUNTIME_ACTIONS))
        ),
    )
    request_input = parser.add_mutually_exclusive_group()
    request_input.add_argument("--request-json", help="inline strict JSON request")
    request_input.add_argument(
        "--request-file", help="absolute path to a strict JSON request file"
    )
    parser.add_argument(
        "--operation-id",
        help=(
            "canonical operation UUID to reuse for an exact broker replay; "
            "one is generated before dispatch when omitted"
        ),
    )

    parser.add_argument("--agent", help="requesting agent or session identity")
    parser.add_argument("--root-repo", help="canonical original Git worktree")
    temporary = parser.add_mutually_exclusive_group()
    temporary.add_argument(
        "--temporary-repo", help="canonical temporary linked worktree"
    )
    temporary.add_argument(
        "--no-temporary-repo",
        action="store_true",
        help="explicitly state that this request has no temporary worktree",
    )

    parser.add_argument(
        "--target-kind",
        metavar="KIND",
        help="target kind: " + "|".join(sorted(RUNTIME_TARGET_KINDS)),
    )
    parser.add_argument(
        "--target-id",
        help=(
            "normalized immutable resource ID; discover it with "
            "`inventory --project ROOT_REPO --compact-json`"
        ),
    )
    parser.add_argument("--target-name", help="required service display/runtime name")
    parser.add_argument(
        "--purpose",
        metavar="PURPOSE",
        help="request purpose: " + "|".join(sorted(RUNTIME_PURPOSES)),
    )

    ttl = parser.add_mutually_exclusive_group()
    ttl.add_argument("--ttl-seconds", help="positive bounded runtime TTL")
    ttl.add_argument(
        "--no-ttl",
        action="store_true",
        help="explicitly state that this request has no TTL",
    )
    parser.add_argument(
        "--kill-after-run",
        metavar="true|false",
        help="explicit KillAfterRun boolean; only action=run may set true",
    )
    parser.add_argument("--reason", help="concise attributed lifecycle reason")
    parser.add_argument("--remove-plan-id", help="durable worker-removal plan UUID")
    parser.add_argument(
        "--remove-plan-fingerprint", help="exact worker-removal plan fingerprint"
    )
    parser.add_argument(
        "--remove-confirmation-phrase",
        help="exact confirmation phrase returned by the removal plan",
    )

    for policy in canonical_policy_flags():
        metavar = "true|false" if policy.value_kind == "boolean" else "N"
        if policy.field == "keep_alive":
            help_text = (
                "required on first persistent-worker start; true arms "
                "crash restart supervision"
            )
        elif policy.field == "restart_limit":
            help_text = (
                "crash-loop limit used with --keep-alive true "
                f"(default {DEFAULT_CRASH_LIMIT})"
            )
        elif policy.field == "restart_window_seconds":
            help_text = (
                "crash-loop window used with --keep-alive true "
                f"(default {DEFAULT_CRASH_WINDOW_SECONDS})"
            )
        elif policy.field == "rearm_crash_loop":
            help_text = (
                "explicitly re-arm a permanently tripped worker after its fix"
            )
        else:  # pragma: no cover - candidates are exhaustive
            help_text = f"canonical {policy.field.replace('_', ' ')} policy"
        parser.add_argument(
            policy.flag,
            dest=policy.field,
            metavar=metavar,
            help=help_text,
        )

    parser.add_argument(
        "--pretty",
        action="store_false",
        dest="compact_json",
        default=True,
        help="pretty-print JSON (compact one-line JSON is the default)",
    )


def _explicit_boolean(raw: Any, *, field: str) -> bool:
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise RuntimeRequestError(f"{field} must be exactly true or false")


def canonical_runtime_operation_id(raw: Any) -> str:
    """Validate outer transport identity without adding it to the request schema."""

    if not isinstance(raw, str):
        raise RuntimeRequestError("operation_id must be a canonical UUID")
    try:
        canonical = str(uuid.UUID(raw))
    except (ValueError, AttributeError, TypeError):
        raise RuntimeRequestError(
            "operation_id must be a canonical UUID"
        ) from None
    if canonical != raw:
        raise RuntimeRequestError("operation_id must be a canonical UUID")
    return canonical


def runtime_cli_operation_id(namespace: argparse.Namespace) -> str:
    """Return and retain the one operation UUID owned by this CLI invocation."""

    raw = getattr(namespace, "operation_id", None)
    if raw is None:
        raw = str(uuid.uuid4())
    operation_id = canonical_runtime_operation_id(raw)
    namespace.operation_id = operation_id
    return operation_id


def _explicit_integer(raw: Any, *, field: str) -> int:
    if not isinstance(raw, str) or not raw or not raw.isascii() or not raw.isdigit():
        raise RuntimeRequestError(f"{field} must be a positive integer")
    try:
        return int(raw, 10)
    except ValueError as error:
        raise RuntimeRequestError(f"{field} must be a positive integer") from error


def _flag_values_present(namespace: argparse.Namespace) -> list[str]:
    names = (
        "runtime_action",
        "agent",
        "root_repo",
        "temporary_repo",
        "no_temporary_repo",
        "target_kind",
        "target_id",
        "target_name",
        "purpose",
        "ttl_seconds",
        "no_ttl",
        "kill_after_run",
        "reason",
        "remove_plan_id",
        "remove_plan_fingerprint",
        "remove_confirmation_phrase",
        *(policy.field for policy in canonical_policy_flags()),
    )
    present: list[str] = []
    for name in names:
        value = getattr(namespace, name, None)
        if value is not None and value is not False:
            present.append(name)
    return present


def runtime_cli_error_context(namespace: argparse.Namespace) -> dict[str, Any]:
    """Recover bounded flag identity without treating invalid input as valid."""

    target: dict[str, Any] = {
        "kind": getattr(namespace, "target_kind", None),
        "id": getattr(namespace, "target_id", None),
        "name": getattr(namespace, "target_name", None),
    }
    return runtime_request_error_context(
        {
            "action": getattr(namespace, "runtime_action", None),
            "root_repo": getattr(namespace, "root_repo", None),
            "temporary_repo": getattr(namespace, "temporary_repo", None),
            "target": target,
        }
    )


def runtime_request_from_flags(namespace: argparse.Namespace) -> dict[str, Any]:
    """Build and canonically validate one request from language-neutral flags."""

    action = getattr(namespace, "runtime_action", None)
    available_actions = RUNTIME_SIMPLE_ACTIONS & RUNTIME_ACTIONS
    if action is None:
        raise RuntimeRequestError(
            "provide a runtime action or exactly one of --request-json/--request-file"
        )
    if action not in available_actions:
        available = ", ".join(sorted(available_actions))
        raise RuntimeRequestError(
            f"flag mode supports {available}; use a JSON request for other actions"
        )

    temporary_repo = getattr(namespace, "temporary_repo", None)
    no_temporary_repo = bool(getattr(namespace, "no_temporary_repo", False))
    if temporary_repo is None and not no_temporary_repo:
        raise RuntimeRequestError(
            "flag mode requires --temporary-repo or --no-temporary-repo"
        )

    raw_ttl = getattr(namespace, "ttl_seconds", None)
    no_ttl = bool(getattr(namespace, "no_ttl", False))
    if raw_ttl is None and not no_ttl:
        raise RuntimeRequestError("flag mode requires --ttl-seconds or --no-ttl")
    ttl_seconds = (
        None
        if no_ttl
        else _explicit_integer(raw_ttl, field="ttl_seconds")
    )

    raw_kill_after_run = getattr(namespace, "kill_after_run", None)
    if raw_kill_after_run is None:
        raise RuntimeRequestError("flag mode requires --kill-after-run true|false")

    target: dict[str, Any] = {"kind": getattr(namespace, "target_kind", None)}
    target_id = getattr(namespace, "target_id", None)
    target_name = getattr(namespace, "target_name", None)
    if target_id is not None:
        target["id"] = target_id
    if target_name is not None:
        target["name"] = target_name

    options: dict[str, Any] = {}
    reason = getattr(namespace, "reason", None)
    if reason is not None:
        options["reason"] = reason
    for field in (
        "remove_plan_id",
        "remove_plan_fingerprint",
        "remove_confirmation_phrase",
    ):
        value = getattr(namespace, field, None)
        if value is not None:
            options[field] = value

    request: dict[str, Any] = {
        "schema_version": 1,
        "action": action,
        "agent": getattr(namespace, "agent", None),
        "root_repo": getattr(namespace, "root_repo", None),
        "temporary_repo": temporary_repo,
        "target": target,
        "purpose": getattr(namespace, "purpose", None),
        "ttl_seconds": ttl_seconds,
        "kill_after_run": _explicit_boolean(
            raw_kill_after_run, field="kill_after_run"
        ),
        "options": options,
    }

    for policy in canonical_policy_flags():
        raw = getattr(namespace, policy.field, None)
        if raw is None:
            continue
        if policy.value_kind == "boolean":
            value: Any = _explicit_boolean(raw, field=policy.field)
        else:
            value = _explicit_integer(raw, field=policy.field)
        if policy.location == "request":
            request[policy.field] = value
        else:
            options[policy.field] = value

    return validate_runtime_request(request)


def load_runtime_cli_request(namespace: argparse.Namespace) -> dict[str, Any]:
    """Load either the legacy JSON form or the flag form, never a mixture."""

    request_json = getattr(namespace, "request_json", None)
    request_file = getattr(namespace, "request_file", None)
    uses_legacy_input = request_json is not None or request_file is not None
    flag_values = _flag_values_present(namespace)
    if uses_legacy_input:
        if flag_values:
            rendered = ", ".join(name.replace("_", "-") for name in flag_values)
            raise RuntimeRequestError(
                "JSON request input cannot be combined with flag-mode fields: "
                + rendered
            )
        return load_runtime_request(
            request_json=request_json,
            request_file=request_file,
        )
    return runtime_request_from_flags(namespace)
