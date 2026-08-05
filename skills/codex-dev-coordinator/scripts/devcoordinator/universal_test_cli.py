"""Agent-facing CLI contracts for the universal asynchronous test harness.

Protected broker planning is preferred whenever it is available so the
snapshot service, rather than the calling account, owns repository discovery.
Local deterministic planning remains available for advisory use and older
brokers. Queue and evidence operations remain broker-only; when the protected
broker profile or an asynchronous operation is unavailable, this module
returns one explicit typed pending contract instead of reaching into
service-owned state.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Callable, Mapping, Sequence
import uuid

from .test_actor import TestActorContractError, calling_codex_test_actor
from .universal_test_contract import (
    MANIFEST_RELATIVE_PATH,
    MANIFEST_SCHEMA_VERSION,
    ManifestContractError,
    SourceMode,
    TestManifest,
    load_test_manifest,
    parse_test_manifest,
)
from .universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    DEFAULT_LAUNCH_TIMEOUT_SECONDS,
    SourceIdentity,
    TestPlan,
    TestPlanError,
    create_test_plan,
)
from .universal_test_service import decode_test_plan_document
from .universal_test_snapshot import (
    GitSnapshotSource,
    SnapshotMaterializationError,
    SnapshotMaterializationRequest,
)


MAX_DISCOVERED_FILES = 100_000
MAX_FINGERPRINT_FILE_BYTES = 256 * 1024 * 1024
MAX_FINGERPRINT_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_GIT_DELTA_BYTES = 256 * 1024 * 1024
MAX_AGENT_ENVELOPE_BYTES = 8 * 1024
_BROKER_PROFILE_ERROR = "protected broker profile is unavailable or invalid"
_LOCK_NAMES = frozenset(
    {
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "package-lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)
_SCHEDULER_MESSAGE = (
    "The protected asynchronous test scheduler is unavailable. "
    "No run or evidence identity was fabricated; restore the broker/testd "
    "connection and retry the same request."
)
_OPAQUE_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)


class UniversalTestCliError(ValueError):
    """One local CLI request cannot be represented safely."""


def _encoded_size(value: Mapping[str, object]) -> int:
    return len(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def _bounded_output_text(value: object, *, maximum_bytes: int = 384) -> str:
    """Return one single-line printable diagnostic with a stable truncation seal."""

    raw = str(value)
    printable = "".join(
        character if character.isprintable() and ord(character) != 127 else " "
        for character in raw
    )
    normalized = " ".join(printable.split()) or "unavailable"
    encoded = normalized.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return normalized
    seal = hashlib.sha256(encoded).hexdigest()[:16]
    suffix = f"...[truncated sha256:{seal}]"
    prefix_bytes = maximum_bytes - len(suffix.encode("utf-8"))
    if prefix_bytes <= 0:
        raise UniversalTestCliError("diagnostic output bound is too small")
    prefix = encoded[:prefix_bytes].decode("utf-8", errors="ignore")
    return prefix + suffix


def _issue_summary(value: object) -> dict[str, str]:
    raw = value if isinstance(value, Mapping) else {}
    severity = str(raw.get("severity", "error"))
    if severity not in {"error", "warning", "info"}:
        severity = "error"
    return {
        "severity": severity,
        "code": _bounded_output_text(raw.get("code", "unknown"), maximum_bytes=96),
        "message": _bounded_output_text(
            raw.get("message", "diagnostic unavailable"), maximum_bytes=384
        ),
    }


def _capability_policy_summary(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return {"ok": False, "status": "invalid"}
    missing_raw = value.get("missing", ())
    missing_values = (
        list(missing_raw)
        if isinstance(missing_raw, (list, tuple))
        else ["invalid-missing-list"]
    )
    retained_count = value.get("missing_count")
    missing_count = (
        retained_count
        if type(retained_count) is int and retained_count >= len(missing_values)
        else len(missing_values)
    )
    visible = [
        _bounded_output_text(item, maximum_bytes=96) for item in missing_values[:8]
    ]
    return {
        "ok": value.get("ok") is True,
        "missing_count": missing_count,
        "missing": visible,
        "truncated": value.get("truncated") is True
        or missing_count > len(visible),
    }


def _require_agent_envelope(
    document: dict[str, Any], *, surface: str
) -> dict[str, Any]:
    if _encoded_size(document) > MAX_AGENT_ENVELOPE_BYTES:
        raise UniversalTestCliError(
            f"{surface} exceeds the 8 KiB default agent output contract"
        )
    return document


def _bounded_positive(raw: str, *, name: str, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
    if not 1 <= value <= maximum:
        raise argparse.ArgumentTypeError(f"{name} must be from 1 through {maximum}")
    return value


def _page_limit(raw: str) -> int:
    return _bounded_positive(raw, name="limit", maximum=50)


def _wait_timeout(raw: str) -> int:
    return _bounded_positive(raw, name="wait timeout", maximum=86_400)


def _execution_timeout(raw: str) -> int:
    return _bounded_positive(raw, name="execution timeout", maximum=86_400)


def _launch_timeout(raw: str) -> int:
    return _bounded_positive(raw, name="launch timeout", maximum=3_600)


def _stats_days(raw: str) -> int:
    return _bounded_positive(raw, name="statistics period", maximum=3_650)


def _stats_limit(raw: str) -> int:
    return _bounded_positive(raw, name="statistics limit", maximum=500)


def _operation_id(raw: str) -> str:
    try:
        parsed = uuid.UUID(raw)
    except (ValueError, AttributeError) as error:
        raise argparse.ArgumentTypeError("operation ID must be a canonical UUID") from error
    if str(parsed) != raw:
        raise argparse.ArgumentTypeError("operation ID must be a canonical UUID")
    return raw


def _opaque_id(raw: str) -> str:
    if (
        not isinstance(raw, str)
        or not 1 <= len(raw) <= 128
        or raw[0] not in _OPAQUE_ID_CHARS - frozenset("_.:@-")
        or any(character not in _OPAQUE_ID_CHARS for character in raw)
        or ".." in raw
    ):
        raise argparse.ArgumentTypeError("identity must be one bounded opaque identifier")
    return raw


def _actor(raw: str) -> str:
    if (
        not isinstance(raw, str)
        or not raw
        or raw != raw.strip()
        or len(raw.encode("utf-8")) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise argparse.ArgumentTypeError("agent must be one bounded printable identifier")
    return raw


def _reason(raw: str) -> str:
    normalized = raw.strip() if isinstance(raw, str) else ""
    if (
        not normalized
        or len(normalized) > 500
        or any(character in normalized for character in "\x00\r\n")
    ):
        raise argparse.ArgumentTypeError(
            "reason must be from 1 through 500 single-line characters"
        )
    return normalized


def _add_explicit_repository_source(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent", required=True, type=_actor)
    parser.add_argument("--root-repo", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--temporary-repo")
    source.add_argument("--no-temporary-repo", action="store_true")


def _add_run_repository(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository-id",
        dest="repository",
        required=True,
        type=_opaque_id,
        help="immutable repository identity that owns the plan or run",
    )


def add_universal_test_cli_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Register the current universal test-harness surface."""

    tests = subparsers.add_parser(
        "test",
        help="plan, submit, and inspect repository tests through the universal harness",
    )
    actions = tests.add_subparsers(dest="action", required=True)

    manifest = actions.add_parser("manifest", help="manage the repository test contract")
    manifest_actions = manifest.add_subparsers(dest="manifest_action", required=True)
    manifest_init = manifest_actions.add_parser(
        "init", help="atomically create a safe starter manifest"
    )
    manifest_init.add_argument("--root-repo", required=True)
    manifest_init.add_argument("--force", action="store_true")
    for action, help_text in (
        ("validate", "validate the manifest contract without executing tests"),
        (
            "doctor",
            "validate the contract and protected repository capability policy",
        ),
    ):
        command = manifest_actions.add_parser(action, help=help_text)
        command.add_argument("--root-repo", required=True)
        if action == "doctor":
            command.set_defaults(compact_json=True)

    plan = actions.add_parser("plan", help="create a deterministic test selection preview")
    _add_explicit_repository_source(plan)
    plan.add_argument("--operation-id", required=True, type=_operation_id)
    plan.add_argument(
        "--intent",
        required=True,
        choices=("change", "checkpoint", "handoff", "release", "manual"),
    )
    plan.add_argument(
        "--change",
        action="append",
        default=[],
        metavar="STATUS:PATH",
        help=(
            "override Git discovery; repeat modified:path, added:path, deleted:path, "
            "untracked:path, or renamed:old-path:new-path"
        ),
    )
    plan.add_argument(
        "--execution-timeout-seconds",
        type=_execution_timeout,
        help=(
            "override every selected target's execution deadline; omitted uses "
            "the repository manifest"
        ),
    )
    plan.add_argument(
        "--launch-timeout-seconds",
        type=_launch_timeout,
        default=DEFAULT_LAUNCH_TIMEOUT_SECONDS,
        help="total launch and reconciliation deadline (default: 300)",
    )
    plan.add_argument(
        "--target",
        action="append",
        default=[],
        help="request one declared target (manual intent only; repeatable)",
    )
    plan.add_argument(
        "--full",
        action="store_true",
        help="include every changed path and selection reason in the preview",
    )
    plan.set_defaults(compact_json=True)

    submit = actions.add_parser(
        "submit", help="enqueue a registered plan and return immediately"
    )
    _add_run_repository(submit)
    submit.add_argument("--plan-id", required=True, type=_opaque_id)
    submit.add_argument("--operation-id", required=True, type=_operation_id)

    for action, help_text in (
        ("status", "read detailed state for one exact run"),
        ("summary", "read the bounded agent-focused run summary"),
    ):
        command = actions.add_parser(action, help=help_text)
        _add_run_repository(command)
        command.add_argument("--run-id", required=True, type=_opaque_id)

    failures = actions.add_parser(
        "failures", help="read one cursor-bounded page of actionable failures"
    )
    _add_run_repository(failures)
    failures.add_argument("--run-id", required=True, type=_opaque_id)
    failures.add_argument("--after", type=_opaque_id)
    failures.add_argument("--limit", type=_page_limit, default=25)

    artifact = actions.add_parser(
        "artifact", help="resolve one exact verified artifact handle"
    )
    _add_run_repository(artifact)
    artifact.add_argument("--run-id", required=True, type=_opaque_id)
    artifact.add_argument("--artifact-id", required=True, type=_opaque_id)

    cancel = actions.add_parser("cancel", help="request cancellation idempotently")
    _add_run_repository(cancel)
    cancel.add_argument("--run-id", required=True, type=_opaque_id)
    cancel.add_argument("--reason", required=True, type=_reason)
    cancel.add_argument("--operation-id", required=True, type=_operation_id)

    retry = actions.add_parser("retry", help="retry only failed work idempotently")
    _add_run_repository(retry)
    retry.add_argument("--run-id", required=True, type=_opaque_id)
    retry.add_argument("--failed-only", action="store_true", required=True)
    retry.add_argument("--operation-id", required=True, type=_operation_id)

    policy = actions.add_parser("policy", help="inspect named evidence policy state")
    policy_actions = policy.add_subparsers(dest="policy_action", required=True)
    policy_check = policy_actions.add_parser(
        "check", help="check one immutable snapshot against a named policy"
    )
    policy_check.add_argument("--root-repo", required=True)
    policy_check.add_argument("--policy", required=True, type=_opaque_id)
    policy_check.add_argument("--snapshot", required=True, type=_opaque_id)
    policy_check.add_argument("--operation-id", type=_operation_id)

    catalog = actions.add_parser(
        "catalog", help="report ready, missing, and invalid repository manifests"
    )
    catalog.add_argument("--root-repo")
    catalog.set_defaults(compact_json=True)

    stats = actions.add_parser("stats", help="read bounded repository test rollups")
    stats.add_argument("--project", "--root-repo", dest="project", required=True)
    stats.add_argument("--days", type=_stats_days, default=30)
    stats.add_argument("--limit", type=_stats_limit, default=25)

    wait = actions.add_parser(
        "wait", help="explicitly wait for one run for at most 86400 seconds"
    )
    _add_run_repository(wait)
    wait.add_argument("--run-id", required=True, type=_opaque_id)
    wait.add_argument("--timeout-seconds", required=True, type=_wait_timeout)
    return tests


def _manifest_template() -> dict[str, object]:
    intents = {
        "change": {"source_mode": "live", "allow_reuse": False},
        "checkpoint": {"source_mode": "live", "allow_reuse": False},
        "handoff": {"source_mode": "immutable", "allow_reuse": True},
        "release": {"source_mode": "immutable", "allow_reuse": False},
        "manual": {"source_mode": "immutable", "allow_reuse": False},
    }
    all_intents = list(intents)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "defaults": {
            "timeout_seconds": 900,
            "network": "none",
            "environment": {},
        },
        "global_inputs": [str(MANIFEST_RELATIVE_PATH)],
        "targets": {
            "tests": {
                "driver": "automation",
                "reporter": "automation-events",
                "argv": ["./scripts/test", "{events}"],
                "cwd": ".",
                "inputs": ["**"],
                "depends_on": [],
                "intents": all_intents,
                "retry": {
                    "max_attempts": 2,
                    "retry_on": ["lease_expired_before_launch"],
                },
            }
        },
        "intents": intents,
        "fixtures": {},
        "credentials": {},
        "evidence_policies": {
            "handoff": {
                "intent": "handoff",
                "required_targets": ["tests"],
                "max_age_seconds": 86400,
                "allow_reuse": True,
            },
            "release": {
                "intent": "release",
                "required_targets": ["tests"],
                "max_age_seconds": 3600,
                "allow_reuse": False,
            },
        },
    }


def _manifest_path(root: Path) -> Path:
    path = root.joinpath(*MANIFEST_RELATIVE_PATH.parts)
    parent = path.parent
    if parent.exists():
        resolved_parent = parent.resolve()
        if resolved_parent != root and root not in resolved_parent.parents:
            raise UniversalTestCliError("manifest directory resolves outside the repository")
    return path


def initialize_manifest(root: Path, *, force: bool) -> dict[str, Any]:
    """Atomically create the final contract under the invoking repository UID."""

    root = root.resolve()
    path = _manifest_path(root)
    if path.exists() or path.is_symlink():
        if not force:
            raise UniversalTestCliError(f"test manifest already exists: {path}")
        if path.is_symlink() or not path.is_file():
            raise UniversalTestCliError("existing test manifest must be one regular file")
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    path = _manifest_path(root)
    document = _manifest_template()
    parse_test_manifest(document, repository_root=root)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return manifest_health(root, doctor=False) | {"created": True}


def _target_graph(manifest: TestManifest) -> dict[str, list[str]]:
    return {
        name: list(target.depends_on)
        for name, target in sorted(manifest.targets.items())
    }


def manifest_health(root: Path, *, doctor: bool) -> dict[str, Any]:
    root = root.resolve()
    try:
        manifest = load_test_manifest(root)
    except ManifestContractError as error:
        missing = "manifest is missing:" in str(error)
        return {
            "schema_version": 1,
            "ok": False,
            "status": "missing" if missing else "invalid",
            "repository": str(root),
            "manifest": str(_manifest_path(root)),
            "issues": [
                {
                    "severity": "error",
                    "code": "manifest_missing" if missing else "manifest_invalid",
                    "message": str(error),
                }
            ],
        }
    issues: list[dict[str, str]] = []
    if doctor:
        if not (root / ".git").exists():
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--git-dir"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
            if completed.returncode != 0:
                issues.append(
                    {
                        "severity": "warning",
                        "code": "git_identity_unavailable",
                        "message": "repository source identity cannot be derived from Git",
                    }
                )
        for name in sorted(manifest.targets):
            target = manifest.targets[name]
            if not (root / target.cwd).is_dir():
                issues.append(
                    {
                        "severity": "error",
                        "code": "target_cwd_missing",
                        "message": f"target {name!r} working directory does not exist",
                    }
                )
    errors = sum(issue["severity"] == "error" for issue in issues)
    warnings = sum(issue["severity"] == "warning" for issue in issues)
    return {
        "schema_version": 1,
        "ok": errors == 0,
        "status": "invalid" if errors else "ready",
        "repository": str(root),
        "manifest": str(_manifest_path(root)),
        "manifest_schema": manifest.schema_version,
        "manifest_fingerprint": manifest.fingerprint,
        "targets": sorted(manifest.targets),
        "target_graph": _target_graph(manifest),
        "intents": sorted(manifest.intents),
        "evidence_policies": sorted(manifest.evidence_policies),
        "issues": issues,
        "warning_count": warnings,
    }


def _bounded_doctor_envelope(document: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(document)
    raw_issues = document.get("issues", ())
    issues = (
        [_issue_summary(item) for item in raw_issues]
        if isinstance(raw_issues, (list, tuple))
        else [_issue_summary(raw_issues)]
    )
    sanitized["issues"] = issues
    targets_value = document.get("targets", ())
    intents_value = document.get("intents", ())
    policies_value = document.get("evidence_policies", ())
    sanitized.setdefault(
        "target_count",
        len(targets_value) if isinstance(targets_value, (list, tuple)) else 0,
    )
    sanitized.setdefault(
        "intent_count",
        len(intents_value) if isinstance(intents_value, (list, tuple)) else 0,
    )
    sanitized.setdefault(
        "evidence_policy_count",
        len(policies_value) if isinstance(policies_value, (list, tuple)) else 0,
    )
    sanitized.setdefault("issue_count", len(issues))
    sanitized.setdefault(
        "error_count", sum(item["severity"] == "error" for item in issues)
    )
    sanitized.setdefault(
        "truncated",
        {
            "targets": False,
            "target_graph": False,
            "intents": False,
            "evidence_policies": False,
            "issues": False,
        },
    )
    if "capability_policy" in sanitized:
        sanitized["capability_policy"] = _capability_policy_summary(
            sanitized["capability_policy"]
        )
    if "broker_profile_error" in sanitized:
        sanitized["broker_profile_error"] = _BROKER_PROFILE_ERROR
    if _encoded_size(sanitized) <= MAX_AGENT_ENVELOPE_BYTES:
        return sanitized

    targets_raw = document.get("targets", ())
    targets = list(targets_raw) if isinstance(targets_raw, (list, tuple)) else []
    intents_raw = document.get("intents", ())
    intents = list(intents_raw) if isinstance(intents_raw, (list, tuple)) else []
    policies_raw = document.get("evidence_policies", ())
    policies = list(policies_raw) if isinstance(policies_raw, (list, tuple)) else []
    graph_raw = document.get("target_graph", {})
    graph = graph_raw if isinstance(graph_raw, Mapping) else {}

    for target_limit, graph_limit, issue_limit, dependency_limit in (
        (32, 16, 12, 8),
        (16, 8, 8, 6),
        (8, 4, 4, 4),
        (4, 2, 2, 2),
        (0, 0, 1, 0),
    ):
        visible_targets = targets[:target_limit]
        graph_names = sorted(str(name) for name in graph)[:graph_limit]
        visible_graph: dict[str, list[str]] = {}
        for name in graph_names:
            dependencies = graph.get(name, ())
            values = (
                list(dependencies)
                if isinstance(dependencies, (list, tuple))
                else []
            )
            visible_graph[_bounded_output_text(name, maximum_bytes=96)] = [
                _bounded_output_text(item, maximum_bytes=96)
                for item in values[:dependency_limit]
            ]
        candidate: dict[str, Any] = {
            "schema_version": document.get("schema_version", 1),
            "ok": document.get("ok") is True,
            "status": document.get("status", "invalid"),
            "repository": _bounded_output_text(
                document.get("repository", "unavailable"), maximum_bytes=768
            ),
            "manifest": _bounded_output_text(
                document.get("manifest", "unavailable"), maximum_bytes=768
            ),
            "target_count": len(targets),
            "targets": [
                _bounded_output_text(item, maximum_bytes=96)
                for item in visible_targets
            ],
            "target_graph": visible_graph,
            "intent_count": len(intents),
            "intents": [
                _bounded_output_text(item, maximum_bytes=96)
                for item in intents[:target_limit]
            ],
            "evidence_policy_count": len(policies),
            "evidence_policies": [
                _bounded_output_text(item, maximum_bytes=96)
                for item in policies[:target_limit]
            ],
            "issue_count": len(issues),
            "error_count": sum(item["severity"] == "error" for item in issues),
            "warning_count": sum(
                item["severity"] == "warning" for item in issues
            ),
            "issues": issues[:issue_limit],
            "truncated": {
                "targets": len(targets) > len(visible_targets),
                "target_graph": len(graph) > len(visible_graph),
                "intents": len(intents) > min(len(intents), target_limit),
                "evidence_policies": len(policies)
                > min(len(policies), target_limit),
                "issues": len(issues) > min(len(issues), issue_limit),
            },
        }
        for key in ("manifest_schema", "manifest_fingerprint"):
            if key in document:
                candidate[key] = document[key]
        if "capability_policy" in sanitized:
            candidate["capability_policy"] = sanitized["capability_policy"]
        if "broker_profile_error" in sanitized:
            candidate["broker_profile_error"] = _BROKER_PROFILE_ERROR
        if _encoded_size(candidate) <= MAX_AGENT_ENVELOPE_BYTES:
            return candidate
    raise UniversalTestCliError(
        "manifest doctor exceeds the 8 KiB default agent output contract"
    )


def _doctor_capability_policy(
    health: dict[str, Any], root: Path, broker_profile: object | None
) -> dict[str, Any]:
    if not health.get("manifest_fingerprint"):
        return _bounded_doctor_envelope(health)
    issues = list(health.get("issues", ()))
    policy = None
    if broker_profile is None:
        issues.append(
            {
                "severity": "error",
                "code": "capability_policy_unavailable",
                "message": "sealed test capability policy could not be checked without the protected broker profile",
            }
        )
    else:
        try:
            repository_id, _enrolled = _repository_id(root, broker_profile)
            setup = _call_scheduler(
                broker_profile,
                "test_repository_setup",
                action="manifest doctor",
                repository=repository_id,
            )
            policy = setup.get("capability_policy") if setup is not None else None
        except Exception:
            issues.append(
                {
                    "severity": "error",
                    "code": "capability_policy_unavailable",
                    "message": "sealed test capability policy could not be checked",
                }
            )
        if policy is not None:
            if not isinstance(policy, Mapping) or policy.get("ok") is not True:
                summary = _capability_policy_summary(policy)
                missing_count = (
                    summary.get("missing_count", 0)
                    if isinstance(summary, Mapping)
                    else 0
                )
                issues.append(
                    {
                        "severity": "error",
                        "code": "capability_policy_missing",
                        "message": (
                            "sealed test capability policy is incomplete; "
                            f"missing grant count: {missing_count}"
                        ),
                    }
                )
        elif not any(
            issue.get("code") == "capability_policy_unavailable"
            for issue in issues
        ):
            issues.append(
                {
                    "severity": "error",
                    "code": "capability_policy_unavailable",
                    "message": "broker setup omitted sealed test capability policy status",
                }
            )
    errors = sum(issue.get("severity") == "error" for issue in issues)
    warnings = sum(issue.get("severity") == "warning" for issue in issues)
    return _bounded_doctor_envelope(
        {
            **health,
            "ok": errors == 0,
            "status": "invalid" if errors else health.get("status", "ready"),
            "issues": issues,
            "warning_count": warnings,
            "capability_policy": _capability_policy_summary(policy),
        }
    )


def _git(root: Path, arguments: Sequence[str], *, maximum_bytes: int) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UniversalTestCliError(f"Git source inspection failed: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise UniversalTestCliError(
            f"Git source inspection failed: {detail or completed.returncode}"
        )
    if len(completed.stdout) > maximum_bytes:
        raise UniversalTestCliError("Git source inspection exceeded its bounded output")
    return completed.stdout


def _parse_explicit_change(raw: str) -> ChangedPath:
    status_text, separator, remainder = raw.partition(":")
    if not separator:
        raise UniversalTestCliError("change must use STATUS:PATH")
    try:
        status_value = ChangeStatus(status_text)
    except ValueError as error:
        raise UniversalTestCliError(f"unsupported change status: {status_text}") from error
    if status_value is ChangeStatus.RENAMED:
        previous, second_separator, path = remainder.partition(":")
        if not second_separator:
            raise UniversalTestCliError("renamed change must use renamed:OLD:NEW")
        return ChangedPath(path=path, status=status_value, previous_path=previous)
    return ChangedPath(path=remainder, status=status_value)


def discover_changes(root: Path) -> tuple[ChangedPath, ...]:
    output = _git(
        root,
        ["diff", "--name-status", "-z", "--find-renames", "HEAD", "--"],
        maximum_bytes=32 * 1024 * 1024,
    )
    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes: list[ChangedPath] = []
    index = 0
    while index < len(fields):
        status_token = fields[index].decode("ascii", errors="strict")
        index += 1
        if index >= len(fields):
            raise UniversalTestCliError("Git returned an incomplete changed-path record")
        first_path = os.fsdecode(fields[index])
        index += 1
        code = status_token[:1]
        if code in {"R", "C"}:
            if index >= len(fields):
                raise UniversalTestCliError("Git returned an incomplete rename record")
            second_path = os.fsdecode(fields[index])
            index += 1
            changes.append(
                ChangedPath(
                    path=second_path,
                    status=ChangeStatus.RENAMED,
                    previous_path=first_path,
                )
            )
        else:
            mapped = {
                "A": ChangeStatus.ADDED,
                "D": ChangeStatus.DELETED,
                "M": ChangeStatus.MODIFIED,
            }.get(code, ChangeStatus.MODIFIED)
            changes.append(ChangedPath(path=first_path, status=mapped))
    untracked = _git(
        root,
        ["ls-files", "-z", "--others", "--exclude-standard"],
        maximum_bytes=32 * 1024 * 1024,
    )
    for raw_path in untracked.split(b"\0"):
        if raw_path:
            changes.append(
                ChangedPath(path=os.fsdecode(raw_path), status=ChangeStatus.UNTRACKED)
            )
    unique = {
        (item.path, item.status.value, item.previous_path): item for item in changes
    }
    return tuple(unique[key] for key in sorted(unique))


def _file_digest(root: Path, relative: str) -> tuple[str, int]:
    candidate = root / relative
    try:
        parent = candidate.parent.resolve()
    except OSError as error:
        raise UniversalTestCliError(f"cannot resolve source path {relative!r}: {error}") from error
    if parent != root and root not in parent.parents:
        raise UniversalTestCliError(f"source path escapes repository: {relative}")
    try:
        metadata = candidate.lstat()
    except FileNotFoundError:
        return hashlib.sha256(b"devcoordinator:deleted\0").hexdigest(), 0
    if stat.S_ISLNK(metadata.st_mode):
        resolved = candidate.resolve(strict=False)
        if resolved != root and root not in resolved.parents:
            raise UniversalTestCliError(
                f"source symlink escapes repository: {relative}"
            )
        payload = os.fsencode(os.readlink(candidate))
        return hashlib.sha256(b"devcoordinator:symlink\0" + payload).hexdigest(), len(payload)
    if not stat.S_ISREG(metadata.st_mode):
        raise UniversalTestCliError(f"source path is not a regular file: {relative}")
    if metadata.st_size > MAX_FINGERPRINT_FILE_BYTES:
        raise UniversalTestCliError(f"source file exceeds fingerprint bound: {relative}")
    digest = hashlib.sha256()
    size = 0
    with candidate.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _lock_file(path: str) -> bool:
    name = Path(path).name.casefold()
    return name in _LOCK_NAMES or name.endswith(".lock") or name.endswith("-lock.json")


def _live_source_fingerprint(
    root: Path,
    manifest: TestManifest,
    changes: Sequence[ChangedPath],
    *,
    repository_id: str,
    original_root: Path,
    intent: str,
) -> str:
    del changes
    request = SnapshotMaterializationRequest(
        repository_id=repository_id,
        original_root=str(original_root),
        temporary_root=(str(root) if root != original_root else None),
        manifest_fingerprint=manifest.fingerprint,
        intent=intent,
        owner_uid=os.geteuid(),
    )
    try:
        return GitSnapshotSource().scan(request).content_fingerprint
    except SnapshotMaterializationError as error:
        message = str(error)
        if any(
            marker in message
            for marker in (
                "absolute symlink is not immutable",
                "snapshot symlink escapes repository",
                "snapshot symlink target is excluded or incomplete",
            )
        ):
            message = "live source symlink escapes or targets excluded content"
        raise UniversalTestCliError(message) from error


def _local_repository_id(root: Path) -> str:
    return "local-" + hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:32]


def _repository_id(root: Path, broker_profile: object | None) -> tuple[str, bool]:
    if broker_profile is None:
        return _local_repository_id(root), False
    try:
        repository = broker_profile.repository(str(root))  # type: ignore[attr-defined]
    except Exception as error:
        raise UniversalTestCliError(
            "root repository is not uniquely enrolled in the configured broker profile"
        ) from error
    return str(repository.repo_id), True


def _json_value(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _json_value(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise UniversalTestCliError(
        f"scheduler returned a non-JSON value: {type(value).__name__}"
    )


def _scheduler_method(
    broker_profile: object | None, method_name: str
) -> Callable[..., object] | None:
    if broker_profile is None:
        return None
    method = getattr(broker_profile, method_name, None)
    return method if callable(method) else None


def _call_scheduler(
    broker_profile: object | None,
    method_name: str,
    *,
    action: str,
    **arguments: object,
) -> dict[str, Any] | None:
    """Invoke only a broker-profile scheduler method, never the test store."""

    method = _scheduler_method(broker_profile, method_name)
    if method is None:
        return None
    try:
        raw = method(**arguments)
    except NotImplementedError:
        return None
    normalized = _json_value(raw)
    if isinstance(normalized, Mapping):
        payload = dict(normalized)
    else:
        payload = {"result": normalized}
    return {
        "schema_version": 1,
        "ok": True,
        "classification": "test_scheduler_result",
        "action": action,
        **payload,
    }


def _plan_registration_summary(
    raw: Mapping[str, object], *, plan: TestPlan
) -> dict[str, object]:
    summary: dict[str, object] = {
        "plan_id": plan.plan_id,
        "snapshot_id": plan.source.snapshot_id,
        "registered": raw.get("registered", True) is True,
    }
    if "capability_policy" in raw:
        summary["capability_policy"] = _capability_policy_summary(
            raw.get("capability_policy")
        )
    return summary


def _compact_plan_document(
    plan: TestPlan, *, maximum_bytes: int = 6000
) -> dict[str, Any]:
    """Bound the default agent preview while retaining exact plan identity."""

    def document(
        *, change_limit: int, target_limit: int, reason_limit: int, wave_limit: int
    ) -> dict[str, Any]:
        visible_targets = plan.selected_targets[:target_limit]
        visible_changes = plan.changes[:change_limit]
        visible_waves = plan.dependency_waves[:wave_limit]
        return {
            "plan_id": plan.plan_id,
            "fingerprint": plan.fingerprint,
            "execution_fingerprint": plan.execution_fingerprint,
            "manifest_fingerprint": plan.manifest_fingerprint,
            "repository_id": plan.repository_id,
            "intent": plan.intent,
            "timeouts": plan.timeouts.to_document(),
            "source": {
                "mode": plan.source.mode.value,
                "content_fingerprint": plan.source.content_fingerprint,
                "snapshot_id": plan.source.snapshot_id,
            },
            "change_count": len(plan.changes),
            "changes": [
                {
                    "path": change.path,
                    "status": change.status.value,
                    "previous_path": change.previous_path,
                }
                for change in visible_changes
            ],
            "selected_target_count": len(plan.selected_targets),
            "selected_targets": list(visible_targets),
            "dependency_wave_count": len(plan.dependency_waves),
            "dependency_waves": [
                list(wave[:target_limit]) for wave in visible_waves
            ],
            "selection": {
                name: list(plan.selection[name].reasons[:reason_limit])
                for name in visible_targets
            },
            "complete_intent_fallback": plan.complete_intent_fallback,
            "reusable": plan.reusable,
            "truncated": {
                "changes": len(plan.changes) > len(visible_changes),
                "targets": len(plan.selected_targets) > len(visible_targets),
                "waves": len(plan.dependency_waves) > len(visible_waves),
                "reasons": any(
                    len(plan.selection[name].reasons) > reason_limit
                    for name in visible_targets
                ),
            },
        }

    for limits in (
        (20, 32, 4, 16),
        (12, 24, 3, 12),
        (8, 16, 2, 8),
        (4, 8, 1, 4),
        (0, 4, 1, 2),
    ):
        candidate = document(
            change_limit=limits[0],
            target_limit=limits[1],
            reason_limit=limits[2],
            wave_limit=limits[3],
        )
        if len(
            json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        ) <= maximum_bytes:
            return candidate
    raise UniversalTestCliError("mandatory plan identity exceeds the agent output bound")


def _validate_temporary_repository(root: Path, temporary: Path) -> None:
    if root == temporary:
        raise UniversalTestCliError(
            "temporary repository must differ from the original root repository"
        )
    root_common = Path(
        _git(
            root,
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
            maximum_bytes=4096,
        )
        .decode("utf-8", errors="strict")
        .strip()
    ).resolve()
    temporary_common = Path(
        _git(
            temporary,
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
            maximum_bytes=4096,
        )
        .decode("utf-8", errors="strict")
        .strip()
    ).resolve()
    if root_common != temporary_common:
        raise UniversalTestCliError(
            "temporary repository is not a Git worktree of the original root"
        )
    worktrees = _git(
        root,
        ["worktree", "list", "--porcelain", "-z"],
        maximum_bytes=8 * 1024 * 1024,
    )
    published = {
        Path(os.fsdecode(field[len(b"worktree ") :])).resolve()
        for field in worktrees.split(b"\0")
        if field.startswith(b"worktree ")
    }
    if temporary not in published:
        raise UniversalTestCliError(
            "temporary repository is absent from the original Git worktree registry"
        )


def _broker_plan_preview(
    *,
    root: Path,
    effective: Path,
    temporary: Path | None,
    agent: str,
    intent: str,
    requested_targets: Sequence[str],
    execution_timeout_seconds: int | None,
    launch_timeout_seconds: int,
    broker_profile: object | None,
    operation_id: str,
    compact: bool,
) -> dict[str, Any] | None:
    """Return one validated broker plan, or ``None`` when preview is absent."""

    repository_id, enrolled = _repository_id(root, broker_profile)
    preview = _call_scheduler(
        broker_profile,
        "preview_test_plan",
        action="plan",
        repository=repository_id,
        intent=intent,
        temporary_root=(str(effective) if temporary is not None else None),
        requested_targets=tuple(requested_targets),
        execution_timeout_seconds=execution_timeout_seconds,
        launch_timeout_seconds=launch_timeout_seconds,
        operation_id=operation_id,
    )
    if preview is None:
        return None
    plan_document = preview.get("plan")
    if not isinstance(plan_document, Mapping):
        raise UniversalTestCliError(
            "broker preview omitted the complete plan document"
        )
    plan = decode_test_plan_document(plan_document)
    expected_temporary = str(effective) if temporary is not None else None
    allowed_source_modes = (
        {SourceMode.IMMUTABLE}
        if intent in {"handoff", "release"}
        else (
            {SourceMode.LIVE, SourceMode.IMMUTABLE}
            if intent == "manual"
            else {SourceMode.LIVE}
        )
    )
    if (
        plan.repository_id != repository_id
        or plan.intent != intent
        or plan.timeouts.execution_seconds != execution_timeout_seconds
        or plan.timeouts.launch_seconds != launch_timeout_seconds
    ):
        raise UniversalTestCliError(
            "broker preview returned contradictory repository, intent, or timeouts"
        )
    if (
        plan.source.original_root != str(root)
        or plan.source.temporary_root != expected_temporary
        or plan.source.mode not in allowed_source_modes
        or (
            plan.source.mode is SourceMode.IMMUTABLE
            and plan.source.snapshot_id is None
        )
        or (
            plan.source.mode is SourceMode.LIVE
            and plan.source.snapshot_id is not None
        )
    ):
        raise UniversalTestCliError(
            "broker preview returned contradictory source identity"
        )
    planned_requests = {
        target
        for target, selection in plan.selection.items()
        if "requested" in selection.reasons
    }
    if planned_requests != set(requested_targets):
        raise UniversalTestCliError(
            "broker preview returned contradictory requested targets"
        )
    if preview.get("operation_id") != operation_id:
        raise UniversalTestCliError(
            "broker preview omitted or contradicted the plan operation identity"
        )
    result = {
        "schema_version": 1,
        "ok": True,
        "classification": "broker_test_plan",
        "agent": agent,
        "operation_id": operation_id,
        "broker_enrolled": enrolled,
        "attestable": plan.source.mode is SourceMode.IMMUTABLE,
        "plan": _compact_plan_document(plan) if compact else plan.to_document(),
        "submission": {
            "available": True,
            "registration": _plan_registration_summary(preview, plan=plan),
        },
    }
    return (
        _require_agent_envelope(result, surface="test plan")
        if compact
        else result
    )


def build_local_plan(
    *,
    root: Path,
    temporary: Path | None,
    agent: str,
    intent: str,
    raw_changes: Sequence[str],
    requested_targets: Sequence[str],
    execution_timeout_seconds: int | None = None,
    launch_timeout_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS,
    broker_profile: object | None,
    operation_id: str,
    compact: bool = True,
) -> dict[str, Any]:
    root = root.resolve()
    effective = temporary.resolve() if temporary is not None else root
    if temporary is not None:
        _validate_temporary_repository(root, effective)
    if requested_targets and intent != "manual":
        raise UniversalTestCliError(
            "explicit test targets are supported only for manual intent"
        )
    # Explicit --change values intentionally keep their documented local
    # override semantics because the broker preview contract owns Git
    # discovery and does not accept caller-supplied paths.
    broker_preview = None
    if not raw_changes:
        broker_preview = _broker_plan_preview(
            root=root,
            effective=effective,
            temporary=temporary,
            agent=agent,
            intent=intent,
            requested_targets=requested_targets,
            execution_timeout_seconds=execution_timeout_seconds,
            launch_timeout_seconds=launch_timeout_seconds,
            broker_profile=broker_profile,
            operation_id=operation_id,
            compact=compact,
        )
    if broker_preview is not None:
        return broker_preview
    if intent in {"handoff", "release", "manual"}:
        if broker_preview is None:
            visible_requests = [
                _bounded_output_text(item, maximum_bytes=96)
                for item in requested_targets[:16]
            ]
            return _require_agent_envelope(
                scheduler_pending(
                    "plan",
                    operation_id=operation_id,
                    code="immutable_snapshot_broker_pending",
                    repository=_bounded_output_text(root, maximum_bytes=768),
                    temporary_repository=(
                        _bounded_output_text(effective, maximum_bytes=768)
                        if temporary is not None
                        else None
                    ),
                    intent=intent,
                    requested_target_count=len(requested_targets),
                    requested_targets=visible_requests,
                    requested_targets_truncated=(
                        len(requested_targets) > len(visible_requests)
                    ),
                ),
                surface="test plan",
            )
    manifest = load_test_manifest(effective)
    intent_contract = manifest.intents.get(intent)
    if intent_contract is None:
        raise TestPlanError(f"manifest does not declare intent {intent!r}")
    if intent_contract.source_mode is SourceMode.IMMUTABLE:
        raise TestPlanError("immutable intents must use broker snapshot preview")
    changes = (
        tuple(_parse_explicit_change(item) for item in raw_changes)
        if raw_changes
        else discover_changes(effective)
    )
    repository_id, enrolled = _repository_id(root, broker_profile)
    content_fingerprint = _live_source_fingerprint(
        effective,
        manifest,
        changes,
        repository_id=repository_id,
        original_root=root,
        intent=intent,
    )
    source = SourceIdentity(
        mode=SourceMode.LIVE,
        repository_id=repository_id,
        content_fingerprint=content_fingerprint,
        original_root=str(root),
        temporary_root=str(effective) if temporary is not None else None,
    )
    plan = create_test_plan(
        manifest,
        intent=intent,
        source=source,
        changes=changes,
        requested_targets=requested_targets,
        execution_timeout_seconds=execution_timeout_seconds,
        launch_timeout_seconds=launch_timeout_seconds,
    )
    registered = _call_scheduler(
        broker_profile,
        "register_test_plan",
        action="plan",
        plan=plan,
        manifest=manifest,
        actor=agent,
        operation_id=operation_id,
    )
    registration_available = registered is not None
    if registered is not None:
        registered_plan_id = registered.get("plan_id", plan.plan_id)
        if registered_plan_id != plan.plan_id:
            raise UniversalTestCliError(
                "broker registered a plan under a different immutable identity"
            )
        if registered.get("operation_id") != operation_id:
            raise UniversalTestCliError(
                "broker registration omitted or contradicted the plan operation identity"
            )
    result = {
        "schema_version": 1,
        "ok": True,
        "classification": (
            "broker_test_plan" if registration_available else "advisory_test_plan"
        ),
        "agent": agent,
        "operation_id": operation_id,
        "broker_enrolled": enrolled,
        # Registration makes the plan asynchronously runnable, but live source
        # can never become reusable or release-grade evidence.
        "attestable": False,
        "plan": _compact_plan_document(plan) if compact else plan.to_document(),
        "submission": {
            "available": registration_available,
            **(
                {"registration": _plan_registration_summary(registered, plan=plan)}
                if registered is not None
                else {
                    "code": "test_scheduler_broker_pending",
                    "message": _SCHEDULER_MESSAGE,
                }
            ),
        },
    }
    return (
        _require_agent_envelope(result, surface="test plan")
        if compact
        else result
    )


def scheduler_pending(
    action: str,
    *,
    code: str = "test_scheduler_broker_pending",
    **context: object,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ok": False,
        "classification": "test_scheduler_pending",
        "code": code,
        "action": action,
        "retryable": False,
        "message": _SCHEDULER_MESSAGE,
        **context,
    }


def _catalog_entry(root: Path) -> dict[str, Any]:
    health = manifest_health(root, doctor=False)
    return {
        key: health[key]
        for key in (
            "repository",
            "status",
            "manifest_fingerprint",
            "targets",
            "intents",
            "evidence_policies",
            "issues",
        )
        if key in health
    }


def _broker_catalog_entry(
    repository: object, broker_profile: object
) -> dict[str, Any]:
    repo_id = str(getattr(repository, "repo_id", ""))
    canonical_root = str(getattr(repository, "canonical_root", ""))
    setup = _call_scheduler(
        broker_profile,
        "test_repository_setup",
        action="catalog",
        repository=repo_id,
    )
    if setup is None:
        raise UniversalTestCliError(
            "protected broker profile does not expose repository test setup"
        )
    if (
        setup.get("repository_id") != repo_id
        or setup.get("status") not in {"ready", "missing", "invalid"}
    ):
        raise UniversalTestCliError(
            "broker returned contradictory repository test setup"
        )
    raw_targets = setup.get("targets", ())
    if not isinstance(raw_targets, (list, tuple)):
        raise UniversalTestCliError("broker returned invalid repository test targets")
    target_names: list[str] = []
    for target in raw_targets:
        if not isinstance(target, Mapping):
            raise UniversalTestCliError("broker returned invalid repository test target")
        name = target.get("name")
        if not isinstance(name, str) or not name:
            raise UniversalTestCliError("broker returned unnamed repository test target")
        target_names.append(name)
    if target_names != sorted(set(target_names)):
        raise UniversalTestCliError("broker returned contradictory repository test targets")
    return {
        "repository": canonical_root,
        "repository_id": repo_id,
        "targets": target_names,
        **{
            key: setup[key]
            for key in (
                "status",
                "manifest_schema",
                "manifest_fingerprint",
                "target_graph",
                "input_coverage",
                "input_coverage_gaps",
                "intents",
                "evidence_policies",
                "fixtures",
                "network_requirements",
                "isolation",
                "issues",
            )
            if key in setup
        },
    }


def _bounded_catalog_envelope(document: dict[str, Any]) -> dict[str, Any]:
    raw_entries = document.get("repositories", ())
    entries = list(raw_entries) if isinstance(raw_entries, (list, tuple)) else []
    sanitized_entries: list[dict[str, Any]] = []
    for raw_entry in entries:
        entry = dict(raw_entry) if isinstance(raw_entry, Mapping) else {}
        entry["repository"] = _bounded_output_text(
            entry.get("repository", "unavailable"), maximum_bytes=768
        )
        if "repository_id" in entry:
            entry["repository_id"] = _bounded_output_text(
                entry["repository_id"], maximum_bytes=128
            )
        raw_issues = entry.get("issues", ())
        entry["issues"] = (
            [_issue_summary(item) for item in raw_issues]
            if isinstance(raw_issues, (list, tuple))
            else [_issue_summary(raw_issues)]
        )
        sanitized_entries.append(entry)
    sanitized = {**document, "repositories": sanitized_entries}
    sanitized.setdefault("repository_count", len(sanitized_entries))
    sanitized.setdefault("truncated", {"repositories": False})
    if "broker_profile_error" in sanitized:
        sanitized["broker_profile_error"] = _BROKER_PROFILE_ERROR
    if _encoded_size(sanitized) <= MAX_AGENT_ENVELOPE_BYTES:
        return sanitized

    def bounded_values(entry: Mapping[str, object], key: str, limit: int) -> list[str]:
        raw = entry.get(key, ())
        values = list(raw) if isinstance(raw, (list, tuple)) else []
        return [
            _bounded_output_text(item, maximum_bytes=96) for item in values[:limit]
        ]

    for repository_limit, value_limit, issue_limit in (
        (24, 8, 2),
        (12, 6, 2),
        (8, 4, 1),
        (4, 2, 1),
        (1, 1, 1),
        (0, 0, 0),
    ):
        visible: list[dict[str, Any]] = []
        for entry in sanitized_entries[:repository_limit]:
            targets = entry.get("targets", ())
            intents = entry.get("intents", ())
            policies = entry.get("evidence_policies", ())
            issues = entry.get("issues", ())
            target_count = len(targets) if isinstance(targets, (list, tuple)) else 0
            intent_count = len(intents) if isinstance(intents, (list, tuple)) else 0
            policy_count = len(policies) if isinstance(policies, (list, tuple)) else 0
            issue_count = len(issues) if isinstance(issues, (list, tuple)) else 0
            compact_entry: dict[str, Any] = {
                "repository": entry["repository"],
                "status": entry.get("status", "invalid"),
                "target_count": target_count,
                "targets": bounded_values(entry, "targets", value_limit),
                "intent_count": intent_count,
                "intents": bounded_values(entry, "intents", value_limit),
                "evidence_policy_count": policy_count,
                "evidence_policies": bounded_values(
                    entry, "evidence_policies", value_limit
                ),
                "issue_count": issue_count,
                "issues": list(issues[:issue_limit])
                if isinstance(issues, (list, tuple))
                else [],
                "truncated": {
                    "targets": target_count > value_limit,
                    "intents": intent_count > value_limit,
                    "evidence_policies": policy_count > value_limit,
                    "issues": issue_count > issue_limit,
                },
            }
            for key in (
                "repository_id",
                "manifest_schema",
                "manifest_fingerprint",
            ):
                if key in entry:
                    compact_entry[key] = entry[key]
            visible.append(compact_entry)
        candidate: dict[str, Any] = {
            "schema_version": document.get("schema_version", 1),
            "ok": document.get("ok") is True,
            "status": document.get("status", "not_ready"),
            "repository_count": document.get(
                "repository_count", len(sanitized_entries)
            ),
            "repositories": visible,
            "counts": document.get(
                "counts", {"ready": 0, "missing": 0, "invalid": 0}
            ),
            "truncated": {
                "repositories": len(sanitized_entries) > len(visible)
            },
        }
        if "broker_profile_error" in sanitized:
            candidate["broker_profile_error"] = _BROKER_PROFILE_ERROR
        if _encoded_size(candidate) <= MAX_AGENT_ENVELOPE_BYTES:
            return candidate
    raise UniversalTestCliError(
        "test catalog exceeds the 8 KiB default agent output contract"
    )


def test_catalog(root: Path | None, broker_profile: object | None) -> dict[str, Any]:
    if broker_profile is not None:
        if root is not None:
            try:
                repositories = [broker_profile.repository(str(root.resolve()))]  # type: ignore[attr-defined]
            except Exception as error:
                raise UniversalTestCliError(
                    "root repository is not uniquely enrolled for test setup"
                ) from error
        else:
            repositories = [
                repository
                for repository in getattr(broker_profile, "repositories", {}).values()
                if getattr(repository, "enabled", False)
            ]
        entries = [
            _broker_catalog_entry(repository, broker_profile)
            for repository in repositories
        ]
    elif root is not None:
        entries = [_catalog_entry(root.resolve())]
    else:
        raise UniversalTestCliError(
            "test catalog requires --root-repo when no broker profile is configured"
        )
    entries.sort(key=lambda item: str(item["repository"]))
    counts = {"ready": 0, "missing": 0, "invalid": 0}
    for entry in entries:
        counts[str(entry["status"])] += 1
    ready = counts["missing"] == 0 and counts["invalid"] == 0
    return _bounded_catalog_envelope(
        {
            "schema_version": 1,
            "ok": ready,
            "status": "ready" if ready else "not_ready",
            "repositories": entries,
            "counts": counts,
        }
    )


def _optional_broker_profile(
    loader: Callable[[], object | None],
) -> tuple[object | None, str | None]:
    """Keep local advisory work available when broker publication is invalid.

    The error remains explicit in the response and queue/evidence work remains
    unavailable.  This does not downgrade or bypass broker authorization.
    """

    try:
        return loader(), None
    except Exception:
        return None, _BROKER_PROFILE_ERROR


def _scheduler_result_or_pending(
    *,
    broker_profile: object | None,
    broker_profile_error: str | None,
    method_name: str,
    action: str,
    arguments: Mapping[str, object],
) -> dict[str, Any]:
    result = _call_scheduler(
        broker_profile, method_name, action=action, **dict(arguments)
    )
    if result is not None:
        if action in {"summary", "wait"}:
            encoded = json.dumps(
                result, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            if len(encoded) > 8192:
                raise UniversalTestCliError(
                    "broker summary exceeds the 8 KiB agent output contract"
                )
        return result
    pending = scheduler_pending(action, **dict(arguments))
    if broker_profile_error is not None:
        pending["broker_profile_error"] = _BROKER_PROFILE_ERROR
    return pending


def handle_universal_test_cli(
    args: argparse.Namespace,
    *,
    canonical_project: Callable[[str], str],
    broker_profile_loader: Callable[[], object | None],
    statistics_reader: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Execute one test CLI action without bypassing broker-owned state."""

    action = args.action
    if action == "manifest":
        root = Path(canonical_project(args.root_repo))
        if args.manifest_action == "init":
            return initialize_manifest(root, force=bool(args.force))
        doctor = args.manifest_action == "doctor"
        health = manifest_health(root, doctor=doctor)
        if not doctor:
            return health
        broker_profile, broker_profile_error = _optional_broker_profile(
            broker_profile_loader
        )
        result = _doctor_capability_policy(health, root, broker_profile)
        if broker_profile_error is not None:
            result["broker_profile_error"] = _BROKER_PROFILE_ERROR
        return _bounded_doctor_envelope(result)
    if action == "plan":
        root = Path(canonical_project(args.root_repo))
        temporary = (
            Path(canonical_project(args.temporary_repo))
            if args.temporary_repo is not None
            else None
        )
        broker_profile, broker_profile_error = _optional_broker_profile(
            broker_profile_loader
        )
        result = build_local_plan(
            root=root,
            temporary=temporary,
            agent=args.agent,
            intent=args.intent,
            raw_changes=args.change,
            requested_targets=args.target,
            execution_timeout_seconds=args.execution_timeout_seconds,
            launch_timeout_seconds=args.launch_timeout_seconds,
            broker_profile=broker_profile,
            operation_id=args.operation_id,
            compact=not args.full,
        )
        if broker_profile_error is not None:
            result["broker_profile_error"] = _BROKER_PROFILE_ERROR
        if not args.full:
            result = _require_agent_envelope(result, surface="test plan")
        return result
    if action == "catalog":
        root = Path(canonical_project(args.root_repo)) if args.root_repo else None
        broker_profile, broker_profile_error = _optional_broker_profile(
            broker_profile_loader
        )
        if root is None and broker_profile_error is not None:
            raise UniversalTestCliError(
                "test catalog cannot enumerate repositories because the broker "
                f"profile is invalid: {broker_profile_error}"
            )
        result = test_catalog(root, broker_profile)
        if broker_profile_error is not None:
            result["broker_profile_error"] = _BROKER_PROFILE_ERROR
        return _bounded_catalog_envelope(result)
    if action == "stats":
        if not 1 <= args.days <= 3650 or not 1 <= args.limit <= 500:
            raise UniversalTestCliError("test stats require days 1-3650 and limit 1-500")
        return statistics_reader(
            project=canonical_project(args.project), days=args.days, limit=args.limit
        )
    if action == "policy":
        root = Path(canonical_project(args.root_repo))
        manifest = load_test_manifest(root)
        if args.policy not in manifest.evidence_policies:
            raise UniversalTestCliError(f"unknown evidence policy: {args.policy}")
        policy = manifest.evidence_policies[args.policy]
        if policy.allow_reuse and args.operation_id is not None:
            raise UniversalTestCliError(
                "reusable evidence checks do not accept an operation ID"
            )
        if not policy.allow_reuse and args.operation_id is None:
            raise UniversalTestCliError(
                "non-reusable evidence requires --operation-id for exact consumption"
            )
        broker_profile, broker_profile_error = _optional_broker_profile(
            broker_profile_loader
        )
        return _scheduler_result_or_pending(
            broker_profile=broker_profile,
            broker_profile_error=broker_profile_error,
            method_name=(
                "check_test_evidence"
                if policy.allow_reuse
                else "consume_test_evidence"
            ),
            action=("policy.check" if policy.allow_reuse else "policy.consume"),
            arguments={
                "repository": str(root),
                "policy": args.policy,
                "snapshot": args.snapshot,
                **(
                    {}
                    if policy.allow_reuse
                    else {"operation_id": args.operation_id}
                ),
            },
        )
    context = {
        key: value
        for key, value in vars(args).items()
        if key
        in {
            "repository",
            "plan_id",
            "run_id",
            "artifact_id",
            "after",
            "limit",
            "reason",
            "operation_id",
            "failed_only",
            "timeout_seconds",
        }
        and value is not None
    }
    if action in {"submit", "cancel", "retry"}:
        try:
            context["actor"] = calling_codex_test_actor()
        except TestActorContractError as error:
            raise UniversalTestCliError(
                "test mutation requires one canonical codex actor"
            ) from error
    scheduler_methods = {
        "submit": "submit_test_plan",
        "status": "test_run_status",
        "summary": "test_run_summary",
        "failures": "test_run_failures",
        "artifact": "test_artifact",
        "cancel": "cancel_test_run",
        "retry": "retry_test_run",
        "wait": "wait_test_run",
    }
    broker_profile, broker_profile_error = _optional_broker_profile(
        broker_profile_loader
    )
    return _scheduler_result_or_pending(
        broker_profile=broker_profile,
        broker_profile_error=broker_profile_error,
        method_name=scheduler_methods[action],
        action=action,
        arguments=context,
    )


__all__ = [
    "UniversalTestCliError",
    "add_universal_test_cli_parser",
    "build_local_plan",
    "discover_changes",
    "handle_universal_test_cli",
    "initialize_manifest",
    "manifest_health",
    "scheduler_pending",
    "test_catalog",
]
