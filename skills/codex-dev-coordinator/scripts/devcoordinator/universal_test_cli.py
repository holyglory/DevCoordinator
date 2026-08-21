"""Thin advanced CLI mappings for the universal asynchronous test harness.

Manifest setup remains repository-local. Planning, execution, and evidence
operations are delegated to the protected broker and testd without a second
client-owned scheduler, planner, or result-shaping authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Callable, Mapping
import uuid

from .test_actor import TestActorContractError, calling_codex_test_actor
from .universal_test_contract import (
    MANIFEST_RELATIVE_PATH,
    MANIFEST_SCHEMA_VERSION,
    ManifestContractError,
    TestManifest,
    load_test_manifest,
    parse_test_manifest,
)
from .universal_test_planner import DEFAULT_LAUNCH_TIMEOUT_SECONDS


MAX_AGENT_ENVELOPE_BYTES = 8 * 1024
_BROKER_PROFILE_ERROR = "protected broker profile is unavailable or invalid"
_OPAQUE_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:@-"
)


class UniversalTestCliError(ValueError):
    """One local CLI request cannot be represented safely."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "test_request_invalid",
        classification: str = "invalid_request",
        action_required: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.classification = classification
        self.action_required = action_required


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


def _case_cursor(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("case cursor must be an integer") from error
    if value < 0:
        raise argparse.ArgumentTypeError("case cursor must be non-negative")
    return value


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
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--repository-id",
        dest="repository",
        type=_opaque_id,
        help="immutable repository identity when a current local route is present",
    )
    source.add_argument(
        "--root-repo",
        help="canonical repository root to resolve through current authority state",
    )


def _add_submit_repository(parser: argparse.ArgumentParser) -> None:
    _add_run_repository(parser)


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
            "validate the contract and host-wide execution prerequisites",
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
            "declare the exact current Git changes; repeat modified:path, added:path, deleted:path, "
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
    _add_submit_repository(submit)
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
    failures.set_defaults(compact_json=True)

    cases = actions.add_parser(
        "cases", help="read one cursor-bounded page of retained case results"
    )
    _add_run_repository(cases)
    cases.add_argument("--run-id", required=True, type=_opaque_id)
    cases.add_argument("--after", type=_case_cursor, default=0)
    cases.add_argument("--limit", type=_page_limit, default=25)
    cases.set_defaults(compact_json=True)

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
        if "broker_profile_error" in sanitized:
            candidate["broker_profile_error"] = _BROKER_PROFILE_ERROR
        if _encoded_size(candidate) <= MAX_AGENT_ENVELOPE_BYTES:
            return candidate
    raise UniversalTestCliError(
        "manifest doctor exceeds the 8 KiB default agent output contract"
    )


def _resolved_broker_repository(root: Path, broker_profile: object) -> object:
    """Resolve one already-adopted repository without mutating first-use state."""

    resolver = getattr(broker_profile, "resolve_repository", None)
    if callable(resolver):
        repository = resolver(str(root))
    else:
        repository = broker_profile.repository(str(root))  # type: ignore[attr-defined]
    if repository is None:
        raise LookupError(str(root))
    return repository


def _required_broker_profile(loader: Callable[[], object | None]) -> object:
    try:
        profile = loader()
    except Exception as error:
        raise UniversalTestCliError(_BROKER_PROFILE_ERROR) from error
    if profile is None:
        raise UniversalTestCliError(_BROKER_PROFILE_ERROR)
    return profile


def _broker_result(
    broker_profile: object,
    method_name: str,
    *,
    action: str,
    arguments: Mapping[str, object],
) -> dict[str, Any]:
    """Call one broker/testd operation without client-owned result semantics."""

    method = getattr(broker_profile, method_name, None)
    if not callable(method):
        raise UniversalTestCliError(
            f"protected broker profile does not expose test {action}"
        )
    result = method(**dict(arguments))
    if not isinstance(result, Mapping):
        raise UniversalTestCliError(
            f"protected broker returned an invalid test {action} reply"
        )
    return dict(result)


def test_catalog(root: Path | None, broker_profile: object) -> dict[str, Any]:
    """Read the broker-owned catalog or one protected repository setup row."""

    if root is None:
        return _broker_result(
            broker_profile,
            "test_repository_catalog",
            action="catalog",
            arguments={},
        )
    try:
        repository = _resolved_broker_repository(root.resolve(), broker_profile)
    except Exception as error:
        raise UniversalTestCliError(
            "root repository is not currently configured for test catalog"
        ) from error
    return _broker_result(
        broker_profile,
        "test_repository_setup",
        action="catalog",
        arguments={"repository": str(repository.repo_id)},
    )


def handle_universal_test_cli(
    args: argparse.Namespace,
    *,
    canonical_project: Callable[[str], str],
    broker_profile_loader: Callable[[], object | None],
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
        return _bounded_doctor_envelope(health)
    if action == "plan":
        root = Path(canonical_project(args.root_repo))
        temporary = (
            Path(canonical_project(args.temporary_repo))
            if args.temporary_repo is not None
            else None
        )
        if args.change:
            raise UniversalTestCliError(
                "protected planning discovers the complete current change set; "
                "omit --change"
            )
        try:
            broker_profile = _required_broker_profile(broker_profile_loader)
            repository = _resolved_broker_repository(root.resolve(), broker_profile)
            result = _broker_result(
                broker_profile,
                "preview_test_plan",
                action="plan",
                arguments={
                    "repository": str(repository.repo_id),
                    "intent": args.intent,
                    "temporary_root": (
                        None if temporary is None else str(temporary.resolve())
                    ),
                    "requested_targets": tuple(args.target),
                    "execution_timeout_seconds": args.execution_timeout_seconds,
                    "launch_timeout_seconds": args.launch_timeout_seconds,
                    "operation_id": args.operation_id,
                },
            )
        except UniversalTestCliError:
            raise
        except Exception as error:
            raise UniversalTestCliError(
                "protected test planning is unavailable"
            ) from error
        if not isinstance(result, Mapping):
            raise UniversalTestCliError("protected test planning reply is invalid")
        if not args.full:
            result = _require_agent_envelope(result, surface="test plan")
        return dict(result)
    if action == "catalog":
        root = Path(canonical_project(args.root_repo)) if args.root_repo else None
        return test_catalog(root, _required_broker_profile(broker_profile_loader))
    if action == "stats":
        if not 1 <= args.days <= 3650 or not 1 <= args.limit <= 500:
            raise UniversalTestCliError("test stats require days 1-3650 and limit 1-500")
        broker_profile = _required_broker_profile(broker_profile_loader)
        root = Path(canonical_project(args.project)).resolve()
        try:
            repository = _resolved_broker_repository(root, broker_profile)
        except Exception as error:
            raise UniversalTestCliError(
                "root repository is not currently configured for test stats"
            ) from error
        return _broker_result(
            broker_profile,
            "test_statistics",
            action="stats",
            arguments={
                "repository": str(repository.repo_id),
                "days": args.days,
                "limit": args.limit,
            },
        )
    if action == "policy":
        broker_profile = _required_broker_profile(broker_profile_loader)
        root = Path(canonical_project(args.root_repo)).resolve()
        try:
            repository = _resolved_broker_repository(root, broker_profile)
        except Exception as error:
            raise UniversalTestCliError(
                "root repository is not currently configured for test policy"
            ) from error
        consume = args.operation_id is not None
        return _broker_result(
            broker_profile,
            (
                "check_test_evidence"
                if not consume
                else "consume_test_evidence"
            ),
            action=("policy.check" if not consume else "policy.consume"),
            arguments={
                "repository": str(repository.repo_id),
                "policy": args.policy,
                "snapshot": args.snapshot,
                **(
                    {}
                    if not consume
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
        "cases": "test_run_cases",
        "artifact": "test_artifact",
        "cancel": "cancel_test_run",
        "retry": "retry_test_run",
        "wait": "wait_test_run",
    }
    broker_profile = _required_broker_profile(broker_profile_loader)
    if getattr(args, "root_repo", None) is not None:
        root = Path(canonical_project(args.root_repo)).resolve()
        try:
            repository = _resolved_broker_repository(root, broker_profile)
        except Exception as error:
            raise UniversalTestCliError(
                f"root repository is not currently configured for test {action}"
            ) from error
        context["repository"] = str(repository.repo_id)
    return _broker_result(
        broker_profile,
        scheduler_methods[action],
        action=action,
        arguments=context,
    )


__all__ = [
    "UniversalTestCliError",
    "add_universal_test_cli_parser",
    "handle_universal_test_cli",
    "initialize_manifest",
    "manifest_health",
    "test_catalog",
]
