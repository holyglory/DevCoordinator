"""Privacy-safe per-account delivery-efficiency snapshot publication."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping


SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 64 * 1024
ROOT_ENV = "DEVCOORDINATOR_EFFICIENCY_ROOT"
DEFAULT_ROOT = Path("/var/lib/devcoordinator-efficiency/accounts")
REPOSITORY_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
OPAQUE_ID = re.compile(r"^id_[0-9a-f]{32}$")
TOKEN_KEYS = (
    "input",
    "cached_input",
    "output",
    "reasoning_output",
    "tool",
    "other",
)
PHASES = (
    "planning",
    "implementation",
    "testing",
    "deployment",
    "reporting",
    "unattributed",
)
TOOL_CATEGORIES = ("shell", "patch", "mcp", "web", "agent", "local", "other")


class EfficiencyRegistryError(RuntimeError):
    """A projection could not be validated or safely published."""


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise EfficiencyRegistryError(f"{label} has invalid fields")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000_000:
        raise EfficiencyRegistryError(f"{label} is invalid")
    return value


def _decimal(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,29}", value):
        raise EfficiencyRegistryError(f"{label} is invalid")
    return value


def _known_counter(value: Any, label: str) -> dict[str, Any]:
    item = _exact(
        value,
        {"known_sum", "known_task_count", "task_count", "coverage"},
        label,
    )
    result = {
        "known_sum": _decimal(item["known_sum"], f"{label}.known_sum"),
        "known_task_count": _count(
            item["known_task_count"], f"{label}.known_task_count"
        ),
        "task_count": _count(item["task_count"], f"{label}.task_count"),
        "coverage": item["coverage"],
    }
    if result["coverage"] not in {"complete", "partial", "unknown"}:
        raise EfficiencyRegistryError(f"{label}.coverage is invalid")
    if result["known_task_count"] > result["task_count"]:
        raise EfficiencyRegistryError(f"{label} coverage counts conflict")
    if (result["known_sum"] is None) != (result["known_task_count"] == 0):
        raise EfficiencyRegistryError(f"{label} known sum conflicts with coverage")
    return result


def _count_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or len(value) > 32:
        raise EfficiencyRegistryError(f"{label} is invalid")
    result: dict[str, int] = {}
    for key, count in sorted(value.items()):
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", key):
            raise EfficiencyRegistryError(f"{label} key is invalid")
        result[key] = _count(count, f"{label}.{key}")
    return result


def validate_repository_summary(value: Any) -> dict[str, Any]:
    item = _exact(
        value,
        {
            "project_id",
            "task_count",
            "complete_task_count",
            "outcomes",
            "causes",
            "tokens",
            "tokens_by_phase",
            "request_to_delivery_ns",
            "execution_to_delivery_ns",
            "automation_opportunities",
        },
        "repository summary",
    )
    project_id = item["project_id"]
    if not isinstance(project_id, str) or OPAQUE_ID.fullmatch(project_id) is None:
        raise EfficiencyRegistryError("source repository identity is invalid")
    task_count = _count(item["task_count"], "task_count")
    complete_count = _count(item["complete_task_count"], "complete_task_count")
    if complete_count > task_count:
        raise EfficiencyRegistryError("complete task count exceeds task count")

    tokens = _exact(item["tokens"], set(TOKEN_KEYS), "tokens")
    normalized_tokens = {
        key: _known_counter(tokens[key], f"tokens.{key}") for key in TOKEN_KEYS
    }
    phase_value = _exact(item["tokens_by_phase"], set(PHASES), "tokens_by_phase")
    phases: dict[str, Any] = {}
    for phase in PHASES:
        phase_item = _exact(
            phase_value[phase], set(TOKEN_KEYS) | {"usage_event_count"}, phase
        )
        phases[phase] = {
            key: _known_counter(phase_item[key], f"{phase}.{key}")
            for key in TOKEN_KEYS
        }
        phases[phase]["usage_event_count"] = _count(
            phase_item["usage_event_count"], f"{phase}.usage_event_count"
        )

    raw_opportunities = item["automation_opportunities"]
    if not isinstance(raw_opportunities, list) or len(raw_opportunities) > 32:
        raise EfficiencyRegistryError("automation opportunities are invalid")
    opportunities = []
    for raw in raw_opportunities:
        opportunity = _exact(
            raw,
            {
                "kind",
                "task_type",
                "scope_size",
                "current_method",
                "occurrence_count",
                "input_tokens",
                "tool_category_counts",
                "basis",
                "recommendation",
            },
            "automation opportunity",
        )
        if opportunity["kind"] != "deterministic-workflow-candidate":
            raise EfficiencyRegistryError("automation opportunity kind is invalid")
        for field in ("task_type", "scope_size", "current_method"):
            if not isinstance(opportunity[field], str) or not re.fullmatch(
                r"[a-z][a-z-]{0,31}", opportunity[field]
            ):
                raise EfficiencyRegistryError(f"automation {field} is invalid")
        if opportunity["basis"] != (
            "at least three comparable non-automated terminal declarations"
        ) or opportunity["recommendation"] != (
            "review the repeated sequence for a script, harness, verifier, or reusable tool boundary"
        ):
            raise EfficiencyRegistryError("automation explanation is invalid")
        tool_counts = _exact(
            opportunity["tool_category_counts"],
            set(TOOL_CATEGORIES),
            "automation tool categories",
        )
        opportunities.append(
            {
                "kind": opportunity["kind"],
                "task_type": opportunity["task_type"],
                "scope_size": opportunity["scope_size"],
                "current_method": opportunity["current_method"],
                "occurrence_count": _count(
                    opportunity["occurrence_count"], "automation occurrence_count"
                ),
                "input_tokens": _known_counter(
                    opportunity["input_tokens"], "automation input_tokens"
                ),
                "tool_category_counts": {
                    key: _count(tool_counts[key], f"automation.{key}")
                    for key in TOOL_CATEGORIES
                },
                "basis": opportunity["basis"],
                "recommendation": opportunity["recommendation"],
            }
        )
    return {
        "project_id": project_id,
        "task_count": task_count,
        "complete_task_count": complete_count,
        "outcomes": _count_map(item["outcomes"], "outcomes"),
        "causes": _count_map(item["causes"], "causes"),
        "tokens": normalized_tokens,
        "tokens_by_phase": phases,
        "request_to_delivery_ns": _known_counter(
            item["request_to_delivery_ns"], "request_to_delivery_ns"
        ),
        "execution_to_delivery_ns": _known_counter(
            item["execution_to_delivery_ns"], "execution_to_delivery_ns"
        ),
        "automation_opportunities": opportunities,
    }


def parse_submission(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_INPUT_BYTES:
        raise EfficiencyRegistryError("efficiency submission is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EfficiencyRegistryError("efficiency submission is invalid JSON") from error
    document = _exact(value, {"schema_version", "summary"}, "submission")
    if document["schema_version"] != SCHEMA_VERSION:
        raise EfficiencyRegistryError("efficiency submission schema is unsupported")
    return validate_repository_summary(document["summary"])


def _root(explicit: Path | None = None) -> Path:
    candidate = explicit or Path(os.environ.get(ROOT_ENV, str(DEFAULT_ROOT)))
    if not candidate.is_absolute():
        raise EfficiencyRegistryError("efficiency root must be absolute")
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise EfficiencyRegistryError("efficiency projection is not installed") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EfficiencyRegistryError("efficiency root is unsafe")
    return candidate


def publish(
    *, repository_id: str, summary: Mapping[str, Any], root: Path | None = None
) -> dict[str, Any]:
    if not isinstance(repository_id, str) or REPOSITORY_ID.fullmatch(repository_id) is None:
        raise EfficiencyRegistryError("Coordinator repository identity is invalid")
    normalized = validate_repository_summary(summary)
    uid = os.geteuid()
    account_id = f"uid-{uid}"
    account_root = _root(root) / account_id
    repositories = account_root / "repositories"
    for directory in (account_root, repositories):
        try:
            directory.mkdir(mode=0o755)
        except FileExistsError:
            pass
        metadata = directory.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
        ):
            raise EfficiencyRegistryError("account projection directory is unsafe")
    destination = repositories / f"{repository_id.lower()}.json"
    try:
        existing = destination.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != uid
    ):
        raise EfficiencyRegistryError("repository projection target is unsafe")
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "account_id": account_id,
        "repository_id": repository_id.lower(),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "summary": normalized,
    }
    encoded = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_INPUT_BYTES:
        raise EfficiencyRegistryError("efficiency projection is oversized")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".efficiency-", dir=repositories)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        directory_fd = os.open(repositories, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": True,
        "status": "published",
        "repository_id": repository_id.lower(),
        "account_id": account_id,
    }


__all__ = [
    "DEFAULT_ROOT",
    "EfficiencyRegistryError",
    "MAX_INPUT_BYTES",
    "ROOT_ENV",
    "parse_submission",
    "publish",
    "validate_repository_summary",
]
