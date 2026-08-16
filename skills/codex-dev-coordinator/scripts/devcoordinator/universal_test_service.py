"""Narrow broker-to-testd boundary for the asynchronous test plane.

Broker and agent clients depend on :class:`TestPlaneClient`; they never open
the test database.  :class:`StoreTestPlaneAdapter` is the in-process endpoint
used by testd and focused tests.  A protected Unix transport can implement the
same protocol without changing broker call sites.
"""

from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from threading import RLock
from types import MappingProxyType
from typing import Mapping, Protocol, Sequence, runtime_checkable

from .universal_test_contract import (
    EvidencePolicy,
    SourceMode,
    deterministic_fingerprint,
    evidence_policy_fingerprint,
    normalize_repository_path,
)
from .universal_test_planner import (
    ChangeStatus,
    ChangedPath,
    DEFAULT_LAUNCH_TIMEOUT_SECONDS,
    MAX_EXECUTION_TIMEOUT_SECONDS,
    MAX_LAUNCH_TIMEOUT_SECONDS,
    MAX_SELECTION_REASONS,
    SourceIdentity,
    TargetSelection,
    TestPlan,
    TestPlanError,
    TestPlanTimeouts,
)
from .universal_test_store import (
    TargetResources,
    TestStoreConflict,
    TestStoreContractError,
    UniversalTestStore,
)
from .universal_test_summary import (
    AgentRunSummary,
    ArtifactSummary,
    FailureSummary,
    MAX_AGENT_SUMMARY_BYTES,
    compact_agent_summary,
)


MAX_TEST_PLANE_RESPONSE_BYTES = 256 * 1024
MAX_TEST_PLANE_PAGE_SIZE = 50
MAX_TEST_PLANE_STATS_PAGE_SIZE = 500
MAX_TEST_ARTIFACT_TEXT_TAIL_BYTES = 4 * 1024
_TEXT_ARTIFACT_KINDS = frozenset({"jsonl", "junit", "log", "trx"})
_SAFE_REPOSITORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_TEST_INTENTS = frozenset({"change", "checkpoint", "handoff", "release", "manual"})


def verified_text_artifact_content(
    artifact: Mapping[str, object],
    *,
    artifact_root: Path = Path("/var/lib/devcoordinator-test-artifacts"),
) -> Mapping[str, object] | None:
    """Read one root-private textual blob with exact immutable verification."""

    if str(artifact.get("kind") or "") not in _TEXT_ARTIFACT_KINDS:
        return None
    artifact_id = artifact.get("artifact_id")
    digest = artifact.get("sha256")
    size_bytes = artifact.get("size_bytes")
    if (
        not isinstance(artifact_id, str)
        or re.fullmatch(r"artifact-[0-9a-f]{32}", artifact_id) is None
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or type(size_bytes) is not int
        or not 0 <= size_bytes <= 32 * 1024 * 1024
        or artifact.get("verified") not in {1, True}
    ):
        raise TestStoreContractError(
            "test artifact metadata cannot authorize content retrieval"
        )
    root = Path(artifact_root).absolute()
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise TestStoreConflict("test artifact store is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise TestStoreConflict("test artifact store is unsafe")
    path = root / f"{artifact_id}-{digest}.blob"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TestStoreConflict("test artifact content is unavailable") from error
    observed = hashlib.sha256()
    tail = bytearray()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size_bytes:
            raise TestStoreConflict("test artifact content identity is invalid")
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            observed.update(chunk)
            tail.extend(chunk)
            if len(tail) > MAX_TEST_ARTIFACT_TEXT_TAIL_BYTES:
                del tail[:-MAX_TEST_ARTIFACT_TEXT_TAIL_BYTES]
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = path.lstat()
    except OSError as error:
        raise TestStoreConflict("test artifact content changed during read") from error
    identity = (before.st_dev, before.st_ino, before.st_size)
    if (
        identity != (after.st_dev, after.st_ino, after.st_size)
        or identity != (path_after.st_dev, path_after.st_ino, path_after.st_size)
        or total != size_bytes
        or observed.hexdigest() != digest
    ):
        raise TestStoreConflict("test artifact content failed integrity verification")
    retained = bytes(tail)
    return {
        "artifact_id": artifact_id,
        "sha256": digest,
        "encoding": "utf-8",
        "text": retained.decode("utf-8", errors="replace"),
        "size_bytes": size_bytes,
        "retained_bytes": len(retained),
        "truncated": len(retained) < size_bytes,
    }

_PLAN_FIELDS = frozenset(
    {
        "plan_id",
        "fingerprint",
        "execution_fingerprint",
        "manifest_fingerprint",
        "repository_id",
        "intent",
        "timeouts",
        "source",
        "changes",
        "eligible_targets",
        "selected_targets",
        "dependency_waves",
        "dependencies",
        "selection",
        "complete_intent_fallback",
        "reusable",
        "evidence_policies",
    }
)
_PLAN_TIMEOUT_FIELDS = frozenset({"execution_seconds", "launch_seconds"})
_SOURCE_FIELDS = frozenset(
    {
        "mode",
        "repository_id",
        "content_fingerprint",
        "original_root",
        "temporary_root",
        "snapshot_id",
    }
)
_CHANGE_FIELDS = frozenset({"path", "status", "previous_path"})
_PLAN_POLICY_FIELDS = frozenset(
    {
        "intent",
        "required_targets",
        "max_age_seconds",
        "allow_reuse",
        "fingerprint",
    }
)
_SETUP_FIELDS = frozenset(
    {
        "schema_version",
        "repository_id",
        "ok",
        "status",
        "manifest_schema",
        "manifest_fingerprint",
        "targets",
        "target_graph",
        "input_coverage",
        "input_coverage_gaps",
        "intents",
        "evidence_policies",
        "fixtures",
        "credentials",
        "network_requirements",
        "isolation",
        "issues",
    }
)
_SETUP_TARGET_FIELDS = frozenset(
    {
        "name",
        "driver",
        "reporter",
        "network",
        "fixtures",
        "credentials",
        "depends_on",
        "resources",
    }
)
_SETUP_RESOURCE_FIELDS = frozenset({"cpu_millis", "memory_mib", "pids"})
_SETUP_INPUT_FIELDS = frozenset(
    {"global_input_count", "target_input_count", "targets_with_inputs"}
)
_SETUP_INPUT_GAP_FIELDS = frozenset({"code", "message", "detail", "path"})
_SETUP_ISOLATION_FIELDS = frozenset(
    {
        "network",
        "cpu_millis",
        "memory_mib",
        "pids",
        "private_scratch",
        "kill_after_run",
    }
)
_SETUP_ISSUE_FIELDS = frozenset({"code", "message"})
_SETUP_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SETUP_BINDING = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SETUP_NETWORKS = {
    "none": 0,
    "loopback": 1,
    "host-loopback": 2,
    "external": 3,
}
_SETUP_ISSUES = {
    "manifest_missing": "repository test manifest is missing",
    "manifest_invalid": "repository test manifest is invalid",
    "manifest_setup_too_large": "repository test manifest is invalid",
}
_SETUP_INPUT_PATH_GAP_LIMIT = 128
_SETUP_INPUT_GAP_MESSAGES = {
    "unmapped_repository_path": (
        "repository path is not mapped by global inputs or target inputs",
        "changes to this path select the complete required intent",
    ),
    "unmapped_repository_paths_omitted": (
        "additional repository paths are not mapped by global inputs or target inputs",
        "the bounded Setup projection omits additional unmapped paths",
    ),
    "input_coverage_inspection_incomplete": (
        "repository input coverage could not be fully inspected",
        "unmapped paths may exist; uncertain changes still select the complete required intent",
    ),
}


def _mapping(field: str, value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TestStoreContractError(f"{field} must be an object")
    return value


class TestPlanPreviewUnavailable(TestStoreConflict):
    """No repository-UID planning helper is connected to this testd."""

    code = "test_plan_preview_unavailable"


class TestRepositorySetupUnavailable(TestPlanPreviewUnavailable):
    """No repository-UID manifest reader is connected to this testd."""

    code = "test_repository_setup_unavailable"


@runtime_checkable
class RepositoryUIDPlanPreviewer(Protocol):
    """Privileged boundary implemented by the repository-UID helper.

    The helper, not broker/testd root code, reads the repository manifest and
    creates the live or immutable source selected by that manifest's intent.
    """

    def preview_as_owner(
        self,
        *,
        repository_id: str,
        intent: str,
        actor: str,
        owner_uid: int,
        access_uid: int | None = None,
        temporary_root: str | None = None,
        requested_targets: Sequence[str] = (),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS,
        launch_deadline_monotonic: float | None = None,
    ) -> Mapping[str, object]: ...

    def setup_as_owner(
        self,
        *,
        repository_id: str,
        owner_uid: int,
    ) -> Mapping[str, object]: ...


def _exact_fields(
    field: str, value: Mapping[str, object], expected: frozenset[str]
) -> None:
    if set(value) != expected:
        raise TestStoreContractError(f"{field} fields are invalid")


def _text(field: str, value: object, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestStoreContractError(f"{field} must be bounded single-line text")
    return value


def _text_sequence(
    field: str, value: object, *, maximum_items: int = 512
) -> tuple[str, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) > maximum_items
    ):
        raise TestStoreContractError(f"{field} must be a bounded array")
    return tuple(_text(f"{field}[]", item, maximum=1024) for item in value)


def _setup_name(field: str, value: object) -> str:
    name = _text(field, value, maximum=64)
    if _SETUP_NAME.fullmatch(name) is None:
        raise TestStoreContractError(f"{field} must be a safe manifest name")
    return name


def _setup_names(field: str, value: object, *, maximum_items: int) -> tuple[str, ...]:
    names = tuple(
        _setup_name(f"{field}[]", item)
        for item in _text_sequence(field, value, maximum_items=maximum_items)
    )
    if tuple(sorted(set(names))) != names:
        raise TestStoreContractError(f"{field} must be unique and sorted")
    return names


def _setup_bindings(
    field: str, value: object, *, maximum_items: int
) -> tuple[str, ...]:
    values = _text_sequence(field, value, maximum_items=maximum_items)
    if (
        any(_SETUP_BINDING.fullmatch(item) is None for item in values)
        or tuple(sorted(set(values))) != values
    ):
        raise TestStoreContractError(
            f"{field} must contain unique sorted credential bindings"
        )
    return values


def _setup_integer(field: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TestStoreContractError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )
    return value


def _setup_input_coverage_gaps(value: object) -> list[dict[str, str]]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or len(value) > _SETUP_INPUT_PATH_GAP_LIMIT + 1
    ):
        raise TestStoreContractError(
            "repository setup input coverage gaps must be a bounded array"
        )

    gaps: list[dict[str, str]] = []
    concrete_paths: list[str] = []
    summary_code: str | None = None
    for index, item in enumerate(value):
        gap = _mapping(f"repository setup input_coverage_gaps[{index}]", item)
        code = _text(
            "repository setup input coverage gap code",
            gap.get("code"),
            maximum=64,
        )
        expected_copy = _SETUP_INPUT_GAP_MESSAGES.get(code)
        if expected_copy is None:
            raise TestStoreContractError(
                "repository setup input coverage gap code is invalid"
            )
        expected_fields = (
            _SETUP_INPUT_GAP_FIELDS
            if code == "unmapped_repository_path"
            else _SETUP_INPUT_GAP_FIELDS - {"path"}
        )
        _exact_fields(
            f"repository setup input_coverage_gaps[{index}]",
            gap,
            frozenset(expected_fields),
        )
        message = _text(
            "repository setup input coverage gap message",
            gap["message"],
            maximum=128,
        )
        detail = _text(
            "repository setup input coverage gap detail",
            gap["detail"],
            maximum=192,
        )
        if (message, detail) != expected_copy:
            raise TestStoreContractError(
                "repository setup input coverage gap copy is invalid"
            )

        decoded = {"code": code, "message": message, "detail": detail}
        if code == "unmapped_repository_path":
            try:
                path = normalize_repository_path(
                    gap["path"], path="repository setup input coverage gap path"
                )
            except ValueError as error:
                raise TestStoreContractError(
                    "repository setup input coverage gap path is invalid"
                ) from error
            concrete_paths.append(path)
            decoded["path"] = path
        else:
            if summary_code is not None:
                raise TestStoreContractError(
                    "repository setup input coverage gap summary is duplicated"
                )
            summary_code = code
        gaps.append(decoded)

    if concrete_paths != sorted(set(concrete_paths)):
        raise TestStoreContractError(
            "repository setup input coverage gap paths must be unique and sorted"
        )
    if summary_code == "input_coverage_inspection_incomplete" and len(gaps) != 1:
        raise TestStoreContractError(
            "repository setup incomplete input inspection must be the only gap"
        )
    if summary_code == "unmapped_repository_paths_omitted" and (
        len(concrete_paths) != _SETUP_INPUT_PATH_GAP_LIMIT
        or gaps[-1]["code"] != summary_code
    ):
        raise TestStoreContractError(
            "repository setup omitted input paths summary is contradictory"
        )
    if summary_code is None and len(concrete_paths) > _SETUP_INPUT_PATH_GAP_LIMIT:
        raise TestStoreContractError(
            "repository setup input coverage path gaps exceed their bound"
        )
    return gaps


def decode_repository_setup_document(
    value: Mapping[str, object],
    *,
    expected_repository_id: str,
) -> Mapping[str, object]:
    """Revalidate the path- and secret-free repository setup projection."""

    raw = dict(_mapping("repository setup", value))
    # Setup projection schema 1 predates sealed operational credentials.
    # Missing fields normalize to the only safe legacy value: no request.
    raw.setdefault("credentials", [])
    _exact_fields("repository setup", raw, _SETUP_FIELDS)
    try:
        encoded = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise TestStoreContractError("repository setup is not bounded JSON") from error
    if len(encoded) > MAX_TEST_PLANE_RESPONSE_BYTES:
        raise TestStoreContractError("repository setup exceeds its byte bound")

    repository_id = raw["repository_id"]
    if (
        not isinstance(repository_id, str)
        or _SAFE_REPOSITORY_ID.fullmatch(repository_id) is None
        or repository_id != expected_repository_id
    ):
        raise TestStoreContractError("repository setup identity is contradictory")
    if raw["schema_version"] != 1:
        raise TestStoreContractError("repository setup schema is unsupported")
    status = _text("repository setup status", raw["status"], maximum=16)
    if status not in {"ready", "missing", "invalid"}:
        raise TestStoreContractError("repository setup status is invalid")
    if type(raw["ok"]) is not bool or raw["ok"] != (status == "ready"):
        raise TestStoreContractError("repository setup readiness is contradictory")

    targets_raw = raw["targets"]
    if (
        not isinstance(targets_raw, Sequence)
        or isinstance(targets_raw, (str, bytes))
        or len(targets_raw) > 512
    ):
        raise TestStoreContractError("repository setup targets must be bounded")
    targets: list[dict[str, object]] = []
    for index, item in enumerate(targets_raw):
        target = dict(_mapping(f"repository setup targets[{index}]", item))
        target.setdefault("credentials", [])
        _exact_fields(
            f"repository setup targets[{index}]", target, _SETUP_TARGET_FIELDS
        )
        resources = _mapping(
            f"repository setup targets[{index}].resources", target["resources"]
        )
        _exact_fields(
            f"repository setup targets[{index}].resources",
            resources,
            _SETUP_RESOURCE_FIELDS,
        )
        dependencies = _setup_names(
            f"repository setup targets[{index}].depends_on",
            target["depends_on"],
            maximum_items=512,
        )
        target_fixtures = _setup_names(
            f"repository setup targets[{index}].fixtures",
            target["fixtures"],
            maximum_items=64,
        )
        target_credentials = _setup_bindings(
            f"repository setup targets[{index}].credentials",
            target["credentials"],
            maximum_items=16,
        )
        driver = _setup_name(
            f"repository setup targets[{index}].driver", target["driver"]
        )
        if driver not in {"pytest", "node", "dotnet", "automation"}:
            raise TestStoreContractError("repository setup target driver is invalid")
        reporter = _setup_name(
            f"repository setup targets[{index}].reporter", target["reporter"]
        )
        network = _text(
            f"repository setup targets[{index}].network",
            target["network"],
            maximum=16,
        )
        if network not in _SETUP_NETWORKS:
            raise TestStoreContractError("repository setup target network is invalid")
        targets.append(
            {
                "name": _setup_name(
                    f"repository setup targets[{index}].name", target["name"]
                ),
                "driver": driver,
                "reporter": reporter,
                "network": network,
                "fixtures": list(target_fixtures),
                "credentials": list(target_credentials),
                "depends_on": list(dependencies),
                "resources": {
                    "cpu_millis": _setup_integer(
                        "repository setup target cpu_millis",
                        resources["cpu_millis"],
                        minimum=50,
                        maximum=64_000,
                    ),
                    "memory_mib": _setup_integer(
                        "repository setup target memory_mib",
                        resources["memory_mib"],
                        minimum=32,
                        maximum=262_144,
                    ),
                    "pids": _setup_integer(
                        "repository setup target pids",
                        resources["pids"],
                        minimum=8,
                        maximum=32_768,
                    ),
                },
            }
        )
    target_names = tuple(str(target["name"]) for target in targets)
    if tuple(sorted(set(target_names))) != target_names:
        raise TestStoreContractError("repository setup targets must be unique and sorted")
    target_name_set = set(target_names)
    for target in targets:
        if not set(target["depends_on"]).issubset(target_name_set):
            raise TestStoreContractError(
                "repository setup target graph contains an unknown dependency"
            )

    graph_raw = _mapping("repository setup target_graph", raw["target_graph"])
    if set(graph_raw) != target_name_set:
        raise TestStoreContractError("repository setup target graph is incomplete")
    graph: dict[str, list[str]] = {}
    for target in targets:
        name = str(target["name"])
        dependencies = _setup_names(
            f"repository setup target_graph.{name}",
            graph_raw[name],
            maximum_items=512,
        )
        if dependencies != tuple(target["depends_on"]):
            raise TestStoreContractError("repository setup target graph is contradictory")
        graph[name] = list(dependencies)

    coverage_raw = _mapping("repository setup input_coverage", raw["input_coverage"])
    _exact_fields(
        "repository setup input_coverage", coverage_raw, _SETUP_INPUT_FIELDS
    )
    coverage = {
        "global_input_count": _setup_integer(
            "repository setup global_input_count",
            coverage_raw["global_input_count"],
            minimum=0,
            maximum=512,
        ),
        "target_input_count": _setup_integer(
            "repository setup target_input_count",
            coverage_raw["target_input_count"],
            minimum=0,
            maximum=512 * 512,
        ),
        "targets_with_inputs": _setup_integer(
            "repository setup targets_with_inputs",
            coverage_raw["targets_with_inputs"],
            minimum=0,
            maximum=512,
        ),
    }
    gaps = _setup_input_coverage_gaps(raw["input_coverage_gaps"])

    intents = _setup_names("repository setup intents", raw["intents"], maximum_items=5)
    policies = _setup_names(
        "repository setup evidence_policies",
        raw["evidence_policies"],
        maximum_items=64,
    )
    fixtures = _setup_names(
        "repository setup fixtures", raw["fixtures"], maximum_items=64
    )
    credentials = _setup_bindings(
        "repository setup credentials", raw["credentials"], maximum_items=64
    )
    fixture_names = set(fixtures)
    for target in targets:
        if not set(target["fixtures"]).issubset(fixture_names):
            raise TestStoreContractError(
                "repository setup target fixtures are contradictory"
            )
        if not set(target["credentials"]).issubset(set(credentials)):
            raise TestStoreContractError(
                "repository setup target credentials are contradictory"
            )
    network_values = _text_sequence(
        "repository setup network_requirements",
        raw["network_requirements"],
        maximum_items=4,
    )
    if (
        any(network not in _SETUP_NETWORKS for network in network_values)
        or tuple(sorted(set(network_values), key=_SETUP_NETWORKS.__getitem__))
        != network_values
    ):
        raise TestStoreContractError(
            "repository setup network requirements are invalid"
        )

    isolation_raw = _mapping("repository setup isolation", raw["isolation"])
    _exact_fields("repository setup isolation", isolation_raw, _SETUP_ISOLATION_FIELDS)
    isolation_network = _text(
        "repository setup isolation.network", isolation_raw["network"], maximum=16
    )
    if isolation_network not in _SETUP_NETWORKS:
        raise TestStoreContractError("repository setup isolation network is invalid")
    isolation = {
        "network": isolation_network,
        "cpu_millis": _setup_integer(
            "repository setup isolation.cpu_millis",
            isolation_raw["cpu_millis"],
            minimum=0,
            maximum=64_000,
        ),
        "memory_mib": _setup_integer(
            "repository setup isolation.memory_mib",
            isolation_raw["memory_mib"],
            minimum=0,
            maximum=262_144,
        ),
        "pids": _setup_integer(
            "repository setup isolation.pids",
            isolation_raw["pids"],
            minimum=0,
            maximum=32_768,
        ),
        "private_scratch": isolation_raw["private_scratch"],
        "kill_after_run": isolation_raw["kill_after_run"],
    }
    if isolation["private_scratch"] is not True or isolation["kill_after_run"] is not True:
        raise TestStoreContractError("repository setup isolation policy is invalid")

    issues_raw = raw["issues"]
    if (
        not isinstance(issues_raw, Sequence)
        or isinstance(issues_raw, (str, bytes))
        or len(issues_raw) > 1
    ):
        raise TestStoreContractError("repository setup issues must be bounded")
    issues: list[dict[str, str]] = []
    for index, item in enumerate(issues_raw):
        issue = _mapping(f"repository setup issues[{index}]", item)
        _exact_fields(f"repository setup issues[{index}]", issue, _SETUP_ISSUE_FIELDS)
        code = _text("repository setup issue code", issue["code"], maximum=64)
        if code not in _SETUP_ISSUES or issue["message"] != _SETUP_ISSUES[code]:
            raise TestStoreContractError("repository setup issue is not sanitized")
        issues.append({"code": code, "message": _SETUP_ISSUES[code]})

    manifest_schema = raw["manifest_schema"]
    manifest_fingerprint = raw["manifest_fingerprint"]
    if status == "ready":
        if type(manifest_schema) is not int or not 1 <= manifest_schema <= 100:
            raise TestStoreContractError("repository setup manifest schema is invalid")
        if (
            not isinstance(manifest_fingerprint, str)
            or _HEX_SHA256.fullmatch(manifest_fingerprint) is None
        ):
            raise TestStoreContractError(
                "repository setup manifest fingerprint is invalid"
            )
        if not targets or not intents or issues:
            raise TestStoreContractError("ready repository setup is incomplete")
        if (
            coverage["global_input_count"] < 1
            or coverage["target_input_count"] < len(targets)
            or coverage["targets_with_inputs"] != len(targets)
        ):
            raise TestStoreContractError(
                "ready repository setup input coverage is contradictory"
            )
        target_networks = {str(target["network"]) for target in targets}
        if not target_networks.issubset(set(network_values)):
            raise TestStoreContractError(
                "repository setup network requirements are incomplete"
            )
        expected_isolation = {
            "network": max(network_values, key=_SETUP_NETWORKS.__getitem__),
            "cpu_millis": max(
                int(target["resources"]["cpu_millis"]) for target in targets  # type: ignore[index]
            ),
            "memory_mib": max(
                int(target["resources"]["memory_mib"]) for target in targets  # type: ignore[index]
            ),
            "pids": max(
                int(target["resources"]["pids"]) for target in targets  # type: ignore[index]
            ),
            "private_scratch": True,
            "kill_after_run": True,
        }
        if isolation != expected_isolation:
            raise TestStoreContractError(
                "repository setup isolation requirements are contradictory"
            )
    else:
        if manifest_schema is not None or manifest_fingerprint is not None:
            raise TestStoreContractError(
                "unready repository setup contains manifest identity"
            )
        if any(
            (targets, graph, intents, policies, fixtures, credentials, network_values)
        ):
            raise TestStoreContractError(
                "unready repository setup contains manifest details"
            )
        if any(coverage.values()) or isolation != {
            "network": "none",
            "cpu_millis": 0,
            "memory_mib": 0,
            "pids": 0,
            "private_scratch": True,
            "kill_after_run": True,
        }:
            raise TestStoreContractError(
                "unready repository setup contains resource requirements"
            )
        if gaps:
            raise TestStoreContractError(
                "unready repository setup contains input coverage gaps"
            )
        allowed_codes = (
            {"manifest_missing"}
            if status == "missing"
            else {"manifest_invalid", "manifest_setup_too_large"}
        )
        if len(issues) != 1 or issues[0]["code"] not in allowed_codes:
            raise TestStoreContractError("repository setup issue contradicts status")

    return {
        "schema_version": 1,
        "repository_id": repository_id,
        "ok": status == "ready",
        "status": status,
        "manifest_schema": manifest_schema,
        "manifest_fingerprint": manifest_fingerprint,
        "targets": targets,
        "target_graph": graph,
        "input_coverage": coverage,
        "input_coverage_gaps": gaps,
        "intents": list(intents),
        "evidence_policies": list(policies),
        "fixtures": list(fixtures),
        "credentials": list(credentials),
        "network_requirements": list(network_values),
        "isolation": isolation,
        "issues": issues,
    }


def decode_test_plan_document(value: Mapping[str, object]) -> TestPlan:
    """Revalidate the complete deterministic planner wire document."""

    raw = _mapping("plan", value)
    has_dependencies = "dependencies" in raw
    _exact_fields(
        "plan",
        raw,
        _PLAN_FIELDS if has_dependencies else _PLAN_FIELDS - {"dependencies"},
    )
    source_raw = _mapping("plan.source", raw["source"])
    _exact_fields("plan.source", source_raw, _SOURCE_FIELDS)
    try:
        source = SourceIdentity(
            mode=SourceMode(_text("plan.source.mode", source_raw["mode"], maximum=16)),
            repository_id=_text(
                "plan.source.repository_id", source_raw["repository_id"], maximum=256
            ),
            content_fingerprint=_text(
                "plan.source.content_fingerprint",
                source_raw["content_fingerprint"],
                maximum=64,
            ),
            original_root=_text(
                "plan.source.original_root", source_raw["original_root"]
            ),
            temporary_root=(
                None
                if source_raw["temporary_root"] is None
                else _text(
                    "plan.source.temporary_root", source_raw["temporary_root"]
                )
            ),
            snapshot_id=(
                None
                if source_raw["snapshot_id"] is None
                else _text(
                    "plan.source.snapshot_id", source_raw["snapshot_id"], maximum=256
                )
            ),
        )
    except (ValueError, TestPlanError) as error:
        raise TestStoreContractError("plan source identity is invalid") from error

    changes_raw = raw["changes"]
    if (
        not isinstance(changes_raw, Sequence)
        or isinstance(changes_raw, (str, bytes))
        or len(changes_raw) > 10_000
    ):
        raise TestStoreContractError("plan changes must be a bounded array")
    changes: list[ChangedPath] = []
    for index, item in enumerate(changes_raw):
        change = _mapping(f"plan.changes[{index}]", item)
        _exact_fields(f"plan.changes[{index}]", change, _CHANGE_FIELDS)
        try:
            changes.append(
                ChangedPath(
                    path=_text(f"plan.changes[{index}].path", change["path"]),
                    status=ChangeStatus(
                        _text(
                            f"plan.changes[{index}].status",
                            change["status"],
                            maximum=32,
                        )
                    ),
                    previous_path=(
                        None
                        if change["previous_path"] is None
                        else _text(
                            f"plan.changes[{index}].previous_path",
                            change["previous_path"],
                        )
                    ),
                )
            )
        except (ValueError, TestPlanError) as error:
            raise TestStoreContractError("plan change is invalid") from error

    eligible = _text_sequence("plan.eligible_targets", raw["eligible_targets"])
    if tuple(sorted(set(eligible))) != eligible or not eligible:
        raise TestStoreContractError(
            "plan eligible_targets must be non-empty, unique, and sorted"
        )
    selected = _text_sequence("plan.selected_targets", raw["selected_targets"])
    if tuple(sorted(set(selected))) != selected:
        raise TestStoreContractError("plan selected_targets must be unique and sorted")
    if not set(selected) <= set(eligible):
        raise TestStoreContractError("plan selected_targets exceed eligible targets")
    waves_raw = raw["dependency_waves"]
    if (
        not isinstance(waves_raw, Sequence)
        or isinstance(waves_raw, (str, bytes))
        or len(waves_raw) > 512
    ):
        raise TestStoreContractError("plan dependency_waves must be bounded")
    waves = tuple(
        _text_sequence(f"plan.dependency_waves[{index}]", wave)
        for index, wave in enumerate(waves_raw)
    )
    flattened = tuple(target for wave in waves for target in wave)
    if tuple(sorted(flattened)) != selected or len(set(flattened)) != len(flattened):
        raise TestStoreContractError(
            "dependency_waves must cover every selected target exactly once"
        )
    selection_raw = _mapping("plan.selection", raw["selection"])
    if set(selection_raw) != set(selected):
        raise TestStoreContractError("plan selection reasons do not match targets")
    selection = MappingProxyType(
        {
            target: TargetSelection(
                target=target,
                reasons=_text_sequence(
                    f"plan.selection.{target}",
                    selection_raw[target],
                    maximum_items=MAX_SELECTION_REASONS,
                ),
            )
            for target in selected
        }
    )
    if any(not item.reasons for item in selection.values()):
        raise TestStoreContractError("every selected target requires a selection reason")
    if has_dependencies:
        dependencies_raw = _mapping("plan.dependencies", raw["dependencies"])
        if set(dependencies_raw) != set(selected):
            raise TestStoreContractError(
                "plan dependencies must cover every selected target exactly once"
            )
        dependencies = MappingProxyType(
            {
                target: _text_sequence(
                    f"plan.dependencies.{target}",
                    dependencies_raw[target],
                    maximum_items=256,
                )
                for target in selected
            }
        )
    else:
        # Schema-2 retained plans predate the exact dependency field. Their
        # deterministic closure reasons preserve direct prerequisite names.
        dependencies = MappingProxyType(
            {
                target: tuple(
                    sorted(
                        reason.split(":", 1)[1]
                        for reason in selection[target].reasons
                        if reason.startswith("dependent-of:")
                    )
                )
                for target in selected
            }
        )
    wave_by_target = {
        target: index for index, wave in enumerate(waves) for target in wave
    }
    for target, required in dependencies.items():
        if (
            tuple(sorted(set(required))) != required
            or target in required
            or not set(required).issubset(selected)
            or any(wave_by_target[name] >= wave_by_target[target] for name in required)
        ):
            raise TestStoreContractError("plan exact dependencies are invalid")
    fallback = raw["complete_intent_fallback"]
    reusable = raw["reusable"]
    if type(fallback) is not bool or type(reusable) is not bool:
        raise TestStoreContractError("plan boolean fields are invalid")
    manifest_fingerprint = _text(
        "plan.manifest_fingerprint", raw["manifest_fingerprint"], maximum=64
    )
    repository_id = _text(
        "plan.repository_id", raw["repository_id"], maximum=256
    )
    if repository_id != source.repository_id:
        raise TestStoreContractError("plan repository identity is contradictory")
    intent = _text("plan.intent", raw["intent"], maximum=64)
    timeouts_raw = _mapping("plan.timeouts", raw["timeouts"])
    _exact_fields("plan.timeouts", timeouts_raw, _PLAN_TIMEOUT_FIELDS)
    execution_timeout = timeouts_raw["execution_seconds"]
    if execution_timeout is not None:
        execution_timeout = _setup_integer(
            "plan.timeouts.execution_seconds",
            execution_timeout,
            minimum=1,
            maximum=MAX_EXECUTION_TIMEOUT_SECONDS,
        )
    launch_timeout = _setup_integer(
        "plan.timeouts.launch_seconds",
        timeouts_raw["launch_seconds"],
        minimum=1,
        maximum=MAX_LAUNCH_TIMEOUT_SECONDS,
    )
    try:
        timeouts = TestPlanTimeouts(
            execution_seconds=execution_timeout,
            launch_seconds=launch_timeout,
        )
    except TestPlanError as error:
        raise TestStoreContractError("plan timeouts are invalid") from error
    policies_raw = _mapping("plan.evidence_policies", raw["evidence_policies"])
    if len(policies_raw) > 64:
        raise TestStoreContractError("plan evidence_policies exceed their bound")
    policies: dict[str, EvidencePolicy] = {}
    for name, value in sorted(policies_raw.items()):
        if not isinstance(name, str) or re.fullmatch(
            r"[a-z][a-z0-9_.-]{0,63}", name
        ) is None:
            raise TestStoreContractError("plan evidence policy name is invalid")
        policy_raw = _mapping(f"plan.evidence_policies.{name}", value)
        _exact_fields(
            f"plan.evidence_policies.{name}", policy_raw, _PLAN_POLICY_FIELDS
        )
        policy_intent = _text(
            f"plan.evidence_policies.{name}.intent",
            policy_raw["intent"],
            maximum=64,
        )
        required_targets = _text_sequence(
            f"plan.evidence_policies.{name}.required_targets",
            policy_raw["required_targets"],
            maximum_items=256,
        )
        max_age_seconds = policy_raw["max_age_seconds"]
        allow_reuse = policy_raw["allow_reuse"]
        if (
            policy_intent != intent
            or not required_targets
            or tuple(sorted(set(required_targets))) != required_targets
            or type(max_age_seconds) is not int
            or not 1 <= max_age_seconds <= 31_536_000
            or type(allow_reuse) is not bool
        ):
            raise TestStoreContractError("plan evidence policy is invalid")
        policy = EvidencePolicy(
            name=name,
            intent=policy_intent,
            required_targets=required_targets,
            max_age_seconds=max_age_seconds,
            allow_reuse=allow_reuse,
        )
        if policy_raw["fingerprint"] != evidence_policy_fingerprint(policy):
            raise TestStoreContractError(
                "plan evidence policy fingerprint is invalid"
            )
        policies[name] = policy
    fingerprint_document = {
        "schema_version": 3 if has_dependencies else 2,
        "manifest_fingerprint": manifest_fingerprint,
        "repository_id": repository_id,
        "intent": intent,
        "timeouts": timeouts.to_document(),
        "source": source.to_document(),
        "changes": [
            {
                "path": change.path,
                "status": change.status.value,
                "previous_path": change.previous_path,
            }
            for change in changes
        ],
        "eligible_targets": list(eligible),
        "selected_targets": list(selected),
        "dependency_waves": [list(wave) for wave in waves],
        **(
            {
                "dependencies": {
                    target: list(values)
                    for target, values in dependencies.items()
                }
            }
            if has_dependencies
            else {}
        ),
        "selection": {
            target: list(item.reasons) for target, item in selection.items()
        },
        "complete_intent_fallback": fallback,
        "reusable": reusable,
    }
    fingerprint = deterministic_fingerprint(fingerprint_document)
    execution_fingerprint = deterministic_fingerprint(
        {
            "schema_version": 3 if has_dependencies else 2,
            "manifest_fingerprint": manifest_fingerprint,
            "repository_id": repository_id,
            "source_mode": source.mode.value,
            "content_fingerprint": source.content_fingerprint,
            "intent": intent,
            "timeouts": timeouts.to_document(),
            "eligible_targets": list(eligible),
            "selected_targets": list(selected),
            "dependency_waves": [list(wave) for wave in waves],
            **(
                {
                    "dependencies": {
                        target: list(values)
                        for target, values in dependencies.items()
                    }
                }
                if has_dependencies
                else {}
            ),
        }
    )
    if (
        raw["fingerprint"] != fingerprint
        or raw["execution_fingerprint"] != execution_fingerprint
        or raw["plan_id"] != "plan-" + fingerprint[:32]
    ):
        raise TestStoreContractError("plan deterministic identity is invalid")
    return TestPlan(
        plan_id=str(raw["plan_id"]),
        fingerprint=fingerprint,
        execution_fingerprint=execution_fingerprint,
        manifest_fingerprint=manifest_fingerprint,
        repository_id=repository_id,
        intent=intent,
        timeouts=timeouts,
        source=source,
        changes=tuple(changes),
        eligible_targets=eligible,
        selected_targets=selected,
        dependency_waves=waves,
        dependencies=dependencies,
        selection=selection,
        complete_intent_fallback=fallback,
        reusable=reusable,
        evidence_policies=MappingProxyType(policies),
        dependency_schema_version=3 if has_dependencies else 2,
    )


@runtime_checkable
class TestPlaneClient(Protocol):
    def health(self) -> Mapping[str, object]: ...

    def setup(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]: ...

    def repository_catalog(
        self,
        *,
        repository_ids: Sequence[str],
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]: ...

    def dashboard_stats(
        self, *, repository_id: str, days: int, limit: int = 25
    ) -> Mapping[str, object]: ...

    def dashboard_fleet(
        self, *, repository_ids: Sequence[str], hours: int = 24
    ) -> Mapping[str, object]: ...

    def preview(
        self,
        *,
        repository_id: str,
        intent: str,
        actor: str,
        owner_uid: int,
        access_uid: int | None = None,
        temporary_root: str | None = None,
        requested_targets: Sequence[str] = (),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS,
        launch_deadline_monotonic: float | None = None,
    ) -> Mapping[str, object]: ...

    def register_plan(
        self,
        plan_document: Mapping[str, object],
        *,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> Mapping[str, object]: ...

    def plan_repository(self, *, plan_id: str, repository_id: str) -> str: ...

    def submit(
        self,
        *,
        plan_id: str,
        repository_id: str,
        operation_id: str,
        actor: str,
        owner_uid: int,
        priority: int = 0,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> Mapping[str, object]: ...

    def status(
        self, *, run_id: str, repository_id: str
    ) -> Mapping[str, object]: ...

    def queue_status(
        self, *, repository_id: str
    ) -> Mapping[str, object]: ...

    def runs(
        self,
        *,
        repository_id: str,
        after: str | None = None,
        limit: int = 50,
        state: str | None = None,
    ) -> Mapping[str, object]: ...

    def summary(
        self, *, run_id: str, repository_id: str
    ) -> Mapping[str, object]: ...

    def failures(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> Mapping[str, object]: ...

    def artifacts(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> Mapping[str, object]: ...

    def artifact(
        self, *, run_id: str, repository_id: str, artifact_id: str
    ) -> Mapping[str, object]: ...

    def cases(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: int = 0,
        limit: int = 25,
    ) -> Mapping[str, object]: ...

    def events(
        self,
        *,
        repository_id: str,
        after_event_id: int = 0,
        limit: int = 200,
    ) -> Mapping[str, object]: ...

    def cancel(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        reason: str,
        operation_id: str,
    ) -> Mapping[str, object]: ...

    def retry(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        failed_only: bool,
        operation_id: str,
    ) -> Mapping[str, object]: ...

    def stats(
        self, *, repository_id: str, grain: str, since: float, limit: int = 500
    ) -> Mapping[str, object]: ...

    def policy_check(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
    ) -> Mapping[str, object]: ...

    def policy_consume(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
        operation_id: str,
    ) -> Mapping[str, object]: ...

    def fleet_overview(
        self,
        *,
        grain: str,
        since: float,
        repository_limit: int = 50,
        bucket_limit: int = 48,
    ) -> Mapping[str, object]: ...

    def repository_detail(
        self,
        *,
        repository_id: str,
        grain: str,
        since: float,
        limit: int = 500,
    ) -> Mapping[str, object]: ...


class StoreTestPlaneAdapter:
    """Testd-owned implementation; broker code sees only TestPlaneClient."""

    def __init__(
        self,
        store: UniversalTestStore,
        *,
        previewer: RepositoryUIDPlanPreviewer | None = None,
    ) -> None:
        if not isinstance(store, UniversalTestStore):
            raise TestStoreContractError("store must be UniversalTestStore")
        self._store = store
        if previewer is not None and not isinstance(
            previewer, RepositoryUIDPlanPreviewer
        ):
            raise TestStoreContractError("repository plan previewer is invalid")
        self._previewer = previewer
        self._plans: dict[str, TestPlan] = {}
        self._preview_resources: dict[str, Mapping[str, TargetResources]] = {}
        self._lock = RLock()

    def health(self) -> Mapping[str, object]:
        metadata = self._store.health()
        return self._bounded(
            {
                "schema_version": 1,
                "status": "ok",
                "test_store_schema_version": metadata["schema_version"],
                "store_generation": metadata["store_generation"],
            }
        )

    @staticmethod
    def _preview_target_resources(
        value: object, *, plan: TestPlan
    ) -> Mapping[str, TargetResources]:
        if not isinstance(value, Mapping) or set(value) != set(plan.selected_targets):
            raise TestStoreContractError(
                "repository plan preview target resources are incomplete"
            )
        result: dict[str, TargetResources] = {}
        expected = set(TargetResources.__dataclass_fields__)
        for target_name, raw in value.items():
            if not isinstance(target_name, str) or not isinstance(raw, Mapping):
                raise TestStoreContractError("preview target resources are invalid")
            if set(raw) != expected:
                raise TestStoreContractError("preview target resource fields are invalid")
            result[target_name] = TargetResources(
                cpu_millis=raw["cpu_millis"],
                memory_mib=raw["memory_mib"],
                pids=raw["pids"],
                estimated_seconds=raw["estimated_seconds"],
                shard_count=raw["shard_count"],
                max_attempts=raw["max_attempts"],
                worktree_key=raw["worktree_key"],
                exclusive_resources=tuple(raw["exclusive_resources"]),
            )
        return MappingProxyType(result)

    def setup(
        self,
        *,
        repository_id: str,
        owner_uid: int,
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        del timeout_seconds
        if (
            not isinstance(repository_id, str)
            or _SAFE_REPOSITORY_ID.fullmatch(repository_id) is None
        ):
            raise TestStoreContractError("repository_id is invalid")
        if type(owner_uid) is not int or owner_uid < 0:
            raise TestStoreContractError("owner_uid must be non-negative")
        if self._previewer is None:
            raise TestRepositorySetupUnavailable(
                "repository-UID test setup inspection is not connected"
            )
        document = decode_repository_setup_document(
            self._previewer.setup_as_owner(
                repository_id=repository_id,
                owner_uid=owner_uid,
            ),
            expected_repository_id=repository_id,
        )
        self._store.retain_repository_setup_projection(document)
        return self._bounded(document)

    def repository_catalog(
        self,
        *,
        repository_ids: Sequence[str],
        timeout_seconds: float | None = None,
    ) -> Mapping[str, object]:
        del timeout_seconds
        rows = self._store.repository_setup_catalog(repository_ids)
        return self._bounded(
            {
                "schema_version": 1,
                "repositories": list(rows),
            }
        )

    @staticmethod
    def _iso_epoch(value: float | int | None) -> str | None:
        if value is None:
            return None
        return datetime.fromtimestamp(float(value), UTC).isoformat().replace(
            "+00:00", "Z"
        )

    @staticmethod
    def _dashboard_summary(values: Mapping[str, object]) -> dict[str, object]:
        passed = int(values.get("passed_count", 0) or 0)
        failed = int(values.get("failed_count", 0) or 0)
        errors = int(values.get("error_count", 0) or 0)
        test_failures = int(values.get("failure_count", 0) or 0)
        infrastructure_failures = int(
            values.get("infrastructure_count", 0) or 0
        )
        decided = passed + failed + errors
        wall = float(values.get("wall_seconds", 0) or 0)
        test_seconds = float(values.get("aggregate_test_seconds", 0) or 0)
        attempts = int(values.get("attempt_count", 0) or 0)
        terminal = (
            int(values.get("success_count", 0) or 0)
            + test_failures
            + infrastructure_failures
        )
        queue = float(values.get("queue_seconds", 0) or 0)
        runs = int(values.get("run_count", 0) or 0)
        return {
            "run_count": runs,
            "running_count": 0,
            "test_count": int(values.get("case_count", 0) or 0),
            "test_seconds": test_seconds,
            "run_seconds": wall,
            "wall_seconds": wall,
            "passed_count": passed,
            "failed_count": failed,
            "skipped_count": int(values.get("skipped_count", 0) or 0),
            "error_count": errors,
            "failure_count": failed + errors,
            # The explicit names are the current dashboard contract.  Keep
            # the historical aliases until every Console/backend deployment
            # can be upgraded atomically on this single-server installation.
            "test_failure_count": test_failures,
            "infrastructure_failure_count": infrastructure_failures,
            "failed_run_count": test_failures,
            "infrastructure_count": infrastructure_failures,
            "retry_attempt_count": int(
                values.get("retry_attempt_count", 0) or 0
            ),
            "selected_target_count": int(
                values.get("selected_target_count", 0) or 0
            ),
            "eligible_target_count": int(
                values.get("eligible_target_count", 0) or 0
            ),
            "avoided_target_count": int(
                values.get("avoided_target_count", 0) or 0
            ),
            "slow_count": int(values.get("slow_count", 0) or 0),
            "regression_count": int(values.get("regression_count", 0) or 0),
            "flaky_test_count": int(values.get("flake_count", 0) or 0),
            "parallel_efficiency_ratio": (
                None if wall <= 0 else test_seconds / wall
            ),
            "pass_rate": None if decided <= 0 else passed / decided,
            "flake_rate": (
                None
                if terminal <= 0
                else int(values.get("flake_count", 0) or 0) / terminal
            ),
            "average_queue_wait_seconds": None if runs <= 0 else queue / runs,
            "p95_queue_wait_seconds": None,
            "attempt_count": attempts,
        }

    @classmethod
    def _dashboard_efficiency(
        cls, values: Mapping[str, object]
    ) -> dict[str, object]:
        summary = cls._dashboard_summary(values)
        eligible = int(values.get("eligible_target_count", 0) or 0)
        attempts = int(values.get("attempt_count", 0) or 0)
        terminal = (
            int(values.get("success_count", 0) or 0)
            + int(values.get("failure_count", 0) or 0)
            + int(values.get("infrastructure_count", 0) or 0)
        )
        return {
            "parallel_efficiency_ratio": summary["parallel_efficiency_ratio"],
            "average_queue_wait_seconds": summary["average_queue_wait_seconds"],
            "p95_queue_wait_seconds": None,
            "selection_savings_ratio": (
                None
                if eligible <= 0
                else int(values.get("avoided_target_count", 0) or 0) / eligible
            ),
            "flake_rate": (
                None
                if terminal <= 0
                else int(values.get("flake_count", 0) or 0) / terminal
            ),
            "failure_rate": (
                None
                if terminal <= 0
                else int(values.get("failure_count", 0) or 0) / terminal
            ),
            "infrastructure_rate": (
                None
                if terminal <= 0
                else int(values.get("infrastructure_count", 0) or 0)
                / terminal
            ),
            "slow_rate": (
                None
                if attempts <= 0
                else int(values.get("slow_count", 0) or 0) / attempts
            ),
            "regression_rate": (
                None
                if attempts <= 0
                else int(values.get("regression_count", 0) or 0) / attempts
            ),
        }

    def dashboard_stats(
        self, *, repository_id: str, days: int, limit: int = 25
    ) -> Mapping[str, object]:
        if (
            not isinstance(repository_id, str)
            or _SAFE_REPOSITORY_ID.fullmatch(repository_id) is None
        ):
            raise TestStoreContractError("repository_id is invalid")
        if type(days) is not int or not 1 <= days <= 3_650:
            raise TestStoreContractError("dashboard days must be from 1 through 3650")
        self._stats_page_limit(limit)
        now = self._store.current_time()
        day = float(int(now) // 86_400 * 86_400)
        current_start = day - float((days - 1) * 86_400)
        current_end = day + 86_400.0
        previous_start = current_start - float(days * 86_400)
        current = self._store.rollup_totals(
            repository_id=repository_id,
            grain="daily",
            since=current_start,
            before=current_end,
        )
        previous = self._store.rollup_totals(
            repository_id=repository_id,
            grain="daily",
            since=previous_start,
            before=current_start,
        )
        series_days = min(days, 365)
        series_start = day - float((series_days * 2 - 1) * 86_400)
        daily_rows = self._store.rollups(
            repository_id=repository_id,
            grain="daily",
            since=series_start,
            limit=series_days * 2,
        )
        heat_start = day - 6 * 86_400.0
        hourly_rows = self._store.rollups(
            repository_id=repository_id,
            grain="hourly",
            since=heat_start,
            limit=168,
        )

        def daily_item(row: Mapping[str, object]) -> dict[str, object]:
            stamp = datetime.fromtimestamp(float(row["bucket_start"]), UTC)
            return {
                "day": stamp.date().isoformat(),
                "test_seconds": float(row["aggregate_test_seconds"]),
                "test_count": int(row["case_count"]),
                "failure_count": int(row["failed_count"])
                + int(row["error_count"]),
                "run_seconds": float(row["wall_seconds"]),
                "queue_seconds": float(row["queue_seconds"]),
                "flake_count": int(row["flake_count"]),
            }

        daily = [daily_item(row) for row in daily_rows]
        current_daily = [
            item
            for row, item in zip(daily_rows, daily)
            if float(row["bucket_start"]) >= current_start
        ]
        previous_daily = [
            item
            for row, item in zip(daily_rows, daily)
            if float(row["bucket_start"]) < current_start
        ]
        hourly = []
        for row in hourly_rows:
            stamp = datetime.fromtimestamp(float(row["bucket_start"]), UTC)
            hourly.append(
                {
                    "day": stamp.date().isoformat(),
                    "hour": stamp.hour,
                    "test_seconds": float(row["aggregate_test_seconds"]),
                    "test_count": int(row["case_count"]),
                    "failure_count": int(row["failed_count"])
                    + int(row["error_count"]),
                }
            )
        summary = self._dashboard_summary(current)
        comparison = self._dashboard_summary(previous)
        efficiency = self._dashboard_efficiency(current)
        eligible = int(current.get("eligible_target_count", 0) or 0)
        avoided = int(current.get("avoided_target_count", 0) or 0)
        observed = current.get("latest_bucket")
        identity = {
            "repository_id": repository_id,
            "days": days,
            "summary": summary,
            "comparison_summary": comparison,
            "daily": current_daily,
            "previous_daily": previous_daily,
            "hourly": hourly,
        }
        return self._bounded(
            {
                "schema_version": 2,
                **identity,
                "repo_id": repository_id,
                "health": {
                    "pass_rate": summary["pass_rate"],
                    "flake_rate": summary["flake_rate"],
                    "failure_rate": efficiency["failure_rate"],
                },
                "efficiency": efficiency,
                "avoided_work": {
                    "available": eligible > 0,
                    "test_count": avoided if eligible > 0 else None,
                    "test_seconds": None,
                },
                "dynamics": [],
                "snapshot": {
                    "generated_at": self._iso_epoch(now),
                    "observed_through": self._iso_epoch(observed),
                    "source": "devcoordinator-testdb-rollups",
                    "source_revision": deterministic_fingerprint(identity),
                    "retention": {"eligible": True, "max_age_seconds": 86_400},
                },
                "series_days": series_days,
                "truncated": days > series_days,
            }
        )

    def dashboard_fleet(
        self, *, repository_ids: Sequence[str], hours: int = 24
    ) -> Mapping[str, object]:
        if (
            isinstance(repository_ids, (str, bytes))
            or not isinstance(repository_ids, Sequence)
            or not repository_ids
            or len(repository_ids) > 50
        ):
            raise TestStoreContractError(
                "fleet dashboard repository scope must contain 1 through 50 IDs"
            )
        normalized = tuple(str(value) for value in repository_ids)
        if (
            len(set(normalized)) != len(normalized)
            or any(_SAFE_REPOSITORY_ID.fullmatch(value) is None for value in normalized)
        ):
            raise TestStoreContractError("fleet dashboard repository IDs are invalid")
        if type(hours) is not int or not 1 <= hours <= 168:
            raise TestStoreContractError("fleet dashboard hours must be from 1 through 168")
        now = self._store.current_time()
        hour_end = float((int(now) // 3_600 + 1) * 3_600)
        hour_start = hour_end - float(hours * 3_600)
        raw = self._store.fleet_rollup_projection(
            grain="hourly",
            since=hour_start,
            repository_limit=len(normalized),
            bucket_limit=hours,
            repository_ids=normalized,
        )
        setup = {
            str(row["repository_id"]): row
            for row in self._store.repository_setup_catalog(normalized)
        }
        fields = tuple(str(field) for field in raw["cell_fields"])
        by_repository: dict[str, list[dict[str, object]]] = {
            repository_id: [] for repository_id in normalized
        }
        for values in raw["cells"]:
            cell = dict(zip(fields, values))
            repository_id = str(cell["repository_id"])
            by_repository[repository_id].append(
                {
                    "hour_start": self._iso_epoch(float(cell["bucket_start"])),
                    "test_seconds": float(cell["aggregate_test_seconds"]),
                    "test_count": int(cell["case_count"]),
                    "failure_count": int(cell["failed_count"])
                    + int(cell["error_count"]),
                    "failed_run_count": int(cell["failure_count"]),
                    "infrastructure_count": int(cell["infrastructure_count"]),
                }
            )
        raw_by_id = {
            str(row["repository_id"]): row for row in raw["repositories"]
        }
        repositories: list[dict[str, object]] = []
        attention: list[dict[str, object]] = []
        for repository_id in normalized:
            values = raw_by_id.get(repository_id, {})
            summary = self._dashboard_summary(values)
            active = values.get("active", {})
            running = (
                sum(int(value) for value in active.values())
                if isinstance(active, Mapping)
                else 0
            )
            summary["running_count"] = running
            failures = int(values.get("failure_count", 0) or 0)
            infrastructure = int(values.get("infrastructure_count", 0) or 0)
            latest_infrastructure_run_at = values.get(
                "latest_infrastructure_run_at"
            )
            latest_clean_measured_run_at = values.get(
                "latest_clean_measured_run_at"
            )
            infrastructure_recovered = (
                infrastructure > 0
                and latest_infrastructure_run_at is not None
                and latest_clean_measured_run_at is not None
                and float(latest_clean_measured_run_at)
                > float(latest_infrastructure_run_at)
            )
            activity = (
                int(values.get("run_count", 0) or 0)
                + int(values.get("attempt_count", 0) or 0)
                + running
            )
            state = (
                "failing"
                if failures
                else "infrastructure"
                if infrastructure and not infrastructure_recovered
                else "healthy"
                if activity or infrastructure_recovered
                else "idle"
            )
            latest_bucket = values.get("latest_bucket")
            failed_cases = int(summary.get("failure_count", 0) or 0)
            if state == "failing":
                state_detail = {
                    "code": "recent_test_failures",
                    "title": "Recent test failures",
                    "detail": (
                        f"{failed_cases} failed or errored test cases across "
                        f"{failures} test-failed attempts were recorded during "
                        f"the selected {hours}-hour window"
                    ),
                    "scope": "selected_window",
                    "window_hours": hours,
                    "test_failure_count": failures,
                    "failed_case_count": failed_cases,
                    "infrastructure_failure_count": infrastructure,
                }
            elif state == "infrastructure":
                state_detail = {
                    "code": "recent_infrastructure_failures",
                    "title": "Recent test infrastructure failures",
                    "detail": (
                        f"{infrastructure} test attempts were prevented from "
                        "completing by setup, runtime, timeout, incomplete, or "
                        f"abandonment failures during the selected {hours}-hour window"
                    ),
                    "scope": "selected_window",
                    "window_hours": hours,
                    "test_failure_count": 0,
                    "failed_case_count": failed_cases,
                    "infrastructure_failure_count": infrastructure,
                }
            elif infrastructure_recovered:
                state_detail = {
                    "code": "recent_infrastructure_recovered",
                    "title": "Test infrastructure recovered",
                    "detail": (
                        f"A later fully successful measured run resolved "
                        f"{infrastructure} earlier infrastructure-failed test "
                        f"attempts in the selected {hours}-hour window"
                    ),
                    "scope": "selected_window",
                    "window_hours": hours,
                    "test_failure_count": 0,
                    "failed_case_count": failed_cases,
                    "infrastructure_failure_count": infrastructure,
                    "recovered_at": self._iso_epoch(
                        float(latest_clean_measured_run_at)
                    ),
                }
            else:
                state_detail = {
                    "code": (
                        "recent_test_activity_clear"
                        if state == "healthy"
                        else "no_recent_test_activity"
                    ),
                    "title": (
                        "No recent test failures"
                        if state == "healthy"
                        else "No recent test activity"
                    ),
                    "detail": (
                        f"No test or infrastructure failures were recorded during "
                        f"the selected {hours}-hour window"
                        if state == "healthy"
                        else f"No test attempts were recorded during the selected "
                        f"{hours}-hour window"
                    ),
                    "scope": "selected_window",
                    "window_hours": hours,
                    "test_failure_count": 0,
                    "failed_case_count": 0,
                    "infrastructure_failure_count": 0,
                }
            repositories.append(
                {
                    "repo_id": repository_id,
                    "repository_id": repository_id,
                    "setup_status": setup[repository_id]["setup_status"],
                    "last_activity_at": self._iso_epoch(latest_bucket),
                    "state": state,
                    # Historical counts remain scoped to the selected window;
                    # current attention requires unresolved terminal evidence.
                    "state_scope": "selected_window",
                    "state_detail": state_detail,
                    "summary": summary,
                    "efficiency": self._dashboard_efficiency(values),
                    "hourly": by_repository[repository_id],
                }
            )
            if state in {"failing", "infrastructure"} and len(attention) < 25:
                infrastructure_only = state == "infrastructure"
                attention.append(
                    {
                        "repo_id": repository_id,
                        "severity": "warning" if infrastructure_only else "error",
                        "code": state_detail["code"],
                        "title": state_detail["title"],
                        "detail": state_detail["detail"],
                        "scope": "selected_window",
                        "test_failure_count": failures,
                        "failed_case_count": failed_cases,
                        "infrastructure_failure_count": infrastructure,
                        "observed_at": self._iso_epoch(latest_bucket),
                    }
                )
        hours_iso = [self._iso_epoch(value) for value in raw["bucket_starts"]]
        capacity = []
        for hour in hours_iso:
            cells = [
                next(
                    (
                        cell
                        for cell in repository["hourly"]
                        if cell["hour_start"] == hour
                    ),
                    None,
                )
                for repository in repositories
            ]
            present = [cell for cell in cells if cell is not None]
            capacity.append(
                {
                    "hour_start": hour,
                    "test_seconds": sum(
                        float(cell["test_seconds"]) for cell in present
                    ),
                    "test_count": sum(int(cell["test_count"]) for cell in present),
                    "failure_count": sum(
                        int(cell["failure_count"]) for cell in present
                    ),
                    "failed_run_count": sum(
                        int(cell["failed_run_count"]) for cell in present
                    ),
                    "infrastructure_count": sum(
                        int(cell["infrastructure_count"]) for cell in present
                    ),
                    "active_repository_count": sum(
                        float(cell["test_seconds"]) > 0 for cell in present
                    ),
                    "p95_queue_wait_seconds": None,
                }
            )
        summary: dict[str, object] = {
            "repository_count": len(repositories),
            "returned_repository_count": len(repositories),
            "repositories_with_activity": sum(
                repository["state"] != "idle" for repository in repositories
            ),
        }
        integer_fields = (
            "run_count", "running_count", "test_count", "passed_count",
            "failure_count", "failed_run_count", "flaky_test_count",
            "infrastructure_count", "test_failure_count",
            "infrastructure_failure_count",
            "selected_target_count", "eligible_target_count",
            "avoided_target_count",
        )
        for field in integer_fields:
            summary[field] = sum(
                int(repository["summary"].get(field, 0) or 0)
                for repository in repositories
            )
        for field in ("test_seconds", "wall_seconds"):
            summary[field] = sum(
                float(repository["summary"].get(field, 0) or 0)
                for repository in repositories
            )
        wall = float(summary["wall_seconds"])
        passed = float(summary["passed_count"])
        failed = float(summary["failure_count"])
        summary["parallel_efficiency_ratio"] = (
            None if wall <= 0 else float(summary["test_seconds"]) / wall
        )
        summary["pass_rate"] = None if passed + failed <= 0 else passed / (passed + failed)
        summary["flake_rate"] = None
        summary["p95_queue_wait_seconds"] = None
        eligible_targets = int(summary["eligible_target_count"])
        summary["avoided_work"] = {
            "available": eligible_targets > 0,
            "test_count": (
                int(summary["avoided_target_count"])
                if eligible_targets > 0
                else None
            ),
            "test_seconds": None,
        }
        identity = {
            "hours": hours_iso,
            "repositories": repositories,
            "capacity": capacity,
            "summary": summary,
        }
        return self._bounded(
            {
                "schema_version": 2,
                "window": {
                    "hours": hours,
                    "start": self._iso_epoch(hour_start),
                    "end": self._iso_epoch(hour_end),
                    "timezone": "UTC",
                },
                "snapshot": {
                    "generated_at": self._iso_epoch(now),
                    "observed_through": max(
                        (
                            repository["last_activity_at"]
                            for repository in repositories
                            if repository["last_activity_at"] is not None
                        ),
                        default=None,
                    ),
                    "source": "devcoordinator-testdb-rollups",
                    "source_revision": deterministic_fingerprint(identity),
                    "retention": {"eligible": True, "max_age_seconds": 86_400},
                },
                **identity,
                "attention": attention,
                "truncated": False,
            }
        )

    def preview(
        self,
        *,
        repository_id: str,
        intent: str,
        actor: str,
        owner_uid: int,
        access_uid: int | None = None,
        temporary_root: str | None = None,
        requested_targets: Sequence[str] = (),
        execution_timeout_seconds: int | None = None,
        launch_timeout_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS,
        launch_deadline_monotonic: float | None = None,
    ) -> Mapping[str, object]:
        if (
            not isinstance(repository_id, str)
            or _SAFE_REPOSITORY_ID.fullmatch(repository_id) is None
        ):
            raise TestStoreContractError("repository_id is invalid")
        if not isinstance(intent, str) or intent not in _TEST_INTENTS:
            raise TestStoreContractError("intent is invalid")
        if (
            not isinstance(actor, str)
            or not actor
            or len(actor) > 256
            or any(character in actor for character in "\x00\r\n")
        ):
            raise TestStoreContractError("actor is invalid")
        if type(owner_uid) is not int or owner_uid < 0:
            raise TestStoreContractError("owner_uid must be non-negative")
        if access_uid is not None and (
            type(access_uid) is not int or access_uid <= 0
        ):
            raise TestStoreContractError("access_uid must be positive")
        if temporary_root is not None and (
            not isinstance(temporary_root, str)
            or not temporary_root.startswith("/")
            or not 1 <= len(temporary_root) <= 4096
            or any(character in temporary_root for character in "\x00\r\n")
        ):
            raise TestStoreContractError("temporary_root is invalid")
        requested_targets = _text_sequence(
            "requested_targets", requested_targets, maximum_items=256
        )
        if len(set(requested_targets)) != len(requested_targets):
            raise TestStoreContractError("requested_targets must be unique")
        if requested_targets and intent != "manual":
            raise TestStoreContractError(
                "requested_targets are supported only for manual intent"
            )
        try:
            timeouts = TestPlanTimeouts(
                execution_seconds=execution_timeout_seconds,
                launch_seconds=launch_timeout_seconds,
            )
        except TestPlanError as error:
            raise TestStoreContractError("plan timeouts are invalid") from error
        if launch_deadline_monotonic is not None and (
            isinstance(launch_deadline_monotonic, bool)
            or not isinstance(launch_deadline_monotonic, (int, float))
            or not math.isfinite(float(launch_deadline_monotonic))
            or float(launch_deadline_monotonic) <= 0
        ):
            raise TestStoreContractError("plan launch deadline is invalid")
        if self._previewer is None:
            raise TestPlanPreviewUnavailable(
                "repository-UID test planning is not connected"
            )
        preview_arguments: dict[str, object] = {
            "repository_id": repository_id,
            "intent": intent,
            "actor": actor,
            "owner_uid": owner_uid,
            "temporary_root": temporary_root,
            "requested_targets": requested_targets,
            "execution_timeout_seconds": timeouts.execution_seconds,
            "launch_timeout_seconds": timeouts.launch_seconds,
            "launch_deadline_monotonic": launch_deadline_monotonic,
        }
        if access_uid is not None:
            preview_arguments["access_uid"] = access_uid
        raw_preview = self._previewer.preview_as_owner(**preview_arguments)
        capability_requests = None
        if isinstance(raw_preview, Mapping) and set(raw_preview) in (
            {"plan", "target_resources"},
            {"plan", "target_resources", "capability_requests"},
        ):
            raw_plan = raw_preview["plan"]
            resources_value = raw_preview["target_resources"]
            capability_requests = raw_preview.get("capability_requests")
        else:
            raw_plan = raw_preview
            resources_value = None
        plan = decode_test_plan_document(raw_plan)  # type: ignore[arg-type]
        if (
            plan.repository_id != repository_id
            or plan.intent != intent
            or plan.timeouts != timeouts
        ):
            raise TestStoreConflict(
                "repository plan preview returned mismatched identity, intent, or timeouts"
            )
        result: dict[str, object] = {
                "schema_version": 1,
                "repository_id": repository_id,
                "intent": intent,
                "plan": plan.to_document(),
                # The broker must authority-check the returned source before it
                # asks testd to persist the plan. Preview alone is read-only.
                "registered": False,
        }
        if resources_value is not None:
            resources = self._preview_target_resources(resources_value, plan=plan)
            with self._lock:
                self._preview_resources[plan.plan_id] = resources
            result["target_resources"] = {
                name: {
                    field: (
                        list(getattr(item, field))
                        if field == "exclusive_resources"
                        else getattr(item, field)
                    )
                    for field in TargetResources.__dataclass_fields__
                }
                for name, item in resources.items()
            }
        if capability_requests is not None:
            if (
                not isinstance(capability_requests, Mapping)
                or set(capability_requests)
                != {"networks", "fixtures", "credentials"}
            ):
                raise TestStoreContractError("preview capability requests are invalid")
            networks = _text_sequence(
                "capability networks",
                capability_requests["networks"],
                maximum_items=4,
            )
            fixtures = _text_sequence(
                "capability fixtures",
                capability_requests["fixtures"],
                maximum_items=256,
            )
            credentials = _text_sequence(
                "capability credentials",
                capability_requests["credentials"],
                maximum_items=64,
            )
            if (
                any(
                    item
                    not in {"none", "loopback", "host-loopback", "external"}
                    for item in networks
                )
                or tuple(sorted(set(networks))) != networks
                or tuple(sorted(set(fixtures))) != fixtures
                or tuple(sorted(set(credentials))) != credentials
                or any(_SETUP_BINDING.fullmatch(item) is None for item in credentials)
            ):
                raise TestStoreContractError("preview capability requests are invalid")
            result["capability_requests"] = {
                "networks": list(networks),
                "fixtures": list(fixtures),
                "credentials": list(credentials),
            }
        return self._bounded(result)

    def register_plan(
        self,
        plan_document: Mapping[str, object],
        *,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> Mapping[str, object]:
        plan = decode_test_plan_document(plan_document)
        if target_resources is not None:
            target_resources = self._preview_target_resources(
                {
                    name: {
                        field: (
                            list(getattr(item, field))
                            if field == "exclusive_resources"
                            else getattr(item, field)
                        )
                        for field in TargetResources.__dataclass_fields__
                    }
                    for name, item in target_resources.items()
                },
                plan=plan,
            )
            target_resources = MappingProxyType(
                {
                    name: replace(
                        resource,
                        shard_count=(
                            effective := self._store.recommend_shard_count(
                                repository_id=plan.repository_id,
                                target_name=name,
                                ceiling=resource.shard_count,
                            )
                        ),
                        estimated_seconds=max(
                            0.001, resource.estimated_seconds / effective
                        ),
                    )
                    for name, resource in target_resources.items()
                }
            )
        durable = self._store.register_plan(
            plan, target_resources=target_resources
        )
        with self._lock:
            existing = self._plans.get(plan.plan_id)
            if existing is not None and existing.fingerprint != plan.fingerprint:
                raise TestStoreConflict("plan_id is registered with another fingerprint")
            self._plans[plan.plan_id] = plan
            if target_resources is not None:
                self._preview_resources[plan.plan_id] = target_resources
        return self._bounded(
            {
                "schema_version": 1,
                "plan_id": plan.plan_id,
                "fingerprint": plan.fingerprint,
                "repository_id": plan.repository_id,
                "registered": bool(durable["registered"]),
            }
        )

    def plan_repository(self, *, plan_id: str, repository_id: str) -> str:
        plan = self._resolve_plan(plan_id)
        if plan.repository_id != repository_id:
            raise TestStoreConflict(
                "plan does not belong to the requested repository"
            )
        return plan.repository_id

    def submit(
        self,
        *,
        plan_id: str,
        repository_id: str,
        operation_id: str,
        actor: str,
        owner_uid: int,
        priority: int = 0,
        target_resources: Mapping[str, TargetResources] | None = None,
    ) -> Mapping[str, object]:
        plan = self._resolve_plan(plan_id)
        if plan.repository_id != repository_id:
            raise TestStoreConflict(
                "submitted repository_id does not match the registered plan"
            )
        if target_resources is None:
            with self._lock:
                target_resources = self._preview_resources.get(plan.plan_id)
        if target_resources is None:
            target_resources = self._store.get_plan_target_resources(plan.plan_id)
        result = self._store.submit_plan(
            plan,
            operation_id=operation_id,
            actor=actor,
            owner_uid=owner_uid,
            priority=priority,
            target_resources=target_resources,
        )
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": plan.repository_id,
                **result.__dict__,
            }
        )

    def _resolve_plan(self, plan_id: str) -> TestPlan:
        with self._lock:
            plan = self._plans.get(plan_id)
        if plan is not None:
            return plan
        try:
            plan = decode_test_plan_document(
                self._store.get_plan_document(plan_id)
            )
        except Exception as error:
            if isinstance(error, TestStoreConflict):
                raise
            raise TestStoreConflict(
                "plan is not registered with the current testd"
            ) from error
        with self._lock:
            self._plans[plan.plan_id] = plan
        return plan

    def status(
        self, *, run_id: str, repository_id: str
    ) -> Mapping[str, object]:
        return self._bounded(
            self._status_document(
                self._store.get_run(run_id, repository_id=repository_id)
            )
        )

    def queue_status(self, *, repository_id: str) -> Mapping[str, object]:
        return self._bounded(
            {
                "schema_version": 1,
                **self._store.queue_status(repository_id=repository_id),
            }
        )

    def runs(
        self,
        *,
        repository_id: str,
        after: str | None = None,
        limit: int = 50,
        state: str | None = None,
    ) -> Mapping[str, object]:
        page_limit = self._history_page_limit(limit)
        rows = self._store.runs(
            repository_id=repository_id,
            after=after,
            limit=page_limit,
            state=state,
        )
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "runs": list(rows),
                "next_cursor": (
                    rows[-1]["run_id"] if len(rows) == page_limit else None
                ),
            }
        )

    def summary(
        self, *, run_id: str, repository_id: str
    ) -> Mapping[str, object]:
        run = self._store.get_run(run_id, repository_id=repository_id)
        plan = decode_test_plan_document(
            self._store.get_plan_document(str(run["plan_id"]))
        )
        metrics = self._store.run_metrics(run_id)
        failures = self._store.failures(run_id=run_id, limit=3)
        artifacts = self._store.artifacts(run_id=run_id, limit=16)
        summary = AgentRunSummary(
            run_id=run_id,
            conclusion=str(run["conclusion"] or run["state"]),
            intent=str(run["intent"]),
            source=plan.source,
            selected_targets=plan.selected_targets,
            selection_reasons={
                target: item.reasons for target, item in plan.selection.items()
            },
            progress={
                "completed_targets": int(metrics["completed_target_count"]),
                "total_targets": int(metrics["target_count"]),
            },
            counts={
                "attempts": int(metrics["attempt_count"]),
                "passed": int(metrics["passed_count"]),
                "failed": int(metrics["failed_count"]),
                "skipped": int(metrics["skipped_count"]),
                "errors": int(metrics["error_count"]),
            },
            timing={
                "queue_seconds": metrics["queue_seconds"],
                "wall_seconds": metrics["wall_seconds"],
                "aggregate_test_seconds": metrics["aggregate_test_seconds"],
            },
            failures=tuple(
                FailureSummary(
                    target=str(item["target_name"]),
                    message=str(item["message"]),
                    location=(
                        None if item["location"] is None else str(item["location"])
                    ),
                    artifact_id=(
                        None
                        if item["artifact_id"] is None
                        else str(item["artifact_id"])
                    ),
                )
                for item in failures
            ),
            artifacts=tuple(
                ArtifactSummary(
                    artifact_id=str(item["artifact_id"]),
                    kind=str(item["kind"]),
                    target=str(item["target_name"]),
                )
                for item in artifacts
            ),
            detail_command=(
                "test failures "
                f"--repository-id {run['repository_id']} --run-id {run_id}"
            ),
        )
        # This is the stronger agent-facing bound; status remains the detailed
        # cursorable operator projection.
        document = compact_agent_summary(
            summary, max_bytes=MAX_AGENT_SUMMARY_BYTES - 384
        )
        document["repository_id"] = repository_id
        document["failure_count"] = int(metrics["failure_record_count"])
        document["artifact_count"] = int(metrics["artifact_count"])
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_AGENT_SUMMARY_BYTES:
            raise AssertionError("agent summary exceeded its contract")
        return document

    def failures(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> Mapping[str, object]:
        self._store.get_run(run_id, repository_id=repository_id)
        page_limit = self._page_limit(limit)
        rows = self._store.failures(run_id=run_id, after=after, limit=page_limit)
        items = [
            {
                **row,
                "message": str(row["message"])[:2048],
                "location": (
                    None if row["location"] is None else str(row["location"])[:2048]
                ),
            }
            for row in rows
        ]
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "run_id": run_id,
                "failures": items,
                "next_cursor": rows[-1]["failure_id"] if len(rows) == page_limit else None,
            }
        )

    def artifacts(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: str | None = None,
        limit: int = 25,
    ) -> Mapping[str, object]:
        self._store.get_run(run_id, repository_id=repository_id)
        page_limit = self._page_limit(limit)
        rows = self._store.artifacts(run_id=run_id, after=after, limit=page_limit)
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "run_id": run_id,
                "artifacts": list(rows),
                "next_cursor": rows[-1]["artifact_id"] if len(rows) == page_limit else None,
            }
        )

    def artifact(
        self, *, run_id: str, repository_id: str, artifact_id: str
    ) -> Mapping[str, object]:
        self._store.get_run(run_id, repository_id=repository_id)
        artifact = self._store.artifact(
            run_id=run_id, artifact_id=artifact_id
        )
        return self._bounded(
            {
                "schema_version": 1,
                "ok": True,
                "repository_id": repository_id,
                "run_id": run_id,
                "artifact": artifact,
            }
        )

    def cases(
        self,
        *,
        run_id: str,
        repository_id: str,
        after: int = 0,
        limit: int = 25,
    ) -> Mapping[str, object]:
        if type(after) is not int or after < 0:
            raise TestStoreContractError("case cursor must be non-negative")
        self._store.get_run(run_id, repository_id=repository_id)
        page_limit = self._page_limit(limit)
        rows = self._store.cases(run_id=run_id, after=after, limit=page_limit)
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "run_id": run_id,
                "cases": list(rows),
                "next_cursor": (
                    int(rows[-1]["cursor"]) if len(rows) == page_limit else None
                ),
            }
        )

    def events(
        self,
        *,
        repository_id: str,
        after_event_id: int = 0,
        limit: int = 200,
    ) -> Mapping[str, object]:
        if type(after_event_id) is not int or after_event_id < 0:
            raise TestStoreContractError("event cursor must be non-negative")
        page_limit = self._event_page_limit(limit)
        rows = self._store.events(
            repository_id=repository_id,
            after_event_id=after_event_id,
            limit=page_limit,
        )
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "events": list(rows),
                "next_cursor": (
                    int(rows[-1]["event_id"]) if len(rows) == page_limit else None
                ),
            }
        )

    def cancel(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        reason: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        self._store.get_run(run_id, repository_id=repository_id)
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                **self._store.request_cancel(
                    run_id, actor=actor, reason=reason, operation_id=operation_id
                ),
            }
        )

    def retry(
        self,
        *,
        run_id: str,
        repository_id: str,
        actor: str,
        failed_only: bool,
        operation_id: str,
    ) -> Mapping[str, object]:
        self._store.get_run(run_id, repository_id=repository_id)
        result = self._store.retry_run(
            run_id,
            actor=actor,
            failed_only=failed_only,
            operation_id=operation_id,
        )
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                **result.__dict__,
            }
        )

    def stats(
        self, *, repository_id: str, grain: str, since: float, limit: int = 500
    ) -> Mapping[str, object]:
        rows = self._store.rollups(
            repository_id=repository_id,
            grain=grain,
            since=since,
            limit=self._stats_page_limit(limit),
        )
        return self._bounded(
            {
                "schema_version": 1,
                "repository_id": repository_id,
                "grain": grain,
                "items": list(rows),
            }
        )

    def policy_check(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
    ) -> Mapping[str, object]:
        return self._bounded(
            {
                "schema_version": 1,
                **self._store.check_evidence_policy(
                    repository_id=repository_id,
                    snapshot_id=snapshot_id,
                    policy_name=policy_name,
                ),
            }
        )

    def policy_consume(
        self,
        *,
        repository_id: str,
        snapshot_id: str,
        policy_name: str,
        operation_id: str,
    ) -> Mapping[str, object]:
        return self._bounded(
            {
                "schema_version": 1,
                **self._store.consume_evidence_policy(
                    repository_id=repository_id,
                    snapshot_id=snapshot_id,
                    policy_name=policy_name,
                    operation_id=operation_id,
                ),
            }
        )

    def fleet_overview(
        self,
        *,
        grain: str,
        since: float,
        repository_limit: int = 50,
        bucket_limit: int = 48,
    ) -> Mapping[str, object]:
        return self._bounded(
            {
                "schema_version": 1,
                **self._store.fleet_rollup_projection(
                    grain=grain,
                    since=since,
                    repository_limit=repository_limit,
                    bucket_limit=bucket_limit,
                ),
            }
        )

    def repository_detail(
        self,
        *,
        repository_id: str,
        grain: str,
        since: float,
        limit: int = 500,
    ) -> Mapping[str, object]:
        return self._bounded(
            {
                "schema_version": 1,
                **self._store.repository_rollup_detail(
                    repository_id=repository_id,
                    grain=grain,
                    since=since,
                    limit=self._stats_page_limit(limit),
                ),
            }
        )

    @staticmethod
    def _status_document(run: Mapping[str, object]) -> dict[str, object]:
        targets = list(run["targets"])
        completed = sum(
            1
            for target in targets
            if target["state"]
            not in {"queued", "leased", "running"}
        )
        return {
            "schema_version": 1,
            "run_id": run["run_id"],
            "repository_id": run["repository_id"],
            "intent": run["intent"],
            "source_mode": run["source_mode"],
            "source_fingerprint": run["source_fingerprint"],
            "state": run["state"],
            "conclusion": run["conclusion"],
            "failure_classification": run["failure_classification"],
            "queued_at": run["queued_at"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "progress": {
                "completed_targets": completed,
                "total_targets": len(targets),
            },
            "usage": run.get("usage"),
            "lease_expiry_evidence": run["lease_expiry_evidence"],
            "targets": [
                {
                    "target_id": target["target_id"],
                    "target_name": target["target_name"],
                    "wave_index": target["wave_index"],
                    "shard_index": target["shard_index"],
                    "shard_count": target["shard_count"],
                    "state": target["state"],
                    "wait": target.get("wait"),
                    "active_attempt": target.get("active_attempt"),
                    "usage": target.get("usage"),
                }
                for target in targets
            ],
        }

    @staticmethod
    def _page_limit(value: object) -> int:
        if type(value) is not int or not 1 <= value <= MAX_TEST_PLANE_PAGE_SIZE:
            raise TestStoreContractError(
                f"page limit must be from 1 through {MAX_TEST_PLANE_PAGE_SIZE}"
            )
        return value

    @staticmethod
    def _stats_page_limit(value: object) -> int:
        if (
            type(value) is not int
            or not 1 <= value <= MAX_TEST_PLANE_STATS_PAGE_SIZE
        ):
            raise TestStoreContractError(
                "stats limit must be from 1 through "
                f"{MAX_TEST_PLANE_STATS_PAGE_SIZE}"
            )
        return value

    @staticmethod
    def _history_page_limit(value: object) -> int:
        if type(value) is not int or not 1 <= value <= 200:
            raise TestStoreContractError("run history limit must be from 1 through 200")
        return value

    @staticmethod
    def _event_page_limit(value: object) -> int:
        if type(value) is not int or not 1 <= value <= 500:
            raise TestStoreContractError("event limit must be from 1 through 500")
        return value

    @staticmethod
    def _bounded(document: Mapping[str, object]) -> Mapping[str, object]:
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_TEST_PLANE_RESPONSE_BYTES:
            raise TestStoreContractError("test-plane response exceeds its byte bound")
        return document


__all__ = [
    "MAX_TEST_PLANE_RESPONSE_BYTES",
    "RepositoryUIDPlanPreviewer",
    "StoreTestPlaneAdapter",
    "TestPlaneClient",
    "TestPlanPreviewUnavailable",
    "TestRepositorySetupUnavailable",
    "decode_repository_setup_document",
    "decode_test_plan_document",
]
