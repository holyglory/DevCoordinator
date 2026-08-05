"""Pure deterministic planning for the universal asynchronous test harness."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping, Sequence

from .universal_test_contract import (
    EvidencePolicy,
    SourceMode,
    TestManifest,
    deterministic_fingerprint,
    evidence_policy_fingerprint,
    is_sha256,
    normalize_repository_path,
    repository_glob_matches,
)


class TestPlanError(ValueError):
    """A plan request is invalid or cannot safely select tests."""


DEFAULT_LAUNCH_TIMEOUT_SECONDS = 300
MAX_EXECUTION_TIMEOUT_SECONDS = 86_400
MAX_LAUNCH_TIMEOUT_SECONDS = 3_600
MAX_SELECTION_REASONS = 32


class ChangeStatus(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    UNTRACKED = "untracked"


@dataclass(frozen=True)
class ChangedPath:
    path: str
    status: ChangeStatus
    previous_path: str | None = None

    def __post_init__(self) -> None:
        try:
            normalized = normalize_repository_path(self.path, path="change.path")
        except ValueError as error:
            raise TestPlanError(str(error)) from error
        object.__setattr__(self, "path", normalized)
        if not isinstance(self.status, ChangeStatus):
            try:
                object.__setattr__(self, "status", ChangeStatus(self.status))
            except ValueError as error:
                raise TestPlanError(f"unsupported change status: {self.status}") from error
        if self.status is ChangeStatus.RENAMED:
            if self.previous_path is None:
                raise TestPlanError("renamed changes require previous_path")
            try:
                previous = normalize_repository_path(
                    self.previous_path, path="change.previous_path"
                )
            except ValueError as error:
                raise TestPlanError(str(error)) from error
            if previous == normalized:
                raise TestPlanError("renamed change paths must differ")
            object.__setattr__(self, "previous_path", previous)
        elif self.previous_path is not None:
            raise TestPlanError("previous_path is valid only for renamed changes")

    @property
    def affected_paths(self) -> tuple[str, ...]:
        if self.previous_path is None:
            return (self.path,)
        return (self.previous_path, self.path)


@dataclass(frozen=True)
class SourceIdentity:
    """Exact repository material used for planning and eventual execution."""

    mode: SourceMode
    repository_id: str
    content_fingerprint: str
    original_root: str
    temporary_root: str | None = None
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, SourceMode):
            try:
                object.__setattr__(self, "mode", SourceMode(self.mode))
            except ValueError as error:
                raise TestPlanError("source mode must be live or immutable") from error
        if (
            not isinstance(self.repository_id, str)
            or not self.repository_id
            or len(self.repository_id) > 256
        ):
            raise TestPlanError("repository_id must identify one enrolled repository")
        if not isinstance(self.content_fingerprint, str) or not is_sha256(
            self.content_fingerprint
        ):
            raise TestPlanError("content_fingerprint must be a lowercase SHA-256 digest")
        original = self._absolute_path(self.original_root, "original_root")
        object.__setattr__(self, "original_root", original)
        if self.temporary_root is not None:
            temporary = self._absolute_path(self.temporary_root, "temporary_root")
            if temporary == original:
                raise TestPlanError("temporary_root must differ from original_root")
            object.__setattr__(self, "temporary_root", temporary)
        if self.mode is SourceMode.IMMUTABLE:
            if (
                not isinstance(self.snapshot_id, str)
                or not self.snapshot_id
                or len(self.snapshot_id) > 256
            ):
                raise TestPlanError("immutable sources require snapshot_id")
        elif self.snapshot_id is not None:
            raise TestPlanError("live sources cannot claim snapshot_id")

    @staticmethod
    def _absolute_path(value: object, field: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise TestPlanError(f"{field} must be one canonical absolute path")
        if "\x00" in value or "\r" in value or "\n" in value or "\\" in value:
            raise TestPlanError(f"{field} must be a POSIX path")
        path = PurePosixPath(value)
        if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
            raise TestPlanError(f"{field} must be a normalized absolute path")
        normalized = str(path)
        if normalized != value.rstrip("/") and value != "/":
            raise TestPlanError(f"{field} must be normalized")
        return normalized

    def to_document(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "repository_id": self.repository_id,
            "content_fingerprint": self.content_fingerprint,
            "original_root": self.original_root,
            "temporary_root": self.temporary_root,
            "snapshot_id": self.snapshot_id,
        }


@dataclass(frozen=True)
class TargetSelection:
    target: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class TestPlanTimeouts:
    """Caller-selected semantic deadlines bound into one deterministic plan."""

    execution_seconds: int | None = None
    launch_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if self.execution_seconds is not None and (
            type(self.execution_seconds) is not int
            or not 1 <= self.execution_seconds <= MAX_EXECUTION_TIMEOUT_SECONDS
        ):
            raise TestPlanError(
                "execution timeout must be from 1 through "
                f"{MAX_EXECUTION_TIMEOUT_SECONDS} seconds"
            )
        if (
            type(self.launch_seconds) is not int
            or not 1 <= self.launch_seconds <= MAX_LAUNCH_TIMEOUT_SECONDS
        ):
            raise TestPlanError(
                "launch timeout must be from 1 through "
                f"{MAX_LAUNCH_TIMEOUT_SECONDS} seconds"
            )

    def to_document(self) -> dict[str, int | None]:
        return {
            "execution_seconds": self.execution_seconds,
            "launch_seconds": self.launch_seconds,
        }


@dataclass(frozen=True)
class TestPlan:
    plan_id: str
    fingerprint: str
    execution_fingerprint: str
    manifest_fingerprint: str
    repository_id: str
    intent: str
    timeouts: TestPlanTimeouts
    source: SourceIdentity
    changes: tuple[ChangedPath, ...]
    eligible_targets: tuple[str, ...]
    selected_targets: tuple[str, ...]
    dependency_waves: tuple[tuple[str, ...], ...]
    selection: Mapping[str, TargetSelection]
    complete_intent_fallback: bool
    reusable: bool
    evidence_policies: Mapping[str, EvidencePolicy]

    def to_document(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "fingerprint": self.fingerprint,
            "execution_fingerprint": self.execution_fingerprint,
            "manifest_fingerprint": self.manifest_fingerprint,
            "repository_id": self.repository_id,
            "intent": self.intent,
            "timeouts": self.timeouts.to_document(),
            "source": self.source.to_document(),
            "changes": [
                {
                    "path": change.path,
                    "status": change.status.value,
                    "previous_path": change.previous_path,
                }
                for change in self.changes
            ],
            "eligible_targets": list(self.eligible_targets),
            "selected_targets": list(self.selected_targets),
            "dependency_waves": [list(wave) for wave in self.dependency_waves],
            "selection": {
                target: list(item.reasons)
                for target, item in self.selection.items()
            },
            "complete_intent_fallback": self.complete_intent_fallback,
            "reusable": self.reusable,
            "evidence_policies": {
                name: {
                    "intent": policy.intent,
                    "required_targets": list(policy.required_targets),
                    "max_age_seconds": policy.max_age_seconds,
                    "allow_reuse": policy.allow_reuse,
                    "fingerprint": evidence_policy_fingerprint(policy),
                }
                for name, policy in self.evidence_policies.items()
            },
        }


def _normalized_changes(changes: Sequence[ChangedPath]) -> tuple[ChangedPath, ...]:
    normalized: list[ChangedPath] = []
    seen: set[tuple[str, str, str | None]] = set()
    for raw in changes:
        if not isinstance(raw, ChangedPath):
            raise TestPlanError("changes must contain ChangedPath values")
        key = (raw.path, raw.status.value, raw.previous_path)
        if key not in seen:
            seen.add(key)
            normalized.append(raw)
    return tuple(
        sorted(
            normalized,
            key=lambda item: (item.path, item.status.value, item.previous_path or ""),
        )
    )


def fingerprint_source_content(
    *,
    files: Mapping[str, str],
    manifest_fingerprint: str,
    dependency_locks: Mapping[str, str] | None = None,
    toolchain: Mapping[str, str] | None = None,
) -> str:
    """Fingerprint one exact materialized repository content set.

    The caller owns bounded discovery of tracked, staged, unstaged and allowed
    untracked files.  This pure helper makes the resulting identity independent
    of enumeration order and includes lock/toolchain inputs explicitly.
    """

    if not isinstance(files, Mapping) or not files:
        raise TestPlanError("source files must be a non-empty path-to-digest mapping")
    if not isinstance(manifest_fingerprint, str) or not is_sha256(
        manifest_fingerprint
    ):
        raise TestPlanError("manifest_fingerprint must be a lowercase SHA-256 digest")

    def digests(raw: Mapping[str, str], field: str) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for path, digest in raw.items():
            try:
                safe_path = normalize_repository_path(path, path=f"{field}.{path}")
            except ValueError as error:
                raise TestPlanError(str(error)) from error
            if not isinstance(digest, str) or not is_sha256(digest):
                raise TestPlanError(f"{field}.{safe_path} must be a SHA-256 digest")
            normalized[safe_path] = digest
        return dict(sorted(normalized.items()))

    normalized_toolchain: dict[str, str] = {}
    for key, value in (toolchain or {}).items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", key) is None
            or not isinstance(value, str)
            or not value
            or len(value) > 256
            or any(character in value for character in "\x00\r\n")
        ):
            raise TestPlanError("toolchain identities must be bounded name/value strings")
        normalized_toolchain[key] = value
    return deterministic_fingerprint(
        {
            "schema_version": 1,
            "manifest_fingerprint": manifest_fingerprint,
            "files": digests(files, "files"),
            "dependency_locks": digests(dependency_locks or {}, "dependency_locks"),
            "toolchain": dict(sorted(normalized_toolchain.items())),
        }
    )


def _reverse_dependencies(manifest: TestManifest) -> dict[str, set[str]]:
    reverse = {name: set() for name in manifest.targets}
    for target in manifest.targets.values():
        for dependency in target.depends_on:
            reverse[dependency].add(target.name)
    return reverse


def _bidirectional_closure(
    manifest: TestManifest,
    initial: set[str],
    reasons: dict[str, set[str]],
) -> set[str]:
    reverse = _reverse_dependencies(manifest)
    selected = set(initial)
    queue = sorted(initial)
    while queue:
        name = queue.pop(0)
        for dependency in manifest.targets[name].depends_on:
            reasons.setdefault(dependency, set()).add(f"dependency-of:{name}")
            if dependency not in selected:
                selected.add(dependency)
                queue.append(dependency)
        for dependent in sorted(reverse[name]):
            reasons.setdefault(dependent, set()).add(f"dependent-of:{name}")
            if dependent not in selected:
                selected.add(dependent)
                queue.append(dependent)
    return selected


def _bounded_selection_reasons(values: set[str]) -> tuple[str, ...]:
    """Keep planner evidence within the broker wire contract.

    Large dirty worktrees can match thousands of paths to one target.  The
    selected target and the complete changed-path set remain in the plan, while
    its human-facing reasons retain representative examples and an exact
    omitted count.
    """

    ordered = sorted(values or {"closure"})
    if len(ordered) <= MAX_SELECTION_REASONS:
        return tuple(ordered)
    visible_count = MAX_SELECTION_REASONS - 1
    return (
        f"additional-reasons:{len(ordered) - visible_count}",
        *ordered[:visible_count],
    )


def _dependency_waves(
    manifest: TestManifest, selected: set[str]
) -> tuple[tuple[str, ...], ...]:
    remaining = set(selected)
    completed: set[str] = set()
    waves: list[tuple[str, ...]] = []
    while remaining:
        ready = tuple(
            sorted(
                name
                for name in remaining
                if set(manifest.targets[name].depends_on).intersection(selected)
                <= completed
            )
        )
        if not ready:
            # Contract validation already rejects cycles.  Keep the planner
            # fail-closed in case a caller constructed a forged contract.
            raise TestPlanError("selected target graph contains a dependency cycle")
        waves.append(ready)
        completed.update(ready)
        remaining.difference_update(ready)
    return tuple(waves)


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(repository_glob_matches(pattern, path) for pattern in patterns)


_PROTECTED_BUILD_INPUT_NAMES = frozenset(
    {
        "build",
        "build.bazel",
        "cargo.lock",
        "cargo.toml",
        "cmakelists.txt",
        "composer.lock",
        "directory.build.props",
        "directory.build.targets",
        "gemfile.lock",
        "global.json",
        "go.mod",
        "go.sum",
        "gradle.properties",
        "makefile",
        "meson.build",
        "meson_options.txt",
        "noxfile.py",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "package.json",
        "packages.lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "uv.lock",
        "workspace",
        "workspace.bazel",
        "yarn.lock",
    }
)


def _protected_global_input(path: str) -> bool:
    """Classify dependency/build/CI control files independent of manifests.

    A repository manifest may broaden this set, but cannot make a lock or
    build-system mutation select less testing by mapping it to one target.
    """

    value = PurePosixPath(path)
    name = value.name.lower()
    if name in _PROTECTED_BUILD_INPUT_NAMES:
        return True
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return True
    if name.endswith((".csproj", ".fsproj", ".vbproj", ".sln", ".gradle")):
        return True
    lowered = path.lower()
    return (
        lowered.startswith(".github/workflows/")
        or lowered in {
            ".gitlab-ci.yml",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
        }
    )


def _selection_document(
    *,
    manifest: TestManifest,
    intent: str,
    timeouts: TestPlanTimeouts,
    source: SourceIdentity,
    changes: tuple[ChangedPath, ...],
    eligible: tuple[str, ...],
    selected: tuple[str, ...],
    waves: tuple[tuple[str, ...], ...],
    reasons: Mapping[str, TargetSelection],
    fallback: bool,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "manifest_fingerprint": manifest.fingerprint,
        "repository_id": source.repository_id,
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
        "selection": {
            name: list(item.reasons) for name, item in reasons.items()
        },
        "complete_intent_fallback": fallback,
        "reusable": manifest.intents[intent].allow_reuse
        and source.mode is SourceMode.IMMUTABLE,
    }


def create_test_plan(
    manifest: TestManifest,
    *,
    intent: str,
    source: SourceIdentity,
    changes: Sequence[ChangedPath] = (),
    requested_targets: Sequence[str] = (),
    execution_timeout_seconds: int | None = None,
    launch_timeout_seconds: int = DEFAULT_LAUNCH_TIMEOUT_SECONDS,
) -> TestPlan:
    """Create an exact deterministic plan without accessing the filesystem.

    Live intents select by changed path and fail toward the complete declared
    intent when a path cannot be mapped.  Immutable intents always select the
    complete declared intent.  Both dependency and reverse-dependent closure
    are included so a directly affected target cannot be considered in
    isolation from either prerequisites or consumers.
    """

    timeouts = TestPlanTimeouts(
        execution_seconds=execution_timeout_seconds,
        launch_seconds=launch_timeout_seconds,
    )
    if intent not in manifest.intents:
        raise TestPlanError(f"manifest does not declare intent {intent!r}")
    intent_contract = manifest.intents[intent]
    if source.mode is not intent_contract.source_mode:
        raise TestPlanError(
            f"intent {intent!r} requires {intent_contract.source_mode.value} source mode"
        )
    normalized_changes = _normalized_changes(changes)
    normalized_requested: tuple[str, ...] = tuple(sorted(set(requested_targets)))
    unknown_requested = sorted(set(normalized_requested) - set(manifest.targets))
    if unknown_requested:
        raise TestPlanError(
            "unknown requested target(s): " + ", ".join(unknown_requested)
        )
    if normalized_requested and intent != "manual":
        raise TestPlanError("explicit target selection is allowed only for manual intent")
    if normalized_changes and source.mode is SourceMode.IMMUTABLE:
        raise TestPlanError("immutable intent plans do not accept live change paths")

    intent_targets = {
        target.name
        for target in manifest.targets.values()
        if intent in target.intents
    }
    if not intent_targets:
        raise TestPlanError(f"intent {intent!r} has no required targets")
    eligible_seed = set(manifest.targets) if intent == "manual" else set(intent_targets)
    eligible = tuple(
        sorted(_bidirectional_closure(manifest, eligible_seed, {}))
    )
    eligible_names = set(eligible)

    reasons: dict[str, set[str]] = {}
    fallback = False
    initial: set[str] = set()
    if source.mode is SourceMode.IMMUTABLE:
        immutable_base = (
            set(normalized_requested)
            if intent == "manual" and normalized_requested
            else intent_targets
        )
        initial.update(immutable_base)
        for name in immutable_base:
            reasons.setdefault(name, set()).add(
                "requested"
                if intent == "manual" and normalized_requested
                else f"required-by-intent:{intent}"
            )
    else:
        unmatched: list[str] = []
        global_change: list[str] = []
        protected_change: list[str] = []
        for change in normalized_changes:
            for affected_path in change.affected_paths:
                if _protected_global_input(affected_path):
                    protected_change.append(affected_path)
                    continue
                if _matches_any(affected_path, manifest.global_inputs):
                    global_change.append(affected_path)
                    continue
                matching_targets = {
                    target.name
                    for target in manifest.targets.values()
                    if target.name in eligible_names
                    and _matches_any(affected_path, target.inputs)
                }
                if matching_targets:
                    initial.update(matching_targets)
                    for name in matching_targets:
                        reasons.setdefault(name, set()).add(f"input:{affected_path}")
                else:
                    unmatched.append(affected_path)
        if protected_change or global_change or unmatched:
            fallback = True
            initial.update(intent_targets)
            reason = (
                "protected-input:" + protected_change[0]
                if protected_change
                else (
                    "global-input:" + global_change[0]
                    if global_change
                    else "unmapped-input:" + unmatched[0]
                )
            )
            for name in intent_targets:
                reasons.setdefault(name, set()).add(reason)
        if normalized_requested:
            initial.update(normalized_requested)
            for name in normalized_requested:
                reasons.setdefault(name, set()).add("requested")

    selected_set = _bidirectional_closure(manifest, initial, reasons)
    selected = tuple(sorted(selected_set))
    waves = _dependency_waves(manifest, selected_set) if selected_set else ()
    selection = MappingProxyType(
        {
            name: TargetSelection(
                name,
                _bounded_selection_reasons(reasons.get(name, {"closure"})),
            )
            for name in selected
        }
    )
    fingerprint_document = _selection_document(
        manifest=manifest,
        intent=intent,
        timeouts=timeouts,
        source=source,
        changes=normalized_changes,
        eligible=eligible,
        selected=selected,
        waves=waves,
        reasons=selection,
        fallback=fallback,
    )
    fingerprint = deterministic_fingerprint(fingerprint_document)
    execution_fingerprint = deterministic_fingerprint(
        {
            "schema_version": 2,
            "manifest_fingerprint": manifest.fingerprint,
            "repository_id": source.repository_id,
            "source_mode": source.mode.value,
            "content_fingerprint": source.content_fingerprint,
            "intent": intent,
            "timeouts": timeouts.to_document(),
            "eligible_targets": list(eligible),
            "selected_targets": list(selected),
            "dependency_waves": [list(wave) for wave in waves],
        }
    )
    evidence_policies = MappingProxyType(
        {
            name: policy
            for name, policy in sorted(manifest.evidence_policies.items())
            if policy.intent == intent
        }
    )
    return TestPlan(
        plan_id="plan-" + fingerprint[:32],
        fingerprint=fingerprint,
        execution_fingerprint=execution_fingerprint,
        manifest_fingerprint=manifest.fingerprint,
        repository_id=source.repository_id,
        intent=intent,
        timeouts=timeouts,
        source=source,
        changes=normalized_changes,
        eligible_targets=eligible,
        selected_targets=selected,
        dependency_waves=waves,
        selection=selection,
        complete_intent_fallback=fallback,
        reusable=bool(fingerprint_document["reusable"]),
        evidence_policies=evidence_policies,
    )


__all__ = [
    "DEFAULT_LAUNCH_TIMEOUT_SECONDS",
    "MAX_EXECUTION_TIMEOUT_SECONDS",
    "MAX_LAUNCH_TIMEOUT_SECONDS",
    "MAX_SELECTION_REASONS",
    "ChangeStatus",
    "ChangedPath",
    "SourceIdentity",
    "TargetSelection",
    "TestPlan",
    "TestPlanTimeouts",
    "TestPlanError",
    "create_test_plan",
    "fingerprint_source_content",
]
