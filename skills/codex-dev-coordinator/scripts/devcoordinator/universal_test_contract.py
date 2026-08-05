"""Validated, immutable contract for the universal asynchronous test harness.

This module intentionally has no broker, database, process, or CLI dependencies.
Repository-controlled JSON is normalized here before a privileged component sees
it.  Execution code should consume :class:`TestManifest`, never the raw document.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Sequence


MANIFEST_SCHEMA_VERSION = 3
MANIFEST_RELATIVE_PATH = PurePosixPath(".codex/tests.json")
MAX_MANIFEST_BYTES = 512 * 1024

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "defaults",
        "global_inputs",
        "targets",
        "intents",
        "fixtures",
        "credentials",
        "evidence_policies",
    }
)
_DEFAULT_FIELDS = frozenset({"timeout_seconds", "network", "environment"})
_TARGET_FIELDS = frozenset(
    {
        "driver",
        "reporter",
        "argv",
        "cwd",
        "inputs",
        "depends_on",
        "intents",
        "timeout_seconds",
        "network",
        "exclusive_resources",
        "fixtures",
        "credentials",
        "shard",
        "retry",
        "artifacts",
        "environment",
    }
)
_INTENT_FIELDS = frozenset({"source_mode", "allow_reuse"})
_FIXTURE_FIELDS = frozenset({"template", "network"})
_CREDENTIAL_FIELDS = frozenset({"binding"})
_EVIDENCE_FIELDS = frozenset(
    {"intent", "required_targets", "max_age_seconds", "allow_reuse"}
)
_SHARD_FIELDS = frozenset({"mode", "max_shards"})
_RETRY_FIELDS = frozenset({"max_attempts", "retry_on"})
_ARTIFACT_FIELDS = frozenset(
    {"name", "path", "kind", "required", "max_bytes"}
)

_ALLOWED_DRIVERS = frozenset({"pytest", "node", "dotnet", "automation"})
_REPORTERS_BY_DRIVER = {
    "pytest": frozenset({"pytest-events"}),
    "node": frozenset({"jsonl"}),
    "dotnet": frozenset({"trx"}),
    "automation": frozenset({"jsonl", "automation-events"}),
}
_ALLOWED_NETWORK = frozenset(
    {"none", "loopback", "host-loopback", "external"}
)
_ALLOWED_FIXTURE_NETWORK = frozenset({"none", "loopback", "external"})
_NETWORK_RANK = {
    "none": 0,
    "loopback": 1,
    "host-loopback": 2,
    "external": 3,
}
_ALLOWED_INTENTS = frozenset(
    {"change", "checkpoint", "handoff", "release", "manual"}
)
_ALLOWED_SHARD_MODES = frozenset({"none", "files", "history"})
_ALLOWED_RETRY_EVENTS = frozenset({"lease_expired_before_launch"})
_ALLOWED_ARTIFACT_KINDS = frozenset(
    {"log", "jsonl", "junit", "trx", "coverage", "trace", "directory"}
)
_ALLOWED_ARG_PLACEHOLDERS = frozenset(
    {
        "{python}",
        "{node}",
        "{dotnet}",
        "{events}",
        "{results}",
        "{shard_index}",
        "{shard_count}",
    }
)
_FORBIDDEN_EXECUTABLES = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "env",
    }
)
_ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_TEMPLATE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SECRET_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|CREDENTIAL)(?:_|$)"
)
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ManifestContractError(ValueError):
    """Repository test manifest failed closed validation."""

    def __init__(self, message: str, *, path: str = "$") -> None:
        self.path = path
        super().__init__(f"{path}: {message}")


class SourceMode(str, Enum):
    LIVE = "live"
    IMMUTABLE = "immutable"


@dataclass(frozen=True)
class ResourceLimits:
    cpu_millis: int
    memory_mib: int
    pids: int


# Python owns this fixed internal accounting and storage placeholder. It is not
# accepted from repository manifests, and neither admission nor transient
# execution treats it as a caller-authored quota.
NON_AUTHORITATIVE_RESOURCES = ResourceLimits(
    cpu_millis=1_000,
    memory_mib=512,
    pids=256,
)


@dataclass(frozen=True)
class ManifestDefaults:
    timeout_seconds: int
    network: str
    environment: Mapping[str, str]


@dataclass(frozen=True)
class ShardPolicy:
    mode: str
    max_shards: int


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded infrastructure-only retry policy.

    Assertion failures, timeouts, incomplete reporting, cancellations, and a
    running worker's lost heartbeat are intentionally absent.  The scheduler
    may retry only a lease that expired before execution launched.
    """

    max_attempts: int
    retry_on: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactContract:
    name: str
    path: str
    kind: str
    required: bool
    max_bytes: int


@dataclass(frozen=True)
class FixtureContract:
    name: str
    template: str
    network: str


@dataclass(frozen=True)
class CredentialContract:
    name: str
    binding: str


@dataclass(frozen=True)
class IntentContract:
    name: str
    source_mode: SourceMode
    allow_reuse: bool


@dataclass(frozen=True)
class EvidencePolicy:
    name: str
    intent: str
    required_targets: tuple[str, ...]
    max_age_seconds: int
    allow_reuse: bool


def evidence_policy_document(policy: EvidencePolicy) -> dict[str, object]:
    """Return the exact named policy identity used by durable attestations."""

    if not isinstance(policy, EvidencePolicy):
        raise TypeError("policy must be EvidencePolicy")
    return {
        "name": policy.name,
        "intent": policy.intent,
        "required_targets": list(policy.required_targets),
        "max_age_seconds": policy.max_age_seconds,
        "allow_reuse": policy.allow_reuse,
    }


def evidence_policy_fingerprint(policy: EvidencePolicy) -> str:
    return deterministic_fingerprint(evidence_policy_document(policy))


@dataclass(frozen=True)
class TargetContract:
    name: str
    driver: str
    reporter: str
    argv: tuple[str, ...]
    cwd: str
    inputs: tuple[str, ...]
    depends_on: tuple[str, ...]
    intents: tuple[str, ...]
    timeout_seconds: int
    resources: ResourceLimits
    network: str
    exclusive_resources: tuple[str, ...]
    fixtures: tuple[str, ...]
    credentials: tuple[str, ...]
    shard: ShardPolicy
    retry: RetryPolicy
    artifacts: tuple[ArtifactContract, ...]
    environment: Mapping[str, str]


@dataclass(frozen=True)
class TestManifest:
    schema_version: int
    defaults: ManifestDefaults
    global_inputs: tuple[str, ...]
    targets: Mapping[str, TargetContract]
    intents: Mapping[str, IntentContract]
    fixtures: Mapping[str, FixtureContract]
    credentials: Mapping[str, CredentialContract]
    evidence_policies: Mapping[str, EvidencePolicy]
    fingerprint: str


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def deterministic_fingerprint(value: object) -> str:
    """Return a stable SHA-256 fingerprint for a JSON-compatible value."""

    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _object(value: object, *, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise ManifestContractError("must be an object with string keys", path=path)
    return value


def _reject_unknown(
    value: Mapping[str, object], allowed: frozenset[str], *, path: str
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ManifestContractError(
            "unknown field(s): " + ", ".join(unknown), path=path
        )


def _required(value: Mapping[str, object], field: str, *, path: str) -> object:
    if field not in value:
        raise ManifestContractError(f"missing required field {field!r}", path=path)
    return value[field]


def _integer(
    value: object,
    *,
    path: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestContractError("must be an integer", path=path)
    if value < minimum or value > maximum:
        raise ManifestContractError(
            f"must be between {minimum} and {maximum}", path=path
        )
    return value


def _boolean(value: object, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise ManifestContractError("must be a boolean", path=path)
    return value


def _string(
    value: object,
    *,
    path: str,
    minimum: int = 1,
    maximum: int = 4096,
) -> str:
    if not isinstance(value, str) or len(value) < minimum or len(value) > maximum:
        raise ManifestContractError(
            f"must be a string of {minimum}..{maximum} characters", path=path
        )
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ManifestContractError("must not contain control line breaks", path=path)
    return value


def _name(value: object, *, path: str) -> str:
    name = _string(value, path=path, maximum=64)
    if _SAFE_NAME.fullmatch(name) is None:
        raise ManifestContractError(
            "must use lowercase letters, digits, '.', '_' or '-'", path=path
        )
    return name


def _string_list(
    value: object,
    *,
    path: str,
    maximum_items: int = 512,
    allow_empty: bool = False,
    item_maximum: int = 512,
    require_unique: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ManifestContractError("must be an array", path=path)
    if (not value and not allow_empty) or len(value) > maximum_items:
        minimum = 0 if allow_empty else 1
        raise ManifestContractError(
            f"must contain {minimum}..{maximum_items} items", path=path
        )
    normalized = tuple(
        _string(item, path=f"{path}[{index}]", maximum=item_maximum)
        for index, item in enumerate(value)
    )
    if require_unique and len(set(normalized)) != len(normalized):
        raise ManifestContractError("must not contain duplicate items", path=path)
    return normalized


def normalize_repository_path(
    value: object,
    *,
    path: str = "$",
    allow_glob: bool = False,
    allow_dot: bool = False,
) -> str:
    """Validate one repository-relative POSIX path without touching the host."""

    raw = _string(value, path=path, maximum=512)
    if raw == "." and allow_dot:
        return raw
    if "\\" in raw or raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise ManifestContractError("must be a normalized relative POSIX path", path=path)
    if not allow_glob and any(character in raw for character in "*?"):
        raise ManifestContractError("must not contain glob characters", path=path)
    if allow_glob and any(character in raw for character in "{}!"):
        raise ManifestContractError(
            "supports only '*' and '?' glob characters", path=path
        )
    parts = PurePosixPath(raw).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ManifestContractError("must remain inside the repository", path=path)
    normalized = "/".join(parts)
    if normalized != raw:
        raise ManifestContractError("must already be normalized", path=path)
    if allow_glob and any("**" in part and part != "**" for part in parts):
        raise ManifestContractError(
            "recursive '**' must occupy a complete path segment", path=path
        )
    return normalized


def _verify_host_containment(
    repository_root: Path | None, relative: str, *, path: str
) -> None:
    if repository_root is None:
        return
    root = repository_root.resolve()
    candidate = (root / relative).resolve(strict=False)
    if candidate != root and root not in candidate.parents:
        raise ManifestContractError(
            "resolves outside the repository (possibly through a symlink)", path=path
        )


def resolve_contained_repository_path(
    repository_root: Path, relative_path: object
) -> Path:
    """Resolve one concrete manifest match and fail on symlink escape.

    Executors must apply this after expanding input or artifact globs and before
    opening the match.  Validation of a glob's static prefix alone cannot prove
    the destination of a dynamic symlink match.
    """

    normalized = normalize_repository_path(relative_path, path="path")
    root = repository_root.resolve()
    candidate = (root / normalized).resolve(strict=False)
    if candidate != root and root not in candidate.parents:
        raise ManifestContractError(
            "resolves outside the repository (possibly through a symlink)",
            path="path",
        )
    return candidate


def _verify_pattern_host_containment(
    repository_root: Path | None, pattern: str, *, path: str
) -> None:
    """Verify the non-glob prefix cannot escape through an existing symlink."""

    static_parts: list[str] = []
    for part in PurePosixPath(pattern).parts:
        if "*" in part or "?" in part:
            break
        static_parts.append(part)
    if static_parts:
        _verify_host_containment(
            repository_root, "/".join(static_parts), path=path
        )


def _environment(value: object, *, path: str) -> Mapping[str, str]:
    raw = _object(value, path=path)
    if len(raw) > 64:
        raise ManifestContractError("must contain at most 64 entries", path=path)
    normalized: dict[str, str] = {}
    total_bytes = 0
    for key in sorted(raw):
        if _ENVIRONMENT_NAME.fullmatch(key) is None:
            raise ManifestContractError(
                "environment name must be uppercase ASCII", path=f"{path}.{key}"
            )
        if _SECRET_ENVIRONMENT_NAME.search(key):
            raise ManifestContractError(
                "secret-like environment names are not allowed", path=f"{path}.{key}"
            )
        item = _string(raw[key], path=f"{path}.{key}", minimum=0, maximum=2048)
        total_bytes += len(key.encode("utf-8")) + len(item.encode("utf-8"))
        normalized[key] = item
    if total_bytes > 16 * 1024:
        raise ManifestContractError("literal environment exceeds 16 KiB", path=path)
    return MappingProxyType(normalized)


def _network(value: object, *, path: str) -> str:
    network = _string(value, path=path, maximum=16)
    if network not in _ALLOWED_NETWORK:
        raise ManifestContractError(
            "must be one of: none, loopback, host-loopback, external",
            path=path,
        )
    return network


def _fixture_network(value: object, *, path: str) -> str:
    """Keep fixture namespaces on their existing network contract.

    ``host-loopback`` is an attempt execution mode, not a fixture topology.
    A fixture claiming it could otherwise smuggle host-network semantics into
    an ordinary target through the reachability ranking.
    """

    network = _string(value, path=path, maximum=16)
    if network not in _ALLOWED_FIXTURE_NETWORK:
        raise ManifestContractError(
            "fixture network must be one of: none, loopback, external",
            path=path,
        )
    return network


def _argv(value: object, *, driver: str, path: str) -> tuple[str, ...]:
    argv = _string_list(
        value,
        path=path,
        maximum_items=256,
        item_maximum=4096,
        require_unique=False,
    )
    for index, item in enumerate(argv):
        if ("{" in item or "}" in item) and item not in _ALLOWED_ARG_PLACEHOLDERS:
            raise ManifestContractError(
                "contains an unsupported placeholder", path=f"{path}[{index}]"
            )
    executable = PurePosixPath(argv[0]).name.lower()
    if executable in _FORBIDDEN_EXECUTABLES:
        raise ManifestContractError(
            "shell and environment trampoline executables are forbidden",
            path=f"{path}[0]",
        )
    required_executable = {
        "pytest": "{python}",
        "node": "{node}",
        "dotnet": "{dotnet}",
    }.get(driver)
    if required_executable is not None and argv[0] != required_executable:
        raise ManifestContractError(
            f"{driver} targets must start with {required_executable!r}",
            path=f"{path}[0]",
        )
    if driver == "pytest" and tuple(argv[1:3]) != ("-m", "pytest"):
        raise ManifestContractError(
            "pytest targets must invoke '{python} -m pytest'", path=path
        )
    return argv


def _parse_defaults(value: object) -> ManifestDefaults:
    path = "$.defaults"
    raw = _object(value, path=path)
    _reject_unknown(raw, _DEFAULT_FIELDS, path=path)
    return ManifestDefaults(
        timeout_seconds=_integer(
            _required(raw, "timeout_seconds", path=path),
            path=f"{path}.timeout_seconds",
            minimum=1,
            maximum=86_400,
        ),
        network=_network(
            _required(raw, "network", path=path), path=f"{path}.network"
        ),
        environment=_environment(
            raw.get("environment", {}), path=f"{path}.environment"
        ),
    )


def _parse_intents(value: object) -> Mapping[str, IntentContract]:
    raw = _object(value, path="$.intents")
    if not raw or len(raw) > len(_ALLOWED_INTENTS):
        raise ManifestContractError("must declare at least one intent", path="$.intents")
    intents: dict[str, IntentContract] = {}
    for raw_name in sorted(raw):
        name = _name(raw_name, path=f"$.intents.{raw_name}")
        if name not in _ALLOWED_INTENTS:
            raise ManifestContractError("unsupported intent", path=f"$.intents.{name}")
        path = f"$.intents.{name}"
        definition = _object(raw[name], path=path)
        _reject_unknown(definition, _INTENT_FIELDS, path=path)
        try:
            source_mode = SourceMode(
                _string(
                    _required(definition, "source_mode", path=path),
                    path=f"{path}.source_mode",
                    maximum=16,
                )
            )
        except ValueError as error:
            raise ManifestContractError(
                "must be 'live' or 'immutable'", path=f"{path}.source_mode"
            ) from error
        if name in {"change", "checkpoint"} and source_mode is not SourceMode.LIVE:
            raise ManifestContractError(
                "change and checkpoint intents must use live source mode", path=path
            )
        if name in {"handoff", "release", "manual"} and source_mode is not SourceMode.IMMUTABLE:
            raise ManifestContractError(
                "handoff, release, and manual intents must use immutable source mode", path=path
            )
        allow_reuse = _boolean(
            definition.get("allow_reuse", False), path=f"{path}.allow_reuse"
        )
        if source_mode is SourceMode.LIVE and allow_reuse:
            raise ManifestContractError(
                "live intent results cannot be reused", path=f"{path}.allow_reuse"
            )
        if name == "release" and allow_reuse:
            raise ManifestContractError(
                "release evidence cannot be reused", path=f"{path}.allow_reuse"
            )
        intents[name] = IntentContract(
            name=name, source_mode=source_mode, allow_reuse=allow_reuse
        )
    return MappingProxyType(intents)


def _parse_fixtures(value: object) -> Mapping[str, FixtureContract]:
    raw = _object(value, path="$.fixtures")
    if len(raw) > 64:
        raise ManifestContractError("must contain at most 64 fixtures", path="$.fixtures")
    fixtures: dict[str, FixtureContract] = {}
    for raw_name in sorted(raw):
        name = _name(raw_name, path=f"$.fixtures.{raw_name}")
        path = f"$.fixtures.{name}"
        definition = _object(raw[name], path=path)
        _reject_unknown(definition, _FIXTURE_FIELDS, path=path)
        template = _string(
            _required(definition, "template", path=path),
            path=f"{path}.template",
            maximum=128,
        )
        if _TEMPLATE_NAME.fullmatch(template) is None:
            raise ManifestContractError("invalid sealed template name", path=path)
        fixtures[name] = FixtureContract(
            name=name,
            template=template,
            network=_fixture_network(
                definition.get("network", "loopback"),
                path=f"{path}.network",
            ),
        )
    return MappingProxyType(fixtures)


def _parse_credentials(value: object) -> Mapping[str, CredentialContract]:
    raw = _object(value, path="$.credentials")
    if len(raw) > 64:
        raise ManifestContractError(
            "must contain at most 64 operational credentials",
            path="$.credentials",
        )
    credentials: dict[str, CredentialContract] = {}
    for raw_name in sorted(raw):
        name = _name(raw_name, path=f"$.credentials.{raw_name}")
        path = f"$.credentials.{name}"
        definition = _object(raw[name], path=path)
        _reject_unknown(definition, _CREDENTIAL_FIELDS, path=path)
        binding = _string(
            _required(definition, "binding", path=path),
            path=f"{path}.binding",
            maximum=128,
        )
        if _TEMPLATE_NAME.fullmatch(binding) is None:
            raise ManifestContractError(
                "invalid administrator-sealed credential binding",
                path=f"{path}.binding",
            )
        credentials[name] = CredentialContract(name=name, binding=binding)
    return MappingProxyType(credentials)


def _parse_artifacts(
    value: object,
    *,
    target_path: str,
    repository_root: Path | None,
) -> tuple[ArtifactContract, ...]:
    path = f"{target_path}.artifacts"
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ManifestContractError("must be an array", path=path)
    if len(value) > 32:
        raise ManifestContractError("must contain at most 32 items", path=path)
    artifacts: list[ArtifactContract] = []
    names: set[str] = set()
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        raw = _object(item, path=item_path)
        _reject_unknown(raw, _ARTIFACT_FIELDS, path=item_path)
        name = _name(_required(raw, "name", path=item_path), path=f"{item_path}.name")
        if name in names:
            raise ManifestContractError("duplicate artifact name", path=f"{item_path}.name")
        names.add(name)
        kind = _string(
            _required(raw, "kind", path=item_path),
            path=f"{item_path}.kind",
            maximum=32,
        )
        if kind not in _ALLOWED_ARTIFACT_KINDS:
            raise ManifestContractError("unsupported artifact kind", path=f"{item_path}.kind")
        artifact_path = normalize_repository_path(
            _required(raw, "path", path=item_path),
            path=f"{item_path}.path",
            allow_glob=True,
        )
        _verify_pattern_host_containment(
            repository_root, artifact_path, path=f"{item_path}.path"
        )
        artifacts.append(
            ArtifactContract(
                name=name,
                path=artifact_path,
                kind=kind,
                required=_boolean(raw.get("required", False), path=f"{item_path}.required"),
                max_bytes=_integer(
                    raw.get("max_bytes", 16 * 1024 * 1024),
                    path=f"{item_path}.max_bytes",
                    minimum=1,
                    maximum=1024 * 1024 * 1024,
                ),
            )
        )
    return tuple(artifacts)


def _parse_shard(value: object, *, target_path: str) -> ShardPolicy:
    path = f"{target_path}.shard"
    raw = _object(value, path=path)
    _reject_unknown(raw, _SHARD_FIELDS, path=path)
    mode = _string(raw.get("mode", "none"), path=f"{path}.mode", maximum=16)
    if mode not in _ALLOWED_SHARD_MODES:
        raise ManifestContractError("unsupported shard mode", path=f"{path}.mode")
    max_shards = _integer(
        raw.get("max_shards", 1),
        path=f"{path}.max_shards",
        minimum=1,
        maximum=64,
    )
    if mode == "none" and max_shards != 1:
        raise ManifestContractError(
            "unsharded targets must have max_shards 1", path=path
        )
    return ShardPolicy(mode=mode, max_shards=max_shards)


def _parse_retry(
    value: object,
    *,
    target_path: str,
) -> RetryPolicy:
    path = f"{target_path}.retry"
    if value is None:
        raise ManifestContractError(
            "every target requires an explicit retry policy", path=path
        )
    raw = _object(value, path=path)
    _reject_unknown(raw, _RETRY_FIELDS, path=path)
    missing = sorted(_RETRY_FIELDS - set(raw))
    if missing:
        raise ManifestContractError(
            "retry policy is missing: " + ", ".join(missing), path=path
        )
    max_attempts = _integer(
        raw["max_attempts"],
        path=f"{path}.max_attempts",
        minimum=1,
        maximum=4,
    )
    events = tuple(
        _string(item, path=f"{path}.retry_on[{index}]", maximum=64)
        for index, item in enumerate(
            _string_list(
                raw["retry_on"],
                path=f"{path}.retry_on",
                allow_empty=True,
                maximum_items=1,
            )
        )
    )
    if len(set(events)) != len(events):
        raise ManifestContractError("retry events must be unique", path=f"{path}.retry_on")
    unknown = sorted(set(events) - _ALLOWED_RETRY_EVENTS)
    if unknown:
        raise ManifestContractError(
            "unsupported automatic retry event(s): " + ", ".join(unknown),
            path=f"{path}.retry_on",
        )
    if max_attempts == 1 and events:
        raise ManifestContractError(
            "max_attempts 1 requires an empty retry_on list", path=path
        )
    if max_attempts > 1 and events != ("lease_expired_before_launch",):
        raise ManifestContractError(
            "multiple attempts require lease_expired_before_launch as the sole retry event",
            path=path,
        )
    return RetryPolicy(max_attempts=max_attempts, retry_on=events)


def _parse_targets(
    value: object,
    *,
    defaults: ManifestDefaults,
    intents: Mapping[str, IntentContract],
    fixtures: Mapping[str, FixtureContract],
    credentials: Mapping[str, CredentialContract],
    repository_root: Path | None,
) -> Mapping[str, TargetContract]:
    raw = _object(value, path="$.targets")
    if not raw or len(raw) > 512:
        raise ManifestContractError("must contain 1..512 targets", path="$.targets")
    targets: dict[str, TargetContract] = {}
    for raw_name in sorted(raw):
        name = _name(raw_name, path=f"$.targets.{raw_name}")
        path = f"$.targets.{name}"
        definition = _object(raw[name], path=path)
        _reject_unknown(definition, _TARGET_FIELDS, path=path)
        driver = _string(
            _required(definition, "driver", path=path),
            path=f"{path}.driver",
            maximum=32,
        )
        if driver not in _ALLOWED_DRIVERS:
            raise ManifestContractError("unsupported target driver", path=f"{path}.driver")
        reporter = _string(
            _required(definition, "reporter", path=path),
            path=f"{path}.reporter",
            maximum=32,
        )
        if reporter not in _REPORTERS_BY_DRIVER[driver]:
            raise ManifestContractError(
                f"reporter is incompatible with {driver} driver",
                path=f"{path}.reporter",
            )
        cwd = normalize_repository_path(
            definition.get("cwd", "."), path=f"{path}.cwd", allow_dot=True
        )
        _verify_host_containment(repository_root, cwd, path=f"{path}.cwd")
        input_values = _string_list(
            _required(definition, "inputs", path=path), path=f"{path}.inputs"
        )
        inputs = tuple(
            normalize_repository_path(
                item, path=f"{path}.inputs[{index}]", allow_glob=True
            )
            for index, item in enumerate(input_values)
        )
        for index, input_pattern in enumerate(inputs):
            _verify_pattern_host_containment(
                repository_root,
                input_pattern,
                path=f"{path}.inputs[{index}]",
            )
        dependencies = tuple(
            _name(item, path=f"{path}.depends_on[{index}]")
            for index, item in enumerate(
                _string_list(
                    definition.get("depends_on", []),
                    path=f"{path}.depends_on",
                    allow_empty=True,
                )
            )
        )
        target_intents = tuple(
            _name(item, path=f"{path}.intents[{index}]")
            for index, item in enumerate(
                _string_list(
                    _required(definition, "intents", path=path), path=f"{path}.intents"
                )
            )
        )
        unknown_intents = sorted(set(target_intents) - set(intents))
        if unknown_intents:
            raise ManifestContractError(
                "unknown intent(s): " + ", ".join(unknown_intents),
                path=f"{path}.intents",
            )
        target_fixtures = tuple(
            _name(item, path=f"{path}.fixtures[{index}]")
            for index, item in enumerate(
                _string_list(
                    definition.get("fixtures", []),
                    path=f"{path}.fixtures",
                    allow_empty=True,
                )
            )
        )
        unknown_fixtures = sorted(set(target_fixtures) - set(fixtures))
        if unknown_fixtures:
            raise ManifestContractError(
                "unknown fixture(s): " + ", ".join(unknown_fixtures),
                path=f"{path}.fixtures",
            )
        target_credentials = tuple(
            _name(item, path=f"{path}.credentials[{index}]")
            for index, item in enumerate(
                _string_list(
                    definition.get("credentials", []),
                    path=f"{path}.credentials",
                    allow_empty=True,
                )
            )
        )
        unknown_credentials = sorted(set(target_credentials) - set(credentials))
        if unknown_credentials:
            raise ManifestContractError(
                "unknown operational credential(s): "
                + ", ".join(unknown_credentials),
                path=f"{path}.credentials",
            )
        if target_credentials and target_intents != ("manual",):
            raise ManifestContractError(
                "operational credentials require a manual-only target",
                path=f"{path}.intents",
            )
        network = _network(
            definition.get("network", defaults.network), path=f"{path}.network"
        )
        if network == "host-loopback":
            if target_intents != ("manual",):
                raise ManifestContractError(
                    "host-loopback requires a manual-only target",
                    path=f"{path}.intents",
                )
            if target_fixtures:
                raise ManifestContractError(
                    "host-loopback targets cannot declare fixtures",
                    path=f"{path}.fixtures",
                )
        for fixture_name in target_fixtures:
            fixture = fixtures[fixture_name]
            if _NETWORK_RANK[network] < _NETWORK_RANK[fixture.network]:
                raise ManifestContractError(
                    f"network policy cannot reach fixture {fixture_name!r}",
                    path=f"{path}.network",
                )
        environment = dict(defaults.environment)
        environment.update(
            _environment(
                definition.get("environment", {}), path=f"{path}.environment"
            )
        )
        targets[name] = TargetContract(
            name=name,
            driver=driver,
            reporter=reporter,
            argv=_argv(
                _required(definition, "argv", path=path),
                driver=driver,
                path=f"{path}.argv",
            ),
            cwd=cwd,
            inputs=inputs,
            depends_on=dependencies,
            intents=target_intents,
            timeout_seconds=_integer(
                definition.get("timeout_seconds", defaults.timeout_seconds),
                path=f"{path}.timeout_seconds",
                minimum=1,
                maximum=86_400,
            ),
            resources=NON_AUTHORITATIVE_RESOURCES,
            network=network,
            exclusive_resources=tuple(
                _name(item, path=f"{path}.exclusive_resources[{index}]")
                for index, item in enumerate(
                    _string_list(
                        definition.get("exclusive_resources", []),
                        path=f"{path}.exclusive_resources",
                        allow_empty=True,
                        maximum_items=32,
                    )
                )
            ),
            fixtures=target_fixtures,
            credentials=target_credentials,
            shard=_parse_shard(definition.get("shard", {}), target_path=path),
            retry=_parse_retry(
                definition.get("retry"),
                target_path=path,
            ),
            artifacts=_parse_artifacts(
                definition.get("artifacts", []),
                target_path=path,
                repository_root=repository_root,
            ),
            environment=MappingProxyType(dict(sorted(environment.items()))),
        )
    target_names = set(targets)
    for target in targets.values():
        unknown = sorted(set(target.depends_on) - target_names)
        if unknown:
            raise ManifestContractError(
                "unknown dependency target(s): " + ", ".join(unknown),
                path=f"$.targets.{target.name}.depends_on",
            )
        if target.name in target.depends_on:
            raise ManifestContractError(
                "target cannot depend on itself",
                path=f"$.targets.{target.name}.depends_on",
            )
    _reject_dependency_cycles(targets)
    for intent_name in intents:
        if not any(intent_name in target.intents for target in targets.values()):
            raise ManifestContractError(
                "intent must be required by at least one target",
                path=f"$.intents.{intent_name}",
            )
    return MappingProxyType(targets)


def _reject_dependency_cycles(targets: Mapping[str, TargetContract]) -> None:
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            start = visiting.index(name)
            cycle = visiting[start:] + [name]
            raise ManifestContractError(
                "dependency cycle: " + " -> ".join(cycle),
                path=f"$.targets.{name}.depends_on",
            )
        visiting.append(name)
        for dependency in targets[name].depends_on:
            visit(dependency)
        visiting.pop()
        visited.add(name)

    for target_name in sorted(targets):
        visit(target_name)


def _parse_evidence_policies(
    value: object,
    *,
    intents: Mapping[str, IntentContract],
    targets: Mapping[str, TargetContract],
) -> Mapping[str, EvidencePolicy]:
    raw = _object(value, path="$.evidence_policies")
    if len(raw) > 64:
        raise ManifestContractError(
            "must contain at most 64 evidence policies", path="$.evidence_policies"
        )
    policies: dict[str, EvidencePolicy] = {}
    for raw_name in sorted(raw):
        name = _name(raw_name, path=f"$.evidence_policies.{raw_name}")
        path = f"$.evidence_policies.{name}"
        definition = _object(raw[name], path=path)
        _reject_unknown(definition, _EVIDENCE_FIELDS, path=path)
        intent = _name(
            _required(definition, "intent", path=path), path=f"{path}.intent"
        )
        if intent not in intents:
            raise ManifestContractError("unknown intent", path=f"{path}.intent")
        if intents[intent].source_mode is not SourceMode.IMMUTABLE:
            raise ManifestContractError(
                "evidence policies require an immutable intent",
                path=f"{path}.intent",
            )
        required_targets = tuple(
            sorted(
                _name(item, path=f"{path}.required_targets[{index}]")
                for index, item in enumerate(
                    _string_list(
                        _required(definition, "required_targets", path=path),
                        path=f"{path}.required_targets",
                    )
                )
            )
        )
        unknown_targets = sorted(set(required_targets) - set(targets))
        if unknown_targets:
            raise ManifestContractError(
                "unknown target(s): " + ", ".join(unknown_targets),
                path=f"{path}.required_targets",
            )
        outside_intent = sorted(
            target_name
            for target_name in required_targets
            if intent not in targets[target_name].intents
        )
        if outside_intent:
            raise ManifestContractError(
                "target(s) do not declare this intent: " + ", ".join(outside_intent),
                path=f"{path}.required_targets",
            )
        allow_reuse = _boolean(
            definition.get("allow_reuse", False), path=f"{path}.allow_reuse"
        )
        if allow_reuse and not intents[intent].allow_reuse:
            raise ManifestContractError(
                "policy cannot broaden the intent reuse policy",
                path=f"{path}.allow_reuse",
            )
        policies[name] = EvidencePolicy(
            name=name,
            intent=intent,
            required_targets=required_targets,
            max_age_seconds=_integer(
                _required(definition, "max_age_seconds", path=path),
                path=f"{path}.max_age_seconds",
                minimum=1,
                maximum=31_536_000,
            ),
            allow_reuse=allow_reuse,
        )
    return MappingProxyType(policies)


def manifest_to_document(manifest: TestManifest) -> dict[str, object]:
    """Return the canonical, privilege-safe normalized manifest document."""

    return {
        "schema_version": manifest.schema_version,
        "defaults": {
            "timeout_seconds": manifest.defaults.timeout_seconds,
            "network": manifest.defaults.network,
            "environment": dict(manifest.defaults.environment),
        },
        "global_inputs": list(manifest.global_inputs),
        "intents": {
            name: {
                "source_mode": intent.source_mode.value,
                "allow_reuse": intent.allow_reuse,
            }
            for name, intent in manifest.intents.items()
        },
        "fixtures": {
            name: {"template": fixture.template, "network": fixture.network}
            for name, fixture in manifest.fixtures.items()
        },
        "credentials": {
            name: {"binding": credential.binding}
            for name, credential in manifest.credentials.items()
        },
        "targets": {
            name: {
                "driver": target.driver,
                "reporter": target.reporter,
                "argv": list(target.argv),
                "cwd": target.cwd,
                "inputs": list(target.inputs),
                "depends_on": list(target.depends_on),
                "intents": list(target.intents),
                "timeout_seconds": target.timeout_seconds,
                "network": target.network,
                "exclusive_resources": list(target.exclusive_resources),
                "fixtures": list(target.fixtures),
                "credentials": list(target.credentials),
                "shard": {
                    "mode": target.shard.mode,
                    "max_shards": target.shard.max_shards,
                },
                "retry": {
                    "max_attempts": target.retry.max_attempts,
                    "retry_on": list(target.retry.retry_on),
                },
                "artifacts": [
                    {
                        "name": artifact.name,
                        "path": artifact.path,
                        "kind": artifact.kind,
                        "required": artifact.required,
                        "max_bytes": artifact.max_bytes,
                    }
                    for artifact in target.artifacts
                ],
                "environment": dict(target.environment),
            }
            for name, target in manifest.targets.items()
        },
        "evidence_policies": {
            name: {
                "intent": policy.intent,
                "required_targets": list(policy.required_targets),
                "max_age_seconds": policy.max_age_seconds,
                "allow_reuse": policy.allow_reuse,
            }
            for name, policy in manifest.evidence_policies.items()
        },
    }


def parse_test_manifest(
    document: object, *, repository_root: Path | None = None
) -> TestManifest:
    """Validate raw JSON and return one normalized immutable contract."""

    raw = _object(document, path="$")
    _reject_unknown(raw, _TOP_LEVEL_FIELDS, path="$")
    schema_version_value = _required(raw, "schema_version", path="$")
    if isinstance(schema_version_value, bool) or not isinstance(
        schema_version_value, int
    ):
        raise ManifestContractError("must be an integer", path="$.schema_version")
    if schema_version_value != MANIFEST_SCHEMA_VERSION:
        raise ManifestContractError(
            f"only manifest schema {MANIFEST_SCHEMA_VERSION} is supported",
            path="$.schema_version",
        )
    schema_version = MANIFEST_SCHEMA_VERSION
    defaults = _parse_defaults(_required(raw, "defaults", path="$"))
    intents = _parse_intents(_required(raw, "intents", path="$"))
    fixtures = _parse_fixtures(_required(raw, "fixtures", path="$"))
    credentials = _parse_credentials(raw.get("credentials", {}))
    global_values = _string_list(
        _required(raw, "global_inputs", path="$"), path="$.global_inputs"
    )
    global_inputs = tuple(
        normalize_repository_path(
            item, path=f"$.global_inputs[{index}]", allow_glob=True
        )
        for index, item in enumerate(global_values)
    )
    for index, input_pattern in enumerate(global_inputs):
        _verify_pattern_host_containment(
            repository_root,
            input_pattern,
            path=f"$.global_inputs[{index}]",
        )
    if str(MANIFEST_RELATIVE_PATH) not in global_inputs:
        raise ManifestContractError(
            f"must include {str(MANIFEST_RELATIVE_PATH)!r}", path="$.global_inputs"
        )
    targets = _parse_targets(
        _required(raw, "targets", path="$"),
        defaults=defaults,
        intents=intents,
        fixtures=fixtures,
        credentials=credentials,
        repository_root=repository_root,
    )
    evidence_policies = _parse_evidence_policies(
        _required(raw, "evidence_policies", path="$"),
        intents=intents,
        targets=targets,
    )
    provisional = TestManifest(
        schema_version=schema_version,
        defaults=defaults,
        global_inputs=global_inputs,
        targets=targets,
        intents=intents,
        fixtures=fixtures,
        credentials=credentials,
        evidence_policies=evidence_policies,
        fingerprint="",
    )
    fingerprint = deterministic_fingerprint(manifest_to_document(provisional))
    return TestManifest(
        schema_version=schema_version,
        defaults=defaults,
        global_inputs=global_inputs,
        targets=targets,
        intents=intents,
        fixtures=fixtures,
        credentials=credentials,
        evidence_policies=evidence_policies,
        fingerprint=fingerprint,
    )


def load_test_manifest(repository_root: Path) -> TestManifest:
    """Load the fixed manifest path with a bounded read and validate it."""

    root = repository_root.resolve()
    path = root / Path(*MANIFEST_RELATIVE_PATH.parts)
    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(str(root), directory_flags)
        descriptors.append(root_fd)
        root_identity = os.fstat(root_fd)
        codex_fd = os.open(".codex", directory_flags, dir_fd=root_fd)
        descriptors.append(codex_fd)
        codex_identity = os.fstat(codex_fd)
        manifest_fd = os.open(
            "tests.json",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=codex_fd,
        )
        descriptors.append(manifest_fd)
        before = os.fstat(manifest_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ManifestContractError("manifest must be one regular file", path="$")
        if before.st_size > MAX_MANIFEST_BYTES:
            raise ManifestContractError(
                f"manifest exceeds {MAX_MANIFEST_BYTES} bytes", path="$"
            )
        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(manifest_fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_MANIFEST_BYTES:
            raise ManifestContractError(
                f"manifest exceeds {MAX_MANIFEST_BYTES} bytes", path="$"
            )
        after = os.fstat(manifest_fd)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(payload) != before.st_size
            or any(getattr(before, field) != getattr(after, field) for field in identity_fields)
        ):
            raise ManifestContractError("manifest changed while it was read", path="$")

        # Re-resolve every held pathname without following links.  Reading from
        # descriptors prevents substitution from changing the bytes already
        # consumed; these final identity checks additionally reject a root,
        # .codex directory, or manifest rename during the read.
        root_after = os.stat(str(root), follow_symlinks=False)
        codex_after = os.stat(".codex", dir_fd=root_fd, follow_symlinks=False)
        manifest_after = os.stat(
            "tests.json", dir_fd=codex_fd, follow_symlinks=False
        )
        for opened, named, label in (
            (root_identity, root_after, "repository root"),
            (codex_identity, codex_after, ".codex directory"),
            (after, manifest_after, "manifest"),
        ):
            if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                raise ManifestContractError(f"{label} changed while manifest was read", path="$")
        document = json.loads(payload.decode("utf-8"))
    except ManifestContractError:
        raise
    except FileNotFoundError as error:
        raise ManifestContractError(f"manifest is missing: {path}") from error
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ManifestContractError(
                "manifest path contains a symlink or non-directory component",
                path="$",
            ) from error
        raise ManifestContractError(f"manifest is unreadable: {error}") from error
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ManifestContractError(f"manifest is unreadable: {error}") from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
    return parse_test_manifest(document, repository_root=root)


def is_sha256(value: str) -> bool:
    """Return whether *value* is a lowercase SHA-256 hexadecimal digest."""

    return _HEX_SHA256.fullmatch(value) is not None


def repository_glob_matches(pattern: str, relative_path: str) -> bool:
    """Match a validated repository path using slash-aware ``*``/``**`` globs."""

    normalized_pattern = normalize_repository_path(
        pattern, path="pattern", allow_glob=True
    )
    normalized_path = normalize_repository_path(relative_path, path="path")
    expression: list[str] = ["^"]
    index = 0
    while index < len(normalized_pattern):
        character = normalized_pattern[index]
        if character == "*":
            if index + 1 < len(normalized_pattern) and normalized_pattern[index + 1] == "*":
                index += 2
                if index < len(normalized_pattern) and normalized_pattern[index] == "/":
                    expression.append("(?:.*/)?")
                    index += 1
                else:
                    expression.append(".*")
                continue
            expression.append("[^/]*")
        elif character == "?":
            expression.append("[^/]")
        else:
            expression.append(re.escape(character))
        index += 1
    expression.append("$")
    return re.fullmatch("".join(expression), normalized_path) is not None


def safe_history_shard_ceiling(target: TargetContract) -> int:
    """Return the maximum shard count backed by a trusted driver adapter.

    A manifest shard policy is only a ceiling.  Automation and .NET commands
    are not duplicated because the harness cannot prove that their argv selects
    distinct work.  Pytest uses the Coordinator's deterministic node-id
    partitioner; Node uses its native ``--test-shard`` selector.
    """

    if target.shard.mode != "history" or target.shard.max_shards <= 1:
        return 1
    if target.driver == "pytest":
        return target.shard.max_shards
    if target.driver == "node" and any(
        argument == "--test" or argument.startswith("--test=")
        for argument in target.argv[1:]
    ):
        return target.shard.max_shards
    return 1


__all__ = [
    "ArtifactContract",
    "EvidencePolicy",
    "FixtureContract",
    "IntentContract",
    "MANIFEST_RELATIVE_PATH",
    "MANIFEST_SCHEMA_VERSION",
    "ManifestContractError",
    "ManifestDefaults",
    "ResourceLimits",
    "RetryPolicy",
    "ShardPolicy",
    "SourceMode",
    "TargetContract",
    "TestManifest",
    "deterministic_fingerprint",
    "is_sha256",
    "load_test_manifest",
    "evidence_policy_document",
    "evidence_policy_fingerprint",
    "manifest_to_document",
    "normalize_repository_path",
    "parse_test_manifest",
    "repository_glob_matches",
    "resolve_contained_repository_path",
    "safe_history_shard_ceiling",
]
