"""Fail-closed contract for Compose files executed by the privileged broker."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import stat
from typing import Any

try:
    import yaml
    from yaml.constructor import ConstructorError
    from yaml.events import AliasEvent
    from yaml.nodes import MappingNode
    from yaml.resolver import BaseResolver
except ImportError:  # pragma: no cover - exercised by installation validation
    yaml = None
    ConstructorError = RuntimeError  # type: ignore[assignment,misc]
    AliasEvent = object  # type: ignore[assignment,misc]
    MappingNode = object  # type: ignore[assignment,misc]
    BaseResolver = None  # type: ignore[assignment]


# These features cause Compose to read additional files or invoke providers
# whose bytes are not represented by the sealed top-level configuration and
# explicit CLI environment snapshots.  They remain unsupported until the
# broker can provision, fingerprint, and seal their complete dependency graph.
_TOP_LEVEL_UNSEALED_KEYS = frozenset({"include", "configs", "secrets"})
_SERVICE_UNSEALED_KEYS = frozenset(
    {
        "extends",
        "build",
        "env_file",
        "label_file",
        "configs",
        "secrets",
        "develop",
        "credential_spec",
        "provider",
    }
)

# The broker executes the merged model as root.  Service-level keys are
# therefore a positive contract: a future Compose feature must be reviewed
# here before a newer plugin can make it executable through the broker.
_EFFECTIVE_TOP_LEVEL_KEYS = frozenset(
    {"name", "networks", "services", "version", "volumes"}
)
_EFFECTIVE_SERVICE_KEYS = frozenset(
    {
        "annotations",
        "attach",
        "blkio_config",
        "cap_add",
        "cap_drop",
        "cgroup",
        "cgroup_parent",
        "command",
        "container_name",
        "cpu_count",
        "cpu_percent",
        "cpu_period",
        "cpu_quota",
        "cpu_rt_period",
        "cpu_rt_runtime",
        "cpu_shares",
        "cpus",
        "cpuset",
        "depends_on",
        "deploy",
        "device_cgroup_rules",
        "devices",
        "dns",
        "dns_opt",
        "dns_search",
        "domainname",
        "entrypoint",
        "environment",
        "expose",
        "extra_hosts",
        "gpus",
        "group_add",
        "healthcheck",
        "hostname",
        "image",
        "init",
        "ipc",
        "isolation",
        "labels",
        "links",
        "logging",
        "mac_address",
        "mem_limit",
        "mem_reservation",
        "mem_swappiness",
        "memswap_limit",
        "network_mode",
        "networks",
        "oom_kill_disable",
        "oom_score_adj",
        "pids_limit",
        "pid",
        "platform",
        "ports",
        "privileged",
        "profiles",
        "pull_policy",
        "read_only",
        "restart",
        "runtime",
        "scale",
        "security_opt",
        "shm_size",
        "stdin_open",
        "stop_grace_period",
        "stop_signal",
        "storage_opt",
        "sysctls",
        "tmpfs",
        "tty",
        "ulimits",
        "use_api_socket",
        "user",
        "userns_mode",
        "uts",
        "volumes",
        "volumes_from",
        "working_dir",
    }
)
_EFFECTIVE_DEPLOY_KEYS = frozenset(
    {
        "endpoint_mode",
        "labels",
        "mode",
        "placement",
        "replicas",
        "resources",
        "restart_policy",
        "rollback_config",
        "update_config",
    }
)
_EFFECTIVE_RESOURCE_KEYS = frozenset({"limits", "reservations"})
_EFFECTIVE_LIMIT_KEYS = frozenset({"cpus", "memory", "pids"})
_EFFECTIVE_RESERVATION_KEYS = frozenset(
    {"cpus", "devices", "generic_resources", "memory"}
)
_EFFECTIVE_DEVICE_RESERVATION_KEYS = frozenset(
    {"capabilities", "count", "device_ids", "driver", "options"}
)
_EFFECTIVE_VOLUME_KEYS = frozenset(
    {"driver", "driver_opts", "external", "labels", "name"}
)
_EFFECTIVE_NETWORK_KEYS = frozenset(
    {
        "attachable",
        "driver",
        "driver_opts",
        "enable_ipv4",
        "enable_ipv6",
        "external",
        "internal",
        "ipam",
        "labels",
        "name",
    }
)
COMPOSE_FIXED_CONTROL_ENV = {
    "COMPOSE_DISABLE_ENV_FILE": "1",
    "COMPOSE_REMOVE_ORPHANS": "0",
    "COMPOSE_PARALLEL_LIMIT": "4",
    "COMPOSE_ANSI": "never",
    "COMPOSE_PROGRESS": "plain",
    "COMPOSE_STATUS_STDOUT": "0",
    "COMPOSE_MENU": "0",
}
DOCKER_FORWARD_ENV_NAMES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "DOCKER_API_VERSION",
)


@dataclass(frozen=True)
class ComposeDirectoryIdentity:
    """Stable filesystem identity for a Compose repository directory."""

    device: int
    inode: int


@dataclass(frozen=True)
class EffectiveComposeEvidence:
    """Secret-free evidence derived from Docker Compose's merged model."""

    model_sha256: str
    services: tuple[str, ...]
    profiles: tuple[str, ...]
    host_access_risks: tuple[str, ...]
    service_replicas: tuple[tuple[str, int], ...]
    replica_budget: int


def bounded_compose_environment(docker_executable: str) -> dict[str, str]:
    """Return the shared broker/preflight Docker Compose environment."""

    try:
        service_home = str(Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve())
    except (KeyError, OSError, RuntimeError):
        service_home = "/"
    command_paths = tuple(
        dict.fromkeys(
            (
                str(Path(docker_executable).parent),
                "/usr/local/bin",
                "/usr/bin",
                "/bin",
                "/opt/homebrew/bin",
            )
        )
    )
    environment = {
        "PATH": ":".join(command_paths),
        "HOME": service_home,
        **COMPOSE_FIXED_CONTROL_ENV,
    }
    for name in DOCKER_FORWARD_ENV_NAMES:
        value = os.environ.get(name)
        if value is not None and value and "\x00" not in value:
            environment[name] = value
    if "DOCKER_CONFIG" not in environment:
        environment["DOCKER_CONFIG"] = str(Path(service_home) / ".docker")
    return environment


def compose_relative_parts(
    path: str,
    *,
    canonical_root: str,
    field: str,
) -> tuple[str, ...]:
    """Return one normalized lexical path beneath an exact canonical root."""

    if not isinstance(path, str) or not isinstance(canonical_root, str):
        raise TypeError(f"{field} path must be text")
    if (
        not path
        or not canonical_root
        or "\x00" in path
        or "\x00" in canonical_root
        or not Path(path).is_absolute()
        or not Path(canonical_root).is_absolute()
        or os.path.abspath(path) != path
        or os.path.normpath(path) != path
        or os.path.abspath(canonical_root) != canonical_root
        or os.path.normpath(canonical_root) != canonical_root
    ):
        raise ValueError(f"{field} path is not canonical")
    try:
        relative = Path(path).relative_to(Path(canonical_root))
    except ValueError as exc:
        raise ValueError(f"{field} escaped its persisted repository") from exc
    parts = tuple(relative.parts)
    if any(part in {"", ".", ".."} or "/" in part for part in parts):
        raise ValueError(f"{field} path is invalid")
    return parts


def _anchored_directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if (
        any(not hasattr(os, name) for name in required)
        or os.open not in os.supports_dir_fd
    ):
        raise RuntimeError("component-anchored Compose path validation is unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def open_anchored_compose_root(path: str) -> int:
    """Open an absolute directory without following any pathname component."""

    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or not Path(path).is_absolute()
        or os.path.abspath(path) != path
        or os.path.normpath(path) != path
    ):
        raise ValueError("Compose repository root is not canonical")
    flags = _anchored_directory_flags()
    descriptor = os.open("/", flags)
    try:
        for component in Path(path).parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_compose_directory_beneath(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> int:
    """Open a descendant directory from a held repository descriptor."""

    flags = _anchored_directory_flags()
    descriptor = os.dup(root_descriptor)
    os.set_inheritable(descriptor, False)
    try:
        for component in relative_parts:
            if component in {"", ".", ".."} or "/" in component:
                raise ValueError("Compose descendant path is invalid")
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def compose_directory_identity(descriptor: int) -> ComposeDirectoryIdentity:
    """Return the immutable identity of one already-opened directory."""

    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Compose directory descriptor is not a directory")
    return ComposeDirectoryIdentity(
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
    )


def _open_compose_file_beneath(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
) -> int:
    if not relative_parts:
        raise ValueError("Compose file path must name a repository descendant")
    parent = open_compose_directory_beneath(root_descriptor, relative_parts[:-1])
    try:
        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOCTTY", 0)
        )
        return os.open(relative_parts[-1], flags, dir_fd=parent)
    finally:
        os.close(parent)


def read_anchored_compose_file(
    root_descriptor: int,
    relative_parts: tuple[str, ...],
    *,
    maximum_bytes: int,
    require_private: bool = False,
    allowed_owner_uids: frozenset[int] | None = None,
) -> tuple[dict[str, int | str], bytes]:
    """Read and re-identify one bounded regular file beneath a held root."""

    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("Compose file size limit must be positive")
    descriptor = _open_compose_file_beneath(root_descriptor, relative_parts)
    try:
        opened = os.fstat(descriptor)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("Compose input must be a regular file")
        if require_private and stat.S_IMODE(opened.st_mode) & 0o077:
            raise ValueError("Compose environment file grants group or other access")
        if (
            allowed_owner_uids is not None
            and int(opened.st_uid) not in allowed_owner_uids
        ):
            raise ValueError("Compose environment file has an untrusted owner")
        if opened.st_size > maximum_bytes:
            raise ValueError("Compose input exceeds its bounded size limit")
        digest = hashlib.sha256()
        size = 0
        chunks: list[bytes] = []
        while size <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - size),
            )
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            chunks.append(chunk)
        if size > maximum_bytes:
            raise ValueError("Compose input exceeds its bounded size limit")
        after = os.fstat(descriptor)
        material_before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        material_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if material_before != material_after:
            raise RuntimeError("Compose input changed while it was being read")
        replacement = _open_compose_file_beneath(root_descriptor, relative_parts)
        try:
            replacement_metadata = os.fstat(replacement)
            if (
                int(replacement_metadata.st_dev),
                int(replacement_metadata.st_ino),
            ) != identity:
                raise RuntimeError("Compose input path changed while it was being read")
        finally:
            os.close(replacement)
        return (
            {"content_sha256": digest.hexdigest(), "byte_size": size},
            b"".join(chunks),
        )
    finally:
        os.close(descriptor)


if yaml is not None:

    class _StrictComposeLoader(yaml.SafeLoader):
        """Safe YAML loader that refuses aliases and duplicate mapping keys."""

        def __init__(self, stream: Any) -> None:
            super().__init__(stream)
            self._compose_depth = 0
            self._compose_node_count = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(AliasEvent):
                event = self.peek_event()
                raise ConstructorError(
                    None,
                    None,
                    "Compose broker input must not contain YAML aliases",
                    event.start_mark,
                )
            self._compose_node_count += 1
            self._compose_depth += 1
            if self._compose_node_count > 100_000 or self._compose_depth > 128:
                raise ConstructorError(
                    None,
                    None,
                    "Compose YAML nesting or node count exceeds the safe limit",
                    self.peek_event().start_mark,
                )
            try:
                return super().compose_node(parent, index)
            finally:
                self._compose_depth -= 1

    def _construct_unique_mapping(
        loader: _StrictComposeLoader,
        node: Any,
        deep: bool = False,
    ) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                "expected a mapping node",
                getattr(node, "start_mark", None),
            )
        loader.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    _StrictComposeLoader.add_constructor(
        BaseResolver.DEFAULT_MAPPING_TAG,
        _construct_unique_mapping,
    )


def _parse_compose_model(text: str) -> Mapping[str, Any]:
    class _DuplicateJSONObjectKey(ValueError):
        """Internal sentinel whose message never includes configuration text."""

    class _NonFiniteJSONConstant(ValueError):
        """Internal sentinel for JSON constants outside the interoperable model."""

    def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJSONObjectKey
            result[key] = value
        return result

    def reject_json_constant(_value: str) -> Any:
        raise _NonFiniteJSONConstant

    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        depth = 0
        nodes = 0
        quoted = False
        escaped = False
        for character in stripped:
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
                continue
            if character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                nodes += 1
            elif character in "]}":
                depth -= 1
            elif character in ",:":
                nodes += 1
            if depth > 128 or nodes > 100_000:
                raise ValueError(
                    "Compose JSON nesting or node count exceeds the safe limit"
                )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except _DuplicateJSONObjectKey as exc:
        raise ValueError("Compose JSON contains a duplicate mapping key") from exc
    except _NonFiniteJSONConstant as exc:
        raise ValueError("Compose JSON contains a non-finite numeric constant") from exc
    except RecursionError as exc:
        raise ValueError("Compose JSON nesting exceeds the safe limit") from exc
    except json.JSONDecodeError:
        if yaml is None:
            raise RuntimeError(
                "YAML Compose validation requires the PyYAML safe-loader dependency"
            )
        try:
            parsed = yaml.load(text, Loader=_StrictComposeLoader)
        except (yaml.YAMLError, RecursionError) as exc:
            raise ValueError("Compose file is not strict safe YAML") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError("Compose file root must be a mapping")
    return parsed


def _require_sealed_model(
    value: Any,
    *,
    path: tuple[str, ...] = (),
    depth: int = 0,
    node_count: list[int] | None = None,
) -> None:
    if node_count is None:
        node_count = [0]
    node_count[0] += 1
    if depth > 128 or node_count[0] > 100_000:
        raise ValueError("Compose model nesting or node count exceeds the safe limit")
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("Compose mapping keys must be strings")
            forbidden = (not path and raw_key in _TOP_LEVEL_UNSEALED_KEYS) or (
                len(path) == 2
                and path[0] == "services"
                and raw_key in _SERVICE_UNSEALED_KEYS
            )
            if forbidden:
                raise ValueError(
                    "Compose broker input uses unsupported transitive key "
                    f"{raw_key!r}; provision a self-contained Compose model"
                )
            _require_sealed_model(
                child,
                path=(*path, raw_key),
                depth=depth + 1,
                node_count=node_count,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _require_sealed_model(
                child,
                path=path,
                depth=depth + 1,
                node_count=node_count,
            )
        return
    if isinstance(value, (bytes, bytearray)) or (
        isinstance(value, float) and not math.isfinite(value)
    ):
        raise ValueError("Compose model contains an unsupported scalar value")
    if type(value) not in {type(None), bool, int, float, str}:
        raise ValueError("Compose model contains an unsupported scalar value")


def require_sealable_compose_payload(payload: bytes) -> None:
    """Reject parsed Compose models with unresolved transitive inputs."""

    if not isinstance(payload, bytes):
        raise TypeError("Compose payload must be bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Compose file must be valid UTF-8") from exc
    if "\x00" in text:
        raise ValueError("Compose file must not contain NUL bytes")
    _require_sealed_model(_parse_compose_model(text))


def _require_effective_keys(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    *,
    field: str,
) -> None:
    unknown = sorted(str(key) for key in value if key not in allowed)
    if unknown:
        raise ValueError(
            f"effective Compose {field} contains unsupported keys: "
            + ", ".join(unknown)
        )


def _require_effective_mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"effective Compose {field} must be a mapping")
    return value


def _classify_namespace_reference(
    value: Any,
    *,
    services: Mapping[str, Any],
    risks: set[str],
    field: str,
) -> None:
    if value in (None, ""):
        return
    if not isinstance(value, str):
        raise ValueError(f"effective Compose {field} reference is invalid")
    normalized = value.lower()
    if normalized == "host" or normalized.startswith("host:"):
        risks.add("host_namespace")
        return
    if normalized.startswith("container:"):
        risks.add("external_container_reference")
        return
    if normalized.startswith("service:"):
        target = value.split(":", 1)[1]
        if target not in services:
            raise ValueError(
                "effective Compose service namespace reference escapes the declared scope"
            )


def _classify_volumes_from(
    value: Any,
    *,
    services: Mapping[str, Any],
    risks: set[str],
) -> None:
    if value in (None, (), []):
        return
    if isinstance(value, str):
        entries: Sequence[Any] = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        entries = value
    else:
        raise ValueError("effective Compose volumes_from scope is invalid")
    for entry in entries:
        if not isinstance(entry, str) or not entry:
            raise ValueError("effective Compose volumes_from reference is invalid")
        reference = entry.rsplit(":", 1)[0] if entry.endswith((":ro", ":rw")) else entry
        if reference.startswith("container:"):
            risks.add("external_container_reference")
            continue
        if reference.startswith("service:"):
            reference = reference.split(":", 1)[1]
        if reference not in services:
            raise ValueError(
                "effective Compose volumes_from reference escapes the declared scope"
            )


def _classify_deploy(
    value: Any,
    *,
    risks: set[str],
) -> Mapping[str, Any] | None:
    if value is None:
        return None
    deploy = _require_effective_mapping(value, field="deploy")
    _require_effective_keys(deploy, _EFFECTIVE_DEPLOY_KEYS, field="deploy")
    resources_value = deploy.get("resources")
    if resources_value is None:
        return deploy
    resources = _require_effective_mapping(resources_value, field="deploy resources")
    _require_effective_keys(
        resources, _EFFECTIVE_RESOURCE_KEYS, field="deploy resources"
    )
    limits_value = resources.get("limits")
    if limits_value is not None:
        limits = _require_effective_mapping(
            limits_value, field="deploy resource limits"
        )
        _require_effective_keys(
            limits, _EFFECTIVE_LIMIT_KEYS, field="deploy resource limits"
        )
    reservations_value = resources.get("reservations")
    if reservations_value is None:
        return deploy
    reservations = _require_effective_mapping(
        reservations_value, field="deploy resource reservations"
    )
    _require_effective_keys(
        reservations,
        _EFFECTIVE_RESERVATION_KEYS,
        field="deploy resource reservations",
    )
    devices = reservations.get("devices") or ()
    if not isinstance(devices, Sequence) or isinstance(
        devices, (str, bytes, bytearray)
    ):
        raise ValueError("effective Compose device reservations are invalid")
    for raw_device in devices:
        device = _require_effective_mapping(
            raw_device, field="deploy device reservation"
        )
        _require_effective_keys(
            device,
            _EFFECTIVE_DEVICE_RESERVATION_KEYS,
            field="deploy device reservation",
        )
        risks.add("host_devices")
        capabilities = device.get("capabilities") or ()
        if (
            isinstance(capabilities, Sequence)
            and not isinstance(capabilities, (str, bytes, bytearray))
            and any(
                str(capability).lower() == "gpu"
                for group in capabilities
                for capability in (
                    group
                    if isinstance(group, Sequence)
                    and not isinstance(group, (str, bytes, bytearray))
                    else (group,)
                )
            )
        ):
            risks.add("gpu_access")
    return deploy


def require_effective_compose_model(
    payload: bytes,
    *,
    declared_services: Sequence[str],
    declared_profiles: Sequence[str],
    project_name: str,
    host_access_approved: bool,
) -> EffectiveComposeEvidence:
    """Validate the exact merged JSON model emitted by ``compose config``.

    The full rendered payload can contain interpolated secrets, so callers
    persist only this digest and bounded classifications.  Administrator
    approval is required for host-equivalent capabilities; resource fan-out
    remains bounded even when such access is approved.
    """

    if not isinstance(payload, bytes):
        raise TypeError("effective Compose payload must be bytes")
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError("effective Compose model exceeds the bounded size limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("effective Compose model must be valid UTF-8") from exc
    if "\x00" in text:
        raise ValueError("effective Compose model must not contain NUL bytes")
    model = _parse_compose_model(text)
    _require_sealed_model(model)
    _require_effective_keys(model, _EFFECTIVE_TOP_LEVEL_KEYS, field="top-level model")
    rendered_name = model.get("name")
    if rendered_name is not None and rendered_name != project_name:
        raise ValueError(
            "effective Compose project name does not match the persisted project identity"
        )
    services_value = model.get("services")
    if not isinstance(services_value, Mapping) or not services_value:
        raise ValueError("effective Compose model has no services mapping")
    if any(not isinstance(name, str) or not name for name in services_value):
        raise ValueError("effective Compose model has an invalid service name")
    services = tuple(sorted(services_value))
    expected_services = tuple(sorted(dict.fromkeys(declared_services)))
    if not expected_services or services != expected_services:
        raise ValueError(
            "declared Compose services do not exactly match the merged effective model"
        )

    risks: set[str] = set()
    volumes_value = model.get("volumes") or {}
    volumes = _require_effective_mapping(volumes_value, field="volume definitions")
    networks_value = model.get("networks") or {}
    networks = _require_effective_mapping(networks_value, field="network definitions")
    for volume_name, raw_volume in volumes.items():
        if not isinstance(volume_name, str) or not volume_name:
            raise ValueError("effective Compose volume name is invalid")
        volume = (
            {}
            if raw_volume is None
            else _require_effective_mapping(raw_volume, field="volume definition")
        )
        _require_effective_keys(
            volume, _EFFECTIVE_VOLUME_KEYS, field="volume definition"
        )
        external = volume.get("external", False)
        if type(external) is not bool:
            raise ValueError("effective Compose volume external flag is invalid")
        if external:
            risks.add("external_volume")
        options = volume.get("driver_opts") or {}
        if not isinstance(options, Mapping):
            raise ValueError("effective Compose volume driver options are invalid")
        option_type = str(options.get("type") or "").lower()
        option_flags = str(options.get("o") or "").lower().split(",")
        device = str(options.get("device") or "")
        if option_type == "none" or "bind" in option_flags or device.startswith("/"):
            risks.add("volume_driver_bind")
    for network_name, raw_network in networks.items():
        if not isinstance(network_name, str) or not network_name:
            raise ValueError("effective Compose network name is invalid")
        network = (
            {}
            if raw_network is None
            else _require_effective_mapping(raw_network, field="network definition")
        )
        _require_effective_keys(
            network, _EFFECTIVE_NETWORK_KEYS, field="network definition"
        )
        external = network.get("external", False)
        if type(external) is not bool:
            raise ValueError("effective Compose network external flag is invalid")
        if external:
            risks.add("external_network")

    available_profiles: set[str] = set()
    service_replicas: dict[str, int] = {}
    replica_budget = 0
    for service_name, raw_service in services_value.items():
        if not isinstance(raw_service, Mapping):
            raise ValueError(
                f"effective Compose service {service_name!r} is not a mapping"
            )
        _require_effective_keys(
            raw_service,
            _EFFECTIVE_SERVICE_KEYS,
            field=f"service {service_name!r}",
        )
        raw_profiles = raw_service.get("profiles", ())
        if isinstance(raw_profiles, str):
            raw_profiles = (raw_profiles,)
        if not isinstance(raw_profiles, Sequence):
            raise ValueError("effective Compose service profiles are invalid")
        for profile in raw_profiles:
            if not isinstance(profile, str) or not profile:
                raise ValueError("effective Compose service profile is invalid")
            available_profiles.add(profile)

        dependencies = raw_service.get("depends_on", {})
        if isinstance(dependencies, Sequence) and not isinstance(
            dependencies, (str, bytes, bytearray)
        ):
            dependency_names = tuple(dependencies)
        elif isinstance(dependencies, Mapping):
            dependency_names = tuple(dependencies)
        elif dependencies in (None, {}):
            dependency_names = ()
        else:
            raise ValueError("effective Compose dependency scope is invalid")
        if any(
            not isinstance(name, str) or name not in services_value
            for name in dependency_names
        ):
            raise ValueError(
                "effective Compose dependency escapes the declared service scope"
            )

        replicas: Any = raw_service.get("scale")
        deploy = _classify_deploy(raw_service.get("deploy"), risks=risks)
        if deploy is not None:
            if str(deploy.get("mode") or "replicated") == "global":
                raise ValueError("global Compose replication is not bounded")
            if replicas is None:
                replicas = deploy.get("replicas")
        replicas = 1 if replicas is None else replicas
        if type(replicas) is not int or not 1 <= replicas <= 16:
            raise ValueError(
                "Compose service replicas must be bounded from one through 16"
            )
        service_replicas[service_name] = replicas
        replica_budget += replicas

        if raw_service.get("privileged") is True:
            risks.add("privileged")
        for key in ("network_mode", "pid", "ipc", "uts", "userns_mode"):
            _classify_namespace_reference(
                raw_service.get(key),
                services=services_value,
                risks=risks,
                field=key,
            )
        _classify_volumes_from(
            raw_service.get("volumes_from"),
            services=services_value,
            risks=risks,
        )
        use_api_socket = raw_service.get("use_api_socket", False)
        if type(use_api_socket) is not bool:
            raise ValueError("effective Compose use_api_socket flag is invalid")
        if use_api_socket:
            risks.add("docker_socket")
        if raw_service.get("devices") or raw_service.get("device_cgroup_rules"):
            risks.add("host_devices")
        if raw_service.get("gpus"):
            risks.add("gpu_access")
        if raw_service.get("cap_add"):
            risks.add("added_capabilities")
        ports = raw_service.get("ports") or ()
        if isinstance(ports, (str, Mapping)):
            ports = (ports,)
        if not isinstance(ports, Sequence):
            raise ValueError("effective Compose service ports are invalid")
        if ports:
            risks.add("published_host_ports")
        service_networks = raw_service.get("networks") or ()
        if isinstance(service_networks, str):
            service_network_names = (service_networks,)
        elif isinstance(service_networks, Mapping):
            service_network_names = tuple(service_networks)
        elif isinstance(service_networks, Sequence):
            service_network_names = tuple(service_networks)
        else:
            raise ValueError("effective Compose service networks are invalid")
        if any(
            not isinstance(name, str) or name not in networks
            for name in service_network_names
        ):
            raise ValueError(
                "effective Compose service network escapes the declared model"
            )
        security_options = raw_service.get("security_opt") or ()
        if isinstance(security_options, str):
            security_options = (security_options,)
        if isinstance(security_options, Sequence) and any(
            "unconfined" in str(item).lower() for item in security_options
        ):
            risks.add("unconfined_security")
        mounts = raw_service.get("volumes") or ()
        if isinstance(mounts, (str, Mapping)):
            mounts = (mounts,)
        if not isinstance(mounts, Sequence):
            raise ValueError("effective Compose service volumes are invalid")
        for mount in mounts:
            if isinstance(mount, Mapping):
                mount_type = str(mount.get("type") or "").lower()
                source = str(mount.get("source") or "")
                target = str(mount.get("target") or "")
                if mount_type == "bind":
                    risks.add("host_bind_mount")
                if "docker.sock" in source or "docker.sock" in target:
                    risks.add("docker_socket")
                if mount_type == "volume" and source and source not in volumes:
                    raise ValueError(
                        "effective Compose named volume escapes the declared model"
                    )
            elif isinstance(mount, str):
                source = mount.split(":", 1)[0]
                if source.startswith(("/", ".", "~")):
                    risks.add("host_bind_mount")
                if "docker.sock" in mount:
                    risks.add("docker_socket")
            else:
                raise ValueError("effective Compose service mount is invalid")

    if replica_budget > 64:
        raise ValueError("effective Compose replica budget exceeds 64 containers")
    requested_profiles = tuple(sorted(dict.fromkeys(declared_profiles)))
    if any(profile not in available_profiles for profile in requested_profiles):
        raise ValueError(
            "declared Compose profile is absent from the merged effective model"
        )

    ordered_risks = tuple(sorted(risks))
    if ordered_risks and not host_access_approved:
        raise PermissionError(
            "effective Compose model requests host-equivalent access; rerun enrollment with explicit administrator approval"
        )
    canonical = json.dumps(
        model,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return EffectiveComposeEvidence(
        model_sha256="sha256:" + hashlib.sha256(canonical).hexdigest(),
        services=services,
        profiles=tuple(sorted(available_profiles)),
        host_access_risks=ordered_risks,
        service_replicas=tuple(sorted(service_replicas.items())),
        replica_budget=replica_budget,
    )
