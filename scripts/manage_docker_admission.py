#!/usr/bin/env python3
"""Remove direct Docker access from Coordinator clients, transactionally.

The Coordinator broker is the only supported Docker admission path.  This
root-only administrator tool removes a sealed, finite set of legacy NSS and
POSIX-ACL grants and then waits for already-running login sessions to lose
their retained credentials.  It never changes Docker configuration, socket
mode/ownership, sudo policy, rootless daemons, contexts, or arbitrary groups.

Every mutating command is derived from a validated request, recorded before it
is executed, and limited to fixed absolute ``gpasswd``/``setfacl`` forms.
Uncertain replies are recovered by observing the exact desired state.  A
successful verify requires fresh-connect denial and a broker inventory canary.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Sequence
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
SKILL_SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from secure_cutover_io import (  # noqa: E402
    SecureIOError,
    read_private_regular,
)
from server_wide_installer_fence import (  # noqa: E402
    DEFAULT_INSTALLER_CLAIM,
    DEFAULT_INSTALLER_LOCK,
    InstallerFenceError,
    acquire_transaction_fence,
)
from devcoordinator.broker_profile import (  # noqa: E402
    BrokerProfileError,
    profile_from_document,
)


SCHEMA_VERSION = 1
REQUEST_KIND = "devcoordinator-docker-admission-request"
REQUEST_DRAFT_KIND = "devcoordinator-docker-admission-request-draft"
JOURNAL_KIND = "devcoordinator-docker-admission-journal"
TERMINAL_KIND = "devcoordinator-docker-admission-terminal"
OWNER_KIND = "devcoordinator-docker-admission"
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
GID_BYPASS_GROUPS = frozenset({"sudo", "wheel", "lxd"})
DOCKER_GROUP = "docker"
DOCKER_SOCKET_CANDIDATES = (Path("/run/docker.sock"), Path("/var/run/docker.sock"))
FIXED_GPASSWD = Path("/usr/bin/gpasswd")
FIXED_SETFACL = Path("/usr/bin/setfacl")
FIXED_GETFACL = Path("/usr/bin/getfacl")
FIXED_SETPRIV = Path("/usr/bin/setpriv")
FIXED_PYTHON = Path("/usr/bin/python3")
PROTECTED_PROFILE_PATH = Path("/etc/devcoordinator/client-profiles.json")
IMMUTABLE_CLIENT_RELATIVE = Path(
    "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
)
PROFILE_MAX_BYTES = 1024 * 1024
RELEASE_MANIFEST_NAME = "release-manifest.json"
RELEASE_SCHEMA_VERSION = 1
DOCKER_CLIENT_NAMES = frozenset({"docker", "docker-compose", "com.docker.cli"})
ALTERNATE_ENGINE_NAMES = frozenset(
    {
        "buildah",
        "colima",
        "containerd",
        "ctr",
        "finch",
        "lima",
        "limactl",
        "lxc",
        "lxd",
        "nerdctl",
        "podman",
        "podman-compose",
    }
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SAFE_REPOSITORY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


class DockerAdmissionError(RuntimeError):
    """The admission transaction or host proof is unsafe."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DockerAdmissionError(f"{label} repeats field {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerAdmissionError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise DockerAdmissionError(f"{label} must be an object")
    return value


def _seal(values: Mapping[str, Any]) -> dict[str, Any]:
    document = dict(values)
    document["document_sha256"] = _sha256(_canonical(document))
    return document


def _validate_seal(document: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    value = dict(document)
    supplied = value.pop("document_sha256", None)
    if not isinstance(supplied, str) or not HEX64_RE.fullmatch(supplied):
        raise DockerAdmissionError(f"{label} digest is invalid")
    if _sha256(_canonical(value)) != supplied:
        raise DockerAdmissionError(f"{label} digest does not match its content")
    value["document_sha256"] = supplied
    return value


def _absolute(path: str | Path, label: str) -> Path:
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts or Path(os.path.normpath(value)) != value:
        raise DockerAdmissionError(f"{label} must be an absolute normalized path")
    return value


def _uuid(value: Any, label: str) -> str:
    try:
        normalized = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as error:
        raise DockerAdmissionError(f"{label} is invalid") from error
    if normalized != value or not UUID_RE.fullmatch(normalized):
        raise DockerAdmissionError(f"{label} is not canonical")
    return normalized


def _require_root() -> None:
    if os.geteuid() != 0 or os.getuid() != 0:
        raise DockerAdmissionError("Docker admission administration requires real and effective UID 0")


def _require_private_dir(path: Path, *, create: bool = False) -> None:
    path = _absolute(path, "transaction directory")
    if create and not path.exists() and not path.is_symlink():
        parent = path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise DockerAdmissionError("transaction parent is unsafe")
        path.mkdir(mode=0o700)
        os.chown(path, os.getuid(), os.getgid())
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_gid != os.getgid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DockerAdmissionError("transaction directory must be authority-owned mode 0700")


def _write_private(path: Path, document: Mapping[str, Any], *, replace: bool) -> None:
    _require_private_dir(path.parent)
    payload = _canonical(document) + b"\n"
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise DockerAdmissionError("private transaction document is too large")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise DockerAdmissionError("private transaction document write stalled")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, os.getuid(), os.getgid())
    finally:
        os.close(descriptor)
    try:
        if replace:
            if not path.exists() or path.is_symlink():
                raise DockerAdmissionError("private transaction document disappeared")
            current = path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.getuid()
                or current.st_gid != os.getgid()
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_nlink != 1
            ):
                raise DockerAdmissionError("private transaction document identity is unsafe")
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except FileExistsError as error:
        raise DockerAdmissionError("private transaction document already exists") from error
    finally:
        temporary.unlink(missing_ok=True)


def _read_private(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = read_private_regular(path, label=label, expected_uid=os.getuid())
    except (SecureIOError, OSError) as error:
        raise DockerAdmissionError(str(error)) from error
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise DockerAdmissionError(f"{label} is too large")
    return _strict_json(raw, label=label)


def _read_root_regular(path: Path, *, label: str, maximum: int) -> bytes:
    """Read one root-owned trust anchor without following or racing an inode."""

    path = _absolute(path, label)
    if path != PROTECTED_PROFILE_PATH and label == "protected broker profile":
        raise DockerAdmissionError("Docker admission requires the fixed protected broker profile")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise DockerAdmissionError(f"{label} has unsafe ancestry")
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise DockerAdmissionError(f"{label} identity is unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise DockerAdmissionError(f"{label} changed before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise DockerAdmissionError(f"{label} exceeds its size bound")
            chunks.append(block)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        ):
            raise DockerAdmissionError(f"{label} changed while read")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _profile_state(path: Path = PROTECTED_PROFILE_PATH) -> tuple[dict[str, Any], dict[str, Any], dict[int, Any]]:
    raw = _read_root_regular(path, label="protected broker profile", maximum=PROFILE_MAX_BYTES)
    document = _strict_json(raw, label="protected broker profile")
    if set(document) != {"version", "service", "clients"} or document.get("version") != 1:
        raise DockerAdmissionError("protected broker profile fields are invalid")
    clients = document.get("clients")
    if not isinstance(clients, dict) or not clients or len(clients) > 10_000:
        raise DockerAdmissionError("protected broker profile client set is invalid")
    client_uids: list[int] = []
    profiles: dict[int, Any] = {}
    for raw_uid in clients:
        if not isinstance(raw_uid, str) or not raw_uid.isdigit():
            raise DockerAdmissionError("protected broker profile client UID is invalid")
        uid = int(raw_uid)
        if uid < 0 or str(uid) != raw_uid or uid in profiles:
            raise DockerAdmissionError("protected broker profile client UID is noncanonical")
        try:
            profiles[uid] = profile_from_document(document, effective_uid=uid)
        except (BrokerProfileError, TypeError, ValueError) as error:
            raise DockerAdmissionError(
                f"protected broker profile client {uid} is invalid: {error}"
            ) from error
        # UID 0 is a valid authenticated broker administrator, but it is not a
        # Docker-admission revocation target. Root necessarily retains host
        # daemon access; keep it covered by ``clients_sha256`` and the parsed
        # profile set while excluding it from the non-root client action set.
        if uid > 0:
            client_uids.append(uid)
    client_uids.sort()
    binding = {
        "path": str(path),
        "sha256": _sha256(raw),
        "clients_sha256": _sha256(_canonical(clients)),
        "client_uids": client_uids,
    }
    return document, binding, profiles


def _release_client_proof(path: Path) -> dict[str, Any]:
    """Bind the canary to the final immutable release manifest, not a path shape."""

    path = _absolute(path, "immutable broker client")
    release: Path | None = None
    for parent in path.parents:
        if HEX64_RE.fullmatch(parent.name):
            release = parent
            break
    if release is None or path != release / IMMUTABLE_CLIENT_RELATIVE:
        raise DockerAdmissionError("broker canary must use the canonical immutable client path")
    if release.parent.name != "releases":
        raise DockerAdmissionError("broker canary release ancestry is invalid")
    current = release
    while current != Path(current.anchor):
        metadata = current.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise DockerAdmissionError("broker canary release ancestry is mutable")
        if current == release.parent.parent:
            break
        current = current.parent
    manifest_path = release / RELEASE_MANIFEST_NAME
    manifest_raw = _read_root_regular(
        manifest_path, label="immutable release manifest", maximum=MAX_DOCUMENT_BYTES
    )
    manifest = _strict_json(manifest_raw, label="immutable release manifest")
    if set(manifest) != {
        "capabilities", "files", "release_digest", "release_directory",
        "schema_version", "source_identity",
    } or manifest.get("schema_version") != RELEASE_SCHEMA_VERSION:
        raise DockerAdmissionError("immutable release manifest contract is invalid")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > 100_000:
        raise DockerAdmissionError("immutable release file inventory is invalid")
    previous = ""
    client_entry: dict[str, Any] | None = None
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"kind", "mode", "path", "sha256", "size"}:
            raise DockerAdmissionError("immutable release file entry is invalid")
        relative = str(entry["path"])
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts or not relative or relative <= previous:
            raise DockerAdmissionError("immutable release file inventory is not canonical")
        previous = relative
        if not isinstance(entry["sha256"], str) or not HEX64_RE.fullmatch(entry["sha256"]):
            raise DockerAdmissionError("immutable release file digest is invalid")
        if not isinstance(entry["mode"], str) or not re.fullmatch(r"0[0-7]{3}", entry["mode"]):
            raise DockerAdmissionError("immutable release file mode is invalid")
        if not isinstance(entry["kind"], str) or not entry["kind"] or len(entry["kind"]) > 64:
            raise DockerAdmissionError("immutable release file kind is invalid")
        if type(entry["size"]) is not int or entry["size"] < 0:
            raise DockerAdmissionError("immutable release file size is invalid")
        if relative == IMMUTABLE_CLIENT_RELATIVE.as_posix():
            client_entry = dict(entry)
    digest = _sha256(_canonical({"schema_version": RELEASE_SCHEMA_VERSION, "files": entries}))
    if manifest.get("release_digest") != digest or release.name != digest:
        raise DockerAdmissionError("immutable release digest does not match its inventory")
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict) or capabilities.get("authority_systemd_socket") is not True:
        raise DockerAdmissionError("immutable client release lacks broker authority capability")
    if client_entry is None:
        raise DockerAdmissionError("immutable release omits the broker client")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != int(str(client_entry["mode"]), 8)
        or info.st_size != client_entry["size"]
    ):
        raise DockerAdmissionError("immutable broker client metadata is invalid")
    payload = _read_root_regular(
        path, label="immutable broker client", maximum=MAX_DOCUMENT_BYTES
    )
    if _sha256(payload) != client_entry["sha256"]:
        raise DockerAdmissionError("immutable broker client differs from its release manifest")
    return {
        "release_digest": digest,
        "client_sha256": client_entry["sha256"],
        "manifest_sha256": _sha256(manifest_raw),
    }


def _validate_request(document: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "kind",
        "operation_id",
        "docker_group",
        "socket_paths",
        "protected_profile",
        "clients",
        "acl_grants",
        "broker_canary",
        "document_sha256",
    }
    if set(document) != expected:
        raise DockerAdmissionError("Docker admission request fields are invalid")
    request = _validate_seal(document, label="Docker admission request")
    if request["schema_version"] != SCHEMA_VERSION or request["kind"] != REQUEST_KIND:
        raise DockerAdmissionError("Docker admission request contract is invalid")
    _uuid(request["operation_id"], "Docker admission operation")
    if request["docker_group"] != DOCKER_GROUP:
        raise DockerAdmissionError("only the exact docker group may be removed")
    paths = request["socket_paths"]
    if not isinstance(paths, list) or not paths or len(paths) > 8:
        raise DockerAdmissionError("Docker socket path set is invalid")
    normalized_paths = [_absolute(item, "Docker socket path") for item in paths]
    if len(set(normalized_paths)) != len(normalized_paths):
        raise DockerAdmissionError("Docker socket paths must be unique")
    if not any(path in DOCKER_SOCKET_CANDIDATES for path in normalized_paths):
        raise DockerAdmissionError("Docker socket paths omit the host daemon socket")
    profile = request["protected_profile"]
    if not isinstance(profile, dict) or set(profile) != {
        "path", "sha256", "clients_sha256", "client_uids"
    }:
        raise DockerAdmissionError("protected broker profile binding fields are invalid")
    if _absolute(profile["path"], "protected broker profile") != PROTECTED_PROFILE_PATH:
        raise DockerAdmissionError("Docker admission requires the fixed protected broker profile")
    if (
        not isinstance(profile["sha256"], str)
        or not HEX64_RE.fullmatch(profile["sha256"])
        or not isinstance(profile["clients_sha256"], str)
        or not HEX64_RE.fullmatch(profile["clients_sha256"])
        or not isinstance(profile["client_uids"], list)
        or not profile["client_uids"]
        or any(type(uid) is not int or uid <= 0 for uid in profile["client_uids"])
        or profile["client_uids"] != sorted(set(profile["client_uids"]))
    ):
        raise DockerAdmissionError("protected broker profile binding is invalid")
    clients = request["clients"]
    if not isinstance(clients, list) or not clients or len(clients) > 10_000:
        raise DockerAdmissionError("Docker admission client set is invalid")
    seen_uids: set[int] = set()
    seen_users: set[str] = set()
    required_client_fields = {
        "user",
        "uid",
        "primary_gid",
        "project",
        "repository_id",
        "repository_generation",
    }
    if clients != sorted(clients, key=lambda item: item.get("uid", -1) if isinstance(item, dict) else -1):
        raise DockerAdmissionError("Docker admission clients must be sorted by UID")
    for client in clients:
        if not isinstance(client, dict) or set(client) != required_client_fields:
            raise DockerAdmissionError("Docker admission client fields are invalid")
        user = client["user"]
        uid = client["uid"]
        gid = client["primary_gid"]
        generation = client["repository_generation"]
        if not isinstance(user, str) or not SAFE_NAME_RE.fullmatch(user):
            raise DockerAdmissionError("Docker admission client user is invalid")
        if type(uid) is not int or uid <= 0 or uid in seen_uids:
            raise DockerAdmissionError("Docker admission client UID is invalid or duplicated")
        if type(gid) is not int or gid <= 0:
            raise DockerAdmissionError("Docker admission client primary GID is invalid")
        if user in seen_users:
            raise DockerAdmissionError("Docker admission client user is duplicated")
        project = _absolute(client["project"], "broker canary project")
        if not isinstance(client["repository_id"], str) or not SAFE_REPOSITORY_ID_RE.fullmatch(client["repository_id"]):
            raise DockerAdmissionError("broker canary repository ID is invalid")
        if type(generation) is not int or generation < 0:
            raise DockerAdmissionError("broker canary repository generation is invalid")
        if not project.name:
            raise DockerAdmissionError("broker canary project is invalid")
        seen_uids.add(uid)
        seen_users.add(user)
    if sorted(seen_uids) != profile["client_uids"]:
        raise DockerAdmissionError("Docker admission clients are not the complete protected profile client set")
    grants = request["acl_grants"]
    if not isinstance(grants, list) or len(grants) > 20_000:
        raise DockerAdmissionError("Docker socket ACL grant set is invalid")
    seen_grants: set[tuple[str, str, str]] = set()
    for grant in grants:
        if not isinstance(grant, dict) or set(grant) != {"path", "tag", "qualifier"}:
            raise DockerAdmissionError("Docker socket ACL grant fields are invalid")
        path = _absolute(grant["path"], "Docker socket ACL path")
        if path not in normalized_paths:
            raise DockerAdmissionError("Docker socket ACL grant names an undeclared socket")
        tag = grant["tag"]
        qualifier = grant["qualifier"]
        if tag == "user":
            if type(qualifier) is not int or qualifier not in seen_uids:
                raise DockerAdmissionError("Docker socket user ACL grant is not a client UID")
            key = (str(path), tag, str(qualifier))
        elif tag == "group":
            if qualifier != DOCKER_GROUP:
                raise DockerAdmissionError("only the docker named-group ACL may be removed")
            key = (str(path), tag, qualifier)
        else:
            raise DockerAdmissionError("Docker socket ACL grant tag is invalid")
        if key in seen_grants:
            raise DockerAdmissionError("Docker socket ACL grants must be unique")
        seen_grants.add(key)
    canary = request["broker_canary"]
    if not isinstance(canary, dict) or set(canary) != {
        "client_path",
        "broker_socket",
        "user",
        "uid",
        "primary_gid",
        "project",
        "repository_id",
        "repository_generation",
        "authority_generation",
        "profile_sha256",
        "release_digest",
        "client_sha256",
        "manifest_sha256",
    }:
        raise DockerAdmissionError("broker canary fields are invalid")
    match = next((item for item in clients if item["uid"] == canary["uid"]), None)
    if match is None or any(canary[key] != match[key] for key in (
        "user", "uid", "primary_gid", "project", "repository_id", "repository_generation"
    )):
        raise DockerAdmissionError("broker canary is not bound to one declared client")
    _absolute(canary["client_path"], "immutable broker client")
    _absolute(canary["broker_socket"], "broker socket")
    if not isinstance(canary["authority_generation"], str) or not canary["authority_generation"]:
        raise DockerAdmissionError("broker canary authority generation is invalid")
    for field in ("profile_sha256", "release_digest", "client_sha256", "manifest_sha256"):
        if not isinstance(canary[field], str) or not HEX64_RE.fullmatch(canary[field]):
            raise DockerAdmissionError(f"broker canary {field.replace('_', ' ')} is invalid")
    if canary["profile_sha256"] != profile["sha256"]:
        raise DockerAdmissionError("broker canary is not bound to the protected profile")
    if Path(canary["client_path"]).parent.parent.parent.parent.name != canary["release_digest"]:
        # The structural check is repeated against the manifest by the live verifier.
        raise DockerAdmissionError("broker canary release digest does not match its client path")
    return request


def load_request(path: Path) -> dict[str, Any]:
    request = _validate_request(_read_private(path, "Docker admission request"))
    _verify_request_profile_binding(request)
    return request


def _verify_request_profile_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    request = _validate_request(request)
    _document, observed, profiles = _profile_state(Path(request["protected_profile"]["path"]))
    if observed != request["protected_profile"]:
        raise DockerAdmissionError("protected broker profile changed after request sealing")
    for client in request["clients"]:
        profile = profiles.get(int(client["uid"]))
        if profile is None:
            raise DockerAdmissionError("Docker admission client is absent from the protected profile")
        try:
            repository = profile.repository(client["project"])
        except BrokerProfileError as error:
            raise DockerAdmissionError(
                f"Docker admission client repository is not current in the protected profile: {error}"
            ) from error
        if (
            repository.repo_id != client["repository_id"]
            or repository.generation != client["repository_generation"]
            or repository.owner_uid != client["uid"]
        ):
            raise DockerAdmissionError("Docker admission client repository binding changed")
    canary = request["broker_canary"]
    profile = profiles[int(canary["uid"])]
    if (
        str(profile.service.socket_path) != canary["broker_socket"]
        or profile.service.database_generation != canary["authority_generation"]
    ):
        raise DockerAdmissionError("broker canary service binding differs from the protected profile")
    proof = _release_client_proof(Path(canary["client_path"]))
    if any(canary[key] != proof[key] for key in (
        "release_digest", "client_sha256", "manifest_sha256"
    )):
        raise DockerAdmissionError("broker canary immutable client binding changed")
    return {
        "profile_sha256": observed["sha256"],
        "clients_sha256": observed["clients_sha256"],
        "client_uids": observed["client_uids"],
        **proof,
    }


def _validate_request_draft(document: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema_version",
        "kind",
        "operation_id",
        "docker_group",
        "socket_paths",
        "client_projects",
        "acl_grants",
        "protected_profile_path",
        "immutable_client_path",
        "broker_canary_user",
    }
    if set(document) != expected:
        raise DockerAdmissionError("Docker admission request draft fields are invalid")
    draft = dict(document)
    if draft["schema_version"] != SCHEMA_VERSION or draft["kind"] != REQUEST_DRAFT_KIND:
        raise DockerAdmissionError("Docker admission request draft contract is invalid")
    _uuid(draft["operation_id"], "Docker admission operation")
    if draft["docker_group"] != DOCKER_GROUP:
        raise DockerAdmissionError("only the exact docker group may be removed")
    if _absolute(draft["protected_profile_path"], "protected broker profile") != PROTECTED_PROFILE_PATH:
        raise DockerAdmissionError("Docker admission draft requires the fixed protected profile")
    _absolute(draft["immutable_client_path"], "immutable broker client")
    if not isinstance(draft["broker_canary_user"], str) or not SAFE_NAME_RE.fullmatch(draft["broker_canary_user"]):
        raise DockerAdmissionError("Docker admission draft canary user is invalid")
    if not isinstance(draft["socket_paths"], list) or not draft["socket_paths"]:
        raise DockerAdmissionError("Docker admission draft socket set is invalid")
    projects = draft["client_projects"]
    if not isinstance(projects, list) or not projects or len(projects) > 10_000:
        raise DockerAdmissionError("Docker admission draft client project set is invalid")
    for item in projects:
        if not isinstance(item, dict) or set(item) != {"user", "project"}:
            raise DockerAdmissionError("Docker admission draft client project fields are invalid")
        if not isinstance(item["user"], str) or not SAFE_NAME_RE.fullmatch(item["user"]):
            raise DockerAdmissionError("Docker admission draft client user is invalid")
        _absolute(item["project"], "Docker admission draft client project")
    if not isinstance(draft["acl_grants"], list):
        raise DockerAdmissionError("Docker admission draft ACL grants are invalid")
    return draft


def produce_sealed_request(draft: Mapping[str, Any]) -> dict[str, Any]:
    """Produce the only accepted request from live profile and release anchors."""

    draft = _validate_request_draft(draft)
    _document, binding, profiles = _profile_state(Path(draft["protected_profile_path"]))
    projects_by_uid: dict[int, tuple[str, str]] = {}
    for item in draft["client_projects"]:
        try:
            account = pwd.getpwnam(item["user"])
        except KeyError as error:
            raise DockerAdmissionError(f"Docker admission client {item['user']} is absent from NSS") from error
        if account.pw_uid in projects_by_uid:
            raise DockerAdmissionError("Docker admission draft duplicates a client UID")
        projects_by_uid[account.pw_uid] = (account.pw_name, str(_absolute(item["project"], "client project")))
    if sorted(projects_by_uid) != binding["client_uids"]:
        raise DockerAdmissionError("Docker admission draft does not cover every protected profile client")
    clients: list[dict[str, Any]] = []
    for uid in binding["client_uids"]:
        user, project = projects_by_uid[uid]
        account = pwd.getpwuid(uid)
        if account.pw_name != user:
            raise DockerAdmissionError("Docker admission client NSS identity is ambiguous")
        try:
            repository = profiles[uid].repository(project)
        except BrokerProfileError as error:
            raise DockerAdmissionError(
                f"Docker admission client project is not enrolled: {error}"
            ) from error
        if repository.owner_uid != uid:
            raise DockerAdmissionError("Docker admission repository owner differs from its client UID")
        clients.append(
            {
                "user": user,
                "uid": uid,
                "primary_gid": account.pw_gid,
                "project": repository.canonical_root,
                "repository_id": repository.repo_id,
                "repository_generation": repository.generation,
            }
        )
    canary_client = next(
        (item for item in clients if item["user"] == draft["broker_canary_user"]), None
    )
    if canary_client is None:
        raise DockerAdmissionError("Docker admission canary user is not a protected profile client")
    canary_profile = profiles[canary_client["uid"]]
    proof = _release_client_proof(Path(draft["immutable_client_path"]))
    request = _seal(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": REQUEST_KIND,
            "operation_id": draft["operation_id"],
            "docker_group": DOCKER_GROUP,
            "socket_paths": draft["socket_paths"],
            "protected_profile": binding,
            "clients": clients,
            "acl_grants": draft["acl_grants"],
            "broker_canary": {
                "client_path": draft["immutable_client_path"],
                "broker_socket": str(canary_profile.service.socket_path),
                **canary_client,
                "authority_generation": canary_profile.service.database_generation,
                "profile_sha256": binding["sha256"],
                **proof,
            },
        }
    )
    return _validate_request(request)


def seal_request_file(*, draft_path: Path, output_path: Path) -> dict[str, Any]:
    _require_root()
    if output_path.exists() or output_path.is_symlink():
        raise DockerAdmissionError("sealed Docker admission request output already exists")
    request = produce_sealed_request(_read_private(draft_path, "Docker admission request draft"))
    _write_private(output_path, request, replace=False)
    _verify_request_profile_binding(request)
    return {
        "ok": True,
        "kind": "devcoordinator-docker-admission-request-seal",
        "operation_id": request["operation_id"],
        "request": str(output_path),
        "request_sha256": request["document_sha256"],
        "profile_sha256": request["protected_profile"]["sha256"],
        "clients_sha256": request["protected_profile"]["clients_sha256"],
        "client_uids": request["protected_profile"]["client_uids"],
        "release_digest": request["broker_canary"]["release_digest"],
    }


def _safe_executable(path: Path) -> None:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o111
        or path.resolve(strict=True) != path
    ):
        raise DockerAdmissionError(f"required host executable is unsafe: {path}")


def _socket_identity(path: Path) -> dict[str, Any]:
    info = path.stat()
    resolved = path.resolve(strict=True)
    resolved_info = resolved.lstat()
    if not stat.S_ISSOCK(resolved_info.st_mode):
        raise DockerAdmissionError(f"Docker socket path is not a Unix socket: {path}")
    return {
        "path": str(path),
        "resolved": str(resolved),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "gid": int(info.st_gid),
        "mode": stat.S_IMODE(info.st_mode),
        "ctime_ns": int(info.st_ctime_ns),
    }


def _parse_acl(payload: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("default:"):
            continue
        parts = line.split(":")
        if len(parts) != 3 or parts[0] not in {"user", "group", "mask", "other"}:
            raise DockerAdmissionError("getfacl returned an unsupported ACL entry")
        tag, qualifier, permissions = parts
        if not re.fullmatch(r"[r-][w-][x-]", permissions):
            raise DockerAdmissionError("getfacl returned invalid ACL permissions")
        entries.append({"tag": tag, "qualifier": qualifier, "permissions": permissions})
    return entries


def _acl_for(path: Path) -> list[dict[str, Any]]:
    _safe_executable(FIXED_GETFACL)
    completed = subprocess.run(
        [str(FIXED_GETFACL), "-c", "-p", "--", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        text=True,
    )
    if completed.returncode != 0:
        raise DockerAdmissionError(f"getfacl could not inspect {path}: {completed.stderr.strip()[:256]}")
    return _parse_acl(completed.stdout)


def _proc_start(stat_payload: str) -> int:
    close = stat_payload.rfind(")")
    if close < 2:
        raise DockerAdmissionError("process stat record is malformed")
    fields = stat_payload[close + 2 :].split()
    if len(fields) < 20:
        raise DockerAdmissionError("process stat record is incomplete")
    try:
        return int(fields[19])
    except ValueError as error:
        raise DockerAdmissionError("process start identity is invalid") from error


def _status_ids(payload: str) -> tuple[int, list[int]]:
    uid: int | None = None
    groups: list[int] | None = None
    for line in payload.splitlines():
        if line.startswith("Uid:"):
            values = line.split()[1:]
            if len(values) != 4 or len(set(values)) != 1:
                raise DockerAdmissionError("process UID credentials are changing or incomplete")
            uid = int(values[0])
        elif line.startswith("Groups:"):
            groups = sorted({int(value) for value in line.split()[1:]})
    if uid is None or groups is None:
        raise DockerAdmissionError("process credential record is incomplete")
    return uid, groups


def _read_proc_file(path: Path, *, binary: bool = False) -> bytes | str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            chunks.append(block)
            if sum(map(len, chunks)) > 4 * 1024 * 1024:
                raise DockerAdmissionError(f"process evidence is unexpectedly large: {path}")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    return raw if binary else raw.decode("utf-8", errors="strict")


def _nul_fields(raw: bytes, *, label: str) -> list[str]:
    fields: list[str] = []
    for value in raw.split(b"\0"):
        if not value:
            continue
        try:
            fields.append(value.decode("utf-8", errors="strict"))
        except UnicodeDecodeError as error:
            raise DockerAdmissionError(f"{label} is not UTF-8") from error
    return fields


def _environment_fields(raw: bytes) -> dict[str, str]:
    environment: dict[str, str] = {}
    for item in _nul_fields(raw, label="process environment"):
        key, separator, value = item.partition("=")
        if not separator or not key or key in environment:
            raise DockerAdmissionError("process environment fields are ambiguous")
        environment[key] = value
    return environment


def _docker_cli_options(argv: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
    hosts: list[str] = []
    contexts: list[str] = []
    errors: list[str] = []
    index = 1
    while index < len(argv):
        value = argv[index]
        if value in {"-H", "--host", "--context"}:
            if index + 1 >= len(argv) or not argv[index + 1]:
                errors.append(f"Docker CLI option {value} lacks a value")
                index += 1
                continue
            target = argv[index + 1]
            (contexts if value == "--context" else hosts).append(target)
            index += 2
            continue
        if value.startswith("--host="):
            hosts.append(value.partition("=")[2])
        elif value.startswith("--context="):
            contexts.append(value.partition("=")[2])
        elif value.startswith("-H") and len(value) > 2:
            hosts.append(value[2:])
        index += 1
    return hosts, contexts, errors


def _process_context_issues(
    *, executable: str, argv: Sequence[str], environment: Mapping[str, str], socket_paths: set[str]
) -> list[str]:
    issues: list[str] = []
    executable_name = Path(executable.removesuffix(" (deleted)")).name.lower()
    argv_name = Path(argv[0]).name.lower() if argv else ""
    engine_name = executable_name if executable_name in DOCKER_CLIENT_NAMES | ALTERNATE_ENGINE_NAMES else argv_name
    if engine_name in ALTERNATE_ENGINE_NAMES:
        issues.append(f"active alternate container engine client: {engine_name}")
    allowed_hosts = set(socket_paths)
    allowed_hosts.update(f"unix://{value}" for value in socket_paths)
    for key in ("DOCKER_HOST", "CONTAINER_HOST", "PODMAN_HOST"):
        value = environment.get(key)
        if value and value not in allowed_hosts:
            issues.append(f"custom container endpoint in {key}")
    context = environment.get("DOCKER_CONTEXT")
    if context not in (None, "", "default"):
        issues.append("custom Docker context in DOCKER_CONTEXT")
    if engine_name in DOCKER_CLIENT_NAMES:
        hosts, contexts, parse_issues = _docker_cli_options(argv)
        issues.extend(parse_issues)
        if any(value not in allowed_hosts for value in hosts):
            issues.append("Docker CLI selects a custom --host/-H endpoint")
        if any(value not in {"", "default"} for value in contexts):
            issues.append("Docker CLI selects a custom --context")
    return sorted(set(issues))


def _processes_for(uids: set[int], docker_gid: int, socket_paths: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    processes: list[dict[str, Any]] = []
    issues: list[str] = []
    try:
        host_namespaces = {
            name: os.readlink(Path("/proc/1/ns") / name) for name in ("mnt", "net", "user")
        }
    except OSError as error:
        raise DockerAdmissionError("host namespace identity is unavailable") from error
    try:
        pids = sorted(int(item.name) for item in Path("/proc").iterdir() if item.name.isdigit())
    except OSError as error:
        raise DockerAdmissionError("process table enumeration is unavailable") from error
    for pid in pids:
        root = Path("/proc") / str(pid)
        try:
            first_stat = str(_read_proc_file(root / "stat"))
            start = _proc_start(first_stat)
            uid, groups = _status_ids(str(_read_proc_file(root / "status")))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError, DockerAdmissionError) as error:
            # A process that still exists but cannot be classified makes the
            # credential census incomplete.  Exited processes are harmless.
            if root.exists():
                issues.append(f"process {pid} could not be classified: {type(error).__name__}")
            continue
        if uid not in uids:
            continue
        try:
            namespaces = {
                name: os.readlink(root / "ns" / name) for name in ("mnt", "net", "user")
            }
            environ_raw = _read_proc_file(root / "environ", binary=True)
            assert isinstance(environ_raw, bytes)
            environment = _environment_fields(environ_raw)
            cmdline_raw = _read_proc_file(root / "cmdline", binary=True)
            assert isinstance(cmdline_raw, bytes)
            argv = _nul_fields(cmdline_raw, label="process command line")
            executable = os.readlink(root / "exe")
            fd_names = sorted((root / "fd").iterdir(), key=lambda item: int(item.name))
            fds: list[dict[str, Any]] = []
            for fd_path in fd_names:
                try:
                    target = os.readlink(fd_path)
                except FileNotFoundError:
                    continue
                fds.append({"fd": int(fd_path.name), "target": target})
            second_stat = str(_read_proc_file(root / "stat"))
            if _proc_start(second_stat) != start:
                raise DockerAdmissionError("process PID was reused during observation")
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError, DockerAdmissionError) as error:
            if root.exists():
                issues.append(f"process {pid} observation was incomplete: {type(error).__name__}")
            continue
        if namespaces != host_namespaces:
            issues.append(f"process {pid} uses a non-host namespace")
        for detail in _process_context_issues(
            executable=executable,
            argv=argv,
            environment=environment,
            socket_paths=socket_paths,
        ):
            issues.append(f"process {pid} {detail}")
        # Direct pathname FDs are observable. Connected anonymous Unix
        # sockets are covered by the privileged ss census below.
        docker_fds = [fd for fd in fds if fd["target"] in socket_paths]
        processes.append(
            {
                "pid": pid,
                "start_ticks": start,
                "uid": uid,
                "groups": groups,
                "namespaces": namespaces,
                "executable": executable,
                "docker_group_retained": docker_gid in groups,
                "docker_fds": docker_fds,
            }
        )
    return processes, issues


def _ss_connections(socket_paths: set[str], uids: set[int]) -> tuple[list[dict[str, int]], list[str]]:
    executable = Path("/usr/bin/ss")
    try:
        _safe_executable(executable)
    except (OSError, DockerAdmissionError) as error:
        return [], [f"privileged Unix-socket connection census unavailable: {type(error).__name__}"]
    completed = subprocess.run(
        [str(executable), "-H", "-x", "-a", "-p"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        text=True,
    )
    if completed.returncode != 0:
        return [], ["privileged Unix-socket connection census failed"]
    connections: list[dict[str, int]] = []
    issues: list[str] = []
    for line in completed.stdout.splitlines():
        if not any(path in line for path in socket_paths):
            continue
        columns = line.split()
        states = {value.upper() for value in columns[:3]}
        listener = bool(states.intersection({"LISTEN", "UNCONN"}))
        connected = bool(states.intersection({"ESTAB", "CONNECTED", "CONNECTING"}))
        if not listener and not connected:
            issues.append("a Docker socket record has an unknown connection state")
        matches = sorted(set(re.findall(r"pid=(\d+),fd=(\d+)", line)))
        if not matches:
            issues.append("a Docker socket connection lacks process attribution")
            continue
        classified = 0
        target_matches = 0
        for pid_raw, fd_raw in matches:
            pid = int(pid_raw)
            try:
                first_start = _proc_start(str(_read_proc_file(Path("/proc") / str(pid) / "stat")))
                status = str(_read_proc_file(Path("/proc") / str(pid) / "status"))
                uid, _groups = _status_ids(status)
                start = _proc_start(str(_read_proc_file(Path("/proc") / str(pid) / "stat")))
                if start != first_start:
                    raise DockerAdmissionError("Docker connection PID was reused")
            except FileNotFoundError:
                issues.append(f"Docker connection process {pid} exited during attribution")
                continue
            except (OSError, UnicodeError, ValueError, DockerAdmissionError) as error:
                issues.append(f"Docker connection process {pid} is unclassified: {type(error).__name__}")
                continue
            classified += 1
            if uid in uids:
                target_matches += 1
                connections.append({"pid": pid, "start_ticks": start, "fd": int(fd_raw), "uid": uid})
        if connected and target_matches == 0 and classified < 2:
            # A single daemon-side users record does not identify the anonymous
            # peer. It could be one of the clients whose direct authority is
            # being removed, so convergence must fail closed.
            issues.append("a connected Docker socket has an unattributed anonymous peer")
    return sorted(connections, key=lambda item: (item["pid"], item["fd"])), issues


def _docker_context_issues(account: pwd.struct_passwd) -> list[str]:
    issues: list[str] = []
    alternate_sockets = (
        Path(f"/run/user/{account.pw_uid}/docker.sock"),
        Path(f"/run/user/{account.pw_uid}/podman/podman.sock"),
        Path(account.pw_dir) / ".docker/run/docker.sock",
        Path(account.pw_dir) / ".docker/desktop/docker.sock",
        Path(account.pw_dir) / ".orbstack/run/docker.sock",
        Path(account.pw_dir) / ".colima/default/docker.sock",
    )
    for candidate in alternate_sockets:
        if candidate.exists() or candidate.is_symlink():
            issues.append(
                f"client {account.pw_name} has an alternate/rootless container socket: {candidate}"
            )
    config = Path(account.pw_dir) / ".docker" / "config.json"
    if config.exists() or config.is_symlink():
        try:
            info = config.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != account.pw_uid or info.st_size > 1024 * 1024:
                raise DockerAdmissionError("Docker client config identity is unsafe")
            document = json.loads(config.read_bytes())
            if not isinstance(document, dict):
                raise DockerAdmissionError("Docker client config is not an object")
            if document.get("currentContext") not in (None, "", "default"):
                issues.append(f"client {account.pw_name} selects a custom Docker context")
        except (OSError, UnicodeError, json.JSONDecodeError, DockerAdmissionError) as error:
            issues.append(f"client {account.pw_name} Docker context coverage is incomplete: {type(error).__name__}")
    contexts = Path(account.pw_dir) / ".docker" / "contexts" / "meta"
    if contexts.exists() or contexts.is_symlink():
        try:
            entries = list(contexts.iterdir())
        except OSError:
            issues.append(f"client {account.pw_name} Docker context directory is unreadable")
        else:
            if entries:
                issues.append(f"client {account.pw_name} has custom Docker contexts")
    return issues


def observe_host(request: Mapping[str, Any]) -> dict[str, Any]:
    """Capture the complete fail-closed host access proof for one request."""

    request = _validate_request(request)
    try:
        docker_group = grp.getgrnam(DOCKER_GROUP)
    except KeyError as error:
        raise DockerAdmissionError("the docker NSS group is unavailable") from error
    clients: list[dict[str, Any]] = []
    issues: list[str] = []
    target_uids = {int(item["uid"]) for item in request["clients"]}
    target_users = {str(item["user"]) for item in request["clients"]}
    all_groups = {entry.gr_name: entry for entry in grp.getgrall()}
    for expected in request["clients"]:
        try:
            account = pwd.getpwnam(expected["user"])
            uid_account = pwd.getpwuid(expected["uid"])
        except KeyError:
            issues.append(f"client {expected['user']} is absent from NSS")
            continue
        if account.pw_name != uid_account.pw_name or (account.pw_uid, account.pw_gid) != (expected["uid"], expected["primary_gid"]):
            issues.append(f"client {expected['user']} NSS identity changed")
            continue
        try:
            gids = sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))
        except OSError:
            issues.append(f"client {account.pw_name} supplementary groups are unavailable")
            continue
        names = sorted(name for name, entry in all_groups.items() if entry.gr_gid in gids)
        bypass = sorted(GID_BYPASS_GROUPS.intersection(names))
        if bypass:
            issues.append(f"client {account.pw_name} retains privileged bypass groups: {','.join(bypass)}")
        if account.pw_gid == docker_group.gr_gid:
            issues.append(f"client {account.pw_name} uses docker as its primary group")
        if docker_group.gr_gid in gids and account.pw_name not in docker_group.gr_mem:
            issues.append(f"client {account.pw_name} Docker membership is not an exact removable gr_mem grant")
        issues.extend(_docker_context_issues(account))
        clients.append(
            {
                "user": account.pw_name,
                "uid": account.pw_uid,
                "primary_gid": account.pw_gid,
                "supplementary_gids": gids,
                "supplementary_groups": names,
                "docker_group_configured": account.pw_name in docker_group.gr_mem,
            }
        )
    if {item["uid"] for item in clients} != target_uids or {item["user"] for item in clients} != target_users:
        issues.append("the complete declared client identity set was not observed")
    sockets: list[dict[str, Any]] = []
    acl_entries: dict[str, list[dict[str, Any]]] = {}
    resolved_paths: set[str] = set()
    for raw in request["socket_paths"]:
        path = Path(raw)
        try:
            identity = _socket_identity(path)
            acl = _acl_for(path)
        except (OSError, DockerAdmissionError) as error:
            issues.append(f"Docker socket {path} is not completely observable: {type(error).__name__}")
            continue
        sockets.append(identity)
        resolved_paths.add(identity["resolved"])
        resolved_paths.add(str(path))
        acl_entries[str(path)] = acl
    if len(sockets) != len(request["socket_paths"]):
        issues.append("the complete Docker socket set was not observed")
    configured_acl_keys = {
        (str(item["path"]), str(item["tag"]), str(item["qualifier"]))
        for item in request["acl_grants"]
    }
    seen_acl_keys: set[tuple[str, str, str]] = set()
    for path, entries in acl_entries.items():
        for entry in entries:
            qualifier = entry["qualifier"]
            if entry["tag"] == "user" and qualifier:
                try:
                    qualifier_uid = pwd.getpwnam(qualifier).pw_uid if not qualifier.isdigit() else int(qualifier)
                except KeyError:
                    continue
                if qualifier_uid in target_uids:
                    key = (path, "user", str(qualifier_uid))
                    seen_acl_keys.add(key)
                    if key not in configured_acl_keys:
                        issues.append(f"Docker socket {path} has an undeclared client ACL grant")
            elif entry["tag"] == "group" and qualifier == DOCKER_GROUP:
                key = (path, "group", DOCKER_GROUP)
                seen_acl_keys.add(key)
                if key not in configured_acl_keys:
                    issues.append(f"Docker socket {path} has an undeclared docker-group ACL grant")
    missing_declared = configured_acl_keys - seen_acl_keys
    processes, process_issues = _processes_for(target_uids, docker_group.gr_gid, resolved_paths)
    connections, connection_issues = _ss_connections(resolved_paths, target_uids)
    issues.extend(process_issues)
    issues.extend(connection_issues)
    actions: list[dict[str, Any]] = []
    for client in sorted(clients, key=lambda item: item["uid"]):
        if client["docker_group_configured"]:
            actions.append(
                {
                    "kind": "nss_group_remove",
                    "user": client["user"],
                    "uid": client["uid"],
                    "group": DOCKER_GROUP,
                    "argv": [str(FIXED_GPASSWD), "-d", client["user"], DOCKER_GROUP],
                }
            )
    for grant in sorted(request["acl_grants"], key=lambda item: (item["path"], item["tag"], str(item["qualifier"]))):
        entries = acl_entries.get(str(grant["path"]), [])
        desired_qualifier = str(grant["qualifier"])
        for entry in entries:
            qualifier = entry["qualifier"]
            if grant["tag"] == "user" and qualifier and not qualifier.isdigit():
                try:
                    qualifier = str(pwd.getpwnam(qualifier).pw_uid)
                except KeyError:
                    continue
            if entry["tag"] == grant["tag"] and qualifier == desired_qualifier:
                spec = ("u" if grant["tag"] == "user" else "g") + f":{desired_qualifier}"
                actions.append(
                    {
                        "kind": "acl_remove",
                        "path": str(grant["path"]),
                        "tag": grant["tag"],
                        "qualifier": grant["qualifier"],
                        "permissions": entry["permissions"],
                        "argv": [str(FIXED_SETFACL), "-x", spec, "--", str(grant["path"])],
                    }
                )
                break
    configured = {
        "docker_group_gid": docker_group.gr_gid,
        "docker_group_members": sorted(name for name in docker_group.gr_mem if name in target_users),
        "clients": clients,
        "sockets": sockets,
        "acl_entries": acl_entries,
        "missing_declared_acl_grants": [list(item) for item in sorted(missing_declared)],
        "actions": actions,
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "devcoordinator-docker-admission-observation",
        "request_sha256": request["document_sha256"],
        "configured": configured,
        "configured_sha256": _configured_fingerprint(configured),
        "processes": processes,
        "docker_connections": connections,
        "issues": sorted(set(issues)),
        "observed_at_epoch": int(time.time()),
    }
    return _seal(result)


def _validate_observation(document: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, Any]:
    observation = _validate_seal(document, label="Docker admission observation")
    if observation.get("schema_version") != SCHEMA_VERSION or observation.get("kind") != "devcoordinator-docker-admission-observation":
        raise DockerAdmissionError("Docker admission observation contract is invalid")
    if observation.get("request_sha256") != request["document_sha256"]:
        raise DockerAdmissionError("Docker admission observation belongs to another request")
    configured = observation.get("configured")
    if not isinstance(configured, dict) or _configured_fingerprint(configured) != observation.get("configured_sha256"):
        raise DockerAdmissionError("Docker admission configured-state binding is invalid")
    if not isinstance(observation.get("issues"), list) or not isinstance(observation.get("processes"), list) or not isinstance(observation.get("docker_connections"), list):
        raise DockerAdmissionError("Docker admission live observation fields are invalid")
    return observation


def _action_key(action: Mapping[str, Any]) -> tuple[Any, ...]:
    if action.get("kind") == "nss_group_remove":
        return ("nss", action.get("uid"), action.get("user"), action.get("group"))
    if action.get("kind") == "acl_remove":
        return ("acl", action.get("path"), action.get("tag"), str(action.get("qualifier")))
    raise DockerAdmissionError("Docker admission action kind is invalid")


def _validate_action(action: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(action)
    kind = value.get("kind")
    argv = value.get("argv")
    if kind == "nss_group_remove":
        if set(value) != {"kind", "user", "uid", "group", "argv"}:
            raise DockerAdmissionError("NSS removal action fields are invalid")
        expected = [str(FIXED_GPASSWD), "-d", value["user"], DOCKER_GROUP]
        if value["group"] != DOCKER_GROUP or not SAFE_NAME_RE.fullmatch(str(value["user"])) or type(value["uid"]) is not int:
            raise DockerAdmissionError("NSS removal action identity is invalid")
    elif kind == "acl_remove":
        if set(value) != {"kind", "path", "tag", "qualifier", "permissions", "argv"}:
            raise DockerAdmissionError("ACL removal action fields are invalid")
        prefix = "u" if value["tag"] == "user" else "g" if value["tag"] == "group" else None
        if prefix is None or not re.fullmatch(r"[r-][w-][x-]", str(value["permissions"])):
            raise DockerAdmissionError("ACL removal action identity is invalid")
        expected = [str(FIXED_SETFACL), "-x", f"{prefix}:{value['qualifier']}", "--", str(_absolute(value["path"], "ACL action path"))]
    else:
        raise DockerAdmissionError("Docker admission action kind is invalid")
    if argv != expected:
        raise DockerAdmissionError("Docker admission action argv is not the fixed command")
    return value


def _action_present(action: Mapping[str, Any], observation: Mapping[str, Any]) -> bool:
    configured = observation["configured"]
    if action["kind"] == "nss_group_remove":
        return action["user"] in configured["docker_group_members"]
    for entry in configured["acl_entries"].get(action["path"], []):
        qualifier = entry.get("qualifier")
        if action["tag"] == "user" and qualifier and not str(qualifier).isdigit():
            try:
                qualifier = str(pwd.getpwnam(str(qualifier)).pw_uid)
            except KeyError:
                continue
        if entry.get("tag") == action["tag"] and str(qualifier) == str(action["qualifier"]):
            return True
    return False


def _action_removed(action: Mapping[str, Any], observation: Mapping[str, Any]) -> bool:
    return not _action_present(action, observation)


def _run_fixed(argv: Sequence[str]) -> None:
    if not argv or Path(argv[0]) not in {FIXED_GPASSWD, FIXED_SETFACL}:
        raise DockerAdmissionError("refusing an unapproved Docker admission command")
    _safe_executable(Path(argv[0]))
    completed = subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        text=True,
    )
    if completed.returncode != 0:
        raise DockerAdmissionError(f"configured grant mutation failed: {completed.stderr.strip()[:256]}")


def _restore_argv(action: Mapping[str, Any]) -> list[str]:
    if action["kind"] == "nss_group_remove":
        return [str(FIXED_GPASSWD), "-a", action["user"], DOCKER_GROUP]
    prefix = "u" if action["tag"] == "user" else "g"
    return [
        str(FIXED_SETFACL),
        "-m",
        f"{prefix}:{action['qualifier']}:{action['permissions']}",
        "--",
        action["path"],
    ]


def _socket_stable(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]], *, include_ctime: bool) -> bool:
    fields = ("path", "resolved", "device", "inode", "uid", "gid", "mode") + (("ctime_ns",) if include_ctime else ())
    left = [{key: item[key] for key in fields} for item in before]
    right = [{key: item[key] for key in fields} for item in after]
    return left == right


def _configured_fingerprint(configured: Mapping[str, Any]) -> str:
    """Hash durable grants while excluding expected socket ctime changes."""

    sockets = [
        {key: item[key] for key in ("path", "resolved", "device", "inode", "uid", "gid", "mode")}
        for item in configured["sockets"]
    ]
    durable = {
        "docker_group_gid": configured["docker_group_gid"],
        "docker_group_members": configured["docker_group_members"],
        "clients": configured["clients"],
        "sockets": sockets,
        "acl_entries": configured["acl_entries"],
        "missing_declared_acl_grants": configured["missing_declared_acl_grants"],
    }
    return _sha256(_canonical(durable))


def _plan_binding(
    *, request_sha256: str, plan_id: str, observation: Mapping[str, Any], actions: Sequence[Mapping[str, Any]]
) -> str:
    return _sha256(
        _canonical(
            {
                "request_sha256": request_sha256,
                "plan_id": plan_id,
                "observation_sha256": observation["document_sha256"],
                "actions": list(actions),
            }
        )
    )


def _apply_binding(journal: Mapping[str, Any], observation: Mapping[str, Any]) -> str:
    return _sha256(
        _canonical(
            {
                "plan_sha256": journal["plan_sha256"],
                "actions": [
                    {key: value for key, value in item.items() if key != "status"}
                    for item in journal["actions"]
                ],
                "post_mutation_observation_sha256": observation["document_sha256"],
            }
        )
    )


@dataclass
class ExecutionHooks:
    observe: Callable[[Mapping[str, Any]], dict[str, Any]] = observe_host
    verify_profile: Callable[[Mapping[str, Any]], dict[str, Any]] = _verify_request_profile_binding
    mutate: Callable[[Sequence[str]], None] = _run_fixed
    deny_connect: Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]] | None = None
    broker_canary: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None
    failpoint: Callable[[str], None] = lambda _name: None


def _journal_paths(transaction: Path) -> tuple[Path, Path]:
    return transaction / "journal.json", transaction / "terminal.json"


def _load_journal(transaction: Path) -> dict[str, Any]:
    journal_path, _terminal = _journal_paths(transaction)
    journal = _validate_seal(_read_private(journal_path, "Docker admission journal"), label="Docker admission journal")
    if journal.get("schema_version") != SCHEMA_VERSION or journal.get("kind") != JOURNAL_KIND:
        raise DockerAdmissionError("Docker admission journal contract is invalid")
    return journal


def _write_journal(transaction: Path, journal: Mapping[str, Any]) -> dict[str, Any]:
    sealed = _seal({key: value for key, value in journal.items() if key != "document_sha256"})
    journal_path, _terminal = _journal_paths(transaction)
    _write_private(journal_path, sealed, replace=journal_path.exists())
    return sealed


def plan_transaction(
    request: Mapping[str, Any],
    *,
    transaction: Path,
    hooks: ExecutionHooks | None = None,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> dict[str, Any]:
    _require_root()
    hooks = ExecutionHooks() if hooks is None else hooks
    request = _validate_request(request)
    transaction = _absolute(transaction, "Docker admission transaction")
    _require_private_dir(transaction, create=True)
    journal_path, terminal_path = _journal_paths(transaction)
    handle = acquire_transaction_fence(
        owner_kind=OWNER_KIND,
        operation_id=request["operation_id"],
        transaction=journal_path,
        terminal=terminal_path,
        action="prepare",
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        lock_path=lock_path,
        claim_path=claim_path,
    )
    succeeded = False
    try:
        hooks.verify_profile(request)
        if journal_path.exists() or journal_path.is_symlink():
            raise DockerAdmissionError("Docker admission transaction already exists")
        observation = _validate_observation(hooks.observe(request), request)
        actions = [_validate_action(item) for item in observation["configured"]["actions"]]
        if len({_action_key(item) for item in actions}) != len(actions):
            raise DockerAdmissionError("Docker admission plan contains duplicate actions")
        plan_id = str(uuid.uuid4())
        plan_actions = [dict(item) for item in actions]
        plan_sha256 = _plan_binding(
            request_sha256=request["document_sha256"],
            plan_id=plan_id,
            observation=observation,
            actions=plan_actions,
        )
        plan_issues = list(observation["issues"])
        if observation["configured"]["missing_declared_acl_grants"]:
            plan_issues.append("declared Docker socket ACL grants are absent")
        journal = _seal(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": JOURNAL_KIND,
                "operation_id": request["operation_id"],
                "request": request,
                "request_sha256": request["document_sha256"],
                "phase": "planned" if not plan_issues else "blocked",
                "plan_id": plan_id,
                "plan_sha256": plan_sha256,
                "plan_observation": observation,
                "configured_sha256": observation["configured_sha256"],
                "actions": [dict(item, status="pending") for item in actions],
                "post_mutation_observation": None,
                "apply_sha256": None,
                "rollback_observation": None,
                "created_at_epoch": int(time.time()),
                "updated_at_epoch": int(time.time()),
            }
        )
        _write_private(journal_path, journal, replace=False)
        if plan_issues:
            terminal = _seal(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": TERMINAL_KIND,
                    "operation_id": request["operation_id"],
                    "outcome": "blocked",
                    "journal_sha256": journal["document_sha256"],
                    "completed_at_epoch": int(time.time()),
                }
            )
            _write_private(terminal_path, terminal, replace=False)
            handle.mark_complete()
        succeeded = True
        return {
            "ok": not plan_issues,
            "kind": "devcoordinator-docker-admission-plan",
            "classification": "ready" if not plan_issues else "blocked",
            "operation_id": request["operation_id"],
            "plan_id": journal["plan_id"],
            "plan_sha256": journal["plan_sha256"],
            "actions": len(actions),
            "issues": plan_issues,
        }
    finally:
        handle.close(command_succeeded=succeeded)


def _resume_handle(transaction: Path, journal: Mapping[str, Any], action: str, lock_path: Path, claim_path: Path):
    journal_path, terminal_path = _journal_paths(transaction)
    return acquire_transaction_fence(
        owner_kind=OWNER_KIND,
        operation_id=journal["operation_id"],
        transaction=journal_path,
        terminal=terminal_path,
        action=action,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        lock_path=lock_path,
        claim_path=claim_path,
    )


def apply_transaction(
    *, transaction: Path, plan_id: str, plan_sha256: str,
    hooks: ExecutionHooks | None = None,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> dict[str, Any]:
    _require_root()
    hooks = ExecutionHooks() if hooks is None else hooks
    transaction = _absolute(transaction, "Docker admission transaction")
    _require_private_dir(transaction)
    journal = _load_journal(transaction)
    if journal["plan_id"] != plan_id or journal["plan_sha256"] != plan_sha256:
        raise DockerAdmissionError("Docker admission plan binding changed")
    if journal["phase"] == "blocked":
        raise DockerAdmissionError("blocked Docker admission plan cannot be applied")
    if journal["phase"] not in {"planned", "applying", "awaiting_session_convergence"}:
        raise DockerAdmissionError("Docker admission transaction is not applicable")
    handle = _resume_handle(transaction, journal, "recover", lock_path, claim_path)
    succeeded = False
    try:
        request = _validate_request(journal["request"])
        hooks.verify_profile(request)
        observation = _validate_observation(hooks.observe(request), request)
        if observation["issues"]:
            raise DockerAdmissionError("host observation is incomplete before mutation: " + "; ".join(observation["issues"][:3]))
        if journal["phase"] in {"planned", "applying"}:
            if observation["configured_sha256"] != journal["configured_sha256"]:
                # Recovery may see already-removed grants.  Other configured
                # drift is rejected below action-by-action and socket identity.
                planned_sockets = journal["plan_observation"]["configured"]["sockets"]
                if not _socket_stable(planned_sockets, observation["configured"]["sockets"], include_ctime=False):
                    raise DockerAdmissionError("Docker socket identity changed before apply recovery")
            journal["phase"] = "applying"
            journal["updated_at_epoch"] = int(time.time())
            journal = _write_journal(transaction, journal)
            for index, stored in enumerate(list(journal["actions"])):
                action = _validate_action({key: value for key, value in stored.items() if key != "status"})
                current = _validate_observation(hooks.observe(request), request)
                if current["issues"]:
                    raise DockerAdmissionError("host observation became incomplete during apply")
                if _action_removed(action, current):
                    journal["actions"][index]["status"] = "applied"
                    journal["updated_at_epoch"] = int(time.time())
                    journal = _write_journal(transaction, journal)
                    continue
                if stored["status"] == "applied":
                    raise DockerAdmissionError("an applied configured grant reappeared")
                hooks.mutate(action["argv"])
                hooks.failpoint(f"after-action-{index}")
                after = _validate_observation(hooks.observe(request), request)
                if not _action_removed(action, after):
                    raise DockerAdmissionError("configured grant mutation did not take effect")
                journal["actions"][index]["status"] = "applied"
                journal["updated_at_epoch"] = int(time.time())
                journal = _write_journal(transaction, journal)
        post = _validate_observation(hooks.observe(request), request)
        if post["issues"]:
            raise DockerAdmissionError("post-mutation host observation is incomplete")
        if any(not _action_removed(_validate_action({key: value for key, value in item.items() if key != "status"}), post) for item in journal["actions"]):
            raise DockerAdmissionError("not every configured Docker grant was removed")
        if journal["post_mutation_observation"] is not None:
            previous = journal["post_mutation_observation"]
            if not _socket_stable(previous["configured"]["sockets"], post["configured"]["sockets"], include_ctime=True):
                raise DockerAdmissionError("Docker socket was recreated after grant removal")
        journal["post_mutation_observation"] = post
        journal["apply_sha256"] = _apply_binding(journal, post)
        journal["phase"] = "awaiting_session_convergence"
        journal["updated_at_epoch"] = int(time.time())
        journal = _write_journal(transaction, journal)
        retained = _retained_authority(post)
        succeeded = True
        return {
            "ok": True,
            "kind": "devcoordinator-docker-admission-apply",
            "classification": "awaiting_session_convergence",
            "operation_id": journal["operation_id"],
            "plan_id": journal["plan_id"],
            "apply_sha256": journal["apply_sha256"],
            "retained_sessions": retained,
        }
    finally:
        handle.close(command_succeeded=succeeded)


def _retained_authority(observation: Mapping[str, Any]) -> list[dict[str, Any]]:
    retained: list[dict[str, Any]] = []
    for process in observation["processes"]:
        if process.get("docker_group_retained") or process.get("docker_fds"):
            retained.append({
                "pid": process["pid"],
                "start_ticks": process["start_ticks"],
                "uid": process["uid"],
                "reason": "retained_docker_group" if process.get("docker_group_retained") else "open_docker_fd",
            })
    for connection in observation["docker_connections"]:
        retained.append({**connection, "reason": "open_docker_connection"})
    return sorted(retained, key=lambda item: (item["uid"], item["pid"], item["reason"]))


def _deny_connect_real(client: Mapping[str, Any], socket_identity: Mapping[str, Any]) -> dict[str, Any]:
    read_fd, write_fd = os.pipe2(getattr(os, "O_CLOEXEC", 0))
    pid = os.fork()
    if pid == 0:  # pragma: no cover - parent validates one bounded reply
        try:
            os.close(read_fd)
            os.setgroups([])
            os.setgid(int(client["primary_gid"]))
            os.setuid(int(client["uid"]))
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(3)
                probe.connect(str(socket_identity["resolved"]))
            except OSError as error:
                payload = _canonical({"connected": False, "errno": error.errno})
            else:
                payload = _canonical({"connected": True, "errno": None})
            finally:
                probe.close()
            os.write(write_fd, payload[:1024])
        except BaseException:
            try:
                os.write(write_fd, b'{"probe_error":true}')
            except OSError:
                pass
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        raw = os.read(read_fd, 1024)
    finally:
        os.close(read_fd)
    _completed, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise DockerAdmissionError("fresh-connect denial child failed")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DockerAdmissionError("fresh-connect denial result is invalid") from error
    if result.get("connected") is not False or result.get("errno") not in {errno.EACCES, errno.EPERM}:
        raise DockerAdmissionError("a fresh client can still connect directly to Docker")
    return {"uid": client["uid"], "socket": socket_identity["resolved"], "denied": True, "errno": result["errno"]}


def _require_immutable_client(path: Path) -> dict[str, Any]:
    return _release_client_proof(path)


def _broker_canary_real(canary: Mapping[str, Any]) -> dict[str, Any]:
    client_path = Path(canary["client_path"])
    proof = _require_immutable_client(client_path)
    if any(canary[key] != proof[key] for key in (
        "release_digest", "client_sha256", "manifest_sha256"
    )):
        raise DockerAdmissionError("broker canary client no longer matches its sealed release")
    for executable in (FIXED_SETPRIV, FIXED_PYTHON):
        _safe_executable(executable)
    command = [
        str(FIXED_SETPRIV),
        f"--reuid={canary['uid']}",
        f"--regid={canary['primary_gid']}",
        "--clear-groups",
        str(FIXED_PYTHON),
        "-I",
        "-B",
        str(client_path),
        "inventory",
        "--project",
        canary["project"],
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        cwd="/",
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": pwd.getpwuid(canary["uid"]).pw_dir,
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
    )
    if completed.returncode != 0:
        raise DockerAdmissionError(f"broker inventory canary failed: {completed.stderr.strip()[:256]}")
    output = _strict_json(
        completed.stdout.encode("utf-8", errors="strict"),
        label="broker inventory canary",
    )
    authority = output.get("authority") if isinstance(output, dict) else None
    repositories = output.get("repositories") if isinstance(output, dict) else None
    if not isinstance(authority, dict) or authority.get("scope") != "server-wide" or authority.get("transport") != "authenticated-unix-socket" or authority.get("generation") != canary["authority_generation"]:
        raise DockerAdmissionError("broker inventory canary authority binding is invalid")
    matches = [item for item in repositories or [] if isinstance(item, dict) and item.get("repo_id") == canary["repository_id"]]
    if len(matches) != 1 or matches[0].get("canonical_root") != canary["project"] or matches[0].get("generation") != canary["repository_generation"] or matches[0].get("owner_uid") != canary["uid"]:
        raise DockerAdmissionError("broker inventory canary repository binding is invalid")
    return {
        "ok": True,
        "authority_generation": authority["generation"],
        "repository_id": matches[0]["repo_id"],
        "profile_sha256": canary["profile_sha256"],
        **proof,
    }


def verify_transaction(
    *, transaction: Path, apply_sha256: str,
    hooks: ExecutionHooks | None = None,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> dict[str, Any]:
    _require_root()
    hooks = ExecutionHooks() if hooks is None else hooks
    transaction = _absolute(transaction, "Docker admission transaction")
    _require_private_dir(transaction)
    journal = _load_journal(transaction)
    if journal["phase"] != "awaiting_session_convergence" or journal["apply_sha256"] != apply_sha256:
        raise DockerAdmissionError("Docker admission apply binding changed or is not awaiting verification")
    handle = _resume_handle(transaction, journal, "finalize", lock_path, claim_path)
    succeeded = False
    try:
        request = _validate_request(journal["request"])
        hooks.verify_profile(request)
        observation = _validate_observation(hooks.observe(request), request)
        if observation["issues"]:
            raise DockerAdmissionError("host observation is incomplete during verification: " + "; ".join(observation["issues"][:3]))
        if not _socket_stable(journal["post_mutation_observation"]["configured"]["sockets"], observation["configured"]["sockets"], include_ctime=True):
            raise DockerAdmissionError("Docker socket was recreated after admission mutation")
        for stored in journal["actions"]:
            action = _validate_action({key: value for key, value in stored.items() if key != "status"})
            if stored["status"] != "applied" or not _action_removed(action, observation):
                raise DockerAdmissionError("a configured Docker access grant is present")
        retained = _retained_authority(observation)
        if retained:
            succeeded = True
            return {
                "ok": False,
                "kind": "devcoordinator-docker-admission-verification",
                "classification": "awaiting_session_convergence",
                "operation_id": journal["operation_id"],
                "retained_sessions": retained,
            }
        deny = hooks.deny_connect or _deny_connect_real
        denial_evidence = [
            deny(client, socket_identity)
            for client in request["clients"]
            for socket_identity in observation["configured"]["sockets"]
        ]
        canary = (hooks.broker_canary or _broker_canary_real)(request["broker_canary"])
        terminal = _seal(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": TERMINAL_KIND,
                "operation_id": journal["operation_id"],
                "outcome": "verified",
                "journal_sha256": journal["document_sha256"],
                "observation_sha256": observation["document_sha256"],
                "fresh_connect_denials": denial_evidence,
                "broker_canary": canary,
                "completed_at_epoch": int(time.time()),
            }
        )
        _write_private(_journal_paths(transaction)[1], terminal, replace=False)
        handle.mark_complete()
        succeeded = True
        return {
            "ok": True,
            "kind": "devcoordinator-docker-admission-verification",
            "classification": "broker_only",
            "operation_id": journal["operation_id"],
            "terminal_sha256": terminal["document_sha256"],
            "fresh_connect_denials": len(denial_evidence),
            "broker_canary": canary,
        }
    finally:
        handle.close(command_succeeded=succeeded)


def rollback_transaction(
    *, transaction: Path, apply_sha256: str,
    hooks: ExecutionHooks | None = None,
    lock_path: Path = DEFAULT_INSTALLER_LOCK,
    claim_path: Path = DEFAULT_INSTALLER_CLAIM,
) -> dict[str, Any]:
    _require_root()
    hooks = ExecutionHooks() if hooks is None else hooks
    transaction = _absolute(transaction, "Docker admission transaction")
    _require_private_dir(transaction)
    journal = _load_journal(transaction)
    if journal["phase"] not in {"applying", "awaiting_session_convergence", "rolling_back"}:
        raise DockerAdmissionError("Docker admission apply binding changed or is not rollback eligible")
    if journal["apply_sha256"] is not None and journal["apply_sha256"] != apply_sha256:
        raise DockerAdmissionError("Docker admission apply binding changed or is not rollback eligible")
    if journal["apply_sha256"] is None and apply_sha256 != journal["plan_sha256"]:
        raise DockerAdmissionError("incomplete Docker admission apply requires its stable plan binding")
    handle = _resume_handle(transaction, journal, "abort", lock_path, claim_path)
    succeeded = False
    try:
        request = _validate_request(journal["request"])
        hooks.verify_profile(request)
        current = _validate_observation(hooks.observe(request), request)
        if current["issues"]:
            raise DockerAdmissionError("host observation is incomplete before rollback")
        if journal["post_mutation_observation"] is not None and not _socket_stable(
            journal["post_mutation_observation"]["configured"]["sockets"],
            current["configured"]["sockets"],
            include_ctime=journal["phase"] != "rolling_back",
        ):
            raise DockerAdmissionError("Docker socket changed before rollback")
        journal["phase"] = "rolling_back"
        journal["updated_at_epoch"] = int(time.time())
        journal = _write_journal(transaction, journal)
        for reverse_index, stored in enumerate(reversed(journal["actions"])):
            index = len(journal["actions"]) - reverse_index - 1
            action = _validate_action({key: value for key, value in stored.items() if key != "status"})
            current = _validate_observation(hooks.observe(request), request)
            present = _action_present(action, current)
            if stored["status"] == "rolled_back":
                if not present:
                    raise DockerAdmissionError("a rolled-back Docker grant disappeared")
                continue
            if stored["status"] == "pending":
                if present:
                    journal["actions"][index]["status"] = "rolled_back"
                    journal = _write_journal(transaction, journal)
                    continue
                raise DockerAdmissionError("an unapplied Docker grant changed before rollback")
            if stored["status"] == "applied" and present:
                # The restore command may have completed before a crash made
                # its reply durable. Exact observed presence is its replay
                # acknowledgement; no second mutation is issued.
                journal["actions"][index]["status"] = "rolled_back"
                journal["updated_at_epoch"] = int(time.time())
                journal = _write_journal(transaction, journal)
                continue
            if stored["status"] != "applied" or present:
                raise DockerAdmissionError("Docker admission rollback state drifted")
            restore = _restore_argv(action)
            hooks.mutate(restore)
            hooks.failpoint(f"after-rollback-action-{index}")
            after = _validate_observation(hooks.observe(request), request)
            if not _action_present(action, after):
                raise DockerAdmissionError("Docker configured grant rollback did not take effect")
            journal["actions"][index]["status"] = "rolled_back"
            journal["updated_at_epoch"] = int(time.time())
            journal = _write_journal(transaction, journal)
        restored = _validate_observation(hooks.observe(request), request)
        planned = journal["plan_observation"]
        if restored["configured_sha256"] != planned["configured_sha256"]:
            raise DockerAdmissionError("Docker admission rollback did not restore exact configured state")
        journal["rollback_observation"] = restored
        journal["phase"] = "rolled_back"
        journal["updated_at_epoch"] = int(time.time())
        journal = _write_journal(transaction, journal)
        terminal = _seal(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": TERMINAL_KIND,
                "operation_id": journal["operation_id"],
                "outcome": "rolled_back",
                "journal_sha256": journal["document_sha256"],
                "observation_sha256": restored["document_sha256"],
                "completed_at_epoch": int(time.time()),
            }
        )
        _write_private(_journal_paths(transaction)[1], terminal, replace=False)
        handle.mark_complete()
        succeeded = True
        return {
            "ok": True,
            "kind": "devcoordinator-docker-admission-rollback",
            "classification": "rolled_back",
            "operation_id": journal["operation_id"],
            "terminal_sha256": terminal["document_sha256"],
        }
    finally:
        handle.close(command_succeeded=succeeded)


def _path(value: str) -> Path:
    try:
        return _absolute(value, "path")
    except DockerAdmissionError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=_path, default=DEFAULT_INSTALLER_LOCK)
    parser.add_argument("--claim", type=_path, default=DEFAULT_INSTALLER_CLAIM)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser(
        "seal-request",
        help="derive and seal the complete client/profile/canary request",
    )
    seal.add_argument("--draft", type=_path, required=True)
    seal.add_argument("--output", type=_path, required=True)
    plan = commands.add_parser("plan", help="seal the exact configured grants to remove")
    plan.add_argument("--request", type=_path, required=True)
    plan.add_argument("--transaction", type=_path, required=True)
    apply = commands.add_parser("apply", help="remove only the sealed configured grants")
    apply.add_argument("--transaction", type=_path, required=True)
    apply.add_argument("--plan-id", required=True)
    apply.add_argument("--plan-sha256", required=True)
    verify = commands.add_parser("verify", help="prove direct denial and broker admission")
    verify.add_argument("--transaction", type=_path, required=True)
    verify.add_argument("--apply-sha256", required=True)
    rollback = commands.add_parser("rollback", help="restore only the exact removed grants")
    rollback.add_argument("--transaction", type=_path, required=True)
    rollback.add_argument("--apply-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "seal-request":
            result = seal_request_file(draft_path=args.draft, output_path=args.output)
        elif args.command == "plan":
            result = plan_transaction(
                load_request(args.request), transaction=args.transaction,
                lock_path=args.lock, claim_path=args.claim,
            )
        elif args.command == "apply":
            result = apply_transaction(
                transaction=args.transaction, plan_id=args.plan_id,
                plan_sha256=args.plan_sha256, lock_path=args.lock, claim_path=args.claim,
            )
        elif args.command == "verify":
            result = verify_transaction(
                transaction=args.transaction, apply_sha256=args.apply_sha256,
                lock_path=args.lock, claim_path=args.claim,
            )
        else:
            result = rollback_transaction(
                transaction=args.transaction, apply_sha256=args.apply_sha256,
                lock_path=args.lock, claim_path=args.claim,
            )
    except (DockerAdmissionError, InstallerFenceError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "code": "docker_admission_failed", "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
