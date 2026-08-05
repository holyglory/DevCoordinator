#!/usr/bin/env python3
"""Release-bound browser LCP acceptance evidence.

The producer is intentionally separate from activation.  It verifies one
content-addressed release and one administrator-locked Playwright runtime,
checks the live edge release identity, executes the immutable browser driver,
and publishes one HMAC-sealed root-private attestation.  Validation is strict,
time-bounded, release-bound, and optionally one-use through a separate
consumption marker.

No cookie, storage-state payload, response body, page text, arbitrary browser
error, or credential is copied into evidence.  Browser execution happens only
through the ``produce`` command; the validation and runtime-lock commands do
not launch Playwright.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping
import uuid
from urllib.parse import urlparse


SCHEMA_VERSION = 1
RELEASE_SCHEMA_VERSION = 1
RUNTIME_LOCK_KIND = "devcoordinator-browser-lcp-runtime-lock"
REQUEST_KIND = "devcoordinator-browser-lcp-request"
OBSERVATION_KIND = "devcoordinator-browser-lcp-observation"
ATTESTATION_KIND = "devcoordinator-browser-lcp-attestation"
CONSUMPTION_KIND = "devcoordinator-browser-lcp-consumption"

DEFAULT_CONSOLE_URL = "https://console.vr.ae/"
DEFAULT_TESTS_URL = "https://console.vr.ae/#/tests"
DEFAULT_IMMUTABLE_ROOT = Path("/opt/devcoordinator/releases")
DEFAULT_TTL_SECONDS = 600
LCP_THRESHOLD_MS = 1000
REQUIRED_VIEWPORTS = (
    {"width": 320, "height": 844},
    {"width": 390, "height": 844},
    {"width": 768, "height": 1024},
    {"width": 981, "height": 1024},
    {"width": 1440, "height": 900},
)
REQUIRED_JOURNEYS = ("console", "tests")

RELEASE_PRODUCER = Path("bin/devcoordinator-browser-lcp")
RELEASE_PRODUCER_SOURCE = Path("scripts/browser_lcp_acceptance.py")
RELEASE_BROWSER_DRIVER = Path(
    "apps/DevOpsConsole/Tools/browser-lcp-producer.mjs"
)
PLAYWRIGHT_MODULE_RELATIVE = Path("node_modules/playwright/index.mjs")
PLAYWRIGHT_PACKAGE_ROOTS = (
    Path("node_modules/playwright"),
    Path("node_modules/playwright-core"),
)

MAX_PRIVATE_JSON_BYTES = 1024 * 1024
MAX_STORAGE_STATE_BYTES = 1024 * 1024
MAX_OBSERVATION_BYTES = 256 * 1024
MAX_RELEASE_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RELEASE_FILES = 10_000
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_FILES = 5_000
MAX_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
MAX_COMMAND_SECONDS = 10
MAX_DRIVER_SECONDS = 120
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 1800
TIMESTAMP_SKEW_SECONDS = 5

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
PRODUCT_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,4}$")
MODE_RE = re.compile(r"^0[0-7]{3}$")


class BrowserLcpAcceptanceError(RuntimeError):
    """Base fail-closed browser acceptance error."""


class BrowserLcpReplayError(BrowserLcpAcceptanceError):
    """Raised when one attestation has already been consumed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BrowserLcpAcceptanceError("evidence is not canonical JSON") from error


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, *, maximum: int = MAX_BINARY_BYTES) -> str:
    try:
        info = path.lstat()
    except OSError as error:
        raise BrowserLcpAcceptanceError(f"required file is unavailable: {path}") from error
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_size > maximum
    ):
        raise BrowserLcpAcceptanceError(f"required file is unsafe or too large: {path}")
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(block)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ):
        raise BrowserLcpAcceptanceError(f"required file changed while hashing: {path}")
    return result.hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str) or len(value) != 24 or not value.endswith("Z"):
        raise BrowserLcpAcceptanceError(f"{label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise BrowserLcpAcceptanceError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None or _format_time(parsed) != value:
        raise BrowserLcpAcceptanceError(f"{label} timestamp is not canonical UTC")
    return parsed


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise BrowserLcpAcceptanceError(f"{label} must be one UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise BrowserLcpAcceptanceError(f"{label} must be one UUID") from error
    if parsed.version != 4 or str(parsed) != value:
        raise BrowserLcpAcceptanceError(f"{label} must be one canonical UUIDv4")
    return value


def _exact_mapping(
    value: object, fields: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise BrowserLcpAcceptanceError(f"{label} fields are invalid")
    return dict(value)


def _absolute(path: str | Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise BrowserLcpAcceptanceError(f"{label} must be one absolute path")
    absolute = Path(os.path.abspath(candidate))
    try:
        if absolute.resolve(strict=True) != absolute:
            raise BrowserLcpAcceptanceError(f"{label} must already be canonical")
    except OSError as error:
        raise BrowserLcpAcceptanceError(f"{label} is unavailable") from error
    return absolute


def _trusted_uid(expected_uid: int | None) -> int:
    uid = os.getuid() if expected_uid is None else int(expected_uid)
    if uid < 0 or (uid != os.geteuid() and os.geteuid() != 0):
        raise BrowserLcpAcceptanceError("owner override requires root")
    return uid


def _trusted_gid(expected_gid: int | None) -> int:
    gid = os.getgid() if expected_gid is None else int(expected_gid)
    if gid < 0 or (gid not in os.getgroups() and gid != os.getegid() and os.geteuid() != 0):
        raise BrowserLcpAcceptanceError("group override requires root")
    return gid


def _private_parent(path: Path, *, uid: int) -> None:
    path = _absolute(path, "private evidence parent")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise BrowserLcpAcceptanceError(
            f"private evidence parent must be owned by UID {uid} with mode 0700: {path}"
        )


def _read_private_bytes(
    path: Path,
    *,
    uid: int,
    label: str,
    maximum: int = MAX_PRIVATE_JSON_BYTES,
) -> bytes:
    path = _absolute(path, label)
    _private_parent(path.parent, uid=uid)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_size > maximum
    ):
        raise BrowserLcpAcceptanceError(
            f"{label} must be one UID {uid} mode-0600 bounded regular file"
        )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise BrowserLcpAcceptanceError(f"{label} exceeds its byte bound")
            chunks.append(block)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ):
        raise BrowserLcpAcceptanceError(f"{label} changed while it was read")
    return b"".join(chunks)


def _read_private_json(
    path: Path,
    *,
    uid: int,
    label: str,
    maximum: int = MAX_PRIVATE_JSON_BYTES,
) -> tuple[dict[str, Any], bytes]:
    payload = _read_private_bytes(path, uid=uid, label=label, maximum=maximum)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrowserLcpAcceptanceError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise BrowserLcpAcceptanceError(f"{label} must be one JSON object")
    return value, payload


def _publish_private(
    path: Path, document: Mapping[str, object], *, uid: int
) -> None:
    if os.geteuid() != uid:
        raise BrowserLcpAcceptanceError("private evidence publisher UID is invalid")
    path = Path(os.path.abspath(path.expanduser()))
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise BrowserLcpAcceptanceError("private evidence output path is invalid")
    _private_parent(path.parent, uid=uid)
    if path.exists() or path.is_symlink():
        raise BrowserLcpAcceptanceError("private evidence output already exists")
    payload = _canonical(document) + b"\n"
    if len(payload) > MAX_PRIVATE_JSON_BYTES:
        raise BrowserLcpAcceptanceError("private evidence exceeds its byte bound")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        parent = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError as error:
        raise BrowserLcpAcceptanceError(
            "private evidence output appeared concurrently"
        ) from error
    finally:
        temporary.unlink(missing_ok=True)


def _seal_digest(kind: str, values: Mapping[str, object]) -> dict[str, object]:
    document = {"schema_version": SCHEMA_VERSION, "kind": kind, **dict(values)}
    if "document_sha256" in document:
        raise BrowserLcpAcceptanceError("sealed evidence reserved field collision")
    document["document_sha256"] = _digest(document)
    return document


def _verify_digest_seal(
    value: object,
    *,
    kind: str,
    fields: frozenset[str] | set[str],
) -> dict[str, Any]:
    document = _exact_mapping(
        value,
        {"schema_version", "kind", "document_sha256", *fields},
        kind,
    )
    if document["schema_version"] != SCHEMA_VERSION or document["kind"] != kind:
        raise BrowserLcpAcceptanceError(f"{kind} contract is unsupported")
    digest = document["document_sha256"]
    unsigned = {
        key: item for key, item in document.items() if key != "document_sha256"
    }
    if (
        not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or not hmac.compare_digest(_digest(unsigned), digest)
    ):
        raise BrowserLcpAcceptanceError(f"{kind} digest is invalid")
    return document


def _validate_https_routes(
    console_url: object, tests_url: object
) -> tuple[str, str, str]:
    if not isinstance(console_url, str) or not isinstance(tests_url, str):
        raise BrowserLcpAcceptanceError("Console acceptance URLs must be strings")
    parsed_console = urlparse(console_url)
    parsed_tests = urlparse(tests_url)
    if (
        parsed_console.scheme != "https"
        or not parsed_console.hostname
        or parsed_console.username is not None
        or parsed_console.password is not None
        or parsed_console.path != "/"
        or parsed_console.params
        or parsed_console.query
        or parsed_console.fragment
        or parsed_tests.scheme != "https"
        or parsed_tests.username is not None
        or parsed_tests.password is not None
        or parsed_tests.path != "/"
        or parsed_tests.params
        or parsed_tests.query
        or parsed_tests.fragment != "/tests"
        or (parsed_console.scheme, parsed_console.hostname, parsed_console.port)
        != (parsed_tests.scheme, parsed_tests.hostname, parsed_tests.port)
    ):
        raise BrowserLcpAcceptanceError(
            "Console and Tests acceptance URLs are not the exact HTTPS routes"
        )
    default_port = "" if parsed_console.port in {None, 443} else f":{parsed_console.port}"
    origin = f"https://{parsed_console.hostname}{default_port}"
    if console_url != f"{origin}/" or tests_url != f"{origin}/#/tests":
        raise BrowserLcpAcceptanceError("Console acceptance URLs are not canonical")
    return console_url, tests_url, f"{origin}/healthz"


def _verify_owned_regular(
    path: Path,
    *,
    uid: int,
    gid: int,
    label: str,
    executable: bool = False,
) -> Path:
    path = _absolute(path, label)
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != gid
        or mode & 0o022
        or (executable and mode & 0o111 == 0)
    ):
        raise BrowserLcpAcceptanceError(f"{label} ownership or mode is unsafe")
    return path


def _run_version(command: list[str], label: str) -> str:
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=MAX_COMMAND_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BrowserLcpAcceptanceError(f"{label} version probe failed") from error
    if result.returncode != 0 or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise BrowserLcpAcceptanceError(f"{label} version probe failed")
    try:
        output = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise BrowserLcpAcceptanceError(f"{label} version output is invalid") from error
    if not output or "\n" in output or "\r" in output or len(output) > 512:
        raise BrowserLcpAcceptanceError(f"{label} version output is invalid")
    return output


def _release_digest(entries: list[dict[str, Any]]) -> str:
    return _sha256_bytes(
        _canonical({"schema_version": RELEASE_SCHEMA_VERSION, "files": entries})
    )


def verify_release_binding(
    release: Path,
    *,
    immutable_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    """Independently verify the exact immutable release inventory."""

    immutable_root = _absolute(immutable_root, "immutable release root")
    release = _absolute(release, "immutable release")
    if release.parent != immutable_root or SHA256_RE.fullmatch(release.name) is None:
        raise BrowserLcpAcceptanceError(
            "release is not one digest directory below the immutable root"
        )
    root_info = immutable_root.lstat()
    release_info = release.lstat()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
        or stat.S_IMODE(root_info.st_mode) & 0o022
        or not stat.S_ISDIR(release_info.st_mode)
        or stat.S_ISLNK(release_info.st_mode)
        or release_info.st_uid != expected_uid
        or release_info.st_gid != expected_gid
        or stat.S_IMODE(release_info.st_mode) != 0o555
    ):
        raise BrowserLcpAcceptanceError("immutable release root ownership or mode is unsafe")

    manifest_path = release / "release-manifest.json"
    manifest_info = manifest_path.lstat()
    if (
        stat.S_ISLNK(manifest_info.st_mode)
        or not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_uid != expected_uid
        or manifest_info.st_gid != expected_gid
        or stat.S_IMODE(manifest_info.st_mode) != 0o444
        or manifest_info.st_size > MAX_RELEASE_MANIFEST_BYTES
    ):
        raise BrowserLcpAcceptanceError("immutable release manifest is unsafe")
    manifest_payload = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrowserLcpAcceptanceError("immutable release manifest is invalid") from error
    manifest = _exact_mapping(
        manifest,
        {
            "capabilities",
            "files",
            "release_digest",
            "release_directory",
            "schema_version",
            "source_identity",
        },
        "immutable release manifest",
    )
    if (
        manifest["schema_version"] != RELEASE_SCHEMA_VERSION
        or manifest["release_directory"] is not None
        or manifest["release_digest"] != release.name
        or not isinstance(manifest["capabilities"], Mapping)
        or manifest["capabilities"].get("browser_lcp_acceptance") is not True
        or not isinstance(manifest["source_identity"], Mapping)
    ):
        raise BrowserLcpAcceptanceError("immutable release manifest contract is invalid")
    entries = manifest["files"]
    if (
        not isinstance(entries, list)
        or not entries
        or len(entries) > MAX_RELEASE_FILES
    ):
        raise BrowserLcpAcceptanceError("immutable release file inventory is invalid")
    normalized: list[dict[str, Any]] = []
    entry_map: dict[str, dict[str, Any]] = {}
    total_size = 0
    previous = ""
    for raw_entry in entries:
        entry = _exact_mapping(
            raw_entry,
            {"kind", "mode", "path", "sha256", "size"},
            "immutable release file entry",
        )
        if (
            not isinstance(entry["path"], str)
            or not entry["path"]
            or not isinstance(entry["kind"], str)
            or not entry["kind"]
            or not isinstance(entry["mode"], str)
            or MODE_RE.fullmatch(entry["mode"]) is None
            or not isinstance(entry["sha256"], str)
            or SHA256_RE.fullmatch(entry["sha256"]) is None
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise BrowserLcpAcceptanceError("immutable release file entry is invalid")
        relative = Path(entry["path"])
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != entry["path"]
            or entry["path"] <= previous
            or entry["path"] == "release-manifest.json"
        ):
            raise BrowserLcpAcceptanceError(
                "immutable release inventory is unsorted, duplicated, or unsafe"
            )
        previous = entry["path"]
        total_size += entry["size"]
        if total_size > MAX_RELEASE_BYTES:
            raise BrowserLcpAcceptanceError("immutable release exceeds its byte bound")
        target = release / relative
        info = target.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != int(entry["mode"], 8)
            or info.st_size != entry["size"]
            or _sha256_file(target, maximum=MAX_RELEASE_BYTES) != entry["sha256"]
        ):
            raise BrowserLcpAcceptanceError(
                f"immutable release file failed verification: {entry['path']}"
            )
        normalized.append(entry)
        entry_map[entry["path"]] = entry
    if _release_digest(normalized) != release.name:
        raise BrowserLcpAcceptanceError("immutable release digest does not match its inventory")
    actual_files: set[str] = set()
    for target in release.rglob("*"):
        relative = target.relative_to(release).as_posix()
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise BrowserLcpAcceptanceError(
                f"immutable release contains a symlink: {relative}"
            )
        if stat.S_ISDIR(info.st_mode):
            if (
                info.st_uid != expected_uid
                or info.st_gid != expected_gid
                or stat.S_IMODE(info.st_mode) != 0o555
            ):
                raise BrowserLcpAcceptanceError(
                    f"immutable release directory is mutable: {relative}"
                )
        elif stat.S_ISREG(info.st_mode):
            actual_files.add(relative)
        else:
            raise BrowserLcpAcceptanceError(
                f"immutable release contains a special file: {relative}"
            )
    if actual_files != {"release-manifest.json", *entry_map}:
        raise BrowserLcpAcceptanceError("immutable release inventory is incomplete")
    required = {
        RELEASE_PRODUCER.as_posix(),
        RELEASE_PRODUCER_SOURCE.as_posix(),
        RELEASE_BROWSER_DRIVER.as_posix(),
    }
    if not required.issubset(entry_map):
        raise BrowserLcpAcceptanceError(
            "immutable release lacks the browser acceptance producer or driver"
        )
    if (
        entry_map[RELEASE_PRODUCER.as_posix()]["mode"] != "0555"
        or entry_map[RELEASE_PRODUCER_SOURCE.as_posix()]["mode"] != "0444"
        or entry_map[RELEASE_BROWSER_DRIVER.as_posix()]["mode"] != "0444"
    ):
        raise BrowserLcpAcceptanceError(
            "immutable browser acceptance producer modes are invalid"
        )
    return {
        "root": str(immutable_root),
        "release": str(release),
        "digest": release.name,
        "manifest_sha256": _sha256_bytes(manifest_payload),
        "entries": entry_map,
    }


def _runtime_tree_entries(
    runtime_root: Path, *, uid: int, gid: int
) -> list[dict[str, object]]:
    selected = [
        Path("package.json"),
        Path("package-lock.json"),
        *PLAYWRIGHT_PACKAGE_ROOTS,
    ]
    entries: list[dict[str, object]] = []
    total = 0
    node_modules = runtime_root / "node_modules"
    node_modules_info = node_modules.lstat()
    if (
        stat.S_ISLNK(node_modules_info.st_mode)
        or not stat.S_ISDIR(node_modules_info.st_mode)
        or node_modules_info.st_uid != uid
        or node_modules_info.st_gid != gid
        or stat.S_IMODE(node_modules_info.st_mode) & 0o022
    ):
        raise BrowserLcpAcceptanceError(
            "Playwright node_modules directory ownership or mode is unsafe"
        )
    for selected_path in selected:
        candidate = runtime_root / selected_path
        if selected_path in {Path("package.json"), Path("package-lock.json")}:
            paths = [candidate]
        else:
            info = candidate.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != uid
                or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise BrowserLcpAcceptanceError(
                    "Playwright package directory ownership or mode is unsafe"
                )
            paths = []
            for item in candidate.rglob("*"):
                item_info = item.lstat()
                if item.is_dir() and not item.is_symlink():
                    if (
                        item_info.st_uid != uid
                        or item_info.st_gid != gid
                        or stat.S_IMODE(item_info.st_mode) & 0o022
                    ):
                        raise BrowserLcpAcceptanceError(
                            "Playwright runtime contains a mutable directory"
                        )
                    continue
                paths.append(item)
        for target in sorted(paths):
            info = target.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != uid
                or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise BrowserLcpAcceptanceError(
                    "Playwright runtime contains a mutable or special file"
                )
            total += info.st_size
            if len(entries) >= MAX_RUNTIME_FILES or total > MAX_RUNTIME_BYTES:
                raise BrowserLcpAcceptanceError("Playwright runtime exceeds its bound")
            entries.append(
                {
                    "path": target.relative_to(runtime_root).as_posix(),
                    "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                    "size": info.st_size,
                    "sha256": _sha256_file(target, maximum=MAX_RUNTIME_BYTES),
                }
            )
    entries.sort(key=lambda item: str(item["path"]))
    if len({str(item["path"]) for item in entries}) != len(entries):
        raise BrowserLcpAcceptanceError("Playwright runtime inventory overlaps")
    return entries


def _load_runtime_package_contract(runtime_root: Path) -> tuple[str, str, str]:
    package_json = runtime_root / "package.json"
    package_lock = runtime_root / "package-lock.json"
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
        lock = json.loads(package_lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BrowserLcpAcceptanceError("Playwright runtime package lock is invalid") from error
    version = package.get("dependencies", {}).get("playwright")
    packages = lock.get("packages")
    if (
        not isinstance(version, str)
        or SEMVER_RE.fullmatch(version) is None
        or not isinstance(packages, Mapping)
        or packages.get("", {}).get("dependencies", {}).get("playwright") != version
        or packages.get("node_modules/playwright", {}).get("version") != version
        or packages.get("node_modules/playwright-core", {}).get("version") != version
    ):
        raise BrowserLcpAcceptanceError(
            "Playwright runtime is not locked to one exact package version"
        )
    module = runtime_root / PLAYWRIGHT_MODULE_RELATIVE
    if not module.is_file() or module.is_symlink():
        raise BrowserLcpAcceptanceError("Playwright runtime module is unavailable")
    return (
        version,
        _sha256_file(package_json, maximum=MAX_PRIVATE_JSON_BYTES),
        _sha256_file(package_lock, maximum=MAX_PRIVATE_JSON_BYTES),
    )


def create_runtime_lock_document(
    *,
    node_executable: Path,
    playwright_runtime_root: Path,
    browser_executable: Path,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    node = _verify_owned_regular(
        node_executable,
        uid=expected_uid,
        gid=expected_gid,
        label="Node executable",
        executable=True,
    )
    browser = _verify_owned_regular(
        browser_executable,
        uid=expected_uid,
        gid=expected_gid,
        label="browser executable",
        executable=True,
    )
    runtime_root = _absolute(playwright_runtime_root, "Playwright runtime root")
    runtime_info = runtime_root.lstat()
    if (
        stat.S_ISLNK(runtime_info.st_mode)
        or not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != expected_uid
        or runtime_info.st_gid != expected_gid
        or stat.S_IMODE(runtime_info.st_mode) & 0o022
    ):
        raise BrowserLcpAcceptanceError(
            "Playwright runtime root ownership or mode is unsafe"
        )
    node_version = _run_version([str(node), "--version"], "Node")
    if re.fullmatch(r"v\d+\.\d+\.\d+", node_version) is None:
        raise BrowserLcpAcceptanceError("Node version is not exact")
    browser_version_output = _run_version([str(browser), "--version"], "browser")
    match = re.search(r"\b(\d+(?:\.\d+){1,4})\b", browser_version_output)
    if match is None:
        raise BrowserLcpAcceptanceError("browser product version is unavailable")
    playwright_version, package_sha, lock_sha = _load_runtime_package_contract(
        runtime_root
    )
    tree = _runtime_tree_entries(
        runtime_root, uid=expected_uid, gid=expected_gid
    )
    return _seal_digest(
        RUNTIME_LOCK_KIND,
        {
            "node": {
                "executable": str(node),
                "version": node_version,
                "sha256": _sha256_file(node),
            },
            "playwright": {
                "runtime_root": str(runtime_root),
                "version": playwright_version,
                "tree_sha256": _digest(tree),
                "package_json_sha256": package_sha,
                "package_lock_sha256": lock_sha,
                "module_relative_path": PLAYWRIGHT_MODULE_RELATIVE.as_posix(),
            },
            "browser": {
                "executable": str(browser),
                "version_output": browser_version_output,
                "product_version": match.group(1),
                "sha256": _sha256_file(browser),
            },
            "created_at": _format_time(_now()),
        },
    )


RUNTIME_LOCK_FIELDS = frozenset({"node", "playwright", "browser", "created_at"})


def verify_runtime_lock_document(
    value: object,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Any]:
    document = _verify_digest_seal(
        value, kind=RUNTIME_LOCK_KIND, fields=RUNTIME_LOCK_FIELDS
    )
    node = _exact_mapping(
        document["node"], {"executable", "version", "sha256"}, "Node runtime lock"
    )
    playwright = _exact_mapping(
        document["playwright"],
        {
            "runtime_root",
            "version",
            "tree_sha256",
            "package_json_sha256",
            "package_lock_sha256",
            "module_relative_path",
        },
        "Playwright runtime lock",
    )
    browser = _exact_mapping(
        document["browser"],
        {"executable", "version_output", "product_version", "sha256"},
        "browser runtime lock",
    )
    _parse_time(document["created_at"], "runtime lock creation")
    for label, digest in (
        ("Node", node.get("sha256")),
        ("Playwright tree", playwright.get("tree_sha256")),
        ("Playwright package", playwright.get("package_json_sha256")),
        ("Playwright lockfile", playwright.get("package_lock_sha256")),
        ("browser", browser.get("sha256")),
    ):
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise BrowserLcpAcceptanceError(f"{label} runtime digest is invalid")
    if (
        not isinstance(node.get("version"), str)
        or re.fullmatch(r"v\d+\.\d+\.\d+", node["version"]) is None
        or not isinstance(playwright.get("version"), str)
        or SEMVER_RE.fullmatch(playwright["version"]) is None
        or playwright.get("module_relative_path")
        != PLAYWRIGHT_MODULE_RELATIVE.as_posix()
        or not isinstance(browser.get("version_output"), str)
        or len(browser["version_output"]) > 512
        or not isinstance(browser.get("product_version"), str)
        or PRODUCT_VERSION_RE.fullmatch(browser["product_version"]) is None
    ):
        raise BrowserLcpAcceptanceError("runtime lock versions are invalid")

    node_path = _verify_owned_regular(
        Path(str(node["executable"])),
        uid=expected_uid,
        gid=expected_gid,
        label="Node executable",
        executable=True,
    )
    browser_path = _verify_owned_regular(
        Path(str(browser["executable"])),
        uid=expected_uid,
        gid=expected_gid,
        label="browser executable",
        executable=True,
    )
    runtime_root = _absolute(
        Path(str(playwright["runtime_root"])), "Playwright runtime root"
    )
    runtime_info = runtime_root.lstat()
    if (
        stat.S_ISLNK(runtime_info.st_mode)
        or not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != expected_uid
        or runtime_info.st_gid != expected_gid
        or stat.S_IMODE(runtime_info.st_mode) & 0o022
    ):
        raise BrowserLcpAcceptanceError("Playwright runtime root is mutable")
    actual_version, package_sha, lock_sha = _load_runtime_package_contract(
        runtime_root
    )
    tree = _runtime_tree_entries(runtime_root, uid=expected_uid, gid=expected_gid)
    if (
        _run_version([str(node_path), "--version"], "Node") != node["version"]
        or _sha256_file(node_path) != node["sha256"]
        or actual_version != playwright["version"]
        or _digest(tree) != playwright["tree_sha256"]
        or package_sha != playwright["package_json_sha256"]
        or lock_sha != playwright["package_lock_sha256"]
        or _run_version([str(browser_path), "--version"], "browser")
        != browser["version_output"]
        or _sha256_file(browser_path) != browser["sha256"]
    ):
        raise BrowserLcpAcceptanceError("locked browser runtime has drifted")
    if browser["product_version"] not in browser["version_output"]:
        raise BrowserLcpAcceptanceError("locked browser product version is contradictory")
    return {
        **document,
        "node": node,
        "playwright": playwright,
        "browser": browser,
        "playwright_module": str(runtime_root / PLAYWRIGHT_MODULE_RELATIVE),
    }


def _validate_storage_state(path: Path, *, uid: int) -> None:
    value, _payload = _read_private_json(
        path,
        uid=uid,
        label="browser authentication storage state",
        maximum=MAX_STORAGE_STATE_BYTES,
    )
    value = _exact_mapping(
        value, {"cookies", "origins"}, "browser authentication storage state"
    )
    if (
        not isinstance(value["cookies"], list)
        or len(value["cookies"]) > 128
        or not isinstance(value["origins"], list)
        or len(value["origins"]) > 32
        or not value["cookies"]
    ):
        raise BrowserLcpAcceptanceError(
            "browser authentication storage state is empty or unbounded"
        )


def _signing_key(path: Path, *, uid: int) -> bytes:
    key = _read_private_bytes(
        path,
        uid=uid,
        label="browser acceptance signing key",
        maximum=64,
    )
    if len(key) not in {32, 64}:
        raise BrowserLcpAcceptanceError(
            "browser acceptance signing key must contain exactly 32 or 64 bytes"
        )
    return key


def _health_record_fields() -> set[str]:
    return {
        "url",
        "status",
        "role",
        "generation",
        "release_digest",
        "response_sha256",
        "observed_at",
    }


def _verify_health_record(
    value: object,
    *,
    health_url: str,
    release_digest: str,
    label: str,
) -> tuple[dict[str, Any], datetime]:
    health = _exact_mapping(value, _health_record_fields(), label)
    observed = _parse_time(health["observed_at"], label)
    if (
        health["url"] != health_url
        or health["status"] != 200
        or health["role"] != "edge"
        or type(health["generation"]) is not int
        or health["generation"] < 1
        or health["release_digest"] != release_digest
        or not isinstance(health["response_sha256"], str)
        or SHA256_RE.fullmatch(health["response_sha256"]) is None
    ):
        raise BrowserLcpAcceptanceError(f"{label} identity is invalid")
    return health, observed


def observe_live_health(
    health_url: str,
    *,
    expected_release_digest: str,
    timeout_seconds: float = 3.0,
    context: ssl.SSLContext | None = None,
) -> dict[str, object]:
    parsed = urlparse(health_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/healthz"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise BrowserLcpAcceptanceError("live health URL is invalid")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=timeout_seconds,
        context=context or ssl.create_default_context(),
    )
    try:
        connection.request("GET", "/healthz", headers={"Accept": "application/json"})
        response = connection.getresponse()
        payload = response.read(64 * 1024 + 1)
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        raise BrowserLcpAcceptanceError("live edge health probe failed") from error
    finally:
        connection.close()
    if response.status != 200 or len(payload) > 64 * 1024:
        raise BrowserLcpAcceptanceError("live edge health probe was not healthy")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BrowserLcpAcceptanceError("live edge health identity is invalid") from error
    value = _exact_mapping(
        value, {"ok", "role", "generation", "release"}, "live edge health"
    )
    if (
        value["ok"] is not True
        or value["role"] != "edge"
        or type(value["generation"]) is not int
        or value["generation"] < 1
        or value["release"] != expected_release_digest
    ):
        raise BrowserLcpAcceptanceError(
            "live edge health belongs to another release or generation"
        )
    return {
        "url": health_url,
        "status": 200,
        "role": "edge",
        "generation": value["generation"],
        "release_digest": value["release"],
        "response_sha256": _sha256_bytes(payload),
        "observed_at": _format_time(_now()),
    }


SAMPLE_FIELDS = frozenset(
    {
        "journey",
        "url",
        "final_url",
        "viewport",
        "navigation_status",
        "api_status",
        "authenticated",
        "retained_tests",
        "fleet_delivery_state",
        "state",
        "lcp_ms",
        "lcp_entry_count",
        "observed_at",
    }
)


def _verify_sample(
    value: object,
    *,
    journey: str,
    viewport: Mapping[str, int],
    console_url: str,
    tests_url: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    sample = _exact_mapping(value, SAMPLE_FIELDS, "browser LCP sample")
    expected_url = tests_url if journey == "tests" else console_url
    expected_state = (
        "authenticated_retained_tests"
        if journey == "tests"
        else "authenticated_console_shell"
    )
    observed = _parse_time(sample["observed_at"], "browser LCP sample")
    if not started_at <= observed <= completed_at:
        raise BrowserLcpAcceptanceError("browser LCP sample timestamp is outside the run")
    if (
        sample["journey"] != journey
        or sample["url"] != expected_url
        or sample["final_url"] != expected_url
        or sample["viewport"] != dict(viewport)
        or sample["navigation_status"] != 200
        or sample["authenticated"] is not True
        or sample["state"] != expected_state
        or type(sample["lcp_ms"]) not in {int, float}
        or not (0 <= float(sample["lcp_ms"]) < LCP_THRESHOLD_MS)
        or type(sample["lcp_entry_count"]) is not int
        or not (1 <= sample["lcp_entry_count"] <= 1000)
    ):
        raise BrowserLcpAcceptanceError(
            f"browser LCP sample failed acceptance for {journey} at {viewport['width']}px"
        )
    if journey == "tests":
        if (
            sample["api_status"] != 200
            or sample["retained_tests"] is not True
            or sample["fleet_delivery_state"] != "retained"
        ):
            raise BrowserLcpAcceptanceError(
                "Tests LCP sample is not the authenticated retained projection"
            )
    elif (
        sample["api_status"] is not None
        or sample["retained_tests"] is not False
        or sample["fleet_delivery_state"] is not None
    ):
        raise BrowserLcpAcceptanceError("Console shell LCP sample state is contradictory")
    return sample


OBSERVATION_FIELDS = frozenset(
    {
        "operation_id",
        "playwright_version",
        "browser_product_version",
        "console_url",
        "tests_url",
        "samples",
        "started_at",
        "completed_at",
    }
)


def verify_observation_document(
    value: object,
    *,
    operation_id: str,
    playwright_version: str,
    browser_product_version: str,
    console_url: str,
    tests_url: str,
) -> dict[str, Any]:
    document = _exact_mapping(
        value,
        {"schema_version", "kind", *OBSERVATION_FIELDS},
        "browser LCP observation",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or document["kind"] != OBSERVATION_KIND
        or document["operation_id"] != operation_id
        or document["playwright_version"] != playwright_version
        or document["browser_product_version"] != browser_product_version
        or document["console_url"] != console_url
        or document["tests_url"] != tests_url
    ):
        raise BrowserLcpAcceptanceError("browser LCP observation identity is invalid")
    started = _parse_time(document["started_at"], "browser observation start")
    completed = _parse_time(document["completed_at"], "browser observation completion")
    if completed < started or completed - started > timedelta(seconds=MAX_DRIVER_SECONDS):
        raise BrowserLcpAcceptanceError("browser observation duration is invalid")
    samples = document["samples"]
    if not isinstance(samples, list) or len(samples) != len(REQUIRED_VIEWPORTS) * 2:
        raise BrowserLcpAcceptanceError("browser LCP observation samples are incomplete")
    verified: list[dict[str, Any]] = []
    expected_pairs = [
        (journey, viewport)
        for viewport in REQUIRED_VIEWPORTS
        for journey in REQUIRED_JOURNEYS
    ]
    for sample, (journey, viewport) in zip(samples, expected_pairs, strict=True):
        verified.append(
            _verify_sample(
                sample,
                journey=journey,
                viewport=viewport,
                console_url=console_url,
                tests_url=tests_url,
                started_at=started,
                completed_at=completed,
            )
        )
    return {**document, "samples": verified}


def _producer_binding(
    release_binding: Mapping[str, Any]
) -> dict[str, object]:
    entries = release_binding["entries"]
    release = Path(str(release_binding["release"]))
    return {
        "executable": str(release / RELEASE_PRODUCER),
        "executable_sha256": entries[RELEASE_PRODUCER.as_posix()]["sha256"],
        "python_source": str(release / RELEASE_PRODUCER_SOURCE),
        "python_source_sha256": entries[RELEASE_PRODUCER_SOURCE.as_posix()][
            "sha256"
        ],
        "browser_driver": str(release / RELEASE_BROWSER_DRIVER),
        "browser_driver_sha256": entries[RELEASE_BROWSER_DRIVER.as_posix()][
            "sha256"
        ],
    }


def _runtime_binding(
    runtime_lock: Mapping[str, Any], runtime_lock_payload: bytes
) -> dict[str, object]:
    return {
        "runtime_lock_sha256": _sha256_bytes(runtime_lock_payload),
        "runtime_lock_document_sha256": runtime_lock["document_sha256"],
        "node": dict(runtime_lock["node"]),
        "playwright": dict(runtime_lock["playwright"]),
        "browser": dict(runtime_lock["browser"]),
    }


def _signed_attestation(
    values: Mapping[str, object], *, signing_key: bytes
) -> dict[str, object]:
    key_id = _sha256_bytes(signing_key)
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": ATTESTATION_KIND,
        **dict(values),
        "signing_key_id": key_id,
    }
    if "document_sha256" in document or "signature_hmac_sha256" in document:
        raise BrowserLcpAcceptanceError("attestation reserved field collision")
    document["document_sha256"] = _digest(document)
    document["signature_hmac_sha256"] = hmac.new(
        signing_key, _canonical(document), hashlib.sha256
    ).hexdigest()
    return document


ATTESTATION_FIELDS = frozenset(
    {
        "operation_id",
        "release",
        "health",
        "urls",
        "runtime",
        "producer",
        "samples",
        "summary",
        "measurement_started_at",
        "measurement_completed_at",
        "issued_at",
        "expires_at",
        "ttl_seconds",
        "signing_key_id",
        "document_sha256",
        "signature_hmac_sha256",
    }
)

CONSUMPTION_FIELDS = frozenset(
    {
        "attestation_document_sha256",
        "attestation_operation_id",
        "consumer_operation_id",
        "release_digest",
        "consumed_at",
    }
)


def _verify_attestation_signature(
    value: object, *, signing_key: bytes
) -> dict[str, Any]:
    document = _exact_mapping(
        value,
        {"schema_version", "kind", *ATTESTATION_FIELDS},
        "browser LCP attestation",
    )
    if document["schema_version"] != SCHEMA_VERSION or document["kind"] != ATTESTATION_KIND:
        raise BrowserLcpAcceptanceError("browser LCP attestation contract is unsupported")
    signature = document["signature_hmac_sha256"]
    signed = {
        key: item
        for key, item in document.items()
        if key != "signature_hmac_sha256"
    }
    unsigned = {
        key: item for key, item in signed.items() if key != "document_sha256"
    }
    if (
        document["signing_key_id"] != _sha256_bytes(signing_key)
        or not isinstance(document["document_sha256"], str)
        or SHA256_RE.fullmatch(document["document_sha256"]) is None
        or not hmac.compare_digest(_digest(unsigned), document["document_sha256"])
        or not isinstance(signature, str)
        or SHA256_RE.fullmatch(signature) is None
        or not hmac.compare_digest(
            hmac.new(signing_key, _canonical(signed), hashlib.sha256).hexdigest(),
            signature,
        )
    ):
        raise BrowserLcpAcceptanceError("browser LCP attestation signature is invalid")
    return document


def _verify_attestation_contract(
    value: object,
    *,
    signing_key: bytes,
    release_binding: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    runtime_lock_payload: bytes,
    expected_operation_id: str,
    expected_console_url: str,
    expected_tests_url: str,
    now: datetime,
) -> dict[str, Any]:
    document = _verify_attestation_signature(value, signing_key=signing_key)
    _canonical_uuid(document["operation_id"], "attestation operation id")
    if document["operation_id"] != expected_operation_id:
        raise BrowserLcpAcceptanceError("browser LCP attestation belongs to another operation")
    console_url, tests_url, health_url = _validate_https_routes(
        expected_console_url, expected_tests_url
    )
    release = _exact_mapping(
        document["release"], {"root", "digest", "manifest_sha256"}, "attested release"
    )
    if release != {
        "root": release_binding["root"],
        "digest": release_binding["digest"],
        "manifest_sha256": release_binding["manifest_sha256"],
    }:
        raise BrowserLcpAcceptanceError("browser LCP attestation binds another release")
    urls = _exact_mapping(document["urls"], {"console", "tests", "health"}, "attested URLs")
    if urls != {"console": console_url, "tests": tests_url, "health": health_url}:
        raise BrowserLcpAcceptanceError("browser LCP attestation URLs are invalid")
    health, health_observed = _verify_health_record(
        document["health"],
        health_url=health_url,
        release_digest=str(release_binding["digest"]),
        label="attested live health",
    )
    runtime = _exact_mapping(
        document["runtime"],
        {
            "runtime_lock_sha256",
            "runtime_lock_document_sha256",
            "node",
            "playwright",
            "browser",
        },
        "attested browser runtime",
    )
    if runtime != _runtime_binding(runtime_lock, runtime_lock_payload):
        raise BrowserLcpAcceptanceError("attested browser runtime differs from its lock")
    producer = _exact_mapping(
        document["producer"],
        {
            "executable",
            "executable_sha256",
            "python_source",
            "python_source_sha256",
            "browser_driver",
            "browser_driver_sha256",
        },
        "attested producer",
    )
    if producer != _producer_binding(release_binding):
        raise BrowserLcpAcceptanceError("attested producer differs from the release")
    started = _parse_time(document["measurement_started_at"], "attested measurement start")
    completed = _parse_time(document["measurement_completed_at"], "attested measurement completion")
    issued = _parse_time(document["issued_at"], "attestation issue")
    expires = _parse_time(document["expires_at"], "attestation expiry")
    if (
        type(document["ttl_seconds"]) is not int
        or not MIN_TTL_SECONDS <= document["ttl_seconds"] <= MAX_TTL_SECONDS
        or completed < started
        or issued < completed
        or health_observed > started
        or started - health_observed > timedelta(seconds=30)
        or expires - issued != timedelta(seconds=document["ttl_seconds"])
        or now < issued - timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
        or now > expires
    ):
        raise BrowserLcpAcceptanceError("browser LCP attestation is stale or temporally invalid")
    samples = document["samples"]
    observation = verify_observation_document(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": OBSERVATION_KIND,
            "operation_id": document["operation_id"],
            "playwright_version": runtime_lock["playwright"]["version"],
            "browser_product_version": runtime_lock["browser"]["product_version"],
            "console_url": console_url,
            "tests_url": tests_url,
            "samples": samples,
            "started_at": document["measurement_started_at"],
            "completed_at": document["measurement_completed_at"],
        },
        operation_id=expected_operation_id,
        playwright_version=runtime_lock["playwright"]["version"],
        browser_product_version=runtime_lock["browser"]["product_version"],
        console_url=console_url,
        tests_url=tests_url,
    )
    maximum_lcp = max(float(item["lcp_ms"]) for item in observation["samples"])
    summary = _exact_mapping(
        document["summary"],
        {
            "sample_count",
            "viewport_widths",
            "journeys",
            "threshold_ms",
            "maximum_lcp_ms",
            "all_below_threshold",
            "all_authenticated",
            "all_tests_retained",
        },
        "browser LCP summary",
    )
    if summary != {
        "sample_count": 10,
        "viewport_widths": [item["width"] for item in REQUIRED_VIEWPORTS],
        "journeys": list(REQUIRED_JOURNEYS),
        "threshold_ms": LCP_THRESHOLD_MS,
        "maximum_lcp_ms": maximum_lcp,
        "all_below_threshold": True,
        "all_authenticated": True,
        "all_tests_retained": True,
    }:
        raise BrowserLcpAcceptanceError("browser LCP summary is contradictory")
    return document


def validate_consumption_document(
    value: object,
    *,
    attestation: Mapping[str, object],
    expected_consumer_operation_id: str,
    expected_release_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate one sealed marker against an already-verified attestation.

    Callers recovering a pending cutover must first verify the attestation with
    :func:`verify_attestation_file`, then validate an existing marker here.  A
    matching marker is recovery evidence; it is never permission to call the
    one-shot consumer again.
    """

    expected_consumer_operation_id = _canonical_uuid(
        expected_consumer_operation_id, "expected consumer operation id"
    )
    if (
        not isinstance(expected_release_digest, str)
        or SHA256_RE.fullmatch(expected_release_digest) is None
    ):
        raise BrowserLcpAcceptanceError(
            "expected consumption release digest is invalid"
        )
    verified_attestation = _exact_mapping(
        attestation,
        {"schema_version", "kind", *ATTESTATION_FIELDS},
        "verified browser LCP attestation",
    )
    if (
        verified_attestation["schema_version"] != SCHEMA_VERSION
        or verified_attestation["kind"] != ATTESTATION_KIND
    ):
        raise BrowserLcpAcceptanceError(
            "verified browser LCP attestation contract is unsupported"
        )
    attestation_digest = verified_attestation["document_sha256"]
    attestation_unsigned = {
        key: item
        for key, item in verified_attestation.items()
        if key not in {"document_sha256", "signature_hmac_sha256"}
    }
    if (
        not isinstance(attestation_digest, str)
        or SHA256_RE.fullmatch(attestation_digest) is None
        or not hmac.compare_digest(_digest(attestation_unsigned), attestation_digest)
    ):
        raise BrowserLcpAcceptanceError(
            "verified browser LCP attestation digest is invalid"
        )
    attestation_operation_id = _canonical_uuid(
        verified_attestation["operation_id"], "attestation operation id"
    )
    release = _exact_mapping(
        verified_attestation["release"],
        {"root", "digest", "manifest_sha256"},
        "attested release",
    )
    if (
        not isinstance(release["digest"], str)
        or SHA256_RE.fullmatch(release["digest"]) is None
        or not hmac.compare_digest(release["digest"], expected_release_digest)
    ):
        raise BrowserLcpAcceptanceError(
            "browser LCP consumption binds another release"
        )
    issued = _parse_time(verified_attestation["issued_at"], "attestation issue")
    expires = _parse_time(verified_attestation["expires_at"], "attestation expiry")
    document = _verify_digest_seal(
        value,
        kind=CONSUMPTION_KIND,
        fields=CONSUMPTION_FIELDS,
    )
    marker_attestation_digest = document["attestation_document_sha256"]
    if (
        not isinstance(marker_attestation_digest, str)
        or SHA256_RE.fullmatch(marker_attestation_digest) is None
        or not hmac.compare_digest(marker_attestation_digest, attestation_digest)
    ):
        raise BrowserLcpAcceptanceError(
            "browser LCP consumption binds another attestation"
        )
    marker_attestation_operation_id = _canonical_uuid(
        document["attestation_operation_id"],
        "consumed attestation operation id",
    )
    marker_consumer_operation_id = _canonical_uuid(
        document["consumer_operation_id"], "consumption operation id"
    )
    if (
        marker_attestation_operation_id != attestation_operation_id
        or marker_consumer_operation_id != expected_consumer_operation_id
    ):
        raise BrowserLcpAcceptanceError(
            "browser LCP consumption operation binding is invalid"
        )
    marker_release_digest = document["release_digest"]
    if (
        not isinstance(marker_release_digest, str)
        or SHA256_RE.fullmatch(marker_release_digest) is None
        or not hmac.compare_digest(marker_release_digest, expected_release_digest)
    ):
        raise BrowserLcpAcceptanceError(
            "browser LCP consumption binds another release"
        )
    consumed = _parse_time(document["consumed_at"], "consumption")
    observed = (now or _now()).astimezone(timezone.utc)
    if (
        expires <= issued
        or consumed < issued
        or consumed > expires
        or observed < consumed - timedelta(seconds=TIMESTAMP_SKEW_SECONDS)
        or observed > expires
    ):
        raise BrowserLcpAcceptanceError(
            "browser LCP consumption is stale or temporally invalid"
        )
    return document


HealthObserver = Callable[..., dict[str, object]]


def verify_attestation_file(
    attestation_path: Path,
    *,
    release: Path,
    immutable_root: Path,
    runtime_lock_path: Path,
    signing_key_path: Path,
    expected_operation_id: str,
    expected_console_url: str = DEFAULT_CONSOLE_URL,
    expected_tests_url: str = DEFAULT_TESTS_URL,
    expected_uid: int = 0,
    expected_gid: int = 0,
    now: datetime | None = None,
    health_observer: HealthObserver = observe_live_health,
) -> dict[str, Any]:
    expected_operation_id = _canonical_uuid(
        expected_operation_id, "expected operation id"
    )
    release_binding = verify_release_binding(
        release,
        immutable_root=immutable_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    runtime_value, runtime_payload = _read_private_json(
        runtime_lock_path, uid=expected_uid, label="browser runtime lock"
    )
    runtime_lock = verify_runtime_lock_document(
        runtime_value, expected_uid=expected_uid, expected_gid=expected_gid
    )
    key = _signing_key(signing_key_path, uid=expected_uid)
    value, _payload = _read_private_json(
        attestation_path, uid=expected_uid, label="browser LCP attestation"
    )
    verified = _verify_attestation_contract(
        value,
        signing_key=key,
        release_binding=release_binding,
        runtime_lock=runtime_lock,
        runtime_lock_payload=runtime_payload,
        expected_operation_id=expected_operation_id,
        expected_console_url=expected_console_url,
        expected_tests_url=expected_tests_url,
        now=(now or _now()).astimezone(timezone.utc),
    )
    _console, _tests, health_url = _validate_https_routes(
        expected_console_url, expected_tests_url
    )
    current_value = health_observer(
        health_url, expected_release_digest=release_binding["digest"]
    )
    current, current_observed = _verify_health_record(
        current_value,
        health_url=health_url,
        release_digest=str(release_binding["digest"]),
        label="current live health",
    )
    if (
        current["generation"] != verified["health"]["generation"]
        or abs(((now or _now()).astimezone(timezone.utc) - current_observed).total_seconds())
        > TIMESTAMP_SKEW_SECONDS
    ):
        raise BrowserLcpAcceptanceError(
            "live edge identity changed after browser acceptance"
        )
    return verified


def verify_historical_attestation_file(
    attestation_path: Path,
    *,
    release: Path,
    immutable_root: Path,
    runtime_lock_path: Path,
    signing_key_path: Path,
    expected_operation_id: str,
    verified_at: datetime,
    expected_console_url: str = DEFAULT_CONSOLE_URL,
    expected_tests_url: str = DEFAULT_TESTS_URL,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> dict[str, Any]:
    """Revalidate a consumed proof at its durable consumption timestamp.

    Activation evidence remains durable after its short live-acceptance TTL.
    Current publication health is intentionally checked by the retention
    transaction separately; this verifier proves that the signed evidence and
    runtime were valid when the one-shot consumption marker was created.
    """

    expected_operation_id = _canonical_uuid(
        expected_operation_id, "expected operation id"
    )
    if verified_at.tzinfo is None:
        raise BrowserLcpAcceptanceError(
            "historical browser verification timestamp lacks a timezone"
        )
    release_binding = verify_release_binding(
        release,
        immutable_root=immutable_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    runtime_value, runtime_payload = _read_private_json(
        runtime_lock_path, uid=expected_uid, label="browser runtime lock"
    )
    runtime_lock = verify_runtime_lock_document(
        runtime_value, expected_uid=expected_uid, expected_gid=expected_gid
    )
    key = _signing_key(signing_key_path, uid=expected_uid)
    value, _payload = _read_private_json(
        attestation_path, uid=expected_uid, label="browser LCP attestation"
    )
    return _verify_attestation_contract(
        value,
        signing_key=key,
        release_binding=release_binding,
        runtime_lock=runtime_lock,
        runtime_lock_payload=runtime_payload,
        expected_operation_id=expected_operation_id,
        expected_console_url=expected_console_url,
        expected_tests_url=expected_tests_url,
        now=verified_at.astimezone(timezone.utc),
    )


def _build_attestation(
    *,
    operation_id: str,
    release_binding: Mapping[str, Any],
    runtime_lock: Mapping[str, Any],
    runtime_lock_payload: bytes,
    health: Mapping[str, object],
    observation: Mapping[str, Any],
    console_url: str,
    tests_url: str,
    signing_key: bytes,
    ttl_seconds: int,
) -> dict[str, object]:
    issued = _now()
    maximum_lcp = max(float(item["lcp_ms"]) for item in observation["samples"])
    return _signed_attestation(
        {
            "operation_id": operation_id,
            "release": {
                "root": release_binding["root"],
                "digest": release_binding["digest"],
                "manifest_sha256": release_binding["manifest_sha256"],
            },
            "health": dict(health),
            "urls": {
                "console": console_url,
                "tests": tests_url,
                "health": _validate_https_routes(console_url, tests_url)[2],
            },
            "runtime": _runtime_binding(runtime_lock, runtime_lock_payload),
            "producer": _producer_binding(release_binding),
            "samples": list(observation["samples"]),
            "summary": {
                "sample_count": 10,
                "viewport_widths": [item["width"] for item in REQUIRED_VIEWPORTS],
                "journeys": list(REQUIRED_JOURNEYS),
                "threshold_ms": LCP_THRESHOLD_MS,
                "maximum_lcp_ms": maximum_lcp,
                "all_below_threshold": True,
                "all_authenticated": True,
                "all_tests_retained": True,
            },
            "measurement_started_at": observation["started_at"],
            "measurement_completed_at": observation["completed_at"],
            "issued_at": _format_time(issued),
            "expires_at": _format_time(issued + timedelta(seconds=ttl_seconds)),
            "ttl_seconds": ttl_seconds,
        },
        signing_key=signing_key,
    )


def produce_attestation(
    *,
    release: Path,
    immutable_root: Path,
    runtime_lock_path: Path,
    storage_state_path: Path,
    signing_key_path: Path,
    output: Path,
    operation_id: str,
    console_url: str = DEFAULT_CONSOLE_URL,
    tests_url: str = DEFAULT_TESTS_URL,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    expected_uid: int = 0,
    expected_gid: int = 0,
    health_observer: HealthObserver = observe_live_health,
) -> dict[str, object]:
    """Run the immutable driver and atomically publish one acceptance proof."""

    operation_id = _canonical_uuid(operation_id, "browser acceptance operation id")
    if type(ttl_seconds) is not int or not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise BrowserLcpAcceptanceError("browser acceptance TTL is invalid")
    console_url, tests_url, health_url = _validate_https_routes(
        console_url, tests_url
    )
    release_binding = verify_release_binding(
        release,
        immutable_root=immutable_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    expected_source = Path(str(release_binding["release"])) / RELEASE_PRODUCER_SOURCE
    if Path(__file__).resolve(strict=True) != expected_source:
        raise BrowserLcpAcceptanceError(
            "browser acceptance producer is not executing from the immutable release"
        )
    runtime_value, runtime_payload = _read_private_json(
        runtime_lock_path, uid=expected_uid, label="browser runtime lock"
    )
    runtime_lock = verify_runtime_lock_document(
        runtime_value, expected_uid=expected_uid, expected_gid=expected_gid
    )
    _validate_storage_state(storage_state_path, uid=expected_uid)
    key = _signing_key(signing_key_path, uid=expected_uid)
    health = health_observer(
        health_url, expected_release_digest=release_binding["digest"]
    )

    output = Path(os.path.abspath(output.expanduser()))
    _private_parent(output.parent, uid=expected_uid)
    request_path = output.with_name(f".{output.name}.{uuid.uuid4().hex}.request")
    observation_path = output.with_name(
        f".{output.name}.{uuid.uuid4().hex}.observation"
    )
    request = {
        "schema_version": SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "operation_id": operation_id,
        "playwright_module": runtime_lock["playwright_module"],
        "playwright_version": runtime_lock["playwright"]["version"],
        "browser_executable": runtime_lock["browser"]["executable"],
        "browser_product_version": runtime_lock["browser"]["product_version"],
        "storage_state": str(_absolute(storage_state_path, "storage state")),
        "console_url": console_url,
        "tests_url": tests_url,
        "viewports": [dict(item) for item in REQUIRED_VIEWPORTS],
        "navigation_timeout_ms": 10_000,
        "retained_warm_delay_ms": 15_500,
    }
    _publish_private(request_path, request, uid=expected_uid)
    driver = Path(str(release_binding["release"])) / RELEASE_BROWSER_DRIVER
    node = runtime_lock["node"]["executable"]
    try:
        try:
            result = subprocess.run(
                [
                    str(node),
                    str(driver),
                    "--request",
                    str(request_path),
                    "--output",
                    str(observation_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=MAX_DRIVER_SECONDS,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(output.parent),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BrowserLcpAcceptanceError(
                "browser LCP observation did not complete"
            ) from error
        if (
            result.returncode != 0
            or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES
            or len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES
        ):
            raise BrowserLcpAcceptanceError("browser LCP observation failed")
        observation_value, _observation_payload = _read_private_json(
            observation_path,
            uid=expected_uid,
            label="browser LCP observation",
            maximum=MAX_OBSERVATION_BYTES,
        )
        observation = verify_observation_document(
            observation_value,
            operation_id=operation_id,
            playwright_version=runtime_lock["playwright"]["version"],
            browser_product_version=runtime_lock["browser"]["product_version"],
            console_url=console_url,
            tests_url=tests_url,
        )
        attestation = _build_attestation(
            operation_id=operation_id,
            release_binding=release_binding,
            runtime_lock=runtime_lock,
            runtime_lock_payload=runtime_payload,
            health=health,
            observation=observation,
            console_url=console_url,
            tests_url=tests_url,
            signing_key=key,
            ttl_seconds=ttl_seconds,
        )
        # Validate the complete in-memory document before making it durable.
        _verify_attestation_contract(
            attestation,
            signing_key=key,
            release_binding=release_binding,
            runtime_lock=runtime_lock,
            runtime_lock_payload=runtime_payload,
            expected_operation_id=operation_id,
            expected_console_url=console_url,
            expected_tests_url=tests_url,
            now=_now(),
        )
        _publish_private(output, attestation, uid=expected_uid)
        return attestation
    finally:
        request_path.unlink(missing_ok=True)
        observation_path.unlink(missing_ok=True)


def consume_attestation(
    attestation_path: Path,
    *,
    consumption_output: Path,
    consumer_operation_id: str,
    release: Path,
    immutable_root: Path,
    runtime_lock_path: Path,
    signing_key_path: Path,
    expected_operation_id: str,
    expected_console_url: str = DEFAULT_CONSOLE_URL,
    expected_tests_url: str = DEFAULT_TESTS_URL,
    expected_uid: int = 0,
    expected_gid: int = 0,
    now: datetime | None = None,
    health_observer: HealthObserver = observe_live_health,
) -> dict[str, object]:
    """Validate and consume one proof; any second use is a replay failure."""

    consumer_operation_id = _canonical_uuid(
        consumer_operation_id, "consumer operation id"
    )
    consumption_output = Path(os.path.abspath(consumption_output.expanduser()))
    _private_parent(consumption_output.parent, uid=expected_uid)
    if consumption_output.exists() or consumption_output.is_symlink():
        raise BrowserLcpReplayError("browser LCP attestation was already consumed")
    verified = verify_attestation_file(
        attestation_path,
        release=release,
        immutable_root=immutable_root,
        runtime_lock_path=runtime_lock_path,
        signing_key_path=signing_key_path,
        expected_operation_id=expected_operation_id,
        expected_console_url=expected_console_url,
        expected_tests_url=expected_tests_url,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        now=now,
        health_observer=health_observer,
    )
    consumed = _now() if now is None else now.astimezone(timezone.utc)
    document = _seal_digest(
        CONSUMPTION_KIND,
        {
            "attestation_document_sha256": verified["document_sha256"],
            "attestation_operation_id": verified["operation_id"],
            "consumer_operation_id": consumer_operation_id,
            "release_digest": verified["release"]["digest"],
            "consumed_at": _format_time(consumed),
        },
    )
    document = validate_consumption_document(
        document,
        attestation=verified,
        expected_consumer_operation_id=consumer_operation_id,
        expected_release_digest=str(verified["release"]["digest"]),
        now=consumed,
    )
    try:
        _publish_private(consumption_output, document, uid=expected_uid)
    except BrowserLcpAcceptanceError as error:
        if consumption_output.exists() or consumption_output.is_symlink():
            raise BrowserLcpReplayError(
                "browser LCP attestation was consumed concurrently"
            ) from error
        raise
    return document


def _safe_result(**values: object) -> str:
    return json.dumps({"ok": True, **values}, sort_keys=True, separators=(",", ":"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    runtime = sub.add_parser(
        "runtime-lock", help="create a static, root-private browser runtime lock"
    )
    runtime.add_argument("--node", required=True)
    runtime.add_argument("--playwright-runtime-root", required=True)
    runtime.add_argument("--browser", required=True)
    runtime.add_argument("--output", required=True)
    runtime.add_argument("--expected-uid", type=int, default=0)
    runtime.add_argument("--expected-gid", type=int, default=0)

    for name in ("produce", "verify", "consume"):
        command = sub.add_parser(name)
        command.add_argument("--release", required=True)
        command.add_argument(
            "--immutable-root", default=str(DEFAULT_IMMUTABLE_ROOT)
        )
        command.add_argument("--runtime-lock", required=True)
        command.add_argument("--signing-key", required=True)
        command.add_argument("--operation-id", required=True)
        command.add_argument("--console-url", default=DEFAULT_CONSOLE_URL)
        command.add_argument("--tests-url", default=DEFAULT_TESTS_URL)
        command.add_argument("--expected-uid", type=int, default=0)
        command.add_argument("--expected-gid", type=int, default=0)
    produce = sub.choices["produce"]
    produce.add_argument("--storage-state", required=True)
    produce.add_argument("--output", required=True)
    produce.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)

    verify = sub.choices["verify"]
    verify.add_argument("--attestation", required=True)

    consume = sub.choices["consume"]
    consume.add_argument("--attestation", required=True)
    consume.add_argument("--consumption-output", required=True)
    consume.add_argument("--consumer-operation-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        uid = _trusted_uid(args.expected_uid)
        gid = _trusted_gid(args.expected_gid)
        if args.command == "runtime-lock":
            document = create_runtime_lock_document(
                node_executable=Path(args.node),
                playwright_runtime_root=Path(args.playwright_runtime_root),
                browser_executable=Path(args.browser),
                expected_uid=uid,
                expected_gid=gid,
            )
            _publish_private(Path(args.output), document, uid=uid)
            print(
                _safe_result(
                    output=str(Path(args.output).expanduser().absolute()),
                    document_sha256=document["document_sha256"],
                )
            )
            return 0
        common = {
            "release": Path(args.release),
            "immutable_root": Path(args.immutable_root),
            "runtime_lock_path": Path(args.runtime_lock),
            "signing_key_path": Path(args.signing_key),
            "expected_operation_id": args.operation_id,
            "expected_console_url": args.console_url,
            "expected_tests_url": args.tests_url,
            "expected_uid": uid,
            "expected_gid": gid,
        }
        if args.command == "produce":
            attestation = produce_attestation(
                release=common["release"],
                immutable_root=common["immutable_root"],
                runtime_lock_path=common["runtime_lock_path"],
                storage_state_path=Path(args.storage_state),
                signing_key_path=common["signing_key_path"],
                output=Path(args.output),
                operation_id=args.operation_id,
                console_url=args.console_url,
                tests_url=args.tests_url,
                ttl_seconds=args.ttl_seconds,
                expected_uid=uid,
                expected_gid=gid,
            )
            print(
                _safe_result(
                    attestation=str(Path(args.output).expanduser().absolute()),
                    document_sha256=attestation["document_sha256"],
                    expires_at=attestation["expires_at"],
                    sample_count=10,
                )
            )
            return 0
        if args.command == "verify":
            attestation = verify_attestation_file(
                Path(args.attestation), **common
            )
            print(
                _safe_result(
                    document_sha256=attestation["document_sha256"],
                    release_digest=attestation["release"]["digest"],
                    expires_at=attestation["expires_at"],
                )
            )
            return 0
        consumption = consume_attestation(
            Path(args.attestation),
            consumption_output=Path(args.consumption_output),
            consumer_operation_id=args.consumer_operation_id,
            **common,
        )
        print(
            _safe_result(
                consumption=str(Path(args.consumption_output).expanduser().absolute()),
                document_sha256=consumption["document_sha256"],
            )
        )
        return 0
    except BrowserLcpReplayError:
        print(
            json.dumps(
                {"ok": False, "classification": "browser_lcp_replay"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 3
    except BrowserLcpAcceptanceError:
        print(
            json.dumps(
                {"ok": False, "classification": "browser_lcp_acceptance_failed"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
