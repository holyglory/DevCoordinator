#!/usr/bin/env python3
"""Switch the production graph to one immutable, same-schema release.

This is the routine fast release path.  It deliberately does not migrate,
copy, validate, or replace databases: authority data, inventory, routes,
grants, Telegram configuration, Console settings, and test history stay in
place unless the caller explicitly selects the disposable test-history reset.

The switch installs the immutable unit set, refreshes systemd identities and
runtime directories, starts a second Console slot on two unused loopback
ports, promotes it through the existing slot-supervisor protocol, atomically
publishes the new edge target, and only then drains the old slot.  The exact
prior unit files are retained for automatic rollback.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from typing import Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import activate_availability_release as activation  # noqa: E402
import install_availability_release as installer  # noqa: E402


KIND = "devcoordinator-same-schema-release-switch"
VERSION = 1
RELEASE_RE = re.compile(r"^[0-9a-f]{64}$")
UNIT_ROOT = Path("/etc/systemd/system")
SYSUSERS_ROOT = Path("/etc/sysusers.d")
TMPFILES_ROOT = Path("/etc/tmpfiles.d")
CODEX_ROOT = Path("/etc/codex")
CODEX_RULE_ROOT = CODEX_ROOT / "rules"
CLIENT_LAUNCHER = Path("/usr/local/bin/devcoordinator")
MCP_LAUNCHER = Path("/usr/local/bin/devcoordinator-mcp")
BUG_LAUNCHER = Path("/usr/local/bin/devcoordinator-bug")
TEST_LAUNCHER = Path("/usr/local/bin/devcoordinator-test")
CALL_LOG_LAUNCHER = Path("/usr/local/bin/devcoordinator-call-log")
READ_ONLY_RULE = CODEX_RULE_ROOT / "devcoordinator-read-only.rules"
TEST_RULE = CODEX_RULE_ROOT / "devcoordinator-test.rules"
CLIENT_LAUNCHER_RENDERED = "devcoordinator-launcher"
MCP_LAUNCHER_RENDERED = "devcoordinator-mcp-launcher"
BUG_LAUNCHER_RENDERED = "devcoordinator-bug-launcher"
TEST_LAUNCHER_RENDERED = "devcoordinator-test-launcher"
CALL_LOG_LAUNCHER_RENDERED = "devcoordinator-call-log-launcher"
READ_ONLY_RULE_RENDERED = "devcoordinator-read-only.rules"
TEST_RULE_RENDERED = "devcoordinator-test.rules"
BROWSER_ACCOUNTING_CAPABILITY = "headless_browser_accounting"
BROWSER_ACCOUNTING_WRAPPER = "devcoordinator-browser-accounting"
BROWSER_LIFECYCLE_STATE = Path("/var/lib/devcoordinator/browser-lifecycle.json")
BROWSER_CLEANUP_QUIESCENCE_SECONDS = 2
BROWSER_CLEANUP_RESULT_MAX_BYTES = 4096
STABLE_LAUNCHERS = {
    CLIENT_LAUNCHER_RENDERED: (CLIENT_LAUNCHER, "devcoordinator"),
    MCP_LAUNCHER_RENDERED: (MCP_LAUNCHER, "devcoordinator-mcp"),
    BUG_LAUNCHER_RENDERED: (BUG_LAUNCHER, "devcoordinator-bug"),
    TEST_LAUNCHER_RENDERED: (TEST_LAUNCHER, "devcoordinator-test"),
    CALL_LOG_LAUNCHER_RENDERED: (
        CALL_LOG_LAUNCHER,
        "devcoordinator-call-log",
    ),
}
TEST_HISTORY_WRAPPER = "devcoordinator-test-history"
TESTD_USER = "devcoordinator-testd"
TESTD_SERVICE = "devcoordinator-testd.service"
TESTD_SOCKET = "devcoordinator-testd.socket"
TEST_DATABASE = Path("/var/lib/devcoordinator-testd/tests.sqlite3")
TEST_SPOOL = Path("/var/lib/devcoordinator-testd/spool")
TEST_SPOOL_QUEUES = (
    "pending",
    "processed",
    "result-pending",
    "result-processed",
    "active",
)
SLOT_ROOT = Path("/etc/devcoordinator/console-slots")
CLIENT_PROFILE = Path("/etc/devcoordinator/client-profiles.json")
PUBLICATION_FILE = Path("/var/lib/devcoordinator-edge/routes.publication")
MAINTENANCE_ROOT = Path("/run/devcoordinator-maintenance")
MAINTENANCE_MARKER = MAINTENANCE_ROOT / "maintenance.json"
CONSOLE_HOST = "console.vr.ae"
PORT_MIN = 30000
PORT_MAX = 60999
SERVICE_ORDER = (
    "devcoordinator-authority.service",
    "devcoordinator-test-snapshotd.service",
    "devcoordinator-testd.service",
    "devcoordinator-api.service",
    "devcoordinator-observer.service",
    "devcoordinator-notifications.service",
    "devcoordinator-edge.service",
)
RUNTIME_SOCKET_REBIND_ORDER = (
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-testd.socket",
)
REQUIRED_SOCKETS = activation.SOCKET_UNITS


class SwitchError(RuntimeError):
    """The same-schema switch could not safely continue."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    atomic_bytes(path, payload, 0o600)


def atomic_bytes(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SwitchError(f"cannot read {path}: {error}") from error
    if not isinstance(value, Mapping):
        raise SwitchError(f"JSON document is not an object: {path}")
    return dict(value)


def load_journal(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    value = load_json(path)
    if value.get("kind") != KIND or value.get("schema_version") != VERSION:
        raise SwitchError("same-schema journal is invalid")
    return value


def testd_uid() -> int:
    try:
        account = pwd.getpwnam(TESTD_USER)
    except KeyError as error:
        raise SwitchError("test-history reset requires the testd service account") from error
    if account.pw_uid <= 0:
        raise SwitchError("test-history reset requires one non-root testd UID")
    return int(account.pw_uid)


def test_history_reset_intent(
    release: Path, *, previous_release_digest: str
) -> dict[str, object]:
    operation_id = str(uuid.uuid4())
    return {
        "requested": True,
        "status": "planned",
        "operation_id": operation_id,
        "test_database": str(TEST_DATABASE),
        "test_spool": str(TEST_SPOOL),
        "forward_discarded_spool": str(
            TEST_SPOOL.parent / f".{TEST_SPOOL.name}.{operation_id}.forward-discarded"
        ),
        "rollback_discarded_spool": str(
            TEST_SPOOL.parent / f".{TEST_SPOOL.name}.{operation_id}.rollback-discarded"
        ),
        "attestation": str(
            TEST_DATABASE.parent / f"schema-readiness-{operation_id}.json"
        ),
        "expected_test_uid": testd_uid(),
        "forward_release": str(release),
        "previous_release": str(release.parent / previous_release_digest),
    }


def valid_test_spool_reset_evidence(
    value: object, *, discarded_path: str
) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value)
        == {
            "test_spool",
            "discarded_path",
            "discarded_existing",
            "queues",
            "fresh",
        }
        and value.get("test_spool") == str(TEST_SPOOL)
        and value.get("discarded_path") == discarded_path
        and type(value.get("discarded_existing")) is bool
        and value.get("queues") == list(TEST_SPOOL_QUEUES)
        and value.get("fresh") is True
    )


def require_test_history_reset_mode(
    document: Mapping[str, object], *, requested: bool
) -> Mapping[str, object] | None:
    raw = document.get("test_history_reset")
    if raw is None:
        if requested:
            raise SwitchError(
                "same-schema transaction was prepared without test-history reset"
            )
        return None
    if (
        not isinstance(raw, Mapping)
        or raw.get("requested") is not True
        or raw.get("status")
        not in {"planned", "resetting", "complete", "rollback-resetting", "rolled-back"}
        or not isinstance(raw.get("operation_id"), str)
        or raw.get("test_database") != str(TEST_DATABASE)
        or raw.get("test_spool") != str(TEST_SPOOL)
        or not isinstance(raw.get("forward_discarded_spool"), str)
        or not isinstance(raw.get("rollback_discarded_spool"), str)
        or not isinstance(raw.get("attestation"), str)
        or type(raw.get("expected_test_uid")) is not int
        or not isinstance(raw.get("forward_release"), str)
        or not isinstance(raw.get("previous_release"), str)
    ):
        raise SwitchError("same-schema test-history reset journal is invalid")
    if not requested:
        raise SwitchError(
            "same-schema transaction requires the explicit test-history reset flag"
        )
    try:
        operation_id = str(uuid.UUID(str(raw["operation_id"])))
    except (ValueError, AttributeError) as error:
        raise SwitchError("same-schema test-history reset operation ID is invalid") from error
    expected_attestation = TEST_DATABASE.parent / f"schema-readiness-{operation_id}.json"
    expected_forward_discard = (
        TEST_SPOOL.parent
        / f".{TEST_SPOOL.name}.{operation_id}.forward-discarded"
    )
    expected_rollback_discard = (
        TEST_SPOOL.parent
        / f".{TEST_SPOOL.name}.{operation_id}.rollback-discarded"
    )
    release = Path(str(document.get("release")))
    previous_digest = document.get("previous_release_digest")
    if (
        operation_id != raw["operation_id"]
        or raw["attestation"] != str(expected_attestation)
        or raw["forward_discarded_spool"] != str(expected_forward_discard)
        or raw["rollback_discarded_spool"] != str(expected_rollback_discard)
        or raw["expected_test_uid"] != testd_uid()
        or raw["forward_release"] != str(release)
        or raw["previous_release"] != str(release.parent / str(previous_digest))
    ):
        raise SwitchError("same-schema test-history reset binding is invalid")
    status = raw["status"]
    if status == "complete":
        evidence = raw.get("forward_evidence")
        if not isinstance(evidence, Mapping) or not valid_test_spool_reset_evidence(
            evidence.get("spool"),
            discarded_path=str(expected_forward_discard),
        ):
            raise SwitchError("same-schema forward spool reset evidence is invalid")
    if status == "rolled-back":
        evidence = raw.get("rollback_evidence")
        if not isinstance(evidence, Mapping) or not valid_test_spool_reset_evidence(
            evidence.get("spool"),
            discarded_path=str(expected_rollback_discard),
        ):
            raise SwitchError("same-schema rollback spool reset evidence is invalid")
    return raw


class Runner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def require(self, argv: Sequence[str], label: str) -> str:
        result = self.run(argv)
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise SwitchError(f"{label} failed" + (f": {detail}" if detail else ""))
        return result.stdout

    def require_json(self, argv: Sequence[str], label: str) -> dict[str, object]:
        raw = self.require(argv, label)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SwitchError(f"{label} returned invalid JSON") from error
        if not isinstance(value, Mapping) or value.get("ok") is not True:
            raise SwitchError(f"{label} returned an unsuccessful result")
        return dict(value)


def release_capability(release: Path, capability: str) -> bool:
    verified = installer.verify_release(release)
    capabilities = verified.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise SwitchError("immutable release capability manifest is invalid")
    return capabilities.get(capability) is True


def retiring_release_capability(release: Path, capability: str) -> bool:
    """Read one content-bound capability without re-gating a running release.

    Historical releases can contain interpreter-generated ``__pycache__``
    directories from launchers that predate the bytecode-disabled wrappers.
    Those non-canonical cache entries must not block replacing the already
    running release.  The candidate still goes through ``verify_release``;
    this narrower reader validates the retiring release's manifest and derives
    the browser capability from the digest-bound file inventory instead of
    filesystem ownership, modes, or generated cache contents.
    """

    if capability != BROWSER_ACCOUNTING_CAPABILITY:
        raise SwitchError("retiring release capability is unsupported")
    release = release.expanduser().absolute()
    if RELEASE_RE.fullmatch(release.name) is None:
        raise SwitchError("retiring release identity is invalid")
    manifest_path = release / "release-manifest.json"
    try:
        manifest_info = manifest_path.lstat()
        if (
            stat.S_ISLNK(manifest_info.st_mode)
            or not stat.S_ISREG(manifest_info.st_mode)
            or manifest_info.st_size <= 0
            or manifest_info.st_size > 16 * 1024 * 1024
        ):
            raise SwitchError("retiring release manifest is invalid")
        document = json.loads(manifest_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SwitchError("retiring release manifest is unavailable") from error
    entries = document.get("files") if isinstance(document, Mapping) else None
    capabilities = (
        document.get("capabilities") if isinstance(document, Mapping) else None
    )
    if (
        not isinstance(document, Mapping)
        or document.get("schema_version") != installer.RELEASE_SCHEMA
        or document.get("release_digest") != release.name
        or not isinstance(entries, list)
        or not entries
        or installer.release_digest(entries) != release.name
        or not isinstance(capabilities, Mapping)
    ):
        raise SwitchError("retiring release manifest contract is invalid")
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            raise SwitchError("retiring release file inventory is invalid")
        path = str(entry["path"])
        if not path or path in paths:
            raise SwitchError("retiring release file inventory is invalid")
        paths.add(path)
    derived = all(
        path in paths
        for path in (
            "bin/devcoordinator-browser-accounting",
            "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
        )
    )
    if capabilities.get(capability) is not derived:
        raise SwitchError("retiring release capability contradicts its inventory")
    return derived


def headless_browser_cleanup_plan(
    release: Path,
    *,
    previous_release_digest: str,
) -> dict[str, object]:
    previous_release = release.parent / previous_release_digest
    candidate_capable = release_capability(
        release, BROWSER_ACCOUNTING_CAPABILITY
    )
    previous_capable = retiring_release_capability(
        previous_release, BROWSER_ACCOUNTING_CAPABILITY
    )
    required = candidate_capable and not previous_capable
    return {
        "required": required,
        "status": "pending" if required else "not-required",
        "candidate_release": str(release),
        "previous_release": str(previous_release),
        "candidate_capable": candidate_capable,
        "previous_capable": previous_capable,
    }


def validate_headless_browser_cleanup_plan(
    document: Mapping[str, object],
    release: Path,
) -> dict[str, object]:
    raw = document.get("headless_browser_cleanup")
    if not isinstance(raw, Mapping):
        raise SwitchError("same-schema browser cleanup plan is unavailable")
    value = dict(raw)
    required = value.get("required")
    candidate_capable = value.get("candidate_capable")
    previous_capable = value.get("previous_capable")
    status = value.get("status")
    previous_release = release.parent / str(document.get("previous_release_digest"))
    actual_candidate_capable = release_capability(
        release, BROWSER_ACCOUNTING_CAPABILITY
    )
    actual_previous_capable = retiring_release_capability(
        previous_release, BROWSER_ACCOUNTING_CAPABILITY
    )
    if (
        type(required) is not bool
        or type(candidate_capable) is not bool
        or type(previous_capable) is not bool
        or value.get("candidate_release") != str(release)
        or value.get("previous_release") != str(previous_release)
        or candidate_capable != actual_candidate_capable
        or previous_capable != actual_previous_capable
        or required is not (candidate_capable and not previous_capable)
        or status not in {"not-required", "pending", "running", "complete", "failed"}
        or (not required and status != "not-required")
        or (required and status == "not-required")
    ):
        raise SwitchError("same-schema browser cleanup plan is invalid")
    if status == "complete":
        result = value.get("result")
        if (
            not isinstance(result, Mapping)
            or result.get("ok") is not True
            or result.get("remaining_session_count") != 0
            or len(canonical(result)) > BROWSER_CLEANUP_RESULT_MAX_BYTES
        ):
            raise SwitchError("same-schema browser cleanup evidence is invalid")
    return value


def bounded_browser_cleanup_result(value: Mapping[str, object]) -> dict[str, object]:
    remaining = value.get("remaining_session_count")
    if value.get("ok") is not True or type(remaining) is not int or remaining != 0:
        raise SwitchError(
            "headless browser cleanup did not remove every eligible session"
        )
    result: dict[str, object] = {
        "ok": True,
        "remaining_session_count": 0,
    }
    for field in (
        "observed_session_count",
        "terminated_session_count",
        "terminated_process_count",
        "reclaimed_memory_bytes",
        "already_stopped_session_count",
        "protected_session_count",
    ):
        item = value.get(field)
        if type(item) is int and item >= 0:
            result[field] = item
    sampled_at = value.get("sampled_at")
    if isinstance(sampled_at, str) and 0 < len(sampled_at) <= 64:
        result["sampled_at"] = sampled_at
    if len(canonical(result)) > BROWSER_CLEANUP_RESULT_MAX_BYTES:
        raise SwitchError("headless browser cleanup result is too large")
    return result


def perform_headless_browser_cleanup(
    release: Path,
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> dict[str, object] | None:
    cleanup = validate_headless_browser_cleanup_plan(document, release)
    if cleanup["required"] is not True:
        return None
    status = cleanup["status"]
    if status == "complete":
        return dict(cleanup["result"])
    if status in {"running", "failed"}:
        raise SwitchError(
            "headless browser cleanup has an uncertain or failed prior outcome; "
            "start a new same-schema transaction instead of replaying it"
        )

    cleanup["status"] = "running"
    cleanup["started_at"] = now()
    document["headless_browser_cleanup"] = cleanup
    save_phase(journal_path, document, str(document["phase"]))
    command = [
        str(release / "bin" / BROWSER_ACCOUNTING_WRAPPER),
        "cleanup-all",
        "--state",
        str(BROWSER_LIFECYCLE_STATE),
        "--quiescence-seconds",
        str(BROWSER_CLEANUP_QUIESCENCE_SECONDS),
        "--json",
    ]
    try:
        result = bounded_browser_cleanup_result(
            runner.require_json(command, "one-time headless browser cleanup")
        )
    except SwitchError as error:
        cleanup["status"] = "failed"
        cleanup["completed_at"] = now()
        cleanup["error"] = " ".join(str(error).split())[:512]
        document["headless_browser_cleanup"] = cleanup
        save_phase(journal_path, document, str(document["phase"]))
        raise
    cleanup["status"] = "complete"
    cleanup["completed_at"] = now()
    cleanup["result"] = result
    document["headless_browser_cleanup"] = cleanup
    save_phase(journal_path, document, str(document["phase"]))
    return result


def active_console(runner: Runner) -> tuple[str, str]:
    output = runner.require(
        [
            "/usr/bin/systemctl",
            "list-units",
            "devcoordinator-console@*.service",
            "--state=active",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        "active Console discovery",
    )
    units = sorted(
        {
            line.split()[0]
            for line in output.splitlines()
            if line.strip() and line.split()[0].startswith("devcoordinator-console@")
        }
    )
    if len(units) != 1:
        raise SwitchError("same-schema switch requires exactly one active Console slot")
    match = re.fullmatch(r"devcoordinator-console@([0-9a-f]{64})\.service", units[0])
    if match is None:
        raise SwitchError("active Console slot is not an immutable release")
    return units[0], match.group(1)


def parse_slot(payload: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in result or "\x00" in value:
            raise SwitchError("Console slot configuration is invalid")
        result[key] = value
    required = {
        "BIND_HOST",
        "DEV_HTTP",
        "HTTP_PORT",
        "HTTPS_PORT",
        "DEVCOORDINATOR_RELEASE_DIGEST",
        "DEVCOORDINATOR_CONSOLE_INNER_PORT",
        "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET",
        "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE",
        "DEVCOORDINATOR_CONSOLE_RUNTIME",
        "DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE",
    }
    if not required <= set(result):
        raise SwitchError("Console slot configuration is incomplete")
    try:
        ports = (int(result["HTTPS_PORT"]), int(result["DEVCOORDINATOR_CONSOLE_INNER_PORT"]))
    except ValueError as error:
        raise SwitchError("Console slot ports are invalid") from error
    if any(not PORT_MIN <= port <= PORT_MAX for port in ports) or ports[0] == ports[1]:
        raise SwitchError("Console slot ports are outside the production range")
    return result


def candidate_slot_payload(digest: str, outer_port: int, inner_port: int) -> bytes:
    if RELEASE_RE.fullmatch(digest) is None:
        raise SwitchError("candidate Console release digest is invalid")
    if (
        outer_port == inner_port
        or any(not PORT_MIN <= value <= PORT_MAX for value in (outer_port, inner_port))
    ):
        raise SwitchError("candidate Console ports are invalid")
    return (
        "# Generated same-schema Console candidate slot.\n"
        "BIND_HOST=127.0.0.1\n"
        "DEV_HTTP=0\n"
        "HTTP_PORT=0\n"
        f"HTTPS_PORT={outer_port}\n"
        f"DEVCOORDINATOR_RELEASE_DIGEST={digest}\n"
        f"DEVCOORDINATOR_CONSOLE_INNER_PORT={inner_port}\n"
        f"DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET=/run/devcoordinator-console/{digest}.sock\n"
        "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE=/var/lib/devcoordinator-console/supervisor\n"
        "DEVCOORDINATOR_CONSOLE_RUNTIME=/run/devcoordinator-console\n"
        "DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE=0\n"
    ).encode("utf-8")


def reserve_candidate_ports(excluded: set[int]) -> tuple[int, int]:
    reservations: list[socket.socket] = []
    values: list[int] = []
    try:
        for _ in range(64):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
            if not PORT_MIN <= port <= PORT_MAX or port in excluded or port in values:
                listener.close()
                continue
            reservations.append(listener)
            values.append(port)
            if len(values) == 2:
                return values[0], values[1]
        raise SwitchError("two unused Console loopback ports are unavailable")
    finally:
        for listener in reservations:
            listener.close()


def bind_exact_ports(ports: Sequence[int]) -> list[socket.socket]:
    listeners: list[socket.socket] = []
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            listener.bind(("127.0.0.1", int(port)))
            listeners.append(listener)
        return listeners
    except OSError as error:
        for listener in listeners:
            listener.close()
        raise SwitchError("candidate Console ports are no longer available") from error


def render_release(release: Path, transaction_root: Path) -> dict[str, object]:
    verified = installer.verify_release(release)
    digest = str(verified["release_digest"])
    rendered = transaction_root / "rendered-units"
    if rendered.exists():
        raise SwitchError("same-schema rendered unit directory already exists")
    rendered.mkdir(parents=True)
    capacity = installer.derive_slice_capacity(installer.host_memory_bytes())
    for name in (
        *activation.TOPOLOGY_FILES,
        "devcoordinator-availability.sysusers.conf",
        "devcoordinator-availability.tmpfiles.conf",
    ):
        source = release / "deploy" / name
        if not source.is_file() or source.is_symlink():
            raise SwitchError(f"immutable release template is unavailable: {name}")
        text = source.read_text(encoding="utf-8").replace("RELEASE_DIGEST", digest)
        for placeholder, field in installer.CAPACITY_PLACEHOLDERS.items():
            text = text.replace(placeholder, str(capacity[field]))
        if "RELEASE_DIGEST" in text or any(
            placeholder in text for placeholder in installer.CAPACITY_PLACEHOLDERS
        ):
            raise SwitchError(f"same-schema template retained a placeholder: {name}")
        atomic_bytes(rendered / name, text.encode("utf-8"), 0o644)
    for rendered_name, (_destination, immutable_name) in STABLE_LAUNCHERS.items():
        immutable = release / "bin" / immutable_name
        if not immutable.is_file() or immutable.is_symlink():
            raise SwitchError(
                f"immutable client wrapper is unavailable: {immutable_name}"
            )
        launcher = (
            "#!/bin/sh\n"
            "set -eu\n"
            f"exec '{immutable}' \"$@\"\n"
        ).encode("utf-8")
        atomic_bytes(rendered / rendered_name, launcher, 0o755)
    for rendered_name in (READ_ONLY_RULE_RENDERED, TEST_RULE_RENDERED):
        immutable_rule = release / "deploy" / rendered_name
        if not immutable_rule.is_file() or immutable_rule.is_symlink():
            raise SwitchError(
                f"immutable Codex client rule is unavailable: {rendered_name}"
            )
        atomic_bytes(rendered / rendered_name, immutable_rule.read_bytes(), 0o644)
    return {"release_digest": digest, "release": str(release), "rendered_units": str(rendered)}


def destinations(rendered: Path) -> dict[str, Path]:
    result = {name: UNIT_ROOT / name for name in activation.TOPOLOGY_FILES}
    result["devcoordinator-availability.sysusers.conf"] = (
        SYSUSERS_ROOT / "devcoordinator-availability.sysusers.conf"
    )
    result["devcoordinator-availability.tmpfiles.conf"] = (
        TMPFILES_ROOT / "devcoordinator-availability.tmpfiles.conf"
    )
    for rendered_name, (destination, _immutable_name) in STABLE_LAUNCHERS.items():
        result[rendered_name] = destination
    result[READ_ONLY_RULE_RENDERED] = READ_ONLY_RULE
    result[TEST_RULE_RENDERED] = TEST_RULE
    if any(not (rendered / name).is_file() for name in result):
        raise SwitchError("rendered same-schema unit set is incomplete")
    return result


def destination_mode(name: str) -> int:
    return 0o755 if name in STABLE_LAUNCHERS else 0o644


def codex_directory_mode(directory: Path) -> int:
    return 0o755


def codex_directory_states() -> dict[str, object]:
    result: dict[str, object] = {}
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            result[str(directory)] = {"existed": False}
            continue
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise SwitchError(f"Codex configuration directory is unsafe: {directory}")
        result[str(directory)] = {
            "existed": True,
            "mode": stat.S_IMODE(info.st_mode),
        }
    return result


def prepare_codex_directories(states: Mapping[str, object]) -> None:
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        raw = states.get(str(directory))
        if not isinstance(raw, Mapping) or type(raw.get("existed")) is not bool:
            raise SwitchError("Codex configuration directory plan is invalid")
        if raw["existed"] is True:
            info = directory.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != raw.get("mode")
            ):
                raise SwitchError(
                    f"Codex configuration directory changed before apply: {directory}"
                )
        else:
            directory.mkdir(mode=codex_directory_mode(directory))
        os.chmod(directory, codex_directory_mode(directory))


def restore_codex_directories(states: Mapping[str, object]) -> None:
    for directory in (CODEX_RULE_ROOT, CODEX_ROOT):
        raw = states.get(str(directory))
        if not isinstance(raw, Mapping) or type(raw.get("existed")) is not bool:
            raise SwitchError("Codex configuration directory rollback plan is invalid")
        if raw["existed"] is True:
            os.chmod(directory, int(raw["mode"]))
        elif directory.exists():
            directory.rmdir()


def publication_snapshot() -> dict[str, object]:
    value = load_json(PUBLICATION_FILE)
    publication = value.get("publication")
    if not isinstance(publication, Mapping):
        raise SwitchError("edge publication payload is invalid")
    console = publication.get("console")
    upstream = console.get("upstream") if isinstance(console, Mapping) else None
    if (
        not isinstance(upstream, Mapping)
        or not isinstance(value.get("payload_sha256"), str)
        or not isinstance(publication.get("release_digest"), str)
        or type(publication.get("generation")) is not int
        or type(upstream.get("port")) is not int
    ):
        raise SwitchError("edge publication Console target is invalid")
    return {
        "payload_sha256": value["payload_sha256"],
        "release_digest": publication["release_digest"],
        "generation": publication["generation"],
        "port": upstream["port"],
    }


def prepare(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.expanduser().resolve(strict=True)
    if (
        release.parent != Path("/opt/devcoordinator/releases")
        or RELEASE_RE.fullmatch(release.name) is None
    ):
        raise SwitchError("same-schema release is not one immutable production path")
    transaction_root.mkdir(parents=True, exist_ok=True)
    existing = load_journal(transaction_root / "journal.json")
    if existing is not None:
        if existing.get("release") != str(release):
            raise SwitchError("same-schema transaction belongs to another release")
        require_test_history_reset_mode(existing, requested=reset_test_history)
        return existing
    current_unit, current_digest = active_console(runner)
    current_slot = SLOT_ROOT / f"{current_digest}.env"
    if not current_slot.is_file() or current_slot.is_symlink():
        raise SwitchError("active Console slot configuration is unavailable")
    current_values = parse_slot(current_slot.read_text(encoding="utf-8"))
    if current_values["DEVCOORDINATOR_RELEASE_DIGEST"] != current_digest:
        raise SwitchError("active Console slot release identity is invalid")
    old_outer = int(current_values["HTTPS_PORT"])
    old_inner = int(current_values["DEVCOORDINATOR_CONSOLE_INNER_PORT"])
    published = publication_snapshot()
    if published["release_digest"] != current_digest or published["port"] != old_outer:
        raise SwitchError("active Console slot contradicts the edge publication")
    if current_digest == release.name:
        browser_cleanup = headless_browser_cleanup_plan(
            release,
            previous_release_digest=current_digest,
        )
        document = {
            "schema_version": VERSION,
            "kind": KIND,
            "phase": "prepared" if reset_test_history else "applied",
            "release": str(release),
            "release_digest": release.name,
            "previous_release_digest": current_digest,
            "previous_console_unit": current_unit,
            "candidate_console_unit": current_unit,
            "previous_console_slot": str(current_slot),
            "candidate_console_slot_source": str(current_slot),
            "previous_control_socket": current_values[
                "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"
            ],
            "candidate_control_socket": current_values[
                "DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"
            ],
            "previous_outer_port": old_outer,
            "previous_inner_port": old_inner,
            "candidate_outer_port": old_outer,
            "candidate_inner_port": old_inner,
            "publication_before": published,
            "rendered_units": None,
            "expected_destinations": {},
            "backups": {},
            "candidate_started": True,
            "promoted": True,
            "publication_switched": True,
            "already_active": True,
            "headless_browser_cleanup": browser_cleanup,
        }
        if reset_test_history:
            document["test_history_reset"] = test_history_reset_intent(
                release, previous_release_digest=current_digest
            )
        else:
            document["completed_at"] = now()
        document["plan_sha256"] = hashlib.sha256(canonical(document)).hexdigest()
        atomic_json(transaction_root / "journal.json", document)
        return document
    outer, inner = reserve_candidate_ports({old_outer, old_inner})
    rendered = render_release(release, transaction_root)
    browser_cleanup = headless_browser_cleanup_plan(
        release,
        previous_release_digest=current_digest,
    )
    new_slot = transaction_root / f"{release.name}.env"
    atomic_bytes(new_slot, candidate_slot_payload(release.name, outer, inner), 0o644)
    unit_sources = destinations(Path(str(rendered["rendered_units"])))
    expected = {
        str(destination): (
            digest_file(destination)
            if destination.is_file() and not destination.is_symlink()
            else None
        )
        for destination in unit_sources.values()
    }
    document: dict[str, object] = {
        "schema_version": VERSION,
        "kind": KIND,
        "phase": "prepared",
        "release": str(release),
        "release_digest": release.name,
        "previous_release_digest": current_digest,
        "previous_console_unit": current_unit,
        "candidate_console_unit": f"devcoordinator-console@{release.name}.service",
        "previous_console_slot": str(current_slot),
        "candidate_console_slot_source": str(new_slot),
        "previous_control_socket": current_values["DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET"],
        "candidate_control_socket": f"/run/devcoordinator-console/{release.name}.sock",
        "previous_outer_port": old_outer,
        "previous_inner_port": old_inner,
        "candidate_outer_port": outer,
        "candidate_inner_port": inner,
        "publication_before": published,
        "rendered_units": rendered["rendered_units"],
        "expected_destinations": expected,
        "codex_directory_states": codex_directory_states(),
        "backups": {},
        "candidate_started": False,
        "promoted": False,
        "publication_switched": False,
        "headless_browser_cleanup": browser_cleanup,
    }
    if reset_test_history:
        document["test_history_reset"] = test_history_reset_intent(
            release, previous_release_digest=current_digest
        )
    document["plan_sha256"] = hashlib.sha256(canonical(document)).hexdigest()
    atomic_json(transaction_root / "journal.json", document)
    return document


def backup_destinations(
    document: Mapping[str, object], transaction_root: Path
) -> dict[str, object]:
    rendered = Path(str(document["rendered_units"]))
    mapping = destinations(rendered)
    root = transaction_root / "backups"
    root.mkdir(parents=True, exist_ok=True)
    expected_destinations = document.get("expected_destinations")
    if not isinstance(expected_destinations, Mapping):
        raise SwitchError("same-schema destination plan is invalid")
    result: dict[str, object] = {}
    for name, destination in mapping.items():
        expected = expected_destinations.get(str(destination))
        if destination.exists() and (not destination.is_file() or destination.is_symlink()):
            raise SwitchError(f"same-schema destination is not a real file: {destination}")
        actual = digest_file(destination) if destination.exists() else None
        if actual != expected:
            raise SwitchError(f"same-schema destination changed before apply: {destination}")
        if destination.exists():
            backup = root / name
            atomic_bytes(backup, destination.read_bytes(), destination.stat().st_mode & 0o777)
            result[str(destination)] = {
                "existed": True,
                "backup": str(backup),
                "mode": destination.stat().st_mode & 0o777,
            }
        else:
            result[str(destination)] = {"existed": False}
    return result


def install_rendered_destinations(rendered: Path) -> None:
    """Atomically replace every destination in the prepared release graph."""

    for name, destination in destinations(rendered).items():
        atomic_bytes(
            destination,
            (rendered / name).read_bytes(),
            destination_mode(name),
        )


def restore_destination_backups(backups: Mapping[str, object]) -> None:
    """Restore or remove every destination exactly as the transaction found it."""

    for raw_destination, evidence in backups.items():
        if not isinstance(evidence, Mapping):
            raise SwitchError("same-schema rollback evidence is invalid")
        destination = Path(raw_destination)
        if evidence.get("existed") is True:
            backup = Path(str(evidence["backup"]))
            atomic_bytes(destination, backup.read_bytes(), int(evidence["mode"]))
        elif evidence.get("existed") is False:
            destination.unlink(missing_ok=True)
        else:
            raise SwitchError("same-schema rollback evidence is invalid")


def restart_services(runner: Runner) -> None:
    # These socket units own their /run directory and pathname. Older service
    # templates lifecycle-managed the same directories, so an already-active
    # socket may retain only an unreachable, unlinked listener after a service
    # restart. Rebinding before service replacement repairs that state and
    # ensures the new process inherits the reachable listener.
    for unit in RUNTIME_SOCKET_REBIND_ORDER:
        runner.require(["/usr/bin/systemctl", "restart", unit], f"rebind {unit}")
    for unit in SERVICE_ORDER:
        runner.require(["/usr/bin/systemctl", "restart", unit], f"restart {unit}")


def unix_socket_health(path: Path, timeout_seconds: float = 1.0) -> dict[str, object]:
    try:
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise OSError("path is not a Unix socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout_seconds)
            connection.connect(str(path))
        return {"ok": True, "path": str(path)}
    except OSError as error:
        return {
            "ok": False,
            "path": str(path),
            "error": " ".join(str(error).split())[:512],
        }


def unit_active(runner: Runner, unit: str) -> bool:
    return runner.run(["/usr/bin/systemctl", "is-active", "--quiet", unit]).returncode == 0


def test_history_wrapper(release: Path) -> Path:
    wrapper = release / "bin" / TEST_HISTORY_WRAPPER
    if not wrapper.is_file() or wrapper.is_symlink() or not os.access(wrapper, os.X_OK):
        raise SwitchError(
            f"immutable release lacks the test-history wrapper: {release}"
        )
    return wrapper


def stop_test_plane(runner: Runner) -> None:
    # Stop socket activation first so the service cannot reappear while the
    # isolated SQLite main/WAL/SHM triplet is replaced.
    runner.require(
        ["/usr/bin/systemctl", "stop", TESTD_SOCKET, TESTD_SERVICE],
        "stop isolated test plane",
    )
    require_test_plane_stopped(runner)


def require_test_plane_stopped(runner: Runner) -> None:
    if unit_active(runner, TESTD_SOCKET) or unit_active(runner, TESTD_SERVICE):
        raise SwitchError("test-history reset requires testd and its socket to be stopped")


def restart_test_plane(runner: Runner) -> None:
    runner.require(
        ["/usr/bin/systemctl", "restart", TESTD_SOCKET],
        "restart testd socket",
    )
    runner.require(
        ["/usr/bin/systemctl", "restart", TESTD_SERVICE],
        "restart testd service",
    )


def run_test_history_command(
    runner: Runner,
    release: Path,
    argv: Sequence[str],
    *,
    label: str,
) -> dict[str, object]:
    return runner.require_json(
        [
            "/usr/sbin/runuser",
            "--user",
            TESTD_USER,
            "--",
            str(test_history_wrapper(release)),
            *argv,
        ],
        label,
    )


def test_store_paths() -> tuple[Path, Path, Path]:
    return (
        Path(str(TEST_DATABASE) + "-shm"),
        Path(str(TEST_DATABASE) + "-wal"),
        TEST_DATABASE,
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_real_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise SwitchError(f"{label} is unavailable: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SwitchError(f"{label} is not a real directory: {path}")
    return metadata


def create_fresh_test_spool(*, expected_test_uid: int) -> None:
    TEST_SPOOL.mkdir(mode=0o700)
    created = [TEST_SPOOL]
    try:
        for name in TEST_SPOOL_QUEUES:
            path = TEST_SPOOL / name
            path.mkdir(mode=0o700)
            created.append(path)
        for path in created:
            os.chown(path, expected_test_uid, -1)
        fsync_directory(TEST_SPOOL)
        fsync_directory(TEST_SPOOL.parent)
    except BaseException:
        shutil.rmtree(TEST_SPOOL, ignore_errors=True)
        raise


def verify_fresh_test_spool() -> None:
    require_real_directory(TEST_SPOOL, label="fresh test spool")
    observed = {entry.name for entry in TEST_SPOOL.iterdir()}
    if observed != set(TEST_SPOOL_QUEUES):
        raise SwitchError("fresh test spool has unexpected entries")
    for name in TEST_SPOOL_QUEUES:
        queue = TEST_SPOOL / name
        require_real_directory(queue, label="fresh test spool queue")
        if any(queue.iterdir()):
            raise SwitchError("fresh test spool queue is not empty")


def discard_test_spool(
    reset: Mapping[str, object], *, rollback: bool, runner: Runner
) -> dict[str, object]:
    require_test_plane_stopped(runner)
    discard_key = (
        "rollback_discarded_spool" if rollback else "forward_discarded_spool"
    )
    discarded_path = Path(str(reset[discard_key]))
    if discarded_path.parent != TEST_SPOOL.parent:
        raise SwitchError("test spool discard path leaves the service state directory")
    try:
        discarded_metadata = discarded_path.lstat()
    except FileNotFoundError:
        discarded_metadata = None
    if discarded_metadata is not None and (
        not stat.S_ISDIR(discarded_metadata.st_mode)
        or stat.S_ISLNK(discarded_metadata.st_mode)
    ):
        raise SwitchError("test spool discard target is not a real directory")

    # A retained discard directory is replay evidence that the prior spool
    # existed and was already atomically rotated before interruption.
    discarded_existing = discarded_metadata is not None
    if discarded_metadata is None:
        try:
            current_metadata = TEST_SPOOL.lstat()
        except FileNotFoundError:
            current_metadata = None
        if current_metadata is not None:
            if (
                not stat.S_ISDIR(current_metadata.st_mode)
                or stat.S_ISLNK(current_metadata.st_mode)
            ):
                raise SwitchError("test spool is not a real directory")
            os.replace(TEST_SPOOL, discarded_path)
            fsync_directory(TEST_SPOOL.parent)
            discarded_existing = True
    elif TEST_SPOOL.exists():
        # Replay after the old spool was rotated must see only the empty spool
        # created by this exact reset operation.  Nothing can legitimately add
        # entries while both testd and its activation socket are stopped.
        verify_fresh_test_spool()

    if not TEST_SPOOL.exists():
        create_fresh_test_spool(expected_test_uid=int(reset["expected_test_uid"]))
    verify_fresh_test_spool()

    if discarded_path.exists():
        shutil.rmtree(discarded_path)
        fsync_directory(TEST_SPOOL.parent)
    return {
        "test_spool": str(TEST_SPOOL),
        "discarded_path": str(discarded_path),
        "discarded_existing": discarded_existing,
        "queues": list(TEST_SPOOL_QUEUES),
        "fresh": True,
    }


def discard_test_store_triplet() -> list[str]:
    discarded: list[str] = []
    for path in test_store_paths():
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise SwitchError(f"test-history rollback path is not a regular file: {path}")
        path.unlink()
        discarded.append(str(path))
    fsync_directory(TEST_DATABASE.parent)
    return discarded


def reset_test_history_for_release(
    release: Path,
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> None:
    reset = dict(require_test_history_reset_mode(document, requested=True) or {})
    if reset.get("status") == "complete":
        return
    if reset.get("status") not in {"planned", "resetting"}:
        raise SwitchError("test-history reset cannot run from the recorded state")
    reset.update({"status": "resetting", "started_at": reset.get("started_at") or now()})
    save_phase(journal_path, document, "applying", test_history_reset=reset)
    stop_test_plane(runner)
    spool_evidence = discard_test_spool(reset, rollback=False, runner=runner)
    result = run_test_history_command(
        runner,
        release,
        [
            "testd-initialize-fresh",
            "--test-database",
            str(TEST_DATABASE),
            "--operation-id",
            str(reset["operation_id"]),
            "--attestation-output",
            str(reset["attestation"]),
            "--expected-test-uid",
            str(reset["expected_test_uid"]),
            "--confirm-discard-test-history",
            "discard-test-history",
        ],
        label="initialize fresh schema-5 test history",
    )
    fingerprint = result.get("attestation_fingerprint")
    if (
        result.get("action") != "testd-initialize-fresh"
        or result.get("branch") != "attested-fresh-v5"
        or result.get("attestation") != reset["attestation"]
        or not isinstance(fingerprint, str)
        or RELEASE_RE.fullmatch(fingerprint) is None
        or not isinstance(result.get("store_generation"), str)
    ):
        raise SwitchError("fresh schema-5 test-history evidence is invalid")
    reset.update(
        {
            "status": "complete",
            "completed_at": now(),
            "forward_evidence": {
                "action": result["action"],
                "schema_version": 5,
                "branch": result["branch"],
                "attestation": result["attestation"],
                "attestation_fingerprint": fingerprint,
                "store_generation": result["store_generation"],
                "discarded_existing": result.get("discarded_existing"),
                "replayed": result.get("replayed"),
                "spool": spool_evidence,
            },
        }
    )
    save_phase(journal_path, document, "applying", test_history_reset=reset)


def reset_test_history_for_rollback(
    document: dict[str, object],
    journal_path: Path,
    runner: Runner,
) -> None:
    reset = dict(require_test_history_reset_mode(document, requested=True) or {})
    if reset.get("status") == "rolled-back":
        return
    if reset.get("status") not in {"resetting", "complete", "rollback-resetting"}:
        raise SwitchError("test-history rollback cannot run from the recorded state")
    reset.update(
        {
            "status": "rollback-resetting",
            "rollback_started_at": reset.get("rollback_started_at") or now(),
        }
    )
    save_phase(journal_path, document, "rolling-back", test_history_reset=reset)
    stop_test_plane(runner)
    spool_evidence = discard_test_spool(reset, rollback=True, runner=runner)
    discarded = discard_test_store_triplet()
    previous_release = Path(str(reset["previous_release"]))
    result = run_test_history_command(
        runner,
        previous_release,
        [
            "create",
            "--test-database",
            str(TEST_DATABASE),
            "--expected-test-uid",
            str(reset["expected_test_uid"]),
        ],
        label="initialize previous-release empty test history",
    )
    if (
        result.get("action") != "create"
        or result.get("test_database") != str(TEST_DATABASE)
        or result.get("schema_version") != 5
        or not isinstance(result.get("store_generation"), str)
    ):
        raise SwitchError("previous release returned invalid empty-store evidence")
    reset.update(
        {
            "status": "rolled-back",
            "rollback_completed_at": now(),
            "rollback_evidence": {
                "action": result["action"],
                "schema_version": result["schema_version"],
                "store_generation": result["store_generation"],
                "test_database": result["test_database"],
                "discarded_paths": discarded,
                "spool": spool_evidence,
                "release": str(previous_release),
            },
        }
    )
    save_phase(journal_path, document, "rolling-back", test_history_reset=reset)


def slot_status(
    runner: Runner, release: Path, control: str, label: str
) -> dict[str, object]:
    return runner.require_json(
        [
            str(release / "bin/devcoordinator-console-slot-control"),
            "status",
            "--socket",
            control,
        ],
        label,
    )


def unit_diagnostics(runner: Runner, unit: str) -> dict[str, object]:
    """Return bounded startup evidence without turning diagnostics into policy."""

    commands = {
        "systemd": [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,StatusErrno",
        ],
        "journal": [
            "/usr/bin/journalctl",
            "--unit",
            unit,
            "--no-pager",
            "--output=short-iso",
            "--lines=80",
        ],
    }
    evidence: dict[str, object] = {}
    for name, argv in commands.items():
        result = runner.run(argv)
        combined = (result.stdout + result.stderr).strip()
        evidence[name] = {
            "returncode": result.returncode,
            "output": combined[-16_384:],
        }
    return evidence


def wait_slot_status(
    runner: Runner,
    release: Path,
    control: str,
    unit: str,
    label: str,
    *,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    """Wait for the supervisor-owned socket after systemd executes the process."""

    deadline = time.monotonic() + timeout_seconds
    last_error = "control socket was not queried"
    while True:
        try:
            return slot_status(runner, release, control, label)
        except SwitchError as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostics = unit_diagnostics(runner, unit)
            raise SwitchError(
                f"{label} did not become ready within {timeout_seconds:g}s: "
                f"{last_error}; diagnostics={json.dumps(diagnostics, sort_keys=True)}"
            )
        time.sleep(min(0.1, remaining))


def http_health(url: str, timeout: float) -> dict[str, object]:
    started = time.monotonic()
    try:
        with urlopen(
            Request(url, headers={"Accept": "application/json"}), timeout=timeout
        ) as response:
            status = int(response.status)
            body = response.read(1024 * 1024)
    except HTTPError as error:
        return {"url": url, "ok": False, "status": int(error.code)}
    except (OSError, URLError):
        return {"url": url, "ok": False, "status": None}
    document: object | None = None
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return {
        "url": url,
        "ok": 200 <= status < 300,
        "status": status,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "document": document,
    }


def wait_edge_publication(
    url: str,
    *,
    release_digest: str,
    generation: int,
    timeout_seconds: float = 8.0,
) -> dict[str, object]:
    """Wait for the running edge to adopt the root-published snapshot."""

    deadline = time.monotonic() + timeout_seconds
    last: dict[str, object] = {"url": url, "ok": False, "status": None}
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SwitchError(
                "running edge did not adopt Console publication "
                f"generation {generation} for release {release_digest}; "
                f"last={json.dumps(last, sort_keys=True)}"
            )
        last = http_health(url, min(2.0, remaining))
        document = last.get("document")
        if (
            last.get("ok") is True
            and isinstance(document, Mapping)
            and document.get("release") == release_digest
            and document.get("generation") == generation
        ):
            return last
        time.sleep(min(0.1, max(0.0, remaining)))


def direct_https_health(port: int, path: str, timeout: float = 8.0) -> dict[str, object]:
    started = time.monotonic()
    status: int | None = None
    body = b""
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=CONSOLE_HOST) as stream:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {CONSOLE_HOST}\r\n"
                    "Accept: application/json\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                stream.sendall(request)
                chunks: list[bytes] = []
                while sum(len(item) for item in chunks) < 1024 * 1024:
                    block = stream.recv(65536)
                    if not block:
                        break
                    chunks.append(block)
                response = b"".join(chunks)
        head, _separator, body = response.partition(b"\r\n\r\n")
        first = head.splitlines()[0].decode("ascii")
        status = int(first.split()[1])
    except (OSError, ssl.SSLError, ValueError, IndexError, UnicodeError):
        pass
    return {
        "url": f"https://127.0.0.1:{port}{path}",
        "ok": status is not None and 200 <= status < 300,
        "status": status,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
    }


def require_probe(result: Mapping[str, object], label: str) -> None:
    if result.get("ok") is not True:
        raise SwitchError(f"{label} failed with status {result.get('status')}")


def publication_cli(release: Path) -> Path:
    command = release / "bin/devcoordinator-edge-publication"
    if not command.is_file() or not os.access(command, os.X_OK):
        raise SwitchError("immutable release lacks edge publication tooling")
    return command


def switch_publication(
    runner: Runner,
    release: Path,
    *,
    digest: str,
    port: int,
) -> dict[str, object]:
    verified = runner.require_json(
        [
            str(publication_cli(release)),
            "verify",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
        ],
        "edge publication verification",
    )
    return runner.require_json(
        [
            str(publication_cli(release)),
            "switch-console",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
            "--expected-payload-sha256",
            str(verified["payload_sha256"]),
            "--release-digest",
            digest,
            "--port",
            str(port),
            "--published-at",
            now(),
        ],
        "edge Console publication switch",
    )


def normalize_local_paths(runner: Runner) -> None:
    runner.require(
        [
            "/usr/bin/systemd-sysusers",
            str(SYSUSERS_ROOT / "devcoordinator-availability.sysusers.conf"),
        ],
        "systemd service identity preparation",
    )
    runner.require(
        [
            "/usr/bin/systemd-tmpfiles",
            "--create",
            str(TMPFILES_ROOT / "devcoordinator-availability.tmpfiles.conf"),
        ],
        "systemd runtime path preparation",
    )
    if not CLIENT_PROFILE.is_file() or CLIENT_PROFILE.is_symlink():
        raise SwitchError("non-secret local client profile is unavailable")
    # Local Unix accounts are one trusted developer.  Publish this non-secret
    # profile for direct reads instead of relying on shared-group membership.
    os.chmod(CLIENT_PROFILE, 0o644)
    # Same-schema delivery never takes the authority database offline.  Any
    # inherited marker therefore belongs to an abandoned legacy cutover and
    # must not keep every local account fenced after this healthy switch.
    MAINTENANCE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(MAINTENANCE_ROOT, 0o755)
    try:
        marker = MAINTENANCE_MARKER.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISDIR(marker.st_mode):
            raise SwitchError("stale maintenance marker path is a directory")
        MAINTENANCE_MARKER.unlink()


def save_phase(path: Path, document: dict[str, object], phase: str, **values: object) -> None:
    document.update(values)
    document["phase"] = phase
    atomic_json(path, document)


def apply(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    journal_path = transaction_root / "journal.json"
    document = load_journal(journal_path)
    if document is None:
        document = prepare(
            release,
            transaction_root,
            runner,
            reset_test_history=reset_test_history,
        )
    if document.get("release") != str(release):
        raise SwitchError("same-schema journal belongs to another release")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    if document.get("phase") == "applied":
        validate_headless_browser_cleanup_plan(document, release)
        if reset is not None and reset.get("status") != "complete":
            raise SwitchError("applied same-schema reset lacks completion evidence")
        return document
    if document.get("phase") not in {"prepared", "applying"}:
        raise SwitchError("same-schema journal cannot be applied from this phase")

    if document.get("already_active") is True:
        validate_headless_browser_cleanup_plan(document, release)
        if reset is None:
            raise SwitchError("already-active same-schema transaction is incomplete")
        reset_test_history_for_release(release, document, journal_path, runner)
        restart_test_plane(runner)
        save_phase(journal_path, document, "applied", completed_at=now())
        return document

    ports = [int(document["candidate_outer_port"]), int(document["candidate_inner_port"])]
    reservations = bind_exact_ports(ports)
    try:
        if not document.get("backups"):
            document["backups"] = backup_destinations(document, transaction_root)
        save_phase(journal_path, document, "applying")
        directory_states = document.get("codex_directory_states")
        if not isinstance(directory_states, Mapping):
            raise SwitchError("Codex configuration directory plan is unavailable")
        prepare_codex_directories(directory_states)
        rendered = Path(str(document["rendered_units"]))
        install_rendered_destinations(rendered)
        candidate_slot = SLOT_ROOT / f"{document['release_digest']}.env"
        atomic_bytes(
            candidate_slot,
            Path(str(document["candidate_console_slot_source"])).read_bytes(),
            0o644,
        )
        normalize_local_paths(runner)
        runner.require(["/usr/bin/systemctl", "daemon-reload"], "systemd daemon reload")
        if reset is not None:
            reset_test_history_for_release(release, document, journal_path, runner)
        perform_headless_browser_cleanup(
            release,
            document,
            journal_path,
            runner,
        )
        restart_services(runner)
    finally:
        for listener in reservations:
            listener.close()

    candidate = str(document["candidate_console_unit"])
    previous = str(document["previous_console_unit"])
    candidate_control = str(document["candidate_control_socket"])
    previous_control = str(document["previous_control_socket"])
    runner.require(["/usr/bin/systemctl", "enable", "--now", candidate], "candidate Console start")
    candidate_status = wait_slot_status(
        runner,
        release,
        candidate_control,
        candidate,
        "candidate Console status",
    )
    if candidate_status.get("release_digest") != document["release_digest"]:
        raise SwitchError("candidate Console status has another release")
    require_probe(
        direct_https_health(int(document["candidate_outer_port"]), "/_devcoordinator/slot-health"),
        "candidate Console supervisor health",
    )
    save_phase(journal_path, document, "applying", candidate_started=True)

    try:
        previous_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console status",
            timeout_seconds=2,
        )
    except SwitchError:
        previous_status = None
    candidate_status = slot_status(runner, release, candidate_control, "candidate Console status")
    live_before_promotion = publication_snapshot()
    previous_is_published = (
        live_before_promotion["release_digest"] == document["previous_release_digest"]
        and live_before_promotion["port"] == document["previous_outer_port"]
    )
    if (
        candidate_status.get("mode") == "active"
        and (previous_status is None or previous_status.get("mode") == "standby")
    ):
        promoted = True
    elif candidate_status.get("mode") == "standby" and (
        previous_status is not None and previous_status.get("mode") == "active"
        or previous_status is None and previous_is_published
    ):
        command = [
            str(release / "bin/devcoordinator-console-slot-control"),
            "promote",
            "--socket",
            candidate_control,
            "--timeout-seconds",
            "30",
        ]
        if previous_status is not None:
            command.extend(["--old-socket", previous_control])
        runner.require_json(command, "candidate Console promotion")
        promoted = True
    else:
        raise SwitchError("Console slots are not in one promotable state")
    require_probe(
        direct_https_health(int(document["candidate_outer_port"]), "/healthz"),
        "candidate Console direct health",
    )
    save_phase(journal_path, document, "applying", promoted=promoted)

    live = publication_snapshot()
    if live["release_digest"] == document["release_digest"] and live["port"] == document["candidate_outer_port"]:
        published = live
        switched = True
    elif live["release_digest"] == document["previous_release_digest"] and live["port"] == document["previous_outer_port"]:
        published = switch_publication(
            runner,
            release,
            digest=str(document["release_digest"]),
            port=int(document["candidate_outer_port"]),
        )
        switched = True
    else:
        raise SwitchError("edge publication has an unknown Console target")
    save_phase(journal_path, document, "applying", publication_switched=switched)
    wait_edge_publication(
        "https://console.vr.ae/healthz",
        release_digest=str(document["release_digest"]),
        generation=int(published["generation"]),
    )

    runner.require(["/usr/bin/systemctl", "stop", previous], "previous Console drain")
    runner.run(["/usr/bin/systemctl", "disable", previous])
    save_phase(
        journal_path,
        document,
        "applied",
        candidate_console_slot=str(candidate_slot),
        completed_at=now(),
    )
    return document


def verify(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    public_url: str,
    api_url: str,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    document = load_journal(transaction_root / "journal.json")
    if document is None or document.get("release") != str(release):
        raise SwitchError("same-schema switch journal is unavailable")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    if reset is not None and reset.get("status") != "complete":
        raise SwitchError("same-schema test-history reset is incomplete")
    units = [*SERVICE_ORDER, *REQUIRED_SOCKETS, str(document["candidate_console_unit"])]
    states = {unit: unit_active(runner, unit) for unit in units}
    probes = [
        http_health(api_url, 5.0),
        direct_https_health(int(document["candidate_outer_port"]), "/healthz"),
        unix_socket_health(Path("/run/devcoordinator-testd/testd.sock")),
        unix_socket_health(Path("/run/devcoordinator-test-snapshotd/snapshot.sock")),
    ]
    status = slot_status(
        runner,
        release,
        str(document["candidate_control_socket"]),
        "candidate Console status",
    )
    publication = runner.require_json(
        [
            str(publication_cli(release)),
            "verify",
            "--file",
            str(PUBLICATION_FILE),
            "--release-root",
            str(release.parent),
        ],
        "edge publication verification",
    )
    probes.append(
        wait_edge_publication(
            public_url,
            release_digest=str(document["release_digest"]),
            generation=int(publication["generation"]),
        )
    )
    profile_readable = False
    try:
        with CLIENT_PROFILE.open("rb") as handle:
            profile_readable = bool(handle.read(1))
    except OSError:
        profile_readable = False
    rendered = Path(str(document["rendered_units"]))
    installed_client_access: dict[str, object] = {}
    for name in (
        *STABLE_LAUNCHERS,
        READ_ONLY_RULE_RENDERED,
        TEST_RULE_RENDERED,
    ):
        destination = destinations(rendered)[name]
        expected_mode = destination_mode(name)
        regular = destination.is_file() and not destination.is_symlink()
        actual_mode = destination.stat().st_mode & 0o777 if regular else None
        installed_client_access[name] = {
            "destination": str(destination),
            "regular_file": regular,
            "sha256_matches": regular
            and digest_file(destination) == digest_file(rendered / name),
            "mode": actual_mode,
            "expected_mode": expected_mode,
            "ok": regular
            and actual_mode == expected_mode
            and digest_file(destination) == digest_file(rendered / name),
        }
    launcher_results = {
        rendered_name: runner.run([str(destination), "--help"])
        for rendered_name, (destination, _immutable_name) in STABLE_LAUNCHERS.items()
    }
    launcher_healthy = all(
        result.returncode == 0 for result in launcher_results.values()
    )
    codex_directories: dict[str, object] = {}
    for directory in (CODEX_ROOT, CODEX_RULE_ROOT):
        regular_directory = directory.is_dir() and not directory.is_symlink()
        mode = directory.stat().st_mode & 0o777 if regular_directory else None
        owner_uid = directory.stat().st_uid if regular_directory else None
        expected_mode = codex_directory_mode(directory)
        codex_directories[str(directory)] = {
            "directory": regular_directory,
            "mode": mode,
            "expected_mode": expected_mode,
            "owner_uid": owner_uid,
            "expected_owner_uid": os.geteuid(),
            "ok": regular_directory
            and mode == expected_mode
            and owner_uid == os.geteuid(),
        }
    ok = (
        all(states.values())
        and all(bool(item["ok"]) for item in probes)
        and status.get("mode") == "active"
        and status.get("release_digest") == document["release_digest"]
        and publication.get("release_digest") == document["release_digest"]
        and profile_readable
        and all(bool(item["ok"]) for item in installed_client_access.values())
        and launcher_healthy
        and all(bool(item["ok"]) for item in codex_directories.values())
    )
    result = {
        "ok": ok,
        "release_digest": document["release_digest"],
        "services": states,
        "probes": probes,
        "console_slot": status,
        "publication": publication,
        "client_profile_readable": profile_readable,
        "codex_client_access": installed_client_access,
        "codex_read_only_access": {
            name: installed_client_access[name]
            for name in (
                CLIENT_LAUNCHER_RENDERED,
                BUG_LAUNCHER_RENDERED,
                CALL_LOG_LAUNCHER_RENDERED,
                READ_ONLY_RULE_RENDERED,
            )
        },
        "codex_test_access": {
            name: installed_client_access[name]
            for name in (TEST_LAUNCHER_RENDERED, TEST_RULE_RENDERED)
        },
        "client_launcher_help": {
            name: {
                "ok": completed.returncode == 0,
                "returncode": completed.returncode,
                "stderr": completed.stderr[-1000:],
            }
            for name, completed in launcher_results.items()
        },
        "test_launcher_help": {
            "ok": launcher_results[TEST_LAUNCHER_RENDERED].returncode == 0,
            "returncode": launcher_results[TEST_LAUNCHER_RENDERED].returncode,
            "stderr": launcher_results[TEST_LAUNCHER_RENDERED].stderr[-1000:],
        },
        "codex_rule_directories": codex_directories,
        "test_history_reset": dict(reset) if reset is not None else None,
    }
    if not ok:
        raise SwitchError("same-schema control-plane health failed")
    return result


def rollback(
    release: Path,
    transaction_root: Path,
    runner: Runner,
    *,
    reset_test_history: bool = False,
) -> dict[str, object]:
    release = release.resolve(strict=True)
    journal_path = transaction_root / "journal.json"
    document = load_journal(journal_path)
    if document is None or document.get("release") != str(release):
        raise SwitchError("same-schema rollback journal is unavailable")
    reset = require_test_history_reset_mode(
        document, requested=reset_test_history
    )
    if document.get("phase") == "rolled-back":
        return document
    backups = document.get("backups")
    if not isinstance(backups, Mapping) or not backups:
        # Apply failed before touching the installed graph.
        if reset is not None and reset.get("status") in {
            "resetting",
            "complete",
            "rollback-resetting",
        }:
            reset_test_history_for_rollback(document, journal_path, runner)
            restart_test_plane(runner)
        save_phase(journal_path, document, "rolled-back", completed_at=now())
        return document

    candidate = str(document["candidate_console_unit"])
    previous = str(document["previous_console_unit"])
    previous_control = str(document["previous_control_socket"])

    live = publication_snapshot()
    live_is_candidate = (
        live["release_digest"] == document["release_digest"]
        and live["port"] == document["candidate_outer_port"]
    )
    live_is_previous = (
        live["release_digest"] == document["previous_release_digest"]
        and live["port"] == document["previous_outer_port"]
    )
    if not live_is_candidate and not live_is_previous:
        raise SwitchError("rollback found an unknown edge Console target")

    # If the edge still serves the previous slot, retire the failed candidate
    # first. Older unit revisions shared one RuntimeDirectory and could remove
    # the previous control socket while stopping; the exact previous restart
    # below recreates it without guessing process identity.
    if live_is_previous and unit_active(runner, candidate):
        runner.run(["/usr/bin/systemctl", "stop", candidate])
        runner.run(["/usr/bin/systemctl", "disable", candidate])

    runner.require(
        ["/usr/bin/systemctl", "restart", previous],
        "previous Console control recovery",
    )
    try:
        previous_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console status",
            timeout_seconds=2,
        )
    except SwitchError:
        previous_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console status",
        )
    if previous_status.get("mode") != "active":
        runner.require_json(
            [
                str(release / "bin/devcoordinator-console-slot-control"),
                "promote",
                "--socket",
                previous_control,
                "--timeout-seconds",
                "30",
            ],
            "previous Console promotion",
        )
    if live_is_candidate:
        switch_publication(
            runner,
            release,
            digest=str(document["previous_release_digest"]),
            port=int(document["previous_outer_port"]),
        )
    require_probe(
        direct_https_health(int(document["previous_outer_port"]), "/healthz"),
        "restored Console direct health",
    )
    require_probe(http_health("https://console.vr.ae/healthz", 8.0), "restored public Console health")
    if unit_active(runner, candidate):
        runner.run(["/usr/bin/systemctl", "stop", candidate])
        runner.run(["/usr/bin/systemctl", "disable", candidate])
        # A legacy candidate stop may have removed the shared directory after
        # publication was restored. Recreate and re-probe the old slot before
        # declaring rollback complete.
        runner.require(
            ["/usr/bin/systemctl", "restart", previous],
            "previous Console post-candidate recovery",
        )
        previous_status = wait_slot_status(
            runner,
            release,
            previous_control,
            previous,
            "previous Console status",
        )
        if previous_status.get("mode") != "active":
            runner.require_json(
                [
                    str(release / "bin/devcoordinator-console-slot-control"),
                    "promote",
                    "--socket",
                    previous_control,
                    "--timeout-seconds",
                    "30",
                ],
                "previous Console promotion",
            )

    restore_destination_backups(backups)
    directory_states = document.get("codex_directory_states")
    if not isinstance(directory_states, Mapping):
        raise SwitchError("Codex configuration directory rollback plan is unavailable")
    restore_codex_directories(directory_states)
    runner.require(["/usr/bin/systemctl", "daemon-reload"], "rollback daemon reload")
    if reset is not None and reset.get("status") in {
        "resetting",
        "complete",
        "rollback-resetting",
    }:
        reset_test_history_for_rollback(document, journal_path, runner)
    normalize_local_paths(runner)
    restart_services(runner)
    runner.require(["/usr/bin/systemctl", "enable", "--now", previous], "previous Console restore")
    final_status = wait_slot_status(
        runner,
        release,
        previous_control,
        previous,
        "previous Console final status",
    )
    if final_status.get("mode") != "active":
        raise SwitchError("restored previous Console slot is not active")
    require_probe(
        direct_https_health(int(document["previous_outer_port"]), "/healthz"),
        "restored Console final direct health",
    )
    require_probe(
        http_health("https://console.vr.ae/healthz", 8.0),
        "restored Console final public health",
    )
    candidate_slot = SLOT_ROOT / f"{document['release_digest']}.env"
    candidate_slot.unlink(missing_ok=True)
    save_phase(journal_path, document, "rolled-back", completed_at=now())
    return document


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    actions = result.add_subparsers(dest="action", required=True)
    for name in ("prepare", "apply", "rollback", "verify"):
        action = actions.add_parser(name)
        action.add_argument("--release", type=Path, required=True)
        action.add_argument("--transaction-root", type=Path, required=True)
        action.add_argument(
            "--reset-test-history",
            action="store_true",
            help=(
                "discard only the isolated test-history store and attempt spool, "
                "then initialize an empty schema-5 test plane while testd is stopped"
            ),
        )
        if name == "verify":
            action.add_argument("--public-url", default="https://console.vr.ae/healthz")
            action.add_argument("--api-url", default="http://127.0.0.1:29876/healthz")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise SwitchError("same-schema release switch must run as root")
        runner = Runner()
        if args.action == "prepare":
            value = prepare(
                args.release,
                args.transaction_root,
                runner,
                reset_test_history=args.reset_test_history,
            )
        elif args.action == "apply":
            value = apply(
                args.release,
                args.transaction_root,
                runner,
                reset_test_history=args.reset_test_history,
            )
        elif args.action == "rollback":
            value = rollback(
                args.release,
                args.transaction_root,
                runner,
                reset_test_history=args.reset_test_history,
            )
        else:
            value = verify(
                args.release,
                args.transaction_root,
                runner,
                public_url=args.public_url,
                api_url=args.api_url,
                reset_test_history=args.reset_test_history,
            )
    except (SwitchError, installer.ReleaseError, OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
