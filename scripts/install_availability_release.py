#!/usr/bin/env python3
"""Build, verify, and render an immutable DevCoordinator release.

This installer never starts or switches a service.  It creates a content-
addressed, non-writable release and renders unit templates into a caller-owned
staging directory.  A separate, explicit cutover must verify candidate
readiness before installing or activating the rendered units.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import uuid
from typing import Any, Iterable, Mapping


# This file is copied into each immutable release and is intentionally usable
# for release self-verification.  Root can otherwise create ``__pycache__``
# beneath a mode-0555 release while importing the bundled Coordinator modules,
# permanently contaminating the content-addressed tree before verification.
sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.maintenance import (  # noqa: E402
    MaintenanceMarkerError,
    load_maintenance_state,
)

DEFAULT_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
RELEASE_SCHEMA = 1
RELEASE_RE = re.compile(r"^[a-f0-9]{64}$")
PORT_RESERVATIONS_KIND = "devcoordinator-first-adoption-port-reservations"
PREPARED_PORT_RESERVATIONS_KIND = (
    "devcoordinator-atomic-first-adoption-bindings-prepared"
)
CLEAN_PORT_RESERVATIONS_KIND = "devcoordinator-clean-adoption-port-reservations"
PORT_RESERVATION_ROLES = (
    "console_outer",
    "console_inner",
    "handoff_http",
    "handoff_https",
    "handoff_api",
)
PORT_RESERVATION_FIELDS = {
    "lease_id",
    "port",
    "agent",
    "purpose",
    "status",
    "expires_at",
}
PORT_RESERVATIONS_FIELDS = {
    "schema_version",
    "kind",
    "operation_id",
    "release_digest",
    "authority_database",
    "authority_generation",
    "authority_state_revision_before",
    "authority_state_revision_after",
    "repository_id",
    "repository_generation",
    "canonical_root",
    "port_range",
    "handoff_ttl_seconds",
    "reservations",
    "transaction_journal_sha256",
    "service_unit",
    "service_restored",
    "maintenance_cleared",
    "created_at",
    "completed_at",
    "document_sha256",
}
PREPARED_PORT_RESERVATIONS_FIELDS = {
    "schema_version",
    "kind",
    "operation_id",
    "release_digest",
    "authority_database",
    "authority_generation",
    "authority_state_revision_before",
    "authority_state_revision_after",
    "repository_id",
    "repository_generation",
    "canonical_root",
    "port_range",
    "handoff_ttl_seconds",
    "reservations",
    "port_journal_sha256",
    "atomic_transaction_journal_sha256",
    "service_unit",
    "service_stopped",
    "maintenance",
    "created_at",
    "completed_at",
    "document_sha256",
}
CLEAN_PORT_RESERVATIONS_FIELDS = {
    "schema_version",
    "kind",
    "operation_id",
    "release_digest",
    "reservations",
    "created_at",
    "document_sha256",
}
CLEAN_PORT_RESERVATION_FIELDS = {"port"}
MAX_PORT_RESERVATIONS_BYTES = 1024 * 1024
AVAILABILITY_TEMPLATES = (
    "devcoordinator-api.service",
    "devcoordinator-api.socket",
    "devcoordinator-api-handoff.service",
    "devcoordinator-api-handoff.socket",
    "devcoordinator-authority.service",
    "devcoordinator-authority.socket",
    "devcoordinator-broker.service",
    "devcoordinator-availability.sysusers.conf",
    "devcoordinator-availability.tmpfiles.conf",
    "devcoordinator.tmpfiles.conf",
    "devcoordinator-background.slice",
    "devcoordinator-console@.service",
    "devcoordinator-control.slice",
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-handoff-http.socket",
    "devcoordinator-edge-handoff-https.socket",
    "devcoordinator-edge-handoff.service",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge-publication.socket",
    "devcoordinator-edge.service",
    "devcoordinator-observer.service",
    "devcoordinator-notifications.service",
    "devcoordinator-projects.slice",
    "devcoordinator-test-snapshotd.service",
    "devcoordinator-test-snapshotd.socket",
    "devcoordinator-testd.service",
    "devcoordinator-testd.socket",
    "devcoordinator-tests.slice",
)
SOURCE_ROOTS = (
    Path("apps/DevOpsConsole/bin"),
    Path("apps/DevOpsConsole/edge"),
    Path("apps/DevOpsConsole/src"),
    Path("skills/codex-dev-coordinator/scripts"),
    Path("skills/postgres-docker-backup"),
)
SOURCE_FILES = (
    Path("apps/DevOpsConsole/package.json"),
    Path("ci/playwright/package.json"),
    Path("apps/DevOpsConsole/Tools/browser-lcp-producer.mjs"),
    Path("apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs"),
    Path("apps/DevOpsConsole/Tools/production-console-acceptance.mjs"),
    Path("deploy/devcoordinator-broker.service"),
    Path("deploy/devcoordinator-read-only.rules"),
    Path("deploy/devcoordinator-test.rules"),
    Path("scripts/activate_availability_release.py"),
    Path("scripts/availability_schema_check.py"),
    Path("scripts/browser_lcp_acceptance.py"),
    Path("scripts/check_availability_topology.py"),
    Path("scripts/clean_adopt_availability.py"),
    Path("scripts/devcoordinator_observer.py"),
    Path("scripts/install_availability_release.py"),
    Path("scripts/install_browser_lcp_runtime.py"),
    Path("scripts/manage_maintenance_mode.py"),
    Path("scripts/manage_universal_test_adoption.py"),
    Path("scripts/manage_universal_test_credentials.py"),
    Path("scripts/migrate_universal_test_history.py"),
    Path("scripts/orchestrate_availability_cutover.py"),
    Path("scripts/prepare_background_service_handoff.py"),
    Path("scripts/read_coordinator_call_log.py"),
    Path("scripts/audit_project_runtime_isolation.py"),
    Path("scripts/refresh_edge_tls_credential.py"),
    Path("scripts/run_fast_repository_validation.py"),
    Path("scripts/run_production_console_acceptance.py"),
    Path("scripts/secure_cutover_io.py"),
    Path("scripts/server_wide_installer_fence.py"),
    Path("scripts/self_test_software_owned_delivery.py"),
    Path("scripts/self_test_verify_codex_test_access.py"),
    Path("scripts/self_test_switch_same_schema_release.py"),
    Path("scripts/software_owned_delivery.py"),
    Path("scripts/switch_same_schema_release.py"),
    Path("scripts/verify_codex_test_access.py"),
    Path("deploy/software-owned-delivery.json"),
) + tuple(Path("deploy") / name for name in AVAILABILITY_TEMPLATES)
FORBIDDEN_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "state",
    "logs",
    "backups",
    "certs",
}
FORBIDDEN_SUFFIXES = (".env", ".key", ".pem", ".sqlite", ".sqlite3", ".log")

WRAPPERS = {
    "devcoordinator-systemd-unit": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("systemd-unit",),
    ),
    "devcoordinator-clean-adoption": (
        "python",
        "scripts/clean_adopt_availability.py",
        (),
    ),
    "devcoordinator-availability-activate": (
        "python",
        "scripts/activate_availability_release.py",
        (),
    ),
    "devcoordinator-cutover": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        (),
    ),
    "devcoordinator-authority-readiness": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        ("recover-authority-readiness",),
    ),
    "devcoordinator-authority-readiness-rebind": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        ("rebind-authority-readiness",),
    ),
    "devcoordinator-authority-readiness-reattest": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        ("reattest-authority-readiness",),
    ),
    "devcoordinator-first-adoption-bindings": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        (),
    ),
    "devcoordinator-authority-repository-repair": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        ("recover-authority-repository-disable",),
    ),
    "devcoordinator-maintenance": (
        "python",
        "scripts/manage_maintenance_mode.py",
        (),
    ),
    "devcoordinator-port-reservations": (
        "python",
        "scripts/orchestrate_availability_cutover.py",
        ("reserve-first-adoption-ports",),
    ),
    "devcoordinator-edge": (
        "node",
        "apps/DevOpsConsole/edge/devcoordinator-edge.mjs",
        (),
    ),
    "devcoordinator-console": (
        "node",
        "apps/DevOpsConsole/bin/devops-console.mjs",
        (),
    ),
    "devcoordinator-console-slot": (
        "node",
        "apps/DevOpsConsole/edge/console-slot-supervisor.mjs",
        (),
    ),
    "devcoordinator-console-slot-control": (
        "node",
        "apps/DevOpsConsole/edge/console-slot-control.mjs",
        (),
    ),
    "devcoordinator-console-state-migration": (
        "node",
        "apps/DevOpsConsole/edge/console-state-migration-cli.mjs",
        (),
    ),
    "devcoordinator-first-adoption-route-resolution": (
        "node",
        "apps/DevOpsConsole/edge/first-adoption-route-resolution-cli.mjs",
        (),
    ),
    "devcoordinator-edge-publication": (
        "node",
        "apps/DevOpsConsole/edge/publication-cli.mjs",
        (),
    ),
    "devcoordinator-edge-cert-refresh": (
        "python",
        "scripts/refresh_edge_tls_credential.py",
        (),
    ),
    "devcoordinator-background-handoff": (
        "python",
        "scripts/prepare_background_service_handoff.py",
        (),
    ),
    "devcoordinator-browser-lcp": (
        "python",
        "scripts/browser_lcp_acceptance.py",
        (),
    ),
    "devcoordinator-browser-runtime": (
        "python",
        "scripts/install_browser_lcp_runtime.py",
        (),
    ),
    "devcoordinator-browser-accounting": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
        (),
    ),
    "devcoordinator-production-browser-session": (
        "node",
        "apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs",
        (),
    ),
    "devcoordinator-production-console-acceptance": (
        "node",
        "apps/DevOpsConsole/Tools/production-console-acceptance.mjs",
        (),
    ),
    "devcoordinator-project-isolation-audit": (
        "python",
        "scripts/audit_project_runtime_isolation.py",
        (),
    ),
    "devcoordinator-production-console-acceptance-batch": (
        "python",
        "scripts/run_production_console_acceptance.py",
        (),
    ),
    "devcoordinator-ship": (
        "python",
        "scripts/software_owned_delivery.py",
        (),
    ),
    "devcoordinator-same-schema-switch": (
        "python",
        "scripts/switch_same_schema_release.py",
        (),
    ),
    "devcoordinator": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
        (),
    ),
    "devcoordinator-mcp": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/agent_mcp.py",
        (),
    ),
    "devcoordinator-bug": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/bug_registry.py",
        (),
    ),
    "devcoordinator-test": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("test",),
    ),
    "devcoordinator-call-log": (
        "python",
        "scripts/read_coordinator_call_log.py",
        (),
    ),
    "devcoordinator-codex-test-access-verify": (
        "python",
        "scripts/verify_codex_test_access.py",
        (),
    ),
    "devcoordinator-first-use-acceptance": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/first_use_acceptance.py",
        (),
    ),
    "devcoordinator-observer": (
        "python",
        "scripts/devcoordinator_observer.py",
        (),
    ),
    "devcoordinator-notifications": (
        "node",
        "apps/DevOpsConsole/bin/devops-console-notifications.mjs",
        (),
    ),
    "devcoordinator-test-manifest-adoption": (
        "python",
        "scripts/manage_universal_test_adoption.py",
        (),
    ),
    "devcoordinator-test-credential": (
        "python",
        "scripts/manage_universal_test_credentials.py",
        (),
    ),
    "devcoordinator-test-history": (
        "python",
        "scripts/migrate_universal_test_history.py",
        (),
    ),
    "devcoordinator-test-preflight": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_preflight.py",
        (),
    ),
    "devcoordinator-api": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("api", "serve"),
    ),
    "devcoordinator-authority": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("broker", "serve"),
    ),
    "devcoordinator-testd": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_testd_main.py",
        (),
    ),
    "devcoordinator-test-snapshotd": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_snapshotd_main.py",
        (),
    ),
    "devcoordinator-schema-check": (
        "python",
        "scripts/availability_schema_check.py",
        ("schema",),
    ),
    "devcoordinator-profile-check": (
        "python",
        "scripts/availability_schema_check.py",
        ("profile",),
    ),
}

RELEASE_COPIES = {
    "libexec/universal_test_uid_helper.py": (
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_uid_helper.py",
        "0444",
    ),
}

# A wrapper and ``--help`` are not sufficient evidence that the bounded client
# can execute real intents.  Keep the direct runtime dependency set explicit so
# a partial package truthfully loses its client capabilities at plan time.
AGENT_CLIENT_RUNTIME_PATHS = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_contract.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_projection.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_test.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/capabilities.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/call_journal.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/bug_registry.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/repository_context.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_service.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/runtime_ensure.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/authority_retention.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/compose_run_once.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/ephemeral_secrets.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/legacy_import.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/schema.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/store.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/test_actor.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_admission.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_contract.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_planner.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_store.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_summary.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/temporary_dev_service.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/worker_native.py",
)
AGENT_NARROW_IMPORT_MODULES = (
    "agent_cli",
    "agent_contract",
    "agent_projection",
    "agent_test",
    "capabilities",
    "call_journal",
    "bug_registry",
    "runtime_ensure",
)
AGENT_MCP_RUNTIME_PATH = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/agent_mcp.py"
)

MIB = 1024 * 1024
GIB = 1024 * MIB
CAPACITY_PLACEHOLDERS = {
    "DEVCOORDINATOR_CONTROL_MEMORY_LOW_BYTES": "control_memory_low_bytes",
    "DEVCOORDINATOR_BACKGROUND_MEMORY_HIGH_BYTES": "background_memory_high_bytes",
    "DEVCOORDINATOR_BACKGROUND_MEMORY_MAX_BYTES": "background_memory_max_bytes",
    "DEVCOORDINATOR_BACKGROUND_CPU_QUOTA_PERCENT": "background_cpu_quota_percent",
    "DEVCOORDINATOR_PROJECT_MEMORY_HIGH_BYTES": "project_memory_high_bytes",
    "DEVCOORDINATOR_PROJECT_MEMORY_MAX_BYTES": "project_memory_max_bytes",
}

class ReleaseError(RuntimeError):
    pass


def host_memory_bytes(meminfo: Path = Path("/proc/meminfo")) -> int:
    try:
        first = meminfo.read_text(encoding="ascii").splitlines()[0]
        label, raw = first.split(":", 1)
        amount, unit = raw.split()
        total = int(amount) * 1024
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise ReleaseError("host memory capacity is unavailable") from error
    if label != "MemTotal" or unit != "kB" or total <= 0:
        raise ReleaseError("host memory capacity is invalid")
    return total


def derive_slice_capacity(
    total_memory_bytes: int,
    *,
    cpu_count: int | None = None,
) -> dict[str, int]:
    """Derive non-overcommitted data-plane bounds from one host capacity."""

    if type(total_memory_bytes) is not int or total_memory_bytes < 3 * GIB:
        raise ReleaseError("availability topology requires at least 3 GiB of host memory")
    effective_cpus = os.cpu_count() if cpu_count is None else cpu_count
    if type(effective_cpus) is not int or effective_cpus <= 0 or effective_cpus > 4096:
        raise ReleaseError("host CPU capacity is invalid")
    os_reserve = max(512 * MIB, total_memory_bytes // 10)
    control_low = max(512 * MIB, min(2 * GIB, total_memory_bytes // 10))
    allocatable = total_memory_bytes - os_reserve - control_low
    background_max = max(512 * MIB, min(8 * GIB, allocatable // 5))
    project_max = allocatable - background_max
    if project_max < GIB:
        raise ReleaseError("host capacity leaves less than 1 GiB for project runtimes")
    background_high = max(256 * MIB, background_max * 4 // 5)
    project_high = max(768 * MIB, project_max * 9 // 10)
    if not (
        0 < background_high < background_max
        and 0 < project_high < project_max
        and os_reserve + control_low + background_max + project_max
        == total_memory_bytes
    ):
        raise ReleaseError("derived slice budgets are contradictory")
    return {
        "host_memory_bytes": total_memory_bytes,
        "os_reserve_bytes": os_reserve,
        "control_memory_low_bytes": control_low,
        "background_memory_high_bytes": background_high,
        "background_memory_max_bytes": background_max,
        "background_cpu_quota_percent": effective_cpus * 100,
        "project_memory_high_bytes": project_high,
        "project_memory_max_bytes": project_max,
        "host_cpu_count": effective_cpus,
    }


def source_root_identity(repo: Path) -> dict[str, int | str]:
    absolute = repo.expanduser().absolute()
    info = absolute.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError("release source root must be one real directory")
    if absolute.resolve(strict=True) != absolute:
        raise ReleaseError("release source root must already be canonical")
    return {
        "path": str(absolute),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }


def validate_source_root(repo: Path) -> dict[str, int | str]:
    """Validate only source properties required to package exact bytes.

    Unix accounts on this host are convenience identities for one trusted
    developer.  UID, GID, and directory mode are therefore not an approval
    boundary.  Canonical path, real-directory, readability, entry type, and
    content-digest checks remain authoritative.
    """

    identity = source_root_identity(repo)
    if not os.access(Path(str(identity["path"])), os.R_OK | os.X_OK):
        raise ReleaseError("release source root is not readable and traversable")
    return identity


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _safe_source_file(repo: Path, relative: Path) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise ReleaseError(f"release source path is unsafe: {relative}")
    if any(part in FORBIDDEN_PARTS for part in relative.parts):
        raise ReleaseError(f"release source path enters a forbidden tree: {relative}")
    lowered = relative.name.lower()
    if lowered.startswith(".env") or lowered.endswith(FORBIDDEN_SUFFIXES):
        raise ReleaseError(f"release source resembles runtime state or credentials: {relative}")
    candidate = repo / relative
    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError(f"release source must be one regular file: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(repo)
    except ValueError as error:
        raise ReleaseError(f"release source escaped repository: {relative}") from error
    return candidate


def source_paths(repo: Path) -> list[Path]:
    repo = repo.resolve(strict=True)
    selected: set[Path] = set()
    for relative in SOURCE_FILES:
        _safe_source_file(repo, relative)
        selected.add(relative)
    for root in SOURCE_ROOTS:
        directory = repo / root
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"release source root is unsafe: {root}")
        for candidate in directory.rglob("*"):
            relative = candidate.relative_to(repo)
            if any(part in FORBIDDEN_PARTS for part in relative.parts):
                continue
            info = candidate.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            _safe_source_file(repo, relative)
            selected.add(relative)
    return sorted(selected, key=lambda item: item.as_posix())


def wrapper_payload(name: str, kind: str, target: str, prefix: tuple[str, ...]) -> bytes:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", name):
        raise ReleaseError(f"wrapper name is invalid: {name}")
    quoted_prefix = " ".join(f"'{item}'" for item in prefix)
    prefix_text = f" {quoted_prefix}" if quoted_prefix else ""
    if kind == "node":
        invocation = f'/usr/bin/node "$ROOT/{target}"'
    else:
        package_prefix = "skills/codex-dev-coordinator/scripts/devcoordinator/"
        if target.startswith(package_prefix) and target.endswith(".py"):
            module = "devcoordinator." + target[
                len(package_prefix) : -3
            ].replace("/", ".")
            bootstrap = (
                "import runpy,sys;"
                "root=sys.argv.pop(1);"
                "module=sys.argv.pop(1);"
                "sys.path.insert(0,root);"
                "sys.argv[0]=module;"
                'runpy.run_module(module,run_name="__main__")'
            )
            invocation = (
                f"/usr/bin/python3 -I -B -c '{bootstrap}' "
                '"$ROOT/skills/codex-dev-coordinator/scripts" '
                f"'{module}'"
            )
        else:
            invocation = f'/usr/bin/python3 -I -B "$ROOT/{target}"'
    if name in {
        "devcoordinator",
        "devcoordinator-mcp",
        "devcoordinator-bug",
        "devcoordinator-test",
    }:
        invocation = (
            "/usr/bin/env "
            "DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl "
            "DEVCOORDINATOR_CALL_LOG_MAX_BYTES=4194304 "
            "DEVCOORDINATOR_CALL_LOG_BACKUPS=4 "
            + invocation
        )
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "SELF=$(readlink -f -- \"$0\")\n"
        "ROOT=$(CDPATH= cd -- \"$(dirname -- \"$SELF\")/..\" && pwd -P)\n"
        f'exec {invocation}{prefix_text} "$@"\n'
    ).encode("utf-8")


def _smoke_test_test_plane_wrappers(release: Path) -> None:
    """Prove package-aware test-plane entrypoints import from this release."""

    for name in (
        "devcoordinator-testd",
        "devcoordinator-test-snapshotd",
    ):
        executable = release / "bin" / name
        try:
            completed = subprocess.run(
                [str(executable), "--help"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseError(
                f"release test-plane wrapper could not execute: {name}: {error}"
            ) from error
        if completed.returncode != 0:
            detail = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise ReleaseError(
                f"release test-plane wrapper failed its import smoke test: "
                f"{name}: {detail or completed.returncode}"
            )


def _smoke_test_agent_wrapper(release: Path) -> None:
    """Prove the single-version CLI grammar from an unrelated cwd."""

    executable = release / "bin" / "devcoordinator"
    for arguments, required in (
        (("--help",), b"usage: devcoordinator"),
        (("capabilities", "--help"), b"--project"),
    ):
        try:
            completed = subprocess.run(
                [str(executable), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseError(
                f"release agent wrapper could not execute: {error}"
            ) from error
        retired = (b"--root-repo", b"--temporary-repo", b"--agent")
        if (
            completed.returncode != 0
            or required not in completed.stdout
            or any(value in completed.stdout for value in retired)
        ):
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ReleaseError(
                "release agent wrapper failed its single-version grammar smoke test: "
                f"{' '.join(arguments)}: {detail or completed.returncode}"
            )


def _smoke_test_agent_runtime_modules(release: Path) -> None:
    """Import the narrow client graph without initializing host backends."""

    module_root = release / "skills" / "codex-dev-coordinator" / "scripts"
    bootstrap = (
        "import importlib,sys;"
        "root=sys.argv.pop(1);"
        "sys.path.insert(0,root);"
        "[importlib.import_module('devcoordinator.'+name) for name in sys.argv[1:]];"
        "forbidden={'devcoordinator.broker_backend',"
        "'devcoordinator.broker_persistence','devcoordinator.store'};"
        "raise SystemExit(1 if forbidden.intersection(sys.modules) else 0)"
    )
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "-c",
                bootstrap,
                str(module_root),
                *AGENT_NARROW_IMPORT_MODULES,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(
            f"release agent runtime modules could not import: {error}"
        ) from error
    if completed.returncode != 0 or completed.stdout:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseError(
            "release agent runtime module smoke test failed or loaded a host "
            f"backend: {detail or completed.returncode}"
        )


def _smoke_test_agent_mcp_wrapper(release: Path) -> None:
    """Probe MCP metadata without entering its long-lived stdio loop."""

    executable = release / "bin" / "devcoordinator-mcp"
    for flag, marker in (
        ("--help", b"usage: devcoordinator-mcp"),
        ("--version", b"devcoordinator-mcp "),
    ):
        try:
            completed = subprocess.run(
                [str(executable), flag],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseError(
                f"release agent MCP wrapper could not execute {flag}: {error}"
            ) from error
        if (
            completed.returncode != 0
            or marker not in completed.stdout
            or completed.stderr
        ):
            detail = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise ReleaseError(
                "release agent MCP wrapper failed its metadata smoke test: "
                f"{flag}: {detail or completed.returncode}"
            )


def _smoke_test_bug_wrapper(release: Path) -> None:
    """Prove outage-safe bug intake grammar without touching host state."""

    executable = release / "bin" / "devcoordinator-bug"
    for arguments, marker in (
        (("--help",), b"usage: devcoordinator-bug"),
        (("report", "--help"), b"--step"),
        (("list", "--help"), b"--component"),
        (("close", "--help"), b"bug_id"),
    ):
        try:
            completed = subprocess.run(
                [str(executable), *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
                cwd="/",
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseError(
                f"release bug wrapper could not execute: {error}"
            ) from error
        if completed.returncode != 0 or marker not in completed.stdout:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ReleaseError(
                "release bug wrapper failed its grammar smoke test: "
                f"{' '.join(arguments)}: {detail or completed.returncode}"
            )


def release_inputs(repo: Path) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    entries: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    for relative in source_paths(repo):
        source = repo / relative
        payload = source.read_bytes()
        payloads[relative.as_posix()] = payload
        entries.append(
            {
                "path": relative.as_posix(),
                "sha256": _sha256_bytes(payload),
                "size": len(payload),
                "mode": "0444",
                "kind": "source",
            }
        )
    for name, (kind, target, prefix) in sorted(WRAPPERS.items()):
        target_path = repo / target
        if not target_path.is_file() or target_path.is_symlink():
            # Components may land in dependency order.  Never publish a broken
            # wrapper; the resulting capabilities make the blocker explicit.
            continue
        payload = wrapper_payload(name, kind, target, prefix)
        relative = f"bin/{name}"
        payloads[relative] = payload
        entries.append(
            {
                "path": relative,
                "sha256": _sha256_bytes(payload),
                "size": len(payload),
                "mode": "0555",
                "kind": "wrapper",
            }
        )
    for destination, (source_name, mode) in sorted(RELEASE_COPIES.items()):
        source = _safe_source_file(repo, Path(source_name))
        payload = source.read_bytes()
        payloads[destination] = payload
        entries.append(
            {
                "path": destination,
                "sha256": _sha256_bytes(payload),
                "size": len(payload),
                "mode": mode,
                "kind": "copy",
            }
        )
    entries.sort(key=lambda item: item["path"])
    return entries, payloads


def release_digest(entries: list[dict[str, Any]]) -> str:
    return _sha256_bytes(
        _canonical_json({"schema_version": RELEASE_SCHEMA, "files": entries})
    )


def plan_release(repo: Path, release_root: Path) -> dict[str, Any]:
    source_identity = source_root_identity(repo)
    repo = repo.resolve(strict=True)
    entries, _wrappers = release_inputs(repo)
    digest = release_digest(entries)
    paths = {item["path"] for item in entries}
    activation_source = (
        "skills/codex-dev-coordinator/scripts/devcoordinator/systemd_activation.py"
        in paths
    )
    capabilities = {
        "edge_systemd_sockets": "bin/devcoordinator-edge" in paths,
        "console_immutable_backend": "bin/devcoordinator-console" in paths,
        # These capabilities are bound to the exact content-addressed source
        # inventory.  Executable self-tests exercise real inherited fd 3 and
        # verify that authority shutdown retains PID 1's socket pathname.
        "api_systemd_socket": (
            "bin/devcoordinator-api" in paths
            and activation_source
            and "skills/codex-dev-coordinator/scripts/dev_coordinator.py" in paths
        ),
        "authority_systemd_socket": (
            "bin/devcoordinator-authority" in paths
            and activation_source
            and "skills/codex-dev-coordinator/scripts/devcoordinator/broker.py" in paths
            and "skills/codex-dev-coordinator/scripts/devcoordinator/broker_cli.py" in paths
        ),
        "console_parallel_writer_safe": (
            "bin/devcoordinator-console-slot" in paths
            and "bin/devcoordinator-console-slot-control" in paths
        ),
        "observer_projection": (
            "bin/devcoordinator-observer" in paths
            and "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py"
            in paths
        ),
        "immutable_agent_client": all(
            path in paths
            for path in ("bin/devcoordinator", *AGENT_CLIENT_RUNTIME_PATHS)
        ),
        "immutable_agent_mcp": all(
            path in paths
            for path in (
                "bin/devcoordinator-mcp",
                AGENT_MCP_RUNTIME_PATH,
                *AGENT_CLIENT_RUNTIME_PATHS,
            )
        ),
        "out_of_band_bug_registry": all(
            path in paths
            for path in (
                "bin/devcoordinator",
                "bin/devcoordinator-bug",
                "bin/devcoordinator-mcp",
                "deploy/devcoordinator-availability.tmpfiles.conf",
                "deploy/devcoordinator-console@.service",
                AGENT_MCP_RUNTIME_PATH,
                *AGENT_CLIENT_RUNTIME_PATHS,
            )
        ),
        "immutable_read_only_agent_access": all(
            path in paths
            for path in (
                "bin/devcoordinator",
                "bin/devcoordinator-call-log",
                "deploy/devcoordinator-read-only.rules",
                "scripts/read_coordinator_call_log.py",
                *AGENT_CLIENT_RUNTIME_PATHS,
            )
        ),
        "project_runtime_isolation": all(
            path in paths
            for path in (
                "bin/devcoordinator-project-isolation-audit",
                "scripts/audit_project_runtime_isolation.py",
                "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/worker_native.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/broker_host.py",
            )
        ),
        "background_service_handoff": all(
            path in paths
            for path in (
                "bin/devcoordinator-background-handoff",
                "scripts/prepare_background_service_handoff.py",
            )
        ),
        "authority_readiness_recovery": all(
            path in paths
            for path in (
                "bin/devcoordinator-authority-readiness",
                "scripts/orchestrate_availability_cutover.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/broker_cli.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            )
        ),
        "authority_readiness_rebind": all(
            path in paths
            for path in (
                "bin/devcoordinator-authority-readiness-rebind",
                "scripts/orchestrate_availability_cutover.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/broker_cli.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            )
        ),
        "authority_readiness_reattestation": all(
            path in paths
            for path in (
                "bin/devcoordinator-authority-readiness-reattest",
                "scripts/orchestrate_availability_cutover.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/broker_cli.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            )
        ),
        "atomic_first_adoption_bindings": all(
            path in paths
            for path in (
                "bin/devcoordinator-first-adoption-bindings",
                "scripts/orchestrate_availability_cutover.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/broker_cli.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            )
        ),
        "typed_maintenance_control": all(
            path in paths
            for path in (
                "bin/devcoordinator-maintenance",
                "scripts/manage_maintenance_mode.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            )
        ),
        "browser_lcp_acceptance": all(
            path in paths
            for path in (
                "bin/devcoordinator-browser-lcp",
                "bin/devcoordinator-browser-runtime",
                "scripts/browser_lcp_acceptance.py",
                "scripts/install_browser_lcp_runtime.py",
                "apps/DevOpsConsole/Tools/browser-lcp-producer.mjs",
            )
        ),
        "headless_browser_accounting": all(
            path in paths
            for path in (
                "bin/devcoordinator-browser-accounting",
                "skills/codex-dev-coordinator/scripts/devcoordinator/browser_lifecycle.py",
            )
        ),
        "production_console_playwright_acceptance": all(
            path in paths
            for path in (
                "bin/devcoordinator-production-browser-session",
                "bin/devcoordinator-production-console-acceptance",
                "apps/DevOpsConsole/Tools/prepare-production-acceptance-storage-state.mjs",
                "apps/DevOpsConsole/Tools/production-console-acceptance.mjs",
                "ci/playwright/package.json",
            )
        ),
        "asynchronous_test_plane": all(
            path in paths
            for path in (
                "bin/devcoordinator-testd",
                "bin/devcoordinator-test-snapshotd",
                "bin/devcoordinator-test-preflight",
                "libexec/universal_test_uid_helper.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/universal_testd_main.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_snapshotd_main.py",
            )
        ),
        "sealed_operational_test_credentials": all(
            path in paths
            for path in (
                "bin/devcoordinator-test-credential",
                "scripts/manage_universal_test_credentials.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_credentials.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runtime.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runner.py",
            )
        ),
        "evidence_gated_activation": all(
            path in paths
            for path in (
                "bin/devcoordinator-availability-activate",
                "scripts/activate_availability_release.py",
                "scripts/orchestrate_availability_cutover.py",
            )
        ),
    }
    return {
        "schema_version": RELEASE_SCHEMA,
        "release_digest": digest,
        "release_directory": str(release_root.resolve() / digest),
        "source_identity": source_identity,
        "files": entries,
        "capabilities": capabilities,
    }


def _default_release_ancestry(
    release_root: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    reconcile: bool,
) -> None:
    """Keep the dedicated immutable-release ancestry publicly traversable.

    Availability releases contain executable code and public unit templates,
    never credentials.  Historical enrolled UIDs must be able to execute a
    descriptor-bound canary from the current release while privileged
    configuration and state remain under their separate private roots.
    """

    release_root = release_root.expanduser().absolute()
    if release_root != DEFAULT_RELEASE_ROOT:
        raise ReleaseError("release ancestry helper received a custom path")
    dedicated_root = release_root.parent
    trusted_parent = dedicated_root.parent
    parent_info = trusted_parent.lstat()
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != owner_uid
        or parent_info.st_gid != owner_gid
        or stat.S_IMODE(parent_info.st_mode) & 0o022
        or stat.S_IMODE(parent_info.st_mode) & 0o111 != 0o111
        or trusted_parent.resolve(strict=True) != trusted_parent
    ):
        raise ReleaseError("default release ancestry has an unsafe trusted parent")

    for directory in (dedicated_root, release_root):
        changed = False
        try:
            info = directory.lstat()
        except FileNotFoundError:
            if not reconcile:
                raise ReleaseError(
                    f"default release ancestry is missing: {directory}"
                ) from None
            os.mkdir(directory, 0o755)
            os.chown(directory, owner_uid, owner_gid)
            os.chmod(directory, 0o755, follow_symlinks=False)
            changed = True
            info = directory.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) & 0o022
            or directory.resolve(strict=True) != directory
        ):
            raise ReleaseError(
                f"default release ancestry is unsafe: {directory}"
            )
        if reconcile and stat.S_IMODE(info.st_mode) != 0o755:
            os.chmod(directory, 0o755, follow_symlinks=False)
            changed = True
            info = directory.lstat()
        if stat.S_IMODE(info.st_mode) != 0o755:
            raise ReleaseError(
                f"default release ancestry mode is not 0755: {directory}"
            )
        if changed:
            descriptor = os.open(
                directory.parent,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def _safe_release_parent(path: Path, *, owner_uid: int, owner_gid: int) -> None:
    path = path.expanduser().absolute()
    if path == DEFAULT_RELEASE_ROOT:
        _default_release_ancestry(
            path,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            reconcile=True,
        )
        return
    if not path.exists():
        path.mkdir(parents=True, mode=0o755)
        os.chown(path, owner_uid, owner_gid)
        os.chmod(path, 0o755)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != owner_uid
        or info.st_gid != owner_gid
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ReleaseError(f"release parent has unsafe ownership or mode: {path}")


def _install_bytes(path: Path, payload: bytes, *, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _verified_entry_payload(entry: dict[str, Any], payload: bytes) -> bytes:
    """Bind a captured payload to its immutable manifest entry."""

    if (
        not isinstance(payload, bytes)
        or len(payload) != entry["size"]
        or _sha256_bytes(payload) != entry["sha256"]
    ):
        raise ReleaseError(f"captured release payload changed: {entry['path']}")
    return payload


def _freeze_tree(root: Path, *, uid: int, gid: int) -> None:
    directories: list[Path] = []
    for directory, child_directories, files in os.walk(root):
        child_directories.sort()
        files.sort()
        current = Path(directory)
        directories.append(current)
        for name in files:
            path = current / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ReleaseError(f"staged release contains a non-regular file: {path}")
            os.chown(path, uid, gid)
            wanted = 0o555 if stat.S_IMODE(info.st_mode) & 0o111 else 0o444
            os.chmod(path, wanted)
    for directory in reversed(directories):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o555)


def _verify_staged_release(
    root: Path,
    plan: dict[str, Any],
    manifest_payload: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    """Verify the exact frozen tree before it can become publicly addressable."""

    expected = {"release-manifest.json"}
    for entry in plan["files"]:
        relative = Path(entry["path"])
        expected.add(relative.as_posix())
        target = root / relative
        info = target.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) != int(entry["mode"], 8)
            or info.st_size != entry["size"]
            or _sha256_file(target) != entry["sha256"]
        ):
            raise ReleaseError(f"staged release file failed verification: {relative}")
    manifest = root / "release-manifest.json"
    manifest_info = manifest.lstat()
    if (
        stat.S_ISLNK(manifest_info.st_mode)
        or not stat.S_ISREG(manifest_info.st_mode)
        or manifest_info.st_uid != owner_uid
        or manifest_info.st_gid != owner_gid
        or stat.S_IMODE(manifest_info.st_mode) != 0o444
        or manifest.read_bytes() != manifest_payload
    ):
        raise ReleaseError("staged release manifest failed verification")

    actual: set[str] = set()
    for target in root.rglob("*"):
        relative = target.relative_to(root).as_posix()
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ReleaseError(f"staged release contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            if (
                info.st_uid != owner_uid
                or info.st_gid != owner_gid
                or stat.S_IMODE(info.st_mode) != 0o555
            ):
                raise ReleaseError(f"staged release directory is unsafe: {relative}")
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseError(f"staged release contains a special file: {relative}")
        actual.add(relative)
    root_info = root.lstat()
    if (
        root_info.st_uid != owner_uid
        or root_info.st_gid != owner_gid
        or stat.S_IMODE(root_info.st_mode) != 0o555
        or actual != expected
    ):
        raise ReleaseError("staged release inventory or root metadata is invalid")


def stage_release(
    repo: Path,
    release_root: Path,
    *,
    owner_uid: int,
    owner_gid: int,
) -> dict[str, Any]:
    validate_source_root(repo)
    repo = repo.resolve(strict=True)
    release_root = release_root.resolve()
    _safe_release_parent(release_root, owner_uid=owner_uid, owner_gid=owner_gid)
    plan = plan_release(repo, release_root)
    destination = Path(plan["release_directory"])
    existed = destination.exists() or destination.is_symlink()
    if existed:
        verified = verify_release(destination, owner_uid=owner_uid, owner_gid=owner_gid)
        if verified["release_digest"] != plan["release_digest"]:
            raise ReleaseError("existing content-addressed release does not match source")
        return {**verified, "created": False}

    temporary = release_root / f".{plan['release_digest']}.{uuid.uuid4().hex}.partial"
    temporary.mkdir(mode=0o700)
    os.chown(temporary, owner_uid, owner_gid)
    try:
        entries, payloads = release_inputs(repo)
        if entries != plan["files"]:
            raise ReleaseError("release source changed after planning")
        for entry in entries:
            relative = Path(entry["path"])
            target = temporary / relative
            payload = _verified_entry_payload(
                entry,
                payloads[relative.as_posix()],
            )
            _install_bytes(
                target,
                payload,
                mode=int(entry["mode"], 8),
                uid=owner_uid,
                gid=owner_gid,
            )
        manifest = {**plan, "release_directory": None}
        manifest_payload = (
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        )
        _install_bytes(
            temporary / "release-manifest.json",
            manifest_payload,
            mode=0o444,
            uid=owner_uid,
            gid=owner_gid,
        )
        _freeze_tree(temporary, uid=owner_uid, gid=owner_gid)
        _verify_staged_release(
            temporary,
            plan,
            manifest_payload,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        validate_source_root(repo)
        current_entries, _current_payloads = release_inputs(repo)
        if current_entries != plan["files"]:
            raise ReleaseError("release source changed while staging")
        os.replace(temporary, destination)
        parent_descriptor = os.open(release_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except BaseException:
        if temporary.exists():
            # The partial tree was created by this invocation and has never
            # been published.  chmod only enough to remove this exact inode
            # tree; published releases are never recursively deleted here.
            for directory, child_directories, files in os.walk(temporary, topdown=False):
                Path(directory).chmod(0o700)
                for name in files:
                    (Path(directory) / name).chmod(0o600)
                    (Path(directory) / name).unlink()
                for name in child_directories:
                    (Path(directory) / name).chmod(0o700)
                    (Path(directory) / name).rmdir()
            temporary.chmod(0o700)
            temporary.rmdir()
        raise
    return {**verify_release(destination, owner_uid=owner_uid, owner_gid=owner_gid), "created": True}


def verify_release(
    release: Path,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> dict[str, Any]:
    requested_release = release.expanduser().absolute()
    if requested_release.parent == DEFAULT_RELEASE_ROOT:
        _default_release_ancestry(
            DEFAULT_RELEASE_ROOT,
            owner_uid=0 if owner_uid is None else owner_uid,
            owner_gid=0 if owner_gid is None else owner_gid,
            reconcile=False,
        )
    requested_info = requested_release.lstat()
    if (
        stat.S_ISLNK(requested_info.st_mode)
        or not stat.S_ISDIR(requested_info.st_mode)
        or requested_release.resolve(strict=True) != requested_release
    ):
        raise ReleaseError("release root must be one canonical real directory")
    release = requested_release
    if not RELEASE_RE.fullmatch(release.name):
        raise ReleaseError("release directory name is not a content digest")
    expected_uid = requested_info.st_uid if owner_uid is None else owner_uid
    expected_gid = requested_info.st_gid if owner_gid is None else owner_gid
    manifest_path = release / "release-manifest.json"
    info = manifest_path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        raise ReleaseError("release manifest is unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"release manifest is invalid: {error}") from error
    if set(manifest) != {
        "capabilities",
        "files",
        "release_digest",
        "release_directory",
        "schema_version",
        "source_identity",
    }:
        raise ReleaseError("release manifest fields are invalid")
    if manifest["schema_version"] != RELEASE_SCHEMA or manifest["release_directory"] is not None:
        raise ReleaseError("release manifest schema is unsupported")
    source_identity = manifest.get("source_identity")
    if (
        not isinstance(source_identity, dict)
        or set(source_identity) != {
            "device", "inode", "mode", "owner_gid", "owner_uid", "path"
        }
        or not isinstance(source_identity.get("path"), str)
        or not re.fullmatch(r"0[0-7]{3}", str(source_identity.get("mode")))
        or any(
            type(source_identity.get(field)) is not int
            or int(source_identity[field]) < 0
            for field in ("device", "inode", "owner_gid", "owner_uid")
        )
    ):
        raise ReleaseError("release source identity attestation is invalid")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ReleaseError("release manifest file inventory is invalid")
    if release_digest(entries) != release.name or manifest["release_digest"] != release.name:
        raise ReleaseError("release digest does not match its manifest")
    expected = {"release-manifest.json"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"kind", "mode", "path", "sha256", "size"}:
            raise ReleaseError("release file entry is invalid")
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in expected:
            raise ReleaseError("release file entry path is unsafe or duplicated")
        expected.add(relative.as_posix())
        target = release / relative
        file_info = target.lstat()
        wanted_mode = int(str(entry["mode"]), 8)
        if (
            stat.S_ISLNK(file_info.st_mode)
            or not stat.S_ISREG(file_info.st_mode)
            or stat.S_IMODE(file_info.st_mode) != wanted_mode
            or file_info.st_uid != expected_uid
            or file_info.st_gid != expected_gid
            or file_info.st_size != entry["size"]
            or _sha256_file(target) != entry["sha256"]
        ):
            raise ReleaseError(f"release file failed verification: {relative}")
    actual: set[str] = set()
    for target in release.rglob("*"):
        relative = target.relative_to(release).as_posix()
        target_info = target.lstat()
        if stat.S_ISLNK(target_info.st_mode):
            raise ReleaseError(f"release contains a symlink: {relative}")
        if stat.S_ISDIR(target_info.st_mode):
            if (
                target_info.st_uid != expected_uid
                or target_info.st_gid != expected_gid
                or stat.S_IMODE(target_info.st_mode) != 0o555
            ):
                raise ReleaseError(
                    f"release directory has unsafe ownership or mode: {relative}"
                )
            continue
        if not stat.S_ISREG(target_info.st_mode):
            raise ReleaseError(f"release contains a special file: {relative}")
        actual.add(relative)
    if actual != expected:
        extra = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise ReleaseError(f"release inventory mismatch; extra={extra}, missing={missing}")
    root_info = release.lstat()
    if (
        root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
        or stat.S_IMODE(root_info.st_mode) != 0o555
    ):
        raise ReleaseError("release root has unsafe ownership or mode")
    if manifest["capabilities"].get("asynchronous_test_plane") is True:
        _smoke_test_test_plane_wrappers(release)
    if manifest["capabilities"].get("immutable_agent_client") is True:
        _smoke_test_agent_wrapper(release)
        _smoke_test_agent_runtime_modules(release)
    if manifest["capabilities"].get("immutable_agent_mcp") is True:
        _smoke_test_agent_mcp_wrapper(release)
    if manifest["capabilities"].get("out_of_band_bug_registry") is True:
        _smoke_test_bug_wrapper(release)
    return {
        "ok": True,
        "release_digest": release.name,
        "release_directory": str(release),
        "capabilities": manifest["capabilities"],
        "file_count": len(entries),
    }


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"port reservation bundle repeats field {key!r}")
        result[key] = value
    return result


def _utc_bundle_time(value: object, field: str) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value,
        )
        is None
    ):
        raise ReleaseError(f"port reservation {field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ReleaseError(f"port reservation {field} is invalid") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReleaseError(f"port reservation {field} must be UTC")
    return parsed


def _canonical_absolute_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReleaseError(f"port reservation {field} is invalid")
    candidate = Path(value)
    if (
        not candidate.is_absolute()
        or str(Path(os.path.abspath(candidate))) != value
        or str(candidate.resolve(strict=False)) != value
    ):
        raise ReleaseError(f"port reservation {field} must be an absolute canonical path")
    return value


def _verify_prepared_port_reservation_fence(document: dict[str, Any]) -> None:
    if os.geteuid() != 0:
        raise ReleaseError(
            "prepared port reservations require the authority UID"
        )
    unit = str(document["service_unit"])
    active = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", unit],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    ).returncode
    if active != 3:
        raise ReleaseError(
            "prepared port reservations require the stopped legacy broker"
        )
    maintenance = document["maintenance"]
    if (
        not isinstance(maintenance, dict)
        or set(maintenance)
        != {
            "root",
            "gid",
            "deployment_id",
            "message",
            "retry_after_seconds",
            "started_at",
        }
        or type(maintenance["gid"]) is not int
        or maintenance["gid"] < 0
        or type(maintenance["retry_after_seconds"]) is not int
        or maintenance["retry_after_seconds"] <= 0
    ):
        raise ReleaseError("prepared port maintenance binding is invalid")
    root = Path(
        _canonical_absolute_path(maintenance["root"], "maintenance root")
    )
    try:
        deployment_id = str(uuid.UUID(str(maintenance["deployment_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise ReleaseError(
            "prepared port maintenance deployment is invalid"
        ) from error
    try:
        marker = load_maintenance_state(
            expected_uid=0,
            expected_gid=int(maintenance["gid"]),
            maintenance_root=root,
        )
    except MaintenanceMarkerError as error:
        raise ReleaseError(
            "prepared port maintenance marker is unavailable"
        ) from error
    if (
        marker is None
        or marker.deployment_id != deployment_id
        or marker.message != maintenance["message"]
        or marker.retry_after_seconds
        != maintenance["retry_after_seconds"]
        or marker.started_at != maintenance["started_at"]
    ):
        raise ReleaseError("prepared port maintenance marker changed")


def _clean_port_reservations(
    reservations: object,
) -> dict[str, dict[str, int]]:
    if not isinstance(reservations, Mapping) or set(reservations) != set(
        PORT_RESERVATION_ROLES
    ):
        raise ReleaseError("clean port reservation roles are invalid")
    normalized: dict[str, dict[str, int]] = {}
    ports: list[int] = []
    for role in PORT_RESERVATION_ROLES:
        reservation = reservations[role]
        if (
            not isinstance(reservation, Mapping)
            or set(reservation) != CLEAN_PORT_RESERVATION_FIELDS
            or type(reservation["port"]) is not int
            or not 30000 <= int(reservation["port"]) <= 60999
        ):
            raise ReleaseError(f"clean port reservation {role} is invalid")
        port = int(reservation["port"])
        normalized[role] = {"port": port}
        ports.append(port)
    if len(set(ports)) != len(PORT_RESERVATION_ROLES):
        raise ReleaseError(
            "clean port reservations must be five distinct high ports"
        )
    return normalized


def _verify_clean_ports_bindable(
    reservations: Mapping[str, Mapping[str, int]],
) -> None:
    listeners: list[socket.socket] = []
    try:
        for role in PORT_RESERVATION_ROLES:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(listener)
            try:
                listener.bind(("127.0.0.1", int(reservations[role]["port"])))
            except OSError as error:
                raise ReleaseError(
                    f"clean port reservation {role} is not bindable on 127.0.0.1"
                ) from error
    finally:
        for listener in listeners:
            listener.close()


def validated_port_reservations(
    path: Path,
    *,
    expected_document_sha256: str,
    release_digest: str,
) -> dict[str, Any]:
    """Read one private, release-bound first-adoption reservation bundle."""

    if (
        not isinstance(expected_document_sha256, str)
        or RELEASE_RE.fullmatch(expected_document_sha256) is None
    ):
        raise ReleaseError("port reservation bundle SHA-256 is invalid")
    path = path.expanduser()
    if not path.is_absolute():
        raise ReleaseError("port reservation bundle path must be absolute")
    path = Path(os.path.abspath(path))
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or path.resolve(strict=True) != path
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_PORT_RESERVATIONS_BYTES
    ):
        raise ReleaseError(
            "port reservation bundle must be one canonical private regular file "
            "owned by the current authority UID"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != before.st_size
        ):
            raise ReleaseError("port reservation bundle identity changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_PORT_RESERVATIONS_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        len(payload) != before.st_size
        or len(payload) > MAX_PORT_RESERVATIONS_BYTES
        or any(getattr(before, field) != getattr(after_open, field) for field in identity_fields)
        or any(getattr(before, field) != getattr(after_path, field) for field in identity_fields)
    ):
        raise ReleaseError("port reservation bundle changed while reading")
    try:
        document = json.loads(payload, object_pairs_hook=_strict_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("port reservation bundle is invalid JSON") from error
    prepared = (
        isinstance(document, dict)
        and document.get("kind") == PREPARED_PORT_RESERVATIONS_KIND
    )
    clean = (
        isinstance(document, dict)
        and document.get("kind") == CLEAN_PORT_RESERVATIONS_KIND
    )
    expected_fields = (
        CLEAN_PORT_RESERVATIONS_FIELDS
        if clean
        else (
            PREPARED_PORT_RESERVATIONS_FIELDS
            if prepared
            else PORT_RESERVATIONS_FIELDS
        )
    )
    if (
        not isinstance(document, dict)
        or set(document) != expected_fields
        or document.get("schema_version") != 1
        or document.get("kind")
        not in {
            PORT_RESERVATIONS_KIND,
            PREPARED_PORT_RESERVATIONS_KIND,
            CLEAN_PORT_RESERVATIONS_KIND,
        }
    ):
        raise ReleaseError("port reservation bundle fields are invalid")
    unsigned = {
        key: value for key, value in document.items() if key != "document_sha256"
    }
    canonical_digest = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if (
        document["document_sha256"] != canonical_digest
        or expected_document_sha256 != canonical_digest
    ):
        raise ReleaseError("port reservation bundle canonical digest is invalid")
    try:
        operation_id = str(uuid.UUID(str(document["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise ReleaseError("port reservation operation ID is invalid") from error
    if operation_id != document["operation_id"]:
        raise ReleaseError("port reservation operation ID is not canonical")
    if (
        not isinstance(release_digest, str)
        or RELEASE_RE.fullmatch(release_digest) is None
        or document["release_digest"] != release_digest
    ):
        raise ReleaseError("port reservation bundle belongs to another immutable release")
    if clean:
        _utc_bundle_time(document["created_at"], "creation time")
        clean_reservations = _clean_port_reservations(document["reservations"])
        _verify_clean_ports_bindable(clean_reservations)
        return {
            **document,
            "reservations": clean_reservations,
        }
    _canonical_absolute_path(document["authority_database"], "authority database")
    _canonical_absolute_path(document["canonical_root"], "canonical root")
    if (
        not isinstance(document["authority_generation"], str)
        or not document["authority_generation"]
        or len(document["authority_generation"]) > 256
        or any(ord(character) < 0x20 for character in document["authority_generation"])
        or not isinstance(document["repository_id"], str)
        or not document["repository_id"]
        or len(document["repository_id"].encode("utf-8")) > 256
        or any(ord(character) < 0x20 for character in document["repository_id"])
        or type(document["repository_generation"]) is not int
        or document["repository_generation"] < 0
        or type(document["authority_state_revision_before"]) is not int
        or document["authority_state_revision_before"] < 0
        or type(document["authority_state_revision_after"]) is not int
        or document["authority_state_revision_after"]
        != document["authority_state_revision_before"] + 1
    ):
        raise ReleaseError("port reservation authority binding is invalid")
    if document["port_range"] != {"start": 30000, "end": 60999}:
        raise ReleaseError("port reservation range must be exactly 30000 through 60999")
    if (
        type(document["handoff_ttl_seconds"]) is not int
        or document["handoff_ttl_seconds"] < 60
        or document["handoff_ttl_seconds"] > 86_400
    ):
        raise ReleaseError("port reservation handoff TTL is invalid")
    if prepared:
        if (
            document["service_unit"] != "devcoordinator-broker.service"
            or document["service_stopped"] is not True
            or not isinstance(document["port_journal_sha256"], str)
            or RELEASE_RE.fullmatch(document["port_journal_sha256"]) is None
            or not isinstance(
                document["atomic_transaction_journal_sha256"], str
            )
            or RELEASE_RE.fullmatch(
                document["atomic_transaction_journal_sha256"]
            )
            is None
        ):
            raise ReleaseError(
                "prepared port reservation fence evidence is incomplete"
            )
        _verify_prepared_port_reservation_fence(document)
    elif (
        document["service_unit"] != "devcoordinator-broker.service"
        or document["service_restored"] is not True
        or document["maintenance_cleared"] is not True
        or not isinstance(document["transaction_journal_sha256"], str)
        or RELEASE_RE.fullmatch(document["transaction_journal_sha256"]) is None
    ):
        raise ReleaseError("port reservation recovery evidence is incomplete")
    created_at = _utc_bundle_time(document["created_at"], "creation time")
    completed_at = _utc_bundle_time(document["completed_at"], "completion time")
    if completed_at < created_at:
        raise ReleaseError("port reservation completion predates creation")
    reservations = document["reservations"]
    if not isinstance(reservations, dict) or set(reservations) != set(
        PORT_RESERVATION_ROLES
    ):
        raise ReleaseError("port reservation roles are invalid")
    expected_agent = f"cutover:first-adoption:{operation_id}"
    ports: list[int] = []
    leases: list[str] = []
    purposes: list[str] = []
    handoff_expiries: list[datetime] = []
    for role in PORT_RESERVATION_ROLES:
        reservation = reservations[role]
        if not isinstance(reservation, dict) or set(reservation) != PORT_RESERVATION_FIELDS:
            raise ReleaseError(f"port reservation {role} fields are invalid")
        lease_id = reservation["lease_id"]
        port = reservation["port"]
        purpose = reservation["purpose"]
        try:
            canonical_lease_id = str(uuid.UUID(str(lease_id)))
        except (ValueError, TypeError, AttributeError) as error:
            raise ReleaseError(f"port reservation {role} lease ID is invalid") from error
        if (
            canonical_lease_id != lease_id
            or type(port) is not int
            or not 30000 <= port <= 60999
            or reservation["agent"] != expected_agent
            or purpose != f"first-adoption:{release_digest}:{role}"
            or reservation["status"] != "active"
        ):
            raise ReleaseError(f"port reservation {role} binding is invalid")
        ports.append(port)
        leases.append(lease_id)
        purposes.append(purpose)
        expires_at = reservation["expires_at"]
        if role.startswith("console_"):
            if expires_at is not None:
                raise ReleaseError("Console port reservations must not expire")
        else:
            handoff_expiries.append(
                _utc_bundle_time(expires_at, f"{role} expiry")
            )
    if len(set(ports)) != len(PORT_RESERVATION_ROLES):
        raise ReleaseError("reserved ports must be five distinct broker-leased high ports")
    if len(set(leases)) != len(PORT_RESERVATION_ROLES):
        raise ReleaseError("port reservation lease IDs must be distinct")
    if len(set(purposes)) != len(PORT_RESERVATION_ROLES):
        raise ReleaseError("port reservation purposes must be distinct")
    expected_expiry = created_at + timedelta(
        seconds=document["handoff_ttl_seconds"]
    )
    if (
        len(handoff_expiries) != 3
        or any(expiry != expected_expiry for expiry in handoff_expiries)
        or handoff_expiries[0] <= datetime.now(timezone.utc)
    ):
        raise ReleaseError(
            "handoff ports must be three distinct broker-leased high ports with one future expiry"
        )
    return document


def prepare_clean_port_reservations(
    release: Path,
    output: Path,
    *,
    operation_id: str,
    ports: Mapping[str, int],
) -> dict[str, Any]:
    """Publish one private, release-bound clean-adoption port bundle."""

    verified = verify_release(release)
    release_digest = str(verified["release_digest"])
    try:
        canonical_operation_id = str(uuid.UUID(str(operation_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise ReleaseError("clean port reservation operation ID is invalid") from error
    if canonical_operation_id != operation_id:
        raise ReleaseError("clean port reservation operation ID is not canonical")
    reservations = _clean_port_reservations(
        {
            role: {"port": ports[role]}
            for role in PORT_RESERVATION_ROLES
        }
        if isinstance(ports, Mapping) and set(ports) == set(PORT_RESERVATION_ROLES)
        else ports
    )
    _verify_clean_ports_bindable(reservations)
    unsigned = {
        "schema_version": 1,
        "kind": CLEAN_PORT_RESERVATIONS_KIND,
        "operation_id": canonical_operation_id,
        "release_digest": release_digest,
        "reservations": reservations,
        "created_at": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    }
    document = {
        **unsigned,
        "document_sha256": hashlib.sha256(_canonical_json(unsigned)).hexdigest(),
    }
    payload = _canonical_json(document) + b"\n"
    if len(payload) > MAX_PORT_RESERVATIONS_BYTES:
        raise ReleaseError("clean port reservation bundle exceeds its byte budget")

    output = output.expanduser()
    if not output.is_absolute():
        raise ReleaseError("clean port reservation output must be absolute")
    output = Path(
        _canonical_absolute_path(
            str(Path(os.path.abspath(output))), "clean port reservation output"
        )
    )
    try:
        parent_info = output.parent.lstat()
    except OSError as error:
        raise ReleaseError("clean port reservation output parent is unavailable") from error
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or output.parent.resolve(strict=True) != output.parent
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise ReleaseError("clean port reservation output parent is unsafe")
    if output.exists() or output.is_symlink():
        raise ReleaseError("clean port reservation output already exists")

    temporary = output.parent / f".{output.name}.{uuid.uuid4().hex}.partial"
    _install_bytes(
        temporary,
        payload,
        mode=0o600,
        uid=os.geteuid(),
        gid=os.getegid(),
    )
    try:
        try:
            os.link(temporary, output, follow_symlinks=False)
        except FileExistsError as error:
            raise ReleaseError("clean port reservation output appeared") from error
        temporary.unlink()
        parent_descriptor = os.open(
            output.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    validated = validated_port_reservations(
        output,
        expected_document_sha256=str(document["document_sha256"]),
        release_digest=release_digest,
    )
    if validated != document:
        raise ReleaseError("published clean port reservation bundle changed")
    return validated


def render_units(
    release: Path,
    output: Path,
    *,
    total_memory_bytes: int | None = None,
    host_cpu_count: int | None = None,
    port_reservations: Path,
    port_reservations_sha256: str,
) -> dict[str, Any]:
    verified = verify_release(release)
    release = release.resolve(strict=True)
    reservation_bundle = validated_port_reservations(
        port_reservations,
        expected_document_sha256=port_reservations_sha256,
        release_digest=verified["release_digest"],
    )
    reservations = reservation_bundle["reservations"]
    handoff_http_port = reservations["handoff_http"]["port"]
    handoff_https_port = reservations["handoff_https"]["port"]
    handoff_api_port = reservations["handoff_api"]["port"]
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise ReleaseError("unit output must be one absent path")
    output.mkdir(parents=True, mode=0o755)
    digest = verified["release_digest"]
    capacity = derive_slice_capacity(
        host_memory_bytes() if total_memory_bytes is None else total_memory_bytes,
        cpu_count=host_cpu_count,
    )
    handoff = {
        "DEVCOORDINATOR_HANDOFF_HTTP_PORT": str(handoff_http_port),
        "DEVCOORDINATOR_HANDOFF_HTTPS_PORT": str(handoff_https_port),
        "DEVCOORDINATOR_HANDOFF_API_PORT": str(handoff_api_port),
    }
    rendered: list[str] = []
    try:
        for name in AVAILABILITY_TEMPLATES:
            source = release / "deploy" / name
            if not source.is_file() or source.is_symlink():
                raise ReleaseError(
                    f"immutable availability template is missing or unsafe: {name}"
                )
            text = source.read_text(encoding="utf-8").replace("RELEASE_DIGEST", digest)
            for placeholder, field in CAPACITY_PLACEHOLDERS.items():
                text = text.replace(placeholder, str(capacity[field]))
            for placeholder, value in handoff.items():
                text = text.replace(placeholder, value)
            if any(placeholder in text for placeholder in (*CAPACITY_PLACEHOLDERS, *handoff)):
                raise ReleaseError(f"availability template retained a placeholder: {name}")
            target = output / name
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            rendered.append(name)
    except BaseException:
        for name in rendered:
            (output / name).unlink(missing_ok=True)
        output.rmdir()
        raise
    return {
        "ok": True,
        "release_digest": digest,
        "output": str(output),
        "files": sorted(rendered),
        "activation_ready": all(verified["capabilities"].values()),
        "capabilities": verified["capabilities"],
        "capacity": capacity,
        "handoff_ports": {
            "http": handoff_http_port,
            "https": handoff_https_port,
            "api": handoff_api_port,
        },
        "port_reservations": str(port_reservations.expanduser().absolute()),
        "port_reservations_sha256": reservation_bundle["document_sha256"],
    }


def initialize_observer_projection(
    release: Path,
    publication: Path,
    *,
    owner_uid: int,
    owner_gid: int,
    database: Path | None = None,
) -> dict[str, Any]:
    """Explicitly initialize the observer-owned database and publication."""

    verified = verify_release(release)
    release = release.resolve(strict=True)
    module_path = (
        release
        / "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py"
    )
    if not module_path.is_file() or module_path.is_symlink():
        raise ReleaseError("verified release has no retained inventory projection module")
    publication = publication.expanduser().absolute()
    database = (
        publication.with_name("inventory.sqlite3")
        if database is None
        else database.expanduser().absolute()
    )
    if database.parent != publication.parent or database == publication:
        raise ReleaseError("retained inventory database must be a sibling of its publication")
    try:
        parent = publication.parent.lstat()
    except OSError as error:
        raise ReleaseError("retained inventory parent does not exist") from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise ReleaseError("retained inventory parent has unsafe ownership or mode")
    if os.geteuid() != 0 and (owner_uid, owner_gid) != (os.geteuid(), os.getegid()):
        raise ReleaseError("only root may initialize a projection for another identity")

    spec = importlib.util.spec_from_file_location(
        f"devcoordinator_inventory_projection_{verified['release_digest']}", module_path
    )
    if spec is None or spec.loader is None:
        raise ReleaseError("cannot load the verified retained inventory module")
    projection = importlib.util.module_from_spec(spec)
    previous_dont_write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(projection)
    finally:
        sys.dont_write_bytecode = previous_dont_write_bytecode

    if publication.exists() or publication.is_symlink():
        try:
            current = projection.read_projection(
                publication, expected_owner_uid=owner_uid
            )
            if not database.exists() and not database.is_symlink():
                projection.initialize_inventory_store(
                    database,
                    current,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
            retained = projection.verify_inventory_store(
                database,
                publication,
                expected_owner_uid=owner_uid,
            )
        except Exception as error:
            raise ReleaseError(f"existing retained projection is invalid: {error}") from error
        return {
            "ok": True,
            "created": False,
            "release_digest": verified["release_digest"],
            "publication": str(publication),
            "database": str(database),
            "generation": retained["generation"],
        }

    if database.exists() or database.is_symlink():
        raise ReleaseError("retained inventory database exists without its publication")

    published_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    initial = projection.envelope(
        generation=1,
        inventory=projection.empty_inventory(),
        published_at=published_at,
    )
    try:
        projection.initialize_inventory_store(
            database,
            initial,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        projection.publish_projection(
            publication,
            initial,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
        )
        current = projection.read_projection(
            publication, expected_owner_uid=owner_uid
        )
        retained = projection.verify_inventory_store(
            database,
            publication,
            expected_owner_uid=owner_uid,
        )
    except Exception as error:
        database.unlink(missing_ok=True)
        Path(f"{database}-wal").unlink(missing_ok=True)
        Path(f"{database}-shm").unlink(missing_ok=True)
        publication.unlink(missing_ok=True)
        raise ReleaseError(f"cannot initialize retained projection: {error}") from error
    return {
        "ok": True,
        "created": True,
        "release_digest": verified["release_digest"],
        "publication": str(publication),
        "database": str(database),
        "generation": retained["generation"],
    }


def render_console_slot(
    release: Path,
    output: Path,
    *,
    port_reservations: Path,
    port_reservations_sha256: str,
    bootstrap_active: bool = False,
) -> dict[str, Any]:
    verified = verify_release(release)
    reservation_bundle = validated_port_reservations(
        port_reservations,
        expected_document_sha256=port_reservations_sha256,
        release_digest=verified["release_digest"],
    )
    reservations = reservation_bundle["reservations"]
    port = reservations["console_outer"]["port"]
    inner_port = reservations["console_inner"]["port"]
    output = output.resolve()
    if output.name != f"{verified['release_digest']}.env":
        raise ReleaseError("Console slot filename must be exactly <release-digest>.env")
    if output.parent.is_symlink():
        raise ReleaseError("Console slot directory must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    parent = output.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) & 0o022:
        raise ReleaseError("Console slot directory has unsafe permissions")
    payload = (
        "# Generated immutable Console candidate slot.\n"
        "BIND_HOST=127.0.0.1\n"
        "DEV_HTTP=0\n"
        "HTTP_PORT=0\n"
        f"HTTPS_PORT={port}\n"
        f"DEVCOORDINATOR_RELEASE_DIGEST={verified['release_digest']}\n"
        f"DEVCOORDINATOR_CONSOLE_INNER_PORT={inner_port}\n"
        f"DEVCOORDINATOR_CONSOLE_CONTROL_SOCKET=/run/devcoordinator-console/{verified['release_digest']}.sock\n"
        "DEVCOORDINATOR_CONSOLE_SUPERVISOR_STATE=/var/lib/devcoordinator-console/supervisor\n"
        "DEVCOORDINATOR_CONSOLE_RUNTIME=/run/devcoordinator-console\n"
        f"DEVCOORDINATOR_CONSOLE_BOOTSTRAP_ACTIVE={1 if bootstrap_active else 0}\n"
    ).encode("utf-8")
    if output.exists() or output.is_symlink():
        if output.is_file() and not output.is_symlink() and output.read_bytes() == payload:
            return {
                "ok": True,
                "created": False,
                "release_digest": verified["release_digest"],
                "slot": str(output),
                "port": port,
                "inner_port": inner_port,
                "port_reservations": str(port_reservations.expanduser().absolute()),
                "port_reservations_sha256": reservation_bundle["document_sha256"],
                "bootstrap_active": bootstrap_active,
                "parallel_writer_safe": verified["capabilities"]["console_parallel_writer_safe"],
            }
        raise ReleaseError("Console slot already exists with different or unsafe content")
    _install_bytes(
        output,
        payload,
        mode=0o644,
        uid=os.geteuid(),
        gid=os.getegid(),
    )
    return {
        "ok": True,
        "created": True,
        "release_digest": verified["release_digest"],
        "slot": str(output),
        "port": port,
        "inner_port": inner_port,
        "port_reservations": str(port_reservations.expanduser().absolute()),
        "port_reservations_sha256": reservation_bundle["document_sha256"],
        "bootstrap_active": bootstrap_active,
        "parallel_writer_safe": verified["capabilities"]["console_parallel_writer_safe"],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    plan = subcommands.add_parser("plan")
    plan.add_argument("--repo", type=Path, default=ROOT)
    plan.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)
    stage = subcommands.add_parser("stage")
    stage.add_argument("--repo", type=Path, default=ROOT)
    stage.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)
    stage.add_argument("--owner-uid", type=int, default=0)
    stage.add_argument("--owner-gid", type=int, default=0)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--release", type=Path, required=True)
    render = subcommands.add_parser("render-units")
    render.add_argument("--release", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--host-memory-bytes", type=int)
    render.add_argument("--host-cpu-count", type=int)
    render.add_argument("--port-reservations", type=Path, required=True)
    render.add_argument("--port-reservations-sha256", required=True)
    observer = subcommands.add_parser("init-observer-projection")
    observer.add_argument("--release", type=Path, required=True)
    observer.add_argument("--publication", type=Path, required=True)
    observer.add_argument("--database", type=Path)
    observer.add_argument("--owner-uid", type=int, required=True)
    observer.add_argument("--owner-gid", type=int, required=True)
    console_slot = subcommands.add_parser("render-console-slot")
    console_slot.add_argument("--release", type=Path, required=True)
    console_slot.add_argument("--output", type=Path, required=True)
    console_slot.add_argument("--port-reservations", type=Path, required=True)
    console_slot.add_argument("--port-reservations-sha256", required=True)
    console_slot.add_argument("--bootstrap-active", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.action == "plan":
            result = plan_release(args.repo, args.release_root)
        elif args.action == "stage":
            if args.release_root == DEFAULT_RELEASE_ROOT and os.geteuid() != 0:
                raise ReleaseError("staging into /opt requires root")
            result = stage_release(
                args.repo,
                args.release_root,
                owner_uid=args.owner_uid,
                owner_gid=args.owner_gid,
            )
        elif args.action == "verify":
            result = verify_release(args.release)
        elif args.action == "render-units":
            result = render_units(
                args.release,
                args.output,
                total_memory_bytes=args.host_memory_bytes,
                host_cpu_count=args.host_cpu_count,
                port_reservations=args.port_reservations,
                port_reservations_sha256=args.port_reservations_sha256,
            )
        elif args.action == "init-observer-projection":
            result = initialize_observer_projection(
                args.release,
                args.publication,
                owner_uid=args.owner_uid,
                owner_gid=args.owner_gid,
                database=args.database,
            )
        else:
            result = render_console_slot(
                args.release,
                args.output,
                port_reservations=args.port_reservations,
                port_reservations_sha256=args.port_reservations_sha256,
                bootstrap_active=bool(args.bootstrap_active),
            )
    except (OSError, ValueError, ReleaseError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
