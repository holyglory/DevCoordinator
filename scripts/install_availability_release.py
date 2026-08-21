#!/usr/bin/env python3
"""Build and verify an immutable DevCoordinator release.

This installer never starts or switches a service. It creates one content-
addressed, non-writable current-format release. The repository-owned delivery
driver performs the fenced activation, health verification, and rollback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid
from typing import Any


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
AVAILABILITY_TEMPLATES = (
    "devcoordinator-api.service",
    "devcoordinator-api.socket",
    "devcoordinator-authority.service",
    "devcoordinator-authority.socket",
    "devcoordinator-availability.sysusers.conf",
    "devcoordinator-availability.tmpfiles.conf",
    "devcoordinator.tmpfiles.conf",
    "devcoordinator-background.slice",
    "devcoordinator-console@.service",
    "devcoordinator-control.slice",
    "devcoordinator-edge-http.socket",
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
    Path("deploy/devcoordinator-read-only.rules"),
    Path("deploy/devcoordinator-test.rules"),
    Path("scripts/availability_schema_check.py"),
    Path("scripts/browser_lcp_acceptance.py"),
    Path("scripts/check_availability_topology.py"),
    Path("scripts/devcoordinator_observer.py"),
    Path("scripts/install_availability_release.py"),
    Path("scripts/install_browser_lcp_runtime.py"),
    Path("scripts/manage_maintenance_mode.py"),
    Path("scripts/manage_universal_test_credentials.py"),
    Path("scripts/manage_test_store.py"),
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
    "devcoordinator-image": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("broker", "publish-image"),
    ),
    "devcoordinator-systemd-unit": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("systemd-unit",),
    ),
    "devcoordinator-authority-repository-repair": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("broker", "approve-compose-host-access"),
    ),
    "devcoordinator-compose-host-access": (
        "python",
        "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        ("broker", "approve-compose-host-access"),
    ),
    "devcoordinator-maintenance": (
        "python",
        "scripts/manage_maintenance_mode.py",
        (),
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
    "devcoordinator-retained-control": (
        "python",
        "skills/codex-dev-coordinator/scripts/devcoordinator/retained_control.py",
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
        "skills/codex-dev-coordinator/scripts/devcoordinator/agent_cli.py",
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
    "devcoordinator-test-credential": (
        "python",
        "scripts/manage_universal_test_credentials.py",
        (),
    ),
    "devcoordinator-test-store": (
        "python",
        "scripts/manage_test_store.py",
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
    "skills/codex-dev-coordinator/scripts/devcoordinator/efficiency_registry.py",
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
    "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/schema.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/store.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/test_actor.py",
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
    "efficiency_registry",
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


def _smoke_test_compose_host_access_wrappers(release: Path) -> None:
    """Prove both packaged approval names bind the current live grammar."""

    for name in (
        "devcoordinator-compose-host-access",
        "devcoordinator-authority-repository-repair",
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
                f"release Compose host-access wrapper could not execute: {name}: {error}"
            ) from error
        if (
            completed.returncode != 0
            or b"approve-compose-host-access" not in completed.stdout
            or b"--approve-compose-host-access" not in completed.stdout
            or completed.stderr
        ):
            detail = completed.stderr.decode(
                "utf-8", errors="replace"
            ).strip()
            raise ReleaseError(
                "release Compose host-access wrapper failed its grammar smoke test: "
                f"{name}: {detail or completed.returncode}"
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
        "current_format_delivery": all(
            path in paths
            for path in (
                "bin/devcoordinator-same-schema-switch",
                "bin/devcoordinator-retained-control",
                "scripts/switch_same_schema_release.py",
                "skills/codex-dev-coordinator/scripts/devcoordinator/retained_control.py",
                "deploy/devcoordinator-api.socket",
                "deploy/devcoordinator-authority.socket",
                "deploy/devcoordinator-edge.service",
                "deploy/devcoordinator-console@.service",
            )
        ),
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
        or not re.fullmatch(r"[0-7]{4}", str(source_identity.get("mode")))
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
    _smoke_test_compose_host_access_wrappers(release)
    return {
        "ok": True,
        "release_digest": release.name,
        "release_directory": str(release),
        "capabilities": manifest["capabilities"],
        "file_count": len(entries),
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
        else:
            result = verify_release(args.release)
    except (OSError, ValueError, ReleaseError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
