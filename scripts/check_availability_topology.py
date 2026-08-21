#!/usr/bin/env python3
"""Validate the staged DevCoordinator availability-topology unit templates.

This is deliberately a static check.  It neither talks to systemd nor changes
the host.  The installer must run it before rendering the release digest into
the templates, and must validate the loaded units again after installation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_UNIT_DIR = ROOT / "deploy"
API_PROFILE_SCHEMA = 2


@dataclass(frozen=True)
class ServiceContract:
    user: str
    slice_name: str
    instance_release: bool = False
    restart: str = "always"
    restart_sec: str = "2"
    kill_mode: str = "mixed"


SERVICE_CONTRACTS = {
    "devcoordinator-edge.service": ServiceContract(
        "devcoordinator-edge", "devcoordinator-control.slice"
    ),
    "devcoordinator-api.service": ServiceContract(
        "devcoordinator-api", "devcoordinator-control.slice"
    ),
    "devcoordinator-authority.service": ServiceContract(
        "root", "devcoordinator-control.slice", restart="on-failure"
    ),
    "devcoordinator-console@.service": ServiceContract(
        "devcoordinator-console", "devcoordinator-control.slice", True
    ),
    "devcoordinator-observer.service": ServiceContract(
        "devcoordinator-observer",
        "devcoordinator-background.slice",
        restart_sec="3",
        kill_mode="control-group",
    ),
    "devcoordinator-notifications.service": ServiceContract(
        "devcoordinator-notifications",
        "devcoordinator-background.slice",
        restart_sec="3",
        kill_mode="control-group",
    ),
    "devcoordinator-testd.service": ServiceContract(
        "devcoordinator-testd",
        "devcoordinator-background.slice",
        restart_sec="3",
        kill_mode="control-group",
    ),
    "devcoordinator-test-snapshotd.service": ServiceContract(
        "root", "devcoordinator-background.slice", kill_mode="control-group"
    ),
}

SOCKET_CONTRACTS = {
    "devcoordinator-edge-http.socket": (
        "devcoordinator-edge.service",
        "80",
        "http",
    ),
    "devcoordinator-edge-https.socket": (
        "devcoordinator-edge.service",
        "443",
        "https",
    ),
    "devcoordinator-edge-publication.socket": (
        "devcoordinator-edge.service",
        "/run/devcoordinator-edge-publication/publish.sock",
        "publication",
    ),
    "devcoordinator-api.socket": (
        "devcoordinator-api.service",
        "127.0.0.1:29876",
        "api",
    ),
    "devcoordinator-authority.socket": (
        "devcoordinator-authority.service",
        "/run/devcoordinator-authority.sock",
        "authority",
    ),
    "devcoordinator-testd.socket": (
        "devcoordinator-testd.service",
        "/run/devcoordinator-testd/testd.sock",
        "testd",
    ),
    "devcoordinator-test-snapshotd.socket": (
        "devcoordinator-test-snapshotd.service",
        "/run/devcoordinator-test-snapshotd/snapshot.sock",
        "snapshotd",
    ),
}

SLICE_CONTRACTS = {
    "devcoordinator-control.slice": 10000,
    "devcoordinator-background.slice": 200,
    "devcoordinator-projects.slice": 100,
    "devcoordinator-tests.slice": None,
}
SLICE_MEMORY_TEMPLATES = {
    "devcoordinator-control.slice": {
        "MemoryLow": "DEVCOORDINATOR_CONTROL_MEMORY_LOW_BYTES",
    },
    "devcoordinator-background.slice": {
        "CPUQuota": "DEVCOORDINATOR_BACKGROUND_CPU_QUOTA_PERCENT%",
        "MemoryHigh": "DEVCOORDINATOR_BACKGROUND_MEMORY_HIGH_BYTES",
        "MemoryMax": "DEVCOORDINATOR_BACKGROUND_MEMORY_MAX_BYTES",
    },
    "devcoordinator-projects.slice": {
        "MemoryHigh": "DEVCOORDINATOR_PROJECT_MEMORY_HIGH_BYTES",
        "MemoryMax": "DEVCOORDINATOR_PROJECT_MEMORY_MAX_BYTES",
    },
    "devcoordinator-tests.slice": {},
}

EXTRA_FILES = {
    "devcoordinator-availability.sysusers.conf",
    "devcoordinator-availability.tmpfiles.conf",
}
DEDICATED_USERS = {
    "devcoordinator-edge",
    "devcoordinator-console",
    "devcoordinator-api",
    "devcoordinator-observer",
    "devcoordinator-testd",
    "devcoordinator-notifications",
}
DEPENDENCY_KEYS = {
    "After",
    "Before",
    "BindsTo",
    "Conflicts",
    "PartOf",
    "PropagatesReloadTo",
    "PropagatesStopTo",
    "Requisite",
    "Requires",
    "Upholds",
    "Wants",
}
EXEC_KEYS = {"ExecStartPre", "ExecStart", "ExecStartPost"}
MIGRATION_PATTERN = re.compile(
    r"(?:\bmigrat(?:e|es|ed|ing|ion|ions)\b|\bupgrade\b|"
    r"\bschema[-_ ]?init\b|\binitialize[-_ ]?schema\b|\balembic\b|"
    r"\bprisma\b|\bddl\b)",
    re.IGNORECASE,
)
RELEASE_EXECUTABLE = re.compile(
    r"^/opt/devcoordinator/releases/(RELEASE_DIGEST|%i|[a-f0-9]{64})/bin/"
    r"[A-Za-z0-9][A-Za-z0-9._-]*$"
)
RELEASE_DIGEST = re.compile(r"^[a-f0-9]{64}$")
BASE_HARDENING = {
    "NoNewPrivileges": {"yes"},
    "PrivateTmp": {"yes"},
    "ProtectSystem": {"strict"},
    "ProtectHome": {"yes", "read-only"},
    "ProtectKernelTunables": {"yes"},
    "ProtectKernelModules": {"yes"},
    "ProtectControlGroups": {"yes"},
    "StandardOutput": {"journal"},
    "StandardError": {"journal"},
}
MUTABLE_PRODUCTION_PATHS = ("/home/DevCoordinator", "/home/holyglory")
CALL_JOURNAL_ENVIRONMENT = {
    "DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl",
    "DEVCOORDINATOR_CALL_LOG_MAX_BYTES=4194304",
    "DEVCOORDINATOR_CALL_LOG_BACKUPS=4",
}
CALL_JOURNAL_ENV_SERVICES = {
    "devcoordinator-api.service",
    "devcoordinator-testd.service",
    "devcoordinator-test-snapshotd.service",
}


@dataclass(frozen=True)
class Violation:
    code: str
    file: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "file": self.file, "detail": self.detail}


Unit = dict[str, dict[str, list[str]]]


def parse_unit(path: Path) -> Unit:
    """Parse the bounded subset of systemd syntax used by these templates."""

    sections: Unit = {}
    section: str | None = None
    pending = ""
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = pending + raw.strip()
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if not section:
                raise ValueError(f"empty section at line {number}")
            sections.setdefault(section, {})
            continue
        if section is None or "=" not in line:
            raise ValueError(f"invalid unit directive at line {number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"empty directive at line {number}")
        sections[section].setdefault(key, []).append(value.strip())
    if pending:
        raise ValueError("unterminated continuation")
    return sections


def values(unit: Unit, section: str, key: str) -> list[str]:
    return unit.get(section, {}).get(key, [])


def one(unit: Unit, section: str, key: str) -> str | None:
    candidates = values(unit, section, key)
    return candidates[0] if len(candidates) == 1 else None


def dependency_names(unit: Unit) -> Iterable[tuple[str, str]]:
    for key in DEPENDENCY_KEYS:
        for value in values(unit, "Unit", key):
            for token in value.split():
                yield key, token.lstrip("-")


def violation(code: str, path: Path, detail: str) -> Violation:
    return Violation(code, path.name, detail)


def validate_service(
    path: Path,
    contract: ServiceContract,
    *,
    release_digest: str | None = None,
) -> list[Violation]:
    findings: list[Violation] = []
    try:
        unit = parse_unit(path)
    except (OSError, UnicodeError, ValueError) as error:
        return [violation("unit_parse_failed", path, str(error))]

    if path.name in CALL_JOURNAL_ENV_SERVICES:
        environment = set(values(unit, "Service", "Environment"))
        if not CALL_JOURNAL_ENVIRONMENT.issubset(environment):
            findings.append(
                violation(
                    "call_journal_environment_invalid",
                    path,
                    "call-boundary service must share the fixed sanitized call-journal path and retention settings",
                )
            )
        if (
            one(unit, "Service", "LogsDirectory") != "devcoordinator"
            or one(unit, "Service", "LogsDirectoryMode") != "0777"
        ):
            findings.append(
                violation(
                    "call_journal_directory_invalid",
                    path,
                    "call-boundary service must receive the shared writable call-journal directory from systemd",
                )
            )

    if one(unit, "Service", "User") != contract.user:
        findings.append(
            violation(
                "service_identity_invalid",
                path,
                f"User must be exactly {contract.user}",
            )
        )
    if one(unit, "Service", "Group") != contract.user:
        findings.append(
            violation(
                "service_identity_invalid",
                path,
                f"Group must be exactly {contract.user}; shared local access groups are forbidden",
            )
        )
    if values(unit, "Service", "SupplementaryGroups"):
        findings.append(
            violation(
                "local_access_group_forbidden",
                path,
                "SupplementaryGroups must be absent; local services communicate without group authorization",
            )
        )
    if one(unit, "Service", "Slice") != contract.slice_name:
        findings.append(
            violation(
                "service_slice_invalid",
                path,
                f"Slice must be exactly {contract.slice_name}",
            )
        )

    service_type = one(unit, "Service", "Type")
    if service_type not in {"exec", "notify"}:
        findings.append(
            violation(
                "service_readiness_invalid",
                path,
                "Type must be exec or notify; simple units expose an earlier readiness point",
            )
        )
    restart = one(unit, "Service", "Restart")
    if restart != contract.restart:
        findings.append(
            violation(
                "service_resilience_invalid",
                path,
                f"Restart must be exactly {contract.restart}",
            )
        )
    if one(unit, "Service", "RestartSec") != contract.restart_sec:
        findings.append(
            violation(
                "service_resilience_invalid",
                path,
                f"RestartSec must be exactly {contract.restart_sec}",
            )
        )
    if one(unit, "Service", "KillMode") != contract.kill_mode:
        findings.append(
            violation(
                "service_resilience_invalid",
                path,
                f"KillMode must be exactly {contract.kill_mode}",
            )
        )
    for key, accepted in BASE_HARDENING.items():
        if path.name == "devcoordinator-test-snapshotd.service" and key == "NoNewPrivileges":
            if one(unit, "Service", key) is not None:
                findings.append(
                    violation(
                        "snapshotd_uid_delegation_blocked",
                        path,
                        "snapshotd must omit NoNewPrivileges so its immutable helper can drop to repository owner UIDs",
                    )
                )
            continue
        if path.name == "devcoordinator-authority.service" and key == "ProtectHome":
            if one(unit, "Service", key) != "false":
                findings.append(
                    violation(
                        "authority_repository_write_view_invalid",
                        path,
                        "authority must set ProtectHome=false so the explicit /home ReadWritePaths exception is effective",
                    )
                )
            continue
        required = (
            {"full"}
            if path.name == "devcoordinator-testd.service" and key == "ProtectSystem"
            else accepted
        )
        if one(unit, "Service", key) not in required:
            findings.append(
                violation(
                    "service_hardening_invalid",
                    path,
                    f"{key} must be exactly one of {sorted(required)}",
                )
            )
    raw_text = path.read_text(encoding="utf-8")
    if any(
        marker in raw_text
        for marker in ("api-token", "--token-file", "COORDINATOR_TOKEN_FILE")
    ):
        findings.append(
            violation(
                "internal_api_shared_credential_forbidden",
                path,
                "on-host Coordinator HTTP clients must use the trusted loopback boundary without a shared token",
            )
        )
    for mutable in MUTABLE_PRODUCTION_PATHS:
        if mutable in raw_text:
            findings.append(
                violation(
                    "mutable_checkout_reference_forbidden",
                    path,
                    f"production template must not reference {mutable}",
                )
            )

    starts = values(unit, "Service", "ExecStart")
    if len(starts) != 1:
        findings.append(
            violation("exec_start_invalid", path, "exactly one ExecStart is required")
        )
    for key in EXEC_KEYS:
        for command in values(unit, "Service", key):
            try:
                argv = shlex.split(command)
            except ValueError as error:
                findings.append(violation("exec_parse_failed", path, f"{key}: {error}"))
                continue
            if not argv or not RELEASE_EXECUTABLE.fullmatch(argv[0]):
                findings.append(
                    violation(
                        "immutable_release_path_required",
                        path,
                        f"{key} must execute an exact /opt/devcoordinator/releases path",
                    )
                )
            else:
                selector = argv[0].split("/", 5)[4]
                selector_valid = selector == "%i" if contract.instance_release else (
                    selector == (release_digest or "RELEASE_DIGEST")
                )
                if selector_valid:
                    pass
                else:
                    expected = "%i" if contract.instance_release else (release_digest or "RELEASE_DIGEST")
                    findings.append(
                        violation(
                            "release_selector_invalid",
                            path,
                            f"{key} must use the {expected} release selector",
                        )
                    )
            if MIGRATION_PATTERN.search(command):
                findings.append(
                    violation(
                        "startup_migration_forbidden",
                        path,
                        f"{key} contains a schema/data migration action",
                    )
                )
            if argv and argv[0].endswith("-check") and "--read-only" not in argv[1:]:
                findings.append(
                    violation(
                        "startup_check_not_read_only",
                        path,
                        f"{key} check must include --read-only",
                    )
                )

    for key, name in dependency_names(unit):
        if name.startswith("devcoordinator-project"):
            findings.append(
                violation(
                    "control_project_dependency_forbidden",
                    path,
                    f"{key} must not reference the project data plane ({name})",
                )
            )

    if path.name == "devcoordinator-edge.service":
        if values(unit, "Service", "SystemCallFilter") != [
            "@system-service pkey_alloc pkey_free pkey_mprotect"
        ]:
            findings.append(
                violation(
                    "edge_node_syscall_filter_invalid",
                    path,
                    "edge must allow exactly the @system-service set plus Node/V8 memory-protection-key syscalls",
                )
            )
        for key, name in dependency_names(unit):
            if any(
                marker in name
                for marker in ("api", "authority", "console", "observer", "testd")
            ):
                findings.append(
                    violation(
                        "edge_control_dependency_forbidden",
                        path,
                        f"the stable edge must not depend on {name} through {key}",
                    )
                )
        credential_names = {
            value.split(":", 1)[0]
            for value in values(unit, "Service", "LoadCredential")
        }
        if credential_names != {
            "session-secret",
            "oidc-client-id",
            "oidc-client-secret",
            "tls-cert",
            "tls-key",
        }:
            findings.append(
                violation(
                    "edge_credential_contract_invalid",
                    path,
                    "edge must load exactly TLS, session, and OIDC client credentials",
                )
            )
        command = one(unit, "Service", "ExecStart") or ""
        for flag in (
            "--systemd-sockets",
            "--route-publication",
            "--session-secret-file",
            "--oidc-issuer",
            "--oidc-client-id-file",
            "--oidc-client-secret-file",
            "--tls-cert",
            "--tls-key",
            "--release-root",
        ):
            if flag not in command:
                findings.append(
                    violation(
                        "edge_launch_contract_invalid",
                        path,
                        f"edge ExecStart must include {flag}",
                    )
                )
    if path.name in {
        "devcoordinator-api.service",
        "devcoordinator-authority.service",
    }:
        command = one(unit, "Service", "ExecStart") or ""
        if "--systemd-socket" not in command:
            findings.append(
                violation(
                    "socket_activation_missing",
                    path,
                    "socket-owned service must explicitly adopt its inherited descriptor",
                )
            )
    if path.name == "devcoordinator-authority.service":
        command = one(unit, "Service", "ExecStart") or ""
        if one(unit, "Service", "TimeoutStopSec") != "65min":
            findings.append(
                violation(
                    "authority_backup_drain_timeout_invalid",
                    path,
                    "authority TimeoutStopSec must be exactly 65min so a bounded database backup can drain before replacement",
                )
            )
        for flag in ("--test-plane-socket",):
            if flag not in command:
                findings.append(
                    violation(
                        "authority_test_plane_contract_invalid",
                        path,
                        f"authority ExecStart must include {flag}",
                    )
                )
        required_call_journal = {
            "--call-log": "/var/log/devcoordinator/calls.jsonl",
            "--call-log-max-bytes": "4194304",
            "--call-log-backups": "4",
        }
        try:
            call_journal_argv = shlex.split(command)
            call_journal_options = {
                call_journal_argv[index]: call_journal_argv[index + 1]
                for index in range(len(call_journal_argv) - 1)
                if call_journal_argv[index].startswith("--")
            }
        except (ValueError, IndexError):
            call_journal_options = {}
        if any(
            call_journal_options.get(flag) != expected
            for flag, expected in required_call_journal.items()
        ):
            findings.append(
                violation(
                    "authority_call_journal_invalid",
                    path,
                    "authority must write the fixed 5-file/20-MiB sanitized call journal",
                )
            )
        if (
            one(unit, "Service", "LogsDirectory") != "devcoordinator"
            or one(unit, "Service", "LogsDirectoryMode") != "0777"
        ):
            findings.append(
                violation(
                    "authority_call_journal_directory_invalid",
                    path,
                    "authority must receive the persistent writable call-journal directory from systemd",
                )
            )
        try:
            authority_argv = shlex.split(command)
        except ValueError:
            authority_argv = []
        obsolete_local_gates = {
            "--access-gid",
            "--access-group",
            "--socket-mode",
            "--test-plane-uid",
            "--test-plane-user",
            "--internal-testd-uid",
            "--internal-testd-user",
        }
        present_local_gates = sorted(obsolete_local_gates.intersection(authority_argv))
        if present_local_gates:
            findings.append(
                violation(
                    "local_transport_metadata_gate_forbidden",
                    path,
                    "authority must not authorize same-server IPC by UID, GID, group, or socket-mode metadata: "
                    + ", ".join(present_local_gates),
                )
            )
        writable_paths: set[str] = set()
        for declaration in values(unit, "Service", "ReadWritePaths"):
            try:
                writable_paths.update(shlex.split(declaration))
            except ValueError:
                writable_paths.clear()
                break
        required_fixture_paths = {
            "/var/lib/devcoordinator-test-fixtures",
            "-/run/devcoordinator/test-fixture-credentials",
        }
        if not required_fixture_paths <= writable_paths:
            findings.append(
                violation(
                    "authority_fixture_storage_contract_invalid",
                    path,
                    "authority must retain the durable fixture journal root and an optional runtime credential root",
                )
            )
        if "/var/lib/devcoordinator-browser-lifecycle" not in writable_paths:
            findings.append(
                violation(
                    "authority_browser_lifecycle_storage_missing",
                    path,
                    "authority must write browser telemetry through its dedicated caller-readable state root",
                )
            )
        if "/home" not in writable_paths:
            findings.append(
                violation(
                    "authority_repository_compatibility_path_missing",
                    path,
                    "authority must expose /home for code-bounded exact-working-tree access normalization",
                )
            )
        state_directories = {
            item
            for declaration in values(unit, "Service", "StateDirectory")
            for item in declaration.split()
        }
        if (
            "/var/lib/devcoordinator-test-artifacts" not in writable_paths
            or "devcoordinator-test-artifacts" not in state_directories
        ):
            findings.append(
                violation(
                    "authority_artifact_storage_contract_invalid",
                    path,
                    "authority must create and write the verified test artifact store",
                )
            )
        if "/var/lib/devcoordinator-test-results" not in writable_paths:
            findings.append(
                violation(
                    "authority_result_package_storage_missing",
                    path,
                    "authority must write the root-verified immutable test result-package store",
                )
            )
    if path.name == "devcoordinator-authority.service":
        if one(unit, "Service", "StateDirectoryMode") != "0711":
            findings.append(
                violation(
                    "authority_state_parent_traversal_invalid",
                    path,
                    "the shared authority state parent must be traverse-only so actual-caller clients can read explicitly published non-secret telemetry",
                )
            )
        runtime_directories = {
            item
            for declaration in values(unit, "Service", "RuntimeDirectory")
            for item in declaration.split()
        }
        if "devcoordinator" in runtime_directories:
            findings.append(
                violation(
                    "authority_runtime_directory_socket_conflict",
                    path,
                    "the socket unit owns /run/devcoordinator; no service may lifecycle-manage the same directory",
                )
            )
    if path.name == "devcoordinator-api.service":
        if one(unit, "Service", "ProtectHome") != "read-only":
            findings.append(
                violation(
                    "api_repository_visibility_invalid",
                    path,
                    "API services must read cataloged repository identities below /home",
                )
            )
        credentials = values(unit, "Service", "LoadCredential")
        if credentials:
            findings.append(
                violation(
                    "api_credential_contract_invalid",
                    path,
                    "trusted loopback API must not load a shared credential",
                )
            )
        command = one(unit, "Service", "ExecStart") or ""
        for flag in ("--profile",):
            if flag not in command:
                findings.append(
                    violation(
                        "api_launch_contract_invalid",
                        path,
                        f"API ExecStart must include {flag}",
                    )
                )
        expected_profile = "/etc/devcoordinator/client-profiles.json"
        preflight = one(unit, "Service", "ExecStartPre") or ""
        if (
            f"--profile {expected_profile}" not in command
            or f"--profile {expected_profile}" not in preflight
            or f"--expected-schema {API_PROFILE_SCHEMA}" not in preflight
        ):
            findings.append(
                violation(
                    "api_profile_contract_invalid",
                    path,
                    "the stable API must use the current protected profile schema",
                )
            )
        expected_role = "DEVCOORDINATOR_ROLE=api"
        if values(unit, "Service", "Environment") != [
            expected_role,
            "DEVCOORDINATOR_INVENTORY_PUBLICATION=/var/lib/devcoordinator-observer/inventory.publication",
            "DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl",
            "DEVCOORDINATOR_CALL_LOG_MAX_BYTES=4194304",
            "DEVCOORDINATOR_CALL_LOG_BACKUPS=4",
        ]:
            findings.append(
                violation(
                    "api_inventory_projection_invalid",
                    path,
                    "API must use only the current retained observer and call-log environment",
                )
            )
    if path.name == "devcoordinator-console@.service":
        credentials = values(unit, "Service", "LoadCredential")
        if credentials != [
            "session-secret:/etc/devcoordinator/edge/session-secret",
            "tls-cert:/etc/letsencrypt/live/vr.ae/fullchain.pem",
            "tls-key:/etc/letsencrypt/live/vr.ae/privkey.pem",
        ]:
            findings.append(
                violation(
                    "console_credential_contract_invalid",
                    path,
                    "Console slot must load exactly public session and TLS credentials",
                )
            )
        environment = values(unit, "Service", "Environment")
        for expected in (
            "SESSION_SECRET_FILE=%d/session-secret",
            "TLS_CERT_FILE=%d/tls-cert",
            "TLS_KEY_FILE=%d/tls-key",
        ):
            if expected not in environment:
                findings.append(
                    violation(
                        "console_credential_contract_invalid",
                        path,
                        f"Console slot must bind {expected}",
                    )
                )
        if "COORDINATOR_RETAINED_INVENTORY=1" not in values(
            unit, "Service", "Environment"
        ):
            findings.append(
                violation(
                    "console_inventory_sampling_forbidden",
                    path,
                    "Console must consume retained inventory without live observation",
                )
            )
        if (
            "DEVCOORDINATOR_BUG_DIR=/var/lib/devcoordinator-bugs/open"
            not in environment
        ):
            findings.append(
                violation(
                    "console_bug_registry_environment_missing",
                    path,
                    "Console must read the canonical out-of-band open-bug directory",
                )
            )
        writable_paths = {
            item
            for declaration in values(unit, "Service", "ReadWritePaths")
            for item in shlex.split(declaration)
        }
        if "/var/lib/devcoordinator-bugs" not in writable_paths:
            findings.append(
                violation(
                    "console_bug_registry_sandbox_missing",
                    path,
                    "Console must list and close bugs through the shared open-only registry",
                )
            )
    if path.name == "devcoordinator-observer.service":
        preflights = values(unit, "Service", "ExecStartPre")
        command = one(unit, "Service", "ExecStart") or ""
        if "--publication-group" in command:
            findings.append(
                violation(
                    "local_access_group_forbidden",
                    path,
                    "retained inventory publication must be locally readable without a shared group",
                )
            )
        observer_store_flags = (
            "--database /var/lib/devcoordinator-observer/inventory.sqlite3",
            "--publication /var/lib/devcoordinator-observer/inventory.publication",
        )
        verify_preflights = [
            item
            for item in preflights
            if " verify " in f" {item} "
            and all(flag in item for flag in observer_store_flags)
        ]
        config_preflights = [
            item
            for item in preflights
            if " config-check " in f" {item} "
        ]
        if len(verify_preflights) != 1:
            findings.append(
                violation(
                    "observer_preflight_invalid",
                    path,
                    "observer must verify an existing retained publication before startup",
                )
            )
        expected_config_flags = (
            "--project ${DEVCOORDINATOR_OBSERVER_PROJECT}",
            "--interval-seconds ${DEVCOORDINATOR_OBSERVER_INTERVAL_SECONDS}",
            "--request-timeout-seconds ${DEVCOORDINATOR_OBSERVER_REQUEST_TIMEOUT_SECONDS}",
            "--log-level ${LOG_LEVEL}",
        )
        if len(config_preflights) != 1 or any(
            flag not in config_preflights[0] for flag in expected_config_flags
        ):
            findings.append(
                violation(
                    "observer_config_preflight_invalid",
                    path,
                    "observer must validate the exact rendered background configuration before startup",
                )
            )
        for flag in (
            " serve ",
            *observer_store_flags,
            *expected_config_flags,
        ):
            if flag not in f" {command} ":
                findings.append(
                    violation(
                        "observer_launch_contract_invalid",
                        path,
                        f"observer ExecStart must include {flag.strip()}",
                    )
                )
    if path.name == "devcoordinator-testd.service":
        preflight = one(unit, "Service", "ExecStartPre") or ""
        command = one(unit, "Service", "ExecStart") or ""
        if (
            "--check" not in preflight
            or "--database" not in preflight
        ):
            findings.append(
                violation(
                    "testd_preflight_invalid",
                    path,
                    "testd must verify its existing disposable Test Store before startup",
                )
            )
        for flag in (
            "--database",
            "--broker-socket",
            "--snapshot-socket",
        ):
            if flag not in command:
                findings.append(
                    violation(
                        "testd_launch_contract_invalid",
                        path,
                        f"testd ExecStart must include {flag}",
                    )
                )
        readonly_paths = {
            item
            for declaration in values(unit, "Service", "ReadOnlyPaths")
            for item in declaration.split()
        }
        if "/var/lib/devcoordinator-test-results" not in readonly_paths:
            findings.append(
                violation(
                    "testd_result_package_read_missing",
                    path,
                    "testd must read only root-verified immutable result packages",
                )
            )
        try:
            argv = shlex.split(command)
            options = {
                argv[index]: argv[index + 1]
                for index in range(len(argv) - 1)
                if argv[index].startswith("--")
            }
        except (ValueError, IndexError):
            options = {}
        obsolete_scheduler_gates = {
            "--max-jobs",
            "--host-cpu-millis",
            "--host-memory-mib",
            "--host-pids",
            "--per-uid-jobs",
            "--per-repository-jobs",
        }
        present_scheduler_gates = sorted(
            obsolete_scheduler_gates.intersection(options)
        )
        if present_scheduler_gates:
            findings.append(
                violation(
                    "testd_resource_budget_forbidden",
                    path,
                    "testd must admit from current available memory and learned peaks, not fixed CPU, memory, PID, UID, repository, or job budgets: "
                    + ", ".join(present_scheduler_gates),
                )
            )
        obsolete_broker_gates = {
            "--broker-uid",
            "--broker-socket-gid",
            "--broker-socket-mode",
        }
        present_broker_gates = sorted(obsolete_broker_gates.intersection(options))
        if present_broker_gates:
            findings.append(
                violation(
                    "local_transport_metadata_gate_forbidden",
                    path,
                    "testd must connect to the local authority socket without UID, GID, or mode authorization gates: "
                    + ", ".join(present_broker_gates),
                )
            )
    if path.name == "devcoordinator-test-snapshotd.service":
        command = one(unit, "Service", "ExecStart") or ""
        for flag in (
            "--authority-database",
            "--helper",
            "--snapshot-root",
            "--catalog-root",
            "--testd-user",
        ):
            if flag not in command:
                findings.append(
                    violation(
                        "snapshotd_launch_contract_invalid",
                        path,
                        f"snapshotd ExecStart must include {flag}",
                    )
                )
        if "/libexec/universal_test_uid_helper.py" not in command:
            findings.append(
                violation(
                    "snapshotd_helper_contract_invalid",
                    path,
                    "snapshotd must use the helper from the same immutable release",
                )
            )
        writable_paths = set(
            (one(unit, "Service", "ReadWritePaths") or "").split()
        )
        state_directories = {
            item
            for declaration in values(unit, "Service", "StateDirectory")
            for item in declaration.split()
        }
        if "devcoordinator-test-runs" in state_directories:
            findings.append(
                violation(
                    "snapshotd_attempt_root_lifecycle_conflict",
                    path,
                    "snapshotd must not lifecycle-manage the shared attempt root because its private StateDirectoryMode strands attributed repository-UID runners during replacement",
                )
            )
        if "/var/lib/devcoordinator" not in writable_paths:
            findings.append(
                violation(
                    "snapshotd_authority_sidecar_path_missing",
                    path,
                    "snapshotd must be able to create authority SQLite WAL sidecars before the writer starts",
                )
            )
    return findings


def validate_socket(
    path: Path,
    expected_service: str,
    expected_listener: str,
    expected_fd_name: str,
    *,
    rendered: bool = False,
) -> list[Violation]:
    findings: list[Violation] = []
    try:
        unit = parse_unit(path)
    except (OSError, UnicodeError, ValueError) as error:
        return [violation("unit_parse_failed", path, str(error))]
    actual_listener = one(unit, "Socket", "ListenStream")
    handoff_placeholder = re.search(
        r"DEVCOORDINATOR_HANDOFF_[A-Z_]+_PORT", expected_listener
    )
    dynamic_handoff = handoff_placeholder is not None
    listener_valid = actual_listener == expected_listener
    if rendered and dynamic_handoff:
        if handoff_placeholder is None:
            return [
                violation(
                    "socket_listener_contract_invalid",
                    path,
                    "dynamic handoff listener placeholder is unavailable",
                )
            ]
        prefix = re.escape(expected_listener[: handoff_placeholder.start()])
        suffix = re.escape(expected_listener[handoff_placeholder.end() :])
        rendered_match = re.fullmatch(prefix + r"([0-9]+)" + suffix, actual_listener or "")
        listener_valid = bool(
            rendered_match
            and 30000 <= int(rendered_match.group(1)) <= 60999
        )
    checks = {
        "Service": expected_service,
        "FileDescriptorName": expected_fd_name,
        "Accept": "no",
        "RemoveOnStop": "no",
    }
    for key, expected in checks.items():
        if one(unit, "Socket", key) != expected:
            findings.append(
                violation(
                    "socket_contract_invalid",
                    path,
                    f"{key} must be exactly {expected}",
                )
            )
    if not listener_valid:
        wanted = "one broker-leased port in 30000-60999" if rendered and dynamic_handoff else expected_listener
        findings.append(
            violation(
                "socket_contract_invalid",
                path,
                f"ListenStream must be exactly {wanted}",
            )
        )
    for key, name in dependency_names(unit):
        if name.startswith("devcoordinator-project"):
            findings.append(
                violation(
                    "control_project_dependency_forbidden",
                    path,
                    f"{key} must not reference the project data plane ({name})",
                )
            )
    if expected_listener.startswith("/"):
        for key, expected in {
            "SocketMode": "0666",
            "DirectoryMode": "0755",
        }.items():
            if one(unit, "Socket", key) != expected:
                findings.append(
                    violation(
                        "local_socket_access_invalid",
                        path,
                        f"{key} must be exactly {expected} for trusted same-server IPC",
                    )
                )
        if one(unit, "Socket", "SocketGroup") is not None:
            findings.append(
                violation(
                    "local_access_group_forbidden",
                    path,
                    "SocketGroup must be absent; local socket access does not depend on group membership",
                )
            )
    return findings


def validate_slice(
    path: Path,
    expected_weight: int | None,
    *,
    rendered: bool = False,
) -> list[Violation]:
    findings: list[Violation] = []
    try:
        unit = parse_unit(path)
    except (OSError, UnicodeError, ValueError) as error:
        return [violation("unit_parse_failed", path, str(error))]
    accounting_keys = {
        "CPUAccounting",
        "MemoryAccounting",
        "IOAccounting",
        "TasksAccounting",
    }
    for key in sorted(accounting_keys):
        if one(unit, "Slice", key) != "yes":
            findings.append(
                violation(
                    "slice_accounting_missing",
                    path,
                    f"{key} must be exactly yes so project pressure remains attributable",
                )
            )
    if expected_weight is None:
        extra = sorted(set(unit.get("Slice", {})) - accounting_keys)
        if extra:
            findings.append(
                violation(
                    "test_slice_quota_forbidden",
                    path,
                    "the test-attempt slice is accounting-only and must not declare CPU, memory, PID, task, or weight controls: "
                    + ", ".join(extra),
                )
            )
    else:
        if one(unit, "Slice", "CPUWeight") != str(expected_weight):
            findings.append(
                violation(
                    "slice_weight_invalid",
                    path,
                    f"CPUWeight must be exactly {expected_weight}",
                )
            )
        if one(unit, "Slice", "IOWeight") != str(expected_weight):
            findings.append(
                violation(
                    "slice_weight_invalid",
                    path,
                    f"IOWeight must be exactly {expected_weight}",
                )
            )
        tasks = one(unit, "Slice", "TasksMax")
        if tasks is None or not tasks.isdigit() or int(tasks) <= 0:
            findings.append(
                violation(
                    "slice_budget_missing",
                    path,
                    "TasksMax must be one explicit positive integer",
                )
            )
        if not rendered:
            for key, placeholder in SLICE_MEMORY_TEMPLATES[path.name].items():
                if one(unit, "Slice", key) != placeholder:
                    findings.append(
                        violation(
                            "slice_budget_not_host_derived",
                            path,
                            f"{key} must use the exact host-capacity placeholder",
                        )
                    )
        elif path.name == "devcoordinator-background.slice":
            quota = one(unit, "Slice", "CPUQuota") or ""
            if not quota.endswith("%") or not quota[:-1].isdigit() or int(quota[:-1]) <= 0:
                findings.append(
                    violation(
                        "slice_budget_invalid",
                        path,
                        "rendered background CPUQuota must be positive host-derived percent",
                    )
                )
        if path.name == "devcoordinator-control.slice":
            memory_low = one(unit, "Slice", "MemoryLow")
            if memory_low is None:
                findings.append(
                    violation(
                        "slice_budget_missing",
                        path,
                        "control slice must reserve MemoryLow",
                    )
                )
            elif rendered and (not memory_low.isdigit() or int(memory_low) <= 0):
                findings.append(
                    violation(
                        "slice_budget_invalid",
                        path,
                        "rendered control MemoryLow must be positive bytes",
                    )
                )
        else:
            for key in ("MemoryHigh", "MemoryMax"):
                budget = one(unit, "Slice", key)
                if budget is None:
                    findings.append(
                        violation(
                            "slice_budget_missing",
                            path,
                            f"bounded data/background slice must declare {key}",
                        )
                    )
                elif rendered and (not budget.isdigit() or int(budget) <= 0):
                    findings.append(
                        violation(
                            "slice_budget_invalid",
                            path,
                            f"rendered {key} must be positive bytes",
                        )
                    )
    if path.name != "devcoordinator-projects.slice":
        for key, name in dependency_names(unit):
            if name.startswith("devcoordinator-project"):
                findings.append(
                    violation(
                        "control_project_dependency_forbidden",
                        path,
                        f"{key} must not reference the project data plane ({name})",
                    )
                )
    return findings


def validate_sysusers(path: Path) -> list[Violation]:
    findings: list[Violation] = []
    declared_users: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        return [violation("sysusers_parse_failed", path, str(error))]
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            fields = shlex.split(line)
        except ValueError as error:
            findings.append(
                violation("sysusers_parse_failed", path, f"line {number}: {error}")
            )
            continue
        if len(fields) >= 6 and fields[0] == "u":
            user = fields[1]
            if user in DEDICATED_USERS:
                declared_users.add(user)
                if fields[-2:] != ["/nonexistent", "/usr/sbin/nologin"]:
                    findings.append(
                        violation(
                            "service_identity_invalid",
                            path,
                            f"{user} must have no home and a nologin shell",
                        )
                    )
        elif len(fields) >= 2 and fields[0] == "g" and fields[1] == "devcoordinator-clients":
            findings.append(
                violation(
                    "local_access_group_forbidden",
                    path,
                    "devcoordinator-clients must not be declared; one-server IPC is not group-authorized",
                )
            )
        elif len(fields) == 3 and fields[0] == "m":
            findings.append(
                violation(
                    "local_access_group_forbidden",
                    path,
                    f"supplementary membership for {fields[1]} is forbidden",
                )
            )
    missing_users = sorted(DEDICATED_USERS - declared_users)
    if missing_users:
        findings.append(
            violation(
                "service_identity_invalid",
                path,
                "missing dedicated service users: " + ", ".join(missing_users),
            )
        )
    return findings


def validate_tmpfiles(path: Path) -> list[Violation]:
    findings: list[Violation] = []
    required = {
        "/opt/devcoordinator/releases": ("d", "0755", "root", "root"),
        "/etc/devcoordinator": ("d", "0755", "root", "root"),
        "/etc/devcoordinator/edge": ("d", "0700", "root", "root"),
        "/etc/devcoordinator/console-slots": ("d", "0755", "root", "root"),
        "/etc/devcoordinator/client-profiles.json": ("z", "0644", "root", "root"),
        "/etc/devcoordinator/browser-runtime-lock.json": ("z", "0644", "root", "root"),
        "/run/devcoordinator": ("d", "0755", "root", "root"),
        "/run/devcoordinator-maintenance": ("d", "0755", "root", "root"),
        "/var/lib/devcoordinator": ("d", "0711", "root", "root"),
        "/var/lib/devcoordinator-browser-lifecycle": ("d", "0755", "root", "root"),
        "/var/lib/devcoordinator-browser-lifecycle/browser-lifecycle.json": ("z", "0644", "root", "root"),
        "/var/lib/devcoordinator-browser-lifecycle/browser-lifecycle.json.lock": ("z", "0644", "root", "root"),
        "/var/lib/devcoordinator-bugs": ("d", "0777", "root", "root"),
        "/var/lib/devcoordinator-bugs/open": ("d", "0777", "root", "root"),
        "/var/lib/devcoordinator-efficiency": ("d", "0777", "root", "root"),
        "/var/lib/devcoordinator-efficiency/accounts": ("d", "0777", "root", "root"),
        "/var/lib/devcoordinator-edge": ("d", "0700", "devcoordinator-edge", "devcoordinator-edge"),
        "/var/lib/devcoordinator-observer": ("d", "0755", "devcoordinator-observer", "devcoordinator-observer"),
        "/var/lib/devcoordinator-observer/inventory.publication": ("z", "0644", "devcoordinator-observer", "devcoordinator-observer"),
        "/var/lib/devcoordinator-testd": ("d", "0700", "devcoordinator-testd", "devcoordinator-testd"),
        "/var/lib/devcoordinator-test-snapshots": ("d", "0711", "root", "root"),
        "/var/lib/devcoordinator-test-snapshot-catalog": ("d", "0700", "root", "root"),
        "/var/lib/devcoordinator-test-runs": ("d", "0711", "root", "root"),
        "/var/lib/devcoordinator-test-results": ("d", "0750", "root", "devcoordinator-testd"),
        "/var/lib/devcoordinator-test-fixtures": ("d", "0700", "root", "root"),
        "/run/devcoordinator/test-fixture-credentials": ("d", "0700", "root", "root"),
        "/run/devcoordinator-test-snapshotd": ("d", "0755", "root", "root"),
    }
    located: dict[str, tuple[str, str, str, str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        return [violation("tmpfiles_parse_failed", path, str(error))]
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            fields = shlex.split(line)
        except ValueError as error:
            findings.append(violation("tmpfiles_parse_failed", path, f"line {number}: {error}"))
            continue
        if len(fields) < 5 or fields[0] not in {"d", "z"} or not fields[1].startswith("/"):
            findings.append(violation("tmpfiles_parse_failed", path, f"line {number}: unsupported declaration"))
            continue
        located[fields[1]] = (fields[0], fields[2], fields[3], fields[4])
    for destination, contract in required.items():
        if located.get(destination) != contract:
            findings.append(
                violation(
                    "tmpfiles_contract_invalid",
                    path,
                    f"{destination} must be declared as {contract}",
                )
            )
    return findings


def validate_source_root(
    path: Path,
) -> tuple[list[Violation], dict[str, int | str] | None]:
    """Validate source structure and report metadata for diagnostics only."""

    findings: list[Violation] = []
    try:
        absolute = path.expanduser().absolute()
        info = absolute.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("source root must be one real directory")
        if absolute.resolve(strict=True) != absolute:
            raise ValueError("source root must already be canonical")
    except (OSError, ValueError) as error:
        return [Violation("source_root_invalid", str(path), str(error))], None
    identity: dict[str, int | str] = {
        "path": str(absolute),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }
    return findings, identity


def validate_topology(
    unit_dir: Path,
    *,
    release_digest: str | None = None,
) -> list[Violation]:
    findings: list[Violation] = []
    required = (
        set(SERVICE_CONTRACTS)
        | set(SOCKET_CONTRACTS)
        | set(SLICE_CONTRACTS)
        | EXTRA_FILES
    )
    for name in sorted(required):
        path = unit_dir / name
        if not path.is_file() or path.is_symlink():
            findings.append(
                violation(
                    "required_template_missing",
                    path,
                    "required availability template must be one regular file",
                )
            )

    for name, contract in SERVICE_CONTRACTS.items():
        path = unit_dir / name
        if path.is_file() and not path.is_symlink():
            findings.extend(
                validate_service(path, contract, release_digest=release_digest)
            )
    for name, contract in SOCKET_CONTRACTS.items():
        path = unit_dir / name
        if path.is_file() and not path.is_symlink():
            findings.extend(
                validate_socket(
                    path,
                    *contract,
                    rendered=release_digest is not None,
                )
            )
            expected_service, expected_listener, _fd_name = contract
            if expected_listener.startswith("/run/") and "/" in expected_listener[5:]:
                runtime_directory = expected_listener.split("/", 3)[2]
                service_path = unit_dir / expected_service
                if service_path.is_file() and not service_path.is_symlink():
                    service_unit = parse_unit(service_path)
                    service_runtime_directories = {
                        item
                        for declaration in values(
                            service_unit, "Service", "RuntimeDirectory"
                        )
                        for item in declaration.split()
                    }
                    if runtime_directory in service_runtime_directories:
                        findings.append(
                            violation(
                                "socket_runtime_directory_conflict",
                                service_path,
                                (
                                    f"the service must not lifecycle-manage /run/{runtime_directory}; "
                                    f"{name} owns that stable socket directory"
                                ),
                            )
                        )
    for name, weight in SLICE_CONTRACTS.items():
        path = unit_dir / name
        if path.is_file() and not path.is_symlink():
            findings.extend(
                validate_slice(path, weight, rendered=release_digest is not None)
            )
    if release_digest is not None:
        parsed_slices = {
            name: parse_unit(unit_dir / name)
            for name in SLICE_CONTRACTS
            if (unit_dir / name).is_file() and not (unit_dir / name).is_symlink()
        }
        try:
            control_low = int(
                one(parsed_slices["devcoordinator-control.slice"], "Slice", "MemoryLow")
                or "0"
            )
            background_high = int(
                one(parsed_slices["devcoordinator-background.slice"], "Slice", "MemoryHigh")
                or "0"
            )
            background_max = int(
                one(parsed_slices["devcoordinator-background.slice"], "Slice", "MemoryMax")
                or "0"
            )
            project_high = int(
                one(parsed_slices["devcoordinator-projects.slice"], "Slice", "MemoryHigh")
                or "0"
            )
            project_max = int(
                one(parsed_slices["devcoordinator-projects.slice"], "Slice", "MemoryMax")
                or "0"
            )
        except (KeyError, ValueError):
            pass
        else:
            if not (
                control_low > 0
                and 0 < background_high < background_max
                and 0 < project_high < project_max
            ):
                findings.append(
                    violation(
                        "slice_budget_contradiction",
                        unit_dir / "devcoordinator-projects.slice",
                        "rendered slice high/max reservations contradict one another",
                    )
                )
    sysusers = unit_dir / "devcoordinator-availability.sysusers.conf"
    if sysusers.is_file() and not sysusers.is_symlink():
        findings.extend(validate_sysusers(sysusers))
    tmpfiles = unit_dir / "devcoordinator-availability.tmpfiles.conf"
    if tmpfiles.is_file() and not tmpfiles.is_symlink():
        findings.extend(validate_tmpfiles(tmpfiles))

    # Ports 80 and 443 have exactly one owner in the staged production graph.
    for socket_path in sorted(unit_dir.glob("*.socket")):
        if socket_path.name in SOCKET_CONTRACTS or socket_path.is_symlink():
            continue
        try:
            unit = parse_unit(socket_path)
        except (OSError, UnicodeError, ValueError):
            continue
        listeners = values(unit, "Socket", "ListenStream")
        if any(listener in {"80", "443", "0.0.0.0:80", "0.0.0.0:443"} for listener in listeners):
            findings.append(
                violation(
                    "public_listener_owner_conflict",
                    socket_path,
                    "only devcoordinator-edge HTTP/HTTPS sockets may own ports 80/443",
                )
            )

    control = SLICE_CONTRACTS["devcoordinator-control.slice"]
    background = SLICE_CONTRACTS["devcoordinator-background.slice"]
    projects = SLICE_CONTRACTS["devcoordinator-projects.slice"]
    if not (
        isinstance(control, int)
        and isinstance(background, int)
        and isinstance(projects, int)
        and control > background > projects
    ):
        findings.append(
            Violation(
                "slice_priority_order_invalid",
                "<contract>",
                "control CPU/I/O weight must exceed background, then projects",
            )
        )
    return sorted(findings, key=lambda item: (item.file, item.code, item.detail))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit-dir", type=Path, default=DEFAULT_UNIT_DIR)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--release-digest")
    parser.add_argument("--source-root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.release_digest is not None and not RELEASE_DIGEST.fullmatch(args.release_digest):
        print("--release-digest must be one lowercase SHA-256 digest", file=sys.stderr)
        return 2
    unit_dir = args.unit_dir.expanduser().resolve()
    findings = validate_topology(unit_dir, release_digest=args.release_digest)
    source_identity = None
    if args.source_root is not None:
        source_findings, source_identity = validate_source_root(args.source_root)
        findings = sorted(
            [*findings, *source_findings],
            key=lambda item: (item.file, item.code, item.detail),
        )
    result = {
        "ok": not findings,
        "unit_dir": str(unit_dir),
        "checked_services": len(SERVICE_CONTRACTS),
        "checked_sockets": len(SOCKET_CONTRACTS),
        "checked_slices": len(SLICE_CONTRACTS),
        "source_identity": source_identity,
        "violations": [item.as_dict() for item in findings],
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif findings:
        for item in findings:
            print(f"{item.file}: {item.code}: {item.detail}", file=sys.stderr)
    else:
        print("availability topology templates ok")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
