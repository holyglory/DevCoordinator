#!/usr/bin/env python3
"""Credential-safe, listener-preserving DevCoordinator release activation.

The migration orchestrator deliberately records evidence without mutating
services.  This is the complementary root-only executor shipped inside every
immutable release.  It refuses to switch a Console publication unless the
cutover ledger is at ``candidate_verified``, every systemd credential has been
verified, both Console slots identify themselves, and the listener inode set
is stable.  Any failure after promotion performs the inverse publication and
slot handoff before returning an error.

Credential bytes are never included in stdout, JSON evidence, command-line
arguments, or logs.  The optional migration command reads the legacy private
environment file directly and atomically publishes systemd credential files.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import hashlib
import http.client
import importlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import threading
import time
from typing import Callable, Mapping, Sequence
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import uuid


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import orchestrate_availability_cutover as cutover  # noqa: E402
import browser_lcp_acceptance as browser_lcp  # noqa: E402
from devcoordinator.schema import SCHEMA_VERSION as COORDINATOR_SCHEMA_VERSION  # noqa: E402
from server_wide_installer_fence import (  # noqa: E402
    InstallerFenceError,
    InstallerFenceHandle,
    acquire_transaction_fence,
)


MIB = 1024 * 1024
MAX_SECRET_BYTES = 64 * 1024
MAX_JSON_BYTES = 2 * MIB
MAX_AUTHORITY_LOGICAL_BYTES = 512 * MIB
DNS_NAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
OIDC_ISSUER = "https://accounts.google.com"
OIDC_DISCOVERY = f"{OIDC_ISSUER}/.well-known/openid-configuration"
IMMUTABLE_RELEASE_ROOT = Path("/opt/devcoordinator/releases")
CREDENTIAL_PREFLIGHT_KIND = "devcoordinator-credential-preflight-attestation"
CREDENTIAL_MIGRATION_KIND = "devcoordinator-credential-migration-attestation"
CREDENTIAL_MIGRATION_FIELDS = {
    "publication_authority_uid",
    "legacy_source_uid",
    "legacy_sources",
    "credentials",
    "tls_sources",
    "created_at",
}
CANDIDATE_PREPARATION_KIND = "devcoordinator-candidate-preparation-attestation"
FIRST_ADOPTION_PREFLIGHT_KIND = "devcoordinator-first-adoption-handoff-preflight"
FIRST_ADOPTION_JOURNAL_KIND = "devcoordinator-first-adoption-handoff-journal"
API_HANDOFF_JOURNAL_KIND = "devcoordinator-api-handoff-journal"
API_HANDOFF_PROFILE_PATH = Path(
    "/etc/devcoordinator/api-handoff-profile.json"
)
LEGACY_API_SERVICE_UNIT = "dev-coordinator.service"
FIRST_ADOPTION_TRANSACTION_KIND = "devcoordinator-first-adoption-transaction"
FIRST_ADOPTION_ATTESTATION_KIND = "devcoordinator-first-adoption-attestation"
FIRST_ADOPTION_REQUEST_KIND = "devcoordinator-first-adoption-request"
FIRST_ADOPTION_MINIMUM_HANDOFF_REMAINING_SECONDS = 300
FIRST_ADOPTION_MANIFEST_TEMPLATE_KIND = (
    "devcoordinator-first-adoption-manifest-template"
)
FIRST_ADOPTION_GRAPH_KIND = "devcoordinator-first-adoption-prepared-graph"
FIRST_ADOPTION_GRAPH_JOURNAL_KIND = (
    "devcoordinator-first-adoption-graph-install-journal"
)
FIRST_ADOPTION_FLEET_JOURNAL_KIND = (
    "devcoordinator-first-adoption-fleet-transaction"
)
FIRST_ADOPTION_FLEET_SETUP_CATALOG_MODE = (
    "availability-bootstrap-setup-catalog"
)
CONSOLE_STATE_MIGRATION_JOURNAL_KIND = (
    "devcoordinator-console-state-migration-journal"
)
PROFILE_PUBLICATION_JOURNAL_KIND = (
    "devcoordinator-protected-profile-publication-journal"
)
AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND = (
    "devcoordinator-authority-maintenance-release-journal"
)
AUTHORITY_ADOPTION_JOURNAL_KIND = "devcoordinator-authority-adoption-journal"
FIRST_ADOPTION_ROLLBACK_PLAN_KIND = "devcoordinator-first-adoption-rollback-plan"
FIRST_ADOPTION_ROLLBACK_RESULT_KIND = "devcoordinator-first-adoption-rollback-result"
LIVE_ROLLBACK_REHEARSAL_JOURNAL_KIND = (
    "devcoordinator-live-rollback-rehearsal-journal"
)
BROWSER_LCP_CUTOVER_JOURNAL_KIND = (
    "devcoordinator-browser-lcp-cutover-consumption-journal"
)
BROWSER_LCP_CUTOVER_PHASES = (
    "produce_intent",
    "attestation_verified",
    "consumption_intent",
    "complete",
)
ACTIVATION_SWITCH_JOURNAL_KIND = (
    "devcoordinator-console-activation-switch-journal"
)
ACTIVATION_SWITCH_PHASES = (
    "prepared",
    "promotion_intent",
    "promoted",
    "publication_intent",
    "published",
    "complete",
)
ACTIVATION_READY_FOR_BROWSER_KIND = (
    "devcoordinator-activation-ready-for-browser-attestation"
)
ACTIVATION_READY_FOR_BROWSER_FIELDS = (
    cutover.ACTIVATION_FIELDS
    - {"browser_lcp_attestation_sha256", "browser_lcp_consumption_sha256"}
)
LIVE_ROLLBACK_REHEARSAL_PHASES = (
    "planned",
    "rollback_slot_intent",
    "rollback_slot_ready",
    "rollback_publication_intent",
    "rollback_ready",
    "reactivation_slot_intent",
    "reactivation_slot_ready",
    "reactivation_publication_intent",
    "reactivated",
    "complete",
    "recovery_switching",
    "recovered",
    "recovery_incomplete",
    "attempt_abandoned",
)
FIRST_ADOPTION_STEPS = (
    "validated",
    "graph_prepared",
    "console_state_migrated",
    "legacy_writer_guarded",
    "storage_split",
    "legacy_writer_retired",
    "snapshotd_ready",
    "authority_test_plane_ready",
    "api_bootstrap_profile_ready",
    "api_handoff_ready",
    "api_final_profile_ready",
    "api_ready",
    "maintenance_released",
    "profile_inventory_ready",
    "project_isolation_ready",
    "inventory_ready",
    "fleet_ready",
    "console_ready",
    "public_handoff",
    "candidate_recorded",
    "activation_recorded",
    "legacy_writer_committed",
    "complete",
)
FIRST_ADOPTION_ROLLBACK_STEPS = (
    "maintenance",
    "notifications",
    "fleet",
    "public",
    "cutover_state",
    "profiles",
    "api",
    "graph",
    "legacy_writer",
    "console_state",
    "authority",
)
CANONICAL_MAINTENANCE_ROOT = Path("/run/devcoordinator-maintenance")
AUTHORITY_ADOPTION_KIND = "devcoordinator-authority-first-adoption"
RETAINED_INVENTORY_READINESS_KIND = (
    "devcoordinator-retained-inventory-readiness"
)
RETAINED_ROUTE_READINESS_KIND = "devcoordinator-retained-route-readiness"
CONSOLE_STATE_MIGRATION_KIND = "devcoordinator-console-state-migration"
EDGE_CERTBOT_HOOK_KIND = "devcoordinator-edge-certbot-hook-migration"
HOST_PREFLIGHT_KIND = "devcoordinator-universal-test-host-preflight-attestation"
BACKGROUND_CONFIG_KIND = "devcoordinator-background-config-transaction"
PROJECT_ISOLATION_VERIFICATION_KIND = "project-runtime-isolation-verification"
HOST_PREFLIGHT_FIELDS = frozenset(
    {
        "ok",
        "blocking",
        "release_root",
        "release_digest",
        "executor",
        "executor_sha256",
        "script",
        "script_sha256",
        "observed_at",
        "host_boot_id",
        "systemd_version",
        "checks",
    }
)
HOST_PREFLIGHT_MAX_AGE_SECONDS = 300
LEGACY_UNITS = ("devcoordinator-broker.service", "devops-console.service")
DEFAULT_CREDENTIALS = {
    "session-secret": Path("/etc/devcoordinator/edge/session-secret"),
    "oidc-client-id": Path("/etc/devcoordinator/edge/google-client-id"),
    "oidc-client-secret": Path("/etc/devcoordinator/edge/google-client-secret"),
    "tls-cert": Path("/etc/letsencrypt/live/vr.ae/fullchain.pem"),
    "tls-key": Path("/etc/letsencrypt/live/vr.ae/privkey.pem"),
}
SOCKET_PATHS = {
    "authority": Path("/run/devcoordinator-authority.sock"),
    "testd": Path("/run/devcoordinator-testd/testd.sock"),
    "snapshotd": Path("/run/devcoordinator-test-snapshotd/snapshot.sock"),
}
SOCKET_PORTS = {"edge-http": 80, "edge-https": 443, "api": 29876}
SYSTEMD_UNIT_ROOT = Path("/etc/systemd/system")
SYSUSERS_ROOT = Path("/etc/sysusers.d")
TMPFILES_ROOT = Path("/etc/tmpfiles.d")
CONSOLE_SLOT_ROOT = Path("/etc/devcoordinator/console-slots")
CONSOLE_CONFIG_PATH = Path("/etc/devcoordinator/console.env")
BACKGROUND_CONFIG_ROOT = Path("/etc/devcoordinator")
CERTBOT_DEPLOY_HOOK_ROOT = Path("/etc/letsencrypt/renewal-hooks/deploy")
LEGACY_CONSOLE_STATE_FILES = {
    "routes.json": 2 * MIB,
    "upstream-auth.json": 2 * MIB,
    "access-control.json": 2 * MIB,
    "telegram-control.json": 16 * MIB,
}
LEGACY_EDGE_IDENTITY_FILES = {
    "identity-assertion-private.pem": 64 * 1024,
    "identity-assertion-public.json": 64 * 1024,
}
CONSOLE_PUBLIC_CONFIG_KEYS = {
    "DOMAIN",
    "CONSOLE_SUBDOMAIN",
    "SESSION_TTL_HOURS",
    "SESSION_COOKIE_NAME",
    "OIDC_ISSUER",
    "ALLOWED_EMAILS",
    "METRICS_INTERVAL_MS",
    "LIFECYCLE_ENABLED",
    "LOG_LEVEL",
}
XTABLES_BINARIES = {
    "iptables": Path("/usr/sbin/iptables"),
    "ip6tables": Path("/usr/sbin/ip6tables"),
    "iptables-save": Path("/usr/sbin/iptables-save"),
    "iptables-restore": Path("/usr/sbin/iptables-restore"),
    "ip6tables-save": Path("/usr/sbin/ip6tables-save"),
    "ip6tables-restore": Path("/usr/sbin/ip6tables-restore"),
}


class PowerLossSimulation(BaseException):
    """Test-only abrupt-termination signal which deliberately bypasses cleanup.

    Production code never raises this type.  Focused replay tests inject it at
    mutation/journal boundaries to exercise the same durable state a SIGKILL
    would leave behind.
    """

    simulated_power_loss = True
HANDOFF_CHAIN = "DC_EDGE_HANDOFF"
API_HANDOFF_CHAIN = "DC_API_HANDOFF"
HANDOFF_FILES = (
    "devcoordinator-edge-handoff.service",
    "devcoordinator-edge-handoff-http.socket",
    "devcoordinator-edge-handoff-https.socket",
)
HANDOFF_SOCKET_UNITS = (
    "devcoordinator-edge-handoff-http.socket",
    "devcoordinator-edge-handoff-https.socket",
)
HANDOFF_SERVICE_UNIT = "devcoordinator-edge-handoff.service"
API_HANDOFF_FILES = (
    "devcoordinator-api-handoff.service",
    "devcoordinator-api-handoff.socket",
)
API_HANDOFF_SOCKET_UNIT = "devcoordinator-api-handoff.socket"
API_HANDOFF_SERVICE_UNIT = "devcoordinator-api-handoff.service"
FINAL_EDGE_UNITS = (
    "devcoordinator-edge-publication.socket",
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge.service",
)
TOPOLOGY_FILES = (
    "devcoordinator-api.service",
    "devcoordinator-api.socket",
    "devcoordinator-authority.service",
    "devcoordinator-authority.socket",
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
)
SOCKET_UNITS = (
    "devcoordinator-edge-http.socket",
    "devcoordinator-edge-https.socket",
    "devcoordinator-edge-publication.socket",
    "devcoordinator-api.socket",
    "devcoordinator-authority.socket",
    "devcoordinator-testd.socket",
    "devcoordinator-test-snapshotd.socket",
)
SERVICE_UNITS = (
    "devcoordinator-edge.service",
    "devcoordinator-api.service",
    "devcoordinator-authority.service",
    "devcoordinator-observer.service",
    "devcoordinator-notifications.service",
    "devcoordinator-testd.service",
    "devcoordinator-test-snapshotd.service",
)
FIRST_ADOPTION_INSTALLER_OWNER_KIND = (
    cutover.FIRST_ADOPTION_INSTALLER_CLAIM_KIND
)
LEGACY_BROKER_SERVICE_UNIT = "devcoordinator-broker.service"
class ActivationError(RuntimeError):
    pass


class BrowserAcceptancePending(ActivationError):
    """Healthy publication is live, but browser acceptance is incomplete."""


def _load_topology_checker():
    source = ROOT / "scripts/check_availability_topology.py"
    spec = importlib.util.spec_from_file_location(
        "devcoordinator_activation_topology", source
    )
    if spec is None or spec.loader is None:
        raise ActivationError("availability topology checker is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _host_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    try:
        value = path.read_text(encoding="ascii").strip().lower()
        parsed = uuid.UUID(value)
    except (OSError, UnicodeError, ValueError, AttributeError) as error:
        raise ActivationError("host boot identity is unavailable") from error
    if str(parsed) != value:
        raise ActivationError("host boot identity is invalid")
    return value


def verify_host_preflight(
    document: Mapping[str, object],
    *,
    release: Path,
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    now: datetime | None = None,
) -> dict[str, object]:
    verified = cutover.verify_seal(
        document,
        kind=HOST_PREFLIGHT_KIND,
        fields=HOST_PREFLIGHT_FIELDS,
    )
    expected_script = (
        release
        / "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_preflight.py"
    )
    executor = Path("/usr/bin/python3")
    if (
        verified["ok"] is not True
        or verified["blocking"] is not True
        or verified["release_root"] != str(IMMUTABLE_RELEASE_ROOT)
        or verified["release_digest"] != release.name
        or verified["script"] != str(expected_script)
        or verified["executor"] != str(executor)
        or verified["script_sha256"] != _sha256_file(expected_script)
        or verified["executor_sha256"] != _sha256_file(executor.resolve(strict=True))
        or verified["host_boot_id"] != _host_boot_id(boot_id_path)
        or type(verified["systemd_version"]) is not int
        or int(verified["systemd_version"]) < 249
    ):
        raise ActivationError("universal-test host preflight release or host binding is invalid")
    observed_text = verified["observed_at"]
    try:
        if not isinstance(observed_text, str) or not observed_text.endswith("Z"):
            raise ValueError("not canonical UTC")
        observed = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
        if observed.isoformat(timespec="milliseconds").replace("+00:00", "Z") != observed_text:
            raise ValueError("not canonical milliseconds")
    except ValueError as error:
        raise ActivationError("universal-test host preflight timestamp is invalid") from error
    current = now or datetime.now(timezone.utc)
    age = (current - observed).total_seconds()
    if age < -30 or age > HOST_PREFLIGHT_MAX_AGE_SECONDS:
        raise ActivationError("universal-test host preflight is stale")
    checks = verified["checks"]
    required = {
        "root-authority",
        "linux-host",
        "cgroup-v2",
        "systemd-manager",
        "systemd-version",
        "private-loopback-and-credential",
        "network-namespace-path",
        "host-loopback-host-127",
        "host-loopback-nonloopback-denied",
        "private-loopback-host-denied",
    }
    if not isinstance(checks, list) or not 1 <= len(checks) <= 32:
        raise ActivationError("universal-test host preflight checks are invalid")
    identifiers: set[str] = set()
    for check in checks:
        if (
            not isinstance(check, Mapping)
            or set(check) != {"id", "ok", "detail"}
            or not isinstance(check.get("id"), str)
            or not isinstance(check.get("detail"), str)
            or not 1 <= len(str(check["detail"])) <= 512
            or check.get("ok") is not True
            or str(check["id"]) in identifiers
        ):
            raise ActivationError("universal-test host preflight check contract is invalid")
        identifiers.add(str(check["id"]))
    if not required.issubset(identifiers):
        raise ActivationError("universal-test host preflight omitted a required capability")
    return verified


def run_host_preflight(
    *,
    release: Path,
    runner: "CommandRunner",
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
) -> dict[str, object]:
    wrapper = release / "bin/devcoordinator-test-preflight"
    info = wrapper.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o555
    ):
        raise ActivationError("immutable universal-test host preflight wrapper is unsafe")
    document = runner.run_json([str(wrapper), "--json"])
    return verify_host_preflight(
        document,
        release=release,
        boot_id_path=boot_id_path,
    )


def _absolute(path: Path, label: str) -> Path:
    path = path.expanduser().absolute()
    if not path.is_absolute():
        raise ActivationError(f"{label} must be absolute")
    return path


def _bounded_regular(
    path: Path,
    *,
    label: str,
    expected_uid: int,
    allow_symlink: bool = False,
    private: bool = True,
    enforce_permissions: bool = True,
    maximum: int = MAX_SECRET_BYTES,
) -> tuple[Path, os.stat_result]:
    path = _absolute(path, label)
    try:
        lexical = path.lstat()
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as error:
        raise ActivationError(f"{label} is unavailable") from error
    if stat.S_ISLNK(lexical.st_mode) and not allow_symlink:
        raise ActivationError(f"{label} must not be a symlink")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid:
        raise ActivationError(f"{label} must be one regular file owned by UID {expected_uid}")
    mode = stat.S_IMODE(info.st_mode)
    if enforce_permissions and (mode & 0o022 or (private and mode & 0o077)):
        raise ActivationError(f"{label} permissions are unsafe")
    if info.st_size <= 0 or info.st_size > maximum:
        raise ActivationError(f"{label} size is invalid")
    if allow_symlink:
        system_root_uid = Path("/").stat().st_uid
        current = Path("/")
        for part in resolved.parts[1:-1]:
            current /= part
            ancestor = current.stat()
            ancestor_mode = stat.S_IMODE(ancestor.st_mode)
            sticky_root = (
                ancestor.st_uid == system_root_uid
                and bool(ancestor_mode & stat.S_ISVTX)
            )
            if (
                ancestor.st_uid not in {system_root_uid, expected_uid}
                or (ancestor_mode & 0o022 and not sticky_root)
            ):
                raise ActivationError(f"{label} has an unsafe resolved ancestor")
    elif resolved != path:
        raise ActivationError(f"{label} must already be canonical")
    return resolved, info


def _read_secret_with_identity(
    path: Path,
    *,
    label: str,
    expected_uid: int,
    maximum: int = MAX_SECRET_BYTES,
) -> tuple[bytes, dict[str, object]]:
    path = _absolute(path, label)
    resolved, before = _bounded_regular(
        path,
        label=label,
        expected_uid=expected_uid,
        maximum=maximum,
    )
    payload = resolved.read_bytes()
    try:
        lexical_after = path.lstat()
        resolved_after = path.resolve(strict=True)
        after = resolved_after.stat()
    except OSError as error:
        raise ActivationError(f"{label} changed while it was read") from error
    identity_fields = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        stat.S_ISLNK(lexical_after.st_mode)
        or resolved_after != resolved
        or any(getattr(before, field) != getattr(after, field) for field in identity_fields)
    ):
        raise ActivationError(f"{label} changed while it was read")
    return payload, {
        "path": str(path),
        "resolved_path": str(resolved),
        "device": int(after.st_dev),
        "inode": int(after.st_ino),
        "size": int(after.st_size),
        "owner_uid": int(after.st_uid),
        "owner_gid": int(after.st_gid),
        "mode": f"{stat.S_IMODE(after.st_mode):04o}",
        "sha256": _sha256_bytes(payload),
    }


def _read_secret(
    path: Path,
    *,
    label: str,
    expected_uid: int,
    maximum: int = MAX_SECRET_BYTES,
) -> bytes:
    payload, _identity = _read_secret_with_identity(
        path,
        label=label,
        expected_uid=expected_uid,
        maximum=maximum,
    )
    return payload


def _parse_private_env_payload(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ActivationError("legacy Console environment is not UTF-8") from error
    result: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ActivationError(f"legacy Console environment line {number} is invalid")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", name) is None:
            raise ActivationError(f"legacy Console environment line {number} has an invalid key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ActivationError(f"legacy Console environment {name} is invalid")
        result[name] = value
    return result


def _parse_private_env(path: Path, *, expected_uid: int) -> dict[str, str]:
    payload = _read_secret(
        path,
        label="legacy Console environment",
        expected_uid=expected_uid,
        maximum=256 * 1024,
    )
    return _parse_private_env_payload(payload)


def _validate_secret_values(values: Mapping[str, bytes]) -> None:
    try:
        session = values["session-secret"].decode("ascii").strip()
        client_id = values["oidc-client-id"].decode("utf-8").strip()
        client_secret = values["oidc-client-secret"].decode("utf-8").strip()
    except (KeyError, UnicodeDecodeError) as error:
        raise ActivationError("credential values are incomplete or invalid") from error
    if re.fullmatch(r"[0-9a-fA-F]{64}", session) is None:
        raise ActivationError("session credential has an invalid format")
    if re.fullmatch(r"[A-Za-z0-9._-]{8,240}\.apps\.googleusercontent\.com", client_id) is None:
        raise ActivationError("OIDC client ID has an invalid format")
    if not 8 <= len(client_secret.encode("utf-8")) <= 512 or client_secret != client_secret.strip():
        raise ActivationError("OIDC client secret has an invalid format")


def _private_directory(path: Path, *, expected_uid: int) -> Path:
    path = _absolute(path, "private directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ActivationError("private directory ownership or mode is unsafe")
    return path


def _atomic_private(path: Path, payload: bytes, *, expected_uid: int) -> None:
    parent = _private_directory(path.parent, expected_uid=expected_uid)
    temporary = parent / f".{path.name}.{uuid.uuid4().hex}.partial"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _write_private_journal(
    path: Path,
    *,
    kind: str,
    payload: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    document = cutover.seal(kind, dict(payload))
    _atomic_private(path, _canonical(document) + b"\n", expected_uid=expected_uid)
    return document


def _load_private_journal(
    path: Path,
    *,
    kind: str,
    expected_uid: int,
) -> dict[str, object] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    value = cutover.read_private_json(path, uid=expected_uid)
    if not isinstance(value, Mapping) or value.get("kind") != kind:
        raise ActivationError(f"{kind} journal kind is invalid")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if value.get("document_sha256") != _sha256_bytes(_canonical(unsigned)):
        raise ActivationError(f"{kind} journal digest is invalid")
    return dict(value)


def _browser_cutover_paths(
    journal: Path, *, operation_id: str
) -> tuple[Path, Path]:
    """Return the only evidence paths accepted for one cutover consumption."""

    journal = Path(os.path.abspath(journal.expanduser()))
    return (
        journal.with_name(f"browser-lcp-{operation_id}.attestation.json"),
        journal.with_name(f"browser-lcp-{operation_id}.consumption.json"),
    )


def _browser_input_binding(
    *,
    runtime_lock: Path,
    storage_state: Path,
    signing_key: Path,
    console_url: str,
    tests_url: str,
    expected_uid: int,
) -> dict[str, object]:
    """Seal every caller-controlled browser input before producing evidence."""

    canonical_console, canonical_tests, _health = browser_lcp._validate_https_routes(
        console_url, tests_url
    )
    bound: dict[str, object] = {
        "console_url": canonical_console,
        "tests_url": canonical_tests,
    }
    for label, path, maximum in (
        ("runtime_lock", runtime_lock, browser_lcp.MAX_PRIVATE_JSON_BYTES),
        ("storage_state", storage_state, browser_lcp.MAX_STORAGE_STATE_BYTES),
        ("signing_key", signing_key, 64),
    ):
        canonical = browser_lcp._absolute(path, f"browser {label}")
        payload = browser_lcp._read_private_bytes(
            canonical,
            uid=expected_uid,
            label=f"browser {label}",
            maximum=maximum,
        )
        bound[label] = str(canonical)
        bound[f"{label}_sha256"] = _sha256_bytes(payload)
    return bound


def bind_browser_lcp_acceptance(
    *,
    release: Path,
    operation_id: str,
    publication_switch: Mapping[str, object],
    runtime_lock: Path,
    storage_state: Path,
    signing_key: Path,
    journal: Path,
    attestation: Path,
    consumption: Path,
    expected_uid: int = 0,
    expected_gid: int = 0,
    console_url: str = browser_lcp.DEFAULT_CONSOLE_URL,
    tests_url: str = browser_lcp.DEFAULT_TESTS_URL,
    producer: Callable[..., Mapping[str, object]] = browser_lcp.produce_attestation,
    verifier: Callable[..., Mapping[str, object]] = browser_lcp.verify_attestation_file,
    consumer: Callable[..., Mapping[str, object]] = browser_lcp.consume_attestation,
    consumption_validator: Callable[..., Mapping[str, object]] = (
        browser_lcp.validate_consumption_document
    ),
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Produce and consume release-bound LCP evidence exactly once.

    The journal is intentionally independent of publication rollback.  It is
    created only after the candidate is healthy and live; any browser failure
    leaves that healthy publication in place while activation/retention remain
    incomplete.  Recovery verifies an existing one-shot marker and never
    invokes the consumer twice.
    """

    try:
        operation_id = str(uuid.UUID(str(operation_id)))
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError("browser acceptance operation ID is invalid") from error
    release = _absolute(release, "browser acceptance release")
    if release.parent != IMMUTABLE_RELEASE_ROOT:
        raise ActivationError("browser acceptance release root is invalid")
    try:
        publication = cutover._publication_switch(
            publication_switch, expected_release=release.name
        )
    except cutover.CutoverError as error:
        raise ActivationError("browser acceptance publication binding is invalid") from error
    journal = Path(os.path.abspath(journal.expanduser()))
    expected_attestation, expected_consumption = _browser_cutover_paths(
        journal, operation_id=operation_id
    )
    if (
        Path(os.path.abspath(attestation.expanduser())) != expected_attestation
        or Path(os.path.abspath(consumption.expanduser())) != expected_consumption
    ):
        raise ActivationError(
            "browser acceptance evidence paths are not deterministic for the cutover"
        )
    _private_directory(journal.parent, expected_uid=expected_uid)

    try:
        input_binding = _browser_input_binding(
            runtime_lock=runtime_lock,
            storage_state=storage_state,
            signing_key=signing_key,
            console_url=console_url,
            tests_url=tests_url,
            expected_uid=expected_uid,
        )
    except browser_lcp.BrowserLcpAcceptanceError as error:
        raise ActivationError("browser acceptance input binding is invalid") from error

    immutable = {
        "operation_id": operation_id,
        "release": str(release),
        "release_digest": release.name,
        "publication_generation": publication["generation"],
        "publication_payload_sha256": publication["payload_sha256"],
        "attestation": str(expected_attestation),
        "consumption": str(expected_consumption),
        **input_binding,
    }

    def persist(phase: str, **updates: object) -> dict[str, object]:
        if phase not in BROWSER_LCP_CUTOVER_PHASES:
            raise ActivationError("browser acceptance journal phase is invalid")
        prior = _load_private_journal(
            journal,
            kind=BROWSER_LCP_CUTOVER_JOURNAL_KIND,
            expected_uid=expected_uid,
        )
        created_at = prior.get("created_at") if prior is not None else _now()
        payload = {
            **immutable,
            "phase": phase,
            "attestation_sha256": (
                prior.get("attestation_sha256") if prior is not None else None
            ),
            "consumption_sha256": (
                prior.get("consumption_sha256") if prior is not None else None
            ),
            "created_at": created_at,
            "updated_at": _now(),
            **updates,
        }
        return _write_private_journal(
            journal,
            kind=BROWSER_LCP_CUTOVER_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )

    recorded = _load_private_journal(
        journal,
        kind=BROWSER_LCP_CUTOVER_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if recorded is None:
        recorded = persist("produce_intent")
        if failpoint is not None:
            failpoint("produce_intent")
    expected_fields = {
        "schema_version",
        "kind",
        "document_sha256",
        *immutable,
        "phase",
        "attestation_sha256",
        "consumption_sha256",
        "created_at",
        "updated_at",
    }
    if (
        set(recorded) != expected_fields
        or any(recorded.get(key) != value for key, value in immutable.items())
        or recorded.get("phase") not in BROWSER_LCP_CUTOVER_PHASES
    ):
        raise ActivationError("browser acceptance journal belongs to another cutover")

    verify_arguments = {
        "release": release,
        "immutable_root": release.parent,
        "runtime_lock_path": runtime_lock,
        "signing_key_path": signing_key,
        "expected_operation_id": operation_id,
        "expected_console_url": console_url,
        "expected_tests_url": tests_url,
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
    }
    if expected_attestation.exists() or expected_attestation.is_symlink():
        verified = dict(verifier(expected_attestation, **verify_arguments))
    else:
        if recorded["phase"] != "produce_intent":
            raise ActivationError("browser acceptance attestation disappeared after verification")
        try:
            producer(
                release=release,
                immutable_root=release.parent,
                runtime_lock_path=runtime_lock,
                storage_state_path=storage_state,
                signing_key_path=signing_key,
                output=expected_attestation,
                operation_id=operation_id,
                console_url=console_url,
                tests_url=tests_url,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            verified = dict(verifier(expected_attestation, **verify_arguments))
        except browser_lcp.BrowserLcpAcceptanceError as error:
            raise BrowserAcceptancePending(
                "browser acceptance failed; the healthy candidate remains live and unretained"
            ) from error
    verified_health = verified.get("health")
    if (
        not isinstance(verified_health, Mapping)
        or verified_health.get("generation") != publication["generation"]
    ):
        raise ActivationError("browser acceptance binds another publication generation")
    attestation_sha256 = str(verified.get("document_sha256", ""))
    if re.fullmatch(r"[0-9a-f]{64}", attestation_sha256) is None:
        raise ActivationError("browser acceptance attestation digest is invalid")
    if recorded["phase"] == "produce_intent":
        recorded = persist(
            "attestation_verified", attestation_sha256=attestation_sha256
        )
        if failpoint is not None:
            failpoint("attestation_verified")
    elif recorded.get("attestation_sha256") != attestation_sha256:
        raise ActivationError("browser acceptance attestation changed during recovery")

    if recorded["phase"] == "attestation_verified":
        recorded = persist(
            "consumption_intent", attestation_sha256=attestation_sha256
        )
        if failpoint is not None:
            failpoint("consumption_intent")
    if expected_consumption.exists() or expected_consumption.is_symlink():
        marker = cutover.read_private_json(expected_consumption, uid=expected_uid)
        try:
            consumed = consumption_validator(
                marker,
                attestation=verified,
                expected_consumer_operation_id=operation_id,
                expected_release_digest=release.name,
            )
        except browser_lcp.BrowserLcpAcceptanceError as error:
            raise ActivationError("browser acceptance consumption marker is invalid") from error
    else:
        if recorded["phase"] != "consumption_intent":
            raise ActivationError("browser acceptance consumption marker disappeared")
        try:
            consumed = dict(
                consumer(
                    expected_attestation,
                    consumption_output=expected_consumption,
                    consumer_operation_id=operation_id,
                    **verify_arguments,
                )
            )
        except browser_lcp.BrowserLcpAcceptanceError as error:
            raise BrowserAcceptancePending(
                "browser acceptance consumption failed; the healthy candidate remains live and unretained"
            ) from error
    consumption_sha256 = str(consumed.get("document_sha256", ""))
    if (
        re.fullmatch(r"[0-9a-f]{64}", consumption_sha256) is None
        or consumption_sha256 == attestation_sha256
    ):
        raise ActivationError("browser acceptance consumption digest is invalid")
    was_complete = recorded["phase"] == "complete"
    if not was_complete:
        recorded = persist(
            "complete",
            attestation_sha256=attestation_sha256,
            consumption_sha256=consumption_sha256,
        )
        if failpoint is not None:
            failpoint("complete")
    elif (
        recorded.get("attestation_sha256") != attestation_sha256
        or recorded.get("consumption_sha256") != consumption_sha256
    ):
        raise ActivationError("browser acceptance completed journal changed")
    return {
        "browser_lcp_attestation_sha256": attestation_sha256,
        "browser_lcp_consumption_sha256": consumption_sha256,
        "journal_sha256": recorded["document_sha256"],
        "replayed": was_complete,
    }


def finalize_browser_bound_activation(
    *,
    state: Mapping[str, object],
    pending_activation: Mapping[str, object],
    browser_binding: Mapping[str, object],
) -> dict[str, object]:
    """Seal the only ledger-eligible activation from health and browser proof."""

    pending = cutover.verify_seal(
        pending_activation,
        kind=ACTIVATION_READY_FOR_BROWSER_KIND,
        fields=ACTIVATION_READY_FOR_BROWSER_FIELDS,
    )
    if not {
        "browser_lcp_attestation_sha256",
        "browser_lcp_consumption_sha256",
    }.issubset(browser_binding):
        raise ActivationError("browser acceptance binding fields are incomplete")
    values = {
        key: value
        for key, value in pending.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    for key in (
        "browser_lcp_attestation_sha256",
        "browser_lcp_consumption_sha256",
    ):
        value = browser_binding.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ActivationError("browser acceptance binding digest is invalid")
        values[key] = value
    activation = cutover.seal(cutover.ACTIVATION_KIND, values)
    cutover.transition(state, evidence_kind="activation", evidence=activation)
    return activation


def _exact_regular_file(
    path: Path,
    *,
    sha256: str,
    mode: int,
    owner_uid: int,
    owner_gid: int | None = None,
) -> bool:
    if not path.exists() or path.is_symlink():
        return False
    info = path.lstat()
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == owner_uid
        and (owner_gid is None or info.st_gid == owner_gid)
        and stat.S_IMODE(info.st_mode) == mode
        and _sha256_file(path) == sha256
    )


def _credential_source_values(
    environment: Mapping[str, str],
    *,
    destinations: Mapping[str, Path],
    expected_uid: int,
) -> dict[str, bytes]:
    """Resolve one complete credential set from either legacy or current layout.

    The first availability adoption externalizes credentials from ``console.env``.
    A later clean adoption must therefore reuse the already-published private
    credential files instead of requiring secrets to be copied back into the
    public environment.  Mixed layouts remain contradictory and fail before a
    destination is changed.
    """

    bindings = {
        "session-secret": "SESSION_SECRET",
        "oidc-client-id": "GOOGLE_CLIENT_ID",
        "oidc-client-secret": "GOOGLE_CLIENT_SECRET",
    }
    present = {key for key in bindings.values() if environment.get(key, "")}
    if present and present != set(bindings.values()):
        raise ActivationError(
            "legacy Console environment credential fields are incomplete"
        )
    if present:
        values = {
            name: environment[key].encode("utf-8") + b"\n"
            for name, key in bindings.items()
        }
    else:
        values = {
            name: _read_secret(
                _absolute(destinations[name], name),
                label=f"existing {name}",
                expected_uid=expected_uid,
            )
            for name in bindings
        }
    _validate_secret_values(values)
    return values


def migrate_credentials(
    *,
    legacy_env: Path,
    legacy_source_uid: int,
    destinations: Mapping[str, Path] = DEFAULT_CREDENTIALS,
    rollback_directory: Path,
    tls_cert: Path | None = None,
    tls_key: Path | None = None,
    expected_uid: int = 0,
) -> dict[str, object]:
    """Copy legacy secrets without ever serializing their values."""

    if os.geteuid() != expected_uid:
        raise ActivationError("credential migration must run as the authority UID")
    if (
        type(legacy_source_uid) is not int
        or legacy_source_uid < 0
        or type(expected_uid) is not int
        or expected_uid < 0
    ):
        raise ActivationError("legacy credential source UID is invalid")
    legacy_payload, legacy_identity = _read_secret_with_identity(
        legacy_env,
        label="legacy Console environment",
        expected_uid=legacy_source_uid,
        maximum=256 * 1024,
    )
    env = _parse_private_env_payload(legacy_payload)
    values = _credential_source_values(
        env,
        destinations=destinations,
        expected_uid=expected_uid,
    )
    _validate_secret_values(values)
    tls_sources = {
        "tls-cert": _absolute(
            tls_cert or destinations["tls-cert"], "tls-cert"
        ),
        "tls-key": _absolute(
            tls_key or destinations["tls-key"], "tls-key"
        ),
    }
    for name, source in tls_sources.items():
        _bounded_regular(
            source,
            label=name,
            expected_uid=expected_uid,
            allow_symlink=True,
            private=name == "tls-key",
            enforce_permissions=False,
            maximum=4 * MIB,
        )
    rollback_directory = _private_directory(
        rollback_directory, expected_uid=expected_uid
    )
    changes: dict[str, object] = {}
    for name, payload in values.items():
        destination = _absolute(destinations[name], name)
        wanted = _sha256_bytes(payload)
        previous = None
        if destination.exists() or destination.is_symlink():
            old = _read_secret(
                destination,
                label=f"existing {name}",
                expected_uid=expected_uid,
            )
            previous_hash = _sha256_bytes(old)
            if previous_hash == wanted:
                changes[name] = {
                    "path": str(destination),
                    "sha256": wanted,
                    "changed": False,
                    "rollback": None,
                }
                continue
            backup = rollback_directory / f"{name}.{previous_hash}.credential"
            if backup.exists() or backup.is_symlink():
                existing = _read_secret(
                    backup,
                    label=f"{name} rollback credential",
                    expected_uid=expected_uid,
                )
                if _sha256_bytes(existing) != previous_hash:
                    raise ActivationError(f"{name} rollback credential has drifted")
            else:
                _atomic_private(backup, old, expected_uid=expected_uid)
            previous = {"path": str(backup), "sha256": previous_hash}
        _atomic_private(destination, payload, expected_uid=expected_uid)
        if _sha256_file(destination) != wanted:
            raise ActivationError(f"{name} publication did not verify")
        changes[name] = {
            "path": str(destination),
            "sha256": wanted,
            "changed": True,
            "rollback": previous,
        }
    return cutover.seal(
        CREDENTIAL_MIGRATION_KIND,
        {
            "publication_authority_uid": expected_uid,
            "legacy_source_uid": legacy_source_uid,
            "legacy_sources": {
                "console-env": legacy_identity,
            },
            "credentials": changes,
            "tls_sources": {
                name: {
                    "path": str(path),
                    "sha256": _sha256_file(path.resolve(strict=True)),
                }
                for name, path in tls_sources.items()
            },
            "created_at": _now(),
        },
    )


def verify_credential_migration(
    document: Mapping[str, object],
    *,
    legacy_env: Path,
    legacy_source_uid: int,
    destinations: Mapping[str, Path] = DEFAULT_CREDENTIALS,
    tls_cert: Path | None = None,
    tls_key: Path | None = None,
    expected_uid: int = 0,
) -> dict[str, object]:
    """Revalidate an exact completed migration without rewriting credentials."""

    verified = cutover.verify_seal(
        document,
        kind=CREDENTIAL_MIGRATION_KIND,
        fields=CREDENTIAL_MIGRATION_FIELDS,
    )
    if (
        type(legacy_source_uid) is not int
        or legacy_source_uid < 0
        or type(expected_uid) is not int
        or expected_uid < 0
        or verified["legacy_source_uid"] != legacy_source_uid
        or verified["publication_authority_uid"] != expected_uid
    ):
        raise ActivationError("credential migration authority binding is invalid")
    legacy_payload, legacy_identity = _read_secret_with_identity(
        legacy_env,
        label="legacy Console environment",
        expected_uid=legacy_source_uid,
        maximum=256 * 1024,
    )
    legacy_sources = verified["legacy_sources"]
    if (
        not isinstance(legacy_sources, Mapping)
        or set(legacy_sources) != {"console-env"}
        or legacy_sources["console-env"] != legacy_identity
    ):
        raise ActivationError("credential migration legacy source identity changed")
    env = _parse_private_env_payload(legacy_payload)
    source_values = _credential_source_values(
        env,
        destinations=destinations,
        expected_uid=expected_uid,
    )
    _validate_secret_values(source_values)
    credentials = verified["credentials"]
    if not isinstance(credentials, Mapping) or set(credentials) != set(source_values):
        raise ActivationError("credential migration destination evidence is invalid")
    for name, source_payload in source_values.items():
        destination = _absolute(destinations[name], name)
        raw = credentials[name]
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"path", "sha256", "changed", "rollback"}
            or raw["path"] != str(destination)
            or raw["sha256"] != _sha256_bytes(source_payload)
            or type(raw["changed"]) is not bool
        ):
            raise ActivationError(
                f"credential migration {name} destination binding is invalid"
            )
        current = _read_secret(
            destination,
            label=f"existing {name}",
            expected_uid=expected_uid,
        )
        if _sha256_bytes(current) != raw["sha256"]:
            raise ActivationError(
                f"credential migration {name} destination changed"
            )
        rollback = raw["rollback"]
        if rollback is not None and (
            not isinstance(rollback, Mapping)
            or set(rollback) != {"path", "sha256"}
            or not isinstance(rollback["path"], str)
            or re.fullmatch(r"[0-9a-f]{64}", str(rollback["sha256"])) is None
        ):
            raise ActivationError(
                f"credential migration {name} rollback binding is invalid"
            )
    tls_sources = verified["tls_sources"]
    if not isinstance(tls_sources, Mapping) or set(tls_sources) != {
        "tls-cert",
        "tls-key",
    }:
        raise ActivationError("credential migration TLS evidence is invalid")
    current_tls_sources = {
        "tls-cert": _absolute(
            tls_cert or destinations["tls-cert"], "tls-cert"
        ),
        "tls-key": _absolute(
            tls_key or destinations["tls-key"], "tls-key"
        ),
    }
    for name, source in current_tls_sources.items():
        raw = tls_sources[name]
        resolved, _info = _bounded_regular(
            source,
            label=name,
            expected_uid=expected_uid,
            allow_symlink=True,
            private=name == "tls-key",
            enforce_permissions=False,
            maximum=4 * MIB,
        )
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"path", "sha256"}
            or raw["path"] != str(source)
            or raw["sha256"] != _sha256_file(resolved)
        ):
            raise ActivationError(f"credential migration {name} source changed")
    if (
        not isinstance(verified["created_at"], str)
        or not str(verified["created_at"]).endswith("Z")
    ):
        raise ActivationError("credential migration timestamp is invalid")
    return dict(verified)


def _default_oidc_fetcher(url: str, timeout: float) -> bytes:
    request = Request(url, headers={"accept": "application/json", "user-agent": "devcoordinator-activation/1"})
    with urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        if response.status != 200:
            raise ActivationError("OIDC discovery returned a non-success status")
        payload = response.read(256 * 1024 + 1)
    if len(payload) > 256 * 1024:
        raise ActivationError("OIDC discovery document is oversized")
    return payload


def preflight_credentials(
    *,
    release_digest: str,
    credentials: Mapping[str, Path] = DEFAULT_CREDENTIALS,
    expected_uid: int = 0,
    oidc_fetcher: Callable[[str, float], bytes] = _default_oidc_fetcher,
) -> dict[str, object]:
    if re.fullmatch(r"[0-9a-f]{64}", release_digest) is None:
        raise ActivationError("release digest is invalid")
    if set(credentials) != set(DEFAULT_CREDENTIALS):
        raise ActivationError("credential preflight set is incomplete")
    metadata: dict[str, object] = {}
    values: dict[str, bytes] = {}
    for name, path in credentials.items():
        tls = name in {"tls-cert", "tls-key"}
        resolved, info = _bounded_regular(
            path,
            label=name,
            expected_uid=expected_uid,
            allow_symlink=tls,
            private=name != "tls-cert",
            enforce_permissions=not tls,
            maximum=4 * MIB if tls else MAX_SECRET_BYTES,
        )
        metadata[name] = {
            "path": str(path),
            "resolved_path": str(resolved),
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "owner_uid": int(info.st_uid),
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "size": int(info.st_size),
            "sha256": _sha256_file(resolved),
        }
        if not tls:
            values[name] = resolved.read_bytes()
    _validate_secret_values(values)
    try:
        discovery_payload = oidc_fetcher(OIDC_DISCOVERY, 5.0)
        discovery = json.loads(discovery_payload)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationError("OIDC discovery preflight failed") from error
    if not isinstance(discovery, Mapping) or discovery.get("issuer") != OIDC_ISSUER:
        raise ActivationError("OIDC discovery issuer is invalid")
    endpoints: dict[str, str] = {}
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = discovery.get(key)
        parsed = urlparse(str(value))
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ActivationError(f"OIDC discovery {key} is invalid")
        endpoints[key] = str(value)
    return cutover.seal(
        CREDENTIAL_PREFLIGHT_KIND,
        {
            "release_digest": release_digest,
            "credentials": metadata,
            "oidc": {
                "issuer": OIDC_ISSUER,
                "discovery_sha256": _sha256_bytes(discovery_payload),
                **endpoints,
            },
            "created_at": _now(),
        },
    )


class CommandRunner:
    def run_json(self, argv: Sequence[str]) -> dict[str, object]:
        try:
            result = subprocess.run(
                list(argv),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as error:
            raise ActivationError(
                "activation command timed out after 120 seconds"
            ) from error
        if len(result.stdout.encode("utf-8")) > MAX_JSON_BYTES or len(result.stderr.encode("utf-8")) > MAX_JSON_BYTES:
            raise ActivationError("activation command returned oversized output")
        stream = result.stdout if result.returncode == 0 else result.stderr
        try:
            document = json.loads(stream)
        except json.JSONDecodeError as error:
            raise ActivationError("activation command returned invalid JSON") from error
        if result.returncode != 0 or not isinstance(document, dict) or document.get("ok") is not True:
            raise ActivationError(str(document.get("error") or "activation command failed"))
        return document

    def status(self, argv: Sequence[str]) -> int:
        try:
            return subprocess.run(
                list(argv),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
            ).returncode
        except subprocess.TimeoutExpired as error:
            raise ActivationError(
                "activation status command timed out after 120 seconds"
            ) from error

    def text(self, argv: Sequence[str]) -> str:
        try:
            result = subprocess.run(
                list(argv),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as error:
            raise ActivationError(
                "activation text command timed out after 120 seconds"
            ) from error
        if result.returncode != 0:
            raise ActivationError("candidate preparation command failed")
        if len(result.stdout.encode("utf-8")) > MAX_JSON_BYTES:
            raise ActivationError("candidate preparation output is oversized")
        return result.stdout


def first_adoption_handoff_preflight(
    *,
    rendered_units: Path,
    publication_file: Path,
    http_handoff_port: int,
    https_handoff_port: int,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
    resume_operation_id: str | None = None,
) -> dict[str, object]:
    """Evaluate, but never mutate, the bounded first-listener handoff path.

    The proof is intentionally explicit.  Absence of the temporary edge unit
    templates or a usable retained publication is a blocker, not permission to
    stop a legacy public listener and hope the final socket binds quickly.
    """

    if os.geteuid() != expected_uid:
        raise ActivationError("first-adoption preflight must run as the authority UID")
    if (
        not 30000 <= http_handoff_port <= 60999
        or not 30000 <= https_handoff_port <= 60999
        or http_handoff_port == https_handoff_port
    ):
        raise ActivationError("first-adoption handoff ports are invalid")
    command = runner or CommandRunner()
    blockers: list[str] = []
    binary_evidence: dict[str, object] = {}
    system_uid = Path("/").stat().st_uid
    for name, lexical in binaries.items():
        try:
            resolved = lexical.resolve(strict=True)
            info = resolved.stat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in {system_uid, expected_uid}
                or stat.S_IMODE(info.st_mode) & 0o022
                or resolved.name != "xtables-nft-multi"
            ):
                raise ActivationError("not the required xtables-nft backend")
            binary_evidence[name] = {
                "path": str(lexical),
                "resolved_path": str(resolved),
                "sha256": _sha256_file(resolved),
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            }
        except (OSError, ActivationError):
            blockers.append(f"{name}:xtables-nft-unavailable")
    rulesets: dict[str, object] = {}
    for family, command_name in (("ipv4", "iptables-save"), ("ipv6", "ip6tables-save")):
        if command_name not in binary_evidence:
            continue
        try:
            rules = command.text([str(binaries[command_name]), "-t", "nat"])
            owned_resume = (
                resume_operation_id is not None
                and _handoff_chain_owned(rules, operation_id=resume_operation_id)
            )
            if HANDOFF_CHAIN in rules and not owned_resume:
                blockers.append(f"{family}:handoff-chain-already-exists")
            rulesets[family] = {
                "nat_ruleset_sha256": _sha256_bytes(rules.encode("utf-8")),
                "chain_absent": HANDOFF_CHAIN not in rules,
                "owned_resume_chain": owned_resume,
            }
        except ActivationError:
            blockers.append(f"{family}:nat-ruleset-unreadable")
    required_handoff_templates = {
        "devcoordinator-edge-handoff.service",
        "devcoordinator-edge-handoff-http.socket",
        "devcoordinator-edge-handoff-https.socket",
    }
    present_templates = {
        path.name for path in rendered_units.iterdir() if path.is_file()
    } if rendered_units.is_dir() else set()
    missing_templates = sorted(required_handoff_templates - present_templates)
    if missing_templates:
        blockers.append("temporary-edge-socket-contract-missing")
    publication_metadata: dict[str, object] | None = None
    try:
        envelope = _load_publication(publication_file)
        publication = envelope["publication"]
        if not isinstance(publication, Mapping):
            raise ActivationError("retained publication payload is invalid")
        console = publication.get("console")
        upstream = console.get("upstream") if isinstance(console, Mapping) else None
        port = upstream.get("port") if isinstance(upstream, Mapping) else None
        if type(port) is not int or port in {80, 443, http_handoff_port, https_handoff_port}:
            blockers.append("retained-publication-console-target-is-not-independent")
        publication_metadata = {
            "generation": publication.get("generation"),
            "payload_sha256": envelope.get("payload_sha256"),
            "release_digest": publication.get("release_digest"),
            "route_count": len(publication.get("routes", {}))
            if isinstance(publication.get("routes"), Mapping)
            else -1,
            "console_port": port,
        }
    except (OSError, ActivationError, KeyError, AssertionError):
        blockers.append("retained-publication-unavailable")
    blockers = sorted(set(blockers))
    return cutover.seal(
        FIRST_ADOPTION_PREFLIGHT_KIND,
        {
            "ready": not blockers,
            "blockers": blockers,
            "chain": HANDOFF_CHAIN,
            "http_handoff_port": http_handoff_port,
            "https_handoff_port": https_handoff_port,
            "binaries": binary_evidence,
            "rulesets": rulesets,
            "publication": publication_metadata,
            "required_templates": sorted(required_handoff_templates),
            "missing_templates": missing_templates,
            "mutated_firewall": False,
            "created_at": _now(),
        },
    )


def _sealed_journal(payload: Mapping[str, object]) -> dict[str, object]:
    return cutover.seal(FIRST_ADOPTION_JOURNAL_KIND, dict(payload))


def _write_journal(path: Path, payload: Mapping[str, object], *, expected_uid: int) -> dict[str, object]:
    document = _sealed_journal(payload)
    _atomic_private(path, _canonical(document) + b"\n", expected_uid=expected_uid)
    return document


def _load_journal(path: Path, *, expected_uid: int) -> dict[str, object] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    document = json.loads(
        _read_secret(
            path,
            label="first-adoption handoff journal",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
    )
    if not isinstance(document, dict) or document.get("kind") != FIRST_ADOPTION_JOURNAL_KIND:
        raise ActivationError("first-adoption handoff journal kind is invalid")
    actual = document.get("document_sha256")
    unsigned = {key: value for key, value in document.items() if key != "document_sha256"}
    if actual != _sha256_bytes(_canonical(unsigned)):
        raise ActivationError("first-adoption handoff journal checksum is invalid")
    return document


def _ruleset_without_handoff(value: str) -> str:
    return "\n".join(
        line
        for line in value.splitlines()
        if HANDOFF_CHAIN not in line
    ) + "\n"


def _handoff_chain_owned(value: str, *, operation_id: str) -> bool:
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError):
        return False
    lines = [line for line in value.splitlines() if HANDOFF_CHAIN in line]
    if not lines:
        return False
    comment = f"devcoordinator:{operation_id}"
    return all(
        line.startswith(f":{HANDOFF_CHAIN} ") or comment in line
        for line in lines
    )


def _family_contract(
    family: str,
    *,
    binaries: Mapping[str, Path],
) -> tuple[Path, Path]:
    if family == "ipv4":
        return binaries["iptables"], binaries["iptables-save"]
    if family == "ipv6":
        return binaries["ip6tables"], binaries["ip6tables-save"]
    raise ActivationError("redirect address family is invalid")


def _redirect_rules(operation_id: str, http_port: int, https_port: int) -> list[list[str]]:
    comment = f"devcoordinator:{operation_id}"
    return [
        ["-A", HANDOFF_CHAIN, "-p", "tcp", "--dport", "80", "-m", "comment", "--comment", comment, "-j", "REDIRECT", "--to-ports", str(http_port)],
        ["-A", HANDOFF_CHAIN, "-p", "tcp", "--dport", "443", "-m", "comment", "--comment", comment, "-j", "REDIRECT", "--to-ports", str(https_port)],
        ["-I", "PREROUTING", "1", "-p", "tcp", "-m", "addrtype", "--dst-type", "LOCAL", "-m", "comment", "--comment", comment, "-j", HANDOFF_CHAIN],
        ["-I", "OUTPUT", "1", "-p", "tcp", "-m", "addrtype", "--dst-type", "LOCAL", "-m", "comment", "--comment", comment, "-j", HANDOFF_CHAIN],
    ]


def _check_rule(runner: CommandRunner, binary: Path, rule: Sequence[str]) -> bool:
    check = list(rule)
    check[0] = "-C"
    if len(check) > 2 and check[2] == "1":
        del check[2]
    return runner.status([str(binary), "-w", "5", "-t", "nat", *check]) == 0


def _ruleset_evidence(
    family: str,
    *,
    runner: CommandRunner,
    binaries: Mapping[str, Path],
) -> dict[str, str]:
    _binary, save = _family_contract(family, binaries=binaries)
    value = runner.text([str(save), "-t", "nat"])
    return {
        "sha256": _sha256_bytes(value.encode("utf-8")),
        "unrelated_sha256": _sha256_bytes(_ruleset_without_handoff(value).encode("utf-8")),
    }


def _apply_redirect_family(
    family: str,
    *,
    operation_id: str,
    http_port: int,
    https_port: int,
    baseline_unrelated_sha256: str,
    runner: CommandRunner,
    binaries: Mapping[str, Path],
) -> dict[str, str]:
    binary, _save = _family_contract(family, binaries=binaries)
    chain_exists = runner.status([str(binary), "-w", "5", "-t", "nat", "-S", HANDOFF_CHAIN]) == 0
    rules = _redirect_rules(operation_id, http_port, https_port)
    if chain_exists:
        before = _ruleset_evidence(family, runner=runner, binaries=binaries)
        _binary, save = _family_contract(family, binaries=binaries)
        raw = runner.text([str(save), "-t", "nat"])
        if (
            before["unrelated_sha256"] != baseline_unrelated_sha256
            or not _handoff_chain_owned(raw, operation_id=operation_id)
        ):
            raise ActivationError(f"{family} handoff chain exists with another contract")
        for rule in rules:
            if not _check_rule(runner, binary, rule) and runner.status(
                [str(binary), "-w", "5", "-t", "nat", *rule]
            ) != 0:
                raise ActivationError(f"{family} handoff rule resume failed")
    else:
        before = _ruleset_evidence(family, runner=runner, binaries=binaries)
        if before["unrelated_sha256"] != baseline_unrelated_sha256:
            raise ActivationError(f"{family} NAT rules changed before redirect CAS")
        if runner.status([str(binary), "-w", "5", "-t", "nat", "-N", HANDOFF_CHAIN]) != 0:
            raise ActivationError(f"{family} handoff chain creation failed")
        for rule in rules:
            if runner.status([str(binary), "-w", "5", "-t", "nat", *rule]) != 0:
                raise ActivationError(f"{family} handoff rule publication failed")
    after = _ruleset_evidence(family, runner=runner, binaries=binaries)
    if after["unrelated_sha256"] != baseline_unrelated_sha256:
        raise ActivationError(f"{family} handoff changed unrelated NAT rules")
    if not all(_check_rule(runner, binary, rule) for rule in rules):
        raise ActivationError(f"{family} handoff rule verification failed")
    return after


def _remove_redirect_family(
    family: str,
    *,
    operation_id: str,
    http_port: int,
    https_port: int,
    baseline_unrelated_sha256: str,
    runner: CommandRunner,
    binaries: Mapping[str, Path],
) -> dict[str, str]:
    binary, _save = _family_contract(family, binaries=binaries)
    if runner.status([str(binary), "-w", "5", "-t", "nat", "-S", HANDOFF_CHAIN]) == 0:
        rules = _redirect_rules(operation_id, http_port, https_port)
        # Delete jumps before flushing the private chain.  The chain-local
        # rules disappear with -F; exact -C prevents deleting unrelated jumps.
        for rule in reversed(rules[2:]):
            if _check_rule(runner, binary, rule):
                delete = list(rule)
                delete[0] = "-D"
                if len(delete) > 2 and delete[2] == "1":
                    del delete[2]
                if runner.status([str(binary), "-w", "5", "-t", "nat", *delete]) != 0:
                    raise ActivationError(f"{family} handoff jump removal failed")
        if runner.status([str(binary), "-w", "5", "-t", "nat", "-F", HANDOFF_CHAIN]) != 0:
            raise ActivationError(f"{family} handoff chain flush failed")
        if runner.status([str(binary), "-w", "5", "-t", "nat", "-X", HANDOFF_CHAIN]) != 0:
            raise ActivationError(f"{family} handoff chain deletion failed")
    if runner.status([str(binary), "-w", "5", "-t", "nat", "-S", HANDOFF_CHAIN]) == 0:
        raise ActivationError(f"{family} handoff chain remains after removal")
    after = _ruleset_evidence(family, runner=runner, binaries=binaries)
    if after["unrelated_sha256"] != baseline_unrelated_sha256:
        raise ActivationError(f"{family} unrelated NAT rules changed during handoff")
    return after


def _ruleset_without_api_handoff(value: str) -> str:
    return "\n".join(
        line for line in value.splitlines() if API_HANDOFF_CHAIN not in line
    ) + "\n"


def _api_handoff_chain_owned(value: str, *, operation_id: str) -> bool:
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError):
        return False
    lines = [line for line in value.splitlines() if API_HANDOFF_CHAIN in line]
    if not lines:
        return False
    comment = f"devcoordinator-api:{operation_id}"
    return all(
        line.startswith(f":{API_HANDOFF_CHAIN} ") or comment in line
        for line in lines
    )


def _api_redirect_rules(operation_id: str, handoff_port: int) -> list[list[str]]:
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError("API handoff operation identity is invalid") from error
    if not 30000 <= handoff_port <= 60999 or handoff_port == SOCKET_PORTS["api"]:
        raise ActivationError("API handoff port is invalid")
    comment = f"devcoordinator-api:{operation_id}"
    return [
        [
            "-A",
            API_HANDOFF_CHAIN,
            "-p",
            "tcp",
            "-d",
            "127.0.0.1/32",
            "--dport",
            str(SOCKET_PORTS["api"]),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "REDIRECT",
            "--to-ports",
            str(handoff_port),
        ],
        [
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "tcp",
            "-d",
            "127.0.0.1/32",
            "--dport",
            str(SOCKET_PORTS["api"]),
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            API_HANDOFF_CHAIN,
        ],
    ]


def _api_ruleset_evidence(
    *, runner: CommandRunner, binaries: Mapping[str, Path]
) -> dict[str, str]:
    value = runner.text([str(binaries["iptables-save"]), "-t", "nat"])
    return {
        "sha256": _sha256_bytes(value.encode("utf-8")),
        "unrelated_sha256": _sha256_bytes(
            _ruleset_without_api_handoff(value).encode("utf-8")
        ),
    }


def apply_api_handoff_redirect(
    *,
    operation_id: str,
    handoff_port: int,
    baseline_unrelated_sha256: str,
    runner: CommandRunner,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
) -> dict[str, str]:
    """CAS-publish only the exact IPv4 loopback API redirect."""

    binary = binaries["iptables"]
    rules = _api_redirect_rules(operation_id, handoff_port)
    chain_exists = runner.status(
        [str(binary), "-w", "5", "-t", "nat", "-S", API_HANDOFF_CHAIN]
    ) == 0
    if chain_exists:
        raw = runner.text([str(binaries["iptables-save"]), "-t", "nat"])
        if not _api_handoff_chain_owned(raw, operation_id=operation_id):
            raise ActivationError("API handoff chain belongs to another operation")
        before = _api_ruleset_evidence(runner=runner, binaries=binaries)
        if before["unrelated_sha256"] != baseline_unrelated_sha256:
            raise ActivationError("IPv4 NAT rules changed before API handoff resume")
        for rule in rules:
            if not _check_rule(runner, binary, rule) and runner.status(
                [str(binary), "-w", "5", "-t", "nat", *rule]
            ) != 0:
                raise ActivationError("API handoff rule resume failed")
    else:
        before = _api_ruleset_evidence(runner=runner, binaries=binaries)
        if before["unrelated_sha256"] != baseline_unrelated_sha256:
            raise ActivationError("IPv4 NAT rules changed before API handoff CAS")
        if runner.status(
            [str(binary), "-w", "5", "-t", "nat", "-N", API_HANDOFF_CHAIN]
        ) != 0:
            raise ActivationError("API handoff chain creation failed")
        for rule in rules:
            if runner.status(
                [str(binary), "-w", "5", "-t", "nat", *rule]
            ) != 0:
                raise ActivationError("API handoff redirect publication failed")
    after = _api_ruleset_evidence(runner=runner, binaries=binaries)
    if after["unrelated_sha256"] != baseline_unrelated_sha256 or not all(
        _check_rule(runner, binary, rule) for rule in rules
    ):
        raise ActivationError("API handoff redirect verification failed")
    return after


def remove_api_handoff_redirect(
    *,
    operation_id: str,
    handoff_port: int,
    baseline_unrelated_sha256: str,
    runner: CommandRunner,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
) -> dict[str, str]:
    """Remove only the operation-tagged loopback API redirect."""

    binary = binaries["iptables"]
    if runner.status(
        [str(binary), "-w", "5", "-t", "nat", "-S", API_HANDOFF_CHAIN]
    ) == 0:
        rules = _api_redirect_rules(operation_id, handoff_port)
        jump = list(rules[1])
        if _check_rule(runner, binary, jump):
            jump[0] = "-D"
            if len(jump) > 2 and jump[2] == "1":
                del jump[2]
            if runner.status(
                [str(binary), "-w", "5", "-t", "nat", *jump]
            ) != 0:
                raise ActivationError("API handoff jump removal failed")
        if runner.status(
            [str(binary), "-w", "5", "-t", "nat", "-F", API_HANDOFF_CHAIN]
        ) != 0 or runner.status(
            [str(binary), "-w", "5", "-t", "nat", "-X", API_HANDOFF_CHAIN]
        ) != 0:
            raise ActivationError("API handoff chain removal failed")
    if runner.status(
        [str(binary), "-w", "5", "-t", "nat", "-S", API_HANDOFF_CHAIN]
    ) == 0:
        raise ActivationError("API handoff chain remains after removal")
    after = _api_ruleset_evidence(runner=runner, binaries=binaries)
    if after["unrelated_sha256"] != baseline_unrelated_sha256:
        raise ActivationError("API handoff changed unrelated IPv4 NAT rules")
    return after


def _probe_local_api(port: int, *, timeout: float = 3.0) -> int:
    if not 1 <= port <= 65535:
        raise ActivationError("local API probe port is invalid")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", "/healthz", headers={"Host": "127.0.0.1"})
        response = connection.getresponse()
        response.read(64 * 1024)
        return int(response.status)
    except OSError as error:
        raise ActivationError("local API health probe was refused") from error
    finally:
        connection.close()


def start_api_handoff(
    *,
    handoff_port: int,
    operation_id: str,
    runner: CommandRunner,
    listener_reader: Callable[[int], int] | None = None,
    api_probe: Callable[[int], int] = _probe_local_api,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
) -> dict[str, object]:
    """Start, verify, and redirect the high-port API before writer takeover."""

    listener_call = listener_reader or _tcp_listener_inode
    _api_redirect_rules(operation_id, handoff_port)
    baseline = _api_ruleset_evidence(runner=runner, binaries=binaries)
    for unit in (API_HANDOFF_SOCKET_UNIT, API_HANDOFF_SERVICE_UNIT):
        if runner.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
            raise ActivationError(f"temporary API failed readiness: {unit}")
    high_inode = listener_call(handoff_port)
    high_status = api_probe(handoff_port)
    if high_status != 200:
        raise ActivationError("temporary API health probe failed")
    redirect = apply_api_handoff_redirect(
        operation_id=operation_id,
        handoff_port=handoff_port,
        baseline_unrelated_sha256=baseline["unrelated_sha256"],
        runner=runner,
        binaries=binaries,
    )
    public_status = api_probe(SOCKET_PORTS["api"])
    if public_status != 200:
        raise ActivationError("redirected stable API health probe failed")
    return {
        "operation_id": operation_id,
        "handoff_port": handoff_port,
        "handoff_socket_inode": high_inode,
        "handoff_status": high_status,
        "stable_status": public_status,
        "baseline": baseline,
        "redirect": redirect,
    }


def finish_api_handoff(
    evidence: Mapping[str, object],
    *,
    runner: CommandRunner,
    listener_reader: Callable[[int], int] | None = None,
    api_probe: Callable[[int], int] = _probe_local_api,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
) -> dict[str, object]:
    """Verify final socket readiness, then remove the high-port redirect."""

    listener_call = listener_reader or _tcp_listener_inode
    required = {
        "operation_id",
        "handoff_port",
        "handoff_socket_inode",
        "handoff_status",
        "stable_status",
        "baseline",
        "redirect",
    }
    if not isinstance(evidence, Mapping) or set(evidence) != required:
        raise ActivationError("API handoff evidence is invalid")
    if runner.status(
        ["/usr/bin/systemctl", "enable", "--now", "devcoordinator-api.socket"]
    ) != 0 or runner.status(
        ["/usr/bin/systemctl", "enable", "--now", "devcoordinator-api.service"]
    ) != 0:
        raise ActivationError("final API socket or service failed readiness")
    final_inode = listener_call(SOCKET_PORTS["api"])
    if api_probe(SOCKET_PORTS["api"]) != 200:
        raise ActivationError("final stable API health probe failed")
    baseline = evidence["baseline"]
    if not isinstance(baseline, Mapping) or not isinstance(
        baseline.get("unrelated_sha256"), str
    ):
        raise ActivationError("API handoff baseline is invalid")
    removal = remove_api_handoff_redirect(
        operation_id=str(evidence["operation_id"]),
        handoff_port=int(evidence["handoff_port"]),
        baseline_unrelated_sha256=str(baseline["unrelated_sha256"]),
        runner=runner,
        binaries=binaries,
    )
    for unit in (API_HANDOFF_SERVICE_UNIT, API_HANDOFF_SOCKET_UNIT):
        _disable_stop_exact_unit(
            runner, unit, label="temporary API handoff unit"
        )
    return {
        "final_socket_inode": final_inode,
        "status": api_probe(SOCKET_PORTS["api"]),
        "redirect_removal": removal,
    }


def _write_api_handoff_journal(
    path: Path, payload: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    document = cutover.seal(API_HANDOFF_JOURNAL_KIND, dict(payload))
    _atomic_private(path, _canonical(document) + b"\n", expected_uid=expected_uid)
    return document


def _load_api_handoff_journal(
    path: Path, *, expected_uid: int
) -> dict[str, object] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    value = json.loads(
        _read_secret(
            path,
            label="API handoff journal",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
    )
    if not isinstance(value, Mapping) or value.get("kind") != API_HANDOFF_JOURNAL_KIND:
        raise ActivationError("API handoff journal kind is invalid")
    digest = value.get("document_sha256")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if digest != _sha256_bytes(_canonical(unsigned)):
        raise ActivationError("API handoff journal digest is invalid")
    return dict(value)


def api_handoff_transaction(
    *,
    journal_file: Path,
    handoff_port: int,
    action: str,
    expected_uid: int,
    runner: CommandRunner,
    listener_reader: Callable[[int], int] | None = None,
    api_probe: Callable[[int], int] = _probe_local_api,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
) -> dict[str, object]:
    """Journal and resume the exact high-port API takeover or its rollback."""

    if os.geteuid() != expected_uid:
        raise ActivationError("API handoff transaction must run as the authority UID")
    if action not in {"start", "finish", "rollback"}:
        raise ActivationError("API handoff transaction action is invalid")
    listener = listener_reader or _tcp_listener_inode
    journal_file = _absolute(journal_file, "API handoff journal")
    current = _load_api_handoff_journal(journal_file, expected_uid=expected_uid)
    if current is None:
        if action != "start":
            raise ActivationError("API handoff has not been started")
        operation_id = str(uuid.uuid4())
        baseline = _api_ruleset_evidence(runner=runner, binaries=binaries)
        legacy_active, legacy_enabled = _unit_state(
            runner, LEGACY_API_SERVICE_UNIT
        )
        current = _write_api_handoff_journal(
            journal_file,
            {
                "operation_id": operation_id,
                "handoff_port": handoff_port,
                "phase": "planned",
                "baseline": baseline,
                "legacy_api": {
                    "unit": LEGACY_API_SERVICE_UNIT,
                    "active": legacy_active,
                    "enabled": legacy_enabled,
                },
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    if current.get("handoff_port") != handoff_port:
        raise ActivationError("API handoff journal port disagrees")
    operation_id = str(current.get("operation_id"))
    phases = {
        "planned": 0,
        "high_ready": 1,
        "redirected": 2,
        "legacy_stopped": 3,
        "final_ready": 4,
        "complete": 5,
        "rolled_back": 6,
    }
    if current.get("phase") not in phases:
        raise ActivationError("API handoff journal phase is invalid")
    if current.get("phase") == "rolled_back":
        if action == "rollback":
            return current
        raise ActivationError("API handoff was rolled back; use a new journal")

    def advance(phase: str, **extra: object) -> None:
        nonlocal current
        payload = {
            key: value
            for key, value in current.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(extra)
        payload["phase"] = phase
        payload["updated_at"] = _now()
        current = _write_api_handoff_journal(
            journal_file, payload, expected_uid=expected_uid
        )

    baseline = current.get("baseline")
    if not isinstance(baseline, Mapping) or not isinstance(
        baseline.get("unrelated_sha256"), str
    ):
        raise ActivationError("API handoff journal baseline is invalid")
    legacy_api = current.get("legacy_api")
    if (
        not isinstance(legacy_api, Mapping)
        or set(legacy_api) != {"unit", "active", "enabled"}
        or legacy_api.get("unit") != LEGACY_API_SERVICE_UNIT
        or type(legacy_api.get("active")) is not bool
        or type(legacy_api.get("enabled")) is not bool
    ):
        raise ActivationError("API handoff legacy service state is invalid")
    if action == "rollback":
        for unit in ("devcoordinator-api.service", "devcoordinator-api.socket"):
            _disable_stop_exact_unit(
                runner, unit, label="final API rollback unit"
            )
        if legacy_api["active"] is True:
            restore = (
                ["enable", "--now"]
                if legacy_api["enabled"] is True
                else ["start"]
            )
            if (
                runner.status(
                    [
                        "/usr/bin/systemctl",
                        *restore,
                        LEGACY_API_SERVICE_UNIT,
                    ]
                )
                != 0
                or runner.status(
                    [
                        "/usr/bin/systemctl",
                        "is-active",
                        "--quiet",
                        LEGACY_API_SERVICE_UNIT,
                    ]
                )
                != 0
            ):
                raise ActivationError(
                    "legacy API could not be restored during rollback"
                )
        elif legacy_api["enabled"] is True:
            if (
                runner.status(
                    [
                        "/usr/bin/systemctl",
                        "enable",
                        LEGACY_API_SERVICE_UNIT,
                    ]
                )
                != 0
            ):
                raise ActivationError(
                    "legacy API enablement could not be restored"
                )
        if _unit_state(runner, LEGACY_API_SERVICE_UNIT) != (
            bool(legacy_api["active"]),
            bool(legacy_api["enabled"]),
        ):
            raise ActivationError(
                "legacy API rollback state did not converge exactly"
            )
        removal = remove_api_handoff_redirect(
            operation_id=operation_id,
            handoff_port=handoff_port,
            baseline_unrelated_sha256=str(baseline["unrelated_sha256"]),
            runner=runner,
            binaries=binaries,
        )
        for unit in (API_HANDOFF_SERVICE_UNIT, API_HANDOFF_SOCKET_UNIT):
            _disable_stop_exact_unit(
                runner, unit, label="temporary API rollback unit"
            )
        if legacy_api["active"] is True:
            status = api_probe(SOCKET_PORTS["api"])
            if status != 200:
                raise ActivationError(
                    "restored legacy API health probe failed"
                )
        advance("rolled_back", redirect_removal=removal, rolled_back_at=_now())
        return current
    if action == "start":
        if phases[str(current["phase"])] <= phases["planned"]:
            for unit in (API_HANDOFF_SOCKET_UNIT, API_HANDOFF_SERVICE_UNIT):
                if runner.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                    raise ActivationError(f"temporary API failed readiness: {unit}")
            status = api_probe(handoff_port)
            if status != 200:
                raise ActivationError("temporary API health probe failed")
            advance(
                "high_ready",
                handoff_socket_inode=listener(handoff_port),
                handoff_status=status,
            )
        if phases[str(current["phase"])] <= phases["high_ready"]:
            redirect = apply_api_handoff_redirect(
                operation_id=operation_id,
                handoff_port=handoff_port,
                baseline_unrelated_sha256=str(baseline["unrelated_sha256"]),
                runner=runner,
                binaries=binaries,
            )
            stable_status = api_probe(SOCKET_PORTS["api"])
            if stable_status != 200:
                raise ActivationError("redirected stable API health probe failed")
            advance(
                "redirected",
                redirect=redirect,
                stable_status=stable_status,
            )
        if phases[str(current["phase"])] <= phases["redirected"]:
            if runner.status(
                [
                    "/usr/bin/systemctl",
                    "disable",
                    "--now",
                    LEGACY_API_SERVICE_UNIT,
                ]
            ) != 0:
                raise ActivationError("legacy API could not be fenced")
            if _unit_state(
                runner, LEGACY_API_SERVICE_UNIT
            ) != (False, False):
                raise ActivationError(
                    "legacy API remained active or enabled after fencing"
                )
            stable_status = api_probe(SOCKET_PORTS["api"])
            if stable_status != 200:
                raise ActivationError(
                    "temporary API failed after legacy fencing"
                )
            advance(
                "legacy_stopped",
                legacy_api_stopped=legacy_api["active"] is True,
                legacy_api_disabled=legacy_api["enabled"] is True,
                stable_status_after_legacy_stop=stable_status,
            )
        return current
    if phases[str(current["phase"])] < phases["legacy_stopped"]:
        raise ActivationError("API handoff is not ready for final takeover")
    if phases[str(current["phase"])] <= phases["legacy_stopped"]:
        for unit in ("devcoordinator-api.socket", "devcoordinator-api.service"):
            if runner.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                raise ActivationError("final API socket or service failed readiness")
        advance(
            "final_ready",
            final_socket_inode=listener(SOCKET_PORTS["api"]),
        )
    if phases[str(current["phase"])] <= phases["final_ready"]:
        removal = remove_api_handoff_redirect(
            operation_id=operation_id,
            handoff_port=handoff_port,
            baseline_unrelated_sha256=str(baseline["unrelated_sha256"]),
            runner=runner,
            binaries=binaries,
        )
        status = api_probe(SOCKET_PORTS["api"])
        if status != 200:
            raise ActivationError("final stable API health probe failed")
        for unit in (API_HANDOFF_SERVICE_UNIT, API_HANDOFF_SOCKET_UNIT):
            _disable_stop_exact_unit(
                runner, unit, label="temporary API handoff unit"
            )
        advance(
            "complete",
            redirect_removal=removal,
            final_status=status,
            completed_at=_now(),
        )
    return current


def bootstrap_edge_publication(
    *,
    release: Path,
    publication_input: Path,
    publication_file: Path,
    edge_uid: int,
    edge_gid: int,
    expected_uid: int,
    runner: CommandRunner,
) -> dict[str, object]:
    payload = _read_secret(
        publication_input,
        label="retained publication bootstrap input",
        expected_uid=expected_uid,
        maximum=MAX_JSON_BYTES,
    )
    # Parse before invoking the immutable validator so the evidence can bind
    # the exact producer bytes without ever serializing their secret fields.
    try:
        if not isinstance(json.loads(payload), dict):
            raise ValueError("not an object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ActivationError("retained publication bootstrap input is invalid") from error
    executable = release / "bin/devcoordinator-edge-publication"
    result = runner.run_json(
        [
            str(executable),
            "seal",
            "--input",
            str(publication_input),
            "--output",
            str(publication_file),
            "--release-root",
            str(IMMUTABLE_RELEASE_ROOT),
            "--owner-uid",
            str(edge_uid),
            "--owner-gid",
            str(edge_gid),
        ]
    )
    envelope = _load_publication(publication_file)
    info = publication_file.lstat()
    if info.st_uid != edge_uid or info.st_gid != edge_gid or stat.S_IMODE(info.st_mode) != 0o600:
        raise ActivationError("retained publication ownership is invalid")
    if envelope.get("payload_sha256") != result.get("payload_sha256"):
        raise ActivationError("retained publication bootstrap result disagrees")
    publication = envelope["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("retained publication bootstrap payload is invalid")
    return {
        "input_sha256": _sha256_bytes(payload),
        "payload_sha256": envelope["payload_sha256"],
        "generation": publication.get("generation"),
        "release_digest": publication.get("release_digest"),
        "route_count": len(publication.get("routes", {})) if isinstance(publication.get("routes"), Mapping) else -1,
    }


def switch_edge_maintenance(
    *,
    release: Path,
    publication_file: Path,
    active: bool,
    deployment_id: str,
    runner: CommandRunner,
    retry_after_seconds: int = 5,
) -> dict[str, object]:
    before = _load_publication(publication_file)
    result = runner.run_json(
        [
            str(release / "bin/devcoordinator-edge-publication"),
            "switch-maintenance",
            "--file",
            str(publication_file),
            "--release-root",
            str(IMMUTABLE_RELEASE_ROOT),
            "--expected-payload-sha256",
            str(before["payload_sha256"]),
            "--active",
            "true" if active else "false",
            "--deployment-id",
            deployment_id,
            "--retry-after-seconds",
            str(retry_after_seconds if active else 0),
            "--published-at",
            _now(),
        ]
    )
    after = _load_publication(publication_file)
    publication = after["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("edge maintenance publication payload is invalid")
    maintenance = publication.get("maintenance")
    if (
        not isinstance(maintenance, Mapping)
        or maintenance.get("active") is not active
        or after.get("payload_sha256") != result.get("payload_sha256")
    ):
        raise ActivationError("edge maintenance publication did not verify")
    return {
        "previous_generation": result.get("previous_generation"),
        "generation": result.get("generation"),
        "previous_payload_sha256": result.get("previous_payload_sha256"),
        "payload_sha256": result.get("payload_sha256"),
        "active": active,
        "deployment_id": deployment_id if active else None,
        "retry_after_seconds": retry_after_seconds if active else 0,
    }


def first_adoption_handoff(
    *,
    release: Path,
    rendered_units: Path,
    publication_file: Path,
    publication_input: Path | None,
    journal_file: Path,
    http_handoff_port: int,
    https_handoff_port: int,
    edge_uid: int,
    edge_gid: int,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
    unit_root: Path = SYSTEMD_UNIT_ROOT,
    probe: Callable[[str], tuple[int | None, bool]] | None = None,
    continuity_probe: Callable[[str], tuple[int | None, bool]] | None = None,
    listener_reader: Callable[[int], int] | None = None,
    after_legacy_console_stopped: Callable[[str], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Adopt ports 80/443 without an unserved interval.

    Every mutating phase is journaled before the next one.  Re-entry resumes
    exact state; ordinary exceptions restore the old listener and remove only
    the operation-tagged IPv4/IPv6 rules.  Full ruleset restore is forbidden so
    unrelated firewall updates are never overwritten.
    """

    if os.geteuid() != expected_uid:
        raise ActivationError("first-adoption handoff must run as the authority UID")
    command = runner or CommandRunner()
    probe_call = probe or _probe_url
    listener_call = listener_reader or _tcp_listener_inode
    release = _absolute(release, "first-adoption release")
    if release.parent != IMMUTABLE_RELEASE_ROOT or re.fullmatch(r"[0-9a-f]{64}", release.name) is None:
        raise ActivationError("first-adoption release is not immutable")
    journal_file = _absolute(journal_file, "first-adoption journal")
    existing = _load_journal(journal_file, expected_uid=expected_uid)
    if existing is not None:
        if existing.get("release_digest") != release.name:
            raise ActivationError("first-adoption journal belongs to another release")
        if existing.get("phase") == "complete":
            try:
                cutover._continuity_probe(
                    existing.get("continuity_probe"),
                    expected_release=release.name,
                )
            except cutover.CutoverError as error:
                raise ActivationError(
                    "completed first-adoption journal lacks valid continuity evidence"
                ) from error
            return existing
        if existing.get("phase") == "rolled_back":
            raise ActivationError("the previous first-adoption operation was rolled back; use a new journal")

    bootstrap = None
    if not publication_file.exists():
        if publication_input is None:
            raise ActivationError("first adoption requires a retained publication bootstrap input")
        bootstrap = bootstrap_edge_publication(
            release=release,
            publication_input=publication_input,
            publication_file=publication_file,
            edge_uid=edge_uid,
            edge_gid=edge_gid,
            expected_uid=expected_uid,
            runner=command,
        )
    preflight = first_adoption_handoff_preflight(
        rendered_units=rendered_units,
        publication_file=publication_file,
        http_handoff_port=http_handoff_port,
        https_handoff_port=https_handoff_port,
        expected_uid=expected_uid,
        runner=command,
        binaries=binaries,
        resume_operation_id=(
            str(existing["operation_id"])
            if existing is not None and "operation_id" in existing
            else None
        ),
    )
    if preflight.get("ready") is not True:
        raise ActivationError(
            "first-adoption handoff preflight is blocked: "
            + ", ".join(str(value) for value in preflight.get("blockers", []))
        )

    if existing is None:
        operation_id = str(uuid.uuid4())
        legacy_active, legacy_enabled = _unit_state(command, "devops-console.service")
        if not legacy_active:
            raise ActivationError("first adoption requires the proven active legacy Console listener")
        baseline = {
            family: _ruleset_evidence(family, runner=command, binaries=binaries)
            for family in ("ipv4", "ipv6")
        }
        prior_files = {
            str(unit_root / name): _capture_destination(
                unit_root / name,
                rollback_directory=_private_directory(journal_file.parent / "file-backups", expected_uid=expected_uid),
                expected_uid=expected_uid,
            )
            for name in HANDOFF_FILES
        }
        payload: dict[str, object] = {
            "release_digest": release.name,
            "operation_id": operation_id,
            "phase": "planned",
            "ports": {"http": http_handoff_port, "https": https_handoff_port},
            "baseline": baseline,
            "legacy_console": {"active": legacy_active, "enabled": legacy_enabled},
            "prior_files": prior_files,
            "publication": {
                "path": str(publication_file),
                "payload_sha256": _load_publication(publication_file)["payload_sha256"],
                "bootstrap": bootstrap,
            },
            "created_at": _now(),
            "updated_at": _now(),
        }
        current = _write_journal(journal_file, payload, expected_uid=expected_uid)
    else:
        current = existing
        operation_id = str(current["operation_id"])
        ports = current.get("ports")
        if not isinstance(ports, Mapping) or ports != {"http": http_handoff_port, "https": https_handoff_port}:
            raise ActivationError("first-adoption resume ports disagree with the journal")
        journal_publication = current.get("publication")
        if (
            not isinstance(journal_publication, Mapping)
            or journal_publication.get("path") != str(publication_file)
            or journal_publication.get("payload_sha256")
            != _load_publication(publication_file).get("payload_sha256")
        ):
            raise ActivationError(
                "first-adoption resume publication disagrees with the journal"
            )

    def advance(phase: str, **extra: object) -> None:
        nonlocal current
        payload = {key: value for key, value in current.items() if key not in {"kind", "document_sha256"}}
        payload.update(extra)
        payload["phase"] = phase
        payload["updated_at"] = _now()
        current = _write_journal(journal_file, payload, expected_uid=expected_uid)

    baseline = current.get("baseline")
    if not isinstance(baseline, Mapping):
        raise ActivationError("first-adoption journal baseline is invalid")
    phase_order = {
        "planned": 0,
        "handoff_ready": 1,
        "redirected": 2,
        "legacy_stopped": 3,
        "background_handoff": 4,
        "final_edge_ready": 5,
        "redirect_removed": 6,
        "complete": 7,
    }
    if current.get("phase") not in phase_order:
        raise ActivationError("first-adoption journal phase is invalid")

    probe_urls = _publication_probes(_load_publication(publication_file))
    continuous = ContinuityProbeSession(
        release_digest=release.name,
        urls=probe_urls,
        http_probe=continuity_probe or probe_call,
        websocket_probe=continuity_probe or _probe_websocket,
    ).start()
    continuity_evidence: dict[str, object] | None = None

    try:
        if phase_order[str(current["phase"])] <= phase_order["planned"]:
            for name in HANDOFF_FILES:
                payload, _source = _read_install_source(rendered_units / name, expected_uid=expected_uid)
                _atomic_install(unit_root / name, payload, expected_uid=expected_uid, mode=0o644)
            if command.status(["/usr/bin/systemctl", "daemon-reload"]) != 0:
                raise ActivationError("temporary edge unit reload failed")
            for unit in (*HANDOFF_SOCKET_UNITS, HANDOFF_SERVICE_UNIT):
                if command.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                    raise ActivationError(f"temporary edge failed readiness: {unit}")
            high_inodes = {
                "http": listener_call(http_handoff_port),
                "https": listener_call(https_handoff_port),
            }
            statuses, refused = _run_probes(probe_urls, probe=probe_call)
            if refused or any(status is None or status >= 500 for status in statuses.values()):
                raise ActivationError("temporary edge route probe failed")
            advance("handoff_ready", handoff_socket_inodes=high_inodes, handoff_probe_statuses=statuses)

        if phase_order[str(current["phase"])] <= phase_order["handoff_ready"]:
            redirect_evidence = {}
            for family in ("ipv4", "ipv6"):
                family_baseline = baseline.get(family)
                if not isinstance(family_baseline, Mapping):
                    raise ActivationError("first-adoption family baseline is invalid")
                redirect_evidence[family] = _apply_redirect_family(
                    family,
                    operation_id=operation_id,
                    http_port=http_handoff_port,
                    https_port=https_handoff_port,
                    baseline_unrelated_sha256=str(family_baseline["unrelated_sha256"]),
                    runner=command,
                    binaries=binaries,
                )
            statuses, refused = _run_probes(probe_urls, probe=probe_call)
            if refused or any(status is None or status >= 500 for status in statuses.values()):
                raise ActivationError("redirected public route probe failed")
            advance("redirected", redirect_evidence=redirect_evidence, redirected_probe_statuses=statuses)

        if phase_order[str(current["phase"])] <= phase_order["redirected"]:
            if command.status(["/usr/bin/systemctl", "stop", "devops-console.service"]) != 0:
                raise ActivationError("legacy Console could not be stopped behind the handoff")
            advance("legacy_stopped")

        if phase_order[str(current["phase"])] <= phase_order["legacy_stopped"]:
            handoff_evidence = (
                None
                if after_legacy_console_stopped is None
                else dict(after_legacy_console_stopped(operation_id))
            )
            advance("background_handoff", legacy_stop_handoff=handoff_evidence)

        if phase_order[str(current["phase"])] <= phase_order["background_handoff"]:
            for unit in FINAL_EDGE_UNITS:
                if command.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                    raise ActivationError(f"final edge listener failed readiness: {unit}")
            final_inodes = {"http": listener_call(80), "https": listener_call(443)}
            statuses, refused = _run_probes(probe_urls, probe=probe_call)
            if refused or any(status is None or status >= 500 for status in statuses.values()):
                raise ActivationError("final edge public route probe failed")
            advance("final_edge_ready", final_socket_inodes=final_inodes, final_probe_statuses=statuses)

        if phase_order[str(current["phase"])] <= phase_order["final_edge_ready"]:
            removal = {}
            for family in ("ipv6", "ipv4"):
                family_baseline = baseline[family]
                if not isinstance(family_baseline, Mapping):
                    raise ActivationError("first-adoption family baseline is invalid")
                removal[family] = _remove_redirect_family(
                    family,
                    operation_id=operation_id,
                    http_port=http_handoff_port,
                    https_port=https_handoff_port,
                    baseline_unrelated_sha256=str(family_baseline["unrelated_sha256"]),
                    runner=command,
                    binaries=binaries,
                )
            statuses, refused = _run_probes(probe_urls, probe=probe_call)
            if refused or any(status is None or status >= 500 for status in statuses.values()):
                raise ActivationError("post-handoff public route probe failed")
            advance("redirect_removed", redirect_removal=removal, post_handoff_probe_statuses=statuses)

        if phase_order[str(current["phase"])] <= phase_order["redirect_removed"]:
            for unit in (HANDOFF_SERVICE_UNIT, *reversed(HANDOFF_SOCKET_UNITS)):
                _disable_stop_exact_unit(
                    command, unit, label="temporary public handoff unit"
                )
            prior_files = current.get("prior_files")
            if not isinstance(prior_files, Mapping):
                raise ActivationError("temporary edge rollback file graph is invalid")
            _restore_prepared_graph(
                {"prior_units": {}, "prior_files": prior_files},
                runner=command,
                expected_uid=expected_uid,
            )
            continuity_evidence = continuous.finish()
            advance(
                "complete",
                continuity_probe=continuity_evidence,
                completed_at=_now(),
            )
        return current
    except BaseException as error:
        if continuity_evidence is None:
            continuous.stop_unverified()
        rollback_errors: list[str] = []
        # Keep the high-port edge alive while the legacy listener is restored.
        for unit in reversed(FINAL_EDGE_UNITS):
            try:
                _disable_stop_exact_unit(
                    command, unit, label="final public rollback unit"
                )
            except BaseException:
                rollback_errors.append(f"final-edge:{unit}")
        legacy = current.get("legacy_console")
        if isinstance(legacy, Mapping) and legacy.get("active") is True:
            if command.status(["/usr/bin/systemctl", "start", "devops-console.service"]) != 0:
                rollback_errors.append("legacy-console")
        for family in ("ipv6", "ipv4"):
            try:
                family_baseline = baseline[family]
                if not isinstance(family_baseline, Mapping):
                    raise ActivationError("first-adoption family baseline is invalid")
                _remove_redirect_family(
                    family,
                    operation_id=operation_id,
                    http_port=http_handoff_port,
                    https_port=https_handoff_port,
                    baseline_unrelated_sha256=str(family_baseline["unrelated_sha256"]),
                    runner=command,
                    binaries=binaries,
                )
            except BaseException:
                rollback_errors.append(f"redirect-{family}")
        for unit in (HANDOFF_SERVICE_UNIT, *reversed(HANDOFF_SOCKET_UNITS)):
            try:
                _disable_stop_exact_unit(
                    command, unit, label="temporary public rollback unit"
                )
            except BaseException:
                rollback_errors.append(f"handoff-edge:{unit}")
        try:
            prior_files = current.get("prior_files")
            if isinstance(prior_files, Mapping):
                _restore_prepared_graph(
                    {"prior_units": {}, "prior_files": prior_files},
                    runner=command,
                    expected_uid=expected_uid,
                )
        except BaseException:
            rollback_errors.append("temporary-unit-files")
        advance("rolled_back", rollback_errors=rollback_errors, rolled_back_at=_now())
        suffix = "" if not rollback_errors else f"; rollback incomplete: {', '.join(rollback_errors)}"
        raise ActivationError(f"first-adoption handoff failed and was rolled back: {error}{suffix}") from error


def rollback_first_adoption_handoff(
    *,
    journal_file: Path,
    expected_uid: int,
    runner: CommandRunner,
    binaries: Mapping[str, Path] = XTABLES_BINARIES,
    probe: Callable[[str], tuple[int | None, bool]] | None = None,
    listener_reader: Callable[[int], int] | None = None,
) -> dict[str, object]:
    """Reverse a completed public first-adoption using its exact journal."""

    if os.geteuid() != expected_uid:
        raise ActivationError("public handoff rollback must run as the authority UID")
    current = _load_journal(
        _absolute(journal_file, "first-adoption journal"), expected_uid=expected_uid
    )
    if current is None:
        raise ActivationError("public handoff rollback journal is absent")
    if current.get("phase") == "rolled_back":
        return current
    operation_id = str(current.get("operation_id"))
    ports = current.get("ports")
    baseline = current.get("baseline")
    legacy = current.get("legacy_console")
    if not all(isinstance(value, Mapping) for value in (ports, baseline, legacy)):
        raise ActivationError("public handoff rollback journal is incomplete")
    listener = listener_reader or _tcp_listener_inode
    probe_call = probe or _probe_url
    publication = current.get("publication")
    if not isinstance(publication, Mapping):
        raise ActivationError("public handoff rollback publication is invalid")
    # Reuse the already installed high-port graph while the final edge still
    # serves traffic; redirect is published before either listener is stopped.
    for unit in (*HANDOFF_SOCKET_UNITS, HANDOFF_SERVICE_UNIT):
        if runner.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
            raise ActivationError("temporary edge could not start for rollback")
    listener(int(ports["http"]))
    listener(int(ports["https"]))
    for family in ("ipv4", "ipv6"):
        family_baseline = baseline.get(family)
        if not isinstance(family_baseline, Mapping):
            raise ActivationError("public handoff rollback baseline is invalid")
        _apply_redirect_family(
            family,
            operation_id=operation_id,
            http_port=int(ports["http"]),
            https_port=int(ports["https"]),
            baseline_unrelated_sha256=str(family_baseline["unrelated_sha256"]),
            runner=runner,
            binaries=binaries,
        )
    for unit in reversed(FINAL_EDGE_UNITS):
        _disable_stop_exact_unit(
            runner, unit, label="final public rollback unit"
        )
    if legacy.get("active") is True and runner.status(
        ["/usr/bin/systemctl", "start", "devops-console.service"]
    ) != 0:
        raise ActivationError("legacy Console could not restart during rollback")
    for family in ("ipv6", "ipv4"):
        family_baseline = baseline[family]
        if not isinstance(family_baseline, Mapping):
            raise ActivationError("public handoff rollback baseline is invalid")
        _remove_redirect_family(
            family,
            operation_id=operation_id,
            http_port=int(ports["http"]),
            https_port=int(ports["https"]),
            baseline_unrelated_sha256=str(family_baseline["unrelated_sha256"]),
            runner=runner,
            binaries=binaries,
        )
    for unit in (HANDOFF_SERVICE_UNIT, *reversed(HANDOFF_SOCKET_UNITS)):
        _disable_stop_exact_unit(
            runner, unit, label="temporary public rollback unit"
        )
    publication_path = Path(str(publication.get("path", "")))
    statuses, refused = _run_probes(
        _publication_probes(_load_publication(publication_path)),
        probe=probe_call,
    )
    if refused or any(status is None or status >= 500 for status in statuses.values()):
        raise ActivationError("legacy public routes failed after rollback")
    payload = {
        key: value
        for key, value in current.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload.update(
        {
            "phase": "rolled_back",
            "rollback_probe_statuses": statuses,
            "rolled_back_at": _now(),
            "updated_at": _now(),
        }
    )
    return _write_journal(journal_file, payload, expected_uid=expected_uid)


def _sqlite_identity(path: Path) -> dict[str, object]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ActivationError(f"SQLite authority store is unsafe: {path}")
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30.0)) as connection:
        check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        row = connection.execute(
            "SELECT schema_version, database_generation, state_revision, observation_revision "
            "FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
    if check != "ok" or row is None or len(row) != 4:
        raise ActivationError("SQLite authority store integrity or generation is invalid")
    return {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "sha256": _sha256_file(path),
        "quick_check": check,
        "schema_version": int(row[0]),
        "database_generation": str(row[1]),
        "state_revision": int(row[2]),
        "observation_revision": int(row[3]),
    }


def _maintenance_api(release: Path):
    package_root = release / "skills/codex-dev-coordinator/scripts"
    package_text = str(package_root)
    if package_text not in sys.path:
        sys.path.insert(0, package_text)
    try:
        from devcoordinator.maintenance import (  # type: ignore[import-not-found]
            CONTROL_PLANE_MAINTENANCE_SCOPE,
            PUBLIC_MAINTENANCE_MESSAGE,
            activate_maintenance,
            clear_maintenance,
            load_maintenance_state,
        )
    except ImportError as error:
        raise ActivationError("immutable maintenance contract is unavailable") from error
    return (
        CONTROL_PLANE_MAINTENANCE_SCOPE,
        PUBLIC_MAINTENANCE_MESSAGE,
        activate_maintenance,
        clear_maintenance,
        load_maintenance_state,
    )


def _storage_split_api(release: Path) -> tuple[Callable[..., object], ...]:
    """Load the storage split only from the immutable release being activated."""

    package_root = release / "skills/codex-dev-coordinator/scripts"
    package = package_root / "devcoordinator"
    required = {
        "storage_split": package / "storage_split.py",
        "inventory_projection": package / "inventory_projection.py",
    }
    if any(not path.is_file() or path.is_symlink() for path in required.values()):
        raise ActivationError("immutable release lacks the logical storage split contract")
    package_text = str(package_root)
    if package_text not in sys.path:
        sys.path.insert(0, package_text)
    loaded_package = sys.modules.get("devcoordinator")
    if loaded_package is not None:
        source = Path(str(getattr(loaded_package, "__file__", ""))).resolve()
        if package.resolve() not in source.parents:
            raise ActivationError(
                "another devcoordinator package is already loaded; refusing a mixed-release split"
            )
    try:
        storage = importlib.import_module("devcoordinator.storage_split")
        inventory = importlib.import_module("devcoordinator.inventory_projection")
    except ImportError as error:
        raise ActivationError("immutable logical storage split could not be loaded") from error
    for module, source in ((storage, required["storage_split"]), (inventory, required["inventory_projection"])):
        if Path(str(getattr(module, "__file__", ""))).resolve() != source.resolve():
            raise ActivationError("logical storage split module is not from the activated release")
    return (
        storage.split_legacy_storage,
        storage.verify_storage_split_attestation,
        inventory.read_sealed_inventory_store,
        inventory.publish_projection,
        inventory.verify_inventory_store,
        inventory.read_projection,
    )


def _regular_file_identity(path: Path, *, expected_uid: int) -> dict[str, object]:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o007
    ):
        raise ActivationError(f"published file identity is unsafe: {path}")
    return {
        "path": str(path),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "sha256": _sha256_file(path),
    }


def _retained_inventory_counts(envelope: Mapping[str, object]) -> dict[str, int]:
    inventory = envelope.get("inventory")
    if not isinstance(inventory, Mapping):
        raise ActivationError("retained inventory envelope is invalid")
    repositories = inventory.get("repositories")
    servers = inventory.get("servers")
    docker = inventory.get("docker")
    containers = docker.get("containers") if isinstance(docker, Mapping) else None
    if (
        not isinstance(repositories, list)
        or not repositories
        or not isinstance(servers, list)
        or not isinstance(containers, list)
        or any(not isinstance(item, Mapping) for item in repositories)
        or any(not isinstance(item, Mapping) for item in servers)
        or any(not isinstance(item, Mapping) for item in containers)
    ):
        raise ActivationError("retained inventory has no attributable repositories")
    return {
        "repositories": len(repositories),
        "servers": len(servers),
        "containers": len(containers),
    }


def adopt_authority_database(
    *,
    release: Path,
    source_database: Path,
    authority_database: Path,
    retained_source_database: Path | None = None,
    inventory_database: Path,
    inventory_publication: Path,
    split_attestation: Path,
    pointer_file: Path,
    maintenance_root: Path,
    maintenance_gid: int,
    authority_owner_uid: int,
    authority_owner_gid: int,
    inventory_owner_uid: int,
    inventory_owner_gid: int,
    operation_journal: Path,
    console_access_source: Path | None = None,
    console_access_destination: Path | None = None,
    console_access_source_uid: int | None = None,
    console_access_destination_uid: int | None = None,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Fence the old writer and create the logical authority/inventory split."""

    if os.geteuid() != expected_uid:
        raise ActivationError("authority database adoption must run as the authority UID")
    command = runner or CommandRunner()
    release = _absolute(release, "authority adoption release")
    if (
        release.parent != IMMUTABLE_RELEASE_ROOT
        or re.fullmatch(r"[0-9a-f]{64}", release.name) is None
    ):
        raise ActivationError("authority adoption release is not immutable")
    source_database = _absolute(source_database, "legacy authority database")
    authority_database = _absolute(authority_database, "final authority database")
    source_rotated = source_database == authority_database
    if source_rotated:
        if retained_source_database is None:
            raise ActivationError(
                "in-place first adoption requires an exact retained source path"
            )
        retained_source_database = _absolute(
            retained_source_database, "retained legacy authority database"
        )
        if retained_source_database.parent != source_database.parent:
            raise ActivationError("legacy authority rotation must be one atomic rename")
    elif retained_source_database is not None:
        raise ActivationError(
            "a retained source path is valid only for in-place first adoption"
        )
    split_source = (
        retained_source_database if source_rotated else source_database
    )
    if split_source is None:
        raise ActivationError("logical split source is unavailable")
    inventory_database = _absolute(inventory_database, "retained inventory database")
    inventory_publication = _absolute(
        inventory_publication, "retained inventory publication"
    )
    split_attestation = _absolute(split_attestation, "storage split attestation")
    pointer_file = _absolute(pointer_file, "authority generation pointer")
    operation_journal = _absolute(
        operation_journal, "authority adoption operation journal"
    )
    destinations = {
        authority_database,
        inventory_database,
        inventory_publication,
        split_attestation,
        pointer_file,
    }
    if (not source_rotated and source_database in destinations) or len(destinations) != 5:
        raise ActivationError("authority adoption paths must be distinct")
    (
        split,
        verify_split,
        read_inventory,
        publish_inventory,
        verify_inventory,
        read_publication,
    ) = _storage_split_api(release)
    adoption_binding = {
        "release_digest": release.name,
        "source_database": str(source_database),
        "authority_database": str(authority_database),
        "retained_source_database": str(retained_source_database)
        if retained_source_database is not None
        else None,
        "inventory_database": str(inventory_database),
        "inventory_publication": str(inventory_publication),
        "split_attestation": str(split_attestation),
        "pointer_file": str(pointer_file),
        "maintenance_root": str(maintenance_root),
        "maintenance_gid": maintenance_gid,
        "authority_owner_uid": authority_owner_uid,
        "authority_owner_gid": authority_owner_gid,
        "inventory_owner_uid": inventory_owner_uid,
        "inventory_owner_gid": inventory_owner_gid,
    }
    adoption_journal = _load_private_journal(
        operation_journal,
        kind=AUTHORITY_ADOPTION_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    command = runner or CommandRunner()
    if adoption_journal is None:
        first_adoption_outputs = set(destinations)
        if source_rotated:
            first_adoption_outputs.remove(authority_database)
            first_adoption_outputs.add(split_source)
        for path in first_adoption_outputs:
            if path.exists() or path.is_symlink():
                raise ActivationError(
                    f"first-adoption destination already exists; explicit recovery is required: {path}"
                )
        source_initial = _regular_file_identity(
            source_database, expected_uid=expected_uid
        )
        legacy_active, legacy_enabled = _unit_state(
            command, "devcoordinator-broker.service"
        )
        if not legacy_active:
            raise ActivationError(
                "authority adoption requires the active legacy writer"
            )
        operation_id = str(uuid.uuid4())
        split_journal = operation_journal.with_name(
            operation_journal.name + ".storage-split"
        )
        adoption_journal = _write_private_journal(
            operation_journal,
            kind=AUTHORITY_ADOPTION_JOURNAL_KIND,
            payload={
                "operation_id": operation_id,
                "binding": adoption_binding,
                "phase": "planned",
                "source_initial": source_initial,
                "legacy_unit": {
                    "active": legacy_active,
                    "enabled": legacy_enabled,
                },
                "split_journal": str(split_journal),
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    else:
        if adoption_journal.get("binding") != adoption_binding:
            raise ActivationError(
                "authority adoption journal belongs to another operation"
            )
        operation_id = str(adoption_journal.get("operation_id"))
        source_initial = adoption_journal.get("source_initial")
        legacy_unit = adoption_journal.get("legacy_unit")
        split_journal_value = adoption_journal.get("split_journal")
        if (
            not isinstance(source_initial, Mapping)
            or not isinstance(legacy_unit, Mapping)
            or legacy_unit.get("active") is not True
            or type(legacy_unit.get("enabled")) is not bool
            or not isinstance(split_journal_value, str)
        ):
            raise ActivationError("authority adoption journal contract is invalid")
        legacy_active = True
        legacy_enabled = bool(legacy_unit["enabled"])
        split_journal = _absolute(
            Path(split_journal_value), "authority storage split journal"
        )

    def persist_adoption(phase: str, **updates: object) -> None:
        nonlocal adoption_journal
        payload = {
            key: value
            for key, value in adoption_journal.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(updates)
        payload["phase"] = phase
        payload["updated_at"] = _now()
        adoption_journal = _write_private_journal(
            operation_journal,
            kind=AUTHORITY_ADOPTION_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )

    if adoption_journal.get("phase") == "complete":
        result = adoption_journal.get("result")
        if not isinstance(result, Mapping):
            raise ActivationError("complete authority adoption lacks its result")
        recorded = cutover.read_private_json(pointer_file, uid=expected_uid)
        if recorded != result:
            raise ActivationError("authority adoption pointer changed after completion")
        return dict(result)
    scope, message, activate_maintenance, _clear, load_maintenance = _maintenance_api(release)
    activate_maintenance(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        deployment_id=operation_id,
        scope=scope,
        message=message,
        retry_after_seconds=5,
        started_at=str(adoption_journal["created_at"]),
        maintenance_root=maintenance_root,
    )
    if failpoint is not None:
        failpoint("authority-maintenance-before-journal")
    persist_adoption("maintenance_active")
    lock_path = source_database.parent / ".broker-service.lock"
    descriptor: int | None = None
    legacy_state_observed = True
    split_document: Mapping[str, object] | None = None
    publication_identity: Mapping[str, object] | None = None
    rotation_identity: Mapping[str, object] | None = None
    try:
        currently_active = command.status(
            [
                "/usr/bin/systemctl",
                "is-active",
                "--quiet",
                "devcoordinator-broker.service",
            ]
        ) == 0
        if currently_active and command.status(
            ["/usr/bin/systemctl", "stop", "devcoordinator-broker.service"]
        ) != 0:
            raise ActivationError(
                "legacy authority writer did not stop behind maintenance"
            )
        descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        lock_info = os.fstat(descriptor)
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != expected_uid or stat.S_IMODE(lock_info.st_mode) != 0o600:
            raise ActivationError("legacy writer fence identity is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ActivationError("legacy authority writer fence is still held") from error
        checkpoint_source = (
            source_database if source_database.exists() else split_source
        )
        if not checkpoint_source.exists() or checkpoint_source.is_symlink():
            raise ActivationError("legacy authority source is unavailable during resume")
        with closing(sqlite3.connect(str(checkpoint_source), timeout=30.0)) as source:
            checkpoint = source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise ActivationError("legacy authority WAL could not be fenced")
        if failpoint is not None:
            failpoint("authority-writer-fenced-before-journal")
        persist_adoption("writer_fenced")
        if source_rotated:
            rotation_identity = source_initial
            if source_database.exists() and not split_source.exists():
                current_source = _regular_file_identity(
                    source_database, expected_uid=expected_uid
                )
                for field in ("device", "inode", "size", "mtime_ns", "sha256"):
                    if current_source[field] != rotation_identity[field]:
                        raise ActivationError(
                            "legacy authority changed before atomic rotation"
                        )
                os.replace(source_database, split_source)
                directory = os.open(
                    source_database.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            elif source_database.exists() or not split_source.exists():
                raise ActivationError(
                    "legacy authority rotation is contradictory during resume"
                )
            rotated_identity = _regular_file_identity(
                split_source, expected_uid=expected_uid
            )
            for field in ("device", "inode", "size", "mtime_ns", "sha256"):
                if rotated_identity[field] != rotation_identity[field]:
                    raise ActivationError("legacy authority changed during atomic rotation")
            if failpoint is not None:
                failpoint("authority-rotation-before-journal")
            persist_adoption("source_rotated")
        candidate_schema = (
            int(_sqlite_identity(authority_database)["schema_version"])
            if authority_database.exists()
            else None
        )
        recorded_split = adoption_journal.get("storage_split")
        if candidate_schema == 12:
            if not isinstance(recorded_split, Mapping):
                raise ActivationError(
                    "split authority exists without its storage-split journal"
                )
            split_document = verify_split(
                recorded_split,
                source_database=split_source,
                authority_database=authority_database,
                inventory_database=inventory_database,
                expected_uid=expected_uid,
                authority_owner_uid=authority_owner_uid,
                inventory_owner_uid=inventory_owner_uid,
            )
        elif candidate_schema is None:
            split_document = split(
                source_database=split_source,
                authority_database=authority_database,
                inventory_database=inventory_database,
                attestation_path=split_attestation,
                expected_uid=expected_uid,
                authority_owner_uid=authority_owner_uid,
                authority_owner_gid=authority_owner_gid,
                inventory_owner_uid=inventory_owner_uid,
                inventory_owner_gid=inventory_owner_gid,
                attestation_owner_gid=maintenance_gid,
                console_access_source=console_access_source,
                console_access_destination=console_access_destination,
                console_access_source_uid=console_access_source_uid,
                console_access_destination_uid=console_access_destination_uid,
                journal_path=split_journal,
                failpoint=failpoint,
            )
            split_document = verify_split(
                split_document,
                source_database=split_source,
                authority_database=authority_database,
                inventory_database=inventory_database,
                expected_uid=expected_uid,
                authority_owner_uid=authority_owner_uid,
                inventory_owner_uid=inventory_owner_uid,
            )
            if recorded_split is not None and recorded_split != split_document:
                raise ActivationError("authority storage split changed during resume")
            if failpoint is not None:
                failpoint("authority-storage-split-before-journal")
            persist_adoption(
                "storage_split_complete", storage_split=split_document
            )
        else:
            raise ActivationError(
                "authority candidate has an unsupported schema during adoption"
            )

        retained = read_inventory(
            inventory_database,
            expected_owner_uid=inventory_owner_uid,
        )
        envelope = retained.get("envelope")
        if not isinstance(envelope, Mapping):
            raise ActivationError("logical split did not seed a retained inventory envelope")
        inventory_counts = _retained_inventory_counts(envelope)
        if inventory_publication.exists() or inventory_publication.is_symlink():
            if read_publication(
                inventory_publication,
                expected_owner_uid=inventory_owner_uid,
            ) != dict(envelope):
                raise ActivationError(
                    "retained inventory publication is contradictory during resume"
                )
        else:
            publish_inventory(
                inventory_publication,
                envelope,
                owner_uid=inventory_owner_uid,
                owner_gid=inventory_owner_gid,
            )
        inventory_state = verify_inventory(
            inventory_database,
            inventory_publication,
            expected_owner_uid=inventory_owner_uid,
        )
        if inventory_state.get("generation") != envelope.get("generation"):
            raise ActivationError("retained inventory publication generation disagrees")
        publication_identity = _regular_file_identity(
            inventory_publication,
            expected_uid=inventory_owner_uid,
        )
        if failpoint is not None:
            failpoint("authority-inventory-publication-before-journal")
        persist_adoption(
            "inventory_published",
            inventory_publication=dict(publication_identity),
            inventory_state=dict(inventory_state),
            inventory_counts=inventory_counts,
        )
        final_identity = _sqlite_identity(authority_database)
        source_evidence = split_document.get("source")
        if not isinstance(source_evidence, Mapping):
            raise ActivationError("logical split source evidence is invalid")
        pointer = cutover.seal(
            AUTHORITY_ADOPTION_KIND,
            {
                "operation_id": operation_id,
                "release_digest": release.name,
                "source": dict(source_evidence),
                "authority": final_identity,
                "inventory": {
                    "database": str(inventory_database),
                    "publication": dict(publication_identity),
                    "generation": inventory_state["generation"],
                    "payload_sha256": inventory_state["payload_sha256"],
                    "counts": inventory_counts,
                },
                "storage_split": {
                    "path": str(split_attestation),
                    "document_sha256": split_document["document_sha256"],
                    "base_authority_sha256": split_document["authority"]["file"]["sha256"],
                },
                "pointer_path": str(pointer_file),
                "legacy_source_original_path": str(source_database),
                "source_rotated": source_rotated,
                "retained_source_is_rollback": True,
                "legacy_unit": {"active": legacy_active, "enabled": legacy_enabled},
                "maintenance": {"deployment_id": operation_id, "root": str(maintenance_root)},
                "created_at": adoption_journal["created_at"],
            },
        )
        if pointer_file.exists() or pointer_file.is_symlink():
            if cutover.read_private_json(pointer_file, uid=expected_uid) != pointer:
                raise ActivationError(
                    "authority adoption pointer is contradictory during resume"
                )
        else:
            _atomic_private(
                pointer_file,
                _canonical(pointer) + b"\n",
                expected_uid=expected_uid,
            )
        if failpoint is not None:
            failpoint("authority-pointer-before-journal")
        persist_adoption("complete", result=pointer)
        if _sha256_file(authority_database) != final_identity["sha256"]:
            raise ActivationError("authority destination changed after pointer publication")
        return pointer
    except PowerLossSimulation:
        raise
    except BaseException as error:
        cleanup_errors: list[str] = []
        if pointer_file.exists() and not pointer_file.is_symlink():
            pointer_file.unlink(missing_ok=True)
        if inventory_publication.exists() or inventory_publication.is_symlink():
            try:
                if publication_identity is not None:
                    if _regular_file_identity(
                        inventory_publication, expected_uid=inventory_owner_uid
                    ) != publication_identity:
                        raise ActivationError("retained publication identity changed")
                else:
                    if "envelope" not in locals() or read_publication(
                        inventory_publication,
                        expected_owner_uid=inventory_owner_uid,
                    ) != dict(envelope):
                        raise ActivationError("retained publication payload changed")
                inventory_publication.unlink()
            except BaseException as cleanup_error:
                cleanup_errors.append(f"inventory-publication: {cleanup_error}")
        if split_document is not None:
            try:
                verify_split(
                    split_document,
                    source_database=split_source,
                    authority_database=authority_database,
                    inventory_database=inventory_database,
                    expected_uid=expected_uid,
                    authority_owner_uid=authority_owner_uid,
                    inventory_owner_uid=inventory_owner_uid,
                )
            except BaseException as verification_error:
                cleanup_errors.append(f"storage-split: {verification_error}")
            else:
                for path in (split_attestation, inventory_database, authority_database):
                    path.unlink(missing_ok=True)
        if source_rotated and split_source.exists():
            try:
                if source_database.exists() or source_database.is_symlink():
                    raise ActivationError("original authority path was recreated concurrently")
                rotated = _regular_file_identity(
                    split_source, expected_uid=expected_uid
                )
                if rotation_identity is None or any(
                    rotated[field] != rotation_identity[field]
                    for field in ("device", "inode", "size", "mtime_ns", "sha256")
                ):
                    raise ActivationError("retained legacy source changed before rollback")
                os.replace(split_source, source_database)
                directory = os.open(
                    source_database.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except BaseException as rotation_error:
                cleanup_errors.append(f"legacy-source-rotation: {rotation_error}")
        if legacy_state_observed:
            try:
                _restore_units(
                    command,
                    {
                        "devcoordinator-broker.service": (
                            legacy_active,
                            legacy_enabled,
                        )
                    },
                )
            except BaseException as restore_error:
                cleanup_errors.append(f"legacy-writer: {restore_error}")
        _scope, _message, _activate, clear, _load = _maintenance_api(release)
        try:
            clear(
                expected_uid=expected_uid,
                expected_gid=maintenance_gid,
                deployment_id=operation_id,
                maintenance_root=maintenance_root,
            )
        except BaseException as clear_error:
            cleanup_errors.append(f"maintenance: {clear_error}")
        suffix = (
            ""
            if not cleanup_errors
            else "; rollback incomplete (" + "; ".join(cleanup_errors) + ")"
        )
        raise ActivationError(
            f"authority adoption failed and rollback was attempted: {error}{suffix}"
        ) from error
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def finalize_authority_adoption(
    adoption: Mapping[str, object],
    *,
    release: Path,
    maintenance_gid: int,
    expected_uid: int,
) -> None:
    verified = cutover.verify_seal(
        adoption,
        kind=AUTHORITY_ADOPTION_KIND,
        fields=(
            "operation_id",
            "release_digest",
            "source",
            "authority",
            "inventory",
            "storage_split",
            "pointer_path",
            "legacy_source_original_path",
            "source_rotated",
            "retained_source_is_rollback",
            "legacy_unit",
            "maintenance",
            "created_at",
        ),
    )
    maintenance = verified["maintenance"]
    if not isinstance(maintenance, Mapping):
        raise ActivationError("authority adoption maintenance evidence is invalid")
    _scope, _message, _activate, clear, _load = _maintenance_api(release)
    clear(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        deployment_id=str(verified["operation_id"]),
        maintenance_root=Path(str(maintenance["root"])),
    )


def _authority_maintenance_release_journal(
    operation_journal: Path,
) -> Path:
    return operation_journal.with_name(
        operation_journal.name + ".maintenance-release"
    )


def _authority_maintenance_binding(
    adoption: Mapping[str, object],
) -> tuple[Mapping[str, object], dict[str, object]]:
    verified = cutover.verify_seal(
        adoption,
        kind=AUTHORITY_ADOPTION_KIND,
        fields=(
            "operation_id",
            "release_digest",
            "source",
            "authority",
            "inventory",
            "storage_split",
            "pointer_path",
            "legacy_source_original_path",
            "source_rotated",
            "retained_source_is_rollback",
            "legacy_unit",
            "maintenance",
            "created_at",
        ),
    )
    maintenance = verified.get("maintenance")
    if (
        not isinstance(maintenance, Mapping)
        or maintenance.get("deployment_id") != verified["operation_id"]
        or maintenance.get("root") != str(CANONICAL_MAINTENANCE_ROOT)
    ):
        raise ActivationError(
            "authority adoption maintenance binding is invalid"
        )
    return verified, {
        "adoption_sha256": verified["document_sha256"],
        "operation_id": verified["operation_id"],
        "maintenance_root": maintenance["root"],
        "started_at": verified["created_at"],
    }


def release_authority_maintenance_for_first_adoption(
    adoption: Mapping[str, object],
    *,
    release: Path,
    maintenance_gid: int,
    operation_journal: Path,
    expected_uid: int,
) -> Mapping[str, object]:
    """Crash-safely open the final authority immediately before API proof."""

    _verified, binding = _authority_maintenance_binding(adoption)
    journal_path = _authority_maintenance_release_journal(
        _absolute(operation_journal, "authority adoption journal")
    )
    journal = _load_private_journal(
        journal_path,
        kind=AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    _scope, _message, _activate, clear, load = _maintenance_api(release)
    if journal is None:
        current = load(
            expected_uid=expected_uid,
            expected_gid=maintenance_gid,
            maintenance_root=CANONICAL_MAINTENANCE_ROOT,
        )
        if (
            current is None
            or current.deployment_id != binding["operation_id"]
            or current.started_at != binding["started_at"]
        ):
            raise ActivationError(
                "authority maintenance was not held before release"
            )
        journal = _write_private_journal(
            journal_path,
            kind=AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND,
            payload={
                "binding": binding,
                "phase": "planned",
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    elif journal.get("binding") != binding:
        raise ActivationError(
            "authority maintenance release journal belongs to another adoption"
        )
    phase = journal.get("phase")
    if phase == "rearmed":
        raise ActivationError(
            "authority maintenance release was already rolled back"
        )
    if phase not in {"planned", "complete"}:
        raise ActivationError(
            "authority maintenance release journal phase is invalid"
        )
    current = load(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        maintenance_root=CANONICAL_MAINTENANCE_ROOT,
    )
    if phase == "complete":
        if current is not None:
            raise ActivationError(
                "completed authority maintenance release is active again"
            )
        result = journal.get("result")
        if not isinstance(result, Mapping):
            raise ActivationError(
                "authority maintenance release result is absent"
            )
        return dict(result)
    if current is not None:
        if (
            current.deployment_id != binding["operation_id"]
            or current.started_at != binding["started_at"]
        ):
            raise ActivationError(
                "another maintenance deployment replaced the adoption fence"
            )
        clear(
            expected_uid=expected_uid,
            expected_gid=maintenance_gid,
            deployment_id=str(binding["operation_id"]),
            maintenance_root=CANONICAL_MAINTENANCE_ROOT,
        )
    if load(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        maintenance_root=CANONICAL_MAINTENANCE_ROOT,
    ) is not None:
        raise ActivationError("authority maintenance release did not converge")
    result = {
        "released": True,
        "operation_id": binding["operation_id"],
        "maintenance_root": binding["maintenance_root"],
    }
    payload = {
        key: value
        for key, value in journal.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload.update(
        {"phase": "complete", "result": result, "updated_at": _now()}
    )
    _write_private_journal(
        journal_path,
        kind=AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND,
        payload=payload,
        expected_uid=expected_uid,
    )
    return result


def rearm_authority_maintenance_for_rollback(
    adoption: Mapping[str, object],
    *,
    release: Path,
    maintenance_gid: int,
    operation_journal: Path,
    expected_uid: int,
) -> Mapping[str, object]:
    """Reinstate the global fence before the first compensating mutation."""

    _verified, binding = _authority_maintenance_binding(adoption)
    journal_path = _authority_maintenance_release_journal(
        _absolute(operation_journal, "authority adoption journal")
    )
    journal = _load_private_journal(
        journal_path,
        kind=AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if journal is not None and journal.get("binding") != binding:
        raise ActivationError(
            "authority maintenance rollback journal belongs to another adoption"
        )
    scope, message, activate, _clear, load = _maintenance_api(release)
    state = activate(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        deployment_id=str(binding["operation_id"]),
        scope=scope,
        message=message,
        retry_after_seconds=5,
        started_at=str(binding["started_at"]),
        maintenance_root=CANONICAL_MAINTENANCE_ROOT,
    )
    observed = load(
        expected_uid=expected_uid,
        expected_gid=maintenance_gid,
        maintenance_root=CANONICAL_MAINTENANCE_ROOT,
    )
    if (
        observed is None
        or observed != state
        or observed.deployment_id != binding["operation_id"]
    ):
        raise ActivationError(
            "authority maintenance rollback fence did not converge"
        )
    payload = {
        "binding": binding,
        "phase": "rearmed",
        "result": {
            "rearmed": True,
            "operation_id": binding["operation_id"],
            "maintenance_root": binding["maintenance_root"],
        },
        "created_at": (
            journal["created_at"]
            if isinstance(journal, Mapping)
            and isinstance(journal.get("created_at"), str)
            else _now()
        ),
        "updated_at": _now(),
    }
    result = _write_private_journal(
        journal_path,
        kind=AUTHORITY_MAINTENANCE_RELEASE_JOURNAL_KIND,
        payload=payload,
        expected_uid=expected_uid,
    )
    return dict(result["result"])


def rollback_authority_adoption(
    adoption: Mapping[str, object],
    *,
    release: Path,
    maintenance_gid: int,
    expected_uid: int,
    runner: CommandRunner,
    operation_journal: Path | None = None,
    failpoint: Callable[[str], None] | None = None,
    legacy_writer_unfencer: Callable[[], Mapping[str, object]] | None = None,
    legacy_writer_verifier: Callable[[], Mapping[str, object]] | None = None,
) -> Mapping[str, object]:
    verified = cutover.verify_seal(
        adoption,
        kind=AUTHORITY_ADOPTION_KIND,
        fields=("operation_id", "release_digest", "source", "authority", "inventory", "storage_split", "pointer_path", "legacy_source_original_path", "source_rotated", "retained_source_is_rollback", "legacy_unit", "maintenance", "created_at"),
    )
    authority = verified["authority"]
    source = verified["source"]
    inventory = verified["inventory"]
    storage = verified["storage_split"]
    if not all(isinstance(value, Mapping) for value in (authority, source, inventory, storage)):
        raise ActivationError("authority adoption rollback identities are invalid")
    target = Path(str(authority["path"]))
    retained = Path(str(source["path"]))
    split_path = Path(str(storage["path"]))
    inventory_database = Path(str(inventory["database"]))
    publication = inventory.get("publication")
    if not isinstance(publication, Mapping):
        raise ActivationError("retained publication rollback identity is invalid")
    publication_path = Path(str(publication["path"]))
    pointer_path = Path(str(verified["pointer_path"]))
    journal: dict[str, object] | None = None
    if operation_journal is not None:
        operation_journal = _absolute(
            operation_journal, "authority adoption rollback journal"
        )
        journal = _load_private_journal(
            operation_journal,
            kind=AUTHORITY_ADOPTION_JOURNAL_KIND,
            expected_uid=expected_uid,
        )
        if (
            journal is None
            or journal.get("operation_id") != verified.get("operation_id")
            or journal.get("result") != verified
            or journal.get("phase")
            not in {"complete", "rolling_back", "rolled_back"}
        ):
            raise ActivationError(
                "authority rollback operation journal is contradictory"
            )
        if journal.get("phase") == "rolled_back":
            readiness = journal.get("legacy_writer_readiness")
            if not isinstance(readiness, Mapping):
                raise ActivationError(
                    "completed authority rollback omitted legacy-writer readiness"
                )
            return {
                "restored": True,
                "replayed": True,
                "legacy_writer_readiness": dict(readiness),
            }

    removed_value = journal.get("rollback_removed", []) if journal else []
    if not isinstance(removed_value, list):
        raise ActivationError("authority rollback removal journal is invalid")
    removed = list(removed_value)

    def persist_authority_rollback(phase: str, **updates: object) -> None:
        nonlocal journal
        if operation_journal is None or journal is None:
            return
        payload = {
            key: value
            for key, value in journal.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(updates)
        payload.update(
            {
                "phase": phase,
                "rollback_removed": list(removed),
                "updated_at": _now(),
            }
        )
        journal = _write_private_journal(
            operation_journal,
            kind=AUTHORITY_ADOPTION_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )

    rollback_validation = journal.get("rollback_validation") if journal else None
    if rollback_validation is not None and not isinstance(
        rollback_validation, Mapping
    ):
        raise ActivationError("authority rollback validation journal is invalid")
    (
        _split,
        verify_split,
        _read_inventory,
        _publish_inventory,
        _verify_inventory,
        _read_publication,
    ) = _storage_split_api(release)
    if rollback_validation is None:
        if not retained.exists() or _sha256_file(retained) != source["sha256"]:
            raise ActivationError(
                "retained rollback authority changed; refusing destructive rollback"
            )
        split_document = cutover.read_private_json(split_path, uid=expected_uid)
        if split_document.get("document_sha256") != storage.get("document_sha256"):
            raise ActivationError(
                "storage split attestation changed; refusing destructive rollback"
            )
        pointer_document = cutover.read_private_json(pointer_path, uid=expected_uid)
        if pointer_document != verified:
            raise ActivationError("authority adoption pointer changed before rollback")
        verify_split(
            split_document,
            source_database=retained,
            authority_database=target,
            inventory_database=inventory_database,
            expected_uid=expected_uid,
            authority_owner_uid=int(authority["owner_uid"]),
            inventory_owner_uid=int(publication["owner_uid"]),
        )
        if _sqlite_identity(target) != authority:
            raise ActivationError(
                "schema-v13 authority changed; refusing destructive rollback"
            )
        if _regular_file_identity(
            publication_path, expected_uid=int(publication["owner_uid"])
        ) != publication:
            raise ActivationError(
                "retained publication changed; refusing destructive rollback"
            )
        rollback_validation = {
            "retained": _regular_file_identity(
                retained, expected_uid=expected_uid
            ),
            "pointer_sha256": _sha256_file(pointer_path),
            "publication": _regular_file_identity(
                publication_path, expected_uid=int(publication["owner_uid"])
            ),
            "split_sha256": _sha256_file(split_path),
            "inventory": _regular_file_identity(
                inventory_database, expected_uid=int(publication["owner_uid"])
            ),
            "authority": _regular_file_identity(
                target, expected_uid=int(authority["owner_uid"])
            ),
        }
        persist_authority_rollback(
            "rolling_back", rollback_validation=rollback_validation
        )
    deletion_plan = (
        (pointer_path, expected_uid, verified, "pointer"),
        (publication_path, int(publication["owner_uid"]), publication, "publication"),
        (split_path, expected_uid, storage, "split-attestation"),
        (
            inventory_database,
            int(publication["owner_uid"]),
            rollback_validation["inventory"],
            "inventory",
        ),
        (target, int(authority["owner_uid"]), authority, "authority"),
    )
    for path, owner_uid, evidence, label in deletion_plan:
        path_text = str(path)
        if path_text in removed:
            if path.exists() or path.is_symlink():
                raise ActivationError(
                    f"removed authority rollback path reappeared: {label}"
                )
            continue
        if path.exists() or path.is_symlink():
            if label == "pointer":
                if cutover.read_private_json(path, uid=owner_uid) != evidence:
                    raise ActivationError("authority rollback pointer changed")
            elif label == "split-attestation":
                split_value = cutover.read_private_json(path, uid=owner_uid)
                if split_value.get("document_sha256") != storage.get("document_sha256"):
                    raise ActivationError("authority rollback split evidence changed")
            elif isinstance(evidence, Mapping):
                observed = (
                    _sqlite_identity(path)
                    if label == "authority"
                    else _regular_file_identity(path, expected_uid=owner_uid)
                )
                if observed != evidence:
                    raise ActivationError(
                        f"authority rollback {label} identity changed"
                    )
            else:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid:
                    raise ActivationError(
                        f"authority rollback {label} identity is unsafe"
                    )
            path.unlink()
        elif journal is None:
            raise ActivationError(
                f"authority rollback path vanished without a journal: {label}"
            )
        if failpoint is not None:
            failpoint(f"authority-rollback-before-journal:{label}")
        removed.append(path_text)
        persist_authority_rollback("rolling_back")
    if verified["source_rotated"] is True:
        original = Path(str(verified["legacy_source_original_path"]))
        if original != target or retained.parent != original.parent:
            raise ActivationError("legacy authority rotation rollback path is invalid")
        if retained.exists() and not original.exists():
            if _sha256_file(retained) != source["sha256"]:
                raise ActivationError("retained rollback source changed")
            os.replace(retained, original)
            directory = os.open(
                original.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        elif retained.exists() or not original.exists() or _sha256_file(original) != source["sha256"]:
            raise ActivationError(
                "legacy authority rotation rollback state is contradictory"
            )
        if failpoint is not None:
            failpoint("authority-rollback-rotation-before-journal")
        persist_authority_rollback("rolling_back", source_restored=True)
    elif verified["source_rotated"] is not False:
        raise ActivationError("legacy authority rotation evidence is invalid")
    legacy = verified["legacy_unit"]
    if not isinstance(legacy, Mapping):
        raise ActivationError("legacy unit rollback evidence is invalid")
    writer_unfenced: Mapping[str, object] = {"skipped": True}
    if legacy_writer_unfencer is not None:
        writer_unfenced = legacy_writer_unfencer()
        if not isinstance(writer_unfenced, Mapping):
            raise ActivationError(
                "legacy writer rollback unfence evidence is invalid"
            )
        persist_authority_rollback(
            "rolling_back", legacy_writer_unfenced=dict(writer_unfenced)
        )
    _restore_units(
        runner,
        {"devcoordinator-broker.service": (legacy.get("active") is True, legacy.get("enabled") is True)},
    )
    writer_readiness: Mapping[str, object] = {"skipped": True}
    if legacy_writer_verifier is not None:
        writer_readiness = legacy_writer_verifier()
        if not isinstance(writer_readiness, Mapping):
            raise ActivationError(
                "legacy writer rollback readiness evidence is invalid"
            )
    if failpoint is not None:
        failpoint("authority-rollback-unit-before-journal")
    persist_authority_rollback(
        "rolling_back",
        legacy_unit_restored=True,
        legacy_writer_unfenced=dict(writer_unfenced),
        legacy_writer_readiness=dict(writer_readiness),
    )
    finalize_authority_adoption(
        verified,
        release=release,
        maintenance_gid=maintenance_gid,
        expected_uid=expected_uid,
    )
    if failpoint is not None:
        failpoint("authority-rollback-maintenance-before-journal")
    persist_authority_rollback("rolled_back", maintenance_cleared=True)
    return {
        "restored": True,
        "replayed": False,
        "legacy_writer_unfenced": dict(writer_unfenced),
        "legacy_writer_readiness": dict(writer_readiness),
    }


def render_console_public_config(
    *,
    legacy_env: Path,
    expected_uid: int,
) -> bytes:
    legacy = _parse_private_env(legacy_env, expected_uid=expected_uid)
    domain = legacy.get("DOMAIN", "").strip().lower().strip(".")
    subdomain = legacy.get("CONSOLE_SUBDOMAIN", "console").strip().lower()
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain) is None:
        raise ActivationError("legacy Console DOMAIN is invalid")
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", subdomain) is None:
        raise ActivationError("legacy Console subdomain is invalid")
    values = {
        key: legacy[key].strip()
        for key in sorted(CONSOLE_PUBLIC_CONFIG_KEYS)
        if legacy.get(key, "").strip()
    }
    values.update(
        {
            "DOMAIN": domain,
            "CONSOLE_SUBDOMAIN": subdomain,
            "STATE_DIR": "/var/lib/devcoordinator-console",
            "ACME_WEBROOT": "/var/lib/devcoordinator-console/acme-unused",
            "PUBLIC_CONSOLE_ORIGIN": f"https://{subdomain}.{domain}",
            "COORDINATOR_URL": "http://127.0.0.1:29876",
            "COORDINATOR_AUTOSTART": "0",
            "COORDINATOR_REGISTRATION_REQUIRED": "0",
            "COORDINATOR_RETAINED_INVENTORY": "1",
            "BIND_HOST": "127.0.0.1",
        }
    )
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value or "\r" in value or "\x00" in value:
            raise ActivationError("legacy Console public configuration is unsafe")
    forbidden = {
        "SESSION_SECRET",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
        "COORDINATOR_TOKEN",
    }
    if forbidden & set(values):
        raise ActivationError("secret material entered the public Console configuration")
    return (
        "# Generated non-secret Console configuration. Credentials are systemd files.\n"
        + "".join(f"{key}={values[key]}\n" for key in sorted(values))
    ).encode("utf-8")


def install_edge_certbot_hook(
    *,
    release: Path,
    rollback_directory: Path,
    expected_uid: int = 0,
    hook_root: Path = CERTBOT_DEPLOY_HOOK_ROOT,
    runner: CommandRunner | None = None,
) -> dict[str, object]:
    """Replace the legacy SIGHUP hook with a credential-refresh restart.

    The immutable helper validates the renewed pair before restarting.  Ports
    remain owned by the socket units, and the helper proves their exact inode
    survives plus that the served leaf matches the renewed source.
    """

    if os.geteuid() != expected_uid:
        raise ActivationError("certbot hook migration must run as the authority UID")
    release = _absolute(release, "certbot hook release")
    if release.parent != IMMUTABLE_RELEASE_ROOT or re.fullmatch(r"[0-9a-f]{64}", release.name) is None:
        raise ActivationError("certbot hook release is not immutable")
    helper = release / "bin/devcoordinator-edge-cert-refresh"
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise ActivationError("immutable edge TLS refresh helper is unavailable")
    hook_root = _absolute(hook_root, "certbot deploy hook root")
    root_info = hook_root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_uid
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise ActivationError("certbot deploy hook root is unsafe")
    command = runner or CommandRunner()
    checked = command.run_json(
        [
            str(helper),
            "--check",
            "--lineage",
            "/etc/letsencrypt/live/vr.ae",
            "--domain",
            "vr.ae",
        ]
    )
    if checked.get("ok") is not True or checked.get("checked") is not True:
        raise ActivationError("immutable edge TLS credential preflight failed")
    destination = hook_root / "devcoordinator-edge"
    legacy = hook_root / "devops-console"
    rollback_directory = _private_directory(rollback_directory, expected_uid=expected_uid)
    prior_files = {
        str(path): _capture_destination(
            path,
            rollback_directory=rollback_directory,
            expected_uid=expected_uid,
        )
        for path in (destination, legacy)
    }
    payload = (
        "#!/bin/sh\n"
        "set -eu\n"
        "case \"${RENEWED_LINEAGE:-/etc/letsencrypt/live/vr.ae}\" in\n"
        "  /etc/letsencrypt/live/vr.ae) ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n"
        f"exec {helper} --lineage /etc/letsencrypt/live/vr.ae --domain vr.ae\n"
    ).encode("utf-8")
    try:
        _atomic_install(
            destination,
            payload,
            expected_uid=expected_uid,
            mode=0o700,
        )
        if legacy.exists() or legacy.is_symlink():
            info = legacy.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid:
                raise ActivationError("legacy certbot hook identity is unsafe")
            legacy.unlink()
        return cutover.seal(
            EDGE_CERTBOT_HOOK_KIND,
            {
                "release_digest": release.name,
                "helper": str(helper),
                "hook": str(destination),
                "hook_sha256": _sha256_bytes(payload),
                "legacy_hook_removed": not legacy.exists(),
                "credential_preflight": {
                    "leaf_sha256": checked.get("leaf_sha256"),
                    "public_key_sha256": checked.get("public_key_sha256"),
                },
                "prior_files": prior_files,
                "created_at": _now(),
            },
        )
    except BaseException as error:
        try:
            _restore_prepared_graph(
                {"prior_units": {}, "prior_files": prior_files},
                runner=command,
                expected_uid=expected_uid,
            )
        except BaseException as rollback_error:
            raise ActivationError(
                f"certbot hook migration failed ({error}); rollback failed ({rollback_error})"
            ) from error
        raise ActivationError(f"certbot hook migration failed and was rolled back: {error}") from error


def migrate_legacy_console_state(
    *,
    release: Path,
    legacy_env: Path,
    legacy_state: Path,
    console_state: Path,
    edge_identity_state: Path,
    console_config: Path,
    route_resolution: Path,
    private_publication_input: Path,
    console_port: int,
    console_uid: int,
    console_gid: int,
    edge_uid: int,
    edge_gid: int,
    legacy_uid: int,
    rollback_directory: Path,
    journal_file: Path,
    migrate_edge_identity: bool = True,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Copy the exact allowlisted legacy state and validate it as final UIDs."""

    if os.geteuid() != expected_uid:
        raise ActivationError("Console state migration must run as the authority UID")
    command = runner or CommandRunner()
    rollback_directory = _absolute(
        rollback_directory, "Console migration rollback directory"
    )
    journal_file = _absolute(journal_file, "Console state migration journal")
    console_state = _absolute(console_state, "Console state destination")
    edge_identity_state = _absolute(edge_identity_state, "edge identity destination")
    private_publication_input = _absolute(
        private_publication_input, "Console publication input destination"
    )
    config_payload = render_console_public_config(
        legacy_env=legacy_env,
        expected_uid=legacy_uid,
    )
    destinations: dict[Path, tuple[bytes, int, int, bool]] = {
        console_config: (config_payload, expected_uid, os.getegid(), False),
    }
    source_evidence: dict[str, object] = {}
    for name, maximum in LEGACY_CONSOLE_STATE_FILES.items():
        source = legacy_state / name
        if not source.exists() and not source.is_symlink():
            source_evidence[name] = {"present": False}
            continue
        payload = _read_secret(
            source,
            label=f"legacy Console {name}",
            expected_uid=legacy_uid,
            maximum=maximum,
        )
        source_evidence[name] = {"present": True, "size": len(payload), "sha256": _sha256_bytes(payload)}
        destinations[console_state / name] = (payload, console_uid, console_gid, True)
    if type(migrate_edge_identity) is not bool:
        raise ActivationError("legacy edge identity migration flag is invalid")
    identity_present = []
    if migrate_edge_identity:
        for name, maximum in LEGACY_EDGE_IDENTITY_FILES.items():
            source = legacy_state / name
            if not source.exists() and not source.is_symlink():
                source_evidence[name] = {"present": False}
                continue
            payload = _read_secret(
                source,
                label=f"legacy edge identity {name}",
                expected_uid=legacy_uid,
                maximum=maximum,
            )
            identity_present.append(name)
            source_evidence[name] = {
                "present": True,
                "size": len(payload),
                "sha256": _sha256_bytes(payload),
            }
            destinations[edge_identity_state / name] = (
                payload,
                edge_uid,
                edge_gid,
                True,
            )
        if identity_present and set(identity_present) != set(LEGACY_EDGE_IDENTITY_FILES):
            raise ActivationError("legacy route identity keypair is incomplete")
    desired = {
        str(destination): {
            "sha256": _sha256_bytes(payload),
            "size": len(payload),
            "owner_uid": owner_uid,
            "owner_gid": owner_gid,
            "mode": "0600" if secret else "0644",
        }
        for destination, (payload, owner_uid, owner_gid, secret) in destinations.items()
    }
    migration_binding = {
        "release_digest": release.name,
        "legacy_state": str(legacy_state),
        "console_state": str(console_state),
        "edge_identity_state": str(edge_identity_state),
        "console_config": str(console_config),
        "route_resolution": str(route_resolution),
        "publication_input": str(private_publication_input),
        "console_port": console_port,
        "console_uid": console_uid,
        "console_gid": console_gid,
        "edge_uid": edge_uid,
        "edge_gid": edge_gid,
        "legacy_uid": legacy_uid,
        "migrate_edge_identity": migrate_edge_identity,
        "sources": source_evidence,
        "desired": desired,
    }
    migration_journal = _load_private_journal(
        journal_file,
        kind=CONSOLE_STATE_MIGRATION_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if migration_journal is None:
        prior_files = {
            str(destination): _plan_destination_prior(
                destination,
                rollback_directory=rollback_directory,
                expected_uid=expected_uid,
            )
            for destination in (*destinations, private_publication_input)
        }
        migration_journal = _write_private_journal(
            journal_file,
            kind=CONSOLE_STATE_MIGRATION_JOURNAL_KIND,
            payload={
                "operation_id": str(uuid.uuid4()),
                "binding": migration_binding,
                "phase": "planned",
                "prior_files": prior_files,
                "backups_ready": [],
                "installed": {},
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    else:
        if (
            migration_journal.get("binding") != migration_binding
            or not isinstance(migration_journal.get("prior_files"), Mapping)
        ):
            raise ActivationError(
                "Console state migration journal belongs to another migration"
            )
        prior_files = dict(migration_journal["prior_files"])
        complete_result = migration_journal.get("result")
        if migration_journal.get("phase") == "complete":
            if not isinstance(complete_result, Mapping):
                raise ActivationError(
                    "complete Console migration journal lacks its result"
                )
            for destination_text, evidence in desired.items():
                if not _exact_regular_file(
                    Path(destination_text),
                    sha256=str(evidence["sha256"]),
                    mode=int(str(evidence["mode"]), 8),
                    owner_uid=int(evidence["owner_uid"]),
                    owner_gid=int(evidence["owner_gid"]),
                ):
                    raise ActivationError(
                        "completed Console migration destination changed"
                    )
            publication = complete_result.get("publication_input")
            if (
                not isinstance(publication, Mapping)
                or not _exact_regular_file(
                    private_publication_input,
                    sha256=str(publication.get("sha256")),
                    mode=0o600,
                    owner_uid=expected_uid,
                )
            ):
                raise ActivationError(
                    "completed Console publication input changed"
                )
            return dict(complete_result)
    rollback_directory = _private_directory(
        rollback_directory, expected_uid=expected_uid
    )
    for directory, uid, gid in (
        (console_state, console_uid, console_gid),
        (edge_identity_state, edge_uid, edge_gid),
    ):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o700)
    installed_value = migration_journal.get("installed")
    backups_value = migration_journal.get("backups_ready")
    if not isinstance(installed_value, Mapping) or not isinstance(
        backups_value, list
    ):
        raise ActivationError("Console migration journal progress is invalid")
    installed: dict[str, object] = dict(installed_value)
    backups_ready = list(backups_value)

    def persist_console_progress(phase: str, **updates: object) -> None:
        nonlocal migration_journal
        payload = {
            key: value
            for key, value in migration_journal.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(updates)
        payload.update(
            {
                "phase": phase,
                "backups_ready": list(backups_ready),
                "installed": dict(installed),
                "updated_at": _now(),
            }
        )
        migration_journal = _write_private_journal(
            journal_file,
            kind=CONSOLE_STATE_MIGRATION_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )

    try:
        for destination_text, prior in prior_files.items():
            if not isinstance(prior, Mapping):
                raise ActivationError("Console migration prior-file entry is invalid")
            planned = desired.get(destination_text)
            desired_sha = (
                str(planned["sha256"])
                if isinstance(planned, Mapping)
                else ""
            )
            _ensure_planned_backup(
                Path(destination_text),
                prior,
                expected_uid=expected_uid,
                desired_sha256=desired_sha,
            )
            if destination_text not in backups_ready:
                if failpoint is not None:
                    failpoint(
                        f"console-backup-before-journal:{destination_text}"
                    )
                backups_ready.append(destination_text)
                persist_console_progress("backups_ready")
        for destination, (payload, owner_uid, owner_gid, secret) in destinations.items():
            destination_text = str(destination)
            evidence = desired[destination_text]
            mode = 0o600 if secret else 0o644
            exact = _exact_regular_file(
                destination,
                sha256=str(evidence["sha256"]),
                mode=mode,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            if destination_text in installed:
                if installed[destination_text] != evidence or not exact:
                    raise ActivationError(
                        "journaled Console migration destination changed"
                    )
                continue
            if not exact:
                root_written = _exact_regular_file(
                    destination,
                    sha256=str(evidence["sha256"]),
                    mode=mode,
                    owner_uid=expected_uid,
                )
                if not root_written:
                    prior = prior_files[destination_text]
                    if not isinstance(prior, Mapping):
                        raise ActivationError(
                            "Console migration prior file state is invalid"
                        )
                    if prior.get("existed") is True:
                        if not _exact_regular_file(
                            destination,
                            sha256=str(prior.get("sha256")),
                            mode=int(str(prior.get("mode")), 8),
                            owner_uid=int(prior.get("owner_uid")),
                            owner_gid=int(prior.get("owner_gid")),
                        ):
                            raise ActivationError(
                                "Console destination is neither prior nor desired"
                            )
                    elif prior.get("existed") is False:
                        if destination.exists() or destination.is_symlink():
                            raise ActivationError(
                                "unexpected Console migration destination appeared"
                            )
                    else:
                        raise ActivationError(
                            "Console migration prior file existence is invalid"
                        )
                    _atomic_install(
                        destination,
                        payload,
                        expected_uid=expected_uid,
                        mode=mode,
                        allowed_parent_uids={owner_uid},
                    )
                os.chown(destination, owner_uid, owner_gid)
                os.chmod(destination, mode)
            if failpoint is not None:
                failpoint(f"console-install-before-journal:{destination_text}")
            installed[destination_text] = dict(evidence)
            persist_console_progress("files_installing")
        validator = release / "bin/devcoordinator-console-state-migration"
        console_validation = command.run_json(
            [
                "/usr/bin/setpriv",
                "--reuid",
                str(console_uid),
                "--regid",
                str(console_gid),
                "--clear-groups",
                str(validator),
                "validate-console",
                "--state-dir",
                str(console_state),
                "--env-file",
                str(console_config),
            ]
        )
        identity_validation = None
        if identity_present:
            public_config = render_console_public_config(legacy_env=legacy_env, expected_uid=legacy_uid).decode("utf-8")
            origin = next(line.split("=", 1)[1] for line in public_config.splitlines() if line.startswith("PUBLIC_CONSOLE_ORIGIN="))
            identity_validation = command.run_json(
                [
                    "/usr/bin/setpriv",
                    "--reuid",
                    str(edge_uid),
                    "--regid",
                    str(edge_gid),
                    "--clear-groups",
                    str(validator),
                    "validate-identity",
                    "--identity-dir",
                    str(edge_identity_state),
                    "--issuer",
                    origin,
                ]
            )
        recorded_console_validation = migration_journal.get("console_validation")
        recorded_identity_validation = migration_journal.get("identity_validation")
        if recorded_console_validation is not None and recorded_console_validation != console_validation:
            raise ActivationError("Console migration validation changed during resume")
        if recorded_identity_validation is not None and recorded_identity_validation != identity_validation:
            raise ActivationError("Console identity validation changed during resume")
        if failpoint is not None:
            failpoint("console-validation-before-journal")
        persist_console_progress(
            "validated",
            console_validation=console_validation,
            identity_validation=identity_validation,
        )
        resolution_payload = _read_secret(
            route_resolution,
            label="first-adoption route resolution snapshot",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
        migration_dir = console_state / ".migration"
        migration_dir.mkdir(mode=0o700, exist_ok=True)
        os.chown(migration_dir, console_uid, console_gid)
        os.chmod(migration_dir, 0o700)
        resolution_copy = migration_dir / "route-resolution.json"
        resolution_sha = _sha256_bytes(resolution_payload)
        if not _exact_regular_file(
            resolution_copy,
            sha256=resolution_sha,
            mode=0o600,
            owner_uid=console_uid,
            owner_gid=console_gid,
        ):
            if resolution_copy.exists() or resolution_copy.is_symlink():
                raise ActivationError(
                    "Console migration resolution intermediary is contradictory"
                )
            _atomic_install(
                resolution_copy,
                resolution_payload,
                expected_uid=expected_uid,
                mode=0o600,
                allowed_parent_uids={console_uid},
            )
            os.chown(resolution_copy, console_uid, console_gid)
        if failpoint is not None:
            failpoint("console-resolution-before-journal")
        persist_console_progress("resolution_ready", resolution_sha256=resolution_sha)
        proposal = migration_dir / "publication-input.json"
        proposal_result = migration_journal.get("proposal_result")
        proposal_evidence = migration_journal.get("proposal")
        if proposal_result is None:
            if not (proposal.exists() or proposal.is_symlink()):
                proposal_result = command.run_json(
                    [
                        "/usr/bin/setpriv",
                        "--reuid",
                        str(console_uid),
                        "--regid",
                        str(console_gid),
                        "--clear-groups",
                        str(validator),
                        "build-publication",
                        "--state-dir",
                        str(console_state),
                        "--env-file",
                        str(console_config),
                        "--resolution",
                        str(resolution_copy),
                        "--output",
                        str(proposal),
                        "--release-root",
                        str(IMMUTABLE_RELEASE_ROOT),
                        "--release-digest",
                        release.name,
                        "--console-port",
                        str(console_port),
                        "--generation",
                        "1",
                    ]
                )
            proposal_payload = _read_secret(
                proposal,
                label="Console retained publication proposal",
                expected_uid=console_uid,
                maximum=MAX_JSON_BYTES,
            )
            if proposal_result is None:
                try:
                    recovered_publication = json.loads(
                        proposal_payload.decode("utf-8")
                    )
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise ActivationError(
                        "crash-recovered Console publication is invalid"
                    ) from error
                routes = recovered_publication.get("routes")
                access = recovered_publication.get("access")
                owners = access.get("owners") if isinstance(access, Mapping) else None
                grants = access.get("grants") if isinstance(access, Mapping) else None
                if (
                    not isinstance(routes, Mapping)
                    or not isinstance(owners, list)
                    or not isinstance(grants, Mapping)
                ):
                    raise ActivationError(
                        "crash-recovered Console publication contract is invalid"
                    )
                proposal_result = {
                    "ok": True,
                    "output": str(proposal),
                    "payload_sha256": _sha256_bytes(proposal_payload),
                    "routes": len(routes),
                    "identities": len(owners) + len(grants),
                }
            proposal_evidence = {
                "sha256": _sha256_bytes(proposal_payload),
                "size": len(proposal_payload),
            }
            if failpoint is not None:
                failpoint("console-proposal-before-journal")
            persist_console_progress(
                "proposal_ready",
                proposal_result=proposal_result,
                proposal=proposal_evidence,
            )
        elif not isinstance(proposal_result, Mapping) or not isinstance(
            proposal_evidence, Mapping
        ):
            raise ActivationError("Console migration proposal journal is invalid")
        proposal_payload = _read_secret(
            proposal if proposal.exists() else private_publication_input,
            label="Console retained publication proposal",
            expected_uid=(
                console_uid if proposal.exists() else expected_uid
            ),
            maximum=MAX_JSON_BYTES,
        )
        if _sha256_bytes(proposal_payload) != proposal_evidence.get("sha256"):
            raise ActivationError("Console migration proposal content changed")
        if not _exact_regular_file(
            private_publication_input,
            sha256=str(proposal_evidence["sha256"]),
            mode=0o600,
            owner_uid=expected_uid,
        ):
            prior = prior_files[str(private_publication_input)]
            if not isinstance(prior, Mapping):
                raise ActivationError("Console publication prior state is invalid")
            if prior.get("existed") is True:
                if not _exact_regular_file(
                    private_publication_input,
                    sha256=str(prior.get("sha256")),
                    mode=int(str(prior.get("mode")), 8),
                    owner_uid=int(prior.get("owner_uid")),
                    owner_gid=int(prior.get("owner_gid")),
                ):
                    raise ActivationError(
                        "Console publication input is neither prior nor desired"
                    )
            elif prior.get("existed") is False:
                if private_publication_input.exists() or private_publication_input.is_symlink():
                    raise ActivationError(
                        "unexpected Console publication input appeared"
                    )
            else:
                raise ActivationError("Console publication prior existence is invalid")
            _atomic_private(
                private_publication_input,
                proposal_payload,
                expected_uid=expected_uid,
            )
        if failpoint is not None:
            failpoint("console-publication-before-journal")
        persist_console_progress("publication_ready")
        result = cutover.seal(
            CONSOLE_STATE_MIGRATION_KIND,
            {
                "release_digest": release.name,
                "legacy_state": str(legacy_state),
                "sources": source_evidence,
                "installed": installed,
                "prior_files": prior_files,
                "console_validation": console_validation,
                "identity_validation": identity_validation,
                "resolution_sha256": resolution_sha,
                "publication_input": {
                    "path": str(private_publication_input),
                    "sha256": _sha256_bytes(proposal_payload),
                    "routes": proposal_result.get("routes"),
                },
                "created_at": migration_journal["created_at"],
            },
        )
        if failpoint is not None:
            failpoint("console-complete-before-journal")
        persist_console_progress("complete", result=result)
        if proposal.exists():
            proposal.unlink()
        if resolution_copy.exists():
            resolution_copy.unlink()
        if migration_dir.exists():
            migration_dir.rmdir()
        return result
    except PowerLossSimulation:
        raise
    except BaseException as error:
        try:
            _restore_prepared_graph(
                {"prior_units": {}, "prior_files": prior_files},
                runner=command,
                expected_uid=expected_uid,
            )
        except BaseException as rollback_error:
            raise ActivationError(f"Console state migration failed ({error}); rollback failed ({rollback_error})") from error
        raise ActivationError(f"Console state migration failed and was rolled back: {error}") from error


def _tcp_listener_inode(port: int, *, proc_root: Path = Path("/proc")) -> int:
    found: set[int] = set()
    for name in ("tcp", "tcp6"):
        path = proc_root / "net" / name
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
                inode = int(fields[9])
            except (ValueError, IndexError):
                continue
            if local_port == port and inode > 0:
                found.add(inode)
    if len(found) != 1:
        raise ActivationError(f"listener port {port} does not have one stable socket inode")
    return next(iter(found))


def socket_inodes(
    *,
    proc_root: Path = Path("/proc"),
    socket_paths: Mapping[str, Path] = SOCKET_PATHS,
    socket_ports: Mapping[str, int] = SOCKET_PORTS,
) -> dict[str, int]:
    result = {
        name: _tcp_listener_inode(port, proc_root=proc_root)
        for name, port in socket_ports.items()
    }
    for name, path in socket_paths.items():
        try:
            info = path.lstat()
        except OSError as error:
            raise ActivationError(f"{name} socket is unavailable") from error
        if not stat.S_ISSOCK(info.st_mode) or info.st_ino <= 0:
            raise ActivationError(f"{name} path is not a socket")
        result[name] = int(info.st_ino)
    if set(result) != cutover.SOCKET_NAMES or len(set(result.values())) != len(result):
        raise ActivationError("listener socket identity set is invalid")
    return result


def _load_publication(path: Path) -> dict[str, object]:
    path = _absolute(path, "edge route publication")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size <= 0
        or info.st_size > MAX_JSON_BYTES
    ):
        raise ActivationError("edge route publication file is unsafe")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        payload = os.read(descriptor, MAX_JSON_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_JSON_BYTES or (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ActivationError("edge route publication changed while it was read")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationError("edge route publication is invalid JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema_version", "payload_sha256", "publication"}:
        raise ActivationError("edge route publication envelope is invalid")
    publication = document.get("publication")
    if not isinstance(publication, dict):
        raise ActivationError("edge route publication payload is invalid")
    return document


def verify_nonempty_retained_routes(
    publication_file: Path,
) -> dict[str, object]:
    """Prove one checksum-valid, non-empty last-known-good route generation."""

    envelope = _load_publication(publication_file)
    publication = envelope["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("retained route publication payload is invalid")
    expected_digest = _sha256_bytes(_canonical(publication))
    routes = publication.get("routes")
    console = publication.get("console")
    generation = publication.get("generation")
    if (
        envelope.get("payload_sha256") != expected_digest
        or type(generation) is not int
        or int(generation) < 1
        or not isinstance(routes, Mapping)
        or not routes
        or any(not isinstance(key, str) or not key for key in routes)
        or any(not isinstance(value, Mapping) for value in routes.values())
        or not isinstance(console, Mapping)
        or not isinstance(console.get("upstream"), Mapping)
    ):
        raise ActivationError("retained route publication is empty or contradictory")
    return cutover.seal(
        RETAINED_ROUTE_READINESS_KIND,
        {
            "publication": str(_absolute(publication_file, "route publication")),
            "generation": generation,
            "payload_sha256": expected_digest,
            "release_digest": publication.get("release_digest"),
            "route_count": len(routes),
            "console_upstream": dict(console["upstream"]),
            "verified_at": _now(),
        },
    )


def verify_nonempty_retained_inventory(
    *,
    release: Path,
    database: Path,
    publication: Path,
    observer_uid: int,
) -> dict[str, object]:
    """Prove the observer store and publication agree on non-empty inventory."""

    release = _absolute(release, "retained inventory release")
    if (
        release.parent != IMMUTABLE_RELEASE_ROOT
        or re.fullmatch(r"[0-9a-f]{64}", release.name) is None
    ):
        raise ActivationError("retained inventory release is not immutable")
    module_path = (
        release
        / "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py"
    )
    if not module_path.is_file() or module_path.is_symlink():
        raise ActivationError("retained inventory verifier is unavailable")
    spec = importlib.util.spec_from_file_location(
        f"devcoordinator_inventory_readiness_{release.name}", module_path
    )
    if spec is None or spec.loader is None:
        raise ActivationError("retained inventory verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        retained = module.verify_inventory_store(
            _absolute(database, "retained inventory database"),
            _absolute(publication, "retained inventory publication"),
            expected_owner_uid=observer_uid,
        )
    except Exception as error:
        raise ActivationError("retained inventory store failed verification") from error
    envelope = retained.get("envelope") if isinstance(retained, Mapping) else None
    counts = _retained_inventory_counts(envelope)
    if (
        type(envelope.get("generation")) is not int
        or int(envelope["generation"]) < 1
        or not isinstance(envelope.get("payload_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(envelope["payload_sha256"])) is None
    ):
        raise ActivationError("retained inventory is empty or malformed")
    return cutover.seal(
        RETAINED_INVENTORY_READINESS_KIND,
        {
            "database": str(_absolute(database, "retained inventory database")),
            "publication": str(
                _absolute(publication, "retained inventory publication")
            ),
            "generation": envelope["generation"],
            "payload_sha256": envelope["payload_sha256"],
            "repository_count": counts["repositories"],
            "server_count": counts["servers"],
            "container_count": counts["containers"],
            "retained_generations": retained.get("retained_generations"),
            "verified_at": _now(),
        },
    )


def _probe_url(url: str, timeout: float = 3.0) -> tuple[int | None, bool]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ActivationError("probe URL must be one HTTPS origin")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=timeout,
        context=ssl.create_default_context(),
    )
    try:
        connection.request("GET", parsed.path or "/", headers={"user-agent": "devcoordinator-activation/1"})
        response = connection.getresponse()
        response.read(64 * 1024)
        return response.status, False
    except (ConnectionRefusedError, socket.timeout, OSError) as error:
        refused = isinstance(error, ConnectionRefusedError) or getattr(error, "errno", None) == 111
        return None, refused
    finally:
        connection.close()


def _publication_probes(envelope: Mapping[str, object]) -> list[str]:
    publication = envelope["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("publication probe payload is invalid")
    console_host = str(publication["console_host"])
    domain = str(publication["domain"])
    routes = publication.get("routes")
    if not isinstance(routes, Mapping):
        raise ActivationError("publication route set is invalid")
    available: list[str] = []
    for slug in sorted(routes):
        route = routes[slug]
        upstream = route.get("upstream") if isinstance(route, Mapping) else None
        if isinstance(upstream, Mapping) and upstream.get("status") == "unavailable":
            if (
                set(upstream)
                != {"status", "scheme", "tls_server_name", "tls_verify"}
                or upstream.get("scheme") not in {"http", "https"}
                or type(upstream.get("tls_verify")) is not bool
                or (
                    upstream.get("scheme") == "http"
                    and (
                        upstream.get("tls_server_name") is not None
                        or upstream.get("tls_verify") is not True
                    )
                )
                or (
                    upstream.get("scheme") == "https"
                    and (
                        not isinstance(upstream.get("tls_server_name"), str)
                        or DNS_NAME_RE.fullmatch(upstream["tls_server_name"])
                        is None
                    )
                )
            ):
                raise ActivationError(
                    "publication unavailable-route protocol is invalid"
                )
            continue
        available.append(f"https://{slug}.{domain}/")
    return [f"https://{console_host}/healthz", *available]


def _run_probes(
    urls: Sequence[str],
    *,
    probe: Callable[[str], tuple[int | None, bool]] = _probe_url,
) -> tuple[dict[str, int | None], int]:
    statuses: dict[str, int | None] = {}
    refused = 0
    for url in urls:
        status, was_refused = probe(url)
        statuses[url] = status
        refused += int(was_refused)
    return statuses, refused


def _probe_websocket(url: str, timeout: float = 3.0) -> tuple[int | None, bool]:
    """Perform a bounded RFC 6455 upgrade request without exchanging payloads."""

    parsed = urlparse(url)
    if parsed.scheme != "wss" or not parsed.hostname or parsed.username or parsed.password:
        raise ActivationError("WebSocket probe URL must be one WSS origin")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=timeout,
        context=ssl.create_default_context(),
    )
    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(
            "GET",
            path,
            headers={
                "connection": "Upgrade",
                "upgrade": "websocket",
                "sec-websocket-version": "13",
                "sec-websocket-key": key,
                "user-agent": "devcoordinator-continuity/1",
            },
        )
        response = connection.getresponse()
        if response.status != 101:
            response.read(64 * 1024)
        return response.status, False
    except (ConnectionRefusedError, socket.timeout, OSError) as error:
        refused = isinstance(error, ConnectionRefusedError) or getattr(error, "errno", None) == 111
        return None, refused
    finally:
        connection.close()


def _continuity_targets(urls: Sequence[str]) -> list[dict[str, str]]:
    if not urls:
        raise ActivationError("continuity probe requires at least one HTTP target")
    targets = [
        {
            "target_id": f"http:{url}",
            "protocol": "http",
            "category": "console" if index == 0 else "project",
            "url": url,
        }
        for index, url in enumerate(urls)
    ]
    websocket_sources = list(urls[1:] or urls[:1])
    for url in websocket_sources:
        parsed = urlparse(url)
        websocket_url = parsed._replace(scheme="wss").geturl()
        targets.append(
            {
                "target_id": f"websocket:{websocket_url}",
                "protocol": "websocket",
                "category": "project" if url in urls[1:] else "console",
                "url": websocket_url,
            }
        )
    return sorted(targets, key=lambda item: item["target_id"])


class ContinuityProbeSession:
    """Continuously sample public HTTP/WSS routes across one mutation window."""

    def __init__(
        self,
        *,
        release_digest: str,
        urls: Sequence[str],
        http_probe: Callable[[str], tuple[int | None, bool]],
        websocket_probe: Callable[[str], tuple[int | None, bool]],
        sample_interval_ms: int = 50,
        ttfb_p99_ms: int = 100,
        control_plane_p99_ms: int = 100,
    ) -> None:
        if not 10 <= sample_interval_ms <= 10_000:
            raise ActivationError("continuity sample interval is out of range")
        self.release_digest = release_digest
        self.targets = _continuity_targets(urls)
        self.http_probe = http_probe
        self.websocket_probe = websocket_probe
        self.sample_interval_ms = sample_interval_ms
        self.slo = {
            "ttfb_p99_ms": ttfb_p99_ms,
            "control_plane_p99_ms": control_plane_p99_ms,
            "minimum_rounds": 2,
        }
        self.operation_id = str(uuid.uuid4())
        self.started_at = _now()
        self._samples: list[dict[str, object]] = []
        self._round_count = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample_round(self) -> None:
        values: list[dict[str, object]] = []
        for target in self.targets:
            started = time.monotonic_ns()
            probe = (
                self.http_probe
                if target["protocol"] == "http"
                else self.websocket_probe
            )
            try:
                status, refused = probe(target["url"])
            except BaseException:
                status, refused = None, False
            latency_ms = max(0, (time.monotonic_ns() - started + 999_999) // 1_000_000)
            values.append(
                {
                    **target,
                    "status": status,
                    "refused": bool(refused),
                    "latency_ms": int(latency_ms),
                }
            )
        with self._lock:
            if len(self._samples) + len(values) > 65_536:
                self._stop.set()
                return
            self._samples.extend(values)
            self._round_count += 1

    def start(self) -> "ContinuityProbeSession":
        self._sample_round()

        def worker() -> None:
            interval = self.sample_interval_ms / 1000.0
            while not self._stop.wait(interval):
                self._sample_round()

        self._thread = threading.Thread(
            target=worker,
            name="devcoordinator-continuity-probe",
            daemon=True,
        )
        self._thread.start()
        return self

    @staticmethod
    def _p99(values: Sequence[int]) -> int:
        if not values:
            return 0
        ordered = sorted(values)
        return int(ordered[max(0, ((99 * len(ordered) + 99) // 100) - 1)])

    def finish(self) -> dict[str, object]:
        self._sample_round()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.sample_interval_ms / 500.0))
            if self._thread.is_alive():
                raise ActivationError("continuity probe worker did not stop")
        with self._lock:
            samples = list(self._samples)
            rounds = self._round_count
        by_target: dict[str, list[dict[str, object]]] = {
            target["target_id"]: [] for target in self.targets
        }
        for sample in samples:
            by_target[str(sample["target_id"])].append(sample)
        refused_count = sum(int(sample["refused"] is True) for sample in samples)
        project_route_failures = 0
        failed_samples = 0
        summaries: list[dict[str, object]] = []
        for target in self.targets:
            target_samples = by_target[target["target_id"]]
            baseline_status = target_samples[0]["status"] if target_samples else None
            failures = 0
            for index, sample in enumerate(target_samples):
                failed = bool(sample["refused"]) or sample["status"] is None
                if index > 0 and isinstance(baseline_status, int) and baseline_status < 500:
                    failed = failed or not isinstance(sample["status"], int) or int(sample["status"]) >= 500
                if target["category"] == "console" and target["protocol"] == "http":
                    failed = failed or sample["status"] != 200
                failures += int(failed)
                if failed and target["category"] == "project":
                    project_route_failures += 1
            failed_samples += failures
            summaries.append(
                {
                    **target,
                    "baseline_status": baseline_status,
                    "last_status": target_samples[-1]["status"] if target_samples else None,
                    "sample_count": len(target_samples),
                    "failure_count": failures,
                    "max_latency_ms": max(
                        (int(sample["latency_ms"]) for sample in target_samples),
                        default=0,
                    ),
                }
            )
        http_samples = [sample for sample in samples if sample["protocol"] == "http"]
        control_samples = [
            sample
            for sample in http_samples
            if sample["category"] in {"console", "api"}
        ]
        ttfb = self._p99([int(item["latency_ms"]) for item in http_samples])
        control = self._p99([int(item["latency_ms"]) for item in control_samples])
        passed = (
            rounds >= int(self.slo["minimum_rounds"])
            and refused_count == 0
            and project_route_failures == 0
            and failed_samples == 0
            and ttfb <= int(self.slo["ttfb_p99_ms"])
            and control <= int(self.slo["control_plane_p99_ms"])
        )
        evidence = cutover.seal(
            cutover.CONTINUITY_PROBE_KIND,
            {
                "operation_id": self.operation_id,
                "release_digest": self.release_digest,
                "started_at": self.started_at,
                "completed_at": _now(),
                "sample_interval_ms": self.sample_interval_ms,
                "round_count": rounds,
                "sample_count": len(samples),
                "http_sample_count": len(http_samples),
                "websocket_sample_count": len(samples) - len(http_samples),
                "connection_refused_count": refused_count,
                "project_route_failures": project_route_failures,
                "failed_sample_count": failed_samples,
                "ttfb_p99_ms": ttfb,
                "control_plane_p99_ms": control,
                "targets": summaries,
                "samples_sha256": _sha256_bytes(_canonical(samples)),
                "slo": self.slo,
                "passed": passed,
            },
        )
        try:
            cutover._continuity_probe(evidence, expected_release=self.release_digest)
        except cutover.CutoverError as error:
            raise ActivationError(str(error)) from error
        return evidence

    def stop_unverified(self) -> None:
        """Stop sampling after a failed mutation without authoring evidence."""

        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.sample_interval_ms / 500.0))


def _publication_switch_evidence(
    before: Mapping[str, object],
    switched: Mapping[str, object],
) -> dict[str, object]:
    publication = before["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("publication switch source payload is invalid")
    upstream = publication["console"]
    if not isinstance(upstream, Mapping):
        raise ActivationError("publication switch Console target is invalid")
    target = upstream["upstream"]
    if not isinstance(target, Mapping):
        raise ActivationError("publication switch upstream target is invalid")
    result = {
        "previous_generation": switched.get("previous_generation"),
        "generation": switched.get("generation"),
        "previous_payload_sha256": switched.get("previous_payload_sha256"),
        "payload_sha256": switched.get("payload_sha256"),
        "previous_release_digest": publication.get("release_digest"),
        "release_digest": switched.get("release_digest"),
        "previous_port": target.get("port"),
        "port": switched.get("port"),
    }
    cutover._publication_switch(result, expected_release=str(result["release_digest"]))
    return result


def _slot_status(
    runner: CommandRunner,
    control: Path,
    executable: Path,
    *,
    expected_release: str,
    expected_mode: str | None = None,
) -> dict[str, object]:
    response = runner.run_json([str(executable), "status", "--socket", str(control)])
    if response.get("release_digest") != expected_release:
        raise ActivationError("Console slot reports another release")
    if expected_mode is not None and response.get("mode") != expected_mode:
        raise ActivationError(f"Console slot is not {expected_mode}")
    if type(response.get("port")) is not int or not 30000 <= int(response["port"]) <= 60999:
        raise ActivationError("Console slot reports an invalid port")
    return response


def _unit_state(runner: CommandRunner, unit: str) -> tuple[bool, bool]:
    if unit not in {*LEGACY_UNITS, LEGACY_API_SERVICE_UNIT}:
        raise ActivationError("legacy unit is not allowlisted")
    return _systemd_unit_state(runner, unit)


def _systemd_unit_state(
    runner: CommandRunner, unit: str
) -> tuple[bool, bool]:
    active = runner.status(["/usr/bin/systemctl", "is-active", "--quiet", unit]) == 0
    enabled = runner.status(["/usr/bin/systemctl", "is-enabled", "--quiet", unit]) == 0
    return active, enabled


def _disable_stop_exact_unit(
    runner: CommandRunner, unit: str, *, label: str
) -> None:
    if runner.status(
        ["/usr/bin/systemctl", "disable", "--now", unit]
    ) != 0:
        raise ActivationError(f"{label} could not be disabled and stopped: {unit}")
    if _systemd_unit_state(runner, unit) != (False, False):
        raise ActivationError(f"{label} remained active or enabled: {unit}")


def _restore_units(runner: CommandRunner, states: Mapping[str, tuple[bool, bool]]) -> None:
    for unit, (active, enabled) in states.items():
        if enabled:
            if runner.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                raise ActivationError(f"failed to restore legacy unit {unit}")
        elif active and runner.status(["/usr/bin/systemctl", "start", unit]) != 0:
            raise ActivationError(f"failed to restart legacy unit {unit}")


def _read_install_source(path: Path, *, expected_uid: int) -> tuple[bytes, dict[str, object]]:
    path = _absolute(path, "candidate install source")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size <= 0
        or info.st_size > MAX_JSON_BYTES
        or path.resolve(strict=True) != path
    ):
        raise ActivationError(f"candidate install source is unsafe: {path}")
    payload = path.read_bytes()
    after = path.lstat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ActivationError("candidate install source changed while it was read")
    return payload, {
        "path": str(path),
        "sha256": _sha256_bytes(payload),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }


def _capture_destination(
    destination: Path,
    *,
    rollback_directory: Path,
    expected_uid: int,
) -> dict[str, object]:
    if not (destination.exists() or destination.is_symlink()):
        return {"existed": False, "backup": None}
    info = destination.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size > MAX_JSON_BYTES
    ):
        raise ActivationError(f"installed destination is unsafe: {destination}")
    payload = destination.read_bytes()
    digest = _sha256_bytes(payload)
    backup = rollback_directory / f"{destination.name}.{digest}.prior"
    if backup.exists() or backup.is_symlink():
        prior = _read_secret(
            backup,
            label="candidate graph backup",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
        if prior != payload:
            raise ActivationError("candidate graph backup has drifted")
    else:
        _atomic_private(backup, payload, expected_uid=expected_uid)
    return {
        "existed": True,
        "backup": str(backup),
        "sha256": digest,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
    }


def publish_first_adoption_profiles(
    *,
    authority_database: Path,
    destination: Path,
    validation_uid: int,
    rollback_directory: Path,
    journal_file: Path,
    expected_uid: int,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Crash-safely publish host-wide routing metadata from the current catalog."""

    if os.geteuid() != expected_uid:
        raise ActivationError(
            "routing profile publication must run as the authority UID"
        )
    authority_database = _absolute(
        authority_database, "routing profile authority database"
    )
    destination = _absolute(destination, "host routing profile")
    journal_file = _absolute(
        journal_file, "routing profile publication journal"
    )
    rollback_directory = _private_directory(
        rollback_directory, expected_uid=expected_uid
    )
    binding = {
        "authority_database": str(authority_database),
        "destination": str(destination),
        "validation_uid": validation_uid,
    }
    journal = _load_private_journal(
        journal_file,
        kind=PROFILE_PUBLICATION_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if journal is None:
        prior = _capture_destination(
            destination,
            rollback_directory=rollback_directory,
            expected_uid=expected_uid,
        )
        journal = _write_private_journal(
            journal_file,
            kind=PROFILE_PUBLICATION_JOURNAL_KIND,
            payload={
                "operation_id": str(uuid.uuid4()),
                "binding": binding,
                "phase": "planned",
                "prior_profile": prior,
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    elif journal.get("binding") != binding or not isinstance(
        journal.get("prior_profile"), Mapping
    ):
        raise ActivationError(
            "routing profile journal belongs to another publication"
        )
    prior_profile = dict(journal["prior_profile"])
    if journal.get("phase") == "complete":
        result = journal.get("result")
        if not isinstance(result, Mapping):
            raise ActivationError(
                "completed routing profile journal lacks its result"
            )
        attestation = cutover.verify_seal(
            result.get("attestation"),
            kind=cutover.PROFILE_REPAIR_KIND,
            fields=cutover.PROFILE_REPAIR_FIELDS,
        )
        info = destination.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o644
            or _sha256_file(destination) != attestation["profile_sha256"]
        ):
            raise ActivationError(
                "completed routing profile publication changed"
            )
        return dict(result)
    result = dict(
        cutover.reconstruct_api_profile_from_authority(
            authority_database=authority_database,
            destination=destination,
            validation_uid=validation_uid,
            authority_uid=expected_uid,
        )
    )
    result["prior_profile"] = prior_profile
    if failpoint is not None:
        failpoint("protected-profile-publication-before-journal")
    payload = {
        key: value
        for key, value in journal.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    payload.update(
        {"phase": "complete", "result": result, "updated_at": _now()}
    )
    _write_private_journal(
        journal_file,
        kind=PROFILE_PUBLICATION_JOURNAL_KIND,
        payload=payload,
        expected_uid=expected_uid,
    )
    return result


def _restore_first_adoption_profile(
    publication: Mapping[str, object],
    *,
    journal_file: Path,
    expected_uid: int,
) -> dict[str, object]:
    attestation = cutover.verify_seal(
        publication.get("attestation"),
        kind=cutover.PROFILE_REPAIR_KIND,
        fields=cutover.PROFILE_REPAIR_FIELDS,
    )
    prior = publication.get("prior_profile")
    if not isinstance(prior, Mapping):
        raise ActivationError("protected profile rollback evidence is invalid")
    destination = _absolute(
        Path(str(attestation["profile_path"])), "host routing profile"
    )
    journal_file = _absolute(
        journal_file, "routing profile publication journal"
    )
    journal = _load_private_journal(
        journal_file,
        kind=PROFILE_PUBLICATION_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if (
        journal is None
        or journal.get("result") != publication
        or journal.get("phase")
        not in {"complete", "rollback_planned", "rolled_back"}
    ):
        raise ActivationError(
            "routing profile rollback journal is contradictory"
        )

    def published_matches() -> bool:
        if not (destination.exists() or destination.is_symlink()):
            return False
        info = destination.lstat()
        return (
            not stat.S_ISLNK(info.st_mode)
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == expected_uid
            and stat.S_IMODE(info.st_mode) == 0o644
            and _sha256_file(destination)
            == attestation["profile_sha256"]
        )

    def prior_matches() -> bool:
        if prior.get("existed") is False:
            return not (
                destination.exists() or destination.is_symlink()
            )
        if prior.get("existed") is not True or not destination.exists():
            return False
        info = destination.lstat()
        return (
            not stat.S_ISLNK(info.st_mode)
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == int(prior["owner_uid"])
            and info.st_gid == int(prior["owner_gid"])
            and f"{stat.S_IMODE(info.st_mode):04o}" == prior["mode"]
            and _sha256_file(destination) == prior["sha256"]
        )

    def persist(phase: str, **updates: object) -> None:
        nonlocal journal
        payload = {
            key: value
            for key, value in journal.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(updates)
        payload.update({"phase": phase, "updated_at": _now()})
        journal = _write_private_journal(
            journal_file,
            kind=PROFILE_PUBLICATION_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )

    if journal["phase"] == "complete":
        if not published_matches():
            raise ActivationError(
                "protected client profile changed before rollback"
            )
        persist("rollback_planned")
    if journal["phase"] == "rolled_back":
        if not prior_matches():
            raise ActivationError(
                "rolled-back protected profile changed"
            )
        return {
            "restored": True,
            "prior_existed": prior.get("existed") is True,
            "replayed": True,
        }
    if published_matches():
        if prior.get("existed") is False:
            destination.unlink()
        elif prior.get("existed") is True:
            backup = _absolute(
                Path(str(prior.get("backup"))),
                "protected profile rollback copy",
            )
            payload = _read_secret(
                backup,
                label="protected profile rollback copy",
                expected_uid=expected_uid,
                maximum=MAX_JSON_BYTES,
            )
            if _sha256_bytes(payload) != prior.get("sha256"):
                raise ActivationError(
                    "protected profile rollback copy changed"
                )
            parent = destination.parent
            temporary = (
                parent
                / f".{destination.name}.{uuid.uuid4().hex}.partial"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                int(str(prior["mode"]), 8),
            )
            try:
                os.write(descriptor, payload)
                os.fchown(
                    descriptor,
                    int(prior["owner_uid"]),
                    int(prior["owner_gid"]),
                )
                os.fchmod(descriptor, int(str(prior["mode"]), 8))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            raise ActivationError(
                "protected profile prior existence is invalid"
            )
    elif not prior_matches():
        raise ActivationError(
            "protected profile rollback mutation is contradictory"
        )
    if not prior_matches():
        raise ActivationError(
            "protected profile rollback did not converge"
        )
    directory = os.open(
        destination.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    persist("rolled_back", rolled_back_at=_now())
    return {
        "restored": True,
        "prior_existed": prior.get("existed") is True,
        "replayed": False,
    }

def _plan_destination_prior(
    destination: Path,
    *,
    rollback_directory: Path,
    expected_uid: int,
) -> dict[str, object]:
    """Describe rollback bytes without mutating the rollback directory."""

    if not (destination.exists() or destination.is_symlink()):
        return {"existed": False, "backup": None}
    info = destination.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size > MAX_JSON_BYTES
    ):
        raise ActivationError(f"installed destination is unsafe: {destination}")
    payload = destination.read_bytes()
    digest = _sha256_bytes(payload)
    return {
        "existed": True,
        "backup": str(rollback_directory / f"{destination.name}.{digest}.prior"),
        "sha256": digest,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "owner_uid": int(info.st_uid),
        "owner_gid": int(info.st_gid),
        "size": len(payload),
    }


def _ensure_planned_backup(
    destination: Path,
    prior: Mapping[str, object],
    *,
    expected_uid: int,
    desired_sha256: str,
) -> None:
    if prior.get("existed") is False:
        if prior.get("backup") is not None:
            raise ActivationError("absent prior file unexpectedly names a backup")
        return
    if prior.get("existed") is not True:
        raise ActivationError("planned prior file existence is invalid")
    backup = _absolute(Path(str(prior.get("backup"))), "planned rollback backup")
    expected_sha = str(prior.get("sha256"))
    if backup.exists() or backup.is_symlink():
        payload = _read_secret(
            backup,
            label="planned rollback backup",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
        if _sha256_bytes(payload) != expected_sha:
            raise ActivationError("planned rollback backup changed")
        return
    if not (destination.exists() or destination.is_symlink()):
        raise ActivationError("prior destination vanished before backup publication")
    info = destination.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != prior.get("owner_uid")
        or info.st_gid != prior.get("owner_gid")
        or f"{stat.S_IMODE(info.st_mode):04o}" != prior.get("mode")
    ):
        raise ActivationError("prior destination identity changed before backup")
    payload = destination.read_bytes()
    digest = _sha256_bytes(payload)
    if digest == desired_sha256 and digest != expected_sha:
        raise ActivationError(
            "destination was replaced before its rollback backup was durable"
        )
    if digest != expected_sha:
        raise ActivationError("prior destination content changed before backup")
    _atomic_private(backup, payload, expected_uid=expected_uid)


def _atomic_install(
    destination: Path,
    payload: bytes,
    *,
    expected_uid: int,
    mode: int = 0o644,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    allowed_parent_uids: set[int] | None = None,
) -> None:
    parent = destination.parent
    parent_info = parent.lstat()
    system_uid = Path("/").stat().st_uid
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid
        not in ({system_uid, expected_uid} | (allowed_parent_uids or set()))
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise ActivationError(f"candidate install parent is unsafe: {parent}")
    temporary = parent / f".{destination.name}.{uuid.uuid4().hex}.partial"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        os.write(descriptor, payload)
        os.fchown(
            descriptor,
            expected_uid if owner_uid is None else owner_uid,
            parent_info.st_gid if owner_gid is None else owner_gid,
        )
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, destination)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_prepared_graph(
    preparation: Mapping[str, object],
    *,
    runner: CommandRunner,
    expected_uid: int,
) -> None:
    prior_units = preparation.get("prior_units")
    prior_files = preparation.get("prior_files")
    if not isinstance(prior_units, Mapping) or not isinstance(prior_files, Mapping):
        raise ActivationError("candidate preparation rollback graph is invalid")
    for unit, raw in reversed(list(prior_units.items())):
        if (
            not isinstance(raw, Mapping)
            or type(raw.get("active")) is not bool
            or type(raw.get("enabled")) is not bool
        ):
            raise ActivationError("candidate prior unit state is invalid")
        if runner.status(
            ["/usr/bin/systemctl", "stop", str(unit)]
        ) != 0:
            raise ActivationError(
                f"candidate rollback could not stop unit {unit}"
            )
    for destination_text, raw in prior_files.items():
        if not isinstance(raw, Mapping):
            raise ActivationError("candidate prior file state is invalid")
        destination = Path(str(destination_text))
        if raw.get("existed") is True:
            backup = Path(str(raw.get("backup")))
            payload = _read_secret(
                backup,
                label="candidate graph rollback file",
                expected_uid=expected_uid,
                maximum=MAX_JSON_BYTES,
            )
            if _sha256_bytes(payload) != raw.get("sha256"):
                raise ActivationError("candidate graph rollback file changed")
            _atomic_install(
                destination,
                payload,
                expected_uid=expected_uid,
                mode=int(str(raw["mode"]), 8),
                owner_uid=int(raw["owner_uid"]),
                owner_gid=int(raw["owner_gid"]),
            )
        elif raw.get("existed") is False:
            info = (
                destination.lstat()
                if destination.exists() or destination.is_symlink()
                else None
            )
            if info is not None:
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise ActivationError("candidate-created path is no longer removable")
                destination.unlink()
                descriptor = os.open(
                    destination.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        else:
            raise ActivationError("candidate prior file existence is invalid")
    if runner.status(["/usr/bin/systemctl", "daemon-reload"]) != 0:
        raise ActivationError("systemd graph rollback reload failed")
    for unit, raw in prior_units.items():
        if not isinstance(raw, Mapping):
            raise ActivationError("candidate prior unit state is invalid")
        active = raw.get("active") is True
        enabled = raw.get("enabled") is True
        if enabled:
            if runner.status(
                ["/usr/bin/systemctl", "enable", str(unit)]
            ) != 0:
                raise ActivationError(f"failed to re-enable prior unit {unit}")
        elif runner.status(
            ["/usr/bin/systemctl", "disable", str(unit)]
        ) != 0:
            raise ActivationError(f"failed to re-disable prior unit {unit}")
        if active and runner.status(
            ["/usr/bin/systemctl", "start", str(unit)]
        ) != 0:
            raise ActivationError(f"failed to restart prior unit {unit}")
        if _systemd_unit_state(runner, str(unit)) != (active, enabled):
            raise ActivationError(
                f"candidate rollback unit state did not converge: {unit}"
            )
    for destination_text, raw in prior_files.items():
        destination = Path(str(destination_text))
        if raw.get("existed") is False:
            if destination.exists() or destination.is_symlink():
                raise ActivationError(
                    "candidate-created path remained after rollback"
                )
            continue
        info = destination.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != int(raw["owner_uid"])
            or info.st_gid != int(raw["owner_gid"])
            or f"{stat.S_IMODE(info.st_mode):04o}" != raw["mode"]
            or _sha256_file(destination) != raw["sha256"]
        ):
            raise ActivationError(
                "candidate rollback file state did not converge"
            )


def _systemd_properties(runner: CommandRunner, unit: str) -> dict[str, str]:
    output = runner.text(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=ActiveState",
            "--property=UID",
            "--property=Slice",
            "--property=FragmentPath",
        ]
    )
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    if set(result) != {"ActiveState", "UID", "Slice", "FragmentPath"}:
        raise ActivationError(f"loaded unit properties are incomplete: {unit}")
    return result


def prepare_background_configuration(
    *,
    release: Path,
    legacy_console_env: Path,
    project_root: Path,
    transaction_directory: Path,
    expected_uid: int,
    runner: CommandRunner,
    legacy_console_uid: int | None = None,
) -> dict[str, object]:
    """Render and verify one immutable background-config transaction.

    A pre-existing transaction is accepted only through the immutable
    verifier, which makes candidate preparation safely resumable without
    trusting caller-authored env files.
    """

    executable = release / "bin/devcoordinator-background-handoff"
    if not executable.is_file() or executable.is_symlink():
        raise ActivationError("immutable background handoff helper is unavailable")
    legacy_console_env = _absolute(legacy_console_env, "legacy Console environment")
    project_root = _absolute(project_root, "background project root")
    transaction_directory = _absolute(
        transaction_directory, "background config transaction"
    )
    source_uid = expected_uid if legacy_console_uid is None else legacy_console_uid
    if type(source_uid) is not int or source_uid < 0:
        raise ActivationError("legacy Console environment owner UID is invalid")
    if not transaction_directory.exists() and not transaction_directory.is_symlink():
        rendered = runner.run_json(
            [
                str(executable),
                "render",
                "--legacy-console-env",
                str(legacy_console_env),
                "--source-owner-uid",
                str(source_uid),
                "--project-root",
                str(project_root),
                "--output-directory",
                str(transaction_directory),
            ]
        )
        if rendered.get("ok") is not True:
            raise ActivationError("background config rendering did not verify")
    verified = runner.run_json(
        [
            str(executable),
            "verify-config",
            "--directory",
            str(transaction_directory),
        ]
    )
    if (
        set(verified)
        != {
            "ok",
            "kind",
            "directory",
            "project_root",
            "files",
            "administrator_count",
        }
        or verified.get("ok") is not True
        or verified.get("kind") != BACKGROUND_CONFIG_KIND
        or verified.get("directory") != str(transaction_directory)
        or verified.get("project_root") != str(project_root)
        or not isinstance(verified.get("files"), Mapping)
        or set(verified["files"]) != {"notifications.env", "observer.env"}
    ):
        raise ActivationError("background config transaction contract is invalid")
    for name in ("notifications.env", "observer.env", "transaction.json"):
        _read_install_source(transaction_directory / name, expected_uid=expected_uid)
    return dict(verified)


def prepare_project_runtime_isolation(
    *,
    release: Path,
    authority_database: Path,
    audit_path: Path,
    ledger_path: Path,
    expected_uid: int,
    runner: CommandRunner,
    observation_only: bool = False,
) -> dict[str, object]:
    """Capture/verify a fresh exact-ID isolation audit without mutating runtimes."""

    executable = release / "bin/devcoordinator-project-isolation-audit"
    if not executable.is_file() or executable.is_symlink():
        raise ActivationError("immutable project isolation auditor is unavailable")
    authority_database = _absolute(authority_database, "authority database")
    audit_path = _absolute(audit_path, "project isolation audit")
    ledger_path = _absolute(ledger_path, "project isolation migration ledger")
    if not audit_path.exists() and not audit_path.is_symlink():
        captured = runner.run_json(
            [
                str(executable),
                "capture",
                "--database",
                str(authority_database),
                "--output",
                str(audit_path),
            ]
        )
        if captured.get("ok") is not True:
            raise ActivationError("project isolation audit capture failed")
    verification_command = [
        str(executable), "verify", "--audit", str(audit_path),
        "--database", str(authority_database), "--require-fresh",
    ]
    base = runner.run_json(verification_command)
    counts = base.get("audit_counts")
    source_schema_version = base.get("source_schema_version")
    if (
        base.get("ok") is not True
        or base.get("kind") != PROJECT_ISOLATION_VERIFICATION_KIND
        or not isinstance(counts, Mapping)
        or set(counts)
        != {"compliant", "legacy_requires_recreation", "unobservable"}
        or any(type(value) is not int or value < 0 for value in counts.values())
        or source_schema_version != COORDINATOR_SCHEMA_VERSION
    ):
        raise ActivationError("project isolation verification contract is invalid")
    if type(observation_only) is not bool:
        raise ActivationError("project isolation observation mode is invalid")
    if counts["unobservable"] and not observation_only:
        raise ActivationError("unobservable project runtimes block candidate preparation")
    verification = base
    if counts["legacy_requires_recreation"] and not observation_only:
        if not ledger_path.exists() and not ledger_path.is_symlink():
            initialized = runner.run_json(
                [
                    str(executable),
                    "ledger-init",
                    "--audit",
                    str(audit_path),
                    "--output",
                    str(ledger_path),
                    "--deadline-hours",
                    "24",
                ]
            )
            if initialized.get("ok") is not True:
                raise ActivationError("project isolation migration ledger initialization failed")
        verification = runner.run_json(
            [
                *verification_command,
                "--ledger",
                str(ledger_path),
            ]
        )
        if (
            verification.get("ok") is not True
            or verification.get("kind") != PROJECT_ISOLATION_VERIFICATION_KIND
            or not isinstance(verification.get("ledger_counts"), Mapping)
        ):
            raise ActivationError("project isolation migration ledger is invalid")
    _read_install_source(audit_path, expected_uid=expected_uid)
    if not observation_only and (ledger_path.exists() or ledger_path.is_symlink()):
        _read_install_source(ledger_path, expected_uid=expected_uid)
    return {
        **verification,
        "authority_database": str(authority_database),
        "audit_path": str(audit_path),
        "ledger_path": (
            str(ledger_path)
            if not observation_only and (ledger_path.exists() or ledger_path.is_symlink())
            else None
        ),
        "observation_only": observation_only,
        "project_resources_mutated": False,
    }


def require_complete_project_runtime_isolation(
    verification: Mapping[str, object],
) -> dict[str, object]:
    """Refuse candidate acceptance while any managed runtime is not isolated."""

    counts = verification.get("audit_counts")
    if (
        not isinstance(counts, Mapping)
        or set(counts) != {"compliant", "legacy_requires_recreation", "unobservable"}
        or any(type(value) is not int or value < 0 for value in counts.values())
    ):
        raise ActivationError("project isolation completion counts are invalid")
    ledger_counts = verification.get("ledger_counts")
    if ledger_counts is not None and (
        not isinstance(ledger_counts, Mapping)
        or set(ledger_counts) != {"pending", "completed", "retired"}
        or any(type(value) is not int or value < 0 for value in ledger_counts.values())
    ):
        raise ActivationError("project isolation ledger completion counts are invalid")
    pending = 0 if ledger_counts is None else int(ledger_counts["pending"])
    if (
        int(counts["legacy_requires_recreation"]) != 0
        or int(counts["unobservable"]) != 0
        or pending != 0
        or verification.get("project_isolation_complete") is not True
    ):
        raise ActivationError(
            "all managed project runtimes must be isolated before candidate acceptance"
        )
    return dict(verification)


def prepare_candidate(
    *,
    state: Mapping[str, object],
    candidate_slot_source: Path,
    host_preflight: Mapping[str, object] | None = None,
    legacy_console_env: Path,
    background_project_root: Path,
    background_config_transaction: Path,
    project_isolation_audit: Path,
    project_isolation_ledger: Path,
    credentials: Mapping[str, Path] = DEFAULT_CREDENTIALS,
    rollback_directory: Path,
    expected_uid: int = 0,
    legacy_console_uid: int | None = None,
    expected_port_reservations: Mapping[str, int] | None = None,
    runner: CommandRunner | None = None,
    oidc_fetcher: Callable[[str, float], bytes] = _default_oidc_fetcher,
    socket_reader: Callable[[], dict[str, int]] = socket_inodes,
    unit_root: Path = SYSTEMD_UNIT_ROOT,
    sysusers_root: Path = SYSUSERS_ROOT,
    tmpfiles_root: Path = TMPFILES_ROOT,
    slot_root: Path = CONSOLE_SLOT_ROOT,
    background_config_root: Path = BACKGROUND_CONFIG_ROOT,
    topology_validator: Callable[[Path, str], Sequence[object]] | None = None,
    first_adoption_defer_start: bool = False,
    clean_adoption_defer_start: bool = False,
    first_adoption_legacy_authority_database: Path | None = None,
    first_adoption_journal: Path | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Install one exact graph and normally start its verified candidate.

    ``first_adoption_defer_start`` installs and seals the same graph but leaves
    every new listener stopped.  Only the journaled first-adoption executor may
    consume that proof; ordinary candidate preparation still starts and
    verifies the complete final topology exactly as before.
    """

    current = cutover.validate_state(state)
    if clean_adoption_defer_start and not first_adoption_defer_start:
        raise ActivationError(
            "clean adoption is valid only for a deferred first installation"
        )
    if current["phase"] != "sealed":
        raise ActivationError("candidate preparation requires the sealed migration")
    if os.geteuid() != expected_uid:
        raise ActivationError("candidate preparation must run as the authority UID")
    release = Path(str(current["release"]))
    digest = str(current["release_digest"])
    if release != IMMUTABLE_RELEASE_ROOT / digest:
        raise ActivationError("candidate release path and digest disagree")
    command = runner or CommandRunner()
    existing_graph_journal: dict[str, object] | None = None
    existing_graph_journal_path: Path | None = None
    if first_adoption_defer_start:
        if first_adoption_journal is None:
            raise ActivationError(
                "deferred first-adoption preparation requires a durable journal"
            )
        existing_graph_journal_path = _absolute(
            first_adoption_journal, "first-adoption graph installation journal"
        )
        existing_graph_journal = _load_private_journal(
            existing_graph_journal_path,
            kind=FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
            expected_uid=expected_uid,
        )
        if (
            existing_graph_journal is not None
            and existing_graph_journal.get("release_digest") != digest
        ):
            raise ActivationError(
                "first-adoption graph journal belongs to another release"
            )
    canonical_host_preflight = run_host_preflight(release=release, runner=command)
    if host_preflight is not None:
        raise ActivationError(
            "caller-supplied host preflight is forbidden; activation executes the immutable release gate"
        )
    rendered = Path(str(current["rendered_units"]))
    validate = topology_validator
    if validate is None:
        checker = _load_topology_checker()
        validate = lambda path, release_digest: checker.validate_topology(  # noqa: E731
            path, release_digest=release_digest
        )
    findings = list(validate(rendered, digest))
    if findings:
        raise ActivationError("rendered candidate topology is invalid")
    background_config = prepare_background_configuration(
        release=release,
        legacy_console_env=legacy_console_env,
        project_root=background_project_root,
        transaction_directory=background_config_transaction,
        expected_uid=expected_uid,
        runner=command,
        legacy_console_uid=legacy_console_uid,
    )
    if first_adoption_defer_start:
        if first_adoption_legacy_authority_database is None:
            raise ActivationError(
                "deferred installation requires an explicit authority database"
            )
        isolation_database = first_adoption_legacy_authority_database
    else:
        if first_adoption_legacy_authority_database is not None:
            raise ActivationError(
                "ordinary candidate preparation must use the current coordinator database"
            )
        isolation_database = Path(str(current["authority_database"]))
    project_isolation = prepare_project_runtime_isolation(
        release=release,
        authority_database=Path(isolation_database),
        audit_path=project_isolation_audit,
        ledger_path=project_isolation_ledger,
        expected_uid=expected_uid,
        runner=command,
        observation_only=clean_adoption_defer_start,
    )
    if not clean_adoption_defer_start:
        project_isolation = require_complete_project_runtime_isolation(
            project_isolation
        )
    current_credential = preflight_credentials(
        release_digest=digest,
        credentials=credentials,
        expected_uid=expected_uid,
        oidc_fetcher=oidc_fetcher,
    )
    credential = current_credential
    if existing_graph_journal is not None:
        recorded_credential = existing_graph_journal.get("credential_preflight")
        recorded_host = existing_graph_journal.get("host_preflight")
        if not isinstance(recorded_credential, Mapping) or not isinstance(
            recorded_host, Mapping
        ):
            raise ActivationError(
                "first-adoption graph journal omitted its preflight evidence"
            )

        def stable_preflight(value: Mapping[str, object]) -> dict[str, object]:
            return {
                key: item
                for key, item in value.items()
                if key not in {"created_at", "observed_at", "document_sha256"}
            }

        if (
            stable_preflight(recorded_credential)
            != stable_preflight(current_credential)
            or stable_preflight(recorded_host)
            != stable_preflight(canonical_host_preflight)
        ):
            raise ActivationError(
                "first-adoption preflight inputs changed during graph resume"
            )
        credential = dict(recorded_credential)
        canonical_host_preflight = dict(recorded_host)
    rollback_directory = _private_directory(
        rollback_directory, expected_uid=expected_uid
    )
    console_unit = f"devcoordinator-console@{digest}.service"
    first_adoption_units = (
        *HANDOFF_SOCKET_UNITS,
        HANDOFF_SERVICE_UNIT,
        API_HANDOFF_SOCKET_UNIT,
        API_HANDOFF_SERVICE_UNIT,
    )
    managed_units = (
        *SOCKET_UNITS,
        *SERVICE_UNITS,
        console_unit,
        *(first_adoption_units if first_adoption_defer_start else ()),
    )
    prior_units = {
        unit: {
            "active": command.status(
                ["/usr/bin/systemctl", "is-active", "--quiet", unit]
            )
            == 0,
            "enabled": command.status(
                ["/usr/bin/systemctl", "is-enabled", "--quiet", unit]
            )
            == 0,
        }
        for unit in managed_units
    }
    sources: dict[Path, tuple[bytes, dict[str, object]]] = {}
    install_modes: dict[Path, int] = {}
    for name in TOPOLOGY_FILES:
        sources[unit_root / name] = _read_install_source(
            rendered / name, expected_uid=expected_uid
        )
    if clean_adoption_defer_start:
        # Clean adoption has already stopped the legacy broker before this
        # graph transaction.  Install its rendered retired definition now so
        # the following daemon-reload cannot retain an older unit which owns
        # the authority socket's shared runtime directory.  Deliberately keep
        # this file out of ``managed_units``: clean adoption must neither start
        # nor otherwise manage the retired broker.
        sources[unit_root / LEGACY_BROKER_SERVICE_UNIT] = _read_install_source(
            rendered / LEGACY_BROKER_SERVICE_UNIT,
            expected_uid=expected_uid,
        )
    if first_adoption_defer_start:
        for name in (*HANDOFF_FILES, *API_HANDOFF_FILES):
            sources[unit_root / name] = _read_install_source(
                rendered / name, expected_uid=expected_uid
            )
    for name, root in (
        ("devcoordinator-availability.sysusers.conf", sysusers_root),
        ("devcoordinator-availability.tmpfiles.conf", tmpfiles_root),
    ):
        sources[root / name] = _read_install_source(
            rendered / name, expected_uid=expected_uid
        )
    slot_payload, slot_source = _read_install_source(
        candidate_slot_source, expected_uid=expected_uid
    )
    slot_ports = _console_slot_listener_ports(slot_payload)
    if expected_port_reservations is not None:
        expected_console_ports = {
            role: expected_port_reservations.get(role)
            for role in ("console_outer", "console_inner")
        }
        if (
            any(type(value) is not int for value in expected_console_ports.values())
            or slot_ports != expected_console_ports
        ):
            raise ActivationError(
                "candidate Console slot does not match the sealed port reservations"
            )
    wanted_slot = slot_root / f"{digest}.env"
    if candidate_slot_source.name != wanted_slot.name:
        raise ActivationError("candidate Console slot source has another release")
    sources[wanted_slot] = (slot_payload, slot_source)
    for name in ("notifications.env", "observer.env"):
        destination = background_config_root / name
        sources[destination] = _read_install_source(
            background_config_transaction / name,
            expected_uid=expected_uid,
        )
        install_modes[destination] = 0o600
    static_preparation = {
        "release_digest": digest,
        "executor_release": str(release),
        "credential_preflight_sha256": credential["document_sha256"],
        "host_preflight_sha256": canonical_host_preflight["document_sha256"],
        "background_config": {
            **background_config,
            "transaction_sha256": _sha256_file(
                background_config_transaction / "transaction.json"
            ),
        },
        "project_isolation": project_isolation,
        "console_slot_ports": slot_ports,
        **({"clean_adoption": True} if clean_adoption_defer_start else {}),
    }
    install_plan = {
        str(destination): {
            **source,
            "installed_sha256": _sha256_bytes(payload),
            "installed_mode": f"{install_modes.get(destination, 0o644):04o}",
        }
        for destination, (payload, source) in sources.items()
    }
    graph_journal: dict[str, object] | None = None
    graph_journal_path: Path | None = None
    if first_adoption_defer_start:
        graph_journal_path = existing_graph_journal_path
        if graph_journal_path is None:
            raise ActivationError("first-adoption graph journal path disappeared")
        graph_journal = existing_graph_journal
        if graph_journal is None:
            prior_files = {
                str(destination): _plan_destination_prior(
                    destination,
                    rollback_directory=rollback_directory,
                    expected_uid=expected_uid,
                )
                for destination in sources
            }
            graph_journal = _write_private_journal(
                graph_journal_path,
                kind=FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
                payload={
                    "operation_id": str(uuid.uuid4()),
                    "release_digest": digest,
                    "phase": "planned",
                    "credential_preflight": credential,
                    "host_preflight": canonical_host_preflight,
                    "static_preparation": static_preparation,
                    "prior_units": prior_units,
                    "prior_files": prior_files,
                    "install_plan": install_plan,
                    "backups_ready": [],
                    "installed_files": {},
                    "created_at": _now(),
                    "updated_at": _now(),
                },
                expected_uid=expected_uid,
            )
        else:
            if (
                graph_journal.get("release_digest") != digest
                or graph_journal.get("static_preparation") != static_preparation
                or graph_journal.get("install_plan") != install_plan
                or not isinstance(graph_journal.get("prior_units"), Mapping)
                or not isinstance(graph_journal.get("prior_files"), Mapping)
            ):
                raise ActivationError(
                    "first-adoption graph journal belongs to another installation"
                )
            prior_units = dict(graph_journal["prior_units"])
            prior_files = dict(graph_journal["prior_files"])
    else:
        if first_adoption_journal is not None:
            raise ActivationError(
                "ordinary candidate preparation cannot consume a first-adoption journal"
            )
        prior_files = {
            str(destination): _capture_destination(
                destination,
                rollback_directory=rollback_directory,
                expected_uid=expected_uid,
            )
            for destination in sources
        }
    preparation_base = {
        **static_preparation,
        "prior_units": prior_units,
        "prior_files": prior_files,
    }
    installed: dict[str, object] = {}
    try:
        if graph_journal is not None and graph_journal_path is not None:
            installed_value = graph_journal.get("installed_files")
            backups_value = graph_journal.get("backups_ready")
            if not isinstance(installed_value, Mapping) or not isinstance(
                backups_value, list
            ):
                raise ActivationError(
                    "first-adoption graph journal progress is invalid"
                )
            installed = dict(installed_value)
            backups_ready = list(backups_value)

            def persist_graph_progress(phase: str) -> None:
                nonlocal graph_journal
                payload = {
                    key: value
                    for key, value in graph_journal.items()
                    if key not in {"schema_version", "kind", "document_sha256"}
                }
                payload.update(
                    {
                        "phase": phase,
                        "backups_ready": list(backups_ready),
                        "installed_files": dict(installed),
                        "updated_at": _now(),
                    }
                )
                graph_journal = _write_private_journal(
                    graph_journal_path,
                    kind=FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
                    payload=payload,
                    expected_uid=expected_uid,
                )

            for destination_text, prior in prior_files.items():
                if not isinstance(prior, Mapping):
                    raise ActivationError(
                        "first-adoption graph prior-file entry is invalid"
                    )
                plan = install_plan.get(destination_text)
                if not isinstance(plan, Mapping):
                    raise ActivationError(
                        "first-adoption graph install plan is incomplete"
                    )
                destination = Path(destination_text)
                _ensure_planned_backup(
                    destination,
                    prior,
                    expected_uid=expected_uid,
                    desired_sha256=str(plan["installed_sha256"]),
                )
                if destination_text not in backups_ready:
                    if failpoint is not None:
                        failpoint(f"graph-backup-before-journal:{destination_text}")
                    backups_ready.append(destination_text)
                    persist_graph_progress("backups_ready")
        for destination, (payload, source) in sources.items():
            destination_text = str(destination)
            desired_mode = install_modes.get(destination, 0o644)
            desired = {
                **source,
                "installed_sha256": _sha256_bytes(payload),
            }
            exact = _exact_regular_file(
                destination,
                sha256=str(desired["installed_sha256"]),
                mode=desired_mode,
                owner_uid=expected_uid,
            )
            if destination_text in installed:
                if installed[destination_text] != desired or not exact:
                    raise ActivationError(
                        f"journaled candidate file changed during resume: {destination}"
                    )
                continue
            if not exact:
                prior = prior_files[destination_text]
                if not isinstance(prior, Mapping):
                    raise ActivationError("candidate prior file state is invalid")
                if prior.get("existed") is True:
                    expected_prior = str(prior.get("sha256"))
                    prior_mode = int(str(prior.get("mode")), 8)
                    if not _exact_regular_file(
                        destination,
                        sha256=expected_prior,
                        mode=prior_mode,
                        owner_uid=int(prior.get("owner_uid")),
                        owner_gid=int(prior.get("owner_gid")),
                    ):
                        raise ActivationError(
                            f"candidate destination is neither prior nor desired: {destination}"
                        )
                elif prior.get("existed") is False:
                    if destination.exists() or destination.is_symlink():
                        raise ActivationError(
                            f"unexpected candidate destination appeared: {destination}"
                        )
                else:
                    raise ActivationError("candidate prior file existence is invalid")
                _atomic_install(
                    destination,
                    payload,
                    expected_uid=expected_uid,
                    mode=desired_mode,
                )
            if failpoint is not None and graph_journal is not None:
                failpoint(f"graph-install-before-journal:{destination_text}")
            installed[destination_text] = desired
            if graph_journal is not None:
                persist_graph_progress("files_installing")
        if command.status(
            [
                "/usr/bin/systemd-sysusers",
                str(sysusers_root / "devcoordinator-availability.sysusers.conf"),
            ]
        ) != 0:
            raise ActivationError("systemd service identity preparation failed")
        if graph_journal is not None:
            if failpoint is not None:
                failpoint("graph-sysusers-before-journal")
            persist_graph_progress("sysusers_ready")
        if command.status(
            [
                "/usr/bin/systemd-tmpfiles",
                "--create",
                str(tmpfiles_root / "devcoordinator-availability.tmpfiles.conf"),
            ]
        ) != 0:
            raise ActivationError("systemd private path preparation failed")
        if graph_journal is not None:
            if failpoint is not None:
                failpoint("graph-tmpfiles-before-journal")
            persist_graph_progress("tmpfiles_ready")
        if command.status(["/usr/bin/systemctl", "daemon-reload"]) != 0:
            raise ActivationError("systemd candidate reload failed")
        if graph_journal is not None:
            if failpoint is not None:
                failpoint("graph-reload-before-journal")
            persist_graph_progress("daemon_reloaded")
        if first_adoption_defer_start:
            preparation = cutover.seal(
                FIRST_ADOPTION_GRAPH_KIND,
                {
                    **preparation_base,
                    "credential_preflight": credential,
                    "installed_files": installed,
                    "deferred_units": sorted(managed_units),
                    "listeners_started": False,
                    "created_at": graph_journal["created_at"],
                },
            )
            if graph_journal is None:
                raise ActivationError("first-adoption graph journal disappeared")
            persisted_result = graph_journal.get("result")
            if persisted_result is not None and persisted_result != preparation:
                raise ActivationError(
                    "first-adoption graph journal result is contradictory"
                )
            payload = {
                key: value
                for key, value in graph_journal.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload.update(
                {
                    "phase": "complete",
                    "installed_files": dict(installed),
                    "result": preparation,
                    "updated_at": _now(),
                }
            )
            _write_private_journal(
                graph_journal_path,
                kind=FIRST_ADOPTION_GRAPH_JOURNAL_KIND,
                payload=payload,
                expected_uid=expected_uid,
            )
            return preparation, credential
        for unit in SOCKET_UNITS:
            if command.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                raise ActivationError(
                    f"stable socket owner could not start without a listener conflict: {unit}"
                )
        for unit in (*SERVICE_UNITS, console_unit):
            if command.status(["/usr/bin/systemctl", "enable", "--now", unit]) != 0:
                raise ActivationError(f"candidate unit failed readiness: {unit}")
        ready_units: dict[str, bool] = {}
        service_uids: dict[str, int] = {}
        service_slices: dict[str, str] = {}
        for unit in sorted(cutover._candidate_units(digest)):
            properties = _systemd_properties(command, unit)
            fragment = Path(properties["FragmentPath"])
            if fragment.parent != unit_root or fragment.name not in {
                unit,
                "devcoordinator-console@.service",
            }:
                raise ActivationError(f"loaded unit is not the installed release unit: {unit}")
            ready_units[unit] = properties["ActiveState"] == "active"
            try:
                service_uids[unit] = int(properties["UID"])
            except ValueError as error:
                raise ActivationError(f"loaded service UID is invalid: {unit}") from error
            service_slices[unit] = properties["Slice"]
        if not all(ready_units.values()):
            raise ActivationError("one or more candidate units are not ready")
        sockets = socket_reader()
        preparation = cutover.seal(
            CANDIDATE_PREPARATION_KIND,
            {
                **preparation_base,
                "installed_files": installed,
                "ready_units": ready_units,
                "socket_inodes": sockets,
                "created_at": _now(),
            },
        )
        completion = cutover._test_store_cutover_completion(current)
        candidate = cutover.seal(
            cutover.CANDIDATE_KIND,
            {
                "release_digest": digest,
                "ready_units": ready_units,
                "service_uids": service_uids,
                "service_slices": service_slices,
                "socket_inodes": sockets,
                "authority_database": current["authority_database"],
                "test_database": current["test_database"],
                "migration_seal_sha256": completion["document_sha256"],
                "checks_passed": True,
                "preparation": preparation,
                "created_at": _now(),
            },
        )
        cutover.transition(current, evidence_kind="candidate", evidence=candidate)
        return candidate, credential
    except PowerLossSimulation:
        raise
    except BaseException as error:
        preparation = {
            **preparation_base,
            "installed_files": installed,
        }
        try:
            _restore_prepared_graph(
                preparation,
                runner=command,
                expected_uid=expected_uid,
            )
        except BaseException as rollback_error:
            raise ActivationError(
                f"candidate preparation failed ({error}); graph rollback failed ({rollback_error})"
            ) from error
        raise ActivationError(f"candidate preparation failed and graph was restored: {error}") from error


def activate(
    *,
    state: Mapping[str, object],
    publication_file: Path,
    candidate_control: Path,
    previous_control: Path,
    credentials: Mapping[str, Path] = DEFAULT_CREDENTIALS,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    oidc_fetcher: Callable[[str, float], bytes] = _default_oidc_fetcher,
    socket_reader: Callable[[], dict[str, int]] = socket_inodes,
    probe: Callable[[str], tuple[int | None, bool]] = _probe_url,
    continuity_probe: Callable[[str], tuple[int | None, bool]] | None = None,
    switch_journal: Path | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    """Activate one candidate and return (activation, credential preflight)."""

    current = cutover.validate_state(state)
    if current["phase"] != "candidate_verified":
        raise ActivationError("cutover candidate is not verified")
    if os.geteuid() != expected_uid:
        raise ActivationError("activation must run as the authority UID")
    release = Path(str(current["release"]))
    digest = str(current["release_digest"])
    if release != IMMUTABLE_RELEASE_ROOT / digest:
        raise ActivationError("candidate release path and digest disagree")
    publication_cli = release / "bin/devcoordinator-edge-publication"
    slot_cli = release / "bin/devcoordinator-console-slot-control"
    for executable in (publication_cli, slot_cli):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ActivationError("immutable release lacks an activation executable")

    # This is intentionally first: no promotion or publication mutation is
    # attempted until every LoadCredential source and live OIDC metadata pass.
    credential_evidence = preflight_credentials(
        release_digest=digest,
        credentials=credentials,
        expected_uid=expected_uid,
        oidc_fetcher=oidc_fetcher,
    )
    command = runner or CommandRunner()
    switch_path = (
        None
        if switch_journal is None
        else _absolute(switch_journal, "activation switch journal")
    )
    preexisting_switch = (
        None
        if switch_path is None
        else _load_private_journal(
            switch_path,
            kind=ACTIVATION_SWITCH_JOURNAL_KIND,
            expected_uid=expected_uid,
        )
    )
    candidate = current["evidence"]["candidate"]  # type: ignore[index]
    preparation = cutover.verify_seal(
        candidate["preparation"],
        kind=cutover.CANDIDATE_PREPARATION_KIND,
        fields=cutover.CANDIDATE_PREPARATION_FIELDS,
    )
    if (
        preparation["release_digest"] != digest
        or preparation["executor_release"] != str(release)
        or preparation["socket_inodes"] != candidate["socket_inodes"]
    ):
        raise ActivationError("candidate preparation evidence contradicts activation")
    edge_uid = int(candidate["service_uids"]["devcoordinator-edge.service"])
    verified = command.run_json(
        [
            str(publication_cli),
            "verify",
            "--file",
            str(publication_file),
            "--release-root",
            str(release.parent),
            "--expected-uid",
            str(edge_uid),
        ]
    )
    before_envelope = _load_publication(publication_file)
    if verified.get("payload_sha256") != before_envelope.get("payload_sha256"):
        raise ActivationError("publication changed after immutable verification")
    publication = before_envelope["publication"]
    if not isinstance(publication, Mapping):
        raise ActivationError("activation publication payload is invalid")
    previous_release = str(
        preexisting_switch["previous_release_digest"]
        if preexisting_switch is not None
        else publication["release_digest"]
    )
    if re.fullmatch(r"[0-9a-f]{64}", previous_release) is None:
        raise ActivationError("activation switch predecessor release is invalid")
    source_publication = (
        preexisting_switch.get("before_publication")
        if preexisting_switch is not None
        else before_envelope
    )
    if not isinstance(source_publication, Mapping):
        raise ActivationError("activation switch predecessor publication is invalid")
    source_payload = source_publication.get("publication")
    if not isinstance(source_payload, Mapping):
        raise ActivationError("activation switch predecessor payload is invalid")
    previous_target = source_payload["console"]
    if not isinstance(previous_target, Mapping):
        raise ActivationError("activation publication Console target is invalid")
    previous_upstream = previous_target["upstream"]
    if not isinstance(previous_upstream, Mapping):
        raise ActivationError("activation publication upstream is invalid")
    previous_port = int(
        preexisting_switch["previous_port"]
        if preexisting_switch is not None
        else previous_upstream["port"]
    )

    candidate_status = _slot_status(
        command,
        candidate_control,
        slot_cli,
        expected_release=digest,
        expected_mode=None if preexisting_switch is not None else "standby",
    )
    previous_status = _slot_status(
        command,
        previous_control,
        slot_cli,
        expected_release=previous_release,
        expected_mode=None if preexisting_switch is not None else "active",
    )
    if int(candidate_status["port"]) == previous_port or int(previous_status["port"]) != previous_port:
        raise ActivationError("Console slot ports contradict the active publication")
    before_sockets = socket_reader()
    if before_sockets != cutover._socket_map(candidate["socket_inodes"]):
        raise ActivationError("listener identity changed after candidate verification")
    if preexisting_switch is None:
        legacy_states = {unit: _unit_state(command, unit) for unit in LEGACY_UNITS}
    else:
        recorded_legacy = preexisting_switch.get("legacy_states")
        if not isinstance(recorded_legacy, Mapping) or set(recorded_legacy) != set(
            LEGACY_UNITS
        ):
            raise ActivationError("activation switch legacy state is invalid")
        legacy_states = {}
        for unit, value in recorded_legacy.items():
            if (
                not isinstance(value, Mapping)
                or set(value) != {"active", "enabled"}
                or type(value["active"]) is not bool
                or type(value["enabled"]) is not bool
            ):
                raise ActivationError("activation switch legacy state is invalid")
            legacy_states[str(unit)] = (bool(value["active"]), bool(value["enabled"]))

    switch_record: dict[str, object] | None = preexisting_switch
    switch_created_at = _now()
    recovery_count = 0

    def persist_switch(
        phase: str,
        *,
        before: Mapping[str, object],
        pending: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        nonlocal switch_record, switch_created_at, recovery_count
        if switch_path is None:
            return {}
        if phase not in ACTIVATION_SWITCH_PHASES:
            raise ActivationError("activation switch journal phase is invalid")
        payload = {
            "cutover_id": str(current["cutover_id"]),
            "release": str(release),
            "release_digest": digest,
            "publication": str(_absolute(publication_file, "edge publication")),
            "candidate_control": str(_absolute(candidate_control, "candidate control")),
            "previous_control": str(_absolute(previous_control, "previous control")),
            "phase": phase,
            "before_publication": dict(before),
            "candidate_port": int(candidate_status["port"]),
            "previous_release_digest": previous_release,
            "previous_port": previous_port,
            "socket_inodes": dict(before_sockets),
            "legacy_states": {
                unit: {"active": active, "enabled": enabled}
                for unit, (active, enabled) in sorted(legacy_states.items())
            },
            "credential_preflight": credential_evidence,
            "pending_activation": None if pending is None else dict(pending),
            "recovery_count": recovery_count,
            "created_at": switch_created_at,
            "updated_at": _now(),
        }
        switch_record = _write_private_journal(
            switch_path,
            kind=ACTIVATION_SWITCH_JOURNAL_KIND,
            payload=payload,
            expected_uid=expected_uid,
        )
        return switch_record

    if switch_path is not None:
        switch_record = preexisting_switch
        if switch_record is not None:
            required = {
                "schema_version", "kind", "document_sha256", "cutover_id",
                "release", "release_digest", "publication",
                "candidate_control", "previous_control", "phase",
                "before_publication", "candidate_port",
                "previous_release_digest", "previous_port", "socket_inodes",
                "legacy_states", "credential_preflight", "pending_activation",
                "recovery_count", "created_at", "updated_at",
            }
            fixed = {
                "cutover_id": str(current["cutover_id"]),
                "release": str(release),
                "release_digest": digest,
                "publication": str(_absolute(publication_file, "edge publication")),
                "candidate_control": str(_absolute(candidate_control, "candidate control")),
                "previous_control": str(_absolute(previous_control, "previous control")),
                "candidate_port": int(candidate_status["port"]),
                "previous_release_digest": previous_release,
                "previous_port": previous_port,
                "socket_inodes": dict(before_sockets),
                "legacy_states": {
                    unit: {"active": active, "enabled": enabled}
                    for unit, (active, enabled) in sorted(legacy_states.items())
                },
            }
            recorded_credential = switch_record.get("credential_preflight")
            try:
                recorded_credential = cutover.verify_seal(
                    recorded_credential,
                    kind=CREDENTIAL_PREFLIGHT_KIND,
                    fields={"release_digest", "credentials", "oidc", "created_at"},
                )
            except cutover.CutoverError as error:
                raise ActivationError(
                    "activation switch credential evidence is invalid"
                ) from error
            credential_binding_fields = {
                "release_digest", "credentials", "oidc"
            }
            if (
                set(switch_record) != required
                or switch_record.get("phase") not in ACTIVATION_SWITCH_PHASES
                or any(switch_record.get(key) != value for key, value in fixed.items())
                or any(
                    recorded_credential.get(key) != credential_evidence.get(key)
                    for key in credential_binding_fields
                )
                or type(switch_record.get("recovery_count")) is not int
                or int(switch_record["recovery_count"]) < 0
            ):
                raise ActivationError("activation switch journal belongs to another cutover")
            switch_created_at = str(switch_record["created_at"])
            recovery_count = int(switch_record["recovery_count"])
            if switch_record["phase"] == "complete":
                pending_value = switch_record.get("pending_activation")
                if not isinstance(pending_value, Mapping):
                    raise ActivationError("completed activation switch lacks evidence")
                pending = cutover.verify_seal(
                    pending_value,
                    kind=ACTIVATION_READY_FOR_BROWSER_KIND,
                    fields=ACTIVATION_READY_FOR_BROWSER_FIELDS,
                )
                live = _load_publication(publication_file)
                live_publication = live.get("publication")
                live_console = (
                    live_publication.get("console")
                    if isinstance(live_publication, Mapping)
                    else None
                )
                live_upstream = (
                    live_console.get("upstream")
                    if isinstance(live_console, Mapping)
                    else None
                )
                switch = pending["publication_switch"]
                if (
                    not isinstance(live_publication, Mapping)
                    or not isinstance(live_upstream, Mapping)
                    or live_publication.get("release_digest") != digest
                    or live_publication.get("generation") != switch.get("generation")
                    or live.get("payload_sha256") != switch.get("payload_sha256")
                    or live_upstream.get("port") != candidate_status["port"]
                    or _slot_status(
                        command, candidate_control, slot_cli,
                        expected_release=digest, expected_mode="active",
                    )["port"] != candidate_status["port"]
                    or _slot_status(
                        command, previous_control, slot_cli,
                        expected_release=previous_release, expected_mode="standby",
                    )["port"] != previous_port
                    or socket_reader() != before_sockets
                ):
                    raise ActivationError("completed activation switch live state changed")
                return pending, dict(recorded_credential)

            journal_before = switch_record.get("before_publication")
            if not isinstance(journal_before, Mapping):
                raise ActivationError("activation switch recovery source is invalid")
            live = _load_publication(publication_file)
            live_publication = live.get("publication")
            live_console = (
                live_publication.get("console")
                if isinstance(live_publication, Mapping)
                else None
            )
            live_upstream = (
                live_console.get("upstream")
                if isinstance(live_console, Mapping)
                else None
            )
            if not isinstance(live_publication, Mapping) or not isinstance(
                live_upstream, Mapping
            ):
                raise ActivationError("activation switch recovery publication is invalid")
            live_release = live_publication.get("release_digest")
            live_port = live_upstream.get("port")
            if (live_release, live_port) == (digest, candidate_status["port"]):
                prior = _slot_status(
                    command, previous_control, slot_cli,
                    expected_release=previous_release,
                )
                candidate_live = _slot_status(
                    command, candidate_control, slot_cli,
                    expected_release=digest,
                )
                if prior.get("mode") != "active":
                    command.run_json(
                        [str(slot_cli), "promote", "--socket", str(previous_control),
                         "--old-socket", str(candidate_control), "--timeout-seconds", "30"]
                    )
                command.run_json(
                    [str(publication_cli), "switch-console", "--file", str(publication_file),
                     "--release-root", str(release.parent), "--expected-uid", str(edge_uid),
                     "--expected-payload-sha256", str(live["payload_sha256"]),
                     "--release-digest", previous_release, "--port", str(previous_port),
                     "--published-at", _now()]
                )
                del candidate_live
            elif (live_release, live_port) == (previous_release, previous_port):
                previous_live = _slot_status(
                    command, previous_control, slot_cli,
                    expected_release=previous_release,
                )
                if previous_live.get("mode") != "active":
                    command.run_json(
                        [str(slot_cli), "promote", "--socket", str(previous_control),
                         "--old-socket", str(candidate_control), "--timeout-seconds", "30"]
                    )
            else:
                raise ActivationError("activation switch recovery found an unknown publication")
            for unit, (was_active, was_enabled) in legacy_states.items():
                if was_enabled and command.status(
                    ["/usr/bin/systemctl", "enable", "--now", unit]
                ) != 0:
                    raise ActivationError("activation switch recovery could not restore a legacy unit")
                if was_active and not was_enabled and command.status(
                    ["/usr/bin/systemctl", "start", unit]
                ) != 0:
                    raise ActivationError("activation switch recovery could not restart a legacy unit")
            if socket_reader() != before_sockets:
                raise ActivationError("activation switch recovery changed listener identity")
            before_envelope = _load_publication(publication_file)
            previous_generation = before_envelope.get("publication", {}).get("generation")
            if not isinstance(previous_generation, int):
                raise ActivationError("activation switch recovery generation is invalid")
            recovery_count += 1
            persist_switch("prepared", before=before_envelope)
        else:
            persist_switch("prepared", before=before_envelope)
    probe_urls = _publication_probes(before_envelope)
    baseline, refused_before = _run_probes(probe_urls, probe=probe)
    if refused_before:
        raise ActivationError("pre-activation listener probe was refused")
    continuous = ContinuityProbeSession(
        release_digest=digest,
        urls=probe_urls,
        http_probe=continuity_probe or probe,
        websocket_probe=continuity_probe or _probe_websocket,
    ).start()
    continuity_evidence: dict[str, object] | None = None

    promoted = False
    switched: dict[str, object] | None = None
    try:
        persist_switch("promotion_intent", before=before_envelope)
        if failpoint is not None:
            failpoint("promotion_intent")
        command.run_json(
            [
                str(slot_cli),
                "promote",
                "--socket",
                str(candidate_control),
                "--old-socket",
                str(previous_control),
                "--timeout-seconds",
                "30",
            ]
        )
        promoted = True
        if failpoint is not None:
            failpoint("promotion_after_effect_before_journal")
        persist_switch("promoted", before=before_envelope)
        persist_switch("publication_intent", before=before_envelope)
        if failpoint is not None:
            failpoint("publication_intent")
        switched = command.run_json(
            [
                str(publication_cli),
                "switch-console",
                "--file",
                str(publication_file),
                "--release-root",
                str(release.parent),
                "--expected-uid",
                str(edge_uid),
                "--expected-payload-sha256",
                str(before_envelope["payload_sha256"]),
                "--release-digest",
                digest,
                "--port",
                str(candidate_status["port"]),
                "--published-at",
                _now(),
            ]
        )
        if failpoint is not None:
            failpoint("publication_after_effect_before_journal")
        persist_switch("published", before=before_envelope)
        after_envelope = _load_publication(publication_file)
        if after_envelope.get("payload_sha256") != switched.get("payload_sha256"):
            raise ActivationError("published Console generation did not verify")
        after_status, refused_after = _run_probes(probe_urls, probe=probe)
        console_url = probe_urls[0]
        console_failure = (
            baseline.get(console_url) is not None
            and int(baseline[console_url]) < 500
            and (
                after_status.get(console_url) is None
                or int(after_status[console_url]) >= 500
            )
        )
        project_failures = sum(
            1
            for url in probe_urls[1:]
            if baseline.get(url) is not None
            and int(baseline[url]) < 500  # type: ignore[arg-type]
            and (after_status.get(url) is None or int(after_status[url]) >= 500)  # type: ignore[arg-type]
        )
        if refused_after or console_failure or project_failures:
            raise ActivationError("post-activation route probes failed")
        after_sockets = socket_reader()
        if after_sockets != before_sockets:
            raise ActivationError("listener identity changed during activation")
        _slot_status(
            command,
            candidate_control,
            slot_cli,
            expected_release=digest,
            expected_mode="active",
        )
        _slot_status(
            command,
            previous_control,
            slot_cli,
            expected_release=previous_release,
            expected_mode="standby",
        )
        for unit, (active, _enabled) in legacy_states.items():
            if active and command.status(["/usr/bin/systemctl", "disable", "--now", unit]) != 0:
                raise ActivationError(f"failed to disable legacy writer {unit}")
        legacy_active = [unit for unit in LEGACY_UNITS if _unit_state(command, unit)[0]]
        publication_switch = _publication_switch_evidence(before_envelope, switched)
        continuity_evidence = continuous.finish()
        activation = cutover.seal(
            ACTIVATION_READY_FOR_BROWSER_KIND,
            {
                "release_digest": digest,
                "migration_seal_sha256": candidate["migration_seal_sha256"],
                "profile_inventory_readiness_sha256": current["evidence"][
                    "profile-inventory-readiness"
                ]["document_sha256"],
                "executor_release": str(release),
                "credential_preflight_sha256": credential_evidence["document_sha256"],
                "publication_switch": publication_switch,
                "continuity_probe": continuity_evidence,
                "socket_inodes_before": before_sockets,
                "socket_inodes_after": after_sockets,
                "connection_refused_count": continuity_evidence[
                    "connection_refused_count"
                ],
                "project_route_failures": continuity_evidence[
                    "project_route_failures"
                ],
                "legacy_units_active": legacy_active,
                "authority_ready": True,
                "testd_ready": True,
                "console_ready": after_status[probe_urls[0]] == 200,
                "created_at": _now(),
            },
        )
        persist_switch("complete", before=before_envelope, pending=activation)
        if failpoint is not None:
            failpoint("complete")
        return activation, credential_evidence
    except PowerLossSimulation:
        if continuity_evidence is None:
            continuous.stop_unverified()
        raise
    except BaseException as error:
        if continuity_evidence is None:
            continuous.stop_unverified()
        rollback_errors: list[str] = []
        if promoted:
            try:
                command.run_json(
                    [
                        str(slot_cli),
                        "promote",
                        "--socket",
                        str(previous_control),
                        "--old-socket",
                        str(candidate_control),
                        "--timeout-seconds",
                        "30",
                    ]
                )
            except BaseException as rollback_error:
                rollback_errors.append(f"slot: {rollback_error}")
        if switched is not None:
            try:
                command.run_json(
                    [
                        str(publication_cli),
                        "switch-console",
                        "--file",
                        str(publication_file),
                        "--release-root",
                        str(release.parent),
                        "--expected-uid",
                        str(edge_uid),
                        "--expected-payload-sha256",
                        str(switched["payload_sha256"]),
                        "--release-digest",
                        previous_release,
                        "--port",
                        str(previous_port),
                        "--published-at",
                        _now(),
                    ]
                )
            except BaseException as rollback_error:
                rollback_errors.append(f"publication: {rollback_error}")
        try:
            _restore_units(command, legacy_states)
        except BaseException as rollback_error:
            rollback_errors.append(f"units: {rollback_error}")
        try:
            _restore_prepared_graph(
                preparation,
                runner=command,
                expected_uid=expected_uid,
            )
        except BaseException as rollback_error:
            rollback_errors.append(f"graph: {rollback_error}")
        if switch_path is not None and not rollback_errors:
            try:
                before_envelope = _load_publication(publication_file)
                recovery_count += 1
                persist_switch("prepared", before=before_envelope)
            except BaseException as rollback_error:
                rollback_errors.append(f"journal: {rollback_error}")
        suffix = "" if not rollback_errors else f"; rollback incomplete ({'; '.join(rollback_errors)})"
        raise ActivationError(f"activation failed and was rolled back: {error}{suffix}") from error


def _live_rehearsal_publication_summary(
    envelope: Mapping[str, object],
) -> dict[str, object]:
    publication = envelope.get("publication")
    if not isinstance(publication, Mapping):
        raise ActivationError("live rehearsal publication is invalid")
    console = publication.get("console")
    upstream = console.get("upstream") if isinstance(console, Mapping) else None
    if not isinstance(upstream, Mapping):
        raise ActivationError("live rehearsal Console upstream is invalid")
    routing = {
        key: publication.get(key)
        for key in (
            "domain",
            "console_host",
            "maintenance",
            "session",
            "access",
            "routes",
        )
    }
    summary = {
        "generation": publication.get("generation"),
        "payload_sha256": envelope.get("payload_sha256"),
        "release_digest": publication.get("release_digest"),
        "port": upstream.get("port"),
        "routing_sha256": _sha256_bytes(_canonical(routing)),
    }
    if (
        type(summary["generation"]) is not int
        or int(summary["generation"]) < 1
        or re.fullmatch(r"[0-9a-f]{64}", str(summary["payload_sha256"]))
        is None
        or summary["payload_sha256"] != _sha256_bytes(_canonical(publication))
        or re.fullmatch(r"[0-9a-f]{64}", str(summary["release_digest"]))
        is None
        or type(summary["port"]) is not int
        or not 30000 <= int(summary["port"]) <= 60999
    ):
        raise ActivationError("live rehearsal publication summary is invalid")
    return summary


def _default_live_rehearsal_profile_health(
    state: Mapping[str, object],
) -> dict[str, object]:
    try:
        fresh = cutover.reverify_profile_inventory_readiness(
            state=state,
            authority_uid=int(state["authority_uid"]),
        )
    except cutover.CutoverError as error:
        raise ActivationError(str(error)) from error
    return {
        "ready": True,
        "proof_sha256": fresh["document_sha256"],
        "profile_sha256": fresh["profile_sha256"],
        "authority_generation": fresh["authority_generation"],
        "project": fresh["project"],
        "owner_uid": fresh["owner_uid"],
        "repository_id": fresh["repository_id"],
        "repository_generation": fresh["repository_generation"],
        "inventory_sha256": fresh["inventory_sha256"],
    }


def _default_live_rehearsal_data_health(
    state: Mapping[str, object],
) -> dict[str, object]:
    stores = {}
    for name, field, uid in (
        ("authority", "authority_database", int(state["authority_uid"])),
        ("testd", "test_database", int(state["testd_uid"])),
    ):
        path = Path(str(state[field]))
        identity = cutover._database_identity(path, uid=uid)
        with closing(
            sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
        ) as connection:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if quick_check != "ok":
            raise ActivationError(f"live rehearsal {name} store is unhealthy")
        stores[name] = {
            "path": str(path),
            "device": identity["device"],
            "inode": identity["inode"],
            "quick_check": quick_check,
        }
    return {"ready": True, "stores": stores}


def _live_rehearsal_route_health(
    urls: Sequence[str],
    *,
    baseline: Mapping[str, int | None],
    probe: Callable[[str], tuple[int | None, bool]],
) -> dict[str, object]:
    statuses, refused = _run_probes(urls, probe=probe)
    failures = sum(
        1
        for url in urls
        if baseline.get(url) is not None
        and int(baseline[url]) < 500  # type: ignore[arg-type]
        and (statuses.get(url) is None or int(statuses[url]) >= 500)  # type: ignore[arg-type]
    )
    if refused or failures or statuses.get(urls[0]) != 200:
        raise ActivationError("live rehearsal route health failed")
    return {
        "ready": True,
        "statuses": statuses,
        "connection_refused_count": refused,
        "project_route_failures": failures,
    }


def rehearse_live_traffic_rollback(
    *,
    state: Mapping[str, object],
    publication_file: Path,
    candidate_control: Path,
    previous_control: Path,
    journal_file: Path,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    socket_reader: Callable[[], dict[str, int]] = socket_inodes,
    probe: Callable[[str], tuple[int | None, bool]] = _probe_url,
    continuity_probe: Callable[[str], tuple[int | None, bool]] | None = None,
    profile_health: Callable[[], Mapping[str, object]] | None = None,
    data_health: Callable[[], Mapping[str, object]] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Reverse and reactivate one successful blue/green Console publication.

    A successful attestation covers one uninterrupted HTTP/WSS probe window.
    If an earlier process died, replay first converges to the activated
    candidate and then repeats the complete reverse/forward exercise.
    """

    current = cutover.validate_state(state)
    if os.geteuid() != expected_uid:
        raise ActivationError("live rollback rehearsal must run as authority UID")
    activation_evidence = current["evidence"].get("activation")
    candidate = current["evidence"].get("candidate")
    if not isinstance(activation_evidence, Mapping) or not isinstance(candidate, Mapping):
        raise ActivationError("live rollback rehearsal lacks activation evidence")
    digest = str(current["release_digest"])
    switch = cutover._publication_switch(
        activation_evidence.get("publication_switch"), expected_release=digest
    )
    if switch.get("mode") == "first-adoption-bootstrap":
        raise ActivationError(
            "live rollback rehearsal requires a retained blue/green release"
        )
    release = Path(str(current["release"]))
    publication_cli = release / "bin/devcoordinator-edge-publication"
    slot_cli = release / "bin/devcoordinator-console-slot-control"
    for executable in (publication_cli, slot_cli):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ActivationError("immutable release lacks rehearsal executable")
    publication_file = _absolute(publication_file, "edge publication")
    candidate_control = _absolute(candidate_control, "candidate control")
    previous_control = _absolute(previous_control, "previous control")
    journal_file = _absolute(journal_file, "live rollback rehearsal journal")
    _private_directory(journal_file.parent, expected_uid=expected_uid)
    command = runner or CommandRunner()
    profile_call = profile_health or (
        lambda: _default_live_rehearsal_profile_health(current)
    )
    data_call = data_health or (
        lambda: _default_live_rehearsal_data_health(current)
    )
    existing = _load_private_journal(
        journal_file,
        kind=LIVE_ROLLBACK_REHEARSAL_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if existing is not None and existing.get("phase") == "complete":
        verified = cutover.verify_seal(
            existing.get("attestation"),
            kind=cutover.LIVE_ROLLBACK_REHEARSAL_KIND,
            fields=cutover.LIVE_ROLLBACK_REHEARSAL_FIELDS,
        )
        recorded = current["evidence"].get("live-rollback-rehearsal")
        if recorded is not None:
            if recorded != verified:
                raise ActivationError("live rehearsal journal contradicts the ledger")
        else:
            cutover.transition(
                current,
                evidence_kind="live-rollback-rehearsal",
                evidence=verified,
            )
        return verified
    if current["phase"] != "activated" or "live-rollback-rehearsal" in current["evidence"]:
        raise ActivationError("live rollback rehearsal requires unrecorded activation")

    before_sockets = socket_reader()
    if before_sockets != cutover._socket_map(activation_evidence["socket_inodes_after"]):
        raise ActivationError("live rehearsal listener identity changed")
    binding = {
        "activation_sha256": activation_evidence["document_sha256"],
        "activation_state_generation": current["state_generation"],
        "release_digest": digest,
        "publication_path": str(publication_file),
        "candidate_control": str(candidate_control),
        "previous_control": str(previous_control),
        "socket_inodes": before_sockets,
    }
    if existing is not None:
        if any(existing.get(key) != value for key, value in binding.items()):
            raise ActivationError("live rehearsal journal binding changed")
        if existing.get("phase") not in LIVE_ROLLBACK_REHEARSAL_PHASES:
            raise ActivationError("live rehearsal journal phase is invalid")
        try:
            journal_operation_id = str(uuid.UUID(str(existing["operation_id"])))
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            raise ActivationError("live rehearsal journal operation is invalid") from error
        if (
            journal_operation_id != existing.get("operation_id")
            or type(existing.get("attempt")) is not int
            or int(existing["attempt"]) < 1
            or not isinstance(existing.get("recovery_events"), list)
        ):
            raise ActivationError("live rehearsal journal contract is invalid")
    operation_id = (
        str(existing["operation_id"])
        if existing is not None
        else str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"devcoordinator-live-rollback:{current['cutover_id']}:{activation_evidence['document_sha256']}",
            )
        )
    )
    recovery_events = list(existing.get("recovery_events", [])) if existing else []
    journal_payload = (
        {
            key: value
            for key, value in existing.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        if existing is not None
        else {
            **binding,
            "operation_id": operation_id,
            "attempt": 1,
            "recovery_events": recovery_events,
            "created_at": _now(),
        }
    )

    def write_phase(phase: str, **values: object) -> dict[str, object]:
        if phase not in LIVE_ROLLBACK_REHEARSAL_PHASES:
            raise ActivationError("live rehearsal journal phase is invalid")
        journal_payload.update(values)
        journal_payload.update(
            {
                **binding,
                "operation_id": operation_id,
                "phase": phase,
                "recovery_events": list(recovery_events),
                "updated_at": _now(),
            }
        )
        return _write_private_journal(
            journal_file,
            kind=LIVE_ROLLBACK_REHEARSAL_JOURNAL_KIND,
            payload=journal_payload,
            expected_uid=expected_uid,
        )

    summary_fields = {
        "generation",
        "payload_sha256",
        "release_digest",
        "port",
        "routing_sha256",
    }

    def stored_summary(value: object, *, label: str) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != summary_fields:
            raise ActivationError(f"live rehearsal {label} publication is invalid")
        result = dict(value)
        if (
            type(result["generation"]) is not int
            or int(result["generation"]) < 1
            or re.fullmatch(r"[0-9a-f]{64}", str(result["payload_sha256"]))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", str(result["release_digest"]))
            is None
            or re.fullmatch(r"[0-9a-f]{64}", str(result["routing_sha256"]))
            is None
            or type(result["port"]) is not int
            or not 30000 <= int(result["port"]) <= 60999
        ):
            raise ActivationError(f"live rehearsal {label} publication is invalid")
        return result

    def next_summary(
        source: Mapping[str, object],
        observed: Mapping[str, object],
        *,
        release_digest: str,
        port: int,
    ) -> bool:
        return bool(
            observed.get("generation") == int(source["generation"]) + 1
            and observed.get("payload_sha256") != source["payload_sha256"]
            and observed.get("release_digest") == release_digest
            and observed.get("port") == port
            and observed.get("routing_sha256") == source["routing_sha256"]
        )

    observed_envelope = _load_publication(publication_file)
    observed_summary = _live_rehearsal_publication_summary(observed_envelope)
    if existing is None:
        if (
            observed_summary["generation"] != switch["generation"]
            or observed_summary["payload_sha256"] != switch["payload_sha256"]
            or observed_summary["release_digest"] != digest
            or observed_summary["port"] != switch["port"]
        ):
            raise ActivationError("live rehearsal activation publication head changed")
    else:
        phase = str(existing["phase"])
        accepted = False
        if phase == "planned":
            accepted = observed_summary == stored_summary(
                existing.get("publication_before"), label="planned"
            )
        elif phase in {
            "rollback_slot_intent",
            "rollback_slot_ready",
            "rollback_publication_intent",
        }:
            source = stored_summary(existing.get("publication_before"), label="rollback source")
            accepted = observed_summary == source or (
                phase == "rollback_publication_intent"
                and next_summary(
                    source,
                    observed_summary,
                    release_digest=str(switch["previous_release_digest"]),
                    port=int(switch["previous_port"]),
                )
            )
        elif phase in {
            "rollback_ready",
            "reactivation_slot_intent",
            "reactivation_slot_ready",
            "reactivation_publication_intent",
        }:
            source = stored_summary(
                existing.get("publication_rollback"), label="reactivation source"
            )
            accepted = observed_summary == source or (
                phase == "reactivation_publication_intent"
                and next_summary(
                    source,
                    observed_summary,
                    release_digest=digest,
                    port=int(switch["port"]),
                )
            )
        elif phase == "reactivated":
            accepted = observed_summary == stored_summary(
                existing.get("publication_reactivated"), label="reactivation result"
            )
        elif phase in {"recovery_switching", "recovery_incomplete"}:
            source = stored_summary(
                existing.get("recovery_before"), label="recovery source"
            )
            accepted = observed_summary == source or next_summary(
                source,
                observed_summary,
                release_digest=digest,
                port=int(switch["port"]),
            )
        elif phase in {"recovered", "attempt_abandoned"}:
            recovery = existing.get("recovery")
            accepted = isinstance(recovery, Mapping) and observed_summary == stored_summary(
                recovery.get("publication"), label="recovery result"
            )
        if not accepted:
            raise ActivationError("live rehearsal observed an unjournaled publication head")

    def prepare_slot(
        *,
        label: str,
        control: Path,
        old_control: Path,
        release_digest: str,
    ) -> dict[str, object]:
        target_status = _slot_status(
            command,
            control,
            slot_cli,
            expected_release=release_digest,
        )
        old_release = digest if release_digest != digest else str(
            switch["previous_release_digest"]
        )
        old_status = _slot_status(
            command,
            old_control,
            slot_cli,
            expected_release=old_release,
        )
        modes = (target_status.get("mode"), old_status.get("mode"))
        if modes == ("standby", "active"):
            command.run_json(
                [
                    str(slot_cli),
                    "promote",
                    "--socket",
                    str(control),
                    "--old-socket",
                    str(old_control),
                    "--timeout-seconds",
                    "30",
                ]
            )
            if failpoint is not None:
                failpoint(f"{label}-slot-after-effect-before-journal")
        elif modes != ("active", "standby"):
            raise ActivationError("live rehearsal Console slot modes are ambiguous")
        _slot_status(
            command,
            control,
            slot_cli,
            expected_release=release_digest,
            expected_mode="active",
        )
        _slot_status(
            command,
            old_control,
            slot_cli,
            expected_release=old_release,
            expected_mode="standby",
        )
        return {
            "target_release_digest": release_digest,
            "target_port": target_status["port"],
            "target_mode": "active",
            "old_release_digest": old_release,
            "old_port": old_status["port"],
            "old_mode": "standby",
        }

    def switch_publication(
        *,
        label: str,
        release_digest: str,
        port: int,
        expected_head: Mapping[str, object],
        published_at: str,
    ) -> tuple[dict[str, object], dict[str, object] | None]:
        envelope = _load_publication(publication_file)
        source = _live_rehearsal_publication_summary(envelope)
        if source != dict(expected_head):
            raise ActivationError("live rehearsal publication CAS head changed")
        switch_evidence: dict[str, object] | None = None
        if source["release_digest"] != release_digest or source["port"] != port:
            service_uids = candidate.get("service_uids")
            if not isinstance(service_uids, Mapping):
                raise ActivationError("candidate service identities are invalid")
            switched = command.run_json(
                [
                    str(publication_cli),
                    "switch-console",
                    "--file",
                    str(publication_file),
                    "--release-root",
                    str(release.parent),
                    "--expected-uid",
                    str(int(service_uids["devcoordinator-edge.service"])),
                    "--expected-payload-sha256",
                    str(envelope["payload_sha256"]),
                    "--release-digest",
                    release_digest,
                    "--port",
                    str(port),
                    "--published-at",
                    published_at,
                ]
            )
            switch_evidence = _publication_switch_evidence(envelope, switched)
            if failpoint is not None:
                failpoint(f"{label}-publication-after-effect-before-journal")
        result = _live_rehearsal_publication_summary(
            _load_publication(publication_file)
        )
        if (
            result["release_digest"] != release_digest
            or result["port"] != port
            or result["routing_sha256"] != source["routing_sha256"]
        ):
            raise ActivationError("live rehearsal publication target is invalid")
        if switch_evidence is not None and (
            result["generation"] != switch_evidence["generation"]
            or result["payload_sha256"] != switch_evidence["payload_sha256"]
        ):
            raise ActivationError("live rehearsal publication result contradicts CAS evidence")
        return result, switch_evidence

    def switch_side(
        *,
        label: str,
        control: Path,
        old_control: Path,
        release_digest: str,
        port: int,
        expected_head: Mapping[str, object],
    ) -> tuple[dict[str, object], dict[str, object] | None]:
        prepare_slot(
            label=label,
            control=control,
            old_control=old_control,
            release_digest=release_digest,
        )
        return switch_publication(
            label=label,
            release_digest=release_digest,
            port=port,
            expected_head=expected_head,
            published_at=_now(),
        )

    def converge_candidate(
        label: str,
        source: Mapping[str, object],
    ) -> dict[str, object]:
        urls = _publication_probes(_load_publication(publication_file))
        baseline, refused = _run_probes(urls, probe=probe)
        if refused or baseline.get(urls[0]) != 200:
            raise ActivationError("live rehearsal recovery baseline is unhealthy")
        write_phase(
            "recovery_switching",
            recovery_before=dict(source),
            recovery_reason=label,
        )
        try:
            summary, recovery_switch = switch_side(
                label="recovery",
                control=candidate_control,
                old_control=previous_control,
                release_digest=digest,
                port=int(switch["port"]),
                expected_head=source,
            )
            health = _live_rehearsal_route_health(urls, baseline=baseline, probe=probe)
            if socket_reader() != before_sockets:
                raise ActivationError("listener identity changed during recovery")
            event = {
                "reason": label,
                "publication": summary,
                "publication_switch": recovery_switch,
                "health": health,
                "at": _now(),
            }
            recovery_events.append(event)
            write_phase("recovered", recovery=event)
            return event
        except PowerLossSimulation:
            raise
        except BaseException as recovery_error:
            write_phase(
                "recovery_incomplete",
                recovery_before=dict(source),
                recovery_error=str(recovery_error),
            )
            raise ActivationError(
                f"live rehearsal could not converge to activated candidate: {recovery_error}"
            ) from recovery_error

    interrupted = existing is not None and existing.get("phase") != "planned"
    if interrupted and existing.get("phase") not in {"recovered", "attempt_abandoned"}:
        converge_candidate(f"resume-from-{existing.get('phase')}", observed_summary)
    if interrupted and existing.get("phase") != "attempt_abandoned":
        write_phase(
            "attempt_abandoned",
            abandoned_attempt=int(journal_payload["attempt"]),
            abandoned_reason=f"resume-from-{existing.get('phase')}",
        )
    observed_envelope = _load_publication(publication_file)
    before_summary = _live_rehearsal_publication_summary(observed_envelope)
    if before_summary["release_digest"] != digest or before_summary["port"] != switch["port"]:
        raise ActivationError("live rehearsal did not converge to activated candidate")
    urls = _publication_probes(observed_envelope)
    baseline, refused = _run_probes(urls, probe=probe)
    if refused or baseline.get(urls[0]) != 200:
        raise ActivationError("live rehearsal baseline is unhealthy")
    if interrupted:
        journal_payload["attempt"] = int(journal_payload["attempt"]) + 1
    for field in (
        "rollback_switch",
        "publication_rollback",
        "rollback_health",
        "rollback_continuity_probe",
        "rollback_slot",
        "reactivation_switch",
        "publication_reactivated",
        "reactivated_health",
        "reactivation_continuity_probe",
        "reactivation_slot",
        "attestation",
    ):
        journal_payload.pop(field, None)
    journal = write_phase("planned", publication_before=before_summary)
    if failpoint is not None:
        failpoint("planned")
    continuous = ContinuityProbeSession(
        release_digest=digest,
        urls=urls,
        http_probe=continuity_probe or probe,
        websocket_probe=continuity_probe or _probe_websocket,
    ).start()

    def profile_binding(value: Mapping[str, object]) -> dict[str, object]:
        return {
            key: item
            for key, item in value.items()
            if key not in {"proof_sha256", "inventory_sha256"}
        }

    rollback_window: ContinuityProbeSession | None = None
    reactivation_window: ContinuityProbeSession | None = None
    try:
        profile_before = dict(profile_call())
        data_before = dict(data_call())
        rollback_window = ContinuityProbeSession(
            release_digest=str(switch["previous_release_digest"]),
            urls=urls,
            http_probe=continuity_probe or probe,
            websocket_probe=continuity_probe or _probe_websocket,
        ).start()
        journal = write_phase("rollback_slot_intent")
        if failpoint is not None:
            failpoint("rollback_slot_intent")
        rollback_slot = prepare_slot(
            label="rollback",
            control=previous_control,
            old_control=candidate_control,
            release_digest=str(switch["previous_release_digest"]),
        )
        journal = write_phase("rollback_slot_ready", rollback_slot=rollback_slot)
        if failpoint is not None:
            failpoint("rollback_slot_ready")
        rollback_published_at = _now()
        journal = write_phase(
            "rollback_publication_intent",
            rollback_published_at=rollback_published_at,
        )
        if failpoint is not None:
            failpoint("rollback_publication_intent")
        rollback_summary, rollback_switch = switch_publication(
            label="rollback",
            release_digest=str(switch["previous_release_digest"]),
            port=int(switch["previous_port"]),
            expected_head=before_summary,
            published_at=rollback_published_at,
        )
        if rollback_switch is None:
            raise ActivationError("live rehearsal rollback did not advance publication")
        rollback_health = _live_rehearsal_route_health(urls, baseline=baseline, probe=probe)
        profile_rollback = dict(profile_call())
        data_rollback = dict(data_call())
        if profile_binding(profile_rollback) != profile_binding(profile_before):
            raise ActivationError("protected profile changed during rollback")
        rollback_continuity = rollback_window.finish()
        rollback_window = None
        journal = write_phase(
            "rollback_ready",
            rollback_switch=rollback_switch,
            publication_rollback=rollback_summary,
            rollback_health=rollback_health,
            rollback_continuity_probe=rollback_continuity,
        )
        if failpoint is not None:
            failpoint("rollback_ready")
        reactivation_window = ContinuityProbeSession(
            release_digest=digest,
            urls=urls,
            http_probe=continuity_probe or probe,
            websocket_probe=continuity_probe or _probe_websocket,
        ).start()
        journal = write_phase("reactivation_slot_intent")
        if failpoint is not None:
            failpoint("reactivation_slot_intent")
        reactivation_slot = prepare_slot(
            label="reactivation",
            control=candidate_control,
            old_control=previous_control,
            release_digest=digest,
        )
        journal = write_phase(
            "reactivation_slot_ready", reactivation_slot=reactivation_slot
        )
        if failpoint is not None:
            failpoint("reactivation_slot_ready")
        reactivation_published_at = _now()
        journal = write_phase(
            "reactivation_publication_intent",
            reactivation_published_at=reactivation_published_at,
        )
        if failpoint is not None:
            failpoint("reactivation_publication_intent")
        reactivated_summary, reactivation_switch = switch_publication(
            label="reactivation",
            release_digest=digest,
            port=int(switch["port"]),
            expected_head=rollback_summary,
            published_at=reactivation_published_at,
        )
        if reactivation_switch is None:
            raise ActivationError("live rehearsal reactivation did not advance publication")
        reactivated_health = _live_rehearsal_route_health(urls, baseline=baseline, probe=probe)
        profile_reactivated = dict(profile_call())
        data_reactivated = dict(data_call())
        if profile_binding(profile_reactivated) != profile_binding(profile_before):
            raise ActivationError("protected profile changed during reactivation")
        after_sockets = socket_reader()
        if after_sockets != before_sockets:
            raise ActivationError("listener identity changed during rehearsal")
        reactivation_continuity = reactivation_window.finish()
        reactivation_window = None
        journal = write_phase(
            "reactivated",
            reactivation_switch=reactivation_switch,
            publication_reactivated=reactivated_summary,
            reactivated_health=reactivated_health,
            reactivation_continuity_probe=reactivation_continuity,
        )
        if failpoint is not None:
            failpoint("reactivated")
        continuity_evidence = continuous.finish()
        attestation = cutover.seal(
            cutover.LIVE_ROLLBACK_REHEARSAL_KIND,
            {
                "operation_id": operation_id,
                "activation_sha256": activation_evidence["document_sha256"],
                "activation_state_generation": current["state_generation"],
                "release_digest": digest,
                "executor_release": str(release),
                "journal_sha256": journal["document_sha256"],
                "publication_before": before_summary,
                "rollback_slot": rollback_slot,
                "rollback_switch": rollback_switch,
                "publication_rollback": rollback_summary,
                "rollback_continuity_probe": rollback_continuity,
                "reactivation_slot": reactivation_slot,
                "reactivation_switch": reactivation_switch,
                "publication_reactivated": reactivated_summary,
                "reactivation_continuity_probe": reactivation_continuity,
                "supported_rollback_head": reactivated_summary,
                "socket_inodes_before": before_sockets,
                "socket_inodes_after": after_sockets,
                "continuity_probe": continuity_evidence,
                "profile_health": {
                    "before": profile_before,
                    "rollback": profile_rollback,
                    "reactivated": profile_reactivated,
                },
                "data_health": {
                    "before": data_before,
                    "rollback": data_rollback,
                    "reactivated": data_reactivated,
                },
                "recovery_count": len(recovery_events),
                "browser_lcp_attestation_sha256": activation_evidence[
                    "browser_lcp_attestation_sha256"
                ],
                "browser_lcp_consumption_sha256": activation_evidence[
                    "browser_lcp_consumption_sha256"
                ],
                "completed_at": _now(),
            },
        )
        cutover.transition(
            current,
            evidence_kind="live-rollback-rehearsal",
            evidence=attestation,
        )
        write_phase("complete", attestation=attestation)
        if failpoint is not None:
            failpoint("complete")
        return attestation
    except PowerLossSimulation:
        if rollback_window is not None:
            rollback_window.stop_unverified()
        if reactivation_window is not None:
            reactivation_window.stop_unverified()
        continuous.stop_unverified()
        raise
    except BaseException as error:
        if rollback_window is not None:
            rollback_window.stop_unverified()
        if reactivation_window is not None:
            reactivation_window.stop_unverified()
        continuous.stop_unverified()
        recovery_source = _live_rehearsal_publication_summary(
            _load_publication(publication_file)
        )
        converge_candidate(f"failure:{type(error).__name__}", recovery_source)
        raise ActivationError(
            f"live rollback rehearsal failed; activated candidate restored: {error}"
        ) from error


_FIRST_ADOPTION_REQUEST_FIELDS = frozenset(
    {
        "state",
        "repair_plan",
        "repair_result",
        "ports",
        "candidate",
        "console",
        "authority",
        "api",
        "public",
        "fleet",
        "background",
        "legacy_writer",
        "browser",
    }
)


def _first_adoption_manifest_template(
    value: Mapping[str, object],
) -> dict[str, object]:
    template = cutover.verify_seal(
        value,
        kind=FIRST_ADOPTION_MANIFEST_TEMPLATE_KIND,
        fields={"operation_id", "manifests", "created_at"},
    )
    try:
        operation_id = str(uuid.UUID(str(template["operation_id"])))
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError(
            "fleet manifest template operation ID is invalid"
        ) from error
    manifests = template.get("manifests")
    repository_ids = [
        str(item.get("repository_id"))
        for item in manifests
        if isinstance(item, Mapping)
    ] if isinstance(manifests, list) else []
    if (
        not isinstance(manifests, list)
        or len(repository_ids) != len(manifests)
        or repository_ids != sorted(repository_ids)
        or len(repository_ids) != len(set(repository_ids))
        or any(
            not isinstance(item, Mapping)
            or set(item) != {"repository_id", "manifest"}
            or not isinstance(item.get("repository_id"), str)
            or not item["repository_id"]
            or not isinstance(item.get("manifest"), Mapping)
            for item in manifests
        )
    ):
        raise ActivationError("fleet manifest template is invalid")
    template["operation_id"] = operation_id
    return template


def _console_slot_listener_ports(payload: bytes) -> dict[str, int]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ActivationError("candidate Console slot is not UTF-8") from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise ActivationError("candidate Console slot fields are invalid")
        values[key] = value
    required = {"HTTPS_PORT", "DEVCOORDINATOR_CONSOLE_INNER_PORT"}
    if not required <= set(values):
        raise ActivationError("candidate Console slot omits its listener ports")
    try:
        result = {
            "console_outer": int(values["HTTPS_PORT"]),
            "console_inner": int(
                values["DEVCOORDINATOR_CONSOLE_INNER_PORT"]
            ),
        }
    except ValueError as error:
        raise ActivationError("candidate Console slot listener port is invalid") from error
    if (
        any(not 30000 <= port <= 60999 for port in result.values())
        or len(set(result.values())) != 2
    ):
        raise ActivationError("candidate Console slot listener ports are unsafe")
    return result


def build_first_adoption_manifest_template(
    arguments: argparse.Namespace,
) -> Mapping[str, object]:
    expected_uid = int(arguments.expected_uid)
    if os.geteuid() != expected_uid:
        raise ActivationError(
            "manifest template builder must run as the authority UID"
        )
    source = cutover.read_private_json(
        Path(arguments.input), uid=expected_uid
    )
    if (
        set(source) != {"schema_version", "operation_id", "manifests"}
        or source.get("schema_version") != 1
    ):
        raise ActivationError(
            "manifest template input fields are invalid"
        )
    candidate = _first_adoption_manifest_template(
        cutover.seal(
            FIRST_ADOPTION_MANIFEST_TEMPLATE_KIND,
            {
                "operation_id": source["operation_id"],
                "manifests": source["manifests"],
                "created_at": _now(),
            },
        )
    )
    output = _absolute(
        Path(arguments.output), "first-adoption manifest template output"
    )
    if output.exists() or output.is_symlink():
        recorded = _first_adoption_manifest_template(
            cutover.read_private_json(output, uid=expected_uid)
        )
        if (
            recorded["operation_id"] != candidate["operation_id"]
            or recorded["manifests"] != candidate["manifests"]
        ):
            raise ActivationError(
                "manifest template output belongs to another input"
            )
        return recorded
    cutover._publish_evidence(output, candidate, uid=expected_uid)
    return candidate


_FIRST_ADOPTION_ARGUMENTS: Mapping[str, Mapping[str, str]] = {
    "ports": {
        "bundle": "port_reservations",
        "sha256": "port_reservations_sha256",
    },
    "legacy_writer": {
        "bridge_transaction": "legacy_bridge_transaction",
        "bridge_operation_id": "legacy_bridge_operation_id",
        "bridge_journal_sha256": "legacy_bridge_journal_sha256",
        "database": "legacy_bridge_database",
        "profile": "legacy_bridge_profile",
        "socket": "legacy_bridge_socket",
        "dropin": "legacy_bridge_dropin",
        "retirement_guard": "legacy_broker_retirement_guard",
        "handoff_journal": "legacy_writer_handoff_journal",
    },
    "candidate": {
        "slot_source": "candidate_slot_source",
        "rollback_directory": "candidate_rollback_directory",
        "legacy_console_env": "legacy_console_env",
        "background_project_root": "background_project_root",
        "background_config_transaction": "background_config_transaction",
        "project_isolation_audit": "project_isolation_audit",
        "project_isolation_ledger": "project_isolation_ledger",
        "graph_evidence": "graph_evidence",
        "credential_evidence": "credential_evidence",
        "candidate_evidence": "candidate_evidence",
        "activation_evidence": "activation_evidence",
        "graph_journal": "candidate_graph_journal",
    },
    "browser": {
        "runtime_lock": "browser_runtime_lock",
        "storage_state": "browser_storage_state",
        "signing_key": "browser_signing_key",
        "journal": "browser_journal",
        "attestation": "browser_attestation",
        "consumption": "browser_consumption",
    },
    "console": {
        "legacy_state": "legacy_console_state",
        "console_state": "console_state",
        "edge_identity_state": "edge_identity_state",
        "console_config": "console_config",
        "route_resolution": "route_resolution",
        "publication_input": "publication_input",
        "console_port": "console_port",
        "console_uid": "console_uid",
        "console_gid": "console_gid",
        "edge_uid": "edge_uid",
        "edge_gid": "edge_gid",
        "legacy_uid": "legacy_console_uid",
        "rollback_directory": "console_rollback_directory",
        "migration_journal": "console_migration_journal",
    },
    "authority": {
        "legacy_database": "legacy_authority_database",
        "database": "authority_database",
        "inventory_database": "inventory_database",
        "inventory_publication": "inventory_publication",
        "split_attestation": "storage_split_attestation",
        "adoption_pointer": "authority_adoption_pointer",
        "maintenance_root": "maintenance_root",
        "maintenance_gid": "maintenance_gid",
        "authority_uid": "authority_service_uid",
        "authority_gid": "authority_service_gid",
        "inventory_uid": "inventory_uid",
        "inventory_gid": "inventory_gid",
        "operation_journal": "authority_operation_journal",
    },
    "api": {
        "handoff_port": "api_handoff_port",
        "journal": "api_handoff_journal",
        "profile_path": "protected_profile_path",
        "bootstrap_profile_path": "api_bootstrap_profile_path",
        "bootstrap_profile_journal": "api_bootstrap_profile_journal",
        "final_profile_journal": "api_final_profile_journal",
        "api_uid": "api_service_uid",
        "inventory_readiness_evidence": "profile_inventory_readiness_evidence",
    },
    "public": {
        "publication": "edge_publication",
        "handoff_journal": "public_handoff_journal",
        "http_handoff_port": "http_handoff_port",
        "https_handoff_port": "https_handoff_port",
    },
    "fleet": {
        "authority_export": "fleet_authority_export",
        "evidence_root": "fleet_evidence_root",
        "manifest_template": "fleet_manifest_template",
        "manifest_template_sha256": "fleet_manifest_template_sha256",
        "manifest_set": "fleet_manifest_set",
        "adoption_request": "fleet_adoption_request",
        "helper": "fleet_uid_helper",
    },
    "background": {
        "telegram_present": "telegram_present",
        "telegram_source": "telegram_source",
        "telegram_destination": "telegram_destination",
        "telegram_rollback": "telegram_rollback",
        "telegram_fence": "telegram_fence",
        "source_owner_uid": "telegram_source_owner_uid",
        "destination_owner_uid": "telegram_destination_owner_uid",
        "destination_owner_gid": "telegram_destination_owner_gid",
    },
}


def _request_group(
    request: Mapping[str, object], name: str, fields: set[str]
) -> dict[str, object]:
    value = request.get(name)
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ActivationError(f"first-adoption {name} request fields are invalid")
    return dict(value)


_FIRST_ADOPTION_PORT_ROLES = frozenset(
    {
        "console_outer",
        "console_inner",
        "handoff_http",
        "handoff_https",
        "handoff_api",
    }
)


def _first_adoption_ports(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {
        "bundle",
        "sha256",
        "reservations",
    }:
        raise ActivationError("first-adoption ports request fields are invalid")
    bundle = value.get("bundle")
    digest = value.get("sha256")
    reservations = value.get("reservations")
    if (
        not isinstance(bundle, str)
        or not bundle
        or "\x00" in bundle
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(reservations, Mapping)
        or set(reservations) != _FIRST_ADOPTION_PORT_ROLES
        or any(
            type(port) is not int or not 30000 <= int(port) <= 60999
            for port in reservations.values()
        )
        or len({int(port) for port in reservations.values()})
        != len(_FIRST_ADOPTION_PORT_ROLES)
    ):
        raise ActivationError("first-adoption port reservations are invalid")
    _absolute(Path(bundle), "first-adoption ports.bundle")
    return {
        "bundle": bundle,
        "sha256": digest,
        "reservations": {
            role: int(reservations[role])
            for role in sorted(_FIRST_ADOPTION_PORT_ROLES)
        },
    }


def _first_adoption_request(value: Mapping[str, object]) -> dict[str, object]:
    request = cutover.verify_seal(
        value,
        kind=FIRST_ADOPTION_REQUEST_KIND,
        fields=_FIRST_ADOPTION_REQUEST_FIELDS,
    )
    _absolute(Path(str(request["state"])), "first-adoption state")
    repair_plan = request["repair_plan"]
    repair_result = request["repair_result"]
    if (repair_plan is None) != (repair_result is None):
        raise ActivationError(
            "first-adoption repair plan and result must both be paths or both be null"
        )
    if repair_plan is not None:
        if any(
            not isinstance(item, str) or not item or "\x00" in item
            for item in (repair_plan, repair_result)
        ):
            raise ActivationError(
                "first-adoption repair plan and result must both be paths or both be null"
            )
        _absolute(Path(repair_plan), "first-adoption repair_plan")
        _absolute(Path(str(repair_result)), "first-adoption repair_result")
    groups = {
        "ports": {"bundle", "sha256", "reservations"},
        "legacy_writer": {
            "bridge_transaction", "bridge_operation_id",
            "bridge_journal_sha256", "database", "profile", "socket",
            "dropin", "retirement_guard", "handoff_journal",
        },
        "candidate": {
            "slot_source", "rollback_directory",
            "legacy_console_env", "background_project_root",
            "background_config_transaction", "project_isolation_audit",
            "project_isolation_ledger", "graph_evidence", "credential_evidence",
            "candidate_evidence", "activation_evidence", "graph_journal",
        },
        "console": {
            "legacy_state", "console_state", "edge_identity_state", "console_config",
            "route_resolution", "publication_input", "console_port", "console_uid",
            "console_gid", "edge_uid", "edge_gid", "legacy_uid", "rollback_directory",
            "migration_journal",
        },
        "authority": {
            "legacy_database", "database", "inventory_database",
            "inventory_publication", "split_attestation", "adoption_pointer",
            "maintenance_root", "maintenance_gid", "authority_uid", "authority_gid",
            "inventory_uid", "inventory_gid", "operation_journal",
        },
        "api": {
            "handoff_port", "journal", "profile_path",
            "bootstrap_profile_path", "bootstrap_profile_journal",
            "final_profile_journal", "api_uid",
            "inventory_readiness_evidence",
        },
        "public": {
            "publication", "handoff_journal", "http_handoff_port",
            "https_handoff_port",
        },
        "fleet": {
            "authority_export", "evidence_root", "manifest_template",
            "manifest_template_sha256", "manifest_set",
            "adoption_request", "helper",
        },
        "background": {
            "telegram_present", "telegram_source", "telegram_destination",
            "telegram_rollback", "telegram_fence", "source_owner_uid",
            "destination_owner_uid", "destination_owner_gid",
        },
        "browser": {
            "runtime_lock", "storage_state", "signing_key", "journal",
            "attestation", "consumption",
        },
    }
    normalized = dict(request)
    for name, fields in groups.items():
        if name == "ports":
            normalized[name] = _first_adoption_ports(request.get(name))
            continue
        group = _request_group(request, name, fields)
        for field, item in group.items():
            if field.endswith(("_uid", "_gid", "_port")):
                if type(item) is not int or int(item) < 0:
                    raise ActivationError(f"first-adoption {name}.{field} is invalid")
            elif field == "telegram_present":
                if type(item) is not bool:
                    raise ActivationError("first-adoption Telegram presence is invalid")
            elif not isinstance(item, str) or not item or "\x00" in item:
                raise ActivationError(f"first-adoption {name}.{field} is invalid")
        normalized[name] = group
    group_path_fields = {
        "ports": {"bundle"},
        "legacy_writer": {
            "bridge_transaction", "database", "profile", "socket",
            "dropin", "retirement_guard", "handoff_journal",
        },
        "candidate": groups["candidate"],
        "console": groups["console"]
        - {
            "console_port",
            "console_uid",
            "console_gid",
            "edge_uid",
            "edge_gid",
            "legacy_uid",
        },
        "authority": groups["authority"]
        - {
            "maintenance_gid",
            "authority_uid",
            "authority_gid",
            "inventory_uid",
            "inventory_gid",
        },
        "api": {
            "journal", "profile_path", "bootstrap_profile_path",
            "bootstrap_profile_journal", "final_profile_journal",
            "inventory_readiness_evidence",
        },
        "public": {"publication", "handoff_journal"},
        "fleet": {
            "authority_export", "evidence_root", "manifest_template",
            "manifest_set", "adoption_request", "helper"
        },
        "background": {
            "telegram_source",
            "telegram_destination",
            "telegram_rollback",
            "telegram_fence",
        },
        "browser": groups["browser"],
    }
    for name, fields in group_path_fields.items():
        group = normalized[name]
        if not isinstance(group, Mapping):
            raise ActivationError(f"first-adoption {name} request changed")
        for field in fields:
            _absolute(
                Path(str(group[field])), f"first-adoption {name}.{field}"
            )
    authority = normalized["authority"]
    legacy_writer = normalized["legacy_writer"]
    if (
        not isinstance(legacy_writer, Mapping)
        or re.fullmatch(
            r"[0-9a-f]{64}", str(legacy_writer["bridge_journal_sha256"])
        )
        is None
        or str(legacy_writer["database"])
        != str(authority["legacy_database"])
        or str(legacy_writer["socket"])
        != "/run/devcoordinator-authority.sock"
        or str(legacy_writer["dropin"])
        != (
            "/etc/systemd/system/devcoordinator-broker.service.d/"
            "95-schema12-cutover-bridge.conf"
        )
        or str(legacy_writer["retirement_guard"])
        != (
            "/etc/systemd/system/devcoordinator-broker.service.d/"
            "99-schema13-retired-legacy-broker.conf"
        )
        or Path(str(legacy_writer["handoff_journal"]))
        != Path(str(legacy_writer["bridge_transaction"]))
        / "writer-handoff-journal.json"
    ):
        raise ActivationError(
            "first-adoption legacy-writer handoff binding is invalid"
        )
    try:
        if str(uuid.UUID(str(legacy_writer["bridge_operation_id"]))) != str(
            legacy_writer["bridge_operation_id"]
        ):
            raise ValueError
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError(
            "first-adoption legacy-writer operation identity is invalid"
        ) from error
    if (
        not isinstance(authority, Mapping)
        or authority["authority_uid"] != 0
        or authority["database"] != cutover.FINAL_AUTHORITY_DATABASE_PATH
        or authority["maintenance_root"]
        != str(CANONICAL_MAINTENANCE_ROOT)
        or len(
            {
                str(authority["legacy_database"]),
                str(authority["database"]),
                str(authority["inventory_database"]),
            }
        )
        != 3
    ):
        raise ActivationError("first-adoption authority must remain root-owned")
    fleet = normalized["fleet"]
    if (
        not isinstance(fleet, Mapping)
        or re.fullmatch(
            r"[0-9a-f]{64}", str(fleet["manifest_template_sha256"])
        )
        is None
    ):
        raise ActivationError(
            "first-adoption fleet manifest template binding is invalid"
        )
    api = normalized["api"]
    public = normalized["public"]
    console = normalized["console"]
    candidate = normalized["candidate"]
    ports = normalized["ports"]
    reservations = (
        ports.get("reservations") if isinstance(ports, Mapping) else None
    )
    if (
        not isinstance(api, Mapping)
        or not isinstance(public, Mapping)
        or not isinstance(console, Mapping)
        or not isinstance(candidate, Mapping)
        or not isinstance(reservations, Mapping)
        or api["profile_path"] != cutover.PROTECTED_PROFILE_PATH
        or api["bootstrap_profile_path"] != str(API_HANDOFF_PROFILE_PATH)
        or api["bootstrap_profile_path"] == api["profile_path"]
        or int(api["api_uid"]) <= 0
        or not 30000 <= int(api["handoff_port"]) <= 60999
        or not 30000 <= int(public["http_handoff_port"]) <= 60999
        or not 30000 <= int(public["https_handoff_port"]) <= 60999
        or not 30000 <= int(console["console_port"]) <= 60999
        or int(console["console_port"]) != reservations["console_outer"]
        or int(api["handoff_port"]) != reservations["handoff_api"]
        or int(public["http_handoff_port"]) != reservations["handoff_http"]
        or int(public["https_handoff_port"]) != reservations["handoff_https"]
    ):
        raise ActivationError("first-adoption listener ports are invalid")
    return normalized


def build_first_adoption_request(
    arguments: argparse.Namespace,
) -> Mapping[str, object]:
    expected_uid = int(arguments.expected_uid)
    if os.geteuid() != expected_uid:
        raise ActivationError(
            "first-adoption request builder must run as the authority UID"
        )
    payload: dict[str, object] = {
        "state": arguments.state,
        "repair_plan": arguments.repair_plan,
        "repair_result": arguments.repair_result,
    }
    state = cutover.load_state(
        Path(arguments.state), authority_uid=expected_uid
    )
    port_bundle_path = _absolute(
        Path(arguments.port_reservations),
        "first-adoption port reservations",
    )
    port_bundle = cutover.verify_first_adoption_port_reservations(
        cutover.read_private_json(port_bundle_path, uid=expected_uid)
    )
    if (
        port_bundle["document_sha256"]
        != arguments.port_reservations_sha256
        or port_bundle["release_digest"] != state["release_digest"]
        or port_bundle["authority_database"]
        != state["legacy_authority_database"]
    ):
        raise ActivationError(
            "first-adoption port reservations are bound to another cutover"
        )
    reservations = port_bundle.get("reservations")
    if not isinstance(reservations, Mapping):
        raise ActivationError("first-adoption port reservations are invalid")
    payload["ports"] = {
        "bundle": str(port_bundle_path),
        "sha256": port_bundle["document_sha256"],
        "reservations": {
            role: item.get("port") if isinstance(item, Mapping) else None
            for role, item in reservations.items()
        },
    }
    for group_name, fields in _FIRST_ADOPTION_ARGUMENTS.items():
        if group_name == "ports":
            continue
        payload[group_name] = {
            field_name: getattr(arguments, argument_name)
            for field_name, argument_name in fields.items()
        }
    document = cutover.seal(FIRST_ADOPTION_REQUEST_KIND, payload)
    checked = _first_adoption_request(document)
    output = _absolute(Path(arguments.output), "first-adoption request output")
    if output.exists() or output.is_symlink():
        recorded = cutover.read_private_json(output, uid=expected_uid)
        if recorded != checked:
            raise ActivationError(
                "first-adoption request output belongs to another transaction"
            )
    else:
        cutover._publish_evidence(output, checked, uid=expected_uid)
    return checked


def _verify_first_adoption_port_binding(
    request: Mapping[str, object],
    *,
    state: Mapping[str, object],
    authority_database: Path,
    expected_uid: int,
    adoption: Mapping[str, object] | None = None,
) -> dict[str, object]:
    ports = request.get("ports")
    if not isinstance(ports, Mapping):
        raise ActivationError("first-adoption port request changed")
    bundle_path = _absolute(
        Path(str(ports.get("bundle"))),
        "first-adoption port reservations",
    )
    bundle = cutover.verify_first_adoption_port_reservations(
        cutover.read_private_json(bundle_path, uid=expected_uid)
    )
    bundle_reservations = bundle.get("reservations")
    request_reservations = ports.get("reservations")
    observed_ports = {
        role: item.get("port") if isinstance(item, Mapping) else None
        for role, item in bundle_reservations.items()
    } if isinstance(bundle_reservations, Mapping) else {}
    if (
        bundle["document_sha256"] != ports.get("sha256")
        or bundle["release_digest"] != state.get("release_digest")
        or bundle["authority_database"]
        != state.get("legacy_authority_database")
        or request_reservations != observed_ports
    ):
        raise ActivationError(
            "first-adoption port reservations changed after request sealing"
        )
    if str(authority_database) == bundle["authority_database"]:
        if adoption is not None:
            raise ActivationError(
                "legacy port verification must not consume adoption evidence"
            )
        row_evidence = cutover.verify_first_adoption_port_reservation_rows(
            authority_database,
            bundle,
            authority_uid=expected_uid,
            minimum_handoff_remaining_seconds=(
                FIRST_ADOPTION_MINIMUM_HANDOFF_REMAINING_SECONDS
            ),
        )
    else:
        if not isinstance(adoption, Mapping):
            raise ActivationError(
                "post-split port verification lacks authority adoption evidence"
            )
        row_evidence = (
            cutover.verify_first_adoption_port_reservation_rows_after_adoption(
                authority_database,
                bundle,
                adoption,
                authority_uid=expected_uid,
                minimum_handoff_remaining_seconds=(
                    FIRST_ADOPTION_MINIMUM_HANDOFF_REMAINING_SECONDS
                ),
            )
        )
    return {"bundle": bundle, "rows": row_evidence}


def _first_adoption_repair_reason_is_exact(
    *, plan: Mapping[str, object], result: Mapping[str, object]
) -> bool:
    state_revision_before = result.get("state_revision_before")
    state_revision_after = result.get("state_revision_after")
    maintenance_deployment_id = result.get("maintenance_deployment_id")
    if (
        type(state_revision_before) is not int
        or type(state_revision_after) is not int
        or type(plan.get("authority_state_revision")) is not int
        or state_revision_before < int(plan["authority_state_revision"])
        or state_revision_after != state_revision_before + 1
        or not isinstance(maintenance_deployment_id, str)
    ):
        return False
    return result.get("reason") == cutover._authority_repair_mutation_reason(
        plan_id=str(plan.get("plan_id")),
        deployment_id=maintenance_deployment_id,
        state_revision_before=state_revision_before,
    )


def _first_adoption_test_store_completion(
    state: Mapping[str, object],
) -> dict[str, object]:
    try:
        completion = cutover._test_store_cutover_completion(state)
    except cutover.CutoverError as error:
        raise ActivationError(str(error)) from error
    if (
        state.get("phase") != "sealed"
        or completion["mode"] != "history-discarded"
        or "test-history-discard" not in state.get("evidence", {})
    ):
        raise ActivationError(
            "first adoption requires one sealed fresh disposable Test Store"
        )
    return completion


def _observe_first_adoption_repair_state(
    database: Path,
    *,
    repository_id: str,
    expected_uid: int,
) -> dict[str, object]:
    """Read one WAL-aware authority snapshot through a retained descriptor."""

    database = _absolute(database, "first-adoption repair authority database")
    descriptor = -1
    connection: sqlite3.Connection | None = None
    try:
        path_before = database.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_uid != expected_uid
            or stat.S_IMODE(path_before.st_mode) & 0o022
            or path_before.st_nlink != 1
            or database.resolve(strict=True) != database
        ):
            raise ActivationError(
                "first-adoption repair authority database identity is unsafe"
            )
        descriptor = os.open(
            database,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor_before = os.fstat(descriptor)
        if (
            descriptor_before.st_dev != path_before.st_dev
            or descriptor_before.st_ino != path_before.st_ino
            or descriptor_before.st_uid != expected_uid
            or not stat.S_ISREG(descriptor_before.st_mode)
            or stat.S_IMODE(descriptor_before.st_mode) & 0o022
            or descriptor_before.st_nlink != 1
        ):
            raise ActivationError(
                "first-adoption repair authority descriptor changed"
            )
        # Do not use immutable=1 here.  The live schema-12 authority uses WAL,
        # and immutable SQLite reads intentionally ignore committed WAL pages.
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("BEGIN")
        cutover._authority_repair_schema(connection)
        schema = connection.execute(
            "SELECT schema_version, migration_state "
            "FROM schema_metadata WHERE singleton = 1"
        ).fetchall()
        if (
            len(schema) != 1
            or int(schema[0][0]) != 12
            or str(schema[0][1]) != "ready"
        ):
            raise ActivationError(
                "first-adoption repair authority schema is not ready schema 12"
            )
        metadata, repository, startup_policies = (
            cutover._authority_repository_repair_snapshot(
                connection, repository_id
            )
        )
        connection.execute("ROLLBACK")
        connection.close()
        connection = None
        descriptor_after = os.fstat(descriptor)
        path_after = database.lstat()
        if (
            descriptor_after.st_dev != descriptor_before.st_dev
            or descriptor_after.st_ino != descriptor_before.st_ino
            or path_after.st_dev != descriptor_before.st_dev
            or path_after.st_ino != descriptor_before.st_ino
            or stat.S_ISLNK(path_after.st_mode)
            or not stat.S_ISREG(path_after.st_mode)
            or path_after.st_uid != expected_uid
            or stat.S_IMODE(path_after.st_mode) & 0o022
            or path_after.st_nlink != 1
        ):
            raise ActivationError(
                "first-adoption repair authority changed during observation"
            )
        return {
            "database_identity": {
                "device": int(descriptor_after.st_dev),
                "inode": int(descriptor_after.st_ino),
                "size": int(descriptor_after.st_size),
            },
            "metadata": metadata,
            "repository": repository,
            "startup_policies": startup_policies,
        }
    except ActivationError:
        raise
    except (OSError, sqlite3.Error, cutover.CutoverError) as error:
        raise ActivationError(
            "first-adoption repair authority could not be observed exactly"
        ) from error
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            connection.close()
        if descriptor >= 0:
            os.close(descriptor)


def _verify_first_adoption_tmp_repair_unnecessary(
    database: Path,
    *,
    expected_uid: int,
) -> dict[str, object]:
    """Prove from one WAL-aware schema-12 snapshot that /tmp is harmless."""

    database = _absolute(database, "first-adoption repair authority database")
    descriptor = -1
    connection: sqlite3.Connection | None = None
    try:
        path_before = database.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_uid != expected_uid
            or stat.S_IMODE(path_before.st_mode) & 0o022
            or path_before.st_nlink != 1
            or database.resolve(strict=True) != database
        ):
            raise ActivationError(
                "first-adoption repair authority database identity is unsafe"
            )
        descriptor = os.open(
            database,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor_before = os.fstat(descriptor)
        if (
            descriptor_before.st_dev != path_before.st_dev
            or descriptor_before.st_ino != path_before.st_ino
            or descriptor_before.st_uid != expected_uid
            or not stat.S_ISREG(descriptor_before.st_mode)
            or stat.S_IMODE(descriptor_before.st_mode) & 0o022
            or descriptor_before.st_nlink != 1
        ):
            raise ActivationError(
                "first-adoption repair authority descriptor changed"
            )
        # This must remain a normal read-only SQLite connection. immutable=1
        # would omit committed WAL pages and could bless a stale /tmp row.
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("BEGIN")
        cutover._authority_repair_schema(connection)
        schema = connection.execute(
            "SELECT schema_version, migration_state, database_generation, "
            "state_revision FROM schema_metadata WHERE singleton = 1"
        ).fetchall()
        if (
            len(schema) != 1
            or int(schema[0][0]) != 12
            or str(schema[0][1]) != "ready"
            or not isinstance(schema[0][2], str)
            or not schema[0][2]
            or type(schema[0][3]) is not int
            or int(schema[0][3]) < 0
        ):
            raise ActivationError(
                "first-adoption repair authority schema is not ready schema 12"
            )
        rows = connection.execute(
            "SELECT repo_id FROM repositories WHERE canonical_root = ? "
            "ORDER BY repo_id LIMIT 2",
            ("/tmp",),
        ).fetchall()
        if len(rows) > 1:
            raise ActivationError(
                "first-adoption /tmp authority repair is still required"
            )
        snapshot: dict[str, object] | None = None
        startup_policies: list[dict[str, object]] = []
        if rows:
            _metadata, snapshot, startup_policies = (
                cutover._authority_repository_repair_snapshot(
                    connection, str(rows[0][0])
                )
            )
        connection.execute("ROLLBACK")
        connection.close()
        connection = None
        descriptor_after = os.fstat(descriptor)
        path_after = database.lstat()
        if (
            descriptor_after.st_dev != descriptor_before.st_dev
            or descriptor_after.st_ino != descriptor_before.st_ino
            or path_after.st_dev != descriptor_before.st_dev
            or path_after.st_ino != descriptor_before.st_ino
            or stat.S_ISLNK(path_after.st_mode)
            or not stat.S_ISREG(path_after.st_mode)
            or path_after.st_uid != expected_uid
            or stat.S_IMODE(path_after.st_mode) & 0o022
            or path_after.st_nlink != 1
        ):
            raise ActivationError(
                "first-adoption repair authority changed during observation"
            )
        if snapshot is not None and (
            snapshot.get("canonical_root") != "/tmp"
            or snapshot.get("state") != "missing"
            or snapshot.get("installation_status") != "disabled"
            or snapshot.get("installation_startup_fenced") is not True
            or snapshot.get("installation_operation_id") is not None
            or snapshot.get("enrollment_count") != 0
            or any(policy.get("requires_update") is not False for policy in startup_policies)
        ):
            raise ActivationError(
                "first-adoption /tmp authority repair is still required"
            )
        return {
            "mode": "repair-not-required",
            "database_identity": {
                "device": int(descriptor_after.st_dev),
                "inode": int(descriptor_after.st_ino),
                "size": int(descriptor_after.st_size),
            },
            "authority_generation": str(schema[0][2]),
            "state_revision": int(schema[0][3]),
            "repository": snapshot,
            "startup_policy_count": len(startup_policies),
            "enabled_startup_policy_count": 0,
        }
    except ActivationError:
        raise
    except (OSError, sqlite3.Error, cutover.CutoverError) as error:
        raise ActivationError(
            "first-adoption repair authority could not be observed exactly"
        ) from error
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            connection.close()
        if descriptor >= 0:
            os.close(descriptor)


def _verify_first_adoption_repair_live_state(
    *,
    database: Path,
    plan: Mapping[str, object],
    result: Mapping[str, object],
    expected_uid: int,
) -> dict[str, object]:
    repository = plan.get("repository")
    if not isinstance(repository, Mapping):
        raise ActivationError("first-adoption repair repository plan changed")
    observation = _observe_first_adoption_repair_state(
        database,
        repository_id=str(result["repository_id"]),
        expected_uid=expected_uid,
    )
    metadata = observation["metadata"]
    snapshot = observation["repository"]
    if not isinstance(metadata, Mapping) or not isinstance(snapshot, Mapping):
        raise ActivationError("first-adoption repair observation is invalid")
    try:
        policy_results = cutover._authority_startup_policy_results(
            planned=plan["startup_policies"],
            current=observation["startup_policies"],
            applied_at=str(result["applied_at"]),
        )
    except cutover.CutoverError as error:
        raise ActivationError(
            "first-adoption repair startup-policy state changed"
        ) from error
    if (
        metadata.get("authority_generation") != result["authority_generation"]
        or type(metadata.get("state_revision")) is not int
        or int(metadata["state_revision"]) < int(result["state_revision_after"])
        or not cutover._authority_repair_same_database(
            planned=result["database_identity_after"],
            current=observation["database_identity"],
        )
        or snapshot.get("display_name") != repository.get("display_name")
        or snapshot.get("canonical_root") != repository.get("canonical_root")
        or not cutover._authority_repository_matches_repair_result(
            repair=result, snapshot=snapshot
        )
        or policy_results != result["startup_policies"]
    ):
        raise ActivationError(
            "first-adoption repair authority semantic state changed"
        )
    return observation


def _verify_first_adoption_repair(
    request: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    authority = request.get("authority")
    if not isinstance(authority, Mapping):
        raise ActivationError("first-adoption authority request changed")
    state = cutover.bind_first_adoption_authority_paths(
        state_path=Path(str(request["state"])),
        legacy_authority_database=Path(str(authority["legacy_database"])),
        authority_database=Path(str(authority["database"])),
        authority_uid=expected_uid,
    )
    completion = _first_adoption_test_store_completion(state)
    if (
        state["phase"] != "sealed"
        or "first-deployment-bootstrap" not in state["evidence"]
        or any(
            key in state["evidence"]
            for key in ("candidate", "activation")
        )
        or state["legacy_authority_database"] != authority["legacy_database"]
        or state["authority_database"] != authority["database"]
    ):
        raise ActivationError(
            "first adoption requires one sealed migrated or discarded Test Store"
        )
    bootstrap = cutover._first_deployment_bootstrap(
        state["evidence"]["first-deployment-bootstrap"],
        expected_release=str(state["release_digest"]),
        expected_test_database=str(state["test_database"]),
        expected_testd_uid=int(state["testd_uid"]),
    )
    if bootstrap["authority_database"] != authority["database"]:
        raise ActivationError(
            "first adoption authority target disagrees with bootstrap"
        )
    candidate = request.get("candidate")
    api = request.get("api")
    if not isinstance(candidate, Mapping) or not isinstance(api, Mapping):
        raise ActivationError("first-adoption evidence outputs changed")
    for output in (
        candidate["candidate_evidence"],
        candidate["activation_evidence"],
    ):
        path = Path(str(output))
        if path.exists() or path.is_symlink():
            raise ActivationError(
                "first adoption requires unused state-evidence outputs"
            )
    plan: dict[str, object] | None = None
    result: dict[str, object] | None = None
    if request["repair_plan"] is None:
        repair_verification = _verify_first_adoption_tmp_repair_unnecessary(
            Path(str(state["legacy_authority_database"])),
            expected_uid=expected_uid,
        )
    else:
        plan = cutover.read_private_json(
            Path(str(request["repair_plan"])), uid=expected_uid
        )
        plan = cutover._validate_authority_repository_disable_plan(plan)
        result = cutover.read_private_json(
            Path(str(request["repair_result"])), uid=expected_uid
        )
        result = cutover._validate_authority_repository_disable_result(result)
        repository = plan["repository"]
        if (
            not isinstance(repository, Mapping)
            or plan["authority_database"] != state["legacy_authority_database"]
            or result["authority_database"] != state["legacy_authority_database"]
            or result["plan_id"] != plan["plan_id"]
            or result["plan_document_sha256"] != plan["document_sha256"]
            or repository.get("canonical_root") != "/tmp"
            or plan["git_metadata_absent"] is not True
            or result["repository_id"] != repository.get("repository_id")
            or result["repository_state"] != "missing"
            or result["installation_status"] != "disabled"
            or result["startup_fenced"] is not True
            or result["enrollment_count"] != 0
            or result["authority_generation"] != plan["authority_generation"]
            or result["authority_uid"] != expected_uid
            or not _first_adoption_repair_reason_is_exact(plan=plan, result=result)
            or result["actor"] != cutover.AUTHORITY_REPOSITORY_REPAIR_ACTOR
        ):
            raise ActivationError("exact /tmp authority repair did not verify")
        repair_verification = _verify_first_adoption_repair_live_state(
            database=Path(str(state["legacy_authority_database"])),
            plan=plan,
            result=result,
            expected_uid=expected_uid,
        )
    ports = _verify_first_adoption_port_binding(
        request,
        state=state,
        authority_database=Path(str(state["legacy_authority_database"])),
        expected_uid=expected_uid,
    )
    return {
        "state": state,
        "plan": plan,
        "result": result,
        "repair_verification": repair_verification,
        "ports": ports,
    }


def _write_first_adoption_transaction(
    path: Path, payload: Mapping[str, object], *, expected_uid: int
) -> dict[str, object]:
    document = cutover.seal(FIRST_ADOPTION_TRANSACTION_KIND, dict(payload))
    _atomic_private(path, _canonical(document) + b"\n", expected_uid=expected_uid)
    return document


def _load_first_adoption_transaction(
    path: Path, *, expected_uid: int
) -> dict[str, object] | None:
    if not (path.exists() or path.is_symlink()):
        return None
    value = cutover.read_private_json(path, uid=expected_uid)
    if not isinstance(value, Mapping) or value.get("kind") != FIRST_ADOPTION_TRANSACTION_KIND:
        raise ActivationError("first-adoption transaction journal kind is invalid")
    unsigned = {key: item for key, item in value.items() if key != "document_sha256"}
    if value.get("document_sha256") != _sha256_bytes(_canonical(unsigned)):
        raise ActivationError("first-adoption transaction journal digest is invalid")
    return dict(value)


def _start_exact_units(runner: CommandRunner, units: Sequence[str]) -> dict[str, bool]:
    ready: dict[str, bool] = {}
    for unit in units:
        # `reset-failed` is advisory here: systemd returns non-zero when a
        # freshly installed unit has no loaded failed state.  The enable/start
        # command results below are the actual readiness contract.
        runner.status(["/usr/bin/systemctl", "reset-failed", unit])
        if unit.endswith(".socket"):
            if runner.status(["/usr/bin/systemctl", "enable", unit]) != 0:
                raise ActivationError(
                    f"first-adoption socket could not be enabled: {unit}"
                )
            # A service start-limit can leave systemd holding an unlinked Unix
            # listener.  Rebind the socket path explicitly before starting its
            # consumer instead of treating an active stale descriptor as ready.
            start_command = ["/usr/bin/systemctl", "restart", unit]
        else:
            start_command = ["/usr/bin/systemctl", "enable", "--now", unit]
        if runner.status(start_command) != 0:
            raise ActivationError(f"first-adoption unit failed readiness: {unit}")
        ready[unit] = True
    return ready


def _legacy_writer_handoff(
    *,
    action: str,
    release: Path,
    legacy_writer: Mapping[str, object],
    outer_transaction_id: str,
    expected_journal_sha256: str,
    expected_uid: int,
    runner: CommandRunner,
) -> dict[str, object]:
    """Run the exact bridge-owned handoff from the immutable release."""

    if action not in {
        "handoff-reference",
        "handoff-arm",
        "handoff-retire",
        "handoff-rollback-prepare",
        "handoff-rollback-unfence",
        "handoff-verify-rearmed",
        "handoff-complete",
    }:
        raise ActivationError("legacy-writer handoff action is invalid")
    try:
        outer_transaction_id = str(uuid.UUID(outer_transaction_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError(
            "legacy-writer outer transaction identity is invalid"
        ) from error
    if re.fullmatch(r"[0-9a-f]{64}", expected_journal_sha256) is None:
        raise ActivationError(
            "legacy-writer predecessor journal digest is invalid"
        )
    helper = release / "bin/devcoordinator-schema12-bridge"
    result = runner.run_json(
        [
            str(helper),
            "--json",
            action,
            "--transaction-dir",
            str(legacy_writer["bridge_transaction"]),
            "--operation-id",
            str(legacy_writer["bridge_operation_id"]),
            "--expected-journal-sha256",
            expected_journal_sha256,
            "--outer-transaction-id",
            outer_transaction_id,
            "--database",
            str(legacy_writer["database"]),
            "--profile",
            str(legacy_writer["profile"]),
            "--socket",
            str(legacy_writer["socket"]),
            "--dropin",
            str(legacy_writer["dropin"]),
            "--retirement-guard",
            str(legacy_writer["retirement_guard"]),
            "--handoff-journal",
            str(legacy_writer["handoff_journal"]),
            "--expected-uid",
            str(expected_uid),
        ]
    )
    document_sha256 = result.get("document_sha256")
    if (
        result.get("operation_id") != legacy_writer["bridge_operation_id"]
        or result.get("outer_transaction_id") != outer_transaction_id
        or not isinstance(document_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", document_sha256) is None
    ):
        raise ActivationError(
            "legacy-writer handoff returned invalid transaction evidence"
        )
    return dict(result)


def _resume_first_adoption_graph(
    *,
    graph_path: Path,
    credential_path: Path,
    release: Path,
    expected_uid: int,
) -> Mapping[str, object] | None:
    graph_present = graph_path.exists() or graph_path.is_symlink()
    credential_present = credential_path.exists() or credential_path.is_symlink()
    if not graph_present:
        if credential_present:
            raise ActivationError(
                "first-adoption credential evidence exists without its prepared graph"
            )
        return None
    raw = cutover.read_private_json(graph_path, uid=expected_uid)
    graph = cutover.verify_seal(
        raw,
        kind=FIRST_ADOPTION_GRAPH_KIND,
        fields={
            "release_digest",
            "executor_release",
            "credential_preflight_sha256",
            "credential_preflight",
            "host_preflight_sha256",
            "background_config",
            "project_isolation",
            "console_slot_ports",
            "prior_units",
            "prior_files",
            "installed_files",
            "deferred_units",
            "listeners_started",
            "created_at",
        },
    )
    embedded = graph.get("credential_preflight")
    if not isinstance(embedded, Mapping):
        raise ActivationError("first-adoption graph lacks credential evidence")
    credential = cutover.verify_seal(
        embedded,
        kind=CREDENTIAL_PREFLIGHT_KIND,
        fields={"release_digest", "credentials", "oidc", "created_at"},
    )
    expected_units = sorted(
        (
            *SOCKET_UNITS,
            *SERVICE_UNITS,
            f"devcoordinator-console@{release.name}.service",
            *HANDOFF_SOCKET_UNITS,
            HANDOFF_SERVICE_UNIT,
            API_HANDOFF_SOCKET_UNIT,
            API_HANDOFF_SERVICE_UNIT,
        )
    )
    console_slot_ports = graph.get("console_slot_ports")
    if (
        not isinstance(console_slot_ports, Mapping)
        or set(console_slot_ports) != {"console_outer", "console_inner"}
        or any(
            type(port) is not int or not 30000 <= int(port) <= 60999
            for port in console_slot_ports.values()
        )
        or len(set(console_slot_ports.values())) != 2
    ):
        raise ActivationError(
            "first-adoption prepared graph Console ports are invalid"
        )
    if (
        graph.get("release_digest") != release.name
        or graph.get("executor_release") != str(release)
        or graph.get("listeners_started") is not False
        or graph.get("deferred_units") != expected_units
        or graph.get("credential_preflight_sha256")
        != credential.get("document_sha256")
        or credential.get("release_digest") != release.name
    ):
        raise ActivationError("first-adoption prepared graph binding is invalid")
    project_isolation = graph.get("project_isolation")
    isolation_counts = (
        project_isolation.get("audit_counts")
        if isinstance(project_isolation, Mapping)
        else None
    )
    isolation_allowed = {
        "ok", "kind", "audit_sha256", "source_schema_version",
        "audit_counts",
        "project_isolation_complete", "authority_database", "audit_path",
        "ledger_path", "ledger_sha256", "ledger_counts",
        "observation_only", "project_resources_mutated",
    }
    if (
        not isinstance(project_isolation, Mapping)
        or not {
            "ok", "kind", "audit_sha256", "source_schema_version",
            "audit_counts",
            "project_isolation_complete", "authority_database", "audit_path",
            "ledger_path",
        } <= set(project_isolation) <= isolation_allowed
        or project_isolation.get("ok") is not True
        or project_isolation.get("kind")
        != PROJECT_ISOLATION_VERIFICATION_KIND
        or project_isolation.get("source_schema_version")
        != COORDINATOR_SCHEMA_VERSION
        or not isinstance(isolation_counts, Mapping)
        or set(isolation_counts)
        != {"compliant", "legacy_requires_recreation", "unobservable"}
        or type(isolation_counts.get("compliant")) is not int
        or int(isolation_counts.get("compliant", -1)) < 0
        or isolation_counts.get("legacy_requires_recreation") != 0
        or isolation_counts.get("unobservable") != 0
        or project_isolation.get("project_isolation_complete") is not True
        or project_isolation.get("observation_only") is not False
        or project_isolation.get("project_resources_mutated") is not False
        or not isinstance(project_isolation.get("audit_sha256"), str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(project_isolation.get("audit_sha256"))
        ) is None
    ):
        raise ActivationError("first-adoption graph isolation evidence is invalid")
    _absolute(
        Path(str(project_isolation["authority_database"])),
        "pre-split project isolation authority database",
    )
    _absolute(
        Path(str(project_isolation["audit_path"])),
        "pre-split project isolation audit",
    )
    if project_isolation.get("ledger_path") is not None:
        raise ActivationError(
            "complete pre-split project isolation unexpectedly retained a ledger"
        )
    installed = graph.get("installed_files")
    if not isinstance(installed, Mapping) or not installed:
        raise ActivationError("first-adoption graph installed-file evidence is invalid")
    for path_text, item in installed.items():
        if not isinstance(path_text, str) or not isinstance(item, Mapping):
            raise ActivationError("first-adoption installed-file entry is invalid")
        path = _absolute(Path(path_text), "first-adoption installed file")
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) & 0o022
            or _sha256_file(path) != item.get("installed_sha256")
        ):
            raise ActivationError(
                f"first-adoption installed file changed during resume: {path}"
            )
    if credential_present:
        recorded = cutover.read_private_json(credential_path, uid=expected_uid)
        if recorded != credential:
            raise ActivationError(
                "first-adoption credential evidence contradicts its graph"
            )
    else:
        cutover._publish_evidence(credential_path, credential, uid=expected_uid)
    return graph


def _fleet_transaction_path(
    fleet: Mapping[str, object],
) -> Path:
    return Path(str(fleet["evidence_root"])) / (
        "first-adoption-fleet-transaction.json"
    )



def _validate_first_adoption_fleet_catalog(
    catalog: object,
    *,
    authority_rows: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], dict[str, Mapping[str, object]]]:
    if not isinstance(catalog, Mapping) or catalog.get("ok") is not True:
        raise ActivationError("fleet pre-adoption catalog is invalid")
    repositories = catalog.get("repositories")
    if not isinstance(repositories, list):
        raise ActivationError("fleet pre-adoption catalog is invalid")
    expected: dict[str, object] = {}
    for item in authority_rows:
        repository_id = item.get("repository_id")
        if (
            not isinstance(repository_id, str)
            or not repository_id
            or repository_id in expected
        ):
            raise ActivationError(
                "fleet authority export repository IDs are invalid"
            )
        expected[repository_id] = item.get("repository_generation")
    indexed: dict[str, Mapping[str, object]] = {}
    for item in repositories:
        if not isinstance(item, Mapping):
            raise ActivationError("fleet pre-adoption catalog is invalid")
        repository_id = item.get("repository_id")
        if not isinstance(repository_id, str) or repository_id in indexed:
            raise ActivationError("fleet pre-adoption catalog is invalid")
        authority_identity = expected.get(repository_id)
        if (
            authority_identity is None
            or item.get("repository_generation") != authority_identity
            or type(item.get("execution_uid")) is not int
            or int(item["execution_uid"]) <= 0
            or item.get("status") not in {"ready", "missing", "invalid"}
            or item.get("readability_status") not in {"clean", "blocked"}
        ):
            raise ActivationError(
                "fleet pre-adoption catalog does not cover the authority export"
            )
        indexed[repository_id] = item
    if set(indexed) != set(expected):
        raise ActivationError(
            "fleet pre-adoption catalog does not cover the authority export"
        )
    return dict(catalog), indexed


def _first_adoption_fleet_setup_result(
    catalog: object,
    *,
    authority_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Validate a read-only fleet census for the availability cutover.

    First availability is intentionally not a fleet-wide manifest migration.
    Every missing, invalid, or unreadable repository is exposed as Setup work
    and may be cataloged later without becoming an availability admission gate.
    """

    normalized, catalog_by_id = _validate_first_adoption_fleet_catalog(
        catalog,
        authority_rows=authority_rows,
    )
    counts = normalized.get("counts")
    repositories = normalized.get("repositories")
    expected_counts = {"ready": 0, "missing": 0, "invalid": 0}
    if not isinstance(repositories, list):
        raise ActivationError("fleet setup catalog repositories are invalid")
    for item in catalog_by_id.values():
        expected_counts[str(item["status"])] += 1
        if (
            not isinstance(item.get("readability_blocker_codes"), list)
            or type(item.get("has_readability_blockers")) is not bool
            or type(item.get("deletion_scan_complete")) is not bool
            or type(item.get("deleted_tracked_count")) is not int
            or int(item["deleted_tracked_count"]) < 0
        ):
            raise ActivationError(
                "fleet setup catalog repository evidence is invalid"
            )
        if item.get("status") == "ready":
            if type(item.get("adoption_ready")) is not bool:
                raise ActivationError(
                    "fleet setup catalog readiness evidence is invalid"
                )
        elif item.get("adoption_ready") is not False:
            raise ActivationError(
                "fleet setup catalog non-ready repository is runnable"
            )
    if (
        not isinstance(counts, Mapping)
        or set(counts) != set(expected_counts)
        or any(type(value) is not int for value in counts.values())
        or dict(counts) != expected_counts
    ):
        raise ActivationError("fleet setup catalog counts are invalid")

    runnable_ids = sorted(
        repository_id
        for repository_id, item in catalog_by_id.items()
        if item.get("status") == "ready"
        and item.get("adoption_ready") is True
        and item.get("readability_status") == "clean"
    )
    setup_ids = sorted(set(catalog_by_id) - set(runnable_ids))
    return {
        "mode": FIRST_ADOPTION_FLEET_SETUP_CATALOG_MODE,
        "catalog": normalized,
        "runnable_repository_ids": runnable_ids,
        "setup_repository_ids": setup_ids,
        "blocked_repository_ids": sorted(
            repository_id
            for repository_id, item in catalog_by_id.items()
            if item.get("readability_status") == "blocked"
        ),
        "manifest_mutations": 0,
    }



def _validate_first_adoption_fleet_plan(
    planned: object,
) -> dict[str, object]:
    if (
        not isinstance(planned, Mapping)
        or planned.get("ok") is not True
        or not isinstance(planned.get("plan_id"), str)
        or not str(planned["plan_id"]).startswith(
            "manifest-adoption-"
        )
        or re.fullmatch(
            r"[0-9a-f]{64}", str(planned.get("plan_sha256"))
        )
        is None
    ):
        raise ActivationError(
            "fleet manifest adoption plan is invalid"
        )
    return dict(planned)


def _validate_first_adoption_fleet_apply(
    applied: object, *, planned: Mapping[str, object]
) -> dict[str, object]:
    if (
        not isinstance(applied, Mapping)
        or applied.get("ok") is not True
        or applied.get("state") != "applied"
        or applied.get("plan_id") != planned["plan_id"]
        or applied.get("plan_sha256") != planned["plan_sha256"]
        or re.fullmatch(
            r"[0-9a-f]{64}", str(applied.get("result_sha256"))
        )
        is None
    ):
        raise ActivationError(
            "fleet manifest adoption did not apply atomically"
        )
    return dict(applied)


def _validate_first_adoption_fleet_request_preparation(
    prepared: object, *, adoption_request: Path
) -> dict[str, object]:
    if (
        not isinstance(prepared, Mapping)
        or prepared.get("ok") is not True
        or prepared.get("request_path") != str(adoption_request.absolute())
        or re.fullmatch(
            r"[0-9a-f]{64}", str(prepared.get("request_sha256"))
        )
        is None
    ):
        raise ActivationError(
            "fleet manifest adoption request preparation failed"
        )
    return dict(prepared)


def _write_fleet_transaction(
    path: Path,
    payload: Mapping[str, object],
    *,
    expected_uid: int,
) -> dict[str, object]:
    return _write_private_journal(
        path,
        kind=FIRST_ADOPTION_FLEET_JOURNAL_KIND,
        payload=payload,
        expected_uid=expected_uid,
    )



def _trusted_loopback_api_catalog(
    api_url: str = "http://127.0.0.1:29876/v1/test-repositories",
    *,
    timeout: float = 10.0,
) -> dict[str, object]:
    """Read the local catalog without creating or transmitting a credential."""

    parsed = urlparse(api_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/test-repositories"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ActivationError("candidate API catalog endpoint is not trusted loopback HTTP")
    port = parsed.port or 80
    host_header = f"127.0.0.1:{port}"
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        connection.request(
            "GET",
            parsed.path,
            headers={
                "Host": host_header,
                "Accept": "application/json",
                "User-Agent": "devcoordinator-activation/1",
            },
        )
        response = connection.getresponse()
        payload = response.read(cutover.MAX_DOCUMENT_BYTES + 1)
    except OSError as error:
        raise ActivationError("candidate API repository catalog is unreachable") from error
    finally:
        connection.close()
    if response.status != 200 or len(payload) > cutover.MAX_DOCUMENT_BYTES:
        raise ActivationError("candidate API repository catalog verification failed")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationError("candidate API repository catalog is invalid JSON") from error
    if not isinstance(document, dict):
        raise ActivationError("candidate API repository catalog is invalid")
    return document


def _first_adoption_live_step(
    step: str,
    *,
    request: Mapping[str, object],
    journal: Mapping[str, object],
    expected_uid: int,
    runner: CommandRunner,
) -> Mapping[str, object]:
    state_path = Path(str(request["state"]))
    candidate_request = request["candidate"]
    console = request["console"]
    authority = request["authority"]
    api = request["api"]
    public = request["public"]
    fleet = request["fleet"]
    background = request["background"]
    legacy_writer = request.get("legacy_writer", {})
    ports = request["ports"]
    if not all(
        isinstance(value, Mapping)
        for value in (
            candidate_request,
            console,
            authority,
            api,
            public,
            fleet,
            background,
            ports,
            legacy_writer,
        )
    ):
        raise ActivationError("first-adoption request groups changed after validation")
    release = Path(
        str(cutover.load_state(state_path, authority_uid=expected_uid)["release"])
    )
    steps = journal.get("steps")
    if not isinstance(steps, Mapping):
        raise ActivationError("first-adoption transaction step journal is invalid")
    if step == "validated":
        verified = _verify_first_adoption_repair(request, expected_uid=expected_uid)
        repair_plan = verified["plan"]
        repair_result = verified["result"]
        bridge_reference = _legacy_writer_handoff(
            action="handoff-reference",
            release=release,
            legacy_writer=legacy_writer,
            outer_transaction_id=str(journal["transaction_id"]),
            expected_journal_sha256=str(
                legacy_writer["bridge_journal_sha256"]
            ),
            expected_uid=expected_uid,
            runner=runner,
        )
        return {
            "cutover_state_sha256": verified["state"]["document_sha256"],
            "repair_plan_sha256": (
                repair_plan["document_sha256"]
                if isinstance(repair_plan, Mapping)
                else None
            ),
            "repair_result_sha256": (
                repair_result["document_sha256"]
                if isinstance(repair_result, Mapping)
                else None
            ),
            "repair_verification": verified["repair_verification"],
            "port_reservations_sha256": verified["ports"]["bundle"][
                "document_sha256"
            ],
            "port_reservation_rows": verified["ports"]["rows"],
            "legacy_writer_reference": bridge_reference,
        }
    if step == "graph_prepared":
        state = cutover.load_state(state_path, authority_uid=expected_uid)
        resumed = _resume_first_adoption_graph(
            graph_path=Path(str(candidate_request["graph_evidence"])),
            credential_path=Path(str(candidate_request["credential_evidence"])),
            release=release,
            expected_uid=expected_uid,
        )
        if resumed is not None:
            pre_split_isolation = resumed.get("project_isolation")
            expected_console_ports = {
                role: ports["reservations"][role]
                for role in ("console_outer", "console_inner")
            }
            if (
                not isinstance(pre_split_isolation, Mapping)
                or pre_split_isolation.get("authority_database")
                != authority["legacy_database"]
                or pre_split_isolation.get("source_schema_version") != 12
                or resumed.get("console_slot_ports")
                != expected_console_ports
            ):
                raise ActivationError(
                    "prepared graph is bound to another final authority"
                )
            return resumed
        graph, credential = prepare_candidate(
            state=state,
            candidate_slot_source=Path(str(candidate_request["slot_source"])),
            legacy_console_env=Path(str(candidate_request["legacy_console_env"])),
            background_project_root=Path(str(candidate_request["background_project_root"])),
            background_config_transaction=Path(str(candidate_request["background_config_transaction"])),
            project_isolation_audit=Path(str(candidate_request["project_isolation_audit"])),
            project_isolation_ledger=Path(str(candidate_request["project_isolation_ledger"])),
            rollback_directory=Path(str(candidate_request["rollback_directory"])),
            expected_uid=expected_uid,
            legacy_console_uid=int(console["legacy_uid"]),
            expected_port_reservations=ports["reservations"],
            runner=runner,
            first_adoption_defer_start=True,
            first_adoption_legacy_authority_database=Path(
                str(authority["legacy_database"])
            ),
            first_adoption_journal=Path(str(candidate_request["graph_journal"])),
        )
        cutover._publish_evidence(
            Path(str(candidate_request["graph_evidence"])), graph, uid=expected_uid
        )
        cutover._publish_evidence(
            Path(str(candidate_request["credential_evidence"])), credential, uid=expected_uid
        )
        return graph
    if step == "console_state_migrated":
        return migrate_legacy_console_state(
            release=release,
            legacy_env=Path(str(candidate_request["legacy_console_env"])),
            legacy_state=Path(str(console["legacy_state"])),
            console_state=Path(str(console["console_state"])),
            edge_identity_state=Path(str(console["edge_identity_state"])),
            console_config=Path(str(console["console_config"])),
            route_resolution=Path(str(console["route_resolution"])),
            private_publication_input=Path(str(console["publication_input"])),
            console_port=int(console["console_port"]),
            console_uid=int(console["console_uid"]),
            console_gid=int(console["console_gid"]),
            edge_uid=int(console["edge_uid"]),
            edge_gid=int(console["edge_gid"]),
            legacy_uid=int(console["legacy_uid"]),
            rollback_directory=Path(str(console["rollback_directory"])),
            journal_file=Path(str(console["migration_journal"])),
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "legacy_writer_guarded":
        validated = steps.get("validated")
        reference = (
            validated.get("legacy_writer_reference")
            if isinstance(validated, Mapping)
            else None
        )
        if not isinstance(reference, Mapping):
            raise ActivationError(
                "legacy-writer guard lacks its validated bridge reference"
            )
        return _legacy_writer_handoff(
            action="handoff-arm",
            release=release,
            legacy_writer=legacy_writer,
            outer_transaction_id=str(journal["transaction_id"]),
            expected_journal_sha256=str(reference["document_sha256"]),
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "api_handoff_ready":
        adoption = steps.get("storage_split")
        if not isinstance(adoption, Mapping):
            raise ActivationError(
                "API handoff lacks authority adoption evidence"
            )
        _verify_first_adoption_port_binding(
            request,
            state=cutover.load_state(
                state_path, authority_uid=expected_uid
            ),
            authority_database=Path(str(authority["database"])),
            expected_uid=expected_uid,
            adoption=adoption,
        )
        return api_handoff_transaction(
            journal_file=Path(str(api["journal"])),
            handoff_port=int(api["handoff_port"]),
            action="start",
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "storage_split":
        current = cutover.load_state(
            state_path, authority_uid=expected_uid
        )
        _verify_first_adoption_port_binding(
            request,
            state=current,
            authority_database=Path(str(authority["legacy_database"])),
            expected_uid=expected_uid,
        )
        adoption = adopt_authority_database(
            release=release,
            source_database=Path(str(authority["legacy_database"])),
            authority_database=Path(str(authority["database"])),
            retained_source_database=None,
            inventory_database=Path(str(authority["inventory_database"])),
            inventory_publication=Path(str(authority["inventory_publication"])),
            split_attestation=Path(str(authority["split_attestation"])),
            pointer_file=Path(str(authority["adoption_pointer"])),
            maintenance_root=Path(str(authority["maintenance_root"])),
            maintenance_gid=int(authority["maintenance_gid"]),
            authority_owner_uid=int(authority["authority_uid"]),
            authority_owner_gid=int(authority["authority_gid"]),
            inventory_owner_uid=int(authority["inventory_uid"]),
            inventory_owner_gid=int(authority["inventory_gid"]),
            operation_journal=Path(str(authority["operation_journal"])),
            expected_uid=expected_uid,
            runner=runner,
        )
        _verify_first_adoption_port_binding(
            request,
            state=current,
            authority_database=Path(str(authority["database"])),
            expected_uid=expected_uid,
            adoption=adoption,
        )
        return adoption
    if step == "legacy_writer_retired":
        guarded = steps.get("legacy_writer_guarded")
        adoption = steps.get("storage_split")
        if not isinstance(guarded, Mapping) or not isinstance(
            adoption, Mapping
        ):
            raise ActivationError(
                "legacy-writer retirement requires its guard and storage split"
            )
        return _legacy_writer_handoff(
            action="handoff-retire",
            release=release,
            legacy_writer=legacy_writer,
            outer_transaction_id=str(journal["transaction_id"]),
            expected_journal_sha256=str(guarded["document_sha256"]),
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "snapshotd_ready":
        return {
            "ready_units": _start_exact_units(
                runner,
                (
                    "devcoordinator-test-snapshotd.socket",
                    "devcoordinator-test-snapshotd.service",
                ),
            )
        }
    if step == "authority_test_plane_ready":
        return {
            "ready_units": _start_exact_units(
                runner,
                (
                    "devcoordinator-testd.socket",
                    "devcoordinator-authority.socket",
                    "devcoordinator-testd.service",
                    "devcoordinator-authority.service",
                ),
            )
        }
    if step in {
        "api_bootstrap_profile_ready",
        "api_final_profile_ready",
    }:
        adoption = steps.get("storage_split")
        authority_identity = (
            adoption.get("authority")
            if isinstance(adoption, Mapping)
            else None
        )
        if (
            not isinstance(authority_identity, Mapping)
            or not isinstance(
                authority_identity.get("database_generation"), str
            )
        ):
            raise ActivationError(
                "protected profile publication lacks database generation evidence"
            )
        bootstrap = step == "api_bootstrap_profile_ready"
        return publish_first_adoption_profiles(
            authority_database=Path(str(authority["database"])),
            destination=Path(
                str(
                    api[
                        "bootstrap_profile_path"
                        if bootstrap
                        else "profile_path"
                    ]
                )
            ),
            validation_uid=int(api["api_uid"]),
            rollback_directory=Path(
                str(candidate_request["rollback_directory"])
            ),
            journal_file=Path(
                str(
                    api[
                        "bootstrap_profile_journal"
                        if bootstrap
                        else "final_profile_journal"
                    ]
                )
            ),
            expected_uid=expected_uid,
        )
    if step == "api_ready":
        return api_handoff_transaction(
            journal_file=Path(str(api["journal"])),
            handoff_port=int(api["handoff_port"]),
            action="finish",
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "maintenance_released":
        adoption = steps.get("storage_split")
        if not isinstance(adoption, Mapping):
            raise ActivationError(
                "maintenance release requires the completed storage split"
            )
        return release_authority_maintenance_for_first_adoption(
            adoption,
            release=release,
            maintenance_gid=int(authority["maintenance_gid"]),
            operation_journal=Path(
                str(authority["operation_journal"])
            ),
            expected_uid=expected_uid,
        )
    if step == "profile_inventory_ready":
        publication = steps.get("api_final_profile_ready")
        if not isinstance(publication, Mapping) or not isinstance(
            publication.get("attestation"), Mapping
        ):
            raise ActivationError(
                "profile inventory readiness requires the journaled v13 profile publication"
            )
        current = cutover.load_state(state_path, authority_uid=expected_uid)
        evidence_path = Path(str(api["inventory_readiness_evidence"]))
        recorded_readiness: Mapping[str, object] | None = None
        if evidence_path.exists() or evidence_path.is_symlink():
            recorded_readiness = cutover._normalize_replay(
                "profile-inventory-readiness",
                cutover.read_private_json(evidence_path, uid=expected_uid),
            )
        state_readiness = current["evidence"].get(
            "profile-inventory-readiness"
        )
        if isinstance(state_readiness, Mapping):
            normalized_state = cutover._normalize_replay(
                "profile-inventory-readiness", state_readiness
            )
            if (
                recorded_readiness is None
                or recorded_readiness != normalized_state
            ):
                raise ActivationError(
                    "recorded profile inventory readiness output is incomplete"
                )
        replay_verified_at = (
            str(recorded_readiness["verified_at"])
            if isinstance(recorded_readiness, Mapping)
            else None
        )
        readiness = cutover.verify_profile_inventory_readiness(
            state=current,
            profile_repair=publication["attestation"],
            authority_database=Path(str(authority["database"])),
            authority_uid=expected_uid,
            verified_at=replay_verified_at,
        )
        if recorded_readiness is not None:
            if recorded_readiness != readiness:
                raise ActivationError(
                    "profile inventory readiness evidence changed during first-adoption resume"
                )
        else:
            cutover._publish_evidence(
                evidence_path, readiness, uid=expected_uid
            )
        cutover.record_evidence(
            state_path=state_path,
            evidence_kind="profile-inventory-readiness",
            evidence_path=evidence_path,
            authority_uid=expected_uid,
            evidence_uid=expected_uid,
        )
        return readiness
    if step == "project_isolation_ready":
        isolation = prepare_project_runtime_isolation(
            release=release,
            authority_database=Path(str(authority["database"])),
            audit_path=Path(
                str(candidate_request["project_isolation_audit"])
            ),
            ledger_path=Path(
                str(candidate_request["project_isolation_ledger"])
            ),
            expected_uid=expected_uid,
            runner=runner,
        )
        return require_complete_project_runtime_isolation(isolation)
    if step == "inventory_ready":
        _start_exact_units(runner, ("devcoordinator-observer.service",))
        return verify_nonempty_retained_inventory(
            release=release,
            database=Path(str(authority["inventory_database"])),
            publication=Path(str(authority["inventory_publication"])),
            observer_uid=int(authority["inventory_uid"]),
        )
    if step == "fleet_ready":
        export_path = Path(str(fleet["authority_export"]))
        observed_export = cutover.export_authority_test_repositories(
            Path(str(authority["database"])), authority_uid=expected_uid
        )
        if export_path.exists() or export_path.is_symlink():
            export = cutover.verify_seal(
                cutover.read_private_json(
                    export_path, uid=expected_uid
                ),
                kind=cutover.AUTHORITY_REPOSITORY_EXPORT_KIND,
                fields=cutover.AUTHORITY_REPOSITORY_EXPORT_FIELDS,
            )
            if any(
                export[field] != observed_export[field]
                for field in ("authority_generation", "repositories")
            ):
                raise ActivationError(
                    "fleet authority export changed during resume"
                )
        else:
            export = observed_export
            cutover._publish_evidence(export_path, export, uid=expected_uid)
        executable = release / "bin/devcoordinator-test-manifest-adoption"
        execution_uid = int(api["api_uid"])
        prefix = [
            str(executable), "--authority-database", str(authority["database"]),
            "--helper", str(fleet["helper"]), "--evidence-root", str(fleet["evidence_root"]),
            "--execution-uid", str(execution_uid),
        ]
        template = _first_adoption_manifest_template(
            cutover.read_private_json(
                Path(str(fleet["manifest_template"])),
                uid=expected_uid,
            )
        )
        if (
            template["document_sha256"]
            != fleet["manifest_template_sha256"]
        ):
            raise ActivationError(
                "fleet manifest template changed after request sealing"
            )
        _private_directory(
            Path(str(fleet["evidence_root"])),
            expected_uid=expected_uid,
        )
        fleet_journal_path = _fleet_transaction_path(fleet)
        binding = _fleet_transaction_binding(
            release=release,
            authority=authority,
            fleet=fleet,
            execution_uid=execution_uid,
        )
        fleet_journal = _load_private_journal(
            fleet_journal_path,
            kind=FIRST_ADOPTION_FLEET_JOURNAL_KIND,
            expected_uid=expected_uid,
        )
        if fleet_journal is not None and (
            fleet_journal.get("binding") != binding
            or fleet_journal.get("phase")
            not in {
                "planned",
                "apply_intent",
                "applied",
                "complete",
                "rolled_back",
            }
        ):
            raise ActivationError(
                "fleet transaction journal belongs to another adoption"
            )
        if fleet_journal is not None and fleet_journal["phase"] == "rolled_back":
            raise ActivationError(
                "fleet transaction was rolled back; use a fresh request"
            )
        if fleet_journal is not None and fleet_journal["phase"] == "complete":
            result = fleet_journal.get("result")
            if not isinstance(result, Mapping):
                raise ActivationError(
                    "completed fleet transaction lacks its result"
                )
            authority_repositories = export.get("repositories")
            if not isinstance(authority_repositories, list) or any(
                not isinstance(item, Mapping)
                for item in authority_repositories
            ):
                raise ActivationError(
                    "fleet authority export repository set is invalid"
                )
            replay = _first_adoption_fleet_setup_result(
                result.get("catalog"),
                authority_rows=[
                    item
                    for item in authority_repositories
                    if isinstance(item, Mapping)
                ],
            )
            if dict(result) != replay:
                raise ActivationError(
                    "completed fleet setup catalog changed during resume"
                )
            return replay
        if fleet_journal is not None:
            raise ActivationError(
                "an older fleet manifest mutation is incomplete; roll it back "
                "and use a fresh first-adoption request"
            )
        authority_repositories = export.get("repositories")
        if not isinstance(authority_repositories, list) or any(
            not isinstance(item, Mapping)
            for item in authority_repositories
        ):
            raise ActivationError(
                "fleet authority export repository set is invalid"
            )
        result = _first_adoption_fleet_setup_result(
            runner.run_json(
                [*prefix, "catalog", "--authority-export", str(export_path)]
            ),
            authority_rows=[
                item
                for item in authority_repositories
                if isinstance(item, Mapping)
            ],
        )
        _write_fleet_transaction(
            fleet_journal_path,
            {
                "binding": binding,
                "phase": "complete",
                "result": result,
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
        return result
    if step == "console_ready":
        adoption = steps.get("storage_split")
        if not isinstance(adoption, Mapping):
            raise ActivationError(
                "Console readiness lacks authority adoption evidence"
            )
        _verify_first_adoption_port_binding(
            request,
            state=cutover.load_state(
                state_path, authority_uid=expected_uid
            ),
            authority_database=Path(str(authority["database"])),
            expected_uid=expected_uid,
            adoption=adoption,
        )
        unit = f"devcoordinator-console@{release.name}.service"
        _start_exact_units(runner, (unit,))
        properties = _systemd_properties(runner, unit)
        if properties["ActiveState"] != "active":
            raise ActivationError("first-adoption Console backend is not ready")
        return {"unit": unit, "properties": properties}
    if step == "public_handoff":
        adoption = steps.get("storage_split")
        if not isinstance(adoption, Mapping):
            raise ActivationError(
                "public handoff lacks authority adoption evidence"
            )
        _verify_first_adoption_port_binding(
            request,
            state=cutover.load_state(
                state_path, authority_uid=expected_uid
            ),
            authority_database=Path(str(authority["database"])),
            expected_uid=expected_uid,
            adoption=adoption,
        )
        telegram_source = Path(str(background["telegram_source"]))

        def background_handoff(operation_id: str) -> Mapping[str, object]:
            if background["telegram_present"] is not True:
                return {"telegram_present": False}
            payload = _read_secret(
                telegram_source,
                label="legacy Telegram state",
                expected_uid=int(background["source_owner_uid"]),
                maximum=16 * MIB,
            )
            digest = "sha256:" + _sha256_bytes(payload)
            fence = {
                "schema_version": 1,
                "kind": "devcoordinator-notification-writer-fence",
                "deployment_id": operation_id,
                "captured_at": _now(),
                "legacy_writer_unit": "devops-console.service",
                "legacy_writer_inactive": True,
                "source_path": str(telegram_source),
                "source_sha256": digest,
            }
            _atomic_private(
                Path(str(background["telegram_fence"])),
                _canonical(fence) + b"\n",
                expected_uid=expected_uid,
            )
            helper = release / "bin/devcoordinator-background-handoff"
            copied = runner.run_json(
                [
                    str(helper), "copy-telegram-state", "--source", str(telegram_source),
                    "--destination", str(background["telegram_destination"]),
                    "--rollback", str(background["telegram_rollback"]),
                    "--fence-attestation", str(background["telegram_fence"]),
                    "--legacy-writer-unit", "devops-console.service",
                    "--expected-source-sha256", digest,
                    "--source-owner-uid", str(background["source_owner_uid"]),
                    "--destination-owner-uid", str(background["destination_owner_uid"]),
                    "--destination-owner-gid", str(background["destination_owner_gid"]),
                ]
            )
            return copied

        return first_adoption_handoff(
            release=release,
            rendered_units=Path(
                str(cutover.load_state(state_path, authority_uid=expected_uid)["rendered_units"])
            ),
            publication_file=Path(str(public["publication"])),
            publication_input=Path(str(console["publication_input"])),
            journal_file=Path(str(public["handoff_journal"])),
            http_handoff_port=int(public["http_handoff_port"]),
            https_handoff_port=int(public["https_handoff_port"]),
            edge_uid=int(console["edge_uid"]),
            edge_gid=int(console["edge_gid"]),
            expected_uid=expected_uid,
            runner=runner,
            after_legacy_console_stopped=background_handoff,
        )
    if step == "candidate_recorded":
        current = cutover.load_state(state_path, authority_uid=expected_uid)
        path = Path(str(candidate_request["candidate_evidence"]))
        recorded_candidate = current.get("evidence", {}).get("candidate")
        if isinstance(recorded_candidate, Mapping):
            if path.exists() or path.is_symlink():
                if cutover.read_private_json(path, uid=expected_uid) != recorded_candidate:
                    raise ActivationError(
                        "first-adoption candidate output contradicts the ledger"
                    )
            else:
                cutover._publish_evidence(path, recorded_candidate, uid=expected_uid)
            cutover.record_evidence(
                state_path=state_path,
                evidence_kind="candidate",
                evidence_path=path,
                authority_uid=expected_uid,
                evidence_uid=expected_uid,
            )
            return recorded_candidate
        if path.exists() or path.is_symlink():
            candidate = cutover.read_private_json(path, uid=expected_uid)
            cutover.transition(current, evidence_kind="candidate", evidence=candidate)
            cutover.record_evidence(
                state_path=state_path,
                evidence_kind="candidate",
                evidence_path=path,
                authority_uid=expected_uid,
                evidence_uid=expected_uid,
            )
            return candidate
        graph = steps.get("graph_prepared")
        project_isolation = steps.get("project_isolation_ready")
        if not isinstance(graph, Mapping) or not isinstance(
            project_isolation, Mapping
        ):
            raise ActivationError("first-adoption graph evidence is absent")
        units = sorted(cutover._candidate_units(release.name))
        ready_units: dict[str, bool] = {}
        service_uids: dict[str, int] = {}
        service_slices: dict[str, str] = {}
        for unit in units:
            properties = _systemd_properties(runner, unit)
            ready_units[unit] = properties["ActiveState"] == "active"
            service_uids[unit] = int(properties["UID"])
            service_slices[unit] = properties["Slice"]
        if not all(ready_units.values()):
            raise ActivationError("first-adoption final graph is not fully ready")
        sockets = socket_inodes()
        preparation = cutover.seal(
            cutover.CANDIDATE_PREPARATION_KIND,
            {
                **{
                    key: graph[key]
                    for key in (
                        "release_digest", "executor_release",
                        "credential_preflight_sha256", "host_preflight_sha256",
                        "background_config", "prior_units",
                        "prior_files", "installed_files", "created_at",
                    )
                },
                "project_isolation": project_isolation,
                "ready_units": ready_units,
                "socket_inodes": sockets,
            },
        )
        candidate = cutover.seal(
            cutover.CANDIDATE_KIND,
            {
                "release_digest": release.name,
                "ready_units": ready_units,
                "service_uids": service_uids,
                "service_slices": service_slices,
                "socket_inodes": sockets,
                "authority_database": current["authority_database"],
                "test_database": current["test_database"],
                "migration_seal_sha256": cutover._test_store_cutover_completion(
                    current
                )["document_sha256"],
                "checks_passed": True,
                "preparation": preparation,
                "created_at": _now(),
            },
        )
        cutover.transition(current, evidence_kind="candidate", evidence=candidate)
        cutover._publish_evidence(path, candidate, uid=expected_uid)
        cutover.record_evidence(
            state_path=state_path,
            evidence_kind="candidate",
            evidence_path=path,
            authority_uid=expected_uid,
            evidence_uid=expected_uid,
        )
        return candidate
    if step == "activation_recorded":
        current = cutover.load_state(state_path, authority_uid=expected_uid)
        path = Path(str(candidate_request["activation_evidence"]))
        recorded_activation = current.get("evidence", {}).get("activation")
        if isinstance(recorded_activation, Mapping):
            if path.exists() or path.is_symlink():
                if cutover.read_private_json(path, uid=expected_uid) != recorded_activation:
                    raise ActivationError(
                        "first-adoption activation output contradicts the ledger"
                    )
            else:
                cutover._publish_evidence(path, recorded_activation, uid=expected_uid)
            cutover.record_evidence(
                state_path=state_path,
                evidence_kind="activation",
                evidence_path=path,
                authority_uid=expected_uid,
                evidence_uid=expected_uid,
            )
            return recorded_activation
        if path.exists() or path.is_symlink():
            activation = cutover.read_private_json(path, uid=expected_uid)
            cutover.transition(current, evidence_kind="activation", evidence=activation)
            cutover.record_evidence(
                state_path=state_path,
                evidence_kind="activation",
                evidence_path=path,
                authority_uid=expected_uid,
                evidence_uid=expected_uid,
            )
            return activation
        candidate = current["evidence"]["candidate"]
        handoff = steps.get("public_handoff")
        if (
            not isinstance(handoff, Mapping)
            or handoff.get("phase") != "complete"
        ):
            raise ActivationError("public handoff evidence is absent")
        try:
            continuity = cutover._continuity_probe(
                handoff.get("continuity_probe"),
                expected_release=release.name,
            )
        except cutover.CutoverError as error:
            raise ActivationError(
                "public handoff continuity evidence is invalid"
            ) from error
        route = verify_nonempty_retained_routes(Path(str(public["publication"])))
        publication = _load_publication(Path(str(public["publication"])))
        public_payload = publication["publication"]
        if not isinstance(public_payload, Mapping):
            raise ActivationError("first-adoption publication payload is invalid")
        sockets = socket_inodes()
        pending = cutover.seal(
            ACTIVATION_READY_FOR_BROWSER_KIND,
            {
                "release_digest": release.name,
                "migration_seal_sha256": candidate["migration_seal_sha256"],
                "profile_inventory_readiness_sha256": current["evidence"][
                    "profile-inventory-readiness"
                ]["document_sha256"],
                "executor_release": str(release),
                "credential_preflight_sha256": candidate["preparation"]["credential_preflight_sha256"],
                "publication_switch": {
                    "mode": "first-adoption-bootstrap",
                    "previous_generation": 0,
                    "generation": public_payload["generation"],
                    "previous_payload_sha256": None,
                    "payload_sha256": publication["payload_sha256"],
                    "previous_release_digest": None,
                    "release_digest": release.name,
                    "previous_port": None,
                    "port": int(console["console_port"]),
                    "retained_routes_sha256": route["document_sha256"],
                    "handoff_journal_sha256": handoff["document_sha256"],
                },
                "continuity_probe": continuity,
                "socket_inodes_before": candidate["socket_inodes"],
                "socket_inodes_after": sockets,
                "connection_refused_count": continuity[
                    "connection_refused_count"
                ],
                "project_route_failures": continuity[
                    "project_route_failures"
                ],
                "legacy_units_active": [],
                "authority_ready": True,
                "testd_ready": True,
                "console_ready": True,
                "created_at": _now(),
            },
        )
        pending_path = path.with_name(f".{path.name}.browser-pending.json")
        if pending_path.exists() or pending_path.is_symlink():
            recorded_pending = cutover.verify_seal(
                cutover.read_private_json(pending_path, uid=expected_uid),
                kind=ACTIVATION_READY_FOR_BROWSER_KIND,
                fields=ACTIVATION_READY_FOR_BROWSER_FIELDS,
            )
            if any(
                recorded_pending[field] != pending[field]
                for field in ACTIVATION_READY_FOR_BROWSER_FIELDS
                if field != "created_at"
            ):
                raise ActivationError(
                    "first-adoption browser-pending activation changed"
                )
            pending = recorded_pending
        else:
            cutover._publish_evidence(pending_path, pending, uid=expected_uid)
        browser = request.get("browser")
        if not isinstance(browser, Mapping):
            raise BrowserAcceptancePending(
                "first-adoption browser acceptance inputs are absent; the healthy publication remains live"
            )
        try:
            binding = bind_browser_lcp_acceptance(
                release=release,
                operation_id=str(current["cutover_id"]),
                publication_switch=pending["publication_switch"],
                runtime_lock=Path(str(browser["runtime_lock"])),
                storage_state=Path(str(browser["storage_state"])),
                signing_key=Path(str(browser["signing_key"])),
                journal=Path(str(browser["journal"])),
                attestation=Path(str(browser["attestation"])),
                consumption=Path(str(browser["consumption"])),
                expected_uid=expected_uid,
            )
        except BrowserAcceptancePending:
            raise
        except BaseException as error:
            raise BrowserAcceptancePending(
                "browser acceptance is incomplete; the healthy first-adoption publication remains live"
            ) from error
        activation = finalize_browser_bound_activation(
            state=current,
            pending_activation=pending,
            browser_binding=binding,
        )
        cutover._publish_evidence(path, activation, uid=expected_uid)
        cutover.record_evidence(
            state_path=state_path,
            evidence_kind="activation",
            evidence_path=path,
            authority_uid=expected_uid,
            evidence_uid=expected_uid,
        )
        return activation
    if step == "legacy_writer_committed":
        retired = steps.get("legacy_writer_retired")
        activation_result = steps.get("activation_recorded")
        if not isinstance(retired, Mapping) or not isinstance(
            activation_result, Mapping
        ):
            raise ActivationError(
                "legacy-writer commit requires retirement and activation evidence"
            )
        return _legacy_writer_handoff(
            action="handoff-complete",
            release=release,
            legacy_writer=legacy_writer,
            outer_transaction_id=str(journal["transaction_id"]),
            expected_journal_sha256=str(retired["document_sha256"]),
            expected_uid=expected_uid,
            runner=runner,
        )
    if step == "complete":
        adoption = steps.get("storage_split")
        released = steps.get("maintenance_released")
        legacy_writer_committed = steps.get("legacy_writer_committed")
        if (
            not isinstance(adoption, Mapping)
            or not isinstance(released, Mapping)
            or released.get("released") is not True
            or not isinstance(legacy_writer_committed, Mapping)
        ):
            raise ActivationError("authority adoption evidence is absent")
        notification_units: dict[str, bool] = {}
        if background["telegram_present"] is True:
            notification_units = _start_exact_units(
                runner, ("devcoordinator-notifications.service",)
            )
        _scope, _message, _activate, _clear, load = _maintenance_api(
            release
        )
        if load(
            expected_uid=expected_uid,
            expected_gid=int(authority["maintenance_gid"]),
            maintenance_root=CANONICAL_MAINTENANCE_ROOT,
        ) is not None:
            raise ActivationError(
                "authority maintenance unexpectedly remained active"
            )
        port_evidence = _verify_first_adoption_port_binding(
            request,
            state=cutover.load_state(
                state_path, authority_uid=expected_uid
            ),
            authority_database=Path(str(authority["database"])),
            expected_uid=expected_uid,
            adoption=adoption,
        )
        return {
            "maintenance_cleared": True,
            "notification_units": notification_units,
            "storage_split_sha256": adoption["storage_split"]["document_sha256"],
            "port_reservations_sha256": port_evidence["bundle"][
                "document_sha256"
            ],
            "port_reservation_rows": port_evidence["rows"],
            "legacy_writer_handoff_sha256": legacy_writer_committed[
                "document_sha256"
            ],
        }
    raise ActivationError(f"unknown first-adoption transaction step: {step}")


def _rollback_first_adoption_cutover_state(
    *,
    state_path: Path,
    candidate_request: Mapping[str, object],
    api_request: Mapping[str, object],
    live_steps: Mapping[str, object],
    expected_uid: int,
) -> Mapping[str, object]:
    """Remove only state evidence whose output paths were unused at validation."""

    bindings = (
        (
            "activation",
            "activation_recorded",
            Path(str(candidate_request["activation_evidence"])),
        ),
        (
            "candidate",
            "candidate_recorded",
            Path(str(candidate_request["candidate_evidence"])),
        ),
        (
            "profile-inventory-readiness",
            "profile_inventory_ready",
            Path(str(api_request["inventory_readiness_evidence"])),
        ),
    )
    state = cutover.load_state(state_path, authority_uid=expected_uid)
    indexed = dict(state["evidence"])
    owned_files: list[
        tuple[str, Path, Mapping[str, object]]
    ] = []
    for evidence_kind, step_name, path in bindings:
        step_evidence = live_steps.get(step_name)
        recorded = indexed.get(evidence_kind)
        file_evidence: Mapping[str, object] | None = None
        if path.exists() or path.is_symlink():
            file_evidence = cutover._normalize_replay(
                evidence_kind,
                cutover.read_private_json(path, uid=expected_uid),
            )
            owned_files.append(
                (evidence_kind, path, file_evidence)
            )
        if isinstance(step_evidence, Mapping):
            normalized_step = cutover._normalize_replay(
                evidence_kind, step_evidence
            )
            if file_evidence is not None and file_evidence != normalized_step:
                raise ActivationError(
                    f"{evidence_kind} rollback output changed"
                )
        if isinstance(recorded, Mapping):
            normalized_recorded = cutover._normalize_replay(
                evidence_kind, recorded
            )
            if (
                file_evidence is None
                or file_evidence != normalized_recorded
            ):
                raise ActivationError(
                    f"{evidence_kind} rollback evidence is incomplete"
                )
            indexed.pop(evidence_kind)
    removed_state = sorted(
        set(state["evidence"]) - set(indexed)  # type: ignore[arg-type]
    )
    if removed_state:
        unsigned = {
            key: item
            for key, item in state.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        unsigned.update(
            {
                "phase": "sealed",
                "evidence": indexed,
                "updated_at": _now(),
                "state_generation": int(state["state_generation"]) + 1,
            }
        )
        rewound = cutover.seal(cutover.STATE_KIND, unsigned)
        cutover.validate_state(rewound)
        cutover._write_private_json(
            state_path,
            rewound,
            uid=expected_uid,
            create=False,
            expected_generation=int(state["state_generation"]),
        )
    removed_files: list[str] = []
    parents: set[Path] = set()
    for evidence_kind, path, evidence in owned_files:
        current = cutover._normalize_replay(
            evidence_kind,
            cutover.read_private_json(path, uid=expected_uid),
        )
        if current != evidence:
            raise ActivationError("first-adoption state output changed")
        path.unlink()
        removed_files.append(str(path))
        parents.add(path.parent)
    for parent in parents:
        descriptor = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {
        "state_evidence_removed": removed_state,
        "files_removed": sorted(removed_files),
    }


def _rollback_first_adoption_fleet(
    *,
    release: Path,
    authority_database: Path,
    fleet_request: Mapping[str, object],
    fleet_evidence: Mapping[str, object],
    runner: CommandRunner,
    execution_uid: int,
) -> Mapping[str, object]:
    planned = fleet_evidence.get("plan")
    applied = fleet_evidence.get("apply")
    if not isinstance(planned, Mapping) or not isinstance(applied, Mapping):
        raise ActivationError("fleet rollback apply evidence is invalid")
    result_sha256 = applied.get("result_sha256")
    if (
        applied.get("ok") is not True
        or applied.get("state") != "applied"
        or applied.get("plan_id") != planned.get("plan_id")
        or applied.get("plan_sha256") != planned.get("plan_sha256")
        or planned.get("ok") is not True
        or not isinstance(planned.get("plan_id"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}", str(planned.get("plan_sha256"))
        )
        is None
        or not isinstance(result_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", result_sha256) is None
    ):
        raise ActivationError("fleet rollback binding is invalid")
    result = runner.run_json(
        [
            str(release / "bin/devcoordinator-test-manifest-adoption"),
            "--authority-database",
            str(authority_database),
            "--helper",
            str(fleet_request["helper"]),
            "--evidence-root",
            str(fleet_request["evidence_root"]),
            "--execution-uid",
            str(execution_uid),
            "rollback",
            "--plan-id",
            str(planned["plan_id"]),
            "--result-sha256",
            result_sha256,
        ]
    )
    if (
        result.get("ok") is not True
        or result.get("state") != "rolled_back"
        or result.get("plan_id") != planned.get("plan_id")
        or result.get("apply_result_sha256") != result_sha256
    ):
        raise ActivationError("fleet rollback did not restore the exact plan")
    return result



def _rollback_first_adoption_fleet_transaction(
    *,
    release: Path,
    authority: Mapping[str, object],
    fleet_request: Mapping[str, object],
    fleet_evidence: object,
    expected_uid: int,
    runner: CommandRunner,
    execution_uid: int,
) -> Mapping[str, object]:
    journal_path = _fleet_transaction_path(fleet_request)
    journal = _load_private_journal(
        journal_path,
        kind=FIRST_ADOPTION_FLEET_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    manifest_result: Mapping[str, object]
    if journal is None:
        if isinstance(fleet_evidence, Mapping):
            raise ActivationError(
                "fleet rollback lacks its durable subtransaction journal"
            )
        manifest_result = {"skipped": True}
    else:
        binding = _fleet_transaction_binding(
            release=release,
            authority=authority,
            fleet=fleet_request,
            execution_uid=execution_uid,
        )
        if (
            journal.get("binding") != binding
            or journal.get("phase")
            not in {
                "planned",
                "apply_intent",
                "applied",
                "complete",
                "rolled_back",
            }
        ):
            raise ActivationError("fleet rollback journal is contradictory")
        if journal["phase"] == "rolled_back":
            result = journal.get("rollback")
            if not isinstance(result, Mapping):
                raise ActivationError(
                    "rolled-back fleet journal lacks its result"
                )
            manifest_result = dict(result)
        elif (
            journal["phase"] == "complete"
            and isinstance(journal.get("result"), Mapping)
            and journal["result"].get("mode")
            == FIRST_ADOPTION_FLEET_SETUP_CATALOG_MODE
        ):
            result = dict(journal["result"])
            if isinstance(fleet_evidence, Mapping) and dict(
                fleet_evidence
            ) != result:
                raise ActivationError(
                    "outer fleet setup evidence contradicts its journal"
                )
            manifest_result = {
                "skipped": True,
                "mode": FIRST_ADOPTION_FLEET_SETUP_CATALOG_MODE,
                "reason": (
                    "first availability only cataloged repository Setup state"
                ),
            }
        else:

            def persist(phase: str, **updates: object) -> None:
                nonlocal journal
                if journal is None:
                    raise ActivationError("fleet rollback journal disappeared")
                payload = {
                    key: value
                    for key, value in journal.items()
                    if key not in {"schema_version", "kind", "document_sha256"}
                }
                payload.update(updates)
                payload.update({"phase": phase, "updated_at": _now()})
                journal = _write_fleet_transaction(
                    journal_path, payload, expected_uid=expected_uid
                )

            planned = _validate_first_adoption_fleet_plan(
                journal.get("plan")
            )
            if journal["phase"] == "planned":
                manifest_result = {
                    "skipped": True,
                    "plan_id": planned["plan_id"],
                    "reason": "apply intent was not published",
                }
                persist("rolled_back", rollback=manifest_result)
            else:
                if journal["phase"] == "apply_intent":
                    prefix = [
                        str(
                            release
                            / "bin/devcoordinator-test-manifest-adoption"
                        ),
                        "--authority-database",
                        str(authority["database"]),
                        "--helper",
                        str(fleet_request["helper"]),
                        "--evidence-root",
                        str(fleet_request["evidence_root"]),
                        "--execution-uid",
                        str(execution_uid),
                    ]
                    applied = _validate_first_adoption_fleet_apply(
                        runner.run_json(
                            [
                                *prefix,
                                "apply",
                                "--plan-id",
                                str(planned["plan_id"]),
                                "--plan-sha256",
                                str(planned["plan_sha256"]),
                            ]
                        ),
                        planned=planned,
                    )
                    persist("applied", apply=applied)
                else:
                    applied = _validate_first_adoption_fleet_apply(
                        journal.get("apply"), planned=planned
                    )
                if isinstance(fleet_evidence, Mapping) and (
                    fleet_evidence.get("plan") != planned
                    or fleet_evidence.get("apply") != applied
                ):
                    raise ActivationError(
                        "outer fleet evidence contradicts its subtransaction"
                    )
                recovered = {"plan": planned, "apply": applied}
                manifest_result = _rollback_first_adoption_fleet(
                    release=release,
                    authority_database=Path(str(authority["database"])),
                    fleet_request=fleet_request,
                    fleet_evidence=recovered,
                    runner=runner,
                    execution_uid=execution_uid,
                )
                persist("rolled_back", rollback=dict(manifest_result))
    return dict(manifest_result)


def _rollback_console_state_migration(
    evidence: Mapping[str, object],
    *,
    runner: CommandRunner,
    expected_uid: int,
) -> None:
    verified = cutover.verify_seal(
        evidence,
        kind=CONSOLE_STATE_MIGRATION_KIND,
        fields={
            "release_digest",
            "legacy_state",
            "sources",
            "installed",
            "prior_files",
            "console_validation",
            "identity_validation",
            "resolution_sha256",
            "publication_input",
            "created_at",
        },
    )
    prior_files = verified.get("prior_files")
    if not isinstance(prior_files, Mapping):
        raise ActivationError("Console state rollback file evidence is invalid")
    _restore_prepared_graph(
        {"prior_units": {}, "prior_files": prior_files},
        runner=runner,
        expected_uid=expected_uid,
    )


def _rollback_notification_state_handoff(
    journal: Mapping[str, object],
    *,
    background: Mapping[str, object],
    runner: CommandRunner,
    expected_uid: int,
) -> Mapping[str, object]:
    if runner.status(
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "devcoordinator-notifications.service",
        ]
    ) != 0:
        raise ActivationError("notification writer could not stop for rollback")
    handoff = journal.get("legacy_stop_handoff")
    if handoff is None or handoff == {"telegram_present": False}:
        return {"telegram_present": False, "removed": []}
    if (
        not isinstance(handoff, Mapping)
        or set(handoff)
        != {
            "ok",
            "kind",
            "deployment_id",
            "source_sha256",
            "destination",
            "rollback",
            "legacy_writer_fenced",
        }
        or handoff.get("ok") is not True
        or handoff.get("kind") != "devcoordinator-notification-state-handoff"
        or handoff.get("legacy_writer_fenced") is not True
        or handoff.get("deployment_id") != journal.get("operation_id")
        or handoff.get("destination") != background.get("telegram_destination")
        or handoff.get("rollback") != background.get("telegram_rollback")
    ):
        raise ActivationError("notification rollback evidence is contradictory")
    digest = handoff.get("source_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ActivationError("notification rollback digest is invalid")
    candidates = (
        (
            Path(str(background["telegram_destination"])),
            int(background["destination_owner_uid"]),
            0o600,
            "notification destination",
        ),
        (
            Path(str(background["telegram_rollback"])),
            expected_uid,
            0o400,
            "notification rollback copy",
        ),
    )
    present: list[Path] = []
    for path, owner_uid, expected_mode, label in candidates:
        if not (path.exists() or path.is_symlink()):
            continue
        payload = _read_secret(
            path,
            label=label,
            expected_uid=owner_uid,
            maximum=16 * MIB,
        )
        if "sha256:" + _sha256_bytes(payload) != digest:
            raise ActivationError(f"{label} changed before rollback")
        if stat.S_IMODE(path.lstat().st_mode) != expected_mode:
            raise ActivationError(f"{label} mode changed before rollback")
        present.append(path)
    fence_path = Path(str(background["telegram_fence"]))
    if fence_path.exists() or fence_path.is_symlink():
        raw = _read_secret(
            fence_path,
            label="notification writer fence",
            expected_uid=expected_uid,
            maximum=MAX_JSON_BYTES,
        )
        try:
            fence = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivationError("notification writer fence is invalid") from error
        if (
            not isinstance(fence, Mapping)
            or fence.get("deployment_id") != journal.get("operation_id")
            or fence.get("source_sha256") != digest
            or fence.get("source_path") != background.get("telegram_source")
            or fence.get("legacy_writer_inactive") is not True
        ):
            raise ActivationError("notification writer fence changed before rollback")
        if stat.S_IMODE(fence_path.lstat().st_mode) != 0o600:
            raise ActivationError("notification writer fence mode changed before rollback")
        present.append(fence_path)
    removed: list[str] = []
    parents: set[Path] = set()
    for path in present:
        path.unlink()
        removed.append(str(path))
        parents.add(path.parent)
    for parent in parents:
        descriptor = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return {"telegram_present": True, "removed": sorted(removed)}


def _publish_first_adoption_attestation(
    *,
    current: Mapping[str, object],
    request_sha256: str,
    attestation: Path,
    expected_uid: int,
) -> Mapping[str, object]:
    if current.get("phase") != "complete" or not isinstance(
        current.get("steps"), Mapping
    ):
        raise ActivationError("first-adoption attestation requires a complete journal")
    result = cutover.seal(
        FIRST_ADOPTION_ATTESTATION_KIND,
        {
            "transaction_id": current["transaction_id"],
            "request_sha256": request_sha256,
            "journal_sha256": current["document_sha256"],
            "steps": current["steps"],
            "completed_at": current["updated_at"],
        },
    )
    if attestation.exists() or attestation.is_symlink():
        recorded = cutover.read_private_json(attestation, uid=expected_uid)
        if recorded != result:
            raise ActivationError(
                "first-adoption attestation contradicts the complete journal"
            )
    else:
        cutover._publish_evidence(attestation, result, uid=expected_uid)
    return result


def _publish_first_adoption_rollback(
    *,
    current: Mapping[str, object],
    rollback_evidence: Path,
    expected_uid: int,
) -> Mapping[str, object]:
    rollback = current.get("rollback")
    if current.get("phase") != "rolled_back" or not isinstance(
        rollback, Mapping
    ):
        raise ActivationError("first-adoption rollback journal is incomplete")
    verified = cutover.verify_seal(
        rollback,
        kind=FIRST_ADOPTION_ROLLBACK_RESULT_KIND,
        fields={
            "transaction_id",
            "request_sha256",
            "failed_phase",
            "error",
            "rollback_errors",
            "rolled_back_at",
        },
    )
    if verified.get("document_sha256") != current.get("rollback_sha256"):
        raise ActivationError("first-adoption rollback digest is contradictory")
    if rollback_evidence.exists() or rollback_evidence.is_symlink():
        recorded = cutover.read_private_json(rollback_evidence, uid=expected_uid)
        if recorded != verified:
            raise ActivationError(
                "first-adoption rollback evidence contradicts the journal"
            )
    else:
        cutover._publish_evidence(rollback_evidence, verified, uid=expected_uid)
    return verified


def _resume_profile_publication_for_rollback(
    *,
    publication: object,
    journal_path: Path,
    adoption: object,
    authority: Mapping[str, object],
    api: Mapping[str, object],
    candidate: Mapping[str, object],
    path_key: str,
    expected_uid: int,
) -> Mapping[str, object] | None:
    """Complete a journaled write so its captured prior profile can be restored."""

    if isinstance(publication, Mapping):
        return publication
    if not (journal_path.exists() or journal_path.is_symlink()):
        return None
    journal = _load_private_journal(
        journal_path,
        kind=PROFILE_PUBLICATION_JOURNAL_KIND,
        expected_uid=expected_uid,
    )
    if (
        isinstance(journal, Mapping)
        and journal.get("phase") == "rolled_back"
        and isinstance(journal.get("result"), Mapping)
    ):
        return dict(journal["result"])
    authority_identity = (
        adoption.get("authority")
        if isinstance(adoption, Mapping)
        else None
    )
    if (
        not isinstance(authority_identity, Mapping)
        or not isinstance(
            authority_identity.get("database_generation"), str
        )
    ):
        raise ActivationError(
            "profile rollback lacks sealed generation evidence"
        )
    return publish_first_adoption_profiles(
        authority_database=Path(str(authority["database"])),
        destination=Path(str(api[path_key])),
        validation_uid=int(api["api_uid"]),
        rollback_directory=Path(str(candidate["rollback_directory"])),
        journal_file=journal_path,
        expected_uid=expected_uid,
    )


def _resume_first_adoption_rollback(
    *,
    current: Mapping[str, object],
    checked: Mapping[str, object],
    journal_file: Path,
    rollback_evidence: Path,
    expected_uid: int,
    runner: CommandRunner,
    failure: Mapping[str, object] | None = None,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Durably resume the exact reverse graph, one mutation at a time."""

    working = dict(current)
    if working.get("phase") not in {"rolling_back", "rollback_incomplete"}:
        if failure is None:
            raise ActivationError("first-adoption rollback lacks failure evidence")
        payload = {
            key: value
            for key, value in working.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(
            {
                "phase": "rolling_back",
                "failure": dict(failure),
                "rollback_steps": {},
                "rollback_attempt_errors": [],
                "updated_at": _now(),
            }
        )
        working = _write_first_adoption_transaction(
            journal_file, payload, expected_uid=expected_uid
        )
    failure_value = working.get("failure")
    reverse_value = working.get("rollback_steps")
    attempt_errors_value = working.get("rollback_attempt_errors", [])
    live_steps = working.get("steps")
    if (
        not isinstance(failure_value, Mapping)
        or not isinstance(reverse_value, Mapping)
        or any(key not in FIRST_ADOPTION_ROLLBACK_STEPS for key in reverse_value)
        or not isinstance(attempt_errors_value, list)
        or not isinstance(live_steps, Mapping)
    ):
        raise ActivationError("first-adoption rollback journal is invalid")
    reverse = dict(reverse_value)
    attempt_errors = list(attempt_errors_value)

    def persist_reverse(phase: str, **updates: object) -> None:
        nonlocal working
        payload = {
            key: value
            for key, value in working.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload.update(updates)
        payload.update(
            {
                "phase": phase,
                "rollback_steps": dict(reverse),
                "rollback_attempt_errors": list(attempt_errors),
                "updated_at": _now(),
            }
        )
        working = _write_first_adoption_transaction(
            journal_file, payload, expected_uid=expected_uid
        )

    public = checked["public"]
    authority = checked["authority"]
    api = checked["api"]
    fleet = checked["fleet"]
    background = checked["background"]
    candidate = checked["candidate"]
    legacy_writer = checked["legacy_writer"]
    if not all(
        isinstance(value, Mapping)
        for value in (
            public,
            authority,
            api,
            fleet,
            background,
            candidate,
            legacy_writer,
        )
    ):
        raise ActivationError("first-adoption rollback request groups changed")
    release = Path(
        str(
            cutover.load_state(
                Path(str(checked["state"])), authority_uid=expected_uid
            )["release"]
        )
    )
    public_journal: Mapping[str, object] | None = None
    public_journal_path = Path(str(public["handoff_journal"]))
    if public_journal_path.exists() or public_journal_path.is_symlink():
        public_journal = _load_journal(
            public_journal_path, expected_uid=expected_uid
        )

    def reverse_step(step: str) -> Mapping[str, object]:
        if step == "maintenance":
            adoption = live_steps.get("storage_split")
            if not isinstance(adoption, Mapping):
                return {"skipped": True}
            return rearm_authority_maintenance_for_rollback(
                adoption,
                release=release,
                maintenance_gid=int(authority["maintenance_gid"]),
                operation_journal=Path(
                    str(authority["operation_journal"])
                ),
                expected_uid=expected_uid,
            )
        if step == "notifications":
            if (
                background.get("telegram_present") is not True
                or not isinstance(public_journal, Mapping)
                or public_journal.get("legacy_stop_handoff") is None
            ):
                return {"skipped": True}
            return _rollback_notification_state_handoff(
                public_journal,
                background=background,
                runner=runner,
                expected_uid=expected_uid,
            )
        if step == "fleet":
            fleet_evidence = live_steps.get("fleet_ready")
            return _rollback_first_adoption_fleet_transaction(
                release=release,
                authority=authority,
                fleet_request=fleet,
                fleet_evidence=fleet_evidence,
                expected_uid=expected_uid,
                runner=runner,
                execution_uid=int(api["api_uid"]),
            )
        if step == "public":
            if public_journal is None:
                return {"skipped": True}
            result = rollback_first_adoption_handoff(
                journal_file=public_journal_path,
                expected_uid=expected_uid,
                runner=runner,
            )
            return dict(result) if isinstance(result, Mapping) else {"ok": True}
        if step == "cutover_state":
            return _rollback_first_adoption_cutover_state(
                state_path=Path(str(checked["state"])),
                candidate_request=candidate,
                api_request=api,
                live_steps=live_steps,
                expected_uid=expected_uid,
            )
        if step == "api":
            api_journal = Path(str(api["journal"]))
            if not (api_journal.exists() or api_journal.is_symlink()):
                return {"skipped": True}
            return api_handoff_transaction(
                journal_file=api_journal,
                handoff_port=int(api["handoff_port"]),
                action="rollback",
                expected_uid=expected_uid,
                runner=runner,
            )
        if step == "profiles":
            restored: dict[str, object] = {}
            adoption = live_steps.get("storage_split")
            for name, path_key, journal_key in (
                (
                    "api_final_profile_ready",
                    "profile_path",
                    "final_profile_journal",
                ),
                (
                    "api_bootstrap_profile_ready",
                    "bootstrap_profile_path",
                    "bootstrap_profile_journal",
                ),
            ):
                journal_path = Path(str(api[journal_key]))
                publication = _resume_profile_publication_for_rollback(
                    publication=live_steps.get(name),
                    journal_path=journal_path,
                    adoption=adoption,
                    authority=authority,
                    api=api,
                    candidate=candidate,
                    path_key=path_key,
                    expected_uid=expected_uid,
                )
                if not isinstance(publication, Mapping):
                    continue
                restored[name] = _restore_first_adoption_profile(
                    publication,
                    journal_file=journal_path,
                    expected_uid=expected_uid,
                )
            return restored or {"skipped": True}
        if step == "graph":
            graph = live_steps.get("graph_prepared")
            if not isinstance(graph, Mapping):
                return {"skipped": True}
            _restore_prepared_graph(
                graph, runner=runner, expected_uid=expected_uid
            )
            return {"restored": True}
        if step == "legacy_writer":
            handoff = next(
                (
                    live_steps.get(name)
                    for name in (
                        "legacy_writer_committed",
                        "legacy_writer_retired",
                        "legacy_writer_guarded",
                    )
                    if isinstance(live_steps.get(name), Mapping)
                ),
                None,
            )
            if handoff is None:
                validated = live_steps.get("validated")
                handoff = (
                    validated.get("legacy_writer_reference")
                    if isinstance(validated, Mapping)
                    else None
                )
            if not isinstance(handoff, Mapping):
                return {"skipped": True}
            return _legacy_writer_handoff(
                action="handoff-rollback-prepare",
                release=release,
                legacy_writer=legacy_writer,
                outer_transaction_id=str(working["transaction_id"]),
                expected_journal_sha256=str(handoff["document_sha256"]),
                expected_uid=expected_uid,
                runner=runner,
            )
        if step == "console_state":
            migration = live_steps.get("console_state_migrated")
            if not isinstance(migration, Mapping):
                return {"skipped": True}
            _rollback_console_state_migration(
                migration, runner=runner, expected_uid=expected_uid
            )
            return {"restored": True}
        if step == "authority":
            adoption = live_steps.get("storage_split")
            if not isinstance(adoption, Mapping):
                return {"skipped": True}
            maintenance_result = reverse.get("maintenance")
            if (
                not isinstance(maintenance_result, Mapping)
                or maintenance_result.get("rearmed") is not True
            ):
                raise ActivationError(
                    "authority rollback requires the global maintenance fence"
                )
            graph_result = reverse.get("graph")
            if not isinstance(graph_result, Mapping) or (
                graph_result.get("restored") is not True
                and graph_result.get("skipped") is not True
            ):
                raise ActivationError(
                    "authority rollback requires the replacement graph stopped"
                )
            writer_result = reverse.get("legacy_writer")
            if not isinstance(writer_result, Mapping):
                raise ActivationError(
                    "authority rollback requires legacy-writer rearm evidence"
                )

            writer_unfenced: Mapping[str, object] | None = None

            def unfence_legacy_writer() -> Mapping[str, object]:
                nonlocal writer_unfenced
                writer_unfenced = _legacy_writer_handoff(
                    action="handoff-rollback-unfence",
                    release=release,
                    legacy_writer=legacy_writer,
                    outer_transaction_id=str(working["transaction_id"]),
                    expected_journal_sha256=str(
                        writer_result["document_sha256"]
                    ),
                    expected_uid=expected_uid,
                    runner=runner,
                )
                return writer_unfenced

            def verify_legacy_writer() -> Mapping[str, object]:
                if not isinstance(writer_unfenced, Mapping):
                    raise ActivationError(
                        "legacy-writer readiness requires its exact unfence evidence"
                    )
                return _legacy_writer_handoff(
                    action="handoff-verify-rearmed",
                    release=release,
                    legacy_writer=legacy_writer,
                    outer_transaction_id=str(working["transaction_id"]),
                    expected_journal_sha256=str(
                        writer_unfenced["document_sha256"]
                    ),
                    expected_uid=expected_uid,
                    runner=runner,
                )

            restored = rollback_authority_adoption(
                adoption,
                release=release,
                maintenance_gid=int(authority["maintenance_gid"]),
                expected_uid=expected_uid,
                runner=runner,
                operation_journal=Path(str(authority["operation_journal"])),
                failpoint=failpoint,
                legacy_writer_unfencer=unfence_legacy_writer,
                legacy_writer_verifier=verify_legacy_writer,
            )
            return dict(restored)
        raise ActivationError("unknown first-adoption rollback step")

    for step in FIRST_ADOPTION_ROLLBACK_STEPS:
        if step in reverse:
            continue
        try:
            result = reverse_step(step)
            if not isinstance(result, Mapping):
                raise ActivationError(
                    f"first-adoption rollback {step} returned invalid evidence"
                )
            if failpoint is not None:
                failpoint(f"first-adoption-rollback-before-journal:{step}")
            reverse[step] = dict(result)
            persist_reverse("rolling_back")
        except PowerLossSimulation:
            raise
        except BaseException as error:
            attempt_errors.append(f"{step}: {error}")
            persist_reverse("rollback_incomplete")
            raise ActivationError(
                f"first-adoption rollback is incomplete at {step}: {error}"
            ) from error
    rollback = cutover.seal(
        FIRST_ADOPTION_ROLLBACK_RESULT_KIND,
        {
            "transaction_id": working["transaction_id"],
            "request_sha256": working["request_sha256"],
            "failed_phase": failure_value.get("failed_phase"),
            "error": str(failure_value.get("error")),
            "rollback_errors": [],
            "rolled_back_at": _now(),
        },
    )
    persist_reverse(
        "rolled_back",
        rollback=rollback,
        rollback_sha256=rollback["document_sha256"],
    )
    _publish_first_adoption_rollback(
        current=working,
        rollback_evidence=rollback_evidence,
        expected_uid=expected_uid,
    )
    return working


def execute_first_adoption_transaction(
    *,
    request: Mapping[str, object],
    journal_file: Path,
    attestation: Path,
    rollback_evidence: Path,
    expected_uid: int = 0,
    runner: CommandRunner | None = None,
    step_handler: Callable[..., Mapping[str, object]] | None = None,
    rollback_failpoint: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Run or resume the whole first adoption from one root-private journal."""

    if os.geteuid() != expected_uid:
        raise ActivationError("first-adoption transaction must run as the authority UID")
    checked = _first_adoption_request(request)
    journal_file = _absolute(journal_file, "first-adoption transaction journal")
    request_sha = str(checked["document_sha256"])
    current = _load_first_adoption_transaction(
        journal_file, expected_uid=expected_uid
    )
    if current is None:
        current = _write_first_adoption_transaction(
            journal_file,
            {
                "transaction_id": str(uuid.uuid4()),
                "request_sha256": request_sha,
                "phase": "planned",
                "steps": {},
                "created_at": _now(),
                "updated_at": _now(),
            },
            expected_uid=expected_uid,
        )
    if current.get("request_sha256") != request_sha:
        raise ActivationError("first-adoption journal belongs to another request")
    if current.get("phase") == "complete":
        _publish_first_adoption_attestation(
            current=current,
            request_sha256=request_sha,
            attestation=attestation,
            expected_uid=expected_uid,
        )
        return current
    if current.get("phase") == "rolled_back":
        _publish_first_adoption_rollback(
            current=current,
            rollback_evidence=rollback_evidence,
            expected_uid=expected_uid,
        )
        raise ActivationError(
            "first-adoption transaction was rolled back; build a fresh sealed "
            "request with new transaction-owned journal and evidence paths"
        )
    steps = current.get("steps")
    if not isinstance(steps, Mapping) or any(key not in FIRST_ADOPTION_STEPS for key in steps):
        raise ActivationError("first-adoption transaction step journal is invalid")
    command = runner or CommandRunner()
    handler = step_handler or _first_adoption_live_step
    if current.get("phase") in {"rolling_back", "rollback_incomplete"}:
        resumed = _resume_first_adoption_rollback(
            current=current,
            checked=checked,
            journal_file=journal_file,
            rollback_evidence=rollback_evidence,
            expected_uid=expected_uid,
            runner=command,
            failpoint=rollback_failpoint,
        )
        raise ActivationError(
            "first-adoption transaction resumed and completed its rollback; "
            f"journal={resumed['document_sha256']}"
        )

    def advance(step: str, result: Mapping[str, object]) -> None:
        nonlocal current
        old_steps = current.get("steps")
        if not isinstance(old_steps, Mapping):
            raise ActivationError("first-adoption transaction steps changed")
        payload = {
            key: value
            for key, value in current.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["steps"] = {**dict(old_steps), step: dict(result)}
        payload["phase"] = step
        payload["updated_at"] = _now()
        current = _write_first_adoption_transaction(
            journal_file, payload, expected_uid=expected_uid
        )

    try:
        for step in FIRST_ADOPTION_STEPS:
            if step in current["steps"]:
                continue
            result = handler(
                step,
                request=checked,
                journal=current,
                expected_uid=expected_uid,
                runner=command,
            )
            if not isinstance(result, Mapping):
                raise ActivationError(f"first-adoption {step} returned invalid evidence")
            advance(step, result)
        _publish_first_adoption_attestation(
            current=current,
            request_sha256=request_sha,
            attestation=attestation,
            expected_uid=expected_uid,
        )
        return current
    except PowerLossSimulation:
        raise
    except BrowserAcceptancePending:
        # Browser acceptance is a completion/retention gate, not a reason to
        # reverse a healthy public handoff or disrupt project traffic.
        raise
    except BaseException as error:
        try:
            _resume_first_adoption_rollback(
                current=current,
                checked=checked,
                journal_file=journal_file,
                rollback_evidence=rollback_evidence,
                expected_uid=expected_uid,
                runner=command,
                failure={
                    "failed_phase": current.get("phase"),
                    "error": str(error),
                },
                failpoint=rollback_failpoint,
            )
        except PowerLossSimulation:
            raise
        except BaseException as rollback_error:
            raise ActivationError(
                "first-adoption transaction failed and rollback is incomplete: "
                f"{error}; {rollback_error}"
            ) from error
        raise ActivationError(
            f"first-adoption transaction failed and was rolled back: {error}"
        ) from error


def _completed_binding_attestation(
    path: Path,
    *,
    operation_id: str,
    release_digest: str,
    expected_uid: int,
) -> dict[str, object]:
    path = _absolute(path, "first-adoption binding attestation")
    try:
        operation_id = str(uuid.UUID(operation_id))
    except (ValueError, TypeError, AttributeError) as error:
        raise ActivationError(
            "first-adoption installer operation identity is invalid"
        ) from error
    result = cutover._atomic_first_adoption_binding_result(
        cutover.read_private_json(path, uid=expected_uid)
    )
    if (
        result["operation_id"] != operation_id
        or result["outcome"] != "completed"
        or result["release_digest"] != release_digest
        or result["service_unit"] != LEGACY_BROKER_SERVICE_UNIT
        or result["service_restored"] is not True
        or result["maintenance_cleared"] is not True
    ):
        raise ActivationError(
            "first-adoption binding attestation is not the exact completed predecessor"
        )
    return result


def _completed_first_adoption_attestation(
    path: Path,
    *,
    release: Path,
    expected_uid: int,
) -> dict[str, object]:
    document = cutover.verify_seal(
        cutover.read_private_json(
            _absolute(path, "first-adoption completion attestation"),
            uid=expected_uid,
        ),
        kind=FIRST_ADOPTION_ATTESTATION_KIND,
        fields={
            "transaction_id",
            "request_sha256",
            "journal_sha256",
            "steps",
            "completed_at",
        },
    )
    steps = document.get("steps")
    activation = (
        steps.get("activation_recorded") if isinstance(steps, Mapping) else None
    )
    complete = steps.get("complete") if isinstance(steps, Mapping) else None
    legacy = (
        steps.get("legacy_writer_committed")
        if isinstance(steps, Mapping)
        else None
    )
    if (
        not isinstance(steps, Mapping)
        or set(steps) != set(FIRST_ADOPTION_STEPS)
        or any(not isinstance(value, Mapping) for value in steps.values())
        or not isinstance(activation, Mapping)
        or activation.get("release_digest") != release.name
        or activation.get("executor_release") != str(release)
        or activation.get("authority_ready") is not True
        or activation.get("testd_ready") is not True
        or activation.get("console_ready") is not True
        or activation.get("connection_refused_count") != 0
        or activation.get("project_route_failures") != 0
        or not isinstance(complete, Mapping)
        or complete.get("maintenance_cleared") is not True
        or not isinstance(legacy, Mapping)
        or not isinstance(legacy.get("document_sha256"), str)
    ):
        raise ActivationError(
            "first-adoption completion attestation does not prove the final release"
        )
    return document


def _credential_paths(arguments: argparse.Namespace) -> dict[str, Path]:
    return {
        name: Path(
            getattr(arguments, name.replace("-", "_"), str(default))
        )
        for name, default in DEFAULT_CREDENTIALS.items()
    }


def _add_credentials(parser: argparse.ArgumentParser) -> None:
    for name, path in DEFAULT_CREDENTIALS.items():
        parser.add_argument(f"--{name}", default=str(path))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)

    migrate = actions.add_parser("migrate-credentials")
    migrate.add_argument("--legacy-env", required=True)
    migrate.add_argument("--rollback-directory", required=True)
    migrate.add_argument("--attestation", required=True)
    migrate.add_argument("--expected-uid", type=int, default=0)
    migrate.add_argument("--legacy-source-uid", type=int, required=True)
    _add_credentials(migrate)

    preflight = actions.add_parser("preflight-credentials")
    preflight.add_argument("--release-digest", required=True)
    preflight.add_argument("--attestation", required=True)
    preflight.add_argument("--expected-uid", type=int, default=0)
    _add_credentials(preflight)

    first_adoption = actions.add_parser("first-adoption-preflight")
    first_adoption.add_argument("--rendered-units", required=True)
    first_adoption.add_argument("--publication", required=True)
    first_adoption.add_argument("--http-handoff-port", type=int, required=True)
    first_adoption.add_argument("--https-handoff-port", type=int, required=True)
    first_adoption.add_argument("--attestation", required=True)
    first_adoption.add_argument("--expected-uid", type=int, default=0)

    manifest_template = actions.add_parser(
        "build-first-adoption-manifest-template"
    )
    manifest_template.add_argument("--input", required=True)
    manifest_template.add_argument("--output", required=True)
    manifest_template.add_argument("--expected-uid", type=int, default=0)

    request_builder = actions.add_parser("build-first-adoption-request")
    for name in ("state", "output"):
        request_builder.add_argument(f"--{name}", required=True)
    for name in ("repair-plan", "repair-result"):
        request_builder.add_argument(f"--{name}")
    for fields in _FIRST_ADOPTION_ARGUMENTS.values():
        for argument_name in fields.values():
            option = "--" + argument_name.replace("_", "-")
            if argument_name == "telegram_present":
                request_builder.add_argument(
                    option,
                    action=argparse.BooleanOptionalAction,
                    required=True,
                )
            elif argument_name.endswith(("_uid", "_gid", "_port")):
                request_builder.add_argument(option, type=int, required=True)
            else:
                request_builder.add_argument(option, required=True)
    request_builder.add_argument("--expected-uid", type=int, default=0)

    transaction = actions.add_parser("first-adoption")
    transaction.add_argument("--request", required=True)
    transaction.add_argument("--journal", required=True)
    transaction.add_argument("--attestation", required=True)
    transaction.add_argument("--rollback-evidence", required=True)
    transaction.add_argument("--binding-attestation", required=True)
    transaction.add_argument("--operation-id", required=True)
    transaction.add_argument("--expected-uid", type=int, default=0)

    prepare = actions.add_parser("prepare-candidate")
    prepare.add_argument("--state", required=True)
    prepare.add_argument("--candidate-slot-source", required=True)
    prepare.add_argument("--rollback-directory", required=True)
    prepare.add_argument("--legacy-console-env", required=True)
    prepare.add_argument("--legacy-console-uid", type=int, required=True)
    prepare.add_argument("--background-project-root", required=True)
    prepare.add_argument("--background-config-transaction", required=True)
    prepare.add_argument("--project-isolation-audit", required=True)
    prepare.add_argument("--project-isolation-ledger", required=True)
    prepare.add_argument("--candidate-evidence", required=True)
    prepare.add_argument("--credential-evidence", required=True)
    prepare.add_argument("--authority-uid", type=int, default=0)
    _add_credentials(prepare)

    prepare_first = actions.add_parser("prepare-first-adoption")
    prepare_first.add_argument("--state", required=True)
    prepare_first.add_argument("--candidate-slot-source", required=True)
    prepare_first.add_argument("--rollback-directory", required=True)
    prepare_first.add_argument("--legacy-console-env", required=True)
    prepare_first.add_argument("--legacy-console-uid", type=int, required=True)
    prepare_first.add_argument("--background-project-root", required=True)
    prepare_first.add_argument("--background-config-transaction", required=True)
    prepare_first.add_argument("--project-isolation-audit", required=True)
    prepare_first.add_argument("--project-isolation-ledger", required=True)
    prepare_first.add_argument("--legacy-authority-database", required=True)
    prepare_first.add_argument("--graph-evidence", required=True)
    prepare_first.add_argument("--graph-journal", required=True)
    prepare_first.add_argument("--credential-evidence", required=True)
    prepare_first.add_argument("--port-reservations", required=True)
    prepare_first.add_argument(
        "--port-reservations-sha256", required=True
    )
    prepare_first.add_argument("--binding-attestation", required=True)
    prepare_first.add_argument("--operation-id", required=True)
    prepare_first.add_argument("--first-adoption-attestation", required=True)
    prepare_first.add_argument("--authority-uid", type=int, default=0)
    _add_credentials(prepare_first)

    activate_parser = actions.add_parser("activate")
    activate_parser.add_argument("--state", required=True)
    activate_parser.add_argument("--publication", required=True)
    activate_parser.add_argument("--candidate-control", required=True)
    activate_parser.add_argument("--previous-control", required=True)
    activate_parser.add_argument("--activation-evidence", required=True)
    activate_parser.add_argument("--continuity-evidence", required=True)
    activate_parser.add_argument("--credential-evidence", required=True)
    activate_parser.add_argument("--browser-runtime-lock", required=True)
    activate_parser.add_argument("--browser-storage-state", required=True)
    activate_parser.add_argument("--browser-signing-key", required=True)
    activate_parser.add_argument("--browser-journal", required=True)
    activate_parser.add_argument("--browser-attestation", required=True)
    activate_parser.add_argument("--browser-consumption", required=True)
    activate_parser.add_argument("--authority-uid", type=int, default=0)
    _add_credentials(activate_parser)

    live_rehearsal = actions.add_parser("rehearse-live-rollback")
    live_rehearsal.add_argument("--state", required=True)
    live_rehearsal.add_argument("--publication", required=True)
    live_rehearsal.add_argument("--candidate-control", required=True)
    live_rehearsal.add_argument("--previous-control", required=True)
    live_rehearsal.add_argument("--journal", required=True)
    live_rehearsal.add_argument("--attestation", required=True)
    live_rehearsal.add_argument("--continuity-evidence", required=True)
    live_rehearsal.add_argument("--authority-uid", type=int, default=0)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    installer_fence: InstallerFenceHandle | None = None
    command_succeeded = False
    try:
        credentials = _credential_paths(arguments)
        if arguments.action == "migrate-credentials":
            attestation = Path(arguments.attestation)
            replayed = attestation.exists() or attestation.is_symlink()
            if replayed:
                document = verify_credential_migration(
                    cutover.read_private_json(
                        attestation, uid=arguments.expected_uid
                    ),
                    legacy_env=Path(arguments.legacy_env),
                    legacy_source_uid=arguments.legacy_source_uid,
                    destinations=credentials,
                    expected_uid=arguments.expected_uid,
                )
            else:
                document = migrate_credentials(
                    legacy_env=Path(arguments.legacy_env),
                    legacy_source_uid=arguments.legacy_source_uid,
                    destinations=credentials,
                    rollback_directory=Path(arguments.rollback_directory),
                    expected_uid=arguments.expected_uid,
                )
                document = verify_credential_migration(
                    document,
                    legacy_env=Path(arguments.legacy_env),
                    legacy_source_uid=arguments.legacy_source_uid,
                    destinations=credentials,
                    expected_uid=arguments.expected_uid,
                )
                cutover._publish_evidence(
                    attestation, document, uid=arguments.expected_uid
                )
            result = {
                "ok": True,
                "replayed": replayed,
                "attestation": arguments.attestation,
                "document_sha256": document["document_sha256"],
            }
        elif arguments.action == "preflight-credentials":
            document = preflight_credentials(
                release_digest=arguments.release_digest,
                credentials=credentials,
                expected_uid=arguments.expected_uid,
            )
            cutover._publish_evidence(
                Path(arguments.attestation), document, uid=arguments.expected_uid
            )
            result = {"ok": True, "attestation": arguments.attestation, "document_sha256": document["document_sha256"]}
        elif arguments.action == "build-first-adoption-manifest-template":
            document = build_first_adoption_manifest_template(arguments)
            result = {
                "ok": True,
                "manifest_template": arguments.output,
                "document_sha256": document["document_sha256"],
            }
        elif arguments.action == "build-first-adoption-request":
            document = build_first_adoption_request(arguments)
            result = {
                "ok": True,
                "request": arguments.output,
                "document_sha256": document["document_sha256"],
            }
        elif arguments.action == "first-adoption":
            request = _first_adoption_request(cutover.read_private_json(
                Path(arguments.request), uid=arguments.expected_uid
            ))
            state = cutover.load_state(
                Path(str(request["state"])), authority_uid=arguments.expected_uid
            )
            release_digest = str(state["release_digest"])
            release = Path(str(state["release"]))
            completion_path = Path(arguments.attestation)
            _completed_binding_attestation(
                Path(arguments.binding_attestation),
                operation_id=arguments.operation_id,
                release_digest=release_digest,
                expected_uid=arguments.expected_uid,
            )
            installer_fence = acquire_transaction_fence(
                owner_kind=FIRST_ADOPTION_INSTALLER_OWNER_KIND,
                operation_id=arguments.operation_id,
                transaction=Path(arguments.binding_attestation),
                terminal=completion_path,
                action="recover",
                expected_uid=arguments.expected_uid,
                expected_gid=0,
            )
            if completion_path.exists() or completion_path.is_symlink():
                document = _completed_first_adoption_attestation(
                    completion_path,
                    release=release,
                    expected_uid=arguments.expected_uid,
                )
                result = {
                    "ok": True,
                    "phase": "complete",
                    "replayed": True,
                    "attestation": arguments.attestation,
                    "document_sha256": document["document_sha256"],
                }
                installer_fence.mark_complete()
            else:
                document = execute_first_adoption_transaction(
                    request=request,
                    journal_file=Path(arguments.journal),
                    attestation=Path(arguments.attestation),
                    rollback_evidence=Path(arguments.rollback_evidence),
                    expected_uid=arguments.expected_uid,
                )
                result = {
                    "ok": True,
                    "phase": document["phase"],
                    "journal": arguments.journal,
                    "attestation": arguments.attestation,
                    "document_sha256": document["document_sha256"],
                }
                if document["phase"] == "complete":
                    installer_fence.mark_complete()
        elif arguments.action == "first-adoption-preflight":
            document = first_adoption_handoff_preflight(
                rendered_units=Path(arguments.rendered_units),
                publication_file=Path(arguments.publication),
                http_handoff_port=arguments.http_handoff_port,
                https_handoff_port=arguments.https_handoff_port,
                expected_uid=arguments.expected_uid,
            )
            cutover._publish_evidence(
                Path(arguments.attestation),
                document,
                uid=arguments.expected_uid,
            )
            result = {
                "ok": True,
                "ready": document["ready"],
                "blockers": document["blockers"],
                "attestation": arguments.attestation,
                "document_sha256": document["document_sha256"],
            }
        elif arguments.action in {"prepare-candidate", "prepare-first-adoption"}:
            state = cutover.load_state(
                Path(arguments.state), authority_uid=arguments.authority_uid
            )
            expected_port_reservations = None
            if arguments.action == "prepare-first-adoption":
                completion_path = Path(arguments.first_adoption_attestation)
                if completion_path.exists() or completion_path.is_symlink():
                    raise ActivationError(
                        "first-adoption transaction is already complete"
                    )
                _completed_binding_attestation(
                    Path(arguments.binding_attestation),
                    operation_id=arguments.operation_id,
                    release_digest=str(state["release_digest"]),
                    expected_uid=arguments.authority_uid,
                )
                installer_fence = acquire_transaction_fence(
                    owner_kind=FIRST_ADOPTION_INSTALLER_OWNER_KIND,
                    operation_id=arguments.operation_id,
                    transaction=Path(arguments.binding_attestation),
                    terminal=completion_path,
                    action="recover",
                    expected_uid=arguments.authority_uid,
                    expected_gid=0,
                )
                port_bundle = cutover.verify_first_adoption_port_reservations(
                    cutover.read_private_json(
                        Path(arguments.port_reservations),
                        uid=arguments.authority_uid,
                    )
                )
                if (
                    port_bundle["document_sha256"]
                    != arguments.port_reservations_sha256
                    or port_bundle["release_digest"]
                    != state["release_digest"]
                    or port_bundle["authority_database"]
                    != state["legacy_authority_database"]
                ):
                    raise ActivationError(
                        "first-adoption port reservations are bound to another cutover"
                    )
                cutover.verify_first_adoption_port_reservation_rows(
                    Path(str(state["legacy_authority_database"])),
                    port_bundle,
                    authority_uid=arguments.authority_uid,
                    minimum_handoff_remaining_seconds=(
                        FIRST_ADOPTION_MINIMUM_HANDOFF_REMAINING_SECONDS
                    ),
                )
                bundle_rows = port_bundle.get("reservations")
                if not isinstance(bundle_rows, Mapping):
                    raise ActivationError(
                        "first-adoption port reservations are invalid"
                    )
                expected_port_reservations = {
                    role: item.get("port")
                    if isinstance(item, Mapping)
                    else None
                    for role, item in bundle_rows.items()
                }
            candidate, credential = prepare_candidate(
                state=state,
                candidate_slot_source=Path(arguments.candidate_slot_source),
                legacy_console_env=Path(arguments.legacy_console_env),
                background_project_root=Path(arguments.background_project_root),
                background_config_transaction=Path(
                    arguments.background_config_transaction
                ),
                project_isolation_audit=Path(arguments.project_isolation_audit),
                project_isolation_ledger=Path(arguments.project_isolation_ledger),
                credentials=credentials,
                rollback_directory=Path(arguments.rollback_directory),
                expected_uid=arguments.authority_uid,
                legacy_console_uid=arguments.legacy_console_uid,
                expected_port_reservations=expected_port_reservations,
                first_adoption_defer_start=(
                    arguments.action == "prepare-first-adoption"
                ),
                first_adoption_legacy_authority_database=(
                    Path(arguments.legacy_authority_database)
                    if arguments.action == "prepare-first-adoption"
                    else None
                ),
                first_adoption_journal=(
                    Path(arguments.graph_journal)
                    if arguments.action == "prepare-first-adoption"
                    else None
                ),
            )
            cutover._publish_evidence(
                Path(arguments.credential_evidence),
                credential,
                uid=arguments.authority_uid,
            )
            if arguments.action == "prepare-first-adoption":
                cutover._publish_evidence(
                    Path(arguments.graph_evidence),
                    candidate,
                    uid=arguments.authority_uid,
                )
                result = {
                    "ok": True,
                    "phase": "prepared",
                    "graph_evidence": arguments.graph_evidence,
                    "credential_evidence": arguments.credential_evidence,
                    "document_sha256": candidate["document_sha256"],
                }
            else:
                cutover._publish_evidence(
                    Path(arguments.candidate_evidence),
                    candidate,
                    uid=arguments.authority_uid,
                )
                transition = cutover.record_evidence(
                    state_path=Path(arguments.state),
                    evidence_kind="candidate",
                    evidence_path=Path(arguments.candidate_evidence),
                    authority_uid=arguments.authority_uid,
                    evidence_uid=arguments.authority_uid,
                )
                result = {
                    "ok": True,
                    "phase": transition["phase"],
                    "candidate_evidence": arguments.candidate_evidence,
                    "credential_evidence": arguments.credential_evidence,
                    "document_sha256": candidate["document_sha256"],
                }
        elif arguments.action == "rehearse-live-rollback":
            state = cutover.load_state(
                Path(arguments.state), authority_uid=arguments.authority_uid
            )
            document = rehearse_live_traffic_rollback(
                state=state,
                publication_file=Path(arguments.publication),
                candidate_control=Path(arguments.candidate_control),
                previous_control=Path(arguments.previous_control),
                journal_file=Path(arguments.journal),
                expected_uid=arguments.authority_uid,
            )
            cutover._publish_evidence(
                Path(arguments.continuity_evidence),
                document["continuity_probe"],
                uid=arguments.authority_uid,
            )
            cutover._publish_evidence(
                Path(arguments.attestation),
                document,
                uid=arguments.authority_uid,
            )
            transition = cutover.record_evidence(
                state_path=Path(arguments.state),
                evidence_kind="live-rollback-rehearsal",
                evidence_path=Path(arguments.attestation),
                authority_uid=arguments.authority_uid,
                evidence_uid=arguments.authority_uid,
            )
            result = {
                "ok": True,
                "phase": transition["phase"],
                "journal": arguments.journal,
                "attestation": arguments.attestation,
                "continuity_evidence": arguments.continuity_evidence,
                "supported_rollback_head": document["supported_rollback_head"],
                "document_sha256": document["document_sha256"],
            }
        else:
            state = cutover.load_state(
                Path(arguments.state), authority_uid=arguments.authority_uid
            )
            activation_output = Path(arguments.activation_evidence)
            pending_output = activation_output.with_name(
                f".{activation_output.name}.browser-pending.json"
            )
            switch_journal = activation_output.with_name(
                f".{activation_output.name}.switch-journal.json"
            )

            def publish_or_match(path: Path, document: Mapping[str, object]) -> None:
                if path.exists() or path.is_symlink():
                    if cutover.read_private_json(
                        path, uid=arguments.authority_uid
                    ) != document:
                        raise ActivationError(
                            "activation recovery evidence changed"
                        )
                else:
                    cutover._publish_evidence(
                        path, document, uid=arguments.authority_uid
                    )

            if pending_output.exists() or pending_output.is_symlink():
                pending = cutover.verify_seal(
                    cutover.read_private_json(
                        pending_output, uid=arguments.authority_uid
                    ),
                    kind=ACTIVATION_READY_FOR_BROWSER_KIND,
                    fields=ACTIVATION_READY_FOR_BROWSER_FIELDS,
                )
                credential = cutover.read_private_json(
                    Path(arguments.credential_evidence),
                    uid=arguments.authority_uid,
                )
            else:
                pending, credential = activate(
                    state=state,
                    publication_file=Path(arguments.publication),
                    candidate_control=Path(arguments.candidate_control),
                    previous_control=Path(arguments.previous_control),
                    credentials=credentials,
                    expected_uid=arguments.authority_uid,
                    switch_journal=switch_journal,
                )
                publish_or_match(
                    Path(arguments.credential_evidence), credential
                )
                publish_or_match(
                    Path(arguments.continuity_evidence),
                    pending["continuity_probe"],
                )
                publish_or_match(pending_output, pending)
            publish_or_match(
                Path(arguments.credential_evidence), credential
            )
            publish_or_match(
                Path(arguments.continuity_evidence),
                pending["continuity_probe"],
            )
            binding = bind_browser_lcp_acceptance(
                release=Path(str(state["release"])),
                operation_id=str(state["cutover_id"]),
                publication_switch=pending["publication_switch"],
                runtime_lock=Path(arguments.browser_runtime_lock),
                storage_state=Path(arguments.browser_storage_state),
                signing_key=Path(arguments.browser_signing_key),
                journal=Path(arguments.browser_journal),
                attestation=Path(arguments.browser_attestation),
                consumption=Path(arguments.browser_consumption),
                expected_uid=arguments.authority_uid,
            )
            activation = finalize_browser_bound_activation(
                state=state,
                pending_activation=pending,
                browser_binding=binding,
            )
            publish_or_match(activation_output, activation)
            transition = cutover.record_evidence(
                state_path=Path(arguments.state),
                evidence_kind="activation",
                evidence_path=activation_output,
                authority_uid=arguments.authority_uid,
                evidence_uid=arguments.authority_uid,
            )
            result = {
                "ok": True,
                "phase": transition["phase"],
                "activation_evidence": arguments.activation_evidence,
                "continuity_evidence": arguments.continuity_evidence,
                "credential_evidence": arguments.credential_evidence,
                "browser_attestation": arguments.browser_attestation,
                "browser_consumption": arguments.browser_consumption,
                "switch_journal": str(switch_journal),
                "document_sha256": activation["document_sha256"],
            }
        command_succeeded = True
    except (
        ActivationError,
        cutover.CutoverError,
        InstallerFenceError,
        OSError,
        ValueError,
    ) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        if installer_fence is not None:
            installer_fence.close(command_succeeded=command_succeeded)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
