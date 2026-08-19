#!/usr/bin/env python3
"""Deterministic checks for the trusted-local immutable release."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/install_availability_release.py"
SPEC = importlib.util.spec_from_file_location("install_availability_release", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import immutable release installer")
INSTALLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALLER
SPEC.loader.exec_module(INSTALLER)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (INSTALLER.ReleaseError, OSError, ValueError, json.JSONDecodeError):
        return
    raise AssertionError(f"unsafe immutable release condition was accepted: {label}")


def write_port_reservations(
    root: Path, release_digest: str
) -> tuple[Path, str]:
    operation_id = "12345678-1234-4234-8234-123456789abc"
    created_at = "2099-01-01T00:00:00.000Z"
    expires_at = "2099-01-01T01:00:00.000Z"
    ports = {
        "console_outer": 30443,
        "console_inner": 30444,
        "handoff_http": 38080,
        "handoff_https": 38443,
        "handoff_api": 39876,
    }
    reservations = {
        role: {
            "lease_id": f"00000000-0000-4000-8000-{index:012d}",
            "port": port,
            "agent": f"cutover:first-adoption:{operation_id}",
            "purpose": f"first-adoption:{release_digest}:{role}",
            "status": "active",
            "expires_at": None if role.startswith("console_") else expires_at,
        }
        for index, (role, port) in enumerate(ports.items(), start=1)
    }
    authority_database = root / "authority.sqlite3"
    authority_database.touch()
    canonical_root = root / "canonical-repository"
    canonical_root.mkdir()
    document: dict[str, object] = {
        "schema_version": 1,
        "kind": INSTALLER.PORT_RESERVATIONS_KIND,
        "operation_id": operation_id,
        "release_digest": release_digest,
        "authority_database": str(authority_database),
        "authority_generation": "authority-generation-7",
        "authority_state_revision_before": 41,
        "authority_state_revision_after": 42,
        "repository_id": "repository-stable-id",
        "repository_generation": 3,
        "canonical_root": str(canonical_root),
        "port_range": {"start": 30000, "end": 60999},
        "handoff_ttl_seconds": 3600,
        "reservations": reservations,
        "transaction_journal_sha256": "a" * 64,
        "service_unit": "devcoordinator-broker.service",
        "service_restored": True,
        "maintenance_cleared": True,
        "created_at": created_at,
        "completed_at": "2099-01-01T00:00:01.000Z",
    }
    document["document_sha256"] = hashlib.sha256(
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    destination = root / "port-reservations.json"
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    destination.chmod(0o600)
    return destination, str(document["document_sha256"])


def main() -> int:
    first = INSTALLER.plan_release(ROOT, Path("/opt/devcoordinator/releases"))
    second = INSTALLER.plan_release(ROOT, Path("/opt/devcoordinator/releases"))
    expect(
        first["release_digest"] == second["release_digest"],
        "release digest is not deterministic",
    )
    paths = {str(entry["path"]) for entry in first["files"]}
    wrappers = {f"bin/{name}" for name in INSTALLER.WRAPPERS}
    for required in (
        "bin/devcoordinator",
        "bin/devcoordinator-mcp",
        "bin/devcoordinator-bug",
        "bin/devcoordinator-api",
        "bin/devcoordinator-authority",
        "bin/devcoordinator-testd",
        "bin/devcoordinator-compose-host-access",
        "bin/devcoordinator-authority-repository-repair",
        "bin/devcoordinator-clean-adoption",
        "bin/devcoordinator-availability-activate",
        "scripts/clean_adopt_availability.py",
        "scripts/activate_availability_release.py",
        "scripts/orchestrate_availability_cutover.py",
    ):
        expect(required in paths, f"release omitted {required}")

    obsolete_fragments = (
        "repository-owner",
        "repository_owner",
        "schema12-bridge",
        "bridge_schema12",
        "docker-admission",
        "manage_docker_admission",
        "test-execution-capabilities",
    )
    for path in paths | wrappers:
        expect(
            not any(fragment in path for fragment in obsolete_fragments),
            f"release still publishes obsolete access surface: {path}",
        )
    for capability in first["capabilities"]:
        expect(
            not any(fragment in capability for fragment in obsolete_fragments),
            f"release still advertises obsolete access capability: {capability}",
        )

    expect(
        first["capabilities"]["immutable_agent_client"] is True
        and first["capabilities"]["immutable_agent_mcp"] is True
        and first["capabilities"]["out_of_band_bug_registry"] is True
        and first["capabilities"]["project_runtime_isolation"] is True,
        "release omitted a current operational capability",
    )

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        releases = root / "releases"
        releases.mkdir(mode=0o755)
        staged = INSTALLER.stage_release(
            ROOT,
            releases,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        release = Path(str(staged["release_directory"]))
        verified = INSTALLER.verify_release(
            release,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(
            verified["release_digest"] == staged["release_digest"],
            "staged release did not verify against its digest",
        )
        expect(
            stat.S_IMODE(release.stat().st_mode) == 0o555,
            "release root is not immutable",
        )

        manifest = release / "release-manifest.json"
        original = manifest.read_bytes()
        manifest.chmod(0o644)
        must_fail(
            lambda: INSTALLER.verify_release(release),
            "writable release manifest",
        )
        manifest.chmod(0o444)
        expect(manifest.read_bytes() == original, "manifest check changed release bytes")

        # Repository worktrees commonly inherit a setgid group-sharing mode.
        # Source identity records the complete four-octal-digit mode; this is
        # evidence, not a requirement that the first digit be zero.
        source_document = json.loads(original)
        source_document["source_identity"]["mode"] = "2775"
        manifest.chmod(0o644)
        manifest.write_text(
            json.dumps(source_document, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o444)
        INSTALLER.verify_release(
            release,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        manifest.chmod(0o644)
        manifest.write_bytes(original)
        manifest.chmod(0o444)

        reservations, digest = write_port_reservations(root, release.name)
        rendered = root / "rendered"
        INSTALLER.render_units(
            release,
            rendered,
            port_reservations=reservations,
            port_reservations_sha256=digest,
        )
        authority_socket = rendered / "devcoordinator-authority.socket"
        expect(authority_socket.is_file(), "rendered graph omitted authority socket")
        socket_source = authority_socket.read_text(encoding="utf-8")
        expect(
            "SocketMode=0666" in socket_source and "SocketGroup=" not in socket_source,
            "authority socket is not trusted-local and host-wide",
        )

    print("immutable availability release self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
