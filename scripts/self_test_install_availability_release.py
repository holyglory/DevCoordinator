#!/usr/bin/env python3
"""Deterministic checks for the trusted-local immutable release."""

from __future__ import annotations

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
        "bin/devcoordinator-same-schema-switch",
        "bin/devcoordinator-retained-control",
        "scripts/switch_same_schema_release.py",
    ):
        expect(required in paths, f"release omitted {required}")
    for retired in (
        "bin/devcoordinator-availability-activate",
        "scripts/activate_availability_release.py",
        "scripts/orchestrate_availability_cutover.py",
        "apps/DevOpsConsole/edge/first-adoption-route-resolution-cli.mjs",
        "apps/DevOpsConsole/edge/console-state-migration-cli.mjs",
    ):
        expect(retired not in paths, f"release retained retired path {retired}")

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
    expect(
        first["capabilities"]["current_format_delivery"] is True,
        "release omitted the current-format delivery capability",
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

    print("immutable availability release self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
