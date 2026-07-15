#!/usr/bin/env python3
"""Deterministic plan and deployment-contract tests for system installation."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import pwd
import tempfile


SCRIPT = Path(__file__).with_name("install_server_wide_coordinator.py")
SPEC = importlib.util.spec_from_file_location("server_wide_install", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load server-wide installer")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def exercise_source_acl_transaction() -> None:
    original_root = INSTALLER.ROOT
    original_source = INSTALLER.SKILL_SOURCE
    original_group = INSTALLER.ACCESS_GROUP
    with tempfile.TemporaryDirectory(prefix="devcoordinator-install-acl-") as raw:
        repository = Path(raw) / "repository"
        source = repository / "skills/codex-dev-coordinator"
        transaction = Path(raw) / "transaction"
        source.mkdir(parents=True)
        transaction.mkdir()
        skill = source / "SKILL.md"
        script = source / "scripts/dev_coordinator.py"
        script.parent.mkdir()
        skill.write_text("canonical\n", encoding="utf-8")
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        script.chmod(0o700)
        try:
            INSTALLER.ROOT = repository
            INSTALLER.SKILL_SOURCE = source
            INSTALLER.ACCESS_GROUP = "root"
            before = INSTALLER.capture(
                INSTALLER.command("getfacl"),
                "--absolute-names",
                "--recursive",
                str(repository),
            )
            backup = INSTALLER.capture_source_acl(transaction)
            INSTALLER.grant_source_acl()
            skill_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(skill)
            ).decode("utf-8")
            script_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(script)
            ).decode("utf-8")
            assert "group:root:r--" in skill_acl
            assert "group:root:r-x" in script_acl
            inherited = source / "future-update.txt"
            inherited.write_text("future\n", encoding="utf-8")
            inherited_acl = INSTALLER.capture(
                INSTALLER.command("getfacl"), "--omit-header", str(inherited)
            ).decode("utf-8")
            assert "group:root:r-x" in inherited_acl
            assert "#effective:r--" in inherited_acl
            inherited.unlink()
            INSTALLER.restore_source_acl(backup)
            after = INSTALLER.capture(
                INSTALLER.command("getfacl"),
                "--absolute-names",
                "--recursive",
                str(repository),
            )
            assert after == before
        finally:
            INSTALLER.ROOT = original_root
            INSTALLER.SKILL_SOURCE = original_source
            INSTALLER.ACCESS_GROUP = original_group


def main() -> int:
    user = pwd.getpwuid(os.geteuid()).pw_name
    plan = INSTALLER.desired_plan([user])
    assert plan["authority"]["database"] == "/var/lib/devcoordinator/coordinator.sqlite3"
    assert plan["authority"]["socket"] == "/run/devcoordinator/broker.sock"
    assert plan["starts_service"] is False
    assert plan["migration"]["legacy_authorities_preserved"] is True
    assert any("owning non-root UID" in step for step in plan["migration"]["steps"])
    assert plan["clients"][0]["journal"] == f"/var/lib/devcoordinator-clients/{os.geteuid()}"
    assert len(plan["clients"][0]["skill_roots"]) == 2

    unit = (INSTALLER.ROOT / "deploy/devcoordinator-broker.service").read_text(
        encoding="utf-8"
    )
    assert "User=root" in unit
    assert "Group=devcoordinator-clients" in unit
    assert "DEVCOORDINATOR_AUTHORITY=service" in unit
    assert "/var/lib/devcoordinator/coordinator.sqlite3" in unit
    assert "/run/devcoordinator/broker.sock" in unit
    assert "%h" not in unit

    tmpfiles = (INSTALLER.ROOT / "deploy/devcoordinator.tmpfiles.conf").read_text(
        encoding="utf-8"
    )
    assert "d /var/lib/devcoordinator 0700 root root" in tmpfiles
    assert "d /var/lib/devcoordinator-clients 0711 root root" in tmpfiles

    installer_source = SCRIPT.read_text(encoding="utf-8")
    assert 'f"g:{ACCESS_GROUP}:rX"' in installer_source
    assert 'f"d:g:{ACCESS_GROUP}:rX"' in installer_source
    assert 'f"--restore={backup}"' in installer_source
    exercise_source_acl_transaction()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
