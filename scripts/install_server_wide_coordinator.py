#!/usr/bin/env python3
"""Install or roll back the server-wide DevCoordinator system boundary.

The installer deliberately does not start the broker.  Enroll exact users,
repositories, and server allowlists first, then enable the unit.  Runtime users
need no sudo after installation: they reach the service through the 0660 Unix
socket and their Codex/Claude skills are direct links to this repository.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACCESS_GROUP = "devcoordinator-clients"
SERVICE_USER = "root"
SYSTEM_FILES = {
    ROOT / "deploy/devcoordinator.sysusers.conf": Path(
        "/etc/sysusers.d/devcoordinator.conf"
    ),
    ROOT / "deploy/devcoordinator.tmpfiles.conf": Path(
        "/etc/tmpfiles.d/devcoordinator.conf"
    ),
    ROOT / "deploy/devcoordinator-broker.service": Path(
        "/etc/systemd/system/devcoordinator-broker.service"
    ),
}
SKILL_SOURCE = ROOT / "skills/codex-dev-coordinator"
JOURNAL_NAME = "install-journal.json"


class InstallError(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_real(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    metadata = absolute.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise InstallError(f"path must not be a symlink: {absolute}")
    if directory != stat.S_ISDIR(metadata.st_mode):
        raise InstallError(f"unexpected path type: {absolute}")
    if absolute.resolve(strict=True) != absolute:
        raise InstallError(f"path contains a symlink component: {absolute}")
    return absolute


def command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise InstallError(f"required system command is unavailable: {name}")
    return resolved


def run(*arguments: str) -> None:
    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode:
        raise InstallError(
            f"command failed ({' '.join(arguments)}): {completed.stderr.strip()}"
        )


def capture(*arguments: str) -> bytes:
    completed = subprocess.run(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise InstallError(
            f"command failed ({' '.join(arguments)}): "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def client_records(names: list[str]) -> list[Any]:
    if not names:
        raise InstallError("at least one explicit --client-user is required")
    records = []
    for name in dict.fromkeys(names):
        try:
            record = pwd.getpwnam(name)
        except KeyError as error:
            raise InstallError(f"client account does not exist: {name}") from error
        home = require_real(Path(record.pw_dir), directory=True)
        records.append((record, home))
    return records


def desired_plan(names: list[str]) -> dict[str, Any]:
    clients = client_records(names)
    return {
        "authority": {
            "database": "/var/lib/devcoordinator/coordinator.sqlite3",
            "socket": "/run/devcoordinator/broker.sock",
            "profile": "/etc/devcoordinator/client-profiles.json",
            "service_user": SERVICE_USER,
            "access_group": ACCESS_GROUP,
        },
        "system_files": [
            {"source": str(source), "destination": str(destination)}
            for source, destination in SYSTEM_FILES.items()
        ],
        "clients": [
            {
                "user": record.pw_name,
                "uid": record.pw_uid,
                "journal": f"/var/lib/devcoordinator-clients/{record.pw_uid}",
                "skill_roots": [
                    str(home / ".codex/skills"),
                    str(home / ".claude/skills"),
                ],
            }
            for record, home in clients
        ],
        "migration": {
            "legacy_authorities_preserved": True,
            "steps": [
                "apply installation without starting the broker",
                "enroll every exact client UID, repository, and server allowlist",
                "start devcoordinator-broker.service",
                "register each pre-existing listener from its owning non-root UID",
                "verify the listener in shared inventory and DevOps Console",
                "retain each legacy account store until host-wide verification succeeds",
            ],
            "rollback": (
                "stop the new broker, run this transaction's rollback action, "
                "and resume the preserved account authority"
            ),
        },
        "starts_service": False,
        "next_step": (
            "Run broker enroll once per user/repository with repeated --server allowlists, "
            "then enable devcoordinator-broker.service."
        ),
    }


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def install_file(source: Path, destination: Path, transaction: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    if destination.parent.is_symlink():
        raise InstallError(f"system configuration parent is a symlink: {destination.parent}")
    backup = transaction / "system-files" / destination.relative_to("/")
    before: dict[str, Any] = {"exists": destination.exists()}
    if destination.exists():
        metadata = destination.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise InstallError(f"refusing non-regular system file: {destination}")
        backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(destination, backup, follow_symlinks=False)
        before.update({"sha256": digest(destination), "mode": stat.S_IMODE(metadata.st_mode)})
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    shutil.copyfile(source, temporary, follow_symlinks=False)
    os.chown(temporary, 0, 0)
    os.chmod(temporary, 0o644)
    os.replace(temporary, destination)
    return {
        "source": str(source),
        "destination": str(destination),
        "installed_sha256": digest(destination),
        "backup": str(backup),
        "before": before,
    }


def ensure_owned_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise InstallError(f"required directory is unsafe: {path}")
    else:
        path.mkdir(parents=True, mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def capture_source_acl(transaction: Path) -> Path:
    """Preserve every ACL the installation will extend before mutation."""

    source = require_real(SKILL_SOURCE, directory=True)
    skills_root = require_real(source.parent, directory=True)
    repository = require_real(ROOT, directory=True)
    backup = transaction / "canonical-skill-source.acl"
    getfacl = command("getfacl")
    payload = b"".join(
        (
            capture(getfacl, "--absolute-names", str(repository)),
            capture(getfacl, "--absolute-names", str(skills_root)),
            capture(getfacl, "--absolute-names", "--recursive", str(source)),
        )
    )
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def grant_source_acl() -> None:
    """Give clients live read/execute access without source write access."""

    source = require_real(SKILL_SOURCE, directory=True)
    skills_root = require_real(source.parent, directory=True)
    repository = require_real(ROOT, directory=True)
    setfacl = command("setfacl")
    run(setfacl, "--modify", f"g:{ACCESS_GROUP}:--x", str(repository))
    run(setfacl, "--modify", f"g:{ACCESS_GROUP}:--x", str(skills_root))
    run(
        setfacl,
        "--recursive",
        "--modify",
        f"g:{ACCESS_GROUP}:rX",
        str(source),
    )
    for directory, child_directories, _files in os.walk(source):
        child_directories.sort()
        run(
            setfacl,
            "--modify",
            f"d:g:{ACCESS_GROUP}:rX",
            str(directory),
        )


def restore_source_acl(backup: Path) -> None:
    if not backup.is_file() or backup.is_symlink():
        raise InstallError(f"canonical source ACL backup is missing or unsafe: {backup}")
    run(command("setfacl"), f"--restore={backup}")


def apply_install(names: list[str], transaction_raw: str, allow_noncanonical: bool) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallError("apply requires root once; clients require no sudo afterward")
    transaction = Path(transaction_raw)
    if not transaction.is_absolute() or transaction.exists() or transaction.is_symlink():
        raise InstallError("--transaction-dir must be one new absolute path")
    transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    transaction.mkdir(mode=0o700)
    clients = client_records(names)
    journal: dict[str, Any] = {
        "version": 1,
        "status": "applying",
        "repo_root": str(ROOT),
        "system_files": [],
        "link_transactions": [],
        "group_members_added": [],
        "client_journals": [],
    }
    atomic_json(transaction / JOURNAL_NAME, journal)
    try:
        for source, destination in SYSTEM_FILES.items():
            journal["system_files"].append(
                install_file(source, destination, transaction)
            )
            atomic_json(transaction / JOURNAL_NAME, journal)

        run(command("systemd-sysusers"), "/etc/sysusers.d/devcoordinator.conf")
        run(command("systemd-tmpfiles"), "--create", "/etc/tmpfiles.d/devcoordinator.conf")
        try:
            service = pwd.getpwnam(SERVICE_USER)
            access = grp.getgrnam(ACCESS_GROUP)
        except KeyError as error:
            raise InstallError("system authority identity or access group is missing") from error

        acl_backup = capture_source_acl(transaction)
        journal["source_acl_backup"] = str(acl_backup)
        atomic_json(transaction / JOURNAL_NAME, journal)
        grant_source_acl()

        manager = ROOT / "scripts/manage_skill_links.py"
        for record, home in clients:
            current_groups = {group.gr_name for group in grp.getgrall() if record.pw_name in group.gr_mem}
            if record.pw_gid == access.gr_gid:
                current_groups.add(ACCESS_GROUP)
            if ACCESS_GROUP not in current_groups:
                run(command("usermod"), "-a", "-G", ACCESS_GROUP, record.pw_name)
                journal["group_members_added"].append(record.pw_name)

            client_journal = Path(f"/var/lib/devcoordinator-clients/{record.pw_uid}")
            ensure_owned_directory(
                client_journal,
                uid=record.pw_uid,
                gid=record.pw_gid,
                mode=0o700,
            )
            journal["client_journals"].append(str(client_journal))

            roots: list[Path] = []
            for relative in (Path(".codex/skills"), Path(".claude/skills")):
                root = home / relative
                root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if root.parent.is_symlink():
                    raise InstallError(f"agent configuration parent is a symlink: {root.parent}")
                if not root.exists():
                    root.mkdir(mode=0o700)
                metadata = root.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise InstallError(f"agent skill root is unsafe: {root}")
                os.chown(root.parent, record.pw_uid, record.pw_gid)
                os.chown(root, record.pw_uid, record.pw_gid)
                roots.append(root)

            link_transaction = transaction / f"skill-links-{record.pw_uid}"
            arguments = [
                sys.executable,
                str(manager),
                "apply",
                "--repo-root",
                str(ROOT),
                "--transaction-dir",
                str(link_transaction),
                "--skill",
                "codex-dev-coordinator",
            ]
            for root in roots:
                arguments.extend(("--target-root", str(root)))
            if allow_noncanonical:
                arguments.append("--allow-noncanonical")
            run(*arguments)
            journal["link_transactions"].append(str(link_transaction))
            atomic_json(transaction / JOURNAL_NAME, journal)

        # These ownership checks document the intended split after tmpfiles.
        authority = Path("/var/lib/devcoordinator").lstat()
        if authority.st_uid != service.pw_uid or stat.S_IMODE(authority.st_mode) != 0o700:
            raise InstallError("service authority directory failed ownership/mode verification")
        profile_parent = Path("/etc/devcoordinator").lstat()
        if (
            profile_parent.st_uid != service.pw_uid
            or profile_parent.st_gid != access.gr_gid
            or stat.S_IMODE(profile_parent.st_mode) != 0o750
        ):
            raise InstallError("client profile directory failed ownership/mode verification")
        run(command("systemctl"), "daemon-reload")
        journal["status"] = "applied"
        journal["starts_service"] = False
        atomic_json(transaction / JOURNAL_NAME, journal)
        return journal
    except BaseException:
        journal["status"] = "rollback_required"
        atomic_json(transaction / JOURNAL_NAME, journal)
        try:
            rollback_install(transaction)
        except BaseException as rollback_error:
            raise InstallError(
                f"installation failed and rollback also failed: {rollback_error}; inspect {transaction}"
            ) from rollback_error
        raise


def rollback_install(transaction: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise InstallError("rollback requires root")
    journal_path = transaction / JOURNAL_NAME
    document = json.loads(journal_path.read_text(encoding="utf-8"))
    if document.get("repo_root") != str(ROOT):
        raise InstallError("transaction belongs to another repository")
    manager = ROOT / "scripts/manage_skill_links.py"
    for link_transaction in reversed(document.get("link_transactions", [])):
        run(
            sys.executable,
            str(manager),
            "rollback",
            "--transaction-dir",
            str(link_transaction),
        )
    source_acl_backup = document.get("source_acl_backup")
    if source_acl_backup:
        restore_source_acl(Path(str(source_acl_backup)))
    for entry in reversed(document.get("system_files", [])):
        destination = Path(entry["destination"])
        if not destination.is_file() or digest(destination) != entry["installed_sha256"]:
            raise InstallError(f"installed system file changed; refusing rollback: {destination}")
        before = entry["before"]
        if before["exists"]:
            backup = Path(entry["backup"])
            shutil.copyfile(backup, destination, follow_symlinks=False)
            os.chown(destination, 0, 0)
            os.chmod(destination, int(before["mode"]))
        else:
            destination.unlink()
    for user in reversed(document.get("group_members_added", [])):
        run(command("gpasswd"), "-d", str(user), ACCESS_GROUP)
    run(command("systemctl"), "daemon-reload")
    document["status"] = "rolled_back"
    atomic_json(journal_path, document)
    return document


def verify_install(names: list[str]) -> dict[str, Any]:
    plan = desired_plan(names)
    failures: list[str] = []
    try:
        access = grp.getgrnam(ACCESS_GROUP)
        service = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        failures.append("service identity or access group is missing")
        access = None
        service = None
    for source, destination in SYSTEM_FILES.items():
        if not destination.is_file() or destination.is_symlink() or digest(destination) != digest(source):
            failures.append(f"system file does not match repository: {destination}")
    profile_parent = Path("/etc/devcoordinator")
    if access is not None and service is not None:
        try:
            metadata = profile_parent.lstat()
        except FileNotFoundError:
            failures.append(f"client profile directory is missing: {profile_parent}")
        else:
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != service.pw_uid
                or metadata.st_gid != access.gr_gid
                or stat.S_IMODE(metadata.st_mode) != 0o750
            ):
                failures.append(f"client profile directory is unsafe: {profile_parent}")
    profile = profile_parent / "client-profiles.json"
    if profile.exists() or profile.is_symlink():
        metadata = profile.lstat()
        if (
            access is None
            or service is None
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != service.pw_uid
            or metadata.st_gid != access.gr_gid
            or stat.S_IMODE(metadata.st_mode) != 0o640
        ):
            failures.append(f"client profile is unsafe: {profile}")
    for client in plan["clients"]:
        record = pwd.getpwnam(client["user"])
        journal = Path(client["journal"])
        if not journal.is_dir() or journal.is_symlink():
            failures.append(f"client journal is missing or unsafe: {journal}")
        for root in client["skill_roots"]:
            destination = Path(root) / "codex-dev-coordinator"
            source = ROOT / "skills/codex-dev-coordinator"
            if not destination.is_symlink() or os.readlink(destination) != str(source):
                failures.append(f"skill is not a direct canonical link: {destination}")
        groups = {group.gr_gid for group in grp.getgrall() if record.pw_name in group.gr_mem}
        if access is not None and record.pw_gid != access.gr_gid and access.gr_gid not in groups:
            failures.append(f"client is not in the broker access group: {record.pw_name}")
    return {"ok": not failures, "failures": failures, "plan": plan}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "verify"):
        action = actions.add_parser(name)
        action.add_argument("--client-user", action="append", required=True)
    apply = actions.add_parser("apply")
    apply.add_argument("--client-user", action="append", required=True)
    apply.add_argument("--transaction-dir", required=True)
    apply.add_argument("--allow-noncanonical-skill-links", action="store_true")
    rollback = actions.add_parser("rollback")
    rollback.add_argument("--transaction-dir", required=True)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.action == "plan":
            result = desired_plan(args.client_user)
        elif args.action == "apply":
            result = apply_install(
                args.client_user,
                args.transaction_dir,
                bool(args.allow_noncanonical_skill_links),
            )
        elif args.action == "rollback":
            result = rollback_install(Path(args.transaction_dir))
        else:
            result = verify_install(args.client_user)
            if not result["ok"]:
                print(json.dumps(result, indent=2, sort_keys=True))
                return 1
    except (InstallError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"server-wide coordinator installation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
