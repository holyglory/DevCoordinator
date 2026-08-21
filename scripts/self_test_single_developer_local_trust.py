#!/usr/bin/env python3
"""Focused regression tests for the single-developer local-trust guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check_single_developer_local_trust.py"
SPEC = importlib.util.spec_from_file_location("check_single_developer_local_trust", CHECK)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import local trust guard")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def replace(root: Path, relative: str, before: str, after: str) -> None:
    path = root / relative
    source = path.read_text(encoding="utf-8")
    expect(before in source, f"fixture text is absent from {relative}: {before}")
    path.write_text(source.replace(before, after, 1), encoding="utf-8")


def append(root: Path, relative: str, source: str) -> None:
    path = root / relative
    with path.open("a", encoding="utf-8") as handle:
        handle.write(source)


def make_clean_fixture(root: Path) -> None:
    for relative in MODULE.LOCAL_SOCKET_UNITS:
        write(
            root,
            relative,
            """[Unit]
Description=fixture

[Socket]
ListenStream=/run/fixture.sock
SocketMode=0666
DirectoryMode=0755
""",
        )
    for relative in MODULE.PRODUCTION_SERVICE_UNITS:
        extra = (
            "RuntimeDirectory=devcoordinator-console\nRuntimeDirectoryMode=0755\n"
            if relative.endswith("devcoordinator-console@.service")
            else ""
        )
        write(
            root,
            relative,
            """[Unit]
Description=fixture

[Service]
ExecStart=/bin/true --expected-schema 13 --socket-mode 0666
"""
            + extra,
        )

    safe_python = """import os
import stat

def observe(peer, path, owner_uid, socket_mode=0o666):
    # Attribution, execution selection, type checks and chmod are allowed.
    if peer is not None:
        audit_uid = peer.uid
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("wrong type")
    if socket_mode < 0:
        raise ValueError("invalid setting")
    os.chmod(path, socket_mode)
    os.chown(path, owner_uid, -1)
    metadata = path.lstat()
    identity = {
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nlink": metadata.st_nlink,
    }
    if metadata.st_uid != owner_uid:
        # Metadata may select/repair the execution identity; it does not deny.
        os.chown(path, owner_uid, -1)
    return owner_uid, audit_uid, identity
"""
    for relative in MODULE.PYTHON_TRUST_SOURCES:
        write(root, relative, safe_python)

    safe_node = """export async function publish(fsp, file) {
  await fsp.chmod(file, 0o666);
  return file;
}
"""
    for relative in MODULE.NODE_TRUST_SOURCES:
        write(root, relative, safe_node)
    write(
        root,
        "apps/DevOpsConsole/edge/console-slot-supervisor.mjs",
        """export async function serve(fsp, controlSocket) {
  await fsp.chmod(controlSocket, 0o666);
}
""",
    )
    write(
        root,
        "apps/DevOpsConsole/src/telegram-ipc.mjs",
        """export async function serve(fsp, socketPath) {
  await fsp.chmod(socketPath, 0o666);
}
""",
    )


def codes(root: Path) -> set[str]:
    return {item.code for item in MODULE.validate_repository(root)}


def case(base: Path, parent: Path, name: str) -> Path:
    destination = parent / name
    shutil.copytree(base, destination)
    return destination


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="single-developer-trust-test-") as raw:
        temp = Path(raw)
        base = temp / "clean"
        make_clean_fixture(base)
        baseline = MODULE.validate_repository(base)
        expect(not baseline, f"clean trust fixture failed: {baseline}")

        cli = subprocess.run(
            [sys.executable, str(CHECK), "--repo", str(base), "--json"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        expect(cli.returncode == 0, f"guard CLI rejected clean fixture: {cli.stderr}")
        expect('"ok": true' in cli.stdout, "guard CLI omitted positive JSON evidence")

        for index, relative in enumerate(MODULE.LOCAL_SOCKET_UNITS):
            fixture = case(base, temp, f"socket-mode-{index}")
            replace(fixture, relative, "SocketMode=0666", "SocketMode=0660")
            expect(
                "local_socket_mode_not_reachable" in codes(fixture),
                f"{relative} mode regression was not detected",
            )

        socket_group = case(base, temp, "socket-group")
        relative = next(iter(MODULE.LOCAL_SOCKET_UNITS))
        replace(
            socket_group,
            relative,
            "SocketMode=0666",
            "SocketMode=0666\nSocketGroup=devcoordinator-clients",
        )
        expect(
            "local_socket_group_forbidden" in codes(socket_group),
            "SocketGroup regression was not detected",
        )

        expected_flag = case(base, temp, "expected-flag")
        replace(
            expected_flag,
            "deploy/devcoordinator-authority.service",
            "--socket-mode 0666",
            "--socket-mode 0666 --expected-owner 0",
        )
        expect(
            "local_metadata_exec_gate_forbidden" in codes(expected_flag),
            "required expected-owner metadata flag was not detected",
        )

        shared_group = case(base, temp, "shared-group")
        append(
            shared_group,
            "deploy/devcoordinator-testd.service",
            "SupplementaryGroups=devcoordinator-clients\n",
        )
        expect(
            "local_access_group_forbidden" in codes(shared_group),
            "shared local access group was not detected",
        )

        console_mode = case(base, temp, "console-mode")
        replace(
            console_mode,
            "apps/DevOpsConsole/edge/console-slot-supervisor.mjs",
            "chmod(controlSocket, 0o666)",
            "chmod(controlSocket, 0o600)",
        )
        expect(
            "console_control_socket_not_reachable" in codes(console_mode),
            "private Console control socket was not detected",
        )

        console_parent = case(base, temp, "console-parent")
        replace(
            console_parent,
            "deploy/devcoordinator-console@.service",
            "RuntimeDirectoryMode=0755",
            "RuntimeDirectoryMode=0750",
        )
        expect(
            "console_socket_parent_not_reachable" in codes(console_parent),
            "private Console control parent was not detected",
        )

        peer_branch = case(base, temp, "peer-branch")
        append(
            peer_branch,
            "skills/codex-dev-coordinator/scripts/devcoordinator/broker.py",
            """
def authorize(peer, request):
    if peer.uid != 0:
        raise PermissionError("peer unauthorized")
    return request
""",
        )
        expect(
            "physical_peer_authorization_forbidden" in codes(peer_branch),
            "physical peer UID authorization was not detected",
        )

        owner_branch = case(base, temp, "owner-branch")
        append(
            owner_branch,
            "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py",
            """
def reject_owner(metadata):
    if metadata.st_uid != 0:
        raise PermissionError("profile owner denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(owner_branch),
            "profile owner denial was not detected",
        )

        mode_branch = case(base, temp, "mode-branch")
        append(
            mode_branch,
            "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
            """
def reject_mode(metadata):
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("maintenance mode denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(mode_branch),
            "maintenance mode denial was not detected",
        )

        link_branch = case(base, temp, "link-branch")
        append(
            link_branch,
            "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py",
            """
def reject_links(metadata):
    if metadata.st_nlink != 1:
        raise PermissionError("link count denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(link_branch),
            "link-count denial was not detected",
        )

        acl = case(base, temp, "filesystem-acl")
        append(
            acl,
            "skills/codex-dev-coordinator/scripts/devcoordinator/repository_context.py",
            "\nfrom devcoordinator import filesystem_acl\n",
        )
        expect(
            "filesystem_acl_authorization_forbidden" in codes(acl),
            "filesystem ACL authority was not detected",
        )

        store_mode = case(base, temp, "store-mode")
        append(
            store_mode,
            "skills/codex-dev-coordinator/scripts/devcoordinator/store.py",
            """
def reject_store_mode(metadata):
    if metadata.st_mode & 0o077:
        raise PermissionError("store permission denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(store_mode),
            "store mode denial was not detected",
        )

        test_store_links = case(base, temp, "test-store-links")
        append(
            test_store_links,
            "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_store.py",
            """
def reject_store_links(metadata):
    if metadata.st_nlink != 1:
        raise PermissionError("test store link count denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(test_store_links),
            "test-store link-count denial was not detected",
        )

        credential_owner = case(base, temp, "credential-owner")
        append(
            credential_owner,
            "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_credentials.py",
            """
def reject_credential_owner(metadata, expected_uid):
    if metadata.st_uid != expected_uid:
        raise PermissionError("credential owner rejected")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(credential_owner),
            "credential owner denial was not detected",
        )

        host_peer = case(base, temp, "host-peer")
        append(
            host_peer,
            "skills/codex-dev-coordinator/scripts/devcoordinator/broker_host.py",
            """
def authorize_host_call(peer, request):
    if peer.uid not in {0, 1000}:
        raise PermissionError("peer forbidden")
    return request
""",
        )
        expect(
            "physical_peer_authorization_forbidden" in codes(host_peer),
            "broker-host physical peer authorization was not detected",
        )

        identity_gate = case(base, temp, "identity-gate")
        append(
            identity_gate,
            """
def reject_identity(root_identity, expected_uid):
    if root_identity.get("uid") != expected_uid:
        raise PermissionError("repository identity denied")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(identity_gate),
            "serialized identity UID denial was not detected",
        )

        runtime_mode = case(base, temp, "runtime-mode")
        append(
            runtime_mode,
            "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runtime.py",
            """
def reject_runtime_mode(metadata):
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise PermissionError("runner metadata rejected")
""",
        )
        expect(
            "local_permission_metadata_branch_forbidden" in codes(runtime_mode),
            "runtime permission denial was not detected",
        )

        publication_option = case(base, temp, "publication-option")
        append(
            publication_option,
            "apps/DevOpsConsole/edge/publication.mjs",
            "\nexport const expectedUid = 0;\n",
        )
        expect(
            "publication_metadata_gate_forbidden" in codes(publication_option),
            "publication expected UID option was not detected",
        )

        publication_branch = case(base, temp, "publication-branch")
        append(
            publication_branch,
            "apps/DevOpsConsole/edge/publication.mjs",
            """
export function reject(info) {
  if (info.uid !== 0) { throw new Error('owner rejected'); }
}
""",
        )
        expect(
            "publication_metadata_branch_forbidden" in codes(publication_branch),
            "publication owner branch was not detected",
        )

    print("single-developer local trust guard self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
