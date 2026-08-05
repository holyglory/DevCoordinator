#!/usr/bin/env python3
"""Regression tests for the static availability-topology validator."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check_availability_topology.py"
SPEC = importlib.util.spec_from_file_location("check_availability_topology", CHECK)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot import availability topology validator")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def copy_templates(destination: Path) -> None:
    names = (
        set(MODULE.SERVICE_CONTRACTS)
        | set(MODULE.SOCKET_CONTRACTS)
        | set(MODULE.SLICE_CONTRACTS)
        | MODULE.EXTRA_FILES
    )
    for name in names:
        shutil.copyfile(ROOT / "deploy" / name, destination / name)


def codes(directory: Path) -> set[str]:
    return {item.code for item in MODULE.validate_topology(directory)}


def replace(path: Path, before: str, after: str) -> None:
    source = path.read_text(encoding="utf-8")
    expect(before in source, f"fixture text is absent from {path.name}: {before}")
    path.write_text(source.replace(before, after, 1), encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="availability-topology-test-") as raw:
        clean = Path(raw) / "clean"
        clean.mkdir()
        copy_templates(clean)
        findings = MODULE.validate_topology(clean)
        expect(not findings, f"canonical templates failed validation: {findings}")

        cli = subprocess.run(
            [sys.executable, str(CHECK), "--unit-dir", str(clean), "--json"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        expect(cli.returncode == 0, f"validator CLI failed: {cli.stderr}")
        expect('"ok": true' in cli.stdout, "validator CLI omitted success evidence")

        mutable = Path(raw) / "mutable"
        shutil.copytree(clean, mutable)
        replace(
            mutable / "devcoordinator-edge.service",
            "/opt/devcoordinator/releases/RELEASE_DIGEST/bin/devcoordinator-edge",
            "/home/DevCoordinator/apps/DevOpsConsole/bin/devops-console.mjs",
        )
        expect(
            "immutable_release_path_required" in codes(mutable),
            "mutable checkout execution was not rejected",
        )

        coupled = Path(raw) / "coupled"
        shutil.copytree(clean, coupled)
        replace(
            coupled / "devcoordinator-api.service",
            "Requires=devcoordinator-api.socket",
            "Requires=devcoordinator-api.socket devcoordinator-projects.slice",
        )
        expect(
            "control_project_dependency_forbidden" in codes(coupled),
            "control-to-project dependency was not rejected",
        )

        migrating = Path(raw) / "migrating"
        shutil.copytree(clean, migrating)
        replace(
            migrating / "devcoordinator-authority.service",
            "devcoordinator-schema-check --read-only",
            "devcoordinator-schema-check migrate --read-only",
        )
        expect(
            "startup_migration_forbidden" in codes(migrating),
            "startup migration was not rejected",
        )

        missing_fixture_write = Path(raw) / "missing-fixture-write"
        shutil.copytree(clean, missing_fixture_write)
        replace(
            missing_fixture_write / "devcoordinator-authority.service",
            " /var/lib/devcoordinator-test-fixtures",
            "",
        )
        expect(
            "authority_fixture_storage_contract_invalid"
            in codes(missing_fixture_write),
            "authority without the durable fixture journal root was not rejected",
        )

        missing_repository_write = Path(raw) / "missing-repository-write"
        shutil.copytree(clean, missing_repository_write)
        replace(
            missing_repository_write / "devcoordinator-authority.service",
            "ReadWritePaths=/home ",
            "ReadWritePaths=",
        )
        expect(
            "authority_repository_compatibility_path_missing"
            in codes(missing_repository_write),
            "authority without the repository compatibility path was not rejected",
        )

        ineffective_repository_write = Path(raw) / "ineffective-repository-write"
        shutil.copytree(clean, ineffective_repository_write)
        replace(
            ineffective_repository_write / "devcoordinator-authority.service",
            "ProtectHome=false",
            "ProtectHome=read-only",
        )
        expect(
            "authority_repository_write_view_invalid"
            in codes(ineffective_repository_write),
            "authority with a ProtectHome read-only override was not rejected",
        )

        mandatory_runtime_fixture = Path(raw) / "mandatory-runtime-fixture"
        shutil.copytree(clean, mandatory_runtime_fixture)
        replace(
            mandatory_runtime_fixture / "devcoordinator-authority.service",
            "-/run/devcoordinator/test-fixture-credentials",
            "/run/devcoordinator/test-fixture-credentials",
        )
        expect(
            "authority_fixture_storage_contract_invalid"
            in codes(mandatory_runtime_fixture),
            "authority with a namespace-fatal missing runtime fixture path was not rejected",
        )

        missing_artifact_state = Path(raw) / "missing-artifact-state"
        shutil.copytree(clean, missing_artifact_state)
        replace(
            missing_artifact_state / "devcoordinator-authority.service",
            "StateDirectory=devcoordinator devcoordinator-test-artifacts",
            "StateDirectory=devcoordinator",
        )
        expect(
            "authority_artifact_storage_contract_invalid"
            in codes(missing_artifact_state),
            "authority without artifact StateDirectory creation was not rejected",
        )

        missing_artifact_write = Path(raw) / "missing-artifact-write"
        shutil.copytree(clean, missing_artifact_write)
        replace(
            missing_artifact_write / "devcoordinator-authority.service",
            " /var/lib/devcoordinator-test-artifacts",
            "",
        )
        expect(
            "authority_artifact_storage_contract_invalid"
            in codes(missing_artifact_write),
            "authority without artifact write access was not rejected",
        )

        authority_runtime_conflict = Path(raw) / "authority-runtime-conflict"
        shutil.copytree(clean, authority_runtime_conflict)
        replace(
            authority_runtime_conflict / "devcoordinator-authority.service",
            "StateDirectoryMode=0700\n",
            "StateDirectoryMode=0700\nRuntimeDirectory=devcoordinator\n",
        )
        expect(
            "authority_runtime_directory_socket_conflict"
            in codes(authority_runtime_conflict),
            "authority ownership of the socket parent runtime directory was not rejected",
        )

        authority_group = Path(raw) / "authority-group"
        shutil.copytree(clean, authority_group)
        replace(
            authority_group / "devcoordinator-authority.service",
            "Group=root",
            "Group=devcoordinator-clients",
        )
        expect(
            "service_identity_invalid" in codes(authority_group),
            "authority loss of its dedicated execution identity was not rejected",
        )

        authority_access_gid = Path(raw) / "authority-access-gid"
        shutil.copytree(clean, authority_access_gid)
        replace(
            authority_access_gid / "devcoordinator-authority.service",
            "devcoordinator-authority --systemd-socket --database /var/lib/devcoordinator/authority.sqlite3",
            "devcoordinator-authority --systemd-socket --database /var/lib/devcoordinator/authority.sqlite3 --access-gid 0",
        )
        expect(
            "local_transport_metadata_gate_forbidden" in codes(authority_access_gid),
            "authority reintroduction of a local access GID gate was not rejected",
        )

        authority_access_group = Path(raw) / "authority-access-group"
        shutil.copytree(clean, authority_access_group)
        replace(
            authority_access_group / "devcoordinator-authority.service",
            "devcoordinator-authority --systemd-socket --database /var/lib/devcoordinator/authority.sqlite3",
            "devcoordinator-authority --systemd-socket --database /var/lib/devcoordinator/authority.sqlite3 --access-group devcoordinator-clients",
        )
        expect(
            "local_transport_metadata_gate_forbidden" in codes(authority_access_group),
            "authority fallback to a shared local access group was not rejected",
        )

        authority_socket_group = Path(raw) / "authority-socket-group"
        shutil.copytree(clean, authority_socket_group)
        replace(
            authority_socket_group / "devcoordinator-authority.socket",
            "SocketUser=root\n",
            "SocketUser=root\nSocketGroup=devcoordinator-clients\n",
        )
        expect(
            "local_access_group_forbidden" in codes(authority_socket_group),
            "authority socket use of a shared local access group was not rejected",
        )

        authority_socket_mode = Path(raw) / "authority-socket-mode"
        shutil.copytree(clean, authority_socket_mode)
        replace(
            authority_socket_mode / "devcoordinator-authority.socket",
            "SocketMode=0666",
            "SocketMode=0660",
        )
        expect(
            "local_socket_access_invalid" in codes(authority_socket_mode),
            "non-public authority socket mode was not rejected",
        )

        supplementary_group = Path(raw) / "supplementary-group"
        shutil.copytree(clean, supplementary_group)
        replace(
            supplementary_group / "devcoordinator-api.service",
            "Group=devcoordinator-api\n",
            "Group=devcoordinator-api\nSupplementaryGroups=devcoordinator-clients\n",
        )
        expect(
            "local_access_group_forbidden" in codes(supplementary_group),
            "supplementary local access group was not rejected",
        )

        declared_client_group = Path(raw) / "declared-client-group"
        shutil.copytree(clean, declared_client_group)
        path = declared_client_group / "devcoordinator-availability.sysusers.conf"
        path.write_text(path.read_text(encoding="utf-8") + "g devcoordinator-clients -\n", encoding="utf-8")
        expect(
            "local_access_group_forbidden" in codes(declared_client_group),
            "obsolete shared client group declaration was not rejected",
        )

        broker_runtime_conflict = Path(raw) / "broker-runtime-conflict"
        shutil.copytree(clean, broker_runtime_conflict)
        shutil.copyfile(
            ROOT / "deploy" / "devcoordinator-broker.service",
            broker_runtime_conflict / "devcoordinator-broker.service",
        )
        replace(
            broker_runtime_conflict / "devcoordinator-broker.service",
            "StateDirectory=devcoordinator\n",
            "RuntimeDirectory=devcoordinator\nStateDirectory=devcoordinator\n",
        )
        expect(
            "authority_runtime_directory_socket_conflict"
            in codes(broker_runtime_conflict),
            "retired broker ownership of the socket parent runtime directory was not rejected",
        )

        missing_fixture_tmpfiles = Path(raw) / "missing-fixture-tmpfiles"
        shutil.copytree(clean, missing_fixture_tmpfiles)
        replace(
            missing_fixture_tmpfiles / "devcoordinator-availability.tmpfiles.conf",
            "d /run/devcoordinator/test-fixture-credentials 0700 root root -\n",
            "",
        )
        expect(
            "tmpfiles_contract_invalid" in codes(missing_fixture_tmpfiles),
            "missing root-private fixture credential directory was not rejected",
        )

        missing_testd_spool_tmpfiles = Path(raw) / "missing-testd-spool-tmpfiles"
        shutil.copytree(clean, missing_testd_spool_tmpfiles)
        replace(
            missing_testd_spool_tmpfiles / "devcoordinator-availability.tmpfiles.conf",
            "d /var/lib/devcoordinator-testd/spool 0700 devcoordinator-testd devcoordinator-testd -\n",
            "",
        )
        expect(
            "tmpfiles_contract_invalid" in codes(missing_testd_spool_tmpfiles),
            "missing test scheduler attempt spool directory was not rejected",
        )

        missing_bug_tmpfiles = Path(raw) / "missing-bug-tmpfiles"
        shutil.copytree(clean, missing_bug_tmpfiles)
        replace(
            missing_bug_tmpfiles / "devcoordinator-availability.tmpfiles.conf",
            "d /var/lib/devcoordinator-bugs/open 0777 root root -\n",
            "",
        )
        expect(
            "tmpfiles_contract_invalid" in codes(missing_bug_tmpfiles),
            "missing shared open-bug registry directory was not rejected",
        )

        missing_bug_environment = Path(raw) / "missing-bug-environment"
        shutil.copytree(clean, missing_bug_environment)
        replace(
            missing_bug_environment / "devcoordinator-console@.service",
            "Environment=DEVCOORDINATOR_BUG_DIR=/var/lib/devcoordinator-bugs/open\n",
            "",
        )
        expect(
            "console_bug_registry_environment_missing"
            in codes(missing_bug_environment),
            "Console without the canonical open-bug directory was not rejected",
        )

        missing_bug_sandbox = Path(raw) / "missing-bug-sandbox"
        shutil.copytree(clean, missing_bug_sandbox)
        replace(
            missing_bug_sandbox / "devcoordinator-console@.service",
            " /var/lib/devcoordinator-bugs",
            "",
        )
        expect(
            "console_bug_registry_sandbox_missing" in codes(missing_bug_sandbox),
            "Console without writable bug-registry sandbox access was not rejected",
        )

        private_profile = Path(raw) / "private-profile"
        shutil.copytree(clean, private_profile)
        replace(
            private_profile / "devcoordinator-availability.tmpfiles.conf",
            "z /etc/devcoordinator/client-profiles.json 0644 root root -",
            "z /etc/devcoordinator/client-profiles.json 0600 root root -",
        )
        expect(
            "tmpfiles_contract_invalid" in codes(private_profile),
            "locally unreadable non-secret client profile was not rejected",
        )

        writable_check = Path(raw) / "writable-check"
        shutil.copytree(clean, writable_check)
        replace(
            writable_check / "devcoordinator-testd.service",
            "--spool /var/lib/devcoordinator-testd/spool --check",
            "--spool /var/lib/devcoordinator-testd/spool --write",
        )
        expect(
            "testd_preflight_invalid" in codes(writable_check),
            "writable startup check was not rejected",
        )

        missing_spool_check = Path(raw) / "missing-spool-check"
        shutil.copytree(clean, missing_spool_check)
        replace(
            missing_spool_check / "devcoordinator-testd.service",
            " --spool /var/lib/devcoordinator-testd/spool",
            "",
        )
        expect(
            "testd_preflight_invalid" in codes(missing_spool_check),
            "testd preflight without private spool validation was not rejected",
        )

        wrong_testd_broker_mode = Path(raw) / "wrong-testd-broker-mode"
        shutil.copytree(clean, wrong_testd_broker_mode)
        replace(
            wrong_testd_broker_mode / "devcoordinator-testd.service",
            "--broker-socket /run/devcoordinator-authority.sock",
            "--broker-socket /run/devcoordinator-authority.sock --broker-socket-mode 0660",
        )
        expect(
            "local_transport_metadata_gate_forbidden"
            in codes(wrong_testd_broker_mode),
            "testd authority-socket mode gate was not rejected",
        )

        wrong_slice = Path(raw) / "wrong-slice"
        shutil.copytree(clean, wrong_slice)
        replace(
            wrong_slice / "devcoordinator-observer.service",
            "Slice=devcoordinator-background.slice",
            "Slice=devcoordinator-control.slice",
        )
        expect(
            "service_slice_invalid" in codes(wrong_slice),
            "background service promotion was not rejected",
        )

        wrong_observer_store = Path(raw) / "wrong-observer-store"
        shutil.copytree(clean, wrong_observer_store)
        replace(
            wrong_observer_store / "devcoordinator-observer.service",
            "/var/lib/devcoordinator-observer/inventory.sqlite3",
            "/var/lib/devcoordinator/authority.sqlite3",
        )
        expect(
            "observer_preflight_invalid" in codes(wrong_observer_store),
            "observer authority-store preflight coupling was not rejected",
        )

        wrong_observer_launch = Path(raw) / "wrong-observer-launch"
        shutil.copytree(clean, wrong_observer_launch)
        replace(
            wrong_observer_launch / "devcoordinator-observer.service",
            "serve --database /var/lib/devcoordinator-observer/inventory.sqlite3",
            "serve --database /var/lib/devcoordinator/authority.sqlite3",
        )
        expect(
            "observer_launch_contract_invalid" in codes(wrong_observer_launch),
            "observer authority-store launch coupling was not rejected",
        )

        wrong_test_plane_peer = Path(raw) / "wrong-test-plane-peer"
        shutil.copytree(clean, wrong_test_plane_peer)
        replace(
            wrong_test_plane_peer / "devcoordinator-authority.service",
            "--test-plane-socket /run/devcoordinator-testd/testd.sock",
            "--test-plane-socket /run/devcoordinator-testd/testd.sock --test-plane-user devcoordinator-testd",
        )
        expect(
            "local_transport_metadata_gate_forbidden" in codes(wrong_test_plane_peer),
            "test-plane peer-UID authorization gate was not rejected",
        )

        transient_socket = Path(raw) / "transient-socket"
        shutil.copytree(clean, transient_socket)
        replace(
            transient_socket / "devcoordinator-api.socket",
            "RemoveOnStop=no",
            "RemoveOnStop=yes",
        )
        expect(
            "socket_contract_invalid" in codes(transient_socket),
            "socket removal across service replacement was not rejected",
        )

        for service_name, runtime_directory in (
            ("devcoordinator-testd.service", "devcoordinator-testd"),
            (
                "devcoordinator-test-snapshotd.service",
                "devcoordinator-test-snapshotd",
            ),
        ):
            socket_runtime_owner = (
                Path(raw) / f"socket-runtime-owner-{runtime_directory}"
            )
            shutil.copytree(clean, socket_runtime_owner)
            replace(
                socket_runtime_owner / service_name,
                "StateDirectoryMode=0700",
                (
                    "StateDirectoryMode=0700\n"
                    f"RuntimeDirectory={runtime_directory}"
                ),
            )
            expect(
                "socket_runtime_directory_conflict"
                in codes(socket_runtime_owner),
                (
                    f"{service_name} ownership of its stable socket directory "
                    "was not rejected"
                ),
            )

        shared_identity = Path(raw) / "shared-identity"
        shutil.copytree(clean, shared_identity)
        replace(
            shared_identity / "devcoordinator-edge.service",
            "User=devcoordinator-edge",
            "User=holyglory",
        )
        expect(
            "service_identity_invalid" in codes(shared_identity),
            "shared project/control identity was not rejected",
        )

        missing_identity = Path(raw) / "missing-identity"
        shutil.copytree(clean, missing_identity)
        replace(
            missing_identity / "devcoordinator-availability.sysusers.conf",
            'u devcoordinator-edge - "DevCoordinator public edge" /nonexistent /usr/sbin/nologin\n',
            "",
        )
        expect(
            "service_identity_invalid" in codes(missing_identity),
            "missing dedicated service identity was not rejected",
        )

        weak_hardening = Path(raw) / "weak-hardening"
        shutil.copytree(clean, weak_hardening)
        replace(
            weak_hardening / "devcoordinator-edge.service",
            "NoNewPrivileges=yes",
            "NoNewPrivileges=no",
        )
        expect(
            "service_hardening_invalid" in codes(weak_hardening),
            "weakened edge hardening was not rejected",
        )

        wrong_testd_filesystem = Path(raw) / "wrong-testd-filesystem"
        shutil.copytree(clean, wrong_testd_filesystem)
        replace(
            wrong_testd_filesystem / "devcoordinator-testd.service",
            "ProtectSystem=full",
            "ProtectSystem=strict",
        )
        expect(
            "service_hardening_invalid" in codes(wrong_testd_filesystem),
            "testd without its writable /var filesystem contract was not rejected",
        )

        for unit_name in (
            "devcoordinator-edge.service",
            "devcoordinator-edge-handoff.service",
        ):
            missing_node_syscalls = Path(raw) / f"missing-node-syscalls-{unit_name}"
            shutil.copytree(clean, missing_node_syscalls)
            replace(
                missing_node_syscalls / unit_name,
                "SystemCallFilter=@system-service pkey_alloc pkey_free pkey_mprotect",
                "SystemCallFilter=@system-service",
            )
            expect(
                "edge_node_syscall_filter_invalid" in codes(missing_node_syscalls),
                f"{unit_name} without the Node/V8 pkey syscall exception was not rejected",
            )

        blocked_snapshot_delegation = Path(raw) / "blocked-snapshot-delegation"
        shutil.copytree(clean, blocked_snapshot_delegation)
        replace(
            blocked_snapshot_delegation / "devcoordinator-test-snapshotd.service",
            "PrivateTmp=yes",
            "NoNewPrivileges=yes\nPrivateTmp=yes",
        )
        expect(
            "snapshotd_uid_delegation_blocked"
            in codes(blocked_snapshot_delegation),
            "snapshotd NoNewPrivileges conflict was not rejected",
        )

        missing_snapshot_sidecars = Path(raw) / "missing-snapshot-sidecars"
        shutil.copytree(clean, missing_snapshot_sidecars)
        replace(
            missing_snapshot_sidecars / "devcoordinator-test-snapshotd.service",
            "ReadWritePaths=/var/lib/devcoordinator /var/lib/devcoordinator-test-snapshots",
            "ReadWritePaths=/var/lib/devcoordinator-test-snapshots",
        )
        expect(
            "snapshotd_authority_sidecar_path_missing"
            in codes(missing_snapshot_sidecars),
            "snapshotd without authority SQLite sidecar access was not rejected",
        )

        missing_credential = Path(raw) / "missing-credential"
        shutil.copytree(clean, missing_credential)
        replace(
            missing_credential / "devcoordinator-edge.service",
            "LoadCredential=tls-key:/etc/letsencrypt/live/vr.ae/privkey.pem\n",
            "",
        )
        expect(
            "edge_credential_contract_invalid" in codes(missing_credential),
            "missing edge TLS credential was not rejected",
        )

        legacy_test_reader = Path(raw) / "legacy-test-reader"
        shutil.copytree(clean, legacy_test_reader)
        replace(
            legacy_test_reader / "devcoordinator-api.service",
            "Environment=DEVCOORDINATOR_TEST_READ_AUTHORITY=testd\n",
            "",
        )
        expect(
            "api_inventory_projection_invalid" in codes(legacy_test_reader),
            "API activation without final testd read authority was not rejected",
        )

        shared_api_profile = Path(raw) / "shared-api-profile"
        shutil.copytree(clean, shared_api_profile)
        replace(
            shared_api_profile / "devcoordinator-api-handoff.service",
            "/etc/devcoordinator/api-handoff-profile.json",
            "/etc/devcoordinator/client-profiles.json",
        )
        expect(
            "api_profile_contract_invalid" in codes(shared_api_profile),
            "handoff API reuse of the live protected profile was not rejected",
        )

        hidden_repositories = Path(raw) / "hidden-repositories"
        shutil.copytree(clean, hidden_repositories)
        replace(
            hidden_repositories / "devcoordinator-api.service",
            "ProtectHome=read-only",
            "ProtectHome=yes",
        )
        expect(
            "api_repository_visibility_invalid" in codes(hidden_repositories),
            "API startup with enrolled repositories hidden below /home was not rejected",
        )

        unbounded_projects = Path(raw) / "unbounded-projects"
        shutil.copytree(clean, unbounded_projects)
        replace(
            unbounded_projects / "devcoordinator-projects.slice",
            "MemoryMax=DEVCOORDINATOR_PROJECT_MEMORY_MAX_BYTES\n",
            "",
        )
        expect(
            "slice_budget_missing" in codes(unbounded_projects),
            "unbounded project slice was not rejected",
        )

        hard_coded_projects = Path(raw) / "hard-coded-projects"
        shutil.copytree(clean, hard_coded_projects)
        replace(
            hard_coded_projects / "devcoordinator-projects.slice",
            "MemoryMax=DEVCOORDINATOR_PROJECT_MEMORY_MAX_BYTES",
            "MemoryMax=85%",
        )
        expect(
            "slice_budget_not_host_derived" in codes(hard_coded_projects),
            "hard-coded project memory percentage was not rejected",
        )

        fixed_budget_testd = Path(raw) / "fixed-budget-testd"
        shutil.copytree(clean, fixed_budget_testd)
        replace(
            fixed_budget_testd / "devcoordinator-testd.service",
            "--broker-socket /run/devcoordinator-authority.sock",
            "--broker-socket /run/devcoordinator-authority.sock --host-memory-mib 4096",
        )
        expect(
            "testd_resource_budget_forbidden" in codes(fixed_budget_testd),
            "fixed test scheduler resource budget was not rejected",
        )

        capped_tests = Path(raw) / "capped-tests"
        shutil.copytree(clean, capped_tests)
        replace(
            capped_tests / "devcoordinator-tests.slice",
            "TasksAccounting=yes",
            "TasksAccounting=yes\nMemoryMax=4096M",
        )
        expect(
            "test_slice_quota_forbidden" in codes(capped_tests),
            "memory-capped ordinary test-attempt slice was not rejected",
        )

        weak_restart = Path(raw) / "weak-restart"
        shutil.copytree(clean, weak_restart)
        replace(
            weak_restart / "devcoordinator-testd.service",
            "RestartSec=3",
            "RestartSec=30",
        )
        expect(
            "service_resilience_invalid" in codes(weak_restart),
            "slow crash recovery was not rejected",
        )

        unsafe_kill_mode = Path(raw) / "unsafe-kill-mode"
        shutil.copytree(clean, unsafe_kill_mode)
        replace(
            unsafe_kill_mode / "devcoordinator-testd.service",
            "KillMode=control-group",
            "KillMode=process",
        )
        expect(
            "service_resilience_invalid" in codes(unsafe_kill_mode),
            "test runner child-process leakage was not rejected",
        )

        unaccounted_projects = Path(raw) / "unaccounted-projects"
        shutil.copytree(clean, unaccounted_projects)
        replace(
            unaccounted_projects / "devcoordinator-projects.slice",
            "MemoryAccounting=yes",
            "MemoryAccounting=no",
        )
        expect(
            "slice_accounting_missing" in codes(unaccounted_projects),
            "unattributable project resource pressure was not rejected",
        )

        mutable_documentation = Path(raw) / "mutable-documentation"
        shutil.copytree(clean, mutable_documentation)
        path = mutable_documentation / "devcoordinator-api.service"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "[Unit]\n",
                "[Unit]\nDocumentation=file:///home/DevCoordinator/README.md\n",
                1,
            ),
            encoding="utf-8",
        )
        expect(
            "mutable_checkout_reference_forbidden" in codes(mutable_documentation),
            "mutable production documentation path was not rejected",
        )

        listener_conflict = Path(raw) / "listener-conflict"
        shutil.copytree(clean, listener_conflict)
        (listener_conflict / "rogue.socket").write_text(
            "[Socket]\nListenStream=443\n",
            encoding="utf-8",
        )
        expect(
            "public_listener_owner_conflict" in codes(listener_conflict),
            "second public listener owner was not rejected",
        )

        rendered = Path(raw) / "rendered"
        shutil.copytree(clean, rendered)
        release = "a" * 64
        for service in MODULE.SERVICE_CONTRACTS:
            if service == "devcoordinator-console@.service":
                continue
            path = rendered / service
            path.write_text(
                path.read_text(encoding="utf-8").replace("RELEASE_DIGEST", release),
                encoding="utf-8",
            )
        rendered_values = {
            "DEVCOORDINATOR_HANDOFF_HTTP_PORT": "45080",
            "DEVCOORDINATOR_HANDOFF_HTTPS_PORT": "45443",
            "DEVCOORDINATOR_HANDOFF_API_PORT": "45876",
            "DEVCOORDINATOR_CONTROL_MEMORY_LOW_BYTES": "1073741824",
            "DEVCOORDINATOR_BACKGROUND_MEMORY_HIGH_BYTES": "1073741824",
            "DEVCOORDINATOR_BACKGROUND_MEMORY_MAX_BYTES": "2147483648",
            "DEVCOORDINATOR_BACKGROUND_CPU_QUOTA_PERCENT": "800",
            "DEVCOORDINATOR_PROJECT_MEMORY_HIGH_BYTES": "4294967296",
            "DEVCOORDINATOR_PROJECT_MEMORY_MAX_BYTES": "5368709120",
        }
        for unit_name in (
            set(MODULE.SLICE_CONTRACTS)
            | set(MODULE.SERVICE_CONTRACTS)
            | set(MODULE.SOCKET_CONTRACTS)
        ):
            path = rendered / unit_name
            text = path.read_text(encoding="utf-8")
            for placeholder, value in rendered_values.items():
                text = text.replace(placeholder, value)
            path.write_text(text, encoding="utf-8")
        expect(
            not MODULE.validate_topology(rendered, release_digest=release),
            "rendered digest topology failed validation",
        )

        expect(
            "release_selector_invalid" in codes(rendered),
            "rendered units passed template-mode validation without their digest",
        )

    print("availability topology self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
