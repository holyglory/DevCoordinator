#!/usr/bin/env python3
"""Focused, host-independent checks for the temporary schema-12 bridge.

The activation half of the bridge intentionally depends on protected host
state and systemd.  These checks cover the independently testable trust
boundary: staging must read one exact Git object, publish immutable sealed
bytes, replay idempotently, and reject content tampering or a non-schema-12
commit.  The checks deliberately avoid ``assert`` so ``python -O`` exercises
the same contract.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager, ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from types import ModuleType, SimpleNamespace
from typing import Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BRIDGE_PATH = ROOT / "scripts" / "bridge_schema12_legacy_broker.py"
SOURCE_PREFIX = Path("skills/codex-dev-coordinator/scripts")


def _fail(message: str) -> None:
    raise RuntimeError(message)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _run(*argv: str, cwd: Path) -> str:
    completed = subprocess.run(
        [*argv],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        _fail(
            f"fixture command failed ({completed.returncode}): {' '.join(argv)}: "
            f"{(completed.stderr or completed.stdout)[:2048]}"
        )
    return completed.stdout.strip()


def _load_bridge() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "devcoordinator_schema12_bridge_self_test", BRIDGE_PATH
    )
    if spec is None or spec.loader is None:
        _fail("could not load the schema-12 bridge module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, payload: str, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    path.chmod(mode)


def _fixture_repository(root: Path) -> tuple[Path, str]:
    repository = root / "source"
    repository.mkdir(mode=0o700)
    _run(
        "/usr/bin/git",
        "-c",
        "init.defaultBranch=main",
        "init",
        "--quiet",
        cwd=repository,
    )
    _run(
        "/usr/bin/git",
        "config",
        "user.name",
        "Schema Bridge Self Test",
        cwd=repository,
    )
    _run(
        "/usr/bin/git",
        "config",
        "user.email",
        "schema-bridge-self-test@localhost",
        cwd=repository,
    )
    scripts = repository / SOURCE_PREFIX
    _write(
        scripts / "dev_coordinator.py",
        "#!/usr/bin/env python3\nprint('committed legacy entry')\n",
        mode=0o755,
    )
    _write(
        scripts / "validate_runtime_dependencies.py",
        "#!/usr/bin/env python3\nraise SystemExit(0)\n",
        mode=0o755,
    )
    _write(scripts / "devcoordinator/__init__.py", "", mode=0o644)
    _write(
        scripts / "devcoordinator/schema.py",
        "SCHEMA_VERSION = 12\n",
        mode=0o644,
    )
    _write(scripts / "committed-marker.txt", "committed-marker\n", mode=0o644)
    _run("/usr/bin/git", "add", "--all", cwd=repository)
    _run(
        "/usr/bin/git",
        "commit",
        "--quiet",
        "--message",
        "schema-12 fixture",
        cwd=repository,
    )
    return repository, _run("/usr/bin/git", "rev-parse", "HEAD", cwd=repository)


def _expect_bridge_error(
    bridge: ModuleType, action: Callable[[], object], expected_text: str
) -> None:
    try:
        action()
    except bridge.BridgeError as error:
        _expect(
            expected_text in str(error),
            f"unexpected bridge error: {error}",
        )
    else:
        _fail(f"bridge accepted invalid state; expected {expected_text!r}")


def _exercise_bounded_failure_diagnostic(bridge: ModuleType, root: Path) -> None:
    broker_socket = root / "diagnostic-broker.sock"
    broker_socket.write_bytes(b"fixture")
    unhealthy = {
        "LoadState": "loaded",
        "ActiveState": "activating",
        "SubState": "auto-restart",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "failed-invocation",
        "NRestarts": 42,
    }
    healthy = {
        **unhealthy,
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": 4312,
        "InvocationID": "healthy-invocation",
        "NRestarts": 43,
    }
    calls: list[tuple[list[str], dict[str, object]]] = []
    journal_lines = [f"old-line-{index}" for index in range(90)]
    journal_lines.extend(
        [
            "x" * (70 * 1024),
            "Authorization: Bearer super-secret-bearer",
            "database=postgresql://operator:super-secret-password@localhost/db",
            "password=super-secret-password",
            '{"token":"super-secret-json-token","message":"failed"}',
        ]
    )

    def diagnostic_run(argv, **kwargs):
        command = [str(item) for item in argv]
        calls.append((command, dict(kwargs)))
        if command[0] == "/usr/bin/systemctl":
            return SimpleNamespace(
                stdout="Result=exit-code\nExecMainCode=1\nExecMainStatus=78\n",
                stderr="",
                returncode=0,
            )
        if command[0] == "/usr/bin/journalctl":
            return SimpleNamespace(
                stdout="\n".join(journal_lines) + "\n",
                stderr="",
                returncode=0,
            )
        _fail(f"failure diagnostic invoked an unexpected command: {command}")

    with (
        mock.patch.object(bridge.os, "geteuid", return_value=0),
        mock.patch.object(bridge, "_systemd_state", return_value=unhealthy),
        mock.patch.object(bridge, "_systemd_execution_identity", return_value={}),
        mock.patch.object(bridge, "_related_unit_states", return_value={}),
        mock.patch.object(bridge, "_run", side_effect=diagnostic_run),
    ):
        result = bridge._broker_status(broker_socket)
    _expect(result["ok"] is True, "unhealthy broker status was not observable")
    _expect(
        result["stably_ready"] is False,
        "restart-loop broker was reported stably ready",
    )
    diagnostic = result.get("failure_diagnostic")
    _expect(isinstance(diagnostic, dict), "unhealthy broker omitted diagnostics")
    _expect(
        diagnostic["properties"]
        == {"Result": "exit-code", "ExecMainCode": 1, "ExecMainStatus": 78},
        "failure diagnostic did not type the exact systemd exit properties",
    )
    journal = diagnostic["journal"]
    tail = journal["tail"]
    _expect(journal["truncated"] is True, "large journal tail was not marked truncated")
    _expect(journal["redacted"] is True, "journal secrets were not marked redacted")
    _expect(
        journal["line_count"] <= bridge.BROKER_FAILURE_JOURNAL_LINES,
        "journal diagnostic exceeded its line bound",
    )
    _expect(
        journal["byte_count"] <= bridge.BROKER_FAILURE_JOURNAL_BYTES,
        "journal diagnostic exceeded its byte bound",
    )
    for secret in (
        "super-secret-bearer",
        "super-secret-password",
        "operator:super-secret-password",
        "super-secret-json-token",
    ):
        _expect(secret not in tail, f"journal diagnostic exposed {secret}")
    journal_calls = [call for call in calls if call[0][0] == "/usr/bin/journalctl"]
    _expect(len(journal_calls) == 1, "diagnostic did not use one journal read")
    journal_argv, journal_kwargs = journal_calls[0]
    _expect(
        journal_argv
        == [
            "/usr/bin/journalctl",
            "--unit",
            bridge.BROKER_UNIT,
            "--boot=0",
            "--no-pager",
            "--lines",
            str(bridge.BROKER_FAILURE_JOURNAL_LINES),
            "--output",
            "short-iso-precise",
        ],
        "diagnostic journal command was not fixed to the exact bounded unit read",
    )
    _expect(
        journal_kwargs.get("timeout")
        == bridge.BROKER_FAILURE_COMMAND_TIMEOUT_SECONDS
        and journal_kwargs.get("check") is False,
        "diagnostic journal command did not retain its timeout contract",
    )
    environment = journal_kwargs.get("env")
    _expect(
        isinstance(environment, dict)
        and environment.get("SYSTEMD_COLORS") == "0"
        and environment.get("LC_ALL") == "C.UTF-8",
        "diagnostic journal command did not use its fixed noninteractive environment",
    )

    with (
        mock.patch.object(bridge.os, "geteuid", return_value=0),
        mock.patch.object(bridge, "_systemd_state", side_effect=[healthy, healthy]),
        mock.patch.object(bridge, "_systemd_execution_identity", return_value={}),
        mock.patch.object(bridge, "_related_unit_states", return_value={}),
        mock.patch.object(bridge, "_socket_ready", return_value=True),
        mock.patch.object(bridge.time, "sleep"),
        mock.patch.object(
            bridge,
            "_broker_failure_diagnostic",
            side_effect=RuntimeError("healthy status read failure evidence"),
        ),
    ):
        healthy_result = bridge._broker_status(broker_socket)
    _expect(
        healthy_result["stably_ready"] is True
        and "failure_diagnostic" not in healthy_result,
        "healthy broker status captured distracting failure evidence",
    )

    with mock.patch.object(bridge.os, "geteuid", return_value=1001):
        _expect_bridge_error(
            bridge,
            lambda: bridge._broker_status(broker_socket),
            "requires the authority identity",
        )

    with mock.patch.object(
        bridge,
        "_run",
        side_effect=bridge.BridgeError("journal failed: password=hunter2"),
    ):
        unavailable = bridge._broker_failure_journal()
    _expect(
        unavailable["available"] is False
        and "hunter2" not in unavailable["error"],
        "journal command failure exposed a credential",
    )

    # Construct the sentinel at runtime so the regression still exercises the
    # private-key redactor without publishing a credential-shaped literal in
    # the repository (or in Codex's reachable turn-diff trees).
    private_key_label = "PRIVATE KEY"
    private_key_fixture = (
        f"-----BEGIN {private_key_label}-----\n"
        "secret-bytes\n"
        f"-----END {private_key_label}-----"
    )
    private_key, private_key_redacted = bridge._redact_diagnostic_text(
        private_key_fixture
    )
    _expect(
        private_key_redacted is True and "secret-bytes" not in private_key,
        "private key material was not fully redacted",
    )


def _exercise_crash_loop_descendant_restore(bridge: ModuleType, root: Path) -> None:
    release = root / "crash-loop-release"
    release.mkdir()
    digest = "a" * 64
    activation_state = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
        "MainPID": 1200,
        "InvocationID": "activation-invocation",
        "NRestarts": 0,
    }
    observed_state = {
        **activation_state,
        "MainPID": 2200,
        "InvocationID": "crash-descendant-41",
        "NRestarts": 41,
    }
    latest_state = {
        **observed_state,
        "MainPID": 0,
        "InvocationID": "crash-descendant-42",
        "NRestarts": 42,
        "ActiveState": "activating",
        "SubState": "auto-restart",
    }
    inactive_state = {
        **latest_state,
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": 0,
    }
    current = {
        "phase": "ready",
        "release": str(release),
        "release_digest": digest,
        "activation": {"systemd": activation_state},
    }
    execution = {
        "systemd": {"ExecStart": "fixture"},
        "argv": ["/usr/bin/python3", "-I", "fixture"],
        "dropin_paths": [str(bridge.DEFAULT_DROPIN)],
        "dropins": [{"sha256": "b" * 64}],
    }
    commands: list[list[str]] = []

    def run(argv, **_kwargs):
        commands.append([str(item) for item in argv])
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    with (
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={
                "release_digest": digest,
                "verified_unsealed_bytecode_cache_sha256": "c" * 64,
            },
        ),
        mock.patch.object(
            bridge,
            "_verify_loaded_bridge_execution",
            side_effect=[execution, execution],
        ),
        mock.patch.object(bridge, "_systemd_state", return_value=latest_state),
        mock.patch.object(bridge, "_run", side_effect=run),
        mock.patch.object(
            bridge, "_wait_inactive", return_value=inactive_state
        ),
    ):
        stopped, evidence = bridge._stop_verified_crash_loop_descendant(
            current,
            observed_state=observed_state,
            broker_socket=bridge.DEFAULT_SOCKET,
            dropin=bridge.DEFAULT_DROPIN,
            wait_seconds=30,
            expected_uid=os.geteuid(),
        )
    _expect(stopped == inactive_state, "crash-loop restore lost inactive proof")
    _expect(
        commands == [["/usr/bin/systemctl", "stop", bridge.BROKER_UNIT]],
        "crash-loop restore did not stop only the exact broker unit",
    )
    _expect(
        evidence["kind"] == "verified-supervised-crash-loop-descendant"
        and evidence["activation_invocation_id"] == "activation-invocation"
        and evidence["observed_restart_count"] == 41
        and evidence["last_restart_count"] == 42
        and evidence["release_digest"] == digest
        and evidence["verified_unsealed_bytecode_cache_sha256"] == "c" * 64,
        "crash-loop restore omitted its immutable descendant evidence",
    )

    unchanged_restart = {**observed_state, "NRestarts": 0}
    with mock.patch.object(
        bridge,
        "_verify_activation_release",
        side_effect=RuntimeError("unproven descendant reached release verification"),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._stop_verified_crash_loop_descendant(
                current,
                observed_state=unchanged_restart,
                broker_socket=bridge.DEFAULT_SOCKET,
                dropin=bridge.DEFAULT_DROPIN,
                wait_seconds=30,
                expected_uid=os.geteuid(),
            ),
            "not a verified crash-loop descendant",
        )

    with (
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={"release_digest": digest},
        ),
        mock.patch.object(
            bridge,
            "_verify_loaded_bridge_execution",
            side_effect=[execution, {**execution, "argv": ["changed"]}],
        ),
        mock.patch.object(bridge, "_systemd_state", return_value=latest_state),
        mock.patch.object(
            bridge,
            "_run",
            side_effect=RuntimeError("changed execution reached systemd stop"),
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._stop_verified_crash_loop_descendant(
                current,
                observed_state=observed_state,
                broker_socket=bridge.DEFAULT_SOCKET,
                dropin=bridge.DEFAULT_DROPIN,
                wait_seconds=30,
                expected_uid=os.geteuid(),
            ),
            "execution changed before stop",
        )


def _make_tree_removable(path: Path) -> None:
    if not path.exists():
        return
    for candidate in sorted(
        path.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        if candidate.is_symlink():
            continue
        try:
            candidate.chmod(0o700 if candidate.is_dir() else 0o600)
        except FileNotFoundError:
            pass
    path.chmod(0o700)


def _exercise_immutable_readiness(bridge: ModuleType, root: Path) -> None:
    database = root / "authority.sqlite3"
    connection = sqlite3.connect(database)
    try:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        _expect(journal_mode == ("wal",), "SQLite fixture did not enter WAL mode")
        connection.execute("CREATE TABLE readiness_probe(value INTEGER NOT NULL)")
        connection.execute("INSERT INTO readiness_probe(value) VALUES (12)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    finally:
        connection.close()
    database.chmod(0o600)

    wal = Path(str(database) + "-wal")
    shm = Path(str(database) + "-shm")
    for sidecar in (wal, shm):
        if sidecar.exists() or sidecar.is_symlink():
            sidecar.unlink()

    # Establish the regression: SQLite's ordinary mode=ro connection is not
    # side-effect free for a WAL database.  Merely reading creates an empty
    # WAL plus a 32 KiB shared-memory file.
    ordinary = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5.0)
    try:
        _expect(
            ordinary.execute("SELECT value FROM readiness_probe").fetchone() == (12,),
            "ordinary read-only SQLite fixture returned the wrong data",
        )
        _expect(wal.is_file(), "ordinary read-only SQLite did not create a WAL")
        _expect(wal.stat().st_size == 0, "ordinary read-only SQLite WAL was not empty")
        _expect(shm.is_file(), "ordinary read-only SQLite did not create shared memory")
        _expect(
            shm.stat().st_size > 0,
            "ordinary read-only SQLite shared memory was unexpectedly empty",
        )
    finally:
        ordinary.close()

    for sidecar in (wal, shm):
        sidecar.unlink()
    _expect(not wal.exists() and not shm.exists(), "fixture sidecars were not reset")

    attestation = root / "readiness.json"
    attestation.write_text("{}\n", encoding="utf-8")
    attestation.chmod(0o600)
    database_identity = bridge._sqlite_regular_identity(
        database,
        uid=os.geteuid(),
        label="authority database",
    )
    snapshot = {
        "metadata": {
            "schema_version": 12,
            "migration_state": "ready",
            "database_generation": "fixture-generation",
            "state_revision": 7,
        },
        "invariants": {"quick_check": "ok"},
    }
    document = {
        "database": str(database),
        "database_identity_after": {
            key: database_identity[key] for key in ("device", "inode", "size")
        },
        "postcondition": snapshot,
        "document_sha256": "a" * 64,
    }
    snapshot_calls: list[sqlite3.Connection] = []

    def read_snapshot(
        selected: Path, *, connection: sqlite3.Connection | None = None
    ) -> dict[str, object]:
        _expect(selected == database, "readiness selected the wrong database")
        _expect(connection is not None, "readiness did not pass its immutable connection")
        _expect(
            connection.execute("SELECT value FROM readiness_probe").fetchone() == (12,),
            "immutable readiness connection returned the wrong data",
        )
        snapshot_calls.append(connection)
        return snapshot

    fake_cutover = SimpleNamespace(
        _authority_readiness_result=lambda _raw: document,
        _read_authority_readiness_snapshot=read_snapshot,
    )
    before_database = bridge._sqlite_regular_identity(
        database,
        uid=os.geteuid(),
        label="authority database",
    )
    before_sidecars = bridge._sqlite_sidecar_identities(
        database,
        uid=os.geteuid(),
    )
    with mock.patch.object(bridge, "_load_cutover_module", return_value=fake_cutover):
        proof = bridge._readiness_proof(
            attestation,
            database=database,
            uid=os.geteuid(),
        )
    _expect(proof.get("database_generation") == "fixture-generation", "bad proof")
    _expect(len(snapshot_calls) == 1, "immutable snapshot reader call count changed")
    _expect(
        bridge._sqlite_regular_identity(
            database,
            uid=os.geteuid(),
            label="authority database",
        )
        == before_database,
        "immutable readiness changed the main database identity",
    )
    _expect(
        bridge._sqlite_sidecar_identities(database, uid=os.geteuid())
        == before_sidecars,
        "immutable readiness created or changed SQLite sidecars",
    )
    _expect(not wal.exists() and not shm.exists(), "immutable readiness created sidecars")

    wal.write_bytes(b"retained-uncheckpointed-frame")
    wal.chmod(0o600)
    with mock.patch.object(bridge, "_load_cutover_module", return_value=fake_cutover):
        _expect_bridge_error(
            bridge,
            lambda: bridge._readiness_proof(
                attestation,
                database=database,
                uid=os.geteuid(),
            ),
            "WAL must be absent or exactly zero bytes",
        )
    _expect(
        len(snapshot_calls) == 1,
        "nonempty WAL reached the readiness snapshot reader",
    )
    _expect(
        wal.read_bytes() == b"retained-uncheckpointed-frame",
        "readiness proof modified or deleted a nonempty WAL",
    )


def _exercise_default_release_visibility(
    bridge: ModuleType, root: Path, repository: Path, commit: str
) -> None:
    # Model the canonical two-directory /opt ancestry without writing outside
    # the test root.  Its parent is pre-existing trust; only the dedicated
    # root and releases directory may be reconciled by stage.
    root.chmod(0o755)
    opt = root / "opt"
    opt.mkdir(mode=0o755)
    opt.chmod(0o755)
    default_root = opt / "devcoordinator-legacy-broker/releases"
    prior_umask = os.umask(0o077)
    try:
        with mock.patch.object(bridge, "DEFAULT_RELEASE_ROOT", default_root):
            first = bridge.stage_release(
                repo=repository,
                commit=commit,
                release_root=default_root,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )
    finally:
        os.umask(prior_umask)
    dedicated = default_root.parent
    _expect(
        stat.S_IMODE(dedicated.lstat().st_mode) == 0o755,
        "restrictive umask made the dedicated release root private",
    )
    _expect(
        stat.S_IMODE(default_root.lstat().st_mode) == 0o755,
        "restrictive umask made the releases directory private",
    )

    # Reproduce the live drift and prove exact, idempotent reconciliation.  No
    # release bytes are rebuilt and the existing content address is retained.
    dedicated.chmod(0o700)
    default_root.chmod(0o700)
    prior_umask = os.umask(0o077)
    try:
        with mock.patch.object(bridge, "DEFAULT_RELEASE_ROOT", default_root):
            replay = bridge.stage_release(
                repo=repository,
                commit=commit,
                release_root=default_root,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )
    finally:
        os.umask(prior_umask)
    _expect(replay.get("created") is False, "ancestry repair rebuilt the release")
    _expect(
        replay.get("release") == first.get("release"),
        "ancestry repair changed the immutable release identity",
    )
    _expect(
        stat.S_IMODE(dedicated.lstat().st_mode) == 0o755
        and stat.S_IMODE(default_root.lstat().st_mode) == 0o755,
        "stage did not reconcile both dedicated ancestry modes",
    )

    release = Path(str(first["release"]))
    marker = release / SOURCE_PREFIX / "committed-marker.txt"
    with mock.patch.object(bridge, "DEFAULT_RELEASE_ROOT", default_root):
        bridge.verify_release(release, release_root=default_root)
        dedicated.chmod(0o700)
        _expect_bridge_error(
            bridge,
            lambda: bridge.verify_release(release, release_root=default_root),
            "ancestry mode is not 0755",
        )
        dedicated.chmod(0o755)

    # Exact modes are the portable proof.  When the test itself is privileged,
    # additionally open the committed bytes as a genuinely unprivileged UID.
    traverse = (root, opt, dedicated, default_root, release)
    _expect(
        all(stat.S_IMODE(path.lstat().st_mode) & 0o005 == 0o005 for path in traverse),
        "an immutable release ancestor is not world-traversable/readable",
    )
    _expect(
        stat.S_IMODE(marker.lstat().st_mode) & 0o004 == 0o004,
        "immutable release file is not readable by enrolled canary UIDs",
    )
    if os.geteuid() == 0:
        try:
            unprivileged = pwd.getpwnam("nobody")
        except KeyError:
            unprivileged = None
        if unprivileged is not None:
            completed = subprocess.run(
                [
                    "/usr/bin/setpriv",
                    "--reuid",
                    str(unprivileged.pw_uid),
                    "--regid",
                    str(unprivileged.pw_gid),
                    "--clear-groups",
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()",
                    str(marker),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            _expect(
                completed.returncode == 0,
                "unprivileged UID could not read the immutable release: "
                + completed.stderr[:1024],
            )

    # The successor deliberately uses a second, equally narrow dedicated
    # release ancestry so its canary never imports the predecessor's runtime
    # bytecode cache.  A restrictive umask and an idempotent replay must have
    # the same visibility guarantees as the primary bridge root.
    clean_root = opt / "devcoordinator-legacy-broker-clean/releases"
    prior_umask = os.umask(0o077)
    try:
        with mock.patch.object(bridge, "DEFAULT_CLEAN_RELEASE_ROOT", clean_root):
            clean_first = bridge.stage_release(
                repo=repository,
                commit=commit,
                release_root=clean_root,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            )
    finally:
        os.umask(prior_umask)
    clean_dedicated = clean_root.parent
    _expect(
        stat.S_IMODE(clean_dedicated.lstat().st_mode) == 0o755
        and stat.S_IMODE(clean_root.lstat().st_mode) == 0o755,
        "clean successor release ancestry is not exactly 0755",
    )
    clean_dedicated.chmod(0o700)
    clean_root.chmod(0o700)
    with mock.patch.object(bridge, "DEFAULT_CLEAN_RELEASE_ROOT", clean_root):
        clean_replay = bridge.stage_release(
            repo=repository,
            commit=commit,
            release_root=clean_root,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        bridge.verify_release(
            Path(str(clean_first["release"])), release_root=clean_root
        )
    _expect(
        clean_replay.get("created") is False
        and stat.S_IMODE(clean_dedicated.lstat().st_mode) == 0o755
        and stat.S_IMODE(clean_root.lstat().st_mode) == 0o755,
        "clean successor release replay did not repair public ancestry",
    )

    _expect_bridge_error(
        bridge,
        lambda: bridge._require_release_root(
            Path("/opt/devcoordinator-legacy-broker-rogue/releases"),
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        ),
        "not one of the sealed dedicated roots",
    )


def _exercise_unsealed_bytecode_rejected(bridge: ModuleType, release: Path) -> None:
    import py_compile

    package = release / SOURCE_PREFIX / "devcoordinator"
    cache = package / "__pycache__"
    package.chmod(0o755)
    cache.mkdir(mode=0o755)
    source = package / "schema.py"
    bytecode = cache / (
        "schema."
        + str(__import__("sys").implementation.cache_tag)
        + ".pyc"
    )
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    bytecode.chmod(0o644)
    package.chmod(0o555)
    _expect_bridge_error(
        bridge,
        lambda: bridge.verify_release(release, release_root=release.parent),
        "unsealed entries",
    )
    verified = bridge.verify_release(
        release,
        release_root=release.parent,
        _allow_verified_bytecode_cache=True,
    )
    cache_evidence = verified.get("verified_unsealed_bytecode_cache")
    _expect(
        isinstance(cache_evidence, list)
        and len(cache_evidence) == 1
        and cache_evidence[0]["source"].endswith("/schema.py"),
        "compiler-identical predecessor bytecode was not narrowly admitted",
    )
    original = bytecode.read_bytes()
    bytecode.chmod(0o644)
    bytecode.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    bytecode.chmod(0o644)
    _expect_bridge_error(
        bridge,
        lambda: bridge.verify_release(
            release,
            release_root=release.parent,
            _allow_verified_bytecode_cache=True,
        ),
        "sealed predecessor source",
    )
    bytecode.write_bytes(original)
    bytecode.chmod(0o644)
    unexpected = cache / "payload.txt"
    unexpected.write_text("unsealed\n", encoding="utf-8")
    unexpected.chmod(0o644)
    _expect_bridge_error(
        bridge,
        lambda: bridge.verify_release(
            release,
            release_root=release.parent,
            _allow_verified_bytecode_cache=True,
        ),
        "unsafe",
    )
    unexpected.unlink()
    bytecode.unlink()
    package.chmod(0o755)
    cache.rmdir()
    package.chmod(0o555)


def _authority_snapshot(
    *, state_revision: int = 93359, observation_revision: int = 170
) -> dict[str, object]:
    return {
        "metadata": {
            "schema_version": 12,
            "database_generation": "schema12-generation",
            "state_revision": state_revision,
            "observation_revision": observation_revision,
            "authority_mode": "sqlite",
            "migration_state": "ready",
            "first_sqlite_mutation_at": "2026-07-28T00:00:00.000Z",
            "created_at": "2026-07-28T00:00:00.000Z",
            "updated_at": "2026-07-28T01:00:00.000Z",
        },
        "invariants": {
            "quick_check": "ok",
            "foreign_key_violations": 0,
            "repositories": 3,
            "installations": 3,
            "principals": 2,
            "enrollments": 4,
            "hosts": 1,
            "open_blocking_conflicts": 0,
            "missing_installations": 0,
            "orphan_installations": 0,
            "orphan_repository_enrollments": 0,
            "orphan_principal_enrollments": 0,
            "partial_v13_tables": [],
        },
    }


def _exercise_descendant_retry_contract(bridge: ModuleType, root: Path) -> None:
    origin_snapshot = _authority_snapshot()
    origin = {
        "database_identity": {"device": 7, "inode": 11, "size": 4096},
        "snapshot": origin_snapshot,
    }
    descendant = copy.deepcopy(origin_snapshot)
    descendant["metadata"]["state_revision"] = 93364
    descendant["metadata"]["updated_at"] = "2026-07-28T01:05:00.000Z"
    bridge._validate_readiness_descendant(
        origin,
        current_identity={"device": 7, "inode": 11, "size": 8192},
        snapshot=descendant,
    )

    def rejected(candidate: dict[str, object], identity: dict[str, int]) -> None:
        _expect_bridge_error(
            bridge,
            lambda: bridge._validate_readiness_descendant(
                origin,
                current_identity=identity,
                snapshot=candidate,
            ),
            "not a safe descendant",
        )

    changed_generation = copy.deepcopy(descendant)
    changed_generation["metadata"]["database_generation"] = "other-generation"
    rejected(changed_generation, {"device": 7, "inode": 11, "size": 8192})
    rejected(descendant, {"device": 7, "inode": 12, "size": 8192})

    changed_inventory = copy.deepcopy(descendant)
    changed_inventory["invariants"]["repositories"] = 4
    changed_inventory["invariants"]["installations"] = 4
    rejected(changed_inventory, {"device": 7, "inode": 11, "size": 8192})

    regressed_revision = copy.deepcopy(descendant)
    regressed_revision["metadata"]["state_revision"] = 93358
    rejected(regressed_revision, {"device": 7, "inode": 11, "size": 8192})

    regressed_time = copy.deepcopy(descendant)
    regressed_time["metadata"]["updated_at"] = "2026-07-27T23:59:00.000Z"
    rejected(regressed_time, {"device": 7, "inode": 11, "size": 8192})

    dropin = root / "missing-bridge.conf"
    release = root / ("a" * 64)
    dropin_sha = "b" * 64
    error = (
        "command failed (2): /usr/bin/setpriv --reuid 1000: /usr/bin/python3: "
        f"can't open file '{release / bridge.ENTRY_RELATIVE}': "
        "[Errno 13] Permission denied"
    )
    current = {
        "schema_version": bridge.CONTRACT_VERSION,
        "phase": "failed",
        "attempts": 1,
        "activation": None,
        "error": error,
        "release": str(release),
        "dropin_sha256": dropin_sha,
        "dropin_identity": {
            "device": 1,
            "inode": 2,
            "size": 300,
            "mtime_ns": 4,
            "ctime_ns": 5,
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "nlink": 1,
            "sha256": dropin_sha,
        },
        "readiness": {"state_revision": 93359},
    }
    baseline = {"ActiveState": "inactive", "SubState": "dead", "MainPID": 0}
    upgraded = bridge._legacy_v1_retry_upgrade(
        current,
        readiness_origin=origin,
        baseline=baseline,
        dropin=dropin,
    )
    upgraded["schema_version"] = bridge.JOURNAL_CONTRACT_VERSION
    _expect(
        bridge._descendant_retry_allowed(upgraded),
        "exact v1 canary incident did not authorize one descendant retry",
    )

    for field, value in (("attempts", 2), ("error", error + " unrelated")):
        unrelated = dict(current)
        unrelated[field] = value
        _expect_bridge_error(
            bridge,
            lambda unrelated=unrelated: bridge._legacy_v1_retry_upgrade(
                unrelated,
                readiness_origin=origin,
                baseline=baseline,
                dropin=dropin,
            ),
            "not the exact canary incident",
        )


def _exercise_fresh_predecessor_contract(bridge: ModuleType, root: Path) -> None:
    transaction = root / "failed-predecessor"
    transaction.mkdir(mode=0o700)
    release = root / ("a" * 64)
    socket_path = root / "broker.sock"
    dropin = root / "bridge.conf"
    operation_id = str(uuid.uuid4())
    origin = {
        "path": str(root / "readiness.json"),
        "document_sha256": "1" * 64,
        "database_identity": {"device": 7, "inode": 11, "size": 4096},
        "database_generation": "generation-1",
        "state_revision": 41,
        "snapshot": _authority_snapshot(state_revision=41),
    }
    error = "second corrected-owner canary failed"
    systemd_ready = {
        "systemd": {"InvocationID": "bridge-invocation"},
        "dropin_identity": {"sha256": "b" * 64},
        "readiness_state_revision": 42,
    }
    predecessor = bridge._journal(
        transaction / bridge.JOURNAL_NAME,
        {
            "operation_id": operation_id,
            "release": str(release),
            "release_digest": "c" * 64,
            "dropin": str(dropin),
            "dropin_sha256": "b" * 64,
            "dropin_identity": {"sha256": "b" * 64},
            "broker_socket": str(socket_path),
            "failed_activation": {"operation_id": str(uuid.uuid4())},
            "readiness": {"state_revision": 42},
            "canaries": [
                {"user": "valid-owner", "uid": 1000, "project": "/project"}
            ],
            "baseline": {
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": 0,
            },
            "phase": "failed",
            "attempts": 1,
            "activation": {"systemd": {"InvocationID": "bridge-invocation"}},
            "error": error,
            "created_at_epoch": 1,
            "updated_at_epoch": 2,
            "readiness_origin": origin,
            "attempt_evidence": {
                "attempt": 1,
                "stage": "failed",
                "last_completed_stage": "systemd-ready",
                "systemd_ready": systemd_ready,
                "failure_stage": "canaries",
                "error_sha256": hashlib.sha256(error.encode()).hexdigest(),
            },
        },
        uid=os.geteuid(),
    )
    journal = transaction / bridge.JOURNAL_NAME
    raw_sha256 = bridge._sha256_file(journal)
    accepted = {"state_revision": 43, "database_generation": "generation-1"}
    with mock.patch.object(
        bridge, "_readiness_origin_from_attestation", return_value=origin
    ), mock.patch.object(bridge, "_readiness_proof", return_value=accepted):
        evidence, current, returned_origin = bridge._failed_predecessor_readiness(
            transaction=transaction,
            raw_sha256=raw_sha256,
            document_sha256=str(predecessor["document_sha256"]),
            operation_id=operation_id,
            release=release,
            release_digest="c" * 64,
            broker_socket=socket_path,
            dropin=dropin,
            dropin_sha256="b" * 64,
            readiness_attestation=root / "readiness.json",
            database=root / "authority.sqlite3",
            baseline={"ActiveState": "inactive", "SubState": "dead", "MainPID": 0},
            expected_uid=os.geteuid(),
        )
        _expect(current == accepted, "fresh retry lost accepted descendant readiness")
        _expect(returned_origin == origin, "fresh retry lost readiness origin")
        _expect(
            evidence["journal_raw_sha256"] == raw_sha256
            and evidence["journal_document_sha256"]
            == predecessor["document_sha256"]
            and "canaries" not in evidence,
            "fresh retry did not bind exact predecessor evidence independently of canaries",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._failed_predecessor_readiness(
                transaction=transaction,
                raw_sha256=raw_sha256,
                document_sha256="d" * 64,
                operation_id=operation_id,
                release=release,
                release_digest="c" * 64,
                broker_socket=socket_path,
                dropin=dropin,
                dropin_sha256="b" * 64,
                readiness_attestation=root / "readiness.json",
                database=root / "authority.sqlite3",
                baseline={
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "MainPID": 0,
                },
                expected_uid=os.geteuid(),
            ),
            "not an exact durable canary-stage failure",
        )


def _exercise_successor_readiness_lineage_contract(
    bridge: ModuleType, root: Path
) -> None:
    attestation = root / "successor-readiness-attestation.json"
    snapshot = _authority_snapshot(state_revision=41)
    identity = {"device": 7, "inode": 11, "size": 4096}
    document = {
        "document_sha256": "1" * 64,
        "database_identity_after": identity,
        "postcondition": snapshot,
    }
    origin = {
        "path": str(attestation),
        "document_sha256": document["document_sha256"],
        "database_identity": identity,
        "database_generation": "schema12-generation",
        "state_revision": 41,
        "snapshot": snapshot,
    }
    cutover = SimpleNamespace(_authority_readiness_result=lambda _raw: document)
    with mock.patch.object(bridge, "_read_private_json", return_value={}), mock.patch.object(
        bridge, "_load_cutover_module", return_value=cutover
    ):
        _expect(
            bridge._readiness_origin_from_attestation(
                attestation, origin, uid=os.geteuid()
            )
            == origin,
            "successor readiness lineage did not retain the exact sealed origin",
        )
        changed_snapshot = copy.deepcopy(origin)
        changed_snapshot["snapshot"]["metadata"]["state_revision"] = 42
        _expect_bridge_error(
            bridge,
            lambda: bridge._readiness_origin_from_attestation(
                attestation, changed_snapshot, uid=os.geteuid()
            ),
            "does not match its sealed attestation",
        )
        extra_field = {**origin, "caller_authorized": True}
        _expect_bridge_error(
            bridge,
            lambda: bridge._readiness_origin_from_attestation(
                attestation, extra_field, uid=os.geteuid()
            ),
            "omitted authority readiness evidence",
        )

    cache_digest = hashlib.sha256(b"[]").hexdigest()
    proof_values = {
        "operation_id": str(uuid.uuid4()),
        "bridge_journal": str(root / "predecessor" / bridge.JOURNAL_NAME),
        "bridge_journal_sha256": "2" * 64,
        "bridge_document_sha256": "3" * 64,
        "broker_release": str(root / ("4" * 64)),
        "broker_release_digest": "5" * 64,
        "historical_client_release": str(root / ("6" * 64)),
        "historical_client_release_digest": "5" * 64,
        "verified_unsealed_bytecode_cache": [],
        "verified_unsealed_bytecode_cache_sha256": cache_digest,
        "readiness_origin": origin,
        "readiness_origin_sha256": hashlib.sha256(
            json.dumps(origin, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "database": str(root / "authority.sqlite3"),
        "database_generation": "schema12-generation",
        "profile": str(root / "client-profiles.json"),
        "profile_identity": {},
        "legacy_profile_repository": {
            "client_uid": 1000,
            "account_id": "account",
            "repository_id": "repo",
            "canonical_root": str(root / "GlobalFinance"),
            "generation": 2,
            "owner_uid_present": False,
        },
        "broker_socket": str(root / "broker.sock"),
        "socket_identity": {},
        "socket_peer": {},
        "dropin": str(root / "bridge.conf"),
        "dropin_identity": {},
        "systemd": {},
        "execution": {},
        "process": {},
        "canary": {},
        "verified_at_epoch": 1,
    }
    proof = bridge._seal(bridge.SUCCESSOR_PREDECESSOR_PROOF_KIND, proof_values)
    bridge._verify_successor_predecessor_proof(proof)
    rearmed_values = {
        **proof_values,
        "outer_rearm": {
            "journal": str(root / bridge.LIFECYCLE_REARM_JOURNAL_NAME),
            "journal_document_sha256": "7" * 64,
            "outer_transaction_journal": str(
                root / "lifecycle-service-intent.json"
            ),
            "outer_transaction_document_sha256": "8" * 64,
        },
    }
    bridge._verify_successor_predecessor_proof(
        bridge._seal(
            bridge.SUCCESSOR_PREDECESSOR_PROOF_KIND, rearmed_values
        )
    )
    invalid_rearm = copy.deepcopy(rearmed_values)
    invalid_rearm["outer_rearm"]["journal_document_sha256"] = "not-a-digest"
    _expect_bridge_error(
        bridge,
        lambda: bridge._verify_successor_predecessor_proof(
            bridge._seal(
                bridge.SUCCESSOR_PREDECESSOR_PROOF_KIND, invalid_rearm
            )
        ),
        "reference digest is invalid",
    )
    tampered_values = dict(proof_values)
    tampered_origin = copy.deepcopy(origin)
    tampered_origin["state_revision"] = 42
    tampered_values["readiness_origin"] = tampered_origin
    _expect_bridge_error(
        bridge,
        lambda: bridge._verify_successor_predecessor_proof(
            bridge._seal(
                bridge.SUCCESSOR_PREDECESSOR_PROOF_KIND, tampered_values
            )
        ),
        "proof binding is invalid",
    )

    parser = bridge._parser()
    activate_parser = next(
        action.choices["activate"]
        for action in parser._actions
        if isinstance(getattr(action, "choices", None), dict)
        and "activate" in action.choices
    )
    option_strings = {
        option
        for action in activate_parser._actions
        for option in action.option_strings
    }
    _expect(
        all("readiness-origin" not in option for option in option_strings),
        "bridge activate CLI exposed successor readiness authority",
    )


def _exercise_successor_predecessor_cache_replay_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "successor-predecessor-cache-replay"
    case.mkdir(mode=0o700)
    transaction = case / "predecessor"
    transaction.mkdir(mode=0o700)
    journal = transaction / bridge.JOURNAL_NAME
    journal.write_text("sealed predecessor journal\n", encoding="utf-8")
    journal.chmod(0o600)
    operation_id = str(uuid.uuid4())
    document_sha256 = "1" * 64
    release_digest = "2" * 64
    release = case / release_digest
    broker_socket = case / "broker.sock"
    dropin = case / "bridge.conf"
    readiness_origin = {
        "path": str(case / "readiness.json"),
        "document_sha256": "3" * 64,
    }
    cache_evidence = [
        {
            "path": (
                "skills/codex-dev-coordinator/scripts/devcoordinator/"
                "__pycache__/schema.cpython-313.pyc"
            ),
            "source": (
                "skills/codex-dev-coordinator/scripts/devcoordinator/schema.py"
            ),
            "sha256": "4" * 64,
            "size": 1024,
            "mode": "0444",
        }
    ]
    cache_sha256 = bridge._sha256_bytes(
        bridge._canonical(cache_evidence)
    )
    proof = {
        "operation_id": operation_id,
        "bridge_journal": str(journal),
        "bridge_journal_sha256": hashlib.sha256(
            journal.read_bytes()
        ).hexdigest(),
        "bridge_document_sha256": document_sha256,
        "broker_release": str(release),
        "broker_release_digest": release_digest,
        "verified_unsealed_bytecode_cache": cache_evidence,
        "verified_unsealed_bytecode_cache_sha256": cache_sha256,
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "dropin_identity": {"sha256": "5" * 64},
        "readiness_origin": readiness_origin,
        "readiness_origin_sha256": bridge._sha256_bytes(
            bridge._canonical(readiness_origin)
        ),
    }
    bridge_journal = {
        "operation_id": operation_id,
        "document_sha256": document_sha256,
        "phase": "ready",
        "release_digest": release_digest,
        "dropin_sha256": "5" * 64,
        "dropin_identity": {"sha256": "5" * 64},
        "readiness_origin": readiness_origin,
    }
    manifest = {
        "release_digest": release_digest,
        "verified_unsealed_bytecode_cache": cache_evidence,
        "verified_unsealed_bytecode_cache_sha256": cache_sha256,
    }
    verifier_calls: list[dict[str, object]] = []

    def verify_release(*_args, **kwargs):
        verifier_calls.append(dict(kwargs))
        return dict(manifest)

    arguments = {
        "transaction": transaction,
        "operation_id": operation_id,
        "journal_sha256": proof["bridge_journal_sha256"],
        "document_sha256": document_sha256,
        "ready_proof": proof,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_uid": os.geteuid(),
    }
    with (
        mock.patch.object(
            bridge,
            "_verify_successor_predecessor_proof",
            side_effect=lambda value: dict(value),
        ),
        mock.patch.object(
            bridge, "_load_bridge_journal", return_value=bridge_journal
        ),
        mock.patch.object(
            bridge, "_verify_activation_release", side_effect=verify_release
        ),
        mock.patch.object(
            bridge,
            "_readiness_origin_from_attestation",
            return_value=readiness_origin,
        ),
    ):
        reference = bridge._successor_predecessor_reference(**arguments)
        _expect(
            reference["release_digest"] == release_digest
            and verifier_calls[-1].get("allow_verified_bytecode_cache")
            is True,
            "successor replay did not narrowly admit verified predecessor bytecode",
        )
        manifest["verified_unsealed_bytecode_cache"] = []
        manifest["verified_unsealed_bytecode_cache_sha256"] = (
            bridge._sha256_bytes(bridge._canonical([]))
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._successor_predecessor_reference(**arguments),
            "release changed",
        )
        changed_evidence = [dict(cache_evidence[0], sha256="6" * 64)]
        manifest["verified_unsealed_bytecode_cache"] = changed_evidence
        manifest["verified_unsealed_bytecode_cache_sha256"] = (
            bridge._sha256_bytes(bridge._canonical(changed_evidence))
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._successor_predecessor_reference(**arguments),
            "release changed",
        )
        manifest["verified_unsealed_bytecode_cache"] = cache_evidence
        manifest["verified_unsealed_bytecode_cache_sha256"] = "7" * 64
        _expect_bridge_error(
            bridge,
            lambda: bridge._successor_predecessor_reference(**arguments),
            "release changed",
        )


def _exercise_lifecycle_successor_producer_split_contract(
    bridge: ModuleType,
) -> None:
    current_release = bridge.ROOT.resolve(strict=True)
    historical_release = current_release.parent / ("8" * 64)
    current_digest = "9" * 64
    historical_digest = "a" * 64
    calls: list[tuple[str, Path, int]] = []

    def verify_current(release: Path, *, owner_uid: int):
        calls.append(("current", release, owner_uid))
        return {"release_digest": current_digest}

    def verify_historical(release: Path, *, owner_uid: int):
        calls.append(("historical", release, owner_uid))
        return {"release_digest": historical_digest}

    with (
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            side_effect=verify_current,
        ),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=verify_historical,
        ),
    ):
        release, manifest = bridge._verified_lifecycle_producer_release(
            {
                "release": str(current_release),
                "release_digest": current_digest,
            },
            expected_uid=os.geteuid(),
        )
        _expect(
            release == current_release
            and manifest["release_digest"] == current_digest
            and calls == [("current", current_release, os.geteuid())],
            "lifecycle successor did not verify its current producer",
        )
        release, manifest = bridge._verified_lifecycle_producer_release(
            {
                "release": str(historical_release),
                "release_digest": historical_digest,
            },
            expected_uid=os.geteuid(),
        )
        _expect(
            release == historical_release
            and manifest["release_digest"] == historical_digest
            and calls[-1]
            == ("historical", historical_release, os.geteuid()),
            "lifecycle successor collapsed its historical producer into the executor",
        )
        for invalid in (
            {},
            {"release": "relative-release", "release_digest": current_digest},
            {
                "release": str(current_release / ".." / current_release.name),
                "release_digest": current_digest,
            },
            {"release": str(current_release), "release_digest": "invalid"},
        ):
            _expect_bridge_error(
                bridge,
                lambda invalid=invalid: (
                    bridge._verified_lifecycle_producer_release(
                        invalid, expected_uid=os.geteuid()
                    )
                ),
                "binding is invalid",
            )
        _expect_bridge_error(
            bridge,
            lambda: bridge._verified_lifecycle_producer_release(
                {
                    "release": str(current_release),
                    "release_digest": "b" * 64,
                },
                expected_uid=os.geteuid(),
            ),
            "digest changed",
        )


def _exercise_clean_successor_canary_phase_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "clean-successor-canary-phases"
    case.mkdir(mode=0o700)
    transaction = case / "candidate"
    transaction.mkdir(mode=0o700)
    journal = transaction / bridge.JOURNAL_NAME
    journal.write_text("candidate journal\n", encoding="utf-8")
    journal.chmod(0o600)
    operation_id = str(uuid.uuid4())
    journal_sha256 = hashlib.sha256(journal.read_bytes()).hexdigest()
    document_sha256 = "c" * 64
    broker_digest = "d" * 64
    client_digest = "e" * 64
    executor_digest = "9" * 64
    broker_release = case / broker_digest
    client_release = case / client_digest
    rescue_executor = case / executor_digest
    broker_release.mkdir(mode=0o700)
    client_release.mkdir(mode=0o700)
    rescue_executor.mkdir(mode=0o700)
    profile = case / "client-profiles.json"
    database = case / "authority.sqlite3"
    broker_socket = case / "broker.sock"
    dropin = case / "bridge.conf"
    project = case / "GlobalFinance"
    accounts = [
        {"user": "owner", "uid": 1000},
        {"user": "collaborator", "uid": 1001},
    ]
    bridge_journal = {
        "operation_id": operation_id,
        "document_sha256": document_sha256,
        "phase": "ready",
        "release": str(broker_release),
        "release_digest": broker_digest,
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "dropin_sha256": "f" * 64,
        "dropin_identity": {"sha256": "f" * 64},
    }
    state = {"InvocationID": "candidate-invocation", "MainPID": 4242}
    calls: list[dict[str, object]] = []

    def repository_binding(_profile: Path, **values: object):
        return {
            "client_uid": values["client_uid"],
            "repository_id": "repo-global-finance",
            "canonical_root": str(project),
            "generation": 4,
            "owner_uid": 1000,
        }

    def inventory_canary(**values: object):
        calls.append(dict(values))
        internal = bool(values.get("_cutover_maintenance_inventory_read"))
        account = values["account"]
        return {
            "user": account.pw_name,
            "uid": account.pw_uid,
            "project": str(project),
            "inventory_sha256": ("1" if internal else "2") * 64,
            "authority": {
                "scope": "server-wide",
                "transport": "authenticated-unix-socket",
                "socket": str(broker_socket),
                "service_uid": 0,
                "database_generation": "generation-12",
            },
            "repository": {
                "repository_id": "repo-global-finance",
                "canonical_root": str(project),
                "generation": 4,
            },
        }

    arguments = {
        "transaction": transaction,
        "operation_id": operation_id,
        "expected_journal_sha256": journal_sha256,
        "expected_journal_document_sha256": document_sha256,
        "broker_release": broker_release,
        "client_release": client_release,
        "database": database,
        "profile": profile,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": "generation-12",
        "canary_user": "owner",
        "expected_canary_uid": 1000,
        "canary_accounts": accounts,
        "canary_project": project,
        "canary_repository_id": "repo-global-finance",
        "canary_repository_generation": 4,
        "wait_seconds": 5,
        "expected_uid": os.geteuid(),
    }
    users = {
        "owner": SimpleNamespace(pw_name="owner", pw_uid=1000),
        "collaborator": SimpleNamespace(
            pw_name="collaborator", pw_uid=1001
        ),
    }
    with (
        mock.patch.object(
            bridge, "_load_bridge_journal", return_value=bridge_journal
        ),
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={"release_digest": broker_digest},
        ),
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            return_value={"release_digest": client_digest},
        ) as current_client_verifier,
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            return_value={"release_digest": client_digest},
        ) as historical_client_verifier,
        mock.patch.object(
            bridge,
            "_verify_dropin_identity",
            return_value=bridge_journal["dropin_identity"],
        ),
        mock.patch.object(
            bridge,
            "_validate_successor_canary_accounts",
            return_value=accounts,
        ),
        mock.patch.object(
            bridge, "_profile_identity", return_value={"sha256": "3" * 64}
        ),
        mock.patch.object(
            bridge,
            "_profile_repository_binding",
            side_effect=repository_binding,
        ),
        mock.patch.object(bridge, "_wait_active", return_value=state),
        mock.patch.object(
            bridge, "_socket_identity", return_value={"inode": 7}
        ),
        mock.patch.object(
            bridge,
            "_verify_loaded_bridge_execution",
            return_value={"argv": ["/usr/bin/python3"]},
        ),
        mock.patch.object(
            bridge, "_broker_process_identity", return_value={"pid": 4242}
        ),
        mock.patch.object(
            bridge,
            "_broker_socket_peer",
            return_value={"pid": 4242, "uid": 0},
        ),
        mock.patch.object(
            bridge, "_inventory_canary", side_effect=inventory_canary
        ),
        mock.patch.object(
            bridge.pwd,
            "getpwnam",
            side_effect=lambda name: users[name],
        ),
    ):
        internal = bridge._verify_clean_successor_live(
            **arguments,
            _cutover_maintenance_inventory_read=True,
        )
        public = bridge._verify_clean_successor_live(**arguments)
        ordinary_calls = list(calls)
        calls.clear()
        executor_rescue = {
            "reason": bridge.SUCCESSOR_EXECUTOR_RESCUE_REASON,
            "rescue_path": bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
            "executor_rescue_sha256": "a" * 64,
            "client_release": str(client_release),
            "client_release_digest": client_digest,
            "executor_release": str(rescue_executor),
            "executor_release_digest": executor_digest,
            "source_profile_sha256": "b" * 64,
            "predecessor_lineage_sha256": "c" * 64,
            "first_handoff_sha256": "d" * 64,
            "owner_binding_refresh_sha256": "e" * 64,
        }
        bridge_journal["executor_rescue"] = executor_rescue
        with mock.patch.object(bridge, "ROOT", rescue_executor):
            rescue = bridge._verify_clean_successor_live(
                **arguments,
                executor_rescue_sha256="a" * 64,
                _executor_rescue_client_binding=executor_rescue,
                _cutover_maintenance_inventory_read=True,
            )
        rescue_calls = list(calls)
    _expect(
        len(ordinary_calls) == 4
        and all(call["release"] == client_release for call in ordinary_calls)
        and all(
            call.get("_cutover_maintenance_inventory_read") is True
            and call.get("_historical_release_digest") == client_digest
            and call.get("profile") == profile
            for call in ordinary_calls[:2]
        )
        and all(
            "_cutover_maintenance_inventory_read" not in call
            and "_historical_release_digest" not in call
            for call in ordinary_calls[2:]
        ),
        "clean successor did not split internal and public current-client canaries",
    )
    _expect(
        internal["client_release"] == str(client_release)
        and public["client_release"] == str(client_release)
        and bridge._successor_live_identity_binding(internal)
        == bridge._successor_live_identity_binding(public),
        "clean successor cross-clear proof lost current-client identity",
    )
    _expect(
        current_client_verifier.call_count == 2
        and historical_client_verifier.call_count == 1
        and len(rescue_calls) == 2
        and rescue["executor_rescue"] == executor_rescue
        and rescue["executor_rescue_sha256"] == "a" * 64
        and rescue["broker_release"] == str(broker_release)
        and rescue["executor_rescue"]["executor_release"]
        == str(rescue_executor)
        and rescue["broker_release"]
        != rescue["executor_rescue"]["executor_release"]
        and all(
            item.get("executor_rescue_sha256") == "a" * 64
            for item in rescue["canaries"]
        ),
        "real successor live proof did not isolate its retained-client rescue path",
    )
    changed = copy.deepcopy(public)
    changed["canaries"][0]["authority"]["database_generation"] = (
        "another-generation"
    )
    _expect(
        bridge._successor_live_identity_binding(internal)
        != bridge._successor_live_identity_binding(changed),
        "clean successor cross-clear binding ignored authority drift",
    )


def _exercise_cutover_current_client_loader_contract(
    bridge: ModuleType,
) -> None:
    release = bridge.ROOT.resolve(strict=True)
    digest = "4" * 64
    alias = f"_devcoordinator_schema12_canary_{digest}"
    try:
        with (
            mock.patch.object(
                bridge,
                "_verify_availability_client_release",
                return_value={"release_digest": digest},
            ),
            mock.patch.object(
                bridge,
                "_verify_activation_release",
                side_effect=AssertionError(
                    "current client reached schema-12 release verification"
                ),
            ),
        ):
            broker, profile = bridge._load_historical_canary_modules(
                release,
                expected_release_digest=digest,
            )
        _expect(
            Path(str(broker.__file__)).resolve()
            == release
            / bridge.SOURCE_PREFIX
            / "devcoordinator"
            / "broker.py"
            and Path(str(profile.__file__)).resolve()
            == release
            / bridge.SOURCE_PREFIX
            / "devcoordinator"
            / "broker_profile.py",
            "cutover inventory did not load the verified current client",
        )
    finally:
        for name in tuple(sys.modules):
            if name == alias or name.startswith(alias + "."):
                sys.modules.pop(name, None)

    with tempfile.TemporaryDirectory(
        prefix="devcoordinator-historical-canary-loader."
    ) as raw:
        case = Path(raw)
        availability_root = case / "availability" / "releases"
        legacy_root = case / "legacy" / "releases"
        availability_root.mkdir(parents=True)
        legacy_root.mkdir(parents=True)
        running = availability_root / ("5" * 64)
        retained = availability_root / ("6" * 64)
        legacy = legacy_root / ("7" * 64)
        source_package = (
            bridge.ROOT
            / bridge.SOURCE_PREFIX
            / "devcoordinator"
        )
        for release in (running, retained, legacy):
            package = release / bridge.SOURCE_PREFIX / "devcoordinator"
            package.parent.mkdir(parents=True)
            shutil.copytree(source_package, package)

        for release, digest, expected_verifier in (
            (retained, retained.name, "availability"),
            (legacy, legacy.name, "legacy"),
        ):
            alias = f"_devcoordinator_schema12_canary_{digest}"
            historical = mock.Mock(
                return_value={"release_digest": retained.name}
            )
            legacy_verify = mock.Mock(
                return_value={"release_digest": legacy.name}
            )
            try:
                with (
                    mock.patch.object(bridge, "ROOT", running),
                    mock.patch.object(
                        bridge,
                        "DEFAULT_AVAILABILITY_RELEASE_ROOT",
                        availability_root,
                    ),
                    mock.patch.object(
                        bridge,
                        "_verify_historical_availability_release",
                        historical,
                    ),
                    mock.patch.object(
                        bridge,
                        "_verify_activation_release",
                        legacy_verify,
                    ),
                ):
                    broker, profile = bridge._load_historical_canary_modules(
                        release,
                        expected_release_digest=digest,
                    )
                _expect(
                    Path(str(broker.__file__)).is_relative_to(release)
                    and Path(str(profile.__file__)).is_relative_to(release)
                    and historical.call_count
                    == (1 if expected_verifier == "availability" else 0)
                    and legacy_verify.call_count
                    == (1 if expected_verifier == "legacy" else 0),
                    "historical canary loader selected the wrong release verifier",
                )
            finally:
                for name in tuple(sys.modules):
                    if name == alias or name.startswith(alias + "."):
                        sys.modules.pop(name, None)


def _exercise_activate_internal_current_client_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "activate-internal-current-client"
    case.mkdir(mode=0o700)
    transaction = case / "transaction"
    transaction.mkdir(mode=0o700)
    release = case / ("5" * 64)
    client_release = case / ("6" * 64)
    rescue_executor = case / ("7" * 64)
    release.mkdir(mode=0o700)
    client_release.mkdir(mode=0o700)
    rescue_executor.mkdir(mode=0o700)
    database = case / "authority.sqlite3"
    profile = case / "client-profiles.json"
    broker_socket = case / "broker.sock"
    dropin = case / "bridge.conf"
    project = case / "GlobalFinance"
    operation_id = str(uuid.uuid4())
    failed_operation_id = str(uuid.uuid4())
    account = SimpleNamespace(pw_name="owner", pw_uid=1000, pw_gid=1000)
    failed = {"operation_id": failed_operation_id}
    readiness = {
        "database_generation": "generation-12",
        "state_revision": 42,
    }
    dropin_sha256 = bridge._sha256_bytes(
        bridge._dropin_payload(release, database, broker_socket)
    )
    canary_binding = {
        "user": account.pw_name,
        "uid": account.pw_uid,
        "project": str(project),
    }
    current = {
        "operation_id": operation_id,
        "release": str(release),
        "release_digest": "5" * 64,
        "dropin": str(dropin),
        "dropin_sha256": dropin_sha256,
        "broker_socket": str(broker_socket),
        "failed_activation": failed,
        "canaries": [canary_binding],
        "readiness": readiness,
        "readiness_origin": readiness,
        "phase": "ready",
        "dropin_identity": {"sha256": dropin_sha256},
        "activation": {
            "systemd": {"InvocationID": "candidate", "MainPID": 4242},
            "execution": {"argv": ["/usr/bin/python3"]},
            "canaries": [],
        },
        "created_at_epoch": 1,
        "updated_at_epoch": 1,
    }
    inventory_calls: list[dict[str, object]] = []

    @contextmanager
    def installer_lock(_uid: int):
        yield

    def inventory_canary(**values: object):
        inventory_calls.append(dict(values))
        return {
            "user": account.pw_name,
            "uid": account.pw_uid,
            "project": str(project),
            "inventory_sha256": "7" * 64,
            "authority": {},
            "repository": {
                "repository_id": "repo-global-finance",
                "canonical_root": str(project),
                "generation": 4,
            },
        }

    with (
        mock.patch.object(bridge, "_installer_lock", installer_lock),
        mock.patch.object(
            bridge,
            "_parse_canary",
            return_value=(account, project),
        ),
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={"release_digest": "5" * 64},
        ),
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            return_value={"release_digest": "6" * 64},
        ) as current_client_verifier,
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=lambda release, **_kwargs: {
                "release_digest": Path(release).name
            },
        ) as historical_client_verifier,
        mock.patch.object(
            bridge, "_failed_activation_proof", return_value=failed
        ),
        mock.patch.object(
            bridge, "_protected_profile", return_value=SimpleNamespace()
        ),
        mock.patch.object(
            bridge, "_load_bridge_journal", return_value=current
        ),
        mock.patch.object(
            bridge,
            "_readiness_origin_from_attestation",
            return_value=readiness,
        ),
        mock.patch.object(
            bridge,
            "_verify_retained_readiness_reference",
            return_value=readiness,
        ),
        mock.patch.object(bridge, "_verify_dropin_identity", return_value={}),
        mock.patch.object(
            bridge,
            "_wait_active",
            return_value={"InvocationID": "candidate", "MainPID": 4242},
        ),
        mock.patch.object(
            bridge,
            "_verify_loaded_bridge_execution",
            return_value={"argv": ["/usr/bin/python3"]},
        ),
        mock.patch.object(
            bridge,
            "_profile_repository_binding",
            return_value={"client_uid": account.pw_uid},
        ),
        mock.patch.object(
            bridge, "_inventory_canary", side_effect=inventory_canary
        ),
        mock.patch.object(
            bridge,
            "_journal",
            side_effect=lambda _path, payload, **_kwargs: {
                **payload,
                "document_sha256": "8" * 64,
            },
        ),
    ):
        result = bridge.activate_bridge(
            release=release,
            release_root=case,
            transaction=transaction,
            operation_id=operation_id,
            failed_installer_transaction=case / "failed",
            failed_installer_operation_id=failed_operation_id,
            readiness_attestation=case / "readiness.json",
            database=database,
            profile=profile,
            broker_socket=broker_socket,
            dropin=dropin,
            canaries=[f"owner={project}"],
            wait_seconds=5,
            expected_uid=os.geteuid(),
            client_release=client_release,
            _authorized_readiness_origin=readiness,
            _cutover_maintenance_inventory_read=True,
            _cutover_canary_repository_id="repo-global-finance",
            _cutover_canary_repository_generation=4,
            _cutover_expected_owner_uid=account.pw_uid,
        )
        ordinary_inventory_calls = list(inventory_calls)
        inventory_calls.clear()
        executor_rescue = {
            "reason": bridge.SUCCESSOR_EXECUTOR_RESCUE_REASON,
            "rescue_path": bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
            "executor_rescue_sha256": "a" * 64,
            "client_release": str(client_release),
            "client_release_digest": "6" * 64,
            "executor_release": str(rescue_executor),
            "executor_release_digest": "7" * 64,
            "source_profile_sha256": "b" * 64,
            "predecessor_lineage_sha256": "c" * 64,
            "first_handoff_sha256": "d" * 64,
            "owner_binding_refresh_sha256": "e" * 64,
        }
        current["executor_rescue"] = executor_rescue
        with mock.patch.object(bridge, "ROOT", rescue_executor):
            rescue_result = bridge.activate_bridge(
                release=release,
                release_root=case,
                transaction=transaction,
                operation_id=operation_id,
                failed_installer_transaction=case / "failed",
                failed_installer_operation_id=failed_operation_id,
                readiness_attestation=case / "readiness.json",
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                canaries=[f"owner={project}"],
                wait_seconds=5,
                expected_uid=os.geteuid(),
                client_release=client_release,
                _authorized_readiness_origin=readiness,
                _cutover_maintenance_inventory_read=True,
                _cutover_canary_repository_id="repo-global-finance",
                _cutover_canary_repository_generation=4,
                _cutover_expected_owner_uid=account.pw_uid,
                _executor_rescue_client_binding=executor_rescue,
            )
            _expect_bridge_error(
                bridge,
                lambda: bridge.activate_bridge(
                    release=release,
                    release_root=case,
                    transaction=transaction,
                    operation_id=operation_id,
                    failed_installer_transaction=case / "failed",
                    failed_installer_operation_id=failed_operation_id,
                    readiness_attestation=case / "readiness.json",
                    database=database,
                    profile=profile,
                    broker_socket=broker_socket,
                    dropin=dropin,
                    canaries=[f"owner={project}"],
                    wait_seconds=5,
                    expected_uid=os.geteuid(),
                    client_release=client_release,
                    _authorized_readiness_origin=readiness,
                    _cutover_maintenance_inventory_read=True,
                    _cutover_canary_repository_id=(
                        "repo-global-finance"
                    ),
                    _cutover_canary_repository_generation=4,
                    _cutover_expected_owner_uid=account.pw_uid,
                ),
                "executor rescue binding was omitted",
            )
        rescue_inventory_calls = list(inventory_calls)
        ordinary_client_verifier_calls = current_client_verifier.call_count
        historical_client_verifier_calls = historical_client_verifier.call_count
        inventory_calls.clear()
        original_executor = case / ("8" * 64)
        continuation_executor = case / ("9" * 64)
        original_executor.mkdir(mode=0o700)
        continuation_executor.mkdir(mode=0o700)
        continuation_runtime = {
            **executor_rescue,
            "executor_release": str(continuation_executor),
            "executor_release_digest": continuation_executor.name,
            "executor_rescue_handoff_sha256": "f" * 64,
            "original_executor_release": str(original_executor),
            "original_executor_release_digest": original_executor.name,
            "executor_rescue_post_export_continuation_sha256": "1" * 64,
            "handoff_executor_release": str(rescue_executor),
            "handoff_executor_release_digest": rescue_executor.name,
        }
        current["phase"] = "systemd-ready"
        current["executor_rescue"] = continuation_runtime
        current["attempt_evidence"] = {
            "attempt": 1,
            "stage": "systemd-ready",
            "last_completed_stage": "systemd-ready",
            "systemd_ready": {"InvocationID": "candidate"},
            "failure_stage": None,
            "error_sha256": None,
        }
        with mock.patch.object(bridge, "ROOT", continuation_executor):
            continuation_result = bridge.activate_bridge(
                release=release,
                release_root=case,
                transaction=transaction,
                operation_id=operation_id,
                failed_installer_transaction=case / "failed",
                failed_installer_operation_id=failed_operation_id,
                readiness_attestation=case / "readiness.json",
                database=database,
                profile=profile,
                broker_socket=broker_socket,
                dropin=dropin,
                canaries=[f"owner={project}"],
                wait_seconds=5,
                expected_uid=os.geteuid(),
                client_release=client_release,
                _authorized_readiness_origin=readiness,
                _cutover_maintenance_inventory_read=True,
                _cutover_canary_repository_id="repo-global-finance",
                _cutover_canary_repository_generation=4,
                _cutover_expected_owner_uid=account.pw_uid,
                _executor_rescue_client_binding=continuation_runtime,
            )
            with mock.patch.object(
                bridge,
                "_wait_active",
                return_value={"InvocationID": "wrong", "MainPID": 4242},
            ):
                _expect_bridge_error(
                    bridge,
                    lambda: bridge.activate_bridge(
                        release=release,
                        release_root=case,
                        transaction=transaction,
                        operation_id=operation_id,
                        failed_installer_transaction=case / "failed",
                        failed_installer_operation_id=failed_operation_id,
                        readiness_attestation=case / "readiness.json",
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        canaries=[f"owner={project}"],
                        wait_seconds=5,
                        expected_uid=os.geteuid(),
                        client_release=client_release,
                        _authorized_readiness_origin=readiness,
                        _cutover_maintenance_inventory_read=True,
                        _cutover_canary_repository_id="repo-global-finance",
                        _cutover_canary_repository_generation=4,
                        _cutover_expected_owner_uid=account.pw_uid,
                        _executor_rescue_client_binding=continuation_runtime,
                    ),
                    "execution changed during replay",
                )
            with mock.patch.object(
                bridge,
                "_verify_dropin_identity",
                side_effect=bridge.BridgeError("drop-in identity changed"),
            ):
                _expect_bridge_error(
                    bridge,
                    lambda: bridge.activate_bridge(
                        release=release,
                        release_root=case,
                        transaction=transaction,
                        operation_id=operation_id,
                        failed_installer_transaction=case / "failed",
                        failed_installer_operation_id=failed_operation_id,
                        readiness_attestation=case / "readiness.json",
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        canaries=[f"owner={project}"],
                        wait_seconds=5,
                        expected_uid=os.geteuid(),
                        client_release=client_release,
                        _authorized_readiness_origin=readiness,
                        _cutover_maintenance_inventory_read=True,
                        _cutover_canary_repository_id="repo-global-finance",
                        _cutover_canary_repository_generation=4,
                        _cutover_expected_owner_uid=account.pw_uid,
                        _executor_rescue_client_binding=continuation_runtime,
                    ),
                    "drop-in identity changed",
                )
            with mock.patch.object(
                bridge,
                "_protected_profile",
                side_effect=bridge.BridgeError("profile identity changed"),
            ):
                _expect_bridge_error(
                    bridge,
                    lambda: bridge.activate_bridge(
                        release=release,
                        release_root=case,
                        transaction=transaction,
                        operation_id=operation_id,
                        failed_installer_transaction=case / "failed",
                        failed_installer_operation_id=failed_operation_id,
                        readiness_attestation=case / "readiness.json",
                        database=database,
                        profile=profile,
                        broker_socket=broker_socket,
                        dropin=dropin,
                        canaries=[f"owner={project}"],
                        wait_seconds=5,
                        expected_uid=os.geteuid(),
                        client_release=client_release,
                        _authorized_readiness_origin=readiness,
                        _cutover_maintenance_inventory_read=True,
                        _cutover_canary_repository_id="repo-global-finance",
                        _cutover_canary_repository_generation=4,
                        _cutover_expected_owner_uid=account.pw_uid,
                        _executor_rescue_client_binding=continuation_runtime,
                    ),
                    "profile identity changed",
                )
        continuation_inventory_calls = list(inventory_calls)
    _expect(
        result.get("replayed") is True
        and len(ordinary_inventory_calls) == 1
        and ordinary_inventory_calls[0].get("release") == client_release
        and ordinary_inventory_calls[0].get("profile") == profile
        and ordinary_inventory_calls[0].get(
            "_cutover_maintenance_inventory_read"
        )
        is True
        and ordinary_inventory_calls[0].get("_historical_release_digest")
        == "6" * 64,
        "ready activation replay did not use the internal current-client canary",
    )
    _expect(
        ordinary_client_verifier_calls == 2
        and historical_client_verifier_calls == 1
        and rescue_result.get("replayed") is True
        and rescue_result.get("executor_rescue") == executor_rescue
        and rescue_result.get("release") == str(release)
        and rescue_result["executor_rescue"]["executor_release"]
        == str(rescue_executor)
        and rescue_result.get("release")
        != rescue_result["executor_rescue"]["executor_release"]
        and len(rescue_inventory_calls) == 1
        and rescue_result["activation"]["canaries"][0].get(
            "executor_rescue_sha256"
        )
        == "a" * 64,
        "real activation replay did not isolate its retained-client rescue path: "
        f"current={ordinary_client_verifier_calls}, "
        f"historical={historical_client_verifier_calls}, "
        f"replayed={rescue_result.get('replayed')}, "
        f"binding={rescue_result.get('executor_rescue') == executor_rescue}, "
        f"calls={rescue_inventory_calls!r}",
    )
    _expect(
        continuation_result.get("phase") == "ready"
        and continuation_result.get("replayed") is True
        and continuation_result.get("executor_rescue")
        == continuation_runtime
        and len(continuation_inventory_calls) == 1
        and continuation_result["activation"]["canaries"][0].get(
            "executor_rescue_sha256"
        )
        == continuation_runtime["executor_rescue_sha256"],
        "post-export continuation did not finalize its exact systemd-ready canaries: "
        f"result={continuation_result!r}, calls={continuation_inventory_calls!r}",
    )


def _exercise_executor_rescue_candidate_journal_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "executor-rescue-candidate-journal"
    case.mkdir(mode=0o700)
    candidate = case / ("4" * 64)
    executor = case / ("5" * 64)
    client = case / ("6" * 64)
    candidate.mkdir(mode=0o700)
    executor.mkdir(mode=0o700)
    client.mkdir(mode=0o700)
    runtime = {
        "reason": bridge.SUCCESSOR_EXECUTOR_RESCUE_REASON,
        "rescue_path": bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "executor_rescue_sha256": "a" * 64,
        "client_release": str(client),
        "client_release_digest": client.name,
        "executor_release": str(executor),
        "executor_release_digest": executor.name,
        "source_profile_sha256": "b" * 64,
        "predecessor_lineage_sha256": "c" * 64,
        "first_handoff_sha256": "d" * 64,
        "owner_binding_refresh_sha256": "e" * 64,
    }
    journal_path = case / bridge.JOURNAL_NAME
    payload = {
        "operation_id": str(uuid.uuid4()),
        "release": str(candidate),
        "release_digest": candidate.name,
        "dropin": str(case / "bridge.conf"),
        "dropin_sha256": "f" * 64,
        "dropin_identity": {"sha256": "f" * 64},
        "broker_socket": str(case / "broker.sock"),
        "failed_activation": {},
        "readiness": {},
        "canaries": [],
        "baseline": {},
        "phase": "ready",
        "attempts": 1,
        "activation": {"systemd": {}, "execution": {}, "canaries": []},
        "error": None,
        "created_at_epoch": 1,
        "updated_at_epoch": 2,
        "readiness_origin": {},
        "attempt_evidence": {},
        "executor_rescue": runtime,
    }
    with (
        mock.patch.object(bridge, "ROOT", executor),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            return_value={"release_digest": client.name},
        ) as historical_verifier,
    ):
        written = bridge._journal(
            journal_path, payload, uid=os.geteuid()
        )
        loaded = bridge._load_bridge_journal(
            journal_path, uid=os.geteuid()
        )
    _expect(
        written["schema_version"]
        == bridge.EXECUTOR_RESCUE_JOURNAL_CONTRACT_VERSION
        and loaded == written
        and loaded["executor_rescue"] == runtime
        and loaded["release"] == str(candidate)
        and loaded["executor_rescue"]["executor_release"] == str(executor)
        and loaded["release"]
        != loaded["executor_rescue"]["executor_release"]
        and historical_verifier.call_count == 1,
        "candidate journal did not retain its exact rescue lineage",
    )


def _exercise_handoff_cli_contract(bridge: ModuleType) -> None:
    parser = bridge._parser()
    actions = (
        "handoff-reference",
        "handoff-arm",
        "handoff-retire",
        "handoff-rollback-prepare",
        "handoff-rollback-unfence",
        "handoff-verify-rearmed",
        "handoff-complete",
    )
    for action in actions:
        parsed = parser.parse_args(
            [
                action,
                "--transaction-dir",
                "/tmp/bridge",
                "--operation-id",
                str(uuid.uuid4()),
                "--expected-journal-sha256",
                "a" * 64,
                "--outer-transaction-id",
                str(uuid.uuid4()),
                "--database",
                "/tmp/authority.sqlite3",
                "--profile",
                "/tmp/profile.json",
                "--socket",
                str(bridge.DEFAULT_SOCKET),
                "--dropin",
                str(bridge.DEFAULT_DROPIN),
                "--retirement-guard",
                str(bridge.DEFAULT_RETIREMENT_GUARD),
                "--handoff-journal",
                "/tmp/bridge/writer-handoff-journal.json",
            ]
        )
        _expect(parsed.action == action, f"handoff parser lost {action}")
    _expect(
        b"ConditionPathExists=!/" in bridge.RETIREMENT_GUARD_PAYLOAD,
        "legacy writer retirement guard is not fail-closed",
    )
    verify_ready = bridge._parser().parse_args(
        [
            "verify-ready",
            "--transaction-dir",
            "/tmp/bridge",
            "--operation-id",
            str(uuid.uuid4()),
            "--expected-journal-sha256",
            "a" * 64,
            "--expected-journal-document-sha256",
            "b" * 64,
            "--expected-database-generation",
            "generation-1",
            "--canary-user",
            pwd.getpwuid(os.geteuid()).pw_name,
            "--expected-canary-uid",
            str(os.geteuid()),
            "--canary-project",
            "/tmp/project",
            "--canary-repository-id",
            "repo-1",
            "--canary-repository-generation",
            "2",
        ]
    )
    _expect(
        verify_ready.action == "verify-ready",
        "bridge parser lost the pure ready verifier",
    )
    current = {
        "phase": "armed",
        "document_sha256": "a" * 64,
        "predecessor_sha256": "9" * 64,
    }
    _expect(
        bridge._handoff_predecessor(
            current,
            expected_sha256="a" * 64,
            source_phases={"armed"},
            target_phase="retired",
        )
        is False,
        "handoff transition did not consume its exact predecessor",
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._handoff_predecessor(
            current,
            expected_sha256="b" * 64,
            source_phases={"armed"},
            target_phase="retired",
        ),
        "predecessor evidence is invalid",
    )


def _exercise_successor_executor_rescue_cli_contract(
    bridge: ModuleType,
) -> None:
    parser = bridge._parser()
    digest = "a" * 64
    candidate_digest = "c" * 64
    common = [
        bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "--candidate-release", "/tmp/releases/" + candidate_digest,
        "--release-root", "/tmp/releases",
        "--transaction-dir", "/tmp/successor",
        "--operation-id", str(uuid.uuid4()),
        "--predecessor-transaction", "/tmp/predecessor",
        "--predecessor-operation-id", str(uuid.uuid4()),
        "--predecessor-journal-sha256", digest,
        "--predecessor-document-sha256", digest,
        "--failed-installer-transaction", "/tmp/failed",
        "--failed-installer-operation-id", str(uuid.uuid4()),
        "--readiness-attestation", "/tmp/readiness.json",
        "--owner-map", "/tmp/owners.json",
        "--owner-map-sha256", digest,
        "--expected-database-generation", "generation-12",
        "--canary-user", "owner",
        "--expected-canary-uid", "1000",
        "--canary-project", "/tmp/GlobalFinance",
        "--canary-repository-id", "repo-global-finance",
        "--canary-repository-generation", "4",
        "--lifecycle-transaction-journal", "/tmp/lifecycle.json",
        "--lifecycle-transaction-journal-sha256", digest,
        "--lifecycle-transaction-document-sha256", digest,
        "--lifecycle-attestation", "/tmp/lifecycle-attestation.json",
        "--lifecycle-attestation-sha256", digest,
        "--lifecycle-attestation-document-sha256", digest,
        "--additional-canary", "collaborator=1001",
    ]
    rescue_only = [
        "--inherited-successor-journal-sha256", digest,
        "--inherited-successor-document-sha256", digest,
        "--previous-executor-release", "/tmp/releases/" + ("b" * 64),
        "--previous-executor-release-digest", "b" * 64,
        "--retained-client-release", "/tmp/releases/" + ("b" * 64),
        "--retained-client-release-digest", "b" * 64,
        "--rescue-executor-release", "/tmp/releases/" + digest,
        "--rescue-executor-release-digest", digest,
    ]
    full = [*common, *rescue_only]
    parsed = parser.parse_args(full)
    _expect(
        parsed.action == bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH
        and not hasattr(parsed, "client_release")
        and parsed.inherited_successor_journal_sha256 == digest,
        "executor rescue parser exposed the ordinary client route",
    )


def _exercise_successor_executor_handoff_cli_contract(
    bridge: ModuleType,
) -> None:
    digest = "a" * 64
    old_digest = "b" * 64
    candidate_digest = "c" * 64
    command = [
        bridge.SUCCESSOR_EXECUTOR_HANDOFF_PATH,
        "--candidate-release", "/tmp/releases/" + candidate_digest,
        "--release-root", "/tmp/releases",
        "--transaction-dir", "/tmp/successor",
        "--operation-id", str(uuid.uuid4()),
        "--predecessor-transaction", "/tmp/predecessor",
        "--predecessor-operation-id", str(uuid.uuid4()),
        "--predecessor-journal-sha256", digest,
        "--predecessor-document-sha256", digest,
        "--failed-installer-transaction", "/tmp/failed",
        "--failed-installer-operation-id", str(uuid.uuid4()),
        "--readiness-attestation", "/tmp/readiness.json",
        "--owner-map", "/tmp/owners.json",
        "--owner-map-sha256", digest,
        "--expected-database-generation", "generation-12",
        "--canary-user", "owner",
        "--expected-canary-uid", "1000",
        "--canary-project", "/tmp/GlobalFinance",
        "--canary-repository-id", "repo-global-finance",
        "--canary-repository-generation", "4",
        "--lifecycle-transaction-journal", "/tmp/lifecycle.json",
        "--lifecycle-transaction-journal-sha256", digest,
        "--lifecycle-transaction-document-sha256", digest,
        "--lifecycle-attestation", "/tmp/lifecycle-attestation.json",
        "--lifecycle-attestation-sha256", digest,
        "--lifecycle-attestation-document-sha256", digest,
        "--additional-canary", "collaborator=1001",
        "--inherited-successor-journal-sha256", digest,
        "--inherited-successor-document-sha256", digest,
        "--previous-executor-release", "/tmp/releases/" + old_digest,
        "--previous-executor-release-digest", old_digest,
        "--retained-client-release", "/tmp/releases/" + ("d" * 64),
        "--retained-client-release-digest", "d" * 64,
        "--rescue-executor-release", "/tmp/releases/" + digest,
        "--rescue-executor-release-digest", digest,
        "--executor-rescue-sha256", "e" * 64,
    ]
    parser = bridge._parser()
    split = command.index("--inherited-successor-journal-sha256")
    common = list(command[:split])
    common[0] = bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH
    rescue_only = list(command[split:-2])
    retained_index = rescue_only.index("--retained-client-release")
    rescue_only[retained_index + 1] = "/tmp/releases/" + old_digest
    retained_digest_index = rescue_only.index(
        "--retained-client-release-digest"
    )
    rescue_only[retained_digest_index + 1] = old_digest
    full = [*common, *rescue_only]
    parsed = parser.parse_args(command)
    _expect(
        parsed.action == bridge.SUCCESSOR_EXECUTOR_HANDOFF_PATH
        and parsed.executor_rescue_sha256 == "e" * 64
        and parsed.previous_executor_release_digest == old_digest,
        "rescue executor handoff parser lost exact lineage evidence",
    )
    captured: dict[str, object] = {}

    def dispatch(**values: object) -> dict[str, object]:
        captured.update(values)
        return {"ok": True}

    with (
        mock.patch.object(
            bridge,
            "handoff_rescued_executor_with_clean_successor",
            side_effect=dispatch,
        ) as handoff_call,
        mock.patch.object(
            bridge,
            "rescue_ready_bridge_with_clean_successor",
            side_effect=AssertionError("handoff reached original rescue"),
        ),
        redirect_stdout(io.StringIO()),
    ):
        result = bridge.main(command)
    _expect(
        result == 0
        and handoff_call.call_count == 1
        and captured["executor_rescue_sha256"] == "e" * 64
        and captured["previous_executor_release_digest"] == old_digest
        and captured["successor_executor_release_digest"] == digest
        and captured["inherited_successor_journal_sha256"] == digest
        and "client_release" not in captured["successor_arguments"],
        "rescue executor handoff CLI crossed into another route",
    )
    rescue = {
        "operation_id": str(uuid.uuid4()),
        "reason": bridge.SUCCESSOR_EXECUTOR_RESCUE_REASON,
        "rescue_path": bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "client_release": "/tmp/releases/" + ("d" * 64),
        "client_release_digest": "d" * 64,
        "rescue_executor_release": "/tmp/releases/" + old_digest,
        "rescue_executor_release_digest": old_digest,
        "source_profile": {"profile": "sealed"},
        "predecessor_lineage": {"predecessor": "sealed"},
        "first_handoff": {"sha256": "f" * 64},
        "owner_binding_refresh_sha256": "1" * 64,
    }
    handoff = {
        "operation_id": rescue["operation_id"],
        "executor_rescue_sha256": hashlib.sha256(
            bridge._canonical(rescue)
        ).hexdigest(),
        "previous_executor_release": rescue["rescue_executor_release"],
        "previous_executor_release_digest": old_digest,
        "retained_client_release": rescue["client_release"],
        "retained_client_release_digest": "d" * 64,
        "successor_executor_release": "/tmp/releases/" + digest,
        "successor_executor_release_digest": digest,
        "source_profile_sha256": hashlib.sha256(
            bridge._canonical(rescue["source_profile"])
        ).hexdigest(),
        "predecessor_lineage_sha256": hashlib.sha256(
            bridge._canonical(rescue["predecessor_lineage"])
        ).hexdigest(),
        "first_handoff_sha256": "f" * 64,
        "owner_binding_refresh_sha256": "1" * 64,
    }
    original = copy.deepcopy(rescue)
    with (
        mock.patch.object(
            bridge,
            "_validated_successor_executor_rescue",
            return_value=copy.deepcopy(rescue),
        ),
        mock.patch.object(
            bridge,
            "_validated_successor_executor_handoff",
            return_value=copy.deepcopy(handoff),
        ),
    ):
        runtime = bridge._successor_executor_rescue_runtime_binding(
            rescue,
            expected_uid=os.geteuid(),
            handoff_value=handoff,
        )
    _expect(
        rescue == original
        and runtime["executor_release"]
        == handoff["successor_executor_release"]
        and runtime["original_executor_release"]
        == rescue["rescue_executor_release"]
        and runtime["executor_rescue_sha256"]
        == handoff["executor_rescue_sha256"]
        and runtime["executor_rescue_handoff_sha256"]
        == hashlib.sha256(bridge._canonical(handoff)).hexdigest(),
        "rescue executor handoff mutated or replaced original rescue evidence",
    )
    for index in range(0, len(rescue_only), 2):
        missing = [
            *common,
            *rescue_only[:index],
            *rescue_only[index + 2 :],
        ]
        with mock.patch.object(sys, "stderr", io.StringIO()):
            try:
                parser.parse_args(missing)
            except SystemExit as error:
                _expect(
                    error.code == 2,
                    "executor rescue missing evidence did not fail parsing",
                )
            else:
                _fail(
                    "executor rescue parser accepted missing mandatory evidence: "
                    + rescue_only[index]
                )
    with mock.patch.object(sys, "stderr", io.StringIO()):
        try:
            parser.parse_args([*full, "--client-release", "/tmp/client"])
        except SystemExit as error:
            _expect(error.code == 2, "rescue client alias failed open")
        else:
            _fail("executor rescue parser accepted --client-release")
    captured: dict[str, object] = {}

    def rescue_dispatch(**values: object) -> dict[str, object]:
        captured.update(values)
        return {"ok": True}

    with (
        mock.patch.object(
            bridge,
            "rescue_ready_bridge_with_clean_successor",
            side_effect=rescue_dispatch,
        ) as rescue_call,
        mock.patch.object(
            bridge,
            "replace_ready_bridge_with_clean_successor",
            side_effect=AssertionError("rescue reached ordinary successor"),
        ),
        redirect_stdout(io.StringIO()),
    ):
        result = bridge.main(full)
    _expect(
        result == 0
        and rescue_call.call_count == 1
        and captured["previous_executor_release_digest"] == "b" * 64
        and captured["retained_client_release_digest"] == "b" * 64
        and captured["rescue_executor_release_digest"] == digest
        and captured["inherited_successor_journal_sha256"] == digest
        and captured["inherited_successor_document_sha256"] == digest
        and captured["successor_arguments"]["candidate_release"]
        == Path("/tmp/releases") / candidate_digest
        and captured["successor_arguments"]["candidate_release"]
        != captured["rescue_executor_release"]
        and "client_release" not in captured["successor_arguments"],
        "executor rescue CLI did not dispatch its exact dedicated contract",
    )


def _exercise_post_export_executor_continuation_cli_contract(
    bridge: ModuleType,
) -> None:
    digest = "a" * 64
    previous = "b" * 64
    candidate = "c" * 64
    retained = "d" * 64
    command = [
        bridge.SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH,
        "--candidate-release", "/tmp/releases/" + candidate,
        "--release-root", "/tmp/releases",
        "--transaction-dir", "/tmp/successor",
        "--operation-id", str(uuid.uuid4()),
        "--predecessor-transaction", "/tmp/predecessor",
        "--predecessor-operation-id", str(uuid.uuid4()),
        "--predecessor-journal-sha256", digest,
        "--predecessor-document-sha256", digest,
        "--failed-installer-transaction", "/tmp/failed",
        "--failed-installer-operation-id", str(uuid.uuid4()),
        "--readiness-attestation", "/tmp/readiness.json",
        "--owner-map", "/tmp/owners.json",
        "--owner-map-sha256", digest,
        "--expected-database-generation", "generation-12",
        "--canary-user", "owner",
        "--expected-canary-uid", "1000",
        "--canary-project", "/tmp/GlobalFinance",
        "--canary-repository-id", "repo-global-finance",
        "--canary-repository-generation", "4",
        "--lifecycle-transaction-journal", "/tmp/lifecycle.json",
        "--lifecycle-transaction-journal-sha256", digest,
        "--lifecycle-transaction-document-sha256", digest,
        "--lifecycle-attestation", "/tmp/lifecycle-attestation.json",
        "--lifecycle-attestation-sha256", digest,
        "--lifecycle-attestation-document-sha256", digest,
        "--additional-canary", "collaborator=1001",
        "--inherited-successor-journal-sha256", digest,
        "--inherited-successor-document-sha256", digest,
        "--previous-executor-release", "/tmp/releases/" + previous,
        "--previous-executor-release-digest", previous,
        "--retained-client-release", "/tmp/releases/" + retained,
        "--retained-client-release-digest", retained,
        "--rescue-executor-release", "/tmp/releases/" + digest,
        "--rescue-executor-release-digest", digest,
        "--executor-rescue-sha256", "e" * 64,
        "--executor-rescue-handoff-sha256", "f" * 64,
    ]
    parsed = bridge._parser().parse_args(command)
    _expect(
        parsed.action
        == bridge.SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH
        and parsed.executor_rescue_sha256 == "e" * 64
        and parsed.executor_rescue_handoff_sha256 == "f" * 64,
        "post-export continuation parser lost its singular lineage",
    )
    captured: dict[str, object] = {}

    def dispatch(**values: object) -> dict[str, object]:
        captured.update(values)
        return {"ok": True}

    with (
        mock.patch.object(
            bridge,
            "continue_post_export_rescued_executor_with_clean_successor",
            side_effect=dispatch,
        ) as continuation_call,
        mock.patch.object(
            bridge,
            "handoff_rescued_executor_with_clean_successor",
            side_effect=AssertionError("continuation reached first handoff"),
        ),
        redirect_stdout(io.StringIO()),
    ):
        result = bridge.main(command)
    _expect(
        result == 0
        and continuation_call.call_count == 1
        and captured["executor_rescue_sha256"] == "e" * 64
        and captured["executor_rescue_handoff_sha256"] == "f" * 64
        and captured["previous_executor_release_digest"] == previous
        and captured["retained_client_release_digest"] == retained
        and captured["successor_executor_release_digest"] == digest
        and "client_release" not in captured["successor_arguments"],
        "post-export continuation CLI crossed into another route",
    )
    missing_index = command.index("--executor-rescue-handoff-sha256")
    with mock.patch.object(sys, "stderr", io.StringIO()):
        try:
            bridge._parser().parse_args(
                command[:missing_index] + command[missing_index + 2 :]
            )
        except SystemExit as error:
            _expect(error.code == 2, "continuation parser failed open")
        else:
            _fail("continuation parser accepted a missing first-handoff hash")


def _exercise_post_export_executor_substitution_rejection(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "post-export-executor-substitutions"
    case.mkdir(mode=0o700)
    releases = {
        name: case / digest
        for name, digest in (
            ("original", "1" * 64),
            ("client", "2" * 64),
            ("candidate", "3" * 64),
            ("previous", "4" * 64),
            ("next", "5" * 64),
        )
    }
    for release in releases.values():
        release.mkdir(mode=0o700)
    rescue = {
        "rescue_executor_release": str(releases["original"]),
        "rescue_executor_release_digest": releases["original"].name,
        "client_release": str(releases["client"]),
        "client_release_digest": releases["client"].name,
    }
    handoff = {
        "successor_executor_release": str(releases["previous"]),
        "successor_executor_release_digest": releases["previous"].name,
    }
    binding = {
        "executor_rescue": rescue,
        "executor_rescue_handoff": handoff,
        "candidate_release": str(releases["candidate"]),
        "candidate_release_digest": releases["candidate"].name,
    }
    current = {
        "phase": "candidate-activation-intent",
        "document_sha256": "a" * 64,
        "binding": binding,
    }

    def request_for(release: Path) -> dict[str, object]:
        return {
            "reason": bridge.SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_REASON,
            "continuation_path": bridge.SUCCESSOR_POST_EXPORT_EXECUTOR_CONTINUATION_PATH,
            "inherited_journal_raw_sha256": "b" * 64,
            "inherited_journal_document_sha256": "a" * 64,
            "executor_rescue_sha256": hashlib.sha256(
                bridge._canonical(rescue)
            ).hexdigest(),
            "executor_rescue_handoff_sha256": hashlib.sha256(
                bridge._canonical(handoff)
            ).hexdigest(),
            "previous_executor_release": str(releases["previous"]),
            "previous_executor_release_digest": releases["previous"].name,
            "retained_client_release": str(releases["client"]),
            "retained_client_release_digest": releases["client"].name,
            "successor_executor_release": str(release),
            "successor_executor_release_digest": release.name,
        }

    with (
        mock.patch.object(
            bridge,
            "_validated_successor_executor_rescue",
            return_value=rescue,
        ),
        mock.patch.object(
            bridge,
            "_validated_successor_executor_handoff",
            return_value=handoff,
        ),
    ):
        valid = request_for(releases["next"])
        with mock.patch.object(bridge, "ROOT", releases["next"]):
            _expect(
                bridge._validate_successor_post_export_executor_continuation_request(
                    valid,
                    current=current,
                    release_pair={
                        "executor_release": str(releases["next"]),
                        "executor_release_digest": releases["next"].name,
                        "client_release": str(releases["client"]),
                        "client_release_digest": releases["client"].name,
                        "historical_client": True,
                    },
                    inherited_journal_sha256="b" * 64,
                    inherited_document_sha256="a" * 64,
                    expected_uid=os.geteuid(),
                )
                == valid,
                "post-export continuation rejected a distinct executor",
            )
        for name in ("original", "client", "candidate", "previous"):
            release = releases[name]
            with mock.patch.object(bridge, "ROOT", release):
                _expect_bridge_error(
                    bridge,
                    lambda release=release: bridge._validate_successor_post_export_executor_continuation_request(
                        request_for(release),
                        current=current,
                        release_pair={
                            "executor_release": str(release),
                            "executor_release_digest": release.name,
                            "client_release": str(releases["client"]),
                            "client_release_digest": releases["client"].name,
                            "historical_client": True,
                        },
                        inherited_journal_sha256="b" * 64,
                        inherited_document_sha256="a" * 64,
                        expected_uid=os.geteuid(),
                    ),
                    "request binding changed",
                )


def _exercise_post_export_successor_candidate_phase_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "post-export-successor-candidate-phases"
    case.mkdir(mode=0o700)
    operation_id = str(uuid.uuid4())
    binding = {
        "candidate_release": str(case / ("a" * 64)),
        "candidate_release_digest": "a" * 64,
    }
    runtime = {"lineage": "exact-post-export-continuation"}
    common = {
        "operation_id": operation_id,
        "release": binding["candidate_release"],
        "release_digest": binding["candidate_release_digest"],
        "executor_rescue": runtime,
    }

    def classify(current: Mapping[str, object] | None) -> dict[str, object]:
        with (
            mock.patch.object(
                bridge, "_load_bridge_journal", return_value=current
            ),
            mock.patch.object(
                bridge,
                "_successor_executor_rescue_runtime_binding",
                return_value=runtime,
            ),
        ):
            return bridge._existing_post_export_successor_candidate(
                transaction=case,
                operation_id=operation_id,
                binding=binding,
                rescue={"lineage": "rescue"},
                handoff={"lineage": "handoff"},
                continuation={"lineage": "continuation"},
                expected_uid=os.geteuid(),
            )

    cleanup_complete_failure = {
        **common,
        "phase": "failed",
        "error": "candidate activation failed after complete cleanup",
    }
    _expect(
        classify(cleanup_complete_failure) == cleanup_complete_failure,
        "cleanup-complete post-export candidate failure was not retryable",
    )
    _expect_bridge_error(
        bridge,
        lambda: classify({**common, "phase": "recovery-required"}),
        "cleanup requires explicit recovery",
    )
    _expect_bridge_error(
        bridge,
        lambda: classify(None),
        "partial and requires explicit recovery",
    )
    _expect_bridge_error(
        bridge,
        lambda: classify({**common, "phase": "failed", "error": None}),
        "failure is incomplete",
    )


def _exercise_inventory_canary_binding(bridge: ModuleType, root: Path) -> None:
    account = pwd.getpwuid(os.geteuid())
    project = root / "GlobalFinance"
    project.mkdir(mode=0o700, exist_ok=True)
    payload = {
        "schema_version": 2,
        "authority": {
            "scope": "server-wide",
            "transport": "authenticated-unix-socket",
            "socket": str(root / "broker.sock"),
            "service_uid": 0,
            "database_generation": "generation-1",
        },
        "repositories": [
            {
                "repo_id": "repo-global-finance",
                "canonical_root": str(project),
                "generation": 2,
            }
        ],
    }
    public_commands: list[list[str]] = []

    def maintenance_blocked_public_cli(
        command: list[str], **_values: object
    ) -> object:
        public_commands.append(list(command))
        raise bridge.BridgeError("maintenance_in_progress")

    with mock.patch.object(
        bridge, "_run", side_effect=maintenance_blocked_public_cli
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
            ),
            "maintenance_in_progress",
        )
    _expect(
        len(public_commands) == 1
        and str(root / "release" / bridge.ENTRY_RELATIVE)
        in public_commands[0]
        and bridge.INTERNAL_CUTOVER_INVENTORY_ACTION not in public_commands[0],
        "public historical inventory stopped using its maintenance-fenced CLI",
    )
    with mock.patch.object(
        bridge,
        "_run",
        return_value=SimpleNamespace(stdout=json.dumps(payload)),
    ):
        canary = bridge._inventory_canary(
            release=root / "release",
            account=account,
            project=project,
            expected_database_generation="generation-1",
            expected_repository_id="repo-global-finance",
            canary_repository_generation=2,
            expected_broker_socket=root / "broker.sock",
            expected_service_uid=0,
        )
        _expect(
            canary["repository"]
            == {
                "repository_id": "repo-global-finance",
                "canonical_root": str(project),
                "generation": 2,
            },
            "inventory canary lost its exact repository binding",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="wrong-generation",
                expected_repository_id="repo-global-finance",
                canary_repository_generation=2,
                expected_broker_socket=root / "broker.sock",
                expected_service_uid=0,
            ),
            "wrong authority generation",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="generation-1",
                expected_repository_id="wrong-repository",
                canary_repository_generation=2,
                expected_broker_socket=root / "broker.sock",
                expected_service_uid=0,
            ),
            "exact requested repository",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="generation-1",
                expected_repository_id="repo-global-finance",
                canary_repository_generation=3,
                expected_broker_socket=root / "broker.sock",
                expected_service_uid=0,
            ),
            "exact requested repository",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="generation-1",
                expected_repository_id="repo-global-finance",
                canary_repository_generation=2,
                expected_broker_socket=root / "other.sock",
                expected_service_uid=0,
            ),
            "wrong authority socket",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="generation-1",
                expected_repository_id="repo-global-finance",
                canary_repository_generation=2,
                expected_broker_socket=root / "broker.sock",
                expected_service_uid=9,
            ),
            "wrong service identity",
        )
    cutover_commands: list[list[str]] = []
    cutover_pass_fds: list[tuple[int, ...]] = []

    def cutover_run(command: list[str], **values: object) -> object:
        cutover_commands.append(list(command))
        cutover_pass_fds.append(tuple(values.get("pass_fds", ())))
        return SimpleNamespace(stdout=json.dumps(payload))

    source = Path(str(bridge.__file__)).resolve(strict=True)
    source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC)
    source_directory_descriptor = os.open(
        source.parent,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    with (
        mock.patch.object(bridge, "_run", side_effect=cutover_run),
        mock.patch.object(
            bridge,
            "_open_immutable_bridge_source",
            return_value=(source_directory_descriptor, source_descriptor),
        ),
    ):
        bridge._inventory_canary(
            release=root / "release",
            account=account,
            project=project,
            profile=root / "client-profiles.json",
            expected_database_generation="generation-1",
            expected_repository_id="repo-global-finance",
            canary_repository_generation=2,
            expected_broker_socket=root / "broker.sock",
            expected_service_uid=0,
            _cutover_maintenance_inventory_read=True,
            _historical_release_digest="c" * 64,
        )
    _expect(
        len(cutover_commands) == 1
        and cutover_commands[0][0:7]
        == [
            "/usr/bin/setpriv",
            "--reuid",
            str(account.pw_uid),
            "--regid",
            str(account.pw_gid),
            "--init-groups",
            "--reset-env",
        ]
        and bridge.INTERNAL_CUTOVER_INVENTORY_ACTION in cutover_commands[0]
        and "--expected-client-uid" in cutover_commands[0]
        and "--expected-client-gid" in cutover_commands[0]
        and "--operation" not in cutover_commands[0]
        and len(cutover_pass_fds) == 1
        and cutover_pass_fds[0]
        == (source_directory_descriptor, source_descriptor)
        and f"/proc/self/fd/{source_directory_descriptor}"
        in cutover_commands[0]
        and f"/proc/self/fd/{source_descriptor}" in cutover_commands[0],
        "cutover inventory canary lost setpriv attribution or read-only routing",
    )
    extra_repository_payload = json.loads(json.dumps(payload))
    extra_repository_payload["repositories"].append(
        {
            "repo_id": "repo-unrequested",
            "canonical_root": str(root / "Unrequested"),
            "generation": 0,
        }
    )
    with mock.patch.object(
        bridge,
        "_run",
        return_value=SimpleNamespace(
            stdout=json.dumps(extra_repository_payload)
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._inventory_canary(
                release=root / "release",
                account=account,
                project=project,
                expected_database_generation="generation-1",
                expected_repository_id="repo-global-finance",
                canary_repository_generation=2,
                expected_broker_socket=root / "broker.sock",
                expected_service_uid=0,
            ),
            "exact requested repository",
        )


def _exercise_internal_cutover_inventory_contract(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "internal-cutover-inventory"
    fixture.mkdir(mode=0o700)
    historical_release = fixture / ("a" * 64)
    profile = fixture / "client-profiles.json"
    project = fixture / "GlobalFinance"
    project.mkdir(mode=0o700)
    broker_socket = fixture / "broker.sock"
    client_uid = 1234
    client_gid = 1235
    release_digest = "b" * 64
    repository_id = "repo-global-finance"
    repository_generation = 2
    database_generation = "generation-1"
    inventory_operation = SimpleNamespace(value="inventory.read")
    mutation_operation = SimpleNamespace(value="repository.remove")
    maintenance_root = fixture / "maintenance"
    requests: list[dict[str, object]] = []
    client_calls: list[dict[str, object]] = []
    profile_loads: list[dict[str, object]] = []

    class FakeRequest:
        @staticmethod
        def create(**values: object) -> object:
            requests.append(dict(values))
            return SimpleNamespace(operation=values["operation"])

    class FakeBrokerClient:
        def __init__(self, socket_path: Path, **values: object) -> None:
            self.socket_path = socket_path
            self.values = dict(values)
            self._maintenance_root = maintenance_root

        def call(self, request: object) -> dict[str, object]:
            client_calls.append(
                {
                    "request": request,
                    "maintenance_root": self._maintenance_root,
                    "socket": self.socket_path,
                    **self.values,
                }
            )
            return {
                "ok": True,
                "result": {
                    "schema_version": 2,
                    "repositories": [
                        {
                            "repo_id": repository_id,
                            "canonical_root": str(project),
                            "generation": repository_generation,
                        }
                    ],
                },
            }

    repository = SimpleNamespace(
        canonical_root=str(project),
        repo_id=repository_id,
        generation=repository_generation,
    )
    service = SimpleNamespace(
        database_generation=database_generation,
        socket_path=broker_socket,
        service_uid=0,
        socket_gid=987,
        socket_mode=0o660,
    )

    class FakeClientProfile:
        def __init__(self) -> None:
            self.client_uid = client_uid
            self.account_id = "account-1"
            self.service = service

        @staticmethod
        def repository(canonical_root: str) -> object:
            _expect(
                canonical_root == str(project),
                "internal inventory resolved another repository",
            )
            return repository

    def load_profile(**values: object) -> object:
        profile_loads.append(dict(values))
        return FakeClientProfile()

    broker = SimpleNamespace(
        BrokerOperation=SimpleNamespace(
            INVENTORY_READ=inventory_operation,
            REPOSITORY_REMOVE=mutation_operation,
        ),
        BrokerRequest=FakeRequest,
        BrokerClient=FakeBrokerClient,
        MAINTENANCE_ROOT=maintenance_root,
    )
    broker_profile = SimpleNamespace(
        load_broker_profile=load_profile,
        INVENTORY_READ_CLIENT_TIMEOUT_SECONDS=60.0,
    )
    arguments = {
        "historical_release": historical_release,
        "historical_release_digest": release_digest,
        "profile": profile,
        "project": project,
        "expected_repository_id": repository_id,
        "expected_repository_generation": repository_generation,
        "expected_database_generation": database_generation,
        "expected_broker_socket": broker_socket,
        "expected_service_uid": 0,
        "expected_client_uid": client_uid,
        "expected_client_gid": client_gid,
    }
    with (
        mock.patch.object(
            bridge.os,
            "getresuid",
            return_value=(client_uid, client_uid, client_uid),
        ),
        mock.patch.object(
            bridge.os,
            "getresgid",
            return_value=(client_gid, client_gid, client_gid),
        ),
        mock.patch.object(
            bridge, "_root_cutover_parent_identity", return_value={"uid": 0}
        ),
        mock.patch.object(
            bridge,
            "_load_historical_canary_modules",
            return_value=(broker, broker_profile),
        ),
    ):
        result = bridge._internal_cutover_inventory_read_canary(**arguments)
        _expect(
            result.get("schema_version") == 2
            and result.get("authority")
            == {
                "scope": "server-wide",
                "transport": "authenticated-unix-socket",
                "socket": str(broker_socket),
                "service_uid": 0,
                "database_generation": database_generation,
            }
            and result.get("repositories")
            == [
                {
                    "repo_id": repository_id,
                    "canonical_root": str(project),
                    "generation": repository_generation,
                }
            ]
            and len(requests) == 1
            and requests[0].get("operation") is inventory_operation
            and requests[0].get("arguments") == {}
            and requests[0].get("resource_id") == repository_id
            and len(client_calls) == 1
            and client_calls[0].get("maintenance_root") is None
            and profile_loads
            and profile_loads[0].get("effective_uid") == client_uid,
            "internal cutover canary was not one attributed inventory read",
        )
        with mock.patch.object(
            bridge.os,
            "getresuid",
            return_value=(client_uid + 1, client_uid + 1, client_uid + 1),
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge._internal_cutover_inventory_read_canary(
                    **arguments
                ),
                "canary identity is invalid",
            )
    parsed = bridge._parser().parse_args(
        [
            bridge.INTERNAL_CUTOVER_INVENTORY_ACTION,
            "--historical-release",
            str(historical_release),
            "--historical-release-digest",
            release_digest,
            "--profile",
            str(profile),
            "--project",
            str(project),
            "--expected-repository-id",
            repository_id,
            "--expected-repository-generation",
            str(repository_generation),
            "--expected-database-generation",
            database_generation,
            "--expected-socket",
            str(broker_socket),
            "--expected-service-uid",
            "0",
            "--expected-client-uid",
            str(client_uid),
            "--expected-client-gid",
            str(client_gid),
        ]
    )
    _expect(
        parsed.action == bridge.INTERNAL_CUTOVER_INVENTORY_ACTION
        and "operation" not in vars(parsed),
        "internal cutover parser exposed a selectable broker operation",
    )


def _exercise_exact_execution_contract(bridge: ModuleType, root: Path) -> None:
    release = root / ("e" * 64)
    database = root / "authority-execution.sqlite3"
    broker_socket = root / "execution.sock"
    dropin = root / "dropins" / "95-schema12.conf"
    enrolled_home_dropin = (
        root / "dropins" / "80-enrolled-home-write-paths.conf"
    )
    expected = [
        "/usr/bin/python3", "-B", "-I",
        str(release / bridge.ENTRY_RELATIVE),
        "broker", "serve", "--database", str(database),
        "--socket", str(broker_socket), "--access-group", bridge.ACCESS_GROUP,
    ]
    identity = {
        "FragmentPath": "/etc/systemd/system/devcoordinator-broker.service",
        "DropInPaths": f"{enrolled_home_dropin} {dropin}",
        "ExecStart": (
            "{ path=/usr/bin/python3 ; argv[]="
            + shlex.join(expected)
            + " ; ignore_errors=no ; }"
        ),
        "TriggeredBy": "",
        "WantedBy": "",
        "RequiredBy": "",
        "ConsistsOf": "",
        "PartOf": "",
        "BindsTo": "",
        "BoundBy": "",
    }
    with (
        mock.patch.object(bridge, "_systemd_execution_identity", return_value=identity),
        mock.patch.object(
            bridge, "DEFAULT_ENROLLED_HOME_DROPIN", enrolled_home_dropin
        ),
        mock.patch.object(bridge, "_sha256_file", return_value="a" * 64),
        mock.patch.object(bridge, "_dropin_identity", return_value={"sha256": "a" * 64}),
    ):
        proof = bridge._verify_loaded_bridge_execution(
            release=release,
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
        )
    _expect(proof["argv"] == expected, "exact systemd argv proof changed")
    malicious = dict(identity)
    malicious["ExecStart"] = identity["ExecStart"].replace(
        " ; ignore_errors", " --unsealed-argument ; ignore_errors"
    )
    with (
        mock.patch.object(
            bridge, "_systemd_execution_identity", return_value=malicious
        ),
        mock.patch.object(
            bridge, "DEFAULT_ENROLLED_HOME_DROPIN", enrolled_home_dropin
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_loaded_bridge_execution(
                release=release,
                database=database,
                broker_socket=broker_socket,
                dropin=dropin,
            ),
            "exact schema-12 bridge execution",
        )
    invalid_dropin_sets = (
        str(dropin),
        f"{enrolled_home_dropin} {dropin} {dropin}",
        (
            f"{enrolled_home_dropin} {dropin} "
            "/etc/systemd/system/devcoordinator-broker.service.d/99-extra.conf"
        ),
    )
    for invalid_paths in invalid_dropin_sets:
        unexpected_dropin = {**identity, "DropInPaths": invalid_paths}
        with (
            mock.patch.object(
                bridge,
                "_systemd_execution_identity",
                return_value=unexpected_dropin,
            ),
            mock.patch.object(
                bridge, "DEFAULT_ENROLLED_HOME_DROPIN", enrolled_home_dropin
            ),
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_loaded_bridge_execution(
                    release=release,
                    database=database,
                    broker_socket=broker_socket,
                    dropin=dropin,
                ),
                "exact schema-12 bridge execution",
            )
    payload = bridge._dropin_payload(release, database, broker_socket)
    _expect(
        b"/usr/bin/python3 -B -I" in payload
        and payload.count(b"/usr/bin/python3 -B -I") == 2,
        "future bridge drop-in does not fence bytecode writes in both Python launches",
    )


def _exercise_live_ready_verifier(bridge: ModuleType, root: Path) -> None:
    transaction = root / "ready-transaction"
    transaction.mkdir(mode=0o700)
    operation_id = str(uuid.uuid4())
    account = pwd.getpwuid(os.geteuid())
    project = root / "GlobalFinance"
    project.mkdir(mode=0o700, exist_ok=True)
    release = root / ("a" * 64)
    retained_client = root / ("b" * 64)
    original_executor = root / ("c" * 64)
    handoff_executor = root / ("d" * 64)
    historical_executor = root / ("e" * 64)
    newer_verifier = root / ("f" * 64)
    for availability_release in (
        retained_client,
        original_executor,
        handoff_executor,
        historical_executor,
        newer_verifier,
    ):
        availability_release.mkdir(mode=0o700, exist_ok=True)
    executor_rescue = {
        "reason": bridge.SUCCESSOR_EXECUTOR_RESCUE_REASON,
        "rescue_path": bridge.SUCCESSOR_EXECUTOR_RESCUE_PATH,
        "executor_rescue_sha256": "1" * 64,
        "client_release": str(retained_client),
        "client_release_digest": retained_client.name,
        "executor_release": str(historical_executor),
        "executor_release_digest": historical_executor.name,
        "source_profile_sha256": "2" * 64,
        "predecessor_lineage_sha256": "3" * 64,
        "first_handoff_sha256": "4" * 64,
        "owner_binding_refresh_sha256": "5" * 64,
        "executor_rescue_handoff_sha256": "6" * 64,
        "original_executor_release": str(original_executor),
        "original_executor_release_digest": original_executor.name,
        "executor_rescue_post_export_continuation_sha256": "7" * 64,
        "handoff_executor_release": str(handoff_executor),
        "handoff_executor_release_digest": handoff_executor.name,
    }
    database = root / "authority.sqlite3"
    profile = root / "client-profiles.json"
    broker_socket = root / "broker.sock"
    dropin = root / "bridge.conf"
    readiness = {
        "path": str(root / "readiness.json"),
        "document_sha256": "1" * 64,
        "database_identity": {"device": 1, "inode": 2, "size": 3},
        "database_generation": "generation-1",
        "state_revision": 17,
        "snapshot": _authority_snapshot(state_revision=17),
    }
    Path(str(readiness["path"])).write_text("{}\n", encoding="utf-8")
    Path(str(readiness["path"])).chmod(0o600)
    dropin_payload = b"fixture drop-in"
    dropin_sha256 = hashlib.sha256(dropin_payload).hexdigest()
    dropin_identity = {"sha256": dropin_sha256}
    argv = [
        "/usr/bin/python3", "-B", "-I",
        str(release / bridge.ENTRY_RELATIVE),
        "broker", "serve", "--database", str(database),
        "--socket", str(broker_socket), "--access-group", bridge.ACCESS_GROUP,
    ]
    execution = {
        "systemd": {},
        "argv": argv,
        "dropin_paths": [str(dropin)],
        "dropins": [dropin_identity],
    }
    journal = bridge._journal(
        transaction / bridge.JOURNAL_NAME,
        {
            "operation_id": operation_id,
            "release": str(release),
            "release_digest": "a" * 64,
            "dropin": str(dropin),
            "dropin_sha256": dropin_sha256,
            "dropin_identity": dropin_identity,
            "broker_socket": str(broker_socket),
            "failed_activation": {"operation_id": str(uuid.uuid4())},
            "readiness": readiness,
            "canaries": [{"user": account.pw_name, "uid": account.pw_uid, "project": str(project)}],
            "baseline": {"ActiveState": "inactive", "SubState": "dead", "MainPID": 0},
            "phase": "ready",
            "attempts": 1,
            "activation": {
                "systemd": {"InvocationID": "old"},
                "execution": execution,
                "canaries": [],
            },
            "error": None,
            "created_at_epoch": 1,
            "updated_at_epoch": 2,
            "readiness_origin": readiness,
            "attempt_evidence": {
                "attempt": 1, "stage": "ready", "last_completed_stage": "canaries",
                "systemd_ready": None, "failure_stage": None, "error_sha256": None,
            },
            "executor_rescue": executor_rescue,
        },
        uid=os.geteuid(),
    )
    journal_path = transaction / bridge.JOURNAL_NAME
    raw_before = journal_path.read_bytes()
    raw_sha256 = hashlib.sha256(raw_before).hexdigest()
    state = {"ActiveState": "active", "SubState": "running", "MainPID": 4312, "InvocationID": "current", "NRestarts": 0}
    socket_identity = {"device": 5, "inode": 6, "uid": 0, "gid": 7, "mode": 0o660}
    profile_identity = {"device": 8, "inode": 9, "size": 10, "mtime_ns": 11, "ctime_ns": 12, "uid": 0, "gid": 7, "mode": 0o640, "nlink": 1, "sha256": "3" * 64}
    process = {"pid": 4312, "uid": 0, "argv": argv, "cgroup": f"0::/system.slice/{bridge.BROKER_UNIT}"}
    peer = {"pid": 4312, "uid": 0, "gid": 0}
    canary = {
        "user": account.pw_name, "uid": account.pw_uid, "project": str(project),
        "inventory_sha256": "4" * 64,
        "authority": {"scope": "server-wide", "transport": "authenticated-unix-socket", "socket": str(broker_socket), "service_uid": 0, "database_generation": "generation-1"},
        "repository": {"repository_id": "repo-global-finance", "canonical_root": str(project), "generation": 2},
    }

    @contextmanager
    def unlocked(_uid: int):
        yield

    def invoke(**overrides: object) -> dict[str, object]:
        arguments: dict[str, object] = {
            "transaction": transaction, "operation_id": operation_id,
            "expected_journal_sha256": raw_sha256,
            "expected_journal_document_sha256": journal["document_sha256"],
            "database": database, "profile": profile, "broker_socket": broker_socket,
            "dropin": dropin, "expected_database_generation": "generation-1",
            "canary_user": account.pw_name, "canary_project": project,
            "canary_repository_id": "repo-global-finance",
            "expected_canary_uid": account.pw_uid,
            "canary_repository_generation": 2, "expected_uid": os.geteuid(),
        }
        arguments.update(overrides)
        return bridge.verify_ready_bridge(**arguments)

    inventory_releases: list[Path] = []

    def inventory_result(**values: object) -> dict[str, object]:
        inventory_releases.append(Path(str(values["release"])))
        return canary

    def patched(
        *, states=None, profiles=None, generations=None, executions=None,
        processes=None, peers=None, canary_result=canary,
    ) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(mock.patch.object(bridge, "DEFAULT_PROFILE", profile))
        stack.enter_context(mock.patch.object(bridge, "DEFAULT_SOCKET", broker_socket))
        stack.enter_context(mock.patch.object(bridge, "DEFAULT_DROPIN", dropin))
        stack.enter_context(mock.patch.object(bridge, "ROOT", newer_verifier))
        stack.enter_context(
            mock.patch.object(
                bridge,
                "_verify_historical_availability_release",
                side_effect=lambda value, **_kwargs: {
                    "release_digest": Path(value).name
                },
            )
        )
        stack.enter_context(mock.patch.object(bridge, "_installer_lock", unlocked))
        stack.enter_context(mock.patch.object(bridge, "_verify_activation_release", side_effect=[{"release_digest": "a" * 64}, {"release_digest": "a" * 64}]))
        stack.enter_context(mock.patch.object(bridge, "_dropin_payload", return_value=dropin_payload))
        stack.enter_context(mock.patch.object(bridge, "_verify_dropin_identity", return_value=dropin_identity))
        ready_values = generations or [readiness, readiness]
        stack.enter_context(mock.patch.object(bridge, "_verify_retained_readiness_reference", side_effect=ready_values))
        stack.enter_context(mock.patch.object(bridge, "_profile_identity", side_effect=profiles or [profile_identity, profile_identity]))
        stack.enter_context(mock.patch.object(bridge, "_profile_repository_binding", return_value={"client_uid": account.pw_uid, "repository_id": "repo-global-finance", "canonical_root": str(project), "generation": 2, "owner_uid": account.pw_uid}))
        stack.enter_context(mock.patch.object(bridge, "_wait_active", side_effect=states or [state, state]))
        stack.enter_context(mock.patch.object(bridge, "_socket_identity", side_effect=[socket_identity, socket_identity]))
        stack.enter_context(mock.patch.object(bridge, "_verify_loaded_bridge_execution", side_effect=executions or [execution, execution]))
        stack.enter_context(mock.patch.object(bridge, "_broker_process_identity", side_effect=processes or [process, process]))
        stack.enter_context(mock.patch.object(bridge, "_broker_socket_peer", side_effect=peers or [peer, peer]))
        if isinstance(canary_result, BaseException):
            stack.enter_context(mock.patch.object(bridge, "_inventory_canary", side_effect=canary_result))
        else:
            stack.enter_context(
                mock.patch.object(
                    bridge,
                    "_inventory_canary",
                    side_effect=(
                        inventory_result
                        if canary_result is canary
                        else lambda **_values: canary_result
                    ),
                )
            )
        return stack

    with patched():
        proof = invoke()
    _expect(
        proof["kind"] == bridge.READY_PROOF_KIND,
        "live bridge readiness returned the wrong proof contract",
    )
    _expect(
        inventory_releases == [retained_client]
        and proof["release"] == str(release)
        and proof["release_digest"] == release.name,
        "historical ready verification did not separate the retained client "
        "canary from broker release proof semantics",
    )
    _expect(
        proof["systemd"]["InvocationID"] == "current",
        "live proof retained the stale pre-prepare invocation",
    )
    _expect(
        journal_path.read_bytes() == raw_before,
        "live readiness rewrote the immutable ready journal",
    )
    _expect(
        bridge.verify_ready_bridge_proof(proof) == proof,
        "public live readiness proof validator changed evidence",
    )
    _expect(
        proof["canary"]["repository"]["generation"] == 2
        and proof["profile_repository"]["owner_uid"] == account.pw_uid,
        "live readiness proof lost repository generation or owner UID",
    )

    historical_verifications: list[Path] = []

    def verify_historical(
        value: Path, **_kwargs: object
    ) -> dict[str, object]:
        historical_verifications.append(Path(value))
        return {"release_digest": Path(value).name}

    with (
        mock.patch.object(bridge, "ROOT", newer_verifier),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=verify_historical,
        ),
    ):
        historical = bridge._load_bridge_journal_for_ready_verification(
            journal_path, uid=os.geteuid()
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._load_bridge_journal(
                journal_path, uid=os.geteuid()
            ),
            "executor rescue runtime binding changed",
        )
    _expect(
        historical == journal
        and set(historical_verifications)
        == {
            retained_client,
            original_executor,
            handoff_executor,
            historical_executor,
        }
        and len(historical_verifications) == 4,
        "external ready verifier did not authenticate every historical "
        "executor/client release exactly once",
    )

    with (
        mock.patch.object(bridge, "ROOT", historical_executor),
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            return_value={"release_digest": historical_executor.name},
        ) as current_verifier,
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=lambda value, **_kwargs: {
                "release_digest": Path(value).name
            },
        ),
    ):
        same_executor = bridge._load_bridge_journal_for_ready_verification(
            journal_path, uid=os.geteuid()
        )
    _expect(
        same_executor == journal and current_verifier.call_count == 1,
        "historical effective executor could not reverify its own ready bridge",
    )

    def wrong_effective_digest(
        value: Path, **_kwargs: object
    ) -> dict[str, object]:
        release_path = Path(value)
        return {
            "release_digest": (
                "0" * 64
                if release_path == historical_executor
                else release_path.name
            )
        }

    with (
        mock.patch.object(bridge, "ROOT", newer_verifier),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=wrong_effective_digest,
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._load_bridge_journal_for_ready_verification(
                journal_path, uid=os.geteuid()
            ),
            "historical ready effective executor release changed",
        )

    def reject_tampered_handoff(
        value: Path, **_kwargs: object
    ) -> dict[str, object]:
        release_path = Path(value)
        if release_path == handoff_executor:
            raise bridge.BridgeError("historical release files changed")
        return {"release_digest": release_path.name}

    with (
        mock.patch.object(bridge, "ROOT", newer_verifier),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=reject_tampered_handoff,
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._load_bridge_journal_for_ready_verification(
                journal_path, uid=os.geteuid()
            ),
            "historical release files changed",
        )

    tampered = dict(proof)
    tampered["database_generation"] = "other-generation"
    _expect_bridge_error(
        bridge,
        lambda: bridge.verify_ready_bridge_proof(tampered),
        "evidence is invalid",
    )
    forged_payload = {
        key: value
        for key, value in proof.items()
        if key not in {"schema_version", "kind", "document_sha256"}
    }
    forged_payload["profile_repository"] = {
        **proof["profile_repository"],
        "owner_uid": proof["profile_repository"]["owner_uid"] + 1,
    }
    forged = bridge._seal(bridge.READY_PROOF_KIND, forged_payload)
    _expect_bridge_error(
        bridge,
        lambda: bridge.verify_ready_bridge_proof(forged),
        "live proof binding is invalid",
    )

    with patched(generations=[{**readiness, "database_generation": "other"}, readiness]):
        _expect_bridge_error(bridge, invoke, "readiness generation changed")
    changed_state = {**state, "InvocationID": "unexpected-restart"}
    with patched(states=[state, changed_state]):
        _expect_bridge_error(bridge, invoke, "changed during live readiness proof")
    with patched(profiles=[profile_identity, {**profile_identity, "inode": 99}]):
        _expect_bridge_error(bridge, invoke, "changed during live readiness proof")
    with patched(canary_result=bridge.BridgeError("canary denied")):
        _expect_bridge_error(bridge, invoke, "canary denied")
    with patched(peers=[peer, {**peer, "pid": 999}]):
        _expect_bridge_error(bridge, invoke, "socket peer is not the MainPID")
    with patched(processes=[process, {**process, "start_time_ticks": 999}]):
        _expect_bridge_error(bridge, invoke, "changed during live readiness proof")
    with patched(
        executions=[execution, {**execution, "dropin_paths": ["unexpected"]}]
    ):
        _expect_bridge_error(bridge, invoke, "changed during live readiness proof")
    with patched():
        _expect_bridge_error(
            bridge,
            lambda: invoke(expected_journal_document_sha256="f" * 64),
            "ready journal binding changed",
        )
    _expect(
        journal_path.read_bytes() == raw_before,
        "failed live readiness changed the ready journal",
    )


def _exercise_owner_bound_profile_export(bridge: ModuleType, root: Path) -> None:
    fixture = root / "successor-profile-export"
    fixture.mkdir(mode=0o700)
    database = fixture / "authority.sqlite3"
    project = fixture / "GlobalFinance"
    project.mkdir(mode=0o700)
    owner_uid = 4241
    generation = str(uuid.uuid4())
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            CREATE TABLE schema_metadata(
              singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL,
              database_generation TEXT NOT NULL, state_revision INTEGER NOT NULL,
              migration_state TEXT NOT NULL
            );
            CREATE TABLE repositories(
              repo_id TEXT PRIMARY KEY, canonical_root TEXT NOT NULL,
              generation INTEGER NOT NULL, state TEXT NOT NULL
            );
            CREATE TABLE repository_installations(
              repo_id TEXT PRIMARY KEY, status TEXT NOT NULL,
              startup_fenced INTEGER NOT NULL
            );
            CREATE TABLE broker_acl_principals(
              uid INTEGER NOT NULL, account_id TEXT NOT NULL, enabled INTEGER NOT NULL,
              PRIMARY KEY(uid, account_id)
            );
            CREATE TABLE broker_repository_enrollments(
              uid INTEGER NOT NULL, account_id TEXT NOT NULL, repo_id TEXT NOT NULL,
              issued_at TEXT NOT NULL, valid_until_epoch INTEGER NOT NULL,
              enabled INTEGER NOT NULL, PRIMARY KEY(uid, repo_id)
            );
            CREATE TABLE broker_resource_acl(
              uid INTEGER NOT NULL, repo_id TEXT NOT NULL, resource_kind TEXT NOT NULL,
              resource_id TEXT NOT NULL, enabled INTEGER NOT NULL
            );
            CREATE TABLE server_definitions(
              server_definition_id TEXT PRIMARY KEY, repo_id TEXT NOT NULL,
              name TEXT NOT NULL
            );
            CREATE TABLE docker_resources(
              docker_resource_id TEXT PRIMARY KEY, current_name TEXT NOT NULL,
              full_container_id TEXT NOT NULL
            );
            CREATE TABLE broker_compose_acl(
              uid INTEGER NOT NULL, repo_id TEXT NOT NULL,
              compose_definition_id TEXT NOT NULL, enabled INTEGER NOT NULL
            );
            CREATE TABLE broker_compose_definitions(
              compose_definition_id TEXT PRIMARY KEY, repo_id TEXT NOT NULL,
              enabled INTEGER NOT NULL
            );
            CREATE TABLE broker_ephemeral_acl(
              uid INTEGER NOT NULL, repo_id TEXT NOT NULL, template_id TEXT NOT NULL,
              operation TEXT NOT NULL, enabled INTEGER NOT NULL
            );
            CREATE TABLE ephemeral_container_templates(
              template_id TEXT PRIMARY KEY, repo_id TEXT NOT NULL, name TEXT NOT NULL,
              secret_policy_kind TEXT, secret_binding_id TEXT, enabled INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO schema_metadata VALUES(1, 12, ?, 7, 'ready')",
            (generation,),
        )
        connection.execute(
            "INSERT INTO repositories VALUES('repo-global-finance', ?, 4, 'active')",
            (str(project),),
        )
        connection.execute(
            "INSERT INTO repository_installations VALUES"
            "('repo-global-finance', 'installed', 0)"
        )
        for uid, account_id in (
            (0, "root-administrator-account"),
            (owner_uid, "owner-account"),
            (4242, "observer-account"),
        ):
            connection.execute(
                "INSERT INTO broker_acl_principals VALUES(?, ?, 1)",
                (uid, account_id),
            )
            connection.execute(
                "INSERT INTO broker_repository_enrollments VALUES"
                "(?, ?, 'repo-global-finance', '2026-01-01T00:00:00Z', ?, 1)",
                (uid, account_id, 2**31),
            )
        owner_contract = bridge._load_owner_contract()
        owner_document = owner_contract.prepare_owner_map(
            connection,
            owner_uids={"repo-global-finance": owner_uid},
            operation_id=str(uuid.uuid4()),
            actor="schema12-successor-self-test",
            created_at="2026-07-29T00:00:00.000Z",
            target_database_generation=str(uuid.uuid4()),
        )
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)
    owner_map = fixture / "owner-map.json"
    owner_map.write_text(
        json.dumps(owner_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    owner_map.chmod(0o600)
    raw_sha256 = hashlib.sha256(owner_map.read_bytes()).hexdigest()
    payload, evidence = bridge._schema12_owner_bound_profile_export(
        database=database,
        profile_path=fixture / "client-profiles.json",
        broker_socket=fixture / "broker.sock",
        owner_map=owner_map,
        owner_map_sha256=raw_sha256,
        snapshot_root=fixture / "snapshots",
        expected_database_generation=generation,
        canary_uid=owner_uid,
        canary_project=project,
        repository_id="repo-global-finance",
        repository_generation=4,
        expected_uid=os.geteuid(),
    )
    document = json.loads(payload)
    _expect(
        sorted(document["clients"], key=int)
        == ["0", str(owner_uid), "4242"],
        "full schema-12 export omitted an active client",
    )
    for client in document["clients"].values():
        repository = client["repositories"][0]
        _expect(
            repository["owner_uid"] == owner_uid,
            "full schema-12 export inferred owner from the client UID",
        )
    _expect(
        evidence["all_clients_parser_verified"] is True
        and evidence["existing_profile_contents_reused"] is False
        and evidence["owner_map"]["raw_sha256"] == raw_sha256,
        "full schema-12 export lost strict parser or owner-map evidence",
    )
    _expect(
        evidence["client_uids"] == [0, owner_uid, 4242]
        and document["clients"]["0"]["repositories"][0]["owner_uid"]
        == owner_uid,
        "full schema-12 export rejected root as a client or inferred root ownership",
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._schema12_owner_bound_profile_export(
            database=database,
            profile_path=fixture / "client-profiles.json",
            broker_socket=fixture / "broker.sock",
            owner_map=owner_map,
            owner_map_sha256="0" * 64,
            snapshot_root=fixture / "rejected-snapshots",
            expected_database_generation=generation,
            canary_uid=owner_uid,
            canary_project=project,
            repository_id="repo-global-finance",
            repository_generation=4,
            expected_uid=os.geteuid(),
        ),
        "raw digest changed",
    )


def _exercise_successor_failpoint_replay(bridge: ModuleType, root: Path) -> None:
    class InjectedCrash(RuntimeError):
        pass

    class FakeFence:
        def __init__(self) -> None:
            self.completed = False

        def mark_complete(self) -> None:
            self.completed = True

    failpoints = (
        "after-initial-journal",
        "after-maintenance-activate",
        "after-maintenance-journal",
        "after-predecessor-stop",
        "after-predecessor-dropin-remove-intent",
        "after-predecessor-dropin-remove",
        "after-profile-repair",
        "after-candidate-activate",
        "after-candidate-verify",
        "after-terminal-publish",
        "after-maintenance-clear",
        "after-completion-publish",
    )
    account = pwd.getpwuid(os.geteuid())
    access_gid = __import__("grp").getgrnam(bridge.ACCESS_GROUP).gr_gid
    reappeared_dropin = root / "handoff-absent-reappeared.conf"
    reappeared_dropin.write_bytes(b"[Service]\nEnvironment=REAPPEARED=1\n")
    reappeared_dropin.chmod(0o644)
    reappeared_sha256 = hashlib.sha256(
        reappeared_dropin.read_bytes()
    ).hexdigest()
    reappeared_identity = bridge._dropin_identity(
        reappeared_dropin,
        uid=os.geteuid(),
        expected_sha256=reappeared_sha256,
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._verify_successor_client_handoff_dropin_boundary(
            {
                "state": "absent",
                "path": str(reappeared_dropin),
                "bound_identity": reappeared_identity,
                "bound_sha256": reappeared_sha256,
            },
            dropin=reappeared_dropin,
            expected_uid=os.geteuid(),
            allow_bound_removal=True,
        ),
        "reappeared after absent boundary",
    )

    def fixture(name: str):
        case = root / f"successor-{name}"
        case.mkdir(mode=0o700)
        transaction = case / "transaction"
        predecessor_transaction = case / "predecessor"
        failed_transaction = case / "failed-installer"
        for directory in (transaction, predecessor_transaction, failed_transaction):
            directory.mkdir(mode=0o700)
        profile_root = case / "protected"
        profile_root.mkdir(mode=0o700)
        profile = profile_root / "client-profiles.json"
        original = b'{"legacy":"exact-predecessor"}\n'
        profile.write_bytes(original)
        profile.chmod(0o600)
        project = case / "GlobalFinance"
        project.mkdir(mode=0o700)
        candidate_root = case / "clean-releases"
        candidate_root.mkdir(mode=0o700)
        candidate_release = candidate_root / ("c" * 64)
        candidate_release.mkdir(mode=0o700)
        predecessor_root = case / "legacy-releases"
        predecessor_root.mkdir(mode=0o700)
        predecessor_release = predecessor_root / ("c" * 64)
        predecessor_release.mkdir(mode=0o700)
        client_release = case / ("d" * 64)
        client_release.mkdir(mode=0o700)
        replacement_client_release = case / ("e" * 64)
        replacement_client_release.mkdir(mode=0o700)
        owner_map = case / "owner-map.json"
        owner_map.write_text("{}\n", encoding="utf-8")
        owner_map.chmod(0o600)
        readiness = case / "readiness.json"
        readiness.write_text("{}\n", encoding="utf-8")
        readiness.chmod(0o600)
        dropin_path = case / "bridge.conf"
        dropin_present = "pre-removal" in name
        if dropin_present:
            dropin_path.write_bytes(b"[Service]\nEnvironment=BOUND=1\n")
            dropin_path.chmod(0o644)
            dropin_sha256 = hashlib.sha256(
                dropin_path.read_bytes()
            ).hexdigest()
            dropin_identity = bridge._dropin_identity(
                dropin_path,
                uid=os.geteuid(),
                expected_sha256=dropin_sha256,
            )
        else:
            dropin_sha256 = "3" * 64
            dropin_identity = {
                "device": 13,
                "inode": 17,
                "size": 718,
                "mtime_ns": 19,
                "ctime_ns": 23,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o644,
                "nlink": 1,
                "sha256": dropin_sha256,
            }
        operation_id = str(uuid.uuid4())
        predecessor_operation_id = str(uuid.uuid4())
        failed_operation_id = str(uuid.uuid4())
        lifecycle_operation_id = str(uuid.uuid4())
        readiness_origin = {
            "path": str(readiness),
            "document_sha256": "8" * 64,
            "database_identity": {"device": 7, "inode": 11, "size": 4096},
            "database_generation": "generation-12",
            "state_revision": 41,
            "snapshot": _authority_snapshot(state_revision=41),
        }
        owner_reference = {
            "path": str(owner_map),
            "raw_sha256": "e" * 64,
            "document_sha256": "f" * 64,
            "identity": {"sha256": "e" * 64},
        }
        lifecycle_outer_rearm = (
            {
                "journal": str(case / "lifecycle-predecessor-rearm.json"),
                "journal_document_sha256": "7" * 64,
            }
            if name.startswith("client-release")
            else None
        )
        verified_predecessor_proof = {
            "database": str(case / "authority.sqlite3"),
            "database_generation": "generation-12",
            "profile": str(profile),
            "broker_socket": str(case / "broker.sock"),
            "dropin": str(dropin_path),
            "dropin_identity": dropin_identity,
            "readiness_origin": readiness_origin,
            "systemd": {"InvocationID": "predecessor-invocation"},
            **(
                {"outer_rearm": lifecycle_outer_rearm}
                if lifecycle_outer_rearm is not None
                else {}
            ),
        }
        predecessor = {
            "transaction": str(predecessor_transaction),
            "operation_id": predecessor_operation_id,
            "journal": str(predecessor_transaction / bridge.JOURNAL_NAME),
            "journal_sha256": "1" * 64,
            "document_sha256": "2" * 64,
            "release": str(predecessor_release),
            "release_digest": "c" * 64,
            "dropin_sha256": dropin_sha256,
            "dropin_identity": dropin_identity,
            "readiness_origin": readiness_origin,
            "readiness_origin_sha256": hashlib.sha256(
                json.dumps(
                    readiness_origin, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
            "ready_proof": verified_predecessor_proof,
        }
        repaired = b'{"owner_bound":true}\n'
        export = {
            "profile": str(profile),
            "profile_sha256": hashlib.sha256(repaired).hexdigest(),
            "database_generation": "generation-12",
            "database_identity": {"sha256": "4" * 64},
            "database_sidecars": [],
            "owner_map": owner_reference,
            "client_uids": [account.pw_uid],
            "repository_bindings": [
                {
                    "client_uid": account.pw_uid,
                    "repository_id": "repo-global-finance",
                    "owner_uid": account.pw_uid,
                }
            ],
            "all_clients_parser_verified": True,
            "existing_profile_contents_reused": False,
        }
        export["evidence_sha256"] = hashlib.sha256(
            json.dumps(export, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        sqlite_bundle_state = {
            "main": {
                "path": str(case / "authority.sqlite3"),
                "device": 7,
                "inode": 11,
                "size": 4096,
                "mtime_ns": 13,
                "ctime_ns": 17,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o600,
                "nlink": 1,
                "sha256": "4" * 64,
            },
            "sidecars": {
                suffix: {
                    "path": str(case / f"authority.sqlite3{suffix}"),
                    "device": 7,
                    "inode": inode,
                    "size": size,
                    "mtime_ns": 19,
                    "ctime_ns": 23,
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                    "mode": 0o600,
                    "nlink": 1,
                    "sha256": digest * 64,
                }
                for suffix, inode, size, digest in (
                    ("-wal", 29, 0, "0"),
                    ("-shm", 31, 32768, "5"),
                )
            },
        }
        maintenance = {
            "active": False,
            "writer_locked": False,
            "writer_lock_acquisitions": 0,
            "events": [],
            "candidate_active": False,
            "_sqlite_bundle_state": sqlite_bundle_state,
        }
        canary_modes: list[bool] = []
        maintenance_binding = {
            "root": str(case / "maintenance"),
            "gid": access_gid,
            "deployment_id": lifecycle_operation_id,
            "scope": "server-wide-authority-upgrade",
            "message": (
                "Coordinator control-plane maintenance is in progress; live controls "
                "will reconnect automatically."
            ),
            "retry_after_seconds": 5,
            "started_at": "2026-07-29T00:00:00Z",
        }
        lifecycle_handoff = {
            "transaction_journal": str(case / "lifecycle-journal.json"),
            "transaction_journal_sha256": "9" * 64,
            "transaction_document_sha256": "a" * 64,
            "attestation": str(case / "lifecycle-result.json"),
            "attestation_sha256": "b" * 64,
            "attestation_document_sha256": "d" * 64,
            "operation_id": lifecycle_operation_id,
            "database_generation": "generation-12",
            "maintenance": maintenance_binding,
            "predecessor_proof": (
                verified_predecessor_proof
                if lifecycle_outer_rearm is not None
                else {}
            ),
        }

        def profile_identity(path: Path, *, uid: int):
            info = path.lstat()
            _expect(uid == os.geteuid(), "successor changed profile authority UID")
            return {
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        def replace_profile(
            path: Path,
            payload: bytes,
            *,
            expected_current_sha256: str,
            owner_uid: int,
            owner_gid: int,
            mode: int,
        ):
            current = profile_identity(path, uid=owner_uid)
            target = hashlib.sha256(payload).hexdigest()
            if current["sha256"] == target:
                return current
            _expect(
                current["sha256"] == expected_current_sha256,
                "successor replaced an unexpected profile",
            )
            path.write_bytes(payload)
            path.chmod(mode)
            return profile_identity(path, uid=owner_uid)

        @contextmanager
        def fenced(**_kwargs):
            yield FakeFence()

        def ensure_maintenance(_binding, *, uid: int) -> None:
            _expect(uid == os.geteuid(), "successor changed maintenance UID")
            _expect(
                maintenance["writer_locked"],
                "successor mutated outside maintenance writer exclusion",
            )
            maintenance["active"] = True

        def clear_maintenance(_binding, *, uid: int) -> None:
            _expect(uid == os.geteuid(), "successor changed maintenance clear UID")
            _expect(
                not maintenance["writer_locked"],
                "successor tried to reacquire maintenance while writer-locked",
            )
            maintenance["active"] = False

        @contextmanager
        def maintenance_writer_lock(**_kwargs):
            _expect(
                not maintenance["writer_locked"],
                "successor nested the non-reentrant maintenance writer lock",
            )
            maintenance["writer_lock_acquisitions"] += 1
            maintenance["events"].append("writer-enter")
            maintenance["writer_locked"] = True
            try:
                yield
            finally:
                maintenance["writer_locked"] = False
                maintenance["events"].append("writer-exit")

        def candidate_reference(
            *,
            transaction,
            operation_id,
            activation,
            uid,
            executor_rescue=None,
            executor_rescue_sha256=None,
        ):
            return {
                "transaction": str(transaction),
                "operation_id": operation_id,
                "journal": str(transaction / bridge.JOURNAL_NAME),
                "journal_sha256": "5" * 64,
                "document_sha256": "6" * 64,
                "activation": dict(activation),
                "executor_rescue": (
                    dict(executor_rescue)
                    if executor_rescue is not None
                    else None
                ),
                "executor_rescue_sha256": executor_rescue_sha256,
                "readiness": None,
            }

        def readiness_result(value: object) -> dict[str, object]:
            if value != {}:
                raise ValueError("fixture readiness seal changed")
            return {"document_sha256": "8" * 64}

        def candidate_ready(**kwargs):
            maintenance_read = bool(
                kwargs.get("_cutover_maintenance_inventory_read")
            )
            canary_modes.append(maintenance_read)
            repository_scope = [
                {
                    "client_uid": account.pw_uid,
                    "repository_id": "repo-global-finance",
                    "canonical_root": str(project),
                    "generation": 4,
                    "owner_uid": account.pw_uid,
                },
                {
                    "client_uid": account.pw_uid + 1,
                    "repository_id": "repo-global-finance",
                    "canonical_root": str(project),
                    "generation": 4,
                    "owner_uid": account.pw_uid,
                },
            ]
            canaries = [
                {
                    "user": account.pw_name,
                    "uid": account.pw_uid,
                    "project": str(project),
                    "inventory_sha256": (
                        "7" if maintenance_read else "9"
                    )
                    * 64,
                    "authority": {},
                    "repository": {
                        "repository_id": "repo-global-finance",
                        "canonical_root": str(project),
                        "generation": 4,
                    },
                },
                {
                    "user": "collaborator",
                    "uid": account.pw_uid + 1,
                    "project": str(project),
                    "inventory_sha256": (
                        "8" if maintenance_read else "a"
                    )
                    * 64,
                    "authority": {},
                    "repository": {
                        "repository_id": "repo-global-finance",
                        "canonical_root": str(project),
                        "generation": 4,
                    },
                },
            ]
            executor_rescue = kwargs.get(
                "_executor_rescue_client_binding"
            )
            if executor_rescue is not None:
                for canary in canaries:
                    canary["executor_rescue_sha256"] = (
                        executor_rescue["executor_rescue_sha256"]
                    )
            return bridge._verify_successor_ready_proof(
                bridge._seal(
                    bridge.SUCCESSOR_READY_PROOF_KIND,
                    {
                        "operation_id": str(
                            uuid.uuid5(
                                uuid.UUID(operation_id),
                                "schema12-clean-successor-candidate",
                            )
                        ),
                        "bridge_journal": str(
                            transaction / bridge.SUCCESSOR_CANDIDATE_DIRECTORY
                            / bridge.JOURNAL_NAME
                        ),
                        "bridge_journal_sha256": "5" * 64,
                        "bridge_document_sha256": "6" * 64,
                        "broker_release": str(candidate_release),
                        "broker_release_digest": "c" * 64,
                        "client_release": str(kwargs["client_release"]),
                        "client_release_digest": Path(
                            str(kwargs["client_release"])
                        ).name,
                        "executor_rescue": executor_rescue,
                        "executor_rescue_sha256": kwargs.get(
                            "executor_rescue_sha256"
                        ),
                        "database": str(case / "authority.sqlite3"),
                        "database_generation": "generation-12",
                        "profile": str(profile),
                        "profile_identity": {},
                        "owner_uid": account.pw_uid,
                        "profile_repositories": repository_scope,
                        "broker_socket": str(case / "broker.sock"),
                        "socket_identity": {},
                        "socket_peer": {},
                        "dropin": str(case / "bridge.conf"),
                        "dropin_identity": {},
                        "systemd": {},
                        "execution": {},
                        "process": {},
                        "canaries": canaries,
                        "verified_at_epoch": 1,
                    },
                )
            )

        def activate_candidate(**kwargs):
            _expect(
                kwargs.get("_authorized_readiness_origin") == readiness_origin,
                "clean successor did not pass its sealed predecessor readiness origin",
            )
            _expect(
                "authorized_readiness_origin" not in kwargs,
                "clean successor exposed readiness authority as a public argument",
            )
            _expect(
                kwargs.get("_cutover_maintenance_inventory_read") is True
                and kwargs.get("_cutover_canary_repository_id")
                == "repo-global-finance"
                and kwargs.get("_cutover_canary_repository_generation") == 4
                and kwargs.get("_cutover_expected_owner_uid")
                == account.pw_uid,
                "clean successor activation did not use its exact internal current-client canary",
            )
            maintenance["events"].append(
                "activate:"
                + Path(str(kwargs["transaction"])).name
                + f":locked={maintenance['writer_locked']}"
            )
            if (
                "post-export-continuation" in name
                and Path(str(kwargs["transaction"])).name
                == bridge.SUCCESSOR_CANDIDATE_DIRECTORY
            ):
                detail = (
                    "legacy /opt release root is not one of the sealed "
                    "dedicated roots"
                )
                error = (
                    "command failed (1): /usr/bin/setpriv --reuid "
                    + str(account.pw_uid)
                    + ": "
                    + json.dumps(
                        {"error": detail, "ok": False},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                bridge._journal(
                    Path(str(kwargs["transaction"])) / bridge.JOURNAL_NAME,
                    {
                        "operation_id": kwargs["operation_id"],
                        "release": str(candidate_release),
                        "release_digest": candidate_release.name,
                        "dropin": str(dropin_path),
                        "dropin_sha256": dropin_sha256,
                        "dropin_identity": {},
                        "broker_socket": str(case / "broker.sock"),
                        "failed_activation": {},
                        "readiness": {
                            "database_generation": "generation-12",
                            "state_revision": 41,
                        },
                        "canaries": [],
                        "baseline": {"ActiveState": "inactive"},
                        "phase": "failed",
                        "attempts": 1,
                        "activation": {
                            "systemd": {"InvocationID": "failed-candidate"},
                            "execution": {"release": str(candidate_release)},
                            "canaries": [],
                        },
                        "error": error,
                        "created_at_epoch": 1,
                        "updated_at_epoch": 2,
                        "readiness_origin": {
                            "database_generation": "generation-12"
                        },
                        "attempt_evidence": {
                            "attempt": 1,
                            "stage": "failed",
                            "last_completed_stage": "systemd-ready",
                            "systemd_ready": {
                                "dropin_identity": {},
                                "readiness_state_revision": 41,
                                "systemd": {
                                    "InvocationID": "failed-candidate"
                                },
                            },
                            "failure_stage": "canaries",
                            "error_sha256": hashlib.sha256(
                                error.encode("utf-8")
                            ).hexdigest(),
                        },
                        "executor_rescue": kwargs.get(
                            "_executor_rescue_client_binding"
                        ),
                    },
                    uid=os.geteuid(),
                )
                raise bridge.BridgeError(error)
            if (
                "post-export-continuation" in name
                and Path(str(kwargs["transaction"])).name
                == bridge.SUCCESSOR_POST_EXPORT_CANDIDATE_DIRECTORY
            ):
                candidate_transaction = Path(str(kwargs["transaction"]))
                candidate_journal = candidate_transaction / bridge.JOURNAL_NAME
                if not candidate_journal.exists():
                    dropin_payload = b"[Service]\nEnvironment=POST_EXPORT=1\n"
                    dropin_path.write_bytes(dropin_payload)
                    dropin_path.chmod(0o644)
                    broker_path = case / "broker.sock"
                    broker_path.write_bytes(b"active\n")
                    broker_path.chmod(0o600)
                    candidate_dropin_sha256 = hashlib.sha256(
                        dropin_payload
                    ).hexdigest()
                    candidate_dropin_identity = bridge._dropin_identity(
                        dropin_path,
                        uid=os.geteuid(),
                        expected_sha256=candidate_dropin_sha256,
                    )
                    bridge._journal(
                        candidate_journal,
                        {
                            "operation_id": kwargs["operation_id"],
                            "release": str(candidate_release),
                            "release_digest": candidate_release.name,
                            "dropin": str(dropin_path),
                            "dropin_sha256": candidate_dropin_sha256,
                            "dropin_identity": candidate_dropin_identity,
                            "broker_socket": str(broker_path),
                            "failed_activation": {},
                            "readiness": {
                                "database_generation": "generation-12"
                            },
                            "canaries": [],
                            "baseline": {"ActiveState": "inactive"},
                            "phase": "ready",
                            "attempts": 1,
                            "activation": {
                                "systemd": {
                                    "InvocationID": "post-export-candidate",
                                    "MainPID": 4242,
                                },
                                "execution": {
                                    "release": str(candidate_release)
                                },
                                "canaries": [],
                            },
                            "error": None,
                            "created_at_epoch": 1,
                            "updated_at_epoch": 2,
                            "readiness_origin": {
                                "database_generation": "generation-12"
                            },
                            "attempt_evidence": {
                                "attempt": 1,
                                "stage": "ready",
                                "last_completed_stage": "canaries",
                                "systemd_ready": {},
                                "failure_stage": None,
                                "error_sha256": None,
                            },
                            "executor_rescue": kwargs.get(
                                "_executor_rescue_client_binding"
                            ),
                        },
                        uid=os.geteuid(),
                    )
                maintenance["candidate_active"] = True
            return {"phase": "ready"}

        restored = bridge._seal(
            bridge.SUCCESSOR_RESTORED_PROOF_KIND,
            {
                "predecessor_journal_sha256": "1" * 64,
                "predecessor_document_sha256": "2" * 64,
                "release": str(predecessor_release),
                "release_digest": "c" * 64,
                "profile": str(profile),
                "profile_identity": {"sha256": hashlib.sha256(original).hexdigest()},
                "profile_owner_binding_sha256": "f" * 64,
                "broker_socket": str(case / "broker.sock"),
                "socket_identity": {},
                "socket_peer": {},
                "dropin": str(case / "bridge.conf"),
                "dropin_identity": {},
                "systemd": {},
                "execution": {},
                "process": {},
                "canary": {},
                "verified_at_epoch": 1,
            },
        )
        patches = ExitStack()
        patches.enter_context(
            mock.patch.object(bridge, "_successor_transaction_fence", fenced)
        )
        patches.enter_context(
            mock.patch.object(
                bridge._load_maintenance_contract(),
                "maintenance_writer_lock",
                maintenance_writer_lock,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_activation_release",
                return_value={"release_digest": "c" * 64},
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_availability_client_release",
                side_effect=lambda release, *, owner_uid: {
                    "release_digest": Path(release).name
                },
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_historical_availability_release",
                side_effect=lambda release, *, owner_uid: {
                    "release_digest": Path(release).name
                },
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_successor_release_pair",
                side_effect=lambda release, *, owner_uid: {
                    "executor_release": str(release),
                    "executor_release_digest": Path(release).name,
                    "client_release": str(release),
                    "client_release_digest": Path(release).name,
                    "historical_client": False,
                },
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_sealed_owner_map_reference", return_value=owner_reference
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_successor_canary_accounts",
                return_value=[
                    {"user": account.pw_name, "uid": account.pw_uid},
                    {"user": "collaborator", "uid": account.pw_uid + 1},
                ],
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_lifecycle_successor_handoff",
                return_value=lifecycle_handoff,
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "_profile_identity", side_effect=profile_identity)
        )
        patches.enter_context(
            mock.patch.object(bridge, "_replace_profile_bytes", side_effect=replace_profile)
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_active_predecessor_for_successor",
                return_value=(
                    verified_predecessor_proof
                    if lifecycle_outer_rearm is not None
                    else {}
                ),
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_successor_predecessor_reference", return_value=predecessor
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_verify_successor_predecessor", return_value=predecessor
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_successor_predecessor_proof",
                return_value=verified_predecessor_proof,
            )
        )
        readiness_proof_patch = patches.enter_context(
            mock.patch.object(
                bridge,
                "_readiness_proof",
                return_value={
                    "path": str(readiness),
                    "document_sha256": "8" * 64,
                    "database_identity": {
                        "device": 7,
                        "inode": 11,
                        "size": 4096,
                    },
                    "database_generation": "generation-12",
                    "state_revision": 41,
                    "snapshot": readiness_origin["snapshot"],
                },
            )
        )
        maintenance["_readiness_proof_patch"] = readiness_proof_patch
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_load_cutover_module",
                return_value=SimpleNamespace(
                    _authority_readiness_result=readiness_result
                ),
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_sqlite_bundle_evidence",
                side_effect=lambda *_args, **_kwargs: copy.deepcopy(
                    sqlite_bundle_state
                ),
            )
        )
        def systemd_state():
            if maintenance["candidate_active"]:
                return {
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 4242,
                    "InvocationID": "post-export-candidate",
                }
            return {
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": 0,
            }

        patches.enter_context(
            mock.patch.object(
                bridge,
                "_systemd_state",
                side_effect=systemd_state,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_loaded_bridge_execution",
                return_value={"release": str(candidate_release)},
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "_ensure_successor_maintenance", ensure_maintenance)
        )
        patches.enter_context(
            mock.patch.object(bridge, "_clear_successor_maintenance", clear_maintenance)
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_maintenance_is_clear",
                side_effect=lambda _binding, uid: not maintenance["active"],
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "_stop_successor_predecessor", return_value={})
        )

        def remove_predecessor_dropin(
            _predecessor, *, dropin: Path, uid: int
        ) -> None:
            _expect(
                uid == os.geteuid() and dropin == dropin_path,
                "successor changed its governed drop-in removal target",
            )
            if dropin_present:
                intent = (
                    transaction
                    / bridge.SUCCESSOR_CLIENT_HANDOFF_INTENT_NAME
                )
                backup = (
                    transaction
                    / bridge.SUCCESSOR_CLIENT_HANDOFF_BACKUP_NAME
                )
                successor_journal = (
                    transaction / bridge.SUCCESSOR_JOURNAL_NAME
                )
                successor_document = json.loads(
                    successor_journal.read_text(encoding="utf-8")
                )
                _expect(
                    intent.is_file()
                    and backup.is_file()
                    and len(
                        successor_document["binding"].get(
                            "client_release_handoffs", []
                        )
                    )
                    == 1,
                    "successor removed the predecessor drop-in before handoff "
                    "evidence was durable",
                )
            dropin.unlink(missing_ok=True)

        patches.enter_context(
            mock.patch.object(
                bridge,
                "_remove_successor_predecessor_dropin",
                side_effect=remove_predecessor_dropin,
            )
        )
        @contextmanager
        def broker_lock(_database, *, expected_uid):
            _expect(
                expected_uid == os.geteuid(),
                "successor changed broker lock UID",
            )
            maintenance["events"].append(
                f"db-enter:writer={maintenance['writer_locked']}"
            )
            try:
                yield
            finally:
                maintenance["events"].append("db-exit")
        patches.enter_context(mock.patch.object(bridge, "_broker_service_lock", broker_lock))

        def export_owner_profile(**_kwargs):
            if name.startswith("client-release-predecessor-retired"):
                successor_journal = (
                    transaction / bridge.SUCCESSOR_JOURNAL_NAME
                )
                successor_document = bridge._load_successor_journal(
                    successor_journal, uid=os.geteuid()
                )
                handoffs = (
                    successor_document["binding"].get(
                        "client_release_handoffs", []
                    )
                    if successor_document is not None
                    else []
                )
                _expect(
                    maintenance["writer_locked"]
                    and len(handoffs) == 1
                    and handoffs[0]["phase"] == "predecessor-retired"
                    and handoffs[0]["predecessor_dropin"]["state"]
                    == "absent",
                    "predecessor-retired owner export ran before its exact "
                    "client lineage was durable under maintenance",
                )
            return repaired, export

        patches.enter_context(
            mock.patch.object(
                bridge,
                "_schema12_owner_bound_profile_export",
                side_effect=export_owner_profile,
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "activate_bridge", side_effect=activate_candidate)
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_candidate_bridge_reference", side_effect=candidate_reference
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_verify_clean_successor_live", side_effect=candidate_ready
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "restore_bridge", return_value={"phase": "restored"})
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_verify_restored_predecessor_live", return_value=restored
            )
        )
        arguments = {
            "candidate_release": candidate_release,
            "release_root": candidate_root,
            "client_release": client_release,
            "transaction": transaction,
            "operation_id": operation_id,
            "predecessor_transaction": predecessor_transaction,
            "predecessor_operation_id": predecessor_operation_id,
            "predecessor_journal_sha256": "1" * 64,
            "predecessor_document_sha256": "2" * 64,
            "failed_installer_transaction": failed_transaction,
            "failed_installer_operation_id": failed_operation_id,
            "readiness_attestation": readiness,
            "database": case / "authority.sqlite3",
            "profile": profile,
            "owner_map": owner_map,
            "owner_map_sha256": "e" * 64,
            "broker_socket": case / "broker.sock",
            "dropin": dropin_path,
            "expected_database_generation": "generation-12",
            "canary_user": account.pw_name,
            "expected_canary_uid": account.pw_uid,
            "canary_project": project,
            "canary_repository_id": "repo-global-finance",
            "canary_repository_generation": 4,
            "lifecycle_transaction_journal": case / "lifecycle-journal.json",
            "lifecycle_transaction_journal_sha256": "9" * 64,
            "lifecycle_transaction_document_sha256": "a" * 64,
            "lifecycle_attestation": case / "lifecycle-result.json",
            "lifecycle_attestation_sha256": "b" * 64,
            "lifecycle_attestation_document_sha256": "d" * 64,
            "additional_canaries": (f"collaborator={account.pw_uid + 1}",),
            "wait_seconds": 5,
            "expected_uid": os.geteuid(),
        }
        return (
            patches,
            arguments,
            original,
            profile,
            maintenance,
            canary_modes,
            replacement_client_release,
        )

    def bind_replacement_client(
        arguments: dict[str, object], replacement_client_release: Path
    ) -> Path:
        inherited_journal = (
            Path(arguments["transaction"]) / bridge.SUCCESSOR_JOURNAL_NAME
        )
        arguments["inherited_successor_journal_sha256"] = hashlib.sha256(
            inherited_journal.read_bytes()
        ).hexdigest()
        arguments["inherited_successor_document_sha256"] = json.loads(
            inherited_journal.read_text(encoding="utf-8")
        )["document_sha256"]
        arguments["client_release"] = replacement_client_release
        return inherited_journal

    def leave_successor_at(
        arguments: dict[str, object], stage: str
    ) -> None:
        def crash(candidate: str) -> None:
            if candidate == stage:
                raise InjectedCrash(stage)

        try:
            bridge.replace_ready_bridge_with_clean_successor(
                **arguments, failpoint=crash
            )
        except InjectedCrash:
            return
        _fail(f"successor fixture did not stop at {stage}")

    def advance_removed_predecessor_to_retired(
        arguments: dict[str, object],
    ) -> dict[str, object]:
        journal = (
            Path(arguments["transaction"]) / bridge.SUCCESSOR_JOURNAL_NAME
        )
        current = bridge._load_successor_journal(
            journal, uid=os.geteuid()
        )
        _expect(
            current is not None
            and current["phase"] == "predecessor-dropin-remove-intent"
            and current["candidate"] == {"activation": None, "readiness": None}
            and "client_release_handoffs" not in current["binding"]
            and not Path(arguments["dropin"]).exists(),
            "external predecessor retirement fixture did not start from the "
            "exact removed-drop-in boundary",
        )
        payload = {
            key: value
            for key, value in current.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["phase"] = "predecessor-retired"
        payload["updated_at_epoch"] = int(payload["updated_at_epoch"]) + 1
        retired = bridge._successor_journal(
            journal, payload, uid=os.geteuid()
        )
        _expect(
            retired["phase"] == "predecessor-retired"
            and retired["candidate"]
            == {"activation": None, "readiness": None}
            and retired["profile"]["repaired_payload_sha256"] is None
            and retired["profile"]["after_identity"] is None
            and "export_evidence" not in retired["profile"],
            "external predecessor retirement fixture crossed owner export",
        )
        return retired

    for stage in failpoints:
        (
            patches,
            arguments,
            _original,
            _profile,
            maintenance,
            canary_modes,
            _replacement_client_release,
        ) = fixture(stage)
        with patches:
            injected = {"done": False}
            rescue_precondition_calls = {"count": 0}

            def crash(candidate: str) -> None:
                if candidate == stage and not injected["done"]:
                    injected["done"] = True
                    raise InjectedCrash(stage)

            try:
                bridge.replace_ready_bridge_with_clean_successor(
                    **arguments, failpoint=crash
                )
            except InjectedCrash:
                pass
            else:
                _fail(f"successor failpoint did not fire: {stage}")
            result = bridge.replace_ready_bridge_with_clean_successor(**arguments)
            _expect(
                result["ok"] is True
                and result["terminal"]["status"] == "committed"
                and maintenance["active"] is False,
                f"successor did not converge after {stage}",
            )
            _expect(
                True in canary_modes and False in canary_modes,
                f"successor did not prove both maintenance and public canary paths after {stage}",
            )

    (
        patches,
        arguments,
        original,
        profile,
        maintenance,
        canary_modes,
        _replacement_client_release,
    ) = fixture("abort")
    with patches:
        def crash_after_profile(stage: str) -> None:
            if stage == "after-profile-repair":
                raise InjectedCrash(stage)

        try:
            bridge.replace_ready_bridge_with_clean_successor(
                **arguments, failpoint=crash_after_profile
            )
        except InjectedCrash:
            pass
        else:
            _fail("successor abort fixture did not stop after profile replacement")
        _expect_bridge_error(
            bridge,
            lambda: bridge.abort_clean_bridge_successor(
                transaction=arguments["transaction"],
                operation_id=arguments["operation_id"],
                expected_uid=os.geteuid(),
            ),
            "forward-only",
        )
        committed = bridge.replace_ready_bridge_with_clean_successor(**arguments)
        _expect(
            committed["terminal"]["status"] == "committed"
            and profile.read_bytes() != original
            and maintenance["active"] is False,
            "inherited successor did not converge through forward replay",
        )
        _expect(
            True in canary_modes and False in canary_modes,
            "forward replay did not exercise both successor canary paths",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        maintenance,
        canary_modes,
        replacement_client_release,
    ) = fixture("client-release-migration")
    with patches:
        def crash_after_dropin_remove(stage: str) -> None:
            if stage == "after-predecessor-dropin-remove":
                raise InjectedCrash(stage)

        try:
            bridge.replace_ready_bridge_with_clean_successor(
                **arguments, failpoint=crash_after_dropin_remove
            )
        except InjectedCrash:
            pass
        else:
            _fail(
                "successor client-release migration fixture did not stop at "
                "predecessor drop-in removal"
            )
        bind_replacement_client(arguments, replacement_client_release)
        migrated = bridge.replace_ready_bridge_with_clean_successor(**arguments)
        _expect(
            migrated["ok"] is True
            and migrated["terminal"]["status"] == "committed"
            and maintenance["active"] is False,
            "new immutable successor client did not rescue the inherited journal",
        )
        _expect(
            True in canary_modes and False in canary_modes,
            "client-release migration did not prove both successor canary paths",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        maintenance,
        canary_modes,
        replacement_client_release,
    ) = fixture("client-release-predecessor-retired")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        bind_replacement_client(arguments, replacement_client_release)
        migrated = bridge.replace_ready_bridge_with_clean_successor(
            **arguments
        )
        _expect(
            migrated["ok"] is True
            and migrated["terminal"]["status"] == "committed"
            and maintenance["active"] is False
            and True in canary_modes
            and False in canary_modes,
            "predecessor-retired immutable client handoff did not converge",
        )

    def exercise_executor_rescue(stage: str | None) -> None:
        post_export_continuation = bool(
            stage and stage.startswith("post-export-continuation")
        )
        post_export_action = (
            stage.partition(":")[2]
            if post_export_continuation and ":" in str(stage)
            else None
        )
        post_export_failpoint = (
            post_export_action
            if post_export_action
            not in {"tamper-original", "tamper-backup"}
            else None
        )
        (
            patches,
            arguments,
            _original,
            _profile,
            maintenance,
            canary_modes,
            replacement_client_release,
        ) = fixture(
            "client-release-executor-rescue-"
            + (stage or "complete")
        )
        with patches:
            leave_successor_at(
                arguments, "after-predecessor-dropin-remove"
            )
            advance_removed_predecessor_to_retired(arguments)
            journal = bind_replacement_client(
                arguments, replacement_client_release
            )
            leave_successor_at(
                arguments, "after-successor-client-release-handoff"
            )
            current = bridge._load_successor_journal(
                journal, uid=os.geteuid()
            )
            _expect(
                current is not None
                and current["phase"] == "predecessor-retired"
                and current["binding"]["client_release"]
                == str(replacement_client_release)
                and len(
                    current["binding"]["client_release_handoffs"]
                )
                == 1,
                "executor rescue fixture did not retain exactly one client handoff",
            )
            handoff = current["binding"]["client_release_handoffs"][0]
            # A read-only SQLite observer may advance WAL/SHM metadata after
            # the first handoff is sealed.  Executor rescue must tolerate only
            # these volatile timestamps; the ordinary retained-handoff path
            # remains exact and the stable fields stay unchanged.
            sqlite_bundle_state = maintenance["_sqlite_bundle_state"]
            sqlite_bundle_state["sidecars"]["-wal"]["ctime_ns"] += 101
            sqlite_bundle_state["sidecars"]["-shm"]["mtime_ns"] += 103
            sqlite_bundle_state["sidecars"]["-shm"]["ctime_ns"] += 107
            owner_reference = current["binding"]["owner_map"]
            refresh_record = {
                "previous": owner_reference,
                "refreshed": owner_reference,
                "previous_source_state_revision": 40,
                "refreshed_source_state_revision": 41,
                "lifecycle_attestation_document_sha256": "d" * 64,
                "lifecycle_preclear_state_revision": 40,
            }
            payload = {
                key: value
                for key, value in current.items()
                if key
                not in {"schema_version", "kind", "document_sha256"}
            }
            profile_state = dict(payload["profile"])
            profile_state["owner_binding_refresh"] = refresh_record
            payload["profile"] = profile_state
            payload["updated_at_epoch"] = int(payload["updated_at_epoch"]) + 1
            current = bridge._successor_journal(
                journal, payload, uid=os.geteuid()
            )
            pre_rescue_raw_sha256 = hashlib.sha256(
                journal.read_bytes()
            ).hexdigest()
            pre_rescue_document_sha256 = current["document_sha256"]
            arguments["inherited_successor_journal_sha256"] = (
                pre_rescue_raw_sha256
            )
            arguments["inherited_successor_document_sha256"] = (
                pre_rescue_document_sha256
            )
            live_state = {
                "owner_binding_refresh": refresh_record,
                "predecessor_lineage": {
                    "operation_id": current["predecessor"][
                        "operation_id"
                    ],
                    "absence": {"state": "absent"},
                    "descriptor": "sealed-rearm-lineage",
                },
                "profile_identity": handoff["profile_identity"],
                "profile_backup": handoff["profile_backup"],
                "readiness_attestation": handoff[
                    "readiness_attestation"
                ],
                "database_bundle": handoff["database_bundle"],
                "database_readiness": handoff["database_readiness"],
                "broker_state": handoff["broker_state"],
                "predecessor_dropin": handoff["predecessor_dropin"],
            }
            requested_binding = dict(current["binding"])
            requested_binding.pop("client_release_handoffs", None)
            client_precondition = {
                key: value
                for key, value in live_state.items()
                if key
                not in {"owner_binding_refresh", "predecessor_lineage"}
            }

            def stable_client_precondition(
                *_args: object, **kwargs: object
            ) -> dict[str, object]:
                _expect(
                    kwargs.get("_stable_retired_sidecar_timestamps") is True,
                    "executor rescue did not request stable WAL/SHM evidence",
                )
                return copy.deepcopy(client_precondition)

            with (
                mock.patch.object(
                    bridge,
                    "_verified_owner_map_refresh_relation",
                    return_value=refresh_record,
                ),
                mock.patch.object(
                    bridge,
                    "_successor_client_handoff_precondition",
                    side_effect=stable_client_precondition,
                ),
                mock.patch.object(
                    bridge,
                    "_successor_executor_rescue_predecessor_lineage",
                    side_effect=lambda *_args, **_kwargs: copy.deepcopy(
                        live_state["predecessor_lineage"]
                    ),
                ),
                mock.patch.object(
                    bridge,
                    "_refresh_inherited_lifecycle_owner_map",
                    side_effect=AssertionError(
                        "executor rescue mutated owner refresh before intent"
                    ),
                ),
            ):
                _expect(
                    bridge._successor_executor_rescue_precondition(
                        current,
                        requested_binding=requested_binding,
                        terminal_path=journal.parent / "terminal",
                        completion_path=journal.parent / "completion",
                        database=Path(arguments["database"]),
                        profile=Path(arguments["profile"]),
                        broker_socket=Path(arguments["broker_socket"]),
                        dropin=Path(arguments["dropin"]),
                        expected_uid=os.geteuid(),
                    )
                    == live_state,
                    "executor rescue precondition did not bind the exact owner refresh",
                )
            with (
                mock.patch.object(
                    bridge,
                    "_verified_owner_map_refresh_relation",
                    return_value={**refresh_record, "refreshed": {}},
                ),
                mock.patch.object(
                    bridge,
                    "_successor_client_handoff_precondition",
                    side_effect=stable_client_precondition,
                ),
                mock.patch.object(
                    bridge,
                    "_successor_executor_rescue_predecessor_lineage",
                    side_effect=lambda *_args, **_kwargs: copy.deepcopy(
                        live_state["predecessor_lineage"]
                    ),
                ),
                mock.patch.object(
                    bridge,
                    "_refresh_inherited_lifecycle_owner_map",
                    side_effect=AssertionError(
                        "executor rescue mutated owner refresh before intent"
                    ),
                ),
            ):
                _expect_bridge_error(
                    bridge,
                    lambda: bridge._successor_executor_rescue_precondition(
                        current,
                        requested_binding=requested_binding,
                        terminal_path=journal.parent / "terminal",
                        completion_path=journal.parent / "completion",
                        database=Path(arguments["database"]),
                        profile=Path(arguments["profile"]),
                        broker_socket=Path(arguments["broker_socket"]),
                        dropin=Path(arguments["dropin"]),
                        expected_uid=os.geteuid(),
                    ),
                    "owner refresh changed",
                )
            candidate_release = Path(arguments["candidate_release"])
            rescue_release = Path(arguments["release_root"]) / ("f" * 64)
            rescue_release.mkdir(mode=0o700)
            release_pair = {
                "executor_release": str(rescue_release),
                "executor_release_digest": rescue_release.name,
                "client_release": str(replacement_client_release),
                "client_release_digest": replacement_client_release.name,
                "historical_client": True,
            }
            _expect(
                bridge._routes_successor_executor_rescue(
                    current,
                    requested_binding=requested_binding,
                    release_pair=release_pair,
                    inherited_journal_sha256=pre_rescue_raw_sha256,
                    inherited_document_sha256=(
                        pre_rescue_document_sha256
                    ),
                )
                and not bridge._routes_successor_executor_rescue(
                    current,
                    requested_binding=requested_binding,
                    release_pair=release_pair,
                    inherited_journal_sha256=None,
                    inherited_document_sha256=(
                        pre_rescue_document_sha256
                    ),
                ),
                "executor rescue route did not require both exact preimage digests",
            )
            changed_candidate_binding = dict(requested_binding)
            changed_candidate_binding["candidate_release"] = str(
                Path(arguments["release_root"]) / ("8" * 64)
            )
            _expect(
                not bridge._routes_successor_executor_rescue(
                    current,
                    requested_binding=changed_candidate_binding,
                    release_pair=release_pair,
                    inherited_journal_sha256=pre_rescue_raw_sha256,
                    inherited_document_sha256=(
                        pre_rescue_document_sha256
                    ),
                ),
                "executor rescue admitted a changed journal-bound candidate",
            )
            post_export = copy.deepcopy(current)
            post_export["phase"] = "profile-repaired"
            _expect(
                not bridge._routes_successor_executor_rescue(
                    post_export,
                    requested_binding=requested_binding,
                    release_pair=release_pair,
                    inherited_journal_sha256=pre_rescue_raw_sha256,
                    inherited_document_sha256=(
                        pre_rescue_document_sha256
                    ),
                ),
                "executor rescue route admitted post-export creation",
            )

            injected = {"done": False}

            def crash(candidate: str) -> None:
                if candidate == stage and not injected["done"]:
                    injected["done"] = True
                    raise InjectedCrash(candidate)

            def rescue_precondition(
                *_args: object, **_kwargs: object
            ) -> dict[str, object]:
                rescue_precondition_calls["count"] += 1
                return live_state

            def invoke_rescue(
                *,
                failpoint=None,
                candidate_release_override: Path | None = None,
            ) -> dict[str, object]:
                successor_arguments = dict(arguments)
                if candidate_release_override is not None:
                    successor_arguments["candidate_release"] = (
                        candidate_release_override
                    )
                successor_arguments.pop("client_release", None)
                successor_arguments.pop(
                    "inherited_successor_journal_sha256", None
                )
                successor_arguments.pop(
                    "inherited_successor_document_sha256", None
                )
                if failpoint is not None:
                    successor_arguments["failpoint"] = failpoint
                return bridge.rescue_ready_bridge_with_clean_successor(
                    previous_executor_release=replacement_client_release,
                    previous_executor_release_digest=(
                        replacement_client_release.name
                    ),
                    retained_client_release=replacement_client_release,
                    retained_client_release_digest=(
                        replacement_client_release.name
                    ),
                    rescue_executor_release=rescue_release,
                    rescue_executor_release_digest=rescue_release.name,
                    inherited_successor_journal_sha256=(
                        pre_rescue_raw_sha256
                    ),
                    inherited_successor_document_sha256=(
                        pre_rescue_document_sha256
                    ),
                    successor_arguments=successor_arguments,
                )

            with (
                mock.patch.object(bridge, "ROOT", rescue_release),
                mock.patch.object(
                    bridge,
                    "_refresh_inherited_lifecycle_owner_map",
                    side_effect=AssertionError(
                        "executor rescue mutated owner refresh before intent"
                    ),
                ),
                mock.patch.object(
                    bridge,
                    "_verify_retained_lifecycle_rearm_descriptor_lineage",
                    return_value=({}, {}),
                ),
                mock.patch.object(
                    bridge,
                    "_verify_successor_release_pair",
                    return_value=release_pair,
                ),
                mock.patch.object(
                    bridge,
                    "_verified_owner_map_refresh_relation",
                    return_value=refresh_record,
                ),
                mock.patch.object(
                    bridge,
                    "_successor_executor_rescue_precondition",
                    side_effect=rescue_precondition,
                ),
                mock.patch.object(
                    bridge,
                    "_successor_executor_rescue_predecessor_lineage",
                    side_effect=lambda *_args, **_kwargs: copy.deepcopy(
                        live_state["predecessor_lineage"]
                    ),
                ),
            ):
                handoff_release: Path | None = None
                handoff_preimage_raw_sha256: str | None = None
                handoff_preimage_document_sha256: str | None = None
                handoff_stages = {
                    "after-successor-rescue-executor-handoff-intent",
                    "after-successor-rescue-executor-handoff-backup",
                    "after-successor-rescue-executor-handoff",
                }
                requires_first_handoff = (
                    stage in handoff_stages or post_export_continuation
                )
                if requires_first_handoff:
                    def stop_after_rescue_publication(
                        candidate: str,
                    ) -> None:
                        if candidate == "after-successor-executor-rescue":
                            raise InjectedCrash(candidate)

                    try:
                        invoke_rescue(
                            failpoint=stop_after_rescue_publication
                        )
                    except InjectedCrash:
                        pass
                    else:
                        _fail(
                            "executor rescue publication setup did not stop"
                        )
                elif stage is not None:
                    try:
                        invoke_rescue(failpoint=crash)
                    except InjectedCrash:
                        pass
                    else:
                        _fail(
                            "executor rescue failpoint did not fire: "
                            f"{stage}"
                        )
                if (
                    stage == "after-successor-executor-rescue"
                    or requires_first_handoff
                ):
                    published_rescue = bridge._load_successor_journal(
                        journal, uid=os.geteuid()
                    )
                    _expect(
                        published_rescue is not None
                        and published_rescue["phase"]
                        == "predecessor-retired"
                        and "executor_rescue"
                        in published_rescue["binding"]
                        and "executor_rescue_handoff"
                        not in published_rescue["binding"],
                        "executor rescue failpoint did not retain its publication",
                    )
                    original_rescue = copy.deepcopy(
                        published_rescue["binding"]["executor_rescue"]
                    )
                    original_rescue_sha256 = hashlib.sha256(
                        bridge._canonical(original_rescue)
                    ).hexdigest()
                    handoff_preimage_raw_sha256 = hashlib.sha256(
                        journal.read_bytes()
                    ).hexdigest()
                    handoff_preimage_document_sha256 = published_rescue[
                        "document_sha256"
                    ]
                    handoff_release = (
                        Path(arguments["release_root"]) / ("7" * 64)
                    )
                    handoff_release.mkdir(mode=0o700)
                    handoff_pair = {
                        **release_pair,
                        "executor_release": str(handoff_release),
                        "executor_release_digest": handoff_release.name,
                    }
                    successor_arguments = dict(arguments)
                    successor_arguments.pop("client_release", None)
                    successor_arguments.pop(
                        "inherited_successor_journal_sha256", None
                    )
                    successor_arguments.pop(
                        "inherited_successor_document_sha256", None
                    )
                    def invoke_first_handoff(
                        *, failpoint=None
                    ) -> dict[str, object]:
                        handoff_arguments = dict(successor_arguments)
                        if failpoint is not None:
                            handoff_arguments["failpoint"] = failpoint
                        with (
                            mock.patch.object(
                                bridge, "ROOT", handoff_release
                            ),
                            mock.patch.object(
                                bridge,
                                "_verify_successor_release_pair",
                                return_value=handoff_pair,
                            ),
                        ):
                            return bridge.handoff_rescued_executor_with_clean_successor(
                                executor_rescue_sha256=(
                                    original_rescue_sha256
                                ),
                                previous_executor_release=rescue_release,
                                previous_executor_release_digest=(
                                    rescue_release.name
                                ),
                                retained_client_release=(
                                    replacement_client_release
                                ),
                                retained_client_release_digest=(
                                    replacement_client_release.name
                                ),
                                successor_executor_release=handoff_release,
                                successor_executor_release_digest=(
                                    handoff_release.name
                                ),
                                inherited_successor_journal_sha256=(
                                    handoff_preimage_raw_sha256
                                ),
                                inherited_successor_document_sha256=(
                                    handoff_preimage_document_sha256
                                ),
                                successor_arguments=handoff_arguments,
                            )
                    if stage in handoff_stages:
                        try:
                            invoke_first_handoff(failpoint=crash)
                        except InjectedCrash:
                            pass
                        else:
                            _fail(
                                "executor handoff failpoint did not fire: "
                                f"{stage}"
                            )
                    if post_export_continuation:
                        try:
                            invoke_first_handoff()
                        except bridge.BridgeError as error:
                            _expect(
                                str(error).endswith(
                                    '{"error":"legacy /opt release root is not one of the sealed dedicated roots","ok":false}'
                                ),
                                "post-export fixture failed at the wrong boundary",
                            )
                        else:
                            _fail(
                                "post-export fixture did not retain its failed candidate"
                            )
                        post_export_current = bridge._load_successor_journal(
                            journal, uid=os.geteuid()
                        )
                        _expect(
                            post_export_current is not None
                            and post_export_current["phase"]
                            == "candidate-activation-intent"
                            and post_export_current["candidate"]
                            == {"activation": None, "readiness": None},
                            "post-export fixture crossed its outer activation boundary",
                        )
                        profile_state = copy.deepcopy(
                            post_export_current["profile"]
                        )
                        export_state = copy.deepcopy(
                            profile_state["export_evidence"]
                        )
                        export_state["database_identity"] = copy.deepcopy(
                            maintenance["_sqlite_bundle_state"]["main"]
                        )
                        export_state["database_sidecars"] = copy.deepcopy(
                            maintenance["_sqlite_bundle_state"]["sidecars"]
                        )
                        profile_state["export_evidence"] = export_state
                        post_export_payload = {
                            key: value
                            for key, value in post_export_current.items()
                            if key
                            not in {"schema_version", "kind", "document_sha256"}
                        }
                        post_export_payload["profile"] = profile_state
                        post_export_payload["updated_at_epoch"] = (
                            int(post_export_payload["updated_at_epoch"]) + 1
                        )
                        post_export_current = bridge._successor_journal(
                            journal,
                            post_export_payload,
                            uid=os.geteuid(),
                        )
                        # A failed broker can legitimately checkpoint the empty
                        # WAL while stopping.  The durable authority revision and
                        # stable database identity stay exact, but main-file
                        # timestamps/content bytes may change and the zero-byte
                        # WAL plus SHM can disappear.  Post-export recovery must
                        # accept that checkpoint without accepting an authority
                        # regression.  Broker startup recovery may also append
                        # state after the owner map was refreshed.  The live
                        # readiness proof must remain a safe descendant with the
                        # same generation, stable database identity and complete
                        # invariant set; its revision may only move forward.
                        checkpointed_bundle = maintenance[
                            "_sqlite_bundle_state"
                        ]
                        checkpointed_bundle["main"]["mtime_ns"] += 109
                        checkpointed_bundle["main"]["ctime_ns"] += 113
                        checkpointed_bundle["main"]["sha256"] = "9" * 64
                        checkpointed_bundle["sidecars"] = {
                            "-wal": None,
                            "-shm": None,
                        }
                        readiness_proof_patch = maintenance[
                            "_readiness_proof_patch"
                        ]
                        descendant_readiness = copy.deepcopy(
                            readiness_proof_patch.return_value
                        )
                        descendant_readiness["state_revision"] = 46
                        descendant_readiness["snapshot"]["metadata"][
                            "state_revision"
                        ] = 46
                        readiness_proof_patch.return_value = descendant_readiness
                        post_export_raw_sha256 = hashlib.sha256(
                            journal.read_bytes()
                        ).hexdigest()
                        post_export_document_sha256 = post_export_current[
                            "document_sha256"
                        ]
                        continuation_release = (
                            Path(arguments["release_root"]) / ("6" * 64)
                        )
                        continuation_release.mkdir(mode=0o700)
                        continuation_pair = {
                            **release_pair,
                            "executor_release": str(continuation_release),
                            "executor_release_digest": continuation_release.name,
                        }
                        continuation_arguments = dict(arguments)
                        continuation_arguments.pop("client_release", None)
                        continuation_arguments.pop(
                            "inherited_successor_journal_sha256", None
                        )
                        continuation_arguments.pop(
                            "inherited_successor_document_sha256", None
                        )
                        handoff_binding = post_export_current["binding"][
                            "executor_rescue_handoff"
                        ]
                        handoff_sha256 = hashlib.sha256(
                            bridge._canonical(handoff_binding)
                        ).hexdigest()
                        lock_count_before = maintenance[
                            "writer_lock_acquisitions"
                        ]
                        continuation_stages: list[tuple[str, bool]] = []
                        continuation_crashed = {"done": False}

                        def observe_continuation(stage_name: str) -> None:
                            continuation_stages.append(
                                (
                                    stage_name,
                                    bool(maintenance["writer_locked"]),
                                )
                            )
                            if (
                                stage_name == post_export_failpoint
                                and not continuation_crashed["done"]
                            ):
                                continuation_crashed["done"] = True
                                raise InjectedCrash(stage_name)

                        with (
                            mock.patch.object(
                                bridge, "ROOT", continuation_release
                            ),
                            mock.patch.object(
                                bridge,
                                "_verify_successor_release_pair",
                                return_value=continuation_pair,
                            ),
                        ):
                            def invoke_continuation() -> dict[str, object]:
                                return bridge.continue_post_export_rescued_executor_with_clean_successor(
                                    executor_rescue_sha256=original_rescue_sha256,
                                    executor_rescue_handoff_sha256=handoff_sha256,
                                    previous_executor_release=handoff_release,
                                    previous_executor_release_digest=(
                                        handoff_release.name
                                    ),
                                    retained_client_release=(
                                        replacement_client_release
                                    ),
                                    retained_client_release_digest=(
                                        replacement_client_release.name
                                    ),
                                    successor_executor_release=(
                                        continuation_release
                                    ),
                                    successor_executor_release_digest=(
                                        continuation_release.name
                                    ),
                                    inherited_successor_journal_sha256=(
                                        post_export_raw_sha256
                                    ),
                                    inherited_successor_document_sha256=(
                                        post_export_document_sha256
                                    ),
                                    successor_arguments={
                                        **continuation_arguments,
                                        "failpoint": observe_continuation,
                                    },
                                )

                            if post_export_action is None:
                                accepted_readiness = copy.deepcopy(
                                    readiness_proof_patch.return_value
                                )
                                regressed_readiness = copy.deepcopy(
                                    accepted_readiness
                                )
                                regressed_readiness["state_revision"] = 40
                                regressed_readiness["snapshot"]["metadata"][
                                    "state_revision"
                                ] = 40
                                readiness_proof_patch.return_value = (
                                    regressed_readiness
                                )
                                _expect_bridge_error(
                                    bridge,
                                    invoke_continuation,
                                    "post-export repaired profile binding changed",
                                )
                                readiness_proof_patch.return_value = (
                                    accepted_readiness
                                )

                            try:
                                migrated = invoke_continuation()
                            except InjectedCrash:
                                _expect(
                                    post_export_failpoint is not None,
                                    "unexpected post-export continuation crash",
                                )
                                migrated = invoke_continuation()
                        retained_post_export = bridge._load_successor_journal(
                            journal, uid=os.geteuid()
                        )
                        continuation_record = retained_post_export["binding"][
                            "executor_rescue_post_export_continuation"
                        ]
                        failed_journal = (
                            journal.parent
                            / bridge.SUCCESSOR_CANDIDATE_DIRECTORY
                            / bridge.JOURNAL_NAME
                        )
                        failed_backup = (
                            journal.parent
                            / bridge.SUCCESSOR_POST_EXPORT_FAILED_CANDIDATE_BACKUP_NAME
                        )
                        fresh_operation = str(
                            uuid.uuid5(
                                uuid.UUID(str(arguments["operation_id"])),
                                "schema12-clean-successor-post-export-candidate",
                            )
                        )
                        _expect(
                            maintenance["writer_lock_acquisitions"]
                            == lock_count_before
                            + (
                                2
                                if post_export_failpoint is not None
                                or post_export_action is None
                                else 1
                            )
                            and all(
                                locked
                                for stage_name, locked in continuation_stages
                                if stage_name
                                not in {
                                    "after-maintenance-clear",
                                    "after-completion-publish",
                                }
                            )
                            and all(
                                not locked
                                for stage_name, locked in continuation_stages
                                if stage_name
                                in {
                                    "after-maintenance-clear",
                                    "after-completion-publish",
                                }
                            )
                            and any(
                                event
                                == "activate:clean-successor-candidate-post-export-continuation:locked=True"
                                for event in maintenance["events"]
                            )
                            and any(
                                event == "db-enter:writer=True"
                                for event in maintenance["events"]
                            )
                            and retained_post_export is not None
                            and retained_post_export["phase"]
                            == "candidate-verified"
                            and continuation_record[
                                "successor_candidate_operation_id"
                            ]
                            == fresh_operation
                            and Path(
                                continuation_record[
                                    "successor_candidate_transaction"
                                ]
                            ).name
                            == bridge.SUCCESSOR_POST_EXPORT_CANDIDATE_DIRECTORY
                            and failed_backup.read_bytes()
                            == failed_journal.read_bytes()
                            and migrated["terminal"]["executor_rescue"].get(
                                "executor_rescue_post_export_continuation_sha256"
                            )
                            == hashlib.sha256(
                                bridge._canonical(continuation_record)
                            ).hexdigest()
                            and migrated["completion"]["executor_rescue"]
                            == migrated["terminal"]["executor_rescue"],
                            "post-export continuation lost its lock, failed attempt, fresh target, or terminal lineage: "
                            f"locks={maintenance['writer_lock_acquisitions'] - lock_count_before}, "
                            f"stages={continuation_stages!r}, events={maintenance['events']!r}, "
                            f"phase={retained_post_export.get('phase') if retained_post_export else None}, "
                            f"op={continuation_record.get('successor_candidate_operation_id')!r}, "
                            f"expected_op={fresh_operation!r}, "
                            f"backup_equal={failed_backup.read_bytes() == failed_journal.read_bytes()}, "
                            f"terminal={migrated['terminal']['executor_rescue']!r}",
                        )
                        if post_export_action in {
                            "tamper-original",
                            "tamper-backup",
                        }:
                            tampered_path = (
                                failed_journal
                                if post_export_action == "tamper-original"
                                else failed_backup
                            )
                            tampered_path.write_bytes(
                                tampered_path.read_bytes() + b"\n"
                            )
                            tampered_path.chmod(0o600)
                            with (
                                mock.patch.object(
                                    bridge, "ROOT", continuation_release
                                ),
                                mock.patch.object(
                                    bridge,
                                    "_verify_successor_release_pair",
                                    return_value=continuation_pair,
                                ),
                            ):
                                _expect_bridge_error(
                                    bridge,
                                    invoke_continuation,
                                    "post-export",
                                )
                        return
                    migrated = invoke_first_handoff()
                    _expect(
                        published_rescue["binding"]["executor_rescue"]
                        == original_rescue,
                        "executor handoff mutated the loaded original rescue",
                    )
                else:
                    migrated = invoke_rescue()

                def invoke_handoff_replay(
                    *,
                    candidate_release_override: Path | None = None,
                    successor_release_override: Path | None = None,
                ) -> dict[str, object]:
                    _expect(
                        handoff_release is not None
                        and handoff_preimage_raw_sha256 is not None
                        and handoff_preimage_document_sha256 is not None,
                        "executor handoff replay lacks its sealed preimage",
                    )
                    successor_arguments = dict(arguments)
                    if candidate_release_override is not None:
                        successor_arguments["candidate_release"] = (
                            candidate_release_override
                        )
                    successor_arguments.pop("client_release", None)
                    successor_arguments.pop(
                        "inherited_successor_journal_sha256", None
                    )
                    successor_arguments.pop(
                        "inherited_successor_document_sha256", None
                    )
                    successor_release = (
                        successor_release_override or handoff_release
                    )
                    replay_pair = {
                        **release_pair,
                        "executor_release": str(successor_release),
                        "executor_release_digest": successor_release.name,
                    }
                    with (
                        mock.patch.object(bridge, "ROOT", successor_release),
                        mock.patch.object(
                            bridge,
                            "_verify_successor_release_pair",
                            return_value=replay_pair,
                        ),
                    ):
                        return bridge.handoff_rescued_executor_with_clean_successor(
                            executor_rescue_sha256=original_rescue_sha256,
                            previous_executor_release=rescue_release,
                            previous_executor_release_digest=(
                                rescue_release.name
                            ),
                            retained_client_release=(
                                replacement_client_release
                            ),
                            retained_client_release_digest=(
                                replacement_client_release.name
                            ),
                            successor_executor_release=successor_release,
                            successor_executor_release_digest=(
                                successor_release.name
                            ),
                            inherited_successor_journal_sha256=(
                                handoff_preimage_raw_sha256
                            ),
                            inherited_successor_document_sha256=(
                                handoff_preimage_document_sha256
                            ),
                            successor_arguments=successor_arguments,
                        )

                invoke_retained = (
                    invoke_handoff_replay
                    if handoff_release is not None
                    else invoke_rescue
                )
                _expect(
                    migrated["ok"] is True
                    and migrated["terminal"]["status"] == "committed"
                    and maintenance["active"] is False
                    and True in canary_modes
                    and False in canary_modes,
                    "executor rescue did not converge through terminal completion",
                )
                retained = bridge._load_successor_journal(
                    journal, uid=os.geteuid()
                )
                _expect(
                    retained is not None
                    and retained["phase"] == "candidate-verified",
                    "executor rescue did not retain its completed journal",
                )
                retained_binding = retained["binding"]
                rescue = retained_binding.get("executor_rescue")
                rescue_sha256 = bridge._successor_executor_rescue_sha256(
                    retained_binding, expected_uid=os.geteuid()
                )
                runtime_rescue = (
                    bridge._successor_executor_rescue_runtime_binding(
                        rescue,
                        expected_uid=os.geteuid(),
                        handoff_value=retained_binding.get(
                            "executor_rescue_handoff"
                        ),
                    )
                )
                _expect(
                    isinstance(rescue, dict)
                    and retained_binding["client_release"]
                    == str(replacement_client_release)
                    and retained_binding["candidate_release"]
                    == str(candidate_release)
                    and retained_binding["candidate_release_digest"]
                    == candidate_release.name
                    and retained_binding["candidate_release_root"]
                    == str(Path(arguments["release_root"]))
                    and len(
                        retained_binding["client_release_handoffs"]
                    )
                    == 1
                    and retained_binding["client_release_handoffs"][0]
                    == handoff
                    and rescue["journal_raw_sha256"]
                    == pre_rescue_raw_sha256
                    and rescue["journal_document_sha256"]
                    == pre_rescue_document_sha256
                    and rescue["rescue_executor_release"]
                    == str(rescue_release)
                    and retained_binding["candidate_release"]
                    != rescue["rescue_executor_release"]
                    and (
                        handoff_release is None
                        or runtime_rescue["executor_release"]
                        == str(handoff_release)
                    )
                    and (
                        handoff_release is None
                        or runtime_rescue[
                            "executor_rescue_handoff_sha256"
                        ]
                        == bridge._successor_executor_handoff_sha256(
                            retained_binding,
                            expected_uid=os.geteuid(),
                        )
                    )
                    and migrated["terminal"]["executor_rescue_sha256"]
                    == rescue_sha256
                    and migrated["completion"]["executor_rescue_sha256"]
                    == rescue_sha256
                    and migrated["terminal"]["executor_rescue"]
                    == runtime_rescue
                    and migrated["completion"]["executor_rescue"]
                    == runtime_rescue
                    and retained["candidate"]["executor_rescue"]
                    == runtime_rescue
                    and retained["candidate"]["readiness"][
                        "executor_rescue"
                    ]
                    == runtime_rescue
                    and retained["candidate"]["executor_rescue_sha256"]
                    == rescue_sha256
                    and retained["candidate"]["readiness"][
                        "executor_rescue_sha256"
                    ]
                    == rescue_sha256
                    and retained["candidate"]["readiness"][
                        "client_release"
                    ]
                    == str(replacement_client_release),
                    "executor rescue lost its client, preimage, or terminal lineage",
                )
                wrong_candidate = Path(arguments["release_root"]) / ("8" * 64)
                wrong_candidate.mkdir(mode=0o700)
                retained_raw_sha256 = hashlib.sha256(
                    journal.read_bytes()
                ).hexdigest()
                _expect_bridge_error(
                    bridge,
                    lambda: invoke_retained(
                        candidate_release_override=wrong_candidate
                    ),
                    (
                        "rescue executor handoff lineage changed"
                        if handoff_release is not None
                        else "historical client requires its exact journaled executor rescue"
                    ),
                )
                _expect(
                    hashlib.sha256(journal.read_bytes()).hexdigest()
                    == retained_raw_sha256,
                    "changed candidate mutated the exact rescue journal binding",
                )
                _expect(
                    rescue_precondition_calls["count"] >= 4,
                    "executor rescue was not revalidated immediately before owner export",
                )
                with mock.patch.object(
                    bridge,
                    "_successor_executor_rescue_precondition",
                    side_effect=AssertionError(
                        "later replay rechecked the retired live boundary"
                    ),
                ):
                    replayed = invoke_retained()
                _expect(
                    replayed["ok"] is True
                    and replayed["replayed"] is True,
                    "later executor-rescue replay did not use retained evidence",
                )
                if handoff_release is not None:
                    second_release = (
                        Path(arguments["release_root"]) / ("6" * 64)
                    )
                    second_release.mkdir(mode=0o700)
                    before_second = hashlib.sha256(
                        journal.read_bytes()
                    ).hexdigest()
                    _expect_bridge_error(
                        bridge,
                        lambda: invoke_handoff_replay(
                            successor_release_override=second_release
                        ),
                        "rescue executor handoff request binding changed",
                    )
                    _expect(
                        hashlib.sha256(journal.read_bytes()).hexdigest()
                        == before_second,
                        "second executor handoff changed the singular lineage",
                    )
                wrong_release = journal.parent / ("9" * 64)
                wrong_pair = {
                    **release_pair,
                    "executor_release": str(wrong_release),
                    "executor_release_digest": wrong_release.name,
                }
                _expect_bridge_error(
                    bridge,
                    lambda: bridge._authorize_successor_release_pair(
                        retained,
                        requested_binding=requested_binding,
                        release_pair=wrong_pair,
                        inherited_journal_sha256=pre_rescue_raw_sha256,
                        inherited_document_sha256=(
                            pre_rescue_document_sha256
                        ),
                    ),
                    "historical client requires its exact journaled executor rescue",
                )
                _expect(
                    not bridge._routes_successor_executor_rescue(
                        retained,
                        requested_binding=requested_binding,
                        release_pair=release_pair,
                        inherited_journal_sha256=hashlib.sha256(
                            journal.read_bytes()
                        ).hexdigest(),
                        inherited_document_sha256=retained[
                            "document_sha256"
                        ],
                    ),
                    "executor rescue accepted post-publication journal digests",
                )
                tampered_payload = {
                    key: value
                    for key, value in retained.items()
                    if key
                    not in {"schema_version", "kind", "document_sha256"}
                }
                tampered_profile = copy.deepcopy(
                    tampered_payload["profile"]
                )
                tampered_profile["owner_binding_refresh"][
                    "refreshed_source_state_revision"
                ] += 1
                tampered_payload["profile"] = tampered_profile
                tampered_payload["updated_at_epoch"] = (
                    int(tampered_payload["updated_at_epoch"]) + 1
                )
                bridge._successor_journal(
                    journal, tampered_payload, uid=os.geteuid()
                )
                _expect_bridge_error(
                    bridge,
                    invoke_retained,
                    (
                        "executor rescue"
                        if handoff_release is not None
                        else "executor rescue state changed"
                    ),
                )

    for executor_rescue_stage in (
        None,
        "after-successor-executor-rescue-intent",
        "after-successor-executor-rescue-backup",
        "after-successor-executor-rescue",
        "after-successor-rescue-executor-handoff-intent",
        "after-successor-rescue-executor-handoff-backup",
        "after-successor-rescue-executor-handoff",
        "post-export-continuation",
        "post-export-continuation:after-successor-post-export-executor-continuation-intent",
        "post-export-continuation:after-successor-post-export-executor-continuation-backup",
        "post-export-continuation:after-successor-post-export-executor-continuation-failed-candidate-backup",
        "post-export-continuation:after-successor-post-export-executor-continuation",
        "post-export-continuation:after-retained-post-export-executor-continuation-verify",
        "post-export-continuation:before-successor-post-export-continuation-candidate-activate",
        "post-export-continuation:after-candidate-activate",
        "post-export-continuation:after-candidate-verify",
        "post-export-continuation:after-terminal-publish",
        "post-export-continuation:after-maintenance-clear",
        "post-export-continuation:after-completion-publish",
        "post-export-continuation:tamper-original",
        "post-export-continuation:tamper-backup",
    ):
        exercise_executor_rescue(executor_rescue_stage)

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        _replacement_client_release,
    ) = fixture("client-release-legacy-dual-release-bypass")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        historical_client = Path(arguments["client_release"])
        historical_pair = {
            "executor_release": str(
                historical_client.parent / ("e" * 64)
            ),
            "executor_release_digest": "e" * 64,
            "client_release": str(historical_client),
            "client_release_digest": historical_client.name,
            "historical_client": True,
        }
        rescue_intent = (
            Path(arguments["transaction"])
            / bridge.SUCCESSOR_EXECUTOR_RESCUE_INTENT_NAME
        )
        with (
            mock.patch.object(
                bridge,
                "_verify_successor_release_pair",
                return_value=historical_pair,
            ),
            mock.patch.object(
                bridge,
                "_refresh_inherited_lifecycle_owner_map",
                side_effect=AssertionError(
                    "ordinary historical rejection mutated owner refresh"
                ),
            ),
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "successor-apply forbids a historical client",
            )
        _expect(
            not rescue_intent.exists() and not rescue_intent.is_symlink(),
            "ordinary successor published executor rescue intent evidence",
        )

    def mutate_bound_file(path: Path, mutation: str) -> None:
        original = path.read_bytes()
        if mutation == "content":
            path.write_bytes(original + b"changed\n")
            path.chmod(0o600)
            return
        if mutation == "inode":
            replacement = path.with_name(f"{path.name}.replacement")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            os.replace(replacement, path)
            return
        if mutation == "symlink":
            target = path.with_name(f"{path.name}.target")
            target.write_bytes(original)
            target.chmod(0o600)
            path.unlink()
            path.symlink_to(target)
            return
        if mutation == "missing":
            path.unlink()
            return
        if mutation == "sealed":
            path.write_text(
                json.dumps({"document_sha256": "0" * 64}) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            return
        _fail(f"unsupported bound-file mutation: {mutation}")

    for evidence_kind, mutations in (
        ("profile-backup", ("content", "inode", "symlink", "missing")),
        ("readiness", ("content", "inode", "sealed")),
    ):
        for boundary in (
            "after-successor-client-release-handoff-intent",
            "after-successor-client-release-handoff",
        ):
            for mutation in mutations:
                (
                    patches,
                    arguments,
                    _original,
                    _profile,
                    _maintenance,
                    _canary_modes,
                    replacement_client_release,
                ) = fixture(
                    "client-release-predecessor-retired-"
                    f"{evidence_kind}-{boundary}-{mutation}"
                )
                with patches:
                    leave_successor_at(
                        arguments, "after-predecessor-dropin-remove"
                    )
                    advance_removed_predecessor_to_retired(arguments)
                    bind_replacement_client(
                        arguments, replacement_client_release
                    )
                    successor_journal = (
                        Path(arguments["transaction"])
                        / bridge.SUCCESSOR_JOURNAL_NAME
                    )
                    retained = bridge._load_successor_journal(
                        successor_journal, uid=os.geteuid()
                    )
                    _expect(
                        retained is not None,
                        "bound evidence race fixture lost its journal",
                    )
                    evidence_path = (
                        Path(retained["profile"]["backup"])
                        if evidence_kind == "profile-backup"
                        else Path(arguments["readiness_attestation"])
                    )
                    injected = {"done": False}

                    def mutate_after_boundary(stage: str) -> None:
                        if stage == boundary and not injected["done"]:
                            injected["done"] = True
                            mutate_bound_file(evidence_path, mutation)

                    _expect_bridge_error(
                        bridge,
                        lambda: bridge.replace_ready_bridge_with_clean_successor(
                            **arguments,
                            failpoint=mutate_after_boundary,
                        ),
                        (
                            "profile backup"
                            if evidence_kind == "profile-backup"
                            else "readiness attestation"
                        ),
                    )

    (
        patches,
        arguments,
        _original,
        _profile,
        maintenance,
        canary_modes,
        replacement_client_release,
    ) = fixture("client-release-predecessor-retired-replay")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        inherited_journal = bind_replacement_client(
            arguments, replacement_client_release
        )
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        retained = bridge._load_successor_journal(
            inherited_journal, uid=os.geteuid()
        )
        _expect(
            retained is not None
            and retained["phase"] == "predecessor-retired"
            and len(
                retained["binding"].get(
                    "client_release_handoffs", []
                )
            )
            == 1
            and retained["binding"]["client_release_handoffs"][0][
                "predecessor_dropin"
            ]["state"]
            == "absent",
            "predecessor-retired crash lost its exact absent-drop-in lineage",
        )
        replayed = bridge.replace_ready_bridge_with_clean_successor(
            **arguments
        )
        _expect(
            replayed["ok"] is True
            and replayed["terminal"]["status"] == "committed"
            and maintenance["active"] is False
            and True in canary_modes
            and False in canary_modes,
            "predecessor-retired retained handoff did not converge",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-predecessor-retired-reappeared")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        dropin = Path(arguments["dropin"])
        dropin.write_bytes(b"[Service]\nEnvironment=REAPPEARED=1\n")
        dropin.chmod(0o644)
        bind_replacement_client(arguments, replacement_client_release)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "requires an absent drop-in",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-predecessor-retired-replay-reappeared")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        dropin = Path(arguments["dropin"])
        dropin.write_bytes(b"[Service]\nEnvironment=REAPPEARED=1\n")
        dropin.chmod(0o644)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "reappeared after absent boundary",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture(
        "client-release-predecessor-retired-post-lineage-reappeared"
    )
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        bind_replacement_client(arguments, replacement_client_release)

        def reappear_after_lineage(stage: str) -> None:
            if stage == "after-successor-client-release-handoff":
                dropin = Path(arguments["dropin"])
                dropin.write_bytes(
                    b"[Service]\nEnvironment=REAPPEARED=1\n"
                )
                dropin.chmod(0o644)

        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments,
                failpoint=reappear_after_lineage,
            ),
            "reappeared after absent boundary",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-predecessor-retired-lineage-tamper")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove"
        )
        advance_removed_predecessor_to_retired(arguments)
        inherited_journal = bind_replacement_client(
            arguments, replacement_client_release
        )
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        retained = bridge._load_successor_journal(
            inherited_journal, uid=os.geteuid()
        )
        _expect(
            retained is not None,
            "predecessor-retired tamper fixture lost its journal",
        )
        payload = {
            key: value
            for key, value in retained.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["binding"]["client_release_handoffs"][0][
            "predecessor_dropin"
        ]["state"] = "present"
        bridge._successor_journal(
            inherited_journal, payload, uid=os.geteuid()
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "handoff binding is invalid",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        maintenance,
        canary_modes,
        replacement_client_release,
    ) = fixture("client-release-pre-removal")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove-intent"
        )
        dropin = Path(arguments["dropin"])
        _expect(
            dropin.is_file(),
            "pre-removal handoff fixture lost its bound predecessor drop-in",
        )
        bind_replacement_client(arguments, replacement_client_release)
        migrated = bridge.replace_ready_bridge_with_clean_successor(
            **arguments
        )
        _expect(
            migrated["ok"] is True
            and migrated["terminal"]["status"] == "committed"
            and not dropin.exists()
            and maintenance["active"] is False
            and True in canary_modes
            and False in canary_modes,
            "pre-removal immutable client handoff did not converge",
        )

    for boundary_failpoint, expected_present in (
        ("after-successor-client-release-handoff", True),
        ("after-predecessor-dropin-remove", False),
    ):
        (
            patches,
            arguments,
            _original,
            _profile,
            maintenance,
            canary_modes,
            replacement_client_release,
        ) = fixture(
            f"client-release-pre-removal-{boundary_failpoint}"
        )
        with patches:
            leave_successor_at(
                arguments, "after-predecessor-dropin-remove-intent"
            )
            bind_replacement_client(
                arguments, replacement_client_release
            )
            leave_successor_at(arguments, boundary_failpoint)
            dropin = Path(arguments["dropin"])
            _expect(
                dropin.exists() is expected_present,
                f"pre-removal boundary {boundary_failpoint} had the wrong "
                "drop-in state",
            )
            replayed = bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            )
            _expect(
                replayed["ok"] is True
                and replayed["terminal"]["status"] == "committed"
                and not dropin.exists()
                and maintenance["active"] is False
                and True in canary_modes
                and False in canary_modes,
                f"pre-removal boundary {boundary_failpoint} did not converge",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-pre-removal-content-changed")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove-intent"
        )
        bind_replacement_client(arguments, replacement_client_release)
        dropin = Path(arguments["dropin"])
        dropin.write_bytes(b"[Service]\nEnvironment=CHANGED=1\n")
        dropin.chmod(0o644)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "content changed",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-pre-removal-symlink")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove-intent"
        )
        bind_replacement_client(arguments, replacement_client_release)
        dropin = Path(arguments["dropin"])
        target = dropin.with_name("unbound-target.conf")
        target.write_bytes(dropin.read_bytes())
        target.chmod(0o644)
        dropin.unlink()
        dropin.symlink_to(target)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "identity is unsafe",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-pre-removal-unbound")
    with patches:
        leave_successor_at(
            arguments, "after-predecessor-dropin-remove-intent"
        )
        bind_replacement_client(arguments, replacement_client_release)
        dropin = Path(arguments["dropin"])
        replacement = dropin.with_name("replacement.conf")
        replacement.write_bytes(dropin.read_bytes())
        replacement.chmod(0o644)
        os.replace(replacement, dropin)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "replaced after publication",
        )

    for migration_failpoint in (
        "after-successor-client-release-handoff-intent",
        "after-successor-client-release-handoff-backup",
        "after-successor-client-release-handoff",
    ):
        (
            patches,
            arguments,
            _original,
            _profile,
            maintenance,
            canary_modes,
            replacement_client_release,
        ) = fixture(f"client-release-{migration_failpoint}")
        with patches:
            leave_successor_at(
                arguments, "after-predecessor-dropin-remove"
            )
            inherited_journal = bind_replacement_client(
                arguments, replacement_client_release
            )
            inherited_raw_sha256 = arguments[
                "inherited_successor_journal_sha256"
            ]
            leave_successor_at(arguments, migration_failpoint)
            if migration_failpoint in {
                "after-successor-client-release-handoff-intent",
                "after-successor-client-release-handoff-backup",
            }:
                _expect(
                    hashlib.sha256(inherited_journal.read_bytes()).hexdigest()
                    == inherited_raw_sha256,
                    "client handoff intent crash advanced the inherited journal",
                )
                intent = (
                    Path(arguments["transaction"])
                    / bridge.SUCCESSOR_CLIENT_HANDOFF_INTENT_NAME
                )
                _expect(
                    intent.is_file(),
                    "client handoff crash lost its durable intent",
                )
            else:
                retained = json.loads(
                    inherited_journal.read_text(encoding="utf-8")
                )
                _expect(
                    len(
                        retained["binding"].get(
                            "client_release_handoffs", []
                        )
                    )
                    == 1,
                    "client handoff journal crash lost its durable lineage",
                )
            replayed = bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            )
            _expect(
                replayed["ok"] is True
                and replayed["terminal"]["status"] == "committed"
                and maintenance["active"] is False
                and True in canary_modes
                and False in canary_modes,
                f"client handoff did not converge after {migration_failpoint}",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-retained-without-digests")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        arguments.pop("inherited_successor_journal_sha256")
        arguments.pop("inherited_successor_document_sha256")
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "must retain its journal-bound client release",
        )
        _expect(
            maintenance["active"] is True,
            "digest-free retained handoff replay changed maintenance",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-second-handoff")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        inherited_journal = bind_replacement_client(
            arguments, replacement_client_release
        )
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        second_client_release = (
            Path(arguments["transaction"]).parent / ("f" * 64)
        )
        second_client_release.mkdir(mode=0o700)
        arguments["client_release"] = second_client_release
        arguments["inherited_successor_journal_sha256"] = hashlib.sha256(
            inherited_journal.read_bytes()
        ).hexdigest()
        arguments["inherited_successor_document_sha256"] = json.loads(
            inherited_journal.read_text(encoding="utf-8")
        )["document_sha256"]
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-malformed-lineage")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        inherited_journal = bind_replacement_client(
            arguments, replacement_client_release
        )
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        retained = json.loads(inherited_journal.read_text(encoding="utf-8"))
        payload = {
            key: value
            for key, value in retained.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        handoffs = payload["binding"]["client_release_handoffs"]
        handoffs.append(copy.deepcopy(handoffs[0]))
        bridge._successor_journal(
            inherited_journal,
            payload,
            uid=os.geteuid(),
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-intent-database-drift")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments,
            "after-successor-client-release-handoff-intent",
        )
        with mock.patch.object(
            bridge,
            "_sqlite_bundle_evidence",
            return_value={
                "main": {
                    "path": str(arguments["database"]),
                    "sha256": "5" * 64,
                },
                "sidecars": {"-wal": None, "-shm": None},
            },
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "intent changed",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-intent-tamper")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments,
            "after-successor-client-release-handoff-intent",
        )
        intent_path = (
            Path(arguments["transaction"])
            / bridge.SUCCESSOR_CLIENT_HANDOFF_INTENT_NAME
        )
        intent_path.write_text("{}\n", encoding="utf-8")
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "client-handoff-intent evidence is invalid",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-missing-evidence")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        arguments["client_release"] = replacement_client_release
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-one-evidence")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        arguments.pop("inherited_successor_document_sha256")
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-wrong-evidence")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        arguments["inherited_successor_journal_sha256"] = "f" * 64
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "inherited journal changed",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-unsafe-phase")
    with patches:
        leave_successor_at(arguments, "after-profile-repair")
        bind_replacement_client(arguments, replacement_client_release)
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-nonclient-change")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        arguments["wait_seconds"] = 6
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-profile-drift")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        profile.write_bytes(b'{"changed":true}\n')
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "profile changed",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-active-predecessor")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        with mock.patch.object(
            bridge,
            "_systemd_state",
            return_value={
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": 4242,
            },
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "predecessor is not retired",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-database-drift")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        database_bundle = {
            "main": {
                "path": str(arguments["database"]),
                "sha256": "4" * 64,
            },
            "sidecars": {"-wal": None, "-shm": None},
        }
        changed_database_bundle = {
            "main": {
                "path": str(arguments["database"]),
                "sha256": "5" * 64,
            },
            "sidecars": {"-wal": None, "-shm": None},
        }
        with mock.patch.object(
            bridge,
            "_sqlite_bundle_evidence",
            side_effect=[database_bundle, changed_database_bundle],
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "state changed before publication",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-backup-tamper")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments,
            "after-successor-client-release-handoff-backup",
        )
        handoff_backup = (
            Path(arguments["transaction"])
            / bridge.SUCCESSOR_CLIENT_HANDOFF_BACKUP_NAME
        )
        handoff_backup.write_text("{}\n", encoding="utf-8")
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "retained bytes changed",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-lineage-tamper")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        inherited_journal = bind_replacement_client(
            arguments, replacement_client_release
        )
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        retained = json.loads(inherited_journal.read_text(encoding="utf-8"))
        payload = {
            key: value
            for key, value in retained.items()
            if key not in {"schema_version", "kind", "document_sha256"}
        }
        payload["binding"]["client_release_handoffs"][0][
            "successor_client_release_digest"
        ] = "f" * 64
        bridge._successor_journal(
            inherited_journal,
            payload,
            uid=os.geteuid(),
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge.replace_ready_bridge_with_clean_successor(
                **arguments
            ),
            "journal-bound client release",
        )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-replay-database-drift")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        with mock.patch.object(
            bridge,
            "_sqlite_bundle_evidence",
            return_value={
                "main": {
                    "path": str(arguments["database"]),
                    "sha256": "5" * 64,
                },
                "sidecars": {"-wal": None, "-shm": None},
            },
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "live state changed",
            )

    (
        patches,
        arguments,
        _original,
        _profile,
        _maintenance,
        _canary_modes,
        replacement_client_release,
    ) = fixture("client-release-replay-systemd-drift")
    with patches:
        leave_successor_at(arguments, "after-predecessor-dropin-remove")
        bind_replacement_client(arguments, replacement_client_release)
        leave_successor_at(
            arguments, "after-successor-client-release-handoff"
        )
        with mock.patch.object(
            bridge,
            "_systemd_state",
            return_value={
                "ActiveState": "active",
                "SubState": "running",
                "MainPID": 4242,
            },
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.replace_ready_bridge_with_clean_successor(
                    **arguments
                ),
                "live state changed",
            )


def _exercise_successor_handoff_and_dual_canary_contract(
    bridge: ModuleType, root: Path
) -> None:
    users = {
        "holyglory": SimpleNamespace(pw_name="holyglory", pw_uid=1000),
        "holygloryTT": SimpleNamespace(pw_name="holygloryTT", pw_uid=1001),
    }
    with mock.patch.object(
        bridge.pwd,
        "getpwnam",
        side_effect=lambda name: users[name],
    ):
        accounts = bridge._successor_canary_accounts(
            owner_user="holyglory",
            owner_uid=1000,
            additional_canaries=("holygloryTT=1001",),
        )
        _expect(
            accounts
            == [
                {"user": "holyglory", "uid": 1000},
                {"user": "holygloryTT", "uid": 1001},
            ],
            "successor did not retain both canonical canary accounts",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._successor_canary_accounts(
                owner_user="holyglory",
                owner_uid=1000,
                additional_canaries=(),
            ),
            "invalid",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._successor_canary_accounts(
                owner_user="holyglory",
                owner_uid=1000,
                additional_canaries=("holygloryTT=1000",),
            ),
            "repeat an identity",
        )

    profile = root / "dual-canary-profile.json"
    project = root / "GlobalFinance-dual-canary"
    project.mkdir(mode=0o700)
    socket_path = root / "dual-canary.sock"
    profile.write_text(
        json.dumps(
            {
                "version": 1,
                "service": {
                    "socket": str(socket_path),
                    "uid": 0,
                    "database_generation": "generation-12",
                },
                "clients": {
                    "1000": {
                        "repositories": [
                            {
                                "repo_id": "repo-global-finance",
                                "canonical_root": str(project),
                                "generation": 4,
                                "owner_uid": 1000,
                            }
                        ]
                    },
                    "1001": {
                        "repositories": [
                            {
                                "repo_id": "repo-global-finance",
                                "canonical_root": str(project),
                                "generation": 4,
                                "owner_uid": 1000,
                            }
                        ]
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    identity = {"sha256": hashlib.sha256(profile.read_bytes()).hexdigest()}
    with mock.patch.object(bridge, "_profile_identity", return_value=identity):
        collaborator = bridge._profile_repository_binding(
            profile,
            client_uid=1001,
            owner_uid=1000,
            repository_id="repo-global-finance",
            repository_generation=4,
            canonical_root=project,
            database_generation="generation-12",
            broker_socket=socket_path,
        )
    _expect(
        collaborator["client_uid"] == 1001
        and collaborator["owner_uid"] == 1000,
        "collaborator canary was incorrectly required to own GlobalFinance",
    )

    case = root / "lifecycle-handoff-binding"
    case.mkdir(mode=0o700)
    journal = case / "service-intent.json"
    result_path = case / "service-result.json"
    plan_path = case / "plan.json"
    recovery_path = case / "repository-recovery-result.json"
    for path in (journal, result_path, plan_path, recovery_path):
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
    database = case / "authority.sqlite3"
    protected_profile = case / "client-profiles.json"
    broker_socket = case / "broker.sock"
    dropin = case / "bridge.conf"
    predecessor_transaction = case / "predecessor"
    current_release = case / "current-release"
    historical_release = case / "historical-release"
    current_release.mkdir(mode=0o700)
    historical_release.mkdir(mode=0o700)
    lifecycle_operation_id = str(uuid.uuid4())
    predecessor_operation_id = str(uuid.uuid4())
    transaction_document_sha256 = "1" * 64
    result_document_sha256 = "2" * 64
    predecessor_journal_sha256 = "3" * 64
    predecessor_document_sha256 = "4" * 64
    recovery_document_sha256 = "6" * 64
    release_digest = "7" * 64
    canary_release_digest = "8" * 64
    plan_id = str(uuid.uuid4())
    source_plan_sha256 = "c" * 64
    source_result_sha256 = "d" * 64
    database_identity = {"device": 1, "inode": 2, "size": 4096}
    protected_rows = {"document_sha256": "e" * 64}
    owner_authority = {"mode": "schema12_absent"}
    mutation_updated_at = "2026-07-29T00:00:01Z"
    recovery_reason = "recover exact shared-root lifecycle"
    predecessor = {
        "transaction": str(predecessor_transaction),
        "operation_id": predecessor_operation_id,
        "journal_sha256": predecessor_journal_sha256,
        "journal_document_sha256": predecessor_document_sha256,
        "profile": str(protected_profile),
        "dropin": str(dropin),
    }
    proof = {
        "operation_id": predecessor_operation_id,
        "bridge_journal_sha256": predecessor_journal_sha256,
        "bridge_document_sha256": predecessor_document_sha256,
        "historical_client_release": str(historical_release),
        "historical_client_release_digest": canary_release_digest,
        "broker_release_digest": canary_release_digest,
        "database": str(database),
        "database_generation": "generation-12",
        "profile": str(protected_profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "socket_identity": {
            "device": 9,
            "inode": 10,
            "uid": 0,
            "gid": 986,
            "mode": 0o660,
        },
        "socket_peer": {"pid": 1234, "uid": 0, "gid": 0},
    }
    preclear_readiness = {
        "phase": "preclear",
        "broker_socket": str(broker_socket),
        "socket_identity": proof["socket_identity"],
        "socket_peer": proof["socket_peer"],
        "authority_generation": "generation-12",
        "canary": None,
        "invariants": {
            "contract": "schema12-pre-owner-authority-complete-v1",
            "schema_version": 12,
            "database_generation": "generation-12",
            "state_revision": 42,
            "quick_check": "ok",
            "semantic_violation_count": 0,
            "database_identity": database_identity,
        },
        "verified_at": "2026-07-29T00:00:02Z",
    }
    maintenance = {
        "root": str(case / "maintenance"),
        "gid": 100,
        "deployment_id": lifecycle_operation_id,
        "message": (
            "Coordinator control-plane maintenance is in progress; live controls "
            "will reconnect automatically."
        ),
        "retry_after_seconds": 5,
        "started_at": "2026-07-29T00:00:00Z",
    }
    transaction_document = {
        "document_sha256": transaction_document_sha256,
        "operation_id": lifecycle_operation_id,
        "release": str(current_release),
        "release_digest": release_digest,
        "canary_release": str(historical_release),
        "canary_release_digest": canary_release_digest,
        "plan": str(plan_path),
        "plan_document_sha256": "5" * 64,
        "database": str(database),
        "predecessor": predecessor,
        "readiness": {"broker_socket": str(broker_socket)},
        "maintenance": maintenance,
        "recovery_attestation": str(recovery_path),
    }
    plan_document = {
        "document_sha256": "5" * 64,
        "plan_id": plan_id,
        "operation_id": lifecycle_operation_id,
        "source_repair_plan_sha256": source_plan_sha256,
        "source_repair_result_sha256": source_result_sha256,
        "authority_uid": 0,
        "authority_generation": "generation-12",
        "authority_schema_version": 12,
        "authority_migration_state": "ready",
        "authority_state_revision": 41,
        "database_identity": database_identity,
        "repository": {
            "repository_id": "tmp-repository",
            "generation": 8,
            "installation_generation": 5,
            "enrollment_count": 0,
        },
        "protected_rows": protected_rows,
        "owner_authority": owner_authority,
        "target": {
            "repository_generation": 9,
            "installation_generation": 6,
            "state_revision": 42,
        },
        "mutation_updated_at": mutation_updated_at,
        "reason": recovery_reason,
    }
    recovery_document = {
        "document_sha256": recovery_document_sha256,
        "plan_id": plan_id,
        "operation_id": lifecycle_operation_id,
        "plan_document_sha256": "5" * 64,
        "source_repair_plan_sha256": source_plan_sha256,
        "source_repair_result_sha256": source_result_sha256,
        "authority_database": str(database),
        "authority_uid": 0,
        "authority_generation": "generation-12",
        "authority_schema_version": 12,
        "authority_migration_state": "ready",
        "maintenance_deployment_id": lifecycle_operation_id,
        "database_identity_before": database_identity,
        "repository_id": "tmp-repository",
        "repository_generation_before": 8,
        "repository_generation_after": 9,
        "installation_generation_before": 5,
        "installation_generation_after": 6,
        "state_revision_before": 41,
        "state_revision_after": 42,
        "protected_rows": protected_rows,
        "owner_authority_before": owner_authority,
        "owner_authority_after": owner_authority,
        "repository_state": "active",
        "installation_status": "installed",
        "startup_fenced": False,
        "enrollment_count": 0,
        "reason": recovery_reason,
        "actor": "authority-repository-lifecycle-recovery",
        "applied_at": mutation_updated_at,
    }
    result_document = {
        "document_sha256": result_document_sha256,
        "operation_id": lifecycle_operation_id,
        "transaction_journal_sha256": transaction_document_sha256,
        "recovery_result_sha256": recovery_document_sha256,
        "release_digest": release_digest,
        "canary_release_digest": canary_release_digest,
        "database": str(database),
        "maintenance": maintenance,
        "predecessor_proof": proof,
        "preclear_readiness": preclear_readiness,
        "service_restored": True,
        "maintenance_cleared": False,
        "successor_handoff_required": True,
    }
    contract = SimpleNamespace(
        AUTHORITY_REPOSITORY_REPAIR_ACTOR=(
            "authority-repository-lifecycle-recovery"
        ),
        _authority_repository_lifecycle_recovery_transaction=(
            lambda _value: transaction_document
        ),
        _validate_authority_repository_lifecycle_recovery_plan=(
            lambda _value: plan_document
        ),
        _validate_authority_repository_lifecycle_recovery_result=(
            lambda _value: recovery_document
        ),
        _authority_repository_owner_is_recovered=(
            lambda *, before, current, plan: (
                before == plan["owner_authority"]
                and current == {"mode": "schema12_absent"}
            )
        ),
        _authority_repository_lifecycle_recovery_transaction_result=(
            lambda _value, **_kwargs: result_document
        ),
    )
    arguments = {
        "transaction_journal": journal,
        "transaction_journal_sha256": hashlib.sha256(journal.read_bytes()).hexdigest(),
        "transaction_document_sha256": transaction_document_sha256,
        "attestation": result_path,
        "attestation_sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "attestation_document_sha256": result_document_sha256,
        "expected_canary_release_digest": canary_release_digest,
        "predecessor_transaction": predecessor_transaction,
        "predecessor_operation_id": predecessor_operation_id,
        "predecessor_journal_sha256": predecessor_journal_sha256,
        "predecessor_document_sha256": predecessor_document_sha256,
        "database": database,
        "profile": protected_profile,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": "generation-12",
        "expected_uid": os.geteuid(),
    }
    with (
        mock.patch.object(
            bridge, "_load_lifecycle_recovery_contract", return_value=contract
        ),
        mock.patch.object(
            bridge, "_verify_successor_predecessor_proof", side_effect=lambda value: value
        ),
        mock.patch.object(
            bridge,
            "_verified_lifecycle_producer_release",
            return_value=(
                current_release,
                {"release_digest": release_digest},
            ),
        ),
    ):
        handoff = bridge._verify_lifecycle_successor_handoff(**arguments)
        _expect(
            handoff["operation_id"] == lifecycle_operation_id
            and handoff["maintenance"]["deployment_id"] == lifecycle_operation_id
            and handoff["predecessor_proof"] == proof
            and handoff["preclear_readiness"] == preclear_readiness,
            "successor did not bind the exact lifecycle recovery handoff",
        )
        result_document["maintenance_cleared"] = True
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
            "binding changed",
        )
        result_document["maintenance_cleared"] = False
        for field, changed in (
            ("recovery_result_sha256", "9" * 64),
            ("release_digest", "a" * 64),
            ("canary_release_digest", "b" * 64),
        ):
            original = result_document[field]
            result_document[field] = changed
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
                "binding changed",
            )
            result_document[field] = original
        original_maintenance = result_document["maintenance"]
        result_document["maintenance"] = dict(maintenance, retry_after_seconds=6)
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
            "binding changed",
        )
        result_document["maintenance"] = original_maintenance
        original_preclear = result_document["preclear_readiness"]
        result_document["preclear_readiness"] = dict(
            preclear_readiness,
            authority_generation="another-generation",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
            "binding changed",
        )
        result_document["preclear_readiness"] = original_preclear
        recovery_mismatches = (
            ("source_repair_plan_sha256", "0" * 64),
            ("source_repair_result_sha256", "1" * 64),
            ("authority_uid", 1),
            ("authority_generation", "another-generation"),
            ("authority_schema_version", 13),
            ("authority_migration_state", "migrating"),
            ("database_identity_before", {"device": 2, "inode": 2, "size": 4096}),
            ("repository_id", "another-repository"),
            ("repository_generation_before", 7),
            ("repository_generation_after", 10),
            ("installation_generation_before", 4),
            ("installation_generation_after", 7),
            ("state_revision_before", 40),
            ("state_revision_after", 43),
            ("protected_rows", {"document_sha256": "f" * 64}),
            ("owner_authority_before", {"mode": "explicit"}),
            ("owner_authority_after", {"mode": "explicit"}),
            ("enrollment_count", 1),
            ("reason", "another reason"),
            ("actor", "another actor"),
            ("applied_at", "2026-07-29T00:00:02Z"),
        )
        for field, changed in recovery_mismatches:
            original = recovery_document[field]
            recovery_document[field] = changed
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
                "binding changed",
            )
            recovery_document[field] = original
        for field, changed in (
            ("release", str(case / "another-current-release")),
            ("canary_release", str(case / "another-historical-release")),
        ):
            original = transaction_document[field]
            transaction_document[field] = changed
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_lifecycle_successor_handoff(**arguments),
                "binding changed",
            )
            transaction_document[field] = original
        file_identity = bridge._private_file_identity
        transaction_reads = {"count": 0}

        def replaced_transaction_identity(path: Path, **kwargs):
            identity = file_identity(path, **kwargs)
            if Path(path) == journal:
                transaction_reads["count"] += 1
                if transaction_reads["count"] == 2:
                    identity = dict(
                        identity,
                        ctime_ns=int(identity["ctime_ns"]) + 1,
                    )
            return identity

        with mock.patch.object(
            bridge,
            "_private_file_identity",
            side_effect=replaced_transaction_identity,
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_lifecycle_successor_handoff(
                    **arguments
                ),
                "changed while verified",
            )

def _exercise_successor_terminal_binding_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "successor-terminal-binding"
    case.mkdir(mode=0o700)
    journal = case / "successor-journal.json"
    journal.write_text("journal\n", encoding="utf-8")
    operation_id = str(uuid.uuid4())
    maintenance_id = str(uuid.uuid4())
    current = {
        "operation_id": operation_id,
        "document_sha256": "1" * 64,
        "predecessor": {"release_digest": "2" * 64},
        "binding": {
            "candidate_release_digest": "3" * 64,
            "maintenance": {"deployment_id": maintenance_id},
            "maintenance_handoff": {"attestation_document_sha256": "4" * 64},
        },
        "profile": {
            "backup_sha256": "5" * 64,
            "repaired_payload_sha256": "6" * 64,
            "owner_binding_sha256": "7" * 64,
        },
        "candidate": {"readiness": {"document_sha256": "8" * 64}},
        "restored_predecessor": None,
    }
    payload = bridge._successor_terminal_payload(
        current=current,
        journal_path=journal,
        status="committed",
    )
    terminal = bridge._verify_successor_terminal(
        bridge._seal(bridge.SUCCESSOR_TERMINAL_KIND, payload)
    )
    bridge._verify_committed_successor_terminal_binding(
        terminal,
        current=current,
        journal_path=journal,
    )
    mutations = {
        "operation_id": str(uuid.uuid4()),
        "status": "aborted",
        "transaction_journal": str(case / "another-journal.json"),
        "transaction_journal_sha256": "9" * 64,
        "transaction_document_sha256": "a" * 64,
        "predecessor_release_digest": "b" * 64,
        "candidate_release_digest": "c" * 64,
        "profile_before_sha256": "d" * 64,
        "profile_after_sha256": "e" * 64,
        "profile_owner_binding_sha256": "f" * 64,
        "candidate_readiness_sha256": "0" * 64,
        "restored_predecessor_sha256": "1" * 64,
        "maintenance_deployment_id": str(uuid.uuid4()),
        "maintenance_handoff_sha256": "2" * 64,
        "maintenance_clear_pending": False,
    }
    for field, changed in mutations.items():
        contradictory = dict(payload)
        contradictory[field] = changed
        contradictory = bridge._seal(
            bridge.SUCCESSOR_TERMINAL_KIND, contradictory
        )
        _expect_bridge_error(
            bridge,
            lambda contradictory=contradictory: (
                bridge._verify_committed_successor_terminal_binding(
                    contradictory,
                    current=current,
                    journal_path=journal,
                )
            ),
            "terminal",
        )


def _exercise_policy_recovery_evidence_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "policy-recovery-evidence"
    case.mkdir(mode=0o700)
    database = case / "authority.sqlite3"
    database.write_bytes(b"fixture")
    database.chmod(0o600)
    paths = {
        label: case / f"{label}.json"
        for label in (
            "source_plan",
            "source_result",
            "policy_plan",
            "policy_result",
        )
    }
    for label, path in paths.items():
        path.write_text(
            json.dumps({"label": label}) + "\n", encoding="utf-8"
        )
        path.chmod(0o600)
    source_plan_id = str(uuid.uuid4())
    policy_plan_id = str(uuid.uuid4())
    deployment_id = str(uuid.uuid4())
    documents = {
        "source_plan": {
            "plan_id": source_plan_id,
            "document_sha256": "1" * 64,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
        },
        "source_result": {
            "plan_id": source_plan_id,
            "plan_document_sha256": "1" * 64,
            "document_sha256": "2" * 64,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
            "repository_id": "tmp-repository",
        },
        "policy_plan": {
            "plan_id": policy_plan_id,
            "document_sha256": "3" * 64,
            "source_repair_plan_sha256": "1" * 64,
            "source_repair_result_sha256": "2" * 64,
            "source_repair_plan_id": source_plan_id,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
            "authority_state_revision": 41,
            "repository": {
                "repository_id": "tmp-repository",
                "generation": 5,
                "installation_generation": 7,
            },
        },
        "policy_result": {
            "plan_id": policy_plan_id,
            "plan_document_sha256": "3" * 64,
            "document_sha256": "4" * 64,
            "source_repair_plan_sha256": "1" * 64,
            "source_repair_result_sha256": "2" * 64,
            "source_repair_plan_id": source_plan_id,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
            "maintenance_deployment_id": deployment_id,
            "repository_id": "tmp-repository",
            "repository_generation": 5,
            "installation_generation": 7,
            "state_revision_before": 41,
            "state_revision_after": 42,
            "startup_policy_update_count": 1,
            "startup_policies": [{"policy_id": "logical-policy"}],
        },
    }

    def document(value):
        return copy.deepcopy(documents[value["label"]])

    contract = SimpleNamespace(
        _validate_authority_repository_disable_plan=(
            lambda value, allow_legacy: document(value)
        ),
        _validate_authority_repository_disable_result=(
            lambda value, allow_legacy: document(value)
        ),
        _validate_authority_repository_policy_reconciliation_plan=document,
        _validate_authority_repository_policy_reconciliation_result=document,
    )
    arguments = {
        "source_repair_plan": paths["source_plan"],
        "source_repair_plan_raw_sha256": hashlib.sha256(
            paths["source_plan"].read_bytes()
        ).hexdigest(),
        "source_repair_plan_document_sha256": "1" * 64,
        "source_repair_result": paths["source_result"],
        "source_repair_result_raw_sha256": hashlib.sha256(
            paths["source_result"].read_bytes()
        ).hexdigest(),
        "source_repair_result_document_sha256": "2" * 64,
        "policy_plan": paths["policy_plan"],
        "policy_plan_raw_sha256": hashlib.sha256(
            paths["policy_plan"].read_bytes()
        ).hexdigest(),
        "policy_plan_document_sha256": "3" * 64,
        "policy_result": paths["policy_result"],
        "policy_result_raw_sha256": hashlib.sha256(
            paths["policy_result"].read_bytes()
        ).hexdigest(),
        "policy_result_document_sha256": "4" * 64,
        "database": database,
        "maintenance_deployment_id": deployment_id,
        "expected_uid": os.geteuid(),
    }
    with mock.patch.object(
        bridge, "_load_cutover_module", return_value=contract
    ):
        plan, result, references = bridge._policy_reconciliation_lineage(
            **arguments
        )
        _expect(
            result["state_revision_after"] == 42
            and plan["authority_state_revision"] == 41
            and len(references) == 4,
            "policy recovery did not bind its exact four-artifact lineage",
        )
        documents["policy_result"]["state_revision_after"] = 43
        _expect_bridge_error(
            bridge,
            lambda: bridge._policy_reconciliation_lineage(**arguments),
            "lineage changed",
        )
        documents["policy_result"]["state_revision_after"] = 42
        documents["policy_result"]["source_repair_result_sha256"] = "9" * 64
        _expect_bridge_error(
            bridge,
            lambda: bridge._policy_reconciliation_lineage(**arguments),
            "lineage changed",
        )


def _exercise_restored_policy_predecessor_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "policy-restored-predecessor"
    case.mkdir(mode=0o700)
    transaction = case / "predecessor"
    transaction.mkdir(mode=0o700)
    readiness = case / "readiness.json"
    readiness.write_text("{}\n", encoding="utf-8")
    readiness.chmod(0o600)
    release = case / "legacy-release"
    release.mkdir(mode=0o700)
    database = case / "authority.sqlite3"
    database.write_bytes(b"fixture")
    database.chmod(0o600)
    broker_socket = case / "broker.sock"
    dropin = case / "bridge.conf"
    operation_id = str(uuid.uuid4())
    origin = {
        "path": str(readiness),
        "document_sha256": "d" * 64,
        "database_identity": {"device": 1, "inode": 2, "size": 3},
        "database_generation": "generation-12",
        "state_revision": 41,
        "snapshot": _authority_snapshot(state_revision=41),
    }
    inactive = {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "last-invocation",
        "NRestarts": 506,
    }
    payload = {
        "operation_id": operation_id,
        "release": str(release),
        "release_digest": "a" * 64,
        "dropin": str(dropin),
        "dropin_sha256": "b" * 64,
        "dropin_identity": {"sha256": "b" * 64},
        "broker_socket": str(broker_socket),
        "failed_activation": {},
        "readiness": {**origin, "state_revision": 42},
        "canaries": [{"user": "fixture"}],
        "baseline": inactive,
        "phase": "restored",
        "attempts": 1,
        "activation": {
            "systemd": {"InvocationID": "activation-invocation"},
            "execution": {},
            "canaries": [],
            "restore_descendant": {
                "kind": "verified-supervised-crash-loop-descendant",
                "activation_invocation_id": "activation-invocation",
                "activation_restart_count": 1,
                "observed_invocation_id": "observed-invocation",
                "observed_restart_count": 505,
                "last_invocation_id": "last-invocation",
                "last_restart_count": 506,
                "release_digest": "a" * 64,
                "verified_unsealed_bytecode_cache_sha256": "c" * 64,
                "execution_sha256": "e" * 64,
                "inactive_state": inactive,
            },
        },
        "error": None,
        "created_at_epoch": 1,
        "updated_at_epoch": 2,
        "readiness_origin": origin,
        "attempt_evidence": {},
        "predecessor_readiness": {},
    }
    journal = bridge._journal(
        transaction / bridge.JOURNAL_NAME,
        payload,
        uid=os.geteuid(),
    )
    journal_bytes = (transaction / bridge.JOURNAL_NAME).read_bytes()
    descendant = {
        **origin,
        "database_generation": "generation-12",
        "state_revision": 42,
    }
    arguments = {
        "transaction": transaction,
        "operation_id": operation_id,
        "journal_raw_sha256": hashlib.sha256(
            (transaction / bridge.JOURNAL_NAME).read_bytes()
        ).hexdigest(),
        "journal_document_sha256": journal["document_sha256"],
        "readiness_attestation": readiness,
        "readiness_raw_sha256": hashlib.sha256(
            readiness.read_bytes()
        ).hexdigest(),
        "readiness_document_sha256": "d" * 64,
        "database": database,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": "generation-12",
        "expected_state_revision": 42,
        "expected_uid": os.geteuid(),
    }
    with (
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={"release_digest": "a" * 64},
        ),
        mock.patch.object(
            bridge,
            "_readiness_origin_from_attestation",
            return_value=origin,
        ),
        mock.patch.object(
            bridge, "_readiness_proof", return_value=descendant
        ),
        mock.patch.object(
            bridge, "_stable_inactive", return_value=inactive
        ),
    ):
        verified = bridge.verify_policy_reconciled_restored_predecessor(
            **arguments
        )
        _expect(
            verified["journal_document_sha256"]
            == journal["document_sha256"]
            and verified["descendant_readiness"]["state_revision"] == 42,
            "restored predecessor lost exact journal/revision evidence",
        )
        invalid = dict(journal)
        invalid["phase"] = "ready"
        with mock.patch.object(
            bridge, "_load_bridge_journal", return_value=invalid
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.verify_policy_reconciled_restored_predecessor(
                    **arguments
                ),
                "exact restored",
            )
        with mock.patch.object(
            bridge,
            "_readiness_proof",
            return_value={**descendant, "state_revision": 43},
        ):
            _expect_bridge_error(
                bridge,
                lambda: bridge.verify_policy_reconciled_restored_predecessor(
                    **arguments
                ),
                "revision changed",
            )
    _expect(
        (transaction / bridge.JOURNAL_NAME).read_bytes() == journal_bytes,
        "restored predecessor verification changed historical journal bytes",
    )


def _exercise_policy_recovery_cli_contract(bridge: ModuleType) -> None:
    sha = "a" * 64
    identities = [str(uuid.uuid4()) for _ in range(4)]
    argv = [
        "--json",
        "recover-policy-reconciled-restored",
        "--candidate-release",
        "/clean/release",
        "--release-root",
        "/clean",
        "--client-release",
        "/client/release",
        "--transaction-dir",
        "/transaction",
        "--operation-id",
        identities[0],
        "--predecessor-transaction",
        "/predecessor",
        "--predecessor-operation-id",
        identities[1],
        "--predecessor-journal-raw-sha256",
        sha,
        "--predecessor-journal-document-sha256",
        sha,
        "--failed-installer-transaction",
        "/failed",
        "--failed-installer-operation-id",
        identities[2],
        "--readiness-attestation",
        "/readiness.json",
        "--readiness-raw-sha256",
        sha,
        "--readiness-document-sha256",
        sha,
    ]
    for prefix in (
        "source-repair-plan",
        "source-repair-result",
        "policy-plan",
        "policy-result",
    ):
        argv.extend(
            [
                f"--{prefix}",
                f"/{prefix}.json",
                f"--{prefix}-raw-sha256",
                sha,
                f"--{prefix}-document-sha256",
                sha,
            ]
        )
    argv.extend(
        [
            "--owner-map",
            "/owner-map.json",
            "--owner-map-sha256",
            sha,
            "--maintenance-root",
            "/maintenance",
            "--maintenance-gid",
            "986",
            "--maintenance-deployment-id",
            identities[3],
            "--canary-user",
            "holyglory",
            "--expected-canary-uid",
            "1000",
            "--canary-project",
            "/home/holyglory/GlobalFinance",
            "--canary-repository-id",
            "global-finance",
            "--canary-repository-generation",
            "4",
            "--additional-canary",
            "holygloryTT=1001",
        ]
    )
    parsed = bridge._parser().parse_args(argv)
    _expect(
        parsed.action == "recover-policy-reconciled-restored"
        and parsed.policy_result_document_sha256 == sha
        and parsed.predecessor_journal_raw_sha256 == sha,
        "policy recovery CLI lost an exact evidence binding",
    )
    captured: dict[str, object] = {}

    def recover(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    with (
        mock.patch.object(
            bridge,
            "recover_policy_reconciled_restored_bridge",
            side_effect=recover,
        ),
        redirect_stdout(io.StringIO()),
    ):
        status = bridge.main(argv)
    _expect(
        status == 0
        and captured["policy_result_document_sha256"] == sha
        and captured["predecessor_journal_raw_sha256"] == sha,
        "policy recovery CLI did not execute its dispatch contract",
    )
    with (
        mock.patch.object(
            bridge,
            "recover_policy_reconciled_restored_bridge",
            return_value={"ok": False, "terminal": {"status": "aborted"}},
        ),
        redirect_stdout(io.StringIO()),
    ):
        aborted_status = bridge.main(argv)
    _expect(
        aborted_status == 1,
        "policy recovery CLI reported an aborted terminal as success",
    )


def _exercise_lifecycle_quiesce_cli_contract(bridge: ModuleType) -> None:
    sha = "b" * 64
    operation_id = str(uuid.uuid4())
    deployment_id = str(uuid.uuid4())
    argv = [
        "--json",
        "quiesce-lifecycle-recovery-crash-loop",
        "--transaction-dir",
        "/transaction",
        "--operation-id",
        operation_id,
    ]
    for prefix in (
        "lifecycle-plan",
        "lifecycle-result",
        "lifecycle-service-intent",
    ):
        argv.extend(
            [
                f"--{prefix}",
                f"/{prefix}.json",
                f"--{prefix}-raw-sha256",
                sha,
                f"--{prefix}-document-sha256",
                sha,
            ]
        )
    argv.extend(
        [
            "--lifecycle-service-result",
            "/lifecycle-service-result.json",
            "--maintenance-root",
            "/maintenance",
            "--maintenance-gid",
            "986",
            "--maintenance-deployment-id",
            deployment_id,
        ]
    )
    parsed = bridge._parser().parse_args(argv)
    _expect(
        parsed.action == "quiesce-lifecycle-recovery-crash-loop"
        and parsed.lifecycle_result_raw_sha256 == sha
        and parsed.lifecycle_service_intent_document_sha256 == sha,
        "lifecycle quiesce CLI lost an exact evidence binding",
    )
    captured: dict[str, object] = {}

    def quiesce(**kwargs):
        captured.update(kwargs)
        return {"ok": True}

    with (
        mock.patch.object(
            bridge,
            "quiesce_lifecycle_recovery_crash_loop",
            side_effect=quiesce,
        ),
        redirect_stdout(io.StringIO()),
    ):
        status = bridge.main(argv)
    _expect(
        status == 0
        and captured["lifecycle_result_raw_sha256"] == sha
        and captured["lifecycle_service_intent_document_sha256"] == sha,
        "lifecycle quiesce CLI did not execute its dispatch contract",
    )


def _exercise_lifecycle_historical_executor_split(
    bridge: ModuleType, root: Path
) -> None:
    historical = root / "historical-releases" / ("a" * 64)
    executor = bridge.ROOT.resolve(strict=True)
    database = root / "executor-split.sqlite3"
    broker_socket = root / "executor-split.sock"
    dropin = root / "executor-split.conf"
    expected_argv = [
        "/usr/bin/python3",
        "-I",
        "/home/DevCoordinator/skills/codex-dev-coordinator/scripts/"
        "dev_coordinator.py",
        "broker",
        "serve",
        "--database",
        str(database),
        "--socket",
        str(broker_socket),
        "--access-group",
        bridge.ACCESS_GROUP,
        "--test-plane-socket",
        "/run/devcoordinator-testd/testd.sock",
        "--test-plane-user",
        "devcoordinator-testd",
        "--internal-testd-user",
        "devcoordinator-testd",
    ]
    identity = {
        "FragmentPath": str(bridge.BROKER_FRAGMENT),
        "DropInPaths": "",
        "ExecStart": (
            "{ path=/usr/bin/python3 ; argv[]="
            + shlex.join(expected_argv)
            + " ; }"
        ),
    }
    calls: list[tuple[str, Path]] = []
    fragment_calls: list[Path] = []

    def verify_executor(release: Path, *, owner_uid: int):
        _expect(
            release == executor and owner_uid == os.geteuid(),
            "lifecycle quiesce treated the historical producer as its executor",
        )
        calls.append(("executor", release))
        return {
            "release_digest": "b" * 64,
            "capabilities": {
                "schema12_lifecycle_crash_loop_quiescence": True
            },
        }

    def verify_historical(release: Path, *, owner_uid: int):
        _expect(
            release == historical
            and release != executor
            and owner_uid == os.geteuid(),
            "lifecycle quiesce did not retain a distinct historical producer",
        )
        calls.append(("historical", release))
        return {"release_digest": historical.name}

    def fragment_identity(path: Path, **_kwargs):
        _expect(
            path != historical / "deploy/devcoordinator-broker.service",
            "lifecycle quiesce required a unit absent from the historical release",
        )
        fragment_calls.append(path)
        return {
            "path": str(path),
            "sha256": "c" * 64,
        }

    with (
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            side_effect=verify_executor,
        ),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=verify_historical,
        ),
        mock.patch.object(
            bridge,
            "_root_regular_identity",
            side_effect=fragment_identity,
        ),
        mock.patch.object(
            bridge, "_systemd_execution_identity", return_value=identity
        ),
    ):
        proof = bridge._lifecycle_crash_loop_execution(
            service_intent={
                "release": str(historical),
                "release_digest": historical.name,
            },
            database=database,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=os.geteuid(),
        )
    _expect(
        calls == [("executor", executor), ("historical", historical)]
        and fragment_calls
        == [
            executor / "deploy/devcoordinator-broker.service",
            bridge.BROKER_FRAGMENT,
        ]
        and proof["historical_release"] == str(historical)
        and proof["executor_release"] == str(executor)
        and proof["historical_release_digest"] != proof[
            "executor_release_digest"
        ],
        "lifecycle quiesce collapsed historical and executor release identity",
    )


def _exercise_lifecycle_quiesce_transaction_contract(
    bridge: ModuleType, root: Path
) -> None:
    class InjectedCrash(BaseException):
        pass

    class FakeFence:
        depth = 1

        def mark_complete(self) -> None:
            return None

    @contextmanager
    def fence(**_kwargs):
        yield FakeFence()

    @contextmanager
    def lock(*_args, **_kwargs):
        yield {"acquired": True}

    deployment_id = str(uuid.uuid4())
    lifecycle_operation_id = str(uuid.uuid4())
    operation_id = str(uuid.uuid4())
    maintenance_root = root / "maintenance"
    maintenance_root.mkdir(mode=0o700)
    profile = root / "client-profiles.json"
    profile.write_text("{}\n", encoding="utf-8")
    profile.chmod(0o600)
    database = root / "lifecycle-quiesce-authority.sqlite3"
    database.write_bytes(b"exact-lifecycle-authority")
    database.chmod(0o600)
    service_result = root / "lifecycle-service-result.json"
    transaction = root / "quiesce"
    plan_path = root / "lifecycle-plan.json"
    result_path = root / "lifecycle-result.json"
    intent_path = root / "lifecycle-service-intent.json"
    for path in (plan_path, result_path, intent_path):
        path.write_text("{}\n", encoding="utf-8")
        path.chmod(0o600)
    maintenance = {
        "root": str(maintenance_root),
        "gid": 986,
        "deployment_id": deployment_id,
        "message": (
            "Coordinator control-plane maintenance is in progress; "
            "live controls will reconnect automatically."
        ),
        "retry_after_seconds": 5,
        "started_at": "2026-07-29T13:57:57.759Z",
    }
    plan = {
        "document_sha256": "1" * 64,
        "operation_id": lifecycle_operation_id,
        "authority_generation": "authority-generation",
        "authority_state_revision": 93405,
        "target": {"state_revision": 93406},
    }
    result = {
        "document_sha256": "2" * 64,
        "operation_id": lifecycle_operation_id,
        "authority_generation": "authority-generation",
        "state_revision_after": 93406,
        "database_identity_after": {
            "device": 11,
            "inode": 12,
            "size": 13,
        },
    }
    service_intent = {
        "document_sha256": "3" * 64,
        "operation_id": lifecycle_operation_id,
        "maintenance": maintenance,
    }
    references = {
        "plan": {"path": str(plan_path), "raw_sha256": "4" * 64},
        "result": {"path": str(result_path), "raw_sha256": "5" * 64},
        "service_intent": {
            "path": str(intent_path),
            "raw_sha256": "6" * 64,
        },
        "service_result": {
            "path": str(service_result),
            "expected_absent": True,
        },
    }
    predecessor = {
        "journal_sha256": "7" * 64,
        "journal_document_sha256": "8" * 64,
    }
    profile_identity = {
        "device": 21,
        "inode": 22,
        "size": 3,
        "mtime_ns": 23,
        "ctime_ns": 24,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "mode": 0o600,
        "nlink": 1,
        "sha256": "9" * 64,
    }
    execution = {
        "release_digest": "a" * 64,
        "argv": ["exact-schema13-entry"],
    }
    active = {
        "LoadState": "loaded",
        "ActiveState": "activating",
        "SubState": "auto-restart",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "failed-invocation",
        "NRestarts": 342,
    }
    inactive = {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "failed-invocation",
        "NRestarts": 343,
    }
    failed_after_stop = {
        "LoadState": "loaded",
        "ActiveState": "failed",
        "SubState": "failed",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "d" * 32,
        "NRestarts": 343,
    }
    failure = {
        "unit": bridge.BROKER_UNIT,
        "properties": {
            "Result": "success",
            "ExecMainCode": 0,
            "ExecMainStatus": 0,
        },
        "journal": {
            "tail": (
                f"{bridge.SCHEMA12_STARTUP_ERROR}\n"
                f"{bridge.SCHEMA12_STARTUP_ERROR}"
            )
        },
    }
    database_proof = {
        "database_sha256": "c" * 64,
        "state_revision": 93406,
    }
    state = {"service": active, "stop_count": 0, "reset_count": 0}

    fake_maintenance = SimpleNamespace(
        CONTROL_PLANE_MAINTENANCE_SCOPE="global-control-plane",
        PUBLIC_MAINTENANCE_MESSAGE=maintenance["message"],
        maintenance_writer_lock=lock,
    )

    def systemd_state():
        return copy.deepcopy(state["service"])

    def set_crash_loop_failure():
        failure["properties"] = {
            "Result": "success",
            "ExecMainCode": 0,
            "ExecMainStatus": 0,
        }
        failure["journal"]["tail"] = (
            f"{bridge.SCHEMA12_STARTUP_ERROR}\n"
            f"{bridge.SCHEMA12_STARTUP_ERROR}"
        )

    def set_stop_failure():
        failure["properties"] = {
            "Result": "signal",
            "ExecMainCode": 0,
            "ExecMainStatus": 0,
        }
        failure["journal"]["tail"] = (
            f"{bridge.SCHEMA12_STARTUP_ERROR}\n"
            "devcoordinator-broker.service: Control process exited, "
            "code=killed, status=15/TERM\n"
            "devcoordinator-broker.service: Failed with result 'signal'.\n"
            "Stopped devcoordinator-broker.service - DevCoordinator "
            "server-wide authority broker."
        )

    def run(command, **_kwargs):
        if command == ["/usr/bin/systemctl", "stop", bridge.BROKER_UNIT]:
            state["stop_count"] += 1
            state["service"] = failed_after_stop
            set_stop_failure()
        elif command == [
            "/usr/bin/systemctl",
            "reset-failed",
            bridge.BROKER_UNIT,
        ]:
            state["reset_count"] += 1
            state["service"] = inactive
        else:
            _fail("lifecycle quiesce executed an unexpected host mutation")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def wait_inactive(*_args, **_kwargs):
        _expect(
            state["service"] == inactive,
            "lifecycle quiesce accepted failed bookkeeping as inactive",
        )
        return copy.deepcopy(inactive)

    def lineage(**_kwargs):
        _expect(
            not service_result.exists(),
            "lifecycle quiesce accepted a generic service terminal",
        )
        return (
            copy.deepcopy(plan),
            copy.deepcopy(result),
            copy.deepcopy(service_intent),
            copy.deepcopy(references),
        )

    common = {
        "transaction": transaction,
        "operation_id": operation_id,
        "lifecycle_plan": plan_path,
        "lifecycle_plan_raw_sha256": "d" * 64,
        "lifecycle_plan_document_sha256": plan["document_sha256"],
        "lifecycle_result": result_path,
        "lifecycle_result_raw_sha256": "e" * 64,
        "lifecycle_result_document_sha256": result["document_sha256"],
        "lifecycle_service_intent": intent_path,
        "lifecycle_service_intent_raw_sha256": "f" * 64,
        "lifecycle_service_intent_document_sha256": service_intent[
            "document_sha256"
        ],
        "lifecycle_service_result": service_result,
        "database": database,
        "profile": profile,
        "broker_socket": root / "broker.sock",
        "dropin": root / "95-schema12.conf",
        "maintenance_root": maintenance_root,
        "maintenance_gid": 986,
        "maintenance_deployment_id": deployment_id,
        "expected_uid": os.geteuid(),
    }
    patches = ExitStack()
    patches.enter_context(
        mock.patch.object(
            bridge, "_load_maintenance_contract", return_value=fake_maintenance
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_successor_transaction_fence", side_effect=fence
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_lifecycle_quiesce_lineage", side_effect=lineage
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge,
            "_lifecycle_quiesce_predecessor",
            return_value=predecessor,
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_profile_identity", return_value=profile_identity
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge,
            "_sqlite_regular_identity",
            return_value={
                **result["database_identity_after"],
                "mtime_ns": 1,
                "ctime_ns": 1,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "mode": 0o600,
                "nlink": 1,
            },
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge,
            "_lifecycle_crash_loop_execution",
            return_value=execution,
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_systemd_state", side_effect=systemd_state
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_broker_failure_diagnostic", return_value=failure
        )
    )
    patches.enter_context(mock.patch.object(bridge, "_run", side_effect=run))
    patches.enter_context(
        mock.patch.object(
            bridge, "_wait_inactive", side_effect=wait_inactive
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_stable_inactive", return_value=inactive
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_broker_service_lock", side_effect=lock
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge,
            "_lifecycle_quiesce_database_proof",
            return_value=database_proof,
        )
    )
    patches.enter_context(
        mock.patch.object(
            bridge, "_ensure_successor_maintenance", return_value=None
        )
    )
    with patches:
        first = bridge.quiesce_lifecycle_recovery_crash_loop(**common)
        _expect(
            first["ok"] is True
            and first["replayed"] is False
            and state["stop_count"] == 1
            and state["reset_count"] == 1
            and state["service"] == inactive,
            "lifecycle quiesce did not normalize its exact stopped failure",
        )
        replay = bridge.quiesce_lifecycle_recovery_crash_loop(**common)
        _expect(
            replay["ok"] is True
            and replay["replayed"] is True
            and state["stop_count"] == 1,
            "lifecycle quiesce replay repeated the stop",
        )

    crash_root = root / "crash-replay"
    crash_root.mkdir(mode=0o700)
    crash_common = {
        **common,
        "transaction": crash_root / "transaction",
        "operation_id": str(uuid.uuid4()),
    }
    state["service"] = active
    state["stop_count"] = 0
    state["reset_count"] = 0
    set_crash_loop_failure()
    crash_execution_calls = {"count": 0}

    def crash_execution(**_kwargs):
        crash_execution_calls["count"] += 1
        _expect(
            crash_execution_calls["count"] <= 2,
            "failed-stop replay revalidated a no-longer-running invocation",
        )
        return copy.deepcopy(execution)

    with ExitStack() as crash_patches:
        for patcher in (
            mock.patch.object(
                bridge,
                "_load_maintenance_contract",
                return_value=fake_maintenance,
            ),
            mock.patch.object(
                bridge, "_successor_transaction_fence", side_effect=fence
            ),
            mock.patch.object(
                bridge, "_lifecycle_quiesce_lineage", side_effect=lineage
            ),
            mock.patch.object(
                bridge,
                "_lifecycle_quiesce_predecessor",
                return_value=predecessor,
            ),
            mock.patch.object(
                bridge, "_profile_identity", return_value=profile_identity
            ),
            mock.patch.object(
                bridge,
                "_sqlite_regular_identity",
                return_value={
                    **result["database_identity_after"],
                    "mtime_ns": 1,
                    "ctime_ns": 1,
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                    "mode": 0o600,
                    "nlink": 1,
                },
            ),
            mock.patch.object(
                bridge,
                "_lifecycle_crash_loop_execution",
                side_effect=crash_execution,
            ),
            mock.patch.object(
                bridge, "_systemd_state", side_effect=systemd_state
            ),
            mock.patch.object(
                bridge, "_broker_failure_diagnostic", return_value=failure
            ),
            mock.patch.object(bridge, "_run", side_effect=run),
            mock.patch.object(
                bridge, "_wait_inactive", side_effect=wait_inactive
            ),
            mock.patch.object(
                bridge, "_stable_inactive", return_value=inactive
            ),
            mock.patch.object(
                bridge, "_broker_service_lock", side_effect=lock
            ),
            mock.patch.object(
                bridge,
                "_lifecycle_quiesce_database_proof",
                return_value=database_proof,
            ),
            mock.patch.object(
                bridge, "_ensure_successor_maintenance", return_value=None
            ),
        ):
            crash_patches.enter_context(patcher)
        try:
            bridge.quiesce_lifecycle_recovery_crash_loop(
                **crash_common,
                failpoint=lambda stage: (
                    (_ for _ in ()).throw(InjectedCrash())
                    if stage == "after-stop-intent"
                    else None
                ),
            )
            _fail("lifecycle quiesce did not expose the injected crash")
        except InjectedCrash:
            pass
        _expect(
            state["stop_count"] == 0,
            "lifecycle quiesce mutated the service before sealed intent",
        )
        state["service"] = failed_after_stop
        state["stop_count"] = 1
        set_stop_failure()
        recovered = bridge.quiesce_lifecycle_recovery_crash_loop(
            **crash_common
        )
        _expect(
            recovered["ok"] is True
            and state["stop_count"] == 1
            and state["reset_count"] == 1
            and crash_execution_calls["count"] == 2
            and not service_result.exists(),
            "lifecycle quiesce did not recover its post-stop crash",
        )


def _exercise_policy_recovery_transaction_contract(
    bridge: ModuleType, root: Path
) -> None:
    class InjectedCrash(BaseException):
        pass

    class FakeFence:
        def __init__(self) -> None:
            self.completed = False

        def mark_complete(self) -> None:
            self.completed = True

    current_account = pwd.getpwuid(os.geteuid())
    collaborator_name = (
        "holyglory"
        if current_account.pw_name != "holyglory"
        else "holygloryTT"
    )
    collaborator = pwd.getpwnam(collaborator_name)

    def fixture(
        name: str,
        *,
        candidate_digest: str = "c" * 64,
        canary_failure: bool = False,
        cleanup_ambiguous: bool = False,
    ):
        case = root / f"policy-recovery-transaction-{name}"
        case.mkdir(mode=0o700)
        transaction = case / "transaction"
        predecessor_transaction = case / "predecessor"
        failed_transaction = case / "failed-installer"
        candidate_root = case / "clean-releases"
        predecessor_root = case / "legacy-releases"
        for directory in (
            transaction,
            predecessor_transaction,
            failed_transaction,
            candidate_root,
            predecessor_root,
        ):
            directory.mkdir(mode=0o700)
        candidate_release = candidate_root / ("c" * 64)
        predecessor_release = predecessor_root / ("c" * 64)
        client_release = case / ("d" * 64)
        for directory in (
            candidate_release,
            predecessor_release,
            client_release,
        ):
            directory.mkdir(mode=0o700)
        profile_root = case / "protected"
        profile_root.mkdir(mode=0o700)
        profile = profile_root / "client-profiles.json"
        original_profile = b'{"legacy":"exact"}\n'
        repaired_profile = b'{"owner_bound":true}\n'
        profile.write_bytes(original_profile)
        profile.chmod(0o600)
        database = case / "authority.sqlite3"
        database_bytes = b"sealed-policy-cas-database"
        database.write_bytes(database_bytes)
        database.chmod(0o600)
        readiness = case / "readiness.json"
        readiness.write_text("{}\n", encoding="utf-8")
        readiness.chmod(0o600)
        owner_map = case / "owner-map.json"
        owner_map.write_text("{}\n", encoding="utf-8")
        owner_map.chmod(0o600)
        project = case / "GlobalFinance"
        project.mkdir(mode=0o700)
        maintenance_root = case / "maintenance"
        maintenance_root.mkdir(mode=0o700)
        evidence_paths = {
            label: case / f"{label}.json"
            for label in (
                "source-plan",
                "source-result",
                "policy-plan",
                "policy-result",
            )
        }
        for path in evidence_paths.values():
            path.write_text("{}\n", encoding="utf-8")
            path.chmod(0o600)
        predecessor_journal = (
            predecessor_transaction / bridge.JOURNAL_NAME
        )
        predecessor_journal_bytes = b'{"sealed":"restored-predecessor"}\n'
        predecessor_journal.write_bytes(predecessor_journal_bytes)
        predecessor_journal.chmod(0o600)
        operation_id = str(uuid.uuid4())
        predecessor_operation_id = str(uuid.uuid4())
        failed_operation_id = str(uuid.uuid4())
        deployment_id = str(uuid.uuid4())
        state = {
            "maintenance_active": True,
            "writer_locked": False,
            "broker_active": False,
            "database_proofs": [],
        }
        maintenance_state = SimpleNamespace(
            deployment_id=deployment_id,
            message=(
                "Coordinator control-plane maintenance is in progress; live "
                "controls will reconnect automatically."
            ),
            retry_after_seconds=5,
            started_at="2026-07-29T00:00:00Z",
        )

        @contextmanager
        def maintenance_writer_lock(**_kwargs):
            _expect(
                not state["writer_locked"],
                "policy recovery nested its maintenance writer lock",
            )
            state["writer_locked"] = True
            lock = maintenance_root / "maintenance.lock"
            if not lock.exists():
                lock.write_bytes(b"")
                lock.chmod(0o640)
            try:
                yield
            finally:
                state["writer_locked"] = False

        def load_maintenance_state(**_kwargs):
            return maintenance_state if state["maintenance_active"] else None

        def clear_maintenance(**_kwargs):
            _expect(
                not state["writer_locked"],
                "policy recovery cleared maintenance while holding its lock",
            )
            state["maintenance_active"] = False

        def activate_maintenance(**_kwargs):
            _expect(
                not state["writer_locked"],
                "policy recovery reactivated maintenance while holding its lock",
            )
            state["maintenance_active"] = True
            return maintenance_state

        maintenance = SimpleNamespace(
            CONTROL_PLANE_MAINTENANCE_SCOPE=(
                "server-wide-authority-upgrade"
            ),
            PUBLIC_MAINTENANCE_MESSAGE=maintenance_state.message,
            MAINTENANCE_LOCK_FILENAME="maintenance.lock",
            maintenance_writer_lock=maintenance_writer_lock,
            load_maintenance_state=load_maintenance_state,
            clear_maintenance=clear_maintenance,
            activate_maintenance=activate_maintenance,
        )

        @contextmanager
        def fenced(**_kwargs):
            yield FakeFence()

        @contextmanager
        def broker_lock(_database, *, expected_uid):
            _expect(
                expected_uid == os.geteuid(),
                "policy recovery changed stopped-writer authority",
            )
            _expect(
                not state["broker_active"],
                "policy recovery acquired stopped-writer lock while active",
            )
            yield

        source_plan_id = str(uuid.uuid4())
        policy_plan_id = str(uuid.uuid4())
        reference_names = {
            "source-plan": "source_repair_plan",
            "source-result": "source_repair_result",
            "policy-plan": "policy_plan",
            "policy-result": "policy_result",
        }
        references = {
            reference_names[label]: {
                "path": str(path),
                "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "document_sha256": {
                    "source-plan": "1" * 64,
                    "source-result": "2" * 64,
                    "policy-plan": "3" * 64,
                    "policy-result": "4" * 64,
                }[label],
                "identity": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
            }
            for label, path in evidence_paths.items()
        }
        plan = {
            "plan_id": policy_plan_id,
            "document_sha256": "3" * 64,
            "source_repair_plan_sha256": "1" * 64,
            "source_repair_result_sha256": "2" * 64,
            "source_repair_plan_id": source_plan_id,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
            "authority_state_revision": 93369,
            "startup_policies": [{"policy_id": "logical-policy"}],
            "repository": {
                "repository_id": "tmp-repository",
                "generation": 9,
                "installation_generation": 6,
            },
        }
        result = {
            "plan_id": policy_plan_id,
            "plan_document_sha256": "3" * 64,
            "document_sha256": "4" * 64,
            "source_repair_plan_sha256": "1" * 64,
            "source_repair_result_sha256": "2" * 64,
            "source_repair_plan_id": source_plan_id,
            "authority_database": str(database),
            "authority_uid": os.geteuid(),
            "authority_generation": "generation-12",
            "maintenance_deployment_id": deployment_id,
            "repository_id": "tmp-repository",
            "repository_generation": 9,
            "installation_generation": 6,
            "state_revision_before": 93369,
            "state_revision_after": 93370,
            "startup_policy_update_count": 1,
            "startup_policies": [{"policy_id": "logical-policy"}],
            "applied_at": "2026-07-29T00:00:00Z",
        }
        database_proof = {
            "database": str(database),
            "database_bundle": {
                "main": {
                    "path": str(database),
                    "device": 1,
                    "inode": 2,
                    "size": len(database_bytes),
                    "mtime_ns": 3,
                    "ctime_ns": 4,
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                    "mode": 0o600,
                    "nlink": 1,
                    "sha256": hashlib.sha256(database_bytes).hexdigest(),
                },
                "sidecars": {"-wal": None, "-shm": None},
            },
            "database_sha256": hashlib.sha256(database_bytes).hexdigest(),
            "database_generation": "generation-12",
            "state_revision": 93370,
            "repository_id": "tmp-repository",
            "repository_generation": 9,
            "installation_generation": 6,
            "startup_policies_sha256": "5" * 64,
            "invariants": {
                "schema_version": 12,
                "state_revision": 93370,
            },
        }
        readiness_origin = {
            "path": str(readiness),
            "document_sha256": "6" * 64,
            "database_identity": {"device": 1, "inode": 2, "size": 3},
            "database_generation": "generation-12",
            "state_revision": 93369,
            "snapshot": _authority_snapshot(state_revision=93369),
        }
        predecessor = {
            "transaction": str(predecessor_transaction),
            "operation_id": predecessor_operation_id,
            "journal": str(predecessor_journal),
            "journal_raw_sha256": hashlib.sha256(
                predecessor_journal_bytes
            ).hexdigest(),
            "journal_document_sha256": "7" * 64,
            "release": str(predecessor_release),
            "release_digest": "c" * 64,
            "verified_unsealed_bytecode_cache_sha256": "8" * 64,
            "readiness_attestation": str(readiness),
            "readiness_raw_sha256": hashlib.sha256(
                readiness.read_bytes()
            ).hexdigest(),
            "readiness_document_sha256": "6" * 64,
            "readiness_origin": readiness_origin,
            "descendant_readiness": {
                **readiness_origin,
                "state_revision": 93370,
            },
            "crash_loop_restore_sha256": "9" * 64,
            "inactive_state": {"ActiveState": "inactive"},
        }
        owner_reference = {
            "path": str(owner_map),
            "raw_sha256": "a" * 64,
            "document_sha256": "b" * 64,
            "identity": {"sha256": "a" * 64},
        }
        accounts = sorted(
            [
                {
                    "user": current_account.pw_name,
                    "uid": current_account.pw_uid,
                },
                {
                    "user": collaborator.pw_name,
                    "uid": collaborator.pw_uid,
                },
            ],
            key=lambda item: (item["uid"], item["user"]),
        )
        export = {
            "profile": str(profile),
            "profile_sha256": hashlib.sha256(repaired_profile).hexdigest(),
            "owner_map": owner_reference,
            "client_uids": [item["uid"] for item in accounts],
            "repository_bindings": [],
            "all_clients_parser_verified": True,
            "existing_profile_contents_reused": False,
        }

        def profile_identity(path: Path, *, uid: int):
            _expect(uid == os.geteuid(), "policy recovery changed profile UID")
            info = path.lstat()
            return {
                "device": info.st_dev,
                "inode": info.st_ino,
                "size": info.st_size,
                "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        def replace_profile(
            path: Path,
            payload: bytes,
            *,
            expected_current_sha256: str,
            owner_uid: int,
            owner_gid: int,
            mode: int,
        ):
            current = profile_identity(path, uid=owner_uid)
            _expect(
                current["sha256"] == expected_current_sha256,
                "policy recovery replaced an unexpected profile",
            )
            path.write_bytes(payload)
            path.chmod(mode)
            return profile_identity(path, uid=owner_uid)

        def policy_lineage(**_kwargs):
            return copy.deepcopy(plan), copy.deepcopy(result), copy.deepcopy(
                references
            )

        def proof_database(**_kwargs):
            proof = copy.deepcopy(database_proof)
            state["database_proofs"].append(proof)
            return proof

        def verify_predecessor(**_kwargs):
            _expect(
                predecessor_journal.read_bytes() == predecessor_journal_bytes,
                "policy recovery changed predecessor journal bytes",
            )
            return copy.deepcopy(predecessor)

        systemd = {"InvocationID": "candidate-invocation", "MainPID": 321}
        socket_identity = {"device": 7, "inode": 8}
        socket_peer = {"pid": 321, "uid": 0, "gid": 986}
        execution = {"argv": ["exact-clean-schema12"]}
        process = {"pid": 321, "argv": ["exact-clean-schema12"]}

        def activate_candidate(**kwargs):
            _expect(
                kwargs.get("_defer_canaries_behind_maintenance") is True
                and kwargs.get("_expected_readiness_state_revision") == 93370,
                "policy recovery did not use exact deferred revision admission",
            )
            _expect(
                state["maintenance_active"],
                "policy recovery started candidate without maintenance",
            )
            candidate_transaction = Path(str(kwargs["transaction"]))
            journal_path = candidate_transaction / bridge.JOURNAL_NAME
            existing = bridge._load_bridge_journal(
                journal_path, uid=os.geteuid()
            )
            if existing is not None:
                return existing
            payload = {
                "operation_id": kwargs["operation_id"],
                "release": str(candidate_release),
                "release_digest": candidate_digest,
                "dropin": str(case / "bridge.conf"),
                "dropin_sha256": "d" * 64,
                "dropin_identity": {"sha256": "d" * 64},
                "broker_socket": str(case / "broker.sock"),
                "failed_activation": {},
                "readiness": {
                    **readiness_origin,
                    "state_revision": 93370,
                },
                "canaries": [
                    {"user": item["user"], "uid": item["uid"]}
                    for item in accounts
                ],
                "baseline": {"ActiveState": "inactive"},
                "phase": "systemd-ready",
                "attempts": 1,
                "activation": {
                    "systemd": systemd,
                    "execution": execution,
                    "canaries": [],
                },
                "error": None,
                "created_at_epoch": 1,
                "updated_at_epoch": 1,
                "readiness_origin": readiness_origin,
                "attempt_evidence": {
                    "attempt": 1,
                    "stage": "systemd-ready",
                },
            }
            state["broker_active"] = True
            return bridge._journal(
                journal_path, payload, uid=os.geteuid()
            )

        def preclear_candidate(**_kwargs):
            _expect(
                state["maintenance_active"] and state["broker_active"],
                "policy recovery preclear ran outside fenced live state",
            )
            return {
                "document_sha256": "e" * 64,
                "systemd": systemd,
                "socket_identity": socket_identity,
                "socket_peer": socket_peer,
                "execution": execution,
                "process": process,
            }

        def finalize_candidate(**kwargs):
            _expect(
                not state["maintenance_active"] and state["broker_active"],
                "policy recovery canary did not run after exact marker clear",
            )
            if canary_failure:
                raise bridge.BridgeError("injected authenticated canary failure")
            journal_path = Path(str(kwargs["transaction"])) / bridge.JOURNAL_NAME
            current = bridge._load_bridge_journal(
                journal_path, uid=os.geteuid()
            )
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload["phase"] = "ready"
            payload["activation"] = {
                "systemd": systemd,
                "execution": execution,
                "canaries": [{"user": item["user"]} for item in accounts],
            }
            payload["updated_at_epoch"] = 2
            return bridge._journal(
                journal_path, payload, uid=os.geteuid()
            )

        def ready_candidate(**kwargs):
            journal_path = (
                Path(str(kwargs["transaction"])) / bridge.JOURNAL_NAME
            )
            journal = bridge._load_bridge_journal(
                journal_path, uid=os.geteuid()
            )
            if (
                journal is None
                or journal.get("phase") != "ready"
                or candidate_release == predecessor_release
                or candidate_release.parent == predecessor_release.parent
            ):
                raise bridge.BridgeError(
                    "strong proof requires a fresh ready candidate"
                )
            return {
                "schema_version": 1,
                "kind": bridge.SUCCESSOR_READY_PROOF_KIND,
                "document_sha256": "f" * 64,
                "systemd": systemd,
                "socket_identity": socket_identity,
                "socket_peer": socket_peer,
                "execution": execution,
                "process": process,
                "verified_at_epoch": 2,
            }

        def restore_candidate(**kwargs):
            if cleanup_ambiguous:
                raise bridge.BridgeError("injected candidate cleanup ambiguity")
            journal_path = (
                Path(str(kwargs["transaction"])) / bridge.JOURNAL_NAME
            )
            current = bridge._load_bridge_journal(
                journal_path, uid=os.geteuid()
            )
            payload = {
                key: value
                for key, value in current.items()
                if key not in {"schema_version", "kind", "document_sha256"}
            }
            payload["phase"] = "restored"
            payload["updated_at_epoch"] = 3
            state["broker_active"] = False
            return bridge._journal(
                journal_path, payload, uid=os.geteuid()
            )

        patches = ExitStack()
        patches.enter_context(
            mock.patch.object(
                bridge, "_load_maintenance_contract", return_value=maintenance
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_successor_transaction_fence", fenced
            )
        )
        patches.enter_context(
            mock.patch.object(bridge, "_broker_service_lock", broker_lock)
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_lock_file_identity",
                return_value={"device": 1, "inode": 2},
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_activation_release",
                return_value={"release_digest": candidate_digest},
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_availability_client_release",
                return_value={"release_digest": "d" * 64},
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_sealed_owner_map_reference",
                return_value=owner_reference,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_successor_canary_accounts",
                return_value=accounts,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_policy_reconciliation_lineage",
                side_effect=policy_lineage,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_policy_reconciled_database_proof",
                side_effect=proof_database,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "verify_policy_reconciled_restored_predecessor",
                side_effect=verify_predecessor,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_profile_identity", side_effect=profile_identity
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "_replace_profile_bytes", side_effect=replace_profile
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_schema12_owner_bound_profile_export",
                return_value=(repaired_profile, export),
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "activate_bridge", side_effect=activate_candidate
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "verify_deferred_bridge_preclear",
                side_effect=preclear_candidate,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "finalize_deferred_bridge_canaries",
                side_effect=finalize_candidate,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_verify_clean_successor_live",
                side_effect=ready_candidate,
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge, "restore_bridge", side_effect=restore_candidate
            )
        )
        patches.enter_context(
            mock.patch.object(
                bridge,
                "_stable_inactive",
                side_effect=lambda _socket: (
                    {"ActiveState": "inactive", "SubState": "dead", "MainPID": 0}
                    if not state["broker_active"]
                    else _fail("policy recovery claimed active broker inactive")
                ),
            )
        )
        arguments = {
            "candidate_release": candidate_release,
            "release_root": candidate_root,
            "client_release": client_release,
            "transaction": transaction,
            "operation_id": operation_id,
            "predecessor_transaction": predecessor_transaction,
            "predecessor_operation_id": predecessor_operation_id,
            "predecessor_journal_raw_sha256": hashlib.sha256(
                predecessor_journal_bytes
            ).hexdigest(),
            "predecessor_journal_document_sha256": "7" * 64,
            "failed_installer_transaction": failed_transaction,
            "failed_installer_operation_id": failed_operation_id,
            "readiness_attestation": readiness,
            "readiness_raw_sha256": hashlib.sha256(
                readiness.read_bytes()
            ).hexdigest(),
            "readiness_document_sha256": "6" * 64,
            "source_repair_plan": evidence_paths["source-plan"],
            "source_repair_plan_raw_sha256": references[
                "source_repair_plan"
            ]["raw_sha256"],
            "source_repair_plan_document_sha256": "1" * 64,
            "source_repair_result": evidence_paths["source-result"],
            "source_repair_result_raw_sha256": references[
                "source_repair_result"
            ]["raw_sha256"],
            "source_repair_result_document_sha256": "2" * 64,
            "policy_plan": evidence_paths["policy-plan"],
            "policy_plan_raw_sha256": references["policy_plan"][
                "raw_sha256"
            ],
            "policy_plan_document_sha256": "3" * 64,
            "policy_result": evidence_paths["policy-result"],
            "policy_result_raw_sha256": references["policy_result"][
                "raw_sha256"
            ],
            "policy_result_document_sha256": "4" * 64,
            "database": database,
            "profile": profile,
            "owner_map": owner_map,
            "owner_map_sha256": "a" * 64,
            "broker_socket": case / "broker.sock",
            "dropin": case / "bridge.conf",
            "maintenance_root": maintenance_root,
            "maintenance_gid": os.getegid(),
            "maintenance_deployment_id": deployment_id,
            "canary_user": current_account.pw_name,
            "expected_canary_uid": current_account.pw_uid,
            "canary_project": project,
            "canary_repository_id": "global-finance",
            "canary_repository_generation": 4,
            "additional_canaries": (
                f"{collaborator.pw_name}={collaborator.pw_uid}",
            ),
            "wait_seconds": 5,
            "expected_uid": os.geteuid(),
        }
        return (
            patches,
            arguments,
            state,
            profile,
            original_profile,
            repaired_profile,
            database,
            database_bytes,
            predecessor_journal,
            predecessor_journal_bytes,
        )

    (
        patches,
        arguments,
        state,
        profile,
        _original,
        repaired,
        database,
        database_bytes,
        predecessor_journal,
        predecessor_bytes,
    ) = fixture("success")
    with patches:
        result = bridge.recover_policy_reconciled_restored_bridge(**arguments)
        replay = bridge.recover_policy_reconciled_restored_bridge(**arguments)
    _expect(
        result["ok"] is True
        and result["terminal"]["status"] == "committed"
        and replay["replayed"] is True
        and state["maintenance_active"] is False
        and profile.read_bytes() == repaired
        and database.read_bytes() == database_bytes
        and predecessor_journal.read_bytes() == predecessor_bytes,
        "policy recovery did not commit/replay without changing sealed authority",
    )

    (
        patches,
        arguments,
        state,
        profile,
        original,
        _repaired,
        database,
        database_bytes,
        predecessor_journal,
        predecessor_bytes,
    ) = fixture("canary-failure", canary_failure=True)
    with patches:
        result = bridge.recover_policy_reconciled_restored_bridge(**arguments)
        replay = bridge.recover_policy_reconciled_restored_bridge(**arguments)
    candidate_journal = (
        arguments["transaction"]
        / bridge.POLICY_RECOVERY_CANDIDATE_DIRECTORY
        / bridge.JOURNAL_NAME
    )
    candidate = bridge._load_bridge_journal(
        candidate_journal, uid=os.geteuid()
    )
    _expect(
        result["ok"] is False
        and result["terminal"]["status"] == "aborted"
        and replay["terminal"]["status"] == "aborted"
        and state["maintenance_active"] is True
        and candidate["phase"] == "restored"
        and profile.read_bytes() == original
        and database.read_bytes() == database_bytes
        and predecessor_journal.read_bytes() == predecessor_bytes
        and all(
            proof["state_revision"] == 93370
            and proof["database_sha256"]
            == hashlib.sha256(database_bytes).hexdigest()
            for proof in state["database_proofs"]
        ),
        "canary rollback did not preserve exact CAS/journal/profile state",
    )

    (
        patches,
        arguments,
        state,
        _profile,
        _original,
        _repaired,
        database,
        database_bytes,
        predecessor_journal,
        predecessor_bytes,
    ) = fixture(
        "cleanup-ambiguity",
        canary_failure=True,
        cleanup_ambiguous=True,
    )
    with patches:
        _expect_bridge_error(
            bridge,
            lambda: bridge.recover_policy_reconciled_restored_bridge(
                **arguments
            ),
            "manual replay",
        )
    journal = bridge._load_policy_recovery_journal(
        arguments["transaction"] / bridge.POLICY_RECOVERY_JOURNAL_NAME,
        uid=os.geteuid(),
    )
    _expect(
        journal["phase"] == "recovery-required"
        and state["maintenance_active"] is True
        and database.read_bytes() == database_bytes
        and predecessor_journal.read_bytes() == predecessor_bytes,
        "ambiguous cleanup did not fail closed behind maintenance",
    )

    patches, arguments, state, *_rest = fixture(
        "cross-release", candidate_digest="0" * 64
    )
    with patches:
        _expect_bridge_error(
            bridge,
            lambda: bridge.recover_policy_reconciled_restored_bridge(
                **arguments
            ),
            "equal-byte distinct clean root",
        )
    _expect(
        state["maintenance_active"] is True,
        "cross-release rejection cleared maintenance",
    )

    (
        patches,
        arguments,
        state,
        _profile,
        _original,
        _repaired,
        database,
        database_bytes,
        predecessor_journal,
        predecessor_bytes,
    ) = fixture("crash-replay")
    with patches:
        injected = {"done": False}

        def crash(stage: str) -> None:
            if stage == "after-maintenance-clear" and not injected["done"]:
                injected["done"] = True
                raise InjectedCrash(stage)

        try:
            bridge.recover_policy_reconciled_restored_bridge(
                **arguments, failpoint=crash
            )
        except InjectedCrash:
            pass
        else:
            _fail("policy recovery maintenance-clear crash did not fire")
        result = bridge.recover_policy_reconciled_restored_bridge(**arguments)
    _expect(
        result["ok"] is True
        and state["maintenance_active"] is False
        and database.read_bytes() == database_bytes
        and predecessor_journal.read_bytes() == predecessor_bytes,
        "policy recovery did not forward-complete marker-clear replay",
    )


def _exercise_lifecycle_restored_rearm_contract(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "lifecycle-restored-rearm"
    fixture.mkdir(mode=0o700)
    transaction = fixture / "predecessor"
    transaction.mkdir(mode=0o700)
    predecessor_journal = transaction / bridge.JOURNAL_NAME
    predecessor_bytes = b'{"sealed":"restored-predecessor"}\n'
    predecessor_journal.write_bytes(predecessor_bytes)
    predecessor_journal.chmod(0o600)
    outer_operation = str(uuid.uuid4())
    predecessor_operation = str(uuid.uuid4())
    outer_document_sha256 = "a" * 64
    outer_journal = fixture / "lifecycle-service-intent.json"
    outer_journal.write_text(
        json.dumps(
            {
                "operation_id": outer_operation,
                "document_sha256": outer_document_sha256,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    outer_journal.chmod(0o600)
    rearm_journal = fixture / bridge.LIFECYCLE_REARM_JOURNAL_NAME
    release = fixture / "historical-release"
    release.mkdir(mode=0o555)
    database = fixture / "authority.sqlite3"
    profile = fixture / "client-profiles.json"
    broker_socket = fixture / "broker.sock"
    dropin = fixture / "dropins/95-schema12-cutover-bridge.conf"
    state = {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "SubState": "dead",
        "UnitFileState": "enabled",
        "MainPID": 0,
        "InvocationID": "inactive-invocation",
        "NRestarts": 0,
    }
    run_calls: list[tuple[str, ...]] = []

    @contextmanager
    def installer_lock(_uid: int):
        yield

    def run(argv: list[str], **_values: object) -> object:
        run_calls.append(tuple(argv))
        if argv[1] == "start":
            state.update(
                {
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": 4242,
                    "InvocationID": "rearmed-invocation",
                }
            )
        return SimpleNamespace(returncode=0)

    def preflight(**values: object) -> dict[str, object]:
        _expect(
            values.get("_allow_rearmed_dropin")
            is (rearm_journal.exists() or rearm_journal.is_symlink()),
            "rearm replay did not declare its retained evidence",
        )
        return {
            "mode": "restored",
            "bridge_journal": str(predecessor_journal),
            "bridge_release": str(release),
            "bridge_release_digest": "b" * 64,
            "dropin_sha256": hashlib.sha256(
                bridge._dropin_payload(release, database, broker_socket)
            ).hexdigest(),
        }

    proof = {"proof": "outer-owned-restored-rearm"}
    original_replace = bridge.os.replace
    interrupted = {"done": False}

    def replace(source: object, destination: object) -> None:
        if Path(destination) == dropin and not interrupted["done"]:
            interrupted["done"] = True
            raise OSError("injected publication interruption")
        original_replace(source, destination)

    arguments = {
        "outer_operation_id": outer_operation,
        "outer_transaction_journal": outer_journal,
        "outer_transaction_document_sha256": outer_document_sha256,
        "rearm_journal": rearm_journal,
        "transaction": transaction,
        "operation_id": predecessor_operation,
        "expected_journal_sha256": "c" * 64,
        "expected_journal_document_sha256": "d" * 64,
        "historical_client_release": fixture / "clean-historical-release",
        "database": database,
        "profile": profile,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": str(uuid.uuid4()),
        "canary_user": pwd.getpwuid(os.getuid()).pw_name,
        "expected_canary_uid": os.getuid(),
        "canary_project": fixture,
        "canary_repository_id": "repository-id",
        "canary_repository_generation": 2,
        "wait_seconds": 5,
        "expected_uid": os.geteuid(),
    }
    patches = (
        mock.patch.object(
            bridge, "_preflight_lifecycle_predecessor", side_effect=preflight
        ),
        mock.patch.object(bridge, "_installer_lock", side_effect=installer_lock),
        mock.patch.object(bridge, "_systemd_state", side_effect=lambda: dict(state)),
        mock.patch.object(bridge, "_run", side_effect=run),
        mock.patch.object(
            bridge, "_wait_active", side_effect=lambda _socket, _wait: dict(state)
        ),
        mock.patch.object(
            bridge,
            "_verify_active_predecessor_for_successor",
            side_effect=lambda **_values: dict(proof),
        ),
        mock.patch.object(bridge.os, "replace", side_effect=replace),
    )
    with ExitStack() as stack:
        for patcher in patches:
            stack.enter_context(patcher)
        try:
            bridge._rearm_restored_predecessor_for_lifecycle(**arguments)
        except OSError as error:
            _expect(
                "injected publication interruption" in str(error),
                f"unexpected rearm interruption: {error}",
            )
        else:
            _fail("lifecycle rearm publication interruption did not fire")
        prepared = bridge._load_lifecycle_rearm_journal(
            rearm_journal, uid=os.geteuid()
        )
        _expect(
            prepared is not None and prepared.get("phase") == "prepared",
            "lifecycle rearm did not retain its prepared stage",
        )
        first = bridge._rearm_restored_predecessor_for_lifecycle(**arguments)
        calls_after_first = list(run_calls)
        second = bridge._rearm_restored_predecessor_for_lifecycle(**arguments)
    ready = bridge._load_lifecycle_rearm_journal(
        rearm_journal, uid=os.geteuid()
    )
    _expect(
        first == proof
        and second == proof
        and ready is not None
        and ready.get("phase") == "ready"
        and dropin.is_file()
        and not Path(str(ready["staged_dropin"])).exists()
        and run_calls == calls_after_first
        and predecessor_journal.read_bytes() == predecessor_bytes,
        "restored predecessor rearm was not exact, replay-safe, and non-mutating",
    )


def _exercise_lifecycle_dropin_payload_compatibility(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "lifecycle-dropin-payload-compatibility"
    fixture.mkdir(mode=0o700)
    transaction = fixture / "predecessor"
    transaction.mkdir(mode=0o700)
    journal = transaction / bridge.JOURNAL_NAME
    journal.write_bytes(b'{"fixture":"predecessor"}\n')
    journal.chmod(0o600)
    release = fixture / "historical-release"
    clean_release = fixture / "clean-historical-release"
    release.mkdir(mode=0o555)
    clean_release.mkdir(mode=0o555)
    database = fixture / "authority.sqlite3"
    profile = fixture / "client-profiles.json"
    broker_socket = fixture / "broker.sock"
    dropin = fixture / "dropins/95-schema12-cutover-bridge.conf"
    account = pwd.getpwuid(os.getuid())
    operation_id = str(uuid.uuid4())
    document_sha256 = "a" * 64
    release_digest = "b" * 64
    database_generation = str(uuid.uuid4())
    historical_payload = bridge._historical_restored_dropin_payload(
        release, database, broker_socket
    )
    hardened_payload = bridge._dropin_payload(
        release, database, broker_socket
    )
    historical_sha256 = hashlib.sha256(historical_payload).hexdigest()
    hardened_sha256 = hashlib.sha256(hardened_payload).hexdigest()
    _expect(
        historical_payload != hardened_payload
        and b"/usr/bin/python3 -I " in historical_payload
        and b"/usr/bin/python3 -B -I " not in historical_payload
        and b"/usr/bin/python3 -B -I " in hardened_payload,
        "historical and hardened bridge payloads are not exact variants",
    )
    bridge_state = {
        "operation_id": operation_id,
        "document_sha256": document_sha256,
        "phase": "restored",
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "canaries": [
            {
                "user": account.pw_name,
                "uid": account.pw_uid,
                "project": str(fixture),
            }
        ],
        "release": str(release),
        "release_digest": release_digest,
        "dropin_sha256": historical_sha256,
        "dropin_identity": {"fixture": "ready-only"},
        "readiness": {"path": str(fixture / "readiness.json")},
        "readiness_origin": {"path": str(fixture / "origin.json")},
    }
    verified_dropin_digests: list[str] = []

    def activation_manifest(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"release_digest": release_digest}

    def verify_dropin(
        _path: Path,
        expected: object,
        *,
        uid: int,
        expected_sha256: str,
    ) -> object:
        del uid
        verified_dropin_digests.append(expected_sha256)
        return expected

    arguments = {
        "transaction": transaction,
        "operation_id": operation_id,
        "expected_journal_sha256": hashlib.sha256(journal.read_bytes()).hexdigest(),
        "expected_journal_document_sha256": document_sha256,
        "historical_client_release": clean_release,
        "database": database,
        "profile": profile,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": database_generation,
        "canary_user": account.pw_name,
        "expected_canary_uid": account.pw_uid,
        "canary_project": fixture,
        "canary_repository_id": "repository-id",
        "canary_repository_generation": 2,
        "expected_uid": os.geteuid(),
    }
    patches = (
        mock.patch.object(
            bridge, "_load_bridge_journal", side_effect=lambda *_args, **_kwargs: bridge_state
        ),
        mock.patch.object(
            bridge, "_verify_activation_release", side_effect=activation_manifest
        ),
        mock.patch.object(
            bridge,
            "_verify_retained_readiness_reference",
            return_value={
                "database_generation": database_generation,
                "database_identity": {},
                "snapshot": {},
            },
        ),
        mock.patch.object(
            bridge, "_readiness_origin_from_attestation", return_value={}
        ),
        mock.patch.object(bridge, "_validate_readiness_descendant"),
        mock.patch.object(bridge, "_legacy_profile_repository_reference"),
        mock.patch.object(
            bridge, "_verify_dropin_identity", side_effect=verify_dropin
        ),
    )
    with ExitStack() as stack:
        for patcher in patches:
            stack.enter_context(patcher)
        restored = bridge._preflight_lifecycle_predecessor(**arguments)
        _expect(
            restored.get("mode") == "restored"
            and restored.get("bridge_dropin_sha256") == historical_sha256
            and restored.get("dropin_sha256") == hardened_sha256,
            "restored preflight did not separate historical and hardened payloads",
        )
        bridge_state["dropin_sha256"] = hardened_sha256
        _expect_bridge_error(
            bridge,
            lambda: bridge._preflight_lifecycle_predecessor(**arguments),
            "lifecycle predecessor release binding changed",
        )
        bridge_state["phase"] = "ready"
        ready_identity = {"fixture": "current-ready"}
        bridge_state["dropin_identity"] = ready_identity
        bridge_state["dropin_sha256"] = hardened_sha256
        ready = bridge._preflight_lifecycle_predecessor(**arguments)
        _expect(
            ready.get("mode") == "ready"
            and ready.get("bridge_dropin_sha256") == hardened_sha256
            and ready.get("dropin_sha256") == hardened_sha256
            and verified_dropin_digests == [hardened_sha256],
            "original-ready preflight no longer uses the hardened bridge payload",
        )
        bridge_state["dropin_sha256"] = historical_sha256
        _expect_bridge_error(
            bridge,
            lambda: bridge._preflight_lifecycle_predecessor(**arguments),
            "lifecycle predecessor release binding changed",
        )


def _exercise_restored_active_proof_uses_outer_rearm(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "restored-active-proof-outer-rearm"
    fixture.mkdir(mode=0o700)
    transaction = fixture / "predecessor"
    transaction.mkdir(mode=0o700)
    journal = transaction / bridge.JOURNAL_NAME
    journal.write_bytes(b'{"fixture":"restored-active-proof"}\n')
    journal.chmod(0o600)
    release = fixture / "historical-release"
    clean_release = fixture / "clean-historical-release"
    release.mkdir(mode=0o555)
    clean_release.mkdir(mode=0o555)
    database = fixture / "authority.sqlite3"
    profile = fixture / "client-profiles.json"
    broker_socket = fixture / "broker.sock"
    dropin = fixture / "dropins/95-schema12-cutover-bridge.conf"
    account = pwd.getpwuid(os.getuid())
    operation_id = str(uuid.uuid4())
    document_sha256 = "1" * 64
    journal_sha256 = hashlib.sha256(journal.read_bytes()).hexdigest()
    release_digest = "2" * 64
    database_generation = str(uuid.uuid4())
    historical_sha256 = hashlib.sha256(
        bridge._historical_restored_dropin_payload(
            release, database, broker_socket
        )
    ).hexdigest()
    hardened_sha256 = hashlib.sha256(
        bridge._dropin_payload(release, database, broker_socket)
    ).hexdigest()
    bridge_state = {
        "operation_id": operation_id,
        "document_sha256": document_sha256,
        "phase": "restored",
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "canaries": [
            {
                "user": account.pw_name,
                "uid": account.pw_uid,
                "project": str(fixture),
            }
        ],
        "release": str(release),
        "release_digest": release_digest,
        "dropin_sha256": historical_sha256,
        "dropin_identity": {"fixture": "removed-historical-dropin"},
        "readiness": {"path": str(fixture / "readiness.json")},
        "readiness_origin": {"path": str(fixture / "origin.json")},
    }
    rearm_reference = {
        "journal": str(fixture / bridge.LIFECYCLE_REARM_JOURNAL_NAME),
        "journal_document_sha256": "3" * 64,
        "outer_transaction_journal": str(
            fixture / "lifecycle-service-intent.json"
        ),
        "outer_transaction_document_sha256": "4" * 64,
    }
    rearm_identity = {
        "fixture": "published-hardened-dropin",
        "sha256": hardened_sha256,
    }
    rearm_state = {
        "bridge_operation_id": operation_id,
        "bridge_journal": str(journal),
        "bridge_journal_sha256": journal_sha256,
        "bridge_document_sha256": document_sha256,
        "release": str(release),
        "release_digest": release_digest,
        "database": str(database),
        "profile": str(profile),
        "broker_socket": str(broker_socket),
        "dropin": str(dropin),
        "dropin_sha256": hardened_sha256,
        "dropin_identity": rearm_identity,
    }
    systemd_state = {
        "InvocationID": "rearmed-invocation",
        "MainPID": 4242,
    }
    profile_identity = {"fixture": "stable-profile"}
    legacy_repository = {"fixture": "legacy-repository"}
    observed_dropins: list[tuple[object, str]] = []
    canary_calls: list[dict[str, object]] = []

    def verify_dropin(
        _path: Path,
        expected: object,
        *,
        uid: int,
        expected_sha256: str,
    ) -> object:
        del uid
        observed_dropins.append((expected, expected_sha256))
        return expected

    def inventory_canary(**values: object) -> dict[str, object]:
        canary_calls.append(dict(values))
        return {"fixture": "canary"}

    arguments = {
        "transaction": transaction,
        "operation_id": operation_id,
        "expected_journal_sha256": journal_sha256,
        "expected_journal_document_sha256": document_sha256,
        "historical_client_release": clean_release,
        "database": database,
        "profile": profile,
        "broker_socket": broker_socket,
        "dropin": dropin,
        "expected_database_generation": database_generation,
        "canary_user": account.pw_name,
        "expected_canary_uid": account.pw_uid,
        "canary_project": fixture,
        "canary_repository_id": "repository-id",
        "canary_repository_generation": 2,
        "wait_seconds": 5,
        "expected_uid": os.geteuid(),
        "_allow_restored": True,
        "_expected_dropin_identity": rearm_identity,
        "_outer_rearm": rearm_reference,
    }
    patches = (
        mock.patch.object(
            bridge, "_load_bridge_journal", side_effect=lambda *_args, **_kwargs: bridge_state
        ),
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={"release_digest": release_digest},
        ),
        mock.patch.object(
            bridge,
            "_verify_retained_readiness_reference",
            return_value={
                "database_generation": database_generation,
                "database_identity": {},
                "snapshot": {},
            },
        ),
        mock.patch.object(
            bridge, "_readiness_origin_from_attestation", return_value={}
        ),
        mock.patch.object(bridge, "_validate_readiness_descendant"),
        mock.patch.object(
            bridge,
            "_verified_lifecycle_rearm_binding",
            side_effect=lambda *_args, **_kwargs: (
                dict(rearm_reference),
                dict(rearm_state),
            ),
        ),
        mock.patch.object(
            bridge, "_verify_dropin_identity", side_effect=verify_dropin
        ),
        mock.patch.object(
            bridge,
            "_legacy_profile_repository_reference",
            return_value=(profile_identity, legacy_repository),
        ),
        mock.patch.object(
            bridge, "_wait_active", return_value=dict(systemd_state)
        ),
        mock.patch.object(
            bridge, "_socket_identity", return_value={"fixture": "socket"}
        ),
        mock.patch.object(
            bridge,
            "_verify_loaded_bridge_execution",
            return_value={"argv": ["/usr/bin/python3", "-B", "-I"]},
        ),
        mock.patch.object(
            bridge, "_broker_process_identity", return_value={"fixture": "process"}
        ),
        mock.patch.object(
            bridge, "_broker_socket_peer", return_value={"pid": 4242, "uid": 0}
        ),
        mock.patch.object(
            bridge, "_inventory_canary", side_effect=inventory_canary
        ),
        mock.patch.object(
            bridge,
            "_verify_successor_predecessor_proof",
            side_effect=lambda value: value,
        ),
    )
    with ExitStack() as stack:
        for patcher in patches:
            stack.enter_context(patcher)
        proof = bridge._verify_active_predecessor_for_successor(**arguments)
        _expect(
            proof.get("dropin_identity") == rearm_identity
            and observed_dropins == [(rearm_identity, hardened_sha256)],
            "restored active proof used the historical bridge drop-in binding",
        )
        predecessor = bridge._successor_predecessor_reference(
            transaction=transaction,
            operation_id=operation_id,
            journal_sha256=journal_sha256,
            document_sha256=document_sha256,
            ready_proof=proof,
            broker_socket=broker_socket,
            dropin=dropin,
            expected_uid=os.geteuid(),
        )
        _expect(
            predecessor.get("dropin_sha256") == hardened_sha256
            and predecessor.get("dropin_identity") == rearm_identity,
            "successor predecessor reference reused the removed historical drop-in digest",
        )
        _expect(
            len(canary_calls) == 1
            and canary_calls[0].get("profile") == profile
            and canary_calls[0].get("_cutover_maintenance_inventory_read")
            is True
            and canary_calls[0].get("_historical_release_digest")
            == release_digest,
            "active predecessor did not select the cutover-only inventory path",
        )
        rearm_state["dropin_sha256"] = historical_sha256
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_active_predecessor_for_successor(**arguments),
            "restored predecessor outer rearm binding changed",
        )


def _exercise_successor_predecessor_sha_replay_repair(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "successor-predecessor-sha-replay-repair"
    fixture.mkdir(mode=0o700)
    transaction = fixture / "successor"
    transaction.mkdir(mode=0o700)
    journal_path = transaction / bridge.SUCCESSOR_JOURNAL_NAME
    predecessor_transaction = fixture / "predecessor"
    predecessor_transaction.mkdir(mode=0o700)
    predecessor_journal = predecessor_transaction / bridge.JOURNAL_NAME
    predecessor_journal.write_text("{}\n", encoding="utf-8")
    predecessor_journal.chmod(0o600)
    dropin = fixture / "95-schema12-cutover-bridge.conf"
    historical_sha256 = "6" * 64
    active_sha256 = "7" * 64
    active_identity = {"fixture": "active-dropin", "sha256": active_sha256}
    outer_rearm = {
        "journal": str(fixture / bridge.LIFECYCLE_REARM_JOURNAL_NAME),
        "journal_document_sha256": "8" * 64,
        "outer_transaction_journal": str(fixture / "lifecycle.json"),
        "outer_transaction_document_sha256": "9" * 64,
    }
    ready_proof = {
        "broker_socket": str(fixture / "broker.sock"),
        "dropin": str(dropin),
        "dropin_identity": active_identity,
        "outer_rearm": outer_rearm,
    }
    predecessor = {
        "transaction": str(predecessor_transaction),
        "operation_id": str(uuid.uuid4()),
        "journal": str(predecessor_journal),
        "journal_sha256": "1" * 64,
        "document_sha256": "2" * 64,
        "release": str(fixture / "release"),
        "release_digest": "3" * 64,
        "dropin_sha256": historical_sha256,
        "dropin_identity": active_identity,
        "readiness_origin": {"fixture": "origin"},
        "readiness_origin_sha256": "4" * 64,
        "ready_proof": ready_proof,
    }
    regenerated = {**predecessor, "dropin_sha256": active_sha256}
    binding = {
        "maintenance_handoff": {"predecessor_proof": dict(ready_proof)}
    }

    def write_current(*, phase: str, predecessor_value: object) -> dict[str, object]:
        return bridge._successor_journal(
            journal_path,
            {
                "operation_id": str(uuid.uuid4()),
                "binding": binding,
                "predecessor": predecessor_value,
                "profile": {},
                "candidate": {},
                "restored_predecessor": None,
                "phase": phase,
                "error": None,
                "created_at_epoch": 1,
                "updated_at_epoch": 1,
            },
            uid=os.geteuid(),
        )

    verified_dropins: list[tuple[object, str]] = []

    def verify_dropin(
        _path: Path,
        expected: object,
        *,
        uid: int,
        expected_sha256: str,
    ) -> object:
        _expect(uid == os.geteuid(), "replay repair changed authority UID")
        verified_dropins.append((expected, expected_sha256))
        return expected

    current = write_current(
        phase="predecessor-dropin-remove-intent",
        predecessor_value=predecessor,
    )
    with (
        mock.patch.object(
            bridge,
            "_verify_successor_predecessor_proof",
            side_effect=lambda value: dict(value),
        ),
        mock.patch.object(
            bridge,
            "_successor_predecessor_reference",
            return_value=regenerated,
        ),
        mock.patch.object(
            bridge,
            "_load_bridge_journal",
            return_value={"phase": "restored", "dropin_sha256": historical_sha256},
        ),
        mock.patch.object(
            bridge,
            "_verified_lifecycle_rearm_binding",
            return_value=(
                outer_rearm,
                {
                    "dropin_sha256": active_sha256,
                    "dropin_identity": active_identity,
                },
            ),
        ),
        mock.patch.object(
            bridge, "_verify_dropin_identity", side_effect=verify_dropin
        ),
    ):
        repaired = bridge._repair_inherited_successor_predecessor_sha_replay(
            current,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        )
        retained = bridge._load_successor_journal(
            journal_path, uid=os.geteuid()
        )
        _expect(
            repaired == retained
            and retained is not None
            and retained["phase"] == "predecessor-dropin-remove-intent"
            and retained["predecessor"] == regenerated
            and verified_dropins == [(active_identity, active_sha256)],
            "successor replay did not seal the exact active predecessor SHA",
        )

        unrelated = {**predecessor, "release_digest": "a" * 64}
        current = write_current(
            phase="predecessor-dropin-remove-intent",
            predecessor_value=unrelated,
        )
        unchanged = bridge._repair_inherited_successor_predecessor_sha_replay(
            current,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        )
        _expect(
            unchanged == current
            and bridge._load_successor_journal(
                journal_path, uid=os.geteuid()
            )
            == current,
            "successor replay repaired more than the stale SHA field",
        )

        current = write_current(
            phase="predecessor-retired", predecessor_value=predecessor
        )
        unchanged = bridge._repair_inherited_successor_predecessor_sha_replay(
            current,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        )
        _expect(
            unchanged == current,
            "successor replay repaired a predecessor after retirement",
        )


def _exercise_retired_predecessor_absent_dropin_reference(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "retired-predecessor-absent-dropin-reference"
    fixture.mkdir(mode=0o700)
    transaction = fixture / "predecessor"
    transaction.mkdir(mode=0o700)
    journal = transaction / bridge.JOURNAL_NAME
    journal.write_text("{}\n", encoding="utf-8")
    journal.chmod(0o600)
    journal_sha256 = hashlib.sha256(journal.read_bytes()).hexdigest()
    operation_id = str(uuid.uuid4())
    document_sha256 = "2" * 64
    release_digest = "3" * 64
    release = fixture / release_digest
    release.mkdir(mode=0o700)
    dropin = fixture / "95-schema12-cutover-bridge.conf"
    dropin_sha256 = "4" * 64
    dropin_identity = {
        "device": 11,
        "inode": 13,
        "size": 17,
        "mtime_ns": 19,
        "ctime_ns": 23,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "mode": 0o644,
        "nlink": 1,
        "sha256": dropin_sha256,
    }
    readiness = fixture / "readiness.json"
    readiness.write_text("{}\n", encoding="utf-8")
    readiness.chmod(0o600)
    readiness_origin = {"path": str(readiness), "fixture": "origin"}
    readiness_origin_sha256 = hashlib.sha256(
        json.dumps(
            readiness_origin, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    outer_rearm = {
        "journal": str(fixture / "lifecycle-predecessor-rearm.json"),
        "journal_document_sha256": "5" * 64,
        "outer_transaction_journal": str(fixture / "lifecycle.json"),
        "outer_transaction_document_sha256": "6" * 64,
    }
    ready_proof = {
        "bridge_journal": str(journal),
        "bridge_journal_sha256": journal_sha256,
        "bridge_document_sha256": document_sha256,
        "broker_release": str(release),
        "broker_release_digest": release_digest,
        "verified_unsealed_bytecode_cache": [],
        "verified_unsealed_bytecode_cache_sha256": hashlib.sha256(b"[]").hexdigest(),
        "broker_socket": str(fixture / "broker.sock"),
        "dropin": str(dropin),
        "dropin_identity": dropin_identity,
        "readiness_origin": readiness_origin,
        "readiness_origin_sha256": readiness_origin_sha256,
        "outer_rearm": outer_rearm,
    }
    predecessor = {
        "transaction": str(transaction),
        "operation_id": operation_id,
        "journal": str(journal),
        "journal_sha256": journal_sha256,
        "document_sha256": document_sha256,
        "release": str(release),
        "release_digest": release_digest,
        "dropin_sha256": dropin_sha256,
        "dropin_identity": dropin_identity,
        "readiness_origin": readiness_origin,
        "readiness_origin_sha256": readiness_origin_sha256,
        "ready_proof": ready_proof,
    }
    bridge_journal = {
        "operation_id": operation_id,
        "document_sha256": document_sha256,
        "phase": "restored",
        "release_digest": release_digest,
        "readiness_origin": readiness_origin,
    }
    rearm_journal = {
        "dropin": str(dropin),
        "dropin_sha256": dropin_sha256,
        "dropin_identity": dropin_identity,
    }
    boundary = {
        "state": "absent",
        "path": str(dropin),
        "bound_identity": dropin_identity,
        "bound_sha256": dropin_sha256,
    }
    with (
        mock.patch.object(
            bridge,
            "_verify_successor_predecessor_proof",
            side_effect=lambda value: dict(value),
        ),
        mock.patch.object(
            bridge, "_load_bridge_journal", return_value=bridge_journal
        ),
        mock.patch.object(
            bridge,
            "_verify_activation_release",
            return_value={
                "release_digest": release_digest,
                "verified_unsealed_bytecode_cache": [],
                "verified_unsealed_bytecode_cache_sha256": hashlib.sha256(
                    b"[]"
                ).hexdigest(),
            },
        ),
        mock.patch.object(
            bridge,
            "_readiness_origin_from_attestation",
            return_value=readiness_origin,
        ),
        mock.patch.object(
            bridge,
            "_verified_lifecycle_rearm_lineage",
            return_value=(
                outer_rearm,
                rearm_journal,
                {
                    "rearm_journal_descriptor": {},
                    "outer_transaction_descriptor": {},
                },
            ),
        ) as lineage,
        mock.patch.object(
            bridge,
            "_verified_lifecycle_rearm_binding",
            side_effect=FileNotFoundError(str(dropin)),
        ) as live_binding,
    ):
        verified = bridge._verify_successor_predecessor(
            predecessor,
            expected_uid=os.geteuid(),
            retired_dropin_boundary=boundary,
        )
        _expect(
            verified == predecessor
            and lineage.call_count == 1
            and live_binding.call_count == 0,
            "retired predecessor did not use its sealed absent-drop-in lineage",
        )
        try:
            bridge._verify_successor_predecessor(
                predecessor, expected_uid=os.geteuid()
            )
        except FileNotFoundError:
            pass
        else:
            _fail("pre-retirement predecessor verification accepted an absent drop-in")
        wrong_boundary = {
            **boundary,
            "bound_sha256": "7" * 64,
            "bound_identity": {**dropin_identity, "sha256": "7" * 64},
        }
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_successor_predecessor(
                predecessor,
                expected_uid=os.geteuid(),
                retired_dropin_boundary=wrong_boundary,
            ),
            "retired drop-in boundary changed",
        )
        dropin.write_text("[Service]\nEnvironment=REAPPEARED=1\n", encoding="utf-8")
        dropin.chmod(0o644)
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_successor_predecessor(
                predecessor,
                expected_uid=os.geteuid(),
                retired_dropin_boundary=boundary,
            ),
            "reappeared after absent boundary",
        )


def _exercise_rearm_descriptor_inode_replacement_contract(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "rearm-descriptor-inode-replacement"
    fixture.mkdir(mode=0o700)
    outer_path = fixture / "outer-transaction.json"
    outer = bridge._seal("fixture-outer-transaction", {"phase": "ready"})
    bridge._atomic_private_json(outer_path, outer, uid=os.geteuid())
    rearm_path = fixture / bridge.LIFECYCLE_REARM_JOURNAL_NAME
    rearm = bridge._write_lifecycle_rearm_journal(
        rearm_path,
        {
            "outer_operation_id": str(uuid.uuid4()),
            "outer_transaction_journal": str(outer_path),
            "outer_transaction_document_sha256": outer[
                "document_sha256"
            ],
            "bridge_operation_id": str(uuid.uuid4()),
            "bridge_journal": str(fixture / "bridge-journal.json"),
            "bridge_journal_sha256": "1" * 64,
            "bridge_document_sha256": "2" * 64,
            "release": str(fixture / ("3" * 64)),
            "release_digest": "3" * 64,
            "database": str(fixture / "authority.sqlite3"),
            "profile": str(fixture / "profiles.json"),
            "broker_socket": str(fixture / "broker.sock"),
            "dropin": str(fixture / "bridge.conf"),
            "dropin_sha256": "4" * 64,
            "staged_dropin": str(fixture / "bridge.conf.staged"),
            "staged_identity": {"sha256": "4" * 64},
            "phase": "ready",
            "dropin_identity": {"sha256": "4" * 64},
            "activation_invocation_id": "fixture-invocation",
            "created_at_epoch": 1,
            "updated_at_epoch": 2,
        },
        uid=os.geteuid(),
    )
    reference = {
        "journal": str(rearm_path),
        "journal_document_sha256": rearm["document_sha256"],
        "outer_transaction_journal": str(outer_path),
        "outer_transaction_document_sha256": outer[
            "document_sha256"
        ],
    }
    _reference, _journal, evidence = (
        bridge._verified_lifecycle_rearm_lineage(
            reference, expected_uid=os.geteuid()
        )
    )
    bridge._verify_retained_lifecycle_rearm_descriptor_lineage(
        reference, evidence, expected_uid=os.geteuid()
    )
    original = rearm_path.read_bytes()
    original_inode = rearm_path.stat().st_ino
    replacement = fixture / "replacement.json"
    replacement.write_bytes(original)
    replacement.chmod(0o600)
    os.replace(replacement, rearm_path)
    _expect(
        rearm_path.read_bytes() == original
        and rearm_path.stat().st_ino != original_inode,
        "rearm inode replacement fixture did not preserve exact bytes",
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._verify_retained_lifecycle_rearm_descriptor_lineage(
            reference, evidence, expected_uid=os.geteuid()
        ),
        "descriptor lineage changed",
    )


def _exercise_successor_release_identity_contract(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "successor-dual-release-replay"
    releases = fixture / "releases"
    releases.mkdir(parents=True, mode=0o700)
    executor = releases / ("a" * 64)
    historical = releases / ("b" * 64)
    executor.mkdir(mode=0o700)
    historical.mkdir(mode=0o700)
    calls: list[tuple[str, Path]] = []

    def verify_executor(release: Path, *, owner_uid: int) -> dict[str, object]:
        _expect(
            release == executor and owner_uid == os.geteuid(),
            "dual-release replay did not self-verify its running executor",
        )
        calls.append(("executor", release))
        return {"release_digest": executor.name}

    def verify_historical(release: Path, *, owner_uid: int) -> dict[str, object]:
        _expect(
            release == historical and owner_uid == os.geteuid(),
            "dual-release replay did not separately verify its retained client",
        )
        calls.append(("historical", release))
        return {"release_digest": historical.name}

    with (
        mock.patch.object(bridge, "ROOT", executor),
        mock.patch.object(
            bridge,
            "_verify_availability_client_release",
            side_effect=verify_executor,
        ),
        mock.patch.object(
            bridge,
            "_verify_historical_availability_release",
            side_effect=verify_historical,
        ),
    ):
        pair = bridge._verify_successor_release_pair(
            historical, owner_uid=os.geteuid()
        )
    _expect(
        calls == [("executor", executor), ("historical", historical)]
        and pair
        == {
            "executor_release": str(executor),
            "executor_release_digest": executor.name,
            "client_release": str(historical),
            "client_release_digest": historical.name,
            "historical_client": True,
        },
        "dual-release replay collapsed executor and client identity",
    )

    outer_rearm = {
        "journal": str(fixture / "lifecycle-predecessor-rearm.json"),
        "journal_document_sha256": "c" * 64,
    }
    binding = {
        "client_release": str(historical),
        "client_release_digest": historical.name,
        "maintenance_handoff": {
            "predecessor_proof": {"outer_rearm": outer_rearm}
        },
    }
    current = {
        "binding": binding,
        "predecessor": {"ready_proof": {"outer_rearm": outer_rearm}},
        "phase": "predecessor-dropin-remove-intent",
    }
    retained = json.loads(json.dumps(current))
    _expect_bridge_error(
        bridge,
        lambda: bridge._authorize_successor_release_pair(
            current,
            requested_binding=binding,
            release_pair=pair,
            inherited_journal_sha256=None,
            inherited_document_sha256=None,
        ),
        "historical client requires its exact journaled executor rescue",
    )
    _expect(
        current == retained,
        "rejected historical-client execution changed the inherited binding",
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._authorize_successor_release_pair(
            None,
            requested_binding=binding,
            release_pair=pair,
            inherited_journal_sha256=None,
            inherited_document_sha256=None,
        ),
        "historical client requires its exact journaled executor rescue",
    )
    changed_binding = {**binding, "wait_seconds": 6}
    _expect_bridge_error(
        bridge,
        lambda: bridge._authorize_successor_release_pair(
            current,
            requested_binding=changed_binding,
            release_pair=pair,
            inherited_journal_sha256=None,
            inherited_document_sha256=None,
        ),
        "historical client requires its exact journaled executor rescue",
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._authorize_successor_release_pair(
            current,
            requested_binding=binding,
            release_pair=pair,
            inherited_journal_sha256="d" * 64,
            inherited_document_sha256="e" * 64,
        ),
        "historical client requires its exact journaled executor rescue",
    )
    executor_pair = {
        **pair,
        "client_release": str(executor),
        "client_release_digest": executor.name,
        "historical_client": False,
    }
    _expect_bridge_error(
        bridge,
        lambda: bridge._authorize_successor_release_pair(
            current,
            requested_binding={
                **binding,
                "client_release": str(executor),
                "client_release_digest": executor.name,
            },
            release_pair=executor_pair,
            inherited_journal_sha256=None,
            inherited_document_sha256=None,
        ),
        "journal-bound client release",
    )
    bridge._authorize_successor_release_pair(
        current,
        requested_binding={
            **binding,
            "client_release": str(executor),
            "client_release_digest": executor.name,
        },
        release_pair=executor_pair,
        inherited_journal_sha256="d" * 64,
        inherited_document_sha256="e" * 64,
    )
    bridge._authorize_successor_release_pair(
        None,
        requested_binding={
            **binding,
            "client_release": str(executor),
            "client_release_digest": executor.name,
        },
        release_pair=executor_pair,
        inherited_journal_sha256=None,
        inherited_document_sha256=None,
    )


def _exercise_successor_owner_map_refresh_contract(
    bridge: ModuleType, root: Path
) -> None:
    fixture = root / "successor-owner-map-refresh"
    fixture.mkdir(mode=0o700)
    journal_path = fixture / "clean-successor-journal.json"
    operation_id = str(uuid.uuid4())
    map_operation_id = str(uuid.uuid4())
    source_generation = str(uuid.uuid4())
    target_generation = str(uuid.uuid4())
    actor = "cutover:schema12-owner-refresh-self-test"
    previous_revision = 93419
    refreshed_revision = 93421
    repositories = [
        {
            "repository_id": "repo-global-finance",
            "canonical_root": "/home/holyglory/GlobalFinance",
            "repository_generation": 7,
            "owner_uid": 1000,
        }
    ]

    def sealed_scope(revision: int) -> dict[str, object]:
        unsigned: dict[str, object] = {
            "schema_version": 1,
            "kind": "devcoordinator-repository-execution-scope",
            "authority_schema_version": 12,
            "database_generation": source_generation,
            "state_revision": revision,
            "migration_state": "ready",
            "repository_count": 1,
            "executable_repository_count": 1,
            "excluded_terminal_repository_count": 0,
            "repository_universe_sha256": "sha256:" + "1" * 64,
            "executable_repositories_sha256": "sha256:" + "2" * 64,
            "excluded_terminal_repositories_sha256": "sha256:" + "3" * 64,
            "executable_repositories": [{"repository_id": "repo-global-finance"}],
            "excluded_terminal_repositories": [],
        }
        return {
            **unsigned,
            "document_sha256": "sha256:"
            + hashlib.sha256(bridge._canonical(unsigned)).hexdigest(),
        }

    def sealed_owner_map(
        name: str,
        revision: int,
        *,
        operation: str = map_operation_id,
        map_actor: str = actor,
        target: str = target_generation,
        rows: list[dict[str, object]] | None = None,
    ) -> tuple[Path, dict[str, object], dict[str, object]]:
        unsigned: dict[str, object] = {
            "schema_version": 3,
            "kind": "devcoordinator-repository-owner-authority-map",
            "operation_id": operation,
            "actor": map_actor,
            "created_at": (
                "2026-07-29T00:00:00.000Z"
                if revision == previous_revision
                else "2026-07-29T00:01:00.000Z"
            ),
            "source_database_generation": source_generation,
            "target_database_generation": target,
            "source_schema_version": 12,
            "source_state_revision": revision,
            "repository_execution_scope": sealed_scope(revision),
            "repositories": copy.deepcopy(repositories if rows is None else rows),
        }
        document = {
            **unsigned,
            "document_sha256": "sha256:"
            + hashlib.sha256(bridge._canonical(unsigned)).hexdigest(),
        }
        path = fixture / name
        path.write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        reference = bridge._sealed_owner_map_reference(
            path,
            owner_map_sha256=raw_sha256,
            expected_uid=os.geteuid(),
        )
        return path, document, reference

    _previous_path, previous_document, previous_reference = sealed_owner_map(
        "owner-map.previous.json", previous_revision
    )
    _refreshed_path, refreshed_document, refreshed_reference = sealed_owner_map(
        "owner-map.refreshed.json", refreshed_revision
    )
    maintenance_handoff = {
        "database_generation": source_generation,
        "attestation_document_sha256": "4" * 64,
        "preclear_readiness": {
            "invariants": {
                "schema_version": 12,
                "database_generation": source_generation,
                "state_revision": previous_revision,
            }
        },
    }
    binding = {
        "candidate_release": str(fixture / "candidate"),
        "client_release": str(fixture / "historical-client"),
        "owner_map": previous_reference,
        "maintenance_handoff": maintenance_handoff,
        "maintenance": {"fixture": "active"},
        "wait_seconds": 30,
    }
    profile = {
        "before_identity": {"fixture": "profile"},
        "backup": str(fixture / "profile.backup"),
        "backup_sha256": "5" * 64,
        "owner_binding": previous_reference,
        "owner_binding_sha256": previous_reference["document_sha256"],
        "repaired_payload_sha256": None,
        "after_identity": None,
        "restored_identity": None,
    }
    current = bridge._successor_journal(
        journal_path,
        {
            "operation_id": operation_id,
            "binding": binding,
            "predecessor": {"fixture": "retired"},
            "profile": profile,
            "candidate": {"activation": None, "readiness": None},
            "restored_predecessor": None,
            "phase": "predecessor-retired",
            "error": None,
            "created_at_epoch": 1,
            "updated_at_epoch": 1,
        },
        uid=os.geteuid(),
    )
    requested_binding = copy.deepcopy(binding)
    requested_binding["owner_map"] = refreshed_reference
    release_pair = {"historical_client": True}
    with mock.patch.object(bridge, "_ensure_successor_maintenance"):
        refreshed = bridge._refresh_inherited_lifecycle_owner_map(
            current,
            requested_binding=requested_binding,
            release_pair=release_pair,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        )
    _expect(refreshed is not None, "owner-map refresh returned no journal")
    retained = bridge._load_successor_journal(journal_path, uid=os.geteuid())
    _expect(
        retained == refreshed
        and refreshed["operation_id"] == operation_id
        and refreshed["phase"] == "predecessor-retired"
        and refreshed["binding"]["owner_map"] == refreshed_reference
        and refreshed["profile"]["owner_binding"] == refreshed_reference
        and refreshed["profile"]["owner_binding_sha256"]
        == refreshed_reference["document_sha256"]
        and {
            key: value
            for key, value in refreshed["binding"].items()
            if key != "owner_map"
        }
        == {key: value for key, value in binding.items() if key != "owner_map"},
        "owner-map refresh did not atomically preserve and reseal the successor",
    )
    refresh_record = refreshed["profile"].get("owner_binding_refresh")
    _expect(
        isinstance(refresh_record, dict)
        and refresh_record["previous"] == previous_reference
        and refresh_record["refreshed"] == refreshed_reference
        and refresh_record["previous_source_state_revision"] == previous_revision
        and refresh_record["refreshed_source_state_revision"] == refreshed_revision
        and refresh_record["lifecycle_preclear_state_revision"]
        == previous_revision
        and previous_document["operation_id"] == refreshed_document["operation_id"]
        == map_operation_id
        and previous_document["actor"] == refreshed_document["actor"] == actor
        and previous_document["target_database_generation"]
        == refreshed_document["target_database_generation"]
        == target_generation,
        "owner-map refresh lost its lifecycle or static-map lineage",
    )
    replay_raw_sha256 = hashlib.sha256(journal_path.read_bytes()).hexdigest()
    with mock.patch.object(bridge, "_ensure_successor_maintenance"):
        replayed = bridge._refresh_inherited_lifecycle_owner_map(
            refreshed,
            requested_binding=requested_binding,
            release_pair=release_pair,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        )
    _expect(
        replayed == refreshed
        and hashlib.sha256(journal_path.read_bytes()).hexdigest()
        == replay_raw_sha256,
        "owner-map refresh replay rewrote retained evidence",
    )
    malformed_replay = copy.deepcopy(refreshed)
    malformed_replay["profile"]["owner_binding_refresh"]["previous"] = None
    _expect_bridge_error(
        bridge,
        lambda: bridge._refresh_inherited_lifecycle_owner_map(
            malformed_replay,
            requested_binding=requested_binding,
            release_pair=release_pair,
            journal_path=journal_path,
            expected_uid=os.geteuid(),
        ),
        "retained owner-map refresh lineage is invalid",
    )

    for name, changes in (
        ("actor", {"map_actor": "cutover:changed-actor"}),
        ("operation", {"operation": str(uuid.uuid4())}),
        ("target", {"target": str(uuid.uuid4())}),
        (
            "owner",
            {
                "rows": [
                    {
                        **repositories[0],
                        "owner_uid": 1001,
                    }
                ]
            },
        ),
    ):
        _path, _document, changed_reference = sealed_owner_map(
            f"owner-map.changed-{name}.json",
            refreshed_revision,
            **changes,
        )
        _expect_bridge_error(
            bridge,
            lambda changed_reference=changed_reference: (
                bridge._verified_owner_map_refresh_relation(
                    previous_reference=previous_reference,
                    refreshed_reference=changed_reference,
                    maintenance_handoff=maintenance_handoff,
                    expected_uid=os.geteuid(),
                )
            ),
            "changed more than its lifecycle-bound revision",
        )

    _expect_bridge_error(
        bridge,
        lambda: bridge._verified_owner_map_refresh_relation(
            previous_reference=previous_reference,
            refreshed_reference=previous_reference,
            maintenance_handoff=maintenance_handoff,
            expected_uid=os.geteuid(),
        ),
        "distinct evidence path",
    )
    wrong_handoff = copy.deepcopy(maintenance_handoff)
    wrong_handoff["preclear_readiness"]["invariants"]["state_revision"] = (
        previous_revision - 1
    )
    _expect_bridge_error(
        bridge,
        lambda: bridge._verified_owner_map_refresh_relation(
            previous_reference=previous_reference,
            refreshed_reference=refreshed_reference,
            maintenance_handoff=wrong_handoff,
            expected_uid=os.geteuid(),
        ),
        "changed more than its lifecycle-bound revision",
    )
    changed_requested = copy.deepcopy(requested_binding)
    changed_requested["wait_seconds"] = 31
    with mock.patch.object(bridge, "_ensure_successor_maintenance"):
        _expect_bridge_error(
            bridge,
            lambda: bridge._refresh_inherited_lifecycle_owner_map(
                current,
                requested_binding=changed_requested,
                release_pair=release_pair,
                journal_path=journal_path,
                expected_uid=os.geteuid(),
            ),
            "pre-export owner-map refresh",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._refresh_inherited_lifecycle_owner_map(
                {**current, "phase": "profile-repaired"},
                requested_binding=requested_binding,
                release_pair=release_pair,
                journal_path=journal_path,
                expected_uid=os.geteuid(),
            ),
            "pre-export owner-map refresh",
        )
        _expect_bridge_error(
            bridge,
            lambda: bridge._refresh_inherited_lifecycle_owner_map(
                current,
                requested_binding=requested_binding,
                release_pair={"historical_client": False},
                journal_path=journal_path,
                expected_uid=os.geteuid(),
            ),
            "pre-export owner-map refresh",
        )


def _exercise_retired_rescue_sqlite_timestamp_contract(
    bridge: ModuleType, root: Path
) -> None:
    case = root / "retired-rescue-sqlite-timestamps"
    case.mkdir(mode=0o700)

    def evidence(
        path: Path, *, inode: int, size: int, digest: str
    ) -> dict[str, object]:
        return {
            "path": str(path),
            "device": 7,
            "inode": inode,
            "size": size,
            "mtime_ns": 19,
            "ctime_ns": 23,
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "mode": 0o600,
            "nlink": 1,
            "sha256": digest,
        }

    database = case / "authority.sqlite3"
    sealed_bundle = {
        "main": evidence(
            database, inode=11, size=4096, digest="1" * 64
        ),
        "sidecars": {
            "-wal": evidence(
                Path(str(database) + "-wal"),
                inode=13,
                size=0,
                digest=hashlib.sha256(b"").hexdigest(),
            ),
            "-shm": evidence(
                Path(str(database) + "-shm"),
                inode=17,
                size=32768,
                digest="2" * 64,
            ),
        },
    }
    live_bundle = copy.deepcopy(sealed_bundle)
    live_bundle["sidecars"]["-wal"]["ctime_ns"] += 101
    live_bundle["sidecars"]["-shm"]["mtime_ns"] += 103
    live_bundle["sidecars"]["-shm"]["ctime_ns"] += 107
    _expect(
        bridge._retired_rescue_sqlite_bundle_view(live_bundle)
        == bridge._retired_rescue_sqlite_bundle_view(sealed_bundle),
        "executor rescue did not ignore only WAL/SHM timestamp drift",
    )

    profile_identity = {"fixture": "profile"}
    broker_state = {
        "ActiveState": "inactive",
        "SubState": "dead",
        "MainPID": 0,
    }
    handoff = {
        "phase": "predecessor-retired",
        "profile_identity": profile_identity,
        "profile_backup": {"fixture": "backup"},
        "readiness_attestation": {"fixture": "readiness"},
        "database_bundle": sealed_bundle,
        "broker_state": broker_state,
        "predecessor_dropin": {"state": "absent"},
    }
    current = {
        "phase": "predecessor-retired",
        "binding": {
            "client_release_handoffs": [handoff],
            "candidate_transaction": str(case / "candidate"),
            "maintenance": {"fixture": "maintenance"},
            "readiness_attestation": str(case / "readiness.json"),
        },
        "profile": {"fixture": "profile-state"},
        "candidate": {"activation": None, "readiness": None},
    }
    state = {"bundle": live_bundle}
    arguments = {
        "terminal_path": case / "terminal.json",
        "completion_path": case / "completion.json",
        "database": database,
        "profile": case / "client-profiles.json",
        "broker_socket": case / "broker.sock",
        "dropin": case / "bridge.conf",
        "expected_uid": os.geteuid(),
    }
    with (
        mock.patch.object(
            bridge,
            "_validated_successor_client_handoff",
            side_effect=lambda value, **_kwargs: value,
        ),
        mock.patch.object(bridge, "_ensure_successor_maintenance"),
        mock.patch.object(
            bridge, "_verify_successor_client_handoff_dropin_boundary"
        ),
        mock.patch.object(
            bridge, "_verify_successor_profile_backup_reference"
        ),
        mock.patch.object(
            bridge, "_verify_successor_readiness_attestation_reference"
        ),
        mock.patch.object(
            bridge, "_profile_identity", return_value=profile_identity
        ),
        mock.patch.object(
            bridge,
            "_sqlite_bundle_evidence",
            side_effect=lambda *_args, **_kwargs: copy.deepcopy(
                state["bundle"]
            ),
        ),
        mock.patch.object(
            bridge, "_systemd_state", return_value=broker_state
        ),
    ):
        _expect_bridge_error(
            bridge,
            lambda: bridge._verify_successor_client_handoff_live_state(
                current, **arguments
            ),
            "live state changed",
        )
        bridge._verify_successor_client_handoff_live_state(
            current,
            **arguments,
            _allow_retired_sidecar_timestamp_drift=True,
        )

        stable_sidecar_fields = (
            "path",
            "sha256",
            "device",
            "inode",
            "size",
            "uid",
            "gid",
            "mode",
            "nlink",
        )
        for suffix in ("-wal", "-shm"):
            for field in stable_sidecar_fields:
                changed = copy.deepcopy(live_bundle)
                value = changed["sidecars"][suffix][field]
                changed["sidecars"][suffix][field] = (
                    f"{value}.changed"
                    if isinstance(value, str)
                    else int(value) + 1
                )
                state["bundle"] = changed
                _expect_bridge_error(
                    bridge,
                    lambda: bridge._verify_successor_client_handoff_live_state(
                        current,
                        **arguments,
                        _allow_retired_sidecar_timestamp_drift=True,
                    ),
                    "live state changed",
                )
        for field in ("mtime_ns", "ctime_ns"):
            changed = copy.deepcopy(live_bundle)
            changed["main"][field] += 1
            state["bundle"] = changed
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_successor_client_handoff_live_state(
                    current,
                    **arguments,
                    _allow_retired_sidecar_timestamp_drift=True,
                ),
                "live state changed",
            )
        for suffix in ("-wal", "-shm"):
            changed = copy.deepcopy(live_bundle)
            changed["sidecars"][suffix] = None
            state["bundle"] = changed
            _expect_bridge_error(
                bridge,
                lambda: bridge._verify_successor_client_handoff_live_state(
                    current,
                    **arguments,
                    _allow_retired_sidecar_timestamp_drift=True,
                ),
                "live state changed",
            )


def _run_contract() -> None:
    bridge = _load_bridge()
    temporary = Path(tempfile.mkdtemp(prefix="devcoordinator-schema12-bridge-test."))
    temporary.chmod(0o700)
    try:
        _exercise_bounded_failure_diagnostic(bridge, temporary)
        _exercise_crash_loop_descendant_restore(bridge, temporary)
        _exercise_handoff_cli_contract(bridge)
        _exercise_successor_executor_rescue_cli_contract(bridge)
        _exercise_successor_executor_handoff_cli_contract(bridge)
        _exercise_post_export_executor_continuation_cli_contract(bridge)
        _exercise_post_export_executor_substitution_rejection(
            bridge, temporary
        )
        _exercise_post_export_successor_candidate_phase_contract(
            bridge, temporary
        )
        _exercise_inventory_canary_binding(bridge, temporary)
        _exercise_internal_cutover_inventory_contract(bridge, temporary)
        _exercise_cutover_current_client_loader_contract(bridge)
        _exercise_clean_successor_canary_phase_contract(bridge, temporary)
        _exercise_activate_internal_current_client_contract(
            bridge, temporary
        )
        _exercise_executor_rescue_candidate_journal_contract(
            bridge, temporary
        )
        _exercise_exact_execution_contract(bridge, temporary)
        _exercise_live_ready_verifier(bridge, temporary)
        _exercise_owner_bound_profile_export(bridge, temporary)
        _exercise_successor_handoff_and_dual_canary_contract(bridge, temporary)
        _exercise_successor_terminal_binding_contract(bridge, temporary)
        _exercise_successor_failpoint_replay(bridge, temporary)
        _exercise_policy_recovery_evidence_contract(bridge, temporary)
        _exercise_restored_policy_predecessor_contract(bridge, temporary)
        _exercise_lifecycle_quiesce_cli_contract(bridge)
        _exercise_lifecycle_historical_executor_split(bridge, temporary)
        _exercise_lifecycle_successor_producer_split_contract(bridge)
        _exercise_lifecycle_quiesce_transaction_contract(bridge, temporary)
        _exercise_policy_recovery_cli_contract(bridge)
        _exercise_policy_recovery_transaction_contract(bridge, temporary)
        _exercise_lifecycle_dropin_payload_compatibility(bridge, temporary)
        _exercise_restored_active_proof_uses_outer_rearm(bridge, temporary)
        _exercise_successor_release_identity_contract(bridge, temporary)
        _exercise_successor_owner_map_refresh_contract(bridge, temporary)
        _exercise_retired_rescue_sqlite_timestamp_contract(
            bridge, temporary
        )
        _exercise_successor_predecessor_sha_replay_repair(bridge, temporary)
        _exercise_retired_predecessor_absent_dropin_reference(
            bridge, temporary
        )
        _exercise_rearm_descriptor_inode_replacement_contract(
            bridge, temporary
        )
        _exercise_lifecycle_restored_rearm_contract(bridge, temporary)
        _exercise_descendant_retry_contract(bridge, temporary)
        _exercise_fresh_predecessor_contract(bridge, temporary)
        _exercise_successor_readiness_lineage_contract(bridge, temporary)
        _exercise_successor_predecessor_cache_replay_contract(
            bridge, temporary
        )
        _exercise_immutable_readiness(bridge, temporary)
        repository, commit = _fixture_repository(temporary)
        _exercise_default_release_visibility(bridge, temporary, repository, commit)
        scripts = repository / SOURCE_PREFIX

        # Dirty source must never enter the bridge release.  In particular, a
        # dirty schema-13 working copy must not alter a requested schema-12 Git
        # object.
        _write(
            scripts / "devcoordinator/schema.py",
            "SCHEMA_VERSION = 13\n",
            mode=0o644,
        )
        _write(scripts / "committed-marker.txt", "dirty-worktree!!\n", mode=0o644)

        release_root = temporary / "releases"
        first = bridge.stage_release(
            repo=repository,
            commit=commit,
            release_root=release_root,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        _expect(first.get("ok") is True, "schema-12 stage did not succeed")
        _expect(first.get("created") is True, "first stage was not a new release")
        _expect(first.get("git_commit") == commit, "release is not bound to the commit")

        release = Path(str(first["release"]))
        verified = bridge.verify_release(release, release_root=release_root)
        _expect(
            verified.get("authority_schema_version") == 12,
            "release did not retain the schema-12 contract",
        )
        marker = release / SOURCE_PREFIX / "committed-marker.txt"
        schema = release / SOURCE_PREFIX / "devcoordinator/schema.py"
        _expect(
            marker.read_text(encoding="utf-8") == "committed-marker\n",
            "dirty marker bytes entered the immutable release",
        )
        _expect(
            schema.read_text(encoding="utf-8") == "SCHEMA_VERSION = 12\n",
            "dirty schema bytes entered the immutable release",
        )
        _exercise_unsealed_bytecode_rejected(bridge, release)
        _expect(
            stat.S_IMODE(release.stat().st_mode) == 0o555,
            "release directory is not immutable",
        )
        _expect(
            stat.S_IMODE(marker.stat().st_mode) == 0o444,
            "non-executable release file is not immutable",
        )
        _expect(
            stat.S_IMODE(
                (release / SOURCE_PREFIX / "dev_coordinator.py").stat().st_mode
            )
            == 0o555,
            "executable release entry lost its immutable executable mode",
        )

        replay = bridge.stage_release(
            repo=repository,
            commit=commit,
            release_root=release_root,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        _expect(replay.get("created") is False, "exact release replay was not idempotent")
        _expect(replay.get("release") == str(release), "release replay changed identity")
        _expect(
            replay.get("release_digest") == first.get("release_digest"),
            "release replay changed its content digest",
        )

        original = marker.read_bytes()
        marker.chmod(0o644)
        marker.write_bytes(b"x" * len(original))
        marker.chmod(0o444)
        _expect_bridge_error(
            bridge,
            lambda: bridge.verify_release(release, release_root=release_root),
            "legacy release file changed",
        )

        # The same builder must not accept a newly committed schema-13 tree.
        _run("/usr/bin/git", "add", "--all", cwd=repository)
        _run(
            "/usr/bin/git",
            "commit",
            "--quiet",
            "--message",
            "schema-13 fixture",
            cwd=repository,
        )
        schema13_commit = _run("/usr/bin/git", "rev-parse", "HEAD", cwd=repository)
        _expect_bridge_error(
            bridge,
            lambda: bridge.stage_release(
                repo=repository,
                commit=schema13_commit,
                release_root=temporary / "schema13-releases",
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            ),
            "not an exact schema-12 broker",
        )
    finally:
        _make_tree_removable(temporary)
        shutil.rmtree(temporary)


def main() -> int:
    _run_contract()
    print("schema-12 legacy broker bridge self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
