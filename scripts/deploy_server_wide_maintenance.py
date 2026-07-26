#!/usr/bin/env python3
"""Deploy one offline server-wide Coordinator upgrade with verified rollback."""

from __future__ import annotations

import argparse
from contextlib import suppress
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "skills/codex-dev-coordinator/scripts"
if str(MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.maintenance import (  # noqa: E402
    MAINTENANCE_ROOT,
    activate_maintenance,
    clear_maintenance,
)


BROKER_UNIT = "devcoordinator-broker.service"
API_UNIT = "dev-coordinator.service"
CONSOLE_UNIT = "devops-console.service"
DATABASE = Path("/var/lib/devcoordinator/coordinator.sqlite3")
PROFILE = Path("/etc/devcoordinator/client-profiles.json")
BROKER_SOCKET = Path("/run/devcoordinator/broker.sock")
DEPLOY_LOCK = Path("/run/devcoordinator-deploy.lock")
CLIENT_GROUP = "devcoordinator-clients"
SCHEMA_BEFORE = 9
SCHEMA_AFTER = 12
CONSOLE_SERVER_ID = "144ba3fb-9939-5a81-91b1-f1bb3a5db418"


class DeploymentError(RuntimeError):
    pass


def _json_write(path: Path, document: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.repository = Path(args.repository).resolve(strict=True)
        self.transaction = Path(args.transaction_dir)
        self.token_file = Path(args.token_file)
        self.console_env_file = Path(args.console_env_file)
        self.deployment_id = str(uuid.UUID(args.deployment_id))
        self.group_gid = grp.getgrnam(CLIENT_GROUP).gr_gid
        self.phase = "initializing"
        self.install_transaction = self.transaction / "server-wide-install"
        self.raw_checkpoint = self.transaction / "writer-free-database"
        self.command_index = 0
        self.marker_active = False
        self.checkout_changed = False
        self.database_captured = False
        self.installer_applied = False
        self.units_captured = False

    def journal(self, **extra: Any) -> None:
        _json_write(
            self.transaction / "deployment.json",
            {
                "version": 1,
                "deployment_id": self.deployment_id,
                "phase": self.phase,
                "repository": str(self.repository),
                "target_commit": self.args.target_commit,
                "rollback_ref": self.args.rollback_ref,
                "marker_active": self.marker_active,
                "checkout_changed": self.checkout_changed,
                "database_captured": self.database_captured,
                "installer_applied": self.installer_applied,
                "units_captured": self.units_captured,
                **extra,
            },
        )

    def run(
        self, arguments: list[str], *, timeout: float = 120, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        self.command_index += 1
        completed = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        _json_write(
            self.transaction / f"command-{self.command_index:03d}.json",
            {
                "argv": arguments,
                "returncode": completed.returncode,
                "stdout": completed.stdout[-200_000:],
                "stderr": completed.stderr[-200_000:],
            },
        )
        if check and completed.returncode:
            raise DeploymentError(
                f"command failed ({' '.join(arguments)}): "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        return completed

    def git(self, *arguments: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
        return self.run(
            [
                "/usr/bin/git",
                "-c",
                f"safe.directory={self.repository}",
                "-C",
                str(self.repository),
                *arguments,
            ],
            timeout=timeout,
        )

    def schema_evidence(self, *, expected: int) -> dict[str, Any]:
        connection = sqlite3.connect(
            f"file:{DATABASE}?mode=ro", uri=True, isolation_level=None, timeout=5
        )
        try:
            connection.execute("PRAGMA query_only = ON")
            integrity = connection.execute("PRAGMA integrity_check").fetchall()
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            metadata = connection.execute(
                "SELECT schema_version, database_generation FROM schema_metadata "
                "WHERE singleton = 1"
            ).fetchone()
            running = connection.execute(
                "SELECT operation_id, kind, status FROM operations "
                "WHERE status IN ('planned', 'running') "
                "ORDER BY operation_id"
            ).fetchall()
        finally:
            connection.close()
        if metadata is None or int(metadata[0]) != expected:
            raise DeploymentError(
                f"Coordinator schema is {metadata[0] if metadata else 'missing'}, expected {expected}"
            )
        if integrity != [("ok",)] or foreign_keys:
            raise DeploymentError("Coordinator database integrity proof failed")
        if running:
            raise DeploymentError(
                f"Coordinator has non-terminal operations: {running!r}"
            )
        return {
            "schema_version": int(metadata[0]),
            "database_generation": str(metadata[1]),
            "running_operations": 0,
            "integrity_check": "ok",
            "foreign_key_check": "ok",
        }

    def require_no_database_helpers(self) -> None:
        findings: list[dict[str, Any]] = []
        for raw in Path("/proc").iterdir():
            if not raw.name.isdigit():
                continue
            try:
                payload = (raw / "cmdline").read_bytes()[:131_072]
            except OSError:
                continue
            arguments = [item.decode("utf-8", "replace") for item in payload.split(b"\0") if item]
            executables = {Path(argument).name for argument in arguments}
            if executables.intersection({"pg_dump", "pg_restore"}):
                findings.append({"pid": int(raw.name), "argv": arguments})
        if findings:
            raise DeploymentError(
                f"PostgreSQL backup/restore helper is still active: {findings!r}"
            )

    def unit_state(self, unit: str) -> dict[str, Any]:
        completed = self.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--property=ActiveState,SubState,MainPID,ControlGroup",
                unit,
            ]
        )
        values: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
        return values

    def require_active(self, unit: str) -> dict[str, Any]:
        state = self.unit_state(unit)
        if state.get("ActiveState") != "active" or int(state.get("MainPID", "0")) <= 0:
            raise DeploymentError(f"{unit} is not active with an exact MainPID: {state}")
        return state

    def wait_inactive(self, unit: str, *, timeout: float = 120) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.unit_state(unit)
            if state.get("ActiveState") in {"inactive", "failed"} and int(
                state.get("MainPID", "0")
            ) == 0:
                return
            time.sleep(0.2)
        raise DeploymentError(f"{unit} did not reach a stopped boundary")

    def public_get(
        self, url: str, *, require_correct_upstream_protocol: bool = True
    ) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": "DevCoordinator-deploy/1"})
        try:
            with urllib.request.urlopen(
                request, timeout=15, context=ssl.create_default_context()
            ) as response:
                body = response.read(1_000_000)
                status = int(response.status)
                final_url = response.geturl()
        except urllib.error.HTTPError as error:
            body = error.read(1_000_000)
            status = int(error.code)
            final_url = error.geturl()
        if status >= 500:
            raise DeploymentError(f"public route {url} returned {status}")
        if (
            require_correct_upstream_protocol
            and b"Client sent an HTTP request to an HTTPS server" in body
        ):
            raise DeploymentError(f"public route {url} still uses the wrong upstream protocol")
        return {"url": url, "final_url": final_url, "status": status, "bytes": len(body)}

    def prepare_maintenance_root(self) -> None:
        try:
            metadata = MAINTENANCE_ROOT.lstat()
        except FileNotFoundError:
            MAINTENANCE_ROOT.mkdir(mode=0o750)
            os.chown(MAINTENANCE_ROOT, 0, self.group_gid)
            os.chmod(MAINTENANCE_ROOT, 0o750)
            metadata = MAINTENANCE_ROOT.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != self.group_gid
            or stat.S_IMODE(metadata.st_mode) != 0o750
        ):
            raise DeploymentError(
                "broker-independent maintenance directory has an unsafe identity"
            )

    def inventory(self, name: str) -> dict[str, Any]:
        if not self.token_file.is_absolute() or ".." in self.token_file.parts:
            raise DeploymentError("Coordinator API token path must be absolute")
        metadata = self.token_file.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > 16 * 1024
        ):
            raise DeploymentError("Coordinator API token file is unsafe")
        descriptor = os.open(
            self.token_file,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise DeploymentError("Coordinator API token changed while opening")
            payload = os.read(descriptor, 16 * 1024 + 1)
        finally:
            os.close(descriptor)
        token = payload.decode("utf-8").strip()
        if not token:
            raise DeploymentError("Coordinator API token is empty")
        request = urllib.request.Request(
            "http://127.0.0.1:29876/v1/inventory/no-docker",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise DeploymentError(
                    f"authenticated inventory returned {response.status}"
                )
            document = json.loads(response.read(8 * 1024 * 1024))
        _json_write(self.transaction / name, document)
        return document

    def online_backup(self) -> Path:
        root = self.transaction / "online-schema-9-backup"
        root.mkdir(mode=0o700)
        completed = self.run(
            [
                "/usr/bin/python3",
                str(
                    self.repository
                    / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
                ),
                "broker",
                "store-backup",
                "--database",
                str(DATABASE),
                "--store-role",
                "service",
                "--output-root",
                str(root),
            ],
            timeout=120,
        )
        try:
            result = json.loads(completed.stdout)
            manifest = Path(result["manifest"])
            document = json.loads(manifest.read_text(encoding="utf-8"))
            artifact = Path(document["artifact_path"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, OSError) as error:
            raise DeploymentError("online backup did not return a readable manifest") from error
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact_metadata = artifact.lstat()
        manifest_metadata = manifest.lstat()
        if (
            stat.S_ISLNK(artifact_metadata.st_mode)
            or not stat.S_ISREG(artifact_metadata.st_mode)
            or artifact_metadata.st_uid != 0
            or stat.S_IMODE(artifact_metadata.st_mode) != 0o600
            or stat.S_ISLNK(manifest_metadata.st_mode)
            or not stat.S_ISREG(manifest_metadata.st_mode)
            or manifest_metadata.st_uid != 0
            or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
            or document.get("type") != "devcoordinator-sqlite-backup"
            or document.get("store_role") != "service"
            or document.get("schema_version") != SCHEMA_BEFORE
            or document.get("verification", {}).get("status") != "verified"
            or document.get("artifact_sha256") != digest
            or document.get("artifact_size_bytes") != artifact.stat().st_size
        ):
            raise DeploymentError("online schema-9 backup manifest verification failed")
        return manifest

    def capture_units(self) -> None:
        destination = self.transaction / "system-units-before"
        destination.mkdir(mode=0o700)
        documents: dict[str, Any] = {}
        for name in (API_UNIT, CONSOLE_UNIT):
            source = Path("/etc/systemd/system") / name
            metadata = source.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise DeploymentError(f"installed unit is not a regular file: {source}")
            payload = source.read_bytes()
            target = destination / name
            target.write_bytes(payload)
            target.chmod(0o600)
            documents[name] = {
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        _json_write(destination / "manifest.json", documents)
        self.units_captured = True
        self.journal()

    def install_console_units(self) -> None:
        for name in (API_UNIT, CONSOLE_UNIT):
            source = self.repository / "apps/DevOpsConsole/deploy" / name
            self.run(
                [
                    "/usr/bin/install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0644",
                    str(source),
                    "/etc/systemd/system/",
                ]
            )
        self.run(["/usr/bin/systemctl", "daemon-reload"])

    def restore_console_units(self) -> None:
        if not self.units_captured:
            return
        source_root = self.transaction / "system-units-before"
        for name in (API_UNIT, CONSOLE_UNIT):
            self.run(
                [
                    "/usr/bin/install",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "-m",
                    "0644",
                    str(source_root / name),
                    "/etc/systemd/system/",
                ]
            )
        self.run(["/usr/bin/systemctl", "daemon-reload"])

    def capture_database(self) -> None:
        self.raw_checkpoint.mkdir(mode=0o700)
        documents: dict[str, Any] = {}
        for source in (DATABASE, Path(f"{DATABASE}-wal"), Path(f"{DATABASE}-shm")):
            name = source.name
            if not os.path.lexists(source):
                documents[name] = {"present": False}
                continue
            metadata = source.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise DeploymentError(f"database checkpoint source is unsafe: {source}")
            payload = source.read_bytes()
            target = self.raw_checkpoint / name
            target.write_bytes(payload)
            target.chmod(0o600)
            with target.open("rb") as handle:
                os.fsync(handle.fileno())
            documents[name] = {
                "present": True,
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        if not documents.get(DATABASE.name, {}).get("present"):
            raise DeploymentError("writer-free checkpoint omitted the authority database")
        _json_write(self.raw_checkpoint / "manifest.json", documents)
        self.database_captured = True
        self.journal()

    def restore_database(self) -> None:
        if not self.database_captured:
            return
        documents = json.loads(
            (self.raw_checkpoint / "manifest.json").read_text(encoding="utf-8")
        )
        for target in (DATABASE, Path(f"{DATABASE}-wal"), Path(f"{DATABASE}-shm")):
            if os.path.lexists(target):
                metadata = target.lstat()
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise DeploymentError(f"database restore target is unsafe: {target}")
                target.unlink()
            record = documents[target.name]
            if not record["present"]:
                continue
            source = self.raw_checkpoint / target.name
            payload = source.read_bytes()
            if hashlib.sha256(payload).hexdigest() != record["sha256"]:
                raise DeploymentError(f"database checkpoint checksum drifted: {source}")
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                int(record["mode"]),
            )
            try:
                os.fchown(descriptor, int(record["uid"]), int(record["gid"]))
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, payload[written:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def checkout(self, ref: str) -> None:
        self.git("checkout", ref)

    def migrate(self) -> None:
        cli = self.repository / "skills/codex-dev-coordinator/scripts/dev_coordinator.py"
        arguments = [
            "/usr/bin/python3",
            "-I",
            str(cli),
            "broker",
            "migrate-profile-enrollments",
            "--database",
            str(DATABASE),
            "--profile",
            str(PROFILE),
        ]
        self.run(arguments, timeout=120)
        second = self.run(arguments, timeout=120)
        try:
            document = json.loads(second.stdout)
        except json.JSONDecodeError as error:
            raise DeploymentError("profile migration did not return JSON") from error
        if int(document.get("inserted", -1)) != 0:
            raise DeploymentError("profile migration is not idempotent")

    def installer(self, action: str) -> None:
        arguments = [
            "/usr/bin/python3",
            str(self.repository / "scripts/install_server_wide_coordinator.py"),
            "--json",
            action,
        ]
        for user in self.args.client_user:
            arguments.extend(("--client-user", user))
        if action == "apply":
            arguments.extend(("--transaction-dir", str(self.install_transaction)))
        self.run(arguments, timeout=300)

    def verify_services(self, *, inventory_name: str) -> dict[str, Any]:
        broker = self.require_active(BROKER_UNIT)
        api = self.require_active(API_UNIT)
        console = self.require_active(CONSOLE_UNIT)
        self.run(
            [
                "/usr/bin/python3",
                str(self.repository / "scripts/check_coordinator_auth_boundary.py"),
                "--token-file",
                str(self.token_file),
                "--host",
                "127.0.0.1",
                "--port",
                "29876",
            ],
            timeout=30,
        )
        inventory = self.inventory(inventory_name)
        if CONSOLE_SERVER_ID not in json.dumps(inventory, sort_keys=True):
            raise DeploymentError(
                "authenticated inventory omitted the exact Console server identity"
            )
        self.run(
            [
                "/usr/bin/python3",
                str(self.repository / "scripts/check_console_registration_ready.py"),
                "--unit",
                CONSOLE_UNIT,
                "--main-pid",
                str(console["MainPID"]),
                "--token-file",
                str(self.token_file),
                "--project",
                str(self.repository),
                "--name",
                "devops-console",
                "--port",
                "443",
                "--host",
                "127.0.0.1",
                "--coordinator-port",
                "29876",
                "--expected-executable",
                "/usr/bin/node",
                "--expected-script",
                "bin/devops-console.mjs",
                "--env-file",
                str(self.console_env_file),
                "--expected-working-directory",
                str(self.repository / "apps/DevOpsConsole"),
                "--wait-seconds",
                "20",
                "--poll-interval-seconds",
                "0.1",
            ],
            timeout=30,
        )
        return {"broker": broker, "api": api, "console": console, "inventory": inventory}

    def rollback(self, original_error: BaseException) -> None:
        failures: list[str] = []
        self.phase = "rolling-back"
        self.journal(original_error=f"{type(original_error).__name__}: {original_error}")

        def attempt(label: str, operation: Any) -> None:
            try:
                operation()
            except BaseException as error:
                failures.append(f"{label}: {type(error).__name__}: {error}")

        attempt(
            "stop broker",
            lambda: self.run(["/usr/bin/systemctl", "stop", "--no-block", BROKER_UNIT]),
        )
        attempt("wait broker stopped", lambda: self.wait_inactive(BROKER_UNIT))
        attempt("restore database", self.restore_database)
        if self.installer_applied:
            attempt(
                "rollback server-wide installer",
                lambda: self.run(
                    [
                        "/usr/bin/python3",
                        str(self.repository / "scripts/install_server_wide_coordinator.py"),
                        "--json",
                        "rollback",
                        "--transaction-dir",
                        str(self.install_transaction),
                    ],
                    timeout=300,
                ),
            )
        attempt("restore Console units", self.restore_console_units)
        attempt("checkout compatibility source", lambda: self.checkout(self.args.rollback_ref))
        attempt(
            "start compatible broker",
            lambda: self.run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=180),
        )
        attempt(
            "restart compatible API",
            lambda: self.run(["/usr/bin/systemctl", "restart", API_UNIT], timeout=90),
        )
        attempt(
            "restart compatible Console",
            lambda: self.run(["/usr/bin/systemctl", "restart", CONSOLE_UNIT], timeout=120),
        )
        if not failures:
            attempt(
                "verify compatible services",
                lambda: self.verify_services(
                    inventory_name="rollback-inventory.json"
                ),
            )
            attempt("verify rollback schema", lambda: self.schema_evidence(expected=SCHEMA_BEFORE))
        if not failures and self.marker_active:
            attempt(
                "clear maintenance marker after rollback",
                lambda: clear_maintenance(
                    expected_uid=0,
                    expected_gid=self.group_gid,
                    deployment_id=self.deployment_id,
                ),
            )
            if not failures:
                self.marker_active = False
        self.phase = "rollback-complete" if not failures else "rollback-failed"
        self.journal(rollback_failures=failures)
        if failures:
            raise DeploymentError(
                f"deployment failed: {original_error}; rollback also failed: {failures}"
            ) from original_error
        raise DeploymentError(
            f"deployment failed and verified rollback completed: {original_error}"
        ) from original_error

    def deploy(self) -> dict[str, Any]:
        if os.geteuid() != 0:
            raise DeploymentError("deployment requires the root host administrator")
        if self.transaction.exists() or self.transaction.is_symlink():
            raise DeploymentError("transaction directory must be one new absolute path")
        self.transaction.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.transaction.mkdir(mode=0o700)
        self.phase = "preflight"
        self.journal()
        if self.git("status", "--porcelain").stdout.strip():
            raise DeploymentError("canonical deployment checkout is dirty")
        current = self.git("rev-parse", "HEAD").stdout.strip()
        target = self.git("rev-parse", self.args.target_commit).stdout.strip()
        main = self.git("rev-parse", "main").stdout.strip()
        rollback = self.git("rev-parse", self.args.rollback_ref).stdout.strip()
        if current != rollback or target != main or target != self.args.target_commit:
            raise DeploymentError(
                "checkout/target/rollback refs do not match the approved exact commits"
            )
        pre_units = {
            unit: self.require_active(unit)
            for unit in (BROKER_UNIT, API_UNIT, CONSOLE_UNIT)
        }
        pre_schema = self.schema_evidence(expected=SCHEMA_BEFORE)
        self.require_no_database_helpers()
        self.inventory("pre-inventory.json")
        public_before = [
            self.public_get(url, require_correct_upstream_protocol=False)
            for url in self.args.public_url
        ]
        backup_manifest = self.online_backup()
        self.capture_units()
        self.prepare_maintenance_root()
        activate_maintenance(
            expected_uid=0,
            expected_gid=self.group_gid,
            deployment_id=self.deployment_id,
            message="Coordinator upgrade in progress; please wait a moment and retry.",
            retry_after_seconds=30,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self.marker_active = True
        self.phase = "maintenance-active"
        self.journal(
            pre_units=pre_units,
            pre_schema=pre_schema,
            public_before=public_before,
            online_backup_manifest=str(backup_manifest),
        )
        try:
            self.checkout("main")
            self.checkout_changed = True
            self.phase = "target-source-active"
            self.journal()
            self.run(["/usr/bin/systemctl", "stop", "--no-block", BROKER_UNIT])
            self.wait_inactive(BROKER_UNIT)
            if BROKER_SOCKET.exists() or BROKER_SOCKET.is_symlink():
                raise DeploymentError("broker socket remains after stopped boundary")
            self.schema_evidence(expected=SCHEMA_BEFORE)
            self.require_no_database_helpers()
            self.capture_database()
            self.phase = "writer-free-checkpoint"
            self.journal()
            self.migrate()
            migrated = self.schema_evidence(expected=SCHEMA_AFTER)
            self.installer("plan")
            self.installer("apply")
            self.installer_applied = True
            self.installer("verify")
            self.run(
                [
                    "/usr/bin/systemd-analyze",
                    "verify",
                    str(self.repository / "apps/DevOpsConsole/deploy/dev-coordinator.service"),
                    str(self.repository / "apps/DevOpsConsole/deploy/devops-console.service"),
                ],
                timeout=60,
            )
            self.install_console_units()
            self.run(
                [
                    "/usr/bin/python3",
                    str(self.repository / "scripts/check_loaded_systemd_paths.py"),
                    "--evidence",
                    str(self.transaction / "loaded-systemd-paths.json"),
                ],
                timeout=30,
            )
            self.phase = "starting-target"
            self.journal(migrated=migrated)
            self.run(["/usr/bin/systemctl", "start", BROKER_UNIT], timeout=180)
            self.run(["/usr/bin/systemctl", "restart", API_UNIT], timeout=90)
            self.run(["/usr/bin/systemctl", "restart", CONSOLE_UNIT], timeout=120)
            services = self.verify_services(inventory_name="post-inventory.json")
            final_schema = self.schema_evidence(expected=SCHEMA_AFTER)
            public_after = [self.public_get(url) for url in self.args.public_url]
            clear_maintenance(
                expected_uid=0,
                expected_gid=self.group_gid,
                deployment_id=self.deployment_id,
            )
            self.marker_active = False
            self.phase = "complete"
            result = {
                "ok": True,
                "deployment_id": self.deployment_id,
                "target_commit": target,
                "transaction": str(self.transaction),
                "backup_manifest": str(backup_manifest),
                "schema": final_schema,
                "units": {
                    name: {"MainPID": state["MainPID"], "ActiveState": state["ActiveState"]}
                    for name, state in services.items()
                    if name != "inventory"
                },
                "public": public_after,
            }
            self.journal(result=result)
            return result
        except BaseException as error:
            self.rollback(error)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default="/home/DevCoordinator")
    parser.add_argument("--target-commit", required=True)
    parser.add_argument("--rollback-ref", required=True)
    parser.add_argument("--transaction-dir", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--client-user", action="append", required=True)
    parser.add_argument("--public-url", action="append", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--console-env-file", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not Path(args.transaction_dir).is_absolute():
        print("deployment failed: --transaction-dir must be absolute", file=sys.stderr)
        return 2
    descriptor = -1
    try:
        descriptor = os.open(
            DEPLOY_LOCK,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = Driver(args).deploy()
    except (DeploymentError, OSError, sqlite3.Error, ValueError, subprocess.TimeoutExpired) as error:
        print(
            json.dumps(
                {"ok": False, "error": f"{type(error).__name__}: {error}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(descriptor)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
