#!/usr/bin/env python3
"""Disposable real-Docker integration test for postgres-docker-backup.

The caller must run the coordinator inventory first and set
POSTGRES_BACKUP_INTEGRATION_INVENTORY_CHECKED=1. The test never selects an
existing database: it creates one uniquely named, labeled, network-isolated
PostgreSQL container and removes it in a finally block.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from shutil import rmtree
from typing import Callable, NoReturn


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "postgres_docker_backup.py"
IMAGE = os.environ.get("POSTGRES_BACKUP_INTEGRATION_IMAGE", "postgres:16-alpine")
DISPOSABLE_LABEL = "com.devcoordinator.postgres-backup.disposable=true"


class IntegrationBodyCleanupError(RuntimeError):
    """The integration body and disposable cleanup both failed."""

    def __init__(self, primary_error: BaseException, cleanup_error: BaseException) -> None:
        super().__init__(
            f"integration body failed: {type(primary_error).__name__}: {primary_error}; "
            f"disposable cleanup also failed: {type(cleanup_error).__name__}: {cleanup_error}"
        )
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


def command(args: list[str], *, expect: int = 0, timeout: float = 90) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {result.returncode}: {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def skill(args: list[str], *, expect: int = 0, timeout: float = 180) -> dict:
    result = command([sys.executable, str(SCRIPT), *args], expect=expect, timeout=timeout)
    stream = result.stdout if expect == 0 else result.stderr
    return json.loads(stream)


def docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if result.returncode != 0:
            return False
        image = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return image.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def labeled_container_ids() -> set[str]:
    result = command(
        ["docker", "ps", "--all", "--quiet", "--filter", f"label={DISPOSABLE_LABEL}"],
        timeout=15,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def remove_disposable_container(container: str) -> None:
    command(["docker", "rm", "--force", container], timeout=30)


def cleanup_disposable_resources(
    *,
    created: bool,
    container: str,
    before: set[str],
    tmp: Path,
    remove_container: Callable[[str], None] = remove_disposable_container,
    container_inventory: Callable[[], set[str]] = labeled_container_ids,
) -> None:
    failures: list[tuple[str, BaseException]] = []
    leaked: set[str] = set()
    try:
        if created:
            try:
                remove_container(container)
            except BaseException as error:
                failures.append(("container removal", error))
        try:
            after = container_inventory()
        except BaseException as error:
            failures.append(("post-cleanup leak audit", error))
        else:
            leaked = after - before
    finally:
        rmtree(tmp, ignore_errors=True)

    if not failures and not leaked:
        return
    details = [f"{phase} failed: {type(error).__name__}: {error}" for phase, error in failures]
    if leaked:
        details.append(f"leaked disposable PostgreSQL containers: {sorted(leaked)}")
    cleanup_error = AssertionError("; ".join(details))
    if failures:
        raise cleanup_error from failures[0][1]
    raise cleanup_error


def raise_after_cleanup(primary_error: BaseException | None, cleanup_error: BaseException) -> NoReturn:
    if primary_error is None:
        raise cleanup_error
    # Uncaught integration errors are rendered from str(error), so the
    # top-level exception must include both incidents.  Keep the requested
    # body failure as the explicit cause and retain cleanup evidence on the
    # wrapper itself.
    raise IntegrationBodyCleanupError(primary_error, cleanup_error) from primary_error


def cleanup_contract_self_test() -> int:
    test_root = Path(tempfile.mkdtemp(prefix="postgres-backup-cleanup-contract-"))
    failing_tmp = test_root / "failing-run"
    failing_tmp.mkdir()
    (failing_tmp / "evidence.txt").write_text("fixture\n", encoding="utf-8")
    before = {"preexisting-container"}
    leaked_id = "leaked-disposable-container"

    def timed_out_remove(container: str) -> None:
        raise subprocess.TimeoutExpired(["docker", "rm", "--force", container], timeout=30)

    def inventory_with_leak() -> set[str]:
        return before | {leaked_id}

    try:
        cleanup_disposable_resources(
            created=True,
            container="fixture-container",
            before=before,
            tmp=failing_tmp,
            remove_container=timed_out_remove,
            container_inventory=inventory_with_leak,
        )
    except AssertionError as error:
        cleanup_error = error
    else:
        raise AssertionError("fault-injected disposable cleanup unexpectedly succeeded")
    if failing_tmp.exists():
        raise AssertionError("local integration scratch data survived cleanup failure")
    if "container removal failed" not in str(cleanup_error) or leaked_id not in str(cleanup_error):
        raise AssertionError(f"cleanup failure lost timeout or leak evidence: {cleanup_error!r}")

    primary_error = RuntimeError("simulated integration body failure")
    try:
        raise_after_cleanup(primary_error, cleanup_error)
    except IntegrationBodyCleanupError as error:
        if error.__cause__ is not primary_error:
            raise AssertionError("integration body failure was not retained as the cause") from error
        if (
            str(primary_error) not in str(error)
            or "container removal failed" not in str(error)
            or leaked_id not in str(error)
        ):
            raise AssertionError(
                f"top-level integration failure lost body, timeout, or leak evidence: {error!r}"
            ) from error
        if error.cleanup_error is not cleanup_error:
            raise AssertionError("integration cleanup error was not retained on the combined failure")
    else:
        raise AssertionError("combined body/cleanup failure unexpectedly returned")

    successful_tmp = test_root / "successful-run"
    successful_tmp.mkdir()
    cleanup_disposable_resources(
        created=True,
        container="fixture-container",
        before=before,
        tmp=successful_tmp,
        remove_container=lambda _container: None,
        container_inventory=lambda: set(before),
    )
    if successful_tmp.exists():
        raise AssertionError("successful cleanup left local integration scratch data")
    rmtree(test_root, ignore_errors=True)
    readiness_contract_self_test()
    print("docker integration deterministic contract self-test ok")
    return 0


def wait_ready(container: str) -> None:
    deadline = time.monotonic() + 45
    probe = [
        "docker",
        "exec",
        container,
        "psql",
        "-X",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "127.0.0.1",
        "-U",
        "app",
        "-d",
        "appdb",
        "-c",
        "SELECT 1;",
    ]
    last_error = "readiness query was not attempted"
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                probe,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            last_error = f"{type(error).__name__}: {error}"
        else:
            output = result.stdout.strip()
            if result.returncode == 0 and output == "1":
                return
            detail = result.stderr.strip() or result.stdout.strip() or f"psql exited {result.returncode}"
            last_error = detail[-1000:]
        time.sleep(0.5)
    raise AssertionError(f"disposable source PostgreSQL appdb did not become query-ready: {last_error}")


def readiness_contract_self_test() -> None:
    expected_command = [
        "docker",
        "exec",
        "fixture-container",
        "psql",
        "-X",
        "-qAt",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        "127.0.0.1",
        "-U",
        "app",
        "-d",
        "appdb",
        "-c",
        "SELECT 1;",
    ]
    original_run = subprocess.run
    original_sleep = time.sleep
    commands: list[list[str]] = []
    sleeps: list[float] = []
    psql_attempts = 0

    def retrying_probe(args, **_kwargs):
        nonlocal psql_attempts
        command_args = list(args)
        commands.append(command_args)
        if "pg_isready" in command_args:
            # This deliberately returns success so the fixture catches the old
            # listener-only readiness implementation.
            return subprocess.CompletedProcess(args, 0, "", "")
        if command_args != expected_command:
            raise AssertionError(f"unexpected readiness command: {command_args}")
        psql_attempts += 1
        if psql_attempts == 1:
            return subprocess.CompletedProcess(args, 2, "", 'FATAL: database "appdb" does not exist')
        return subprocess.CompletedProcess(args, 0, "1\n", "")

    subprocess.run = retrying_probe
    time.sleep = lambda seconds: sleeps.append(seconds)
    try:
        wait_ready("fixture-container")
    finally:
        subprocess.run = original_run
        time.sleep = original_sleep
    if commands != [expected_command, expected_command]:
        raise AssertionError(f"readiness must retry a real appdb SELECT after database initialization: {commands}")
    if sleeps != [0.5]:
        raise AssertionError(f"readiness retry must use one bounded backoff in this fixture: {sleeps}")

    # False-positive control: a successful SELECT 1 should return immediately
    # without a redundant probe or sleep.
    ready_commands: list[list[str]] = []
    ready_sleeps: list[float] = []

    def ready_probe(args, **_kwargs):
        command_args = list(args)
        ready_commands.append(command_args)
        if command_args != expected_command:
            raise AssertionError(f"unexpected ready-control command: {command_args}")
        return subprocess.CompletedProcess(args, 0, "1\n", "")

    subprocess.run = ready_probe
    time.sleep = lambda seconds: ready_sleeps.append(seconds)
    try:
        wait_ready("fixture-container")
    finally:
        subprocess.run = original_run
        time.sleep = original_sleep
    if ready_commands != [expected_command] or ready_sleeps:
        raise AssertionError(
            f"ready SELECT control should return after one probe without sleeping: commands={ready_commands}, sleeps={ready_sleeps}"
        )


def scalar(container: str, sql: str) -> str:
    return command(
        ["docker", "exec", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "app", "-d", "appdb", "-c", sql],
        timeout=30,
    ).stdout.strip()


def main() -> int:
    required = os.environ.get("POSTGRES_BACKUP_INTEGRATION_REQUIRED") == "1"
    if os.environ.get("POSTGRES_BACKUP_INTEGRATION_INVENTORY_CHECKED") != "1":
        message = "integration skipped: run coordinator inventory, then set POSTGRES_BACKUP_INTEGRATION_INVENTORY_CHECKED=1"
        print(message, file=sys.stderr if required else sys.stdout)
        return 1 if required else 0
    if not docker_available():
        message = f"integration skipped: Docker is unavailable or local image {IMAGE!r} is missing"
        print(message, file=sys.stderr if required else sys.stdout)
        return 1 if required else 0

    before = labeled_container_ids()
    container = f"devcoordinator-pg-it-{uuid.uuid4().hex[:12]}"
    tmp = Path(tempfile.mkdtemp(prefix="postgres-backup-docker-integration-"))
    created = False
    primary_error: BaseException | None = None
    try:
        command(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                container,
                "--label",
                DISPOSABLE_LABEL,
                "--network",
                "none",
                "--tmpfs",
                "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
                "-e",
                "POSTGRES_HOST_AUTH_METHOD=trust",
                "-e",
                "POSTGRES_USER=app",
                "-e",
                "POSTGRES_DB=appdb",
                IMAGE,
            ],
            timeout=30,
        )
        created = True
        wait_ready(container)
        container_id = command(["docker", "inspect", "--format", "{{.Id}}", container], timeout=15).stdout.strip()
        if len(container_id) != 64:
            raise AssertionError(f"Docker did not return a full immutable container ID: {container_id!r}")
        short_container_id = container_id[:12]
        wrong_container_id = ("0" if container_id[0] != "0" else "1") + container_id[1:]
        command(
            [
                "docker",
                "exec",
                container,
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "app",
                "-d",
                "appdb",
                "-c",
                "CREATE TABLE widgets(id integer PRIMARY KEY, name text NOT NULL); INSERT INTO widgets VALUES (1, 'one'), (2, 'two'), (3, 'three');",
            ]
        )

        mismatch = skill(
            [
                "backup",
                "--container",
                container,
                "--expect-container-id",
                wrong_container_id,
                "--database",
                "appdb",
                "--out-dir",
                str(tmp / "identity-mismatch"),
            ],
            expect=1,
        )
        if "identity mismatch" not in mismatch.get("error", ""):
            raise AssertionError(f"wrong immutable container ID was not rejected: {mismatch}")

        database_backup = skill(
            [
                "backup",
                "--container",
                container,
                "--expect-container-id",
                container_id,
                "--database",
                "appdb",
                "--out-dir",
                str(tmp / "database"),
            ]
        )
        database_path = Path(database_backup["backup"])
        verified = skill(
            [
                "verify",
                "--container",
                container,
                "--expect-container-id",
                short_container_id,
                "--file",
                str(database_path),
                "--test-restore",
            ]
        )
        if verified.get("verification_target") != "scratch_database" or verified.get("table_count") != 1:
            raise AssertionError(f"unexpected database verification result: {verified}")

        command(
            ["docker", "exec", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "app", "-d", "appdb", "-c", "INSERT INTO widgets VALUES (4, 'four');"]
        )
        if scalar(container, "SELECT count(*) FROM widgets;") != "4":
            raise AssertionError("disposable mutation did not take effect")
        restored = skill(
            [
                "restore",
                "--container",
                container,
                "--expect-container-id",
                container_id,
                "--database",
                "appdb",
                "--file",
                str(database_path),
                "--confirm-restore",
                "--safety-out-dir",
                str(tmp / "pre-restore"),
            ]
        )
        if restored.get("transactional") is not True or not restored.get("safety_verification", {}).get("test_restore"):
            raise AssertionError(f"restore did not prove transactional safety: {restored}")
        if scalar(container, "SELECT count(*) FROM widgets;") != "3":
            raise AssertionError("transactional restore did not recover the backed-up rows")

        cluster_backup = skill(
            [
                "backup",
                "--container",
                container,
                "--expect-container-id",
                container_id,
                "--format",
                "all",
                "--scope",
                "cluster",
                "--out-dir",
                str(tmp / "cluster"),
            ],
            timeout=180,
        )
        cluster_path = Path(cluster_backup["backup"])
        cluster_verified = skill(
            [
                "verify",
                "--container",
                container,
                "--expect-container-id",
                short_container_id,
                "--file",
                str(cluster_path),
                "--test-restore",
            ],
            timeout=240,
        )
        if cluster_verified.get("verification_target") != "disposable_cluster" or cluster_verified.get("cleaned_up") is not True:
            raise AssertionError(f"cluster verification was not disposable: {cluster_verified}")
        refused = skill(["restore", "--file", str(cluster_path), "--confirm-restore"], expect=1)
        if "staged replacement" not in refused.get("error", ""):
            raise AssertionError(f"unsafe cluster restore was not refused: {refused}")
        if scalar(container, "SELECT count(*) FROM widgets;") != "3":
            raise AssertionError("cluster verification changed the disposable source")

        print("docker integration test ok")
        return 0
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            cleanup_disposable_resources(
                created=created,
                container=container,
                before=before,
                tmp=tmp,
            )
        except BaseException as cleanup_error:
            raise_after_cleanup(primary_error, cleanup_error)


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test-cleanup"]:
        raise SystemExit(cleanup_contract_self_test())
    raise SystemExit(main())
