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


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "postgres_docker_backup.py"
IMAGE = os.environ.get("POSTGRES_BACKUP_INTEGRATION_IMAGE", "postgres:16-alpine")
DISPOSABLE_LABEL = "com.holyskills.postgres-backup.disposable=true"


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


def wait_ready(container: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "app", "-d", "appdb"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise AssertionError("disposable source PostgreSQL did not become ready")


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
    container = f"holyskills-pg-it-{uuid.uuid4().hex[:12]}"
    tmp = Path(tempfile.mkdtemp(prefix="postgres-backup-docker-integration-"))
    created = False
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
    finally:
        if created:
            subprocess.run(
                ["docker", "rm", "--force", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        rmtree(tmp, ignore_errors=True)
        after = labeled_container_ids()
        leaked = after - before
        if leaked:
            raise AssertionError(f"disposable PostgreSQL containers leaked after integration test: {sorted(leaked)}")


if __name__ == "__main__":
    raise SystemExit(main())
