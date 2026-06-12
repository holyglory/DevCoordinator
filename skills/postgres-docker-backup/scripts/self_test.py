#!/usr/bin/env python3
"""Self-tests for postgres-docker-backup."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import rmtree


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "postgres_docker_backup.py"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run(args: list[str], *, env: dict[str, str], expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {result.returncode}: {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def make_fake_docker(path: Path) -> None:
    write(
        path,
        """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
log = os.environ.get("FAKE_DOCKER_LOG")
if log:
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(args) + "\\n")

if args[:2] == ["ps", "--format"]:
    print(json.dumps({"ID":"pg123","Image":"postgres:16","Names":"pg-fixture","Status":"Up 2 minutes","Ports":"5432/tcp"}))
    raise SystemExit(0)

if args[:2] == ["inspect", "pg-fixture"] or args[:2] == ["inspect", "pg123"]:
    print(json.dumps([{
        "Id":"pg123456",
        "Config":{
            "Image":"postgres:16",
            "Env":["POSTGRES_USER=app","POSTGRES_DB=appdb","POSTGRES_PASSWORD=secret"]
        }
    }]))
    raise SystemExit(0)

if args[:2] == ["version", "--format"]:
    print(json.dumps({"Server":{"Version":"fixture"}}))
    raise SystemExit(0)

if args[:2] == ["exec", "pg-fixture"] and "pg_dump" in args:
    sys.stdout.write("PGDMP fixture custom backup\\n")
    raise SystemExit(0)

if args[:3] == ["exec", "-i", "pg-fixture"] and "pg_restore" in args and "--list" in args:
    _ = sys.stdin.read()
    print("; archive created by pg_dump fixture")
    print("123 TABLE public widgets app")
    raise SystemExit(0)

if args[:3] == ["exec", "-i", "pg-fixture"] and "pg_restore" in args:
    _ = sys.stdin.read()
    print("restore ok")
    raise SystemExit(0)

print("unsupported fake docker command: " + json.dumps(args), file=sys.stderr)
raise SystemExit(2)
""",
    )
    path.chmod(0o755)


def parse_json(result: subprocess.CompletedProcess[str]) -> dict | list:
    return json.loads(result.stdout)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="postgres-docker-backup-self-test-"))
    try:
        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        make_fake_docker(fake_bin / "docker")
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
        env["FAKE_DOCKER_LOG"] = str(tmp / "docker.log")

        listed = parse_json(run(["list"], env=env))
        check(listed[0]["name"] == "pg-fixture", "list should find fake Postgres container")
        check(listed[0]["database"] == "appdb", "list should infer POSTGRES_DB")

        backup = parse_json(run(["backup", "--out-dir", str(tmp / "backups")], env=env))
        backup_path = Path(backup["backup"])
        manifest_path = Path(backup["manifest"])
        check(backup_path.exists(), "backup file should exist")
        check(manifest_path.exists(), "manifest file should exist")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        check(manifest["sha256"] == backup["sha256"], "manifest should store checksum")

        verified = parse_json(run(["verify", "--file", str(backup_path)], env=env))
        check(verified["ok"], "verify should pass")
        check("widgets" in verified["pg_restore_list"], "verify should return pg_restore list output")

        rejected = run(["restore", "--file", str(backup_path), "--no-safety-backup"], env=env, expect=1)
        check("confirm" in rejected.stderr.lower(), "restore should require confirmation")

        restored = parse_json(
            run(
                [
                    "restore",
                    "--file",
                    str(backup_path),
                    "--confirm-restore",
                    "--safety-out-dir",
                    str(tmp / "pre-restore"),
                ],
                env=env,
            )
        )
        check(restored["database"] == "appdb", "restore should infer database")
        check(restored["safety_backup"]["backup"], "restore should create safety backup by default")

        print("self-test ok")
        return 0
    finally:
        rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
