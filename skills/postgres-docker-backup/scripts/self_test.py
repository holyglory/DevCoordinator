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

# Deep verify (--test-restore): create/drop scratch DB + sanity query run via
# `psql -c` without stdin (exec, not exec -i).
if args[:2] == ["exec", "pg-fixture"] and "psql" in args and "-c" in args:
    sql = args[args.index("-c") + 1]
    fail = os.environ.get("FAKE_DOCKER_FAIL", "")
    if sql.startswith("CREATE DATABASE"):
        if fail == "create":
            print("could not create database", file=sys.stderr)
            raise SystemExit(1)
        print("CREATE DATABASE")
        raise SystemExit(0)
    if sql.startswith("DROP DATABASE"):
        print("DROP DATABASE")
        raise SystemExit(0)
    # Sanity query against the scratch DB.
    if fail == "sanity":
        print("relation does not exist", file=sys.stderr)
        raise SystemExit(1)
    print("7")
    raise SystemExit(0)

if args[:3] == ["exec", "-i", "pg-fixture"] and "pg_restore" in args and "--list" in args:
    _ = sys.stdin.read()
    print("; archive created by pg_dump fixture")
    print("123 TABLE public widgets app")
    raise SystemExit(0)

if args[:3] == ["exec", "-i", "pg-fixture"] and "pg_restore" in args:
    _ = sys.stdin.read()
    if os.environ.get("FAKE_DOCKER_FAIL", "") == "restore":
        print("pg_restore: error: truncated dump", file=sys.stderr)
        raise SystemExit(1)
    print("restore ok")
    raise SystemExit(0)

# Plain-SQL restore into scratch DB uses psql over stdin (no -c).
if args[:3] == ["exec", "-i", "pg-fixture"] and "psql" in args:
    _ = sys.stdin.read()
    if os.environ.get("FAKE_DOCKER_FAIL", "") == "restore":
        print("psql: error: syntax error at end of input", file=sys.stderr)
        raise SystemExit(1)
    print("plain restore ok")
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
        check("test_restore" not in verified, "default verify should stay lightweight (no test restore)")

        # --- Deep verify (--test-restore) happy path ---
        log_path = Path(env["FAKE_DOCKER_LOG"])
        log_path.write_text("", encoding="utf-8")
        deep = parse_json(run(["verify", "--file", str(backup_path), "--test-restore"], env=env))
        check(deep["ok"], "deep verify should pass")
        check(deep.get("test_restore") is True, "deep verify should report test_restore=True")
        scratch = deep["scratch_db"]
        check(scratch.startswith("codex_verify_"), "scratch DB should be uniquely named codex_verify_*")
        check(scratch != "appdb", "scratch DB must not be the real database")
        check(deep["restore_returncode"] == 0, "deep verify should report restore exit status")
        check(deep["table_count"] == 7, "deep verify should report sanity-query table_count")
        check(deep["target_database"] == "appdb", "deep verify should report the real target database")

        # Inspect the actual docker command sequence that was emitted.
        seq = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

        def phase_index(pred) -> int:
            for i, cmd in enumerate(seq):
                if pred(cmd):
                    return i
            return -1

        create_i = phase_index(lambda c: "psql" in c and "-c" in c and c[c.index("-c") + 1].startswith("CREATE DATABASE"))
        restore_i = phase_index(lambda c: c[:3] == ["exec", "-i", "pg-fixture"] and "pg_restore" in c and "--list" not in c)
        sanity_i = phase_index(lambda c: "psql" in c and "-c" in c and "pg_tables" in c[c.index("-c") + 1])
        drop_i = phase_index(lambda c: "psql" in c and "-c" in c and c[c.index("-c") + 1].startswith("DROP DATABASE"))
        check(create_i != -1, "deep verify should create a scratch DB")
        check(restore_i != -1, "deep verify should restore into the scratch DB")
        check(sanity_i != -1, "deep verify should run a sanity query")
        check(drop_i != -1, "deep verify should drop the scratch DB")
        check(create_i < restore_i < sanity_i < drop_i, "deep verify order: create -> restore -> sanity -> drop")

        # Restore must target the scratch DB, never the real --database.
        restore_cmd = seq[restore_i]
        check(restore_cmd[restore_cmd.index("-d") + 1] == scratch, "restore must target the scratch DB")
        for cmd in seq:
            if "pg_restore" in cmd and "--list" not in cmd:
                check("appdb" not in cmd, "test-restore must never target the real database")

        # --- Deep verify drops scratch DB even when restore fails ---
        fail_env = dict(env)
        fail_env["FAKE_DOCKER_FAIL"] = "restore"
        log_path.write_text("", encoding="utf-8")
        run(["verify", "--file", str(backup_path), "--test-restore"], env=fail_env, expect=1)
        fail_seq = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        check(
            any("psql" in c and "-c" in c and c[c.index("-c") + 1].startswith("DROP DATABASE") for c in fail_seq),
            "scratch DB must be dropped even when restore fails",
        )

        # --- Deep verify drops scratch DB even when the sanity query fails ---
        sanity_fail_env = dict(env)
        sanity_fail_env["FAKE_DOCKER_FAIL"] = "sanity"
        log_path.write_text("", encoding="utf-8")
        run(["verify", "--file", str(backup_path), "--test-restore"], env=sanity_fail_env, expect=1)
        sanity_seq = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        check(
            any("psql" in c and "-c" in c and c[c.index("-c") + 1].startswith("DROP DATABASE") for c in sanity_seq),
            "scratch DB must be dropped even when the sanity query fails",
        )
        log_path.write_text("", encoding="utf-8")

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
