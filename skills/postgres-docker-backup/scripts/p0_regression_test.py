#!/usr/bin/env python3
"""Must-catch regressions for postgres-docker-backup's P0 safety boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
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


def make_fake_docker(path: Path) -> None:
    write(
        path,
        """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
SOURCE_ID = "1111111111111111111111111111111111111111111111111111111111111111"
REPLACEMENT_ID = "2222222222222222222222222222222222222222222222222222222222222222"
with open(os.environ["FAKE_DOCKER_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\\n")

if args[:2] == ["ps", "--format"]:
    print(json.dumps({"ID":"p0","Image":"postgres:16","Names":"p0-source","Status":"Up","Ports":"5432/tcp"}))
    raise SystemExit(0)
if args[:2] in (["inspect", "p0-source"], ["inspect", "p0"]):
    print(json.dumps([{"Id":os.environ.get("FAKE_DOCKER_CONTAINER_ID", SOURCE_ID),"Config":{"Image":"postgres:16","Env":["POSTGRES_USER=app","POSTGRES_DB=appdb","POSTGRES_PASSWORD=do-not-leak"]}}]))
    raise SystemExit(0)
if args[:3] == ["inspect", "--type", "container"] and len(args) == 4:
    expected = args[3]
    if os.environ.get("FAKE_DOCKER_AMBIGUOUS_SHORT") == "1":
        print("ambiguous ID prefix", file=sys.stderr)
        raise SystemExit(1)
    actual = os.environ.get("FAKE_DOCKER_CONTAINER_ID", SOURCE_ID)
    if actual.startswith(expected):
        print(json.dumps([{"Id":actual,"Config":{"Image":"postgres:16","Env":[]}}]))
        raise SystemExit(0)
    print("No such container", file=sys.stderr)
    raise SystemExit(1)

def exec_container():
    if not args or args[0] != "exec":
        return None
    return args[2] if len(args) > 2 and args[1] == "-i" else args[1]

container = exec_container()
if container in {"p0-source", SOURCE_ID, REPLACEMENT_ID} and args[:2] == ["exec", "-i"] and "sh" in args and "cat" in args[args.index("-c") + 1]:
    _ = sys.stdin.buffer.read()
    raise SystemExit(0)
if container in {"p0-source", SOURCE_ID, REPLACEMENT_ID} and "rm" in args:
    raise SystemExit(0)
if container in {"p0-source", SOURCE_ID, REPLACEMENT_ID} and "psql" in args and "-c" in args:
    sql = args[args.index("-c") + 1]
    if "codex_catalog_signature" in sql:
        print("2|1|1|3")
        raise SystemExit(0)
if container in {"p0-source", SOURCE_ID, REPLACEMENT_ID} and "pg_dump" in args:
    if os.environ.get("FAKE_DOCKER_FAIL_DUMP") == "1":
        print("dump failed and mentioned do-not-leak", file=sys.stderr)
        raise SystemExit(9)
    sys.stdout.write("PGDMP p0 fixture\\n")
    raise SystemExit(0)
print("unsupported: " + json.dumps(args), file=sys.stderr)
raise SystemExit(2)
""",
    )
    path.chmod(0o755)


def invoke(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def load_production_module():
    spec = importlib.util.spec_from_file_location("postgres_docker_backup_p0_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load production module: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_partial_publication_rollback(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    module = load_production_module()
    staging = root / "publication.partial"
    output = root / "publication.dump"
    staging.write_bytes(b"verified backup bytes")
    original_atomic_json_write = module.atomic_json_write
    original_unlink = Path.unlink

    def fail_manifest(*_args, **_kwargs):
        raise RuntimeError("manifest publication failed")

    def fail_published_unlink(self, *args, **kwargs):
        if self == output:
            raise OSError("published backup rollback unlink failed")
        return original_unlink(self, *args, **kwargs)

    module.atomic_json_write = fail_manifest
    Path.unlink = fail_published_unlink
    try:
        try:
            module.publish_artifact(staging, output, {})
        except RuntimeError as error:
            text = str(error)
            check("manifest publication failed" in text, "publication rollback hid the manifest failure")
            check("published backup rollback unlink failed" in text, "publication rollback failure was hidden")
            check(error.__cause__ is not None and "manifest publication failed" in str(error.__cause__), "publication rollback lost its primary cause")
        else:
            raise AssertionError("failed publication unexpectedly succeeded")
    finally:
        Path.unlink = original_unlink
        module.atomic_json_write = original_atomic_json_write
    check(output.exists(), "rollback-failure fixture did not leave the realistically unremovable published file")
    output.unlink()

    # False-positive control: when rollback succeeds, retain the original
    # publication error without inventing a cleanup failure or leaving output.
    staging = root / "publication-control.partial"
    output = root / "publication-control.dump"
    staging.write_bytes(b"verified backup bytes")
    module.atomic_json_write = fail_manifest
    try:
        try:
            module.publish_artifact(staging, output, {})
        except RuntimeError as error:
            check(str(error) == "manifest publication failed", "successful publication rollback changed the primary failure")
            check("additionally" not in str(error), "successful publication rollback invented a secondary failure")
        else:
            raise AssertionError("publication rollback control unexpectedly succeeded")
    finally:
        module.atomic_json_write = original_atomic_json_write
    check(not output.exists(), "successful publication rollback left a final backup")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="postgres-backup-p0-regression-")).resolve(strict=True)
    try:
        test_partial_publication_rollback(tmp / "publication-rollback")
        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        make_fake_docker(fake_bin / "docker")
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
        env["FAKE_DOCKER_LOG"] = str(tmp / "docker.log")

        # Fail-before reproduction: an operator recorded the immutable ID,
        # but the same container name was recreated before backup. The old
        # implementation has no identity preflight and reaches pg_dump in the
        # replacement container.
        recreated_env = dict(env)
        recreated_env["FAKE_DOCKER_CONTAINER_ID"] = "2222222222222222222222222222222222222222222222222222222222222222"
        Path(env["FAKE_DOCKER_LOG"]).write_text("", encoding="utf-8")
        recreated = invoke(
            [
                "backup",
                "--container",
                "p0-source",
                "--expect-container-id",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "--out-dir",
                str(tmp / "recreated"),
            ],
            recreated_env,
        )
        check(recreated.returncode != 0, "same-name replacement must be rejected before pg_dump")
        check("identity mismatch" in recreated.stderr, "same-name replacement must produce identity evidence")
        check(not any("pg_dump" in json.loads(line) for line in Path(env["FAKE_DOCKER_LOG"]).read_text(encoding="utf-8").splitlines()), "identity mismatch must not reach pg_dump")

        short_control = invoke(
            [
                "backup",
                "--container",
                "p0-source",
                "--expect-container-id",
                "111111111111",
                "--out-dir",
                str(tmp / "short-control"),
                "--dry-run",
            ],
            env,
        )
        check(short_control.returncode == 0, f"unambiguous standard short ID must remain valid: {short_control.stderr}")

        out_dir = tmp / "backups"
        created = invoke(
            [
                "backup",
                "--expect-container-id",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "--out-dir",
                str(out_dir),
            ],
            env,
        )
        check(created.returncode == 0, f"fixture backup failed: {created.stderr}")
        payload = json.loads(created.stdout)
        backup = Path(payload["backup"])
        manifest_path = Path(payload["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        check(mode(out_dir) == 0o700, "backup directory must be private (0700)")
        check(mode(backup) == 0o600, "backup artifact must be private (0600)")
        check(mode(manifest_path) == 0o600, "manifest must be private (0600)")
        check(manifest.get("schema_version") == 2, "manifest must use the versioned v2 schema")
        check(manifest.get("scope") == "database", "manifest must declare database scope")
        check(manifest.get("source", {}).get("container", {}).get("id") == "1" * 64, "manifest must preserve source provenance")
        check(manifest.get("container_identity_preflight", {}).get("actual_id") == "1" * 64, "manifest must preserve execution identity evidence")

        combined = created.stdout + created.stderr + Path(env["FAKE_DOCKER_LOG"]).read_text(encoding="utf-8") + manifest_path.read_text(encoding="utf-8")
        check("do-not-leak" not in combined, "database password must never appear in argv, output, logs, or manifest")

        collision = tmp / "collision.dump"
        collision.write_bytes(b"known-good-existing-backup")
        collided = invoke(
            ["backup", "--expect-container-id", "1" * 64, "--output", str(collision)],
            env,
        )
        check(collided.returncode != 0, "backup must refuse an existing output path")
        check(collision.read_bytes() == b"known-good-existing-backup", "collision must not truncate an existing backup")

        failed = tmp / "failed.dump"
        fail_env = dict(env)
        fail_env["FAKE_DOCKER_FAIL_DUMP"] = "1"
        failure = invoke(
            ["backup", "--expect-container-id", "1" * 64, "--output", str(failed)],
            fail_env,
        )
        check(failure.returncode != 0, "failed dump fixture must fail")
        check(not failed.exists(), "failed dump must not publish a partial final artifact")
        check(not Path(f"{failed}.manifest.json").exists(), "failed dump must not publish a manifest")
        check("do-not-leak" not in failure.stderr, "failure diagnostics must redact the password")

        print("p0 regression test ok")
        return 0
    finally:
        rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
