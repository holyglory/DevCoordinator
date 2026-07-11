#!/usr/bin/env python3
"""Deterministic recall and safety tests for postgres-docker-backup."""

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
P0_TEST = ROOT / "scripts" / "p0_regression_test.py"
INTEGRATION_TEST = ROOT / "scripts" / "integration_test.py"
SOURCE_ID = "a" * 64
SOURCE_SHORT_ID = SOURCE_ID[:12]
REPLACEMENT_ID = "b" * 64


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run(
    args: list[str],
    *,
    env: dict[str, str],
    expect: int = 0,
    stdin: str | None = None,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"expected {expect}, got {result.returncode}: {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def parse_json(result: subprocess.CompletedProcess[str]) -> dict | list:
    return json.loads(result.stdout)


def parse_error_json(result: subprocess.CompletedProcess[str]) -> str:
    try:
        payload = json.loads(result.stderr)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"failure was not machine-readable JSON: {result.stderr!r}") from exc
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, str) or not error:
        raise AssertionError(f"failure JSON did not contain a non-empty error: {payload!r}")
    return error


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def docker_log(path: Path) -> list[list[str]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def make_fake_docker(path: Path) -> None:
    write(
        path,
        r'''#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
log = os.environ["FAKE_DOCKER_LOG"]
state_path = os.environ["FAKE_DOCKER_STATE"]
SOURCE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REPLACEMENT_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
DISPOSABLE_ID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
with open(log, "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\n")

def state():
    if not os.path.exists(state_path):
        return {}
    with open(state_path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def save(value):
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(value, fh)

def exec_container():
    if not args or args[0] != "exec":
        return None
    return args[2] if len(args) > 2 and args[1] == "-i" else args[1]

container = exec_container()
fail = os.environ.get("FAKE_DOCKER_FAIL", "")
failures = set(item for item in fail.split(",") if item)

def failing(name):
    return name in failures

def current_source_id():
    current = state()
    if current.get("source_replaced"):
        return REPLACEMENT_ID
    return os.environ.get("FAKE_DOCKER_CONTAINER_ID", SOURCE_ID)

def is_source(value):
    return value in {"pg-fixture", "pg123", SOURCE_ID, REPLACEMENT_ID, current_source_id()}

if args[:2] == ["ps", "--format"]:
    print(json.dumps({"ID":"pg123","Image":"postgres:16","Names":"pg-fixture","Status":"Up 2 minutes","Ports":"5432/tcp"}))
    raise SystemExit(0)

if args[:2] in (["inspect", "pg-fixture"], ["inspect", "pg123"]):
    print(json.dumps([{
        "Id":current_source_id(),
        "Image":"sha256:postgres16-fixture",
        "Config":{"Image":"postgres:16","Env":["POSTGRES_USER=app","POSTGRES_DB=appdb","POSTGRES_PASSWORD=DO_NOT_LEAK_7zQ"]}
    }]))
    raise SystemExit(0)

if args[:3] == ["inspect", "--type", "container"] and len(args) == 4:
    expected = args[3]
    if os.environ.get("FAKE_DOCKER_AMBIGUOUS_SHORT") == "1":
        print("Error: multiple containers match that ID prefix", file=sys.stderr)
        raise SystemExit(1)
    actual = current_source_id()
    if actual.startswith(expected):
        print(json.dumps([{"Id":actual,"Image":"sha256:postgres16-fixture","Config":{"Image":"postgres:16","Env":[]}}]))
        raise SystemExit(0)
    print("Error: No such container", file=sys.stderr)
    raise SystemExit(1)

if args and args[0] == "inspect" and len(args) == 2 and args[1].startswith("codex-pg-verify-"):
    current = state()
    print(json.dumps([{"Id":current.get("target_id", DISPOSABLE_ID), "Config":{"Image":"postgres:16","Env":[]}}]))
    raise SystemExit(0)

if args[:2] == ["version", "--format"]:
    print(json.dumps({"Server":{"Version":"fixture"}}))
    raise SystemExit(0)

# The password reaches the container only on stdin while creating a private
# pgpass file; it must never be present in these argv entries.
if is_source(container) and args[:2] == ["exec", "-i"] and "sh" in args:
    _ = sys.stdin.buffer.read()
    raise SystemExit(0)
if is_source(container) and "rm" in args:
    if failing("auth_cleanup"):
        print("credential cleanup echoed DO_NOT_LEAK_7zQ", file=sys.stderr)
        raise SystemExit(1)
    current = state()
    if os.environ.get("FAKE_DOCKER_REPLACE_AFTER_INCOMING") == "1" and current.get("incoming_drop_complete"):
        current["source_replaced"] = True
        save(current)
    raise SystemExit(0)

if args and args[0] == "run":
    target = args[args.index("--name") + 1]
    admin = next(item.split("=", 1)[1] for item in args if item.startswith("POSTGRES_USER="))
    control = next(item.split("=", 1)[1] for item in args if item.startswith("POSTGRES_DB="))
    current = {"target":target, "target_id":DISPOSABLE_ID, "admin":admin, "control":control}
    save(current)
    print(current["target_id"])
    raise SystemExit(0)

if args[:2] == ["rm", "--force"]:
    if failing("cluster_cleanup"):
        print("could not remove disposable cluster", file=sys.stderr)
        raise SystemExit(1)
    save({})
    print(args[-1])
    raise SystemExit(0)

if container and container.startswith("codex-pg-verify-") and "pg_isready" in args:
    if failing("ready"):
        print("not ready", file=sys.stderr)
        raise SystemExit(1)
    print("accepting connections")
    raise SystemExit(0)

if is_source(container) and "createdb" in args:
    if failing("create"):
        print("could not create database", file=sys.stderr)
        raise SystemExit(1)
    print("CREATE DATABASE")
    raise SystemExit(0)

if is_source(container) and "dropdb" in args:
    if failing("drop"):
        print("could not drop scratch database", file=sys.stderr)
        raise SystemExit(1)
    current = state()
    current["incoming_drop_complete"] = True
    save(current)
    print("DROP DATABASE")
    raise SystemExit(0)

if is_source(container) and "pg_dumpall" in args:
    if failing("dump"):
        print("cluster dump failed and echoed secret", file=sys.stderr)
        raise SystemExit(7)
    sys.stdout.write("-- PostgreSQL database cluster dump fixture\n\\connect appdb\nCREATE TABLE widgets(id integer);\n")
    raise SystemExit(0)

if is_source(container) and "pg_dump" in args:
    if failing("dump"):
        print("database dump failed and echoed secret", file=sys.stderr)
        raise SystemExit(7)
    if "-Fc" in args:
        sys.stdout.write("PGDMP fixture custom backup\n")
    else:
        sys.stdout.write("-- plain fixture\nCREATE TABLE widgets(id integer);\n")
    raise SystemExit(0)

if is_source(container) and "pg_restore" in args and "--list" in args:
    _ = sys.stdin.buffer.read()
    print("; archive created by pg_dump fixture")
    print("123 TABLE public widgets app")
    raise SystemExit(0)

if is_source(container) and "pg_restore" in args:
    _ = sys.stdin.buffer.read()
    is_transactional_target = "--single-transaction" in args and args[args.index("-d") + 1] == "appdb"
    if failing("db_restore") or (failing("transactional_restore") and is_transactional_target):
        print("pg_restore: fixture restore failed", file=sys.stderr)
        raise SystemExit(1)
    print("restore ok")
    raise SystemExit(0)

if is_source(container) and "psql" in args and "-c" not in args:
    _ = sys.stdin.buffer.read()
    is_transactional_target = "--single-transaction" in args and args[args.index("-d") + 1] == "appdb"
    if failing("db_restore") or (failing("transactional_restore") and is_transactional_target):
        print("psql: fixture restore failed", file=sys.stderr)
        raise SystemExit(1)
    print("plain restore ok")
    raise SystemExit(0)

if container and container.startswith("codex-pg-verify-") and "psql" in args and "-c" not in args:
    _ = sys.stdin.buffer.read()
    if failing("cluster_restore"):
        print("cluster restore failed", file=sys.stderr)
        raise SystemExit(1)
    print("cluster restore ok")
    raise SystemExit(0)

if container and "psql" in args and "-c" in args:
    sql = args[args.index("-c") + 1]
    current = state()
    if "codex_database_list" in sql:
        print("appdb")
        if container.startswith("codex-pg-verify-"):
            print(current["control"])
        print("postgres")
        raise SystemExit(0)
    if "codex_role_list" in sql:
        print("app")
        if container.startswith("codex-pg-verify-"):
            print(current["admin"])
        print("pg_read_all_data")
        print("postgres")
        raise SystemExit(0)
    if "codex_catalog_signature" in sql:
        if failing("catalog_mismatch") and is_source(container) and args[args.index("-d") + 1].startswith("codex_verify_"):
            print("99|1|1|3")
        else:
            print("2|1|1|3")
        raise SystemExit(0)

print("unsupported fake docker command: " + json.dumps(args), file=sys.stderr)
raise SystemExit(2)
''',
    )
    path.chmod(0o755)


def phase_index(sequence: list[list[str]], predicate) -> int:
    for index, command in enumerate(sequence):
        if predicate(command):
            return index
    return -1


def load_production_module():
    spec = importlib.util.spec_from_file_location("postgres_docker_backup_under_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load production module: {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_throwable_cleanup_guards() -> None:
    module = load_production_module()
    secret = "AUTH_CLEANUP_SECRET_91q"
    body_error = RuntimeError("database operation failed before credential cleanup")

    def throwable_auth_docker(args, **_kwargs):
        if "rm" in args:
            raise RuntimeError(f"credential cleanup transport failed and echoed {secret}")
        return subprocess.CompletedProcess(args, 0, "", "")

    original_docker = module.docker
    module.docker = throwable_auth_docker
    try:
        try:
            with module.postgres_auth("immutable-container", secret):
                raise body_error
        except RuntimeError as error:
            check("database operation failed" in str(error), "credential cleanup invocation hid the database failure")
            check("credential cleanup transport failed" in str(error), "credential cleanup invocation failure was hidden")
            check(secret not in str(error) and "<redacted>" in str(error), "credential cleanup invocation leaked its password")
            check(error.__cause__ is body_error, "credential cleanup wrapper did not retain the database error as its cause")
            check(secret not in repr(error.__context__), "credential cleanup retained an unredacted exception context")
        else:
            raise AssertionError("throwable credential cleanup unexpectedly succeeded")
    finally:
        module.docker = original_docker

    # False-positive control: successful cleanup must not wrap or replace an
    # ordinary body failure.
    module.docker = lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "", "")
    control_error = RuntimeError("control database failure")
    try:
        try:
            with module.postgres_auth("immutable-container", secret):
                raise control_error
        except RuntimeError as error:
            check(error is control_error, "successful credential cleanup replaced the body error")
            check("additionally" not in str(error), "successful credential cleanup invented a secondary failure")
        else:
            raise AssertionError("credential cleanup control unexpectedly succeeded")
    finally:
        module.docker = original_docker

    module = load_production_module()
    original_docker = module.docker
    original_preflight = module.container_identity_preflight
    module.container_identity_preflight = lambda *_args, **_kwargs: ({}, {}, {"actual_id": "immutable-container"})

    def throwable_scratch_docker(args, **_kwargs):
        if "createdb" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        if "pg_restore" in args:
            return subprocess.CompletedProcess(args, 1, "", "scratch restore body failed")
        if "dropdb" in args:
            raise RuntimeError("scratch cleanup transport exploded")
        raise AssertionError(f"unexpected scratch Docker command: {args}")

    module.docker = throwable_scratch_docker
    try:
        try:
            module.deep_verify_database(
                Path("/dev/null"),
                "source",
                "app",
                None,
                "custom",
                None,
                expected_container_id=SOURCE_ID,
                phase="throwable scratch cleanup test",
            )
        except RuntimeError as error:
            check("test restore into scratch database failed" in str(error), "scratch cleanup invocation hid the restore failure")
            check("scratch cleanup transport exploded" in str(error), "scratch cleanup invocation failure was hidden")
            check(error.__cause__ is not None and "test restore" in str(error.__cause__), "scratch cleanup wrapper lost its body cause")
        else:
            raise AssertionError("throwable scratch cleanup unexpectedly succeeded")
    finally:
        module.docker = original_docker
        module.container_identity_preflight = original_preflight

    # False-positive control: a successful scratch drop must preserve the
    # original restore failure without adding cleanup language.
    module = load_production_module()
    original_docker = module.docker
    original_preflight = module.container_identity_preflight
    module.container_identity_preflight = lambda *_args, **_kwargs: ({}, {}, {"actual_id": "immutable-container"})

    def successful_scratch_cleanup(args, **_kwargs):
        if "createdb" in args or "dropdb" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        if "pg_restore" in args:
            return subprocess.CompletedProcess(args, 1, "", "scratch restore control failed")
        raise AssertionError(f"unexpected scratch control command: {args}")

    module.docker = successful_scratch_cleanup
    try:
        try:
            module.deep_verify_database(
                Path("/dev/null"),
                "source",
                "app",
                None,
                "custom",
                None,
                expected_container_id=SOURCE_ID,
                phase="successful scratch cleanup control",
            )
        except RuntimeError as error:
            check("scratch restore control failed" in str(error), "scratch cleanup control lost the restore failure")
            check("additionally" not in str(error), "successful scratch cleanup invented a secondary failure")
        else:
            raise AssertionError("scratch cleanup control unexpectedly succeeded")
    finally:
        module.docker = original_docker
        module.container_identity_preflight = original_preflight

    manifest = {
        "source": {
            "container": {"id": "source-id", "image": "postgres:16"},
            "postgres": {"catalog": {"databases": [], "roles": []}},
        }
    }
    module = load_production_module()
    original_docker = module.docker
    original_inspect = module.inspect_container
    original_wait = module.wait_for_disposable_cluster
    original_diagnostics = module.disposable_cluster_diagnostics
    original_cleanup = module.cleanup_disposable_cluster

    def failing_cluster_docker(args, **_kwargs):
        if args and args[0] == "run":
            return subprocess.CompletedProcess(args, 0, "target-id\n", "")
        if "psql" in args:
            return subprocess.CompletedProcess(args, 1, "", "cluster restore body failed")
        raise AssertionError(f"unexpected cluster Docker command: {args}")

    module.docker = failing_cluster_docker
    module.inspect_container = lambda _target: {"Id": "target-id"}
    module.wait_for_disposable_cluster = lambda *_args, **_kwargs: None
    module.disposable_cluster_diagnostics = lambda _target: (_ for _ in ()).throw(
        RuntimeError("cluster diagnostics transport exploded")
    )
    module.cleanup_disposable_cluster = lambda _target: (_ for _ in ()).throw(
        RuntimeError("cluster cleanup transport exploded")
    )
    try:
        try:
            module.deep_verify_cluster(Path("/dev/null"), manifest, verification_image=None, timeout=1)
        except RuntimeError as error:
            text = str(error)
            check("cluster test restore failed" in text, "cluster diagnostics failure hid the restore failure")
            check("cluster diagnostics transport exploded" in text, "cluster diagnostics failure was hidden")
            check("cluster cleanup transport exploded" in text, "cluster cleanup failure was hidden")
            check(error.__cause__ is not None, "combined cluster failure lost its cause chain")
            check(
                error.__cause__.__cause__ is not None and "cluster test restore failed" in str(error.__cause__.__cause__),
                "combined cluster failure lost its original restore cause",
            )
        else:
            raise AssertionError("combined cluster failures unexpectedly succeeded")
    finally:
        module.docker = original_docker
        module.inspect_container = original_inspect
        module.wait_for_disposable_cluster = original_wait
        module.disposable_cluster_diagnostics = original_diagnostics
        module.cleanup_disposable_cluster = original_cleanup

    # False-positive control: successful diagnostics and cleanup should report
    # only real restore evidence, never an invented cleanup failure.
    module = load_production_module()
    module.docker = failing_cluster_docker
    module.inspect_container = lambda _target: {"Id": "target-id"}
    module.wait_for_disposable_cluster = lambda *_args, **_kwargs: None
    module.disposable_cluster_diagnostics = lambda _target: "state: fixture diagnostic"
    module.cleanup_disposable_cluster = lambda _target: None
    try:
        module.deep_verify_cluster(Path("/dev/null"), manifest, verification_image=None, timeout=1)
    except RuntimeError as error:
        text = str(error)
        check("cluster restore body failed" in text and "state: fixture diagnostic" in text, "cluster control lost body diagnostics")
        check("failed to collect" not in text and "additionally" not in text, "cluster control invented a cleanup failure")
    else:
        raise AssertionError("cluster diagnostics control unexpectedly succeeded")


def main() -> int:
    p0 = subprocess.run(
        [sys.executable, str(P0_TEST)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    check(p0.returncode == 0, f"P0 publication regression suite failed:\n{p0.stdout}\n{p0.stderr}")
    integration_contract = subprocess.run(
        [sys.executable, str(INTEGRATION_TEST), "--self-test-cleanup"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    check(
        integration_contract.returncode == 0,
        "Docker integration cleanup/readiness contract failed:\n"
        f"{integration_contract.stdout}\n{integration_contract.stderr}",
    )
    test_throwable_cleanup_guards()

    tmp = Path(tempfile.mkdtemp(prefix="postgres-docker-backup-self-test-")).resolve(strict=True)
    try:
        fake_bin = tmp / "bin"
        fake_bin.mkdir()
        make_fake_docker(fake_bin / "docker")
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
        log_path = tmp / "docker.log"
        state_path = tmp / "docker-state.json"
        log_path.write_text("", encoding="utf-8")
        env["FAKE_DOCKER_LOG"] = str(log_path)
        env["FAKE_DOCKER_STATE"] = str(state_path)

        listed = parse_json(run(["list"], env=env))
        check(listed[0]["name"] == "pg-fixture", "list should find the fake Postgres container")
        check(listed[0]["database"] == "appdb", "list should infer POSTGRES_DB")
        check(listed[0]["has_password"] is True, "list may report password presence but not its value")

        # Every command that selects or executes against a live source/target
        # must start from an operator-supplied immutable identity. Missing
        # identity must fail before even Docker inspection, not merely before
        # the final dump/restore mutation.
        log_path.write_text("", encoding="utf-8")
        missing_backup_identity = run(
            ["backup", "--container", "pg-fixture", "--out-dir", str(tmp / "missing-backup-identity")],
            env=env,
            expect=2,
        )
        check(
            "--expect-container-id" in missing_backup_identity.stderr
            and not docker_log(log_path),
            "backup without an immutable expected ID must fail before any Docker source selection or PostgreSQL work",
        )

        # Same-name replacement must fail before any container exec. Weak and
        # ambiguous prefixes are rejected; exact full and unambiguous standard
        # short IDs are legitimate controls.
        replacement_env = dict(env)
        replacement_env["FAKE_DOCKER_CONTAINER_ID"] = REPLACEMENT_ID
        log_path.write_text("", encoding="utf-8")
        mismatch = run(
            ["backup", "--container", "pg-fixture", "--expect-container-id", SOURCE_ID, "--out-dir", str(tmp / "identity-mismatch")],
            env=replacement_env,
            expect=1,
        )
        check("identity mismatch" in mismatch.stderr, "same-name replacement must report an identity mismatch")
        check(not any(command and command[0] == "exec" for command in docker_log(log_path)), "backup identity mismatch must execute no PostgreSQL command")

        log_path.write_text("", encoding="utf-8")
        weak = run(
            ["backup", "--container", "pg-fixture", "--expect-container-id", SOURCE_ID[:11], "--out-dir", str(tmp / "weak-prefix")],
            env=env,
            expect=1,
        )
        check("exactly 12" in weak.stderr and not any(command and command[0] == "exec" for command in docker_log(log_path)), "weak ID prefixes must fail before PostgreSQL work")

        ambiguous_env = dict(env)
        ambiguous_env["FAKE_DOCKER_AMBIGUOUS_SHORT"] = "1"
        log_path.write_text("", encoding="utf-8")
        ambiguous = run(
            ["backup", "--container", "pg-fixture", "--expect-container-id", SOURCE_SHORT_ID, "--out-dir", str(tmp / "ambiguous-prefix")],
            env=ambiguous_env,
            expect=1,
        )
        check("unambiguously" in ambiguous.stderr and not any(command and command[0] == "exec" for command in docker_log(log_path)), "ambiguous standard short IDs must fail before PostgreSQL work")

        short_control = parse_json(
            run(
                ["backup", "--container", "pg-fixture", "--expect-container-id", SOURCE_SHORT_ID, "--out-dir", str(tmp / "short-control")],
                env=env,
            )
        )
        short_manifest = json.loads(Path(short_control["manifest"]).read_text(encoding="utf-8"))
        check(short_manifest["container_identity_preflight"]["match"] == "exact_full", "execution recheck must lock a valid short-ID selection to the full ID")
        check(short_manifest["container_identity_preflight"]["requested_expected_id"] == SOURCE_SHORT_ID, "manifest must retain the operator's standard short-ID expectation")

        backup = parse_json(
            run(["backup", "--expect-container-id", SOURCE_ID, "--out-dir", str(tmp / "backups")], env=env)
        )
        backup_path = Path(backup["backup"])
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        check(backup["scope"] == "database", "custom backup must declare database scope")
        check(manifest["schema_version"] == 2, "manifest must be schema v2")
        check(manifest["source"]["container"]["id"] == SOURCE_ID, "manifest must contain immutable source container identity")
        check(manifest["container_identity_preflight"]["actual_id"] == SOURCE_ID, "manifest must retain the execution-time identity preflight")
        check(manifest["source"]["postgres"]["catalog"] == {"tables": 2, "sequences": 1, "views": 1, "functions": 3}, "manifest must contain a real source catalog signature")
        check(stat.S_IMODE(backup_path.stat().st_mode) == 0o600, "backup file must be private")
        check(stat.S_IMODE(manifest_path.stat().st_mode) == 0o600, "manifest must be private")
        combined = log_path.read_text(encoding="utf-8") + manifest_path.read_text(encoding="utf-8")
        check("DO_NOT_LEAK_7zQ" not in combined, "container password must not appear in Docker argv or manifest")

        for command_name, identity_args, expected_exit in (
            ("database verification", ["verify", "--file", str(backup_path)], 1),
            ("database restore", [
                "restore",
                "--file",
                str(backup_path),
                "--confirm-restore",
                "--no-safety-backup",
            ], 1),
        ):
            log_path.write_text("", encoding="utf-8")
            missing_identity = run(identity_args, env=env, expect=expected_exit)
            check(
                "requires --expect-container-id" in missing_identity.stderr
                and not docker_log(log_path),
                f"{command_name} without an immutable expected ID must fail before Docker selection or PostgreSQL work",
            )

        verified = parse_json(run(["verify", "--file", str(backup_path), "--expect-container-id", SOURCE_SHORT_ID], env=env))
        check(verified["ok"], "lightweight custom verification should pass")
        check("widgets" in verified["pg_restore_list"], "custom verification should parse the archive list")
        updated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        check(updated_manifest["verification"]["mode"] == "lightweight", "successful verification must be recorded atomically")
        check(updated_manifest["verification"]["container_identity_preflight"]["requested_expected_id"] == SOURCE_SHORT_ID, "verification manifest must retain the requested short ID")
        check(updated_manifest["verification"]["container_identity_preflight"]["selection_match"] == "unambiguous_standard_short", "verification evidence must prove the short ID resolved unambiguously")

        # Database test restore must use a fresh scratch DB, compare the source
        # catalog signature, and clean up after success.
        log_path.write_text("", encoding="utf-8")
        deep = parse_json(run(["verify", "--file", str(backup_path), "--test-restore", "--expect-container-id", SOURCE_ID], env=env))
        check(deep["verification_target"] == "scratch_database", "database dump must verify in a scratch database")
        check(deep["catalog_signature"] == manifest["source"]["postgres"]["catalog"], "scratch restore must match source catalog provenance")
        scratch = deep["scratch_db"]
        sequence = docker_log(log_path)
        create_i = phase_index(sequence, lambda c: "createdb" in c and scratch in c)
        restore_i = phase_index(sequence, lambda c: "pg_restore" in c and "--list" not in c and scratch in c)
        catalog_i = phase_index(sequence, lambda c: "psql" in c and "-c" in c and "codex_catalog_signature" in c[c.index("-c") + 1] and scratch in c)
        drop_i = phase_index(sequence, lambda c: "dropdb" in c and scratch in c)
        check(-1 not in (create_i, restore_i, catalog_i, drop_i), "scratch verification must execute create, restore, catalog, and cleanup phases")
        check(create_i < restore_i < catalog_i < drop_i, "scratch verification order must be create -> restore -> inspect -> drop")
        check("appdb" not in sequence[restore_i], "strong verification must never restore into the real database")

        # Restore failure and catalog mismatch must both clean up; cleanup
        # failure itself must be surfaced rather than silently ignored.
        for failure_mode in ("db_restore", "catalog_mismatch"):
            failed_env = dict(env)
            failed_env["FAKE_DOCKER_FAIL"] = failure_mode
            log_path.write_text("", encoding="utf-8")
            run(
                ["verify", "--file", str(backup_path), "--test-restore", "--expect-container-id", SOURCE_ID],
                env=failed_env,
                expect=1,
            )
            check(any("dropdb" in command for command in docker_log(log_path)), f"{failure_mode} must still drop its scratch database")
        cleanup_env = dict(env)
        cleanup_env["FAKE_DOCKER_FAIL"] = "drop"
        cleanup_failure = run(
            ["verify", "--file", str(backup_path), "--test-restore", "--expect-container-id", SOURCE_ID],
            env=cleanup_env,
            expect=1,
        )
        check("failed to drop scratch" in cleanup_failure.stderr, "scratch cleanup failure must fail verification")
        combined_failure_env = dict(env)
        combined_failure_env["FAKE_DOCKER_FAIL"] = "db_restore,drop"
        combined_failure = run(
            ["verify", "--file", str(backup_path), "--test-restore", "--expect-container-id", SOURCE_ID],
            env=combined_failure_env,
            expect=1,
        )
        check(
            "test restore" in parse_error_json(combined_failure) and "failed to drop scratch" in parse_error_json(combined_failure),
            "restore and cleanup failures must both remain visible",
        )

        auth_cleanup_env = dict(env)
        auth_cleanup_env["FAKE_DOCKER_FAIL"] = "dump,auth_cleanup"
        auth_cleanup_failure = run(
            ["backup", "--expect-container-id", SOURCE_ID, "--out-dir", str(tmp / "auth-cleanup-failure")],
            env=auth_cleanup_env,
            expect=1,
        )
        auth_cleanup_error = parse_error_json(auth_cleanup_failure)
        check("database dump failed" in auth_cleanup_error, "credential cleanup hid the backup failure from CLI JSON")
        check("failed to remove temporary PostgreSQL credential file" in auth_cleanup_error, "credential cleanup failure was absent from CLI JSON")
        check("DO_NOT_LEAK_7zQ" not in auth_cleanup_error and "<redacted>" in auth_cleanup_error, "credential cleanup JSON leaked the password")

        unmanifested = tmp / "legacy.dump"
        unmanifested.write_bytes(backup_path.read_bytes())
        run(
            ["verify", "--container", "pg-fixture", "--expect-container-id", SOURCE_ID, "--file", str(unmanifested)],
            env=env,
            expect=1,
        )
        implicit_legacy = run(
            [
                "verify",
                "--container",
                "pg-fixture",
                "--expect-container-id",
                SOURCE_ID,
                "--file",
                str(unmanifested),
                "--allow-unmanifested",
            ],
            env=env,
            expect=1,
        )
        check("explicit --scope database" in implicit_legacy.stderr, "legacy override must still require explicit database scope and format")
        legacy = parse_json(
            run(
                [
                    "verify",
                    "--container",
                    "pg-fixture",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--file",
                    str(unmanifested),
                    "--allow-unmanifested",
                    "--scope",
                    "database",
                    "--format",
                    "custom",
                ],
                env=env,
            )
        )
        check(legacy["ok"], "reviewed legacy database dumps may use explicit --allow-unmanifested")

        # A plain cluster/control script must never be allowed to escape a
        # database scratch target through psql meta-commands or server-wide DDL.
        for label, sql in {
            "cluster_header": "-- PostgreSQL database cluster dump\n\\connect postgres\n",
            "connect": "-- reviewed?\n\\connect appdb\nSELECT 1;\n",
            "role_ddl": "CREATE ROLE escaped LOGIN;\n",
            "copy_program": "COPY widgets FROM PROGRAM 'id';\n",
        }.items():
            unsafe = tmp / f"unsafe-{label}.sql"
            unsafe.write_text(sql, encoding="utf-8")
            unsafe_result = run(
                [
                    "verify",
                    "--container",
                    "pg-fixture",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--file",
                    str(unsafe),
                    "--allow-unmanifested",
                    "--scope",
                    "database",
                    "--format",
                    "plain",
                ],
                env=env,
                expect=1,
            )
            check("cross-scope" in unsafe_result.stderr, f"plain database verifier must reject {label}")

        tampered = tmp / "tampered.dump"
        tampered.write_bytes(backup_path.read_bytes() + b"tamper")
        tampered_manifest = dict(manifest)
        tampered_manifest["path"] = str(tampered)
        Path(f"{tampered}.manifest.json").write_text(json.dumps(tampered_manifest), encoding="utf-8")
        run(["verify", "--file", str(tampered), "--expect-container-id", SOURCE_ID], env=env, expect=1)

        # Scope and format cannot be mixed, and a database argument is invalid
        # for a whole-cluster dump.
        mismatch = run(
            [
                "backup",
                "--expect-container-id",
                SOURCE_ID,
                "--format",
                "all",
                "--scope",
                "database",
                "--out-dir",
                str(tmp / "scope-mismatch"),
            ],
            env=env,
            expect=1,
        )
        check("scope" in mismatch.stderr, "format/scope mismatch must fail")
        run(
            [
                "backup",
                "--expect-container-id",
                SOURCE_ID,
                "--format",
                "all",
                "--database",
                "appdb",
                "--out-dir",
                str(tmp / "cluster-with-db"),
            ],
            env=env,
            expect=1,
        )

        # Verify and restore share the same fail-closed identity boundary. An
        # already-recreated name must cause zero PostgreSQL execs.
        for command_name, identity_args in {
            "verify": ["verify", "--file", str(backup_path)],
            "restore": ["restore", "--file", str(backup_path), "--confirm-restore", "--no-safety-backup"],
        }.items():
            log_path.write_text("", encoding="utf-8")
            result = run([*identity_args, "--expect-container-id", SOURCE_ID], env=replacement_env, expect=1)
            check("identity mismatch" in result.stderr, f"{command_name} must report same-name identity replacement")
            check(
                not any(command and command[0] == "exec" for command in docker_log(log_path)),
                f"{command_name} identity mismatch must execute no PostgreSQL command",
            )

        # A restore can span several verification phases. Recreate the name
        # immediately after incoming scratch verification and prove the
        # required post-verification recheck blocks safety backup and target
        # restore rather than trusting the stale name.
        state_path.write_text("{}", encoding="utf-8")
        replaced_mid_restore_env = dict(env)
        replaced_mid_restore_env["FAKE_DOCKER_REPLACE_AFTER_INCOMING"] = "1"
        log_path.write_text("", encoding="utf-8")
        replaced_mid_restore = run(
            [
                "restore",
                "--file",
                str(backup_path),
                "--confirm-restore",
                "--expect-container-id",
                SOURCE_ID,
                "--safety-out-dir",
                str(tmp / "replaced-mid-restore"),
            ],
            env=replaced_mid_restore_env,
            expect=1,
        )
        replaced_sequence = docker_log(log_path)
        check("post-incoming" in replaced_mid_restore.stderr and "identity mismatch" in replaced_mid_restore.stderr, "restore must recheck identity after incoming verification")
        check(not any("pg_dump" in command or "pg_dumpall" in command for command in replaced_sequence), "post-verification identity mismatch must block the safety backup")
        check(
            not any(
                ("pg_restore" in command or "psql" in command)
                and "--single-transaction" in command
                and "-d" in command
                and command[command.index("-d") + 1] == "appdb"
                for command in replaced_sequence
            ),
            "post-verification identity mismatch must block target database mutation",
        )
        state_path.write_text("{}", encoding="utf-8")

        # Transactional database restore verifies the incoming artifact, creates
        # and strongly verifies a safety backup, then uses one transaction.
        log_path.write_text("", encoding="utf-8")
        restored = parse_json(
            run(
                [
                    "restore",
                    "--file",
                    str(backup_path),
                    "--confirm-restore",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--safety-out-dir",
                    str(tmp / "pre-restore"),
                ],
                env=env,
            )
        )
        check(restored["transactional"] is True, "database restore must report transactional execution")
        check(restored["incoming_verification"]["test_restore"] is True, "incoming backup must be strongly verified")
        check(restored["safety_backup"]["backup"], "database restore must create a safety backup")
        check(restored["safety_verification"]["test_restore"] is True, "safety backup must be strongly verified before target mutation")
        sequence = docker_log(log_path)
        target_restores = [
            command for command in sequence
            if "pg_restore" in command and "--list" not in command and "-d" in command and command[command.index("-d") + 1] == "appdb"
        ]
        check(len(target_restores) == 1, "exactly one final restore may target appdb")
        check("--single-transaction" in target_restores[0] and "--exit-on-error" in target_restores[0], "custom restore must use one error-stopping transaction")

        rollback_env = dict(env)
        rollback_env["FAKE_DOCKER_FAIL"] = "transactional_restore"
        rollback = run(
            [
                "restore",
                "--file",
                str(backup_path),
                "--confirm-restore",
                "--expect-container-id",
                SOURCE_ID,
                "--safety-out-dir",
                str(tmp / "rollback-safety"),
            ],
            env=rollback_env,
            expect=1,
        )
        check("rolled back" in rollback.stderr, "transaction failure must be reported as rolled back")

        remap = run(
            [
                "restore",
                "--file",
                str(backup_path),
                "--database",
                "clone",
                "--expect-container-id",
                SOURCE_ID,
                "--dry-run",
            ],
            env=env,
            expect=1,
        )
        check("allow-database-remap" in remap.stderr, "database remap must require explicit acknowledgement")
        remapped = parse_json(
            run(
                [
                    "restore",
                    "--file",
                    str(backup_path),
                    "--database",
                    "clone",
                    "--allow-database-remap",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--dry-run",
                ],
                env=env,
            )
        )
        check(remapped["database"] == "clone", "acknowledged database remap may be planned")

        # Plain SQL follows the same database scope and transactional restore path.
        plain = parse_json(
            run(
                ["backup", "--format", "plain", "--expect-container-id", SOURCE_ID, "--out-dir", str(tmp / "plain")],
                env=env,
            )
        )
        plain_path = Path(plain["backup"])
        parse_json(
            run(
                ["verify", "--file", str(plain_path), "--test-restore", "--expect-container-id", SOURCE_ID],
                env=env,
            )
        )
        log_path.write_text("", encoding="utf-8")
        parse_json(
            run(
                [
                    "restore",
                    "--file",
                    str(plain_path),
                    "--confirm-restore",
                    "--no-safety-backup",
                    "--expect-container-id",
                    SOURCE_ID,
                ],
                env=env,
            )
        )
        plain_target = [
            command for command in docker_log(log_path)
            if "psql" in command and "-c" not in command and "-d" in command and command[command.index("-d") + 1] == "appdb"
        ]
        check(len(plain_target) == 1 and "--single-transaction" in plain_target[0], "plain restore must use psql --single-transaction")

        # Cluster dumps carry cluster provenance and are test-restored only in a
        # generated, network-isolated, disposable target with a different ID.
        log_path.write_text("", encoding="utf-8")
        cluster = parse_json(
            run(
                [
                    "backup",
                    "--format",
                    "all",
                    "--scope",
                    "cluster",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--out-dir",
                    str(tmp / "cluster"),
                ],
                env=env,
            )
        )
        cluster_path = Path(cluster["backup"])
        cluster_manifest = json.loads(Path(cluster["manifest"]).read_text(encoding="utf-8"))
        check(cluster_manifest["scope"] == "cluster" and cluster_manifest["database"] is None, "pg_dumpall manifest must be cluster-scoped")
        check(cluster_manifest["source"]["postgres"]["catalog"]["databases"] == ["appdb", "postgres"], "cluster provenance must inventory databases")
        legacy_cluster = tmp / "legacy-cluster.sql"
        legacy_cluster.write_bytes(cluster_path.read_bytes())
        legacy_cluster_manifest = {
            "type": "postgres-docker-backup",
            "format": "all",
            "size": legacy_cluster.stat().st_size,
            "sha256": cluster_manifest["sha256"],
        }
        Path(f"{legacy_cluster}.manifest.json").write_text(json.dumps(legacy_cluster_manifest), encoding="utf-8")
        legacy_cluster_result = run(["verify", "--file", str(legacy_cluster)], env=env, expect=1)
        check("v2 manifest" in legacy_cluster_result.stderr, "cluster verification must require explicit v2 provenance")

        # Cluster artifact verification is the intentional exception: with no
        # source identity request, lightweight verification is fully offline
        # and strong verification touches only its new disposable target.
        log_path.write_text("", encoding="utf-8")
        cluster_lightweight = parse_json(run(["verify", "--file", str(cluster_path)], env=env))
        check(
            cluster_lightweight["ok"] and not docker_log(log_path),
            "cluster checksum/manifest verification without an expected ID must remain fully offline",
        )
        log_path.write_text("", encoding="utf-8")
        ignored_source_hint = run(
            ["verify", "--container", "pg-fixture", "--file", str(cluster_path)],
            env=env,
            expect=1,
        )
        check(
            "requires --expect-container-id" in ignored_source_hint.stderr
            and not docker_log(log_path),
            "cluster --container must not be silently ignored without an explicit expected-ID source check",
        )

        log_path.write_text("", encoding="utf-8")
        source_checked_cluster = parse_json(
            run(["verify", "--file", str(cluster_path), "--expect-container-id", SOURCE_ID], env=env)
        )
        source_check_sequence = docker_log(log_path)
        check(
            source_checked_cluster["container_identity_preflight"]["actual_id"] == SOURCE_ID
            and any(command[:2] == ["inspect", "pg-fixture"] for command in source_check_sequence)
            and not any(command and command[0] == "exec" for command in source_check_sequence),
            "optional cluster expected ID should perform only an explicit source-still-matches inspection",
        )

        log_path.write_text("", encoding="utf-8")
        cluster_verified = parse_json(run(["verify", "--file", str(cluster_path), "--test-restore"], env=env))
        check(cluster_verified["verification_target"] == "disposable_cluster", "pg_dumpall must verify in a separate cluster")
        check(cluster_verified["source_container_id"] != cluster_verified["verification_container_id"], "verification cluster must differ from source")
        check(cluster_verified["cleaned_up"] is True, "disposable cluster must be removed")
        cluster_sequence = docker_log(log_path)
        run_command = next(command for command in cluster_sequence if command and command[0] == "run")
        check("--network" in run_command and run_command[run_command.index("--network") + 1] == "none", "disposable verification cluster must have no network")
        check("--label" in run_command and "com.devcoordinator.postgres-backup.disposable=true" in run_command, "disposable target must be labeled")
        cluster_restore = next(command for command in cluster_sequence if command[:2] == ["exec", "-i"] and "psql" in command)
        check(cluster_restore[2].startswith("codex-pg-verify-"), "cluster SQL must be piped only into the disposable target")
        source_targets = {"pg-fixture", "pg123", SOURCE_ID}
        check(
            not any(
                command
                and (
                    (command[0] == "inspect" and command[-1] in source_targets)
                    or (
                        command[0] == "exec"
                        and len(command) > 1
                        and (command[2] if command[1] == "-i" else command[1]) in source_targets
                    )
                )
                for command in cluster_sequence
            ),
            "cluster verification without an expected ID must not inspect or exec against the live source",
        )
        check(not any(command[:3] == ["exec", "-i", "pg-fixture"] and "psql" in command for command in cluster_sequence), "cluster test restore must never pipe into source")
        check(any(command[:2] == ["rm", "--force"] for command in cluster_sequence), "disposable target must be removed")

        cluster_fail_env = dict(env)
        cluster_fail_env["FAKE_DOCKER_FAIL"] = "cluster_restore"
        log_path.write_text("", encoding="utf-8")
        cluster_failed = run(["verify", "--file", str(cluster_path), "--test-restore"], env=cluster_fail_env, expect=1)
        check("cluster test restore failed" in parse_error_json(cluster_failed), "cluster restore failure was absent from CLI JSON")
        check(any(command[:2] == ["rm", "--force"] for command in docker_log(log_path)), "failed cluster verification must still remove the target")
        cluster_cleanup_env = dict(env)
        cluster_cleanup_env["FAKE_DOCKER_FAIL"] = "cluster_cleanup"
        cleanup = run(["verify", "--file", str(cluster_path), "--test-restore"], env=cluster_cleanup_env, expect=1)
        check("failed to remove disposable" in parse_error_json(cleanup), "cluster cleanup failure must fail verification")
        combined_cluster_env = dict(env)
        combined_cluster_env["FAKE_DOCKER_FAIL"] = "cluster_restore,cluster_cleanup"
        combined_cluster = run(["verify", "--file", str(cluster_path), "--test-restore"], env=combined_cluster_env, expect=1)
        combined_cluster_error = parse_error_json(combined_cluster)
        check(
            "cluster test restore failed" in combined_cluster_error and "failed to remove disposable" in combined_cluster_error,
            "cluster restore and cleanup failures must both remain in CLI JSON",
        )

        # No direct cluster restore path exists without declared staged
        # replacement/rollback topology.
        log_path.write_text("", encoding="utf-8")
        refused = run(["restore", "--file", str(cluster_path), "--confirm-restore"], env=env, expect=1)
        check("staged replacement" in refused.stderr and "refused" in refused.stderr, "in-place cluster restore must be refused")
        check(not any(command and command[0] == "exec" for command in docker_log(log_path)), "refused cluster restore must not touch any container")

        # Explicit passwords use a private file or stdin and are delivered to
        # the container over stdin, never argv.
        insecure_password = tmp / "insecure-password"
        insecure_password.write_text("file-secret\n", encoding="utf-8")
        insecure_password.chmod(0o644)
        run(
            [
                "backup",
                "--expect-container-id",
                SOURCE_ID,
                "--password-file",
                str(insecure_password),
                "--out-dir",
                str(tmp / "insecure"),
            ],
            env=env,
            expect=1,
        )
        secure_password = tmp / "secure-password"
        secure_password.write_text("file-secret\n", encoding="utf-8")
        secure_password.chmod(0o600)
        log_path.write_text("", encoding="utf-8")
        file_password_backup = parse_json(
            run(
                [
                    "backup",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--password-file",
                    str(secure_password),
                    "--out-dir",
                    str(tmp / "file-password"),
                ],
                env=env,
            )
        )
        file_manifest = Path(file_password_backup["manifest"]).read_text(encoding="utf-8")
        check("file-secret" not in log_path.read_text(encoding="utf-8") + file_manifest, "password-file secret must not reach argv or manifest")
        stdin_password_backup = parse_json(
            run(
                [
                    "backup",
                    "--expect-container-id",
                    SOURCE_ID,
                    "--password-stdin",
                    "--out-dir",
                    str(tmp / "stdin-password"),
                ],
                env=env,
                stdin="stdin-secret\n",
            )
        )
        check(stdin_password_backup["scope"] == "database", "password stdin path should remain functional")
        stdin_manifest = Path(stdin_password_backup["manifest"]).read_text(encoding="utf-8")
        check("stdin-secret" not in log_path.read_text(encoding="utf-8") + stdin_manifest, "stdin password must not reach argv or manifest")
        unsafe_cli = run(["backup", "--password", "DO_NOT_ECHO_CLI_SECRET", "--out-dir", str(tmp / "unsafe-cli")], env=env, expect=2)
        check("unsafe and unsupported" in unsafe_cli.stderr, "unsafe --password option must be rejected")
        check("DO_NOT_ECHO_CLI_SECRET" not in unsafe_cli.stderr, "unsafe password value must not be echoed in diagnostics")

        print("self-test ok")
        return 0
    finally:
        rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
