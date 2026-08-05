#!/usr/bin/env python3
"""Focused contracts for the bounded Coordinator call-log reader."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "read_coordinator_call_log.py"
MODULE_ROOT = ROOT / "skills" / "codex-dev-coordinator" / "scripts"
sys.path.insert(0, str(MODULE_ROOT))

from devcoordinator.call_journal import (  # noqa: E402
    MAX_CALL_JOURNAL_PAGE_BYTES,
    RollingCallJournal,
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def invoke(path: Path, *arguments: str) -> tuple[subprocess.CompletedProcess[str], object]:
    command = [sys.executable]
    if sys.flags.optimize:
        command.append("-O")
    command.extend((str(SCRIPT), "--log", str(path), *arguments))
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        output: object = json.loads(completed.stdout)
    except json.JSONDecodeError:
        output = None
    expect(
        len(completed.stdout.encode("utf-8")) <= MAX_CALL_JOURNAL_PAGE_BYTES,
        "reader exceeded its exact final output byte bound",
    )
    if completed.stdout:
        expect(completed.stdout.endswith("\n"), "reader output lacks one final newline")
    return completed, output


def record(index: int, *, ok: bool, code: str | None = None) -> dict[str, object]:
    return {
        "schema_version": 1,
        "record_id": f"record-{index}",
        "call_id": f"call-{index}",
        "recorded_at": "2026-08-02T00:00:00.000Z",
        "duration_ms": float(index),
        "authority_pid": 123,
        "peer_uid": 1000 + index,
        "peer_gid": 1003,
        "peer_pid": 2000 + index,
        "operation_id": f"operation-{index}",
        "operation": "test.plan" if index % 2 else "inventory",
        "project_id": "project-a",
        "ok": ok,
        "code": code,
        "message": "bounded diagnostic",
        "request": {"repo_id": "repository-a", "run_id": f"run-{index}"},
        "result": {},
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="devcoordinator-call-reader-") as raw:
        path = Path(raw) / "calls.jsonl"
        journal = RollingCallJournal(path, max_bytes=8192, backups=2)
        for index in range(1, 6):
            journal.append(
                record(
                    index,
                    ok=index in {1, 3, 5},
                    code=None if index in {1, 3, 5} else "snapshot_failed",
                )
            )
        journal.append(
            {
                "schema_version": 1,
                "record_id": "received-record",
                "call_id": "received-call",
                "phase": "received",
                "outcome": "received",
                "repository_id": "repository-b",
                "operation": "snapshot.resolve",
                "ok": False,
            }
        )

        completed, output = invoke(path)
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(output, dict)
        expect(output["returned_count"] == 5, "default reader limit is not five")
        expect(output["matched_count"] == 6, "reader matched count is inaccurate")
        expect(output["eligible_count"] == 6, "reader eligible count is inaccurate")
        expect(output["omitted_count"] == 1, "reader omitted count is inaccurate")
        expect(output["next_cursor"] == "record-2", "reader cursor is not deterministic")
        expect(output["retained_byte_count"] > 0, "reader lost retained byte count")
        expect(output["retained_file_count"] == 1, "reader lost retained file count")
        expect("journal" not in output, "default reader exposed its journal path")
        expect("retained_files" not in output, "default reader exposed retained paths")
        expect(str(path) not in completed.stdout, "default reader output contains a path")

        completed, older = invoke(
            path,
            "--before",
            output["next_cursor"],
            "--limit",
            "2",
        )
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(older, dict)
        expect(
            [item["record_id"] for item in older["records"]] == ["record-1"],
            "reader cursor did not select only older matching records",
        )
        expect(older["matched_count"] == 6, "cursor changed the total matched count")
        expect(older["eligible_count"] == 1, "cursor eligible count is inaccurate")
        expect(older["omitted_count"] == 0, "cursor omitted count is inaccurate")

        completed, output = invoke(path, "--failures-only", "--limit", "1")
        expect(completed.returncode == 0, completed.stderr)
        expect(isinstance(output, dict), "reader did not return a JSON envelope")
        assert isinstance(output, dict)
        expect(output["returned_count"] == 1, "failure/limit filter was not applied")
        expect(
            output["records"][0]["operation_id"] == "operation-4",
            "reader did not retain the newest matching record",
        )
        completed, output = invoke(
            path,
            "--repository-id",
            "repository-a",
            "--run-id",
            "run-3",
        )
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(output, dict)
        expect(
            [item["record_id"] for item in output["records"]] == ["record-3"],
            "nested correlation filters did not select the exact record",
        )

        completed, output = invoke(path, "--call-id", "call-2")
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(output, dict)
        expect(
            [item["record_id"] for item in output["records"]] == ["record-2"],
            "call-id filter did not select the exact lifecycle",
        )

        completed, output = invoke(
            path,
            "--repository-id",
            "repository-b",
            "--failures-only",
        )
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(output, dict)
        expect(
            output["records"] == [],
            "a generic received lifecycle record was misreported as a failure",
        )

        journal.append(
            {
                "schema_version": 1,
                "record_id": "pair-received",
                "call_id": "pair-call",
                "phase": "received",
                "outcome": "received",
                "operation": "test.plan_preview",
                "ok": False,
            }
        )
        journal.append(
            {
                "schema_version": 1,
                "record_id": "pair-terminal",
                "call_id": "pair-call",
                "phase": "rejected",
                "outcome": "failed",
                "operation": "test.plan_preview",
                "operation_id": "paired-operation",
                "run_id": "paired-run",
                "code": "snapshot_failed",
                "ok": False,
            }
        )
        completed, output = invoke(path, "--run-id", "paired-run")
        expect(completed.returncode == 0, completed.stderr)
        assert isinstance(output, dict)
        expect(
            [item["record_id"] for item in output["records"]]
            == ["pair-received", "pair-terminal"],
            "exact run filter did not preserve its received/terminal lifecycle",
        )
        expect(output["pairing"] == "exact_call_lifecycle", "pairing was not disclosed")

        completed, _output = invoke(path, "--limit", "21")
        expect(completed.returncode != 0, "unbounded reader limit was accepted")

        completed, output = invoke(path, "--before", "missing-record")
        expect(completed.returncode == 2, "expired cursor was silently accepted")
        assert isinstance(output, dict)
        expect(output["code"] == "call_journal_page_invalid", "cursor error is untyped")

        missing_root = Path(raw) / "read-only-missing"
        missing_root.mkdir()
        missing = missing_root / "missing.jsonl"
        missing_root.chmod(0o555)
        try:
            completed, output = invoke(missing)
            expect(completed.returncode == 0, completed.stderr)
            assert isinstance(output, dict)
            expect(
                output["records"] == []
                and output["retained_byte_count"] == 0
                and output["retained_file_count"] == 0,
                "missing journal did not produce an honest empty result",
            )
            expect(
                tuple(missing_root.iterdir()) == (),
                "missing-journal read created a lock or data file",
            )
        finally:
            missing_root.chmod(0o755)

        read_only_root = Path(raw) / "read-only-existing"
        read_only_root.mkdir()
        read_only_path = read_only_root / "calls.jsonl"
        read_only_journal = RollingCallJournal(read_only_path)
        read_only_journal.append(record(50, ok=True))
        read_only_lock = read_only_path.with_name(read_only_path.name + ".lock")
        read_only_path.chmod(0o444)
        read_only_lock.chmod(0o444)
        before = {
            item.name: (item.stat().st_ino, item.stat().st_size, item.stat().st_mode)
            for item in read_only_root.iterdir()
        }
        read_only_root.chmod(0o555)
        try:
            completed, output = invoke(read_only_path)
            expect(completed.returncode == 0, completed.stderr)
            assert isinstance(output, dict)
            expect(
                [item["record_id"] for item in output["records"]] == ["record-50"],
                "read-only journal did not return its retained record",
            )
            after = {
                item.name: (
                    item.stat().st_ino,
                    item.stat().st_size,
                    item.stat().st_mode,
                )
                for item in read_only_root.iterdir()
            }
            expect(after == before, "read-only journal metadata or entries changed")
        finally:
            read_only_root.chmod(0o755)

        large_path = Path(raw) / "large-calls.jsonl"
        large = RollingCallJournal(large_path, max_bytes=64 * 1024, backups=0)
        for index in range(20):
            item = record(100 + index, ok=False, code="bounded_failure")
            item["message"] = (
                f"failure at /private/repository/source-{index}.py "
                "token=top-secret "
                + ("x" * 1500)
            )
            item["raw_payload"] = {"path": "/must/not/escape", "secret": "nope"}
            large.append(item)
        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--log",
                str(large_path),
                "--limit",
                "20",
                "--format",
                "jsonl",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        expect(completed.returncode == 0, completed.stderr.decode("utf-8"))
        expect(
            len(completed.stdout) <= MAX_CALL_JOURNAL_PAGE_BYTES
            and completed.stdout.endswith(b"\n"),
            "JSONL final output violated its exact byte/newline contract",
        )
        lines = [json.loads(line) for line in completed.stdout.splitlines()]
        metadata = lines[0]
        expect(metadata["matched_count"] == 20, "JSONL lost matched count")
        expect(
            metadata["returned_count"] + metadata["omitted_count"] == 20,
            "JSONL returned/omitted counts are contradictory",
        )
        rendered = completed.stdout.decode("utf-8")
        expect("/private/" not in rendered, "JSONL exposed a source path")
        expect("top-secret" not in rendered, "JSONL exposed a secret")
        expect("raw_payload" not in rendered, "JSONL exposed a raw payload")

        installer = load_module(
            "call_log_release_installer",
            ROOT / "scripts" / "install_availability_release.py",
        )
        expect(
            installer.WRAPPERS.get("devcoordinator-call-log")
            == ("python", "scripts/read_coordinator_call_log.py", ()),
            "immutable release omits the diagnostic call-log wrapper",
        )
        expect(
            Path("scripts/read_coordinator_call_log.py") in installer.SOURCE_FILES,
            "immutable release omits the diagnostic call-log source",
        )
        wrapper = installer.wrapper_payload(
            "devcoordinator-call-log",
            *installer.WRAPPERS["devcoordinator-call-log"],
        ).decode("utf-8")
        expect(
            "scripts/read_coordinator_call_log.py" in wrapper,
            "diagnostic wrapper does not execute the release-owned reader",
        )
        test_wrapper = installer.wrapper_payload(
            "devcoordinator-test",
            *installer.WRAPPERS["devcoordinator-test"],
        ).decode("utf-8")
        expect(
            "DEVCOORDINATOR_CALL_LOG=/var/log/devcoordinator/calls.jsonl"
            in test_wrapper,
            "installed test client does not record its bounded CLI boundary",
        )

        topology = load_module(
            "call_log_topology",
            ROOT / "scripts" / "check_availability_topology.py",
        )
        authority_source = ROOT / "deploy" / "devcoordinator-authority.service"
        broken_flags = Path(raw) / "missing-call-log" / authority_source.name
        broken_flags.parent.mkdir()
        shutil.copyfile(authority_source, broken_flags)
        broken_flags.write_text(
            broken_flags.read_text(encoding="utf-8").replace(
                " --call-log /var/log/devcoordinator/calls.jsonl",
                "",
                1,
            ),
            encoding="utf-8",
        )
        codes = {
            finding.code
            for finding in topology.validate_service(
                broken_flags,
                topology.SERVICE_CONTRACTS["devcoordinator-authority.service"],
            )
        }
        expect(
            "authority_call_journal_invalid" in codes,
            "topology accepted an authority without its bounded call journal",
        )

        broken_directory = Path(raw) / "missing-log-directory" / authority_source.name
        broken_directory.parent.mkdir()
        shutil.copyfile(authority_source, broken_directory)
        broken_directory.write_text(
            broken_directory.read_text(encoding="utf-8").replace(
                "LogsDirectory=devcoordinator\n",
                "",
                1,
            ),
            encoding="utf-8",
        )
        codes = {
            finding.code
            for finding in topology.validate_service(
                broken_directory,
                topology.SERVICE_CONTRACTS["devcoordinator-authority.service"],
            )
        }
        expect(
            "authority_call_journal_directory_invalid" in codes,
            "topology accepted a protected authority without a writable log directory",
        )

        api_source = ROOT / "deploy" / "devcoordinator-api.service"
        broken_environment = Path(raw) / "missing-call-environment" / api_source.name
        broken_environment.parent.mkdir()
        shutil.copyfile(api_source, broken_environment)
        broken_environment.write_text(
            broken_environment.read_text(encoding="utf-8").replace(
                "Environment=DEVCOORDINATOR_CALL_LOG_BACKUPS=4\n",
                "",
                1,
            ),
            encoding="utf-8",
        )
        codes = {
            finding.code
            for finding in topology.validate_service(
                broken_environment,
                topology.SERVICE_CONTRACTS[api_source.name],
            )
        }
        expect(
            "call_journal_environment_invalid" in codes,
            "topology accepted a call boundary with divergent retention settings",
        )

        broken_shared_directory = (
            Path(raw) / "non-shared-call-directory" / api_source.name
        )
        broken_shared_directory.parent.mkdir()
        shutil.copyfile(api_source, broken_shared_directory)
        broken_shared_directory.write_text(
            broken_shared_directory.read_text(encoding="utf-8").replace(
                "LogsDirectoryMode=0777",
                "LogsDirectoryMode=0755",
                1,
            ),
            encoding="utf-8",
        )
        codes = {
            finding.code
            for finding in topology.validate_service(
                broken_shared_directory,
                topology.SERVICE_CONTRACTS[api_source.name],
            )
        }
        expect(
            "call_journal_directory_invalid" in codes,
            "topology accepted a call boundary that could not rotate the shared journal",
        )

    print("Coordinator call-log operational self-test passed (24 contracts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
