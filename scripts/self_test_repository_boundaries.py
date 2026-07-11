#!/usr/bin/env python3
"""Recall and false-positive tests for the DevCoordinator boundary guard."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import copy2, rmtree


SCRIPT = Path(__file__).with_name("check_repository_boundaries.py")


def git(repo: Path, *args: str) -> None:
    completed = subprocess.run(
        ["git", *args], cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {completed.stderr}")


def write(path: Path, content: str | bytes = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=boundary-fixture", "-c", "user.email=fixture@example.invalid", "commit", "-q", "-m", message)


def run(repo: Path, expected: int) -> dict:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", str(repo), "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != expected:
        raise AssertionError(
            f"expected {expected}, got {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def provenance(image: bytes, source_path: str, source: bytes) -> str:
    source_hash = hashlib.sha256(source).hexdigest()
    aggregate = f"{source_path}\0{source_hash}\n".encode("utf-8")
    value = {
        "schema_version": 1,
        "artifact_type": "test-fixture-snapshot",
        "source": "isolated-test-fixture",
        "fixture_id": "boundary-safe-v1",
        "generator": source_path,
        "sha256": hashlib.sha256(image).hexdigest(),
        "source_files": [{"path": source_path, "sha256": source_hash}],
        "source_sha256": hashlib.sha256(aggregate).hexdigest(),
    }
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> int:
    temp = Path(tempfile.mkdtemp(prefix="devcoordinator-boundary-self-test-")).resolve(strict=True)
    try:
        repo = temp / "repo"
        repo.mkdir()
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "boundary-fixture")
        git(repo, "config", "user.email", "fixture@example.invalid")
        for skill in ("codex-dev-coordinator", "postgres-docker-backup"):
            write(repo / "skills" / skill / "SKILL.md", f"---\nname: {skill}\ndescription: fixture\n---\n")
        write(repo / "apps/DevOpsBoard/Sources/DevOpsBoard/App.swift")
        write(repo / "apps/DevOpsConsole/src/app.mjs")
        write(
            repo / "apps/DevOpsConsole/.env.example",
            "GOOGLE_CLIENT_SECRET=\nSESSION_SECRET=\nOPENAI_API_KEY=<token>\n",  # public-artifact-guard: allow text-secret
        )
        write(repo / "apps/DevOpsBoard/Tools/identity.py", 'BUNDLE_ID = "local.holyskills.codex-ops-console"\n')
        safe_image = b"safe canonical fixture"
        safe_source_path = "apps/DevOpsConsole/src/app.mjs"
        safe_source = (repo / safe_source_path).read_bytes()
        safe_image_path = repo / "apps/DevOpsConsole/Artifacts/Canonical/safe.png"
        write(safe_image_path, safe_image)
        write(Path(f"{safe_image_path}.provenance.json"), provenance(safe_image, safe_source_path, safe_source))
        write(
            repo / "docs/history/holyskills-to-devcoordinator.commit-map",
            "old                                      new\n" + "1" * 40 + " " + "2" * 40 + "\n" + "3" * 40 + " " + "4" * 40 + "\n",
        )
        commit(repo, "safe canonical layout")

        # The full guard intentionally requires product contract files. Test
        # path/content classifiers directly for their clean false-positive
        # controls, then use a copy of the real repository for integrated
        # product-contract coverage below.
        spec = importlib.util.spec_from_file_location("boundary_guard", SCRIPT)
        if spec is None or spec.loader is None:
            raise AssertionError("cannot import boundary guard")
        module = importlib.util.module_from_spec(spec)
        sys.modules["boundary_guard"] = module
        spec.loader.exec_module(module)
        unsafe_system_unit = """[Unit]
Description=realistic system service
Documentation=file://%h/app/README.md
[Service]
User = app
EnvironmentFile=%h/.config/app/env
Environment=STATE_HOME=%h/.local/state/app
ExecStartPre=/usr/bin/test -r %h/.config/app/token
ExecStart=/usr/bin/app --token-file %h/.config/app/token
ReadWritePaths=%h/.local/state/app
"""
        unsafe_home_findings = module.unsafe_system_unit_home_findings(
            "deploy/app.service", unsafe_system_unit
        )
        check(
            len(unsafe_home_findings) == 6
            and all(item.rule == "system-unit-manager-home" for item in unsafe_home_findings),
            f"system-manager %h paths were not caught: {unsafe_home_findings}",
        )
        safe_system_unit = """[Unit]
Description=explicit service home
[Service]
User=fixture
# Documentation may mention %h without becoming a directive.
Environment=STATE_HOME=/home/fixture/.local/state/app
Environment=LITERAL_SPECIFIER=%%h
ExecStart=/usr/bin/app --token-file /home/fixture/.config/app/token
"""
        check(
            not module.unsafe_system_unit_home_findings("deploy/app.service", safe_system_unit),
            "explicit service-account paths or comments were falsely flagged",
        )
        root_system_unit = """[Service]
User = root
Environment=ROOT_STATE=%h/.local/state/root-app
"""
        check(
            not module.unsafe_system_unit_home_findings("deploy/root-app.service", root_system_unit),
            "root system service's intentional manager-home path was falsely flagged",
        )
        integrated_unsafe = repo / "deploy" / "worker.service"
        integrated_safe = repo / "deploy" / "root-worker.service"
        write(integrated_unsafe, unsafe_system_unit)
        write(integrated_safe, root_system_unit + "Environment=LITERAL=%%h\n")
        git(repo, "add", integrated_unsafe.relative_to(repo).as_posix(), integrated_safe.relative_to(repo).as_posix())
        integrated_findings = module.scan_tip(repo)
        check(
            any(
                item.rule == "system-unit-manager-home" and item.path == "deploy/worker.service"
                for item in integrated_findings
            ),
            "tracked extra system unit bypassed the repository-wide manager-home scan",
        )
        check(
            not any(
                item.rule == "system-unit-manager-home" and item.path == "deploy/root-worker.service"
                for item in integrated_findings
            ),
            "intentional root service or escaped specifier was falsely flagged by integrated scan",
        )
        git(repo, "reset", "-q", "--", integrated_unsafe.relative_to(repo).as_posix(), integrated_safe.relative_to(repo).as_posix())
        integrated_unsafe.unlink()
        integrated_safe.unlink()
        check(module.forbidden_history_path("apps/DevOpsConsole/.env.example") is None, ".env.example was flagged")
        check(module.forbidden_history_path("skills/postgres-docker-backup/SKILL.md") is None, "skill name was flagged")
        check(
            module.forbidden_history_path("apps/DevOpsConsole/Artifacts/Canonical/projects.png") is None,
            "canonical fixture was flagged",
        )
        baseline_history = module.scan_history(repo)
        check(not baseline_history, f"clean history false positive: {baseline_history}")
        missing_contract_findings = module.scan_tip(repo)
        check(
            any(item.rule == "required-contract-file" for item in missing_contract_findings)
            and any(item.rule == "required-contract-marker" for item in missing_contract_findings),
            "missing production contract files/markers were not caught",
        )

        # A path introduced only in a merge result must still be visible to the
        # history-path detector after a later tip deletes it.
        primary = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.strip()
        git(repo, "checkout", "-q", "-b", "merge-left")
        write(repo / "merge-left.txt")
        commit(repo, "left side")
        git(repo, "checkout", "-q", primary)
        write(repo / "merge-right.txt")
        commit(repo, "right side")
        git(repo, "merge", "--no-commit", "--no-ff", "merge-left")
        merge_only = repo / "apps/DevOpsConsole/design-qa-merge-result.png"
        write(merge_only, b"merge-only unsafe image")
        commit(repo, "merge with unsafe resolution artifact")
        merge_only.unlink()
        commit(repo, "remove merge-only artifact")

        merge_findings = module.scan_history(repo)
        check(
            any("design-qa-merge-result.png" in item.path for item in merge_findings),
            "merge-result-only unsafe path was not caught",
        )

        # Realistic must-catch history survives deletion at the tip.
        write(repo / "apps/DevOpsConsole/design-qa-live-production.png", b"not-a-real-png")
        write(repo / "apps/DevOpsConsole/.env", "SESSION_SECRET=production-value\n")  # public-artifact-guard: allow text-secret
        private_key_fixture = "-----BEGIN " + "PRIVATE KEY-----\n"
        write(repo / "ops/private.key", private_key_fixture)
        write(repo / "runtime-backups/state.json", "{}\n")
        missing_sidecar = repo / "apps/DevOpsConsole/Artifacts/Canonical/missing-sidecar.png"
        write(missing_sidecar, b"canonical name without provenance")
        openai_secret = "sk-" + "A" * 32
        openai_project_secret = "sk-proj-" + "B" * 32
        google_api_secret = "AIza" + "C" * 35
        google_oauth_secret = "GOCSPX-" + "D" * 24
        session_secret = "ab" * 32
        write(
            repo / "docs/accidental-secrets.txt",
            "\n".join(
                [
                    openai_secret,
                    openai_project_secret,
                    google_api_secret,
                    google_oauth_secret,
                    "GOOGLE_CLIENT_SECRET=production-client-secret-value",  # public-artifact-guard: allow text-secret
                    f"SESSION_SECRET={session_secret}",
                ]
            )
            + "\n",
        )
        commit(repo, "accidentally publish runtime artifacts")
        for path in (
            repo / "apps/DevOpsConsole/design-qa-live-production.png",
            repo / "apps/DevOpsConsole/.env",
            repo / "ops/private.key",
            repo / "runtime-backups/state.json",
            missing_sidecar,
            repo / "docs/accidental-secrets.txt",
        ):
            path.unlink()
        (repo / "runtime-backups").rmdir()
        (repo / "ops").rmdir()
        commit(repo, "delete from current tip only")

        # A matching pair may still be historically bad after the image bytes
        # or a declared renderer input changes without refreshing provenance.
        tampered_image_path = repo / "apps/DevOpsConsole/Artifacts/Canonical/tampered.png"
        original_image = b"original deterministic image"
        write(tampered_image_path, original_image)
        write(Path(f"{tampered_image_path}.provenance.json"), provenance(original_image, safe_source_path, safe_source))
        commit(repo, "add a valid canonical pair")
        write(tampered_image_path, b"tampered image bytes")
        write(repo / safe_source_path, "changed renderer source\n")
        commit(repo, "tamper image and source without provenance")
        tampered_image_path.unlink()
        Path(f"{tampered_image_path}.provenance.json").unlink()
        write(repo / safe_source_path, safe_source)
        commit(repo, "remove tampered pair and restore source")

        history_findings = module.scan_history(repo)
        rules = {item.rule for item in history_findings}
        details = "\n".join(f"{item.path}: {item.detail}" for item in history_findings)
        check("unsafe-history-path" in rules, "historical paths were not caught")
        check("unsafe-history-secret" in rules, "historical private-key content was not caught")
        check("historical-image-missing-provenance" in rules, "historical missing sidecar was not caught")
        check("historical-image-provenance" in rules, "historical image/source tampering was not caught")
        for expected in ("design-qa-live-production.png", ".env", "private.key", "runtime-backups/state.json"):
            check(expected in details, f"must-catch historical class missing: {expected}")
        check("missing-sidecar.png" in details, "missing canonical sidecar path was not reported")
        check("tampered.png" in details, "tampered canonical pair was not reported")
        for secret in (openai_secret, openai_project_secret, google_api_secret, google_oauth_secret, session_secret):
            check(secret not in details, "secret value leaked into detector output")

        forbidden_root = "HOLY" + "SKILLS_ROOT"
        write(repo / "scripts/launcher.py", f'ROOT = os.environ["{forbidden_root}"]\n')
        commit(repo, "introduce a cross-repository runtime dependency")
        tip_findings = module.scan_tip(repo)
        check(
            any(item.rule == "cross-repository-dependency" for item in tip_findings),
            "HOLYSKILLS_ROOT source dependency was not caught",
        )

        real_repo = SCRIPT.parents[1]
        real_report = run(real_repo, 0)
        check(real_report["ok"] is True, "real clean repository failed integrated boundary guard")

        # Realistic must-catch control for the tracked private-cutover CLI
        # interface matrix: materialize the current tracked repository in an
        # isolated Git index, then drift one exact candidate option.  This
        # proves the boundary guard owns the executable contract rather than
        # merely accepting its own marker table.
        contract_repo = temp / "cutover-cli-contract-repo"
        contract_repo.mkdir()
        git(contract_repo, "init", "-q")
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=real_repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
        relative_paths = {item.decode("utf-8") for item in tracked if item}
        relative_paths.add("scripts/self_test_cutover_helper_cli_contracts.py")
        for relative in sorted(relative_paths):
            source = real_repo / relative
            if not source.exists() and not source.is_symlink():
                continue
            destination = contract_repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                destination.symlink_to(source.readlink())
            elif source.is_file():
                copy2(source, destination)
        git(contract_repo, "add", "-A")
        clean_contract_findings = module.scan_tip(contract_repo)
        check(
            not any(
                item.rule in {"required-contract-file", "required-contract-marker"}
                and item.path == "scripts/self_test_cutover_helper_cli_contracts.py"
                for item in clean_contract_findings
            ),
            f"clean cutover CLI contract fixture was flagged: {clean_contract_findings}",
        )
        contract_test = contract_repo / "scripts/self_test_cutover_helper_cli_contracts.py"
        contract_body = contract_test.read_text(encoding="utf-8")
        check('"--inventory-output",' in contract_body, "CLI contract fixture omitted inventory evidence argv")
        contract_test.write_text(
            contract_body.replace('"--inventory-output",', '"--renamed-inventory-output",', 1),
            encoding="utf-8",
        )
        drift_findings = module.scan_tip(contract_repo)
        check(
            any(
                item.rule == "required-contract-marker"
                and item.path == "scripts/self_test_cutover_helper_cli_contracts.py"
                and "authenticated inventory evidence argv" in item.detail
                for item in drift_findings
            ),
            "cutover helper CLI option drift was not caught by the repository boundary guard",
        )
        print("repository boundary self-test ok")
        return 0
    finally:
        rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
