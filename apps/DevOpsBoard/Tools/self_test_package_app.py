#!/usr/bin/env python3
"""Python-only runtime-contract, provenance, structure, and packager tests."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import re
import shutil
import stat
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


SCRIPT = Path(__file__).with_name("package_app.py")
OPS_STORE = SCRIPT.parent.parent / "Sources" / "DevOpsBoard" / "OpsStore.swift"


def load_packager() -> ModuleType:
    spec = importlib.util.spec_from_file_location("package_app", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load package_app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load_packager()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_packaging_error(action: Any, message: str, *, contains: str | None = None) -> None:
    try:
        action()
    except packager.PackagingError as error:
        if contains is not None:
            check(contains in str(error), f"{message}: expected {contains!r}, got {error!r}")
        return
    raise AssertionError(message)


def write(path: Path, data: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    if executable:
        path.chmod(0o755)


def task_cancellation_loop_bodies(source: str) -> list[str]:
    bodies: list[str] = []
    pattern = re.compile(r"\bwhile\s+!Task\.isCancelled\s*\{")
    for match in pattern.finditer(source):
        depth = 1
        cursor = match.end()
        while cursor < len(source) and depth > 0:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        bodies.append(source[match.end() : cursor - 1 if depth == 0 else cursor])
    return bodies


def runtime_contract_findings(source: str) -> set[str]:
    findings: set[str] = set()
    marker = "actor SystemCommandExecutor: CommandExecuting"
    if marker not in source:
        return {"executor-missing"}
    executor = source.split(marker, 1)[1]
    if ".waitUntilExit(" in executor:
        findings.add("blocking-wait")
    if re.search(r"\busleep\s*\(", executor):
        findings.add("blocking-poll")
    if any("budget.isExceeded" in body for body in task_cancellation_loop_bodies(executor)):
        findings.add("output-budget-poll")
    handler = executor.find("process.terminationHandler =")
    launch = executor.find("try process.run()")
    if handler < 0 or launch < 0 or handler > launch:
        findings.add("late-or-missing-termination-handler")
    for name, anchor in {
        "cancellation-watchdog": "withTaskCancellationHandler",
        "timeout-watchdog": ".timedOut",
        "output-limit-watchdog": ".outputLimitExceeded",
        "graceful-termination": "process.terminate()",
        "forced-termination": "SIGKILL",
        "bounded-exit-completion": "processExit.wait(timeout:",
    }.items():
        if anchor not in executor:
            findings.add(name)
    if (
        "SpoolBudget(limit: request.maxOutputBytes) {" not in executor
        or "if shouldSignal { onExceeded() }" not in source
    ):
        findings.add("event-driven-output-limit")
    if "withTaskGroup(" not in source or "OriginInventoryLoadOutcome" not in source:
        findings.add("sequential-origin-inventory")
    if "ordered[outcome.index] = outcome" not in source:
        findings.add("nondeterministic-origin-application")
    return findings


def check_runtime_contract_detector() -> None:
    source = OPS_STORE.read_text(encoding="utf-8")
    check(not runtime_contract_findings(source), "current runtime source violates async execution contracts")

    blocking = source + "\n// realistic stale implementation\nprocess.waitUntilExit()\nusleep(20_000)\n"
    blocking_findings = runtime_contract_findings(blocking)
    check("blocking-wait" in blocking_findings, "runtime guard missed waitUntilExit regression")
    check("blocking-poll" in blocking_findings, "runtime guard missed usleep polling regression")

    output_polling = source.replace(
        "let event = await withTaskCancellationHandler {",
        """let outputTask = Task.detached {
                while !Task.isCancelled {
                    if budget.isExceeded { watchdog.resolve(.outputLimitExceeded); return }
                    try await Task.sleep(for: .milliseconds(20))
                }
            }
            let event = await withTaskCancellationHandler {""",
        1,
    )
    check(
        "output-budget-poll" in runtime_contract_findings(output_polling),
        "runtime guard missed async output-budget polling",
    )

    ordinary_async_sleep = source.replace(
        "try await Task.sleep(for: .seconds(timeout))",
        """while !Task.isCancelled {
                        try await Task.sleep(for: .seconds(timeout))
                        break
                    }""",
        1,
    )
    check(
        "output-budget-poll" not in runtime_contract_findings(ordinary_async_sleep),
        "runtime guard flagged an ordinary async sleep loop that does not inspect the output budget",
    )

    eventless_budget = source.replace("if shouldSignal { onExceeded() }", "if shouldSignal { _ = 0 }", 1)
    check(
        "event-driven-output-limit" in runtime_contract_findings(eventless_budget),
        "runtime guard missed a disconnected output-limit callback",
    )

    late_handler = source.replace(
        "process.terminationHandler = { finished in",
        "try process.run()\n            process.terminationHandler = { finished in",
        1,
    )
    check(
        "late-or-missing-termination-handler" in runtime_contract_findings(late_handler),
        "runtime guard missed post-launch termination handler",
    )

    sequential = source.replace("withTaskGroup(", "withSequentialLoads(", 1)
    check(
        "sequential-origin-inventory" in runtime_contract_findings(sequential),
        "runtime guard missed sequential multi-origin inventory",
    )

    nondeterministic = source.replace("ordered[outcome.index] = outcome", "completionOrder.append(outcome)", 1)
    check(
        "nondeterministic-origin-application" in runtime_contract_findings(nondeterministic),
        "runtime guard missed completion-order inventory application",
    )


def main() -> int:
    check_runtime_contract_detector()
    temp = Path(tempfile.mkdtemp(prefix="devops-board-app-package-test-")).resolve(strict=True)
    original_app_root = packager.APP_ROOT
    original_repository_root = packager.REPOSITORY_ROOT
    original_run = packager.run
    original_subprocess_run = packager.subprocess.run
    try:
        repository = temp / "repository"
        app_root = repository / "apps" / "DevOpsBoard"
        source = app_root / "Sources" / "DevOpsBoard" / "Main.swift"
        package_manifest = app_root / "Package.swift"
        write(package_manifest, "// swift-tools-version: 6.0\n")
        write(source, "@main struct Main { static func main() {} }\n")

        for index, relative in enumerate(packager.RUNTIME_SCRIPTS):
            write(repository / relative, f"#!/usr/bin/env python3\n# helper {index}\n", executable=True)

        binary_dir = app_root / ".build" / "fake" / "debug"
        binary = binary_dir / packager.PRODUCT_NAME
        write(binary, "current executable bytes\n", executable=True)

        calls: list[list[str]] = []
        git_status_output = ""
        head_mismatch_paths: set[str] = set()
        mutate_codesigned_executable = False

        def fake_run(command: list[str], *, cwd: Path = app_root, capture: bool = False) -> str:
            nonlocal mutate_codesigned_executable
            del cwd, capture
            calls.append(command.copy())
            if command[:2] == ["swift", "build"] and "--show-bin-path" in command:
                return str(binary_dir)
            if command[:2] == ["swift", "build"]:
                return ""
            if command[:3] == ["git", "rev-parse", "HEAD"]:
                return "1" * 40
            if command[:3] == ["git", "rev-parse", "HEAD^{tree}"]:
                return "2" * 40
            if command[:2] == ["git", "rev-parse"] and command[2].startswith("HEAD:"):
                return "3" * 40
            if command[:2] == ["git", "hash-object"]:
                relative = next(
                    item.removeprefix("--path=")
                    for item in command
                    if item.startswith("--path=")
                )
                return ("4" if relative in head_mismatch_paths else "3") * 40
            if command[:3] == ["git", "status", "--porcelain"]:
                return git_status_output
            if command and command[0] == "plutil":
                with Path(command[-1]).open("rb") as stream:
                    plistlib.load(stream)
                return ""
            if command and command[0] == "codesign":
                if mutate_codesigned_executable and "--sign" in command:
                    signed_app = Path(command[-1])
                    signed_executable = signed_app / "Contents" / "MacOS" / packager.PRODUCT_NAME
                    signed_executable.write_bytes(
                        signed_executable.read_bytes() + b"realistic-mutated-code-signature\n"
                    )
                return ""
            raise AssertionError(f"unexpected external command: {command}")

        def forbidden_subprocess(*args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            raise AssertionError("packaging self-test must not launch any external process")

        packager.APP_ROOT = app_root
        packager.REPOSITORY_ROOT = repository
        packager.run = fake_run
        packager.subprocess.run = forbidden_subprocess

        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=temp / "missing-sidecar.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "--skip-build accepted an executable without a build sidecar",
            contains="requires current build provenance",
        )

        output = temp / "DevOpsBoard.app"
        result = packager.package_app(
            configuration="debug",
            output=output,
            version="9.8.7",
            build="42",
            skip_build=False,
            sign=False,
            force=False,
        )
        check(result["app"] == str(output), "packager returned the wrong output")
        check(any(command[:2] == ["swift", "build"] for command in calls), "normal packaging did not request a build")
        sidecar = packager.build_provenance_path("debug")
        check(sidecar.is_file() and not sidecar.is_symlink(), "normal packaging did not create a safe build sidecar")
        executable = output / "Contents" / "MacOS" / packager.PRODUCT_NAME
        check(executable.is_file(), "app executable is missing")
        check(stat.S_IMODE(executable.stat().st_mode) & 0o111 != 0, "app executable is not executable")
        with (output / "Contents" / "Info.plist").open("rb") as stream:
            plist = plistlib.load(stream)
        check(plist["CFBundleExecutable"] == packager.PRODUCT_NAME, "Info.plist executable mismatch")
        check(plist["CFBundleIdentifier"] == packager.BUNDLE_IDENTIFIER, "bundle identifier mismatch")
        check(
            plist["CFBundleShortVersionString"] == "9.8.7" and plist["CFBundleVersion"] == "42",
            "version metadata mismatch",
        )

        provenance_path = output / "Contents" / "Resources" / packager.RUNTIME_PROVENANCE_NAME
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        check(provenance["schema_version"] == 4, "packaged provenance schema was not upgraded")
        check(
            provenance["repository"]
            == {"commit": "1" * 40, "tree": "2" * 40, "tracked_changes": False},
            "packaged provenance does not bind the DevCoordinator revision",
        )
        provenance_without_repository = dict(provenance)
        del provenance_without_repository["repository"]
        provenance_path.write_text(
            json.dumps(provenance_without_repository, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        expect_packaging_error(
            lambda: packager.verify_packaged_app(output, require_signature=False),
            "packaged-app verifier accepted missing DevCoordinator revision evidence",
            contains="DevCoordinator revision",
        )
        provenance_path.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        check(
            provenance["executable"]["build_sha256"] == digest(executable),
            "packaged provenance does not bind the verified build executable bytes",
        )
        expected_source_paths = ["Package.swift", "Sources/DevOpsBoard/Main.swift"]
        check(
            [item["path"] for item in provenance["executable"]["build_inputs"]] == expected_source_paths,
            "packaged provenance does not name the exact Package.swift and Swift inputs",
        )
        check(
            all(len(item["sha256"]) == 64 for item in provenance["executable"]["build_inputs"]),
            "packaged provenance is missing per-input hashes",
        )

        for relative in packager.RUNTIME_SCRIPTS:
            canonical = repository / relative
            bundled = output / "Contents" / "Resources" / relative
            check(bundled.is_file() and not bundled.is_symlink(), f"bundled helper missing or linked: {relative}")
            check(digest(canonical) == digest(bundled), f"bundled helper drifted: {relative}")
        check(len(provenance["runtime_helpers"]) == len(packager.RUNTIME_SCRIPTS), "runtime provenance is incomplete")

        # Real macOS codesign rewrites the Mach-O signature bytes. The signed
        # package must preserve the verified pre-sign build hash in provenance,
        # accept the signature-mutated executable, and report its actual final
        # whole-file hash. A no-op codesign fake cannot exercise this boundary.
        mutate_codesigned_executable = True
        signed_output = temp / "signed-DevOpsBoard.app"
        signed_result = packager.package_app(
            configuration="debug",
            output=signed_output,
            version="1.0.0",
            build="1",
            skip_build=True,
            sign=True,
            force=False,
        )
        mutate_codesigned_executable = False
        signed_executable = signed_output / "Contents" / "MacOS" / packager.PRODUCT_NAME
        signed_provenance = json.loads(
            (signed_output / "Contents" / "Resources" / packager.RUNTIME_PROVENANCE_NAME).read_text(
                encoding="utf-8"
            )
        )
        check(
            signed_provenance["executable"]["build_sha256"] == digest(binary),
            "signed provenance lost the verified pre-sign build hash",
        )
        check(
            signed_result["executable_sha256"] == digest(signed_executable),
            "signed package did not report the final executable hash",
        )
        check(
            signed_result["executable_sha256"] != signed_provenance["executable"]["build_sha256"],
            "signed regression fixture did not mutate the executable like real codesign",
        )

        # A commit id is not reproducible provenance when tracked source is
        # dirty. The packager must fail even if the modified file is outside
        # the immediate helper copy loop.
        git_status_output = " M apps/DevOpsBoard/Sources/DevOpsBoard/Main.swift\n"
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=temp / "dirty-tracked-source.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "packager accepted a tracked-dirty checkout while claiming HEAD provenance",
            contains="tracked changes",
        )
        git_status_output = ""

        # Prove the per-input blob detector independently of status output: a
        # stale or compromised status implementation must not let either a
        # Swift input or bundled helper differ from the recorded commit.
        for relative in (
            "apps/DevOpsBoard/Sources/DevOpsBoard/Main.swift",
            packager.RUNTIME_SCRIPTS[0].as_posix(),
        ):
            head_mismatch_paths.add(relative)
            expect_packaging_error(
                lambda relative=relative: packager.package_app(
                    configuration="debug",
                    output=temp / f"head-mismatch-{Path(relative).name}.app",
                    version="1.0.0",
                    build="1",
                    skip_build=True,
                    sign=False,
                    force=False,
                ),
                f"packager accepted input bytes not reconstructible from HEAD: {relative}",
                contains="recorded HEAD blob",
            )
            head_mismatch_paths.remove(relative)

        # Current-source skip-build is the intentional safe control. It must
        # consume the matching build sidecar without even requesting Swift.
        calls.clear()
        skip_output = temp / "current-skip-build.app"
        packager.package_app(
            configuration="debug",
            output=skip_output,
            version="1.0.0",
            build="1",
            skip_build=True,
            sign=False,
            force=False,
        )
        check(not any(command and command[0] == "swift" for command in calls), "--skip-build requested Swift")
        check(
            digest(skip_output / "Contents" / "MacOS" / packager.PRODUCT_NAME) == digest(binary),
            "safe skip-build copied the wrong binary",
        )

        # A metadata-only source change is a false-positive guard: provenance
        # is content-addressed, so touching a source must remain accepted.
        os.utime(source, None)
        touched_output = temp / "touched-source.app"
        packager.package_app(
            configuration="debug",
            output=touched_output,
            version="1.0.0",
            build="1",
            skip_build=True,
            sign=False,
            force=False,
        )

        # A failed atomic publication can be followed by a failed rollback.
        # The user needs the publication error as the primary exception while
        # still retaining both the restoration error and the old app backup
        # as recovery evidence.
        rollback_output = temp / "rollback-preservation.app"
        shutil.copytree(output, rollback_output)
        rollback_marker = rollback_output / "Contents" / "Resources" / "preexisting-marker.txt"
        rollback_marker.write_text("original app must survive\n", encoding="utf-8")
        rollback_backup = rollback_output.with_name(
            f".{rollback_output.name}.previous-{os.getpid()}"
        )
        real_replace = packager.os.replace
        publication_failure = "simulated staging publication failure"
        restoration_failure = "simulated backup restoration failure"

        def fail_publication_and_restoration(source_path: Any, destination_path: Any) -> None:
            source = Path(source_path)
            destination = Path(destination_path)
            if destination == rollback_output and source.name.startswith(
                f".{packager.PRODUCT_NAME}.staging-"
            ):
                raise OSError(publication_failure)
            if source == rollback_backup and destination == rollback_output:
                raise OSError(restoration_failure)
            real_replace(source_path, destination_path)

        packager.os.replace = fail_publication_and_restoration
        try:
            try:
                packager.package_app(
                    configuration="debug",
                    output=rollback_output,
                    version="1.0.0",
                    build="1",
                    skip_build=True,
                    sign=False,
                    force=True,
                )
            except packager.PublicationRollbackError as error:
                check(
                    publication_failure in str(error) and restoration_failure in str(error),
                    f"top-level rollback error did not retain both failures: {error!r}",
                )
                check(
                    isinstance(error.__cause__, OSError)
                    and publication_failure in str(error.__cause__),
                    f"original publication failure was not retained as the cause: {error.__cause__!r}",
                )
            else:
                raise AssertionError("fault-injected publication unexpectedly succeeded")
        finally:
            packager.os.replace = real_replace
        check(not rollback_output.exists(), "failed restoration unexpectedly created the output path")
        check(
            rollback_backup.is_dir()
            and (rollback_backup / "Contents" / "Resources" / "preexisting-marker.txt").read_text(
                encoding="utf-8"
            )
            == "original app must survive\n",
            "failed restoration did not retain the original app backup",
        )
        real_replace(rollback_backup, rollback_output)

        # Exercise the real CLI serialization path as well: package_app.main
        # prints only str(error), so both failures must be visible there
        # without requiring traceback or __cause__ inspection.
        cli_stderr = io.StringIO()
        packager.os.replace = fail_publication_and_restoration
        try:
            with contextlib.redirect_stderr(cli_stderr):
                cli_status = packager.main(
                    [
                        "--configuration",
                        "debug",
                        "--output",
                        str(rollback_output),
                        "--skip-build",
                        "--no-sign",
                        "--force",
                    ]
                )
        finally:
            packager.os.replace = real_replace
        cli_failure = cli_stderr.getvalue()
        check(cli_status == 1, "fault-injected package CLI unexpectedly succeeded")
        check(
            publication_failure in cli_failure and restoration_failure in cli_failure,
            f"package CLI omitted publication or restoration evidence: {cli_failure!r}",
        )
        check(
            rollback_backup.is_dir()
            and (rollback_backup / "Contents" / "Resources" / "preexisting-marker.txt").is_file(),
            "package CLI did not retain the original app backup after failed restoration",
        )
        real_replace(rollback_backup, rollback_output)

        original_source = source.read_text(encoding="utf-8")
        source.write_text(original_source + "// source changed after build\n", encoding="utf-8")
        stale_output = temp / "stale-source.app"
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=stale_output,
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "--skip-build accepted a binary built from stale source",
            contains="build inputs",
        )
        expect_packaging_error(
            lambda: packager.verify_packaged_app(output, require_signature=False),
            "packaged-app verifier accepted an executable bound to stale Swift source",
            contains="build inputs",
        )
        check(not stale_output.exists(), "stale-source rejection left a packaged app")
        source.write_text(original_source, encoding="utf-8")

        original_manifest = package_manifest.read_text(encoding="utf-8")
        package_manifest.write_text(original_manifest + "// manifest changed after build\n", encoding="utf-8")
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=temp / "stale-package-manifest.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "--skip-build accepted a binary built from a stale Package.swift",
            contains="build inputs",
        )
        package_manifest.write_text(original_manifest, encoding="utf-8")

        package_resolved = app_root / "Package.resolved"
        package_resolved.write_text('{"pins": [], "version": 2}\n', encoding="utf-8")
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=temp / "new-package-resolved.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "--skip-build ignored a newly introduced Package.resolved input",
            contains="build inputs",
        )
        package_resolved.unlink()

        original_binary = binary.read_bytes()
        binary.write_bytes(original_binary + b"tampered build output\n")
        binary.chmod(0o755)
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=temp / "tampered-build-binary.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "--skip-build accepted a binary that no longer matched its sidecar",
            contains="executable hash",
        )
        binary.write_bytes(original_binary)
        binary.chmod(0o755)

        packaged_to_tamper = skip_output / "Contents" / "MacOS" / packager.PRODUCT_NAME
        packaged_to_tamper.write_bytes(packaged_to_tamper.read_bytes() + b"tampered packaged executable\n")
        packaged_to_tamper.chmod(0o755)
        expect_packaging_error(
            lambda: packager.verify_packaged_app(skip_output, require_signature=False),
            "packaged-app verifier failed to catch a tampered executable",
            contains="executable",
        )

        bundled_to_tamper = output / "Contents" / "Resources" / packager.RUNTIME_SCRIPTS[0]
        bundled_to_tamper.write_text("tampered helper\n", encoding="utf-8")
        expect_packaging_error(
            lambda: packager.verify_packaged_app(output, require_signature=False),
            "packaged-app verifier failed to catch a tampered runtime helper",
            contains="runtime helper",
        )

        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=touched_output,
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=False,
            ),
            "packager must refuse to overwrite an app without --force",
            contains="already exists",
        )

        external = temp / "external-target.app"
        external.mkdir()
        marker = external / "must-survive.txt"
        marker.write_text("preserve me\n", encoding="utf-8")
        linked_output = temp / "linked-output.app"
        linked_output.symlink_to(external, target_is_directory=True)
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=linked_output,
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=True,
            ),
            "packager must refuse an output path that is a symlink",
            contains="symlink",
        )
        check(marker.read_text(encoding="utf-8") == "preserve me\n", "symlink target was modified")

        real_parent = temp / "real-parent"
        real_parent.mkdir()
        linked_parent = temp / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        expect_packaging_error(
            lambda: packager.package_app(
                configuration="debug",
                output=linked_parent / "nested.app",
                version="1.0.0",
                build="1",
                skip_build=True,
                sign=False,
                force=True,
            ),
            "packager must refuse a symlinked output parent",
            contains="symlink",
        )
        check(not (real_parent / "nested.app").exists(), "packager wrote through a symlinked parent")

        print("app package self-test ok (Python-only; no external process launched)")
        return 0
    finally:
        packager.APP_ROOT = original_app_root
        packager.REPOSITORY_ROOT = original_repository_root
        packager.run = original_run
        packager.subprocess.run = original_subprocess_run
        shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
