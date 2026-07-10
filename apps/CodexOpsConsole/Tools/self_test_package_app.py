#!/usr/bin/env python3
"""Python-only provenance, structure, and tamper tests for the app packager."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import stat
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


SCRIPT = Path(__file__).with_name("package_app.py")


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


def main() -> int:
    temp = Path(tempfile.mkdtemp(prefix="codex-ops-app-package-test-"))
    original_app_root = packager.APP_ROOT
    original_repository_root = packager.REPOSITORY_ROOT
    original_run = packager.run
    original_subprocess_run = packager.subprocess.run
    try:
        repository = temp / "repository"
        app_root = repository / "apps" / "CodexOpsConsole"
        source = app_root / "Sources" / "CodexOpsConsole" / "Main.swift"
        package_manifest = app_root / "Package.swift"
        write(package_manifest, "// swift-tools-version: 6.0\n")
        write(source, "@main struct Main { static func main() {} }\n")

        for index, relative in enumerate(packager.RUNTIME_SCRIPTS):
            write(repository / relative, f"#!/usr/bin/env python3\n# helper {index}\n", executable=True)

        binary_dir = app_root / ".build" / "fake" / "debug"
        binary = binary_dir / packager.PRODUCT_NAME
        write(binary, "current executable bytes\n", executable=True)

        calls: list[list[str]] = []

        def fake_run(command: list[str], *, cwd: Path = app_root, capture: bool = False) -> str:
            del cwd, capture
            calls.append(command.copy())
            if command[:2] == ["swift", "build"] and "--show-bin-path" in command:
                return str(binary_dir)
            if command[:2] == ["swift", "build"]:
                return ""
            if command and command[0] == "plutil":
                with Path(command[-1]).open("rb") as stream:
                    plistlib.load(stream)
                return ""
            if command and command[0] == "codesign":
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

        output = temp / "CodexOpsConsole.app"
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

        provenance_path = output / "Contents" / "Resources" / "holyskills-runtime.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        check(provenance["schema_version"] == 2, "packaged provenance schema was not upgraded")
        check(
            provenance["executable"]["sha256"] == digest(executable),
            "packaged provenance does not bind the executable bytes",
        )
        expected_source_paths = ["Package.swift", "Sources/CodexOpsConsole/Main.swift"]
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
