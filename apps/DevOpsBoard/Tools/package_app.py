#!/usr/bin/env python3
"""Build and atomically package DevOps Board as a launchable macOS app."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


APP_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = APP_ROOT.parents[1]
PRODUCT_NAME = "DevOpsBoard"
BUNDLE_NAME = "DevOps Board"
# Preserve the existing application identity and settings across the product rename.
BUNDLE_IDENTIFIER = "local.holyskills.codex-ops-console"
RUNTIME_SCRIPTS = (
    Path("skills/codex-dev-coordinator/scripts/dev_coordinator.py"),
    Path("skills/postgres-docker-backup/scripts/postgres_docker_backup.py"),
)
RUNTIME_PACKAGE_DIRECTORIES = (
    Path("skills/codex-dev-coordinator/scripts/devcoordinator"),
)
BUILD_PROVENANCE_SCHEMA = 1
PACKAGED_PROVENANCE_SCHEMA = 4
BUILD_PROVENANCE_DIRECTORY = Path(".build/devcoordinator-packaging")
RUNTIME_PROVENANCE_NAME = "devcoordinator-runtime.json"


class PackagingError(RuntimeError):
    """A safe, user-actionable packaging failure."""


class PublicationRollbackError(PackagingError):
    """Publication and restoration both failed without losing either error."""

    def __init__(
        self,
        *,
        output: Path,
        backup: Path,
        publication_error: BaseException,
        restoration_error: BaseException,
    ) -> None:
        super().__init__(
            f"app publication failed for {output}: {type(publication_error).__name__}: "
            f"{publication_error}; backup restoration also failed: "
            f"{type(restoration_error).__name__}: {restoration_error}; "
            f"original app backup remains at {backup}"
        )
        self.publication_error = publication_error
        self.restoration_error = restoration_error
        self.backup = backup


def run(command: list[str], *, cwd: Path = APP_ROOT, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise PackagingError(f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}".rstrip())
    return (completed.stdout or "").strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_inputs() -> list[dict[str, str]]:
    """Hash the exact package manifest and production Swift source inputs."""

    candidates = [APP_ROOT / "Package.swift"]
    package_resolved = APP_ROOT / "Package.resolved"
    if package_resolved.exists() or package_resolved.is_symlink():
        candidates.append(package_resolved)

    sources = APP_ROOT / "Sources"
    if not sources.is_dir() or sources.is_symlink():
        raise PackagingError("Swift Sources directory is missing or unsafe")
    source_files: list[Path] = []
    for candidate in sorted(sources.rglob("*")):
        if candidate.is_symlink():
            raise PackagingError(f"Swift source tree contains a symlink: {candidate.relative_to(APP_ROOT)}")
        if candidate.is_file() and candidate.suffix == ".swift":
            source_files.append(candidate)
    candidates.extend(source_files)
    if not source_files:
        raise PackagingError("no production Swift source inputs were found")

    evidence: list[dict[str, str]] = []
    for source in candidates:
        if not source.is_file() or source.is_symlink():
            try:
                relative = source.relative_to(APP_ROOT)
            except ValueError:
                relative = source
            raise PackagingError(f"build input is missing or unsafe: {relative}")
        relative = source.relative_to(APP_ROOT).as_posix()
        evidence.append({"path": relative, "sha256": sha256(source)})
    return sorted(evidence, key=lambda item: item["path"])


def build_inputs_sha256(inputs: list[dict[str, str]]) -> str:
    encoded = json.dumps(inputs, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def runtime_source_paths() -> list[Path]:
    """Return the complete production Python runtime copied into the app.

    The coordinator entrypoint imports its normalized SQLite, observation,
    lifecycle, and broker modules at runtime. Packaging only the historical
    monolith would therefore produce a signed app that builds successfully but
    cannot refresh inventory. Tests and bytecode caches are deliberately not
    product runtime inputs.
    """

    paths = list(RUNTIME_SCRIPTS)
    for relative_root in RUNTIME_PACKAGE_DIRECTORIES:
        root = REPOSITORY_ROOT / relative_root
        if not root.is_dir() or root.is_symlink():
            raise PackagingError(f"runtime package is missing or unsafe: {relative_root}")
        for candidate in sorted(root.rglob("*")):
            if candidate.is_symlink():
                raise PackagingError(
                    f"runtime package contains a symlink: {candidate.relative_to(REPOSITORY_ROOT)}"
                )
            if not candidate.is_file() or candidate.suffix != ".py":
                continue
            package_relative = candidate.relative_to(root)
            if "__pycache__" in package_relative.parts or "tests" in package_relative.parts[:-1]:
                continue
            paths.append(candidate.relative_to(REPOSITORY_ROOT))
    return sorted(set(paths), key=lambda item: item.as_posix())


def repository_input_paths(inputs: list[dict[str, str]]) -> list[Path]:
    """Return every tracked source path whose HEAD bytes must reproduce the app."""

    app_relative = APP_ROOT.relative_to(REPOSITORY_ROOT)
    paths = [app_relative / item["path"] for item in inputs]
    paths.extend(runtime_source_paths())
    return sorted(set(paths), key=lambda item: item.as_posix())


def require_head_inputs(paths: list[Path]) -> None:
    """Prove each packaged input is the exact blob recorded by HEAD.

    A clean-looking revision string is not provenance when helper or Swift
    bytes come from an uncommitted worktree.  Compare Git's filtered blob id
    for every current input with the blob id named by HEAD, in addition to the
    repository-wide tracked-change guard below.
    """

    for relative in paths:
        if relative.is_absolute() or relative.as_posix() != str(relative):
            raise PackagingError(f"packaging input is not a portable repository path: {relative}")
        source = REPOSITORY_ROOT / relative
        if not source.is_file() or source.is_symlink():
            raise PackagingError(f"packaging input is missing or unsafe: {relative}")
        try:
            recorded = run(
                ["git", "rev-parse", f"HEAD:{relative.as_posix()}"],
                cwd=REPOSITORY_ROOT,
                capture=True,
            )
        except PackagingError as error:
            raise PackagingError(f"packaging input is not tracked at HEAD: {relative}") from error
        current = run(
            [
                "git",
                "hash-object",
                f"--path={relative.as_posix()}",
                str(source),
            ],
            cwd=REPOSITORY_ROOT,
            capture=True,
        )
        if not recorded or current != recorded:
            raise PackagingError(
                f"packaging input differs from the recorded HEAD blob: {relative}; "
                "commit the exact source before packaging"
            )


def repository_revision(inputs: list[dict[str, str]]) -> dict[str, Any]:
    """Return the reproducible DevCoordinator revision owning all package inputs."""

    commit = run(["git", "rev-parse", "HEAD"], cwd=REPOSITORY_ROOT, capture=True)
    tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=REPOSITORY_ROOT, capture=True)
    tracked_changes = run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPOSITORY_ROOT,
        capture=True,
    )
    if len(commit) != 40 or len(tree) != 40:
        raise PackagingError("DevCoordinator Git revision is unavailable or invalid")
    if tracked_changes:
        raise PackagingError(
            "DevCoordinator has tracked changes; commit the exact source before packaging"
        )
    require_head_inputs(repository_input_paths(inputs))
    return {"commit": commit, "tree": tree, "tracked_changes": False}


def build_provenance_path(configuration: str) -> Path:
    return APP_ROOT / BUILD_PROVENANCE_DIRECTORY / f"{configuration}.json"


def require_app_local_path(path: Path, *, label: str, require_file: bool) -> tuple[Path, Path]:
    """Return a lexical app-local path after rejecting every symlink component."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        relative = absolute.relative_to(APP_ROOT)
    except ValueError as error:
        raise PackagingError(f"{label} must stay inside the app build directory: {absolute}") from error

    current = APP_ROOT
    for part in relative.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as error:
            raise PackagingError(f"cannot validate {label} path component {current}: {error}") from error
        if stat.S_ISLNK(mode):
            raise PackagingError(f"refusing {label} with symlink component: {current}")
    if require_file and (not absolute.is_file() or absolute.is_symlink()):
        raise PackagingError(f"{label} is missing or unsafe: {absolute}")
    return absolute, relative


def make_build_provenance(
    *, configuration: str, binary: Path, inputs: list[dict[str, str]]
) -> dict[str, Any]:
    binary, relative_binary = require_app_local_path(
        binary, label="built executable", require_file=True
    )
    if not os.access(binary, os.X_OK):
        raise PackagingError(f"built executable is not executable: {binary}")
    return {
        "schema_version": BUILD_PROVENANCE_SCHEMA,
        "product": PRODUCT_NAME,
        "configuration": configuration,
        "binary": {
            "path": relative_binary.as_posix(),
            "sha256": sha256(binary),
        },
        "build_inputs": inputs,
        "build_inputs_sha256": build_inputs_sha256(inputs),
    }


def write_build_provenance(configuration: str, provenance: dict[str, Any]) -> Path:
    destination = build_provenance_path(configuration)
    require_app_local_path(destination.parent, label="build provenance directory", require_file=False)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    require_app_local_path(destination.parent, label="build provenance directory", require_file=False)
    if destination.is_symlink():
        raise PackagingError(f"refusing linked build provenance sidecar: {destination}")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(provenance, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def validated_skip_build(configuration: str) -> tuple[Path, dict[str, Any]]:
    sidecar = build_provenance_path(configuration)
    if not sidecar.is_file() or sidecar.is_symlink():
        raise PackagingError(
            f"--skip-build requires current build provenance at {sidecar}; run once without --skip-build"
        )
    require_app_local_path(sidecar, label="build provenance sidecar", require_file=True)
    try:
        provenance = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackagingError(f"build provenance is invalid: {error}") from error
    if not isinstance(provenance, dict):
        raise PackagingError("build provenance must be a JSON object")
    if (
        provenance.get("schema_version") != BUILD_PROVENANCE_SCHEMA
        or provenance.get("product") != PRODUCT_NAME
        or provenance.get("configuration") != configuration
    ):
        raise PackagingError("build provenance identity does not match the requested executable")

    current_inputs = build_inputs()
    recorded_inputs = provenance.get("build_inputs")
    if recorded_inputs != current_inputs:
        raise PackagingError("build inputs differ from the recorded executable; rebuild before packaging")
    if provenance.get("build_inputs_sha256") != build_inputs_sha256(current_inputs):
        raise PackagingError("build input fingerprint does not match the recorded executable")

    binary_record = provenance.get("binary")
    if not isinstance(binary_record, dict) or not isinstance(binary_record.get("path"), str):
        raise PackagingError("build provenance is missing the executable path")
    relative_binary = Path(binary_record["path"])
    if relative_binary.is_absolute() or relative_binary.as_posix() != binary_record["path"]:
        raise PackagingError("build provenance executable path is not a portable relative path")
    binary, _ = require_app_local_path(
        APP_ROOT / relative_binary, label="recorded executable", require_file=True
    )
    if not os.access(binary, os.X_OK):
        raise PackagingError(f"recorded executable is not executable: {binary}")
    if binary_record.get("sha256") != sha256(binary):
        raise PackagingError("recorded executable hash no longer matches the build provenance")
    return binary, provenance


def info_plist(version: str, build: str) -> dict[str, Any]:
    return {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": BUNDLE_NAME,
        "CFBundleExecutable": PRODUCT_NAME,
        "CFBundleIdentifier": BUNDLE_IDENTIFIER,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": BUNDLE_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": build,
        "LSMinimumSystemVersion": "14.0",
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
    }


def require_safe_output(output: Path) -> Path:
    expanded = output.expanduser()
    output = Path(os.path.abspath(os.fspath(expanded)))
    if output.suffix != ".app":
        raise PackagingError("--output must end in .app")
    if output == Path("/") or output == APP_ROOT or output == REPOSITORY_ROOT:
        raise PackagingError("refusing unsafe output path")

    # Inspect the lexical path before any filesystem operation can follow a
    # link. In particular, `Path.resolve()` here would turn an innocent-looking
    # `generated.app` symlink into permission to replace its external target
    # when --force is used.
    for component in (output, *output.parents):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as error:
            raise PackagingError(f"cannot validate output path component {component}: {error}") from error
        if stat.S_ISLNK(mode):
            raise PackagingError(f"refusing output path with symlink component: {component}")
    return output


def copy_runtime_scripts(resources: Path) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    executable_helpers = set(RUNTIME_SCRIPTS)
    for relative in runtime_source_paths():
        source = REPOSITORY_ROOT / relative
        if not source.is_file() or source.is_symlink():
            raise PackagingError(f"runtime helper is missing or unsafe: {relative}")
        destination = resources / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copy2(source, destination, follow_symlinks=False)
        destination.chmod(0o755 if relative in executable_helpers else 0o644)
        if sha256(source) != sha256(destination):
            raise PackagingError(f"runtime helper copy verification failed: {relative}")
        evidence.append({"path": relative.as_posix(), "sha256": sha256(destination)})
    return evidence


def verify_packaged_app(
    app: Path,
    *,
    require_signature: bool,
    expected_build_sha256: str | None = None,
) -> dict[str, Any]:
    app = require_safe_output(app)
    contents = app / "Contents"
    executable = contents / "MacOS" / PRODUCT_NAME
    plist_path = contents / "Info.plist"
    provenance_path = contents / "Resources" / RUNTIME_PROVENANCE_NAME
    if not executable.is_file() or executable.is_symlink() or not os.access(executable, os.X_OK):
        raise PackagingError("packaged executable is missing, linked, or not executable")
    try:
        with plist_path.open("rb") as stream:
            plist = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as error:
        raise PackagingError(f"packaged Info.plist is invalid: {error}") from error
    if plist.get("CFBundleExecutable") != PRODUCT_NAME or plist.get("CFBundleIdentifier") != BUNDLE_IDENTIFIER:
        raise PackagingError("packaged Info.plist identity does not match DevOps Board")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PackagingError(f"runtime provenance is missing or invalid: {error}") from error
    if not isinstance(provenance, dict):
        raise PackagingError("runtime provenance must be a JSON object")
    if (
        provenance.get("schema_version") != PACKAGED_PROVENANCE_SCHEMA
        or provenance.get("product") != PRODUCT_NAME
    ):
        raise PackagingError("runtime provenance identity or schema does not match DevOps Board")

    repository = provenance.get("repository")
    if (
        not isinstance(repository, dict)
        or not isinstance(repository.get("commit"), str)
        or len(repository["commit"]) != 40
        or not isinstance(repository.get("tree"), str)
        or len(repository["tree"]) != 40
        or repository.get("tracked_changes") is not False
    ):
        raise PackagingError("runtime provenance is missing the DevCoordinator revision")

    executable_record = provenance.get("executable")
    if not isinstance(executable_record, dict):
        raise PackagingError("runtime provenance is missing executable evidence")
    expected_executable_path = f"Contents/MacOS/{PRODUCT_NAME}"
    if executable_record.get("path") != expected_executable_path:
        raise PackagingError("runtime provenance names the wrong packaged executable")
    executable_hash = sha256(executable)
    recorded_build_hash = executable_record.get("build_sha256")
    if not isinstance(recorded_build_hash, str) or len(recorded_build_hash) != 64:
        raise PackagingError("runtime provenance is missing the verified build executable hash")
    if expected_build_sha256 is not None and recorded_build_hash != expected_build_sha256:
        raise PackagingError("runtime provenance does not match the verified build executable")
    # Ad-hoc bundle signing legitimately rewrites the Mach-O code signature and
    # therefore its whole-file hash. The copy is compared byte-for-byte with
    # the verified build before signing; after signing, the bundle signature is
    # the integrity boundary. Unsigned packages retain exact whole-file hash
    # verification because their executable bytes must remain unchanged.
    if not require_signature and recorded_build_hash != executable_hash:
        raise PackagingError("packaged executable does not match runtime provenance")
    configuration = executable_record.get("configuration")
    if configuration not in {"debug", "release"}:
        raise PackagingError("runtime provenance has an invalid executable configuration")
    current_inputs = build_inputs()
    if executable_record.get("build_inputs") != current_inputs:
        raise PackagingError("packaged executable build inputs differ from current Swift source")
    if executable_record.get("build_inputs_sha256") != build_inputs_sha256(current_inputs):
        raise PackagingError("packaged executable build-input fingerprint is invalid")
    current_revision = repository_revision(current_inputs)
    if repository != current_revision:
        raise PackagingError("packaged app revision differs from the current reproducible DevCoordinator revision")

    recorded = {
        item.get("path"): item.get("sha256")
        for item in provenance.get("runtime_helpers", [])
        if isinstance(item, dict)
    }
    expected_runtime_paths = runtime_source_paths()
    if set(recorded) != {relative.as_posix() for relative in expected_runtime_paths}:
        raise PackagingError("runtime provenance does not name the complete normalized helper set")
    for relative in expected_runtime_paths:
        source = REPOSITORY_ROOT / relative
        bundled = contents / "Resources" / relative
        if not bundled.is_file() or bundled.is_symlink():
            raise PackagingError(f"bundled runtime helper is missing or linked: {relative}")
        bundled_hash = sha256(bundled)
        if recorded.get(relative.as_posix()) != bundled_hash:
            raise PackagingError(f"bundled runtime helper does not match provenance: {relative}")
        if source.is_file() and sha256(source) != bundled_hash:
            raise PackagingError(f"bundled runtime helper differs from canonical source: {relative}")
    if require_signature:
        run(["codesign", "--verify", "--deep", "--strict", str(app)])
    return {
        "app": str(app),
        "bundle_identifier": BUNDLE_IDENTIFIER,
        "executable_sha256": executable_hash,
        "build_inputs_sha256": executable_record.get("build_inputs_sha256"),
        "runtime_helpers": provenance.get("runtime_helpers", []),
        "signature_verified": require_signature,
    }


def package_app(
    *,
    configuration: str,
    output: Path,
    version: str,
    build: str,
    skip_build: bool,
    sign: bool,
    force: bool,
) -> dict[str, Any]:
    if configuration not in {"debug", "release"}:
        raise PackagingError("configuration must be debug or release")
    output = require_safe_output(output)
    if output.exists() and not force:
        raise PackagingError(f"output already exists; pass --force to replace generated app: {output}")

    if skip_build:
        binary, build_provenance = validated_skip_build(configuration)
    else:
        inputs_before_build = build_inputs()
        run(["swift", "build", "--configuration", configuration])
        binary_dir = Path(
            run(
                ["swift", "build", "--configuration", configuration, "--show-bin-path"],
                capture=True,
            )
        )
        if not binary_dir.is_absolute():
            binary_dir = APP_ROOT / binary_dir
        binary = binary_dir / PRODUCT_NAME
        inputs_after_build = build_inputs()
        if inputs_after_build != inputs_before_build:
            raise PackagingError("Swift build inputs changed while the executable was being built; rebuild")
        build_provenance = make_build_provenance(
            configuration=configuration,
            binary=binary,
            inputs=inputs_after_build,
        )
        write_build_provenance(configuration, build_provenance)

    revision_before_packaging = repository_revision(build_provenance["build_inputs"])

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{PRODUCT_NAME}.staging-", suffix=".app", dir=output.parent))
    try:
        contents = staging / "Contents"
        macos = contents / "MacOS"
        resources = contents / "Resources"
        macos.mkdir(parents=True, mode=0o755)
        resources.mkdir(parents=True, mode=0o755)

        packaged_binary = macos / PRODUCT_NAME
        shutil.copy2(binary, packaged_binary, follow_symlinks=False)
        packaged_binary.chmod(0o755)
        recorded_build_binary = build_provenance.get("binary")
        recorded_build_hash = (
            recorded_build_binary.get("sha256")
            if isinstance(recorded_build_binary, dict)
            else None
        )
        packaged_binary_hash = sha256(packaged_binary)
        if (
            not isinstance(recorded_build_hash, str)
            or sha256(binary) != recorded_build_hash
            or packaged_binary_hash != recorded_build_hash
        ):
            raise PackagingError("packaged executable does not match its verified build provenance")
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump(info_plist(version, build), stream, fmt=plistlib.FMT_XML, sort_keys=True)
        (contents / "PkgInfo").write_bytes(b"APPL????")
        runtime_evidence = copy_runtime_scripts(resources)
        revision_after_copy = repository_revision(build_provenance["build_inputs"])
        if revision_after_copy != revision_before_packaging:
            raise PackagingError("DevCoordinator revision changed while the app was being packaged")
        provenance = {
            "schema_version": PACKAGED_PROVENANCE_SCHEMA,
            "product": PRODUCT_NAME,
            "configuration": configuration,
            "repository": revision_after_copy,
            "executable": {
                "path": f"Contents/MacOS/{PRODUCT_NAME}",
                "build_sha256": packaged_binary_hash,
                "configuration": configuration,
                "build_inputs": build_provenance["build_inputs"],
                "build_inputs_sha256": build_provenance["build_inputs_sha256"],
            },
            "runtime_helpers": runtime_evidence,
        }
        (resources / RUNTIME_PROVENANCE_NAME).write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        run(["plutil", "-lint", str(contents / "Info.plist")])
        if sign:
            run(["codesign", "--force", "--deep", "--sign", "-", str(staging)])
        verified_staging = verify_packaged_app(
            staging,
            require_signature=sign,
            expected_build_sha256=recorded_build_hash,
        )

        backup: Path | None = None
        if output.exists():
            backup = output.with_name(f".{output.name}.previous-{os.getpid()}")
            if backup.exists():
                shutil.rmtree(backup)
            os.replace(output, backup)
        try:
            os.replace(staging, output)
        except BaseException as publication_error:
            if backup and backup.exists() and not output.exists():
                try:
                    os.replace(backup, output)
                except BaseException as restoration_error:
                    # The CLI serializes only str(error), so the top-level
                    # failure must contain both incidents.  Keep the original
                    # publication exception as the explicit cause and retain
                    # the backup for manual recovery.
                    raise PublicationRollbackError(
                        output=output,
                        backup=backup,
                        publication_error=publication_error,
                        restoration_error=restoration_error,
                    ) from publication_error
            raise
        if backup and backup.exists():
            shutil.rmtree(backup)
        staging = Path()
        return {
            **verified_staging,
            "app": str(output),
            "configuration": configuration,
            "signed": sign,
        }
    finally:
        if staging != Path() and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", choices=["debug", "release"], default="release")
    parser.add_argument("--output", default=str(APP_ROOT / ".build" / "app" / f"{PRODUCT_NAME}.app"))
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--build", default="1")
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="reuse only a binary whose current-source provenance sidecar matches exactly",
    )
    parser.add_argument("--no-sign", action="store_true", help="skip ad-hoc signing")
    parser.add_argument("--force", action="store_true", help="replace an existing generated app atomically")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = package_app(
            configuration=args.configuration,
            output=Path(args.output),
            version=args.version,
            build=args.build,
            skip_build=args.skip_build,
            sign=not args.no_sign,
            force=args.force,
        )
    except (OSError, PackagingError) as error:
        print(f"package_app: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else f"packaged {result['app']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
