"""Fail-closed production host gate for the universal-test execution plane."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import tempfile
from typing import Callable, Mapping, Sequence
import uuid


Runner = Callable[..., subprocess.CompletedProcess[str]]
MINIMUM_SYSTEMD_VERSION = 249
PREFLIGHT_ATTESTATION_KIND = "devcoordinator-universal-test-host-preflight-attestation"
RELEASE_SCRIPT_RELATIVE = Path(
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_preflight.py"
)
DEFAULT_EXECUTOR = Path("/usr/bin/python3")
MAX_CHECKS = 32


class TestPlanePreflightError(RuntimeError):
    pass


def _safe_executable(path: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise TestPlanePreflightError("required executable is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111:
        raise TestPlanePreflightError("required executable is unsafe")
    return str(resolved)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise TestPlanePreflightError("release binding could not be hashed") from error
    return digest.hexdigest()


def _canonical(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _seal(document: Mapping[str, object]) -> dict[str, object]:
    sealed = dict(document)
    if "document_sha256" in sealed:
        raise TestPlanePreflightError("preflight attestation is already sealed")
    sealed["document_sha256"] = hashlib.sha256(_canonical(sealed)).hexdigest()
    return sealed


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _host_nonloopback_ipv4(explicit: str | None = None) -> str:
    """Resolve one address assigned through the host's non-loopback route."""

    candidates: list[str] = []
    if explicit is not None:
        candidates.append(explicit)
    else:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connecting UDP selects a local route without sending a packet.
            probe.connect(("192.0.2.1", 9))
            candidates.append(str(probe.getsockname()[0]))
        except OSError:
            pass
        finally:
            probe.close()
        try:
            candidates.extend(
                str(item[4][0])
                for item in socket.getaddrinfo(
                    socket.gethostname(),
                    None,
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                )
            )
        except OSError:
            pass
    for candidate in candidates:
        try:
            address = ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        if not (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        ):
            return str(address)
    raise TestPlanePreflightError(
        "host has no usable non-loopback IPv4 address for isolation proof"
    )


def _host_boot_id(path: Path) -> str:
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise TestPlanePreflightError("host boot identity is unavailable") from error
    if len(raw) > 64:
        raise TestPlanePreflightError("host boot identity is invalid")
    value = raw.strip().lower()
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise TestPlanePreflightError("host boot identity is invalid") from error
    if str(parsed) != value:
        raise TestPlanePreflightError("host boot identity is invalid")
    return value


def _release_binding(
    *,
    release_root: Path,
    release_digest: str,
    script: Path,
    executor: Path,
) -> dict[str, str]:
    if re.fullmatch(r"[0-9a-f]{64}", release_digest) is None:
        raise TestPlanePreflightError("release digest is invalid")
    try:
        canonical_root = release_root.resolve(strict=True)
    except OSError as error:
        raise TestPlanePreflightError("immutable release root is unavailable") from error
    if not canonical_root.is_dir():
        raise TestPlanePreflightError("immutable release root is invalid")
    expected_script = canonical_root / release_digest / RELEASE_SCRIPT_RELATIVE
    try:
        script_info = expected_script.lstat()
        canonical_script = expected_script.resolve(strict=True)
        supplied_script = script.absolute()
    except OSError as error:
        raise TestPlanePreflightError("immutable preflight script is unavailable") from error
    if (
        supplied_script != expected_script
        or canonical_script != expected_script
        or stat.S_ISLNK(script_info.st_mode)
        or not stat.S_ISREG(script_info.st_mode)
        or script_info.st_mode & 0o222
    ):
        raise TestPlanePreflightError("immutable preflight script binding is invalid")
    executor_name = str(executor)
    if not executor.is_absolute():
        raise TestPlanePreflightError("preflight executor path is invalid")
    canonical_executor = Path(_safe_executable(executor))
    return {
        "release_root": str(canonical_root),
        "release_digest": release_digest,
        "executor": executor_name,
        "executor_sha256": _sha256_file(canonical_executor),
        "script": str(expected_script),
        "script_sha256": _sha256_file(expected_script),
    }


def _installed_release_binding(
    script: Path = Path(__file__),
    executor: Path = DEFAULT_EXECUTOR,
) -> dict[str, str]:
    try:
        canonical_script = script.resolve(strict=True)
    except OSError as error:
        raise TestPlanePreflightError("installed preflight script is unavailable") from error
    if len(canonical_script.parents) <= 4:
        raise TestPlanePreflightError("installed preflight script is outside a release")
    release = canonical_script.parents[4]
    return _release_binding(
        release_root=release.parent,
        release_digest=release.name,
        script=canonical_script,
        executor=executor,
    )


def _run(runner: Runner, argv: Sequence[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TestPlanePreflightError("host capability probe could not execute") from error
    if len(result.stdout or "") + len(result.stderr or "") > 64 * 1024:
        raise TestPlanePreflightError("host capability probe returned excessive output")
    return result


def production_test_plane_preflight(
    *,
    release_root: Path,
    release_digest: str,
    script: Path,
    runner: Runner = subprocess.run,
    effective_uid: int | None = None,
    systemd_run: Path = Path("/usr/bin/systemd-run"),
    executor: Path = DEFAULT_EXECUTOR,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    systemd_runtime: Path = Path("/run/systemd/system"),
    credential_root: Path = Path("/run"),
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    host_nonloopback_address: str | None = None,
) -> Mapping[str, object]:
    """Run a live isolated transient and return release-bound activation evidence."""

    uid = os.geteuid() if effective_uid is None else effective_uid
    checks: list[dict[str, object]] = []

    def require(check_id: str, condition: bool, detail: str) -> None:
        checks.append({"id": check_id, "ok": bool(condition), "detail": detail})
        if not condition:
            raise TestPlanePreflightError(detail)

    require("root-authority", uid == 0, "universal test activation requires root authority")
    binding = _release_binding(
        release_root=release_root,
        release_digest=release_digest,
        script=script,
        executor=executor,
    )
    boot_id = _host_boot_id(boot_id_path)
    require("linux-host", platform.system() == "Linux", "universal test activation requires Linux")
    require(
        "cgroup-v2",
        (cgroup_root / "cgroup.controllers").is_file(),
        "universal test activation requires cgroup v2",
    )
    require("systemd-manager", systemd_runtime.is_dir(), "systemd is not the active service manager")
    systemd = _safe_executable(systemd_run)
    executor_path = _safe_executable(executor)
    version = _run(runner, (systemd, "--version"), timeout=10)
    match = re.search(r"\bsystemd\s+(\d+)\b", version.stdout or "")
    require(
        "systemd-version",
        version.returncode == 0 and match is not None and int(match.group(1)) >= MINIMUM_SYSTEMD_VERSION,
        "systemd lacks required namespace/credential controls",
    )

    token = uuid.uuid4().hex
    credential_payload = ("devcoordinator-test-preflight:" + token).encode("ascii")
    credential_digest = hashlib.sha256(credential_payload).hexdigest()
    descriptor, raw_path = tempfile.mkstemp(
        prefix="devcoordinator-test-preflight-", dir=credential_root
    )
    credential_path = Path(raw_path)
    unit = "devcoordinator-test-preflight-" + token
    host_listener: socket.socket | None = None
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, credential_payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        host_address = _host_nonloopback_ipv4(host_nonloopback_address)
        host_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        host_listener.bind(("0.0.0.0", 0))
        host_listener.listen(8)
        host_port = int(host_listener.getsockname()[1])
        probe = (
            "import hashlib,os,socket,sys;"
            "p=os.path.join(os.environ['CREDENTIALS_DIRECTORY'],'fixture-proof');"
            "(hashlib.sha256(open(p,'rb').read()).hexdigest()==os.environ['EXPECTED'])"
            " or sys.exit(71);"
            "s=socket.socket();s.bind(('127.0.0.1',0));s.listen();"
            "c=socket.socket();c.connect(s.getsockname());a,_=s.accept();"
            "c.sendall(b'x');(a.recv(1)==b'x') or sys.exit(72);"
            "a.close();c.close();s.close()"
        )
        result = _run(
            runner,
            (
                systemd,
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                f"--unit={unit}",
                "--property=Type=exec",
                "--property=PrivateNetwork=yes",
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=localhost",
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "--property=NoNewPrivileges=yes",
                "--property=PrivateTmp=yes",
                "--property=PrivateDevices=yes",
                "--property=ProtectSystem=strict",
                "--property=ProtectHome=yes",
                "--property=RuntimeMaxSec=10s",
                f"--property=LoadCredential=fixture-proof:{credential_path}",
                f"--setenv=EXPECTED={credential_digest}",
                "--",
                executor_path,
                "-I",
                "-c",
                probe,
            ),
            timeout=20,
        )
        require(
            "private-loopback-and-credential",
            result.returncode == 0,
            "systemd did not prove private loopback and LoadCredential isolation",
        )
        host_loopback_probe = "\n".join(
            (
                "import socket,sys",
                f"port={host_port}",
                "socket.create_connection(('127.0.0.1',port),timeout=2).close()",
                "try:",
                f"    socket.create_connection(({host_address!r},port),timeout=2).close()",
                "except OSError:",
                "    pass",
                "else:",
                "    sys.exit(73)",
            )
        )
        host_loopback = _run(
            runner,
            (
                systemd,
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                f"--unit={unit}-host-loopback",
                "--property=Type=exec",
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=localhost",
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "--property=NoNewPrivileges=yes",
                "--property=RuntimeMaxSec=10s",
                "--",
                executor_path,
                "-I",
                "-c",
                host_loopback_probe,
            ),
            timeout=20,
        )
        require(
            "host-loopback-host-127",
            host_loopback.returncode == 0,
            "systemd did not preserve host 127 access in host-loopback mode",
        )
        require(
            "host-loopback-nonloopback-denied",
            host_loopback.returncode == 0,
            "systemd did not deny non-loopback host addresses in host-loopback mode",
        )
        private_host_probe = "\n".join(
            (
                "import socket,sys",
                "try:",
                f"    socket.create_connection(('127.0.0.1',{host_port}),timeout=2).close()",
                "except OSError:",
                "    pass",
                "else:",
                "    sys.exit(74)",
            )
        )
        private_host = _run(
            runner,
            (
                systemd,
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                f"--unit={unit}-private-host-denied",
                "--property=Type=exec",
                "--property=PrivateNetwork=yes",
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=localhost",
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "--property=NoNewPrivileges=yes",
                "--property=RuntimeMaxSec=10s",
                "--",
                executor_path,
                "-I",
                "-c",
                private_host_probe,
            ),
            timeout=20,
        )
        require(
            "private-loopback-host-denied",
            private_host.returncode == 0,
            "private loopback unexpectedly reached the host loopback listener",
        )
        namespace = _run(
            runner,
            (
                systemd,
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                f"--unit={unit}-netns",
                "--property=Type=exec",
                "--property=NetworkNamespacePath=/proc/1/ns/net",
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=localhost",
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                "--property=NoNewPrivileges=yes",
                "--property=RuntimeMaxSec=10s",
                f"--property=LoadCredential=fixture-proof:{credential_path}",
                f"--setenv=EXPECTED={credential_digest}",
                "--",
                executor_path,
                "-I",
                "-c",
                probe,
            ),
            timeout=20,
        )
        require(
            "network-namespace-path",
            namespace.returncode == 0,
            "systemd did not prove combined NetworkNamespacePath and credential isolation",
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if host_listener is not None:
            host_listener.close()
        credential_path.unlink(missing_ok=True)
    if len(checks) > MAX_CHECKS:
        raise TestPlanePreflightError("preflight produced excessive check evidence")
    evidence: dict[str, object] = {
        "schema_version": 1,
        "kind": PREFLIGHT_ATTESTATION_KIND,
        "ok": True,
        "blocking": True,
        **binding,
        "observed_at": _now(),
        "host_boot_id": boot_id,
        "systemd_version": int(match.group(1)),
        "checks": checks,
    }
    return _seal(evidence)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", required=True)
    arguments = parser.parse_args(argv)
    del arguments
    try:
        binding = _installed_release_binding()
        document = production_test_plane_preflight(
            release_root=Path(binding["release_root"]),
            release_digest=binding["release_digest"],
            script=Path(binding["script"]),
            executor=Path(binding["executor"]),
        )
    except TestPlanePreflightError as error:
        failure = _seal(
            {
                "schema_version": 1,
                "kind": PREFLIGHT_ATTESTATION_KIND,
                "ok": False,
                "blocking": True,
                "observed_at": _now(),
                "error": str(error),
            }
        )
        print(json.dumps(failure, sort_keys=True))
        return 1
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_EXECUTOR",
    "PREFLIGHT_ATTESTATION_KIND",
    "RELEASE_SCRIPT_RELATIVE",
    "TestPlanePreflightError",
    "production_test_plane_preflight",
]
