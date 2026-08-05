#!/usr/bin/env python3
"""Validate renewed TLS material and refresh the socket-activated edge.

systemd ``LoadCredential=`` snapshots credential bytes at process start, so a
SIGHUP cannot observe certbot's newly published lineage.  This root-only hook
validates the exact certificate/key pair first, restarts only the edge service
(the 80/443 socket units remain listening), then proves the listener inode and
served leaf certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
from typing import Callable, Sequence


OPENSSL = Path("/usr/bin/openssl")
SYSTEMCTL = Path("/usr/bin/systemctl")
DEFAULT_LINEAGE = Path("/etc/letsencrypt/live/vr.ae")
DEFAULT_UNIT = "devcoordinator-edge.service"


class RefreshError(RuntimeError):
    pass


class Runner:
    def run(self, argv: Sequence[str], *, binary: bool = False) -> bytes | str:
        completed = subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise RefreshError(f"command failed without exposing credential output: {Path(argv[0]).name}")
        return completed.stdout if binary else completed.stdout.decode("utf-8", errors="strict")

    def status(self, argv: Sequence[str]) -> int:
        return subprocess.run(
            list(argv),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode


def _credential(path: Path, *, lineage: Path, private: bool, expected_uid: int) -> Path:
    path = path.absolute()
    lineage = lineage.absolute()
    if path.parent != lineage or path.name not in {"fullchain.pem", "privkey.pem"}:
        raise RefreshError("TLS credential path is outside the exact certbot lineage")
    lexical = path.lstat()
    if not (stat.S_ISLNK(lexical.st_mode) or stat.S_ISREG(lexical.st_mode)):
        raise RefreshError("TLS credential source is not a regular file or certbot symlink")
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_size < 1 or info.st_size > 1024 * 1024:
        raise RefreshError("TLS credential target identity is unsafe")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise RefreshError("TLS private key is group/world accessible")
    return resolved


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def validate_pair(
    *,
    lineage: Path,
    domain: str,
    runner: Runner,
    expected_uid: int = 0,
) -> dict[str, object]:
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain) is None:
        raise RefreshError("TLS domain is invalid")
    cert = lineage / "fullchain.pem"
    key = lineage / "privkey.pem"
    resolved_cert = _credential(cert, lineage=lineage, private=False, expected_uid=expected_uid)
    resolved_key = _credential(key, lineage=lineage, private=True, expected_uid=expected_uid)
    if runner.status([str(OPENSSL), "x509", "-in", str(cert), "-noout", "-checkend", "604800"]) != 0:
        raise RefreshError("renewed certificate is invalid or expires within seven days")
    for host in (domain, f"console.{domain}", f"probe.{domain}"):
        if runner.status([str(OPENSSL), "x509", "-in", str(cert), "-noout", "-checkhost", host]) != 0:
            raise RefreshError(f"renewed certificate does not cover {host}")
    cert_public = runner.run([str(OPENSSL), "x509", "-in", str(cert), "-noout", "-pubkey"], binary=True)
    key_public = runner.run([str(OPENSSL), "pkey", "-in", str(key), "-pubout"], binary=True)
    assert isinstance(cert_public, bytes) and isinstance(key_public, bytes)
    if not cert_public or cert_public != key_public:
        raise RefreshError("renewed certificate and private key do not match")
    leaf_der = runner.run([str(OPENSSL), "x509", "-in", str(cert), "-outform", "DER"], binary=True)
    assert isinstance(leaf_der, bytes)
    return {
        "lineage": str(lineage),
        "cert_target": str(resolved_cert),
        "key_target": str(resolved_key),
        "leaf_sha256": _sha256(leaf_der),
        "public_key_sha256": _sha256(cert_public),
    }


def listener_inode(port: int, *, proc_root: Path = Path("/proc")) -> int:
    found: set[int] = set()
    for name in ("tcp", "tcp6"):
        try:
            rows = (proc_root / "net" / name).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                row_port = int(fields[1].rsplit(":", 1)[1], 16)
                inode = int(fields[9])
            except (IndexError, ValueError):
                continue
            if row_port == port and inode > 0:
                found.add(inode)
    if len(found) != 1:
        raise RefreshError(f"TLS listener identity on port {port} is not unique")
    return next(iter(found))


def served_leaf_sha256(host: str, port: int, *, timeout: float = 5.0) -> str:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as plain:
        with context.wrap_socket(plain, server_hostname=host) as tls:
            return _sha256(tls.getpeercert(binary_form=True))


def refresh(
    *,
    lineage: Path,
    domain: str,
    unit: str = DEFAULT_UNIT,
    port: int = 443,
    check_only: bool = False,
    expected_uid: int = 0,
    runner: Runner | None = None,
    inode_reader: Callable[[int], int] = listener_inode,
    peer_reader: Callable[[str, int], str] = served_leaf_sha256,
) -> dict[str, object]:
    if os.geteuid() != expected_uid:
        raise RefreshError("TLS credential refresh must run as root")
    if re.fullmatch(r"devcoordinator-edge\.service", unit) is None:
        raise RefreshError("TLS refresh unit is invalid")
    if not 1 <= port <= 65535:
        raise RefreshError("TLS refresh port is invalid")
    command = runner or Runner()
    validated = validate_pair(
        lineage=lineage,
        domain=domain,
        runner=command,
        expected_uid=expected_uid,
    )
    if check_only:
        return {"ok": True, "checked": True, "restarted": False, **validated}
    if command.status([str(SYSTEMCTL), "is-active", "--quiet", unit]) != 0:
        raise RefreshError("stable edge service is not active")
    before = inode_reader(port)
    if command.status([str(SYSTEMCTL), "restart", unit]) != 0:
        raise RefreshError("stable edge credential restart failed")
    if command.status([str(SYSTEMCTL), "is-active", "--quiet", unit]) != 0:
        raise RefreshError("stable edge did not return active after credential refresh")
    after = inode_reader(port)
    if before != after:
        raise RefreshError("socket-owned TLS listener identity changed during credential refresh")
    served = peer_reader(f"console.{domain}", port)
    if served != validated["leaf_sha256"]:
        raise RefreshError("stable edge did not serve the renewed certificate")
    return {
        "ok": True,
        "checked": True,
        "restarted": True,
        "listener_inode_before": before,
        "listener_inode_after": after,
        "served_leaf_sha256": served,
        **validated,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lineage", default=str(DEFAULT_LINEAGE))
    parser.add_argument("--domain", default="vr.ae")
    parser.add_argument("--unit", default=DEFAULT_UNIT)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = refresh(
            lineage=Path(arguments.lineage),
            domain=arguments.domain,
            unit=arguments.unit,
            port=arguments.port,
            check_only=arguments.check,
        )
    except (OSError, UnicodeError, RefreshError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
