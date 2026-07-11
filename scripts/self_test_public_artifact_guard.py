#!/usr/bin/env python3
"""Recall and false-positive tests for the publishable-artifact guard."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path
from shutil import rmtree


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "public_artifact_guard.py"


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def png_bytes(*, metadata: str | None = None) -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    text = png_chunk(b"tEXt", b"Source\x00" + metadata.encode("utf-8")) if metadata else b""
    pixels = png_chunk(b"IDAT", zlib.compress(b"\x00\x20\x40\x60\xff"))
    return signature + ihdr + text + pixels + png_chunk(b"IEND", b"")


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def git(repo: Path, *args: str) -> None:
    result = subprocess.run(["git", *args], cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")


def run_guard(repo: Path, *, expect: int, extra: list[str] | None = None) -> dict:
    result = subprocess.run(
        [sys.executable, str(GUARD), "--repo", str(repo), "--json", *(extra or [])],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"guard expected {expect}, got {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(result.stdout)


def provenance(path: Path, *, digest: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "artifact_type": "test-fixture-snapshot",
        "source": "isolated-test-fixture",
        "fixture_id": "neutral-ops-v1",
        "generator": "FixtureRenderer",
        "width": 1,
        "height": 1,
        "sha256": digest or hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="public-artifact-guard-self-test-"))
    external_target = tmp.parent / f"{tmp.name}-external.md"
    try:
        git(tmp, "init", "-q")

        private_home = "/" + "Users" + "/real.operator/Projects/customer-console"
        private_linux_home = "/" + "home" + "/realoperator/work/customer-console"
        private_windows_home = "C:" + "\\Users\\realoperator\\work\\customer-console"
        dollar_bearing_secret = "realprod" + "$" + "LeakedPass123"
        write(
            tmp / "docs" / "unsafe.md",
            "\n".join(
                [
                    f"Local capture: {private_home}",
                    f"Linux capture: {private_linux_home}",
                    f"Windows capture: {private_windows_home}",
                    "Command: coordinator server start --agent real.operator --project /fixtures/project",  # public-artifact-guard: allow text-literal-username
                    "Authorization: Bearer " + "ghp_" + ("A" * 36),
                    "POSTGRES_PASSWORD=" + "production-value-4Hh7s91x",
                    f"DEPLOY_TOKEN={dollar_bearing_secret}",
                ]
            ),
        )
        write(
            tmp / "docs" / "safe.md",
            "\n".join(
                [
                    "Use $HOME/.codex or ~/.codex rather than a private absolute path.",
                    "Portable examples may say /Users/<username>/src or /home/example/src.",
                    "The public deployment checkout is /home/DevCoordinator/apps/DevOpsConsole.",
                    "Use --agent \"$USER\" or --agent fixture-agent in tests.",
                    "Authorization: Bearer <contents-of-token>",
                    "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}",
                    "DEPLOY_TOKEN=$DEPLOY_TOKEN",
                    "API_TOKEN=fixture-token",
                ]
            ),
        )
        write(tmp / "docs" / "dollar-secret.env", f"DEPLOY_TOKEN={dollar_bearing_secret}\n")

        write(external_target, "safe external content must not bypass repository boundaries\n")
        write(tmp / "docs" / "internal-target.md", "safe internal linked content\n")
        (tmp / "docs" / "external-link.md").symlink_to(external_target)
        (tmp / "docs" / "internal-link.md").symlink_to("internal-target.md")

        unsafe_metadata = tmp / "artifacts" / "unsafe-metadata.png"
        write(unsafe_metadata, png_bytes(metadata=private_home))

        missing_provenance = tmp / "artifacts" / "missing-provenance.png"
        write(missing_provenance, png_bytes())

        forged = tmp / "artifacts" / "forged.png"
        write(forged, png_bytes())
        forged_payload = provenance(forged, digest="0" * 64)
        write(Path(f"{forged}.provenance.json"), json.dumps(forged_payload, indent=2) + "\n")

        safe_png = tmp / "artifacts" / "safe.png"
        write(safe_png, png_bytes())
        write(Path(f"{safe_png}.provenance.json"), json.dumps(provenance(safe_png), indent=2) + "\n")

        write(tmp / ".gitignore", "ignored/\n")
        git(tmp, "add", ".")

        untracked_private = tmp / "docs" / "untracked-private.md"
        write(untracked_private, f"Untracked capture: {private_home}\n")
        untracked_png = tmp / "artifacts" / "untracked-missing-provenance.png"
        write(untracked_png, png_bytes())
        write(tmp / "ignored" / "private.md", f"Ignored local note: {private_home}\n")
        write(tmp / "ignored" / "local.png", png_bytes(metadata=private_home))

        report = run_guard(tmp, expect=1)
        rules = {item["rule"] for item in report["findings"]}
        for rule in {
            "text-private-home",
            "text-literal-username",
            "text-secret",
            "png-sensitive-metadata",
            "png-missing-provenance",
            "png-provenance-mismatch",
            "publishable-external-symlink",
            "publishable-symlink",
        }:
            check(rule in rules, f"must-catch class was not detected: {rule}")
        check(not any(item["path"] == "docs/safe.md" for item in report["findings"]), "portable placeholder documentation must not be flagged")
        check(not any(item["path"] == "artifacts/safe.png" for item in report["findings"]), "clean PNG with valid fixture provenance must not be flagged")
        check(any(item["path"] == "docs/dollar-secret.env" and item["rule"] == "text-secret" for item in report["findings"]), "a bare dollar inside a literal secret must not become a placeholder bypass")
        check(any(item["path"] == "docs/untracked-private.md" for item in report["findings"]), "non-ignored untracked text must be scanned")
        check(any(item["path"] == "artifacts/untracked-missing-provenance.png" for item in report["findings"]), "non-ignored untracked PNGs must be scanned")
        check(not any(item["path"].startswith("ignored/") for item in report["findings"]), "ignored local-only files must not be scanned")
        check(any(item["path"] == "docs/external-link.md" for item in report["findings"]), "external symlink must be rejected before following it")
        check(any(item["path"] == "docs/internal-link.md" for item in report["findings"]), "internal symlink must require explicit policy opt-in")

        for path in [
            tmp / "docs" / "unsafe.md",
            tmp / "docs" / "dollar-secret.env",
            unsafe_metadata,
            missing_provenance,
            forged,
            Path(f"{forged}.provenance.json"),
            untracked_private,
            untracked_png,
            tmp / "docs" / "external-link.md",
        ]:
            path.unlink()

        internal_allowed = run_guard(tmp, expect=0, extra=["--allow-internal-symlinks"])
        check(internal_allowed["ok"] is True, "explicit internal-symlink policy should allow only in-repository targets")
        (tmp / "docs" / "internal-link.md").unlink()
        clean_report = run_guard(tmp, expect=0)
        check(clean_report["ok"] is True and not clean_report["findings"], "intentional portable artifacts should pass cleanly")

        print("public artifact guard self-test ok")
        return 0
    finally:
        rmtree(tmp, ignore_errors=True)
        external_target.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
