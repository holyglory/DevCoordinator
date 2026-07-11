#!/usr/bin/env python3
"""Fail closed on private text and unprovenanced publishable PNG artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_METADATA_CHUNKS = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
PORTABLE_USERS = {"devcoordinator", "example", "fixture", "runner", "root", "test", "user", "username"}
PORTABLE_AGENT_MARKERS = ("fixture", "example", "test", "codex", "claude", "agent", "sample")
AGENT_GRAMMAR_WORDS = {"a", "and", "for", "or", "so", "the", "to", "with"}
PLACEHOLDER_SECRET_VALUES = {
    "redacted",
    "do-not-leak",
    "do_not_leak",
    "do-not-audit",
    "not-a-secret",
    "changeme",
}
PLACEHOLDER_SECRET_PREFIXES = (
    "fixture-",
    "example-",
    "dummy-",
    "test-",
    "placeholder-",
    "do-not-audit-",
    "do-not-leak-",
    "do_not_leak_",
    "not-a-secret-",
)
PINNED_DEPLOYMENT_HOME_FILES = {
    "apps/DevOpsConsole/deploy/dev-coordinator.service",
    "apps/DevOpsConsole/deploy/devops-console.service",
    "apps/DevOpsConsole/test/unit.deploy.test.mjs",
    "scripts/check_repository_boundaries.py",
    "scripts/self_test_loaded_systemd_paths.py",
}
PINNED_DEPLOYMENT_HOME_SUFFIXES = (
    "/.codex/agent-coordinator",
    "/.config/devops-console",
    "/.local/state/devops-console",
)

HOME_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])/(?:Users|home)/([A-Za-z0-9._-]+)(?=/)"),
    re.compile(r"(?i)(?:^|[^A-Za-z0-9])(?:[A-Z]:\\Users\\)([^\\/\s]+)(?=\\)"),
)
AGENT_PATTERN = re.compile(r"--agent(?:=|\s+)[\"']?([A-Za-z][A-Za-z0-9._-]+)")
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)Authorization\s*:\s*Bearer\s+(?![<$])[A-Za-z0-9._~+/=-]{16,}"),
)
ENV_SECRET_ASSIGNMENT = re.compile(  # public-artifact-guard: allow text-secret
    r"\b(?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\s*=\s*[\"']?([^\s\"',;}{]{8,})"
)
STRUCTURED_SECRET_ASSIGNMENT = re.compile(  # public-artifact-guard: allow text-secret
    r"(?i)^\s*[\"']?(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)[\"']?\s*:\s*[\"']?([^\s\"',;}{]{8,})"
)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int | None
    detail: str


def publishable_paths(repo: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip() or "git ls-files failed")
    return [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


def suppressed(line: str, rule: str) -> bool:
    marker = "public-artifact-guard: allow "
    return f"{marker}{rule}" in line


def portable_username(value: str) -> bool:
    lowered = value.lower()
    return lowered in PORTABLE_USERS or lowered in AGENT_GRAMMAR_WORDS or any(marker in lowered for marker in PORTABLE_AGENT_MARKERS)


def placeholder_secret(value: str) -> bool:
    normalized = value.strip().strip("\"'")
    lowered = normalized.lower()
    if lowered in PLACEHOLDER_SECRET_VALUES or lowered.startswith(PLACEHOLDER_SECRET_PREFIXES):
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", normalized):
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?][^}]*)?\}", normalized):
        return True
    return re.fullmatch(r"<[A-Za-z0-9 _./:-]+>", normalized) is not None


def approved_pinned_deployment_home(rel_path: Path, line: str, match: re.Match[str]) -> bool:
    if rel_path.as_posix() not in PINNED_DEPLOYMENT_HOME_FILES or match.group(1) != "holyglory":
        return False
    suffix = line[match.end() :]
    return any(suffix.startswith(expected) for expected in PINNED_DEPLOYMENT_HOME_SUFFIXES)


def scan_text(rel_path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in HOME_PATTERNS:
            for match in pattern.finditer(line):
                username = match.group(1)
                if (
                    username.lower() not in PORTABLE_USERS
                    and not approved_pinned_deployment_home(rel_path, line, match)
                    and not suppressed(line, "text-private-home")
                ):
                    findings.append(Finding("text-private-home", rel_path.as_posix(), line_number, "literal private home path"))
                    break
        agent_match = AGENT_PATTERN.search(line)
        if agent_match and not portable_username(agent_match.group(1)) and not suppressed(line, "text-literal-username"):
            findings.append(Finding("text-literal-username", rel_path.as_posix(), line_number, "literal operating-system or agent identity"))
        if not suppressed(line, "text-secret"):
            if any(pattern.search(line) for pattern in SECRET_PATTERNS):
                findings.append(Finding("text-secret", rel_path.as_posix(), line_number, "credential-like literal; value withheld"))
            else:
                assignment = ENV_SECRET_ASSIGNMENT.search(line) or STRUCTURED_SECRET_ASSIGNMENT.search(line)
                if assignment and not placeholder_secret(assignment.group(1)):
                    findings.append(Finding("text-secret", rel_path.as_posix(), line_number, "credential assignment contains a literal value; value withheld"))
    return findings


def png_chunks(data: bytes) -> tuple[int, int, list[tuple[bytes, bytes]]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("invalid PNG signature")
    offset = len(PNG_SIGNATURE)
    chunks: list[tuple[bytes, bytes]] = []
    width: int | None = None
    height: int | None = None
    saw_end = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if crc_end > len(data):
            raise ValueError("truncated PNG payload")
        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack(">I", data[payload_end:crc_end])[0]
        actual_crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"invalid CRC for {kind.decode('ascii', errors='replace')} chunk")
        chunks.append((kind, payload))
        if kind == b"IHDR":
            if length != 13:
                raise ValueError("invalid IHDR length")
            width, height = struct.unpack(">II", payload[:8])
        if kind == b"IEND":
            saw_end = True
            if crc_end != len(data):
                raise ValueError("bytes found after IEND")
            break
        offset = crc_end
    if not saw_end or width is None or height is None:
        raise ValueError("PNG is missing IHDR or IEND")
    return width, height, chunks


def load_provenance(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("provenance must be a JSON object")
    return value


def scan_png(repo: Path, rel_path: Path, publishable: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    path = repo / rel_path
    try:
        data = path.read_bytes()
        width, height, chunks = png_chunks(data)
    except (OSError, ValueError) as exc:
        return [Finding("png-invalid", rel_path.as_posix(), None, str(exc))]

    metadata = sorted({kind.decode("ascii", errors="replace") for kind, _ in chunks if kind in PNG_METADATA_CHUNKS})
    if metadata:
        findings.append(
            Finding(
                "png-sensitive-metadata",
                rel_path.as_posix(),
                None,
                "publishable PNG contains unnecessary metadata chunks: " + ", ".join(metadata),
            )
        )

    provenance_rel = f"{rel_path.as_posix()}.provenance.json"
    provenance_path = repo / provenance_rel
    if provenance_rel not in publishable or not provenance_path.is_file():
        findings.append(Finding("png-missing-provenance", rel_path.as_posix(), None, "publishable PNG lacks a publishable provenance sidecar"))
        return findings
    try:
        provenance = load_provenance(provenance_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        findings.append(Finding("png-invalid-provenance", rel_path.as_posix(), None, f"invalid provenance sidecar: {exc}"))
        return findings

    required = {
        "schema_version": 1,
        "artifact_type": "test-fixture-snapshot",
        "source": "isolated-test-fixture",
    }
    if any(provenance.get(key) != value for key, value in required.items()):
        findings.append(Finding("png-invalid-provenance", rel_path.as_posix(), None, "provenance is not an isolated test-fixture snapshot"))
    for key in ("fixture_id", "generator"):
        if not isinstance(provenance.get(key), str) or not provenance[key].strip():
            findings.append(Finding("png-invalid-provenance", rel_path.as_posix(), None, f"provenance is missing {key}"))
    digest = hashlib.sha256(data).hexdigest()
    if provenance.get("sha256") != digest or provenance.get("width") != width or provenance.get("height") != height:
        findings.append(Finding("png-provenance-mismatch", rel_path.as_posix(), None, "PNG hash or dimensions do not match provenance"))
    return findings


def path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def scan(repo: Path, *, allow_internal_symlinks: bool = False) -> dict[str, Any]:
    paths = publishable_paths(repo)
    publishable = {path.as_posix() for path in paths}
    findings: list[Finding] = []
    scanned = 0
    for rel_path in paths:
        path = repo / rel_path
        if path.is_symlink():
            scanned += 1
            target = path.resolve(strict=False)
            if not path_is_within(target, repo):
                findings.append(
                    Finding(
                        "publishable-external-symlink",
                        rel_path.as_posix(),
                        None,
                        "publishable symlink resolves outside the repository",
                    )
                )
                continue
            if not allow_internal_symlinks:
                findings.append(
                    Finding(
                        "publishable-symlink",
                        rel_path.as_posix(),
                        None,
                        "publishable symlinks are disabled; copy the artifact or opt in to internal links",
                    )
                )
                continue
        if not path.is_file():
            continue
        if not path.is_symlink():
            scanned += 1
        if rel_path.suffix.lower() == ".png":
            findings.extend(scan_png(repo, rel_path, publishable))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            findings.append(Finding("artifact-read-error", rel_path.as_posix(), None, str(exc)))
            continue
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(rel_path, text))
    findings = sorted(set(findings), key=lambda item: (item.path, item.line or 0, item.rule, item.detail))
    return {"ok": not findings, "scanned": scanned, "finding_count": len(findings), "findings": [asdict(item) for item in findings]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check tracked and non-ignored untracked public artifacts for private text and unsafe PNG provenance."
    )
    parser.add_argument("--repo", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--allow-internal-symlinks",
        action="store_true",
        help="allow symlinks only when their resolved target remains inside the repository",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).expanduser().resolve()
    try:
        report = scan(repo, allow_internal_symlinks=args.allow_internal_symlinks)
    except Exception as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"public artifact guard failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ok"]:
        print(f"public artifact guard ok ({report['scanned']} publishable files)")
    else:
        for finding in report["findings"]:
            location = f"{finding['path']}:{finding['line']}" if finding["line"] else finding["path"]
            print(f"{location}: {finding['rule']}: {finding['detail']}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
