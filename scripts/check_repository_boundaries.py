#!/usr/bin/env python3
"""Fail closed on DevCoordinator ownership, independence, and public history."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath


EXPECTED_SKILLS = {"codex-dev-coordinator", "postgres-docker-backup"}
EXPECTED_APPS = {"DevOpsBoard", "DevOpsConsole"}
PUBLIC_HISTORY_REF_PREFIXES = ("refs/heads", "refs/remotes", "refs/tags")
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg"}
PRIVATE_FILE_SUFFIXES = {".der", ".jks", ".key", ".p12", ".pem", ".pfx"}
PRIVATE_DIRECTORY_NAMES = {
    ".codex-db-backups",
    ".private",
    ".runtime-state",
    ".state",
    "credentials",
    "runtime-backup",
    "runtime-backups",
    "secrets",
}
CANONICAL_IMAGE = re.compile(
    r"^apps/(?:CodexOpsConsole|DevOpsBoard|DevOpsConsole)/Artifacts/(?:Canonical/[^/]+|Design/[^/]+-selected-reference)\.(?:png|jpg|jpeg)$",
    re.IGNORECASE,
)
SECRET_CONTENT_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(rb"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"(?m)^[ \t]*SESSION_SECRET[ \t]*=[ \t]*[0-9A-Fa-f]{64}[ \t]*(?:#.*)?$"),
)
GOOGLE_CLIENT_SECRET_ASSIGNMENT = re.compile(
    rb"(?m)^[ \t]*GOOGLE_CLIENT_SECRET[ \t]*=[ \t]*([^\s#]+)"
)
CROSS_DEPENDENCY_PATTERNS = (
    re.compile(r"\bHOLYSKILLS_ROOT\b"),
    re.compile(r"github\.com/holyglory/holyskills", re.IGNORECASE),
    re.compile(r"/(?:Users|home)/[^\s'\"]+/[^\s'\"]*holyskills(?:/|\b)", re.IGNORECASE),
    re.compile(r"(?:\.\./)+holyskills(?:/|\b)", re.IGNORECASE),
)

# Several published main commits, most recently a507505, retained canonical
# image/sidecar bytes but changed renderer inputs without refreshing
# their source bindings. Public history is immutable, so accept only the exact
# tree, image, sidecar, and mismatch-detail tuples below. Current-tip provenance
# remains mandatory and repaired successors replace the stale bindings.
_LEGACY_HISTORICAL_SOURCE_DRIFT_KEYS = frozenset(
    {
        (
            "24179f8205f339066ea3bd1a37c53fd96714e129",
            "apps/DevOpsBoard/Artifacts/Canonical/databases.png",
            "c4d2b324b42b09a49a6ffcaa316fa299c7d7d03d",
            "42f29fae8320846964340261d35b23c4e444fb3c",
        ),
        (
            "24179f8205f339066ea3bd1a37c53fd96714e129",
            "apps/DevOpsBoard/Artifacts/Canonical/dev-servers.png",
            "303f77c3f4f1e58120d519b7931cd619f35e9b4e",
            "d19a0eb99e0f3cb91cabcc1bfbdc2e64974d2b9e",
        ),
        (
            "24179f8205f339066ea3bd1a37c53fd96714e129",
            "apps/DevOpsBoard/Artifacts/Canonical/docker-board.png",
            "4134bcb68ceb5dc7785a12fcd1222ae0310c9e59",
            "a44c603c12783f9710fbd72728405b0f2d6fd159",
        ),
        (
            "24179f8205f339066ea3bd1a37c53fd96714e129",
            "apps/DevOpsBoard/Artifacts/Canonical/menu-action-error.png",
            "842876ee2db927833c0f2d0f494fa27796c3cbac",
            "8770bdb3053dccadb33a6e199a3a036eeb261aa4",
        ),
        (
            "944edc8e7cd6f08beebe9ea7169395aeac335df2",
            "apps/DevOpsConsole/Artifacts/Canonical/login-desktop.png",
            "c923e6e0cd1db244774c982484d336d4cb7d1489",
            "70c86f525098959061b3710e93800b10b3af9d1e",
        ),
        (
            "944edc8e7cd6f08beebe9ea7169395aeac335df2",
            "apps/DevOpsConsole/Artifacts/Canonical/login-mobile.png",
            "c94c0b78c7fe25d57589234a7f9731e449eefe97",
            "39189e448ab2c9689783f3ee00b326247db20b22",
        ),
        (
            "944edc8e7cd6f08beebe9ea7169395aeac335df2",
            "apps/DevOpsConsole/Artifacts/Canonical/projects-desktop.png",
            "17391fd846134764359ec073bbd64b4ed759448f",
            "4ad77eb85a90ebc614b9ff51b5b3e7f153edb59b",
        ),
        (
            "944edc8e7cd6f08beebe9ea7169395aeac335df2",
            "apps/DevOpsConsole/Artifacts/Canonical/projects-mobile.png",
            "b8df5ab7fd431b4040001524fb4226fedb698fcc",
            "8faefd0f7366f7ad4a08d9686c0e5a849d2a86a9",
        ),
    }
)

KNOWN_HISTORICAL_SOURCE_DRIFT = frozenset(
    (*key, detail)
    for key in _LEGACY_HISTORICAL_SOURCE_DRIFT_KEYS
    for detail in (
        "aggregate source hash mismatch",
        "source hash mismatch: apps/DevOpsConsole/src/ui/app.js",
    )
) | frozenset(
    {
        (
            tree,
            image_path,
            image_blob,
            sidecar_blob,
            "source hash mismatch: apps/DevOpsConsole/src/ui/app.css",
        )
        for tree in (
            "462d2124bb13063414fef57d7bb5ee961123772e",
            "a715fd561c89428c5ca00688babf36b450eea11f",
        )
        for image_path, image_blob, sidecar_blob in (
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-desktop.png",
                "c923e6e0cd1db244774c982484d336d4cb7d1489",
                "1c4e714aeb8d2d7af6015a0e5992c8a199f56397",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-mobile.png",
                "c94c0b78c7fe25d57589234a7f9731e449eefe97",
                "2620787edb977c82070c1955f0c3fa10af4ae037",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-desktop.png",
                "17391fd846134764359ec073bbd64b4ed759448f",
                "b86f092091ef19478ab81b41d49be5b9fb444536",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-mobile.png",
                "b8df5ab7fd431b4040001524fb4226fedb698fcc",
                "635827bbff999a2719488b0cde77097018bb7c2d",
            ),
        )
    }
) | frozenset(
    {
        (
            "0925a647bd3584cca08af15087cadcd4c89c713d",
            image_path,
            image_blob,
            sidecar_blob,
            detail,
        )
        for image_path, image_blob, sidecar_blob, detail in (
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-desktop.png",
                "c923e6e0cd1db244774c982484d336d4cb7d1489",
                "f155b9b10dae16288cc8e5971cb5cc84ef343d2b",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-mobile.png",
                "c94c0b78c7fe25d57589234a7f9731e449eefe97",
                "45fdf040df738ee44efdeaed36c60b44b8c9fad1",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-desktop.png",
                "5fefcb7009ef21deee13f4d319864171ee9b00b3",
                "b6d5d17ab60e6c2e8d56a8b9e8fbc689dd396d20",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-mobile.png",
                "ffe502891dc31ffe13ff6f18af41812d1120082b",
                "ca9110a3b60aabffceca3d8281b0615dae83e930",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/tests-detail-desktop.png",
                "fd9359b7f24278abd4baa233736765be453fd2d3",
                "0c0c7e7aa8c9208ab9c6ac5110ef7d8d58cf5570",
                "source hash mismatch: apps/DevOpsConsole/src/ui/app.js",
            ),
        )
    }
) | frozenset(
    {
        (
            "d74262db1a6a14c1ae8a3931edc4aaeb468b966e",
            image_path,
            image_blob,
            sidecar_blob,
            detail,
        )
        for image_path, image_blob, sidecar_blob, detail in (
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-desktop.png",
                "c923e6e0cd1db244774c982484d336d4cb7d1489",
                "f155b9b10dae16288cc8e5971cb5cc84ef343d2b",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/login-mobile.png",
                "c94c0b78c7fe25d57589234a7f9731e449eefe97",
                "45fdf040df738ee44efdeaed36c60b44b8c9fad1",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-desktop.png",
                "5fefcb7009ef21deee13f4d319864171ee9b00b3",
                "b6d5d17ab60e6c2e8d56a8b9e8fbc689dd396d20",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/projects-mobile.png",
                "ffe502891dc31ffe13ff6f18af41812d1120082b",
                "ca9110a3b60aabffceca3d8281b0615dae83e930",
                "source hash mismatch: apps/DevOpsConsole/Tools/canonical-api-fixtures.mjs",
            ),
            (
                "apps/DevOpsConsole/Artifacts/Canonical/tests-detail-desktop.png",
                "fd9359b7f24278abd4baa233736765be453fd2d3",
                "0c0c7e7aa8c9208ab9c6ac5110ef7d8d58cf5570",
                "source hash mismatch: apps/DevOpsConsole/src/ui/app.css",
            ),
        )
    }
)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    detail: str


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={repo}", *args],
        cwd=repo,
        text=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr.strip()}")
    return completed.stdout


def tracked_paths(repo: Path) -> list[str]:
    if not (repo / ".git").exists():
        return sorted(
            path.relative_to(repo).as_posix()
            for path in repo.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
    output = git(repo, "ls-files", "-z", text=False)
    assert isinstance(output, bytes)
    return sorted(item.decode("utf-8") for item in output.split(b"\0") if item)


def public_history_revisions(repo: Path) -> list[str]:
    """Return revisions that can contribute to repository public history.

    Codex keeps private, direct-tree snapshots under ``refs/codex/turn-diffs``.
    Those tool-owned refs are neither branches nor publishable history, and
    including them makes a corrected working-tree fixture continue to fail on
    superseded editor checkpoints.  HEAD still covers a detached checkout;
    inactive branches, remotes, and tags preserve the fail-closed public-history
    scan. A branch currently checked out in another linked worktree is active,
    incomplete source owned by that worktree; its own delivery scans it as
    HEAD. Including it here lets unrelated concurrent edits block a verified
    release before that branch is ready.
    """
    output = git(
        repo,
        "for-each-ref",
        "--format=%(refname)",
        *PUBLIC_HISTORY_REF_PREFIXES,
    )
    assert isinstance(output, str)
    worktrees = git(repo, "worktree", "list", "--porcelain")
    assert isinstance(worktrees, str)
    current = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    ).stdout.strip()
    active_other_branches = {
        line.removeprefix("branch ").strip()
        for line in worktrees.splitlines()
        if line.startswith("branch ") and line.removeprefix("branch ").strip() != current
    }
    refs = {
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.strip() not in active_other_branches
    }
    return ["HEAD", *sorted(refs)]


def history_paths(repo: Path) -> list[str]:
    output = git(
        repo,
        "log",
        *public_history_revisions(repo),
        "--diff-merges=separate",
        "--format=",
        "--name-only",
        "-z",
        text=False,
    )
    assert isinstance(output, bytes)
    return sorted({item.decode("utf-8") for item in output.split(b"\0") if item.strip()})


def forbidden_history_path(path: str) -> str | None:
    value = Path(path)
    lowered = value.name.lower()
    suffix = value.suffix.lower()
    if suffix in IMAGE_SUFFIXES and not CANONICAL_IMAGE.fullmatch(path):
        return "non-canonical historical image"
    if lowered == ".env" or (suffix == ".env" and lowered != ".env.example"):
        return "actual environment file"
    if suffix in PRIVATE_FILE_SUFFIXES:
        return "private key or credential file"
    if any(part.lower() in PRIVATE_DIRECTORY_NAMES for part in value.parts):
        return "runtime secret/state/backup path"
    return None


def validate_selected_design_provenance(
    image_path: str,
    image: bytes,
    provenance: object,
) -> None:
    if not isinstance(provenance, dict):
        raise ValueError("selected-design provenance must be an object")
    if provenance.get("artifact_kind") != "selected-product-design-reference":
        raise ValueError("artifact_kind is not selected-product-design-reference")
    if provenance.get("repository_path") != image_path:
        raise ValueError("repository_path does not match selected design")
    if provenance.get("sha256") != hashlib.sha256(image).hexdigest():
        raise ValueError("image SHA-256 does not match sidecar")
    if provenance.get("bytes") != len(image):
        raise ValueError("image byte count does not match sidecar")
    origin = provenance.get("origin")
    if not isinstance(origin, dict) or origin.get("kind") != "openai-image-generation-result":
        raise ValueError("selected design lacks generated-image origin")
    if not isinstance(origin.get("generation_event"), str) or not origin["generation_event"]:
        raise ValueError("selected design lacks generation identity")


def known_historical_source_drift(
    *,
    tree: str,
    image_path: str,
    image_blob: str,
    sidecar_blob: str,
    detail: str,
) -> bool:
    return (
        tree,
        image_path,
        image_blob,
        sidecar_blob,
        detail,
    ) in KNOWN_HISTORICAL_SOURCE_DRIFT


def production_dependency_paths(paths: list[str]) -> list[str]:
    selected: list[str] = []
    detector_paths = {
        "scripts/check_repository_boundaries.py",
        "scripts/self_test_repository_boundaries.py",
    }
    for path in paths:
        if path in detector_paths:
            continue
        parts = Path(path).parts
        if path.startswith((".github/", ".codex/", "scripts/", "skills/")):
            selected.append(path)
        elif path.startswith("apps/") and any(
            marker in parts
            for marker in ("Sources", "src", "bin", "deploy", "Tools")
        ):
            selected.append(path)
        elif Path(path).name in {"Package.swift", "Package.resolved", "package.json"}:
            selected.append(path)
    return selected


def unsafe_system_unit_home_findings(path: str, text: str) -> list[Finding]:
    """Reject service-user home paths resolved from the system manager's `%h`."""
    findings: list[Finding] = []
    service_user = ""
    section = ""
    active_lines: list[tuple[int, str]] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        active_lines.append((line_number, stripped))
        user_match = re.fullmatch(r"User\s*=\s*(.+)", stripped) if section == "Service" else None
        if user_match:
            service_user = user_match.group(1).strip()

    def has_home_specifier(value: str) -> bool:
        index = 0
        while index < len(value):
            if value[index] != "%":
                index += 1
                continue
            if index + 1 < len(value) and value[index + 1] == "%":
                index += 2
                continue
            if index + 1 < len(value) and value[index + 1] == "h":
                return True
            index += 1
        return False

    if service_user and service_user not in {"0", "root"}:
        for line_number, line in active_lines:
            if has_home_specifier(line):
                findings.append(
                    Finding(
                        "system-unit-manager-home",
                        path,
                        (
                            f"line {line_number}: system unit User={service_user} uses %h; "
                            "the system manager can resolve it to /root instead of the service account home"
                        ),
                    )
                )
    return findings


def scan_tip(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    skills_root = repo / "skills"
    apps_root = repo / "apps"
    actual_skills = {item.name for item in skills_root.iterdir() if item.is_dir()} if skills_root.is_dir() else set()
    actual_apps = {item.name for item in apps_root.iterdir() if item.is_dir()} if apps_root.is_dir() else set()
    if actual_skills != EXPECTED_SKILLS:
        findings.append(
            Finding("tip-skill-ownership", "skills", f"expected {sorted(EXPECTED_SKILLS)}, got {sorted(actual_skills)}")
        )
    if actual_apps != EXPECTED_APPS:
        findings.append(
            Finding("tip-app-ownership", "apps", f"expected {sorted(EXPECTED_APPS)}, got {sorted(actual_apps)}")
        )
    if (apps_root / "CodexOpsConsole").exists():
        findings.append(Finding("tip-legacy-app", "apps/CodexOpsConsole", "legacy app path exists at the current tip"))

    paths = tracked_paths(repo)
    for relative in sorted(path for path in paths if Path(path).suffix == ".service"):
        unit_path = repo / relative
        if not unit_path.is_file() or unit_path.is_symlink():
            continue
        try:
            unit_text = unit_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(unsafe_system_unit_home_findings(relative, unit_text))
    for relative in production_dependency_paths(paths):
        path = repo / relative
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for pattern in CROSS_DEPENDENCY_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding("cross-repository-dependency", relative, "source/build/runtime/CI references holyskills")
                )
                break

    required_files = {
        "coordinator": repo / "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
        "console client": repo / "apps/DevOpsConsole/src/coordinator.mjs",
        "console config": repo / "apps/DevOpsConsole/src/config.mjs",
        "console proxy": repo / "apps/DevOpsConsole/src/proxy.mjs",
        "console server": repo / "apps/DevOpsConsole/src/server.mjs",
        "console entry": repo / "apps/DevOpsConsole/bin/devops-console.mjs",
        "coordinator unit": repo / "apps/DevOpsConsole/deploy/dev-coordinator.service",
        "capability integration": repo / "skills/codex-dev-coordinator/scripts/capability_integration_test.py",
        "console unit": repo / "apps/DevOpsConsole/deploy/devops-console.service",
        "packager": repo / "apps/DevOpsBoard/Tools/package_app.py",
        "board runtime locator": repo / "apps/DevOpsBoard/Sources/DevOpsBoard/Models.swift",
        "production preflight": repo / "scripts/check_production_layout.py",
        "coordinator auth boundary": repo / "scripts/check_coordinator_auth_boundary.py",
        "legacy runtime migration": repo / "scripts/migrate_legacy_console_runtime.py",
        "loaded unit preflight": repo / "scripts/check_loaded_systemd_paths.py",
        "post-cutover registration": repo / "scripts/verify_post_cutover_registration.py",
        "Console registration readiness": repo / "scripts/check_console_registration_ready.py",
        "coordinator HTTP contract": repo / "apps/DevOpsConsole/docs/coordinator-http-api.json",
        "legacy rollback readiness": repo / "scripts/verify_legacy_console_rollback_ready.py",
        "cutover helper CLI contracts": repo / "scripts/self_test_cutover_helper_cli_contracts.py",
        "validation entrypoint": repo / "scripts/validate.py",
        "skill link manager": repo / "scripts/manage_skill_links.py",
    }
    texts: dict[str, str] = {}
    for label, path in required_files.items():
        try:
            texts[label] = path.read_text(encoding="utf-8")
        except OSError:
            findings.append(Finding("required-contract-file", path.relative_to(repo).as_posix(), f"missing {label}"))

    contract_needles = {
        "coordinator": {
            "anonymous health": 'if path == "/healthz":',
            "trusted-loopback no-Docker inventory": 'elif path == "/v1/inventory/no-docker":',
            "protected API path classifier": 'protected = path == "/v1" or path.startswith("/v1/")',
            "trusted request boundary": "def _request_boundary_ok(self) -> bool:",
            "foreign Host rejection": 'self._send(400, {"error": "invalid Host header"})',
            "foreign Origin rejection": 'self._send(403, {"error": "cross-origin requests are forbidden"})',
            "atomic checkout relocation": "def relocate_port_assignment(",
            "listener evidence without bind": "def listener_evidence_for_port(",
            "strict explicit registration PID": "def registration_pid_identity(",
            "capability exec boundary": "def clear_exec_capability_inheritance(",
            "unobservable ownership class": "class ListenerIdentityUnobservable(",
            "API capability boundary invocation": "clear_exec_capability_inheritance()\n    host = validate_api_bind_host",
            "relocation CLI": 'port_sub.add_parser("relocate")',
        },
        "console client": {
            "credential-free request headers": "const headers = {};",
            "anonymous health probe": "`${baseUrl}/healthz`",
        },
        "console config": {
            "loopback-only coordinator": "coordinator must be loopback",
            "origin-only coordinator URL": "coordinator URL must name the loopback origin only",
        },
        "console proxy": {
            "protected parent-domain cookies": "const protectedCookieNames = new Set([sessionCookieName, FLOW_COOKIE_NAME]);",
            "HTTP response cookie isolation": "filterResponseHeaders(r.headers, protectedCookieNames, excluded)",
            "WebSocket response cookie isolation": "appendSafeRawHeaders(lines, upstreamRes.rawHeaders, protectedCookieNames, excluded)",
            "protected route strips caller Authorization": "delete headers.authorization;",
            "protected route injects private upstream Authorization": "headers.authorization = target.upstreamAuthorization;",
            "protected route suppresses upstream HTTP-auth prompts": "UPSTREAM_AUTH_RESPONSE_HEADERS",
        },
        "console server": {
            "explicit production IPv4 bind": "config.bindHost ?? '0.0.0.0'",
        },
        "console entry": {
            "session cookie boundary composition": "sessionCookieName: config.cookieName",
            "required production registration": "COORDINATOR_REGISTRATION_REQUIRED === '1'",
            "bounded production registration": "coordinator self-registration failed after",
            "required registration overrides PORT": "productionEdge && (required || !env.PORT)",
            "explicit production PID": "pid = process.pid",
            "complete registration response": "incomplete or mismatched registration graph",
        },
        "coordinator unit": {
            "loopback bind": "api serve --host 127.0.0.1 --port 29876",
            "non-cascading broker startup dependency": "Wants=network-online.target devcoordinator-broker.service",
            "clean and failed exit supervision": "Restart=always",
            "explicit stdout journal": "StandardOutput=journal",
            "explicit stderr journal": "StandardError=journal",
            "stable journal identity": "SyslogIdentifier=dev-coordinator",
            "bounded journal burst interval": "LogRateLimitIntervalSec=30s",
            "bounded journal burst size": "LogRateLimitBurst=10000",
            "service identity": "User=holyglory",
            "service group": "Group=holyglory",
            "server-wide authority mode": "DEVCOORDINATOR_AUTHORITY=system",
            "external client journal": "CODEX_AGENT_COORDINATOR_HOME=/var/lib/devcoordinator-clients/1000",
            "bounded loopback readiness": "ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py",
            "bounded startup deadline": "TimeoutStartSec=20",
            "managed-server-preserving stop": "KillMode=process",
            "matching listener capability": "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "unmodified manager capability ceiling": "Do not narrow CapabilityBoundingSet",
        },
        "console unit": {
            "non-cascading coordinator startup dependency": "Wants=network-online.target dev-coordinator.service",
            "clean and failed exit supervision": "Restart=always",
            "explicit stdout journal": "StandardOutput=journal",
            "explicit stderr journal": "StandardError=journal",
            "stable journal identity": "SyslogIdentifier=devops-console",
            "bounded journal burst interval": "LogRateLimitIntervalSec=30s",
            "bounded journal burst size": "LogRateLimitBurst=10000",
            "service identity": "User=holyglory",
            "service group": "Group=holyglory",
            "external env": "EnvironmentFile=/home/holyglory/.config/devops-console/console.env",
            "external state": "ReadWritePaths=/home/holyglory/.local/state/devops-console",
            "console cgroup ownership": "KillMode=control-group",
            "pinned production environment": "ExecStart=/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator DEVCOORDINATOR_AUTHORITY=system COORDINATOR_AUTOSTART=0",
            "required registration environment": "COORDINATOR_REGISTRATION_REQUIRED=1",
            "pinned coordinator script": "COORDINATOR_SCRIPT=/home/DevCoordinator/skills/codex-dev-coordinator/scripts/dev_coordinator.py",
            "pinned ACME state": "ACME_WEBROOT=/home/holyglory/.local/state/devops-console/acme",
            "read-only checkout home": "ProtectHome=read-only",
            "fail-closed production preflight": "ExecStartPre=/usr/bin/python3 /home/DevCoordinator/scripts/check_production_layout.py",
            "MainPID registration readiness": "ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_console_registration_ready.py --unit devops-console.service --main-pid $MAINPID",
            "bounded registration deadline": "--wait-seconds 80 --poll-interval-seconds 0.1",
            "bounded Console startup": "TimeoutStartSec=90",
        },
        "capability integration": {
            "real capability fixture": "--ambient-caps=+",
            "asymmetric no-cap recall": "no-cap coordinator did not reproduce listener invisibility",
            "relocation replacement lease": "relocated server, replacement lease, and assignment are not fully linked",
            "managed child non-propagation": "managed child inherited active capability",
            "incapable lifecycle fail closed": "signalled, launched, or changed the registration graph",
            "incapable project atomicity": "partially mutated before identity proof",
            "default bounding ceiling": "capability API narrowed the host's preexisting bounding ceiling",
            "child inherited bounding ceiling": "managed child capability ceiling did not inherit the API's default ceiling",
        },
        "post-cutover registration": {
            "exact systemd PID": '"pid", main_pid',
            "registration proof": "registration identity evidence is missing",
            "exact listener inode": "no exact LISTEN socket inode evidence",
            "replacement lease": "active Console lease reused the retired pre-cutover lease id",
            "bidirectional lease linkage": '"lease_id", lease_id',
        },
        "Console registration readiness": {
            "trusted-loopback targeted no-Docker endpoint": 'f"/v1/inventory/no-docker?{query}"',
            "exact query target": '"port": int(server_port)',
            "shared exact current graph": "verify_current_registration_graph(",
            "systemd MainPID stability": "Console systemd MainPID changed",
            "runtime argv contract": "Console MainPID argv does not match the production contract",
            "clean absence retry": '"pending-clean-absence"',
            "stopped baseline retry": '"pending-stopped-baseline"',
            "active lease conflict": "an active lease still claims the Console port",
            "raw listener MainPID binding": "raw port listener is not the systemd MainPID",
            "terminal deadline recheck": "observation crossed the readiness deadline",
        },
        "coordinator HTTP contract": {
            "documented no-Docker route": '"/v1/inventory/no-docker"',
            "documented readiness semantics": '"no_docker"',
            "documented Docker omission": "without a Docker CLI/daemon probe",
            "documented bounded target": "project, name, and port query target",
            "documented unrelated-work exclusion": "excludes unrelated services",
        },
        "legacy rollback readiness": {
            "fixed systemd identity": "_require_fixed_unit",
            "exact listener ownership": "_parse_listener_owners",
            "bounded convergence": "RollbackReadinessTimeout",
            "verified public TLS": 'health.get("tls_verify_result") != 0',
            "terminal topology recheck": 'observation["post_listener_topology"]',
            "credential-free legacy inventory": '"GET",\n            "/v1/inventory"',
            "shared exact current graph": "verify_current_registration_graph(",
            "explicit legacy graph contract": 'schema_contract="legacy"',
            "captured server identity": "expected_server_id=expected_server_id",
            "captured lease identity": "expected_lease_id=expected_lease_id",
            "absence is identity loss": "captured server identity is absent",
            "unregistered is identity loss": "assignment has lost the captured server identity",
            "stopped baseline retry": '"pending-stopped-baseline"',
            "exact stopped health": "exact 40a dead-process proof",
            "dangling captured lease": "dangling after pruning",
            "replacement lease required": "captured lease survived the ready graph",
            "sanitized registration evidence": 'observation["registration"]',
            "post-registration listeners": 'observation["post_registration_listener_owners"]',
            "post-registration topology": 'observation["post_registration_topology"]',
        },
        "cutover helper CLI contracts": {
            "credential-free production layout argv": '"--coordinator-home",\n            str(coordinator),',
            "state-only migration argv": '"--sync-state-only",',
            "captured coordinator termination argv": '"--role",\n            "coordinator",\n            "--timeout-seconds",\n            "5",',
            "exact stopped listener ports argv": '"--ports",\n            "80",\n            "443",\n            "29876",',
            "trusted-loopback inventory evidence argv": '"--inventory-output",',
            "Console production registration argv": '"check_console_registration_ready.py",',
            "loaded unit evidence argv": '["--evidence", str(evidence)]',
            "real helper subprocess boundary": "subprocess.run(",
            "argparse exit refusal": "completed.returncode != 2",
            "optimized helper subprocesses": "if sys.flags.optimize > 0:",
        },
        "validation entrypoint": {
            "normal cutover CLI matrix": 'run([sys.executable, str(ROOT / "scripts" / "self_test_cutover_helper_cli_contracts.py")])',
            "optimized cutover CLI matrix": 'run([sys.executable, "-O", str(ROOT / "scripts" / "self_test_cutover_helper_cli_contracts.py")])',
        },
        "packager": {
            "coordinator helper": "skills/codex-dev-coordinator/scripts/dev_coordinator.py",
            "postgres helper": "skills/postgres-docker-backup/scripts/postgres_docker_backup.py",
            "single repository commit": '"commit": commit',
            "single repository tree": '"tree": tree',
            "helper hashes": '"runtime_helpers": runtime_evidence',
            "HEAD input equality": "require_head_inputs(repository_input_paths(inputs))",
            "dirty checkout refusal": "DevCoordinator has tracked changes; commit the exact source before packaging",
            "clean provenance assertion": 'repository.get("tracked_changes") is not False',
        },
        "board runtime locator": {
            "DevCoordinator root contract": 'environment["DEVCOORDINATOR_ROOT"]',
            "coordinator skill": 'return "skills/codex-dev-coordinator/scripts/dev_coordinator.py"',
            "postgres skill": 'return "skills/postgres-docker-backup/scripts/postgres_docker_backup.py"',
        },
        "production preflight": {
            "private environment": 'require_file(env_file, 0o600, "Console environment")',
            "private state": 'require_directory(state_dir, 0o700, "Console state")',
            "outside-Git enforcement": 'path must stay outside Git',
            "private coordinator home": 'require_directory(coordinator_home, 0o700, "coordinator home")',
        },
        "coordinator auth boundary": {
            "trusted-loopback status contract": '"foreign_origin_ready": 403,',
            "credential-free inventory capture": "def fetch_local_inventory(",
            "exclusive private evidence": "os.O_WRONLY | os.O_CREAT | os.O_EXCL",
            "inventory output CLI": 'parser.add_argument("--inventory-output")',
        },
        "legacy runtime migration": {
            "live-safe environment phase": "def commit_environment_only(",
            "atomic environment no-replace": "def install_staged_no_replace(",
            "late state source revalidation": "legacy state changed after staging; destination was not replaced",
            "cross-phase rollback": "migration failed and was rolled back",
            "same-filesystem state rollback": "state backup and destination must share a filesystem",
        },
        "loaded unit preflight": {
            "exact loaded properties": "def require_exact(",
            "exact loaded commands": "def require_command(",
            "manager-home refusal": 'if "/root/" in combined:',
            "unresolved-home refusal": 'if "%h" in combined:',
            "drop-in refusal": '"DropInPaths": ""',
            "exact trusted-loopback coordinator": '"api serve --host 127.0.0.1 --port 29876"',
            "exact Console environment": 'CONSOLE_ENV = f"{SERVICE_HOME}/.config/devops-console/console.env"',
            "exact Console sandbox": 'CONSOLE_STATE = f"{SERVICE_HOME}/.local/state/devops-console"',
            "exact Console root": '"/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator DEVCOORDINATOR_AUTHORITY=system COORDINATOR_AUTOSTART=0 "',
        },
        "skill link manager": {
            "real canonical skills directory": "repository skills directory must be a real in-repository directory",
            "no nested canonical links": "canonical skills tree must not contain symlinks",
            "apply-time source identity revalidation": 'require_source_snapshot(source, entry["source_snapshot"])',
            "source swap refusal": "canonical source identity or content changed after planning",
            "rollback ignores swapped source": "direct_link_path_matches",
        },
    }
    for label, needles in contract_needles.items():
        body = texts.get(label, "")
        missing = [name for name, needle in needles.items() if needle not in body]
        if missing:
            findings.append(
                Finding("required-contract-marker", required_files[label].relative_to(repo).as_posix(), ", ".join(missing))
            )

    coordinator_unit = texts.get("coordinator unit", "")
    inherited_sandbox = re.findall(
        r"(?m)^(PrivateTmp|ProtectSystem|ReadWritePaths|NoNewPrivileges|UMask)=",
        coordinator_unit,
    )
    if inherited_sandbox:
        findings.append(
            Finding(
                "coordinator-child-semantics",
                required_files["coordinator unit"].relative_to(repo).as_posix(),
                "generic managed children would inherit: " + ", ".join(sorted(set(inherited_sandbox))),
            )
        )

    packager = texts.get("packager", "")
    helper_occurrences = re.findall(r'Path\("skills/[^\"]+/scripts/[^\"]+\.py"\)', packager)
    if len(helper_occurrences) != 2:
        findings.append(
            Finding("packaged-helper-set", "apps/DevOpsBoard/Tools/package_app.py", "packager must name exactly two helpers")
        )

    console_design_artifacts = repo / "apps/DevOpsConsole/Artifacts/Design"
    if console_design_artifacts.is_dir():
        for image in sorted(console_design_artifacts.glob("*-selected-reference.png")):
            sidecar = Path(f"{image}.provenance.json")
            try:
                validate_selected_design_provenance(
                    image.relative_to(repo).as_posix(),
                    image.read_bytes(),
                    json.loads(sidecar.read_text(encoding="utf-8")),
                )
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
                findings.append(
                    Finding(
                        "console-selected-design-provenance",
                        image.relative_to(repo).as_posix(),
                        str(error),
                    )
                )

    board_root = repo / "apps/DevOpsBoard"
    board_artifacts = board_root / "Artifacts/Canonical"
    if board_artifacts.is_dir():
        for sidecar in sorted(board_artifacts.glob("*.png.provenance.json")):
            try:
                provenance = json.loads(sidecar.read_text(encoding="utf-8"))
                records = provenance["source_files"]
                if (
                    not isinstance(records, list)
                    or not records
                    or not all(isinstance(record, str) for record in records)
                    or len(set(records)) != len(records)
                ):
                    raise ValueError("relative source_files must be unique canonical paths")
                fingerprint = hashlib.sha256()
                for source_path in sorted(records):
                    relative = PurePosixPath(source_path)
                    if (
                        relative.is_absolute()
                        or relative.as_posix() != source_path
                        or any(part in {"", ".", ".."} for part in relative.parts)
                    ):
                        raise ValueError("relative source_files contains a non-canonical path")
                    source = board_root / source_path
                    if not source.is_file():
                        raise ValueError(f"source_files names a missing path: {source_path}")
                    fingerprint.update(source_path.encode("utf-8"))
                    fingerprint.update(b"\0")
                    fingerprint.update(source.read_bytes())
                    fingerprint.update(b"\0")
                if fingerprint.hexdigest() != provenance["source_sha256"]:
                    raise ValueError("aggregate source hash drift")
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                findings.append(
                    Finding("board-artifact-source-provenance", sidecar.relative_to(repo).as_posix(), str(error))
                )
    return findings


def scan_history(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in history_paths(repo):
        reason = forbidden_history_path(path)
        if reason:
            findings.append(Finding("unsafe-history-path", path, reason))

    history_revisions = public_history_revisions(repo)
    objects = git(repo, "rev-list", "--objects", *history_revisions)
    assert isinstance(objects, str)
    object_paths: dict[str, set[str]] = {}
    for line in objects.splitlines():
        oid, separator, path = line.partition(" ")
        if separator:
            object_paths.setdefault(oid, set()).add(path)
    for oid, paths in object_paths.items():
        kind = git(repo, "cat-file", "-t", oid)
        assert isinstance(kind, str)
        if kind.strip() != "blob":
            continue
        size_text = git(repo, "cat-file", "-s", oid)
        assert isinstance(size_text, str)
        if int(size_text.strip()) > 5_000_000:
            continue
        content = git(repo, "cat-file", "blob", oid, text=False)
        assert isinstance(content, bytes)
        assignment = GOOGLE_CLIENT_SECRET_ASSIGNMENT.search(content)
        google_secret = False
        if assignment:
            value = assignment.group(1).strip().strip(b"\"'").lower()
            google_secret = bool(value) and not value.startswith(
                (b"$", b"<", b"dummy-", b"example-", b"fixture-", b"placeholder-", b"test-")
            )
        if google_secret or any(pattern.search(content) for pattern in SECRET_CONTENT_PATTERNS):
            findings.append(
                Finding("unsafe-history-secret", sorted(paths)[0], f"credential/private-key pattern in reachable blob {oid}")
            )

    checked_trees: set[str] = set()
    commits = git(repo, "rev-list", *history_revisions)
    assert isinstance(commits, str)
    for commit in commits.splitlines():
        tree = git(repo, "rev-parse", f"{commit}^{{tree}}")
        assert isinstance(tree, str)
        tree = tree.strip()
        if tree in checked_trees:
            continue
        checked_trees.add(tree)
        output = git(repo, "ls-tree", "-r", "--name-only", "-z", commit, text=False)
        assert isinstance(output, bytes)
        paths = {item.decode("utf-8") for item in output.split(b"\0") if item}
        for image_path in sorted(path for path in paths if CANONICAL_IMAGE.fullmatch(path)):
            sidecar_path = f"{image_path}.provenance.json"
            location = f"{commit}:{image_path}"
            if sidecar_path not in paths:
                findings.append(
                    Finding("historical-image-missing-provenance", location, "canonical image has no same-tree sidecar")
                )
                continue
            try:
                image = git(repo, "show", f"{commit}:{image_path}", text=False)
                sidecar_raw = git(repo, "show", f"{commit}:{sidecar_path}")
                assert isinstance(image, bytes) and isinstance(sidecar_raw, str)
                provenance = json.loads(sidecar_raw)
                if "/Artifacts/Design/" in image_path:
                    validate_selected_design_provenance(
                        image_path,
                        image,
                        provenance,
                    )
                    continue
                if provenance.get("source") != "isolated-test-fixture":
                    raise ValueError("source is not isolated-test-fixture")
                if provenance.get("sha256") != hashlib.sha256(image).hexdigest():
                    raise ValueError("image SHA-256 does not match sidecar")
                records = provenance.get("source_files")
                if records is not None:
                    if not isinstance(records, list) or not records:
                        raise ValueError("source_files must be a non-empty list when present")
                    if all(isinstance(record, str) for record in records):
                        # DevOps Board snapshots bind to source paths relative to
                        # the app's package root. Preserve that generator contract
                        # while resolving every path inside the historical tree.
                        source_root, marker, _ = image_path.partition("/Artifacts/Canonical/")
                        if not marker or len(set(records)) != len(records):
                            raise ValueError("relative source_files must be unique canonical paths")
                        fingerprint = hashlib.sha256()
                        for source_path in sorted(records):
                            relative = PurePosixPath(source_path)
                            if (
                                relative.is_absolute()
                                or relative.as_posix() != source_path
                                or any(part in {"", ".", ".."} for part in relative.parts)
                            ):
                                raise ValueError("relative source_files contains a non-canonical path")
                            tree_path = f"{source_root}/{source_path}"
                            if tree_path not in paths:
                                raise ValueError("source_files names a missing same-tree path")
                            source = git(repo, "show", f"{commit}:{tree_path}", text=False)
                            assert isinstance(source, bytes)
                            fingerprint.update(source_path.encode("utf-8"))
                            fingerprint.update(b"\0")
                            fingerprint.update(source)
                            fingerprint.update(b"\0")
                        if provenance.get("source_sha256") != fingerprint.hexdigest():
                            raise ValueError("aggregate source hash mismatch")
                    elif all(isinstance(record, dict) for record in records):
                        current: list[dict[str, str]] = []
                        for record in records:
                            source_path = record.get("path")
                            recorded_hash = record.get("sha256")
                            if not isinstance(source_path, str) or source_path not in paths:
                                raise ValueError("source_files names a missing same-tree path")
                            source = git(repo, "show", f"{commit}:{source_path}", text=False)
                            assert isinstance(source, bytes)
                            digest = hashlib.sha256(source).hexdigest()
                            if digest != recorded_hash:
                                raise ValueError(f"source hash mismatch: {source_path}")
                            current.append({"path": source_path, "sha256": digest})
                        aggregate = "".join(f"{item['path']}\0{item['sha256']}\n" for item in current)
                        if provenance.get("source_sha256") != hashlib.sha256(aggregate.encode("utf-8")).hexdigest():
                            raise ValueError("aggregate source hash mismatch")
                    else:
                        raise ValueError("source_files must use one supported provenance schema")
            except (AssertionError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                detail = str(error)
                image_blob = git(repo, "rev-parse", f"{commit}:{image_path}")
                sidecar_blob = git(repo, "rev-parse", f"{commit}:{sidecar_path}")
                assert isinstance(image_blob, str) and isinstance(sidecar_blob, str)
                if known_historical_source_drift(
                    tree=tree,
                    image_path=image_path,
                    image_blob=image_blob.strip(),
                    sidecar_blob=sidecar_blob.strip(),
                    detail=detail,
                ):
                    continue
                findings.append(Finding("historical-image-provenance", location, detail))

    mapping = repo / "docs/history/holyskills-to-devcoordinator.commit-map"
    try:
        mapping_text = mapping.read_text(encoding="utf-8")
    except OSError:
        findings.append(Finding("history-attribution-map", mapping.relative_to(repo).as_posix(), "mapping file is missing"))
    else:
        rows = [line for line in mapping_text.splitlines()[1:] if line.strip()]
        if not mapping_text.startswith("old                                      new\n") or len(rows) < 2:
            findings.append(
                Finding("history-attribution-map", mapping.relative_to(repo).as_posix(), "mapping header or rows are incomplete")
            )
    return findings


def scan(repo: Path) -> dict[str, object]:
    history = scan_history(repo) if (repo / ".git").exists() else []
    findings = sorted(
        set([*scan_tip(repo), *history]),
        key=lambda item: (item.rule, item.path, item.detail),
    )
    return {
        "ok": not findings,
        "finding_count": len(findings),
        "findings": [asdict(item) for item in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    repo = Path(args.repo).expanduser().resolve()
    try:
        report = scan(repo)
    except Exception as error:
        report = {"ok": False, "error": str(error)}
        status = 2
    else:
        status = 0 if report["ok"] else 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report.get("ok"):
        print("repository boundary and reachable-history guard ok")
    elif "findings" in report:
        for finding in report["findings"]:
            print(f"{finding['path']}: {finding['rule']}: {finding['detail']}")
    else:
        print(f"repository boundary guard failed: {report['error']}", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
