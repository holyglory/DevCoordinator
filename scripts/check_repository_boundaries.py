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
from pathlib import Path


EXPECTED_SKILLS = {"codex-dev-coordinator", "postgres-docker-backup"}
EXPECTED_APPS = {"DevOpsBoard", "DevOpsConsole"}
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
    r"^apps/(?:CodexOpsConsole|DevOpsBoard|DevOpsConsole)/Artifacts/Canonical/[^/]+\.(?:png|jpg|jpeg)$",
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


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    detail: str


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    completed = subprocess.run(
        ["git", *args],
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
    output = git(repo, "ls-files", "-z", text=False)
    assert isinstance(output, bytes)
    return sorted(item.decode("utf-8") for item in output.split(b"\0") if item)


def history_paths(repo: Path) -> list[str]:
    output = git(
        repo,
        "log",
        "--all",
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
            "authenticated no-Docker inventory": 'elif path == "/v1/inventory/no-docker":',
            "protected API path classifier": 'protected = path == "/v1" or path.startswith("/v1/")',
            "protected API authorization": "if not self._require_authorization()",
            "authenticated unsupported method": '_method_not_allowed(("GET",))',
            "bearer validation": "Authorization",
            "atomic checkout relocation": "def relocate_port_assignment(",
            "listener evidence without bind": "def listener_evidence_for_port(",
            "strict explicit registration PID": "def registration_pid_identity(",
            "capability exec boundary": "def clear_exec_capability_inheritance(",
            "unobservable ownership class": "class ListenerIdentityUnobservable(",
            "API capability boundary invocation": "clear_exec_capability_inheritance()\n    host = validate_api_bind_host",
            "relocation CLI": 'port_sub.add_parser("relocate")',
        },
        "console client": {
            "server-side token read": "function readToken()",
            "bearer header": "headers.authorization = `Bearer ${token}`",
            "anonymous health probe": "`${baseUrl}/healthz`",
        },
        "console config": {
            "loopback-only coordinator": "coordinator must be loopback",
            "origin-only coordinator URL": "coordinator URL must name the loopback origin only",
        },
        "console proxy": {
            "protected parent-domain cookies": "const protectedCookieNames = new Set([sessionCookieName, FLOW_COOKIE_NAME]);",
            "HTTP response cookie isolation": "filterResponseHeaders(r.headers, protectedCookieNames)",
            "WebSocket response cookie isolation": "appendSafeRawHeaders(lines, upstreamRes.rawHeaders, protectedCookieNames)",
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
            "service identity": "User=holyglory",
            "service group": "Group=holyglory",
            "external state": "CODEX_AGENT_COORDINATOR_HOME=/home/holyglory/.codex/agent-coordinator",
            "external token": "--token-file /home/holyglory/.codex/agent-coordinator/api-token",
            "bounded authenticated readiness": "ExecStartPost=/usr/bin/python3 /home/DevCoordinator/scripts/check_coordinator_auth_boundary.py",
            "bounded startup deadline": "TimeoutStartSec=20",
            "managed-server-preserving stop": "KillMode=process",
            "matching listener capability": "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "unmodified manager capability ceiling": "Do not narrow CapabilityBoundingSet",
        },
        "console unit": {
            "unit dependency": "Requires=dev-coordinator.service",
            "service identity": "User=holyglory",
            "service group": "Group=holyglory",
            "external env": "EnvironmentFile=/home/holyglory/.config/devops-console/console.env",
            "server-side token": "COORDINATOR_TOKEN_FILE=/home/holyglory/.codex/agent-coordinator/api-token",
            "external state": "ReadWritePaths=/home/holyglory/.local/state/devops-console",
            "console cgroup ownership": "KillMode=control-group",
            "pinned production environment": "ExecStart=/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator COORDINATOR_AUTOSTART=0",
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
            "authenticated no-Docker endpoint": '"/v1/inventory/no-docker"',
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
            "documented Docker omission": "docker.available=null with empty containers/postgres",
        },
        "legacy rollback readiness": {
            "fixed systemd identity": "_require_fixed_unit",
            "exact listener ownership": "_parse_listener_owners",
            "bounded convergence": "RollbackReadinessTimeout",
            "verified public TLS": 'health.get("tls_verify_result") != 0',
            "terminal topology recheck": 'observation["post_listener_topology"]',
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
            "required token phase": "elif require_token:",
        },
        "coordinator auth boundary": {
            "private token read": 'read_private_regular(token_file, label="coordinator token")',
            "authenticated inventory capture": "def fetch_authenticated_inventory(",
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
            "exact coordinator token": 'f"api serve --host 127.0.0.1 --port 29876 --token-file {COORDINATOR_HOME}/api-token"',
            "exact Console environment": 'CONSOLE_ENV = f"{SERVICE_HOME}/.config/devops-console/console.env"',
            "exact Console sandbox": 'CONSOLE_STATE = f"{SERVICE_HOME}/.local/state/devops-console"',
            "exact Console root": '"/usr/bin/env DEVCOORDINATOR_ROOT=/home/DevCoordinator COORDINATOR_AUTOSTART=0 "',
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

    console_artifacts = repo / "apps/DevOpsConsole/Artifacts/Canonical"
    if console_artifacts.is_dir():
        for sidecar in sorted(console_artifacts.glob("*.png.provenance.json")):
            try:
                provenance = json.loads(sidecar.read_text(encoding="utf-8"))
                records = provenance["source_files"]
                current = []
                for record in records:
                    source_path = repo / record["path"]
                    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
                    if digest != record["sha256"]:
                        raise ValueError(f"source hash drift: {record['path']}")
                    current.append({"path": record["path"], "sha256": digest})
                aggregate = "".join(f"{item['path']}\0{item['sha256']}\n" for item in current)
                if hashlib.sha256(aggregate.encode("utf-8")).hexdigest() != provenance["source_sha256"]:
                    raise ValueError("aggregate source hash drift")
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                findings.append(
                    Finding("console-artifact-source-provenance", sidecar.relative_to(repo).as_posix(), str(error))
                )
    return findings


def scan_history(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in history_paths(repo):
        reason = forbidden_history_path(path)
        if reason:
            findings.append(Finding("unsafe-history-path", path, reason))

    objects = git(repo, "rev-list", "--objects", "--all")
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
    commits = git(repo, "rev-list", "--all")
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
                if provenance.get("source") != "isolated-test-fixture":
                    raise ValueError("source is not isolated-test-fixture")
                if provenance.get("sha256") != hashlib.sha256(image).hexdigest():
                    raise ValueError("image SHA-256 does not match sidecar")
                records = provenance.get("source_files")
                if records is not None:
                    if not isinstance(records, list) or not records:
                        raise ValueError("source_files must be a non-empty list when present")
                    current: list[dict[str, str]] = []
                    for record in records:
                        source_path = record.get("path") if isinstance(record, dict) else None
                        recorded_hash = record.get("sha256") if isinstance(record, dict) else None
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
            except (AssertionError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                findings.append(Finding("historical-image-provenance", location, str(error)))

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
    findings = sorted(
        set([*scan_tip(repo), *scan_history(repo)]),
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
