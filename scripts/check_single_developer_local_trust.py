#!/usr/bin/env python3
"""Fail fast when same-server metadata becomes an authorization boundary.

DevCoordinator serves one developer through several Unix accounts.  UID/GID
and filesystem metadata are useful for attribution, execution selection and
writing reachable sockets, but they must not decide whether a local request is
accepted.  This static guard covers only the production transport, profile and
publication paths; legacy migration/recovery tooling is deliberately outside
the ordinary release gate.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import sys
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]

LOCAL_SOCKET_UNITS = {
    "deploy/devcoordinator-authority.socket": ("authority", "0666", "0755"),
    "deploy/devcoordinator-testd.socket": ("testd", "0666", "0755"),
    "deploy/devcoordinator-test-snapshotd.socket": (
        "snapshotd",
        "0666",
        "0755",
    ),
    "deploy/devcoordinator-edge-publication.socket": (
        "edge publication",
        "0666",
        "0755",
    ),
}

PRODUCTION_SERVICE_UNITS = (
    "deploy/devcoordinator-edge.service",
    "deploy/devcoordinator-api.service",
    "deploy/devcoordinator-authority.service",
    "deploy/devcoordinator-console@.service",
    "deploy/devcoordinator-observer.service",
    "deploy/devcoordinator-notifications.service",
    "deploy/devcoordinator-testd.service",
    "deploy/devcoordinator-test-snapshotd.service",
)

PYTHON_TRUST_SOURCES = (
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker_persistence.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/repository_context.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_transport.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/store.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_store.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_credentials.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker_host.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/image_publication.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runner.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runtime.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_spool.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/worker_runner.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/broker_configuration.py",
    "skills/codex-dev-coordinator/scripts/devcoordinator/project_runtime_isolation.py",
)

METADATA_GUARD_SOURCES = frozenset(
    {
        "skills/codex-dev-coordinator/scripts/devcoordinator/broker.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/broker_profile.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/maintenance.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/repository_context.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/inventory_projection.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_transport.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/store.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_store.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_credentials.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/broker_host.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/image_publication.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runner.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_runtime.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/universal_test_spool.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/worker_runner.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/broker_configuration.py",
        "skills/codex-dev-coordinator/scripts/devcoordinator/project_runtime_isolation.py",
    }
)

NODE_TRUST_SOURCES = (
    "apps/DevOpsConsole/edge/publication.mjs",
    "apps/DevOpsConsole/edge/publication-cli.mjs",
    "apps/DevOpsConsole/edge/devcoordinator-edge.mjs",
    "apps/DevOpsConsole/edge/console-slot-supervisor.mjs",
    "apps/DevOpsConsole/src/telegram-ipc.mjs",
)

FORBIDDEN_EXEC_FLAG = re.compile(
    r"^--(?:"
    r"access-(?:uid|gid|group)|"
    r"allowed-peer-(?:uid|uids|gid|gids)|"
    r"peer-(?:uid|gid)|"
    r"socket-gid|test-plane-uid|"
    r"trusted-owner-(?:uid|gid)|"
    r"expected-(?:(?:socket|file|profile)-)?(?:uid|gid|mode|owner|group)"
    r")$"
)

PHYSICAL_PEER = re.compile(
    r"(?:\bpeer\.(?:uid|gid)\b|\b(?:physical_peer|caller_peer)\.(?:uid|gid)\b|"
    r"\b(?:physical_peer|caller_peer|peer)_(?:uid|gid)\b)"
)
DENIAL_LANGUAGE = re.compile(
    r"(?:denied|unauthori[sz]ed|not_authorized|peer_not_authorized|forbidden|"
    r"permission|reject)",
    re.IGNORECASE,
)


@dataclass(frozen=True, order=True)
class Finding:
    code: str
    file: str
    line: int
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
        }


def _read(root: Path, relative: str, findings: list[Finding]) -> str | None:
    path = root / relative
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError("not a regular non-symlink file")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        findings.append(
            Finding(
                "trust_contract_source_unavailable",
                relative,
                0,
                f"required production source is unavailable: {error}",
            )
        )
        return None


def _parse_unit(source: str) -> dict[str, dict[str, list[tuple[int, str]]]]:
    result: dict[str, dict[str, list[tuple[int, str]]]] = {}
    section = ""
    pending = ""
    pending_line = 0
    for number, raw in enumerate(source.splitlines(), 1):
        line = pending + raw.strip()
        if line.endswith("\\"):
            if not pending:
                pending_line = number
            pending = line[:-1] + " "
            continue
        line_number = pending_line or number
        pending = ""
        pending_line = 0
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            result.setdefault(section, {})
            continue
        if section and "=" in line:
            key, value = line.split("=", 1)
            result[section].setdefault(key.strip(), []).append(
                (line_number, value.strip())
            )
    return result


def _unit_values(
    unit: dict[str, dict[str, list[tuple[int, str]]]],
    section: str,
    key: str,
) -> list[tuple[int, str]]:
    return list(unit.get(section, {}).get(key, ()))


def _validate_units(root: Path, findings: list[Finding]) -> None:
    for relative, (label, required_mode, required_directory_mode) in (
        LOCAL_SOCKET_UNITS.items()
    ):
        source = _read(root, relative, findings)
        if source is None:
            continue
        unit = _parse_unit(source)
        modes = _unit_values(unit, "Socket", "SocketMode")
        if len(modes) != 1 or modes[0][1] != required_mode:
            findings.append(
                Finding(
                    "local_socket_mode_not_reachable",
                    relative,
                    modes[0][0] if modes else 0,
                    f"{label} socket must set SocketMode={required_mode}",
                )
            )
        directories = _unit_values(unit, "Socket", "DirectoryMode")
        if len(directories) != 1 or directories[0][1] != required_directory_mode:
            findings.append(
                Finding(
                    "local_socket_parent_not_reachable",
                    relative,
                    directories[0][0] if directories else 0,
                    f"{label} socket parent must set DirectoryMode={required_directory_mode}",
                )
            )
        groups = _unit_values(unit, "Socket", "SocketGroup")
        if groups:
            findings.append(
                Finding(
                    "local_socket_group_forbidden",
                    relative,
                    groups[0][0],
                    "local socket reachability must not depend on SocketGroup",
                )
            )

    for relative in PRODUCTION_SERVICE_UNITS:
        source = _read(root, relative, findings)
        if source is None:
            continue
        unit = _parse_unit(source)
        supplementary = _unit_values(unit, "Service", "SupplementaryGroups")
        if supplementary:
            findings.append(
                Finding(
                    "local_access_group_forbidden",
                    relative,
                    supplementary[0][0],
                    "production service must not require a shared local access group",
                )
            )
        if "devcoordinator-clients" in source:
            line = next(
                index
                for index, value in enumerate(source.splitlines(), 1)
                if "devcoordinator-clients" in value
            )
            findings.append(
                Finding(
                    "local_access_group_forbidden",
                    relative,
                    line,
                    "obsolete devcoordinator-clients access group is referenced",
                )
            )
        for key in ("ExecStartPre", "ExecStart", "ExecStartPost"):
            for line, command in _unit_values(unit, "Service", key):
                try:
                    tokens = shlex.split(command)
                except ValueError as error:
                    findings.append(
                        Finding(
                            "production_exec_unparseable",
                            relative,
                            line,
                            f"{key} cannot be parsed: {error}",
                        )
                    )
                    continue
                for token in tokens:
                    flag = token.split("=", 1)[0]
                    if FORBIDDEN_EXEC_FLAG.fullmatch(flag):
                        findings.append(
                            Finding(
                                "local_metadata_exec_gate_forbidden",
                                relative,
                                line,
                                f"{key} requires obsolete local metadata flag {flag}",
                            )
                        )

    console_relative = "deploy/devcoordinator-console@.service"
    console_source = _read(root, console_relative, findings)
    if console_source is not None:
        console = _parse_unit(console_source)
        values = _unit_values(console, "Service", "RuntimeDirectoryMode")
        if len(values) != 1 or values[0][1] != "0755":
            findings.append(
                Finding(
                    "console_socket_parent_not_reachable",
                    console_relative,
                    values[0][0] if values else 0,
                    "Console control socket parent must set RuntimeDirectoryMode=0755",
                )
            )


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _condition_uses_permission_metadata(
    test: ast.AST, parents: dict[ast.AST, ast.AST]
) -> bool:
    del parents
    type_only_modes: set[int] = set()
    for candidate in ast.walk(test):
        if (
            isinstance(candidate, ast.Call)
            and candidate.args
            and _call_name(candidate.func).split(".")[-1].startswith("S_IS")
        ):
            type_only_modes.update(
                id(item)
                for item in ast.walk(candidate.args[0])
                if isinstance(item, ast.Attribute) and item.attr == "st_mode"
            )
    for node in ast.walk(test):
        if isinstance(node, ast.Attribute) and node.attr in {
            "st_uid",
            "st_gid",
            "st_nlink",
        }:
            return True
        if isinstance(node, ast.Call) and _call_name(node.func).endswith("S_IMODE"):
            return True
        if isinstance(node, ast.Attribute) and node.attr == "st_mode":
            if id(node) in type_only_modes:
                continue
            return True
        if isinstance(node, ast.Subscript):
            key = node.slice
            if isinstance(key, ast.Constant) and key.value in {
                "uid",
                "gid",
                "mode",
                "nlink",
            }:
                base = _call_name(node.value)
                if re.search(
                    r"(?:identity|metadata|stat|info|marker|profile|file|path|root|codex|manifest)",
                    base,
                    re.IGNORECASE,
                ):
                    return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in {"uid", "gid", "mode", "nlink"}
        ):
            base = _call_name(node.func.value)
            if re.search(
                r"(?:identity|metadata|stat|info|marker|profile|file|path|root|codex|manifest)",
                base,
                re.IGNORECASE,
            ):
                return True
    return False


def _has_denial_path(node: ast.AST, source: str) -> bool:
    if any(isinstance(item, ast.Raise) for item in ast.walk(node)):
        return True
    for item in ast.walk(node):
        if isinstance(item, ast.Return) and (
            item.value is None
            or (isinstance(item.value, ast.Constant) and item.value.value in {None, False})
        ):
            return True
        if isinstance(item, ast.Call) and re.search(
            r"(?:fail|reject|deny|forbid)", _call_name(item.func), re.IGNORECASE
        ):
            return True
    segment = ast.get_source_segment(source, node) or ""
    return bool(DENIAL_LANGUAGE.search(segment))


class _PythonTrustVisitor(ast.NodeVisitor):
    def __init__(self, *, relative: str, source: str, check_metadata: bool) -> None:
        self.relative = relative
        self.source = source
        self.check_metadata = check_metadata
        self.findings: list[Finding] = []
        self.parents: dict[ast.AST, ast.AST] = {}
        self.functions: list[str] = []

    def visit(self, node: ast.AST) -> object:
        for child in ast.iter_child_nodes(node):
            self.parents[child] = node
        return super().visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name == "operation_follow":
            segment = ast.get_source_segment(self.source, node) or ""
            if re.search(r"original\.(?:account_id|repo_id)\s*=", segment):
                self.findings.append(
                    Finding(
                        "operation_follow_scope_gate_forbidden",
                        self.relative,
                        node.lineno,
                        "exact operation follow must be host-wide for trusted local callers",
                    )
                )
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _visit_branch(self, node: ast.If | ast.While | ast.Assert) -> None:
        test = node.test
        if (
            self.check_metadata
            and _condition_uses_permission_metadata(test, self.parents)
            and _has_denial_path(node, self.source)
        ):
            self.findings.append(
                Finding(
                    "local_permission_metadata_branch_forbidden",
                    self.relative,
                    int(getattr(node, "lineno", 0)),
                    "local acceptance must not branch on owner, group, permission mode, ACL, or link count",
                )
            )
        condition = ast.get_source_segment(self.source, test) or ""
        function = self.functions[-1] if self.functions else ""
        if (
            PHYSICAL_PEER.search(condition)
            and function != "_authorize_connection_for_policy_uid"
            and ("authoriz" in function or _has_denial_path(node, self.source))
        ):
            self.findings.append(
                Finding(
                    "physical_peer_authorization_forbidden",
                    self.relative,
                    int(getattr(node, "lineno", 0)),
                    "physical peer UID/GID is attribution only and cannot authorize a local request",
                )
            )
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self._visit_branch(node)

    def visit_While(self, node: ast.While) -> None:
        self._visit_branch(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._visit_branch(node)

    def visit_Import(self, node: ast.Import) -> None:
        if any("filesystem_acl" in alias.name for alias in node.names):
            self.findings.append(
                Finding(
                    "filesystem_acl_authorization_forbidden",
                    self.relative,
                    node.lineno,
                    "active local transport/profile source imports filesystem ACL authority",
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if "filesystem_acl" in str(node.module or "") or any(
            "filesystem_acl" in alias.name for alias in node.names
        ):
            self.findings.append(
                Finding(
                    "filesystem_acl_authorization_forbidden",
                    self.relative,
                    node.lineno,
                    "active local transport/profile source imports filesystem ACL authority",
                )
            )

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if "filesystem_acl" in name or name.endswith("require_fd_acl_trusted"):
            self.findings.append(
                Finding(
                    "filesystem_acl_authorization_forbidden",
                    self.relative,
                    node.lineno,
                    "active local transport/profile source calls filesystem ACL authority",
                )
            )
        self.generic_visit(node)


def _validate_python(root: Path, findings: list[Finding]) -> None:
    for relative in PYTHON_TRUST_SOURCES:
        source = _read(root, relative, findings)
        if source is None:
            continue
        if (
            relative.endswith("/broker_persistence.py")
            and "ephemeral_image_prefetch_templates" in source
        ):
            findings.append(
                Finding(
                    "retired_repository_profile_policy_field",
                    relative,
                    _line_of(source, source.index("ephemeral_image_prefetch_templates")),
                    "broker repository replies must not serialize the retired image-prefetch allowlist",
                )
            )
        try:
            tree = ast.parse(source, filename=relative)
        except SyntaxError as error:
            findings.append(
                Finding(
                    "trust_contract_source_invalid",
                    relative,
                    int(error.lineno or 0),
                    f"active trust source cannot be parsed: {error.msg}",
                )
            )
            continue
        visitor = _PythonTrustVisitor(
            relative=relative,
            source=source,
            check_metadata=relative in METADATA_GUARD_SOURCES,
        )
        visitor.visit(tree)
        findings.extend(visitor.findings)


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _validate_node(root: Path, findings: list[Finding]) -> None:
    for relative in NODE_TRUST_SOURCES:
        source = _read(root, relative, findings)
        if source is None:
            continue
        if relative.endswith(("publication.mjs", "publication-cli.mjs")):
            for pattern, label in (
                (r"\bexpected(?:Uid|Gid|Mode)\b", "expected metadata option"),
                (
                    r"\b(?:expected|owner)_(?:uid|gid|mode)\b",
                    "publication metadata CLI option",
                ),
                (r"--(?:expected|owner)-(?:uid|gid|mode)\b", "publication metadata flag"),
            ):
                match = re.search(pattern, source)
                if match:
                    findings.append(
                        Finding(
                            "publication_metadata_gate_forbidden",
                            relative,
                            _line_of(source, match.start()),
                            f"active edge publication retains an obsolete {label}",
                        )
                    )
        for match in re.finditer(
            r"\bif\s*\((?P<condition>[^)]*(?:\.uid|\.gid|\.nlink)[^)]*)\)"
            r"(?P<body>\s*(?:\{[^{}]{0,1200}\}|[^;]{0,500};))",
            source,
            re.DOTALL,
        ):
            if re.search(r"\b(?:throw|fail|reject)\b", match.group("body")):
                findings.append(
                    Finding(
                        "publication_metadata_branch_forbidden",
                        relative,
                        _line_of(source, match.start()),
                        "active local publication rejects a caller or file using UID/GID/link metadata",
                    )
                )

    console_relative = "apps/DevOpsConsole/edge/console-slot-supervisor.mjs"
    console = _read(root, console_relative, findings)
    if console is not None:
        match = re.search(r"chmod\s*\(\s*controlSocket\s*,\s*0o666\s*\)", console)
        if match is None:
            findings.append(
                Finding(
                    "console_control_socket_not_reachable",
                    console_relative,
                    0,
                    "Console control socket must be chmod(controlSocket, 0o666)",
                )
            )

    telegram_relative = "apps/DevOpsConsole/src/telegram-ipc.mjs"
    telegram = _read(root, telegram_relative, findings)
    if telegram is not None:
        match = re.search(r"chmod\s*\([^,]+,\s*0o666\s*\)", telegram)
        if match is None:
            findings.append(
                Finding(
                    "notification_socket_not_reachable",
                    telegram_relative,
                    0,
                    "notification IPC socket must be reachable by every local account",
                )
            )


def validate_repository(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    _validate_units(root, findings)
    _validate_python(root, findings)
    _validate_node(root, findings)
    return sorted(set(findings))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    findings = validate_repository(args.repo.resolve())
    document = {
        "ok": not findings,
        "contract": "single-developer-local-trust",
        "checked": {
            "local_sockets": len(LOCAL_SOCKET_UNITS) + 2,
            "production_services": len(PRODUCTION_SERVICE_UNITS),
            "python_sources": len(PYTHON_TRUST_SOURCES),
            "node_sources": len(NODE_TRUST_SOURCES),
        },
        "findings": [item.as_dict() for item in findings],
    }
    if args.json:
        print(json.dumps(document, sort_keys=True))
    elif findings:
        for finding in findings:
            line = f":{finding.line}" if finding.line else ""
            print(
                f"{finding.code}: {finding.file}{line}: {finding.detail}",
                file=sys.stderr,
            )
    else:
        print("single-developer local trust contract ok")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
