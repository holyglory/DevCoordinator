#!/usr/bin/env python3
"""Deterministic safety contract for archive and destructive cleanup surfaces.

The checker intentionally inspects production source, not prose or tests.  It
keeps the older ``repository remove`` journey a reversible archive alias and
requires every new purge path to use an exact, planned, owner-authorized
contract.  It also rejects command forms that can silently widen cleanup into
data deletion.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import re
import shlex
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


COORDINATOR_REL = Path("skills/codex-dev-coordinator/scripts")
LIFECYCLE_CLI_REL = COORDINATOR_REL / "devcoordinator/lifecycle_cli.py"
REPOSITORY_LIFECYCLE_REL = COORDINATOR_REL / "devcoordinator/repository_lifecycle.py"
CLEANUP_LIFECYCLE_REL = COORDINATOR_REL / "devcoordinator/cleanup_lifecycle.py"
HTTP_API_REL = COORDINATOR_REL / "dev_coordinator.py"
CONSOLE_API_REL = Path("apps/DevOpsConsole/src/api.mjs")
CONSOLE_UI_REL = Path("apps/DevOpsConsole/src/ui/app.js")

REPOSITORY_COMMANDS = {
    "plan-archive",
    "archive",
    "list-archived",
    "restore",
    # Compatibility names are deliberately retained and must remain aliases.
    "plan-remove",
    "remove",
    "list-removed",
    "reinstall",
}
RESOURCE_COMMANDS = {"plan-archive", "archive", "restore"}
ALIAS_PAIRS = (
    frozenset({"plan-remove", "plan-archive"}),
    frozenset({"remove", "archive"}),
    frozenset({"list-removed", "list-archived"}),
    frozenset({"reinstall", "restore"}),
)
PURGE_TARGET_KINDS = {"project", "server", "container", "worktree"}
APPLY_FIELDS = {"plan_id", "plan_fingerprint", "confirmation_phrase"}
PLAN_FIELDS = {"action", "target_kind", "target_id", "reason"}
FORBIDDEN_CLIENT_FIELDS = {
    "argv",
    "cmd",
    "command",
    "cwd",
    "executable",
    "file",
    "files",
    "filesystem_path",
    "path",
    "script",
    "shell",
}
RETAINED_REPOSITORY_DATA = {
    "repository_files",
    "containers",
    "volumes",
    "databases",
    "backups",
    "audit_history",
}


def _error(code: str, message: str) -> str:
    return f"[{code}] {message}"


def _read(path: Path, errors: list[str], code: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        errors.append(_error(code, f"cannot read {path}: {exc}"))
        return ""


def _parse_python(path: Path, source: str, errors: list[str]) -> ast.Module | None:
    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        errors.append(_error("python-syntax", f"cannot parse {path}: {exc}"))
        return None


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _literal_collection(node: ast.AST, constants: Mapping[str, set[str]] | None = None) -> set[str] | None:
    constants = constants or {}
    if isinstance(node, ast.Name):
        return set(constants[node.id]) if node.id in constants else None
    if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
        values: set[str] = set()
        for item in node.elts:
            value = _literal_string(item)
            if value is None:
                return None
            values.add(value)
        return values
    if isinstance(node, ast.Dict):
        values = set()
        for key in node.keys:
            value = _literal_string(key)
            if value is None:
                return None
            values.add(value)
        return values
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
        "frozenset",
        "set",
        "tuple",
    } and len(node.args) == 1:
        return _literal_collection(node.args[0], constants)
    return None


def _module_string_collections(tree: ast.Module) -> tuple[dict[str, set[str]], list[set[str]]]:
    constants: dict[str, set[str]] = {}
    collections: list[set[str]] = []
    for statement in tree.body:
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            target = statement.targets[0] if isinstance(statement, ast.Assign) and statement.targets else statement.target
        if value is None:
            continue
        parsed = _literal_collection(value, constants)
        if parsed is None:
            continue
        collections.append(parsed)
        if isinstance(target, ast.Name):
            constants[target.id] = parsed
    for node in ast.walk(tree):
        parsed = _literal_collection(node, constants)
        if parsed is not None:
            collections.append(parsed)
    return constants, collections


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = [node.func.attr]
        value = node.func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def _parser_contract(tree: ast.Module, errors: list[str]) -> None:
    parser_names: set[str] = set()
    argument_names: set[str] = set()
    choice_sets: list[set[str]] = []
    _constants, collections = _module_string_collections(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr == "add_parser" and node.args:
            value = _literal_string(node.args[0])
            if value is not None:
                parser_names.add(value)
        elif node.func.attr == "add_argument":
            for arg in node.args:
                value = _literal_string(arg)
                if value is not None:
                    argument_names.add(value)
            for keyword in node.keywords:
                if keyword.arg == "choices":
                    values = _literal_collection(keyword.value)
                    if values is not None:
                        choice_sets.append(values)

    # argparse surfaces are often declared from a literal alias tuple.  Treat
    # only a loop whose target is passed directly to add_parser as parser
    # evidence; a dormant constant elsewhere is not enough.
    for node in ast.walk(tree):
        if not isinstance(node, ast.For) or not isinstance(node.target, ast.Name):
            continue
        values = _literal_collection(node.iter)
        if values is None:
            continue
        loop_name = node.target.id
        if any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "add_parser"
            and child.args
            and isinstance(child.args[0], ast.Name)
            and child.args[0].id == loop_name
            for statement in node.body
            for child in ast.walk(statement)
        ):
            parser_names.update(values)

    missing_repository = sorted(REPOSITORY_COMMANDS - parser_names)
    if missing_repository:
        errors.append(
            _error(
                "legacy-archive-alias",
                "repository CLI is missing reversible archive/compatibility commands: "
                + ", ".join(missing_repository),
            )
        )
    missing_resource = sorted(RESOURCE_COMMANDS - parser_names)
    if missing_resource:
        errors.append(
            _error(
                "resource-archive-surface",
                "resource CLI is missing archive/restore commands: " + ", ".join(missing_resource),
            )
        )
    for command in ("cleanup", "plan", "apply"):
        if command not in parser_names:
            errors.append(_error("purge-cli-surface", f"cleanup CLI is missing {command!r}"))
    required_arguments = {
        "--action",
        "--target-kind",
        "--plan-id",
        "--plan-fingerprint",
        "--confirmation-phrase",
    }
    missing_arguments = sorted(required_arguments - argument_names)
    if missing_arguments:
        errors.append(
            _error(
                "purge-confirmation-contract",
                "cleanup CLI is missing exact plan/confirmation arguments: "
                + ", ".join(missing_arguments),
            )
        )
    if not any(PURGE_TARGET_KINDS <= values for values in choice_sets + collections):
        errors.append(
            _error(
                "purge-target-kinds",
                "cleanup target-kind choices must include project, server, container, and worktree",
            )
        )
    if not any("purge" in values for values in choice_sets + collections):
        errors.append(_error("purge-action", "cleanup planning must expose the typed purge action"))
    for pair in ALIAS_PAIRS:
        if not any(pair == values for values in collections):
            errors.append(
                _error(
                    "legacy-archive-alias",
                    f"legacy/canonical repository actions are not one explicit alias group: {sorted(pair)}",
                )
            )


def _retention_contract(tree: ast.Module, errors: list[str]) -> None:
    constants, _collections = _module_string_collections(tree)
    retained = constants.get("RETAINED_DATA", set())
    missing = sorted(RETAINED_REPOSITORY_DATA - retained)
    if missing:
        errors.append(
            _error(
                "legacy-archive-retention",
                "legacy repository archive no longer declares retained data: " + ", ".join(missing),
            )
        )
    names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
    if "RepositoryDecommissionPlan" not in names or "reinstall_repository" not in names:
        errors.append(
            _error(
                "legacy-archive-retention",
                "reversible repository decommission/reinstall types must remain available behind archive aliases",
            )
        )


def _class_methods(
    tree: ast.Module, class_name: str
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                child.name: child
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    return {}


def _local_assignments(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.AST]:
    assignments: dict[str, ast.AST] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                assignments[node.target.id] = node.value
    return assignments


def _resolve_local(node: ast.AST, assignments: Mapping[str, ast.AST]) -> ast.AST:
    seen: set[str] = set()
    while isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        seen.add(node.id)
        node = assignments[node.id]
    return node


def _dict_items(
    node: ast.AST, assignments: Mapping[str, ast.AST]
) -> dict[str, ast.AST] | None:
    resolved = _resolve_local(node, assignments)
    if not isinstance(resolved, ast.Dict):
        return None
    result: dict[str, ast.AST] = {}
    for key, value in zip(resolved.keys, resolved.values):
        name = _literal_string(key)
        if name is None:
            return None
        result[name] = value
    return result


def _depends_on_parameter(
    node: ast.AST, parameter: str, assignments: Mapping[str, ast.AST], seen: set[str] | None = None
) -> bool:
    seen = set() if seen is None else set(seen)
    if isinstance(node, ast.Name):
        if node.id == parameter:
            return True
        if node.id in assignments and node.id not in seen:
            seen.add(node.id)
            return _depends_on_parameter(assignments[node.id], parameter, assignments, seen)
        return False
    return any(
        _depends_on_parameter(child, parameter, assignments, seen)
        for child in ast.iter_child_nodes(node)
    )


def _string_values(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }


def _self_method_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[str, ast.Call]]:
    calls: list[tuple[str, ast.Call]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if isinstance(node.func.value, ast.Name) and node.func.value.id == "self":
            calls.append((node.func.attr, node))
    return calls


def _reachable_methods(
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef], start: str
) -> set[str]:
    reachable: set[str] = set()
    pending = [start]
    while pending:
        name = pending.pop()
        if name in reachable or name not in methods:
            continue
        reachable.add(name)
        pending.extend(
            called
            for called, _call in _self_method_calls(methods[name])
            if called in methods
        )
    return reachable


def _sql_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", child.value, re.IGNORECASE)
    ]


def _plan_binding_contract(
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef], errors: list[str]
) -> None:
    plan = methods.get("plan")
    if plan is None:
        errors.append(
            _error(
                "plan-actor-reason-binding",
                "cleanup lifecycle has no durable plan implementation",
            )
        )
        return
    assignments = _local_assignments(plan)
    bound = False
    for call in (node for node in ast.walk(plan) if isinstance(node, ast.Call)):
        if not _call_name(call).rsplit(".", 1)[-1].endswith("fingerprint") or not call.args:
            continue
        items = _dict_items(call.args[0], assignments)
        if items is None:
            continue
        actor = items.get("actor", ast.Constant(None))
        reason = items.get("reason", ast.Constant(None))
        if _depends_on_parameter(actor, "actor", assignments) and _depends_on_parameter(
            reason, "reason", assignments
        ):
            bound = True
            break
    if not bound:
        errors.append(
            _error(
                "plan-actor-reason-binding",
                "cleanup plan fingerprint must bind the normalized actor and reason",
            )
        )

    for method in methods.values():
        for sql in _sql_strings(method):
            if re.search(
                r"\bUPDATE\s+cleanup_plans\b(?:(?!\bWHERE\b).)*\b(?:actor|reason)\s*=",
                sql,
                re.IGNORECASE | re.DOTALL,
            ):
                errors.append(
                    _error(
                        "plan-actor-reason-binding",
                        "cleanup apply must not overwrite the actor/reason bound into a durable plan",
                    )
                )
                break

    insert = methods.get("_insert_tombstone")
    tombstone_identity_bound = False
    if insert is not None:
        for call in (node for node in ast.walk(insert) if isinstance(node, ast.Call)):
            if not call.args:
                continue
            sql = _literal_string(call.args[0])
            if sql is None or "INSERT INTO cleanup_tombstones" not in sql:
                continue
            attributes = {
                (child.value.id, child.attr)
                for child in ast.walk(call)
                if isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
            }
            if {("plan", "actor"), ("plan", "reason")} <= attributes:
                tombstone_identity_bound = True
                break
    if not tombstone_identity_bound:
        errors.append(
            _error(
                "plan-actor-reason-binding",
                "cleanup tombstones must retain the plan-bound actor and reason",
            )
        )


def _durable_phase_start_methods(
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> set[str]:
    result: set[str] = set()
    for name, method in methods.items():
        sql = "\n".join(_sql_strings(method)).lower()
        calls = {_call_name(node) for node in ast.walk(method) if isinstance(node, ast.Call)}
        if (
            "cleanup_phase_evidence" in sql
            and any(
                re.search(r"\brunning\b", value, re.IGNORECASE)
                for value in _string_values(method)
            )
            and any(call.endswith("immediate_transaction") for call in calls)
        ):
            result.add(name)
    return result


def _effect_calls(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Call]:
    result: list[ast.Call] = []
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        name = _call_name(call)
        if name.endswith("docker_backend.remove") or name.endswith("._remove_worktree"):
            result.append(call)
            continue
        if _is_execution_call(call) and call.args:
            tokens = _literal_tokens(call.args[0])
            if tokens is not None and (
                "docker" in {Path(value).name for value in tokens}
                or (
                    "git" in {Path(value).name for value in tokens}
                    and "worktree" in tokens
                    and "remove" in tokens
                )
            ):
                result.append(call)
    return result


def _host_effect_contract(
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef], errors: list[str]
) -> None:
    apply = methods.get("apply")
    if apply is None:
        errors.append(_error("cleanup-effect-journal", "cleanup lifecycle has no apply method"))
        errors.append(
            _error(
                "cleanup-effect-reconciliation",
                "cleanup lifecycle has no absent-host-effect reconciliation path",
            )
        )
        return
    durable_start = _durable_phase_start_methods(methods)
    journaled_effects = 0
    effect_calls = _effect_calls(apply)
    for effect in effect_calls:
        prior = [
            called
            for called, call in _self_method_calls(apply)
            if called in durable_start
            and call.lineno < effect.lineno
            and "host_remove" in _string_values(call)
        ]
        if prior:
            journaled_effects += 1
    effects = len(effect_calls)
    if effects == 0 or journaled_effects != effects:
        errors.append(
            _error(
                "cleanup-effect-journal",
                "each Docker/Git removal needs a committed host_remove running phase before the external effect",
            )
        )

    reconciled_absent = False
    for branch in (node for node in ast.walk(apply) if isinstance(node, ast.If)):
        if "absent" not in _string_values(branch.test):
            continue
        branch_values = _string_values(branch)
        phase_started_check = "running" in branch_values and any(
            "host_remove" in _string_values(call)
            and any(word in called.lower() for word in ("phase_status", "phase_started"))
            for called, call in [
                (node.func.attr, node)
                for node in ast.walk(branch)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
            ]
        )
        if not phase_started_check:
            continue
        branch_calls = [
            pair
            for statement in branch.body
            for pair in (
                _self_method_calls(statement)
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
                else [
                    (node.func.attr, node)
                    for node in ast.walk(statement)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "self"
                ]
            )
        ]
        for called, call in branch_calls:
            call_values = _string_values(call)
            if (
                called == "_finish_phase"
                and {"host_remove", "target_absent"} <= call_values
                and {
                    "recovered_after_interruption",
                    "reconciled_absent",
                    "outcome_uncertain",
                }
                & call_values
            ):
                reconciled_absent = True
                break
            if "reconcile" not in called.lower() or called not in methods:
                continue
            helper = methods[called]
            helper_values = _string_values(helper)
            helper_calls = {name for name, _call in _self_method_calls(helper)}
            has_durable_outcome = bool(
                {"reconciled_absent", "outcome_uncertain"} & helper_values
            ) and (
                "_finish_phase" in helper_calls
                or "cleanup_phase_evidence" in "\n".join(_sql_strings(helper))
            )
            if "host_remove" in _string_values(call) and has_durable_outcome:
                reconciled_absent = True
                break
        if reconciled_absent:
            break
    if not reconciled_absent:
        errors.append(
            _error(
                "cleanup-effect-reconciliation",
                "an absent target after a started host_remove phase needs durable reconciliation or outcome-uncertain evidence",
            )
        )


def _blocker_in_if(node: ast.If, code: str) -> bool:
    return any(
        isinstance(call, ast.Call)
        and _call_name(call).rsplit(".", 1)[-1] == "_blocker"
        and call.args
        and _literal_string(call.args[0]) == code
        for statement in node.body
        for call in ast.walk(statement)
    )


def _destructive_target_blockers(
    tree: ast.Module,
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
    errors: list[str],
) -> None:
    relevant: list[ast.FunctionDef | ast.AsyncFunctionDef] = list(methods.values())
    relevant.extend(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(word in node.name.lower() for word in ("cleanup", "container", "worktree"))
    )
    root_refusal = False
    mounted_container = False
    compose_owned = False
    compose_labels = {
        "com.docker.compose.",
        "com.docker.compose.project",
        "com.docker.compose.service",
        "com.docker.compose.config-hash",
    }
    for function in relevant:
        for branch in (node for node in ast.walk(function) if isinstance(node, ast.If)):
            test_values = _string_values(branch.test)
            if _blocker_in_if(branch, "root_owned_worktree") and any(
                isinstance(child, ast.Attribute) and child.attr == "st_uid"
                for child in ast.walk(branch.test)
            ) and any(
                isinstance(child, ast.Constant) and child.value == 0
                for child in ast.walk(branch.test)
            ):
                root_refusal = True
            if "mounts" in test_values and _blocker_in_if(branch, "mounted_container"):
                mounted_container = True
            if test_values & compose_labels and _blocker_in_if(branch, "compose_owned"):
                compose_owned = True
    if not root_refusal:
        errors.append(
            _error(
                "root-owned-worktree",
                "cleanup must refuse a linked worktree whose root directory is owned by uid 0",
            )
        )
    if not mounted_container:
        errors.append(
            _error(
                "mounted-container",
                "permanent container removal must block every container with a live mount",
            )
        )
    if not compose_owned:
        errors.append(
            _error(
                "compose-owned-container",
                "permanent container removal must block live Docker Compose label ownership",
            )
        )


def _dict_has_removed_projection(node: ast.Dict) -> bool:
    items = {
        key.value: value
        for key, value in zip(node.keys, node.values)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    return (
        {"target_kind", "target_id", "removed_at", "status", "restorable", "removable"}
        <= set(items)
        and isinstance(items["status"], ast.Constant)
        and items["status"].value == "removed"
        and isinstance(items["restorable"], ast.Constant)
        and items["restorable"].value is False
        and isinstance(items["removable"], ast.Constant)
        and items["removable"].value is False
    )


def _tombstone_projection_contract(
    methods: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef], errors: list[str]
) -> None:
    reachable = _reachable_methods(methods, "list_archives")
    sql = "\n".join(
        statement for name in reachable for statement in _sql_strings(methods[name])
    )
    projected = any(
        _dict_has_removed_projection(node)
        for name in reachable
        for node in ast.walk(methods[name])
        if isinstance(node, ast.Dict)
    )
    if not re.search(r"\bFROM\s+cleanup_tombstones\b", sql, re.IGNORECASE) or not projected:
        errors.append(
            _error(
                "removed-tombstone-projection",
                "archive listing must project durable cleanup tombstones as non-restorable, non-removable removed rows",
            )
        )


def _cleanup_lifecycle_contract(tree: ast.Module, errors: list[str]) -> None:
    methods = _class_methods(tree, "CleanupLifecycle")
    if not methods:
        errors.append(
            _error("cleanup-lifecycle-service", "CleanupLifecycle service is missing")
        )
        return
    _plan_binding_contract(methods, errors)
    _host_effect_contract(methods, errors)
    _destructive_target_blockers(tree, methods, errors)
    _tombstone_projection_contract(methods, errors)


def _literal_tokens(node: ast.AST, env: Mapping[str, list[str]] | None = None) -> list[str] | None:
    env = env or {}
    if isinstance(node, ast.Name):
        return list(env[node.id]) if node.id in env else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        result: list[str] = []
        for item in node.elts:
            if isinstance(item, ast.Starred):
                value = _literal_tokens(item.value, env)
            else:
                value = _literal_tokens(item, env)
            result.extend(value if value is not None else ["<dynamic>"])
        return result
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_tokens(node.left, env)
        right = _literal_tokens(node.right, env)
        if left is not None and right is not None:
            return [*left, *right]
    return None


def _short_flag(token: str, letter: str) -> bool:
    return token.startswith("-") and not token.startswith("--") and letter in token[1:]


def _command_issues(tokens: Sequence[str]) -> list[tuple[str, str]]:
    values = [str(item) for item in tokens]
    basenames = [Path(item).name if item and item != "<dynamic>" else item for item in values]
    issues: list[tuple[str, str]] = []
    for index, token in enumerate(basenames):
        if token == "rm":
            flags = basenames[index + 1 :]
            recursive = any(_short_flag(flag, "r") or flag == "--recursive" for flag in flags)
            force = any(_short_flag(flag, "f") or flag == "--force" for flag in flags)
            if recursive and force:
                issues.append(("raw-rm-rf", "raw recursive forced rm is forbidden"))
        if token == "git" and basenames[index + 1 : index + 3] == ["worktree", "remove"]:
            flags = basenames[index + 3 :]
            if any(flag == "--force" or _short_flag(flag, "f") for flag in flags):
                issues.append(
                    ("git-worktree-force", "git worktree remove must never use --force/-f")
                )
        if token != "docker":
            continue
        docker = basenames[index + 1 :]
        remove_offset: int | None = None
        if docker[:1] in (["rm"], ["remove"]):
            remove_offset = 1
        elif len(docker) >= 2 and docker[0] == "container" and docker[1] in {"rm", "remove"}:
            remove_offset = 2
        if remove_offset is not None:
            flags = docker[remove_offset:]
            bad = [
                flag
                for flag in flags
                if flag in {"--force", "--volumes"}
                or _short_flag(flag, "f")
                or _short_flag(flag, "v")
            ]
            if bad:
                issues.append(
                    (
                        "docker-remove-flags",
                        "Docker container removal must not force or delete attached volumes: "
                        + ", ".join(bad),
                    )
                )
        if "compose" in docker:
            compose_index = docker.index("compose")
            compose = docker[compose_index + 1 :]
            subcommand_index = next(
                (position for position, value in enumerate(compose) if value in {"down", "rm", "remove"}),
                None,
            )
            if subcommand_index is not None:
                flags = compose[subcommand_index + 1 :]
                bad = [
                    flag
                    for flag in flags
                    if flag in {"--volumes", "--rmi", "--remove-orphans"}
                    or _short_flag(flag, "v")
                ]
                if bad:
                    issues.append(
                        (
                            "compose-destructive-flags",
                            "Compose cleanup must retain volumes, images, and undeclared containers: "
                            + ", ".join(bad),
                        )
                    )
        for position, value in enumerate(docker[:-1]):
            if value in {"system", "container", "image", "volume", "network", "builder"} and docker[position + 1] == "prune":
                issues.append(
                    ("implicit-prune", f"implicit docker {value} prune is forbidden")
                )
    # De-duplicate an argv inspected through more than one AST route.
    return list(dict.fromkeys(issues))


def _shell_command_issues(value: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    for segment in re.split(r"(?:&&|\|\||[;\n])", value):
        try:
            tokens = shlex.split(segment, comments=True, posix=True)
        except ValueError:
            continue
        results.extend(_command_issues(tokens))
    return list(dict.fromkeys(results))


EXECUTION_CALLS = {
    "call",
    "check_call",
    "check_output",
    "coordinated_run_docker",
    "docker_available_command",
    "exec",
    "execute",
    "execute_docker_subprocess",
    "execFile",
    "execFileSync",
    "os.system",
    "Popen",
    "run",
    "run_command",
    "spawn",
    "spawnSync",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
    "system",
}


def _is_execution_call(call: ast.Call) -> bool:
    name = _call_name(call)
    tail = name.rsplit(".", 1)[-1]
    return (
        name in EXECUTION_CALLS
        or tail in EXECUTION_CALLS
        or tail.lstrip("_") in EXECUTION_CALLS
        or any(word in tail.lower() for word in ("execute", "runner", "spawn"))
    )


class _PythonCommandFlow:
    def __init__(self, path: Path, errors: list[str]) -> None:
        self.path = path
        self.errors = errors
        self.reported: set[tuple[str, int, str]] = set()

    def report(self, code: str, message: str, lineno: int) -> None:
        key = (code, lineno, message)
        if key in self.reported:
            return
        self.reported.add(key)
        self.errors.append(_error(code, f"{self.path}:{lineno}: {message}"))

    def inspect_tokens(self, tokens: list[str] | None, lineno: int) -> None:
        if tokens is None:
            return
        for code, message in _command_issues(tokens):
            self.report(code, message, lineno)

    def inspect_call(self, call: ast.Call, env: Mapping[str, list[str]]) -> None:
        if _is_execution_call(call) and call.args:
            for arg in call.args:
                tokens = _literal_tokens(arg, env)
                if tokens is not None and any(
                    Path(item).name in {"rm", "git", "docker"} for item in tokens
                ):
                    self.inspect_tokens(tokens, call.lineno)
            first = call.args[0]
            self.inspect_tokens(_literal_tokens(first, env), call.lineno)
            value = _literal_string(first)
            if value is not None:
                for code, message in _shell_command_issues(value):
                    self.report(code, message, call.lineno)

    def scan_block(self, statements: Sequence[ast.stmt], env: dict[str, list[str]]) -> None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_block(statement.body, {})
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(statement.body, {})
                continue
            if isinstance(statement, ast.Assign):
                value = _literal_tokens(statement.value, env)
                for target in statement.targets:
                    if isinstance(target, ast.Name) and value is not None:
                        env[target.id] = value
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                value = _literal_tokens(statement.value, env) if statement.value is not None else None
                if value is not None:
                    env[statement.target.id] = value
            elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
                value = _literal_tokens(statement.value, env)
                if isinstance(statement.op, ast.Add) and value is not None and statement.target.id in env:
                    env[statement.target.id] = [*env[statement.target.id], *value]

            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    variable = node.func.value.id
                    if variable in env and node.func.attr in {"append", "extend"} and node.args:
                        value = _literal_tokens(node.args[0], env)
                        if value is not None:
                            env[variable].extend(value)
                self.inspect_call(node, env)

            nested_blocks: list[Sequence[ast.stmt]] = []
            if isinstance(statement, ast.If):
                nested_blocks.extend((statement.body, statement.orelse))
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                nested_blocks.extend((statement.body, statement.orelse))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                nested_blocks.append(statement.body)
            elif isinstance(statement, ast.Try):
                nested_blocks.extend((statement.body, statement.orelse, statement.finalbody))
                nested_blocks.extend(handler.body for handler in statement.handlers)
            for block in nested_blocks:
                self.scan_block(block, dict(env))


def _js_strings(value: str) -> list[str]:
    strings: list[str] = []
    index = 0
    while index < len(value):
        quote = value[index]
        if quote not in {"'", '"', "`"}:
            index += 1
            continue
        start = index
        index += 1
        content: list[str] = []
        dynamic = False
        while index < len(value):
            character = value[index]
            if character == "\\" and index + 1 < len(value):
                content.append(value[index + 1])
                index += 2
                continue
            if quote == "`" and value.startswith("${", index):
                dynamic = True
            if character == quote:
                index += 1
                break
            content.append(character)
            index += 1
        if not dynamic:
            strings.append("".join(content))
        if index <= start:
            index = start + 1
    return strings


def _strip_js_comments(source: str) -> str:
    result: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is not None:
            result.append(character)
            if character == "\\" and index + 1 < len(source):
                result.append(source[index + 1])
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            result.append(character)
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
            result.append("\n")
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 2
            result.append(" ")
            continue
        result.append(character)
        index += 1
    return "".join(result)


def _scan_non_python_commands(path: Path, source: str, errors: list[str]) -> None:
    stripped = _strip_js_comments(source)
    for match in re.finditer(r"\[([^\[\]]{0,1200})\]", stripped, re.DOTALL):
        tokens = _js_strings(match.group(1))
        for code, message in _command_issues(tokens):
            errors.append(_error(code, f"{path}:{source.count(chr(10), 0, match.start()) + 1}: {message}"))
    for match in re.finditer(
        r"\b(?:exec|execFile|execFileSync|spawn|spawnSync|run)\s*\((.{0,1200}?)\)",
        stripped,
        re.DOTALL,
    ):
        strings = _js_strings(match.group(1))
        for value in strings:
            for code, message in _shell_command_issues(value):
                errors.append(
                    _error(code, f"{path}:{source.count(chr(10), 0, match.start()) + 1}: {message}")
                )


def _production_files(root: Path) -> Iterator[Path]:
    coordinator = root / COORDINATOR_REL
    if coordinator.is_dir():
        for path in sorted(coordinator.rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".js", ".mjs", ".cjs", ".sh"}:
                continue
            relative = path.relative_to(coordinator)
            if "tests" in relative.parts or path.name.startswith(("test_", "self_test_")):
                continue
            yield path
    for base in (root / "apps/DevOpsConsole/src", root / "apps/DevOpsBoard/Sources"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".js", ".mjs", ".cjs", ".swift", ".sh"}:
                yield path
    scripts = root / "scripts"
    if scripts.is_dir():
        for path in sorted(scripts.iterdir()):
            lowered = path.name.lower()
            if (
                path.is_file()
                and path.suffix in {".py", ".js", ".mjs", ".sh"}
                and any(word in lowered for word in ("archive", "cleanup", "lifecycle", "purge", "worktree"))
                and path.name not in {"check_cleanup_contract.py", "self_test_cleanup_contract.py"}
                and not path.name.startswith(("test_", "self_test_"))
            ):
                yield path


def _scan_commands(root: Path, errors: list[str]) -> None:
    for path in _production_files(root):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(_error("source-read", f"cannot inspect {path}: {exc}"))
            continue
        if path.suffix == ".py":
            tree = _parse_python(path, source, errors)
            if tree is not None:
                _PythonCommandFlow(path, errors).scan_block(tree.body, {})
        else:
            _scan_non_python_commands(path, source, errors)


def _field_accesses(node: ast.AST, receiver_names: set[str]) -> set[str]:
    fields: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name) and child.value.id in receiver_names:
            value = _literal_string(child.slice)
            if value is not None:
                fields.add(value)
        elif (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id in receiver_names
            and child.func.attr in {"get", "pop", "setdefault"}
            and child.args
        ):
            value = _literal_string(child.args[0])
            if value is not None:
                fields.add(value)
    return fields


def _if_string_values(node: ast.If) -> set[str]:
    return {
        child.value
        for child in ast.walk(node.test)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }


def _apply_validation_functions(
    tree: ast.Module, constants: Mapping[str, set[str]]
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    candidates: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    exact_constant_names = {
        name for name, values in constants.items() if values == APPLY_FIELDS
    }
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        referenced = {
            child.id for child in ast.walk(function) if isinstance(child, ast.Name)
        }
        fields = _field_accesses(function, {"payload", "arguments", "body", "request"})
        has_exact_literal = any(
            _literal_collection(child, constants) == APPLY_FIELDS
            for child in ast.walk(function)
        )
        argument_names = {
            argument.arg
            for argument in (
                list(function.args.posonlyargs)
                + list(function.args.args)
                + list(function.args.kwonlyargs)
            )
        }
        if (
            APPLY_FIELDS <= fields
            or APPLY_FIELDS <= argument_names
            or referenced & exact_constant_names
            or has_exact_literal
        ):
            candidates.append(function)
    return candidates


def _has_confirmation_comparison(
    functions: Iterable[ast.FunctionDef | ast.AsyncFunctionDef],
) -> bool:
    for function in functions:
        values = {
            child.value
            for child in ast.walk(function)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
        }
        attributes = {
            child.attr for child in ast.walk(function) if isinstance(child, ast.Attribute)
        }
        if "purge" not in values or (
            "confirmation_phrase" not in values
            and "confirmation_phrase" not in attributes
        ):
            continue
        phrase_access = any(
            "confirmation_phrase" in _field_accesses(child, {"payload", "arguments", "body", "request"})
            for child in [function]
        ) or "confirmation_phrase" in attributes
        has_compare = any(isinstance(child, ast.Compare) for child in ast.walk(function))
        has_constant_time = any(
            isinstance(child, ast.Call) and _call_name(child).endswith("compare_digest")
            for child in ast.walk(function)
        )
        target_bound = (
            {"target_kind", "target_id"} <= values
            or {"target_kind", "target_id"} <= attributes
        )
        if phrase_access and (has_compare or has_constant_time) and target_bound:
            return True
    return False


def _http_contract(
    tree: ast.Module,
    source: str,
    errors: list[str],
    *,
    authority_trees: Iterable[ast.Module] = (),
) -> None:
    required_routes = {
        "/v1/archives",
        "/v1/lifecycle/plan",
        "/v1/lifecycle/apply",
        "/v1/lifecycle/restore",
    }
    missing_routes = sorted(route for route in required_routes if route not in source)
    if missing_routes:
        errors.append(
            _error("lifecycle-http-surface", "coordinator HTTP API is missing: " + ", ".join(missing_routes))
        )

    constants, collections = _module_string_collections(tree)
    apply_functions = _apply_validation_functions(tree, constants)
    for authority_tree in authority_trees:
        authority_constants, _authority_collections = _module_string_collections(
            authority_tree
        )
        apply_functions.extend(
            _apply_validation_functions(authority_tree, authority_constants)
        )
    if not any(APPLY_FIELDS == values for values in collections):
        errors.append(
            _error(
                "purge-confirmation-contract",
                "lifecycle apply must accept exactly plan_id, plan_fingerprint, and confirmation_phrase",
            )
        )
    if not any(PLAN_FIELDS <= values and not (values & FORBIDDEN_CLIENT_FIELDS) for values in collections):
        errors.append(
            _error(
                "typed-cleanup-plan",
                "lifecycle plan must use typed action/target_kind/target_id/reason fields",
            )
        )
    if not _has_confirmation_comparison(apply_functions):
        errors.append(
            _error(
                "purge-confirmation-contract",
                "purge apply must compare an exact target-bound confirmation_phrase",
            )
        )

    names = {
        _call_name(node)
        for function in apply_functions
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
    }
    has_uuid = any("canonical_uuid" in name or name.endswith("UUID") for name in names)
    has_sha = any(
        "sha256" in name.lower()
        or "sha_256" in name.lower()
        or (
            "fingerprint" in name.lower()
            and any(verb in name.lower() for verb in ("canonical", "validate", "verify"))
        )
        for name in names
    )
    if not has_uuid:
        errors.append(_error("plan-uuid", "cleanup apply must validate a canonical plan UUID"))
    if not has_sha:
        errors.append(_error("plan-sha256", "cleanup apply must validate a SHA-256 plan fingerprint"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        routes = _if_string_values(node) & required_routes
        if not routes:
            continue
        forbidden = _field_accesses(node, {"payload", "body", "request", "arguments"}) & FORBIDDEN_CLIENT_FIELDS
        if forbidden:
            errors.append(
                _error(
                    "client-execution-input",
                    f"{sorted(routes)} accepts client filesystem/command fields: {sorted(forbidden)}",
                )
            )
        for call in (child for child in ast.walk(node) if isinstance(child, ast.Call)):
            if not _is_execution_call(call):
                continue
            direct_fields = _field_accesses(
                call, {"payload", "body", "request", "arguments"}
            )
            if direct_fields:
                errors.append(
                    _error(
                        "client-execution-input",
                        f"{sorted(routes)} passes client fields directly to command execution: {sorted(direct_fields)}",
                    )
                )

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(
            word in function.name.lower()
            for word in ("archive", "cleanup", "lifecycle", "purge", "worktree")
        ):
            continue
        for call in (child for child in ast.walk(function) if isinstance(child, ast.Call)):
            if not _is_execution_call(call):
                continue
            direct_fields = _field_accesses(
                call, {"payload", "body", "request", "arguments"}
            )
            if direct_fields:
                errors.append(
                    _error(
                        "client-execution-input",
                        f"{function.name} passes client fields directly to command execution: {sorted(direct_fields)}",
                    )
                )

    # A module-level exact field constant is useful, but it must not itself
    # include a command or path merely because another exact set is safe.
    for name, values in constants.items():
        if any(word in name.lower() for word in ("cleanup", "lifecycle", "purge")):
            forbidden = values & FORBIDDEN_CLIENT_FIELDS
            if forbidden:
                errors.append(
                    _error(
                        "client-execution-input",
                        f"{name} exposes client filesystem/command fields: {sorted(forbidden)}",
                    )
                )


@dataclass(frozen=True)
class _JsFunction:
    name: str
    arguments: str
    body: str


def _find_matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    index = opening
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is not None:
            if character == "\\" and index + 1 < len(source):
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _js_functions(source: str) -> dict[str, _JsFunction]:
    stripped = _strip_js_comments(source)
    functions: dict[str, _JsFunction] = {}
    pattern = re.compile(r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{")
    for match in pattern.finditer(stripped):
        opening = match.end() - 1
        closing = _find_matching_brace(stripped, opening)
        if closing is None:
            continue
        functions[match.group(1)] = _JsFunction(
            name=match.group(1),
            arguments=match.group(2),
            body=stripped[opening + 1 : closing],
        )
    return functions


def _owner_gated(name: str, functions: Mapping[str, _JsFunction], seen: set[str] | None = None) -> bool:
    seen = set() if seen is None else set(seen)
    if name in seen or name not in functions:
        return False
    seen.add(name)
    body = functions[name].body
    if re.search(r"\brequireAccessAdmin\s*\(\s*session\s*\)", body):
        return True
    for candidate in functions:
        if candidate == name or not re.search(rf"\b{re.escape(candidate)}\s*\(\s*session\b", body):
            continue
        if _owner_gated(candidate, functions, seen):
            return True
    return False


def _console_contract(api_source: str, ui_source: str, errors: list[str]) -> None:
    endpoint_suffixes = ("list", "plan", "apply", "restore")
    required = {f"/api/lifecycle/{suffix}" for suffix in endpoint_suffixes}
    missing = sorted(endpoint for endpoint in required if endpoint not in api_source)
    if missing:
        errors.append(_error("console-lifecycle-surface", "Console API is missing: " + ", ".join(missing)))

    functions = _js_functions(api_source)
    handlers = {
        suffix: [
            name
            for name, function in functions.items()
            if name.lower().startswith("handlelifecycle") and suffix in name.lower()
        ]
        for suffix in endpoint_suffixes
    }
    for suffix, names in handlers.items():
        if not names:
            errors.append(
                _error("console-owner-gate", f"Console lifecycle {suffix} has no dedicated handler")
            )
            continue
        for name in names:
            if not _owner_gated(name, functions):
                errors.append(
                    _error(
                        "console-owner-gate",
                        f"Console lifecycle handler {name} is not configured-owner gated",
                    )
                )
            forbidden = set(_js_strings(functions[name].body)) & FORBIDDEN_CLIENT_FIELDS
            # Exact string literals used as body property keys are not all
            # returned by _js_strings, so include direct dotted access too.
            forbidden.update(
                field
                for field in FORBIDDEN_CLIENT_FIELDS
                if re.search(rf"\b(?:body|payload|request)\s*(?:\.\s*{re.escape(field)}|\[\s*['\"]{re.escape(field)}['\"]\s*\])", functions[name].body)
            )
            if forbidden:
                errors.append(
                    _error(
                        "client-execution-input",
                        f"Console lifecycle handler {name} accepts filesystem/command fields: {sorted(forbidden)}",
                    )
                )

    ui_functions = _js_functions(ui_source)
    for name, function in ui_functions.items():
        lowered = name.lower()
        if not any(word in lowered for word in ("hide", "hidden", "pref", "autounhide")):
            continue
        labels = set(_js_strings(function.body))
        if {"Archive", "Archived"} & labels or (
            "/api/prefs" in function.body and re.search(r"\bArchive(?:d)?\b", function.body)
        ):
            errors.append(
                _error(
                    "hide-is-not-archive",
                    f"Console preference/hide function {name} relabels ephemeral Hide as Archive",
                )
            )


def _inventory_contract(trees: Iterable[tuple[Path, ast.Module]], errors: list[str]) -> None:
    for path, tree in trees:
        constants, _collections = _module_string_collections(tree)
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            values = {
                child.value
                for child in ast.walk(function)
                if isinstance(child, ast.Constant) and isinstance(child.value, str)
            }
            referenced = {
                child.id for child in ast.walk(function) if isinstance(child, ast.Name)
            }
            for name in referenced:
                values.update(constants.get(name, set()))
            if not {"archived", "removed", "start_fence_violated"} <= values:
                continue
            marker_return = False
            for returned in (
                child for child in ast.walk(function) if isinstance(child, ast.Return) and child.value is not None
            ):
                if "start_fence_violated" in _field_accesses(
                    returned.value, {"record", "row", "item", "resource"}
                ):
                    marker_return = True
                if any(
                    isinstance(child, ast.Constant) and child.value == "start_fence_violated"
                    for child in ast.walk(returned.value)
                ):
                    marker_return = True
            if marker_return and any(isinstance(child, (ast.If, ast.IfExp)) for child in ast.walk(function)):
                return
    errors.append(
        _error(
            "active-lifecycle-projection",
            "active inventory needs one explicit archived/removed exclusion helper that returns only a start_fence_violated marker exception",
        )
    )


def cleanup_contract_errors(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    lifecycle_source = _read(root / LIFECYCLE_CLI_REL, errors, "lifecycle-cli-source")
    repository_source = _read(
        root / REPOSITORY_LIFECYCLE_REL, errors, "repository-lifecycle-source"
    )
    cleanup_source = _read(
        root / CLEANUP_LIFECYCLE_REL, errors, "cleanup-lifecycle-source"
    )
    http_source = _read(root / HTTP_API_REL, errors, "coordinator-http-source")
    console_api = _read(root / CONSOLE_API_REL, errors, "console-api-source")
    console_ui = _read(root / CONSOLE_UI_REL, errors, "console-ui-source")

    lifecycle_tree = _parse_python(root / LIFECYCLE_CLI_REL, lifecycle_source, errors)
    repository_tree = _parse_python(
        root / REPOSITORY_LIFECYCLE_REL, repository_source, errors
    )
    cleanup_tree = _parse_python(
        root / CLEANUP_LIFECYCLE_REL, cleanup_source, errors
    )
    http_tree = _parse_python(root / HTTP_API_REL, http_source, errors)
    if lifecycle_tree is not None:
        _parser_contract(lifecycle_tree, errors)
    if repository_tree is not None:
        _retention_contract(repository_tree, errors)
    if cleanup_tree is not None:
        _cleanup_lifecycle_contract(cleanup_tree, errors)
    if http_tree is not None:
        _http_contract(
            http_tree,
            http_source,
            errors,
            authority_trees=((cleanup_tree,) if cleanup_tree is not None else ()),
        )
    if console_api and console_ui:
        _console_contract(console_api, console_ui, errors)

    inventory_trees: list[tuple[Path, ast.Module]] = []
    coordinator = root / COORDINATOR_REL
    if coordinator.is_dir():
        for path in sorted(coordinator.rglob("*.py")):
            if "tests" in path.parts or path.name.startswith(("test_", "self_test_")):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError):
                continue
            inventory_trees.append((path, tree))
    _inventory_contract(inventory_trees, errors)
    _scan_commands(root, errors)
    return errors


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check archive and purge safety contracts.")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root to inspect",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    errors = cleanup_contract_errors(args.repo)
    if errors:
        print("cleanup contract failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("cleanup contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
