"""Confirmation-bound commissioning for exact project-owned systemd one-shots."""

from __future__ import annotations

import configparser
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable, Mapping, Sequence
import uuid


MAX_UNIT_BYTES = 256 * 1024
UNIT_NAME = re.compile(r"[a-z0-9][a-z0-9_.@-]{0,126}")
PLAN_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
DESIRED_STATES = frozenset(
    {"commissioned", "run-once", "timer-enabled", "timer-disabled"}
)
SYSTEMD_SHOW_FIELDS = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "InvocationID",
    "UnitFileState",
)


class SystemdCommissioningError(RuntimeError):
    """One safe, operator-actionable commissioning failure."""


@dataclass(frozen=True)
class UnitSource:
    name: str
    path: Path
    payload: bytes
    sha256: str


def _unit_stem(unit: str) -> str:
    """Accept the natural service filename while retaining one sibling stem."""

    if isinstance(unit, str) and unit.endswith(".service"):
        unit = unit[: -len(".service")]
    if not isinstance(unit, str) or UNIT_NAME.fullmatch(unit) is None:
        raise SystemdCommissioningError("systemd unit selector is invalid")
    return unit


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _read_regular(path: Path, *, required: bool) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not required:
            return None
        raise SystemdCommissioningError(f"unit source is unavailable: {path.name}")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_UNIT_BYTES
    ):
        raise SystemdCommissioningError(
            f"unit source must be one bounded regular file: {path.name}"
        )
    payload = path.read_bytes()
    if len(payload) != metadata.st_size or b"\0" in payload:
        raise SystemdCommissioningError(f"unit source is invalid: {path.name}")
    return payload


def _parsed_unit(payload: bytes, *, name: str) -> configparser.ConfigParser:
    try:
        text = payload.decode("utf-8")
        parser = configparser.ConfigParser(
            interpolation=None,
            strict=False,
            empty_lines_in_values=False,
        )
        parser.optionxform = str
        parser.read_string(text)
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise SystemdCommissioningError(f"unit file is invalid: {name}") from exc
    return parser


def _require_service_policy(source: UnitSource) -> None:
    parser = _parsed_unit(source.payload, name=source.name)
    if not parser.has_section("Service"):
        raise SystemdCommissioningError("commissioned unit requires [Service]")
    service = parser["Service"]
    user = str(service.get("User") or "").strip()
    group = str(service.get("Group") or "").strip()
    exec_start = str(service.get("ExecStart") or "").strip()
    if service.get("Type") != "oneshot":
        raise SystemdCommissioningError("commissioned service must use Type=oneshot")
    if not user or user in {"root", "0"} or not group:
        raise SystemdCommissioningError(
            "commissioned service requires one explicit non-root User and Group"
        )
    if not exec_start.startswith("/") or any(value in exec_start for value in "\0\r\n"):
        raise SystemdCommissioningError(
            "commissioned service requires one absolute fixed ExecStart"
        )
    forbidden = {
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    }
    if forbidden & set(service):
        raise SystemdCommissioningError(
            "commissioned one-shot must expose only its exact ExecStart command"
        )
    required = {
        "NoNewPrivileges": "true",
        "ProtectSystem": "strict",
        "UMask": "0077",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
    }
    for field, expected in required.items():
        if str(service.get(field, "")).strip() != expected:
            raise SystemdCommissioningError(
                f"commissioned service requires {field}={expected}"
            )


def _require_timer_policy(source: UnitSource, *, unit: str) -> None:
    parser = _parsed_unit(source.payload, name=source.name)
    if not parser.has_section("Timer") or not parser.has_section("Install"):
        raise SystemdCommissioningError(
            "commissioned timer requires [Timer] and [Install]"
        )
    if parser["Timer"].get("Unit") != f"{unit}.service":
        raise SystemdCommissioningError(
            "commissioned timer must target its exact sibling service"
        )
    if parser["Install"].get("WantedBy") != "timers.target":
        raise SystemdCommissioningError(
            "commissioned timer must use WantedBy=timers.target"
        )


def load_unit_sources(project: Path, unit: str) -> tuple[UnitSource, ...]:
    unit = _unit_stem(unit)
    try:
        project_info = project.lstat()
        resolved = project.resolve(strict=True)
    except OSError as exc:
        raise SystemdCommissioningError("project directory is unavailable") from exc
    if (
        project.is_symlink()
        or not stat.S_ISDIR(project_info.st_mode)
        or resolved != project
    ):
        raise SystemdCommissioningError(
            "project must be one canonical non-symlink directory"
        )
    directory = project / "deploy" / "systemd"
    service_path = directory / f"{unit}.service"
    service_payload = _read_regular(service_path, required=True)
    assert service_payload is not None
    service = UnitSource(
        name=service_path.name,
        path=service_path,
        payload=service_payload,
        sha256="sha256:" + hashlib.sha256(service_payload).hexdigest(),
    )
    _require_service_policy(service)
    sources = [service]
    timer_path = directory / f"{unit}.timer"
    timer_payload = _read_regular(timer_path, required=False)
    if timer_payload is not None:
        timer = UnitSource(
            name=timer_path.name,
            path=timer_path,
            payload=timer_payload,
            sha256="sha256:" + hashlib.sha256(timer_payload).hexdigest(),
        )
        _require_timer_policy(timer, unit=unit)
        sources.append(timer)
    return tuple(sources)


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        tuple(command),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30.0,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )


def _systemd_state(
    name: str,
    *,
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
    allow_unobservable: bool = False,
) -> dict[str, Any]:
    result = runner(
        (
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=" + ",".join(SYSTEMD_SHOW_FIELDS),
            name,
        )
    )
    if not isinstance(result, subprocess.CompletedProcess):
        raise SystemdCommissioningError("systemd observer returned invalid evidence")
    output = str(result.stdout or "")
    if len(output.encode("utf-8")) > 16 * 1024:
        raise SystemdCommissioningError("systemd observer exceeded its output bound")
    fields: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in SYSTEMD_SHOW_FIELDS:
            fields[key] = value
    if result.returncode != 0 or set(fields) != set(SYSTEMD_SHOW_FIELDS):
        if allow_unobservable:
            return {
                "name": name,
                "observable": False,
                "returncode": int(result.returncode),
                **{field: fields.get(field) for field in SYSTEMD_SHOW_FIELDS},
            }
        raise SystemdCommissioningError(
            f"systemd state is unobservable for exact unit {name}"
        )
    return {
        "name": name,
        "observable": True,
        "returncode": int(result.returncode),
        **fields,
    }


def _installed_evidence(installed_root: Path, source: UnitSource) -> dict[str, Any]:
    target = installed_root / source.name
    payload = _read_regular(target, required=False)
    return {
        "name": source.name,
        "present": payload is not None,
        "sha256": (
            None
            if payload is None
            else "sha256:" + hashlib.sha256(payload).hexdigest()
        ),
        "matches_source": payload == source.payload,
    }


def plan_commissioning(
    *,
    project: Path,
    unit: str,
    desired: str,
    installed_root: Path = Path("/etc/systemd/system"),
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _default_runner,
) -> dict[str, Any]:
    if desired not in DESIRED_STATES:
        raise SystemdCommissioningError("systemd desired state is invalid")
    unit = _unit_stem(unit)
    sources = load_unit_sources(project, unit)
    if desired in {"timer-enabled", "timer-disabled"} and len(sources) != 2:
        raise SystemdCommissioningError("timer lifecycle requires a sibling timer unit")
    source_evidence = [
        {"name": item.name, "sha256": item.sha256} for item in sources
    ]
    installed = [_installed_evidence(installed_root, item) for item in sources]
    states = [
        _systemd_state(
            item.name,
            runner=runner,
            allow_unobservable=desired == "commissioned",
        )
        for item in sources
        if (installed_root / item.name).exists()
    ]
    document = {
        "schema_version": 1,
        "project": str(project),
        "project_identity": {
            "device": project.stat().st_dev,
            "inode": project.stat().st_ino,
        },
        "unit": unit,
        "desired": desired,
        "sources": source_evidence,
        "installed": installed,
        "states": states,
    }
    fingerprint = _digest(document)
    return {
        **document,
        "plan_fingerprint": fingerprint,
        "confirmation": f"CONFIRM {desired} {unit} {fingerprint}",
        "mutation_performed": False,
    }


def _write_atomic(path: Path, payload: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _invoke(
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]],
    command: Sequence[str],
    *,
    action: str,
) -> None:
    result = runner(command)
    if not isinstance(result, subprocess.CompletedProcess) or result.returncode != 0:
        raise SystemdCommissioningError(
            f"systemd {action} outcome is uncertain; inspect exact status before retry"
        )


def apply_commissioning(
    *,
    project: Path,
    unit: str,
    desired: str,
    operation_id: str,
    confirmation_fingerprint: str,
    installed_root: Path = Path("/etc/systemd/system"),
    journal_root: Path = Path("/var/lib/devcoordinator/systemd-commissioning"),
    runner: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] = _default_runner,
    effective_uid: int | None = None,
) -> dict[str, Any]:
    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid != 0:
        raise PermissionError("systemd commissioning apply requires root")
    try:
        canonical_operation_id = str(uuid.UUID(operation_id))
    except (ValueError, AttributeError) as exc:
        raise SystemdCommissioningError("operation_id must be a canonical UUID") from exc
    if canonical_operation_id != operation_id:
        raise SystemdCommissioningError("operation_id must be a canonical UUID")
    if PLAN_FINGERPRINT.fullmatch(confirmation_fingerprint) is None:
        raise SystemdCommissioningError("confirmation fingerprint is invalid")
    unit = _unit_stem(unit)
    plan = plan_commissioning(
        project=project,
        unit=unit,
        desired=desired,
        installed_root=installed_root,
        runner=runner,
    )
    request_fingerprint = _digest(
        {
            "operation_id": operation_id,
            "plan_fingerprint": confirmation_fingerprint,
            "desired": desired,
        }
    )
    journal = journal_root / f"{operation_id}.json"
    reconciled_run_once = False
    prior: Mapping[str, Any] | None = None
    if journal.exists():
        prior = json.loads(journal.read_text(encoding="utf-8"))
        if prior.get("request_fingerprint") != request_fingerprint:
            raise SystemdCommissioningError(
                "operation_id was already used for another commissioning request"
            )
        if prior.get("status") == "completed":
            return dict(prior["result"])
    if plan["plan_fingerprint"] != confirmation_fingerprint:
        prior_plan = prior.get("plan") if isinstance(prior, Mapping) else None
        stable_fields = (
            "project",
            "project_identity",
            "unit",
            "desired",
            "sources",
        )
        if (
            not isinstance(prior_plan, Mapping)
            or prior_plan.get("plan_fingerprint") != confirmation_fingerprint
            or any(prior_plan.get(field) != plan.get(field) for field in stable_fields)
        ):
            raise SystemdCommissioningError(
                "systemd commissioning plan changed before confirmation"
            )
    if prior is not None:
        if desired == "run-once":
            service_state = _systemd_state(f"{unit}.service", runner=runner)
            before = prior.get("before_service_state")
            if (
                not isinstance(before, Mapping)
                or service_state["InvocationID"] == before.get("InvocationID")
                or service_state["Result"] != "success"
                or service_state["ExecMainStatus"] != "0"
            ):
                raise SystemdCommissioningError(
                    "prior run-once outcome requires manual reconciliation; it was not repeated"
                )
            reconciled_run_once = True
        # Commissioning and timer enable/disable are exact idempotent host
        # mutations. Replaying the same operation repairs an interrupted
        # journal without widening its source or target.
    else:
        before_service_state = (
            _systemd_state(
                f"{unit}.service",
                runner=runner,
                allow_unobservable=desired == "commissioned",
            )
            if (installed_root / f"{unit}.service").exists()
            else None
        )
        _write_atomic(
            journal,
            _canonical_json(
                {
                    "schema_version": 1,
                    "status": "running",
                    "request_fingerprint": request_fingerprint,
                    "plan": plan,
                    "before_service_state": before_service_state,
                }
            ),
            mode=0o600,
        )

    sources = load_unit_sources(project, unit)
    if desired == "commissioned":
        for source in sources:
            _write_atomic(installed_root / source.name, source.payload, mode=0o644)
        _invoke(
            runner,
            ("/usr/bin/systemctl", "daemon-reload"),
            action="daemon-reload",
        )
    else:
        if any(
            not _installed_evidence(installed_root, source)["matches_source"]
            for source in sources
        ):
            raise SystemdCommissioningError(
                "activate only an already commissioned source-current unit"
            )
        if desired == "run-once":
            if not reconciled_run_once:
                _invoke(
                    runner,
                    ("/usr/bin/systemctl", "start", f"{unit}.service"),
                    action="run-once",
                )
        elif desired == "timer-enabled":
            _invoke(
                runner,
                ("/usr/bin/systemctl", "enable", "--now", f"{unit}.timer"),
                action="timer enable",
            )
        else:
            _invoke(
                runner,
                ("/usr/bin/systemctl", "disable", "--now", f"{unit}.timer"),
                action="timer disable",
            )

    installed = [_installed_evidence(installed_root, item) for item in sources]
    if not all(item["matches_source"] for item in installed):
        raise SystemdCommissioningError(
            "commissioned unit identity changed during apply"
        )
    states = [_systemd_state(item.name, runner=runner) for item in sources]
    service_state = states[0]
    if desired == "run-once" and (
        service_state["Result"] != "success"
        or service_state["ExecMainStatus"] != "0"
    ):
        raise SystemdCommissioningError(
            "run-once unit did not prove a successful terminal result"
        )
    if desired == "timer-enabled" and states[1]["ActiveState"] != "active":
        raise SystemdCommissioningError("timer did not become active")
    if desired == "timer-disabled" and states[1]["ActiveState"] == "active":
        raise SystemdCommissioningError("timer remained active")
    result = {
        "ok": True,
        "operation_id": operation_id,
        "unit": unit,
        "desired": desired,
        "plan_fingerprint": confirmation_fingerprint,
        "installed": installed,
        "states": states,
        "mutation_performed": True,
        "reconciled_without_reexecution": reconciled_run_once,
    }
    _write_atomic(
        journal,
        _canonical_json(
            {
                "schema_version": 1,
                "status": "completed",
                "request_fingerprint": request_fingerprint,
                "result": result,
            }
        ),
        mode=0o600,
    )
    return result


__all__ = [
    "DESIRED_STATES",
    "SystemdCommissioningError",
    "apply_commissioning",
    "load_unit_sources",
    "plan_commissioning",
]
