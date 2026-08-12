"""Bounded observation and cleanup for host-side automation browser trees.

The browser observer intentionally owns only automation browsers launched in a
developer login session or otherwise left unmanaged on the host.  Browsers in
project, container, test, or Coordinator control cgroups keep their existing
lifecycle owner.  Test and control browsers remain visible as protected detail;
project and container browsers are excluded entirely so their memory is never
counted twice.

Linux does not expose a historical "last used" timestamp for a process.  This
module therefore records only first/last observation and resource activity
proved by deltas between samples.  Cleanup is fenced by the kernel boot ID plus
PID/start ticks and uses pidfds, TERM, a bounded wait, then KILL.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import tempfile
import time
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol


SCHEMA_VERSION = 1
DEFAULT_STATE_PATH = Path(
    "/var/lib/devcoordinator-browser-lifecycle/browser-lifecycle.json"
)
DEFAULT_IDLE_SECONDS = 15 * 60
DEFAULT_TERM_TIMEOUT_SECONDS = 5.0
DEFAULT_KILL_TIMEOUT_SECONDS = 2.0
DEFAULT_QUIESCENCE_SECONDS = 2.0
MAX_SCANNED_PROCESSES = 4096
MAX_ACTIVE_SESSIONS = 128
MAX_MEMBERS_PER_SESSION = 128
MAX_TOTAL_MEMBER_IDENTITIES = 4096
MAX_REAPED_SESSIONS = 256
MAX_STATE_BYTES = 1024 * 1024
MAX_CGROUP_LENGTH = 512

_CHROME_EXECUTABLES = frozenset(
    {
        "chrome",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome-headless-shell",
    }
)
_FIREFOX_EXECUTABLES = frozenset({"firefox", "firefox-esr"})
_WEBKIT_ROOT_EXECUTABLES = frozenset({"minibrowser", "webkit-minibrowser"})
_AUTOMATION_FLAGS = frozenset(
    {
        "--enable-automation",
        "--remote-debugging-pipe",
        "--test-type",
    }
)
_AGENT_BROWSER = re.compile(r"^agent-browser(?:-[a-z0-9_.-]+)?$")
_BROWSER_HELPER_EXECUTABLES = frozenset(
    {
        "chrome_crashpad_handler",
        "chromedriver",
        "chrome-sandbox",
        "nacl_helper",
        "webkitwebprocess",
        "webkitnetworkprocess",
        "webkitgpuprocess",
        "webkitwebextensionprocess",
    }
)


class BrowserLifecycleError(RuntimeError):
    """Browser lifecycle evidence could not be produced or applied safely."""


class ProcessController(Protocol):
    """A race-safe handle-based process signaling boundary."""

    def open(self, pid: int) -> Any: ...

    def send(self, handle: Any, signum: int) -> None: ...

    def wait(self, handle: Any, timeout_seconds: float) -> bool: ...

    def close(self, handle: Any) -> None: ...


class PidfdProcessController:
    """Linux pidfd implementation used by production cleanup."""

    def __init__(self) -> None:
        if (
            not hasattr(os, "pidfd_open")
            or not hasattr(signal, "pidfd_send_signal")
            or not hasattr(select, "poll")
        ):
            raise BrowserLifecycleError(
                "browser cleanup requires Linux pidfd signaling"
            )

    def open(self, pid: int) -> int:
        return os.pidfd_open(pid, 0)

    def send(self, handle: int, signum: int) -> None:
        signal.pidfd_send_signal(handle, signum, None, 0)

    def wait(self, handle: int, timeout_seconds: float) -> bool:
        poller = select.poll()
        poller.register(handle, select.POLLIN)
        return bool(poller.poll(max(0, round(timeout_seconds * 1000))))

    def close(self, handle: int) -> None:
        os.close(handle)


@dataclass(frozen=True)
class _Process:
    pid: int
    ppid: int
    start_ticks: str
    uid: int | None
    cgroup: str
    executable: str
    argv: tuple[str, ...]
    cpu_ticks: int
    io_read_bytes: int | None
    io_write_bytes: int | None
    rss_bytes: int | None
    pss_bytes: int | None

    @property
    def measured_memory_bytes(self) -> int | None:
        return self.pss_bytes if self.pss_bytes is not None else self.rss_bytes


def _bounded_text(value: object, maximum: int) -> str:
    text = str(value or "")
    if len(text) <= maximum:
        return text
    return text[: maximum - 1] + "…"


def _iso_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _timestamp_epoch(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _parse_stat(text: str) -> dict[str, int | str]:
    closing = text.rfind(")")
    opening = text.find("(")
    if opening <= 0 or closing <= opening:
        raise BrowserLifecycleError("process stat has no valid comm field")
    fields = text[closing + 1 :].split()
    if len(fields) < 22:
        raise BrowserLifecycleError("process stat has fewer than 24 fields")
    try:
        return {
            "state": fields[0],
            "ppid": int(fields[1]),
            "utime": int(fields[11]),
            "stime": int(fields[12]),
            "start_ticks": fields[19],
            "rss_pages": int(fields[21]),
        }
    except (TypeError, ValueError) as error:
        raise BrowserLifecycleError("process stat fields are malformed") from error


def _parse_status_uid(text: str) -> int | None:
    for line in text.splitlines():
        if not line.startswith("Uid:"):
            continue
        fields = line.split()
        try:
            return int(fields[1])
        except (IndexError, ValueError):
            return None
    return None


def _parse_cgroup(text: str) -> str:
    fallback = ""
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        fallback = fields[2]
        if fields[0] == "0" and fields[1] == "":
            return _bounded_text(fields[2], MAX_CGROUP_LENGTH)
    return _bounded_text(fallback, MAX_CGROUP_LENGTH)


def _parse_io(text: str) -> tuple[int | None, int | None]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        name, separator, raw = line.partition(":")
        if not separator:
            continue
        try:
            values[name.strip()] = max(0, int(raw.strip()))
        except ValueError:
            continue
    return values.get("read_bytes"), values.get("write_bytes")


def _parse_pss(text: str) -> int | None:
    for line in text.splitlines():
        if not line.startswith("Pss:"):
            continue
        fields = line.split()
        try:
            return max(0, int(fields[1])) * 1024
        except (IndexError, ValueError):
            return None
    return None


def _read_optional_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError:
        return None


def _read_process(
    process: Path,
    *,
    page_size: int,
    include_usage: bool = False,
) -> _Process:
    """Read stat -> process evidence -> stat and reject PID reuse."""

    before = _parse_stat((process / "stat").read_text(encoding="utf-8"))
    command = tuple(
        part.decode("utf-8", errors="replace")
        for part in (process / "cmdline").read_bytes().split(b"\0")
        if part
    )
    # UID and cgroup ownership determine whether this process is eligible for
    # separate accounting or cleanup.  They are mandatory evidence: treating
    # an unreadable project/container cgroup as "unmanaged" would be unsafe.
    status_text = (process / "status").read_text(encoding="utf-8")
    cgroup_text = (process / "cgroup").read_text(encoding="utf-8")
    io_text = _read_optional_text(process / "io") if include_usage else None
    smaps_text = _read_optional_text(process / "smaps_rollup") if include_usage else None
    try:
        executable = os.path.basename(os.readlink(process / "exe"))
    except OSError:
        executable = os.path.basename(command[0]) if command else ""
    after = _parse_stat((process / "stat").read_text(encoding="utf-8"))
    if before["start_ticks"] != after["start_ticks"]:
        raise BrowserLifecycleError("process identity changed during observation")
    if after["state"] in {"Z", "X"}:
        raise ProcessLookupError(process.name)
    io_read, io_write = _parse_io(io_text) if io_text is not None else (None, None)
    rss_pages = int(after["rss_pages"])
    return _Process(
        pid=int(process.name),
        ppid=int(after["ppid"]),
        start_ticks=str(after["start_ticks"]),
        uid=_parse_status_uid(status_text),
        cgroup=_parse_cgroup(cgroup_text),
        executable=_bounded_text(executable, 128),
        argv=command,
        cpu_ticks=int(after["utime"]) + int(after["stime"]),
        io_read_bytes=io_read,
        io_write_bytes=io_write,
        rss_bytes=max(0, rss_pages) * page_size,
        pss_bytes=_parse_pss(smaps_text) if smaps_text is not None else None,
    )


def _browser_kind(process: _Process) -> str | None:
    executable = process.executable.lower()
    if executable == "headless_shell" or executable == "chrome-headless-shell":
        return "headless-shell"
    if _AGENT_BROWSER.fullmatch(executable):
        return "agent-browser"
    if executable in {"node", "nodejs"} and _node_agent_browser_launcher(process.argv):
        return "agent-browser"
    if executable in _FIREFOX_EXECUTABLES:
        flags = process.argv[1:]
        if any(flag in {"-headless", "--headless"} for flag in flags):
            return "firefox-headless"
        if "-juggler-pipe" in flags:
            return "firefox-automation"
        return None
    if executable in _WEBKIT_ROOT_EXECUTABLES:
        flags = process.argv[1:]
        if any(
            flag in {
                "-headless",
                "--headless",
                "--inspector-pipe",
                "-inspector-pipe",
                "--automation",
            }
            for flag in flags
        ) or _playwright_webkit_path(process.argv):
            return "webkit-playwright"
        return None
    if executable not in _CHROME_EXECUTABLES:
        return None
    flags = process.argv[1:]
    if any(flag == "--headless" or flag.startswith("--headless=") for flag in flags):
        return "chrome-headless"
    if any(flag in _AUTOMATION_FLAGS for flag in flags):
        return "chrome-automation"
    return None


def _node_agent_browser_launcher(argv: tuple[str, ...]) -> bool:
    """Recognize only the executable/script slot of an explicit Node launcher."""

    for raw in argv[:2]:
        path = raw.replace("\\", "/")
        basename = path.rsplit("/", 1)[-1].lower()
        stem = re.sub(r"\.(?:c?js|mjs)$", "", basename)
        if _AGENT_BROWSER.fullmatch(stem):
            return True
        components = [component.lower() for component in path.split("/") if component]
        if any(_AGENT_BROWSER.fullmatch(component) for component in components):
            return True
    return False


def _playwright_webkit_path(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    components = [
        component.lower()
        for component in argv[0].replace("\\", "/").split("/")
        if component
    ]
    return "ms-playwright" in components and any(
        component.startswith("webkit-") for component in components
    )


def _is_browser_tree_member(process: _Process) -> bool:
    executable = process.executable.lower()
    return bool(
        executable in _CHROME_EXECUTABLES
        or executable in _FIREFOX_EXECUTABLES
        or executable in _WEBKIT_ROOT_EXECUTABLES
        or executable in _BROWSER_HELPER_EXECUTABLES
        or executable == "headless_shell"
        or _AGENT_BROWSER.fullmatch(executable)
        or _browser_kind(process) == "agent-browser"
    )


def classify_browser_cgroup(paths: Iterable[str]) -> str:
    """Classify ownership from explicit cgroup topology, never process names."""

    values = tuple(str(path or "") for path in paths)
    components = {
        component
        for value in values
        for component in value.split("/")
        if component
    }
    if (
        any(component.startswith("docker-") and component.endswith(".scope") for component in components)
        or any(component.startswith("libpod-") and component.endswith(".scope") for component in components)
        or any(component.startswith("containerd-") for component in components)
        or "containerd.service" in components
        or "docker" in components
        or any(component.startswith("kubepods") for component in components)
    ):
        return "container"
    if any("devcoordinator-projects" in component for component in components):
        return "project"
    if any("devcoordinator-tests" in component for component in components):
        return "test"
    if any(
        component in {
            "devcoordinator.slice",
            "devcoordinator-control.slice",
            "devcoordinator-background.slice",
        }
        for component in components
    ):
        return "control"
    if any(value.startswith("/user.slice/") for value in values):
        return "developer-session"
    return "unmanaged"


def _boot_id(proc_root: Path) -> str:
    value = _read_optional_text(proc_root / "sys/kernel/random/boot_id")
    return _bounded_text((value or "unknown").strip() or "unknown", 80)


def _session_id(boot_id: str, root: _Process) -> str:
    digest = hashlib.sha256(
        f"{boot_id}\0{root.pid}\0{root.start_ticks}".encode("utf-8")
    ).hexdigest()[:32]
    return f"browser-{digest}"


def _candidate_roots(processes: Mapping[int, _Process]) -> list[tuple[_Process, str]]:
    candidates = {
        pid: kind
        for pid, process in processes.items()
        if (kind := _browser_kind(process)) is not None
    }
    roots: list[tuple[_Process, str]] = []
    for pid in sorted(candidates):
        parent = processes[pid].ppid
        seen: set[int] = set()
        has_candidate_ancestor = False
        while parent in processes and parent not in seen:
            seen.add(parent)
            if parent in candidates:
                has_candidate_ancestor = True
                break
            parent = processes[parent].ppid
        if not has_candidate_ancestor:
            roots.append((processes[pid], candidates[pid]))
    return roots


def _descendant_members(
    root: _Process,
    processes: Mapping[int, _Process],
) -> tuple[list[tuple[_Process, int]], bool]:
    children: dict[int, list[int]] = {}
    for process in processes.values():
        children.setdefault(process.ppid, []).append(process.pid)
    members: list[tuple[_Process, int]] = []
    queue: list[tuple[int, int]] = [(root.pid, 0)]
    seen: set[int] = set()
    complete = True
    while queue:
        pid, depth = queue.pop(0)
        if pid in seen or pid not in processes:
            continue
        seen.add(pid)
        if len(members) >= MAX_MEMBERS_PER_SESSION:
            complete = False
            continue
        members.append((processes[pid], depth))
        queue.extend((child, depth + 1) for child in sorted(children.get(pid, ())))
    return members, complete


def _positive_delta(current: int | None, previous: object) -> int:
    if current is None or type(previous) is not int:
        return 0
    return max(0, current - int(previous))


def _build_session(
    *,
    boot_id: str,
    root: _Process,
    kind: str,
    members: list[tuple[_Process, int]],
    identity_complete: bool,
    previous: Mapping[str, Any] | None,
    sampled_at: str,
    elapsed_seconds: float | None,
    clock_ticks: int,
    root_parent_present: bool,
) -> dict[str, Any]:
    classification = classify_browser_cgroup(process.cgroup for process, _ in members)
    previous_members = {
        (int(item.get("pid", -1)), str(item.get("start_ticks") or "")): item
        for item in (previous or {}).get("members", ())
        if isinstance(item, Mapping)
    }
    cpu_total = sum(process.cpu_ticks for process, _ in members)
    cpu_delta = 0
    io_read_total = 0
    io_write_total = 0
    io_read_complete = True
    io_write_complete = True
    io_read_delta = 0
    io_write_delta = 0
    new_member = previous is not None and len(previous_members) != len(members)
    member_records: list[dict[str, Any]] = []
    pss_count = 0
    rss_fallback_count = 0
    memory_count = 0
    memory_bytes = 0
    rss_bytes = 0
    for process, depth in members:
        prior = previous_members.get((process.pid, process.start_ticks), {})
        cpu_delta += _positive_delta(process.cpu_ticks, prior.get("cpu_ticks"))
        if process.io_read_bytes is None:
            io_read_complete = False
        else:
            io_read_total += process.io_read_bytes
            io_read_delta += _positive_delta(
                process.io_read_bytes, prior.get("io_read_bytes")
            )
        if process.io_write_bytes is None:
            io_write_complete = False
        else:
            io_write_total += process.io_write_bytes
            io_write_delta += _positive_delta(
                process.io_write_bytes, prior.get("io_write_bytes")
            )
        if process.rss_bytes is not None:
            rss_bytes += process.rss_bytes
        measured = process.measured_memory_bytes
        if measured is not None:
            memory_count += 1
            memory_bytes += measured
            if process.pss_bytes is not None:
                pss_count += 1
            else:
                rss_fallback_count += 1
        member_records.append(
            {
                "pid": process.pid,
                "ppid": process.ppid,
                "depth": depth,
                "start_ticks": process.start_ticks,
                "cpu_ticks": process.cpu_ticks,
                "io_read_bytes": process.io_read_bytes,
                "io_write_bytes": process.io_write_bytes,
            }
        )
    resource_activity = cpu_delta > 0 or io_read_delta > 0 or io_write_delta > 0 or new_member
    prior_resource_activity = (previous or {}).get("last_resource_activity_at")
    last_resource_activity_at = sampled_at if resource_activity else prior_resource_activity
    first_seen_at = str((previous or {}).get("first_seen_at") or sampled_at)
    fully_browser_classified = all(
        _is_browser_tree_member(process) for process, _depth in members
    )
    orphaned = bool(
        fully_browser_classified
        and (root.ppid == 1 or (root.ppid > 1 and not root_parent_present))
    )
    previous_orphaned = bool((previous or {}).get("orphaned"))
    orphan_observation_count = (
        int((previous or {}).get("orphan_observation_count") or 0) + 1
        if orphaned and previous_orphaned
        else (1 if orphaned else 0)
    )
    orphan_first_seen_at = (
        str((previous or {}).get("orphan_first_seen_at") or sampled_at)
        if orphaned
        else None
    )
    if pss_count == len(members):
        measurement = "pss"
    elif pss_count > 0:
        measurement = "mixed"
    else:
        measurement = "rss"
    cpu_percent = None
    if elapsed_seconds is not None and elapsed_seconds > 0 and clock_ticks > 0:
        cpu_percent = round((cpu_delta / clock_ticks / elapsed_seconds) * 100.0, 4)
    accounted = classification in {"developer-session", "unmanaged"}
    protected = classification in {"test", "control"}
    return {
        "session_id": _session_id(boot_id, root),
        "managed": False,
        "state": "active",
        "classification": classification,
        "accounted": accounted,
        "protected": protected,
        "protection_reason": (
            f"{classification}-owned" if protected else None
        ),
        "owner_uid": root.uid,
        "root_pid": root.pid,
        "root_start_ticks": root.start_ticks,
        "browser_kind": kind,
        "launcher_kind": "legacy-process-tree",
        "cgroup_path": _bounded_text(root.cgroup, MAX_CGROUP_LENGTH),
        "first_seen_at": first_seen_at,
        "last_seen_at": sampled_at,
        "last_activity_at": last_resource_activity_at,
        "last_resource_activity_at": last_resource_activity_at,
        "activity_source": "resource-delta" if last_resource_activity_at else "first-observed",
        "activity_confidence": "observed-window" if previous is not None else "unknown-before-first-observation",
        "resource_activity": resource_activity,
        "orphaned": orphaned,
        "orphan_observation_count": orphan_observation_count,
        "orphan_first_seen_at": orphan_first_seen_at,
        "fully_browser_classified": fully_browser_classified,
        "process_count": len(members),
        "identity_complete": identity_complete,
        "current_memory_bytes": memory_bytes,
        "rss_bytes": rss_bytes,
        "memory_measurement": measurement,
        "memory_exact": pss_count == len(members),
        "memory_coverage": round(memory_count / len(members), 6) if members else 0.0,
        "pss_process_count": pss_count,
        "rss_fallback_process_count": rss_fallback_count,
        "cpu_ticks": cpu_total,
        "cpu_ticks_delta": cpu_delta,
        "cpu_percent": cpu_percent,
        "io_read_bytes": io_read_total if io_read_complete else None,
        "io_write_bytes": io_write_total if io_write_complete else None,
        "io_read_bytes_delta": io_read_delta,
        "io_write_bytes_delta": io_write_delta,
        "members": member_records,
    }


def _scan(
    *,
    proc_root: Path,
    previous: Mapping[str, Any] | None,
    sampled_epoch: float,
    page_size: int,
    clock_ticks: int,
) -> dict[str, Any]:
    sampled_at = _iso_timestamp(sampled_epoch)
    previous_sample_epoch = _timestamp_epoch((previous or {}).get("sampled_at"))
    elapsed = (
        max(0.0, sampled_epoch - previous_sample_epoch)
        if previous_sample_epoch is not None
        else None
    )
    current_boot_id = _boot_id(proc_root)
    previous_active = {
        str(item.get("session_id")): item
        for item in (previous or {}).get("active", ())
        if isinstance(item, Mapping)
        and (previous or {}).get("boot_id") == current_boot_id
    }
    processes: dict[int, _Process] = {}
    unreadable = 0
    candidates = []
    try:
        candidates = sorted(
            (item for item in proc_root.iterdir() if item.name.isdigit()),
            key=lambda item: int(item.name),
        )
    except OSError as error:
        raise BrowserLifecycleError(f"process inventory is unavailable: {error}") from error
    scan_complete = len(candidates) <= MAX_SCANNED_PROCESSES
    for process_path in candidates[:MAX_SCANNED_PROCESSES]:
        try:
            process = _read_process(process_path, page_size=page_size)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, BrowserLifecycleError, OSError):
            unreadable += 1
            scan_complete = False
            continue
        processes[process.pid] = process

    active: list[dict[str, Any]] = []
    excluded = {
        "project_session_count": 0,
        "project_process_count": 0,
        "container_session_count": 0,
        "container_process_count": 0,
    }
    total_members = 0
    omitted_sessions = 0
    for root, kind in _candidate_roots(processes):
        lightweight_members, identity_complete = _descendant_members(root, processes)
        members: list[tuple[_Process, int]] = []
        for lightweight, depth in lightweight_members:
            try:
                detailed = _read_process(
                    proc_root / str(lightweight.pid),
                    page_size=page_size,
                    include_usage=True,
                )
            except (FileNotFoundError, ProcessLookupError):
                identity_complete = False
                continue
            except (PermissionError, BrowserLifecycleError, OSError):
                identity_complete = False
                scan_complete = False
                continue
            if detailed.start_ticks != lightweight.start_ticks:
                identity_complete = False
                scan_complete = False
                continue
            members.append((detailed, depth))
        if not members or members[0][0].pid != root.pid:
            scan_complete = False
            continue
        detailed_root = members[0][0]
        classification = classify_browser_cgroup(item.cgroup for item, _ in members)
        if classification in {"project", "container"}:
            excluded[f"{classification}_session_count"] += 1
            excluded[f"{classification}_process_count"] += len(members)
            continue
        if len(active) >= MAX_ACTIVE_SESSIONS or total_members + len(members) > MAX_TOTAL_MEMBER_IDENTITIES:
            omitted_sessions += 1
            scan_complete = False
            continue
        session_id = _session_id(current_boot_id, detailed_root)
        session = _build_session(
            boot_id=current_boot_id,
            root=detailed_root,
            kind=kind,
            members=members,
            identity_complete=identity_complete,
            previous=previous_active.get(session_id),
            sampled_at=sampled_at,
            elapsed_seconds=elapsed,
            clock_ticks=clock_ticks,
            root_parent_present=detailed_root.ppid in processes,
        )
        if not identity_complete:
            scan_complete = False
        active.append(session)
        total_members += len(members)

    active.sort(key=lambda item: (str(item["classification"]), str(item["session_id"])))
    accounted = [item for item in active if item["accounted"]]
    memory_measurements = {str(item["memory_measurement"]) for item in accounted}
    if not memory_measurements or memory_measurements == {"pss"}:
        total_measurement = "pss"
    elif memory_measurements == {"rss"}:
        total_measurement = "rss"
    else:
        total_measurement = "mixed"
    all_previous_reaped = [
        dict(item)
        for item in (previous or {}).get("reaped", ())
        if isinstance(item, Mapping)
    ]
    previous_reaped = list(all_previous_reaped)
    prior_reaped_omitted = int((previous or {}).get("reaped_omitted_count") or 0)
    reaped_omitted = prior_reaped_omitted
    if len(previous_reaped) > MAX_REAPED_SESSIONS:
        reaped_omitted += len(previous_reaped) - MAX_REAPED_SESSIONS
        previous_reaped = previous_reaped[-MAX_REAPED_SESSIONS:]
    return {
        "schema_version": SCHEMA_VERSION,
        "generation": int((previous or {}).get("generation") or 0) + 1,
        "sampled_at": sampled_at,
        "boot_id": current_boot_id,
        "scan_complete": scan_complete,
        "unreadable_process_count": unreadable,
        "omitted_session_count": omitted_sessions,
        "active_session_count": len(active),
        "accounted_session_count": len(accounted),
        "protected_session_count": sum(1 for item in active if item["protected"]),
        "active": active,
        "reaped": previous_reaped,
        "reaped_omitted_count": reaped_omitted,
        "reaped_total": int(
            (previous or {}).get("reaped_total")
            or (prior_reaped_omitted + len(all_previous_reaped))
        ),
        "reclaimed_memory_bytes_total": int(
            (previous or {}).get("reclaimed_memory_bytes_total")
            or sum(int(item.get("memory_bytes") or 0) for item in all_previous_reaped)
        ),
        "excluded": excluded,
        "totals": {
            "session_count": len(accounted),
            "process_count": sum(int(item["process_count"]) for item in accounted),
            "memory_bytes": sum(int(item["current_memory_bytes"]) for item in accounted),
            "rss_bytes": sum(int(item["rss_bytes"]) for item in accounted),
            "memory_measurement": total_measurement,
            "memory_exact": all(bool(item["memory_exact"]) for item in accounted),
            "memory_coverage": (
                round(
                    sum(int(item["process_count"]) * float(item["memory_coverage"]) for item in accounted)
                    / sum(int(item["process_count"]) for item in accounted),
                    6,
                )
                if sum(int(item["process_count"]) for item in accounted)
                else 1.0
            ),
            "cpu_percent": round(sum(float(item["cpu_percent"] or 0.0) for item in accounted), 4),
            "cpu_ticks_delta": sum(int(item["cpu_ticks_delta"]) for item in accounted),
            "io_read_bytes_delta": sum(int(item["io_read_bytes_delta"]) for item in accounted),
            "io_write_bytes_delta": sum(int(item["io_write_bytes_delta"]) for item in accounted),
        },
    }


def _state_lock_path(state_path: Path) -> Path:
    return state_path.with_name(state_path.name + ".lock")


@contextmanager
def _state_lock(state_path: Path, *, exclusive: bool) -> Iterator[None]:
    lock_path = _state_lock_path(state_path)
    if exclusive:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        # The authority service runs with UMask=0077. Status readers need no
        # write access, but every trusted developer account must be able to
        # acquire a shared flock on this coordination inode.
        os.fchmod(descriptor, 0o644)
    else:
        try:
            descriptor = os.open(lock_path, os.O_RDONLY)
        except FileNotFoundError:
            if state_path.exists() or state_path.is_symlink():
                raise BrowserLifecycleError(
                    "browser lifecycle lock is unavailable for existing state"
                )
            yield
            return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _validate_state(document: object) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise BrowserLifecycleError("browser lifecycle state schema is invalid")
    if not isinstance(document.get("active"), list) or not isinstance(document.get("reaped"), list):
        raise BrowserLifecycleError("browser lifecycle active/reaped state is invalid")
    return document


def _read_state_unlocked(state_path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        raise BrowserLifecycleError(f"browser lifecycle state is unreadable: {error}") from error
    return _validate_state(document)


def read_browser_lifecycle_state(
    state_path: Path | str = DEFAULT_STATE_PATH,
) -> dict[str, Any] | None:
    """Return the current bounded document without probing or mutating host state."""

    path = Path(state_path)
    with _state_lock(path, exclusive=False):
        document = _read_state_unlocked(path)
        return None if document is None else json.loads(json.dumps(document))


def _write_state_unlocked(state_path: Path, document: Mapping[str, Any]) -> None:
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise BrowserLifecycleError(
            f"browser lifecycle state exceeds {MAX_STATE_BYTES} bytes"
        )
    state_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{state_path.name}.", suffix=".tmp", dir=state_path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, state_path)
        directory = os.open(state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _append_reaped(
    document: dict[str, Any],
    records: Iterable[Mapping[str, Any]],
) -> None:
    additions = [dict(item) for item in records]
    retained = [dict(item) for item in document.get("reaped", ()) if isinstance(item, Mapping)]
    retained.extend(additions)
    document["reaped_total"] = int(document.get("reaped_total") or 0) + len(additions)
    document["reclaimed_memory_bytes_total"] = int(
        document.get("reclaimed_memory_bytes_total") or 0
    ) + sum(int(item.get("memory_bytes") or 0) for item in additions)
    overflow = max(0, len(retained) - MAX_REAPED_SESSIONS)
    if overflow:
        document["reaped_omitted_count"] = int(document.get("reaped_omitted_count") or 0) + overflow
        retained = retained[overflow:]
    document["reaped"] = retained


def _stable_identity(proc_root: Path, pid: int) -> tuple[str, tuple[str, ...]] | None:
    process = proc_root / str(pid)
    try:
        before = _parse_stat((process / "stat").read_text(encoding="utf-8"))
        command = tuple(
            part.decode("utf-8", errors="replace")
            for part in (process / "cmdline").read_bytes().split(b"\0")
            if part
        )
        after = _parse_stat((process / "stat").read_text(encoding="utf-8"))
    except (FileNotFoundError, ProcessLookupError):
        return None
    if before["start_ticks"] != after["start_ticks"]:
        raise BrowserLifecycleError("process identity changed during cleanup binding")
    return str(after["start_ticks"]), command


def _terminate_session(
    session: Mapping[str, Any],
    *,
    proc_root: Path,
    controller: ProcessController,
    term_timeout_seconds: float,
    kill_timeout_seconds: float,
    monotonic_fn: Callable[[], float],
) -> dict[str, Any]:
    if not session.get("identity_complete"):
        return {"ok": False, "code": "identity_incomplete", "terminated_process_count": 0}
    members = [item for item in session.get("members", ()) if isinstance(item, Mapping)]
    members.sort(key=lambda item: (-int(item.get("depth") or 0), int(item.get("pid") or 0)))
    handles: list[tuple[Mapping[str, Any], Any]] = []
    try:
        for member in members:
            pid = int(member["pid"])
            expected_start = str(member["start_ticks"])
            observed = _stable_identity(proc_root, pid)
            if observed is None:
                continue
            if observed[0] != expected_start:
                return {"ok": False, "code": "identity_changed", "terminated_process_count": 0}
            try:
                handle = controller.open(pid)
            except ProcessLookupError:
                continue
            rebound = _stable_identity(proc_root, pid)
            if rebound is None:
                controller.close(handle)
                continue
            if rebound[0] != expected_start:
                controller.close(handle)
                return {"ok": False, "code": "identity_changed", "terminated_process_count": 0}
            handles.append((member, handle))
        for _member, handle in handles:
            try:
                controller.send(handle, signal.SIGTERM)
            except ProcessLookupError:
                pass
        term_deadline = monotonic_fn() + max(0.0, term_timeout_seconds)
        survivors: list[tuple[Mapping[str, Any], Any]] = []
        for member, handle in handles:
            remaining = max(0.0, term_deadline - monotonic_fn())
            if not controller.wait(handle, remaining):
                survivors.append((member, handle))
        for _member, handle in survivors:
            try:
                controller.send(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass
        kill_deadline = monotonic_fn() + max(0.0, kill_timeout_seconds)
        not_stopped = 0
        for _member, handle in survivors:
            remaining = max(0.0, kill_deadline - monotonic_fn())
            if not controller.wait(handle, remaining):
                not_stopped += 1
        if not_stopped:
            return {
                "ok": False,
                "code": "processes_survived_sigkill",
                "terminated_process_count": len(handles) - not_stopped,
            }
        return {
            "ok": True,
            "code": "terminated",
            "terminated_process_count": len(handles),
            "killed_process_count": len(survivors),
        }
    except (KeyError, TypeError, ValueError, OSError, BrowserLifecycleError) as error:
        return {
            "ok": False,
            "code": "termination_error",
            "error_type": type(error).__name__,
            "terminated_process_count": 0,
        }
    finally:
        for _member, handle in handles:
            try:
                controller.close(handle)
            except OSError:
                pass


def _eligible(session: Mapping[str, Any]) -> bool:
    return bool(session.get("accounted")) and session.get("classification") in {
        "developer-session",
        "unmanaged",
    }


def _orphan_reap_due(session: Mapping[str, Any], sampled_epoch: float) -> bool:
    if not session.get("orphaned") or not session.get("fully_browser_classified"):
        return False
    if int(session.get("orphan_observation_count") or 0) >= 2:
        return True
    first_seen = _timestamp_epoch(session.get("orphan_first_seen_at"))
    return first_seen is not None and sampled_epoch - first_seen >= 60.0


def _observe_unlocked(
    *,
    state_path: Path,
    proc_root: Path,
    previous: Mapping[str, Any] | None,
    sampled_epoch: float,
    page_size: int,
    clock_ticks: int,
) -> dict[str, Any]:
    document = _scan(
        proc_root=proc_root,
        previous=previous,
        sampled_epoch=sampled_epoch,
        page_size=page_size,
        clock_ticks=clock_ticks,
    )
    _write_state_unlocked(state_path, document)
    return document


def observe_browser_lifecycle(
    state_path: Path | str = DEFAULT_STATE_PATH,
    *,
    reap_idle: bool = True,
    idle_seconds: int = DEFAULT_IDLE_SECONDS,
    proc_root: Path | str = Path("/proc"),
    now_fn: Callable[[], float] = time.time,
    monotonic_fn: Callable[[], float] = time.monotonic,
    page_size: int | None = None,
    clock_ticks: int | None = None,
    controller: ProcessController | None = None,
    term_timeout_seconds: float = DEFAULT_TERM_TIMEOUT_SECONDS,
    kill_timeout_seconds: float = DEFAULT_KILL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Observe browsers, optionally reap eligible trees idle for 15 minutes."""

    if idle_seconds < 1:
        raise BrowserLifecycleError("idle_seconds must be positive")
    path = Path(state_path)
    proc = Path(proc_root)
    page = int(page_size or os.sysconf("SC_PAGE_SIZE"))
    ticks = int(clock_ticks or os.sysconf("SC_CLK_TCK"))
    with _state_lock(path, exclusive=True):
        previous = _read_state_unlocked(path)
        sampled_epoch = now_fn()
        document = _observe_unlocked(
            state_path=path,
            proc_root=proc,
            previous=previous,
            sampled_epoch=sampled_epoch,
            page_size=page,
            clock_ticks=ticks,
        )
        reaped: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        if reap_idle and document["scan_complete"]:
            effective_controller = controller or PidfdProcessController()
            for session in document["active"]:
                if not _eligible(session):
                    continue
                orphan_due = _orphan_reap_due(session, sampled_epoch)
                activity_at = _timestamp_epoch(session.get("last_resource_activity_at"))
                first_seen_at = _timestamp_epoch(session.get("first_seen_at"))
                idle_from = activity_at if activity_at is not None else first_seen_at
                if not orphan_due and (
                    idle_from is None or sampled_epoch - idle_from < idle_seconds
                ):
                    continue
                result = _terminate_session(
                    session,
                    proc_root=proc,
                    controller=effective_controller,
                    term_timeout_seconds=term_timeout_seconds,
                    kill_timeout_seconds=kill_timeout_seconds,
                    monotonic_fn=monotonic_fn,
                )
                if result["ok"]:
                    reaped.append(
                        {
                            "session_id": session["session_id"],
                            "stopped_at": _iso_timestamp(now_fn()),
                            "stop_reason": (
                                "orphaned-browser-tree" if orphan_due else "idle-timeout"
                            ),
                            "process_count": session["process_count"],
                            "memory_bytes": session["current_memory_bytes"],
                            "termination": result,
                        }
                    )
                else:
                    failures.append({"session_id": session["session_id"], **result})
        if reaped:
            refreshed = _scan(
                proc_root=proc,
                previous=document,
                sampled_epoch=now_fn(),
                page_size=page,
                clock_ticks=ticks,
            )
            _append_reaped(refreshed, reaped)
            document = refreshed
            _write_state_unlocked(path, document)
        document = json.loads(json.dumps(document))
        document["ok"] = bool(document["scan_complete"] and not failures)
        document["idle_reap"] = {
            "idle_seconds": idle_seconds,
            "reaped_session_count": len(reaped),
            "failures": failures,
        }
        return document


def cleanup_all_headless(
    state_path: Path | str = DEFAULT_STATE_PATH,
    *,
    proc_root: Path | str = Path("/proc"),
    quiescence_seconds: float = DEFAULT_QUIESCENCE_SECONDS,
    max_passes: int = 2,
    now_fn: Callable[[], float] = time.time,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
    page_size: int | None = None,
    clock_ticks: int | None = None,
    controller: ProcessController | None = None,
    term_timeout_seconds: float = DEFAULT_TERM_TIMEOUT_SECONDS,
    kill_timeout_seconds: float = DEFAULT_KILL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Manually terminate every eligible host automation browser tree.

    Project/container trees are excluded.  Unlike routine idle reaping, this
    explicit first-cutover operation also terminates host test/control browser
    trees so the browser-aware release starts from a clean host.  Ordinary
    cleanup uses :func:`observe_browser_lifecycle` and its idle TTL and never
    reaps those protected owners.
    """

    if quiescence_seconds < 0 or quiescence_seconds > 60:
        raise BrowserLifecycleError("quiescence_seconds must be between 0 and 60")
    if not 1 <= max_passes <= 5:
        raise BrowserLifecycleError("max_passes must be between 1 and 5")
    path = Path(state_path)
    proc = Path(proc_root)
    page = int(page_size or os.sysconf("SC_PAGE_SIZE"))
    ticks = int(clock_ticks or os.sysconf("SC_CLK_TCK"))
    effective_controller = controller or PidfdProcessController()
    terminated_ids: set[str] = set()
    terminated_process_count = 0
    reclaimed_memory_bytes = 0
    failures: list[dict[str, Any]] = []
    with _state_lock(path, exclusive=True):
        previous = _read_state_unlocked(path)
        document = _observe_unlocked(
            state_path=path,
            proc_root=proc,
            previous=previous,
            sampled_epoch=now_fn(),
            page_size=page,
            clock_ticks=ticks,
        )
        if not document["scan_complete"]:
            return {
                "ok": False,
                "remaining_session_count": document["active_session_count"],
                "terminated_session_count": 0,
                "terminated_process_count": 0,
                "reclaimed_memory_bytes": 0,
                "sampled_at": document["sampled_at"],
                "code": "process_scan_incomplete",
            }
        for pass_number in range(max_passes):
            candidates = list(document["active"])
            if candidates:
                reaped: list[dict[str, Any]] = []
                for session in candidates:
                    result = _terminate_session(
                        session,
                        proc_root=proc,
                        controller=effective_controller,
                        term_timeout_seconds=term_timeout_seconds,
                        kill_timeout_seconds=kill_timeout_seconds,
                        monotonic_fn=monotonic_fn,
                    )
                    if result["ok"]:
                        session_id = str(session["session_id"])
                        if session_id not in terminated_ids:
                            terminated_ids.add(session_id)
                            terminated_process_count += int(result["terminated_process_count"])
                            reclaimed_memory_bytes += int(session["current_memory_bytes"])
                        reaped.append(
                            {
                                "session_id": session_id,
                                "stopped_at": _iso_timestamp(now_fn()),
                                "stop_reason": "manual-cleanup-all",
                                "process_count": session["process_count"],
                                "memory_bytes": session["current_memory_bytes"],
                                "termination": result,
                            }
                        )
                    else:
                        failures.append({"session_id": session["session_id"], **result})
                refreshed = _scan(
                    proc_root=proc,
                    previous=document,
                    sampled_epoch=now_fn(),
                    page_size=page,
                    clock_ticks=ticks,
                )
                _append_reaped(refreshed, reaped)
                document = refreshed
                _write_state_unlocked(path, document)
            if document["active"]:
                if pass_number + 1 >= max_passes:
                    break
                continue
            if quiescence_seconds:
                sleep_fn(quiescence_seconds)
                document = _observe_unlocked(
                    state_path=path,
                    proc_root=proc,
                    previous=document,
                    sampled_epoch=now_fn(),
                    page_size=page,
                    clock_ticks=ticks,
                )
                if document["active"]:
                    if pass_number + 1 >= max_passes:
                        break
                    continue
            break
        remaining = len(document["active"])
        return {
            "ok": bool(document["scan_complete"] and remaining == 0 and not failures),
            "remaining_session_count": remaining,
            "terminated_session_count": len(terminated_ids),
            "terminated_process_count": terminated_process_count,
            "reclaimed_memory_bytes": reclaimed_memory_bytes,
            "protected_session_count": document["protected_session_count"],
            "sampled_at": document["sampled_at"],
            "failures": failures,
        }


def browser_lifecycle_inventory_projection(
    document: Mapping[str, Any],
    *,
    idle_seconds: int = DEFAULT_IDLE_SECONDS,
) -> dict[str, Any]:
    """Return the bounded, path-free browser projection used by Console.

    Raw PID/start-tick/member/cgroup evidence remains private to the lifecycle
    state.  The public projection contains only operator-facing attribution,
    activity, and resource totals.
    """

    state = _validate_state(dict(document))
    sampled_epoch = _timestamp_epoch(state.get("sampled_at"))
    sessions: list[dict[str, Any]] = []
    idle_session_count = 0
    for raw in state.get("active", ())[:MAX_ACTIVE_SESSIONS]:
        if not isinstance(raw, Mapping):
            continue
        activity_epoch = _timestamp_epoch(
            raw.get("last_activity_at") or raw.get("first_seen_at")
        )
        observed_idle = (
            max(0, round(sampled_epoch - activity_epoch))
            if sampled_epoch is not None and activity_epoch is not None
            else None
        )
        reap_eligible = _eligible(raw)
        if (
            reap_eligible
            and observed_idle is not None
            and observed_idle >= idle_seconds
        ):
            idle_session_count += 1
        sessions.append(
            {
                "session_id": str(raw.get("session_id") or ""),
                "state": str(raw.get("state") or "active"),
                "uid": raw.get("owner_uid") if type(raw.get("owner_uid")) is int else None,
                "cgroup_class": str(raw.get("classification") or "unmanaged"),
                "agent": str(raw.get("browser_kind") or "automation-browser"),
                "repository_name": None,
                "first_seen_at": raw.get("first_seen_at") if isinstance(raw.get("first_seen_at"), str) else None,
                "last_observed_at": raw.get("last_seen_at") if isinstance(raw.get("last_seen_at"), str) else None,
                "last_observed_work_at": raw.get("last_resource_activity_at") if isinstance(raw.get("last_resource_activity_at"), str) else None,
                "memory_bytes": max(0, int(raw.get("current_memory_bytes") or 0)),
                "idle_seconds": observed_idle,
                "cpu_percent": max(0.0, float(raw.get("cpu_percent") or 0.0)),
                "process_count": max(0, int(raw.get("process_count") or 0)),
                "reap_eligible": reap_eligible,
                "orphaned": bool(raw.get("orphaned")),
                "protected": bool(raw.get("protected")),
            }
        )
    totals = state.get("totals") if isinstance(state.get("totals"), Mapping) else {}
    recent_reaps: list[dict[str, Any]] = []
    for raw in state.get("reaped", ())[-20:]:
        if not isinstance(raw, Mapping):
            continue
        recent_reaps.append(
            {
                "session_id": str(raw.get("session_id") or ""),
                "reaped_at": raw.get("stopped_at") if isinstance(raw.get("stopped_at"), str) else None,
                "reason": str(raw.get("stop_reason") or "unknown"),
                "reclaimed_memory_bytes": max(0, int(raw.get("memory_bytes") or 0)),
                "process_count": max(0, int(raw.get("process_count") or 0)),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "sampled_at": state.get("sampled_at"),
        "policy": {
            "idle_timeout_seconds": idle_seconds,
            "termination_grace_seconds": (
                DEFAULT_TERM_TIMEOUT_SECONDS + DEFAULT_KILL_TIMEOUT_SECONDS
            ),
        },
        "totals": {
            "session_count": max(0, int(totals.get("session_count") or 0)),
            "process_count": max(0, int(totals.get("process_count") or 0)),
            "memory_bytes": max(0, int(totals.get("memory_bytes") or 0)),
            "rss_bytes": max(0, int(totals.get("rss_bytes") or 0)),
            "memory_measurement": str(totals.get("memory_measurement") or "rss"),
            "memory_exact": bool(totals.get("memory_exact")),
            "memory_coverage": max(0.0, min(1.0, float(totals.get("memory_coverage") or 0.0))),
            "cpu_percent": max(0.0, float(totals.get("cpu_percent") or 0.0)),
            "protected_session_count": max(0, int(state.get("protected_session_count") or 0)),
            "idle_session_count": idle_session_count,
            "reaped_total": max(0, int(state.get("reaped_total") or 0)),
            "reclaimed_memory_bytes": max(
                0, int(state.get("reclaimed_memory_bytes_total") or 0)
            ),
        },
        "sessions": sessions,
        "recent_reaps": recent_reaps,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    cleanup = subparsers.add_parser("cleanup-all", help="terminate eligible host automation browsers")
    cleanup.add_argument("--state", default=str(DEFAULT_STATE_PATH))
    cleanup.add_argument("--quiescence-seconds", type=float, default=DEFAULT_QUIESCENCE_SECONDS)
    cleanup.add_argument("--json", action="store_true")
    status = subparsers.add_parser("status", help="read the last bounded browser lifecycle document")
    status.add_argument("--state", default=str(DEFAULT_STATE_PATH))
    status.add_argument("--json", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    controller: ProcessController | None = None,
    proc_root: Path | str = Path("/proc"),
    now_fn: Callable[[], float] = time.time,
    monotonic_fn: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "cleanup-all":
            result = cleanup_all_headless(
                args.state,
                proc_root=proc_root,
                quiescence_seconds=args.quiescence_seconds,
                controller=controller,
                now_fn=now_fn,
                monotonic_fn=monotonic_fn,
                sleep_fn=sleep_fn,
            )
        else:
            document = read_browser_lifecycle_state(args.state)
            result = (
                {"ok": False, "code": "browser_lifecycle_state_missing"}
                if document is None
                else {**document, "ok": True}
            )
    except (BrowserLifecycleError, OSError) as error:
        result = {
            "ok": False,
            "code": "browser_lifecycle_error",
            "error_type": type(error).__name__,
            "message": str(error),
        }
    if getattr(args, "json", False):
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
