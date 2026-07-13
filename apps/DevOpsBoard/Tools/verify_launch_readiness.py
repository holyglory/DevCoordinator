#!/usr/bin/env python3
"""Wait for a fresh DevOps Board inventory-readiness telemetry marker."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


MARKER_PATTERN = re.compile(
    r"(?<!\S)Inventory refresh (?P<outcome>completed|failed) "
    r"pid=(?P<pid>[1-9][0-9]*) loaded=(?P<loaded>[0-9]+) "
    r"total=(?P<total>[0-9]+) "
    r"sources=(?P<sources>none|[0-9a-f]{64}(?:,[0-9a-f]{64})*) "
    r"disabled=(?P<disabled>none|[0-9a-f]{64}(?:,[0-9a-f]{64})*) "
    r"server_counts=(?P<server_counts>none|[0-9a-f]{64}:[0-9]+(?:,[0-9a-f]{64}:[0-9]+)*) "
    r"managed=(?P<managed>[0-9]+) visible=(?P<visible>[0-9]+) "
    r"repositories=(?P<repositories>[0-9]+) "
    r"repository_groups=(?P<repository_groups>[0-9]+) "
    r"unassigned_groups=(?P<unassigned_groups>[0-9]+)\s*$"
)
SOURCE_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_SOURCE_INVENTORY_PATTERN = re.compile(r"^[0-9a-f]{64}:(?:[0-9]+|\?)$")
MAX_PARTIAL_LINE_CHARS = 65_536


class LaunchReadinessError(RuntimeError):
    """The newly launched app did not prove usable inventory readiness."""


@dataclass(frozen=True)
class InventoryMarker:
    outcome: str
    pid: int
    loaded: int
    total: int
    source_fingerprints: tuple[str, ...]
    disabled_source_fingerprints: tuple[str, ...]
    server_counts: tuple[tuple[str, int], ...]
    managed_servers: int
    visible_servers: int
    repositories: int
    repository_groups: int
    unassigned_groups: int


@dataclass(frozen=True)
class ReadinessResult:
    pid: int
    loaded: int
    total: int
    source_fingerprints: tuple[str, ...]
    disabled_source_fingerprints: tuple[str, ...]
    server_counts: tuple[tuple[str, int], ...]
    managed_servers: int
    visible_servers: int
    repositories: int
    repository_groups: int
    unassigned_groups: int


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    executable: str
    start: str


def normalize_source_path(value: str | Path) -> str:
    return os.path.realpath(os.path.normpath(os.path.abspath(os.fspath(value))))


def source_fingerprint(value: str | Path) -> str:
    normalized = normalize_source_path(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def os_account_home() -> Path:
    try:
        home = pwd.getpwuid(os.geteuid()).pw_dir
    except KeyError:
        raise ValueError("OS account home is unavailable") from None
    if not home or not os.path.isabs(home):
        raise ValueError("OS account home is unavailable")
    return Path(normalize_source_path(home))


def observable_entry_exists(path: Path) -> bool:
    """Return absence only when the filesystem conclusively reports it."""

    try:
        os.stat(path)
        return True
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR}:
            return False
        raise LaunchReadinessError(
            "automatic OS-account coordinator source could not be observed"
        ) from None


def observable_directory_entries(path: Path) -> tuple[str, ...]:
    """List one automatic-source parent without treating denial as absence."""

    try:
        return tuple(sorted(os.listdir(path)))
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR}:
            return ()
        raise LaunchReadinessError(
            "automatic OS-account coordinator source parent could not be observed"
        ) from None


def automatic_source_paths(
    *,
    account_home: Path | None = None,
    environment: dict[str, str] | None = None,
    entry_exists: Callable[[Path], bool] = observable_entry_exists,
    directory_entries: Callable[[Path], tuple[str, ...]] = observable_directory_entries,
) -> tuple[Path, ...]:
    """Discover every source the Board auto-discovers for this OS account."""

    account_home = account_home or os_account_home()
    environment = os.environ if environment is None else environment
    candidates: list[Path] = []
    configured = environment.get("CODEX_AGENT_COORDINATOR_HOME", "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        (
            account_home / ".codex/agent-coordinator",
            account_home / ".claude/agent-coordinator",
        )
    )
    parall_root = account_home / "Library/Application Support/Parall"
    candidates.extend(
        parall_root / entry / ".codex/agent-coordinator"
        for entry in directory_entries(parall_root)
    )

    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = normalize_source_path(candidate)
        if normalized in seen:
            continue
        path = Path(normalized)
        if not entry_exists(path) and not entry_exists(path / "state.json"):
            continue
        seen.add(normalized)
        result.append(path)
    return tuple(result)


def expected_automatic_source_fingerprints(
    **kwargs: object,
) -> tuple[str, ...]:
    """Return all required auto-source fingerprints, never private paths."""

    return tuple(sorted(source_fingerprint(path) for path in automatic_source_paths(**kwargs)))


def expected_automatic_source_fingerprint(
    **kwargs: object,
) -> str | None:
    """Compatibility helper for callers that expect exactly one source."""

    fingerprints = expected_automatic_source_fingerprints(**kwargs)
    return fingerprints[0] if len(fingerprints) == 1 else None


def normalize_expected_source_fingerprint(value: str | None) -> str | None:
    if value is None or value == "none":
        return None
    if SOURCE_FINGERPRINT_PATTERN.fullmatch(value) is None:
        raise ValueError("expected source fingerprint must be exactly 64 lowercase hex characters")
    return value


def normalize_expected_source_inventory(
    value: str | None,
) -> tuple[tuple[str, int | None], ...]:
    if value is None or value == "none":
        return ()
    result: list[tuple[str, int | None]] = []
    seen: set[str] = set()
    for item in value.split(","):
        if EXPECTED_SOURCE_INVENTORY_PATTERN.fullmatch(item) is None:
            raise ValueError(
                "expected source inventory must contain fingerprint:count or fingerprint:? entries"
            )
        fingerprint, raw_count = item.split(":", 1)
        if fingerprint in seen:
            raise ValueError("expected source inventory repeats a source fingerprint")
        seen.add(fingerprint)
        result.append((fingerprint, None if raw_count == "?" else int(raw_count)))
    return tuple(sorted(result))


def collect_expected_source_inventory(
    *,
    coordinator_script: Path,
    source_paths: tuple[Path, ...] | None = None,
    timeout: float = 20.0,
) -> tuple[tuple[str, int | None], ...]:
    """Measure each automatic source through the same packaged helper as the Board."""

    paths = automatic_source_paths() if source_paths is None else source_paths
    result: list[tuple[str, int | None]] = []
    for source in paths:
        fingerprint = source_fingerprint(source)
        environment = dict(os.environ)
        environment["CODEX_AGENT_COORDINATOR_HOME"] = normalize_source_path(source)
        try:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(coordinator_script),
                    "inventory",
                    "--compact-json",
                    "--stats-history-limit",
                    "1",
                    "--no-docker",
                ],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if completed.returncode != 0:
                result.append((fingerprint, None))
                continue
            payload = json.loads(completed.stdout)
            servers = payload.get("servers")
            reported_home = payload.get("coordinator_home")
            if not isinstance(servers, list) or not isinstance(reported_home, str):
                result.append((fingerprint, None))
                continue
            if normalize_source_path(reported_home) != normalize_source_path(source):
                result.append((fingerprint, None))
                continue
            result.append((fingerprint, len(servers)))
        except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
            result.append((fingerprint, None))
    return tuple(sorted(result))


def format_expected_source_inventory(
    inventory: tuple[tuple[str, int | None], ...],
) -> str:
    if not inventory:
        return "none"
    return ",".join(
        f"{fingerprint}:{'?' if count is None else count}"
        for fingerprint, count in sorted(inventory)
    )


def parse_inventory_marker(line: str) -> InventoryMarker | None:
    """Parse only the exact marker emitted at the end of a unified-log line."""

    match = MARKER_PATTERN.search(line)
    if match is None:
        return None
    source_evidence = match.group("sources")
    disabled_evidence = match.group("disabled")
    server_count_evidence = match.group("server_counts")
    server_counts: tuple[tuple[str, int], ...]
    if server_count_evidence == "none":
        server_counts = ()
    else:
        server_counts = tuple(
            (fingerprint, int(count))
            for fingerprint, count in (
                item.split(":", 1) for item in server_count_evidence.split(",")
            )
        )
    return InventoryMarker(
        outcome=match.group("outcome"),
        pid=int(match.group("pid")),
        loaded=int(match.group("loaded")),
        total=int(match.group("total")),
        source_fingerprints=() if source_evidence == "none" else tuple(source_evidence.split(",")),
        disabled_source_fingerprints=()
        if disabled_evidence == "none"
        else tuple(disabled_evidence.split(",")),
        server_counts=server_counts,
        managed_servers=int(match.group("managed")),
        visible_servers=int(match.group("visible")),
        repositories=int(match.group("repositories")),
        repository_groups=int(match.group("repository_groups")),
        unassigned_groups=int(match.group("unassigned_groups")),
    )


def evaluate_inventory_marker(
    marker: InventoryMarker,
    *,
    expected_pid: int,
    expected_source_fingerprint: str | None = None,
    expected_source_inventory: str | None = None,
    require_unfiltered_servers: bool = False,
) -> ReadinessResult | None:
    """Ignore stale PIDs and classify a marker from the newly launched app."""

    if marker.pid != expected_pid:
        return None
    expected_source_fingerprint = normalize_expected_source_fingerprint(expected_source_fingerprint)
    expected_inventory = normalize_expected_source_inventory(expected_source_inventory)
    if marker.total < marker.loaded:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} is inconsistent: "
            f"loaded={marker.loaded} total={marker.total}"
        )
    if len(set(marker.source_fingerprints)) != len(marker.source_fingerprints):
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} repeats a source fingerprint"
        )
    if len(set(marker.disabled_source_fingerprints)) != len(marker.disabled_source_fingerprints):
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} repeats a disabled source fingerprint"
        )
    if set(marker.source_fingerprints) & set(marker.disabled_source_fingerprints):
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} reports one source as loaded and disabled"
        )
    if len(marker.source_fingerprints) != marker.loaded:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} has "
            f"{len(marker.source_fingerprints)} source fingerprints for {marker.loaded} loaded sources"
        )
    count_fingerprints = tuple(fingerprint for fingerprint, _count in marker.server_counts)
    if len(set(count_fingerprints)) != len(count_fingerprints):
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} repeats a server-count fingerprint"
        )
    if set(count_fingerprints) != set(marker.source_fingerprints):
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} does not bind server counts to every loaded source"
        )
    if marker.visible_servers > marker.managed_servers:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} reports more visible than managed servers"
        )
    if marker.repository_groups != marker.repositories:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} renders "
            f"{marker.repository_groups} repository groups for {marker.repositories} canonical repositories"
        )
    if marker.unassigned_groups > 1:
        raise LaunchReadinessError(
            f"inventory readiness marker for PID {expected_pid} renders "
            f"{marker.unassigned_groups} unassigned resource groups; expected at most one"
        )
    if marker.outcome == "failed":
        if marker.loaded != 0:
            raise LaunchReadinessError(
                f"inventory failure marker for PID {expected_pid} reported loaded={marker.loaded}; expected 0"
            )
        raise LaunchReadinessError(
            f"inventory refresh failed for PID {expected_pid}: loaded=0 total={marker.total}"
        )
    if marker.loaded < 1:
        raise LaunchReadinessError(
            f"inventory refresh completed for PID {expected_pid} without a loaded source"
        )
    if (
        expected_source_fingerprint is not None
        and expected_source_fingerprint not in marker.source_fingerprints
        and expected_source_fingerprint not in marker.disabled_source_fingerprints
    ):
        raise LaunchReadinessError(
            "automatic OS-account coordinator source was neither loaded nor explicitly disabled"
        )
    present_or_disabled = set(marker.source_fingerprints) | set(marker.disabled_source_fingerprints)
    missing_expected = {
        fingerprint for fingerprint, _count in expected_inventory
        if fingerprint not in present_or_disabled
    }
    if missing_expected:
        raise LaunchReadinessError(
            f"{len(missing_expected)} automatic OS-account coordinator source(s) were neither loaded nor explicitly disabled"
        )
    measured_counts = dict(marker.server_counts)
    for fingerprint, expected_count in expected_inventory:
        if fingerprint in marker.disabled_source_fingerprints:
            continue
        if expected_count is None:
            raise LaunchReadinessError(
                "packaged-helper preflight could not measure a loaded automatic source"
            )
        if measured_counts.get(fingerprint) != expected_count:
            raise LaunchReadinessError(
                "loaded automatic source server count did not match packaged-helper preflight"
            )
    if require_unfiltered_servers and marker.visible_servers != marker.managed_servers:
        raise LaunchReadinessError(
            f"clean launch rendered {marker.visible_servers} of {marker.managed_servers} managed servers"
        )
    return ReadinessResult(
        pid=expected_pid,
        loaded=marker.loaded,
        total=marker.total,
        source_fingerprints=marker.source_fingerprints,
        disabled_source_fingerprints=marker.disabled_source_fingerprints,
        server_counts=marker.server_counts,
        managed_servers=marker.managed_servers,
        visible_servers=marker.visible_servers,
        repositories=marker.repositories,
        repository_groups=marker.repository_groups,
        unassigned_groups=marker.unassigned_groups,
    )


def process_state_is_alive(state: str) -> bool:
    normalized = state.strip()
    return bool(normalized) and not normalized.startswith("Z")


def _ps_field(pid: int, field: str) -> str | None:
    result = subprocess.run(
        ["/bin/ps", "-ww", "-p", str(pid), "-o", f"{field}="],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def normalize_start_identity(value: str) -> str:
    return " ".join(value.split())


def normalize_executable(value: str) -> str:
    return os.path.realpath(value)


def process_identity(pid: int) -> ProcessIdentity | None:
    """Read one stable, non-zombie executable/start identity for a PID."""

    state_before = _ps_field(pid, "stat")
    start_before = _ps_field(pid, "lstart")
    executable = _ps_field(pid, "comm")
    start_after = _ps_field(pid, "lstart")
    state_after = _ps_field(pid, "stat")
    if (
        state_before is None
        or start_before is None
        or executable is None
        or start_after is None
        or state_after is None
        or not process_state_is_alive(state_before)
        or not process_state_is_alive(state_after)
    ):
        return None
    normalized_before = normalize_start_identity(start_before)
    normalized_after = normalize_start_identity(start_after)
    if normalized_before != normalized_after:
        return None
    return ProcessIdentity(
        pid=pid,
        executable=normalize_executable(executable),
        start=normalized_before,
    )


def process_is_alive(pid: int) -> bool:
    state = _ps_field(pid, "stat")
    return state is not None and process_state_is_alive(state)


def require_process_identity(
    expected: ProcessIdentity,
    *,
    identity_reader: Callable[[int], ProcessIdentity | None],
    phase: str,
) -> None:
    current = identity_reader(expected.pid)
    if current is None:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} exited or became unobservable {phase}"
        )
    if current != expected:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} changed identity {phase}; "
            "refusing stale-process readiness"
        )


def wait_for_stable_identity(
    *,
    expected: ProcessIdentity,
    capture_pid: int | None,
    duration: float,
    poll_interval: float,
    identity_reader: Callable[[int], ProcessIdentity | None],
    is_alive: Callable[[int], bool],
    monotonic: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    deadline = monotonic() + duration
    while True:
        require_process_identity(
            expected,
            identity_reader=identity_reader,
            phase="during launch stabilization",
        )
        if capture_pid is not None and not is_alive(capture_pid):
            raise LaunchReadinessError(
                "unified-log capture exited during launch stabilization"
            )
        now = monotonic()
        if now >= deadline:
            return
        sleep(min(poll_interval, deadline - now))


def wait_for_inventory_readiness(
    *,
    log_path: Path,
    expected_identity: ProcessIdentity,
    timeout: float,
    poll_interval: float = 0.05,
    stabilization: float = 1.5,
    capture_pid: int | None = None,
    expected_source_fingerprint: str | None = None,
    expected_source_inventory: str | None = None,
    require_unfiltered_servers: bool = False,
    identity_reader: Callable[[int], ProcessIdentity | None] = process_identity,
    is_alive: Callable[[int], bool] = process_is_alive,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> ReadinessResult:
    """Tail one fresh capture until the expected PID proves inventory readiness."""

    if expected_identity.pid < 1:
        raise ValueError("expected PID must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    if stabilization <= 0:
        raise ValueError("stabilization must be positive")
    expected_source_fingerprint = normalize_expected_source_fingerprint(expected_source_fingerprint)
    expected_source_inventory = format_expected_source_inventory(
        normalize_expected_source_inventory(expected_source_inventory)
    )

    deadline = monotonic() + timeout
    offset = 0
    partial = ""

    def inspect(line: str) -> ReadinessResult | None:
        marker = parse_inventory_marker(line)
        if marker is None:
            return None
        result = evaluate_inventory_marker(
            marker,
            expected_pid=expected_identity.pid,
            expected_source_fingerprint=expected_source_fingerprint,
            expected_source_inventory=expected_source_inventory,
            require_unfiltered_servers=require_unfiltered_servers,
        )
        if result is not None:
            require_process_identity(
                expected_identity,
                identity_reader=identity_reader,
                phase="after reporting inventory readiness",
            )
        return result

    while True:
        require_process_identity(
            expected_identity,
            identity_reader=identity_reader,
            phase="before inventory readiness",
        )
        if capture_pid is not None and not is_alive(capture_pid):
            raise LaunchReadinessError("unified-log capture exited before inventory readiness")

        try:
            current_size = log_path.stat().st_size
        except FileNotFoundError:
            current_size = 0
        if current_size < offset:
            offset = 0
            partial = ""
        if current_size > offset:
            with log_path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(offset)
                partial += stream.read()
                offset = stream.tell()
            while "\n" in partial:
                line, partial = partial.split("\n", 1)
                result = inspect(line)
                if result is not None:
                    wait_for_stable_identity(
                        expected=expected_identity,
                        capture_pid=capture_pid,
                        duration=stabilization,
                        poll_interval=poll_interval,
                        identity_reader=identity_reader,
                        is_alive=is_alive,
                        monotonic=monotonic,
                        sleep=sleep,
                    )
                    return result
            if len(partial) > MAX_PARTIAL_LINE_CHARS:
                partial = partial[-MAX_PARTIAL_LINE_CHARS:]

        now = monotonic()
        if now >= deadline:
            if partial:
                result = inspect(partial)
                if result is not None:
                    wait_for_stable_identity(
                        expected=expected_identity,
                        capture_pid=capture_pid,
                        duration=stabilization,
                        poll_interval=poll_interval,
                        identity_reader=identity_reader,
                        is_alive=is_alive,
                        monotonic=monotonic,
                        sleep=sleep,
                    )
                    return result
            raise LaunchReadinessError(
                f"timed out waiting for inventory readiness from DevOpsBoard PID {expected_identity.pid}"
            )
        sleep(min(poll_interval, deadline - now))


def terminate_exact_process(
    expected: ProcessIdentity,
    *,
    grace: float = 2.0,
    poll_interval: float = 0.05,
    identity_reader: Callable[[int], ProcessIdentity | None] = process_identity,
    send_signal: Callable[[int, int], None] = os.kill,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Boundedly terminate only the process that still has the captured identity."""

    if grace <= 0:
        raise ValueError("grace must be positive")
    current = identity_reader(expected.pid)
    if current is None or current != expected:
        return False
    try:
        send_signal(expected.pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = monotonic() + grace
    while monotonic() < deadline:
        current = identity_reader(expected.pid)
        if current is None or current != expected:
            return True
        sleep(max(0.0, min(poll_interval, deadline - monotonic())))
    current = identity_reader(expected.pid)
    if current is None or current != expected:
        return True
    try:
        send_signal(expected.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    kill_deadline = monotonic() + grace
    while monotonic() < kill_deadline:
        current = identity_reader(expected.pid)
        if current is None or current != expected:
            return True
        sleep(max(0.0, min(poll_interval, kill_deadline - monotonic())))
    current = identity_reader(expected.pid)
    if current is not None and current == expected:
        raise LaunchReadinessError(
            f"DevOpsBoard PID {expected.pid} retained its exact identity after SIGKILL"
        )
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect, verify, or safely terminate one DevOps Board launch identity."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect")
    inspect.add_argument("--pid", type=int, required=True)
    inspect.add_argument("--expected-executable", required=True)

    commands.add_parser(
        "expected-source",
        help="print every automatic OS-account source fingerprint, or none",
    )
    expected_inventory = commands.add_parser(
        "expected-inventory",
        help="measure every automatic source with the packaged coordinator helper",
    )
    expected_inventory.add_argument("--coordinator-script", type=Path, required=True)

    wait = commands.add_parser("wait")
    wait.add_argument("--log-file", type=Path, required=True)
    wait.add_argument("--pid", type=int, required=True)
    wait.add_argument("--expected-executable", required=True)
    wait.add_argument("--expected-start", required=True)
    wait.add_argument("--capture-pid", type=int)
    wait.add_argument("--timeout", type=float, default=30.0)
    wait.add_argument("--poll-interval", type=float, default=0.05)
    wait.add_argument("--stabilization", type=float, default=1.5)
    wait.add_argument("--expected-source-fingerprint")
    wait.add_argument("--expected-source-inventory")
    wait.add_argument("--expect-unfiltered-servers", action="store_true")

    terminate = commands.add_parser("terminate")
    terminate.add_argument("--pid", type=int, required=True)
    terminate.add_argument("--expected-executable", required=True)
    terminate.add_argument("--expected-start", required=True)
    terminate.add_argument("--grace", type=float, default=2.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "expected-source":
            fingerprints = expected_automatic_source_fingerprints()
            print(",".join(fingerprints) if fingerprints else "none")
            return 0

        if args.command == "expected-inventory":
            print(
                format_expected_source_inventory(
                    collect_expected_source_inventory(coordinator_script=args.coordinator_script)
                )
            )
            return 0

        if args.command == "inspect":
            identity = process_identity(args.pid)
            if identity is None:
                raise LaunchReadinessError(
                    f"DevOpsBoard PID {args.pid} exited or became unobservable during identity capture"
                )
            expected_executable = normalize_executable(args.expected_executable)
            if identity.executable != expected_executable:
                raise LaunchReadinessError(
                    f"PID {args.pid} executable does not match the packaged DevOpsBoard binary"
                )
            print(identity.start)
            return 0

        expected_identity = ProcessIdentity(
            pid=args.pid,
            executable=normalize_executable(args.expected_executable),
            start=normalize_start_identity(args.expected_start),
        )
        if args.command == "terminate":
            terminated = terminate_exact_process(expected_identity, grace=args.grace)
            print(
                f"DevOps Board cleanup: pid={args.pid} "
                f"status={'terminated' if terminated else 'already-exited-or-identity-changed'}"
            )
            return 0

        result = wait_for_inventory_readiness(
            log_path=args.log_file,
            expected_identity=expected_identity,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            stabilization=args.stabilization,
            capture_pid=args.capture_pid,
            expected_source_fingerprint=args.expected_source_fingerprint,
            expected_source_inventory=args.expected_source_inventory,
            require_unfiltered_servers=args.expect_unfiltered_servers,
        )
    except (LaunchReadinessError, OSError, ValueError) as error:
        print(f"DevOps Board launch verification failed: {error}", file=sys.stderr)
        return 1
    print(
        f"DevOps Board ready: pid={result.pid} loaded={result.loaded} total={result.total} "
        f"managed={result.managed_servers} visible={result.visible_servers} "
        f"repositories={result.repositories} repository_groups={result.repository_groups} "
        f"unassigned_groups={result.unassigned_groups}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
