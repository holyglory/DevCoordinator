#!/usr/bin/env python3
"""Fail closed until the captured legacy cgroup, processes, and listeners are gone."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Callable

from linux_proc_identity import ProcIdentityError, read_stable_process_identity
from secure_cutover_io import SecureIOError, read_private_regular


class StoppedBoundaryError(RuntimeError):
    pass


def default_port_probe(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def load_evidence(path: Path) -> dict[str, object]:
    try:
        evidence = json.loads(read_private_regular(path, label="captured process evidence"))
        cgroup = evidence["cgroup"]
        console = evidence["console"]
        coordinator = evidence["coordinator"]
        if not isinstance(cgroup, str) or not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise ValueError("captured cgroup must be an absolute cgroup path")
        for item in (console, coordinator):
            if not isinstance(item["pid"], int) or item["pid"] <= 1:
                raise ValueError("captured PID must be an integer greater than one")
            if not isinstance(item["start_ticks"], str) or not isinstance(item["command"], list):
                raise ValueError("captured process identity is incomplete")
    except (SecureIOError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise StoppedBoundaryError(f"invalid captured process evidence: {error}") from error
    return evidence


def check_stopped(
    *,
    evidence_path: Path,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_root: Path = Path("/proc"),
    ports: tuple[int, ...] = (80, 443, 29876),
    port_probe: Callable[[int], bool] = default_port_probe,
) -> dict[str, object]:
    evidence = load_evidence(evidence_path)
    members_path = cgroup_root / str(evidence["cgroup"]).lstrip("/") / "cgroup.procs"
    try:
        members = {
            int(value)
            for value in members_path.read_text(encoding="utf-8").splitlines()
            if value.strip()
        }
    except FileNotFoundError:
        members = set()
    except (PermissionError, OSError, ValueError) as error:
        raise StoppedBoundaryError(f"legacy cgroup process list cannot be verified: {error}") from error
    if members:
        records: list[dict[str, object]] = []
        for pid in sorted(members):
            try:
                start, _command = read_stable_process_identity(proc_root / str(pid))
                records.append({"pid": pid, "start_ticks": start, "identity": "captured"})
            except (FileNotFoundError, ProcessLookupError, PermissionError, ProcIdentityError, OSError) as error:
                records.append({"pid": pid, "identity_error": f"{type(error).__name__}: {error}"})
        raise StoppedBoundaryError(
            "legacy cgroup still has managed processes: " + json.dumps(records, sort_keys=True)
        )

    for role in ("console", "coordinator"):
        item = evidence[role]
        try:
            actual = read_stable_process_identity(proc_root / str(item["pid"]))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, ProcIdentityError, OSError) as error:
            raise StoppedBoundaryError(f"cannot verify captured {role} process exit: {error}") from error
        if actual[0] == item["start_ticks"]:
            raise StoppedBoundaryError(
                f"captured legacy process is still alive: {item['pid']}"
            )

    open_ports = [port for port in ports if port_probe(port)]
    if open_ports:
        raise StoppedBoundaryError(f"legacy listener still accepts connections on ports: {open_ports}")
    return {
        "ok": True,
        "cgroup": evidence["cgroup"],
        "cgroup_members": [],
        "closed_ports": list(ports),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--cgroup-root", default="/sys/fs/cgroup", help=argparse.SUPPRESS)
    parser.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    parser.add_argument("--ports", nargs="+", type=int, default=[80, 443, 29876])
    args = parser.parse_args(argv)
    if any(port < 1 or port > 65535 for port in args.ports):
        parser.error("ports must be between 1 and 65535")
    try:
        report = check_stopped(
            evidence_path=Path(args.evidence),
            cgroup_root=Path(args.cgroup_root),
            proc_root=Path(args.proc_root),
            ports=tuple(args.ports),
        )
    except (StoppedBoundaryError, OSError) as error:
        print(f"legacy stopped-boundary failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
