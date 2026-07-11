"""Strict helpers for Linux /proc process-instance identity."""

from __future__ import annotations

from pathlib import Path
from typing import Callable


class ProcIdentityError(ValueError):
    pass


def parse_start_ticks(stat_text: str) -> str:
    """Return field 22 from /proc/<pid>/stat without splitting field 2 (comm)."""
    opening = stat_text.find("(")
    closing = stat_text.rfind(")")
    if opening <= 0 or closing <= opening:
        raise ProcIdentityError("process stat has no parenthesized comm field")
    # Fields after comm begin with field 3 (state). Field 22 (starttime) is
    # therefore offset 19. `comm` itself may legally contain spaces or `)`;
    # the kernel's final closing parenthesis is the only safe boundary.
    after_comm = stat_text[closing + 1 :].split()
    if len(after_comm) < 20:
        raise ProcIdentityError("process stat has fewer than 22 fields")
    start_ticks = after_comm[19]
    if not start_ticks.isdigit():
        raise ProcIdentityError("process starttime is not an unsigned integer")
    return start_ticks


def read_stable_process_identity(
    process: Path,
    *,
    after_first_stat: Callable[[], None] | None = None,
) -> tuple[str, list[str]]:
    """Read stat→cmdline→stat and reject a PID instance change mid-read."""
    before = parse_start_ticks((process / "stat").read_text(encoding="utf-8"))
    if after_first_stat is not None:
        after_first_stat()
    command = (process / "cmdline").read_bytes().split(b"\0")
    after = parse_start_ticks((process / "stat").read_text(encoding="utf-8"))
    if before != after:
        raise ProcIdentityError(
            f"process identity changed while reading stat/cmdline/stat: {before} -> {after}"
        )
    return before, [part.decode("utf-8", errors="replace") for part in command if part]
