"""Strict, one-listener systemd socket activation helpers.

The availability topology deliberately gives the listening socket to PID 1.
These helpers adopt that exact descriptor without rebinding, probing another
port, or accepting an ambiguous descriptor set.  They are small enough to be
used by both the HTTP API and the AF_UNIX authority transport.
"""

from __future__ import annotations

import os
import socket
from typing import Any


SD_LISTEN_FDS_START = 3


class SystemdActivationError(RuntimeError):
    """The inherited descriptor set does not match the executable contract."""


def _integer_environment(name: str, environment: dict[str, str]) -> int:
    raw = environment.get(name)
    if raw is None or not raw.isdigit():
        raise SystemdActivationError(f"{name} must be one decimal integer")
    return int(raw)


def validate_listener(
    listener: socket.socket,
    *,
    family: int,
    expected_address: Any,
) -> socket.socket:
    """Validate a listening stream descriptor and return the same object."""

    if listener.family != family:
        raise SystemdActivationError("inherited listener address family is invalid")
    if listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise SystemdActivationError("inherited descriptor is not a stream socket")
    if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
        raise SystemdActivationError("inherited stream socket is not listening")
    actual = listener.getsockname()
    if family in {socket.AF_INET, socket.AF_INET6}:
        if not isinstance(actual, tuple) or tuple(actual[:2]) != tuple(expected_address):
            raise SystemdActivationError(
                f"inherited listener address is {actual!r}, expected {expected_address!r}"
            )
    elif actual != expected_address:
        raise SystemdActivationError(
            f"inherited listener address is {actual!r}, expected {expected_address!r}"
        )
    listener.set_inheritable(False)
    return listener


def take_systemd_listener(
    *,
    descriptor_name: str,
    family: int,
    expected_address: Any,
    environment: dict[str, str] | None = None,
    pid: int | None = None,
) -> socket.socket:
    """Adopt systemd's sole descriptor and consume the activation variables.

    Exactly one named descriptor is accepted.  Ambiguity is a startup failure,
    because silently selecting the first descriptor can cross-wire the public
    API and privileged authority sockets after a unit edit.
    """

    env = os.environ if environment is None else environment
    expected_pid = os.getpid() if pid is None else int(pid)
    if _integer_environment("LISTEN_PID", env) != expected_pid:
        raise SystemdActivationError("LISTEN_PID does not identify this process")
    if _integer_environment("LISTEN_FDS", env) != 1:
        raise SystemdActivationError("systemd must pass exactly one descriptor")
    if env.get("LISTEN_FDNAMES") != descriptor_name:
        raise SystemdActivationError(
            f"LISTEN_FDNAMES must be exactly {descriptor_name!r}"
        )

    listener: socket.socket | None = None
    try:
        listener = socket.socket(fileno=SD_LISTEN_FDS_START)
        return validate_listener(
            listener,
            family=family,
            expected_address=expected_address,
        )
    except BaseException:
        if listener is not None:
            listener.close()
        raise
    finally:
        # Do not leak activation metadata into repository-controlled children.
        for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            env.pop(name, None)
