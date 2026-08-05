#!/usr/bin/env python3
"""Executable regression checks for native inherited-listener adoption."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import socket
import stat
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR_SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
sys.path.insert(0, str(COORDINATOR_SCRIPTS))

from devcoordinator.broker import UnixBrokerServer  # noqa: E402
from devcoordinator.systemd_activation import (  # noqa: E402
    SystemdActivationError,
    take_systemd_listener,
    validate_listener,
)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (SystemdActivationError, RuntimeError):
        return
    raise AssertionError(f"invalid activation contract was accepted: {label}")


def inherited_tcp_child() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    address = listener.getsockname()[:2]
    child = os.fork()
    if child == 0:
        try:
            original = listener.fileno()
            if original != 3:
                os.dup2(original, 3, inheritable=True)
                listener.close()
            else:
                os.set_inheritable(3, True)
                listener.detach()
            environment = {
                "LISTEN_PID": str(os.getpid()),
                "LISTEN_FDS": "1",
                "LISTEN_FDNAMES": "api",
            }
            adopted = take_systemd_listener(
                descriptor_name="api",
                family=socket.AF_INET,
                expected_address=address,
                environment=environment,
            )
            expect(not adopted.get_inheritable(), "adopted listener remained inheritable")
            expect(not environment, "activation variables were not consumed")
            adopted.close()
        except BaseException:
            os._exit(1)
        os._exit(0)
    listener.close()
    _pid, status = os.waitpid(child, 0)
    expect(os.waitstatus_to_exitcode(status) == 0, "real fd 3 activation failed")


def inherited_broker_path_is_retained() -> None:
    trusted_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
    with tempfile.TemporaryDirectory(
        prefix=".broker-activation-", dir=trusted_home
    ) as raw:
        runtime = Path(raw)
        runtime.chmod(0o750)
        socket_path = runtime / "broker.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        listener.listen()
        os.chmod(socket_path, 0o660)
        before = socket_path.lstat()
        server = UnixBrokerServer(
            socket_path,
            object(),  # No client is accepted in this transport-only check.
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        server.start(listener=listener)
        server.close(timeout_seconds=1.0)
        after = socket_path.lstat()
        expect(stat.S_ISSOCK(after.st_mode), "systemd-owned broker path was removed")
        expect(
            (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            "systemd-owned broker socket identity changed",
        )


def continuous_http_replacement_is_refusal_free() -> None:
    """A retained listener queues HTTP while one service generation is absent."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    address = listener.getsockname()[:2]
    probe_stop = threading.Event()
    failures: list[str] = []
    responses: list[str] = []
    lock = threading.Lock()

    def generation(label: str, adopted: socket.socket, stop: threading.Event) -> None:
        adopted.settimeout(0.05)
        while not stop.is_set():
            try:
                connection, _peer = adopted.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    break
                raise
            with connection:
                connection.settimeout(1)
                connection.recv(4096)
                body = label.encode("ascii")
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\r\n\r\n"
                    + body
                )

    def probe() -> None:
        while not probe_stop.is_set():
            try:
                with socket.create_connection(address, timeout=1) as connection:
                    connection.settimeout(1)
                    connection.sendall(
                        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    )
                    payload = b""
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        payload += chunk
                if b"HTTP/1.1 200 OK" not in payload:
                    raise RuntimeError("replacement probe returned non-200 HTTP")
                label = payload.rsplit(b"\r\n\r\n", 1)[-1].decode("ascii")
                if label not in {"generation-a", "generation-b"}:
                    raise RuntimeError("replacement probe returned unknown generation")
                with lock:
                    responses.append(label)
            except Exception as error:
                with lock:
                    failures.append(f"{type(error).__name__}: {error}")
            time.sleep(0.005)

    def duplicate_listener() -> socket.socket:
        adopted = socket.socket(fileno=os.dup(listener.fileno()))
        adopted.set_inheritable(False)
        return adopted

    first_stop = threading.Event()
    first_socket = duplicate_listener()
    first = threading.Thread(
        target=generation, args=("generation-a", first_socket, first_stop), daemon=True
    )
    first.start()
    probing = threading.Thread(target=probe, daemon=True)
    probing.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with lock:
            if responses.count("generation-a") >= 3:
                break
        time.sleep(0.01)
    else:
        raise AssertionError("initial socket generation did not serve probes")

    first_stop.set()
    first.join(1)
    first_socket.close()
    # The service is deliberately absent, but PID 1's listener remains open.
    # TCP connects/HTTP requests queue here instead of receiving ECONNREFUSED.
    time.sleep(0.05)

    second_stop = threading.Event()
    second_socket = duplicate_listener()
    second = threading.Thread(
        target=generation, args=("generation-b", second_socket, second_stop), daemon=True
    )
    second.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        with lock:
            if responses.count("generation-b") >= 3:
                break
        time.sleep(0.01)
    else:
        raise AssertionError("replacement socket generation did not serve queued probes")

    probe_stop.set()
    probing.join(1)
    second_stop.set()
    second.join(1)
    second_socket.close()
    listener.close()
    expect(not probing.is_alive(), "continuous replacement probe did not stop")
    expect(not first.is_alive() and not second.is_alive(), "replacement server did not stop")
    expect(not failures, f"socket replacement interrupted HTTP probes: {failures}")
    expect("generation-a" in responses, "initial generation was not observed")
    expect("generation-b" in responses, "replacement generation was not observed")


def main() -> int:
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    try:
        address = tcp.getsockname()[:2]
        validate_listener(tcp, family=socket.AF_INET, expected_address=address)
        must_fail(
            lambda: validate_listener(
                tcp,
                family=socket.AF_INET,
                expected_address=("127.0.0.1", address[1] + 1),
            ),
            "wrong TCP address",
        )
    finally:
        tcp.close()
    must_fail(
        lambda: take_systemd_listener(
            descriptor_name="api",
            family=socket.AF_INET,
            expected_address=("127.0.0.1", 29876),
            environment={
                "LISTEN_PID": str(os.getpid() + 1),
                "LISTEN_FDS": "1",
                "LISTEN_FDNAMES": "api",
            },
        ),
        "foreign LISTEN_PID",
    )
    inherited_tcp_child()
    inherited_broker_path_is_retained()
    continuous_http_replacement_is_refusal_free()
    print("systemd activation self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
