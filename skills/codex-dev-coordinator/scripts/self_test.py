#!/usr/bin/env python3
"""Self-tests for codex-dev-coordinator."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from shutil import rmtree


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "dev_coordinator.py"
SKILL = ROOT / "SKILL.md"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(args: list[str], *, env: dict[str, str]) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(args)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return json.loads(result.stdout)


def post_json(port: int, path: str, payload: dict) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(payload)
    conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    conn.close()
    if response.status != 200:
        raise AssertionError(f"{path} returned {response.status}: {data}")
    return data


def get_json(port: int, path: str) -> dict | list:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    response = conn.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    conn.close()
    if response.status != 200:
        raise AssertionError(f"{path} returned {response.status}: {data}")
    return data


def wait_for_api(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"api exited early: {process.returncode}")
        try:
            get_json(port, "/v1/state")
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("api did not become ready")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="codex-dev-coordinator-self-test-"))
    env = os.environ.copy()
    env["CODEX_AGENT_COORDINATOR_HOME"] = str(tmp / "state")
    api_process: subprocess.Popen[str] | None = None
    try:
        skill_text = SKILL.read_text(encoding="utf-8")
        for needle in ("inventory --project", "Do not start dev/test servers", "try the default port"):
            check(needle in skill_text, f"SKILL.md should retain policy text: {needle}")

        port_a = free_port()
        port_b = free_port()
        low, high = sorted((port_a, port_b))

        first = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--range",
                f"{low}-{high}",
                "--preferred",
                str(low),
            ],
            env=env,
        )
        second = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-b",
                "--project",
                str(tmp),
                "--range",
                f"{low}-{high}",
                "--preferred",
                str(low),
            ],
            env=env,
        )
        check(first["port"] == low, "first lease should use preferred port")
        check(second["port"] != first["port"], "second lease should avoid active lease")

        released = run(["port", "release", "--lease-id", first["id"]], env=env)
        check(released["status"] == "released", "release should report released status")

        server_port = free_port()
        server = run(
            [
                "server",
                "start",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "fixture-web",
                "--cwd",
                str(tmp),
                "--cmd",
                f"{shlex_join([sys.executable, '-m', 'http.server', '{port}', '--bind', '127.0.0.1'])}",
                "--range",
                f"{server_port}-{server_port}",
                "--health-url",
                "http://127.0.0.1:{port}/",
            ],
            env=env,
        )
        check(server["health"]["ok"], "managed server should become healthy")
        inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        check(inventory["urls"][0]["url"] == server["url"], "inventory should expose managed server URL")
        check(inventory["servers"][0]["status"] == "running", "inventory should health-check managed server")
        status = run(["server", "status", "--project", str(tmp), "--name", "fixture-web"], env=env)
        check(status["status"] == "running", "server status should be running")
        stopped = run(["server", "stop", "--project", str(tmp), "--name", "fixture-web"], env=env)
        check(stopped["status"] == "stopped", "server stop should return stopped server")

        docker = run(["docker", "compose-up", "--cwd", str(tmp), "--file", "compose.yml", "--detach", "--dry-run"], env=env)
        check(docker["dry_run"], "docker dry-run should not execute docker")
        check(docker["command"] == ["docker", "compose", "-f", "compose.yml", "up", "-d"], "docker command shape drifted")
        docker_restart = run(["docker", "restart", "--container", "fixture-postgres", "--dry-run"], env=env)
        check(docker_restart["command"] == ["docker", "restart", "fixture-postgres"], "docker restart command shape drifted")

        api_port = free_port()
        api_process = subprocess.Popen(
            [sys.executable, str(SCRIPT), "api", "serve", "--host", "127.0.0.1", "--port", str(api_port)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        wait_for_api(api_process, api_port)
        api_lease = post_json(
            api_port,
            "/v1/ports/lease",
            {"agent": "api-agent", "project": str(tmp), "range": f"{low}-{high}", "ttl": 60},
        )
        check("port" in api_lease, "API lease should return a port")
        ports = get_json(api_port, "/v1/ports")
        check(any(item["id"] == api_lease["id"] for item in ports), "API lease should appear in port list")
        api_inventory = get_json(api_port, "/v1/inventory")
        check("urls" in api_inventory and "docker" in api_inventory, "API inventory should expose URLs and Docker summary")
        state = get_json(api_port, "/v1/state")
        history_types = {item["type"] for item in state["history"]}
        check("port.leased" in history_types and "server.stopped" in history_types, "state should retain action history")

        print("self-test ok")
        return 0
    finally:
        if api_process and api_process.poll() is None:
            api_process.terminate()
            try:
                api_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_process.kill()
        rmtree(tmp, ignore_errors=True)


def shlex_join(parts: list[str]) -> str:
    return " ".join("'" + part.replace("'", "'\"'\"'") + "'" for part in parts)


if __name__ == "__main__":
    raise SystemExit(main())
