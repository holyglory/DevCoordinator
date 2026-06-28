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


def run_fail(args: list[str], *, env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=20,
    )
    if result.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {' '.join(args)}\nstdout:\n{result.stdout}")
    haystack = f"{result.stdout}\n{result.stderr}"
    if expected not in haystack:
        raise AssertionError(f"failure did not mention {expected!r}: {' '.join(args)}\n{haystack}")


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


def wait_for_http(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"HTTP fixture on {port} did not become ready")


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="codex-dev-coordinator-self-test-"))
    env = os.environ.copy()
    env["CODEX_AGENT_COORDINATOR_HOME"] = str(tmp / "state")
    api_process: subprocess.Popen[str] | None = None
    external_processes: list[subprocess.Popen[str]] = []
    try:
        skill_text = SKILL.read_text(encoding="utf-8")
        for needle in ("PROJECT_ROOT=", "server register", "docker register", "Do not start dev/test servers", "try the default port"):
            check(needle in skill_text, f"SKILL.md should retain policy text: {needle}")

        run_fail(["docker", "restart", "--container", "fixture-postgres", "--dry-run"], env=env, expected="--agent")
        run_fail(["server", "stop", "--project", str(tmp), "--name", "fixture-web"], env=env, expected="--agent")

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
        stopped = run(["server", "stop", "--agent", "agent-a", "--project", str(tmp), "--name", "fixture-web", "--reason", "test stop"], env=env)
        check(stopped["status"] == "stopped", "server stop should return stopped server")
        check(stopped["stopped_reason"] == "test stop", "server stop should retain explicit stopped reason")
        stopped_inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        check(stopped_inventory["servers"][0]["status"] == "stopped", "stopped server should remain in inventory")
        check(stopped_inventory["servers"][0]["stopped_reason"] == "test stop", "inventory should expose stopped reason")
        logs = run(["server", "logs", "--project", str(tmp), "--name", "fixture-web", "--tail", "20"], env=env)
        check(logs["server"]["stopped_reason"] == "test stop", "server logs should expose stopped reason")
        check(logs["server"]["log_path"], "server logs should expose log path")
        logs_by_id = run(["server", "logs", "--server-id", stopped["id"], "--tail", "20"], env=env)
        check(logs_by_id["server"]["id"] == stopped["id"], "server logs should support exact server id")

        adopted_port = free_port()
        adopted_process = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(adopted_port), "--bind", "127.0.0.1"],
            cwd=tmp,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(adopted_process)
        wait_for_http(adopted_port)
        adopted = run(
            [
                "server",
                "register",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--name",
                "adopted-web",
                "--port",
                str(adopted_port),
                "--url",
                f"http://127.0.0.1:{adopted_port}",
            ],
            env=env,
        )
        check(adopted["adopted"], "server register should mark adopted servers")
        check(adopted["missing_command"], "server register without --cmd should expose missing_command")
        adopted_inventory = run(["inventory", "--project", str(tmp), "--no-docker"], env=env)
        check(any(item["name"] == "adopted-web" for item in adopted_inventory["servers"]), "inventory should include adopted server")

        adopt_project = tmp / "adopt-project"
        adopt_project.mkdir()
        adopt_runtime_dir = adopt_project / ".codex"
        adopt_runtime_dir.mkdir()
        adopt_runtime_port = free_port()
        (adopt_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "adopt-runtime",
                    "servers": [
                        {
                            "name": "web",
                            "role": "web",
                            "port": adopt_runtime_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-m", "http.server", "{port}", "--bind", "127.0.0.1"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        runtime_adopt_process = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(adopt_runtime_port), "--bind", "127.0.0.1"],
            cwd=adopt_project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        external_processes.append(runtime_adopt_process)
        wait_for_http(adopt_runtime_port)
        runtime_adopted = run(["project", "start", "--agent", "agent-a", "--project", str(adopt_project)], env=env)
        check(runtime_adopted["ok"], f"project start should adopt healthy fixed-port server: {runtime_adopted}")
        adopted_services = [item for item in runtime_adopted["services"] if item.get("name") == "web"]
        check(adopted_services and adopted_services[0].get("adopted"), "project start should report adopted server service")
        restarted_adopted = run(["server", "restart", "--agent", "agent-a", "--project", str(adopt_project), "--name", "web"], env=env)
        check(restarted_adopted["status"] == "running", f"adopted fixed-port server restart should recover cleanly: {restarted_adopted}")
        check(not restarted_adopted.get("adopted"), "restarted adopted server should become coordinator-managed")
        stopped_restarted_adopted = run(["server", "stop", "--agent", "agent-a", "--project", str(adopt_project), "--name", "web"], env=env)
        check(stopped_restarted_adopted["status"] == "stopped", "restarted adopted server should stop cleanly")

        runtime_port = free_port()
        runtime_config_dir = tmp / ".codex"
        runtime_config_dir.mkdir()
        (runtime_config_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "fixture-runtime",
                    "servers": [
                        {
                            "name": "runtime-web",
                            "role": "web",
                            "port": runtime_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-m", "http.server", "{port}", "--bind", "127.0.0.1"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                    "health_checks": [
                        {
                            "name": "runtime-web-ready",
                            "url": f"http://127.0.0.1:{runtime_port}/",
                            "expect_status": 200,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        runtime_start = run(["project", "start", "--agent", "agent-a", "--project", str(tmp)], env=env)
        check(runtime_start["ok"], f"project start should verify full runtime: {runtime_start}")
        check(runtime_start["urls"][0]["url"] == f"http://127.0.0.1:{runtime_port}", "project start should preserve fixed URL/port")
        check(runtime_start["services"][0]["type"] == "server", "project runtime should report server service status")
        runtime_status = run(["project", "status", "--project", str(tmp)], env=env)
        check(runtime_status["ok"], "project status should be healthy after project start")
        check(runtime_status["health_checks"][0]["ok"], "project status should run declared readiness checks")
        runtime_stop = run(["project", "stop", "--agent", "agent-a", "--project", str(tmp)], env=env)
        check(runtime_stop["ok"], "project stop should report successful stop operation")
        runtime_stopped_status = run(["project", "status", "--project", str(tmp)], env=env)
        check(runtime_stopped_status["classification"] == "crashed_process", "stopped project status should not report working")

        stale_lease_project = tmp / "stale-lease-project"
        stale_lease_project.mkdir()
        stale_lease_runtime_dir = stale_lease_project / ".codex"
        stale_lease_runtime_dir.mkdir()
        stale_lease_port = free_port()
        (stale_lease_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "stale-lease-runtime",
                    "servers": [
                        {
                            "name": "web",
                            "role": "web",
                            "port": stale_lease_port,
                            "cwd": ".",
                            "cmd": shlex_join([sys.executable, "-m", "http.server", "{port}", "--bind", "127.0.0.1"]),
                            "health_url": "http://127.0.0.1:{port}/",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        stale_lease = run(
            [
                "port",
                "lease",
                "--agent",
                "agent-a",
                "--project",
                str(stale_lease_project),
                "--range",
                f"{stale_lease_port}-{stale_lease_port}",
                "--preferred",
                str(stale_lease_port),
                "--purpose",
                "server:web",
            ],
            env=env,
        )
        stale_start = run(["project", "start", "--agent", "agent-a", "--project", str(stale_lease_project)], env=env)
        check(stale_start["ok"], f"project start should reclaim same-project stale fixed-port leases: {stale_start}")
        stale_inventory = run(["inventory", "--project", str(stale_lease_project), "--no-docker"], env=env)
        check(
            all(item["id"] != stale_lease["id"] for item in stale_inventory["leases"]),
            "stale fixed-port lease should not remain active after project start",
        )
        stale_stop = run(["project", "stop", "--agent", "agent-a", "--project", str(stale_lease_project)], env=env)
        check(stale_stop["ok"], "stale lease project should stop cleanly after reclamation")

        docker = run(
            [
                "docker",
                "compose-up",
                "--agent",
                "agent-a",
                "--project",
                str(tmp),
                "--cwd",
                str(tmp),
                "--file",
                "compose.yml",
                "--detach",
                "--dry-run",
            ],
            env=env,
        )
        check(docker["dry_run"], "docker dry-run should not execute docker")
        check(docker["command"] == ["docker", "compose", "-f", "compose.yml", "up", "-d"], "docker command shape drifted")
        docker_restart = run(
            ["docker", "restart", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-postgres", "--role", "postgres", "--dry-run"],
            env=env,
        )
        check(docker_restart["command"] == ["docker", "restart", "fixture-postgres"], "docker restart command shape drifted")
        check(docker_restart["metadata"]["project"] == str(tmp.resolve()), "docker action should attach sidecar project metadata")
        docker_ps_all = run(["docker", "ps", "--all", "--dry-run"], env=env)
        check(docker_ps_all["command"] == ["docker", "ps", "--all"], "docker ps --all command shape drifted")
        docker_stats = run(["docker", "stats", "--dry-run"], env=env)
        check(
            docker_stats["command"] == ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
            "docker stats command shape drifted",
        )

        fake_bin = tmp / "fake-bin"
        fake_bin.mkdir()
        compose_owner = tmp / "compose-owner"
        fake_docker = fake_bin / "docker"
        fake_containers = {
            "abc123def456": {"Id": "abc123def4567890", "Name": "/fixture-postgres", "Config": {"Labels": {}}},
            "fixture-postgres": {"Id": "abc123def4567890", "Name": "/fixture-postgres", "Config": {"Labels": {}}},
            "fed789abc012": {"Id": "fed789abc0123456", "Name": "/runtime-db", "Config": {"Labels": {}}},
            "runtime-db": {"Id": "fed789abc0123456", "Name": "/runtime-db", "Config": {"Labels": {}}},
            "def456abc123": {
                "Id": "def456abc1237890",
                "Name": "/fixture-compose-db",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(compose_owner),
                        "com.docker.compose.project": "fixture-compose",
                    }
                },
            },
            "fixture-compose-db": {
                "Id": "def456abc1237890",
                "Name": "/fixture-compose-db",
                "Config": {
                    "Labels": {
                        "com.docker.compose.project.working_dir": str(compose_owner),
                        "com.docker.compose.project": "fixture-compose",
                    }
                },
            },
        }
        fake_ps = [
            {"ID": "abc123def456", "Names": "fixture-postgres", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "0.0.0.0:5544->5432/tcp"},
            {"ID": "fed789abc012", "Names": "runtime-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
            {"ID": "def456abc123", "Names": "fixture-compose-db", "Image": "postgres:16", "Status": "Up 1 second", "Ports": "5432/tcp"},
        ]
        fake_docker.write_text(
            f"""#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
containers = json.loads({json.dumps(json.dumps(fake_containers))})
ps_rows = json.loads({json.dumps(json.dumps(fake_ps))})
if args[:1] == ["ps"]:
    for row in ps_rows:
        print(json.dumps(row))
elif args[:3] == ["inspect", "--format", "{{{{json .}}}}"]:
    for key in args[3:]:
        print(json.dumps(containers[key]))
elif args[:1] == ["stats"]:
    pass
else:
    sys.exit(1)
""",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        fake_env = env.copy()
        fake_env["PATH"] = f"{fake_bin}:{fake_env.get('PATH', '')}"
        undeclared_compose_project = tmp / "undeclared-compose-project"
        undeclared_compose_project.mkdir()
        (undeclared_compose_project / "docker-compose.yml").write_text(
            "services:\n  db:\n    image: postgres:16\n    ports:\n      - '5544:5432'\n",
            encoding="utf-8",
        )
        undeclared_start = run(
            ["project", "start", "--agent", "agent-a", "--project", str(undeclared_compose_project), "--dry-run"],
            env=fake_env,
        )
        check(not undeclared_start["ok"], "undeclared Compose-only project start should not report success")
        check(
            not any(action.get("command", [])[:3] == ["docker", "compose", "up"] for action in undeclared_start.get("actions", [])),
            "project start must not run docker compose up from discovered files without a runtime declaration",
        )
        check(
            any(item.get("type") == "compose" and item.get("discovered") for item in undeclared_start.get("services", [])),
            "undeclared Compose files should be reported as discovered evidence",
        )

        registered_container = run(
            ["docker", "register", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-postgres", "--role", "postgres"],
            env=fake_env,
        )
        check(registered_container["metadata_source"] == "coordinator_sidecar", "docker register should create sidecar metadata for unlabeled containers")
        docker_inventory = run(["inventory", "--project", str(tmp)], env=fake_env)
        fixture_pg = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "fixture-postgres")
        check(fixture_pg["project"] == str(tmp.resolve()), "inventory should merge sidecar project metadata")
        check(fixture_pg["metadata_source"] == "coordinator_sidecar", "inventory should expose sidecar metadata source")
        compose_register = run(
            ["docker", "register", "--agent", "agent-a", "--project", str(tmp), "--container", "fixture-compose-db", "--role", "postgres"],
            env=fake_env,
        )
        check(compose_register["metadata_source"] == "docker_labels" and compose_register["skipped"], "compose labels should win over sidecar registration")
        docker_inventory = run(["inventory", "--project", str(tmp)], env=fake_env)
        fixture_compose = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "fixture-compose-db")
        check(fixture_compose["project"] == str(compose_owner.resolve()), "inventory should preserve Compose working-dir project metadata")

        declared_docker_project = tmp / "declared-docker-project"
        declared_docker_project.mkdir()
        declared_docker_runtime_dir = declared_docker_project / ".codex"
        declared_docker_runtime_dir.mkdir()
        (declared_docker_runtime_dir / "dev-runtime.json").write_text(
            json.dumps(
                {
                    "name": "declared-docker-runtime",
                    "dependencies": [
                        {"type": "docker", "name": "database", "container": "runtime-db", "required": True}
                    ],
                }
            ),
            encoding="utf-8",
        )
        declared_docker_start = run(["project", "start", "--agent", "agent-a", "--project", str(declared_docker_project)], env=fake_env)
        check(declared_docker_start["ok"], f"declared running Docker dependency should make project start healthy: {declared_docker_start}")
        docker_inventory = run(["inventory", "--project", str(declared_docker_project)], env=fake_env)
        runtime_db = next(item for item in docker_inventory["docker"]["containers"] if item["name"] == "runtime-db")
        check(runtime_db["project"] == str(declared_docker_project.resolve()), "project start should attach sidecar metadata to declared unlabeled containers")
        check(runtime_db["metadata_source"] == "coordinator_sidecar", "declared unlabeled containers should expose coordinator sidecar metadata")

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
        api_runtime = post_json(api_port, "/v1/projects/status", {"project": str(tmp)})
        check("services" in api_runtime and "ok" in api_runtime, "API project status should expose runtime report")
        api_stats = post_json(api_port, "/v1/docker/stats", {"dry_run": True})
        check(api_stats["command"] == ["docker", "stats", "--no-stream", "--format", "{{json .}}"], "API docker stats should use real stats command")
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
        for process in external_processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        rmtree(tmp, ignore_errors=True)


def shlex_join(parts: list[str]) -> str:
    return " ".join("'" + part.replace("'", "'\"'\"'") + "'" for part in parts)


if __name__ == "__main__":
    raise SystemExit(main())
