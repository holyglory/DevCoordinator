"""Focused browser lifecycle census, accounting, and cleanup tests."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from devcoordinator import browser_lifecycle as lifecycle  # noqa: E402


def stat_text(
    pid: int,
    *,
    ppid: int,
    start_ticks: int,
    cpu_ticks: int = 0,
    rss_pages: int = 1,
    executable: str = "process",
) -> str:
    fields = [
        "S",
        str(ppid),
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        str(cpu_ticks),
        "0",
        "0",
        "0",
        "0",
        "0",
        "1",
        "0",
        str(start_ticks),
        "0",
        str(rss_pages),
    ]
    return f"{pid} ({executable}) {' '.join(fields)}\n"


def write_process(
    proc_root: Path,
    pid: int,
    *,
    ppid: int,
    executable: str,
    argv: list[str] | None = None,
    cgroup: str = "/user.slice/user-1000.slice/session-1.scope",
    uid: int = 1000,
    start_ticks: int | None = None,
    cpu_ticks: int = 0,
    rss_pages: int = 1,
    pss_kib: int | None = 4,
    io_read: int | None = 0,
    io_write: int | None = 0,
) -> None:
    process = proc_root / str(pid)
    if process.exists():
        shutil.rmtree(process)
    process.mkdir(parents=True)
    start = start_ticks if start_ticks is not None else pid * 100
    (process / "stat").write_text(
        stat_text(
            pid,
            ppid=ppid,
            start_ticks=start,
            cpu_ticks=cpu_ticks,
            rss_pages=rss_pages,
            executable=executable,
        ),
        encoding="utf-8",
    )
    command = argv if argv is not None else [f"/usr/bin/{executable}"]
    (process / "cmdline").write_bytes(
        b"\0".join(item.encode("utf-8") for item in command) + b"\0"
    )
    (process / "status").write_text(f"Name:\t{executable}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n", encoding="utf-8")
    (process / "cgroup").write_text(f"0::{cgroup}\n", encoding="utf-8")
    if io_read is not None or io_write is not None:
        rows = []
        if io_read is not None:
            rows.append(f"read_bytes: {io_read}")
        if io_write is not None:
            rows.append(f"write_bytes: {io_write}")
        (process / "io").write_text("\n".join(rows) + "\n", encoding="utf-8")
    if pss_kib is not None:
        (process / "smaps_rollup").write_text(f"Pss: {pss_kib} kB\n", encoding="utf-8")
    (process / "exe").symlink_to(f"/usr/bin/{executable}")


class FakeController:
    def __init__(
        self,
        proc_root: Path,
        *,
        survive_term: set[int] | None = None,
        mutate_on_open: dict[int, int] | None = None,
    ) -> None:
        self.proc_root = proc_root
        self.survive_term = set(survive_term or ())
        self.mutate_on_open = dict(mutate_on_open or {})
        self.signals: list[tuple[int, int]] = []
        self.closed: list[int] = []

    def open(self, pid: int) -> int:
        if not (self.proc_root / str(pid)).exists():
            raise ProcessLookupError(pid)
        if pid in self.mutate_on_open:
            path = self.proc_root / str(pid) / "stat"
            current = path.read_text(encoding="utf-8")
            fields = lifecycle._parse_stat(current)
            path.write_text(
                current.replace(
                    f" {fields['start_ticks']} 0 ",
                    f" {self.mutate_on_open[pid]} 0 ",
                    1,
                ),
                encoding="utf-8",
            )
        return pid

    def send(self, handle: int, signum: int) -> None:
        self.signals.append((handle, signum))
        if signum == signal.SIGTERM and handle in self.survive_term:
            return
        shutil.rmtree(self.proc_root / str(handle), ignore_errors=True)

    def wait(self, handle: int, _timeout_seconds: float) -> bool:
        return not (self.proc_root / str(handle)).exists()

    def close(self, handle: int) -> None:
        self.closed.append(handle)


class BrowserLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="browser-lifecycle-")
        self.root = Path(self.temporary.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        boot = self.proc / "sys/kernel/random"
        boot.mkdir(parents=True)
        (boot / "boot_id").write_text("boot-fixture\n", encoding="utf-8")
        self.state = self.root / "state" / "browsers.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def parent(self, pid: int = 10, *, cgroup: str = "/user.slice/user-1000.slice/session-1.scope") -> None:
        write_process(
            self.proc,
            pid,
            ppid=1,
            executable="bash",
            argv=["/bin/bash"],
            cgroup=cgroup,
        )

    def observe(self, epoch: float, **kwargs: object) -> dict:
        return lifecycle.observe_browser_lifecycle(
            self.state,
            proc_root=self.proc,
            now_fn=lambda: epoch,
            monotonic_fn=lambda: 1.0,
            page_size=4096,
            clock_ticks=100,
            **kwargs,
        )

    def test_detects_only_explicit_automation_roots_and_consolidates_trees(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless=new"],
            pss_kib=10,
        )
        write_process(
            self.proc,
            21,
            ppid=20,
            executable="chrome",
            argv=["/usr/bin/chrome", "--type=renderer"],
            pss_kib=5,
        )
        write_process(
            self.proc,
            30,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "https://example.test"],
        )
        write_process(
            self.proc,
            31,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--remote-debugging-port=9222"],
        )
        write_process(
            self.proc,
            40,
            ppid=10,
            executable="python3",
            argv=["/usr/bin/python3", "runner.py", "--headless"],
        )
        write_process(
            self.proc,
            50,
            ppid=10,
            executable="agent-browser-linux-x64",
            argv=["/opt/agent-browser-linux-x64"],
        )
        write_process(
            self.proc,
            51,
            ppid=50,
            executable="chromium",
            argv=["/usr/bin/chromium", "--type=renderer"],
        )
        write_process(
            self.proc,
            60,
            ppid=10,
            executable="headless_shell",
        )
        write_process(
            self.proc,
            70,
            ppid=10,
            executable="firefox",
            argv=["/usr/bin/firefox", "-headless"],
        )
        write_process(
            self.proc,
            80,
            ppid=10,
            executable="firefox",
            argv=["/usr/bin/firefox", "https://example.test"],
        )
        write_process(
            self.proc,
            75,
            ppid=10,
            executable="firefox-esr",
            argv=["/usr/bin/firefox-esr", "-juggler-pipe"],
        )
        write_process(
            self.proc,
            90,
            ppid=10,
            executable="MiniBrowser",
            argv=[
                "/home/dev/.cache/ms-playwright/webkit-123/minibrowser-gtk/bin/MiniBrowser"
            ],
        )
        write_process(
            self.proc,
            91,
            ppid=90,
            executable="WebKitWebProcess",
            argv=["/opt/WebKitWebProcess"],
        )
        write_process(
            self.proc,
            100,
            ppid=10,
            executable="MiniBrowser",
            argv=["/usr/bin/MiniBrowser"],
        )

        document = self.observe(1_000.0, reap_idle=False)

        self.assertTrue(document["ok"])
        self.assertEqual(document["accounted_session_count"], 6)
        self.assertEqual(document["totals"]["process_count"], 9)
        by_kind = {item["browser_kind"]: item for item in document["active"]}
        self.assertEqual(by_kind["chrome-headless"]["process_count"], 2)
        self.assertEqual(by_kind["agent-browser"]["process_count"], 2)
        self.assertEqual(by_kind["headless-shell"]["process_count"], 1)
        self.assertEqual(by_kind["firefox-headless"]["process_count"], 1)
        self.assertEqual(by_kind["firefox-automation"]["process_count"], 1)
        self.assertEqual(by_kind["webkit-playwright"]["process_count"], 2)
        all_pids = {member["pid"] for item in document["active"] for member in item["members"]}
        self.assertNotIn(30, all_pids)
        self.assertNotIn(31, all_pids)
        self.assertNotIn(40, all_pids)
        self.assertNotIn(80, all_pids)
        self.assertNotIn(100, all_pids)

    def test_node_agent_browser_launcher_is_strictly_detected_from_launch_slots(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="node",
            argv=["/usr/bin/node", "/opt/agent-browser/agent-browser.js", "serve"],
        )
        write_process(
            self.proc,
            21,
            ppid=20,
            executable="chrome",
            argv=["/usr/bin/chrome", "--type=renderer"],
        )
        write_process(
            self.proc,
            30,
            ppid=10,
            executable="node",
            argv=["/usr/bin/node", "/opt/unrelated.js", "--label=agent-browser"],
        )

        document = self.observe(1_000.0, reap_idle=False)

        self.assertEqual(document["accounted_session_count"], 1)
        session = document["active"][0]
        self.assertEqual(session["browser_kind"], "agent-browser")
        self.assertEqual(session["root_pid"], 20)
        self.assertEqual(session["process_count"], 2)
        self.assertTrue(session["fully_browser_classified"])

    def test_expensive_usage_files_are_read_only_for_browser_tree_members(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
        )
        for pid in range(100, 150):
            write_process(
                self.proc,
                pid,
                ppid=10,
                executable="python3",
                argv=["/usr/bin/python3", f"worker-{pid}.py"],
            )
        original = lifecycle._read_optional_text
        expensive_reads: list[Path] = []

        def recording_read(path: Path) -> str | None:
            if path.name in {"smaps_rollup", "io"}:
                expensive_reads.append(path)
            return original(path)

        with mock.patch.object(lifecycle, "_read_optional_text", side_effect=recording_read):
            self.observe(1_000.0, reap_idle=False)

        self.assertEqual({path.parent.name for path in expensive_reads}, {"20"})

    def test_classifies_and_excludes_existing_lifecycle_owners(self) -> None:
        definitions = (
            (20, "/user.slice/user-1000.slice/session-1.scope", "developer-session"),
            (30, "/devcoordinator-tests.slice/test.scope", "test"),
            (40, "/devcoordinator-control.slice/api.scope", "control"),
            (50, "/devcoordinator-projects.slice/repo.scope", "project"),
            (60, "/system.slice/docker-deadbeef.scope", "container"),
            (80, "/system.slice/containerd.service/browser.scope", "container"),
        )
        for pid, cgroup, _classification in definitions:
            self.parent(pid - 1, cgroup=cgroup)
            write_process(
                self.proc,
                pid,
                ppid=pid - 1,
                executable="chrome",
                argv=["/usr/bin/chrome", "--headless"],
                cgroup=cgroup,
                pss_kib=pid,
            )

        document = self.observe(1_000.0, reap_idle=False)

        classifications = {item["classification"]: item for item in document["active"]}
        self.assertEqual(set(classifications), {"developer-session", "test", "control"})
        self.assertTrue(classifications["developer-session"]["accounted"])
        self.assertFalse(classifications["test"]["accounted"])
        self.assertTrue(classifications["test"]["protected"])
        self.assertTrue(classifications["control"]["protected"])
        self.assertEqual(document["accounted_session_count"], 1)
        self.assertEqual(document["protected_session_count"], 2)
        self.assertEqual(document["excluded"]["project_session_count"], 1)
        self.assertEqual(document["excluded"]["container_session_count"], 2)
        self.assertEqual(document["totals"]["memory_bytes"], 20 * 1024)

    def test_pss_memory_and_resource_activity_deltas_are_aggregated(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            cpu_ticks=100,
            pss_kib=4,
            io_read=10,
            io_write=20,
        )
        write_process(
            self.proc,
            21,
            ppid=20,
            executable="chrome",
            argv=["/usr/bin/chrome", "--type=renderer"],
            cpu_ticks=50,
            rss_pages=2,
            pss_kib=None,
            io_read=30,
            io_write=40,
        )
        first = self.observe(1_000.0, reap_idle=False)
        self.assertEqual(first["active"][0]["memory_measurement"], "mixed")
        self.assertEqual(first["active"][0]["current_memory_bytes"], 4 * 1024 + 2 * 4096)
        self.assertFalse(first["active"][0]["memory_exact"])

        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            cpu_ticks=200,
            pss_kib=6,
            io_read=110,
            io_write=70,
        )
        write_process(
            self.proc,
            21,
            ppid=20,
            executable="chrome",
            argv=["/usr/bin/chrome", "--type=renderer"],
            cpu_ticks=50,
            rss_pages=2,
            pss_kib=None,
            io_read=50,
            io_write=45,
        )
        second = self.observe(1_010.0, reap_idle=False)
        session = second["active"][0]
        self.assertTrue(session["resource_activity"])
        self.assertEqual(session["cpu_ticks_delta"], 100)
        self.assertEqual(session["cpu_percent"], 10.0)
        self.assertEqual(session["io_read_bytes_delta"], 120)
        self.assertEqual(session["io_write_bytes_delta"], 55)
        self.assertEqual(session["last_resource_activity_at"], second["sampled_at"])

    def test_idle_reaping_uses_exact_identity_and_term_then_kill(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            pss_kib=12,
        )
        self.observe(100.0, reap_idle=True, controller=FakeController(self.proc))
        controller = FakeController(self.proc, survive_term={20})

        document = self.observe(1_001.0, reap_idle=True, controller=controller)

        self.assertTrue(document["ok"])
        self.assertEqual(document["idle_reap"]["reaped_session_count"], 1)
        self.assertEqual(document["active_session_count"], 0)
        self.assertEqual(controller.signals, [(20, signal.SIGTERM), (20, signal.SIGKILL)])
        state = lifecycle.read_browser_lifecycle_state(self.state)
        assert state is not None
        self.assertEqual(len(state["reaped"]), 1)
        self.assertEqual(state["reaped"][0]["stop_reason"], "idle-timeout")

    def test_identity_drift_refuses_to_signal(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            start_ticks=2_000,
        )
        self.observe(100.0, reap_idle=False)
        controller = FakeController(self.proc, mutate_on_open={20: 9_999})

        document = self.observe(1_001.0, reap_idle=True, controller=controller)

        self.assertFalse(document["ok"])
        self.assertEqual(document["idle_reap"]["failures"][0]["code"], "identity_changed")
        self.assertEqual(controller.signals, [])
        self.assertTrue((self.proc / "20").exists())

    def test_missing_cgroup_evidence_fails_closed_before_cleanup(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
        )
        (self.proc / "20" / "cgroup").unlink()
        (self.proc / "20" / "cgroup").mkdir()
        controller = FakeController(self.proc)

        result = lifecycle.cleanup_all_headless(
            self.state,
            proc_root=self.proc,
            quiescence_seconds=0,
            controller=controller,
            now_fn=lambda: 1_000.0,
            monotonic_fn=lambda: 1.0,
            page_size=4096,
            clock_ticks=100,
        )

        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "process_scan_incomplete")
        self.assertEqual(controller.signals, [])

    def test_test_browser_is_never_idle_reaped(self) -> None:
        cgroup = "/devcoordinator-tests.slice/test.scope"
        self.parent(cgroup=cgroup)
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="headless_shell",
            cgroup=cgroup,
        )
        self.observe(100.0, reap_idle=False)
        controller = FakeController(self.proc)

        document = self.observe(2_000.0, reap_idle=True, controller=controller)

        self.assertTrue(document["ok"])
        self.assertEqual(document["idle_reap"]["reaped_session_count"], 0)
        self.assertEqual(controller.signals, [])
        self.assertEqual(document["protected_session_count"], 1)

    def test_orphan_reaps_on_second_observation_despite_activity(self) -> None:
        write_process(
            self.proc,
            20,
            ppid=1,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            cpu_ticks=100,
        )
        first = self.observe(100.0, reap_idle=True, controller=FakeController(self.proc))
        self.assertTrue(first["active"][0]["orphaned"])
        self.assertEqual(first["active"][0]["orphan_observation_count"], 1)
        write_process(
            self.proc,
            20,
            ppid=1,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            cpu_ticks=500,
        )
        controller = FakeController(self.proc)

        second = self.observe(105.0, reap_idle=True, controller=controller)

        self.assertTrue(second["ok"])
        self.assertEqual(second["idle_reap"]["reaped_session_count"], 1)
        state = lifecycle.read_browser_lifecycle_state(self.state)
        assert state is not None
        self.assertEqual(state["reaped"][0]["stop_reason"], "orphaned-browser-tree")

    def test_cleanup_all_targets_host_sessions_but_not_projects_or_containers(self) -> None:
        definitions = (
            (20, "/user.slice/user-1000.slice/session-1.scope"),
            (30, "/system.slice/unmanaged.scope"),
            (40, "/devcoordinator-tests.slice/test.scope"),
            (50, "/devcoordinator-control.slice/control.scope"),
            (60, "/devcoordinator-projects.slice/repo.scope"),
            (70, "/system.slice/docker-deadbeef.scope"),
        )
        for pid, cgroup in definitions:
            self.parent(pid - 1, cgroup=cgroup)
            write_process(
                self.proc,
                pid,
                ppid=pid - 1,
                executable="chrome",
                argv=["/usr/bin/chrome", "--headless"],
                cgroup=cgroup,
                pss_kib=pid,
            )
        controller = FakeController(self.proc)

        result = lifecycle.cleanup_all_headless(
            self.state,
            proc_root=self.proc,
            quiescence_seconds=0,
            controller=controller,
            now_fn=lambda: 1_000.0,
            monotonic_fn=lambda: 1.0,
            page_size=4096,
            clock_ticks=100,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["remaining_session_count"], 0)
        self.assertEqual(result["terminated_session_count"], 4)
        self.assertEqual(result["terminated_process_count"], 4)
        self.assertEqual(result["reclaimed_memory_bytes"], (20 + 30 + 40 + 50) * 1024)
        self.assertEqual(result["protected_session_count"], 0)
        self.assertFalse((self.proc / "20").exists())
        self.assertFalse((self.proc / "30").exists())
        self.assertFalse((self.proc / "40").exists())
        self.assertFalse((self.proc / "50").exists())
        for pid in (60, 70):
            self.assertTrue((self.proc / str(pid)).exists())

    def test_inventory_projection_is_path_free_and_operator_bounded(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            pss_kib=8,
        )
        document = self.observe(1_000.0, reap_idle=False)

        projection = lifecycle.browser_lifecycle_inventory_projection(document)

        self.assertEqual(projection["totals"]["session_count"], 1)
        self.assertEqual(projection["totals"]["process_count"], 1)
        session = projection["sessions"][0]
        self.assertEqual(session["cgroup_class"], "developer-session")
        self.assertEqual(session["agent"], "chrome-headless")
        self.assertTrue(session["reap_eligible"])
        self.assertEqual(projection["policy"]["idle_timeout_seconds"], 900)
        self.assertIn("termination_grace_seconds", projection["policy"])
        self.assertEqual(projection["totals"]["reaped_total"], 0)
        self.assertEqual(projection["totals"]["reclaimed_memory_bytes"], 0)
        serialized = json.dumps(projection)
        for forbidden in ("root_pid", "start_ticks", "members", "cgroup_path"):
            self.assertNotIn(forbidden, serialized)

    def test_reaped_history_and_serialized_state_are_bounded(self) -> None:
        initial = {
            "schema_version": lifecycle.SCHEMA_VERSION,
            "generation": 1,
            "sampled_at": "1970-01-01T00:00:01.000000Z",
            "boot_id": "boot-fixture",
            "active": [],
            "reaped": [
                {"session_id": f"old-{index}", "stopped_at": "1970-01-01T00:00:01Z"}
                for index in range(lifecycle.MAX_REAPED_SESSIONS + 20)
            ],
            "reaped_omitted_count": 0,
        }
        self.state.parent.mkdir(parents=True)
        self.state.write_text(json.dumps(initial), encoding="utf-8")

        document = self.observe(2.0, reap_idle=False)

        self.assertEqual(len(document["reaped"]), lifecycle.MAX_REAPED_SESSIONS)
        self.assertEqual(document["reaped_omitted_count"], 20)
        self.assertEqual(document["reaped_total"], lifecycle.MAX_REAPED_SESSIONS + 20)
        self.assertLessEqual(self.state.stat().st_size, lifecycle.MAX_STATE_BYTES)
        self.assertTrue(self.state.with_name(self.state.name + ".lock").is_file())
        json.loads(self.state.read_text(encoding="utf-8"))

    def test_status_opens_existing_lock_read_only(self) -> None:
        self.observe(2.0, reap_idle=False)
        lock_path = self.state.with_name(self.state.name + ".lock")
        opened_flags: list[int] = []
        real_open = lifecycle.os.open

        def recording_open(path: object, flags: int, *args: object) -> int:
            if Path(path) == lock_path:
                opened_flags.append(flags)
            return real_open(path, flags, *args)

        with mock.patch.object(lifecycle.os, "open", side_effect=recording_open):
            state = lifecycle.read_browser_lifecycle_state(self.state)
        self.assertIsNotNone(state)
        self.assertEqual(opened_flags, [os.O_RDONLY])
        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o644)

    def test_status_and_cleanup_cli_json_contracts(self) -> None:
        self.parent()
        write_process(
            self.proc,
            20,
            ppid=10,
            executable="chrome",
            argv=["/usr/bin/chrome", "--headless"],
            pss_kib=8,
        )
        self.observe(1_000.0, reap_idle=False)
        output = io.StringIO()
        with redirect_stdout(output):
            status_code = lifecycle.main(["status", "--state", str(self.state), "--json"])
        status = json.loads(output.getvalue())
        self.assertEqual(status_code, 0)
        self.assertTrue(status["ok"])
        self.assertEqual(status["accounted_session_count"], 1)

        output = io.StringIO()
        with redirect_stdout(output):
            cleanup_code = lifecycle.main(
                [
                    "cleanup-all",
                    "--state",
                    str(self.state),
                    "--quiescence-seconds",
                    "0",
                    "--json",
                ],
                controller=FakeController(self.proc),
                proc_root=self.proc,
                now_fn=lambda: 1_001.0,
                monotonic_fn=lambda: 1.0,
                sleep_fn=lambda _seconds: None,
            )
        cleanup = json.loads(output.getvalue())
        self.assertEqual(cleanup_code, 0)
        self.assertTrue(cleanup["ok"])
        self.assertEqual(cleanup["remaining_session_count"], 0)
        self.assertEqual(cleanup["terminated_session_count"], 1)
        self.assertEqual(cleanup["terminated_process_count"], 1)
        self.assertEqual(cleanup["reclaimed_memory_bytes"], 8 * 1024)
        self.assertIn("sampled_at", cleanup)


if __name__ == "__main__":
    unittest.main()
