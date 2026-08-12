"""Focused controls for sealed project systemd one-shot commissioning."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from devcoordinator.systemd_commissioning import (
    SystemdCommissioningError,
    apply_commissioning,
    plan_commissioning,
)


UNIT = "example-maintenance"


class FakeSystemd:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.invocation = "before"
        self.timer_active = False
        self.unobservable: set[str] = set()

    def __call__(self, command: object) -> subprocess.CompletedProcess[str]:
        argv = tuple(str(item) for item in command)  # type: ignore[arg-type]
        self.commands.append(argv)
        if argv[1] == "start":
            self.invocation = "after"
        elif argv[1] == "enable":
            self.timer_active = True
        elif argv[1] == "disable":
            self.timer_active = False
        if argv[1] == "show":
            name = argv[-1]
            if name in self.unobservable:
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr="Unit not found"
                )
            is_timer = name.endswith(".timer")
            active = "active" if is_timer and self.timer_active else "inactive"
            output = {
                "LoadState": "loaded",
                "ActiveState": active,
                "SubState": "waiting" if active == "active" else "dead",
                "Result": "success",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "InvocationID": self.invocation if not is_timer else "timer",
                "UnitFileState": "enabled" if self.timer_active else "disabled",
            }
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout="".join(f"{key}={value}\n" for key, value in output.items()),
                stderr="",
            )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


class SystemdCommissioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.units = self.project / "deploy" / "systemd"
        self.units.mkdir(parents=True)
        (self.units / f"{UNIT}.service").write_text(
            "[Unit]\nDescription=Fixture\n\n"
            "[Service]\nType=oneshot\nUser=developer\nGroup=developer\n"
            "ExecStart=/usr/bin/true\nNoNewPrivileges=true\n"
            "ProtectSystem=strict\nUMask=0077\n"
            "CapabilityBoundingSet=\nAmbientCapabilities=\n",
            encoding="utf-8",
        )
        (self.units / f"{UNIT}.timer").write_text(
            "[Unit]\nDescription=Fixture timer\n\n"
            f"[Timer]\nOnCalendar=daily\nUnit={UNIT}.service\n\n"
            "[Install]\nWantedBy=timers.target\n",
            encoding="utf-8",
        )
        self.installed = self.root / "installed"
        self.installed.mkdir()
        self.journal = self.root / "journal"
        self.runner = FakeSystemd()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _plan(self, desired: str) -> dict[str, object]:
        return plan_commissioning(
            project=self.project,
            unit=UNIT,
            desired=desired,
            installed_root=self.installed,
            runner=self.runner,
        )

    def _apply(self, desired: str, plan: dict[str, object]) -> dict[str, object]:
        return apply_commissioning(
            project=self.project,
            unit=UNIT,
            desired=desired,
            operation_id=str(uuid.uuid4()),
            confirmation_fingerprint=str(plan["plan_fingerprint"]),
            installed_root=self.installed,
            journal_root=self.journal,
            runner=self.runner,
            effective_uid=0,
        )

    def test_plan_is_read_only_and_binds_exact_sources(self) -> None:
        plan = self._plan("commissioned")
        self.assertFalse(plan["mutation_performed"])
        self.assertEqual([item["present"] for item in plan["installed"]], [False, False])
        self.assertEqual(self.runner.commands, [])
        self.assertTrue(str(plan["confirmation"]).startswith("CONFIRM commissioned"))

    def test_service_filename_selector_is_normalized_to_one_unit_stem(self) -> None:
        plan = plan_commissioning(
            project=self.project,
            unit=f"{UNIT}.service",
            desired="commissioned",
            installed_root=self.installed,
            runner=self.runner,
        )
        self.assertEqual(plan["unit"], UNIT)
        self.assertEqual(
            [item["name"] for item in plan["sources"]],
            [f"{UNIT}.service", f"{UNIT}.timer"],
        )

    def test_commissioning_plan_reports_installed_unobservable_unit(self) -> None:
        for source in self.units.iterdir():
            (self.installed / source.name).write_bytes(source.read_bytes())
        self.runner.unobservable.add(f"{UNIT}.timer")

        plan = self._plan("commissioned")

        timer = next(
            item for item in plan["states"] if item["name"] == f"{UNIT}.timer"
        )
        self.assertFalse(timer["observable"])
        self.assertEqual(timer["returncode"], 1)
        with self.assertRaisesRegex(SystemdCommissioningError, "unobservable"):
            self._plan("timer-enabled")

    def test_commission_installs_exact_files_and_only_reloads(self) -> None:
        result = self._apply("commissioned", self._plan("commissioned"))
        self.assertTrue(result["ok"])
        self.assertEqual(
            (self.installed / f"{UNIT}.service").read_bytes(),
            (self.units / f"{UNIT}.service").read_bytes(),
        )
        self.assertIn(("/usr/bin/systemctl", "daemon-reload"), self.runner.commands)
        self.assertFalse(any(command[1] == "start" for command in self.runner.commands))

    def test_run_once_is_confirmation_bound_and_replay_does_not_repeat(self) -> None:
        self._apply("commissioned", self._plan("commissioned"))
        plan = self._plan("run-once")
        operation_id = str(uuid.uuid4())
        first = apply_commissioning(
            project=self.project,
            unit=UNIT,
            desired="run-once",
            operation_id=operation_id,
            confirmation_fingerprint=str(plan["plan_fingerprint"]),
            installed_root=self.installed,
            journal_root=self.journal,
            runner=self.runner,
            effective_uid=0,
        )
        second = apply_commissioning(
            project=self.project,
            unit=UNIT,
            desired="run-once",
            operation_id=operation_id,
            confirmation_fingerprint=str(plan["plan_fingerprint"]),
            installed_root=self.installed,
            journal_root=self.journal,
            runner=self.runner,
            effective_uid=0,
        )
        starts = [command for command in self.runner.commands if command[1] == "start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(first, second)

    def test_source_change_invalidates_confirmation(self) -> None:
        plan = self._plan("commissioned")
        service = self.units / f"{UNIT}.service"
        service.write_text(
            service.read_text(encoding="utf-8").replace(
                "ExecStart=/usr/bin/true", "ExecStart=/usr/bin/false"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            SystemdCommissioningError, "plan changed"
        ):
            self._apply("commissioned", plan)

    def test_timer_enable_uses_only_exact_sibling_unit(self) -> None:
        self._apply("commissioned", self._plan("commissioned"))
        result = self._apply("timer-enabled", self._plan("timer-enabled"))
        self.assertEqual(result["states"][1]["ActiveState"], "active")
        self.assertIn(
            ("/usr/bin/systemctl", "enable", "--now", f"{UNIT}.timer"),
            self.runner.commands,
        )

    def test_root_service_is_rejected_before_any_systemd_call(self) -> None:
        service = self.units / f"{UNIT}.service"
        service.write_text(
            service.read_text(encoding="utf-8").replace(
                "User=developer", "User=root"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            SystemdCommissioningError, "non-root User"
        ):
            self._plan("commissioned")
        self.assertEqual(self.runner.commands, [])


if __name__ == "__main__":
    unittest.main()
