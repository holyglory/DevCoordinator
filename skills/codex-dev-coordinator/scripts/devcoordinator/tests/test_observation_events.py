"""Focused transition-journal and event catch-up contract tests."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_ROOT = Path(__file__).resolve().parents[2]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import dev_coordinator  # noqa: E402
from devcoordinator.broker import (  # noqa: E402
    BrokerOperation,
    BrokerRequest,
    BrokerService,
    PeerCredentials,
    SerializedMutationWriter,
)
from devcoordinator.broker_backend import StoreBackedMutationBackend  # noqa: E402
from devcoordinator.broker_persistence import (  # noqa: E402
    BrokerPersistence,
    StoreBackedAuthorizer,
)
from devcoordinator.events import decode_event_cursor, list_event_page  # noqa: E402
from devcoordinator.host_observation import commit_host_inventory_observation  # noqa: E402
from devcoordinator.observer import SingleFlightObserver  # noqa: E402
from devcoordinator.store import AccountStore  # noqa: E402


class ObservationEventTests(unittest.TestCase):
    def setUp(self) -> None:
        canonical_home = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".observation-events-", dir=str(canonical_home)
        )
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "store"
        self.project = self.root / "project"
        self.project.mkdir(mode=0o700)
        (self.project / ".git").mkdir(mode=0o700)
        self.repo_id = "repo-events"
        self.server_id = "server-events"
        with AccountStore.open_default(self.home) as store:
            self.host_id = store.ensure_local_host()
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO repositories(
                        repo_id, host_id, canonical_root, display_name, state,
                        generation, created_at, updated_at
                    ) VALUES (?, ?, ?, 'Events', 'active', 0, ?, ?)
                    """,
                    (
                        self.repo_id,
                        self.host_id,
                        str(self.project),
                        "2026-07-18T10:00:00Z",
                        "2026-07-18T10:00:00Z",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO repository_installations(
                        repo_id, status, startup_fenced, generation, actor, updated_at
                    ) VALUES (?, 'installed', 0, 0, 'fixture', ?)
                    """,
                    (self.repo_id, "2026-07-18T10:00:00Z"),
                )
                connection.execute(
                    """
                    INSERT INTO server_definitions(
                        server_definition_id, repo_id, name, cwd,
                        definition_fingerprint, generation, created_at, updated_at
                    ) VALUES (?, ?, 'web', ?, 'fixture-server', 0, ?, ?)
                    """,
                    (
                        self.server_id,
                        self.repo_id,
                        str(self.project),
                        "2026-07-18T10:00:00Z",
                        "2026-07-18T10:00:00Z",
                    ),
                )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def observe(self, sample: dict) -> None:
        with AccountStore.open_default(self.home) as store:
            SingleFlightObserver(store).observe(
                host_id=self.host_id,
                observer_domain="event-transition-fixture",
                sampler=lambda: sample,
                commit=lambda connection, snapshot_id, observed: commit_host_inventory_observation(
                    connection,
                    snapshot_id,
                    observed,
                    host_id=self.host_id,
                    coordinator_home=str(self.home),
                ),
            )

    def server_sample(
        self,
        timestamp: str,
        *,
        lifecycle: str,
        classification: str,
        ok: bool | None,
        pid_alive: bool | None,
        identity: dict,
        stopped_reason: str | None = None,
    ) -> dict:
        server = {
            "id": self.server_id,
            "project": str(self.project),
            "name": "web",
            "status": lifecycle,
            "pid": 12345 if lifecycle != "stopped" else None,
            "port": 3100,
            "health": {
                "ok": ok,
                "pid_alive": pid_alive,
                "classification": classification,
                "identity": identity,
            },
        }
        if stopped_reason is not None:
            server["stopped_reason"] = stopped_reason
        return {
            "sampled_at": timestamp,
            "inventory": {
                "servers": [server],
                "docker": {"available": False, "containers": [], "postgres": []},
            },
        }

    def docker_sample(
        self,
        timestamp: str,
        *,
        status: str | None,
        health: str | None = "healthy",
        available: bool = True,
        inspectable: bool = True,
    ) -> dict:
        containers = []
        if status is not None:
            container = {
                "id": "a" * 64,
                "full_id": "a" * 64,
                "name": "events-worker",
                "image": "fixture:latest",
                "status": status,
                "running": status.startswith("Up "),
                "project": str(self.project),
                "metadata_source": (
                    "coordinator_sidecar" if inspectable else "inspection_unavailable"
                ),
                "inspection_observable": inspectable,
                "labels": {},
                "port_bindings": [],
                "databases": [],
            }
            if health is not None:
                container["container_health"] = health
            containers.append(container)
        docker = {
            "available": available,
            "containers": containers,
            "postgres": [],
        }
        if not available:
            docker["error"] = "fixture Docker unavailable"
        return {
            "sampled_at": timestamp,
            "inventory": {"servers": [], "docker": docker},
        }

    def events(self) -> list[dict]:
        with AccountStore.open_default_read_only(self.home) as store:
            with store.read_transaction() as connection:
                return [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT event_id, repo_id, operation_id, event_kind, code,
                               message, diagnostic_json, occurred_at
                        FROM events ORDER BY occurred_at, event_id
                        """
                    )
                ]

    def test_server_transitions_are_exact_once_and_unknown_is_not_failure(self) -> None:
        healthy = self.server_sample(
            "2026-07-18T10:01:00Z",
            lifecycle="running",
            classification="healthy",
            ok=True,
            pid_alive=True,
            identity={"ok": True, "observable": True},
        )
        self.observe(healthy)
        self.observe({**healthy, "sampled_at": "2026-07-18T10:02:00Z"})
        self.observe(
            self.server_sample(
                "2026-07-18T10:03:00Z",
                lifecycle="running",
                classification="unverified-listener",
                ok=None,
                pid_alive=True,
                identity={"ok": None, "observable": False},
            )
        )
        self.assertEqual(self.events(), [])

        stopped = self.server_sample(
            "2026-07-18T10:04:00Z",
            lifecycle="stopped",
            classification="stopped",
            ok=False,
            pid_alive=False,
            identity={"ok": True},
            stopped_reason="fixture process exited",
        )
        self.observe(stopped)
        self.observe({**stopped, "sampled_at": "2026-07-18T10:05:00Z"})
        self.observe(
            self.server_sample(
                "2026-07-18T10:06:00Z",
                lifecycle="running",
                classification="healthy",
                ok=True,
                pid_alive=True,
                identity={"ok": True, "observable": True},
            )
        )
        self.observe(
            self.server_sample(
                "2026-07-18T10:07:00Z",
                lifecycle="unhealthy",
                classification="unhealthy",
                ok=False,
                pid_alive=True,
                identity={"ok": True, "observable": True},
            )
        )
        self.observe(
            self.server_sample(
                "2026-07-18T10:08:00Z",
                lifecycle="running",
                classification="healthy",
                ok=True,
                pid_alive=True,
                identity={"ok": True, "observable": True},
            )
        )

        events = self.events()
        self.assertEqual(
            [(item["event_kind"], item["code"]) for item in events],
            [
                ("server.stopped", "server_crashed"),
                ("server.started", "server_observed_started"),
                ("server.failed", "server_observed_unhealthy"),
                ("server.recovered", "server_observed_recovered"),
            ],
        )
        self.assertTrue(all(item["repo_id"] == self.repo_id for item in events))

    def test_intentional_server_stop_defers_to_authoritative_lifecycle_event(self) -> None:
        self.observe(
            self.server_sample(
                "2026-07-18T12:00:00Z",
                lifecycle="running",
                classification="healthy",
                ok=True,
                pid_alive=True,
                identity={"ok": True, "observable": True},
            )
        )
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (
                        'intentional-server-stop', ?, 'server.stop', 'running',
                        'reserved', 0, 'fixture', 'fixture', ?, ?
                    )
                    """,
                    (
                        self.repo_id,
                        "2026-07-18T12:01:00Z",
                        "2026-07-18T12:01:00Z",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id, action,
                        immutable_fingerprint, phase, status
                    ) VALUES (
                        'intentional-server-stop', 0, 'server', ?, 'stop',
                        'fixture-server', 'host_stop', 'running'
                    )
                    """,
                    (self.server_id,),
                )
                # Match reserve_stop's durable pre-host-effect state.  The
                # observer may prove the stopped boundary before commit_stop
                # records the authoritative lifecycle event.
                connection.execute(
                    """
                    UPDATE server_observations
                    SET lifecycle = 'stopping',
                        health_classification = 'stopping',
                        sampled_at = ?, observation_fingerprint = 'fixture-stopping'
                    WHERE server_definition_id = ?
                    """,
                    ("2026-07-18T12:01:00Z", self.server_id),
                )

        self.observe(
            self.server_sample(
                "2026-07-18T12:02:00Z",
                lifecycle="stopped",
                classification="stopped",
                ok=False,
                pid_alive=False,
                identity={"ok": True},
                stopped_reason="Stopped by coordinator",
            )
        )
        self.assertEqual(
            self.events(), [], "an intentional stop must not be relabeled as a crash"
        )

        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE operations SET status = 'succeeded', phase = 'committed',
                        updated_at = ? WHERE operation_id = 'intentional-server-stop'
                    """,
                    ("2026-07-18T12:02:30Z",),
                )
                connection.execute(
                    """
                    UPDATE operation_targets SET status = 'succeeded',
                        phase = 'committed', finished_at = ?
                    WHERE operation_id = 'intentional-server-stop'
                    """,
                    ("2026-07-18T12:02:30Z",),
                )
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, operation_id, event_kind, code,
                        message, diagnostic_json, occurred_at
                    ) VALUES (
                        'authoritative-server-stop', ?,
                        'intentional-server-stop', 'server.stopped',
                        'server_stopped', 'Stopped by coordinator', '{}', ?
                    )
                    """,
                    (self.repo_id, "2026-07-18T12:02:30Z"),
                )

        self.observe(
            self.server_sample(
                "2026-07-18T12:03:00Z",
                lifecycle="running",
                classification="healthy",
                ok=True,
                pid_alive=True,
                identity={"ok": True, "observable": True},
            )
        )
        self.observe(
            self.server_sample(
                "2026-07-18T12:04:00Z",
                lifecycle="stopped",
                classification="stopped",
                ok=False,
                pid_alive=False,
                identity={"ok": True},
                stopped_reason="process exited",
            )
        )

        events = self.events()
        self.assertEqual(
            [(item["event_kind"], item["code"]) for item in events],
            [
                ("server.stopped", "server_stopped"),
                ("server.started", "server_observed_started"),
                ("server.stopped", "server_crashed"),
            ],
        )
        self.assertEqual(events[0]["operation_id"], "intentional-server-stop")
        self.assertIsNone(events[2]["operation_id"])

    def test_docker_transitions_preserve_unavailable_truth_and_intent(self) -> None:
        self.observe(self.docker_sample("2026-07-18T11:00:00Z", status="Up 1 minute"))
        self.observe(self.docker_sample("2026-07-18T11:01:00Z", status="Up 2 minutes"))
        self.observe(
            self.docker_sample(
                "2026-07-18T11:02:00Z", status=None, available=False
            )
        )
        self.observe(
            self.docker_sample(
                "2026-07-18T11:03:00Z",
                status="Up 3 minutes",
                health=None,
                inspectable=False,
            )
        )
        self.assertEqual(self.events(), [])

        self.observe(
            self.docker_sample(
                "2026-07-18T11:04:00Z",
                status="Up 4 minutes",
                health="unhealthy",
            )
        )
        self.observe(
            self.docker_sample(
                "2026-07-18T11:05:00Z",
                status="Up 5 minutes",
                health="healthy",
            )
        )

        resource_id = None
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                resource_id = str(
                    connection.execute(
                        "SELECT docker_resource_id FROM docker_resources"
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    INSERT INTO operations(
                        operation_id, repo_id, kind, status, phase, generation,
                        request_fingerprint, actor, created_at, updated_at
                    ) VALUES (
                        'intentional-docker-stop', ?, 'broker.docker.stop',
                        'running', 'reserved', 0, 'fixture', 'fixture', ?, ?
                    )
                    """,
                    (
                        self.repo_id,
                        "2026-07-18T11:05:30Z",
                        "2026-07-18T11:05:30Z",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO operation_targets(
                        operation_id, ordinal, target_kind, target_id, action,
                        immutable_fingerprint, phase, status
                    ) VALUES (
                        'intentional-docker-stop', 0, 'container', ?,
                        'docker.stop', 'fixture', 'reserved', 'running'
                    )
                    """,
                    (resource_id,),
                )
        self.observe(
            self.docker_sample(
                "2026-07-18T11:06:00Z",
                status="Exited (0) 1 second ago",
                health=None,
            )
        )
        self.observe(
            self.docker_sample(
                "2026-07-18T11:07:00Z",
                status="Exited (0) 1 minute ago",
                health=None,
            )
        )
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    UPDATE operations SET status = 'succeeded', phase = 'committed',
                        updated_at = ? WHERE operation_id = 'intentional-docker-stop'
                    """,
                    ("2026-07-18T11:07:30Z",),
                )
                connection.execute(
                    """
                    UPDATE operation_targets SET status = 'succeeded',
                        phase = 'committed', finished_at = ?
                    WHERE operation_id = 'intentional-docker-stop'
                    """,
                    ("2026-07-18T11:07:30Z",),
                )
        self.observe(self.docker_sample("2026-07-18T11:08:00Z", status="Up 1 second"))
        self.observe(self.docker_sample("2026-07-18T11:09:00Z", status=None))
        self.observe(self.docker_sample("2026-07-18T11:10:00Z", status=None))

        events = self.events()
        self.assertEqual(
            [(item["event_kind"], item["code"]) for item in events],
            [
                ("docker.failed", "docker_observed_unhealthy"),
                ("docker.recovered", "docker_observed_recovered"),
                ("docker.stopped", "docker_stopped"),
                ("docker.started", "docker_started"),
                ("docker.stopped", "docker_crashed"),
            ],
        )
        self.assertEqual(events[2]["operation_id"], "intentional-docker-stop")
        self.assertTrue(all(item["repo_id"] == self.repo_id for item in events))

    def test_cursor_and_broker_event_read_are_bounded_and_lossless(self) -> None:
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                for index in range(5):
                    connection.execute(
                        """
                        INSERT INTO events(
                            event_id, repo_id, event_kind, code, message,
                            diagnostic_json, occurred_at
                        ) VALUES (?, ?, 'fixture.event', 'fixture', ?, ?, ?)
                        """,
                        (
                            f"event-{index}",
                            self.repo_id,
                            f"message {index}",
                            '{"private":"not-for-feed"}',
                            f"2026-07-18T12:00:0{index}Z",
                        ),
                    )
        cursors: list[str] = []
        seen: list[str] = []
        after = None
        with AccountStore.open_default_read_only(self.home) as store:
            with store.read_transaction() as connection:
                while True:
                    page = list_event_page(connection, after=after, limit=2)
                    seen.extend(item["event_id"] for item in page["events"])
                    self.assertTrue(
                        all("diagnostic_json" not in item for item in page["events"])
                    )
                    after = page["next_cursor"]
                    if after is not None:
                        cursors.append(after)
                    if not page["has_more"]:
                        break
        self.assertEqual(seen, [f"event-{index}" for index in range(5)])
        self.assertEqual(decode_event_cursor(cursors[-1])[1], "event-4")
        with self.assertRaisesRegex(ValueError, "cursor"):
            decode_event_cursor("not-a-cursor")

        # A slow operation can commit after the consumer checkpoint with an
        # earlier occurred_at. The cursor follows durable insertion sequence,
        # so that late record remains visible instead of falling behind a
        # timestamp high-watermark.
        with AccountStore.open_default(self.home) as store:
            with store.immediate_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, repo_id, event_kind, code, message, occurred_at
                    ) VALUES (
                        'event-late', ?, 'fixture.event', 'fixture',
                        'late commit', '2026-07-18T09:00:00Z'
                    )
                    """,
                    (self.repo_id,),
                )
        with AccountStore.open_default_read_only(self.home) as store:
            with store.read_transaction() as connection:
                late_page = list_event_page(
                    connection, after=cursors[-1], limit=2
                )
        self.assertEqual(
            [item["event_id"] for item in late_page["events"]], ["event-late"]
        )

        persistence = BrokerPersistence(
            self.home / "coordinator.sqlite3", expected_uid=os.geteuid()
        )
        persistence.provision_principal(uid=os.geteuid(), account_id="events-account")
        persistence.provision_repository_enrollment(
            uid=os.geteuid(),
            repo_id=self.repo_id,
            account_id="events-account",
            issued_at="2026-07-18T12:05:00Z",
            valid_until_epoch=4_102_444_800,
        )
        with AccountStore.open_default_read_only(self.home) as store:
            generation = store.metadata.database_generation
        service = BrokerService(
            StoreBackedAuthorizer(persistence),
            SerializedMutationWriter(
                StoreBackedMutationBackend(persistence, mock.Mock())
            ),
        )
        request = BrokerRequest.create(
            account_id="events-account",
            project_id=self.repo_id,
            resource_id=self.repo_id,
            operation=BrokerOperation.EVENTS_READ,
            arguments={"limit": 3},
            authority_generation=generation,
        )
        reply = service.reply_for_document(
            PeerCredentials(uid=os.geteuid(), gid=os.getegid(), pid=os.getpid()),
            request.to_wire(),
        )
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(
            [item["event_id"] for item in reply["result"]["events"]],
            ["event-0", "event-1", "event-2"],
        )
        self.assertNotIn("diagnostic_json", reply["result"]["events"][0])

    def test_http_route_shapes_are_strict(self) -> None:
        self.assertIn("/v1/events", dev_coordinator.API_GET_ROUTES)
        self.assertIn("/v1/observe", dev_coordinator.API_POST_ROUTES)
        self.assertEqual(
            dev_coordinator.parse_event_query("limit=25"),
            {"after": None, "limit": 25},
        )
        with self.assertRaisesRegex(ValueError, "limit"):
            dev_coordinator.parse_event_query("limit=501")
        with self.assertRaises(ValueError):
            dev_coordinator.parse_event_query("project=repo-events")


if __name__ == "__main__":
    unittest.main()
