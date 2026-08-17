#!/usr/bin/env python3
"""Deterministic retained-inventory projection and failover tests."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/codex-dev-coordinator/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from devcoordinator.inventory_projection import (  # noqa: E402
    InventoryProjectionError,
    empty_inventory,
    envelope,
    initialize_inventory_store,
    publish_retained_inventory,
    publish_projection,
    read_inventory_store,
    read_projection,
    verify_inventory_store,
)
from devcoordinator import inventory_projection as INVENTORY_STORE  # noqa: E402
import dev_coordinator as COORDINATOR  # noqa: E402


OBSERVER_SPEC = importlib.util.spec_from_file_location(
    "devcoordinator_observer_self_test", ROOT / "scripts/devcoordinator_observer.py"
)
if OBSERVER_SPEC is None or OBSERVER_SPEC.loader is None:
    raise RuntimeError("cannot import retained inventory observer")
OBSERVER = importlib.util.module_from_spec(OBSERVER_SPEC)
OBSERVER_SPEC.loader.exec_module(OBSERVER)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def must_fail(operation, label: str) -> None:
    try:
        operation()
    except (InventoryProjectionError, OSError, ValueError, json.JSONDecodeError):
        return
    raise AssertionError(f"unsafe retained inventory was accepted: {label}")


def inventory_with_server(server_id: str) -> dict:
    value = empty_inventory()
    value.update(
        {
            "schema_version": 2,
            "projection_status": "retained",
            "servers": [{"id": server_id, "status": "running"}],
            "repositories": [
                {
                    "repo_id": "repo-1",
                    "host_id": "host-1",
                    "canonical_root": "/repo",
                    "display_name": "repo",
                }
            ],
            "repository_trees": [
                {
                    "family_id": "family-1",
                    "root_repository": {
                        "repo_id": "repo-1",
                        "canonical_root": "/repo",
                        "display_name": "repo",
                    },
                    "usage": {},
                    "scopes": [
                        {
                            "repo_id": "repo-1",
                            "kind": "root",
                            "canonical_root": "/repo",
                            "display_name": "repo",
                            "usage": {},
                            "server_ids": [server_id],
                            "container_resource_ids": [],
                            "database_binding_ids": [],
                        }
                    ],
                }
            ],
        }
    )
    value["resources"]["servers"] = [
        {"server_definition_id": server_id, "repo_id": "repo-1"}
    ]
    value["v1_compatibility"] = {
        "coordinator_home": "/state",
        "state_path": "/state/authority.sqlite3",
        "project": None,
        "urls": [],
        "servers": value["servers"],
        "leases": [],
        "port_assignments": [],
        "recent_events": [],
        "docker": value["docker"],
        "postgres": [],
        "backups": [],
        "project_usage": [],
    }
    return value


def inventory_with_unassigned_database(*, include_database_problem: bool) -> dict:
    value = empty_inventory()
    container_id = "container-unassigned-1"
    binding_id = "database-unassigned-1"
    value.update(
        {
            "schema_version": 2,
            "projection_status": "retained",
            "servers": [],
            "repositories": [],
            "repository_trees": [],
            "unassigned_resources": [
                {
                    "resource_kind": "container",
                    "resource_id": container_id,
                    "display_name": "orphan-postgres",
                    "reason_code": "missing_repo",
                }
            ],
        }
    )
    if include_database_problem:
        value["unassigned_resources"].append(
            {
                "resource_kind": "database",
                "resource_id": binding_id,
                "display_name": "app",
                "reason_code": "missing_repo",
                "parent_resource_id": container_id,
            }
        )
    value["resources"].update(
        {
            "docker": [
                {
                    "docker_resource_id": container_id,
                    "engine_id": "engine-1",
                    "full_container_id": "a" * 64,
                    "current_name": "orphan-postgres",
                }
            ],
            "databases": [
                {
                    "database_binding_id": binding_id,
                    "docker_resource_id": container_id,
                    "repo_id": None,
                    "database_name": "app",
                    "engine_kind": "postgresql",
                }
            ],
        }
    )
    value["observations"].update(
        {
            "docker": [
                {"docker_resource_id": container_id, "lifecycle": "running"}
            ],
            "databases": [
                {
                    "database_binding_id": binding_id,
                    "docker_resource_id": container_id,
                    "available": 1,
                }
            ],
        }
    )
    value["v1_compatibility"] = {
        "coordinator_home": "/state",
        "state_path": "/state/authority.sqlite3",
        "project": None,
        "urls": [],
        "servers": [],
        "leases": [],
        "port_assignments": [],
        "recent_events": [],
        "docker": value["docker"],
        "postgres": [],
        "backups": [],
        "project_usage": [],
    }
    return value


def main() -> int:
    complete_unassigned = inventory_with_unassigned_database(
        include_database_problem=True
    )
    envelope(
        generation=1,
        inventory=complete_unassigned,
        published_at="2026-07-28T00:00:00.000Z",
    )
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=inventory_with_unassigned_database(
                include_database_problem=False
            ),
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "current database observation omitted from both tree and explicit ownership problems",
    )
    wrong_repository = inventory_with_server("wrong-repository-server")
    wrong_repository["resources"]["servers"][0]["repo_id"] = "repo-other"
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=wrong_repository,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "tree server assigned to the wrong repository",
    )

    # A predecessor release could retain a checksummed schema-3 generation
    # whose repository association disagrees with its tree.  Reads must admit
    # that one transition source so the observer can replace it, while every
    # new publication remains strict.
    with tempfile.TemporaryDirectory(prefix="inventory-association-upgrade-") as raw:
        root = Path(raw)
        database = root / "inventory.sqlite3"
        publication = root / "inventory.publication"
        valid_first = envelope(
            generation=1,
            inventory=inventory_with_server("legacy-server"),
            published_at="2026-07-28T00:00:00.000Z",
        )
        initialize_inventory_store(
            database,
            valid_first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        legacy_inventory = inventory_with_server("legacy-server")
        legacy_inventory["schema_version"] = 3
        legacy_inventory["resources"]["servers"][0]["repo_id"] = "repo-old"
        legacy_payload = {
            "schema_version": valid_first["schema_version"],
            "generation": 1,
            "published_at": valid_first["published_at"],
            "inventory": legacy_inventory,
        }
        legacy = {
            **legacy_payload,
            "payload_sha256": INVENTORY_STORE._digest(legacy_payload),
        }
        encoded = INVENTORY_STORE._canonical(legacy)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE inventory_publications "
                "SET payload_sha256 = ?, envelope_json = ?, logical_bytes = ? "
                "WHERE generation = 1",
                (legacy["payload_sha256"], encoded, len(encoded)),
            )
            connection.commit()
        publication.write_text(
            json.dumps(legacy, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        publication.chmod(0o644)
        expect(
            verify_inventory_store(
                database,
                publication,
                expected_owner_uid=os.geteuid(),
            )["generation"]
            == 1,
            "legacy association generation was not admitted for transition",
        )
        must_fail(
            lambda: publish_projection(
                publication,
                legacy,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
            ),
            "new publication with a legacy repository association",
        )
        current = envelope(
            generation=2,
            inventory=inventory_with_server("current-server"),
            published_at="2026-07-28T00:00:01.000Z",
        )
        publish_retained_inventory(
            database=database,
            publication=publication,
            value=current,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(
            verify_inventory_store(
                database,
                publication,
                expected_owner_uid=os.geteuid(),
            )["generation"]
            == 2,
            "strict current inventory did not replace the legacy association",
        )
    duplicate_claim = inventory_with_server("duplicate-server")
    duplicate_claim["repository_trees"][0]["scopes"][0]["server_ids"].append(
        "duplicate-server"
    )
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=duplicate_claim,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "duplicate tree resource claim",
    )
    duplicate_problem = inventory_with_unassigned_database(
        include_database_problem=True
    )
    duplicate_problem["unassigned_resources"].append(
        dict(duplicate_problem["unassigned_resources"][1])
    )
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=duplicate_problem,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "duplicate ownership problem inside unassigned_resources",
    )
    cross_list_duplicate = inventory_with_unassigned_database(
        include_database_problem=True
    )
    cross_list_duplicate["lifecycle_violations"].append(
        {
            **cross_list_duplicate["unassigned_resources"][1],
            "lifecycle_violation": True,
        }
    )
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=cross_list_duplicate,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "same ownership problem duplicated across unassigned and lifecycle lists",
    )
    assigned_parent = inventory_with_unassigned_database(
        include_database_problem=True
    )
    assigned_parent["repositories"] = [
        {
            "repo_id": "repo-1",
            "host_id": "host-1",
            "canonical_root": "/repo",
            "display_name": "repo",
        }
    ]
    assigned_parent["repository_trees"] = [
        {
            "family_id": "family-1",
            "root_repository": {
                "repo_id": "repo-1",
                "canonical_root": "/repo",
                "display_name": "repo",
            },
            "scopes": [
                {
                    "repo_id": "repo-1",
                    "kind": "root",
                    "canonical_root": "/repo",
                    "display_name": "repo",
                    "server_ids": [],
                    "container_resource_ids": ["container-unassigned-1"],
                    "database_binding_ids": [],
                }
            ],
        }
    ]
    assigned_parent["resources"]["databases"][0]["repo_id"] = "repo-1"
    assigned_parent["unassigned_resources"] = [
        item
        for item in assigned_parent["unassigned_resources"]
        if item["resource_kind"] == "database"
    ]
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=assigned_parent,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "database problem detached from an otherwise assigned parent container",
    )
    unknown_problem = inventory_with_unassigned_database(
        include_database_problem=True
    )
    unknown_problem["unassigned_resources"].append(
        {
            "resource_kind": "unknown",
            "resource_id": "unknown-1",
            "display_name": "unknown",
            "reason_code": "ambiguous_control",
        }
    )
    must_fail(
        lambda: envelope(
            generation=1,
            inventory=unknown_problem,
            published_at="2026-07-28T00:00:00.000Z",
        ),
        "ownership problem with an unknown normalized resource kind",
    )

    with tempfile.TemporaryDirectory(prefix="inventory-projection-test-") as raw:
        root = Path(raw)
        root.chmod(0o700)
        database = root / "inventory.sqlite3"
        publication = root / "inventory.publication"
        first = envelope(
            generation=1,
            inventory=empty_inventory(),
            published_at="2026-07-28T00:00:00.000Z",
        )
        initialize_inventory_store(
            database,
            first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        publish_projection(
            publication,
            first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        loaded = read_projection(publication, expected_owner_uid=os.geteuid())
        expect(loaded == first, "initialized retained projection changed")
        initial_inventory = loaded["inventory"]
        expect(
            initial_inventory["repository_trees"] == []
            and initial_inventory["resources"] == {
                "servers": [], "docker": [], "docker_ports": [], "databases": []
            }
            and initial_inventory["observations"]["docker"] == []
            and initial_inventory["observations"]["databases"] == [],
            "initialized retained projection is not a valid empty authoritative graph",
        )
        expect(
            stat.S_IMODE(publication.stat().st_mode) == 0o644,
            "retained projection is not trusted-local readable and non-writable",
        )

        race_publication = root / "race.publication"
        race_successor = root / "race-successor.publication"
        successor = envelope(
            generation=2,
            inventory=inventory_with_server("server-race-successor"),
            published_at="2026-07-28T00:00:02.000Z",
        )
        publish_projection(
            race_publication,
            first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        publish_projection(
            race_successor,
            successor,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        original_read = INVENTORY_STORE.os.read
        replaced_during_read = False

        def replace_publication_before_read(descriptor, count):
            nonlocal replaced_during_read
            if not replaced_during_read:
                replaced_during_read = True
                os.replace(race_successor, race_publication)
            return original_read(descriptor, count)

        with mock.patch.object(
            INVENTORY_STORE.os,
            "read",
            side_effect=replace_publication_before_read,
        ):
            race_loaded = read_projection(
                race_publication,
                expected_owner_uid=os.geteuid(),
            )
        expect(
            race_loaded == first,
            "atomic replacement invalidated the complete descriptor-anchored generation",
        )
        expect(
            read_projection(race_publication, expected_owner_uid=os.geteuid())
            == successor,
            "atomic replacement did not publish the successor generation",
        )

        tamper_publication = root / "tamper-during-read.publication"
        publish_projection(
            tamper_publication,
            first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        tamper_bytes = tamper_publication.read_bytes()
        tampered_during_read = False

        def truncate_open_publication(descriptor, count):
            nonlocal tampered_during_read
            if not tampered_during_read:
                tampered_during_read = True
                tamper_publication.write_bytes(tamper_bytes[:-1])
            return original_read(descriptor, count)

        with mock.patch.object(
            INVENTORY_STORE.os,
            "read",
            side_effect=truncate_open_publication,
        ):
            must_fail(
                lambda: read_projection(
                    tamper_publication,
                    expected_owner_uid=os.geteuid(),
                ),
                "opened publication mutated in place during its read",
            )

        calls: list[tuple[str, dict | None]] = []
        original_api_json = OBSERVER.api_json

        def successful_api(_base, endpoint, *, payload=None, timeout=0):
            calls.append((endpoint, payload))
            if endpoint == "/v1/observe":
                return {"ok": True}
            return inventory_with_server("server-1")

        args = argparse.Namespace(
            api_url="http://127.0.0.1:29876",
            project="/repo",
            database=database,
            publication=publication,
            request_timeout_seconds=1.0,
        )
        try:
            OBSERVER.api_json = successful_api
            with mock.patch.object(
                OBSERVER,
                "verify_inventory_store",
                wraps=OBSERVER.verify_inventory_store,
            ) as hot_path_verify:
                second = OBSERVER.refresh_once(
                    args,
                    loaded,
                    group_id=os.getegid(),
                )
            expect(
                hot_path_verify.call_args.kwargs.get("integrity_check") is False,
                "observer refresh performed a full SQLite integrity scan",
            )
            expect(second["generation"] == 2, "observer did not advance generation")
            stored_second = verify_inventory_store(
                database,
                publication,
                expected_owner_uid=os.geteuid(),
            )
            expect(
                stored_second["generation"] == 2,
                "observer did not activate the retained store generation",
            )
            expect(
                calls == [
                    ("/v1/inventory/source", None),
                    ("/v1/observe", {"agent": "devcoordinator-observer", "project": "/repo"}),
                    ("/v1/inventory/source", None),
                ],
                "observer did not publish authority state before bounded observation",
            )
            before_failure = publication.read_bytes()

            def malformed_api(_base, endpoint, *, payload=None, timeout=0):
                if endpoint == "/v1/observe":
                    return {"ok": True}
                value = inventory_with_server("server-malformed")
                value.pop("repository_trees")
                return value

            OBSERVER.api_json = malformed_api
            must_fail(
                lambda: OBSERVER.refresh_once(
                    args,
                    second,
                    group_id=os.getegid(),
                ),
                "source inventory without an authoritative repository tree",
            )
            expect(
                publication.read_bytes() == before_failure,
                "malformed source inventory replaced the last-known-good generation",
            )

            def incomplete_database_api(_base, endpoint, *, payload=None, timeout=0):
                if endpoint == "/v1/observe":
                    return {"ok": True}
                return inventory_with_unassigned_database(
                    include_database_problem=False
                )

            OBSERVER.api_json = incomplete_database_api
            must_fail(
                lambda: OBSERVER.refresh_once(
                    args,
                    second,
                    group_id=os.getegid(),
                ),
                "source inventory with an uncovered current database binding",
            )
            expect(
                publication.read_bytes() == before_failure,
                "uncovered database binding replaced the last-known-good generation",
            )

            def failed_api(_base, endpoint, *, payload=None, timeout=0):
                if endpoint == "/v1/observe":
                    return {"ok": True}
                raise InventoryProjectionError("source unavailable")

            OBSERVER.api_json = failed_api
            must_fail(
                lambda: OBSERVER.refresh_once(
                    args,
                    second,
                    group_id=os.getegid(),
                ),
                "failed source refresh",
            )
            expect(
                publication.read_bytes() == before_failure,
                "failed observer refresh replaced the last-known-good generation",
            )

            def unavailable_observation(_base, endpoint, *, payload=None, timeout=0):
                if endpoint == "/v1/observe":
                    raise InventoryProjectionError("host sampling unavailable")
                return inventory_with_server("server-authority-only")

            OBSERVER.api_json = unavailable_observation
            authority_only = OBSERVER.refresh_once(
                args,
                second,
                group_id=os.getegid(),
            )
            expect(
                authority_only["generation"] == 3
                and authority_only["inventory"]["repository_trees"],
                "host sampling failure prevented authoritative repository publication",
            )
        finally:
            OBSERVER.api_json = original_api_json

        fourth = envelope(
            generation=4,
            inventory=inventory_with_server("server-4"),
            published_at="2026-07-28T00:00:04.000Z",
        )
        before_capacity = database.read_bytes()
        before_publication = publication.read_bytes()
        must_fail(
            lambda: publish_retained_inventory(
                database=database,
                publication=publication,
                value=fourth,
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
                capacity_probe=lambda _path: 0,
            ),
            "retained store capacity exhaustion",
        )
        expect(database.read_bytes() == before_capacity, "capacity failure changed store")
        expect(
            publication.read_bytes() == before_publication,
            "capacity failure changed publication",
        )

        with mock.patch.object(
            INVENTORY_STORE,
            "_activate_inventory_generation",
            side_effect=RuntimeError("simulated activation interruption"),
        ):
            try:
                publish_retained_inventory(
                    database=database,
                    publication=publication,
                    value=fourth,
                    owner_uid=os.geteuid(),
                    owner_gid=os.getegid(),
                )
            except RuntimeError:
                pass
            else:
                raise AssertionError("inventory activation interruption was not injected")
        recovered = verify_inventory_store(
            database,
            publication,
            expected_owner_uid=os.geteuid(),
        )
        expect(recovered["generation"] == 4, "pending publication was not recovered")

        original_limit = INVENTORY_STORE.MAX_RETAINED_GENERATIONS
        INVENTORY_STORE.MAX_RETAINED_GENERATIONS = 3
        try:
            for generation in range(5, 11):
                value = envelope(
                    generation=generation,
                    inventory=inventory_with_server(f"server-{generation}"),
                    published_at=f"2026-07-28T00:00:{generation:02d}.000Z",
                )
                publish_retained_inventory(
                    database=database,
                    publication=publication,
                    value=value,
                    owner_uid=os.geteuid(),
                    owner_gid=os.getegid(),
                )
            bounded = read_inventory_store(database, expected_owner_uid=os.geteuid())
            expect(
                bounded["retained_generations"] == 3,
                "inventory generation retention exceeded its configured cap",
            )
            INVENTORY_STORE.MAX_RETAINED_GENERATIONS = 2
            repaired = verify_inventory_store(
                database,
                publication,
                expected_owner_uid=os.geteuid(),
            )
            expect(
                repaired["retained_generations"] == 2,
                "startup verification did not repair excessive retained generations",
            )
        finally:
            INVENTORY_STORE.MAX_RETAINED_GENERATIONS = original_limit

        old_publication = os.environ.get("DEVCOORDINATOR_INVENTORY_PUBLICATION")
        original_builder = COORDINATOR.coordinated_build_inventory
        try:
            os.environ["DEVCOORDINATOR_INVENTORY_PUBLICATION"] = str(publication)

            def forbidden_live_inventory(*_args, **_kwargs):
                raise AssertionError("ordinary inventory read sampled live authority state")

            COORDINATOR.coordinated_build_inventory = forbidden_live_inventory
            retained = COORDINATOR.coordinated_retained_inventory()
            expect(
                retained["retained_projection"]["generation"] == 10,
                "API did not return the retained observer generation",
            )
            expect(
                retained["servers"][0]["id"] == "server-10",
                "API retained inventory did not preserve producer data",
            )
        finally:
            COORDINATOR.coordinated_build_inventory = original_builder
            if old_publication is None:
                os.environ.pop("DEVCOORDINATOR_INVENTORY_PUBLICATION", None)
            else:
                os.environ["DEVCOORDINATOR_INVENTORY_PUBLICATION"] = old_publication

        document = json.loads(publication.read_text(encoding="utf-8"))
        document["inventory"]["servers"][0]["status"] = "stopped"
        publication.write_text(json.dumps(document), encoding="utf-8")
        publication.chmod(0o644)
        must_fail(lambda: read_projection(publication), "checksum mutation")

        foreign = root / "foreign.publication"
        foreign.write_text("{}", encoding="utf-8")
        foreign.chmod(0o600)
        link = root / "link.publication"
        link.symlink_to(foreign)
        must_fail(lambda: read_projection(link), "publication symlink")

        replaceable = root / "replaceable"
        replaceable.mkdir(mode=0o770)
        replaceable.chmod(0o770)
        shared = replaceable / "inventory.publication"
        publish_projection(
            shared,
            first,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
        )
        expect(
            read_projection(shared)["generation"] == first["generation"],
            "shared publication path did not preserve the retained projection",
        )

    print("retained inventory projection self-test ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
