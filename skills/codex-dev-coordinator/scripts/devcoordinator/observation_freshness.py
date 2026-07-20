"""Exact per-call freshness fences for service-owned host observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


FULL_DOCKER_OBSERVER_DOMAIN = "host-runtime-v2:full-docker"


class ObservationFreshnessError(RuntimeError):
    """Returned observation evidence was not created or joined by this call."""


class ObservationStore(Protocol):
    @property
    def metadata(self) -> Any: ...

    def read_transaction(self): ...


@dataclass(frozen=True)
class ObservationFreshnessFence:
    host_id: str
    observer_domain: str
    before_revision: int
    maximum_snapshot_rowid: int
    joinable_snapshot_ids: frozenset[str]


def capture_observation_freshness_fence(
    store: ObservationStore,
    *,
    host_id: str,
    observer_domain: str = FULL_DOCKER_OBSERVER_DOMAIN,
) -> ObservationFreshnessFence:
    """Capture tickets eligible to satisfy one imminent observation call.

    Observation snapshots are append-only evidence.  A satisfying ticket must
    either be the exact in-flight ticket visible at this boundary or a row
    inserted after the boundary.  A global revision increment alone is not a
    freshness proof because an unrelated observer may increment it.
    """

    before_revision = int(store.metadata.observation_revision)
    with store.read_transaction() as connection:
        maximum = connection.execute(
            "SELECT COALESCE(MAX(rowid), 0) FROM observation_snapshots"
        ).fetchone()
        joinable = frozenset(
            str(row["snapshot_id"])
            for row in connection.execute(
                """
                SELECT snapshot_id
                FROM observation_snapshots
                WHERE host_id = ? AND observer_domain = ? AND status = 'running'
                """,
                (host_id, observer_domain),
            )
        )
    return ObservationFreshnessFence(
        host_id=host_id,
        observer_domain=observer_domain,
        before_revision=before_revision,
        maximum_snapshot_rowid=int(maximum[0] if maximum is not None else 0),
        joinable_snapshot_ids=joinable,
    )


def require_exact_fresh_observation(
    store: ObservationStore,
    *,
    evidence: Mapping[str, Any] | None,
    fence: ObservationFreshnessFence,
    allow_joined_ticket: bool = True,
) -> dict[str, Any]:
    """Return bounded committed evidence only for this call's exact ticket."""

    if not isinstance(evidence, Mapping) or not evidence.get("snapshot_id"):
        raise ObservationFreshnessError(
            "observation did not return exact committed snapshot evidence"
        )
    snapshot_id = str(evidence["snapshot_id"])
    with store.read_transaction() as connection:
        committed = connection.execute(
            """
            SELECT snapshot.rowid AS snapshot_rowid,
                   snapshot.host_id, snapshot.observer_domain, snapshot.status,
                   snapshot.material_fingerprint, snapshot.started_at,
                   snapshot.completed_at,
                   capability.observer_domain AS capability_domain,
                   capability.docker_available,
                   capability.capability_fingerprint
            FROM observation_snapshots snapshot
            JOIN observation_capabilities capability USING(snapshot_id)
            WHERE snapshot.snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()
    after_revision = int(store.metadata.observation_revision)
    ticket_is_fresh = committed is not None and (
        (
            allow_joined_ticket
            and snapshot_id in fence.joinable_snapshot_ids
        )
        or int(committed["snapshot_rowid"]) > fence.maximum_snapshot_rowid
    )
    if (
        evidence.get("observer_domain") != fence.observer_domain
        or evidence.get("docker_available") is not True
        or not evidence.get("completed_at")
        or not isinstance(evidence.get("capability_fingerprint"), str)
        or not isinstance(evidence.get("material_fingerprint"), str)
        or after_revision <= fence.before_revision
        or not ticket_is_fresh
        or committed is None
        or str(committed["host_id"]) != fence.host_id
        or str(committed["observer_domain"]) != fence.observer_domain
        or str(committed["capability_domain"]) != fence.observer_domain
        or str(committed["status"]) != "completed"
        or bool(committed["docker_available"]) is not True
        or committed["capability_fingerprint"]
        != evidence.get("capability_fingerprint")
        or committed["material_fingerprint"]
        != evidence.get("material_fingerprint")
        or committed["completed_at"] != evidence.get("completed_at")
    ):
        raise ObservationFreshnessError(
            "observation did not commit the exact fresh full-Docker ticket"
        )
    return {
        "snapshot_id": snapshot_id,
        "observer_domain": str(committed["observer_domain"]),
        "docker_available": True,
        "capability_fingerprint": str(committed["capability_fingerprint"]),
        "material_fingerprint": str(committed["material_fingerprint"]),
        "started_at": str(committed["started_at"]),
        "completed_at": str(committed["completed_at"]),
        "observation_revision": after_revision,
    }
