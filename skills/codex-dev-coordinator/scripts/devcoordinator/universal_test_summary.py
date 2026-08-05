"""Bounded progressive-disclosure summaries for coding agents."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import Mapping, Sequence

from .universal_test_planner import SourceIdentity


MAX_AGENT_SUMMARY_BYTES = 8 * 1024
MIN_AGENT_SUMMARY_BYTES = 768


class AgentSummaryError(ValueError):
    """Agent-facing run information cannot be represented safely."""


@dataclass(frozen=True)
class FailureSummary:
    target: str
    message: str
    location: str | None = None
    artifact_id: str | None = None


@dataclass(frozen=True)
class ArtifactSummary:
    artifact_id: str
    kind: str
    target: str | None = None


@dataclass(frozen=True)
class AgentRunSummary:
    run_id: str
    conclusion: str
    intent: str
    source: SourceIdentity
    selected_targets: Sequence[str]
    selection_reasons: Mapping[str, Sequence[str]]
    progress: Mapping[str, int | float]
    counts: Mapping[str, int]
    timing: Mapping[str, int | float | None]
    failures: Sequence[FailureSummary]
    artifacts: Sequence[ArtifactSummary]
    detail_command: str


def _text(value: object, *, maximum: int) -> str:
    if not isinstance(value, str):
        value = str(value)
    normalized = " ".join(value.replace("\x00", "").split())
    if len(normalized) <= maximum:
        return normalized
    if maximum <= 1:
        return normalized[:maximum]
    return normalized[: maximum - 1] + "…"


def _finite_number(value: object, *, field: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgentSummaryError(f"{field} must be numeric or null")
    if isinstance(value, float) and not math.isfinite(value):
        raise AgentSummaryError(f"{field} must be finite")
    return value


def _encode(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _document(
    summary: AgentRunSummary,
    *,
    text_limit: int,
    target_limit: int,
    reason_limit: int,
    artifact_limit: int,
) -> dict[str, object]:
    selected = sorted({_text(item, maximum=128) for item in summary.selected_targets})
    visible_targets = selected[:target_limit]
    selection: dict[str, list[str]] = {}
    for target in visible_targets:
        raw_reasons = summary.selection_reasons.get(target, ())
        selection[target] = [
            _text(reason, maximum=min(text_limit, 256))
            for reason in list(raw_reasons)[:reason_limit]
        ]
    failures = [
        {
            "target": _text(failure.target, maximum=128),
            "message": _text(failure.message, maximum=text_limit),
            "location": (
                _text(failure.location, maximum=min(text_limit, 512))
                if failure.location
                else None
            ),
            "artifact_id": (
                _text(failure.artifact_id, maximum=160)
                if failure.artifact_id
                else None
            ),
        }
        for failure in list(summary.failures)[:3]
    ]
    artifacts = [
        {
            "artifact_id": _text(artifact.artifact_id, maximum=160),
            "kind": _text(artifact.kind, maximum=64),
            "target": _text(artifact.target, maximum=128) if artifact.target else None,
        }
        for artifact in list(summary.artifacts)[:artifact_limit]
    ]
    progress = {
        _text(key, maximum=64): _finite_number(value, field=f"progress.{key}")
        for key, value in sorted(summary.progress.items())[:16]
    }
    counts: dict[str, int] = {}
    for key, value in sorted(summary.counts.items())[:32]:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AgentSummaryError(f"counts.{key} must be a non-negative integer")
        counts[_text(key, maximum=64)] = value
    timing = {
        _text(key, maximum=64): _finite_number(value, field=f"timing.{key}")
        for key, value in sorted(summary.timing.items())[:16]
    }
    source = {
        "mode": summary.source.mode.value,
        "repository_id": _text(summary.source.repository_id, maximum=256),
        "content_fingerprint": summary.source.content_fingerprint,
        "snapshot_id": (
            _text(summary.source.snapshot_id, maximum=256)
            if summary.source.snapshot_id
            else None
        ),
    }
    return {
        "schema_version": 1,
        "run_id": _text(summary.run_id, maximum=160),
        "conclusion": _text(summary.conclusion, maximum=64),
        "intent": _text(summary.intent, maximum=64),
        "source": source,
        "selection": {
            "selected_target_count": len(selected),
            "targets": selection,
            "truncated": len(selected) > len(visible_targets),
        },
        "progress": progress,
        "counts": counts,
        "timing": timing,
        "failures": failures,
        "failure_count": len(summary.failures),
        "artifacts": artifacts,
        "artifact_count": len(summary.artifacts),
        "next": _text(summary.detail_command, maximum=min(text_limit, 512)),
    }


def compact_agent_summary(
    summary: AgentRunSummary, *, max_bytes: int = MAX_AGENT_SUMMARY_BYTES
) -> dict[str, object]:
    """Return a deterministic summary no larger than eight KiB when encoded.

    At most three failures are exposed.  Larger selections and artifact lists
    are summarized with exact counts; the returned ``next`` command is the
    progressive-disclosure path to complete evidence.
    """

    if not isinstance(summary, AgentRunSummary):
        raise AgentSummaryError("summary must be AgentRunSummary")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise AgentSummaryError("max_bytes must be an integer")
    limit = min(max_bytes, MAX_AGENT_SUMMARY_BYTES)
    if limit < MIN_AGENT_SUMMARY_BYTES:
        raise AgentSummaryError(
            f"max_bytes must be at least {MIN_AGENT_SUMMARY_BYTES}"
        )
    strategies = (
        (1024, 32, 3, 16),
        (512, 24, 2, 12),
        (256, 16, 2, 8),
        (160, 12, 1, 4),
        (96, 8, 1, 2),
        (64, 4, 1, 1),
    )
    for text_limit, target_limit, reason_limit, artifact_limit in strategies:
        document = _document(
            summary,
            text_limit=text_limit,
            target_limit=target_limit,
            reason_limit=reason_limit,
            artifact_limit=artifact_limit,
        )
        if len(_encode(document)) <= limit:
            return document
    raise AgentSummaryError(
        "summary identifiers and mandatory fields exceed the requested byte limit"
    )


def agent_summary_json(
    summary: AgentRunSummary, *, max_bytes: int = MAX_AGENT_SUMMARY_BYTES
) -> str:
    """Encode :func:`compact_agent_summary` as stable compact JSON."""

    document = compact_agent_summary(summary, max_bytes=max_bytes)
    encoded = _encode(document)
    if len(encoded) > min(max_bytes, MAX_AGENT_SUMMARY_BYTES):
        raise AssertionError("agent summary byte bound was violated")
    return encoded.decode("utf-8")


__all__ = [
    "AgentRunSummary",
    "AgentSummaryError",
    "ArtifactSummary",
    "FailureSummary",
    "MAX_AGENT_SUMMARY_BYTES",
    "agent_summary_json",
    "compact_agent_summary",
]
