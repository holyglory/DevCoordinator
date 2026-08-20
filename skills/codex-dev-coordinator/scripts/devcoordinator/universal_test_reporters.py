"""Driver-neutral reporter dispatch for normalized test results."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .universal_test_store import TestStoreContractError


ReporterResult = tuple[list[dict[str, object]], list[dict[str, object]]]
ReporterParser = Callable[..., ReporterResult]


class ReporterDrivers:
    """Exact reporter-kind registry used by the trusted runner."""

    def __init__(self, parsers: Mapping[str, ReporterParser]) -> None:
        if set(parsers) != {"jsonl", "junit", "trx"} or any(
            not callable(parser) for parser in parsers.values()
        ):
            raise TestStoreContractError("reporter driver registry is incomplete")
        self._parsers = dict(parsers)

    def parse(
        self,
        kind: str,
        path: Path,
        *,
        artifact_id: str | None = None,
        case_namespace: str | None = None,
    ) -> ReporterResult:
        parser = self._parsers.get(kind)
        if parser is None:
            raise TestStoreContractError("reporter driver is unsupported")
        if kind == "trx":
            return parser(
                path,
                artifact_id=artifact_id,
                case_namespace=case_namespace,
            )
        if artifact_id is not None or case_namespace is not None:
            raise TestStoreContractError(
                "only the TRX reporter accepts artifact identity context"
            )
        return parser(path)


__all__ = ["ReporterDrivers", "ReporterParser", "ReporterResult"]
