"""One canonical actor contract for governed test mutations."""

from __future__ import annotations

import os
import re
from typing import Literal, Mapping


ActorNamespace = Literal["codex", "google"]
_GOOGLE_ACTOR = re.compile(
    r"^google:[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$"
)
_CODEX_ACTOR = re.compile(
    r"^codex:(?:uid:[0-9]{1,20}|[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191})$"
)


class TestActorContractError(ValueError):
    """The supplied actor is outside the current governed-test contract."""


def canonical_test_actor(value: object) -> tuple[ActorNamespace, str]:
    """Validate one exact actor without normalization or namespace fallback."""

    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or any(character in value for character in "\x00\r\n")
    ):
        raise TestActorContractError("test actor is not one bounded line")
    if _CODEX_ACTOR.fullmatch(value) is not None:
        return "codex", value
    if _GOOGLE_ACTOR.fullmatch(value) is not None:
        return "google", value
    raise TestActorContractError("test actor is not canonical")


def codex_test_actor(*, identity: str | None, uid: int) -> str:
    """Build the sole local-agent actor form used by the stable client."""

    candidate = f"codex:uid:{uid}" if identity is None else f"codex:{identity}"
    namespace, canonical = canonical_test_actor(candidate)
    if namespace != "codex":  # defensive: the producer always adds codex:
        raise TestActorContractError("local test actor namespace is invalid")
    return canonical


def calling_codex_test_actor(
    *,
    environment: Mapping[str, str] | None = None,
    uid: int | None = None,
) -> str:
    """Derive the one local-agent actor from the current Codex task context."""

    source = os.environ if environment is None else environment
    identity = None
    for name in ("CODEX_THREAD_ID", "CODEX_TASK_ID"):
        value = str(source.get(name) or "").strip()
        if value:
            identity = value
            break
    return codex_test_actor(
        identity=identity,
        uid=os.geteuid() if uid is None else uid,
    )
