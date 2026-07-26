"""Fail-closed redaction for runtime requests, results, and diagnostics."""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit


_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|credential|password|passwd|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(authorization|cookie|password|passwd|secret|token|api[_-]?key)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_ENVIRONMENT_KEYS = frozenset({"env", "environment", "run_env"})
_ARGUMENT_KEYS = frozenset({"argv", "run_argv"})
_URL = re.compile(r"(?i)\b(?:https?|wss?)://[^\s\"'<>]+")


def runtime_secret_values(request: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Return exact request values that must never cross a durable boundary."""

    if not isinstance(request, Mapping):
        return ()
    options = request.get("options")
    if not isinstance(options, Mapping):
        return ()
    values: set[str] = set()
    for key in _ENVIRONMENT_KEYS:
        environment = options.get(key)
        if isinstance(environment, Mapping):
            values.update(
                str(value) for value in environment.values() if str(value)
            )
    for key in _ARGUMENT_KEYS:
        arguments = options.get(key)
        if isinstance(arguments, (list, tuple)):
            values.update(str(value) for value in arguments[1:] if str(value))
    return tuple(sorted(values, key=lambda value: (-len(value), value)))


def _redact_text(value: str, *, secrets: tuple[str, ...]) -> str:
    result = _BEARER.sub(r"\1[REDACTED]", value)
    result = _ASSIGNMENT_SECRET.sub(r"\1=[REDACTED]", result)
    for secret in secrets:
        result = result.replace(secret, "[REDACTED]")
    def sanitize_url(match: re.Match[str]) -> str:
        candidate = match.group(0)
        trailing = ""
        while candidate and candidate[-1] in ").,;]}":
            trailing = candidate[-1] + trailing
            candidate = candidate[:-1]
        try:
            parsed = urlsplit(candidate)
            host = parsed.hostname
            if not host:
                return "[REDACTED-URL]" + trailing
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = host + (f":{parsed.port}" if parsed.port is not None else "")
            safe = urlunsplit(
                SplitResult(parsed.scheme, netloc, parsed.path or "", "", "")
            )
            return safe + trailing
        except (TypeError, ValueError):
            return "[REDACTED-URL]" + trailing

    result = _URL.sub(sanitize_url, result)
    return result


def _argument_summary(value: Any) -> dict[str, Any]:
    arguments = list(value) if isinstance(value, (list, tuple)) else []
    executable = arguments[0] if arguments and isinstance(arguments[0], str) else None
    return {
        "redacted": True,
        "executable": executable,
        "argument_count": len(arguments),
    }


def _environment_summary(value: Any) -> dict[str, Any]:
    environment = value if isinstance(value, Mapping) else {}
    return {
        "redacted": True,
        "names": sorted(str(name) for name in environment),
        "count": len(environment),
    }


def redact_runtime_value(
    value: Any,
    *,
    request: Mapping[str, Any] | None = None,
    _key: str = "",
    _secrets: tuple[str, ...] | None = None,
) -> Any:
    """Return a JSON-compatible copy with request secrets and commands removed."""

    secrets = runtime_secret_values(request) if _secrets is None else _secrets
    key = _key.lower()
    if key in _ARGUMENT_KEYS:
        return _argument_summary(value)
    if key in _ENVIRONMENT_KEYS:
        return _environment_summary(value)
    if _SENSITIVE_KEY.search(_key):
        return {"redacted": True}
    if isinstance(value, Mapping):
        return {
            str(item_key): redact_runtime_value(
                item,
                request=request,
                _key=str(item_key),
                _secrets=secrets,
            )
            for item_key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            redact_runtime_value(
                item, request=request, _key=_key, _secrets=secrets
            )
            for item in value
        ]
    if isinstance(value, str):
        return _redact_text(value, secrets=secrets)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(str(value), secrets=secrets)


def redact_runtime_request(request: Mapping[str, Any]) -> dict[str, Any]:
    redacted = redact_runtime_value(request, request=request)
    if not isinstance(redacted, dict):  # pragma: no cover - Mapping guarantees this
        raise TypeError("redacted runtime request is not an object")
    return redacted
