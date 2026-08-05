"""Public compatibility exports for the DevCoordinator package.

Importing one narrow client module must not initialize the broker backend,
stores, lifecycle adapters, or host integrations.  The historical package
exports remain available, but they are resolved only when a caller asks for
the individual symbol.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any


_LAZY_EXPORTS = {
    "ImportConflict": (".legacy_import", "ImportConflict"),
    "ImportReport": (".legacy_import", "ImportReport"),
    "LegacyImportError": (".legacy_import", "LegacyImportError"),
    "LegacySourceChanged": (".legacy_import", "LegacySourceChanged"),
    "AccountStore": (".store", "AccountStore"),
    "CoordinatorStore": (".store", "CoordinatorStore"),
    "StoreInvariantError": (".store", "StoreInvariantError"),
    "AccountAccessPolicy": (".broker", "AccountAccessPolicy"),
    "BrokerClient": (".broker", "BrokerClient"),
    "BrokerError": (".broker", "BrokerError"),
    "BrokerOperation": (".broker", "BrokerOperation"),
    "BrokerRequest": (".broker", "BrokerRequest"),
    "BrokerService": (".broker", "BrokerService"),
    "PeerCredentials": (".broker", "PeerCredentials"),
    "PortLeasePolicy": (".broker", "PortLeasePolicy"),
    "SerializedMutationWriter": (".broker", "SerializedMutationWriter"),
    "StaticPeerAuthorizer": (".broker", "StaticPeerAuthorizer"),
    "UnixBrokerServer": (".broker", "UnixBrokerServer"),
    "StoreBackedBrokerRuntime": (".broker_backend", "StoreBackedBrokerRuntime"),
    "StoreBackedMutationBackend": (
        ".broker_backend",
        "StoreBackedMutationBackend",
    ),
    "TypedHostMutationAPI": (".broker_backend", "TypedHostMutationAPI"),
    "build_store_backed_broker_runtime": (
        ".broker_backend",
        "build_store_backed_broker_runtime",
    ),
    "BrokerPersistence": (".broker_persistence", "BrokerPersistence"),
    "StoreBackedAuthorizer": (".broker_persistence", "StoreBackedAuthorizer"),
}

__all__ = [
    "AccountStore",
    "AccountAccessPolicy",
    "BrokerClient",
    "BrokerError",
    "BrokerOperation",
    "BrokerPersistence",
    "BrokerRequest",
    "BrokerService",
    "CoordinatorStore",
    "ImportConflict",
    "ImportReport",
    "LegacyImportError",
    "LegacySourceChanged",
    "PeerCredentials",
    "PortLeasePolicy",
    "SerializedMutationWriter",
    "StaticPeerAuthorizer",
    "StoreBackedAuthorizer",
    "StoreBackedBrokerRuntime",
    "StoreBackedMutationBackend",
    "StoreInvariantError",
    "TypedHostMutationAPI",
    "UnixBrokerServer",
    "build_store_backed_broker_runtime",
]


def __getattr__(name: str) -> Any:
    """Load one legacy public symbol without importing unrelated subsystems."""

    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY_EXPORTS})


if TYPE_CHECKING:  # pragma: no cover - imported only by static analyzers
    from .broker import (
        AccountAccessPolicy,
        BrokerClient,
        BrokerError,
        BrokerOperation,
        BrokerRequest,
        BrokerService,
        PeerCredentials,
        PortLeasePolicy,
        SerializedMutationWriter,
        StaticPeerAuthorizer,
        UnixBrokerServer,
    )
    from .broker_backend import (
        StoreBackedBrokerRuntime,
        StoreBackedMutationBackend,
        TypedHostMutationAPI,
        build_store_backed_broker_runtime,
    )
    from .broker_persistence import BrokerPersistence, StoreBackedAuthorizer
    from .legacy_import import (
        ImportConflict,
        ImportReport,
        LegacyImportError,
        LegacySourceChanged,
    )
    from .store import AccountStore, CoordinatorStore, StoreInvariantError
