"""Explicit dependency-driver registry for immutable test attempts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from .universal_test_store import TestStoreContractError


Binding = Mapping[str, object]
PythonResolver = Callable[[], tuple[Binding | None, str | None]]
NodeResolver = Callable[[], Binding | None]
DotnetResolver = Callable[
    [], tuple[Binding | None, str | None, Binding | None]
]


@dataclass(frozen=True)
class DependencyResolution:
    bindings: tuple[Binding, ...]
    python_executable: str | None
    dotnet_executable: str | None
    toolchains: tuple[Binding, ...]


class DependencyDrivers:
    """Resolve each supported ecosystem through one narrow callable."""

    def __init__(
        self,
        *,
        python: PythonResolver,
        node: NodeResolver,
        dotnet: DotnetResolver,
    ) -> None:
        if not all(callable(item) for item in (python, node, dotnet)):
            raise TestStoreContractError("dependency driver registry is incomplete")
        self._python = python
        self._node = node
        self._dotnet = dotnet

    def resolve(self) -> DependencyResolution:
        bindings: list[Binding] = []
        python, python_executable = self._python()
        if python is not None:
            bindings.append(python)
        node = self._node()
        if node is not None:
            bindings.append(node)
        dotnet, dotnet_executable, dotnet_toolchain = self._dotnet()
        if dotnet is not None:
            bindings.append(dotnet)
        return DependencyResolution(
            bindings=tuple(bindings),
            python_executable=python_executable,
            dotnet_executable=dotnet_executable,
            toolchains=(() if dotnet_toolchain is None else (dotnet_toolchain,)),
        )


__all__ = ["DependencyDrivers", "DependencyResolution"]
