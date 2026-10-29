"""Where the Runner finds defense factories by name.

Installed packages register factories under the `mcp_security_proxy.defenses`
entry-point group, so adding a defense never requires editing the Runner.
Configuration then decides which registered defenses are enabled.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib.metadata import entry_points
from typing import Protocol

from mcp_security_proxy.sdk import DEFENSE_ENTRY_POINT_GROUP, DefenseFactory


class DefenseCatalog(Protocol):
    def factory(self, name: str) -> DefenseFactory | None: ...

    def names(self) -> list[str]: ...


class EntryPointCatalog:
    def __init__(self, group: str = DEFENSE_ENTRY_POINT_GROUP) -> None:
        self._entry_points = {ep.name: ep for ep in entry_points(group=group)}

    def factory(self, name: str) -> DefenseFactory | None:
        entry_point = self._entry_points.get(name)
        if entry_point is None:
            return None
        factory: DefenseFactory = entry_point.load()
        return factory

    def names(self) -> list[str]:
        return sorted(self._entry_points)


class StaticCatalog:
    """A fixed set of factories, for tests and embedded use."""

    def __init__(self, factories: Mapping[str, DefenseFactory]) -> None:
        self._factories = dict(factories)

    def factory(self, name: str) -> DefenseFactory | None:
        return self._factories.get(name)

    def names(self) -> list[str]:
        return sorted(self._factories)
