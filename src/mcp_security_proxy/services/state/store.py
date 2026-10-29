"""The State contract: scoped, versioned records with atomic updates.

Every record lives under a `Scope` (which service or defense owns it, for
which principal and task) and a key. Each write bumps the record's version.
Updates are optimistic: a change names the version it was based on and is
applied only if that is still the stored version. `apply` commits several
changes all-or-nothing, for decisions that touch more than one record.

Values must be JSON-serializable. Reads return frozen values.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from mcp_security_proxy.sdk import VersionedValue, freeze


class StateUnavailableError(Exception):
    """The storage backend failed; callers must fail closed."""


@dataclass(frozen=True)
class Scope:
    """`owner` is `history`, `defense:<id>`, or another service's name."""

    owner: str
    principal_id: str
    task_id: str


@dataclass(frozen=True)
class Change:
    """Write `value` to `key`, if its stored version is still `expected_version`
    (0 to create a key that must not exist yet)."""

    scope: Scope
    key: str
    expected_version: int
    value: Any

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", freeze(self.value))


@dataclass(frozen=True)
class UpdateResult:
    applied: bool
    conflicts: tuple[Change, ...] = field(default=())


class StateStore(ABC):
    @abstractmethod
    async def read(self, scope: Scope, key: str) -> VersionedValue:
        """A missing key reads as version 0 with no value."""

    @abstractmethod
    async def read_scope(self, scope: Scope) -> Mapping[str, VersionedValue]:
        """Every key stored under `scope`."""

    @abstractmethod
    async def scopes(self, owner: str) -> list[Scope]:
        """Every scope `owner` has stored records under."""

    @abstractmethod
    async def apply(self, changes: Sequence[Change]) -> UpdateResult:
        """Apply every change, or none if any expected version is stale."""

    async def compare_and_set(
        self, scope: Scope, key: str, expected_version: int, value: Any
    ) -> UpdateResult:
        return await self.apply([Change(scope, key, expected_version, value)])

    async def close(self) -> None:  # noqa: B027 - optional hook; nothing to release by default
        """Release backend resources."""
