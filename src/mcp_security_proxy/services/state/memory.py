"""In-memory State, for tests and deployments that need no restart recovery."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from mcp_security_proxy.sdk import ABSENT, VersionedValue
from mcp_security_proxy.services.state.store import Change, Scope, StateStore, UpdateResult


class InMemoryStateStore(StateStore):
    """No method awaits, so each one runs atomically on the event loop
    without a lock. Everything is lost when the process exits."""

    def __init__(self) -> None:
        self._records: dict[tuple[Scope, str], VersionedValue] = {}

    async def read(self, scope: Scope, key: str) -> VersionedValue:
        return self._records.get((scope, key), ABSENT)

    async def read_scope(self, scope: Scope) -> Mapping[str, VersionedValue]:
        return {key: value for (s, key), value in self._records.items() if s == scope}

    async def scopes(self, owner: str) -> list[Scope]:
        owned = {s for s, _ in self._records if s.owner == owner}
        return sorted(owned, key=lambda s: (s.principal_id, s.task_id))

    async def apply(self, changes: Sequence[Change]) -> UpdateResult:
        conflicts = tuple(
            change
            for change in changes
            if self._records.get((change.scope, change.key), ABSENT).version
            != change.expected_version
        )
        if conflicts:
            return UpdateResult(applied=False, conflicts=conflicts)
        for change in changes:
            self._records[(change.scope, change.key)] = VersionedValue(
                change.expected_version + 1, change.value
            )
        return UpdateResult(applied=True)
