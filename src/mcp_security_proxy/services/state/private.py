"""Each defense's private state, scoped to that defense and one task.

A defense only reads its own snapshot and proposes `StateChange`s; it never
writes. The core commits every proposal from one inspection in a single
atomic `apply`, scoped by the defense id the Runner attributed it to, so a
defense cannot write into another defense's state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from mcp_security_proxy.sdk import PrivateState, StateChange
from mcp_security_proxy.services.state.store import Change, StateStore, TaskRef, UpdateResult


def defense_owner(defense_id: str) -> str:
    return f"defense:{defense_id}"


class DefenseStateStore:
    def __init__(self, store: StateStore) -> None:
        self._store = store

    async def snapshot(self, defense_id: str, task: TaskRef) -> PrivateState:
        return PrivateState(await self._store.read_scope(task.scope(defense_owner(defense_id))))

    async def commit(
        self, task: TaskRef, proposals: Mapping[str, Sequence[StateChange]]
    ) -> UpdateResult:
        """`proposals` maps a defense id to the changes it proposed."""
        changes = [
            Change(task.scope(defense_owner(defense_id)), c.key, c.expected_version, c.value)
            for defense_id, proposed in proposals.items()
            for c in proposed
        ]
        if not changes:
            return UpdateResult(applied=True)
        return await self._store.apply(changes)
