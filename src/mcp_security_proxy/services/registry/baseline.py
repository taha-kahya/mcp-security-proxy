"""Approved tool definitions, kept in the state backend (plan MR T2).

The first definition the proxy discovers for a tool id is its approved
version. It is stored under the `registry_baseline` owner, so a restart
doesn't silently approve a definition that changed while the proxy was
down: the stored version stays approved until the operator forgets it
(`python -m mcp_security_proxy.app.approve_definitions`), and the next
discovery approves whatever the server lists then.

With the in-memory state backend nothing survives a restart, so the
approved version is the first one seen by each process.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from mcp_security_proxy.sdk import ToolDefinition, ToolId
from mcp_security_proxy.services.state import Change, Scope, StateStore

OWNER = "registry_baseline"
SCOPE = Scope(OWNER, "-", "-")


def _thaw(value: Any) -> Any:
    """Plain dicts and lists from the store's frozen values."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


class DefinitionBaselines:
    def __init__(self, state: StateStore) -> None:
        self._state = state

    async def approve_if_new(self, definition: ToolDefinition) -> ToolDefinition:
        """The approved version of `definition.tool_id`: the stored one if any,
        otherwise `definition`, which is stored as approved."""
        key = str(definition.tool_id)
        stored = await self._state.read(SCOPE, key)
        if stored.value is not None:
            return self._definition(definition.tool_id, stored.value)
        # Absent, or forgotten (the store has no delete, so forgetting writes None).
        value = {"version": definition.version, "definition": _thaw(definition.definition)}
        result = await self._state.compare_and_set(SCOPE, key, stored.version, value)
        if result.applied:
            return definition
        # Another writer approved it first; theirs stands.
        stored = await self._state.read(SCOPE, key)
        return self._definition(definition.tool_id, stored.value)

    async def forget(self, tool_ids: Iterable[ToolId] | None = None) -> list[str]:
        """Drop approved versions (all of them when `tool_ids` is None), so the
        next discovery approves what each server lists then. Returns the keys
        that were dropped."""
        stored = await self._state.read_scope(SCOPE)
        keys = sorted(stored) if tool_ids is None else sorted(str(t) for t in tool_ids)
        changes = [
            Change(SCOPE, key, stored[key].version, None)
            for key in keys
            if key in stored and stored[key].value is not None
        ]
        if changes:
            result = await self._state.apply(changes)
            if not result.applied:
                raise RuntimeError("approved definitions changed while forgetting them; retry")
        return [change.key for change in changes]

    @staticmethod
    def _definition(tool_id: ToolId, value: Any) -> ToolDefinition:
        return ToolDefinition(tool_id, value["version"], _thaw(value["definition"]))
