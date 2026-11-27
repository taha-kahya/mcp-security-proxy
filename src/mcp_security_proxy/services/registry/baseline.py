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

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from mcp_security_proxy.sdk import ToolDefinition, ToolId, canonical_digest, thaw
from mcp_security_proxy.services.state import Change, Scope, StateStore

OWNER = "registry_baseline"
SCOPE = Scope(OWNER, "-", "-")


class DefinitionBaselines:
    """`normalize` maps a definition to the one canonical form that is stored
    and compared. It is applied to what is stored and, on every load, to what
    was stored before, so a change in how definitions are serialized (another
    MCP SDK version, leaving transparent mode) isn't mistaken for drift."""

    def __init__(
        self,
        state: StateStore,
        normalize: Callable[[Mapping[str, Any]], Mapping[str, Any]] = thaw,
        attempts: int = 5,
    ) -> None:
        self._state = state
        self._normalize = normalize
        self._attempts = attempts

    def canonical(self, definition: ToolDefinition) -> ToolDefinition:
        body = self._normalize(thaw(definition.definition))
        return ToolDefinition(definition.tool_id, canonical_digest(body), body)

    async def approve_if_new(self, definition: ToolDefinition) -> ToolDefinition:
        """The approved version of `definition.tool_id`: the stored one if any,
        otherwise `definition` (in canonical form), which is stored as approved.

        A concurrent writer can approve first, or `forget` can clear the value
        between the write and the re-read; both are retried, never crashed on.
        """
        key = str(definition.tool_id)
        current = self.canonical(definition)
        for _ in range(self._attempts):
            stored = await self._state.read(SCOPE, key)
            if stored.value is not None:
                return self._definition(definition.tool_id, stored.value)
            # Absent, or forgotten (the store has no delete, so forgetting writes None).
            value = {"version": current.version, "definition": thaw(current.definition)}
            result = await self._state.compare_and_set(SCOPE, key, stored.version, value)
            if result.applied:
                return current
        raise RuntimeError(f"approved definition of {key} kept changing; retry")

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

    def _definition(self, tool_id: ToolId, value: Any) -> ToolDefinition:
        body = self._normalize(thaw(value["definition"]))
        return ToolDefinition(tool_id, canonical_digest(body), body)
