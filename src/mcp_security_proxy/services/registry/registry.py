"""Registry: versioned tool definitions and their configured semantics.

A definition's version is a hash of its canonical JSON form, so any change
the server makes to a tool (description, schema, annotations) produces a new
version. Definitions are what the server claims; they are never treated as
verified permissions.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp_security_proxy.sdk import Action, ToolDefinition, ToolId, canonical_digest
from mcp_security_proxy.services.registry.adapters import ToolAdapter


class Registry:
    """Satisfies the SDK's read-only `RegistryView`; `register` is for the core."""

    def __init__(self, adapter: ToolAdapter) -> None:
        self._adapter = adapter
        self._definitions: dict[ToolId, ToolDefinition] = {}

    def register(self, tool_id: ToolId, definition: Mapping[str, Any]) -> ToolDefinition:
        registered = ToolDefinition(tool_id, canonical_digest(definition), definition)
        self._definitions[tool_id] = registered
        return registered

    def current(self, tool_id: ToolId) -> ToolDefinition | None:
        return self._definitions.get(tool_id)

    def action(self, tool_id: ToolId, arguments: Mapping[str, Any]) -> Action:
        if tool_id not in self._definitions:
            return Action.unknown(self._adapter.adapter_id, self._adapter.adapter_version)
        return self._adapter.action(tool_id, arguments)

    def tool_ids(self) -> list[ToolId]:
        return list(self._definitions)
