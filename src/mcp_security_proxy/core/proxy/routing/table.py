"""Aggregated discovery and routing across upstream servers.

Built once at proxy startup from each upstream server's own `list_tools`
result (V1 does not yet re-discover per request; that belongs to a later,
Registry-aware phase). Keeps each upstream `Tool` definition's metadata
intact and only overrides `name` with the disambiguated external name, to
preserve structure rather than reconstructing tools from scratch. In
transparent mode (0023) the external name is the bare name, which is
unambiguous because exactly one upstream is configured.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from mcp import types

from mcp_security_proxy.core.proxy.routing.identity import external_tool_name
from mcp_security_proxy.sdk import ToolId


@dataclass(frozen=True)
class RoutedTool:
    server_id: str
    bare_name: str
    external_name: str
    tool: types.Tool
    # The definition exactly as the upstream sent it on the wire, key order
    # included. Only captured in transparent mode (see `register_server_tools`).
    raw: Mapping[str, Any] | None = None

    @property
    def tool_id(self) -> ToolId:
        return ToolId(server_id=self.server_id, name=self.bare_name)

    def external_tool(self) -> types.Tool:
        """The upstream definition as advertised to the agent."""
        return self.tool.model_copy(update={"name": self.external_name})

    def external_wire(self) -> dict[str, Any] | None:
        """The upstream's own JSON definition, with `name` set to the external
        name in place so every key keeps its position. None when not captured."""
        if self.raw is None:
            return None
        return {k: (self.external_name if k == "name" else v) for k, v in self.raw.items()}


class RoutingTable:
    def __init__(self, *, transparent: bool = False) -> None:
        self._transparent = transparent
        self._by_external_name: dict[str, RoutedTool] = {}

    def register_server_tools(
        self,
        server_id: str,
        tools: list[types.Tool],
        raw_tools: list[dict[str, Any]] | None = None,
    ) -> None:
        """`raw_tools` are the same definitions as the upstream sent them,
        matched to `tools` by name."""
        raw_by_name = {r["name"]: r for r in raw_tools or [] if isinstance(r.get("name"), str)}
        for tool in tools:
            name = tool.name if self._transparent else external_tool_name(server_id, tool.name)
            if name in self._by_external_name:
                raise ValueError(f"duplicate external tool name: {name!r}")
            self._by_external_name[name] = RoutedTool(
                server_id, tool.name, name, tool, raw_by_name.get(tool.name)
            )

    def entries(self) -> list[RoutedTool]:
        return list(self._by_external_name.values())

    def all_tools(self) -> list[types.Tool]:
        return [routed.external_tool() for routed in self.entries()]

    def find(self, external_name: str) -> RoutedTool | None:
        return self._by_external_name.get(external_name)
