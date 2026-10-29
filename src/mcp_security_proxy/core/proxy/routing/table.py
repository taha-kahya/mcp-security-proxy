"""Aggregated discovery and routing across upstream servers.

Built once at proxy startup from each upstream server's own `list_tools`
result (V1 does not yet re-discover per request; that belongs to a later,
Registry-aware phase). Keeps each upstream `Tool` definition's metadata
intact and only overrides `name` with the disambiguated external name, to
preserve structure rather than reconstructing tools from scratch.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp import types

from mcp_security_proxy.core.proxy.routing.identity import external_tool_name
from mcp_security_proxy.sdk import ToolId


@dataclass(frozen=True)
class RoutedTool:
    server_id: str
    bare_name: str
    external_name: str
    tool: types.Tool

    @property
    def tool_id(self) -> ToolId:
        return ToolId(server_id=self.server_id, name=self.bare_name)

    def external_tool(self) -> types.Tool:
        """The upstream definition as advertised to the agent."""
        return self.tool.model_copy(update={"name": self.external_name})


class RoutingTable:
    def __init__(self) -> None:
        self._by_external_name: dict[str, RoutedTool] = {}

    def register_server_tools(self, server_id: str, tools: list[types.Tool]) -> None:
        for tool in tools:
            name = external_tool_name(server_id, tool.name)
            if name in self._by_external_name:
                raise ValueError(f"duplicate external tool name: {name!r}")
            self._by_external_name[name] = RoutedTool(server_id, tool.name, name, tool)

    def entries(self) -> list[RoutedTool]:
        return list(self._by_external_name.values())

    def all_tools(self) -> list[types.Tool]:
        return [routed.external_tool() for routed in self.entries()]

    def find(self, external_name: str) -> RoutedTool | None:
        return self._by_external_name.get(external_name)
