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


@dataclass(frozen=True)
class RoutedTool:
    server_id: str
    bare_name: str
    external_name: str
    tool: types.Tool


class RoutingTable:
    def __init__(self) -> None:
        self._by_external_name: dict[str, RoutedTool] = {}

    def register_server_tools(self, server_id: str, tools: list[types.Tool]) -> None:
        for tool in tools:
            name = external_tool_name(server_id, tool.name)
            if name in self._by_external_name:
                raise ValueError(f"duplicate external tool name: {name!r}")
            self._by_external_name[name] = RoutedTool(server_id, tool.name, name, tool)

    def all_tools(self) -> list[types.Tool]:
        return [
            routed.tool.model_copy(update={"name": routed.external_name})
            for routed in self._by_external_name.values()
        ]

    def resolve(self, external_name: str) -> RoutedTool:
        try:
            return self._by_external_name[external_name]
        except KeyError:
            raise KeyError(f"unknown tool: {external_name!r}") from None
