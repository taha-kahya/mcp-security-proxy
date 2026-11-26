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
    # The definition exactly as the upstream sent it on the wire, key order and
    # unknown fields included; `tool` is built from this same object. Only
    # captured in transparent mode (see `register_server_tools`).
    raw: Mapping[str, Any] | None = None

    @property
    def tool_id(self) -> ToolId:
        return ToolId(server_id=self.server_id, name=self.bare_name)

    def external_tool(self) -> types.Tool:
        """The upstream definition as advertised to the agent."""
        return self.tool.model_copy(update={"name": self.external_name})

    def external_wire(self) -> Mapping[str, Any] | None:
        """The upstream's own JSON definition, or None when not captured. In
        transparent mode the external name is the bare name, so nothing in it
        needs rewriting."""
        return self.raw


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
        """`raw_tools` are the definitions as the upstream sent them, one per
        entry of `tools` and in the same order (each tool is built from its
        raw object)."""
        if raw_tools is not None and len(raw_tools) != len(tools):
            raise ValueError("raw_tools must hold one definition per tool")
        for index, tool in enumerate(tools):
            name = tool.name if self._transparent else external_tool_name(server_id, tool.name)
            if name in self._by_external_name:
                raise ValueError(f"duplicate external tool name: {name!r}")
            self._by_external_name[name] = RoutedTool(
                server_id, tool.name, name, tool, raw_tools[index] if raw_tools else None
            )

    def replace_server_tools(
        self,
        server_id: str,
        tools: list[types.Tool],
        raw_tools: list[dict[str, Any]] | None = None,
    ) -> None:
        """Swap one server's tools for a fresh listing (re-discovery, T2).

        Other servers' entries are untouched; a name that would collide with
        one of them raises, and the table is left as it was.
        """
        kept = {n: r for n, r in self._by_external_name.items() if r.server_id != server_id}
        previous = self._by_external_name
        self._by_external_name = kept
        try:
            self.register_server_tools(server_id, tools, raw_tools)
        except ValueError:
            self._by_external_name = previous
            raise

    def entries(self) -> list[RoutedTool]:
        return list(self._by_external_name.values())

    def all_tools(self) -> list[types.Tool]:
        return [routed.external_tool() for routed in self.entries()]

    def find(self, external_name: str) -> RoutedTool | None:
        return self._by_external_name.get(external_name)
