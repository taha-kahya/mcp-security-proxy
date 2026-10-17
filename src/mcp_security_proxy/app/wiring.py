"""Startup wiring: connects to configured upstream servers, builds the routing
table, and assembles the proxy's own agent-facing MCP server.

Proxy remains a thin orchestrator: this module only wires together the
transport, routing, and correlation pieces. It contains no attack detection
or policy logic — that belongs to later phases.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from mcp import ClientSession, types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.core.proxy.codec.jsonrpc import (
    ensure_call_tool_result,
    unknown_tool_error,
)
from mcp_security_proxy.core.proxy.routing.correlation import CallStatus, CorrelationTracker
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.core.proxy.transport.stdio_client import connect_stdio_upstream


class ProxyApp:
    def __init__(self, server: Server) -> None:
        self.server = server


@asynccontextmanager
async def build_app(config: ProxyConfig) -> AsyncIterator[ProxyApp]:
    routing_table = RoutingTable()
    correlation = CorrelationTracker()
    sessions: dict[str, ClientSession] = {}

    async with AsyncExitStack() as stack:
        for upstream in config.servers:
            session = await stack.enter_async_context(
                connect_stdio_upstream(upstream.command, upstream.args)
            )
            sessions[upstream.id] = session
            discovered = await session.list_tools()
            routing_table.register_server_tools(upstream.id, discovered.tools)

        async def on_list_tools(
            ctx: ServerRequestContext[object, object],
            params: types.PaginatedRequestParams | None,
        ) -> types.ListToolsResult:
            return types.ListToolsResult(tools=routing_table.all_tools())

        async def on_call_tool(
            ctx: ServerRequestContext[object, object],
            params: types.CallToolRequestParams,
        ) -> types.CallToolResult:
            try:
                routed = routing_table.resolve(params.name)
            except KeyError as exc:
                raise unknown_tool_error(params.name) from exc

            correlation_id = correlation.begin(routed.server_id, routed.external_name)
            try:
                result = await sessions[routed.server_id].call_tool(
                    routed.bare_name, params.arguments or {}
                )
            except BaseException:
                correlation.end(correlation_id, CallStatus.FAILED)
                raise
            correlation.end(correlation_id, CallStatus.COMPLETED)
            return ensure_call_tool_result(params.name, result)

        server = Server(
            name="mcp-security-proxy",
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )
        yield ProxyApp(server)
