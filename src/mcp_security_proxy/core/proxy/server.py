"""The agent-facing MCP server: adapts SDK handler callbacks to the orchestrator.

Built on the low-level `Server` rather than `MCPServer`'s mount feature so
every discovery and call passes through the proxy's own lifecycle (see
`docs/design/tool-identity-and-routing.md`).
"""

from __future__ import annotations

from typing import Any

from mcp import types
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.lowlevel import Server

from mcp_security_proxy.core.identity import IdentityResolver, UnauthenticatedError
from mcp_security_proxy.core.proxy.codec.jsonrpc import unauthenticated_error
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator
from mcp_security_proxy.sdk import Principal

_NAME = "mcp-security-proxy"


def build_proxy_server(
    orchestrator: ProxyOrchestrator,
    identity: IdentityResolver,
    server_info: types.Implementation | None = None,
    verbatim_tools: bool = False,
) -> Server:
    """`server_info` is the upstream's identity in transparent mode; otherwise
    the proxy reports its own fixed name. `verbatim_tools` (transparent mode)
    lists each tool as the upstream's own JSON, key order and unknown fields
    included."""

    def principal_of(ctx: ServerRequestContext[object, object]) -> Principal:
        try:
            return identity.resolve(ctx.request)
        except UnauthenticatedError as exc:
            raise unauthenticated_error() from exc

    async def on_list_tools(
        ctx: ServerRequestContext[object, object],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        return types.ListToolsResult(tools=await orchestrator.list_tools(principal_of(ctx)))

    async def on_call_tool(
        ctx: ServerRequestContext[object, object],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        return await orchestrator.call_tool(
            principal_of(ctx), params.name, params.arguments or {}, params.meta
        )

    async def verbatim_tool_definitions(
        ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        """The SDK re-serializes a `tools/list` result through its spec model,
        which reorders keys and drops fields it does not declare. Swap each
        entry for the upstream's own JSON; which tools are listed stays the
        handler's decision."""
        result = await call_next(ctx)
        if ctx.method != "tools/list" or not isinstance(result, dict):
            return result
        listed = result.get("tools")
        if not isinstance(listed, list):
            return result
        tools: list[Any] = []
        for entry in listed:
            wire = orchestrator.wire_definition(entry["name"]) if isinstance(entry, dict) else None
            tools.append(entry if wire is None else wire)
        return {**result, "tools": tools}

    name, version = (server_info.name, server_info.version) if server_info else (_NAME, "")
    server: Server = Server(
        name=name,
        version=version,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    if verbatim_tools:
        server.middleware.append(verbatim_tool_definitions)
    return server
