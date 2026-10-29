"""The agent-facing MCP server: adapts SDK handler callbacks to the orchestrator.

Built on the low-level `Server` rather than `MCPServer`'s mount feature so
every discovery and call passes through the proxy's own lifecycle (see
`docs/design/tool-identity-and-routing.md`).
"""

from __future__ import annotations

from mcp import types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server

from mcp_security_proxy.core.identity import IdentityResolver, UnauthenticatedError
from mcp_security_proxy.core.proxy.codec.jsonrpc import unauthenticated_error
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator
from mcp_security_proxy.sdk import Principal


def build_proxy_server(orchestrator: ProxyOrchestrator, identity: IdentityResolver) -> Server:
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
        return await orchestrator.call_tool(principal_of(ctx), params.name, params.arguments or {})

    return Server(
        name="mcp-security-proxy",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
