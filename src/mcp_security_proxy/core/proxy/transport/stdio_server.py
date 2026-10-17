"""Proxy's inbound, agent-facing MCP listener over stdio."""

from __future__ import annotations

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


async def serve_stdio(server: Server) -> None:
    init_options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, init_options)
