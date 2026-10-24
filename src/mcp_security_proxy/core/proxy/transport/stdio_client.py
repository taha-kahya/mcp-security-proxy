"""Proxy's outbound stdio connection to a single upstream MCP server."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@asynccontextmanager
async def connect_stdio_upstream(command: str, args: list[str]) -> AsyncIterator[ClientSession]:
    params = StdioServerParameters(command=command, args=args)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
