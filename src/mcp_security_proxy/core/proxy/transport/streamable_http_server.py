"""Proxy's inbound, agent-facing MCP listener over Streamable HTTP."""

from __future__ import annotations

import uvicorn
from mcp.server.lowlevel import Server


async def serve_streamable_http(server: Server, host: str, port: int) -> None:
    app = server.streamable_http_app(host=host)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()
