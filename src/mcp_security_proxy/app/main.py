from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from mcp.server.lowlevel import Server

from mcp_security_proxy.app.config import ProxyConfig, load_config
from mcp_security_proxy.app.wiring import build_app
from mcp_security_proxy.core.proxy.transport.stdio_server import serve_stdio
from mcp_security_proxy.core.proxy.transport.streamable_http_server import serve_streamable_http


async def _serve(config: ProxyConfig, server: Server) -> None:
    if config.agent_transport == "stdio":
        await serve_stdio(server)
    else:
        await serve_streamable_http(server, config.agent_host, config.agent_port)


async def _run(config_path: Path) -> None:
    config = load_config(config_path)
    async with build_app(config) as app:
        await _serve(config, app.server)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP security proxy (V1)")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(_run(args.config))


if __name__ == "__main__":
    main()
