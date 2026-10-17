"""Test-only fixture: an MCP server that crashes shortly after answering one
call, to exercise the proxy's handling of a dropped upstream stdio connection.

Not part of the reusable mock_servers package since crashing deliberately
isn't a "harmless mock tool" — it's test-failure-injection scaffolding.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from mock_servers.common.audit_log import AuditLog

SERVER_ID = "flaky_server"


def build_flaky_server(audit_log_path: Path) -> MCPServer:
    server = MCPServer(name=SERVER_ID)
    audit_log = AuditLog(audit_log_path)

    @server.tool()
    async def crash_after_response(key: str, value: str) -> str:
        audit_log.record(SERVER_ID, "crash_after_response", {"key": key, "value": value})

        async def die() -> None:
            await asyncio.sleep(0.05)
            os._exit(1)

        asyncio.create_task(die())
        return f"wrote '{key}', about to crash"

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-log", type=Path, required=True)
    args = parser.parse_args()
    build_flaky_server(args.audit_log).run(transport="stdio")


if __name__ == "__main__":
    main()
