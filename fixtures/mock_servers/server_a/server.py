from __future__ import annotations

from pathlib import Path

from mcp.server.mcpserver import MCPServer

from fixtures.mock_servers.common.audit_log import AuditLog
from fixtures.mock_servers.common.tools import register_mock_tools

SERVER_ID = "server_a"


def build_server(audit_log_path: Path) -> MCPServer:
    server = MCPServer(name=SERVER_ID)
    register_mock_tools(server, SERVER_ID, AuditLog(audit_log_path))
    return server
