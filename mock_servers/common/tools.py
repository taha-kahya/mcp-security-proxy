"""Shared harmless tool factories for the mock MCP servers.

Both server_a and server_b register the exact same tool set via this module,
including a `send_message` tool with an identical bare name on both servers —
this is deliberate, to exercise the proxy's server-scoped identity handling in
a later phase. Every write/send call is appended to the server's audit log,
which is the ground truth tests check against instead of trusting responses.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from mock_servers.common.audit_log import AuditLog


def register_mock_tools(server: MCPServer, server_id: str, audit_log: AuditLog) -> None:
    store: dict[str, str] = {}

    @server.tool()
    def read_record(key: str) -> str:
        """Read a value previously written to this server's in-memory store."""
        if key not in store:
            raise ValueError(f"no record found for key '{key}'")
        return store[key]

    @server.tool()
    def write_record(key: str, value: str) -> str:
        """Write a value into this server's in-memory store."""
        store[key] = value
        audit_log.record(server_id, "write_record", {"key": key, "value": value})
        return f"wrote '{key}'"

    @server.tool()
    def send_message(recipient: str, message: str) -> str:
        """Send a harmless mock message. Identically named on both mock servers."""
        audit_log.record(server_id, "send_message", {"recipient": recipient, "message": message})
        return f"{server_id} sent message to {recipient}"
