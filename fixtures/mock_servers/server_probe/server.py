"""A mock server for transparent mode (0023): definitions whose exact JSON
shape can be compared through the proxy, and a tool that reports the request
`_meta` it received. Not part of the A/B pair, so their tool contract is
unchanged."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from pydantic import BaseModel, Field

from fixtures.mock_servers.common.audit_log import AuditLog

SERVER_ID = "server_probe"
SERVER_VERSION = "3.4.5"


class Limits(BaseModel):
    upper: int
    lower: int = 0


class Scope(BaseModel):
    zone: str
    limits: Limits
    labels: list[str] = Field(default_factory=list)


def build_server(audit_log_path: Path) -> MCPServer:
    server = MCPServer(name=SERVER_ID, version=SERVER_VERSION)
    audit_log = AuditLog(audit_log_path)

    # Registered out of alphabetical order, with a nested schema whose keys are
    # not alphabetical either, so a test can see order and values survive.
    @server.tool()
    def zeta_search(query: str, scope: Scope, limit: int = 10) -> str:
        """Search within a scope. Registered before `alpha_note` on purpose."""
        return f"{query}:{scope.zone}:{limit}"

    @server.tool()
    def alpha_note(text: str) -> str:
        """Store a note."""
        audit_log.record(SERVER_ID, "alpha_note", {"text": text})
        return "noted"

    @server.tool()
    def observe_meta(ctx: Context) -> str:
        """Record the `_meta` of this request in the audit log."""
        meta: dict[str, Any] = dict(ctx.request_context.meta or {})
        audit_log.record(SERVER_ID, "observe_meta", {"meta": meta})
        return "observed"

    return server
