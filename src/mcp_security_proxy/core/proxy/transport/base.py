"""Transport adapter contract. Implementations (stdio, Streamable HTTP) land in MR4/MR5."""

from __future__ import annotations

from typing import Protocol


class ClientTransport(Protocol):
    """Proxy's outbound connection to a single upstream MCP server."""


class ServerTransport(Protocol):
    """Proxy's inbound, agent-facing MCP listener."""
