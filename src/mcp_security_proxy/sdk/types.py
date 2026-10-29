"""Identifiers for who is calling and what is being called."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    """A caller identity verified by Identity, never taken from a message payload.

    `authenticated_by` names the mechanism that established it (e.g.
    `static_config` for stdio, `bearer_token` for Streamable HTTP), so audit
    records show how strong the identity claim is.
    """

    id: str
    authenticated_by: str


@dataclass(frozen=True)
class ToolId:
    """Server-scoped tool identity: never a bare tool name alone."""

    server_id: str
    name: str

    @classmethod
    def parse(cls, text: str) -> ToolId:
        """Parse the `server_id/name` form produced by `str()`."""
        server_id, separator, name = text.partition("/")
        if not separator or not server_id or not name or "/" in name:
            raise ValueError(f"tool id must look like 'server_id/tool_name': {text!r}")
        return cls(server_id=server_id, name=name)

    def __str__(self) -> str:
        return f"{self.server_id}/{self.name}"
