"""Server-scoped tool identity.

Two upstream servers may expose a tool with the identical bare name (e.g. both
mock servers expose `send_message`). The proxy must keep each server's
original identity rather than silently colliding on the bare name, so it
advertises a disambiguated external name and maps it back to (server_id,
bare_name) for routing.
"""

from __future__ import annotations

_DELIMITER = "__"


def external_tool_name(server_id: str, bare_name: str) -> str:
    if _DELIMITER in server_id:
        raise ValueError(f"server_id {server_id!r} must not contain {_DELIMITER!r}")
    return f"{server_id}{_DELIMITER}{bare_name}"


def parse_external_tool_name(external_name: str) -> tuple[str, str]:
    server_id, sep, bare_name = external_name.partition(_DELIMITER)
    if not sep or not server_id or not bare_name:
        raise ValueError(f"not a proxy-disambiguated tool name: {external_name!r}")
    return server_id, bare_name
