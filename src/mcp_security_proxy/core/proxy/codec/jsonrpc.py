"""Protocol-level error construction and result validation for the proxy.

The MCP SDK already validates and encodes/decodes JSON-RPC messages on each
connection. This module covers the part that's genuinely the proxy's own
responsibility: translating an internal routing miss into a correctly-shaped
protocol error, and asserting that whatever comes back from an upstream call
is a well-typed `CallToolResult` before it's passed through unchanged
(preserving its content blocks as-is, rather than flattening them).
"""

from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import MCPError


def unknown_tool_error(external_name: str) -> MCPError:
    return MCPError(code=types.INVALID_PARAMS, message=f"Unknown tool: {external_name}")


def unexpected_upstream_result_error(external_name: str, result: object) -> MCPError:
    return MCPError(
        code=types.INTERNAL_ERROR,
        message=f"Unexpected result type from upstream for tool {external_name}: {type(result)!r}",
    )


def ensure_call_tool_result(external_name: str, result: object) -> types.CallToolResult:
    if not isinstance(result, types.CallToolResult):
        raise unexpected_upstream_result_error(external_name, result)
    return result
