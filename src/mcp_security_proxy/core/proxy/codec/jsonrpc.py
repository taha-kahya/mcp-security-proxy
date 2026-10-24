"""Protocol-level error construction and result validation for the proxy.

The MCP SDK already validates and encodes/decodes JSON-RPC messages on each
connection. This module covers the part that's genuinely the proxy's own
responsibility: translating routing misses, denials, and missing identity
into correctly-shaped protocol responses, and asserting that whatever comes
back from an upstream call is a well-typed `CallToolResult` before it's
passed through unchanged (preserving its content blocks as-is, rather than
flattening them).

A tool the principal may not discover is answered with exactly the same
`unknown_tool_error` as a nonexistent tool, so its existence never leaks
(see 0012).
"""

from __future__ import annotations

from mcp import types
from mcp.shared.exceptions import MCPError


def unknown_tool_error(external_name: str) -> MCPError:
    return MCPError(code=types.INVALID_PARAMS, message=f"Unknown tool: {external_name}")


def unauthenticated_error() -> MCPError:
    return MCPError(code=types.INVALID_REQUEST, message="Unauthenticated request")


def blocked_call_result(reason: str, decision_id: str) -> types.CallToolResult:
    """A tool-level error for a call the agent may see but that was not dispatched."""
    message = f"Call blocked: {reason} (decision {decision_id})."
    return types.CallToolResult(content=[types.TextContent(text=message)], is_error=True)


def unexpected_upstream_result_error(external_name: str, result: object) -> MCPError:
    return MCPError(
        code=types.INTERNAL_ERROR,
        message=f"Unexpected result type from upstream for tool {external_name}: {type(result)!r}",
    )


def ensure_call_tool_result(external_name: str, result: object) -> types.CallToolResult:
    if not isinstance(result, types.CallToolResult):
        raise unexpected_upstream_result_error(external_name, result)
    return result
