"""Pure-logic tests for protocol-level error construction."""

from __future__ import annotations

import pytest
from mcp import types

from mcp_security_proxy.core.proxy.codec.jsonrpc import (
    blocked_call_result,
    ensure_call_tool_result,
    unauthenticated_error,
    unexpected_upstream_result_error,
    unknown_tool_error,
)


def test_unknown_tool_error_uses_invalid_params_not_method_not_found() -> None:
    error = unknown_tool_error("server_a__nonexistent")
    assert error.error.code == types.INVALID_PARAMS


def test_ensure_call_tool_result_passes_through_a_valid_result() -> None:
    result = types.CallToolResult(content=[])
    assert ensure_call_tool_result("server_a__write_record", result) is result


def test_ensure_call_tool_result_rejects_an_unexpected_type() -> None:
    with pytest.raises(Exception) as exc_info:
        ensure_call_tool_result("server_a__write_record", object())
    assert exc_info.value.error.code == types.INTERNAL_ERROR


def test_unexpected_upstream_result_error_uses_internal_error() -> None:
    error = unexpected_upstream_result_error("server_a__write_record", object())
    assert error.error.code == types.INTERNAL_ERROR


def test_blocked_call_result_is_a_tool_error_citing_reason_and_decision() -> None:
    result = blocked_call_result("requires approval", "abc123")

    assert result.is_error
    assert isinstance(result.content[0], types.TextContent)
    assert "requires approval" in result.content[0].text
    assert "abc123" in result.content[0].text


def test_unauthenticated_error_is_an_invalid_request() -> None:
    assert unauthenticated_error().error.code == types.INVALID_REQUEST
