"""Pure-logic tests for tool identity disambiguation and the routing table.

No subprocess involved: this exercises the collision-handling data structures
directly, independent of any live mock server.
"""

from __future__ import annotations

import pytest
from mcp import types

from mcp_security_proxy.core.proxy.routing.identity import (
    external_tool_name,
    parse_external_tool_name,
)
from mcp_security_proxy.core.proxy.routing.table import RoutingTable


def _tool(name: str) -> types.Tool:
    return types.Tool(name=name, inputSchema={"type": "object", "properties": {}})


def test_external_tool_name_round_trips() -> None:
    name = external_tool_name("server_a", "send_message")
    assert name == "server_a__send_message"
    assert parse_external_tool_name(name) == ("server_a", "send_message")


def test_external_tool_name_rejects_delimiter_in_server_id() -> None:
    with pytest.raises(ValueError):
        external_tool_name("server__a", "send_message")


def test_parse_external_tool_name_rejects_malformed_input() -> None:
    with pytest.raises(ValueError):
        parse_external_tool_name("not_disambiguated")


def test_routing_table_disambiguates_colliding_bare_names() -> None:
    table = RoutingTable()
    table.register_server_tools("server_a", [_tool("send_message")])
    table.register_server_tools("server_b", [_tool("send_message")])

    external_names = {t.name for t in table.all_tools()}
    assert external_names == {"server_a__send_message", "server_b__send_message"}

    routed_a = table.resolve("server_a__send_message")
    assert routed_a.server_id == "server_a"
    assert routed_a.bare_name == "send_message"

    routed_b = table.resolve("server_b__send_message")
    assert routed_b.server_id == "server_b"
    assert routed_b.bare_name == "send_message"


def test_routing_table_resolve_unknown_tool_raises() -> None:
    table = RoutingTable()
    table.register_server_tools("server_a", [_tool("read_record")])
    with pytest.raises(KeyError):
        table.resolve("server_a__nonexistent")


def test_routing_table_preserves_original_tool_metadata() -> None:
    original = types.Tool(
        name="send_message",
        description="Send a message",
        inputSchema={"type": "object", "properties": {"recipient": {"type": "string"}}},
    )
    table = RoutingTable()
    table.register_server_tools("server_a", [original])

    (exposed,) = table.all_tools()
    assert exposed.name == "server_a__send_message"
    assert exposed.description == original.description
    assert exposed.input_schema == original.input_schema
