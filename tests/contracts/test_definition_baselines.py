"""Approved definitions (plan MR T2): stored on first sight, kept across
restarts, forgotten only by the operator; the Registry exposes them, and the
routing table can swap one server's tools on re-discovery."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml
from mcp import types

from mcp_security_proxy.app.approve_definitions import main as approve_main
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.sdk import ToolDefinition, ToolId, canonical_digest
from mcp_security_proxy.services.registry import (
    ConfiguredToolAdapter,
    DefinitionBaselines,
    Registry,
)
from mcp_security_proxy.services.state import InMemoryStateStore, SqliteStateStore

TOOL = ToolId("server_a", "read_record")
V1 = {"name": "read_record", "description": "Reads a record."}
V2 = {"name": "read_record", "description": "Reads a record and mirrors it."}


def _definition(body: dict[str, object], tool_id: ToolId = TOOL) -> ToolDefinition:
    return ToolDefinition(tool_id, canonical_digest(body), body)


async def test_the_first_definition_seen_is_approved_and_kept() -> None:
    baselines = DefinitionBaselines(InMemoryStateStore())
    first = await baselines.approve_if_new(_definition(V1))
    later = await baselines.approve_if_new(_definition(V2))
    assert first.version == later.version == canonical_digest(V1)
    assert later.definition["description"] == "Reads a record."


async def test_approved_versions_survive_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = SqliteStateStore.open(path)
    await DefinitionBaselines(store).approve_if_new(_definition(V1))
    await store.close()

    store = SqliteStateStore.open(path)
    approved = await DefinitionBaselines(store).approve_if_new(_definition(V2))
    await store.close()
    assert approved.version == canonical_digest(V1)


async def test_forgetting_lets_the_next_definition_be_approved() -> None:
    baselines = DefinitionBaselines(InMemoryStateStore())
    other = ToolId("server_a", "write_record")
    await baselines.approve_if_new(_definition(V1))
    await baselines.approve_if_new(_definition({"name": "write_record"}, other))

    assert await baselines.forget([TOOL]) == [str(TOOL)]
    assert (await baselines.approve_if_new(_definition(V2))).version == canonical_digest(V2)
    kept = await baselines.approve_if_new(_definition({"name": "changed"}, other))
    assert kept.definition == {"name": "write_record"}


async def test_forget_all_and_forgetting_twice() -> None:
    baselines = DefinitionBaselines(InMemoryStateStore())
    await baselines.approve_if_new(_definition(V1))
    assert await baselines.forget() == [str(TOOL)]
    assert await baselines.forget() == []
    assert await baselines.forget([ToolId("x", "y")]) == []


def test_the_registry_keeps_approved_and_current_apart() -> None:
    registry = Registry(ConfiguredToolAdapter.empty())
    current = registry.register(TOOL, V2)
    registry.set_approved(_definition(V1))
    assert registry.current(TOOL) == current
    approved = registry.approved(TOOL)
    assert approved is not None and approved.version == canonical_digest(V1)


def test_unregistering_drops_the_tool_but_keeps_its_approved_version() -> None:
    registry = Registry(ConfiguredToolAdapter.empty())
    registry.register(TOOL, V1)
    registry.set_approved(_definition(V1))
    registry.unregister(TOOL)
    assert registry.current(TOOL) is None and list(registry.tool_ids()) == []
    assert registry.approved(TOOL) is not None


def _tool(name: str) -> types.Tool:
    return types.Tool(name=name, input_schema={"type": "object"})


def test_replacing_one_servers_tools_leaves_the_others() -> None:
    table = RoutingTable()
    table.register_server_tools("a", [_tool("read"), _tool("old")])
    table.register_server_tools("b", [_tool("send")])
    table.replace_server_tools("a", [_tool("read"), _tool("new")])
    assert sorted(r.external_name for r in table.entries()) == ["a__new", "a__read", "b__send"]


def test_a_colliding_replacement_leaves_the_table_as_it_was() -> None:
    table = RoutingTable(transparent=True)
    table.register_server_tools("a", [_tool("read")])
    table.register_server_tools("b", [_tool("send")])
    with pytest.raises(ValueError):
        table.replace_server_tools("a", [_tool("send")])
    assert sorted(r.external_name for r in table.entries()) == ["read", "send"]


def _config(tmp_path: Path) -> Path:
    (tmp_path / "policy.yaml").write_text("principals: {}\n", encoding="utf-8")
    config = {
        "identity": {"stdio_principal": "agent"},
        "policy_path": str(tmp_path / "policy.yaml"),
        "audit_log_path": str(tmp_path / "audit.jsonl"),
        "state": {"backend": "sqlite", "path": str(tmp_path / "state.sqlite3")},
        "servers": [{"id": "server_a", "command": "python"}],
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


async def _approve(tmp_path: Path) -> None:
    store = SqliteStateStore.open(tmp_path / "state.sqlite3")
    await DefinitionBaselines(store).approve_if_new(_definition(V1))
    await store.close()


def test_the_cli_forgets_named_tools(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = _config(tmp_path)
    asyncio.run(_approve(tmp_path))
    assert approve_main(["--config", str(config), "server_a/read_record"]) == 0
    assert "forgot server_a/read_record" in capsys.readouterr().out
    assert approve_main(["--config", str(config), "--all"]) == 0
    assert "nothing to forget" in capsys.readouterr().out


def test_the_cli_rejects_a_bad_tool_id(tmp_path: Path) -> None:
    assert approve_main(["--config", str(_config(tmp_path)), "not-a-tool-id"]) == 2


def test_the_cli_needs_tools_or_all(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        approve_main(["--config", str(_config(tmp_path))])
