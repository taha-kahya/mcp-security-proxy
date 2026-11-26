"""Redacted exposure through the real proxy (plan MR D5).

A scripted discovery defense flags one field of one tool, and the operator
maps that finding to `redact`: the agent sees the tool with the field
replaced by the proxy notice, its calls are blocked as needing approval
(and never reach the server), and the discovery audit record names it. In
transparent mode the verbatim wire definition is redacted too.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from mcp import Client

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.app.wiring import build_app
from mcp_security_proxy.core.proxy.redaction import NOTICE
from mcp_security_proxy.core.runner import StaticCatalog
from mcp_security_proxy.sdk import Context, Event, Finding, Result, Severity, Stage
from tests.harness.client import PROXY_AUDIT_LOG, build_proxy_config, mock_server_entry
from tests.harness.defenses import ScriptedDefense

SCRIPT = Path(__file__).with_name("raw_upstream_script.py")
RULE = "redactor.flag"


def _flagging(tool: str, pointer: str) -> ScriptedDefense:
    async def behavior(event: Event, context: Context) -> Result:
        if event.tool_id is not None and event.tool_id.name == tool:
            return Result.completed([Finding(RULE, "direct", Severity.HIGH, "flagged", (pointer,))])
        return Result.completed()

    return ScriptedDefense("redactor", behavior=behavior, stages=frozenset({Stage.DISCOVERY}))


def _config(
    tmp_path: Path, servers: list[dict[str, Any]], transparent: bool = False
) -> ProxyConfig:
    raw = build_proxy_config(
        servers,
        "stdio",
        tmp_path,
        defenses=[{"id": "redactor", "enforcement": {"findings": {RULE: "redact"}}}],
    )
    raw["transparent"] = transparent
    return ProxyConfig.model_validate(raw)


def _discovery_records(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / PROXY_AUDIT_LOG).read_text(encoding="utf-8").splitlines()
    return [r for r in map(json.loads, lines) if r.get("kind") == "discovery"]


async def test_a_redacted_tool_is_listed_with_the_notice_and_its_calls_are_blocked(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "a.jsonl"
    defense = _flagging("read_record", "/description#0-6")
    catalog = StaticCatalog({"redactor": lambda settings: defense})
    config = _config(tmp_path, [mock_server_entry("server_a", audit, "stdio")])
    async with build_app(config, catalog) as app:
        async with Client(app.server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert tools["server_a__read_record"].description == NOTICE
            assert tools["server_a__write_record"].description != NOTICE
            result = await client.call_tool("server_a__read_record", {"key": "k"})

    assert result.is_error
    assert "redacted" in result.content[0].text  # type: ignore[union-attr]
    assert not audit.exists() or "read_record" not in audit.read_text(encoding="utf-8")
    assert _discovery_records(tmp_path)[-1]["redacted"] == ["server_a/read_record"]


async def test_a_flag_on_the_name_hides_the_tool_instead(tmp_path: Path) -> None:
    defense = _flagging("read_record", "/name")
    catalog = StaticCatalog({"redactor": lambda settings: defense})
    config = _config(tmp_path, [mock_server_entry("server_a", tmp_path / "a.jsonl", "stdio")])
    async with build_app(config, catalog) as app:
        async with Client(app.server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
    assert "server_a__read_record" not in names and "server_a__write_record" in names
    assert _discovery_records(tmp_path)[-1]["hidden_by_inspection"] == ["server_a/read_record"]


async def test_transparent_mode_redacts_the_verbatim_wire_definition(tmp_path: Path) -> None:
    defense = _flagging("zeta", "/description")
    catalog = StaticCatalog({"redactor": lambda settings: defense})
    server = {"id": "raw", "command": sys.executable, "args": [str(SCRIPT)]}
    async with build_app(_config(tmp_path, [server], transparent=True), catalog) as app:
        async with Client(app.server) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
    assert tools["zeta"].description == NOTICE
    assert tools["alpha"].description == "listed after zeta"
