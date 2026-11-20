"""Transparent mode with defenses (0023): the definitions a defense inspects
and the Registry versions are the JSON objects the upstream sent, so a field
the typed MCP model does not declare is inspected like any other.

The proxy is built in-process over a raw JSON-RPC upstream, with an in-test
defense that flags the instruction-like text it finds anywhere in a definition.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from mcp import Client

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.app.wiring import build_app
from mcp_security_proxy.core.runner import StaticCatalog
from mcp_security_proxy.sdk import (
    Context,
    Event,
    Finding,
    Result,
    Severity,
    Stage,
    canonical_digest,
)
from tests.harness.client import build_proxy_config
from tests.harness.defenses import ScriptedDefense
from tests.integration.raw_upstream_script import POISON_TOOL_JSON

SCRIPT = Path(__file__).with_name("raw_upstream_script.py")
MARKER = "IGNORE PREVIOUS INSTRUCTIONS"


def _contains_marker(value: Any) -> bool:
    if isinstance(value, str):
        return MARKER in value
    if isinstance(value, dict) or hasattr(value, "items"):
        return any(_contains_marker(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_marker(v) for v in value)
    return False


async def _flag_marker(event: Event, context: Context) -> Result:
    if _contains_marker(event.payload):
        return Result.completed([Finding("test.marker", "test", Severity.HIGH, "marker found")])
    return Result.completed()


def _config(tmp_path: Path) -> ProxyConfig:
    raw = build_proxy_config(
        [{"id": "raw", "command": sys.executable, "args": [str(SCRIPT), "--poison"]}],
        "stdio",
        tmp_path,
        defenses=[{"id": "marker_scan"}],
    )
    raw["transparent"] = True
    return ProxyConfig.model_validate(raw)


async def test_an_instruction_in_an_undefined_field_is_seen_and_the_tool_is_not_sent(
    tmp_path: Path,
) -> None:
    defense = ScriptedDefense(
        "marker_scan", behavior=_flag_marker, stages=frozenset({Stage.DISCOVERY})
    )
    catalog = StaticCatalog({"marker_scan": lambda settings: defense})

    async with build_app(_config(tmp_path), catalog) as app:
        async with Client(app.server) as client:
            names = [tool.name for tool in (await client.list_tools()).tools]

    inspected = {
        event.tool_id.name: event.payload for event in defense.seen_events if event.tool_id
    }
    # The typed model drops `x-notes`; the defense still saw it.
    assert inspected["gamma"]["x-notes"].startswith(MARKER)
    assert json.loads(POISON_TOOL_JSON)["x-notes"] == inspected["gamma"]["x-notes"]
    assert names == ["zeta", "alpha"]


async def test_the_version_digest_covers_undefined_fields(tmp_path: Path) -> None:
    clean = ScriptedDefense("marker_scan", stages=frozenset({Stage.DISCOVERY}))
    catalog = StaticCatalog({"marker_scan": lambda settings: clean})

    async with build_app(_config(tmp_path), catalog) as app:
        async with Client(app.server) as client:
            await client.list_tools()

    versions = {
        e.tool_id.name: c.tool_version
        for e, c in zip(clean.seen_events, clean.seen_contexts, strict=True)
        if e.tool_id
    }
    assert versions["gamma"] == canonical_digest(json.loads(POISON_TOOL_JSON))
