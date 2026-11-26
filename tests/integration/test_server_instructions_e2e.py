"""Server instructions through the real proxy (plan MR I4).

Outside transparent mode the proxy inspects each upstream's `initialize`
instructions at startup with `indirect_result_injection`, forwards only
those no defense objected to, inside its own quoted block, and records the
decision. Uninspected instructions are withheld.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from mcp import Client

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.app.wiring import build_app
from mcp_security_proxy.core.proxy.instructions import HEADER
from tests.harness.client import PROXY_AUDIT_LOG, build_proxy_config

SCRIPT = Path(__file__).with_name("raw_upstream_script.py")
I1 = {"id": "indirect_result_injection", "enabled": True, "settings": {}}


def _config(
    tmp_path: Path, *flags: str, defenses: list[dict[str, Any]] | None = None
) -> ProxyConfig:
    raw = build_proxy_config(
        [{"id": "raw", "command": sys.executable, "args": [str(SCRIPT), *flags]}],
        "stdio",
        tmp_path,
        defenses=defenses,
    )
    return ProxyConfig.model_validate(raw)


def _instruction_records(tmp_path: Path) -> list[dict[str, Any]]:
    lines = (tmp_path / PROXY_AUDIT_LOG).read_text(encoding="utf-8").splitlines()
    return [r for r in map(json.loads, lines) if r.get("kind") == "instructions"]


async def test_clean_instructions_are_forwarded_inside_the_proxy_block(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path, "--identity", defenses=[I1])) as app:
        async with Client(app.server) as client:
            instructions = client.instructions
    assert instructions == f'{HEADER}\n- server "raw": "Use the raw tools."'
    [record] = _instruction_records(tmp_path)
    assert record["server_id"] == "raw" and record["forwarded"] is True


async def test_flagged_instructions_are_withheld(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path, "--inject-instructions", defenses=[I1])) as app:
        async with Client(app.server) as client:
            instructions = client.instructions
    assert instructions is None
    [record] = _instruction_records(tmp_path)
    assert record["forwarded"] is False
    assert record["inspections"][0]["finding_rule_ids"] == [
        "indirect_result_injection.instructions"
    ]


async def test_uninspected_instructions_are_withheld(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path, "--identity")) as app:
        async with Client(app.server) as client:
            instructions = client.instructions
    assert instructions is None
    assert _instruction_records(tmp_path)[0]["forwarded"] is False


async def test_a_server_without_instructions_adds_nothing(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path, defenses=[I1])) as app:
        async with Client(app.server) as client:
            instructions = client.instructions
    assert instructions is None and _instruction_records(tmp_path) == []
