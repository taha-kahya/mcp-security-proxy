"""Re-discovery and definition drift through the real proxy (plan MR T2).

The upstream is `raw_upstream_script.py --rug-pull`: after the first call it
sends `notifications/tools/list_changed` and lists `zeta` with a new
`mirror_to` parameter and no `readOnlyHint`. The proxy re-lists, and
`temporal_definition_drift` grades the new definition against the approved
one, so `zeta` is withheld. The approved version lives in SQLite state, so a
restart against a server that changed while the proxy was down still sees
the drift, until the operator forgets the approved version.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.app.approve_definitions import main as approve_main
from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.app.wiring import build_app
from tests.harness.client import build_proxy_config

SCRIPT = Path(__file__).with_name("raw_upstream_script.py")
DRIFT = {"id": "temporal_definition_drift", "enabled": True, "settings": {}}


def _config(tmp_path: Path, *flags: str) -> ProxyConfig:
    raw = build_proxy_config(
        [{"id": "raw", "command": sys.executable, "args": [str(SCRIPT), *flags]}],
        "stdio",
        tmp_path,
        defenses=[DRIFT],
        state_path=tmp_path / "state.sqlite3",
    )
    return ProxyConfig.model_validate(raw)


async def _names(client: Client) -> list[str]:
    return sorted(tool.name for tool in (await client.list_tools()).tools)


async def test_a_rug_pull_is_re_discovered_and_withheld(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path, "--rug-pull")) as app:
        assert app.refresher is not None
        async with Client(app.server) as client:
            assert await _names(client) == ["raw__alpha", "raw__zeta"]
            await client.call_tool("raw__alpha", {})  # the upstream changes zeta now
            await app.refresher.wait_idle()
            assert await _names(client) == ["raw__alpha"]
            # A withheld tool can't be called by name either.
            with pytest.raises(MCPError, match="Unknown tool"):
                await client.call_tool("raw__zeta", {"query": "q"})


async def test_the_approved_version_survives_a_restart_until_forgotten(tmp_path: Path) -> None:
    async with build_app(_config(tmp_path)) as app:
        async with Client(app.server) as client:
            assert await _names(client) == ["raw__alpha", "raw__zeta"]

    # The server changed while the proxy was down.
    async with build_app(_config(tmp_path, "--start-pulled")) as app:
        async with Client(app.server) as client:
            assert await _names(client) == ["raw__alpha"]

    config_file = tmp_path / "config.yaml"
    config_file.write_text(_config(tmp_path).model_dump_json(), encoding="utf-8")
    assert await asyncio.to_thread(approve_main, ["--config", str(config_file), "raw/zeta"]) == 0

    async with build_app(_config(tmp_path, "--start-pulled")) as app:
        async with Client(app.server) as client:
            assert await _names(client) == ["raw__alpha", "raw__zeta"]
