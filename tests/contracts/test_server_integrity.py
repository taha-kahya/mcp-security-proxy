"""Pinned server files (plan MR E1): a matching SHA-256 is verified and the
hashed file is what gets launched; a mismatch or a missing file stops startup
before anything is spawned; an unpinned server is reported as unpinned."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from mcp import Client

from mcp_security_proxy.app.config import ConfigError, ProxyConfig, UpstreamServerConfig
from mcp_security_proxy.app.integrity import (
    Integrity,
    ServerIntegrityError,
    check_server,
    check_servers,
    file_sha256,
    resolve_command,
)
from mcp_security_proxy.app.wiring import build_app
from tests.harness.client import build_proxy_config, mock_server_entry

PYTHON_SHA256 = file_sha256(Path(sys.executable))


def _server(command: str, sha256: str | None = None, **fields: object) -> UpstreamServerConfig:
    return UpstreamServerConfig.model_validate(
        {"id": "srv", "command": command, "sha256": sha256, **fields}
    )


def _script(tmp_path: Path, content: bytes = b"print('hi')\n") -> Path:
    path = tmp_path / "server.py"
    path.write_bytes(content)
    return path


def test_a_matching_pin_is_verified_and_launches_the_hashed_file(tmp_path: Path) -> None:
    script = _script(tmp_path)
    result = check_server(_server(str(script), hashlib.sha256(script.read_bytes()).hexdigest()))
    assert result.status is Integrity.VERIFIED
    assert result.command == str(script.resolve())


def test_a_changed_file_stops_startup_naming_the_server(tmp_path: Path) -> None:
    script = _script(tmp_path)
    pin = hashlib.sha256(script.read_bytes()).hexdigest()
    script.write_bytes(b"print('tampered')\n")
    with pytest.raises(ServerIntegrityError, match="server 'srv'.*refusing to start"):
        check_server(_server(str(script), pin))


def test_a_missing_pinned_file_stops_startup(tmp_path: Path) -> None:
    with pytest.raises(ServerIntegrityError, match="not found"):
        check_server(_server(str(tmp_path / "gone.py"), "0" * 64))


def test_an_unpinned_server_is_reported_and_launched_as_configured() -> None:
    result = check_server(_server("python"))
    assert result.status is Integrity.UNPINNED and result.command == "python"


def test_a_bare_command_is_resolved_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    interpreter = Path(sys.executable)
    monkeypatch.setenv("PATH", str(interpreter.parent))
    assert resolve_command(interpreter.name) == interpreter.resolve()
    result = check_server(_server(interpreter.name, PYTHON_SHA256))
    assert result.status is Integrity.VERIFIED
    assert result.command == str(interpreter.resolve())


def test_check_servers_stops_at_the_first_bad_pin(tmp_path: Path) -> None:
    script = _script(tmp_path)
    good = _server(str(script), hashlib.sha256(script.read_bytes()).hexdigest())
    bad = UpstreamServerConfig.model_validate(
        {"id": "bad", "command": str(script), "sha256": "f" * 64}
    )
    assert check_servers([good])["srv"].status is Integrity.VERIFIED
    with pytest.raises(ServerIntegrityError, match="'bad'"):
        check_servers([good, bad])


def test_server_integrity_errors_are_config_errors() -> None:
    assert issubclass(ServerIntegrityError, ConfigError)


@pytest.mark.parametrize(
    "pin",
    [
        pytest.param("A" * 64, id="uppercase"),
        pytest.param("abc", id="short"),
        pytest.param("g" * 64, id="not hex"),
    ],
)
def test_malformed_pins_are_rejected_by_the_config(pin: str) -> None:
    with pytest.raises(ValueError):
        _server("python", pin)


async def test_a_pinned_server_starts_and_serves(tmp_path: Path) -> None:
    entry = mock_server_entry("server_a", tmp_path / "a.jsonl", "stdio") | {"sha256": PYTHON_SHA256}
    config = ProxyConfig.model_validate(build_proxy_config([entry], "stdio", tmp_path))
    async with build_app(config) as app:
        async with Client(app.server) as client:
            assert (await client.list_tools()).tools


async def test_a_bad_pin_stops_build_app_before_any_server_is_spawned(tmp_path: Path) -> None:
    audit = tmp_path / "a.jsonl"
    entry = mock_server_entry("server_a", audit, "stdio") | {"sha256": "0" * 64}
    config = ProxyConfig.model_validate(build_proxy_config([entry], "stdio", tmp_path))
    with pytest.raises(ServerIntegrityError):
        async with build_app(config):
            pass
    assert not audit.exists()
