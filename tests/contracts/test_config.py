"""Config loading wraps every failure in ConfigError, like load_policy does."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_security_proxy.app.config import ConfigError, load_config


def test_load_config_wraps_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "missing.yaml")


def test_load_config_wraps_malformed_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("servers: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(path)


def test_load_config_wraps_schema_violations(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("agent_transport: stdio\nservers: []\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid config"):
        load_config(path)
