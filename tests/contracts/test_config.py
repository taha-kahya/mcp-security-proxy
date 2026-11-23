"""Config loading wraps every failure in ConfigError, like load_policy does."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mcp_security_proxy.app.config import ConfigError, ProxyConfig, load_config


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


def _config_document(server_ids: list[str], **extra: object) -> dict[str, object]:
    return {
        "identity": {"stdio_principal": "agent"},
        "policy_path": "policy.yaml",
        "audit_log_path": "audit.jsonl",
        "servers": [{"id": server_id, "command": "python"} for server_id in server_ids],
        **extra,
    }


def _load(tmp_path: Path, document: dict[str, object]) -> ProxyConfig:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return load_config(path)


def test_transparent_mode_is_off_by_default(tmp_path: Path) -> None:
    config = _load(tmp_path, _config_document(["a", "b"]))

    assert config.transparent is False
    assert config.audit_meta_allowlist == []


def test_transparent_mode_accepts_exactly_one_server(tmp_path: Path) -> None:
    config = _load(tmp_path, _config_document(["a"], transparent=True))

    assert config.transparent is True


@pytest.mark.parametrize("server_ids", [["a", "b"], []])
def test_transparent_mode_rejects_any_other_number_of_servers(
    tmp_path: Path, server_ids: list[str]
) -> None:
    with pytest.raises(ConfigError, match="exactly one upstream server"):
        _load(tmp_path, _config_document(server_ids, transparent=True))


def test_audit_meta_allowlist_requires_transparent_mode(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="requires transparent mode"):
        _load(tmp_path, _config_document(["a"], audit_meta_allowlist=["eval_id"]))
