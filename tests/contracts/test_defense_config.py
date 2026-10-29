"""Loading defense configs and the security half of startup wiring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_security_proxy.app.config import ConfigError, ProxyConfig, StateConfig
from mcp_security_proxy.app.defenses import load_defense_configs
from mcp_security_proxy.app.security import build_registry, load_security
from mcp_security_proxy.core.runner import DefenseLoadError, StaticCatalog
from mcp_security_proxy.services.registry import ToolSemanticsError, parse_tool_semantics
from tests.harness.control import routing_for
from tests.harness.defenses import ScriptedDefense


def _write(path: Path, data: Any) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _config(tmp_path: Path, defenses_dir: Path | None) -> ProxyConfig:
    policy = _write(tmp_path / "policy.yaml", {"schema_version": 1, "principals": {}})
    return ProxyConfig.model_validate(
        {
            "identity": {"stdio_principal": "agent"},
            "policy_path": str(policy),
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "servers": [],
            "defenses_path": str(defenses_dir) if defenses_dir else None,
        }
    )


def test_no_directory_means_no_defenses() -> None:
    assert load_defense_configs(None) == []


def test_configs_load_sorted_by_file_name(tmp_path: Path) -> None:
    _write(tmp_path / "b.yaml", {"id": "second", "enabled": False})
    _write(tmp_path / "a.yaml", {"id": "first", "settings": {"max": 3}})

    configs = load_defense_configs(tmp_path)

    assert [(c.id, c.enabled, c.settings) for c in configs] == [
        ("first", True, {"max": 3}),
        ("second", False, {}),
    ]


@pytest.mark.parametrize(
    "files",
    [
        {"a.yaml": {"id": "same"}, "b.yaml": {"id": "same"}},
        {"a.yaml": {"id": "x", "unexpected": 1}},
        {"a.yaml": {"enabled": True}},
    ],
)
def test_invalid_defense_configs_are_rejected(tmp_path: Path, files: dict[str, Any]) -> None:
    for name, data in files.items():
        _write(tmp_path / name, data)
    with pytest.raises(ConfigError):
        load_defense_configs(tmp_path)


def test_sqlite_state_requires_a_path() -> None:
    with pytest.raises(ValueError):
        StateConfig(backend="sqlite")


def test_only_enabled_defenses_are_loaded_and_their_enforcement_versions_policy(
    tmp_path: Path,
) -> None:
    defenses_dir = tmp_path / "defenses"
    defenses_dir.mkdir()
    _write(defenses_dir / "on.yaml", {"id": "on", "enforcement": {"on_failure": "allow"}})
    _write(defenses_dir / "off.yaml", {"id": "off", "enabled": False})
    catalog = StaticCatalog({"on": lambda settings: ScriptedDefense("on")})

    with_override = load_security(_config(tmp_path, defenses_dir), catalog)
    without = load_security(_config(tmp_path, None), catalog)

    assert with_override.plan.defense_ids() == ["on"]
    assert with_override.policy.version != without.policy.version


def test_enabled_defense_that_is_not_installed_stops_startup(tmp_path: Path) -> None:
    defenses_dir = tmp_path / "defenses"
    defenses_dir.mkdir()
    _write(defenses_dir / "ghost.yaml", {"id": "ghost"})

    with pytest.raises(DefenseLoadError):
        load_security(_config(tmp_path, defenses_dir), StaticCatalog({}))


def test_tool_semantics_naming_no_discovered_tool_stop_startup() -> None:
    semantics = parse_tool_semantics(
        {"schema_version": 1, "tools": {"server_a/typo": {"operation": "write"}}}
    )
    with pytest.raises(ToolSemanticsError):
        build_registry(routing_for({"server_a": ["write"]}), semantics)
