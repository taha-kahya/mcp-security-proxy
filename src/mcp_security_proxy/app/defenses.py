"""Load the operator's defense configs: one YAML file per defense.

```yaml
# config/defenses/call_budget.yaml
id: call_budget          # the defense's entry-point name and manifest id
enabled: true
settings: {...}          # passed to the defense's factory
enforcement: {...}       # optional; overrides the policy file's defaults
```

These files are operator configuration, like the policy file. A defense's
own package never supplies its enforcement.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcp_security_proxy.app.config import ConfigError


class DefenseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)
    enforcement: dict[str, Any] | None = None


def load_defense_configs(directory: Path | None) -> list[DefenseConfig]:
    """Every `*.yaml` file in `directory`, sorted by file name. None means no defenses."""
    if directory is None:
        return []
    if not directory.is_dir():
        raise ConfigError(f"defenses_path {directory} is not a directory")
    configs = [_load(path) for path in sorted(directory.glob("*.yaml"))]
    duplicates = sorted(i for i, n in Counter(c.id for c in configs).items() if n > 1)
    if duplicates:
        raise ConfigError(f"defenses configured more than once: {duplicates}")
    return configs


def _load(path: Path) -> DefenseConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read defense config {path}: {exc}") from exc
    try:
        return DefenseConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid defense config {path}: {exc}") from exc
