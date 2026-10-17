"""Proxy configuration schema and YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class UpstreamServerConfig(BaseModel):
    id: str
    command: str
    args: list[str] = Field(default_factory=list)


class ProxyConfig(BaseModel):
    agent_transport: Literal["stdio"] = "stdio"
    servers: list[UpstreamServerConfig]


def load_config(path: Path) -> ProxyConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ProxyConfig.model_validate(data)
