"""Proxy configuration schema and YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator


class UpstreamServerConfig(BaseModel):
    id: str
    command: str
    args: list[str] = Field(default_factory=list)
    transport: Literal["stdio", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int | None = None
    url: str | None = None

    @model_validator(mode="after")
    def _require_connection_info_for_http(self) -> UpstreamServerConfig:
        if self.transport == "streamable-http" and (self.port is None or self.url is None):
            raise ValueError(
                f"server {self.id!r}: 'port' and 'url' are required when transport is "
                "'streamable-http'"
            )
        return self


class ProxyConfig(BaseModel):
    agent_transport: Literal["stdio", "streamable-http"] = "stdio"
    agent_host: str = "127.0.0.1"
    agent_port: int = 9000
    servers: list[UpstreamServerConfig]


def load_config(path: Path) -> ProxyConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return ProxyConfig.model_validate(data)
