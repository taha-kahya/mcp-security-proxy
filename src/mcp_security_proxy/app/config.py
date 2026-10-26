"""Proxy configuration schema and YAML loading.

Relative paths (`policy_path`, `audit_log_path`) resolve against the working
directory the proxy is started from, the same as the mock servers'
`--audit-log` arguments.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

Transport = Literal["stdio", "streamable-http"]


class ConfigError(ValueError):
    """The config file is missing, malformed, or inconsistent."""


class UpstreamServerConfig(BaseModel):
    id: str
    command: str
    args: list[str] = Field(default_factory=list)
    transport: Transport = "stdio"
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


class BearerTokenConfig(BaseModel):
    principal: str
    token_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class IdentityConfig(BaseModel):
    """How the agent-facing listener establishes the principal (see 0011)."""

    stdio_principal: str | None = None
    bearer_tokens: list[BearerTokenConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def _token_digests_are_unique(self) -> IdentityConfig:
        counts = Counter(entry.token_sha256 for entry in self.bearer_tokens)
        if any(n > 1 for n in counts.values()):
            raise ValueError("each bearer token may be listed only once")
        return self


class ProxyConfig(BaseModel):
    agent_transport: Transport = "stdio"
    agent_host: str = "127.0.0.1"
    agent_port: int = 9000
    identity: IdentityConfig
    policy_path: Path
    audit_log_path: Path
    servers: list[UpstreamServerConfig]

    @model_validator(mode="after")
    def _require_identity_for_agent_transport(self) -> ProxyConfig:
        if self.agent_transport == "stdio" and self.identity.stdio_principal is None:
            raise ValueError("identity.stdio_principal is required when agent_transport is stdio")
        if self.agent_transport == "streamable-http" and not self.identity.bearer_tokens:
            raise ValueError(
                "identity.bearer_tokens is required when agent_transport is streamable-http"
            )
        return self


def load_config(path: Path) -> ProxyConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        return ProxyConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc
