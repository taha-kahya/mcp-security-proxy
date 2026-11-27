"""Proxy configuration schema and YAML loading.

Relative paths (`policy_path`, `audit_log_path`, `tools_path`,
`defenses_path`, `state.path`, `scan.classifier.model_dir`) resolve
against the working directory the proxy is started from, the same as the
mock servers' `--audit-log` arguments.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

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
    # SHA-256 of the file `command` launches, lowercase hex; startup fails on a
    # mismatch (plan MR E1, `app.integrity`).
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

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


class StateConfig(BaseModel):
    """`memory` loses history on restart; `sqlite` keeps it in `path`."""

    backend: Literal["memory", "sqlite"] = "memory"
    path: Path | None = None

    @model_validator(mode="after")
    def _require_path_for_sqlite(self) -> StateConfig:
        if self.backend == "sqlite" and self.path is None:
            raise ValueError("state.path is required when state.backend is 'sqlite'")
        return self


class ClassifierConfig(BaseModel):
    """Scan's classifier stage (ADR 0026). `model_dir` holds a known model
    bundle (weights, config and tokenizer, each hash-checked at startup).
    `operating_point` picks the frozen thresholds: `high_recall` (default)
    grades more tools high or critical than `balanced`, so fewer poisoned
    tools pass."""

    model_config = ConfigDict(extra="forbid")

    model_dir: Path
    operating_point: Literal["high_recall", "balanced"] = "high_recall"
    device: str = "cpu"
    token_budget: int = Field(default=8192, ge=512)
    cache_entries: int = Field(default=10_000, ge=1)
    # A scoring call that takes longer is abandoned and its tools fail closed.
    timeout_seconds: float = Field(default=600.0, gt=0)


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Unset: no classifier stage, and `context.scan.poisoning` raises.
    classifier: ClassifierConfig | None = None


class ProxyConfig(BaseModel):
    agent_transport: Transport = "stdio"
    agent_host: str = "127.0.0.1"
    agent_port: int = 9000
    identity: IdentityConfig
    policy_path: Path
    audit_log_path: Path
    servers: list[UpstreamServerConfig]
    tools_path: Path | None = None
    defenses_path: Path | None = None
    defense_deadline_seconds: float = Field(default=2.0, gt=0)
    state: StateConfig = Field(default_factory=StateConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    # Transparent mode (0023): one upstream, bare tool names, upstream server
    # identity, and request `_meta` forwarded. Opt-in; the default is unchanged.
    transparent: bool = False
    # `_meta` keys whose string, number, or boolean values the audit record
    # keeps unmasked (0013, 0023). Only meaningful in transparent mode.
    audit_meta_allowlist: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _transparent_mode_fronts_exactly_one_server(self) -> ProxyConfig:
        if self.transparent and len(self.servers) != 1:
            raise ValueError(
                f"transparent mode requires exactly one upstream server, got {len(self.servers)}"
            )
        if self.audit_meta_allowlist and not self.transparent:
            raise ValueError("audit_meta_allowlist requires transparent mode")
        return self

    @model_validator(mode="after")
    def _require_identity_for_agent_transport(self) -> ProxyConfig:
        if self.agent_transport == "stdio" and self.identity.stdio_principal is None:
            raise ValueError("identity.stdio_principal is required when agent_transport is stdio")
        if self.agent_transport == "streamable-http" and not self.identity.bearer_tokens:
            raise ValueError(
                "identity.bearer_tokens is required when agent_transport is streamable-http"
            )
        return self

    def agent_principal_ids(self) -> frozenset[str]:
        """Principals the configured agent transport can authenticate as."""
        if self.agent_transport == "stdio":
            assert self.identity.stdio_principal is not None  # enforced above
            return frozenset({self.identity.stdio_principal})
        return frozenset(entry.principal for entry in self.identity.bearer_tokens)


def load_config(path: Path) -> ProxyConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        return ProxyConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}: {exc}") from exc
