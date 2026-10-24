"""Pair the agent-facing transport with the identity mechanism it supports.

Each transport authenticates differently (see 0011), so the listener and the
resolver that reads its credentials are always chosen together.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial

from mcp.server.lowlevel import Server

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.core.identity import (
    BearerTokenPrincipalResolver,
    IdentityResolver,
    StaticPrincipalResolver,
    StaticTokenVerifier,
)
from mcp_security_proxy.core.proxy.transport.stdio_server import serve_stdio
from mcp_security_proxy.core.proxy.transport.streamable_http_server import serve_streamable_http


@dataclass(frozen=True)
class AgentFacing:
    identity: IdentityResolver
    serve: Callable[[Server], Awaitable[None]]


def build_agent_facing(config: ProxyConfig) -> AgentFacing:
    if config.agent_transport == "stdio":
        principal_id = config.identity.stdio_principal
        assert principal_id is not None  # enforced by config validation
        return AgentFacing(identity=StaticPrincipalResolver(principal_id), serve=serve_stdio)

    verifier = StaticTokenVerifier(
        {entry.token_sha256: entry.principal for entry in config.identity.bearer_tokens}
    )
    return AgentFacing(
        identity=BearerTokenPrincipalResolver(),
        serve=partial(
            serve_streamable_http,
            host=config.agent_host,
            port=config.agent_port,
            token_verifier=verifier,
        ),
    )
