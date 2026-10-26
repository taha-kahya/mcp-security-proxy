"""Pair the agent-facing transport with the identity mechanism it supports.

Each transport authenticates differently (see 0011), so the listener and the
resolver that reads its credentials are always chosen together.

The HTTP listener speaks plain HTTP, so bearer tokens are only safe on a
loopback address; binding anywhere else is allowed but warned about (see 0014).
"""

from __future__ import annotations

import ipaddress
import logging
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

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentFacing:
    identity: IdentityResolver
    serve: Callable[[Server], Awaitable[None]]


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # any other hostname may resolve off-host


def _warn_if_exposed(host: str) -> None:
    if not is_loopback_host(host):
        logger.warning(
            "agent_host %r is not a loopback address: bearer tokens and tool traffic "
            "travel unencrypted. Keep it on 127.0.0.1 or put a TLS-terminating "
            "reverse proxy in front (see docs/decisions/0014).",
            host,
        )


def build_agent_facing(config: ProxyConfig) -> AgentFacing:
    if config.agent_transport == "stdio":
        principal_id = config.identity.stdio_principal
        assert principal_id is not None  # enforced by config validation
        return AgentFacing(identity=StaticPrincipalResolver(principal_id), serve=serve_stdio)

    _warn_if_exposed(config.agent_host)
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
