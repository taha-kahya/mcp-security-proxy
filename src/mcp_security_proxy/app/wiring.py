"""Startup wiring: loads policy and the audit sink, connects to configured
upstream servers, builds the routing table, and assembles the proxy's own
agent-facing MCP server.

This module only constructs concrete implementations and injects them; the
request lifecycle lives in `core/proxy/orchestrator.py`. Anything that can be
validated without upstream servers (policy, audit sink, identity) is checked
before any subprocess is spawned.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager

from mcp import ClientSession
from mcp.server.lowlevel import Server

from mcp_security_proxy.app.agent_facing import build_agent_facing
from mcp_security_proxy.app.config import ProxyConfig, UpstreamServerConfig
from mcp_security_proxy.core.guard import Guard
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator
from mcp_security_proxy.core.proxy.routing.correlation import CorrelationTracker
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.core.proxy.server import build_proxy_server
from mcp_security_proxy.core.proxy.transport.stdio_client import connect_stdio_upstream
from mcp_security_proxy.core.proxy.transport.streamable_http_client import (
    spawn_streamable_http_upstream,
)
from mcp_security_proxy.services.log import JsonlAuditSink
from mcp_security_proxy.services.policy import PolicyError, PolicySnapshot, load_policy

logger = logging.getLogger(__name__)


class ProxyApp:
    def __init__(self, server: Server, serve: Callable[[Server], Awaitable[None]]) -> None:
        self.server = server
        self._serve = serve

    async def serve(self) -> None:
        await self._serve(self.server)


def _connect_upstream(upstream: UpstreamServerConfig) -> AbstractAsyncContextManager[ClientSession]:
    if upstream.transport == "stdio":
        return connect_stdio_upstream(upstream.command, upstream.args)
    assert upstream.port is not None and upstream.url is not None  # enforced by config validation
    return spawn_streamable_http_upstream(
        upstream.command, upstream.args, upstream.host, upstream.port, upstream.url
    )


async def _discover_tools(sessions: Mapping[str, ClientSession]) -> RoutingTable:
    routing_table = RoutingTable()
    for server_id, session in sessions.items():
        discovered = await session.list_tools()
        routing_table.register_server_tools(server_id, discovered.tools)
    return routing_table


def _ensure_policy_targets_exist(policy: PolicySnapshot, routing_table: RoutingTable) -> None:
    unmatched = policy.unmatched_patterns(routed.tool_id for routed in routing_table.entries())
    if unmatched:
        names = ", ".join(str(pattern) for pattern in unmatched)
        raise PolicyError(f"policy rules match no discovered tool: {names}")


def warn_about_principal_mismatches(
    policy: PolicySnapshot, identity_principal_ids: frozenset[str]
) -> None:
    """Mismatches fail safe (default deny), so they are warned about, not fatal:
    one policy file may legitimately serve configs with different identities."""
    for principal_id in sorted(policy.principal_ids - identity_principal_ids):
        logger.warning(
            "policy principal %r matches no configured identity; its rules apply to nobody",
            principal_id,
        )
    for principal_id in sorted(identity_principal_ids - policy.principal_ids):
        logger.warning(
            "principal %r has no policy entry; every tool will be denied to it",
            principal_id,
        )


@asynccontextmanager
async def build_app(config: ProxyConfig) -> AsyncIterator[ProxyApp]:
    policy = load_policy(config.policy_path)
    audit = JsonlAuditSink.create(config.audit_log_path)
    agent_facing = build_agent_facing(config)
    warn_about_principal_mismatches(policy, config.agent_principal_ids())

    async with AsyncExitStack() as stack:
        sessions = {
            upstream.id: await stack.enter_async_context(_connect_upstream(upstream))
            for upstream in config.servers
        }
        routing_table = await _discover_tools(sessions)
        _ensure_policy_targets_exist(policy, routing_table)

        orchestrator = ProxyOrchestrator(
            routing=routing_table,
            upstreams=sessions,
            policy=policy,
            guard=Guard(),
            audit=audit,
            correlation=CorrelationTracker(),
        )
        server = build_proxy_server(orchestrator, agent_facing.identity)
        yield ProxyApp(server, agent_facing.serve)
