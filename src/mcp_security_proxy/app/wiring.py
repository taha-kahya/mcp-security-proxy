"""Startup wiring: loads policy, defenses, state, and the audit sink,
connects to configured upstream servers, builds the routing table and
registry, and assembles the proxy's own agent-facing MCP server.

This module only constructs concrete implementations and injects them; the
request lifecycle lives in `core/proxy/orchestrator.py`, and the security
components are assembled in `app/security.py`. Anything that can be
validated without upstream servers (policy, defenses, tool semantics, state,
audit sink, identity) is checked before any subprocess is spawned.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from typing import Any

from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from pydantic import BaseModel

from mcp_security_proxy.app.agent_facing import build_agent_facing
from mcp_security_proxy.app.config import ProxyConfig, UpstreamServerConfig
from mcp_security_proxy.app.security import (
    build_control,
    build_registry,
    load_security,
    open_state,
)
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator
from mcp_security_proxy.core.proxy.routing.correlation import CorrelationTracker
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.core.proxy.server import build_proxy_server
from mcp_security_proxy.core.proxy.transport.stdio_client import connect_stdio_upstream
from mcp_security_proxy.core.proxy.transport.streamable_http_client import (
    spawn_streamable_http_upstream,
)
from mcp_security_proxy.core.runner import DefenseCatalog, EntryPointCatalog
from mcp_security_proxy.services.history import History
from mcp_security_proxy.services.log import JsonlAuditSink
from mcp_security_proxy.services.policy import PolicyError, PolicySnapshot

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


class _RawToolList(BaseModel):
    """A `tools/list` result kept as plain JSON objects, so the upstream's key
    order and any field the typed model does not declare survive."""

    tools: list[dict[str, Any]]


async def _raw_tool_definitions(session: ClientSession) -> list[dict[str, Any]]:
    result = await session.send_request(types.ListToolsRequest(), _RawToolList)
    return result.tools


async def _discover_tools(
    sessions: Mapping[str, ClientSession], *, transparent: bool = False
) -> RoutingTable:
    routing_table = RoutingTable(transparent=transparent)
    for server_id, session in sessions.items():
        discovered = await session.list_tools()
        raw = await _raw_tool_definitions(session) if transparent else None
        routing_table.register_server_tools(server_id, discovered.tools, raw)
    return routing_table


def _upstream_identity(sessions: Mapping[str, ClientSession]) -> types.Implementation | None:
    """The sole upstream's name and version, as it reported them on initialize.
    None when it reported none, in which case the proxy keeps its own name."""
    (session,) = sessions.values()  # transparent mode has exactly one (see ProxyConfig)
    return session.server_info


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


async def _recover_history(history: History) -> None:
    recovered = await history.recover_interrupted()
    if recovered:
        logger.warning(
            "%d task(s) had operations interrupted by a restart; marked outcome-unknown",
            recovered,
        )


@asynccontextmanager
async def build_app(
    config: ProxyConfig, catalog: DefenseCatalog | None = None
) -> AsyncIterator[ProxyApp]:
    """`catalog` defaults to the installed `mcp_security_proxy.defenses` entry points."""
    security = load_security(config, catalog or EntryPointCatalog())
    audit = JsonlAuditSink.create(config.audit_log_path)
    agent_facing = build_agent_facing(config)
    warn_about_principal_mismatches(security.policy, config.agent_principal_ids())

    async with AsyncExitStack() as stack:
        state = open_state(config.state)
        stack.push_async_callback(state.close)
        history = History(state)
        await _recover_history(history)

        sessions = {
            upstream.id: await stack.enter_async_context(_connect_upstream(upstream))
            for upstream in config.servers
        }
        routing_table = await _discover_tools(sessions, transparent=config.transparent)
        _ensure_policy_targets_exist(security.policy, routing_table)
        registry = build_registry(routing_table, security.tool_semantics)

        orchestrator = ProxyOrchestrator(
            routing=routing_table,
            upstreams=sessions,
            control=build_control(security, registry, history, state),
            audit=audit,
            correlation=CorrelationTracker(),
            forward_meta=config.transparent,
            unmasked_meta_keys=config.audit_meta_allowlist,
        )
        server = build_proxy_server(
            orchestrator,
            agent_facing.identity,
            _upstream_identity(sessions) if config.transparent else None,
            verbatim_tools=config.transparent,
        )
        yield ProxyApp(server, agent_facing.serve)
