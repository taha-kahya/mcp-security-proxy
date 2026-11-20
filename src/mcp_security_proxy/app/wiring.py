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
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

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


class _RawToolPage(BaseModel):
    """One `tools/list` page kept as plain JSON objects, so the upstream's key
    order and any field the typed model does not declare survive."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    tools: list[dict[str, Any]]
    next_cursor: str | None = None


async def _raw_tool_definitions(session: ClientSession) -> list[dict[str, Any]]:
    """Every page of the upstream's tool list, fetched once, as raw JSON objects."""
    tools: list[dict[str, Any]] = []
    seen: set[str] = set()
    cursor: str | None = None
    while True:
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await session.send_request(types.ListToolsRequest(params=params), _RawToolPage)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools
        if cursor in seen:
            raise ValueError("upstream tools/list repeated a pagination cursor")
        seen.add(cursor)


def _share_tool_listing_with_session(session: ClientSession, tools: list[types.Tool]) -> None:
    """Give the session the listing already fetched, so it never lists again.

    The SDK checks a tool result against the output schema cached by
    `ClientSession.list_tools()`, and calls `list_tools()` itself the first time
    it meets a tool it has not cached. Transparent mode fetches the raw list
    without `list_tools()`, so without this a second `tools/list` would happen
    at the first call, and an upstream could serve a different `outputSchema`
    than the one inspected. The SDK has no public way to seed that cache, so
    this uses the same private method `list_tools()` uses to fill it; a test
    (`test_the_upstream_is_listed_once_*`) fails if the SDK stops behaving so.
    """
    session._absorb_tool_listing(types.ListToolsResult(tools=tools), complete=True)


async def _discover_tools(
    sessions: Mapping[str, ClientSession], *, transparent: bool = False
) -> RoutingTable:
    routing_table = RoutingTable(transparent=transparent)
    for server_id, session in sessions.items():
        if transparent:
            # One fetch: the typed tool is built from the same JSON object the
            # agent will receive and the defenses and Registry will see.
            raw = await _raw_tool_definitions(session)
            tools = [types.Tool.model_validate(definition) for definition in raw]
            _share_tool_listing_with_session(session, tools)
            routing_table.register_server_tools(server_id, tools, raw)
        else:
            routing_table.register_server_tools(server_id, (await session.list_tools()).tools)
    return routing_table


def _upstream_identity(
    sessions: Mapping[str, ClientSession],
) -> tuple[types.Implementation | None, str | None]:
    """The sole upstream's `serverInfo` and `instructions`, as it reported them
    on initialize. No `serverInfo` means the proxy keeps its own name."""
    (session,) = sessions.values()  # transparent mode has exactly one (see ProxyConfig)
    return session.server_info, session.instructions


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
        server_info, instructions = (
            _upstream_identity(sessions) if config.transparent else (None, None)
        )
        if instructions:
            logger.warning(
                "transparent mode forwards the upstream's server instructions unchanged "
                "(ADR 0023 decision 4); they are not inspected"
            )
        server = build_proxy_server(
            orchestrator,
            agent_facing.identity,
            server_info,
            instructions,
            verbatim_tools=config.transparent,
        )
        yield ProxyApp(server, agent_facing.serve)
