"""Build a real `ProxyOrchestrator` in-process, with in-test defenses and fakes.

Uses the same startup helpers as the app (`build_registry`, `build_control`),
so lifecycle tests exercise production wiring without subprocesses.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mcp import types

from mcp_security_proxy.app.security import (
    AVAILABLE_CAPABILITIES,
    SecuritySetup,
    build_control,
    build_registry,
)
from mcp_security_proxy.core.proxy.orchestrator import ProxyOrchestrator, ToolCaller
from mcp_security_proxy.core.proxy.routing.correlation import CorrelationTracker
from mcp_security_proxy.core.proxy.routing.table import RoutingTable
from mcp_security_proxy.core.runner import DefenseSpec, StaticCatalog, build_plan
from mcp_security_proxy.sdk import Defense
from mcp_security_proxy.services.history import History
from mcp_security_proxy.services.log import AuditSink
from mcp_security_proxy.services.policy import parse_policy
from mcp_security_proxy.services.registry import ConfiguredToolAdapter, parse_tool_semantics
from mcp_security_proxy.services.state import InMemoryStateStore, StateStore


def tool(name: str) -> types.Tool:
    return types.Tool(name=name, input_schema={"type": "object", "properties": {}})


def routing_for(tools_by_server: Mapping[str, Sequence[str]]) -> RoutingTable:
    routing = RoutingTable()
    for server_id, names in tools_by_server.items():
        routing.register_server_tools(server_id, [tool(name) for name in names])
    return routing


@dataclass
class ProxyUnderTest:
    orchestrator: ProxyOrchestrator
    history: History
    correlation: CorrelationTracker


def build_proxy(
    *,
    routing: RoutingTable,
    upstreams: Mapping[str, ToolCaller],
    policy: Mapping[str, Any],
    audit: AuditSink,
    defenses: Sequence[Defense] = (),
    enforcement_overrides: Mapping[str, object] | None = None,
    tool_operations: Mapping[str, str] | None = None,
    state: StateStore | None = None,
    deadline_seconds: float = 1.0,
) -> ProxyUnderTest:
    """`tool_operations` maps `server_id/tool` to an operation name."""
    catalog = StaticCatalog({d.manifest().id: _factory(d) for d in defenses})
    plan = build_plan(
        [DefenseSpec(d.manifest().id) for d in defenses], catalog, AVAILABLE_CAPABILITIES
    )
    semantics = (
        parse_tool_semantics(
            {
                "schema_version": 1,
                "tools": {t: {"operation": op} for t, op in tool_operations.items()},
            }
        )
        if tool_operations
        else ConfiguredToolAdapter.empty()
    )
    setup = SecuritySetup(
        policy=parse_policy(policy, enforcement_overrides),
        plan=plan,
        tool_semantics=semantics,
        defense_deadline_seconds=deadline_seconds,
    )
    store = state or InMemoryStateStore()
    history = History(store)
    correlation = CorrelationTracker()
    orchestrator = ProxyOrchestrator(
        routing=routing,
        upstreams=upstreams,
        control=build_control(setup, build_registry(routing, semantics), history, store),
        audit=audit,
        correlation=correlation,
    )
    return ProxyUnderTest(orchestrator, history, correlation)


def _factory(defense: Defense) -> Any:
    return lambda settings: defense
