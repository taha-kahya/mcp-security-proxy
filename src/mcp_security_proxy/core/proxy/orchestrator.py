"""The proxy's request lifecycle for tool discovery and tool calls.

For every call: route the name, let Guard decide, record the decision, then
either answer with a denial or dispatch upstream and record the outcome. The
orchestrator holds no policy rules and no detection logic of its own; it
coordinates the modules that do.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import anyio
from mcp import types
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.core.guard import Decision, Guard
from mcp_security_proxy.core.proxy.audit import decision_record, discovery_record, outcome_record
from mcp_security_proxy.core.proxy.codec.jsonrpc import (
    audit_unavailable_error,
    blocked_call_result,
    ensure_call_tool_result,
    unknown_tool_error,
)
from mcp_security_proxy.core.proxy.routing.correlation import (
    CallStatus,
    CorrelationTracker,
    new_correlation_id,
)
from mcp_security_proxy.core.proxy.routing.table import RoutedTool, RoutingTable
from mcp_security_proxy.sdk import Principal
from mcp_security_proxy.services.log import AuditRecord, AuditSink, AuditWriteError
from mcp_security_proxy.services.policy import PolicySnapshot, PrincipalPolicy

logger = logging.getLogger(__name__)

# Upstream errors after which the call may or may not have taken effect.
_OUTCOME_UNCERTAIN_ERROR_CODES = frozenset({types.CONNECTION_CLOSED, types.REQUEST_TIMEOUT})


class ToolCaller(Protocol):
    """The one upstream capability the orchestrator needs (`ClientSession` satisfies it)."""

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult: ...


@dataclass(frozen=True)
class _AuthorizedCall:
    principal: Principal
    correlation_id: str
    decision: Decision
    routed: RoutedTool


class ProxyOrchestrator:
    def __init__(
        self,
        *,
        routing: RoutingTable,
        upstreams: Mapping[str, ToolCaller],
        policy: PolicySnapshot,
        guard: Guard,
        audit: AuditSink,
        correlation: CorrelationTracker,
    ) -> None:
        self._routing = routing
        self._upstreams = upstreams
        self._policy = policy
        self._guard = guard
        self._audit = audit
        self._correlation = correlation

    async def list_tools(self, principal: Principal) -> list[types.Tool]:
        policy = self._policy.for_principal(principal)
        visible = [
            routed.external_tool()
            for routed in self._routing.entries()
            if policy.can_discover(routed.tool_id)
        ]
        await self._record_or_refuse(
            discovery_record(principal, policy.policy_version, len(visible))
        )
        return visible

    async def call_tool(
        self, principal: Principal, external_name: str, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        policy = self._policy.for_principal(principal)
        routed = self._routing.find(external_name)
        tool_id = routed.tool_id if routed is not None else None
        decision = self._guard.decide(tool_id, policy)
        correlation_id = new_correlation_id()

        await self._record_or_refuse(
            decision_record(
                principal=principal,
                correlation_id=correlation_id,
                requested_tool=external_name,
                tool_id=tool_id,
                decision=decision,
                arguments=arguments,
            )
        )

        if routed is None or not decision.permits_dispatch:
            return self._deny(external_name, routed, policy, decision)
        call = _AuthorizedCall(principal, correlation_id, decision, routed)
        return await self._dispatch(call, arguments)

    @staticmethod
    def _deny(
        external_name: str,
        routed: RoutedTool | None,
        policy: PrincipalPolicy,
        decision: Decision,
    ) -> types.CallToolResult:
        """A tool the principal cannot discover gets the same error as a
        nonexistent one, so a hidden tool's existence never leaks (0012)."""
        if routed is None or not policy.can_discover(routed.tool_id):
            raise unknown_tool_error(external_name)
        return blocked_call_result(decision.reason, decision.decision_id)

    async def _dispatch(
        self, call: _AuthorizedCall, arguments: dict[str, Any]
    ) -> types.CallToolResult:
        routed = call.routed
        self._correlation.begin(call.correlation_id, routed.server_id, routed.external_name)
        status, tool_error = CallStatus.UNKNOWN, None
        try:
            upstream = self._upstreams[routed.server_id]
            result = ensure_call_tool_result(
                routed.external_name, await upstream.call_tool(routed.bare_name, arguments)
            )
            status, tool_error = CallStatus.COMPLETED, result.is_error
            return result
        except MCPError as exc:
            if exc.error.code not in _OUTCOME_UNCERTAIN_ERROR_CODES:
                status = CallStatus.FAILED
            raise
        finally:
            # Anything else (cancellation included) leaves status UNKNOWN.
            self._correlation.end(call.correlation_id, status)
            await self._record_after_dispatch(
                outcome_record(
                    principal=call.principal,
                    correlation_id=call.correlation_id,
                    decision_id=call.decision.decision_id,
                    tool_id=routed.tool_id,
                    status=status,
                    tool_error=tool_error,
                )
            )

    async def _record_or_refuse(self, record: AuditRecord) -> None:
        """Fail closed: nothing proceeds unless its record was written (0013)."""
        try:
            await self._audit.write(record)
        except AuditWriteError as exc:
            logger.error("refusing request: %s", exc)
            raise audit_unavailable_error() from exc

    async def _record_after_dispatch(self, record: AuditRecord) -> None:
        """The call already happened and cannot be undone, so a failed write is
        reported rather than raised. Shielded so a cancelled call still gets
        its outcome recorded."""
        with anyio.CancelScope(shield=True):
            try:
                await self._audit.write(record)
            except AuditWriteError:
                logger.exception("failed to record outcome %s", record.record_id)
