"""Translate core lifecycle facts into Log's audit record schemas.

Kept out of the orchestrator so it reads as the request lifecycle rather
than as record construction, and out of `services/log` so Log never depends
on core types such as `Decision`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp_security_proxy.core.guard import Decision
from mcp_security_proxy.core.proxy.routing.correlation import CallStatus
from mcp_security_proxy.sdk import Principal, ToolId
from mcp_security_proxy.services.log import (
    ArgumentDigest,
    DecisionRecord,
    DiscoveryRecord,
    OutcomeRecord,
)


def discovery_record(
    principal: Principal, policy_version: str, visible_tool_count: int
) -> DiscoveryRecord:
    return DiscoveryRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        policy_version=policy_version,
        visible_tool_count=visible_tool_count,
    )


def decision_record(
    *,
    principal: Principal,
    correlation_id: str,
    requested_tool: str,
    tool_id: ToolId | None,
    decision: Decision,
    arguments: Mapping[str, Any],
) -> DecisionRecord:
    return DecisionRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        correlation_id=correlation_id,
        requested_tool=requested_tool,
        tool_id=str(tool_id) if tool_id is not None else None,
        decision_id=decision.decision_id,
        outcome=decision.outcome,
        rule_refs=decision.rule_refs,
        reason=decision.reason,
        policy_version=decision.policy_version,
        arguments=ArgumentDigest.of(arguments),
    )


def outcome_record(
    *,
    principal: Principal,
    correlation_id: str,
    decision_id: str,
    tool_id: ToolId,
    status: CallStatus,
    tool_error: bool | None,
) -> OutcomeRecord:
    return OutcomeRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        correlation_id=correlation_id,
        decision_id=decision_id,
        tool_id=str(tool_id),
        status=status,
        tool_error=tool_error,
    )
