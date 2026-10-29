"""Translate core lifecycle facts into Log's audit record schemas.

Kept out of the orchestrator so it reads as the request lifecycle rather
than as record construction, and out of `services/log` so Log never depends
on core types such as `Decision`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from mcp_security_proxy.core.proxy.control import CallAuthorization, DeliveryReview, Discovery
from mcp_security_proxy.core.runner import InspectionReport
from mcp_security_proxy.sdk import OperationStatus, Principal, ToolId
from mcp_security_proxy.services.log import (
    ArgumentDigest,
    DecisionRecord,
    DeliveryRecord,
    DiscoveryRecord,
    InspectionSummary,
    OutcomeRecord,
)


def discovery_record(principal: Principal, discovery: Discovery) -> DiscoveryRecord:
    return DiscoveryRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        policy_version=discovery.policy_version,
        visible_tool_count=len(discovery.visible),
        hidden_by_inspection=tuple(str(r.tool_id) for r in discovery.hidden_by_inspection),
    )


def decision_record(
    authorization: CallAuthorization, requested_tool: str, arguments: Mapping[str, Any]
) -> DecisionRecord:
    principal, decision = authorization.principal, authorization.decision
    routed, action = authorization.routed, authorization.action
    return DecisionRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        correlation_id=authorization.correlation_id,
        requested_tool=requested_tool,
        tool_id=str(routed.tool_id) if routed is not None else None,
        decision_id=decision.decision_id,
        outcome=decision.outcome,
        rule_refs=decision.rule_refs,
        reason=decision.reason,
        policy_version=decision.policy_version,
        arguments=ArgumentDigest.of(arguments),
        operation=action.operation if action is not None else None,
        inspections=inspection_summaries(authorization.reports),
    )


def outcome_record(
    *,
    principal: Principal,
    correlation_id: str,
    decision_id: str,
    tool_id: ToolId,
    status: OperationStatus,
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


def delivery_record(authorization: CallAuthorization, review: DeliveryReview) -> DeliveryRecord:
    principal, decision = authorization.principal, review.decision
    assert authorization.routed is not None
    return DeliveryRecord(
        principal_id=principal.id,
        authenticated_by=principal.authenticated_by,
        correlation_id=authorization.correlation_id,
        tool_id=str(authorization.routed.tool_id),
        decision_id=decision.decision_id,
        outcome=decision.outcome,
        rule_refs=decision.rule_refs,
        reason=decision.reason,
        policy_version=decision.policy_version,
        inspections=inspection_summaries(review.reports),
    )


def inspection_summaries(reports: Iterable[InspectionReport]) -> tuple[InspectionSummary, ...]:
    return tuple(
        InspectionSummary(
            defense_id=report.defense_id,
            defense_version=report.defense_version,
            status=report.status,
            finding_rule_ids=tuple(f.rule_id for f in report.result.findings),
            detail=report.result.detail,
        )
        for report in reports
    )
