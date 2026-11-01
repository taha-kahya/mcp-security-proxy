"""Pure-logic tests for Guard decisions."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_security_proxy.core.guard import (
    DEFAULT_DENY_RULE,
    UNKNOWN_TOOL_RULE,
    Guard,
    Outcome,
)
from mcp_security_proxy.core.runner import InspectionReport
from mcp_security_proxy.sdk import Finding, Principal, Result, Severity, ToolId
from mcp_security_proxy.services.policy import PrincipalPolicy, parse_policy

ALICE = Principal(id="alice", authenticated_by="test")


def _alice_policy() -> PrincipalPolicy:
    snapshot = parse_policy(
        {
            "schema_version": 1,
            "principals": {
                "alice": [
                    {"tool": "server_a/*", "effect": "allow"},
                    {"tool": "server_a/send_message", "effect": "require_approval"},
                ]
            },
        }
    )
    return snapshot.for_principal(ALICE)


def test_allow_rule_permits_dispatch_and_cites_the_rule() -> None:
    policy = _alice_policy()
    decision = Guard().decide(ToolId("server_a", "read_record"), policy)

    assert decision.outcome is Outcome.ALLOW
    assert decision.permits_dispatch
    assert decision.rule_refs == ("policy:alice:server_a/*",)
    assert decision.policy_version == policy.policy_version


def test_require_approval_is_not_dispatched_while_approval_is_unavailable() -> None:
    decision = Guard().decide(ToolId("server_a", "send_message"), _alice_policy())

    assert decision.outcome is Outcome.REQUIRE_APPROVAL
    assert not decision.permits_dispatch
    assert decision.rule_refs == ("policy:alice:server_a/send_message",)


def test_unlisted_tool_is_blocked_by_default_deny() -> None:
    decision = Guard().decide(ToolId("server_b", "read_record"), _alice_policy())

    assert decision.outcome is Outcome.BLOCK
    assert decision.rule_refs == (DEFAULT_DENY_RULE,)


def test_unresolved_tool_is_blocked_as_unknown() -> None:
    decision = Guard().decide(None, _alice_policy())

    assert decision.outcome is Outcome.BLOCK
    assert decision.rule_refs == (UNKNOWN_TOOL_RULE,)


def test_every_decision_gets_a_distinct_id() -> None:
    guard, policy, tool = Guard(), _alice_policy(), ToolId("server_a", "read_record")
    assert guard.decide(tool, policy).decision_id != guard.decide(tool, policy).decision_id


# --- inspection reports -----------------------------------------------------


def _report(defense_id: str, result: Result) -> InspectionReport:
    return InspectionReport(defense_id, "1.0.0", result)


def _finding(rule_id: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(rule_id, "sample", severity, "defense-supplied text")


def _policy_with(
    enforcement: dict[str, Any] | None = None, overrides: dict[str, Any] | None = None
) -> PrincipalPolicy:
    document: dict[str, Any] = {
        "schema_version": 1,
        "principals": {"alice": [{"tool": "server_a/*", "effect": "allow"}]},
    }
    if enforcement:
        document["enforcement"] = enforcement
    return parse_policy(document, overrides).for_principal(ALICE)


READ = ToolId("server_a", "read_record")


def _blocking_result() -> Result:
    return Result.completed([_finding("budget.exceeded")])


def test_clean_and_not_applicable_inspections_keep_the_policy_decision() -> None:
    reports = [_report("a", Result.completed()), _report("b", Result.not_applicable())]
    decision = Guard().decide(READ, _policy_with(), reports)

    assert decision.outcome is Outcome.ALLOW
    assert decision.rule_refs == ("policy:alice:server_a/*",)


def test_a_finding_blocks_an_allowed_call_and_cites_the_defense_rule() -> None:
    reports = [_report("clean", Result.completed()), _report("budget", _blocking_result())]
    decision = Guard().decide(READ, _policy_with(), reports)

    assert decision.outcome is Outcome.BLOCK
    assert decision.rule_refs == ("defense:budget:budget.exceeded",)
    assert decision.reason == "blocked by a security check"


@pytest.mark.parametrize("status", ["failed", "unsupported"])
def test_incomplete_inspections_block_by_default(status: str) -> None:
    result = Result.failed("x") if status == "failed" else Result.unsupported("x")
    decision = Guard().decide(READ, _policy_with(), [_report("check", result)])

    assert decision.outcome is Outcome.BLOCK
    assert decision.rule_refs == (f"inspection:check:{status}",)


def test_observation_only_override_lets_failures_through_and_still_cites_them() -> None:
    policy = _policy_with(overrides={"observer": {"on_failure": "allow"}})
    decision = Guard().decide(READ, policy, [_report("observer", Result.failed("x"))])

    assert decision.outcome is Outcome.ALLOW
    assert decision.rule_refs == ("policy:alice:server_a/*", "inspection:observer:failed")


def test_block_wins_over_approval_and_allow_regardless_of_report_order() -> None:
    policy = _policy_with(overrides={"asks": {"findings": {"asks.rule": "require_approval"}}})
    asks = _report("asks", Result.completed([_finding("asks.rule")]))
    blocks = _report("budget", _blocking_result())

    for reports in ([asks, blocks], [blocks, asks]):
        decision = Guard().decide(READ, policy, reports)
        assert decision.outcome is Outcome.BLOCK
        assert decision.rule_refs == ("defense:budget:budget.exceeded",)


def test_findings_cannot_loosen_a_policy_denial() -> None:
    policy = _policy_with(enforcement={"by_severity": {"high": "allow"}})
    reports = [_report("budget", _blocking_result())]

    decision = Guard().decide(ToolId("server_b", "read_record"), policy, reports)
    assert decision.outcome is Outcome.BLOCK
    assert decision.rule_refs == (DEFAULT_DENY_RULE,)


def test_review_allows_content_nothing_objected_to() -> None:
    decision = Guard().review(_policy_with(), [_report("a", Result.completed())])
    assert decision.outcome is Outcome.ALLOW and decision.rule_refs == ()


def test_review_blocks_content_with_findings() -> None:
    decision = Guard().review(_policy_with(), [_report("scan", _blocking_result())])
    assert decision.outcome is Outcome.BLOCK
