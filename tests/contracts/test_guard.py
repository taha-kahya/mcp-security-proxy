"""Pure-logic tests for Guard decisions."""

from __future__ import annotations

from mcp_security_proxy.core.guard import (
    DEFAULT_DENY_RULE,
    UNKNOWN_TOOL_RULE,
    Guard,
    Outcome,
)
from mcp_security_proxy.sdk import Principal, ToolId
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
