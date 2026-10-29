"""Combine policy and authorization context into one decision.

Guard neither inspects content nor calls servers. In V2 its only input is
the principal's policy; inspection results join in V3.
"""

from __future__ import annotations

from mcp_security_proxy.core.guard.decision import Decision, Outcome
from mcp_security_proxy.sdk import ToolId
from mcp_security_proxy.services.policy import Effect, PrincipalPolicy

UNKNOWN_TOOL_RULE = "routing:unknown_tool"
DEFAULT_DENY_RULE = "policy:default_deny"

_OUTCOME_BY_EFFECT = {
    Effect.ALLOW: Outcome.ALLOW,
    Effect.REQUIRE_APPROVAL: Outcome.REQUIRE_APPROVAL,
}

_REASON_BY_OUTCOME = {
    Outcome.ALLOW: "permitted by policy",
    Outcome.REQUIRE_APPROVAL: "requires approval, and no approval mechanism is available",
}


class Guard:
    def decide(self, tool_id: ToolId | None, policy: PrincipalPolicy) -> Decision:
        """`tool_id` is None when the requested name resolves to no known tool."""
        if tool_id is None:
            return self._block(UNKNOWN_TOOL_RULE, "no such tool", policy)

        rule = policy.rule_for(tool_id)
        if rule is None:
            return self._block(DEFAULT_DENY_RULE, "not permitted by policy", policy)

        outcome = _OUTCOME_BY_EFFECT[rule.effect]
        return Decision(
            outcome=outcome,
            rule_refs=(rule.rule_id,),
            reason=_REASON_BY_OUTCOME[outcome],
            policy_version=policy.policy_version,
        )

    @staticmethod
    def _block(rule_ref: str, reason: str, policy: PrincipalPolicy) -> Decision:
        return Decision(
            outcome=Outcome.BLOCK,
            rule_refs=(rule_ref,),
            reason=reason,
            policy_version=policy.policy_version,
        )
