"""Immutable, versioned view of the loaded policy.

Matching is default-deny: a tool no rule matches is neither discoverable nor
callable. When both an exact rule and a server wildcard match, the exact rule
wins, so `server_a/*: allow` can be narrowed with
`server_a/write_record: require_approval`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from mcp_security_proxy.sdk import Principal, ToolId
from mcp_security_proxy.services.policy.enforcement import EnforcementPolicy
from mcp_security_proxy.services.policy.rules import ToolPattern, ToolRule


@dataclass(frozen=True)
class PrincipalPolicy:
    """The subset of a policy snapshot that applies to one principal.

    Satisfies the SDK's read-only `PolicyView`.
    """

    principal_id: str
    policy_version: str
    rules: tuple[ToolRule, ...]
    enforcement: EnforcementPolicy = field(default_factory=EnforcementPolicy)

    @property
    def version(self) -> str:
        return self.policy_version

    def rule_for(self, tool_id: ToolId) -> ToolRule | None:
        matching = [rule for rule in self.rules if rule.pattern.matches(tool_id)]
        for rule in matching:
            if not rule.pattern.is_wildcard:
                return rule
        return matching[0] if matching else None

    def can_discover(self, tool_id: ToolId) -> bool:
        return self.rule_for(tool_id) is not None


class PolicySnapshot:
    def __init__(
        self,
        version: str,
        rules_by_principal: Mapping[str, tuple[ToolRule, ...]],
        enforcement: EnforcementPolicy | None = None,
    ) -> None:
        self._version = version
        self._rules_by_principal = MappingProxyType(dict(rules_by_principal))
        self._enforcement = enforcement or EnforcementPolicy()

    @property
    def version(self) -> str:
        return self._version

    @property
    def enforcement(self) -> EnforcementPolicy:
        return self._enforcement

    @property
    def principal_ids(self) -> frozenset[str]:
        return frozenset(self._rules_by_principal)

    def for_principal(self, principal: Principal) -> PrincipalPolicy:
        return PrincipalPolicy(
            principal_id=principal.id,
            policy_version=self._version,
            rules=self._rules_by_principal.get(principal.id, ()),
            enforcement=self._enforcement,
        )

    def unmatched_patterns(self, known_tools: Iterable[ToolId]) -> list[ToolPattern]:
        """Patterns that target no known tool: typos or servers that don't exist."""
        known = list(known_tools)
        return [
            rule.pattern
            for rules in self._rules_by_principal.values()
            for rule in rules
            if not any(rule.pattern.matches(tool_id) for tool_id in known)
        ]
