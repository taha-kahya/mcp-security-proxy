"""Indirect defense: injected instructions written into call arguments."""

from mcp_security_proxy.defenses.indirect.argument_propagation.defense import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    INSTRUCTIONS_IN_QUERY_RULE,
    INSTRUCTIONS_RULE,
    ArgumentPropagationDefense,
    ArgumentPropagationSettings,
    create,
)

__all__ = [
    "CONCEALED_INSTRUCTIONS_RULE",
    "DEFENSE_ID",
    "INSTRUCTIONS_IN_QUERY_RULE",
    "INSTRUCTIONS_RULE",
    "ArgumentPropagationDefense",
    "ArgumentPropagationSettings",
    "create",
]
