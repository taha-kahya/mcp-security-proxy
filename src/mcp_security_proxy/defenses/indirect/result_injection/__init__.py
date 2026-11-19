"""Indirect defense: injected instructions in tool results."""

from mcp_security_proxy.defenses.indirect.result_injection.defense import (
    CONCEALED_INSTRUCTIONS_RULE,
    DEFENSE_ID,
    INSTRUCTIONS_RULE,
    ResultInjectionDefense,
    ResultInjectionSettings,
    create,
)

__all__ = [
    "CONCEALED_INSTRUCTIONS_RULE",
    "DEFENSE_ID",
    "INSTRUCTIONS_RULE",
    "ResultInjectionDefense",
    "ResultInjectionSettings",
    "create",
]
