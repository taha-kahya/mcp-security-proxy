"""Direct defense: tool definitions Scan's classifier grades as poisoned."""

from mcp_security_proxy.defenses.direct.definition_classifier.defense import (
    CRITICAL_RULE,
    DEFENSE_ID,
    HIGH_RULE,
    MEDIUM_RULE,
    DefinitionClassifierDefense,
    DefinitionClassifierSettings,
    create,
)

__all__ = [
    "CRITICAL_RULE",
    "DEFENSE_ID",
    "HIGH_RULE",
    "MEDIUM_RULE",
    "DefinitionClassifierDefense",
    "DefinitionClassifierSettings",
    "create",
]
