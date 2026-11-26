"""Direct defense: plain instructions and suspicious values in tool definitions."""

from mcp_security_proxy.defenses.direct.schema_injection.defense import (
    DEFENSE_ID,
    INSTRUCTION_PHRASE_RULE,
    LONG_TEXT_RULE,
    SUSPICIOUS_VALUE_RULE,
    SchemaInjectionDefense,
    SchemaInjectionSettings,
    create,
)

__all__ = [
    "DEFENSE_ID",
    "INSTRUCTION_PHRASE_RULE",
    "LONG_TEXT_RULE",
    "SUSPICIOUS_VALUE_RULE",
    "SchemaInjectionDefense",
    "SchemaInjectionSettings",
    "create",
]
