"""Detect plain instructions and suspicious values in a tool definition (plan MR D3).

Tool poisoning doesn't need hiding: a description, a parameter description,
a parameter name or an `enum` value can simply tell the model what to do,
and most users never read the whole definition. This defense covers the
plain-text half of what `direct_hidden_metadata` (D2) covers when hidden:

- `instruction_phrase`: text addressed to the model (an override, a role
  switch, a chat-template token, a fake `<system>` tag) anywhere in the
  definition, keys included, unless it sits in a prohibition ("never ignore
  ..."). High for chat-template tokens, which never occur by accident;
  medium otherwise. Concealed matches are D2's, so one piece of text isn't
  reported twice.
- `suspicious_value`: a `default`, `examples`, `enum` or `const` value, at
  any depth of the schemas, that holds shell command syntax or a credential
  file path (Scan's `commands` detector). The model copies these into calls
  because the schema says they are expected.
- `long_text`: one text value longer than `max_text_length`. A hint, never
  a block on its own: long descriptions are common in complex tools.

Does not cover: reworded instructions with no known phrase (Scan's
classifier, `direct_definition_classifier`, S4), camelCase parameter names
(only `_` and `-` separate words), outside URLs on their own (a base-URL
parameter legitimately has one), or a definition that changes after
approval (T2).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mcp_security_proxy.sdk import (
    Capability,
    Confidence,
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    Severity,
    Stage,
    iter_keyword_values,
    iter_strings,
)

DEFENSE_ID = "direct_schema_injection"
CATEGORY = "direct"
INSTRUCTION_PHRASE_RULE = f"{DEFENSE_ID}.instruction_phrase"
SUSPICIOUS_VALUE_RULE = f"{DEFENSE_ID}.suspicious_value"
LONG_TEXT_RULE = f"{DEFENSE_ID}.long_text"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.2,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.SCAN}),
)

# Reasons never quote the inspected text.
REASONS: Mapping[str, str] = {
    INSTRUCTION_PHRASE_RULE: "tool definition contains text addressed to the model",
    SUSPICIOUS_VALUE_RULE: "a schema value holds shell command syntax or a credential file path",
    LONG_TEXT_RULE: "tool definition has an unusually long text value",
}

# Schema keywords whose values the model copies into calls.
VALUE_KEYWORDS = frozenset({"default", "examples", "enum", "const"})


class SchemaInjectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_text_length: int = Field(default=2000, ge=100)


class SchemaInjectionDefense:
    def __init__(self, settings: SchemaInjectionSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        definition = event.payload
        findings: list[Finding] = []

        instructions = (await context.scan.instructions(definition)).matches
        plain = [m for m in instructions if not m.concealed]
        if plain:
            high = any(m.confidence is Confidence.HIGH for m in plain)
            severity = Severity.HIGH if high else Severity.MEDIUM
            findings.append(_finding(INSTRUCTION_PHRASE_RULE, severity, {m.ref for m in plain}))

        suspicious: set[str] = set()
        for pointer, value in iter_keyword_values(definition, VALUE_KEYWORDS):
            for match in (await context.scan.commands(value)).matches:
                suspicious.add(pointer + match.ref)
        if suspicious:
            findings.append(_finding(SUSPICIOUS_VALUE_RULE, Severity.MEDIUM, suspicious))

        limit = self._settings.max_text_length
        long = {pointer for pointer, text in iter_strings(definition) if len(text) > limit}
        if long:
            findings.append(_finding(LONG_TEXT_RULE, Severity.LOW, long))
        return Result.completed(findings)


def _finding(rule: str, severity: Severity, refs: set[str]) -> Finding:
    return Finding(rule, CATEGORY, severity, REASONS[rule], tuple(sorted(refs)))


def create(settings: Mapping[str, Any]) -> SchemaInjectionDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return SchemaInjectionDefense(SchemaInjectionSettings.model_validate(settings))
