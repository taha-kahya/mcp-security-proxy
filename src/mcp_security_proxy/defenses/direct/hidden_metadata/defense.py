"""Detect content hidden in a tool definition (plan MR D2).

A tool definition reaches the model as soon as the agent lists tools, so
anything a reviewer can't see in it is a way to instruct the model unseen:
an HTML comment, zero-width or bidirectional characters, Unicode tag
characters, terminal escapes, a base64 blob that decodes to text, or padding
that pushes text out of view. Every text value is inspected at any depth,
keys included (`name`, `description`, every JSON Schema keyword, `_meta`,
`annotations`), and each finding points at the exact field.

Instructions are reported here only when they are concealed: revealed by
decoding, spelled with lookalike letters, or inside hidden content. That is
near-certain intent, so it is high severity. Plain-text injection phrases in
metadata are the job of `direct_schema_injection` (plan MR D3).

Does not cover: reworded instructions with no hiding (needs Scan's
classifier stage), lookalike tool names (D4), or server instructions from
`initialize`, which are not inspected yet.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Detector,
    Event,
    Finding,
    Manifest,
    MatchKind,
    Result,
    ScanMatch,
    Severity,
    Stage,
)

DEFENSE_ID = "direct_hidden_metadata"
CATEGORY = "direct"
CONCEALED_INSTRUCTIONS_RULE = f"{DEFENSE_ID}.concealed_instructions"
HIDDEN_COMMENT_RULE = f"{DEFENSE_ID}.hidden_comment"
INVISIBLE_CHARACTERS_RULE = f"{DEFENSE_ID}.invisible_characters"
TAG_CHARACTERS_RULE = f"{DEFENSE_ID}.tag_characters"
CONTROL_CHARACTERS_RULE = f"{DEFENSE_ID}.control_characters"
ENCODED_TEXT_RULE = f"{DEFENSE_ID}.encoded_text"
PADDING_RULE = f"{DEFENSE_ID}.padding"
DATA_URI_RULE = f"{DEFENSE_ID}.data_uri"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.1,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.SCAN}),
)

# rule id -> (severity, reason); reasons never quote the inspected text.
RULES: Mapping[str, tuple[Severity, str]] = {
    CONCEALED_INSTRUCTIONS_RULE: (
        Severity.HIGH,
        "tool definition contains instructions to the model hidden by encoding or markup",
    ),
    HIDDEN_COMMENT_RULE: (Severity.MEDIUM, "tool definition contains a comment the user can't see"),
    INVISIBLE_CHARACTERS_RULE: (
        Severity.MEDIUM,
        "tool definition contains invisible or bidirectional control characters",
    ),
    TAG_CHARACTERS_RULE: (Severity.HIGH, "tool definition contains invisible Unicode tag text"),
    CONTROL_CHARACTERS_RULE: (
        Severity.HIGH,
        "tool definition contains control characters or terminal escape sequences",
    ),
    ENCODED_TEXT_RULE: (Severity.MEDIUM, "tool definition contains base64-encoded text"),
    PADDING_RULE: (Severity.MEDIUM, "tool definition pads text out of view with whitespace"),
    DATA_URI_RULE: (Severity.LOW, "tool definition contains a data: URI"),
}

_RULE_BY_KIND: Mapping[MatchKind, str] = {
    MatchKind.HTML_COMMENT: HIDDEN_COMMENT_RULE,
    MatchKind.MARKDOWN_COMMENT: HIDDEN_COMMENT_RULE,
    MatchKind.INVISIBLE_CHARACTER: INVISIBLE_CHARACTERS_RULE,
    MatchKind.BIDI_CONTROL: INVISIBLE_CHARACTERS_RULE,
    MatchKind.TAG_CHARACTER: TAG_CHARACTERS_RULE,
    MatchKind.CONTROL_CHARACTER: CONTROL_CHARACTERS_RULE,
    MatchKind.ENCODED_TEXT: ENCODED_TEXT_RULE,
    MatchKind.PADDING: PADDING_RULE,
    MatchKind.DATA_URI: DATA_URI_RULE,
}


class HiddenMetadataSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HiddenMetadataDefense:
    def __init__(self, settings: HiddenMetadataSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        definition = event.payload
        hidden = (await context.scan.hidden(definition)).matches
        instructions = (await context.scan.instructions(definition)).matches
        concealed = [m for m in instructions if m.concealed]
        return Result.completed(_findings([*hidden, *concealed]))


def rule_for(match: ScanMatch) -> str | None:
    if match.detector is Detector.INSTRUCTIONS:
        return CONCEALED_INSTRUCTIONS_RULE
    return _RULE_BY_KIND.get(match.kind)


def _findings(matches: Iterable[ScanMatch]) -> list[Finding]:
    """One finding per rule, listing every place it matched."""
    refs: dict[str, set[str]] = {}
    for match in matches:
        rule = rule_for(match)
        if rule is not None:
            refs.setdefault(rule, set()).add(match.ref)
    return [
        Finding(rule, CATEGORY, RULES[rule][0], RULES[rule][1], tuple(sorted(refs[rule])))
        for rule in sorted(refs)
    ]


def create(settings: Mapping[str, Any]) -> HiddenMetadataDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return HiddenMetadataDefense(HiddenMetadataSettings.model_validate(settings))
