"""Detect injected instructions in tool results (plan MR I1).

A tool result can carry text written by anyone: a web page, an email, a
ticket. Text addressed to the model ("ignore all previous instructions",
chat-template tokens, fake `<system>` tags) is an injection attempt.

Severity follows where the evidence is, not just the phrase:

- **concealed** (revealed by base64, tag characters or lookalike letters,
  or inside an HTML comment or invisible text) is high: benign content has
  no reason to hide instructions;
- **plain** visible text is low, because results legitimately quote such
  phrases, for example an article about prompt injection. With the
  reference policy it is recorded, not blocked.

Text blocks and structured content are inspected, each finding pointing at
the exact block (`/content/2/text#140-190`, `/structuredContent/notes#0-40`).
So are an upstream's JSON-RPC error for the call (`/error/message`,
`/error/data/...`) and the message of a progress notification
(`/params/message`), which agents read as closely as results (plan MR I3).
Any other block (image, audio, embedded resource, resource link) can't be
inspected, so the whole result is `unsupported`, never clean.

A server's `initialize` instructions are inspected the same way at startup,
pointing at `/instructions` (plan MR I4); the proxy forwards them only when
no defense found anything.

Does not cover: reworded injections with no hiding (needs Scan's classifier
stage), log notifications (`notifications/message`, which the proxy doesn't
relay), or injected text in call arguments (I2).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    ERROR_CONTENT_TYPE,
    NOTIFICATION_CONTENT_TYPE,
    Capability,
    ContentBlock,
    ContentSource,
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    ScanMatch,
    Severity,
    Stage,
)

DEFENSE_ID = "indirect_result_injection"
CATEGORY = "indirect"
CONCEALED_INSTRUCTIONS_RULE = f"{DEFENSE_ID}.concealed_instructions"
INSTRUCTIONS_RULE = f"{DEFENSE_ID}.instructions"

STRUCTURED_BLOCK_TYPE = "structured"
INSPECTED_BLOCK_TYPES = frozenset(
    {"text", STRUCTURED_BLOCK_TYPE, ERROR_CONTENT_TYPE, NOTIFICATION_CONTENT_TYPE}
)

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.2.0",
    sdk_version_range=">=1.2,<2",
    stages=frozenset({Stage.BEFORE_DELIVERY}),
    required_capabilities=frozenset({Capability.SCAN}),
)

# rule id -> (severity, reason); reasons never quote the inspected text.
RULES: Mapping[str, tuple[Severity, str]] = {
    CONCEALED_INSTRUCTIONS_RULE: (
        Severity.HIGH,
        "tool output contains instructions to the model hidden by encoding or markup",
    ),
    INSTRUCTIONS_RULE: (Severity.LOW, "tool output contains text addressed to the model"),
}


class ResultInjectionSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ResultInjectionDefense:
    def __init__(self, settings: ResultInjectionSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.BEFORE_DELIVERY:
            return Result.not_applicable()
        uninspected = sorted({block.type for block in event.content} - INSPECTED_BLOCK_TYPES)
        if uninspected:
            return Result.unsupported(f"{', '.join(uninspected)} content")
        refs: dict[str, set[str]] = {}
        for index, block in enumerate(event.content):
            pointer, value = _inspected_value(index, block)
            for match in (await context.scan.instructions(value)).matches:
                refs.setdefault(_rule_for(match), set()).add(pointer + match.ref)
        return Result.completed(_findings(refs))


def _inspected_value(index: int, block: ContentBlock) -> tuple[str, Any]:
    """The part of the block to scan, and its JSON Pointer in the result."""
    if block.type == STRUCTURED_BLOCK_TYPE:
        return "/structuredContent", block.data
    if block.type == ERROR_CONTENT_TYPE:
        return "/error", block.data
    if block.type == NOTIFICATION_CONTENT_TYPE:
        return "/params", block.data

    if block.provenance.source is ContentSource.SERVER_INSTRUCTIONS:
        return "/instructions", block.data.get("text", "")
    return f"/content/{index}/text", block.data.get("text", "")


def _rule_for(match: ScanMatch) -> str:
    return CONCEALED_INSTRUCTIONS_RULE if match.concealed else INSTRUCTIONS_RULE


def _findings(refs: Mapping[str, Iterable[str]]) -> list[Finding]:
    """One finding per rule, listing every place it matched."""
    return [
        Finding(rule, CATEGORY, RULES[rule][0], RULES[rule][1], tuple(sorted(refs[rule])))
        for rule in sorted(refs)
    ]


def create(settings: Mapping[str, Any]) -> ResultInjectionDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return ResultInjectionDefense(ResultInjectionSettings.model_validate(settings))
