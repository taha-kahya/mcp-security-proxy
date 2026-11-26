"""Detect injected instructions in call arguments (plan MR I2).

An agent that has read injected text may write it, or what it was told to
write, into a call: a comment on a shared ticket, a wiki page, a message to
another agent, a record in a shared store. A second agent reads it later and
is injected in turn. The call is the one point where the proxy sees the text
before it spreads, so this defense scans every argument value, keys
included, for text addressed to a model.

Severity follows the evidence and where the text is going:

- **concealed** (revealed by decoding or lookalike letters, or inside hidden
  content) is high, whatever the call does: benign arguments have no reason
  to hide instructions;
- **plain** text on a `write`, `send` or `execute` call, or on a call whose
  operation is `unknown`, is medium: it lands somewhere another agent may
  read, and an unclassified tool is treated as one that writes;
- **plain** text on a `read` call is low: a search query that mentions an
  injection phrase is usually a question about it, and the text goes no
  further than the server.

Findings point at the exact argument (`/arguments/body#12-60`). The defense
reports; the operator's policy decides, so nothing here blocks a write.

Does not cover: reworded instructions with no known phrase and no hiding
(needs Scan's classifier stage), whether the user asked for the text (the
proxy doesn't see the conversation), or text split across several calls.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Finding,
    Manifest,
    Operation,
    Result,
    ScanMatch,
    Severity,
    Stage,
)

DEFENSE_ID = "indirect_argument_propagation"
CATEGORY = "indirect"
CONCEALED_INSTRUCTIONS_RULE = f"{DEFENSE_ID}.concealed_instructions"
INSTRUCTIONS_RULE = f"{DEFENSE_ID}.instructions"
INSTRUCTIONS_IN_QUERY_RULE = f"{DEFENSE_ID}.instructions_in_query"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.1,<2",
    stages=frozenset({Stage.BEFORE_EXECUTION}),
    required_capabilities=frozenset({Capability.SCAN}),
)

# rule id -> (severity, reason); reasons never quote the inspected text.
RULES: Mapping[str, tuple[Severity, str]] = {
    CONCEALED_INSTRUCTIONS_RULE: (
        Severity.HIGH,
        "call arguments contain instructions to a model hidden by encoding or markup",
    ),
    INSTRUCTIONS_RULE: (
        Severity.MEDIUM,
        "call that writes or sends carries text addressed to a model",
    ),
    INSTRUCTIONS_IN_QUERY_RULE: (
        Severity.LOW,
        "read call carries text addressed to a model",
    ),
}


class ArgumentPropagationSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArgumentPropagationDefense:
    def __init__(self, settings: ArgumentPropagationSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.BEFORE_EXECUTION:
            return Result.not_applicable()
        operation = event.action.operation if event.action is not None else Operation.UNKNOWN
        arguments = event.payload.get("arguments", {})
        refs: dict[str, set[str]] = {}
        for match in (await context.scan.instructions(arguments)).matches:
            refs.setdefault(_rule_for(match, operation), set()).add("/arguments" + match.ref)
        return Result.completed(_findings(refs))


def _rule_for(match: ScanMatch, operation: Operation) -> str:
    if match.concealed:
        return CONCEALED_INSTRUCTIONS_RULE
    if operation is Operation.READ:
        return INSTRUCTIONS_IN_QUERY_RULE
    return INSTRUCTIONS_RULE


def _findings(refs: Mapping[str, Iterable[str]]) -> list[Finding]:
    """One finding per rule, listing every place it matched."""
    return [
        Finding(rule, CATEGORY, RULES[rule][0], RULES[rule][1], tuple(sorted(refs[rule])))
        for rule in sorted(refs)
    ]


def create(settings: Mapping[str, Any]) -> ArgumentPropagationDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return ArgumentPropagationDefense(ArgumentPropagationSettings.model_validate(settings))
