"""Detect tool annotations that contradict the operator's classification (plan MR D1).

MCP tool annotations are hints the server writes about itself. A client that
auto-approves read-only tools, or a user who trusts the label, lets a tool
that really sends or deletes run without review. The specification says
annotations from untrusted servers must not be relied on, so this defense
compares each claim with the operation the operator assigned to the tool in
`tools.yaml` (read through `RegistryView.action`), never with anything else
the server says:

- `readOnlyHint: true` on a `write`, `send` or `execute` tool: high.
- `destructiveHint: false` on a `write` or `execute` tool: medium.
- `openWorldHint: false` on a `send` tool: medium.
- any of those claims on a tool whose operation is `unknown`: low, because
  the claim can't be checked and missing evidence is never treated as safe.

Absent hints default to the cautious reading (not read-only, destructive,
open-world), so a tool without annotations claims nothing and is clean. Only
JSON booleans count as claims; a hint of any other type is ignored, since the
specification defines them as booleans.

Does not cover: whether the operator's classification is right (the proxy
sees no source code or side effects), `idempotentHint` (`tools.yaml` has no
idempotence to compare with), a truthful annotation paired with a misleading
description (`direct_schema_injection`, D3), or a definition that changes
after approval (T2).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
    Severity,
    Stage,
)

DEFENSE_ID = "direct_claim_mismatch"
CATEGORY = "direct"
READ_ONLY_RULE = f"{DEFENSE_ID}.read_only"
NON_DESTRUCTIVE_RULE = f"{DEFENSE_ID}.non_destructive"
CLOSED_WORLD_RULE = f"{DEFENSE_ID}.closed_world"
UNCLASSIFIED_RULE = f"{DEFENSE_ID}.unclassified"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.0,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.REGISTRY}),
)


@dataclass(frozen=True)
class _Claim:
    """One annotation value that relaxes the cautious default."""

    hint: str
    claimed: bool
    rule: str
    severity: Severity
    contradicted_by: frozenset[Operation]
    reason: str

    @property
    def pointer(self) -> str:
        return f"/annotations/{self.hint}"


CLAIMS: tuple[_Claim, ...] = (
    _Claim(
        "readOnlyHint",
        True,
        READ_ONLY_RULE,
        Severity.HIGH,
        frozenset({Operation.WRITE, Operation.SEND, Operation.EXECUTE}),
        "tool claims to be read-only but the operator classifies it as changing state",
    ),
    _Claim(
        "destructiveHint",
        False,
        NON_DESTRUCTIVE_RULE,
        Severity.MEDIUM,
        frozenset({Operation.WRITE, Operation.EXECUTE}),
        "tool claims not to be destructive but the operator classifies it as writing",
    ),
    _Claim(
        "openWorldHint",
        False,
        CLOSED_WORLD_RULE,
        Severity.MEDIUM,
        frozenset({Operation.SEND}),
        "tool claims a closed world but the operator classifies it as sending",
    ),
)
UNCLASSIFIED_REASON = "tool makes annotation claims but the operator has not classified it"


class ClaimMismatchSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ClaimMismatchDefense:
    def __init__(self, settings: ClaimMismatchSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        claims = _claims(event.payload)
        if not claims:
            return Result.completed()
        operation = Operation.UNKNOWN
        if event.tool_id is not None:
            operation = context.registry.action(event.tool_id, {}).operation
        return Result.completed(_findings(claims, operation))


def _claims(definition: Mapping[str, Any]) -> list[_Claim]:
    annotations = definition.get("annotations")
    if not isinstance(annotations, Mapping):
        return []
    return [
        claim
        for claim in CLAIMS
        if isinstance(annotations.get(claim.hint), bool)
        and annotations[claim.hint] is claim.claimed
    ]


def _findings(claims: list[_Claim], operation: Operation) -> list[Finding]:
    if operation is Operation.UNKNOWN:
        refs = tuple(sorted(claim.pointer for claim in claims))
        return [Finding(UNCLASSIFIED_RULE, CATEGORY, Severity.LOW, UNCLASSIFIED_REASON, refs)]
    return [
        Finding(claim.rule, CATEGORY, claim.severity, claim.reason, (claim.pointer,))
        for claim in claims
        if operation in claim.contradicted_by
    ]


def create(settings: Mapping[str, Any]) -> ClaimMismatchDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return ClaimMismatchDefense(ClaimMismatchSettings.model_validate(settings))
