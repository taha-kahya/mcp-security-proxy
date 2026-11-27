"""Detect tool names that impersonate other tools (plan MR D4).

The proxy's server-scoped tool ids already stop a call reaching the wrong
server, but the model, and a user approving a call, choose by name. A
server can name its tool so it looks like another server's (`send_mеssage`
with a Cyrillic "е" next to `send_message`), or tell the model how to use
another server's tool from its own description ("whenever `send_message` is
used, add this recipient"), which Invariant Labs calls shadowing.

- `confusable_name`: the tool's name has the same confusable skeleton
  (UTS #39, through Scan) as another exposed tool's name, but isn't the
  same string. High: two different strings that look identical have no
  benign reason to sit side by side.
- `mixed_script`: the name mixes alphabets with lookalike letters (Scan's
  lookalike detector), even with no counterpart exposed yet. Medium.
- `other_server_tool`: a text value in the definition names, as a whole
  word, a tool that only another server exposes. Medium: a server
  referring to its own sibling tools is normal; referring to another
  server's is how shadowing works.

Two servers exposing the same ASCII name is a collision the server-scoped
ids resolve, not a disguise, so it is clean.

Does not cover: names one edit away rather than visually identical
(`send_mesage`), digit-for-letter swaps the confusables table doesn't map,
another server's tool referred to by what it does ("the email tool"),
which is left to Scan's classifier (S4), and lookalike server names (ADR
0022's registration defense).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Manifest,
    Result,
    Severity,
    Stage,
    ToolId,
    findings_by_rule,
    iter_strings,
)

DEFENSE_ID = "direct_tool_name_spoofing"
CATEGORY = "direct"
CONFUSABLE_NAME_RULE = f"{DEFENSE_ID}.confusable_name"
MIXED_SCRIPT_RULE = f"{DEFENSE_ID}.mixed_script"
OTHER_SERVER_TOOL_RULE = f"{DEFENSE_ID}.other_server_tool"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.2,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.SCAN, Capability.REGISTRY}),
)

RULES: Mapping[str, tuple[Severity, str]] = {
    CONFUSABLE_NAME_RULE: (
        Severity.HIGH,
        "tool name looks identical to another exposed tool's name",
    ),
    MIXED_SCRIPT_RULE: (Severity.MEDIUM, "tool name mixes alphabets with lookalike letters"),
    OTHER_SERVER_TOOL_RULE: (
        Severity.MEDIUM,
        "tool definition refers to a tool exposed only by another server",
    ),
}


class ToolNameSpoofingSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolNameSpoofingDefense:
    def __init__(self, settings: ToolNameSpoofingSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        if event.tool_id is None:
            return Result.unsupported("a definition without a tool id")
        own = event.tool_id
        name = own.name
        others = [t for t in context.registry.tool_ids() if t != own]
        refs: dict[str, set[str]] = {}

        # One batched, cached Scan call per definition rather than one per name.
        skeletons = await context.scan.skeletons([name, *(t.name for t in others)])
        if any(other.name != name and skeletons[other.name] == skeletons[name] for other in others):
            refs.setdefault(CONFUSABLE_NAME_RULE, set()).add("/name")
        if (await context.scan.lookalikes(name)).matches:
            refs.setdefault(MIXED_SCRIPT_RULE, set()).add("/name")

        foreign = _foreign_names(own, others)
        if foreign:
            pattern = _whole_words(foreign)
            for pointer, text in iter_strings(event.payload):
                if pointer != "/name" and pattern.search(text):
                    refs.setdefault(OTHER_SERVER_TOOL_RULE, set()).add(pointer)
        return Result.completed(findings_by_rule(refs, RULES, CATEGORY))


def _foreign_names(own: ToolId, others: list[ToolId]) -> set[str]:
    """Names, bare and server-qualified, that only other servers expose."""
    mine = {t.name for t in others if t.server_id == own.server_id} | {own.name}
    names: set[str] = set()
    for tool in others:
        if tool.server_id == own.server_id:
            continue
        names.add(str(tool))
        if tool.name not in mine:
            names.add(tool.name)
    return names


def _whole_words(names: set[str]) -> re.Pattern[str]:
    alternatives = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(rf"(?<![\w/]){alternatives}(?![\w/])")


def create(settings: Mapping[str, Any]) -> ToolNameSpoofingDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return ToolNameSpoofingDefense(ToolNameSpoofingSettings.model_validate(settings))
