"""Grade how a tool definition changed since it was approved (plan MR T2).

A rug pull ships a harmless tool, waits until it is reviewed or installed,
then changes the definition: a new parameter that carries data out, a lost
`readOnlyHint`, new instructions in the description. The proxy re-discovers
a server's tools when it sends `notifications/tools/list_changed`, and keeps
the first definition it saw for each tool as the approved version
(`RegistryView.approved`). At `discovery`, and so before every call, this
defense compares the definition being inspected with the approved one:

- `capability_added` (high): the tool can now carry or change more: a new
  property anywhere in `inputSchema`, a property newly `required`, a new
  `enum` value, a lost `readOnlyHint: true`, or a `destructiveHint` or
  `openWorldHint` that no longer says false.
- `text_changed` (medium): a `description` or `title` differs. The new text
  may carry instructions; Direct's defenses inspect it too.
- `narrowed` (low): the only changes are removals: a property, a
  requirement or an `enum` value removed.
- `unclassified` (medium): the definition changed in a way none of the
  above explains (a type, a default, `_meta`, an output schema). Reported,
  never treated as unchanged.

Evidence points at each changed field (`/inputSchema/properties/mirror_to`,
`/annotations/readOnlyHint`). A tool with no approved version yet is clean:
its first definition is what Direct's defenses inspect.

Does not cover: a server that changes behaviour without changing its
definition, or a tool removed and re-added under a new name (a new tool,
first seen). Invalidating earlier approvals is V5's.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Event,
    Finding,
    Manifest,
    Result,
    Severity,
    Stage,
)

DEFENSE_ID = "temporal_definition_drift"
CATEGORY = "temporal"
CAPABILITY_ADDED_RULE = f"{DEFENSE_ID}.capability_added"
TEXT_CHANGED_RULE = f"{DEFENSE_ID}.text_changed"
NARROWED_RULE = f"{DEFENSE_ID}.narrowed"
UNCLASSIFIED_RULE = f"{DEFENSE_ID}.unclassified"

MANIFEST = Manifest(
    id=DEFENSE_ID,
    version="0.1.0",
    sdk_version_range=">=1.2,<2",
    stages=frozenset({Stage.DISCOVERY}),
    required_capabilities=frozenset({Capability.REGISTRY}),
)

RULES: Mapping[str, tuple[Severity, str]] = {
    CAPABILITY_ADDED_RULE: (
        Severity.HIGH,
        "tool gained parameters, values or permissions since it was approved",
    ),
    TEXT_CHANGED_RULE: (Severity.MEDIUM, "tool's descriptive text changed since it was approved"),
    NARROWED_RULE: (Severity.LOW, "tool only lost parameters or values since it was approved"),
    UNCLASSIFIED_RULE: (
        Severity.MEDIUM,
        "tool definition changed since it was approved in a way that isn't classified",
    ),
}

TEXT_KEYS = frozenset({"description", "title"})
SET_KEYS = frozenset({"enum", "required"})
# annotation -> the value that claims less power; losing it is a capability gain.
CAUTIOUS_CLAIMS: Mapping[str, bool] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}


class DefinitionDriftSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DefinitionDriftDefense:
    def __init__(self, settings: DefinitionDriftSettings) -> None:
        self._settings = settings

    def manifest(self) -> Manifest:
        return MANIFEST

    async def evaluate(self, event: Event, context: Context) -> Result:
        if event.stage is not Stage.DISCOVERY or event.method != "tools/list":
            return Result.not_applicable()
        if event.tool_id is None:
            return Result.unsupported("a definition without a tool id")
        approved = context.registry.approved(event.tool_id)
        if approved is None:
            return Result.completed()
        return Result.completed(_findings(_classify(approved.definition, event.payload)))


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _flatten(value: Any, pointer: str = "") -> Iterator[tuple[str, str]]:
    """Leaves as (pointer, canonical JSON). Lists may arrive frozen, as tuples.
    Members of `enum` and `required` are keyed by value, so reordering them is
    not a change."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{pointer}/{_escape(str(key))}"
            if key in SET_KEYS and isinstance(item, (list, tuple)):
                for member in item:
                    yield f"{child}/{_escape(_canonical(member))}", "true"
            else:
                yield from _flatten(item, child)
        if not value:
            yield pointer, "{}"
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{pointer}/{index}")
        if not value:
            yield pointer, "[]"
    else:
        yield pointer, _canonical(value)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _parts(pointer: str) -> list[str]:
    return pointer.split("/")[1:]


def _property_roots(pointer: str) -> list[str]:
    """Every `.../properties/<name>` in `inputSchema` that contains `pointer`,
    outermost first."""
    parts = _parts(pointer)
    if not parts or parts[0] != "inputSchema":
        return []
    return [
        "/" + "/".join(parts[: index + 2])
        for index in range(len(parts) - 1)
        if parts[index] == "properties"
    ]


def _outermost(props: set[str]) -> set[str]:
    return {p for p in props if not any(p.startswith(q + "/") for q in props if q != p)}


def _classify(old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, set[str]]:
    before = dict(_flatten(old))
    after = dict(_flatten(new))
    old_props = {root for p in before for root in _property_roots(p)}
    new_props = {root for p in after for root in _property_roots(p)}
    added, removed = new_props - old_props, old_props - new_props
    refs: dict[str, set[str]] = {}

    def add(rule: str, pointer: str) -> None:
        refs.setdefault(rule, set()).add(pointer)

    for prop in _outermost(added):
        add(CAPABILITY_ADDED_RULE, prop)
    for prop in _outermost(removed):
        add(NARROWED_RULE, prop)

    for pointer in sorted(before.keys() | after.keys()):
        if before.get(pointer) == after.get(pointer):
            continue
        if any(root in added or root in removed for root in _property_roots(pointer)):
            continue  # the whole property was added or removed, reported above
        if _emptied_or_filled(pointer, before, after):
            continue  # an empty `{}` or `[]` that gained or lost members, reported per member
        parts = _parts(pointer)
        annotation = parts[1] if len(parts) == 2 and parts[0] == "annotations" else None
        if annotation is not None and annotation in CAUTIOUS_CLAIMS:
            cautious = _canonical(CAUTIOUS_CLAIMS[annotation])
            if before.get(pointer) == cautious:
                add(CAPABILITY_ADDED_RULE, pointer)
            else:
                add(UNCLASSIFIED_RULE, pointer)
        elif len(parts) >= 2 and parts[-2] in SET_KEYS:
            set_pointer = "/" + "/".join(parts[:-1])
            add(CAPABILITY_ADDED_RULE if pointer in after else NARROWED_RULE, set_pointer)
        elif parts and parts[-1] in TEXT_KEYS:
            add(TEXT_CHANGED_RULE, pointer)
        else:
            add(UNCLASSIFIED_RULE, pointer)

    if NARROWED_RULE in refs and len(refs) > 1:
        # Removals alongside other changes are part of those changes.
        del refs[NARROWED_RULE]
    return refs


def _emptied_or_filled(pointer: str, before: Mapping[str, str], after: Mapping[str, str]) -> bool:
    for side, other in ((before, after), (after, before)):
        if side.get(pointer) in ("{}", "[]") and pointer not in other:
            if any(key.startswith(pointer + "/") for key in other):
                return True
    return False


def _findings(refs: Mapping[str, set[str]]) -> list[Finding]:
    return [
        Finding(rule, CATEGORY, RULES[rule][0], RULES[rule][1], tuple(sorted(refs[rule])))
        for rule in sorted(refs)
    ]


def create(settings: Mapping[str, Any]) -> DefinitionDriftDefense:
    """Entry point: raises `ValueError` (pydantic's ValidationError) for bad settings."""
    return DefinitionDriftDefense(DefinitionDriftSettings.model_validate(settings))
