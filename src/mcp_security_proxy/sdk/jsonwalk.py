"""Walking JSON values that defenses receive (SDK 1.2).

Event payloads are frozen (`sdk.frozen`): objects arrive as read-only
mappings and arrays as tuples. These helpers treat both forms alike, so a
defense never skips what sits inside `anyOf`, `examples` or `enum` because it
checked only for `list`. Every location is a JSON Pointer (RFC 6901).
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Iterator, Mapping
from typing import Any

from mcp_security_proxy.sdk.results import Finding, Severity


def is_array(value: Any) -> bool:
    return isinstance(value, list | tuple)


def escape(key: object) -> str:
    """One JSON Pointer reference token."""
    return str(key).replace("~", "~0").replace("/", "~1")


def child(pointer: str, key: object) -> str:
    return f"{pointer}/{escape(key)}"


def iter_strings(value: Any, pointer: str = "") -> Iterator[tuple[str, str]]:
    """Every string value at any depth, with its pointer. Keys are not included."""
    if isinstance(value, str):
        yield pointer, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from iter_strings(item, child(pointer, key))
    elif is_array(value):
        for index, item in enumerate(value):
            yield from iter_strings(item, child(pointer, index))


def iter_keyword_values(
    value: Any, keywords: Collection[str], pointer: str = "", _parent: str | None = None
) -> Iterator[tuple[str, Any]]:
    """The value of every JSON Schema keyword in `keywords`, at any depth.

    Keys directly under `properties` (or `patternProperties`) are property
    names, so a parameter called `default` is a schema to walk, not a value.
    """
    if isinstance(value, Mapping):
        for key, item in value.items():
            location = child(pointer, key)
            if key in keywords and _parent not in ("properties", "patternProperties"):
                yield location, item
            else:
                yield from iter_keyword_values(item, keywords, location, str(key))
    elif is_array(value):
        for index, item in enumerate(value):
            yield from iter_keyword_values(item, keywords, child(pointer, index))


def findings_by_rule(
    refs: Mapping[str, Iterable[str]],
    rules: Mapping[str, tuple[Severity, str]],
    category: str,
) -> list[Finding]:
    """One finding per rule, listing every evidence reference, in rule order."""
    return [
        Finding(rule, category, rules[rule][0], rules[rule][1], tuple(sorted(set(refs[rule]))))
        for rule in sorted(refs)
        if refs[rule]
    ]
