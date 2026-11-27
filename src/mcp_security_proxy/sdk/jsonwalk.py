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


_NAME_MAPS = ("properties", "patternProperties")


def iter_keyword_values(
    value: Any, keywords: Collection[str], pointer: str = "", _names: bool = False
) -> Iterator[tuple[str, Any]]:
    """The value of every JSON Schema keyword in `keywords`, at any depth.

    Keys directly under `properties` (or `patternProperties`) are property
    names, so a parameter called `default` is a schema to walk, not a value.
    A parameter called `properties` is likewise a schema: its own keys are
    keywords again, not property names.
    """
    if isinstance(value, Mapping):
        for key, item in value.items():
            location = child(pointer, key)
            if key in keywords and not _names:
                yield location, item
            else:
                names = not _names and key in _NAME_MAPS
                yield from iter_keyword_values(item, keywords, location, names)
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
