"""Every piece of text in a JSON value, with the JSON Pointer that locates it.

Mapping keys are text too: a property name is shown to the model as much as
its description, so keys are yielded as leaves of their own (`in_key`).
Numbers, booleans and null carry no text and are skipped. The walk uses an
explicit stack, so deeply nested values can't exhaust the call stack.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

_NO_TEXT = (int, float, bool, type(None))


@dataclass(frozen=True)
class TextLeaf:
    pointer: str
    text: str
    in_key: bool = False


def text_leaves(value: Any) -> Iterator[TextLeaf]:
    """Leaves in document order. Raises `TypeError` for a value that isn't JSON."""
    stack: list[tuple[str, Any]] = [("", value)]
    while stack:
        pointer, item = stack.pop()
        if isinstance(item, TextLeaf):
            yield item
        elif isinstance(item, str):
            yield TextLeaf(pointer, item)
        elif isinstance(item, Mapping):
            children: list[tuple[str, Any]] = []
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError(f"mapping key at {pointer!r} is not a string")
                child_pointer = f"{pointer}/{escape(key)}"
                children += [
                    (child_pointer, TextLeaf(child_pointer, key, in_key=True)),
                    (child_pointer, child),
                ]
            stack.extend(reversed(children))
        elif isinstance(item, list | tuple):
            stack.extend(reversed([(f"{pointer}/{i}", child) for i, child in enumerate(item)]))
        elif not isinstance(item, _NO_TEXT):
            raise TypeError(f"value at {pointer!r} is not JSON: {type(item).__name__}")


def escape(token: str) -> str:
    """RFC 6901: `~` becomes `~0` and `/` becomes `~1`."""
    return token.replace("~", "~0").replace("/", "~1")
