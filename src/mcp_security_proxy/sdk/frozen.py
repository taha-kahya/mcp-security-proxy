"""Deep-immutable views of JSON-like data.

Contract inputs carry protocol content as nested mappings and lists. Freezing
them means a defense can never alter what the core, Guard, or another
defense sees.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any


def freeze(value: Any) -> Any:
    """Mappings become read-only mappings and lists become tuples, recursively."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    """The inverse of `freeze`: plain dicts and lists, ready to serialize."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [thaw(item) for item in value]
    return value
