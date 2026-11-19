"""A small least-recently-used cache for scan results.

Results hold only pointers and ranges, never content, so sharing them
across principals can't expose one user's text to another.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Hashable
from typing import Generic, TypeVar

_V = TypeVar("_V")


class LruCache(Generic[_V]):
    def __init__(self, max_entries: int) -> None:
        if max_entries < 0:
            raise ValueError("max_entries must not be negative")
        self._max_entries = max_entries
        self._entries: OrderedDict[Hashable, _V] = OrderedDict()

    def get(self, key: Hashable) -> _V | None:
        value = self._entries.get(key)
        if value is not None:
            self._entries.move_to_end(key)
        return value

    def put(self, key: Hashable, value: _V) -> None:
        if self._max_entries == 0:
            return
        self._entries[key] = value
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)
