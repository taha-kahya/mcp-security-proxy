"""Unicode lookalike data: each character's script and its confusable prototype.

Loaded once from the vendored Unicode files (`data/unicode-<version>/`), so
detection doesn't depend on a third-party package's copy of the standard.
`skeleton` follows UTS #39: two strings that look alike have equal skeletons.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from types import MappingProxyType

UNICODE_VERSION = "17.0.0"
UNKNOWN_SCRIPT = "Unknown"
# Scripts that never make a word mixed: punctuation, digits, combining marks.
NEUTRAL_SCRIPTS = frozenset({"Common", "Inherited", UNKNOWN_SCRIPT})


@dataclass(frozen=True)
class ScriptRanges:
    """Sorted, non-overlapping code point ranges, searched by bisection."""

    starts: tuple[int, ...]
    ends: tuple[int, ...]
    names: tuple[str, ...]

    def script(self, char: str) -> str:
        code_point = ord(char)
        index = bisect_right(self.starts, code_point) - 1
        if index >= 0 and code_point <= self.ends[index]:
            return self.names[index]
        return UNKNOWN_SCRIPT


@dataclass(frozen=True)
class UnicodeData:
    version: str
    prototypes: Mapping[str, str]
    scripts: ScriptRanges
    # For each prototype, the scripts that have a character looking like it.
    prototype_scripts: Mapping[str, frozenset[str]]
    # `str.translate` table: non-ASCII lookalikes of a single ASCII character.
    ascii_folding: Mapping[int, str]

    def script(self, char: str) -> str:
        return self.scripts.script(char)

    def prototype(self, char: str) -> str:
        """The character this one is confusable with, or itself."""
        return self.prototypes.get(char, char)

    def has_lookalike_in(self, char: str, script: str) -> bool:
        """Whether `script` has a character that looks like `char`."""
        return script in self.prototype_scripts.get(self.prototype(char), frozenset())

    def skeleton(self, text: str) -> str:
        decomposed = unicodedata.normalize("NFD", text)
        mapped = "".join(self.prototype(char) for char in decomposed)
        return unicodedata.normalize("NFD", mapped)


@cache
def unicode_data() -> UnicodeData:
    folder = files("mcp_security_proxy.services.scan").joinpath(
        "data", f"unicode-{UNICODE_VERSION}"
    )
    confusables = folder.joinpath("confusables.txt").read_text(encoding="utf-8-sig")
    scripts = folder.joinpath("Scripts.txt").read_text(encoding="utf-8-sig")
    prototypes = parse_confusables(confusables)
    script_ranges = parse_scripts(scripts)
    return UnicodeData(
        UNICODE_VERSION,
        MappingProxyType(prototypes),
        script_ranges,
        MappingProxyType(_prototype_scripts(prototypes, script_ranges)),
        MappingProxyType(_ascii_folding(prototypes)),
    )


def _ascii_folding(prototypes: Mapping[str, str]) -> dict[int, str]:
    return {
        ord(char): prototype
        for char, prototype in prototypes.items()
        if not char.isascii() and len(prototype) == 1 and prototype.isascii()
    }


def _prototype_scripts(
    prototypes: Mapping[str, str], scripts: ScriptRanges
) -> dict[str, frozenset[str]]:
    found: dict[str, set[str]] = {}
    for char, prototype in prototypes.items():
        found.setdefault(prototype, set()).add(scripts.script(char))
        if len(prototype) == 1:
            found[prototype].add(scripts.script(prototype))
    return {prototype: frozenset(names) for prototype, names in found.items()}


def parse_confusables(text: str) -> dict[str, str]:
    """`0430 ;\t0061 ;\tMA\t# ...` maps CYRILLIC SMALL LETTER A to LATIN SMALL LETTER A."""
    prototypes: dict[str, str] = {}
    for fields in _data_lines(text):
        source, target = fields[0], fields[1]
        prototypes[_chars(source)] = _chars(target)
    return prototypes


def parse_scripts(text: str) -> ScriptRanges:
    """`0041..005A    ; Latin # ...` or `00AA          ; Latin # ...`."""
    ranges: list[tuple[int, int, str]] = []
    for fields in _data_lines(text):
        first, _, last = fields[0].partition("..")
        ranges.append((int(first, 16), int(last or first, 16), fields[1]))
    ranges.sort()
    return ScriptRanges(
        tuple(start for start, _, _ in ranges),
        tuple(end for _, end, _ in ranges),
        tuple(name for _, _, name in ranges),
    )


def _data_lines(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        content = line.split("#", 1)[0].strip()
        if content:
            rows.append([field.strip() for field in content.split(";")])
    return rows


def _chars(code_points: str) -> str:
    return "".join(chr(int(code_point, 16)) for code_point in code_points.split())
