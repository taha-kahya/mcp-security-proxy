"""Views of one piece of text that undo the usual ways of hiding words.

A detector matches its patterns against every view, so encoding can't hide
a phrase:

- the **normalized** view: NFKC, with invisible and control characters
  removed (`ｉｇｎｏｒｅ`, `ig​nore` -> `ignore`);
- the **folded** view: the normalized view with lookalike letters mapped to
  their ASCII prototype (Cyrillic `іgnore` -> `ignore`), only when it differs;
- views of **decoded segments**: Unicode tag characters, base64 (standard
  and URL-safe) and percent-encoding, recursively, so double encoding is
  undone too.

Every view keeps a map back to the original text. `View.locate` turns a
match in a view into the original character range plus the decodings that
had to be undone to reveal it. A match in a decoded segment covers the whole
encoded segment.
"""

from __future__ import annotations

import binascii
import re
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import cache, cached_property, lru_cache
from urllib.parse import unquote

from mcp_security_proxy.sdk import Decoding, ScanLimitError
from mcp_security_proxy.services.scan.unicode_data import UnicodeData

MAX_DEPTH = 3
# More disguised segments (base64, tag characters) than this in one string is
# not normal text; the scan stops with `ScanLimitError` rather than skip the
# rest. Percent-encoding is normal in URLs, so it doesn't count.
MAX_DISGUISED_SEGMENTS = 256
MIN_BASE64_LENGTH = 16

# Characters with no visible glyph that are not format characters (Cf).
_FILLERS = frozenset("\u034f\u115f\u1160\u3164\uffa0")
_KEPT_CONTROLS = frozenset("\t\n\r")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
# Anything normalization might change: outside printable ASCII and kept controls.
_SPECIAL_RUN = re.compile(r"[^\x20-\x7e\t\n\r]+")
_TAG_FIRST, _TAG_LAST = 0xE0000, 0xE007F
_TAG_OFFSET = _TAG_FIRST
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_BASE64 = re.compile(rf"(?<![\w+/=-])[A-Za-z0-9+/_-]{{{MIN_BASE64_LENGTH},}}={{0,2}}(?![\w+/=-])")
# A whole whitespace-delimited token with at least two escapes. Matching starts
# only at a token start, so long words are scanned once, not once per position.
_PERCENT = re.compile(r"(?<!\S)(?=\S*?%[0-9A-Fa-f]{2}\S*?%[0-9A-Fa-f]{2})\S+")


def is_invisible(char: str) -> bool:
    """A character that renders as nothing: format characters and fillers."""
    return unicodedata.category(char) == "Cf" or char in _FILLERS


@cache
def invisible_run() -> re.Pattern[str]:
    """Runs of invisible characters other than tag characters, which are
    handled as encoded text. Built once from the interpreter's Unicode data."""
    members = [
        code_point
        for code_point in range(0x110000)
        if not _TAG_FIRST <= code_point <= _TAG_LAST and is_invisible(chr(code_point))
    ]
    return re.compile(f"[{''.join(_class_ranges(members))}]+")


def _class_ranges(code_points: list[int]) -> Iterator[str]:
    start = previous = code_points[0]
    for code_point in [*code_points[1:], -1]:
        if code_point != previous + 1:
            yield f"\\U{start:08x}-\\U{previous:08x}"
            start = code_point
        previous = code_point


@lru_cache(maxsize=8192)
def normalize_char(char: str) -> str:
    if is_invisible(char):
        return ""
    if unicodedata.category(char) == "Cc" and char not in _KEPT_CONTROLS:
        return ""
    return unicodedata.normalize("NFKC", char)


def _obfuscates(char: str) -> bool:
    """Normalization changed a character that isn't just a kind of space,
    such as a fullwidth letter or a removed invisible character."""
    return normalize_char(char) != char and unicodedata.category(char) != "Zs"


@dataclass(frozen=True)
class Located:
    """Where a match is in the original text, and how it was revealed.

    `obfuscated` is set when normalization had to undo a deliberate
    disguise (fullwidth letters, invisible characters), not just spacing.
    """

    span: tuple[int, int]
    decoded_by: tuple[Decoding, ...] = ()
    obfuscated: bool = False


@dataclass(frozen=True)
class View:
    """`text` as matched; `base` is the same text before lookalike folding,
    position for position; `index_map[i]` is the position in `source` that
    `text[i]` came from. `outer` places a view of a decoded segment in the
    original text."""

    text: str
    base: str
    source: str
    index_map: Sequence[int]
    outer: Located | None = None

    @property
    def is_folded(self) -> bool:
        return self.text != self.base

    def locate(self, start: int, end: int) -> Located:
        src_start, src_end = self.index_map[start], self.index_map[end - 1] + 1
        original = self.source[src_start:src_end]
        decoded_by: list[Decoding] = []
        if self.base[start:end] != original:
            decoded_by.append(Decoding.NORMALIZATION)
        if self.text[start:end] != self.base[start:end]:
            decoded_by.append(Decoding.CONFUSABLES)
        obfuscated = any(_obfuscates(char) for char in original)
        if self.outer is None:
            return Located((src_start, src_end), tuple(decoded_by), obfuscated)
        return Located(
            self.outer.span,
            self.outer.decoded_by + tuple(decoded_by),
            self.outer.obfuscated or obfuscated,
        )


@dataclass(frozen=True)
class Segment:
    """An encoded run of the text, its span in the text, and what it decodes to."""

    span: tuple[int, int]
    decoding: Decoding
    decoded: str


class TextViews:
    def __init__(
        self, text: str, unicode: UnicodeData, *, depth: int = 0, outer: Located | None = None
    ) -> None:
        self.text = text
        self._unicode = unicode
        self._depth = depth
        self._outer = outer

    def views(self) -> Iterator[View]:
        yield self.normalized
        if self.folded is not None:
            yield self.folded
        if self._depth >= MAX_DEPTH:
            return
        for segment in self.segments:
            nested = TextViews(
                segment.decoded, self._unicode, depth=self._depth + 1, outer=self._place(segment)
            )
            yield from nested.views()

    @cached_property
    def normalized(self) -> View:
        text = self.text
        if not _SPECIAL_RUN.search(text):
            return View(text, text, text, range(len(text)), self._outer)
        chars: list[str] = []
        index_map: list[int] = []
        position = 0
        for match in _SPECIAL_RUN.finditer(text):
            start, end = match.span()
            chars.append(text[position:start])
            index_map.extend(range(position, start))
            self._normalize_run(match.group(), start, chars, index_map)
            position = end
        chars.append(text[position:])
        index_map.extend(range(position, len(text)))
        normalized = "".join(chars)
        return View(normalized, normalized, text, index_map, self._outer)

    @cached_property
    def folded(self) -> View | None:
        base = self.normalized
        if base.text.isascii():
            return None
        folded = base.text.translate(self._unicode.ascii_folding)
        if folded == base.text:
            return None
        return View(folded, base.text, self.text, base.index_map, self._outer)

    @cached_property
    def segments(self) -> tuple[Segment, ...]:
        found = [*self._tag_segments(), *self._encoded_segments()]
        disguised = sum(segment.decoding is not Decoding.PERCENT for segment in found)
        if disguised > MAX_DISGUISED_SEGMENTS:
            raise ScanLimitError(
                f"more than {MAX_DISGUISED_SEGMENTS} encoded segments in one string"
            )
        return tuple(sorted(found, key=lambda segment: segment.span))

    @staticmethod
    def _normalize_run(run: str, start: int, chars: list[str], index_map: list[int]) -> None:
        """Copy a run that is already normalized and visible in one step;
        otherwise normalize it character by character."""
        if unicodedata.is_normalized("NFKC", run) and not invisible_run().search(run):
            if not _CONTROL.search(run) and not _TAG_RUN.search(run):
                chars.append(run)
                index_map.extend(range(start, start + len(run)))
                return
        for offset, char in enumerate(run):
            replacement = normalize_char(char)
            chars.append(replacement)
            index_map.extend([start + offset] * len(replacement))

    def _place(self, segment: Segment) -> Located:
        if self._outer is None:
            return Located(segment.span, (segment.decoding,))
        return Located(
            self._outer.span,
            self._outer.decoded_by + (segment.decoding,),
            self._outer.obfuscated,
        )

    def _tag_segments(self) -> Iterator[Segment]:
        """Tag characters mirror ASCII (U+E0041 is an invisible `A`)."""
        for match in _TAG_RUN.finditer(self.text):
            decoded = "".join(
                chr(ord(char) - _TAG_OFFSET)
                for char in match.group()
                if 0xE0020 <= ord(char) <= 0xE007E
            )
            if decoded.strip():
                yield Segment(match.span(), Decoding.UNICODE_TAGS, decoded)

    def _encoded_segments(self) -> Iterator[Segment]:
        view = self.normalized
        patterns = [(_BASE64, decode_base64)]
        if "%" in view.text:
            patterns.append((_PERCENT, _decode_percent))
        for pattern, decode in patterns:
            for match in pattern.finditer(view.text):
                decoded = decode(match.group())
                if decoded is not None:
                    start, end = match.span()
                    span = (view.index_map[start], view.index_map[end - 1] + 1)
                    yield Segment(span, decoded[0], decoded[1])


def decode_base64(candidate: str) -> tuple[Decoding, str] | None:
    """The decoded text, if `candidate` is base64 of readable UTF-8 text."""
    standard = "+" in candidate or "/" in candidate
    url_safe = "-" in candidate or "_" in candidate
    if standard and url_safe:
        return None
    stripped = candidate.rstrip("=")
    if len(stripped) % 4 == 1:
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    if url_safe:
        padded = padded.replace("-", "+").replace("_", "/")
    try:
        raw = binascii.a2b_base64(padded, strict_mode=True)
    except (binascii.Error, ValueError):
        return None
    text = readable_text(raw)
    if text is None:
        return None
    return (Decoding.BASE64_URL if url_safe else Decoding.BASE64), text


def _decode_percent(candidate: str) -> tuple[Decoding, str] | None:
    try:
        decoded = unquote(candidate, errors="strict")
    except UnicodeDecodeError:
        return None
    return (Decoding.PERCENT, decoded) if decoded != candidate else None


def readable_text(raw: bytes) -> str | None:
    """`raw` as text, if it is UTF-8 that is mostly printable and has words."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    printable = sum(char.isprintable() or char in _KEPT_CONTROLS for char in text)
    letters = sum(char.isalpha() for char in text)
    if printable < 0.95 * len(text) or letters < 0.3 * len(text):
        return None
    return text
