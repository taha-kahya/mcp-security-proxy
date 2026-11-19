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
from functools import cached_property
from urllib.parse import unquote

from mcp_security_proxy.sdk import Decoding
from mcp_security_proxy.services.scan.unicode_data import UnicodeData

MAX_DEPTH = 3
MAX_SEGMENTS = 32
MIN_BASE64_LENGTH = 16

# Characters with no visible glyph that are not format characters (Cf).
_FILLERS = frozenset("͏ᅟᅠㅤﾠ")
_KEPT_CONTROLS = frozenset("\t\n\r")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_TAG_OFFSET = 0xE0000
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_BASE64 = re.compile(rf"(?<![\w+/=-])[A-Za-z0-9+/_-]{{{MIN_BASE64_LENGTH},}}={{0,2}}(?![\w+/=-])")
_PERCENT = re.compile(r"[^\s%]*(?:%[0-9A-Fa-f]{2}[^\s%]*){2,}")


def is_invisible(char: str) -> bool:
    """A character that renders as nothing: format characters and fillers."""
    return unicodedata.category(char) == "Cf" or char in _FILLERS


def normalize_char(char: str) -> str:
    if is_invisible(char):
        return ""
    if unicodedata.category(char) == "Cc" and char not in _KEPT_CONTROLS:
        return ""
    return unicodedata.normalize("NFKC", char)


def normalize(text: str) -> str:
    return "".join(normalize_char(char) for char in text)


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
        if self.text.isascii() and not _CONTROL.search(self.text):
            return View(self.text, self.text, self.text, range(len(self.text)), self._outer)
        chars: list[str] = []
        index_map: list[int] = []
        for index, char in enumerate(self.text):
            replacement = normalize_char(char)
            chars.append(replacement)
            index_map.extend([index] * len(replacement))
        text = "".join(chars)
        return View(text, text, self.text, index_map, self._outer)

    @cached_property
    def folded(self) -> View | None:
        base = self.normalized
        folded = "".join(self._fold(char) for char in base.text)
        if folded == base.text:
            return None
        return View(folded, base.text, self.text, base.index_map, self._outer)

    @cached_property
    def segments(self) -> tuple[Segment, ...]:
        found = [*self._tag_segments(), *self._encoded_segments()]
        return tuple(sorted(found, key=lambda s: s.span)[:MAX_SEGMENTS])

    def _fold(self, char: str) -> str:
        if char.isascii():
            return char
        prototype = self._unicode.prototype(char)
        return prototype if len(prototype) == 1 and prototype.isascii() else char

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
        for pattern, decode in ((_BASE64, decode_base64), (_PERCENT, _decode_percent)):
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
