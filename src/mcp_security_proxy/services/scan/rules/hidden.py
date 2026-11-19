"""Hidden content: text the model reads but a person reviewing it would not see.

Covers HTML and Markdown comments, invisible and bidirectional control
characters, Unicode tag characters, control characters and terminal escape
sequences, `data:` URIs, base64 that decodes to readable text, and padding
that pushes content out of view.

Known benign uses are left out: a byte-order mark at the start, joiners
between non-ASCII characters (emoji sequences, Indic and Arabic shaping),
and the tag sequences of subdivision flag emoji.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_security_proxy.sdk import Confidence, Decoding, Detector, MatchKind
from mcp_security_proxy.services.scan.rules.base import Evidence, search
from mcp_security_proxy.services.scan.views import Located, TextViews, invisible_run

_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
_MARKDOWN_COMMENT = re.compile(
    r"^[ \t]*\[[^\]\n]*\]:[ \t]*(?:#|<>)[ \t]*(?:\([^\n]*\)|\"[^\n]*\"|'[^\n]*')[ \t]*$",
    re.MULTILINE,
)
_DATA_URI = re.compile(
    r"\bdata:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*(?:;base64)?,[^\s\"'<>)]*",
    re.IGNORECASE,
)
_CONTROL = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: colours, cursor movement, erase line
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC: window titles, hyperlinks
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]+"
)
_PADDING = re.compile(r"(?:[^\S\r\n]{80,}|(?:[ \t]*\r?\n){20,})(?=\s*\S)")
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
_JOINERS = frozenset("‌‍")
_BYTE_ORDER_MARK = "﻿"
_BLACK_FLAG = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"

# Kinds whose span hides other text: a match inside one is concealed.
# Padding hides everything after it, so its region runs to the end.
REGION_KINDS = frozenset(
    {
        MatchKind.HTML_COMMENT,
        MatchKind.MARKDOWN_COMMENT,
        MatchKind.INVISIBLE_CHARACTER,
        MatchKind.BIDI_CONTROL,
        MatchKind.TAG_CHARACTER,
        MatchKind.CONTROL_CHARACTER,
    }
)


class HiddenContentRule:
    detector = Detector.HIDDEN

    def detect(self, text: TextViews) -> Iterator[Evidence]:
        view = text.normalized
        yield from search(_HTML_COMMENT, view, MatchKind.HTML_COMMENT, Confidence.HIGH)
        yield from search(_MARKDOWN_COMMENT, view, MatchKind.MARKDOWN_COMMENT, Confidence.HIGH)
        yield from search(_DATA_URI, view, MatchKind.DATA_URI, Confidence.MEDIUM)
        yield from search(_PADDING, view, MatchKind.PADDING, Confidence.MEDIUM)
        yield from _characters(text.text)
        yield from _controls(text.text)
        yield from _tags(text.text)
        yield from _encoded_text(text)


def hidden_regions(text: TextViews) -> list[tuple[int, int]]:
    """Spans of `text` that hide whatever they contain."""
    regions = []
    for evidence in HiddenContentRule().detect(text):
        if evidence.kind in REGION_KINDS:
            regions.append(evidence.located.span)
        elif evidence.kind is MatchKind.PADDING:
            regions.append((evidence.located.span[0], len(text.text)))
    return regions


def _characters(text: str) -> Iterator[Evidence]:
    """Runs of invisible or bidirectional control characters, split by kind."""
    for run in invisible_run().finditer(text):
        start = run.start()
        kind: MatchKind | None = None
        for index in range(run.start(), run.end() + 1):
            current = _character_kind(text, index) if index < run.end() else None
            if current is not kind:
                if kind is not None:
                    yield Evidence(kind, Located((start, index)), Confidence.HIGH)
                start, kind = index, current


def _character_kind(text: str, index: int) -> MatchKind | None:
    char = text[index]
    if char in _BIDI_CONTROLS:
        return MatchKind.BIDI_CONTROL
    if char == _BYTE_ORDER_MARK and index == 0:
        return None
    if char in _JOINERS and not _next_to_ascii(text, index):
        return None
    return MatchKind.INVISIBLE_CHARACTER


def _next_to_ascii(text: str, index: int) -> bool:
    neighbours = text[max(index - 1, 0) : index] + text[index + 1 : index + 2]
    return any(char.isascii() for char in neighbours)


def _controls(text: str) -> Iterator[Evidence]:
    for match in _CONTROL.finditer(text):
        label = "terminal_escape" if match.group().startswith("\x1b") else ""
        yield Evidence(MatchKind.CONTROL_CHARACTER, Located(match.span()), Confidence.HIGH, label)


def _tags(text: str) -> Iterator[Evidence]:
    for match in _TAG_RUN.finditer(text):
        start, end = match.span()
        is_flag = text[start - 1 : start] == _BLACK_FLAG and match.group().endswith(_CANCEL_TAG)
        if not is_flag:
            yield Evidence(MatchKind.TAG_CHARACTER, Located((start, end)), Confidence.HIGH)


def _encoded_text(text: TextViews) -> Iterator[Evidence]:
    for segment in text.segments:
        if segment.decoding in (Decoding.BASE64, Decoding.BASE64_URL):
            located = Located(segment.span, (segment.decoding,))
            yield Evidence(MatchKind.ENCODED_TEXT, located, Confidence.MEDIUM)
