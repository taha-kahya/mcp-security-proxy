"""What a rule is: a pure function from one analyzed string to evidence."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from re import Pattern
from typing import Protocol

from mcp_security_proxy.sdk import Confidence, Detector, MatchKind
from mcp_security_proxy.services.scan.views import Located, TextViews, View


@dataclass(frozen=True)
class Evidence:
    """A rule's hit in one string, before Scan places it in the scanned value."""

    kind: MatchKind
    located: Located
    confidence: Confidence
    label: str = ""


class Rule(Protocol):
    detector: Detector

    def detect(self, text: TextViews) -> Iterable[Evidence]: ...


def search(
    pattern: Pattern[str], view: View, kind: MatchKind, confidence: Confidence
) -> Iterator[Evidence]:
    """Every match of `pattern` in `view`, located in the original text."""
    for match in pattern.finditer(view.text):
        if match.end() > match.start():
            yield Evidence(kind, view.locate(*match.span()), confidence)
