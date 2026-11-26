"""Words that mix alphabets using lookalike letters, such as `pаypal` with a
Cyrillic `а`.

Follows UTS #39: digits, punctuation and combining marks never make a word
mixed, and Latin mixed with Han, Hiragana, Katakana, Bopomofo or Hangul is
normal writing. A mixed word is reported only when a letter from the
minority script looks like a letter of the word's main script, so
scientific notation such as `μs` and words in other scripts stay clean.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from functools import lru_cache

from mcp_security_proxy.sdk import Confidence, Detector, MatchKind
from mcp_security_proxy.services.scan.rules.base import Evidence
from mcp_security_proxy.services.scan.unicode_data import NEUTRAL_SCRIPTS, UnicodeData
from mcp_security_proxy.services.scan.views import TextViews

# Words with at least one non-ASCII character; all-ASCII words can't mix scripts.
_WORD = re.compile(r"(?<!\w)\w*[^\W\x00-\x7f]\w*")
_ALLOWED_MIXES = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),
    frozenset({"Latin", "Han", "Bopomofo"}),
    frozenset({"Latin", "Han", "Hangul"}),
)


class LookalikesRule:
    detector = Detector.LOOKALIKES

    def __init__(self, unicode: UnicodeData) -> None:
        self._unicode = unicode
        # Words repeat a lot in natural text, so each is classified once.
        self._label = lru_cache(maxsize=65536)(self._confusable_mix)

    def detect(self, text: TextViews) -> Iterator[Evidence]:
        view = text.normalized
        if view.text.isascii():
            return
        for match in _WORD.finditer(view.text):
            label = self._label(match.group())
            if label:
                located = view.locate(*match.span())
                yield Evidence(MatchKind.MIXED_SCRIPT_CONFUSABLE, located, Confidence.MEDIUM, label)

    def _confusable_mix(self, word: str) -> str | None:
        """`"Cyrillic>Latin"` when Cyrillic lookalikes sit in a Latin word."""
        scripts = Counter(
            script
            for char in word
            if char.isalpha() and (script := self._unicode.script(char)) not in NEUTRAL_SCRIPTS
        )
        if len(scripts) < 2 or any(set(scripts) <= allowed for allowed in _ALLOWED_MIXES):
            return None
        main = max(sorted(scripts), key=lambda name: (scripts[name], name == "Latin"))
        minority = sorted(
            {
                self._unicode.script(char)
                for char in word
                if char.isalpha()
                and self._unicode.script(char) not in NEUTRAL_SCRIPTS | {main}
                and self._unicode.has_lookalike_in(char, main)
            }
        )
        return f"{'+'.join(minority)}>{main}" if minority else None
