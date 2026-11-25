"""Scan's rule stage behind the `ScanView` contract.

For each string in the scanned value, the detector's rule reports evidence;
the scanner places it in the value (JSON Pointer, original range), marks it
concealed when it was revealed by a disguising decoding or sits inside
hidden content, and drops duplicates found by several views. Results are
cached per detector and content digest.

Values over `max_chars` raise `ScanLimitError` rather than being partly
scanned: a defense must report them as failed, never as clean.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from mcp_security_proxy.sdk import (
    Decoding,
    Detector,
    ScanError,
    ScanLimitError,
    ScanMatch,
    ScanResult,
    canonical_digest,
)
from mcp_security_proxy.services.scan.cache import LruCache
from mcp_security_proxy.services.scan.rules import (
    Evidence,
    HiddenContentRule,
    InstructionsRule,
    LookalikesRule,
    Rule,
    SecretsRule,
    hidden_regions,
)
from mcp_security_proxy.services.scan.unicode_data import UnicodeData, unicode_data
from mcp_security_proxy.services.scan.views import Located, TextViews
from mcp_security_proxy.services.scan.walk import TextLeaf, text_leaves

RULES_VERSION = "1"
DEFAULT_MAX_CHARS = 1_000_000
DEFAULT_CACHE_ENTRIES = 1024

# Decodings that only make sense as a disguise. Percent-encoding is normal in
# URLs, so only double percent-encoding counts.
_DISGUISES = frozenset(
    {Decoding.BASE64, Decoding.BASE64_URL, Decoding.UNICODE_TAGS, Decoding.CONFUSABLES}
)


class RuleScanner:
    def __init__(
        self,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
        unicode: UnicodeData | None = None,
    ) -> None:
        data = unicode or unicode_data()
        self._max_chars = max_chars
        self._cache: LruCache[tuple[ScanMatch, ...]] = LruCache(cache_entries)
        self._unicode = data
        self._rules: Mapping[Detector, Rule] = {
            Detector.HIDDEN: HiddenContentRule(),
            Detector.INSTRUCTIONS: InstructionsRule(),
            Detector.LOOKALIKES: LookalikesRule(data),
            Detector.SECRETS: SecretsRule(),
        }
        self.version = f"rules-{RULES_VERSION}+unicode-{data.version}"

    async def hidden(self, value: Any) -> ScanResult:
        return self._scan(Detector.HIDDEN, value)

    async def instructions(self, value: Any) -> ScanResult:
        return self._scan(Detector.INSTRUCTIONS, value)

    async def lookalikes(self, value: Any) -> ScanResult:
        return self._scan(Detector.LOOKALIKES, value)

    async def secrets(self, value: Any) -> ScanResult:
        return self._scan(Detector.SECRETS, value)

    async def poisoning(self, definition: Mapping[str, Any]) -> ScanResult:
        raise ScanError("no classifier stage is configured (scan.classifier, ADR 0026)")

    def _scan(self, detector: Detector, value: Any) -> ScanResult:
        leaves = list(text_leaves(value))
        size = sum(len(leaf.text) for leaf in leaves)
        if size > self._max_chars:
            raise ScanLimitError(f"{size} characters to scan; the limit is {self._max_chars}")
        key = (detector, canonical_digest(value))
        matches = self._cache.get(key)
        if matches is None:
            rule = self._rules[detector]
            matches = tuple(match for leaf in leaves for match in self._matches(rule, leaf))
            self._cache.put(key, matches)
        return ScanResult(matches, self.version)

    def _matches(self, rule: Rule, leaf: TextLeaf) -> Iterator[ScanMatch]:
        text = TextViews(leaf.text, self._unicode)
        regions: list[tuple[int, int]] | None = None
        seen: set[tuple[Any, ...]] = set()
        for evidence in rule.detect(text):
            identity = (evidence.kind, evidence.located.span, evidence.label)
            if identity in seen:
                continue
            seen.add(identity)
            if rule.detector is Detector.HIDDEN:
                concealed = True
            else:
                regions = hidden_regions(text) if regions is None else regions
                concealed = is_concealed(evidence.located, regions)
            yield _match(rule.detector, leaf, evidence, concealed)


def is_concealed(located: Located, hidden: list[tuple[int, int]]) -> bool:
    start, end = located.span
    return (
        located.obfuscated
        or bool(_DISGUISES.intersection(located.decoded_by))
        or located.decoded_by.count(Decoding.PERCENT) > 1
        or any(start < region_end and region_start < end for region_start, region_end in hidden)
    )


def _match(detector: Detector, leaf: TextLeaf, evidence: Evidence, concealed: bool) -> ScanMatch:
    return ScanMatch(
        detector=detector,
        kind=evidence.kind,
        pointer=leaf.pointer,
        span=evidence.located.span,
        confidence=evidence.confidence,
        decoded_by=evidence.located.decoded_by,
        concealed=concealed,
        in_key=leaf.in_key,
        label=evidence.label,
    )
