"""Scan's classifier stage: grade tool definitions once, outside the deadline.

`prepare` scores every definition the proxy is about to inspect that it has
not scored yet, in a worker thread, before the Runner starts (ADR 0026). It
is called by the proxy, not by defenses, so the model's time never counts
against a defense's 2 s deadline. `result` only reads the cache; a
definition that was never scored, or whose scoring failed, raises
`ScanError`, so the inspection is reported as failed and policy
`on_failure` decides (block by default). A cache miss is never clean, and
neither is a definition longer than the model's input window: it is
reported as failed rather than graded on its beginning alone.

Failures are contained. Scores that are not numbers in [0, 1] count as a
scorer failure. When a batch fails, each definition is retried alone, so
one bad definition does not hide the whole listing. A scoring call that
exceeds `timeout` is abandoned; while it is still running, new definitions
stay unscored (fail closed) instead of queueing behind it.

The cache is keyed by the definition's canonical digest. The scorer,
checkpoint and operating point are fixed for the life of the stage, so the
key needs nothing else; they are all named in `version`, which every result
carries. Cached entries hold a level and three numbers, never content.
The cache grows to hold the largest listing it is given, so a listing never
evicts its own scores before the Runner reads them.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import anyio
import anyio.to_thread

from mcp_security_proxy.sdk import (
    Confidence,
    Detector,
    MatchKind,
    ScanError,
    ScanMatch,
    ScanResult,
    ScanStage,
    canonical_digest,
)
from mcp_security_proxy.services.scan.cache import LruCache
from mcp_security_proxy.services.scan.classifier.checkpoints import (
    Checkpoint,
    OperatingPoint,
    grade,
)
from mcp_security_proxy.services.scan.classifier.serialize import (
    SERIALIZATION_VERSION,
    serialize_tool,
)

logger = logging.getLogger(__name__)

DEFAULT_CACHE_ENTRIES = 10_000
DEFAULT_TIMEOUT_SECONDS = 600.0

CutScores = tuple[float, float, float]


class Scorer(Protocol):
    """Blocking: cut scores `P(level > k)`, k = 0, 1, 2, for each text, or
    None for a text longer than the model's input window."""

    def score(self, texts: Sequence[str]) -> list[CutScores | None]: ...


@dataclass(frozen=True)
class _Graded:
    level: str | None
    scores: CutScores | None  # None: too long to score


class DefinitionClassifier:
    def __init__(
        self,
        scorer: Scorer,
        checkpoint: Checkpoint,
        operating_point: OperatingPoint = OperatingPoint.HIGH_RECALL,
        *,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if checkpoint.serialization != SERIALIZATION_VERSION:
            raise ValueError(
                f"{checkpoint.name} was trained on {checkpoint.serialization}, "
                f"this proxy serializes {SERIALIZATION_VERSION}"
            )
        self._scorer = scorer
        self._thresholds = checkpoint.operating_points[operating_point]
        self._cache: LruCache[_Graded] = LruCache(cache_entries)
        self._lock = anyio.Lock()
        self._timeout = timeout
        # Set while the scorer runs, so an abandoned (timed-out) call that
        # is still running is visible to the next `prepare`.
        self._busy = threading.Event()
        self.version = f"classifier-{checkpoint.name}+{SERIALIZATION_VERSION}+{operating_point}"

    async def prepare(self, definitions: Iterable[Mapping[str, Any]]) -> None:
        """Score the definitions not in the cache. Never raises for a scoring
        failure: it is logged and the definitions stay unscored, so `result`
        reports them as unknown."""
        listing = self._distinct(definitions)
        if self._cache.reserve(len(listing)):
            logger.warning("classifier cache grown to %d entries for one listing", len(listing))
        pending = self._unscored(listing)
        if not pending:
            return
        async with self._lock:
            # Another inspection may have scored some while this one waited.
            pending = self._unscored(pending)
            if not pending:
                return
            texts = {digest: serialize_tool(d) for digest, d in pending.items()}
            scores = await self._score(list(texts.values()))
            if scores is not None:
                for digest, cut_scores in zip(texts, scores, strict=True):
                    self._store(digest, cut_scores)
                return
            if len(texts) == 1:
                return
            # Contain the failure to the definitions that cause it.
            for digest, text in texts.items():
                one = await self._score([text])
                if one is not None:
                    self._store(digest, one[0])

    async def _score(self, texts: list[str]) -> list[CutScores | None] | None:
        """The scorer's output, checked; None (logged) when it failed."""
        if self._busy.is_set():
            logger.error("classifier busy after a timeout; %d definitions unscored", len(texts))
            return None
        try:
            with anyio.fail_after(self._timeout):
                scores = await anyio.to_thread.run_sync(self._run, texts, abandon_on_cancel=True)
            _check(scores, len(texts))
        except TimeoutError:
            logger.error("classifier timed out on %d definitions", len(texts))
            return None
        except Exception as exc:
            # The message may quote content; log the type only.
            logger.error("classifier failed on %d definitions: %s", len(texts), type(exc))
            return None
        return scores

    def _run(self, texts: list[str]) -> list[CutScores | None]:
        self._busy.set()
        try:
            return self._scorer.score(texts)
        finally:
            self._busy.clear()

    def _store(self, digest: str, scores: CutScores | None) -> None:
        level = None if scores is None else grade(scores, self._thresholds)
        self._cache.put(digest, _Graded(level, scores))

    def result(self, definition: Mapping[str, Any]) -> ScanResult:
        graded = self._cache.get(canonical_digest(definition))
        if graded is None:
            raise ScanError("the classifier has not scored this tool definition")
        if graded.scores is None:
            raise ScanError("this tool definition is longer than the classifier's input window")
        if graded.level is None:
            return ScanResult((), self.version)
        match = ScanMatch(
            detector=Detector.POISONING,
            kind=MatchKind.POISONED_DEFINITION,
            pointer="",
            span=(0, 0),
            # Scores are not calibrated probabilities (ADR 0026), so no
            # graded confidence is claimed.
            confidence=Confidence.MEDIUM,
            stage=ScanStage.CLASSIFIER,
            label=graded.level,
        )
        return ScanResult((match,), self.version)

    @staticmethod
    def _distinct(definitions: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
        distinct: dict[str, Mapping[str, Any]] = {}
        for definition in definitions:
            distinct.setdefault(canonical_digest(definition), definition)
        return distinct

    def _unscored(self, listing: Mapping[str, Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
        return {k: d for k, d in listing.items() if self._cache.get(k) is None}


def _check(scores: Sequence[CutScores | None], expected: int) -> None:
    """A broken model fails the scan: wrong count, or scores that are not
    numbers in [0, 1] (NaN included)."""
    if len(scores) != expected:
        raise ValueError(f"{len(scores)} scores for {expected} definitions")
    for row in scores:
        if row is not None and (
            len(row) != 3 or not all(math.isfinite(x) and 0.0 <= x <= 1.0 for x in row)
        ):
            raise ValueError("scores outside [0, 1]")
