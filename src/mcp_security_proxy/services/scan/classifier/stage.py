"""Scan's classifier stage: grade tool definitions once, outside the deadline.

`prepared` scores every definition the proxy is about to inspect that it has
not scored yet, in a worker thread, before the Runner starts (ADR 0026). It
is entered by the proxy, not by defenses, so the model's time never counts
against a defense's 2 s deadline. `result` only reads grades; a definition
that was never scored, or whose scoring failed, raises `ScanError`, so the
inspection is reported as failed and policy `on_failure` decides (block by
default). A missing grade is never clean, and neither is a definition
longer than the model's input window: it is reported as failed rather than
graded on its beginning alone.

Failures are contained. Scores that are not numbers in [0, 1] count as a
scorer failure. When a batch fails, each definition is retried alone, so
one bad definition does not hide the whole listing; the retries share one
`timeout`, so a model that fails slowly holds the stage for at most two
timeouts. A scoring call that exceeds `timeout` is abandoned; while it is
still running, new definitions stay unscored (fail closed) instead of
queueing behind it.

Grades live in a bounded LRU cache keyed by the definition's canonical
digest. The scorer, checkpoint and operating point are fixed for the life
of the stage, so the key needs nothing else; they are all named in
`version`, which every result carries. Entries hold a level and three
numbers, never content. Inside a `prepared` block the listing's grades are
also held outside the cache, so neither a listing larger than the cache nor
another principal's listing can evict them before the Runner reads them.
"""

from __future__ import annotations

import logging
import math
import threading
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
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
    CutScores,
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
        # Grades of the listings being inspected: digest -> [holders, grade].
        self._held: dict[str, list[Any]] = {}
        self.version = f"classifier-{checkpoint.name}+{SERIALIZATION_VERSION}+{operating_point}"

    @asynccontextmanager
    async def prepared(self, definitions: Iterable[Mapping[str, Any]]) -> AsyncIterator[None]:
        """Score the definitions not scored yet, and keep their grades
        readable by `result` until the block exits, whatever the cache
        evicts meanwhile. Never raises for a scoring failure: it is logged
        and the definitions stay unscored, so `result` reports them as
        unknown."""
        graded = await self._prepare(self._distinct(definitions))
        for digest, entry in graded.items():
            self._held.setdefault(digest, [0, entry])[0] += 1
        try:
            yield
        finally:
            for digest in graded:
                held = self._held[digest]
                held[0] -= 1
                if held[0] == 0:
                    del self._held[digest]

    async def prepare(self, definitions: Iterable[Mapping[str, Any]]) -> None:
        """Score the definitions not scored yet into the cache only."""
        await self._prepare(self._distinct(definitions))

    async def _prepare(self, listing: Mapping[str, Mapping[str, Any]]) -> dict[str, _Graded]:
        """The grades of the listing's definitions that have one."""
        graded = self._graded(listing)
        if len(graded) == len(listing):
            return graded
        async with self._lock:
            # Another inspection may have scored some while this one waited.
            graded |= self._graded(listing)
            texts = {
                digest: serialize_tool(definition)
                for digest, definition in listing.items()
                if digest not in graded
            }
            if not texts:
                return graded
            scores = await self._score(list(texts.values()))
            if scores is not None:
                for digest, cut_scores in zip(texts, scores, strict=True):
                    graded[digest] = self._store(digest, cut_scores)
                return graded
            if len(texts) == 1:
                return graded
            # Contain the failure to the definitions that cause it. The
            # retries share one timeout, so a model that fails slowly cannot
            # hold the lock for one timeout per definition.
            with anyio.move_on_after(self._timeout) as retries:
                for digest, text in texts.items():
                    one = await self._score([text])
                    if one is not None:
                        graded[digest] = self._store(digest, one[0])
            if retries.cancelled_caught:
                unscored = sum(digest not in graded for digest in texts)
                logger.error("classifier retries timed out; %d definitions unscored", unscored)
            return graded

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

    def _store(self, digest: str, scores: CutScores | None) -> _Graded:
        level = None if scores is None else grade(scores, self._thresholds)
        graded = _Graded(level, scores)
        self._cache.put(digest, graded)
        return graded

    def result(self, definition: Mapping[str, Any]) -> ScanResult:
        digest = canonical_digest(definition)
        held = self._held.get(digest)
        graded = held[1] if held is not None else self._cache.get(digest)
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

    def _graded(self, listing: Mapping[str, Mapping[str, Any]]) -> dict[str, _Graded]:
        found = {digest: self._cache.get(digest) for digest in listing}
        return {digest: graded for digest, graded in found.items() if graded is not None}


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
