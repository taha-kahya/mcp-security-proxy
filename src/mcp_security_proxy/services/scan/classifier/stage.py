"""Scan's classifier stage: grade tool definitions once, outside the deadline.

`prepare` scores every definition the proxy is about to inspect that it has
not scored yet, in a worker thread, before the Runner starts (ADR 0026). It
is called by the proxy, not by defenses, so the model's time never counts
against a defense's 2 s deadline. `result` only reads the cache; a
definition that was never scored, or whose scoring failed, raises
`ScanError`, so the inspection is reported as failed and policy
`on_failure` decides (block by default). A cache miss is never clean.

The cache is keyed by the definition's canonical digest. The scorer,
checkpoint and operating point are fixed for the life of the stage, so the
key needs nothing else; they are all named in `version`, which every result
carries. Cached entries hold a level and three numbers, never content.
"""

from __future__ import annotations

import logging
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

CutScores = tuple[float, float, float]


class Scorer(Protocol):
    """Blocking: cut scores `P(level > k)`, k = 0, 1, 2, for each text."""

    def score(self, texts: Sequence[str]) -> list[CutScores]: ...


@dataclass(frozen=True)
class _Graded:
    level: str | None
    scores: CutScores


class DefinitionClassifier:
    def __init__(
        self,
        scorer: Scorer,
        checkpoint: Checkpoint,
        operating_point: OperatingPoint = OperatingPoint.HIGH_RECALL,
        *,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
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
        self.version = f"classifier-{checkpoint.name}+{SERIALIZATION_VERSION}+{operating_point}"

    async def prepare(self, definitions: Iterable[Mapping[str, Any]]) -> None:
        """Score the definitions not in the cache. Never raises for a scoring
        failure: it is logged and the definitions stay unscored, so `result`
        reports them as unknown."""
        pending = self._unscored(definitions)
        if not pending:
            return
        async with self._lock:
            # Another inspection may have scored some while this one waited.
            pending = self._unscored(pending.values())
            if not pending:
                return
            texts = [serialize_tool(definition) for definition in pending.values()]
            try:
                scores = await anyio.to_thread.run_sync(self._scorer.score, texts)
                if len(scores) != len(texts):
                    raise ValueError(f"{len(scores)} scores for {len(texts)} definitions")
            except Exception as exc:
                # The message may quote content; log the type only.
                logger.error("classifier failed on %d definitions: %s", len(texts), type(exc))
                return
            for digest, cut_scores in zip(pending, scores, strict=True):
                self._cache.put(digest, _Graded(grade(cut_scores, self._thresholds), cut_scores))

    def result(self, definition: Mapping[str, Any]) -> ScanResult:
        graded = self._cache.get(canonical_digest(definition))
        if graded is None:
            raise ScanError("the classifier has not scored this tool definition")
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

    def _unscored(self, definitions: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
        pending: dict[str, Mapping[str, Any]] = {}
        for definition in definitions:
            digest = canonical_digest(definition)
            if digest not in pending and self._cache.get(digest) is None:
                pending[digest] = definition
        return pending
