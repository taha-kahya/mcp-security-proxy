"""Scan's classifier stage (ADR 0026): a local model that grades whole tool
definitions as medium, high or critical.

Importing this package never imports torch; `load_classifier` does, and
only when the operator configured `scan.classifier`.
"""

from __future__ import annotations

from pathlib import Path

from mcp_security_proxy.services.scan.classifier.checkpoints import (
    CHECKPOINTS,
    Checkpoint,
    OperatingPoint,
    Thresholds,
    grade,
)
from mcp_security_proxy.services.scan.classifier.serialize import (
    SERIALIZATION_VERSION,
    serialize_tool,
)
from mcp_security_proxy.services.scan.classifier.stage import (
    DEFAULT_CACHE_ENTRIES,
    DEFAULT_TIMEOUT_SECONDS,
    DefinitionClassifier,
    Scorer,
)
from mcp_security_proxy.services.scan.classifier.torch_scorer import (
    ClassifierLoadError,
    verify_bundle,
)


def load_classifier(
    model_dir: Path,
    operating_point: OperatingPoint,
    *,
    device: str = "cpu",
    token_budget: int = 8192,
    cache_entries: int = DEFAULT_CACHE_ENTRIES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> DefinitionClassifier:
    """Verify the bundle's hashes, load the model, and build the stage.
    Raises `ClassifierLoadError` for a missing, altered or unknown bundle, or
    when the classifier extra is not installed."""
    from mcp_security_proxy.services.scan.classifier.torch_scorer import load_scorer

    checkpoint, scorer = load_scorer(model_dir, device=device, token_budget=token_budget)
    return DefinitionClassifier(
        scorer, checkpoint, operating_point, cache_entries=cache_entries, timeout=timeout
    )


__all__ = [
    "CHECKPOINTS",
    "DEFAULT_CACHE_ENTRIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "SERIALIZATION_VERSION",
    "Checkpoint",
    "ClassifierLoadError",
    "DefinitionClassifier",
    "OperatingPoint",
    "Scorer",
    "Thresholds",
    "grade",
    "load_classifier",
    "serialize_tool",
    "verify_bundle",
]
