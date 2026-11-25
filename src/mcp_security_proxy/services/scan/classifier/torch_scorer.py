"""Score serialized tool definitions with an ordinal (CORN) checkpoint.

Only this module imports torch and transformers, and only when a scorer is
built, so the proxy runs without the `classifier` extra unless
`scan.classifier` is configured.

Loading matches the scorer the thresholds were fitted with (pinned by
`tests/contracts/test_scan_classifier_model.py`): the
architecture comes from the bundle's `config.json` with the checkpoint's
number of outputs, and the fine-tuned weights are loaded strictly, so a
missing or extra tensor is an error rather than a randomly initialised head.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp_security_proxy.services.scan.classifier.checkpoints import (
    CHECKPOINTS,
    WEIGHTS_FILE,
    Checkpoint,
)

CutScores = tuple[float, float, float]


class ClassifierLoadError(RuntimeError):
    """The model bundle is missing, altered, or its libraries are not installed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_bundle(model_dir: Path) -> Checkpoint:
    """The checkpoint this bundle is, after checking every file's hash."""
    weights = model_dir / WEIGHTS_FILE
    if not weights.is_file():
        raise ClassifierLoadError(f"no {WEIGHTS_FILE} in {model_dir}")
    checkpoint = CHECKPOINTS.get(sha256_file(weights))
    if checkpoint is None:
        raise ClassifierLoadError(
            f"{weights} is not a known checkpoint; thresholds exist only for known weights"
        )
    for name, expected in checkpoint.files.items():
        path = model_dir / name
        if not path.is_file():
            raise ClassifierLoadError(f"{checkpoint.name}: {name} is missing from {model_dir}")
        if name != WEIGHTS_FILE and sha256_file(path) != expected:
            raise ClassifierLoadError(f"{checkpoint.name}: {name} does not match its pinned hash")
    return checkpoint


class TorchCornScorer:
    """`score` is blocking CPU or GPU work; callers run it in a worker thread."""

    def __init__(
        self, model_dir: Path, checkpoint: Checkpoint, *, device: str, token_budget: int
    ) -> None:
        try:
            import torch
            from safetensors.torch import load_file
            from transformers import (
                AutoConfig,
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
        except ImportError as exc:
            raise ClassifierLoadError(
                "scan.classifier needs the classifier extra: uv sync --extra classifier"
            ) from exc
        self._torch: Any = torch
        self._max_tokens = checkpoint.max_tokens
        self._token_budget = token_budget
        self._device = device
        config = AutoConfig.from_pretrained(str(model_dir), num_labels=checkpoint.num_labels)
        model = AutoModelForSequenceClassification.from_config(config, dtype=torch.float32)
        model.load_state_dict(load_file(str(model_dir / WEIGHTS_FILE)), strict=True)
        model.train(False)
        self._model: Any = model.to(device)
        self._tokenizer: Any = AutoTokenizer.from_pretrained(str(model_dir))
        self._pad = self._tokenizer.pad_token_id

    def score(self, texts: Sequence[str]) -> list[CutScores]:
        """Cut scores `P(level > k)` for k = 0, 1, 2, in input order."""
        encoded = [
            self._tokenizer(text, truncation=True, max_length=self._max_tokens)["input_ids"]
            for text in texts
        ]
        out: dict[int, CutScores] = {}
        for batch in _batches(encoded, self._token_budget):
            logits = self._logits([encoded[i] for i in batch])
            for row, index in zip(_corn_cuts(self._torch, logits), batch, strict=True):
                out[index] = row
        return [out[i] for i in range(len(texts))]

    def _logits(self, batch: list[list[int]]) -> Any:
        torch = self._torch
        width = max(len(ids) for ids in batch)
        input_ids = torch.full((len(batch), width), self._pad, dtype=torch.long)
        mask = torch.zeros((len(batch), width), dtype=torch.long)
        for row, ids in enumerate(batch):
            input_ids[row, : len(ids)] = torch.tensor(ids)
            mask[row, : len(ids)] = 1
        with torch.no_grad():
            logits = self._model(
                input_ids=input_ids.to(self._device), attention_mask=mask.to(self._device)
            ).logits
        return logits.detach().cpu().double()


def _corn_cuts(torch: Any, logits: Any) -> list[CutScores]:
    """CORN: `P(level > k)` is the running product of the conditional sigmoids."""
    cuts = torch.cumprod(torch.sigmoid(logits), dim=1).tolist()
    return [(float(a), float(b), float(c)) for a, b, c in cuts]


def _batches(encoded: Sequence[Sequence[int]], token_budget: int) -> list[list[int]]:
    """Length-sorted batches whose padded size stays within `token_budget`."""
    order = sorted(range(len(encoded)), key=lambda i: len(encoded[i]))
    batches: list[list[int]] = []
    current: list[int] = []
    for index in order:
        if current and (len(current) + 1) * len(encoded[index]) > token_budget:
            batches.append(current)
            current = []
        current.append(index)
    if current:
        batches.append(current)
    return batches
