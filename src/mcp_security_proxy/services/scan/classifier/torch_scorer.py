"""Score serialized tool definitions with an ordinal (CORN) checkpoint.

Only this module imports torch and transformers, and only when a scorer is
built, so the proxy runs without the `classifier` extra unless
`scan.classifier` is configured.

Loading matches the scorer the thresholds were fitted with (pinned by
`tests/contracts/test_scan_classifier_model.py`): the
architecture comes from the bundle's `config.json` with the checkpoint's
number of outputs, and the fine-tuned weights are loaded strictly, so a
missing or extra tensor is an error rather than a randomly initialised head.

The libraries read only the pinned files, and only the bytes that were
hashed: `load_scorer` first checks the bundle in place, so an unknown or
altered bundle is refused before anything is copied, then copies each
pinned file into a private temporary directory, hashing the same bytes it
writes, and loads from there. Other files in the bundle directory are never
read, and a file changed after the check is not loaded.

A text longer than the checkpoint's window is not truncated: its score is
None, and the stage reports the definition as failed.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp_security_proxy.services.scan.classifier.checkpoints import (
    CHECKPOINTS,
    WEIGHTS_FILE,
    Checkpoint,
    CutScores,
)


class ClassifierLoadError(RuntimeError):
    """The model bundle is missing, altered, or its libraries are not installed."""


def sha256_file(path: Path, copy_to: Path | None = None) -> str:
    """The file's SHA-256; with `copy_to`, also writes the hashed bytes there."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        out = copy_to.open("xb") if copy_to is not None else None
        try:
            for block in iter(lambda: handle.read(1 << 22), b""):
                digest.update(block)
                if out is not None:
                    out.write(block)
        finally:
            if out is not None:
                out.close()
    return digest.hexdigest()


def verify_bundle(model_dir: Path, copy_to: Path | None = None) -> Checkpoint:
    """The checkpoint this bundle is, after checking every pinned file's
    hash. With `copy_to`, the pinned files, and nothing else, are copied
    there as they are hashed."""
    weights = model_dir / WEIGHTS_FILE
    if not weights.is_file():
        raise ClassifierLoadError(f"no {WEIGHTS_FILE} in {model_dir}")
    target = (lambda name: copy_to / name) if copy_to is not None else (lambda name: None)
    checkpoint = CHECKPOINTS.get(sha256_file(weights, target(WEIGHTS_FILE)))
    if checkpoint is None:
        raise ClassifierLoadError(
            f"{weights} is not a known checkpoint; thresholds exist only for known weights"
        )
    for name, expected in checkpoint.files.items():
        if name == WEIGHTS_FILE:
            continue
        path = model_dir / name
        if not path.is_file():
            raise ClassifierLoadError(f"{checkpoint.name}: {name} is missing from {model_dir}")
        if sha256_file(path, target(name)) != expected:
            raise ClassifierLoadError(f"{checkpoint.name}: {name} does not match its pinned hash")
    return checkpoint


def load_scorer(
    model_dir: Path, *, device: str, token_budget: int
) -> tuple[Checkpoint, TorchCornScorer]:
    """Verify the bundle and load it from a private copy of its pinned files."""
    _require_extra()
    # In place first, so a wrong bundle is refused before anything is copied.
    _check_temp_space(model_dir, verify_bundle(model_dir))
    with tempfile.TemporaryDirectory(prefix="mcp-proxy-classifier-") as private:
        try:
            checkpoint = verify_bundle(model_dir, copy_to=Path(private))
        except OSError as exc:
            raise ClassifierLoadError(
                f"could not copy the classifier bundle to {tempfile.gettempdir()} "
                f"({type(exc).__name__}); set TMPDIR to a disk-backed directory with space"
            ) from exc
        scorer = TorchCornScorer(
            Path(private), checkpoint, device=device, token_budget=token_budget
        )
    return checkpoint, scorer


def _check_temp_space(model_dir: Path, checkpoint: Checkpoint) -> None:
    """The private copy needs room for every pinned file."""
    needed = sum((model_dir / name).stat().st_size for name in checkpoint.files)
    free = shutil.disk_usage(tempfile.gettempdir()).free
    if free < needed:
        raise ClassifierLoadError(
            f"the classifier bundle needs {needed >> 20} MB in {tempfile.gettempdir()}, "
            f"which has {free >> 20} MB free; set TMPDIR to a disk-backed directory with space"
        )


def _require_extra() -> None:
    try:
        import safetensors  # noqa: F401
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except ImportError as exc:
        raise ClassifierLoadError(
            "scan.classifier needs the classifier extra: uv sync --extra classifier"
        ) from exc


class TorchCornScorer:
    """`score` is blocking CPU or GPU work; callers run it in a worker thread.
    Build it with `load_scorer`, which hands it a verified private copy."""

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
        config = AutoConfig.from_pretrained(
            str(model_dir), num_labels=checkpoint.num_labels, local_files_only=True
        )
        model = AutoModelForSequenceClassification.from_config(config, dtype=torch.float32)
        model.load_state_dict(load_file(str(model_dir / WEIGHTS_FILE)), strict=True)
        model.train(False)
        self._model: Any = model.to(device)
        self._tokenizer: Any = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
        self._pad = self._tokenizer.pad_token_id
        if self._pad is None:
            # Batches are padded; without a pad token every scoring call fails.
            raise ClassifierLoadError(f"{checkpoint.name}: the tokenizer has no pad token")

    def score(self, texts: Sequence[str]) -> list[CutScores | None]:
        """Cut scores `P(level > k)` for k = 0, 1, 2, in input order; None
        for a text longer than the window, which is never scored truncated."""
        # One token past the window is enough to tell that a text does not fit.
        encoded = [
            self._tokenizer(text, truncation=True, max_length=self._max_tokens + 1)["input_ids"]
            for text in texts
        ]
        fits = [i for i, ids in enumerate(encoded) if len(ids) <= self._max_tokens]
        out: dict[int, CutScores] = {}
        for batch in _batches([encoded[i] for i in fits], self._token_budget):
            indices = [fits[j] for j in batch]
            logits = self._logits([encoded[i] for i in indices])
            for row, index in zip(_corn_cuts(self._torch, logits), indices, strict=True):
                out[index] = row
        return [out.get(i) for i in range(len(texts))]

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
