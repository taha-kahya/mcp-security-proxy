"""Known classifier checkpoints and their frozen operating points (ADR 0026).

Thresholds hold only for the exact weights, tokenizer and serialization
they were fitted with, so each checkpoint is identified by the SHA-256 of
every file in its bundle. A bundle that matches no entry is refused at
startup rather than scored with thresholds that do not apply to it.

The grading rule is gated:

- `s0 = P(level > LOW)`, `s1 = P(level > MEDIUM)`, `s2 = P(level > HIGH)`;
- clean when `s0 <= gate`;
- otherwise `critical` when `s2 >= critical`, else `high` when
  `s1 >= high`, else `medium`.

The thresholds were fitted for this checkpoint and do not transfer to
another one. The two operating points share the gate and differ in the
high and critical cuts: `high_recall` (the default) favours grading
poisoned tools high or critical, at the cost of grading more medium tools
high; `balanced` grades fewer tools high.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

# Cut scores `P(level > k)` for k = 0, 1, 2.
CutScores = tuple[float, float, float]


class OperatingPoint(StrEnum):
    HIGH_RECALL = "high_recall"
    BALANCED = "balanced"


@dataclass(frozen=True)
class Thresholds:
    gate: float
    high: float
    critical: float


@dataclass(frozen=True)
class Checkpoint:
    name: str
    serialization: str
    max_tokens: int
    num_labels: int
    files: Mapping[str, str]  # bundle file name -> SHA-256
    operating_points: Mapping[OperatingPoint, Thresholds]

    @property
    def weights_sha256(self) -> str:
        return self.files[WEIGHTS_FILE]


WEIGHTS_FILE = "model.safetensors"

_GATE = 0.6981630639616991

DEFINITION_V1 = Checkpoint(
    name="definition-v1",
    serialization="ser-1",
    max_tokens=8192,
    num_labels=3,
    files={
        WEIGHTS_FILE: "c22a8e0a19ed8efc242cd2edfa658c3efc4ae9f4bf0cf341bdba028f06326a68",
        "config.json": "1609d59e627c33eaed524b4f01e546d42e84190a079a5a5ded84b212c41c324f",
        "tokenizer.json": "9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1",
        "tokenizer_config.json": "3cd2017ff46d0a527e5d39cae39272eccfa1f19bb9f89b05d166aab2e38354e2",
        "special_tokens_map.json": (
            "ea97ecdbcc73713039d8d64dbb05e3689495c96657fbd9a18f5bed381be81049"
        ),
    },
    operating_points={
        OperatingPoint.HIGH_RECALL: Thresholds(
            gate=_GATE, high=1.6073254617555488e-05, critical=1.3496491814395476e-05
        ),
        OperatingPoint.BALANCED: Thresholds(
            gate=_GATE, high=0.027631395926539886, critical=0.007745582431606162
        ),
    },
)

CHECKPOINTS: Mapping[str, Checkpoint] = {DEFINITION_V1.weights_sha256: DEFINITION_V1}


def grade(scores: CutScores, thresholds: Thresholds) -> str | None:
    """The level for cut scores `(s0, s1, s2)`, or None when clean."""
    s0, s1, s2 = scores
    if s0 <= thresholds.gate:
        return None
    if s2 >= thresholds.critical:
        return "critical"
    if s1 >= thresholds.high:
        return "high"
    return "medium"
