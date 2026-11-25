"""Scan's classifier stage (ADR 0026), without the model.

The serialization is pinned by golden strings produced by the serializer
the checkpoint was trained with: any change to it invalidates the
checkpoint's thresholds. The stage is driven by a fake scorer;
`test_scan_classifier_model.py` scores the real checkpoint when its bundle
is installed.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.defenses.direct.definition_classifier import CRITICAL_RULE
from mcp_security_proxy.defenses.direct.definition_classifier import (
    create as create_classifier_defense,
)
from mcp_security_proxy.sdk import (
    Detector,
    MatchKind,
    Principal,
    ScanError,
    ScanStage,
    freeze,
)
from mcp_security_proxy.services.log import DecisionRecord, DiscoveryRecord
from mcp_security_proxy.services.scan import RuleScanner, Scan
from mcp_security_proxy.services.scan.classifier import (
    CHECKPOINTS,
    ClassifierLoadError,
    DefinitionClassifier,
    OperatingPoint,
    Thresholds,
    grade,
    serialize_tool,
    verify_bundle,
)
from mcp_security_proxy.services.scan.classifier.checkpoints import DEFINITION_V1, WEIGHTS_FILE
from tests.harness.control import build_proxy, routing_for
from tests.harness.fakes import FakeUpstream, MemorySink

# --- serialization ----------------------------------------------------------

GOLDEN: list[tuple[str, dict[str, Any], str]] = [
    ("minimal", {"name": "ping"}, "tool: ping"),
    (
        "titles",
        {
            "name": "search",
            "title": "Search",
            "annotations": {"title": "Web search", "readOnlyHint": True},
            "description": "Search the web.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        "tool: search\ntitle: Search\nannotation title: Web search\ndescription: Search the web.",
    ),
    (
        "params",
        {
            "name": "convert",
            "description": "Convert units.",
            "inputSchema": {
                "type": "object",
                "required": ["value", "unit"],
                "properties": {
                    "value": {"type": "number", "description": "Amount."},
                    "unit": {"type": "string", "enum": ["m", "ft", 3, None], "title": "Unit"},
                    "precision": {"type": ["integer", "null"], "default": 2},
                    "mode": {"const": "fast"},
                },
            },
        },
        "tool: convert\ndescription: Convert units.\nparameters:\n"
        "- value (number; required): Amount.\n"
        "- unit (string; required; title: Unit; enum: m | ft | 3 | null):\n"
        "- precision (integer|null; default: 2):\n"
        "- mode (any; const: fast):",
    ),
    (
        "nested",
        {
            "name": "create_event",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "event": {
                        "type": "object",
                        "required": ["start"],
                        "properties": {
                            "start": {"type": "string", "description": "ISO time."},
                            "tags": {
                                "type": "array",
                                "items": {"type": "string", "description": "Tag."},
                            },
                        },
                    },
                    "target": {
                        "anyOf": [
                            {"type": "string"},
                            {"type": "object", "properties": {"id": {"type": "integer"}}},
                        ]
                    },
                    "pair": {"type": "array", "items": [{"type": "string"}, {"type": "number"}]},
                },
                "oneOf": [{"type": "object", "properties": {"extra": {"type": "boolean"}}}],
            },
            "outputSchema": {"type": "object"},
            "_meta": {"x": 1},
        },
        "tool: create_event\nparameters:\n- event (object):\n"
        "- event.start (string; required): ISO time.\n- event.tags (array):\n"
        "- event.tags[] (string): Tag.\n- target (anyOf):\n- target (string):\n"
        "- target (object):\n- target.id (integer):\n- pair (array):\n"
        "- pair[] (string):\n- pair[] (number):\n- extra (boolean):",
    ),
    (
        "non_strings",
        {
            "name": "odd",
            "title": 5,
            "description": None,
            "inputSchema": {"properties": {"a": {"description": 7, "default": {"k": "ü"}}}},
        },
        'tool: odd\nparameters:\n- a (any; default: {"k": "ü"}):',
    ),
]


@pytest.mark.parametrize(
    ("definition", "expected"), [pytest.param(d, e, id=n) for n, d, e in GOLDEN]
)
def test_serialization_matches_the_training_serialization(
    definition: dict[str, Any], expected: str
) -> None:
    assert serialize_tool(definition) == expected


@pytest.mark.parametrize(
    ("definition", "expected"), [pytest.param(d, e, id=n) for n, d, e in GOLDEN]
)
def test_frozen_definitions_serialize_like_plain_ones(
    definition: dict[str, Any], expected: str
) -> None:
    """The proxy's definitions are read-only mappings and tuples; `required`,
    `enum` and tuple `items` must still be read as lists."""
    assert serialize_tool(freeze(definition)) == expected


# --- grading ----------------------------------------------------------------

T = Thresholds(gate=0.5, high=0.2, critical=0.1)


@pytest.mark.parametrize(
    ("scores", "level"),
    [
        ((0.5, 0.9, 0.9), None),  # at the gate is clean
        ((0.49, 1.0, 1.0), None),
        ((0.51, 0.0, 0.0), "medium"),
        ((0.51, 0.2, 0.0), "high"),  # thresholds are inclusive
        ((0.51, 0.0, 0.1), "critical"),  # critical is checked first
        ((0.51, 0.19, 0.09), "medium"),
    ],
)
def test_grading_is_gated(scores: tuple[float, float, float], level: str | None) -> None:
    assert grade(scores, T) == level


def test_the_default_operating_point_grades_more_tools_high_than_balanced() -> None:
    points = DEFINITION_V1.operating_points
    assert points[OperatingPoint.HIGH_RECALL].gate == points[OperatingPoint.BALANCED].gate
    assert points[OperatingPoint.HIGH_RECALL].high < points[OperatingPoint.BALANCED].high
    assert points[OperatingPoint.HIGH_RECALL].critical < points[OperatingPoint.BALANCED].critical


# --- the stage, with a fake scorer ------------------------------------------

CLEAN = (0.0, 0.0, 0.0)
HIGH = (0.9, 0.5, 0.0)
CRITICAL = (0.9, 0.9, 0.9)


class FakeScorer:
    """Scores by tool name; records every batch it is asked to score."""

    def __init__(self, scores: dict[str, tuple[float, float, float]], fail: bool = False):
        self.scores = scores
        self.fail = fail
        self.batches: list[list[str]] = []

    def score(self, texts: Sequence[str]) -> list[tuple[float, float, float]]:
        self.batches.append(list(texts))
        if self.fail:
            raise RuntimeError("model failed")
        return [self.scores[text.splitlines()[0].removeprefix("tool: ")] for text in texts]


def _classifier(scorer: FakeScorer) -> DefinitionClassifier:
    checkpoint = DEFINITION_V1
    fake = type(checkpoint)(
        name="fake",
        serialization=checkpoint.serialization,
        max_tokens=checkpoint.max_tokens,
        num_labels=3,
        files=checkpoint.files,
        operating_points={OperatingPoint.HIGH_RECALL: T},
    )
    return DefinitionClassifier(scorer, fake, OperatingPoint.HIGH_RECALL, cache_entries=16)


async def test_results_come_from_one_batch_and_are_cached() -> None:
    scorer = FakeScorer({"a": CLEAN, "b": HIGH})
    classifier = _classifier(scorer)
    a, b = freeze({"name": "a"}), freeze({"name": "b"})

    await classifier.prepare([a, b, a])
    await classifier.prepare([a, b])

    assert scorer.batches == [["tool: a", "tool: b"]]  # deduplicated, then cached
    assert classifier.result(a).matches == ()
    [match] = classifier.result(b).matches
    assert (match.detector, match.kind, match.stage, match.label) == (
        Detector.POISONING,
        MatchKind.POISONED_DEFINITION,
        ScanStage.CLASSIFIER,
        "high",
    )
    assert classifier.result(b).version == "classifier-fake+ser-1+high_recall"


async def test_an_unscored_definition_is_never_clean() -> None:
    classifier = _classifier(FakeScorer({}))
    with pytest.raises(ScanError):
        classifier.result({"name": "never-prepared"})


async def test_a_scorer_failure_leaves_definitions_unscored_and_is_retried() -> None:
    scorer = FakeScorer({"a": CLEAN}, fail=True)
    classifier = _classifier(scorer)

    await classifier.prepare([{"name": "a"}])  # does not raise
    with pytest.raises(ScanError):
        classifier.result({"name": "a"})

    scorer.fail = False
    await classifier.prepare([{"name": "a"}])
    assert classifier.result({"name": "a"}).matches == ()
    assert len(scorer.batches) == 2


async def test_scan_without_a_classifier_refuses_poisoning() -> None:
    scan = Scan(RuleScanner())
    await scan.prepare([{"name": "a"}])  # a no-op
    with pytest.raises(ScanError):
        await scan.poisoning({"name": "a"})


# --- the bundle -------------------------------------------------------------


def test_a_bundle_without_weights_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ClassifierLoadError):
        verify_bundle(tmp_path)


def test_unknown_weights_are_refused(tmp_path: Path) -> None:
    (tmp_path / WEIGHTS_FILE).write_bytes(b"not the checkpoint")
    with pytest.raises(ClassifierLoadError, match="not a known checkpoint"):
        verify_bundle(tmp_path)


def test_every_known_checkpoint_pins_its_tokenizer_and_config() -> None:
    for weights, checkpoint in CHECKPOINTS.items():
        assert checkpoint.weights_sha256 == weights
        assert {"config.json", "tokenizer.json", "tokenizer_config.json"} <= set(checkpoint.files)
        assert set(checkpoint.operating_points) == set(OperatingPoint)


def test_the_proxy_imports_without_torch() -> None:
    """The classifier extra is optional: nothing imports torch until a
    classifier is configured."""
    code = (
        "import sys\n"
        "import mcp_security_proxy.app.main, mcp_security_proxy.app.security\n"
        "import mcp_security_proxy.services.scan.classifier\n"
        "import mcp_security_proxy.defenses.direct.definition_classifier\n"
        "assert not {'torch', 'transformers', 'safetensors'} & set(sys.modules), 'imported'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


# --- in the proxy -----------------------------------------------------------

POLICY: dict[str, Any] = {
    "schema_version": 1,
    "principals": {"alice": [{"tool": "server_a/*", "effect": "allow"}]},
}
ALICE = Principal(id="alice", authenticated_by="test")


def _proxy(scorer: FakeScorer, sink: MemorySink, upstream: FakeUpstream | None = None) -> Any:
    return build_proxy(
        routing=routing_for({"server_a": ["read", "write", "exec"]}),
        upstreams={"server_a": upstream or FakeUpstream()},
        policy=POLICY,
        audit=sink,
        defenses=[create_classifier_defense({})],
        scan=Scan(RuleScanner(), _classifier(scorer)),
    )


async def test_a_listing_is_scored_in_one_batch_before_inspection() -> None:
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL})
    sink = MemorySink()
    proxy = _proxy(scorer, sink)

    tools = await proxy.orchestrator.list_tools(ALICE)

    assert [t.name for t in tools] == ["server_a__read"]
    assert len(scorer.batches) == 1 and len(scorer.batches[0]) == 3
    [listing] = sink.of_kind(DiscoveryRecord)
    assert set(listing.hidden_by_inspection) == {"server_a/write", "server_a/exec"}


async def test_a_call_without_a_prior_listing_is_scored_then_decided() -> None:
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL})
    sink, upstream = MemorySink(), FakeUpstream()
    proxy = _proxy(scorer, sink, upstream)

    allowed = await proxy.orchestrator.call_tool(ALICE, "server_a__read", {})

    assert not allowed.is_error and len(upstream.calls) == 1
    assert scorer.batches == [["tool: read"]]


async def test_a_listing_the_classifier_cannot_score_hides_every_tool() -> None:
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL}, fail=True)
    proxy = _proxy(scorer, MemorySink())

    assert await proxy.orchestrator.list_tools(ALICE) == []
    scorer.fail = False
    assert [t.name for t in await proxy.orchestrator.list_tools(ALICE)] == ["server_a__read"]


async def test_a_critical_tool_called_without_a_listing_is_refused() -> None:
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL})
    sink, upstream = MemorySink(), FakeUpstream()
    proxy = _proxy(scorer, sink, upstream)

    with pytest.raises(MCPError):
        await proxy.orchestrator.call_tool(ALICE, "server_a__exec", {})

    assert upstream.calls == []
    [decision] = sink.of_kind(DecisionRecord)
    assert decision.rule_refs == (f"defense:direct_definition_classifier:{CRITICAL_RULE}",)
