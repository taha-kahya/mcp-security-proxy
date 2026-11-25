"""Scan's classifier stage (ADR 0026), without the model.

The serialization is pinned by golden strings produced by the serializer
the checkpoint was trained with: any change to it invalidates the
checkpoint's thresholds. The stage is driven by a fake scorer;
`test_scan_classifier_model.py` scores the real checkpoint when its bundle
is installed.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.shared.exceptions import MCPError

from mcp_security_proxy.app.config import ProxyConfig
from mcp_security_proxy.app.security import load_security
from mcp_security_proxy.core.runner import DefenseLoadError, StaticCatalog
from mcp_security_proxy.defenses.direct.definition_classifier import CRITICAL_RULE
from mcp_security_proxy.defenses.direct.definition_classifier import (
    create as create_classifier_defense,
)
from mcp_security_proxy.sdk import (
    Capability,
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
    torch_scorer,
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


TOO_LONG = None
NAN = (float("nan"), 0.0, 0.0)


class FakeScorer:
    """Scores by tool name; records every batch it is asked to score. A
    batch containing a name in `crash` raises; with `hold`, scoring blocks
    until the event is set."""

    def __init__(
        self,
        scores: dict[str, tuple[float, float, float] | None],
        fail: bool = False,
        crash: frozenset[str] = frozenset(),
        hold: threading.Event | None = None,
        delay: float = 0.0,
    ):
        self.scores = scores
        self.fail = fail
        self.crash = crash
        self.hold = hold
        self.delay = delay
        self.batches: list[list[str]] = []

    def score(self, texts: Sequence[str]) -> list[tuple[float, float, float] | None]:
        self.batches.append(list(texts))
        if self.hold is not None:
            self.hold.wait()
        time.sleep(self.delay)
        names = [text.splitlines()[0].removeprefix("tool: ") for text in texts]
        if self.fail or self.crash & set(names):
            raise RuntimeError("model failed")
        return [self.scores[name] for name in names]


def _classifier(
    scorer: FakeScorer, *, cache_entries: int = 16, timeout: float = 120.0
) -> DefinitionClassifier:
    checkpoint = DEFINITION_V1
    fake = type(checkpoint)(
        name="fake",
        serialization=checkpoint.serialization,
        max_tokens=checkpoint.max_tokens,
        num_labels=3,
        files=checkpoint.files,
        operating_points={OperatingPoint.HIGH_RECALL: T},
    )
    return DefinitionClassifier(
        scorer, fake, OperatingPoint.HIGH_RECALL, cache_entries=cache_entries, timeout=timeout
    )


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


async def test_a_definition_longer_than_the_window_is_never_clean() -> None:
    scorer = FakeScorer({"long": TOO_LONG})
    classifier = _classifier(scorer)

    await classifier.prepare([{"name": "long"}])
    await classifier.prepare([{"name": "long"}])

    with pytest.raises(ScanError, match="longer than"):
        classifier.result({"name": "long"})
    assert len(scorer.batches) == 1  # the outcome is cached, not rescored


@pytest.mark.parametrize(
    "bad",
    [NAN, (0.5, float("inf"), 0.0), (1.5, 0.0, 0.0), (-0.1, 0.0, 0.0)],
    ids=["nan", "inf", "above-one", "negative"],
)
async def test_scores_that_are_not_probabilities_fail_the_scan(
    bad: tuple[float, float, float],
) -> None:
    classifier = _classifier(FakeScorer({"a": bad, "b": CLEAN}))
    await classifier.prepare([{"name": "a"}, {"name": "b"}])
    with pytest.raises(ScanError):
        classifier.result({"name": "a"})
    assert classifier.result({"name": "b"}).matches == ()  # contained to "a"


async def test_one_failing_definition_does_not_unscore_the_listing() -> None:
    scorer = FakeScorer({"a": CLEAN, "b": HIGH, "c": CLEAN}, crash=frozenset({"b"}))
    classifier = _classifier(scorer)

    await classifier.prepare([{"name": "a"}, {"name": "b"}, {"name": "c"}])

    assert classifier.result({"name": "a"}).matches == ()
    assert classifier.result({"name": "c"}).matches == ()
    with pytest.raises(ScanError):
        classifier.result({"name": "b"})
    assert scorer.batches[1:] == [["tool: a"], ["tool: b"], ["tool: c"]]


async def test_a_listing_larger_than_the_cache_keeps_its_grades_while_prepared() -> None:
    classifier = _classifier(FakeScorer({"a": CLEAN, "b": HIGH, "c": CRITICAL}), cache_entries=2)
    listing = [{"name": "a"}, {"name": "b"}, {"name": "c"}]

    async with classifier.prepared(listing):
        labels = [m.label for d in listing for m in classifier.result(d).matches]

    assert labels == ["high", "critical"]
    assert len(classifier._cache) == 2  # the cache did not grow
    assert classifier._held == {}


async def test_another_listing_cannot_evict_grades_being_read() -> None:
    """Two principals listing at once share one bounded cache."""
    scorer = FakeScorer({"a": HIGH, "b": CLEAN, "c": CLEAN})
    classifier = _classifier(scorer, cache_entries=1)

    async with classifier.prepared([{"name": "a"}]):
        async with classifier.prepared([{"name": "b"}, {"name": "c"}]):
            pass  # evicts "a" from the cache
        [match] = classifier.result({"name": "a"}).matches

    assert match.label == "high"
    with pytest.raises(ScanError):  # released, and no longer cached
        classifier.result({"name": "a"})


async def test_retries_after_a_failed_batch_share_one_timeout() -> None:
    """A model that fails slowly holds the stage for about two timeouts,
    not one per definition."""
    names = [f"t{i}" for i in range(20)]
    scorer = FakeScorer(dict.fromkeys(names, CLEAN), fail=True, delay=0.05)
    classifier = _classifier(scorer, timeout=0.2)

    await classifier.prepare([{"name": n} for n in names])

    assert 2 <= len(scorer.batches) < 1 + len(names)
    for _ in range(200):  # until the abandoned retry returns
        if not classifier._busy.is_set():
            break
        await anyio.sleep(0.01)


async def test_a_hung_scorer_times_out_and_fails_closed_until_it_returns() -> None:
    hold = threading.Event()
    scorer = FakeScorer({"a": CLEAN, "b": CLEAN}, hold=hold)
    classifier = _classifier(scorer, timeout=0.05)

    await classifier.prepare([{"name": "a"}])  # times out; does not hang
    await classifier.prepare([{"name": "b"}])  # not queued behind the stuck call
    for name in ("a", "b"):
        with pytest.raises(ScanError):
            classifier.result({"name": name})
    assert scorer.batches == [["tool: a"]]

    hold.set()
    for _ in range(200):  # until the abandoned call returns
        if not classifier._busy.is_set():
            break
        await anyio.sleep(0.01)
    await classifier.prepare([{"name": "b"}])
    assert classifier.result({"name": "b"}).matches == ()


def _startup_config(tmp_path: Path, *, defense: bool, classifier: bool) -> ProxyConfig:
    defenses = tmp_path / "defenses"
    defenses.mkdir()
    (defenses / "c.yaml").write_text(f"id: direct_definition_classifier\nenabled: {defense}\n")
    policy = tmp_path / "policy.yaml"
    policy.write_text("schema_version: 1\nprincipals: {}\n")
    return ProxyConfig.model_validate(
        {
            "identity": {"stdio_principal": "agent"},
            "policy_path": str(policy),
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "servers": [],
            "defenses_path": str(defenses),
            "scan": {"classifier": {"model_dir": str(tmp_path)}} if classifier else {},
        }
    )


CLASSIFIER_CATALOG = StaticCatalog({"direct_definition_classifier": create_classifier_defense})


def test_the_defense_without_a_classifier_stops_startup(tmp_path: Path) -> None:
    """Otherwise every tool would be hidden, which an evaluation arm could
    misread as the defense blocking everything."""
    with pytest.raises(DefenseLoadError, match="scan_classifier"):
        load_security(_startup_config(tmp_path, defense=True, classifier=False), CLASSIFIER_CATALOG)


def test_a_classifier_no_defense_needs_is_not_loaded(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # An empty model_dir: loading it would raise ClassifierLoadError.
    config = _startup_config(tmp_path, defense=False, classifier=True)
    setup = load_security(config, CLASSIFIER_CATALOG)
    assert "the model is not loaded" in caplog.text
    with pytest.raises(ScanError, match="no classifier stage"):
        anyio.run(setup.scan.poisoning, {"name": "a"})


def test_the_classifier_capability_is_needed_only_by_the_classifier_defense() -> None:
    manifest = create_classifier_defense({}).manifest()
    assert Capability.SCAN_CLASSIFIER in manifest.required_capabilities


async def test_scan_without_a_classifier_refuses_poisoning() -> None:
    scan = Scan(RuleScanner())
    async with scan.prepared([{"name": "a"}]):  # a no-op
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


def test_only_the_pinned_files_are_copied_for_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, private = tmp_path / "bundle", tmp_path / "private"
    bundle.mkdir()
    private.mkdir()
    files = {WEIGHTS_FILE: b"weights", "tokenizer.json": b"{}"}
    for name, data in files.items():
        (bundle / name).write_bytes(data)
    (bundle / "vocab.txt").write_text("not pinned")  # a file a tokenizer might read
    pinned = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    fake = type(DEFINITION_V1)(
        name="fake",
        serialization="ser-1",
        max_tokens=8,
        num_labels=3,
        files=pinned,
        operating_points={},
    )
    monkeypatch.setattr(torch_scorer, "CHECKPOINTS", {pinned[WEIGHTS_FILE]: fake})

    assert verify_bundle(bundle, copy_to=private) is fake
    assert {p.name: p.read_bytes() for p in private.iterdir()} == files

    (bundle / "tokenizer.json").write_bytes(b"{ }")
    (tmp_path / "again").mkdir()
    with pytest.raises(ClassifierLoadError, match="does not match"):
        verify_bundle(bundle, copy_to=tmp_path / "again")


def _fake_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / WEIGHTS_FILE).write_bytes(b"weights")
    fake = type(DEFINITION_V1)(
        name="fake",
        serialization="ser-1",
        max_tokens=8,
        num_labels=3,
        files={WEIGHTS_FILE: hashlib.sha256(b"weights").hexdigest()},
        operating_points={},
    )
    monkeypatch.setattr(torch_scorer, "CHECKPOINTS", {fake.files[WEIGHTS_FILE]: fake})
    monkeypatch.setattr(torch_scorer, "_require_extra", lambda: None)
    return bundle


def test_a_wrong_bundle_is_refused_before_anything_is_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _fake_bundle(tmp_path, monkeypatch)
    (bundle / WEIGHTS_FILE).write_bytes(b"other weights")

    def no_copy(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("copied before the bundle was checked")

    monkeypatch.setattr(torch_scorer.tempfile, "TemporaryDirectory", no_copy)
    with pytest.raises(ClassifierLoadError, match="not a known checkpoint"):
        torch_scorer.load_scorer(bundle, device="cpu", token_budget=8)


def test_too_little_temporary_space_is_a_load_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = _fake_bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(torch_scorer.shutil, "disk_usage", lambda _: type("U", (), {"free": 0}))
    with pytest.raises(ClassifierLoadError, match="TMPDIR"):
        torch_scorer.load_scorer(bundle, device="cpu", token_budget=8)


def test_a_failed_copy_is_a_load_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _fake_bundle(tmp_path, monkeypatch)
    real = torch_scorer.sha256_file

    def full_disk(path: Path, copy_to: Path | None = None) -> str:
        if copy_to is not None:
            raise OSError(28, "No space left on device")
        return real(path)

    monkeypatch.setattr(torch_scorer, "sha256_file", full_disk)
    with pytest.raises(ClassifierLoadError, match="could not copy"):
        torch_scorer.load_scorer(bundle, device="cpu", token_budget=8)


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


async def test_a_tool_the_classifier_cannot_score_hides_only_that_tool() -> None:
    scores = {"read": CLEAN, "write": TOO_LONG, "exec": CLEAN}
    scorer = FakeScorer(scores, crash=frozenset({"exec"}))
    proxy = _proxy(scorer, MemorySink())

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


async def test_a_listing_scores_a_failing_tool_once_more_not_twice() -> None:
    """After a failed batch each tool is retried alone, and inspection does
    not score it yet again."""
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL}, fail=True)
    proxy = _proxy(scorer, MemorySink())

    assert await proxy.orchestrator.list_tools(ALICE) == []
    assert len(scorer.batches) == 1 + 3


class RecordingScan(Scan):
    def __init__(self, classifier: DefinitionClassifier) -> None:
        super().__init__(RuleScanner(), classifier)
        self.prepared_names: list[list[str]] = []

    def prepared(self, definitions: Any) -> Any:
        definitions = list(definitions)
        self.prepared_names.append([d["name"] for d in definitions])
        return super().prepared(definitions)


async def test_tools_already_inspected_are_not_prescanned_again() -> None:
    scorer = FakeScorer({"read": CLEAN, "write": HIGH, "exec": CRITICAL})
    scan = RecordingScan(_classifier(scorer))
    proxy = build_proxy(
        routing=routing_for({"server_a": ["read", "write", "exec"]}),
        upstreams={"server_a": FakeUpstream()},
        policy=POLICY,
        audit=MemorySink(),
        defenses=[create_classifier_defense({})],
        scan=scan,
    )

    await proxy.orchestrator.list_tools(ALICE)
    await proxy.orchestrator.list_tools(ALICE)

    assert scan.prepared_names == [["read", "write", "exec"], []]
