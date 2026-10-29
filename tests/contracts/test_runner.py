"""Runner planning and execution, using scripted in-test defenses."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import anyio
import pytest

from mcp_security_proxy.core.runner import (
    ContextFactory,
    DefenseLoadError,
    DefenseSpec,
    InspectionScope,
    Runner,
    StaticCatalog,
    build_plan,
)
from mcp_security_proxy.sdk import (
    Capability,
    Context,
    Defense,
    Event,
    HistorySnapshot,
    InspectionStatus,
    Result,
    Signal,
    Stage,
    VersionedValue,
)
from mcp_security_proxy.sdk.testing import (
    TEST_PRINCIPAL,
    FakePolicy,
    FakeRegistry,
    make_event,
)
from mcp_security_proxy.services.state import (
    DefenseStateStore,
    InMemoryStateStore,
    TaskRef,
    defense_owner,
)
from tests.harness.defenses import ScriptedDefense

ALL_CAPABILITIES = frozenset(Capability)
TASK = TaskRef(TEST_PRINCIPAL.id, "task")


def _catalog(*defenses: ScriptedDefense) -> StaticCatalog:
    def factory_for(defense: ScriptedDefense) -> Callable[[Mapping[str, Any]], Defense]:
        return lambda settings: defense

    return StaticCatalog({d.id: factory_for(d) for d in defenses})


def _plan(*defenses: ScriptedDefense, available: frozenset[Capability] = ALL_CAPABILITIES) -> Any:
    specs = [DefenseSpec(d.id) for d in defenses]
    return build_plan(specs, _catalog(*defenses), available)


def _runner(*defenses: ScriptedDefense, state: InMemoryStateStore | None = None) -> Runner:
    contexts = ContextFactory(DefenseStateStore(state or InMemoryStateStore()))
    return Runner(_plan(*defenses), contexts, deadline_seconds=0.2)


def _scope() -> InspectionScope:
    return InspectionScope(
        principal=TEST_PRINCIPAL,
        task=TASK,
        policy=FakePolicy(),
        registry=FakeRegistry(),
        history=HistorySnapshot(task_id=TASK.task_id, version=7),
    )


async def _inspect(runner: Runner, stage: Stage = Stage.BEFORE_EXECUTION) -> dict[str, Result]:
    reports = await runner.inspect(make_event(stage), _scope())
    return {report.defense_id: report.result for report in reports}


# --- planning ---------------------------------------------------------------


def test_enabled_but_uninstalled_defense_is_rejected() -> None:
    with pytest.raises(DefenseLoadError, match="not installed"):
        build_plan([DefenseSpec("missing")], StaticCatalog({}), ALL_CAPABILITIES)


def test_invalid_settings_are_rejected_at_startup() -> None:
    def factory(settings: Mapping[str, Any]) -> Defense:
        raise ValueError("max must be positive")

    with pytest.raises(DefenseLoadError, match="rejected its settings"):
        build_plan([DefenseSpec("strict")], StaticCatalog({"strict": factory}), ALL_CAPABILITIES)


def test_manifest_id_must_match_the_configured_name() -> None:
    impostor = ScriptedDefense("other")
    catalog = StaticCatalog({"expected": lambda settings: impostor})
    with pytest.raises(DefenseLoadError, match="manifest id"):
        build_plan([DefenseSpec("expected")], catalog, ALL_CAPABILITIES)


def test_incompatible_sdk_range_is_rejected() -> None:
    with pytest.raises(DefenseLoadError, match="supports SDK"):
        _plan(ScriptedDefense("future", sdk_range=">=2.0"))


def test_unavailable_capability_is_rejected() -> None:
    defense = ScriptedDefense("needs_history", capabilities=frozenset({Capability.HISTORY}))
    with pytest.raises(DefenseLoadError, match="unavailable"):
        _plan(defense, available=frozenset({Capability.REGISTRY}))


def test_required_signal_without_a_producer_is_rejected() -> None:
    with pytest.raises(DefenseLoadError, match="no enabled defense produces"):
        _plan(ScriptedDefense("consumer", requires=frozenset({"sensitivity"})))


def test_signal_dependency_cycles_are_rejected() -> None:
    a = ScriptedDefense("a", requires=frozenset({"y"}), produces=frozenset({"x"}))
    b = ScriptedDefense("b", requires=frozenset({"x"}), produces=frozenset({"y"}))
    with pytest.raises(DefenseLoadError, match="cycle"):
        _plan(a, b)


def test_producers_run_before_consumers_regardless_of_config_order() -> None:
    consumer = ScriptedDefense("a_consumer", requires=frozenset({"sensitivity"}))
    producer = ScriptedDefense("z_producer", produces=frozenset({"sensitivity"}))
    plan = _plan(consumer, producer)

    order = [p.manifest.id for p in plan.for_stage(Stage.BEFORE_EXECUTION)]
    assert order == ["z_producer", "a_consumer"]


# --- execution --------------------------------------------------------------


async def test_only_defenses_for_the_event_stage_run() -> None:
    discovery = ScriptedDefense("discovery_only", stages=frozenset({Stage.DISCOVERY}))
    runner = _runner(discovery, ScriptedDefense("execution_only"))

    assert list(await _inspect(runner)) == ["execution_only"]
    assert not runner.applies_to(Stage.BEFORE_DELIVERY)


async def test_failures_are_reported_distinctly_from_clean_inspections() -> None:
    async def raises(event: Event, context: Context) -> Result:
        raise RuntimeError("secret-bearing message")

    async def hangs(event: Event, context: Context) -> Result:
        await anyio.sleep(5)
        return Result.completed()

    async def malformed(event: Event, context: Context) -> Any:
        return {"status": "completed"}

    async def unsupported(event: Event, context: Context) -> Result:
        return Result.unsupported("image content")

    runner = _runner(
        ScriptedDefense("clean"),
        ScriptedDefense("raises", raises),
        ScriptedDefense("hangs", hangs),
        ScriptedDefense("malformed", malformed),
        ScriptedDefense("unsupported", unsupported),
    )
    results = await _inspect(runner)

    assert results["clean"].status is InspectionStatus.COMPLETED
    assert results["raises"].status is InspectionStatus.FAILED
    assert results["raises"].detail == "raised RuntimeError"
    assert results["hangs"].detail == "deadline exceeded"
    assert results["malformed"].status is InspectionStatus.FAILED
    assert results["unsupported"].status is InspectionStatus.UNSUPPORTED


async def test_using_an_undeclared_capability_fails_the_inspection() -> None:
    async def peeks(event: Event, context: Context) -> Result:
        _ = context.history
        return Result.completed()

    results = await _inspect(_runner(ScriptedDefense("peeks", peeks)))
    assert results["peeks"].detail == "raised CapabilityNotGrantedError"


async def test_signals_reach_consumers_and_failed_producers_fail_them() -> None:
    async def produce(event: Event, context: Context) -> Result:
        return Result.completed(signals=[Signal("sensitivity", 1, "producer", "high")])

    async def consume(event: Event, context: Context) -> Result:
        assert [s.value for s in context.signals_of("sensitivity")] == ["high"]
        return Result.completed()

    async def broken(event: Event, context: Context) -> Result:
        raise RuntimeError

    producer = ScriptedDefense("producer", produce, produces=frozenset({"sensitivity"}))
    consumer = ScriptedDefense("consumer", consume, requires=frozenset({"sensitivity"}))
    assert (await _inspect(_runner(producer, consumer)))["consumer"].status is (
        InspectionStatus.COMPLETED
    )

    failing = ScriptedDefense("producer", broken, produces=frozenset({"sensitivity"}))
    results = await _inspect(_runner(failing, consumer))
    assert results["consumer"].status is InspectionStatus.FAILED
    assert "producer" in (results["consumer"].detail or "")


async def test_signals_with_a_false_producer_or_undeclared_type_fail() -> None:
    async def spoofs(event: Event, context: Context) -> Result:
        return Result.completed(signals=[Signal("sensitivity", 1, "someone_else", "x")])

    async def undeclared(event: Event, context: Context) -> Result:
        return Result.completed(signals=[Signal("other", 1, "undeclared", "x")])

    results = await _inspect(
        _runner(
            ScriptedDefense("spoofs", spoofs, produces=frozenset({"sensitivity"})),
            ScriptedDefense("undeclared", undeclared),
        )
    )
    assert results["spoofs"].status is InspectionStatus.FAILED
    assert results["undeclared"].status is InspectionStatus.FAILED


async def test_context_carries_trusted_scope_and_own_private_state() -> None:
    state = InMemoryStateStore()
    await state.compare_and_set(TASK.scope(defense_owner("stateful")), "seen", 0, ["x"])
    await state.compare_and_set(TASK.scope(defense_owner("other")), "seen", 0, ["leak"])
    defense = ScriptedDefense(
        "stateful", capabilities=frozenset({Capability.PRIVATE_STATE, Capability.HISTORY})
    )

    await _inspect(_runner(defense, state=state))

    [context] = defense.seen_contexts
    assert context.principal == TEST_PRINCIPAL and context.task_id == "task"
    assert context.state_version == 7
    assert context.private_state.get("seen") == VersionedValue(1, ["x"])
    assert context.history.version == 7
