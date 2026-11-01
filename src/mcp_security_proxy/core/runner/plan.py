"""Load enabled defenses, reject incompatible ones at startup, and order them.

Every check that can fail does so here, before the proxy serves anything: an
unknown defense, invalid settings, an incompatible SDK range, a capability
the core does not provide, or a required signal nothing produces. Within a
stage, producers of a signal run before its consumers; ties are broken by
defense id, so order never depends on registration or config order.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from mcp_security_proxy.core.runner.catalog import DefenseCatalog
from mcp_security_proxy.sdk import SDK_VERSION, Capability, Defense, Manifest, Stage


class DefenseLoadError(ValueError):
    """An enabled defense cannot be loaded or is incompatible with the core."""


@dataclass(frozen=True)
class DefenseSpec:
    """One enabled defense as configured: its catalog name and settings."""

    id: str
    settings: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LoadedDefense:
    manifest: Manifest
    defense: Defense


@dataclass(frozen=True)
class PlannedDefense:
    """A defense in one stage, with the producers it must run after."""

    loaded: LoadedDefense
    depends_on: frozenset[str]

    @property
    def manifest(self) -> Manifest:
        return self.loaded.manifest


class ExecutionPlan:
    def __init__(self, by_stage: Mapping[Stage, tuple[PlannedDefense, ...]]) -> None:
        self._by_stage = dict(by_stage)

    def for_stage(self, stage: Stage) -> tuple[PlannedDefense, ...]:
        return self._by_stage.get(stage, ())

    def defense_ids(self) -> list[str]:
        return sorted({d.manifest.id for stage in self._by_stage.values() for d in stage})


def build_plan(
    specs: Sequence[DefenseSpec],
    catalog: DefenseCatalog,
    available_capabilities: frozenset[Capability],
    sdk_version: str = SDK_VERSION,
) -> ExecutionPlan:
    loaded = [_load(spec, catalog) for spec in specs]
    for defense in loaded:
        _check_compatible(defense.manifest, available_capabilities, Version(sdk_version))
    return ExecutionPlan({stage: _order_stage(stage, loaded) for stage in Stage})


def _load(spec: DefenseSpec, catalog: DefenseCatalog) -> LoadedDefense:
    factory = catalog.factory(spec.id)
    if factory is None:
        raise DefenseLoadError(f"defense {spec.id!r} is enabled but not installed")
    try:
        defense = factory(spec.settings)
    except ValueError as exc:
        raise DefenseLoadError(f"defense {spec.id!r} rejected its settings: {exc}") from exc
    manifest = defense.manifest()
    if manifest.id != spec.id:
        raise DefenseLoadError(f"defense {spec.id!r} reports manifest id {manifest.id!r}")
    return LoadedDefense(manifest, defense)


def _check_compatible(
    manifest: Manifest, available: frozenset[Capability], sdk_version: Version
) -> None:
    try:
        supported = SpecifierSet(manifest.sdk_version_range)
    except InvalidSpecifier as exc:
        raise DefenseLoadError(f"defense {manifest.id!r}: invalid sdk_version_range") from exc
    if sdk_version not in supported:
        raise DefenseLoadError(
            f"defense {manifest.id!r} supports SDK {supported}, but the core provides {sdk_version}"
        )
    missing = manifest.required_capabilities - available
    if missing:
        raise DefenseLoadError(f"defense {manifest.id!r} requires unavailable {sorted(missing)}")


def _order_stage(stage: Stage, loaded: Iterable[LoadedDefense]) -> tuple[PlannedDefense, ...]:
    """Kahn's algorithm over signal dependencies, ties broken by id."""
    pending = {d.manifest.id: d for d in loaded if stage in d.manifest.stages}
    producers = _producers_by_signal(pending.values())
    depends_on = {
        defense_id: _producers_required_by(defense.manifest, producers, stage)
        for defense_id, defense in pending.items()
    }

    ordered: list[PlannedDefense] = []
    done: set[str] = set()
    while pending:
        ready = sorted(d for d in pending if depends_on[d] <= done)
        if not ready:
            raise DefenseLoadError(f"signal dependency cycle among {sorted(pending)} in {stage}")
        for defense_id in ready:
            ordered.append(PlannedDefense(pending.pop(defense_id), depends_on[defense_id]))
            done.add(defense_id)
    return tuple(ordered)


def _producers_by_signal(defenses: Iterable[LoadedDefense]) -> dict[str, set[str]]:
    producers: dict[str, set[str]] = {}
    for defense in defenses:
        for signal_type in defense.manifest.produced_signals:
            producers.setdefault(signal_type, set()).add(defense.manifest.id)
    return producers


def _producers_required_by(
    manifest: Manifest, producers: Mapping[str, set[str]], stage: Stage
) -> frozenset[str]:
    dependencies: set[str] = set()
    for signal_type in sorted(manifest.required_signals):
        producer_ids = producers.get(signal_type, set()) - {manifest.id}
        if not producer_ids:
            raise DefenseLoadError(
                f"defense {manifest.id!r} requires signal {signal_type!r}, "
                f"which no enabled defense produces in {stage}"
            )
        dependencies |= producer_ids
    return frozenset(dependencies)
