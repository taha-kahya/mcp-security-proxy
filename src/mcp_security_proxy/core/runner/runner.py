"""Run the planned defenses for one event and collect an explicit report each.

The Runner neither decides nor forwards: it returns one `InspectionReport`
per defense that applies to the event's stage, and Guard decides. A defense
that raises, overruns its deadline, returns something malformed, or depends
on a signal producer that did not complete is reported as `failed`, never
silently dropped. Cancellation of the request itself still propagates.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import anyio

from mcp_security_proxy.core.runner.context import ContextFactory, InspectionScope
from mcp_security_proxy.core.runner.plan import ExecutionPlan, PlannedDefense
from mcp_security_proxy.sdk import (
    Context,
    Event,
    InspectionStatus,
    Manifest,
    Result,
    Signal,
    Stage,
)

logger = logging.getLogger(__name__)

DEFAULT_DEADLINE_SECONDS = 2.0
_INCOMPLETE = frozenset({InspectionStatus.FAILED, InspectionStatus.UNSUPPORTED})


@dataclass(frozen=True)
class InspectionReport:
    defense_id: str
    defense_version: str
    result: Result

    @property
    def status(self) -> InspectionStatus:
        return self.result.status


class Runner:
    def __init__(
        self,
        plan: ExecutionPlan,
        contexts: ContextFactory,
        deadline_seconds: float = DEFAULT_DEADLINE_SECONDS,
    ) -> None:
        self._plan = plan
        self._contexts = contexts
        self._deadline = deadline_seconds

    def applies_to(self, stage: Stage) -> bool:
        return bool(self._plan.for_stage(stage))

    async def inspect(self, event: Event, scope: InspectionScope) -> tuple[InspectionReport, ...]:
        reports: list[InspectionReport] = []
        signals: list[Signal] = []
        incomplete: set[str] = set()

        for planned in self._plan.for_stage(event.stage):
            manifest = planned.manifest
            unmet = sorted(planned.depends_on & incomplete)
            if unmet:
                result = Result.failed(f"required signal producers did not complete: {unmet}")
            else:
                context = await self._contexts.build(manifest, scope, signals)
                result = validated(manifest, await self._evaluate(planned, event, context))

            if result.status in _INCOMPLETE:
                incomplete.add(manifest.id)
            signals.extend(result.signals)
            reports.append(InspectionReport(manifest.id, manifest.version, result))
        return tuple(reports)

    async def _evaluate(self, planned: PlannedDefense, event: Event, context: Context) -> Result:
        defense_id = planned.manifest.id
        try:
            with anyio.fail_after(self._deadline):
                return await planned.loaded.defense.evaluate(event, context)
        except TimeoutError:
            logger.warning("defense %s exceeded its %.2fs deadline", defense_id, self._deadline)
            return Result.failed("deadline exceeded")
        except Exception as exc:
            # Only the type is reported: the message may quote inspected content.
            logger.exception("defense %s raised while evaluating %s", defense_id, event.event_id)
            return Result.failed(f"raised {type(exc).__name__}")


def validated(manifest: Manifest, result: object) -> Result:
    """Malformed output fails the inspection instead of reaching Guard."""
    if not isinstance(result, Result):
        return Result.failed(f"returned {type(result).__name__}, not Result")
    for signal in result.signals:
        if signal.producer != manifest.id:
            return Result.failed(f"signal claims producer {signal.producer!r}")
        if signal.type not in manifest.produced_signals:
            return Result.failed(f"signal type {signal.type!r} is not declared in the manifest")
    return result
